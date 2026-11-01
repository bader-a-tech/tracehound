//! Live sensor sessions and bounded recording with an installed capture helper.
//!
//! Linux can show live sensor findings and inventory. Other desktop platforms
//! can use an existing dumpcap installation to record first and then analyse the
//! resulting PCAP. Recording is never presented as real-time detection.

use crate::runtime::{CaptureJob, JobReport, SensorOptions};
use crate::{Alert, Severity};
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_HTTP_BYTES: usize = 4 * 1024 * 1024;
const MAX_ALERT_BYTES: u64 = 1024 * 1024;
const MAX_RECENT_FINDINGS: usize = 1000;
const API_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn serialize_arc<T: Serialize, S: Serializer>(
    value: &Arc<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.as_ref().serialize(serializer)
}

fn milliseconds(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub up: bool,
    pub loopback: bool,
}

/// Interfaces supported by the native Linux sensor. No privileges are needed
/// to list them; starting packet capture still requires CAP_NET_RAW.
pub fn interfaces() -> Result<Vec<NetworkInterface>, String> {
    if !cfg!(target_os = "linux") {
        return Err("Native live analysis requires Linux. Use an installed capture helper to record and analyse on this platform.".into());
    }
    let mut result = Vec::new();
    for entry in
        fs::read_dir("/sys/class/net").map_err(|e| format!("list network interfaces: {e}"))?
    {
        let entry = entry.map_err(|e| format!("read network interface: {e}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "network interface name is not valid UTF-8")?;
        let index = fs::read_to_string(entry.path().join("ifindex"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let flags = fs::read_to_string(entry.path().join("flags"))
            .ok()
            .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        result.push(NetworkInterface {
            name,
            index,
            up: flags & 1 != 0,
            loopback: flags & 8 != 0,
        });
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveState {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

impl LiveState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct LiveSnapshot {
    pub mode: &'static str,
    pub state: LiveState,
    pub interface: String,
    pub endpoint: String,
    pub elapsed_ms: u64,
    #[serde(serialize_with = "serialize_arc")]
    pub stats: Arc<Value>,
    #[serde(serialize_with = "serialize_arc")]
    pub devices: Arc<Vec<Value>>,
    #[serde(serialize_with = "serialize_arc")]
    pub flows: Arc<Vec<Value>>,
    #[serde(serialize_with = "serialize_arc")]
    pub findings: Arc<Vec<Alert>>,
    pub alert_records: u64,
    pub dropped_findings: u64,
    pub poll_error: Option<String>,
    pub error: Option<String>,
}

struct LiveShared {
    data: Mutex<LiveSnapshot>,
    stop: AtomicBool,
    finished: Condvar,
    started: Instant,
}

/// A Linux sensor and its loopback-only read API. Snapshot collections are
/// shared, so a GUI can poll without cloning its full device and flow tables.
pub struct LiveSession {
    shared: Arc<LiveShared>,
}

impl LiveSession {
    pub fn start(
        options: SensorOptions,
        interface: String,
        promiscuous: bool,
    ) -> Result<Self, String> {
        if interface.trim().is_empty() || options.executable.is_empty() || options.max_alerts == 0 {
            return Err(
                "Select a network interface, a sensor executable, and a positive record limit."
                    .into(),
            );
        }
        if !cfg!(target_os = "linux") {
            return Err("Native live analysis requires Linux and CAP_NET_RAW. On this platform use record-then-analyse with an installed dumpcap, or open a capture file.".into());
        }
        Self::start_worker(options, interface, promiscuous)
    }

    fn start_worker(
        options: SensorOptions,
        interface: String,
        promiscuous: bool,
    ) -> Result<Self, String> {
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|e| format!("reserve local sensor port: {e}"))?;
        let address = reservation
            .local_addr()
            .map_err(|e| format!("read local sensor address: {e}"))?;
        let shared = Arc::new(LiveShared {
            data: Mutex::new(LiveSnapshot {
                mode: "live_analysis",
                state: LiveState::Starting,
                interface: interface.clone(),
                endpoint: format!("http://{address}"),
                elapsed_ms: 0,
                stats: Arc::new(Value::Null),
                devices: Arc::new(Vec::new()),
                flows: Arc::new(Vec::new()),
                findings: Arc::new(Vec::new()),
                alert_records: 0,
                dropped_findings: 0,
                poll_error: None,
                error: None,
            }),
            stop: AtomicBool::new(false),
            finished: Condvar::new(),
            started: Instant::now(),
        });
        let worker = Arc::clone(&shared);
        thread::Builder::new()
            .name("tracehound-live".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    // Keep the reservation until immediately before launching. A
                    // sensor bind failure is detected from its stderr, not treated
                    // as a successful connection to a different local server.
                    drop(reservation);
                    run_live(options, interface, promiscuous, address, &worker)
                }))
                .unwrap_or_else(|_| Err("Live sensor worker stopped unexpectedly.".into()));
                let mut data = lock(&worker.data);
                data.elapsed_ms = milliseconds(worker.started);
                if worker.stop.load(Ordering::Acquire) {
                    data.state = LiveState::Stopped;
                    data.error = None;
                } else if let Err(error) = outcome {
                    data.state = LiveState::Failed;
                    data.error = Some(error);
                } else {
                    data.state = LiveState::Stopped;
                }
                drop(data);
                worker.finished.notify_all();
            })
            .map_err(|e| format!("start live sensor worker: {e}"))?;
        Ok(Self { shared })
    }

    pub fn snapshot(&self) -> LiveSnapshot {
        let mut data = lock(&self.shared.data).clone();
        if !data.state.is_terminal() {
            data.elapsed_ms = milliseconds(self.shared.started);
        }
        data
    }

    pub fn stop(&self) -> bool {
        let mut data = lock(&self.shared.data);
        if data.state.is_terminal() {
            return false;
        }
        self.shared.stop.store(true, Ordering::Release);
        data.state = LiveState::Stopping;
        true
    }

    pub fn finished(&self) -> bool {
        lock(&self.shared.data).state.is_terminal()
    }

    pub fn wait(&self) -> Result<LiveSnapshot, String> {
        let mut data = lock(&self.shared.data);
        while !data.state.is_terminal() {
            data = self
                .shared
                .finished
                .wait(data)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if let Some(error) = &data.error {
            Err(error.clone())
        } else {
            Ok(data.clone())
        }
    }
}

impl Drop for LiveSession {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Process {
    child: Child,
    readers: Vec<thread::JoinHandle<()>>,
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

fn stop_process(process: &mut Process) -> Result<ExitStatus, String> {
    #[cfg(unix)]
    {
        let pid = libc::pid_t::try_from(process.child.id())
            .map_err(|_| "Invalid sensor process identifier.")?;
        // The positive PID belongs to this still-owned child. SIGINT lets the
        // sensor flush final flow detections and the capture helper close its
        // file before a bounded kill fallback is needed.
        if pid > 0 {
            unsafe {
                libc::kill(pid, libc::SIGINT);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = process.child.kill();
    }
    let started = Instant::now();
    loop {
        if let Some(status) = process
            .child
            .try_wait()
            .map_err(|e| format!("Stop capture process: {e}"))?
        {
            return Ok(status);
        }
        if started.elapsed() >= Duration::from_secs(2) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = process.child.kill();
    process
        .child
        .wait()
        .map_err(|e| format!("Reap capture process: {e}"))
}

fn interrupted_status(status: &ExitStatus) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status
            .signal()
            .is_some_and(|signal| signal == libc::SIGINT || signal == libc::SIGKILL)
    }
    #[cfg(windows)]
    {
        status.code() == Some(1)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

fn quiet_command(executable: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(executable);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command.stdin(Stdio::null());
    command
}

fn run_live(
    options: SensorOptions,
    interface: String,
    promiscuous: bool,
    address: SocketAddr,
    shared: &Arc<LiveShared>,
) -> Result<(), String> {
    if shared.stop.load(Ordering::Acquire) {
        return Ok(());
    }
    let mut command = quiet_command(&options.executable);
    command
        .args([
            "sniff",
            "-i",
            &interface,
            "-listen",
            &address.to_string(),
            "-json",
            "-quiet",
            "-min-severity",
            "low",
        ])
        .arg(format!("-promiscuous={promiscuous}"));
    if let Some(rules) = &options.rules {
        command.arg("-rules").arg(rules);
    }
    if let Some(nets) = &options.home_nets {
        command.arg("-home-nets").arg(nets);
    }
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Start live sensor: {e}"))?;
    let mut process = Process {
        child,
        readers: Vec::new(),
    };
    let stdout = process
        .child
        .stdout
        .take()
        .ok_or("live sensor stdout unavailable")?;
    let stderr = process
        .child
        .stderr
        .take()
        .ok_or("live sensor stderr unavailable")?;
    let (sender, receiver) = mpsc::sync_channel(128);
    let stream_error = Arc::new(Mutex::new(None::<String>));
    let diagnostics = Arc::new(Mutex::new(Vec::<u8>::new()));
    let dropped = Arc::new(AtomicU64::new(0));
    let records = Arc::new(AtomicU64::new(0));
    let parse_error = Arc::clone(&stream_error);
    let lost = Arc::clone(&dropped);
    let read_records = Arc::clone(&records);
    process.readers.push(thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader
                .by_ref()
                .take(MAX_ALERT_BYTES + 1)
                .read_until(b'\n', &mut line)
            {
                Ok(0) => break,
                Ok(_) if line.len() as u64 > MAX_ALERT_BYTES => {
                    *lock(&parse_error) = Some("Live sensor alert exceeds 1 MiB.".into());
                    break;
                }
                Ok(_) if line.iter().all(u8::is_ascii_whitespace) => continue,
                Ok(_) => match serde_json::from_slice::<Alert>(&line) {
                    Ok(alert) => {
                        read_records.fetch_add(1, Ordering::Relaxed);
                        match sender.try_send(alert) {
                            Ok(()) => {}
                            Err(mpsc::TrySendError::Full(_)) => {
                                lost.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(mpsc::TrySendError::Disconnected(_)) => break,
                        }
                    }
                    Err(error) => {
                        *lock(&parse_error) = Some(format!("Invalid live sensor JSON: {error}"));
                        break;
                    }
                },
                Err(error) => {
                    *lock(&parse_error) = Some(format!("Read live findings: {error}"));
                    break;
                }
            }
        }
    }));
    let stderr_output = Arc::clone(&diagnostics);
    let stderr_error = Arc::clone(&stream_error);
    process.readers.push(thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader
                .by_ref()
                .take(MAX_ALERT_BYTES + 1)
                .read_until(b'\n', &mut line)
            {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let mut output = lock(&stderr_output);
                    let keep = line.len().min(65_536usize.saturating_sub(output.len()));
                    output.extend_from_slice(&line[..keep]);
                    if line.starts_with(b"tracehound: dashboard:") {
                        *lock(&stderr_error) = Some(String::from_utf8_lossy(&line).trim().into());
                    }
                    if line.len() as u64 > MAX_ALERT_BYTES {
                        break;
                    }
                }
            }
        }
    }));
    let ring_size = options.max_alerts.min(MAX_RECENT_FINDINGS);
    let mut ring = VecDeque::new();
    let mut last_poll = Instant::now() - Duration::from_secs(1);
    let mut failures = 0;
    loop {
        if shared.stop.load(Ordering::Acquire) {
            let _ = stop_process(&mut process)?;
            drop(process);
            receive_findings(&receiver, &mut ring, ring_size, &dropped, &records, shared);
            return Ok(());
        }
        if let Some(error) = lock(&stream_error).clone() {
            return Err(error);
        }
        if let Some(status) = process
            .child
            .try_wait()
            .map_err(|e| format!("Read live sensor status: {e}"))?
        {
            drop(process);
            receive_findings(&receiver, &mut ring, ring_size, &dropped, &records, shared);
            if let Some(error) = lock(&stream_error).clone() {
                return Err(error);
            }
            if status.success() {
                return Ok(());
            }
            return Err(format!(
                "Live capture failed ({status}): {}",
                String::from_utf8_lossy(&lock(&diagnostics)).trim()
            ));
        }
        receive_findings(&receiver, &mut ring, ring_size, &dropped, &records, shared);
        if last_poll.elapsed() >= Duration::from_millis(750) {
            last_poll = Instant::now();
            match poll_api(address, &shared.stop) {
                Ok((stats, devices, flows)) => {
                    failures = 0;
                    let mut data = lock(&shared.data);
                    if !shared.stop.load(Ordering::Acquire) {
                        data.state = LiveState::Running;
                    }
                    data.stats = Arc::new(stats);
                    data.devices = Arc::new(devices);
                    data.flows = Arc::new(flows);
                    data.poll_error = None;
                }
                Err(error) => {
                    failures += 1;
                    let mut data = lock(&shared.data);
                    data.poll_error = Some(error.clone());
                    if (data.state == LiveState::Starting
                        && shared.started.elapsed() > API_STARTUP_TIMEOUT)
                        || (data.state == LiveState::Running && failures >= 5)
                    {
                        return Err(format!("Live inventory API unavailable: {error}"));
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn receive_findings(
    receiver: &mpsc::Receiver<Alert>,
    ring: &mut VecDeque<Alert>,
    ring_size: usize,
    dropped: &AtomicU64,
    records: &AtomicU64,
    shared: &LiveShared,
) {
    let mut changed = false;
    while let Ok(alert) = receiver.try_recv() {
        if ring.len() == ring_size {
            ring.pop_front();
            dropped.fetch_add(1, Ordering::Relaxed);
        }
        ring.push_back(alert);
        changed = true;
    }
    let mut data = lock(&shared.data);
    if changed {
        data.findings = Arc::new(ring.iter().cloned().collect());
    }
    data.alert_records = records.load(Ordering::Relaxed);
    data.dropped_findings = dropped.load(Ordering::Relaxed);
}

fn poll_api(
    address: SocketAddr,
    stop: &AtomicBool,
) -> Result<(Value, Vec<Value>, Vec<Value>), String> {
    if http_get(address, "/healthz")?
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect::<Vec<_>>()
        != b"ok"
    {
        return Err("The selected loopback port did not answer as a Tracehound sensor.".into());
    }
    if stop.load(Ordering::Acquire) {
        return Err("Stopping live capture.".into());
    }
    let stats: Value = serde_json::from_slice(&http_get(address, "/api/stats")?)
        .map_err(|e| format!("Decode live statistics: {e}"))?;
    if !stats["packets"].is_number() || !stats["detectors"].is_array() {
        return Err("Live statistics response is not a sensor snapshot.".into());
    }
    if stop.load(Ordering::Acquire) {
        return Err("Stopping live capture.".into());
    }
    let devices = serde_json::from_slice(&http_get(address, "/api/devices")?)
        .map_err(|e| format!("Decode device inventory: {e}"))?;
    if stop.load(Ordering::Acquire) {
        return Err("Stopping live capture.".into());
    }
    let flows = serde_json::from_slice(&http_get(address, "/api/flows?limit=500")?)
        .map_err(|e| format!("Decode flow inventory: {e}"))?;
    Ok((stats, devices, flows))
}

fn http_get(address: SocketAddr, path: &str) -> Result<Vec<u8>, String> {
    if !address.ip().is_loopback() {
        return Err("Live API polling requires a loopback address.".into());
    }
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(150))
        .map_err(|e| format!("Connect local sensor: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_millis(150)))
        .map_err(|e| e.to_string())?;
    write!(stream, "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n").map_err(|e| format!("Request local inventory: {e}"))?;
    let mut response = Vec::new();
    stream
        .take((MAX_HTTP_BYTES + 32_769) as u64)
        .read_to_end(&mut response)
        .map_err(|e| format!("Read local inventory: {e}"))?;
    parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> Result<Vec<u8>, String> {
    let header_end = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or("Incomplete local API HTTP response.")?;
    if header_end > 32_768 {
        return Err("Local API HTTP headers exceed 32 KiB.".into());
    }
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| "Local API HTTP headers are not UTF-8.")?;
    let mut lines = headers.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        return Err(format!("Local API returned {status}"));
    }
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                let value = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "Invalid local API content length.")?;
                if length.is_some_and(|previous| previous != value) {
                    return Err("Conflicting local API content lengths.".into());
                }
                length = Some(value);
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                if !value.trim().eq_ignore_ascii_case("chunked") {
                    return Err("Unsupported local API transfer encoding.".into());
                }
                chunked = true;
            }
        }
    }
    let body = &response[header_end + 4..];
    if chunked {
        if length.is_some() {
            return Err("Conflicting local API response framing.".into());
        }
        return decode_chunks(body);
    }
    if body.len() > MAX_HTTP_BYTES || length.is_some_and(|len| len > MAX_HTTP_BYTES) {
        return Err("Local inventory exceeds 4 MiB; narrow the monitored network.".into());
    }
    if length.is_some_and(|len| len != body.len()) {
        return Err("Incomplete local API response body.".into());
    }
    Ok(body.to_vec())
}

fn decode_chunks(mut input: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    loop {
        let end = input
            .windows(2)
            .position(|bytes| bytes == b"\r\n")
            .ok_or("Incomplete local API chunk size.")?;
        if end > 128 {
            return Err("Invalid local API chunk size.".into());
        }
        let size = std::str::from_utf8(&input[..end])
            .ok()
            .and_then(|s| {
                usize::from_str_radix(s.split(';').next().unwrap_or_default().trim(), 16).ok()
            })
            .ok_or("Invalid local API chunk size.")?;
        input = &input[end + 2..];
        if size == 0 {
            return Ok(output);
        }
        if size > MAX_HTTP_BYTES.saturating_sub(output.len()) {
            return Err("Local inventory exceeds 4 MiB.".into());
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return Err("Incomplete local API chunk.".into());
        }
        output.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CaptureInterface {
    pub id: String,
    pub name: String,
}

/// Find an already installed capture helper. This does not install a driver or
/// alter any system configuration.
pub fn discover_capture_tool() -> Option<PathBuf> {
    let filename = if cfg!(windows) {
        "dumpcap.exe"
    } else {
        "dumpcap"
    };
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|directory| directory.join(filename)));
    }
    if cfg!(windows) {
        if let Some(programs) = std::env::var_os("ProgramFiles") {
            candidates.push(PathBuf::from(programs).join("Wireshark").join(filename));
        }
        candidates.push(PathBuf::from(r"C:\Program Files\Wireshark\dumpcap.exe"));
    } else {
        candidates.extend(
            [
                "/Applications/Wireshark.app/Contents/MacOS/dumpcap",
                "/usr/bin/dumpcap",
                "/usr/local/bin/dumpcap",
                "/opt/homebrew/bin/dumpcap",
            ]
            .into_iter()
            .map(PathBuf::from),
        );
    }
    candidates.into_iter().find(|path| path.is_file())
}

pub fn capture_interfaces(tool: &Path) -> Result<Vec<CaptureInterface>, String> {
    let mut command = quiet_command(tool);
    command.arg("-D");
    let output = run_bounded_command(command)?;
    let text =
        std::str::from_utf8(&output).map_err(|_| "Capture helper interface list is not UTF-8.")?;
    let mut interfaces = Vec::new();
    for line in text.lines() {
        if let Some((id, name)) = line.split_once(". ") {
            if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) && !name.trim().is_empty() {
                interfaces.push(CaptureInterface {
                    id: id.into(),
                    name: name.trim().into(),
                });
            }
        }
    }
    if interfaces.is_empty() {
        return Err("No capture interfaces are available. Check capture permissions and the installed packet-capture driver.".into());
    }
    Ok(interfaces)
}

fn run_bounded_command(mut command: Command) -> Result<Vec<u8>, String> {
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Start capture helper: {e}"))?;
    let mut process = Process {
        child,
        readers: Vec::new(),
    };
    let stdout = process
        .child
        .stdout
        .take()
        .ok_or("capture helper stdout unavailable")?;
    let stderr = process
        .child
        .stderr
        .take()
        .ok_or("capture helper stderr unavailable")?;
    let output = Arc::new(Mutex::new(Vec::new()));
    let diagnostics = Arc::new(Mutex::new(Vec::new()));
    for (mut stream, target) in [
        (
            Box::new(stdout) as Box<dyn Read + Send>,
            Arc::clone(&output),
        ),
        (
            Box::new(stderr) as Box<dyn Read + Send>,
            Arc::clone(&diagnostics),
        ),
    ] {
        process.readers.push(thread::spawn(move || {
            let mut buffer = [0; 8192];
            while let Ok(n) = stream.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                let mut output = lock(&target);
                let keep = n.min(1_048_576usize.saturating_sub(output.len()));
                output.extend_from_slice(&buffer[..keep]);
            }
        }));
    }
    let started = Instant::now();
    let status = loop {
        if let Some(status) = process.child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(10) {
            return Err("Capture helper did not answer within 10 seconds.".into());
        }
        thread::sleep(Duration::from_millis(20));
    };
    drop(process);
    if !status.success() {
        return Err(format!(
            "Capture helper failed ({status}): {}",
            String::from_utf8_lossy(&lock(&diagnostics)).trim()
        ));
    }
    let bytes = lock(&output).clone();
    if bytes.len() >= 1_048_576 {
        return Err("Capture helper output exceeds 1 MiB.".into());
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct RecordingLimits {
    pub max_mebibytes: u32,
    pub max_seconds: u32,
}

impl Default for RecordingLimits {
    fn default() -> Self {
        Self {
            max_mebibytes: 64,
            max_seconds: 3600,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingState {
    Recording,
    Stopping,
    Analysing,
    Completed,
    Cancelled,
    Failed,
}

impl RecordingState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RecordingSnapshot {
    pub mode: &'static str,
    pub state: RecordingState,
    pub interface: String,
    pub elapsed_ms: u64,
    pub capture_bytes: u64,
    pub alert_records: usize,
    pub unique_findings: usize,
    pub error: Option<String>,
}

static NEXT_RECORDING: AtomicU64 = AtomicU64::new(0);

struct PrivateCapture {
    directory: PathBuf,
    path: PathBuf,
    parent: PathBuf,
}

impl PrivateCapture {
    fn new() -> Result<Self, String> {
        let parent = fs::canonicalize(std::env::temp_dir())
            .map_err(|e| format!("Resolve capture temporary directory: {e}"))?;
        for _ in 0..10 {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos();
            let directory = parent.join(format!(
                "tracehound-recording-{}-{stamp}-{}",
                std::process::id(),
                NEXT_RECORDING.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = fs::DirBuilder::new();
            builder.recursive(false);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&directory) {
                Ok(()) => {
                    return Ok(Self {
                        path: directory.join("capture.pcap"),
                        directory,
                        parent,
                    })
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("Create private recording directory: {error}")),
            }
        }
        Err("Could not allocate a private recording directory.".into())
    }
}

impl Drop for PrivateCapture {
    fn drop(&mut self) {
        if let Ok(directory) = fs::canonicalize(&self.directory) {
            if directory.parent() == Some(self.parent.as_path()) {
                let _ = fs::remove_file(&self.path);
                let _ = fs::remove_dir(directory);
            }
        }
    }
}

struct RecordingData {
    snapshot: RecordingSnapshot,
    result: Option<Result<Arc<JobReport>, String>>,
}
struct RecordingShared {
    data: Mutex<RecordingData>,
    stop: AtomicBool,
    cancel: AtomicBool,
    finished: Condvar,
    started: Instant,
    capture: Arc<PrivateCapture>,
}

/// Bounded, explicit record-then-analyse operation using a pre-existing dumpcap.
/// There are no live findings while the capture is being recorded.
pub struct PortableRecording {
    shared: Arc<RecordingShared>,
}

impl PortableRecording {
    pub fn start(
        options: SensorOptions,
        capture_tool: PathBuf,
        interface: String,
        limits: RecordingLimits,
    ) -> Result<Self, String> {
        Self::start_filtered(options, capture_tool, interface, limits, None)
    }

    pub fn start_filtered(
        options: SensorOptions,
        capture_tool: PathBuf,
        interface: String,
        limits: RecordingLimits,
        filter: Option<String>,
    ) -> Result<Self, String> {
        if interface.trim().is_empty()
            || capture_tool.as_os_str().is_empty()
            || options.executable.is_empty()
            || options.max_alerts == 0
        {
            return Err(
                "Choose an interface, an installed capture helper, and a sensor executable.".into(),
            );
        }
        if limits.max_mebibytes == 0
            || limits.max_mebibytes > 4096
            || limits.max_seconds == 0
            || limits.max_seconds > 86_400
        {
            return Err("Recording limits must be 1–4096 MiB and 1–86400 seconds.".into());
        }
        if filter.as_ref().is_some_and(|value| {
            value.trim().is_empty() || value.len() > 8192 || value.contains('\0')
        }) {
            return Err(
                "Capture filter must be a non-empty expression of at most 8192 bytes.".into(),
            );
        }
        let capture = Arc::new(PrivateCapture::new()?);
        let shared = Arc::new(RecordingShared {
            data: Mutex::new(RecordingData {
                snapshot: RecordingSnapshot {
                    mode: "record_then_analyse",
                    state: RecordingState::Recording,
                    interface: interface.clone(),
                    elapsed_ms: 0,
                    capture_bytes: 0,
                    alert_records: 0,
                    unique_findings: 0,
                    error: None,
                },
                result: None,
            }),
            stop: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            finished: Condvar::new(),
            started: Instant::now(),
            capture,
        });
        let worker = Arc::clone(&shared);
        thread::Builder::new()
            .name("tracehound-recording".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_recording(options, capture_tool, interface, limits, filter, &worker)
                }))
                .unwrap_or_else(|_| Err("Recording worker stopped unexpectedly.".into()));
                let mut data = lock(&worker.data);
                let outcome = if worker.cancel.load(Ordering::Acquire) {
                    Err("Recording cancelled.".into())
                } else {
                    outcome
                };
                data.snapshot.state = if worker.cancel.load(Ordering::Acquire) {
                    RecordingState::Cancelled
                } else if outcome.is_ok() {
                    RecordingState::Completed
                } else {
                    RecordingState::Failed
                };
                data.snapshot.elapsed_ms = milliseconds(worker.started);
                data.snapshot.error = outcome.as_ref().err().cloned();
                data.result = Some(outcome);
                drop(data);
                worker.finished.notify_all();
            })
            .map_err(|e| format!("Start recording worker: {e}"))?;
        Ok(Self { shared })
    }

    pub fn snapshot(&self) -> RecordingSnapshot {
        let mut snapshot = lock(&self.shared.data).snapshot.clone();
        if !snapshot.state.is_terminal() {
            snapshot.elapsed_ms = milliseconds(self.shared.started);
        }
        snapshot
    }

    /// End recording and analyse the completed packets. To discard the entire
    /// operation instead, call cancel.
    pub fn stop(&self) -> bool {
        let mut data = lock(&self.shared.data);
        if !matches!(
            data.snapshot.state,
            RecordingState::Recording | RecordingState::Stopping
        ) {
            return false;
        }
        self.shared.stop.store(true, Ordering::Release);
        data.snapshot.state = RecordingState::Stopping;
        true
    }

    pub fn cancel(&self) -> bool {
        let data = lock(&self.shared.data);
        if data.snapshot.state.is_terminal() {
            return false;
        }
        self.shared.cancel.store(true, Ordering::Release);
        true
    }

    pub fn finished(&self) -> bool {
        lock(&self.shared.data).snapshot.state.is_terminal()
    }
    pub fn try_result(&self) -> Option<Result<Arc<JobReport>, String>> {
        lock(&self.shared.data).result.clone()
    }

    pub fn wait(&self) -> Result<Arc<JobReport>, String> {
        let mut data = lock(&self.shared.data);
        while data.result.is_none() {
            data = self
                .shared
                .finished
                .wait(data)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        data.result.as_ref().unwrap().clone()
    }

    /// Save the raw capture only on an explicit request, after recording ends.
    /// Existing files are preserved. The private original is deleted on drop.
    pub fn save_capture(&self, destination: &Path) -> Result<(), String> {
        if !self.finished() {
            return Err("Finish recording and analysis before saving the raw capture.".into());
        }
        if lock(&self.shared.data).snapshot.state != RecordingState::Completed {
            return Err("Only a completed recording can be saved.".into());
        }
        let mut input = fs::File::open(&self.shared.capture.path)
            .map_err(|e| format!("Open completed capture: {e}"))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|e| format!("Create capture {}: {e}", destination.display()))?;
        std::io::copy(&mut input, &mut output)
            .map_err(|e| format!("Save capture {}: {e}", destination.display()))?;
        Ok(())
    }
}

impl Drop for PortableRecording {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn run_recording(
    options: SensorOptions,
    capture_tool: PathBuf,
    interface: String,
    limits: RecordingLimits,
    filter: Option<String>,
    shared: &Arc<RecordingShared>,
) -> Result<Arc<JobReport>, String> {
    if shared.cancel.load(Ordering::Acquire) {
        return Err("Recording cancelled.".into());
    }
    let mut command = quiet_command(capture_tool);
    command
        .args([
            "-i", &interface, "-p", "-q", "-F", "pcap", "-s", "262144", "-w",
        ])
        .arg(&shared.capture.path)
        .args([
            "-a",
            &format!("filesize:{}", u64::from(limits.max_mebibytes) * 1024),
            "-a",
            &format!("duration:{}", limits.max_seconds),
        ]);
    if let Some(filter) = filter {
        command.arg("-f").arg(filter);
    }
    let child = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!(
                "Start capture helper: {e}. Check its installation and capture-driver permissions."
            )
        })?;
    let mut process = Process {
        child,
        readers: Vec::new(),
    };
    let mut stderr = process
        .child
        .stderr
        .take()
        .ok_or("capture helper stderr unavailable")?;
    let diagnostics = Arc::new(Mutex::new(Vec::new()));
    let errors = Arc::clone(&diagnostics);
    process.readers.push(thread::spawn(move || {
        let mut buffer = [0; 8192];
        while let Ok(n) = stderr.read(&mut buffer) {
            if n == 0 {
                break;
            }
            let mut errors = lock(&errors);
            let keep = n.min(65_536usize.saturating_sub(errors.len()));
            errors.extend_from_slice(&buffer[..keep]);
        }
    }));
    let started = Instant::now();
    let (status, ended_by_controller) = loop {
        if shared.cancel.load(Ordering::Acquire) {
            return Err("Recording cancelled.".into());
        }
        let bytes = fs::metadata(&shared.capture.path)
            .map(|m| m.len())
            .unwrap_or(0);
        lock(&shared.data).snapshot.capture_bytes = bytes;
        if let Some(status) = process
            .child
            .try_wait()
            .map_err(|e| format!("Read capture helper status: {e}"))?
        {
            break (status, false);
        }
        if shared.stop.load(Ordering::Acquire)
            || bytes >= u64::from(limits.max_mebibytes) * 1024 * 1024
            || started.elapsed() >= Duration::from_secs(u64::from(limits.max_seconds))
        {
            break (stop_process(&mut process)?, true);
        }
        thread::sleep(Duration::from_millis(25));
    };
    drop(process);
    if !status.success() && !(ended_by_controller && interrupted_status(&status)) {
        return Err(format!(
            "Capture helper failed ({status}): {}",
            String::from_utf8_lossy(&lock(&diagnostics)).trim()
        ));
    }
    if shared.cancel.load(Ordering::Acquire) {
        return Err("Recording cancelled.".into());
    }
    let bytes = fs::metadata(&shared.capture.path)
        .map(|m| m.len())
        .unwrap_or(0);
    if bytes == 0 {
        return Err("The capture helper did not write a capture. Check interface selection and capture permissions.".into());
    }
    {
        let mut data = lock(&shared.data);
        data.snapshot.state = RecordingState::Analysing;
        data.snapshot.capture_bytes = bytes;
    }
    let job = CaptureJob::analyze(shared.capture.path.clone(), options, Severity::Low)
        .map_err(|e| e.to_string())?;
    loop {
        if shared.cancel.load(Ordering::Acquire) {
            job.cancel();
        }
        let progress = job.snapshot();
        {
            let mut data = lock(&shared.data);
            data.snapshot.alert_records = progress.alert_records;
            data.snapshot.unique_findings = progress.unique_findings;
        }
        if let Some(result) = job.try_result() {
            return result.map_err(|e| e.to_string());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_http_parser_handles_lengths_chunks_and_rejects_bad_or_large_bodies() {
        assert_eq!(
            parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap(),
            b"ok"
        );
        assert_eq!(parse_http_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[1\r\n1\r\n]\r\n0\r\n\r\n").unwrap(), b"[1]");
        assert!(parse_http_response(b"HTTP/1.1 403 Forbidden\r\n\r\n").is_err());
        assert!(parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok").is_err());
        assert!(decode_chunks(b"ffffff\r\n").is_err());
        assert!(decode_chunks(b"2\r\nx\r\n").is_err());
        assert!(http_get(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 80)), "/").is_err());
    }
}
