//! Background capture jobs shared by terminal and desktop clients.
//!
//! The worker owns its sensor process. UI threads only request cancellation or
//! read cheap snapshots; no process wait or capture parsing happens in them.

use crate::{Alert, AlertAccumulator, AnalysisReport, CaptureCase, EvaluationReport, Severity};
use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct SensorOptions {
    pub executable: OsString,
    pub rules: Option<PathBuf>,
    pub home_nets: Option<OsString>,
    /// Explicit local, source-attributed TLS pair indicators; never fetched implicitly.
    pub pair_feed: Option<PathBuf>,
    /// Zero disables the per-capture timeout.
    pub timeout: Duration,
    pub max_alerts: usize,
}

impl Default for SensorOptions {
    fn default() -> Self {
        Self {
            executable: "tracehound".into(),
            rules: None,
            home_nets: None,
            pair_feed: None,
            timeout: Duration::from_secs(300),
            max_alerts: 1_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Starting,
    Running,
    Cancelling,
    Completed,
    Cancelled,
    TimedOut,
    Failed,
}

impl JobState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::TimedOut | Self::Failed
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobErrorKind {
    InvalidInput,
    Spawn,
    Read,
    OutputLimit,
    TimedOut,
    Cancelled,
    SensorFailed,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobError {
    pub kind: JobErrorKind,
    pub message: String,
}

impl JobError {
    fn new(kind: JobErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for JobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for JobError {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CaptureReport {
    pub capture: PathBuf,
    #[serde(flatten)]
    pub report: AnalysisReport,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub enrichment: serde_json::Value,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum JobReport {
    Analysis(CaptureReport),
    Evaluation(Box<EvaluationReport>),
}

#[derive(Clone, Debug, Serialize)]
pub struct JobSnapshot {
    pub state: JobState,
    /// Accepted JSON alert records, including those below the reporting floor.
    pub alert_records: usize,
    /// Qualifying rule/source/destination groups received so far. Provisional
    /// until successful sensor completion; snapshots never publish partial reports.
    pub unique_findings: usize,
    /// Bytes read from the sensor's JSONL stdout, not bytes of capture processed.
    pub output_bytes: u64,
    pub elapsed_ms: u64,
    pub error: Option<JobError>,
}

type Outcome = Result<Arc<JobReport>, JobError>;

struct JobData {
    state: JobState,
    result: Option<Outcome>,
    elapsed_ms: Option<u64>,
}

struct Shared {
    data: Mutex<JobData>,
    finished: Condvar,
    cancelled: AtomicBool,
    alert_records: AtomicUsize,
    unique_findings: AtomicUsize,
    output_bytes: AtomicU64,
    started: Instant,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, JobData> {
        self.data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn check_cancelled(&self) -> Result<(), JobError> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(JobError::new(JobErrorKind::Cancelled, "analysis cancelled"))
        } else {
            Ok(())
        }
    }
}

/// One immediately claimed background job. Dropping an active handle requests
/// cancellation without blocking its caller. The worker still kills and reaps
/// the sensor and joins output readers before publishing a terminal result.
pub struct CaptureJob {
    shared: Arc<Shared>,
}

impl CaptureJob {
    pub fn analyze(
        path: PathBuf,
        options: SensorOptions,
        min_severity: Severity,
    ) -> Result<Self, JobError> {
        Self::start(path, options, Request::Analyze(min_severity))
    }

    pub fn evaluate(
        path: PathBuf,
        options: SensorOptions,
        case: CaptureCase,
    ) -> Result<Self, JobError> {
        case.validate()
            .map_err(|e| JobError::new(JobErrorKind::InvalidInput, e))?;
        Self::start(path, options, Request::Evaluate(case))
    }

    fn start(path: PathBuf, options: SensorOptions, request: Request) -> Result<Self, JobError> {
        validate_capture(&path)?;
        if options.executable.is_empty() || options.max_alerts == 0 {
            return Err(JobError::new(
                JobErrorKind::InvalidInput,
                "sensor executable and a positive max-alerts are required",
            ));
        }
        let resolved = fs::canonicalize(&path).map_err(|e| {
            JobError::new(
                JobErrorKind::InvalidInput,
                format!("open capture {}: {e}", path.display()),
            )
        })?;
        let shared = Arc::new(Shared {
            data: Mutex::new(JobData {
                state: JobState::Starting,
                result: None,
                elapsed_ms: None,
            }),
            finished: Condvar::new(),
            cancelled: AtomicBool::new(false),
            alert_records: AtomicUsize::new(0),
            unique_findings: AtomicUsize::new(0),
            output_bytes: AtomicU64::new(0),
            started: Instant::now(),
        });
        let worker = Arc::clone(&shared);
        thread::Builder::new()
            .name("tracehound-analysis".into())
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    worker.check_cancelled()?;
                    let minimum = match &request {
                        Request::Analyze(minimum) => *minimum,
                        Request::Evaluate(case) => case.min_severity,
                    };
                    let feed = options
                        .pair_feed
                        .as_deref()
                        .map(crate::feed::PairFeed::load)
                        .transpose()
                        .map_err(|e| JobError::new(JobErrorKind::InvalidInput, e))?;
                    let prepared = PreparedCapture::new(&resolved, &options, &worker)?;
                    let dns_policy = prepared
                        .enrichment
                        .as_ref()
                        .map(|_| crate::dns::DnsPolicy::load(options.rules.as_deref()))
                        .transpose()
                        .map_err(|e| JobError::new(JobErrorKind::InvalidInput, e))?;
                    let mut accumulated = run_sensor(
                        &options,
                        prepared.path(&resolved).as_ref(),
                        minimum,
                        &worker,
                        dns_policy.is_some(),
                    )?;
                    if let (Some(policy), Some(enrichment)) = (&dns_policy, &prepared.enrichment) {
                        check_deadline(&options, &worker)?;
                        let networks = home_networks(&options)?;
                        let queries: Vec<_> = enrichment
                            .dns
                            .iter()
                            .filter(|q| {
                                networks
                                    .iter()
                                    .any(|net| net.contains(&crate::canonical_ip(q.src)))
                            })
                            .cloned()
                            .collect();
                        for alert in policy.detect(&queries) {
                            append_native(&mut accumulated, alert, &options, &worker)?;
                        }
                    }
                    if let (Some(feed), Some(enrichment)) = (&feed, &prepared.enrichment) {
                        check_deadline(&options, &worker)?;
                        for alert in feed
                            .detect(&enrichment.tls)
                            .map_err(|e| JobError::new(JobErrorKind::Read, e))?
                        {
                            append_native(&mut accumulated, alert, &options, &worker)?;
                        }
                    }
                    let enrichment = prepared
                        .enrichment
                        .as_ref()
                        .map(serde_json::to_value)
                        .transpose()
                        .map_err(|e| JobError::new(JobErrorKind::Internal, e.to_string()))?
                        .unwrap_or(serde_json::Value::Null);
                    worker.check_cancelled()?;
                    let report = match request {
                        Request::Analyze(_) => JobReport::Analysis(CaptureReport {
                            capture: path,
                            report: accumulated.finish(),
                            enrichment,
                        }),
                        Request::Evaluate(case) => {
                            let mut report = accumulated
                                .finish_evaluation(&case)
                                .map_err(|e| JobError::new(JobErrorKind::Read, e))?;
                            report.enrichment = enrichment;
                            JobReport::Evaluation(Box::new(report))
                        }
                    };
                    worker.check_cancelled()?;
                    check_deadline(&options, &worker)?;
                    Ok(Arc::new(report))
                }))
                .unwrap_or_else(|_| {
                    Err(JobError::new(
                        JobErrorKind::Internal,
                        "analysis worker failed",
                    ))
                });
                let mut data = worker.lock();
                // Cancellation wins until a terminal result is published, even if
                // it arrived while the final report was being assembled.
                let outcome = if worker.cancelled.load(Ordering::Acquire) {
                    Err(JobError::new(JobErrorKind::Cancelled, "analysis cancelled"))
                } else {
                    outcome
                };
                data.state = match &outcome {
                    Ok(_) => JobState::Completed,
                    Err(error) if error.kind == JobErrorKind::Cancelled => JobState::Cancelled,
                    Err(error) if error.kind == JobErrorKind::TimedOut => JobState::TimedOut,
                    Err(_) => JobState::Failed,
                };
                data.elapsed_ms = Some(elapsed_ms(worker.started));
                data.result = Some(outcome);
                drop(data);
                worker.finished.notify_all();
            })
            .map_err(|e| {
                JobError::new(
                    JobErrorKind::Internal,
                    format!("start analysis worker: {e}"),
                )
            })?;
        Ok(Self { shared })
    }

    pub fn snapshot(&self) -> JobSnapshot {
        let data = self.shared.lock();
        JobSnapshot {
            state: data.state,
            alert_records: self.shared.alert_records.load(Ordering::Relaxed),
            unique_findings: self.shared.unique_findings.load(Ordering::Relaxed),
            output_bytes: self.shared.output_bytes.load(Ordering::Relaxed),
            elapsed_ms: data
                .elapsed_ms
                .unwrap_or_else(|| elapsed_ms(self.shared.started)),
            error: data
                .result
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .cloned(),
        }
    }

    pub fn cancel(&self) -> bool {
        let mut data = self.shared.lock();
        if data.state.is_terminal() {
            return false;
        }
        self.shared.cancelled.store(true, Ordering::Release);
        data.state = JobState::Cancelling;
        true
    }

    pub fn try_result(&self) -> Option<Outcome> {
        self.shared.lock().result.clone()
    }

    pub fn wait(&self) -> Outcome {
        let mut data = self.shared.lock();
        loop {
            if let Some(result) = &data.result {
                return result.clone();
            }
            data = self
                .shared
                .finished
                .wait(data)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

impl Drop for CaptureJob {
    fn drop(&mut self) {
        self.cancel();
    }
}

enum Request {
    Analyze(Severity),
    Evaluate(CaptureCase),
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

pub fn validate_capture(path: &Path) -> Result<(), JobError> {
    if !path.is_file() {
        return Err(JobError::new(
            JobErrorKind::InvalidInput,
            format!("capture {} is not a readable file", path.display()),
        ));
    }
    Ok(())
}

// The process guard also reaps the child if an unexpected worker panic occurs.
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct PreparedCapture {
    directory: Option<PathBuf>,
    enrichment: Option<crate::capture::CaptureEnrichment>,
}
impl PreparedCapture {
    fn new(input: &Path, options: &SensorOptions, shared: &Shared) -> Result<Self, JobError> {
        let mut magic = [0; 4];
        let length = fs::File::open(input)
            .and_then(|mut file| file.read(&mut magic))
            .map_err(|e| JobError::new(JobErrorKind::Read, format!("read capture header: {e}")))?;
        // Unknown formats remain the sensor's responsibility. Known capture formats
        // are parsed strictly, so corrupt data cannot bypass preparation.
        if length != 4
            || !matches!(
                magic,
                [0xd4, 0xc3, 0xb2, 0xa1]
                    | [0xa1, 0xb2, 0xc3, 0xd4]
                    | [0x4d, 0x3c, 0xb2, 0xa1]
                    | [0xa1, 0xb2, 0x3c, 0x4d]
                    | [0x0a, 0x0d, 0x0d, 0x0a]
            )
        {
            return Ok(Self {
                directory: None,
                enrichment: None,
            });
        }
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "tracehound-prepare-{}-{stamp}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let builder = fs::DirBuilder::new();
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            builder
        };
        builder.create(&directory).map_err(|e| {
            JobError::new(
                JobErrorKind::Read,
                format!("create private capture workspace: {e}"),
            )
        })?;
        let mut owned = Self {
            directory: Some(directory),
            enrichment: None,
        };
        let cancelled = || {
            shared.cancelled.load(Ordering::Acquire)
                || (!options.timeout.is_zero() && shared.started.elapsed() >= options.timeout)
        };
        let enrichment =
            crate::capture::prepare_capture_cancellable(input, &owned.path(input), &cancelled);
        shared.check_cancelled()?;
        check_deadline(options, shared)?;
        owned.enrichment = Some(
            enrichment
                .map_err(|e| JobError::new(JobErrorKind::Read, format!("prepare capture: {e}")))?,
        );
        Ok(owned)
    }
    fn path<'a>(&'a self, original: &'a Path) -> std::borrow::Cow<'a, Path> {
        self.directory
            .as_ref()
            .map(|directory| std::borrow::Cow::Owned(directory.join("normalized.pcap")))
            .unwrap_or(std::borrow::Cow::Borrowed(original))
    }
}
impl Drop for PreparedCapture {
    fn drop(&mut self) {
        if let Some(directory) = &self.directory {
            let _ = fs::remove_file(directory.join("normalized.pcap"));
            let _ = fs::remove_dir(directory);
        }
    }
}
fn check_deadline(options: &SensorOptions, shared: &Shared) -> Result<(), JobError> {
    if !options.timeout.is_zero() && shared.started.elapsed() >= options.timeout {
        return Err(JobError::new(
            JobErrorKind::TimedOut,
            format!(
                "capture analysis exceeded {} seconds; adjust the timeout for larger captures",
                options.timeout.as_secs()
            ),
        ));
    }
    Ok(())
}
fn append_native(
    accumulated: &mut AlertAccumulator,
    alert: Alert,
    options: &SensorOptions,
    shared: &Shared,
) -> Result<(), JobError> {
    shared.check_cancelled()?;
    check_deadline(options, shared)?;
    if shared.alert_records.load(Ordering::Relaxed) >= options.max_alerts {
        return Err(JobError::new(
            JobErrorKind::OutputLimit,
            "combined sensor and native alert limit exceeded",
        ));
    }
    accumulated
        .push(alert)
        .map_err(|e| JobError::new(JobErrorKind::Read, e))?;
    shared.alert_records.fetch_add(1, Ordering::Relaxed);
    shared
        .unique_findings
        .store(accumulated.unique_findings(), Ordering::Relaxed);
    Ok(())
}
fn home_networks(options: &SensorOptions) -> Result<Vec<ipnet::IpNet>, JobError> {
    let defaults = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,127.0.0.0/8,100.64.0.0/10,fc00::/7,fe80::/10,::1/128";
    let supplied = options
        .home_nets
        .as_deref()
        .map(|value| {
            value.to_str().ok_or_else(|| {
                JobError::new(
                    JobErrorKind::InvalidInput,
                    "home networks must be UTF-8 CIDRs",
                )
            })
        })
        .transpose()?;
    supplied
        .unwrap_or(defaults)
        .split(',')
        .map(|value| {
            value.trim().parse().map_err(|e| {
                JobError::new(
                    JobErrorKind::InvalidInput,
                    format!("invalid home network {value:?}: {e}"),
                )
            })
        })
        .collect()
}

// The process guard also reaps the child if an unexpected worker panic occurs.
struct SensorChild(Child);

impl Drop for SensorChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run_sensor(
    options: &SensorOptions,
    path: &Path,
    minimum: Severity,
    shared: &Arc<Shared>,
    native_dns: bool,
) -> Result<AlertAccumulator, JobError> {
    shared.check_cancelled()?;
    let mut command = Command::new(&options.executable);
    command.args([
        OsStr::new("replay"),
        path.as_os_str(),
        OsStr::new("-json"),
        OsStr::new("-quiet"),
        OsStr::new("-min-severity"),
        OsStr::new("info"),
    ]);
    if let Some(rules) = &options.rules {
        command.arg("-rules").arg(rules);
    }
    if let Some(nets) = &options.home_nets {
        command.arg("-home-nets").arg(nets);
    }
    // Native desktop analysis should not flash a terminal window on Windows.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| {
            JobError::new(
                JobErrorKind::Spawn,
                format!(
                    "start sensor {}: {e}; select the Tracehound executable",
                    Path::new(&options.executable).display()
                ),
            )
        })?;
    let mut child = SensorChild(child);
    {
        let mut data = shared.lock();
        if !shared.cancelled.load(Ordering::Acquire) {
            data.state = JobState::Running;
        }
    }
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| JobError::new(JobErrorKind::Internal, "sensor stdout unavailable"))?;
    let stderr = child
        .0
        .stderr
        .take()
        .ok_or_else(|| JobError::new(JobErrorKind::Internal, "sensor stderr unavailable"))?;
    let max_alerts = options.max_alerts;
    let progress = Arc::clone(shared);
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let _ = tx.send(read_alerts(
            stdout, max_alerts, minimum, &progress, native_dns,
        ));
    });
    let errors = thread::spawn(move || bounded_stderr(stderr));
    let mut collected = None;
    let status = loop {
        let interruption = shared.check_cancelled().err().or_else(|| {
            if !options.timeout.is_zero() && shared.started.elapsed() >= options.timeout {
                Some(JobError::new(
                    JobErrorKind::TimedOut,
                    format!(
                        "sensor exceeded {} seconds; adjust the timeout for larger captures",
                        options.timeout.as_secs()
                    ),
                ))
            } else {
                None
            }
        });
        if let Some(error) = interruption {
            let _ = child.0.kill();
            let _ = child.0.wait();
            let _ = reader.join();
            let _ = errors.join();
            return Err(error);
        }
        if collected.is_none() {
            match rx.try_recv() {
                Ok(Ok(parsed)) => collected = Some(parsed),
                Ok(Err(error)) => {
                    let _ = child.0.kill();
                    let _ = child.0.wait();
                    let _ = reader.join();
                    let _ = errors.join();
                    return Err(error);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    let _ = child.0.kill();
                    let _ = child.0.wait();
                    let _ = reader.join();
                    let _ = errors.join();
                    return Err(JobError::new(
                        JobErrorKind::Internal,
                        "sensor output reader failed",
                    ));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        match child.0.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.0.kill();
                let _ = child.0.wait();
                let _ = reader.join();
                let _ = errors.join();
                return Err(JobError::new(
                    JobErrorKind::Internal,
                    format!("wait for sensor: {error}"),
                ));
            }
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stderr = errors
        .join()
        .map_err(|_| JobError::new(JobErrorKind::Internal, "sensor stderr reader failed"))?;
    reader
        .join()
        .map_err(|_| JobError::new(JobErrorKind::Internal, "sensor stdout reader failed"))?;
    if !status.success() {
        return Err(JobError::new(
            JobErrorKind::SensorFailed,
            format!(
                "sensor exited with {status}: {}",
                String::from_utf8_lossy(&stderr).trim()
            ),
        ));
    }
    match collected {
        Some(accumulated) => Ok(accumulated),
        None => rx
            .recv()
            .map_err(|_| JobError::new(JobErrorKind::Internal, "sensor output reader failed"))?,
    }
}

fn bounded_stderr(mut stream: impl Read) -> Vec<u8> {
    let mut output = Vec::new();
    let mut buffer = [0; 8192];
    while let Ok(n) = stream.read(&mut buffer) {
        if n == 0 {
            break;
        }
        let keep = n.min(65536usize.saturating_sub(output.len()));
        output.extend_from_slice(&buffer[..keep]);
    }
    output
}

fn read_alerts(
    stream: impl Read,
    max_alerts: usize,
    minimum: Severity,
    shared: &Shared,
    native_dns: bool,
) -> Result<AlertAccumulator, JobError> {
    let mut reader = BufReader::new(stream);
    let mut accumulated = AlertAccumulator::new(minimum);
    let mut line = Vec::new();
    let mut line_number = 0;
    let mut records = 0;
    loop {
        shared.check_cancelled()?;
        line.clear();
        let count = reader
            .by_ref()
            .take(1_048_577)
            .read_until(b'\n', &mut line)
            .map_err(|e| JobError::new(JobErrorKind::Read, format!("read sensor output: {e}")))?;
        if count == 0 {
            break;
        }
        shared
            .output_bytes
            .fetch_add(count as u64, Ordering::Relaxed);
        line_number += 1;
        if line.len() > 1_048_576 {
            return Err(JobError::new(
                JobErrorKind::OutputLimit,
                format!("sensor JSON line {line_number} exceeds 1 MiB"),
            ));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if records >= max_alerts {
            return Err(JobError::new(JobErrorKind::OutputLimit, format!("sensor exceeded {max_alerts} alert records; adjust the limit or narrow the capture")));
        }
        let alert: Alert = serde_json::from_slice(&line).map_err(|e| {
            JobError::new(
                JobErrorKind::Read,
                format!("invalid sensor JSON at line {line_number}: {e}"),
            )
        })?;
        records += 1;
        shared.alert_records.fetch_add(1, Ordering::Relaxed);
        // Prepared files use the Rust DNS scorer and complete suffix table.
        // Count suppressed legacy emissions towards the raw record guard.
        if native_dns && alert.rule_id == "TH-0002" {
            continue;
        }
        accumulated
            .push(alert)
            .map_err(|e| JobError::new(JobErrorKind::Read, e))?;
        shared
            .unique_findings
            .store(accumulated.unique_findings(), Ordering::Relaxed);
    }
    Ok(accumulated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared() -> Shared {
        Shared {
            data: Mutex::new(JobData {
                state: JobState::Starting,
                result: None,
                elapsed_ms: None,
            }),
            finished: Condvar::new(),
            cancelled: AtomicBool::new(false),
            alert_records: AtomicUsize::new(0),
            unique_findings: AtomicUsize::new(0),
            output_bytes: AtomicU64::new(0),
            started: Instant::now(),
        }
    }

    #[test]
    fn output_reader_reports_malformed_input_and_limits() {
        assert_eq!(
            read_alerts("not json\n".as_bytes(), 10, Severity::Low, &shared(), false)
                .unwrap_err()
                .kind,
            JobErrorKind::Read
        );
        let data = b"{\"rule_id\":\"TH-0001\",\"severity\":\"high\",\"src\":\"10.0.0.1\"}\n";
        assert_eq!(
            read_alerts(
                data.as_slice().repeat(2).as_slice(),
                1,
                Severity::Low,
                &shared(),
                false
            )
            .unwrap_err()
            .kind,
            JobErrorKind::OutputLimit
        );
        assert_eq!(
            read_alerts(
                vec![b'x'; 1_048_577].as_slice(),
                1,
                Severity::Low,
                &shared(),
                false
            )
            .unwrap_err()
            .kind,
            JobErrorKind::OutputLimit
        );
    }
    #[test]
    fn native_dns_suppression_keeps_the_raw_record_limit_and_progress() {
        let data = b"{\"rule_id\":\"TH-0002\",\"severity\":\"high\",\"src\":\"10.0.0.1\"}\n";
        let progress = shared();
        let result = read_alerts(
            data.as_slice().repeat(2).as_slice(),
            2,
            Severity::Low,
            &progress,
            true,
        )
        .unwrap();
        assert_eq!(result.total_alerts(), 0);
        assert_eq!(progress.alert_records.load(Ordering::Relaxed), 2);
        assert_eq!(
            read_alerts(
                data.as_slice().repeat(2).as_slice(),
                1,
                Severity::Low,
                &shared(),
                true
            )
            .unwrap_err()
            .kind,
            JobErrorKind::OutputLimit
        );
    }
}
