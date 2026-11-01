//! Reproducible resource measurements of the real capture-job backend.
//! Stress captures are deliberately separate from detection-accuracy evaluation.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tracehound_eval::runtime::{AnalysisEngine, CaptureJob, JobReport, SensorOptions};
use tracehound_eval::Severity;

const GIB: u64 = 1024 * 1024 * 1024;
const FRAME_BYTES: usize = 1514;
const HELP: &str = "tracehound-bench --work-dir DIRECTORY --output NEW-REPORT.json [--engine rust|sensor] [--sensor PATH] [--sizes-gib 1,5,10] [--sample-ms 50] [--cancel-after-ms 250] [--skip-index] [--retain-fixtures]\n\nRust is the default engine; the sensor engine requires an explicit executable.\nWrites valid MTU-sized UDP stress captures and measures real backend analysis,\nprocess-tree memory, cancellation, and truncated-input rejection. These captures\ncarry no accuracy labels. Default fixtures are processed one at a time.\n";

struct Options {
    engine: AnalysisEngine,
    sensor: PathBuf,
    work: PathBuf,
    output: PathBuf,
    sizes: Vec<u64>,
    sample: Duration,
    cancel_after: Duration,
    retain: bool,
    skip_index: bool,
}

#[derive(Default, Serialize)]
struct Memory {
    baseline_tree_rss_bytes: u64,
    sampled_peak_tree_rss_bytes: u64,
    sum_observed_process_lifetime_peak_rss_bytes: Option<u64>,
    samples: u64,
    unavailable_samples: u64,
    observed_processes: usize,
}

#[derive(Serialize)]
struct Measurement {
    operation: &'static str,
    elapsed_ms: u128,
    input_bytes: u64,
    mib_per_second: Option<f64>,
    packets_per_second: Option<f64>,
    input_packets: Option<u64>,
    output_packets: Option<u64>,
    alert_records: Option<usize>,
    unique_findings: Option<usize>,
    state: String,
    error: Option<String>,
    cancellation_requested: bool,
    cancellation_cleanup_ms: Option<u128>,
    completed_report: bool,
    leftover_preparation_entries: usize,
    memory: Memory,
}

#[derive(Serialize)]
struct FixtureResult {
    nominal_gib: u64,
    actual_bytes: u64,
    packets: u64,
    generation_ms: u128,
    analysis: Measurement,
    cancellation: Measurement,
    truncation: Measurement,
    indexing: Option<IndexMeasurement>,
    index_cancellation: Option<IndexMeasurement>,
}

#[derive(Serialize)]
struct IndexMeasurement {
    elapsed_ms: u128,
    mib_per_second: Option<f64>,
    indexed_packets: Option<u64>,
    flows: Option<u64>,
    index_bytes: Option<u64>,
    reopen_ms: Option<u128>,
    cancellation_requested: bool,
    error: Option<String>,
    incomplete_database_present: bool,
    memory: Memory,
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{HELP}");
        return;
    }
    if let Err(error) = parse(args).and_then(run) {
        eprintln!("tracehound-bench: {error}");
        std::process::exit(2);
    }
}

fn parse(args: Vec<std::ffi::OsString>) -> Result<Options, String> {
    let mut sensor = None;
    let mut engine = AnalysisEngine::Rust;
    let mut work = None;
    let mut output = None;
    let mut sizes = vec![1, 5, 10];
    let mut sample = 50;
    let mut cancel_after = 250;
    let mut retain = false;
    let mut skip_index = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--skip-index" {
            skip_index = true;
            continue;
        }
        if arg == "--retain-fixtures" {
            retain = true;
            continue;
        }
        let value = args
            .next()
            .ok_or_else(|| format!("{} needs a value", arg.to_string_lossy()))?;
        match arg.to_str() {
            Some("--engine") => {
                engine = match value.to_str() {
                    Some("rust") => AnalysisEngine::Rust,
                    Some("sensor") => AnalysisEngine::Sensor,
                    _ => return Err("engine must be rust or sensor".into()),
                }
            }
            Some("--sensor") => sensor = Some(PathBuf::from(value)),
            Some("--work-dir") => work = Some(PathBuf::from(value)),
            Some("--output") => output = Some(PathBuf::from(value)),
            Some("--sizes-gib") => {
                sizes = value
                    .to_str()
                    .ok_or("sizes must be UTF-8")?
                    .split(',')
                    .map(|part| {
                        part.parse::<u64>()
                            .map_err(|_| "sizes must be comma-separated integers".to_string())
                    })
                    .collect::<Result<_, _>>()?;
                if sizes.is_empty()
                    || sizes.len() > 3
                    || sizes.iter().any(|size| ![1, 5, 10].contains(size))
                {
                    return Err(
                        "supported fixture sizes are 1,5,10 GiB, at most three per invocation"
                            .into(),
                    );
                }
                sizes.sort_unstable();
                sizes.dedup();
            }
            Some("--sample-ms") => {
                sample = value
                    .to_str()
                    .ok_or("sample interval must be UTF-8")?
                    .parse::<u64>()
                    .map_err(|_| "invalid sample interval")?
            }
            Some("--cancel-after-ms") => {
                cancel_after = value
                    .to_str()
                    .ok_or("cancellation interval must be UTF-8")?
                    .parse::<u64>()
                    .map_err(|_| "invalid cancellation interval")?
            }
            _ => return Err(format!("unknown option {}", arg.to_string_lossy())),
        }
    }
    if !(10..=1000).contains(&sample) || !(10..=60_000).contains(&cancel_after) {
        return Err("sample interval must be 10..1000ms and cancellation delay 10..60000ms".into());
    }
    Ok(Options {
        engine,
        sensor: match sensor {
            Some(sensor) => sensor,
            None if engine == AnalysisEngine::Rust => PathBuf::new(),
            None => return Err("--sensor is required for the sensor engine".into()),
        },
        work: work.ok_or("--work-dir is required")?,
        output: output.ok_or("--output is required")?,
        sizes,
        sample: Duration::from_millis(sample),
        cancel_after: Duration::from_millis(cancel_after),
        retain,
        skip_index,
    })
}

fn run(mut options: Options) -> Result<(), String> {
    let (revision_start, dirty_start) = source_state();
    if options.output.exists() {
        return Err("output report already exists; choose a new path".into());
    }
    if options.engine == AnalysisEngine::Sensor {
        options.sensor =
            fs::canonicalize(&options.sensor).map_err(|e| format!("resolve sensor: {e}"))?;
    }
    fs::create_dir_all(&options.work).map_err(|e| format!("create work root: {e}"))?;
    options.work = fs::canonicalize(&options.work).map_err(|e| e.to_string())?;
    let run_directory = options.work.join(format!(
        "run-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs()
    ));
    fs::create_dir(&run_directory)
        .map_err(|e| format!("create isolated benchmark directory: {e}"))?;
    let temporary = run_directory.join("preparation");
    fs::create_dir(&temporary).map_err(|e| e.to_string())?;
    // This process owns the environment before spawning workers. Only its own
    // backend/sensor children see the isolated temporary location.
    std::env::set_var("TMP", &temporary);
    std::env::set_var("TEMP", &temporary);
    std::env::set_var("TMPDIR", &temporary);
    let interrupted = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&interrupted);
    ctrlc::set_handler(move || flag.store(true, Ordering::Release))
        .map_err(|e| format!("install cancellation handler: {e}"))?;
    let mut results = Vec::new();
    let mut all_checks_passed = true;
    for size in &options.sizes {
        if interrupted.load(Ordering::Acquire) {
            return Err("benchmark interrupted".into());
        }
        let capture = run_directory.join(format!("stress-{size}gib.pcap"));
        eprintln!("Writing {size} GiB stress capture (no accuracy labels)");
        let generated = Instant::now();
        let (bytes, packets) = generate(&capture, size * GIB, &|| {
            interrupted.load(Ordering::Acquire)
        })?;
        let generation_ms = generated.elapsed().as_millis();
        let analysis = measure(
            "analysis",
            &capture,
            bytes,
            &temporary,
            &options,
            None,
            &interrupted,
        )?;
        eprintln!(
            "{size} GiB analysis: {}ms, {}",
            analysis.elapsed_ms, analysis.state
        );
        let cancellation = measure(
            "cancellation",
            &capture,
            bytes,
            &temporary,
            &options,
            Some(options.cancel_after),
            &interrupted,
        )?;
        let truncated = run_directory.join(format!("truncated-{size}gib.pcap"));
        let mut input = File::open(&capture)
            .map_err(|e| e.to_string())?
            .take(24 + 16 + 17);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&truncated)
            .map_err(|e| e.to_string())?;
        std::io::copy(&mut input, &mut output).map_err(|e| e.to_string())?;
        drop(output);
        let truncation = measure(
            "truncation",
            &truncated,
            57,
            &temporary,
            &options,
            None,
            &interrupted,
        )?;
        let indexing = if options.skip_index {
            None
        } else {
            Some(measure_index(
                &capture,
                &run_directory.join(format!("stress-{size}gib.sqlite")),
                bytes,
                &options,
                None,
                &interrupted,
            )?)
        };
        if let Some(indexing) = &indexing {
            eprintln!("{size} GiB case index: {}ms", indexing.elapsed_ms);
        }
        let index_cancellation = if options.skip_index {
            None
        } else {
            Some(measure_index(
                &capture,
                &run_directory.join(format!("cancelled-{size}gib.sqlite")),
                bytes,
                &options,
                Some(options.cancel_after),
                &interrupted,
            )?)
        };
        all_checks_passed &= analysis.completed_report
            && analysis.input_packets == Some(packets)
            && analysis.leftover_preparation_entries == 0
            && cancellation.cancellation_requested
            && !cancellation.completed_report
            && cancellation.state == "Cancelled"
            && cancellation.leftover_preparation_entries == 0
            && !truncation.completed_report
            && truncation.state == "Failed"
            && truncation.leftover_preparation_entries == 0;
        if let (Some(indexing), Some(index_cancellation)) = (&indexing, &index_cancellation) {
            all_checks_passed &= indexing.error.is_none()
                && indexing.indexed_packets == Some(packets)
                && index_cancellation.cancellation_requested
                && index_cancellation.error.is_some()
                && !index_cancellation.incomplete_database_present;
        }
        fs::remove_file(&truncated).map_err(|e| e.to_string())?;
        if !options.retain {
            fs::remove_file(&capture).map_err(|e| format!("remove owned stress fixture: {e}"))?;
        }
        results.push(FixtureResult {
            nominal_gib: *size,
            actual_bytes: bytes,
            packets,
            generation_ms,
            analysis,
            cancellation,
            truncation,
            indexing,
            index_cancellation,
        });
    }
    let version = if options.engine == AnalysisEngine::Sensor {
        Some(
            Command::new(&options.sensor)
                .arg("version")
                .output()
                .map_err(|e| format!("read sensor version: {e}"))?,
        )
    } else {
        None
    };
    let (revision, dirty_end) = source_state();
    let dirty = dirty_start
        .zip(dirty_end)
        .map(|(start, end)| start || end || revision_start != revision);
    let report = serde_json::json!({"schema_version":1,"mode":"resource_benchmark","analysis_backend":options.engine,"application_version":env!("CARGO_PKG_VERSION"),"platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,
        "logical_cpus":thread::available_parallelism().ok().map(std::num::NonZeroUsize::get),"processor":std::env::var("PROCESSOR_IDENTIFIER").ok(),"revision":revision,"revision_start":revision_start,"working_tree_dirty":dirty,"working_tree_dirty_at_start":dirty_start,"working_tree_dirty_at_end":dirty_end,
        "sensor_version":version.as_ref().map(|version|String::from_utf8_lossy(&version.stdout).trim().to_string()),"sensor_sha256":if options.engine==AnalysisEngine::Sensor {Some(digest_file(&options.sensor)?)}else{None},"benchmark_sha256":digest_file(&std::env::current_exe().map_err(|e|e.to_string())?)?,
        "profile":"valid Ethernet/IPv4/UDP, 1514-byte frames, 64 fixed flows, documentation addresses; no accuracy labels",
        "sample_interval_ms":options.sample.as_millis(),"checks_passed":all_checks_passed,"fixtures_retained":options.retain,"results":results,
        "limitations":["Newly written files may be served from the operating-system cache; cold-cache performance is not claimed.","Memory is sampled concurrent resident memory of this process and its descendants; very short-lived children can be missed.","Per-process high-water marks, where available, cover each process lifetime and need not occur simultaneously.","This fixed-flow stress profile does not estimate detection accuracy, adversarial worst-case complexity, or all protocol workloads."]});
    tracehound_eval::store::write_new(&options.output, &report)?;
    eprintln!("Saved reproducible benchmark report; checks_passed={all_checks_passed}");
    if !all_checks_passed {
        return Err("one or more benchmark safety checks failed; see saved report".into());
    }
    Ok(())
}

fn source_state() -> (Option<String>, Option<bool>) {
    let revision = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string());
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| !output.stdout.is_empty());
    (revision, dirty)
}

fn measure_index(
    capture: &Path,
    destination: &Path,
    bytes: u64,
    options: &Options,
    cancel_after: Option<Duration>,
    interrupted: &AtomicBool,
) -> Result<IndexMeasurement, String> {
    use tracehound_eval::investigation::CaseIndex;
    let sampler = Sampler::start(options.sample);
    let started = Instant::now();
    let requested = AtomicBool::new(false);
    let cancelled = || {
        let stop = interrupted.load(Ordering::Acquire)
            || cancel_after.is_some_and(|delay| started.elapsed() >= delay);
        if stop {
            requested.store(true, Ordering::Relaxed);
        }
        stop
    };
    let outcome = CaseIndex::build(capture, destination, &cancelled, &mut |_| {});
    let elapsed = started.elapsed();
    let memory = sampler.finish();
    let mut measurement = IndexMeasurement {
        elapsed_ms: elapsed.as_millis(),
        mib_per_second: None,
        indexed_packets: None,
        flows: None,
        index_bytes: None,
        reopen_ms: None,
        cancellation_requested: requested.load(Ordering::Relaxed),
        error: None,
        incomplete_database_present: false,
        memory,
    };
    match outcome {
        Ok(overview) => {
            measurement.indexed_packets = Some(overview.packets);
            measurement.flows = Some(overview.flows);
            measurement.index_bytes =
                Some(fs::metadata(destination).map_err(|e| e.to_string())?.len());
            if elapsed.as_secs_f64() > 0.0 {
                measurement.mib_per_second =
                    Some(bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64());
            }
            let reopen = Instant::now();
            let index = CaseIndex::open(destination)?;
            measurement.reopen_ms = Some(reopen.elapsed().as_millis());
            drop(index);
            fs::remove_file(destination)
                .map_err(|e| format!("remove owned benchmark index: {e}"))?;
        }
        Err(error) => {
            measurement.error =
                Some(error.replace(&options.work.display().to_string(), "<workdir>"));
            measurement.incomplete_database_present = destination.exists();
        }
    }
    Ok(measurement)
}

fn measure(
    operation: &'static str,
    capture: &Path,
    bytes: u64,
    temporary: &Path,
    options: &Options,
    cancel_after: Option<Duration>,
    interrupted: &AtomicBool,
) -> Result<Measurement, String> {
    let sampler = Sampler::start(options.sample);
    let started = Instant::now();
    let job = CaptureJob::analyze(
        capture.to_path_buf(),
        SensorOptions {
            engine: options.engine,
            executable: options.sensor.clone().into_os_string(),
            timeout: Duration::ZERO,
            ..Default::default()
        },
        Severity::Low,
    )
    .map_err(|e| e.to_string())?;
    let mut cancelled = None;
    let outcome = loop {
        if cancelled.is_none()
            && (interrupted.load(Ordering::Acquire)
                || cancel_after.is_some_and(|delay| started.elapsed() >= delay))
            && job.cancel()
        {
            cancelled = Some(Instant::now());
        }
        if let Some(outcome) = job.try_result() {
            break outcome;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let elapsed = started.elapsed();
    let cancellation_cleanup_ms = cancelled.map(|time| time.elapsed().as_millis());
    let state = format!("{:?}", job.snapshot().state);
    let memory = sampler.finish();
    let leftovers = fs::read_dir(temporary).map_err(|e| e.to_string())?.count();
    let mut measurement = Measurement {
        operation,
        elapsed_ms: elapsed.as_millis(),
        input_bytes: bytes,
        mib_per_second: None,
        packets_per_second: None,
        input_packets: None,
        output_packets: None,
        alert_records: None,
        unique_findings: None,
        state,
        error: None,
        cancellation_requested: cancelled.is_some(),
        cancellation_cleanup_ms,
        completed_report: false,
        leftover_preparation_entries: leftovers,
        memory,
    };
    match outcome {
        Ok(report) => {
            let JobReport::Analysis(report) = report.as_ref() else {
                return Err("benchmark received another report type".into());
            };
            measurement.completed_report = true;
            measurement.input_packets = report.enrichment["input_packets"].as_u64();
            measurement.output_packets = report.enrichment["output_packets"].as_u64();
            measurement.alert_records = Some(report.report.total_alerts);
            measurement.unique_findings = Some(report.report.findings.len());
            if elapsed.as_secs_f64() > 0.0 {
                measurement.mib_per_second =
                    Some(bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64());
                measurement.packets_per_second = measurement
                    .input_packets
                    .map(|packets| packets as f64 / elapsed.as_secs_f64());
            }
        }
        Err(error) => {
            let mut message = error
                .to_string()
                .replace(&options.work.display().to_string(), "<workdir>");
            if options.engine == AnalysisEngine::Sensor {
                message = message.replace(&options.sensor.display().to_string(), "<sensor>");
            }
            measurement.error = Some(message);
        }
    }
    Ok(measurement)
}

fn digest_file(path: &Path) -> Result<String, String> {
    let mut input = File::open(path).map_err(|e| e.to_string())?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let read = input.read(&mut buffer).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|part| u16::from_be_bytes([part[0], *part.get(1).unwrap_or(&0)]) as u32)
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

fn frame(flow: u16) -> Vec<u8> {
    let mut packet = vec![0; FRAME_BYTES];
    packet[..14].copy_from_slice(&[2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0]);
    let ip = &mut packet[14..34];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&1500u16.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[10, 203, 0, 10]);
    ip[16..20].copy_from_slice(&[192, 0, 2, 10]);
    let digest = checksum(ip);
    ip[10..12].copy_from_slice(&digest.to_be_bytes());
    packet[34..36].copy_from_slice(&(40000 + flow).to_be_bytes());
    packet[36..38].copy_from_slice(&9000u16.to_be_bytes());
    packet[38..40].copy_from_slice(&1480u16.to_be_bytes());
    // IPv4 permits an omitted UDP checksum. Opaque data never resembles a
    // ClientHello or DNS packet and is not labelled as normal network activity.
    packet[42..].fill(0x19);
    packet
}

fn generate(path: &Path, target: u64, cancelled: &dyn Fn() -> bool) -> Result<(u64, u64), String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);
        let mut header = Vec::new();
        header.extend(0xa1b2c3d4u32.to_le_bytes());
        header.extend(2u16.to_le_bytes());
        header.extend(4u16.to_le_bytes());
        header.extend([0; 8]);
        header.extend(65535u32.to_le_bytes());
        header.extend(1u32.to_le_bytes());
        writer.write_all(&header).map_err(|e| e.to_string())?;
        let frames: Vec<_> = (0..64).map(frame).collect();
        let mut bytes = 24;
        let mut packets = 0u64;
        while bytes < target {
            if packets.is_multiple_of(4096) && cancelled() {
                return Err("stress fixture generation cancelled".into());
            }
            writer
                .write_all(&(1_700_000_000 + packets / 10000).to_le_bytes()[..4])
                .map_err(|e| e.to_string())?;
            writer
                .write_all(&((packets % 10000) as u32 * 100).to_le_bytes())
                .map_err(|e| e.to_string())?;
            writer
                .write_all(&(FRAME_BYTES as u32).to_le_bytes())
                .map_err(|e| e.to_string())?;
            writer
                .write_all(&(FRAME_BYTES as u32).to_le_bytes())
                .map_err(|e| e.to_string())?;
            writer
                .write_all(&frames[(packets % 64) as usize])
                .map_err(|e| e.to_string())?;
            packets += 1;
            bytes += 16 + FRAME_BYTES as u64;
        }
        writer
            .flush()
            .and_then(|()| writer.get_ref().sync_all())
            .map_err(|e| e.to_string())?;
        Ok((bytes, packets))
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

#[derive(Clone, Copy)]
struct Process {
    id: u32,
    parent: u32,
    rss: u64,
    peak: Option<u64>,
}

struct Sampler {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Memory>>,
}
impl Sampler {
    fn start(interval: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut memory = Memory::default();
            let mut peaks = BTreeMap::new();
            let mut seen = BTreeSet::new();
            while !flag.load(Ordering::Acquire) {
                match process_tree(std::process::id()) {
                    Ok(processes) if !processes.is_empty() => {
                        let rss = processes.iter().map(|process| process.rss).sum();
                        if memory.samples == 0 {
                            memory.baseline_tree_rss_bytes = rss;
                        }
                        memory.sampled_peak_tree_rss_bytes =
                            memory.sampled_peak_tree_rss_bytes.max(rss);
                        memory.samples += 1;
                        for process in processes {
                            seen.insert(process.id);
                            if let Some(peak) = process.peak {
                                let previous = peaks.entry(process.id).or_insert(0);
                                *previous = (*previous).max(peak);
                            }
                        }
                    }
                    _ => memory.unavailable_samples += 1,
                }
                thread::sleep(interval);
            }
            memory.observed_processes = seen.len();
            if !peaks.is_empty() {
                memory.sum_observed_process_lifetime_peak_rss_bytes = Some(peaks.values().sum());
            }
            memory
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> Memory {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .and_then(|worker| worker.join().ok())
            .unwrap_or_default()
    }
}
impl Drop for Sampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn descendants(root: u32, processes: Vec<Process>) -> Vec<Process> {
    let mut ids = BTreeSet::from([root]);
    loop {
        let before = ids.len();
        for process in &processes {
            if ids.contains(&process.parent) {
                ids.insert(process.id);
            }
        }
        if ids.len() == before {
            break;
        }
    }
    processes
        .into_iter()
        .filter(|process| ids.contains(&process.id))
        .collect()
}

#[cfg(target_os = "linux")]
fn process_tree(root: u32) -> Result<Vec<Process>, String> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc").map_err(|e| e.to_string())? {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(id) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(status) = fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let number = |field: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .and_then(|line| line.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
        };
        if let (Some(parent), Some(rss)) = (number("PPid:"), number("VmRSS:")) {
            processes.push(Process {
                id,
                parent: parent as u32,
                rss: rss * 1024,
                peak: number("VmHWM:").map(|value| value * 1024),
            });
        }
    }
    Ok(descendants(root, processes))
}

#[cfg(target_os = "macos")]
fn process_tree(root: u32) -> Result<Vec<Process>, String> {
    use std::process::Stdio;
    let child = Command::new("ps")
        .args(["-axo", "pid=,ppid=,rss="])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let monitor = child.id();
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("ps process sampling failed".into());
    }
    let processes = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let id = fields.next()?.parse().ok()?;
            let parent = fields.next()?.parse().ok()?;
            let rss = fields.next()?.parse::<u64>().ok()? * 1024;
            (id != monitor).then_some(Process {
                id,
                parent,
                rss,
                peak: None,
            })
        })
        .collect();
    Ok(descendants(root, processes))
}

#[cfg(windows)]
fn process_tree(root: u32) -> Result<Vec<Process>, String> {
    use std::ffi::c_void;
    type Handle = *mut c_void;
    #[repr(C)]
    struct Entry {
        size: u32,
        usage: u32,
        id: u32,
        heap: usize,
        module: u32,
        threads: u32,
        parent: u32,
        priority: i32,
        flags: u32,
        name: [u16; 260],
    }
    #[repr(C)]
    struct Counters {
        size: u32,
        faults: u32,
        peak: usize,
        rss: usize,
        quota_peak_paged: usize,
        quota_paged: usize,
        quota_peak_nonpaged: usize,
        quota_nonpaged: usize,
        pagefile: usize,
        peak_pagefile: usize,
        private: usize,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, id: u32) -> Handle;
        fn Process32FirstW(snapshot: Handle, entry: *mut Entry) -> i32;
        fn Process32NextW(snapshot: Handle, entry: *mut Entry) -> i32;
        fn OpenProcess(access: u32, inherit: i32, id: u32) -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
    }
    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetProcessMemoryInfo(process: Handle, counters: *mut Counters, size: u32) -> i32;
    }
    struct Owned(Handle);
    impl Drop for Owned {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    // Toolhelp supplies only process/parent identifiers; memory is queried only
    // for this benchmark and its descendants, without command-line collection.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(2, 0);
        if snapshot as isize == -1 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let snapshot = Owned(snapshot);
        let mut entry: Entry = std::mem::zeroed();
        entry.size = std::mem::size_of::<Entry>() as u32;
        let mut processes = Vec::new();
        if Process32FirstW(snapshot.0, &mut entry) != 0 {
            loop {
                processes.push(Process {
                    id: entry.id,
                    parent: entry.parent,
                    rss: 0,
                    peak: None,
                });
                if Process32NextW(snapshot.0, &mut entry) == 0 {
                    break;
                }
            }
        }
        let mut measured = Vec::new();
        for process in descendants(root, processes) {
            let handle = OpenProcess(0x0400 | 0x0010, 0, process.id);
            if handle.is_null() {
                continue;
            }
            let handle = Owned(handle);
            let mut counters: Counters = std::mem::zeroed();
            counters.size = std::mem::size_of::<Counters>() as u32;
            if GetProcessMemoryInfo(handle.0, &mut counters, counters.size) != 0 {
                measured.push(Process {
                    rss: counters.rss as u64,
                    peak: Some(counters.peak as u64),
                    ..process
                });
            }
        }
        Ok(measured)
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn process_tree(_root: u32) -> Result<Vec<Process>, String> {
    Err("resident-memory sampling unavailable on this platform".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn memory_sampler_covers_current_process_and_excludes_unrelated_processes() {
        let processes = process_tree(std::process::id()).unwrap();
        assert!(processes
            .iter()
            .any(|process| process.id == std::process::id() && process.rss > 0));
        let tree = descendants(
            1,
            vec![
                Process {
                    id: 1,
                    parent: 0,
                    rss: 1,
                    peak: None,
                },
                Process {
                    id: 2,
                    parent: 1,
                    rss: 1,
                    peak: None,
                },
                Process {
                    id: 3,
                    parent: 2,
                    rss: 1,
                    peak: None,
                },
                Process {
                    id: 4,
                    parent: 0,
                    rss: 1,
                    peak: None,
                },
            ],
        );
        assert_eq!(
            tree.iter().map(|process| process.id).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }
    #[test]
    fn stress_packets_have_valid_ip_lengths_checksum_and_bounded_flow_count() {
        let packet = frame(63);
        assert_eq!(packet.len(), 1514);
        assert_eq!(checksum(&packet[14..34]), 0);
        assert_eq!(u16::from_be_bytes([packet[34], packet[35]]), 40063);
        assert_eq!(u16::from_be_bytes([packet[38], packet[39]]), 1480);
    }
}
