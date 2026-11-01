//! Exercise the user-facing CLI with independently encoded capture files.
//! These fixtures use ordinary capture containers and wire checksums, without
//! Tracehound's demo generator or packet-building code.

use serde_json::{json, Value};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
    parent: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).expect("resolve temporary directory");
        let path = parent.join(format!(
            "tracehound capture eval {} {} {}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create isolated test directory");
        Self { path, parent }
    }

    fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.path.join(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        // Only remove the exact directory this test created, after verifying
        // its resolved path remains immediately under the temporary root.
        if let Ok(target) = fs::canonicalize(&self.path) {
            if target.parent() == Some(self.parent.as_path())
                && target.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with("tracehound capture eval ")
                })
            {
                let _ = fs::remove_dir_all(target);
            }
        }
    }
}

fn sensor() -> Option<PathBuf> {
    let Some(path) = std::env::var_os("TRACEHOUND_TEST_SENSOR") else {
        eprintln!("skipping sensor-dependent integration test: set TRACEHOUND_TEST_SENSOR to a built Tracehound executable");
        return None;
    };
    Some(fs::canonicalize(path).expect("TRACEHOUND_TEST_SENSOR must name an existing executable"))
}

fn evaluator() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tracehound-eval"))
}

fn assert_code(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid report: {error}; stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

#[test]
fn report_history_open_and_comparison_work_without_reanalysing_captures() {
    let Some(sensor) = sensor() else {
        return;
    };
    let directory = TestDirectory::new();
    let capture = directory.join("office.pcap");
    write_pcap(&capture, &benign_frames());
    let history = directory.join("history");
    let saved = directory.join("report.json");
    let output = evaluator()
        .arg("analyze")
        .arg(&capture)
        .arg("--sensor")
        .arg(sensor)
        .args(["--save-history", "--history-dir"])
        .arg(&history)
        .arg("--output")
        .arg(&saved)
        .output()
        .unwrap();
    assert_code(&output, 0);
    let output = evaluator()
        .args(["history", "--history-dir"])
        .arg(&history)
        .output()
        .unwrap();
    assert_code(&output, 0);
    let entries: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(entries.len(), 1);
    let output = evaluator().arg("open").arg(&saved).output().unwrap();
    assert_code(&output, 0);
    assert_eq!(report(&output)["mode"], "analysis");
    let output = evaluator()
        .arg("compare")
        .arg(&saved)
        .arg(&saved)
        .output()
        .unwrap();
    assert_code(&output, 0);
    let changes = report(&output);
    assert_eq!(changes["added"], json!([]));
    assert_eq!(changes["removed"], json!([]));
    assert_eq!(changes["changed"], json!([]));
}

#[test]
fn cached_corpus_outputs_reopen_with_provenance_and_unlabelled_cases() {
    use sha2::{Digest, Sha256};
    let Some(sensor) = sensor() else {
        return;
    };
    let directory = TestDirectory::new();
    let cache = directory.join("corpus");
    fs::create_dir(&cache).unwrap();
    let capture = cache.join("office.pcap");
    write_pcap(&capture, &benign_frames());
    let bytes = fs::read(&capture).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    for labelled in [true, false] {
        let mut entry = json!({"id":"external-office","filename":"office.pcap","url":"https://example.test/office.pcap","source_url":"https://example.test/source","sha256":digest,"bytes":bytes.len(),"license":"Test capture","description":"Independent normal wire fixture","classification":"fixture","min_severity":"low"});
        if labelled {
            entry["expected"] = json!([]);
        }
        let manifest = directory.join(format!("manifest-{labelled}.json"));
        write_json(&manifest, &json!({"schema_version":1,"captures":[entry]}));
        let saved = directory.join(format!("corpus-{labelled}.json"));
        let history = directory.join("history");
        let output = evaluator()
            .arg("corpus")
            .arg(&cache)
            .arg("--manifest")
            .arg(&manifest)
            .arg("--sensor")
            .arg(&sensor)
            .arg("--json")
            .arg("--output")
            .arg(&saved)
            .args(["--save-history", "--history-dir"])
            .arg(&history)
            .output()
            .unwrap();
        assert_code(&output, 0);
        let output = evaluator().arg("open").arg(&saved).output().unwrap();
        assert_code(&output, 0);
        let reopened = report(&output);
        assert_eq!(reopened["sources"][0]["sha256"], digest);
        if labelled {
            assert_eq!(reopened["evaluation"]["summary"]["captures"], 1);
        } else {
            assert_eq!(reopened["observations"].as_array().unwrap().len(), 1);
            assert!(reopened["evaluation"]["summary"]["precision"].is_null());
        }
        let output = evaluator()
            .arg("compare")
            .arg(&saved)
            .arg(&saved)
            .output()
            .unwrap();
        assert_code(&output, 0);
    }
}

// Internet checksums use big-endian 16-bit words and one's-complement addition.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn syn_frame(source: [u8; 4], destination: [u8; 4], source_port: u16, port: u16) -> Vec<u8> {
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&40u16.to_be_bytes());
    ip[4..6].copy_from_slice(&source_port.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&source);
    ip[16..20].copy_from_slice(&destination);
    let ip_checksum = checksum(&ip);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&port.to_be_bytes());
    tcp[4..8].copy_from_slice(&1u32.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x02;
    tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
    let mut pseudoheader = Vec::from(source);
    pseudoheader.extend(destination);
    pseudoheader.extend([0, 6]);
    pseudoheader.extend(20u16.to_be_bytes());
    pseudoheader.extend(tcp);
    let tcp_checksum = checksum(&pseudoheader);
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());

    let mut frame = vec![2, 0, 0, 0, 0, 10, 2, 0, 0, 0, 0, 99, 0x08, 0x00];
    frame.extend(ip);
    frame.extend(tcp);
    frame
}

fn scan_frames() -> Vec<Vec<u8>> {
    (0..128)
        .map(|index| syn_frame([10, 7, 0, 99], [10, 7, 0, 10], 40000 + index, 1000 + index))
        .collect()
}

fn benign_frames() -> Vec<Vec<u8>> {
    vec![syn_frame([10, 7, 0, 10], [192, 0, 2, 20], 51000, 443)]
}

fn write_pcap(path: &Path, frames: &[Vec<u8>]) {
    let mut bytes = Vec::new();
    bytes.extend(0xa1b2c3d4u32.to_le_bytes());
    bytes.extend(2u16.to_le_bytes());
    bytes.extend(4u16.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(65535u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes()); // Ethernet link type.
    for (index, frame) in frames.iter().enumerate() {
        bytes.extend((1_700_000_000 + index as u32 / 10).to_le_bytes());
        bytes.extend(((index as u32 % 10) * 100_000).to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend(frame);
    }
    fs::write(path, bytes).unwrap();
}

fn write_pcapng(path: &Path, frames: &[Vec<u8>]) {
    let mut bytes = Vec::new();
    // Section Header Block, little-endian, version 1.0, unspecified section size.
    bytes.extend(0x0a0d0d0au32.to_le_bytes());
    bytes.extend(28u32.to_le_bytes());
    bytes.extend(0x1a2b3c4du32.to_le_bytes());
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend(u64::MAX.to_le_bytes());
    bytes.extend(28u32.to_le_bytes());
    // Interface Description Block; default timestamp resolution is microseconds.
    bytes.extend(1u32.to_le_bytes());
    bytes.extend(20u32.to_le_bytes());
    bytes.extend(1u16.to_le_bytes());
    bytes.extend(0u16.to_le_bytes());
    bytes.extend(65535u32.to_le_bytes());
    bytes.extend(20u32.to_le_bytes());
    for (index, frame) in frames.iter().enumerate() {
        let padded = (frame.len() + 3) & !3;
        let block_size = (32 + padded) as u32;
        let timestamp = 1_700_000_000_000_000u64 + index as u64 * 100_000;
        bytes.extend(6u32.to_le_bytes());
        bytes.extend(block_size.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(((timestamp >> 32) as u32).to_le_bytes());
        bytes.extend((timestamp as u32).to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend(frame);
        bytes.resize(bytes.len() + padded - frame.len(), 0);
        bytes.extend(block_size.to_le_bytes());
    }
    fs::write(path, bytes).unwrap();
}

#[test]
fn analyze_user_pcap_retains_evidence_without_accuracy_claims() {
    let Some(sensor) = sensor() else { return };
    let directory = TestDirectory::new();
    let capture = directory.join("office scan capture.pcap");
    write_pcap(&capture, &scan_frames());
    // Exercise executable paths containing spaces too, not just capture paths.
    let copied_sensor = directory.join(if cfg!(windows) {
        "Tracehound sensor with spaces.exe"
    } else {
        "Tracehound sensor with spaces"
    });
    fs::copy(sensor, &copied_sensor).unwrap();
    let output = evaluator()
        .arg("analyze")
        .arg(&capture)
        .arg("--sensor")
        .arg(copied_sensor)
        .arg("--json")
        .output()
        .unwrap();
    assert_code(&output, 0);
    let report = report(&output);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["mode"], "analysis");
    assert!(report.get("passed").is_none());
    assert!(report.get("precision").is_none());
    assert!(report.get("recall").is_none());
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "unexpected findings: {report}");
    assert_eq!(findings[0]["alert"]["rule_id"], "TH-0003");
    assert_eq!(findings[0]["alert"]["src"], "10.7.0.99");
    assert_eq!(findings[0]["alert"]["dst"], "10.7.0.10");
    assert_eq!(findings[0]["alert"]["severity"], "high");
    assert_eq!(findings[0]["alert"]["evidence"]["ports_probed"], 128);
    assert!(findings[0]["occurrences"].as_u64().unwrap() > 0);
}

#[test]
fn analyze_user_pcapng_accepts_benign_capture_without_labels() {
    let Some(sensor) = sensor() else { return };
    let directory = TestDirectory::new();
    let capture = directory.join("ordinary office traffic.pcapng");
    write_pcapng(&capture, &benign_frames());
    let output = evaluator()
        .arg("analyze")
        .arg(&capture)
        .arg("--sensor")
        .arg(sensor)
        .arg("--json")
        .output()
        .unwrap();
    assert_code(&output, 0);
    let report = report(&output);
    assert_eq!(report["mode"], "analysis");
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert!(report.get("passed").is_none());
    assert!(report.get("precision").is_none());
    assert!(report.get("recall").is_none());
}

#[test]
fn evaluate_relative_capture_paths_returns_pass_or_detection_mismatch() {
    let Some(sensor) = sensor() else { return };
    let directory = TestDirectory::new();
    fs::create_dir(directory.join("captures")).unwrap();
    fs::create_dir(directory.join("labels")).unwrap();
    write_pcap(
        &directory.join("captures/scan capture.pcap"),
        &scan_frames(),
    );
    write_pcapng(&directory.join("captures/benign.pcapng"), &benign_frames());
    let suite_path = directory.join("labels/office suite.json");
    let mut suite = json!({
        "schema_version": 1,
        "captures": [
            {
                "name": "Labelled scan",
                "capture": "../captures/scan capture.pcap",
                "expected": [{"rule_id": "TH-0003", "src": "10.7.0.99", "dst": "10.7.0.10"}],
                "benign_hosts": ["10.7.0.10"],
                "min_severity": "low"
            },
            {
                "name": "Benign baseline",
                "capture": "../captures/benign.pcapng",
                "expected": [],
                "benign_hosts": ["10.7.0.10"]
            }
        ]
    });
    write_json(&suite_path, &suite);
    let output = evaluator()
        .current_dir(&directory.path)
        .arg("evaluate")
        .arg(&suite_path)
        .arg("--sensor")
        .arg(&sensor)
        .arg("--json")
        .output()
        .unwrap();
    assert_code(&output, 0);
    let passed = report(&output);
    assert_eq!(passed["passed"], true);
    assert_eq!(passed["summary"]["captures"], 2);
    assert_eq!(passed["summary"]["passed"], 2);
    assert_eq!(passed["summary"]["matched_expectations"], 1);
    assert_eq!(passed["summary"]["missed_expectations"], 0);
    assert_eq!(passed["summary"]["unexpected_findings"], 0);
    assert_eq!(passed["summary"]["precision"], 1.0);
    assert_eq!(passed["summary"]["recall"], 1.0);

    suite["captures"][0]["expected"][0]["rule_id"] = json!("TH-0002");
    write_json(&suite_path, &suite);
    let output = evaluator()
        .arg("evaluate")
        .arg(suite_path)
        .arg("--sensor")
        .arg(sensor)
        .arg("--json")
        .output()
        .unwrap();
    assert_code(&output, 1);
    let mismatch = report(&output);
    assert_eq!(mismatch["passed"], false);
    assert_eq!(mismatch["summary"]["missed_expectations"], 1);
    assert_eq!(mismatch["summary"]["unexpected_findings"], 1);
    assert_eq!(
        mismatch["captures"][0]["missed_expectations"][0]["rule_id"],
        "TH-0002"
    );
    assert_eq!(
        mismatch["captures"][0]["unexpected_findings"][0]["alert"]["rule_id"],
        "TH-0003"
    );
}

#[test]
fn malformed_suite_is_an_input_error_without_a_success_report() {
    let directory = TestDirectory::new();
    let suite = directory.join("invalid suite.json");
    write_json(
        &suite,
        &json!({"schema_version": 1, "captures": [{"name": "unlabelled", "capture": "office.pcap"}]}),
    );
    let output = evaluator()
        .arg("evaluate")
        .arg(suite)
        .arg("--sensor")
        .arg(directory.join("sensor does not exist"))
        .arg("--json")
        .output()
        .unwrap();
    assert_code(&output, 2);
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected"));
}

#[test]
fn unavailable_sensor_is_an_execution_error() {
    let directory = TestDirectory::new();
    let capture = directory.join("capture.pcap");
    write_pcap(&capture, &benign_frames());
    let output = evaluator()
        .arg("analyze")
        .arg(capture)
        .arg("--sensor")
        .arg(directory.join("sensor does not exist"))
        .arg("--json")
        .output()
        .unwrap();
    assert_code(&output, 2);
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("start sensor"));
}

#[test]
fn corrupt_capture_is_an_error_and_never_creates_a_report() {
    let Some(sensor) = sensor() else { return };
    let directory = TestDirectory::new();
    let capture = directory.join("broken.pcapng");
    let report_path = directory.join("must not exist.json");
    fs::write(&capture, b"not a capture file").unwrap();
    let output = evaluator()
        .arg("analyze")
        .arg(capture)
        .arg("--sensor")
        .arg(sensor)
        .arg("--output")
        .arg(&report_path)
        .arg("--json")
        .output()
        .unwrap();
    assert_code(&output, 2);
    assert!(output.stdout.is_empty());
    assert!(!report_path.exists());
}

#[test]
fn json_report_is_saved_and_existing_output_is_never_overwritten() {
    let Some(sensor) = sensor() else { return };
    let directory = TestDirectory::new();
    let capture = directory.join("office.pcap");
    let report_path = directory.join("office report.json");
    write_pcap(&capture, &benign_frames());
    let output = evaluator()
        .arg("analyze")
        .arg(&capture)
        .arg("--sensor")
        .arg(sensor)
        .arg("--output")
        .arg(&report_path)
        .arg("--json")
        .output()
        .unwrap();
    assert_code(&output, 0);
    let saved = fs::read(&report_path).unwrap();
    let saved_json: Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(saved_json, report(&output));

    let output = evaluator()
        .arg("analyze")
        .arg(capture)
        .arg("--sensor")
        .arg(directory.join("sensor does not exist"))
        .arg("--output")
        .arg(&report_path)
        .arg("--json")
        .output()
        .unwrap();
    assert_code(&output, 2);
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
    assert_eq!(fs::read(report_path).unwrap(), saved);
}

#[test]
fn unknown_threshold_and_missing_capture_are_input_errors() {
    let directory = TestDirectory::new();
    for options in [
        vec![OsStr::new("--min-severity"), OsStr::new("urgent")],
        vec![],
    ] {
        let output = evaluator()
            .arg("analyze")
            .arg(directory.join("capture does not exist.pcap"))
            .args(options)
            .arg("--json")
            .output()
            .unwrap();
        assert_code(&output, 2);
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn suite_validates_all_capture_paths_before_running_any_sensor() {
    let directory = TestDirectory::new();
    let valid_capture = directory.join("available.pcap");
    write_pcap(&valid_capture, &benign_frames());
    let suite = directory.join("suite.json");
    write_json(
        &suite,
        &json!({
            "schema_version": 1,
            "captures": [
                {"name": "Available", "capture": "available.pcap", "expected": []},
                {"name": "Unavailable", "capture": "absent.pcap", "expected": []}
            ]
        }),
    );
    let output = evaluator()
        .arg("evaluate")
        .arg(suite)
        .arg("--sensor")
        .arg(directory.join("sensor does not exist"))
        .arg("--json")
        .output()
        .unwrap();
    assert_code(&output, 2);
    assert!(output.stdout.is_empty());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("absent.pcap"), "{error}");
    assert!(!error.contains("start sensor"), "{error}");
}

#[test]
fn execution_guards_reject_timeout_malformed_output_limits_and_sensor_failure() {
    let directory = TestDirectory::new();
    let source = directory.join("fake_sensor.rs");
    let executable = directory.join(if cfg!(windows) {
        "fake-sensor.exe"
    } else {
        "fake-sensor"
    });
    fs::write(
        &source,
        r##"
use std::io::Write;

fn main() {
    let capture = std::path::PathBuf::from(std::env::args_os().nth(2).expect("capture argument"));
    let mode = std::fs::read(&capture).expect("read fixture")[0];
    match mode {
        b't' => {
            std::fs::write(capture.with_extension("started"), std::process::id().to_string()).unwrap();
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
        b'j' => println!("malformed JSON"),
        b'm' => {
            for _ in 0..3 {
                println!(r#"{{"rule_id":"TH-0001","severity":"high","src":"10.7.0.99"}}"#);
            }
        }
        b'e' => {
            std::io::stderr().write_all(&vec![b'x'; 100_000]).unwrap();
            std::process::exit(3);
        }
        _ => panic!("unknown fixture mode"),
    }
}
"##,
    )
    .unwrap();
    let mut compiler = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()));
    compiler
        .current_dir(&directory.path)
        .arg("--edition=2021")
        .arg("fake_sensor.rs")
        .arg("-o")
        .arg(executable.file_name().unwrap());
    if cfg!(all(windows, target_env = "gnu")) {
        compiler.args(["-C", "link-self-contained=yes"]);
    }
    let built = compiler
        .output()
        .expect("run rustc for isolated fake sensor");
    assert_code(&built, 0);

    let cases: &[(u8, &[&str], &str)] = &[
        (b't', &["--timeout", "1"], "exceeded 1 seconds"),
        (b'j', &[], "invalid sensor JSON"),
        (b'm', &["--max-alerts", "1"], "exceeded 1 alert"),
        (b'e', &[], "sensor exited"),
    ];
    for (mode, options, expected_error) in cases {
        let capture = directory.join(format!("input {}.pcap", *mode as char));
        let output_path = directory.join(format!("report {}.json", *mode as char));
        fs::write(&capture, [*mode]).unwrap();
        let started = std::time::Instant::now();
        let output = evaluator()
            .arg("analyze")
            .arg(capture)
            .arg("--sensor")
            .arg(&executable)
            .args(*options)
            .arg("--output")
            .arg(&output_path)
            .arg("--json")
            .output()
            .unwrap();
        assert_code(&output, 2);
        assert!(output.stdout.is_empty());
        assert!(!output_path.exists());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(expected_error), "{error}");
        if *mode == b't' {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "timeout waited for the sensor's 30-second sleep"
            );
        }
    }

    #[cfg(unix)]
    {
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        let capture = directory.join("interrupted capture.pcap");
        let marker = capture.with_extension("started");
        let report_path = directory.join("interrupted report.json");
        fs::write(&capture, b"t").unwrap();
        let mut child = evaluator()
            .arg("analyze")
            .arg(&capture)
            .arg("--sensor")
            .arg(&executable)
            .args(["--timeout", "0", "--json", "--output"])
            .arg(&report_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let startup = Instant::now();
        let sensor_pid: u32 = loop {
            let pid = fs::read_to_string(&marker)
                .ok()
                .and_then(|contents| contents.parse::<u32>().ok())
                .filter(|pid| *pid > 0);
            if let Some(pid) = pid {
                break pid;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("evaluator exited before the interrupt fixture started: {status}");
            }
            if startup.elapsed() > Duration::from_secs(5) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("interrupt fixture did not start");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let evaluator_pid = child.id().to_string();
        let signal = Command::new("kill")
            .args(["-s", "INT", &evaluator_pid])
            .output()
            .expect("send SIGINT to this test's evaluator process");
        if !signal.status.success() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = Command::new("kill")
                .args(["-s", "KILL", &sensor_pid.to_string()])
                .output();
            panic!(
                "could not interrupt evaluator: {}",
                String::from_utf8_lossy(&signal.stderr)
            );
        }
        let stopping = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if stopping.elapsed() > Duration::from_secs(5) {
                let _ = child.kill();
                let _ = child.wait();
                let _ = Command::new("kill")
                    .args(["-s", "KILL", &sensor_pid.to_string()])
                    .output();
                panic!("evaluator did not finish cleaning up after SIGINT");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = child.wait_with_output().unwrap();
        let sensor_alive = Command::new("kill")
            .args(["-0", &sensor_pid.to_string()])
            .output()
            .expect("check the fixture sensor was reaped");
        if sensor_alive.status.success() {
            let _ = Command::new("kill")
                .args(["-s", "KILL", &sensor_pid.to_string()])
                .output();
        }
        assert_code(&output, 130);
        assert!(
            output.stdout.is_empty(),
            "interrupted analysis printed a success report"
        );
        assert!(!report_path.exists());
        assert!(
            !sensor_alive.status.success(),
            "SIGINT left the sensor process running"
        );
    }
}
