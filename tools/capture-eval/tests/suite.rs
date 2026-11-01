//! Exercise suite progress and cancellation with a small executable sensor.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tracehound_eval::runtime::SensorOptions;
use tracehound_eval::suite::{load_suite, SuiteJob, SuiteState};
use tracehound_eval::{CaptureCase, Expectation, Severity, Suite};

struct Fixture {
    directory: PathBuf,
    parent: PathBuf,
    executable: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let directory = parent.join(format!(
            "tracehound suite {} {}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("sensor.rs"), r##"
use std::io::Write;
fn main() {
    let path = std::path::PathBuf::from(std::env::args_os().nth(2).unwrap());
    let mode = std::fs::read(&path).unwrap()[0];
    if mode == b'e' { eprintln!("intentional sensor failure"); std::process::exit(7); }
    for observations in [4, 8] {
        println!(r#"{{"rule_id":"TH-0001","severity":"high","src":"10.7.0.99","dst":"198.51.100.23","title":"Captured finding","evidence":{{"observations":{observations}}}}}"#);
    }
    std::io::stdout().flush().unwrap();
    std::fs::write(path.with_extension("started"), b"ready").unwrap();
    if mode == b'b' {
        while !path.with_extension("release").exists() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
"##).unwrap();
        let name = format!("sensor{}", std::env::consts::EXE_SUFFIX);
        let mut compiler =
            Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()));
        compiler
            .current_dir(&directory)
            .args(["--edition=2021", "sensor.rs", "-o", &name]);
        if cfg!(all(windows, target_env = "gnu")) {
            compiler.args(["-C", "link-self-contained=yes"]);
        }
        let output = compiler.output().unwrap();
        assert!(
            output.status.success(),
            "fixture compile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let executable = directory.join(name);
        Self {
            directory,
            parent,
            executable,
        }
    }
    fn capture(&self, name: &str, mode: u8) -> PathBuf {
        let path = self.directory.join(name);
        fs::write(&path, [mode]).unwrap();
        path
    }
    fn manifest(&self, first: &Path, second: &Path, first_rule: &str) -> PathBuf {
        let suite = Suite {
            schema_version: 1,
            captures: vec![
                case("first", first, first_rule),
                case("second", second, "TH-0001"),
            ],
        };
        let path = self.directory.join("labelled suite.json");
        fs::write(&path, serde_json::to_vec_pretty(&suite).unwrap()).unwrap();
        path
    }
    fn options(&self) -> SensorOptions {
        SensorOptions {
            executable: self.executable.clone().into_os_string(),
            timeout: Duration::from_secs(10),
            ..Default::default()
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Ok(path) = fs::canonicalize(&self.directory) {
            if path.parent() == Some(self.parent.as_path())
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("tracehound suite "))
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}

fn case(name: &str, capture: &Path, rule: &str) -> CaptureCase {
    CaptureCase {
        name: name.into(),
        capture: PathBuf::from(capture.file_name().unwrap()),
        expected: vec![Expectation {
            rule_id: rule.into(),
            src: "10.7.0.99".parse().unwrap(),
            dst: None,
        }],
        benign_hosts: Vec::new(),
        min_severity: Severity::Low,
    }
}

fn until(mut predicate: impl FnMut() -> bool, description: &str) {
    let started = Instant::now();
    while !predicate() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "timed out waiting for {description}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn two_case_suite_reports_current_case_and_aggregates_finished_results() {
    let fixture = Fixture::new();
    let first = fixture.capture("first capture.pcap", b'b');
    let second = fixture.capture("second capture.pcapng", b's');
    let job = SuiteJob::start(
        fixture.manifest(&first, &second, "TH-0001"),
        fixture.options(),
    )
    .unwrap();
    until(
        || first.with_extension("started").exists() && job.snapshot().alert_records == 2,
        "first capture progress",
    );
    let progress = job.snapshot();
    assert_eq!(progress.state, SuiteState::Running);
    assert_eq!(progress.total, 2);
    assert_eq!(progress.completed, 0);
    assert_eq!(progress.current.as_deref(), Some("first"));
    assert_eq!(progress.unique_findings, 1);
    assert!(!second.with_extension("started").exists());
    fs::write(first.with_extension("release"), b"continue").unwrap();
    until(|| job.try_result().is_some(), "suite completion");
    let report = job.wait().unwrap();
    assert!(report.passed);
    assert_eq!(report.captures.len(), 2);
    assert_eq!(report.summary.matched_expectations, 2);
    assert_eq!(report.summary.unique_findings, 2);
    let completed = job.snapshot();
    assert_eq!(completed.state, SuiteState::Completed);
    assert_eq!(completed.completed, 2);
    assert!(completed.current.is_none());
    assert!(!job.cancel());
}

#[test]
fn cancelling_second_case_retains_progress_without_a_completed_report() {
    let fixture = Fixture::new();
    let first = fixture.capture("first capture.pcap", b's');
    let second = fixture.capture("second capture.pcap", b'b');
    let job = SuiteJob::start(
        fixture.manifest(&first, &second, "TH-0001"),
        fixture.options(),
    )
    .unwrap();
    until(
        || second.with_extension("started").exists() && job.snapshot().alert_records == 4,
        "second capture progress",
    );
    assert_eq!(job.snapshot().completed, 1);
    assert_eq!(job.snapshot().unique_findings, 2);
    assert_eq!(job.snapshot().current.as_deref(), Some("second"));
    assert!(job.cancel());
    until(|| job.try_result().is_some(), "cancelled suite cleanup");
    assert!(job.wait().unwrap_err().contains("cancel"));
    assert_eq!(job.snapshot().state, SuiteState::Cancelled);
    assert_eq!(job.snapshot().completed, 1);
    assert!(!job.cancel());
}

#[test]
fn detection_mismatch_completes_but_sensor_failure_fails_the_suite() {
    let fixture = Fixture::new();
    let first = fixture.capture("first capture.pcap", b's');
    let second = fixture.capture("second capture.pcap", b's');
    let job = SuiteJob::start(
        fixture.manifest(&first, &second, "TH-0002"),
        fixture.options(),
    )
    .unwrap();
    until(|| job.try_result().is_some(), "mismatched suite completion");
    let report = job.wait().unwrap();
    assert!(!report.passed);
    assert_eq!(report.summary.failed, 1);
    assert_eq!(report.summary.missed_expectations, 1);
    assert_eq!(report.summary.unexpected_findings, 1);
    assert_eq!(job.snapshot().state, SuiteState::Completed);
    fs::write(&second, b"e").unwrap();
    let job = SuiteJob::start(
        fixture.manifest(&first, &second, "TH-0001"),
        fixture.options(),
    )
    .unwrap();
    until(|| job.try_result().is_some(), "failed suite cleanup");
    let error = job.wait().unwrap_err();
    assert!(error.contains("second"), "missing case context: {error}");
    assert_eq!(job.snapshot().state, SuiteState::Failed);
    assert_eq!(job.snapshot().completed, 1);
    assert!(job.snapshot().error.is_some());
}

#[test]
fn missing_second_capture_is_rejected_before_any_sensor_starts() {
    let fixture = Fixture::new();
    let first = fixture.capture("first capture.pcap", b'b');
    let missing = fixture.directory.join("missing.pcap");
    let manifest = fixture.manifest(&first, &missing, "TH-0001");
    assert!(load_suite(&manifest).is_err());
    assert!(SuiteJob::start(manifest, fixture.options()).is_err());
    assert!(!first.with_extension("started").exists());
}
