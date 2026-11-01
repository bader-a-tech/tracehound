//! Background-job lifecycle checks use an isolated executable so cancellation
//! and progress can be observed independently of capture size or machine speed.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracehound_eval::runtime::{CaptureJob, JobErrorKind, JobReport, JobState, SensorOptions};
use tracehound_eval::{CaptureCase, Expectation, Severity};

struct Fixture {
    directory: PathBuf,
    parent: PathBuf,
    executable: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).expect("resolve temporary root");
        let directory = parent.join(format!(
            "tracehound runtime {} {}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).expect("create isolated runtime fixture");
        fs::write(
            directory.join("sensor.rs"),
            r##"
use std::io::Write;

fn emit(value: u8) {
    println!(r#"{{"rule_id":"TH-0001","severity":"high","src":"10.7.0.99","dst":"198.51.100.23","title":"Captured finding","evidence":{{"observations":{value}}}}}"#);
    std::io::stdout().flush().unwrap();
}

fn emit_info() {
    println!(r#"{{"rule_id":"TH-0006","severity":"info","src":"10.7.0.10","title":"New device","evidence":{{}}}}"#);
    std::io::stdout().flush().unwrap();
}

fn main() {
    let path = std::path::PathBuf::from(std::env::args_os().nth(2).unwrap());
    match std::fs::read(&path).unwrap()[0] {
        b'b' => {
            emit(1);
            emit(2);
            emit_info();
            std::fs::write(path.with_extension("started"), b"ready").unwrap();
            while !path.with_extension("release").exists() {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        b's' => { emit(1); emit(2); }
        b'l' => { emit(1); emit(2); emit_info(); }
        b't' => std::thread::sleep(std::time::Duration::from_secs(30)),
        b'e' => { eprintln!("sensor failed intentionally"); std::process::exit(7); }
        b'd' => {
            std::fs::write(path.with_extension("started"), b"ready").unwrap();
            std::thread::sleep(std::time::Duration::from_secs(1));
            std::fs::write(path.with_extension("survived"), b"child was not stopped").unwrap();
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
        _ => panic!("unknown runtime fixture mode"),
    }
}
"##,
        )
        .unwrap();
        let name = if cfg!(windows) {
            "sensor.exe"
        } else {
            "sensor"
        };
        let executable = directory.join(name);
        let mut compiler =
            Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()));
        compiler
            .current_dir(&directory)
            .args(["--edition=2021", "sensor.rs", "-o", name]);
        if cfg!(all(windows, target_env = "gnu")) {
            compiler.args(["-C", "link-self-contained=yes"]);
        }
        let output = compiler.output().expect("compile isolated sensor fixture");
        assert!(
            output.status.success(),
            "fixture compile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            directory,
            parent,
            executable,
        }
    }

    fn input(&self, name: &str, mode: u8) -> PathBuf {
        let path = self.directory.join(name);
        fs::write(&path, [mode]).unwrap();
        path
    }

    fn options(&self) -> SensorOptions {
        SensorOptions {
            executable: self.executable.clone().into_os_string(),
            timeout: Duration::from_secs(5),
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
                    .is_some_and(|name| name.to_string_lossy().starts_with("tracehound runtime "))
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}

fn until(mut predicate: impl FnMut() -> bool, description: &str) {
    let started = Instant::now();
    while !predicate() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for {description}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn case(capture: &Path, rule_id: &str) -> CaptureCase {
    CaptureCase {
        name: "A user-labelled capture".into(),
        capture: capture.to_path_buf(),
        expected: vec![Expectation {
            rule_id: rule_id.into(),
            src: "10.7.0.99".parse().unwrap(),
            dst: None,
        }],
        benign_hosts: Vec::new(),
        min_severity: Severity::Low,
    }
}

#[test]
fn jobs_expose_live_progress_and_preserve_distinct_terminal_outcomes() {
    let fixture = Fixture::new();

    // Records and deduplicated findings are available while the child is still
    // blocked. The duplicate and informational event do not add unique findings.
    let blocked = fixture.input("blocked capture.pcap", b'b');
    let job = CaptureJob::analyze(blocked.clone(), fixture.options(), Severity::Low).unwrap();
    until(|| job.snapshot().alert_records == 3, "live alert records");
    let progress = job.snapshot();
    assert_eq!(progress.state, JobState::Running);
    assert_eq!(progress.unique_findings, 1);
    assert!(progress.output_bytes > 0);
    assert!(progress.error.is_none());
    assert!(job.try_result().is_none());

    // Concurrent readers and cancellation callers must not need the child
    // process lock or wait for the blocked output reader.
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let job = &job;
            scope.spawn(move || {
                for _ in 0..10 {
                    let _ = job.snapshot();
                    let _ = job.cancel();
                }
            });
        }
    });
    let cancelled = job.wait().unwrap_err();
    assert_eq!(cancelled.kind, JobErrorKind::Cancelled);
    let status = job.snapshot();
    assert_eq!(status.state, JobState::Cancelled);
    assert!(status.state.is_terminal());
    assert_eq!(status.error.unwrap().kind, JobErrorKind::Cancelled);
    assert!(!job.cancel());

    // Cancellation immediately after Start must be claimed before the worker
    // has a chance to launch. Repeating this covers both scheduling orders.
    for index in 0..4 {
        let input = fixture.input(&format!("immediate {index}.pcap"), b'b');
        let job = CaptureJob::analyze(input, fixture.options(), Severity::Low).unwrap();
        assert!(job.cancel(), "immediate cancellation was lost");
        assert_eq!(job.wait().unwrap_err().kind, JobErrorKind::Cancelled);
    }

    let completed_input = fixture.input("completed.pcap", b's');
    let completed =
        CaptureJob::analyze(completed_input.clone(), fixture.options(), Severity::Low).unwrap();
    let result = completed.wait().unwrap();
    assert_eq!(completed.snapshot().state, JobState::Completed);
    assert_eq!(completed.snapshot().alert_records, 2);
    assert_eq!(completed.snapshot().unique_findings, 1);
    let JobReport::Analysis(report) = result.as_ref() else {
        panic!("analysis job returned evaluation");
    };
    assert_eq!(report.capture, completed_input);
    assert_eq!(report.report.findings.len(), 1);
    assert_eq!(report.report.findings[0].occurrences, 2);
    assert_eq!(report.report.findings[0].alert.evidence["observations"], 2);
    assert!(Arc::ptr_eq(
        &result,
        &completed.try_result().unwrap().unwrap()
    ));
    assert!(!completed.cancel());

    // A labelled detection mismatch is a completed evaluation, not a failure
    // to execute the sensor or obtain a trustworthy report.
    let evaluation = CaptureJob::evaluate(
        completed_input.clone(),
        fixture.options(),
        case(&completed_input, "TH-0002"),
    )
    .unwrap();
    let report = evaluation.wait().unwrap();
    assert_eq!(evaluation.snapshot().state, JobState::Completed);
    let JobReport::Evaluation(report) = report.as_ref() else {
        panic!("evaluation job returned analysis");
    };
    assert!(!report.passed);
    assert_eq!(report.missed_expectations.len(), 1);
    assert_eq!(report.unexpected_findings.len(), 1);

    let timeout_input = fixture.input("timeout.pcap", b't');
    let options = SensorOptions {
        timeout: Duration::from_millis(100),
        ..fixture.options()
    };
    let timeout = CaptureJob::analyze(timeout_input, options, Severity::Low).unwrap();
    assert_eq!(timeout.wait().unwrap_err().kind, JobErrorKind::TimedOut);
    assert_eq!(timeout.snapshot().state, JobState::TimedOut);

    let failed = CaptureJob::analyze(
        fixture.input("failed.pcap", b'e'),
        fixture.options(),
        Severity::Low,
    )
    .unwrap();
    let error = failed.wait().unwrap_err();
    assert_eq!(error.kind, JobErrorKind::SensorFailed);
    assert!(error.message.contains("sensor failed intentionally"));
    assert_eq!(failed.snapshot().state, JobState::Failed);

    // The limit counts every input record, including repeated findings and
    // records below the selected reporting floor.
    for maximum in [1, 2] {
        let limited = CaptureJob::analyze(
            fixture.input(&format!("limited {maximum}.pcap"), b'l'),
            SensorOptions {
                max_alerts: maximum,
                ..fixture.options()
            },
            Severity::Low,
        )
        .unwrap();
        assert_eq!(limited.wait().unwrap_err().kind, JobErrorKind::OutputLimit);
        assert_eq!(limited.snapshot().state, JobState::Failed);
        assert_eq!(limited.snapshot().alert_records, maximum);
        assert_eq!(limited.snapshot().unique_findings, 1);
    }

    let dropped_input = fixture.input("dropped.pcap", b'd');
    let dropped =
        CaptureJob::analyze(dropped_input.clone(), fixture.options(), Severity::Low).unwrap();
    until(
        || dropped_input.with_extension("started").exists(),
        "drop fixture startup",
    );
    let before_drop = Instant::now();
    drop(dropped);
    assert!(
        before_drop.elapsed() < Duration::from_secs(1),
        "Drop blocked the client event loop"
    );
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        !dropped_input.with_extension("survived").exists(),
        "dropping the job left its sensor running"
    );
}

#[test]
fn requests_validate_before_execution_and_report_spawn_failures() {
    let path =
        std::env::temp_dir().join(format!("missing-tracehound-capture-{}", std::process::id()));
    let error = CaptureJob::analyze(path.clone(), SensorOptions::default(), Severity::Low)
        .err()
        .expect("missing input must be rejected");
    assert_eq!(error.kind, JobErrorKind::InvalidInput);

    // The executable value is intentionally not usable: validation should stop
    // invalid configuration before there is any attempt to start that process.
    let options = SensorOptions {
        executable: OsString::from("never-start-this-sensor"),
        max_alerts: 0,
        ..Default::default()
    };
    let existing_file = std::env::current_exe().unwrap();
    let error = CaptureJob::analyze(existing_file.clone(), options, Severity::Low)
        .err()
        .expect("invalid options must be rejected");
    assert_eq!(error.kind, JobErrorKind::InvalidInput);

    let mut contradictory = case(&existing_file, "TH-0001");
    contradictory
        .benign_hosts
        .push("10.7.0.99".parse().unwrap());
    let error = CaptureJob::evaluate(
        existing_file.clone(),
        SensorOptions::default(),
        contradictory,
    )
    .err()
    .expect("contradictory evaluation labels must be rejected");
    assert_eq!(error.kind, JobErrorKind::InvalidInput);

    let missing_sensor = CaptureJob::analyze(
        existing_file,
        SensorOptions {
            executable: path.into_os_string(),
            ..Default::default()
        },
        Severity::Low,
    )
    .unwrap();
    assert_eq!(missing_sensor.wait().unwrap_err().kind, JobErrorKind::Spawn);
    assert_eq!(missing_sensor.snapshot().state, JobState::Failed);
}
