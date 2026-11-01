//! Live-session lifecycle tests use local sensor/helper fixtures, not a real NIC.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracehound_eval::live::{
    capture_interfaces, LiveSession, PortableRecording, RecordingLimits, RecordingState,
};
use tracehound_eval::runtime::{JobReport, SensorOptions};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    parent: PathBuf,
    executable: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let directory = parent.join(format!(
            "tracehound live tests {} {} {}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("sensor.rs"), r##"
use std::io::{Read,Write};
#[cfg(unix)]
static STOP:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
#[cfg(unix)]
extern "C" fn interrupt(_:i32) {STOP.store(true,std::sync::atomic::Ordering::Relaxed);}
fn stopped()->bool {
    #[cfg(unix)] {STOP.load(std::sync::atomic::Ordering::Relaxed)}
    #[cfg(not(unix))] {false}
}
fn alert() {
    println!(r#"{{"rule_id":"TH-0001","severity":"high","src":"10.7.0.99","dst":"198.51.100.23","title":"Captured finding","evidence":{{"observations":1}}}}"#);
    std::io::stdout().flush().unwrap();
}
fn pcap(path: &std::path::Path) {
    let mut data = Vec::new();
    data.extend(0xa1b2c3d4u32.to_le_bytes()); data.extend(2u16.to_le_bytes()); data.extend(4u16.to_le_bytes());
    data.extend(0u32.to_le_bytes()); data.extend(0u32.to_le_bytes()); data.extend(65535u32.to_le_bytes()); data.extend(1u32.to_le_bytes());
    std::fs::write(path,data).unwrap();
}
fn main() {
    let args:Vec<_> = std::env::args().collect();
    let value = |name:&str| -> String { let index=args.iter().position(|arg|arg==name).unwrap(); args[index+1].clone() };
    match args.get(1).map(String::as_str) {
        Some("-D") => { println!("1. fixture0 (Test adapter)\n2. fixture1 (Other adapter)"); }
        Some("replay") => { assert_eq!(&std::fs::read(&args[2]).unwrap()[..4],&0xa1b23c4du32.to_le_bytes()); alert(); }
        Some("sniff") => {
            let listener=std::net::TcpListener::bind(value("-listen")).unwrap();
            listener.set_nonblocking(true).unwrap();
            #[cfg(unix)] unsafe {
                unsafe extern "C" {fn signal(number:i32,handler:extern "C" fn(i32))->usize;}
                signal(2,interrupt);
            }
            alert();
            while !stopped() {
                let mut stream=match listener.accept() {
                    Ok((stream,_))=>stream,
                    Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>{std::thread::sleep(std::time::Duration::from_millis(5));continue;},
                    Err(error)=>panic!("{error}"),
                };
                let mut buffer=[0;4096]; let n=stream.read(&mut buffer).unwrap();
                let request=String::from_utf8_lossy(&buffer[..n]);
                let body=if request.starts_with("GET /healthz ") { "ok\n" }
                    else if request.starts_with("GET /api/stats ") { r#"{"packets":12,"detectors":["beaconing"]}"# }
                    else if request.starts_with("GET /api/devices ") { r#"[{"addr":"10.7.0.99","flows":2}]"# }
                    else { r#"[{"client":"10.7.0.99","server":"198.51.100.23","bytes":100}]"# };
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
            }
            alert();
        }
        Some("-i") => {
            let interface=value("-i");
            if args.iter().any(|arg|arg=="-f") {assert_eq!(value("-f"),"udp port 49697");}
            if interface=="fail" { eprintln!("capture-driver permission denied"); std::process::exit(3); }
            let path=std::path::PathBuf::from(value("-w")); pcap(&path);
            if interface=="wait" || interface=="drop" {
                std::thread::sleep(std::time::Duration::from_secs(1));
                std::fs::write(std::env::current_exe().unwrap().with_extension("survived"),b"child survived").unwrap();
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        }
        _ => panic!("unknown fixture mode"),
    }
}
"##).unwrap();
        let name = if cfg!(windows) {
            "sensor.exe"
        } else {
            "sensor"
        };
        let mut compiler =
            Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()));
        compiler
            .current_dir(&directory)
            .args(["--edition=2021", "sensor.rs", "-o", name]);
        if cfg!(all(windows, target_env = "gnu")) {
            compiler.args(["-C", "link-self-contained=yes"]);
        }
        let output = compiler.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            executable: directory.join(name),
            directory,
            parent,
        }
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
                && path.file_name().is_some_and(|name| {
                    name.to_string_lossy().starts_with("tracehound live tests ")
                })
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}

fn until(mut condition: impl FnMut() -> bool, description: &str) {
    let start = Instant::now();
    while !condition() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for {description}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn recording_lists_interfaces_and_analyses_only_after_capture_finishes() {
    let fixture = Fixture::new();
    let interfaces = capture_interfaces(&fixture.executable).unwrap();
    assert_eq!(interfaces.len(), 2);
    assert_eq!(interfaces[0].id, "1");
    let recording = PortableRecording::start(
        fixture.options(),
        fixture.executable.clone(),
        "wait".into(),
        RecordingLimits::default(),
    )
    .unwrap();
    until(
        || recording.snapshot().capture_bytes >= 24,
        "recording header",
    );
    let snapshot = recording.snapshot();
    assert_eq!(snapshot.mode, "record_then_analyse");
    assert_eq!(snapshot.state, RecordingState::Recording);
    assert_eq!(snapshot.alert_records, 0);
    assert_eq!(snapshot.unique_findings, 0);
    assert!(recording.try_result().is_none());
    assert!(recording.stop());
    let result = recording.wait().unwrap();
    assert_eq!(recording.snapshot().state, RecordingState::Completed);
    assert_eq!(recording.snapshot().unique_findings, 1);
    assert!(Arc::ptr_eq(
        &result,
        &recording.try_result().unwrap().unwrap()
    ));
    let JobReport::Analysis(report) = result.as_ref() else {
        panic!("expected analysis report")
    };
    assert_eq!(report.report.findings.len(), 1);
    assert_eq!(report.report.findings[0].alert.rule_id, "TH-0001");
    let raw_capture = report.capture.clone();
    assert!(raw_capture.is_file());
    let exported = fixture.directory.join("explicitly saved.pcap");
    recording.save_capture(&exported).unwrap();
    assert_eq!(fs::metadata(&exported).unwrap().len(), 24);
    assert!(recording.save_capture(&exported).is_err());
    assert!(!recording.stop());
    drop(recording);
    until(|| !raw_capture.exists(), "private capture cleanup");
    let filtered = PortableRecording::start_filtered(
        fixture.options(),
        fixture.executable.clone(),
        "fast".into(),
        RecordingLimits::default(),
        Some("udp port 49697".into()),
    )
    .unwrap();
    assert!(filtered.wait().is_ok());
}

#[test]
fn recording_cancellation_errors_and_drop_do_not_publish_partial_success() {
    let fixture = Fixture::new();
    let recording = PortableRecording::start(
        fixture.options(),
        fixture.executable.clone(),
        "wait".into(),
        RecordingLimits::default(),
    )
    .unwrap();
    until(
        || recording.snapshot().capture_bytes >= 24,
        "capture startup",
    );
    assert!(recording.cancel());
    assert!(recording.wait().is_err());
    assert_eq!(recording.snapshot().state, RecordingState::Cancelled);
    assert!(recording
        .save_capture(Path::new("never-created.pcap"))
        .is_err());
    let failed = PortableRecording::start(
        fixture.options(),
        fixture.executable.clone(),
        "fail".into(),
        RecordingLimits::default(),
    )
    .unwrap();
    let error = failed.wait().unwrap_err();
    assert!(error.contains("permission denied"), "{error}");
    assert_eq!(failed.snapshot().state, RecordingState::Failed);
    let dropped = PortableRecording::start(
        fixture.options(),
        fixture.executable.clone(),
        "drop".into(),
        RecordingLimits::default(),
    )
    .unwrap();
    until(
        || dropped.snapshot().capture_bytes >= 24,
        "drop capture startup",
    );
    let started = Instant::now();
    drop(dropped);
    assert!(started.elapsed() < Duration::from_secs(1));
    std::thread::sleep(Duration::from_millis(1400));
    assert!(
        !fixture.executable.with_extension("survived").exists(),
        "capture helper continued after drop"
    );
    assert!(PortableRecording::start(
        fixture.options(),
        fixture.executable.clone(),
        "1".into(),
        RecordingLimits {
            max_mebibytes: 0,
            max_seconds: 1
        }
    )
    .is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn linux_live_inventory_and_findings_are_available_before_stopping() {
    use tracehound_eval::live::LiveState;
    let fixture = Fixture::new();
    let session = LiveSession::start(fixture.options(), "fixture0".into(), false).unwrap();
    until(
        || session.snapshot().state == LiveState::Running,
        "live API startup",
    );
    let snapshot = session.snapshot();
    assert_eq!(snapshot.mode, "live_analysis");
    assert_eq!(snapshot.stats["packets"], 12);
    assert_eq!(snapshot.devices.len(), 1);
    assert_eq!(snapshot.flows.len(), 1);
    until(|| !session.snapshot().findings.is_empty(), "live finding");
    assert_eq!(session.snapshot().findings[0].rule_id, "TH-0001");
    let json = serde_json::to_value(session.snapshot()).unwrap();
    assert_eq!(json["devices"][0]["addr"], "10.7.0.99");
    assert!(session.stop());
    let stopped = session.wait().unwrap();
    assert_eq!(stopped.state, LiveState::Stopped);
    assert_eq!(
        stopped.alert_records, 2,
        "final detections from graceful shutdown were lost"
    );
    assert!(!session.stop());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_native_live_platform_has_an_actionable_recording_alternative() {
    let error = LiveSession::start(SensorOptions::default(), "interface".into(), false)
        .err()
        .unwrap();
    assert!(error.contains("Linux"));
    assert!(error.contains("record-then-analyse"));
}

#[test]
#[ignore = "requires explicit installed capture helper, sensor and loopback driver"]
fn installed_loopback_recording_captures_only_the_tests_own_udp() {
    use std::net::UdpSocket;
    let sensor = std::env::var_os("TRACEHOUND_TEST_SENSOR")
        .expect("set TRACEHOUND_TEST_SENSOR to a built sensor");
    let tool = PathBuf::from(
        std::env::var_os("TRACEHOUND_CAPTURE_TOOL")
            .expect("set TRACEHOUND_CAPTURE_TOOL to installed dumpcap"),
    );
    let adapters = capture_interfaces(&tool).expect("enumerate installed capture adapters");
    let adapter = adapters
        .iter()
        .find(|adapter| {
            adapter.name.to_ascii_lowercase().contains("loopback")
                || adapter
                    .name
                    .split_whitespace()
                    .next()
                    .is_some_and(|name| matches!(name, "lo" | "lo0"))
        })
        .unwrap_or_else(|| panic!("no loopback adapter in {adapters:?}"));
    let receiver = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 49697))
        .expect("reserve this test's local UDP destination");
    let sender = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("create this test's local UDP sender");
    let recording = PortableRecording::start_filtered(
        SensorOptions {
            executable: sensor,
            timeout: Duration::from_secs(30),
            ..Default::default()
        },
        tool,
        adapter.id.clone(),
        RecordingLimits {
            max_mebibytes: 64,
            max_seconds: 30,
        },
        Some("udp port 49697".into()),
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(1));
    assert!(
        !recording.finished(),
        "capture helper failed: {:?}",
        recording.snapshot()
    );
    for _ in 0..12 {
        sender
            .send_to(
                b"tracehound-local-capture-check",
                receiver.local_addr().unwrap(),
            )
            .unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(250));
    assert!(recording.stop());
    let report = recording.wait().unwrap_or_else(|error| {
        panic!(
            "installed capture failed: {error}; {:?}",
            recording.snapshot()
        )
    });
    assert_eq!(recording.snapshot().state, RecordingState::Completed);
    let JobReport::Analysis(report) = report.as_ref() else {
        panic!("recording returned a non-analysis report")
    };
    assert!(
        report.report.findings.is_empty(),
        "own small UDP exchange should not be accused: {:?}",
        report.report.findings
    );
    assert!(
        fs::metadata(&report.capture).unwrap().len() > 24,
        "capture contains only a container header"
    );
    if let Some(packets) = report
        .enrichment
        .get("input_packets")
        .and_then(serde_json::Value::as_u64)
    {
        assert!(packets > 0);
    }
    let fixture = Fixture::new();
    let saved = fixture.directory.join("local-loopback-check.pcap");
    recording.save_capture(&saved).unwrap();
    assert!(fs::metadata(saved).unwrap().len() > 24);
}
