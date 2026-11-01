//! Verify the executables extracted from a release archive.

use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn main() {
    if let Err(error) = run() {
        eprintln!("release verification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err(
            "usage: release-smoke BUNDLE_DIRECTORY SENSOR_VERSION NEW_WORK_DIRECTORY".into(),
        );
    }
    let bundle = fs::canonicalize(&args[0]).map_err(|e| format!("resolve release bundle: {e}"))?;
    let expected_version = args[1].to_str().ok_or("version must be UTF-8")?;
    let sensor = bundle.join(executable("tracehound"));
    let evaluator = bundle.join(executable("tracehound-eval"));
    let desktop = bundle.join(executable("tracehound-desktop"));
    for binary in [&sensor, &evaluator, &desktop] {
        if !binary.is_file() {
            return Err(format!("missing packaged executable {}", binary.display()));
        }
    }
    check_version(
        &sensor,
        "version",
        &format!("tracehound {expected_version}"),
    )?;
    check_version(
        &evaluator,
        "--version",
        &format!("tracehound-eval {}", env!("CARGO_PKG_VERSION")),
    )?;
    let work = PathBuf::from(&args[2]);
    fs::create_dir(&work)
        .map_err(|e| format!("create new verification directory {}: {e}", work.display()))?;
    let work =
        fs::canonicalize(work).map_err(|e| format!("resolve verification directory: {e}"))?;
    let capture = work.join("independent scan capture.pcap");
    write_scan_capture(&capture)?;

    let output = checked(
        Command::new(&evaluator)
            .arg("analyze")
            .arg(&capture)
            .arg("--sensor")
            .arg(&sensor)
            .arg("--json"),
    )?;
    let report: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("invalid analysis JSON: {e}"))?;
    let findings = report["findings"]
        .as_array()
        .ok_or("analysis omitted findings")?;
    if findings.len() != 1
        || findings[0]["alert"]["rule_id"] != "TH-0003"
        || findings[0]["alert"]["src"] != "10.7.0.99"
        || findings[0]["alert"]["dst"] != "10.7.0.10"
        || findings[0]["alert"]["evidence"]["ports_probed"] != 128
    {
        return Err(format!(
            "independent 128-port scan did not match its wire-level label: {report}"
        ));
    }
    fs::write(work.join("analysis.json"), &output.stdout)
        .map_err(|e| format!("save analysis: {e}"))?;

    let suite = work.join("suite.json");
    let labels = json!({"schema_version": 1, "captures": [{
        "name": "independent 128-port scan", "capture": "independent scan capture.pcap",
        "expected": [{"rule_id": "TH-0003", "src": "10.7.0.99", "dst": "10.7.0.10"}],
        "benign_hosts": [], "min_severity": "low"
    }]});
    fs::write(
        &suite,
        serde_json::to_vec_pretty(&labels).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("write verification labels: {e}"))?;
    let output = checked(
        Command::new(&evaluator)
            .arg("evaluate")
            .arg(&suite)
            .arg("--sensor")
            .arg(&sensor)
            .arg("--json"),
    )?;
    let report: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("invalid evaluation JSON: {e}"))?;
    if report["passed"] != true
        || report["summary"]["matched_expectations"] != 1
        || report["summary"]["missed_expectations"] != 0
        || report["summary"]["unexpected_findings"] != 0
    {
        return Err(format!(
            "packaged evaluator failed independent scan labels: {report}"
        ));
    }
    fs::write(work.join("evaluation.json"), &output.stdout)
        .map_err(|e| format!("save evaluation: {e}"))?;
    println!("Verified packaged sensor {expected_version}, evaluator {}, desktop binary, and independent PCAP analysis/evaluation", env!("CARGO_PKG_VERSION"));
    Ok(())
}

fn executable(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

fn checked(command: &mut Command) -> Result<Output, String> {
    let output = command
        .output()
        .map_err(|e| format!("execute packaged binary: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "packaged command exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output)
}

fn check_version(binary: &Path, argument: &str, expected: &str) -> Result<(), String> {
    let output = checked(Command::new(binary).arg(argument))?;
    let actual = String::from_utf8_lossy(&output.stdout);
    if actual.trim() != expected {
        return Err(format!(
            "{} reports {:?}, expected {expected:?}",
            binary.display(),
            actual.trim()
        ));
    }
    Ok(())
}

// Construct Ethernet/IPv4/TCP bytes directly. This fixture uses no detector or
// demo-generator packet builders and carries valid IP and TCP checksums.
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32)
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn write_scan_capture(path: &Path) -> Result<(), String> {
    let source = [10, 7, 0, 99];
    let destination = [10, 7, 0, 10];
    let mut bytes = Vec::new();
    bytes.extend(0xa1b2c3d4u32.to_le_bytes());
    bytes.extend(2u16.to_le_bytes());
    bytes.extend(4u16.to_le_bytes());
    bytes.extend([0; 8]);
    bytes.extend(65535u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    for index in 0..128u16 {
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        ip[4..6].copy_from_slice(&index.to_be_bytes());
        ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&source);
        ip[16..20].copy_from_slice(&destination);
        let check = checksum(&ip);
        ip[10..12].copy_from_slice(&check.to_be_bytes());
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&(40000 + index).to_be_bytes());
        tcp[2..4].copy_from_slice(&(1000 + index).to_be_bytes());
        tcp[4..8].copy_from_slice(&1u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x02;
        tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
        let mut pseudo = Vec::from(source);
        pseudo.extend(destination);
        pseudo.extend([0, 6]);
        pseudo.extend(20u16.to_be_bytes());
        pseudo.extend(tcp);
        let check = checksum(&pseudo);
        tcp[16..18].copy_from_slice(&check.to_be_bytes());
        let mut frame = vec![2, 0, 0, 0, 0, 10, 2, 0, 0, 0, 0, 99, 0x08, 0x00];
        frame.extend(ip);
        frame.extend(tcp);
        bytes.extend((1_700_000_000 + index as u32 / 10).to_le_bytes());
        bytes.extend(((index as u32 % 10) * 100_000).to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend(frame);
    }
    fs::write(path, bytes).map_err(|e| format!("write independent PCAP: {e}"))
}
