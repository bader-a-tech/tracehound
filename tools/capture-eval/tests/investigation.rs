use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracehound_eval::capture::inspect_capture;
use tracehound_eval::case_export::{export_host, export_packets, inspect_packet, wireshark_filter};
use tracehound_eval::case_job::{InvestigationJob, InvestigationState};
use tracehound_eval::investigation::CaseIndex;
use tracehound_eval::streaming::StreamOptions;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tracehound-case-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let root = fs::canonicalize(std::env::temp_dir()).unwrap();
        if let Ok(path) = fs::canonicalize(&self.0) {
            if path.parent() == Some(root.as_path())
                && path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("tracehound-case-test-")
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|p| u32::from(u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn packet(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 8, 0];
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&[10, 0, 0, 5]);
    ip[16..20].copy_from_slice(&[192, 0, 2, 10]);
    let sum = checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    frame.extend(ip);
    frame.extend(payload);
    frame
}
fn tcp(flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 20];
    bytes[..2].copy_from_slice(&50000u16.to_be_bytes());
    bytes[2..4].copy_from_slice(&80u16.to_be_bytes());
    bytes[4..8].copy_from_slice(&(if flags == 2 { 1u32 } else { 2 }).to_be_bytes());
    bytes[12] = 0x50;
    bytes[13] = flags;
    bytes.extend(payload);
    packet(6, &bytes)
}
fn dns() -> Vec<u8> {
    let mut bytes = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7];
    bytes.extend(b"example");
    bytes.push(4);
    bytes.extend(b"test");
    bytes.extend([0, 0, 1, 0, 1]);
    let mut udp = vec![0x9c, 0x40, 0, 53];
    udp.extend(((8 + bytes.len()) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(bytes);
    packet(17, &udp)
}
fn fixture(directory: &Directory) -> (PathBuf, Vec<Vec<u8>>) {
    let frames=vec![tcp(2,&[]),dns(),tcp(0x18,b"GET / HTTP/1.1\r\nHost: <script>alert(1)</script>\r\nUser-Agent: independent-case-fixture\r\n\r\n")];
    let path = directory.path("original.pcap");
    write_frames(&path, &frames);
    (path, frames)
}
fn write_frames(path: &Path, frames: &[Vec<u8>]) {
    let mut bytes = Vec::new();
    bytes.extend(0xa1b2c3d4u32.to_le_bytes());
    bytes.extend(2u16.to_le_bytes());
    bytes.extend(4u16.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(0u32.to_le_bytes());
    bytes.extend(65535u32.to_le_bytes());
    bytes.extend(1u32.to_le_bytes());
    for (i, frame) in frames.iter().enumerate() {
        bytes.extend((1700000000 + i as u32).to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend(frame);
    }
    fs::write(path, bytes).unwrap();
}

#[test]
fn reused_tcp_sequence_after_close_or_data_starts_a_new_indexed_episode() {
    let directory = Directory::new();
    for (name, middle, expected) in [
        ("reset", tcp(4, &[]), 2),
        ("finish", tcp(1, &[]), 2),
        ("data", tcp(0x18, b"payload"), 2),
        ("retransmitted-syn", tcp(2, &[]), 1),
    ] {
        let source = directory.path(&format!("{name}.pcap"));
        write_frames(&source, &[tcp(2, &[]), middle, tcp(2, &[])]);
        assert_eq!(inspect_capture(&source).unwrap().flows.len(), expected);
        let index = directory.path(&format!("{name}.db"));
        build(&source, &index);
        assert_eq!(
            CaseIndex::open(&index).unwrap().overview().flows as usize,
            expected
        );
    }
}
fn build(source: &Path, index: &Path) {
    CaseIndex::build(source, index, &|| false, &mut |_| {}).unwrap();
}

#[test]
fn indexed_host_queries_preserve_original_frames_and_stable_timeline_pagination() {
    let directory = Directory::new();
    let (source, frames) = fixture(&directory);
    let index = directory.path("case.db");
    build(&source, &index);
    let case = CaseIndex::open(&index).unwrap();
    assert_eq!(case.overview().packets, 3);
    assert_eq!(
        case.overview().capture.bytes,
        fs::metadata(&source).unwrap().len()
    );
    assert_eq!(case.overview().flows, 2);
    let hosts = case.hosts(0, 100).unwrap();
    let host = hosts
        .iter()
        .find(|h| h.address.to_string() == "10.0.0.5")
        .unwrap();
    assert_eq!(host.packets_sent, 3);
    assert_eq!(host.packets_received, 0);
    assert_eq!(host.connections, 2);
    let mut cursor = 0;
    let mut all = Vec::new();
    loop {
        let page = case.timeline(host.address, cursor, 1).unwrap();
        all.extend(page.events);
        if let Some(next) = page.next_id {
            cursor = next;
        } else {
            break;
        }
    }
    assert!(all
        .windows(2)
        .all(|pair| (pair[0].timestamp_ns, pair[0].id) < (pair[1].timestamp_ns, pair[1].id)));
    assert!(all.iter().any(|e| e.kind == "dns"));
    assert!(all.iter().any(|e| e.kind == "http"));
    let mut verified = case.verify_source(None, &|| false).unwrap();
    for (number, frame) in frames.iter().enumerate() {
        let reference = case.packet(number as u64 + 1).unwrap();
        assert_eq!(verified.read_packet(&reference).unwrap(), *frame);
    }
    assert!(case
        .timeline("203.0.113.1".parse().unwrap(), all[0].id, 10)
        .is_err());
}
#[test]
fn source_tampering_and_out_of_range_references_are_rejected() {
    let directory = Directory::new();
    let (source, _) = fixture(&directory);
    let index = directory.path("case.db");
    build(&source, &index);
    let case = CaseIndex::open(&index).unwrap();
    let mut verified = case.verify_source(None, &|| false).unwrap();
    let mut bad = case.packet(1).unwrap();
    bad.data_offset = u64::MAX;
    assert!(verified.read_packet(&bad).is_err());
    drop(verified);
    let mut bytes = fs::read(&source).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&source, bytes).unwrap();
    assert!(case.verify_source(None, &|| false).is_err());
    assert!(inspect_packet(&case, 1, None, &|| false).is_err());
}
#[test]
fn packet_and_html_exports_are_verifiable_private_and_preserve_existing_files() {
    let directory = Directory::new();
    let (source, frames) = fixture(&directory);
    let index = directory.path("case.db");
    build(&source, &index);
    let case = CaseIndex::open(&index).unwrap();
    let packets = directory.path("selected.pcapng");
    assert_eq!(
        export_packets(&case, &[3, 1, 3], &packets, None, &|| false).unwrap(),
        2
    );
    let export = inspect_capture(&packets).unwrap();
    assert_eq!(export.input_packets, 2);
    assert_eq!(export.http.len(), 1);
    let preview = inspect_packet(&case, 3, None, &|| false).unwrap();
    assert!(preview.source_verified);
    assert_eq!(preview.reference.captured_len as usize, frames[2].len());
    assert_eq!(preview.sha256.len(), 64);
    assert!(export_packets(&case, &[1], &packets, None, &|| false).is_err());
    let folder = directory.path("report");
    let report = export_host(&index, "10.0.0.5".parse().unwrap(), &folder, true, &|| {
        false
    })
    .unwrap();
    assert!(report.packet_capture.unwrap().is_file());
    let html = fs::read_to_string(report.html).unwrap();
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(folder.join("SHA256SUMS.txt").is_file());
    assert!(
        export_host(&index, "10.0.0.5".parse().unwrap(), &folder, false, &|| {
            false
        })
        .is_err()
    );
    let filter = wireshark_filter("10.0.0.5".parse().unwrap(), &[3, 1, 1]);
    assert!(filter.contains("frame.number == 1"));
    assert!(filter.contains("frame.number == 3"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&packets).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[test]
fn rust_investigation_job_completes_and_cancelled_index_has_no_partial_output() {
    let directory = Directory::new();
    let (source, _) = fixture(&directory);
    let output = directory.path("job.db");
    let job = InvestigationJob::start(
        source.clone(),
        output.clone(),
        StreamOptions::default(),
        Duration::from_secs(30),
    )
    .unwrap();
    let result = job.wait().unwrap();
    assert_eq!(result.packets, 3);
    assert_eq!(job.snapshot().state, InvestigationState::Completed);
    assert_eq!(
        CaseIndex::open(&output).unwrap().overview().analysis["engine"],
        "rust"
    );
    let partial = directory.path("cancel.db");
    assert!(CaseIndex::build(&source, &partial, &|| true, &mut |_| {}).is_err());
    assert!(!partial.exists());
}

#[test]
fn mutable_case_references_cannot_relabel_other_original_packets() {
    let directory = Directory::new();
    let (source, _) = fixture(&directory);
    let index = directory.path("case.db");
    build(&source, &index);
    let connection = rusqlite::Connection::open(&index).unwrap();
    connection.execute("UPDATE packets SET data_offset=(SELECT data_offset FROM packets WHERE number=2),captured_len=(SELECT captured_len FROM packets WHERE number=2),original_len=(SELECT original_len FROM packets WHERE number=2) WHERE number=1",[]).unwrap();
    drop(connection);
    let case = CaseIndex::open(&index).unwrap();
    assert!(case.verify_source(None, &|| false).is_ok());
    assert!(inspect_packet(&case, 1, None, &|| false).is_err());
    assert!(!directory.path("forged.pcapng").exists());
    assert!(
        export_packets(&case, &[1], &directory.path("forged.pcapng"), None, &|| {
            false
        })
        .is_err()
    );
    assert!(!directory.path("forged.pcapng").exists());
}

#[test]
fn behavior_comparison_uses_equal_windows_and_preserves_change_semantics() {
    let directory = Directory::new();
    let (source, _) = fixture(&directory);
    let before = directory.path("before.db");
    build(&source, &before);
    let mut bytes = fs::read(&source).unwrap();
    let at = bytes
        .windows(7)
        .position(|value| value == b"example")
        .unwrap();
    bytes[at..at + 7].copy_from_slice(b"changed");
    let after_source = directory.path("after.pcap");
    fs::write(&after_source, bytes).unwrap();
    let after = directory.path("after.db");
    build(&after_source, &after);
    let report = tracehound_eval::baseline::compare_cases(
        &before,
        &after,
        "10.0.0.5".parse().unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(report.window_seconds, Some(2.0));
    assert_eq!(report.changes["domains"].added, vec!["changed.test"]);
    assert_eq!(report.changes["domains"].removed, vec!["example.test"]);
    assert_eq!(report.rates["packets_sent_per_second"].ratio, Some(1.0));
    assert!(report
        .notes
        .iter()
        .any(|note| note.contains("not a malware verdict")));
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    assert!(tracehound_eval::baseline::compare_cases_cancellable(
        &before,
        &after,
        "10.0.0.5".parse().unwrap(),
        None,
        cancelled
    )
    .is_err());
}

#[test]
fn cancellation_at_final_scan_progress_does_not_commit_an_index() {
    let directory = Directory::new();
    let (source, _) = fixture(&directory);
    let index = directory.path("cancel-at-finish.db");
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let result = CaseIndex::build(
        &source,
        &index,
        &|| cancelled.load(Ordering::Acquire),
        &mut |_| cancelled.store(true, Ordering::Release),
    );
    assert!(result.is_err());
    assert!(!index.exists());
}

#[test]
fn report_times_are_human_readable_utc_including_leap_day() {
    use tracehound_eval::case_export::format_timestamp_ns;
    assert_eq!(format_timestamp_ns(0), "1970-01-01 00:00:00.000000000 UTC");
    assert_eq!(
        format_timestamp_ns(1_700_000_000_123_456_789),
        "2023-11-14 22:13:20.123456789 UTC"
    );
    assert_eq!(
        format_timestamp_ns(951_782_400_000_000_000),
        "2000-02-29 00:00:00.000000000 UTC"
    );
}

#[test]
fn comparison_includes_final_packet_findings_and_client_only_fingerprints() {
    use serde_json::json;
    use tracehound_eval::investigation::CaseBuilder;
    let directory = Directory::new();
    let (source, _) = fixture(&directory);
    let index = directory.path("endpoint.db");
    let mut builder = CaseBuilder::create(&source, &index).unwrap();
    let enrichment = tracehound_eval::capture::scan_capture_events(
        &source,
        None,
        &|| false,
        &mut |packet, decoded| builder.push(packet, decoded),
    )
    .unwrap();
    let host = "10.0.0.5".parse().unwrap();
    let end = 1_700_000_002_000_000_000;
    builder
        .event(
            end,
            "tls_client",
            host,
            None,
            "Client-only hello".into(),
            "packet",
            &[],
            false,
            &json!({"ja4":"independent-client-fingerprint"}),
        )
        .unwrap();
    builder
        .event(
            end,
            "finding",
            host,
            None,
            "EOF finding".into(),
            "context",
            &[],
            false,
            &json!({"alert":{"rule_id":"TH-0007"}}),
        )
        .unwrap();
    builder.finish(&enrichment, json!({})).unwrap();
    let report = tracehound_eval::baseline::compare_cases(&index, &index, host, None).unwrap();
    assert_eq!(report.before.packets_sent, 3);
    assert!(report.before.finding_rules.contains("TH-0007"));
    assert!(report
        .before
        .client_fingerprints
        .contains("independent-client-fingerprint"));
    assert_eq!(report.changes["client_fingerprints"].unchanged, 1);
}

#[test]
fn first_packet_protocol_fact_preserves_submillisecond_capture_time() {
    let directory = Directory::new();
    let source = directory.path("dns.pcap");
    write_frames(&source, &[dns()]);
    let mut bytes = fs::read(&source).unwrap();
    bytes[28..32].copy_from_slice(&12345u32.to_le_bytes());
    fs::write(&source, bytes).unwrap();
    let index = directory.path("dns.db");
    build(&source, &index);
    let case = CaseIndex::open(&index).unwrap();
    let host = "10.0.0.5".parse().unwrap();
    let event = case
        .timeline(host, 0, 100)
        .unwrap()
        .events
        .into_iter()
        .find(|event| event.kind == "dns")
        .unwrap();
    assert_eq!(Some(event.timestamp_ns), case.overview().first_timestamp_ns);
    let report = tracehound_eval::baseline::compare_cases(&index, &index, host, None).unwrap();
    assert!(report.before.domains.contains("example.test"));
    assert_eq!(report.before.packets_sent, 1);
    assert_eq!(report.before.packets_sent_per_second, None);
}

#[test]
fn preexisting_sqlite_sidecars_are_preserved_and_reject_a_case_build() {
    let directory = Directory::new();
    let (source, _) = fixture(&directory);
    let index = directory.path("case.db");
    let journal = directory.path("case.db-journal");
    fs::write(&journal, b"preserve existing file").unwrap();
    assert!(CaseIndex::build(&source, &index, &|| false, &mut |_| {}).is_err());
    assert!(!index.exists());
    assert_eq!(fs::read(&journal).unwrap(), b"preserve existing file");
}
