use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracehound_eval::capture::{DecodeEvents, DecodedPacket, PacketRef};
use tracehound_eval::streaming::{read_pcap_stream, StreamOptions, StreamingAnalyzer};
use tracehound_eval::Severity;

fn packet(
    source: &str,
    destination: &str,
    source_port: u16,
    destination_port: u16,
    at: u64,
    flags: u8,
    bytes: u64,
) -> DecodedPacket {
    DecodedPacket {
        flow_id: Some(1),
        src: source.parse().unwrap(),
        dst: destination.parse().unwrap(),
        src_port: source_port,
        dst_port: destination_port,
        protocol: 6,
        tcp_flags: Some(flags),
        tcp_sequence: Some(u32::from(source_port)),
        tcp_ack: None,
        timestamp_ms: at,
        packets: vec![PacketRef {
            number: at + u64::from(source_port) + 1,
            timestamp_ns: at * 1_000_000,
            link_type: 1,
            captured_len: 54,
            original_len: 54,
            ..Default::default()
        }],
        payload: Vec::new(),
        wire_bytes: bytes,
        captured_bytes: 54,
    }
}
fn push(analyzer: &mut StreamingAnalyzer, packet: DecodedPacket) -> Vec<tracehound_eval::Alert> {
    analyzer
        .observe(DecodeEvents {
            packet: Some(packet),
            ..Default::default()
        })
        .unwrap()
        .alerts
}
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
struct Rules(PathBuf);
impl Rules {
    fn new(text: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "tracehound-stream-rules-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("rules.yaml"), text).unwrap();
        Self(root)
    }
    fn options(&self) -> StreamOptions {
        StreamOptions {
            rules: Some(self.0.clone()),
            ..Default::default()
        }
    }
}
impl Drop for Rules {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("rules.yaml"));
        let _ = fs::remove_dir(&self.0);
    }
}

#[test]
fn periodic_outbound_connections_have_bounded_original_packet_evidence() {
    let mut analyzer = StreamingAnalyzer::new(StreamOptions::default()).unwrap();
    let mut alerts = Vec::new();
    for index in 0..25 {
        let port = 40_000 + index as u16;
        let at = index * 60_000;
        alerts.extend(push(
            &mut analyzer,
            packet("10.0.0.5", "198.51.100.9", port, 443, at, 2, 60),
        ));
        alerts.extend(push(
            &mut analyzer,
            packet("10.0.0.5", "198.51.100.9", port, 443, at + 100, 4, 60),
        ));
        // TCP tail packets after teardown are not new conversations.
        alerts.extend(push(
            &mut analyzer,
            packet("10.0.0.5", "198.51.100.9", port, 443, at + 101, 0x10, 60),
        ));
        alerts.extend(push(
            &mut analyzer,
            packet("10.0.0.5", "198.51.100.9", port, 443, at + 102, 0x10, 60),
        ));
    }
    alerts.extend(analyzer.tick(1_500_000).unwrap().alerts);
    let beacon = alerts
        .iter()
        .find(|alert| alert.rule_id == "TH-0001")
        .unwrap();
    assert_eq!(beacon.evidence["interval_mean_s"], 60.0);
    assert!(beacon.extra["packets"].as_array().unwrap().len() >= 8);
    let summary = analyzer.finish().unwrap();
    assert!(summary
        .report
        .findings
        .iter()
        .any(|finding| finding.alert.rule_id == "TH-0001"));
    assert_eq!(summary.analysis_meta["engine"], "rust-stream");
    assert_eq!(
        summary.analysis_meta["rule_pack_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn scan_scoring_respects_answers_window_and_yaml_severity_and_exceptions() {
    let rules=Rules::new("id: TH-0003\nname: Scan\ndetector: port-scan\nseverity: critical\ntuning:\n  vertical_ports: 3\n  window: 5s\nexceptions:\n- description: known scanner\n  src: 10.0.90.10\n");
    let mut analyzer = StreamingAnalyzer::new(rules.options()).unwrap();
    for port in 1..=4 {
        push(
            &mut analyzer,
            packet(
                "10.0.0.5",
                "198.51.100.1",
                50_000,
                port,
                u64::from(port) * 10,
                2,
                60,
            ),
        );
        push(
            &mut analyzer,
            packet(
                "198.51.100.1",
                "10.0.0.5",
                port,
                50_000,
                u64::from(port) * 10 + 1,
                0x12,
                60,
            ),
        );
    }
    assert!(analyzer.tick(1000).unwrap().alerts.is_empty());
    for port in 10..=14 {
        push(
            &mut analyzer,
            packet(
                "10.0.90.10",
                "198.51.100.2",
                50_001,
                port,
                u64::from(port) * 10,
                2,
                60,
            ),
        );
        push(
            &mut analyzer,
            packet(
                "10.0.0.6",
                "198.51.100.3",
                50_002,
                port,
                u64::from(port) * 10,
                2,
                60,
            ),
        );
    }
    let found = analyzer.tick(2000).unwrap().alerts;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].src.unwrap().to_string(), "10.0.0.6");
    assert_eq!(found[0].severity, Severity::Critical);
    assert!(analyzer.tick(10_000).unwrap().alerts.is_empty());
    for port in 20..=22 {
        push(
            &mut analyzer,
            packet(
                "10.0.0.7",
                "198.51.100.4",
                50_003,
                port,
                11_000 + u64::from(port),
                2,
                60,
            ),
        );
    }
    assert!(analyzer
        .tick(12_000)
        .unwrap()
        .alerts
        .iter()
        .any(|alert| alert.src.unwrap().to_string() == "10.0.0.7"));
}

#[test]
fn tcp_half_close_waits_for_inbound_reply_before_upload_verdict() {
    let mut analyzer = StreamingAnalyzer::new(StreamOptions::default()).unwrap();
    push(
        &mut analyzer,
        packet("10.0.0.5", "198.51.100.9", 40_000, 443, 0, 2, 60),
    );
    push(
        &mut analyzer,
        packet(
            "10.0.0.5",
            "198.51.100.9",
            40_000,
            443,
            100,
            0x18,
            11 * 1024 * 1024,
        ),
    );
    assert!(!push(
        &mut analyzer,
        packet("10.0.0.5", "198.51.100.9", 40_000, 443, 200, 0x11, 60)
    )
    .iter()
    .any(|alert| alert.rule_id == "TH-0005"));
    push(
        &mut analyzer,
        packet(
            "198.51.100.9",
            "10.0.0.5",
            443,
            40_000,
            300,
            0x18,
            1024 * 1024,
        ),
    );
    assert!(!push(
        &mut analyzer,
        packet("198.51.100.9", "10.0.0.5", 443, 40_000, 400, 0x11, 60)
    )
    .iter()
    .any(|alert| alert.rule_id == "TH-0005"));
    assert!(!analyzer
        .finish()
        .unwrap()
        .report
        .findings
        .iter()
        .any(|finding| finding.alert.rule_id == "TH-0005"));
    let mut upload = StreamingAnalyzer::new(StreamOptions::default()).unwrap();
    push(
        &mut upload,
        packet("10.0.0.5", "198.51.100.9", 40_001, 443, 0, 2, 60),
    );
    push(
        &mut upload,
        packet(
            "10.0.0.5",
            "198.51.100.9",
            40_001,
            443,
            100,
            0x18,
            11 * 1024 * 1024,
        ),
    );
    let alerts = push(
        &mut upload,
        packet("198.51.100.9", "10.0.0.5", 443, 40_001, 200, 4, 100),
    );
    assert!(alerts.iter().any(|alert| alert.rule_id == "TH-0005"));
}

#[test]
fn tracking_pressure_is_bounded_and_reported_and_offline_attribution_is_rejected() {
    let mut options = StreamOptions::default();
    options.limits.max_flows = 2;
    options.limits.max_devices = 2;
    options.limits.max_beacon_tracks = 2;
    options.limits.max_scan_sources = 2;
    options.limits.max_probes_per_source = 2;
    let mut analyzer = StreamingAnalyzer::new(options).unwrap();
    for index in 0..100 {
        push(
            &mut analyzer,
            packet(
                "10.0.0.5",
                "198.51.100.9",
                40_000 + index,
                443,
                u64::from(index),
                2,
                60,
            ),
        );
    }
    let stats = analyzer.stats();
    assert_eq!(stats.active_flows, 2);
    assert!(stats.dropped_flow_packets >= 98);
    assert!(analyzer
        .set_process_snapshot(tracehound_eval::process::ProcessSnapshot {
            sampled_at_ms: 0,
            completed_at_ms: 0,
            endpoints: Vec::new(),
            warnings: Vec::new()
        })
        .is_err());
}

#[test]
fn malformed_or_unknown_rule_tuning_fails_without_starting_a_capture() {
    for text in [
        "id: TH-0003\nname: bad\ndetector: port-scan\ntuning:\n  vertcal_ports: 3\n",
        "id: TH-0001\nname: bad\ndetector: beaconing\ntuning:\n  history: forever\n",
        "id: TH-0001\nname: bad\ndetector: port-scan\n",
    ] {
        let rules = Rules::new(text);
        assert!(StreamingAnalyzer::new(rules.options()).is_err());
    }
}

#[test]
fn rarity_learns_client_only_hellos_without_counting_server_pairs_twice() {
    use tracehound_eval::capture::{TlsClientObservation, TlsObservation};
    let mut analyzer = StreamingAnalyzer::new(StreamOptions::default()).unwrap();
    for host in 1..=5 {
        push(
            &mut analyzer,
            packet(
                &format!("10.0.0.{host}"),
                "198.51.100.9",
                40_000 + host,
                443,
                0,
                2,
                60,
            ),
        );
    }
    let client = |host: u8, ja4: &str, at: u64| TlsClientObservation {
        src: format!("10.0.0.{host}").parse().unwrap(),
        dst: "198.51.100.9".parse().unwrap(),
        src_port: 40_000 + u16::from(host),
        dst_port: 443,
        ja4: ja4.into(),
        server_name: Some("example.test".into()),
        timestamp_ms: at,
        packets: vec![PacketRef {
            number: at + u64::from(host) + 1,
            timestamp_ns: at * 1_000_000,
            ..Default::default()
        }],
    };
    for (host, fingerprint) in [
        (1, "common_a"),
        (2, "common_a"),
        (3, "common_b"),
        (4, "common_b"),
        (5, "rare_c"),
    ] {
        analyzer
            .observe(DecodeEvents {
                tls_clients: vec![client(host, fingerprint, 100)],
                ..Default::default()
            })
            .unwrap();
    }
    for at in [200, 300] {
        analyzer
            .observe(DecodeEvents {
                tls_clients: vec![client(5, "rare_c", at)],
                ..Default::default()
            })
            .unwrap();
    }
    for host in [3, 4] {
        analyzer
            .observe(DecodeEvents {
                tls_clients: vec![client(host, "common_a", 350)],
                ..Default::default()
            })
            .unwrap();
    }
    assert_eq!(analyzer.stats().fingerprint_user_samples_omitted, 2);
    analyzer
        .observe(DecodeEvents {
            tls: vec![TlsObservation {
                src: "10.0.0.5".parse().unwrap(),
                dst: "198.51.100.9".parse().unwrap(),
                src_port: 40_005,
                dst_port: 443,
                ja4: "rare_c".into(),
                ja4s: "server".into(),
                timestamp_ms: 400,
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();
    let alerts = analyzer.tick(600_100).unwrap().alerts;
    let rare = alerts
        .iter()
        .find(|alert| alert.rule_id == "TH-0007")
        .unwrap();
    assert_eq!(rare.evidence["observations"], 3);
    assert_eq!(rare.src.unwrap().to_string(), "10.0.0.5");
}

#[test]
fn externally_decoded_diagnostics_survive_finish() {
    let mut analyzer = StreamingAnalyzer::new(StreamOptions::default()).unwrap();
    let mut events = DecodeEvents::default();
    events.diagnostics.truncated_packets = 7;
    events.diagnostics.discarded_fragment_sets = 2;
    analyzer.observe_ref(&events).unwrap();
    let summary = analyzer.finish().unwrap();
    assert_eq!(summary.diagnostics.truncated_packets, 7);
    assert_eq!(summary.diagnostics.discarded_fragment_sets, 2);
}

#[test]
fn inherited_dns_evidence_respects_the_streams_smaller_reference_budget() {
    let mut options = StreamOptions::default();
    options.limits.max_evidence_packets = 4;
    let mut analyzer = StreamingAnalyzer::new(options).unwrap();
    let mut alerts = Vec::new();
    for index in 0..40u64 {
        let query = tracehound_eval::capture::DnsObservation {
            src: "10.0.0.5".parse().unwrap(),
            dst: "192.0.2.53".parse().unwrap(),
            name: format!("{index:04x}abcdefghijklmnopqrstuvwxyz0123456789abcdefghij.attacker.net"),
            query_type: 16,
            timestamp_ms: index * 1000,
            packets: (0..10)
                .map(|part| PacketRef {
                    number: index * 10 + part + 1,
                    timestamp_ns: index * 1_000_000_000,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        alerts.extend(
            analyzer
                .observe(DecodeEvents {
                    dns: vec![query],
                    ..Default::default()
                })
                .unwrap()
                .alerts,
        );
    }
    let dns = alerts
        .iter()
        .find(|alert| alert.rule_id == "TH-0002")
        .unwrap();
    assert_eq!(dns.extra["packets"].as_array().unwrap().len(), 4);
    assert_eq!(dns.extra["packet_refs_truncated"], true);
    assert!(analyzer.stats().dropped_evidence_refs > 0);
}

fn pcap() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(0xa1b2c3d4u32.to_le_bytes());
    bytes.extend(2u16.to_le_bytes());
    bytes.extend(4u16.to_le_bytes());
    for value in [0u32, 0, 65535, 1] {
        bytes.extend(value.to_le_bytes());
    }
    let mut packet = vec![0u8; 54];
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    packet[14] = 0x45;
    packet[16..18].copy_from_slice(&40u16.to_be_bytes());
    packet[22] = 64;
    packet[23] = 6;
    packet[26..30].copy_from_slice(&[10, 0, 0, 5]);
    packet[30..34].copy_from_slice(&[198, 51, 100, 9]);
    packet[34..36].copy_from_slice(&40_000u16.to_be_bytes());
    packet[36..38].copy_from_slice(&443u16.to_be_bytes());
    packet[46] = 0x50;
    packet[47] = 2;
    for value in [1u32, 0, 54, 54] {
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend(packet);
    bytes
}

#[test]
fn pipe_reader_uses_the_shared_packet_parser_and_rejects_truncation() {
    let bytes = pcap();
    let mut analyzer = StreamingAnalyzer::new(StreamOptions::default()).unwrap();
    let mut batches = 0;
    read_pcap_stream(
        &mut Cursor::new(bytes.clone()),
        &mut analyzer,
        &|| false,
        &mut |_| {
            batches += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(batches, 1);
    assert_eq!(analyzer.stats().transport_packets, 1);
    assert_eq!(analyzer.flows().next().unwrap().packets[0].data_offset, 40);
    let mut analyzer = StreamingAnalyzer::new(StreamOptions::default()).unwrap();
    assert!(read_pcap_stream(
        &mut Cursor::new(bytes[..bytes.len() - 1].to_vec()),
        &mut analyzer,
        &|| false,
        &mut |_| Ok(())
    )
    .unwrap_err()
    .contains("Truncated"));
    let mut analyzer = StreamingAnalyzer::new(StreamOptions::default()).unwrap();
    assert!(read_pcap_stream(
        &mut Cursor::new(bytes),
        &mut analyzer,
        &|| true,
        &mut |_| Ok(())
    )
    .unwrap_err()
    .contains("cancelled"));
}

struct Helper {
    directory: PathBuf,
    executable: PathBuf,
}
impl Helper {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "tracehound-rust-pipe-test-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("fixture.pcap"), pcap()).unwrap();
        let source = r#"use std::io::Write;fn main(){let args=std::env::args().collect::<Vec<_>>();let mode=args.windows(2).find(|pair|pair[0]=="-i").map(|pair|pair[1].as_str()).unwrap_or("quiet");if mode=="error"{eprintln!("permission denied by capture driver");std::process::exit(1);}let path=std::env::current_exe().unwrap().parent().unwrap().join("fixture.pcap");let bytes=std::fs::read(path).unwrap();let mut output=std::io::stdout().lock();output.write_all(&bytes[..24]).unwrap();if mode=="traffic"{output.write_all(&bytes[24..]).unwrap();}output.flush().unwrap();std::thread::sleep(std::time::Duration::from_secs(30));}"#;
        let path = directory.join("helper.rs");
        fs::write(&path, source).unwrap();
        let executable = directory.join(if cfg!(windows) {
            "helper.exe"
        } else {
            "helper"
        });
        let mut compiler = std::process::Command::new("rustc");
        if cfg!(all(windows, target_env = "gnu")) {
            compiler.arg("-Clink-self-contained=yes");
        }
        let output = compiler
            .arg("--edition=2021")
            .arg(&path)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            directory,
            executable,
        }
    }
    fn session(&self, interface: &str) -> tracehound_eval::streaming::RustLiveSession {
        tracehound_eval::streaming::RustLiveSession::start(
            tracehound_eval::streaming::RustLiveOptions {
                capture_tool: self.executable.clone(),
                interface: interface.into(),
                filter: Some("udp port 49697".into()),
                promiscuous: false,
                recording_limits: tracehound_eval::live::RecordingLimits {
                    max_mebibytes: 1,
                    max_seconds: 30,
                },
                analysis: StreamOptions::default(),
                process_attribution: false,
            },
        )
        .unwrap()
    }
}
impl Drop for Helper {
    fn drop(&mut self) {
        for file in [
            "fixture.pcap",
            "helper.rs",
            "helper.exe",
            "helper",
            "saved.pcap",
        ] {
            let _ = fs::remove_file(self.directory.join(file));
        }
        let _ = fs::remove_dir(&self.directory);
    }
}
fn until(mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while !condition() {
        assert!(
            std::time::Instant::now() < deadline,
            "live session did not reach its expected state"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn live_wrapper_stops_quiet_links_reaps_children_and_retains_only_valid_capture_prefixes() {
    use tracehound_eval::streaming::RustLiveState;
    let helper = Helper::new();
    let quiet = helper.session("quiet");
    until(|| quiet.snapshot().capture_bytes >= 24);
    let started = std::time::Instant::now();
    assert!(quiet.stop());
    until(|| quiet.finished());
    assert!(started.elapsed() < std::time::Duration::from_secs(4));
    assert_eq!(quiet.snapshot().state, RustLiveState::Completed);
    assert_eq!(quiet.wait().unwrap().stats.packets, 0);
    let retained = quiet.retained_capture_path().unwrap();
    assert_eq!(fs::metadata(&retained).unwrap().len(), 24);
    drop(quiet);
    until(|| !retained.exists());
    let traffic = helper.session("traffic");
    until(|| traffic.snapshot().capture_bytes > 24);
    traffic.stop();
    until(|| traffic.finished());
    let summary = traffic.wait().unwrap();
    assert_eq!(summary.stats.transport_packets, 1);
    assert!(summary.report.findings.is_empty());
    let destination = helper.directory.join("saved.pcap");
    traffic.save_capture(&destination).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), pcap());
    assert!(traffic.save_capture(&destination).is_err());
    drop(traffic);
    let cancelled = helper.session("quiet");
    until(|| cancelled.snapshot().capture_bytes >= 24);
    assert!(cancelled.cancel());
    until(|| cancelled.finished());
    assert!(cancelled.wait().is_err());
    assert_eq!(cancelled.snapshot().state, RustLiveState::Cancelled);
    assert!(cancelled.retained_capture_path().is_none());
    drop(cancelled);
    let failure = helper.session("error");
    until(|| failure.finished());
    assert!(failure.wait().unwrap_err().contains("permission denied"));
    assert_eq!(failure.snapshot().state, RustLiveState::Failed);
}

#[test]
#[ignore = "Requires an explicitly supplied installed dumpcap and local capture permission; captures only this test's UDP port"]
fn installed_rust_live_loopback_stream_has_real_packets_and_optional_windows_owners() {
    use std::net::UdpSocket;
    use tracehound_eval::streaming::{RustLiveOptions, RustLiveSession, RustLiveState};
    let tool = PathBuf::from(
        std::env::var_os("TRACEHOUND_CAPTURE_TOOL")
            .expect("set TRACEHOUND_CAPTURE_TOOL to an installed dumpcap"),
    );
    let interfaces = tracehound_eval::live::capture_interfaces(&tool).unwrap();
    let interface = interfaces
        .iter()
        .find(|entry| {
            format!("{} {}", entry.id, entry.name)
                .to_ascii_lowercase()
                .contains("loopback")
        })
        .expect("capture helper has no loopback interface");
    let receiver = UdpSocket::bind("127.0.0.1:49697").unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let live = RustLiveSession::start(RustLiveOptions {
        capture_tool: tool,
        interface: interface.id.clone(),
        filter: Some("udp port 49697".into()),
        promiscuous: false,
        recording_limits: tracehound_eval::live::RecordingLimits {
            max_mebibytes: 64,
            max_seconds: 30,
        },
        analysis: StreamOptions::default(),
        process_attribution: cfg!(windows),
    })
    .unwrap();
    until(|| live.snapshot().state == RustLiveState::Running);
    std::thread::sleep(std::time::Duration::from_secs(1));
    for _ in 0..12 {
        sender
            .send_to(
                b"tracehound-owned-rust-stream-test",
                receiver.local_addr().unwrap(),
            )
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
    until(|| live.snapshot().stats.transport_packets > 0);
    std::thread::sleep(std::time::Duration::from_millis(600));
    if cfg!(windows) {
        assert!(live.snapshot().flows.iter().any(|flow| flow
            .process
            .iter()
            .any(|association| association.process.pid == std::process::id()
                && association.identity_time_verified)));
    }
    live.stop();
    until(|| live.finished());
    let summary = live.wait().unwrap();
    assert_eq!(live.snapshot().state, RustLiveState::Completed);
    assert!(summary.stats.transport_packets > 0);
    assert!(summary.report.findings.is_empty());
    let capture = live.retained_capture_path().unwrap();
    assert!(fs::metadata(&capture).unwrap().len() > 24);
    assert!(
        tracehound_eval::capture::inspect_capture(&capture)
            .unwrap()
            .input_packets
            > 0
    );
}
