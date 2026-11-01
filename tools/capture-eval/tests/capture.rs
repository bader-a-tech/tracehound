//! Independent wire fixtures: no packet generator or fingerprint reference code.
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tracehound_eval::capture::{
    http_fingerprint, inspect_capture, ja4s_from_handshake, prepare_capture,
    prepare_capture_cancellable,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tracehound-wire-{}-{}-{}",
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
        for entry in fs::read_dir(&self.0).unwrap().flatten() {
            let _ = fs::remove_file(entry.path());
        }
        let _ = fs::remove_dir(&self.0);
    }
}
fn hex(value: &str) -> Vec<u8> {
    value
        .split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data
        .chunks(2)
        .map(|b| u32::from(u16::from_be_bytes([b[0], *b.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn v4(
    protocol: u8,
    id: u16,
    offset: u16,
    source: [u8; 4],
    destination: [u8; 4],
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 8, 0];
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&id.to_be_bytes());
    ip[6..8].copy_from_slice(&offset.to_be_bytes());
    ip[8] = 64;
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&source);
    ip[16..20].copy_from_slice(&destination);
    let sum = checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    frame.extend(ip);
    frame.extend(payload);
    frame
}
fn udp_dns() -> Vec<u8> {
    dns_request("abc.example.co.uk", 1)
}
fn dns_request(name: &str, kind: u16) -> Vec<u8> {
    let mut dns = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        dns.push(label.len() as u8);
        dns.extend(label.as_bytes());
    }
    dns.push(0);
    dns.extend(kind.to_be_bytes());
    dns.extend([0, 1]);
    let mut udp = vec![0x9c, 0x40, 0, 53];
    udp.extend(((8 + dns.len()) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(dns);
    udp
}
fn tcp(reverse: bool, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let (src, dst, sp, dp) = if reverse {
        ([192, 0, 2, 1], [10, 0, 0, 1], 443u16, 50000u16)
    } else {
        ([10, 0, 0, 1], [192, 0, 2, 1], 50000u16, 443u16)
    };
    let mut tcp = vec![0u8; 20];
    tcp[..2].copy_from_slice(&sp.to_be_bytes());
    tcp[2..4].copy_from_slice(&dp.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
    tcp.extend(payload);
    let mut pseudo = Vec::from(src);
    pseudo.extend(dst);
    pseudo.extend([0, 6]);
    pseudo.extend((tcp.len() as u16).to_be_bytes());
    pseudo.extend(&tcp);
    let sum = checksum(&pseudo);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    v4(6, 1, 0, src, dst, &tcp)
}
fn pcap(directory: &Directory, name: &str, frames: &[(u32, Vec<u8>)]) -> PathBuf {
    let path = directory.path(name);
    let mut bytes = hex("d4 c3 b2 a1 02 00 04 00 00 00 00 00 00 00 00 00 ff ff 00 00 01 00 00 00");
    for (seconds, frame) in frames {
        bytes.extend(seconds.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend(frame);
    }
    fs::write(&path, bytes).unwrap();
    path
}
// RFC 8448 section 3 ServerHello. The golden hash is SHA256("0033,002b")[:12],
// with TLS 1.3, two extensions, no ALPN, and cipher 0x1301 decoded by hand.
fn rfc_server() -> Vec<u8> {
    hex("02 00 00 56 03 03 a6 af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04")
}
fn rfc_client() -> Vec<u8> {
    hex("01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01")
}
fn record(hello: &[u8]) -> Vec<u8> {
    let mut out = vec![22, 3, 3];
    out.extend((hello.len() as u16).to_be_bytes());
    out.extend(hello);
    out
}

#[test]
fn rfc8448_ja4s_is_independently_derived_and_truncation_is_rejected() {
    let hello = rfc_server();
    assert_eq!(
        ja4s_from_handshake(&hello).as_deref(),
        Some("t130200_1301_234ea6891581")
    );
    for length in 0..hello.len() {
        assert!(ja4s_from_handshake(&hello[..length]).is_none());
    }
    let mut bad = hello;
    bad.push(0);
    bad[3] += 1;
    assert!(ja4s_from_handshake(&bad).is_none());
}
#[test]
fn ipv4_fragments_reassemble_out_of_order_and_reject_overlap_or_expiry() {
    let directory = Directory::new();
    let data = udp_dns();
    let source = [10, 0, 0, 1];
    let dst = [192, 0, 2, 53];
    let first = v4(17, 7, 0x2000, source, dst, &data[..24]);
    let last = v4(17, 7, 3, source, dst, &data[24..]);
    let input = pcap(
        &directory,
        "fragment.pcap",
        &[(1, last.clone()), (2, first.clone())],
    );
    let output = directory.path("prepared.pcap");
    let report = prepare_capture(&input, &output).unwrap();
    assert_eq!(report.input_packets, 2);
    assert_eq!(report.output_packets, 1);
    assert_eq!(report.reassembled_datagrams, 1);
    assert_eq!(report.dns[0].name, "abc.example.co.uk");
    assert_eq!(inspect_capture(&output).unwrap().dns.len(), 1);
    let input = pcap(
        &directory,
        "overlap.pcap",
        &[(1, first.clone()), (2, first.clone()), (3, last.clone())],
    );
    let report = inspect_capture(&input).unwrap();
    assert_eq!(report.reassembled_datagrams, 0);
    assert!(report.discarded_fragment_sets > 0);
    let input = pcap(&directory, "expired.pcap", &[(1, first), (130, last)]);
    assert_eq!(inspect_capture(&input).unwrap().reassembled_datagrams, 0);
}
#[test]
fn ipv6_fragment_header_is_removed_and_payload_length_repaired() {
    let directory = Directory::new();
    let udp = udp_dns();
    let fragment = |offset: u16, more: bool, payload: &[u8]| {
        let mut out = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x86, 0xdd];
        let mut ip = vec![0; 40];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        ip[6] = 44;
        ip[7] = 64;
        ip[8..24].copy_from_slice(&"fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        ip[24..40].copy_from_slice(
            &"2001:db8::53"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        out.extend(ip);
        out.extend([17, 0]);
        out.extend((offset | u16::from(more)).to_be_bytes());
        out.extend(123u32.to_be_bytes());
        out.extend(payload);
        out
    };
    let input = pcap(
        &directory,
        "ipv6.pcap",
        &[
            (1, fragment(24, false, &udp[24..])),
            (2, fragment(0, true, &udp[..24])),
        ],
    );
    let output = directory.path("ipv6-prepared.pcap");
    let result = prepare_capture(&input, &output).unwrap();
    assert_eq!(result.reassembled_datagrams, 1);
    assert_eq!(result.dns.len(), 1);
    assert_eq!(inspect_capture(&output).unwrap().fragments_seen, 0);
}
#[test]
fn segmented_http_and_tls_are_reassembled_and_tuples_reset_on_syn() {
    let directory = Directory::new();
    let http=b"GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: wire-test\r\nAccept-Language: en-US,en;q=0.9\r\n\r\n";
    let cut = 32;
    let client = record(&rfc_client());
    let server = record(&rfc_server());
    let input = pcap(
        &directory,
        "streams.pcap",
        &[
            (1, tcp(false, 1, 2, &[])),
            (2, tcp(false, 2 + cut as u32, 0x18, &http[cut..])),
            (3, tcp(false, 2, 0x18, &http[..cut])),
            (4, tcp(false, 1, 2, &[])),
            (5, tcp(false, 2, 0x18, &client[..30])),
            (6, tcp(false, 32, 0x18, &client[30..])),
            (7, tcp(true, 1, 0x18, &server)),
        ],
    );
    let report = inspect_capture(&input).unwrap();
    assert_eq!(report.http.len(), 1);
    assert_eq!(report.tls.len(), 1);
    assert_eq!(report.tls[0].ja4s, "t130200_1301_234ea6891581");
    assert_eq!(report.tls[0].server_name.as_deref(), Some("server"));
    assert_eq!(report.http[0].host.as_deref(), Some("example.test"));
    assert_eq!(report.http[0].header_count, 3);
}
#[test]
fn invalid_containers_and_cancelled_preparation_never_leave_output() {
    let directory = Directory::new();
    let input = pcap(&directory, "valid.pcap", &[]);
    let output = directory.path("cancelled.pcap");
    assert!(prepare_capture_cancellable(&input, &output, &|| true).is_err());
    assert!(!output.exists());
    let mut bytes = fs::read(&input).unwrap();
    bytes.extend([0u8; 4]);
    fs::write(&input, bytes).unwrap();
    assert!(prepare_capture(&input, &output).is_err());
    assert!(!output.exists());
    fs::write(&output, b"preserve").unwrap();
    assert!(prepare_capture(&input, &output).is_err());
    assert_eq!(fs::read(&output).unwrap(), b"preserve");
}
#[test]
fn http_fingerprint_has_independent_header_and_cookie_hashes() {
    let request=b"GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: wire-test\r\nAccept-Language: en-US,en;q=0.9\r\nCookie: b=2; a=1\r\nReferer: https://example.test/\r\n\r\n";
    let (_, _, fingerprint, count) = http_fingerprint(request).unwrap();
    // Hashes computed independently with the platform SHA-256 utility.
    assert_eq!(count, 3);
    assert_eq!(
        fingerprint,
        "ge11cr03enus_5f038b23aea3_1eb7c54d5283_06beefe2b477"
    );
    assert!(http_fingerprint(b"PRI * HTTP/2.0\r\n\r\n").is_none());
    assert!(http_fingerprint(b"GET / HTTP/1.1\r\nInvalid header\r\n\r\n").is_none());
}
#[test]
fn sensor_ja4s_matches_rfc8448_over_the_public_flow_api() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let Some(sensor) = std::env::var_os("TRACEHOUND_TEST_SENSOR") else {
        eprintln!("set TRACEHOUND_TEST_SENSOR to validate the actual sensor");
        return;
    };
    let directory = Directory::new();
    let input = pcap(
        &directory,
        "rfc.pcap",
        &[
            (1, tcp(false, 1, 2, &[])),
            (1, tcp(false, 2, 0x18, &record(&rfc_client()))),
            (1, tcp(true, 1, 0x18, &record(&rfc_server()))),
            (601, tcp(false, 1000, 0x10, &[])),
        ],
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Child(
        Command::new(sensor)
            .arg("replay")
            .arg(input)
            .args([
                "-listen",
                &address.to_string(),
                "-speed",
                "1",
                "-quiet",
                "-json",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last_response = String::new();
    while Instant::now() < deadline {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "sensor exited before fingerprint inspection"
        );
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            stream
                .write_all(
                    b"GET /api/flows HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut response = Vec::new();
            if stream.take(1024 * 1024).read_to_end(&mut response).is_ok() {
                last_response = String::from_utf8_lossy(&response).into_owned();
                if let Some(at) = response.windows(4).position(|b| b == b"\r\n\r\n") {
                    if let Ok(flows) =
                        serde_json::from_slice::<Vec<serde_json::Value>>(&response[at + 4..])
                    {
                        if let Some(flow) = flows.iter().find(|flow| flow.get("ja4s").is_some()) {
                            assert_eq!(flow["ja4s"], "t130200_1301_234ea6891581");
                            return;
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    panic!("sensor did not publish the RFC8448 ServerHello fingerprint: {last_response}");
}
#[test]
fn explicit_pair_feed_is_applied_by_capture_jobs_and_preserves_provenance() {
    use tracehound_eval::feed::{PairFeed, PairIndicator};
    use tracehound_eval::runtime::{CaptureJob, JobReport, SensorOptions};
    use tracehound_eval::Severity;
    let Some(sensor) = std::env::var_os("TRACEHOUND_TEST_SENSOR") else {
        return;
    };
    let directory = Directory::new();
    let input = pcap(
        &directory,
        "pair.pcap",
        &[
            (1, tcp(false, 1, 2, &[])),
            (1, tcp(false, 2, 0x18, &record(&rfc_client()))),
            (1, tcp(true, 1, 0x18, &record(&rfc_server()))),
        ],
    );
    let enrichment = inspect_capture(&input).unwrap();
    let pair = &enrichment.tls[0];
    let path = directory.path("feed.json");
    let feed = PairFeed {
        schema_version: 1,
        source_url: "https://example.test/feed".into(),
        source_sha256: "a".repeat(64),
        license: "Test indicators".into(),
        entries: vec![PairIndicator {
            ja4: pair.ja4.clone(),
            ja4s: pair.ja4s.clone(),
            name: "Independent test association".into(),
            source_url: "https://example.test/report".into(),
            classification: "associated".into(),
            confidence: 0.65,
        }],
    };
    fs::write(&path, serde_json::to_vec(&feed).unwrap()).unwrap();
    let report = CaptureJob::analyze(
        input,
        SensorOptions {
            executable: sensor,
            pair_feed: Some(path),
            ..Default::default()
        },
        Severity::Low,
    )
    .unwrap()
    .wait()
    .unwrap();
    let JobReport::Analysis(report) = report.as_ref() else {
        panic!("expected analysis")
    };
    let finding = report
        .report
        .findings
        .iter()
        .find(|f| f.alert.rule_id == "TH-0008")
        .expect("explicit pair match");
    assert_eq!(
        finding.alert.evidence["source_url"],
        "https://example.test/report"
    );
    assert_eq!(finding.alert.severity, Severity::Medium);
    assert_eq!(
        report.enrichment["tls"][0]["ja4s"],
        "t130200_1301_234ea6891581"
    );
}
#[test]
fn capture_jobs_use_native_dns_private_suffix_grouping_and_home_networks() {
    use tracehound_eval::runtime::{CaptureJob, JobReport, SensorOptions};
    use tracehound_eval::Severity;
    let Some(sensor) = std::env::var_os("TRACEHOUND_TEST_SENSOR") else {
        return;
    };
    let directory = Directory::new();
    let frames: Vec<_> = (0..40)
        .map(|i| {
            let name =
                format!("{i:02}abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl.tenant.github.io");
            (
                1 + i,
                v4(
                    17,
                    i as u16,
                    0,
                    [10, 0, 0, 1],
                    [192, 0, 2, 53],
                    &dns_request(&name, 16),
                ),
            )
        })
        .collect();
    let input = pcap(&directory, "dns-policy.pcap", &frames);
    let options = SensorOptions {
        executable: sensor,
        ..Default::default()
    };
    let report = CaptureJob::analyze(input.clone(), options.clone(), Severity::Low)
        .unwrap()
        .wait()
        .unwrap();
    let JobReport::Analysis(report) = report.as_ref() else {
        panic!("expected analysis")
    };
    let matches: Vec<_> = report
        .report
        .findings
        .iter()
        .filter(|finding| finding.alert.rule_id == "TH-0002")
        .collect();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].alert.evidence["domain"], "tenant.github.io");
    assert_eq!(
        matches[0].alert.evidence["public_suffix_list"],
        "psl-crate-embedded"
    );
    let report = CaptureJob::analyze(
        input,
        SensorOptions {
            home_nets: Some("192.168.0.0/16".into()),
            ..options
        },
        Severity::Low,
    )
    .unwrap()
    .wait()
    .unwrap();
    let JobReport::Analysis(report) = report.as_ref() else {
        panic!("expected analysis")
    };
    assert!(report
        .report
        .findings
        .iter()
        .all(|finding| finding.alert.rule_id != "TH-0002"));
}
