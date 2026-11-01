//! Wire-built fixtures verify original offsets independently of the reader.
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tracehound_eval::capture::{
    inspect_capture, inspect_capture_with_visitor, scan_capture_events, PacketRef, StreamDecoder,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "tracehound-provenance-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
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
fn ip(protocol: u8, source_port: u16, reverse: bool, data: &[u8]) -> Vec<u8> {
    let mut transport = Vec::new();
    transport.extend(if reverse { 443u16 } else { source_port }.to_be_bytes());
    transport.extend(if reverse { source_port } else { 443u16 }.to_be_bytes());
    if protocol == 6 {
        transport.extend(1u32.to_be_bytes());
        transport.extend(0u32.to_be_bytes());
        transport.extend([0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    } else {
        transport.extend(((8 + data.len()) as u16).to_be_bytes());
        transport.extend([0, 0]);
    }
    transport.extend(data);
    let mut frame = vec![0u8; 20];
    frame[0] = 0x45;
    frame[9] = protocol;
    frame[2..4].copy_from_slice(&((20 + transport.len()) as u16).to_be_bytes());
    frame[12..20].copy_from_slice(if reverse {
        &[192, 0, 2, 1, 10, 0, 0, 1]
    } else {
        &[10, 0, 0, 1, 192, 0, 2, 1]
    });
    frame.extend(transport);
    frame
}
fn classic(frames: &[(u32, Vec<u8>, u32)]) -> Vec<u8> {
    let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    bytes.extend([0; 8]);
    bytes.extend(65_535u32.to_le_bytes());
    bytes.extend(101u32.to_le_bytes());
    for (seconds, frame, wire) in frames {
        bytes.extend(seconds.to_le_bytes());
        bytes.extend(123_456u32.to_le_bytes());
        bytes.extend((frame.len() as u32).to_le_bytes());
        bytes.extend(wire.to_le_bytes());
        bytes.extend(frame);
    }
    bytes
}
fn read_reference(path: &std::path::Path, reference: &PacketRef) -> Vec<u8> {
    let mut file = File::open(path).unwrap();
    file.seek(SeekFrom::Start(reference.data_offset)).unwrap();
    let mut bytes = vec![0; reference.captured_len as usize];
    file.read_exact(&mut bytes).unwrap();
    bytes
}

#[test]
fn classic_refs_seek_original_bytes_and_hash_complete_immutable_input() {
    let directory = Directory::new();
    let path = directory.path("source.pcap");
    let first = ip(
        6,
        50_000,
        false,
        b"GET / HTTP/1.1\r\nHost: source.test\r\n\r\n",
    );
    let second = ip(6, 50_000, true, b"HTTP/1.1 200 OK\r\n\r\n");
    let bytes = classic(&[
        (2, first.clone(), first.len() as u32),
        (3, second.clone(), second.len() as u32 + 10),
    ]);
    fs::write(&path, &bytes).unwrap();
    let mut events = Vec::new();
    let report = inspect_capture_with_visitor(&path, &|| false, &mut |event| {
        events.push(event.clone());
        Ok(())
    })
    .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].reference.number, 1);
    assert_eq!(events[1].reference.number, 2);
    assert_eq!(events[0].reference.data_offset, 40);
    assert_eq!(events[1].reference.data_offset, 56 + first.len() as u64);
    assert_eq!(events[0].reference.timestamp_ns, 2_123_456_000);
    assert_eq!(events[0].reference.link_type, 101);
    assert_eq!(read_reference(&path, &events[0].reference), first);
    assert_eq!(read_reference(&path, &events[1].reference), second);
    assert_eq!(events[0].src_port, Some(50_000));
    assert_eq!(events[0].tcp_flags, Some(0x18));
    let identity = report.capture.unwrap();
    assert_eq!(identity.bytes, bytes.len() as u64);
    assert_eq!(identity.sha256, format!("{:x}", Sha256::digest(&bytes)));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(report.http[0].packets, [events[0].reference.clone()]);
    assert_eq!(report.diagnostics.truncated_packets, 1);
    let flow = &report.flows[0];
    assert_eq!(flow.forward_packets, 1);
    assert_eq!(flow.reverse_packets, 1);
    assert_eq!(flow.forward_wire_bytes, first.len() as u64);
    assert_eq!(flow.reverse_wire_bytes, second.len() as u64 + 10);
}

fn block(kind: u32, mut body: Vec<u8>, out: &mut Vec<u8>) -> u64 {
    let start = out.len() as u64;
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let length = (body.len() + 12) as u32;
    out.extend(kind.to_le_bytes());
    out.extend(length.to_le_bytes());
    out.extend(body);
    out.extend(length.to_le_bytes());
    start
}
fn section(out: &mut Vec<u8>) {
    let mut body = 0x1a2b3c4du32.to_le_bytes().to_vec();
    body.extend([1, 0, 0, 0]);
    body.extend((-1i64).to_le_bytes());
    block(0x0a0d0d0a, body, out);
}
fn interface(resolution: u8, out: &mut Vec<u8>) {
    let mut body = 101u16.to_le_bytes().to_vec();
    body.extend([0, 0]);
    body.extend(65_535u32.to_le_bytes());
    body.extend([9, 0, 1, 0, resolution, 0, 0, 0, 0, 0, 0, 0]);
    block(1, body, out);
}
fn enhanced(id: u32, ticks: u64, data: &[u8], out: &mut Vec<u8>) -> u64 {
    let mut body = id.to_le_bytes().to_vec();
    body.extend(((ticks >> 32) as u32).to_le_bytes());
    body.extend((ticks as u32).to_le_bytes());
    body.extend((data.len() as u32).to_le_bytes());
    body.extend((data.len() as u32).to_le_bytes());
    body.extend(data);
    block(6, body, out) + 28
}

#[test]
fn pcapng_sections_interfaces_timestamps_and_payload_offsets_are_preserved() {
    let directory = Directory::new();
    let path = directory.path("source.pcapng");
    let frame = ip(17, 40_000, false, b"bytes");
    let mut bytes = Vec::new();
    section(&mut bytes);
    interface(9, &mut bytes);
    interface(6, &mut bytes);
    let first = enhanced(1, 2_500_000, &frame, &mut bytes);
    section(&mut bytes);
    interface(9, &mut bytes);
    let second = enhanced(0, 3_123_456_789, &frame, &mut bytes);
    fs::write(&path, &bytes).unwrap();
    let mut refs = Vec::new();
    inspect_capture_with_visitor(&path, &|| false, &mut |event| {
        refs.push(event.reference.clone());
        Ok(())
    })
    .unwrap();
    assert_eq!((refs[0].section, refs[0].interface), (0, 1));
    assert_eq!((refs[1].section, refs[1].interface), (1, 0));
    assert_eq!(refs[0].timestamp_ns, 2_500_000_000);
    assert_eq!(refs[1].timestamp_ns, 3_123_456_789);
    assert_eq!((refs[0].data_offset, refs[1].data_offset), (first, second));
    assert_eq!(read_reference(&path, &refs[0]), frame);
    assert_eq!(read_reference(&path, &refs[1]), frame);
}

#[test]
fn streaming_callback_drains_observations_and_failure_cleans_normalized_output() {
    let directory = Directory::new();
    let input = directory.path("source.pcap");
    let output = directory.path("normalized.pcap");
    let frames: Vec<_> = (0..80)
        .map(|i| {
            let frame = ip(
                6,
                40_000 + i,
                false,
                b"GET / HTTP/1.1\r\nHost: stream.test\r\n\r\n",
            );
            (i as u32, frame.clone(), frame.len() as u32)
        })
        .collect();
    fs::write(&input, classic(&frames)).unwrap();
    let mut observations = 0;
    let report = scan_capture_events(&input, Some(&output), &|| false, &mut |event, decoded| {
        assert_eq!(event.reference.number, observations + 1);
        observations += decoded.http.len() as u64;
        assert!(decoded.http.len() <= 1);
        assert!(decoded.packet.is_some());
        Ok(())
    })
    .unwrap();
    assert_eq!(observations, 80);
    assert!(report.http.is_empty());
    assert_eq!(report.flows.len(), 80);
    let failed = directory.path("failed.pcap");
    assert!(
        scan_capture_events(&input, Some(&failed), &|| false, &mut |_, _| Err(
            "index write failed".into()
        ))
        .is_err()
    );
    assert!(!failed.exists());
}

#[test]
fn incremental_decoder_has_complete_original_fragment_provenance() {
    let payload = b"GET / HTTP/1.1\r\nHost: fragment.test\r\n\r\n";
    let full = ip(6, 50_000, false, payload);
    let transport = &full[20..];
    let fragment = |offset: usize, more: bool, data: &[u8]| {
        let mut packet = full[..20].to_vec();
        packet[2..4].copy_from_slice(&((20 + data.len()) as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&42u16.to_be_bytes());
        packet[6..8].copy_from_slice(
            &(((offset / 8) as u16) | if more { 0x2000 } else { 0 }).to_be_bytes(),
        );
        packet.extend(data);
        packet
    };
    let first = fragment(0, true, &transport[..24]);
    let last = fragment(24, false, &transport[24..]);
    let reference = |number, data: &[u8]| PacketRef {
        number,
        link_type: 101,
        timestamp_ns: number * 1_000_000_000,
        captured_len: data.len() as u32,
        original_len: data.len() as u32,
        ..PacketRef::default()
    };
    let mut decoder = StreamDecoder::default();
    assert!(decoder
        .push_packet(reference(1, &last), &last)
        .unwrap()
        .packet
        .is_none());
    let events = decoder.push_packet(reference(2, &first), &first).unwrap();
    let packet = events.packet.unwrap();
    assert_eq!(
        packet.packets.iter().map(|r| r.number).collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(packet.payload, payload);
    assert_eq!(events.http[0].packets, packet.packets);
    assert_eq!(packet.wire_bytes, (first.len() + last.len()) as u64);
    assert!(packet.flow_id.is_some());
}

#[test]
fn flow_refs_are_bounded_without_losing_counts_and_old_enrichment_is_readable() {
    let directory = Directory::new();
    let input = directory.path("many.pcap");
    let frame = ip(17, 40_000, false, b"datagram");
    fs::write(
        &input,
        classic(
            &(0..100)
                .map(|i| (i, frame.clone(), frame.len() as u32))
                .collect::<Vec<_>>(),
        ),
    )
    .unwrap();
    let report = inspect_capture(&input).unwrap();
    let flow = &report.flows[0];
    assert_eq!(flow.forward_packets + flow.reverse_packets, 100);
    assert_eq!(flow.packets.len(), 32);
    assert!(flow.packet_refs_truncated);
    assert_eq!(report.diagnostics.packet_references_dropped, 68);
    let old = serde_json::json!({"input_packets":0,"output_packets":0,"fragments_seen":0,"reassembled_datagrams":0,"discarded_fragment_sets":0,"http":[],"tls":[],"dns":[],"warnings":[]});
    let old: tracehound_eval::capture::CaptureEnrichment = serde_json::from_value(old).unwrap();
    assert!(old.capture.is_none());
    assert!(old.flows.is_empty());
}

#[test]
fn long_running_decoder_drains_dns_beyond_the_report_observation_cap() {
    let dns = [
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];
    let mut frame = ip(17, 40_000, false, &dns);
    frame[22..24].copy_from_slice(&53u16.to_be_bytes());
    let mut decoder = StreamDecoder::default();
    for number in 1..=50_005u64 {
        let reference = PacketRef {
            number,
            link_type: 101,
            timestamp_ns: number * 1_000_000,
            captured_len: frame.len() as u32,
            original_len: frame.len() as u32,
            ..PacketRef::default()
        };
        let events = decoder.push_packet(reference, &frame).unwrap();
        assert_eq!(events.dns.len(), 1);
        assert_eq!(events.dns[0].packets[0].number, number);
    }
    let report = decoder.finish();
    assert_eq!(report.input_packets, 50_005);
    assert!(report.dns.is_empty());
    assert_eq!(report.flows.len(), 1);
}
