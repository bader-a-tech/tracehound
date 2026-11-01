//! Bounded passive capture enrichment and IP fragment reassembly.
//!
//! This implementation reads packet bytes independently of the Go sensor. HTTP
//! fingerprints cover cleartext HTTP/1.x; encrypted HTTP and HTTP/2/3 are not
//! decoded. TLS fingerprints cover TCP ClientHello/ServerHello only. Algorithms
//! are independently implemented from public field descriptions; no FoxIO
//! reference code or restricted expected-value corpus is included.
//!
//! Protocol references: RFC 791, RFC 8200, RFC 5722, RFC 8446, and the published
//! RFC 8448 section 3 handshake bytes. JA4H field layout is described by FoxIO's
//! public `technical_details/JA4H.png`; the ordered-header hash is independently
//! checked against a public HTTP observation at thumbprint.me/fp/http/9446.
//! JA4/JA4H/JA4S are FoxIO names; JA4+ has separate licensing/patent terms. This
//! source does not import FoxIO implementation code or its expected-value files.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_FRAME: usize = 1_048_576;
const MAX_FRAGMENT_SETS: usize = 256;
const MAX_FRAGMENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_TCP_STREAMS: usize = 512;
const MAX_TCP_BYTES: usize = 16 * 1024 * 1024;
const MAX_STREAM: usize = 65_536;
const MAX_PIECES_PER_STREAM: usize = 1024;
const MAX_PIECES_PER_DATAGRAM: usize = 1024;
const MAX_PENDING_PIECES: usize = 16_384;
const MAX_OBSERVATIONS: usize = 50_000;
const MAX_AGE_MS: u64 = 120_000;
const MAX_FLOWS: usize = 20_000;
const MAX_FLOW_REFS: usize = 32;
const MAX_STREAM_REFS: usize = 4096;
const MAX_PENDING_REFS: usize = 65_536;
const MAX_REPORT_REFS: usize = 262_144;

/// Absolute byte offset refers to the original captured frame payload, excluding
/// the PCAP record / PCAPNG block header. Numbers are one-based; sections and
/// interfaces are zero-based. References never point into normalized output.
#[derive(Clone, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PacketRef {
    pub number: u64,
    pub section: u32,
    pub interface: u32,
    pub link_type: u32,
    pub timestamp_ns: u64,
    pub data_offset: u64,
    pub captured_len: u32,
    pub original_len: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CaptureIdentity {
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CaptureDiagnostics {
    pub truncated_packets: u64,
    pub malformed_transport_packets: u64,
    pub discarded_fragment_sets: u64,
    pub discarded_tcp_streams: u64,
    pub untracked_flow_packets: u64,
    pub packet_references_dropped: u64,
}

/// Metadata for every original frame, suitable for an incremental disk index.
/// Fragmented or malformed transports can have IP endpoints but no ports.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PacketEvent {
    pub reference: PacketRef,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<u8>,
    pub tcp_flags: Option<u8>,
}

/// One complete transport datagram after IP reassembly. Only this incremental
/// event owns application payload bytes; stored enrichment contains references.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecodedPacket {
    #[serde(default)]
    pub flow_id: Option<u64>,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub tcp_flags: Option<u8>,
    pub tcp_sequence: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub timestamp_ms: u64,
    pub packets: Vec<PacketRef>,
    pub payload: Vec<u8>,
    pub wire_bytes: u64,
    pub captured_bytes: u64,
}

/// Canonical endpoint ordering makes direction stable across observations.
/// `src` is the lexicographically smaller (address, port) endpoint. TCP tuple
/// reuse starts a new observation when a distinct initiating SYN is seen.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FlowObservation {
    pub id: u64,
    pub section: u32,
    pub interface: u32,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub first_timestamp_ms: u64,
    pub last_timestamp_ms: u64,
    pub forward_packets: u64,
    pub reverse_packets: u64,
    pub forward_wire_bytes: u64,
    pub reverse_wire_bytes: u64,
    pub forward_captured_bytes: u64,
    pub reverse_captured_bytes: u64,
    pub syn_packets: u64,
    pub syn_ack_packets: u64,
    pub fin_packets: u64,
    pub rst_packets: u64,
    pub tcp_data_packets: u64,
    pub tcp_flags: u8,
    pub initiator: Option<IpAddr>,
    pub initiator_port: Option<u16>,
    pub tcp_syn_sequence: Option<u32>,
    pub packets: Vec<PacketRef>,
    pub packet_refs_truncated: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CaptureEnrichment {
    pub input_packets: u64,
    pub output_packets: u64,
    pub fragments_seen: u64,
    pub reassembled_datagrams: u64,
    pub discarded_fragment_sets: u64,
    pub http: Vec<HttpObservation>,
    pub tls: Vec<TlsObservation>,
    #[serde(default)]
    pub tls_clients: Vec<TlsClientObservation>,
    pub dns: Vec<DnsObservation>,
    pub warnings: Vec<String>,
    #[serde(default)]
    pub capture: Option<CaptureIdentity>,
    #[serde(default)]
    pub flows: Vec<FlowObservation>,
    #[serde(default)]
    pub diagnostics: CaptureDiagnostics,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpObservation {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub method: String,
    pub host: Option<String>,
    pub ja4h: String,
    pub header_count: usize,
    #[serde(default)]
    pub timestamp_ms: u64,
    #[serde(default)]
    pub packets: Vec<PacketRef>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TlsObservation {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ja4: String,
    pub ja4s: String,
    pub server_name: Option<String>,
    #[serde(default)]
    pub timestamp_ms: u64,
    #[serde(default)]
    pub last_timestamp_ms: u64,
    #[serde(default)]
    pub packets: Vec<PacketRef>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TlsClientObservation {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ja4: String,
    pub server_name: Option<String>,
    pub timestamp_ms: u64,
    pub packets: Vec<PacketRef>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsObservation {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub name: String,
    pub query_type: u16,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub src_port: u16,
    #[serde(default)]
    pub dst_port: u16,
    #[serde(default)]
    pub packets: Vec<PacketRef>,
}

impl Default for HttpObservation {
    fn default() -> Self {
        Self {
            src: Ipv4Addr::UNSPECIFIED.into(),
            dst: Ipv4Addr::UNSPECIFIED.into(),
            src_port: 0,
            dst_port: 0,
            method: String::new(),
            host: None,
            ja4h: String::new(),
            header_count: 0,
            timestamp_ms: 0,
            packets: Vec::new(),
        }
    }
}
impl Default for TlsObservation {
    fn default() -> Self {
        Self {
            src: Ipv4Addr::UNSPECIFIED.into(),
            dst: Ipv4Addr::UNSPECIFIED.into(),
            src_port: 0,
            dst_port: 0,
            ja4: String::new(),
            ja4s: String::new(),
            server_name: None,
            timestamp_ms: 0,
            last_timestamp_ms: 0,
            packets: Vec::new(),
        }
    }
}
impl Default for DnsObservation {
    fn default() -> Self {
        Self {
            src: Ipv4Addr::UNSPECIFIED.into(),
            dst: Ipv4Addr::UNSPECIFIED.into(),
            name: String::new(),
            query_type: 0,
            timestamp_ms: 0,
            src_port: 0,
            dst_port: 0,
            packets: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DecodeEvents {
    pub packet: Option<DecodedPacket>,
    pub http: Vec<HttpObservation>,
    pub tls: Vec<TlsObservation>,
    pub tls_clients: Vec<TlsClientObservation>,
    pub dns: Vec<DnsObservation>,
    pub warnings: Vec<String>,
    pub diagnostics: CaptureDiagnostics,
}

/// Incremental decoder for a live Rust sensor. Observations are drained after
/// each push; payload and provenance state remain bounded across long sessions.
#[derive(Default)]
pub struct StreamDecoder {
    inspector: Inspector,
}

impl StreamDecoder {
    pub fn push_packet(
        &mut self,
        reference: PacketRef,
        data: &[u8],
    ) -> Result<DecodeEvents, String> {
        if data.len() != reference.captured_len as usize
            || data.len() > MAX_FRAME
            || reference.original_len < reference.captured_len
        {
            return Err("packet reference lengths do not match captured bytes".into());
        }
        let packet = self.inspector.packet(reference, data, &mut None)?;
        Ok(self.inspector.take_events(packet))
    }
    pub fn finish(mut self) -> CaptureEnrichment {
        self.inspector.finish();
        self.inspector.report
    }
}

/// Inspect a capture without creating a normalized output file.
pub fn inspect_capture(input: &Path) -> Result<CaptureEnrichment, String> {
    process(input, None, &|| false, &mut |_| Ok(()), None, false)
}

pub fn inspect_capture_with_visitor(
    input: &Path,
    cancelled: &dyn Fn() -> bool,
    visitor: &mut dyn FnMut(&PacketEvent) -> Result<(), String>,
) -> Result<CaptureEnrichment, String> {
    process(input, None, cancelled, visitor, None, false)
}

/// Visit original frame metadata and optionally prepare normalized output in a
/// single read. Visitor failures abort preparation and remove its partial output.
pub fn scan_capture(
    input: &Path,
    output: Option<&Path>,
    cancelled: &dyn Fn() -> bool,
    visitor: &mut dyn FnMut(&PacketEvent) -> Result<(), String>,
) -> Result<CaptureEnrichment, String> {
    process(input, output, cancelled, visitor, None, false)
}

/// Streaming mode drains protocol observations after each callback. Returned
/// HTTP/TLS/DNS arrays are empty; callbacks can persist every event to disk.
pub fn scan_capture_events(
    input: &Path,
    output: Option<&Path>,
    cancelled: &dyn Fn() -> bool,
    visitor: &mut dyn FnMut(&PacketEvent, &DecodeEvents) -> Result<(), String>,
) -> Result<CaptureEnrichment, String> {
    process(
        input,
        output,
        cancelled,
        &mut |_| Ok(()),
        Some(visitor),
        false,
    )
}

/// Preserve unfragmented frames and replace complete IP fragment sets with one
/// reassembled frame in a nanosecond-resolution PCAP. Existing outputs are never
/// replaced. Incomplete, overlapping, expired, or over-budget sets are dropped
/// and counted. Mixed-link-type PCAPNG is rejected instead of being misdecoded.
pub fn prepare_capture(input: &Path, output: &Path) -> Result<CaptureEnrichment, String> {
    process(input, Some(output), &|| false, &mut |_| Ok(()), None, false)
}

/// The background runner can cancel preparation before or between packet reads.
/// The output belongs to this operation and is removed if cancellation occurs.
pub fn prepare_capture_cancellable(
    input: &Path,
    output: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<CaptureEnrichment, String> {
    process(input, Some(output), cancelled, &mut |_| Ok(()), None, false)
}

/// Authenticate original frame numbering and container metadata without keeping
/// fragment, connection, fingerprint, or protocol-observation state.
pub fn scan_packet_metadata(
    input: &Path,
    cancelled: &dyn Fn() -> bool,
    visitor: &mut dyn FnMut(&PacketEvent) -> Result<(), String>,
) -> Result<CaptureIdentity, String> {
    process(input, None, cancelled, visitor, None, true)?
        .capture
        .ok_or("capture identity is unavailable".into())
}

struct CaptureReader {
    reader: BufReader<File>,
    hash: Sha256,
    offset: u64,
}
impl Read for CaptureReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let length = self.reader.read(output)?;
        self.hash.update(&output[..length]);
        self.offset += length as u64;
        Ok(length)
    }
}

struct PreparedOutput {
    path: PathBuf,
    writer: Option<BufWriter<File>>,
    committed: bool,
    link: Option<u32>,
}

impl PreparedOutput {
    fn new(path: &Path) -> Result<Self, String> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| format!("create prepared capture {}: {e}", path.display()))?;
        Ok(Self {
            path: path.into(),
            writer: Some(BufWriter::new(file)),
            committed: false,
            link: None,
        })
    }

    fn header(&mut self, link: u32) -> Result<(), String> {
        if let Some(previous) = self.link {
            if previous != link {
                return Err("mixed-link-type PCAPNG cannot be normalized into one PCAP".into());
            }
            return Ok(());
        }
        self.link = Some(link);
        let out = self.writer.as_mut().unwrap();
        out.write_all(&0xa1b23c4du32.to_le_bytes())
            .map_err(io_error)?;
        for word in [2u16, 4] {
            out.write_all(&word.to_le_bytes()).map_err(io_error)?;
        }
        for word in [0u32, 0, MAX_FRAME as u32, link] {
            out.write_all(&word.to_le_bytes()).map_err(io_error)?;
        }
        Ok(())
    }

    fn packet(
        &mut self,
        link: u32,
        timestamp: Duration,
        wire: u32,
        data: &[u8],
    ) -> Result<(), String> {
        self.header(link)?;
        let seconds: u32 = timestamp
            .as_secs()
            .try_into()
            .map_err(|_| "PCAP timestamp exceeds 32-bit seconds")?;
        let out = self.writer.as_mut().unwrap();
        for word in [
            seconds,
            timestamp.subsec_nanos(),
            data.len() as u32,
            wire.max(data.len() as u32),
        ] {
            out.write_all(&word.to_le_bytes()).map_err(io_error)?;
        }
        out.write_all(data).map_err(io_error)
    }

    fn finish(mut self, link: u32) -> Result<(), String> {
        self.header(link)?;
        self.writer.as_mut().unwrap().flush().map_err(io_error)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for PreparedOutput {
    fn drop(&mut self) {
        self.writer.take();
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn io_error(error: std::io::Error) -> String {
    format!("capture I/O: {error}")
}

#[derive(Clone, Copy)]
enum Order {
    Little,
    Big,
}

impl Order {
    fn u16(self, b: &[u8]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes([b[0], b[1]]),
            Self::Big => u16::from_be_bytes([b[0], b[1]]),
        }
    }
    fn u32(self, b: &[u8]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(b[..4].try_into().unwrap()),
            Self::Big => u32::from_be_bytes(b[..4].try_into().unwrap()),
        }
    }
    fn i64(self, b: &[u8]) -> i64 {
        match self {
            Self::Little => i64::from_le_bytes(b[..8].try_into().unwrap()),
            Self::Big => i64::from_be_bytes(b[..8].try_into().unwrap()),
        }
    }
}

#[derive(Clone, Copy)]
struct Interface {
    link: u32,
    snaplen: u32,
    resolution: u8,
    offset: i64,
}

fn read_exact_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> Result<bool, String> {
    let first = reader.read(&mut buf[..1]).map_err(io_error)?;
    if first == 0 {
        return Ok(false);
    }
    reader.read_exact(&mut buf[1..]).map_err(io_error)?;
    Ok(true)
}

type DecodeVisitor<'a> = &'a mut dyn FnMut(&PacketEvent, &DecodeEvents) -> Result<(), String>;

fn process(
    input: &Path,
    output: Option<&Path>,
    cancelled: &dyn Fn() -> bool,
    visitor: &mut dyn FnMut(&PacketEvent) -> Result<(), String>,
    mut decoded_visitor: Option<DecodeVisitor<'_>>,
    metadata_only: bool,
) -> Result<CaptureEnrichment, String> {
    if cancelled() {
        return Err("capture preparation cancelled".into());
    }
    let mut reader = CaptureReader {
        reader: BufReader::new(
            File::open(input).map_err(|e| format!("open capture {}: {e}", input.display()))?,
        ),
        hash: Sha256::new(),
        offset: 0,
    };
    let mut magic = [0; 4];
    reader.read_exact(&mut magic).map_err(io_error)?;
    let mut sink = output.map(PreparedOutput::new).transpose()?;
    let mut inspector = Inspector::default();
    let mut default_link = 1;
    if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        let mut first = [0; 8];
        reader.read_exact(&mut first).map_err(io_error)?;
        let mut order = match &first[4..] {
            [0x4d, 0x3c, 0x2b, 0x1a] => Order::Little,
            [0x1a, 0x2b, 0x3c, 0x4d] => Order::Big,
            _ => return Err("invalid PCAPNG byte-order magic".into()),
        };
        let len = order.u32(&first) as usize;
        validate_block_length(len, 28)?;
        let mut rest = vec![0; len - 12];
        reader.read_exact(&mut rest).map_err(io_error)?;
        if order.u32(&rest[rest.len() - 4..]) as usize != len {
            return Err("invalid PCAPNG section length trailer".into());
        }
        if order.u16(&rest) != 1 || order.u16(&rest[2..]) != 0 {
            return Err("unsupported PCAPNG version".into());
        }
        let mut interfaces = Vec::<Interface>::new();
        let mut capture_link = None;
        let mut section = 0u32;
        let mut header = [0; 8];
        while read_exact_or_eof(&mut reader, &mut header)? {
            if cancelled() {
                return Err("capture preparation cancelled".into());
            }
            if header[..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
                let mut bom = [0; 4];
                reader.read_exact(&mut bom).map_err(io_error)?;
                order = match bom {
                    [0x4d, 0x3c, 0x2b, 0x1a] => Order::Little,
                    [0x1a, 0x2b, 0x3c, 0x4d] => Order::Big,
                    _ => return Err("invalid PCAPNG byte-order magic".into()),
                };
                let len = order.u32(&header[4..]) as usize;
                validate_block_length(len, 28)?;
                let mut body = vec![0; len - 12];
                reader.read_exact(&mut body).map_err(io_error)?;
                if order.u32(&body[body.len() - 4..]) as usize != len {
                    return Err("invalid PCAPNG section trailer".into());
                }
                if order.u16(&body) != 1 || order.u16(&body[2..]) != 0 {
                    return Err("unsupported PCAPNG version".into());
                }
                interfaces.clear();
                section = section
                    .checked_add(1)
                    .ok_or("PCAPNG section index overflow")?;
                continue;
            }
            let kind = order.u32(&header);
            let len = order.u32(&header[4..]) as usize;
            validate_block_length(len, 12)?;
            let mut body = vec![0; len - 8];
            let body_offset = reader.offset;
            reader.read_exact(&mut body).map_err(io_error)?;
            if order.u32(&body[body.len() - 4..]) as usize != len {
                return Err("invalid PCAPNG block length trailer".into());
            }
            let body = &body[..body.len() - 4];
            match kind {
                1 => {
                    if body.len() < 8 { return Err("truncated PCAPNG interface".into()); }
                    let mut interface = Interface { link: u32::from(order.u16(body)), snaplen: order.u32(&body[4..]), resolution: 6, offset: 0 };
                    let mut at = 8;
                    while at+4 <= body.len() {
                        let code = order.u16(&body[at..]); let size = order.u16(&body[at+2..]) as usize; at += 4;
                        if code == 0 { break; }
                        if at+size > body.len() { return Err("truncated PCAPNG interface option".into()); }
                        if code == 9 && size == 1 { interface.resolution = body[at]; }
                        if code == 14 && size == 8 { interface.offset = order.i64(&body[at..]); }
                        at += (size+3)&!3;
                    }
                    if interfaces.len() >= 4096 { return Err("too many PCAPNG interfaces".into()); }
                    if capture_link.is_some_and(|link| link != interface.link) {
                        return Err("mixed-link-type PCAPNG is not supported for enrichment".into());
                    }
                    capture_link = Some(interface.link);
                    if let Some(first) = interfaces.first() {
                        if first.link != interface.link { return Err("mixed-link-type PCAPNG is not supported for enrichment".into()); }
                    }
                    default_link = interface.link;
                    interfaces.push(interface);
                }
                6 | 2 => {
                    if body.len() < 20 { return Err("truncated PCAPNG packet block".into()); }
                    let id = if kind == 6 { order.u32(body) } else { u32::from(order.u16(body)) };
                    let interface = interfaces.get(id as usize).ok_or("PCAPNG packet references an unknown interface")?;
                    let ticks = (u64::from(order.u32(&body[4..]))<<32) | u64::from(order.u32(&body[8..]));
                    let timestamp = timestamp(ticks, *interface)?;
                    let captured = order.u32(&body[12..]) as usize;
                    let original = order.u32(&body[16..]);
                    if captured > MAX_FRAME || captured > body.len()-20 || original < captured as u32 { return Err("invalid PCAPNG packet length".into()); }
                    if interface.snaplen > 0 && captured > interface.snaplen as usize { return Err("PCAPNG packet exceeds interface snapshot length".into()); }
                    let reference = PacketRef {
                        number: inspector.report.input_packets + 1, section, interface: id,
                        link_type: interface.link, timestamp_ns: timestamp.as_nanos().try_into().map_err(|_| "capture timestamp exceeds nanosecond provenance range")?,
                        data_offset: body_offset + 20, captured_len: captured as u32, original_len: original,
                    };
                    let data = &body[20..20+captured];
                    let event = packet_event(reference.clone(), data);
                    visitor(&event)?;
                    let decoded = if metadata_only{inspector.report.input_packets+=1;None}else{inspector.packet(reference, data, &mut sink)?};
                    if let Some(callback) = &mut decoded_visitor { callback(&event, &inspector.take_events(decoded))?; }
                }
                3 => return Err("PCAPNG Simple Packet Blocks have no timestamps; export timestamped Enhanced Packet Blocks before analysis".into()),
                _ => {}
            }
        }
    } else {
        let (order, nanos) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (Order::Little, false),
            [0xa1, 0xb2, 0xc3, 0xd4] => (Order::Big, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => (Order::Little, true),
            [0xa1, 0xb2, 0x3c, 0x4d] => (Order::Big, true),
            _ => return Err("capture is not PCAP or PCAPNG".into()),
        };
        let mut header = [0; 20];
        reader.read_exact(&mut header).map_err(io_error)?;
        if order.u16(&header) != 2 || order.u16(&header[2..]) != 4 {
            return Err("unsupported PCAP version".into());
        }
        default_link = order.u32(&header[16..]) & 0xffff;
        let snaplen = order.u32(&header[12..]) as usize;
        if snaplen == 0 || snaplen > MAX_FRAME {
            return Err("unsupported PCAP snapshot length".into());
        }
        let mut packet = [0; 16];
        while read_exact_or_eof(&mut reader, &mut packet)? {
            if cancelled() {
                return Err("capture preparation cancelled".into());
            }
            let seconds = order.u32(&packet);
            let fraction = order.u32(&packet[4..]);
            if fraction >= if nanos { 1_000_000_000 } else { 1_000_000 } {
                return Err("invalid PCAP timestamp fraction".into());
            }
            let captured = order.u32(&packet[8..]) as usize;
            let original = order.u32(&packet[12..]);
            if captured > snaplen || captured > MAX_FRAME || original < captured as u32 {
                return Err("invalid PCAP packet length".into());
            }
            let mut data = vec![0; captured];
            let data_offset = reader.offset;
            reader.read_exact(&mut data).map_err(io_error)?;
            let timestamp = Duration::new(
                u64::from(seconds),
                if nanos { fraction } else { fraction * 1000 },
            );
            let reference = PacketRef {
                number: inspector.report.input_packets + 1,
                section: 0,
                interface: 0,
                link_type: default_link,
                timestamp_ns: timestamp
                    .as_nanos()
                    .try_into()
                    .map_err(|_| "capture timestamp exceeds nanosecond provenance range")?,
                data_offset,
                captured_len: captured as u32,
                original_len: original,
            };
            let event = packet_event(reference.clone(), &data);
            visitor(&event)?;
            let decoded = if metadata_only {
                inspector.report.input_packets += 1;
                None
            } else {
                inspector.packet(reference, &data, &mut sink)?
            };
            if let Some(callback) = &mut decoded_visitor {
                callback(&event, &inspector.take_events(decoded))?;
            }
        }
    }
    inspector.finish();
    inspector.report.capture = Some(CaptureIdentity {
        bytes: reader.offset,
        sha256: format!("{:x}", reader.hash.finalize()),
    });
    if let Some(sink) = sink {
        sink.finish(default_link)?;
    }
    Ok(inspector.report)
}

fn validate_block_length(size: usize, minimum: usize) -> Result<(), String> {
    if size < minimum || size > MAX_FRAME + 4096 || !size.is_multiple_of(4) {
        return Err("invalid or oversized PCAPNG block".into());
    }
    Ok(())
}

fn timestamp(ticks: u64, interface: Interface) -> Result<Duration, String> {
    let exponent = interface.resolution & 0x7f;
    let denominator = if interface.resolution & 0x80 != 0 {
        2u128.checked_pow(u32::from(exponent))
    } else {
        10u128.checked_pow(u32::from(exponent))
    }
    .ok_or("unsupported PCAPNG timestamp resolution")?;
    let nanos = u128::from(ticks)
        .checked_mul(1_000_000_000)
        .ok_or("PCAPNG timestamp overflow")?
        / denominator;
    let adjusted = i128::try_from(nanos).map_err(|_| "PCAPNG timestamp overflow")?
        + i128::from(interface.offset) * 1_000_000_000;
    if adjusted < 0 {
        return Err("negative PCAPNG timestamp is unsupported".into());
    }
    let seconds =
        u64::try_from(adjusted / 1_000_000_000).map_err(|_| "PCAPNG timestamp overflow")?;
    Ok(Duration::new(seconds, (adjusted % 1_000_000_000) as u32))
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FragmentKey {
    scope: u64,
    src: IpAddr,
    dst: IpAddr,
    id: u32,
    protocol: u8,
}
struct FragmentSet {
    parts: BTreeMap<usize, Vec<u8>>,
    prefix: Option<Vec<u8>>,
    network: usize,
    ipv6: bool,
    final_len: Option<usize>,
    updated: u64,
    wire: u64,
    packets: Vec<PacketRef>,
}
struct Fragment<'a> {
    key: FragmentKey,
    offset: usize,
    more: bool,
    payload: &'a [u8],
    prefix: Vec<u8>,
    network: usize,
    ipv6: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Endpoint {
    address: IpAddr,
    port: u16,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StreamKey {
    scope: u64,
    source: Endpoint,
    destination: Endpoint,
}
impl StreamKey {
    fn reverse(&self) -> Self {
        Self {
            scope: self.scope,
            source: self.destination.clone(),
            destination: self.source.clone(),
        }
    }
}
struct Stream {
    base: u32,
    parts: BTreeMap<u32, Vec<u8>>,
    updated: u64,
    done: bool,
    packets: BTreeMap<u32, Vec<PacketRef>>,
}
#[derive(Default)]
struct Pair {
    ja4: Option<String>,
    ja4s: Option<String>,
    server_name: Option<String>,
    emitted: bool,
    packets: Vec<PacketRef>,
}

#[derive(Default)]
struct Inspector {
    report: CaptureEnrichment,
    fragments: BTreeMap<FragmentKey, FragmentSet>,
    rejected: BTreeMap<FragmentKey, u64>,
    fragment_bytes: usize,
    streams: BTreeMap<StreamKey, Stream>,
    blocked_streams: BTreeMap<StreamKey, u64>,
    stream_bytes: usize,
    pairs: BTreeMap<StreamKey, Pair>,
    max_time: u64,
    flow_index: BTreeMap<(StreamKey, u8), usize>,
    retained_refs: usize,
}

impl Inspector {
    fn take_events(&mut self, packet: Option<DecodedPacket>) -> DecodeEvents {
        self.report.diagnostics.discarded_fragment_sets = self.report.discarded_fragment_sets;
        self.retained_refs = 0;
        DecodeEvents {
            packet,
            http: std::mem::take(&mut self.report.http),
            tls: std::mem::take(&mut self.report.tls),
            tls_clients: std::mem::take(&mut self.report.tls_clients),
            dns: std::mem::take(&mut self.report.dns),
            warnings: std::mem::take(&mut self.report.warnings),
            diagnostics: self.report.diagnostics.clone(),
        }
    }
    fn retain_references(&mut self, count: usize) -> bool {
        if self.retained_refs + count > MAX_REPORT_REFS {
            self.report.diagnostics.packet_references_dropped += count as u64;
            self.warn("Stored protocol evidence reference limit reached; use streaming indexing to retain later observations");
            false
        } else {
            self.retained_refs += count;
            true
        }
    }
    fn observe_flow(&mut self, scope: u64, packet: &DecodedPacket) -> Option<u64> {
        let source = Endpoint {
            address: packet.src,
            port: packet.src_port,
        };
        let destination = Endpoint {
            address: packet.dst,
            port: packet.dst_port,
        };
        let directional = StreamKey {
            scope,
            source,
            destination,
        };
        let canonical = Self::connection_key(&directional);
        let key = (canonical.clone(), packet.protocol);
        let syn = packet.tcp_flags.is_some_and(|flags| flags & 0x12 == 2);
        let existing = self.flow_index.get(&key).copied();
        let reused = existing.is_some_and(|index| {
            let flow = &self.report.flows[index];
            syn && (flow.tcp_syn_sequence != packet.tcp_sequence
                || flow.tcp_data_packets > 0
                || flow.fin_packets > 0
                || flow.rst_packets > 0
                || packet.timestamp_ms.saturating_sub(flow.last_timestamp_ms) > MAX_AGE_MS)
        });
        let index = if let Some(index) = existing.filter(|_| !reused) {
            index
        } else {
            if self.report.flows.len() >= MAX_FLOWS {
                self.flow_index.remove(&key);
                self.report.diagnostics.untracked_flow_packets += packet.packets.len() as u64;
                self.warn("Flow observation limit reached; remaining new connections are available only through the streaming packet index");
                return None;
            }
            let index = self.report.flows.len();
            let reference = packet.packets.first();
            self.report.flows.push(FlowObservation {
                id: index as u64 + 1,
                section: reference.map_or(0, |p| p.section),
                interface: reference.map_or(0, |p| p.interface),
                src: canonical.source.address,
                dst: canonical.destination.address,
                src_port: canonical.source.port,
                dst_port: canonical.destination.port,
                protocol: packet.protocol,
                first_timestamp_ms: packet.timestamp_ms,
                last_timestamp_ms: packet.timestamp_ms,
                forward_packets: 0,
                reverse_packets: 0,
                forward_wire_bytes: 0,
                reverse_wire_bytes: 0,
                forward_captured_bytes: 0,
                reverse_captured_bytes: 0,
                syn_packets: 0,
                syn_ack_packets: 0,
                fin_packets: 0,
                rst_packets: 0,
                tcp_data_packets: 0,
                tcp_flags: 0,
                initiator: None,
                initiator_port: None,
                tcp_syn_sequence: None,
                packets: Vec::new(),
                packet_refs_truncated: false,
            });
            self.flow_index.insert(key, index);
            index
        };
        let flow = &mut self.report.flows[index];
        flow.first_timestamp_ms = flow.first_timestamp_ms.min(packet.timestamp_ms);
        flow.last_timestamp_ms = flow.last_timestamp_ms.max(packet.timestamp_ms);
        if directional.source == canonical.source {
            flow.forward_packets += packet.packets.len() as u64;
            flow.forward_wire_bytes = flow.forward_wire_bytes.saturating_add(packet.wire_bytes);
            flow.forward_captured_bytes = flow
                .forward_captured_bytes
                .saturating_add(packet.captured_bytes);
        } else {
            flow.reverse_packets += packet.packets.len() as u64;
            flow.reverse_wire_bytes = flow.reverse_wire_bytes.saturating_add(packet.wire_bytes);
            flow.reverse_captured_bytes = flow
                .reverse_captured_bytes
                .saturating_add(packet.captured_bytes);
        }
        if let Some(flags) = packet.tcp_flags {
            flow.tcp_flags |= flags;
            flow.syn_packets += u64::from(flags & 0x12 == 2);
            flow.syn_ack_packets += u64::from(flags & 0x12 == 0x12);
            flow.fin_packets += u64::from(flags & 1 != 0);
            flow.rst_packets += u64::from(flags & 4 != 0);
            flow.tcp_data_packets += u64::from(!packet.payload.is_empty());
            if syn {
                flow.initiator = Some(packet.src);
                flow.initiator_port = Some(packet.src_port);
                flow.tcp_syn_sequence = packet.tcp_sequence;
            }
        }
        for reference in &packet.packets {
            if flow.packets.len() < MAX_FLOW_REFS {
                flow.packets.push(reference.clone());
            } else {
                flow.packet_refs_truncated = true;
                self.report.diagnostics.packet_references_dropped += 1;
            }
        }
        Some(flow.id)
    }
    fn warn(&mut self, message: &str) {
        if self.report.warnings.len() < 32
            && !self.report.warnings.iter().any(|item| item == message)
        {
            self.report.warnings.push(message.into());
        }
    }
    fn packet(
        &mut self,
        reference: PacketRef,
        data: &[u8],
        output: &mut Option<PreparedOutput>,
    ) -> Result<Option<DecodedPacket>, String> {
        let link = reference.link_type;
        let scope = (u64::from(reference.section) << 32) | u64::from(reference.interface);
        let time = Duration::from_nanos(reference.timestamp_ns);
        let wire = reference.original_len;
        self.report.input_packets += 1;
        if reference.captured_len < reference.original_len {
            self.report.diagnostics.truncated_packets += 1;
        }
        let ms = time.as_millis().min(u128::from(u64::MAX)) as u64;
        self.max_time = self.max_time.max(ms);
        self.expire();
        let frame = if let Some(fragment) = fragment(link, scope, data) {
            self.report.fragments_seen += 1;
            self.reassemble(fragment, wire, ms, reference)
        } else if fragment_marked(link, data) {
            self.report.fragments_seen += 1;
            self.report.discarded_fragment_sets += 1;
            self.warn("Malformed or truncated IP fragments were discarded");
            None
        } else {
            Some((data.to_vec(), wire, vec![reference]))
        };
        let mut decoded = None;
        if let Some((data, wire, references)) = frame {
            self.report.output_packets += 1;
            decoded = decode_packet(link, &data, &references);
            if let Some(packet) = &mut decoded {
                packet.flow_id = self.observe_flow(scope, packet);
            } else if transport(link, &data)
                .is_some_and(|(_, _, protocol, _)| matches!(protocol, 6 | 17))
            {
                self.report.diagnostics.malformed_transport_packets += 1;
            }
            self.inspect_with_refs(link, scope, &data, ms, &references);
            if let Some(output) = output {
                output.packet(link, time, wire, &data)?;
            }
        }
        Ok(decoded)
    }
    fn expire(&mut self) {
        let oldest = self.max_time.saturating_sub(MAX_AGE_MS);
        let expired: Vec<_> = self
            .fragments
            .iter()
            .filter(|(_, set)| set.updated < oldest)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.discard(&key);
        }
        self.rejected.retain(|_, at| *at >= oldest);
        self.blocked_streams.retain(|_, at| *at >= oldest);
        let expired: Vec<_> = self
            .streams
            .iter()
            .filter(|(_, stream)| stream.updated < oldest)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            if self.streams.get(&key).is_some_and(|stream| !stream.done) {
                self.report.diagnostics.discarded_tcp_streams += 1;
            }
            self.drop_stream(&key);
        }
    }
    fn discard(&mut self, key: &FragmentKey) {
        if let Some(set) = self.fragments.remove(key) {
            self.fragment_bytes -= set.parts.values().map(Vec::len).sum::<usize>();
            self.report.discarded_fragment_sets += 1;
        }
    }
    fn reject(&mut self, key: &FragmentKey, at: u64) {
        if !self.fragments.contains_key(key) && !self.rejected.contains_key(key) {
            self.report.discarded_fragment_sets += 1;
        }
        self.discard(key);
        if self.rejected.len() >= MAX_FRAGMENT_SETS * 4 {
            self.rejected.pop_first();
        }
        self.rejected.insert(key.clone(), at);
    }
    fn reassemble(
        &mut self,
        fragment: Fragment<'_>,
        wire: u32,
        at: u64,
        reference: PacketRef,
    ) -> Option<(Vec<u8>, u32, Vec<PacketRef>)> {
        if self.rejected.contains_key(&fragment.key) {
            return None;
        }
        let end = fragment.offset.checked_add(fragment.payload.len())?;
        if end > 65_535
            || fragment.payload.is_empty()
            || (fragment.more && !fragment.payload.len().is_multiple_of(8))
        {
            self.reject(&fragment.key, at);
            self.warn("Malformed IP fragments were discarded");
            return None;
        }
        if !self.fragments.contains_key(&fragment.key) && self.fragments.len() >= MAX_FRAGMENT_SETS
        {
            if let Some(key) = self
                .fragments
                .iter()
                .min_by_key(|(_, set)| set.updated)
                .map(|(key, _)| key.clone())
            {
                self.discard(&key);
            }
            self.warn("IP fragment state reached its capacity; oldest incomplete datagrams were discarded");
        }
        if self.fragment_bytes + fragment.payload.len() > MAX_FRAGMENT_BYTES {
            self.reject(&fragment.key, at);
            self.warn("IP fragment memory limit reached");
            return None;
        }
        if self
            .fragments
            .get(&fragment.key)
            .is_some_and(|set| set.parts.len() >= MAX_PIECES_PER_DATAGRAM)
            || self
                .fragments
                .values()
                .map(|set| set.parts.len())
                .sum::<usize>()
                >= MAX_PENDING_PIECES
        {
            self.reject(&fragment.key, at);
            self.warn("IP fragment segment limit reached; incomplete datagram discarded");
            return None;
        }
        let key = fragment.key.clone();
        let set = self
            .fragments
            .entry(key.clone())
            .or_insert_with(|| FragmentSet {
                parts: BTreeMap::new(),
                prefix: None,
                network: fragment.network,
                ipv6: fragment.ipv6,
                final_len: None,
                updated: at,
                wire: 0,
                packets: Vec::new(),
            });
        let overlap = set
            .parts
            .iter()
            .any(|(start, bytes)| fragment.offset < start + bytes.len() && *start < end);
        if overlap
            || set.final_len.is_some_and(|length| end > length)
            || (!fragment.more && set.final_len.is_some_and(|length| length != end))
        {
            self.reject(&key, at);
            self.warn("Overlapping or inconsistent IP fragments were discarded");
            return None;
        }
        set.updated = at;
        set.wire = set.wire.saturating_add(u64::from(wire));
        set.packets.push(reference);
        if fragment.offset == 0 {
            set.prefix = Some(fragment.prefix);
        }
        if !fragment.more {
            set.final_len = Some(end);
        }
        self.fragment_bytes += fragment.payload.len();
        set.parts.insert(fragment.offset, fragment.payload.to_vec());
        let final_len = set.final_len?;
        let mut next = 0;
        for (start, bytes) in &set.parts {
            if *start != next {
                return None;
            }
            next += bytes.len();
        }
        if next != final_len || set.prefix.is_none() {
            return None;
        }
        let mut set = self.fragments.remove(&key).unwrap();
        self.fragment_bytes -= set.parts.values().map(Vec::len).sum::<usize>();
        let mut packet = set.prefix.take().unwrap();
        for bytes in set.parts.into_values() {
            packet.extend(bytes);
        }
        if set.ipv6 {
            let payload = packet.len().checked_sub(set.network + 40)?;
            if payload > 65_535 {
                self.report.discarded_fragment_sets += 1;
                return None;
            }
            packet[set.network + 4..set.network + 6]
                .copy_from_slice(&(payload as u16).to_be_bytes());
        } else {
            let length = packet.len().checked_sub(set.network)?;
            if length > 65_535 {
                self.report.discarded_fragment_sets += 1;
                return None;
            }
            packet[set.network + 2..set.network + 4]
                .copy_from_slice(&(length as u16).to_be_bytes());
            let flags = be16(&packet[set.network + 6..]) & 0x4000;
            packet[set.network + 6..set.network + 8].copy_from_slice(&flags.to_be_bytes());
            packet[set.network + 10..set.network + 12].fill(0);
            let header = (packet[set.network] & 15) as usize * 4;
            let sum = checksum(&packet[set.network..set.network + header]);
            packet[set.network + 10..set.network + 12].copy_from_slice(&sum.to_be_bytes());
        }
        self.report.reassembled_datagrams += 1;
        set.packets.sort_by_key(|packet| packet.number);
        Some((
            packet,
            set.wire.min(u64::from(u32::MAX)) as u32,
            set.packets,
        ))
    }
    fn drop_stream(&mut self, key: &StreamKey) {
        if let Some(stream) = self.streams.remove(key) {
            self.stream_bytes -= stream.parts.values().map(Vec::len).sum::<usize>();
        }
        self.pairs.remove(key);
        self.pairs.remove(&key.reverse());
    }
    fn connection_key(key: &StreamKey) -> StreamKey {
        key.clone().min(key.reverse())
    }
    fn block_stream(&mut self, key: &StreamKey, at: u64) {
        self.report.diagnostics.discarded_tcp_streams += 1;
        self.drop_stream(key);
        self.drop_stream(&key.reverse());
        let connection = Self::connection_key(key);
        if !self.blocked_streams.contains_key(&connection)
            && self.blocked_streams.len() >= MAX_TCP_STREAMS
        {
            if let Some(old) = self
                .blocked_streams
                .iter()
                .min_by_key(|(_, time)| *time)
                .map(|(key, _)| key.clone())
            {
                self.blocked_streams.remove(&old);
            }
            self.warn("TCP ambiguity tombstone limit reached; oldest tombstone was discarded");
        }
        self.blocked_streams.insert(connection, at);
    }
    fn complete_stream(&mut self, key: &StreamKey) {
        if let Some(stream) = self.streams.get_mut(key) {
            self.stream_bytes -= stream.parts.values().map(Vec::len).sum::<usize>();
            stream.parts.clear();
            stream.packets.clear();
            stream.done = true;
        }
    }
    #[cfg(test)]
    fn inspect(&mut self, link: u32, scope: u64, frame: &[u8], at: u64) {
        self.inspect_with_refs(link, scope, frame, at, &[]);
    }
    fn inspect_with_refs(
        &mut self,
        link: u32,
        scope: u64,
        frame: &[u8],
        at: u64,
        references: &[PacketRef],
    ) {
        let Some((src, dst, protocol, payload)) = transport(link, frame) else {
            return;
        };
        if protocol == 17 && payload.len() >= 8 && be16(&payload[2..]) == 53 {
            let length = usize::from(be16(&payload[4..]));
            if length < 8 || length > payload.len() {
                self.warn("Malformed or truncated UDP datagrams were not enriched");
                return;
            }
            if let Some((name, query_type)) = dns_query(&payload[8..length]) {
                if self.report.dns.len() < MAX_OBSERVATIONS
                    && self.retain_references(references.len())
                {
                    self.report.dns.push(DnsObservation {
                        src,
                        dst,
                        name,
                        query_type,
                        timestamp_ms: at,
                        src_port: be16(payload),
                        dst_port: be16(&payload[2..]),
                        packets: references.to_vec(),
                    });
                } else {
                    self.warn("DNS enrichment observation limit reached");
                }
            }
            return;
        }
        if protocol != 6 || payload.len() < 20 {
            return;
        }
        let header = usize::from(payload[12] >> 4) * 4;
        if header < 20 || header > payload.len() {
            return;
        }
        let key = StreamKey {
            scope,
            source: Endpoint {
                address: src,
                port: be16(payload),
            },
            destination: Endpoint {
                address: dst,
                port: be16(&payload[2..]),
            },
        };
        let syn = payload[13] & 2 != 0;
        if syn && payload[13] & 16 == 0 {
            self.drop_stream(&key);
            self.drop_stream(&key.reverse());
            self.blocked_streams.remove(&Self::connection_key(&key));
        }
        if self
            .blocked_streams
            .contains_key(&Self::connection_key(&key))
        {
            return;
        }
        let data = &payload[header..];
        if data.is_empty() {
            return;
        }
        if !self.streams.contains_key(&key) && self.streams.len() >= MAX_TCP_STREAMS {
            if let Some(old) = self
                .streams
                .iter()
                .min_by_key(|(_, stream)| stream.updated)
                .map(|(key, _)| key.clone())
            {
                self.drop_stream(&old);
            }
            self.warn("TCP enrichment stream limit reached; oldest streams were discarded");
        }
        if self.stream_bytes + data.len() > MAX_TCP_BYTES {
            self.report.diagnostics.discarded_tcp_streams += 1;
            self.warn("TCP enrichment memory limit reached");
            return;
        }
        if self
            .streams
            .get(&key)
            .is_some_and(|stream| stream.parts.len() >= MAX_PIECES_PER_STREAM)
            || self
                .streams
                .values()
                .map(|stream| stream.parts.len())
                .sum::<usize>()
                >= MAX_PENDING_PIECES
        {
            self.block_stream(&key, at);
            self.warn("TCP enrichment segment limit reached; incomplete handshake was discarded");
            return;
        }
        let stream_refs = self.streams.get(&key).map_or(0, |stream| {
            stream.packets.values().map(Vec::len).sum::<usize>()
        });
        let pending_refs = self
            .streams
            .values()
            .flat_map(|stream| stream.packets.values())
            .map(Vec::len)
            .sum::<usize>()
            + self
                .pairs
                .values()
                .map(|pair| pair.packets.len())
                .sum::<usize>();
        if stream_refs + references.len() > MAX_STREAM_REFS
            || pending_refs + references.len() > MAX_PENDING_REFS
        {
            self.report.diagnostics.packet_references_dropped += references.len() as u64;
            self.block_stream(&key, at);
            self.warn("TCP evidence reference limit reached; incomplete fingerprint was discarded");
            return;
        }
        let sequence = be32(&payload[4..]).wrapping_add(u32::from(syn));
        let stream = self.streams.entry(key.clone()).or_insert_with(|| Stream {
            base: sequence,
            parts: BTreeMap::new(),
            updated: at,
            done: false,
            packets: BTreeMap::new(),
        });
        stream.updated = at;
        if stream.done {
            return;
        }
        if sequence.wrapping_sub(stream.base) > u32::MAX / 2 {
            let backwards = stream.base.wrapping_sub(sequence) as usize;
            if backwards > MAX_STREAM {
                return;
            }
            stream.base = sequence;
        }
        if sequence.wrapping_sub(stream.base) as usize + data.len() > MAX_STREAM {
            self.block_stream(&key, at);
            return;
        }
        if let Some(previous) = stream.parts.get(&sequence) {
            if previous == data {
                return;
            }
            self.block_stream(&key, at);
            self.warn("Conflicting TCP retransmissions were not fingerprinted");
            return;
        }
        self.stream_bytes += data.len();
        stream.parts.insert(sequence, data.to_vec());
        stream.packets.insert(sequence, references.to_vec());
        let mut pieces: Vec<_> = stream
            .parts
            .iter()
            .map(|(seq, data)| (seq.wrapping_sub(stream.base) as usize, data))
            .collect();
        pieces.sort_by_key(|(offset, _)| *offset);
        let mut contiguous = Vec::new();
        let mut support = Vec::new();
        for (offset, data) in pieces {
            if offset > contiguous.len() {
                break;
            }
            let overlap = contiguous.len() - offset;
            let common = overlap.min(data.len());
            if contiguous[offset..offset + common] != data[..common] {
                self.block_stream(&key, at);
                self.warn("Overlapping conflicting TCP data was not fingerprinted");
                return;
            }
            contiguous.extend_from_slice(&data[common..]);
            if common < data.len() {
                if let Some(packets) = stream.packets.get(&stream.base.wrapping_add(offset as u32))
                {
                    support.extend(packets.iter().cloned());
                }
            }
        }
        support.sort_by_key(|packet| packet.number);
        support.dedup_by_key(|packet| packet.number);
        if let Some((method, host, ja4h, header_count)) = http_fingerprint(&contiguous) {
            if self.report.http.len() < MAX_OBSERVATIONS && self.retain_references(support.len()) {
                self.report.http.push(HttpObservation {
                    src,
                    dst,
                    src_port: key.source.port,
                    dst_port: key.destination.port,
                    method,
                    host,
                    ja4h,
                    header_count,
                    timestamp_ms: support
                        .iter()
                        .map(|p| p.timestamp_ns / 1_000_000)
                        .min()
                        .unwrap_or(at),
                    packets: support.clone(),
                });
            } else {
                self.warn("HTTP fingerprint observation limit reached");
            }
            self.complete_stream(&key);
        }
        if let Some(handshake) = tls_handshake(&contiguous) {
            if let Some((ja4, server_name)) = ja4_from_handshake(&handshake) {
                if self.report.tls_clients.len() < MAX_OBSERVATIONS
                    && self.retain_references(support.len())
                {
                    self.report.tls_clients.push(TlsClientObservation {
                        src,
                        dst,
                        src_port: key.source.port,
                        dst_port: key.destination.port,
                        ja4: ja4.clone(),
                        server_name: server_name.clone(),
                        timestamp_ms: support
                            .iter()
                            .map(|p| p.timestamp_ns / 1_000_000)
                            .min()
                            .unwrap_or(at),
                        packets: support.clone(),
                    });
                } else {
                    self.warn("TLS client observation limit reached");
                }
                let pair = self.pairs.entry(key.clone()).or_default();
                pair.ja4 = Some(ja4);
                pair.server_name = server_name;
                pair.packets.extend(support.iter().cloned());
                self.complete_stream(&key);
                self.emit_pair(&key);
            } else if let Some(ja4s) = ja4s_from_handshake(&handshake) {
                let client = key.reverse();
                let pair = self.pairs.entry(client.clone()).or_default();
                pair.ja4s = Some(ja4s);
                pair.packets.extend(support.iter().cloned());
                self.complete_stream(&key);
                self.emit_pair(&client);
            }
        }
    }
    fn emit_pair(&mut self, key: &StreamKey) {
        let Some(pair) = self.pairs.get_mut(key) else {
            return;
        };
        if pair.emitted {
            return;
        }
        let (Some(ja4), Some(ja4s)) = (&pair.ja4, &pair.ja4s) else {
            return;
        };
        let reference_count = pair.packets.len();
        if self.retained_refs + reference_count > MAX_REPORT_REFS {
            pair.emitted = true;
            self.report.diagnostics.packet_references_dropped += reference_count as u64;
            self.warn("Stored TLS evidence reference limit reached; use streaming indexing to retain later observations");
            return;
        }
        if self.report.tls.len() < MAX_OBSERVATIONS {
            pair.packets.sort_by_key(|packet| packet.number);
            pair.packets.dedup_by_key(|packet| packet.number);
            self.report.tls.push(TlsObservation {
                src: key.source.address,
                dst: key.destination.address,
                src_port: key.source.port,
                dst_port: key.destination.port,
                ja4: ja4.clone(),
                ja4s: ja4s.clone(),
                server_name: pair.server_name.clone(),
                timestamp_ms: pair
                    .packets
                    .iter()
                    .map(|p| p.timestamp_ns / 1_000_000)
                    .min()
                    .unwrap_or(0),
                last_timestamp_ms: pair
                    .packets
                    .iter()
                    .map(|p| p.timestamp_ns / 1_000_000)
                    .max()
                    .unwrap_or(0),
                packets: pair.packets.clone(),
            });
            self.retained_refs += reference_count;
        } else {
            self.warn("TLS pair observation limit reached");
        }
        self.pairs.get_mut(key).unwrap().emitted = true;
        self.pairs.get_mut(key).unwrap().packets.clear();
    }
    fn finish(&mut self) {
        self.report.discarded_fragment_sets += self.fragments.len() as u64;
        self.report.diagnostics.discarded_fragment_sets = self.report.discarded_fragment_sets;
        if !self.fragments.is_empty() {
            self.warn("Incomplete IP fragment sets were discarded at end of capture");
        }
        self.warn("HTTP enrichment covers the first cleartext HTTP/1.x request per TCP flow; encrypted HTTP and HTTP/2/3 are not decoded");
    }
}

fn packet_event(reference: PacketRef, data: &[u8]) -> PacketEvent {
    let mut event = PacketEvent {
        reference,
        ..PacketEvent::default()
    };
    if let Some((src, dst, protocol, payload)) = transport(event.reference.link_type, data) {
        event.src = Some(src);
        event.dst = Some(dst);
        event.protocol = Some(protocol);
        if (protocol == 6 && payload.len() >= 20) || (protocol == 17 && payload.len() >= 8) {
            event.src_port = Some(be16(payload));
            event.dst_port = Some(be16(&payload[2..]));
            if protocol == 6 {
                event.tcp_flags = Some(payload[13]);
            }
        }
    } else if let Some(offset) = network_offset(event.reference.link_type, data) {
        let ip = &data[offset..];
        match ip.first().map(|byte| byte >> 4) {
            Some(4) if ip.len() >= 20 => {
                event.src = Some(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]).into());
                event.dst = Some(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]).into());
                event.protocol = Some(ip[9]);
            }
            Some(6) if ip.len() >= 40 => {
                event.src = Some(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap()).into());
                event.dst = Some(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap()).into());
                event.protocol = Some(ip[6]);
                let mut next = ip[6];
                let mut at = 40;
                for _ in 0..16 {
                    if next == 44 {
                        if let Some(protocol) = ip.get(at) {
                            event.protocol = Some(*protocol);
                        }
                        break;
                    }
                    if !matches!(next, 0 | 43 | 60 | 51) || at + 2 > ip.len() {
                        break;
                    }
                    let size = if next == 51 {
                        (usize::from(ip[at + 1]) + 2) * 4
                    } else {
                        (usize::from(ip[at + 1]) + 1) * 8
                    };
                    next = ip[at];
                    at += size;
                    if at > ip.len() {
                        break;
                    }
                    event.protocol = Some(next);
                }
            }
            _ => {}
        }
    }
    event
}

fn decode_packet(link: u32, frame: &[u8], references: &[PacketRef]) -> Option<DecodedPacket> {
    let (src, dst, protocol, transport) = transport(link, frame)?;
    let (src_port, dst_port, tcp_flags, tcp_sequence, tcp_ack, payload) = match protocol {
        6 => {
            if transport.len() < 20 {
                return None;
            }
            let header = usize::from(transport[12] >> 4) * 4;
            if header < 20 || header > transport.len() {
                return None;
            }
            (
                be16(transport),
                be16(&transport[2..]),
                Some(transport[13]),
                Some(be32(&transport[4..])),
                Some(be32(&transport[8..])),
                &transport[header..],
            )
        }
        17 => {
            if transport.len() < 8 {
                return None;
            }
            let length = usize::from(be16(&transport[4..]));
            if length < 8 || length > transport.len() {
                return None;
            }
            (
                be16(transport),
                be16(&transport[2..]),
                None,
                None,
                None,
                &transport[8..length],
            )
        }
        _ => (0, 0, None, None, None, transport),
    };
    Some(DecodedPacket {
        flow_id: None,
        src,
        dst,
        src_port,
        dst_port,
        protocol,
        tcp_flags,
        tcp_sequence,
        tcp_ack,
        timestamp_ms: references
            .iter()
            .map(|p| p.timestamp_ns / 1_000_000)
            .max()
            .unwrap_or(0),
        packets: references.to_vec(),
        payload: payload.to_vec(),
        wire_bytes: references.iter().map(|p| u64::from(p.original_len)).sum(),
        captured_bytes: references.iter().map(|p| u64::from(p.captured_len)).sum(),
    })
}

fn network_offset(link: u32, frame: &[u8]) -> Option<usize> {
    match link {
        1 => {
            if frame.len() < 14 {
                return None;
            }
            let mut offset = 14;
            let mut kind = be16(&frame[12..]);
            for _ in 0..4 {
                if kind != 0x8100 && kind != 0x88a8 {
                    break;
                }
                if frame.len() < offset + 4 {
                    return None;
                }
                kind = be16(&frame[offset + 2..]);
                offset += 4;
            }
            if kind == 0x0800 || kind == 0x86dd {
                Some(offset)
            } else {
                None
            }
        }
        101 | 228 | 229 => Some(0),
        0 | 108 => (frame.len() >= 4).then_some(4),
        113 => (frame.len() >= 16).then_some(16),
        276 => (frame.len() >= 20).then_some(20),
        _ => None,
    }
}

fn fragment_marked(link: u32, frame: &[u8]) -> bool {
    let Some(at) = network_offset(link, frame) else {
        return false;
    };
    let ip = &frame[at..];
    match ip.first().map(|v| v >> 4) {
        Some(4) => ip.len() >= 8 && be16(&ip[6..]) & 0x3fff != 0,
        Some(6) if ip.len() >= 40 => {
            let mut next = ip[6];
            let mut offset = 40;
            for _ in 0..16 {
                if next == 44 {
                    return true;
                }
                if !matches!(next, 0 | 43 | 60 | 51) || offset + 2 > ip.len() {
                    return false;
                }
                let size = if next == 51 {
                    (usize::from(ip[offset + 1]) + 2) * 4
                } else {
                    (usize::from(ip[offset + 1]) + 1) * 8
                };
                next = ip[offset];
                offset += size;
                if offset > ip.len() {
                    return false;
                }
            }
            false
        }
        _ => false,
    }
}

fn fragment(link: u32, scope: u64, frame: &[u8]) -> Option<Fragment<'_>> {
    let at = network_offset(link, frame)?;
    let ip = frame.get(at..)?;
    match ip.first()? >> 4 {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let header = usize::from(ip[0] & 15) * 4;
            let length = usize::from(be16(&ip[2..]));
            if header < 20 || length < header || length > ip.len() {
                return None;
            }
            let flags = be16(&ip[6..]);
            if flags & 0x3fff == 0 {
                return None;
            }
            Some(Fragment {
                key: FragmentKey {
                    scope,
                    src: IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])),
                    dst: IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])),
                    id: u32::from(be16(&ip[4..])),
                    protocol: ip[9],
                },
                offset: usize::from(flags & 0x1fff) * 8,
                more: flags & 0x2000 != 0,
                payload: &ip[header..length],
                prefix: frame[..at + header].to_vec(),
                network: at,
                ipv6: false,
            })
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            let length = 40 + usize::from(be16(&ip[4..]));
            if length > ip.len() {
                return None;
            }
            let mut next = ip[6];
            let mut offset = 40;
            let mut previous = 6;
            for _ in 0..16 {
                if next == 44 {
                    if offset + 8 > length {
                        return None;
                    }
                    let field = be16(&ip[offset + 2..]);
                    let mut prefix = frame[..at + offset].to_vec();
                    prefix[at + previous] = ip[offset];
                    return Some(Fragment {
                        key: FragmentKey {
                            scope,
                            src: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?)),
                            dst: IpAddr::V6(Ipv6Addr::from(
                                <[u8; 16]>::try_from(&ip[24..40]).ok()?,
                            )),
                            id: be32(&ip[offset + 4..]),
                            protocol: ip[offset],
                        },
                        offset: usize::from(field & 0xfff8),
                        more: field & 1 != 0,
                        payload: &ip[offset + 8..length],
                        prefix,
                        network: at,
                        ipv6: true,
                    });
                }
                if !matches!(next, 0 | 43 | 60 | 51) || offset + 2 > length {
                    return None;
                }
                let size = if next == 51 {
                    (usize::from(ip[offset + 1]) + 2) * 4
                } else {
                    (usize::from(ip[offset + 1]) + 1) * 8
                };
                previous = offset;
                next = ip[offset];
                offset += size;
                if offset > length {
                    return None;
                }
            }
            None
        }
        _ => None,
    }
}

fn transport(link: u32, frame: &[u8]) -> Option<(IpAddr, IpAddr, u8, &[u8])> {
    let ip = frame.get(network_offset(link, frame)?..)?;
    match ip.first()? >> 4 {
        4 => {
            if ip.len() < 20 {
                return None;
            }
            let header = usize::from(ip[0] & 15) * 4;
            let length = usize::from(be16(&ip[2..])).min(ip.len());
            if header < 20 || header > length || be16(&ip[6..]) & 0x3fff != 0 {
                return None;
            }
            Some((
                Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]).into(),
                Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]).into(),
                ip[9],
                &ip[header..length],
            ))
        }
        6 => {
            if ip.len() < 40 {
                return None;
            }
            let length = (40 + usize::from(be16(&ip[4..]))).min(ip.len());
            let mut next = ip[6];
            let mut offset = 40;
            for _ in 0..16 {
                if !matches!(next, 0 | 43 | 60 | 51) {
                    break;
                }
                if offset + 2 > length {
                    return None;
                }
                let size = if next == 51 {
                    (usize::from(ip[offset + 1]) + 2) * 4
                } else {
                    (usize::from(ip[offset + 1]) + 1) * 8
                };
                next = ip[offset];
                offset += size;
                if offset > length {
                    return None;
                }
            }
            if next == 44 || offset > length {
                return None;
            }
            Some((
                Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?).into(),
                Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?).into(),
                next,
                &ip[offset..length],
            ))
        }
        _ => None,
    }
}

fn dns_query(data: &[u8]) -> Option<(String, u16)> {
    if data.len() < 12 || data[2] & 0x80 != 0 || be16(&data[4..]) == 0 {
        return None;
    }
    let mut offset = 12;
    let mut end = None;
    let mut labels = Vec::new();
    let mut seen = BTreeSet::new();
    for _ in 0..128 {
        if !seen.insert(offset) {
            return None;
        }
        let length = *data.get(offset)?;
        offset += 1;
        if length & 0xc0 == 0xc0 {
            let low = *data.get(offset)?;
            if end.is_none() {
                end = Some(offset + 1);
            }
            offset = (usize::from(length & 0x3f) << 8) | usize::from(low);
            continue;
        }
        if length == 0 {
            let q = end.unwrap_or(offset);
            if q + 4 > data.len() {
                return None;
            }
            let name = labels.join(".");
            if name.len() > 253 {
                return None;
            }
            return Some((name, be16(&data[q..])));
        }
        if length > 63 {
            return None;
        }
        let label = data.get(offset..offset + usize::from(length))?;
        if !label.iter().all(|b| b.is_ascii_graphic() && *b != b'.') {
            return None;
        }
        labels.push(String::from_utf8(label.to_vec()).ok()?.to_ascii_lowercase());
        offset += usize::from(length);
    }
    None
}

/// Independent HTTP/1.x fingerprint from public JA4H field descriptions. Header
/// names are lowercased and kept in wire order. Cookie and Referer are excluded
/// from the header count/hash; cookie names/pairs are sorted independently.
pub fn http_fingerprint(data: &[u8]) -> Option<(String, Option<String>, String, usize)> {
    let end = data[..data.len().min(MAX_STREAM + 4)]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")?;
    if end > MAX_STREAM {
        return None;
    }
    let text = std::str::from_utf8(&data[..end]).ok()?;
    let mut lines = text.split("\r\n");
    let request = lines.next()?;
    let mut words = request.split(' ');
    let method = words.next()?;
    let target = words.next()?;
    if target.is_empty() || target.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return None;
    }
    let version = match words.next()? {
        "HTTP/1.0" => "10",
        "HTTP/1.1" => "11",
        _ => return None,
    };
    if words.next().is_some()
        || method.len() < 2
        || method.len() > 16
        || !method.bytes().all(|c| c.is_ascii_uppercase())
    {
        return None;
    }
    let mut names = Vec::new();
    let mut cookies = Vec::<(String, String)>::new();
    let mut cookie = false;
    let mut referer = false;
    let mut language = String::new();
    let mut host = None;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if value.bytes().any(|b| b == 0x7f || (b < 0x20 && b != b'\t')) {
            return None;
        }
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return None;
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "cookie" => {
                cookie = true;
                for part in value.split(';') {
                    let (name, value) = part.trim().split_once('=').unwrap_or((part.trim(), ""));
                    if !name.is_empty() {
                        cookies.push((name.into(), value.into()));
                    }
                }
            }
            "referer" => referer = true,
            _ => names.push(name.clone()),
        }
        if name == "host" && value.len() <= 253 {
            host = Some(value.to_ascii_lowercase());
        }
        if name == "accept-language" && language.is_empty() {
            language = value
                .split(',')
                .next()
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .bytes()
                .filter(u8::is_ascii_alphabetic)
                .take(4)
                .map(|b| char::from(b.to_ascii_lowercase()))
                .collect();
        }
    }
    while language.len() < 4 {
        language.push('0');
    }
    let count = names.len();
    cookies.sort();
    let cookie_names = cookies
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let cookie_pairs = cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    let hash = format!(
        "{}{}{}{}{:02}{}_{}_{}_{}",
        method[..2].to_ascii_lowercase(),
        version,
        if cookie { 'c' } else { 'n' },
        if referer { 'r' } else { 'n' },
        count.min(99),
        language,
        hash12(names.join(",").as_bytes()),
        hash_or_zero(cookie_names.as_bytes()),
        hash_or_zero(cookie_pairs.as_bytes())
    );
    Some((method.into(), host, hash, count))
}

fn tls_handshake(data: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;
    let mut body = Vec::new();
    while offset + 5 <= data.len() {
        if data[offset] != 22 || data[offset + 1] != 3 || data[offset + 2] > 3 {
            return None;
        }
        let length = usize::from(be16(&data[offset + 3..]));
        if length > 18_432 || offset + 5 + length > data.len() {
            return None;
        }
        body.extend_from_slice(&data[offset + 5..offset + 5 + length]);
        if body.len() >= 4 {
            let expected = 4
                + (usize::from(body[1]) << 16)
                + (usize::from(body[2]) << 8)
                + usize::from(body[3]);
            if expected > MAX_STREAM {
                return None;
            }
            if body.len() >= expected {
                body.truncate(expected);
                return Some(body);
            }
        }
        offset += 5 + length;
    }
    None
}

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
    fn bytes(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(length)?;
        let result = self.data.get(self.offset..end)?;
        self.offset = end;
        Some(result)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(be16(self.bytes(2)?))
    }
    fn vector8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.bytes(n)
    }
    fn vector16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.bytes(n)
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }
}

pub fn ja4_from_handshake(handshake: &[u8]) -> Option<(String, Option<String>)> {
    if !valid_handshake(handshake, 1) {
        return None;
    }
    let mut cursor = Cursor::new(&handshake[4..]);
    let legacy = cursor.u16()?;
    cursor.bytes(32)?;
    if cursor.vector8()?.len() > 32 {
        return None;
    }
    let cipher_bytes = cursor.vector16()?;
    if cipher_bytes.is_empty() || !cipher_bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut ciphers: Vec<u16> = cipher_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| be16(bytes))
        .filter(|n| !grease(*n))
        .collect();
    if cursor.vector8()?.is_empty() {
        return None;
    }
    let mut version = legacy;
    let mut extensions = Vec::new();
    let mut signatures = Vec::new();
    let mut alpn = Vec::new();
    let mut sni = None;
    let mut seen_extensions = BTreeSet::new();
    if cursor.remaining() > 0 {
        let mut exts = Cursor::new(cursor.vector16()?);
        while exts.remaining() > 0 {
            let kind = exts.u16()?;
            let payload = exts.vector16()?;
            if !seen_extensions.insert(kind) {
                return None;
            }
            if grease(kind) {
                continue;
            }
            extensions.push(kind);
            let mut value = Cursor::new(payload);
            match kind {
                0 => {
                    let mut names = Cursor::new(value.vector16()?);
                    let mut seen_names = BTreeSet::new();
                    if names.remaining() == 0 {
                        return None;
                    }
                    while names.remaining() > 0 {
                        let kind = names.u8()?;
                        let bytes = names.vector16()?;
                        if !seen_names.insert(kind) || bytes.is_empty() {
                            return None;
                        }
                        if kind == 0 {
                            if bytes.len() > 253 || !bytes.iter().all(u8::is_ascii_graphic) {
                                return None;
                            }
                            sni = Some(std::str::from_utf8(bytes).ok()?.to_ascii_lowercase());
                        }
                    }
                }
                13 => {
                    let bytes = value.vector16()?;
                    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
                        return None;
                    }
                    signatures = bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|bytes| be16(bytes))
                        .filter(|n| !grease(*n))
                        .collect();
                }
                16 => {
                    let mut protocols = Cursor::new(value.vector16()?);
                    if protocols.remaining() == 0 {
                        return None;
                    }
                    let mut first = true;
                    while protocols.remaining() > 0 {
                        let p = protocols.vector8()?;
                        if p.is_empty() {
                            return None;
                        }
                        if first {
                            alpn = p.to_vec();
                            first = false;
                        }
                    }
                }
                43 => {
                    let bytes = value.vector8()?;
                    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
                        return None;
                    }
                    if let Some(max) = bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|bytes| be16(bytes))
                        .filter(|n| !grease(*n))
                        .max()
                    {
                        version = max;
                    }
                }
                _ => {}
            }
            if matches!(kind, 0 | 13 | 16 | 43) && value.remaining() != 0 {
                return None;
            }
        }
    }
    if cursor.remaining() != 0 {
        return None;
    }
    let count = extensions.len();
    let has_sni = extensions.contains(&0);
    ciphers.sort_unstable();
    extensions.retain(|n| *n != 0 && *n != 16);
    extensions.sort_unstable();
    let mut extension_input = hex_list(&extensions);
    if !extensions.is_empty() && !signatures.is_empty() {
        extension_input.push('_');
        extension_input.push_str(&hex_list(&signatures));
    }
    let fingerprint = format!(
        "t{}{}{:02}{:02}{}_{}_{}",
        version_code(version),
        if has_sni { 'd' } else { 'i' },
        ciphers.len().min(99),
        count.min(99),
        alpn_code(&alpn),
        hash_or_zero(hex_list(&ciphers).as_bytes()),
        hash_or_zero(extension_input.as_bytes())
    );
    Some((fingerprint, sni))
}

/// ServerHello fingerprint independently decoded from TLS wire fields. GREASE
/// extensions remain in wire order, unlike the client algorithm.
pub fn ja4s_from_handshake(handshake: &[u8]) -> Option<String> {
    if !valid_handshake(handshake, 2) {
        return None;
    }
    let mut cursor = Cursor::new(&handshake[4..]);
    let mut version = cursor.u16()?;
    let random = cursor.bytes(32)?;
    const RETRY: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];
    if random == RETRY {
        return None;
    }
    if cursor.vector8()?.len() > 32 {
        return None;
    }
    let cipher = cursor.u16()?;
    let compression = cursor.u8()?;
    let mut extensions = Vec::new();
    let mut alpn = Vec::new();
    let mut seen_extensions = BTreeSet::new();
    if cursor.remaining() > 0 {
        let mut exts = Cursor::new(cursor.vector16()?);
        while exts.remaining() > 0 {
            let kind = exts.u16()?;
            let payload = exts.vector16()?;
            if !seen_extensions.insert(kind) {
                return None;
            }
            extensions.push(kind);
            if kind == 43 {
                if payload.len() != 2 || grease(be16(payload)) {
                    return None;
                }
                version = be16(payload);
            }
            if kind == 16 {
                let mut protocol = Cursor::new(payload);
                let mut names = Cursor::new(protocol.vector16()?);
                alpn = names.vector8()?.to_vec();
                if alpn.is_empty() || names.remaining() != 0 || protocol.remaining() != 0 {
                    return None;
                }
            }
        }
    }
    if cursor.remaining() != 0 {
        return None;
    }
    if version == 0x0304 && compression != 0 {
        return None;
    }
    Some(format!(
        "t{}{:02}{}_{cipher:04x}_{}",
        version_code(version),
        extensions.len().min(99),
        alpn_code(&alpn),
        hash_or_zero(hex_list(&extensions).as_bytes())
    ))
}

fn valid_handshake(data: &[u8], kind: u8) -> bool {
    data.len() >= 4
        && data[0] == kind
        && data.len() - 4
            == (usize::from(data[1]) << 16) + (usize::from(data[2]) << 8) + usize::from(data[3])
}

fn grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff
}
fn version_code(value: u16) -> &'static str {
    match value {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}
fn alpn_code(value: &[u8]) -> String {
    if value.is_empty() {
        "00".into()
    } else if value[0].is_ascii_alphanumeric() && value[value.len() - 1].is_ascii_alphanumeric() {
        format!(
            "{}{}",
            char::from(value[0]),
            char::from(value[value.len() - 1])
        )
    } else {
        format!("{:x}{:x}", value[0] >> 4, value[value.len() - 1] & 15)
    }
}
fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|n| format!("{n:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}
fn hash12(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let mut out = String::with_capacity(12);
    for byte in &hash[..6] {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
fn hash_or_zero(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "000000000000".into()
    } else {
        hash12(bytes)
    }
}
fn be16(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}
fn be32(data: &[u8]) -> u32 {
    u32::from_be_bytes(data[..4].try_into().unwrap())
}
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod parser_edges {
    use super::*;

    fn ip(protocol: u8, reverse: bool, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        packet[9] = protocol;
        packet[12..20].copy_from_slice(if reverse {
            &[10, 0, 0, 2, 10, 0, 0, 1]
        } else {
            &[10, 0, 0, 1, 10, 0, 0, 2]
        });
        packet.extend(payload);
        packet
    }
    fn tcp(sequence: u32, flags: u8, reverse: bool, data: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[..4].copy_from_slice(if reverse {
            &[0, 80, 0xc3, 0x50]
        } else {
            &[0xc3, 0x50, 0, 80]
        });
        packet[4..8].copy_from_slice(&sequence.to_be_bytes());
        packet[12] = 0x50;
        packet[13] = flags;
        packet.extend(data);
        ip(6, reverse, &packet)
    }
    fn hello(kind: u8, session: usize, extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([1; 32]);
        body.push(session as u8);
        body.extend(vec![0; session]);
        if kind == 1 {
            body.extend([0, 2, 0x13, 1, 1, 0]);
        } else {
            body.extend([0x13, 1, 0]);
        }
        let mut exts = Vec::new();
        for (kind, value) in extensions {
            exts.extend(kind.to_be_bytes());
            exts.extend((value.len() as u16).to_be_bytes());
            exts.extend(*value);
        }
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(exts);
        let mut packet = vec![kind, 0, (body.len() >> 8) as u8, body.len() as u8];
        packet.extend(body);
        packet
    }
    fn record(hello: &[u8], version: [u8; 2]) -> Vec<u8> {
        let mut packet = vec![22, version[0], version[1]];
        packet.extend((hello.len() as u16).to_be_bytes());
        packet.extend(hello);
        packet
    }

    #[test]
    fn udp_length_cannot_turn_trailing_ip_bytes_into_dns() {
        let mut udp = vec![0xc3, 0x50, 0, 53, 0, 8, 0, 0];
        udp.extend([
            0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]);
        let mut inspector = Inspector::default();
        inspector.inspect(101, 0, &ip(17, false, &udp), 0);
        assert!(inspector.report.dns.is_empty());
        let length = udp.len() as u16;
        udp[4..6].copy_from_slice(&length.to_be_bytes());
        inspector.inspect(101, 0, &ip(17, false, &udp), 1);
        assert_eq!(inspector.report.dns.len(), 1);
        udp[4..6].copy_from_slice(&(length + 1).to_be_bytes());
        inspector.inspect(101, 0, &ip(17, false, &udp), 2);
        assert_eq!(inspector.report.dns.len(), 1);
    }

    #[test]
    fn tcp_conflicts_block_both_directions_until_syn_or_expiry() {
        let request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut inspector = Inspector::default();
        inspector.inspect(101, 0, &tcp(1, 0x18, false, b"GET /"), 0);
        inspector.inspect(101, 0, &tcp(1, 0x18, false, b"GOT /"), 1);
        inspector.inspect(101, 0, &tcp(1, 0x18, false, request), 2);
        inspector.inspect(101, 0, &tcp(1, 0x18, true, request), 3);
        assert!(inspector.report.http.is_empty());
        assert_eq!(inspector.blocked_streams.len(), 1);
        inspector.inspect(101, 0, &tcp(0, 2, true, &[]), 4);
        inspector.inspect(101, 0, &tcp(1, 0x18, false, request), 5);
        assert_eq!(inspector.report.http.len(), 1);
        inspector.block_stream(
            &StreamKey {
                scope: 0,
                source: Endpoint {
                    address: "10.0.0.1".parse().unwrap(),
                    port: 50_000,
                },
                destination: Endpoint {
                    address: "10.0.0.2".parse().unwrap(),
                    port: 80,
                },
            },
            10,
        );
        inspector.max_time = MAX_AGE_MS + 11;
        inspector.expire();
        assert!(inspector.blocked_streams.is_empty());
    }

    #[test]
    fn ambiguity_tombstones_are_bounded_and_discard_pair_state() {
        let mut inspector = Inspector::default();
        for port in 1..=MAX_TCP_STREAMS + 10 {
            let key = StreamKey {
                scope: 0,
                source: Endpoint {
                    address: "10.0.0.1".parse().unwrap(),
                    port: port as u16,
                },
                destination: Endpoint {
                    address: "10.0.0.2".parse().unwrap(),
                    port: 443,
                },
            };
            inspector.pairs.entry(key.clone()).or_default();
            inspector.block_stream(&key, port as u64);
        }
        assert!(inspector.pairs.is_empty());
        assert_eq!(inspector.blocked_streams.len(), MAX_TCP_STREAMS);
    }

    #[test]
    fn strict_tls_vectors_sessions_duplicates_and_record_versions() {
        let valid = hello(1, 0, &[(43, &[2, 3, 4]), (16, &[0, 3, 2, b'h', b'2'])]);
        assert!(ja4_from_handshake(&valid).is_some());
        for malformed in [
            hello(1, 33, &[]),
            hello(1, 0, &[(43, &[2, 3, 4, 0])]),
            hello(1, 0, &[(13, &[0, 2, 8, 4, 0])]),
            hello(1, 0, &[(16, &[0, 3, 2, b'h', b'2', 0])]),
            hello(1, 0, &[(43, &[2, 3, 4]), (43, &[2, 3, 4])]),
        ] {
            assert!(ja4_from_handshake(&malformed).is_none());
        }
        assert!(
            ja4s_from_handshake(&hello(2, 0, &[(16, &[0, 6, 2, b'h', b'2', 2, b'h', b'3'])]))
                .is_none()
        );
        assert!(ja4s_from_handshake(&hello(2, 33, &[])).is_none());
        assert!(ja4s_from_handshake(&hello(2, 0, &[(43, &[3, 4, 0])])).is_none());
        assert!(tls_handshake(&record(&valid, [3, 3])).is_some());
        assert!(tls_handshake(&record(&valid, [2, 3])).is_none());
        assert!(tls_handshake(&record(&valid, [3, 4])).is_none());
    }

    #[test]
    fn malformed_http_and_fragment_rejections_are_counted() {
        for request in [
            b"GET  HTTP/1.1\r\n\r\n".as_slice(),
            b"GET /\0 HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: bad\0.test\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: bad\x7f.test\r\n\r\n",
        ] {
            assert!(http_fingerprint(request).is_none());
        }
        assert!(http_fingerprint(b"GET / HTTP/1.1\r\nHost:\t example.test\r\n\r\n").is_some());
        let mut inspector = Inspector::default();
        let key = FragmentKey {
            scope: 0,
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            id: 1,
            protocol: 17,
        };
        inspector.reject(&key, 0);
        inspector.reject(&key, 1);
        assert_eq!(inspector.report.discarded_fragment_sets, 1);
    }

    #[test]
    fn later_pcapng_sections_revalidate_version_and_capture_link_type() {
        fn block(kind: u32, mut body: Vec<u8>, output: &mut Vec<u8>) {
            while !body.len().is_multiple_of(4) {
                body.push(0);
            }
            let size = (body.len() + 12) as u32;
            output.extend(kind.to_le_bytes());
            output.extend(size.to_le_bytes());
            output.extend(body);
            output.extend(size.to_le_bytes());
        }
        fn section(version: u16, link: u16, output: &mut Vec<u8>) {
            let mut body = 0x1a2b3c4du32.to_le_bytes().to_vec();
            body.extend(version.to_le_bytes());
            body.extend(0u16.to_le_bytes());
            body.extend((-1i64).to_le_bytes());
            block(0x0a0d0d0a, body, output);
            let mut interface = link.to_le_bytes().to_vec();
            interface.extend([0, 0]);
            interface.extend(65_535u32.to_le_bytes());
            block(1, interface, output);
        }
        struct Temporary(PathBuf);
        impl Drop for Temporary {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }
        let file = Temporary(std::env::temp_dir().join(format!(
                "tracehound-ng-edge-{}-{}.pcapng",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )));
        for (version, link, message) in [(2, 1, "version"), (1, 101, "mixed-link-type")] {
            let mut bytes = Vec::new();
            section(1, 1, &mut bytes);
            section(version, link, &mut bytes);
            fs::write(&file.0, bytes).unwrap();
            assert!(inspect_capture(&file.0).unwrap_err().contains(message));
        }
    }
}
