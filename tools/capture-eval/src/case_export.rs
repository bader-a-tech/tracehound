//! Standalone investigation reports and explicitly selected packet exports.
use crate::capture::PacketRef;
use crate::investigation::{CaseIndex, CaseOverview, TimelineEvent};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const MAX_EXPORT_PACKETS: usize = 10_000;
const MAX_EXPORT_EVENTS: usize = 10_000;

#[derive(Clone, Debug, Serialize)]
pub struct PacketPreview {
    pub reference: PacketRef,
    pub sha256: String,
    pub hex: String,
    pub preview_truncated: bool,
    pub source_verified: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct InvestigationExport {
    pub directory: PathBuf,
    pub html: PathBuf,
    pub json: PathBuf,
    pub packet_capture: Option<PathBuf>,
    pub events: usize,
    pub events_truncated: bool,
    pub packets: usize,
    pub packets_truncated: bool,
    pub supporting_evidence_truncated: bool,
}

pub fn inspect_packet(
    case: &CaseIndex,
    number: u64,
    source: Option<&Path>,
    cancelled: &dyn Fn() -> bool,
) -> Result<PacketPreview, String> {
    let reference = case.packet(number)?;
    let mut verified = case.verify_source(source, cancelled)?;
    verified.validate_references(std::slice::from_ref(&reference), cancelled)?;
    let bytes = verified.read_packet(&reference)?;
    let hex = hex_dump(&bytes[..bytes.len().min(4096)]);
    Ok(PacketPreview {
        reference,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        hex,
        preview_truncated: bytes.len() > 4096,
        source_verified: true,
    })
}
fn hex_dump(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::new();
    for (offset, chunk) in bytes.chunks(16).enumerate() {
        let _ = write!(text, "{:08x}  ", offset * 16);
        for n in 0..16 {
            if let Some(byte) = chunk.get(n) {
                let _ = write!(text, "{byte:02x} ");
            } else {
                text.push_str("   ");
            }
        }
        text.push(' ');
        for byte in chunk {
            text.push(if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            });
        }
        text.push('\n');
    }
    text
}

pub fn wireshark_filter(host: IpAddr, numbers: &[u64]) -> String {
    let address = format!(
        "{}.addr == {host}",
        if host.is_ipv4() { "ip" } else { "ipv6" }
    );
    let numbers: BTreeSet<_> = numbers
        .iter()
        .copied()
        .filter(|n| *n > 0)
        .take(1000)
        .collect();
    if numbers.is_empty() {
        address
    } else {
        format!(
            "({address}) && ({})",
            numbers
                .iter()
                .map(|n| format!("frame.number == {n}"))
                .collect::<Vec<_>>()
                .join(" || ")
        )
    }
}
/// Called only by an explicit user action. Arguments never pass through a shell.
pub fn open_wireshark(executable: &Path, capture: &Path, filter: &str) -> Result<(), String> {
    if !executable.is_file() || !capture.is_file() {
        return Err(
            "select an installed Wireshark executable and an existing original capture".into(),
        );
    }
    if filter.len() > 65536 || filter.chars().any(char::is_control) {
        return Err("invalid Wireshark filter".into());
    }
    let mut child = Command::new(executable)
        .arg("-r")
        .arg(capture)
        .arg("-Y")
        .arg(filter)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("open Wireshark: {e}"))?;
    // Keep the interactive application independent, but reap its process when
    // it exits so repeated launches do not leave Unix zombies.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
pub fn discover_wireshark() -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = if cfg!(windows) {
        [
            std::env::var_os("ProgramFiles"),
            std::env::var_os("ProgramFiles(x86)"),
        ]
        .into_iter()
        .flatten()
        .map(|p| PathBuf::from(p).join("Wireshark/Wireshark.exe"))
        .collect()
    } else if cfg!(target_os = "macos") {
        vec!["/Applications/Wireshark.app/Contents/MacOS/Wireshark".into()]
    } else {
        vec![
            "/usr/bin/wireshark".into(),
            "/usr/local/bin/wireshark".into(),
        ]
    };
    candidates.into_iter().find(|p| p.is_file())
}

struct NewOutput {
    path: PathBuf,
    writer: Option<BufWriter<File>>,
    complete: bool,
}
impl NewOutput {
    fn create(path: &Path) -> Result<Self, String> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|e| format!("create {}: {e}", path.display()))?;
        Ok(Self {
            path: path.into(),
            writer: Some(BufWriter::new(file)),
            complete: false,
        })
    }
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.writer
            .as_mut()
            .expect("open export")
            .write_all(bytes)
            .map_err(|e| format!("write packet export: {e}"))
    }
    fn finish(mut self) -> Result<(), String> {
        let writer = self.writer.as_mut().expect("open export");
        writer
            .flush()
            .and_then(|()| writer.get_ref().sync_all())
            .map_err(|e| format!("finish packet export: {e}"))?;
        self.complete = true;
        Ok(())
    }
    fn block(&mut self, kind: u32, body: &[u8]) -> Result<(), String> {
        let size = u32::try_from(body.len() + 12).map_err(|_| "packet block too large")?;
        self.write(&kind.to_le_bytes())?;
        self.write(&size.to_le_bytes())?;
        self.write(body)?;
        self.write(&size.to_le_bytes())
    }
}
impl Drop for NewOutput {
    fn drop(&mut self) {
        self.writer.take();
        if !self.complete {
            let _ = fs::remove_file(&self.path);
        }
    }
}
fn option(body: &mut Vec<u8>, kind: u16, value: &[u8]) -> Result<(), String> {
    let len = u16::try_from(value.len()).map_err(|_| "PCAPNG option exceeds 65535 bytes")?;
    body.extend(kind.to_le_bytes());
    body.extend(len.to_le_bytes());
    body.extend(value);
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    Ok(())
}

/// Export original selected frames as PCAPNG, retaining link types, nanosecond
/// timestamps, wire lengths, and comments naming the original frame/hash.
pub fn export_packets(
    case: &CaseIndex,
    numbers: &[u64],
    destination: &Path,
    source: Option<&Path>,
    cancelled: &dyn Fn() -> bool,
) -> Result<usize, String> {
    let unique: BTreeSet<_> = numbers.iter().copied().collect();
    if unique.is_empty() || unique.len() > MAX_EXPORT_PACKETS {
        return Err("select 1–10000 original packet numbers".into());
    }
    let references = unique
        .into_iter()
        .map(|n| case.packet(n))
        .collect::<Result<Vec<_>, _>>()?;
    let mut verified = case.verify_source(source, cancelled)?;
    verified.validate_references(&references, cancelled)?;
    if cancelled() {
        return Err("packet export cancelled".into());
    }
    let mut output = NewOutput::create(destination)?;
    let mut header = Vec::new();
    header.extend(0x1a2b3c4du32.to_le_bytes());
    header.extend(1u16.to_le_bytes());
    header.extend(0u16.to_le_bytes());
    header.extend(u64::MAX.to_le_bytes());
    output.block(0x0a0d0d0a, &header)?;
    let mut interfaces = BTreeMap::new();
    for reference in &references {
        if cancelled() {
            return Err("packet export cancelled".into());
        }
        let key = (reference.section, reference.interface, reference.link_type);
        let interface = if let Some(id) = interfaces.get(&key) {
            *id
        } else {
            if interfaces.len() >= 4096 {
                return Err("packet export has more than 4096 interfaces".into());
            }
            let id = interfaces.len() as u32;
            let link = u16::try_from(reference.link_type)
                .map_err(|_| "link type exceeds PCAPNG interface range")?;
            let mut body = Vec::new();
            body.extend(link.to_le_bytes());
            body.extend(0u16.to_le_bytes());
            body.extend(1_048_576u32.to_le_bytes());
            option(&mut body, 9, &[9])?;
            option(
                &mut body,
                2,
                format!(
                    "original-section-{}-interface-{}",
                    reference.section, reference.interface
                )
                .as_bytes(),
            )?;
            option(&mut body, 0, &[])?;
            output.block(1, &body)?;
            interfaces.insert(key, id);
            id
        };
        let data = verified.read_packet(reference)?;
        let mut body = Vec::with_capacity(data.len() + 256);
        body.extend(interface.to_le_bytes());
        body.extend(((reference.timestamp_ns >> 32) as u32).to_le_bytes());
        body.extend((reference.timestamp_ns as u32).to_le_bytes());
        body.extend(reference.captured_len.to_le_bytes());
        body.extend(reference.original_len.to_le_bytes());
        body.extend(data);
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        option(
            &mut body,
            1,
            format!(
                "Original frame {}; capture SHA-256 {}",
                reference.number,
                case.overview().capture.sha256
            )
            .as_bytes(),
        )?;
        option(&mut body, 0, &[])?;
        output.block(6, &body)?;
    }
    if cancelled() {
        return Err("packet export cancelled".into());
    }
    output.finish()?;
    Ok(references.len())
}

#[derive(Serialize)]
struct HostDocument<'a> {
    schema_version: u32,
    mode: &'static str,
    overview: &'a CaseOverview,
    host: IpAddr,
    events: &'a [TimelineEvent],
    events_truncated: bool,
    packets_included: bool,
    packet_numbers: &'a [u64],
    packets_truncated: bool,
    supporting_evidence_truncated: bool,
    notes: Vec<&'static str>,
}

pub fn export_host(
    case_path: &Path,
    host: IpAddr,
    destination: &Path,
    include_packets: bool,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<InvestigationExport, String> {
    export_host_with_source(
        case_path,
        host,
        destination,
        include_packets,
        None,
        cancelled,
    )
}

pub fn export_host_with_source(
    case_path: &Path,
    host: IpAddr,
    destination: &Path,
    include_packets: bool,
    source: Option<&Path>,
    cancelled: &(dyn Fn() -> bool + Sync),
) -> Result<InvestigationExport, String> {
    if cancelled() {
        return Err("investigation export cancelled".into());
    }
    let case = CaseIndex::open(case_path)?;
    let interrupt = case.connection.get_interrupt_handle();
    let done = AtomicBool::new(false);
    struct Finish<'a>(&'a AtomicBool);
    impl Drop for Finish<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    std::thread::scope(|scope| {
        let finished = &done;
        scope.spawn(move || {
            while !finished.load(Ordering::Acquire) {
                if cancelled() {
                    interrupt.interrupt();
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let _finished = Finish(&done);
        export_host_opened(&case, host, destination, include_packets, source, cancelled)
    })
}
fn export_host_opened(
    case: &CaseIndex,
    host: IpAddr,
    destination: &Path,
    include_packets: bool,
    source: Option<&Path>,
    cancelled: &dyn Fn() -> bool,
) -> Result<InvestigationExport, String> {
    let mut events = Vec::new();
    let mut cursor = 0;
    let mut truncated = false;
    loop {
        if cancelled() {
            return Err("investigation export cancelled".into());
        }
        let page = case.timeline(host, cursor, 1000)?;
        events.extend(page.events);
        if events.len() >= MAX_EXPORT_EVENTS {
            truncated = page.next_id.is_some();
            events.truncate(MAX_EXPORT_EVENTS);
            break;
        }
        if let Some(next) = page.next_id {
            cursor = next;
        } else {
            break;
        }
    }
    let mut numbers: BTreeSet<_> = events
        .iter()
        .flat_map(|event| event.packets.iter().map(|packet| packet.number))
        .collect();
    let mut packets_truncated = numbers.len() > MAX_EXPORT_PACKETS;
    let supporting_evidence_truncated = events.iter().any(|event| event.packet_refs_truncated);
    while numbers.len() > MAX_EXPORT_PACKETS {
        numbers.pop_last();
    }
    if include_packets && numbers.is_empty() {
        let packets = case.host_packets(host, 0, 1000)?;
        numbers.extend(packets.into_iter().map(|packet| packet.number));
        packets_truncated = true;
    }
    let numbers: Vec<_> = numbers.into_iter().collect();
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    builder
        .create(destination)
        .map_err(|e| format!("create new investigation export folder: {e}"))?;
    let result = (|| {
        let capture = if include_packets && !numbers.is_empty() {
            let path = destination.join("evidence.pcapng");
            export_packets(case, &numbers, &path, source, cancelled)?;
            Some(path)
        } else {
            None
        };
        let document=HostDocument{schema_version:1,mode:"host_investigation",overview:case.overview(),host,events:&events,events_truncated:truncated,packets_included:capture.is_some(),packet_numbers:&numbers,packets_truncated,supporting_evidence_truncated,notes:vec!["An IP address in a capture is not proof of a persistent device identity; NAT, DHCP and capture interfaces can affect attribution.","Packet facts have original frame references. Contextual/time-window associations do not establish causation.","Included packets are retained event references, not a complete capture of every packet involving this host.","The JSON and HTML can contain addresses, domains and other capture metadata even when packet bytes are excluded."]};
        let json_path = destination.join("investigation.json");
        crate::store::write_new(&json_path, &document)?;
        let html_path = destination.join("investigation.html");
        let html = host_html(&document)?;
        let mut html_output = NewOutput::create(&html_path)?;
        html_output.write(html.as_bytes())?;
        html_output.finish()?;
        if cancelled() {
            return Err("investigation export cancelled".into());
        }
        let mut sums = Vec::new();
        for path in [&json_path, &html_path].into_iter().chain(capture.iter()) {
            let mut file = File::open(path).map_err(|e| e.to_string())?;
            let mut hash = Sha256::new();
            let mut buffer = [0; 65536];
            loop {
                if cancelled() {
                    return Err("investigation export cancelled".into());
                }
                let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                hash.update(&buffer[..n]);
            }
            sums.push(format!(
                "{:x}  {}",
                hash.finalize(),
                path.file_name().unwrap_or_default().to_string_lossy()
            ));
        }
        let mut output = NewOutput::create(&destination.join("SHA256SUMS.txt"))?;
        output.write(format!("{}\n", sums.join("\n")).as_bytes())?;
        output.finish()?;
        Ok(InvestigationExport {
            directory: destination.into(),
            html: html_path,
            json: json_path,
            packet_capture: capture,
            events: events.len(),
            events_truncated: truncated,
            packets: numbers.len(),
            packets_truncated,
            supporting_evidence_truncated,
        })
    })();
    if result.is_err() {
        for name in [
            "evidence.pcapng",
            "investigation.json",
            "investigation.html",
            "SHA256SUMS.txt",
        ] {
            let _ = fs::remove_file(destination.join(name));
        }
        let _ = fs::remove_dir(destination);
    }
    result
}
fn escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '"' => "&quot;".chars().collect(),
            '\'' => "&#39;".chars().collect(),
            _ => vec![ch],
        })
        .collect()
}
pub fn format_timestamp_ns(nanos: u64) -> String {
    let seconds = nanos / 1_000_000_000;
    let mut days = seconds / 86_400;
    let mut year = 1970u64;
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    loop {
        let length = if leap(year) { 366 } else { 365 };
        if days < length {
            break;
        }
        days -= length;
        year += 1;
    }
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for length in months {
        if days < length {
            break;
        }
        days -= length;
        month += 1;
    }
    format!(
        "{year:04}-{month:02}-{:02} {:02}:{:02}:{:02}.{:09} UTC",
        days + 1,
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60,
        nanos % 1_000_000_000
    )
}
fn host_html(document: &HostDocument<'_>) -> Result<String, String> {
    use std::fmt::Write;
    let mut html=format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none';style-src 'unsafe-inline';img-src data:;base-uri 'none';form-action 'none'\"><title>Tracehound investigation: {}</title><style>body{{font:16px system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#172638;background:#f7f9fc}}h1{{font-size:32px}}article{{border-left:4px solid #377bb5;background:white;padding:16px 20px;margin:16px 0}}small{{color:#465a70}}pre{{overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;background:#edf2f7;padding:12px}}code{{overflow-wrap:anywhere}}details{{margin-top:12px}}.notice{{background:#fff3d5;padding:14px}}.meta{{display:grid;grid-template-columns:150px 1fr;gap:8px}}@media print{{body{{background:white;margin:0}}article{{break-inside:avoid}}details>div{{display:block}}}}</style><h1>Host investigation: {}</h1><p>Tracehound · local, reproducible network evidence</p><div class=\"meta\"><b>Original capture</b><span>{}</span><b>SHA-256</b><code>{}</code><b>Capture packets</b><span>{}</span><b>Case schema</b><span>{}</span></div>",document.host,document.host,escape(&document.overview.source.display().to_string()),escape(&document.overview.capture.sha256),document.overview.packets,document.schema_version);
    if document.events_truncated || document.packets_truncated {
        html.push_str("<p class=\"notice\">This export is bounded. Inspect the JSON truncation fields and the original case for additional context.</p>");
    }
    if document.supporting_evidence_truncated {
        html.push_str("<p class=\"notice\">Supporting packet references were limited in one or more events. Listed frames are bounded evidence examples, not every packet in the detector window.</p>");
    }
    for note in &document.notes {
        let _ = write!(html, "<p><small>{}</small></p>", escape(note));
    }
    html.push_str("<h2>Chronological activity</h2>");
    for event in document.events {
        let _=write!(html,"<article><small>{} · {} · {}</small><h3>{}</h3><p>{} → {}</p><p>Original frames: {}</p><details><summary>Evidence and measurements</summary><div><pre>{}</pre></div></details></article>",format_timestamp_ns(event.timestamp_ns),escape(&event.kind),escape(&event.evidence_kind),escape(&event.summary),event.host,event.peer.map(|p|p.to_string()).unwrap_or_else(||"unspecified".into()),event.packets.iter().map(|p|p.number.to_string()).collect::<Vec<_>>().join(", "),escape(&serde_json::to_string_pretty(&event.details).map_err(|e|e.to_string())?));
    }
    let _=write!(html,"<h2>Analysis configuration</h2><pre>{}</pre><h2>Capture coverage</h2><pre>{}</pre><p>Supporting files: investigation.json, SHA256SUMS.txt{}.</p></html>",escape(&serde_json::to_string_pretty(&document.overview.analysis).map_err(|e|e.to_string())?),escape(&serde_json::to_string_pretty(&document.overview.diagnostics).map_err(|e|e.to_string())?),if document.packets_included{", evidence.pcapng"}else{""});
    Ok(html)
}
