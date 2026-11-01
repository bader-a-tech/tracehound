//! Indexed investigations over immutable original capture references.
//!
//! Packet bytes stay in their original capture. The case database stores
//! references, decoded facts, detector results, and reproducible analysis context.
use crate::capture::{CaptureEnrichment, CaptureIdentity, DecodeEvents, PacketEvent, PacketRef};
use crate::Finding;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const APPLICATION_ID: i32 = 0x54484341;
const CASE_VERSION: u32 = 1;
const MAX_PAGE: usize = 1000;
const MAX_PACKET: u32 = 1_048_576;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CaseOverview {
    pub schema_version: u32,
    pub source: PathBuf,
    pub capture: CaptureIdentity,
    pub created_at_ms: u64,
    pub packets: u64,
    pub flows: u64,
    pub events: u64,
    pub first_timestamp_ns: Option<u64>,
    pub last_timestamp_ns: Option<u64>,
    pub diagnostics: Value,
    pub analysis: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostSummary {
    pub address: IpAddr,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub wire_bytes_sent: u64,
    pub wire_bytes_received: u64,
    pub connections: u64,
    pub findings: u64,
    pub first_timestamp_ns: u64,
    pub last_timestamp_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimelineEvent {
    pub id: u64,
    pub timestamp_ns: u64,
    pub kind: String,
    pub host: IpAddr,
    pub peer: Option<IpAddr>,
    pub summary: String,
    /// `packet` facts come directly from decoded bytes. `context` joins only
    /// identify related traffic and must not be presented as proof of causation.
    pub evidence_kind: String,
    pub packets: Vec<PacketRef>,
    pub packet_refs_truncated: bool,
    pub details: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimelinePage {
    pub host: IpAddr,
    pub events: Vec<TimelineEvent>,
    pub next_id: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConnectionSummary {
    pub id: u64,
    pub section: u32,
    pub interface: u32,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub first_timestamp_ns: u64,
    pub last_timestamp_ns: u64,
    pub forward_packets: u64,
    pub reverse_packets: u64,
    pub forward_wire_bytes: u64,
    pub reverse_wire_bytes: u64,
    pub syn_packets: u64,
    pub fin_packets: u64,
    pub rst_packets: u64,
}

fn error(context: &str, value: impl std::fmt::Display) -> String {
    format!("{context}: {value}")
}
fn sql<T>(result: rusqlite::Result<T>) -> Result<T, String> {
    result.map_err(|e| error("case database", e))
}
fn integer(value: u64) -> Result<i64, String> {
    value
        .try_into()
        .map_err(|_| "case value exceeds SQLite integer range".into())
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
fn json_text(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_string(value).map_err(|e| error("serialize case data", e))
}
fn observation_time(packets: &[PacketRef], millis: u64) -> u64 {
    packets
        .iter()
        .map(|packet| packet.timestamp_ns)
        .min()
        .unwrap_or_else(|| millis.saturating_mul(1_000_000))
}
fn ip(value: String) -> rusqlite::Result<IpAddr> {
    value.parse().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}
fn unsigned(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    value.try_into().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(e),
        )
    })
}
fn optional_unsigned(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    row.get::<_, Option<i64>>(index)?
        .map(|value| {
            value.try_into().map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    index,
                    rusqlite::types::Type::Integer,
                    Box::new(e),
                )
            })
        })
        .transpose()
}

/// A new private case. Partial builds are removed when the owner is dropped.
/// All rows are committed together; readers reject unfinished cases.
pub struct CaseBuilder {
    connection: Option<Connection>,
    destination: PathBuf,
    source: PathBuf,
    created_at_ms: u64,
    committed: bool,
    count: u64,
}

impl CaseBuilder {
    pub fn create(source: &Path, destination: &Path) -> Result<Self, String> {
        let source = fs::canonicalize(source).map_err(|e| error("resolve original capture", e))?;
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut sidecar = destination.as_os_str().to_owned();
            sidecar.push(suffix);
            if Path::new(&sidecar)
                .try_exists()
                .map_err(|e| error("check case sidecar", e))?
            {
                return Err("case sidecar already exists; choose a new database path".into());
            }
        }
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(destination)
            .map_err(|e| error("create new case", e))?;
        let mut builder = Self {
            connection: None,
            destination: destination.into(),
            source,
            created_at_ms: now_ms(),
            committed: false,
            count: 0,
        };
        let connection = sql(Connection::open_with_flags(
            destination,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?;
        sql(connection.busy_timeout(Duration::from_secs(3)))?;
        sql(connection.execute_batch(&format!("PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version={CASE_VERSION}; PRAGMA trusted_schema=OFF; PRAGMA cache_size=-16384; PRAGMA temp_store=FILE; PRAGMA mmap_size=0; PRAGMA synchronous=NORMAL;
            CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE packets(number INTEGER PRIMARY KEY,section INTEGER NOT NULL,interface INTEGER NOT NULL,link_type INTEGER NOT NULL,timestamp_ns INTEGER NOT NULL,data_offset INTEGER NOT NULL,captured_len INTEGER NOT NULL,original_len INTEGER NOT NULL,src TEXT,dst TEXT,src_port INTEGER,dst_port INTEGER,protocol INTEGER,tcp_flags INTEGER);
            CREATE TABLE flows(id INTEGER PRIMARY KEY,key TEXT NOT NULL,section INTEGER NOT NULL,interface INTEGER NOT NULL,src TEXT NOT NULL,dst TEXT NOT NULL,src_port INTEGER NOT NULL,dst_port INTEGER NOT NULL,protocol INTEGER NOT NULL,first_ns INTEGER NOT NULL,last_ns INTEGER NOT NULL,forward_packets INTEGER NOT NULL,reverse_packets INTEGER NOT NULL,forward_bytes INTEGER NOT NULL,reverse_bytes INTEGER NOT NULL,syn INTEGER NOT NULL,fin INTEGER NOT NULL,rst INTEGER NOT NULL,syn_sequence INTEGER,data_packets INTEGER NOT NULL);
            CREATE INDEX flow_key ON flows(key,id DESC);
            CREATE TABLE events(id INTEGER PRIMARY KEY,timestamp_ns INTEGER NOT NULL,kind TEXT NOT NULL,host TEXT NOT NULL,peer TEXT,summary TEXT NOT NULL,evidence_kind TEXT NOT NULL,packets TEXT NOT NULL,refs_truncated INTEGER NOT NULL,details TEXT NOT NULL);
            BEGIN IMMEDIATE;")))?;
        builder.connection = Some(connection);
        Ok(builder)
    }
    fn connection(&self) -> &Connection {
        self.connection.as_ref().expect("active case builder")
    }
    pub fn interrupt_when(
        &mut self,
        callback: impl FnMut() -> bool + Send + 'static,
    ) -> Result<(), String> {
        sql(self
            .connection
            .as_mut()
            .expect("active case builder")
            .progress_handler(10_000, Some(callback)))
    }
    pub fn packet_count(&self) -> u64 {
        self.count
    }
    pub fn push(&mut self, event: &PacketEvent, decoded: &DecodeEvents) -> Result<(), String> {
        let r = &event.reference;
        if r.number == 0 || r.captured_len > MAX_PACKET || r.original_len < r.captured_len {
            return Err("invalid original packet reference".into());
        }
        sql(self.connection().prepare_cached(
            "INSERT INTO packets VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        ))?
        .execute(params![
            integer(r.number)?,
            r.section,
            r.interface,
            r.link_type,
            integer(r.timestamp_ns)?,
            integer(r.data_offset)?,
            r.captured_len,
            r.original_len,
            event.src.map(|v| v.to_string()),
            event.dst.map(|v| v.to_string()),
            event.src_port,
            event.dst_port,
            event.protocol,
            event.tcp_flags
        ])
        .map_err(|e| error("index original packet", e))?;
        self.count += 1;
        if let Some(packet) = &decoded.packet {
            self.flow(packet)?;
        }
        for value in &decoded.dns {
            self.event(
                observation_time(&value.packets, value.timestamp_ms),
                "dns",
                value.src,
                Some(value.dst),
                format!("DNS {} (type {})", value.name, value.query_type),
                "packet",
                &value.packets,
                false,
                &serde_json::to_value(value).map_err(|e| e.to_string())?,
            )?;
        }
        for value in &decoded.http {
            self.event(
                observation_time(&value.packets, value.timestamp_ms),
                "http",
                value.src,
                Some(value.dst),
                format!(
                    "HTTP {} {}",
                    value.method,
                    value.host.as_deref().unwrap_or("")
                ),
                "packet",
                &value.packets,
                false,
                &serde_json::to_value(value).map_err(|e| e.to_string())?,
            )?;
        }
        for value in &decoded.tls {
            self.event(
                observation_time(&value.packets, value.timestamp_ms),
                "tls",
                value.src,
                Some(value.dst),
                format!(
                    "TLS {}",
                    value.server_name.as_deref().unwrap_or("handshake pair")
                ),
                "packet",
                &value.packets,
                false,
                &serde_json::to_value(value).map_err(|e| e.to_string())?,
            )?;
        }
        for value in &decoded.tls_clients {
            self.event(
                observation_time(&value.packets, value.timestamp_ms),
                "tls_client",
                value.src,
                Some(value.dst),
                format!(
                    "TLS ClientHello {}",
                    value.server_name.as_deref().unwrap_or("without SNI")
                ),
                "packet",
                &value.packets,
                false,
                &serde_json::to_value(value).map_err(|e| e.to_string())?,
            )?;
        }
        for value in &decoded.peer_protocols {
            self.event(
                observation_time(&value.packets, value.timestamp_ms),
                "peer_protocol",
                value.src,
                Some(value.dst),
                "BitTorrent peer handshake observed (one direction)".into(),
                "packet",
                &value.packets,
                false,
                &serde_json::to_value(value).map_err(|e| e.to_string())?,
            )?;
        }
        Ok(())
    }
    fn flow(&self, packet: &crate::capture::DecodedPacket) -> Result<(), String> {
        let Some(reference) = packet.packets.first() else {
            return Err("decoded datagram lacks original references".into());
        };
        let forward = (packet.src, packet.src_port) <= (packet.dst, packet.dst_port);
        let (src, sp, dst, dp) = if forward {
            (packet.src, packet.src_port, packet.dst, packet.dst_port)
        } else {
            (packet.dst, packet.dst_port, packet.src, packet.src_port)
        };
        let key = json_text(&(
            reference.section,
            reference.interface,
            packet.protocol,
            src,
            sp,
            dst,
            dp,
        ))?;
        let timestamp = observation_time(&packet.packets, packet.timestamp_ms);
        let time = integer(timestamp)?;
        let flags = packet.tcp_flags.unwrap_or(0);
        let syn = flags & 2 != 0 && flags & 16 == 0;
        let old: Option<(i64, i64, Option<u32>, bool)> = sql(self
            .connection()
            .query_row(
                "SELECT id,last_ns,syn_sequence,(fin>0 OR rst>0 OR data_packets>0) FROM flows WHERE key=?1 ORDER BY id DESC LIMIT 1",
                [&key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional())?;
        let previous = old.filter(|(_, last, sequence, established)| {
            time.saturating_sub(*last) <= 120_000_000_000
                && !(syn && (*established || *sequence != packet.tcp_sequence))
        });
        let n = packet.packets.len() as u64;
        let has_data = u8::from(packet.protocol == 6 && !packet.payload.is_empty());
        if let Some((id, _, _, _)) = previous {
            sql(self.connection().execute("UPDATE flows SET first_ns=min(first_ns,?2),last_ns=max(last_ns,?2),forward_packets=forward_packets+?3,reverse_packets=reverse_packets+?4,forward_bytes=forward_bytes+?5,reverse_bytes=reverse_bytes+?6,syn=syn+?7,fin=fin+?8,rst=rst+?9,syn_sequence=coalesce(syn_sequence,?10),data_packets=data_packets+?11 WHERE id=?1",params![id,time,if forward{integer(n)?}else{0},if forward{0}else{integer(n)?},if forward{integer(packet.wire_bytes)?}else{0},if forward{0}else{integer(packet.wire_bytes)?},u8::from(syn),u8::from(flags&1!=0),u8::from(flags&4!=0),if syn{packet.tcp_sequence}else{None},has_data]))?;
        } else {
            sql(self.connection().execute("INSERT INTO flows(key,section,interface,src,dst,src_port,dst_port,protocol,first_ns,last_ns,forward_packets,reverse_packets,forward_bytes,reverse_bytes,syn,fin,rst,syn_sequence,data_packets) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",params![key,reference.section,reference.interface,src.to_string(),dst.to_string(),sp,dp,packet.protocol,time,if forward{integer(n)?}else{0},if forward{0}else{integer(n)?},if forward{integer(packet.wire_bytes)?}else{0},if forward{0}else{integer(packet.wire_bytes)?},u8::from(syn),u8::from(flags&1!=0),u8::from(flags&4!=0),if syn{packet.tcp_sequence}else{None},has_data]))?;
            let protocol = match packet.protocol {
                6 => "TCP".into(),
                17 => "UDP".into(),
                1 => "ICMP".into(),
                58 => "ICMPv6".into(),
                number => format!("IP protocol {number}"),
            };
            self.event(timestamp,"connection",packet.src,Some(packet.dst),format!("{} {} → {}",protocol,packet.src_port,packet.dst_port),"packet",&packet.packets,false,&json!({"flow_id":self.connection().last_insert_rowid(),"src_port":packet.src_port,"dst_port":packet.dst_port,"protocol":packet.protocol,"initiator_observed":syn}))?;
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn event(
        &self,
        time: u64,
        kind: &str,
        host: IpAddr,
        peer: Option<IpAddr>,
        summary: String,
        evidence_kind: &str,
        packets: &[PacketRef],
        truncated: bool,
        details: &Value,
    ) -> Result<(), String> {
        sql(self.connection().execute("INSERT INTO events(timestamp_ns,kind,host,peer,summary,evidence_kind,packets,refs_truncated,details) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![integer(time)?,kind,host.to_string(),peer.map(|p|p.to_string()),summary,evidence_kind,json_text(&packets)?,truncated,json_text(details)?]))?;
        Ok(())
    }
    pub fn finding(&self, finding: &Finding) -> Result<(), String> {
        let Some(host) = finding.alert.src else {
            return Ok(());
        };
        let packets: Vec<PacketRef> = finding
            .alert
            .extra
            .get("packets")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| error("finding packet references", e))?
            .unwrap_or_default();
        let timestamp = finding
            .alert
            .extra
            .get("capture_timestamp_ms")
            .and_then(Value::as_u64)
            .map(|n| n.saturating_mul(1_000_000))
            .or_else(|| packets.first().map(|p| p.timestamp_ns))
            .unwrap_or(0);
        self.event(
            timestamp,
            "finding",
            host,
            finding.alert.dst,
            finding.alert.title.clone(),
            if packets.is_empty() {
                "context"
            } else {
                "detector_evidence"
            },
            &packets,
            finding
                .alert
                .extra
                .get("packet_refs_truncated")
                .and_then(Value::as_bool)
                .unwrap_or(packets.is_empty()),
            &serde_json::to_value(finding).map_err(|e| e.to_string())?,
        )
    }
    pub fn finish(
        self,
        enrichment: &CaptureEnrichment,
        analysis: Value,
    ) -> Result<CaseOverview, String> {
        self.finish_with_commit_guard(enrichment, analysis, &mut || Ok(()))
    }
    pub fn finish_with_commit_guard(
        mut self,
        enrichment: &CaptureEnrichment,
        analysis: Value,
        before_commit: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<CaseOverview, String> {
        let capture = enrichment
            .capture
            .clone()
            .ok_or("indexed capture lacks its original SHA-256 identity")?;
        if self.count != enrichment.input_packets {
            return Err("indexed packet count does not match the parser".into());
        }
        sql(self.connection().execute_batch("CREATE INDEX packet_src_time ON packets(src,timestamp_ns,number); CREATE INDEX packet_dst_time ON packets(dst,timestamp_ns,number); CREATE INDEX event_host_time ON events(host,timestamp_ns,id); CREATE INDEX event_peer_time ON events(peer,timestamp_ns,id); CREATE INDEX flow_source ON flows(src,first_ns); CREATE INDEX flow_destination ON flows(dst,first_ns);"))?;
        sql(self.connection().execute_batch("CREATE TABLE hosts AS
            WITH endpoints AS (
              SELECT src AS address,count(*) AS sent,0 AS received,sum(original_len) AS sent_bytes,0 AS received_bytes,min(timestamp_ns) AS first_ns,max(timestamp_ns) AS last_ns FROM packets WHERE src IS NOT NULL GROUP BY src
              UNION ALL
              SELECT dst AS address,0,count(*),0,sum(original_len),min(timestamp_ns),max(timestamp_ns) FROM packets WHERE dst IS NOT NULL GROUP BY dst)
            SELECT address,sum(sent) AS sent,sum(received) AS received,sum(sent_bytes) AS sent_bytes,sum(received_bytes) AS received_bytes,min(first_ns) AS first_ns,max(last_ns) AS last_ns FROM endpoints GROUP BY address;
            CREATE UNIQUE INDEX host_address ON hosts(address);"))?;
        let times: (Option<u64>, Option<u64>) = sql(self.connection().query_row(
            "SELECT min(timestamp_ns),max(timestamp_ns) FROM packets",
            [],
            |row| Ok((optional_unsigned(row, 0)?, optional_unsigned(row, 1)?)),
        ))?;
        let overview = CaseOverview {
            schema_version: CASE_VERSION,
            source: self.source.clone(),
            capture,
            created_at_ms: self.created_at_ms,
            packets: self.count,
            flows: sql(self
                .connection()
                .query_row("SELECT count(*) FROM flows", [], |r| unsigned(r, 0)))?,
            events: sql(self
                .connection()
                .query_row("SELECT count(*) FROM events", [], |r| unsigned(r, 0)))?,
            first_timestamp_ns: times.0,
            last_timestamp_ns: times.1,
            diagnostics: json!({"parser":enrichment.diagnostics,"warnings":enrichment.warnings}),
            analysis,
        };
        sql(self.connection().execute(
            "INSERT INTO meta(key,value) VALUES('overview',?1)",
            [json_text(&overview)?],
        ))?;
        before_commit()?;
        sql(self
            .connection()
            .execute_batch("INSERT INTO meta(key,value) VALUES('status','complete'); COMMIT;"))?;
        self.committed = true;
        Ok(overview)
    }
}
impl Drop for CaseBuilder {
    fn drop(&mut self) {
        self.connection.take();
        if !self.committed {
            let _ = fs::remove_file(&self.destination);
            let mut journal = self.destination.as_os_str().to_owned();
            journal.push("-journal");
            let _ = fs::remove_file(journal);
        }
    }
}

pub struct CaseIndex {
    pub(crate) connection: Connection,
    path: PathBuf,
    overview: CaseOverview,
}
impl CaseIndex {
    pub fn build(
        source: &Path,
        destination: &Path,
        cancelled: &(dyn Fn() -> bool + Sync),
        progress: &mut dyn FnMut(u64),
    ) -> Result<CaseOverview, String> {
        if cancelled() {
            return Err("investigation indexing cancelled".into());
        }
        let mut builder = CaseBuilder::create(source, destination)?;
        let interrupt = builder.connection().get_interrupt_handle();
        let finished = AtomicBool::new(false);
        struct Finish<'a>(&'a AtomicBool);
        impl Drop for Finish<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        std::thread::scope(|scope| {
            let flag = &finished;
            scope.spawn(move || {
                while !flag.load(Ordering::Acquire) {
                    if cancelled() {
                        interrupt.interrupt();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            let _finish = Finish(&finished);
            let enrichment = crate::capture::scan_capture_events(
                source,
                None,
                cancelled,
                &mut |packet, decoded| {
                    builder.push(packet, decoded)?;
                    if packet.reference.number % 4096 == 0 {
                        progress(packet.reference.number);
                    }
                    Ok(())
                },
            )?;
            if cancelled() {
                return Err("investigation indexing cancelled".into());
            }
            progress(builder.packet_count());
            builder.finish_with_commit_guard(
                &enrichment,
                json!({"mode":"index_only","application_version":env!("CARGO_PKG_VERSION")}),
                &mut || {
                    if cancelled() {
                        Err("investigation indexing cancelled before commit".into())
                    } else {
                        Ok(())
                    }
                },
            )
        })
    }
    pub fn open(path: &Path) -> Result<Self, String> {
        let connection = sql(Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?;
        sql(connection.busy_timeout(Duration::from_secs(3)))?;
        sql(connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; PRAGMA cache_size=-16384; PRAGMA mmap_size=0;"))?;
        let app: i32 = sql(connection.pragma_query_value(None, "application_id", |r| r.get(0)))?;
        let version: u32 = sql(connection.pragma_query_value(None, "user_version", |r| r.get(0)))?;
        if app != APPLICATION_ID || version != CASE_VERSION {
            return Err("unsupported investigation database".into());
        }
        let status: String = sql(connection.query_row(
            "SELECT value FROM meta WHERE key='status'",
            [],
            |r| r.get(0),
        ))?;
        if status != "complete" {
            return Err("investigation database is incomplete".into());
        }
        let text: String = sql(connection.query_row(
            "SELECT value FROM meta WHERE key='overview'",
            [],
            |r| r.get(0),
        ))?;
        if text.len() > 4 * 1024 * 1024 {
            return Err("case metadata exceeds 4 MiB".into());
        }
        let overview: CaseOverview =
            serde_json::from_str(&text).map_err(|e| error("case metadata", e))?;
        if overview.schema_version != CASE_VERSION
            || overview.capture.sha256.len() != 64
            || !overview
                .capture
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err("invalid case metadata".into());
        }
        Ok(Self {
            connection,
            path: path.into(),
            overview,
        })
    }
    pub fn overview(&self) -> &CaseOverview {
        &self.overview
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn interrupt_when(
        &mut self,
        callback: impl FnMut() -> bool + Send + 'static,
    ) -> Result<(), String> {
        sql(self.connection.progress_handler(10_000, Some(callback)))
    }
    pub fn hosts(&self, offset: u64, limit: usize) -> Result<Vec<HostSummary>, String> {
        self.search_hosts("", offset, limit)
    }
    pub fn search_hosts(
        &self,
        query: &str,
        offset: u64,
        limit: usize,
    ) -> Result<Vec<HostSummary>, String> {
        if query.len() > 128 || query.chars().any(char::is_control) {
            return Err("host search must be at most 128 printable characters".into());
        }
        let pattern = format!(
            "%{}%",
            query
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        let mut statement=sql(self.connection.prepare("SELECT address,sent,received,sent_bytes,received_bytes,(SELECT count(*) FROM flows WHERE src=address OR dst=address) AS connections,(SELECT count(*) FROM events WHERE host=address AND kind='finding') AS findings,first_ns,last_ns FROM hosts WHERE address LIKE ?3 ESCAPE '\\' ORDER BY findings DESC,sent_bytes DESC,address LIMIT ?1 OFFSET ?2"))?;
        let rows = sql(statement.query_map(
            params![limit.clamp(1, MAX_PAGE) as i64, integer(offset)?, pattern],
            |r| {
                Ok(HostSummary {
                    address: ip(r.get(0)?)?,
                    packets_sent: unsigned(r, 1)?,
                    packets_received: unsigned(r, 2)?,
                    wire_bytes_sent: unsigned(r, 3)?,
                    wire_bytes_received: unsigned(r, 4)?,
                    connections: unsigned(r, 5)?,
                    findings: unsigned(r, 6)?,
                    first_timestamp_ns: unsigned(r, 7)?,
                    last_timestamp_ns: unsigned(r, 8)?,
                })
            },
        ))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| error("read investigation hosts", e))
    }
    pub fn connections(
        &self,
        host: IpAddr,
        after_id: u64,
        limit: usize,
    ) -> Result<Vec<ConnectionSummary>, String> {
        let mut statement=sql(self.connection.prepare("SELECT id,section,interface,src,dst,src_port,dst_port,protocol,first_ns,last_ns,forward_packets,reverse_packets,forward_bytes,reverse_bytes,syn,fin,rst FROM flows WHERE (src=?1 OR dst=?1) AND id>?2 ORDER BY id LIMIT ?3"))?;
        let rows = sql(statement.query_map(
            params![
                host.to_string(),
                integer(after_id)?,
                limit.clamp(1, MAX_PAGE) as i64
            ],
            |r| {
                Ok(ConnectionSummary {
                    id: unsigned(r, 0)?,
                    section: r.get(1)?,
                    interface: r.get(2)?,
                    src: ip(r.get(3)?)?,
                    dst: ip(r.get(4)?)?,
                    src_port: r.get(5)?,
                    dst_port: r.get(6)?,
                    protocol: r.get(7)?,
                    first_timestamp_ns: unsigned(r, 8)?,
                    last_timestamp_ns: unsigned(r, 9)?,
                    forward_packets: unsigned(r, 10)?,
                    reverse_packets: unsigned(r, 11)?,
                    forward_wire_bytes: unsigned(r, 12)?,
                    reverse_wire_bytes: unsigned(r, 13)?,
                    syn_packets: unsigned(r, 14)?,
                    fin_packets: unsigned(r, 15)?,
                    rst_packets: unsigned(r, 16)?,
                })
            },
        ))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| error("read host connections", e))
    }
    pub fn timeline(
        &self,
        host: IpAddr,
        after_id: u64,
        limit: usize,
    ) -> Result<TimelinePage, String> {
        let limit = limit.clamp(1, MAX_PAGE);
        // IDs are insertion order. Sorting by timestamp uses a timestamp+ID cursor
        // resolved from the previous row, so out-of-order captures remain stable.
        let cursor: Option<(u64, u64)> = if after_id == 0 {
            None
        } else {
            sql(self
                .connection
                .query_row(
                    "SELECT timestamp_ns,id FROM events WHERE id=?1 AND (host=?2 OR peer=?2)",
                    params![integer(after_id)?, host.to_string()],
                    |r| Ok((unsigned(r, 0)?, unsigned(r, 1)?)),
                )
                .optional())?
        };
        if after_id != 0 && cursor.is_none() {
            return Err("timeline cursor does not belong to this host".into());
        }
        let (time, id) = cursor.unwrap_or((0, 0));
        let mut statement=sql(self.connection.prepare("SELECT id,timestamp_ns,kind,host,peer,summary,evidence_kind,packets,refs_truncated,details FROM events WHERE (host=?1 OR peer=?1) AND (timestamp_ns>?2 OR (timestamp_ns=?2 AND id>?3)) ORDER BY timestamp_ns,id LIMIT ?4"))?;
        let rows = sql(statement.query_map(
            params![
                host.to_string(),
                integer(time)?,
                integer(id)?,
                (limit + 1) as i64
            ],
            event_row,
        ))?;
        let mut events = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| error("read host timeline", e))?;
        let next_id = if events.len() > limit {
            events.truncate(limit);
            events.last().map(|e| e.id)
        } else {
            None
        };
        Ok(TimelinePage {
            host,
            events,
            next_id,
        })
    }
    pub fn packet(&self, number: u64) -> Result<PacketRef, String> {
        sql(self.connection.query_row("SELECT number,section,interface,link_type,timestamp_ns,data_offset,captured_len,original_len FROM packets WHERE number=?1",[integer(number)?],packet_row))
    }
    pub fn host_packets(
        &self,
        host: IpAddr,
        after_number: u64,
        limit: usize,
    ) -> Result<Vec<PacketRef>, String> {
        let mut statement=sql(self.connection.prepare("SELECT number,section,interface,link_type,timestamp_ns,data_offset,captured_len,original_len FROM packets WHERE (src=?1 OR dst=?1) AND number>?2 ORDER BY number LIMIT ?3"))?;
        let rows = sql(statement.query_map(
            params![
                host.to_string(),
                integer(after_number)?,
                limit.clamp(1, MAX_PAGE) as i64
            ],
            packet_row,
        ))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| error("read host packet references", e))
    }
    pub fn verify_source(
        &self,
        path: Option<&Path>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VerifiedCapture, String> {
        VerifiedCapture::open(
            path.unwrap_or(&self.overview.source),
            &self.overview.capture,
            cancelled,
        )
    }
}
fn packet_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PacketRef> {
    Ok(PacketRef {
        number: unsigned(row, 0)?,
        section: row.get(1)?,
        interface: row.get(2)?,
        link_type: row.get(3)?,
        timestamp_ns: unsigned(row, 4)?,
        data_offset: unsigned(row, 5)?,
        captured_len: row.get(6)?,
        original_len: row.get(7)?,
    })
}
fn event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TimelineEvent> {
    fn parse<T: serde::de::DeserializeOwned>(value: String) -> rusqlite::Result<T> {
        serde_json::from_str(&value).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })
    }
    Ok(TimelineEvent {
        id: unsigned(row, 0)?,
        timestamp_ns: unsigned(row, 1)?,
        kind: row.get(2)?,
        host: ip(row.get(3)?)?,
        peer: row.get::<_, Option<String>>(4)?.map(ip).transpose()?,
        summary: row.get(5)?,
        evidence_kind: row.get(6)?,
        packets: parse(row.get(7)?)?,
        packet_refs_truncated: row.get(8)?,
        details: parse(row.get(9)?)?,
    })
}

/// A source file opened before verification; packet reads use the same handle.
pub struct VerifiedCapture {
    file: File,
    path: PathBuf,
    identity: CaptureIdentity,
    validated: BTreeSet<PacketRef>,
}
impl VerifiedCapture {
    fn open(
        path: &Path,
        identity: &CaptureIdentity,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, String> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(1);
        }
        let mut file = options
            .open(path)
            .map_err(|e| error("open original capture", e))?;
        if file.metadata().map_err(|e| e.to_string())?.len() != identity.bytes {
            return Err("original capture size differs from the indexed file".into());
        }
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut bytes = 0u64;
        loop {
            if cancelled() {
                return Err("source verification cancelled".into());
            }
            let n = file
                .read(&mut buffer)
                .map_err(|e| error("verify original capture", e))?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
            bytes += n as u64;
        }
        if bytes != identity.bytes
            || format!("{:x}", hash.finalize()) != identity.sha256.to_ascii_lowercase()
        {
            return Err(
                "original capture SHA-256 differs from this investigation; evidence was not read"
                    .into(),
            );
        }
        Ok(Self {
            file,
            path: path.into(),
            identity: identity.clone(),
            validated: BTreeSet::new(),
        })
    }
    pub fn validate_references(
        &mut self,
        references: &[PacketRef],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        if references.len() > 10_000 {
            return Err("verify at most 10000 packet references per operation".into());
        }
        let requested: BTreeMap<_, _> = references
            .iter()
            .map(|reference| (reference.number, reference))
            .collect();
        let mut seen = BTreeSet::new();
        let identity = crate::capture::scan_packet_metadata(&self.path, cancelled, &mut |event| {
            if let Some(expected) = requested.get(&event.reference.number) {
                if **expected != event.reference {
                    return Err(
                        "case packet reference does not match the original container metadata"
                            .into(),
                    );
                }
                seen.insert(event.reference.number);
            }
            Ok(())
        })?;
        if identity != self.identity || seen.len() != requested.len() {
            return Err("original packet references could not be authenticated".into());
        }
        self.validated.extend(references.iter().cloned());
        Ok(())
    }
    pub fn read_packet(&mut self, reference: &PacketRef) -> Result<Vec<u8>, String> {
        if reference.number == 0
            || reference.captured_len > MAX_PACKET
            || reference.original_len < reference.captured_len
            || reference
                .data_offset
                .checked_add(u64::from(reference.captured_len))
                .is_none_or(|end| end > self.identity.bytes)
        {
            return Err("packet reference lies outside the verified original capture".into());
        }
        if !self.validated.contains(reference) {
            self.validate_references(std::slice::from_ref(reference), &|| false)?;
        }
        self.file
            .seek(SeekFrom::Start(reference.data_offset))
            .map_err(|e| error("seek original packet", e))?;
        let mut bytes = vec![0; reference.captured_len as usize];
        self.file
            .read_exact(&mut bytes)
            .map_err(|e| error("read original packet", e))?;
        Ok(bytes)
    }
}
