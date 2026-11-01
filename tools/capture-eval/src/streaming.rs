//! Shared incremental Rust detection for offline readers and local live capture.
//! The decoder is shared with capture-file analysis; no Go sensor is launched.
//! Rule tuning, exception predicates, and alert metadata use the existing YAML
//! format. A replacement Rust pack enables only the rule IDs it contains.

use crate::capture::{
    CaptureDiagnostics, DecodeEvents, DecodedPacket, DnsObservation, HttpObservation, PacketRef,
    StreamDecoder, TlsClientObservation, TlsObservation,
};
use crate::dns::{DnsAnalyzer, DnsPolicy};
use crate::feed::PairFeed;
use crate::process::{ProcessAssociation, ProcessSnapshot, Transport};
use crate::{Alert, AlertAccumulator, AnalysisReport, Severity};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

const BUILTIN: [&str; 7] = [
    include_str!("../../../internal/rules/builtin/th-0001-beaconing.yaml"),
    include_str!("../../../internal/rules/builtin/th-0002-dns-tunnel.yaml"),
    include_str!("../../../internal/rules/builtin/th-0003-scan-vertical.yaml"),
    include_str!("../../../internal/rules/builtin/th-0004-scan-horizontal.yaml"),
    include_str!("../../../internal/rules/builtin/th-0005-exfiltration.yaml"),
    include_str!("../../../internal/rules/builtin/th-0006-new-device.yaml"),
    include_str!("../../../internal/rules/builtin/th-0007-rare-ja4.yaml"),
];

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StreamLimits {
    pub max_flows: usize,
    pub max_findings: usize,
    pub max_devices: usize,
    pub max_beacon_tracks: usize,
    pub max_starts_per_track: usize,
    pub max_scan_sources: usize,
    pub max_probes_per_source: usize,
    pub max_fingerprints: usize,
    pub max_evidence_packets: usize,
    pub flow_idle_ms: u64,
    pub tick_ms: u64,
    pub max_alert_records: u64,
}
impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_flows: 20_000,
            max_findings: 20_000,
            max_devices: 20_000,
            max_beacon_tracks: 20_000,
            max_starts_per_track: 512,
            max_scan_sources: 2_000,
            max_probes_per_source: 4096,
            max_fingerprints: 20_000,
            max_evidence_packets: 128,
            flow_idle_ms: 120_000,
            tick_ms: 1000,
            max_alert_records: 1_000_000,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StreamOptions {
    pub rules: Option<PathBuf>,
    pub home_nets: Vec<IpNet>,
    pub pair_feed: Option<PathBuf>,
    pub min_severity: Severity,
    pub limits: StreamLimits,
    /// Only the local live-capture entry point enables this. Capture-file
    /// analysis leaves it false, including files with local/loopback addresses.
    pub local_live: bool,
}
impl Default for StreamOptions {
    fn default() -> Self {
        Self {
            rules: None,
            pair_feed: None,
            min_severity: Severity::Low,
            limits: StreamLimits::default(),
            local_live: false,
            home_nets: [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "127.0.0.0/8",
                "100.64.0.0/10",
                "fc00::/7",
                "fe80::/10",
                "::1/128",
            ]
            .iter()
            .map(|text| text.parse().unwrap())
            .collect(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StreamStats {
    pub packets: u64,
    pub wire_bytes: u64,
    pub transport_packets: u64,
    pub alert_records: u64,
    pub active_flows: usize,
    pub devices: usize,
    pub findings: usize,
    pub dropped_flow_packets: u64,
    pub dropped_tracking_events: u64,
    pub dropped_evidence_refs: u64,
    pub dropped_findings: u64,
    pub out_of_order_packets: u64,
    #[serde(default)]
    pub dropped_dns_name_events: u64,
    #[serde(default)]
    pub uncertainty_limited_dns_scores: u64,
    #[serde(default)]
    pub fingerprint_user_samples_omitted: u64,
    pub first_timestamp_ms: Option<u64>,
    pub last_timestamp_ms: Option<u64>,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct StreamBatch {
    pub alerts: Vec<Alert>,
    pub processes: Vec<ProcessAssociation>,
    pub http: Vec<HttpObservation>,
    pub tls: Vec<TlsObservation>,
    pub tls_clients: Vec<TlsClientObservation>,
    pub dns: Vec<DnsObservation>,
    pub warnings: Vec<String>,
    pub diagnostics: CaptureDiagnostics,
}
#[derive(Clone, Debug, Serialize)]
pub struct StreamSummary {
    pub schema_version: u32,
    pub mode: String,
    pub report: AnalysisReport,
    pub stats: StreamStats,
    pub diagnostics: CaptureDiagnostics,
    pub policy_notes: Vec<String>,
    pub analysis_meta: Value,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exception {
    description: String,
    #[serde(default)]
    src: String,
    #[serde(default)]
    dst: String,
    #[serde(default)]
    dst_port: u16,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    ja4: String,
}
impl Exception {
    fn validate(&self) -> Result<(), String> {
        if self.description.trim().is_empty()
            || (self.src.is_empty()
                && self.dst.is_empty()
                && self.dst_port == 0
                && self.domain.is_empty()
                && self.ja4.is_empty())
        {
            return Err(
                "Rule exceptions require a description and at least one match field.".into(),
            );
        }
        for text in [&self.src, &self.dst] {
            if !text.is_empty() {
                parse_net(text)?;
            }
        }
        Ok(())
    }
    fn matches(&self, alert: &Alert) -> bool {
        let network = |text: &str, address: Option<IpAddr>| {
            text.is_empty()
                || parse_net(text)
                    .ok()
                    .is_some_and(|net| address.is_some_and(|ip| net.contains(&unmap(ip))))
        };
        let domain = self
            .domain
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        network(&self.src, alert.src)
            && network(&self.dst, alert.dst)
            && (self.dst_port == 0
                || alert.extra.get("dst_port").and_then(Value::as_u64)
                    == Some(u64::from(self.dst_port)))
            && (domain.is_empty()
                || ["domain", "server_name"].iter().any(|key| {
                    alert
                        .evidence
                        .get(key)
                        .and_then(Value::as_str)
                        .is_some_and(|name| {
                            let name = name.to_ascii_lowercase();
                            name == domain || name.ends_with(&format!(".{domain}"))
                        })
                }))
            && (self.ja4.is_empty()
                || alert.evidence.get("ja4").and_then(Value::as_str) == Some(self.ja4.as_str()))
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    name: String,
    detector: String,
    #[serde(default = "yes")]
    enabled: bool,
    severity: Option<Severity>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    techniques: Vec<Value>,
    #[serde(default)]
    tuning: BTreeMap<String, serde_yaml_ng::Value>,
    #[serde(default)]
    exceptions: Vec<Exception>,
}
fn yes() -> bool {
    true
}
#[derive(Clone)]
struct Policy {
    rules: BTreeMap<String, Rule>,
    tuning: BTreeMap<(String, String), serde_yaml_ng::Value>,
    sha256: String,
}
impl Policy {
    fn load(path: Option<&Path>) -> Result<Self, String> {
        let documents = if let Some(path) = path {
            let mut files = if path.is_dir() {
                fs::read_dir(path)
                    .map_err(|e| e.to_string())?
                    .map(|entry| entry.map(|entry| entry.path()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| e.to_string())?
            } else {
                vec![path.to_path_buf()]
            };
            files.retain(|path| {
                path.extension()
                    .and_then(|v| v.to_str())
                    .is_some_and(|v| matches!(v, "yaml" | "yml"))
            });
            files.sort();
            if files.is_empty() || files.len() > 128 {
                return Err("Rule pack must contain 1–128 YAML files.".into());
            }
            files
                .into_iter()
                .map(|path| {
                    if fs::metadata(&path).map_err(|e| e.to_string())?.len() > 2 * 1024 * 1024 {
                        return Err("Rule file exceeds 2 MiB.".into());
                    }
                    fs::read_to_string(path).map_err(|e| e.to_string())
                })
                .collect::<Result<Vec<_>, String>>()?
        } else {
            BUILTIN.iter().map(|text| (*text).to_owned()).collect()
        };
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for document in &documents {
            hasher.update((document.len() as u64).to_le_bytes());
            hasher.update(document.as_bytes());
        }
        let sha256 = format!("{:x}", hasher.finalize());
        let mut rules = BTreeMap::new();
        let mut tuning = BTreeMap::new();
        for text in documents {
            for document in serde_yaml_ng::Deserializer::from_str(&text) {
                let rule = Rule::deserialize(document).map_err(|e| format!("Stream rule: {e}"))?;
                let allowed = match rule.detector.as_str() {
                    "beaconing" => &[
                        "min_connections",
                        "min_interval",
                        "max_interval",
                        "threshold",
                        "history",
                        "max_tracked",
                    ][..],
                    "dns-tunnel" => &[
                        "min_queries",
                        "threshold",
                        "history",
                        "max_tracked",
                        "max_unique_names",
                    ][..],
                    "port-scan" => &[
                        "vertical_ports",
                        "horizontal_hosts",
                        "window",
                        "max_answered_ratio",
                        "max_tracked",
                        "max_ports_per_target",
                        "max_targets_per_port",
                    ][..],
                    "exfiltration" => &["min_bytes_out", "min_ratio"][..],
                    "inventory" => &[
                        "max_devices",
                        "silence_new_device",
                        "min_hosts_for_rarity",
                        "min_fingerprints_for_rarity",
                        "min_shared_fingerprints",
                        "min_observations",
                        "min_age",
                    ][..],
                    "long-connection" => &["min_duration", "min_bytes"][..],
                    "known-tls-pair" => &[][..],
                    _ => return Err(format!("Unknown stream detector {}", rule.detector)),
                };
                if rule.name.trim().is_empty() || !valid_id(&rule.id) {
                    return Err("Rule needs a valid id and nonempty name.".into());
                }
                let expected = match rule.id.as_str() {
                    "TH-0001" => Some("beaconing"),
                    "TH-0002" => Some("dns-tunnel"),
                    "TH-0003" | "TH-0004" => Some("port-scan"),
                    "TH-0005" => Some("exfiltration"),
                    "TH-0006" | "TH-0007" => Some("inventory"),
                    "TH-0008" => Some("known-tls-pair"),
                    "TH-0009" => Some("long-connection"),
                    _ => None,
                };
                if expected.is_some_and(|expected| rule.detector != expected) {
                    return Err(format!("{} uses the wrong detector", rule.id));
                }
                for exception in &rule.exceptions {
                    exception.validate()?;
                }
                for technique in &rule.techniques {
                    if technique
                        .get("id")
                        .and_then(Value::as_str)
                        .is_none_or(|id| id.trim().is_empty())
                    {
                        return Err("Technique needs an id.".into());
                    }
                }
                for (key, value) in &rule.tuning {
                    if !allowed.contains(&key.as_str()) {
                        return Err(format!("Unknown {} tuning key {key}", rule.id));
                    }
                    let numeric = matches!(
                        key.as_str(),
                        "threshold" | "max_answered_ratio" | "min_ratio"
                    );
                    if key == "silence_new_device" {
                        if value.as_bool().is_none() {
                            return Err(format!("{key} must be boolean"));
                        }
                    } else if matches!(
                        key.as_str(),
                        "min_interval"
                            | "max_interval"
                            | "history"
                            | "window"
                            | "min_age"
                            | "min_duration"
                    ) {
                        duration_ms(value.as_str().ok_or("Rule duration must be a string.")?)?;
                    } else if numeric {
                        let n = value.as_f64().ok_or("Rule tuning must be numeric.")?;
                        if !n.is_finite() || n < 0.0 || (key != "min_ratio" && n > 1.0) {
                            return Err(format!("Invalid {key}"));
                        }
                    } else if value.as_u64().is_none() {
                        return Err(format!("{key} must be a nonnegative integer"));
                    }
                    tuning.insert((rule.detector.clone(), key.clone()), value.clone());
                }
                if rules.insert(rule.id.clone(), rule).is_some() {
                    return Err("Duplicate stream rule ID.".into());
                }
            }
        }
        Ok(Self {
            rules,
            tuning,
            sha256,
        })
    }
    fn enabled(&self, id: &str) -> bool {
        self.rules.get(id).is_some_and(|rule| rule.enabled)
    }
    fn number(&self, detector: &str, key: &str, default: f64) -> f64 {
        self.tuning
            .get(&(detector.into(), key.into()))
            .and_then(serde_yaml_ng::Value::as_f64)
            .filter(|n| *n > 0.0)
            .unwrap_or(default)
    }
    fn count(&self, detector: &str, key: &str, default: usize) -> usize {
        self.number(detector, key, default as f64) as usize
    }
    fn duration(&self, detector: &str, key: &str, default: u64) -> u64 {
        self.tuning
            .get(&(detector.into(), key.into()))
            .and_then(serde_yaml_ng::Value::as_str)
            .and_then(|text| duration_ms(text).ok())
            .filter(|n| *n > 0)
            .unwrap_or(default)
    }
    fn apply(&self, alert: &mut Alert) -> bool {
        if let Some(rule) = self.rules.get(&alert.rule_id) {
            if !rule.enabled
                || rule
                    .exceptions
                    .iter()
                    .any(|exception| exception.matches(alert))
            {
                return false;
            }
            if let Some(severity) = rule.severity {
                alert.severity = severity;
            }
            if !rule.techniques.is_empty() {
                alert
                    .extra
                    .insert("techniques".into(), json!(rule.techniques));
            }
            if !rule.references.is_empty() {
                alert
                    .extra
                    .insert("references".into(), json!(rule.references));
            }
            if !rule.description.trim().is_empty() {
                alert
                    .extra
                    .insert("rule_description".into(), json!(rule.description));
            }
        } else if alert.rule_id != "TH-0008" {
            return false;
        }
        true
    }
}
fn valid_id(id: &str) -> bool {
    id.split_once('-').is_some_and(|(prefix, digits)| {
        (2..=8).contains(&prefix.len())
            && prefix.bytes().all(|b| b.is_ascii_uppercase())
            && digits.len() == 4
            && digits.bytes().all(|b| b.is_ascii_digit())
    })
}
fn duration_ms(text: &str) -> Result<u64, String> {
    if text == "0" {
        return Ok(0);
    }
    let mut rest = text;
    let mut total = 0.0;
    while !rest.is_empty() {
        let n = rest
            .bytes()
            .take_while(|b| b.is_ascii_digit() || *b == b'.')
            .count();
        if n == 0 {
            return Err(format!("Invalid duration {text}"));
        }
        let number = rest[..n].parse::<f64>().map_err(|e| e.to_string())?;
        rest = &rest[n..];
        let (unit, multiplier) = [
            ("ns", 0.000001),
            ("us", 0.001),
            ("ms", 1.0),
            ("s", 1000.0),
            ("m", 60_000.0),
            ("h", 3_600_000.0),
        ]
        .into_iter()
        .find(|(unit, _)| rest.starts_with(unit))
        .ok_or_else(|| format!("Invalid duration {text}"))?;
        total += number * multiplier;
        rest = &rest[unit.len()..];
    }
    if text.is_empty() || !total.is_finite() || total > i64::MAX as f64 / 1_000_000.0 {
        return Err("Duration out of range.".into());
    }
    Ok(total as u64)
}
fn parse_net(text: &str) -> Result<IpNet, String> {
    text.parse::<IpAddr>()
        .map(|ip| IpNet::from(unmap(ip)))
        .or_else(|_| text.parse::<IpNet>())
        .map_err(|e| format!("Invalid IP/CIDR {text}: {e}"))
}
fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        _ => ip,
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FlowKey {
    section: u32,
    interface: u32,
    first: SocketAddr,
    second: SocketAddr,
    protocol: u8,
}
impl FlowKey {
    fn packet(packet: &DecodedPacket) -> Self {
        let src = SocketAddr::new(unmap(packet.src), packet.src_port);
        let dst = SocketAddr::new(unmap(packet.dst), packet.dst_port);
        let reference = packet.packets.first();
        Self {
            section: reference.map_or(0, |r| r.section),
            interface: reference.map_or(0, |r| r.interface),
            first: src.min(dst),
            second: src.max(dst),
            protocol: packet.protocol,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct StreamFlow {
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub protocol: u8,
    pub first_ms: u64,
    pub last_ms: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub packets_out: u64,
    pub packets_in: u64,
    pub packets: Vec<PacketRef>,
    pub refs_truncated: bool,
    pub server_name: Option<String>,
    pub ja4: Option<String>,
    pub process: Vec<ProcessAssociation>,
    #[serde(skip)]
    syn_sequence: Option<u32>,
    #[serde(skip)]
    fin_client: bool,
    #[serde(skip)]
    fin_server: bool,
}
struct BeaconTrack {
    starts: VecDeque<u64>,
    sizes: VecDeque<f64>,
    packets: Vec<PacketRef>,
    last: u64,
}
struct Probe {
    last: u64,
    answered: bool,
    packets: Vec<PacketRef>,
}
#[derive(Clone, Debug, Serialize)]
pub struct StreamDevice {
    pub address: IpAddr,
    pub first_ms: u64,
    pub last_ms: u64,
    pub packets: u64,
    pub fingerprints: BTreeSet<String>,
}
struct FingerprintTrack {
    hosts: BTreeSet<IpAddr>,
    first: u64,
    observations: u64,
    packets: Vec<PacketRef>,
}
struct Previous {
    at: u64,
    severity: Severity,
    evidence: Value,
}

pub struct StreamingAnalyzer {
    options: StreamOptions,
    policy: Policy,
    decoder: StreamDecoder,
    dns: Option<DnsAnalyzer>,
    feed: Option<PairFeed>,
    flows: BTreeMap<FlowKey, StreamFlow>,
    beacons: BTreeMap<(IpAddr, IpAddr, u16, u8), BeaconTrack>,
    scans: BTreeMap<IpAddr, BTreeMap<(IpAddr, u16), Probe>>,
    scan_vertical_reported: BTreeSet<IpAddr>,
    scan_horizontal_reported: BTreeSet<IpAddr>,
    devices: BTreeMap<IpAddr, StreamDevice>,
    fingerprints: BTreeMap<String, FingerprintTrack>,
    suppression: BTreeMap<(String, IpAddr, Option<IpAddr>), Previous>,
    seen_findings: BTreeSet<(String, IpAddr, Option<IpAddr>)>,
    accumulator: AlertAccumulator,
    stats: StreamStats,
    diagnostics: CaptureDiagnostics,
    next_tick: u64,
    processes: Option<ProcessSnapshot>,
}
impl StreamingAnalyzer {
    pub fn new(options: StreamOptions) -> Result<Self, String> {
        let limits = &options.limits;
        if [
            limits.max_flows,
            limits.max_findings,
            limits.max_devices,
            limits.max_beacon_tracks,
            limits.max_starts_per_track,
            limits.max_scan_sources,
            limits.max_probes_per_source,
            limits.max_fingerprints,
            limits.max_evidence_packets,
        ]
        .iter()
        .any(|n| *n == 0 || *n > 1_000_000)
            || limits.max_evidence_packets > 4096
            || limits.max_starts_per_track > 65536
            || limits.tick_ms == 0
            || limits.max_alert_records == 0
            || limits.flow_idle_ms == 0
        {
            return Err("Invalid streaming memory/time limits.".into());
        }
        let policy = Policy::load(options.rules.as_deref())?;
        let dns = DnsAnalyzer::new(DnsPolicy::load(options.rules.as_deref())?);
        let feed = options
            .pair_feed
            .as_deref()
            .map(PairFeed::load)
            .transpose()?;
        let accumulator = AlertAccumulator::new(options.min_severity);
        Ok(Self {
            options,
            policy,
            decoder: StreamDecoder::default(),
            dns: Some(dns),
            feed,
            flows: BTreeMap::new(),
            beacons: BTreeMap::new(),
            scans: BTreeMap::new(),
            scan_vertical_reported: BTreeSet::new(),
            scan_horizontal_reported: BTreeSet::new(),
            devices: BTreeMap::new(),
            fingerprints: BTreeMap::new(),
            suppression: BTreeMap::new(),
            seen_findings: BTreeSet::new(),
            accumulator,
            stats: StreamStats::default(),
            diagnostics: CaptureDiagnostics::default(),
            next_tick: 0,
            processes: None,
        })
    }
    pub fn stats(&self) -> StreamStats {
        let mut stats = self.stats.clone();
        stats.active_flows = self.flows.len();
        stats.devices = self.devices.len();
        stats.findings = self.seen_findings.len();
        if let Some(dns) = &self.dns {
            stats.dropped_dns_name_events = dns.dropped_name_events;
            stats.uncertainty_limited_dns_scores = dns.uncertainty_limited_scores;
            stats.dropped_tracking_events = stats
                .dropped_tracking_events
                .saturating_add(dns.dropped_track_events);
        }
        stats
    }
    pub fn flows(&self) -> impl Iterator<Item = &StreamFlow> {
        self.flows.values()
    }
    pub fn devices(&self) -> impl Iterator<Item = &StreamDevice> {
        self.devices.values()
    }
    pub fn analysis_meta(&self) -> Value {
        json!({"engine":"rust-stream","engine_version":env!("CARGO_PKG_VERSION"),"rule_pack_sha256":self.policy.sha256,"rule_pack_mode":"replacement_present_rules","public_suffix_list":"psl-crate-embedded","tls_client_scope":"completed_client_hello","dns_global_name_budget":crate::dns::MAX_GLOBAL_NAMES,"fingerprint_users_retained":2,"local_live":self.options.local_live,"limits":self.options.limits})
    }
    /// Borrowed decoder output avoids duplicating application payload bytes.
    pub fn observe_ref(&mut self, events: &DecodeEvents) -> Result<StreamBatch, String> {
        self.observe_inner(events)
    }
    pub fn set_process_snapshot(&mut self, snapshot: ProcessSnapshot) -> Result<(), String> {
        if !self.options.local_live {
            return Err("Process tables are only allowed for local live captures.".into());
        }
        self.processes = Some(snapshot);
        Ok(())
    }
    pub fn push_packet(
        &mut self,
        reference: PacketRef,
        data: &[u8],
    ) -> Result<StreamBatch, String> {
        let events = self.decoder.push_packet(reference, data)?;
        self.observe(events)
    }
    pub fn observe(&mut self, events: DecodeEvents) -> Result<StreamBatch, String> {
        self.observe_inner(&events)
    }
    fn observe_inner(&mut self, events: &DecodeEvents) -> Result<StreamBatch, String> {
        self.stats.packets += 1;
        self.diagnostics = events.diagnostics.clone();
        let mut batch = StreamBatch {
            http: events.http.clone(),
            tls: events.tls.clone(),
            tls_clients: events.tls_clients.clone(),
            dns: events.dns.clone(),
            warnings: events.warnings.clone(),
            diagnostics: events.diagnostics.clone(),
            ..Default::default()
        };
        let observed_at = events
            .packet
            .as_ref()
            .map(|packet| packet.timestamp_ms)
            .or_else(|| batch.dns.first().map(|query| query.timestamp_ms))
            .or_else(|| batch.tls_clients.first().map(|client| client.timestamp_ms))
            .or_else(|| batch.tls.first().map(|tls| tls.timestamp_ms))
            .or_else(|| batch.http.first().map(|http| http.timestamp_ms));
        let now = observed_at.unwrap_or(self.stats.last_timestamp_ms.unwrap_or(0));
        if let Some(now) = observed_at {
            self.stats.first_timestamp_ms.get_or_insert(now);
        }
        if observed_at.is_some() && self.stats.last_timestamp_ms.is_some_and(|last| now < last) {
            self.stats.out_of_order_packets += 1;
        }
        let watermark = self.stats.last_timestamp_ms.unwrap_or(now).max(now);
        if observed_at.is_some() {
            self.stats.last_timestamp_ms = Some(watermark);
        }
        if let Some(packet) = &events.packet {
            self.packet(packet, &mut batch)?;
        }
        for query in &batch.dns {
            if self.internal(query.src) {
                let alerts = self.dns.as_mut().unwrap().observe(query);
                for alert in alerts {
                    self.emit(alert, &[], now, &mut batch.alerts)?;
                }
            }
        }
        let clients = batch.tls_clients.clone();
        for client in &clients {
            self.tls_client(client, now);
        }
        let tls = batch.tls.clone();
        for observation in &tls {
            self.tls(observation, now, &mut batch.alerts)?;
        }
        if watermark >= self.next_tick {
            self.tick_into(watermark, &mut batch.alerts)?;
            self.next_tick = watermark.saturating_add(self.options.limits.tick_ms);
        }
        Ok(batch)
    }
    fn internal(&self, address: IpAddr) -> bool {
        self.options
            .home_nets
            .iter()
            .any(|net| net.contains(&unmap(address)))
    }
    fn refs(&mut self, target: &mut Vec<PacketRef>, references: &[PacketRef]) {
        for reference in references {
            if target.iter().any(|stored| {
                stored.number == reference.number
                    && stored.section == reference.section
                    && stored.interface == reference.interface
            }) {
                continue;
            }
            if target.len() < self.options.limits.max_evidence_packets {
                target.push(reference.clone());
            } else {
                self.stats.dropped_evidence_refs += 1;
            }
        }
    }
    fn emit(
        &mut self,
        mut alert: Alert,
        references: &[PacketRef],
        now: u64,
        out: &mut Vec<Alert>,
    ) -> Result<(), String> {
        if !self.policy.apply(&mut alert) || alert.severity < self.options.min_severity {
            return Ok(());
        }
        let source = alert.src.ok_or("Streaming finding is missing source.")?;
        let key = (alert.rule_id.clone(), source, alert.dst);
        if self.suppression.get(&key).is_some_and(|previous| {
            previous.evidence == alert.evidence
                || (alert.severity <= previous.severity
                    && now.saturating_sub(previous.at) < 600_000)
        }) {
            return Ok(());
        }
        if !self.seen_findings.contains(&key)
            && self.seen_findings.len() >= self.options.limits.max_findings
        {
            self.stats.dropped_findings += 1;
            return Ok(());
        }
        if self.stats.alert_records >= self.options.limits.max_alert_records {
            return Err("Stream alert-record limit reached; stop the session or increase max_alert_records.".into());
        }
        self.seen_findings.insert(key.clone());
        self.suppression.insert(
            key,
            Previous {
                at: now,
                severity: alert.severity,
                evidence: alert.evidence.clone(),
            },
        );
        alert
            .extra
            .insert("capture_timestamp_ms".into(), json!(now));
        alert.extra.insert("engine".into(), json!("rust-stream"));
        if !references.is_empty() || !alert.extra.contains_key("packets") {
            alert.extra.insert(
                "packets".into(),
                json!(references
                    .iter()
                    .take(self.options.limits.max_evidence_packets)
                    .collect::<Vec<_>>()),
            );
        }
        let mut inherited_truncation = false;
        if let Some(references) = alert.extra.get_mut("packets").and_then(Value::as_array_mut) {
            let excess = references
                .len()
                .saturating_sub(self.options.limits.max_evidence_packets);
            if excess > 0 {
                references.truncate(self.options.limits.max_evidence_packets);
                self.stats.dropped_evidence_refs += excess as u64;
                inherited_truncation = true;
            }
        }
        let truncated = inherited_truncation
            || alert
                .extra
                .get("packet_refs_truncated")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            || references.len() >= self.options.limits.max_evidence_packets;
        alert
            .extra
            .insert("packet_refs_truncated".into(), json!(truncated));
        alert
            .extra
            .insert("evidence_scope".into(), json!("bounded_packet_examples"));
        for key in ["window_start_ms", "window_end_ms"] {
            if let Some(value) = alert.evidence.get(key) {
                alert.extra.insert(key.into(), value.clone());
            }
        }
        self.accumulator.push(alert.clone())?;
        self.stats.alert_records += 1;
        out.push(alert);
        Ok(())
    }
    fn packet(&mut self, packet: &DecodedPacket, batch: &mut StreamBatch) -> Result<(), String> {
        self.stats.transport_packets += 1;
        self.stats.wire_bytes = self.stats.wire_bytes.saturating_add(packet.wire_bytes);
        for address in [packet.src, packet.dst] {
            if !self.internal(address) {
                continue;
            }
            if !self.devices.contains_key(&address) {
                if self.devices.len()
                    >= self.options.limits.max_devices.min(self.policy.count(
                        "inventory",
                        "max_devices",
                        100_000,
                    ))
                {
                    self.stats.dropped_tracking_events += 1;
                    continue;
                }
                self.devices.insert(
                    address,
                    StreamDevice {
                        address,
                        first_ms: packet.timestamp_ms,
                        last_ms: packet.timestamp_ms,
                        packets: 0,
                        fingerprints: BTreeSet::new(),
                    },
                );
                if self.policy.enabled("TH-0006")
                    && !self
                        .policy
                        .tuning
                        .get(&("inventory".into(), "silence_new_device".into()))
                        .and_then(serde_yaml_ng::Value::as_bool)
                        .unwrap_or(false)
                {
                    self.emit(
                        alert(
                            "TH-0006",
                            Severity::Info,
                            address,
                            None,
                            0,
                            "New device observed",
                            json!({"address":address}),
                        ),
                        &packet.packets,
                        packet.timestamp_ms,
                        &mut batch.alerts,
                    )?;
                }
            }
            if let Some(device) = self.devices.get_mut(&address) {
                device.last_ms = device.last_ms.max(packet.timestamp_ms);
                device.packets += 1;
            }
        }
        let key = FlowKey::packet(packet);
        let bare_syn =
            packet.protocol == 6 && packet.tcp_flags.is_some_and(|flags| flags & 0x12 == 0x02);
        let new_connection = if packet.protocol == 6 {
            bare_syn
                && self
                    .flows
                    .get(&key)
                    .is_none_or(|flow| flow.syn_sequence != packet.tcp_sequence)
        } else {
            !self.flows.contains_key(&key)
        };
        if bare_syn
            && self.flows.get(&key).is_some_and(|flow| {
                flow.syn_sequence
                    .is_some_and(|sequence| Some(sequence) != packet.tcp_sequence)
            })
        {
            if let Some(flow) = self.flows.remove(&key) {
                self.close_flow(flow, &mut batch.alerts)?;
            }
        }
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= self.options.limits.max_flows {
                self.stats.dropped_flow_packets += 1;
                return Ok(());
            }
            let client = SocketAddr::new(packet.src, packet.src_port);
            let server = SocketAddr::new(packet.dst, packet.dst_port);
            self.flows.insert(
                key.clone(),
                StreamFlow {
                    client,
                    server,
                    protocol: packet.protocol,
                    first_ms: packet.timestamp_ms,
                    last_ms: packet.timestamp_ms,
                    bytes_out: 0,
                    bytes_in: 0,
                    packets_out: 0,
                    packets_in: 0,
                    packets: Vec::new(),
                    refs_truncated: false,
                    server_name: None,
                    ja4: None,
                    process: Vec::new(),
                    syn_sequence: if bare_syn { packet.tcp_sequence } else { None },
                    fin_client: false,
                    fin_server: false,
                },
            );
        }
        if new_connection
            && self.internal(packet.src)
            && !self.internal(packet.dst)
            && self.policy.enabled("TH-0001")
        {
            let beacon_key = (packet.src, packet.dst, packet.dst_port, packet.protocol);
            if self.beacons.contains_key(&beacon_key)
                || self.beacons.len()
                    < self.options.limits.max_beacon_tracks.min(self.policy.count(
                        "beaconing",
                        "max_tracked",
                        50_000,
                    ))
            {
                let track = self
                    .beacons
                    .entry(beacon_key)
                    .or_insert_with(|| BeaconTrack {
                        starts: VecDeque::new(),
                        sizes: VecDeque::new(),
                        packets: Vec::new(),
                        last: packet.timestamp_ms,
                    });
                let position = track
                    .starts
                    .make_contiguous()
                    .binary_search(&packet.timestamp_ms)
                    .unwrap_or_else(|position| position);
                track.starts.insert(position, packet.timestamp_ms);
                track.last = track.last.max(packet.timestamp_ms);
                while track.starts.len() > self.options.limits.max_starts_per_track {
                    track.starts.pop_front();
                    self.stats.dropped_tracking_events += 1;
                }
                for reference in &packet.packets {
                    if track.packets.len() < self.options.limits.max_evidence_packets {
                        track.packets.push(reference.clone());
                    }
                }
            } else {
                self.stats.dropped_tracking_events += 1;
            }
        }
        let mut flow = self.flows.remove(&key).unwrap();
        if bare_syn && flow.syn_sequence.is_none() {
            if flow.client.ip() != packet.src || flow.client.port() != packet.src_port {
                std::mem::swap(&mut flow.client, &mut flow.server);
                std::mem::swap(&mut flow.bytes_out, &mut flow.bytes_in);
                std::mem::swap(&mut flow.packets_out, &mut flow.packets_in);
            }
            flow.syn_sequence = packet.tcp_sequence;
        }
        flow.last_ms = flow.last_ms.max(packet.timestamp_ms);
        if flow.client.ip() == packet.src && flow.client.port() == packet.src_port {
            flow.bytes_out = flow.bytes_out.saturating_add(packet.wire_bytes);
            flow.packets_out += 1;
        } else {
            flow.bytes_in = flow.bytes_in.saturating_add(packet.wire_bytes);
            flow.packets_in += 1;
        }
        let before = self.stats.dropped_evidence_refs;
        self.refs(&mut flow.packets, &packet.packets);
        flow.refs_truncated |= self.stats.dropped_evidence_refs > before;
        if matches!(packet.protocol, 6 | 17) {
            if let Some(snapshot) = &self.processes {
                let associations = snapshot.associate(
                    self.options.local_live,
                    if packet.protocol == 6 {
                        Transport::Tcp
                    } else {
                        Transport::Udp
                    },
                    SocketAddr::new(packet.src, packet.src_port),
                    SocketAddr::new(packet.dst, packet.dst_port),
                    packet.timestamp_ms,
                    2000,
                );
                for association in associations {
                    if flow.process.len() < 8
                        && !flow.process.iter().any(|previous| {
                            previous.process == association.process
                                && previous.endpoint == association.endpoint
                        })
                    {
                        flow.process.push(association.clone());
                    }
                    batch.processes.push(association);
                }
            }
        }
        if packet.protocol == 6 {
            self.scan(packet);
        }
        if packet.tcp_flags.is_some_and(|flags| flags & 0x01 != 0) {
            if flow.client.ip() == packet.src && flow.client.port() == packet.src_port {
                flow.fin_client = true;
            } else {
                flow.fin_server = true;
            }
        }
        if packet.tcp_flags.is_some_and(|flags| flags & 0x04 != 0)
            || (flow.fin_client && flow.fin_server)
        {
            self.close_flow(flow, &mut batch.alerts)?;
        } else {
            self.flows.insert(key, flow);
        }
        Ok(())
    }
    fn scan(&mut self, packet: &DecodedPacket) {
        let flags = packet.tcp_flags.unwrap_or(0);
        if flags & 0x12 == 0x02 {
            if !self.scans.contains_key(&packet.src)
                && self.scans.len()
                    >= self.options.limits.max_scan_sources.min(self.policy.count(
                        "port-scan",
                        "max_tracked",
                        10_000,
                    ))
            {
                self.stats.dropped_tracking_events += 1;
                return;
            }
            let track = self.scans.entry(packet.src).or_default();
            let key = (packet.dst, packet.dst_port);
            if !track.contains_key(&key)
                && (track.len() >= self.options.limits.max_probes_per_source
                    || track.keys().filter(|(host, _)| *host == packet.dst).count()
                        >= self.policy.count("port-scan", "max_ports_per_target", 4096)
                    || track
                        .keys()
                        .filter(|(_, port)| *port == packet.dst_port)
                        .count()
                        >= self.policy.count("port-scan", "max_targets_per_port", 4096))
            {
                self.stats.dropped_tracking_events += 1;
                return;
            }
            let probe = track.entry(key).or_insert_with(|| Probe {
                last: packet.timestamp_ms,
                answered: false,
                packets: packet
                    .packets
                    .iter()
                    .take(self.options.limits.max_evidence_packets.min(4))
                    .cloned()
                    .collect(),
            });
            if packet.timestamp_ms >= probe.last {
                probe.last = packet.timestamp_ms;
                probe.packets = packet
                    .packets
                    .iter()
                    .take(self.options.limits.max_evidence_packets.min(4))
                    .cloned()
                    .collect();
            }
        } else if flags & 0x12 == 0x12 {
            if let Some(probe) = self
                .scans
                .get_mut(&packet.dst)
                .and_then(|track| track.get_mut(&(packet.src, packet.src_port)))
            {
                probe.answered = true;
            }
        }
    }
    fn tls_client(&mut self, observation: &TlsClientObservation, now: u64) {
        for flow in self.flows.values_mut() {
            if flow.client.ip() == observation.src
                && flow.server.ip() == observation.dst
                && flow.client.port() == observation.src_port
                && flow.server.port() == observation.dst_port
            {
                flow.server_name = observation.server_name.clone();
                flow.ja4 = Some(observation.ja4.clone());
            }
        }
        if self.internal(observation.src) && !observation.ja4.is_empty() {
            if let Some(device) = self.devices.get_mut(&observation.src) {
                if device.fingerprints.len() < 32 {
                    device.fingerprints.insert(observation.ja4.clone());
                }
            }
            if self.fingerprints.contains_key(&observation.ja4)
                || self.fingerprints.len() < self.options.limits.max_fingerprints
            {
                let track = self
                    .fingerprints
                    .entry(observation.ja4.clone())
                    .or_insert_with(|| FingerprintTrack {
                        hosts: BTreeSet::new(),
                        first: now,
                        observations: 0,
                        packets: Vec::new(),
                    });
                if track.hosts.len() < 2 {
                    track.hosts.insert(observation.src);
                } else if !track.hosts.contains(&observation.src) {
                    self.stats.fingerprint_user_samples_omitted += 1;
                }
                track.observations += 1;
                for reference in &observation.packets {
                    if track.packets.len() < self.options.limits.max_evidence_packets {
                        track.packets.push(reference.clone());
                    }
                }
            } else {
                self.stats.dropped_tracking_events += 1;
            }
        }
    }
    fn tls(
        &mut self,
        observation: &TlsObservation,
        now: u64,
        out: &mut Vec<Alert>,
    ) -> Result<(), String> {
        if let Some(feed) = &self.feed {
            for hit in feed.detect(std::slice::from_ref(observation))? {
                self.emit(hit, &observation.packets, now, out)?;
            }
        }
        Ok(())
    }
    fn close_flow(&mut self, flow: StreamFlow, out: &mut Vec<Alert>) -> Result<(), String> {
        if self.internal(flow.client.ip()) && !self.internal(flow.server.ip()) {
            if let Some(track) = self.beacons.get_mut(&(
                flow.client.ip(),
                flow.server.ip(),
                flow.server.port(),
                flow.protocol,
            )) {
                if flow.protocol != 6 || flow.syn_sequence.is_some() {
                    track.sizes.push_back(flow.bytes_out as f64);
                }
                while track.sizes.len() > 512 {
                    track.sizes.pop_front();
                }
            }
            let ratio = flow.bytes_out as f64 / flow.bytes_in.max(1) as f64;
            if self.policy.enabled("TH-0005")
                && flow.bytes_out
                    >= self
                        .policy
                        .number("exfiltration", "min_bytes_out", 10_485_760.0)
                        as u64
                && ratio >= self.policy.number("exfiltration", "min_ratio", 20.0)
            {
                self.emit(alert("TH-0005",if flow.bytes_out>=104_857_600{Severity::High}else{Severity::Medium},flow.client.ip(),Some(flow.server.ip()),flow.server.port(),"Large outbound data transfer",json!({"bytes_out":flow.bytes_out,"bytes_in":flow.bytes_in,"ratio":round3(ratio),"duration_s":flow.last_ms.saturating_sub(flow.first_ms) as f64/1000.0,"server_name":flow.server_name,"ja4":flow.ja4,"packets_out":flow.packets_out,"dest_port":flow.server.port()})),&flow.packets,flow.last_ms,out)?;
            }
        }
        Ok(())
    }
    fn tick_into(&mut self, now: u64, out: &mut Vec<Alert>) -> Result<(), String> {
        let dns = self.dns.as_mut().unwrap().tick(now);
        for hit in dns {
            self.emit(hit, &[], now, out)?;
        }
        let expired = self
            .flows
            .iter()
            .filter_map(|(key, flow)| {
                (now.saturating_sub(flow.last_ms) >= self.options.limits.flow_idle_ms)
                    .then_some(key.clone())
            })
            .collect::<Vec<_>>();
        for key in expired {
            let flow = self.flows.remove(&key).unwrap();
            self.close_flow(flow, out)?;
        }
        let cutoff = now.saturating_sub(self.policy.duration("beaconing", "history", 21_600_000));
        let mut hits = Vec::new();
        self.beacons.retain(|_, track| {
            while track.starts.front().is_some_and(|at| *at < cutoff) {
                track.starts.pop_front();
            }
            track
                .packets
                .retain(|reference| reference.timestamp_ns / 1_000_000 >= cutoff);
            track.last >= cutoff
        });
        for ((src, dst, port, _), track) in &self.beacons {
            if track.starts.len() < self.policy.count("beaconing", "min_connections", 8) {
                continue;
            }
            let starts = track.starts.iter().copied().collect::<Vec<_>>();
            let intervals = starts
                .windows(2)
                .filter(|pair| pair[1] > pair[0])
                .map(|pair| (pair[1] - pair[0]) as f64 / 1000.0)
                .collect::<Vec<_>>();
            if intervals.is_empty() {
                continue;
            }
            let mean = average(&intervals);
            if mean * 1000.0 < self.policy.duration("beaconing", "min_interval", 2000) as f64
                || mean * 1000.0
                    > self
                        .policy
                        .duration("beaconing", "max_interval", 21_600_000)
                        as f64
            {
                continue;
            }
            let cv = coefficient(&intervals);
            let med = median(&intervals);
            let mad = if med > 0.0 {
                median(
                    &intervals
                        .iter()
                        .map(|value| (value - med).abs())
                        .collect::<Vec<_>>(),
                ) / med
            } else {
                0.0
            };
            let periodicity = 1.0 - cv.min(mad).clamp(0.0, 1.0);
            let sizes = track.sizes.iter().copied().collect::<Vec<_>>();
            let size_score = if sizes.len() >= 3 {
                1.0 - coefficient(&sizes).clamp(0.0, 1.0)
            } else {
                0.5
            };
            let score = 0.75 * periodicity + 0.25 * size_score;
            if score < self.policy.number("beaconing", "threshold", 0.75) {
                continue;
            }
            hits.push((alert("TH-0001",if score>=0.9&&starts.len()>=20{Severity::High}else{Severity::Medium},*src,Some(*dst),*port,"Periodic outbound beaconing",json!({"connections":starts.len(),"interval_mean_s":round3(mean),"interval_cv":round3(cv),"interval_mad_ratio":round3(mad),"jitter_pct":round3(cv*100.0),"periodicity_score":round3(periodicity),"size_consistency":round3(size_score),"mean_bytes_to_server":round3(average(&sizes))})),track.packets.clone()));
        }
        let cutoff = now.saturating_sub(self.policy.duration("port-scan", "window", 300_000));
        self.scans.retain(|_, track| {
            track.retain(|_, probe| probe.last >= cutoff);
            !track.is_empty()
        });
        self.scan_vertical_reported
            .retain(|source| self.scans.contains_key(source));
        self.scan_horizontal_reported
            .retain(|source| self.scans.contains_key(source));
        for (source, track) in &self.scans {
            let answered = track.values().filter(|probe| probe.answered).count();
            let scan_like = answered as f64 / track.len() as f64
                <= self.policy.number("port-scan", "max_answered_ratio", 0.5);
            let mut targets = BTreeMap::<IpAddr, usize>::new();
            let mut ports = BTreeMap::<u16, usize>::new();
            for (target, port) in track.keys() {
                *targets.entry(*target).or_default() += 1;
                *ports.entry(*port).or_default() += 1;
            }
            let vertical = self.policy.count("port-scan", "vertical_ports", 20);
            let horizontal = self.policy.count("port-scan", "horizontal_hosts", 25);
            if targets.values().copied().max().unwrap_or(0) < vertical {
                self.scan_vertical_reported.remove(source);
            }
            if ports.values().copied().max().unwrap_or(0) < horizontal {
                self.scan_horizontal_reported.remove(source);
            }
            let first = track.values().map(|probe| probe.last).min().unwrap_or(now);
            let last = track.values().map(|probe| probe.last).max().unwrap_or(now);
            let references = track
                .values()
                .flat_map(|probe| probe.packets.iter().cloned())
                .take(self.options.limits.max_evidence_packets)
                .collect::<Vec<_>>();
            if let Some((target, count)) = targets.iter().max_by_key(|(_, count)| *count) {
                if self.policy.enabled("TH-0003")
                    && *count >= vertical
                    && scan_like
                    && !self.scan_vertical_reported.contains(source)
                {
                    hits.push((alert("TH-0003",if *count>=100{Severity::High}else{Severity::Medium},*source,Some(*target),0,"Vertical port scan",json!({"scan_type":"vertical","target":target,"ports_probed":count,"open_ports":answered,"answered_pct":round3(100.0*answered as f64/track.len()as f64),"window_start_ms":first,"window_end_ms":last})),references.clone()));
                    self.scan_vertical_reported.insert(*source);
                }
            }
            if let Some((port, count)) = ports.iter().max_by_key(|(_, count)| *count) {
                if self.policy.enabled("TH-0004")
                    && *count >= horizontal
                    && scan_like
                    && !self.scan_horizontal_reported.contains(source)
                {
                    hits.push((alert("TH-0004",if *count>=100{Severity::High}else{Severity::Medium},*source,None,*port,"Horizontal network sweep",json!({"scan_type":"horizontal","port":port,"hosts_probed":count,"responded":answered,"answered_pct":round3(100.0*answered as f64/track.len()as f64),"window_start_ms":first,"window_end_ms":last})),references));
                    self.scan_horizontal_reported.insert(*source);
                }
            }
        }
        if self.policy.enabled("TH-0007")
            && self.devices.len() >= self.policy.count("inventory", "min_hosts_for_rarity", 5)
            && self.fingerprints.len()
                >= self
                    .policy
                    .count("inventory", "min_fingerprints_for_rarity", 3)
            && self
                .fingerprints
                .values()
                .filter(|track| track.hosts.len() >= 2)
                .count()
                >= self.policy.count("inventory", "min_shared_fingerprints", 2)
        {
            for (fingerprint, track) in &self.fingerprints {
                if track.hosts.len() == 1
                    && track.observations
                        >= self.policy.count("inventory", "min_observations", 3) as u64
                    && now.saturating_sub(track.first)
                        >= self.policy.duration("inventory", "min_age", 600_000)
                {
                    hits.push((alert("TH-0007",Severity::Medium,*track.hosts.first().unwrap(),None,0,"Rare TLS fingerprint",json!({"ja4":fingerprint,"hosts":1,"observations":track.observations,"age_s":now.saturating_sub(track.first)/1000})),track.packets.clone()));
                }
            }
        }
        if self.policy.enabled("TH-0009") {
            for flow in self.flows.values() {
                if now.saturating_sub(flow.first_ms)
                    >= self
                        .policy
                        .duration("long-connection", "min_duration", 3_600_000)
                    && flow.bytes_out.saturating_add(flow.bytes_in)
                        >= self.policy.number("long-connection", "min_bytes", 1.0) as u64
                {
                    hits.push((alert("TH-0009",Severity::Low,flow.client.ip(),Some(flow.server.ip()),flow.server.port(),"Long-lived connection",json!({"duration_s":now.saturating_sub(flow.first_ms)/1000,"bytes_out":flow.bytes_out,"bytes_in":flow.bytes_in,"server_name":flow.server_name})),flow.packets.clone()));
                }
            }
        }
        for (hit, references) in hits {
            self.emit(hit, &references, now, out)?;
        }
        Ok(())
    }
    pub fn tick(&mut self, now_ms: u64) -> Result<StreamBatch, String> {
        let mut batch = StreamBatch::default();
        self.tick_into(now_ms, &mut batch.alerts)?;
        batch.diagnostics = self.diagnostics.clone();
        Ok(batch)
    }
    pub fn finish(mut self) -> Result<StreamSummary, String> {
        let mut alerts = Vec::new();
        let now = self.stats.last_timestamp_ms.unwrap_or(0);
        self.tick_into(now, &mut alerts)?;
        let flows = std::mem::take(&mut self.flows);
        for (_, flow) in flows {
            self.close_flow(flow, &mut alerts)?;
        }
        let mut dns = self.dns.take().unwrap();
        let final_dns = dns.flush();
        self.stats.dropped_dns_name_events = dns.dropped_name_events;
        self.stats.uncertainty_limited_dns_scores = dns.uncertainty_limited_scores;
        self.stats.dropped_tracking_events = self
            .stats
            .dropped_tracking_events
            .saturating_add(dns.dropped_track_events);
        for hit in final_dns {
            self.emit(hit, &[], now, &mut alerts)?;
        }
        let stats = self.stats();
        let analysis_meta = self.analysis_meta();
        let finalized = self.decoder.finish().diagnostics;
        let mut diagnostics = self.diagnostics;
        diagnostics.truncated_packets = diagnostics
            .truncated_packets
            .max(finalized.truncated_packets);
        diagnostics.malformed_transport_packets = diagnostics
            .malformed_transport_packets
            .max(finalized.malformed_transport_packets);
        diagnostics.discarded_fragment_sets = diagnostics
            .discarded_fragment_sets
            .max(finalized.discarded_fragment_sets);
        diagnostics.discarded_tcp_streams = diagnostics
            .discarded_tcp_streams
            .max(finalized.discarded_tcp_streams);
        diagnostics.untracked_flow_packets = diagnostics
            .untracked_flow_packets
            .max(finalized.untracked_flow_packets);
        diagnostics.packet_references_dropped = diagnostics
            .packet_references_dropped
            .max(finalized.packet_references_dropped);
        Ok(StreamSummary{schema_version:1,mode:"streaming_analysis".into(),report:self.accumulator.finish(),stats,diagnostics,analysis_meta,policy_notes:vec!["Rust replacement packs enable only listed rule IDs; Go permits unlisted emitted IDs.".into(),"Hard stream limits may reduce retained evidence; inspect dropped counters.".into(),"TH-0009 long-connection is opt-in; it has no built-in enabled rule.".into()]})
    }
}
fn alert(
    id: &str,
    severity: Severity,
    source: IpAddr,
    destination: Option<IpAddr>,
    port: u16,
    title: &str,
    evidence: Value,
) -> Alert {
    Alert {
        rule_id: id.into(),
        severity,
        src: Some(source),
        dst: destination,
        title: title.into(),
        time: None,
        description: Some(title.into()),
        score: None,
        evidence,
        extra: BTreeMap::from([("dst_port".into(), json!(port))]),
    }
}
fn average(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}
fn coefficient(values: &[f64]) -> f64 {
    let mean = average(values);
    if mean == 0.0 {
        0.0
    } else {
        (values
            .iter()
            .map(|value| (value - mean).powi(2))
            .sum::<f64>()
            / values.len().max(1) as f64)
            .sqrt()
            / mean
    }
}
fn median(values: &[f64]) -> f64 {
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    if ordered.is_empty() {
        0.0
    } else if ordered.len().is_multiple_of(2) {
        (ordered[ordered.len() / 2 - 1] + ordered[ordered.len() / 2]) / 2.0
    } else {
        ordered[ordered.len() / 2]
    }
}
fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

/// Incrementally read classic PCAP, the format requested from dumpcap stdout.
/// The caller owns cancellation of a blocked pipe by stopping its capture child.
/// No complete-file buffering or Go subprocess is involved.
pub fn read_pcap_stream(
    reader: &mut dyn Read,
    analyzer: &mut StreamingAnalyzer,
    cancelled: &dyn Fn() -> bool,
    emit: &mut dyn FnMut(StreamBatch) -> Result<(), String>,
) -> Result<(), String> {
    read_records(reader, cancelled, None, None, &mut |reference, data| {
        emit(analyzer.push_packet(reference, data)?)
    })
    .map(|_| ())
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum RecordEnd {
    Eof,
    SizeLimit,
}
type PacketConsumer<'a> = dyn FnMut(PacketRef, &[u8]) -> Result<(), String> + 'a;
fn read_records(
    reader: &mut dyn Read,
    cancelled: &dyn Fn() -> bool,
    mut recording: Option<(&mut dyn Write, u64)>,
    recorded_bytes: Option<&std::sync::atomic::AtomicU64>,
    emit: &mut PacketConsumer<'_>,
) -> Result<RecordEnd, String> {
    let mut header = [0u8; 24];
    reader
        .read_exact(&mut header)
        .map_err(|e| format!("Read live PCAP header: {e}"))?;
    let (little, nano) = match &header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err("Live helper must emit classic PCAP (-F pcap -w -).".into()),
    };
    let word = |bytes: &[u8]| {
        if little {
            u32::from_le_bytes(bytes.try_into().unwrap())
        } else {
            u32::from_be_bytes(bytes.try_into().unwrap())
        }
    };
    let short = |bytes: &[u8]| {
        if little {
            u16::from_le_bytes(bytes.try_into().unwrap())
        } else {
            u16::from_be_bytes(bytes.try_into().unwrap())
        }
    };
    if short(&header[4..6]) != 2 || short(&header[6..8]) != 4 {
        return Err("Unsupported live PCAP version.".into());
    }
    let snap = word(&header[16..20]);
    if snap == 0 || snap > 1_048_576 {
        return Err("Live PCAP snapshot length exceeds 1 MiB.".into());
    }
    let link = word(&header[20..24]) & 0xffff;
    if let Some((writer, _)) = &mut recording {
        writer
            .write_all(&header)
            .map_err(|e| format!("Write live capture header: {e}"))?;
    }
    if let Some(bytes) = recorded_bytes {
        bytes.store(24, std::sync::atomic::Ordering::Relaxed);
    }
    let mut offset = 24u64;
    let mut number = 0;
    loop {
        if cancelled() {
            return Err("Live stream cancelled.".into());
        }
        let mut record = [0u8; 16];
        let first = loop {
            match reader.read(&mut record[..1]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result,
            }
        }
        .map_err(|e| e.to_string())?;
        if first == 0 {
            return Ok(RecordEnd::Eof);
        }
        reader
            .read_exact(&mut record[1..])
            .map_err(|e| format!("Truncated live PCAP record: {e}"))?;
        let seconds = word(&record[..4]);
        let fraction = word(&record[4..8]);
        let captured = word(&record[8..12]);
        let original = word(&record[12..16]);
        if captured > snap
            || original < captured
            || fraction >= if nano { 1_000_000_000 } else { 1_000_000 }
        {
            return Err("Invalid live PCAP record lengths/timestamp.".into());
        }
        if recording
            .as_ref()
            .is_some_and(|(_, limit)| offset.saturating_add(16 + u64::from(captured)) > *limit)
        {
            return Ok(RecordEnd::SizeLimit);
        }
        let mut data = vec![0; captured as usize];
        reader
            .read_exact(&mut data)
            .map_err(|e| format!("Truncated live packet: {e}"))?;
        if let Some((writer, _)) = &mut recording {
            writer
                .write_all(&record)
                .and_then(|()| writer.write_all(&data))
                .map_err(|e| format!("Write live capture: {e}"))?;
        }
        number += 1;
        let reference = PacketRef {
            number,
            section: 0,
            interface: 0,
            link_type: link,
            timestamp_ns: u64::from(seconds) * 1_000_000_000
                + u64::from(fraction) * if nano { 1 } else { 1000 },
            data_offset: offset + 16,
            captured_len: captured,
            original_len: original,
        };
        offset = offset
            .checked_add(16 + u64::from(captured))
            .ok_or("Live PCAP byte offset overflow.")?;
        if let Some(bytes) = recorded_bytes {
            bytes.store(offset, std::sync::atomic::Ordering::Relaxed);
        }
        emit(reference, &data)?;
    }
}

#[derive(Clone, Debug)]
pub struct RustLiveOptions {
    pub capture_tool: PathBuf,
    pub interface: String,
    pub filter: Option<String>,
    pub promiscuous: bool,
    pub recording_limits: crate::live::RecordingLimits,
    pub analysis: StreamOptions,
    pub process_attribution: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RustLiveState {
    Starting,
    Running,
    Stopping,
    Completed,
    Cancelled,
    Failed,
}
impl RustLiveState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct RustLiveSnapshot {
    pub state: RustLiveState,
    pub interface: String,
    pub elapsed_ms: u64,
    pub capture_bytes: u64,
    pub stats: StreamStats,
    #[serde(serialize_with = "serialize_arc")]
    pub findings: std::sync::Arc<Vec<Alert>>,
    #[serde(serialize_with = "serialize_arc")]
    pub devices: std::sync::Arc<Vec<StreamDevice>>,
    #[serde(serialize_with = "serialize_arc")]
    pub flows: std::sync::Arc<Vec<StreamFlow>>,
    pub diagnostics: CaptureDiagnostics,
    pub process_status: String,
    pub warnings: Vec<String>,
    pub error: Option<String>,
    pub analysis_meta: Value,
    pub earlier_alert_records: u64,
    pub snapshot_entry_limit: usize,
}
fn serialize_arc<T: Serialize, S: serde::Serializer>(
    value: &std::sync::Arc<T>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.as_ref().serialize(serializer)
}
type LiveOutcome = Result<std::sync::Arc<StreamSummary>, String>;
struct LiveData {
    snapshot: RustLiveSnapshot,
    result: Option<LiveOutcome>,
}
struct LiveShared {
    data: std::sync::Mutex<LiveData>,
    done: std::sync::Condvar,
    stop: std::sync::atomic::AtomicBool,
    cancel: std::sync::atomic::AtomicBool,
    bytes: std::sync::atomic::AtomicU64,
    started: std::time::Instant,
}
struct LiveCapture {
    directory: PathBuf,
    path: PathBuf,
    parent: PathBuf,
}
impl LiveCapture {
    fn new() -> Result<Self, String> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = fs::canonicalize(std::env::temp_dir()).map_err(|e| e.to_string())?;
        for _ in 0..10 {
            let directory = parent.join(format!(
                "tracehound-rust-live-{}-{}-{}",
                std::process::id(),
                wall_ms(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            let mut builder = builder;
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&directory) {
                Ok(()) => {
                    return Ok(Self {
                        path: directory.join("capture.pcap"),
                        directory,
                        parent,
                    })
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("Create private live capture: {error}")),
            }
        }
        Err("Could not allocate a private live capture.".into())
    }
}
impl Drop for LiveCapture {
    fn drop(&mut self) {
        if fs::canonicalize(&self.directory)
            .ok()
            .as_deref()
            .and_then(Path::parent)
            == Some(self.parent.as_path())
        {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_dir(&self.directory);
        }
    }
}
pub struct RustLiveSession {
    shared: std::sync::Arc<LiveShared>,
    capture: std::sync::Arc<LiveCapture>,
}
impl RustLiveSession {
    pub fn start(mut options: RustLiveOptions) -> Result<Self, String> {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::AtomicU64;
        use std::sync::{Arc, Condvar, Mutex};
        if options.interface.trim().is_empty()
            || options.interface.len() > 4096
            || options.interface.chars().any(char::is_control)
        {
            return Err("Choose a valid live capture interface.".into());
        }
        if options
            .filter
            .as_ref()
            .is_some_and(|filter| filter.len() > 8192 || filter.contains('\0'))
        {
            return Err("Live BPF filter exceeds 8192 bytes or contains NUL.".into());
        }
        if !(1..=4096).contains(&options.recording_limits.max_mebibytes)
            || !(1..=86_400).contains(&options.recording_limits.max_seconds)
        {
            return Err("Live recording bounds must be 1–4096 MiB and 1–86400 seconds.".into());
        }
        options.analysis.local_live = true;
        let analyzer = StreamingAnalyzer::new(options.analysis.clone())?;
        let capture = Arc::new(LiveCapture::new()?);
        let snapshot = RustLiveSnapshot {
            state: RustLiveState::Starting,
            interface: options.interface.clone(),
            elapsed_ms: 0,
            capture_bytes: 0,
            stats: StreamStats::default(),
            findings: Arc::new(Vec::new()),
            devices: Arc::new(Vec::new()),
            flows: Arc::new(Vec::new()),
            diagnostics: CaptureDiagnostics::default(),
            process_status: if !options.process_attribution {
                "disabled"
            } else if cfg!(windows) {
                "sampling Windows endpoint owners"
            } else {
                "unavailable: process attribution requires Windows"
            }
            .into(),
            warnings: Vec::new(),
            error: None,
            analysis_meta: analyzer.analysis_meta(),
            earlier_alert_records: 0,
            snapshot_entry_limit: 1000,
        };
        let shared = Arc::new(LiveShared {
            data: Mutex::new(LiveData {
                snapshot,
                result: None,
            }),
            done: Condvar::new(),
            stop: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            bytes: AtomicU64::new(0),
            started: std::time::Instant::now(),
        });
        let worker = Arc::clone(&shared);
        let retained = Arc::clone(&capture);
        std::thread::Builder::new()
            .name("rust-live-session".into())
            .spawn(move || {
                let result = run_live(options, analyzer, &worker, &retained);
                // Terminal state must not be published while a worker still
                // owns the temporary capture. Session drop then cleans it
                // synchronously, including immediate application shutdown.
                drop(retained);
                let mut data = live_lock(&worker.data);
                let cancelled = worker.cancel.load(std::sync::atomic::Ordering::Acquire);
                let result = if cancelled {
                    Err("Live capture cancelled.".into())
                } else {
                    result.map(Arc::new)
                };
                data.snapshot.state = if cancelled {
                    RustLiveState::Cancelled
                } else if result.is_ok() {
                    RustLiveState::Completed
                } else {
                    RustLiveState::Failed
                };
                data.snapshot.error = if cancelled {
                    None
                } else {
                    result.as_ref().err().cloned()
                };
                data.snapshot.elapsed_ms = elapsed_ms(worker.started);
                data.snapshot.capture_bytes =
                    worker.bytes.load(std::sync::atomic::Ordering::Relaxed);
                if let Ok(summary) = &result {
                    data.snapshot.stats = summary.stats.clone();
                    data.snapshot.diagnostics = summary.diagnostics.clone();
                    data.snapshot.findings = Arc::new(
                        summary
                            .report
                            .findings
                            .iter()
                            .rev()
                            .take(1000)
                            .map(|finding| finding.alert.clone())
                            .collect(),
                    );
                }
                data.result = Some(result);
                drop(data);
                worker.done.notify_all();
            })
            .map_err(|e| format!("Start Rust live worker: {e}"))?;
        Ok(Self { shared, capture })
    }
    pub fn snapshot(&self) -> RustLiveSnapshot {
        let mut snapshot = live_lock(&self.shared.data).snapshot.clone();
        if !snapshot.state.is_terminal() {
            snapshot.elapsed_ms = elapsed_ms(self.shared.started);
            snapshot.capture_bytes = self.shared.bytes.load(std::sync::atomic::Ordering::Relaxed);
        }
        snapshot
    }
    pub fn stop(&self) -> bool {
        let mut data = live_lock(&self.shared.data);
        if data.snapshot.state.is_terminal() {
            return false;
        }
        self.shared
            .stop
            .store(true, std::sync::atomic::Ordering::Release);
        data.snapshot.state = RustLiveState::Stopping;
        true
    }
    pub fn cancel(&self) -> bool {
        let mut data = live_lock(&self.shared.data);
        if data.snapshot.state.is_terminal() {
            return false;
        }
        self.shared
            .cancel
            .store(true, std::sync::atomic::Ordering::Release);
        self.shared
            .stop
            .store(true, std::sync::atomic::Ordering::Release);
        data.snapshot.state = RustLiveState::Stopping;
        true
    }
    pub fn finished(&self) -> bool {
        live_lock(&self.shared.data).result.is_some()
    }
    pub fn try_result(&self) -> Option<LiveOutcome> {
        live_lock(&self.shared.data).result.clone()
    }
    pub fn wait(&self) -> LiveOutcome {
        let mut data = live_lock(&self.shared.data);
        loop {
            if let Some(result) = &data.result {
                return result.clone();
            }
            data = self
                .shared
                .done
                .wait(data)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
    pub fn retained_capture_path(&self) -> Option<PathBuf> {
        (self.snapshot().state == RustLiveState::Completed).then(|| self.capture.path.clone())
    }
    pub fn save_capture(&self, destination: &Path) -> Result<(), String> {
        if self.snapshot().state != RustLiveState::Completed {
            return Err("Finish the live capture before saving its PCAP.".into());
        }
        let mut source = fs::File::open(&self.capture.path).map_err(|e| e.to_string())?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(destination)
            .map_err(|e| format!("Create saved capture {}: {e}", destination.display()))?;
        io::copy(&mut source, &mut output)
            .and_then(|_| output.sync_all())
            .map_err(|e| e.to_string())
    }
}
impl Drop for RustLiveSession {
    fn drop(&mut self) {
        self.cancel();
    }
}
fn live_lock<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn elapsed_ms(started: std::time::Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
fn live_batch(shared: &LiveShared, batch: StreamBatch) {
    let mut data = live_lock(&shared.data);
    if !batch.alerts.is_empty() {
        let mut recent = data.snapshot.findings.as_ref().clone();
        recent.extend(batch.alerts);
        let excess = recent.len().saturating_sub(1000);
        if excess > 0 {
            recent.drain(..excess);
            data.snapshot.earlier_alert_records += excess as u64;
        }
        data.snapshot.findings = std::sync::Arc::new(recent);
    }
    data.snapshot.diagnostics = batch.diagnostics;
    for warning in batch.warnings {
        if data.snapshot.warnings.len() < 32 && !data.snapshot.warnings.contains(&warning) {
            data.snapshot.warnings.push(warning);
        }
    }
}
fn run_live(
    options: RustLiveOptions,
    analyzer: StreamingAnalyzer,
    shared: &std::sync::Arc<LiveShared>,
    capture: &std::sync::Arc<LiveCapture>,
) -> Result<StreamSummary, String> {
    use std::process::{Command, Stdio};
    use std::sync::atomic::Ordering;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;
    let analyzer = Arc::new(Mutex::new(analyzer));
    if options.process_attribution && cfg!(windows) {
        match crate::process::snapshot() {
            Ok(snapshot) => {
                live_lock(&analyzer).set_process_snapshot(snapshot)?;
            }
            Err(error) => {
                live_lock(&shared.data).snapshot.process_status = format!("unavailable: {error}");
            }
        }
    }
    let mut command = Command::new(&options.capture_tool);
    command
        .arg("-i")
        .arg(&options.interface)
        .args(["-q", "-F", "pcap", "-s", "262144", "-w", "-"])
        .arg("-a")
        .arg(format!("duration:{}", options.recording_limits.max_seconds));
    if !options.promiscuous {
        command.arg("-p");
    }
    if let Some(filter) = &options.filter {
        command.arg("-f").arg(filter);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child=LiveChild{child:command.spawn().map_err(|e|format!("Start capture helper {}: {e}. Use an existing dumpcap installation and capture permissions.",options.capture_tool.display()))?,parser:None,stderr:None};
    let stdout = child
        .child
        .stdout
        .take()
        .ok_or("Capture helper has no stdout pipe.")?;
    let stderr = child
        .child
        .stderr
        .take()
        .ok_or("Capture helper has no stderr pipe.")?;
    child.stderr = Some(
        std::thread::Builder::new()
            .name("rust-live-stderr".into())
            .spawn(move || {
                let mut reader = stderr;
                let mut output = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match reader.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let retained = n.min(16_384usize.saturating_sub(output.len()));
                            output.extend_from_slice(&chunk[..retained]);
                        }
                    }
                }
                String::from_utf8_lossy(&output).trim().to_string()
            })
            .map_err(|e| e.to_string())?,
    );
    let parser_analyzer = Arc::clone(&analyzer);
    let parser_shared = Arc::clone(shared);
    let path = capture.path.clone();
    let maximum = u64::from(options.recording_limits.max_mebibytes) * 1_048_576;
    let (tx, rx) = mpsc::channel();
    child.parser = Some(
        std::thread::Builder::new()
            .name("rust-live-packets".into())
            .spawn(move || {
                let outcome = (|| {
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .map_err(|e| format!("Create retained capture: {e}"))?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        file.set_permissions(fs::Permissions::from_mode(0o600))
                            .map_err(|e| e.to_string())?;
                    }
                    let mut reader = io::BufReader::new(stdout);
                    let result = read_records(
                        &mut reader,
                        &|| parser_shared.cancel.load(Ordering::Acquire),
                        Some((&mut file, maximum)),
                        Some(&parser_shared.bytes),
                        &mut |reference, data| {
                            let batch = live_lock(&parser_analyzer).push_packet(reference, data)?;
                            live_batch(&parser_shared, batch);
                            Ok(())
                        },
                    );
                    file.sync_all().map_err(|e| e.to_string())?;
                    result
                })();
                let _ = tx.send(outcome);
            })
            .map_err(|e| e.to_string())?,
    );
    {
        let mut data = live_lock(&shared.data);
        data.snapshot.state = RustLiveState::Running;
    }
    let mut read_result = None;
    let mut duration_limit = false;
    let mut next_snapshot = std::time::Instant::now();
    let mut next_process = next_snapshot + Duration::from_secs(1);
    let final_status = loop {
        match rx.try_recv() {
            Ok(result) => read_result = Some(result),
            Err(mpsc::TryRecvError::Disconnected) if read_result.is_none() => {
                read_result = Some(Err("Live packet reader stopped unexpectedly.".into()))
            }
            _ => {}
        }
        let status = child.try_wait().map_err(|e| e.to_string())?;
        if let Some(status) = status {
            break status;
        }
        duration_limit =
            shared.started.elapsed().as_secs() >= u64::from(options.recording_limits.max_seconds);
        if shared.stop.load(Ordering::Acquire) || read_result.is_some() || duration_limit {
            break stop_live_child(&mut child)?;
        }
        if std::time::Instant::now() >= next_snapshot {
            let batch = live_lock(&analyzer).tick(wall_ms());
            match batch {
                Ok(batch) => live_batch(shared, batch),
                Err(error) => {
                    read_result = Some(Err(error));
                    continue;
                }
            }
            let core = live_lock(&analyzer);
            let stats = core.stats();
            let devices = Arc::new(core.devices().take(1000).cloned().collect());
            let flows = Arc::new(core.flows().take(1000).cloned().collect());
            drop(core);
            let mut data = live_lock(&shared.data);
            data.snapshot.stats = stats;
            data.snapshot.devices = devices;
            data.snapshot.flows = flows;
            next_snapshot = std::time::Instant::now() + Duration::from_millis(500);
        }
        if options.process_attribution && cfg!(windows) && std::time::Instant::now() >= next_process
        {
            match crate::process::snapshot() {
                Ok(snapshot) => {
                    let warnings = snapshot.warnings.clone();
                    live_lock(&analyzer).set_process_snapshot(snapshot)?;
                    let mut data = live_lock(&shared.data);
                    data.snapshot.process_status =
                        "Windows endpoint owner snapshots (sampled associations)".into();
                    for warning in warnings {
                        if data.snapshot.warnings.len() < 32
                            && !data.snapshot.warnings.contains(&warning)
                        {
                            data.snapshot.warnings.push(warning);
                        }
                    }
                }
                Err(error) => {
                    live_lock(&shared.data).snapshot.process_status =
                        format!("unavailable: {error}")
                }
            };
            next_process = std::time::Instant::now() + Duration::from_secs(1);
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    child
        .parser
        .take()
        .unwrap()
        .join()
        .map_err(|_| "Live packet reader panicked.".to_string())?;
    let stderr = child
        .stderr
        .take()
        .unwrap()
        .join()
        .map_err(|_| "Live helper diagnostic reader panicked.".to_string())?;
    if read_result.is_none() {
        read_result = Some(rx.recv().map_err(|e| e.to_string())?);
    }
    if shared.cancel.load(Ordering::Acquire) {
        return Err("Live capture cancelled.".into());
    }
    let read_result = read_result.unwrap();
    let bounded = matches!(read_result, Ok(RecordEnd::SizeLimit));
    if let Err(error) = read_result {
        if (shared.stop.load(Ordering::Acquire) || duration_limit)
            && error.starts_with("Truncated live")
        {
            live_lock(&shared.data).snapshot.warnings.push("Capture stopped during a packet write; the retained PCAP ends at the previous complete packet.".into());
        } else {
            return Err(if stderr.is_empty() {
                error
            } else {
                format!("{error}; capture helper: {stderr}")
            });
        }
    }
    if !final_status.success()
        && !shared.stop.load(Ordering::Acquire)
        && !bounded
        && !duration_limit
    {
        return Err(format!("Capture helper exited unsuccessfully: {stderr}"));
    }
    if bounded {
        live_lock(&shared.data).snapshot.warnings.push(
            "Recording size bound reached; capture ended on a complete packet boundary.".into(),
        );
    }
    let analyzer = Arc::try_unwrap(analyzer)
        .map_err(|_| "Live analysis still has an active reader.".to_string())?
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    analyzer.finish()
}
struct LiveChild {
    child: std::process::Child,
    parser: Option<std::thread::JoinHandle<()>>,
    stderr: Option<std::thread::JoinHandle<String>>,
}
impl std::ops::Deref for LiveChild {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.child
    }
}
impl std::ops::DerefMut for LiveChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}
impl Drop for LiveChild {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(parser) = self.parser.take() {
            let _ = parser.join();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
    }
}
fn stop_live_child(child: &mut std::process::Child) -> Result<std::process::ExitStatus, String> {
    if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
        return Ok(status);
    }
    #[cfg(unix)]
    {
        let pid = libc::pid_t::try_from(child.id()).map_err(|e| e.to_string())?;
        unsafe {
            libc::kill(pid, libc::SIGINT);
        }
    }
    #[cfg(windows)]
    {
        let _ = child.kill();
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(status);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            return child.wait().map_err(|e| e.to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}
