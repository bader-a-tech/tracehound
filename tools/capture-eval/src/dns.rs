//! Passive DNS tunnel scoring with the full Mozilla Public Suffix List bundled
//! by the pinned `psl` crate. Rules retain the project's YAML policy format.
//! Home-network filtering belongs to the caller. Only captured UDP DNS queries
//! supplied by the capture reader are scored; no names are resolved online.

use crate::{
    capture::{DnsObservation, PacketRef},
    Alert, Severity,
};
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

const MAX_INPUT: usize = 50_000;
const MAX_TRACKS: usize = 20_000;
const MAX_NAMES: usize = 65_536;
const DEFAULT_NAMES: usize = 2_000;
/// Global backstop in addition to each rule's per-domain name limit.
pub const MAX_GLOBAL_NAMES: usize = 65_536;
const SCORE_INTERVAL: u64 = 30_000;
const COOLDOWN: u64 = 600_000;

#[derive(Clone, Debug)]
pub struct DnsPolicy {
    pub enabled: bool,
    severity: Option<Severity>,
    techniques: Vec<Technique>,
    min_queries: usize,
    threshold: f64,
    history_ms: u64,
    max_tracked: usize,
    max_unique: usize,
    exceptions: Vec<Exception>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Technique {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    tactic: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    name: String,
    detector: String,
    enabled: Option<bool>,
    severity: Option<Severity>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    techniques: Vec<Technique>,
    tuning: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    exceptions: Vec<Exception>,
}

#[derive(Default, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Tuning {
    min_queries: usize,
    threshold: f64,
    history: Option<String>,
    max_tracked: usize,
    max_unique_names: usize,
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
    #[serde(skip)]
    source_net: Option<IpNet>,
    #[serde(skip)]
    destination_net: Option<IpNet>,
}

impl Exception {
    fn compile(&mut self) -> Result<(), String> {
        if self.description.trim().is_empty() {
            return Err("DNS exception needs a description".into());
        }
        if self.src.is_empty()
            && self.dst.is_empty()
            && self.dst_port == 0
            && self.domain.is_empty()
            && self.ja4.is_empty()
        {
            return Err("DNS exception matches everything; provide a match field".into());
        }
        self.source_net = prefix(&self.src)?;
        self.destination_net = prefix(&self.dst)?;
        self.domain = self
            .domain
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if self.source_net.is_none()
            && self.destination_net.is_none()
            && self.dst_port == 0
            && self.domain.is_empty()
            && self.ja4.is_empty()
        {
            return Err("DNS exception domain must contain a name".into());
        }
        Ok(())
    }
    fn matches(&self, query: &DnsObservation, name: &str) -> bool {
        self.source_net.is_none_or(|net| net.contains(&unmap(query.src)))
            && self.destination_net.is_none_or(|net| net.contains(&unmap(query.dst)))
            && (self.dst_port == 0 || self.dst_port == 53)
            && (self.domain.is_empty() || name == self.domain || name.ends_with(&format!(".{}", self.domain)))
            // UDP DNS has no associated TLS JA4. A JA4 condition cannot match.
            && self.ja4.is_empty()
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

fn prefix(text: &str) -> Result<Option<IpNet>, String> {
    if text.is_empty() {
        return Ok(None);
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Ok(Some(IpNet::from(unmap(ip))));
    }
    text.parse::<IpNet>()
        .map(|net| Some(net.trunc()))
        .map_err(|e| format!("invalid DNS exception IP/CIDR {text:?}: {e}"))
}

impl DnsPolicy {
    /// `None` loads the shipped TH-0002 rule. A directory replaces the shipped
    /// pack; when it omits TH-0002 this detector is disabled. A single YAML file
    /// is also accepted for library clients. Rule files are bounded at 2 MiB.
    pub fn load(rules: Option<&Path>) -> Result<Self, String> {
        let mut documents = Vec::new();
        if let Some(path) = rules {
            let mut files = if path.is_dir() {
                let mut files = Vec::new();
                for entry in fs::read_dir(path).map_err(|e| format!("read DNS rules: {e}"))? {
                    let path = entry.map_err(|e| format!("read DNS rules: {e}"))?.path();
                    if path
                        .extension()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| s == "yaml" || s == "yml")
                    {
                        files.push(path);
                    }
                }
                files
            } else {
                vec![path.to_path_buf()]
            };
            files.sort();
            if files.len() > 128 {
                return Err("DNS rules directory exceeds 128 YAML files".into());
            }
            for file in files {
                if fs::metadata(&file)
                    .map_err(|e| format!("read DNS rule {}: {e}", file.display()))?
                    .len()
                    > 2 * 1024 * 1024
                {
                    return Err(format!("DNS rule file {} exceeds 2 MiB", file.display()));
                }
                let text = fs::read_to_string(&file)
                    .map_err(|e| format!("read DNS rule {}: {e}", file.display()))?;
                documents.push((file.display().to_string(), text));
            }
        } else {
            documents.push((
                "built-in TH-0002".into(),
                include_str!("../../../internal/rules/builtin/th-0002-dns-tunnel.yaml").into(),
            ));
        }
        let mut found = None;
        let mut ids = std::collections::BTreeSet::new();
        for (source, text) in documents {
            for document in serde_yaml_ng::Deserializer::from_str(&text) {
                let mut rule =
                    Rule::deserialize(document).map_err(|e| format!("DNS rules {source}: {e}"))?;
                if !ids.insert(rule.id.clone()) {
                    return Err(format!("duplicate rule ID {}", rule.id));
                }
                if rule.id.is_empty() || rule.name.trim().is_empty() || rule.detector.is_empty() {
                    return Err(format!("DNS rules {source}: missing rule id/name/detector"));
                }
                // Read these fields deliberately: they belong to the shared
                // pack but detection evidence supplies the alert description.
                let _ = (&rule.description, &rule.references);
                if rule.id != "TH-0002" {
                    continue;
                }
                if rule.detector != "dns-tunnel" {
                    return Err("TH-0002 must use the dns-tunnel detector".into());
                }
                for technique in &rule.techniques {
                    if technique.id.trim().is_empty() {
                        return Err("DNS technique needs an id".into());
                    }
                }
                for exception in &mut rule.exceptions {
                    exception.compile()?;
                }
                let tuning: Tuning = rule
                    .tuning
                    .take()
                    .map(serde_yaml_ng::from_value)
                    .transpose()
                    .map_err(|e| format!("TH-0002 tuning: {e}"))?
                    .unwrap_or_default();
                found = Some(Self::from_rule(rule, tuning)?);
            }
        }
        Ok(found.unwrap_or(Self {
            enabled: false,
            severity: None,
            techniques: Vec::new(),
            min_queries: 30,
            threshold: 0.7,
            history_ms: 3_600_000,
            max_tracked: MAX_TRACKS,
            max_unique: DEFAULT_NAMES,
            exceptions: Vec::new(),
        }))
    }

    fn from_rule(rule: Rule, tuning: Tuning) -> Result<Self, String> {
        if !tuning.threshold.is_finite() || !(0.0..=1.0).contains(&tuning.threshold) {
            return Err("DNS threshold must be between 0 and 1".into());
        }
        let history_ms = tuning
            .history
            .as_deref()
            .map(duration_ms)
            .transpose()?
            .filter(|n| *n > 0)
            .unwrap_or(3_600_000);
        Ok(Self {
            enabled: rule.enabled.unwrap_or(true),
            severity: rule.severity,
            techniques: rule.techniques,
            exceptions: rule.exceptions,
            min_queries: if tuning.min_queries == 0 {
                30
            } else {
                tuning.min_queries
            },
            threshold: if tuning.threshold == 0.0 {
                0.7
            } else {
                tuning.threshold
            },
            history_ms,
            max_tracked: if tuning.max_tracked == 0 {
                MAX_TRACKS
            } else {
                tuning.max_tracked.min(MAX_TRACKS)
            },
            max_unique: if tuning.max_unique_names == 0 {
                DEFAULT_NAMES
            } else {
                tuning.max_unique_names.min(MAX_NAMES)
            },
        })
    }
}

// Shared rule packs use Go duration notation, including compound durations.
fn duration_ms(text: &str) -> Result<u64, String> {
    let normalized = text.replace(['µ', 'μ'], "u");
    let mut rest = normalized.strip_prefix('+').unwrap_or(&normalized);
    if rest.is_empty() {
        return Err("empty DNS history duration".into());
    }
    if rest == "0" {
        return Ok(0);
    }
    let mut total = 0.0;
    while !rest.is_empty() {
        let digits = rest
            .bytes()
            .take_while(|c| c.is_ascii_digit() || *c == b'.')
            .count();
        if digits == 0 {
            return Err(format!("invalid DNS history duration {text:?}"));
        }
        let value = rest[..digits]
            .parse::<f64>()
            .map_err(|_| format!("invalid DNS history duration {text:?}"))?;
        rest = &rest[digits..];
        let (unit, scale) = [
            ("ns", 0.000001),
            ("us", 0.001),
            ("ms", 1.0),
            ("s", 1000.0),
            ("m", 60_000.0),
            ("h", 3_600_000.0),
        ]
        .into_iter()
        .find(|(unit, _)| rest.starts_with(unit))
        .ok_or_else(|| format!("invalid DNS history duration {text:?}"))?;
        total += value * scale;
        rest = &rest[unit.len()..];
        if !total.is_finite() || total > i64::MAX as f64 / 1_000_000.0 {
            return Err("DNS history duration overflows Go duration range".into());
        }
    }
    if normalized.is_empty() {
        return Err("empty DNS history duration".into());
    }
    // At least one millisecond keeps buckets finite for sub-millisecond rules.
    Ok(if total > 0.0 {
        (total as u64).max(1)
    } else {
        0
    })
}

#[derive(Default)]
struct Bucket {
    start: u64,
    first: u64,
    queries: usize,
    lengths: f64,
    entropy: f64,
    maximum: usize,
    signal: usize,
}

struct Track {
    server: IpAddr,
    last: u64,
    buckets: VecDeque<Bucket>,
    unique: BTreeMap<String, u64>,
    overflow: bool,
    reported: Option<Reported>,
    packets: Vec<PacketRef>,
    last_reference_drop_ms: Option<u64>,
    last_name_drop_ms: Option<u64>,
}
struct Reported {
    at: u64,
    severity: Severity,
    evidence: Value,
}

impl Track {
    fn prune(&mut self, cutoff: u64, width: u64, max_unique: usize) {
        while self
            .buckets
            .front()
            .is_some_and(|b| b.start.saturating_add(width) <= cutoff)
        {
            self.buckets.pop_front();
        }
        self.unique.retain(|_, time| *time >= cutoff);
        self.packets
            .retain(|reference| reference.timestamp_ns / 1_000_000 >= cutoff);
        if self.last_reference_drop_ms.is_some_and(|at| at < cutoff) {
            self.last_reference_drop_ms = None;
        }
        if self.last_name_drop_ms.is_some_and(|at| at < cutoff) {
            self.last_name_drop_ms = None;
        }
        if self.unique.len() < max_unique && self.last_name_drop_ms.is_none() {
            self.overflow = false;
        }
    }
    fn observe(
        &mut self,
        query: &DnsObservation,
        name: String,
        subdomain: &str,
        width: u64,
        max_unique: usize,
    ) {
        self.last = query.timestamp_ms;
        for reference in &query.packets {
            if self.packets.iter().any(|stored| {
                stored.section == reference.section
                    && stored.interface == reference.interface
                    && stored.number == reference.number
            }) {
                continue;
            }
            if self.packets.len() < 128 {
                self.packets.push(reference.clone());
            } else {
                self.last_reference_drop_ms = Some(query.timestamp_ms);
            }
        }
        let start = self.last / width * width;
        if self.buckets.back().is_none_or(|b| b.start != start) {
            self.buckets.push_back(Bucket {
                start,
                first: self.last,
                ..Bucket::default()
            });
        }
        let bucket = self.buckets.back_mut().unwrap();
        bucket.queries += 1;
        bucket.lengths += subdomain.len() as f64;
        bucket.entropy += entropy(subdomain.as_bytes());
        bucket.maximum = bucket.maximum.max(subdomain.len());
        bucket.signal += usize::from(matches!(query.query_type, 5 | 10 | 16));
        if self.unique.contains_key(&name) || self.unique.len() < max_unique {
            self.unique.insert(name, self.last);
        } else {
            self.overflow = true;
            self.last_name_drop_ms = Some(query.timestamp_ms);
        }
    }
}

impl DnsPolicy {
    /// Score at most the capture reader's 50,000-observation limit, ordered by
    /// capture time. Retention is a sliding history with at most one bucket of
    /// boundary skew, rather than counters accumulated over the capture's life.
    pub fn detect(&self, observations: &[DnsObservation]) -> Vec<Alert> {
        let mut ordered: Vec<_> = observations.iter().take(MAX_INPUT).collect();
        ordered.sort_by_key(|q| q.timestamp_ms);
        let mut analyzer = DnsAnalyzer::new(self.clone());
        let mut alerts = Vec::new();
        for query in ordered {
            alerts.extend(analyzer.observe(query));
        }
        alerts.extend(analyzer.finish());
        alerts
    }

    fn score_tracks(
        &self,
        tracks: &mut BTreeMap<(IpAddr, String), Track>,
        now: u64,
        width: u64,
        alerts: &mut Vec<Alert>,
        uncertainty_limited_scores: &mut u64,
    ) {
        let cutoff = now.saturating_sub(self.history_ms);
        tracks.retain(|_, track| {
            track.prune(cutoff, width, self.max_unique);
            !track.buckets.is_empty() || track.last >= cutoff
        });
        for ((source, domain), track) in tracks.iter_mut() {
            let count: usize = track.buckets.iter().map(|b| b.queries).sum();
            if count < self.min_queries {
                continue;
            }
            let length = track.buckets.iter().map(|b| b.lengths).sum::<f64>() / count as f64;
            let entropy = track.buckets.iter().map(|b| b.entropy).sum::<f64>() / count as f64;
            let signal =
                track.buckets.iter().map(|b| b.signal).sum::<usize>() as f64 / count as f64;
            let unique = track.unique.len().min(count);
            let ratio = unique as f64 / count as f64;
            let upper_ratio = if track.overflow { 1.0 } else { ratio };
            let score = 0.35 * ratio
                + 0.25 * normalize(length, 15.0, 50.0)
                + 0.25 * normalize(entropy, 3.2, 4.6)
                + 0.15 * signal;
            let upper_score = score + 0.35 * (upper_ratio - ratio);
            if score < self.threshold {
                if upper_score >= self.threshold {
                    *uncertainty_limited_scores += 1;
                }
                continue;
            }
            let severity = self.severity.unwrap_or(if score >= 0.85 {
                Severity::High
            } else {
                Severity::Medium
            });
            let first = track.buckets.front().unwrap().first;
            let rate = if track.last > first {
                count as f64 * 60_000.0 / (track.last - first) as f64
            } else {
                0.0
            };
            let evidence = json!({
                "domain": domain, "queries": count, "unique_names": track.unique.len(),
                "unique_ratio": round3(ratio), "avg_subdomain_len": round3(length),
                "unique_ratio_is_lower_bound":track.overflow,
                "unique_ratio_upper_bound":round3(upper_ratio),
                "score_upper_bound":round3(upper_score),
                "name_retention_limited":track.last_name_drop_ms.is_some(),
                "max_subdomain_len": track.buckets.iter().map(|b| b.maximum).max().unwrap_or(0),
                "avg_entropy_bits": round3(entropy), "txt_null_ratio": round3(signal),
                "queries_per_min": round3(rate), "public_suffix_list": "psl-crate-embedded",
            });
            if track.reported.as_ref().is_some_and(|previous| {
                previous.evidence == evidence
                    || (severity <= previous.severity && now.saturating_sub(previous.at) < COOLDOWN)
            }) {
                continue;
            }
            track.reported = Some(Reported {
                at: now,
                severity,
                evidence: evidence.clone(),
            });
            let techniques = if self.techniques.is_empty() {
                json!([
                    {"id":"T1071.004", "name":"Application Layer Protocol: DNS", "tactic":"command-and-control"},
                    {"id":"T1048.003", "name":"Exfiltration Over Alternative Protocol", "tactic":"exfiltration"},
                    {"id":"T1572", "name":"Protocol Tunneling", "tactic":"command-and-control"},
                ])
            } else {
                Value::Array(
                    self.techniques
                        .iter()
                        .map(|t| json!({"id":t.id,"name":t.name,"tactic":t.tactic}))
                        .collect(),
                )
            };
            alerts.push(Alert {
                rule_id: "TH-0002".into(), severity, src: Some(*source), dst: Some(track.server),
                title: format!("Probable DNS tunnelling to {domain}"), time: None,
                description: Some(format!("{source} issued {count} queries under {domain}; {}{:.0}% name uniqueness, with an average subdomain length of {length:.1} and entropy of {entropy:.2} bits per character.", if track.overflow{"retained evidence establishes at least "}else{"observed "},ratio * 100.0)),
                score: Some(round3(score)), evidence,
                extra: BTreeMap::from([
                    ("detector".into(), json!("dns-tunnel")), ("dst_port".into(), json!(53)),
                    ("proto".into(), json!("udp")), ("techniques".into(), techniques),
                    ("capture_timestamp_ms".into(), json!(now)),
                    ("window_start_ms".into(), json!(first)),
                    ("window_end_ms".into(), json!(track.last)),
                    ("packets".into(), json!(track.packets)),
                    ("packet_refs_truncated".into(), json!(track.last_reference_drop_ms.is_some())),
                    ("evidence_scope".into(), json!("captured_query_packet_examples")),
                ]),
            });
        }
    }
}

/// The same policy/scoring engine used by offline analysis, with bounded
/// sliding state and no lifetime observation cap for long-running sessions.
pub struct DnsAnalyzer {
    policy: DnsPolicy,
    tracks: BTreeMap<(IpAddr, String), Track>,
    next_score: Option<u64>,
    last: u64,
    pub dropped_out_of_order: u64,
    pub dropped_name_events: u64,
    pub dropped_track_events: u64,
    pub uncertainty_limited_scores: u64,
    retained_names: usize,
    max_names: usize,
}
impl DnsAnalyzer {
    pub fn new(policy: DnsPolicy) -> Self {
        Self {
            policy,
            tracks: BTreeMap::new(),
            next_score: None,
            last: 0,
            dropped_out_of_order: 0,
            dropped_name_events: 0,
            dropped_track_events: 0,
            uncertainty_limited_scores: 0,
            retained_names: 0,
            max_names: MAX_GLOBAL_NAMES,
        }
    }
    pub fn with_name_budget(policy: DnsPolicy, max_names: usize) -> Result<Self, String> {
        if max_names == 0 || max_names > MAX_GLOBAL_NAMES {
            return Err(format!(
                "DNS global name budget must be 1–{MAX_GLOBAL_NAMES}."
            ));
        }
        Ok(Self {
            max_names,
            ..Self::new(policy)
        })
    }
    pub fn retained_names(&self) -> usize {
        self.retained_names
    }
    pub fn tracked_domains(&self) -> usize {
        self.tracks.len()
    }
    pub fn observe(&mut self, query: &DnsObservation) -> Vec<Alert> {
        if !self.policy.enabled {
            return Vec::new();
        }
        if query.timestamp_ms < self.last {
            self.dropped_out_of_order += 1;
            return Vec::new();
        }
        self.next_score
            .get_or_insert(query.timestamp_ms.saturating_add(SCORE_INTERVAL));
        let alerts = self.tick(query.timestamp_ms);
        self.last = query.timestamp_ms;
        let name = query.name.trim_end_matches('.').to_ascii_lowercase();
        if name.len() > 253
            || name
                .split('.')
                .any(|label| label.is_empty() || label.len() > 63)
            || self
                .policy
                .exceptions
                .iter()
                .any(|exception| exception.matches(query, &name))
        {
            return alerts;
        }
        let Some(domain) = psl::domain_str(&name) else {
            return alerts;
        };
        let subdomain = name
            .strip_suffix(domain)
            .unwrap_or("")
            .trim_end_matches('.');
        let key = (unmap(query.src), domain.to_string());
        if !self.tracks.contains_key(&key) && self.tracks.len() >= self.policy.max_tracked {
            self.dropped_track_events += 1;
            return alerts;
        }
        let track = self.tracks.entry(key).or_insert_with(|| Track {
            server: unmap(query.dst),
            last: self.last,
            buckets: VecDeque::new(),
            unique: BTreeMap::new(),
            overflow: false,
            reported: None,
            packets: Vec::new(),
            last_reference_drop_ms: None,
            last_name_drop_ms: None,
        });
        let width = (self.policy.history_ms / 12).max(1);
        let previous = track.unique.len();
        track.prune(
            self.last.saturating_sub(self.policy.history_ms),
            width,
            self.policy.max_unique,
        );
        self.retained_names = self
            .retained_names
            .saturating_sub(previous - track.unique.len());
        let before = track.unique.len();
        let allowed = self
            .policy
            .max_unique
            .min(self.max_names.saturating_sub(self.retained_names) + before);
        if !track.unique.contains_key(&name) && before >= allowed {
            self.dropped_name_events += 1;
        }
        track.observe(query, name.clone(), subdomain, width, allowed);
        self.retained_names += track.unique.len() - before;
        alerts
    }
    pub fn tick(&mut self, now_ms: u64) -> Vec<Alert> {
        let mut alerts = Vec::new();
        if now_ms < self.last {
            return alerts;
        }
        self.last = now_ms;
        if self.policy.enabled && self.next_score.is_some_and(|next| now_ms >= next) {
            self.policy.score_tracks(
                &mut self.tracks,
                now_ms,
                (self.policy.history_ms / 12).max(1),
                &mut alerts,
                &mut self.uncertainty_limited_scores,
            );
            self.retained_names = self.tracks.values().map(|track| track.unique.len()).sum();
            self.next_score = Some(now_ms.saturating_add(SCORE_INTERVAL));
        }
        alerts
    }
    pub fn flush(&mut self) -> Vec<Alert> {
        let mut alerts = Vec::new();
        if self.policy.enabled {
            self.policy.score_tracks(
                &mut self.tracks,
                self.last,
                (self.policy.history_ms / 12).max(1),
                &mut alerts,
                &mut self.uncertainty_limited_scores,
            );
        }
        alerts
    }
    pub fn finish(mut self) -> Vec<Alert> {
        self.flush()
    }
}

fn normalize(value: f64, lower: f64, upper: f64) -> f64 {
    ((value - lower) / (upper - lower)).clamp(0.0, 1.0)
}
fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}
fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in data {
        counts[usize::from(*byte)] += 1;
    }
    counts
        .into_iter()
        .filter(|n| *n > 0)
        .map(|n| {
            let p = n as f64 / data.len() as f64;
            -p * p.log2()
        })
        .sum()
}
