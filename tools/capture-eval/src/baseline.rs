//! Compare observed behavior over explicitly comparable capture-time windows.
use crate::investigation::CaseIndex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const MAX_FEATURES: usize = 10_000;
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ActivityProfile {
    pub host: IpAddr,
    pub capture_sha256: String,
    pub window_start_ns: u64,
    pub window_end_ns: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub wire_bytes_sent: u64,
    pub wire_bytes_received: u64,
    pub packets_sent_per_second: Option<f64>,
    pub wire_bytes_sent_per_second: Option<f64>,
    pub destinations: BTreeSet<String>,
    pub services: BTreeSet<String>,
    pub domains: BTreeSet<String>,
    pub tls_pairs: BTreeSet<String>,
    pub client_fingerprints: BTreeSet<String>,
    pub http_hosts: BTreeSet<String>,
    pub finding_rules: BTreeSet<String>,
    pub features_truncated: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeatureChanges {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub unchanged: usize,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RateChange {
    pub before: Option<f64>,
    pub after: Option<f64>,
    pub difference: Option<f64>,
    pub ratio: Option<f64>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BaselineComparison {
    pub schema_version: u32,
    pub mode: String,
    pub host: IpAddr,
    pub window_seconds: Option<f64>,
    pub before: ActivityProfile,
    pub after: ActivityProfile,
    pub changes: BTreeMap<String, FeatureChanges>,
    pub rates: BTreeMap<String, RateChange>,
    pub notes: Vec<String>,
}
fn fail(e: impl std::fmt::Display) -> String {
    format!("compare investigation windows: {e}")
}
fn signed(value: u64) -> Result<i64, String> {
    value
        .try_into()
        .map_err(|_| "comparison timestamp exceeds database range".into())
}
fn count(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    value.try_into().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(e),
        )
    })
}

pub fn compare_cases(
    before: &Path,
    after: &Path,
    host: IpAddr,
    duration_seconds: Option<u64>,
) -> Result<BaselineComparison, String> {
    compare_cases_cancellable(
        before,
        after,
        host,
        duration_seconds,
        Arc::new(AtomicBool::new(false)),
    )
}
pub fn compare_cases_cancellable(
    before: &Path,
    after: &Path,
    host: IpAddr,
    duration_seconds: Option<u64>,
    cancelled: Arc<AtomicBool>,
) -> Result<BaselineComparison, String> {
    if cancelled.load(Ordering::Acquire) {
        return Err("behavior comparison cancelled".into());
    }
    if duration_seconds == Some(0) {
        return Err("comparison duration must be positive".into());
    }
    let mut before = CaseIndex::open(before)?;
    let mut after = CaseIndex::open(after)?;
    let left = Arc::clone(&cancelled);
    before.interrupt_when(move || left.load(Ordering::Acquire))?;
    let right = Arc::clone(&cancelled);
    after.interrupt_when(move || right.load(Ordering::Acquire))?;
    let start_before = before
        .overview()
        .first_timestamp_ns
        .ok_or("baseline has no timestamped packets")?;
    let start_after = after
        .overview()
        .first_timestamp_ns
        .ok_or("comparison has no timestamped packets")?;
    let available_before = before
        .overview()
        .last_timestamp_ns
        .unwrap_or(start_before)
        .saturating_sub(start_before);
    let available_after = after
        .overview()
        .last_timestamp_ns
        .unwrap_or(start_after)
        .saturating_sub(start_after);
    let available = available_before.min(available_after);
    let requested = duration_seconds
        .map(|value| {
            value
                .checked_mul(1_000_000_000)
                .ok_or("comparison duration overflow")
        })
        .transpose()?;
    let duration = requested.unwrap_or(available).min(available);
    let seconds = (duration > 0).then_some(duration as f64 / 1_000_000_000.0);
    let old = profile(
        &before,
        host,
        start_before,
        start_before.saturating_add(duration),
        seconds,
        &cancelled,
    )?;
    let new = profile(
        &after,
        host,
        start_after,
        start_after.saturating_add(duration),
        seconds,
        &cancelled,
    )?;
    let mut changes = BTreeMap::new();
    for (name, left, right) in [
        ("destinations", &old.destinations, &new.destinations),
        ("services", &old.services, &new.services),
        ("domains", &old.domains, &new.domains),
        ("tls_pairs", &old.tls_pairs, &new.tls_pairs),
        (
            "client_fingerprints",
            &old.client_fingerprints,
            &new.client_fingerprints,
        ),
        ("http_hosts", &old.http_hosts, &new.http_hosts),
        ("finding_rules", &old.finding_rules, &new.finding_rules),
    ] {
        changes.insert(
            name.into(),
            FeatureChanges {
                added: right.difference(left).cloned().collect(),
                removed: left.difference(right).cloned().collect(),
                unchanged: left.intersection(right).count(),
            },
        );
    }
    let rate = |left: Option<f64>, right: Option<f64>| RateChange {
        before: left,
        after: right,
        difference: left.zip(right).map(|(a, b)| b - a),
        ratio: left
            .zip(right)
            .filter(|(a, _)| *a > 0.0)
            .map(|(a, b)| b / a),
    };
    let rates = BTreeMap::from([
        (
            "packets_sent_per_second".into(),
            rate(old.packets_sent_per_second, new.packets_sent_per_second),
        ),
        (
            "wire_bytes_sent_per_second".into(),
            rate(
                old.wire_bytes_sent_per_second,
                new.wire_bytes_sent_per_second,
            ),
        ),
    ]);
    let mut notes=vec!["Windows begin at each capture's first packet and use equal elapsed duration; they are not aligned by time of day.".into(),"Both window endpoints are included so final-packet facts and EOF findings are retained; rates use the elapsed duration between endpoints.".into(),"Capture timestamps do not prove continuous observation. Gaps, dropped packets, NAT and DHCP can affect comparisons.".into(),"A newly observed destination, domain or fingerprint is a change, not a malware verdict.".into(),"Packet/byte rates use original on-wire lengths and include fragments. Protocol features require successfully decoded observations.".into()];
    if seconds.is_none() {
        notes.push(
            "No positive shared elapsed duration is available; rate comparisons are undefined."
                .into(),
        );
    }
    if requested.is_some_and(|requested| requested > available) {
        notes.push("Requested duration was shortened to the shared capture-time coverage.".into());
    }
    if old.features_truncated || new.features_truncated {
        notes.push(
            "Feature sets reached their explicit limit; additions/removals may be incomplete."
                .into(),
        );
    }
    Ok(BaselineComparison {
        schema_version: 1,
        mode: "behavior_comparison".into(),
        host,
        window_seconds: seconds,
        before: old,
        after: new,
        changes,
        rates,
        notes,
    })
}
fn strings(
    connection: &Connection,
    query: &str,
    host: IpAddr,
    start: u64,
    end: u64,
) -> Result<(BTreeSet<String>, bool), String> {
    let mut statement = connection.prepare(query).map_err(fail)?;
    let rows = statement
        .query_map(
            params![
                host.to_string(),
                signed(start)?,
                signed(end)?,
                (MAX_FEATURES + 1) as i64
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(fail)?;
    let mut set = rows
        .collect::<rusqlite::Result<BTreeSet<_>>>()
        .map_err(fail)?;
    let truncated = set.len() > MAX_FEATURES;
    while set.len() > MAX_FEATURES {
        set.pop_last();
    }
    Ok((set, truncated))
}
fn profile(
    case: &CaseIndex,
    host: IpAddr,
    start: u64,
    end: u64,
    seconds: Option<f64>,
    cancelled: &AtomicBool,
) -> Result<ActivityProfile, String> {
    let c = &case.connection;
    let(sent,received,sent_bytes,received_bytes)=c.query_row("SELECT coalesce(sum(CASE WHEN src=?1 THEN 1 ELSE 0 END),0),coalesce(sum(CASE WHEN dst=?1 THEN 1 ELSE 0 END),0),coalesce(sum(CASE WHEN src=?1 THEN original_len ELSE 0 END),0),coalesce(sum(CASE WHEN dst=?1 THEN original_len ELSE 0 END),0) FROM packets WHERE (src=?1 OR dst=?1) AND timestamp_ns>=?2 AND timestamp_ns<=?3",params![host.to_string(),signed(start)?,signed(end)?],|r|Ok((count(r,0)?,count(r,1)?,count(r,2)?,count(r,3)?))).map_err(fail)?;
    let(destinations,a)=strings(c,"SELECT DISTINCT dst FROM packets WHERE src=?1 AND timestamp_ns>=?2 AND timestamp_ns<=?3 AND dst IS NOT NULL ORDER BY dst LIMIT ?4",host,start,end)?;
    let(services,b)=strings(c,"SELECT DISTINCT CAST(protocol AS TEXT)||'/'||CAST(dst_port AS TEXT) FROM packets WHERE src=?1 AND timestamp_ns>=?2 AND timestamp_ns<=?3 AND protocol IS NOT NULL AND dst_port IS NOT NULL ORDER BY 1 LIMIT ?4",host,start,end)?;
    let mut profile = ActivityProfile {
        host,
        capture_sha256: case.overview().capture.sha256.clone(),
        window_start_ns: start,
        window_end_ns: end,
        packets_sent: sent,
        packets_received: received,
        wire_bytes_sent: sent_bytes,
        wire_bytes_received: received_bytes,
        packets_sent_per_second: seconds.map(|d| sent as f64 / d),
        wire_bytes_sent_per_second: seconds.map(|d| sent_bytes as f64 / d),
        destinations,
        services,
        domains: BTreeSet::new(),
        tls_pairs: BTreeSet::new(),
        client_fingerprints: BTreeSet::new(),
        http_hosts: BTreeSet::new(),
        finding_rules: BTreeSet::new(),
        features_truncated: a || b,
    };
    let mut statement=c.prepare("SELECT kind,details FROM events WHERE host=?1 AND timestamp_ns>=?2 AND timestamp_ns<=?3 AND kind IN ('dns','tls','tls_client','http','finding') ORDER BY timestamp_ns,id LIMIT ?4").map_err(fail)?;
    let rows = statement
        .query_map(
            params![
                host.to_string(),
                signed(start)?,
                signed(end)?,
                (MAX_FEATURES + 1) as i64
            ],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .map_err(fail)?;
    for (index, row) in rows.enumerate() {
        if cancelled.load(Ordering::Acquire) {
            return Err("behavior comparison cancelled".into());
        }
        if index == MAX_FEATURES {
            profile.features_truncated = true;
            break;
        }
        let (kind, text) = row.map_err(fail)?;
        let value: Value = serde_json::from_str(&text).map_err(fail)?;
        match kind.as_str() {
            "dns" => {
                if let Some(name) = value.get("name").and_then(Value::as_str) {
                    profile.domains.insert(name.into());
                }
            }
            "tls" => {
                if let (Some(a), Some(b)) = (
                    value.get("ja4").and_then(Value::as_str),
                    value.get("ja4s").and_then(Value::as_str),
                ) {
                    profile.tls_pairs.insert(format!("{a} / {b}"));
                }
            }
            "tls_client" => {
                if let Some(fingerprint) = value.get("ja4").and_then(Value::as_str) {
                    profile.client_fingerprints.insert(fingerprint.into());
                }
            }
            "http" => {
                if let Some(name) = value.get("host").and_then(Value::as_str) {
                    profile.http_hosts.insert(name.into());
                }
            }
            "finding" => {
                if let Some(rule) = value
                    .get("alert")
                    .and_then(|a| a.get("rule_id"))
                    .and_then(Value::as_str)
                {
                    profile.finding_rules.insert(rule.into());
                }
            }
            _ => {}
        }
    }
    Ok(profile)
}
