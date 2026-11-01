//! Explicit, source-attributed TLS fingerprint-pair intelligence.
use crate::capture::TlsObservation;
use crate::{Alert, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

pub const PUBLIC_MAPPING_URL: &str =
    "https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv";
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairIndicator {
    pub ja4: String,
    pub ja4s: String,
    pub name: String,
    pub source_url: String,
    pub classification: String,
    pub confidence: f64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairFeed {
    pub schema_version: u32,
    pub source_url: String,
    pub source_sha256: String,
    pub license: String,
    pub entries: Vec<PairIndicator>,
}
impl PairFeed {
    pub fn load(path: &Path) -> Result<Self, String> {
        if fs::metadata(path).map_err(|e| e.to_string())?.len() > 16 * 1024 * 1024 {
            return Err("fingerprint feed exceeds 16 MiB".into());
        }
        let feed: Self = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("invalid fingerprint feed: {e}"))?;
        feed.validate()?;
        Ok(feed)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.entries.len() > 100_000
            || !https(&self.source_url)
            || self.license.trim().is_empty()
        {
            return Err("invalid fingerprint feed version, source, licence, or size".into());
        }
        if self.source_sha256.len() != 64
            || !self.source_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("feed source requires a SHA-256".into());
        }
        let mut pairs = BTreeSet::new();
        for entry in &self.entries {
            if !fingerprint(&entry.ja4)
                || !fingerprint(&entry.ja4s)
                || entry.name.trim().is_empty()
                || !https(&entry.source_url)
                || !matches!(
                    entry.classification.as_str(),
                    "associated" | "malicious" | "benign"
                )
                || !entry.confidence.is_finite()
                || !(0.0..=1.0).contains(&entry.confidence)
                || !pairs.insert((&entry.ja4, &entry.ja4s))
            {
                return Err("invalid or duplicate fingerprint-pair entry".into());
            }
        }
        Ok(())
    }
    pub fn detect(&self, observations: &[TlsObservation]) -> Result<Vec<Alert>, String> {
        self.validate()?;
        let index: BTreeMap<_, _> = self
            .entries
            .iter()
            .map(|entry| ((entry.ja4.as_str(), entry.ja4s.as_str()), entry))
            .collect();
        let mut alerts = Vec::new();
        let mut seen = BTreeSet::new();
        for observation in observations {
            let Some(entry) = index.get(&(observation.ja4.as_str(), observation.ja4s.as_str()))
            else {
                continue;
            };
            if entry.classification == "benign"
                || !seen.insert((observation.src, observation.dst, &entry.ja4, &entry.ja4s))
            {
                continue;
            }
            alerts.push(Alert { rule_id: "TH-0008".into(), severity: if entry.classification == "malicious" { Severity::High } else { Severity::Medium },
                src: Some(observation.src), dst: Some(observation.dst), title: format!("TLS fingerprint pair associated with {}", entry.name),
                time: None, description: Some("A source-attributed client/server fingerprint pair matched. Shared TLS stacks can produce the same pair; investigate the surrounding activity before attribution.".into()),
                score: Some(entry.confidence), evidence: json!({"ja4":entry.ja4,"ja4s":entry.ja4s,"association":entry.name,"classification":entry.classification,"source_url":entry.source_url,"feed_sha256":self.source_sha256,"server_name":observation.server_name}),
                extra: BTreeMap::from([("detector".into(), json!("known-tls-pair")), ("dst_port".into(), json!(observation.dst_port))]) });
        }
        Ok(alerts)
    }
    /// Import the publisher's publicly available examples, without bundling its
    /// database or silently labelling common browsers as malicious.
    pub fn from_public_mapping(csv: &str) -> Result<Self, String> {
        let rows = csv_rows(csv)?;
        let header = rows.first().ok_or("mapping is empty")?;
        let column = |name: &str| {
            header
                .iter()
                .position(|v| v.eq_ignore_ascii_case(name))
                .ok_or_else(|| format!("mapping lacks {name}"))
        };
        let app = column("Application")?;
        let ja4 = column("ja4")?;
        let ja4s = column("ja4s")?;
        let mut entries = Vec::new();
        let mut seen = BTreeSet::new();
        for row in rows.iter().skip(1) {
            let value = |index| row.get(index).map(String::as_str).unwrap_or("").trim();
            let name = value(app);
            let a = value(ja4);
            let b = value(ja4s);
            let label = name.to_ascii_lowercase();
            if a.is_empty()
                || b.is_empty()
                || !["sliver", "icedid", "cobalt strike", "malware"]
                    .iter()
                    .any(|s| label.contains(s))
                || !seen.insert((a.to_owned(), b.to_owned()))
            {
                continue;
            }
            entries.push(PairIndicator {
                ja4: a.into(),
                ja4s: b.into(),
                name: name.into(),
                source_url: PUBLIC_MAPPING_URL.into(),
                classification: "associated".into(),
                confidence: 0.65,
            });
        }
        if entries.is_empty() {
            return Err("publisher mapping contains no usable attributed pairs".into());
        }
        let feed = Self { schema_version:1, source_url:PUBLIC_MAPPING_URL.into(), source_sha256:format!("{:x}",Sha256::digest(csv.as_bytes())),
            license:"Publisher dataset: FoxIO terms apply; fetched for local use. No publisher database is bundled with this application.".into(), entries };
        feed.validate()?;
        Ok(feed)
    }
}

pub fn update_public_mapping(destination: &Path) -> Result<PairFeed, String> {
    if destination.exists() {
        return Err(format!(
            "feed {} already exists; choose a new filename",
            destination.display()
        ));
    }
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .build();
    let agent: ureq::Agent = config.into();
    let mut response = agent
        .get(PUBLIC_MAPPING_URL)
        .call()
        .map_err(|e| format!("download mapping: {e}"))?;
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("mapping exceeds 1 MiB".into());
    }
    let csv = String::from_utf8(bytes).map_err(|_| "mapping is not UTF-8")?;
    let feed = PairFeed::from_public_mapping(&csv)?;
    crate::store::write_new(destination, &feed)?;
    Ok(feed)
}

fn https(url: &str) -> bool {
    url.starts_with("https://") && !url.contains('@') && !url.chars().any(char::is_control)
}
fn fingerprint(value: &str) -> bool {
    (10..=128).contains(&value.len())
        && value.contains('_')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn csv_rows(text: &str) -> Result<Vec<Vec<String>>, String> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => row.push(std::mem::take(&mut field)),
            '\n' if !quoted => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            '\r' if !quoted => {}
            _ => field.push(ch),
        }
    }
    if quoted {
        return Err("unterminated quoted CSV field".into());
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapping_import_filters_browsers_and_preserves_provenance() {
        let csv = "Application,ja4,ja4s\nBrowser,t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb,t130200_1301_cccccccccccc\n\"Malware, test\",t13d1516h2_dddddddddddd_eeeeeeeeeeee,t130200_1301_ffffffffffff\n";
        let feed = PairFeed::from_public_mapping(csv).unwrap();
        assert_eq!(feed.entries.len(), 1);
        assert_eq!(feed.entries[0].name, "Malware, test");
        assert_eq!(feed.entries[0].classification, "associated");
        let observation = TlsObservation {
            src: "10.0.0.1".parse().unwrap(),
            dst: "192.0.2.1".parse().unwrap(),
            src_port: 50000,
            dst_port: 443,
            ja4: feed.entries[0].ja4.clone(),
            ja4s: feed.entries[0].ja4s.clone(),
            server_name: None,
        };
        assert_eq!(
            feed.detect(&[observation.clone(), observation])
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn malformed_feed_is_rejected() {
        assert!(PairFeed::from_public_mapping("Application,ja4,ja4s\n\"broken").is_err());
    }
}
