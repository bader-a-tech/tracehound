//! Capture analysis and labelled evaluation shared by the CLI and future GUI.
//!
//! Expectations describe behaviours over a whole capture, rather than individual
//! alert emissions. Repeated findings are grouped by rule, source, and destination.
//! Precision assumes the supplied positive labels are complete; no true-negative
//! count or false-positive rate is inferred from an unlabelled capture.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

pub mod runtime;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(format!(
                "invalid severity {value:?}; expected info, low, medium, high, or critical"
            )),
        }
    }
}

/// One sensor JSONL record. Unknown fields are retained for clients that need
/// protocol, technique, port, or detector metadata added by the sensor.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Alert {
    pub rule_id: String,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<IpAddr>,
    #[serde(default)]
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default)]
    pub evidence: Value,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// A required behaviour. Omitting dst allows any destination for this rule and
/// source; it does not allow any source or any rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    pub rule_id: String,
    pub src: IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<IpAddr>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureCase {
    pub name: String,
    pub capture: PathBuf,
    // Required even when empty: [] explicitly asserts a negative case.
    pub expected: Vec<Expectation>,
    #[serde(default)]
    pub benign_hosts: Vec<IpAddr>,
    #[serde(default)]
    pub min_severity: Severity,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    pub schema_version: u32,
    pub captures: Vec<CaptureCase>,
}

impl Suite {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema_version {}; expected {SCHEMA_VERSION}",
                self.schema_version
            ));
        }
        if self.captures.is_empty() {
            return Err("evaluation suite must contain at least one capture".into());
        }
        let mut names = BTreeSet::new();
        for case in &self.captures {
            case.validate()?;
            if !names.insert(&case.name) {
                return Err(format!("duplicate capture name {:?}", case.name));
            }
        }
        Ok(())
    }
}

impl CaptureCase {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("capture name must not be empty".into());
        }
        if self.capture.as_os_str().is_empty() {
            return Err(format!(
                "capture {:?}: capture path must not be empty",
                self.name
            ));
        }
        let mut benign = BTreeSet::new();
        for host in &self.benign_hosts {
            if !benign.insert(canonical_ip(*host)) {
                return Err(format!(
                    "capture {:?}: duplicate benign host {host}",
                    self.name
                ));
            }
        }
        let mut destinations: BTreeMap<(String, IpAddr), BTreeSet<Option<IpAddr>>> =
            BTreeMap::new();
        for expectation in &self.expected {
            if !valid_rule_id(&expectation.rule_id) {
                return Err(format!(
                    "capture {:?}: invalid expected rule_id {:?}; use 2-8 uppercase letters, a hyphen, and 4 digits",
                    self.name, expectation.rule_id
                ));
            }
            let src = canonical_ip(expectation.src);
            if benign.contains(&src) {
                return Err(format!(
                    "capture {:?}: expected source {} is also labelled benign",
                    self.name, expectation.src
                ));
            }
            let dst = expectation.dst.map(canonical_ip);
            let seen = destinations
                .entry((expectation.rule_id.clone(), src))
                .or_default();
            if seen.contains(&dst) {
                return Err(format!(
                    "capture {:?}: duplicate expectation for {} from {}",
                    self.name, expectation.rule_id, expectation.src
                ));
            }
            if (dst.is_none() && !seen.is_empty()) || seen.contains(&None) {
                return Err(format!(
                    "capture {:?}: overlapping wildcard and destination-specific expectations for {} from {}",
                    self.name, expectation.rule_id, expectation.src
                ));
            }
            seen.insert(dst);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    /// The last eligible emission retains the latest measurements and severity.
    pub alert: Alert,
    pub occurrences: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct AnalysisReport {
    pub schema_version: u32,
    pub mode: &'static str,
    pub min_severity: Severity,
    pub total_alerts: usize,
    pub evaluated_alerts: usize,
    pub ignored_alerts: usize,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvaluationSummary {
    pub expected_total: usize,
    pub matched_expectations: usize,
    pub missed_expectations: usize,
    pub unique_findings: usize,
    pub matched_findings: usize,
    pub unexpected_findings: usize,
    pub benign_findings: usize,
    /// Matched unique findings / all unique findings, or null with no findings.
    pub precision: Option<f64>,
    /// Matched expectations / all expectations, or null with no expectations.
    pub recall: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvaluationReport {
    pub schema_version: u32,
    pub mode: &'static str,
    pub name: String,
    pub capture: PathBuf,
    pub min_severity: Severity,
    pub passed: bool,
    pub total_alerts: usize,
    pub evaluated_alerts: usize,
    pub ignored_alerts: usize,
    pub findings: Vec<Finding>,
    pub matched_expectations: Vec<Expectation>,
    pub missed_expectations: Vec<Expectation>,
    pub unexpected_findings: Vec<Finding>,
    /// A subset of unexpected_findings whose source is explicitly benign.
    pub benign_findings: Vec<Finding>,
    pub summary: EvaluationSummary,
}

/// Summarise findings without assuming any ground truth. An empty findings list
/// says only that no eligible alert was emitted, not that a capture is safe.
pub fn analyze(alerts: &[Alert], min_severity: Severity) -> Result<AnalysisReport, String> {
    let mut grouped: BTreeMap<FindingKey, Finding> = BTreeMap::new();
    let mut evaluated_alerts = 0;
    for (index, alert) in alerts.iter().enumerate() {
        if alert.severity < min_severity {
            continue;
        }
        validate_alert(alert).map_err(|err| format!("alert {}: {err}", index + 1))?;
        evaluated_alerts += 1;
        let key = finding_key(alert);
        grouped
            .entry(key)
            .and_modify(|finding| {
                finding.occurrences += 1;
                finding.alert = alert.clone();
            })
            .or_insert_with(|| Finding {
                alert: alert.clone(),
                occurrences: 1,
            });
    }
    Ok(AnalysisReport {
        schema_version: SCHEMA_VERSION,
        mode: "analysis",
        min_severity,
        total_alerts: alerts.len(),
        evaluated_alerts,
        ignored_alerts: alerts.len() - evaluated_alerts,
        findings: grouped.into_values().collect(),
    })
}

/// Compare observed findings with complete positive labels and optional benign
/// sources. Every eligible finding absent from the labels is unexpected.
pub fn evaluate(case: &CaptureCase, alerts: &[Alert]) -> Result<EvaluationReport, String> {
    case.validate()?;
    let analysis = analyze(alerts, case.min_severity)?;
    // Index destinations once. Large captures and label sets should not require
    // comparing every finding with every expectation.
    let mut observed: BTreeMap<(String, IpAddr), BTreeSet<Option<IpAddr>>> = BTreeMap::new();
    for finding in &analysis.findings {
        let (rule, src, dst) = finding_key(&finding.alert);
        observed.entry((rule, src)).or_default().insert(dst);
    }
    let mut required: BTreeMap<(String, IpAddr), BTreeSet<Option<IpAddr>>> = BTreeMap::new();
    for expectation in &case.expected {
        let (rule, src, dst) = expectation_key(expectation);
        required.entry((rule, src)).or_default().insert(dst);
    }
    let mut matched_expectations = Vec::new();
    let mut missed_expectations = Vec::new();
    let mut expectations = case.expected.clone();
    expectations.sort_by_key(expectation_key);
    for expectation in expectations {
        let (rule, src, dst) = expectation_key(&expectation);
        let matched = observed
            .get(&(rule, src))
            .is_some_and(|destinations| dst.is_none() || destinations.contains(&dst));
        if matched {
            matched_expectations.push(expectation);
        } else {
            missed_expectations.push(expectation);
        }
    }
    let benign: BTreeSet<IpAddr> = case
        .benign_hosts
        .iter()
        .copied()
        .map(canonical_ip)
        .collect();
    let mut unexpected_findings = Vec::new();
    let mut benign_findings = Vec::new();
    let mut matched_findings = 0;
    for finding in &analysis.findings {
        let (rule, src, dst) = finding_key(&finding.alert);
        let matched = required.get(&(rule, src)).is_some_and(|destinations| {
            destinations.contains(&None) || destinations.contains(&dst)
        });
        if matched {
            matched_findings += 1;
        } else {
            unexpected_findings.push(finding.clone());
        }
        if finding
            .alert
            .src
            .is_some_and(|src| benign.contains(&canonical_ip(src)))
        {
            benign_findings.push(finding.clone());
        }
    }
    let summary = EvaluationSummary {
        expected_total: case.expected.len(),
        matched_expectations: matched_expectations.len(),
        missed_expectations: missed_expectations.len(),
        unique_findings: analysis.findings.len(),
        matched_findings,
        unexpected_findings: unexpected_findings.len(),
        benign_findings: benign_findings.len(),
        precision: ratio(matched_findings, analysis.findings.len()),
        recall: ratio(matched_expectations.len(), case.expected.len()),
    };
    Ok(EvaluationReport {
        schema_version: SCHEMA_VERSION,
        mode: "evaluation",
        name: case.name.clone(),
        capture: case.capture.clone(),
        min_severity: case.min_severity,
        passed: missed_expectations.is_empty() && unexpected_findings.is_empty(),
        total_alerts: analysis.total_alerts,
        evaluated_alerts: analysis.evaluated_alerts,
        ignored_alerts: analysis.ignored_alerts,
        findings: analysis.findings,
        matched_expectations,
        missed_expectations,
        unexpected_findings,
        benign_findings,
        summary,
    })
}

type FindingKey = (String, IpAddr, Option<IpAddr>);

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

fn expectation_key(expectation: &Expectation) -> FindingKey {
    (
        expectation.rule_id.clone(),
        canonical_ip(expectation.src),
        expectation.dst.map(canonical_ip),
    )
}

fn finding_key(alert: &Alert) -> FindingKey {
    (
        alert.rule_id.clone(),
        canonical_ip(alert.src.expect("validated eligible alert has a source")),
        alert.dst.map(canonical_ip),
    )
}

fn valid_rule_id(value: &str) -> bool {
    let Some((prefix, digits)) = value.split_once('-') else {
        return false;
    };
    (2..=8).contains(&prefix.len())
        && prefix.bytes().all(|byte| byte.is_ascii_uppercase())
        && digits.len() == 4
        && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_alert(alert: &Alert) -> Result<(), String> {
    if alert.rule_id.trim().is_empty() {
        return Err("rule_id must not be empty".into());
    }
    if alert.src.is_none() {
        return Err("eligible alert is missing its source address".into());
    }
    if let Some(score) = alert.score {
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return Err("score must be finite and between 0 and 1".into());
        }
    }
    Ok(())
}

fn ratio(numerator: usize, denominator: usize) -> Option<f64> {
    (denominator != 0).then(|| numerator as f64 / denominator as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn alert(rule: &str, src: &str, dst: Option<&str>, severity: Severity) -> Alert {
        serde_json::from_value(json!({
            "rule_id": rule,
            "src": src,
            "dst": dst,
            "severity": severity,
            "title": "Observed behaviour",
            "score": 0.8,
            "evidence": {"connections": 8},
            "techniques": [{"id": "T1071.001"}]
        }))
        .unwrap()
    }

    fn expectation(rule: &str, src: &str, dst: Option<&str>) -> Expectation {
        Expectation {
            rule_id: rule.into(),
            src: src.parse().unwrap(),
            dst: dst.map(|value| value.parse().unwrap()),
        }
    }

    fn case(expected: Vec<Expectation>) -> CaptureCase {
        CaptureCase {
            name: "User-labelled capture".into(),
            capture: "captures/site-a.pcapng".into(),
            expected,
            benign_hosts: Vec::new(),
            min_severity: Severity::Low,
        }
    }

    #[test]
    fn analysis_groups_restatements_and_retains_latest_evidence() {
        let first = alert("TH-0001", "10.0.0.42", Some("192.0.2.9"), Severity::Medium);
        let mut latest = first.clone();
        latest.evidence = json!({"connections": 20});
        latest.severity = Severity::High;
        let ignored = alert("TH-0006", "10.0.0.10", None, Severity::Info);
        let report = analyze(&[first, ignored, latest], Severity::Low).unwrap();
        assert_eq!(report.mode, "analysis");
        assert_eq!(report.total_alerts, 3);
        assert_eq!(report.evaluated_alerts, 2);
        assert_eq!(report.ignored_alerts, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].occurrences, 2);
        assert_eq!(report.findings[0].alert.evidence["connections"], 20);
        assert_eq!(
            report.findings[0].alert.extra["techniques"][0]["id"],
            "T1071.001"
        );
        let json = serde_json::to_value(report).unwrap();
        assert!(json.get("precision").is_none());
        assert!(json.get("recall").is_none());
        assert!(json.get("passed").is_none());
    }

    #[test]
    fn wildcard_destination_matches_multiple_findings_without_inflating_recall() {
        let case = case(vec![expectation("TH-0001", "10.0.0.42", None)]);
        let a = alert("TH-0001", "10.0.0.42", Some("192.0.2.1"), Severity::Medium);
        let b = alert("TH-0001", "10.0.0.42", Some("192.0.2.2"), Severity::Medium);
        let report = evaluate(&case, &[b, a.clone(), a]).unwrap();
        assert!(report.passed);
        assert_eq!(report.summary.matched_expectations, 1);
        assert_eq!(report.summary.matched_findings, 2);
        assert_eq!(report.summary.precision, Some(1.0));
        assert_eq!(report.summary.recall, Some(1.0));
        assert_eq!(
            report.findings[0].alert.dst.unwrap().to_string(),
            "192.0.2.1"
        );
    }

    #[test]
    fn evaluation_reports_missed_unexpected_and_benign_violations() {
        let mut case = case(vec![
            expectation("TH-0001", "10.0.0.42", Some("192.0.2.1")),
            expectation("TH-0002", "10.0.0.42", None),
        ]);
        case.benign_hosts.push("10.0.0.10".parse().unwrap());
        let report = evaluate(
            &case,
            &[
                alert("TH-0001", "10.0.0.42", Some("192.0.2.1"), Severity::Medium),
                alert("TH-0001", "10.0.0.10", Some("192.0.2.1"), Severity::Medium),
            ],
        )
        .unwrap();
        assert!(!report.passed);
        assert_eq!(report.missed_expectations[0].rule_id, "TH-0002");
        assert_eq!(report.unexpected_findings.len(), 1);
        assert_eq!(report.benign_findings.len(), 1);
        assert_eq!(report.summary.precision, Some(0.5));
        assert_eq!(report.summary.recall, Some(0.5));
    }

    #[test]
    fn wrong_destination_is_both_missed_and_unexpected() {
        let case = case(vec![expectation("TH-0001", "10.0.0.42", Some("192.0.2.1"))]);
        let report = evaluate(
            &case,
            &[alert(
                "TH-0001",
                "10.0.0.42",
                Some("192.0.2.2"),
                Severity::High,
            )],
        )
        .unwrap();
        assert!(!report.passed);
        assert_eq!(report.summary.missed_expectations, 1);
        assert_eq!(report.summary.unexpected_findings, 1);
        assert_eq!(report.summary.precision, Some(0.0));
        assert_eq!(report.summary.recall, Some(0.0));
    }

    #[test]
    fn empty_negative_case_has_no_invented_metrics() {
        let case = case(Vec::new());
        let report = evaluate(&case, &[]).unwrap();
        assert!(report.passed);
        assert_eq!(report.summary.precision, None);
        assert_eq!(report.summary.recall, None);
        let report =
            evaluate(&case, &[alert("TH-0001", "10.0.0.42", None, Severity::Low)]).unwrap();
        assert!(!report.passed);
        assert_eq!(report.summary.precision, Some(0.0));
        assert_eq!(report.summary.recall, None);
    }

    #[test]
    fn minimum_severity_applies_before_matching() {
        let mut case = case(vec![expectation("TH-0001", "10.0.0.42", None)]);
        case.min_severity = Severity::High;
        let report = evaluate(
            &case,
            &[alert("TH-0001", "10.0.0.42", None, Severity::Medium)],
        )
        .unwrap();
        assert!(!report.passed);
        assert_eq!(report.ignored_alerts, 1);
        assert_eq!(report.summary.unique_findings, 0);
        assert_eq!(report.summary.missed_expectations, 1);
    }

    #[test]
    fn ipv6_and_ipv4_mapped_addresses_match() {
        let case = case(vec![
            expectation("TH-0001", "2001:db8::42", Some("2001:db8::1")),
            expectation("TH-0002", "10.0.0.42", None),
        ]);
        let report = evaluate(
            &case,
            &[
                alert(
                    "TH-0001",
                    "2001:0db8:0:0:0:0:0:42",
                    Some("2001:db8::1"),
                    Severity::High,
                ),
                alert("TH-0002", "::ffff:10.0.0.42", None, Severity::High),
            ],
        )
        .unwrap();
        assert!(report.passed);
    }

    #[test]
    fn invalid_eligible_alerts_are_errors() {
        let valid = alert("TH-0001", "10.0.0.42", None, Severity::Low);
        let mut invalid = valid.clone();
        invalid.src = None;
        assert!(analyze(&[invalid], Severity::Low).is_err());
        let mut invalid = valid.clone();
        invalid.rule_id.clear();
        assert!(analyze(&[invalid], Severity::Low).is_err());
        for score in [f64::NAN, f64::INFINITY, -0.1, 1.1] {
            let mut invalid = valid.clone();
            invalid.score = Some(score);
            assert!(analyze(&[invalid], Severity::Low).is_err());
        }
    }

    #[test]
    fn strict_manifest_requires_labels_and_known_fields() {
        let missing_expected = json!({
            "schema_version": 1,
            "captures": [{"name": "office", "capture": "office.pcap"}]
        });
        assert!(serde_json::from_value::<Suite>(missing_expected).is_err());
        let unknown_field = json!({
            "schema_version": 1,
            "captures": [{"name": "office", "capture": "office.pcap", "expected": [], "benign_host": []}]
        });
        assert!(serde_json::from_value::<Suite>(unknown_field).is_err());
        let suite: Suite = serde_json::from_value(json!({
            "schema_version": 1,
            "captures": [{"name": "office", "capture": "office.pcapng", "expected": []}]
        }))
        .unwrap();
        suite.validate().unwrap();
        assert_eq!(suite.captures[0].min_severity, Severity::Low);
    }

    #[test]
    fn validation_rejects_ambiguous_labels() {
        let mut case = case(vec![expectation("TH-0001", "10.0.0.42", None)]);
        case.expected.push(case.expected[0].clone());
        assert!(case
            .validate()
            .unwrap_err()
            .contains("duplicate expectation"));
        case.expected[1].dst = Some("192.0.2.1".parse().unwrap());
        assert!(case.validate().unwrap_err().contains("overlapping"));
        case.expected.truncate(1);
        case.benign_hosts.push("::ffff:10.0.0.42".parse().unwrap());
        assert!(case
            .validate()
            .unwrap_err()
            .contains("also labelled benign"));
        case.expected.clear();
        case.benign_hosts.push("10.0.0.42".parse().unwrap());
        assert!(case.validate().unwrap_err().contains("duplicate benign"));
    }

    #[test]
    fn suite_validation_rejects_missing_identity_and_versions() {
        let mut suite = Suite {
            schema_version: 2,
            captures: vec![case(Vec::new())],
        };
        assert!(suite.validate().is_err());
        suite.schema_version = SCHEMA_VERSION;
        suite.captures.push(suite.captures[0].clone());
        assert!(suite
            .validate()
            .unwrap_err()
            .contains("duplicate capture name"));
        suite.captures.truncate(1);
        suite.captures[0].name.clear();
        assert!(suite.validate().is_err());
        suite.captures[0].name = "office".into();
        suite.captures[0].capture.clear();
        assert!(suite.validate().is_err());
        suite.captures.clear();
        assert!(suite.validate().is_err());
    }

    #[test]
    fn invalid_rule_ids_are_rejected_and_severity_round_trips() {
        for rule in ["", "th-0001", "TH-001", "TH-00001", "T-0001", "TH_0001"] {
            let case = case(vec![expectation(rule, "10.0.0.42", None)]);
            assert!(case.validate().is_err(), "accepted {rule:?}");
        }
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(severity.to_string().parse::<Severity>().unwrap(), severity);
        }
        assert!("HIGH".parse::<Severity>().is_err());
    }
}
