//! Label-scoped recall and explicitly reviewed benign monitoring exposure.

use crate::corpus::{BenignExposure, VerifiedCapture};
use crate::EvaluationReport;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuleMetrics {
    pub rule_id: String,
    pub labelled_behaviours: usize,
    pub matched_behaviours: usize,
    pub missed_behaviours: usize,
    pub labelled_recall: Option<f64>,
    pub unexpected_unique_findings: usize,
    pub labelled_benign_alert_records: usize,
    pub labelled_benign_unique_findings: usize,
    pub exposure_benign_alert_records: usize,
    pub exposure_benign_unique_findings: usize,
    pub monitored_benign_host_hours: Option<f64>,
    pub benign_alert_records_per_host_hour: Option<f64>,
    pub benign_unique_findings_per_host_hour: Option<f64>,
    pub exposure_cases: Vec<ExposureCase>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExposureCase {
    pub case_id: String,
    #[serde(flatten)]
    pub exposure: BenignExposure,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ValidationSummary {
    pub schema_version: u32,
    pub labelled_cases: usize,
    pub observation_only_cases: usize,
    pub per_rule: Vec<RuleMetrics>,
    pub interpretation: Vec<String>,
}

pub fn summarize(
    sources: &[VerifiedCapture],
    reports: &[EvaluationReport],
) -> Result<ValidationSummary, String> {
    let mut rules: BTreeMap<String, RuleMetrics> = BTreeMap::new();
    let mut labelled_cases = 0;
    let mut observation_only_cases = 0;
    for source in sources {
        let Some(case) = &source.case else {
            observation_only_cases += 1;
            continue;
        };
        let report = reports
            .iter()
            .find(|report| report.name == case.name)
            .ok_or_else(|| format!("missing evaluated case {}", case.name))?;
        if reports
            .iter()
            .filter(|report| report.name == case.name)
            .count()
            != 1
        {
            return Err(format!("duplicate evaluated case {}", case.name));
        }
        labelled_cases += 1;
        for expected in &case.expected {
            row(&mut rules, &expected.rule_id).labelled_behaviours += 1;
        }
        for matched in &report.matched_expectations {
            row(&mut rules, &matched.rule_id).matched_behaviours += 1;
        }
        for missed in &report.missed_expectations {
            row(&mut rules, &missed.rule_id).missed_behaviours += 1;
        }
        for finding in &report.unexpected_findings {
            row(&mut rules, &finding.alert.rule_id).unexpected_unique_findings += 1;
        }
        for finding in &report.benign_findings {
            let metric = row(&mut rules, &finding.alert.rule_id);
            metric.labelled_benign_alert_records += finding.occurrences;
            metric.labelled_benign_unique_findings += 1;
        }
        for exposure in &source.benign_exposure {
            if !case.benign_hosts.contains(&exposure.host)
                || !exposure.monitored_seconds.is_finite()
                || exposure.monitored_seconds <= 0.0
            {
                return Err(format!("unreviewed or invalid exposure for {}", case.name));
            }
            for rule_id in &exposure.rule_ids {
                let metric = row(&mut rules, rule_id);
                let hours = metric.monitored_benign_host_hours.get_or_insert(0.0);
                *hours += exposure.monitored_seconds / 3600.0;
                if !hours.is_finite() {
                    return Err("benign exposure overflow".into());
                }
                for finding in report.benign_findings.iter().filter(|finding| {
                    finding.alert.rule_id == *rule_id
                        && finding.alert.src.map(crate::canonical_ip)
                            == Some(crate::canonical_ip(exposure.host))
                }) {
                    metric.exposure_benign_alert_records += finding.occurrences;
                    metric.exposure_benign_unique_findings += 1;
                }
                metric.exposure_cases.push(ExposureCase {
                    case_id: case.name.clone(),
                    exposure: exposure.clone(),
                });
            }
        }
    }
    for metric in rules.values_mut() {
        if metric.matched_behaviours + metric.missed_behaviours != metric.labelled_behaviours {
            return Err(format!("inconsistent labels for {}", metric.rule_id));
        }
        metric.labelled_recall = ratio(metric.matched_behaviours, metric.labelled_behaviours);
        if let Some(hours) = metric.monitored_benign_host_hours {
            metric.benign_alert_records_per_host_hour =
                Some(metric.exposure_benign_alert_records as f64 / hours);
            metric.benign_unique_findings_per_host_hour =
                Some(metric.exposure_benign_unique_findings as f64 / hours);
        }
    }
    Ok(ValidationSummary {schema_version:1,labelled_cases,observation_only_cases,per_rule:rules.into_values().collect(),interpretation:vec![
        "Recall applies only to the supplied labelled behaviours for each rule, not all attacks in the traces or field malware recall.".into(),
        "Benign rates use only explicitly reviewed whole-capture monitored host windows and their declared observable rule scope; idle activity is not inferred from packet timestamps.".into(),
        "Repeated alert records and unique finding groups are reported separately. Neither host-hour rate is a true-negative-based false-positive probability.".into(),
        "Missing or unreviewed exposure produces null rates. Capture coverage, policy, severity floor, and stated source assumptions limit comparisons.".into(),
    ]})
}

fn row<'a>(rules: &'a mut BTreeMap<String, RuleMetrics>, rule: &str) -> &'a mut RuleMetrics {
    rules
        .entry(rule.to_string())
        .or_insert_with(|| RuleMetrics {
            rule_id: rule.to_string(),
            ..Default::default()
        })
}
fn ratio(a: usize, b: usize) -> Option<f64> {
    (b != 0).then(|| a as f64 / b as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{evaluate, CaptureCase, Severity};
    use serde_json::json;
    fn source(exposure: bool) -> VerifiedCapture {
        let case = CaptureCase {
            name: "reviewed normal".into(),
            capture: "normal.pcap".into(),
            expected: vec![],
            benign_hosts: vec!["10.0.0.1".parse().unwrap()],
            min_severity: Severity::Low,
        };
        VerifiedCapture {
            id: case.name.clone(),
            path: case.capture.clone(),
            sha256: "a".repeat(64),
            bytes: 64,
            source_url: "https://example.org/publisher".into(),
            license: "Research terms".into(),
            classification: "publisher normal".into(),
            description: "test metadata".into(),
            home_nets: None,
            case: Some(case),
            benign_exposure: if exposure {
                vec![BenignExposure {
                    host: "10.0.0.1".parse().unwrap(),
                    monitored_seconds: 60.0,
                    rule_ids: vec!["TH-0001".into()],
                    source_url: "https://example.org/publisher".into(),
                    basis: "Publisher's known monitoring interval".into(),
                    assumptions: vec!["Whole capture interval is monitored".into()],
                }]
            } else {
                vec![]
            },
        }
    }
    #[test]
    fn rates_use_only_reviewed_host_windows_and_separate_restatements() {
        let source = source(true);
        let alert: crate::Alert = serde_json::from_value(
            json!({"rule_id":"TH-0001","severity":"high","src":"10.0.0.1","evidence":{}}),
        )
        .unwrap();
        let report = evaluate(
            source.case.as_ref().unwrap(),
            &[alert.clone(), alert.clone(), alert],
        )
        .unwrap();
        let summary = summarize(&[source], &[report]).unwrap();
        let rule = &summary.per_rule[0];
        assert_eq!(rule.labelled_recall, None);
        assert_eq!(rule.exposure_benign_alert_records, 3);
        assert_eq!(rule.exposure_benign_unique_findings, 1);
        assert_eq!(rule.benign_alert_records_per_host_hour, Some(180.0));
        assert_eq!(rule.benign_unique_findings_per_host_hour, Some(60.0));
    }
    #[test]
    fn missing_exposure_never_invents_a_host_hour_denominator() {
        let source = source(false);
        let alert: crate::Alert = serde_json::from_value(
            json!({"rule_id":"TH-0001","severity":"high","src":"10.0.0.1","evidence":{}}),
        )
        .unwrap();
        let report = evaluate(source.case.as_ref().unwrap(), &[alert]).unwrap();
        let summary = summarize(&[source], &[report]).unwrap();
        assert_eq!(summary.per_rule[0].labelled_benign_alert_records, 1);
        assert_eq!(summary.per_rule[0].benign_alert_records_per_host_hour, None);
    }
}
