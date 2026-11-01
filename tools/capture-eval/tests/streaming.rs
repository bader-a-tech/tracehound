//! Streaming checks keep independent expected reports as well as comparing the
//! public batch adapters, so a shared implementation cannot hide changed results.

use serde_json::{json, Value};
use std::path::PathBuf;
use tracehound_eval::{
    analyze, evaluate, Alert, AlertAccumulator, CaptureCase, Expectation, Severity,
};

fn alert(value: Value) -> Alert {
    serde_json::from_value(value).unwrap()
}

fn mixed_alerts() -> Vec<Alert> {
    vec![
        alert(json!({
            "rule_id": "TH-0006", "severity": "info", "src": "10.0.0.50",
            "title": "New device", "evidence": {"first_seen": true}
        })),
        alert(json!({
            "rule_id": "TH-0003", "severity": "high", "src": "2001:db8::42",
            "dst": "2001:db8::10", "title": "Scan", "score": 0.8,
            "evidence": {"ports_probed": 32}, "custom_nested": {"values": [1, 2]}
        })),
        alert(json!({
            "rule_id": "TH-0001", "severity": "high", "src": "10.0.0.42",
            "dst": "198.51.100.23", "title": "Beacon", "score": 0.91,
            "description": "Regular timing", "evidence": {"connections": 8},
            "time": "2026-03-14T09:10:00Z", "proto": "tcp", "dst_port": 443
        })),
        alert(json!({
            "rule_id": "TH-0001", "severity": "medium", "src": "::ffff:10.0.0.42",
            "dst": "::ffff:198.51.100.23", "title": "Beacon updated", "score": 0.96,
            "evidence": {"connections": 12}, "time": "2026-03-14T09:12:00Z",
            "id": "observation-2", "proto": "tcp", "dst_port": 443,
            "detector": "beaconing", "techniques": [{"id": "T1071.001"}]
        })),
        alert(json!({
            "rule_id": "TH-0001", "severity": "low", "src": "10.0.0.42",
            "dst": "198.51.100.23", "title": "Below reporting floor",
            "evidence": {"connections": 1}
        })),
    ]
}

fn collect(records: &[Alert], minimum: Severity) -> AlertAccumulator {
    let mut accumulator = AlertAccumulator::new(minimum);
    for record in records {
        accumulator.push(record.clone()).unwrap();
    }
    accumulator
}

fn case(expected: Vec<Expectation>, minimum: Severity) -> CaptureCase {
    CaptureCase {
        name: "User capture".into(),
        capture: PathBuf::from("captures/office.pcapng"),
        expected,
        benign_hosts: Vec::new(),
        min_severity: minimum,
    }
}

fn expectation(rule_id: &str, src: &str, dst: Option<&str>) -> Expectation {
    Expectation {
        rule_id: rule_id.into(),
        src: src.parse().unwrap(),
        dst: dst.map(|value| value.parse().unwrap()),
    }
}

#[test]
fn streaming_preserves_independent_report_shape_and_latest_eligible_evidence() {
    let records = mixed_alerts();
    let collected = collect(&records, Severity::Medium);
    assert_eq!(collected.total_alerts(), 5);
    assert_eq!(collected.evaluated_alerts(), 3);
    assert_eq!(collected.unique_findings(), 2);
    assert_eq!(
        serde_json::to_value(collected.finish()).unwrap(),
        json!({
            "schema_version": 1,
            "mode": "analysis",
            "min_severity": "medium",
            "total_alerts": 5,
            "evaluated_alerts": 3,
            "ignored_alerts": 2,
            "findings": [
                {
                    "alert": {
                        "rule_id": "TH-0001", "severity": "medium",
                        "src": "::ffff:10.0.0.42", "dst": "::ffff:198.51.100.23",
                        "title": "Beacon updated", "score": 0.96,
                        "evidence": {"connections": 12}, "time": "2026-03-14T09:12:00Z",
                        "id": "observation-2", "proto": "tcp", "dst_port": 443,
                        "detector": "beaconing", "techniques": [{"id": "T1071.001"}]
                    },
                    "occurrences": 2
                },
                {
                    "alert": {
                        "rule_id": "TH-0003", "severity": "high", "src": "2001:db8::42",
                        "dst": "2001:db8::10", "title": "Scan", "score": 0.8,
                        "evidence": {"ports_probed": 32}, "custom_nested": {"values": [1, 2]}
                    },
                    "occurrences": 1
                }
            ]
        })
    );
}

#[test]
fn streamed_and_batch_evaluation_agree_on_matches_misses_and_benign_violations() {
    let records = mixed_alerts();
    assert_eq!(
        serde_json::to_value(collect(&records, Severity::Medium).finish()).unwrap(),
        serde_json::to_value(analyze(&records, Severity::Medium).unwrap()).unwrap()
    );
    let mut labels = case(
        vec![
            expectation("TH-0001", "10.0.0.42", None),
            expectation("TH-0002", "10.0.0.66", Some("10.0.0.1")),
        ],
        Severity::Medium,
    );
    labels.benign_hosts.push("2001:db8::42".parse().unwrap());
    let streamed = collect(&records, Severity::Medium)
        .finish_evaluation(&labels)
        .unwrap();
    assert!(!streamed.passed);
    assert_eq!(
        serde_json::to_value(&streamed).unwrap(),
        serde_json::to_value(evaluate(&labels, &records).unwrap()).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&streamed.summary).unwrap(),
        json!({
            "expected_total": 2,
            "matched_expectations": 1,
            "missed_expectations": 1,
            "unique_findings": 2,
            "matched_findings": 1,
            "unexpected_findings": 1,
            "benign_findings": 1,
            "precision": 0.5,
            "recall": 0.5
        })
    );
    assert_eq!(streamed.matched_expectations[0].rule_id, "TH-0001");
    assert_eq!(streamed.missed_expectations[0].rule_id, "TH-0002");
    assert_eq!(streamed.unexpected_findings[0].alert.rule_id, "TH-0003");
    assert_eq!(streamed.benign_findings[0].alert.rule_id, "TH-0003");
}

#[test]
fn wildcard_and_negative_cases_keep_metric_denominators_explicit() {
    let records = [
        alert(
            json!({"rule_id":"TH-0001", "severity":"high", "src":"10.0.0.42", "dst":"198.51.100.23"}),
        ),
        alert(
            json!({"rule_id":"TH-0001", "severity":"high", "src":"10.0.0.42", "dst":"198.51.100.24"}),
        ),
    ];
    let labels = case(
        vec![expectation("TH-0001", "10.0.0.42", None)],
        Severity::Low,
    );
    let report = collect(&records, Severity::Low)
        .finish_evaluation(&labels)
        .unwrap();
    assert!(report.passed);
    assert_eq!(report.summary.expected_total, 1);
    assert_eq!(report.summary.matched_expectations, 1);
    assert_eq!(report.summary.matched_findings, 2);
    assert_eq!(report.summary.precision, Some(1.0));
    assert_eq!(report.summary.recall, Some(1.0));
    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        serde_json::to_value(evaluate(&labels, &records).unwrap()).unwrap()
    );

    let negative = case(Vec::new(), Severity::Low);
    let empty = AlertAccumulator::new(Severity::Low)
        .finish_evaluation(&negative)
        .unwrap();
    assert!(empty.passed);
    assert_eq!(
        serde_json::to_value(&empty.summary).unwrap(),
        json!({
            "expected_total": 0, "matched_expectations": 0, "missed_expectations": 0,
            "unique_findings": 0, "matched_findings": 0, "unexpected_findings": 0,
            "benign_findings": 0, "precision": null, "recall": null
        })
    );
    assert_eq!(
        serde_json::to_value(&empty).unwrap(),
        serde_json::to_value(evaluate(&negative, &[]).unwrap()).unwrap()
    );
    let unexpected = collect(&records, Severity::Low)
        .finish_evaluation(&negative)
        .unwrap();
    assert!(!unexpected.passed);
    assert_eq!(unexpected.summary.unexpected_findings, 2);
    assert_eq!(unexpected.summary.precision, Some(0.0));
    assert_eq!(unexpected.summary.recall, None);
}

#[test]
fn invalid_eligible_push_is_transactional_and_evaluation_requires_the_same_floor() {
    let original = alert(json!({
        "rule_id":"TH-0001", "severity":"high", "src":"10.0.0.42",
        "evidence":{"observations":8}
    }));
    let mut accumulator = AlertAccumulator::new(Severity::Medium);
    accumulator.push(original.clone()).unwrap();
    // Ignored records still count toward input limits, but are not required to
    // contain the eligible finding fields and cannot replace retained evidence.
    accumulator
        .push(alert(json!({"rule_id":"", "severity":"info"})))
        .unwrap();
    let invalid = [
        alert(json!({"rule_id":"TH-0001", "severity":"high", "evidence":{"observations":100}})),
        alert(json!({"rule_id":"TH-0001", "severity":"high", "src":"10.0.0.42", "score":1.5})),
        alert(json!({"rule_id":"", "severity":"high", "src":"10.0.0.42"})),
    ];
    for record in invalid {
        assert!(accumulator.push(record).is_err());
        assert_eq!(accumulator.total_alerts(), 2);
        assert_eq!(accumulator.evaluated_alerts(), 1);
        assert_eq!(accumulator.unique_findings(), 1);
    }
    let result = accumulator.finish();
    assert_eq!(result.ignored_alerts, 1);
    assert_eq!(result.findings[0].occurrences, 1);
    assert_eq!(result.findings[0].alert, original);

    let mismatched = case(Vec::new(), Severity::High);
    let error = AlertAccumulator::new(Severity::Medium)
        .finish_evaluation(&mismatched)
        .unwrap_err();
    assert!(error.contains("severity floor"));
}

#[test]
fn a_large_repeated_stream_retains_one_finding_without_collecting_input_records() {
    let mut accumulator = AlertAccumulator::new(Severity::Low);
    let mut record = alert(json!({
        "rule_id":"TH-0001", "severity":"high", "src":"10.0.0.42",
        "dst":"198.51.100.23", "evidence":{"observations":0}
    }));
    for observations in 1..=100_000 {
        record.evidence["observations"] = json!(observations);
        accumulator.push(record.clone()).unwrap();
    }
    assert_eq!(accumulator.total_alerts(), 100_000);
    assert_eq!(accumulator.evaluated_alerts(), 100_000);
    assert_eq!(accumulator.unique_findings(), 1);
    let report = accumulator.finish();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].occurrences, 100_000);
    assert_eq!(report.findings[0].alert.evidence["observations"], 100_000);
}
