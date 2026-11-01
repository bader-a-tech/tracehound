use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tracehound_eval::runtime::{CaptureReport, JobReport};
use tracehound_eval::store::{compare, load_report, write_new, ReportDocument, ReportStore};
use tracehound_eval::suite::SuiteReport;
use tracehound_eval::{
    analyze, evaluate, Alert, CaptureCase, EvaluationReport, Expectation, Severity,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Directory {
    path: PathBuf,
    parent: PathBuf,
}
impl Directory {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let path = parent.join(format!(
            "tracehound store {} {} {}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self { path, parent }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if let Ok(path) = fs::canonicalize(&self.path) {
            if path.parent() == Some(self.parent.as_path())
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("tracehound store "))
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}

fn alert(rule: &str, source: &str, measurements: u32) -> Alert {
    serde_json::from_value(json!({"rule_id":rule,"severity":"high","src":source,"dst":"198.51.100.23","title":"Observed behaviour","evidence":{"observations":measurements}})).unwrap()
}

fn analysis(alerts: &[Alert]) -> CaptureReport {
    CaptureReport {
        capture: PathBuf::from("office capture.pcap"),
        report: analyze(alerts, Severity::Low).unwrap(),
        enrichment: json!({"packets":42}),
    }
}

fn evaluation(name: &str) -> EvaluationReport {
    let case = CaptureCase {
        name: name.into(),
        capture: format!("{name}.pcap").into(),
        expected: vec![Expectation {
            rule_id: "TH-0001".into(),
            src: "10.0.0.1".parse().unwrap(),
            dst: None,
        }],
        benign_hosts: Vec::new(),
        min_severity: Severity::Low,
    };
    evaluate(&case, &[alert("TH-0001", "10.0.0.1", 4)]).unwrap()
}

#[test]
fn analysis_evaluation_and_suite_round_trip_without_losing_evidence() {
    let directory = Directory::new();
    let documents = [
        serde_json::to_value(JobReport::Analysis(analysis(&[alert(
            "TH-0001", "10.0.0.1", 4,
        )])))
        .unwrap(),
        serde_json::to_value(JobReport::Evaluation(Box::new(evaluation("workstation")))).unwrap(),
        serde_json::to_value(SuiteReport::from_cases(vec![
            evaluation("first"),
            evaluation("second"),
        ]))
        .unwrap(),
    ];
    for (index, original) in documents.iter().enumerate() {
        let path = directory.path.join(format!("report-{index}.json"));
        write_new(&path, original).unwrap();
        let loaded = load_report(&path).unwrap();
        assert_eq!(serde_json::to_value(&loaded).unwrap(), *original);
        assert_eq!(loaded.single().is_some(), index != 2);
    }
    let before = fs::read(directory.path.join("report-0.json")).unwrap();
    assert!(write_new(&directory.path.join("report-0.json"), &json!({})).is_err());
    assert_eq!(
        fs::read(directory.path.join("report-0.json")).unwrap(),
        before
    );
}

#[test]
fn imported_reports_reject_unknown_versions_and_inconsistent_counters() {
    let original = serde_json::to_value(analysis(&[alert("TH-0001", "10.0.0.1", 4)])).unwrap();
    for (pointer, value) in [
        ("/schema_version", json!(2)),
        ("/mode", json!("other")),
        ("/total_alerts", json!(8)),
        ("/evaluated_alerts", json!(0)),
        ("/findings/0/occurrences", json!(0)),
        ("/findings/0/alert/rule_id", json!("")),
    ] {
        let mut tampered = original.clone();
        *tampered.pointer_mut(pointer).unwrap() = value;
        assert!(
            ReportDocument::from_value(tampered).is_err(),
            "accepted changed {pointer}"
        );
    }
    let original = serde_json::to_value(evaluation("workstation")).unwrap();
    for (pointer, value) in [
        ("/summary/matched_findings", json!(99)),
        ("/summary/precision", json!(0.1)),
        ("/summary/recall", json!(0.5)),
        ("/passed", json!(false)),
        ("/schema_version", json!(2)),
        ("/findings/0/alert/severity", json!("info")),
    ] {
        let mut tampered = original.clone();
        *tampered.pointer_mut(pointer).unwrap() = value;
        assert!(
            ReportDocument::from_value(tampered).is_err(),
            "accepted changed {pointer}"
        );
    }
    let mut suite = serde_json::to_value(SuiteReport::from_cases(vec![
        evaluation("first"),
        evaluation("second"),
    ]))
    .unwrap();
    suite["summary"]["captures"] = json!(1);
    assert!(ReportDocument::from_value(suite).is_err());
}

#[test]
fn private_history_lists_valid_entries_and_blocks_identifier_traversal() {
    let directory = Directory::new();
    let store = ReportStore::new(directory.path.join("history"));
    assert!(store.list().unwrap().is_empty());
    let saved = store
        .save(&analysis(&[alert("TH-0001", "10.0.0.1", 4)]))
        .unwrap();
    let evaluated = store.save(&evaluation("workstation")).unwrap();
    let suite = store
        .save(&SuiteReport::from_cases(vec![evaluation("first")]))
        .unwrap();
    fs::write(store.root().join("unrelated.txt"), b"not history").unwrap();
    fs::write(store.root().join("broken.meta"), b"{invalid JSON").unwrap();
    fs::write(store.root().join("123-456.meta"), serde_json::to_vec(&json!({"id":"123-456","saved_at_ms":1,"title":"missing report","mode":"analysis","findings":0})).unwrap()).unwrap();
    fs::write(store.root().join("traversal.meta"), serde_json::to_vec(&json!({"id":"../outside","saved_at_ms":1,"title":"outside","mode":"analysis","findings":0})).unwrap()).unwrap();
    let entries = store.list().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(store.open(&saved.id).unwrap().mode(), "analysis");
    assert_eq!(store.open(&evaluated.id).unwrap().mode(), "evaluation");
    assert_eq!(store.open(&suite.id).unwrap().mode(), "evaluation_suite");
    assert!(entries
        .windows(2)
        .all(|pair| pair[0].saved_at_ms >= pair[1].saved_at_ms));
    for id in [
        "",
        "../outside",
        "..\\outside",
        "/tmp/report",
        "C:\\report",
        "123.json",
        "123/456",
    ] {
        assert!(store.open(id).is_err(), "accepted identifier {id:?}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(store.root()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(store.root().join(format!("{}.json", saved.id)))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

fn document(alerts: &[Alert]) -> ReportDocument {
    ReportDocument::from_value(serde_json::to_value(analysis(alerts)).unwrap()).unwrap()
}

#[test]
fn comparison_separates_new_removed_changed_and_unchanged_findings() {
    let before = document(&[
        alert("TH-0001", "10.0.0.1", 4),
        alert("TH-0002", "10.0.0.2", 4),
        alert("TH-0003", "10.0.0.3", 4),
    ]);
    let after = document(&[
        alert("TH-0001", "10.0.0.1", 9),
        alert("TH-0003", "10.0.0.3", 4),
        alert("TH-0004", "10.0.0.4", 4),
    ]);
    let changes = compare(&before, &after);
    assert_eq!(changes.added.len(), 1);
    assert_eq!(changes.added[0].alert.rule_id, "TH-0004");
    assert_eq!(changes.removed.len(), 1);
    assert_eq!(changes.removed[0].alert.rule_id, "TH-0002");
    assert_eq!(changes.changed.len(), 1);
    assert_eq!(changes.changed[0].before.alert.evidence["observations"], 4);
    assert_eq!(changes.changed[0].after.alert.evidence["observations"], 9);
    assert_eq!(changes.unchanged, 1);
}

#[test]
fn suite_comparison_preserves_identical_keys_in_separate_cases() {
    let before = SuiteReport::from_cases(vec![evaluation("first"), evaluation("second")]);
    let mut after = before.clone();
    after.captures[0].findings[0].alert.evidence = json!({"observations": 8});
    let before = ReportDocument::from_value(serde_json::to_value(before).unwrap()).unwrap();
    let after = ReportDocument::from_value(serde_json::to_value(after).unwrap()).unwrap();
    let changes = compare(&before, &after);
    assert_eq!(changes.unchanged, 1);
    assert_eq!(changes.changed.len(), 1);
    assert!(changes.added.is_empty() && changes.removed.is_empty());
}

#[test]
fn corpus_reports_preserve_provenance_observations_and_contextual_comparisons() {
    use tracehound_eval::store::CorpusReport;
    let directory = Directory::new();
    let corpus = CorpusReport {
        schema_version: 1,
        mode: "corpus_evaluation".into(),
        sources: vec![
            json!({"id":"labelled","sha256":"a".repeat(64)}),
            json!({"id":"observed","sha256":"b".repeat(64)}),
        ],
        evaluation: SuiteReport::from_cases(vec![evaluation("labelled")]),
        observations: vec![analysis(&[alert("TH-0001", "10.0.0.1", 4)])],
        validation: None,
    };
    let value = serde_json::to_value(&corpus).unwrap();
    let document = ReportDocument::from_value(value.clone()).unwrap();
    assert_eq!(document.findings().len(), 2);
    let comparison = compare(&document, &document);
    assert_eq!(comparison.unchanged, 2);
    let path = directory.path.join("corpus.json");
    write_new(&path, &document).unwrap();
    assert_eq!(
        serde_json::to_value(load_report(&path).unwrap()).unwrap(),
        value
    );
    let store = ReportStore::new(directory.path.join("history"));
    let saved = store.save(&document).unwrap();
    assert_eq!(store.open(&saved.id).unwrap().mode(), "corpus_evaluation");
    let mut invalid = value;
    invalid["sources"][1]["id"] = json!("labelled");
    assert!(ReportDocument::from_value(invalid).is_err());
    let observed = CorpusReport {
        schema_version: 1,
        mode: "corpus_evaluation".into(),
        sources: vec![json!({"id":"only-observation","sha256":"c".repeat(64)})],
        evaluation: SuiteReport::from_cases(Vec::new()),
        observations: vec![analysis(&[])],
        validation: None,
    };
    assert!(ReportDocument::from_value(serde_json::to_value(observed).unwrap()).is_ok());
}
