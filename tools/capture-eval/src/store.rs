//! Versioned report loading, private local history, and capture comparisons.
use crate::runtime::{CaptureReport, JobReport};
use crate::suite::SuiteReport;
use crate::{AnalysisReport, EvaluationReport, Finding};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_REPORT: u64 = 256 * 1024 * 1024;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CorpusReport {
    pub schema_version: u32,
    pub mode: String,
    pub sources: Vec<Value>,
    pub evaluation: SuiteReport,
    pub observations: Vec<CaptureReport>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ReportDocument {
    Analysis(CaptureReport),
    Evaluation(Box<EvaluationReport>),
    Suite(Box<SuiteReport>),
    Corpus(Box<CorpusReport>),
}
impl ReportDocument {
    pub fn from_value(value: Value) -> Result<Self, String> {
        if value.get("schema_version").and_then(Value::as_u64) != Some(1) {
            return Err("unsupported report schema_version; expected 1".into());
        }
        let document = match value.get("mode").and_then(Value::as_str) {
            Some("analysis") => Self::Analysis(
                serde_json::from_value(value)
                    .map_err(|e| format!("invalid analysis report: {e}"))?,
            ),
            Some("evaluation") => Self::Evaluation(Box::new(
                serde_json::from_value(value)
                    .map_err(|e| format!("invalid evaluation report: {e}"))?,
            )),
            Some("evaluation_suite") => Self::Suite(Box::new(
                serde_json::from_value(value).map_err(|e| format!("invalid suite report: {e}"))?,
            )),
            Some("corpus_evaluation") => Self::Corpus(Box::new(
                serde_json::from_value(value).map_err(|e| format!("invalid corpus report: {e}"))?,
            )),
            _ => return Err("unrecognised report mode".into()),
        };
        match &document {
            Self::Analysis(report) => validate_analysis(&report.report)?,
            Self::Evaluation(report) => validate_evaluation(report)?,
            Self::Suite(report) => {
                if report.captures.is_empty() {
                    return Err("suite report has no captures".into());
                }
                let mut names = BTreeSet::new();
                let mut totals = [0usize; 8];
                for case in &report.captures {
                    validate_evaluation(case)?;
                    if !names.insert(&case.name) {
                        return Err("suite contains duplicate case names".into());
                    }
                    for (total, count) in totals.iter_mut().zip([
                        case.summary.expected_total,
                        case.summary.matched_expectations,
                        case.summary.missed_expectations,
                        case.summary.unique_findings,
                        case.summary.matched_findings,
                        case.summary.unexpected_findings,
                        case.summary.benign_findings,
                        1,
                    ]) {
                        *total = total
                            .checked_add(count)
                            .ok_or("suite report count overflow")?;
                    }
                }
                let expected = SuiteReport::from_cases(report.captures.clone());
                if serde_json::to_value(&report.summary).map_err(|e| e.to_string())?
                    != serde_json::to_value(&expected.summary).map_err(|e| e.to_string())?
                    || report.passed != expected.passed
                {
                    return Err("suite summary does not match its case reports".into());
                }
            }
            Self::Corpus(report) => {
                if report.sources.is_empty()
                    || report.sources.len()
                        != report.evaluation.captures.len() + report.observations.len()
                {
                    return Err("corpus sources do not match its capture reports".into());
                }
                let mut ids = BTreeSet::new();
                for source in &report.sources {
                    let id = source
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|v| !v.trim().is_empty())
                        .ok_or("corpus source lacks an id")?;
                    if !ids.insert(id) {
                        return Err("duplicate corpus source id".into());
                    }
                    let hash = source
                        .get("sha256")
                        .and_then(Value::as_str)
                        .ok_or("corpus source lacks a digest")?;
                    if hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit()) {
                        return Err("invalid corpus source digest".into());
                    }
                }
                if report.evaluation.captures.is_empty() {
                    let expected = SuiteReport::from_cases(Vec::new());
                    if serde_json::to_value(&report.evaluation).map_err(|e| e.to_string())?
                        != serde_json::to_value(expected).map_err(|e| e.to_string())?
                    {
                        return Err("invalid empty corpus evaluation".into());
                    }
                } else {
                    Self::from_value(
                        serde_json::to_value(&report.evaluation).map_err(|e| e.to_string())?,
                    )?;
                }
                let mut paths = BTreeSet::new();
                for capture in &report.observations {
                    validate_analysis(&capture.report)?;
                    if !paths.insert(&capture.capture) {
                        return Err("duplicate corpus observation path".into());
                    }
                }
            }
        }
        Ok(document)
    }
    pub fn single(&self) -> Option<JobReport> {
        match self {
            Self::Analysis(report) => Some(JobReport::Analysis(report.clone())),
            Self::Evaluation(report) => Some(JobReport::Evaluation(report.clone())),
            Self::Suite(_) | Self::Corpus(_) => None,
        }
    }
    pub fn mode(&self) -> &'static str {
        match self {
            Self::Analysis(_) => "analysis",
            Self::Evaluation(_) => "evaluation",
            Self::Suite(_) => "evaluation_suite",
            Self::Corpus(_) => "corpus_evaluation",
        }
    }
    pub fn findings(&self) -> Vec<&Finding> {
        match self {
            Self::Analysis(report) => report.report.findings.iter().collect(),
            Self::Evaluation(report) => report.findings.iter().collect(),
            Self::Suite(report) => report
                .captures
                .iter()
                .flat_map(|case| case.findings.iter())
                .collect(),
            Self::Corpus(report) => report
                .evaluation
                .captures
                .iter()
                .flat_map(|case| case.findings.iter())
                .chain(
                    report
                        .observations
                        .iter()
                        .flat_map(|capture| capture.report.findings.iter()),
                )
                .collect(),
        }
    }
    pub fn title(&self) -> String {
        match self {
            Self::Analysis(report) => report.capture.display().to_string(),
            Self::Evaluation(report) => report.name.clone(),
            Self::Suite(report) => format!("{} evaluated captures", report.captures.len()),
            Self::Corpus(report) => format!("{} verified corpus sources", report.sources.len()),
        }
    }
}

fn validate_analysis(report: &AnalysisReport) -> Result<(), String> {
    if report.schema_version != 1
        || report.mode != "analysis"
        || report.evaluated_alerts.checked_add(report.ignored_alerts) != Some(report.total_alerts)
    {
        return Err("inconsistent analysis report counters or version".into());
    }
    if report
        .findings
        .iter()
        .any(|f| f.alert.severity < report.min_severity)
    {
        return Err("finding is below the report severity floor".into());
    }
    validate_findings(&report.findings, report.evaluated_alerts)
}
fn validate_evaluation(report: &EvaluationReport) -> Result<(), String> {
    if report.schema_version != 1
        || report.mode != "evaluation"
        || report.evaluated_alerts.checked_add(report.ignored_alerts) != Some(report.total_alerts)
        || report.summary.unique_findings != report.findings.len()
        || report.summary.expected_total
            != report.matched_expectations.len() + report.missed_expectations.len()
        || report.summary.matched_expectations != report.matched_expectations.len()
        || report.summary.missed_expectations != report.missed_expectations.len()
        || report.summary.unexpected_findings != report.unexpected_findings.len()
        || report.summary.benign_findings != report.benign_findings.len()
        || report.passed
            != (report.missed_expectations.is_empty() && report.unexpected_findings.is_empty())
    {
        return Err("inconsistent evaluation report counters or version".into());
    }
    validate_findings(&report.findings, report.evaluated_alerts)?;
    let mut expected = report.matched_expectations.clone();
    expected.extend(report.missed_expectations.iter().cloned());
    let case = crate::CaptureCase {
        name: report.name.clone(),
        capture: report.capture.clone(),
        min_severity: report.min_severity,
        expected,
        benign_hosts: report
            .benign_findings
            .iter()
            .filter_map(|f| f.alert.src)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    };
    case.validate()?;
    if report
        .findings
        .iter()
        .any(|f| f.alert.severity < report.min_severity)
    {
        return Err("finding is below the report severity floor".into());
    }
    let recomputed = crate::evaluate_analysis(
        &case,
        AnalysisReport {
            schema_version: 1,
            mode: "analysis".into(),
            min_severity: report.min_severity,
            total_alerts: report.total_alerts,
            evaluated_alerts: report.evaluated_alerts,
            ignored_alerts: report.ignored_alerts,
            findings: report.findings.clone(),
        },
    );
    for (provided, calculated) in [
        (
            serde_json::to_value(&report.summary),
            serde_json::to_value(&recomputed.summary),
        ),
        (
            serde_json::to_value(&report.matched_expectations),
            serde_json::to_value(&recomputed.matched_expectations),
        ),
        (
            serde_json::to_value(&report.missed_expectations),
            serde_json::to_value(&recomputed.missed_expectations),
        ),
        (
            serde_json::to_value(&report.unexpected_findings),
            serde_json::to_value(&recomputed.unexpected_findings),
        ),
        (
            serde_json::to_value(&report.benign_findings),
            serde_json::to_value(&recomputed.benign_findings),
        ),
    ] {
        if provided.map_err(|e| e.to_string())? != calculated.map_err(|e| e.to_string())? {
            return Err(
                "evaluation measurements or classifications do not match findings and labels"
                    .into(),
            );
        }
    }
    Ok(())
}
fn validate_findings(findings: &[Finding], evaluated: usize) -> Result<(), String> {
    let mut total = 0usize;
    let mut keys = BTreeSet::new();
    for finding in findings {
        if finding.occurrences == 0 {
            return Err("finding has zero occurrences".into());
        }
        crate::validate_alert(&finding.alert)?;
        if !keys.insert(crate::finding_key(&finding.alert)) {
            return Err("report contains duplicate finding groups".into());
        }
        total = total
            .checked_add(finding.occurrences)
            .ok_or("report occurrence count overflow")?;
    }
    if total != evaluated {
        return Err("finding occurrences do not match evaluated alert count".into());
    }
    Ok(())
}

pub fn load_report(path: &Path) -> Result<ReportDocument, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| format!("read report {}: {e}", path.display()))?
        .take(MAX_REPORT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read report: {e}"))?;
    if bytes.len() as u64 > MAX_REPORT {
        return Err("report exceeds 256 MiB loading limit".into());
    }
    let value = serde_json::from_slice(&bytes).map_err(|e| format!("invalid report JSON: {e}"))?;
    ReportDocument::from_value(value)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HistoryEntry {
    pub id: String,
    pub saved_at_ms: u64,
    pub title: String,
    pub mode: String,
    pub findings: usize,
}
#[derive(Clone, Debug)]
pub struct ReportStore {
    root: PathBuf,
}
impl ReportStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
    pub fn default_location() -> Self {
        let base = std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("XDG_STATE_HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(std::env::temp_dir)
                    .join(".local/state")
            });
        Self::new(base.join("tracehound/reports"))
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn save(&self, report: &impl Serialize) -> Result<HistoryEntry, String> {
        let value = serde_json::to_value(report).map_err(|e| e.to_string())?;
        let document = ReportDocument::from_value(value)?;
        fs::create_dir_all(&self.root).map_err(|e| format!("create report history: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let saved_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let id = format!(
            "{saved_at_ms}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let entry = HistoryEntry {
            id: id.clone(),
            saved_at_ms,
            title: document.title(),
            mode: document.mode().into(),
            findings: document.findings().len(),
        };
        write_new(&self.root.join(format!("{id}.json")), &document)?;
        write_new(&self.root.join(format!("{id}.meta")), &entry)?;
        Ok(entry)
    }
    pub fn list(&self) -> Result<Vec<HistoryEntry>, String> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for file in fs::read_dir(&self.root).map_err(|e| e.to_string())? {
            let file = file.map_err(|e| e.to_string())?;
            if file.path().extension().and_then(|v| v.to_str()) != Some("meta") {
                continue;
            }
            if file.metadata().map_err(|e| e.to_string())?.len() > 65536 {
                continue;
            }
            let entry: HistoryEntry =
                match serde_json::from_slice(&fs::read(file.path()).map_err(|e| e.to_string())?) {
                    Ok(entry) => entry,
                    Err(_) => continue,
                };
            if valid_id(&entry.id) && self.root.join(format!("{}.json", entry.id)).is_file() {
                entries.push(entry);
            }
        }
        entries.sort_by(|a, b| {
            b.saved_at_ms
                .cmp(&a.saved_at_ms)
                .then_with(|| b.id.cmp(&a.id))
        });
        Ok(entries)
    }
    pub fn open(&self, id: &str) -> Result<ReportDocument, String> {
        if !valid_id(id) {
            return Err("invalid history identifier".into());
        }
        load_report(&self.root.join(format!("{id}.json")))
    }
}
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() < 128 && id.bytes().all(|b| b.is_ascii_digit() || b == b'-')
}

pub fn write_new(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let text = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    let result = file
        .write_all(&text)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write report: {e}"));
    drop(file);
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

#[derive(Clone, Debug, Serialize)]
pub struct ComparedFinding {
    pub case: Option<String>,
    #[serde(flatten)]
    pub finding: Finding,
}
impl std::ops::Deref for ComparedFinding {
    type Target = Finding;
    fn deref(&self) -> &Finding {
        &self.finding
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct ChangedFinding {
    pub case: Option<String>,
    pub before: Finding,
    pub after: Finding,
}
#[derive(Clone, Debug, Serialize)]
pub struct ReportComparison {
    pub added: Vec<ComparedFinding>,
    pub removed: Vec<ComparedFinding>,
    pub changed: Vec<ChangedFinding>,
    pub unchanged: usize,
}
pub fn compare(before: &ReportDocument, after: &ReportDocument) -> ReportComparison {
    fn indexed(
        document: &ReportDocument,
    ) -> BTreeMap<(Option<String>, crate::FindingKey), &Finding> {
        match document {
            ReportDocument::Suite(suite) => suite
                .captures
                .iter()
                .flat_map(|case| {
                    case.findings.iter().map(move |finding| {
                        (
                            (Some(case.name.clone()), crate::finding_key(&finding.alert)),
                            finding,
                        )
                    })
                })
                .collect(),
            ReportDocument::Corpus(corpus) => corpus
                .evaluation
                .captures
                .iter()
                .flat_map(|case| {
                    case.findings.iter().map(move |finding| {
                        (
                            (Some(case.name.clone()), crate::finding_key(&finding.alert)),
                            finding,
                        )
                    })
                })
                .chain(corpus.observations.iter().flat_map(|capture| {
                    capture.report.findings.iter().map(move |finding| {
                        (
                            (
                                Some(format!("observation: {}", capture.capture.display())),
                                crate::finding_key(&finding.alert),
                            ),
                            finding,
                        )
                    })
                }))
                .collect(),
            _ => document
                .findings()
                .into_iter()
                .map(|finding| ((None, crate::finding_key(&finding.alert)), finding))
                .collect(),
        }
    }
    let old = indexed(before);
    let new = indexed(after);
    let mut out = ReportComparison {
        added: Vec::new(),
        removed: Vec::new(),
        changed: Vec::new(),
        unchanged: 0,
    };
    for (key, finding) in &new {
        match old.get(key) {
            None => out.added.push(ComparedFinding {
                case: key.0.clone(),
                finding: (*finding).clone(),
            }),
            Some(previous)
                if previous.alert != finding.alert
                    || previous.occurrences != finding.occurrences =>
            {
                out.changed.push(ChangedFinding {
                    case: key.0.clone(),
                    before: (**previous).clone(),
                    after: (*finding).clone(),
                })
            }
            Some(_) => out.unchanged += 1,
        }
    }
    for (key, finding) in old {
        if !new.contains_key(&key) {
            out.removed.push(ComparedFinding {
                case: key.0,
                finding: finding.clone(),
            });
        }
    }
    out
}
