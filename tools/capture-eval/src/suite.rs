//! Sequential labelled evaluation with cancellable, GUI-friendly progress.
use crate::runtime::{validate_capture, CaptureJob, JobReport, SensorOptions};
use crate::{EvaluationReport, Suite};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SuiteSummary {
    pub captures: usize,
    pub passed: usize,
    pub failed: usize,
    pub expected_total: usize,
    pub matched_expectations: usize,
    pub missed_expectations: usize,
    pub unique_findings: usize,
    pub matched_findings: usize,
    pub unexpected_findings: usize,
    pub benign_findings: usize,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SuiteReport {
    pub schema_version: u32,
    pub mode: String,
    pub passed: bool,
    pub summary: SuiteSummary,
    pub captures: Vec<EvaluationReport>,
}

impl SuiteReport {
    pub fn from_cases(captures: Vec<EvaluationReport>) -> Self {
        let mut summary = SuiteSummary {
            captures: captures.len(),
            ..Default::default()
        };
        for case in &captures {
            summary.passed += usize::from(case.passed);
            summary.failed += usize::from(!case.passed);
            summary.expected_total += case.summary.expected_total;
            summary.matched_expectations += case.summary.matched_expectations;
            summary.missed_expectations += case.summary.missed_expectations;
            summary.unique_findings += case.summary.unique_findings;
            summary.matched_findings += case.summary.matched_findings;
            summary.unexpected_findings += case.summary.unexpected_findings;
            summary.benign_findings += case.summary.benign_findings;
        }
        summary.precision = ratio(summary.matched_findings, summary.unique_findings);
        summary.recall = ratio(summary.matched_expectations, summary.expected_total);
        Self {
            schema_version: 1,
            mode: "evaluation_suite".into(),
            passed: summary.failed == 0,
            summary,
            captures,
        }
    }
}

fn ratio(n: usize, d: usize) -> Option<f64> {
    (d != 0).then(|| n as f64 / d as f64)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuiteState {
    Running,
    Cancelling,
    Completed,
    Cancelled,
    Failed,
}
impl SuiteState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SuiteSnapshot {
    pub state: SuiteState,
    pub total: usize,
    pub completed: usize,
    pub current: Option<String>,
    pub alert_records: usize,
    pub unique_findings: usize,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}
type Outcome = Result<Arc<SuiteReport>, String>;
struct Data {
    snapshot: SuiteSnapshot,
    result: Option<Outcome>,
}
struct Shared {
    data: Mutex<Data>,
    done: Condvar,
    cancel: AtomicBool,
    started: Instant,
}
pub struct SuiteJob {
    shared: Arc<Shared>,
}

pub fn load_suite(path: &Path) -> Result<Suite, String> {
    if fs::metadata(path)
        .map_err(|e| format!("read suite: {e}"))?
        .len()
        > 16 * 1024 * 1024
    {
        return Err("suite manifest exceeds 16 MiB".into());
    }
    let suite: Suite =
        serde_json::from_slice(&fs::read(path).map_err(|e| format!("read suite: {e}"))?)
            .map_err(|e| format!("invalid suite: {e}"))?;
    suite.validate()?;
    if suite.captures.len() > 10_000 {
        return Err("suite contains more than 10000 captures".into());
    }
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    for case in &suite.captures {
        validate_capture(&base.join(&case.capture)).map_err(|e| e.to_string())?;
    }
    Ok(suite)
}

impl SuiteJob {
    pub fn start(path: PathBuf, options: SensorOptions) -> Result<Self, String> {
        let suite = load_suite(&path)?;
        let shared = Arc::new(Shared {
            data: Mutex::new(Data {
                snapshot: SuiteSnapshot {
                    state: SuiteState::Running,
                    total: suite.captures.len(),
                    completed: 0,
                    current: None,
                    alert_records: 0,
                    unique_findings: 0,
                    elapsed_ms: 0,
                    error: None,
                },
                result: None,
            }),
            done: Condvar::new(),
            cancel: AtomicBool::new(false),
            started: Instant::now(),
        });
        let worker = Arc::clone(&shared);
        thread::Builder::new()
            .name("capture-suite".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_suite(&path, suite, options, &worker)
                }))
                .unwrap_or_else(|_| Err("suite worker failed".into()));
                let mut data = worker
                    .data
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let result = if worker.cancel.load(Ordering::Acquire) {
                    Err("suite cancelled".into())
                } else {
                    result
                };
                data.snapshot.state = if worker.cancel.load(Ordering::Acquire) {
                    SuiteState::Cancelled
                } else if result.is_ok() {
                    SuiteState::Completed
                } else {
                    SuiteState::Failed
                };
                data.snapshot.error = result.as_ref().err().cloned();
                data.snapshot.elapsed_ms = worker
                    .started
                    .elapsed()
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64;
                data.result = Some(result.map(Arc::new));
                drop(data);
                worker.done.notify_all();
            })
            .map_err(|e| format!("start suite worker: {e}"))?;
        Ok(Self { shared })
    }
    pub fn snapshot(&self) -> SuiteSnapshot {
        let mut out = self
            .shared
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot
            .clone();
        if !out.state.is_terminal() {
            out.elapsed_ms = self
                .shared
                .started
                .elapsed()
                .as_millis()
                .min(u128::from(u64::MAX)) as u64;
        }
        out
    }
    pub fn cancel(&self) -> bool {
        let mut data = self
            .shared
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if data.snapshot.state.is_terminal() {
            return false;
        }
        self.shared.cancel.store(true, Ordering::Release);
        data.snapshot.state = SuiteState::Cancelling;
        true
    }
    pub fn try_result(&self) -> Option<Outcome> {
        self.shared
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .result
            .clone()
    }
    pub fn wait(&self) -> Outcome {
        let mut data = self
            .shared
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
}
impl Drop for SuiteJob {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn run_suite(
    path: &Path,
    suite: Suite,
    options: SensorOptions,
    shared: &Shared,
) -> Result<SuiteReport, String> {
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let mut reports = Vec::new();
    let mut records = 0;
    let mut findings = 0;
    for case in suite.captures {
        if shared.cancel.load(Ordering::Acquire) {
            return Err("suite cancelled".into());
        }
        shared
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot
            .current = Some(case.name.clone());
        let job = CaptureJob::evaluate(base.join(&case.capture), options.clone(), case.clone())
            .map_err(|e| e.to_string())?;
        let result = loop {
            if shared.cancel.load(Ordering::Acquire) {
                job.cancel();
            }
            let progress = job.snapshot();
            {
                let mut data = shared
                    .data
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                data.snapshot.alert_records = records + progress.alert_records;
                data.snapshot.unique_findings = findings + progress.unique_findings;
            }
            if let Some(result) = job.try_result() {
                break result.map_err(|e| format!("case {}: {e}", case.name))?;
            }
            thread::sleep(Duration::from_millis(25));
        };
        let JobReport::Evaluation(report) = result.as_ref() else {
            return Err("suite received an invalid report type".into());
        };
        records += job.snapshot().alert_records;
        findings += report.findings.len();
        reports.push(report.as_ref().clone());
        let mut data = shared
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        data.snapshot.completed += 1;
        data.snapshot.current = None;
        data.snapshot.alert_records = records;
        data.snapshot.unique_findings = findings;
    }
    Ok(SuiteReport::from_cases(reports))
}
