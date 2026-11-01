//! Cancellable, one-pass Rust analysis and disk-backed investigation building.
use crate::capture;
use crate::investigation::{CaseBuilder, CaseOverview};
use crate::streaming::{StreamOptions, StreamingAnalyzer};
use serde::Serialize;
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationState {
    Indexing,
    Finalizing,
    Cancelling,
    Completed,
    Cancelled,
    TimedOut,
    Failed,
}
impl InvestigationState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::TimedOut | Self::Failed
        )
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct InvestigationSnapshot {
    pub state: InvestigationState,
    pub packets: u64,
    pub findings: u64,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}
type Outcome = Result<Arc<CaseOverview>, String>;
struct Data {
    state: InvestigationState,
    result: Option<Outcome>,
    elapsed_ms: u64,
}
struct Shared {
    data: Mutex<Data>,
    done: Condvar,
    phase: AtomicU8,
    packets: AtomicU64,
    findings: AtomicU64,
    started: Instant,
}
pub struct InvestigationJob {
    shared: Arc<Shared>,
}
impl InvestigationJob {
    pub fn start(
        source: PathBuf,
        destination: PathBuf,
        options: StreamOptions,
        timeout: Duration,
    ) -> Result<Self, String> {
        if options.local_live {
            return Err("file investigations cannot use local process telemetry".into());
        }
        if !source.is_file() {
            return Err("select an existing original capture".into());
        }
        if destination.exists() {
            return Err("investigation already exists; select a new destination".into());
        }
        // Reject invalid policies before a worker creates any case file.
        let analyzer = StreamingAnalyzer::new(options)?;
        let shared = Arc::new(Shared {
            data: Mutex::new(Data {
                state: InvestigationState::Indexing,
                result: None,
                elapsed_ms: 0,
            }),
            done: Condvar::new(),
            phase: AtomicU8::new(0),
            packets: AtomicU64::new(0),
            findings: AtomicU64::new(0),
            started: Instant::now(),
        });
        let worker = Arc::clone(&shared);
        thread::Builder::new()
            .name("host-investigation".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(source, destination, analyzer, timeout, &worker)
                }))
                .unwrap_or_else(|_| Err("investigation worker failed".into()));
                let cancelled = worker.phase.load(Ordering::Acquire) == 1;
                let timed_out =
                    result.is_err() && !timeout.is_zero() && worker.started.elapsed() >= timeout;
                let result = if cancelled {
                    Err("investigation cancelled".into())
                } else if timed_out {
                    Err("investigation timed out".into())
                } else {
                    result
                };
                let mut data = worker
                    .data
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                data.state = if cancelled {
                    InvestigationState::Cancelled
                } else if timed_out {
                    InvestigationState::TimedOut
                } else if result.is_ok() {
                    InvestigationState::Completed
                } else {
                    InvestigationState::Failed
                };
                data.elapsed_ms = elapsed(&worker);
                data.result = Some(result.map(Arc::new));
                drop(data);
                worker.done.notify_all();
            })
            .map_err(|e| format!("start investigation worker: {e}"))?;
        Ok(Self { shared })
    }
    pub fn cancel(&self) -> bool {
        let mut data = self
            .shared
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if data.state.is_terminal()
            || self
                .shared
                .phase
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return false;
        }
        data.state = InvestigationState::Cancelling;
        true
    }
    pub fn snapshot(&self) -> InvestigationSnapshot {
        let data = self
            .shared
            .data
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        InvestigationSnapshot {
            state: data.state,
            packets: self.shared.packets.load(Ordering::Relaxed),
            findings: self.shared.findings.load(Ordering::Relaxed),
            elapsed_ms: if data.state.is_terminal() {
                data.elapsed_ms
            } else {
                elapsed(&self.shared)
            },
            error: data
                .result
                .as_ref()
                .and_then(|result| result.as_ref().err().cloned()),
        }
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
impl Drop for InvestigationJob {
    fn drop(&mut self) {
        self.cancel();
    }
}
fn elapsed(shared: &Shared) -> u64 {
    shared
        .started
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
fn run(
    source: PathBuf,
    destination: PathBuf,
    mut analyzer: StreamingAnalyzer,
    timeout: Duration,
    shared: &Arc<Shared>,
) -> Result<CaseOverview, String> {
    let cancelled = || {
        shared.phase.load(Ordering::Acquire) == 1
            || (!timeout.is_zero() && shared.started.elapsed() >= timeout)
    };
    if cancelled() {
        return Err("investigation interrupted".into());
    }
    let mut builder = CaseBuilder::create(&source, &destination)?;
    let interrupt = Arc::clone(shared);
    builder.interrupt_when(move || {
        interrupt.phase.load(Ordering::Acquire) == 1
            || (!timeout.is_zero() && interrupt.started.elapsed() >= timeout)
    })?;
    let enrichment =
        capture::scan_capture_events(&source, None, &cancelled, &mut |packet, decoded| {
            if cancelled() {
                return Err("investigation interrupted".into());
            }
            builder.push(packet, decoded)?;
            analyzer.observe_ref(decoded)?;
            shared
                .packets
                .store(packet.reference.number, Ordering::Relaxed);
            shared
                .findings
                .store(analyzer.stats().findings as u64, Ordering::Relaxed);
            Ok(())
        })?;
    let summary = analyzer.finish()?;
    for finding in &summary.report.findings {
        if cancelled() {
            return Err("investigation interrupted".into());
        }
        builder.finding(finding)?;
    }
    if cancelled() {
        return Err("investigation interrupted".into());
    }
    let result=builder.finish_with_commit_guard(&enrichment,json!({"engine":"rust","metadata":summary.analysis_meta,"stats":summary.stats,"policy_notes":summary.policy_notes,"min_severity":summary.report.min_severity,"total_alerts":summary.report.total_alerts,"evaluated_alerts":summary.report.evaluated_alerts,"ignored_alerts":summary.report.ignored_alerts,"unique_findings":summary.report.findings.len()}),&mut||{
        if cancelled(){return Err("investigation interrupted before commit".into());}
        shared.phase.compare_exchange(0,2,Ordering::AcqRel,Ordering::Acquire).map_err(|_|"investigation cancelled before commit")?;
        shared.data.lock().unwrap_or_else(std::sync::PoisonError::into_inner).state=InvestigationState::Finalizing;Ok(())
    })?;
    shared
        .findings
        .store(summary.report.findings.len() as u64, Ordering::Relaxed);
    Ok(result)
}
