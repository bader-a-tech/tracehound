#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use eframe::egui::{self, Color32, RichText};
use serde_json::Value;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;
use tracehound_eval::feed::{self, PairFeed};
use tracehound_eval::live::{
    self, CaptureInterface, LiveSession, LiveSnapshot, PortableRecording, RecordingLimits,
    RecordingState,
};
use tracehound_eval::runtime::{AnalysisEngine, CaptureJob, JobReport, SensorOptions};
use tracehound_eval::store::{self, HistoryEntry, ReportComparison, ReportDocument, ReportStore};
use tracehound_eval::streaming::{
    RustLiveOptions, RustLiveSession, RustLiveSnapshot, RustLiveState, StreamOptions, StreamSummary,
};
use tracehound_eval::suite::{SuiteJob, SuiteReport};
use tracehound_eval::{EvaluationReport, Finding, Severity};
#[path = "desktop/beacon.rs"]
mod beacon_ui;
#[path = "desktop/investigation.rs"]
mod investigation_ui;
#[path = "desktop/smoke.rs"]
mod native_smoke;
use investigation_ui::{CasePath, InvestigationUi};

fn main() -> eframe::Result {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("Tracehound desktop\nUsage: tracehound-desktop [CAPTURE]\n       tracehound-desktop --smoke-test [--smoke-timeout SECONDS]\n       tracehound-desktop --smoke-case CASE.db --smoke-output NEW.png --smoke-exit\n\nA startup capture is selected without automatic analysis. Smoke modes explicitly render a native window, then exit; case screenshots require a new output path.");
        return Ok(());
    }
    if args.len() == 1 && args[0] == "--version" {
        println!("Tracehound desktop {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let startup = match native_smoke::parse(args) {
        Ok(startup) => startup,
        Err(error) => {
            eprintln!("Tracehound: {error}");
            std::process::exit(2);
        }
    };
    let outcome = startup
        .smoke
        .as_ref()
        .map(|_| Arc::new(std::sync::atomic::AtomicI32::new(2)));
    let smoke_outcome = outcome.clone();
    let result = eframe::run_native(
        "Tracehound",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1200.0, 850.0])
                .with_min_inner_size([820.0, 620.0])
                .with_drag_and_drop(true),
            ..Default::default()
        },
        Box::new(move |_| {
            let mut desktop = Desktop::default();
            if let Some(capture) = startup.capture {
                desktop.capture = capture.to_string_lossy().into_owned();
            }
            if let Some(config) = startup.smoke {
                if let Some(case) = &config.case {
                    desktop.page = Page::Investigation;
                    desktop.investigation.open_case(case.clone());
                }
                desktop.smoke = Some(native_smoke::NativeSmoke::new(
                    config,
                    smoke_outcome.expect("smoke outcome exists"),
                ));
            }
            Ok(Box::new(desktop))
        }),
    );
    if let Some(outcome) = outcome {
        if let Err(error) = &result {
            eprintln!("Native GUI initialization failed: {error}");
        }
        std::process::exit(outcome.load(Ordering::Acquire));
    }
    result
}

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Capture,
    Investigation,
    Suite,
    Live,
    Reports,
    Settings,
}
#[derive(Clone, Copy, PartialEq)]
enum ResultPage {
    Findings,
    Protocols,
    Evaluation,
}
#[derive(Clone, Copy, PartialEq)]
enum LiveMode {
    Rust,
    Native,
    Recording,
}

enum Task {
    Rust(Arc<RustLiveSession>),
    Capture(CaptureJob),
    Suite(SuiteJob),
    Native(LiveSession),
    Recording(Arc<PortableRecording>),
}
enum CompletedReport {
    Rust(Arc<StreamSummary>, PathBuf),
    Capture(Arc<JobReport>),
    Suite(Arc<SuiteReport>),
}
impl Task {
    fn active(&self) -> bool {
        match self {
            Self::Rust(job) => !job.finished(),
            Self::Capture(job) => !job.snapshot().state.is_terminal(),
            Self::Suite(job) => !job.snapshot().state.is_terminal(),
            Self::Native(job) => !job.finished(),
            Self::Recording(job) => !job.finished(),
        }
    }
    fn cancel(&self) {
        match self {
            Self::Rust(job) => {
                job.cancel();
            }
            Self::Capture(job) => {
                job.cancel();
            }
            Self::Suite(job) => {
                job.cancel();
            }
            Self::Native(job) => {
                job.stop();
            }
            Self::Recording(job) => {
                job.cancel();
            }
        }
    }
    fn cancelled(&self) -> bool {
        match self {
            Self::Rust(job) => job.snapshot().state == RustLiveState::Cancelled,
            Self::Capture(job) => {
                job.snapshot().state == tracehound_eval::runtime::JobState::Cancelled
            }
            Self::Suite(job) => {
                job.snapshot().state == tracehound_eval::suite::SuiteState::Cancelled
            }
            Self::Recording(job) => job.snapshot().state == RecordingState::Cancelled,
            Self::Native(_) => false,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Input {
    Capture,
    Suite,
    Sensor,
    Rules,
    Feed,
    Helper,
    Open,
    Baseline,
    Export,
    Raw,
    History,
    CaseCapture,
    CaseDestination,
    CaseOpen,
    CaseExport,
    CasePacketExport,
    CaseBaseline,
    Wireshark,
    CaseSource,
}
impl Input {
    fn directory(self) -> bool {
        matches!(self, Self::Rules | Self::History | Self::CaseExport)
    }
    fn title(self) -> &'static str {
        match self {
            Self::Capture => "Choose a packet capture",
            Self::Suite => "Choose an evaluation suite",
            Self::Sensor => "Choose the Tracehound executable",
            Self::Rules => "Choose a rule directory",
            Self::Feed => "Choose a TLS pair feed",
            Self::Helper => "Choose dumpcap",
            Self::Open => "Open a report",
            Self::Baseline => "Choose a comparison baseline",
            Self::Export => "Choose a report destination",
            Self::Raw => "Choose a capture destination",
            Self::History => "Choose a report history directory",
            Self::CaseCapture => "Choose an original packet capture",
            Self::CaseDestination => "Choose a new investigation case file",
            Self::CaseOpen => "Open a saved investigation",
            Self::CaseExport => "Choose an investigation export directory",
            Self::CasePacketExport => "Choose a new packet extraction file",
            Self::CaseBaseline => "Choose a baseline investigation",
            Self::Wireshark => "Choose Wireshark",
            Self::CaseSource => "Locate the original capture",
        }
    }
}
struct DirectoryEntry {
    path: PathBuf,
    directory: bool,
}
struct Picker {
    target: Input,
    directory: String,
    entries: Vec<DirectoryEntry>,
    selected: String,
    loading: bool,
    generation: u64,
}
enum Work {
    Started(Box<Task>),
    Document(Arc<ReportDocument>),
    Ready(Arc<ReportDocument>),
    History(Vec<HistoryEntry>),
    Compared(String, String, ReportComparison),
    Interfaces(LiveMode, Vec<CaptureInterface>, Option<PathBuf>),
    Directory(u64, PathBuf, Vec<DirectoryEntry>),
    Message(String),
    Feed(PathBuf, String),
    Context(u64, [Vec<usize>; 4]),
    Filtered(u64, Vec<usize>),
    CaptureSaved(PathBuf),
}
struct Worker {
    receiver: mpsc::Receiver<Result<Work, String>>,
    starting: bool,
}

struct Desktop {
    smoke: Option<native_smoke::NativeSmoke>,
    page: Page,
    result_page: ResultPage,
    capture: String,
    suite: String,
    sensor: String,
    analysis_engine: AnalysisEngine,
    rules: String,
    home_nets: String,
    feed: String,
    timeout: u64,
    max_alerts: usize,
    floor: Severity,
    task: Option<Task>,
    collected: bool,
    workers: Vec<Worker>,
    status: String,
    result: Option<Arc<ReportDocument>>,
    case: usize,
    search: String,
    view_floor: Severity,
    filtered: Vec<usize>,
    filter_generation: Arc<AtomicU64>,
    filter_loading: bool,
    selected: Option<usize>,
    context_search: String,
    context_key: Option<(usize, String)>,
    context_generation: Arc<AtomicU64>,
    context_rows: [Vec<usize>; 4],
    context_loading: bool,
    export: String,
    raw: String,
    history_root: String,
    history: Vec<HistoryEntry>,
    open_path: String,
    baseline: String,
    comparison: Option<(String, String, ReportComparison)>,
    live_mode: LiveMode,
    helper: String,
    interfaces: Vec<CaptureInterface>,
    interface: String,
    bpf: String,
    max_mebibytes: u32,
    max_seconds: u32,
    promiscuous: bool,
    live_snapshot: Option<LiveSnapshot>,
    rust_snapshot: Option<RustLiveSnapshot>,
    process_attribution: bool,
    rust_selected: Option<usize>,
    rust_flow: Option<usize>,
    picker: Option<Picker>,
    picker_generation: u64,
    error: Option<String>,
    notice: Option<String>,
    closing: bool,
    cancel_pending_start: bool,
    investigation: InvestigationUi,
}

impl Default for Desktop {
    fn default() -> Self {
        Self {
            smoke: None,
            page: Page::Capture,
            result_page: ResultPage::Findings,
            capture: String::new(),
            suite: String::new(),
            sensor: find_sensor().to_string_lossy().into_owned(),
            analysis_engine: AnalysisEngine::Rust,
            rules: String::new(),
            home_nets: String::new(),
            feed: String::new(),
            timeout: 300,
            max_alerts: 1_000_000,
            floor: Severity::Low,
            task: None,
            collected: false,
            workers: Vec::new(),
            status: "Ready".into(),
            result: None,
            case: 0,
            search: String::new(),
            view_floor: Severity::Low,
            filtered: Vec::new(),
            filter_generation: Arc::new(AtomicU64::new(0)),
            filter_loading: false,
            selected: None,
            context_search: String::new(),
            context_key: None,
            context_generation: Arc::new(AtomicU64::new(0)),
            context_rows: Default::default(),
            context_loading: false,
            export: String::new(),
            raw: String::new(),
            history_root: ReportStore::default_location()
                .root()
                .to_string_lossy()
                .into_owned(),
            history: Vec::new(),
            open_path: String::new(),
            baseline: String::new(),
            comparison: None,
            live_mode: LiveMode::Rust,
            helper: String::new(),
            interfaces: Vec::new(),
            interface: String::new(),
            bpf: String::new(),
            max_mebibytes: 64,
            max_seconds: 3600,
            promiscuous: false,
            live_snapshot: None,
            rust_snapshot: None,
            process_attribution: false,
            rust_selected: None,
            rust_flow: None,
            picker: None,
            picker_generation: 0,
            error: None,
            notice: None,
            closing: false,
            cancel_pending_start: false,
            investigation: InvestigationUi::default(),
        }
    }
}

impl Desktop {
    fn active(&self) -> bool {
        self.workers.iter().any(|worker| worker.starting)
            || self.task.as_ref().is_some_and(Task::active)
            || self.investigation.active()
    }
    fn busy(&self) -> bool {
        self.active()
            || !self.workers.is_empty()
            || self.investigation.busy()
            || self
                .smoke
                .as_ref()
                .is_some_and(native_smoke::NativeSmoke::writing)
    }
    fn stream_options(&self) -> Result<StreamOptions, String> {
        let mut options = StreamOptions {
            rules: optional_path(&self.rules),
            pair_feed: optional_path(&self.feed),
            min_severity: self.floor,
            ..StreamOptions::default()
        };
        options.limits.max_alert_records = self.max_alerts as u64;
        if !self.home_nets.trim().is_empty() {
            options.home_nets = self
                .home_nets
                .split(',')
                .map(|value| {
                    value
                        .trim()
                        .parse()
                        .map_err(|e| format!("Invalid internal network {value:?}: {e}"))
                })
                .collect::<Result<_, _>>()?;
        }
        Ok(options)
    }
    fn options(&self) -> Result<SensorOptions, String> {
        if self.analysis_engine == AnalysisEngine::Sensor && self.sensor.trim().is_empty() {
            return Err("Choose the Tracehound executable in Settings.".into());
        }
        Ok(SensorOptions {
            engine: self.analysis_engine,
            executable: OsString::from(self.sensor.trim()),
            rules: optional_path(&self.rules),
            home_nets: non_empty(&self.home_nets).map(OsString::from),
            pair_feed: optional_path(&self.feed),
            timeout: Duration::from_secs(self.timeout),
            max_alerts: self.max_alerts,
        })
    }
    fn work(
        &mut self,
        starting: bool,
        run: impl FnOnce() -> Result<Work, String> + Send + 'static,
    ) {
        let (sender, receiver) = mpsc::channel();
        self.workers.push(Worker { receiver, starting });
        std::thread::spawn(move || {
            let _ = sender.send(run());
        });
    }
    fn begin(&mut self, kind: Page) {
        let options = match self.options() {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        self.error = None;
        self.notice = None;
        self.status = "Starting…".into();
        self.cancel_pending_start = false;
        let path = PathBuf::from(if kind == Page::Suite {
            self.suite.trim()
        } else {
            self.capture.trim()
        });
        if path.as_os_str().is_empty() {
            self.error = Some("Choose an input file first.".into());
            return;
        }
        let floor = self.floor;
        self.work(true, move || {
            let task = if kind == Page::Suite {
                Task::Suite(SuiteJob::start(path, options)?)
            } else {
                Task::Capture(CaptureJob::analyze(path, options, floor).map_err(|e| e.to_string())?)
            };
            Ok(Work::Started(Box::new(task)))
        });
    }
    fn begin_live(&mut self) {
        let options = match if self.live_mode == LiveMode::Rust {
            Ok(SensorOptions::default())
        } else {
            self.options()
        } {
            Ok(value) => value,
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        if self.interface.trim().is_empty() {
            self.error = Some("Discover and choose a capture interface first.".into());
            return;
        }
        if self.live_mode != LiveMode::Native && self.helper.trim().is_empty() {
            self.error = Some("Find an installed dumpcap helper first.".into());
            return;
        }
        self.error = None;
        self.notice = None;
        self.status = "Starting capture…".into();
        self.cancel_pending_start = false;
        let interface = self.interface.clone();
        let helper = PathBuf::from(self.helper.trim());
        let mode = self.live_mode;
        let promiscuous = self.promiscuous;
        let limits = RecordingLimits {
            max_mebibytes: self.max_mebibytes,
            max_seconds: self.max_seconds,
        };
        let filter = non_empty(&self.bpf).map(str::to_owned);
        let analysis = match self.stream_options() {
            Ok(options) => options,
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        let process_attribution = self.process_attribution;
        self.work(true, move || {
            Ok(Work::Started(Box::new(match mode {
                LiveMode::Rust => Task::Rust(Arc::new(RustLiveSession::start(RustLiveOptions {
                    capture_tool: helper,
                    interface,
                    filter,
                    promiscuous,
                    recording_limits: limits,
                    analysis,
                    process_attribution,
                })?)),
                LiveMode::Native => {
                    Task::Native(LiveSession::start(options, interface, promiscuous)?)
                }
                LiveMode::Recording => Task::Recording(Arc::new(
                    PortableRecording::start_filtered(options, helper, interface, limits, filter)?,
                )),
            })))
        });
    }
    fn discover(&mut self) {
        let mode = self.live_mode;
        let configured = optional_path(&self.helper);
        self.work(false, move || {
            if mode == LiveMode::Native {
                Ok(Work::Interfaces(mode, live::interfaces()?.into_iter().map(|entry| CaptureInterface { id: entry.name.clone(), name: format!("{}{}{}", entry.name, if entry.up { "" } else { " (down)" }, if entry.loopback { " (loopback)" } else { "" }) }).collect(), None))
            } else {
                let helper = configured.or_else(live::discover_capture_tool).ok_or("No capture helper found. Choose an existing Wireshark dumpcap executable. Windows also requires an installed Npcap driver; macOS requires capture permissions.")?;
                let entries = live::capture_interfaces(&helper)?;
                Ok(Work::Interfaces(mode, entries, Some(helper)))
            }
        });
    }
    fn document(&mut self, document: Arc<ReportDocument>) {
        self.result = Some(document);
        self.case = 0;
        self.selected = None;
        self.comparison = None;
        self.view_floor = current_floor(self.result.as_deref(), self.case);
        self.result_page = ResultPage::Findings;
        self.context_key = None;
        self.rebuild_filter();
        if self.export.trim().is_empty() {
            self.export = std::env::current_dir()
                .unwrap_or_default()
                .join("tracehound-report.json")
                .to_string_lossy()
                .into_owned();
        }
    }
    fn poll(&mut self) {
        self.investigation.poll();
        let mut completed = Vec::new();
        for (index, worker) in self.workers.iter().enumerate() {
            match worker.receiver.try_recv() {
                Ok(result) => completed.push((index, result)),
                Err(mpsc::TryRecvError::Disconnected) => completed.push((
                    index,
                    Err("A background operation stopped before returning a result.".into()),
                )),
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        for (index, result) in completed.into_iter().rev() {
            self.workers.remove(index);
            match result {
                Err(error) => {
                    if let Some(picker) = &mut self.picker {
                        picker.loading = false;
                    }
                    self.error = Some(error);
                    if self.task.is_none() {
                        self.status = "Action needed".into();
                    }
                }
                Ok(Work::Started(task)) => {
                    if self.closing || self.cancel_pending_start {
                        task.cancel();
                    }
                    self.task = Some(*task);
                    self.collected = false;
                    self.live_snapshot = None;
                    self.rust_snapshot = None;
                    self.rust_selected = None;
                    self.rust_flow = None;
                    self.result = None;
                    self.filtered.clear();
                    self.selected = None;
                    self.comparison = None;
                }
                Ok(Work::Document(document)) => {
                    self.document(document);
                    self.notice = Some("Report opened.".into());
                }
                Ok(Work::Ready(document)) => {
                    self.document(document);
                    self.notice = Some(
                        "Results are ready. Save to history or export JSON to keep a report."
                            .into(),
                    );
                    self.error = None;
                }
                Ok(Work::History(entries)) => self.history = entries,
                Ok(Work::CaptureSaved(path)) => {
                    self.raw = path.to_string_lossy().into_owned();
                    self.investigation.source = self.raw.clone();
                    self.investigation.destination =
                        path.with_extension("thcase").to_string_lossy().into_owned();
                    self.notice=Some("Original live capture saved. Investigate hosts can now build a persistent case from this file.".into());
                }
                Ok(Work::Compared(before, after, comparison)) => {
                    self.comparison = Some((before, after, comparison))
                }
                Ok(Work::Interfaces(mode, entries, helper)) => {
                    if mode != self.live_mode {
                        continue;
                    }
                    if !entries.iter().any(|entry| entry.id == self.interface) {
                        self.interface = entries
                            .first()
                            .map(|entry| entry.id.clone())
                            .unwrap_or_default();
                    }
                    self.interfaces = entries;
                    if let Some(helper) = helper {
                        self.helper = helper.to_string_lossy().into_owned();
                    }
                    if self.interfaces.is_empty() {
                        self.notice = Some("No capture interfaces were reported. Check the helper and capture permissions.".into());
                    }
                }
                Ok(Work::Directory(generation, path, entries)) => {
                    if let Some(picker) = &mut self.picker {
                        if picker.generation == generation {
                            picker.directory = path.to_string_lossy().into_owned();
                            picker.entries = entries;
                            picker.loading = false;
                        }
                    }
                }
                Ok(Work::Message(message)) => self.notice = Some(message),
                Ok(Work::Feed(path, message)) => {
                    self.feed = path.to_string_lossy().into_owned();
                    self.notice = Some(message);
                }
                Ok(Work::Context(generation, rows)) => {
                    if generation == self.context_generation.load(Ordering::Relaxed) {
                        self.context_rows = rows;
                        self.context_loading = false;
                    }
                }
                Ok(Work::Filtered(generation, indices)) => {
                    if generation == self.filter_generation.load(Ordering::Relaxed) {
                        self.filtered = indices;
                        self.filter_loading = false;
                        if self
                            .selected
                            .is_some_and(|index| !self.filtered.contains(&index))
                        {
                            self.selected = None;
                        }
                    }
                }
            }
        }
        let mut result = None;
        if let Some(task) = &self.task {
            match task {
                Task::Rust(job) => {
                    let progress = job.snapshot();
                    self.status = format!(
                        "{:?} · {} packets · {} findings · {:.1}s",
                        progress.state,
                        progress.stats.packets,
                        progress.stats.findings,
                        progress.elapsed_ms as f64 / 1000.0
                    );
                    if !self.collected {
                        if let Some(outcome) = job.try_result() {
                            self.collected = true;
                            let path = job.retained_capture_path().unwrap_or_default();
                            result =
                                Some(outcome.map(|report| CompletedReport::Rust(report, path)));
                        }
                    }
                    self.rust_snapshot = Some(progress);
                }
                Task::Capture(job) => {
                    let progress = job.snapshot();
                    self.status = format!(
                        "{:?} · {} grouped findings so far · {} alert records · {:.1}s",
                        progress.state,
                        progress.unique_findings,
                        progress.alert_records,
                        progress.elapsed_ms as f64 / 1000.0
                    );
                    if !self.collected {
                        if let Some(outcome) = job.try_result() {
                            self.collected = true;
                            result = Some(
                                outcome
                                    .map(CompletedReport::Capture)
                                    .map_err(|e| e.to_string()),
                            );
                        }
                    }
                }
                Task::Suite(job) => {
                    let progress = job.snapshot();
                    self.status = format!(
                        "{:?} · {}/{} captures · {} · {:.1}s",
                        progress.state,
                        progress.completed,
                        progress.total,
                        progress.current.as_deref().unwrap_or(""),
                        progress.elapsed_ms as f64 / 1000.0
                    );
                    if !self.collected {
                        if let Some(outcome) = job.try_result() {
                            self.collected = true;
                            result = Some(outcome.map(CompletedReport::Suite));
                        }
                    }
                }
                Task::Native(job) => {
                    let progress = job.snapshot();
                    self.status = format!(
                        "{:?} · {} alert records · {} recent findings · {:.1}s",
                        progress.state,
                        progress.alert_records,
                        progress.findings.len(),
                        progress.elapsed_ms as f64 / 1000.0
                    );
                    if !self.collected && job.finished() {
                        self.collected = true;
                        if let Some(error) = &progress.error {
                            self.error = Some(error.clone());
                        }
                    }
                    self.live_snapshot = Some(progress);
                }
                Task::Recording(job) => {
                    let progress = job.snapshot();
                    self.status = format!(
                        "{:?} · {:.2} MiB captured · {:.1}s{}",
                        progress.state,
                        progress.capture_bytes as f64 / 1_048_576.0,
                        progress.elapsed_ms as f64 / 1000.0,
                        if progress.state == RecordingState::Analysing {
                            " · analysing the completed recording"
                        } else {
                            ""
                        }
                    );
                    if !self.collected {
                        if let Some(outcome) = job.try_result() {
                            self.collected = true;
                            result = Some(outcome.map(CompletedReport::Capture));
                        }
                    }
                }
            }
        }
        if let Some(outcome) = result {
            match outcome {
                Ok(completed) => self.work(true, move || {
                    Ok(Work::Ready(Arc::new(match completed {
                        CompletedReport::Rust(summary,path)=>ReportDocument::Analysis(tracehound_eval::runtime::CaptureReport {capture:path,report:summary.report.clone(),enrichment:serde_json::json!({"analysis_meta":summary.analysis_meta,"diagnostics":summary.diagnostics,"policy_notes":summary.policy_notes,"stats":summary.stats,"engine":"rust","capture_retention":"temporary_until_saved"})}),
                        CompletedReport::Capture(report) => document_from_job(&report),
                        CompletedReport::Suite(report) => {
                            ReportDocument::Suite(Box::new(report.as_ref().clone()))
                        }
                    })))
                }),
                Err(_) if self.task.as_ref().is_some_and(Task::cancelled) => {
                    self.notice =
                        Some("Task cancelled. No partial result was marked complete.".into());
                    self.error = None;
                }
                Err(error) => self.error = Some(error),
            }
        }
    }
    fn rebuild_filter(&mut self) {
        let generation = self.filter_generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.filtered.clear();
        let Some(document) = self.result.clone() else {
            self.filter_loading = false;
            return;
        };
        self.filter_loading = true;
        let query = self.search.to_lowercase();
        let case = self.case;
        let floor = self.view_floor;
        let current = Arc::clone(&self.filter_generation);
        self.work(false, move || {
            let mut indices = Vec::new();
            for (index, finding) in findings(Some(&document), case).iter().enumerate() {
                if current.load(Ordering::Relaxed) != generation {
                    break;
                }
                if finding.alert.severity >= floor
                    && (query.is_empty() || finding_search(finding).contains(&query))
                {
                    indices.push(index);
                }
            }
            Ok(Work::Filtered(generation, indices))
        });
    }
    fn refresh_history(&mut self) {
        let root = PathBuf::from(self.history_root.trim());
        self.work(false, move || {
            ReportStore::new(root).list().map(Work::History)
        });
    }
    fn browse(&mut self, target: Input) {
        self.picker_generation += 1;
        let current = PathBuf::from(self.input(target).trim());
        let directory = if target.directory() && !current.as_os_str().is_empty() {
            current.clone()
        } else {
            current
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .to_path_buf()
        };
        self.picker = Some(Picker {
            target,
            directory: directory.to_string_lossy().into_owned(),
            entries: Vec::new(),
            selected: current
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            loading: true,
            generation: self.picker_generation,
        });
        self.read_directory(directory);
    }
    fn read_directory(&mut self, path: PathBuf) {
        self.picker_generation += 1;
        let generation = self.picker_generation;
        if let Some(picker) = &mut self.picker {
            picker.loading = true;
            picker.generation = generation;
        }
        self.work(false, move || {
            let path = path.canonicalize().map_err(|e| format!("Open directory {}: {e}", path.display()))?;
            let mut entries = Vec::new();
            for entry in std::fs::read_dir(&path).map_err(|e| e.to_string())?.take(5001) {
                let entry = entry.map_err(|e| e.to_string())?; let kind = entry.file_type().map_err(|e| e.to_string())?;
                if kind.is_dir() || kind.is_file() { entries.push(DirectoryEntry { path: entry.path(), directory: kind.is_dir() }); }
            }
            if entries.len() > 5000 { return Err("This directory has more than 5000 entries. Enter a more specific directory or paste the file path.".into()); }
            entries.sort_by(|a, b| b.directory.cmp(&a.directory).then_with(|| a.path.cmp(&b.path)));
            Ok(Work::Directory(generation, path, entries))
        });
    }
    fn input(&mut self, target: Input) -> &mut String {
        match target {
            Input::Capture => &mut self.capture,
            Input::Suite => &mut self.suite,
            Input::Sensor => &mut self.sensor,
            Input::Rules => &mut self.rules,
            Input::Feed => &mut self.feed,
            Input::Helper => &mut self.helper,
            Input::Open => &mut self.open_path,
            Input::Baseline => &mut self.baseline,
            Input::Export => &mut self.export,
            Input::Raw => &mut self.raw,
            Input::History => &mut self.history_root,
            Input::CaseCapture => &mut self.investigation.source,
            Input::CaseDestination => &mut self.investigation.destination,
            Input::CaseOpen => &mut self.investigation.open,
            Input::CaseExport => &mut self.investigation.export,
            Input::CasePacketExport => &mut self.investigation.packet_export,
            Input::CaseBaseline => &mut self.investigation.baseline,
            Input::Wireshark => &mut self.investigation.wireshark,
            Input::CaseSource => &mut self.investigation.original_override,
        }
    }
    fn choose_path(&mut self, target: Input, path: PathBuf) {
        let path = path.to_string_lossy().into_owned();
        if matches!(target, Input::CaseCapture) {
            self.investigation.select_capture(&path);
        } else {
            *self.input(target) = path;
        }
    }

    fn investigate_capture(&mut self) {
        if !self.capture.trim().is_empty() {
            self.investigation.select_capture(&self.capture);
            self.page = Page::Investigation;
        }
    }

    fn dropped_file(&mut self, path: String) {
        match self.page {
            Page::Investigation => self.investigation.select_capture(&path),
            Page::Suite => self.suite = path,
            Page::Reports => self.open_path = path,
            _ => {
                self.capture = path;
                self.page = Page::Capture;
            }
        }
    }
    fn path_input(&mut self, ui: &mut egui::Ui, target: Input, label: &str, hint: &str) {
        let label = ui.label(label);
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(self.input(target))
                    .hint_text(hint)
                    .desired_width((ui.available_width() - 80.0).max(150.0)),
            )
            .labelled_by(label.id);
            if ui.button("Browse…").clicked() {
                self.browse(target);
            }
        });
    }
    fn picker(&mut self, ctx: &egui::Context) {
        let Some(mut picker) = self.picker.take() else {
            return;
        };
        let mut open = true;
        let mut navigate = None;
        let mut chosen = None;
        egui::Window::new(picker.target.title())
            .id(egui::Id::unique("file-browser"))
            .open(&mut open)
            .resizable(true)
            .default_size([700.0, 490.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut picker.directory).desired_width(500.0));
                    if ui.button("Go").clicked() {
                        navigate = Some(PathBuf::from(picker.directory.trim()));
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("Parent folder").clicked() {
                        navigate = Path::new(&picker.directory).parent().map(Path::to_path_buf);
                    }
                    if picker.loading {
                        ui.spinner();
                        ui.label("Reading directory…");
                    }
                });
                egui::ScrollArea::vertical()
                    .id_salt("browser-entries")
                    .max_height(310.0)
                    .show_rows(ui, 23.0, picker.entries.len(), |ui, range| {
                        for index in range {
                            let entry = &picker.entries[index];
                            let name = entry.path.file_name().unwrap_or_default().to_string_lossy();
                            let response = ui.selectable_label(
                                picker.selected == name,
                                format!("{}{}", if entry.directory { "▸ " } else { "  " }, name),
                            );
                            if response.clicked() {
                                picker.selected = name.into_owned();
                            }
                            if response.double_clicked() {
                                if entry.directory {
                                    navigate = Some(entry.path.clone());
                                } else if !picker.target.directory() {
                                    chosen = Some(entry.path.clone());
                                }
                            }
                        }
                    });
                ui.separator();
                if !picker.target.directory() {
                    ui.horizontal(|ui| {
                        ui.label("File name");
                        ui.text_edit_singleline(&mut picker.selected);
                    });
                }
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !picker.loading,
                            egui::Button::new(if picker.target.directory() {
                                "Use this directory"
                            } else {
                                "Use selected path"
                            }),
                        )
                        .clicked()
                    {
                        chosen = Some(if picker.target.directory() {
                            PathBuf::from(picker.directory.trim())
                        } else {
                            PathBuf::from(picker.directory.trim()).join(picker.selected.trim())
                        });
                    }
                    ui.small(
                        "Double-click a folder to open it. Full paths can also be pasted directly.",
                    );
                });
            });
        if let Some(path) = chosen {
            self.choose_path(picker.target, path);
        } else if open {
            self.picker = Some(picker);
            if let Some(path) = navigate {
                self.read_directory(path);
            }
        }
    }
}

impl Desktop {
    fn investigation_page(&mut self, ui: &mut egui::Ui) {
        let options = self.stream_options();
        let disabled = self.closing
            || self.task.as_ref().is_some_and(Task::active)
            || self.workers.iter().any(|worker| worker.starting);
        ui.add_enabled_ui(!self.closing, |ui| {
            self.investigation.ui(
                ui,
                options,
                Duration::from_secs(self.timeout),
                &self.capture,
                disabled,
            )
        });
        if let Some(target) = self.investigation.take_browse() {
            self.browse(match target {
                CasePath::Capture => Input::CaseCapture,
                CasePath::Destination => Input::CaseDestination,
                CasePath::Open => Input::CaseOpen,
                CasePath::Export => Input::CaseExport,
                CasePath::PacketExport => Input::CasePacketExport,
                CasePath::Baseline => Input::CaseBaseline,
                CasePath::Wireshark => Input::Wireshark,
                CasePath::Source => Input::CaseSource,
            });
        }
    }
    fn capture_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Analyse a capture");
        ui.label("Open a real PCAP or PCAPNG capture. Drop a file here or choose it below.");
        ui.add_enabled_ui(!self.active() && !self.closing, |ui| {
            self.path_input(ui, Input::Capture, "Capture file", "capture.pcapng");
            ui.horizontal(|ui| {
                ui.label("Report severity");
                severity_selector(ui, "analysis-floor", &mut self.floor, Severity::Info);
                if ui.button("Analyse capture").clicked() {
                    self.begin(Page::Capture);
                }
                if ui
                    .add_enabled(
                        !self.capture.trim().is_empty(),
                        egui::Button::new("Investigate this capture"),
                    )
                    .clicked()
                {
                    self.investigate_capture();
                }
            });
            ui.small("Create an investigation to follow hosts, inspect original packets, and export a readable case.");
            ui.horizontal_wrapped(|ui| {
                ui.small("Private networks are internal by default. Configure other ranges for a public-address lab or a different network boundary.");
                if ui.small_button("Internal network settings").clicked() {
                    self.page = Page::Settings;
                }
            });
        });
        ui.small("Findings describe observed behaviour. Evaluation labels are needed to measure detection accuracy.");
    }
    fn suite_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Evaluate labelled captures");
        ui.label("Run a suite manifest against its real capture files and measure matched, missed, and unexpected behaviours.");
        ui.add_enabled_ui(!self.active() && !self.closing, |ui| {
            self.path_input(
                ui,
                Input::Suite,
                "Suite JSON manifest",
                "Path to suite.json",
            );
            if ui.button("Evaluate suite").clicked() {
                self.begin(Page::Suite);
            }
        });
        ui.collapsing("Manifest format", |ui| {
            ui.label("Capture paths are relative to the manifest. Each case supplies its own minimum severity and expected rule/source pairs. An empty expected list explicitly labels a negative case.");
            ui.monospace("{\n  \"schema_version\": 1,\n  \"captures\": [{\n    \"name\": \"labelled capture\",\n    \"capture\": \"traffic.pcap\",\n    \"min_severity\": \"low\",\n    \"expected\": [{\"rule_id\": \"TH-0001\", \"src\": \"10.0.0.5\"}],\n    \"benign_hosts\": []\n  }]\n}");
        });
    }
    fn live_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Capture traffic");
        ui.add_enabled_ui(!self.active() && !self.closing, |ui| {
            let old_mode = self.live_mode;
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.live_mode, LiveMode::Rust, "Rust live analysis");
                ui.add_enabled_ui(cfg!(target_os = "linux"), |ui| { ui.selectable_value(&mut self.live_mode, LiveMode::Native, "Linux live analysis"); });
                ui.selectable_value(&mut self.live_mode, LiveMode::Recording, "Record, then analyse");
            });
            if old_mode != self.live_mode { self.interfaces.clear(); self.interface.clear(); }
            if self.live_mode != LiveMode::Native {
                ui.label(if self.live_mode==LiveMode::Rust {"Uses an installed dumpcap to stream packets directly into the shared Rust analysis engine. Findings, devices and flows update while capture runs."}else{"Uses an existing dumpcap installation. Findings become available after recording stops and the complete file is analysed."});
                self.path_input(ui, Input::Helper, "Capture helper (optional until discovery)", "Path to dumpcap; Discover checks existing installations");
            } else {
                ui.label("The Linux sensor streams recent findings and polls local inventory. Packet capture requires CAP_NET_RAW or equivalent permissions.");
                ui.small("Live mode uses the sensor's live detectors. Record, then analyse adds protocol context, fragment reassembly, the full public-suffix DNS detector, and an optional local TLS pair feed after capture stops.");
            }
            ui.horizontal(|ui| {
                if ui.button("Discover interfaces").clicked() { self.discover(); }
                egui::ComboBox::from_id_salt("capture-interface").width(420.0).selected_text(self.interfaces.iter().find(|entry| entry.id == self.interface).map(|entry| entry.name.as_str()).unwrap_or("Choose an interface")).show_ui(ui, |ui| {
                    for entry in &self.interfaces { ui.selectable_value(&mut self.interface, entry.id.clone(), &entry.name); }
                });
            });
            if self.live_mode != LiveMode::Native {
                let label = ui.label("Capture filter (BPF, optional)");
                ui.add(egui::TextEdit::singleline(&mut self.bpf).hint_text("host 192.168.1.10 or udp port 53").desired_width(f32::INFINITY)).labelled_by(label.id);
                ui.horizontal(|ui| { ui.label("Stop at MiB"); ui.add(egui::DragValue::new(&mut self.max_mebibytes).range(1..=4096)); ui.label("or seconds"); ui.add(egui::DragValue::new(&mut self.max_seconds).range(1..=86_400)); });
                ui.small("Capture stops at either bound. Only traffic permitted by the selected filter is recorded.");
                if self.live_mode==LiveMode::Rust{
                    ui.checkbox(&mut self.promiscuous,"Promiscuous mode");
                    ui.checkbox(&mut self.process_attribution,"Associate local live sockets with process owners");
                    ui.small("Process association is optional, limited to this computer's live sockets, and can be unavailable or race with short-lived connections. Captures from files do not receive process attribution.");
                }
            } else { ui.checkbox(&mut self.promiscuous, "Promiscuous mode"); }
            if ui.button(if self.live_mode == LiveMode::Recording { "Start recording" } else { "Start live analysis" }).clicked() { self.begin_live(); }
        });
        if let Some(Task::Rust(job)) = &self.task {
            let state = job.snapshot().state;
            if matches!(state, RustLiveState::Starting | RustLiveState::Running)
                && ui.button("Stop capture and finish analysis").clicked()
            {
                job.stop();
            }
            if state == RustLiveState::Completed {
                self.path_input(
                    ui,
                    Input::Raw,
                    "Save original live capture",
                    "Choose a new .pcap file before replacing this session",
                );
                if ui
                    .add_enabled(
                        !self.raw.trim().is_empty() && !self.closing,
                        egui::Button::new("Save original capture"),
                    )
                    .clicked()
                {
                    if let Some(Task::Rust(job)) = &self.task {
                        let job = Arc::clone(job);
                        let path = PathBuf::from(self.raw.trim());
                        self.work(false, move || {
                            job.save_capture(&path)?;
                            Ok(Work::CaptureSaved(path))
                        });
                    }
                }
                ui.small("The private recording is removed when this session is replaced or the application closes. Save the original capture before creating a persistent investigation.");
            }
        }
        if let Some(snapshot) = self.rust_snapshot.clone() {
            self.rust_live_results(ui, &snapshot);
        }
        if let Some(Task::Recording(job)) = &self.task {
            let state = job.snapshot().state;
            if state == RecordingState::Recording
                && ui.button("Stop recording and analyse").clicked()
            {
                job.stop();
            }
            if state == RecordingState::Completed {
                self.path_input(
                    ui,
                    Input::Raw,
                    "Save the recorded PCAP (optional)",
                    "Choose a new .pcap file",
                );
                if ui
                    .add_enabled(
                        !self.closing && !self.raw.trim().is_empty(),
                        egui::Button::new("Save capture"),
                    )
                    .clicked()
                {
                    let Some(Task::Recording(job)) = &self.task else {
                        return;
                    };
                    let job = Arc::clone(job);
                    let path = PathBuf::from(self.raw.trim());
                    self.work(false, move || {
                        job.save_capture(&path)?;
                        Ok(Work::Message(format!(
                            "Capture saved to {}",
                            path.display()
                        )))
                    });
                }
                ui.small("The temporary capture is removed when this session is replaced or the application closes. Saving a JSON report does not save packets.");
            }
        }
        if let Some(snapshot) = self.live_snapshot.clone() {
            ui.separator();
            if let Some(error) = &snapshot.poll_error {
                ui.colored_label(
                    severity_color(ui, Severity::Medium),
                    format!("Inventory update delayed: {error}"),
                );
            }
            ui.label(format!("Interface {} · {} retained recent findings · {} earlier records outside the recent view", snapshot.interface, snapshot.findings.len(), snapshot.dropped_findings));
            ui.collapsing("Traffic statistics", |ui| {
                json_details(ui, snapshot.stats.as_ref())
            });
            ui.collapsing(format!("Devices ({})", snapshot.devices.len()), |ui| {
                json_rows(ui, "live-devices", snapshot.devices.as_ref(), "")
            });
            ui.collapsing(format!("Flows ({})", snapshot.flows.len()), |ui| {
                json_rows(ui, "live-flows", snapshot.flows.as_ref(), "")
            });
            ui.collapsing("Recent live findings", |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("recent-live-findings")
                    .max_height(320.0)
                    .show_rows(ui, 48.0, snapshot.findings.len(), |ui, range| {
                        for index in range {
                            let alert = &snapshot.findings[index];
                            ui.colored_label(
                                severity_color(ui, alert.severity),
                                format!("{} · {} · {}", alert.severity, alert.rule_id, alert.title),
                            );
                            ui.label(format!("{} -> {}", address(alert.src), address(alert.dst)));
                        }
                    });
            });
        }
    }
    fn rust_live_results(&mut self, ui: &mut egui::Ui, snapshot: &RustLiveSnapshot) {
        ui.separator();
        ui.strong(format!(
            "{} · {} original packets · {:.2} MiB recorded",
            snapshot.interface,
            snapshot.stats.packets,
            snapshot.capture_bytes as f64 / 1_048_576.0
        ));
        ui.label(&snapshot.process_status);
        if let Some(error) = &snapshot.error {
            ui.colored_label(severity_color(ui, Severity::High), error);
        }
        ui.small(format!("Recent view: {} findings, {} devices and {} flows; up to {} entries per collection. {} earlier alert records are outside this view. Completed reports retain the bounded full analysis.",snapshot.findings.len(),snapshot.devices.len(),snapshot.flows.len(),snapshot.snapshot_entry_limit,snapshot.earlier_alert_records));
        if let Ok(stats) = serde_json::to_value(&snapshot.stats) {
            beacon_ui::show_analysis_context(ui, &stats);
        }
        ui.collapsing("Live findings", |ui| {
            egui::ScrollArea::vertical()
                .id_salt("rust-live-findings")
                .max_height(360.0)
                .show_rows(ui, 58.0, snapshot.findings.len(), |ui, range| {
                    for index in range {
                        let alert = &snapshot.findings[index];
                        if ui
                            .selectable_label(
                                self.rust_selected == Some(index),
                                RichText::new(format!(
                                    "{} · {} · {}",
                                    alert.severity, alert.rule_id, alert.title
                                ))
                                .color(severity_color(ui, alert.severity)),
                            )
                            .clicked()
                        {
                            self.rust_selected = Some(index);
                        }
                        ui.label(format!("{} -> {}", address(alert.src), address(alert.dst)));
                    }
                });
            if let Some(alert) = self
                .rust_selected
                .and_then(|index| snapshot.findings.get(index))
            {
                ui.strong("Selected live finding");
                beacon_ui::show(ui, alert);
                json_details(ui, &alert.evidence);
            }
        });
        ui.collapsing(
            format!("Observed devices ({})", snapshot.devices.len()),
            |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("rust-live-devices")
                    .max_height(280.0)
                    .show_rows(ui, 44.0, snapshot.devices.len(), |ui, range| {
                        for index in range {
                            let device = &snapshot.devices[index];
                            ui.strong(device.address.to_string());
                            ui.small(format!(
                                "{} packets · {} client fingerprints",
                                device.packets,
                                device.fingerprints.len()
                            ));
                        }
                    });
            },
        );
        ui.collapsing(format!("Recent flows ({})", snapshot.flows.len()), |ui| {
            egui::ScrollArea::vertical()
                .id_salt("rust-live-flows")
                .max_height(280.0)
                .show_rows(ui, 48.0, snapshot.flows.len(), |ui, range| {
                    for index in range {
                        let flow = &snapshot.flows[index];
                        if ui
                            .selectable_label(
                                self.rust_flow == Some(index),
                                format!(
                                    "{} -> {} · {}",
                                    flow.client,
                                    flow.server,
                                    if flow.protocol == 6 { "TCP" } else { "UDP" }
                                ),
                            )
                            .clicked()
                        {
                            self.rust_flow = Some(index);
                        }
                        ui.small(format!(
                            "{} outbound / {} inbound bytes{}",
                            flow.bytes_out,
                            flow.bytes_in,
                            flow.server_name
                                .as_deref()
                                .map(|name| format!(" · {name}"))
                                .unwrap_or_default()
                        ));
                    }
                });
            if let Some(flow) = self.rust_flow.and_then(|index| snapshot.flows.get(index)) {
                ui.strong("Selected flow and local process associations");
                if let Ok(value) = serde_json::to_value(flow) {
                    json_details(ui, &value);
                }
            }
        });
        ui.collapsing("Statistics, diagnostics and analysis configuration", |ui| {
            for warning in &snapshot.warnings {
                ui.label(warning);
            }
            if let Ok(value) = serde_json::to_value(&snapshot.stats) {
                json_details(ui, &value);
            }
            if let Ok(value) = serde_json::to_value(&snapshot.diagnostics) {
                json_details(ui, &value);
            }
            json_details(ui, &snapshot.analysis_meta);
        });
    }
    fn reports_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Reports and history");
        self.path_input(
            ui,
            Input::Open,
            "Open a saved JSON report",
            "Path to a Tracehound analysis, evaluation, or suite report",
        );
        if ui
            .add_enabled(
                !self.open_path.trim().is_empty() && !self.closing,
                egui::Button::new("Open report"),
            )
            .clicked()
        {
            let path = PathBuf::from(self.open_path.trim());
            self.work(false, move || {
                store::load_report(&path).map(|document| Work::Document(Arc::new(document)))
            });
        }
        ui.add_space(8.0);
        self.path_input(
            ui,
            Input::History,
            "Local report history",
            "Directory for explicitly saved reports",
        );
        if ui.button("Refresh history").clicked() {
            self.refresh_history();
        }
        let mut open_id = None;
        let mut baseline_id = None;
        egui::ScrollArea::vertical()
            .id_salt("history-list")
            .max_height(230.0)
            .show_rows(ui, 52.0, self.history.len(), |ui, range| {
                for index in range {
                    let entry = &self.history[index];
                    ui.horizontal(|ui| {
                        if ui.button("Open").clicked() {
                            open_id = Some(entry.id.clone());
                        }
                        if ui.button("Use as baseline").clicked() {
                            baseline_id = Some(entry.id.clone());
                        }
                        ui.vertical(|ui| {
                            ui.label(&entry.title);
                            ui.small(format!(
                                "{} · {} findings · saved {}",
                                entry.mode, entry.findings, entry.id
                            ));
                        });
                    });
                }
            });
        if let Some(id) = open_id {
            let root = PathBuf::from(self.history_root.trim());
            self.work(false, move || {
                ReportStore::new(root)
                    .open(&id)
                    .map(|report| Work::Document(Arc::new(report)))
            });
        }
        if let Some(id) = baseline_id {
            self.baseline = PathBuf::from(self.history_root.trim())
                .join(format!("{id}.json"))
                .to_string_lossy()
                .into_owned();
        }
        if self.history.is_empty() {
            ui.small("No history loaded. Save a completed report below, then refresh to list it.");
        }
        ui.separator();
        self.path_input(
            ui,
            Input::Baseline,
            "Comparison baseline",
            "Choose an older report to compare with the report currently open",
        );
        if ui
            .add_enabled(
                self.result.is_some() && !self.baseline.trim().is_empty() && !self.closing,
                egui::Button::new("Compare with current report"),
            )
            .clicked()
        {
            let path = PathBuf::from(self.baseline.trim());
            let after = self.result.clone().unwrap();
            self.work(false, move || {
                let before = store::load_report(&path)?;
                Ok(Work::Compared(
                    before.title(),
                    after.title(),
                    store::compare(&before, &after),
                ))
            });
        }
        if let Some((before, after, comparison)) = &self.comparison {
            ui.strong(format!("{} -> {}", before, after));
            ui.label(format!(
                "{} added · {} removed · {} changed · {} unchanged",
                comparison.added.len(),
                comparison.removed.len(),
                comparison.changed.len(),
                comparison.unchanged
            ));
            ui.collapsing("Added findings", |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("comparison-added")
                    .max_height(240.0)
                    .show_rows(ui, 44.0, comparison.added.len(), |ui, range| {
                        for index in range {
                            let entry = &comparison.added[index];
                            comparison_finding(ui, "+", entry.case.as_deref(), &entry.finding);
                        }
                    });
            });
            ui.collapsing("Removed findings", |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("comparison-removed")
                    .max_height(240.0)
                    .show_rows(ui, 44.0, comparison.removed.len(), |ui, range| {
                        for index in range {
                            let entry = &comparison.removed[index];
                            comparison_finding(ui, "−", entry.case.as_deref(), &entry.finding);
                        }
                    });
            });
            ui.collapsing("Changed findings", |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("comparison-changed")
                    .max_height(260.0)
                    .show_rows(ui, 70.0, comparison.changed.len(), |ui, range| {
                        for index in range {
                            let entry = &comparison.changed[index];
                            comparison_finding(ui, "Δ", entry.case.as_deref(), &entry.after);
                            ui.small(format!(
                                "Previously {} severity, {} occurrences; now {}, {} occurrences",
                                entry.before.alert.severity,
                                entry.before.occurrences,
                                entry.after.alert.severity,
                                entry.after.occurrences
                            ));
                        }
                    });
            });
        }
    }
    fn settings_page(&mut self, ui: &mut egui::Ui) {
        ui.heading("Analysis settings");
        ui.label("Settings apply to new jobs. Captures, reports, and fingerprint feeds stay on this computer.");
        ui.add_enabled_ui(!self.active() && !self.closing, |ui| {
            ui.horizontal_wrapped(|ui|{ui.label("Capture-file engine");ui.selectable_value(&mut self.analysis_engine,AnalysisEngine::Rust,"Built-in Rust");ui.selectable_value(&mut self.analysis_engine,AnalysisEngine::Sensor,"Legacy sensor");});
            self.path_input(ui, Input::Sensor, "Tracehound executable", "Full path or executable name on PATH");
            self.path_input(ui, Input::Rules, "Custom rule directory (optional)", "Leave empty to use bundled rules");
            let label = ui.label("Internal networks (optional, comma-separated CIDRs)");
            ui.add(egui::TextEdit::singleline(&mut self.home_nets).hint_text("10.0.0.0/8,192.168.0.0/16").desired_width(f32::INFINITY)).labelled_by(label.id);
            ui.horizontal(|ui| { ui.label("Per-capture timeout (seconds; 0 = unlimited)"); ui.add(egui::DragValue::new(&mut self.timeout).range(0..=86_400)); });
            ui.horizontal(|ui| { ui.label("Maximum alert records"); ui.add(egui::DragValue::new(&mut self.max_alerts).range(1..=10_000_000)); });
            ui.separator(); ui.strong("TLS fingerprint pair intelligence");
            self.path_input(ui, Input::Feed, "Local source-attributed pair feed (optional)", "Path to a validated pair-feed JSON file");
            ui.horizontal(|ui| {
                if ui.add_enabled(!self.feed.trim().is_empty(), egui::Button::new("Validate local feed")).clicked() {
                    let path = PathBuf::from(self.feed.trim()); self.work(false, move || { let feed = PairFeed::load(&path)?; Ok(Work::Message(format!("Feed valid: {} attributed pairs. Source: {}. {}", feed.entries.len(), feed.source_url, feed.license))) });
                }
                if ui.add_enabled(!self.feed.trim().is_empty(), egui::Button::new("Download publisher mapping to this path")).clicked() {
                    let path = PathBuf::from(self.feed.trim()); self.work(false, move || { let feed = feed::update_public_mapping(&path)?; let message = format!("Saved {} attributed pairs to {}. Source: {}. {}", feed.entries.len(), path.display(), feed.source_url, feed.license); Ok(Work::Feed(path, message)) });
                }
            });
            ui.hyperlink_to("Publisher mapping and terms", feed::PUBLIC_MAPPING_URL);
            ui.small("Downloading is explicit and requires a new destination file. Publisher terms apply; no publisher database is bundled. Pair matches are associations that require supporting evidence.");
            ui.small("Local pair feeds apply to Rust live analysis, capture-file analysis and completed recordings. The legacy Linux stream shows the sensor's own live rules.");
        });
    }
}

impl Desktop {
    fn results(&mut self, ui: &mut egui::Ui) {
        let Some(document) = self.result.clone() else {
            return;
        };
        ui.add_space(14.0);
        ui.separator();
        ui.heading("Current report");
        ui.label(document.title());
        if let ReportDocument::Corpus(corpus) = document.as_ref() {
            ui.label(format!(
                "{} labelled cases · {} unlabelled observations",
                corpus.evaluation.captures.len(),
                corpus.observations.len()
            ));
            ui.small("Accuracy measurements apply to the labelled cases. Unlabelled observations provide findings and protocol context.");
            ui.collapsing(
                format!("Source provenance ({})", corpus.sources.len()),
                |ui| {
                    json_rows(ui, "corpus-provenance", &corpus.sources, "");
                },
            );
            if let Some(validation) = &corpus.validation {
                validation_details(ui, validation);
            }
        }
        if let Some(suite) = labelled_suite(&document) {
            if suite.captures.is_empty() {
                ui.label("This corpus has no labelled cases; accuracy measurements are undefined.");
            } else {
                ui.label(format!("{} · {} passed / {} captures · {} missed expectations · {} unexpected findings · precision {} · recall {}", if suite.passed { "PASS" } else { "FAIL" }, suite.summary.passed, suite.summary.captures, suite.summary.missed_expectations, suite.summary.unexpected_findings, percent(suite.summary.precision), percent(suite.summary.recall)));
            }
            let previous = self.case;
            egui::ComboBox::from_id_salt("suite-case")
                .width(500.0)
                .selected_text(case_title(&document, self.case))
                .show_ui(ui, |ui| {
                    for (index, case) in suite.captures.iter().enumerate() {
                        ui.selectable_value(
                            &mut self.case,
                            index,
                            format!(
                                "{} · {}",
                                if case.passed { "PASS" } else { "FAIL" },
                                case.name
                            ),
                        );
                    }
                    if let ReportDocument::Corpus(corpus) = document.as_ref() {
                        for (index, report) in corpus.observations.iter().enumerate() {
                            ui.selectable_value(
                                &mut self.case,
                                suite.captures.len() + index,
                                format!("Observation · {}", report.capture.display()),
                            );
                        }
                    }
                });
            if previous != self.case {
                self.selected = None;
                self.view_floor = current_floor(Some(&document), self.case);
                self.rebuild_filter();
            }
        }
        if self.result_page == ResultPage::Evaluation
            && evaluation(Some(&document), self.case).is_none()
        {
            self.result_page = ResultPage::Findings;
        }
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.result_page, ResultPage::Findings, "Findings");
            ui.selectable_value(
                &mut self.result_page,
                ResultPage::Protocols,
                "Payload and protocol context",
            );
            if evaluation(Some(&document), self.case).is_some() {
                ui.selectable_value(
                    &mut self.result_page,
                    ResultPage::Evaluation,
                    "Evaluation details",
                );
            }
        });
        match self.result_page {
            ResultPage::Findings => self.finding_results(ui, &document),
            ResultPage::Protocols => self.protocol_results(ui, &document),
            ResultPage::Evaluation => {
                if let Some(report) = evaluation(Some(&document), self.case) {
                    evaluation_details(ui, report);
                }
            }
        }
        ui.separator();
        ui.add_enabled_ui(!self.closing, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Save current report to history").clicked() {
                    let root = PathBuf::from(self.history_root.trim());
                    let document = document.clone();
                    self.work(false, move || {
                        let entry = ReportStore::new(root).save(document.as_ref())?;
                        Ok(Work::Message(format!(
                            "Saved report to local history: {}",
                            entry.id
                        )))
                    });
                }
                ui.small("Saves the complete report, including every suite case.");
            });
            self.path_input(
                ui,
                Input::Export,
                "Export JSON report",
                "Choose a new filename",
            );
            if ui
                .add_enabled(
                    !self.export.trim().is_empty(),
                    egui::Button::new("Export complete report"),
                )
                .clicked()
            {
                let path = PathBuf::from(self.export.trim());
                let document = document.clone();
                self.work(false, move || {
                    store::write_new(&path, document.as_ref())?;
                    Ok(Work::Message(format!(
                        "Report exported to {}",
                        path.display()
                    )))
                });
            }
        });
        ui.small("View filters do not affect saved reports. Existing files are preserved.");
    }
    fn finding_results(&mut self, ui: &mut egui::Ui, document: &ReportDocument) {
        let values = findings(Some(document), self.case);
        let collected_floor = current_floor(Some(document), self.case);
        ui.small(format!(
            "{} grouped findings · report includes {} severity and above",
            values.len(),
            collected_floor
        ));
        let context = enrichment(document, self.case);
        let stats = context
            .get("analysis")
            .and_then(|analysis| analysis.get("stats"))
            .or_else(|| context.get("stats"));
        if let Some(stats) = stats {
            beacon_ui::show_analysis_context(ui, stats);
        }
        ui.horizontal(|ui| {
            let search = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search rule, host, domain, or evidence")
                    .desired_width(350.0),
            );
            let old_floor = self.view_floor;
            severity_selector(ui, "finding-floor", &mut self.view_floor, collected_floor);
            if search.changed() || old_floor != self.view_floor {
                self.rebuild_filter();
            }
            ui.label(format!("{} shown", self.filtered.len()));
        });
        if values.is_empty() {
            ui.label("No findings at the collected severity. Reanalyse at a lower severity to include lower-level findings.");
            return;
        }
        if self.filter_loading {
            ui.label("Filtering findings…");
            return;
        }
        if self.filtered.is_empty() {
            ui.label("No findings match these filters.");
            return;
        }
        ui.columns(2, |columns| {
            egui::ScrollArea::vertical()
                .id_salt("findings-list")
                .max_height(330.0)
                .show_rows(&mut columns[0], 70.0, self.filtered.len(), |ui, range| {
                    for position in range {
                        let index = self.filtered[position];
                        let finding = &values[index];
                        let text = format!(
                            "{} · {} · {} occurrence(s)\n{}\n{} -> {}",
                            finding.alert.severity.to_string().to_uppercase(),
                            finding.alert.rule_id,
                            finding.occurrences,
                            finding.alert.title,
                            address(finding.alert.src),
                            address(finding.alert.dst)
                        );
                        if ui
                            .add_sized(
                                [ui.available_width(), 66.0],
                                egui::Button::new(text).selected(self.selected == Some(index)),
                            )
                            .clicked()
                        {
                            self.selected = Some(index);
                        }
                    }
                });
            egui::ScrollArea::vertical()
                .id_salt("finding-details")
                .max_height(330.0)
                .show(&mut columns[1], |ui| {
                    if let Some(finding) = self.selected.and_then(|index| values.get(index)) {
                        finding_details(ui, finding);
                    } else {
                        ui.label("Select a finding to inspect its explanation and measurements.");
                    }
                });
        });
    }
    fn protocol_results(&mut self, ui: &mut egui::Ui, document: &ReportDocument) {
        let value = enrichment(document, self.case);
        if value.is_null() {
            ui.label("This report has no protocol enrichment. Analyse the original capture with the current backend to collect payload and protocol observations.");
            return;
        }
        ui.horizontal(|ui| {
            ui.label("Filter observations");
            ui.add(
                egui::TextEdit::singleline(&mut self.context_search)
                    .hint_text("Host, domain, fingerprint, or address")
                    .desired_width(400.0),
            );
        });
        let key = (self.case, self.context_search.to_lowercase());
        if self.context_key.as_ref() != Some(&key) && !self.closing {
            self.context_key = Some(key.clone());
            let generation = self.context_generation.fetch_add(1, Ordering::Relaxed) + 1;
            let current = Arc::clone(&self.context_generation);
            self.context_loading = true;
            let document = self.result.clone().unwrap();
            self.work(false, move || {
                let enrichment = enrichment(&document, key.0);
                let rows = ["http", "tls", "dns", "peer_protocols"].map(|name| {
                    enrichment
                        .get(name)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .enumerate()
                        .take_while(|_| current.load(Ordering::Relaxed) == generation)
                        .filter_map(|(index, value)| {
                            (key.1.is_empty() || value.to_string().to_lowercase().contains(&key.1))
                                .then_some(index)
                        })
                        .collect()
                });
                Ok(Work::Context(generation, rows))
            });
        }
        if self.context_loading {
            ui.label("Filtering protocol context…");
        }
        ui.label(format!("{} input packets · {} prepared packets · {} reassembled datagrams · {} incomplete/discarded fragment sets", value["input_packets"], value["output_packets"], value["reassembled_datagrams"], value["discarded_fragment_sets"]));
        if let Some(warnings) = value.get("warnings").and_then(Value::as_array) {
            for warning in warnings {
                ui.colored_label(
                    severity_color(ui, Severity::Medium),
                    warning.as_str().unwrap_or("Capture warning"),
                );
            }
        }
        for (position, (key, title)) in [
            ("http", "HTTP requests and JA4H"),
            ("tls", "TLS client/server pairs and JA4 / JA4S"),
            ("dns", "DNS queries"),
            ("peer_protocols", "Peer-protocol observations"),
        ]
        .into_iter()
        .enumerate()
        {
            let values = value
                .get(key)
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            ui.collapsing(format!("{title} ({})", values.len()), |ui| {
                if key == "peer_protocols" {
                    ui.small("A BitTorrent peer observation records a complete 68-byte prefix in one TCP direction, independent of port. It does not establish a complete peer exchange or classify all traffic to that endpoint.");
                }
                if !self.context_loading {
                    indexed_json_rows(ui, key, values, &self.context_rows[position]);
                }
            });
        }
        ui.small("Context is limited to protocols and complete sessions that the parser can observe. Encrypted payloads are not decrypted.");
    }
}

impl eframe::App for Desktop {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        if ui.ctx().input(|input| input.viewport().close_requested()) && self.busy() {
            self.closing = true;
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::CancelClose);
            if let Some(task) = &self.task {
                task.cancel();
            }
            self.investigation.cancel();
        }
        if self.closing && !self.busy() {
            self.closing = false;
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if self.busy() {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        }
        if !self.active() && !self.closing {
            let files = ui.ctx().input(|input| {
                input
                    .raw
                    .dropped_files
                    .iter()
                    .map(|file| file.path().to_path_buf())
                    .collect::<Vec<_>>()
            });
            if files.len() == 1 {
                let path = files[0].to_string_lossy().into_owned();
                self.dropped_file(path);
            } else if files.len() > 1 {
                self.error = Some("Drop one input file at a time. Use a suite manifest to evaluate multiple captures.".into());
            }
        }
        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("Tracehound");
                ui.add_space(15.0);
                for (page, title) in [
                    (Page::Capture, "Analyse"),
                    (Page::Investigation, "Investigate hosts"),
                    (Page::Suite, "Evaluate"),
                    (Page::Live, "Capture traffic"),
                    (Page::Reports, "Reports"),
                    (Page::Settings, "Settings"),
                ] {
                    if ui.selectable_value(&mut self.page, page, title).clicked()
                        && page == Page::Reports
                        && self.history.is_empty()
                        && self.workers.is_empty()
                    {
                        self.refresh_history();
                    }
                }
            });
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                if self.busy() {
                    ui.spinner();
                }
                ui.label(&self.status);
                if self.active() && !self.closing && ui.button("Cancel current task").clicked() {
                    self.cancel_pending_start = true;
                    if let Some(task) = &self.task {
                        task.cancel();
                    }
                    self.investigation.cancel();
                }
            });
            if self.closing {
                ui.strong("Stopping capture and finishing background operations before closing…");
            }
            if let Some(error) = &self.error {
                ui.group(|ui| {
                    ui.colored_label(
                        severity_color(ui, Severity::High),
                        RichText::new("Action needed").strong(),
                    );
                    ui.label(error);
                });
            }
            if let Some(notice) = &self.notice {
                ui.label(notice);
            }
            egui::ScrollArea::vertical()
                .id_salt("workspace")
                .show(ui, |ui| {
                    ui.add_space(8.0);
                    match self.page {
                        Page::Capture => self.capture_page(ui),
                        Page::Investigation => self.investigation_page(ui),
                        Page::Suite => self.suite_page(ui),
                        Page::Live => self.live_page(ui),
                        Page::Reports => self.reports_page(ui),
                        Page::Settings => self.settings_page(ui),
                    }
                    if !matches!(self.page, Page::Settings | Page::Investigation) {
                        self.results(ui);
                    }
                });
        });
        let ctx = ui.ctx().clone();
        self.picker(&ctx);
        if let Some(mut smoke) = self.smoke.take() {
            smoke.advance(self, &ctx);
            self.smoke = Some(smoke);
        }
    }
}

fn document_from_job(report: &JobReport) -> ReportDocument {
    match report {
        JobReport::Analysis(report) => ReportDocument::Analysis(report.clone()),
        JobReport::Evaluation(report) => ReportDocument::Evaluation(report.clone()),
    }
}
fn findings(document: Option<&ReportDocument>, case: usize) -> &[Finding] {
    match document {
        Some(ReportDocument::Analysis(report)) => &report.report.findings,
        Some(ReportDocument::Evaluation(report)) => &report.findings,
        Some(ReportDocument::Suite(report)) => report
            .captures
            .get(case)
            .map(|case| case.findings.as_slice())
            .unwrap_or_default(),
        Some(ReportDocument::Corpus(report)) => {
            if let Some(evaluation) = report.evaluation.captures.get(case) {
                &evaluation.findings
            } else {
                report
                    .observations
                    .get(case.saturating_sub(report.evaluation.captures.len()))
                    .map(|report| report.report.findings.as_slice())
                    .unwrap_or_default()
            }
        }
        None => &[],
    }
}
fn evaluation(document: Option<&ReportDocument>, case: usize) -> Option<&EvaluationReport> {
    match document {
        Some(ReportDocument::Evaluation(report)) => Some(report),
        Some(ReportDocument::Suite(report)) => report.captures.get(case),
        Some(ReportDocument::Corpus(report)) => report.evaluation.captures.get(case),
        _ => None,
    }
}
fn current_floor(document: Option<&ReportDocument>, case: usize) -> Severity {
    match document {
        Some(ReportDocument::Analysis(report)) => report.report.min_severity,
        Some(document @ ReportDocument::Corpus(_)) => observation(document, case)
            .map(|report| report.report.min_severity)
            .or_else(|| evaluation(Some(document), case).map(|report| report.min_severity))
            .unwrap_or(Severity::Low),
        _ => evaluation(document, case)
            .map(|case| case.min_severity)
            .unwrap_or(Severity::Low),
    }
}
fn enrichment(document: &ReportDocument, case: usize) -> &Value {
    match document {
        ReportDocument::Analysis(report) => &report.enrichment,
        ReportDocument::Corpus(_) => {
            if let Some(report) = observation(document, case) {
                &report.enrichment
            } else {
                evaluation(Some(document), case)
                    .map(|report| &report.enrichment)
                    .unwrap_or(&Value::Null)
            }
        }
        _ => evaluation(Some(document), case)
            .map(|report| &report.enrichment)
            .unwrap_or(&Value::Null),
    }
}
fn labelled_suite(document: &ReportDocument) -> Option<&SuiteReport> {
    match document {
        ReportDocument::Suite(report) => Some(report),
        ReportDocument::Corpus(report) => Some(&report.evaluation),
        _ => None,
    }
}
fn observation(
    document: &ReportDocument,
    case: usize,
) -> Option<&tracehound_eval::runtime::CaptureReport> {
    match document {
        ReportDocument::Corpus(report) => case
            .checked_sub(report.evaluation.captures.len())
            .and_then(|index| report.observations.get(index)),
        _ => None,
    }
}
fn case_title(document: &ReportDocument, case: usize) -> String {
    if let Some(report) = evaluation(Some(document), case) {
        report.name.clone()
    } else if let Some(report) = observation(document, case) {
        format!("Observation · {}", report.capture.display())
    } else {
        "Choose capture".into()
    }
}
fn finding_search(finding: &Finding) -> String {
    format!(
        "{} {} {} {} {} {}",
        finding.alert.rule_id,
        finding.alert.title,
        address(finding.alert.src),
        address(finding.alert.dst),
        finding.alert.description.as_deref().unwrap_or(""),
        finding.alert.evidence
    )
    .to_lowercase()
}
fn address(address: Option<std::net::IpAddr>) -> String {
    address
        .map(|address| address.to_string())
        .unwrap_or_else(|| "any / unspecified".into())
}
fn percent(value: Option<f64>) -> String {
    value
        .map(|value| format!("{:.1}%", value * 100.0))
        .unwrap_or_else(|| "not defined".into())
}
fn validation_details(
    ui: &mut egui::Ui,
    validation: &tracehound_eval::validation::ValidationSummary,
) {
    ui.collapsing("Per-rule labelled recall and reviewed benign exposure",|ui|{
        egui::ScrollArea::horizontal().id_salt("rule-validation-metrics").show(ui,|ui|{
            egui::Grid::new("per-rule-validation").striped(true).show(ui,|ui|{
                for heading in ["Rule","Labelled recall","Matched / missed","Unexpected findings","Benign alert records / host-hour","Reviewed host-hours"]{ui.strong(heading);}ui.end_row();
                for rule in &validation.per_rule{
                    ui.label(&rule.rule_id);ui.label(percent(rule.labelled_recall));ui.label(format!("{} / {}",rule.matched_behaviours,rule.missed_behaviours));ui.label(rule.unexpected_unique_findings.to_string());
                    ui.label(rule.benign_alert_records_per_host_hour.map(|value|format!("{value:.3}")).unwrap_or_else(||"undefined".into()));
                    ui.label(rule.monitored_benign_host_hours.map(|value|format!("{value:.4}")).unwrap_or_else(||"not supplied".into()));ui.end_row();
                }
            });
        });
        for note in &validation.interpretation{ui.small(note);}
        ui.small("Undefined rates indicate missing reviewed exposure. Unexpected findings in labelled captures are not automatically confirmed false positives.");
        for rule in &validation.per_rule{ui.collapsing(format!("{} counts and exposure provenance",rule.rule_id),|ui|{if let Ok(value)=serde_json::to_value(rule){json_details(ui,&value);}});}
    });
}
fn evaluation_details(ui: &mut egui::Ui, report: &EvaluationReport) {
    ui.strong(format!(
        "{} · {}",
        if report.passed { "PASS" } else { "FAIL" },
        report.name
    ));
    ui.label(format!(
        "{} matched / {} expectations · {} unexpected findings · {} from explicitly benign hosts",
        report.summary.matched_expectations,
        report.summary.expected_total,
        report.summary.unexpected_findings,
        report.summary.benign_findings
    ));
    ui.label(format!(
        "Precision {} · Recall {}",
        percent(report.summary.precision),
        percent(report.summary.recall)
    ));
    ui.small("Precision assumes the supplied positive labels are complete. Benign-host findings are a subset of unexpected findings; no true-negative count or false-positive rate is inferred.");
    ui.collapsing(
        format!("Missed expectations ({})", report.missed_expectations.len()),
        |ui| {
            for entry in &report.missed_expectations {
                ui.label(format!(
                    "{} · {} -> {}",
                    entry.rule_id,
                    entry.src,
                    address(entry.dst)
                ));
            }
        },
    );
    ui.collapsing(
        format!(
            "Matched expectations ({})",
            report.matched_expectations.len()
        ),
        |ui| {
            for entry in &report.matched_expectations {
                ui.label(format!(
                    "{} · {} -> {}",
                    entry.rule_id,
                    entry.src,
                    address(entry.dst)
                ));
            }
        },
    );
    ui.collapsing(
        format!("Unexpected findings ({})", report.unexpected_findings.len()),
        |ui| {
            for finding in &report.unexpected_findings {
                comparison_finding(ui, "", None, finding);
            }
        },
    );
}
fn comparison_finding(ui: &mut egui::Ui, symbol: &str, case: Option<&str>, finding: &Finding) {
    ui.label(format!(
        "{symbol} {}{} · {} · {} -> {} · {} occurrence(s)",
        case.map(|name| format!("{name}: ")).unwrap_or_default(),
        finding.alert.rule_id,
        finding.alert.title,
        address(finding.alert.src),
        address(finding.alert.dst),
        finding.occurrences
    ));
}
fn finding_details(ui: &mut egui::Ui, finding: &Finding) {
    let alert = &finding.alert;
    ui.colored_label(
        severity_color(ui, alert.severity),
        RichText::new(alert.severity.to_string().to_uppercase()).strong(),
    );
    ui.strong(&alert.title);
    ui.label(format!(
        "Rule {} · {} occurrence(s)",
        alert.rule_id, finding.occurrences
    ));
    if let Some(description) = &alert.description {
        ui.label(description);
    }
    if let Some(score) = alert.score.filter(|_| alert.rule_id != "TH-0001") {
        ui.label(format!("Detector score: {score:.2}"));
    }
    if let Some(time) = &alert.time {
        ui.label(format!("Latest observation: {time}"));
    }
    ui.separator();
    beacon_ui::show(ui, alert);
    json_details(ui, &alert.evidence);
    if !alert.extra.is_empty() {
        ui.collapsing("Additional metadata", |ui| {
            for (key, value) in alert.extra.iter().take(64) {
                ui.strong(key.replace('_', " "));
                ui.monospace(value_preview(value, 2));
            }
            if alert.extra.len() > 64 {
                ui.small("Additional fields are retained in the complete JSON report.");
            }
        });
    }
}
fn json_details(ui: &mut egui::Ui, value: &Value) {
    if let Some(object) = value.as_object() {
        for (key, value) in object.iter().take(64) {
            ui.horizontal_wrapped(|ui| {
                ui.strong(key.replace('_', " "));
                ui.monospace(value_preview(value, 2));
            });
        }
        if object.len() > 64 {
            ui.small("Additional fields are retained in the complete JSON report.");
        }
    } else {
        ui.monospace(value_preview(value, 2));
    }
}
fn value_preview(value: &Value, depth: usize) -> String {
    match value {
        Value::String(text) => {
            let mut preview = text.chars().take(4097).collect::<String>();
            if preview.chars().count() > 4096 {
                preview = preview.chars().take(4096).collect();
                preview.push_str("… [full value in JSON]");
            }
            preview
        }
        Value::Array(values) if depth > 0 => {
            let mut preview = values
                .iter()
                .take(8)
                .map(|value| value_preview(value, depth - 1))
                .collect::<Vec<_>>()
                .join(", ");
            if values.len() > 8 {
                preview.push_str(", … [full list in JSON]");
            }
            format!("[{preview}]")
        }
        Value::Array(values) => format!("{} entries [details in JSON]", values.len()),
        Value::Object(values) if depth > 0 => {
            let mut preview = values
                .iter()
                .take(8)
                .map(|(key, value)| format!("{key}: {}", value_preview(value, depth - 1)))
                .collect::<Vec<_>>()
                .join(", ");
            if values.len() > 8 {
                preview.push_str(", … [full object in JSON]");
            }
            format!("{{{preview}}}")
        }
        Value::Object(values) => format!("{} fields [details in JSON]", values.len()),
        _ => value.to_string(),
    }
}
fn json_rows(ui: &mut egui::Ui, id: &str, values: &[Value], query: &str) {
    let query = query.to_lowercase();
    let filtered = values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| {
            (query.is_empty() || value.to_string().to_lowercase().contains(&query)).then_some(index)
        })
        .collect::<Vec<_>>();
    indexed_json_rows(ui, id, values, &filtered);
}
fn indexed_json_rows(ui: &mut egui::Ui, id: &str, values: &[Value], filtered: &[usize]) {
    if filtered.is_empty() {
        ui.label("No observations match this view.");
    }
    egui::ScrollArea::vertical().id_salt(id).max_height(320.0).show(ui, |ui| {
        for &index in filtered.iter().take(500) { if let Some(value) = values.get(index) { ui.push_id(index, |ui| { ui.group(|ui| json_details(ui, value)); }); } }
        if filtered.len() > 500 { ui.small(format!("Showing 500 of {} observations. Refine the search; the JSON report retains all observations.", filtered.len())); }
    });
}
fn severity_selector(ui: &mut egui::Ui, id: &str, value: &mut Severity, floor: Severity) {
    *value = (*value).max(floor);
    egui::ComboBox::from_id_salt(id)
        .selected_text(value.to_string())
        .show_ui(ui, |ui| {
            for severity in [
                Severity::Info,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ] {
                ui.add_enabled_ui(severity >= floor, |ui| {
                    ui.selectable_value(value, severity, severity.to_string());
                });
            }
        });
}
fn severity_color(ui: &egui::Ui, severity: Severity) -> Color32 {
    match (ui.visuals().dark_mode, severity) {
        (true, Severity::Critical) => Color32::from_rgb(255, 146, 190),
        (true, Severity::High) => Color32::from_rgb(255, 158, 128),
        (true, Severity::Medium) => Color32::from_rgb(249, 204, 110),
        (true, Severity::Low) => Color32::from_rgb(130, 210, 195),
        (false, Severity::Critical) => Color32::from_rgb(150, 0, 70),
        (false, Severity::High) => Color32::from_rgb(156, 46, 10),
        (false, Severity::Medium) => Color32::from_rgb(125, 82, 0),
        (false, Severity::Low) => Color32::from_rgb(0, 103, 83),
        (_, Severity::Info) => ui.visuals().text_color(),
    }
}
fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}
fn optional_path(value: &str) -> Option<PathBuf> {
    non_empty(value).map(PathBuf::from)
}
fn find_sensor() -> PathBuf {
    let filename = if cfg!(windows) {
        "tracehound.exe"
    } else {
        "tracehound"
    };
    let executable = std::env::current_exe().ok();
    if let Some(parent) = executable.as_deref().and_then(Path::parent) {
        let adjacent = parent.join(filename);
        if adjacent.is_file() {
            return adjacent;
        }
    }
    let current = std::env::current_dir().ok();
    for start in [
        executable.as_deref().and_then(Path::parent),
        current.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        for root in start.ancestors().take(8) {
            for directory in ["bin", "dist/backend-check"] {
                let path = root.join(directory).join(filename);
                if path.is_file() {
                    return path;
                }
            }
        }
    }
    filename.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    fn report() -> Arc<ReportDocument> {
        Arc::new(ReportDocument::from_value(json!({
            "schema_version": 1, "mode": "analysis", "capture": "capture.pcap",
            "min_severity": "low", "total_alerts": 3, "evaluated_alerts": 3,
            "ignored_alerts": 0, "findings": [
                {"occurrences": 2, "alert": {"rule_id": "TH-0001", "severity": "high", "src": "10.0.0.5", "title": "Repeated connection", "evidence": {"connections": 8}}},
                {"occurrences": 1, "alert": {"rule_id": "TH-0002", "severity": "low", "src": "10.0.0.6", "title": "DNS observation", "evidence": {"domain": "example.test"}}}
            ],
            "enrichment": {"input_packets": 12, "output_packets": 12, "reassembled_datagrams": 0, "discarded_fragment_sets": 0,
                "http": [{"method": "GET", "host": "example.test", "ja4h": "fingerprint"}], "tls": [], "dns": [],
                "peer_protocols": [{"src":"10.0.0.5","dst":"192.0.2.5","src_port":50000,"dst_port":50001,"protocol":"bittorrent_peer","handshake_bytes":68,"timestamp_ms":1_700_000_000_000_u64,"packets":[]}], "warnings": []}
        })).unwrap())
    }

    fn drain(desktop: &mut Desktop) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !desktop.workers.is_empty() {
            desktop.poll();
            assert!(
                Instant::now() < deadline,
                "background operation did not complete"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(desktop.error.is_none(), "{:?}", desktop.error);
    }

    #[test]
    fn capture_handoffs_prepare_investigations_without_automatic_jobs() {
        let mut desktop = Desktop::default();
        desktop.investigate_capture();
        assert!(desktop.page == Page::Capture);
        desktop.capture = "capture with spaces.pcapng".into();
        desktop.investigate_capture();
        assert!(desktop.page == Page::Investigation);
        assert_eq!(desktop.investigation.source, "capture with spaces.pcapng");
        assert_eq!(
            desktop.investigation.destination,
            "capture with spaces.thcase"
        );
        assert!(!desktop.active());

        desktop.investigation.destination.clear();
        desktop.choose_path(Input::CaseCapture, PathBuf::from("browsed.pcap"));
        assert_eq!(desktop.investigation.source, "browsed.pcap");
        assert_eq!(desktop.investigation.destination, "browsed.thcase");
        desktop.investigation.destination = "user chosen.thcase".into();
        desktop.dropped_file("dropped.pcapng".into());
        assert_eq!(desktop.investigation.source, "dropped.pcapng");
        assert_eq!(desktop.investigation.destination, "user chosen.thcase");
        assert!(!desktop.active());
        assert!(desktop.task.is_none() && desktop.workers.is_empty());

        desktop.page = Page::Reports;
        desktop.dropped_file("saved report.json".into());
        assert_eq!(desktop.open_path, "saved report.json");
        assert_eq!(desktop.investigation.source, "dropped.pcapng");
    }

    #[test]
    fn history_round_trip_keeps_findings_hidden_by_the_view_filter() {
        let directory = std::env::temp_dir().join(format!(
            "tracehound-desktop-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut desktop = Desktop::default();
        desktop.document(report());
        desktop.view_floor = Severity::High;
        desktop.rebuild_filter();
        drain(&mut desktop);
        assert_eq!(desktop.filtered.len(), 1);
        let document = desktop.result.clone().unwrap();
        let root = directory.clone();
        desktop.work(false, move || {
            let store = ReportStore::new(root);
            let entry = store.save(document.as_ref())?;
            store
                .open(&entry.id)
                .map(|document| Work::Document(Arc::new(document)))
        });
        drain(&mut desktop);
        assert_eq!(findings(desktop.result.as_deref(), 0).len(), 2);
        assert_eq!(
            enrichment(desktop.result.as_deref().unwrap(), 0)["input_packets"],
            12
        );
        let entries = ReportStore::new(directory.clone()).list().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].findings, 2);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn waiting_file_work_keeps_the_workspace_available() {
        let (release, wait) = mpsc::channel();
        let mut desktop = Desktop::default();
        desktop.work(false, move || {
            wait.recv().map_err(|e| e.to_string())?;
            Ok(Work::Message("finished".into()))
        });
        let started = Instant::now();
        desktop.poll();
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(desktop.busy());
        assert!(!desktop.active());
        release.send(()).unwrap();
        drain(&mut desktop);
        assert_eq!(desktop.notice.as_deref(), Some("finished"));
        assert!(!desktop.busy());
    }

    #[test]
    fn all_workspace_pages_and_evaluation_context_render_headlessly() {
        let mut desktop = Desktop::default();
        let document = report();
        let ReportDocument::Analysis(analysis) = document.as_ref() else {
            unreachable!()
        };
        let case = tracehound_eval::CaptureCase {
            name: "Labelled capture".into(),
            capture: "capture.pcap".into(),
            expected: Vec::new(),
            benign_hosts: Vec::new(),
            min_severity: Severity::Low,
        };
        let alerts = analysis
            .report
            .findings
            .iter()
            .flat_map(|finding| std::iter::repeat_n(finding.alert.clone(), finding.occurrences))
            .collect::<Vec<_>>();
        let mut evaluated = tracehound_eval::evaluate(&case, &alerts).unwrap();
        evaluated.enrichment = analysis.enrichment.clone();
        let suite = SuiteReport::from_cases(vec![evaluated]);
        let mut observed = analysis.clone();
        observed.capture = "observation.pcap".into();
        let sources = vec![
            json!({"id":"labelled", "sha256":"0".repeat(64), "source_url":"https://example.test/labelled", "license":"test fixture"}),
            json!({"id":"observation", "sha256":"1".repeat(64), "source_url":"https://example.test/observation", "license":"test fixture"}),
        ];
        let corpus = ReportDocument::Corpus(Box::new(store::CorpusReport {
            schema_version: 1,
            mode: "corpus_evaluation".into(),
            sources: sources.clone(),
            evaluation: suite.clone(),
            observations: vec![observed],
            validation: None,
        }));
        let serialized = serde_json::to_value(&corpus).unwrap();
        assert_eq!(serialized["sources"], json!(sources));
        assert_eq!(serialized["observations"].as_array().unwrap().len(), 1);
        let corpus = ReportDocument::from_value(serialized).unwrap();
        let context = egui::Context::default();
        for document in [ReportDocument::Suite(Box::new(suite)), corpus] {
            let captures = if matches!(&document, ReportDocument::Corpus(_)) {
                2
            } else {
                1
            };
            desktop.document(Arc::new(document));
            drain(&mut desktop);
            for selected_case in 0..captures {
                desktop.case = selected_case;
                desktop.view_floor = current_floor(desktop.result.as_deref(), selected_case);
                desktop.rebuild_filter();
                drain(&mut desktop);
                desktop.selected = Some(0);
                if selected_case == 1 {
                    assert!(evaluation(desktop.result.as_deref(), selected_case).is_none());
                    assert!(
                        case_title(desktop.result.as_deref().unwrap(), selected_case)
                            .contains("observation.pcap")
                    );
                    assert_eq!(
                        enrichment(desktop.result.as_deref().unwrap(), selected_case)
                            ["input_packets"],
                        12
                    );
                }
                for page in [
                    Page::Capture,
                    Page::Investigation,
                    Page::Suite,
                    Page::Live,
                    Page::Reports,
                    Page::Settings,
                ] {
                    for result_page in [
                        ResultPage::Findings,
                        ResultPage::Protocols,
                        ResultPage::Evaluation,
                    ] {
                        desktop.result_page = result_page;
                        let output = context.run_ui(egui::RawInput::default(), |ui| {
                            egui::CentralPanel::default().show(ui, |ui| {
                                match page {
                                    Page::Capture => desktop.capture_page(ui),
                                    Page::Investigation => desktop.investigation_page(ui),
                                    Page::Suite => desktop.suite_page(ui),
                                    Page::Live => desktop.live_page(ui),
                                    Page::Reports => desktop.reports_page(ui),
                                    Page::Settings => desktop.settings_page(ui),
                                }
                                desktop.results(ui);
                            });
                        });
                        assert!(!output.shapes.is_empty());
                        output.drop_without_applying_deltas();
                    }
                }
                drain(&mut desktop);
                assert_eq!(desktop.filtered.len(), 2);
            }
        }
    }
}
