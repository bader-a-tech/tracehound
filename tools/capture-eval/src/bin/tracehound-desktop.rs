#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use eframe::egui::{self, Color32, RichText};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::Duration;
use tracehound_eval::runtime::{CaptureJob, JobReport, JobState, SensorOptions};
use tracehound_eval::{AnalysisReport, Finding, Severity};

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 780.0])
            .with_min_inner_size([760.0, 560.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "Tracehound — capture analysis",
        options,
        Box::new(|_| Ok(Box::new(Desktop::default()))),
    )
}

struct Desktop {
    capture_text: String,
    dropped_capture: Option<PathBuf>,
    sensor_text: String,
    rules_text: String,
    home_nets_text: String,
    timeout_seconds: u64,
    max_alerts: usize,
    reporting_floor: Severity,
    job: Option<CaptureJob>,
    result: Option<Arc<JobReport>>,
    collected_result: bool,
    state: Option<JobState>,
    alert_records: usize,
    unique_findings: usize,
    elapsed_ms: u64,
    search: String,
    view_floor: Severity,
    filtered: Vec<usize>,
    selected: Option<usize>,
    export_text: String,
    export_receiver: Option<mpsc::Receiver<Result<PathBuf, String>>>,
    error: Option<String>,
    notice: Option<String>,
    closing: bool,
}

impl Default for Desktop {
    fn default() -> Self {
        Self {
            capture_text: String::new(),
            dropped_capture: None,
            sensor_text: find_sensor().to_string_lossy().into_owned(),
            rules_text: String::new(),
            home_nets_text: String::new(),
            timeout_seconds: 300,
            max_alerts: 1_000_000,
            reporting_floor: Severity::Low,
            job: None,
            result: None,
            collected_result: false,
            state: None,
            alert_records: 0,
            unique_findings: 0,
            elapsed_ms: 0,
            search: String::new(),
            view_floor: Severity::Low,
            filtered: Vec::new(),
            selected: None,
            export_text: String::new(),
            export_receiver: None,
            error: None,
            notice: None,
            closing: false,
        }
    }
}

impl Desktop {
    fn active(&self) -> bool {
        self.state.is_some_and(|state| !state.is_terminal())
    }

    fn capture_path(&self) -> PathBuf {
        self.dropped_capture
            .clone()
            .unwrap_or_else(|| PathBuf::from(self.capture_text.trim()))
    }

    fn start(&mut self) {
        let capture = self.capture_path();
        if capture.as_os_str().is_empty() {
            self.error = Some(
                "Choose a capture first: drop a PCAP or PCAPNG file here, or paste its path."
                    .into(),
            );
            return;
        }
        if self.sensor_text.trim().is_empty() {
            self.error = Some("Set the Tracehound executable in Analysis settings.".into());
            return;
        }
        let options = SensorOptions {
            executable: OsString::from(self.sensor_text.trim()),
            rules: optional_path(&self.rules_text),
            home_nets: non_empty(&self.home_nets_text).map(OsString::from),
            timeout: Duration::from_secs(self.timeout_seconds),
            max_alerts: self.max_alerts,
        };
        match CaptureJob::analyze(capture.clone(), options, self.reporting_floor) {
            Ok(job) => {
                self.state = Some(job.snapshot().state);
                self.job = Some(job);
                self.result = None;
                self.collected_result = false;
                self.alert_records = 0;
                self.unique_findings = 0;
                self.elapsed_ms = 0;
                self.filtered.clear();
                self.selected = None;
                self.view_floor = self.reporting_floor;
                self.error = None;
                self.notice = None;
                self.export_text = capture
                    .with_extension("tracehound.json")
                    .to_string_lossy()
                    .into_owned();
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn poll(&mut self) {
        if let Some(job) = &self.job {
            let snapshot = job.snapshot();
            self.state = Some(snapshot.state);
            self.alert_records = snapshot.alert_records;
            self.unique_findings = snapshot.unique_findings;
            self.elapsed_ms = snapshot.elapsed_ms;
            if !self.collected_result {
                if let Some(result) = job.try_result() {
                    self.collected_result = true;
                    match result {
                        Ok(report) => {
                            if let JobReport::Analysis(capture) = report.as_ref() {
                                self.unique_findings = capture.report.findings.len();
                            }
                            self.result = Some(report);
                            self.error = None;
                            self.rebuild_filter();
                        }
                        Err(error) if matches!(self.state, Some(JobState::Cancelled)) => {
                            self.notice = Some(
                                "Analysis cancelled. No partial result was marked complete.".into(),
                            );
                            self.error = None;
                            let _ = error;
                        }
                        Err(error) => self.error = Some(error.to_string()),
                    }
                }
            }
        }
        if let Some(receiver) = &self.export_receiver {
            match receiver.try_recv() {
                Ok(Ok(path)) => {
                    self.notice = Some(format!("Report saved to {}", path.display()));
                    self.export_receiver = None;
                }
                Ok(Err(error)) => {
                    self.error = Some(error);
                    self.export_receiver = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.error =
                        Some("The report could not be saved because its worker stopped.".into());
                    self.export_receiver = None;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
    }

    fn analysis(&self) -> Option<&AnalysisReport> {
        match self.result.as_deref() {
            Some(JobReport::Analysis(report)) => Some(&report.report),
            _ => None,
        }
    }

    fn rebuild_filter(&mut self) {
        let query = self.search.to_lowercase();
        self.filtered = self
            .analysis()
            .map(|report| {
                report
                    .findings
                    .iter()
                    .enumerate()
                    .filter_map(|(index, finding)| {
                        if finding.alert.severity < self.view_floor {
                            return None;
                        }
                        let matches = query.is_empty()
                            || finding.alert.title.to_lowercase().contains(&query)
                            || finding.alert.rule_id.to_lowercase().contains(&query)
                            || finding
                                .alert
                                .src
                                .is_some_and(|addr| addr.to_string().contains(&query))
                            || finding
                                .alert
                                .dst
                                .is_some_and(|addr| addr.to_string().contains(&query))
                            || finding
                                .alert
                                .description
                                .as_deref()
                                .is_some_and(|text| text.to_lowercase().contains(&query))
                            || finding
                                .alert
                                .evidence
                                .to_string()
                                .to_lowercase()
                                .contains(&query);
                        matches.then_some(index)
                    })
                    .collect()
            })
            .unwrap_or_default();
        if self
            .selected
            .is_some_and(|index| !self.filtered.contains(&index))
        {
            self.selected = None;
        }
    }

    fn export(&mut self) {
        let Some(report) = self.result.clone() else {
            return;
        };
        let path = PathBuf::from(self.export_text.trim());
        if path.as_os_str().is_empty() {
            self.error = Some("Enter a destination for the JSON report.".into());
            return;
        }
        let (sender, receiver) = mpsc::channel();
        self.export_receiver = Some(receiver);
        self.error = None;
        self.notice = None;
        std::thread::spawn(move || {
            let _ = sender.send(write_report(&path, report.as_ref()).map(|()| path));
        });
    }

    fn setup(&mut self, ui: &mut egui::Ui) {
        let active = self.active();
        ui.group(|ui| {
            ui.add_enabled_ui(!active && !self.closing, |ui| {
                ui.strong("Open a capture");
                ui.label("Drop a PCAP or PCAPNG file into this window, or paste its full path.");
                let label = ui.label("Capture file");
                let input = ui.add(egui::TextEdit::singleline(&mut self.capture_text)
                    .hint_text("Path to your capture.pcapng")
                    .desired_width(f32::INFINITY))
                    .labelled_by(label.id);
                if input.changed() {
                    self.dropped_capture = None;
                }
                ui.add_space(6.0);
                egui::CollapsingHeader::new("Analysis settings").show(ui, |ui| {
                    let label = ui.label("Tracehound executable");
                    ui.add(egui::TextEdit::singleline(&mut self.sensor_text).desired_width(f32::INFINITY))
                        .labelled_by(label.id);
                    ui.small("The sensor analyses packets locally. Use a full path if Tracehound is not installed on PATH.");
                    ui.horizontal(|ui| {
                        ui.label("Report severity");
                        severity_selector(ui, "reporting-floor", &mut self.reporting_floor);
                        ui.label("Timeout (seconds; 0 means unlimited)");
                        ui.add(egui::DragValue::new(&mut self.timeout_seconds).range(0..=86_400));
                    });
                    ui.horizontal(|ui| {
                        ui.label("Maximum alert records");
                        ui.add(egui::DragValue::new(&mut self.max_alerts).range(1..=10_000_000));
                    });
                    let label = ui.label("Custom rule directory (optional)");
                    ui.add(egui::TextEdit::singleline(&mut self.rules_text).desired_width(f32::INFINITY))
                        .labelled_by(label.id);
                    let label = ui.label("Internal networks (optional, comma-separated CIDRs)");
                    ui.add(egui::TextEdit::singleline(&mut self.home_nets_text)
                        .hint_text("10.0.0.0/8,192.168.0.0/16")
                        .desired_width(f32::INFINITY))
                        .labelled_by(label.id);
                });
            });
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                if ui.add_enabled(!active && !self.closing, egui::Button::new("Analyse capture").min_size(egui::vec2(140.0, 32.0))).clicked() {
                    self.start();
                }
                if active {
                    if ui.button("Cancel analysis").clicked() {
                        if let Some(job) = &self.job {
                            job.cancel();
                        }
                    }
                    ui.spinner();
                }
                ui.strong(status_label(self.state));
                if self.state.is_some() {
                    let findings = if matches!(self.state, Some(JobState::Completed)) {
                        format!("{} findings", self.unique_findings)
                    } else {
                        format!("{} findings so far (provisional)", self.unique_findings)
                    };
                    ui.label(format!("{findings} · {} alert records · {:.1}s", self.alert_records, self.elapsed_ms as f64 / 1000.0));
                }
            });
            if active {
                ui.small("Findings so far are provisional until analysis completes. Repeated alert records are grouped into unique findings at the selected analysis severity; these counts are not packet progress.");
            }
        });
    }

    fn results(&mut self, ui: &mut egui::Ui) {
        let Some(report) = self.result.clone() else {
            ui.add_space(28.0);
            ui.vertical_centered(|ui| {
                ui.heading(if self.active() { "Analysis is running" } else { "Your findings will appear here" });
                ui.label(if self.active() {
                    "You can cancel at any time. The interface stays available while the capture is processed."
                } else {
                    "Open a capture to see the evidence behind each detection."
                });
            });
            return;
        };
        let JobReport::Analysis(capture) = report.as_ref() else {
            return;
        };
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.heading("Findings");
            ui.label(format!(
                "{} unique · {} alert records",
                capture.report.findings.len(),
                capture.report.total_alerts
            ));
        });
        ui.small("These are sensor findings. Without evaluation labels, this view does not measure accuracy or establish that a capture is safe.");
        ui.label(format!("Analysed capture: {}", capture.capture.display()));
        ui.small(format!(
            "This analysis collected findings at {} and above. Analyse again at a lower reporting severity to include lower levels.",
            capture.report.min_severity
        ));
        ui.horizontal(|ui| {
            let search = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search host, domain, rule, or evidence")
                    .desired_width(340.0),
            );
            let previous = self.view_floor;
            ui.label("Minimum severity");
            severity_selector_min(
                ui,
                "view-floor",
                &mut self.view_floor,
                capture.report.min_severity,
            );
            if search.changed() || previous != self.view_floor {
                self.rebuild_filter();
            }
            ui.label(format!("{} shown", self.filtered.len()));
        });
        ui.separator();
        if capture.report.findings.is_empty() {
            ui.label("No findings at the selected analysis severity. You can analyse again with a lower reporting floor in Analysis settings.");
        } else if self.filtered.is_empty() {
            ui.label("No findings match these filters. Clear the search or lower the view's severity filter.");
        } else {
            ui.columns(2, |columns| {
                columns[0].strong("Select a finding");
                let row_height = 68.0;
                egui::ScrollArea::vertical()
                    .id_salt("findings-list")
                    .max_height(300.0)
                    .show_rows(
                        &mut columns[0],
                        row_height,
                        self.filtered.len(),
                        |ui, range| {
                            for position in range {
                                let index = self.filtered[position];
                                let finding = &capture.report.findings[index];
                                let text = format!(
                                    "{} · {}\n{}\n{} → {}",
                                    finding.alert.severity.to_string().to_uppercase(),
                                    finding.alert.rule_id,
                                    finding.alert.title,
                                    finding.alert.src.map(|a| a.to_string()).unwrap_or_default(),
                                    finding
                                        .alert
                                        .dst
                                        .map(|a| a.to_string())
                                        .unwrap_or_else(|| "multiple destinations".into())
                                );
                                if ui
                                    .add_sized(
                                        [ui.available_width(), row_height - 4.0],
                                        egui::Button::new(text)
                                            .selected(self.selected == Some(index)),
                                    )
                                    .clicked()
                                {
                                    self.selected = Some(index);
                                }
                            }
                        },
                    );
                columns[1].strong("Evidence and details");
                egui::ScrollArea::vertical()
                    .id_salt("finding-details")
                    .max_height(300.0)
                    .show(&mut columns[1], |ui| {
                        if let Some(index) = self.selected {
                            finding_details(ui, &capture.report.findings[index]);
                        } else {
                            ui.label(
                                "Choose a finding to inspect its explanation and measurements.",
                            );
                        }
                    });
            });
        }
        ui.separator();
        ui.horizontal(|ui| {
            let label = ui.label("JSON report");
            ui.add(egui::TextEdit::singleline(&mut self.export_text).desired_width(400.0))
                .labelled_by(label.id);
            if ui
                .add_enabled(
                    self.export_receiver.is_none() && !self.closing,
                    egui::Button::new("Export report"),
                )
                .clicked()
            {
                self.export();
            }
            if self.export_receiver.is_some() {
                ui.spinner();
                ui.label("Saving…");
            }
        });
        ui.small("Exports include every finding from this analysis, regardless of the current view filters. Existing files are preserved.");
    }
}

impl eframe::App for Desktop {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        if ui.ctx().input(|input| input.viewport().close_requested())
            && (self.active() || self.export_receiver.is_some())
        {
            self.closing = true;
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::CancelClose);
            if let Some(job) = &self.job {
                job.cancel();
                self.state = Some(job.snapshot().state);
            }
        }
        if self.closing && !self.active() && self.export_receiver.is_none() {
            self.closing = false;
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if self.active() || self.export_receiver.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        }
        if !self.active() {
            let dropped = ui.ctx().input(|input| {
                input
                    .raw
                    .dropped_files
                    .iter()
                    .map(|file| file.path().to_path_buf())
                    .collect::<Vec<_>>()
            });
            if dropped.len() == 1 {
                self.capture_text = dropped[0].to_string_lossy().into_owned();
                self.dropped_capture = Some(dropped[0].clone());
                self.error = None;
            } else if dropped.len() > 1 {
                self.error =
                    Some("Open one capture at a time. Drop a single PCAP or PCAPNG file.".into());
            }
        }
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("application")
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("Tracehound");
                        ui.label("CAPTURE ANALYSIS");
                    });
                    ui.label("Investigate network captures with the evidence behind each finding.");
                    ui.add_space(12.0);
                    self.setup(ui);
                    if self.closing {
                        ui.add_space(8.0);
                        ui.strong(if self.active() {
                            "Stopping analysis before closing…"
                        } else {
                            "Finishing report export before closing…"
                        });
                    }
                    if let Some(error) = &self.error {
                        ui.add_space(8.0);
                        ui.group(|ui| {
                            ui.colored_label(
                                severity_color(ui, Severity::High),
                                RichText::new("Action needed").strong(),
                            );
                            ui.label(error);
                        });
                    }
                    if let Some(notice) = &self.notice {
                        ui.add_space(8.0);
                        ui.label(notice);
                    }
                    self.results(ui);
                });
        });
    }
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
    if let Some(score) = alert.score {
        ui.label(format!("Sensor confidence score: {score:.2}"));
    }
    if let Some(time) = &alert.time {
        ui.label(format!("Latest observation: {time}"));
    }
    ui.separator();
    ui.strong("Measurements");
    if let Some(evidence) = alert.evidence.as_object() {
        for (name, value) in evidence {
            ui.horizontal_wrapped(|ui| {
                ui.strong(name.replace('_', " "));
                ui.monospace(
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string()),
                );
            });
        }
    } else {
        ui.monospace(alert.evidence.to_string());
    }
    if !alert.extra.is_empty() {
        ui.collapsing("Additional sensor metadata", |ui| {
            if let Ok(text) = serde_json::to_string_pretty(&alert.extra) {
                ui.monospace(text);
            }
        });
    }
}

fn severity_selector(ui: &mut egui::Ui, id: &str, value: &mut Severity) {
    severity_selector_min(ui, id, value, Severity::Info);
}

fn severity_selector_min(
    ui: &mut egui::Ui,
    id: &str,
    value: &mut Severity,
    collected_floor: Severity,
) {
    *value = (*value).max(collected_floor);
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
                ui.add_enabled_ui(severity >= collected_floor, |ui| {
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

fn status_label(state: Option<JobState>) -> &'static str {
    match state {
        None => "Ready",
        Some(JobState::Starting) => "Starting…",
        Some(JobState::Running) => "Analysing…",
        Some(JobState::Cancelling) => "Cancelling…",
        Some(JobState::Completed) => "Completed",
        Some(JobState::Cancelled) => "Cancelled",
        Some(JobState::TimedOut) => "Timed out",
        Some(JobState::Failed) => "Failed",
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
                let candidate = root.join(directory).join(filename);
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }
    filename.into()
}

fn write_report(path: &Path, report: &JobReport) -> Result<(), String> {
    let text =
        serde_json::to_string_pretty(report).map_err(|error| format!("Prepare report: {error}"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "Save report {}: {error}. Choose a new filename if it already exists.",
                path.display()
            )
        })?;
    writeln!(file, "{text}").map_err(|error| format!("Write report {}: {error}", path.display()))
}
