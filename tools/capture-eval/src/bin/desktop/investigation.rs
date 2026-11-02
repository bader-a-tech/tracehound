use eframe::egui::{self, RichText};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;
use tracehound_eval::baseline::BaselineComparison;
use tracehound_eval::capture::PacketRef;
use tracehound_eval::case_export::{self, PacketPreview};
use tracehound_eval::case_job::InvestigationJob;
use tracehound_eval::investigation::{
    CaseIndex, CaseOverview, ConnectionSummary, HostSummary, TimelineEvent, TimelinePage,
};
use tracehound_eval::streaming::StreamOptions;

const PAGE: usize = 100;

#[derive(Clone, Copy)]
pub enum CasePath {
    Capture,
    Destination,
    Open,
    Export,
    PacketExport,
    Baseline,
    Wireshark,
    Source,
}
#[derive(Clone, Copy, PartialEq)]
enum HostTab {
    Timeline,
    Connections,
    Packets,
}
#[derive(Clone, Copy, PartialEq)]
enum EvidenceScope {
    Host,
    Event,
    Packet,
}

enum Work {
    Started(InvestigationJob, PathBuf),
    Opened(PathBuf, CaseOverview, Vec<HostSummary>),
    Hosts(u64, Vec<HostSummary>),
    Host(IpAddr, TimelinePage, Vec<ConnectionSummary>, Vec<PacketRef>),
    Timeline(TimelinePage),
    Connections(Vec<ConnectionSummary>),
    Packets(Vec<PacketRef>),
    Packet(PacketPreview),
    Wireshark(PathBuf),
    Comparison(Box<BaselineComparison>),
    Message(String),
}
struct Worker {
    generation: u64,
    starting: bool,
    cancelled: Arc<AtomicBool>,
    receiver: mpsc::Receiver<Result<Work, String>>,
}

pub struct InvestigationUi {
    pub source: String,
    pub destination: String,
    pub open: String,
    pub export: String,
    pub packet_export: String,
    pub baseline: String,
    pub wireshark: String,
    pub original_override: String,
    overview: Option<CaseOverview>,
    path: Option<PathBuf>,
    hosts: Vec<HostSummary>,
    host_offset: u64,
    host_filter: String,
    applied_filter: String,
    selected_host: Option<IpAddr>,
    timeline: Vec<TimelineEvent>,
    next_event: Option<u64>,
    selected_event: Option<u64>,
    connections: Vec<ConnectionSummary>,
    packet_refs: Vec<PacketRef>,
    packet_number: u64,
    packet: Option<PacketPreview>,
    evidence_scope: EvidenceScope,
    export_name: String,
    include_packets: bool,
    baseline_seconds: u64,
    comparison: Option<BaselineComparison>,
    tab: HostTab,
    generation: u64,
    workers: Vec<Worker>,
    job: Option<InvestigationJob>,
    job_path: Option<PathBuf>,
    collected: bool,
    stop_requested: bool,
    status: String,
    error: Option<String>,
    notice: Option<String>,
    browse: Option<CasePath>,
    reveal_setup: bool,
}

impl Default for InvestigationUi {
    fn default() -> Self {
        Self {
            source: String::new(),
            destination: String::new(),
            open: String::new(),
            export: String::new(),
            packet_export: String::new(),
            baseline: String::new(),
            wireshark: String::new(),
            original_override: String::new(),
            overview: None,
            path: None,
            hosts: Vec::new(),
            host_offset: 0,
            host_filter: String::new(),
            applied_filter: String::new(),
            selected_host: None,
            timeline: Vec::new(),
            next_event: None,
            selected_event: None,
            connections: Vec::new(),
            packet_refs: Vec::new(),
            packet_number: 1,
            packet: None,
            evidence_scope: EvidenceScope::Host,
            export_name: "tracehound-host-export".into(),
            include_packets: false,
            baseline_seconds: 0,
            comparison: None,
            tab: HostTab::Timeline,
            generation: 0,
            workers: Vec::new(),
            job: None,
            job_path: None,
            collected: false,
            stop_requested: false,
            status: "Choose a capture or open a saved investigation.".into(),
            error: None,
            notice: None,
            browse: None,
            reveal_setup: false,
        }
    }
}

impl InvestigationUi {
    pub fn select_capture(&mut self, capture: &str) {
        let capture = capture.trim();
        if capture.is_empty() {
            return;
        }
        self.source = capture.into();
        if self.destination.trim().is_empty() {
            self.destination = PathBuf::from(capture)
                .with_extension("thcase")
                .to_string_lossy()
                .into_owned();
        }
        self.reveal_setup = true;
    }

    pub fn smoke_ready(&mut self) -> Result<bool, String> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        if self.busy() {
            return Ok(false);
        }
        if self.overview.is_none() {
            return Err("Smoke case did not open.".into());
        }
        if self.selected_host.is_none() {
            let host = self
                .hosts
                .first()
                .ok_or("Smoke case has no IP hosts")?
                .address;
            self.select_host(host);
            return Ok(false);
        }
        if self.packet.is_none() {
            let number = self
                .packet_refs
                .first()
                .ok_or("Smoke host has no indexed packets")?
                .number;
            self.selected_event = self.timeline.first().map(|event| event.id);
            self.tab = HostTab::Timeline;
            self.read_packet(number);
            return Ok(false);
        }
        Ok(true)
    }
    pub fn active(&self) -> bool {
        self.workers.iter().any(|w| w.starting)
            || self
                .job
                .as_ref()
                .is_some_and(|job| !job.snapshot().state.is_terminal())
    }
    pub fn busy(&self) -> bool {
        self.active() || !self.workers.is_empty()
    }
    pub fn cancel(&mut self) {
        self.stop_requested = true;
        if let Some(job) = &self.job {
            job.cancel();
        }
        for worker in &self.workers {
            worker.cancelled.store(true, Ordering::Release);
        }
    }
    pub fn take_browse(&mut self) -> Option<CasePath> {
        self.browse.take()
    }
    fn work(
        &mut self,
        starting: bool,
        run: impl FnOnce(Arc<AtomicBool>) -> Result<Work, String> + Send + 'static,
    ) {
        self.stop_requested = false;
        let (sender, receiver) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        self.workers.push(Worker {
            generation: self.generation,
            starting,
            cancelled: Arc::clone(&cancelled),
            receiver,
        });
        std::thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if cancelled.load(Ordering::Acquire) {
                    return Err("Investigation operation cancelled.".into());
                }
                run(cancelled)
            }))
            .unwrap_or_else(|_| Err("Investigation operation stopped unexpectedly.".into()));
            let _ = sender.send(result);
        });
    }
    fn reset_view(&mut self) {
        self.overview = None;
        self.path = None;
        self.comparison = None;
        self.host_filter.clear();
        self.applied_filter.clear();
        self.generation += 1;
        self.host_offset = 0;
        self.hosts.clear();
        self.selected_host = None;
        self.timeline.clear();
        self.connections.clear();
        self.packet_refs.clear();
        self.packet = None;
        self.selected_event = None;
        self.next_event = None;
        self.error = None;
        self.notice = None;
        self.packet_number = 1;
    }
    pub fn open_case(&mut self, path: PathBuf) {
        self.reset_view();
        self.stop_requested = false;
        self.status = "Opening saved investigation…".into();
        self.work(false, move |cancelled| {
            let index = open_index(&path, &cancelled)?;
            let overview = index.overview().clone();
            let hosts = index.hosts(0, PAGE)?;
            if cancelled.load(Ordering::Acquire) {
                return Err("Opening investigation cancelled.".into());
            }
            Ok(Work::Opened(path, overview, hosts))
        });
    }
    fn build(&mut self, options: StreamOptions, timeout: Duration) {
        self.reset_view();
        self.stop_requested = false;
        self.status = "Starting Rust investigation…".into();
        let source = PathBuf::from(self.source.trim());
        let destination = PathBuf::from(self.destination.trim());
        self.work(true, move |_| {
            let job = InvestigationJob::start(source, destination.clone(), options, timeout)?;
            Ok(Work::Started(job, destination))
        });
    }
    pub fn poll(&mut self) {
        let mut finished = Vec::new();
        for (i, worker) in self.workers.iter().enumerate() {
            match worker.receiver.try_recv() {
                Ok(result) => finished.push((i, result)),
                Err(mpsc::TryRecvError::Disconnected) => finished.push((
                    i,
                    Err("Investigation worker closed before returning a result.".into()),
                )),
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        for (i, result) in finished.into_iter().rev() {
            let worker = self.workers.remove(i);
            if worker.generation != self.generation {
                if let Ok(Work::Started(job, _)) = result {
                    job.cancel();
                }
                continue;
            }
            match result {
                Err(error) => {
                    if !self.stop_requested {
                        self.error = Some(error);
                    }
                }
                Ok(Work::Started(job, path)) => {
                    if self.stop_requested {
                        job.cancel();
                    }
                    self.job = Some(job);
                    self.job_path = Some(path);
                    self.collected = false;
                }
                Ok(Work::Opened(path, overview, hosts)) => {
                    self.open = path.to_string_lossy().into_owned();
                    self.path = Some(path);
                    self.overview = Some(overview);
                    self.hosts = hosts;
                    self.status =
                        "Investigation ready. Select a host to follow its traffic.".into();
                    self.notice=Some("Packet reads and exports verify the original capture's SHA-256 before using its bytes.".into());
                }
                Ok(Work::Hosts(offset, hosts)) => {
                    self.host_offset = offset;
                    self.hosts = hosts;
                }
                Ok(Work::Host(host, page, connections, packets)) => {
                    if self.selected_host == Some(host) {
                        self.timeline = page.events;
                        self.next_event = page.next_id;
                        self.connections = connections;
                        self.packet_refs = packets;
                    }
                }
                Ok(Work::Timeline(page)) => {
                    self.timeline = page.events;
                    self.next_event = page.next_id;
                    self.selected_event = None;
                }
                Ok(Work::Connections(rows)) => self.connections = rows,
                Ok(Work::Packets(rows)) => self.packet_refs = rows,
                Ok(Work::Packet(preview)) => {
                    if preview.reference.number == self.packet_number {
                        self.packet = Some(preview);
                    }
                }
                Ok(Work::Wireshark(path)) => self.wireshark = path.to_string_lossy().into_owned(),
                Ok(Work::Comparison(value)) => self.comparison = Some(*value),
                Ok(Work::Message(message)) => self.notice = Some(message),
            }
        }
        let completed = self.job.as_ref().and_then(|job| {
            let snapshot = job.snapshot();
            if !snapshot.state.is_terminal() || !self.collected {
                self.status = format!(
                    "{:?} · {} original packets · {} findings · {:.1}s",
                    snapshot.state,
                    snapshot.packets,
                    snapshot.findings,
                    snapshot.elapsed_ms as f64 / 1000.0
                );
            }
            if !self.collected {
                job.try_result()
            } else {
                None
            }
        });
        if let Some(outcome) = completed {
            self.collected = true;
            match outcome {
                Ok(_) => {
                    if let Some(path) = self.job_path.clone() {
                        if self.stop_requested {
                            self.open = path.to_string_lossy().into_owned();
                            self.status = "Investigation finished finalizing.".into();
                            self.notice = Some(format!(
                                "The completed case was saved at {}. Open it when ready.",
                                path.display()
                            ));
                        } else {
                            self.open_case(path);
                        }
                    }
                }
                Err(error) => {
                    if !self.stop_requested {
                        self.error = Some(error);
                    } else {
                        self.notice =
                            Some("Investigation cancelled. Partial cases were removed.".into());
                    }
                }
            }
        }
    }
    fn select_host(&mut self, host: IpAddr) {
        self.comparison = None;
        self.generation += 1;
        self.selected_host = Some(host);
        self.timeline.clear();
        self.connections.clear();
        self.packet_refs.clear();
        self.packet = None;
        self.selected_event = None;
        self.error = None;
        let Some(path) = self.path.clone() else {
            return;
        };
        self.work(false, move |cancelled| {
            let index = open_index(&path, &cancelled)?;
            Ok(Work::Host(
                host,
                index.timeline(host, 0, PAGE)?,
                index.connections(host, 0, PAGE)?,
                index.host_packets(host, 0, PAGE)?,
            ))
        });
    }
    fn read_packet(&mut self, number: u64) {
        let Some(path) = self.path.clone() else {
            return;
        };
        self.packet_number = number;
        self.packet = None;
        self.error = None;
        let source = super::optional_path(&self.original_override);
        self.work(false, move |cancelled| {
            let index = open_index(&path, &cancelled)?;
            Ok(Work::Packet(case_export::inspect_packet(
                &index,
                number,
                source.as_deref(),
                &|| cancelled.load(Ordering::Acquire),
            )?))
        });
    }
    fn verify(&mut self) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let source = super::optional_path(&self.original_override);
        self.work(false, move |cancelled| {
            let index = open_index(&path, &cancelled)?;
            let _verified =
                index.verify_source(source.as_deref(), &|| cancelled.load(Ordering::Acquire))?;
            Ok(Work::Message(
                "Original capture SHA-256 and byte length match this case.".into(),
            ))
        });
    }
    fn path_row(&mut self, ui: &mut egui::Ui, target: CasePath, label: &str) {
        ui.label(label);
        ui.horizontal(|ui| {
            let text = match target {
                CasePath::Capture => &mut self.source,
                CasePath::Destination => &mut self.destination,
                CasePath::Open => &mut self.open,
                CasePath::Export => &mut self.export,
                CasePath::PacketExport => &mut self.packet_export,
                CasePath::Baseline => &mut self.baseline,
                CasePath::Wireshark => &mut self.wireshark,
                CasePath::Source => &mut self.original_override,
            };
            ui.add(
                egui::TextEdit::singleline(text)
                    .desired_width((ui.available_width() - 80.0).max(150.0)),
            );
            if ui.button("Browse…").clicked() {
                self.browse = Some(target);
            }
        });
    }

    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        options: Result<StreamOptions, String>,
        timeout: Duration,
        current_capture: &str,
        disabled: bool,
    ) {
        ui.heading("Host investigations");
        ui.label("Build a searchable case from an original capture, then follow hosts, connections and the exact packets behind each finding.");
        let reveal_setup = std::mem::take(&mut self.reveal_setup);
        egui::CollapsingHeader::new("Build or open an investigation")
            .default_open(self.overview.is_none())
            .open(reveal_setup.then_some(true))
            .show(ui, |ui| {
            ui.add_enabled_ui(!disabled && !self.active(), |ui| {
                self.path_row(ui, CasePath::Capture, "Original PCAP / PCAPNG");
                if !current_capture.trim().is_empty()
                    && ui.button("Use capture from Analyse").clicked()
                {
                    self.select_capture(current_capture);
                }
                self.path_row(ui, CasePath::Destination, "New case file (.thcase)");
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            !self.source.trim().is_empty() && !self.destination.trim().is_empty(),
                            egui::Button::new("Create investigation"),
                        )
                        .clicked()
                    {
                        match options {
                            Ok(options) => self.build(options, timeout),
                            Err(error) => self.error = Some(error),
                        }
                    }
                    ui.small(
                        "Original packets stay unchanged. An existing case is never overwritten.",
                    );
                });
                ui.small("Internal networks come from Settings. Private ranges are used when no override is set.");
                ui.separator();
                self.path_row(ui, CasePath::Open, "Saved investigation");
                if ui
                    .add_enabled(
                        !self.open.trim().is_empty(),
                        egui::Button::new("Open saved case"),
                    )
                    .clicked()
                {
                    self.open_case(PathBuf::from(self.open.trim()));
                }
            });
        });
        ui.horizontal_wrapped(|ui| {
            if self.busy() {
                ui.spinner();
            }
            ui.label(&self.status);
            if self.busy() && ui.button("Cancel investigation operation").clicked() {
                self.cancel();
            }
        });
        if let Some(error) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        if let Some(notice) = &self.notice {
            ui.label(notice);
        }
        let Some(overview) = self.overview.clone() else {
            return;
        };
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.strong(format!(
                "{} packets · {} connections · {} indexed events",
                overview.packets, overview.flows, overview.events
            ));
            if let Some(first) = overview.first_timestamp_ns {
                ui.label(utc(first));
            }
        });
        if let Some(stats) = overview.analysis.get("stats") {
            super::beacon_ui::show_analysis_context(ui, stats);
        }
        ui.collapsing("Original capture and reproducible analysis", |ui| {
            ui.label(format!("Source: {}", overview.source.display()));
            ui.label(format!("SHA-256: {}", overview.capture.sha256));
            ui.label(format!("{} original file bytes", overview.capture.bytes));
            self.path_row(
                ui,
                CasePath::Source,
                "Original capture moved? Choose its new location (optional)",
            );
            if ui
                .add_enabled(!self.busy(), egui::Button::new("Verify original capture"))
                .clicked()
            {
                self.verify();
            }
            ui.collapsing("Analysis configuration", |ui| {
                super::json_details(ui, &overview.analysis)
            });
            ui.collapsing("Capture diagnostics and coverage", |ui| {
                super::json_details(ui, &overview.diagnostics)
            });
        });
        ui.columns(2, |columns| {
            self.hosts_ui(&mut columns[0]);
            self.host_ui(&mut columns[1]);
        });
    }

    fn hosts_ui(&mut self, ui: &mut egui::Ui) {
        ui.strong("Hosts, ranked by findings and outbound traffic");
        let response = ui.add(
            egui::TextEdit::singleline(&mut self.host_filter)
                .hint_text("Find an IP across all hosts"),
        );
        let enter = response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.busy(), egui::Button::new("Search index"))
                .clicked()
                || (enter && !self.busy())
            {
                self.applied_filter = self.host_filter.trim().to_string();
                self.load_hosts(0);
            }
            if ui
                .add_enabled(
                    !self.applied_filter.is_empty() && !self.busy(),
                    egui::Button::new("Clear search"),
                )
                .clicked()
            {
                self.host_filter.clear();
                self.applied_filter.clear();
                self.load_hosts(0);
            }
        });
        let mut selected = None;
        egui::ScrollArea::vertical()
            .id_salt("investigation-hosts")
            .max_height(500.0)
            .show(ui, |ui| {
                for host in &self.hosts {
                    let title = format!("{} · {} findings", host.address, host.findings);
                    if ui
                        .selectable_label(
                            self.selected_host == Some(host.address),
                            RichText::new(title).strong(),
                        )
                        .clicked()
                    {
                        selected = Some(host.address);
                    }
                    ui.small(format!(
                        "{} connections · {} sent / {} received packets",
                        host.connections, host.packets_sent, host.packets_received
                    ));
                    ui.small(format!(
                        "{} sent · {} received",
                        bytes(host.wire_bytes_sent),
                        bytes(host.wire_bytes_received)
                    ));
                    ui.separator();
                }
                if self.hosts.is_empty() {
                    ui.label("No IP hosts on this page.");
                }
            });
        if let Some(host) = selected {
            self.select_host(host);
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.host_offset > 0 && !self.busy(),
                    egui::Button::new("Previous hosts"),
                )
                .clicked()
            {
                self.load_hosts(self.host_offset.saturating_sub(PAGE as u64));
            }
            ui.label(format!("Page {}", self.host_offset / PAGE as u64 + 1));
            if ui
                .add_enabled(
                    self.hosts.len() == PAGE && !self.busy(),
                    egui::Button::new("Next hosts"),
                )
                .clicked()
            {
                self.load_hosts(self.host_offset + PAGE as u64);
            }
        });
        ui.small("Search runs against the complete case index. Results keep the findings and traffic ranking.");
    }
    fn load_hosts(&mut self, offset: u64) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let query = self.applied_filter.clone();
        self.work(false, move |cancelled| {
            let index = open_index(&path, &cancelled)?;
            Ok(Work::Hosts(
                offset,
                index.search_hosts(&query, offset, PAGE)?,
            ))
        });
    }
    fn host_ui(&mut self, ui: &mut egui::Ui) {
        let Some(host) = self.selected_host else {
            ui.label("Select a host to inspect its timeline and original packet evidence.");
            return;
        };
        ui.heading(host.to_string());
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.tab, HostTab::Timeline, "Timeline");
            ui.selectable_value(&mut self.tab, HostTab::Connections, "Connections");
            ui.selectable_value(&mut self.tab, HostTab::Packets, "Packets");
        });
        match self.tab {
            HostTab::Timeline => self.timeline_ui(ui, host),
            HostTab::Connections => self.connections_ui(ui, host),
            HostTab::Packets => self.packets_ui(ui, host),
        }
        self.packet_ui(ui);
        self.actions_ui(ui, host);
    }
    fn timeline_ui(&mut self, ui: &mut egui::Ui, host: IpAddr) {
        let mut packet = None;
        egui::ScrollArea::vertical().id_salt("host-timeline").max_height(360.0).show(ui,|ui| {
            for event in &self.timeline {
                let title=format!("{} · {}",utc(event.timestamp_ns),event.kind);
                if ui.selectable_label(self.selected_event==Some(event.id),RichText::new(title).strong()).clicked(){self.selected_event=Some(event.id);}
                ui.label(event.summary.replace('→', "->").replace('↔', "<->"));
                ui.small(match event.evidence_kind.as_str(){"packet"=>"Observed in captured packet bytes","detector_evidence"=>"Detector result with supporting packet references",_=>"Related context; this association does not establish causation"});
                if event.packet_refs_truncated{ui.small("This event's packet-reference list is incomplete; browse host packets for the remaining traffic.");}
                ui.horizontal_wrapped(|ui|{for reference in event.packets.iter().take(8){if ui.small_button(format!("Packet {}",reference.number)).clicked(){packet=Some(reference.number);}}if event.packets.len()>8{ui.small(format!("{} supporting packets total",event.packets.len()));}});
                ui.separator();
            }
            if self.timeline.is_empty(){ui.label("No timeline events on this page.");}
        });
        if let Some(number) = packet {
            self.read_packet(number);
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.busy(), egui::Button::new("First events"))
                .clicked()
            {
                self.load_timeline(host, 0);
            }
            if ui
                .add_enabled(
                    self.next_event.is_some() && !self.busy(),
                    egui::Button::new("Next events"),
                )
                .clicked()
            {
                self.load_timeline(host, self.next_event.unwrap_or(0));
            }
        });
        if let Some(event) = self
            .timeline
            .iter()
            .find(|event| Some(event.id) == self.selected_event)
            .cloned()
        {
            ui.collapsing("Selected event details", |ui| {
                if event.kind == "finding" {
                    if let Ok(finding) =
                        serde_json::from_value::<tracehound_eval::Finding>(event.details.clone())
                    {
                        super::finding_details(ui, &finding);
                    } else {
                        super::json_details(ui, &event.details);
                    }
                } else {
                    super::json_details(ui, &event.details);
                }
                ui.label(format!(
                    "{} exact original packet references",
                    event.packets.len()
                ));
                egui::ScrollArea::vertical()
                    .id_salt("event-reference-list")
                    .max_height(140.0)
                    .show_rows(ui, 23.0, event.packets.len(), |ui, range| {
                        for i in range {
                            let reference = &event.packets[i];
                            if ui
                                .button(format!(
                                    "Inspect packet {} · {} bytes",
                                    reference.number, reference.captured_len
                                ))
                                .clicked()
                            {
                                self.read_packet(reference.number);
                            }
                        }
                    });
            });
        }
    }
    fn load_timeline(&mut self, host: IpAddr, cursor: u64) {
        let Some(path) = self.path.clone() else {
            return;
        };
        self.work(false, move |cancelled| {
            let index = open_index(&path, &cancelled)?;
            Ok(Work::Timeline(index.timeline(host, cursor, PAGE)?))
        });
    }
    fn connections_ui(&mut self, ui: &mut egui::Ui, host: IpAddr) {
        egui::ScrollArea::vertical()
            .id_salt("host-connections")
            .max_height(360.0)
            .show(ui, |ui| {
                for flow in &self.connections {
                    ui.strong(format!(
                        "{} {} <-> {}",
                        protocol(flow.protocol),
                        std::net::SocketAddr::new(flow.src, flow.src_port),
                        std::net::SocketAddr::new(flow.dst, flow.dst_port)
                    ));
                    ui.small(format!(
                        "{} · {} packets · {} / {} directional bytes",
                        utc(flow.first_timestamp_ns),
                        flow.forward_packets + flow.reverse_packets,
                        bytes(flow.forward_wire_bytes),
                        bytes(flow.reverse_wire_bytes)
                    ));
                    if flow.protocol == 6 {
                        ui.small(format!(
                            "SYN {} · FIN {} · RST {}",
                            flow.syn_packets, flow.fin_packets, flow.rst_packets
                        ));
                    }
                    ui.separator();
                }
                if self.connections.is_empty() {
                    ui.label("No connections on this page.");
                }
            });
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.busy(), egui::Button::new("First connections"))
                .clicked()
            {
                self.load_connections(host, 0);
            }
            if ui
                .add_enabled(
                    self.connections.len() == PAGE && !self.busy(),
                    egui::Button::new("Next connections"),
                )
                .clicked()
            {
                self.load_connections(host, self.connections.last().map_or(0, |flow| flow.id));
            }
        });
    }
    fn load_connections(&mut self, host: IpAddr, cursor: u64) {
        let Some(path) = self.path.clone() else {
            return;
        };
        self.work(false, move |cancelled| {
            let index = open_index(&path, &cancelled)?;
            Ok(Work::Connections(index.connections(host, cursor, PAGE)?))
        });
    }
    fn packets_ui(&mut self, ui: &mut egui::Ui, host: IpAddr) {
        let mut selected = None;
        egui::ScrollArea::vertical()
            .id_salt("host-original-packets")
            .max_height(360.0)
            .show_rows(ui, 25.0, self.packet_refs.len(), |ui, range| {
                for i in range {
                    let packet = &self.packet_refs[i];
                    if ui
                        .selectable_label(
                            self.packet
                                .as_ref()
                                .is_some_and(|preview| preview.reference.number == packet.number),
                            format!(
                                "#{} · {} · {} bytes{}",
                                packet.number,
                                utc(packet.timestamp_ns),
                                packet.captured_len,
                                if packet.captured_len < packet.original_len {
                                    " (truncated)"
                                } else {
                                    ""
                                }
                            ),
                        )
                        .clicked()
                    {
                        selected = Some(packet.number);
                    }
                }
            });
        if let Some(number) = selected {
            self.read_packet(number);
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.busy(), egui::Button::new("First packets"))
                .clicked()
            {
                self.load_packets(host, 0);
            }
            if ui
                .add_enabled(
                    self.packet_refs.len() == PAGE && !self.busy(),
                    egui::Button::new("Next packets"),
                )
                .clicked()
            {
                self.load_packets(
                    host,
                    self.packet_refs.last().map_or(0, |packet| packet.number),
                );
            }
        });
    }
    fn load_packets(&mut self, host: IpAddr, cursor: u64) {
        let Some(path) = self.path.clone() else {
            return;
        };
        self.work(false, move |cancelled| {
            let index = open_index(&path, &cancelled)?;
            Ok(Work::Packets(index.host_packets(host, cursor, PAGE)?))
        });
    }
    fn packet_ui(&mut self, ui: &mut egui::Ui) {
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Original packet number");
            ui.add(egui::DragValue::new(&mut self.packet_number).range(1..=u64::MAX));
            if ui
                .add_enabled(!self.busy(), egui::Button::new("Verify and inspect"))
                .clicked()
            {
                self.read_packet(self.packet_number);
            }
        });
        let Some(preview) = &self.packet else {
            return;
        };
        let reference = &preview.reference;
        ui.strong(format!(
            "Packet {} · {}",
            reference.number,
            utc(reference.timestamp_ns)
        ));
        ui.small(format!(
            "Original file offset {} · section {} · interface {} · link type {}",
            reference.data_offset, reference.section, reference.interface, reference.link_type
        ));
        ui.small(format!(
            "{} captured / {} wire bytes · original SHA-256 verified",
            reference.captured_len, reference.original_len
        ));
        ui.small(format!("Packet SHA-256: {}", preview.sha256));
        if preview.preview_truncated {
            ui.small("Showing the first 4096 bytes. Export packets or open Wireshark for the complete frame.");
        }
        egui::ScrollArea::both()
            .id_salt("packet-hex")
            .max_height(250.0)
            .show(ui, |ui| {
                ui.monospace(&preview.hex);
            });
        if ui.button("Copy displayed hex").clicked() {
            ui.ctx().copy_text(preview.hex.clone());
        }
    }

    fn selected_numbers(&self) -> Vec<u64> {
        match self.evidence_scope {
            EvidenceScope::Host => Vec::new(),
            EvidenceScope::Event => self
                .timeline
                .iter()
                .find(|event| Some(event.id) == self.selected_event)
                .map(|event| event.packets.iter().map(|packet| packet.number).collect())
                .unwrap_or_default(),
            EvidenceScope::Packet => self
                .packet
                .as_ref()
                .map(|preview| vec![preview.reference.number])
                .unwrap_or_default(),
        }
    }
    fn baseline_ui(&mut self, ui: &mut egui::Ui, host: IpAddr) {
        ui.collapsing("Compare this host with a baseline case",|ui|{
            self.path_row(ui,CasePath::Baseline,"Earlier saved investigation");
            ui.horizontal_wrapped(|ui|{ui.label("Equal window (seconds; 0 = shared coverage)");ui.add(egui::DragValue::new(&mut self.baseline_seconds).range(0..=31_536_000));});
            ui.small("Compare the same IP across equal elapsed windows beginning at each capture's first packet. NAT, DHCP and capture gaps can affect attribution. Changes are observations, not threat verdicts.");
            if ui.add_enabled(!self.baseline.trim().is_empty()&&!self.busy(),egui::Button::new("Compare observed behavior")).clicked(){
                if let Some(after)=self.path.clone(){let before=PathBuf::from(self.baseline.trim());let seconds=(self.baseline_seconds>0).then_some(self.baseline_seconds);
                    self.work(false,move |cancelled|{let comparison=tracehound_eval::baseline::compare_cases_cancellable(&before,&after,host,seconds,Arc::clone(&cancelled))?;if cancelled.load(Ordering::Acquire){return Err("Baseline comparison cancelled.".into());}Ok(Work::Comparison(Box::new(comparison)))});
                }
            }
            if let Some(comparison)=&self.comparison{
                ui.strong(comparison.window_seconds.map(|seconds|format!("Compared {seconds:.3} seconds of each capture")).unwrap_or_else(||"No positive shared duration; rates are unavailable".into()));
                egui::Grid::new("host-baseline-rates").striped(true).show(ui,|ui|{
                    ui.strong("Rate");ui.strong("Baseline");ui.strong("Current");ui.strong("Difference");ui.end_row();
                    for (name,rate) in &comparison.rates{ui.label(name);ui.label(rate.before.map(|n|format!("{n:.3}")).unwrap_or_else(||"—".into()));ui.label(rate.after.map(|n|format!("{n:.3}")).unwrap_or_else(||"—".into()));ui.label(rate.difference.map(|n|format!("{n:+.3}")).unwrap_or_else(||"—".into()));ui.end_row();}
                });
                for (feature,change) in &comparison.changes{
                    ui.collapsing(format!("{feature}: {} added, {} removed, {} unchanged",change.added.len(),change.removed.len(),change.unchanged),|ui|{
                        egui::ScrollArea::vertical().id_salt(("baseline-feature",feature)).max_height(180.0).show(ui,|ui|{for value in &change.added{ui.label(format!("+ {value}"));}for value in &change.removed{ui.label(format!("− {value}"));}});
                    });
                }
                for note in &comparison.notes{ui.small(note);}
                if ui.button("Copy comparison JSON").clicked(){if let Ok(json)=serde_json::to_string_pretty(comparison){ui.ctx().copy_text(json);}}
            }
        });
    }
    fn actions_ui(&mut self, ui: &mut egui::Ui, host: IpAddr) {
        self.baseline_ui(ui, host);
        ui.separator();
        ui.collapsing("Wireshark and packet extraction",|ui|{
            ui.horizontal_wrapped(|ui|{ui.selectable_value(&mut self.evidence_scope,EvidenceScope::Host,"All host traffic");ui.selectable_value(&mut self.evidence_scope,EvidenceScope::Event,"Selected event");ui.selectable_value(&mut self.evidence_scope,EvidenceScope::Packet,"Inspected packet");});
            let numbers=self.selected_numbers();let selected=self.evidence_scope==EvidenceScope::Host||!numbers.is_empty();
            if !selected{ui.small("Select a timeline event with packet references, or inspect a packet first.");}
            if numbers.len()>1000{ui.small("Wireshark filters include the first 1000 selected packet numbers. Packet extraction supports up to 10000.");}
            if ui.add_enabled(selected,egui::Button::new("Copy Wireshark display filter")).clicked(){ui.ctx().copy_text(case_export::wireshark_filter(host,&numbers));}
            self.path_row(ui,CasePath::Wireshark,"Wireshark executable");
            ui.horizontal_wrapped(|ui|{
                if ui.button("Find installed Wireshark").clicked(){self.work(false,move |_|case_export::discover_wireshark().map(Work::Wireshark).ok_or_else(||"No Wireshark installation found. Browse to an existing executable.".into()));}
                if ui.add_enabled(selected&&!self.wireshark.trim().is_empty()&&!self.busy(),egui::Button::new("Verify and open in Wireshark")).clicked(){
                    if let Some(path)=self.path.clone(){let exe=PathBuf::from(self.wireshark.trim());let source=super::optional_path(&self.original_override);let filter=case_export::wireshark_filter(host,&numbers);
                        self.work(false,move |cancelled|{let case=open_index(&path,&cancelled)?;let _verified=case.verify_source(source.as_deref(),&||cancelled.load(Ordering::Acquire))?;if cancelled.load(Ordering::Acquire){return Err("Open in Wireshark cancelled.".into());}case_export::open_wireshark(&exe,source.as_deref().unwrap_or(&case.overview().source),&filter)?;Ok(Work::Message("Opened the verified original capture in Wireshark with the selected display filter.".into()))});
                    }
                }
            });
            self.path_row(ui,CasePath::PacketExport,"New packet export (.pcapng)");
            if ui.add_enabled(!numbers.is_empty()&&!self.packet_export.trim().is_empty()&&!self.busy(),egui::Button::new("Extract selected original packets")).clicked(){
                if let Some(path)=self.path.clone(){let destination=PathBuf::from(self.packet_export.trim());let source=super::optional_path(&self.original_override);
                    self.work(false,move |cancelled|{let case=open_index(&path,&cancelled)?;let count=case_export::export_packets(&case,&numbers,&destination,source.as_deref(),&||cancelled.load(Ordering::Acquire))?;Ok(Work::Message(format!("Extracted {count} original packets to {}",destination.display())))});
                }
            }
            ui.small("Packet extraction uses the selected event or inspected packet. Each exported frame retains original provenance. Choose a new destination file.");
        });
        ui.collapsing("Export this host investigation",|ui|{
            self.path_row(ui,CasePath::Export,"Export parent directory");ui.label("New export folder name");ui.text_edit_singleline(&mut self.export_name);
            ui.checkbox(&mut self.include_packets,"Include supporting original packet bytes");
            ui.small("The standalone HTML and JSON include capture metadata and packet references. Packet bytes are included only when selected; the bundle also includes SHA256SUMS.txt.");

            if ui.add_enabled(!self.export.trim().is_empty()&&!self.export_name.trim().is_empty()&&!self.busy(),egui::Button::new("Export HTML and JSON bundle")).clicked(){
                if self.export_name.contains(['/', '\\'])||self.export_name=="."||self.export_name==".."{self.error=Some("Choose a folder name without path separators.".into());}
                else if let Some(path)=self.path.clone(){let destination=PathBuf::from(self.export.trim()).join(self.export_name.trim());let include=self.include_packets;let source=super::optional_path(&self.original_override);
                    self.work(false,move |cancelled|{let report=case_export::export_host_with_source(&path,host,&destination,include,source.as_deref(),&||cancelled.load(Ordering::Acquire))?;Ok(Work::Message(format!("Exported {} events to {}{}",report.events,report.directory.display(),if report.events_truncated||report.packets_truncated{". The export reports its truncation limits."}else{"."})))});
                }
            }
        });
    }
}

fn open_index(path: &std::path::Path, cancelled: &Arc<AtomicBool>) -> Result<CaseIndex, String> {
    let mut index = CaseIndex::open(path)?;
    let cancelled = Arc::clone(cancelled);
    index.interrupt_when(move || cancelled.load(Ordering::Acquire))?;
    Ok(index)
}
fn protocol(value: u8) -> String {
    match value {
        6 => "TCP".into(),
        17 => "UDP".into(),
        1 => "ICMP".into(),
        58 => "ICMPv6".into(),
        value => format!("IP protocol {value}"),
    }
}
fn bytes(value: u64) -> String {
    if value >= 1_048_576 {
        format!("{:.2} MiB", value as f64 / 1_048_576.0)
    } else if value >= 1024 {
        format!("{:.1} KiB", value as f64 / 1024.0)
    } else {
        format!("{value} B")
    }
}
fn utc(nanoseconds: u64) -> String {
    case_export::format_timestamp_ns(nanoseconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    static NEXT_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "tracehound-case-ui-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            for entry in fs::read_dir(&self.0).unwrap().flatten() {
                let _ = fs::remove_file(entry.path());
            }
            let _ = fs::remove_dir(&self.0);
        }
    }
    fn drain(view: &mut InvestigationUi) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while view.busy() {
            assert!(Instant::now() < deadline, "investigation UI worker stalled");
            view.poll();
            std::thread::sleep(Duration::from_millis(2));
        }
        view.poll();
        assert!(view.error.is_none(), "{:?}", view.error);
    }
    fn capture() -> Vec<u8> {
        let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        bytes.extend([0; 8]);
        bytes.extend(65_535u32.to_le_bytes());
        bytes.extend(101u32.to_le_bytes());
        let mut frame = vec![0u8; 28];
        frame[0] = 0x45;
        frame[2..4].copy_from_slice(&28u16.to_be_bytes());
        frame[9] = 17;
        frame[12..20].copy_from_slice(&[10, 0, 0, 1, 192, 0, 2, 1]);
        frame[20..28].copy_from_slice(&[0xc3, 0x50, 0, 53, 0, 8, 0, 0]);
        bytes.extend(1_700_000_000u32.to_le_bytes());
        bytes.extend(123_456u32.to_le_bytes());
        bytes.extend(28u32.to_le_bytes());
        bytes.extend(28u32.to_le_bytes());
        bytes.extend(frame);
        bytes
    }
    #[test]
    fn capture_selection_suggests_a_case_without_starting_work_or_replacing_user_choices() {
        let directory = Directory::new();
        let source = directory.0.join("original capture.pcapng");
        let existing = source.with_extension("thcase");
        fs::write(&existing, b"existing case must stay unchanged").unwrap();
        let mut view = InvestigationUi::default();
        view.select_capture(&source.to_string_lossy());
        assert_eq!(PathBuf::from(&view.source), source);
        assert_eq!(PathBuf::from(&view.destination), existing);
        assert_eq!(
            fs::read(&existing).unwrap(),
            b"existing case must stay unchanged"
        );
        assert!(!view.busy());
        assert!(view.job.is_none() && view.overview.is_none());

        let chosen = directory.0.join("chosen name.thcase");
        view.destination = chosen.to_string_lossy().into_owned();
        let another = directory.0.join("another.pcap");
        view.select_capture(&another.to_string_lossy());
        assert_eq!(PathBuf::from(&view.source), another);
        assert_eq!(PathBuf::from(&view.destination), chosen);
        assert!(!chosen.exists());
        assert!(!view.busy());
        view.select_capture("   ");
        assert_eq!(PathBuf::from(&view.source), another);
        assert_eq!(PathBuf::from(&view.destination), chosen);
    }

    #[test]
    fn first_investigation_view_exposes_create_action_without_opening_an_accordion() {
        let mut view = InvestigationUi::default();
        let context = egui::Context::default();
        let output = context.run_ui(egui::RawInput::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                view.ui(
                    ui,
                    Ok(StreamOptions::default()),
                    Duration::from_secs(10),
                    "",
                    false,
                );
            });
        });
        assert!(output.shapes.iter().any(|shape| matches!(
            &shape.shape,
            egui::epaint::Shape::Text(text) if text.galley.text() == "Create investigation"
        )));
        output.drop_without_applying_deltas();
        assert!(!view.busy());
    }

    #[test]
    fn real_case_background_queries_packet_verification_and_host_pages_render() {
        let directory = Directory::new();
        let source = directory.0.join("capture.pcap");
        let case = directory.0.join("capture.thcase");
        fs::write(&source, capture()).unwrap();
        CaseIndex::build(&source, &case, &|| false, &mut |_| {}).unwrap();
        let mut view = InvestigationUi::default();
        view.open_case(case);
        drain(&mut view);
        assert_eq!(view.overview.as_ref().unwrap().packets, 1);
        assert_eq!(view.hosts.len(), 2);
        view.applied_filter = "192.0.2".into();
        view.load_hosts(0);
        drain(&mut view);
        assert_eq!(view.hosts.len(), 1);
        assert_eq!(
            view.hosts[0].address,
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
        view.applied_filter.clear();
        view.load_hosts(0);
        drain(&mut view);
        view.select_host("10.0.0.1".parse().unwrap());
        drain(&mut view);
        assert!(!view.timeline.is_empty());
        assert_eq!(view.connections.len(), 1);
        assert_eq!(view.packet_refs.len(), 1);
        view.read_packet(1);
        drain(&mut view);
        assert!(view.packet.as_ref().unwrap().source_verified);
        assert_eq!(view.packet.as_ref().unwrap().reference.data_offset, 40);
        let context = egui::Context::default();
        for tab in [HostTab::Timeline, HostTab::Connections, HostTab::Packets] {
            view.tab = tab;
            let output = context.run_ui(egui::RawInput::default(), |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    view.ui(
                        ui,
                        Ok(StreamOptions::default()),
                        Duration::from_secs(10),
                        "",
                        false,
                    )
                });
            });
            assert!(!output.shapes.is_empty());
            output.drop_without_applying_deltas();
        }
        assert_eq!(view.selected_numbers(), Vec::<u64>::new());
        view.evidence_scope = EvidenceScope::Packet;
        assert_eq!(view.selected_numbers(), [1]);
    }
    #[test]
    fn close_cancels_and_waits_for_background_investigation_work() {
        let mut view = InvestigationUi::default();
        view.work(false, move |cancelled| {
            while !cancelled.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(2));
            }
            Err("cancelled".into())
        });
        let started = Instant::now();
        view.poll();
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(view.busy());
        view.cancel();
        drain(&mut view);
        assert!(!view.busy());
    }
}
