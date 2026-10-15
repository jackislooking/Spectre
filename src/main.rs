use eframe::{self, NativeOptions};
use eframe::egui::{self, Context, TextEdit, RichText, ScrollArea, Slider, Color32, Grid};
use std::thread::JoinHandle;
use tokio::sync::{mpsc, oneshot};
use tokio::runtime::Runtime;
use log::{info, error, warn, LevelFilter};
use env_logger::Builder;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::error::Error as StdError;
use crate::cert::CaCert;
use crate::proxy::{start_proxy, start_webhook};
use crate::traffic::{TrafficLog, TrafficEntry};
use crate::node::start_node_server;
use crate::cve_fetcher::{CveFetcher, CveEntry};
use std::mem;
use reqwest::Client;
use std::sync::{Arc, Mutex};
use rusqlite::Connection;
use anyhow::{Result, anyhow};
use std::time::Duration;
use crate::scanner::passive_scan_response;
use crate::llm_scanner::{LlmScanner, DetectionType};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

mod llm_scanner;
mod cert;
mod proxy;
mod traffic;
mod node;
mod cve_fetcher;
mod scanner;

#[derive(Clone)]
enum UiTask {
    Replay(String, String, String, String, Arc<CveFetcher>, bool),
    FetchRecentCves(Arc<CveFetcher>),
    RescanLogs(Arc<CveFetcher>, TrafficLog),
    BatchLlmScan,
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Control,
    Logs,
    Repeater,
    CVEs,
    LlmFindings,
}

#[derive(Clone, Copy, PartialEq)]
enum RepeaterSubTab {
    Editor,
    ReplayedResponse,
    OriginalResponse,
    Diff,
}

#[derive(Clone, Copy, PartialEq)]
enum LogSubTab {
    All,
    Vulnerabilities,
    Requests,
    Responses,
    Connections,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct LlmFinding {
    timestamp: String,
    hostname: String,
    severity: String,
    message: String,
    evidence: String,
}

struct ProxyToolApp {
    ca: Arc<CaCert>,
    traffic_log: TrafficLog,
    proxy_handle: Option<JoinHandle<anyhow::Result<()>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    webhook_handle: Option<JoinHandle<anyhow::Result<()>>>,
    webhook_shutdown_tx: Option<oneshot::Sender<()>>,
    node_handle: Option<JoinHandle<anyhow::Result<()>>>,
    node_shutdown_tx: Option<oneshot::Sender<()>>,
    selected_entry: Option<TrafficEntry>,
    selected_response: Option<TrafficEntry>,
    edited_method_path: String,
    edited_request_headers: String,
    edited_request_body: String,
    replay_status: String,
    replay_headers: String,
    replay_body: String,
    original_response_status: String,
    original_response_headers: String,
    original_response_body: String,
    task_tx: mpsc::Sender<UiTask>,
    result_tx: mpsc::Sender<anyhow::Result<(Option<String>, Duration, Vec<String>, Option<String>)>>,
    result_rx: mpsc::Receiver<anyhow::Result<(Option<String>, Duration, Vec<String>, Option<String>)>>,
    task_shutdown_tx: Option<oneshot::Sender<()>>,
    task_handle: JoinHandle<()>,
    status_message: String,
    selected_tab: Tab,
    log_filter: String,
    cve_filter: String,
    fetcher: Arc<CveFetcher>,
    proxy_running: bool,
    webhook_running: bool,
    node_running: bool,
    status_tx: mpsc::Sender<String>,
    status_rx: mpsc::Receiver<String>,
    cves: Vec<CveEntry>,
    prev_log_filter: String,
    prev_cve_filter: String,
    filtered: Vec<usize>,
    current_page: usize,
    page_size: usize,
    log_current_page: usize,
    log_page_size: usize,
    log_filtered: Vec<usize>,
    log_prev_filter: String,
    filter_on_data: bool,
    runtime: Arc<Runtime>,

    follow_redirects: bool,
    replay_duration_ms: u64,
    redirect_chain: Vec<String>,
    last_error_kind: Option<String>,
    pretty_json: bool,
    repeater_sub_tab: RepeaterSubTab,

    log_sub_tab: LogSubTab,
    prev_log_sub_tab: LogSubTab,
    prev_filter_on_data: bool,

    batch_in_progress: bool,
    batch_progress: (usize, usize),

    llm_findings: Vec<LlmFinding>,
    llm_findings_filter: String,
    llm_findings_prev_filter: String,
    llm_findings_filtered: Vec<usize>,
    llm_findings_current_page: usize,
    llm_findings_page_size: usize,
}

impl ProxyToolApp {
    fn new(ca: Arc<CaCert>, fetcher: Arc<CveFetcher>) -> Self {
        let cves = fetcher.get_all_cves().unwrap_or_default();
        let filtered = (0..cves.len()).collect();
        let (task_tx, mut task_rx) = mpsc::channel::<UiTask>(32);
        let (result_tx, result_rx) = mpsc::channel(32);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (status_tx, status_rx) = mpsc::channel(32);
        let runtime = Arc::new(Runtime::new().unwrap());
        let runtime_clone = runtime.clone();

        let traffic_log = TrafficLog::load(status_tx.clone()).unwrap_or_else(|e| {
            error!("Failed to load traffic log: {}", e);
            panic!("Traffic log initialization failed: {}", e);
        });

        let traffic_log_for_tasks = traffic_log.clone();

        let status_tx_for_tasks = status_tx.clone();
        let result_tx_for_tasks = result_tx.clone();

        let task_handle = std::thread::spawn(move || {
            runtime_clone.block_on(async move {
                tokio::select! {
                    _ = shutdown_rx => { info!("Task thread shutting down"); }
                    _ = async {
                        while let Some(task) = task_rx.recv().await {
                            match task {
                                UiTask::Replay(hostname, method_path, headers, body, fetcher, follow) => {
                                    let full = format!("{}\r\n{}\r\n\r\n{}", method_path, headers, body);
                                    let res = TrafficLog::replay_request_with_data(&hostname, &full, &fetcher, status_tx_for_tasks.clone(), follow).await;
                                    let _ = result_tx_for_tasks.send(res).await;
                                }
                                UiTask::FetchRecentCves(fetcher) => {
                                    if let Err(e) = fetcher.fetch_recent_cves().await {
                                        let _ = result_tx_for_tasks.send(Err(e)).await;
                                    } else {
                                        let _ = result_tx_for_tasks.send(Ok((None, Duration::ZERO, vec![], None))).await;
                                    }
                                }
                                UiTask::RescanLogs(fetcher, traffic_log) => {
                                    if let Ok(entries) = traffic_log.entries() {
                                        for entry in entries {
                                            if entry.entry_type == "response" {
                                                let _ = passive_scan_response(&entry.hostname, &entry.data, &traffic_log, &entry.client_ip, &fetcher).await;
                                            }
                                        }
                                    }
                                    let _ = result_tx_for_tasks.send(Ok((None, Duration::ZERO, vec![], None))).await;
                                }
                                UiTask::BatchLlmScan => {
                                    let llm = LlmScanner::new();
                                    let (progress_tx, mut progress_rx) = mpsc::channel(16);
                                    let log_clone = traffic_log_for_tasks.clone();
                                    let status_tx_clone = status_tx_for_tasks.clone();

                                    let result_tx_for_spawn = result_tx_for_tasks.clone();

                                    tokio::spawn(async move {
                                        let res = batch_llm_scan(&log_clone, &llm, status_tx_clone.clone(), progress_tx).await;
                                        match res {
                                            Ok(count) => {
                                                let _ = result_tx_for_spawn.send(Ok((
                                                    None,
                                                    Duration::ZERO,
                                                    vec![],
                                                    Some(format!("batch_done:{}", count)),
                                                ))).await;
                                            }
                                            Err(e) => {
                                                let _ = status_tx_clone.send(format!("Batch scan failed: {}", e)).await;
                                                let _ = result_tx_for_spawn.send(Err(e)).await;
                                            }
                                        }
                                    });

                                    while let Some((cur, tot)) = progress_rx.recv().await {
                                        let _ = result_tx_for_tasks.send(Ok((
                                            None,
                                            Duration::ZERO,
                                            vec![],
                                            Some(format!("progress:{}/{}", cur, tot)),
                                        ))).await;
                                    }
                                }
                            }
                        }
                    } => {},
                }
            });
        });

        let llm_findings_path = "llm_findings.jsonl".to_string();
        let mut llm_findings = Vec::new();
        if let Ok(file) = File::open(&llm_findings_path) {
            let reader = io::BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    if let Ok(finding) = serde_json::from_str::<LlmFinding>(&line) {
                        llm_findings.push(finding);
                    }
                }
            }
            info!("Loaded {} LLM findings from {}", llm_findings.len(), llm_findings_path);
        }

        Self {
            ca,
            traffic_log,
            proxy_handle: None,
            shutdown_tx: None,
            webhook_handle: None,
            webhook_shutdown_tx: None,
            node_handle: None,
            node_shutdown_tx: None,
            selected_entry: None,
            selected_response: None,
            edited_method_path: String::new(),
            edited_request_headers: String::new(),
            edited_request_body: String::new(),
            replay_status: String::new(),
            replay_headers: String::new(),
            replay_body: String::new(),
            original_response_status: String::new(),
            original_response_headers: String::new(),
            original_response_body: String::new(),
            task_tx,
            result_tx,
            result_rx,
            task_shutdown_tx: Some(shutdown_tx),
            task_handle,
            status_message: "Application started. Ready.".to_string(),
            selected_tab: Tab::Control,
            log_filter: String::new(),
            cve_filter: String::new(),
            fetcher,
            proxy_running: false,
            webhook_running: false,
            node_running: false,
            status_tx,
            status_rx,
            cves,
            prev_log_filter: String::new(),
            prev_cve_filter: String::new(),
            filtered,
            current_page: 0,
            page_size: 50,
            log_current_page: 0,
            log_page_size: 50,
            log_filtered: Vec::new(),
            log_prev_filter: String::new(),
            filter_on_data: false,
            runtime,

            follow_redirects: true,
            replay_duration_ms: 0,
            redirect_chain: vec![],
            last_error_kind: None,
            pretty_json: true,
            repeater_sub_tab: RepeaterSubTab::Editor,

            log_sub_tab: LogSubTab::All,
            prev_log_sub_tab: LogSubTab::All,
            prev_filter_on_data: false,

            batch_in_progress: false,
            batch_progress: (0, 0),

            llm_findings,
            llm_findings_filter: String::new(),
            llm_findings_prev_filter: String::new(),
            llm_findings_filtered: Vec::new(),
            llm_findings_current_page: 0,
            llm_findings_page_size: 50,
        }
    }

    fn stop_proxy(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.proxy_handle.take() {
            if let Err(e) = handle.join() {
                error!("Failed to join proxy handle: {:?}", e);
            }
        }
        self.proxy_running = false;
        self.status_message = "Proxy stopped.".to_string();
    }

    fn stop_webhook(&mut self) {
        if let Some(tx) = self.webhook_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.webhook_handle.take() {
            if let Err(e) = handle.join() {
                error!("Failed to join webhook handle: {:?}", e);
            }
        }
        self.webhook_running = false;
        self.status_message = "Webhook stopped.".to_string();
    }

    fn stop_node(&mut self) {
        if let Some(tx) = self.node_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.node_handle.take() {
            if let Err(e) = handle.join() {
                error!("Failed to join node handle: {:?}", e);
            }
        }
        self.node_running = false;
        self.status_message = "Node server stopped.".to_string();
    }
}

impl eframe::App for ProxyToolApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.selected_tab, Tab::Control, "Control");
                ui.selectable_value(&mut self.selected_tab, Tab::Logs, "Logs");
                ui.selectable_value(&mut self.selected_tab, Tab::Repeater, "Repeater");
                ui.selectable_value(&mut self.selected_tab, Tab::CVEs, "CVEs");
                ui.selectable_value(&mut self.selected_tab, Tab::LlmFindings, "LLM Findings");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.selected_tab {
                Tab::Control => {
                    ui.heading("Proxy Control");
                    ui.add_space(10.0);
                    ui.label(RichText::new(&self.status_message).color(egui::Color32::from_rgb(100, 255, 100)));
                    ui.add_space(10.0);

                    ui.horizontal(|ui| {
                        if ui.button("Start Proxy").clicked() && !self.proxy_running {
                            self.status_message = "Starting proxy...".to_string();
                            ctx.request_repaint();
                            let (shutdown_tx, shutdown_rx) = oneshot::channel();
                            let ca = self.ca.clone();
                            let traffic_log = self.traffic_log.clone();
                            let fetcher = self.fetcher.clone();
                            let runtime = self.runtime.clone();
                            self.proxy_handle = Some(std::thread::spawn(move || {
                                runtime.block_on(start_proxy(ca, traffic_log, fetcher, shutdown_rx))
                            }));
                            self.shutdown_tx = Some(shutdown_tx);
                            self.proxy_running = true;
                            self.status_message = "Proxy started on port 8080".to_string();
                        }
                        if ui.button("Stop Proxy").clicked() && self.proxy_running {
                            self.stop_proxy();
                        }
                    });

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Start Webhook").clicked() && !self.webhook_running {
                            self.status_message = "Starting webhook server...".to_string();
                            ctx.request_repaint();
                            let (shutdown_tx, shutdown_rx) = oneshot::channel();
                            let traffic_log = self.traffic_log.clone();
                            let runtime = self.runtime.clone();
                            self.webhook_handle = Some(std::thread::spawn(move || {
                                runtime.block_on(start_webhook(traffic_log, shutdown_rx))
                            }));
                            self.webhook_shutdown_tx = Some(shutdown_tx);
                            self.webhook_running = true;
                            self.status_message = "Webhook started on port 8081".to_string();
                        }
                        if ui.button("Stop Webhook").clicked() && self.webhook_running {
                            self.stop_webhook();
                        }
                    });

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Start Node Server").clicked() && !self.node_running {
                            self.status_message = "Starting node server...".to_string();
                            ctx.request_repaint();
                            let (shutdown_tx, shutdown_rx) = oneshot::channel();
                            let traffic_log = self.traffic_log.clone();
                            let runtime = self.runtime.clone();
                            self.node_handle = Some(std::thread::spawn(move || {
                                runtime.block_on(start_node_server(traffic_log, shutdown_rx))
                            }));
                            self.node_shutdown_tx = Some(shutdown_tx);
                            self.node_running = true;
                            self.status_message = "Node server started on port 3000".to_string();
                        }
                        if ui.button("Stop Node Server").clicked() && self.node_running {
                            self.stop_node();
                        }
                    });

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Regenerate CA").clicked() {
                            self.status_message = "Regenerating CA certificate...".to_string();
                            ctx.request_repaint();
                            if let Err(e) = self.ca.regenerate_and_import(Some(self.status_tx.clone())) {
                                self.status_message = format!("Failed to regenerate CA: {}", e);
                            } else {
                                self.status_message = "CA regenerated and imported to Firefox".to_string();
                            }
                        }
                        if ui.button("Remove CA from Firefox").clicked() {
                            self.status_message = "Removing CA from Firefox...".to_string();
                            ctx.request_repaint();
                            if let Err(e) = self.ca.remove_from_firefox(Some(self.status_tx.clone())) {
                                self.status_message = format!("Failed to remove CA: {}", e);
                            } else {
                                self.status_message = "CA removed from Firefox".to_string();
                            }
                        }
                    });

                    ui.add_space(10.0);
                    if !self.status_message.is_empty() {
                        ui.label(RichText::new(&self.status_message).color(egui::Color32::from_rgb(255, 200, 0)));
                    }
                }

                Tab::Logs => {
                    ui.heading("Traffic Logs");
                    ui.add_space(10.0);

                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.log_sub_tab, LogSubTab::All, "All Traffic");
                        ui.selectable_value(&mut self.log_sub_tab, LogSubTab::Vulnerabilities, "Vulnerabilities");
                        ui.selectable_value(&mut self.log_sub_tab, LogSubTab::Requests, "Requests");
                        ui.selectable_value(&mut self.log_sub_tab, LogSubTab::Responses, "Responses");
                        ui.selectable_value(&mut self.log_sub_tab, LogSubTab::Connections, "Connections");
                    });
                    ui.separator();

                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui.add(egui::Button::new(RichText::new("Batch Scan with LLM").strong())
                            .fill(Color32::from_rgb(80, 200, 120))
                            .min_size([180.0, 36.0].into())
                        ).clicked() && !self.batch_in_progress {
                            self.batch_in_progress = true;
                            self.batch_progress = (0, 0);
                            self.status_message = "Starting batch LLM scan...".to_string();
                            ctx.request_repaint();

                            let _ = self.task_tx.blocking_send(UiTask::BatchLlmScan);
                        }

                        if self.batch_in_progress {
                            ui.spinner();
                            ui.add_space(8.0);
                            ui.label(RichText::new(format!(
                                "Scanning: {}/{} entries",
                                self.batch_progress.0, self.batch_progress.1
                            )));
                        }
                    });

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("Filter: ");
                        ui.text_edit_singleline(&mut self.log_filter);
                        ui.checkbox(&mut self.filter_on_data, "Filter on Data");
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("Page size:");
                        ui.add(Slider::new(&mut self.log_page_size, 10..=1000));
                    });
                    ui.add_space(10.0);

                    let filter_lc = self.log_filter.to_lowercase();
                    if self.log_filter != self.log_prev_filter ||
                        self.filter_on_data != self.prev_filter_on_data ||
                        self.log_sub_tab != self.prev_log_sub_tab
                        {
                            self.log_prev_filter = self.log_filter.clone();
                            self.prev_filter_on_data = self.filter_on_data;
                            self.prev_log_sub_tab = self.log_sub_tab;

                            self.log_filtered = (0..self.traffic_log.entries().map(|e| e.len()).unwrap_or(0))
                            .filter(|&i| {
                                let entries = self.traffic_log.entries().unwrap_or_default();
                                let entry = &entries[i];
                                let type_match = match self.log_sub_tab {
                                    LogSubTab::All => true,
                                    LogSubTab::Vulnerabilities => entry.entry_type == "vuln_alert",
                                    LogSubTab::Requests => entry.entry_type == "request",
                                    LogSubTab::Responses => entry.entry_type == "response",
                                    LogSubTab::Connections => entry.entry_type == "connect",
                                };
                                if !type_match { return false; }
                                self.log_filter.is_empty()
                                || entry.timestamp.to_lowercase().contains(&filter_lc)
                                || entry.hostname.to_lowercase().contains(&filter_lc)
                                || entry.entry_type.to_lowercase().contains(&filter_lc)
                                || entry.client_ip.to_lowercase().contains(&filter_lc)
                                || entry.evidence.as_ref().map_or(false, |e| e.to_lowercase().contains(&filter_lc))
                                || entry.severity.as_ref().map_or(false, |s| s.to_lowercase().contains(&filter_lc))
                                || (self.filter_on_data && entry.data.to_lowercase().contains(&filter_lc))
                            })
                            .collect();
                            self.log_current_page = 0;
                        }

                        let start = self.log_current_page * self.log_page_size;
                        let end = (start + self.log_page_size).min(self.log_filtered.len());
                        let num_pages = (self.log_filtered.len() + self.log_page_size - 1) / self.log_page_size;

                        if self.log_sub_tab == LogSubTab::Vulnerabilities {
                            let entries = self.traffic_log.entries().unwrap_or_default();
                            let mut high = 0; let mut medium = 0; let mut low = 0; let mut info = 0;
                            for &i in &self.log_filtered {
                                if let Some(sev) = &entries[i].severity {
                                    match sev.as_str() {
                                        "HIGH" => high += 1,
                                        "MEDIUM" => medium += 1,
                                        "LOW" => low += 1,
                                        "INFO" => info += 1,
                                        _ => {},
                                    }
                                }
                            }
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("HIGH: {}", high)).color(Color32::from_rgb(255, 100, 100)));
                                ui.label(RichText::new(format!("MEDIUM: {}", medium)).color(Color32::from_rgb(255, 200, 100)));
                                ui.label(RichText::new(format!("LOW: {}", low)).color(Color32::from_rgb(200, 200, 100)));
                                ui.label(RichText::new(format!("INFO: {}", info)).color(Color32::from_rgb(100, 200, 255)));
                            });
                            ui.add_space(10.0);
                        }

                        ScrollArea::vertical().show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("ID/Timestamp").strong());
                                ui.add_space(80.0);
                                ui.label(RichText::new("Hostname").strong());
                                ui.add_space(80.0);
                                ui.label(RichText::new("Type").strong());
                                ui.add_space(60.0);
                                ui.label(RichText::new("Client IP").strong());
                                ui.add_space(80.0);
                                ui.label(RichText::new("Evidence").strong());
                                ui.add_space(80.0);
                                ui.label(RichText::new("Severity").strong());
                                ui.add_space(100.0);
                                ui.label(RichText::new("Data Preview").strong());
                            });
                            ui.add_space(5.0);

                            for p in 0..(end - start) {
                                let i = self.log_filtered[start + p];
                                let entry = &self.traffic_log.entries().unwrap_or_default()[i];

                                let row_color = if entry.entry_type == "vuln_alert" {
                                    match entry.severity.as_deref() {
                                        Some("HIGH")   => Color32::from_rgb(255, 100, 100),
                                                    Some("MEDIUM") => Color32::from_rgb(255, 200, 100),
                                                    Some("LOW")    => Color32::from_rgb(200, 200, 100),
                                                    Some("INFO")   => Color32::from_rgb(100, 200, 255),
                                                    _ => Color32::from_rgb(200, 200, 200),
                                    }
                                } else {
                                    Color32::WHITE
                                };

                                let data_preview = if entry.data.contains('\u{FFFD}') || entry.data.len() > 500 {
                                    "[binary/content too large]".to_string()
                                } else if self.log_sub_tab == LogSubTab::Vulnerabilities {
                                    entry.data.clone()
                                } else if entry.data.len() > 100 {
                                    format!("{}...", &entry.data[..100])
                                } else {
                                    entry.data.clone()
                                };

                                let timestamp_display = if entry.entry_type == "request" {
                                    format!("Req#{} @ {}", i + 1, entry.timestamp)
                                } else {
                                    entry.timestamp.clone()
                                };

                                ui.horizontal(|ui| {
                                    if ui.button(RichText::new(&timestamp_display).color(row_color)).clicked() {
                                        if entry.entry_type == "request" {
                                            self.selected_entry = Some(entry.clone());

                                            let lines: Vec<&str> = entry.data.lines().collect();
                                            if !lines.is_empty() {
                                                self.edited_method_path = lines[0].to_string();
                                                let header_end = lines.iter().position(|&l| l.trim().is_empty()).unwrap_or(lines.len());
                                                self.edited_request_headers = if header_end > 1 {
                                                    lines[1..header_end].join("\n")
                                                } else {
                                                    String::new()
                                                };
                                                self.edited_request_body = if header_end + 1 < lines.len() {
                                                    lines[header_end + 1..].join("\n")
                                                } else {
                                                    String::new()
                                                };
                                            }

                                            if let Ok(all) = self.traffic_log.entries() {
                                                if let Some(idx) = all.iter().position(|e| e == entry) {
                                                    if let Some(next) = all.get(idx + 1) {  // FIXED: saturating_add → +1
                                                        if next.entry_type == "response" && next.hostname == entry.hostname {
                                                            self.selected_response = Some(next.clone());
                                                            let resp_lines: Vec<&str> = next.data.lines().collect();
                                                            if !resp_lines.is_empty() {
                                                                self.original_response_status = resp_lines[0].to_string();
                                                                let h_end = resp_lines.iter().position(|&l| l.is_empty()).unwrap_or(resp_lines.len());
                                                                self.original_response_headers = if h_end > 1 {
                                                                    resp_lines[1..h_end].join("\n")
                                                                } else { String::new() };
                                                                self.original_response_body = if h_end + 1 < resp_lines.len() {
                                                                    resp_lines[h_end + 1..].join("\n")
                                                                } else { String::new() };
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            self.replay_status.clear();
                                            self.replay_headers.clear();
                                            self.replay_body.clear();
                                            self.repeater_sub_tab = RepeaterSubTab::Editor;
                                            self.selected_tab = Tab::Repeater;
                                        }
                                    } else {
                                        ui.label(RichText::new(&timestamp_display).color(row_color));
                                    }
                                    ui.add_space(80.0);
                                    ui.label(RichText::new(&entry.hostname).color(row_color));
                                    ui.add_space(80.0);
                                    ui.label(RichText::new(&entry.entry_type).color(row_color));
                                    ui.add_space(60.0);
                                    ui.label(RichText::new(&entry.client_ip).color(row_color));
                                    ui.add_space(80.0);
                                    ui.label(RichText::new(entry.evidence.as_ref().map_or("", |e| e)).color(row_color));
                                    ui.add_space(80.0);
                                    ui.label(RichText::new(entry.severity.as_ref().map_or("", |s| s)).color(row_color));
                                    ui.add_space(100.0);
                                    ui.label(RichText::new(&data_preview).color(row_color));
                                });
                            }
                        });

                        ui.horizontal(|ui| {
                            if ui.button("Previous").clicked() && self.log_current_page > 0 {
                                self.log_current_page -= 1;
                            }
                            ui.label(format!("Page {} of {}", self.log_current_page + 1, num_pages));
                            if ui.button("Next").clicked() && self.log_current_page + 1 < num_pages {
                                self.log_current_page += 1;
                            }
                        });
                }

                Tab::Repeater => {
                    ui.heading("Repeater");
                    ui.add_space(12.0);

                    if let Some(entry) = &self.selected_entry {
                        ui.label(RichText::new(format!("Request from: {} @ {}", entry.hostname, entry.timestamp)).strong());
                    } else {
                        ui.label(RichText::new("No request selected").color(Color32::LIGHT_RED));
                        return;
                    }

                    ui.add_space(16.0);

                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.repeater_sub_tab, RepeaterSubTab::Editor, "Request Editor");
                        ui.selectable_value(&mut self.repeater_sub_tab, RepeaterSubTab::ReplayedResponse, "Replayed Response");
                        ui.selectable_value(&mut self.repeater_sub_tab, RepeaterSubTab::OriginalResponse, "Original Response");
                        ui.selectable_value(&mut self.repeater_sub_tab, RepeaterSubTab::Diff, "Diff");
                    });

                    ui.separator();
                    ui.add_space(10.0);

                    match self.repeater_sub_tab {
                        RepeaterSubTab::Editor => {
                            ui.group(|ui| {
                                ui.heading(RichText::new("Request to Modify").color(Color32::from_rgb(100, 255, 200)));
                                ui.add_space(8.0);

                                ui.label("Method + Path:");
                                ui.add(TextEdit::singleline(&mut self.edited_method_path).desired_width(f32::INFINITY));

                                ui.add_space(8.0);
                                ui.label("Headers:");
                                ui.add(TextEdit::multiline(&mut self.edited_request_headers)
                                .desired_rows(8)
                                .desired_width(f32::INFINITY));

                                ui.add_space(8.0);
                                ui.label("Body:");
                                ui.add(TextEdit::multiline(&mut self.edited_request_body)
                                .desired_rows(10)
                                .desired_width(f32::INFINITY));
                            });

                            ui.add_space(16.0);
                            ui.checkbox(&mut self.follow_redirects, "Follow redirects (max 10)");

                            if ui.add(egui::Button::new(RichText::new("SEND REQUEST →").strong().color(Color32::BLACK))
                                .fill(Color32::from_rgb(0, 200, 80))
                                .min_size([180.0, 48.0].into())
                            ).clicked() {
                                if self.selected_entry.is_some() {
                                    self.replay_status = "Sending...".to_string();
                                    self.replay_headers.clear();
                                    self.replay_body.clear();
                                    self.redirect_chain.clear();
                                    self.replay_duration_ms = 0;
                                    self.last_error_kind = None;
                                    self.status_message = "Executing replay...".to_string();
                                    ctx.request_repaint();

                                    let hostname = self.selected_entry.as_ref().unwrap().hostname.clone();
                                    let method_path = self.edited_method_path.trim().to_string();
                                    let headers = self.edited_request_headers.trim().to_string();
                                    let body = self.edited_request_body.trim().to_string();
                                    let fetcher = self.fetcher.clone();
                                    let status_tx = self.status_tx.clone();
                                    let result_tx = self.result_tx.clone();
                                    let follow = self.follow_redirects;

                                    self.runtime.spawn(async move {
                                        let full = format!("{}\r\n{}\r\n\r\n{}", method_path, headers, body);
                                        let res = TrafficLog::replay_request_with_data(
                                            &hostname,
                                            &full,
                                            &fetcher,
                                            status_tx,
                                            follow,
                                        ).await;
                                        let _ = result_tx.send(res).await;
                                    });
                                } else {
                                    self.status_message = "No request selected!".to_string();
                                }
                            }
                        }
                        RepeaterSubTab::ReplayedResponse => {
                            ui.heading(RichText::new("Replayed Response").color(Color32::from_rgb(220, 180, 100)));

                            if self.replay_status == "Sending..." {
                                ui.spinner();
                                ui.label(RichText::new("Waiting for response...").italics());
                            } else if self.replay_status.is_empty() {
                                ui.label(RichText::new("No replay performed yet").italics().color(Color32::GRAY));
                            } else {
                                let status_color = if self.replay_status.contains(" 2") || self.replay_status.contains("200") {
                                    Color32::GREEN
                                } else if self.replay_status.contains(" 3") {
                                    Color32::YELLOW
                                } else if self.replay_status.contains(" 4") {
                                    Color32::from_rgb(255, 140, 0)
                                } else if self.replay_status.contains(" 5") {
                                    Color32::RED
                                } else {
                                    Color32::from_rgb(180, 40, 180)
                                };

                                ui.label(RichText::new(&self.replay_status).strong().color(status_color));

                                if self.replay_duration_ms > 0 {
                                    ui.label(
                                        RichText::new(format!("Round-trip: {} ms", self.replay_duration_ms))
                                        .italics()
                                        .color(Color32::LIGHT_BLUE)
                                    );
                                }

                                if !self.redirect_chain.is_empty() && self.redirect_chain.len() > 1 {
                                    ui.collapsing(format!("Redirect chain ({} steps)", self.redirect_chain.len() - 1), |ui| {
                                        for (i, url) in self.redirect_chain.iter().enumerate() {
                                            ui.label(format!("{} → {}", i + 1, url));
                                        }
                                    });
                                }

                                ui.checkbox(&mut self.pretty_json, "Pretty-print JSON (if applicable)");

                                ui.add_space(12.0);
                                ui.separator();

                                ui.label("Headers:");
                                ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                                    ui.label(&self.replay_headers);
                                });

                                ui.add_space(8.0);
                                ui.label("Body:");
                                ScrollArea::vertical().show(ui, |ui| {
                                    ui.label(&self.replay_body);
                                });

                                if let Some(kind) = &self.last_error_kind {
                                    ui.add_space(12.0);
                                    ui.separator();
                                    ui.label(RichText::new("Error details:").color(Color32::LIGHT_RED).strong());

                                    let explanation = match kind.as_str() {
                                        "timeout" => "Request timed out.\nServer did not respond within the timeout period.",
                                        "connection_refused" => "Connection refused.\nThe server is down, port is closed, or a firewall is blocking.",
                                        "dns_failure" => "DNS resolution failed.\nThe hostname could not be resolved.",
                                        "tls_handshake" => "TLS handshake failed.\nPossible causes: invalid certificate, protocol/version mismatch.",
                                        "body_error" => "Could not read or decode response body.",
                                        _ => "Unknown request error occurred.",
                                    };

                                    ui.label(RichText::new(explanation).color(Color32::from_rgb(255, 100, 100)));
                                }
                            }
                        }
                        RepeaterSubTab::OriginalResponse => {
                            ui.heading(RichText::new("Original Response").color(Color32::from_rgb(220, 180, 100)));
                            if self.original_response_status.is_empty() {
                                ui.label(RichText::new("No original response captured for this request").italics().color(Color32::GRAY));
                            } else {
                                ui.label(RichText::new(&self.original_response_status).color(Color32::LIGHT_BLUE));
                                ui.add_space(12.0);
                                ui.separator();
                                ui.label("Headers:");
                                ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                                    ui.label(&self.original_response_headers);
                                });
                                ui.add_space(8.0);
                                ui.label("Body:");
                                ScrollArea::vertical().show(ui, |ui| {
                                    ui.label(&self.original_response_body);
                                });
                            }
                        }
                        RepeaterSubTab::Diff => {
                            ui.heading(RichText::new("Diff View (highlighted changes)").color(Color32::from_rgb(200, 220, 255)));
                            let orig_lines: Vec<&str> = self.original_response_body.lines().collect();
                            let repl_lines: Vec<&str> = self.replay_body.lines().collect();

                            Grid::new("body_diff")
                            .num_columns(3)
                            .spacing([12.0, 8.0])
                            .show(ui, |ui| {
                                ui.label(RichText::new("Line").strong());
                                ui.label(RichText::new("Original").color(Color32::LIGHT_RED).strong());
                                ui.label(RichText::new("Replayed").color(Color32::LIGHT_GREEN).strong());
                                ui.end_row();

                                let max = orig_lines.len().max(repl_lines.len());
                                for i in 0..max {
                                    let o = orig_lines.get(i).copied().unwrap_or("[missing]");
                                    let r = repl_lines.get(i).copied().unwrap_or("[missing]");

                                    ui.label(format!("{}", i + 1));

                                    if o == r {
                                        ui.label(o);
                                        ui.label(r);
                                    } else {
                                        ui.label(RichText::new(o).color(Color32::RED).background_color(Color32::from_rgb(50, 20, 20)));
                                        ui.label(RichText::new(r).color(Color32::GREEN).background_color(Color32::from_rgb(20, 50, 20)));
                                    }
                                    ui.end_row();
                                }
                            });
                        }
                    }
                }

                Tab::CVEs => {
                    ui.heading("CVE Database");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Fetch Recent CVEs").clicked() {
                            let fetcher = self.fetcher.clone();
                            let task_tx = self.task_tx.clone();
                            self.runtime.spawn(async move {
                                let _ = task_tx.send(UiTask::FetchRecentCves(fetcher)).await;
                            });
                        }
                        if ui.button("Rescan Logs").clicked() {
                            let fetcher = self.fetcher.clone();
                            let traffic_log = self.traffic_log.clone();
                            let task_tx = self.task_tx.clone();
                            self.runtime.spawn(async move {
                                let _ = task_tx.send(UiTask::RescanLogs(fetcher, traffic_log)).await;
                            });
                        }
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("Filter: ");
                        ui.text_edit_singleline(&mut self.cve_filter);
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("Page size:");
                        ui.add(Slider::new(&mut self.page_size, 10..=1000));
                    });
                    ui.add_space(10.0);

                    let filter_lc = self.cve_filter.to_lowercase();
                    if self.cve_filter != self.prev_cve_filter {
                        self.prev_cve_filter = self.cve_filter.clone();
                        self.filtered = (0..self.cves.len())
                        .filter(|&i| {
                            let row = &self.cves[i];
                            self.cve_filter.is_empty()
                            || row.cve_id.to_lowercase().contains(&filter_lc)
                            || row.vendor.as_ref().map_or(false, |v| v.to_lowercase().contains(&filter_lc))
                            || row.software.to_lowercase().contains(&filter_lc)
                            || row.version_range.to_lowercase().contains(&filter_lc)
                        })
                        .collect();
                        self.current_page = 0;
                    }

                    let start = self.current_page * self.page_size;
                    let end = (start + self.page_size).min(self.filtered.len());
                    let num_pages = (self.filtered.len() + self.page_size - 1) / self.page_size;

                    ScrollArea::vertical().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("CVE ID").strong());
                            ui.add_space(100.0);
                            ui.label(RichText::new("Vendor").strong());
                            ui.add_space(100.0);
                            ui.label(RichText::new("Software").strong());
                            ui.add_space(100.0);
                            ui.label(RichText::new("Version Range").strong());
                        });
                        ui.add_space(5.0);
                        for p in 0..(end - start) {
                            let i = self.filtered[start + p];
                            let row = &self.cves[i];
                            ui.horizontal(|ui| {
                                ui.label(&row.cve_id);
                                ui.add_space(100.0);
                                ui.label(row.vendor.clone().unwrap_or_default());
                                ui.add_space(100.0);
                                ui.label(&row.software);
                                ui.add_space(100.0);
                                ui.label(&row.version_range);
                            });
                        }
                    });

                    ui.horizontal(|ui| {
                        if ui.button("Previous").clicked() && self.current_page > 0 {
                            self.current_page -= 1;
                        }
                        ui.label(format!("Page {} of {}", self.current_page + 1, num_pages));
                        if ui.button("Next").clicked() && self.current_page + 1 < num_pages {
                            self.current_page += 1;
                        }
                    });
                }

                Tab::LlmFindings => {
                    ui.heading("LLM Findings");
                    ui.add_space(12.0);

                    ui.horizontal(|ui| {
                        ui.label("Filter: ");
                        ui.text_edit_singleline(&mut self.llm_findings_filter);
                    });
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label("Page size:");
                        ui.add(Slider::new(&mut self.llm_findings_page_size, 10..=500));
                    });
                    ui.add_space(10.0);

                    let filter_lc = self.llm_findings_filter.to_lowercase();
                    if self.llm_findings_filter != self.llm_findings_prev_filter {
                        self.llm_findings_prev_filter = self.llm_findings_filter.clone();
                        self.llm_findings_filtered = (0..self.llm_findings.len())
                        .filter(|&i| {
                            let f = &self.llm_findings[i];
                            self.llm_findings_filter.is_empty()
                            || f.timestamp.to_lowercase().contains(&filter_lc)
                            || f.hostname.to_lowercase().contains(&filter_lc)
                            || f.message.to_lowercase().contains(&filter_lc)
                            || f.evidence.to_lowercase().contains(&filter_lc)
                            || f.severity.to_lowercase().contains(&filter_lc)
                        })
                        .collect();
                        self.llm_findings_current_page = 0;
                    }

                    let start = self.llm_findings_current_page * self.llm_findings_page_size;
                    let end = (start + self.llm_findings_page_size).min(self.llm_findings_filtered.len());
                    let num_pages = (self.llm_findings_filtered.len() + self.llm_findings_page_size - 1) / self.llm_findings_page_size;

                    let mut high = 0; let mut medium = 0; let mut info = 0;
                    for &i in &self.llm_findings_filtered {
                        match self.llm_findings[i].severity.as_str() {
                            "HIGH"   => high += 1,
                            "MEDIUM" => medium += 1,
                            "INFO"   => info += 1,
                            _ => {},
                        }
                    }
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("HIGH: {}", high)).color(Color32::from_rgb(255, 100, 100)));
                        ui.label(RichText::new(format!("MEDIUM: {}", medium)).color(Color32::from_rgb(255, 200, 100)));
                        ui.label(RichText::new(format!("INFO: {}", info)).color(Color32::from_rgb(100, 200, 255)));
                        ui.label(format!("Total: {}", self.llm_findings_filtered.len()));
                    });
                    ui.add_space(10.0);

                    if ui.button(RichText::new("Copy All Findings to Clipboard").strong()).clicked() {
                        let text = self.llm_findings.iter()
                        .map(|f| format!("[{}] {} - {}: {}\nEvidence: {}", f.timestamp, f.severity, f.hostname, f.message, f.evidence))
                        .collect::<Vec<_>>()
                        .join("\n\n");
                        ctx.output_mut(|o| o.copied_text = text);  // FIXED: correct way to copy text in egui
                        self.status_message = "All findings copied to clipboard!".to_string();
                    }
                    ui.add_space(12.0);

                    ScrollArea::vertical().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Timestamp").strong());
                            ui.add_space(120.0);
                            ui.label(RichText::new("Hostname").strong());
                            ui.add_space(100.0);
                            ui.label(RichText::new("Severity").strong());
                            ui.add_space(80.0);
                            ui.label(RichText::new("Message").strong());
                            ui.add_space(100.0);
                            ui.label(RichText::new("Evidence").strong());
                        });
                        ui.add_space(8.0);

                        for p in 0..(end - start) {
                            let i = self.llm_findings_filtered[start + p];
                            let f = &self.llm_findings[i];

                            let color = match f.severity.as_str() {
                                "HIGH"   => Color32::from_rgb(255, 100, 100),
                                                "MEDIUM" => Color32::from_rgb(255, 200, 100),
                                                "INFO"   => Color32::from_rgb(100, 200, 255),
                                                _ => Color32::WHITE,
                            };

                            ui.horizontal(|ui| {
                                ui.label(&f.timestamp);
                                ui.add_space(120.0);
                                ui.label(&f.hostname);
                                ui.add_space(100.0);
                                ui.label(RichText::new(&f.severity).color(color));
                                ui.add_space(80.0);
                                ui.label(&f.message);
                                ui.add_space(100.0);
                                ui.label(&f.evidence);
                            });
                        }
                    });

                    ui.horizontal(|ui| {
                        if ui.button("Previous").clicked() && self.llm_findings_current_page > 0 {
                            self.llm_findings_current_page -= 1;
                        }
                        ui.label(format!("Page {} of {}", self.llm_findings_current_page + 1, num_pages));
                        if ui.button("Next").clicked() && self.llm_findings_current_page + 1 < num_pages {
                            self.llm_findings_current_page += 1;
                        }
                    });
                }
            }
        });

        while let Ok(msg) = self.status_rx.try_recv() {
            self.status_message = msg;
            ctx.request_repaint();
        }

        while let Ok(result) = self.result_rx.try_recv() {
            match result {
                Ok((Some(resp), duration, chain, None)) => {
                    self.replay_duration_ms = duration.as_millis() as u64;
                    self.redirect_chain = chain;
                    self.last_error_kind = None;

                    let lines: Vec<&str> = resp.lines().collect();
                    if !lines.is_empty() {
                        self.replay_status = lines[0].to_string();

                        let header_end = lines.iter().position(|&l| l.is_empty()).unwrap_or(lines.len());
                        self.replay_headers = if header_end > 1 {
                            lines[1..header_end].join("\n")
                        } else {
                            String::new()
                        };

                        let body_start = header_end + 1;
                        let raw_body = if body_start < lines.len() {
                            lines[body_start..].join("\n")
                        } else {
                            String::new()
                        };

                        if self.pretty_json && self.replay_headers.to_lowercase().contains("application/json") {
                            if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&raw_body) {
                                if let Ok(pretty) = serde_json::to_string_pretty(&json_val) {
                                    self.replay_body = pretty;
                                } else {
                                    self.replay_body = raw_body;
                                }
                            } else {
                                self.replay_body = raw_body;
                            }
                        } else {
                            self.replay_body = if raw_body.len() > 5000 {
                                format!("{}\n\n[Truncated – full length: {} chars]", &raw_body[..5000], raw_body.len())
                            } else {
                                raw_body
                            };
                        }
                    }
                    self.status_message = "Replay complete!".to_string();
                    self.repeater_sub_tab = RepeaterSubTab::ReplayedResponse;
                }
                Ok((None, duration, _, Some(err_kind))) if !err_kind.starts_with("progress:") && !err_kind.starts_with("batch_done:") => {
                    self.replay_duration_ms = duration.as_millis() as u64;
                    self.replay_status = format!("Error – {}", err_kind.replace('_', " "));
                    self.replay_headers.clear();
                    self.replay_body = match err_kind.as_str() {
                        "timeout" => "The request timed out.\nServer did not respond in time.".to_string(),
                        "connection_refused" => "Connection refused.\n→ Server is down, port is closed, or firewall blocking".to_string(),
                        "dns_failure" => "DNS resolution failed.\n→ Hostname could not be resolved".to_string(),
                        "tls_handshake" => "TLS handshake failed.\n→ Invalid cert / protocol mismatch".to_string(),
                        "body_error" => "Response body could not be read/decoded".to_string(),
                        _ => format!("Unknown error: {}", err_kind),
                    };
                    self.last_error_kind = Some(err_kind);
                    self.status_message = "Replay failed".to_string();
                    self.repeater_sub_tab = RepeaterSubTab::ReplayedResponse;
                }
                Ok((_, _, _, Some(msg))) => {
                    if msg.starts_with("progress:") {
                        if let Some(parts) = msg.strip_prefix("progress:") {
                            let nums: Vec<&str> = parts.split('/').collect();
                            if nums.len() == 2 {
                                if let (Ok(cur), Ok(tot)) = (nums[0].parse::<usize>(), nums[1].parse::<usize>()) {
                                    self.batch_progress = (cur, tot);
                                    ctx.request_repaint();
                                }
                            }
                        }
                    } else if msg.starts_with("batch_done:") {
                        self.batch_in_progress = false;
                        self.status_message = format!(
                            "Batch LLM scan complete — {} entries processed.",
                            msg.strip_prefix("batch_done:").unwrap_or("0")
                        );

                        let llm_findings_path = "llm_findings.jsonl".to_string();
                        self.llm_findings.clear();
                        if let Ok(file) = File::open(&llm_findings_path) {
                            let reader = io::BufReader::new(file);
                            for line in reader.lines() {
                                if let Ok(line) = line {
                                    if let Ok(finding) = serde_json::from_str::<LlmFinding>(&line) {
                                        self.llm_findings.push(finding);
                                    }
                                }
                            }
                        }
                        self.llm_findings_filtered = (0..self.llm_findings.len()).collect();
                        ctx.request_repaint();
                    }
                }
                Err(e) => {
                    self.status_message = format!("Task error: {}", e);
                    self.batch_in_progress = false;
                    ctx.request_repaint();
                }
                _ => {}
            }
        }

        if self.selected_tab == Tab::Logs || self.batch_in_progress || self.selected_tab == Tab::LlmFindings {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }

        let entries_len = self.traffic_log.entries().map(|e| e.len()).unwrap_or(0);
        static mut LAST_LOG_COUNT: usize = 0;
        if entries_len != unsafe { LAST_LOG_COUNT } || !self.status_message.is_empty() || self.batch_in_progress {
            unsafe { LAST_LOG_COUNT = entries_len };
            ctx.request_repaint();
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        info!("Exiting application");
        self.stop_proxy();
        self.stop_webhook();
        self.stop_node();
        if let Some(tx) = self.task_shutdown_tx.take() {
            let _ = tx.send(());
        }
        let handle = mem::replace(&mut self.task_handle, std::thread::spawn(|| {}));
        if let Err(e) = handle.join() {
            error!("Failed to join task handle: {:?}", e);
        }
    }
}

async fn batch_llm_scan(
    traffic_log: &TrafficLog,
    llm: &LlmScanner,
    status_tx: mpsc::Sender<String>,
    progress_tx: mpsc::Sender<(usize, usize)>,
) -> Result<usize> {
    let entries = traffic_log.entries()?;

    let to_scan: Vec<(usize, TrafficEntry)> = entries
    .into_iter()
    .enumerate()
    .filter(|(_, e)| !e.llm_scanned && should_scan_entry(e))
    .collect();

    let total = to_scan.len();
    if total == 0 {
        let _ = status_tx.send("No unscanned entries eligible for LLM scan (all skipped or already scanned).".to_string()).await;
        return Ok(0);
    }

    let _ = status_tx.send(format!("Starting batch LLM scan — {} entries eligible", total)).await;

    let llm_findings_path = "llm_findings.jsonl".to_string();
    let mut file = OpenOptions::new()
    .create(true)
    .append(true)
    .open(&llm_findings_path)
    .map_err(|e| anyhow!("Failed to open llm_findings.jsonl: {}", e))?;

    let mut scanned = 0;
    let mut written = 0;

    for (idx, entry) in to_scan {
        let hostname = entry.hostname.clone();

        match llm.scan_saved_entry(&hostname, &entry.entry_type, &entry.data).await {
            Ok(detections) => {
                info!("Entry {} ({}) → {} detections from LLM", idx, hostname, detections.len());
                for det in detections.into_iter().filter(|d| d.confidence > 0.5) { // lowered to 0.5 for testing
                    let severity = match det.detection_type {
                        DetectionType::Secret => "HIGH",
                        DetectionType::Note => "MEDIUM",
                        _ => "INFO",
                    };
                    let msg = format!(
                        "{:?}: {} = {} (conf: {:.2})",
                                      det.detection_type, det.software_or_key, det.value_or_version, det.confidence
                    );

                    // Write to file
                    let finding = LlmFinding {
                        timestamp: OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default(),
                        hostname: hostname.clone(),
                        severity: severity.to_string(),
                        message: msg.clone(),
                        evidence: det.evidence.clone(),
                    };
                    if let Ok(line) = serde_json::to_string(&finding) {
                        if writeln!(file, "{}", line).is_ok() {
                            written += 1;
                        }
                    }

                    info!("Wrote finding: {} - {}", severity, msg);
                }
            }
            Err(e) => {
                warn!("LLM scan failed on entry {} ({}): {}", idx, hostname, e);
            }
        }

        // Mark as scanned
        {
            let mut guard = traffic_log.entries().map_err(|e| anyhow!("RwLock error: {}", e))?;
            if let Some(e) = guard.get_mut(idx) {
                e.llm_scanned = true;
            }
        }

        scanned += 1;
        let _ = progress_tx.send((scanned, total)).await;
        let _ = status_tx.send(format!("Scanned {}/{}", scanned, total)).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
    }

    let _ = status_tx.send(format!("Batch finished — {} entries scanned, {} findings written.", scanned, written)).await;

    Ok(scanned)
}

fn should_scan_entry(e: &TrafficEntry) -> bool {
    if e.llm_scanned {
        return false;
    }
    if e.entry_type != "request" && e.entry_type != "response" {
        return false;
    }
    if e.data.len() > 800_000 || e.data.contains('\u{FFFD}') {
        return false;
    }
    true
}

fn main() -> Result<(), Box<dyn StdError>> {
    let log_file = File::create("proxy_errors.log").map_err(|e| Box::<dyn StdError>::from(format!("Failed to create log file: {}", e)))?;
    Builder::new()
    .filter_level(LevelFilter::Debug)
    .target(env_logger::Target::Pipe(Box::new(log_file)))
    .write_style(env_logger::WriteStyle::Always)
    .init();
    info!("Starting Proxy Tool...");

    let (status_tx, _status_rx) = mpsc::channel(32);

    let ca = Arc::new(CaCert::new(false, Some(status_tx.clone())).map_err(|e| {
        error!("Failed to init CA: {}", e);
        Box::<dyn StdError>::from(format!("Failed to init CA: {}", e))
    })?);

    let client = Client::new();
    let db = Arc::new(Mutex::new(Connection::open_in_memory()?));
    let fetcher = Arc::new(CveFetcher::new(client, db).map_err(|e| {
        error!("CveFetcher init failed: {}", e);
        Box::<dyn StdError>::from(format!("Failed to init CveFetcher: {}", e))
    })?);

    eframe::run_native(
        "Proxy Tool",
        NativeOptions {
            viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_resizable(true),
                       ..Default::default()
        },
        Box::new(|_cc| Box::new(ProxyToolApp::new(ca, fetcher))),
    )?;
    Ok(())
}
