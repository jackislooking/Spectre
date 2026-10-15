use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use anyhow::{Result, anyhow};
use std::fs::{File, OpenOptions};
use std::io::{Write, BufRead, BufReader};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use log::{warn, info};
use crate::cve_fetcher::CveFetcher;
use tokio::sync::mpsc::{self, Sender};
use std::time::{Duration, Instant};
use reqwest::{redirect::Policy, ClientBuilder};
use crate::scanner::passive_scan_response;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TrafficEntry {
    pub timestamp: String,
    pub hostname: String,
    pub entry_type: String,
    pub data: String,
    pub client_ip: String,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default = "default_false")]
    pub llm_scanned: bool,          // NEW: tracks whether LLM analysis has already been done
}

fn default_false() -> bool {
    false
}

#[derive(Clone)]
pub struct TrafficLog {
    entries: Arc<RwLock<Vec<TrafficEntry>>>,
    save_tx: Sender<TrafficEntry>,
    notify_tx: Sender<String>,  // Channel for GUI notifications
}

impl TrafficLog {
    pub fn load(notify_tx: Sender<String>) -> Result<Self> {
        let file_path = "traffic_log.jsonl".to_string();
        let mut entries = Vec::new();

        if let Ok(file) = File::open(&file_path) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    if !line.trim().is_empty() {
                        match serde_json::from_str::<TrafficEntry>(&line) {
                            Ok(entry) => {
                                // For old logs without the field → ensure default false
                                // (serde default already handles this, but explicit for clarity)
                                entries.push(entry);
                            }
                            Err(e) => warn!("Failed to parse log line: {}", e),
                        }
                    }
                }
            }
            info!("Loaded {} entries from traffic_log.jsonl", entries.len());
        } else {
            warn!("Traffic log file '{}' not found; starting fresh", file_path);
        }

        let (save_tx, mut save_rx) = mpsc::channel::<TrafficEntry>(32);

        std::thread::spawn(move || {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("traffic_log.jsonl") {
                while let Some(entry) = save_rx.blocking_recv() {
                    if let Ok(serialized) = serde_json::to_string(&entry) {
                        if let Err(e) = writeln!(file, "{}", serialized) {
                            warn!("Failed to append to log file: {}", e);
                        }
                    }
                }
            } else {
                warn!("Failed to open log file for append");
            }
        });

        Ok(TrafficLog {
            entries: Arc::new(RwLock::new(entries)),
           save_tx,
           notify_tx,
        })
    }

    pub async fn add_entry(&self, hostname: &str, entry_type: &str, data: &str, client_ip: &str) -> Result<()> {
        let entry = TrafficEntry {
            timestamp: OffsetDateTime::now_utc().format(&Rfc3339)?,
            hostname: hostname.to_string(),
            entry_type: entry_type.to_string(),
            data: data.to_string(),
            client_ip: client_ip.to_string(),
            evidence: None,
            severity: None,
            llm_scanned: false,                    // Regular traffic entries start unscanned
        };

        {
            let mut entries = self.entries.write().map_err(|e| anyhow!("RwLock write error: {}", e))?;
            entries.push(entry.clone());
        }

        self.save_tx.send(entry).await
        .map_err(|e| anyhow!("Failed to send entry to save channel: {}", e))?;

        let _ = self.notify_tx.send("New log entry added".to_string());

        Ok(())
    }

    pub async fn add_vuln_alert(&self, hostname: &str, alert_data: &str, evidence: &str, severity: &str, client_ip: &str) -> Result<()> {
        let entry = TrafficEntry {
            timestamp: OffsetDateTime::now_utc().format(&Rfc3339)?,
            hostname: hostname.to_string(),
            entry_type: "vuln_alert".to_string(),
            data: alert_data.to_string(),
            client_ip: client_ip.to_string(),
            evidence: Some(evidence.to_string()),
            severity: Some(severity.to_string()),
            llm_scanned: true,                     // vuln_alerts are already processed results
        };

        {
            let mut entries = self.entries.write().map_err(|e| anyhow!("RwLock write error: {}", e))?;
            entries.push(entry.clone());
        }

        self.save_tx.send(entry).await
        .map_err(|e| anyhow!("Failed to send vuln alert to save channel: {}", e))?;

        let _ = self.notify_tx.send("New vuln alert added".to_string());

        Ok(())
    }

    pub fn entries(&self) -> Result<Vec<TrafficEntry>> {
        let entries = self.entries.read().map_err(|e| anyhow!("RwLock read error: {}", e))?;
        Ok(entries.clone())
    }

    #[allow(dead_code)]
    pub fn lock_entries(&self) -> Result<std::sync::RwLockWriteGuard<'_, Vec<TrafficEntry>>> {
        self.entries.write().map_err(|e| anyhow!("RwLock write error: {}", e))
    }

    pub async fn replay_request_with_data(
        hostname: &str,
        data: &str,
        fetcher: &CveFetcher,
        notify_tx: Sender<String>,
        follow_redirects: bool,
    ) -> Result<(
        Option<String>,           // full response text or None on error
        Duration,                 // round-trip time
        Vec<String>,              // redirect chain (simplified)
    Option<String>,           // error kind if failed
    )> {
        let start = Instant::now();

        let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .redirect(if follow_redirects {
            Policy::limited(10)
        } else {
            Policy::none()
        })
        .build()?;

        let lines: Vec<&str> = data.lines().collect();
        if lines.is_empty() {
            return Ok((None, Duration::ZERO, vec![], Some("empty_request".to_string())));
        }

        let first_line = lines[0];
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Ok((None, Duration::ZERO, vec![], Some("invalid_request_line".to_string())));
        }

        let method = parts[0];
        let path = parts[1];
        let uri = format!("https://{}{}", hostname, if path.starts_with('/') { path } else { &format!("/{}", path) });

        let mut builder = client.request(method.parse()?, &uri);

        let mut body_start = 1;
        for (idx, line) in lines.iter().enumerate().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                body_start = idx + 1;
                break;
            }
            if let Some((key, value)) = trimmed.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                builder = builder.header(key, value);
            }
        }

        let body = if body_start < lines.len() {
            lines[body_start..].join("\n")
        } else {
            String::new()
        };

        let send_result = builder.body(body).send().await;

        let duration = start.elapsed();

        match send_result {
            Ok(response) => {
                let chain = vec![response.url().to_string()];

                let status_line = format!(
                    "HTTP/1.1 {} {}",
                    response.status().as_u16(),
                                          response.status().canonical_reason().unwrap_or("")
                );

                let headers_str = response.headers()
                .iter()
                .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("<?>")))
                .collect::<Vec<_>>()
                .join("\n");

                let body_bytes = response.bytes().await.unwrap_or_default();
                let body_text = if body_bytes.is_empty() {
                    "[empty body]".to_string()
                } else {
                    String::from_utf8_lossy(&body_bytes).to_string()
                };

                let full_response = format!("{}\n{}\n\n{}", status_line, headers_str, body_text);

                // Passive scan the replayed response
                let log_for_scan = TrafficLog::load(notify_tx.clone()).unwrap_or_else(|e| {
                    warn!("Failed to load traffic log for passive scan in replay: {}", e);
                    TrafficLog::load(mpsc::channel(1).0).expect("Fallback log creation failed")
                });

                if let Err(e) = passive_scan_response(
                    &hostname,
                    &full_response,
                    &log_for_scan,
                    "127.0.0.1",
                    fetcher,
                ).await {
                    warn!("Passive scan in replay failed: {}", e);
                }

                Ok((Some(full_response), duration, chain, None))
            }

            Err(e) => {
                let kind = if e.is_timeout() {
                    "timeout".to_string()
                } else if e.is_connect() {
                    "connection_refused".to_string()
                } else if e.to_string().to_lowercase().contains("resolve") || e.to_string().to_lowercase().contains("dns") {
                    "dns_failure".to_string()
                } else if e.to_string().to_lowercase().contains("certificate") || e.to_string().to_lowercase().contains("tls") {
                    "tls_handshake".to_string()
                } else if e.is_body() || e.is_decode() {
                    "body_error".to_string()
                } else {
                    "other".to_string()
                };

                info!("Replay failed with kind: {}", kind);

                Ok((None, duration, vec![], Some(kind)))
            }
        }
    }
}
