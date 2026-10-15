use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use anyhow::{Result, anyhow};
use std::fs::File;
use std::io::BufReader;
use csv::ReaderBuilder;
use std::path::Path;
use std::env;
use std::cmp::Ordering;
use log::info;
use reqwest::Client;
use rusqlite::{Connection, params};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CveEntry {
    pub cve_id: String,
    pub vendor: Option<String>,
    pub software: String,
    pub version_range: String,
}

#[derive(Clone)]
pub struct CveFetcher {
    pub client: Client,
    pub db: Arc<Mutex<Connection>>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct NvdResponse {
    #[serde(rename = "resultsPerPage")]
    results_per_page: u32,
    start_index: u32,
    #[serde(rename = "totalResults")]
    total_results: u32,
    vulnerabilities: Vec<Vulnerability>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct Vulnerability {
    cve: Cve,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct Cve {
    id: String,
    configurations: Vec<Configuration>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct Configuration {
    nodes: Vec<Node>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct Node {
    #[serde(rename = "cpeMatch")]
    cpe_match: Vec<CpeMatch>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct CpeMatch {
    criteria: String,
    vulnerable: bool,
    #[serde(rename = "versionStartIncluding")]
    version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    version_end_excluding: Option<String>,
}

impl CveFetcher {
    pub fn new(client: Client, db: Arc<Mutex<Connection>>) -> Result<Self> {
        {
            let conn = db.lock().map_err(|e| anyhow!("Mutex lock error: {}", e))?;
            conn.execute(
                "CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT,
                    vendor TEXT,
                    software TEXT,
                    version_range TEXT,
                    PRIMARY KEY (cve_id, software, version_range)
            )",
            [],
            )?;
            let csv_path = env::var("CVE_CSV_PATH")
            .map(|p| Path::new(&p).to_path_buf())
            .unwrap_or_else(|_| Path::new("/home/hacker/proxy/cve_software_data.csv").to_path_buf());

            if csv_path.exists() {
                let file = File::open(&csv_path).map_err(|e| anyhow!("Failed to open CSV file: {}", e))?;
                let mut rdr = ReaderBuilder::new().from_reader(BufReader::new(file));
                for result in rdr.deserialize() {
                    let record: CveRecord = result.map_err(|e| anyhow!("Failed to parse CSV record: {}", e))?;
                    conn.execute(
                        "INSERT OR IGNORE INTO cves (cve_id, vendor, software, version_range) VALUES (?, ?, ?, ?)",
                                 params![record.cve_id, record.vendor, record.software, record.version_range],
                    )?;
                }
            }
        }
        Ok(CveFetcher { client, db })
    }

    pub fn build_cpe(software: &str, version: &str) -> Option<String> {
        Some(format!("cpe:2.3:a:*:{}:{}:*:*:*:*:*:*", software, version))
    }

    pub async fn fetch_cves_for_cpe(&self, cpe: &str) -> Result<Vec<(String, f32, String)>> {
        let parts: Vec<&str> = cpe.split(':').collect();
        if parts.len() < 6 {
            return Ok(vec![]);
        }
        let software = parts[4];
        let version = parts[5];
        let conn = self.db.lock().map_err(|e| anyhow!("Mutex lock error: {}", e))?;
        let mut stmt = conn.prepare("SELECT cve_id, version_range FROM cves WHERE software = ?")?;
        let rows = stmt.query_map([software], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut result = Vec::new();
        for row_res in rows {
            let (cve_id, version_range): (String, String) = row_res?;
            if self.version_matches(&version_range, version) {
                result.push((cve_id, 7.0, "HIGH".to_string()));
            }
        }
        Ok(result)
    }

    pub fn lookup_cve(&self, cve_id: &str) -> Result<Option<(String, String, f32, String)>> {
        let conn = self.db.lock().map_err(|e| anyhow!("Mutex lock error: {}", e))?;
        let mut stmt = conn.prepare("SELECT software, version_range FROM cves WHERE cve_id = ? LIMIT 1")?;
        let mut rows = stmt.query([cve_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some((
                row.get(0)?,
                     row.get(1)?,
                     7.0,
                     "HIGH".to_string(),
            )))
        } else {
            Ok(None)
        }
    }

    fn version_matches(&self, version_range: &str, version: &str) -> bool {
        if version_range.starts_with('<') {
            let range_version = version_range.trim_start_matches('<').trim();
            self.compare_versions(version, range_version) < 0
        } else if version_range.starts_with("==") {
            let range_version = version_range.trim_start_matches("==").trim();
            self.compare_versions(version, range_version) == 0
        } else if version_range.starts_with(">=") {
            let range_version = version_range.trim_start_matches(">=").trim();
            self.compare_versions(version, range_version) >= 0
        } else if version_range.starts_with(">") {
            let range_version = version_range.trim_start_matches(">").trim();
            self.compare_versions(version, range_version) > 0
        } else if version_range == "*" {
            true
        } else {
            false
        }
    }

    fn compare_versions(&self, v1: &str, v2: &str) -> i32 {
        let v1_parts: Vec<&str> = v1.split('.').collect();
        let v2_parts: Vec<&str> = v2.split('.').collect();
        let len = v1_parts.len().min(v2_parts.len());

        for i in 0..len {
            let p1: i32 = v1_parts[i].parse().unwrap_or(0);
            let p2: i32 = v2_parts[i].parse().unwrap_or(0);
            if p1 != p2 {
                return match p1.cmp(&p2) {
                    Ordering::Less => -1,
                    Ordering::Equal => 0,
                    Ordering::Greater => 1,
                };
            }
        }
        v1_parts.len() as i32 - v2_parts.len() as i32
    }

    pub fn get_all_cves(&self) -> Result<Vec<CveEntry>> {
        let conn = self.db.lock().map_err(|e| anyhow!("Mutex lock error: {}", e))?;
        let mut stmt = conn.prepare("SELECT cve_id, vendor, software, version_range FROM cves")?;
        let rows = stmt.query_map([], |row| {
            Ok(CveEntry {
                cve_id: row.get(0)?,
               vendor: row.get(1)?,
               software: row.get(2)?,
               version_range: row.get(3)?,
            })
        })?;
        let mut cves = Vec::new();
        for row in rows {
            cves.push(row?);
        }
        Ok(cves)
    }

    pub fn get_unique_software(&self) -> Result<Vec<String>> {
        let conn = self.db.lock().map_err(|e| anyhow!("Mutex lock error: {}", e))?;
        let mut stmt = conn.prepare("SELECT DISTINCT software FROM cves")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut softwares = Vec::new();
        for row in rows {
            softwares.push(row?);
        }
        Ok(softwares)
    }

    #[allow(dead_code)]
    pub async fn fetch_recent_cves(&self) -> Result<()> {
        let mut start_index = 0;
        loop {
            let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={}", start_index);
            let json = self.client.get(&url).send().await?.json::<NvdResponse>().await?;
            let mut cves = Vec::new();
            for vuln in json.vulnerabilities {
                let cve_id = vuln.cve.id;
                for config in vuln.cve.configurations {
                    for node in config.nodes {
                        for match_ in node.cpe_match {
                            if !match_.vulnerable {
                                continue;
                            }
                            let parts: Vec<String> = match_.criteria.split(':').map(|s| s.to_string()).collect();
                            if parts.len() < 5 {
                                continue;
                            }
                            let vendor = parts.get(3).cloned();
                            let software = parts[4].to_string();
                            let mut version_range = String::new();
                            if let Some(ref start_inc) = match_.version_start_including {
                                version_range.push_str(&format!(">={}", start_inc));
                            }
                            if let Some(ref start_exc) = match_.version_start_excluding {
                                if !version_range.is_empty() {
                                    version_range.push(' ');
                                }
                                version_range.push_str(&format!(">{}", start_exc));
                            }
                            if let Some(ref end_inc) = match_.version_end_including {
                                if !version_range.is_empty() {
                                    version_range.push(' ');
                                }
                                version_range.push_str(&format!("<={}", end_inc));
                            }
                            if let Some(ref end_exc) = match_.version_end_excluding {
                                if !version_range.is_empty() {
                                    version_range.push(' ');
                                }
                                version_range.push_str(&format!("<{}", end_exc));
                            }
                            if version_range.is_empty() {
                                let version = parts[5].clone();
                                if version != "*" && version != "-" {
                                    version_range = format!("=={}", version);
                                } else {
                                    version_range = "*".to_string();
                                }
                            }
                            cves.push((cve_id.clone(), vendor, software, version_range));
                        }
                    }
                }
            }

            info!("Inserting {} CVEs into database", cves.len());
            let conn = self.db.lock().map_err(|e| anyhow!("Mutex lock error: {}", e))?;
            for (cve_id, vendor, software, version_range) in cves {
                conn.execute(
                    "INSERT OR IGNORE INTO cves (cve_id, vendor, software, version_range) VALUES (?, ?, ?, ?)",
                             params![cve_id, vendor, software, version_range],
                )?;
            }
            drop(conn);
            info!("Inserted CVEs for start_index: {}", start_index);

            start_index += json.results_per_page;
            if start_index >= json.total_results {
                info!("Completed fetching CVEs, total results: {}", json.total_results);
                break;
            }
        }
        info!("fetch_recent_cves completed");
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct CveRecord {
    cve_id: String,
    vendor: Option<String>,
    software: String,
    version_range: String,
    source: String,
}
