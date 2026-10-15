use anyhow::Result;
use log::{info, warn};
use hyper::{header, HeaderMap, StatusCode};
use regex::Regex;
use lazy_static::lazy_static;
use crate::traffic::TrafficLog;
use hyper::http::{HeaderName, HeaderValue};

lazy_static! {
    static ref SERVER_RE: Regex = Regex::new(r"(?i)(Apache|Nginx|IIS|LiteSpeed|cloudflare)/([\d.]+)").unwrap();
    static ref GENERATOR_RE: Regex = Regex::new(r#"(?i)<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"']+)["']"#).unwrap();
    static ref PHP_RE: Regex = Regex::new(r"(?i)X-Powered-By:\s*PHP/([\d.]+)").unwrap();
    static ref WORDPRESS_RE: Regex = Regex::new(r"(?i)wp-content|wordpress\s+([\d.]+)").unwrap();
    static ref JOOMLA_RE: Regex = Regex::new(r"(?i)Joomla!\s*([\d.]+)").unwrap();
    static ref DRUPAL_RE: Regex = Regex::new(r"(?i)Drupal\s*([\d.]+)").unwrap();
    static ref EXPRESS_RE: Regex = Regex::new(r"(?i)X-Powered-By:\s*Express\s*([\d.]+)?").unwrap();

    static ref JS_LIB_VERSIONS: Vec<(&'static str, Regex)> = vec![
        ("jQuery", Regex::new(r"(?i)jquery[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js").unwrap()),
        ("React", Regex::new(r"(?i)react(?:-dom)?[.-](\d+\.\d+\.\d+)(?:\.min)?\.js").unwrap()),
        ("Vue", Regex::new(r"(?i)vue[.-](\d+\.\d+\.\d+)(?:\.min)?\.js").unwrap()),
        ("Angular", Regex::new(r"(?i)angular[.-](\d+\.\d+\.\d+)(?:\.min)?\.js").unwrap()),
        ("Bootstrap", Regex::new(r"(?i)bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.js").unwrap()),
        ("Lodash", Regex::new(r"(?i)lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js").unwrap()),
    ];
}

pub async fn passive_scan_response(
    hostname: &str,
    raw_data: &str,
    traffic_log: &TrafficLog,
    client_ip: &str,
    _fetcher: &crate::cve_fetcher::CveFetcher,  // kept for future batch/CVE use
) -> Result<()> {
    let (status, headers, body) = parse_http_response(raw_data)?;
    let headers_str = format!("{:#?}", headers);

    let mut detections = Vec::new();

    // Cheap & fast: regex-based version detection (live only)
    add_regex_boosts(&headers, &body, &headers_str, hostname, client_ip, traffic_log, &mut detections).await;

    // Flag obvious HTTP errors (still live)
    if status.is_client_error() || status.is_server_error() {
        let msg = format!("HTTP error status: {}", status);
        if let Err(e) = traffic_log.add_vuln_alert(hostname, &msg, &msg, "MEDIUM", client_ip).await {
            warn!("Failed to add HTTP error alert: {}", e);
        }
        warn!("{}", msg);
    }

    Ok(())
}

pub async fn passive_scan_request(
    hostname: &str,
    raw_data: &str,
    traffic_log: &TrafficLog,
    client_ip: &str,
    _fetcher: &crate::cve_fetcher::CveFetcher,  // kept for future batch/CVE use
) -> Result<()> {
    let (_method, headers, _body) = parse_http_request(raw_data)?;

    // Cheap & fast: User-Agent browser/version detection only (live)
    if let Some(ua) = headers.get(header::USER_AGENT) {
        if let Ok(ua_str) = ua.to_str() {
            for (browser, re_str) in [
                ("Chrome", r"Chrome/([\d.]+)"),
                ("Firefox", r"Firefox/([\d.]+)"),
                ("Safari", r"Safari/([\d.]+)"),
                ("Edge", r"Edg/([\d.]+)"),
            ] {
                if let Ok(re) = Regex::new(re_str) {
                    if let Some(caps) = re.captures(ua_str) {
                        let version = caps.get(1).map(|m| m.as_str()).unwrap_or_default().to_string();
                        if !version.is_empty() {
                            let software = browser.to_lowercase();
                            let msg = format!("{} {}", software, version);
                            let evidence = format!("User-Agent: {}", ua_str);
                            let _ = traffic_log.add_vuln_alert(hostname, &msg, &evidence, "INFO", client_ip).await;
                            info!("Detected client UA (live): {}", msg);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn add_regex_boosts(
    headers: &HeaderMap,
    body: &str,
    headers_str: &str,
    hostname: &str,
    client_ip: &str,
    traffic_log: &TrafficLog,
    detections: &mut Vec<crate::llm_scanner::Detection>,
) {
    // Server header
    if let Some(server) = headers.get(header::SERVER) {
        if let Ok(server_str) = server.to_str() {
            if let Some(caps) = SERVER_RE.captures(server_str) {
                let software = caps.get(1).map(|m| m.as_str().to_lowercase()).unwrap_or_default();
                let version = caps.get(2).map(|m| m.as_str()).unwrap_or_default().to_string();
                if !version.is_empty() && !detections.iter().any(|d| {
                    matches!(d.detection_type, crate::llm_scanner::DetectionType::Version) &&
                    d.software_or_key == software &&
                    d.value_or_version == version
                }) {
                    let msg = format!("{} {}", software, version);
                    let evidence = format!("Server: {}", server_str);
                    let new_det = crate::llm_scanner::Detection {
                        detection_type: crate::llm_scanner::DetectionType::Version,
                        software_or_key: software.clone(),
                        value_or_version: version.clone(),
                        evidence,
                        confidence: 1.0,
                    };
                    detections.push(new_det);
                    let _ = traffic_log.add_vuln_alert(hostname, &msg, &msg, "INFO", client_ip).await;
                    info!("Regex boost (Server): {}", msg);
                }
            }
        }
    }

    // Generator meta tag
    if let Some(caps) = GENERATOR_RE.captures(body) {
        let generator = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let parts: Vec<&str> = generator.split_whitespace().collect();
        if !parts.is_empty() {
            let software = parts[0].to_lowercase();
            let version = parts.get(1).copied().unwrap_or_default().to_string();
            if !version.is_empty() && !detections.iter().any(|d| {
                matches!(d.detection_type, crate::llm_scanner::DetectionType::Version) &&
                d.software_or_key == software &&
                d.value_or_version == version
            }) {
                let msg = format!("{} {}", software, version);
                let evidence = format!("<meta generator=\"{}\">", generator);
                let new_det = crate::llm_scanner::Detection {
                    detection_type: crate::llm_scanner::DetectionType::Version,
                    software_or_key: software.clone(),
                    value_or_version: version.clone(),
                    evidence,
                    confidence: 0.95,
                };
                detections.push(new_det);
                let _ = traffic_log.add_vuln_alert(hostname, &msg, &msg, "INFO", client_ip).await;
                info!("Regex boost (Generator): {}", msg);
            }
        }
    }

    // JavaScript library versions from filenames
    for (name, re) in JS_LIB_VERSIONS.iter() {
        for cap in re.captures_iter(body) {
            if let Some(ver) = cap.get(1) {
                let software = name.to_lowercase();
                let version = ver.as_str().to_string();
                if !detections.iter().any(|d| {
                    matches!(d.detection_type, crate::llm_scanner::DetectionType::Version) &&
                    d.software_or_key == software &&
                    d.value_or_version == version
                }) {
                    let msg = format!("{} {}", software, version);
                    let evidence = format!("JS filename match: {}", cap.get(0).unwrap().as_str());
                    let new_det = crate::llm_scanner::Detection {
                        detection_type: crate::llm_scanner::DetectionType::Version,
                        software_or_key: software.clone(),
                        value_or_version: version.clone(),
                        evidence,
                        confidence: 0.95,
                    };
                    detections.push(new_det);
                    let _ = traffic_log.add_vuln_alert(hostname, &msg, &msg, "INFO", client_ip).await;
                    info!("Regex boost (JS lib): {}", msg);
                }
            }
        }
    }

    // PHP version from X-Powered-By
    if let Some(caps) = PHP_RE.captures(headers_str) {
        if let Some(ver) = caps.get(1) {
            let software = "php".to_string();
            let version = ver.as_str().to_string();
            if !detections.iter().any(|d| {
                matches!(d.detection_type, crate::llm_scanner::DetectionType::Version) &&
                d.software_or_key == software &&
                d.value_or_version == version
            }) {
                let msg = format!("{} {}", software, version);
                let evidence = format!("X-Powered-By: {}", caps.get(0).unwrap().as_str());
                let new_det = crate::llm_scanner::Detection {
                    detection_type: crate::llm_scanner::DetectionType::Version,
                    software_or_key: software.clone(),
                    value_or_version: version.clone(),
                    evidence,
                    confidence: 0.95,
                };
                detections.push(new_det);
                let _ = traffic_log.add_vuln_alert(hostname, &msg, &msg, "INFO", client_ip).await;
                info!("Regex boost (PHP): {}", msg);
            }
        }
    }

    // WordPress version
    if let Some(caps) = WORDPRESS_RE.captures(body) {
        if let Some(ver) = caps.get(1) {
            let software = "wordpress".to_string();
            let version = ver.as_str().to_string();
            if !detections.iter().any(|d| {
                matches!(d.detection_type, crate::llm_scanner::DetectionType::Version) &&
                d.software_or_key == software &&
                d.value_or_version == version
            }) {
                let msg = format!("{} {}", software, version);
                let evidence = format!("Body match: {}", caps.get(0).unwrap().as_str());
                let new_det = crate::llm_scanner::Detection {
                    detection_type: crate::llm_scanner::DetectionType::Version,
                    software_or_key: software.clone(),
                    value_or_version: version.clone(),
                    evidence,
                    confidence: 0.90,
                };
                detections.push(new_det);
                let _ = traffic_log.add_vuln_alert(hostname, &msg, &msg, "INFO", client_ip).await;
                info!("Regex boost (WordPress): {}", msg);
            }
        }
    }

    // Joomla version
    if let Some(caps) = JOOMLA_RE.captures(body) {
        if let Some(ver) = caps.get(1) {
            let software = "joomla".to_string();
            let version = ver.as_str().to_string();
            if !detections.iter().any(|d| {
                matches!(d.detection_type, crate::llm_scanner::DetectionType::Version) &&
                d.software_or_key == software &&
                d.value_or_version == version
            }) {
                let msg = format!("{} {}", software, version);
                let evidence = format!("Body match: {}", caps.get(0).unwrap().as_str());
                let new_det = crate::llm_scanner::Detection {
                    detection_type: crate::llm_scanner::DetectionType::Version,
                    software_or_key: software.clone(),
                    value_or_version: version.clone(),
                    evidence,
                    confidence: 0.90,
                };
                detections.push(new_det);
                let _ = traffic_log.add_vuln_alert(hostname, &msg, &msg, "INFO", client_ip).await;
                info!("Regex boost (Joomla): {}", msg);
            }
        }
    }

    // Drupal version
    if let Some(caps) = DRUPAL_RE.captures(body) {
        if let Some(ver) = caps.get(1) {
            let software = "drupal".to_string();
            let version = ver.as_str().to_string();
            if !detections.iter().any(|d| {
                matches!(d.detection_type, crate::llm_scanner::DetectionType::Version) &&
                d.software_or_key == software &&
                d.value_or_version == version
            }) {
                let msg = format!("{} {}", software, version);
                let evidence = format!("Body match: {}", caps.get(0).unwrap().as_str());
                let new_det = crate::llm_scanner::Detection {
                    detection_type: crate::llm_scanner::DetectionType::Version,
                    software_or_key: software.clone(),
                    value_or_version: version.clone(),
                    evidence,
                    confidence: 0.90,
                };
                detections.push(new_det);
                let _ = traffic_log.add_vuln_alert(hostname, &msg, &msg, "INFO", client_ip).await;
                info!("Regex boost (Drupal): {}", msg);
            }
        }
    }

    // Express version
    if let Some(caps) = EXPRESS_RE.captures(headers_str) {
        if let Some(ver) = caps.get(1) {
            let software = "express".to_string();
            let version = ver.as_str().to_string();
            if !detections.iter().any(|d| {
                matches!(d.detection_type, crate::llm_scanner::DetectionType::Version) &&
                d.software_or_key == software &&
                d.value_or_version == version
            }) {
                let msg = format!("{} {}", software, version);
                let evidence = format!("X-Powered-By: {}", caps.get(0).unwrap().as_str());
                let new_det = crate::llm_scanner::Detection {
                    detection_type: crate::llm_scanner::DetectionType::Version,
                    software_or_key: software.clone(),
                    value_or_version: version.clone(),
                    evidence,
                    confidence: 0.95,
                };
                detections.push(new_det);
                let _ = traffic_log.add_vuln_alert(hostname, &msg, &msg, "INFO", client_ip).await;
                info!("Regex boost (Express): {}", msg);
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// HTTP PARSERS — PUBLIC so llm_scanner.rs can use them for batch scanning
// ────────────────────────────────────────────────────────────────────────────────

pub fn parse_http_response(raw: &str) -> Result<(StatusCode, HeaderMap, String)> {
    let mut headers = HeaderMap::new();
    let mut lines = raw.lines();

    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    let status = parts.get(1)
    .and_then(|s| s.parse::<u16>().ok())
    .and_then(|code| StatusCode::from_u16(code).ok())
    .unwrap_or(StatusCode::OK);

    let mut body_lines = Vec::new();
    let mut in_headers = true;

    for line in lines {
        if in_headers {
            if line.trim().is_empty() {
                in_headers = false;
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                if let (Ok(hk), Ok(hv)) = (HeaderName::from_bytes(key.as_bytes()), HeaderValue::from_str(value)) {
                    headers.insert(hk, hv);
                }
            }
        } else {
            body_lines.push(line);
        }
    }

    let body = body_lines.join("\n");
    Ok((status, headers, body))
}

pub fn parse_http_request(raw: &str) -> Result<(hyper::Method, HeaderMap, String)> {
    let mut headers = HeaderMap::new();
    let mut lines = raw.lines();

    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    let method = parts.get(0)
    .and_then(|s| hyper::Method::from_bytes(s.as_bytes()).ok())
    .unwrap_or(hyper::Method::GET);

    let mut body_lines = Vec::new();
    let mut in_headers = true;

    for line in lines {
        if in_headers {
            if line.trim().is_empty() {
                in_headers = false;
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim();
                if let (Ok(hk), Ok(hv)) = (HeaderName::from_bytes(key.as_bytes()), HeaderValue::from_str(value)) {
                    headers.insert(hk, hv);
                }
            }
        } else {
            body_lines.push(line);
        }
    }

    let body = body_lines.join("\n");
    Ok((method, headers, body))
}
