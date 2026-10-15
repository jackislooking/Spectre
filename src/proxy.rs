use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{ServerConfig, RootCertStore};
use tokio_rustls::TlsAcceptor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rustls::pki_types::PrivateKeyDer;
use std::sync::Arc;
use log::{info, error, debug};
use std::fs;
use std::io::{BufReader, Cursor};
use crate::cert::{CaCert, generate_server_cert};
use crate::traffic::TrafficLog;
use crate::scanner::{passive_scan_response, passive_scan_request};
use webpki_roots;
use tokio::sync::oneshot::Receiver;
use rustls::pki_types::ServerName;
use std::io::ErrorKind;

pub async fn start_proxy(
    ca: Arc<CaCert>,
    traffic_log: TrafficLog,
    fetcher: Arc<crate::cve_fetcher::CveFetcher>,
    mut shutdown: Receiver<()>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    info!("Proxy server started on port 8080");

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Proxy shutdown signal received");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, client_addr)) => {
                        info!("Accepted connection from {}", client_addr);
                        let ca = ca.clone();
                        let traffic_log = traffic_log.clone();
                        let fetcher = fetcher.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, client_addr, &ca, &traffic_log, &fetcher).await {
                                error!("Error handling connection from {}: {}", client_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Error accepting connection: {}", e);
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_connection(
    mut stream: TcpStream,
    client_addr: std::net::SocketAddr,
    ca: &CaCert,
    traffic_log: &TrafficLog,
    fetcher: &crate::cve_fetcher::CveFetcher,
) -> anyhow::Result<()> {
    // Peek to check if it's a CONNECT request
    let mut buffer = vec![0; 1024];
    let n = stream.peek(&mut buffer).await?;
    let initial_data = String::from_utf8_lossy(&buffer[..n]);

    if !initial_data.to_uppercase().starts_with("CONNECT") {
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
        return Ok(());
    }

    // Read full CONNECT request
    let mut request_data = Vec::new();
    let mut temp_buffer = [0; 1024];
    loop {
        let n = stream.read(&mut temp_buffer).await?;
        if n == 0 {
            return Err(anyhow::anyhow!("Unexpected EOF while reading CONNECT request"));
        }
        request_data.extend_from_slice(&temp_buffer[..n]);
        if request_data.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let request_str = String::from_utf8_lossy(&request_data);
    debug!("Consumed CONNECT request: {}", request_str);

    // Extract hostname
    let hostname = request_str
    .split_whitespace()
    .nth(1)
    .and_then(|s| s.split(':').next())
    .ok_or_else(|| anyhow::anyhow!("Invalid CONNECT request: no hostname"))?
    .to_string();

    if hostname.is_empty() || !hostname.contains('.') {
        return Err(anyhow::anyhow!("Invalid hostname: {}", hostname));
    }
    debug!("Processing CONNECT for hostname: {}", hostname);

    // Log CONNECT
    traffic_log.add_entry(&hostname, "connect", &request_str, &client_addr.ip().to_string()).await?;

    // Send 200 Connection Established
    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    // Generate and use MITM certificate
    let (cert_path, key_path, _chain_path) = generate_server_cert(&hostname, ca, false)?;
    let mut root_store = RootCertStore::empty();
    let ca_certs = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(ca.cert_pem.as_bytes())))
    .collect::<Result<Vec<_>, _>>()?;
    for cert in ca_certs {
        root_store.add(cert)?;
    }

    let certs = rustls_pemfile::certs(&mut BufReader::new(fs::File::open(&cert_path)?))
    .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(fs::File::open(&key_path)?))
    .next()
    .ok_or_else(|| anyhow::anyhow!("No private key found"))??;

    let server_config = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, PrivateKeyDer::Pkcs8(key))?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let tls_stream = acceptor.accept(stream).await
    .map_err(|e| {
        error!("TLS handshake failed for {}: {}", hostname, e);
        e
    })?;

    // Connect to real server
    let server_stream = TcpStream::connect((&hostname[..], 443)).await?;
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = Arc::new(
        rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
    );

    let connector = tokio_rustls::TlsConnector::from(client_config);
    let server_name = ServerName::try_from(hostname.as_str())?.to_owned();
    let server_tls = connector.connect(server_name, server_stream).await?;

    // Split streams
    let (mut client_reader, mut client_writer) = tokio::io::split(tls_stream);
    let (mut server_reader, mut server_writer) = tokio::io::split(server_tls);

    // Client → Server direction
    let client_to_server = async {
        let mut buffer = vec![0; 8192];
        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    let data = String::from_utf8_lossy(&buffer[..n]).to_string();
                    debug!("Request chunk for {}: {} bytes", hostname, n);

                    traffic_log.add_entry(&hostname, "request", &data, &client_addr.ip().to_string()).await?;

                    if let Err(e) = passive_scan_request(
                        &hostname,
                        &data,
                        traffic_log,
                        &client_addr.ip().to_string(),
                                                         fetcher,
                    ).await {
                        error!("Request passive scan failed for {}: {}", hostname, e);
                    }

                    server_writer.write_all(&buffer[..n]).await?;
                }
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    // Server → Client direction
    let server_to_client = async {
        let mut buffer = vec![0; 8192];
        loop {
            match server_reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    let data = String::from_utf8_lossy(&buffer[..n]).to_string();
                    debug!("Response chunk for {}: {} bytes", hostname, n);

                    traffic_log.add_entry(&hostname, "response", &data, &client_addr.ip().to_string()).await?;

                    if let Err(e) = passive_scan_response(
                        &hostname,
                        &data,
                        traffic_log,
                        &client_addr.ip().to_string(),
                                                          fetcher,
                    ).await {
                        error!("Response passive scan failed for {}: {}", hostname, e);
                    }

                    client_writer.write_all(&buffer[..n]).await?;
                }
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

async fn handle_webhook_connection(
    mut stream: TcpStream,
    client_addr: std::net::SocketAddr,
    traffic_log: &TrafficLog,
) -> anyhow::Result<()> {
    let mut buffer = vec![0; 8192];
    let mut total_read = 0;

    loop {
        let n = stream.read(&mut buffer[total_read..]).await?;
        if n == 0 {
            break;
        }
        total_read += n;
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if total_read >= buffer.len() {
            buffer.resize(buffer.len() * 2, 0);
        }
    }

    let request_str = String::from_utf8_lossy(&buffer[..total_read]).to_string();
    debug!("Webhook request from {}: {}", client_addr, request_str);

    traffic_log.add_entry("webhook-server", "webhook", &request_str, &client_addr.ip().to_string()).await?;

    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await?;
    Ok(())
}

pub async fn start_webhook(
    traffic_log: TrafficLog,
    mut shutdown: Receiver<()>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:8081").await?;
    info!("Webhook server started on port 8081");

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("Webhook shutdown signal received");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, addr)) => {
                        let tl = traffic_log.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_webhook_connection(stream, addr, &tl).await {
                                error!("Webhook connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Webhook accept error: {}", e);
                    }
                }
            }
        }
    }
    Ok(())
}
