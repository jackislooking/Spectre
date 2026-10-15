use hyper::{Request, Response, StatusCode, service::service_fn};
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use log::{info, warn};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use anyhow::Result;
use crate::traffic::TrafficLog;
use hyper::body::Bytes;

pub async fn start_node_server(traffic_log: TrafficLog, shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(&addr).await?;
    info!("Node server running on {}", addr);

    tokio::select! {
        _ = shutdown_rx => {
            info!("Shutting down node server");
            Ok(())
        }
        _ = async {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Failed to accept node connection: {}", e);
                        continue;
                    }
                };

                let traffic_log = traffic_log.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_node_connection(stream, traffic_log).await {
                        warn!("Error handling node connection: {}", e);
                    }
                });
            }
        } => Ok(())
    }
}

async fn handle_node_connection(stream: tokio::net::TcpStream, traffic_log: TrafficLog) -> Result<()> {
    let service = service_fn(move |req| {
        let traffic_log = traffic_log.clone();
        handle_node_request(req, traffic_log)
    });
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await
        {
            warn!("Node server connection error: {}", e);
            return Err(e.into());
        }
        Ok(())
}

async fn handle_node_request(req: Request<hyper::body::Incoming>, traffic_log: TrafficLog) -> Result<Response<Full<Bytes>>, anyhow::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let body_bytes = match http_body_util::BodyExt::collect(req).await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            warn!("Failed to collect node request body: {}", e);
            return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("Invalid request")))?);
        }
    };
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    if method == hyper::Method::POST && path == "/vuln" {
        // Fixed: added .await
        if let Err(e) = traffic_log.add_vuln_alert(
            "node",
            &body_str,
            "node_request",
            "HIGH",
            "127.0.0.1",
        ).await {
            warn!("Failed to log vuln alert: {}", e);
        }
        Ok(Response::new(Full::new(Bytes::from("OK"))))
    } else {
        Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from("Not Found")))?)
    }
}
