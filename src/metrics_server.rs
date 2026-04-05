//! Prometheus Metrics HTTP 端点
//!
//! 使用 hyper 1.x 实现最小化 HTTP server，仅响应 `GET /metrics`。
//! 极其轻量，仅在 Prometheus 抓取时处理请求，对代理性能几乎无影响。

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::PrometheusHandle;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::error::SocksError;

/// 启动 Metrics HTTP 服务器
///
/// 在指定地址监听，仅响应 `GET /metrics` 请求，返回 Prometheus 格式的指标文本。
/// 其他路径返回 404，非 GET 方法返回 405。
pub async fn serve_metrics(
    bind: SocketAddr,
    handle: PrometheusHandle,
    cancel: CancellationToken,
) -> Result<(), SocksError> {
    let listener = TcpListener::bind(bind).await?;
    info!("Metrics server listening on http://{}/metrics", bind);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                let handle = handle.clone();
                let io = TokioIo::new(stream);

                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let handle = handle.clone();
                        async move {
                            handle_request(req, handle)
                        }
                    });

                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        error!(error = %e, "Metrics HTTP connection error");
                    }
                });
            }
            _ = cancel.cancelled() => {
                info!("Metrics server shutting down");
                break;
            }
        }
    }

    Ok(())
}

/// 处理单个 HTTP 请求
fn handle_request(
    req: Request<Incoming>,
    handle: PrometheusHandle,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let body = handle.render();
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }
        (&Method::GET, _) => {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not Found\n")))
                .unwrap()
        }
        _ => {
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::from("Method Not Allowed\n")))
                .unwrap()
        }
    };
    Ok(response)
}
