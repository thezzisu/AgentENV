//! Temporary HTTP/WebSocket forwarding through the existing sandbox data plane.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::client::Client;

#[derive(Clone)]
struct Forward {
    http: reqwest::Client,
    upstream: String,
    authority: String,
    routing: HeaderMap,
}

pub(super) async fn attach(
    client: Client,
    sandbox_id: String,
    port: u16,
    open: bool,
) -> Result<()> {
    let sandbox = client.connect_sandbox(&sandbox_id, super::DEFAULT_TIMEOUT_SECS)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let authority = listener.local_addr()?.to_string();
    let forward = Forward::new(
        client.base_url(),
        &sandbox_id,
        port,
        sandbox.traffic_access_token.as_deref(),
        authority.clone(),
    )?;
    let url = format!("http://{authority}/");
    println!("Desktop: {url}");
    eprintln!("Forwarding sandbox port {port}. Ctrl-C disconnects; the desktop keeps running.");
    if open {
        open_browser(&url);
    }
    let router = Router::new().fallback(proxy).with_state(Arc::new(forward));
    let keepalive = async {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            tick.tick().await;
            let client = client.clone();
            let sandbox_id = sandbox_id.clone();
            let result = tokio::task::spawn_blocking(move || {
                client.refresh_sandbox(&sandbox_id, Some(super::DEFAULT_TIMEOUT_SECS))
            })
            .await?;
            if let Err(error) = result {
                break Err::<(), _>(error.context("desktop sandbox is no longer available"));
            }
        }
    };
    tokio::select! {
        result = axum::serve(listener, router) => result.context("desktop forward failed"),
        result = tokio::signal::ctrl_c() => result.context("waiting for Ctrl-C"),
        result = keepalive => result,
    }
}

impl Forward {
    fn new(
        base: &str,
        sandbox_id: &str,
        port: u16,
        token: Option<&str>,
        authority: String,
    ) -> Result<Self> {
        let mut routing = HeaderMap::new();
        routing.insert("x-agentenv-sandbox-id", sandbox_id.parse()?);
        routing.insert("x-agentenv-target-port", port.to_string().parse()?);
        if let Some(token) = token {
            let mut value = HeaderValue::from_str(token)?;
            value.set_sensitive(true);
            routing.insert("e2b-traffic-access-token", value);
        }
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10));
        if crate::grpc::bypass_proxy_for_base_url(base) {
            builder = builder.no_proxy();
        }
        Ok(Self {
            http: builder.build()?,
            upstream: format!("{}/proxy", base.trim_end_matches('/')),
            authority,
            routing,
        })
    }

    fn accepts(&self, headers: &HeaderMap) -> bool {
        // Restrict this authenticated forward to its local origin, including
        // WebSocket requests. A remote page must not drive the user's desktop.
        headers.get(header::HOST).and_then(|v| v.to_str().ok()) == Some(self.authority.as_str())
            && headers.get(header::ORIGIN).is_none_or(|origin| {
                origin.to_str().ok() == Some(format!("http://{}", self.authority).as_str())
            })
            && headers
                .get("sec-fetch-site")
                .is_none_or(|site| matches!(site.to_str(), Ok("same-origin" | "none")))
    }
}

async fn proxy(State(forward): State<Arc<Forward>>, request: Request) -> Response {
    if !forward.accepts(request.headers()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match relay(&forward, request).await {
        Ok(response) => response,
        Err(error) => {
            eprintln!("Desktop forward: {error:#}");
            (StatusCode::BAD_GATEWAY, "Sandbox desktop is unavailable").into_response()
        }
    }
}

async fn relay(forward: &Forward, mut request: Request) -> Result<Response> {
    let websocket = request
        .headers()
        .get(header::UPGRADE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    let upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
    let path = request.uri().path_and_query().map_or("/", |p| p.as_str());
    // `/proxy` is the root route; the server's wildcard needs a nonempty suffix.
    let path = if request.uri().path() == "/" {
        path.trim_start_matches('/')
    } else {
        path
    };
    let url = format!("{}{path}", forward.upstream);
    let (parts, body) = request.into_parts();
    let mut headers = parts.headers;
    strip_hop_headers(&mut headers, websocket);
    // The local Origin has been checked. The data plane rewrites Host, so
    // forward the WebSocket as a non-browser client rather than a false origin.
    if websocket {
        headers.remove(header::ORIGIN);
    }
    // The browser cannot change the sandbox, port, or credentials of a forward.
    for name in [
        "x-api-key",
        "x-access-token",
        "x-agentenv-sandbox-id",
        "e2b-sandbox-id",
        "x-agentenv-target-port",
        "e2b-sandbox-port",
        "e2b-traffic-access-token",
    ] {
        headers.remove(name);
    }
    headers.extend(forward.routing.clone());
    let upstream = forward
        .http
        .request(parts.method, url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await?;
    let status = upstream.status();
    let mut headers = upstream.headers().clone();
    strip_hop_headers(
        &mut headers,
        websocket && status == StatusCode::SWITCHING_PROTOCOLS,
    );
    let body = if let Some(upgrade) = upgrade.filter(|_| status == StatusCode::SWITCHING_PROTOCOLS)
    {
        let mut backend = upstream.upgrade().await?;
        tokio::spawn(async move {
            if let Ok(frontend) = upgrade.await {
                let _ =
                    tokio::io::copy_bidirectional(&mut TokioIo::new(frontend), &mut backend).await;
            }
        });
        Body::empty()
    } else {
        Body::from_stream(upstream.bytes_stream())
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

fn strip_hop_headers(headers: &mut HeaderMap, websocket: bool) {
    let connection = headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    for name in connection.split(',').map(str::trim) {
        if !name.is_empty() && !(websocket && name.eq_ignore_ascii_case("upgrade")) {
            headers.remove(name);
        }
    }
    for name in [
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
    ] {
        headers.remove(name);
    }
    if !websocket {
        headers.remove(header::CONNECTION);
        headers.remove(header::UPGRADE);
    } else {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    }
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", "start", ""]);
        command
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut command = std::process::Command::new("xdg-open");
    if let Err(error) = command.arg(url).spawn() {
        eprintln!("Could not open the browser ({error}); open the printed URL manually.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use clap::Parser;
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    #[test]
    fn gui_is_opt_in_and_cn_stays_a_shell_alias() {
        assert!(crate::Cli::try_parse_from(["aenv", "cn", "sandbox"]).is_ok());
        assert!(crate::Cli::try_parse_from(["aenv", "connect", "sandbox", "--gui"]).is_ok());
        assert!(crate::Cli::try_parse_from([
            "aenv",
            "connect",
            "sandbox",
            "--gui-port",
            "0",
            "--gui"
        ])
        .is_err());
        assert!(crate::Cli::try_parse_from(["aenv", "connect", "sandbox", "--no-open"]).is_err());
    }

    async fn start(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (address, task)
    }

    async fn forward_to(base: &str) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let authority = listener.local_addr().unwrap().to_string();
        let forward = Forward::new(
            base,
            "sandbox",
            6900,
            Some("private-traffic-token"),
            authority.clone(),
        )
        .unwrap();
        let router = Router::new().fallback(proxy).with_state(Arc::new(forward));
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (format!("http://{authority}"), task)
    }

    #[tokio::test]
    async fn streams_files_preserves_application_auth_and_rejects_other_origins() {
        let router = Router::new().fallback(|request: Request| async move {
            assert_eq!(request.uri().to_string(), "/proxy/api/upload?name=a%20b");
            assert_eq!(request.headers()["x-agentenv-sandbox-id"], "sandbox");
            assert_eq!(request.headers()["x-agentenv-target-port"], "6900");
            assert_eq!(
                request.headers()["e2b-traffic-access-token"],
                "private-traffic-token"
            );
            assert_eq!(
                request.headers()[header::AUTHORIZATION],
                "Basic app-credential"
            );
            assert!(!request.headers().contains_key("x-api-key"));
            let data = to_bytes(request.into_body(), 2 * 1024 * 1024)
                .await
                .unwrap();
            ([(header::CONTENT_TYPE, "application/octet-stream")], data)
        });
        let (upstream, upstream_task) = start(router).await;
        let (url, task) = forward_to(&format!("http://{upstream}")).await;
        let http = reqwest::Client::new();
        for (name, value) in [
            ("origin", "https://foreign.invalid"),
            ("host", "foreign.invalid"),
            ("sec-fetch-site", "cross-site"),
        ] {
            let response = http.get(&url).header(name, value).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        let payload = vec![42u8; 1024 * 1024];
        let response = http
            .post(format!("{url}/api/upload?name=a%20b"))
            .header("x-agentenv-sandbox-id", "other-sandbox")
            .header("x-agentenv-target-port", "22")
            .header("e2b-traffic-access-token", "untrusted-token")
            .header("x-api-key", "must-not-leave-client")
            .header(header::AUTHORIZATION, "Basic app-credential")
            .body(payload.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.bytes().await.unwrap().as_ref(), payload);
        task.abort();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn websocket_upgrade_relays_binary_frames_and_close() {
        let router = Router::new().fallback(|mut request: Request| async move {
            assert_eq!(request.uri(), "/proxy/websocket");
            assert_eq!(
                request.headers()["e2b-traffic-access-token"],
                "private-traffic-token"
            );
            let key = request.headers()["sec-websocket-key"].as_bytes();
            let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key);
            let upgrade = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                let socket = TokioIo::new(upgrade.await.unwrap());
                let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                    socket,
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    None,
                )
                .await;
                while let Some(Ok(message)) = ws.next().await {
                    if message.is_close() {
                        let _ = ws.close(None).await;
                        break;
                    }
                    ws.send(message).await.unwrap();
                }
            });
            Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(header::CONNECTION, "Upgrade")
                .header(header::UPGRADE, "websocket")
                .header("sec-websocket-accept", accept)
                .body(Body::empty())
                .unwrap()
        });
        let (upstream, upstream_task) = start(router).await;
        let (url, task) = forward_to(&format!("http://{upstream}")).await;
        let (mut ws, _) = connect_async(format!("{}/websocket", url.replacen("http", "ws", 1)))
            .await
            .unwrap();
        let payload = Message::Binary(vec![7; 256 * 1024].into());
        ws.send(payload.clone()).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            payload
        );
        ws.close(None).await.unwrap();
        task.abort();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn redirects_are_returned_without_following_to_other_hosts() {
        let router = Router::new().fallback(|request: Request| async move {
            assert_eq!(request.uri(), "/proxy");
            (
                StatusCode::FOUND,
                [(header::LOCATION, "https://external.invalid/login")],
            )
        });
        let (upstream, upstream_task) = start(router).await;
        let (url, task) = forward_to(&format!("http://{upstream}")).await;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let response = http.get(url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://external.invalid/login"
        );
        task.abort();
        upstream_task.abort();
    }
}
