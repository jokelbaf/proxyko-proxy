use anyhow::{Context, Result};
use bytes::Bytes;
use cidr::IpCidr;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use wildmatch::WildMatch;

static CONFIG: Lazy<Config> = Lazy::new(|| Config::from_env().expect("Failed to load config"));
static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(60))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to create HTTP client")
});

#[derive(Debug, Clone)]
struct Config {
    proxy_host: String,
    proxy_port: u16,
    internal_api_key: String,
    proxyko_host: String,
    proxyko_port: u16,
}

impl Config {
    fn from_env() -> Result<Self> {
        Ok(Config {
            proxy_host: std::env::var("HOST").context("HOST not set")?,
            proxy_port: std::env::var("PORT")
                .context("PORT not set")?
                .parse()
                .context("Invalid PORT")?,
            internal_api_key: std::env::var("INTERNAL_API_KEY")
                .context("INTERNAL_API_KEY not set")?,
            proxyko_host: std::env::var("PROXYKO_HOST").context("PROXYKO_HOST not set")?,
            proxyko_port: std::env::var("PROXYKO_PORT")
                .context("PROXYKO_PORT not set")?
                .parse()
                .context("Invalid PROXYKO_PORT")?,
        })
    }

    fn api_base_url(&self) -> String {
        format!("http://{}:{}", self.proxyko_host, self.proxyko_port)
    }
}

fn is_loopback_to_self(host: &str, _port: u16) -> bool {
    let is_same_host = if let Ok(target_ip) = IpAddr::from_str(host) {
        target_ip.is_loopback()
            || target_ip.is_unspecified()
            || IpAddr::from_str(&CONFIG.proxy_host).map_or(false, |our_ip| target_ip == our_ip)
    } else {
        let host_lower = host.to_lowercase();
        host_lower == "localhost" || host_lower == CONFIG.proxy_host.to_lowercase()
    };

    if !is_same_host {
        return false;
    }

    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProxyStatus {
    enabled: bool,
    require_auth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProxyRule {
    id: i64,
    name: String,
    priority: i32,
    is_enabled: bool,
    ip_filter: Option<String>,
    protocol_matches: Option<String>,
    host_matches: Option<String>,
    port_matches: Option<String>,
    path_matches: Option<String>,
    query_str_matches: Option<String>,
    forward_protocol: Option<String>,
    forward_host: Option<String>,
    forward_port: Option<i32>,
    action: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ApiResponse<T> {
    status: u16,
    message: String,
    data: T,
}

#[derive(Debug, Serialize, Deserialize)]
struct WebSocketMessage {
    action: String,
    message: Option<String>,
    data: Option<serde_json::Value>,
}

#[derive(Clone)]
struct ProxyState {
    status: Arc<RwLock<ProxyStatus>>,
    rules: Arc<RwLock<Vec<ProxyRule>>>,
}

impl ProxyState {
    fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(ProxyStatus {
                enabled: true,
                require_auth: false,
            })),
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    async fn fetch_rules(&self) -> Result<()> {
        let url = format!("{}/api/internal/proxy/rules", CONFIG.api_base_url());

        let response = HTTP_CLIENT
            .get(&url)
            .header("X-Internal-API-Key", &CONFIG.internal_api_key)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        let api_response: ApiResponse<Vec<ProxyRule>> = response.json().await?;
        let mut rules = api_response.data;
        rules.sort_by_key(|r| r.priority);
        info!("Loaded {} proxy rules", rules.len());
        *self.rules.write().await = rules;
        Ok(())
    }

    async fn websocket_loop(self) {
        loop {
            match self.connect_websocket().await {
                Ok(_) => {
                    warn!("WebSocket connection closed, reconnecting in 5 seconds...");
                }
                Err(e) => {
                    error!("WebSocket error: {}, reconnecting in 5 seconds...", e);
                }
            }
            time::sleep(Duration::from_secs(5)).await;
        }
    }

    async fn connect_websocket(&self) -> Result<()> {
        let ws_url = format!(
            "ws://{}:{}/api/internal/proxy/ws",
            CONFIG.proxyko_host, CONFIG.proxyko_port
        );

        info!("Connecting to WebSocket at {}", ws_url);

        let (ws_stream, _) = connect_async(&ws_url)
            .await
            .context("Failed to connect to WebSocket")?;

        info!("WebSocket connected, authenticating...");

        let (mut write, mut read) = ws_stream.split();

        let login_msg = WebSocketMessage {
            action: "login_req".to_string(),
            message: None,
            data: Some(serde_json::json!({
                "api_key": CONFIG.internal_api_key
            })),
        };

        write
            .send(Message::Text(serde_json::to_string(&login_msg)?.into()))
            .await
            .context("Failed to send login request")?;

        let mut heartbeat_interval = time::interval(Duration::from_secs(10));
        heartbeat_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                msg = read.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            if let Err(e) = self.handle_ws_message(&text).await {
                                error!("Failed to handle WebSocket message: {}", e);
                            }
                        }
                        Some(Ok(Message::Close(_))) => {
                            info!("WebSocket closed by server");
                            break;
                        }
                        Some(Err(e)) => {
                            error!("WebSocket read error: {}", e);
                            break;
                        }
                        None => {
                            warn!("WebSocket stream ended");
                            break;
                        }
                        _ => {}
                    }
                }
                _ = heartbeat_interval.tick() => {
                    let heartbeat_msg = WebSocketMessage {
                        action: "heartbeat_push".to_string(),
                        message: None,
                        data: None,
                    };

                    if let Err(e) = write.send(Message::Text(serde_json::to_string(&heartbeat_msg)?.into())).await {
                        error!("Failed to send heartbeat: {}", e);
                        break;
                    }
                    debug!("Heartbeat sent");
                }
            }
        }

        Ok(())
    }

    async fn handle_ws_message(&self, text: &str) -> Result<()> {
        let msg: WebSocketMessage =
            serde_json::from_str(text).context("Failed to parse WebSocket message")?;

        match msg.action.as_str() {
            "login_res" => {
                info!("WebSocket authentication successful");
            }
            "status_notify" => {
                if let Some(data) = msg.data {
                    let status: ProxyStatus =
                        serde_json::from_value(data).context("Failed to parse status data")?;
                    info!(
                        "Status updated: enabled={}, require_auth={}",
                        status.enabled, status.require_auth
                    );
                    *self.status.write().await = status;
                }
            }
            "rules_notify" => {
                if let Some(data) = msg.data {
                    let mut rules: Vec<ProxyRule> =
                        serde_json::from_value(data).context("Failed to parse rules data")?;
                    rules.sort_by_key(|r| r.priority);
                    info!("Rules updated: {} rules loaded", rules.len());
                    *self.rules.write().await = rules;
                }
            }
            "error" => {
                error!("WebSocket error: {:?}", msg.message);
            }
            _ => {
                warn!("Unknown WebSocket action: {}", msg.action);
            }
        }

        Ok(())
    }
}

struct RequestContext {
    client_ip: IpAddr,
    protocol: String,
    host: Option<String>,
    port: u16,
    path: Option<String>,
    query_str: Option<String>,
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-connection"
    )
}

impl RequestContext {
    fn matches_rule(&self, rule: &ProxyRule) -> bool {
        if let Some(ref ip_filter) = rule.ip_filter
            && !self.matches_ip_filter(ip_filter)
        {
            return false;
        }

        if let Some(ref protocol) = rule.protocol_matches
            && !protocol.eq_ignore_ascii_case(&self.protocol)
        {
            return false;
        }

        if let Some(ref host_pattern) = rule.host_matches {
            if let Some(ref host) = self.host {
                if !WildMatch::new(host_pattern).matches(host) {
                    return false;
                }
            } else {
                return false;
            }
        }

        if let Some(ref port_pattern) = rule.port_matches
            && !self.matches_port(port_pattern)
        {
            return false;
        }

        if let Some(ref path_pattern) = rule.path_matches {
            if let Some(ref path) = self.path {
                if !WildMatch::new(path_pattern).matches(path) {
                    return false;
                }
            } else {
                return false;
            }
        }

        if let Some(ref query_pattern) = rule.query_str_matches {
            if let Some(ref query) = self.query_str {
                if !WildMatch::new(query_pattern).matches(query) {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }

    fn matches_ip_filter(&self, filter: &str) -> bool {
        for entry in filter.split(',') {
            let entry = entry.trim();
            if entry.contains('/') {
                if let Ok(cidr) = IpCidr::from_str(entry)
                    && cidr.contains(&self.client_ip)
                {
                    return true;
                }
            } else if let Ok(ip) = IpAddr::from_str(entry)
                && ip == self.client_ip
            {
                return true;
            }
        }
        false
    }

    fn matches_port(&self, pattern: &str) -> bool {
        for entry in pattern.split(',') {
            let entry = entry.trim();
            if entry.contains('-') {
                if let Some((start, end)) = entry.split_once('-')
                    && let (Ok(start), Ok(end)) = (start.parse::<u16>(), end.parse::<u16>())
                    && self.port >= start
                    && self.port <= end
                {
                    return true;
                }
            } else if let Ok(port) = entry.parse::<u16>()
                && self.port == port
            {
                return true;
            }
        }
        false
    }
}

async fn handle_connection(
    stream: TcpStream,
    client_addr: SocketAddr,
    state: ProxyState,
) -> Result<()> {
    let mut buffer = vec![0u8; 1024];

    stream.set_nodelay(true)?;

    let n = match tokio::time::timeout(Duration::from_secs(3), stream.peek(&mut buffer)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()),
    };

    if n == 0 {
        return Ok(());
    }

    let is_http = buffer[..n].starts_with(b"GET ")
        || buffer[..n].starts_with(b"POST ")
        || buffer[..n].starts_with(b"PUT ")
        || buffer[..n].starts_with(b"DELETE ")
        || buffer[..n].starts_with(b"HEAD ")
        || buffer[..n].starts_with(b"OPTIONS ")
        || buffer[..n].starts_with(b"PATCH ")
        || buffer[..n].starts_with(b"CONNECT ");

    if is_http {
        let io = TokioIo::new(stream);
        let service = service_fn(|req| {
            let state = state.clone();
            async move { handle_http_request(req, client_addr, state).await }
        });

        let _ = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(io, service)
            .with_upgrades()
            .await;
    } else {
        handle_tcp_tunnel(stream, client_addr, state).await?;
    }

    Ok(())
}

async fn handle_http_request(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    state: ProxyState,
) -> Result<Response<Full<Bytes>>> {
    let status = state.status.read().await;
    if !status.enabled {
        return Ok(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Full::new(Bytes::from("Proxy disabled")))?);
    }
    drop(status);

    if req.method() == Method::CONNECT {
        return handle_https_connect(req, client_addr, state).await;
    }

    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let uri = req.uri();
    let port = uri
        .port_u16()
        .or_else(|| {
            if uri.scheme_str() == Some("https") {
                Some(443)
            } else {
                Some(80)
            }
        })
        .unwrap_or(80);

    let path = uri.path().to_string();
    let query_str = uri.query().map(|s| s.to_string());

    let ctx = RequestContext {
        client_ip: client_addr.ip(),
        protocol: "http".to_string(),
        host: host.clone(),
        port,
        path: Some(path),
        query_str,
    };

    let rules = state.rules.read().await;
    let matching_rule = rules.iter().find(|rule| rule.is_enabled && ctx.matches_rule(rule));

    if let Some(rule) = matching_rule {
        debug!(
            "HTTP request from {} to {}:{}{} matched rule '{}' (action: {})",
            client_addr.ip(),
            ctx.host.as_deref().unwrap_or("unknown"),
            ctx.port,
            ctx.path.as_deref().unwrap_or(""),
            rule.name,
            rule.action
        );

        match rule.action.as_str() {
            "BLOCK" => {
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Full::new(Bytes::from("Blocked by proxy rule")))?);
            }
            "FORWARD" => {
                return proxy_http_via_forward(req, rule).await;
            }
            _ => {}
        }
    } else {
        debug!(
            "HTTP request from {} to {}:{}{} - no matching rule, proxying directly",
            client_addr.ip(),
            ctx.host.as_deref().unwrap_or("unknown"),
            ctx.port,
            ctx.path.as_deref().unwrap_or("")
        );
    }
    drop(rules);

    proxy_http_direct(req).await
}

async fn proxy_http_direct(req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    let body_bytes = req.collect().await?.to_bytes();

    let scheme = uri.scheme_str().unwrap_or("http");
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    let (host_name, port) = if let Some((h, p)) = host.split_once(':') {
        (
            h,
            p.parse()
                .unwrap_or(if scheme == "https" { 443 } else { 80 }),
        )
    } else {
        (host, if scheme == "https" { 443 } else { 80 })
    };

    if is_loopback_to_self(host_name, port) {
        warn!("Blocked loop-back attempt to {}:{}", host_name, port);
        return Err(anyhow::anyhow!("Loop-back to proxy detected"));
    }

    let absolute_url = if uri.path_and_query().is_some() {
        format!("{}://{}{}", scheme, host, uri.path_and_query().unwrap())
    } else {
        format!("{}://{}/", scheme, host)
    };

    let mut request_builder = HTTP_CLIENT.request(method.as_str().parse()?, &absolute_url);

    for (name, value) in headers.iter() {
        if !is_hop_by_hop_header(name.as_str()) && name != "host" {
            request_builder = request_builder.header(name.as_str(), value.as_bytes());
        }
    }

    request_builder = request_builder.body(body_bytes.to_vec());

    let response = request_builder.send().await?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let response_body = response.bytes().await?;

    let mut builder = Response::builder().status(status.as_u16());

    for (name, value) in response_headers.iter() {
        builder = builder.header(name.as_str(), value.as_bytes());
    }

    Ok(builder.body(Full::new(response_body))?)
}

async fn proxy_http_via_forward(
    req: Request<Incoming>,
    rule: &ProxyRule,
) -> Result<Response<Full<Bytes>>> {
    let forward_host = rule
        .forward_host
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Forward rule missing forward_host"))?;
    let forward_port = rule
        .forward_port
        .ok_or_else(|| anyhow::anyhow!("Forward rule missing forward_port"))?;
    let forward_protocol = rule.forward_protocol.as_deref().unwrap_or("http");

    if is_loopback_to_self(forward_host, forward_port as u16) {
        warn!(
            "Blocked loop-back attempt: forward rule '{}' points to self ({}:{})",
            rule.name, forward_host, forward_port
        );
        return Err(anyhow::anyhow!(
            "Forward rule would create loop-back to proxy"
        ));
    }

    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let body_bytes = req.collect().await?.to_bytes();

    let scheme = uri.scheme_str().unwrap_or("http");
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    let absolute_url = if uri.path_and_query().is_some() {
        format!("{}://{}{}", scheme, host, uri.path_and_query().unwrap())
    } else {
        format!("{}://{}/", scheme, host)
    };

    debug!(
        "Forwarding HTTP request to proxy {}://{}:{} for URL: {}",
        forward_protocol, forward_host, forward_port, absolute_url
    );

    let proxy_url = format!(
        "{}://{}:{}{}",
        forward_protocol,
        forward_host,
        forward_port,
        if absolute_url.starts_with("http") {
            ""
        } else {
            "/"
        }
    );

    if forward_protocol == "https" || forward_protocol == "http" {
        let proxy = reqwest::Proxy::all(&proxy_url).context("Invalid proxy URL")?;

        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to create proxied HTTP client")?;

        let mut request_builder = client.request(method.as_str().parse()?, &absolute_url);

        for (name, value) in headers.iter() {
            if !is_hop_by_hop_header(name.as_str()) && name != "host" {
                request_builder = request_builder.header(name.as_str(), value.as_bytes());
            }
        }

        request_builder = request_builder.body(body_bytes.to_vec());

        let response = request_builder
            .send()
            .await
            .context("Failed to send request through proxy")?;

        let status = response.status();
        let response_headers = response.headers().clone();
        let response_body = response.bytes().await?;

        let mut builder = Response::builder().status(status.as_u16());

        for (name, value) in response_headers.iter() {
            builder = builder.header(name.as_str(), value.as_bytes());
        }

        return Ok(builder.body(Full::new(response_body))?);
    }

    let proxy_addr = format!("{}:{}", forward_host, forward_port);
    let mut proxy_stream =
        tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&proxy_addr))
            .await
            .context("Timeout connecting to forward proxy")?
            .context("Failed to connect to forward proxy")?;

    let _ = proxy_stream.set_nodelay(true);

    let mut request_data = format!("{} {} HTTP/1.1\r\n", method, absolute_url);

    for (name, value) in headers.iter() {
        if let Ok(value_str) = value.to_str() {
            request_data.push_str(&format!("{}: {}\r\n", name, value_str));
        }
    }

    if !headers.contains_key("connection") {
        request_data.push_str("Connection: close\r\n");
    }

    request_data.push_str("\r\n");

    proxy_stream.write_all(request_data.as_bytes()).await?;

    if !body_bytes.is_empty() {
        proxy_stream.write_all(&body_bytes).await?;
    }

    let mut response_headers_raw = Vec::new();
    let mut buffer = [0u8; 4096];

    loop {
        if response_headers_raw.len() >= 65536 {
            break;
        }
        match tokio::time::timeout(Duration::from_secs(30), proxy_stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                response_headers_raw.extend_from_slice(&buffer[..n]);
                if let Some(pos) = response_headers_raw
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                {
                    response_headers_raw.truncate(pos + 4);
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "Timeout reading response from forward proxy"
                ));
            }
        }
    }

    let response_str = String::from_utf8_lossy(&response_headers_raw);
    let mut lines = response_str.lines();

    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("Empty response from proxy"))?;

    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(502);

    let mut response_builder = Response::builder().status(status_code);

    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            let name_lower = name.trim().to_lowercase();
            if name_lower != "connection"
                && name_lower != "transfer-encoding"
                && name_lower != "proxy-connection"
            {
                response_builder = response_builder.header(name.trim(), value);
            }
        }
    }

    let mut response_body = Vec::new();
    let _ = proxy_stream.read_to_end(&mut response_body).await;

    Ok(response_builder.body(Full::new(Bytes::from(response_body)))?)
}

async fn establish_proxy_tunnel(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
) -> Result<()> {
    let connect_request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        target_host, target_port, target_host, target_port
    );

    stream
        .write_all(connect_request.as_bytes())
        .await
        .context("Failed to send CONNECT request to proxy")?;

    let mut response = Vec::new();
    let mut header_end_found = false;

    while !header_end_found && response.len() < 8192 {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut byte)).await {
            Ok(Ok(_)) => {
                response.push(byte[0]);

                let len = response.len();
                if len >= 4 && &response[len - 4..] == b"\r\n\r\n" {
                    header_end_found = true;
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow::anyhow!("Timeout reading proxy response")),
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    let status_line = response_str
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Empty proxy response"))?;

    if !status_line.contains("200") {
        return Err(anyhow::anyhow!("Proxy refused connection: {}", status_line));
    }

    Ok(())
}

async fn handle_https_connect(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    state: ProxyState,
) -> Result<Response<Full<Bytes>>> {
    let uri = req.uri();
    let host_port = uri.authority().map(|a| a.as_str()).unwrap_or("");

    let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
        (h.to_string(), p.parse().unwrap_or(443))
    } else {
        (host_port.to_string(), 443)
    };

    if is_loopback_to_self(&host, port) {
        warn!(
            "Blocked HTTPS CONNECT loop-back attempt from {} to {}:{}",
            client_addr.ip(),
            host,
            port
        );
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from("Loop-back to proxy detected")))?);
    }

    let ctx = RequestContext {
        client_ip: client_addr.ip(),
        protocol: "https".to_string(),
        host: Some(host.clone()),
        port,
        path: None,
        query_str: None,
    };

    let rules = state.rules.read().await;
    let matching_rule = rules.iter().find(|rule| rule.is_enabled && ctx.matches_rule(rule));

    enum ConnectMode {
        Direct(String),
        Forward {
            proxy_addr: String,
            target_host: String,
            target_port: u16,
        },
    }

    let mode = if let Some(rule) = matching_rule {
        debug!(
            "HTTPS CONNECT from {} to {}:{} matched rule '{}' (action: {})",
            client_addr.ip(),
            host,
            port,
            rule.name,
            rule.action
        );

        match rule.action.as_str() {
            "BLOCK" => {
                drop(rules);
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Full::new(Bytes::from("Blocked by proxy rule")))?);
            }
            "FORWARD" => {
                let forward_host = rule
                    .forward_host
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Forward rule missing forward_host"))?;
                let forward_port = rule
                    .forward_port
                    .ok_or_else(|| anyhow::anyhow!("Forward rule missing forward_port"))?;

                if is_loopback_to_self(forward_host, forward_port as u16) {
                    warn!(
                        "Blocked HTTPS CONNECT loop-back: forward rule '{}' points to self ({}:{})",
                        rule.name, forward_host, forward_port
                    );
                    drop(rules);
                    return Ok(Response::builder().status(StatusCode::FORBIDDEN).body(
                        Full::new(Bytes::from("Forward rule would create loop-back to proxy")),
                    )?);
                }

                debug!(
                    "Forwarding HTTPS CONNECT through proxy {}:{}",
                    forward_host, forward_port
                );
                ConnectMode::Forward {
                    proxy_addr: format!("{}:{}", forward_host, forward_port),
                    target_host: host.clone(),
                    target_port: port,
                }
            }
            _ => ConnectMode::Direct(format!("{}:{}", host, port)),
        }
    } else {
        debug!(
            "HTTPS CONNECT from {} to {}:{} - no matching rule, direct tunnel",
            client_addr.ip(),
            host,
            port
        );
        ConnectMode::Direct(format!("{}:{}", host, port))
    };
    drop(rules);

    let mut server_stream = match &mode {
        ConnectMode::Direct(target) => {
            match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(target)).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    stream
                }
                Ok(Err(e)) => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from(format!("Failed to connect: {}", e))))?);
                }
                Err(_) => {
                    return Ok(Response::builder()
                        .status(StatusCode::GATEWAY_TIMEOUT)
                        .body(Full::new(Bytes::from("Connection timeout")))?);
                }
            }
        }
        ConnectMode::Forward {
            proxy_addr,
            target_host,
            target_port,
        } => {
            let mut stream =
                match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(proxy_addr))
                    .await
                {
                    Ok(Ok(stream)) => {
                        let _ = stream.set_nodelay(true);
                        stream
                    }
                    Ok(Err(e)) => {
                        return Ok(Response::builder().status(StatusCode::BAD_GATEWAY).body(
                            Full::new(Bytes::from(format!("Failed to connect to proxy: {}", e))),
                        )?);
                    }
                    Err(_) => {
                        return Ok(Response::builder()
                            .status(StatusCode::GATEWAY_TIMEOUT)
                            .body(Full::new(Bytes::from("Proxy connection timeout")))?);
                    }
                };

            if let Err(e) = establish_proxy_tunnel(&mut stream, target_host, *target_port).await {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!(
                        "Proxy tunnel failed: {}",
                        e
                    ))))?);
            }

            debug!(
                "Successfully established tunnel through proxy to {}:{}",
                target_host, target_port
            );
            stream
        }
    };

    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client_stream = TokioIo::new(upgraded);
                let _ = tunnel_streams(&mut client_stream, &mut server_stream).await;
            }
            Err(e) => {
                error!("Failed to upgrade HTTPS connection: {}", e);
            }
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))?)
}

async fn handle_tcp_tunnel(
    mut client_stream: TcpStream,
    client_addr: SocketAddr,
    state: ProxyState,
) -> Result<()> {
    let mut buffer = vec![0u8; 1024];
    let n =
        match tokio::time::timeout(Duration::from_secs(3), client_stream.peek(&mut buffer)).await {
            Ok(Ok(n)) => n,
            _ => return Ok(()),
        };

    let host = extract_sni_hostname(&buffer[..n]);
    let port = host
        .as_ref()
        .and_then(|h| h.split(':').next_back())
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(443);

    if let Some(ref hostname) = host {
        if is_loopback_to_self(hostname, port) {
            warn!(
                "Blocked TCP tunnel loop-back attempt from {} to {}:{}",
                client_addr.ip(),
                hostname,
                port
            );
            return Ok(());
        }
    }

    let ctx = RequestContext {
        client_ip: client_addr.ip(),
        protocol: "tcp".to_string(),
        host: host.clone(),
        port,
        path: None,
        query_str: None,
    };

    let rules = state.rules.read().await;
    let matching_rule = rules.iter().find(|rule| rule.is_enabled && ctx.matches_rule(rule));

    enum TcpMode {
        Direct(String),
        Forward {
            proxy_addr: String,
            target_host: String,
            target_port: u16,
        },
    }

    let mode = if let Some(rule) = matching_rule {
        debug!(
            "TCP tunnel from {} to {}:{} matched rule '{}' (action: {})",
            client_addr.ip(),
            ctx.host.as_deref().unwrap_or("unknown"),
            ctx.port,
            rule.name,
            rule.action
        );

        match rule.action.as_str() {
            "BLOCK" => {
                drop(rules);
                return Ok(());
            }
            "FORWARD" => {
                let forward_host = match rule.forward_host.as_ref() {
                    Some(h) => h,
                    None => {
                        error!("Forward rule missing forward_host");
                        drop(rules);
                        return Ok(());
                    }
                };
                let forward_port = match rule.forward_port {
                    Some(p) => p,
                    None => {
                        error!("Forward rule missing forward_port");
                        drop(rules);
                        return Ok(());
                    }
                };

                if is_loopback_to_self(forward_host, forward_port as u16) {
                    warn!(
                        "Blocked TCP tunnel loop-back: forward rule '{}' points to self ({}:{})",
                        rule.name, forward_host, forward_port
                    );
                    drop(rules);
                    return Ok(());
                }

                let target_host = host.clone().unwrap_or_default();
                debug!(
                    "Forwarding TCP connection through proxy {}:{}",
                    forward_host, forward_port
                );
                TcpMode::Forward {
                    proxy_addr: format!("{}:{}", forward_host, forward_port),
                    target_host,
                    target_port: port,
                }
            }
            _ => {
                let target = host
                    .as_ref()
                    .map(|h| format!("{}:{}", h, port))
                    .unwrap_or_default();
                TcpMode::Direct(target)
            }
        }
    } else {
        debug!(
            "TCP tunnel from {} to {}:{} - no matching rule, direct tunnel",
            client_addr.ip(),
            ctx.host.as_deref().unwrap_or("unknown"),
            ctx.port
        );
        let target = host
            .as_ref()
            .map(|h| format!("{}:{}", h, port))
            .unwrap_or_default();
        TcpMode::Direct(target)
    };
    drop(rules);

    let mut server_stream = match mode {
        TcpMode::Direct(target) => {
            if target.is_empty() {
                debug!(
                    "TCP tunnel from {} - no SNI hostname extracted, dropping connection",
                    client_addr.ip()
                );
                return Ok(());
            }
            match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&target)).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    stream
                }
                Ok(Err(e)) => {
                    debug!(
                        "TCP tunnel from {} to {} failed: {}",
                        client_addr.ip(),
                        target,
                        e
                    );
                    return Ok(());
                }
                Err(_) => {
                    debug!(
                        "TCP tunnel from {} to {} timed out",
                        client_addr.ip(),
                        target
                    );
                    return Ok(());
                }
            }
        }
        TcpMode::Forward {
            proxy_addr,
            target_host,
            target_port,
        } => {
            let mut stream = match tokio::time::timeout(
                Duration::from_secs(10),
                TcpStream::connect(&proxy_addr),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    stream
                }
                _ => return Ok(()),
            };

            if let Err(e) = establish_proxy_tunnel(&mut stream, &target_host, target_port).await {
                error!("Failed to establish TCP tunnel through proxy: {}", e);
                return Ok(());
            }

            debug!(
                "Successfully established TCP tunnel through proxy to {}:{}",
                target_host, target_port
            );
            stream
        }
    };

    let _ = tunnel_streams(&mut client_stream, &mut server_stream).await;

    Ok(())
}

async fn tunnel_streams<C, S>(client: &mut C, server: &mut S) -> Result<()>
where
    C: AsyncReadExt + AsyncWriteExt + Unpin,
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut server_read, mut server_write) = tokio::io::split(server);

    let client_to_server = async {
        let result = tokio::io::copy(&mut client_read, &mut server_write).await;
        let _ = server_write.shutdown().await;
        result
    };

    let server_to_client = async {
        let result = tokio::io::copy(&mut server_read, &mut client_write).await;
        let _ = client_write.shutdown().await;
        result
    };

    let _ = tokio::join!(client_to_server, server_to_client);

    Ok(())
}

fn extract_sni_hostname(data: &[u8]) -> Option<String> {
    if data.len() < 43 || data[0] != 0x16 {
        return None;
    }

    let mut pos = 43;

    if pos + 1 > data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if pos + 1 > data.len() {
        return None;
    }
    let compression_methods_len = data[pos] as usize;
    pos += 1 + compression_methods_len;

    if pos + 2 > data.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;

    while pos + 4 <= extensions_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > data.len() || pos + ext_len > extensions_end {
            return None;
        }

        if ext_type == 0 {
            if pos + 2 > data.len() {
                return None;
            }
            pos += 2;

            if pos + 3 > data.len() {
                return None;
            }
            let name_type = data[pos];
            let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
            pos += 3;

            if name_type == 0 && pos + name_len <= data.len() {
                let hostname = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
                return Some(hostname);
            }
        } else {
            pos += ext_len;
        }
    }

    None
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init();

    let config = &*CONFIG;
    info!(
        "Starting proxy server on {}:{}",
        config.proxy_host, config.proxy_port
    );

    let state = ProxyState::new();

    info!("Fetching initial proxy rules...");
    state.fetch_rules().await?;

    let ws_state = state.clone();
    tokio::spawn(async move {
        ws_state.websocket_loop().await;
    });

    let addr: SocketAddr = format!("{}:{}", config.proxy_host, config.proxy_port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("Proxy server listening on {}", addr);

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal, closing proxy server...");
        }
        _ = async {
            loop {
                match listener.accept().await {
                    Ok((stream, client_addr)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            let _ = handle_connection(stream, client_addr, state).await;
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        } => {}
    }

    Ok(())
}
