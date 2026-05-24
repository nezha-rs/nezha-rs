use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Component, Path as FsPath, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{
        Path, Query, Request, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use nezha_core::TaskType;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    DashboardState, OnlineUser, frontend, i18n,
    store::{
        CycleTransferStats, DashboardSettings, NatResource, OAuth2Config, ProfileResource,
        PublicServer, ServerGroupResource, Store,
    },
};

const SWAGGER_DOC_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/swagger-doc.json"));
const SWAGGER_UI_BUNDLE_JS: &[u8] = include_bytes!("../swagger-ui/swagger-ui-bundle.js");
const SWAGGER_UI_STANDALONE_PRESET_JS: &[u8] =
    include_bytes!("../swagger-ui/swagger-ui-standalone-preset.js");
const SWAGGER_UI_CSS: &[u8] = include_bytes!("../swagger-ui/swagger-ui.css");
const SWAGGER_FAVICON_16: &[u8] = include_bytes!("../swagger-ui/favicon-16x16.png");
const SWAGGER_FAVICON_32: &[u8] = include_bytes!("../swagger-ui/favicon-32x32.png");
const UPSTREAM_WAF_HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../upstream/nezha/cmd/dashboard/controller/waf/waf.html"
));
const SWAGGER_INDEX_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nezha Swagger UI</title>
  <link rel="stylesheet" href="./swagger-ui.css">
  <link rel="icon" type="image/png" sizes="32x32" href="./favicon-32x32.png">
  <link rel="icon" type="image/png" sizes="16x16" href="./favicon-16x16.png">
  <style>
    html { box-sizing: border-box; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="./swagger-ui-bundle.js"></script>
  <script src="./swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function () {
      window.ui = SwaggerUIBundle({
        url: "./doc.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>
"##;

#[derive(Debug, Clone)]
pub struct HttpState {
    pub dashboard: Arc<DashboardState>,
    pub jwt_secret: String,
    pub jwt_timeout_hours: u64,
    pub site_name: String,
    pub debug: bool,
    pub force_auth: bool,
    pub agent_tls: bool,
    pub install_host: String,
    pub static_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
    expire: String,
}

#[derive(Debug, Deserialize)]
struct SettingPatch {
    language: Option<String>,
    site_name: Option<String>,
    custom_code: Option<String>,
    custom_code_dashboard: Option<String>,
    install_host: Option<String>,
    tls: Option<bool>,
    dns_servers: Option<String>,
    ignored_ip_notification: Option<String>,
    ip_change_notification_group_id: Option<u64>,
    cover: Option<u8>,
    web_real_ip_header: Option<String>,
    agent_real_ip_header: Option<String>,
    user_template: Option<String>,
    enable_ip_change_notification: Option<bool>,
    enable_plain_ip_in_notification: Option<bool>,
    oauth2: Option<HashMap<String, OAuth2Config>>,
}

#[derive(Debug, Serialize)]
struct SettingResponse {
    config: Value,
    #[serde(skip_serializing_if = "String::is_empty")]
    version: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    frontend_templates: Vec<frontend::FrontendTemplate>,
    tsdb_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct NotificationGroupRequest {
    name: String,
    #[serde(default)]
    notifications: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct ServerGroupRequest {
    name: String,
    #[serde(default)]
    servers: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct BatchDeleteRequest {
    ids: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct ProfileRequest {
    original_password: String,
    new_username: String,
    new_password: String,
    #[serde(default)]
    reject_password: bool,
}

#[derive(Debug, Deserialize)]
struct UserRequest {
    username: String,
    password: String,
    role: u8,
}

#[derive(Debug, Deserialize)]
struct BatchMoveRequest {
    ids: Vec<u64>,
    to_user: u64,
}

#[derive(Debug, Deserialize)]
struct TerminalRequest {
    server_id: u64,
}

#[derive(Debug, Serialize)]
struct CreateTerminalResponse {
    session_id: String,
    server_id: u64,
    server_name: String,
}

#[derive(Debug, Serialize)]
struct CreateFmResponse {
    session_id: String,
}

#[derive(Debug, Deserialize)]
struct PageQuery {
    limit: Option<u64>,
    offset: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ServerTaskResponse {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    success: Vec<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    failure: Vec<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    offline: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct StreamServerData<T>
where
    T: Serialize,
{
    now: u64,
    online: u64,
    servers: Vec<T>,
}

#[derive(Debug, Serialize)]
struct ServerMetricsResponse {
    server_id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    server_name: String,
    metric: String,
    data_points: Vec<crate::store::ServerMetricPoint>,
}

#[derive(Debug, Deserialize)]
struct OAuth2RedirectQuery {
    #[serde(default = "default_oauth2_login_type", rename = "type")]
    r#type: u8,
}

#[derive(Debug, Serialize)]
struct OAuth2RedirectResponse {
    redirect: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OAuth2StateClaims {
    action: u8,
    provider: String,
    state: String,
    redirect_url: String,
    exp: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    uid: u64,
    username: String,
    role: u8,
    exp: usize,
}

#[derive(Debug, Serialize)]
struct CommonResponse<T>
where
    T: Serialize,
{
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct PaginatedResponse<T>
where
    T: Serialize,
{
    value: T,
    pagination: Pagination,
}

#[derive(Debug, Serialize)]
struct Pagination {
    offset: u64,
    limit: u64,
    total: u64,
}

impl<T> CommonResponse<T>
where
    T: Serialize,
{
    fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn err(error: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error.into()),
        }
    }
}

pub fn router(state: HttpState) -> Router {
    let mut router = Router::new()
        .route("/api/v1/login", post(login))
        .route("/api/v1/oauth2/callback", get(oauth2_callback))
        .route("/api/v1/oauth2/{provider}", get(oauth2_redirect))
        .route("/api/v1/oauth2/{provider}/unbind", post(unbind_oauth2))
        .route("/api/v1/setting", get(setting).patch(update_setting))
        .route("/api/v1/refresh-token", get(refresh_token))
        .route("/api/v1/terminal", post(create_terminal))
        .route("/api/v1/ws/terminal/{id}", get(terminal_stream))
        .route("/api/v1/file", get(create_file_manager))
        .route("/api/v1/ws/file/{id}", get(file_manager_stream))
        .route("/api/v1/profile", get(get_profile).post(update_profile))
        .route("/api/v1/user", get(list_users).post(create_user))
        .route("/api/v1/ws/server", get(server_stream))
        .route("/api/v1/batch-delete/user", post(batch_delete_user))
        .route("/api/v1/server", get(list_servers))
        .route("/api/v1/server/{id}", patch(update_server))
        .route("/api/v1/batch-delete/server", post(batch_delete_server))
        .route("/api/v1/batch-move/server", post(batch_move_server))
        .route("/api/v1/force-update/server", post(force_update_server))
        .route("/api/v1/server/config/{id}", get(get_server_config))
        .route("/api/v1/server/config", post(set_server_config))
        .route(
            "/api/v1/server-group",
            get(list_server_groups).post(create_server_group),
        )
        .route("/api/v1/server-group/{id}", patch(update_server_group))
        .route(
            "/api/v1/batch-delete/server-group",
            post(batch_delete_server_group),
        )
        .route(
            "/api/v1/notification",
            get(list_notifications).post(create_notification),
        )
        .route("/api/v1/notification/{id}", patch(update_notification))
        .route(
            "/api/v1/batch-delete/notification",
            post(batch_delete_notification),
        )
        .route(
            "/api/v1/notification-group",
            get(list_notification_groups).post(create_notification_group),
        )
        .route(
            "/api/v1/notification-group/{id}",
            patch(update_notification_group),
        )
        .route(
            "/api/v1/batch-delete/notification-group",
            post(batch_delete_notification_group),
        )
        .route("/api/v1/service", get(show_service).post(create_service))
        .route("/api/v1/service/list", get(list_services))
        .route("/api/v1/service/server", get(list_service_servers))
        .route("/api/v1/service/{id}", patch(update_service))
        .route("/api/v1/service/{id}/history", get(get_service_history))
        .route("/api/v1/server/{id}/service", get(list_server_services))
        .route("/api/v1/server/{id}/metrics", get(get_server_metrics))
        .route("/api/v1/batch-delete/service", post(batch_delete_service))
        .route(
            "/api/v1/alert-rule",
            get(list_alert_rules).post(create_alert_rule),
        )
        .route("/api/v1/alert-rule/{id}", patch(update_alert_rule))
        .route(
            "/api/v1/batch-delete/alert-rule",
            post(batch_delete_alert_rule),
        )
        .route("/api/v1/cron", get(list_crons).post(create_cron))
        .route("/api/v1/cron/{id}", patch(update_cron))
        .route("/api/v1/cron/{id}/manual", get(manual_trigger_cron))
        .route("/api/v1/batch-delete/cron", post(batch_delete_cron))
        .route("/api/v1/ddns", get(list_ddns).post(create_ddns))
        .route("/api/v1/ddns/providers", get(list_ddns_providers))
        .route("/api/v1/ddns/{id}", patch(update_ddns))
        .route("/api/v1/batch-delete/ddns", post(batch_delete_ddns))
        .route("/api/v1/nat", get(list_nat).post(create_nat))
        .route("/api/v1/nat/{id}", patch(update_nat))
        .route("/api/v1/batch-delete/nat", post(batch_delete_nat))
        .route("/api/v1/waf", get(list_waf))
        .route("/api/v1/batch-delete/waf", post(batch_delete_waf))
        .route("/api/v1/online-user", get(list_online_users))
        .route(
            "/api/v1/online-user/batch-block",
            post(batch_block_online_user),
        )
        .route("/api/v1/maintenance", post(run_maintenance));

    if state.debug {
        router = router
            .route("/swagger", get(swagger_root))
            .route("/swagger/{*path}", get(swagger_asset));
    }

    router
        .fallback(frontend_fallback)
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, waf_middleware))
}

async fn swagger_root() -> impl IntoResponse {
    (
        StatusCode::MOVED_PERMANENTLY,
        [(header::LOCATION, "/swagger/index.html")],
        Body::empty(),
    )
        .into_response()
}

async fn swagger_asset(Path(path): Path<String>) -> Response {
    swagger_response(path.trim_start_matches('/'))
}

fn swagger_response(path: &str) -> Response {
    match path {
        "" | "index.html" => bytes_response(
            StatusCode::OK,
            "text/html; charset=utf-8",
            SWAGGER_INDEX_HTML.as_bytes().to_vec(),
        ),
        "doc.json" => bytes_response(
            StatusCode::OK,
            "application/json; charset=utf-8",
            SWAGGER_DOC_JSON.as_bytes().to_vec(),
        ),
        "swagger-ui.css" => bytes_response(
            StatusCode::OK,
            "text/css; charset=utf-8",
            SWAGGER_UI_CSS.to_vec(),
        ),
        "swagger-ui-bundle.js" => bytes_response(
            StatusCode::OK,
            "text/javascript; charset=utf-8",
            SWAGGER_UI_BUNDLE_JS.to_vec(),
        ),
        "swagger-ui-standalone-preset.js" => bytes_response(
            StatusCode::OK,
            "text/javascript; charset=utf-8",
            SWAGGER_UI_STANDALONE_PRESET_JS.to_vec(),
        ),
        "favicon-16x16.png" => {
            bytes_response(StatusCode::OK, "image/png", SWAGGER_FAVICON_16.to_vec())
        }
        "favicon-32x32.png" => {
            bytes_response(StatusCode::OK, "image/png", SWAGGER_FAVICON_32.to_vec())
        }
        _ => api_error(StatusCode::NOT_FOUND, "404 Not Found"),
    }
}

fn bytes_response(status: StatusCode, content_type: &'static str, bytes: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(bytes))
        .unwrap_or_else(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
}

async fn frontend_fallback(State(state): State<HttpState>, request: Request) -> Response {
    let request_path = request.uri().path();
    if request_path.starts_with("/api") {
        return api_error(StatusCode::NOT_FOUND, "404 Not Found");
    }
    if let Some(nat) = nat_for_request(&state, request.headers()) {
        return serve_nat_request(state, request, nat).await;
    }
    if request_path == "/dashboard" {
        return (
            StatusCode::MOVED_PERMANENTLY,
            [(header::LOCATION, "/dashboard/")],
            Body::empty(),
        )
            .into_response();
    }

    let settings = load_settings(&state).unwrap_or_else(|_| settings_from_state_defaults(&state));
    let fallback_status = frontend_fallback_status(request_path);
    let (template, stripped_path) = if request_path.starts_with("/dashboard") {
        (
            admin_template(&settings),
            request_path.trim_start_matches("/dashboard"),
        )
    } else {
        (user_template(&settings), request_path)
    };

    for path in frontend_file_paths(&state.static_dir, template, stripped_path) {
        if let Some(response) = serve_static_file(path, StatusCode::OK).await {
            return response;
        }
    }
    if let Some(response) =
        serve_embedded_frontend_file(&frontend_asset_key(template, stripped_path), StatusCode::OK)
    {
        return response;
    }

    for path in frontend_file_paths(&state.static_dir, template, "/index.html") {
        if let Some(response) = serve_static_file(path, fallback_status).await {
            return response;
        }
    }

    serve_embedded_frontend_file(
        &frontend_asset_key(template, "/index.html"),
        fallback_status,
    )
    .unwrap_or_else(|| api_error(StatusCode::NOT_FOUND, "404 Not Found"))
}

fn nat_for_request(state: &HttpState, headers: &HeaderMap) -> Option<NatResource> {
    let host = headers.get(header::HOST)?.to_str().ok()?.trim();
    if host.is_empty() {
        return None;
    }
    let host_without_port = host
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|ch| ch.is_ascii_digit()))
        .map(|(host, _)| host)
        .unwrap_or(host);
    let store = state.dashboard.store.lock().ok()?;
    let nat_list = store.list_nat().ok()?;
    nat_list
        .iter()
        .find(|nat| nat.domain.eq_ignore_ascii_case(host))
        .cloned()
        .or_else(|| {
            nat_list
                .into_iter()
                .find(|nat| nat.domain.eq_ignore_ascii_case(host_without_port))
        })
}

async fn serve_nat_request(state: HttpState, request: Request, nat: NatResource) -> Response {
    if !nat.enabled {
        return waf_block_response(&format!("nat host {} is disabled", nat.domain));
    }

    let stream_id = uuid::Uuid::new_v4().to_string();
    state
        .dashboard
        .io_streams
        .create_stream(stream_id.clone(), 0, nat.server_id)
        .await;
    let payload = serde_json::json!({
        "StreamID": stream_id,
        "Host": nat.host,
    })
    .to_string();
    if !state
        .dashboard
        .dispatch_task(nat.server_id, TaskType::Nat, payload)
        .await
    {
        state.dashboard.io_streams.close_stream(&stream_id).await;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "server not found or not connected",
        )
            .into_response();
    }

    let Some(session) = state.dashboard.io_streams.get_stream(&stream_id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, "nat stream disappeared").into_response();
    };
    let Some(mut response_rx) = session.take_user_receiver().await else {
        state.dashboard.io_streams.close_stream(&stream_id).await;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "nat stream receiver unavailable",
        )
            .into_response();
    };

    let raw_request = match nat_request_bytes(request).await {
        Ok(raw) => raw,
        Err(err) => {
            state.dashboard.io_streams.close_stream(&stream_id).await;
            return (
                StatusCode::BAD_REQUEST,
                format!("request wrapper error: {err}"),
            )
                .into_response();
        }
    };
    if session.send_to_agent(raw_request).await.is_err() {
        state.dashboard.io_streams.close_stream(&stream_id).await;
        return (StatusCode::SERVICE_UNAVAILABLE, "nat stream send failed").into_response();
    }

    let parsed = match read_nat_response_head(&mut response_rx).await {
        Ok(parsed) => parsed,
        Err(err) => {
            state.dashboard.io_streams.close_stream(&stream_id).await;
            return (StatusCode::BAD_GATEWAY, err).into_response();
        }
    };
    let dashboard = state.dashboard.clone();
    let stream_id_for_body = stream_id.clone();
    let body = Body::from_stream(async_stream::stream! {
        if !parsed.body_prefix.is_empty() {
            yield Ok::<Bytes, std::io::Error>(Bytes::from(parsed.body_prefix));
        }
        while let Some(data) = response_rx.recv().await {
            if !data.is_empty() {
                yield Ok(Bytes::from(data));
            }
        }
        dashboard.io_streams.close_stream(&stream_id_for_body).await;
    });

    let mut builder = Response::builder().status(parsed.status);
    for (name, value) in parsed.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(body)
        .unwrap_or_else(|_| api_error(StatusCode::BAD_GATEWAY, "invalid nat response"))
}

async fn nat_request_bytes(request: Request) -> Result<Vec<u8>> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, usize::MAX)
        .await
        .context("failed to read request body")?;
    let path = parts
        .uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/");
    let mut raw = format!("{} {} HTTP/1.1\r\n", parts.method, path).into_bytes();
    let mut has_host = false;
    let mut has_content_length = false;
    for (name, value) in &parts.headers {
        if name == header::HOST {
            has_host = true;
        }
        if name == header::CONTENT_LENGTH {
            has_content_length = true;
        }
        raw.extend_from_slice(name.as_str().as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(value.as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    if !has_host && let Some(authority) = parts.uri.authority() {
        raw.extend_from_slice(b"Host: ");
        raw.extend_from_slice(authority.as_str().as_bytes());
        raw.extend_from_slice(b"\r\n");
    }
    if !body.is_empty() && !has_content_length {
        raw.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(&body);
    Ok(raw)
}

struct ParsedNatResponse {
    status: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
    body_prefix: Vec<u8>,
}

async fn read_nat_response_head(
    rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> std::result::Result<ParsedNatResponse, String> {
    let mut buffer = Vec::new();
    loop {
        if let Some(index) = find_header_end(&buffer) {
            return parse_nat_response(buffer, index);
        }
        if buffer.len() > 64 * 1024 {
            return Err("nat response header too large".to_string());
        }
        let next = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .map_err(|_| "nat response timeout".to_string())?
            .ok_or_else(|| "nat response stream closed".to_string())?;
        buffer.extend_from_slice(&next);
    }
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_nat_response(
    mut buffer: Vec<u8>,
    header_end: usize,
) -> std::result::Result<ParsedNatResponse, String> {
    let body_prefix = buffer.split_off(header_end + 4);
    buffer.truncate(header_end);
    let header_text = String::from_utf8(buffer).map_err(|_| "invalid nat response header")?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| "missing nat response status".to_string())?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .and_then(|value| StatusCode::from_u16(value).ok())
        .ok_or_else(|| "invalid nat response status".to_string())?;
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let Ok(name) = HeaderName::from_bytes(name.trim().as_bytes()) else {
            continue;
        };
        if name == header::CONNECTION || name == header::TRANSFER_ENCODING {
            continue;
        }
        let Ok(value) = HeaderValue::from_str(value.trim()) else {
            continue;
        };
        headers.push((name, value));
    }
    Ok(ParsedNatResponse {
        status,
        headers,
        body_prefix,
    })
}

fn user_template(settings: &DashboardSettings) -> &str {
    if settings.user_template.trim().is_empty() {
        "user-dist"
    } else {
        settings.user_template.trim()
    }
}

fn admin_template(settings: &DashboardSettings) -> &str {
    if settings.admin_template.trim().is_empty() {
        "admin-dist"
    } else {
        settings.admin_template.trim()
    }
}

fn frontend_fallback_status(path: &str) -> StatusCode {
    if frontend_page_path(path) {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

fn frontend_page_path(path: &str) -> bool {
    matches!(
        path,
        "/" | "/dashboard/"
            | "/dashboard/login"
            | "/dashboard/service"
            | "/dashboard/cron"
            | "/dashboard/notification"
            | "/dashboard/alert-rule"
            | "/dashboard/ddns"
            | "/dashboard/nat"
            | "/dashboard/server-group"
            | "/dashboard/notification-group"
            | "/dashboard/profile"
            | "/dashboard/settings"
            | "/dashboard/settings/user"
            | "/dashboard/settings/online-user"
            | "/dashboard/settings/waf"
    ) || server_page_path(path)
}

fn server_page_path(path: &str) -> bool {
    let Some(id) = path.strip_prefix("/server/") else {
        return false;
    };
    !id.is_empty() && id.chars().all(|ch| ch.is_ascii_digit())
}

fn frontend_file_paths(static_dir: &FsPath, template: &str, request_path: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = frontend_file_path(FsPath::new(template), request_path) {
        candidates.push(path);
    }
    if let Some(path) = frontend_file_path(&static_dir.join(template), request_path)
        && !candidates.iter().any(|candidate| candidate == &path)
    {
        candidates.push(path);
    }
    candidates
}

fn frontend_file_path(base: &FsPath, request_path: &str) -> Option<PathBuf> {
    let mut path = base.to_path_buf();
    let relative = request_path.trim_start_matches('/');
    if relative.is_empty() {
        return Some(path);
    }

    for component in FsPath::new(relative).components() {
        match component {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(path)
}

fn frontend_asset_key(template: &str, request_path: &str) -> String {
    let relative = request_path.trim_start_matches('/');
    if relative.is_empty() {
        template.to_string()
    } else {
        format!("{template}/{relative}")
    }
}

async fn serve_static_file(path: PathBuf, status: StatusCode) -> Option<Response> {
    let metadata = tokio::fs::metadata(&path).await.ok()?;
    if !metadata.is_file() {
        return None;
    }
    let bytes = tokio::fs::read(&path).await.ok()?;
    let content_type = static_content_type(&path);
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(bytes))
        .ok()
}

fn serve_embedded_frontend_file(path: &str, status: StatusCode) -> Option<Response> {
    let bytes = frontend::embedded_asset(path)?;
    let content_type = static_content_type(FsPath::new(path));
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(bytes.to_vec()))
        .ok()
}

fn static_content_type(path: &FsPath) -> &'static str {
    match path.extension().and_then(|ext| ext.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

async fn waf_middleware(State(state): State<HttpState>, request: Request, next: Next) -> Response {
    let ip = match resolve_request_ip(&state, request.headers()) {
        Ok(ip) => ip,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    if let Some(ip) = ip {
        match state.dashboard.store.lock() {
            Ok(store) => match store.waf_block_active(&ip) {
                Ok(true) => return waf_block_response("you were blocked by nezha WAF"),
                Ok(false) => {}
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            },
            Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
        }
    }
    next.run(request).await
}

async fn login(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    let user = match state.dashboard.store.lock() {
        Ok(store) => match store.authenticate_user(&body.username, &body.password) {
            Ok(user) => user,
            Err(err) => return api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    };

    let Some(user) = user else {
        record_login_failure(&state, &headers);
        return api_error(StatusCode::OK, "incorrect username or password");
    };

    record_login_success(&state, &headers, user.id);

    match issue_token(&state, user.id, &user.username, user.role) {
        Ok(response) => (
            StatusCode::OK,
            [(
                header::SET_COOKIE,
                jwt_cookie(&response.token, state.jwt_timeout_hours),
            )],
            Json(CommonResponse::ok(response)),
        )
            .into_response(),
        Err(err) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn oauth2_redirect(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(query): Query<OAuth2RedirectQuery>,
) -> impl IntoResponse {
    let provider_key = provider.trim().to_ascii_lowercase();
    if provider_key.is_empty() {
        return api_error(StatusCode::OK, "provider is required");
    }
    let settings = match load_settings(&state) {
        Ok(settings) => settings,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let Some(config) = settings.oauth2.get(&provider_key) else {
        return api_error(StatusCode::OK, "provider not found");
    };
    if let Err(err) = validate_oauth2_config(config) {
        return api_error(StatusCode::OK, err.to_string());
    }

    let state_value = Uuid::new_v4().simple().to_string();
    let redirect_url = oauth2_redirect_url(&headers);
    let state_claims = OAuth2StateClaims {
        action: query.r#type,
        provider: provider_key,
        state: state_value.clone(),
        redirect_url: redirect_url.clone(),
        exp: (unix_now() + 300) as usize,
    };
    let cookie = match encode_oauth2_state_cookie(&state, &state_claims) {
        Ok(cookie) => cookie,
        Err(err) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    let redirect = oauth2_auth_url(config, &redirect_url, &state_value);
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(CommonResponse::ok(OAuth2RedirectResponse { redirect })),
    )
        .into_response()
}

async fn unbind_oauth2(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let provider = provider.trim().to_ascii_lowercase();
    if provider.is_empty() {
        return api_error(StatusCode::OK, "provider is required");
    }
    let settings = match load_settings(&state) {
        Ok(settings) => settings,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    if !settings.oauth2.contains_key(&provider) {
        return api_error(StatusCode::OK, "provider not found");
    }
    match state.dashboard.store.lock() {
        Ok(store) => match store.unbind_oauth2(claims.uid, &provider) {
            Ok(()) => (StatusCode::OK, Json(CommonResponse::ok(Value::Null))).into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn oauth2_callback(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let Some(state_param) = query.get("state").filter(|value| !value.is_empty()) else {
        record_oauth2_failure(&state, &headers);
        return api_error(StatusCode::OK, "invalid state key");
    };
    let state_claims = match oauth2_state_from_headers(&state, &headers) {
        Ok(claims) if claims.state == *state_param => claims,
        Ok(_) | Err(_) => {
            record_oauth2_failure(&state, &headers);
            return api_error(StatusCode::OK, "invalid state key");
        }
    };
    let Some(code) = query.get("code").filter(|value| !value.is_empty()) else {
        record_oauth2_failure(&state, &headers);
        return api_error(StatusCode::OK, "code is required");
    };
    let settings = match load_settings(&state) {
        Ok(settings) => settings,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let Some(config) = settings.oauth2.get(&state_claims.provider) else {
        return api_error(StatusCode::OK, "provider not found");
    };
    let open_id = match exchange_oauth2_open_id(config, code, &state_claims.redirect_url).await {
        Ok(open_id) => open_id,
        Err(err) => {
            record_oauth2_failure(&state, &headers);
            return api_error(StatusCode::OK, err.to_string());
        }
    };

    let user = match state_claims.action {
        2 => {
            let claims = match auth_from_headers_optional(&state, &headers) {
                Ok(Some(claims)) => claims,
                _ => return api_error(StatusCode::OK, "unauthorized"),
            };
            match state.dashboard.store.lock() {
                Ok(store) => {
                    if let Err(err) =
                        store.bind_oauth2(claims.uid, &state_claims.provider, &open_id)
                    {
                        return api_error(StatusCode::OK, err.to_string());
                    }
                    match store.get_user(claims.uid) {
                        Ok(user) => user,
                        Err(err) => return api_error(StatusCode::OK, err.to_string()),
                    }
                }
                Err(_) => {
                    return api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned");
                }
            }
        }
        _ => match state.dashboard.store.lock() {
            Ok(store) => match store.user_by_oauth2(&state_claims.provider, &open_id) {
                Ok(Some(user)) => user,
                Ok(None) => return api_error(StatusCode::OK, "oauth2 user not binded yet"),
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            },
            Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
        },
    };

    record_login_success(&state, &headers, user.id);
    match issue_token(&state, user.id, &user.username, user.role) {
        Ok(token) => {
            let target = if state_claims.action == 2 {
                "/dashboard/profile?oauth2=true"
            } else {
                "/dashboard/login?oauth2=true"
            };
            (
                StatusCode::FOUND,
                [
                    (header::LOCATION, target.to_string()),
                    (
                        header::SET_COOKIE,
                        jwt_cookie(&token.token, state.jwt_timeout_hours),
                    ),
                ],
                Body::empty(),
            )
                .into_response()
        }
        Err(err) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn setting(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let claims = require_auth_from_request(&state, &headers, &query).ok();
    match load_settings(&state) {
        Ok(settings) => (
            StatusCode::OK,
            Json(CommonResponse::ok(setting_response(
                &settings,
                claims.as_ref(),
            ))),
        )
            .into_response(),
        Err(err) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn update_setting(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<SettingPatch>,
) -> impl IntoResponse {
    if let Err(err) = require_admin(&state, &headers) {
        return api_error(StatusCode::OK, err.to_string());
    }

    let mut settings = match load_settings(&state) {
        Ok(settings) => settings,
        Err(err) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    if let Err(err) = apply_setting_patch(&mut settings, body) {
        return api_error(StatusCode::OK, err.to_string());
    }

    match state.dashboard.store.lock() {
        Ok(store) => match store.save_dashboard_settings(&settings) {
            Ok(()) => {
                i18n::set_language(&settings.language);
                (StatusCode::OK, Json(CommonResponse::ok(Value::Null))).into_response()
            }
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn refresh_token(State(state): State<HttpState>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match issue_token(&state, claims.uid, &claims.username, claims.role) {
        Ok(response) => (
            StatusCode::OK,
            [(
                header::SET_COOKIE,
                jwt_cookie(&response.token, state.jwt_timeout_hours),
            )],
            Json(CommonResponse::ok(response)),
        )
            .into_response(),
        Err(err) => api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn create_terminal(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<TerminalRequest>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match user_can_manage_server(&state, &claims, body.server_id) {
        Ok(true) => {}
        Ok(false) => return api_error(StatusCode::OK, "permission denied"),
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    }
    let server_name = match server_name(&state, body.server_id) {
        Ok(name) => name,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let stream_id = uuid::Uuid::new_v4().to_string();
    state
        .dashboard
        .io_streams
        .create_stream(stream_id.clone(), claims.uid, body.server_id)
        .await;

    let payload = serde_json::json!({ "StreamID": stream_id }).to_string();
    if !state
        .dashboard
        .dispatch_task(body.server_id, TaskType::TerminalGrpc, payload)
        .await
    {
        state.dashboard.io_streams.close_stream(&stream_id).await;
        return api_error(StatusCode::OK, "server not found or not connected");
    }

    (
        StatusCode::OK,
        Json(CommonResponse::ok(CreateTerminalResponse {
            session_id: stream_id,
            server_id: body.server_id,
            server_name,
        })),
    )
        .into_response()
}

async fn terminal_stream(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    stream_upgrade(state, headers, id, query, ws).await
}

async fn create_file_manager(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let Some(server_id) = query.get("id").and_then(|value| value.parse::<u64>().ok()) else {
        return api_error(StatusCode::OK, "invalid server id");
    };
    match user_can_manage_server(&state, &claims, server_id) {
        Ok(true) => {}
        Ok(false) => return api_error(StatusCode::OK, "permission denied"),
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    }
    if let Err(err) = server_name(&state, server_id) {
        return api_error(StatusCode::OK, err.to_string());
    }

    let stream_id = uuid::Uuid::new_v4().to_string();
    state
        .dashboard
        .io_streams
        .create_stream(stream_id.clone(), claims.uid, server_id)
        .await;
    let payload = serde_json::json!({ "StreamID": stream_id }).to_string();
    if !state
        .dashboard
        .dispatch_task(server_id, TaskType::FileManager, payload)
        .await
    {
        state.dashboard.io_streams.close_stream(&stream_id).await;
        return api_error(StatusCode::OK, "server not found or not connected");
    }

    (
        StatusCode::OK,
        Json(CommonResponse::ok(CreateFmResponse {
            session_id: stream_id,
        })),
    )
        .into_response()
}

async fn file_manager_stream(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    stream_upgrade(state, headers, id, query, ws).await
}

async fn server_stream(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let claims = match auth_from_request_optional_by_policy(&state, &headers, &query) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let ip = request_ip(&headers).unwrap_or_default();
    let conn_id = uuid::Uuid::new_v4().to_string();
    ws.on_upgrade(move |socket| stream_server_updates(state, claims, ip, conn_id, socket))
}

async fn stream_server_updates(
    state: HttpState,
    claims: Option<Claims>,
    ip: String,
    conn_id: String,
    mut socket: WebSocket,
) {
    state.dashboard.add_online_user(
        conn_id.clone(),
        OnlineUser {
            user_id: claims.as_ref().map(|claims| claims.uid).unwrap_or_default(),
            connected_at: unix_now(),
            ip: ip.clone(),
        },
    );
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut count = 0_u64;
    loop {
        interval.tick().await;
        if !ip.is_empty() && state.dashboard.online_ip_is_blocked(&ip) {
            break;
        }
        let frame = match server_stream_frame(&state, claims.as_ref(), count == 0) {
            Ok(frame) => frame,
            Err(_) => continue,
        };
        let Ok(raw) = serde_json::to_string(&frame) else {
            continue;
        };
        if socket.send(Message::Text(raw.into())).await.is_err() {
            break;
        }
        count += 1;
        if count % 4 == 0 && socket.send(Message::Ping(Vec::new().into())).await.is_err() {
            break;
        }
    }
    state.dashboard.remove_online_user(&conn_id);
}

fn server_stream_frame(
    state: &HttpState,
    claims: Option<&Claims>,
    with_public_note: bool,
) -> Result<StreamServerData<crate::store::PublicServer>> {
    let mut servers = state
        .dashboard
        .store
        .lock()
        .map_err(|_| anyhow::anyhow!("store lock poisoned"))?
        .list_servers()?;
    let viewer_user_id = claims.map(|claims| claims.uid).unwrap_or_default();
    let viewer_is_admin = claims.is_some_and(|claims| claims.role == 0);
    servers.retain(|server| {
        viewer_is_admin
            || (viewer_user_id != 0 && viewer_user_id == server.user_id)
            || !server.hide_for_guest
    });
    for server in &mut servers {
        if !viewer_is_admin && viewer_user_id != server.user_id {
            if let Some(host) = &server.host {
                server.host = Some(host.filtered());
            }
        }
        if !with_public_note {
            server.public_note.clear();
        }
    }
    Ok(StreamServerData {
        now: unix_now().saturating_mul(1000),
        online: state.dashboard.online_user_count(),
        servers,
    })
}

async fn stream_upgrade(
    state: HttpState,
    headers: HeaderMap,
    stream_id: String,
    query: HashMap<String, String>,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let claims = match require_auth_from_request(&state, &headers, &query) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    if !state
        .dashboard
        .io_streams
        .is_stream_authorized_for_user(&stream_id, claims.uid, claims.role == 0)
        .await
    {
        return api_error(StatusCode::OK, "permission denied");
    }
    if state
        .dashboard
        .io_streams
        .get_stream(&stream_id)
        .await
        .is_none()
    {
        return api_error(StatusCode::OK, "stream not found");
    }

    ws.on_upgrade(move |socket| bridge_websocket_stream(state.dashboard, stream_id, socket))
}

async fn bridge_websocket_stream(
    dashboard: Arc<DashboardState>,
    stream_id: String,
    socket: WebSocket,
) {
    let Some(session) = dashboard.io_streams.get_stream(&stream_id).await else {
        return;
    };
    let Some(mut to_user_rx) = session.take_user_receiver().await else {
        return;
    };
    let (mut ws_tx, mut ws_rx) = socket.split();
    loop {
        tokio::select! {
            message = ws_rx.next() => {
                let Some(Ok(message)) = message else {
                    break;
                };
                let data = match message {
                    Message::Binary(data) => data.to_vec(),
                    Message::Text(data) => data.to_string().into_bytes(),
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) => continue,
                };
                if session.send_to_agent(data).await.is_err() {
                    break;
                }
            }
            data = to_user_rx.recv() => {
                let Some(data) = data else {
                    break;
                };
                if data.is_empty() {
                    continue;
                }
                if ws_tx.send(Message::Binary(data.into())).await.is_err() {
                    break;
                }
            }
        }
    }
    dashboard.io_streams.close_stream(&stream_id).await;
}

async fn get_profile(State(state): State<HttpState>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };

    match state.dashboard.store.lock() {
        Ok(store) => match store.get_user(claims.uid) {
            Ok(user) => {
                let oauth2_bind = match store.oauth2_binds_for_user(claims.uid) {
                    Ok(bindings) => bindings,
                    Err(err) => return api_error(StatusCode::OK, err.to_string()),
                };
                (
                    StatusCode::OK,
                    Json(CommonResponse::ok(ProfileResource {
                        id: user.id,
                        username: user.username,
                        role: user.role,
                        agent_secret: user.agent_secret,
                        reject_password: user.reject_password,
                        login_ip: String::new(),
                        oauth2_bind,
                    })),
                )
                    .into_response()
            }
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn update_profile(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<ProfileRequest>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };

    match state.dashboard.store.lock() {
        Ok(store) => match store.update_profile(
            claims.uid,
            &body.original_password,
            &body.new_username,
            &body.new_password,
            body.reject_password,
        ) {
            Ok(()) => (StatusCode::OK, Json(CommonResponse::ok(Value::Null))).into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn list_users(State(state): State<HttpState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(err) = require_admin(&state, &headers) {
        return api_error(StatusCode::OK, err.to_string());
    }
    match state.dashboard.store.lock() {
        Ok(store) => match store.list_users() {
            Ok(users) => (StatusCode::OK, Json(CommonResponse::ok(users))).into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn create_user(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<UserRequest>,
) -> impl IntoResponse {
    if let Err(err) = require_admin(&state, &headers) {
        return api_error(StatusCode::OK, err.to_string());
    }
    match state.dashboard.store.lock() {
        Ok(store) => match store.create_user(&body.username, &body.password, body.role) {
            Ok(id) => (StatusCode::OK, Json(CommonResponse::ok(id))).into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn batch_delete_user(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let claims = match require_admin(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let ids = id_list(body);
    if ids.contains(&claims.uid) {
        return api_error(StatusCode::OK, "can't delete yourself");
    }
    match state.dashboard.store.lock() {
        Ok(store) => match store.delete_users(&ids) {
            Ok(count) => (StatusCode::OK, Json(CommonResponse::ok(count))).into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn list_servers(State(state): State<HttpState>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };

    match state.dashboard.store.lock() {
        Ok(store) => match store.list_servers() {
            Ok(servers) => (
                StatusCode::OK,
                Json(CommonResponse::ok(filter_owned(
                    servers,
                    &claims,
                    |server| server.user_id,
                ))),
            )
                .into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn update_server(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match user_can_manage_server(&state, &claims, id) {
        Ok(true) => {}
        Ok(false) => return api_error(StatusCode::OK, "permission denied"),
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    }
    match state.dashboard.store.lock() {
        Ok(store) => match store.update_server(id, &body) {
            Ok(server) => (StatusCode::OK, Json(CommonResponse::ok(server))).into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn batch_delete_server(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let ids = id_list(body);
    match state.dashboard.store.lock() {
        Ok(store) => {
            let servers = match store.list_servers() {
                Ok(servers) => servers,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !ids_are_owned(
                &servers,
                &ids,
                &claims,
                |server| server.id,
                |server| server.user_id,
            ) {
                return api_error(StatusCode::OK, "permission denied");
            }
            match store.delete_servers(&ids) {
                Ok(count) => (StatusCode::OK, Json(CommonResponse::ok(count))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn batch_move_server(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<BatchMoveRequest>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    if body.to_user == 0 {
        return api_error(StatusCode::OK, "user id is required");
    }
    if claims.role != 0 && body.to_user != claims.uid {
        return api_error(StatusCode::OK, "permission denied");
    }
    match state.dashboard.store.lock() {
        Ok(store) => {
            if store.get_user(body.to_user).is_err() {
                return api_error(
                    StatusCode::OK,
                    format!("user id {} does not exist", body.to_user),
                );
            }
            let servers = match store.list_servers() {
                Ok(servers) => servers,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !ids_are_owned(
                &servers,
                &body.ids,
                &claims,
                |server| server.id,
                |server| server.user_id,
            ) {
                return api_error(StatusCode::OK, "permission denied");
            }
            match store.move_servers(&body.ids, body.to_user) {
                Ok(count) => (StatusCode::OK, Json(CommonResponse::ok(count))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn force_update_server(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let mut response = ServerTaskResponse {
        success: Vec::new(),
        failure: Vec::new(),
        offline: Vec::new(),
    };
    for id in id_list(body) {
        match user_can_manage_server(&state, &claims, id) {
            Ok(true) => {}
            Ok(false) => {
                response.offline.push(id);
                continue;
            }
            Err(err) => return api_error(StatusCode::OK, err.to_string()),
        }
        if state
            .dashboard
            .dispatch_task(id, TaskType::Upgrade, String::new())
            .await
        {
            response.success.push(id);
        } else {
            response.offline.push(id);
        }
    }
    (StatusCode::OK, Json(CommonResponse::ok(response))).into_response()
}

async fn get_server_config(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match user_can_manage_server(&state, &claims, id) {
        Ok(true) => {}
        Ok(false) => return api_error(StatusCode::OK, "permission denied"),
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    }
    match state.dashboard.request_config(id).await {
        Ok(Some(config)) => (StatusCode::OK, Json(CommonResponse::ok(config))).into_response(),
        Ok(None) => (StatusCode::OK, Json(CommonResponse::ok(String::new()))).into_response(),
        Err(err) => api_error(StatusCode::OK, err),
    }
}

async fn set_server_config(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let ids: Vec<u64> = body
        .get("servers")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    let config = body
        .get("config")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut response = ServerTaskResponse {
        success: Vec::new(),
        failure: Vec::new(),
        offline: Vec::new(),
    };
    for id in ids {
        match user_can_manage_server(&state, &claims, id) {
            Ok(true) => {}
            Ok(false) => {
                response.offline.push(id);
                continue;
            }
            Err(err) => return api_error(StatusCode::OK, err.to_string()),
        }
        if state
            .dashboard
            .dispatch_task(id, TaskType::ApplyConfig, config.clone())
            .await
        {
            response.success.push(id);
        } else {
            response.offline.push(id);
        }
    }
    (StatusCode::OK, Json(CommonResponse::ok(response))).into_response()
}

async fn list_service_servers(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let claims = match auth_from_request_optional_by_policy(&state, &headers, &query) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => {
            let ids = match store.service_server_ids() {
                Ok(ids) => ids,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            let servers = match store.list_servers() {
                Ok(servers) => servers,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            let visible = ids
                .into_iter()
                .filter(|id| {
                    servers
                        .iter()
                        .find(|server| server.id == *id)
                        .is_some_and(|server| user_can_view_server(claims.as_ref(), server))
                })
                .collect::<Vec<_>>();
            (StatusCode::OK, Json(CommonResponse::ok(visible))).into_response()
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn get_server_metrics(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let claims = match auth_from_headers_optional_by_policy(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let server = match state.dashboard.store.lock() {
        Ok(store) => match store.list_servers() {
            Ok(servers) => servers.into_iter().find(|server| server.id == id),
            Err(err) => return api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    };
    let Some(server) = server else {
        return api_error(StatusCode::OK, "server not found");
    };
    if !user_can_view_server(claims.as_ref(), &server) {
        return api_error(StatusCode::OK, "unauthorized");
    }
    let metric = query
        .get("metric")
        .cloned()
        .unwrap_or_else(|| "cpu".to_string());
    let period = query.get("period").map(String::as_str).unwrap_or("1d");
    if claims.is_none() && period != "1d" {
        return api_error(
            StatusCode::OK,
            "unauthorized: only 1d data available for guests",
        );
    }
    let since_ms = unix_now()
        .saturating_sub(period_seconds(period).unwrap_or(24 * 3600))
        .saturating_mul(1000);

    match state.dashboard.store.lock() {
        Ok(store) => match store.query_server_metrics(id, &metric, since_ms) {
            Ok(data_points) => (
                StatusCode::OK,
                Json(CommonResponse::ok(ServerMetricsResponse {
                    server_id: id,
                    server_name: server.name,
                    metric,
                    data_points,
                })),
            )
                .into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn get_service_history(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let claims = match auth_from_headers_optional_by_policy(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let period = query.get("period").map(String::as_str).unwrap_or("1d");
    if claims.is_none() && period != "1d" {
        return api_error(
            StatusCode::OK,
            "unauthorized: only 1d data available for guests",
        );
    }
    let since = unix_now().saturating_sub(period_seconds(period).unwrap_or(24 * 3600));

    match state.dashboard.store.lock() {
        Ok(store) => match (store.query_service_history(id, since), store.list_servers()) {
            (Ok(mut history), Ok(servers)) => {
                history.servers.retain(|stats| {
                    servers
                        .iter()
                        .find(|server| server.id == stats.server_id)
                        .is_some_and(|server| user_can_view_server(claims.as_ref(), server))
                });
                (StatusCode::OK, Json(CommonResponse::ok(history))).into_response()
            }
            (Err(err), _) | (_, Err(err)) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn list_server_services(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let claims = match auth_from_headers_optional_by_policy(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let server = match state.dashboard.store.lock() {
        Ok(store) => match store.list_servers() {
            Ok(servers) => servers.into_iter().find(|server| server.id == id),
            Err(err) => return api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    };
    let Some(server) = server else {
        return api_error(StatusCode::OK, "server not found");
    };
    if !user_can_view_server(claims.as_ref(), &server) {
        return api_error(StatusCode::OK, "unauthorized");
    }
    let period = query.get("period").map(String::as_str).unwrap_or("1d");
    if claims.is_none() && period != "1d" {
        return api_error(
            StatusCode::OK,
            "unauthorized: only 1d data available for guests",
        );
    }
    let since = unix_now().saturating_sub(period_seconds(period).unwrap_or(24 * 3600));

    match state.dashboard.store.lock() {
        Ok(store) => match store.query_server_services(id, since) {
            Ok(items) => (StatusCode::OK, Json(CommonResponse::ok(items))).into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn list_server_groups(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match auth_from_headers_optional_by_policy(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => match (store.list_server_groups(), store.list_servers()) {
            (Ok(groups), Ok(servers)) => (
                StatusCode::OK,
                Json(CommonResponse::ok(filter_server_groups(
                    groups,
                    servers.as_slice(),
                    claims.as_ref(),
                ))),
            )
                .into_response(),
            (Err(err), _) | (_, Err(err)) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn create_server_group(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<ServerGroupRequest>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => {
            if let Err(err) = validate_server_group_servers(&store, &claims, &body.servers) {
                return api_error(StatusCode::OK, err.to_string());
            }
            match store.upsert_server_group(None, claims.uid, &body.name, &body.servers) {
                Ok(item) => {
                    (StatusCode::OK, Json(CommonResponse::ok(item.group.id))).into_response()
                }
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn update_server_group(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Json(body): Json<ServerGroupRequest>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => {
            let groups = match store.list_server_groups() {
                Ok(groups) => groups,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !id_is_owned(
                &groups,
                id,
                &claims,
                |item| item.group.id,
                |item| item.group.user_id,
            ) {
                return api_error(StatusCode::OK, "unauthorized");
            }
            if let Err(err) = validate_server_group_servers(&store, &claims, &body.servers) {
                return api_error(StatusCode::OK, err.to_string());
            }
            match store.upsert_server_group(Some(id), claims.uid, &body.name, &body.servers) {
                Ok(_) => (StatusCode::OK, Json(CommonResponse::ok(Value::Null))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn batch_delete_server_group(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let ids = id_list(body);
    match state.dashboard.store.lock() {
        Ok(store) => {
            let groups = match store.list_server_groups() {
                Ok(groups) => groups,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !ids_are_owned(
                &groups,
                &ids,
                &claims,
                |item| item.group.id,
                |item| item.group.user_id,
            ) {
                return api_error(StatusCode::OK, "permission denied");
            }
            match store.delete_server_groups(&ids) {
                Ok(count) => (StatusCode::OK, Json(CommonResponse::ok(count))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn list_notification_groups(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => match store.list_notification_groups() {
            Ok(items) => (
                StatusCode::OK,
                Json(CommonResponse::ok(filter_owned(items, &claims, |item| {
                    item.group.user_id
                }))),
            )
                .into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn create_notification_group(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<NotificationGroupRequest>,
) -> impl IntoResponse {
    upsert_notification_group(state, headers, None, body).await
}

async fn update_notification_group(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Json(body): Json<NotificationGroupRequest>,
) -> impl IntoResponse {
    upsert_notification_group(state, headers, Some(id), body).await
}

async fn batch_delete_notification_group(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<BatchDeleteRequest>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => {
            let items = match store.list_notification_groups() {
                Ok(items) => items,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !ids_are_owned(
                &items,
                &body.ids,
                &claims,
                |item| item.group.id,
                |item| item.group.user_id,
            ) {
                return api_error(StatusCode::OK, "permission denied");
            }
            match store.delete_notification_groups(&body.ids) {
                Ok(count) => (StatusCode::OK, Json(CommonResponse::ok(count))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn upsert_notification_group(
    state: HttpState,
    headers: HeaderMap,
    id: Option<u64>,
    body: NotificationGroupRequest,
) -> axum::response::Response {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => {
            if let Some(id) = id {
                let items = match store.list_notification_groups() {
                    Ok(items) => items,
                    Err(err) => return api_error(StatusCode::OK, err.to_string()),
                };
                if !id_is_owned(
                    &items,
                    id,
                    &claims,
                    |item| item.group.id,
                    |item| item.group.user_id,
                ) {
                    return api_error(StatusCode::OK, "permission denied");
                }
            }
            let notifications = match store.list_notifications() {
                Ok(notifications) => notifications,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !ids_are_owned(
                &notifications,
                &body.notifications,
                &claims,
                |item| item.id,
                |item| item.user_id,
            ) {
                return api_error(StatusCode::OK, "permission denied");
            }
            match store.upsert_notification_group(id, claims.uid, &body.name, &body.notifications) {
                Ok(item) => (StatusCode::OK, Json(CommonResponse::ok(item))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn list_notifications(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => match store.list_notifications() {
            Ok(items) => (
                StatusCode::OK,
                Json(CommonResponse::ok(filter_owned(items, &claims, |item| {
                    item.user_id
                }))),
            )
                .into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn create_notification(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    upsert_notification(state, headers, None, body).await
}

async fn update_notification(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    upsert_notification(state, headers, Some(id), body).await
}

async fn upsert_notification(
    state: HttpState,
    headers: HeaderMap,
    id: Option<u64>,
    body: serde_json::Value,
) -> axum::response::Response {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => {
            if let Some(id) = id {
                let items = match store.list_notifications() {
                    Ok(items) => items,
                    Err(err) => return api_error(StatusCode::OK, err.to_string()),
                };
                if !id_is_owned(&items, id, &claims, |item| item.id, |item| item.user_id) {
                    return api_error(StatusCode::OK, "permission denied");
                }
            }
            match store.upsert_notification(id, claims.uid, &body) {
                Ok(item) => (StatusCode::OK, Json(CommonResponse::ok(item))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn batch_delete_notification(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let ids = id_list(body);
    match state.dashboard.store.lock() {
        Ok(store) => {
            let items = match store.list_notifications() {
                Ok(items) => items,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !ids_are_owned(&items, &ids, &claims, |item| item.id, |item| item.user_id) {
                return api_error(StatusCode::OK, "permission denied");
            }
            match store.delete_notifications(&ids) {
                Ok(count) => (StatusCode::OK, Json(CommonResponse::ok(count))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn show_service(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let _claims = require_auth_from_request(&state, &headers, &query).ok();
    let (services, servers) = match state.dashboard.store.lock() {
        Ok(store) => match (store.service_response_items(), store.list_servers()) {
            (Ok(services), Ok(servers)) => (services, servers),
            (Err(err), _) | (_, Err(err)) => return api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    };
    let cycle_transfer_stats = filter_cycle_transfer_stats(
        state.dashboard.cycle_transfer_stats.read().await.clone(),
        _claims.as_ref(),
        servers.as_slice(),
    );
    (
        StatusCode::OK,
        Json(CommonResponse::ok(serde_json::json!({
            "services": services,
            "cycle_transfer_stats": cycle_transfer_stats
        }))),
    )
        .into_response()
}

async fn list_services(State(state): State<HttpState>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => match store.list_services() {
            Ok(items) => (
                StatusCode::OK,
                Json(CommonResponse::ok(filter_owned(items, &claims, |item| {
                    item.user_id
                }))),
            )
                .into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn create_service(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    upsert_service(state, headers, None, body).await
}

async fn update_service(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    upsert_service(state, headers, Some(id), body).await
}

async fn upsert_service(
    state: HttpState,
    headers: HeaderMap,
    id: Option<u64>,
    body: Value,
) -> axum::response::Response {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => {
            if let Some(id) = id {
                let items = match store.list_services() {
                    Ok(items) => items,
                    Err(err) => return api_error(StatusCode::OK, err.to_string()),
                };
                if !id_is_owned(&items, id, &claims, |item| item.id, |item| item.user_id) {
                    return api_error(StatusCode::OK, "permission denied");
                }
            }
            if let Err(err) = validate_monitor_references(&store, &claims, &body) {
                return api_error(StatusCode::OK, err.to_string());
            }
            match store.upsert_service(id, claims.uid, &body) {
                Ok(item) => (StatusCode::OK, Json(CommonResponse::ok(item))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn batch_delete_service(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let ids = id_list(body);
    match state.dashboard.store.lock() {
        Ok(store) => {
            let items = match store.list_services() {
                Ok(items) => items,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !ids_are_owned(&items, &ids, &claims, |item| item.id, |item| item.user_id) {
                return api_error(StatusCode::OK, "permission denied");
            }
            match store.delete_services(&ids) {
                Ok(count) => (StatusCode::OK, Json(CommonResponse::ok(count))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn list_alert_rules(State(state): State<HttpState>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => match store.list_alert_rules() {
            Ok(items) => (
                StatusCode::OK,
                Json(CommonResponse::ok(filter_owned(items, &claims, |item| {
                    item.user_id
                }))),
            )
                .into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn create_alert_rule(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    upsert_alert_rule(state, headers, None, body).await
}

async fn update_alert_rule(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    upsert_alert_rule(state, headers, Some(id), body).await
}

async fn upsert_alert_rule(
    state: HttpState,
    headers: HeaderMap,
    id: Option<u64>,
    body: Value,
) -> axum::response::Response {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => {
            if let Some(id) = id {
                let items = match store.list_alert_rules() {
                    Ok(items) => items,
                    Err(err) => return api_error(StatusCode::OK, err.to_string()),
                };
                if !id_is_owned(&items, id, &claims, |item| item.id, |item| item.user_id) {
                    return api_error(StatusCode::OK, "permission denied");
                }
            }
            if let Err(err) = validate_alert_rule_references(&store, &claims, &body) {
                return api_error(StatusCode::OK, err.to_string());
            }
            match store.upsert_alert_rule(id, claims.uid, &body) {
                Ok(item) => (StatusCode::OK, Json(CommonResponse::ok(item))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn batch_delete_alert_rule(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let ids = id_list(body);
    match state.dashboard.store.lock() {
        Ok(store) => {
            let items = match store.list_alert_rules() {
                Ok(items) => items,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !ids_are_owned(&items, &ids, &claims, |item| item.id, |item| item.user_id) {
                return api_error(StatusCode::OK, "permission denied");
            }
            match store.delete_alert_rules(&ids) {
                Ok(count) => (StatusCode::OK, Json(CommonResponse::ok(count))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn list_crons(State(state): State<HttpState>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => match store.list_crons() {
            Ok(items) => (
                StatusCode::OK,
                Json(CommonResponse::ok(filter_owned(items, &claims, |item| {
                    item.user_id
                }))),
            )
                .into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn create_cron(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    upsert_cron(state, headers, None, body).await
}

async fn update_cron(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    upsert_cron(state, headers, Some(id), body).await
}

async fn upsert_cron(
    state: HttpState,
    headers: HeaderMap,
    id: Option<u64>,
    body: serde_json::Value,
) -> axum::response::Response {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => {
            if let Some(id) = id {
                let items = match store.list_crons() {
                    Ok(items) => items,
                    Err(err) => return api_error(StatusCode::OK, err.to_string()),
                };
                if !id_is_owned(&items, id, &claims, |item| item.id, |item| item.user_id) {
                    return api_error(StatusCode::OK, "permission denied");
                }
            }
            if let Err(err) = validate_cron_references(&store, &claims, &body) {
                return api_error(StatusCode::OK, err.to_string());
            }
            match store.upsert_cron(id, claims.uid, &body) {
                Ok(item) => (StatusCode::OK, Json(CommonResponse::ok(item))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn batch_delete_cron(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let ids = id_list(body);
    match state.dashboard.store.lock() {
        Ok(store) => {
            let items = match store.list_crons() {
                Ok(items) => items,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !ids_are_owned(&items, &ids, &claims, |item| item.id, |item| item.user_id) {
                return api_error(StatusCode::OK, "permission denied");
            }
            match store.delete_crons(&ids) {
                Ok(count) => (StatusCode::OK, Json(CommonResponse::ok(count))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn manual_trigger_cron(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let cron = match state.dashboard.store.lock() {
        Ok(store) => {
            let cron = match store.get_cron(id) {
                Ok(cron) => cron,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !owner_is_permitted(&claims, cron.user_id) {
                return api_error(StatusCode::OK, "permission denied");
            }
            cron
        }
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    };
    let (success, offline) =
        crate::scheduler::dispatch_cron_detailed(&state.dashboard, &cron).await;
    let response = ServerTaskResponse {
        success,
        failure: Vec::new(),
        offline,
    };
    (StatusCode::OK, Json(CommonResponse::ok(response))).into_response()
}

async fn list_ddns(State(state): State<HttpState>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => match store.list_ddns() {
            Ok(items) => (
                StatusCode::OK,
                Json(CommonResponse::ok(filter_owned(items, &claims, |item| {
                    item.user_id
                }))),
            )
                .into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn list_ddns_providers(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(err) = require_auth(&state, &headers) {
        return api_error(StatusCode::OK, err.to_string());
    }
    (
        StatusCode::OK,
        Json(CommonResponse::ok(vec![
            "dummy",
            "webhook",
            "cloudflare",
            "tencentcloud",
            "he",
        ])),
    )
        .into_response()
}

async fn create_ddns(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    upsert_ddns(state, headers, None, body).await
}

async fn update_ddns(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    upsert_ddns(state, headers, Some(id), body).await
}

async fn upsert_ddns(
    state: HttpState,
    headers: HeaderMap,
    id: Option<u64>,
    body: Value,
) -> axum::response::Response {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => {
            if let Some(id) = id {
                let items = match store.list_ddns() {
                    Ok(items) => items,
                    Err(err) => return api_error(StatusCode::OK, err.to_string()),
                };
                if !id_is_owned(&items, id, &claims, |item| item.id, |item| item.user_id) {
                    return api_error(StatusCode::OK, "permission denied");
                }
            }
            match store.upsert_ddns(id, claims.uid, &body) {
                Ok(item) => (StatusCode::OK, Json(CommonResponse::ok(item))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn batch_delete_ddns(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let ids = id_list(body);
    match state.dashboard.store.lock() {
        Ok(store) => {
            let items = match store.list_ddns() {
                Ok(items) => items,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !ids_are_owned(&items, &ids, &claims, |item| item.id, |item| item.user_id) {
                return api_error(StatusCode::OK, "permission denied");
            }
            match store.delete_ddns(&ids) {
                Ok(count) => (StatusCode::OK, Json(CommonResponse::ok(count))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn list_nat(State(state): State<HttpState>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => match store.list_nat() {
            Ok(items) => (
                StatusCode::OK,
                Json(CommonResponse::ok(filter_owned(items, &claims, |item| {
                    item.user_id
                }))),
            )
                .into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn create_nat(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    upsert_nat(state, headers, None, body).await
}

async fn update_nat(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Path(id): Path<u64>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    upsert_nat(state, headers, Some(id), body).await
}

async fn upsert_nat(
    state: HttpState,
    headers: HeaderMap,
    id: Option<u64>,
    body: serde_json::Value,
) -> axum::response::Response {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    match state.dashboard.store.lock() {
        Ok(store) => {
            if let Some(id) = id {
                let items = match store.list_nat() {
                    Ok(items) => items,
                    Err(err) => return api_error(StatusCode::OK, err.to_string()),
                };
                if !id_is_owned(&items, id, &claims, |item| item.id, |item| item.user_id) {
                    return api_error(StatusCode::OK, "permission denied");
                }
            }
            if let Some(server_id) = body.get("server_id").and_then(Value::as_u64) {
                let servers = match store.list_servers() {
                    Ok(servers) => servers,
                    Err(err) => return api_error(StatusCode::OK, err.to_string()),
                };
                if !id_is_owned(
                    &servers,
                    server_id,
                    &claims,
                    |server| server.id,
                    |server| server.user_id,
                ) {
                    return api_error(StatusCode::OK, "permission denied");
                }
            }
            match store.upsert_nat(id, claims.uid, &body) {
                Ok(item) => (StatusCode::OK, Json(CommonResponse::ok(item))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn batch_delete_nat(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let claims = match require_auth(&state, &headers) {
        Ok(claims) => claims,
        Err(err) => return api_error(StatusCode::OK, err.to_string()),
    };
    let ids = id_list(body);
    match state.dashboard.store.lock() {
        Ok(store) => {
            let items = match store.list_nat() {
                Ok(items) => items,
                Err(err) => return api_error(StatusCode::OK, err.to_string()),
            };
            if !ids_are_owned(&items, &ids, &claims, |item| item.id, |item| item.user_id) {
                return api_error(StatusCode::OK, "permission denied");
            }
            match store.delete_nat(&ids) {
                Ok(count) => (StatusCode::OK, Json(CommonResponse::ok(count))).into_response(),
                Err(err) => api_error(StatusCode::OK, err.to_string()),
            }
        }
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn list_waf(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> impl IntoResponse {
    if let Err(err) = require_admin(&state, &headers) {
        return api_error(StatusCode::OK, err.to_string());
    }
    let limit = query.limit.unwrap_or(25).clamp(1, 500);
    let offset = query.offset.unwrap_or(0);
    match state.dashboard.store.lock() {
        Ok(store) => match store.list_waf(limit, offset) {
            Ok((items, total)) => (
                StatusCode::OK,
                Json(CommonResponse::ok(PaginatedResponse {
                    value: items,
                    pagination: Pagination {
                        offset,
                        limit,
                        total,
                    },
                })),
            )
                .into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn list_online_users(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> impl IntoResponse {
    if let Err(err) = require_admin(&state, &headers) {
        return api_error(StatusCode::OK, err.to_string());
    }
    let limit = query.limit.unwrap_or(25).clamp(1, 500);
    let offset = query.offset.unwrap_or(0);
    let (users, total) = state.dashboard.list_online_users(limit, offset);
    (
        StatusCode::OK,
        Json(CommonResponse::ok(PaginatedResponse {
            value: users,
            pagination: Pagination {
                offset,
                limit,
                total,
            },
        })),
    )
        .into_response()
}

async fn batch_block_online_user(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Vec<String>>,
) -> impl IntoResponse {
    if let Err(err) = require_admin(&state, &headers) {
        return api_error(StatusCode::OK, err.to_string());
    }
    let ips = unique_strings(body);
    match state.dashboard.store.lock() {
        Ok(store) => {
            for ip in &ips {
                if let Err(err) = store.record_waf_block(ip, 4, -124) {
                    return api_error(StatusCode::OK, err.to_string());
                }
            }
        }
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
    state.dashboard.block_online_ips(&ips);
    (StatusCode::OK, Json(CommonResponse::ok(Value::Null))).into_response()
}

async fn batch_delete_waf(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(body): Json<Vec<String>>,
) -> impl IntoResponse {
    if let Err(err) = require_admin(&state, &headers) {
        return api_error(StatusCode::OK, err.to_string());
    }
    match state.dashboard.store.lock() {
        Ok(store) => match store.delete_waf_ips(&body) {
            Ok(count) => (StatusCode::OK, Json(CommonResponse::ok(count))).into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

async fn run_maintenance(State(state): State<HttpState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(err) = require_admin(&state, &headers) {
        return api_error(StatusCode::OK, err.to_string());
    }
    match state.dashboard.store.lock() {
        Ok(store) => match store.maintenance() {
            Ok(()) => (StatusCode::OK, Json(CommonResponse::ok(Value::Null))).into_response(),
            Err(err) => api_error(StatusCode::OK, err.to_string()),
        },
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "store lock poisoned"),
    }
}

fn record_login_failure(state: &HttpState, headers: &HeaderMap) {
    let Some(ip) = request_ip(headers) else {
        return;
    };
    if let Ok(store) = state.dashboard.store.lock() {
        let _ = store.record_waf_block(&ip, 1, -125);
    }
}

fn record_login_success(state: &HttpState, headers: &HeaderMap, user_id: u64) {
    let Some(ip) = request_ip(headers) else {
        return;
    };
    if let Ok(store) = state.dashboard.store.lock() {
        let _ = store.delete_waf_ip_identifier(&ip, -125);
        let _ = store.delete_waf_ip_identifier(&ip, user_id as i64);
    }
}

fn resolve_request_ip(state: &HttpState, headers: &HeaderMap) -> Result<Option<String>> {
    let settings = load_settings(state)?;
    if settings.web_real_ip_header.is_empty() || settings.web_real_ip_header == "NZ::Use-Peer-IP" {
        return Ok(request_ip(headers));
    }
    let raw = headers
        .get(settings.web_real_ip_header.as_str())
        .and_then(|value| value.to_str().ok())
        .context("real ip header not found")?;
    parse_ip_from_header(raw).map(Some)
}

fn parse_ip_from_header(raw: &str) -> Result<String> {
    let value = raw
        .split(',')
        .next_back()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("real ip header not found")?;
    let ip: IpAddr = value.parse().context("invalid ip")?;
    Ok(ip.to_string())
}

fn waf_block_response(error: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        [("content-type", "text/html; charset=utf-8")],
        UPSTREAM_WAF_HTML.replace("{error}", error),
    )
        .into_response()
}

fn unique_strings(items: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for item in items {
        let item = item.trim().to_string();
        if !item.is_empty() && !unique.contains(&item) {
            unique.push(item);
        }
    }
    unique
}

#[cfg(test)]
fn desensitize_ip(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(addr)) => {
            let mut octets = addr.octets();
            octets[3] = 0;
            format!("{}.{}.{}.*", octets[0], octets[1], octets[2])
        }
        Ok(std::net::IpAddr::V6(addr)) => {
            let segments = addr.segments();
            format!(
                "{:x}:{:x}:{:x}:{:x}:****:****:****:****",
                segments[0], segments[1], segments[2], segments[3]
            )
        }
        Err(_) => String::new(),
    }
}

fn request_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_ip_from_header(value).ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| parse_ip_from_header(value).ok())
        })
}

fn server_name(state: &HttpState, server_id: u64) -> Result<String> {
    let store = state
        .dashboard
        .store
        .lock()
        .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
    store
        .list_servers()?
        .into_iter()
        .find(|server| server.id == server_id)
        .map(|server| server.name)
        .context("server not found")
}

fn user_can_manage_server(state: &HttpState, claims: &Claims, server_id: u64) -> Result<bool> {
    let store = state
        .dashboard
        .store
        .lock()
        .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
    let Some(server) = store
        .list_servers()?
        .into_iter()
        .find(|server| server.id == server_id)
    else {
        return Ok(false);
    };
    Ok(claims.role == 0 || server.user_id == claims.uid)
}

fn user_can_view_server(claims: Option<&Claims>, server: &PublicServer) -> bool {
    match claims {
        Some(claims) if claims.role == 0 => true,
        Some(claims) if claims.uid == server.user_id => true,
        _ => !server.hide_for_guest,
    }
}

fn filter_cycle_transfer_stats(
    stats: HashMap<u64, CycleTransferStats>,
    claims: Option<&Claims>,
    servers: &[PublicServer],
) -> HashMap<u64, CycleTransferStats> {
    stats
        .into_iter()
        .filter_map(|(alert_id, mut stats)| {
            stats.server_name.retain(|server_id, _| {
                servers
                    .iter()
                    .find(|server| server.id == *server_id)
                    .is_some_and(|server| user_can_view_server(claims, server))
            });
            stats.transfer.retain(|server_id, _| {
                servers
                    .iter()
                    .find(|server| server.id == *server_id)
                    .is_some_and(|server| user_can_view_server(claims, server))
            });
            stats.next_update.retain(|server_id, _| {
                servers
                    .iter()
                    .find(|server| server.id == *server_id)
                    .is_some_and(|server| user_can_view_server(claims, server))
            });
            (!stats.server_name.is_empty()
                || !stats.transfer.is_empty()
                || !stats.next_update.is_empty())
            .then_some((alert_id, stats))
        })
        .collect()
}

fn owner_is_permitted(claims: &Claims, owner_id: u64) -> bool {
    claims.role == 0 || claims.uid == owner_id
}

fn filter_owned<T>(items: Vec<T>, claims: &Claims, owner_id: impl Fn(&T) -> u64) -> Vec<T> {
    if claims.role == 0 {
        return items;
    }
    items
        .into_iter()
        .filter(|item| owner_id(item) == claims.uid)
        .collect()
}

fn filter_server_groups(
    groups: Vec<ServerGroupResource>,
    servers: &[PublicServer],
    claims: Option<&Claims>,
) -> Vec<ServerGroupResource> {
    let is_admin = claims.is_some_and(|claims| claims.role == 0);
    let is_member = claims.is_some();
    groups
        .into_iter()
        .filter_map(|mut item| {
            if is_member && !is_admin && item.group.user_id != claims.expect("member claims").uid {
                return None;
            }
            if claims.is_none() {
                item.servers.retain(|server_id| {
                    servers
                        .iter()
                        .find(|server| server.id == *server_id)
                        .is_some_and(|server| user_can_view_server(None, server))
                });
            }
            Some(item)
        })
        .collect()
}

fn validate_server_group_servers(store: &Store, claims: &Claims, servers: &[u64]) -> Result<()> {
    let all_servers = store.list_servers()?;
    for server_id in unique_u64s(servers) {
        let Some(server) = all_servers.iter().find(|server| server.id == server_id) else {
            anyhow::bail!("have invalid server id");
        };
        if claims.role != 0 && server.user_id != claims.uid {
            anyhow::bail!("permission denied");
        }
    }
    Ok(())
}

fn unique_u64s(items: &[u64]) -> Vec<u64> {
    let mut unique = Vec::new();
    for item in items {
        if !unique.contains(item) {
            unique.push(*item);
        }
    }
    unique
}

fn id_is_owned<T>(
    items: &[T],
    id: u64,
    claims: &Claims,
    item_id: impl Fn(&T) -> u64,
    owner_id: impl Fn(&T) -> u64,
) -> bool {
    items
        .iter()
        .find(|item| item_id(item) == id)
        .is_some_and(|item| owner_is_permitted(claims, owner_id(item)))
}

fn ids_are_owned<T>(
    items: &[T],
    ids: &[u64],
    claims: &Claims,
    item_id: impl Fn(&T) -> u64,
    owner_id: impl Fn(&T) -> u64,
) -> bool {
    ids.iter()
        .all(|id| id_is_owned(items, *id, claims, &item_id, &owner_id))
}

fn validate_notification_group_ref(store: &Store, claims: &Claims, group_id: u64) -> Result<()> {
    if group_id == 0 {
        return Ok(());
    }
    let groups = store.list_notification_groups()?;
    anyhow::ensure!(
        id_is_owned(
            &groups,
            group_id,
            claims,
            |item| item.group.id,
            |item| item.group.user_id
        ),
        "permission denied"
    );
    Ok(())
}

fn validate_server_ids(store: &Store, claims: &Claims, ids: &[u64]) -> Result<()> {
    let servers = store.list_servers()?;
    anyhow::ensure!(
        ids_are_owned(
            &servers,
            ids,
            claims,
            |server| server.id,
            |server| { server.user_id }
        ),
        "permission denied"
    );
    Ok(())
}

fn validate_cron_ids(store: &Store, claims: &Claims, ids: &[u64]) -> Result<()> {
    let crons = store.list_crons()?;
    anyhow::ensure!(
        ids_are_owned(&crons, ids, claims, |cron| cron.id, |cron| cron.user_id),
        "permission denied"
    );
    Ok(())
}

fn validate_cron_references(store: &Store, claims: &Claims, body: &Value) -> Result<()> {
    validate_server_ids(store, claims, &u64_array(body, "servers"))?;
    validate_notification_group_ref(
        store,
        claims,
        body.get("notification_group_id")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
    )
}

fn validate_monitor_references(store: &Store, claims: &Claims, body: &Value) -> Result<()> {
    validate_server_ids(store, claims, &object_key_ids(body.get("skip_servers")))?;
    validate_cron_ids(store, claims, &object_key_ids(body.get("trigger_tasks")))?;
    validate_cron_ids(store, claims, &u64_array(body, "fail_trigger_tasks"))?;
    validate_cron_ids(store, claims, &u64_array(body, "recover_trigger_tasks"))?;
    validate_notification_group_ref(
        store,
        claims,
        body.get("notification_group_id")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
    )
}

fn validate_alert_rule_references(store: &Store, claims: &Claims, body: &Value) -> Result<()> {
    validate_cron_ids(store, claims, &u64_array(body, "fail_trigger_tasks"))?;
    validate_cron_ids(store, claims, &u64_array(body, "recover_trigger_tasks"))?;
    validate_notification_group_ref(
        store,
        claims,
        body.get("notification_group_id")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
    )
}

fn u64_array(body: &Value, field: &str) -> Vec<u64> {
    body.get(field)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default()
}

fn object_key_ids(value: Option<&Value>) -> Vec<u64> {
    value
        .and_then(Value::as_object)
        .map(|items| {
            items
                .keys()
                .filter_map(|key| key.parse::<u64>().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn load_settings(state: &HttpState) -> Result<DashboardSettings> {
    let stored = state
        .dashboard
        .store
        .lock()
        .map_err(|_| anyhow::anyhow!("store lock poisoned"))?
        .dashboard_settings()?;
    let settings = stored.unwrap_or_else(|| settings_from_state_defaults(state));
    i18n::set_language(&settings.language);
    Ok(settings)
}

fn settings_from_state_defaults(state: &HttpState) -> DashboardSettings {
    DashboardSettings {
        site_name: state.site_name.clone(),
        install_host: state.install_host.clone(),
        tls: state.agent_tls,
        ..DashboardSettings::default()
    }
}

fn setting_response(settings: &DashboardSettings, claims: Option<&Claims>) -> SettingResponse {
    let is_admin = claims.is_some_and(|claims| claims.role == 0);
    let is_authorized = claims.is_some();
    SettingResponse {
        config: setting_config(settings, is_authorized, is_admin),
        version: if is_admin {
            env!("CARGO_PKG_VERSION").to_string()
        } else {
            String::new()
        },
        frontend_templates: if is_admin {
            frontend::templates().to_vec()
        } else {
            Vec::new()
        },
        tsdb_enabled: true,
    }
}

fn setting_config(settings: &DashboardSettings, is_authorized: bool, is_admin: bool) -> Value {
    let mut config = serde_json::Map::new();
    config.insert(
        "language".to_string(),
        Value::String(api_language(&settings.language)),
    );
    config.insert(
        "site_name".to_string(),
        Value::String(settings.site_name.clone()),
    );
    insert_non_empty(&mut config, "custom_code", &settings.custom_code);
    insert_non_empty(
        &mut config,
        "custom_code_dashboard",
        &settings.custom_code_dashboard,
    );
    let providers = oauth2_providers(settings);
    if !providers.is_empty() {
        config.insert("oauth2_providers".to_string(), serde_json::json!(providers));
    }

    if is_authorized {
        insert_non_empty(&mut config, "install_host", &settings.install_host);
        insert_true(&mut config, "tls", settings.tls);
    }

    if is_admin {
        insert_non_empty(&mut config, "dns_servers", &settings.dns_servers);
        insert_non_empty(
            &mut config,
            "ignored_ip_notification",
            &settings.ignored_ip_notification,
        );
        let ignored_server_ids =
            ignored_ip_notification_server_ids(&settings.ignored_ip_notification);
        if !ignored_server_ids.is_empty() {
            config.insert(
                "ignored_ip_notification_server_ids".to_string(),
                serde_json::json!(ignored_server_ids),
            );
        }
        config.insert(
            "ip_change_notification_group_id".to_string(),
            serde_json::json!(settings.ip_change_notification_group_id),
        );
        config.insert("cover".to_string(), serde_json::json!(settings.cover));
        insert_non_empty(
            &mut config,
            "web_real_ip_header",
            &settings.web_real_ip_header,
        );
        insert_non_empty(
            &mut config,
            "agent_real_ip_header",
            &settings.agent_real_ip_header,
        );
        insert_non_empty(&mut config, "user_template", &settings.user_template);
        insert_non_empty(&mut config, "admin_template", &settings.admin_template);
        insert_true(
            &mut config,
            "enable_ip_change_notification",
            settings.enable_ip_change_notification,
        );
        insert_true(
            &mut config,
            "enable_plain_ip_in_notification",
            settings.enable_plain_ip_in_notification,
        );
    }

    Value::Object(config)
}

fn insert_non_empty(config: &mut serde_json::Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        config.insert(key.to_string(), Value::String(value.to_string()));
    }
}

fn insert_true(config: &mut serde_json::Map<String, Value>, key: &str, value: bool) {
    if value {
        config.insert(key.to_string(), Value::Bool(value));
    }
}

fn api_language(language: &str) -> String {
    language.replace('_', "-")
}

fn oauth2_providers(settings: &DashboardSettings) -> Vec<String> {
    let mut providers = settings.oauth2.keys().cloned().collect::<Vec<_>>();
    providers.sort();
    providers
}

fn ignored_ip_notification_server_ids(raw: &str) -> HashMap<u64, bool> {
    raw.split(',')
        .filter_map(|item| item.trim().parse::<u64>().ok())
        .map(|id| (id, true))
        .collect()
}

fn apply_setting_patch(settings: &mut DashboardSettings, patch: SettingPatch) -> Result<()> {
    if let Some(language) = patch.language {
        let language = normalize_language(&language);
        anyhow::ensure!(language.len() >= 2, "language is invalid");
        settings.language = language;
    }
    if let Some(site_name) = patch.site_name {
        let site_name = site_name.trim().to_string();
        anyhow::ensure!(!site_name.is_empty(), "site_name can't be empty");
        settings.site_name = site_name;
    }
    if let Some(custom_code) = patch.custom_code {
        settings.custom_code = custom_code;
    }
    if let Some(custom_code_dashboard) = patch.custom_code_dashboard {
        settings.custom_code_dashboard = custom_code_dashboard;
    }
    if let Some(install_host) = patch.install_host {
        settings.install_host = install_host.trim().to_string();
    }
    if let Some(tls) = patch.tls {
        settings.tls = tls;
    }
    if let Some(dns_servers) = patch.dns_servers {
        settings.dns_servers = dns_servers;
    }
    if let Some(ignored_ip_notification) = patch.ignored_ip_notification {
        settings.ignored_ip_notification = ignored_ip_notification;
    }
    if let Some(ip_change_notification_group_id) = patch.ip_change_notification_group_id {
        settings.ip_change_notification_group_id = ip_change_notification_group_id;
    }
    if let Some(cover) = patch.cover {
        settings.cover = cover;
    }
    if let Some(web_real_ip_header) = patch.web_real_ip_header {
        settings.web_real_ip_header = web_real_ip_header.trim().to_string();
    }
    if let Some(agent_real_ip_header) = patch.agent_real_ip_header {
        settings.agent_real_ip_header = agent_real_ip_header.trim().to_string();
    }
    if let Some(user_template) = patch.user_template {
        anyhow::ensure!(
            frontend::has_user_template(&user_template),
            "invalid user template"
        );
        settings.user_template = user_template;
    }
    if let Some(enable_ip_change_notification) = patch.enable_ip_change_notification {
        settings.enable_ip_change_notification = enable_ip_change_notification;
    }
    if let Some(enable_plain_ip_in_notification) = patch.enable_plain_ip_in_notification {
        settings.enable_plain_ip_in_notification = enable_plain_ip_in_notification;
    }
    if let Some(oauth2) = patch.oauth2 {
        for config in oauth2.values() {
            validate_oauth2_config(config)?;
        }
        settings.oauth2 = oauth2
            .into_iter()
            .map(|(provider, config)| (provider.to_ascii_lowercase(), config))
            .collect();
    }
    Ok(())
}

fn normalize_language(language: &str) -> String {
    language.trim().replace('-', "_")
}

fn period_seconds(period: &str) -> Option<u64> {
    match period {
        "1d" => Some(24 * 3600),
        "7d" => Some(7 * 24 * 3600),
        "30d" => Some(30 * 24 * 3600),
        _ => None,
    }
}

fn issue_token(state: &HttpState, uid: u64, username: &str, role: u8) -> Result<LoginResponse> {
    let exp = unix_now() + state.jwt_timeout_hours.saturating_mul(3600);
    let claims = Claims {
        sub: uid.to_string(),
        uid,
        username: username.to_string(),
        role,
        exp: exp as usize,
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .context("failed to sign jwt")?;

    Ok(LoginResponse {
        token,
        expire: exp.to_string(),
    })
}

fn default_oauth2_login_type() -> u8 {
    1
}

fn validate_oauth2_config(config: &OAuth2Config) -> Result<()> {
    anyhow::ensure!(
        !config.client_id.trim().is_empty(),
        "oauth2 client_id is required"
    );
    anyhow::ensure!(
        !config.client_secret.trim().is_empty(),
        "oauth2 client_secret is required"
    );
    anyhow::ensure!(
        config.endpoint.auth_url.starts_with("http://")
            || config.endpoint.auth_url.starts_with("https://"),
        "oauth2 auth_url is invalid"
    );
    anyhow::ensure!(
        config.endpoint.token_url.starts_with("http://")
            || config.endpoint.token_url.starts_with("https://"),
        "oauth2 token_url is invalid"
    );
    anyhow::ensure!(
        config.user_info_url.starts_with("http://") || config.user_info_url.starts_with("https://"),
        "oauth2 user_info_url is invalid"
    );
    Ok(())
}

fn oauth2_redirect_url(headers: &HeaderMap) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|value| *value == "https")
        .map(|_| "https")
        .or_else(|| {
            headers
                .get("referer")
                .and_then(|value| value.to_str().ok())
                .filter(|value| value.starts_with("https://"))
                .map(|_| "https")
        })
        .unwrap_or("http");
    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost");
    format!("{scheme}://{host}/api/v1/oauth2/callback")
}

fn oauth2_auth_url(config: &OAuth2Config, redirect_url: &str, state: &str) -> String {
    let mut url = config.endpoint.auth_url.clone();
    let separator = if url.contains('?') { '&' } else { '?' };
    let scope = config.scopes.join(" ");
    url.push(separator);
    url.push_str(&form_pairs(&[
        ("response_type", "code"),
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", redirect_url),
        ("scope", scope.as_str()),
        ("state", state),
    ]));
    url
}

fn encode_oauth2_state_cookie(state: &HttpState, claims: &OAuth2StateClaims) -> Result<String> {
    let token = encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .context("failed to sign oauth2 state")?;
    Ok(format!(
        "nz-o2s={}; Path=/; Max-Age=300; SameSite=Lax; HttpOnly",
        token
    ))
}

fn oauth2_state_from_headers(state: &HttpState, headers: &HeaderMap) -> Result<OAuth2StateClaims> {
    let token = cookie_value(headers, "nz-o2s").context("invalid state key")?;
    Ok(decode::<OAuth2StateClaims>(
        &token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .context("invalid state key")?
    .claims)
}

fn jwt_cookie(token: &str, timeout_hours: u64) -> String {
    format!(
        "nz-jwt={}; Path=/; Max-Age={}; SameSite=Lax; HttpOnly",
        token,
        timeout_hours.saturating_mul(3600)
    )
}

async fn exchange_oauth2_open_id(
    config: &OAuth2Config,
    code: &str,
    redirect_url: &str,
) -> Result<String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build oauth2 client")?;
    let token_response = client
        .post(&config.endpoint.token_url)
        .header("accept", "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_url),
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
        ])
        .send()
        .await
        .context("failed to exchange oauth2 code")?;
    let token_body = token_response
        .text()
        .await
        .context("failed to read oauth2 token response")?;
    let token_json = serde_json::from_str::<Value>(&token_body)
        .context("failed to decode oauth2 token response")?;
    let access_token = token_json
        .get("access_token")
        .and_then(Value::as_str)
        .context("oauth2 access_token missing")?;
    let user_info_body = client
        .get(&config.user_info_url)
        .bearer_auth(access_token)
        .send()
        .await
        .context("failed to fetch oauth2 user info")?
        .text()
        .await
        .context("failed to read oauth2 user info")?;
    let user_info = serde_json::from_str::<Value>(&user_info_body)
        .context("failed to decode oauth2 user info")?;
    let open_id = json_path_string(&user_info, &config.user_id_path)
        .filter(|value| !value.is_empty())
        .context("oauth2 user id missing")?;
    Ok(open_id)
}

fn json_path_string(value: &Value, path: &str) -> Option<String> {
    let mut current = value;
    for segment in json_path_segments(path) {
        if segment.is_empty() {
            continue;
        }
        if segment == "#" {
            return current.as_array().map(|items| items.len().to_string());
        }
        current = if let Some(index) = segment.parse::<usize>().ok() {
            current
                .as_array()
                .and_then(|items| items.get(index))
                .or_else(|| current.get(segment.as_str()))?
        } else {
            current.get(segment.as_str())?
        };
    }
    current
        .as_str()
        .map(ToOwned::to_owned)
        .or_else(|| current.as_u64().map(|value| value.to_string()))
        .or_else(|| current.as_i64().map(|value| value.to_string()))
        .or_else(|| current.as_f64().map(|value| value.to_string()))
        .or_else(|| current.as_bool().map(|value| value.to_string()))
}

fn json_path_segments(path: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = path.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            '.' => {
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
            }
            '[' => {
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
                let mut bracket = String::new();
                let mut quote = None;
                while let Some(next) = chars.next() {
                    if let Some(quote_ch) = quote {
                        if next == '\\' {
                            if let Some(escaped) = chars.next() {
                                bracket.push(escaped);
                            }
                        } else if next == quote_ch {
                            quote = None;
                        } else {
                            bracket.push(next);
                        }
                    } else if next == '"' || next == '\'' {
                        quote = Some(next);
                    } else if next == ']' {
                        break;
                    } else {
                        bracket.push(next);
                    }
                }
                if !bracket.trim().is_empty() {
                    segments.push(bracket.trim().to_string());
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

fn auth_from_headers_optional(state: &HttpState, headers: &HeaderMap) -> Result<Option<Claims>> {
    request_token(headers)
        .map(|token| decode_token(state, &token))
        .transpose()
}

fn auth_from_headers_optional_by_policy(
    state: &HttpState,
    headers: &HeaderMap,
) -> Result<Option<Claims>> {
    if state.force_auth {
        require_auth(state, headers).map(Some)
    } else {
        auth_from_headers_optional(state, headers)
    }
}

fn auth_from_request_optional(
    state: &HttpState,
    headers: &HeaderMap,
    query: &HashMap<String, String>,
) -> Result<Option<Claims>> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(header_token)
        .or_else(|| query.get("token").cloned())
        .or_else(|| cookie_token(headers))
        .map(|token| decode_token(state, &token))
        .transpose()
}

fn auth_from_request_optional_by_policy(
    state: &HttpState,
    headers: &HeaderMap,
    query: &HashMap<String, String>,
) -> Result<Option<Claims>> {
    if state.force_auth {
        require_auth_from_request(state, headers, query).map(Some)
    } else {
        auth_from_request_optional(state, headers, query)
    }
}

fn form_pairs(items: &[(&str, &str)]) -> String {
    items
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode(raw: &str) -> String {
    raw.bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            b' ' => vec!['+'],
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn record_oauth2_failure(state: &HttpState, headers: &HeaderMap) {
    if let Some(ip) = request_ip(headers)
        && let Ok(store) = state.dashboard.store.lock()
    {
        let _ = store.record_waf_block(&ip, 2, -1);
    }
}

fn require_auth(state: &HttpState, headers: &HeaderMap) -> Result<Claims> {
    let token = request_token(headers).context("unauthorized")?;
    decode_token(state, &token)
}

fn require_auth_from_request(
    state: &HttpState,
    headers: &HeaderMap,
    query: &HashMap<String, String>,
) -> Result<Claims> {
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(header_token)
        .or_else(|| query.get("token").cloned())
        .or_else(|| cookie_token(headers))
        .context("unauthorized")?;
    decode_token(state, &token)
}

fn request_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(header_token)
        .or_else(|| cookie_token(headers))
}

fn header_token(raw: &str) -> String {
    raw.strip_prefix("Bearer ").unwrap_or(raw).to_string()
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, "nz-jwt")
}

fn cookie_value(headers: &HeaderMap, target: &str) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| {
            raw.split(';').find_map(|cookie| {
                let (name, value) = cookie.trim().split_once('=')?;
                (name == target).then(|| value.to_string())
            })
        })
}

fn decode_token(state: &HttpState, token: &str) -> Result<Claims> {
    let claims = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .context("unauthorized")?
    .claims;
    Ok(claims)
}

fn require_admin(state: &HttpState, headers: &HeaderMap) -> Result<Claims> {
    let claims = require_auth(state, headers)?;
    anyhow::ensure!(claims.role == 0, "permission denied");
    Ok(claims)
}

fn id_list(body: Value) -> Vec<u64> {
    if let Some(ids) = body.as_array() {
        return ids.iter().filter_map(Value::as_u64).collect();
    }
    body.get("ids")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default()
}

fn api_error(status: StatusCode, error: impl Into<String>) -> axum::response::Response {
    let error = i18n::translate(&error.into());
    (
        status,
        Json(CommonResponse::<serde_json::Value>::err(error)),
    )
        .into_response()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[test]
    fn jwt_roundtrip() {
        let state = HttpState {
            dashboard: Arc::new(crate::DashboardState::new_for_test()),
            jwt_secret: "secret".into(),
            jwt_timeout_hours: 1,
            site_name: "Nezha".into(),
            debug: false,
            force_auth: false,
            agent_tls: false,
            install_host: String::new(),
            static_dir: PathBuf::from("static"),
        };

        let token = issue_token(&state, 1, "admin", 0).unwrap().token;
        let headers = HeaderMap::from_iter([(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        )]);

        let claims = require_auth(&state, &headers).unwrap();
        assert_eq!(claims.uid, 1);
    }

    #[test]
    fn accepts_cookie_token_for_websocket_compatible_auth() {
        let state = HttpState {
            dashboard: Arc::new(crate::DashboardState::new_for_test()),
            jwt_secret: "secret".into(),
            jwt_timeout_hours: 1,
            site_name: "Nezha".into(),
            debug: false,
            force_auth: false,
            agent_tls: false,
            install_host: String::new(),
            static_dir: PathBuf::from("static"),
        };

        let token = issue_token(&state, 2, "member", 1).unwrap().token;
        let headers = HeaderMap::from_iter([(
            axum::http::header::COOKIE,
            format!("nz-jwt={token}").parse().unwrap(),
        )]);

        let claims = require_auth(&state, &headers).unwrap();
        assert_eq!(claims.uid, 2);
    }

    #[test]
    fn server_stream_hides_guest_hidden_servers_from_guests() {
        let state = HttpState {
            dashboard: Arc::new(crate::DashboardState::new_for_test()),
            jwt_secret: "secret".into(),
            jwt_timeout_hours: 1,
            site_name: "Nezha".into(),
            debug: false,
            force_auth: false,
            agent_tls: false,
            install_host: String::new(),
            static_dir: PathBuf::from("static"),
        };
        let server_id = {
            let store = state.dashboard.store.lock().unwrap();
            let server = store
                .ensure_server_for_user(uuid::Uuid::new_v4(), 0)
                .unwrap();
            store
                .update_server(
                    server.id,
                    &serde_json::json!({
                        "name": "hidden",
                        "hide_for_guest": true
                    }),
                )
                .unwrap();
            server.id
        };

        let guest_frame = server_stream_frame(&state, None, true).unwrap();
        assert!(
            guest_frame
                .servers
                .iter()
                .all(|server| server.id != server_id)
        );

        let owner = Claims {
            sub: "42".into(),
            uid: 42,
            username: "member".into(),
            role: 1,
            exp: usize::MAX,
        };
        state
            .dashboard
            .store
            .lock()
            .unwrap()
            .move_servers(&[server_id], 42)
            .unwrap();
        let owner_frame = server_stream_frame(&state, Some(&owner), true).unwrap();
        assert!(
            owner_frame
                .servers
                .iter()
                .any(|server| server.id == server_id)
        );
    }

    #[test]
    fn server_management_requires_owner_or_admin() {
        let state = HttpState {
            dashboard: Arc::new(crate::DashboardState::new_for_test()),
            jwt_secret: "secret".into(),
            jwt_timeout_hours: 1,
            site_name: "Nezha".into(),
            debug: false,
            force_auth: false,
            agent_tls: false,
            install_host: String::new(),
            static_dir: PathBuf::from("static"),
        };
        let server_id = {
            let store = state.dashboard.store.lock().unwrap();
            let server = store
                .ensure_server_for_user(uuid::Uuid::new_v4(), 0)
                .unwrap();
            store.move_servers(&[server.id], 100).unwrap();
            server.id
        };
        let owner = Claims {
            sub: "100".into(),
            uid: 100,
            username: "alice".into(),
            role: 1,
            exp: usize::MAX,
        };
        let foreign = Claims {
            sub: "200".into(),
            uid: 200,
            username: "bob".into(),
            role: 1,
            exp: usize::MAX,
        };
        let admin = Claims {
            sub: "1".into(),
            uid: 1,
            username: "admin".into(),
            role: 0,
            exp: usize::MAX,
        };

        assert!(user_can_manage_server(&state, &owner, server_id).unwrap());
        assert!(user_can_manage_server(&state, &admin, server_id).unwrap());
        assert!(!user_can_manage_server(&state, &foreign, server_id).unwrap());
        assert!(!user_can_manage_server(&state, &foreign, 9999).unwrap());
    }

    #[test]
    fn permission_matrix_filters_and_validates_owned_resources() {
        let store = Store::open(":memory:").unwrap();
        let alice_id = store.create_user("alice", "secret1", 1).unwrap();
        let bob_id = store.create_user("bob", "secret2", 1).unwrap();
        let alice_server = store
            .ensure_server_for_user(uuid::Uuid::new_v4(), alice_id)
            .unwrap();
        let bob_server = store
            .ensure_server_for_user(uuid::Uuid::new_v4(), bob_id)
            .unwrap();
        let alice_group = store
            .upsert_notification_group(None, alice_id, "alice-ng", &[])
            .unwrap()
            .group
            .id;
        let bob_group = store
            .upsert_notification_group(None, bob_id, "bob-ng", &[])
            .unwrap()
            .group
            .id;
        let alice_cron = store
            .upsert_cron(
                None,
                alice_id,
                &serde_json::json!({
                    "name": "alice-cron",
                    "servers": [alice_server.id],
                    "notification_group_id": alice_group
                }),
            )
            .unwrap();

        let alice = Claims {
            sub: alice_id.to_string(),
            uid: alice_id,
            username: "alice".into(),
            role: 1,
            exp: usize::MAX,
        };
        let admin = Claims {
            sub: "1".into(),
            uid: 1,
            username: "admin".into(),
            role: 0,
            exp: usize::MAX,
        };

        let visible = filter_owned(store.list_servers().unwrap(), &alice, |server| {
            server.user_id
        });
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, alice_server.id);
        assert!(validate_server_ids(&store, &alice, &[alice_server.id]).is_ok());
        assert!(validate_server_ids(&store, &alice, &[bob_server.id]).is_err());
        assert!(validate_server_ids(&store, &admin, &[bob_server.id]).is_ok());
        assert!(validate_notification_group_ref(&store, &alice, alice_group).is_ok());
        assert!(validate_notification_group_ref(&store, &alice, bob_group).is_err());

        assert!(
            validate_monitor_references(
                &store,
                &alice,
                &serde_json::json!({
                    "skip_servers": { alice_server.id.to_string(): true },
                    "trigger_tasks": { alice_cron.id.to_string(): true },
                    "notification_group_id": alice_group
                }),
            )
            .is_ok()
        );
        assert!(
            validate_cron_references(
                &store,
                &alice,
                &serde_json::json!({
                    "servers": [bob_server.id],
                    "notification_group_id": alice_group
                }),
            )
            .is_err()
        );
    }

    #[test]
    fn service_server_visibility_matches_upstream_optional_auth() {
        let store = Store::open(":memory:").unwrap();
        let hidden = store.ensure_server_for_user(Uuid::new_v4(), 100).unwrap();
        let public = store.ensure_server_for_user(Uuid::new_v4(), 200).unwrap();
        store
            .update_server(
                hidden.id,
                &serde_json::json!({
                    "name": "hidden",
                    "hide_for_guest": true
                }),
            )
            .unwrap();
        let servers = store.list_servers().unwrap();
        let hidden = servers
            .iter()
            .find(|server| server.id == hidden.id)
            .unwrap();
        let public = servers
            .iter()
            .find(|server| server.id == public.id)
            .unwrap();
        let owner = Claims {
            sub: "100".into(),
            uid: 100,
            username: "owner".into(),
            role: 1,
            exp: usize::MAX,
        };
        let foreign = Claims {
            sub: "300".into(),
            uid: 300,
            username: "foreign".into(),
            role: 1,
            exp: usize::MAX,
        };
        let admin = Claims {
            sub: "1".into(),
            uid: 1,
            username: "admin".into(),
            role: 0,
            exp: usize::MAX,
        };

        assert!(!user_can_view_server(None, hidden));
        assert!(user_can_view_server(None, public));
        assert!(user_can_view_server(Some(&owner), hidden));
        assert!(!user_can_view_server(Some(&foreign), hidden));
        assert!(user_can_view_server(Some(&foreign), public));
        assert!(user_can_view_server(Some(&admin), hidden));
    }

    #[test]
    fn setting_response_filters_guest_and_admin_fields_like_upstream() {
        let mut settings = DashboardSettings {
            language: "zh_CN".to_string(),
            site_name: "Nezha RS".to_string(),
            custom_code: "<script></script>".to_string(),
            custom_code_dashboard: String::new(),
            install_host: "https://example.com".to_string(),
            tls: true,
            dns_servers: "1.1.1.1".to_string(),
            ignored_ip_notification: "1, 2".to_string(),
            ip_change_notification_group_id: 9,
            cover: 1,
            web_real_ip_header: "X-Real-IP".to_string(),
            agent_real_ip_header: String::new(),
            user_template: "user-dist".to_string(),
            admin_template: "admin-dist".to_string(),
            enable_ip_change_notification: true,
            enable_plain_ip_in_notification: false,
            oauth2: HashMap::new(),
        };
        settings.oauth2.insert(
            "github".to_string(),
            OAuth2Config {
                client_id: "id".to_string(),
                client_secret: "secret".to_string(),
                endpoint: crate::store::OAuth2Endpoint::default(),
                scopes: Vec::new(),
                user_info_url: "https://example.com/user".to_string(),
                user_id_path: "id".to_string(),
            },
        );
        let admin = Claims {
            sub: "1".into(),
            uid: 1,
            username: "admin".into(),
            role: 0,
            exp: usize::MAX,
        };

        let guest = serde_json::to_value(setting_response(&settings, None)).unwrap();
        let guest_config = guest["config"].as_object().unwrap();
        assert_eq!(guest_config["language"], "zh-CN");
        assert_eq!(guest_config["site_name"], "Nezha RS");
        assert_eq!(guest_config["custom_code"], "<script></script>");
        assert_eq!(
            guest_config["oauth2_providers"],
            serde_json::json!(["github"])
        );
        assert_eq!(guest["tsdb_enabled"], true);
        assert!(guest.get("version").is_none());
        assert!(guest.get("frontend_templates").is_none());
        assert!(!guest_config.contains_key("install_host"));
        assert!(!guest_config.contains_key("dns_servers"));

        let admin_value = serde_json::to_value(setting_response(&settings, Some(&admin))).unwrap();
        let admin_config = admin_value["config"].as_object().unwrap();
        assert!(
            admin_value["version"]
                .as_str()
                .is_some_and(|v| !v.is_empty())
        );
        assert!(
            admin_value["frontend_templates"]
                .as_array()
                .is_some_and(|v| v.len() == 4)
        );
        assert_eq!(admin_value["frontend_templates"][0]["path"], "admin-dist");
        assert_eq!(admin_value["frontend_templates"][0]["version"], "v2.0.7");
        assert_eq!(admin_config["install_host"], "https://example.com");
        assert_eq!(admin_config["tls"], true);
        assert_eq!(admin_config["dns_servers"], "1.1.1.1");
        assert_eq!(
            admin_config["ignored_ip_notification_server_ids"]["1"],
            true
        );
        assert_eq!(admin_config["ip_change_notification_group_id"], 9);
        assert_eq!(admin_config["cover"], 1);
        assert_eq!(admin_config["web_real_ip_header"], "X-Real-IP");
        assert_eq!(admin_config["user_template"], "user-dist");
        assert_eq!(admin_config["admin_template"], "admin-dist");
        assert_eq!(admin_config["enable_ip_change_notification"], true);
        assert!(!admin_config.contains_key("enable_plain_ip_in_notification"));
    }

    #[test]
    fn router_builds_with_dashboard_routes() {
        let state = HttpState {
            dashboard: Arc::new(crate::DashboardState::new_for_test()),
            jwt_secret: "secret".into(),
            jwt_timeout_hours: 1,
            site_name: "Nezha".into(),
            debug: false,
            force_auth: false,
            agent_tls: false,
            install_host: String::new(),
            static_dir: PathBuf::from("static"),
        };

        let _router = router(state);
    }

    #[tokio::test]
    async fn password_login_sets_jwt_cookie_for_admin_frontend() {
        let state = HttpState {
            dashboard: Arc::new(crate::DashboardState::new_for_test()),
            jwt_secret: "secret".into(),
            jwt_timeout_hours: 1,
            site_name: "Nezha".into(),
            debug: false,
            force_auth: false,
            agent_tls: false,
            install_host: String::new(),
            static_dir: PathBuf::from("static"),
        };
        state
            .dashboard
            .store
            .lock()
            .unwrap()
            .ensure_admin("admin", "secret")
            .unwrap();

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"username":"admin","password":"secret"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert!(cookie.starts_with("nz-jwt="));
        assert!(cookie.contains("HttpOnly"));
    }

    #[tokio::test]
    async fn frontend_fallback_serves_spa_index_and_static_assets() {
        let static_dir = temp_static_dir("frontend");
        let admin_dir = static_dir.join("admin-dist");
        let custom_admin_dir = static_dir.join("custom-admin-dist");
        let user_dir = static_dir.join("user-dist");
        std::fs::create_dir_all(&admin_dir).unwrap();
        std::fs::create_dir_all(&custom_admin_dir).unwrap();
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(admin_dir.join("index.html"), "<admin></admin>").unwrap();
        std::fs::write(admin_dir.join("app.js"), "console.log('ok')").unwrap();
        std::fs::write(
            custom_admin_dir.join("index.html"),
            "<custom-admin></custom-admin>",
        )
        .unwrap();
        std::fs::write(custom_admin_dir.join("custom.js"), "console.log('custom')").unwrap();
        std::fs::write(user_dir.join("index.html"), "<user></user>").unwrap();

        let state = HttpState {
            dashboard: Arc::new(crate::DashboardState::new_for_test()),
            jwt_secret: "secret".into(),
            jwt_timeout_hours: 1,
            site_name: "Nezha".into(),
            debug: false,
            force_auth: false,
            agent_tls: false,
            install_host: String::new(),
            static_dir: static_dir.clone(),
        };
        state
            .dashboard
            .store
            .lock()
            .unwrap()
            .save_dashboard_settings(&DashboardSettings {
                admin_template: "custom-admin-dist".to_string(),
                ..DashboardSettings::default()
            })
            .unwrap();

        let dashboard = frontend_fallback(
            State(state.clone()),
            Request::builder()
                .uri("/dashboard/service")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(dashboard.status(), StatusCode::OK);

        let asset = frontend_fallback(
            State(state.clone()),
            Request::builder()
                .uri("/dashboard/custom.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(asset.status(), StatusCode::OK);
        assert_eq!(
            asset.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/javascript; charset=utf-8"
        );

        let unknown = frontend_fallback(
            State(state),
            Request::builder()
                .uri("/dashboard/not-a-page")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

        let _ = std::fs::remove_dir_all(static_dir);
    }

    #[tokio::test]
    async fn frontend_fallback_serves_direct_template_paths_like_upstream() {
        let static_dir = temp_static_dir("frontend-direct");
        let direct_admin_dir = temp_static_dir("frontend-direct-admin");
        std::fs::create_dir_all(&direct_admin_dir).unwrap();
        std::fs::write(
            direct_admin_dir.join("index.html"),
            "<direct-admin></direct-admin>",
        )
        .unwrap();
        std::fs::write(direct_admin_dir.join("custom.js"), "console.log('direct')").unwrap();

        let state = HttpState {
            dashboard: Arc::new(crate::DashboardState::new_for_test()),
            jwt_secret: "secret".into(),
            jwt_timeout_hours: 1,
            site_name: "Nezha".into(),
            debug: false,
            force_auth: false,
            agent_tls: false,
            install_host: String::new(),
            static_dir: static_dir.clone(),
        };
        state
            .dashboard
            .store
            .lock()
            .unwrap()
            .save_dashboard_settings(&DashboardSettings {
                admin_template: direct_admin_dir.to_string_lossy().to_string(),
                ..DashboardSettings::default()
            })
            .unwrap();

        let dashboard = frontend_fallback(
            State(state.clone()),
            Request::builder()
                .uri("/dashboard/service")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(dashboard.status(), StatusCode::OK);

        let asset = frontend_fallback(
            State(state),
            Request::builder()
                .uri("/dashboard/custom.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(asset.status(), StatusCode::OK);
        let asset_body = String::from_utf8(
            axum::body::to_bytes(asset.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(asset_body.contains("direct"));

        let _ = std::fs::remove_dir_all(static_dir);
        let _ = std::fs::remove_dir_all(direct_admin_dir);
    }

    #[tokio::test]
    async fn frontend_fallback_serves_embedded_assets_without_static_dir() {
        let state = HttpState {
            dashboard: Arc::new(crate::DashboardState::new_for_test()),
            jwt_secret: "secret".into(),
            jwt_timeout_hours: 1,
            site_name: "Nezha".into(),
            debug: false,
            force_auth: false,
            agent_tls: false,
            install_host: String::new(),
            static_dir: PathBuf::from("__missing_static_dir__"),
        };

        let user = frontend_fallback(
            State(state.clone()),
            Request::builder().uri("/").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(user.status(), StatusCode::OK);
        let user_body = String::from_utf8(
            axum::body::to_bytes(user.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(user_body.contains("Nezha Monitoring"));

        let admin = frontend_fallback(
            State(state),
            Request::builder()
                .uri("/dashboard/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(admin.status(), StatusCode::OK);
        let admin_body = String::from_utf8(
            axum::body::to_bytes(admin.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(admin_body.contains("dashboard/assets/"));
    }

    #[tokio::test]
    async fn frontend_fallback_redirects_dashboard_and_keeps_api_404_json() {
        let state = HttpState {
            dashboard: Arc::new(crate::DashboardState::new_for_test()),
            jwt_secret: "secret".into(),
            jwt_timeout_hours: 1,
            site_name: "Nezha".into(),
            debug: false,
            force_auth: false,
            agent_tls: false,
            install_host: String::new(),
            static_dir: PathBuf::from("static"),
        };

        let redirect = frontend_fallback(
            State(state.clone()),
            Request::builder()
                .uri("/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(redirect.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            redirect.headers().get(header::LOCATION).unwrap(),
            "/dashboard/"
        );

        let api = frontend_fallback(
            State(state),
            Request::builder()
                .uri("/api/v1/missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(api.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            api.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn swagger_routes_redirect_and_serve_generated_doc() {
        let redirect = swagger_root().await.into_response();
        assert_eq!(redirect.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            redirect.headers().get(header::LOCATION).unwrap(),
            "/swagger/index.html"
        );

        let doc = swagger_asset(Path("doc.json".to_string())).await;
        assert_eq!(doc.status(), StatusCode::OK);
        assert_eq!(
            doc.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json; charset=utf-8"
        );
        let body = axum::body::to_bytes(doc.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["openapi"], "3.0.3");
        assert_eq!(json["info"]["title"], "Nezha Monitoring API");
        assert!(json["paths"].get("/api/v1/login").is_some());
        assert!(json["paths"].get("/api/v1/service").is_some());
    }

    #[tokio::test]
    async fn swagger_routes_are_debug_only() {
        let disabled = HttpState {
            dashboard: Arc::new(crate::DashboardState::new_for_test()),
            jwt_secret: "secret".into(),
            jwt_timeout_hours: 1,
            site_name: "Nezha".into(),
            debug: false,
            force_auth: false,
            agent_tls: false,
            install_host: String::new(),
            static_dir: PathBuf::from("__missing_static_dir__"),
        };
        let enabled = HttpState {
            debug: true,
            ..disabled.clone()
        };

        let disabled_response = router(disabled)
            .oneshot(
                Request::builder()
                    .uri("/swagger/index.html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disabled_response.status(), StatusCode::NOT_FOUND);

        let enabled_response = router(enabled)
            .oneshot(
                Request::builder()
                    .uri("/swagger/index.html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(enabled_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn swagger_assets_serve_local_ui_files() {
        let index = swagger_asset(Path("index.html".to_string())).await;
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(
            index.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let html = String::from_utf8(
            axum::body::to_bytes(index.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("./doc.json"));
        assert!(html.contains("./swagger-ui-bundle.js"));
        assert!(html.contains("./swagger-ui.css"));

        let js = swagger_asset(Path("swagger-ui-bundle.js".to_string())).await;
        assert_eq!(js.status(), StatusCode::OK);
        assert_eq!(
            js.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/javascript; charset=utf-8"
        );

        let missing = swagger_asset(Path("missing.js".to_string())).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn waf_block_page_matches_upstream_template() {
        let response = waf_block_response("custom block reason");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert_eq!(
            body,
            UPSTREAM_WAF_HTML.replace("{error}", "custom block reason")
        );
        assert!(body.contains("class=\"secondary\""));
    }

    fn temp_static_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("nezha-dashboard-{name}-{nanos}"))
    }

    #[test]
    fn setting_patch_updates_supported_dashboard_fields() {
        let mut settings = DashboardSettings::default();

        apply_setting_patch(
            &mut settings,
            SettingPatch {
                language: Some("zh-CN".to_string()),
                site_name: Some(" Nezha RS ".to_string()),
                custom_code: Some("<script></script>".to_string()),
                custom_code_dashboard: Some("<style></style>".to_string()),
                install_host: Some(" https://example.com ".to_string()),
                tls: Some(true),
                dns_servers: Some("1.1.1.1,8.8.8.8".to_string()),
                ignored_ip_notification: Some("1,2".to_string()),
                ip_change_notification_group_id: Some(7),
                cover: Some(1),
                web_real_ip_header: Some(" X-Real-IP ".to_string()),
                agent_real_ip_header: Some(" CF-Connecting-IP ".to_string()),
                user_template: Some("user-dist".to_string()),
                enable_ip_change_notification: Some(true),
                enable_plain_ip_in_notification: Some(true),
                oauth2: Some(HashMap::from([(
                    "GitHub".to_string(),
                    OAuth2Config {
                        client_id: "client".into(),
                        client_secret: "secret".into(),
                        endpoint: crate::store::OAuth2Endpoint {
                            auth_url: "https://github.com/login/oauth/authorize".into(),
                            token_url: "https://github.com/login/oauth/access_token".into(),
                        },
                        scopes: vec!["user:email".into()],
                        user_info_url: "https://api.github.com/user".into(),
                        user_id_path: "id".into(),
                    },
                )])),
            },
        )
        .unwrap();

        assert_eq!(settings.language, "zh_CN");
        assert_eq!(settings.site_name, "Nezha RS");
        assert_eq!(settings.install_host, "https://example.com");
        assert!(settings.tls);
        assert_eq!(settings.web_real_ip_header, "X-Real-IP");
        assert_eq!(settings.agent_real_ip_header, "CF-Connecting-IP");
        assert_eq!(settings.ip_change_notification_group_id, 7);
        assert!(settings.enable_ip_change_notification);
        assert!(settings.enable_plain_ip_in_notification);
        assert!(settings.oauth2.contains_key("github"));
    }

    #[test]
    fn oauth2_redirect_url_and_state_cookie_match_callback_contract() {
        let state = HttpState {
            dashboard: Arc::new(crate::DashboardState::new_for_test()),
            jwt_secret: "secret".into(),
            jwt_timeout_hours: 1,
            site_name: "Nezha".into(),
            debug: false,
            force_auth: false,
            agent_tls: false,
            install_host: String::new(),
            static_dir: PathBuf::from("static"),
        };
        let headers = HeaderMap::from_iter([
            (header::HOST, "dash.example.com".parse().unwrap()),
            (
                axum::http::HeaderName::from_static("x-forwarded-proto"),
                "https".parse().unwrap(),
            ),
        ]);
        let redirect_url = oauth2_redirect_url(&headers);
        let config = OAuth2Config {
            client_id: "client id".into(),
            client_secret: "secret".into(),
            endpoint: crate::store::OAuth2Endpoint {
                auth_url: "https://idp.example.com/authorize".into(),
                token_url: "https://idp.example.com/token".into(),
            },
            scopes: vec!["openid".into(), "profile".into()],
            user_info_url: "https://idp.example.com/user".into(),
            user_id_path: "sub".into(),
        };
        let auth_url = oauth2_auth_url(&config, &redirect_url, "state-1");

        assert_eq!(
            redirect_url,
            "https://dash.example.com/api/v1/oauth2/callback"
        );
        assert!(auth_url.contains("client_id=client+id"));
        assert!(auth_url.contains(
            "redirect_uri=https%3A%2F%2Fdash.example.com%2Fapi%2Fv1%2Foauth2%2Fcallback"
        ));
        assert!(auth_url.contains("scope=openid+profile"));
        assert!(auth_url.contains("state=state-1"));

        let cookie = encode_oauth2_state_cookie(
            &state,
            &OAuth2StateClaims {
                action: 2,
                provider: "github".into(),
                state: "state-1".into(),
                redirect_url,
                exp: (unix_now() + 300) as usize,
            },
        )
        .unwrap();
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
    }

    #[test]
    fn oauth2_user_id_path_supports_gjson_like_segments() {
        let value = serde_json::json!({
            "data": {
                "users": [
                    {"id": 7},
                    {"id": "second"}
                ],
                "profile.name": {
                    "sub": true
                }
            }
        });

        assert_eq!(
            json_path_string(&value, "data.users.0.id"),
            Some("7".into())
        );
        assert_eq!(
            json_path_string(&value, "data.users[1].id"),
            Some("second".into())
        );
        assert_eq!(
            json_path_string(&value, r#"data.profile\.name.sub"#),
            Some("true".into())
        );
        assert_eq!(json_path_string(&value, "data.users.#"), Some("2".into()));
    }

    #[test]
    fn setting_patch_rejects_invalid_template_and_empty_site_name() {
        let mut settings = DashboardSettings::default();

        assert!(
            apply_setting_patch(
                &mut settings,
                SettingPatch {
                    site_name: Some(" ".to_string()),
                    language: None,
                    custom_code: None,
                    custom_code_dashboard: None,
                    install_host: None,
                    tls: None,
                    dns_servers: None,
                    ignored_ip_notification: None,
                    ip_change_notification_group_id: None,
                    cover: None,
                    web_real_ip_header: None,
                    agent_real_ip_header: None,
                    user_template: None,
                    enable_ip_change_notification: None,
                    enable_plain_ip_in_notification: None,
                    oauth2: None,
                },
            )
            .is_err()
        );

        assert!(
            apply_setting_patch(
                &mut settings,
                SettingPatch {
                    user_template: Some("nazhua-dist".to_string()),
                    language: None,
                    site_name: None,
                    custom_code: None,
                    custom_code_dashboard: None,
                    install_host: None,
                    tls: None,
                    dns_servers: None,
                    ignored_ip_notification: None,
                    ip_change_notification_group_id: None,
                    cover: None,
                    web_real_ip_header: None,
                    agent_real_ip_header: None,
                    enable_ip_change_notification: None,
                    enable_plain_ip_in_notification: None,
                    oauth2: None,
                },
            )
            .is_ok()
        );

        assert!(
            apply_setting_patch(
                &mut settings,
                SettingPatch {
                    user_template: Some("admin-dist".to_string()),
                    language: None,
                    site_name: None,
                    custom_code: None,
                    custom_code_dashboard: None,
                    install_host: None,
                    tls: None,
                    dns_servers: None,
                    ignored_ip_notification: None,
                    ip_change_notification_group_id: None,
                    cover: None,
                    web_real_ip_header: None,
                    agent_real_ip_header: None,
                    enable_ip_change_notification: None,
                    enable_plain_ip_in_notification: None,
                    oauth2: None,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn accepts_upstream_and_legacy_batch_delete_shapes() {
        assert_eq!(id_list(serde_json::json!([1, 2])), vec![1, 2]);
        assert_eq!(id_list(serde_json::json!({ "ids": [3, 4] })), vec![3, 4]);
    }

    #[test]
    fn online_user_helpers_unique_and_mask_ips() {
        assert_eq!(
            unique_strings(vec![
                " 203.0.113.10 ".to_string(),
                "203.0.113.10".to_string(),
                String::new(),
                "2001:db8::1".to_string(),
            ]),
            vec!["203.0.113.10".to_string(), "2001:db8::1".to_string()]
        );
        assert_eq!(desensitize_ip("203.0.113.10"), "203.0.113.*");
        assert_eq!(
            desensitize_ip("2001:db8::1"),
            "2001:db8:0:0:****:****:****:****"
        );
    }

    #[test]
    fn real_ip_header_uses_last_valid_forwarded_ip() {
        assert_eq!(
            parse_ip_from_header("198.51.100.1, 203.0.113.10").unwrap(),
            "203.0.113.10"
        );
        assert!(parse_ip_from_header("not an ip").is_err());

        let headers = HeaderMap::from_iter([(
            "x-forwarded-for".parse().unwrap(),
            "198.51.100.1, 203.0.113.10".parse().unwrap(),
        )]);
        assert_eq!(request_ip(&headers), Some("203.0.113.10".to_string()));
    }
}
