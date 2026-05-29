mod ddns;
mod frontend;
mod http;
mod i18n;
mod iostream;
mod notification;
mod scheduler;
mod store;

use std::{
    collections::{HashMap, HashSet},
    env, fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use async_stream::try_stream;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use clap::Parser;
use futures_util::Stream;
use nezha_core::{CRON_COVER_ALERT_TRIGGER, TaskType};
use nezha_proto::{
    GeoIp, Host, IoStreamData, Receipt, State, Task, TaskResult, Uint64Receipt,
    nezha_service_server::{NezhaService, NezhaServiceServer},
};
use tokio::{
    net::TcpListener,
    sync::{RwLock, mpsc, oneshot},
    time,
};
use tonic::{
    Request, Response, Status, Streaming,
    metadata::MetadataMap,
    transport::{Identity, Server, ServerTlsConfig},
};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{ddns::update_server_ddns, store::CronResource};

const SERVICE_STATUS_UNSET: u8 = 0;
const SERVICE_STATUS_NO_DATA: u8 = 1;
const SERVICE_STATUS_GOOD: u8 = 2;
const SERVICE_STATUS_LOW_AVAILABILITY: u8 = 3;
const SERVICE_STATUS_DOWN: u8 = 4;
const SERVICE_CURRENT_STATUS_SIZE: usize = 30;

#[derive(Debug, clap::Subcommand)]
enum DashboardCommand {
    SyncFrontends,
    ResetAdminPassword,
}

#[derive(Debug, Parser)]
#[command(version, about = "Nezha Dashboard rewritten in Rust")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:5555")]
    bind: SocketAddr,

    #[arg(long, default_value = "0.0.0.0:8008")]
    http_bind: SocketAddr,

    #[arg(short = 'c', long, default_value = "data/config.yaml")]
    config: PathBuf,

    #[arg(long, env = "NZ_CLIENT_SECRET")]
    client_secret: Option<String>,

    #[arg(long, default_value = "data/sqlite.db")]
    data: PathBuf,

    #[arg(long, default_value = "admin", env = "NZ_ADMIN_USERNAME")]
    admin_username: String,

    #[arg(long, default_value = "admin", env = "NZ_ADMIN_PASSWORD")]
    admin_password: String,

    #[arg(long, env = "NZ_JWT_SECRET")]
    jwt_secret: Option<String>,

    #[arg(long, env = "NZ_JWT_TIMEOUT")]
    jwt_timeout: Option<u64>,

    #[arg(long)]
    site_name: Option<String>,

    #[arg(long, env = "NZ_DEBUG")]
    debug: bool,

    #[arg(long, env = "NZ_FORCE_AUTH")]
    force_auth: bool,

    #[arg(long, env = "NZ_TRUST_PROXY_HEADERS")]
    trust_proxy_headers: bool,

    #[arg(long, default_value = "")]
    install_host: String,

    #[arg(long, default_value = "static")]
    static_dir: PathBuf,

    #[arg(long, default_value = "data/geoip.db")]
    geoip_db: PathBuf,

    #[arg(long, env = "NZ_TLS_CERT")]
    tls_cert: Option<PathBuf>,

    #[arg(long, env = "NZ_TLS_KEY")]
    tls_key: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<DashboardCommand>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct DashboardConfigFile {
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    site_name: Option<String>,
    #[serde(default)]
    custom_code: Option<String>,
    #[serde(default)]
    custom_code_dashboard: Option<String>,
    #[serde(default)]
    install_host: Option<String>,
    #[serde(default)]
    tls: Option<bool>,
    #[serde(default)]
    dns_servers: Option<String>,
    #[serde(default)]
    ignored_ip_notification: Option<String>,
    #[serde(default)]
    ip_change_notification_group_id: Option<u64>,
    #[serde(default)]
    cover: Option<u8>,
    #[serde(default)]
    web_real_ip_header: Option<String>,
    #[serde(default)]
    agent_real_ip_header: Option<String>,
    #[serde(default)]
    user_template: Option<String>,
    #[serde(default)]
    admin_template: Option<String>,
    #[serde(default)]
    enable_ip_change_notification: Option<bool>,
    #[serde(default)]
    enable_plain_ip_in_notification: Option<bool>,
    #[serde(default)]
    force_auth: Option<bool>,
    #[serde(default)]
    debug: Option<bool>,
    #[serde(default)]
    agent_secret_key: Option<String>,
    #[serde(default)]
    jwt_secret_key: Option<String>,
    #[serde(default)]
    jwt_timeout: Option<u64>,
    #[serde(default)]
    listen_host: Option<String>,
    #[serde(default)]
    listen_port: Option<u16>,
    #[serde(default)]
    trust_proxy_headers: Option<bool>,
    #[serde(default)]
    tls_cert: Option<PathBuf>,
    #[serde(default)]
    tls_key: Option<PathBuf>,
    #[serde(default)]
    oauth2: Option<HashMap<String, store::OAuth2Config>>,
}

#[derive(Debug)]
struct ResolvedDashboardConfig {
    client_secret: String,
    jwt_secret: String,
    jwt_timeout: u64,
    http_bind: SocketAddr,
    site_name: String,
    debug: bool,
    force_auth: bool,
    agent_tls: bool,
    install_host: String,
    trust_proxy_headers: bool,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    initial_settings: store::DashboardSettings,
}

#[derive(Debug, Clone)]
struct ServerRecord {
    id: u64,
    user_id: u64,
    host: Option<Host>,
    state: Option<State>,
    geoip: Option<GeoIp>,
    last_active_unix: u64,
}

#[derive(Debug, Clone, Copy)]
struct AuthenticatedAgent {
    uuid: Uuid,
    user_id: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct OnlineUser {
    pub(crate) user_id: u64,
    #[serde(serialize_with = "store::serialize_unix_as_rfc3339")]
    pub(crate) connected_at: u64,
    pub(crate) ip: String,
}

#[derive(Debug)]
pub(crate) struct DashboardState {
    pub(crate) client_secret: String,
    pub(crate) boot_time: u64,
    pub(crate) store: Mutex<store::Store>,
    pub(crate) io_streams: iostream::IoStreamRegistry,
    pub(crate) servers: RwLock<HashMap<Uuid, ServerRecord>>,
    pub(crate) task_senders: RwLock<HashMap<u64, mpsc::Sender<Task>>>,
    pub(crate) cycle_transfer_stats: RwLock<HashMap<u64, store::CycleTransferStats>>,
    online_users: Mutex<HashMap<String, OnlineUser>>,
    blocked_online_ips: Mutex<HashSet<String>>,
    config_waiters: Mutex<HashMap<u64, oneshot::Sender<String>>>,
    apply_config_waiters: Mutex<HashMap<u64, oneshot::Sender<(bool, String)>>>,
    pending_alert_trigger_tasks: Mutex<HashMap<u64, HashMap<u64, Vec<u64>>>>,
    service_current_results: Mutex<HashMap<(u64, u64), Vec<bool>>>,
    service_last_status: Mutex<HashMap<(u64, u64), u8>>,
    service_tls_cert_cache: Mutex<HashMap<(u64, u64), String>>,
    geoip_db: PathBuf,
    next_task_id: AtomicU64,
}

#[derive(Debug, Clone)]
struct DashboardService {
    state: Arc<DashboardState>,
}

#[derive(Debug)]
struct ServiceResultEffects {
    notifications: Vec<ServiceNotification>,
    trigger_crons: Vec<CronResource>,
}

#[derive(Debug)]
struct ServiceNotification {
    notifications: Vec<store::NotificationResource>,
    message: String,
    log_context: &'static str,
    context: Option<notification::NotificationContext>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    if let Some(DashboardCommand::SyncFrontends) = args.command {
        let synced = frontend::sync_frontends(&args.static_dir).await?;
        for path in synced {
            println!("Synced {}", path.display());
        }
        return Ok(());
    }
    if let Some(DashboardCommand::ResetAdminPassword) = args.command {
        let store = store::Store::open(&args.data)?;
        store.reset_admin_password(&args.admin_username, &args.admin_password)?;
        println!("Admin password reset for {}", args.admin_username);
        return Ok(());
    }
    let file_config = read_dashboard_config_file(&args.config)?;
    let store = store::Store::open(&args.data)?;
    store.ensure_admin(&args.admin_username, &args.admin_password)?;
    let stored_settings = store.dashboard_settings()?;
    let resolved_config = resolve_dashboard_config(&args, &file_config, stored_settings.as_ref())?;
    match stored_settings {
        None => {
            let mut initial = resolved_config.initial_settings.clone();
            initial.client_secret = resolved_config.client_secret.clone();
            initial.jwt_secret = resolved_config.jwt_secret.clone();
            store.save_dashboard_settings(&initial)?;
        }
        Some(mut existing) => {
            let mut dirty = false;
            if existing.install_host.is_empty()
                && !resolved_config.initial_settings.install_host.is_empty()
            {
                existing.install_host = resolved_config.initial_settings.install_host.clone();
                dirty = true;
            }
            if !existing.tls && resolved_config.initial_settings.tls {
                existing.tls = true;
                dirty = true;
            }
            if existing.client_secret != resolved_config.client_secret {
                existing.client_secret = resolved_config.client_secret.clone();
                dirty = true;
            }
            if existing.jwt_secret != resolved_config.jwt_secret {
                existing.jwt_secret = resolved_config.jwt_secret.clone();
                dirty = true;
            }
            if dirty {
                store.save_dashboard_settings(&existing)?;
            }
        }
    }
    let service = DashboardService {
        state: Arc::new(DashboardState {
            client_secret: resolved_config.client_secret,
            boot_time: unix_now(),
            store: Mutex::new(store),
            io_streams: iostream::IoStreamRegistry::default(),
            servers: RwLock::new(HashMap::new()),
            task_senders: RwLock::new(HashMap::new()),
            cycle_transfer_stats: RwLock::new(HashMap::new()),
            online_users: Mutex::new(HashMap::new()),
            blocked_online_ips: Mutex::new(HashSet::new()),
            config_waiters: Mutex::new(HashMap::new()),
            apply_config_waiters: Mutex::new(HashMap::new()),
            pending_alert_trigger_tasks: Mutex::new(HashMap::new()),
            service_current_results: Mutex::new(HashMap::new()),
            service_last_status: Mutex::new(HashMap::new()),
            service_tls_cert_cache: Mutex::new(HashMap::new()),
            geoip_db: args.geoip_db,
            next_task_id: AtomicU64::new(1),
        }),
    };
    let http_state = http::HttpState {
        dashboard: service.state.clone(),
        jwt_secret: resolved_config.jwt_secret,
        jwt_timeout_hours: resolved_config.jwt_timeout,
        site_name: resolved_config.site_name,
        debug: resolved_config.debug,
        force_auth: resolved_config.force_auth,
        agent_tls: resolved_config.agent_tls,
        install_host: resolved_config.install_host,
        static_dir: args.static_dir,
        trust_proxy_headers: resolved_config.trust_proxy_headers,
    };
    let http_listener = TcpListener::bind(resolved_config.http_bind).await?;
    let http_router = http::router(http_state);
    let cron_scheduler = tokio::spawn(scheduler::cron_scheduler(service.state.clone()));
    let service_scheduler =
        tokio::spawn(scheduler::service_monitor_scheduler(service.state.clone()));
    let alert_scheduler = tokio::spawn(scheduler::alert_scheduler(service.state.clone()));

    info!(bind = %args.bind, "starting rust dashboard grpc server");
    info!(bind = %resolved_config.http_bind, "starting rust dashboard http server");
    let grpc_tls = build_grpc_tls(
        resolved_config.agent_tls,
        resolved_config.tls_cert.as_deref(),
        resolved_config.tls_key.as_deref(),
    )?;
    let grpc = async move {
        let mut builder = Server::builder();
        if let Some(tls) = grpc_tls {
            builder = builder.tls_config(tls).map_err(anyhow::Error::from)?;
        }
        builder
            .add_service(NezhaServiceServer::new(service))
            .serve(args.bind)
            .await
            .map_err(anyhow::Error::from)
    };
    let http = async move {
        axum::serve(http_listener, http_router)
            .await
            .map_err(anyhow::Error::from)
    };

    tokio::try_join!(grpc, http)?;
    cron_scheduler.abort();
    service_scheduler.abort();
    alert_scheduler.abort();
    Ok(())
}

fn build_grpc_tls(
    agent_tls: bool,
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> Result<Option<ServerTlsConfig>> {
    if !agent_tls {
        if cert_path.is_some() || key_path.is_some() {
            warn!("tls cert/key configured but agent tls is disabled; ignoring tls material");
        }
        return Ok(None);
    }
    let (Some(cert_path), Some(key_path)) = (cert_path, key_path) else {
        warn!(
            "agent tls is enabled but tls_cert/tls_key are not configured; serving grpc in plaintext"
        );
        return Ok(None);
    };
    let cert_pem = fs::read(cert_path)
        .with_context(|| format!("failed to read tls cert {}", cert_path.display()))?;
    let key_pem = fs::read(key_path)
        .with_context(|| format!("failed to read tls key {}", key_path.display()))?;
    let identity = Identity::from_pem(cert_pem, key_pem);
    Ok(Some(ServerTlsConfig::new().identity(identity)))
}

fn read_dashboard_config_file(path: &Path) -> Result<DashboardConfigFile> {
    if !path.exists() {
        return Ok(DashboardConfigFile::default());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(DashboardConfigFile::default());
    }
    serde_yaml::from_str(&raw)
        .with_context(|| format!("failed to parse config file {}", path.display()))
}

fn resolve_dashboard_config(
    args: &Args,
    file: &DashboardConfigFile,
    stored: Option<&store::DashboardSettings>,
) -> Result<ResolvedDashboardConfig> {
    let client_secret = args
        .client_secret
        .clone()
        .or_else(|| env::var("NZ_AGENT_SECRET_KEY").ok())
        .or_else(|| non_empty_opt(file.agent_secret_key.clone()))
        .or_else(|| stored.and_then(|s| non_empty_opt(Some(s.client_secret.clone()))))
        .unwrap_or_else(|| generated_secret(32));
    let jwt_secret = args
        .jwt_secret
        .clone()
        .or_else(|| env::var("NZ_JWT_SECRET_KEY").ok())
        .or_else(|| non_empty_opt(file.jwt_secret_key.clone()))
        .or_else(|| stored.and_then(|s| non_empty_opt(Some(s.jwt_secret.clone()))))
        .unwrap_or_else(|| generated_secret(128));
    let jwt_timeout = args.jwt_timeout.or(file.jwt_timeout).unwrap_or(1).max(1);
    let site_name = args
        .site_name
        .clone()
        .or_else(|| file.site_name.clone())
        .unwrap_or_else(|| "Nezha".to_string());
    let install_host = if !args.install_host.is_empty() {
        args.install_host.clone()
    } else {
        file.install_host.clone().unwrap_or_default()
    };
    let agent_tls = file.tls.unwrap_or(false);
    let debug = args.debug || file.debug.unwrap_or(false);
    let force_auth = args.force_auth || file.force_auth.unwrap_or(false);
    let trust_proxy_headers = args.trust_proxy_headers || file.trust_proxy_headers.unwrap_or(false);
    let http_bind = if args.http_bind == default_http_bind() {
        config_http_bind(file)?
    } else {
        args.http_bind
    };
    let tls_cert = args.tls_cert.clone().or_else(|| file.tls_cert.clone());
    let tls_key = args.tls_key.clone().or_else(|| file.tls_key.clone());
    let initial_settings = initial_dashboard_settings(file, &site_name, &install_host, agent_tls);

    Ok(ResolvedDashboardConfig {
        client_secret,
        jwt_secret,
        jwt_timeout,
        http_bind,
        site_name,
        debug,
        force_auth,
        agent_tls,
        install_host,
        trust_proxy_headers,
        tls_cert,
        tls_key,
        initial_settings,
    })
}

fn initial_dashboard_settings(
    file: &DashboardConfigFile,
    site_name: &str,
    install_host: &str,
    agent_tls: bool,
) -> store::DashboardSettings {
    let mut settings = store::DashboardSettings {
        site_name: site_name.to_string(),
        install_host: install_host.to_string(),
        tls: agent_tls,
        ..store::DashboardSettings::default()
    };
    if let Some(value) = &file.language {
        settings.language = value.clone();
    }
    if let Some(value) = &file.custom_code {
        settings.custom_code = value.clone();
    }
    if let Some(value) = &file.custom_code_dashboard {
        settings.custom_code_dashboard = value.clone();
    }
    if let Some(value) = &file.dns_servers {
        settings.dns_servers = value.clone();
    }
    if let Some(value) = &file.ignored_ip_notification {
        settings.ignored_ip_notification = value.clone();
    }
    if let Some(value) = file.ip_change_notification_group_id {
        settings.ip_change_notification_group_id = value;
    }
    if let Some(value) = file.cover {
        settings.cover = if value == 0 { 1 } else { value };
    }
    if let Some(value) = &file.web_real_ip_header {
        settings.web_real_ip_header = value.clone();
    }
    if let Some(value) = &file.agent_real_ip_header {
        settings.agent_real_ip_header = value.clone();
    }
    if let Some(value) = &file.user_template {
        settings.user_template = value.clone();
    }
    if let Some(value) = &file.admin_template {
        settings.admin_template = value.clone();
    }
    if let Some(value) = file.enable_ip_change_notification {
        settings.enable_ip_change_notification = value;
    }
    if let Some(value) = file.enable_plain_ip_in_notification {
        settings.enable_plain_ip_in_notification = value;
    }
    if let Some(value) = &file.oauth2 {
        settings.oauth2 = value.clone();
    }
    settings
}

fn default_http_bind() -> SocketAddr {
    "0.0.0.0:8008".parse().expect("valid default bind")
}

fn config_http_bind(file: &DashboardConfigFile) -> Result<SocketAddr> {
    let host = file.listen_host.as_deref().unwrap_or("0.0.0.0");
    let port = file.listen_port.unwrap_or(8008);
    let raw = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    raw.parse()
        .with_context(|| format!("invalid listen host/port in config: {raw}"))
}

fn non_empty_opt(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_string();
        if value.is_empty() { None } else { Some(value) }
    })
}

fn generated_secret(chars: usize) -> String {
    let mut secret = String::new();
    while secret.len() < chars {
        secret.push_str(&Uuid::new_v4().simple().to_string());
    }
    secret.truncate(chars);
    secret
}

impl DashboardState {
    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        Self {
            client_secret: "secret".to_string(),
            boot_time: unix_now(),
            store: Mutex::new(store::Store::open(":memory:").expect("test store")),
            io_streams: iostream::IoStreamRegistry::default(),
            servers: RwLock::new(HashMap::new()),
            task_senders: RwLock::new(HashMap::new()),
            cycle_transfer_stats: RwLock::new(HashMap::new()),
            online_users: Mutex::new(HashMap::new()),
            blocked_online_ips: Mutex::new(HashSet::new()),
            config_waiters: Mutex::new(HashMap::new()),
            apply_config_waiters: Mutex::new(HashMap::new()),
            pending_alert_trigger_tasks: Mutex::new(HashMap::new()),
            service_current_results: Mutex::new(HashMap::new()),
            service_last_status: Mutex::new(HashMap::new()),
            service_tls_cert_cache: Mutex::new(HashMap::new()),
            geoip_db: PathBuf::from("data/geoip.db"),
            next_task_id: AtomicU64::new(1),
        }
    }

    pub(crate) async fn dispatch_task(
        &self,
        server_id: u64,
        task_type: TaskType,
        data: impl Into<String>,
    ) -> bool {
        self.dispatch_task_with_id(
            server_id,
            self.next_task_id.fetch_add(1, Ordering::Relaxed),
            task_type,
            data,
        )
        .await
    }

    pub(crate) async fn dispatch_task_with_id(
        &self,
        server_id: u64,
        task_id: u64,
        task_type: TaskType,
        data: impl Into<String>,
    ) -> bool {
        let task = Task {
            id: task_id,
            r#type: task_type.as_u64(),
            data: data.into(),
        };
        self.send_task(server_id, task).await
    }

    pub(crate) async fn request_config(&self, server_id: u64) -> Result<Option<String>, String> {
        let task = Task {
            id: self.next_task_id.fetch_add(1, Ordering::Relaxed),
            r#type: TaskType::ReportConfig.as_u64(),
            data: String::new(),
        };
        let (tx, rx) = oneshot::channel();
        self.config_waiters
            .lock()
            .map_err(|_| "config waiter lock poisoned".to_string())?
            .insert(task.id, tx);

        if !self.send_task(server_id, task.clone()).await {
            if let Ok(mut waiters) = self.config_waiters.lock() {
                waiters.remove(&task.id);
            }
            return Ok(None);
        }

        match time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(config)) => Ok(Some(config)),
            Ok(Err(_)) => Err("get server config failed".to_string()),
            Err(_) => {
                if let Ok(mut waiters) = self.config_waiters.lock() {
                    waiters.remove(&task.id);
                }
                Err("operation timeout".to_string())
            }
        }
    }

    pub(crate) async fn apply_config_and_wait(
        &self,
        server_id: u64,
        config: String,
    ) -> Result<Option<(bool, String)>, String> {
        let task = Task {
            id: self.next_task_id.fetch_add(1, Ordering::Relaxed),
            r#type: TaskType::ApplyConfig.as_u64(),
            data: config,
        };
        let (tx, rx) = oneshot::channel();
        self.apply_config_waiters
            .lock()
            .map_err(|_| "apply config waiter lock poisoned".to_string())?
            .insert(task.id, tx);

        if !self.send_task(server_id, task.clone()).await {
            if let Ok(mut waiters) = self.apply_config_waiters.lock() {
                waiters.remove(&task.id);
            }
            return Ok(None);
        }

        match time::timeout(std::time::Duration::from_secs(15), rx).await {
            Ok(Ok(result)) => Ok(Some(result)),
            Ok(Err(_)) => Err("apply config failed".to_string()),
            Err(_) => {
                if let Ok(mut waiters) = self.apply_config_waiters.lock() {
                    waiters.remove(&task.id);
                }
                Err("operation timeout".to_string())
            }
        }
    }

    pub(crate) fn add_online_user(&self, conn_id: String, user: OnlineUser) {
        if let Ok(mut users) = self.online_users.lock() {
            users.insert(conn_id, user);
        }
    }

    pub(crate) fn remove_online_user(&self, conn_id: &str) {
        if let Ok(mut users) = self.online_users.lock() {
            users.remove(conn_id);
        }
    }

    pub(crate) fn list_online_users(&self, limit: u64, offset: u64) -> (Vec<OnlineUser>, u64) {
        let Ok(users) = self.online_users.lock() else {
            return (Vec::new(), 0);
        };
        let mut users = users.values().cloned().collect::<Vec<_>>();
        users.sort_by_key(|user| user.connected_at);
        let total = users.len() as u64;
        let start = (offset as usize).min(users.len());
        let end = start.saturating_add(limit as usize).min(users.len());
        (users[start..end].to_vec(), total)
    }

    pub(crate) fn online_user_count(&self) -> u64 {
        self.online_users
            .lock()
            .map(|users| users.len() as u64)
            .unwrap_or_default()
    }

    pub(crate) fn block_online_ips(&self, ips: &[String]) {
        let Ok(mut blocked) = self.blocked_online_ips.lock() else {
            return;
        };
        let Ok(mut users) = self.online_users.lock() else {
            return;
        };
        for ip in ips {
            blocked.insert(ip.clone());
        }
        users.retain(|_, user| !blocked.contains(&user.ip));
    }

    pub(crate) fn unblock_online_ips(&self, ips: &[String]) {
        let Ok(mut blocked) = self.blocked_online_ips.lock() else {
            return;
        };
        for ip in ips {
            blocked.remove(ip);
        }
    }

    pub(crate) fn online_ip_is_blocked(&self, ip: &str) -> bool {
        self.blocked_online_ips
            .lock()
            .map(|blocked| blocked.contains(ip))
            .unwrap_or(false)
    }

    pub(crate) fn reserve_alert_trigger_result(&self, cron_id: u64, server_id: u64) {
        let Ok(mut pending) = self.pending_alert_trigger_tasks.lock() else {
            return;
        };
        let expires_at = unix_now().saturating_add(24 * 3600);
        pending
            .entry(cron_id)
            .or_default()
            .entry(server_id)
            .or_default()
            .push(expires_at);
    }

    pub(crate) fn revoke_alert_trigger_result(&self, cron_id: u64, server_id: u64) {
        let Ok(mut pending) = self.pending_alert_trigger_tasks.lock() else {
            return;
        };
        let Some(server_tasks) = pending.get_mut(&cron_id) else {
            return;
        };
        let Some(expirations) = server_tasks.get_mut(&server_id) else {
            return;
        };
        expirations.pop();
        if expirations.is_empty() {
            server_tasks.remove(&server_id);
        }
        if server_tasks.is_empty() {
            pending.remove(&cron_id);
        }
    }

    fn consume_alert_trigger_result(&self, cron_id: u64, server_id: u64) -> bool {
        let Ok(mut pending) = self.pending_alert_trigger_tasks.lock() else {
            return false;
        };
        let now = unix_now();
        pending.retain(|_, server_tasks| {
            server_tasks.retain(|_, expirations| {
                expirations.retain(|expires_at| *expires_at > now);
                !expirations.is_empty()
            });
            !server_tasks.is_empty()
        });
        let Some(server_tasks) = pending.get_mut(&cron_id) else {
            return false;
        };
        let Some(expirations) = server_tasks.get_mut(&server_id) else {
            return false;
        };
        expirations.pop();
        if expirations.is_empty() {
            server_tasks.remove(&server_id);
        }
        if server_tasks.is_empty() {
            pending.remove(&cron_id);
        }
        true
    }

    async fn complete_task_result(&self, server_id: u64, result: &TaskResult) {
        if result.r#type == TaskType::ReportConfig.as_u64() {
            let Ok(mut waiters) = self.config_waiters.lock() else {
                return;
            };
            if let Some(waiter) = waiters.remove(&result.id) {
                let _ = waiter.send(result.data.clone());
            }
            return;
        }

        if result.r#type == TaskType::ApplyConfig.as_u64() {
            let Ok(mut waiters) = self.apply_config_waiters.lock() else {
                return;
            };
            if let Some(waiter) = waiters.remove(&result.id) {
                let _ = waiter.send((result.successful, result.data.clone()));
            }
            return;
        }

        if result.r#type == TaskType::Command.as_u64() {
            let notification = {
                let Ok(store) = self.store.lock() else {
                    return;
                };
                let cron = store.get_cron(result.id).ok();
                let alert_trigger_authorized =
                    self.consume_alert_trigger_result(result.id, server_id);
                match store.record_cron_result(server_id, result, alert_trigger_authorized) {
                    Ok(true) => cron.and_then(|cron| {
                        if result.successful && !cron.push_successful {
                            return None;
                        }
                        let message = cron_result_message(&cron.name, result);
                        let context = store
                            .list_servers()
                            .ok()
                            .and_then(|servers| {
                                servers.into_iter().find(|server| server.id == server_id)
                            })
                            .as_ref()
                            .map(notification::NotificationContext::for_public_server);
                        store
                            .notifications_for_group(cron.notification_group_id)
                            .ok()
                            .map(|notifications| (notifications, message, context))
                    }),
                    Ok(false) => None,
                    Err(err) => {
                        error!(%err, server_id, cron_id = result.id, "failed to record cron result");
                        None
                    }
                }
            };
            if let Some((notifications, message, context)) = notification {
                let results = notification::send_notification_group_with_context(
                    notifications,
                    &message,
                    context.as_ref(),
                )
                .await;
                if let Ok(store) = self.store.lock() {
                    notification::record_dead_letters(&store, &message, &results);
                }
                for (id, result) in &results {
                    if let Err(err) = result {
                        warn!(notification_id = *id, %err, "failed to send cron notification");
                    }
                }
            }
            return;
        }

        if is_service_monitor_task(result.r#type) {
            self.complete_service_result(server_id, result).await;
        }
    }

    async fn complete_service_result(&self, server_id: u64, result: &TaskResult) {
        let effects = {
            let Ok(store) = self.store.lock() else {
                return;
            };
            let recorded = match store.record_service_result(server_id, result) {
                Ok(recorded) => recorded,
                Err(err) => {
                    error!(%err, server_id, service_id = result.id, "failed to record service result");
                    return;
                }
            };
            if !recorded {
                return;
            }

            let service = match store.get_service(result.id) {
                Ok(service) => service,
                Err(err) => {
                    error!(%err, service_id = result.id, "failed to load service for result effects");
                    return;
                }
            };
            let Some((last_status, current_status, should_run_status_effects)) =
                self.record_service_current_status(result.id, server_id, result.successful)
            else {
                return;
            };
            let notifications = store
                .notifications_for_group(service.notification_group_id)
                .unwrap_or_else(|err| {
                    warn!(
                        %err,
                        service_id = service.id,
                        notification_group_id = service.notification_group_id,
                        "failed to load service notification group"
                    );
                    Vec::new()
                });
            let server = store
                .list_servers()
                .ok()
                .and_then(|servers| servers.into_iter().find(|server| server.id == server_id));
            let server_name = server
                .as_ref()
                .map(|server| server.name.clone())
                .unwrap_or_else(|| server_id.to_string());
            let context = server
                .as_ref()
                .map(notification::NotificationContext::for_public_server);
            let trigger_owner_is_admin = store.user_is_admin(service.user_id).unwrap_or(false);
            let mut effects = ServiceResultEffects {
                notifications: Vec::new(),
                trigger_crons: Vec::new(),
            };

            if should_run_status_effects
                && service.notify
                && (last_status != SERVICE_STATUS_UNSET || current_status == SERVICE_STATUS_DOWN)
            {
                effects.notifications.push(ServiceNotification {
                    notifications: notifications.clone(),
                    message: format!(
                        "[{}] {} Reporter: {}, Error: {}",
                        service_status_label(current_status),
                        service.name,
                        server_name,
                        result.data
                    ),
                    log_context: "service status",
                    context: context.clone(),
                });
            }

            if result.delay > 0.0 && service.latency_notify {
                if service.max_latency > 0.0 && (result.delay as f64) > service.max_latency {
                    effects.notifications.push(ServiceNotification {
                        notifications: notifications.clone(),
                        message: format!(
                            "[Latency] {} {:.2} > {:.2}, Reporter: {}",
                            service.name, result.delay, service.max_latency, server_name
                        ),
                        log_context: "service latency",
                        context: context.clone(),
                    });
                } else if service.min_latency > 0.0 && (result.delay as f64) < service.min_latency {
                    effects.notifications.push(ServiceNotification {
                        notifications: notifications.clone(),
                        message: format!(
                            "[Latency] {} {:.2} < {:.2}, Reporter: {}",
                            service.name, result.delay, service.min_latency, server_name
                        ),
                        log_context: "service latency",
                        context: context.clone(),
                    });
                }
            }

            if service.notify {
                effects.notifications.extend(self.service_tls_notifications(
                    service.id,
                    server_id,
                    &service.name,
                    notifications.clone(),
                    &result.data,
                    context.clone(),
                ));
            }

            if should_run_status_effects
                && service.enable_trigger_task
                && last_status != SERVICE_STATUS_UNSET
            {
                let task_ids: &[u64] =
                    if current_status == SERVICE_STATUS_GOOD && last_status != current_status {
                        &service.recover_trigger_tasks
                    } else if last_status == SERVICE_STATUS_GOOD && last_status != current_status {
                        &service.fail_trigger_tasks
                    } else {
                        &[]
                    };
                for id in task_ids {
                    let Ok(cron) = store.get_cron(*id) else {
                        continue;
                    };
                    if cron.user_id == service.user_id || trigger_owner_is_admin {
                        effects.trigger_crons.push(cron);
                    }
                }
            }
            effects
        };

        for notification in effects.notifications {
            let results = notification::send_notification_group_with_context(
                notification.notifications,
                &notification.message,
                notification.context.as_ref(),
            )
            .await;
            if let Ok(store) = self.store.lock() {
                notification::record_dead_letters(&store, &notification.message, &results);
            }
            for (id, result) in &results {
                if let Err(err) = result {
                    warn!(
                        notification_id = *id,
                        %err,
                        context = notification.log_context,
                        "failed to send service notification"
                    );
                }
            }
        }
        for cron in effects.trigger_crons {
            self.dispatch_service_trigger_cron(server_id, &cron).await;
        }
    }

    fn record_service_current_status(
        &self,
        service_id: u64,
        server_id: u64,
        successful: bool,
    ) -> Option<(u8, u8, bool)> {
        let key = (service_id, server_id);
        let current_status = {
            let Ok(mut results) = self.service_current_results.lock() else {
                return None;
            };
            let samples = results.entry(key).or_default();
            samples.push(successful);
            if samples.len() > SERVICE_CURRENT_STATUS_SIZE {
                let remove = samples.len() - SERVICE_CURRENT_STATUS_SIZE;
                samples.drain(..remove);
            }
            let total = samples.len() as u64;
            let up = samples.iter().filter(|sample| **sample).count() as u64;
            service_status_code_from_samples(total, up)
        };

        let Ok(mut last_statuses) = self.service_last_status.lock() else {
            return None;
        };
        let last_status = *last_statuses.entry(key).or_insert(SERVICE_STATUS_UNSET);
        let should_run_status_effects =
            current_status == SERVICE_STATUS_DOWN || current_status != last_status;
        if should_run_status_effects {
            last_statuses.insert(key, current_status);
        }
        Some((last_status, current_status, should_run_status_effects))
    }

    fn service_tls_notifications(
        &self,
        service_id: u64,
        server_id: u64,
        service_name: &str,
        notifications: Vec<store::NotificationResource>,
        data: &str,
        context: Option<notification::NotificationContext>,
    ) -> Vec<ServiceNotification> {
        let Some((new_issuer, new_expires)) = parse_tls_certificate_data(data) else {
            return Vec::new();
        };
        let mut messages = Vec::new();
        let mut cache = match self.service_tls_cert_cache.lock() {
            Ok(cache) => cache,
            Err(_) => return Vec::new(),
        };
        let old = cache
            .entry((service_id, server_id))
            .or_insert_with(|| data.to_string())
            .clone();

        if new_expires < Utc::now() + ChronoDuration::days(7) {
            messages.push(ServiceNotification {
                notifications: notifications.clone(),
                message: format!(
                    "[TLS] {} The TLS certificate will expire within seven days. Expiration time: {}",
                    service_name,
                    format_tls_time(new_expires)
                ),
                log_context: "service tls",
                context: context.clone(),
            });
        }

        if old != data {
            if let Some((old_issuer, old_expires)) = parse_tls_certificate_data(&old) {
                messages.push(ServiceNotification {
                    notifications,
                    message: format!(
                        "[TLS] {} TLS certificate changed, old: issuer {}, expires at {}; new: issuer {}, expires at {}",
                        service_name,
                        old_issuer,
                        format_tls_time(old_expires),
                        new_issuer,
                        format_tls_time(new_expires)
                    ),
                    log_context: "service tls",
                    context: context.clone(),
                });
            }
            cache.insert((service_id, server_id), data.to_string());
        }
        messages
    }

    async fn dispatch_service_trigger_cron(&self, server_id: u64, cron: &CronResource) {
        if cron.cover == CRON_COVER_ALERT_TRIGGER {
            if self
                .dispatch_task_with_id(server_id, cron.id, TaskType::Command, cron.command.clone())
                .await
            {
                self.reserve_alert_trigger_result(cron.id, server_id);
            } else {
                self.revoke_alert_trigger_result(cron.id, server_id);
            }
        } else {
            scheduler::dispatch_cron_detailed(self, cron).await;
        }
    }

    async fn send_task(&self, server_id: u64, task: Task) -> bool {
        let sender = self.task_senders.read().await.get(&server_id).cloned();
        if let Some(sender) = sender {
            match sender.send(task.clone()).await {
                Ok(()) => return true,
                Err(_) => {
                    self.task_senders.write().await.remove(&server_id);
                }
            }
        }
        if task_type_can_persist(task.r#type) {
            if let Err(err) = self.persist_pending_task(server_id, &task) {
                error!(%err, server_id, "failed to persist pending task");
            }
        }
        false
    }

    fn persist_pending_task(&self, server_id: u64, task: &Task) -> anyhow::Result<()> {
        let store = self
            .store
            .lock()
            .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
        store.enqueue_pending_task(server_id, task.id, task.r#type, &task.data)
    }

    pub(crate) async fn remove_cached_servers_by_id(&self, ids: &[u64]) {
        if ids.is_empty() {
            return;
        }
        let mut servers = self.servers.write().await;
        servers.retain(|_, server| !ids.contains(&server.id));
        drop(servers);

        let mut task_senders = self.task_senders.write().await;
        for id in ids {
            task_senders.remove(id);
        }
    }
}

impl DashboardService {
    async fn authenticate(&self, metadata: &MetadataMap) -> Result<AuthenticatedAgent, Status> {
        let secret = metadata
            .get("client_secret")
            .ok_or_else(|| Status::unauthenticated("missing client_secret"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("invalid client_secret"))?
            .trim();
        if secret.is_empty() {
            return Err(Status::unauthenticated("missing client_secret"));
        }

        let user_id = self
            .state
            .store
            .lock()
            .map_err(|_| Status::internal("store lock poisoned"))?
            .agent_secret_owner(secret, &self.state.client_secret)
            .map_err(|err| Status::internal(err.to_string()))?
            .ok_or_else(|| Status::unauthenticated("invalid client_secret"))?;

        let uuid = metadata
            .get("client_uuid")
            .ok_or_else(|| Status::unauthenticated("missing client_uuid"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("invalid client_uuid"))?;
        let uuid = uuid
            .parse()
            .map_err(|_| Status::unauthenticated("invalid client_uuid"))?;

        Ok(AuthenticatedAgent { uuid, user_id })
    }

    async fn ensure_server(&self, agent: AuthenticatedAgent) -> Result<ServerRecord, Status> {
        let cached = { self.state.servers.read().await.get(&agent.uuid).cloned() };
        if let Some(server) = cached {
            if agent.user_id != 0 && server.user_id != agent.user_id {
                let stored = self
                    .state
                    .store
                    .lock()
                    .map_err(|_| Status::internal("store lock poisoned"))?
                    .ensure_server_for_user(agent.uuid, agent.user_id)
                    .map_err(store_error_status)?;
                let updated = ServerRecord {
                    id: stored.id,
                    user_id: stored.user_id,
                    host: stored.host.clone(),
                    state: stored.state.clone(),
                    geoip: stored.geoip.clone(),
                    last_active_unix: stored.last_active_unix,
                };
                self.state
                    .servers
                    .write()
                    .await
                    .insert(agent.uuid, updated.clone());
                return Ok(updated);
            }
            return Ok(server);
        }

        let stored = self
            .state
            .store
            .lock()
            .map_err(|_| Status::internal("store lock poisoned"))?
            .ensure_server_for_user(agent.uuid, agent.user_id)
            .map_err(store_error_status)?;

        let mut servers = self.state.servers.write().await;
        let entry = servers.entry(agent.uuid).or_insert_with(|| {
            info!(uuid = %agent.uuid, id = stored.id, user_id = stored.user_id, "registered agent");
            ServerRecord {
                id: stored.id,
                user_id: stored.user_id,
                host: stored.host.clone(),
                state: stored.state.clone(),
                geoip: stored.geoip.clone(),
                last_active_unix: stored.last_active_unix,
            }
        });
        Ok(entry.clone())
    }

    async fn update_host(&self, agent: AuthenticatedAgent, host: Host) -> Result<(), Status> {
        let stored = self
            .state
            .store
            .lock()
            .map_err(|_| Status::internal("store lock poisoned"))?
            .update_host_for_user(agent.uuid, agent.user_id, host)
            .map_err(store_error_status)?;

        let mut servers = self.state.servers.write().await;
        let server = servers.entry(agent.uuid).or_insert_with(|| ServerRecord {
            id: stored.id,
            user_id: stored.user_id,
            host: None,
            state: None,
            geoip: None,
            last_active_unix: stored.last_active_unix,
        });
        server.user_id = stored.user_id;
        server.host = stored.host;
        server.state = stored.state;
        server.geoip = stored.geoip;
        server.last_active_unix = stored.last_active_unix;
        info!(server_id = server.id, uuid = %agent.uuid, "host info updated");
        Ok(())
    }

    async fn update_state(&self, agent: AuthenticatedAgent, state: State) -> Result<(), Status> {
        let stored = self
            .state
            .store
            .lock()
            .map_err(|_| Status::internal("store lock poisoned"))?
            .update_state_for_user(agent.uuid, agent.user_id, state)
            .map_err(store_error_status)?;

        let mut servers = self.state.servers.write().await;
        let server = servers.entry(agent.uuid).or_insert_with(|| ServerRecord {
            id: stored.id,
            user_id: stored.user_id,
            host: None,
            state: None,
            geoip: None,
            last_active_unix: stored.last_active_unix,
        });
        server.user_id = stored.user_id;
        server.host = stored.host;
        server.state = stored.state;
        server.geoip = stored.geoip;
        server.last_active_unix = stored.last_active_unix;
        info!(server_id = server.id, uuid = %agent.uuid, "state updated");
        Ok(())
    }
}

#[tonic::async_trait]
impl NezhaService for DashboardService {
    type ReportSystemStateStream =
        Pin<Box<dyn Stream<Item = Result<Receipt, Status>> + Send + 'static>>;
    type RequestTaskStream = Pin<Box<dyn Stream<Item = Result<Task, Status>> + Send + 'static>>;
    type IOStreamStream =
        Pin<Box<dyn Stream<Item = Result<IoStreamData, Status>> + Send + 'static>>;

    async fn report_system_state(
        &self,
        request: Request<Streaming<State>>,
    ) -> Result<Response<Self::ReportSystemStateStream>, Status> {
        let agent = self.authenticate(request.metadata()).await?;
        self.ensure_server(agent).await?;
        let mut inbound = request.into_inner();
        let service = self.clone();

        let outbound = try_stream! {
            while let Some(state) = inbound.message().await? {
                service.update_state(agent, state).await?;
                yield Receipt { proced: true };
            }
        };

        Ok(Response::new(Box::pin(outbound)))
    }

    async fn report_system_info(
        &self,
        request: Request<Host>,
    ) -> Result<Response<Receipt>, Status> {
        let agent = self.authenticate(request.metadata()).await?;
        self.update_host(agent, request.into_inner()).await?;
        Ok(Response::new(Receipt { proced: true }))
    }

    async fn request_task(
        &self,
        request: Request<Streaming<TaskResult>>,
    ) -> Result<Response<Self::RequestTaskStream>, Status> {
        let agent = self.authenticate(request.metadata()).await?;
        let server = self.ensure_server(agent).await?;
        let mut inbound = request.into_inner();
        let state = self.state.clone();
        let result_state = self.state.clone();
        let (tx, mut rx) = mpsc::channel::<Task>(16);
        let tx_guard = tx.clone();
        self.state.task_senders.write().await.insert(server.id, tx);

        let pending = match self.state.store.lock() {
            Ok(store) => store.drain_pending_tasks(server.id).unwrap_or_else(|err| {
                error!(%err, server_id = server.id, "failed to drain pending tasks");
                Vec::new()
            }),
            Err(_) => {
                error!(
                    server_id = server.id,
                    "store lock poisoned while draining pending tasks"
                );
                Vec::new()
            }
        };

        tokio::spawn(async move {
            loop {
                match inbound.message().await {
                    Ok(Some(result)) => {
                        result_state.complete_task_result(server.id, &result).await;
                        info!(
                            server_id = server.id,
                            uuid = %agent.uuid,
                            task_id = result.id,
                            task_type = result.r#type,
                            successful = result.successful,
                            "task result received"
                        );
                    }
                    Ok(None) => break,
                    Err(err) => {
                        error!(%err, uuid = %agent.uuid, "task result stream failed");
                        break;
                    }
                }
            }
        });

        let outbound = try_stream! {
            for entry in pending {
                yield Task {
                    id: entry.task_id,
                    r#type: entry.task_type,
                    data: entry.data,
                };
                let row_id = entry.row_id;
                if let Ok(store) = state.store.lock() {
                    if let Err(err) = store.delete_pending_task(row_id) {
                        error!(%err, server_id = server.id, "failed to delete pending task");
                    }
                }
            }
            let mut interval = time::interval(std::time::Duration::from_secs(30));
            loop {
                tokio::select! {
                    task = rx.recv() => {
                        let Some(task) = task else {
                            break;
                        };
                        yield task;
                    }
                    _ = interval.tick() => {
                        yield Task {
                            id: 0,
                            r#type: TaskType::Keepalive.as_u64(),
                            data: String::new(),
                        };
                    }
                }
            }
            let mut senders = state.task_senders.write().await;
            if senders.get(&server.id).is_some_and(|current| current.same_channel(&tx_guard)) {
                senders.remove(&server.id);
            }
        };

        Ok(Response::new(Box::pin(outbound)))
    }

    async fn io_stream(
        &self,
        request: Request<Streaming<IoStreamData>>,
    ) -> Result<Response<Self::IOStreamStream>, Status> {
        let agent = self.authenticate(request.metadata()).await?;
        let server = self.ensure_server(agent).await?;
        let mut inbound = request.into_inner();
        let init = inbound
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("missing stream id"))?;
        let stream_id = iostream::stream_id_from_init(&init.data)
            .ok_or_else(|| Status::invalid_argument("invalid stream id"))?;
        let session = self
            .state
            .io_streams
            .get_stream(&stream_id)
            .await
            .ok_or_else(|| Status::not_found("stream not found"))?;
        if !session.is_authorized_for_agent(server.id) {
            return Err(Status::permission_denied("stream not authorized for agent"));
        }
        let mut to_agent_rx = session
            .take_agent_receiver()
            .await
            .ok_or_else(|| Status::already_exists("agent stream already connected"))?;
        session.mark_agent_connected();
        let to_user_session = session.clone();
        let stream_id_for_task = stream_id.clone();
        tokio::spawn(async move {
            loop {
                match inbound.message().await {
                    Ok(Some(data)) => {
                        if data.data.is_empty() {
                            continue;
                        }
                        if to_user_session.send_to_user(data.data).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        error!(%err, stream_id = %stream_id_for_task, "IOStream inbound failed");
                        break;
                    }
                }
            }
        });

        let outbound = try_stream! {
            let mut interval = time::interval(std::time::Duration::from_secs(30));
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    data = to_agent_rx.recv() => {
                        let Some(data) = data else {
                            break;
                        };
                        yield IoStreamData { data };
                    }
                    _ = interval.tick() => {
                        yield IoStreamData { data: Vec::new() };
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(outbound)))
    }

    async fn report_geo_ip(&self, request: Request<GeoIp>) -> Result<Response<GeoIp>, Status> {
        let agent = self.authenticate(request.metadata()).await?;
        let mut geo = request.into_inner();
        geo.dashboard_boot_time = self.state.boot_time;
        if let Some(ip) = geoip_lookup_ip(&geo) {
            geo.country_code = lookup_geoip_country(&self.state.geoip_db, ip).unwrap_or_default();
        }
        let stored_geo = geo.clone();
        let (stored, ip_change_notification, ddns_update) = {
            let store = self
                .state
                .store
                .lock()
                .map_err(|_| Status::internal("store lock poisoned"))?;
            let previous = store
                .ensure_server_for_user(agent.uuid, agent.user_id)
                .map_err(store_error_status)?;
            let previous_ip = previous
                .geoip
                .as_ref()
                .map(geoip_ip_string)
                .unwrap_or_default();
            let stored = store
                .update_geoip_for_user(agent.uuid, agent.user_id, stored_geo)
                .map_err(store_error_status)?;
            let current_ip = geoip_ip_string(&geo);
            let settings = store
                .dashboard_settings()
                .map_err(|err| Status::internal(err.to_string()))?
                .unwrap_or_default();
            let dns_servers = settings.dns_servers.clone();
            let public_server = store
                .list_servers()
                .map_err(store_error_status)?
                .into_iter()
                .find(|server| server.id == stored.id);
            let ddns_update = if !current_ip.is_empty() && current_ip != previous_ip {
                public_server
                    .as_ref()
                    .filter(|server| server.enable_ddns)
                    .cloned()
                    .map(|server| {
                        let profiles = store.ddns_profiles_for_server(server.id)?;
                        Ok((server, profiles, dns_servers.clone()))
                    })
                    .transpose()
                    .map_err(store_error_status)?
            } else {
                None
            };
            let notification = if should_send_ip_change_notification(
                &settings,
                stored.id,
                &previous_ip,
                &current_ip,
            ) {
                let message = format!(
                    "[IP Changed] server {}: {} -> {}",
                    stored.id, previous_ip, current_ip
                );
                let context = public_server
                    .as_ref()
                    .map(notification::NotificationContext::for_public_server);
                Some((
                    store
                        .notifications_for_group(settings.ip_change_notification_group_id)
                        .map_err(|err| Status::internal(err.to_string()))?,
                    message,
                    context,
                ))
            } else {
                None
            };
            (stored, notification, ddns_update)
        };
        if let Some(server) = self.state.servers.write().await.get_mut(&agent.uuid) {
            server.user_id = stored.user_id;
            server.geoip = stored.geoip;
            server.last_active_unix = stored.last_active_unix;
        }
        if let Some((notifications, message, context)) = ip_change_notification {
            let results = notification::send_notification_group_with_context(
                notifications,
                &message,
                context.as_ref(),
            )
            .await;
            if let Ok(store) = self.state.store.lock() {
                notification::record_dead_letters(&store, &message, &results);
            }
            for (id, result) in &results {
                if let Err(err) = result {
                    warn!(notification_id = *id, %err, "failed to send ip change notification");
                }
            }
        }
        if let Some((server, profiles, dns_servers)) = ddns_update {
            let ipv4 = geo
                .ip
                .as_ref()
                .map(|ip| ip.ipv4.clone())
                .unwrap_or_default();
            let ipv6 = geo
                .ip
                .as_ref()
                .map(|ip| ip.ipv6.clone())
                .unwrap_or_default();
            for (profile_id, result) in
                update_server_ddns(server, profiles, ipv4, ipv6, dns_servers).await
            {
                if let Err(err) = result {
                    warn!(profile_id, %err, "failed to update ddns profile");
                }
            }
        }
        Ok(Response::new(geo))
    }

    async fn report_system_info2(
        &self,
        request: Request<Host>,
    ) -> Result<Response<Uint64Receipt>, Status> {
        let agent = self.authenticate(request.metadata()).await?;
        self.update_host(agent, request.into_inner()).await?;
        Ok(Response::new(Uint64Receipt {
            data: self.state.boot_time,
        }))
    }
}

fn store_error_status(err: anyhow::Error) -> Status {
    let message = err.to_string();
    if message.contains("client UUID does not belong to the agent secret owner") {
        Status::permission_denied(message)
    } else {
        Status::internal(message)
    }
}

fn cron_result_message(cron_name: &str, result: &TaskResult) -> String {
    let status = if result.successful {
        "Scheduled Task Executed Successfully"
    } else {
        "Scheduled Task Executed Failed"
    };
    format!(
        "[{status}] {cron_name}, {:.3}s\n{}",
        result.delay, result.data
    )
}

fn geoip_ip_string(geoip: &GeoIp) -> String {
    let Some(ip) = &geoip.ip else {
        return String::new();
    };
    match (ip.ipv4.is_empty(), ip.ipv6.is_empty()) {
        (false, false) => format!("{}/{}", ip.ipv4, ip.ipv6),
        (false, true) => ip.ipv4.clone(),
        (true, false) => ip.ipv6.clone(),
        (true, true) => String::new(),
    }
}

fn geoip_lookup_ip(geoip: &GeoIp) -> Option<IpAddr> {
    let ip = geoip.ip.as_ref()?;
    let raw = if !ip.ipv6.is_empty() && (geoip.use6 || ip.ipv4.is_empty()) {
        ip.ipv6.as_str()
    } else {
        ip.ipv4.as_str()
    };
    raw.parse().ok()
}

fn service_status_code_from_samples(total: u64, up: u64) -> u8 {
    if total == 0 {
        SERVICE_STATUS_NO_DATA
    } else {
        service_status_code(up * 100 / total)
    }
}

fn service_status_code(percent: u64) -> u8 {
    if percent > 95 {
        SERVICE_STATUS_GOOD
    } else if percent > 80 {
        SERVICE_STATUS_LOW_AVAILABILITY
    } else {
        SERVICE_STATUS_DOWN
    }
}

fn service_status_label(status: u8) -> &'static str {
    match status {
        SERVICE_STATUS_NO_DATA => "No Data",
        SERVICE_STATUS_GOOD => "Good",
        SERVICE_STATUS_LOW_AVAILABILITY => "Low Availability",
        SERVICE_STATUS_DOWN => "Down",
        _ => "",
    }
}

fn parse_tls_certificate_data(raw: &str) -> Option<(String, DateTime<Utc>)> {
    let (issuer, expires) = raw.split_once('|')?;
    let expires = DateTime::parse_from_str(expires.trim(), "%Y-%m-%d %H:%M:%S %z %Z")
        .or_else(|_| {
            DateTime::parse_from_str(
                expires.trim().trim_end_matches(" UTC").trim(),
                "%Y-%m-%d %H:%M:%S %z",
            )
        })
        .ok()?
        .with_timezone(&Utc);
    Some((issuer.to_string(), expires))
}

fn format_tls_time(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%d %H:%M:%S").to_string()
}

#[derive(serde::Deserialize)]
struct GeoIpDbRecord<'a> {
    #[serde(default, borrow)]
    country: Option<&'a str>,
    #[serde(default, borrow)]
    continent: Option<&'a str>,
}

fn lookup_geoip_country(db_path: &Path, ip: IpAddr) -> Option<String> {
    let reader = maxminddb::Reader::open_readfile(db_path).ok()?;
    let result = reader.lookup(ip).ok()?;
    let record = result.decode::<GeoIpDbRecord>().ok().flatten()?;
    record
        .country
        .or(record.continent)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}

fn should_send_ip_change_notification(
    settings: &store::DashboardSettings,
    server_id: u64,
    previous_ip: &str,
    current_ip: &str,
) -> bool {
    if !settings.enable_ip_change_notification
        || settings.ip_change_notification_group_id == 0
        || previous_ip.is_empty()
        || current_ip.is_empty()
        || previous_ip == current_ip
    {
        return false;
    }
    let selected = csv_u64_contains(&settings.ignored_ip_notification, server_id);
    match settings.cover {
        0 => !selected,
        1 => selected,
        _ => false,
    }
}

fn csv_u64_contains(raw: &str, needle: u64) -> bool {
    raw.split(',')
        .filter_map(|item| item.trim().parse::<u64>().ok())
        .any(|item| item == needle)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn is_service_monitor_task(task_type: u64) -> bool {
    !matches!(
        TaskType::from_u64(task_type),
        None | Some(
            TaskType::Command
                | TaskType::Terminal
                | TaskType::Upgrade
                | TaskType::Keepalive
                | TaskType::TerminalGrpc
                | TaskType::Nat
                | TaskType::FileManager
                | TaskType::ReportConfig
                | TaskType::ApplyConfig
        )
    )
}

fn task_type_can_persist(task_type: u64) -> bool {
    matches!(
        TaskType::from_u64(task_type),
        Some(TaskType::Command | TaskType::Upgrade | TaskType::ApplyConfig)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_args() -> Args {
        Args {
            bind: "0.0.0.0:5555".parse().unwrap(),
            http_bind: default_http_bind(),
            config: PathBuf::from("data/config.yaml"),
            client_secret: None,
            data: PathBuf::from("data/sqlite.db"),
            admin_username: "admin".to_string(),
            admin_password: "admin".to_string(),
            jwt_secret: None,
            jwt_timeout: None,
            site_name: None,
            debug: false,
            force_auth: false,
            install_host: String::new(),
            trust_proxy_headers: false,
            static_dir: PathBuf::from("static"),
            geoip_db: PathBuf::from("data/geoip.db"),
            tls_cert: None,
            tls_key: None,
            command: None,
        }
    }

    #[test]
    fn dashboard_config_file_matches_upstream_keys() {
        let file: DashboardConfigFile = serde_yaml::from_str(
            r#"
agent_secret_key: agent-secret
jwt_secret_key: jwt-secret
jwt_timeout: 3
listen_host: 127.0.0.1
listen_port: 9000
site_name: Configured
install_host: https://dash.example.com
tls: true
force_auth: true
debug: true
oauth2:
  github:
    client_id: id
    client_secret: secret
    endpoint:
      auth_url: https://github.com/login/oauth/authorize
      token_url: https://github.com/login/oauth/access_token
    scopes: [read:user]
    user_info_url: https://api.github.com/user
    user_id_path: id
"#,
        )
        .unwrap();
        let resolved = resolve_dashboard_config(&test_args(), &file, None).unwrap();

        assert_eq!(resolved.client_secret, "agent-secret");
        assert_eq!(resolved.jwt_secret, "jwt-secret");
        assert_eq!(resolved.jwt_timeout, 3);
        assert_eq!(resolved.http_bind, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(resolved.site_name, "Configured");
        assert_eq!(resolved.install_host, "https://dash.example.com");
        assert!(resolved.agent_tls);
        assert!(resolved.force_auth);
        assert!(resolved.debug);
        assert!(resolved.initial_settings.oauth2.contains_key("github"));
    }

    #[tokio::test]
    async fn dispatch_task_sends_to_registered_agent() {
        let state = DashboardState::new_for_test();
        let (tx, mut rx) = mpsc::channel(1);
        state.task_senders.write().await.insert(42, tx);

        assert!(
            state
                .dispatch_task(42, TaskType::Upgrade, String::new())
                .await
        );

        let task = rx.recv().await.expect("queued task");
        assert_eq!(task.r#type, TaskType::Upgrade.as_u64());
        assert!(task.id > 0);
    }

    #[tokio::test]
    async fn remove_cached_servers_clears_server_and_task_sender() {
        let state = DashboardState::new_for_test();
        let uuid = Uuid::new_v4();
        state.servers.write().await.insert(
            uuid,
            ServerRecord {
                id: 42,
                user_id: 1,
                host: None,
                state: None,
                geoip: None,
                last_active_unix: 0,
            },
        );
        let (tx, _rx) = mpsc::channel(1);
        state.task_senders.write().await.insert(42, tx);

        state.remove_cached_servers_by_id(&[42]).await;

        assert!(!state.servers.read().await.contains_key(&uuid));
        assert!(!state.task_senders.read().await.contains_key(&42));
    }

    #[tokio::test]
    async fn offline_dispatch_persists_only_replayable_tasks() {
        let state = DashboardState::new_for_test();

        assert!(
            !state
                .dispatch_task(42, TaskType::Command, "uptime".to_string())
                .await
        );
        assert!(
            !state
                .dispatch_task(42, TaskType::TerminalGrpc, "{}".to_string())
                .await
        );
        assert!(
            !state
                .dispatch_task(42, TaskType::HttpGet, "https://example.com".to_string())
                .await
        );

        let pending = state.store.lock().unwrap().drain_pending_tasks(42).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].task_type, TaskType::Command.as_u64());
        assert_eq!(pending[0].data, "uptime");
    }

    #[tokio::test]
    async fn request_config_completes_from_task_result() {
        let state = Arc::new(DashboardState::new_for_test());
        let (tx, mut rx) = mpsc::channel(1);
        state.task_senders.write().await.insert(7, tx);

        let waiter_state = state.clone();
        let waiter = tokio::spawn(async move { waiter_state.request_config(7).await });

        let task = rx.recv().await.expect("report config task");
        assert_eq!(task.r#type, TaskType::ReportConfig.as_u64());
        state
            .complete_task_result(
                7,
                &TaskResult {
                    id: task.id,
                    r#type: TaskType::ReportConfig.as_u64(),
                    delay: 0.0,
                    data: "agent-config".to_string(),
                    successful: true,
                },
            )
            .await;

        assert_eq!(
            waiter.await.unwrap().unwrap(),
            Some("agent-config".to_string())
        );
    }

    #[test]
    fn service_current_status_treats_zero_percent_as_down() {
        let state = DashboardState::new_for_test();

        assert_eq!(
            state.record_service_current_status(1, 10, false),
            Some((SERVICE_STATUS_UNSET, SERVICE_STATUS_DOWN, true))
        );
        assert_eq!(
            state.record_service_current_status(1, 10, false),
            Some((SERVICE_STATUS_DOWN, SERVICE_STATUS_DOWN, true))
        );
        assert_eq!(
            service_status_code_from_samples(0, 0),
            SERVICE_STATUS_NO_DATA
        );
    }

    #[test]
    fn service_current_status_isolated_by_server() {
        let state = DashboardState::new_for_test();

        assert_eq!(
            state.record_service_current_status(1, 10, false),
            Some((SERVICE_STATUS_UNSET, SERVICE_STATUS_DOWN, true))
        );
        assert_eq!(
            state.record_service_current_status(1, 20, true),
            Some((SERVICE_STATUS_UNSET, SERVICE_STATUS_GOOD, true))
        );
    }

    #[test]
    fn online_user_registry_lists_and_blocks_ips() {
        let state = DashboardState::new_for_test();
        state.add_online_user(
            "b".to_string(),
            OnlineUser {
                user_id: 2,
                connected_at: 20,
                ip: "203.0.113.20".to_string(),
            },
        );
        state.add_online_user(
            "a".to_string(),
            OnlineUser {
                user_id: 1,
                connected_at: 10,
                ip: "203.0.113.10".to_string(),
            },
        );

        let (users, total) = state.list_online_users(25, 0);
        assert_eq!(total, 2);
        assert_eq!(users[0].user_id, 1);
        assert_eq!(state.online_user_count(), 2);

        state.block_online_ips(&["203.0.113.10".to_string()]);
        assert!(state.online_ip_is_blocked("203.0.113.10"));
        let (users, total) = state.list_online_users(25, 0);
        assert_eq!(total, 1);
        assert_eq!(users[0].user_id, 2);
    }

    #[test]
    fn ip_change_notification_respects_cover_and_ip_delta() {
        let mut settings = store::DashboardSettings {
            enable_ip_change_notification: true,
            ip_change_notification_group_id: 3,
            cover: 0,
            ignored_ip_notification: "1, 2".to_string(),
            ..Default::default()
        };

        assert!(should_send_ip_change_notification(
            &settings,
            3,
            "203.0.113.10",
            "203.0.113.11"
        ));
        assert!(!should_send_ip_change_notification(
            &settings,
            2,
            "203.0.113.10",
            "203.0.113.11"
        ));
        assert!(!should_send_ip_change_notification(
            &settings,
            3,
            "203.0.113.10",
            "203.0.113.10"
        ));
        assert!(!should_send_ip_change_notification(
            &settings,
            3,
            "",
            "203.0.113.10"
        ));

        settings.cover = 1;
        assert!(should_send_ip_change_notification(
            &settings,
            2,
            "203.0.113.10",
            "203.0.113.11"
        ));
        assert!(!should_send_ip_change_notification(
            &settings,
            3,
            "203.0.113.10",
            "203.0.113.11"
        ));

        let geoip = GeoIp {
            use6: false,
            ip: Some(nezha_proto::Ip {
                ipv4: "203.0.113.10".into(),
                ipv6: "2001:db8::1".into(),
            }),
            country_code: String::new(),
            dashboard_boot_time: 0,
        };
        assert_eq!(geoip_ip_string(&geoip), "203.0.113.10/2001:db8::1");
        assert_eq!(
            geoip_lookup_ip(&geoip),
            Some("203.0.113.10".parse().unwrap())
        );
        assert_eq!(
            lookup_geoip_country(Path::new("missing.mmdb"), geoip_lookup_ip(&geoip).unwrap()),
            None
        );

        let mut use_v6 = geoip;
        use_v6.use6 = true;
        assert_eq!(
            geoip_lookup_ip(&use_v6),
            Some("2001:db8::1".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn agent_auth_maps_user_secret_and_cache_enforces_uuid_owner() {
        let state = Arc::new(DashboardState::new_for_test());
        let (alice_id, alice_secret, bob_id) = {
            let store = state.store.lock().unwrap();
            let alice_id = store.create_user("alice", "secret1", 1).unwrap();
            let bob_id = store.create_user("bob", "secret2", 1).unwrap();
            let alice = store.get_user(alice_id).unwrap();
            (alice_id, alice.agent_secret, bob_id)
        };
        let service = DashboardService {
            state: state.clone(),
        };
        let uuid = Uuid::new_v4();
        let metadata = agent_metadata(&alice_secret, uuid);

        let agent = service.authenticate(&metadata).await.unwrap();
        assert_eq!(agent.uuid, uuid);
        assert_eq!(agent.user_id, alice_id);

        let server = service.ensure_server(agent).await.unwrap();
        assert_eq!(server.user_id, alice_id);

        let err = service
            .ensure_server(AuthenticatedAgent {
                uuid,
                user_id: bob_id,
            })
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        {
            let store = state.store.lock().unwrap();
            store.move_servers(&[server.id], bob_id).unwrap();
        }
        let moved = service
            .ensure_server(AuthenticatedAgent {
                uuid,
                user_id: bob_id,
            })
            .await
            .unwrap();
        assert_eq!(moved.user_id, bob_id);
    }

    fn agent_metadata(secret: &str, uuid: Uuid) -> MetadataMap {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "client_secret",
            tonic::metadata::MetadataValue::try_from(secret).unwrap(),
        );
        metadata.insert(
            "client_uuid",
            tonic::metadata::MetadataValue::try_from(uuid.to_string().as_str()).unwrap(),
        );
        metadata
    }
}
