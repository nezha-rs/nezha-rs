mod dns;
mod edit;
mod monitor;
mod process_group;
mod service;
mod updater;

use std::{
    io::{Read as _, Write as _},
    net::IpAddr,
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use monitor::Monitor;
use nezha_core::{AgentConfig, TaskType};
use nezha_proto::{
    GeoIp, IoStreamData, Ip, Task, TaskResult, nezha_service_client::NezhaServiceClient,
};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::Command as TokioCommand,
    sync::{mpsc, oneshot},
    time,
};
use tokio_rustls::rustls::{
    DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    Request, Streaming,
    metadata::MetadataValue,
    transport::{Channel, ClientTlsConfig, Endpoint},
};
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(version, about = "Nezha Agent rewritten in Rust")]
struct Args {
    #[arg(short, long, default_value = "config.yml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<AgentCommand>,
}

#[derive(Debug, clap::Subcommand)]
enum AgentCommand {
    Edit,
    Service {
        #[arg(value_enum)]
        action: service::ServiceAction,
    },
}

#[derive(Debug, Deserialize)]
struct StreamTask {
    #[serde(alias = "StreamID", alias = "stream_id")]
    stream_id: String,
    #[serde(default, alias = "Host", alias = "host")]
    host: String,
}

#[derive(Debug, Deserialize)]
struct WindowSize {
    #[serde(alias = "Cols", alias = "cols")]
    cols: u16,
    #[serde(alias = "Rows", alias = "rows")]
    rows: u16,
}

#[derive(Debug, Default, Clone)]
struct GeoIpState {
    query_ip: String,
    cached_country_code: String,
    dashboard_boot_time: u64,
    reported: bool,
}

impl GeoIpState {
    fn observe_dashboard_boot_time(&mut self, boot_time: u64) {
        self.reported =
            self.reported && self.dashboard_boot_time > 0 && boot_time == self.dashboard_boot_time;
        self.dashboard_boot_time = boot_time;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    ensure_windows_kernel_arch_matches_binary()?;
    match args.command {
        Some(AgentCommand::Edit) => edit::run(&args.config),
        Some(AgentCommand::Service { action }) => {
            AgentConfig::load(&args.config)?;
            service::control(action, &args.config)
        }
        None => {
            let cfg = AgentConfig::load(&args.config)?;
            start_auto_update_worker(cfg);
            run(args.config).await
        }
    }
}

fn ensure_windows_kernel_arch_matches_binary() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        if let Some(host_arch) = windows_kernel_arch_from_env(
            std::env::var("PROCESSOR_ARCHITECTURE").ok().as_deref(),
            std::env::var("PROCESSOR_ARCHITEW6432").ok().as_deref(),
        ) {
            let binary_arch = std::env::consts::ARCH;
            if binary_arch != host_arch {
                bail!(
                    "binary architecture does not match current system: running windows_{binary_arch}, expected windows_{host_arch}"
                );
            }
        }
    }
    Ok(())
}

async fn run(config_path: PathBuf) -> Result<()> {
    let mut backoff = time::interval(Duration::from_secs(10));
    loop {
        let cfg = AgentConfig::load(&config_path)?;
        match connect(&cfg).await {
            Ok(channel) => {
                info!("connected to dashboard {}", cfg.server);
                if let Err(err) = run_session(cfg.clone(), config_path.clone(), channel).await {
                    error!(%err, "agent session ended");
                }
            }
            Err(err) => error!(%err, "failed to connect dashboard"),
        }
        backoff.tick().await;
    }
}

fn start_auto_update_worker(cfg: AgentConfig) {
    if !updater::auto_update_allowed(&cfg) {
        return;
    }

    tokio::spawn(async move {
        if run_auto_update_once(&cfg).await {
            std::process::exit(1);
        }

        let period = updater::auto_update_period(&cfg);
        loop {
            time::sleep(period).await;
            if run_auto_update_once(&cfg).await {
                std::process::exit(1);
            }
        }
    });
}

async fn run_auto_update_once(cfg: &AgentConfig) -> bool {
    match updater::run(cfg, updater::UpdateMode::Auto).await {
        Ok(outcome) if outcome.updated => {
            info!(
                provider = ?outcome.provider,
                version = %outcome.version,
                "agent self-update installed; exiting for restart"
            );
            true
        }
        Ok(outcome) => {
            info!(
                provider = ?outcome.provider,
                version = %outcome.version,
                "agent self-update checked"
            );
            false
        }
        Err(err) => {
            warn!(%err, "agent self-update check failed");
            false
        }
    }
}

async fn connect(cfg: &AgentConfig) -> Result<Channel> {
    let endpoint = Endpoint::from_shared(endpoint_uri(cfg))?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30));

    let endpoint = if cfg.tls {
        if cfg.insecure_tls {
            warn!("insecure_tls is enabled; skipping dashboard TLS certificate verification");
            endpoint.tls_config_with_verifier(
                ClientTlsConfig::new(),
                Arc::new(NoCertificateVerification),
            )?
        } else {
            endpoint.tls_config(ClientTlsConfig::new().with_native_roots())?
        }
    } else {
        endpoint
    };

    endpoint.connect().await.context("grpc connect failed")
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn endpoint_uri(cfg: &AgentConfig) -> String {
    if cfg.server.starts_with("http://") || cfg.server.starts_with("https://") {
        cfg.server.clone()
    } else if cfg.tls {
        format!("https://{}", cfg.server)
    } else {
        format!("http://{}", cfg.server)
    }
}

fn windows_kernel_arch_from_env(
    processor_architecture: Option<&str>,
    processor_architew6432: Option<&str>,
) -> Option<&'static str> {
    let raw = processor_architew6432
        .filter(|value| !value.trim().is_empty())
        .or(processor_architecture)?
        .trim()
        .to_ascii_lowercase();
    match raw.as_str() {
        "amd64" | "x86_64" => Some("x86_64"),
        "arm64" | "aarch64" => Some("aarch64"),
        "x86" | "i386" | "i686" => Some("x86"),
        _ => None,
    }
}

async fn run_session(cfg: AgentConfig, config_path: PathBuf, channel: Channel) -> Result<()> {
    let mut client = NezhaServiceClient::new(channel);
    let mut monitor = Monitor::new(&cfg);

    let host = monitor.host();
    let mut host_request = Request::new(host);
    apply_auth(&cfg, &mut host_request)?;
    let boot_time = client
        .report_system_info2(host_request)
        .await?
        .into_inner()
        .data;
    info!(dashboard_boot_time = boot_time, "reported host info");
    let mut geoip_state = GeoIpState::default();
    geoip_state.observe_dashboard_boot_time(boot_time);
    if let Err(err) = report_geoip(&cfg, client.clone(), &mut geoip_state).await {
        warn!(%err, "failed to report geoip");
    }

    let periodic_cfg = cfg.clone();
    let periodic_client = client.clone();
    let periodic_worker =
        tokio::spawn(
            async move { periodic_reports(periodic_cfg, periodic_client, geoip_state).await },
        );

    let task_client = client.clone();
    let task_cfg = cfg.clone();
    let (reload_tx, reload_rx) = oneshot::channel();
    let task_worker =
        tokio::spawn(
            async move { request_tasks(task_cfg, config_path, task_client, reload_tx).await },
        );

    let state_result = tokio::select! {
        result = report_state(cfg, client, monitor) => result,
        _ = reload_rx => {
            info!("configuration applied; restarting agent session");
            bail!("configuration applied; restarting agent session")
        }
    };
    task_worker.abort();
    periodic_worker.abort();
    state_result
}

async fn report_state(
    cfg: AgentConfig,
    mut client: NezhaServiceClient<Channel>,
    mut monitor: Monitor,
) -> Result<()> {
    let delay = Duration::from_secs(cfg.report_delay as u64);
    let state_stream = async_stream::stream! {
        loop {
            yield monitor.state();
            time::sleep(delay).await;
        }
    };

    let mut request = Request::new(state_stream);
    apply_auth(&cfg, &mut request)?;
    let mut receipts = client.report_system_state(request).await?.into_inner();

    while let Some(receipt) = receipts.message().await? {
        if !receipt.proced {
            warn!("dashboard returned a negative state receipt");
        }
    }
    bail!("state stream closed")
}

async fn report_geoip(
    cfg: &AgentConfig,
    mut client: NezhaServiceClient<Channel>,
    state: &mut GeoIpState,
) -> Result<bool> {
    let Some((ipv4, ipv6)) = fetch_public_ip(cfg).await else {
        bail!("failed to fetch public ip");
    };
    let query_ip = selected_geoip_query_ip(&ipv4, &ipv6, cfg.use_ipv6_country_code);
    if query_ip.is_empty() {
        bail!("failed to select public ip");
    }
    if state.reported && state.query_ip == query_ip {
        return Ok(false);
    }
    let mut request = Request::new(GeoIp {
        use6: cfg.use_ipv6_country_code,
        ip: Some(Ip { ipv4, ipv6 }),
        country_code: String::new(),
        dashboard_boot_time: 0,
    });
    apply_auth(cfg, &mut request)?;
    let response = client.report_geo_ip(request).await?.into_inner();
    state.query_ip = query_ip;
    state.cached_country_code = response.country_code.trim().to_ascii_lowercase();
    state.dashboard_boot_time = response.dashboard_boot_time;
    state.reported = true;
    updater::set_cached_country_code(&state.cached_country_code);
    Ok(true)
}

async fn periodic_reports(
    cfg: AgentConfig,
    client: NezhaServiceClient<Channel>,
    mut geoip_state: GeoIpState,
) {
    let mut host_interval = time::interval(host_report_period());
    let mut ip_interval = time::interval(ip_report_period(&cfg));
    host_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    ip_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = host_interval.tick() => {
                match report_host(&cfg, client.clone()).await {
                    Ok(boot_time) => geoip_state.observe_dashboard_boot_time(boot_time),
                    Err(err) => warn!(%err, "failed to report host info"),
                }
            }
            _ = ip_interval.tick() => {
                if let Err(err) = report_geoip(&cfg, client.clone(), &mut geoip_state).await {
                    warn!(%err, "failed to report geoip");
                }
            }
        }
    }
}

async fn report_host(cfg: &AgentConfig, mut client: NezhaServiceClient<Channel>) -> Result<u64> {
    let mut monitor = Monitor::new(cfg);
    let mut request = Request::new(monitor.host());
    apply_auth(cfg, &mut request)?;
    let boot_time = client.report_system_info2(request).await?.into_inner().data;
    Ok(boot_time)
}

fn host_report_period() -> Duration {
    Duration::from_secs(600)
}

fn ip_report_period(cfg: &AgentConfig) -> Duration {
    Duration::from_secs(cfg.ip_report_period.max(30) as u64)
}

async fn fetch_public_ip(cfg: &AgentConfig) -> Option<(String, String)> {
    let endpoints = if cfg.custom_ip_api.is_empty() {
        vec![
            "https://blog.cloudflare.com/cdn-cgi/trace",
            "https://developers.cloudflare.com/cdn-cgi/trace",
            "https://hostinger.com/cdn-cgi/trace",
            "https://ahrefs.com/cdn-cgi/trace",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>()
    } else {
        cfg.custom_ip_api.clone()
    };

    let ipv4_client = dns::single_stack_http_client(&cfg.dns, dns::IpFamily::V4).ok();
    let ipv6_client = dns::single_stack_http_client(&cfg.dns, dns::IpFamily::V6).ok();

    let ipv4_task = async {
        match ipv4_client {
            Some(client) => fetch_public_ip_family(&client, &endpoints, dns::IpFamily::V4).await,
            None => String::new(),
        }
    };
    let ipv6_task = async {
        match ipv6_client {
            Some(client) => fetch_public_ip_family(&client, &endpoints, dns::IpFamily::V6).await,
            None => String::new(),
        }
    };
    let (ipv4, ipv6) = tokio::join!(ipv4_task, ipv6_task);

    if ipv4.is_empty() && ipv6.is_empty() {
        None
    } else {
        Some((ipv4, ipv6))
    }
}

async fn fetch_public_ip_family(
    client: &dns::AgentHttpClient,
    endpoints: &[String],
    family: dns::IpFamily,
) -> String {
    for endpoint in endpoints {
        match client.get(endpoint).await {
            Ok(response) => {
                if let Some(value) = public_ip_for_family(&response.body, family) {
                    return value;
                }
            }
            Err(err) => {
                if single_stack_network_unreachable(&err.to_string()) {
                    break;
                }
            }
        }
    }
    String::new()
}

fn parse_public_ip_response(body: &str) -> Option<(String, String)> {
    let raw = body
        .lines()
        .find_map(|line| line.strip_prefix("ip="))
        .unwrap_or_else(|| body.trim())
        .trim();
    let ip: IpAddr = raw.parse().ok()?;
    match ip {
        IpAddr::V4(_) => Some((raw.to_string(), String::new())),
        IpAddr::V6(_) => Some((String::new(), raw.to_string())),
    }
}

fn public_ip_for_family(body: &str, family: dns::IpFamily) -> Option<String> {
    let (ipv4, ipv6) = parse_public_ip_response(body)?;
    match family {
        dns::IpFamily::V4 if !ipv4.is_empty() => Some(ipv4),
        dns::IpFamily::V6 if !ipv6.is_empty() => Some(ipv6),
        _ => None,
    }
}

fn single_stack_network_unreachable(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("no route to host") || message.contains("network is unreachable")
}

fn selected_geoip_query_ip(ipv4: &str, ipv6: &str, use_ipv6_country_code: bool) -> String {
    if !ipv6.is_empty() && (use_ipv6_country_code || ipv4.is_empty()) {
        ipv6.to_string()
    } else {
        ipv4.to_string()
    }
}

async fn request_tasks(
    mut cfg: AgentConfig,
    config_path: PathBuf,
    mut client: NezhaServiceClient<Channel>,
    reload_tx: oneshot::Sender<()>,
) -> Result<()> {
    let (tx, rx) = mpsc::channel::<TaskResult>(16);
    let mut request = Request::new(ReceiverStream::new(rx));
    apply_auth(&cfg, &mut request)?;
    let mut tasks = client.request_task(request).await?.into_inner();
    let mut reload_tx = Some(reload_tx);

    while let Some(task) = tasks.message().await? {
        if let Some(result) = handle_task(&mut cfg, &config_path, task).await {
            let should_reload =
                result.r#type == TaskType::ApplyConfig.as_u64() && result.successful;
            tx.send(result)
                .await
                .context("failed to send task result")?;
            if should_reload {
                if let Some(reload_tx) = reload_tx.take() {
                    let _ = reload_tx.send(());
                }
                bail!("configuration applied; restarting task stream");
            }
        }
    }
    bail!("task stream closed")
}

async fn handle_task(
    cfg: &mut AgentConfig,
    config_path: &PathBuf,
    task: Task,
) -> Option<TaskResult> {
    let task_type = TaskType::from_u64(task.r#type)?;
    let mut result = TaskResult {
        id: task.id,
        r#type: task.r#type,
        delay: 0.0,
        data: String::new(),
        successful: false,
    };

    let started = std::time::Instant::now();
    match task_type {
        TaskType::Keepalive => return None,
        TaskType::HttpGet => run_http_get(cfg, &task.data, &mut result).await,
        TaskType::TcpPing => run_tcp_ping(cfg, &task.data, &mut result).await,
        TaskType::Command => run_command(cfg, &task.data, &mut result).await,
        TaskType::ReportConfig => {
            run_report_config(cfg, &mut result);
        }
        TaskType::IcmpPing => run_icmp_ping(cfg, &task.data, &mut result).await,
        TaskType::Upgrade => run_upgrade_task(cfg, &mut result).await,
        TaskType::ApplyConfig => run_apply_config(cfg, config_path, &task.data, &mut result),
        TaskType::TerminalGrpc | TaskType::Terminal => {
            let cfg = cfg.clone();
            let data = task.data.clone();
            tokio::spawn(async move {
                if let Err(err) = run_terminal_stream(cfg, &data).await {
                    warn!(%err, "terminal stream task failed");
                }
            });
            return None;
        }
        TaskType::Nat => {
            let cfg = cfg.clone();
            let data = task.data.clone();
            tokio::spawn(async move {
                if let Err(err) = run_nat_stream(cfg, &data).await {
                    warn!(%err, "nat stream task failed");
                }
            });
            return None;
        }
        TaskType::FileManager => {
            let cfg = cfg.clone();
            let data = task.data.clone();
            tokio::spawn(async move {
                if let Err(err) = run_file_manager_stream(cfg, &data).await {
                    warn!(%err, "file manager stream task failed");
                }
            });
            return None;
        }
        TaskType::ReportHostInfoDeprecated => return None,
    }

    if !matches!(
        task_type,
        TaskType::HttpGet | TaskType::TcpPing | TaskType::IcmpPing
    ) {
        result.delay = started.elapsed().as_secs_f32();
    }
    Some(result)
}

async fn run_upgrade_task(cfg: &AgentConfig, result: &mut TaskResult) {
    if cfg.disable_force_update {
        result.data = "force update is disabled".into();
        return;
    }

    match updater::run(cfg, updater::UpdateMode::Force).await {
        Ok(outcome) if outcome.updated => {
            info!(
                provider = ?outcome.provider,
                version = %outcome.version,
                "agent force update installed; exiting for restart"
            );
            std::process::exit(1);
        }
        Ok(outcome) => {
            result.successful = true;
            result.data = format!(
                "agent is up to date via {:?}: {}",
                outcome.provider, outcome.version
            );
        }
        Err(err) => {
            result.data = err.to_string();
        }
    }
}

fn run_report_config(cfg: &AgentConfig, result: &mut TaskResult) {
    if cfg.disable_command_execute {
        result.data = "command execution is disabled".into();
        return;
    }

    result.successful = true;
    result.data = serde_json::to_string(cfg).unwrap_or_else(|err| err.to_string());
}

fn run_apply_config(
    cfg: &mut AgentConfig,
    config_path: &PathBuf,
    data: &str,
    result: &mut TaskResult,
) {
    if cfg.disable_command_execute {
        result.data = "command execution is disabled".into();
        return;
    }

    match apply_config_payload(cfg, config_path, data) {
        Ok(()) => {
            result.successful = true;
            result.data = "configuration applied".into();
        }
        Err(err) => result.data = err.to_string(),
    }
}

fn apply_config_payload(cfg: &mut AgentConfig, config_path: &PathBuf, data: &str) -> Result<()> {
    let mut base =
        serde_json::to_value(cfg.clone()).context("failed to serialize current config")?;
    let patch: serde_json::Value =
        serde_json::from_str(data).context("failed to parse remote config json")?;
    merge_json(&mut base, patch);

    let mut next: AgentConfig =
        serde_json::from_value(base).context("failed to decode remote config")?;
    next.validate(true)?;
    next.save(config_path)?;
    *cfg = next;
    Ok(())
}

fn merge_json(base: &mut serde_json::Value, patch: serde_json::Value) {
    match (base, patch) {
        (serde_json::Value::Object(base), serde_json::Value::Object(patch)) => {
            for (key, value) in patch {
                if value.is_null() {
                    continue;
                }
                match base.get_mut(&key) {
                    Some(existing) => merge_json(existing, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (base, patch) => *base = patch,
    }
}

async fn run_http_get(cfg: &AgentConfig, url: &str, result: &mut TaskResult) {
    if cfg.disable_send_query {
        result.data = "query sending is disabled".into();
        return;
    }
    let started = std::time::Instant::now();
    let client = match dns::http_client(&cfg.dns).await {
        Ok(client) => client,
        Err(err) => {
            result.data = err.to_string();
            return;
        }
    };
    match client.get(url).await {
        Ok(resp) => {
            result.delay = started.elapsed().as_secs_f32() * 1000.0;
            result.successful = dns::upstream_http_success(resp.status);
            if result.successful {
                result.data = resp.tls_certificate_data.unwrap_or_default();
            } else {
                result.data = format!("application error: {}", resp.status_text);
            }
        }
        Err(err) => result.data = err.to_string(),
    }
}

async fn run_tcp_ping(cfg: &AgentConfig, address: &str, result: &mut TaskResult) {
    if cfg.disable_send_query {
        result.data = "query sending is disabled".into();
        return;
    }
    let started = std::time::Instant::now();
    match time::timeout(Duration::from_secs(10), dns::connect_tcp(&cfg.dns, address)).await {
        Ok(Ok(_stream)) => {
            result.delay = started.elapsed().as_secs_f32() * 1000.0;
            result.successful = true;
        }
        Ok(Err(err)) => result.data = err.to_string(),
        Err(_) => result.data = "tcp ping timed out".into(),
    }
}

async fn run_icmp_ping(cfg: &AgentConfig, host: &str, result: &mut TaskResult) {
    if cfg.disable_send_query {
        result.data = "query sending is disabled".into();
        return;
    }
    if host.trim().is_empty() {
        result.data = "icmp ping target is empty".into();
        return;
    }

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = TokioCommand::new("ping");
        command.args(["-n", "5", "-w", "20000", host]);
        command
    };

    #[cfg(not(target_os = "windows"))]
    let mut command = {
        let mut command = TokioCommand::new("ping");
        command.args(["-c", "5", "-W", "20", host]);
        command
    };

    let started = std::time::Instant::now();
    match time::timeout(Duration::from_secs(25), command.output()).await {
        Ok(Ok(output)) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            result.data = if stderr.is_empty() {
                stdout.clone()
            } else {
                format!("{stdout}{stderr}")
            };
            result.successful = output.status.success();
            if result.successful {
                result.delay = parse_ping_average_ms(&stdout)
                    .unwrap_or_else(|| started.elapsed().as_secs_f32() * 1000.0 / 5.0);
            }
        }
        Ok(Err(err)) => result.data = err.to_string(),
        Err(_) => result.data = "icmp ping timed out".into(),
    }
}

async fn run_command(cfg: &AgentConfig, command: &str, result: &mut TaskResult) {
    run_command_with_timeout(cfg, command, result, Duration::from_secs(7200)).await;
}

async fn run_command_with_timeout(
    cfg: &AgentConfig,
    command: &str,
    result: &mut TaskResult,
    timeout: Duration,
) {
    if cfg.disable_command_execute {
        result.data = "command execution is disabled".into();
        return;
    }

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut shell = TokioCommand::new("cmd");
        shell.args(["/C", command]);
        shell
    };

    #[cfg(not(target_os = "windows"))]
    let mut command = {
        let mut shell = TokioCommand::new("sh");
        shell.args(["-c", command]);
        shell
    };

    process_group::prepare_process_group(&mut command);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            result.data = err.to_string();
            return;
        }
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_reader = stdout.map(|stdout| tokio::spawn(read_child_pipe(stdout)));
    let stderr_reader = stderr.map(|stderr| tokio::spawn(read_child_pipe(stderr)));

    match time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => {
            result.successful = status.success();
        }
        Ok(Err(err)) => {
            result.data = err.to_string();
        }
        Err(_) => {
            result.data = "command timed out".into();
            process_group::terminate_process_group(&mut child).await;
        }
    }

    if let Some(output) = collect_child_pipe(stdout_reader).await {
        result.data.push_str(&output);
    }
    if let Some(output) = collect_child_pipe(stderr_reader).await {
        result.data.push_str(&output);
    }
}

async fn read_child_pipe<R>(mut reader: R) -> String
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    let _ = reader.read_to_end(&mut output).await;
    String::from_utf8_lossy(&output).to_string()
}

async fn collect_child_pipe(reader: Option<tokio::task::JoinHandle<String>>) -> Option<String> {
    reader?.await.ok()
}

async fn run_terminal_stream(cfg: AgentConfig, data: &str) -> Result<()> {
    let task: StreamTask = serde_json::from_str(data).context("failed to parse terminal task")?;
    if task.stream_id.trim().is_empty() {
        bail!("terminal stream id is empty");
    }
    let (tx, mut remote) = open_iostream(&cfg, &task.stream_id).await?;
    if cfg.disable_command_execute {
        send_terminal_error(&tx, "command execution is disabled").await;
        bail!("command execution is disabled");
    }

    let pty_system = native_pty_system();
    let pair = match pty_system.openpty(default_pty_size()) {
        Ok(pair) => pair,
        Err(err) => {
            let message = format!("failed to open terminal pty: {err}");
            send_terminal_error(&tx, &message).await;
            bail!(message);
        }
    };
    let mut child = match pair.slave.spawn_command(terminal_command()) {
        Ok(child) => child,
        Err(err) => {
            let message = format!("failed to spawn terminal shell: {err}");
            send_terminal_error(&tx, &message).await;
            bail!(message);
        }
    };
    drop(pair.slave);

    let mut reader = match pair.master.try_clone_reader() {
        Ok(reader) => reader,
        Err(err) => {
            let message = format!("failed to clone terminal pty reader: {err}");
            send_terminal_error(&tx, &message).await;
            bail!(message);
        }
    };
    let mut writer = match pair.master.take_writer() {
        Ok(writer) => writer,
        Err(err) => {
            let message = format!("failed to open terminal pty writer: {err}");
            send_terminal_error(&tx, &message).await;
            bail!(message);
        }
    };

    let (pty_tx, mut pty_rx) = mpsc::channel::<Vec<u8>>(64);
    let reader_task = tokio::task::spawn_blocking(move || {
        let mut buf = vec![0; 16 * 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if pty_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(err) => {
                    warn!(error = %err, "terminal pty read failed");
                    break;
                }
            }
        }
    });
    let to_agent_tx = tx.clone();
    let output_task = tokio::spawn(async move {
        while let Some(data) = pty_rx.recv().await {
            if let Err(err) = to_agent_tx.send(IoStreamData { data }).await {
                warn!(error = %err, "terminal output forward failed");
                break;
            }
        }
    });

    loop {
        let Some(data) = remote.message().await? else {
            break;
        };
        if data.data.is_empty() {
            continue;
        }
        match parse_terminal_input(&data.data) {
            TerminalInput::Resize(size) => {
                pair.master.resize(size)?;
            }
            TerminalInput::Data(input) => {
                writer.write_all(input)?;
                writer.flush()?;
            }
        }
    }
    let _ = child.kill();
    let _ = tokio::task::spawn_blocking(move || {
        let mut child = child;
        let _ = child.wait();
    })
    .await;
    let _ = reader_task.await;
    output_task.abort();
    Ok(())
}

async fn send_terminal_error(tx: &mpsc::Sender<IoStreamData>, error: &str) {
    let message = format!("\r\n[nezha] terminal error: {error}\r\n");
    let _ = tx
        .send(IoStreamData {
            data: message.into_bytes(),
        })
        .await;
}

fn default_pty_size() -> PtySize {
    PtySize {
        rows: 24,
        cols: 80,
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn terminal_command() -> CommandBuilder {
    #[cfg(target_os = "windows")]
    {
        CommandBuilder::new("cmd.exe")
    }
    #[cfg(not(target_os = "windows"))]
    {
        CommandBuilder::new(std::env::var("SHELL").unwrap_or_else(|_| "sh".to_string()))
    }
}

fn parse_terminal_resize(raw: &[u8]) -> Option<PtySize> {
    let size: WindowSize = serde_json::from_slice(raw).ok()?;
    Some(PtySize {
        rows: size.rows.max(1),
        cols: size.cols.max(1),
        pixel_width: 0,
        pixel_height: 0,
    })
}

enum TerminalInput<'a> {
    Resize(PtySize),
    Data(&'a [u8]),
}

fn parse_terminal_input(data: &[u8]) -> TerminalInput<'_> {
    if data.first() == Some(&1)
        && data.len() > 1
        && let Some(size) = parse_terminal_resize(&data[1..])
    {
        return TerminalInput::Resize(size);
    }
    TerminalInput::Data(data)
}

async fn run_nat_stream(cfg: AgentConfig, data: &str) -> Result<()> {
    if cfg.disable_nat {
        bail!("nat traversal is disabled");
    }
    let task: StreamTask = serde_json::from_str(data).context("failed to parse nat task")?;
    if task.stream_id.trim().is_empty() {
        bail!("nat stream id is empty");
    }
    if task.host.trim().is_empty() {
        bail!("nat target host is empty");
    }
    let (tx, mut remote) = open_iostream(&cfg, &task.stream_id).await?;
    let socket = TcpStream::connect(&task.host)
        .await
        .with_context(|| format!("failed to connect nat target {}", task.host))?;
    let (mut socket_read, mut socket_write) = socket.into_split();
    tokio::spawn(async move {
        let mut buf = vec![0; 16 * 1024];
        loop {
            let Ok(n) = socket_read.read(&mut buf).await else {
                break;
            };
            if n == 0 {
                break;
            }
            if tx
                .send(IoStreamData {
                    data: buf[..n].to_vec(),
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });

    while let Some(data) = remote.message().await? {
        if data.data.is_empty() {
            continue;
        }
        socket_write.write_all(&data.data).await?;
    }
    Ok(())
}

async fn run_file_manager_stream(cfg: AgentConfig, data: &str) -> Result<()> {
    if cfg.disable_command_execute {
        bail!("command execution is disabled");
    }
    let task: StreamTask = serde_json::from_str(data).context("failed to parse file task")?;
    if task.stream_id.trim().is_empty() {
        bail!("file manager stream id is empty");
    }
    let (tx, mut remote) = open_iostream(&cfg, &task.stream_id).await?;

    while let Some(data) = remote.message().await? {
        if data.data.is_empty() {
            continue;
        }
        match data.data[0] {
            0 => fm_list_dir(&tx, &data.data[1..]).await,
            1 => {
                let path = String::from_utf8_lossy(&data.data[1..]).to_string();
                let tx = tx.clone();
                tokio::spawn(async move {
                    fm_download(&tx, &path).await;
                });
            }
            2 => fm_upload(&tx, &mut remote, &data.data).await,
            _ => send_fm_error(&tx, "unsupported file manager task").await,
        }
    }
    Ok(())
}

async fn open_iostream(
    cfg: &AgentConfig,
    stream_id: &str,
) -> Result<(mpsc::Sender<IoStreamData>, Streaming<IoStreamData>)> {
    let channel = connect(cfg).await?;
    let mut client = NezhaServiceClient::new(channel);
    let (tx, rx) = mpsc::channel::<IoStreamData>(64);
    let mut init = vec![0xff, 0x05, 0xff, 0x05];
    init.extend_from_slice(stream_id.as_bytes());
    tx.send(IoStreamData { data: init })
        .await
        .context("failed to queue iostream init")?;
    let mut request = Request::new(ReceiverStream::new(rx));
    apply_auth(cfg, &mut request)?;
    let remote = client.io_stream(request).await?.into_inner();
    Ok((tx, remote))
}

const FM_FILE: &[u8; 4] = b"NZTD";
const FM_FILE_NAME: &[u8; 4] = b"NZFN";
const FM_ERROR: &[u8; 4] = b"NERR";
const FM_COMPLETE: &[u8; 4] = b"NZUP";

async fn fm_list_dir(tx: &mpsc::Sender<IoStreamData>, raw_path: &[u8]) {
    let mut path = String::from_utf8_lossy(raw_path).to_string();
    let mut entries = match tokio::fs::read_dir(&path).await {
        Ok(entries) => entries,
        Err(_) => {
            path = fallback_home_dir();
            match tokio::fs::read_dir(&path).await {
                Ok(entries) => entries,
                Err(err) => {
                    send_fm_error(tx, &err.to_string()).await;
                    return;
                }
            }
        }
    };

    let mut payload = create_fm_dir_payload_header(&path);
    loop {
        match entries.next_entry().await {
            Ok(Some(entry)) => {
                let name = entry.file_name().to_string_lossy().to_string();
                let is_dir = entry
                    .file_type()
                    .await
                    .map(|ty| ty.is_dir())
                    .unwrap_or(false);
                append_fm_file_name(&mut payload, &name, is_dir);
            }
            Ok(None) => break,
            Err(err) => {
                send_fm_error(tx, &err.to_string()).await;
                return;
            }
        }
    }

    let _ = tx.send(IoStreamData { data: payload }).await;
}

async fn fm_download(tx: &mpsc::Sender<IoStreamData>, path: &str) {
    if path.is_empty() {
        send_fm_error(tx, "download path is empty").await;
        return;
    }
    if !is_safe_fm_path(path) {
        send_fm_error(tx, "download path is not allowed").await;
        return;
    }
    let mut file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(err) => {
            send_fm_error(tx, &err.to_string()).await;
            return;
        }
    };
    let size = match file.metadata().await {
        Ok(metadata) => metadata.len(),
        Err(err) => {
            send_fm_error(tx, &err.to_string()).await;
            return;
        }
    };
    let mut header = Vec::with_capacity(12);
    header.extend_from_slice(FM_FILE);
    header.extend_from_slice(&size.to_be_bytes());
    if tx.send(IoStreamData { data: header }).await.is_err() {
        return;
    }

    let mut buf = vec![0; 1024 * 1024];
    loop {
        match file.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if tx
                    .send(IoStreamData {
                        data: buf[..n].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(err) => {
                send_fm_error(tx, &err.to_string()).await;
                break;
            }
        }
    }
}

async fn fm_upload(
    tx: &mpsc::Sender<IoStreamData>,
    remote: &mut Streaming<IoStreamData>,
    first: &[u8],
) {
    if first.len() < 9 {
        send_fm_error(tx, "data is invalid").await;
        return;
    }
    let size_bytes: [u8; 8] = match first[1..9].try_into() {
        Ok(arr) => arr,
        Err(_) => {
            send_fm_error(tx, "data is invalid").await;
            return;
        }
    };
    let size = u64::from_be_bytes(size_bytes);
    let path = String::from_utf8_lossy(&first[9..]).to_string();
    if path.is_empty() {
        send_fm_error(tx, "upload path is empty").await;
        return;
    }
    if !is_safe_fm_path(&path) {
        send_fm_error(tx, "upload path is not allowed").await;
        return;
    }
    let mut file = match tokio::fs::File::create(&path).await {
        Ok(file) => file,
        Err(err) => {
            send_fm_error(tx, &err.to_string()).await;
            return;
        }
    };
    let mut received = 0_u64;
    while received < size {
        let data = match remote.message().await {
            Ok(Some(data)) => data.data,
            Ok(None) => {
                send_fm_error(tx, "upload stream closed").await;
                return;
            }
            Err(err) => {
                send_fm_error(tx, &err.to_string()).await;
                return;
            }
        };
        let remaining = (size - received) as usize;
        let chunk = if data.len() > remaining {
            &data[..remaining]
        } else {
            &data
        };
        if let Err(err) = file.write_all(chunk).await {
            send_fm_error(tx, &err.to_string()).await;
            return;
        }
        received += chunk.len() as u64;
    }
    let _ = tx
        .send(IoStreamData {
            data: FM_COMPLETE.to_vec(),
        })
        .await;
}

async fn send_fm_error(tx: &mpsc::Sender<IoStreamData>, error: &str) {
    let mut payload = FM_ERROR.to_vec();
    payload.extend_from_slice(error.as_bytes());
    let _ = tx.send(IoStreamData { data: payload }).await;
}

fn is_safe_fm_path(raw: &str) -> bool {
    use std::path::{Component, Path};
    let p = Path::new(raw);
    for comp in p.components() {
        if matches!(comp, Component::ParentDir) {
            return false;
        }
    }
    true
}

fn create_fm_dir_payload_header(path: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + path.len());
    payload.extend_from_slice(FM_FILE_NAME);
    payload.extend_from_slice(&(path.len() as u32).to_be_bytes());
    payload.extend_from_slice(path.as_bytes());
    payload
}

fn append_fm_file_name(payload: &mut Vec<u8>, name: &str, is_dir: bool) {
    let bytes = name.as_bytes();
    let max = u8::MAX as usize;
    let mut len = bytes.len().min(max);
    while len > 0 && !name.is_char_boundary(len) {
        len -= 1;
    }
    payload.push(if is_dir { 1 } else { 0 });
    payload.push(len as u8);
    payload.extend_from_slice(&bytes[..len]);
}

fn fallback_home_dir() -> String {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".to_string())
}

fn parse_ping_average_ms(output: &str) -> Option<f32> {
    parse_windows_ping_average_ms(output).or_else(|| parse_unix_ping_average_ms(output))
}

fn parse_windows_ping_average_ms(output: &str) -> Option<f32> {
    let line = output
        .lines()
        .find(|line| line.contains("Average =") || line.contains("平均 ="))?;
    let raw = line
        .split("Average =")
        .nth(1)
        .or_else(|| line.split("平均 =").nth(1))?
        .trim();
    parse_ms_prefix(raw)
}

fn parse_unix_ping_average_ms(output: &str) -> Option<f32> {
    let line = output
        .lines()
        .find(|line| line.contains("min/avg/max") || line.contains("round-trip min/avg/max"))?;
    let stats = line.split('=').nth(1)?.trim();
    let avg = stats.split('/').nth(1)?.trim();
    avg.parse().ok()
}

fn parse_ms_prefix(raw: &str) -> Option<f32> {
    let raw = raw.trim_start_matches('<').trim();
    let number: String = raw
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
        .collect();
    number.parse().ok()
}

fn apply_auth<T>(cfg: &AgentConfig, request: &mut Request<T>) -> Result<()> {
    let metadata = request.metadata_mut();
    metadata.insert(
        "client_secret",
        MetadataValue::try_from(cfg.client_secret.as_str()).context("invalid client_secret")?,
    );
    metadata.insert(
        "client_uuid",
        MetadataValue::try_from(cfg.uuid.to_string()).context("invalid client_uuid")?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AgentConfig {
        AgentConfig {
            server: "127.0.0.1:5555".to_string(),
            client_secret: "secret".to_string(),
            report_delay: 3,
            ..AgentConfig::default()
        }
    }

    fn temp_config_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("nezha-agent-{name}-{nanos}.yml"))
    }

    #[tokio::test]
    async fn apply_config_task_merges_saves_and_updates_reported_config() {
        let mut cfg = test_config();
        let path = temp_config_path("apply");
        cfg.save(&path).unwrap();

        let result = handle_task(
            &mut cfg,
            &path,
            Task {
                id: 10,
                r#type: TaskType::ApplyConfig.as_u64(),
                data: serde_json::json!({
                    "report_delay": 4,
                    "disable_send_query": true
                })
                .to_string(),
            },
        )
        .await
        .unwrap();

        assert!(result.successful);
        assert_eq!(cfg.report_delay, 4);
        assert!(cfg.disable_send_query);

        let saved = AgentConfig::load(&path).unwrap();
        assert_eq!(saved.report_delay, 4);
        assert!(saved.disable_send_query);

        let report = handle_task(
            &mut cfg,
            &path,
            Task {
                id: 11,
                r#type: TaskType::ReportConfig.as_u64(),
                data: String::new(),
            },
        )
        .await
        .unwrap();
        assert!(report.successful);
        assert!(report.data.contains("\"report_delay\":4"));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn apply_config_rejects_invalid_remote_config() {
        let mut cfg = test_config();
        let path = temp_config_path("reject");
        cfg.save(&path).unwrap();

        let result = handle_task(
            &mut cfg,
            &path,
            Task {
                id: 12,
                r#type: TaskType::ApplyConfig.as_u64(),
                data: serde_json::json!({ "report_delay": 99 }).to_string(),
            },
        )
        .await
        .unwrap();

        assert!(!result.successful);
        assert_eq!(cfg.report_delay, 3);
        assert!(result.data.contains("report_delay ranges"));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn upgrade_task_respects_force_update_disable_flag() {
        let mut cfg = AgentConfig {
            disable_force_update: true,
            ..test_config()
        };
        let path = temp_config_path("upgrade-disabled");

        let result = handle_task(
            &mut cfg,
            &path,
            Task {
                id: 13,
                r#type: TaskType::Upgrade.as_u64(),
                data: String::new(),
            },
        )
        .await
        .unwrap();

        assert!(!result.successful);
        assert_eq!(result.data, "force update is disabled");
    }

    #[test]
    fn parses_ping_average_from_common_outputs() {
        let windows = r#"
Minimum = 1ms, Maximum = 3ms, Average = 2ms
"#;
        let linux = r#"
rtt min/avg/max/mdev = 0.026/1.250/3.000/0.010 ms
"#;
        let macos = r#"
round-trip min/avg/max/stddev = 1.100/2.500/4.200/0.300 ms
"#;

        assert_eq!(parse_ping_average_ms(windows), Some(2.0));
        assert_eq!(parse_ping_average_ms(linux), Some(1.25));
        assert_eq!(parse_ping_average_ms(macos), Some(2.5));
    }

    #[test]
    fn parses_public_ip_from_trace_or_plain_body() {
        assert_eq!(
            parse_public_ip_response("fl=1\nip=203.0.113.10\nloc=US\n"),
            Some(("203.0.113.10".to_string(), String::new()))
        );
        assert_eq!(
            parse_public_ip_response("2001:db8::1\n"),
            Some((String::new(), "2001:db8::1".to_string()))
        );
        assert_eq!(parse_public_ip_response("not an ip"), None);
    }

    #[test]
    fn public_ip_family_selection_matches_requested_stack() {
        assert_eq!(
            public_ip_for_family("fl=1\nip=203.0.113.10\n", dns::IpFamily::V4),
            Some("203.0.113.10".to_string())
        );
        assert_eq!(
            public_ip_for_family("fl=1\nip=203.0.113.10\n", dns::IpFamily::V6),
            None
        );
        assert_eq!(
            public_ip_for_family("2001:db8::1\n", dns::IpFamily::V6),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn single_stack_unreachable_detection_matches_upstream_short_circuit() {
        assert!(single_stack_network_unreachable(
            "failed to GET endpoint: no route to host"
        ));
        assert!(single_stack_network_unreachable(
            "connect error: Network is unreachable"
        ));
        assert!(!single_stack_network_unreachable(
            "failed to GET endpoint: the AAAA record not resolved"
        ));
    }

    #[test]
    fn geoip_state_retries_after_dashboard_reboot_or_ip_change() {
        let mut state = GeoIpState::default();
        assert!(!state.reported);

        state.query_ip = "203.0.113.10".to_string();
        state.dashboard_boot_time = 100;
        state.reported = true;
        state.observe_dashboard_boot_time(100);
        assert!(state.reported);

        state.observe_dashboard_boot_time(200);
        assert!(!state.reported);

        assert_eq!(
            selected_geoip_query_ip("203.0.113.10", "2001:db8::1", false),
            "203.0.113.10"
        );
        assert_eq!(
            selected_geoip_query_ip("203.0.113.10", "2001:db8::1", true),
            "2001:db8::1"
        );
        assert_eq!(
            selected_geoip_query_ip("", "2001:db8::1", false),
            "2001:db8::1"
        );
    }

    #[test]
    fn file_manager_directory_payload_matches_upstream_shape() {
        let mut payload = create_fm_dir_payload_header("/tmp");
        append_fm_file_name(&mut payload, "file.txt", false);
        append_fm_file_name(&mut payload, "dir", true);

        assert_eq!(&payload[..4], b"NZFN");
        assert_eq!(u32::from_be_bytes(payload[4..8].try_into().unwrap()), 4);
        assert_eq!(&payload[8..12], b"/tmp");
        assert_eq!(payload[12], 0);
        assert_eq!(payload[13], 8);
        assert_eq!(&payload[14..22], b"file.txt");
        assert_eq!(payload[22], 1);
        assert_eq!(payload[23], 3);
        assert_eq!(&payload[24..27], b"dir");
    }

    #[tokio::test]
    async fn file_manager_download_allows_zero_byte_files() {
        let path =
            std::env::temp_dir().join(format!("nezha-empty-download-{}", uuid::Uuid::new_v4()));
        tokio::fs::write(&path, []).await.unwrap();
        let (tx, mut rx) = mpsc::channel(2);

        fm_download(&tx, &path.to_string_lossy()).await;

        let header = rx.recv().await.unwrap().data;
        assert_eq!(&header[..4], FM_FILE);
        assert_eq!(u64::from_be_bytes(header[4..12].try_into().unwrap()), 0);
        assert!(rx.try_recv().is_err());
        let _ = tokio::fs::remove_file(path).await;
    }

    #[test]
    fn terminal_resize_payload_accepts_upstream_shape() {
        let size = parse_terminal_resize(br#"{"Cols":132,"Rows":43}"#).unwrap();

        assert_eq!(size.cols, 132);
        assert_eq!(size.rows, 43);
    }

    #[test]
    fn terminal_input_keeps_ctrl_a_frames_when_resize_parse_fails() {
        match parse_terminal_input(b"\x01a") {
            TerminalInput::Data(data) => assert_eq!(data, b"\x01a"),
            TerminalInput::Resize(_) => panic!("ctrl-a input must not be treated as resize"),
        }

        let mut resize = vec![1];
        resize.extend_from_slice(br#"{"Cols":132,"Rows":43}"#);
        match parse_terminal_input(&resize) {
            TerminalInput::Resize(size) => {
                assert_eq!(size.cols, 132);
                assert_eq!(size.rows, 43);
            }
            TerminalInput::Data(_) => panic!("valid resize frame must remain resize"),
        }
    }

    #[test]
    fn report_periods_match_agent_defaults() {
        let mut cfg = test_config();
        cfg.ip_report_period = 0;
        assert_eq!(host_report_period(), Duration::from_secs(600));
        assert_eq!(ip_report_period(&cfg), Duration::from_secs(30));

        cfg.ip_report_period = 1800;
        assert_eq!(ip_report_period(&cfg), Duration::from_secs(1800));
    }

    #[test]
    fn windows_arch_guard_normalizes_kernel_arch_names() {
        assert_eq!(
            windows_kernel_arch_from_env(Some("AMD64"), None),
            Some("x86_64")
        );
        assert_eq!(
            windows_kernel_arch_from_env(Some("x86"), Some("ARM64")),
            Some("aarch64")
        );
        assert_eq!(
            windows_kernel_arch_from_env(Some("i686"), None),
            Some("x86")
        );
        assert_eq!(windows_kernel_arch_from_env(Some("mips"), None), None);
    }

    #[tokio::test]
    async fn icmp_ping_respects_query_disable_flag() {
        let mut result = TaskResult {
            id: 1,
            r#type: TaskType::IcmpPing.as_u64(),
            delay: 0.0,
            data: String::new(),
            successful: false,
        };
        let cfg = AgentConfig {
            disable_send_query: true,
            ..test_config()
        };

        run_icmp_ping(&cfg, "127.0.0.1", &mut result).await;

        assert!(!result.successful);
        assert_eq!(result.data, "query sending is disabled");
    }

    #[tokio::test]
    async fn command_timeout_reports_failure_and_cleans_process_group() {
        let mut result = TaskResult {
            id: 2,
            r#type: TaskType::Command.as_u64(),
            delay: 0.0,
            data: String::new(),
            successful: false,
        };

        #[cfg(target_os = "windows")]
        let command = "ping -n 6 127.0.0.1 > NUL";
        #[cfg(not(target_os = "windows"))]
        let command = "sleep 5";

        run_command_with_timeout(
            &test_config(),
            command,
            &mut result,
            Duration::from_millis(100),
        )
        .await;

        assert!(!result.successful);
        assert!(result.data.contains("command timed out"));
    }
}
