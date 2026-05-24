use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use hickory_resolver::{
    TokioAsyncResolver,
    config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts},
};
use reqwest::{
    Client as ReqwestClient,
    dns::{Addrs, Name, Resolve, Resolving},
    header::{ACCEPT, ACCEPT_LANGUAGE, HeaderMap, HeaderValue, USER_AGENT},
};
use spectreq::{
    Client as SpectreqClient, Profile, RedirectConfig, TimeoutConfig,
    core::Headers as SpectreqHeaders,
};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn matches(self, ip: IpAddr) -> bool {
        match self {
            Self::V4 => ip.is_ipv4(),
            Self::V6 => ip.is_ipv6(),
        }
    }

    fn record_type(self) -> &'static str {
        match self {
            Self::V4 => "A",
            Self::V6 => "AAAA",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AgentDnsResolver {
    inner: TokioAsyncResolver,
}

impl AgentDnsResolver {
    fn new(servers: &[String]) -> Result<Self> {
        let configs = parse_dns_servers(servers)?;
        let group = NameServerConfigGroup::from(
            configs
                .into_iter()
                .flat_map(|socket_addr| {
                    [
                        name_server_config(socket_addr, Protocol::Udp),
                        name_server_config(socket_addr, Protocol::Tcp),
                    ]
                })
                .collect::<Vec<_>>(),
        );
        let config = ResolverConfig::from_parts(None, Vec::new(), group);
        Ok(Self {
            inner: TokioAsyncResolver::tokio(config, ResolverOpts::default()),
        })
    }

    async fn lookup_socket_addrs(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let addrs = self
            .inner
            .lookup_ip(host)
            .await
            .with_context(|| format!("failed to resolve {host}"))?
            .iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>();
        anyhow::ensure!(!addrs.is_empty(), "no address resolved for {host}");
        Ok(addrs)
    }

    async fn lookup_socket_addrs_for_family(
        &self,
        host: &str,
        port: u16,
        family: IpFamily,
    ) -> Result<Vec<SocketAddr>> {
        let addrs =
            filter_socket_addrs_by_family(self.lookup_socket_addrs(host, port).await?, family);
        anyhow::ensure!(
            !addrs.is_empty(),
            "the {} record not resolved",
            family.record_type()
        );
        Ok(addrs)
    }
}

impl Resolve for AgentDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = resolver.lookup_socket_addrs(&host, 0).await?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

pub(crate) struct AgentHttpResponse {
    pub status: u16,
    pub status_text: String,
    pub body: String,
    pub tls_certificate_data: Option<String>,
}

pub(crate) enum AgentHttpClient {
    Browser(SpectreqClient),
    Resolver(ReqwestClient),
}

impl AgentHttpClient {
    pub(crate) async fn get(&self, url: &str) -> Result<AgentHttpResponse> {
        match self {
            Self::Browser(client) => {
                let response = client
                    .get(url)
                    .await
                    .with_context(|| format!("failed to GET {url}"))?;
                Ok(AgentHttpResponse {
                    status: response.status,
                    status_text: response.status.to_string(),
                    body: response.text()?,
                    tls_certificate_data: fetch_tls_certificate_data(url).await.unwrap_or(None),
                })
            }
            Self::Resolver(client) => {
                let response = client
                    .get(url)
                    .send()
                    .await
                    .with_context(|| format!("failed to GET {url}"))?;
                let status = response.status();
                let tls_certificate_data = response
                    .extensions()
                    .get::<reqwest::tls::TlsInfo>()
                    .and_then(|info| info.peer_certificate())
                    .and_then(certificate_data_from_der);
                Ok(AgentHttpResponse {
                    status: status.as_u16(),
                    status_text: status.to_string(),
                    body: response.text().await?,
                    tls_certificate_data,
                })
            }
        }
    }
}

pub(crate) async fn http_client(cfg_dns: &[String]) -> Result<AgentHttpClient> {
    if cfg_dns.is_empty() {
        let client = SpectreqClient::builder()
            .profile(chrome_profile())
            .enable_cache(false)
            .enable_cookies(false)
            .headers(browser_headers_spectreq())
            .redirect_config(RedirectConfig::new().follow(false))
            .timeout_config(
                TimeoutConfig::new()
                    .connect(std::time::Duration::from_secs(5))
                    .read(std::time::Duration::from_secs(30))
                    .total(std::time::Duration::from_secs(30)),
            )
            .build()
            .await
            .context("failed to build browser-fingerprint http client")?;
        return Ok(AgentHttpClient::Browser(client));
    }

    let builder = ReqwestClient::builder()
        .default_headers(browser_headers_reqwest())
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .tls_info(true)
        .dns_resolver(Arc::new(AgentDnsResolver::new(cfg_dns)?));
    Ok(AgentHttpClient::Resolver(
        builder
            .build()
            .context("failed to build resolver http client")?,
    ))
}

pub(crate) fn single_stack_http_client(
    cfg_dns: &[String],
    family: IpFamily,
) -> Result<AgentHttpClient> {
    let builder = ReqwestClient::builder()
        .default_headers(browser_headers_reqwest())
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .dns_resolver(Arc::new(SingleStackResolver::new(cfg_dns, family)?));
    Ok(AgentHttpClient::Resolver(
        builder
            .build()
            .context("failed to build single-stack http client")?,
    ))
}

fn chrome_profile() -> Profile {
    #[cfg(target_os = "macos")]
    {
        return Profile::chrome_120_macos();
    }
    #[cfg(target_os = "linux")]
    {
        return Profile::chrome_120_linux();
    }
    #[cfg(target_os = "android")]
    {
        return Profile::chrome_120_android();
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    {
        Profile::chrome_120_windows()
    }
}

fn browser_headers_reqwest() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        ),
    );
    headers.insert(
        ACCEPT_LANGUAGE,
        HeaderValue::from_static("en,zh-CN;q=0.9,zh;q=0.8"),
    );
    headers.insert(USER_AGENT, HeaderValue::from_static("nezha-agent/1.0"));
    headers
}

fn browser_headers_spectreq() -> SpectreqHeaders {
    HashMap::from([
        (
            "Accept".to_string(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
                .to_string(),
        ),
        (
            "Accept-Language".to_string(),
            "en,zh-CN;q=0.9,zh;q=0.8".to_string(),
        ),
        ("User-Agent".to_string(), "nezha-agent/1.0".to_string()),
    ])
}

pub(crate) fn upstream_http_success(status: u16) -> bool {
    (200..=399).contains(&status)
}

async fn fetch_tls_certificate_data(url: &str) -> Result<Option<String>> {
    if !url
        .get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
    {
        return Ok(None);
    }
    let client = ReqwestClient::builder()
        .default_headers(browser_headers_reqwest())
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .tls_info(true)
        .build()
        .context("failed to build tls-info http client")?;
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to GET {url} for tls info"))?;
    Ok(response
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .and_then(certificate_data_from_der))
}

pub(crate) fn certificate_data_from_der(der: &[u8]) -> Option<String> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    let issuer = certificate
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok())
        .unwrap_or_default();
    let not_after = certificate.validity().not_after.to_datetime();
    Some(format!(
        "{issuer}|{:04}-{:02}-{:02} {:02}:{:02}:{:02} +0000 UTC",
        not_after.year(),
        u8::from(not_after.month()),
        not_after.day(),
        not_after.hour(),
        not_after.minute(),
        not_after.second(),
    ))
}

pub(crate) async fn connect_tcp(cfg_dns: &[String], address: &str) -> Result<TcpStream> {
    if cfg_dns.is_empty() {
        return TcpStream::connect(address)
            .await
            .with_context(|| format!("failed to connect {address}"));
    }

    let (host, port) = split_host_port(address)?;
    let resolver = AgentDnsResolver::new(cfg_dns)?;
    let addrs = resolver.lookup_socket_addrs(&host, port).await?;
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow!("failed to connect {address}")))
}

#[derive(Debug, Clone)]
struct SingleStackResolver {
    family: IpFamily,
    configured: Option<AgentDnsResolver>,
    fallback: AgentDnsResolver,
}

impl SingleStackResolver {
    fn new(cfg_dns: &[String], family: IpFamily) -> Result<Self> {
        let configured = if cfg_dns.is_empty() {
            None
        } else {
            Some(AgentDnsResolver::new(cfg_dns)?)
        };
        Ok(Self {
            family,
            configured,
            fallback: AgentDnsResolver::new(&default_dns_servers(family))?,
        })
    }
}

impl Resolve for SingleStackResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let family = self.family;
        let host = name.as_str().trim_end_matches('.').to_string();
        let configured = self.configured.clone();
        let fallback = self.fallback.clone();
        Box::pin(async move {
            if let Ok(addrs) = lookup_system_socket_addrs(&host, family).await {
                return Ok(Box::new(addrs.into_iter()) as Addrs);
            }

            if let Some(resolver) = configured {
                if let Ok(addrs) = resolver
                    .lookup_socket_addrs_for_family(&host, 0, family)
                    .await
                {
                    return Ok(Box::new(addrs.into_iter()) as Addrs);
                }
            }

            let addrs = fallback
                .lookup_socket_addrs_for_family(&host, 0, family)
                .await?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

async fn lookup_system_socket_addrs(host: &str, family: IpFamily) -> Result<Vec<SocketAddr>> {
    let addrs = tokio::net::lookup_host((host, 0))
        .await
        .with_context(|| format!("failed to resolve {host}"))?
        .collect::<Vec<_>>();
    let addrs = filter_socket_addrs_by_family(addrs, family);
    anyhow::ensure!(
        !addrs.is_empty(),
        "the {} record not resolved",
        family.record_type()
    );
    Ok(addrs)
}

fn filter_socket_addrs_by_family(addrs: Vec<SocketAddr>, family: IpFamily) -> Vec<SocketAddr> {
    addrs
        .into_iter()
        .filter(|addr| family.matches(addr.ip()))
        .collect()
}

fn default_dns_servers(family: IpFamily) -> Vec<String> {
    match family {
        IpFamily::V4 => vec![
            "8.8.8.8:53".to_string(),
            "8.8.4.4:53".to_string(),
            "1.1.1.1:53".to_string(),
            "1.0.0.1:53".to_string(),
        ],
        IpFamily::V6 => vec![
            "[2001:4860:4860::8888]:53".to_string(),
            "[2001:4860:4860::8844]:53".to_string(),
            "[2606:4700:4700::1111]:53".to_string(),
            "[2606:4700:4700::1001]:53".to_string(),
        ],
    }
}

fn name_server_config(socket_addr: SocketAddr, protocol: Protocol) -> NameServerConfig {
    NameServerConfig {
        socket_addr,
        protocol,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    }
}

fn split_host_port(address: &str) -> Result<(String, u16)> {
    if let Some(rest) = address.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').context("invalid bracketed address")?;
        let port = rest
            .strip_prefix(':')
            .context("missing port")?
            .parse()
            .context("invalid port")?;
        return Ok((host.to_string(), port));
    }

    let (host, port) = address.rsplit_once(':').context("missing port")?;
    let port = port.parse().context("invalid port")?;
    anyhow::ensure!(!host.is_empty(), "missing host");
    Ok((host.to_string(), port))
}

fn parse_dns_servers(servers: &[String]) -> Result<Vec<SocketAddr>> {
    let mut addrs = Vec::new();
    for raw in servers {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            addrs.push(addr);
            continue;
        }
        let ip = raw
            .parse::<IpAddr>()
            .with_context(|| format!("invalid dns server {raw}"))?;
        addrs.push(SocketAddr::new(ip, 53));
    }
    anyhow::ensure!(!addrs.is_empty(), "dns server list is empty");
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_servers_with_default_and_explicit_ports() {
        let servers = parse_dns_servers(&[
            "1.1.1.1".to_string(),
            "8.8.8.8:5353".to_string(),
            "2001:4860:4860::8888".to_string(),
            "[2606:4700:4700::1111]:5353".to_string(),
        ])
        .unwrap();

        assert_eq!(servers[0], "1.1.1.1:53".parse().unwrap());
        assert_eq!(servers[1], "8.8.8.8:5353".parse().unwrap());
        assert_eq!(servers[2], "[2001:4860:4860::8888]:53".parse().unwrap());
        assert_eq!(servers[3], "[2606:4700:4700::1111]:5353".parse().unwrap());
    }

    #[test]
    fn split_host_port_accepts_hosts_and_bracketed_ipv6() {
        assert_eq!(
            split_host_port("example.com:443").unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".to_string(), 443)
        );
        assert!(split_host_port("example.com").is_err());
    }

    #[test]
    fn browser_headers_match_upstream_agent() {
        let headers = browser_headers_reqwest();
        assert_eq!(
            headers.get(USER_AGENT).unwrap(),
            HeaderValue::from_static("nezha-agent/1.0")
        );
        assert_eq!(
            headers.get(ACCEPT_LANGUAGE).unwrap(),
            HeaderValue::from_static("en,zh-CN;q=0.9,zh;q=0.8")
        );
    }

    #[test]
    fn http_status_success_matches_upstream_agent() {
        assert!(!upstream_http_success(199));
        assert!(upstream_http_success(200));
        assert!(upstream_http_success(302));
        assert!(upstream_http_success(399));
        assert!(!upstream_http_success(400));
    }

    #[test]
    fn filter_socket_addrs_by_family_keeps_requested_stack() {
        let addrs = vec![
            "203.0.113.10:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        ];

        assert_eq!(
            filter_socket_addrs_by_family(addrs.clone(), IpFamily::V4),
            vec!["203.0.113.10:443".parse().unwrap()]
        );
        assert_eq!(
            filter_socket_addrs_by_family(addrs, IpFamily::V6),
            vec!["[2001:db8::1]:443".parse().unwrap()]
        );
    }

    #[test]
    fn default_dns_servers_match_upstream_single_stack_lists() {
        assert_eq!(
            default_dns_servers(IpFamily::V4),
            vec![
                "8.8.8.8:53".to_string(),
                "8.8.4.4:53".to_string(),
                "1.1.1.1:53".to_string(),
                "1.0.0.1:53".to_string(),
            ]
        );
        assert_eq!(
            default_dns_servers(IpFamily::V6),
            vec![
                "[2001:4860:4860::8888]:53".to_string(),
                "[2001:4860:4860::8844]:53".to_string(),
                "[2606:4700:4700::1111]:53".to_string(),
                "[2606:4700:4700::1001]:53".to_string(),
            ]
        );
    }
}
