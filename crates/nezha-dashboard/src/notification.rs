use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::{Client, Method, Url, redirect::Policy};
use serde_json::Value;

use crate::store::{NotificationResource, PublicServer};

const REQUEST_METHOD_GET: u8 = 1;
const REQUEST_METHOD_POST: u8 = 2;
const REQUEST_TYPE_JSON: u8 = 1;
const REQUEST_TYPE_FORM: u8 = 2;

const NOTIFICATION_MAX_ATTEMPTS: u32 = 3;
const NOTIFICATION_BACKOFF_BASE_MS: u64 = 1_000;
const TEMPLATE_MAX_PASSES: usize = 8;

#[derive(Debug, Clone, Default)]
pub(crate) struct NotificationContext {
    server: Option<ServerTemplateContext>,
}

#[derive(Debug, Clone, Default)]
struct ServerTemplateContext {
    name: String,
    ip: String,
    ipv4: String,
    ipv6: String,
    cpu: f64,
    mem: f64,
    swap: f64,
    disk: f64,
    transfer_in: u64,
    transfer_out: u64,
    net_in_speed: u64,
    net_out_speed: u64,
    load1: f64,
    load5: f64,
    load15: f64,
}

impl NotificationContext {
    pub(crate) fn for_public_server(server: &PublicServer) -> Self {
        let geoip = server.geoip.as_ref();
        let state = server.state.as_ref();
        let host = server.host.as_ref();
        Self {
            server: Some(ServerTemplateContext {
                name: server.name.clone(),
                ip: geoip.map(|geoip| geoip.ip.join()).unwrap_or_default(),
                ipv4: geoip
                    .map(|geoip| geoip.ip.ipv4_addr.clone())
                    .unwrap_or_default(),
                ipv6: geoip
                    .map(|geoip| geoip.ip.ipv6_addr.clone())
                    .unwrap_or_default(),
                cpu: state.map(|state| state.cpu).unwrap_or_default(),
                mem: percentage(
                    state.map(|state| state.mem_used).unwrap_or_default(),
                    host.map(|host| host.mem_total).unwrap_or_default(),
                ),
                swap: percentage(
                    state.map(|state| state.swap_used).unwrap_or_default(),
                    host.map(|host| host.swap_total).unwrap_or_default(),
                ),
                disk: percentage(
                    state.map(|state| state.disk_used).unwrap_or_default(),
                    host.map(|host| host.disk_total).unwrap_or_default(),
                ),
                transfer_in: state.map(|state| state.net_in_transfer).unwrap_or_default(),
                transfer_out: state
                    .map(|state| state.net_out_transfer)
                    .unwrap_or_default(),
                net_in_speed: state.map(|state| state.net_in_speed).unwrap_or_default(),
                net_out_speed: state.map(|state| state.net_out_speed).unwrap_or_default(),
                load1: state.map(|state| state.load1).unwrap_or_default(),
                load5: state.map(|state| state.load5).unwrap_or_default(),
                load15: state.map(|state| state.load15).unwrap_or_default(),
            }),
        }
    }
}

pub(crate) async fn send_notification_group_with_context(
    notifications: Vec<NotificationResource>,
    message: &str,
    context: Option<&NotificationContext>,
) -> Vec<(u64, Result<(), String>)> {
    let mut results = Vec::with_capacity(notifications.len());
    for notification in notifications {
        let id = notification.id;
        results.push((
            id,
            send_notification_with_retry_with_context(&notification, message, context)
                .await
                .map_err(|err| err.to_string()),
        ));
    }
    results
}

pub(crate) async fn send_notification_with_retry(
    notification: &NotificationResource,
    message: &str,
) -> Result<()> {
    send_notification_with_retry_with_context(notification, message, None).await
}

async fn send_notification_with_retry_with_context(
    notification: &NotificationResource,
    message: &str,
    context: Option<&NotificationContext>,
) -> Result<()> {
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..NOTIFICATION_MAX_ATTEMPTS {
        match send_notification_with_context(notification, message, context).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = Some(err);
                if attempt + 1 < NOTIFICATION_MAX_ATTEMPTS {
                    let delay_ms = NOTIFICATION_BACKOFF_BASE_MS << attempt;
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("notification send failed")))
}

pub(crate) fn record_dead_letters(
    store: &crate::store::Store,
    message: &str,
    results: &[(u64, Result<(), String>)],
) {
    for (id, result) in results {
        if let Err(err) = result {
            if let Err(e) =
                store.record_notification_dead_letter(*id, message, err, NOTIFICATION_MAX_ATTEMPTS)
            {
                tracing::warn!(notification_id = *id, %e, "failed to persist notification dead-letter");
            }
        }
    }
}

async fn send_notification_with_context(
    notification: &NotificationResource,
    message: &str,
    context: Option<&NotificationContext>,
) -> Result<()> {
    let format_metric_units = notification.format_metric_units.unwrap_or(false);
    let url = render_template_url(&notification.url, message, context, format_metric_units)?;
    let pinned_addrs = resolve_allowed_notification_addrs(&url).await?;

    let method = request_method(notification.request_method)?;
    let body = request_body(notification, message, context)?;
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(!notification.verify_tls.unwrap_or(true));
    if let Some(host) = url.host_str() {
        if !pinned_addrs.is_empty() {
            builder = builder.resolve_to_addrs(host, &pinned_addrs);
        }
    }
    let client = builder
        .build()
        .context("failed to build notification http client")?;

    let mut request = client.request(method, url);
    request = apply_headers(request, notification, message, context)?;
    if let Some(body) = body {
        request = request.body(body);
        request = if notification.request_type == REQUEST_TYPE_FORM {
            request.header("content-type", "application/x-www-form-urlencoded")
        } else {
            request.header("content-type", "application/json")
        };
    }

    let response = request
        .send()
        .await
        .context("failed to send notification")?;
    let status = response.status();
    if !status.is_success() {
        bail!("{}@{}", status.as_u16(), status);
    }
    Ok(())
}

fn request_method(method: u8) -> Result<Method> {
    match method {
        REQUEST_METHOD_GET => Ok(Method::GET),
        REQUEST_METHOD_POST => Ok(Method::POST),
        _ => bail!("unsupported request method"),
    }
}

fn request_body(
    notification: &NotificationResource,
    message: &str,
    context: Option<&NotificationContext>,
) -> Result<Option<String>> {
    if notification.request_method == REQUEST_METHOD_GET || message.is_empty() {
        return Ok(None);
    }
    let format_metric_units = notification.format_metric_units.unwrap_or(false);
    match notification.request_type {
        REQUEST_TYPE_JSON => Ok(Some(render_template_json_string(
            &notification.request_body,
            message,
            context,
            format_metric_units,
        ))),
        REQUEST_TYPE_FORM => {
            let fields = json_string_map(&notification.request_body)?;
            let body = fields
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        percent_encode(&key),
                        percent_encode(&render_template_plain(
                            &value,
                            message,
                            context,
                            format_metric_units
                        ))
                    )
                })
                .collect::<Vec<_>>()
                .join("&");
            Ok(Some(body))
        }
        _ => bail!("unsupported request type"),
    }
}

fn apply_headers(
    mut request: reqwest::RequestBuilder,
    notification: &NotificationResource,
    message: &str,
    context: Option<&NotificationContext>,
) -> Result<reqwest::RequestBuilder> {
    let raw_headers = &notification.request_header;
    if raw_headers.trim().is_empty() {
        return Ok(request);
    }
    let format_metric_units = notification.format_metric_units.unwrap_or(false);
    for (key, value) in json_string_map(raw_headers)? {
        let rendered_value = render_template_plain(&value, message, context, format_metric_units);
        request = request.header(key, rendered_value);
    }
    Ok(request)
}

fn render_template_url(
    raw: &str,
    message: &str,
    context: Option<&NotificationContext>,
    format_metric_units: bool,
) -> Result<Url> {
    let rendered = render_template(raw, message, context, format_metric_units, percent_encode);
    Url::parse(&rendered).context("invalid notification url")
}

fn render_template_plain(
    raw: &str,
    message: &str,
    context: Option<&NotificationContext>,
    format_metric_units: bool,
) -> String {
    render_template(
        raw,
        message,
        context,
        format_metric_units,
        ToOwned::to_owned,
    )
}

fn render_template_json_string(
    raw: &str,
    message: &str,
    context: Option<&NotificationContext>,
    format_metric_units: bool,
) -> String {
    render_template(raw, message, context, format_metric_units, json_escape)
}

fn render_template(
    raw: &str,
    message: &str,
    context: Option<&NotificationContext>,
    format_metric_units: bool,
    message_mod: impl Fn(&str) -> String,
) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mut values = vec![
        ("#NEZHA#", message_mod(message)),
        ("#DATETIME#", message_mod(&now)),
    ];
    if let Some(server) = context.and_then(|context| context.server.as_ref()) {
        values.extend(server_template_values(
            server,
            format_metric_units,
            &message_mod,
        ));
    }
    expand_placeholders(raw, &values)
}

fn expand_placeholders(raw: &str, context: &[(&str, String)]) -> String {
    let mut current = raw.to_owned();
    for _ in 0..TEMPLATE_MAX_PASSES {
        let mut next = current.clone();
        for (placeholder, value) in context {
            if next.contains(placeholder) {
                next = next.replace(placeholder, value);
            }
        }
        if next == current {
            return next;
        }
        current = next;
    }
    current
}

fn json_string_map(raw: &str) -> Result<Vec<(String, String)>> {
    let value = serde_json::from_str::<Value>(raw).context("failed to parse json object")?;
    let Some(map) = value.as_object() else {
        bail!("expected json object");
    };
    Ok(map
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| value.to_string()),
            )
        })
        .collect())
}

fn server_template_values(
    server: &ServerTemplateContext,
    format_metric_units: bool,
    message_mod: &impl Fn(&str) -> String,
) -> Vec<(&'static str, String)> {
    let percent = |value: f64| {
        if format_metric_units {
            format!("{value:.2}%")
        } else {
            format!("{value:.2}")
        }
    };
    let bytes = |value: u64| {
        if format_metric_units {
            format_bytes(value)
        } else {
            value.to_string()
        }
    };
    let speed = |value: u64| {
        if format_metric_units {
            format!("{}/s", format_bytes(value))
        } else {
            value.to_string()
        }
    };
    [
        ("#SERVER.NAME#", server.name.clone()),
        ("#SERVER.IP#", server.ip.clone()),
        ("#SERVER.IPV4#", server.ipv4.clone()),
        ("#SERVER.IPV6#", server.ipv6.clone()),
        ("#SERVER.CPU#", percent(server.cpu)),
        ("#SERVER.MEM#", percent(server.mem)),
        ("#SERVER.SWAP#", percent(server.swap)),
        ("#SERVER.DISK#", percent(server.disk)),
        ("#SERVER.TRANSFERIN#", bytes(server.transfer_in)),
        ("#SERVER.TRANSFEROUT#", bytes(server.transfer_out)),
        ("#SERVER.NETINSPEED#", speed(server.net_in_speed)),
        ("#SERVER.NETOUTSPEED#", speed(server.net_out_speed)),
        ("#SERVER.LOAD1#", format!("{:.2}", server.load1)),
        ("#SERVER.LOAD5#", format!("{:.2}", server.load5)),
        ("#SERVER.LOAD15#", format!("{:.2}", server.load15)),
    ]
    .into_iter()
    .map(|(placeholder, value)| (placeholder, message_mod(&value)))
    .collect()
}

fn percentage(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        used as f64 * 100.0 / total as f64
    }
}

fn format_bytes(value: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} {}", UNITS[unit])
    } else {
        format!("{size:.2} {}", UNITS[unit])
    }
}

pub(crate) async fn resolve_allowed_notification_addrs(url: &Url) -> Result<Vec<SocketAddr>> {
    if !matches!(url.scheme(), "http" | "https") {
        bail!("HTTP URL target is not allowed");
    }
    let Some(host) = url.host_str() else {
        bail!("HTTP URL target is not allowed");
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        ensure_allowed_notification_ip(ip)?;
        return Ok(Vec::new());
    }

    let port = url.port_or_known_default().unwrap_or(80);
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .context("failed to resolve notification target")?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        bail!("HTTP URL target is not allowed");
    }
    for address in &addresses {
        ensure_allowed_notification_ip(address.ip())?;
    }
    Ok(addresses)
}

pub(crate) fn ensure_allowed_notification_ip(ip: IpAddr) -> Result<()> {
    if notification_ip_allowed(ip) {
        Ok(())
    } else {
        bail!("HTTP URL target is not allowed")
    }
}

fn notification_ip_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ipv4_allowed(ip),
        IpAddr::V6(ip) => ipv6_allowed(ip),
    }
}

fn ipv4_allowed(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || octets[0] == 0
        || octets[0] >= 224
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113))
}

fn ipv6_allowed(ip: Ipv6Addr) -> bool {
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unicast_link_local()
        || ip.is_unique_local()
        || ip.to_ipv4_mapped().is_some()
        || in_ipv6_prefix(ip, 0x0064, 0xff9b, 96)
        || in_ipv6_prefix(ip, 0x0100, 0x0000, 64)
        || in_ipv6_prefix(ip, 0x2001, 0x0000, 23)
        || in_ipv6_prefix(ip, 0x2001, 0x0db8, 32))
}

fn in_ipv6_prefix(ip: Ipv6Addr, first: u16, second: u16, bits: u8) -> bool {
    let segments = ip.segments();
    match bits {
        23 => segments[0] == first && (segments[1] & 0xfffe) == second,
        32 => segments[0] == first && segments[1] == second,
        64 => segments[0] == first && segments[1] == second && segments[2] == 0 && segments[3] == 0,
        96 => {
            segments[0] == first
                && segments[1] == second
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0
        }
        _ => false,
    }
}

fn percent_encode(raw: &str) -> String {
    raw.bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

fn json_escape(raw: &str) -> String {
    let encoded = serde_json::to_string(raw).unwrap_or_default();
    encoded
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(&encoded)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_message_for_url_json_and_form_contexts() {
        assert_eq!(
            render_template_url(
                "https://example.com/?text=#NEZHA#",
                "hello world",
                None,
                false
            )
            .unwrap()
            .as_str(),
            "https://example.com/?text=hello%20world"
        );
        assert_eq!(
            render_template_json_string(r##"{"text":"#NEZHA#"}"##, "hello\nworld", None, false),
            r#"{"text":"hello\nworld"}"#
        );
        assert_eq!(
            render_template_plain("msg=#NEZHA#", "hello world", None, false),
            "msg=hello world"
        );
    }

    #[test]
    fn server_placeholders_are_rendered_and_metric_units_can_format() {
        let context = NotificationContext {
            server: Some(ServerTemplateContext {
                name: "edge-1".into(),
                ip: "198.51.100.10/2001:db8::10".into(),
                ipv4: "198.51.100.10".into(),
                ipv6: "2001:db8::10".into(),
                cpu: 12.345,
                mem: 50.0,
                swap: 0.0,
                disk: 75.0,
                transfer_in: 1024,
                transfer_out: 1536,
                net_in_speed: 2048,
                net_out_speed: 4096,
                load1: 0.5,
                load5: 0.25,
                load15: 0.125,
            }),
        };
        let rendered = render_template_plain(
            "#SERVER.NAME# #SERVER.CPU# #SERVER.MEM# #SERVER.TRANSFERIN# #SERVER.NETOUTSPEED# #SERVER.LOAD15#",
            "",
            Some(&context),
            true,
        );
        assert_eq!(rendered, "edge-1 12.35% 50.00% 1.00 KB 4.00 KB/s 0.12");
        assert!(!rendered.contains("#SERVER."));
    }

    #[test]
    fn rejects_internal_notification_targets() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "203.0.113.10",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(
                ensure_allowed_notification_ip(ip.parse().unwrap()).is_err(),
                "{ip}"
            );
        }
        assert!(ensure_allowed_notification_ip("1.1.1.1".parse().unwrap()).is_ok());
        assert!(ensure_allowed_notification_ip("2606:4700:4700::1111".parse().unwrap()).is_ok());
    }

    #[test]
    fn form_body_is_urlencoded_from_json_object() {
        let notification = NotificationResource {
            id: 1,
            user_id: 1,
            name: "test".into(),
            url: "https://example.com".into(),
            request_method: REQUEST_METHOD_POST,
            request_type: REQUEST_TYPE_FORM,
            request_header: String::new(),
            request_body: r##"{"text":"#NEZHA#"}"##.into(),
            verify_tls: Some(true),
            format_metric_units: Some(false),
            skip_check: None,
            created_at: 0,
            updated_at: 0,
        };

        assert_eq!(
            request_body(&notification, "hello world", None).unwrap(),
            Some("text=hello%20world".to_string())
        );
    }

    #[test]
    fn nested_placeholder_expansion_resolves_recursively() {
        let context = [
            ("#NEZHA#", "msg=#DATETIME#".to_string()),
            ("#DATETIME#", "2026-05-25T00:00:00Z".to_string()),
        ];
        assert_eq!(
            expand_placeholders("hello #NEZHA#", &context),
            "hello msg=2026-05-25T00:00:00Z"
        );
    }

    #[test]
    fn placeholder_expansion_terminates_on_self_reference() {
        let context = [("#NEZHA#", "#NEZHA#".to_string())];
        // Must not loop forever; result still contains placeholder after max passes.
        let result = expand_placeholders("v=#NEZHA#", &context);
        assert!(result.contains("#NEZHA#"));
    }

    #[test]
    fn header_values_are_template_rendered() {
        let raw_headers = r##"{"X-Trace":"req=#NEZHA#"}"##;
        // apply_headers consumes a RequestBuilder; verify rendering by using the same
        // template path the real call site walks.
        let value = render_template_plain("req=#NEZHA#", "abc", None, false);
        assert_eq!(value, "req=abc");
        // and that json_string_map yields the same key our code would feed in
        let map = json_string_map(raw_headers).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].0, "X-Trace");
        assert_eq!(map[0].1, "req=#NEZHA#");
    }
}
