use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::{Client, Method, Url, redirect::Policy};
use serde_json::Value;

use crate::store::NotificationResource;

const REQUEST_METHOD_GET: u8 = 1;
const REQUEST_METHOD_POST: u8 = 2;
const REQUEST_TYPE_JSON: u8 = 1;
const REQUEST_TYPE_FORM: u8 = 2;

const NOTIFICATION_MAX_ATTEMPTS: u32 = 3;
const NOTIFICATION_BACKOFF_BASE_MS: u64 = 1_000;
const TEMPLATE_MAX_PASSES: usize = 8;

pub(crate) async fn send_notification_group(
    notifications: Vec<NotificationResource>,
    message: &str,
) -> Vec<(u64, Result<(), String>)> {
    let mut results = Vec::with_capacity(notifications.len());
    for notification in notifications {
        let id = notification.id;
        results.push((
            id,
            send_notification_with_retry(&notification, message)
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
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..NOTIFICATION_MAX_ATTEMPTS {
        match send_notification(notification, message).await {
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
            if let Err(e) = store.record_notification_dead_letter(
                *id,
                message,
                err,
                NOTIFICATION_MAX_ATTEMPTS,
            ) {
                tracing::warn!(notification_id = *id, %e, "failed to persist notification dead-letter");
            }
        }
    }
}

pub(crate) async fn send_notification(
    notification: &NotificationResource,
    message: &str,
) -> Result<()> {
    let url = render_template_url(&notification.url, message)?;
    let pinned_addrs = resolve_allowed_notification_addrs(&url).await?;

    let method = request_method(notification.request_method)?;
    let body = request_body(notification, message)?;
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
    request = apply_headers(request, &notification.request_header, message)?;
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

fn request_body(notification: &NotificationResource, message: &str) -> Result<Option<String>> {
    if notification.request_method == REQUEST_METHOD_GET || message.is_empty() {
        return Ok(None);
    }
    match notification.request_type {
        REQUEST_TYPE_JSON => Ok(Some(render_template_json_string(
            &notification.request_body,
            message,
        ))),
        REQUEST_TYPE_FORM => {
            let fields = json_string_map(&notification.request_body)?;
            let body = fields
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        percent_encode(&key),
                        percent_encode(&render_template_plain(&value, message))
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
    raw_headers: &str,
    message: &str,
) -> Result<reqwest::RequestBuilder> {
    if raw_headers.trim().is_empty() {
        return Ok(request);
    }
    for (key, value) in json_string_map(raw_headers)? {
        let rendered_value = render_template_plain(&value, message);
        request = request.header(key, rendered_value);
    }
    Ok(request)
}

fn render_template_url(raw: &str, message: &str) -> Result<Url> {
    let rendered = render_template(raw, message, percent_encode);
    Url::parse(&rendered).context("invalid notification url")
}

fn render_template_plain(raw: &str, message: &str) -> String {
    render_template(raw, message, ToOwned::to_owned)
}

fn render_template_json_string(raw: &str, message: &str) -> String {
    render_template(raw, message, json_escape)
}

fn render_template(raw: &str, message: &str, message_mod: impl Fn(&str) -> String) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let context = [
        ("#NEZHA#", message_mod(message)),
        ("#DATETIME#", message_mod(&now)),
    ];
    expand_placeholders(raw, &context)
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
            render_template_url("https://example.com/?text=#NEZHA#", "hello world")
                .unwrap()
                .as_str(),
            "https://example.com/?text=hello%20world"
        );
        assert_eq!(
            render_template_json_string(r##"{"text":"#NEZHA#"}"##, "hello\nworld"),
            r#"{"text":"hello\nworld"}"#
        );
        assert_eq!(
            render_template_plain("msg=#NEZHA#", "hello world"),
            "msg=hello world"
        );
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
            request_body(&notification, "hello world").unwrap(),
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
        let value = render_template_plain("req=#NEZHA#", "abc");
        assert_eq!(value, "req=abc");
        // and that json_string_map yields the same key our code would feed in
        let map = json_string_map(raw_headers).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].0, "X-Trace");
        assert_eq!(map[0].1, "req=#NEZHA#");
    }
}
