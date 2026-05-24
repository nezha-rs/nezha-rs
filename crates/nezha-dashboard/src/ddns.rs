use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use reqwest::{Client, Method};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{net::UdpSocket, time};

use crate::store::{DdnsResource, PublicServer};

const METHOD_GET: u8 = 1;
const METHOD_POST: u8 = 2;
const METHOD_PATCH: u8 = 3;
const METHOD_DELETE: u8 = 4;
const METHOD_PUT: u8 = 5;
const REQUEST_TYPE_JSON: u8 = 1;
const REQUEST_TYPE_FORM: u8 = 2;
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_DNS_SERVERS: &[&str] = &[
    "8.8.8.8:53",
    "8.8.4.4:53",
    "1.1.1.1:53",
    "1.0.0.1:53",
    "[2001:4860:4860::8888]:53",
    "[2001:4860:4860::8844]:53",
    "[2606:4700:4700::1111]:53",
    "[2606:4700:4700::1001]:53",
];

#[derive(Debug, Clone)]
struct DdnsBody {
    enable_ipv4: bool,
    enable_ipv6: bool,
    max_retries: u64,
    access_id: String,
    access_secret: String,
    webhook_url: String,
    webhook_method: u8,
    webhook_request_type: u8,
    webhook_request_body: String,
    webhook_headers: String,
}

impl DdnsBody {
    fn from_value(value: &Value) -> Self {
        Self {
            enable_ipv4: value
                .get("enable_ipv4")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            enable_ipv6: value
                .get("enable_ipv6")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            max_retries: value
                .get("max_retries")
                .and_then(Value::as_u64)
                .unwrap_or(3),
            access_id: string_value(value, "access_id"),
            access_secret: string_value(value, "access_secret"),
            webhook_url: string_value(value, "webhook_url"),
            webhook_method: value
                .get("webhook_method")
                .and_then(Value::as_u64)
                .unwrap_or(METHOD_GET as u64) as u8,
            webhook_request_type: value
                .get("webhook_request_type")
                .and_then(Value::as_u64)
                .unwrap_or(REQUEST_TYPE_JSON as u64) as u8,
            webhook_request_body: string_value(value, "webhook_request_body"),
            webhook_headers: string_value(value, "webhook_headers"),
        }
    }
}

pub(crate) async fn update_server_ddns(
    server: PublicServer,
    profiles: Vec<DdnsResource>,
    ipv4: String,
    ipv6: String,
    dns_servers: String,
) -> Vec<(u64, Result<(), String>)> {
    if !server.enable_ddns || (ipv4.is_empty() && ipv6.is_empty()) {
        return Vec::new();
    }
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build();
    let client = match client {
        Ok(client) => client,
        Err(err) => {
            return profiles
                .into_iter()
                .map(|profile| (profile.id, Err(err.to_string())))
                .collect();
        }
    };

    let mut results = Vec::new();
    for profile in profiles {
        let domains = server
            .override_ddns_domains
            .get(&profile.id)
            .cloned()
            .filter(|domains| !domains.is_empty())
            .unwrap_or_else(|| profile.domains.clone());
        let result = update_profile(&client, &profile, &domains, &ipv4, &ipv6, &dns_servers)
            .await
            .map_err(|err| err.to_string());
        results.push((profile.id, result));
    }
    results
}

async fn update_profile(
    client: &Client,
    profile: &DdnsResource,
    domains: &[String],
    ipv4: &str,
    ipv6: &str,
    dns_servers: &str,
) -> Result<()> {
    let body = DdnsBody::from_value(&profile.body);
    let attempts = body.max_retries.clamp(1, 10);
    for domain in domains {
        for attempt in 1..=attempts {
            let result =
                update_domain(client, profile, &body, domain, ipv4, ipv6, dns_servers).await;
            if result.is_ok() || attempt == attempts {
                result?;
                break;
            }
        }
    }
    Ok(())
}

async fn update_domain(
    client: &Client,
    profile: &DdnsResource,
    body: &DdnsBody,
    domain: &str,
    ipv4: &str,
    ipv6: &str,
    dns_servers: &str,
) -> Result<()> {
    match profile.provider.as_str() {
        "dummy" => Ok(()),
        "webhook" => {
            if body.enable_ipv4 && !ipv4.is_empty() {
                send_webhook(client, body, domain, "A", ipv4).await?;
            }
            if body.enable_ipv6 && !ipv6.is_empty() {
                send_webhook(client, body, domain, "AAAA", ipv6).await?;
            }
            Ok(())
        }
        "cloudflare" => {
            if body.enable_ipv4 && !ipv4.is_empty() {
                update_cloudflare(client, body, domain, "A", ipv4, dns_servers).await?;
            }
            if body.enable_ipv6 && !ipv6.is_empty() {
                update_cloudflare(client, body, domain, "AAAA", ipv6, dns_servers).await?;
            }
            Ok(())
        }
        "he" => {
            if body.enable_ipv4 && !ipv4.is_empty() {
                update_he(client, body, domain, ipv4).await?;
            }
            if body.enable_ipv6 && !ipv6.is_empty() {
                update_he(client, body, domain, ipv6).await?;
            }
            Ok(())
        }
        "tencentcloud" => {
            if body.enable_ipv4 && !ipv4.is_empty() {
                update_tencentcloud(client, body, domain, "A", ipv4, dns_servers).await?;
            }
            if body.enable_ipv6 && !ipv6.is_empty() {
                update_tencentcloud(client, body, domain, "AAAA", ipv6, dns_servers).await?;
            }
            Ok(())
        }
        provider => bail!("cannot find DDNS provider {provider}"),
    }
}

async fn send_webhook(
    client: &Client,
    body: &DdnsBody,
    domain: &str,
    record_type: &str,
    ip: &str,
) -> Result<()> {
    let url = format_webhook_string(
        &body.webhook_url.replace('#', "%23"),
        body,
        domain,
        record_type,
        ip,
    );
    let method = webhook_method(body.webhook_method)?;
    let mut request = client.request(method, url);
    for (key, value) in webhook_headers(body, domain, record_type, ip)? {
        request = request.header(key, value);
    }
    if !matches!(body.webhook_method, METHOD_GET | METHOD_DELETE) {
        let request_body = webhook_body(body, domain, record_type, ip)?;
        request = request.body(request_body);
        request = if body.webhook_request_type == REQUEST_TYPE_FORM {
            request.header("content-type", "application/x-www-form-urlencoded")
        } else {
            request.header("content-type", "application/json")
        };
    }
    let status = request
        .send()
        .await
        .context("failed to send webhook")?
        .status();
    anyhow::ensure!(status.is_success(), "webhook returned {status}");
    Ok(())
}

async fn update_cloudflare(
    client: &Client,
    body: &DdnsBody,
    domain: &str,
    record_type: &str,
    ip: &str,
    dns_servers: &str,
) -> Result<()> {
    let (_prefix, zone) = split_domain_soa(domain, dns_servers).await?;
    let zone_id = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/zones?name={zone}"
        ))
        .bearer_auth(&body.access_secret)
        .send()
        .await
        .context("failed to query cloudflare zone")?
        .text()
        .await
        .context("failed to read cloudflare zone response")
        .and_then(|raw| cloudflare_first_id(&raw).context("cloudflare zone not found"))?;
    let records_url = format!(
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type={record_type}&name={domain}"
    );
    let record_id = client
        .get(&records_url)
        .bearer_auth(&body.access_secret)
        .send()
        .await
        .context("failed to query cloudflare dns record")?
        .text()
        .await
        .context("failed to read cloudflare dns record response")
        .and_then(|raw| cloudflare_first_id(&raw).context("cloudflare dns record not found"))?;
    let payload = serde_json::json!({
        "type": record_type,
        "name": domain,
        "content": ip,
        "ttl": 60
    });
    let status = client
        .put(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
        ))
        .bearer_auth(&body.access_secret)
        .header("content-type", "application/json")
        .body(payload.to_string())
        .send()
        .await
        .context("failed to update cloudflare dns record")?
        .status();
    anyhow::ensure!(status.is_success(), "cloudflare returned {status}");
    Ok(())
}

async fn update_he(client: &Client, body: &DdnsBody, domain: &str, ip: &str) -> Result<()> {
    let url = format!(
        "https://dyn.dns.he.net/nic/update?hostname={}&password={}&myip={}",
        percent_encode(domain),
        percent_encode(&body.access_secret),
        percent_encode(ip)
    );
    let status = client
        .get(url)
        .send()
        .await
        .context("failed to update he dns record")?
        .status();
    anyhow::ensure!(status.is_success(), "he returned {status}");
    Ok(())
}

async fn update_tencentcloud(
    client: &Client,
    body: &DdnsBody,
    fqdn: &str,
    record_type: &str,
    ip: &str,
    dns_servers: &str,
) -> Result<()> {
    anyhow::ensure!(
        !body.access_id.is_empty() && !body.access_secret.is_empty(),
        "tencentcloud access_id/access_secret are required"
    );
    let (sub_domain, domain) = split_domain_soa(fqdn, dns_servers).await?;
    let sub_domain = if sub_domain.is_empty() {
        "@".to_string()
    } else {
        sub_domain
    };
    let describe_payload = serde_json::json!({
        "Domain": domain,
        "Subdomain": sub_domain,
        "RecordType": record_type
    })
    .to_string();
    let describe = tencentcloud_request(
        client,
        body,
        "DescribeRecordList",
        describe_payload,
        unix_timestamp(),
    )
    .await?;
    let record_id = describe
        .get("Response")
        .and_then(|response| response.get("RecordList"))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("RecordId"))
        .and_then(Value::as_u64)
        .context("tencentcloud dns record not found")?;
    let modify_payload = serde_json::json!({
        "Domain": domain,
        "SubDomain": sub_domain,
        "RecordType": record_type,
        "RecordLine": "默认",
        "Value": ip,
        "RecordId": record_id
    })
    .to_string();
    let _ = tencentcloud_request(
        client,
        body,
        "ModifyRecord",
        modify_payload,
        unix_timestamp(),
    )
    .await?;
    Ok(())
}

async fn tencentcloud_request(
    client: &Client,
    body: &DdnsBody,
    action: &str,
    payload: String,
    timestamp: i64,
) -> Result<Value> {
    let authorization = tencentcloud_authorization(
        &body.access_id,
        &body.access_secret,
        action,
        &payload,
        timestamp,
    )?;
    let status_body = client
        .post("https://dnspod.tencentcloudapi.com/")
        .header("authorization", authorization)
        .header("content-type", "application/json; charset=utf-8")
        .header("host", "dnspod.tencentcloudapi.com")
        .header("x-tc-action", action)
        .header("x-tc-timestamp", timestamp.to_string())
        .header("x-tc-version", "2021-03-23")
        .header("x-tc-language", "en-US")
        .body(payload)
        .send()
        .await
        .with_context(|| format!("failed to call tencentcloud {action}"))?;
    let status = status_body.status();
    let raw = status_body
        .text()
        .await
        .context("failed to read tencentcloud response")?;
    anyhow::ensure!(status.is_success(), "tencentcloud returned {status}: {raw}");
    let value =
        serde_json::from_str::<Value>(&raw).context("failed to decode tencentcloud response")?;
    if let Some(error) = value
        .get("Response")
        .and_then(|response| response.get("Error"))
    {
        bail!("tencentcloud returned error: {error}");
    }
    Ok(value)
}

fn tencentcloud_authorization(
    secret_id: &str,
    secret_key: &str,
    action: &str,
    payload: &str,
    timestamp: i64,
) -> Result<String> {
    let date = tencentcloud_date(timestamp);
    let canonical_request = format!(
        "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:dnspod.tencentcloudapi.com\nx-tc-action:{}\n\ncontent-type;host;x-tc-action\n{}",
        action.to_ascii_lowercase(),
        sha256_hex(payload.as_bytes())
    );
    let credential_scope = format!("{date}/dnspod/tc3_request");
    let string_to_sign = format!(
        "TC3-HMAC-SHA256\n{timestamp}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let secret_date = hmac_sha256(format!("TC3{secret_key}").as_bytes(), date.as_bytes())?;
    let secret_service = hmac_sha256(&secret_date, b"dnspod")?;
    let secret_signing = hmac_sha256(&secret_service, b"tc3_request")?;
    let signature = bytes_hex(&hmac_sha256(&secret_signing, string_to_sign.as_bytes())?);
    Ok(format!(
        "TC3-HMAC-SHA256 Credential={secret_id}/{credential_scope}, SignedHeaders=content-type;host;x-tc-action, Signature={signature}"
    ))
}

fn webhook_method(method: u8) -> Result<Method> {
    match method {
        METHOD_GET => Ok(Method::GET),
        METHOD_POST => Ok(Method::POST),
        METHOD_PATCH => Ok(Method::PATCH),
        METHOD_DELETE => Ok(Method::DELETE),
        METHOD_PUT => Ok(Method::PUT),
        _ => bail!("webhook method not supported"),
    }
}

fn webhook_headers(
    body: &DdnsBody,
    domain: &str,
    record_type: &str,
    ip: &str,
) -> Result<Vec<(String, String)>> {
    if body.webhook_headers.trim().is_empty() {
        return Ok(Vec::new());
    }
    json_string_map(&body.webhook_headers).map(|items| {
        items
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    format_webhook_string(&value, body, domain, record_type, ip),
                )
            })
            .collect()
    })
}

fn webhook_body(body: &DdnsBody, domain: &str, record_type: &str, ip: &str) -> Result<String> {
    match body.webhook_request_type {
        REQUEST_TYPE_JSON => Ok(format_webhook_string(
            &body.webhook_request_body,
            body,
            domain,
            record_type,
            ip,
        )),
        REQUEST_TYPE_FORM => {
            let fields = json_string_map(&body.webhook_request_body)?;
            Ok(fields
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        percent_encode(&key),
                        percent_encode(&format_webhook_string(
                            &value,
                            body,
                            domain,
                            record_type,
                            ip
                        ))
                    )
                })
                .collect::<Vec<_>>()
                .join("&"))
        }
        _ => bail!("request type not supported"),
    }
}

fn format_webhook_string(
    raw: &str,
    body: &DdnsBody,
    domain: &str,
    record_type: &str,
    ip: &str,
) -> String {
    raw.trim()
        .replace("#ip#", ip)
        .replace("#domain#", domain)
        .replace("#type#", record_to_ip_type(record_type))
        .replace("#record#", record_type)
        .replace("#access_id#", &body.access_id)
        .replace("#access_secret#", &body.access_secret)
        .replace('\r', "")
}

fn record_to_ip_type(record_type: &str) -> &'static str {
    match record_type {
        "A" => "ipv4",
        "AAAA" => "ipv6",
        _ => "",
    }
}

fn cloudflare_first_id(raw: &str) -> Option<String> {
    serde_json::from_str::<Value>(raw)
        .ok()?
        .get("result")?
        .as_array()?
        .first()?
        .get("id")?
        .as_str()
        .map(ToOwned::to_owned)
}

async fn split_domain_soa(fqdn: &str, dns_servers: &str) -> Result<(String, String)> {
    let labels = domain_labels(fqdn)?;
    let servers = dns_server_list(dns_servers);
    for zone in soa_candidates(&labels) {
        for server in &servers {
            if soa_exists(&zone, server).await.unwrap_or(false) {
                return Ok((relative_name(&labels.join("."), &zone), zone));
            }
        }
    }
    bail!(
        "SOA record not found for domain: {}",
        fqdn.trim_end_matches('.')
    )
}

fn domain_labels(fqdn: &str) -> Result<Vec<&str>> {
    let labels = fqdn
        .trim()
        .trim_end_matches('.')
        .split('.')
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    if labels.len() < 2 {
        bail!("invalid domain");
    }
    Ok(labels)
}

fn soa_candidates(labels: &[&str]) -> Vec<String> {
    (0..labels.len())
        .map(|index| labels[index..].join("."))
        .collect()
}

fn relative_name(fqdn: &str, zone: &str) -> String {
    let fqdn = fqdn.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if fqdn.eq_ignore_ascii_case(zone) {
        return String::new();
    }
    fqdn.strip_suffix(&format!(".{zone}"))
        .unwrap_or(fqdn)
        .to_string()
}

fn dns_server_list(raw: &str) -> Vec<String> {
    let servers = raw
        .split(',')
        .map(str::trim)
        .filter(|server| !server.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if servers.is_empty() {
        DEFAULT_DNS_SERVERS
            .iter()
            .map(|server| (*server).to_string())
            .collect()
    } else {
        servers
    }
}

async fn soa_exists(domain: &str, server: &str) -> Result<bool> {
    let addr: SocketAddr = server
        .parse()
        .with_context(|| format!("invalid DNS server {server}"))?;
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    let query = build_soa_query(domain)?;
    socket.send_to(&query, addr).await?;
    let mut response = [0_u8; 1500];
    let (len, _) = time::timeout(DNS_TIMEOUT, socket.recv_from(&mut response)).await??;
    Ok(response_has_soa(&response[..len])?)
}

fn build_soa_query(domain: &str) -> Result<Vec<u8>> {
    let id = (unix_timestamp() as u16).wrapping_mul(31);
    let mut out = Vec::with_capacity(domain.len() + 18);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100_u16.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    encode_dns_name(domain, &mut out)?;
    out.extend_from_slice(&6_u16.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    Ok(out)
}

fn encode_dns_name(domain: &str, out: &mut Vec<u8>) -> Result<()> {
    for label in domain.trim_end_matches('.').split('.') {
        anyhow::ensure!(
            !label.is_empty() && label.len() <= 63,
            "invalid domain label"
        );
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn response_has_soa(buf: &[u8]) -> Result<bool> {
    anyhow::ensure!(buf.len() >= 12, "short DNS response");
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(buf, pos)?;
        anyhow::ensure!(pos + 4 <= buf.len(), "short DNS question");
        pos += 4;
    }
    for _ in 0..ancount {
        pos = skip_dns_name(buf, pos)?;
        anyhow::ensure!(pos + 10 <= buf.len(), "short DNS answer");
        let record_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let data_len = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        anyhow::ensure!(pos + data_len <= buf.len(), "short DNS rdata");
        if record_type == 6 {
            return Ok(true);
        }
        pos += data_len;
    }
    Ok(false)
}

fn skip_dns_name(buf: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        anyhow::ensure!(pos < buf.len(), "short DNS name");
        let len = buf[pos];
        if len & 0xc0 == 0xc0 {
            anyhow::ensure!(pos + 1 < buf.len(), "short DNS pointer");
            return Ok(pos + 2);
        }
        pos += 1;
        if len == 0 {
            return Ok(pos);
        }
        anyhow::ensure!(len & 0xc0 == 0, "invalid DNS label");
        pos += len as usize;
    }
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn tencentcloud_date(timestamp: i64) -> String {
    let days = timestamp.div_euclid(86_400);
    civil_from_days(days)
}

fn civil_from_days(days_since_unix_epoch: i64) -> String {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}-{day:02}")
}

fn sha256_hex(data: &[u8]) -> String {
    bytes_hex(&Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).context("invalid hmac key")?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn bytes_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
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

fn string_value(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn webhook_body_fixture() -> DdnsBody {
        DdnsBody {
            enable_ipv4: true,
            enable_ipv6: true,
            max_retries: 3,
            access_id: "id".into(),
            access_secret: "secret".into(),
            webhook_url: "https://example.com".into(),
            webhook_method: METHOD_POST,
            webhook_request_type: REQUEST_TYPE_FORM,
            webhook_request_body: r##"{"value":"#ip#","#domain":"#domain#","#kind":"#type#","#record":"#record#","#secret":"#access_secret#"}"##.into(),
            webhook_headers: r##"{"X-Token":"#access_id#:#access_secret#"}"##.into(),
        }
    }

    #[test]
    fn webhook_templates_match_upstream_placeholders() {
        let body = webhook_body_fixture();

        let rendered = webhook_body(&body, "node.example.com", "A", "203.0.113.1").unwrap();
        assert!(rendered.contains("value=203.0.113.1"));
        assert!(rendered.contains("%23domain=node.example.com"));
        assert!(rendered.contains("%23kind=ipv4"));
        assert!(rendered.contains("%23record=A"));
        assert!(rendered.contains("%23secret=secret"));
        assert_eq!(
            webhook_headers(&body, "node.example.com", "AAAA", "2001:db8::1").unwrap(),
            vec![("X-Token".into(), "id:secret".into())]
        );
    }

    #[test]
    fn cloudflare_helpers_extract_ids() {
        assert_eq!(
            cloudflare_first_id(r#"{"result":[{"id":"abc"}]}"#),
            Some("abc".into())
        );
    }

    #[test]
    fn tencentcloud_helpers_shape_domain_and_signature() {
        assert_eq!(
            soa_candidates(&["node", "example", "co", "uk"]),
            vec!["node.example.co.uk", "example.co.uk", "co.uk", "uk"]
        );
        assert_eq!(relative_name("node.example.co.uk", "example.co.uk"), "node");
        assert_eq!(relative_name("example.co.uk", "example.co.uk"), "");
        assert_eq!(
            dns_server_list("1.1.1.1:53, 8.8.8.8:53"),
            vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()]
        );
        assert_eq!(tencentcloud_date(1_700_000_000), "2023-11-14");
        let auth = tencentcloud_authorization(
            "id",
            "secret",
            "DescribeRecordList",
            r#"{"Domain":"example.com"}"#,
            1_700_000_000,
        )
        .unwrap();
        assert!(auth.starts_with("TC3-HMAC-SHA256 Credential=id/2023-11-14/dnspod/tc3_request"));
        assert!(auth.contains("SignedHeaders=content-type;host;x-tc-action"));
    }
}
