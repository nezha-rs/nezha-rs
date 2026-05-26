use std::{collections::HashMap, fs, net::IpAddr, path::Path};

use anyhow::{Context, Result};
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::{DateTime, Utc};
#[cfg(test)]
use chrono::{Duration as ChronoDuration, Months, TimeZone};
use nezha_core::{
    CRON_COVER_ALERT_TRIGGER, CRON_COVER_ALL, CRON_COVER_IGNORE_ALL, GeoIp as CoreGeoIp,
    Host as CoreHost, HostState as CoreHostState, SERVICE_COVER_ALL, SERVICE_COVER_IGNORE_ALL,
};
use nezha_proto::{GeoIp, Host, State, TaskResult};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use uuid::Uuid;

pub(crate) fn serialize_unix_as_rfc3339<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    if *v == 0 {
        return s.serialize_str("0001-01-01T00:00:00Z");
    }
    match DateTime::<Utc>::from_timestamp(*v as i64, 0) {
        Some(dt) => s.serialize_str(&dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        None => s.serialize_str("0001-01-01T00:00:00Z"),
    }
}

pub(crate) fn serialize_unix_opt_as_rfc3339<S: Serializer>(
    v: &Option<u64>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match v {
        Some(t) => serialize_unix_as_rfc3339(t, s),
        None => s.serialize_str("0001-01-01T00:00:00Z"),
    }
}

#[derive(Debug, Clone)]
pub struct StoredServer {
    pub id: u64,
    pub user_id: u64,
    pub host: Option<Host>,
    pub state: Option<State>,
    pub geoip: Option<GeoIp>,
    pub last_active_unix: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiUser {
    pub id: u64,
    pub username: String,
    pub role: u8,
    pub agent_secret: String,
    pub reject_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResource {
    pub id: u64,
    pub username: String,
    pub role: u8,
    pub agent_secret: String,
    pub reject_password: bool,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub created_at: u64,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileResource {
    pub id: u64,
    pub username: String,
    pub role: u8,
    pub agent_secret: String,
    pub reject_password: bool,
    pub login_ip: String,
    pub oauth2_bind: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PublicServer {
    pub id: u64,
    pub user_id: u64,
    pub uuid: String,
    pub name: String,
    pub note: String,
    pub public_note: String,
    pub display_index: i32,
    pub hide_for_guest: bool,
    pub enable_ddns: bool,
    pub ddns_profiles: Vec<u64>,
    pub override_ddns_domains: HashMap<u64, Vec<String>>,
    pub host: Option<CoreHost>,
    pub state: Option<CoreHostState>,
    pub geoip: Option<CoreGeoIp>,
    pub last_active: u64,
    pub prev_transfer_in_snapshot: u64,
    pub prev_transfer_out_snapshot: u64,
}

impl Serialize for PublicServer {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("PublicServer", 16)?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("user_id", &self.user_id)?;
        s.serialize_field("uuid", &self.uuid)?;
        s.serialize_field("name", &self.name)?;
        s.serialize_field("note", &self.note)?;
        s.serialize_field("public_note", &self.public_note)?;
        s.serialize_field("display_index", &self.display_index)?;
        s.serialize_field("hide_for_guest", &self.hide_for_guest)?;
        s.serialize_field("enable_ddns", &self.enable_ddns)?;
        s.serialize_field("ddns_profiles", &self.ddns_profiles)?;
        s.serialize_field("override_ddns_domains", &self.override_ddns_domains)?;
        s.serialize_field("host", &self.host)?;
        s.serialize_field("state", &self.state)?;
        s.serialize_field("geoip", &self.geoip)?;
        let country_code = self
            .geoip
            .as_ref()
            .map(|g| g.country_code.as_str())
            .unwrap_or("");
        s.serialize_field("country_code", country_code)?;
        s.serialize_field("last_active", &UnixRfc3339Ser(&self.last_active))?;
        s.end()
    }
}

struct UnixRfc3339Ser<'a>(&'a u64);

impl<'a> Serialize for UnixRfc3339Ser<'a> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serialize_unix_as_rfc3339(self.0, s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedResource {
    pub id: u64,
    pub name: String,
    pub user_id: u64,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub created_at: u64,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationGroupResource {
    pub group: NamedResource,
    pub notifications: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerGroupResource {
    pub group: NamedResource,
    pub servers: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationResource {
    pub id: u64,
    pub user_id: u64,
    pub name: String,
    pub url: String,
    pub request_method: u8,
    pub request_type: u8,
    pub request_header: String,
    pub request_body: String,
    pub verify_tls: Option<bool>,
    pub format_metric_units: Option<bool>,
    pub skip_check: Option<bool>,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub created_at: u64,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronResource {
    pub id: u64,
    pub user_id: u64,
    pub name: String,
    pub task_type: u8,
    pub scheduler: String,
    pub command: String,
    pub servers: Vec<u64>,
    pub push_successful: bool,
    pub notification_group_id: u64,
    #[serde(serialize_with = "serialize_unix_opt_as_rfc3339")]
    pub last_executed_at: Option<u64>,
    pub last_result: bool,
    pub cover: u8,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub created_at: u64,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatResource {
    pub id: u64,
    pub user_id: u64,
    pub enabled: bool,
    pub name: String,
    pub server_id: u64,
    pub host: String,
    pub domain: String,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub created_at: u64,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResource {
    pub id: u64,
    pub user_id: u64,
    pub name: String,
    pub r#type: u8,
    pub target: String,
    pub duration: u64,
    pub display_index: i32,
    pub notify: bool,
    pub notification_group_id: u64,
    pub cover: u8,
    pub enable_trigger_task: bool,
    pub enable_show_in_service: bool,
    pub fail_trigger_tasks: Vec<u64>,
    pub recover_trigger_tasks: Vec<u64>,
    pub min_latency: f64,
    pub max_latency: f64,
    pub latency_notify: bool,
    pub skip_servers: serde_json::Map<String, Value>,
    pub trigger_tasks: serde_json::Map<String, Value>,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub created_at: u64,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub updated_at: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DdnsResource {
    pub id: u64,
    pub user_id: u64,
    pub name: String,
    pub provider: String,
    pub domains: Vec<String>,
    pub body: Value,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Serialize for DdnsResource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let extra_len = self.body.as_object().map(|m| m.len()).unwrap_or(0);
        let mut m = serializer.serialize_map(Some(7 + extra_len))?;
        m.serialize_entry("id", &self.id)?;
        m.serialize_entry("user_id", &self.user_id)?;
        m.serialize_entry("name", &self.name)?;
        m.serialize_entry("provider", &self.provider)?;
        m.serialize_entry("domains", &self.domains)?;
        if let Some(obj) = self.body.as_object() {
            const RESERVED: &[&str] = &[
                "id",
                "user_id",
                "name",
                "provider",
                "domains",
                "created_at",
                "updated_at",
            ];
            for (k, v) in obj {
                if RESERVED.contains(&k.as_str()) {
                    continue;
                }
                m.serialize_entry(k, v)?;
            }
        }
        m.serialize_entry("created_at", &UnixRfc3339Ser(&self.created_at))?;
        m.serialize_entry("updated_at", &UnixRfc3339Ser(&self.updated_at))?;
        m.end()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRuleResource {
    pub id: u64,
    pub user_id: u64,
    pub name: String,
    pub enable: Option<bool>,
    pub trigger_mode: u8,
    pub notification_group_id: u64,
    pub rules: Vec<Value>,
    pub fail_trigger_tasks: Vec<u64>,
    pub recover_trigger_tasks: Vec<u64>,
    #[serde(default)]
    pub muted_until: u64,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub created_at: u64,
    #[serde(serialize_with = "serialize_unix_as_rfc3339")]
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafResource {
    pub ip: String,
    pub block_identifier: i64,
    pub block_reason: u8,
    pub block_timestamp: u64,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct PendingTask {
    pub row_id: i64,
    pub task_id: u64,
    pub task_type: u64,
    pub data: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationDeadLetterEntry {
    pub id: u64,
    pub notification_id: u64,
    pub message: String,
    pub error: String,
    pub attempts: u32,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerMetricPoint {
    pub ts: i64,
    pub value: f64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferResource {
    pub id: u64,
    pub server_id: u64,
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHistoryDataPoint {
    pub ts: i64,
    pub delay: f64,
    pub status: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHistorySummary {
    pub avg_delay: f64,
    pub up_percent: f32,
    pub total_up: u64,
    pub total_down: u64,
    pub data_points: Vec<ServiceHistoryDataPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerServiceStats {
    pub server_id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    pub stats: ServiceHistorySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHistoryResponse {
    pub service_id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub service_name: String,
    pub servers: Vec<ServerServiceStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub monitor_id: u64,
    pub server_id: u64,
    pub monitor_name: String,
    pub server_name: String,
    pub display_index: i32,
    pub created_at: Vec<i64>,
    pub avg_delay: Vec<f64>,
    pub packet_loss: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResponseItem {
    pub service_name: String,
    pub current_up: u64,
    pub current_down: u64,
    pub total_up: u64,
    pub total_down: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<[f64; 30]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<[u64; 30]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down: Option<[u64; 30]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleTransferStats {
    pub name: String,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub max: u64,
    pub min: u64,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub server_name: HashMap<u64, String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub transfer: HashMap<u64, u64>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub next_update: HashMap<u64, DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardSettings {
    pub language: String,
    pub site_name: String,
    pub custom_code: String,
    pub custom_code_dashboard: String,
    pub install_host: String,
    pub tls: bool,
    pub dns_servers: String,
    pub ignored_ip_notification: String,
    pub ip_change_notification_group_id: u64,
    pub cover: u8,
    pub web_real_ip_header: String,
    pub agent_real_ip_header: String,
    pub user_template: String,
    pub admin_template: String,
    pub enable_ip_change_notification: bool,
    pub enable_plain_ip_in_notification: bool,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub oauth2: HashMap<String, OAuth2Config>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_secret: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub jwt_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuth2Config {
    pub client_id: String,
    pub client_secret: String,
    pub endpoint: OAuth2Endpoint,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub user_info_url: String,
    pub user_id_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OAuth2Endpoint {
    pub auth_url: String,
    pub token_url: String,
}

impl Default for DashboardSettings {
    fn default() -> Self {
        Self {
            language: "en_US".to_string(),
            site_name: "Nezha".to_string(),
            custom_code: String::new(),
            custom_code_dashboard: String::new(),
            install_host: String::new(),
            tls: false,
            dns_servers: String::new(),
            ignored_ip_notification: String::new(),
            ip_change_notification_group_id: 0,
            cover: 1,
            web_real_ip_header: String::new(),
            agent_real_ip_header: String::new(),
            user_template: "user-dist".to_string(),
            admin_template: "admin-dist".to_string(),
            enable_ip_change_notification: false,
            enable_plain_ip_in_notification: false,
            oauth2: HashMap::new(),
            client_secret: String::new(),
            jwt_secret: String::new(),
        }
    }
}

#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create data dir {}", parent.display()))?;
        }

        let conn = Connection::open(path)
            .with_context(|| format!("failed to open sqlite database {}", path.display()))?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn ensure_server_for_user(&self, uuid: Uuid, user_id: u64) -> Result<StoredServer> {
        if let Some(server) = self.server_by_uuid(uuid)? {
            anyhow::ensure!(
                user_id == 0 || server.user_id == user_id,
                "client UUID does not belong to the agent secret owner"
            );
            return Ok(server);
        }

        let now = unix_now();
        self.conn.execute(
            "INSERT INTO servers (user_id, uuid, name, created_at_unix, updated_at_unix, last_active_unix)
             VALUES (?1, ?2, ?3, ?4, ?4, ?4)",
            params![user_id as i64, uuid.to_string(), pet_name(uuid), now as i64],
        )?;

        self.server_by_uuid(uuid)?
            .context("server was inserted but cannot be loaded")
    }

    pub fn agent_secret_owner(&self, secret: &str, global_secret: &str) -> Result<Option<u64>> {
        if secret == global_secret {
            return Ok(Some(0));
        }
        let user_id = self
            .conn
            .query_row(
                "SELECT id FROM users WHERE agent_secret = ?1",
                params![secret],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(i64_to_u64);
        Ok(user_id)
    }

    pub fn dashboard_settings(&self) -> Result<Option<DashboardSettings>> {
        let raw = self
            .conn
            .query_row(
                "SELECT value_json FROM settings WHERE key = 'dashboard'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        raw.map(|raw| serde_json::from_str(&raw).context("failed to decode dashboard settings"))
            .transpose()
    }

    pub fn save_dashboard_settings(&self, settings: &DashboardSettings) -> Result<()> {
        let raw = serde_json::to_string(settings)?;
        self.conn.execute(
            "INSERT INTO settings (key, value_json, updated_at_unix)
             VALUES ('dashboard', ?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json,
                                            updated_at_unix = excluded.updated_at_unix",
            params![raw, unix_now() as i64],
        )?;
        Ok(())
    }

    pub fn ensure_admin(&self, username: &str, password: &str) -> Result<()> {
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM users WHERE username = ?1",
                params![username],
                |row| row.get(0),
            )
            .optional()?;

        if existing.is_some() {
            return Ok(());
        }

        let now = unix_now() as i64;
        let password = hash(password, DEFAULT_COST).context("failed to hash bootstrap password")?;
        self.conn.execute(
            "INSERT INTO users (username, password, role, agent_secret, reject_password, created_at_unix, updated_at_unix)
             VALUES (?1, ?2, 0, ?3, 0, ?4, ?4)",
            params![username, password, generate_secret(), now],
        )?;
        Ok(())
    }

    pub fn reset_admin_password(&self, username: &str, password: &str) -> Result<()> {
        anyhow::ensure!(!username.is_empty(), "username can't be empty");

        let now = unix_now() as i64;
        let password = hash(password, DEFAULT_COST).context("failed to hash admin password")?;
        let changed = self.conn.execute(
            "UPDATE users SET password = ?1, role = 0, reject_password = 0, updated_at_unix = ?2
             WHERE username = ?3",
            params![password, now, username],
        )?;

        if changed == 0 {
            self.conn.execute(
                "INSERT INTO users (username, password, role, agent_secret, reject_password, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, 0, ?3, 0, ?4, ?4)",
                params![username, password, generate_secret(), now],
            )?;
        }

        Ok(())
    }

    pub fn authenticate_user(&self, username: &str, password: &str) -> Result<Option<ApiUser>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, username, password, role, agent_secret, reject_password
                 FROM users WHERE username = ?1",
                params![username],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;

        let Some((id, username, password_hash, role, agent_secret, reject_password)) = row else {
            return Ok(None);
        };

        if reject_password != 0 || !verify(password, &password_hash).unwrap_or(false) {
            return Ok(None);
        }

        Ok(Some(ApiUser {
            id: id.max(0) as u64,
            username,
            role: role.max(0) as u8,
            agent_secret,
            reject_password: reject_password != 0,
        }))
    }

    pub fn list_servers(&self) -> Result<Vec<PublicServer>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, user_id, uuid, name, note, public_note, display_index, hide_for_guest, enable_ddns,
                    ddns_profiles_json, override_ddns_domains_json,
                    host_json, state_json, geoip_json, last_active_unix,
                    prev_transfer_in_snapshot, prev_transfer_out_snapshot
             FROM servers
             ORDER BY display_index DESC, id ASC",
        )?;

        let servers = stmt
            .query_map([], |row| {
                let ddns_profiles_json: String = row.get(9)?;
                let override_ddns_domains_json: String = row.get(10)?;
                let host_json: Option<String> = row.get(11)?;
                let state_json: Option<String> = row.get(12)?;
                let geoip_json: Option<String> = row.get(13)?;
                let id: i64 = row.get(0)?;
                let user_id: i64 = row.get(1)?;
                let display_index: i64 = row.get(6)?;
                let last_active: i64 = row.get(14)?;
                let prev_transfer_in_snapshot: i64 = row.get(15)?;
                let prev_transfer_out_snapshot: i64 = row.get(16)?;
                Ok(PublicServer {
                    id: id.max(0) as u64,
                    user_id: user_id.max(0) as u64,
                    uuid: row.get(2)?,
                    name: row.get(3)?,
                    note: row.get(4)?,
                    public_note: row.get(5)?,
                    display_index: display_index as i32,
                    hide_for_guest: row.get::<_, i64>(7)? != 0,
                    enable_ddns: row.get::<_, i64>(8)? != 0,
                    ddns_profiles: serde_json::from_str(&ddns_profiles_json).unwrap_or_default(),
                    override_ddns_domains: serde_json::from_str(&override_ddns_domains_json)
                        .unwrap_or_default(),
                    host: host_json
                        .as_deref()
                        .and_then(|raw| serde_json::from_str::<CoreHost>(raw).ok()),
                    state: state_json
                        .as_deref()
                        .and_then(|raw| serde_json::from_str::<CoreHostState>(raw).ok()),
                    geoip: geoip_json
                        .as_deref()
                        .and_then(|raw| serde_json::from_str::<CoreGeoIp>(raw).ok()),
                    last_active: last_active.max(0) as u64,
                    prev_transfer_in_snapshot: prev_transfer_in_snapshot.max(0) as u64,
                    prev_transfer_out_snapshot: prev_transfer_out_snapshot.max(0) as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(servers)
    }

    pub fn update_server(&self, id: u64, body: &Value) -> Result<PublicServer> {
        let now = unix_now() as i64;
        let name = string_field(body, "name");
        let note = string_field(body, "note");
        let public_note = string_field(body, "public_note");
        let display_index = i64_field(body, "display_index") as i32;
        let hide_for_guest = bool_i64(body, "hide_for_guest");
        let enable_ddns = bool_i64(body, "enable_ddns");
        let ddns_profiles_json = serde_json::to_string(&u64_list_field(body, "ddns_profiles"))?;
        let override_ddns_domains_json = serde_json::to_string(
            body.get("override_ddns_domains")
                .unwrap_or(&Value::Object(Default::default())),
        )?;

        let changed = self.conn.execute(
            "UPDATE servers SET name = ?1, note = ?2, public_note = ?3, display_index = ?4,
             hide_for_guest = ?5, enable_ddns = ?6, ddns_profiles_json = ?7,
             override_ddns_domains_json = ?8, updated_at_unix = ?9 WHERE id = ?10",
            params![
                name,
                note,
                public_note,
                display_index,
                hide_for_guest,
                enable_ddns,
                ddns_profiles_json,
                override_ddns_domains_json,
                now,
                id as i64
            ],
        )?;
        anyhow::ensure!(changed > 0, "server not found");
        self.get_public_server(id)
    }

    pub fn delete_servers(&self, ids: &[u64]) -> Result<usize> {
        let mut deleted = 0;
        for id in ids {
            let sid = *id as i64;
            deleted += self
                .conn
                .execute("DELETE FROM servers WHERE id = ?1", params![sid])?;
            self.conn.execute(
                "DELETE FROM server_group_servers WHERE server_id = ?1",
                params![sid],
            )?;
            self.conn
                .execute("DELETE FROM transfers WHERE server_id = ?1", params![sid])?;
            self.conn.execute(
                "DELETE FROM service_history WHERE server_id = ?1",
                params![sid],
            )?;
            self.conn.execute(
                "DELETE FROM server_metrics WHERE server_id = ?1",
                params![sid],
            )?;
            self.conn.execute(
                "DELETE FROM pending_tasks WHERE server_id = ?1",
                params![sid],
            )?;
            self.conn
                .execute("DELETE FROM nat WHERE server_id = ?1", params![sid])?;
        }
        Ok(deleted)
    }

    pub fn move_servers(&self, ids: &[u64], to_user: u64) -> Result<usize> {
        let mut changed = 0;
        for id in ids {
            changed += self.conn.execute(
                "UPDATE servers SET user_id = ?1, updated_at_unix = ?2 WHERE id = ?3",
                params![to_user as i64, unix_now() as i64, *id as i64],
            )?;
        }
        Ok(changed)
    }

    pub fn list_users(&self) -> Result<Vec<UserResource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, username, role, agent_secret, reject_password, created_at_unix, updated_at_unix
             FROM users ORDER BY id ASC",
        )?;
        let rows = stmt
            .query_map([], user_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn get_user(&self, id: u64) -> Result<UserResource> {
        self.conn
            .query_row(
                "SELECT id, username, role, agent_secret, reject_password, created_at_unix, updated_at_unix
                 FROM users WHERE id = ?1",
                params![id as i64],
                user_from_row,
            )
            .context("user not found")
    }

    pub fn create_user(&self, username: &str, password: &str, role: u8) -> Result<u64> {
        anyhow::ensure!(!username.is_empty(), "username can't be empty");
        anyhow::ensure!(
            password.len() >= 6,
            "password length must be greater than 6"
        );
        anyhow::ensure!(role <= 1, "invalid role");

        let now = unix_now() as i64;
        let password = hash(password, DEFAULT_COST).context("failed to hash password")?;
        self.conn.execute(
            "INSERT INTO users (username, password, role, agent_secret, reject_password, created_at_unix, updated_at_unix)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?5)",
            params![username, password, role as i64, generate_secret(), now],
        )?;
        Ok(self.conn.last_insert_rowid() as u64)
    }

    pub fn delete_users(&self, ids: &[u64]) -> Result<usize> {
        self.delete_by_ids("users", ids)
    }

    pub fn update_profile(
        &self,
        user_id: u64,
        original_password: &str,
        new_username: &str,
        new_password: &str,
        reject_password: bool,
    ) -> Result<()> {
        let row = self
            .conn
            .query_row(
                "SELECT password FROM users WHERE id = ?1",
                params![user_id as i64],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .context("user not found")?;

        anyhow::ensure!(
            verify(original_password, &row).unwrap_or(false),
            "incorrect password"
        );
        anyhow::ensure!(
            !reject_password || self.oauth2_bind_count(user_id)? > 0,
            "you don't have any oauth2 bindings"
        );

        let password = hash(new_password, DEFAULT_COST).context("failed to hash password")?;
        let now = unix_now() as i64;
        self.conn.execute(
            "UPDATE users SET username = ?1, password = ?2, reject_password = ?3, updated_at_unix = ?4
             WHERE id = ?5",
            params![
                new_username,
                password,
                if reject_password { 1 } else { 0 },
                now,
                user_id as i64
            ],
        )?;
        Ok(())
    }

    pub fn oauth2_binds_for_user(&self, user_id: u64) -> Result<HashMap<String, String>> {
        let mut stmt = self.conn.prepare(
            "SELECT provider, open_id FROM oauth2_binds WHERE user_id = ?1 ORDER BY provider ASC",
        )?;
        let rows = stmt
            .query_map(params![user_id as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<HashMap<_, _>>>()?;
        Ok(rows)
    }

    pub fn oauth2_bind_count(&self, user_id: u64) -> Result<u64> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM oauth2_binds WHERE user_id = ?1",
                params![user_id as i64],
                |row| row.get::<_, i64>(0),
            )
            .map(i64_to_u64)
            .map_err(Into::into)
    }

    pub fn bind_oauth2(&self, user_id: u64, provider: &str, open_id: &str) -> Result<()> {
        anyhow::ensure!(!provider.trim().is_empty(), "provider is required");
        anyhow::ensure!(!open_id.trim().is_empty(), "open_id is required");
        let provider = provider.trim().to_ascii_lowercase();
        let now = unix_now() as i64;
        self.conn.execute(
            "INSERT INTO oauth2_binds (user_id, provider, open_id, created_at_unix, updated_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(user_id, provider) DO UPDATE SET
                open_id = excluded.open_id,
                updated_at_unix = excluded.updated_at_unix",
            params![user_id as i64, provider, open_id.trim(), now],
        )?;
        Ok(())
    }

    pub fn user_by_oauth2(&self, provider: &str, open_id: &str) -> Result<Option<UserResource>> {
        let provider = provider.trim().to_ascii_lowercase();
        self.conn
            .query_row(
                "SELECT u.id, u.username, u.role, u.agent_secret, u.reject_password,
                        u.created_at_unix, u.updated_at_unix
                 FROM oauth2_binds b
                 JOIN users u ON u.id = b.user_id
                 WHERE b.provider = ?1 AND b.open_id = ?2",
                params![provider, open_id.trim()],
                user_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn unbind_oauth2(&self, user_id: u64, provider: &str) -> Result<()> {
        let user = self.get_user(user_id)?;
        let bind_count = self.oauth2_bind_count(user_id)?;
        anyhow::ensure!(
            !(user.reject_password && bind_count < 2),
            "operation not permitted"
        );
        self.conn.execute(
            "DELETE FROM oauth2_binds WHERE user_id = ?1 AND provider = ?2",
            params![user_id as i64, provider.trim().to_ascii_lowercase()],
        )?;
        Ok(())
    }

    pub fn list_named(&self, table: NamedTable) -> Result<Vec<NamedResource>> {
        let sql = format!(
            "SELECT id, name, user_id, created_at_unix, updated_at_unix FROM {} ORDER BY id ASC",
            table.as_str()
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(NamedResource {
                    id: i64_to_u64(row.get(0)?),
                    name: row.get(1)?,
                    user_id: i64_to_u64(row.get(2)?),
                    created_at: i64_to_u64(row.get(3)?),
                    updated_at: i64_to_u64(row.get(4)?),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn create_named(
        &self,
        table: NamedTable,
        user_id: u64,
        name: &str,
    ) -> Result<NamedResource> {
        let now = unix_now() as i64;
        let sql = format!(
            "INSERT INTO {} (user_id, name, created_at_unix, updated_at_unix) VALUES (?1, ?2, ?3, ?3)",
            table.as_str()
        );
        self.conn
            .execute(&sql, params![user_id as i64, name, now])?;
        self.get_named(table, self.conn.last_insert_rowid() as u64)
    }

    pub fn update_named(&self, table: NamedTable, id: u64, name: &str) -> Result<NamedResource> {
        let now = unix_now() as i64;
        let sql = format!(
            "UPDATE {} SET name = ?1, updated_at_unix = ?2 WHERE id = ?3",
            table.as_str()
        );
        self.conn.execute(&sql, params![name, now, id as i64])?;
        self.get_named(table, id)
    }

    pub fn delete_named(&self, table: NamedTable, ids: &[u64]) -> Result<usize> {
        let sql = format!("DELETE FROM {} WHERE id = ?1", table.as_str());
        let mut deleted = 0;
        for id in ids {
            deleted += self.conn.execute(&sql, params![*id as i64])?;
        }
        Ok(deleted)
    }

    pub fn list_notifications(&self) -> Result<Vec<NotificationResource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, user_id, name, url, request_method, request_type, request_header,
                    request_body, verify_tls, format_metric_units, skip_check,
                    created_at_unix, updated_at_unix
             FROM notifications ORDER BY id ASC",
        )?;
        let rows = stmt
            .query_map([], notification_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn upsert_notification(
        &self,
        id: Option<u64>,
        user_id: u64,
        body: &Value,
    ) -> Result<NotificationResource> {
        let now = unix_now() as i64;
        let name = string_field(body, "name");
        let url = string_field(body, "url");
        let request_method = u8_field(body, "request_method");
        let request_type = u8_field(body, "request_type");
        let request_header = string_field(body, "request_header");
        let request_body = string_field(body, "request_body");
        let verify_tls = opt_bool_i64(body, "verify_tls");
        let format_metric_units = opt_bool_i64(body, "format_metric_units");
        let skip_check = opt_bool_i64(body, "skip_check");

        let id = if let Some(id) = id {
            self.conn.execute(
                "UPDATE notifications SET name=?1, url=?2, request_method=?3, request_type=?4,
                 request_header=?5, request_body=?6, verify_tls=?7, format_metric_units=?8,
                 skip_check=?9, updated_at_unix=?10 WHERE id=?11",
                params![
                    name,
                    url,
                    request_method as i64,
                    request_type as i64,
                    request_header,
                    request_body,
                    verify_tls,
                    format_metric_units,
                    skip_check,
                    now,
                    id as i64
                ],
            )?;
            id
        } else {
            self.conn.execute(
                "INSERT INTO notifications
                 (user_id, name, url, request_method, request_type, request_header, request_body,
                  verify_tls, format_metric_units, skip_check, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
                params![
                    user_id as i64,
                    name,
                    url,
                    request_method as i64,
                    request_type as i64,
                    request_header,
                    request_body,
                    verify_tls,
                    format_metric_units,
                    skip_check,
                    now
                ],
            )?;
            self.conn.last_insert_rowid() as u64
        };
        self.get_notification(id)
    }

    pub fn delete_notifications(&self, ids: &[u64]) -> Result<usize> {
        let deleted = self.delete_by_ids("notifications", ids)?;
        for id in ids {
            self.conn.execute(
                "DELETE FROM notification_group_notifications WHERE notification_id = ?1",
                params![*id as i64],
            )?;
        }
        Ok(deleted)
    }

    pub fn list_notification_groups(&self) -> Result<Vec<NotificationGroupResource>> {
        let groups = self.list_named(NamedTable::NotificationGroups)?;
        groups
            .into_iter()
            .map(|group| {
                let notifications = self.notification_ids_for_group(group.id)?;
                Ok(NotificationGroupResource {
                    group,
                    notifications,
                })
            })
            .collect()
    }

    pub fn list_server_groups(&self) -> Result<Vec<ServerGroupResource>> {
        let groups = self.list_named(NamedTable::ServerGroups)?;
        groups
            .into_iter()
            .map(|group| {
                let servers = self.server_ids_for_group(group.id)?;
                Ok(ServerGroupResource { group, servers })
            })
            .collect()
    }

    pub fn upsert_server_group(
        &self,
        id: Option<u64>,
        user_id: u64,
        name: &str,
        servers: &[u64],
    ) -> Result<ServerGroupResource> {
        self.ensure_servers_exist(servers)?;
        let group = if let Some(id) = id {
            self.update_named(NamedTable::ServerGroups, id, name)?
        } else {
            self.create_named(NamedTable::ServerGroups, user_id, name)?
        };
        self.conn.execute(
            "DELETE FROM server_group_servers WHERE server_group_id = ?1",
            params![group.id as i64],
        )?;
        for server_id in unique_u64s(servers) {
            self.conn.execute(
                "INSERT INTO server_group_servers (server_group_id, server_id) VALUES (?1, ?2)",
                params![group.id as i64, server_id as i64],
            )?;
        }
        Ok(ServerGroupResource {
            group: group.clone(),
            servers: self.server_ids_for_group(group.id)?,
        })
    }

    pub fn delete_server_groups(&self, ids: &[u64]) -> Result<usize> {
        let deleted = self.delete_named(NamedTable::ServerGroups, ids)?;
        for id in ids {
            self.conn.execute(
                "DELETE FROM server_group_servers WHERE server_group_id = ?1",
                params![*id as i64],
            )?;
        }
        Ok(deleted)
    }

    pub fn upsert_notification_group(
        &self,
        id: Option<u64>,
        user_id: u64,
        name: &str,
        notifications: &[u64],
    ) -> Result<NotificationGroupResource> {
        self.ensure_notifications_exist(notifications)?;
        let group = if let Some(id) = id {
            self.update_named(NamedTable::NotificationGroups, id, name)?
        } else {
            self.create_named(NamedTable::NotificationGroups, user_id, name)?
        };
        self.conn.execute(
            "DELETE FROM notification_group_notifications WHERE notification_group_id = ?1",
            params![group.id as i64],
        )?;
        for notification_id in unique_u64s(notifications) {
            self.conn.execute(
                "INSERT INTO notification_group_notifications (notification_group_id, notification_id)
                 VALUES (?1, ?2)",
                params![group.id as i64, notification_id as i64],
            )?;
        }
        Ok(NotificationGroupResource {
            group: group.clone(),
            notifications: self.notification_ids_for_group(group.id)?,
        })
    }

    pub fn delete_notification_groups(&self, ids: &[u64]) -> Result<usize> {
        let deleted = self.delete_named(NamedTable::NotificationGroups, ids)?;
        for id in ids {
            self.conn.execute(
                "DELETE FROM notification_group_notifications WHERE notification_group_id = ?1",
                params![*id as i64],
            )?;
        }
        Ok(deleted)
    }

    pub fn notifications_for_group(&self, group_id: u64) -> Result<Vec<NotificationResource>> {
        let mut stmt = self.conn.prepare(
            "SELECT n.id, n.user_id, n.name, n.url, n.request_method, n.request_type,
                    n.request_header, n.request_body, n.verify_tls, n.format_metric_units,
                    n.skip_check, n.created_at_unix, n.updated_at_unix
             FROM notifications n
             JOIN notification_group_notifications ngn ON ngn.notification_id = n.id
             WHERE ngn.notification_group_id = ?1
             ORDER BY n.id ASC",
        )?;
        let rows = stmt
            .query_map(params![group_id as i64], notification_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn list_crons(&self) -> Result<Vec<CronResource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, user_id, name, task_type, scheduler, command, servers_json,
                    push_successful, notification_group_id, last_executed_at_unix,
                    last_result, cover, created_at_unix, updated_at_unix
             FROM crons ORDER BY id ASC",
        )?;
        let rows = stmt
            .query_map([], cron_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn upsert_cron(&self, id: Option<u64>, user_id: u64, body: &Value) -> Result<CronResource> {
        let now = unix_now() as i64;
        let name = string_field(body, "name");
        let task_type = u8_field(body, "task_type");
        let scheduler = string_field(body, "scheduler");
        let command = string_field(body, "command");
        let servers_json = serde_json::to_string(&u64_list_field(body, "servers"))?;
        let push_successful = bool_i64(body, "push_successful");
        let notification_group_id = u64_field(body, "notification_group_id") as i64;
        let cover = u8_field(body, "cover");

        let id = if let Some(id) = id {
            self.conn.execute(
                "UPDATE crons SET name=?1, task_type=?2, scheduler=?3, command=?4, servers_json=?5,
                 push_successful=?6, notification_group_id=?7, cover=?8, updated_at_unix=?9 WHERE id=?10",
                params![
                    name,
                    task_type as i64,
                    scheduler,
                    command,
                    servers_json,
                    push_successful,
                    notification_group_id,
                    cover as i64,
                    now,
                    id as i64
                ],
            )?;
            id
        } else {
            self.conn.execute(
                "INSERT INTO crons
                 (user_id, name, task_type, scheduler, command, servers_json, push_successful,
                  notification_group_id, cover, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
                params![
                    user_id as i64,
                    name,
                    task_type as i64,
                    scheduler,
                    command,
                    servers_json,
                    push_successful,
                    notification_group_id,
                    cover as i64,
                    now
                ],
            )?;
            self.conn.last_insert_rowid() as u64
        };
        self.get_cron(id)
    }

    pub fn delete_crons(&self, ids: &[u64]) -> Result<usize> {
        self.delete_by_ids("crons", ids)
    }

    pub fn record_cron_execution(&self, id: u64, successful: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE crons SET last_executed_at_unix = ?1, last_result = ?2, updated_at_unix = ?1
             WHERE id = ?3",
            params![unix_now() as i64, if successful { 1 } else { 0 }, id as i64],
        )?;
        Ok(())
    }

    pub fn record_cron_result(
        &self,
        server_id: u64,
        result: &TaskResult,
        alert_trigger_authorized: bool,
    ) -> Result<bool> {
        let cron = match self.get_cron(result.id) {
            Ok(cron) => cron,
            Err(_) => return Ok(false),
        };
        let server = match self.get_public_server(server_id) {
            Ok(server) => server,
            Err(_) => return Ok(false),
        };
        if !self.can_report_cron_result(&cron, &server, alert_trigger_authorized)? {
            return Ok(false);
        }

        let executed_at = unix_now().saturating_sub(result.delay.max(0.0) as u64) as i64;
        self.conn.execute(
            "UPDATE crons SET last_executed_at_unix = ?1, last_result = ?2, updated_at_unix = ?1
             WHERE id = ?3",
            params![
                executed_at,
                if result.successful { 1 } else { 0 },
                result.id as i64
            ],
        )?;
        Ok(true)
    }

    pub fn list_nat(&self) -> Result<Vec<NatResource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, user_id, enabled, name, server_id, host, domain, created_at_unix, updated_at_unix
             FROM nat ORDER BY id ASC",
        )?;
        let rows = stmt
            .query_map([], nat_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn upsert_nat(&self, id: Option<u64>, user_id: u64, body: &Value) -> Result<NatResource> {
        let now = unix_now() as i64;
        let enabled = bool_i64(body, "enabled");
        let name = string_field(body, "name");
        let server_id = u64_field(body, "server_id") as i64;
        let host = string_field(body, "host");
        let domain = string_field(body, "domain");

        let id = if let Some(id) = id {
            self.conn.execute(
                "UPDATE nat SET enabled=?1, name=?2, server_id=?3, host=?4, domain=?5,
                 updated_at_unix=?6 WHERE id=?7",
                params![enabled, name, server_id, host, domain, now, id as i64],
            )?;
            id
        } else {
            self.conn.execute(
                "INSERT INTO nat (user_id, enabled, name, server_id, host, domain, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                params![user_id as i64, enabled, name, server_id, host, domain, now],
            )?;
            self.conn.last_insert_rowid() as u64
        };
        self.get_nat(id)
    }

    pub fn delete_nat(&self, ids: &[u64]) -> Result<usize> {
        self.delete_by_ids("nat", ids)
    }

    pub fn list_waf(&self, limit: u64, offset: u64) -> Result<(Vec<WafResource>, u64)> {
        let limit = limit.clamp(1, 500) as i64;
        let offset = offset as i64;
        let mut stmt = self.conn.prepare(
            "SELECT ip, block_identifier, block_reason, block_timestamp, count
             FROM waf ORDER BY block_timestamp DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt
            .query_map(params![limit, offset], waf_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM waf", [], |row| row.get(0))?;
        Ok((rows, i64_to_u64(total)))
    }

    pub fn delete_waf_ips(&self, ips: &[String]) -> Result<usize> {
        let mut deleted = 0;
        let mut seen = Vec::new();
        for ip in ips {
            let Some(binary) = ip_string_to_binary(ip) else {
                continue;
            };
            if seen.contains(&binary) {
                continue;
            }
            seen.push(binary.clone());
            deleted += self
                .conn
                .execute("DELETE FROM waf WHERE ip = ?1", params![binary])?;
        }
        Ok(deleted)
    }

    pub fn waf_block_active(&self, ip: &str) -> Result<bool> {
        let Some(binary) = ip_string_to_binary(ip) else {
            return Ok(false);
        };
        let latest: Option<i64> = self
            .conn
            .query_row(
                "SELECT block_timestamp FROM waf WHERE ip = ?1 ORDER BY block_timestamp DESC LIMIT 1",
                params![binary],
                |row| row.get(0),
            )
            .optional()?;
        let Some(latest) = latest else {
            return Ok(false);
        };
        let count: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(count), 0) FROM waf WHERE ip = ?1",
            params![ip_string_to_binary(ip).unwrap_or_default()],
            |row| row.get(0),
        )?;
        Ok(waf_block_until(count.max(0) as u64, latest.max(0) as u64) > unix_now())
    }

    pub fn delete_waf_ip_identifier(&self, ip: &str, block_identifier: i64) -> Result<usize> {
        let Some(binary) = ip_string_to_binary(ip) else {
            return Ok(0);
        };
        Ok(self.conn.execute(
            "DELETE FROM waf WHERE ip = ?1 AND block_identifier = ?2",
            params![binary, block_identifier],
        )?)
    }

    pub fn record_waf_block(
        &self,
        ip: &str,
        block_reason: u8,
        block_identifier: i64,
    ) -> Result<()> {
        let Some(binary) = ip_string_to_binary(ip) else {
            return Ok(());
        };
        let now = unix_now() as i64;
        let count = if block_reason == 4 { 99_999 } else { 1 };
        self.conn.execute(
            "INSERT INTO waf (ip, block_identifier, block_reason, block_timestamp, count)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(ip, block_identifier) DO UPDATE SET
                block_reason = excluded.block_reason,
                block_timestamp = excluded.block_timestamp,
                count = CASE
                    WHEN excluded.block_reason = 4 THEN 99999
                    ELSE waf.count + 1
                END",
            params![binary, block_identifier, block_reason as i64, now, count],
        )?;
        Ok(())
    }

    pub fn enqueue_pending_task(
        &self,
        server_id: u64,
        task_id: u64,
        task_type: u64,
        data: &str,
    ) -> Result<()> {
        let now = unix_now() as i64;
        self.conn.execute(
            "INSERT INTO pending_tasks (server_id, task_id, task_type, data, created_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![server_id as i64, task_id as i64, task_type as i64, data, now],
        )?;
        Ok(())
    }

    pub fn drain_pending_tasks(&self, server_id: u64) -> Result<Vec<PendingTask>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, task_id, task_type, data
             FROM pending_tasks WHERE server_id = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt
            .query_map(params![server_id as i64], |row| {
                Ok(PendingTask {
                    row_id: row.get::<_, i64>(0)?,
                    task_id: row.get::<_, i64>(1)? as u64,
                    task_type: row.get::<_, i64>(2)? as u64,
                    data: row.get::<_, String>(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn delete_pending_task(&self, row_id: i64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM pending_tasks WHERE id = ?1",
            params![row_id],
        )?;
        Ok(())
    }

    pub fn record_notification_dead_letter(
        &self,
        notification_id: u64,
        message: &str,
        error: &str,
        attempts: u32,
    ) -> Result<()> {
        let now = unix_now() as i64;
        self.conn.execute(
            "INSERT INTO notification_dead_letter (notification_id, message, error, attempts, created_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![notification_id as i64, message, error, attempts as i64, now],
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn list_notification_dead_letter(&self) -> Result<Vec<NotificationDeadLetterEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, notification_id, message, error, attempts, created_at_unix
             FROM notification_dead_letter ORDER BY id DESC LIMIT 500",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(NotificationDeadLetterEntry {
                    id: row.get::<_, i64>(0)? as u64,
                    notification_id: row.get::<_, i64>(1)? as u64,
                    message: row.get::<_, String>(2)?,
                    error: row.get::<_, String>(3)?,
                    attempts: row.get::<_, i64>(4)? as u32,
                    created_at_unix: row.get::<_, i64>(5)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn list_services(&self) -> Result<Vec<ServiceResource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, user_id, name, type, target, duration, display_index, notify,
                    notification_group_id, cover, skip_servers_json, trigger_tasks_json,
                    enable_trigger_task, enable_show_in_service, fail_trigger_tasks_json,
                    recover_trigger_tasks_json, min_latency, max_latency, latency_notify,
                    created_at_unix, updated_at_unix
             FROM services ORDER BY display_index DESC, id ASC",
        )?;
        let rows = stmt
            .query_map([], service_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn upsert_service(
        &self,
        id: Option<u64>,
        user_id: u64,
        body: &Value,
    ) -> Result<ServiceResource> {
        let now = unix_now() as i64;
        let name = string_field(body, "name");
        let service_type = u8_field(body, "type");
        let target = string_field(body, "target").trim().to_string();
        let duration = u64_field(body, "duration") as i64;
        let display_index = i64_field(body, "display_index");
        let notify = bool_i64(body, "notify");
        let notification_group_id = u64_field(body, "notification_group_id") as i64;
        let cover = u8_field(body, "cover") as i64;
        let enable_trigger_task = bool_i64(body, "enable_trigger_task");
        let enable_show_in_service = bool_i64(body, "enable_show_in_service");
        let fail_trigger_tasks = u64_list_field(body, "fail_trigger_tasks");
        let recover_trigger_tasks = u64_list_field(body, "recover_trigger_tasks");
        let fail_trigger_tasks_json = serde_json::to_string(&fail_trigger_tasks)?;
        let recover_trigger_tasks_json = serde_json::to_string(&recover_trigger_tasks)?;
        let min_latency = body
            .get("min_latency")
            .and_then(Value::as_f64)
            .unwrap_or_default();
        let max_latency = body
            .get("max_latency")
            .and_then(Value::as_f64)
            .unwrap_or_default();
        let latency_notify = bool_i64(body, "latency_notify");
        let skip_servers_json = serde_json::to_string(
            body.get("skip_servers")
                .unwrap_or(&Value::Object(Default::default())),
        )?;
        let trigger_tasks_json = serde_json::to_string(
            body.get("trigger_tasks")
                .or_else(|| body.get("fail_trigger_tasks"))
                .unwrap_or(&Value::Object(Default::default())),
        )?;

        let id = if let Some(id) = id {
            self.conn.execute(
                "UPDATE services SET name=?1, type=?2, target=?3, duration=?4, display_index=?5,
                 notify=?6, notification_group_id=?7, cover=?8, skip_servers_json=?9,
                 trigger_tasks_json=?10, enable_trigger_task=?11, enable_show_in_service=?12,
                 fail_trigger_tasks_json=?13, recover_trigger_tasks_json=?14,
                 min_latency=?15, max_latency=?16, latency_notify=?17,
                 updated_at_unix=?18 WHERE id=?19",
                params![
                    name,
                    service_type as i64,
                    target,
                    duration,
                    display_index,
                    notify,
                    notification_group_id,
                    cover,
                    skip_servers_json,
                    trigger_tasks_json,
                    enable_trigger_task,
                    enable_show_in_service,
                    fail_trigger_tasks_json,
                    recover_trigger_tasks_json,
                    min_latency,
                    max_latency,
                    latency_notify,
                    now,
                    id as i64
                ],
            )?;
            id
        } else {
            self.conn.execute(
                "INSERT INTO services
                 (user_id, name, type, target, duration, display_index, notify,
                  notification_group_id, cover, skip_servers_json, trigger_tasks_json,
                  enable_trigger_task, enable_show_in_service, fail_trigger_tasks_json,
                  recover_trigger_tasks_json, min_latency, max_latency, latency_notify,
                  created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?19)",
                params![
                    user_id as i64,
                    name,
                    service_type as i64,
                    target,
                    duration,
                    display_index,
                    notify,
                    notification_group_id,
                    cover,
                    skip_servers_json,
                    trigger_tasks_json,
                    enable_trigger_task,
                    enable_show_in_service,
                    fail_trigger_tasks_json,
                    recover_trigger_tasks_json,
                    min_latency,
                    max_latency,
                    latency_notify,
                    now
                ],
            )?;
            self.conn.last_insert_rowid() as u64
        };
        self.get_service(id)
    }

    pub fn delete_services(&self, ids: &[u64]) -> Result<usize> {
        self.delete_by_ids("services", ids)
    }

    pub fn record_service_result(&self, server_id: u64, result: &TaskResult) -> Result<bool> {
        let service = match self.get_service(result.id) {
            Ok(service) => service,
            Err(_) => return Ok(false),
        };
        let server = match self.get_public_server(server_id) {
            Ok(server) => server,
            Err(_) => return Ok(false),
        };
        if !self.can_report_service_result(&service, &server, result.r#type)? {
            return Ok(false);
        }

        let now = unix_now() as i64;
        self.conn.execute(
            "INSERT INTO service_history
             (service_id, server_id, avg_delay, up, down, data, created_at_unix, updated_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![
                result.id as i64,
                server_id as i64,
                result.delay as f64,
                if result.successful { 1_i64 } else { 0_i64 },
                if result.successful { 0_i64 } else { 1_i64 },
                &result.data,
                now
            ],
        )?;
        Ok(true)
    }

    pub fn query_service_history(
        &self,
        service_id: u64,
        since_unix: u64,
    ) -> Result<ServiceHistoryResponse> {
        let service = self.get_service(service_id)?;
        let mut stmt = self.conn.prepare(
            "SELECT h.server_id, s.name, h.avg_delay, h.up, h.down, h.created_at_unix
             FROM service_history h
             JOIN servers s ON s.id = h.server_id
             WHERE h.service_id = ?1 AND h.server_id != 0 AND h.created_at_unix >= ?2
             ORDER BY h.server_id ASC, h.created_at_unix ASC",
        )?;
        let rows = stmt
            .query_map(params![service_id as i64, since_unix as i64], |row| {
                Ok((
                    i64_to_u64(row.get(0)?),
                    row.get::<_, String>(1)?,
                    row.get::<_, f64>(2)?,
                    i64_to_u64(row.get(3)?),
                    i64_to_u64(row.get(4)?),
                    i64_to_u64(row.get(5)?),
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut servers = Vec::<ServerServiceStats>::new();
        for (server_id, server_name, delay, up, down, created_at) in rows {
            if servers
                .last()
                .is_none_or(|stats| stats.server_id != server_id)
            {
                servers.push(ServerServiceStats {
                    server_id,
                    server_name,
                    stats: ServiceHistorySummary {
                        avg_delay: 0.0,
                        up_percent: 0.0,
                        total_up: 0,
                        total_down: 0,
                        data_points: Vec::new(),
                    },
                });
            }
            let stats = servers.last_mut().expect("stats entry was just inserted");
            stats.stats.total_up += up;
            stats.stats.total_down += down;
            stats.stats.avg_delay += delay;
            stats.stats.data_points.push(ServiceHistoryDataPoint {
                ts: (created_at as i64).saturating_mul(1000),
                delay,
                status: if down > 0 && up == 0 { 0 } else { 1 },
            });
        }

        for server in &mut servers {
            let count = server.stats.data_points.len();
            if count > 0 {
                server.stats.avg_delay /= count as f64;
            }
            let total = server.stats.total_up + server.stats.total_down;
            if total > 0 {
                server.stats.up_percent = server.stats.total_up as f32 / total as f32 * 100.0;
            }
        }

        Ok(ServiceHistoryResponse {
            service_id,
            service_name: service.name,
            servers,
        })
    }

    pub fn query_server_services(
        &self,
        server_id: u64,
        since_unix: u64,
    ) -> Result<Vec<ServiceInfo>> {
        let server = self.get_public_server(server_id)?;
        let services = self.list_services()?;
        let mut stmt = self.conn.prepare(
            "SELECT service_id, created_at_unix, avg_delay, up, down
             FROM service_history
             WHERE server_id = ?1 AND created_at_unix >= ?2
             ORDER BY service_id ASC, created_at_unix ASC",
        )?;
        let rows = stmt
            .query_map(params![server_id as i64, since_unix as i64], |row| {
                Ok((
                    i64_to_u64(row.get(0)?),
                    i64_to_u64(row.get(1)?),
                    row.get::<_, f64>(2)?,
                    i64_to_u64(row.get(3)?),
                    i64_to_u64(row.get(4)?),
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut result = Vec::new();
        for service in services {
            if !service_covers_server(&service, server_id) {
                continue;
            }
            let points = rows
                .iter()
                .filter(|(service_id, _, _, _, _)| *service_id == service.id)
                .collect::<Vec<_>>();
            if points.is_empty() {
                continue;
            }

            result.push(ServiceInfo {
                monitor_id: service.id,
                server_id,
                monitor_name: service.name,
                server_name: server.name.clone(),
                display_index: service.display_index,
                created_at: points
                    .iter()
                    .map(|(_, created_at, _, _, _)| (*created_at as i64).saturating_mul(1000))
                    .collect(),
                avg_delay: points
                    .iter()
                    .map(|(_, _, delay, _, _)| *delay)
                    .collect(),
                packet_loss: points
                    .iter()
                    .map(|(_, _, _, up, down)| {
                        let total = up.saturating_add(*down);
                        if total == 0 {
                            0.0
                        } else {
                            *down as f64 / total as f64
                        }
                    })
                    .collect(),
            });
        }
        Ok(result)
    }

    pub fn service_response_items(&self) -> Result<HashMap<u64, ServiceResponseItem>> {
        let services = self.list_services()?;
        let mut items = services
            .into_iter()
            .map(|service| {
                (
                    service.id,
                    ServiceResponseItem {
                        service_name: service.name,
                        current_up: 0,
                        current_down: 0,
                        total_up: 0,
                        total_down: 0,
                        delay: None,
                        up: None,
                        down: None,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        let mut latest_by_server = HashMap::<(u64, u64), bool>::new();
        let mut rolling = HashMap::<u64, Vec<(f64, u64, u64)>>::new();
        let mut stmt = self.conn.prepare(
            "SELECT service_id, server_id, avg_delay, up, down
             FROM service_history
             WHERE server_id != 0
             ORDER BY service_id ASC, server_id ASC, created_at_unix ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    i64_to_u64(row.get(0)?),
                    i64_to_u64(row.get(1)?),
                    row.get::<_, f64>(2)?,
                    i64_to_u64(row.get(3)?),
                    i64_to_u64(row.get(4)?),
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        for (service_id, server_id, delay, up, down) in rows {
            let Some(item) = items.get_mut(&service_id) else {
                continue;
            };
            item.total_up += up;
            item.total_down += down;
            latest_by_server.insert((service_id, server_id), up > 0 && down == 0);
            let samples = rolling.entry(service_id).or_default();
            samples.push((delay, up, down));
            if samples.len() > 30 {
                samples.remove(0);
            }
        }

        for ((service_id, _), is_up) in latest_by_server {
            let Some(item) = items.get_mut(&service_id) else {
                continue;
            };
            if is_up {
                item.current_up += 1;
            } else {
                item.current_down += 1;
            }
        }

        for (service_id, samples) in rolling {
            let Some(item) = items.get_mut(&service_id) else {
                continue;
            };
            let mut delay = [0.0_f64; 30];
            let mut up = [0_u64; 30];
            let mut down = [0_u64; 30];
            let start = 30_usize.saturating_sub(samples.len());
            for (index, (sample_delay, sample_up, sample_down)) in samples.into_iter().enumerate() {
                let target = start + index;
                delay[target] = sample_delay;
                up[target] = sample_up;
                down[target] = sample_down;
            }
            item.delay = Some(delay);
            item.up = Some(up);
            item.down = Some(down);
        }

        Ok(items)
    }

    pub fn service_server_ids(&self) -> Result<Vec<u64>> {
        let services = self.list_services()?;
        let servers = self.list_servers()?;
        let mut ids = Vec::new();
        for service in &services {
            for server in &servers {
                if service_covers_server(service, server.id) && !ids.contains(&server.id) {
                    ids.push(server.id);
                }
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    #[cfg(test)]
    pub fn cycle_transfer_stats(&self) -> Result<HashMap<u64, CycleTransferStats>> {
        let alerts = self.list_alert_rules()?;
        let servers = self.list_servers()?;
        let now = unix_now();
        let mut stats = HashMap::new();

        for alert in alerts {
            if !alert.enable.unwrap_or(false) || alert.rules.is_empty() {
                continue;
            }
            let Some(rule) = alert
                .rules
                .iter()
                .find(|rule| rule_type(rule).is_some_and(is_transfer_cycle_rule))
            else {
                continue;
            };
            let Some(from) = transfer_cycle_start(rule, now) else {
                continue;
            };
            let Some(to) = transfer_cycle_end(rule, now) else {
                continue;
            };
            let mut item = CycleTransferStats {
                name: alert.name.clone(),
                from,
                to,
                max: numeric_u64(rule, "max"),
                min: numeric_u64(rule, "min"),
                server_name: HashMap::new(),
                transfer: HashMap::new(),
                next_update: HashMap::new(),
            };

            for server in &servers {
                if alert.user_id != server.user_id && !self.user_is_admin(alert.user_id)? {
                    continue;
                }
                if rule_excludes_server(rule, server.id) {
                    continue;
                }
                let value = transfer_cycle_rule_value(rule, server, self).unwrap_or_default();
                item.server_name.insert(server.id, server.name.clone());
                item.transfer.insert(server.id, value);
                item.next_update
                    .insert(server.id, cycle_transfer_next_update(rule, value, now));
            }

            stats.insert(alert.id, item);
        }

        Ok(stats)
    }

    pub fn list_ddns(&self) -> Result<Vec<DdnsResource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, user_id, name, provider, domains_json, body_json, created_at_unix, updated_at_unix
             FROM ddns ORDER BY id ASC",
        )?;
        let rows = stmt
            .query_map([], ddns_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn upsert_ddns(&self, id: Option<u64>, user_id: u64, body: &Value) -> Result<DdnsResource> {
        let max_retries = u64_field(body, "max_retries");
        anyhow::ensure!(
            (1..=10).contains(&max_retries),
            "the retry count must be an integer between 1 and 10"
        );

        let now = unix_now() as i64;
        let name = string_field(body, "name");
        let provider = string_field(body, "provider");
        let domains_json = serde_json::to_string(&string_list_field(body, "domains"))?;
        let body_json = serde_json::to_string(body)?;

        let id = if let Some(id) = id {
            self.conn.execute(
                "UPDATE ddns SET name=?1, provider=?2, domains_json=?3, body_json=?4,
                 updated_at_unix=?5 WHERE id=?6",
                params![name, provider, domains_json, body_json, now, id as i64],
            )?;
            id
        } else {
            self.conn.execute(
                "INSERT INTO ddns (user_id, name, provider, domains_json, body_json, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                params![user_id as i64, name, provider, domains_json, body_json, now],
            )?;
            self.conn.last_insert_rowid() as u64
        };
        self.get_ddns(id)
    }

    pub fn delete_ddns(&self, ids: &[u64]) -> Result<usize> {
        self.delete_by_ids("ddns", ids)
    }

    pub fn ddns_profiles_for_server(&self, server_id: u64) -> Result<Vec<DdnsResource>> {
        let server = self.get_public_server(server_id)?;
        let profiles = self.list_ddns()?;
        Ok(profiles
            .into_iter()
            .filter(|profile| server.ddns_profiles.contains(&profile.id))
            .collect())
    }

    pub fn list_alert_rules(&self) -> Result<Vec<AlertRuleResource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, user_id, name, enable, trigger_mode, notification_group_id, rules_json,
                    fail_trigger_tasks_json, recover_trigger_tasks_json, muted_until_unix,
                    created_at_unix, updated_at_unix
             FROM alert_rules ORDER BY id ASC",
        )?;
        let rows = stmt
            .query_map([], alert_rule_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn upsert_alert_rule(
        &self,
        id: Option<u64>,
        user_id: u64,
        body: &Value,
    ) -> Result<AlertRuleResource> {
        let now = unix_now() as i64;
        let name = string_field(body, "name");
        let enable = opt_bool_i64(body, "enable");
        let trigger_mode = u8_field(body, "trigger_mode") as i64;
        let notification_group_id = u64_field(body, "notification_group_id") as i64;
        let rules_json = serde_json::to_string(&value_array_field(body, "rules"))?;
        let fail_trigger_tasks_json =
            serde_json::to_string(&u64_list_field(body, "fail_trigger_tasks"))?;
        let recover_trigger_tasks_json =
            serde_json::to_string(&u64_list_field(body, "recover_trigger_tasks"))?;

        let id = if let Some(id) = id {
            self.conn.execute(
                "UPDATE alert_rules SET name=?1, enable=?2, trigger_mode=?3,
                 notification_group_id=?4, rules_json=?5, fail_trigger_tasks_json=?6,
                 recover_trigger_tasks_json=?7, updated_at_unix=?8 WHERE id=?9",
                params![
                    name,
                    enable,
                    trigger_mode,
                    notification_group_id,
                    rules_json,
                    fail_trigger_tasks_json,
                    recover_trigger_tasks_json,
                    now,
                    id as i64
                ],
            )?;
            id
        } else {
            self.conn.execute(
                "INSERT INTO alert_rules
                 (user_id, name, enable, trigger_mode, notification_group_id, rules_json,
                  fail_trigger_tasks_json, recover_trigger_tasks_json, created_at_unix, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
                params![
                    user_id as i64,
                    name,
                    enable,
                    trigger_mode,
                    notification_group_id,
                    rules_json,
                    fail_trigger_tasks_json,
                    recover_trigger_tasks_json,
                    now
                ],
            )?;
            self.conn.last_insert_rowid() as u64
        };
        self.get_alert_rule(id)
    }

    pub fn delete_alert_rules(&self, ids: &[u64]) -> Result<usize> {
        self.delete_by_ids("alert_rules", ids)
    }

    pub fn set_alert_rule_mute(&self, id: u64, muted_until: u64) -> Result<AlertRuleResource> {
        let now = unix_now() as i64;
        let updated = self.conn.execute(
            "UPDATE alert_rules SET muted_until_unix = ?1, updated_at_unix = ?2 WHERE id = ?3",
            params![u64_to_i64_saturating(muted_until), now, id as i64],
        )?;
        if updated == 0 {
            anyhow::bail!("alert rule not found");
        }
        self.get_alert_rule(id)
    }

    pub fn update_host_for_user(
        &self,
        uuid: Uuid,
        user_id: u64,
        host: Host,
    ) -> Result<StoredServer> {
        self.ensure_server_for_user(uuid, user_id)?;
        let now = unix_now();
        let host_json = serde_json::to_string(&CoreHost::from(host))?;
        self.conn.execute(
            "UPDATE servers SET host_json = ?1, updated_at_unix = ?2, last_active_unix = ?2 WHERE uuid = ?3",
            params![host_json, now as i64, uuid.to_string()],
        )?;
        self.server_by_uuid(uuid)?
            .context("server disappeared after host update")
    }

    pub fn update_state_for_user(
        &self,
        uuid: Uuid,
        user_id: u64,
        state: State,
    ) -> Result<StoredServer> {
        self.ensure_server_for_user(uuid, user_id)?;
        let now = unix_now();
        let state = CoreHostState::from(state);
        let state_json = serde_json::to_string(&state)?;
        self.conn.execute(
            "UPDATE servers SET state_json = ?1, updated_at_unix = ?2, last_active_unix = ?2 WHERE uuid = ?3",
            params![state_json, now as i64, uuid.to_string()],
        )?;
        let stored = self
            .server_by_uuid(uuid)?
            .context("server disappeared after state update")?;
        self.record_server_metrics(stored.id, unix_now_millis(), &state)?;
        self.record_transfer_delta(stored.id, &state)?;
        Ok(stored)
    }

    pub fn update_geoip_for_user(
        &self,
        uuid: Uuid,
        user_id: u64,
        geoip: GeoIp,
    ) -> Result<StoredServer> {
        self.ensure_server_for_user(uuid, user_id)?;
        let now = unix_now();
        let geoip_json = serde_json::to_string(&CoreGeoIp::from(geoip))?;
        self.conn.execute(
            "UPDATE servers SET geoip_json = ?1, updated_at_unix = ?2, last_active_unix = ?2 WHERE uuid = ?3",
            params![geoip_json, now as i64, uuid.to_string()],
        )?;
        self.server_by_uuid(uuid)?
            .context("server disappeared after geoip update")
    }

    pub fn maintenance(&self) -> Result<()> {
        const SERVER_METRICS_RETAIN_DAYS: u64 = 30;
        const SERVICE_HISTORY_RETAIN_DAYS: u64 = 30;
        const TRANSFERS_RETAIN_DAYS: u64 = 90;
        const WAF_RETAIN_DAYS: u64 = 30;

        let now_ms = unix_now_millis();
        let now_s = unix_now();
        let metrics_cutoff_ms = now_ms.saturating_sub(SERVER_METRICS_RETAIN_DAYS * 86_400_000);
        let history_cutoff_s = now_s.saturating_sub(SERVICE_HISTORY_RETAIN_DAYS * 86_400);
        let transfers_cutoff_s = now_s.saturating_sub(TRANSFERS_RETAIN_DAYS * 86_400);
        let waf_cutoff_s = now_s.saturating_sub(WAF_RETAIN_DAYS * 86_400);

        self.conn.execute(
            "DELETE FROM server_metrics WHERE timestamp_ms < ?1",
            params![metrics_cutoff_ms as i64],
        )?;
        self.conn.execute(
            "DELETE FROM service_history WHERE created_at_unix < ?1",
            params![history_cutoff_s as i64],
        )?;
        self.conn.execute(
            "DELETE FROM transfers WHERE created_at_unix < ?1",
            params![transfers_cutoff_s as i64],
        )?;
        self.conn.execute(
            "DELETE FROM waf WHERE block_timestamp < ?1",
            params![waf_cutoff_s as i64],
        )?;
        self.conn.execute_batch(
            "
            PRAGMA optimize;
            VACUUM;
            ",
        )?;
        Ok(())
    }

    pub fn query_server_metrics(
        &self,
        server_id: u64,
        metric: &str,
        since_ms: u64,
    ) -> Result<Vec<ServerMetricPoint>> {
        anyhow::ensure!(is_known_server_metric(metric), "invalid metric name");
        let mut stmt = self.conn.prepare(
            "SELECT timestamp_ms, value FROM server_metrics
             WHERE server_id = ?1 AND metric = ?2 AND timestamp_ms >= ?3
             ORDER BY timestamp_ms ASC",
        )?;
        let rows = stmt
            .query_map(params![server_id as i64, metric, since_ms as i64], |row| {
                Ok(ServerMetricPoint {
                    ts: row.get(0)?,
                    value: row.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    #[allow(dead_code)]
    pub fn list_transfers_since(
        &self,
        server_id: u64,
        since_unix: u64,
    ) -> Result<Vec<TransferResource>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, server_id, in_bytes, out_bytes, created_at_unix, updated_at_unix
             FROM transfers
             WHERE server_id = ?1 AND created_at_unix >= ?2
             ORDER BY created_at_unix ASC",
        )?;
        let rows = stmt
            .query_map(
                params![server_id as i64, since_unix as i64],
                transfer_from_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub(crate) fn transfer_totals_since(
        &self,
        server_id: u64,
        since_unix: u64,
    ) -> Result<(u64, u64)> {
        self.conn
            .query_row(
                "SELECT COALESCE(SUM(in_bytes), 0), COALESCE(SUM(out_bytes), 0)
                 FROM transfers
                 WHERE server_id = ?1 AND created_at_unix >= ?2",
                params![server_id as i64, since_unix as i64],
                |row| {
                    Ok((
                        i64_to_u64(row.get::<_, i64>(0)?),
                        i64_to_u64(row.get::<_, i64>(1)?),
                    ))
                },
            )
            .map_err(Into::into)
    }

    fn record_server_metrics(
        &self,
        server_id: u64,
        timestamp_ms: u64,
        state: &CoreHostState,
    ) -> Result<()> {
        let max_temp = state
            .temperatures
            .iter()
            .map(|item| item.temperature)
            .fold(0.0_f64, f64::max);
        let max_gpu = state.gpu.iter().copied().fold(0.0_f64, f64::max);
        let rows = [
            ("cpu", state.cpu),
            ("memory", state.mem_used as f64),
            ("swap", state.swap_used as f64),
            ("disk", state.disk_used as f64),
            ("net_in_speed", state.net_in_speed as f64),
            ("net_out_speed", state.net_out_speed as f64),
            ("net_in_transfer", state.net_in_transfer as f64),
            ("net_out_transfer", state.net_out_transfer as f64),
            ("load1", state.load1),
            ("load5", state.load5),
            ("load15", state.load15),
            ("tcp_conn", state.tcp_conn_count as f64),
            ("udp_conn", state.udp_conn_count as f64),
            ("process_count", state.process_count as f64),
            ("temperature", max_temp),
            ("uptime", state.uptime as f64),
            ("gpu", max_gpu),
        ];
        for (metric, value) in rows {
            self.conn.execute(
                "INSERT INTO server_metrics (server_id, metric, timestamp_ms, value)
                 VALUES (?1, ?2, ?3, ?4)",
                params![server_id as i64, metric, timestamp_ms as i64, value],
            )?;
        }
        Ok(())
    }

    fn record_transfer_delta(&self, server_id: u64, state: &CoreHostState) -> Result<()> {
        let (prev_in, prev_out) = self.conn.query_row(
            "SELECT prev_transfer_in_snapshot, prev_transfer_out_snapshot FROM servers WHERE id = ?1",
            params![server_id as i64],
            |row| Ok((i64_to_u64(row.get(0)?), i64_to_u64(row.get(1)?))),
        )?;

        let counters_reset =
            state.net_in_transfer < prev_in || state.net_out_transfer < prev_out;
        if counters_reset {
            self.conn.execute(
                "UPDATE servers SET prev_transfer_in_snapshot = ?1, prev_transfer_out_snapshot = ?2
                 WHERE id = ?3",
                params![
                    u64_to_i64_saturating(state.net_in_transfer),
                    u64_to_i64_saturating(state.net_out_transfer),
                    server_id as i64
                ],
            )?;
            return Ok(());
        }

        let in_delta = state.net_in_transfer.saturating_sub(prev_in);
        let out_delta = state.net_out_transfer.saturating_sub(prev_out);
        if in_delta == 0 && out_delta == 0 {
            return Ok(());
        }

        let now = unix_now();
        let hour_start = now - (now % 3600);
        self.conn.execute(
            "INSERT INTO transfers (server_id, in_bytes, out_bytes, created_at_unix, updated_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(server_id, created_at_unix) DO UPDATE SET
                in_bytes = transfers.in_bytes + excluded.in_bytes,
                out_bytes = transfers.out_bytes + excluded.out_bytes,
                updated_at_unix = excluded.updated_at_unix",
            params![
                server_id as i64,
                u64_to_i64_saturating(in_delta),
                u64_to_i64_saturating(out_delta),
                hour_start as i64,
                now as i64
            ],
        )?;
        self.conn.execute(
            "UPDATE servers SET prev_transfer_in_snapshot = ?1, prev_transfer_out_snapshot = ?2
             WHERE id = ?3",
            params![
                u64_to_i64_saturating(state.net_in_transfer),
                u64_to_i64_saturating(state.net_out_transfer),
                server_id as i64
            ],
        )?;
        Ok(())
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                uuid TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                public_note TEXT NOT NULL DEFAULT '',
                display_index INTEGER NOT NULL DEFAULT 0,
                hide_for_guest INTEGER NOT NULL DEFAULT 0,
                enable_ddns INTEGER NOT NULL DEFAULT 0,
                ddns_profiles_json TEXT NOT NULL DEFAULT '[]',
                override_ddns_domains_json TEXT NOT NULL DEFAULT '{}',
                host_json TEXT,
                state_json TEXT,
                geoip_json TEXT,
                last_active_unix INTEGER NOT NULL DEFAULT 0,
                prev_transfer_in_snapshot INTEGER NOT NULL DEFAULT 0,
                prev_transfer_out_snapshot INTEGER NOT NULL DEFAULT 0,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL DEFAULT '',
                role INTEGER NOT NULL DEFAULT 1,
                agent_secret TEXT NOT NULL UNIQUE,
                reject_password INTEGER NOT NULL DEFAULT 0,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS oauth2_binds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                open_id TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL,
                UNIQUE(user_id, provider),
                UNIQUE(provider, open_id)
            );

            CREATE TABLE IF NOT EXISTS server_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS server_group_servers (
                server_group_id INTEGER NOT NULL,
                server_id INTEGER NOT NULL,
                PRIMARY KEY (server_group_id, server_id)
            );

            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                type INTEGER NOT NULL,
                target TEXT NOT NULL,
                duration INTEGER NOT NULL DEFAULT 30,
                display_index INTEGER NOT NULL DEFAULT 0,
                notify INTEGER NOT NULL DEFAULT 0,
                notification_group_id INTEGER NOT NULL DEFAULT 0,
                cover INTEGER NOT NULL DEFAULT 0,
                skip_servers_json TEXT NOT NULL DEFAULT '{}',
                trigger_tasks_json TEXT NOT NULL DEFAULT '{}',
                enable_trigger_task INTEGER NOT NULL DEFAULT 0,
                enable_show_in_service INTEGER NOT NULL DEFAULT 0,
                fail_trigger_tasks_json TEXT NOT NULL DEFAULT '[]',
                recover_trigger_tasks_json TEXT NOT NULL DEFAULT '[]',
                min_latency REAL NOT NULL DEFAULT 0,
                max_latency REAL NOT NULL DEFAULT 0,
                latency_notify INTEGER NOT NULL DEFAULT 0,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS crons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                task_type INTEGER NOT NULL DEFAULT 0,
                scheduler TEXT NOT NULL,
                command TEXT NOT NULL DEFAULT '',
                servers_json TEXT NOT NULL DEFAULT '[]',
                push_successful INTEGER NOT NULL DEFAULT 0,
                notification_group_id INTEGER NOT NULL DEFAULT 0,
                last_executed_at_unix INTEGER,
                last_result INTEGER NOT NULL DEFAULT 0,
                cover INTEGER NOT NULL DEFAULT 0,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                request_method INTEGER NOT NULL,
                request_type INTEGER NOT NULL,
                request_header TEXT NOT NULL DEFAULT '',
                request_body TEXT NOT NULL DEFAULT '',
                verify_tls INTEGER,
                format_metric_units INTEGER,
                skip_check INTEGER,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notification_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notification_group_notifications (
                notification_group_id INTEGER NOT NULL,
                notification_id INTEGER NOT NULL,
                PRIMARY KEY (notification_group_id, notification_id)
            );

            CREATE TABLE IF NOT EXISTS alert_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                enable INTEGER,
                trigger_mode INTEGER NOT NULL DEFAULT 0,
                notification_group_id INTEGER NOT NULL DEFAULT 0,
                rules_json TEXT NOT NULL DEFAULT '[]',
                fail_trigger_tasks_json TEXT NOT NULL DEFAULT '[]',
                recover_trigger_tasks_json TEXT NOT NULL DEFAULT '[]',
                muted_until_unix INTEGER NOT NULL DEFAULT 0,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ddns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL,
                provider TEXT NOT NULL,
                domains_json TEXT NOT NULL DEFAULT '[]',
                body_json TEXT NOT NULL DEFAULT '{}',
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS nat (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                name TEXT NOT NULL,
                server_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                domain TEXT NOT NULL UNIQUE,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS service_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id INTEGER NOT NULL,
                server_id INTEGER NOT NULL,
                avg_delay REAL NOT NULL DEFAULT 0,
                up INTEGER NOT NULL DEFAULT 0,
                down INTEGER NOT NULL DEFAULT 0,
                data TEXT NOT NULL DEFAULT '',
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS server_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                metric TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                value REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_server_metrics_lookup
                ON server_metrics (server_id, metric, timestamp_ms);

            CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                in_bytes INTEGER NOT NULL DEFAULT 0,
                out_bytes INTEGER NOT NULL DEFAULT 0,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_transfers_server_hour
                ON transfers (server_id, created_at_unix);

            CREATE TABLE IF NOT EXISTS waf (
                ip BLOB NOT NULL,
                block_identifier INTEGER NOT NULL,
                block_reason INTEGER NOT NULL,
                block_timestamp INTEGER NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (ip, block_identifier)
            );

            CREATE TABLE IF NOT EXISTS pending_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                task_id INTEGER NOT NULL DEFAULT 0,
                task_type INTEGER NOT NULL,
                data TEXT NOT NULL DEFAULT '',
                created_at_unix INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pending_tasks_server
                ON pending_tasks (server_id, id);

            CREATE TABLE IF NOT EXISTS notification_dead_letter (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                notification_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                error TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at_unix INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_notification_dead_letter_created
                ON notification_dead_letter (created_at_unix);
            ",
        )?;
        self.run_versioned_migrations()?;
        Ok(())
    }

    fn current_schema_version(&self) -> Result<u32> {
        let v: Option<i64> = self
            .conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .optional()?
            .flatten();
        Ok(v.unwrap_or(0).max(0) as u32)
    }

    fn record_schema_version(&self, version: u32) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO schema_version (version, applied_at_unix) VALUES (?1, ?2)",
            params![version as i64, unix_now() as i64],
        )?;
        Ok(())
    }

    fn run_versioned_migrations(&self) -> Result<()> {
        type MigrationFn = fn(&Store) -> Result<()>;
        const MIGRATIONS: &[(u32, MigrationFn)] = &[
            (1, |s| {
                s.add_column_if_missing("servers", "user_id", "INTEGER NOT NULL DEFAULT 0")?;
                s.add_column_if_missing(
                    "servers",
                    "prev_transfer_in_snapshot",
                    "INTEGER NOT NULL DEFAULT 0",
                )?;
                s.add_column_if_missing(
                    "servers",
                    "prev_transfer_out_snapshot",
                    "INTEGER NOT NULL DEFAULT 0",
                )?;
                Ok(())
            }),
            (2, |s| {
                s.add_column_if_missing(
                    "services",
                    "enable_trigger_task",
                    "INTEGER NOT NULL DEFAULT 0",
                )?;
                s.add_column_if_missing(
                    "services",
                    "enable_show_in_service",
                    "INTEGER NOT NULL DEFAULT 0",
                )?;
                s.add_column_if_missing(
                    "services",
                    "fail_trigger_tasks_json",
                    "TEXT NOT NULL DEFAULT '[]'",
                )?;
                s.add_column_if_missing(
                    "services",
                    "recover_trigger_tasks_json",
                    "TEXT NOT NULL DEFAULT '[]'",
                )?;
                s.add_column_if_missing("services", "min_latency", "REAL NOT NULL DEFAULT 0")?;
                s.add_column_if_missing("services", "max_latency", "REAL NOT NULL DEFAULT 0")?;
                s.add_column_if_missing(
                    "services",
                    "latency_notify",
                    "INTEGER NOT NULL DEFAULT 0",
                )?;
                Ok(())
            }),
            (3, |s| {
                s.add_column_if_missing(
                    "alert_rules",
                    "muted_until_unix",
                    "INTEGER NOT NULL DEFAULT 0",
                )?;
                Ok(())
            }),
            (4, |s| {
                s.conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS notification_dead_letter (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        notification_id INTEGER NOT NULL,
                        message TEXT NOT NULL,
                        error TEXT NOT NULL,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        created_at_unix INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_notification_dead_letter_created
                        ON notification_dead_letter (created_at_unix);",
                )?;
                Ok(())
            }),
            (5, |s| {
                s.add_column_if_missing("notifications", "skip_check", "INTEGER")?;
                Ok(())
            }),
        ];

        let current = self.current_schema_version()?;
        for (version, migrator) in MIGRATIONS {
            if *version > current {
                migrator(self)?;
                self.record_schema_version(*version)?;
            }
        }
        Ok(())
    }

    fn add_column_if_missing(&self, table: &str, column: &str, definition: &str) -> Result<()> {
        let mut stmt = self.conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if !columns.iter().any(|name| name == column) {
            self.conn.execute(
                &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
        Ok(())
    }

    fn server_by_uuid(&self, uuid: Uuid) -> Result<Option<StoredServer>> {
        self.conn
            .query_row(
                "SELECT id, user_id, host_json, state_json, geoip_json, last_active_unix
                 FROM servers WHERE uuid = ?1",
                params![uuid.to_string()],
                |row| {
                    let id: i64 = row.get(0)?;
                    let user_id: i64 = row.get(1)?;
                    let host_json: Option<String> = row.get(2)?;
                    let state_json: Option<String> = row.get(3)?;
                    let geoip_json: Option<String> = row.get(4)?;
                    let last_active_unix: i64 = row.get(5)?;

                    Ok(StoredServer {
                        id: id.max(0) as u64,
                        user_id: user_id.max(0) as u64,
                        host: host_json
                            .as_deref()
                            .and_then(|raw| serde_json::from_str::<CoreHost>(raw).ok())
                            .map(Into::into),
                        state: state_json
                            .as_deref()
                            .and_then(|raw| serde_json::from_str::<CoreHostState>(raw).ok())
                            .map(Into::into),
                        geoip: geoip_json
                            .as_deref()
                            .and_then(|raw| serde_json::from_str::<CoreGeoIp>(raw).ok())
                            .map(Into::into),
                        last_active_unix: last_active_unix.max(0) as u64,
                    })
                },
            )
            .optional()
            .context("failed to load server by uuid")
    }

    fn get_named(&self, table: NamedTable, id: u64) -> Result<NamedResource> {
        let sql = format!(
            "SELECT id, name, user_id, created_at_unix, updated_at_unix FROM {} WHERE id = ?1",
            table.as_str()
        );
        self.conn
            .query_row(&sql, params![id as i64], |row| {
                Ok(NamedResource {
                    id: i64_to_u64(row.get(0)?),
                    name: row.get(1)?,
                    user_id: i64_to_u64(row.get(2)?),
                    created_at: i64_to_u64(row.get(3)?),
                    updated_at: i64_to_u64(row.get(4)?),
                })
            })
            .context("resource not found")
    }

    fn get_notification(&self, id: u64) -> Result<NotificationResource> {
        self.conn
            .query_row(
                "SELECT id, user_id, name, url, request_method, request_type, request_header,
                        request_body, verify_tls, format_metric_units, skip_check,
                        created_at_unix, updated_at_unix
                 FROM notifications WHERE id = ?1",
                params![id as i64],
                notification_from_row,
            )
            .context("notification not found")
    }

    fn notification_ids_for_group(&self, group_id: u64) -> Result<Vec<u64>> {
        let mut stmt = self.conn.prepare(
            "SELECT notification_id FROM notification_group_notifications
             WHERE notification_group_id = ?1 ORDER BY notification_id ASC",
        )?;
        let ids = stmt
            .query_map(params![group_id as i64], |row| row.get::<_, i64>(0))?
            .map(|row| row.map(i64_to_u64))
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ids)
    }

    fn server_ids_for_group(&self, group_id: u64) -> Result<Vec<u64>> {
        let mut stmt = self.conn.prepare(
            "SELECT server_id FROM server_group_servers
             WHERE server_group_id = ?1 ORDER BY server_id ASC",
        )?;
        let ids = stmt
            .query_map(params![group_id as i64], |row| row.get::<_, i64>(0))?
            .map(|row| row.map(i64_to_u64))
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(ids)
    }

    fn ensure_notifications_exist(&self, ids: &[u64]) -> Result<()> {
        let unique = unique_u64s(ids);
        for id in unique {
            self.get_notification(id)?;
        }
        Ok(())
    }

    fn ensure_servers_exist(&self, ids: &[u64]) -> Result<()> {
        let unique = unique_u64s(ids);
        for id in unique {
            self.get_public_server(id)?;
        }
        Ok(())
    }

    pub fn get_cron(&self, id: u64) -> Result<CronResource> {
        self.conn
            .query_row(
                "SELECT id, user_id, name, task_type, scheduler, command, servers_json,
                        push_successful, notification_group_id, last_executed_at_unix,
                        last_result, cover, created_at_unix, updated_at_unix
                 FROM crons WHERE id = ?1",
                params![id as i64],
                cron_from_row,
            )
            .context("cron not found")
    }

    fn get_nat(&self, id: u64) -> Result<NatResource> {
        self.conn
            .query_row(
                "SELECT id, user_id, enabled, name, server_id, host, domain, created_at_unix, updated_at_unix
                 FROM nat WHERE id = ?1",
                params![id as i64],
                nat_from_row,
            )
            .context("nat not found")
    }

    fn get_public_server(&self, id: u64) -> Result<PublicServer> {
        self.conn
            .query_row(
                "SELECT id, user_id, uuid, name, note, public_note, display_index, hide_for_guest, enable_ddns,
                        ddns_profiles_json, override_ddns_domains_json,
                        host_json, state_json, geoip_json, last_active_unix,
                        prev_transfer_in_snapshot, prev_transfer_out_snapshot
                 FROM servers WHERE id = ?1",
                params![id as i64],
                public_server_from_row,
            )
            .context("server not found")
    }

    fn can_report_service_result(
        &self,
        service: &ServiceResource,
        server: &PublicServer,
        task_type: u64,
    ) -> Result<bool> {
        if service.r#type as u64 != task_type || !service_covers_server(service, server.id) {
            return Ok(false);
        }
        Ok(service.user_id == server.user_id || self.user_is_admin(service.user_id)?)
    }

    fn can_report_cron_result(
        &self,
        cron: &CronResource,
        server: &PublicServer,
        alert_trigger_authorized: bool,
    ) -> Result<bool> {
        if !(cron.user_id == server.user_id || self.user_is_admin(cron.user_id)?) {
            return Ok(false);
        }
        Ok(match cron.cover {
            CRON_COVER_ALL => !cron.servers.contains(&server.id),
            CRON_COVER_IGNORE_ALL => cron.servers.contains(&server.id),
            CRON_COVER_ALERT_TRIGGER => alert_trigger_authorized,
            _ => false,
        })
    }

    pub fn service_targets(&self, service: &ServiceResource) -> Result<Vec<u64>> {
        let servers = self.list_servers()?;
        servers
            .into_iter()
            .filter(|server| service_covers_server(service, server.id))
            .filter(|server| {
                service.user_id == server.user_id
                    || self.user_is_admin(service.user_id).unwrap_or(false)
            })
            .map(|server| Ok(server.id))
            .collect()
    }

    pub(crate) fn user_is_admin(&self, user_id: u64) -> Result<bool> {
        if user_id == 0 {
            return Ok(true);
        }
        let role = self
            .conn
            .query_row(
                "SELECT role FROM users WHERE id = ?1",
                params![user_id as i64],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        Ok(role.is_some_and(|role| role == 0))
    }

    pub(crate) fn get_service(&self, id: u64) -> Result<ServiceResource> {
        self.conn
            .query_row(
                "SELECT id, user_id, name, type, target, duration, display_index, notify,
                        notification_group_id, cover, skip_servers_json, trigger_tasks_json,
                        enable_trigger_task, enable_show_in_service, fail_trigger_tasks_json,
                        recover_trigger_tasks_json, min_latency, max_latency, latency_notify,
                        created_at_unix, updated_at_unix
                 FROM services WHERE id = ?1",
                params![id as i64],
                service_from_row,
            )
            .context("service not found")
    }

    fn get_ddns(&self, id: u64) -> Result<DdnsResource> {
        self.conn
            .query_row(
                "SELECT id, user_id, name, provider, domains_json, body_json, created_at_unix, updated_at_unix
                 FROM ddns WHERE id = ?1",
                params![id as i64],
                ddns_from_row,
            )
            .context("ddns profile not found")
    }

    fn get_alert_rule(&self, id: u64) -> Result<AlertRuleResource> {
        self.conn
            .query_row(
                "SELECT id, user_id, name, enable, trigger_mode, notification_group_id, rules_json,
                        fail_trigger_tasks_json, recover_trigger_tasks_json, muted_until_unix,
                        created_at_unix, updated_at_unix
                 FROM alert_rules WHERE id = ?1",
                params![id as i64],
                alert_rule_from_row,
            )
            .context("alert rule not found")
    }

    fn delete_by_ids(&self, table: &str, ids: &[u64]) -> Result<usize> {
        let sql = format!("DELETE FROM {table} WHERE id = ?1");
        let mut deleted = 0;
        for id in ids {
            deleted += self.conn.execute(&sql, params![*id as i64])?;
        }
        Ok(deleted)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum NamedTable {
    ServerGroups,
    NotificationGroups,
}

impl NamedTable {
    fn as_str(self) -> &'static str {
        match self {
            Self::ServerGroups => "server_groups",
            Self::NotificationGroups => "notification_groups",
        }
    }
}

fn user_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserResource> {
    Ok(UserResource {
        id: i64_to_u64(row.get(0)?),
        username: row.get(1)?,
        role: i64_to_u64(row.get(2)?) as u8,
        agent_secret: row.get(3)?,
        reject_password: row.get::<_, i64>(4)? != 0,
        created_at: i64_to_u64(row.get(5)?),
        updated_at: i64_to_u64(row.get(6)?),
    })
}

fn public_server_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PublicServer> {
    let ddns_profiles_json: String = row.get(9)?;
    let override_ddns_domains_json: String = row.get(10)?;
    let host_json: Option<String> = row.get(11)?;
    let state_json: Option<String> = row.get(12)?;
    let geoip_json: Option<String> = row.get(13)?;
    let id: i64 = row.get(0)?;
    let user_id: i64 = row.get(1)?;
    let display_index: i64 = row.get(6)?;
    let last_active: i64 = row.get(14)?;
    let prev_transfer_in_snapshot: i64 = row.get(15)?;
    let prev_transfer_out_snapshot: i64 = row.get(16)?;
    Ok(PublicServer {
        id: id.max(0) as u64,
        user_id: user_id.max(0) as u64,
        uuid: row.get(2)?,
        name: row.get(3)?,
        note: row.get(4)?,
        public_note: row.get(5)?,
        display_index: display_index as i32,
        hide_for_guest: row.get::<_, i64>(7)? != 0,
        enable_ddns: row.get::<_, i64>(8)? != 0,
        ddns_profiles: serde_json::from_str(&ddns_profiles_json).unwrap_or_default(),
        override_ddns_domains: serde_json::from_str(&override_ddns_domains_json)
            .unwrap_or_default(),
        host: host_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<CoreHost>(raw).ok()),
        state: state_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<CoreHostState>(raw).ok()),
        geoip: geoip_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<CoreGeoIp>(raw).ok()),
        last_active: last_active.max(0) as u64,
        prev_transfer_in_snapshot: prev_transfer_in_snapshot.max(0) as u64,
        prev_transfer_out_snapshot: prev_transfer_out_snapshot.max(0) as u64,
    })
}

#[allow(dead_code)]
fn transfer_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TransferResource> {
    Ok(TransferResource {
        id: i64_to_u64(row.get(0)?),
        server_id: i64_to_u64(row.get(1)?),
        in_bytes: i64_to_u64(row.get(2)?),
        out_bytes: i64_to_u64(row.get(3)?),
        created_at: i64_to_u64(row.get(4)?),
        updated_at: i64_to_u64(row.get(5)?),
    })
}

fn notification_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NotificationResource> {
    Ok(NotificationResource {
        id: i64_to_u64(row.get(0)?),
        user_id: i64_to_u64(row.get(1)?),
        name: row.get(2)?,
        url: row.get(3)?,
        request_method: i64_to_u64(row.get(4)?) as u8,
        request_type: i64_to_u64(row.get(5)?) as u8,
        request_header: row.get(6)?,
        request_body: row.get(7)?,
        verify_tls: opt_i64_to_bool(row.get(8)?),
        format_metric_units: opt_i64_to_bool(row.get(9)?),
        skip_check: opt_i64_to_bool(row.get(10)?),
        created_at: i64_to_u64(row.get(11)?),
        updated_at: i64_to_u64(row.get(12)?),
    })
}

fn cron_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CronResource> {
    let servers_json: String = row.get(6)?;
    Ok(CronResource {
        id: i64_to_u64(row.get(0)?),
        user_id: i64_to_u64(row.get(1)?),
        name: row.get(2)?,
        task_type: i64_to_u64(row.get(3)?) as u8,
        scheduler: row.get(4)?,
        command: row.get(5)?,
        servers: serde_json::from_str(&servers_json).unwrap_or_default(),
        push_successful: row.get::<_, i64>(7)? != 0,
        notification_group_id: i64_to_u64(row.get(8)?),
        last_executed_at: row.get::<_, Option<i64>>(9)?.map(i64_to_u64),
        last_result: row.get::<_, i64>(10)? != 0,
        cover: i64_to_u64(row.get(11)?) as u8,
        created_at: i64_to_u64(row.get(12)?),
        updated_at: i64_to_u64(row.get(13)?),
    })
}

fn service_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ServiceResource> {
    let skip_servers_json: String = row.get(10)?;
    let trigger_tasks_json: String = row.get(11)?;
    let fail_trigger_tasks_json: String = row.get(14)?;
    let recover_trigger_tasks_json: String = row.get(15)?;
    Ok(ServiceResource {
        id: i64_to_u64(row.get(0)?),
        user_id: i64_to_u64(row.get(1)?),
        name: row.get(2)?,
        r#type: i64_to_u64(row.get(3)?) as u8,
        target: row.get(4)?,
        duration: i64_to_u64(row.get(5)?),
        display_index: row.get::<_, i64>(6)? as i32,
        notify: row.get::<_, i64>(7)? != 0,
        notification_group_id: i64_to_u64(row.get(8)?),
        cover: i64_to_u64(row.get(9)?) as u8,
        enable_trigger_task: row.get::<_, i64>(12)? != 0,
        enable_show_in_service: row.get::<_, i64>(13)? != 0,
        fail_trigger_tasks: serde_json::from_str(&fail_trigger_tasks_json).unwrap_or_default(),
        recover_trigger_tasks: serde_json::from_str(&recover_trigger_tasks_json)
            .unwrap_or_default(),
        min_latency: row.get::<_, f64>(16)?,
        max_latency: row.get::<_, f64>(17)?,
        latency_notify: row.get::<_, i64>(18)? != 0,
        skip_servers: serde_json::from_str(&skip_servers_json).unwrap_or_default(),
        trigger_tasks: serde_json::from_str(&trigger_tasks_json).unwrap_or_default(),
        created_at: i64_to_u64(row.get(19)?),
        updated_at: i64_to_u64(row.get(20)?),
    })
}

fn ddns_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DdnsResource> {
    let domains_json: String = row.get(4)?;
    let body_json: String = row.get(5)?;
    Ok(DdnsResource {
        id: i64_to_u64(row.get(0)?),
        user_id: i64_to_u64(row.get(1)?),
        name: row.get(2)?,
        provider: row.get(3)?,
        domains: serde_json::from_str(&domains_json).unwrap_or_default(),
        body: serde_json::from_str(&body_json)
            .unwrap_or_else(|_| Value::Object(Default::default())),
        created_at: i64_to_u64(row.get(6)?),
        updated_at: i64_to_u64(row.get(7)?),
    })
}

fn alert_rule_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertRuleResource> {
    let rules_json: String = row.get(6)?;
    let fail_trigger_tasks_json: String = row.get(7)?;
    let recover_trigger_tasks_json: String = row.get(8)?;
    Ok(AlertRuleResource {
        id: i64_to_u64(row.get(0)?),
        user_id: i64_to_u64(row.get(1)?),
        name: row.get(2)?,
        enable: opt_i64_to_bool(row.get(3)?),
        trigger_mode: i64_to_u64(row.get(4)?) as u8,
        notification_group_id: i64_to_u64(row.get(5)?),
        rules: serde_json::from_str(&rules_json).unwrap_or_default(),
        fail_trigger_tasks: serde_json::from_str(&fail_trigger_tasks_json).unwrap_or_default(),
        recover_trigger_tasks: serde_json::from_str(&recover_trigger_tasks_json)
            .unwrap_or_default(),
        muted_until: i64_to_u64(row.get(9)?),
        created_at: i64_to_u64(row.get(10)?),
        updated_at: i64_to_u64(row.get(11)?),
    })
}

fn nat_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NatResource> {
    Ok(NatResource {
        id: i64_to_u64(row.get(0)?),
        user_id: i64_to_u64(row.get(1)?),
        enabled: row.get::<_, i64>(2)? != 0,
        name: row.get(3)?,
        server_id: i64_to_u64(row.get(4)?),
        host: row.get(5)?,
        domain: row.get(6)?,
        created_at: i64_to_u64(row.get(7)?),
        updated_at: i64_to_u64(row.get(8)?),
    })
}

fn waf_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WafResource> {
    let ip: Vec<u8> = row.get(0)?;
    Ok(WafResource {
        ip: binary_to_ip_string(&ip),
        block_identifier: row.get(1)?,
        block_reason: i64_to_u64(row.get(2)?) as u8,
        block_timestamp: i64_to_u64(row.get(3)?),
        count: i64_to_u64(row.get(4)?),
    })
}

fn i64_to_u64(value: i64) -> u64 {
    value.max(0) as u64
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn opt_i64_to_bool(value: Option<i64>) -> Option<bool> {
    value.map(|v| v != 0)
}

fn string_field(body: &Value, key: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn u64_field(body: &Value, key: &str) -> u64 {
    body.get(key).and_then(Value::as_u64).unwrap_or_default()
}

#[cfg(test)]
fn numeric_u64(body: &Value, key: &str) -> u64 {
    body.get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_f64().map(|value| value as u64))
        })
        .unwrap_or_default()
}

fn i64_field(body: &Value, key: &str) -> i64 {
    body.get(key)
        .and_then(Value::as_i64)
        .or_else(|| body.get(key).and_then(Value::as_u64).map(|v| v as i64))
        .unwrap_or_default()
}

fn u8_field(body: &Value, key: &str) -> u8 {
    u64_field(body, key) as u8
}

fn bool_i64(body: &Value, key: &str) -> i64 {
    if body.get(key).and_then(Value::as_bool).unwrap_or(false) {
        1
    } else {
        0
    }
}

fn opt_bool_i64(body: &Value, key: &str) -> Option<i64> {
    body.get(key)
        .and_then(Value::as_bool)
        .map(|v| if v { 1 } else { 0 })
}

fn u64_list_field(body: &Value, key: &str) -> Vec<u64> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default()
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

fn string_list_field(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn value_array_field(body: &Value, key: &str) -> Vec<Value> {
    body.get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

#[cfg(test)]
fn rule_type(rule: &Value) -> Option<&str> {
    rule.get("type").and_then(Value::as_str)
}

#[cfg(test)]
fn rule_excludes_server(rule: &Value, server_id: u64) -> bool {
    let cover = rule
        .get("cover")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let ignored = rule
        .get("ignore")
        .and_then(Value::as_object)
        .and_then(|items| items.get(&server_id.to_string()))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match cover {
        0 => ignored,
        1 => !ignored,
        _ => false,
    }
}

#[cfg(test)]
fn is_transfer_cycle_rule(rule_type: &str) -> bool {
    rule_type.ends_with("_cycle")
}

#[cfg(test)]
fn transfer_cycle_rule_value(rule: &Value, server: &PublicServer, store: &Store) -> Option<u64> {
    let state = server.state.as_ref()?;
    let current_in = state
        .net_in_transfer
        .saturating_sub(server.prev_transfer_in_snapshot);
    let current_out = state
        .net_out_transfer
        .saturating_sub(server.prev_transfer_out_snapshot);
    let interval = rule
        .get("cycle_interval")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let (stored_in, stored_out) = if interval == 0 {
        (0, 0)
    } else {
        let since = transfer_cycle_start(rule, unix_now())?.timestamp().max(0) as u64;
        store.transfer_totals_since(server.id, since).ok()?
    };
    let value = match rule_type(rule)? {
        "transfer_in_cycle" => stored_in.saturating_add(current_in),
        "transfer_out_cycle" => stored_out.saturating_add(current_out),
        "transfer_all_cycle" => stored_in
            .saturating_add(stored_out)
            .saturating_add(current_in)
            .saturating_add(current_out),
        _ => return None,
    };
    Some(value)
}

#[cfg(test)]
fn cycle_transfer_next_update(rule: &Value, value: u64, now_unix: u64) -> DateTime<Utc> {
    let max = rule.get("max").and_then(Value::as_f64).unwrap_or_default();
    let seconds = if max > 0.0 {
        (1800.0 * ((max - value as f64) / max)).max(180.0)
    } else {
        180.0
    };
    let now = Utc
        .timestamp_opt(now_unix as i64, 0)
        .single()
        .unwrap_or_else(Utc::now);
    now.checked_add_signed(ChronoDuration::seconds(seconds as i64))
        .unwrap_or(now)
}

#[cfg(test)]
fn transfer_cycle_start(rule: &Value, now_unix: u64) -> Option<DateTime<Utc>> {
    let start = rule.get("cycle_start").and_then(parse_cycle_start)?;
    let interval = rule.get("cycle_interval").and_then(Value::as_u64)?;
    if interval == 0 {
        return Some(start);
    }
    let unit = rule
        .get("cycle_unit")
        .and_then(Value::as_str)
        .unwrap_or("hour")
        .to_ascii_lowercase();
    let now = Utc.timestamp_opt(now_unix as i64, 0).single()?;
    let mut current = start;
    let mut next = add_cycle_interval(current, &unit, interval)?;
    while now > next {
        current = next;
        next = add_cycle_interval(current, &unit, interval)?;
    }
    Some(current)
}

#[cfg(test)]
fn transfer_cycle_end(rule: &Value, now_unix: u64) -> Option<DateTime<Utc>> {
    let start = transfer_cycle_start(rule, now_unix)?;
    let interval = rule.get("cycle_interval").and_then(Value::as_u64)?;
    let unit = rule
        .get("cycle_unit")
        .and_then(Value::as_str)
        .unwrap_or("hour")
        .to_ascii_lowercase();
    if interval == 0 {
        return Some(start);
    }
    add_cycle_interval(start, &unit, interval)
}

#[cfg(test)]
fn parse_cycle_start(value: &Value) -> Option<DateTime<Utc>> {
    if let Some(raw) = value.as_str() {
        return DateTime::parse_from_rfc3339(raw)
            .ok()
            .map(|time| time.with_timezone(&Utc));
    }
    if let Some(unix) = value.as_i64() {
        return Utc.timestamp_opt(unix, 0).single();
    }
    value
        .as_u64()
        .and_then(|unix| Utc.timestamp_opt(unix as i64, 0).single())
}

#[cfg(test)]
fn add_cycle_interval(time: DateTime<Utc>, unit: &str, interval: u64) -> Option<DateTime<Utc>> {
    match unit {
        "year" => time.checked_add_months(Months::new((interval * 12).try_into().ok()?)),
        "month" => time.checked_add_months(Months::new(interval.try_into().ok()?)),
        "week" => time.checked_add_signed(ChronoDuration::weeks(interval.try_into().ok()?)),
        "day" => time.checked_add_signed(ChronoDuration::days(interval.try_into().ok()?)),
        _ => time.checked_add_signed(ChronoDuration::seconds(
            interval.checked_mul(3600)?.try_into().ok()?,
        )),
    }
}

fn service_covers_server(service: &ServiceResource, server_id: u64) -> bool {
    let selected = service
        .skip_servers
        .get(&server_id.to_string())
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match service.cover {
        SERVICE_COVER_ALL => !selected,
        SERVICE_COVER_IGNORE_ALL => selected,
        _ => false,
    }
}

fn pet_name(uuid: Uuid) -> String {
    let raw = uuid.simple().to_string();
    format!("server-{}", &raw[..8])
}

fn ip_string_to_binary(ip: &str) -> Option<Vec<u8>> {
    match ip.trim().parse::<IpAddr>().ok()? {
        IpAddr::V4(addr) => Some(addr.to_ipv6_mapped().octets().to_vec()),
        IpAddr::V6(addr) => Some(addr.octets().to_vec()),
    }
}

fn binary_to_ip_string(binary: &[u8]) -> String {
    let Ok(bytes) = <[u8; 16]>::try_from(binary) else {
        return "::".to_string();
    };
    let addr = std::net::Ipv6Addr::from(bytes);
    addr.to_ipv4_mapped()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| addr.to_string())
}

fn waf_block_until(count: u64, block_timestamp: u64) -> u64 {
    let backoff = (count as u128).saturating_pow(4);
    let until = (block_timestamp as u128).saturating_add(backoff);
    let min_until = block_timestamp.saturating_add(3) as u128;
    until.max(min_until).min(u64::MAX as u128) as u64
}

fn generate_secret() -> String {
    Uuid::new_v4().simple().to_string()
}

fn is_known_server_metric(metric: &str) -> bool {
    matches!(
        metric,
        "cpu"
            | "memory"
            | "swap"
            | "disk"
            | "net_in_speed"
            | "net_out_speed"
            | "net_in_transfer"
            | "net_out_transfer"
            | "load1"
            | "load5"
            | "load15"
            | "tcp_conn"
            | "udp_conn"
            | "process_count"
            | "temperature"
            | "uptime"
            | "gpu"
    )
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use nezha_core::TaskType;

    #[test]
    fn ensure_server_is_idempotent() {
        let store = Store::open(":memory:").unwrap();
        let uuid = Uuid::new_v4();

        let first = store.ensure_server_for_user(uuid, 0).unwrap();
        let second = store.ensure_server_for_user(uuid, 0).unwrap();

        assert_eq!(first.id, second.id);
    }

    #[test]
    fn agent_secret_owner_controls_uuid_registration_and_updates() {
        let store = Store::open(":memory:").unwrap();
        store.ensure_admin("admin", "secret").unwrap();
        let alice_id = store.create_user("alice", "secret1", 1).unwrap();
        let bob_id = store.create_user("bob", "secret2", 1).unwrap();
        let alice = store.get_user(alice_id).unwrap();

        assert_eq!(
            store.agent_secret_owner("global", "global").unwrap(),
            Some(0)
        );
        assert_eq!(
            store
                .agent_secret_owner(&alice.agent_secret, "global")
                .unwrap(),
            Some(alice_id)
        );
        assert_eq!(store.agent_secret_owner("bad", "global").unwrap(), None);

        let uuid = Uuid::new_v4();
        let server = store.ensure_server_for_user(uuid, alice_id).unwrap();
        assert_eq!(server.user_id, alice_id);

        let err = store.ensure_server_for_user(uuid, bob_id).unwrap_err();
        assert!(
            err.to_string()
                .contains("client UUID does not belong to the agent secret owner")
        );

        let err = store
            .update_state_for_user(uuid, bob_id, State::default())
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("client UUID does not belong to the agent secret owner")
        );

        assert!(
            store
                .update_state_for_user(uuid, 0, State::default())
                .is_ok()
        );
    }

    #[test]
    fn bootstrap_admin_can_login() {
        let store = Store::open(":memory:").unwrap();
        store.ensure_admin("admin", "secret").unwrap();

        let user = store.authenticate_user("admin", "secret").unwrap().unwrap();
        assert_eq!(user.username, "admin");
        assert_eq!(user.role, 0);
        assert!(store.authenticate_user("admin", "bad").unwrap().is_none());
    }

    #[test]
    fn bootstrap_admin_does_not_overwrite_existing_password() {
        let store = Store::open(":memory:").unwrap();
        store.ensure_admin("admin", "secret").unwrap();
        store.ensure_admin("admin", "changed").unwrap();

        assert!(
            store
                .authenticate_user("admin", "secret")
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .authenticate_user("admin", "changed")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn reset_admin_password_updates_existing_admin() {
        let store = Store::open(":memory:").unwrap();
        store.ensure_admin("admin", "secret").unwrap();
        store.reset_admin_password("admin", "changed").unwrap();

        assert!(
            store
                .authenticate_user("admin", "secret")
                .unwrap()
                .is_none()
        );
        let user = store
            .authenticate_user("admin", "changed")
            .unwrap()
            .unwrap();
        assert_eq!(user.username, "admin");
        assert_eq!(user.role, 0);
    }

    #[test]
    fn dashboard_settings_persist_as_singleton_resource() {
        let store = Store::open(":memory:").unwrap();
        assert!(store.dashboard_settings().unwrap().is_none());

        let settings = DashboardSettings {
            language: "zh_CN".to_string(),
            site_name: "Nezha RS".to_string(),
            install_host: "https://example.com".to_string(),
            tls: true,
            oauth2: HashMap::from([(
                "github".to_string(),
                OAuth2Config {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    endpoint: OAuth2Endpoint {
                        auth_url: "https://github.com/login/oauth/authorize".into(),
                        token_url: "https://github.com/login/oauth/access_token".into(),
                    },
                    scopes: vec!["user:email".into()],
                    user_info_url: "https://api.github.com/user".into(),
                    user_id_path: "id".into(),
                },
            )]),
            ..DashboardSettings::default()
        };
        store.save_dashboard_settings(&settings).unwrap();

        assert_eq!(store.dashboard_settings().unwrap(), Some(settings));
    }

    #[test]
    fn oauth2_bindings_drive_profile_and_unbind_guard() {
        let store = Store::open(":memory:").unwrap();
        let user_id = store.create_user("alice", "password", 1).unwrap();

        store.bind_oauth2(user_id, "GitHub", "open-1").unwrap();

        assert_eq!(
            store
                .user_by_oauth2("github", "open-1")
                .unwrap()
                .unwrap()
                .id,
            user_id
        );
        assert_eq!(
            store.oauth2_binds_for_user(user_id).unwrap().get("github"),
            Some(&"open-1".to_string())
        );

        store
            .update_profile(user_id, "password", "alice", "password2", true)
            .unwrap();
        assert!(store.unbind_oauth2(user_id, "github").is_err());

        store.bind_oauth2(user_id, "gitlab", "open-2").unwrap();
        store.unbind_oauth2(user_id, "github").unwrap();
        assert_eq!(store.oauth2_bind_count(user_id).unwrap(), 1);
    }

    #[test]
    fn dashboard_crud_resources_roundtrip() {
        let store = Store::open(":memory:").unwrap();

        let notification = store
            .upsert_notification(
                None,
                1,
                &serde_json::json!({
                    "name": "webhook",
                    "url": "https://example.com/?text=#NEZHA#",
                    "request_method": 1,
                    "request_type": 1,
                    "verify_tls": true
                }),
            )
            .unwrap();
        let group = store
            .upsert_notification_group(None, 1, "default", &[notification.id, notification.id])
            .unwrap();
        assert_eq!(group.notifications, vec![notification.id]);
        assert_eq!(
            store
                .notifications_for_group(group.group.id)
                .unwrap()
                .first()
                .unwrap()
                .id,
            notification.id
        );

        let service = store
            .upsert_service(
                None,
                1,
                &serde_json::json!({
                    "name": "homepage",
                    "type": 1,
                    "target": " https://example.com ",
                    "duration": 30,
                    "display_index": 2,
                    "notify": true,
                    "notification_group_id": 0,
                    "cover": 0,
                    "skip_servers": { "1": true }
                }),
            )
            .unwrap();
        assert_eq!(service.target, "https://example.com");
        assert_eq!(store.list_services().unwrap().len(), 1);

        let ddns = store
            .upsert_ddns(
                None,
                1,
                &serde_json::json!({
                    "name": "dns",
                    "provider": "dummy",
                    "domains": ["example.com"],
                    "max_retries": 1
                }),
            )
            .unwrap();
        assert_eq!(ddns.domains, vec!["example.com"]);

        let alert = store
            .upsert_alert_rule(
                None,
                1,
                &serde_json::json!({
                    "name": "cpu",
                    "enable": true,
                    "trigger_mode": 0,
                    "rules": [{ "type": "cpu", "max": 90 }],
                    "fail_trigger_tasks": [service.id],
                    "recover_trigger_tasks": []
                }),
            )
            .unwrap();
        assert_eq!(alert.enable, Some(true));

        assert_eq!(store.delete_services(&[service.id]).unwrap(), 1);
        assert_eq!(store.delete_ddns(&[ddns.id]).unwrap(), 1);
        assert_eq!(store.delete_alert_rules(&[alert.id]).unwrap(), 1);
    }

    #[test]
    fn move_servers_updates_owner() {
        let store = Store::open(":memory:").unwrap();
        let uuid = Uuid::new_v4();
        let server = store.ensure_server_for_user(uuid, 0).unwrap();

        assert_eq!(store.move_servers(&[server.id], 99).unwrap(), 1);

        let owner: i64 = store
            .conn
            .query_row(
                "SELECT user_id FROM servers WHERE id = ?1",
                params![server.id as i64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(owner, 99);
    }

    #[test]
    fn waf_records_page_and_delete_by_ip() {
        let store = Store::open(":memory:").unwrap();

        store.record_waf_block("203.0.113.10", 1, -126).unwrap();
        store.record_waf_block("203.0.113.10", 1, -126).unwrap();
        store.record_waf_block("2001:db8::1", 4, -124).unwrap();
        assert!(store.waf_block_active("203.0.113.10").unwrap());
        assert!(store.waf_block_active("2001:db8::1").unwrap());

        let (page, total) = store.list_waf(25, 0).unwrap();
        assert_eq!(total, 2);
        assert_eq!(page.len(), 2);
        assert!(page.iter().any(|item| {
            item.ip == "203.0.113.10" && item.block_identifier == -126 && item.count == 2
        }));
        assert!(page.iter().any(|item| {
            item.ip == "2001:db8::1" && item.block_identifier == -124 && item.count == 99_999
        }));

        assert_eq!(
            store
                .delete_waf_ips(&[
                    "203.0.113.10".to_string(),
                    "203.0.113.10".to_string(),
                    "not an ip".to_string(),
                ])
                .unwrap(),
            1
        );
        assert!(!store.waf_block_active("203.0.113.10").unwrap());

        let (page, total) = store.list_waf(25, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(page[0].ip, "2001:db8::1");

        assert_eq!(
            store.delete_waf_ip_identifier("2001:db8::1", -124).unwrap(),
            1
        );
        assert!(!store.waf_block_active("2001:db8::1").unwrap());
    }

    #[test]
    fn maintenance_runs_sqlite_housekeeping() {
        let store = Store::open(":memory:").unwrap();
        store.maintenance().unwrap();
    }

    #[test]
    fn maintenance_prunes_expired_server_metrics() {
        let store = Store::open(":memory:").unwrap();
        let uuid = Uuid::new_v4();
        let server = store.ensure_server_for_user(uuid, 0).unwrap();
        let old = unix_now_millis().saturating_sub(31 * 24 * 3600 * 1000);
        let fresh = unix_now_millis();

        store
            .conn
            .execute(
                "INSERT INTO server_metrics (server_id, metric, timestamp_ms, value)
                 VALUES (?1, 'cpu', ?2, 1.0), (?1, 'cpu', ?3, 2.0)",
                params![server.id as i64, old as i64, fresh as i64],
            )
            .unwrap();

        store.maintenance().unwrap();

        let points = store.query_server_metrics(server.id, "cpu", 0).unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].value, 2.0);
    }

    #[test]
    fn maintenance_prunes_expired_history_transfers_and_waf() {
        let store = Store::open(":memory:").unwrap();
        let uuid = Uuid::new_v4();
        let server = store.ensure_server_for_user(uuid, 0).unwrap();
        let now = unix_now();
        let stale_history = now.saturating_sub(31 * 86_400);
        let fresh_history = now.saturating_sub(3_600);
        let stale_transfer = now.saturating_sub(91 * 86_400);
        let fresh_transfer = now.saturating_sub(86_400);
        let stale_waf = now.saturating_sub(31 * 86_400);
        let fresh_waf = now.saturating_sub(3_600);

        // service_history: one stale, one fresh
        store
            .conn
            .execute(
                "INSERT INTO service_history
                    (service_id, server_id, avg_delay, up, down, data, created_at_unix, updated_at_unix)
                 VALUES (1, ?1, 0.0, 0, 0, '', ?2, ?2),
                        (1, ?1, 0.0, 0, 0, '', ?3, ?3)",
                params![server.id as i64, stale_history as i64, fresh_history as i64],
            )
            .unwrap();

        // transfers: one stale, one fresh
        store
            .conn
            .execute(
                "INSERT INTO transfers
                    (server_id, in_bytes, out_bytes, created_at_unix, updated_at_unix)
                 VALUES (?1, 1, 1, ?2, ?2), (?1, 2, 2, ?3, ?3)",
                params![server.id as i64, stale_transfer as i64, fresh_transfer as i64],
            )
            .unwrap();

        // waf: one stale identifier, one fresh identifier
        let ip = ip_string_to_binary("203.0.113.7").unwrap();
        store
            .conn
            .execute(
                "INSERT INTO waf (ip, block_identifier, block_reason, block_timestamp, count)
                 VALUES (?1, 1, 0, ?2, 1), (?1, 2, 0, ?3, 1)",
                params![ip, stale_waf as i64, fresh_waf as i64],
            )
            .unwrap();

        store.maintenance().unwrap();

        let history_count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM service_history WHERE server_id = ?1",
                params![server.id as i64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(history_count, 1);

        let transfer_count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM transfers WHERE server_id = ?1",
                params![server.id as i64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(transfer_count, 1);

        let waf_count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM waf", [], |row| row.get(0))
            .unwrap();
        assert_eq!(waf_count, 1);
    }

    #[test]
    fn schema_version_migrations_are_recorded_and_idempotent() {
        let store = Store::open(":memory:").unwrap();
        let version: i64 = store
            .conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(version >= 3, "expected at least version 3, got {version}");

        let count_before: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))
            .unwrap();
        // Re-running migrations must not duplicate version rows.
        store.run_versioned_migrations().unwrap();
        let count_after: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count_before, count_after);
    }

    #[test]
    fn state_updates_write_queryable_server_metrics() {
        let store = Store::open(":memory:").unwrap();
        let uuid = Uuid::new_v4();
        let server = store.ensure_server_for_user(uuid, 0).unwrap();
        store
            .update_state_for_user(
                uuid,
                0,
                State {
                    cpu: 12.5,
                    mem_used: 42,
                    uptime: 99,
                    ..State::default()
                },
            )
            .unwrap();

        let cpu = store.query_server_metrics(server.id, "cpu", 0).unwrap();
        assert_eq!(cpu.len(), 1);
        assert_eq!(cpu[0].value, 12.5);

        let memory = store.query_server_metrics(server.id, "memory", 0).unwrap();
        assert_eq!(memory[0].value, 42.0);

        assert!(
            store
                .query_server_metrics(server.id, "not-a-metric", 0)
                .is_err()
        );
    }

    #[test]
    fn state_updates_record_hourly_transfer_deltas() {
        let store = Store::open(":memory:").unwrap();
        let uuid = Uuid::new_v4();
        let server = store.ensure_server_for_user(uuid, 0).unwrap();

        store
            .update_state_for_user(
                uuid,
                0,
                State {
                    net_in_transfer: 100,
                    net_out_transfer: 50,
                    ..State::default()
                },
            )
            .unwrap();
        store
            .update_state_for_user(
                uuid,
                0,
                State {
                    net_in_transfer: 130,
                    net_out_transfer: 70,
                    ..State::default()
                },
            )
            .unwrap();

        let transfers = store.list_transfers_since(server.id, 0).unwrap();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].in_bytes, 130);
        assert_eq!(transfers[0].out_bytes, 70);
        assert_eq!(transfers[0].created_at % 3600, 0);

        store
            .update_state_for_user(
                uuid,
                0,
                State {
                    net_in_transfer: 120,
                    net_out_transfer: 60,
                    ..State::default()
                },
            )
            .unwrap();
        let transfers = store.list_transfers_since(server.id, 0).unwrap();
        assert_eq!(transfers[0].in_bytes, 130);
        assert_eq!(transfers[0].out_bytes, 70);
    }

    #[test]
    fn agent_counter_reset_starts_new_baseline_without_phantom_delta() {
        let store = Store::open(":memory:").unwrap();
        let uuid = Uuid::new_v4();
        let server = store.ensure_server_for_user(uuid, 0).unwrap();

        store
            .update_state_for_user(
                uuid,
                0,
                State {
                    net_in_transfer: 1_000,
                    net_out_transfer: 500,
                    ..State::default()
                },
            )
            .unwrap();
        store
            .update_state_for_user(
                uuid,
                0,
                State {
                    net_in_transfer: 10,
                    net_out_transfer: 5,
                    ..State::default()
                },
            )
            .unwrap();
        store
            .update_state_for_user(
                uuid,
                0,
                State {
                    net_in_transfer: 60,
                    net_out_transfer: 25,
                    ..State::default()
                },
            )
            .unwrap();

        let transfers = store.list_transfers_since(server.id, 0).unwrap();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].in_bytes, 1_050);
        assert_eq!(transfers[0].out_bytes, 520);
    }

    #[test]
    fn cycle_transfer_stats_follow_alert_transfer_rules() {
        let store = Store::open(":memory:").unwrap();
        let uuid = Uuid::new_v4();
        let server = store.ensure_server_for_user(uuid, 0).unwrap();
        store
            .update_state_for_user(
                uuid,
                0,
                State {
                    net_in_transfer: 100,
                    net_out_transfer: 50,
                    ..State::default()
                },
            )
            .unwrap();
        store
            .update_state_for_user(
                uuid,
                0,
                State {
                    net_in_transfer: 130,
                    net_out_transfer: 70,
                    ..State::default()
                },
            )
            .unwrap();
        let cycle_start = Utc
            .timestamp_opt(unix_now().saturating_sub(3600) as i64, 0)
            .single()
            .unwrap()
            .to_rfc3339();
        let alert = store
            .upsert_alert_rule(
                None,
                0,
                &serde_json::json!({
                    "name": "monthly traffic",
                    "enable": true,
                    "rules": [{
                        "type": "transfer_all_cycle",
                        "max": 500,
                        "min": 10,
                        "cycle_start": cycle_start,
                        "cycle_interval": 1,
                        "cycle_unit": "hour",
                        "cover": 0
                    }]
                }),
            )
            .unwrap();

        let stats = store.cycle_transfer_stats().unwrap();
        let item = stats.get(&alert.id).unwrap();
        let public = store
            .list_servers()
            .unwrap()
            .into_iter()
            .find(|item| item.id == server.id)
            .unwrap();
        assert_eq!(item.name, "monthly traffic");
        assert_eq!(item.max, 500);
        assert_eq!(item.min, 10);
        assert_eq!(item.server_name.get(&server.id).unwrap(), &public.name);
        assert_eq!(item.transfer.get(&server.id), Some(&200));
        assert!(item.next_update.contains_key(&server.id));
    }

    #[test]
    fn service_results_are_authorized_and_queryable() {
        let store = Store::open(":memory:").unwrap();
        let owner_server = store.ensure_server_for_user(Uuid::new_v4(), 0).unwrap();
        let foreign_server = store.ensure_server_for_user(Uuid::new_v4(), 0).unwrap();
        store.move_servers(&[owner_server.id], 100).unwrap();
        store.move_servers(&[foreign_server.id], 200).unwrap();
        let service = store
            .upsert_service(
                None,
                100,
                &serde_json::json!({
                    "name": "tcp",
                    "type": 3,
                    "target": "example.com:443",
                    "duration": 30,
                    "cover": 1,
                    "skip_servers": {
                        (owner_server.id.to_string()): true,
                        (foreign_server.id.to_string()): true
                    }
                }),
            )
            .unwrap();
        let result = TaskResult {
            id: service.id,
            r#type: 3,
            delay: 12.0,
            data: "ok".to_string(),
            successful: true,
        };

        assert!(
            !store
                .record_service_result(foreign_server.id, &result)
                .unwrap()
        );
        assert!(
            store
                .record_service_result(owner_server.id, &result)
                .unwrap()
        );

        let history = store.query_service_history(service.id, 0).unwrap();
        assert_eq!(history.service_name, "tcp");
        assert_eq!(history.servers.len(), 1);
        assert_eq!(history.servers[0].server_id, owner_server.id);
        assert_eq!(history.servers[0].stats.total_up, 1);
        assert_eq!(history.servers[0].stats.total_down, 0);

        let server_services = store.query_server_services(owner_server.id, 0).unwrap();
        assert_eq!(server_services.len(), 1);
        assert_eq!(server_services[0].monitor_id, service.id);
        assert_eq!(server_services[0].avg_delay, vec![12.0]);
        assert_eq!(server_services[0].packet_loss, vec![0.0]);

        let services = store.service_response_items().unwrap();
        let item = services.get(&service.id).unwrap();
        assert_eq!(item.service_name, "tcp");
        assert_eq!(item.current_up, 1);
        assert_eq!(item.current_down, 0);
        assert_eq!(item.total_up, 1);
        assert_eq!(item.total_down, 0);
        assert_eq!(item.delay.unwrap()[29], 12.0);
        assert_eq!(item.up.unwrap()[29], 1);
        assert_eq!(item.down.unwrap()[29], 0);
    }

    #[test]
    fn service_server_ids_match_cover_configuration() {
        let store = Store::open(":memory:").unwrap();
        let first = store.ensure_server_for_user(Uuid::new_v4(), 0).unwrap();
        let second = store.ensure_server_for_user(Uuid::new_v4(), 0).unwrap();
        let third = store.ensure_server_for_user(Uuid::new_v4(), 0).unwrap();

        store
            .upsert_service(
                None,
                0,
                &serde_json::json!({
                    "name": "public-http",
                    "type": 1,
                    "target": "https://example.com",
                    "duration": 30,
                    "cover": 0,
                    "skip_servers": { (third.id.to_string()): true }
                }),
            )
            .unwrap();
        store
            .upsert_service(
                None,
                0,
                &serde_json::json!({
                    "name": "selected-tcp",
                    "type": 3,
                    "target": "example.com:443",
                    "duration": 30,
                    "cover": 1,
                    "skip_servers": {
                        (second.id.to_string()): true,
                        (third.id.to_string()): false
                    }
                }),
            )
            .unwrap();

        assert_eq!(
            store.service_server_ids().unwrap(),
            vec![first.id, second.id]
        );
    }

    #[test]
    fn service_result_rejects_mismatched_task_type() {
        let store = Store::open(":memory:").unwrap();
        let server = store.ensure_server_for_user(Uuid::new_v4(), 0).unwrap();
        let service = store
            .upsert_service(
                None,
                0,
                &serde_json::json!({
                    "name": "http",
                    "type": 1,
                    "target": "https://example.com",
                    "duration": 30,
                    "cover": 1,
                    "skip_servers": { (server.id.to_string()): true }
                }),
            )
            .unwrap();

        assert!(
            !store
                .record_service_result(
                    server.id,
                    &TaskResult {
                        id: service.id,
                        r#type: 3,
                        delay: 0.0,
                        data: String::new(),
                        successful: false,
                    },
                )
                .unwrap()
        );
        assert!(
            store
                .query_service_history(service.id, 0)
                .unwrap()
                .servers
                .is_empty()
        );
    }

    #[test]
    fn cron_results_are_authorized_by_cover_and_owner() {
        let store = Store::open(":memory:").unwrap();
        let owner_server = store.ensure_server_for_user(Uuid::new_v4(), 0).unwrap();
        let foreign_server = store.ensure_server_for_user(Uuid::new_v4(), 0).unwrap();
        store.move_servers(&[owner_server.id], 100).unwrap();
        store.move_servers(&[foreign_server.id], 200).unwrap();
        let cron = store
            .upsert_cron(
                None,
                100,
                &serde_json::json!({
                    "name": "uptime",
                    "task_type": 0,
                    "scheduler": "0/5 * * * * * *",
                    "command": "uptime",
                    "servers": [owner_server.id, foreign_server.id],
                    "cover": 0
                }),
            )
            .unwrap();
        let result = TaskResult {
            id: cron.id,
            r#type: 4,
            delay: 0.0,
            data: "ok".to_string(),
            successful: true,
        };

        assert!(
            !store
                .record_cron_result(foreign_server.id, &result, false)
                .unwrap()
        );
        assert!(
            store
                .record_cron_result(owner_server.id, &result, false)
                .unwrap()
        );

        let cron = store.get_cron(cron.id).unwrap();
        assert!(cron.last_result);
        assert!(cron.last_executed_at.is_some());
    }

    #[test]
    fn alert_trigger_cron_results_require_reserved_authorization() {
        let store = Store::open(":memory:").unwrap();
        let server = store.ensure_server_for_user(Uuid::new_v4(), 0).unwrap();
        let cron = store
            .upsert_cron(
                None,
                0,
                &serde_json::json!({
                    "name": "trigger",
                    "task_type": 1,
                    "command": "echo alert",
                    "cover": CRON_COVER_ALERT_TRIGGER
                }),
            )
            .unwrap();
        let result = TaskResult {
            id: cron.id,
            r#type: TaskType::Command.as_u64(),
            delay: 0.0,
            data: "ok".into(),
            successful: true,
        };

        assert!(!store.record_cron_result(server.id, &result, false).unwrap());
        assert!(store.record_cron_result(server.id, &result, true).unwrap());
    }

    #[test]
    fn delete_servers_cascades_to_related_tables() {
        let store = Store::open(":memory:").unwrap();
        let server = store.ensure_server_for_user(Uuid::new_v4(), 0).unwrap();
        let sid = server.id as i64;
        let now = unix_now() as i64;

        store
            .conn
            .execute(
                "INSERT INTO transfers (server_id, in_bytes, out_bytes, created_at_unix, updated_at_unix)
                 VALUES (?1, 1, 2, ?2, ?2)",
                params![sid, now],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO service_history
                   (service_id, server_id, avg_delay, up, down, data, created_at_unix, updated_at_unix)
                 VALUES (1, ?1, 0, 1, 0, '', ?2, ?2)",
                params![sid, now],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO server_metrics (server_id, metric, timestamp_ms, value)
                 VALUES (?1, 'cpu', ?2, 1.0)",
                params![sid, now * 1000],
            )
            .unwrap();
        store
            .enqueue_pending_task(server.id, 1, TaskType::Command.as_u64(), "")
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO nat (user_id, enabled, name, server_id, host, domain, created_at_unix, updated_at_unix)
                 VALUES (0, 1, 'n', ?1, 'h', 'd', ?2, ?2)",
                params![sid, now],
            )
            .unwrap();

        assert_eq!(store.delete_servers(&[server.id]).unwrap(), 1);

        for table in [
            "transfers",
            "service_history",
            "server_metrics",
            "pending_tasks",
            "nat",
        ] {
            let count: i64 = store
                .conn
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE server_id = ?1"),
                    params![sid],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{table} should be empty after delete_servers");
        }
    }
}
