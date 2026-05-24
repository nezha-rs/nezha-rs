use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{GeoIp, Host, HostState};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Common {
    pub id: u64,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub user_id: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    #[default]
    Admin = 0,
    Member = 1,
}

impl Role {
    pub fn is_admin(self) -> bool {
        self == Self::Admin
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    #[serde(flatten)]
    pub common: Common,
    pub username: String,
    pub password: String,
    pub role: Role,
    pub agent_secret: String,
    pub reject_password: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    #[serde(flatten)]
    pub user: User,
    pub login_ip: String,
    pub oauth2_bind: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Server {
    #[serde(flatten)]
    pub common: Common,
    pub name: String,
    pub uuid: String,
    pub note: String,
    pub public_note: String,
    pub display_index: i32,
    pub hide_for_guest: bool,
    pub enable_ddns: bool,
    pub ddns_profiles: Vec<u64>,
    pub override_ddns_domains: HashMap<u64, Vec<String>>,
    pub host: Option<Host>,
    pub state: Option<HostState>,
    pub geoip: Option<GeoIp>,
    pub last_active: Option<DateTime<Utc>>,
    pub prev_transfer_in_snapshot: u64,
    pub prev_transfer_out_snapshot: u64,
}

impl Server {
    pub fn is_online(&self, now: DateTime<Utc>) -> bool {
        self.last_active
            .is_some_and(|last| now.signed_duration_since(last).num_seconds() <= 10)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerGroup {
    #[serde(flatten)]
    pub common: Common,
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerGroupServer {
    pub server_group_id: u64,
    pub server_id: u64,
}

pub const SERVICE_COVER_ALL: u8 = 0;
pub const SERVICE_COVER_IGNORE_ALL: u8 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Service {
    #[serde(flatten)]
    pub common: Common,
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
    pub min_latency: f32,
    pub max_latency: f32,
    pub latency_notify: bool,
    pub skip_servers: HashMap<u64, bool>,
}

impl Service {
    pub fn interval_seconds(&self) -> u64 {
        if self.duration == 0 {
            30
        } else {
            self.duration
        }
    }
}

pub const CRON_COVER_IGNORE_ALL: u8 = 0;
pub const CRON_COVER_ALL: u8 = 1;
pub const CRON_COVER_ALERT_TRIGGER: u8 = 2;
pub const CRON_TYPE_CRON_TASK: u8 = 0;
pub const CRON_TYPE_TRIGGER_TASK: u8 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cron {
    #[serde(flatten)]
    pub common: Common,
    pub name: String,
    pub task_type: u8,
    pub scheduler: String,
    pub command: String,
    pub servers: Vec<u64>,
    pub push_successful: bool,
    pub notification_group_id: u64,
    pub last_executed_at: Option<DateTime<Utc>>,
    pub last_result: bool,
    pub cover: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationGroup {
    #[serde(flatten)]
    pub common: Common,
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Notification {
    #[serde(flatten)]
    pub common: Common,
    pub name: String,
    pub url: String,
    pub request_method: u8,
    pub request_type: u8,
    pub request_header: String,
    pub request_body: String,
    pub verify_tls: Option<bool>,
    pub format_metric_units: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationGroupNotification {
    pub notification_group_id: u64,
    pub notification_id: u64,
}

pub const ALERT_MODE_ALWAYS_TRIGGER: u8 = 0;
pub const ALERT_MODE_ONETIME_TRIGGER: u8 = 1;
pub const RULE_COVER_ALL: u64 = 0;
pub const RULE_COVER_IGNORE_ALL: u64 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Rule {
    pub r#type: String,
    pub min: f64,
    pub max: f64,
    pub cycle_start: Option<DateTime<Utc>>,
    pub cycle_interval: u64,
    pub cycle_unit: String,
    pub duration: u64,
    pub cover: u64,
    pub ignore: HashMap<u64, bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AlertRule {
    #[serde(flatten)]
    pub common: Common,
    pub name: String,
    pub enable: Option<bool>,
    pub trigger_mode: u8,
    pub notification_group_id: u64,
    pub rules: Vec<Rule>,
    pub fail_trigger_tasks: Vec<u64>,
    pub recover_trigger_tasks: Vec<u64>,
}

impl AlertRule {
    pub fn enabled(&self) -> bool {
        self.enable.unwrap_or(false)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DdnsProfile {
    #[serde(flatten)]
    pub common: Common,
    pub enable_ipv4: Option<bool>,
    pub enable_ipv6: Option<bool>,
    pub max_retries: u64,
    pub name: String,
    pub provider: String,
    pub access_id: String,
    pub access_secret: String,
    pub webhook_url: String,
    pub webhook_method: u8,
    pub webhook_request_type: u8,
    pub webhook_request_body: String,
    pub webhook_headers: String,
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Nat {
    #[serde(flatten)]
    pub common: Common,
    pub enabled: bool,
    pub name: String,
    pub server_id: u64,
    pub host: String,
    pub domain: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ServiceHistory {
    pub id: u64,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub service_id: u64,
    pub server_id: u64,
    pub avg_delay: f64,
    pub up: u64,
    pub down: u64,
    pub data: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transfer {
    #[serde(flatten)]
    pub common: Common,
    pub server_id: u64,
    pub r#in: u64,
    pub out: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WafEntry {
    pub ip: Vec<u8>,
    pub block_identifier: i64,
    pub block_reason: u8,
    pub block_timestamp: u64,
    pub count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_default_interval_matches_go() {
        assert_eq!(Service::default().interval_seconds(), 30);
    }

    #[test]
    fn alert_rule_enabled_requires_true_pointer() {
        assert!(!AlertRule::default().enabled());
        assert!(
            AlertRule {
                enable: Some(true),
                ..AlertRule::default()
            }
            .enabled()
        );
    }
}
