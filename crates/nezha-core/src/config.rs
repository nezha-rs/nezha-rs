use std::{collections::HashMap, env, fs, path::Path};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AgentConfig {
    pub debug: bool,
    pub server: String,
    pub client_secret: String,
    pub uuid: Uuid,
    pub hard_drive_partition_allowlist: Vec<String>,
    pub nic_allowlist: HashMap<String, bool>,
    pub dns: Vec<String>,
    pub gpu: bool,
    pub temperature: bool,
    pub skip_connection_count: bool,
    pub skip_procs_count: bool,
    pub disable_auto_update: bool,
    pub disable_force_update: bool,
    pub disable_command_execute: bool,
    pub report_delay: u32,
    pub tls: bool,
    pub insecure_tls: bool,
    pub use_ipv6_country_code: bool,
    pub use_gitee_to_upgrade: bool,
    pub use_atomgit_to_upgrade: bool,
    pub disable_nat: bool,
    pub disable_send_query: bool,
    pub ip_report_period: u32,
    pub self_update_period: u32,
    pub custom_ip_api: Vec<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            debug: false,
            server: String::new(),
            client_secret: String::new(),
            uuid: Uuid::new_v4(),
            hard_drive_partition_allowlist: Vec::new(),
            nic_allowlist: HashMap::new(),
            dns: Vec::new(),
            gpu: false,
            temperature: false,
            skip_connection_count: false,
            skip_procs_count: false,
            disable_auto_update: false,
            disable_force_update: false,
            disable_command_execute: false,
            report_delay: 3,
            tls: false,
            insecure_tls: false,
            use_ipv6_country_code: false,
            use_gitee_to_upgrade: false,
            use_atomgit_to_upgrade: false,
            disable_nat: false,
            disable_send_query: false,
            ip_report_period: 1800,
            self_update_period: 0,
            custom_ip_api: Vec::new(),
        }
    }
}

impl AgentConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut cfg = if path.exists() {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("failed to read config {}", path.display()))?;
            serde_yaml::from_str::<Self>(&raw)
                .with_context(|| format!("failed to parse config {}", path.display()))?
        } else {
            let cfg = Self::default();
            cfg.save(path)?;
            cfg
        };

        cfg.apply_env_overrides()?;
        cfg.validate(false)?;
        Ok(cfg)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create config dir {}", parent.display()))?;
        }
        let raw = serde_yaml::to_string(self).context("failed to serialize config")?;
        fs::write(path, raw).with_context(|| format!("failed to write config {}", path.display()))
    }

    pub fn validate(&mut self, _remote_edit: bool) -> Result<()> {
        if self.report_delay == 0 {
            self.report_delay = 3;
        }
        if self.ip_report_period == 0 {
            self.ip_report_period = 1800;
        } else if self.ip_report_period < 30 {
            self.ip_report_period = 30;
        }
        if !(1..=4).contains(&self.report_delay) {
            return Err(anyhow!("report_delay ranges from 1 to 4 seconds"));
        }
        if self.server.trim().is_empty() {
            return Err(anyhow!("server address should not be empty"));
        }
        if self.client_secret.trim().is_empty() {
            return Err(anyhow!("client_secret must be specified"));
        }
        Ok(())
    }

    fn apply_env_overrides(&mut self) -> Result<()> {
        set_string(&mut self.server, "NZ_SERVER");
        set_string(&mut self.client_secret, "NZ_CLIENT_SECRET");
        if let Ok(raw) = env::var("NZ_UUID") {
            self.uuid = raw.parse().context("invalid NZ_UUID")?;
        }
        set_bool(&mut self.debug, "NZ_DEBUG")?;
        set_bool(&mut self.gpu, "NZ_GPU")?;
        set_bool(&mut self.temperature, "NZ_TEMPERATURE")?;
        set_bool(&mut self.skip_connection_count, "NZ_SKIP_CONNECTION_COUNT")?;
        set_bool(&mut self.skip_procs_count, "NZ_SKIP_PROCS_COUNT")?;
        set_bool(&mut self.disable_auto_update, "NZ_DISABLE_AUTO_UPDATE")?;
        set_bool(&mut self.disable_force_update, "NZ_DISABLE_FORCE_UPDATE")?;
        set_bool(
            &mut self.disable_command_execute,
            "NZ_DISABLE_COMMAND_EXECUTE",
        )?;
        set_bool(&mut self.tls, "NZ_TLS")?;
        set_bool(&mut self.insecure_tls, "NZ_INSECURE_TLS")?;
        set_bool(&mut self.use_ipv6_country_code, "NZ_USE_IPV6_COUNTRY_CODE")?;
        set_bool(&mut self.use_gitee_to_upgrade, "NZ_USE_GITEE_TO_UPGRADE")?;
        set_bool(
            &mut self.use_atomgit_to_upgrade,
            "NZ_USE_ATOMGIT_TO_UPGRADE",
        )?;
        set_bool(&mut self.disable_nat, "NZ_DISABLE_NAT")?;
        set_bool(&mut self.disable_send_query, "NZ_DISABLE_SEND_QUERY")?;
        set_u32(&mut self.report_delay, "NZ_REPORT_DELAY")?;
        set_u32(&mut self.ip_report_period, "NZ_IP_REPORT_PERIOD")?;
        set_u32(&mut self.self_update_period, "NZ_SELF_UPDATE_PERIOD")?;
        set_string_list(&mut self.dns, "NZ_DNS");
        set_string_list(&mut self.custom_ip_api, "NZ_CUSTOM_IP_API");
        Ok(())
    }
}

fn set_string(target: &mut String, key: &str) {
    if let Ok(value) = env::var(key) {
        *target = value;
    }
}

fn set_string_list(target: &mut Vec<String>, key: &str) {
    if let Ok(value) = env::var(key) {
        *target = value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }
}

fn set_bool(target: &mut bool, key: &str) -> Result<()> {
    if let Ok(value) = env::var(key) {
        *target = match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => return Err(anyhow!("invalid boolean value for {key}: {value}")),
        };
    }
    Ok(())
}

fn set_u32(target: &mut u32, key: &str) -> Result<()> {
    if let Ok(value) = env::var(key) {
        *target = value
            .parse()
            .with_context(|| format!("invalid integer value for {key}: {value}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_sets_defaults() {
        let mut cfg = AgentConfig {
            server: "127.0.0.1:5555".to_string(),
            client_secret: "secret".to_string(),
            report_delay: 0,
            ip_report_period: 1,
            ..AgentConfig::default()
        };

        cfg.validate(false).unwrap();

        assert_eq!(cfg.report_delay, 3);
        assert_eq!(cfg.ip_report_period, 30);
    }

    #[test]
    fn remote_validate_rejects_empty_connection_fields() {
        let mut cfg = AgentConfig {
            server: String::new(),
            client_secret: "secret".to_string(),
            ..AgentConfig::default()
        };
        assert!(cfg.validate(true).is_err());

        let mut cfg = AgentConfig {
            server: "127.0.0.1:5555".to_string(),
            client_secret: String::new(),
            ..AgentConfig::default()
        };
        assert!(cfg.validate(true).is_err());
    }
}
