use std::{
    collections::HashSet,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use dialoguer::{Confirm, Input, MultiSelect, theme::ColorfulTheme};
use nezha_core::AgentConfig;
use sysinfo::{Disks, Networks};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiskChoice {
    label: String,
    mount_point: String,
}

pub(crate) fn run(config_path: &Path) -> Result<()> {
    let mut config = AgentConfig::load(config_path)?;
    let theme = ColorfulTheme::default();
    let network_choices = collect_network_choices();
    let disk_choices = collect_disk_choices();
    let uuid_suggestion = Uuid::new_v4();

    let selected_nics = select_items(
        &theme,
        "Select network interfaces to monitor",
        &network_choices,
        &selected_network_indexes(&network_choices, &config),
    )?;
    let selected_disks = select_items(
        &theme,
        "Select disk partitions to monitor",
        &disk_labels(&disk_choices),
        &selected_disk_indexes(&disk_choices, &config),
    )?;
    let dns_input: String = Input::with_theme(&theme)
        .with_prompt("Custom DNS servers (comma-separated ip:port, blank to skip)")
        .default(config.dns.join(","))
        .interact_text()?;
    let uuid_input: String = Input::with_theme(&theme)
        .with_prompt(format!("Agent UUID (suggested: {uuid_suggestion})"))
        .default(config.uuid.to_string())
        .show_default(true)
        .allow_empty(false)
        .validate_with(|input: &String| -> std::result::Result<(), &str> {
            let raw = input.trim();
            if raw.is_empty() {
                return Err("UUID cannot be empty");
            }
            if raw.parse::<Uuid>().is_ok() {
                Ok(())
            } else {
                Err("Enter a valid UUID")
            }
        })
        .interact_text()?;
    let gpu = Confirm::with_theme(&theme)
        .with_prompt("Enable GPU monitoring?")
        .default(config.gpu)
        .interact()?;
    let temperature = Confirm::with_theme(&theme)
        .with_prompt("Enable temperature monitoring?")
        .default(config.temperature)
        .interact()?;
    let debug = Confirm::with_theme(&theme)
        .with_prompt("Enable debug mode?")
        .default(config.debug)
        .interact()?;

    apply_edit_answers(
        &mut config,
        &network_choices,
        &disk_choices,
        &selected_nics,
        &selected_disks,
        &dns_input,
        &uuid_input,
        gpu,
        temperature,
        debug,
    )?;

    let save_path = absolute_config_path(config_path)?;
    config.save(&save_path)?;
    println!(
        "Saved agent config to {}. Restart the agent to apply it.",
        save_path.display()
    );
    Ok(())
}

fn select_items(
    theme: &ColorfulTheme,
    prompt: &str,
    items: &[String],
    defaults: &[bool],
) -> Result<Vec<usize>> {
    if items.is_empty() {
        return Ok(Vec::new());
    }
    Ok(MultiSelect::with_theme(theme)
        .with_prompt(prompt)
        .items(items)
        .defaults(defaults)
        .interact()?)
}

fn collect_network_choices() -> Vec<String> {
    let mut choices = Networks::new_with_refreshed_list()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    choices.sort();
    choices
}

fn collect_disk_choices() -> Vec<DiskChoice> {
    let mut choices = Disks::new_with_refreshed_list()
        .iter()
        .map(|disk| DiskChoice {
            label: format!(
                "{}\t{}\t{}",
                disk.mount_point().display(),
                disk.file_system().to_string_lossy(),
                disk.name().to_string_lossy()
            ),
            mount_point: disk.mount_point().display().to_string(),
        })
        .collect::<Vec<_>>();
    choices.sort_by(|left, right| left.mount_point.cmp(&right.mount_point));
    choices
}

fn disk_labels(choices: &[DiskChoice]) -> Vec<String> {
    choices.iter().map(|choice| choice.label.clone()).collect()
}

fn selected_network_indexes(choices: &[String], config: &AgentConfig) -> Vec<bool> {
    choices
        .iter()
        .map(|choice| config.nic_allowlist.get(choice).copied().unwrap_or(false))
        .collect()
}

fn selected_disk_indexes(choices: &[DiskChoice], config: &AgentConfig) -> Vec<bool> {
    let selected = config
        .hard_drive_partition_allowlist
        .iter()
        .collect::<HashSet<_>>();
    choices
        .iter()
        .map(|choice| selected.contains(&choice.mount_point))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn apply_edit_answers(
    config: &mut AgentConfig,
    network_choices: &[String],
    disk_choices: &[DiskChoice],
    selected_nics: &[usize],
    selected_disks: &[usize],
    dns_input: &str,
    uuid_input: &str,
    gpu: bool,
    temperature: bool,
    debug: bool,
) -> Result<()> {
    config.nic_allowlist = selected_nics
        .iter()
        .filter_map(|index| network_choices.get(*index))
        .map(|name| (name.clone(), true))
        .collect();
    config.hard_drive_partition_allowlist = selected_disks
        .iter()
        .filter_map(|index| disk_choices.get(*index))
        .map(|choice| choice.mount_point.clone())
        .collect();
    config.dns = parse_dns_servers(dns_input)?;
    config.uuid = uuid_input
        .trim()
        .parse()
        .with_context(|| format!("invalid uuid {}", uuid_input.trim()))?;
    config.gpu = gpu;
    config.temperature = temperature;
    config.debug = debug;
    Ok(())
}

fn parse_dns_servers(input: &str) -> Result<Vec<String>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    trimmed
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(validate_dns_server)
        .collect()
}

fn validate_dns_server(value: &str) -> Result<String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid DNS server {value}: expected ip:port"))?;
    if host.is_empty() || port.is_empty() {
        bail!("invalid DNS server {value}: expected ip:port");
    }
    if host.starts_with('[') && host.ends_with(']') {
        host[1..host.len() - 1]
            .parse::<IpAddr>()
            .with_context(|| format!("invalid DNS server {value}: host must be a literal IP"))?;
    } else {
        host.parse::<IpAddr>()
            .with_context(|| format!("invalid DNS server {value}: host must be a literal IP"))?;
    }
    let port_num: u16 = port
        .parse()
        .with_context(|| format!("invalid DNS server {value}: port must be numeric"))?;
    if port_num == 0 {
        bail!("invalid DNS server {value}: port must be non-zero");
    }
    Ok(value.to_string())
}

fn absolute_config_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("failed to resolve current directory")?
            .join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_config() -> AgentConfig {
        AgentConfig {
            server: "127.0.0.1:5555".to_string(),
            client_secret: "secret".to_string(),
            ..AgentConfig::default()
        }
    }

    #[test]
    fn parse_dns_servers_accepts_empty_and_literal_hosts() {
        assert_eq!(parse_dns_servers(" ").unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_dns_servers("1.1.1.1:53,[2606:4700:4700::1111]:53").unwrap(),
            vec![
                "1.1.1.1:53".to_string(),
                "[2606:4700:4700::1111]:53".to_string()
            ]
        );
    }

    #[test]
    fn parse_dns_servers_rejects_hostnames_and_missing_ports() {
        assert!(parse_dns_servers("dns.google:53").is_err());
        assert!(parse_dns_servers("1.1.1.1").is_err());
        assert!(parse_dns_servers("1.1.1.1:0").is_err());
    }

    #[test]
    fn selected_indexes_follow_existing_config() {
        let mut config = test_config();
        config.nic_allowlist.insert("eth0".to_string(), true);
        config.hard_drive_partition_allowlist = vec!["/".to_string()];

        assert_eq!(
            selected_network_indexes(&["eth0".to_string(), "wlan0".to_string()], &config),
            vec![true, false]
        );
        assert_eq!(
            selected_disk_indexes(
                &[
                    DiskChoice {
                        label: "/\text4\t/dev/sda1".to_string(),
                        mount_point: "/".to_string(),
                    },
                    DiskChoice {
                        label: "/data\text4\t/dev/sdb1".to_string(),
                        mount_point: "/data".to_string(),
                    }
                ],
                &config
            ),
            vec![true, false]
        );
    }

    #[test]
    fn apply_edit_answers_updates_only_editable_fields() {
        let mut config = test_config();
        config.nic_allowlist = HashMap::from([("old".to_string(), true)]);
        config.hard_drive_partition_allowlist = vec!["/old".to_string()];
        let networks = vec!["eth0".to_string(), "wlan0".to_string()];
        let disks = vec![
            DiskChoice {
                label: "/\text4\t/dev/sda1".to_string(),
                mount_point: "/".to_string(),
            },
            DiskChoice {
                label: "/data\text4\t/dev/sdb1".to_string(),
                mount_point: "/data".to_string(),
            },
        ];

        apply_edit_answers(
            &mut config,
            &networks,
            &disks,
            &[1],
            &[0, 1],
            "1.1.1.1:53",
            "123e4567-e89b-12d3-a456-426614174000",
            true,
            true,
            true,
        )
        .unwrap();

        assert_eq!(
            config.nic_allowlist,
            HashMap::from([("wlan0".to_string(), true)])
        );
        assert_eq!(
            config.hard_drive_partition_allowlist,
            vec!["/".to_string(), "/data".to_string()]
        );
        assert_eq!(config.dns, vec!["1.1.1.1:53".to_string()]);
        assert!(config.gpu);
        assert!(config.temperature);
        assert!(config.debug);
        assert_eq!(config.server, "127.0.0.1:5555");
        assert_eq!(config.client_secret, "secret");
    }
}
