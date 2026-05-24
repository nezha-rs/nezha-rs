use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow};
use clap::ValueEnum;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum ServiceAction {
    Install,
    Uninstall,
    Start,
    Stop,
    Restart,
}

pub(crate) fn control(action: ServiceAction, config_path: &Path) -> Result<()> {
    match action {
        ServiceAction::Install => install(config_path),
        ServiceAction::Uninstall => uninstall(config_path),
        ServiceAction::Start => start(config_path),
        ServiceAction::Stop => stop(config_path),
        ServiceAction::Restart => {
            stop(config_path)?;
            start(config_path)
        }
    }
}

#[cfg(target_os = "windows")]
fn install(config_path: &Path) -> Result<()> {
    let executable = current_exe()?;
    let config = absolute_config_path(config_path)?;
    let name = service_name(&executable, &config);
    let bin_path = format!(
        "\"{}\" --config \"{}\"",
        executable.display(),
        config.display()
    );

    run_status(
        "sc",
        &[
            "create",
            &name,
            "binPath=",
            &bin_path,
            "DisplayName=",
            "nezha-agent",
            "start=",
            "auto",
        ],
    )
    .context("failed to create Windows service")?;
    run_status(
        "sc",
        &["failure", &name, "reset=", "0", "actions=", "restart/5000"],
    )
    .context("failed to set Windows service restart policy")?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall(config_path: &Path) -> Result<()> {
    let name = service_name(&current_exe()?, &absolute_config_path(config_path)?);
    let _ = run_status("sc", &["stop", &name]);
    run_status("sc", &["delete", &name]).context("failed to delete Windows service")
}

#[cfg(target_os = "windows")]
fn start(config_path: &Path) -> Result<()> {
    let name = service_name(&current_exe()?, &absolute_config_path(config_path)?);
    run_status("sc", &["start", &name]).context("failed to start Windows service")
}

#[cfg(target_os = "windows")]
fn stop(config_path: &Path) -> Result<()> {
    let name = service_name(&current_exe()?, &absolute_config_path(config_path)?);
    run_status("sc", &["stop", &name]).context("failed to stop Windows service")
}

#[cfg(target_os = "linux")]
fn install(config_path: &Path) -> Result<()> {
    let executable = current_exe()?;
    let config = absolute_config_path(config_path)?;
    let name = service_name(&executable, &config);
    let unit = format!(
        r#"[Unit]
Description=Nezha Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={} --config {}
WorkingDirectory={}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"#,
        systemd_escape_arg(&executable),
        systemd_escape_arg(&config),
        systemd_escape_arg(executable.parent().unwrap_or_else(|| Path::new("/"))),
    );
    let unit_path = PathBuf::from("/etc/systemd/system").join(format!("{name}.service"));
    std::fs::write(&unit_path, unit)
        .with_context(|| format!("failed to write {}", unit_path.display()))?;
    run_status("systemctl", &["daemon-reload"])?;
    run_status("systemctl", &["enable", &format!("{name}.service")])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall(config_path: &Path) -> Result<()> {
    let name = service_name(&current_exe()?, &absolute_config_path(config_path)?);
    let unit = format!("{name}.service");
    let _ = run_status("systemctl", &["stop", &unit]);
    let _ = run_status("systemctl", &["disable", &unit]);
    let unit_path = PathBuf::from("/etc/systemd/system").join(&unit);
    if unit_path.exists() {
        std::fs::remove_file(&unit_path)
            .with_context(|| format!("failed to remove {}", unit_path.display()))?;
    }
    run_status("systemctl", &["daemon-reload"])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn start(config_path: &Path) -> Result<()> {
    let name = service_name(&current_exe()?, &absolute_config_path(config_path)?);
    run_status("systemctl", &["start", &format!("{name}.service")])
}

#[cfg(target_os = "linux")]
fn stop(config_path: &Path) -> Result<()> {
    let name = service_name(&current_exe()?, &absolute_config_path(config_path)?);
    run_status("systemctl", &["stop", &format!("{name}.service")])
}

#[cfg(target_os = "macos")]
fn install(config_path: &Path) -> Result<()> {
    let executable = current_exe()?;
    let config = absolute_config_path(config_path)?;
    let name = service_name(&executable, &config);
    let label = format!("io.nezha.{name}");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>--config</string>
    <string>{}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>WorkingDirectory</key><string>{}</string>
</dict>
</plist>
"#,
        xml_escape(&executable.to_string_lossy()),
        xml_escape(&config.to_string_lossy()),
        xml_escape(
            &executable
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .to_string_lossy()
        ),
    );
    let plist_path = launchd_plist_path(&name)?;
    std::fs::write(&plist_path, plist)
        .with_context(|| format!("failed to write {}", plist_path.display()))?;
    run_status(
        "launchctl",
        &["load", "-w", plist_path.to_string_lossy().as_ref()],
    )
}

#[cfg(target_os = "macos")]
fn uninstall(config_path: &Path) -> Result<()> {
    let name = service_name(&current_exe()?, &absolute_config_path(config_path)?);
    let plist_path = launchd_plist_path(&name)?;
    if plist_path.exists() {
        let _ = run_status(
            "launchctl",
            &["unload", "-w", plist_path.to_string_lossy().as_ref()],
        );
        std::fs::remove_file(&plist_path)
            .with_context(|| format!("failed to remove {}", plist_path.display()))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn start(config_path: &Path) -> Result<()> {
    let name = service_name(&current_exe()?, &absolute_config_path(config_path)?);
    run_status("launchctl", &["start", &format!("io.nezha.{name}")])
}

#[cfg(target_os = "macos")]
fn stop(config_path: &Path) -> Result<()> {
    let name = service_name(&current_exe()?, &absolute_config_path(config_path)?);
    run_status("launchctl", &["stop", &format!("io.nezha.{name}")])
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn install(_config_path: &Path) -> Result<()> {
    anyhow::bail!("service management is not supported on this platform")
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn uninstall(_config_path: &Path) -> Result<()> {
    anyhow::bail!("service management is not supported on this platform")
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn start(_config_path: &Path) -> Result<()> {
    anyhow::bail!("service management is not supported on this platform")
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn stop(_config_path: &Path) -> Result<()> {
    anyhow::bail!("service management is not supported on this platform")
}

fn run_status(command: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(command)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {command}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "{command} exited with {}: {}{}",
        output.status,
        stdout,
        stderr
    ))
}

fn current_exe() -> Result<PathBuf> {
    env::current_exe().context("failed to resolve current executable")
}

fn absolute_config_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()
            .context("failed to resolve current directory")?
            .join(path))
    }
}

fn service_name(executable: &Path, config_path: &Path) -> String {
    let base = executable
        .file_stem()
        .or_else(|| executable.file_name())
        .and_then(|value| value.to_str())
        .unwrap_or("nezha-agent");
    if config_path == default_config_path(executable).as_path() {
        sanitize_service_name(base)
    } else {
        format!(
            "{}-{:07x}",
            sanitize_service_name(base),
            stable_path_hash(config_path) & 0x0fff_ffff
        )
    }
}

fn default_config_path(executable: &Path) -> PathBuf {
    executable
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("config.yml")
}

fn sanitize_service_name(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn stable_path_hash(path: &Path) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in path.to_string_lossy().as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

#[cfg(target_os = "linux")]
fn systemd_escape_arg(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if raw
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "/._:-".contains(ch))
    {
        raw.to_string()
    } else {
        format!("'{}'", raw.replace('\'', "'\\''"))
    }
}

#[cfg(target_os = "macos")]
fn launchd_plist_path(name: &str) -> Result<PathBuf> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("io.nezha.{name}.plist")))
}

#[cfg(target_os = "macos")]
fn xml_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_name_uses_base_for_default_config() {
        let exe = PathBuf::from("/opt/nezha/nezha-agent");
        assert_eq!(
            service_name(&exe, &PathBuf::from("/opt/nezha/config.yml")),
            "nezha-agent"
        );
    }

    #[test]
    fn service_name_is_stable_for_custom_config() {
        let exe = PathBuf::from("/opt/nezha/nezha-agent");
        let one = service_name(&exe, &PathBuf::from("/etc/nezha/config.yml"));
        let two = service_name(&exe, &PathBuf::from("/etc/nezha/config.yml"));

        assert_eq!(one, two);
        assert!(one.starts_with("nezha-agent-"));
    }
}
