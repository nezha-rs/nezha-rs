use std::{
    fs::{self, OpenOptions},
    io::ErrorKind,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use nezha_core::AgentConfig;

const BINARY_NAME: &str = "nezha-agent";
const RELEASE_REPO_OWNER: &str = "nezha-rs";
const RELEASE_REPO_NAME: &str = "nezha-rs";
const AUTO_CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const FORCE_BASELINE_VERSION: &str = "0.1.0";
const MIN_UPDATE_INTERVAL_MINUTES: u64 = 1440;
const MAX_UPDATE_INTERVAL_MINUTES: u64 = 2880;
static CACHED_COUNTRY_CODE: Mutex<String> = Mutex::new(String::new());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateMode {
    Auto,
    Force,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateProvider {
    GitHub,
    Gitee,
    AtomGit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdateOutcome {
    pub provider: UpdateProvider,
    pub updated: bool,
    pub version: String,
}

pub(crate) async fn run(cfg: &AgentConfig, mode: UpdateMode) -> Result<UpdateOutcome> {
    let cfg = cfg.clone();
    tokio::task::spawn_blocking(move || run_blocking(&cfg, mode))
        .await
        .context("self-update worker panicked")?
}

pub(crate) fn auto_update_period(cfg: &AgentConfig) -> Duration {
    if cfg.self_update_period > 0 {
        return Duration::from_secs(u64::from(cfg.self_update_period) * 60);
    }

    let span = MAX_UPDATE_INTERVAL_MINUTES - MIN_UPDATE_INTERVAL_MINUTES;
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    Duration::from_secs((MIN_UPDATE_INTERVAL_MINUTES + (seed % span)) * 60)
}

pub(crate) fn auto_update_allowed(cfg: &AgentConfig) -> bool {
    !cfg.disable_auto_update && version_looks_semver(AUTO_CURRENT_VERSION)
}

pub(crate) fn provider_for_config(cfg: &AgentConfig) -> UpdateProvider {
    if cfg.use_gitee_to_upgrade {
        UpdateProvider::Gitee
    } else if cfg.use_atomgit_to_upgrade {
        UpdateProvider::AtomGit
    } else if cached_country_code() == "cn" {
        cn_update_provider()
    } else {
        UpdateProvider::GitHub
    }
}

pub(crate) fn set_cached_country_code(country_code: &str) {
    if let Ok(mut cached) = CACHED_COUNTRY_CODE.lock() {
        *cached = country_code.trim().to_ascii_lowercase();
    }
}

pub(crate) fn cached_country_code() -> String {
    CACHED_COUNTRY_CODE
        .lock()
        .map(|value| value.clone())
        .unwrap_or_default()
}

fn cn_update_provider() -> UpdateProvider {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    if seed % 2 == 0 {
        UpdateProvider::Gitee
    } else {
        UpdateProvider::AtomGit
    }
}

fn run_blocking(cfg: &AgentConfig, mode: UpdateMode) -> Result<UpdateOutcome> {
    let provider = provider_for_config(cfg);
    let current_version = match mode {
        UpdateMode::Auto => AUTO_CURRENT_VERSION,
        UpdateMode::Force => FORCE_BASELINE_VERSION,
    };
    let update_lock = match acquire_update_lock()? {
        UpdateLock::Acquired(guard) => guard,
        UpdateLock::WaitedForPeer => {
            return Ok(UpdateOutcome {
                provider,
                updated: false,
                version: current_version.to_string(),
            });
        }
    };

    let release_target = rust_release_target();
    let status = match provider {
        UpdateProvider::GitHub => ::self_update::backends::github::Update::configure()
            .repo_owner(RELEASE_REPO_OWNER)
            .repo_name(RELEASE_REPO_NAME)
            .bin_name(BINARY_NAME)
            .target(&release_target)
            .show_download_progress(false)
            .show_output(false)
            .no_confirm(true)
            .current_version(current_version)
            .build()?
            .update()?,
        UpdateProvider::Gitee => ::self_update::backends::gitea::Update::configure()
            .with_host("https://gitee.com")
            .repo_owner(RELEASE_REPO_OWNER)
            .repo_name(RELEASE_REPO_NAME)
            .bin_name(BINARY_NAME)
            .target(&release_target)
            .show_download_progress(false)
            .show_output(false)
            .no_confirm(true)
            .current_version(current_version)
            .build()?
            .update()?,
        UpdateProvider::AtomGit => ::self_update::backends::gitea::Update::configure()
            .with_host("https://api.atomgit.com")
            .repo_owner(RELEASE_REPO_OWNER)
            .repo_name(RELEASE_REPO_NAME)
            .bin_name(BINARY_NAME)
            .target(&release_target)
            .show_download_progress(false)
            .show_output(false)
            .no_confirm(true)
            .current_version(current_version)
            .build()?
            .update()?,
    };
    drop(update_lock);

    Ok(UpdateOutcome {
        provider,
        updated: status.updated(),
        version: status.version().to_string(),
    })
}

fn version_looks_semver(version: &str) -> bool {
    let mut parts = version.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    [major, minor, patch]
        .iter()
        .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

fn rust_release_target() -> String {
    format!("{}_{}", goos(), goarch())
}

fn goos() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "windows",
        "linux" => "linux",
        "freebsd" => "freebsd",
        other => other,
    }
}

fn goarch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "x86" => "386",
        "aarch64" => "arm64",
        "arm" => "arm",
        "mips" => "mips",
        "mipsel" => "mipsle",
        "s390x" => "s390x",
        "riscv64" => "riscv64",
        "loongarch64" => "loong64",
        other => other,
    }
}

enum UpdateLock {
    Acquired(UpdateLockGuard),
    WaitedForPeer,
}

struct UpdateLockGuard {
    path: PathBuf,
}

impl Drop for UpdateLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn acquire_update_lock() -> Result<UpdateLock> {
    let path = update_lock_path()?;
    let Some(parent) = path.parent() else {
        return Ok(UpdateLock::Acquired(UpdateLockGuard { path }));
    };
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create update lock dir {}", parent.display()))?;
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(_) => Ok(UpdateLock::Acquired(UpdateLockGuard { path })),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            let deadline = Instant::now() + Duration::from_secs(10 * 60);
            while path.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_secs(1));
            }
            if path.exists() {
                let _ = fs::remove_file(&path);
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .with_context(|| format!("failed to recreate {}", path.display()))?;
                return Ok(UpdateLock::Acquired(UpdateLockGuard { path }));
            }
            Ok(UpdateLock::WaitedForPeer)
        }
        Err(err) => Err(err).with_context(|| format!("failed to create {}", path.display())),
    }
}

fn update_lock_path() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("failed to resolve current executable")?;
    let hash = stable_path_hash(&executable.to_string_lossy());
    Ok(std::env::temp_dir()
        .join(BINARY_NAME)
        .join(format!("agent-{hash:08x}.stat")))
}

fn stable_path_hash(path: &str) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in path.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_guard_matches_upstream_auto_update_gate() {
        assert!(version_looks_semver("1.2.3"));
        assert!(!version_looks_semver("nezha-agent"));
        assert!(!version_looks_semver("1.2"));
        assert!(!version_looks_semver("1.2.3-beta"));
    }

    #[test]
    fn provider_flags_follow_upstream_precedence() {
        set_cached_country_code("");
        assert_eq!(
            provider_for_config(&AgentConfig::default()),
            UpdateProvider::GitHub
        );
        assert_eq!(
            provider_for_config(&AgentConfig {
                use_atomgit_to_upgrade: true,
                ..AgentConfig::default()
            }),
            UpdateProvider::AtomGit
        );
        assert_eq!(
            provider_for_config(&AgentConfig {
                use_gitee_to_upgrade: true,
                use_atomgit_to_upgrade: true,
                ..AgentConfig::default()
            }),
            UpdateProvider::Gitee
        );
    }

    #[test]
    fn country_code_can_select_cn_mirrors_when_flags_are_unset() {
        set_cached_country_code("CN");
        assert!(matches!(
            provider_for_config(&AgentConfig::default()),
            UpdateProvider::Gitee | UpdateProvider::AtomGit
        ));
        set_cached_country_code("");
    }

    #[test]
    fn auto_update_policy_respects_disable_flag_and_period() {
        assert!(!auto_update_allowed(&AgentConfig {
            disable_auto_update: true,
            ..AgentConfig::default()
        }));
        assert!(auto_update_allowed(&AgentConfig::default()));

        assert_eq!(
            auto_update_period(&AgentConfig {
                self_update_period: 5,
                ..AgentConfig::default()
            }),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn release_source_matches_rust_release_repo() {
        assert_eq!(RELEASE_REPO_OWNER, "nezha-rs");
        assert_eq!(RELEASE_REPO_NAME, "nezha-rs");
    }

    #[test]
    fn release_target_uses_installer_asset_os_arch_names() {
        let target = rust_release_target();
        assert!(target.contains('_'));
        assert!(!target.contains("x86_64"));
        assert!(!target.contains("macos"));
    }

    #[test]
    fn update_lock_path_is_scoped_like_upstream_stat_file() {
        let path = update_lock_path().unwrap();
        assert_eq!(
            path.parent().and_then(|path| path.file_name()).unwrap(),
            BINARY_NAME
        );
        assert!(
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("agent-") && name.ends_with(".stat"))
        );
    }
}
