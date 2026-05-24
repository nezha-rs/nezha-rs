use std::{
    fs,
    io::{Cursor, Write},
    path::{Component, Path, PathBuf},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use include_dir::{Dir, include_dir};
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

const FRONTEND_TEMPLATES_YAML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../upstream/nezha/service/singleton/frontend-templates.yaml"
));

static FRONTEND_TEMPLATES: OnceLock<Vec<FrontendTemplate>> = OnceLock::new();
static EMBEDDED_FRONTENDS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../static");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct FrontendTemplate {
    pub(crate) path: String,
    pub(crate) name: String,
    pub(crate) repository: String,
    pub(crate) author: String,
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) is_admin: bool,
    #[serde(default)]
    pub(crate) is_official: bool,
}

pub(crate) fn templates() -> &'static [FrontendTemplate] {
    FRONTEND_TEMPLATES
        .get_or_init(|| {
            serde_yaml::from_str(FRONTEND_TEMPLATES_YAML)
                .expect("frontend template catalog is valid")
        })
        .as_slice()
}

pub(crate) fn has_user_template(path: &str) -> bool {
    templates()
        .iter()
        .any(|template| !template.is_admin && template.path == path)
}

pub(crate) fn embedded_asset(relative_path: &str) -> Option<&'static [u8]> {
    let path = normalize_embedded_path(relative_path)?;
    EMBEDDED_FRONTENDS.get_file(path)?.contents().into()
}

pub(crate) async fn sync_frontends(static_dir: &Path) -> Result<Vec<PathBuf>> {
    let client = reqwest::Client::builder()
        .user_agent(format!(
            "nezha-dashboard-rs/{} (+https://github.com/nezhahq/nezha-rs)",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .context("failed to build frontend sync client")?;

    let mut synced = Vec::new();
    for template in templates() {
        let release_url = release_zip_url(template);
        println!(
            "Syncing {} {} from {}",
            template.name, template.version, release_url
        );
        let payload = client
            .get(&release_url)
            .send()
            .await
            .with_context(|| format!("failed to download {release_url}"))?
            .error_for_status()
            .with_context(|| format!("release request failed for {release_url}"))?
            .bytes()
            .await
            .with_context(|| format!("failed to read payload {release_url}"))?;
        let bytes = payload.to_vec();
        let target_dir = static_dir.join(&template.path);
        let target_dir_for_extract = target_dir.clone();
        tokio::task::spawn_blocking(move || extract_dist_zip(&bytes, &target_dir_for_extract))
            .await
            .context("frontend extraction task failed")??;
        synced.push(target_dir);
    }
    Ok(synced)
}

fn release_zip_url(template: &FrontendTemplate) -> String {
    format!(
        "{}/releases/download/{}/dist.zip",
        template.repository.trim_end_matches('/'),
        template.version
    )
}

fn extract_dist_zip(bytes: &[u8], target_dir: &Path) -> Result<()> {
    if target_dir.exists() {
        fs::remove_dir_all(target_dir)
            .with_context(|| format!("failed to remove {}", target_dir.display()))?;
    }
    fs::create_dir_all(target_dir)
        .with_context(|| format!("failed to create {}", target_dir.display()))?;

    let temp_dir = temp_extract_dir(target_dir)?;
    fs::create_dir_all(&temp_dir)
        .with_context(|| format!("failed to create {}", temp_dir.display()))?;

    let extraction = (|| -> Result<()> {
        let mut archive =
            ZipArchive::new(Cursor::new(bytes)).context("invalid dist.zip archive")?;
        let mut extracted_files = 0usize;
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .with_context(|| format!("failed to read zip entry #{index}"))?;
            let Some(raw_name) = entry.enclosed_name().map(PathBuf::from) else {
                continue;
            };
            let Some(relative_path) = archive_output_path(&raw_name) else {
                continue;
            };
            let output_path = temp_dir.join(relative_path);
            if entry.is_dir() {
                fs::create_dir_all(&output_path)
                    .with_context(|| format!("failed to create {}", output_path.display()))?;
                continue;
            }
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            let mut output = fs::File::create(&output_path)
                .with_context(|| format!("failed to create {}", output_path.display()))?;
            std::io::copy(&mut entry, &mut output)
                .with_context(|| format!("failed to extract {}", output_path.display()))?;
            output
                .flush()
                .with_context(|| format!("failed to flush {}", output_path.display()))?;
            extracted_files += 1;
        }
        if extracted_files == 0 {
            bail!("dist.zip did not contain any extractable files");
        }
        Ok(())
    })();

    if extraction.is_err() {
        let _ = fs::remove_dir_all(&temp_dir);
        return extraction;
    }

    copy_dir_contents(&temp_dir, target_dir)?;
    let _ = fs::remove_dir_all(&temp_dir);
    Ok(())
}

fn archive_output_path(path: &Path) -> Option<PathBuf> {
    let mut components = path.components().peekable();
    if components
        .peek()
        .is_some_and(|component| {
            matches!(component, Component::Normal(name) if *name == std::ffi::OsStr::new("dist"))
        })
    {
        components.next();
    }

    let mut relative = PathBuf::new();
    for component in components {
        if let Component::Normal(part) = component {
            relative.push(part);
        }
    }

    (!relative.as_os_str().is_empty()).then_some(relative)
}

fn normalize_embedded_path(path: &str) -> Option<String> {
    let mut normalized = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    let path = normalized.to_string_lossy().replace('\\', "/");
    (!path.is_empty()).then_some(path)
}

fn copy_dir_contents(source: &Path, target: &Path) -> Result<()> {
    for entry in
        fs::read_dir(source).with_context(|| format!("failed to read {}", source.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read entry in {}", source.display()))?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        if entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", source_path.display()))?
            .is_dir()
        {
            fs::create_dir_all(&target_path)
                .with_context(|| format!("failed to create {}", target_path.display()))?;
            copy_dir_contents(&source_path, &target_path)?;
        } else {
            fs::copy(&source_path, &target_path).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    source_path.display(),
                    target_path.display()
                )
            })?;
        }
    }
    Ok(())
}

fn temp_extract_dir(target_dir: &Path) -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock drifted before unix epoch")?
        .as_nanos();
    let name = target_dir
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("invalid template target {}", target_dir.display()))?;
    Ok(std::env::temp_dir().join(format!("nezha-frontend-{name}-{nanos}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_yaml_matches_upstream_catalog() {
        let templates = templates();
        assert_eq!(templates.len(), 4);
        assert!(templates.iter().any(|template| {
            template.path == "admin-dist"
                && template.is_admin
                && template.is_official
                && template.version == "v2.0.7"
        }));
        assert!(templates.iter().any(|template| {
            template.path == "user-dist"
                && !template.is_admin
                && template.is_official
                && template.version == "v2.0.3"
        }));
        assert!(
            templates
                .iter()
                .any(|template| template.path == "nazhua-dist")
        );
        assert!(
            templates
                .iter()
                .any(|template| template.path == "nezha-ascii-dist")
        );
    }

    #[test]
    fn user_template_validation_follows_catalog() {
        assert!(has_user_template("user-dist"));
        assert!(has_user_template("nazhua-dist"));
        assert!(!has_user_template("admin-dist"));
        assert!(!has_user_template("missing-dist"));
    }

    #[test]
    fn embedded_assets_are_available_for_synced_frontends() {
        assert!(embedded_asset("user-dist/index.html").is_some());
        assert!(embedded_asset("admin-dist/index.html").is_some());
    }

    #[test]
    fn release_zip_url_matches_upstream_fetch_script_shape() {
        let template = FrontendTemplate {
            path: "user-dist".to_string(),
            name: "Official".to_string(),
            repository: "https://github.com/example/frontend".to_string(),
            author: "example".to_string(),
            version: "v1.2.3".to_string(),
            is_admin: false,
            is_official: true,
        };
        assert_eq!(
            release_zip_url(&template),
            "https://github.com/example/frontend/releases/download/v1.2.3/dist.zip"
        );
    }

    #[test]
    fn archive_output_path_strips_top_level_dist_dir() {
        assert_eq!(
            archive_output_path(Path::new("dist/assets/logo.png")),
            Some(PathBuf::from("assets/logo.png"))
        );
        assert_eq!(
            archive_output_path(Path::new("index.html")),
            Some(PathBuf::from("index.html"))
        );
        assert_eq!(archive_output_path(Path::new("dist")), None);
    }
}
