use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

use serde_json::{Map, Value, json};

#[derive(Debug, Default)]
struct SwaggerMeta {
    title: String,
    version: String,
    description: String,
    terms_of_service: String,
    contact_name: String,
    contact_url: String,
    contact_email: String,
    license_name: String,
    license_url: String,
    host: String,
    base_path: String,
    security_schemes: Vec<String>,
    external_docs_description: String,
    external_docs_url: String,
}

#[derive(Debug, Default)]
struct OperationDoc {
    summary: String,
    description: String,
    tags: Vec<String>,
    parameters: Vec<Value>,
    request_body: Option<Value>,
    responses: Map<String, Value>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let upstream_dashboard = manifest_dir.join("../../upstream/nezha/cmd/dashboard");
    let upstream_frontend_templates_yaml =
        manifest_dir.join("../../upstream/nezha/service/singleton/frontend-templates.yaml");
    let vendored_frontend_templates_yaml = manifest_dir.join("assets/frontend-templates.yaml");
    let upstream_waf_html = upstream_dashboard.join("controller/waf/waf.html");
    let vendored_waf_html = manifest_dir.join("assets/waf.html");
    let static_dir = manifest_dir.join("../../static");
    let controller_dir = upstream_dashboard.join("controller");
    let main_go = upstream_dashboard.join("main.go");
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    println!("cargo:rerun-if-changed={}", main_go.display());
    println!("cargo:rerun-if-changed={}", controller_dir.display());
    println!(
        "cargo:rerun-if-changed={}",
        upstream_frontend_templates_yaml.display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        vendored_frontend_templates_yaml.display()
    );
    println!("cargo:rerun-if-changed={}", upstream_waf_html.display());
    println!("cargo:rerun-if-changed={}", vendored_waf_html.display());
    println!("cargo:rerun-if-changed={}", static_dir.display());

    let frontend_templates_yaml = if upstream_frontend_templates_yaml.exists() {
        upstream_frontend_templates_yaml
    } else {
        vendored_frontend_templates_yaml
    };
    ensure_frontend_static_dirs(&static_dir, &frontend_templates_yaml)?;

    let waf_html = if upstream_waf_html.exists() {
        upstream_waf_html
    } else {
        vendored_waf_html
    };
    fs::copy(&waf_html, out_dir.join("waf.html"))?;

    let mut paths = BTreeMap::<String, Map<String, Value>>::new();
    let meta = if main_go.exists() && controller_dir.exists() {
        let meta = parse_main_annotations(&fs::read_to_string(&main_go)?);
        let security_scheme = meta.security_schemes.first().map(String::as_str);
        for file in go_files(&controller_dir)? {
            println!("cargo:rerun-if-changed={}", file.display());
            parse_controller_annotations(
                &fs::read_to_string(&file)?,
                &meta.base_path,
                &mut paths,
                security_scheme,
            );
        }
        meta
    } else {
        println!(
            "cargo:warning=upstream Go sources not found at {}; emitting minimal swagger doc",
            upstream_dashboard.display()
        );
        SwaggerMeta::default()
    };

    let security_schemes = if meta.security_schemes.is_empty() {
        Map::new()
    } else {
        Map::from_iter(meta.security_schemes.iter().map(|name| {
            (
                name.clone(),
                json!({
                    "type": "apiKey",
                    "name": "Authorization",
                    "in": "header"
                }),
            )
        }))
    };

    let document = json!({
        "openapi": "3.0.3",
        "info": {
            "title": value_or_default(&meta.title, "Nezha Monitoring API"),
            "version": value_or_default(&meta.version, "1.0"),
            "description": value_or_default(&meta.description, "Nezha Monitoring API"),
            "termsOfService": empty_to_none(&meta.terms_of_service),
            "contact": empty_to_none_object([
                ("name", meta.contact_name.as_str()),
                ("url", meta.contact_url.as_str()),
                ("email", meta.contact_email.as_str()),
            ]),
            "license": empty_to_none_object([
                ("name", meta.license_name.as_str()),
                ("url", meta.license_url.as_str()),
            ]),
        },
        "servers": [
            { "url": "/" }
        ],
        "paths": paths,
        "components": {
            "securitySchemes": security_schemes
        },
        "externalDocs": empty_to_none_object([
            ("description", meta.external_docs_description.as_str()),
            ("url", meta.external_docs_url.as_str()),
        ]),
    });

    fs::write(
        out_dir.join("swagger-doc.json"),
        serde_json::to_vec_pretty(&document)?,
    )?;
    Ok(())
}

fn ensure_frontend_static_dirs(
    static_dir: &Path,
    frontend_templates_yaml: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(static_dir)?;
    let yaml = fs::read_to_string(frontend_templates_yaml)?;
    for line in yaml.lines() {
        let line = line.trim();
        let Some(path) = line
            .strip_prefix("path:")
            .or_else(|| line.strip_prefix("- path:"))
        else {
            continue;
        };
        let path = path.trim().trim_matches('"');
        if path.is_empty() {
            continue;
        }
        fs::create_dir_all(static_dir.join(path))?;
    }
    Ok(())
}

fn parse_main_annotations(source: &str) -> SwaggerMeta {
    let mut meta = SwaggerMeta::default();
    for line in source.lines() {
        let Some(line) = line.trim().strip_prefix("// @") else {
            continue;
        };
        let (key, value) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let value = value.trim();
        match key {
            "title" => meta.title = value.to_string(),
            "version" => meta.version = value.to_string(),
            "description" => meta.description = value.to_string(),
            "termsOfService" => meta.terms_of_service = value.to_string(),
            "contact.name" => meta.contact_name = value.to_string(),
            "contact.url" => meta.contact_url = value.to_string(),
            "contact.email" => meta.contact_email = value.to_string(),
            "license.name" => meta.license_name = value.to_string(),
            "license.url" => meta.license_url = value.to_string(),
            "host" => meta.host = value.to_string(),
            "BasePath" => meta.base_path = normalize_base_path(value),
            "securityDefinitions.apikey" => meta.security_schemes.push(value.to_string()),
            "externalDocs.description" => meta.external_docs_description = value.to_string(),
            "externalDocs.url" => meta.external_docs_url = value.to_string(),
            _ => {}
        }
    }
    meta
}

fn parse_controller_annotations(
    source: &str,
    base_path: &str,
    paths: &mut BTreeMap<String, Map<String, Value>>,
    security_scheme: Option<&str>,
) {
    let mut current = OperationDoc::default();
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(annotation) = trimmed.strip_prefix("// @") {
            let (key, value) = annotation
                .split_once(char::is_whitespace)
                .unwrap_or((annotation, ""));
            let value = value.trim();
            match key {
                "Summary" => current.summary = value.to_string(),
                "Description" => {
                    if !current.description.is_empty() {
                        current.description.push('\n');
                    }
                    current.description.push_str(value);
                }
                "Tags" => current.tags = split_csv(value),
                "Param" => parse_param(value, &mut current),
                "Success" | "Failure" => parse_response(key, value, &mut current),
                "Router" => {
                    if let Some((path, method)) = parse_router(value, base_path) {
                        let operation = build_operation(&current, security_scheme);
                        paths.entry(path).or_default().insert(method, operation);
                    }
                    current = OperationDoc::default();
                }
                _ => {}
            }
        } else if !trimmed.starts_with("//") && !trimmed.is_empty() && !current.summary.is_empty() {
            current = OperationDoc::default();
        }
    }
}

fn parse_param(value: &str, operation: &mut OperationDoc) {
    let mut parts = value.split_whitespace();
    let name = parts.next().unwrap_or_default();
    let location = parts.next().unwrap_or_default();
    let schema_type = parts.next().unwrap_or("string");
    let required = parts
        .next()
        .is_some_and(|required| required.eq_ignore_ascii_case("true"));
    let description = extract_quoted(value).unwrap_or_else(|| name.to_string());

    if location.eq_ignore_ascii_case("body") {
        operation.request_body = Some(json!({
            "required": required,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "description": format!("Request body: {schema_type}")
                    }
                }
            },
            "description": description,
        }));
        return;
    }

    operation.parameters.push(json!({
        "name": name,
        "in": normalize_param_location(location),
        "required": required || location.eq_ignore_ascii_case("path"),
        "description": description,
        "schema": {
            "type": normalize_schema_type(schema_type)
        }
    }));
}

fn parse_response(kind: &str, value: &str, operation: &mut OperationDoc) {
    let mut parts = value.split_whitespace();
    let status = parts.next().unwrap_or("200").to_string();
    let schema = parts.nth(1).unwrap_or("any");
    let description = if kind == "Success" {
        format!("Success response: {schema}")
    } else {
        format!("Failure response: {schema}")
    };
    operation.responses.insert(
        status,
        json!({
            "description": description
        }),
    );
}

fn parse_router(value: &str, base_path: &str) -> Option<(String, String)> {
    let (path, method) = value.rsplit_once('[')?;
    let method = method.trim_end_matches(']').trim().to_ascii_lowercase();
    let mut path = path.trim().to_string();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !base_path.is_empty() && !path.starts_with(base_path) {
        path = format!("{base_path}{path}");
    }
    Some((path, method))
}

fn build_operation(operation: &OperationDoc, security_scheme: Option<&str>) -> Value {
    let mut value = json!({
        "summary": operation.summary,
        "description": if operation.description.is_empty() {
            operation.summary.clone()
        } else {
            operation.description.clone()
        },
        "tags": operation.tags,
        "responses": if operation.responses.is_empty() {
            Map::from_iter([("200".to_string(), json!({"description": "Success"}))])
        } else {
            operation.responses.clone()
        },
    });

    if !operation.parameters.is_empty() {
        value["parameters"] = Value::Array(operation.parameters.clone());
    }
    if let Some(request_body) = &operation.request_body {
        value["requestBody"] = request_body.clone();
    }
    if operation
        .tags
        .iter()
        .any(|tag| tag.contains("auth required") || tag.contains("admin required"))
    {
        let scheme = security_scheme.unwrap_or("BearerAuth");
        value["security"] = json!([{ scheme: [] }]);
    }
    value
}

fn go_files(dir: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            files.extend(go_files(&path)?);
            continue;
        }
        if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("go"))
            && !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with("_test.go"))
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn normalize_base_path(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        String::new()
    } else if value.starts_with('/') {
        value.trim_end_matches('/').to_string()
    } else {
        format!("/{}", value.trim_end_matches('/'))
    }
}

fn normalize_param_location(location: &str) -> &'static str {
    match location {
        "query" => "query",
        "path" => "path",
        "header" => "header",
        "cookie" => "cookie",
        _ => "query",
    }
}

fn normalize_schema_type(raw: &str) -> &'static str {
    let raw = raw.trim();
    if raw.starts_with("[]") || raw.eq_ignore_ascii_case("array") {
        return "array";
    }
    if raw.eq_ignore_ascii_case("int")
        || raw.eq_ignore_ascii_case("uint")
        || raw.eq_ignore_ascii_case("int64")
        || raw.eq_ignore_ascii_case("uint64")
        || raw.eq_ignore_ascii_case("integer")
    {
        return "integer";
    }
    if raw.eq_ignore_ascii_case("bool") || raw.eq_ignore_ascii_case("boolean") {
        return "boolean";
    }
    "string"
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn extract_quoted(value: &str) -> Option<String> {
    let start = value.find('"')?;
    let rest = &value[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn empty_to_none(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn empty_to_none_object<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<Value> {
    let map = Map::from_iter(pairs.into_iter().filter_map(|(key, value)| {
        empty_to_none(value).map(|value| (key.to_string(), json!(value)))
    }));
    (!map.is_empty()).then_some(Value::Object(map))
}

fn value_or_default<'a>(value: &'a str, default: &'a str) -> &'a str {
    let value = value.trim();
    if value.is_empty() { default } else { value }
}
