use crate::models::{Dependency, Ecosystem};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;
use tokio::process::Command;

pub struct MiseAdapter;

impl MiseAdapter {
    pub fn try_new() -> Result<Self> {
        Ok(Self)
    }

    pub async fn check_outdated(&self, _dir: &Path) -> Result<Vec<Dependency>> {
        let has_mise = Command::new("which").arg("mise").output().await;
        if has_mise.is_err() || !has_mise.unwrap().status.success() {
            return Ok(Vec::new());
        }

        let output = Command::new("mise")
            .args(["outdated", "--json"])
            .output()
            .await;

        let output = match output {
            Ok(out) if out.status.success() => out,
            _ => return Ok(Vec::new()),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_mise_outdated_json(&stdout))
    }
}

fn parse_mise_outdated_json(stdout: &str) -> Vec<Dependency> {
    let parsed: Value = match serde_json::from_str(stdout) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };

    let entries: Vec<Value> = match parsed {
        Value::Object(map) => map.into_values().collect(),
        Value::Array(items) => items,
        _ => return Vec::new(),
    };

    let mut deps = Vec::new();
    for entry in entries {
        let name = entry.get("name").and_then(Value::as_str);
        let current_version = entry.get("current").and_then(Value::as_str);
        let latest_version = entry.get("latest").and_then(Value::as_str);

        let (Some(name), Some(current_version), Some(latest_version)) =
            (name, current_version, latest_version)
        else {
            continue;
        };

        let is_valid_version =
            |version: &str| !version.is_empty() && !version.eq_ignore_ascii_case("unknown");

        if !is_valid_version(latest_version) || !is_valid_version(current_version) {
            continue;
        }

        if strip_build_metadata(current_version) == strip_build_metadata(latest_version) {
            continue;
        }

        deps.push(Dependency {
            name: name.to_string(),
            current_version: current_version.to_string(),
            latest_version: latest_version.to_string(),
            ecosystem: Ecosystem::Mise,
            is_global: true,
            origin: None,
        });
    }

    deps
}

fn strip_build_metadata(version: &str) -> &str {
    version.split('+').next().unwrap_or(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mise_outdated_json_reads_current_and_latest_columns() {
        let sample = r#"{
            "go": {
                "name": "go",
                "requested": "latest",
                "current": "1.26.6",
                "bump": null,
                "latest": "1.27.0",
                "source": {"type": "mise.toml", "path": "/home/user/.config/mise/config.toml"}
            },
            "python": {
                "name": "python",
                "requested": "latest",
                "current": "3.14.3",
                "bump": null,
                "latest": "3.14.7",
                "source": {"type": "mise.toml", "path": "/home/user/.config/mise/config.toml"}
            }
        }"#;

        let deps = parse_mise_outdated_json(sample);

        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "go");
        assert_eq!(deps[0].current_version, "1.26.6");
        assert_eq!(deps[0].latest_version, "1.27.0");
        assert!(deps[0].is_global);
        assert_eq!(deps[1].current_version, "3.14.3");
        assert_eq!(deps[1].latest_version, "3.14.7");
    }

    #[test]
    fn parse_mise_outdated_json_skips_up_to_date_and_invalid_entries() {
        let sample = r#"{
            "node": {
                "name": "node",
                "requested": "latest",
                "current": "22.14.0",
                "latest": "22.14.0"
            },
            "deno": {
                "name": "deno",
                "requested": "2.1.0",
                "current": null,
                "latest": "2.4.0"
            },
            "terraform": {
                "name": "terraform",
                "requested": "latest",
                "current": "1.9.0",
                "latest": "Unknown"
            }
        }"#;

        let deps = parse_mise_outdated_json(sample);

        assert!(deps.is_empty());
    }

    #[test]
    fn parse_mise_outdated_json_accepts_array_format_and_ignores_garbage() {
        let array_sample = r#"[{"name": "go", "current": "1.26.6", "latest": "1.27.0"}]"#;
        let deps = parse_mise_outdated_json(array_sample);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].latest_version, "1.27.0");

        assert!(parse_mise_outdated_json("not json at all").is_empty());
        assert!(parse_mise_outdated_json("42").is_empty());
    }
}
