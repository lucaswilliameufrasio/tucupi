use crate::models::{Dependency, Ecosystem};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;
use tokio::process::Command;

pub struct PhpAdapter;

impl PhpAdapter {
    pub fn try_new() -> Result<Self> {
        Ok(Self)
    }

    pub async fn check_outdated(&self, dir: &Path) -> Result<Vec<Dependency>> {
        if !dir.join("composer.json").exists() {
            return Ok(Vec::new());
        }

        let output = Command::new("composer")
            .args(["outdated", "--format=json", "--no-interaction", "--no-ansi"])
            .current_dir(dir)
            .output()
            .await;

        let output = match output {
            Ok(out) => out,
            Err(_) => return Ok(Vec::new()),
        };

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let parsed_json: Value = match serde_json::from_str(&stdout_str) {
            Ok(value) => value,
            Err(_) => return Ok(Vec::new()),
        };

        let mut dependencies = Vec::new();

        if let Some(installed) = parsed_json["installed"].as_array() {
            for package in installed {
                let name = package["name"].as_str().unwrap_or("Unknown").to_string();
                let version = package["version"].as_str().unwrap_or("Unknown").to_string();
                let latest = package["latest"].as_str().unwrap_or("Unknown").to_string();

                if name != "Unknown" && version != latest && latest != "Unknown" {
                    dependencies.push(Dependency {
                        name,
                        current_version: version,
                        latest_version: latest,
                        ecosystem: Ecosystem::Php,
                        is_global: false,
                        origin: None,
                    });
                }
            }
        }

        Ok(dependencies)
    }
}
