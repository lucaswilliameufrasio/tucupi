use crate::models::{Dependency, Ecosystem};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;
use tokio::process::Command;

pub struct PythonAdapter;

impl PythonAdapter {
    pub fn try_new() -> Result<Self> {
        Ok(Self)
    }

    pub async fn check_outdated(&self, dir: &Path) -> Result<Vec<Dependency>> {
        let has_pyproject = dir.join("pyproject.toml").exists();
        let has_requirements = dir.join("requirements.txt").exists();

        if !has_pyproject && !has_requirements {
            return Ok(Vec::new());
        }

        let pip = if cfg!(windows) { "pip" } else { "pip3" };

        let output = Command::new(pip)
            .args(["list", "--outdated", "--format=json"])
            .current_dir(dir)
            .output()
            .await;

        let output = match output {
            Ok(out) => out,
            Err(_) => {
                let output = Command::new("pip")
                    .args(["list", "--outdated", "--format=json"])
                    .current_dir(dir)
                    .output()
                    .await;
                match output {
                    Ok(out) => out,
                    Err(_) => return Ok(Vec::new()),
                }
            }
        };

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout_string = String::from_utf8_lossy(&output.stdout);
        let parsed_json: Value = match serde_json::from_str(&stdout_string) {
            Ok(value) => value,
            Err(_) => return Ok(Vec::new()),
        };

        let mut dependencies = Vec::new();

        if let Some(packages) = parsed_json.as_array() {
            for package in packages {
                let name = package["name"].as_str().unwrap_or("Unknown").to_string();
                let version = package["version"].as_str().unwrap_or("Unknown").to_string();
                let latest_version = package["latest_version"]
                    .as_str()
                    .unwrap_or("Unknown")
                    .to_string();

                if name != "Unknown" && version != latest_version && latest_version != "Unknown" {
                    dependencies.push(Dependency {
                        name,
                        current_version: version,
                        latest_version,
                        ecosystem: Ecosystem::Python,
                        is_global: false,
                    });
                }
            }
        }

        Ok(dependencies)
    }
}
