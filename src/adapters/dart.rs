use crate::models::{Dependency, Ecosystem};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;
use tokio::process::Command;

pub struct DartAdapter;

impl DartAdapter {
    pub fn try_new() -> Result<Self> {
        Ok(Self)
    }

    pub async fn check_outdated(&self, dir: &Path) -> Result<Vec<Dependency>> {
        let output = Command::new("dart")
            .args(["pub", "outdated", "--json"])
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

        let parsed: Value =
            serde_json::from_slice(&output.stdout).context("Failed to parse dart pub JSON")?;

        let mut deps = Vec::new();

        if let Some(packages) = parsed["packages"].as_array() {
            for pkg in packages {
                let name = pkg["package"].as_str().unwrap_or("Unknown").to_string();
                let current = pkg["current"]["version"]
                    .as_str()
                    .unwrap_or("Unknown")
                    .to_string();

                if let Some(upgradable) = pkg.get("upgradable") {
                    let latest = upgradable["version"]
                        .as_str()
                        .unwrap_or("Unknown")
                        .to_string();
                    if !name.is_empty()
                        && name != "Unknown"
                        && current != latest
                        && latest != "Unknown"
                    {
                        deps.push(Dependency {
                            name,
                            current_version: current,
                            latest_version: latest,
                            ecosystem: Ecosystem::Dart,
                            is_global: false,
                        });
                    }
                }
            }
        }

        Ok(deps)
    }
}
