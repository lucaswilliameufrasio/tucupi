use crate::models::{Dependency, Ecosystem};
use anyhow::Result;
use std::path::Path;
use tokio::process::Command;

pub struct MiseAdapter;

impl MiseAdapter {
    pub fn try_new() -> Result<Self> {
        Ok(Self)
    }

    pub async fn check_outdated(&self, dir: &Path) -> Result<Vec<Dependency>> {
        let has_mise = Command::new("which").arg("mise").output().await;
        if has_mise.is_err() || !has_mise.unwrap().status.success() {
            return Ok(Vec::new());
        }

        let _dir = dir;
        let mut deps = Vec::new();

        let output = Command::new("mise").args(["outdated"]).output().await;

        let output = match output {
            Ok(out) => out,
            Err(_) => return Ok(Vec::new()),
        };

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("Plugin") || line.starts_with("---") {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let name = parts[0].to_string();
                let current_version = parts[1].to_string();
                let latest_version = parts[2].to_string();

                if current_version != latest_version && latest_version != "Unknown" {
                    deps.push(Dependency {
                        name,
                        current_version,
                        latest_version,
                        ecosystem: Ecosystem::Mise,
                        is_global: true,
                    });
                }
            }
        }

        Ok(deps)
    }
}
