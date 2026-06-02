use crate::models::{Dependency, Ecosystem};
use std::path::Path;
use tokio::process::Command;
use anyhow::Result;

pub struct RubyAdapter;

impl RubyAdapter {
    pub fn try_new() -> Result<Self> {
        Ok(Self)
    }

    pub async fn check_outdated(&self, dir: &Path) -> Result<Vec<Dependency>> {
        if !dir.join("Gemfile").exists() {
            return Ok(Vec::new());
        }

        let output = Command::new("bundle")
            .args(["outdated", "--parseable"])
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
        let mut dependencies = Vec::new();

        for raw_line in stdout_str.lines() {
            let trimmed_line = raw_line.trim();
            if trimmed_line.is_empty() {
                continue;
            }

            if let Some((package_name, rest)) = trimmed_line.split_once(" (newest ") {
                if let Some((newest_part, installed_part)) = rest.split_once(", installed ") {
                    let latest_version = newest_part.to_string();
                    let current_version_str = installed_part
                        .split_once(", requested ")
                        .map(|(version_part, _)| version_part)
                        .unwrap_or(installed_part)
                        .split_once(')')
                        .map(|(version_part, _)| version_part)
                        .unwrap_or(installed_part)
                        .to_string();

                    if package_name != "Unknown" && current_version_str != latest_version && latest_version != "Unknown" {
                        dependencies.push(Dependency {
                            name: package_name.to_string(),
                            current_version: current_version_str,
                            latest_version: latest_version,
                            ecosystem: Ecosystem::Ruby,
                            is_global: false,
                        });
                    }
                }
            }
        }

        Ok(dependencies)
    }
}
