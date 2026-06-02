use crate::models::{Dependency, Ecosystem};
use std::path::Path;
use tokio::process::Command;
use anyhow::Result;

pub struct PacmanAdapter;

impl PacmanAdapter {
    pub fn try_new() -> Result<Self> {
        Ok(Self)
    }

    pub async fn check_outdated(&self, dir: &Path) -> Result<Vec<Dependency>> {
        if !dir.join("PKGBUILD").exists() && !dir.join(".SRCINFO").exists() {
            let has_pacman = Command::new("which").arg("pacman").output().await;
            if has_pacman.is_err() || !has_pacman.unwrap().status.success() {
                return Ok(Vec::new());
            }
        }

        let mut deps = Vec::new();
        let _dir = dir; // unused but kept for signature consistency

        let pacman_output = Command::new("pacman")
            .args(["-Qu"])
            .output()
            .await;

        if let Ok(output) = pacman_output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let name = parts[0].to_string();
                        let version_info = parts[1..].join(" ");
                        if let Some((current, latest)) = version_info.split_once(" -> ") {
                            let current_version = current.to_string();
                            let latest_version = latest.to_string();
                            if current_version != latest_version && latest_version != "Unknown" {
                                deps.push(Dependency {
                                    name,
                                    current_version,
                                    latest_version,
                                    ecosystem: Ecosystem::Pacman,
                                    is_global: true,
                                });
                            }
                        }
                    }
                }
            }
        }

        let paru_output = Command::new("paru")
            .args(["-Qua"])
            .output()
            .await;

        if let Ok(output) = paru_output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let name = parts[0].to_string();
                        let version_info = parts[1..].join(" ");
                        if let Some((current, latest)) = version_info.split_once(" -> ") {
                            let current_version = current.to_string();
                            let latest_version = latest.to_string();
                            if current_version != latest_version && latest_version != "Unknown" {
                                if !deps.iter().any(|d: &Dependency| d.name == name) {
                                    deps.push(Dependency {
                                        name,
                                        current_version,
                                        latest_version,
                                        ecosystem: Ecosystem::Pacman,
                                        is_global: true,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(deps)
    }
}
