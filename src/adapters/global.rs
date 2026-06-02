use crate::models::{Dependency, Ecosystem};
use tokio::process::Command;
use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use reqwest::Client;
use std::time::Duration;

pub struct GlobalAdapter {
    client: Client,
}

impl GlobalAdapter {
    pub fn try_new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .user_agent("tucupi/0.1.0 (contact@example.com)")
            .build()?;
        Ok(Self { client })
    }

    pub async fn check_outdated(&self) -> Result<Vec<Dependency>> {
        let mut outdated = Vec::new();

        if let Ok(npm_outdated) = self.check_npm_global().await {
            outdated.extend(npm_outdated);
        }

        if let Ok(pnpm_outdated) = self.check_pnpm_global().await {
            outdated.extend(pnpm_outdated);
        }

        if let Ok(bun_outdated) = self.check_bun_global().await {
            outdated.extend(bun_outdated);
        }

        if let Ok(cargo_outdated) = self.check_cargo_global().await {
            outdated.extend(cargo_outdated);
        }

        Ok(outdated)
    }

    async fn check_npm_global(&self) -> Result<Vec<Dependency>> {
        let output = Command::new("npm")
            .args(["outdated", "-g", "--json"])
            .output()
            .await;

        let output = match output {
            Ok(out) => out,
            Err(_) => return Ok(Vec::new()),
        };

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        if stdout_str.trim().is_empty() || stdout_str.trim() == "{}" {
            return Ok(Vec::new());
        }

        #[derive(Deserialize)]
        struct NpmOutdatedItem {
            current: Option<String>,
            latest: Option<String>,
        }

        let mut deps = Vec::new();
        if let Ok(parsed) = serde_json::from_str::<HashMap<String, NpmOutdatedItem>>(&stdout_str) {
            for (name, item) in parsed {
                let current = item.current.unwrap_or_else(|| "Unknown".to_string());
                let latest = item.latest.unwrap_or_else(|| "Unknown".to_string());
                if current != latest && latest != "Unknown" {
                    deps.push(Dependency {
                        name,
                        current_version: current,
                        latest_version: latest,
                        ecosystem: Ecosystem::Npm,
                        is_global: true,
                    });
                }
            }
        }

        Ok(deps)
    }

    async fn check_cargo_global(&self) -> Result<Vec<Dependency>> {
        let output = Command::new("cargo")
            .args(["install", "--list"])
            .output()
            .await;

        let output = match output {
            Ok(out) => out,
            Err(_) => return Ok(Vec::new()),
        };

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let mut installed_crates = HashMap::new();

        for line in stdout_str.lines() {
            if line.ends_with(':') && line.contains(' ') {
                let parts: Vec<&str> = line.trim_end_matches(':').split_whitespace().collect();
                if parts.len() == 2 && parts[1].starts_with('v') {
                    let name = parts[0].to_string();
                    let version = parts[1][1..].to_string();
                    installed_crates.insert(name, version);
                }
            }
        }

        let mut deps = Vec::new();
        if installed_crates.is_empty() {
            return Ok(deps);
        }

        let mut tasks = Vec::new();
        for (name, current) in installed_crates {
            let client = self.client.clone();
            tasks.push(tokio::spawn(async move {
                let url = format!("https://crates.io/api/v1/crates/{}", name);
                let response = client.get(&url).send().await;
                match response {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            #[derive(Deserialize)]
                            struct CrateInfo {
                                max_version: String,
                            }
                            #[derive(Deserialize)]
                            struct CratesIoResponse {
                                #[serde(rename = "crate")]
                                krate: CrateInfo,
                            }
                            if let Ok(crates_resp) = resp.json::<CratesIoResponse>().await {
                                let latest = crates_resp.krate.max_version;
                                if current != latest && !latest.is_empty() {
                                    let is_newer = if let (Ok(cur), Ok(lat)) = (semver::Version::parse(&current), semver::Version::parse(&latest)) {
                                        lat > cur
                                    } else {
                                        current != latest
                                    };

                                    if is_newer {
                                        return Some(Dependency {
                                            name,
                                            current_version: current,
                                            latest_version: latest,
                                            ecosystem: Ecosystem::Cargo,
                                            is_global: true,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {}
                }
                None
            }));
        }

        for task in tasks {
            if let Ok(Some(dep)) = task.await {
                deps.push(dep);
            }
        }

        Ok(deps)
    }

    async fn check_pnpm_global(&self) -> Result<Vec<Dependency>> {
        let output = Command::new("pnpm")
            .args(["outdated", "-g", "--json"])
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
        if stdout_str.trim().is_empty() || stdout_str.trim() == "{}" {
            return Ok(Vec::new());
        }

        #[derive(Deserialize)]
        struct PkgItem {
            current: Option<String>,
            latest: Option<String>,
        }

        let mut deps = Vec::new();
        if let Ok(parsed) = serde_json::from_str::<std::collections::HashMap<String, PkgItem>>(&stdout_str) {
            for (name, item) in parsed {
                let current = item.current.unwrap_or_else(|| "Unknown".to_string());
                let latest = item.latest.unwrap_or_else(|| "Unknown".to_string());
                if current != latest && latest != "Unknown" {
                    deps.push(Dependency {
                        name,
                        current_version: current,
                        latest_version: latest,
                        ecosystem: Ecosystem::Npm,
                        is_global: true,
                    });
                }
            }
        }

        Ok(deps)
    }

    async fn check_bun_global(&self) -> Result<Vec<Dependency>> {
        let output = Command::new("bun")
            .args(["pm", "ls", "-g"])
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
        let mut deps = Vec::new();

        for line in stdout_str.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || !trimmed.contains('@') || trimmed.starts_with('/') {
                continue;
            }

            let parts: Vec<&str> = trimmed.splitn(2, '@').collect();
            if parts.len() == 2 {
                let name = parts[0].to_string();
                let current = parts[1].to_string();

                let check_url = format!("https://registry.npmjs.org/{}/latest", name);
                let client = self.client.clone();
                if let Ok(resp) = client.get(&check_url).send().await {
                    if resp.status().is_success() {
                        #[derive(Deserialize)]
                        struct LatestVersion {
                            version: String,
                        }
                        if let Ok(lv) = resp.json::<LatestVersion>().await {
                            let latest = lv.version;
                            if current != latest && latest != "Unknown" {
                                deps.push(Dependency {
                                    name,
                                    current_version: current,
                                    latest_version: latest,
                                    ecosystem: Ecosystem::Npm,
                                    is_global: true,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(deps)
    }
}
