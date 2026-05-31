use crate::models::{Dependency, Ecosystem};
use std::path::Path;
use anyhow::{Result, Context};
use serde::Deserialize;
use std::collections::HashMap;
use reqwest::Client;
use std::time::Duration;

#[derive(Deserialize, Debug)]
struct CargoToml {
    #[serde(default)]
    dependencies: HashMap<String, toml::Value>,
    #[serde(rename = "dev-dependencies", default)]
    dev_dependencies: HashMap<String, toml::Value>,
    #[serde(rename = "build-dependencies", default)]
    build_dependencies: HashMap<String, toml::Value>,
}

pub struct CargoAdapter {
    client: Client,
}

impl CargoAdapter {
    pub fn try_new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .user_agent("tucupi/0.1.0 (contact@example.com)")
            .build()?;
        Ok(Self { client })
    }

    pub async fn check_outdated(&self, dir: &Path) -> Result<Vec<Dependency>> {
        let cargo_toml_path = dir.join("Cargo.toml");
        if !cargo_toml_path.exists() {
            return Ok(Vec::new());
        }

        let content = tokio::fs::read_to_string(&cargo_toml_path)
            .await
            .context("Failed to read Cargo.toml")?;

        let parsed: CargoToml = toml::from_str(&content)
            .context("Failed to parse Cargo.toml")?;

        let mut deps_to_check = HashMap::new();

        let mut extract = |map: HashMap<String, toml::Value>| {
            for (name, val) in map {
                if let Some(ver_str) = val.as_str() {
                    deps_to_check.insert(name, ver_str.to_string());
                } else if let Some(table) = val.as_table() {
                    if let Some(ver_val) = table.get("version") {
                        if let Some(ver_str) = ver_val.as_str() {
                            deps_to_check.insert(name, ver_str.to_string());
                        }
                    }
                }
            }
        };

        extract(parsed.dependencies);
        extract(parsed.dev_dependencies);
        extract(parsed.build_dependencies);

        let mut outdated = Vec::new();
        let mut tasks = Vec::new();

        for (name, current_constraint) in deps_to_check {
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
                                let clean_current = current_constraint.trim_start_matches(|c| c == '^' || c == '=' || c == '~');
                                if clean_current != latest && !latest.is_empty() {
                                    let is_newer = if let (Ok(cur), Ok(lat)) = (semver::Version::parse(clean_current), semver::Version::parse(&latest)) {
                                        lat > cur
                                    } else {
                                        clean_current != latest
                                    };

                                    if is_newer {
                                        return Some(Dependency {
                                            name,
                                            current_version: current_constraint,
                                            latest_version: latest,
                                            ecosystem: Ecosystem::Cargo,
                                            is_global: false,
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
                outdated.push(dep);
            }
        }

        Ok(outdated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_cargo_adapter_outdated() {
        let mock_path = PathBuf::from("../mock-project");
        if !mock_path.exists() {
            return;
        }
        let adapter = CargoAdapter::try_new().unwrap();
        let outdated = adapter.check_outdated(&mock_path).await.unwrap();
        
        assert!(!outdated.is_empty(), "Mock project should have outdated dependencies");
        
        let anyhow_dep = outdated.iter().find(|d| d.name == "anyhow");
        assert!(anyhow_dep.is_some(), "Should detect anyhow as outdated");
        
        let serde_dep = outdated.iter().find(|d| d.name == "serde");
        assert!(serde_dep.is_some(), "Should detect serde as outdated");
    }
}

