use crate::models::{Dependency, Ecosystem};
use std::path::Path;
use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use reqwest::Client;
use std::time::Duration;

#[derive(Deserialize, Debug)]
struct PackageJson {
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(rename = "devDependencies", default)]
    dev_dependencies: HashMap<String, String>,
}

#[derive(Deserialize, Debug)]
struct DenoJson {
    #[serde(default)]
    imports: HashMap<String, String>,
}

pub struct JsTsAdapter {
    client: Client,
}

impl JsTsAdapter {
    pub fn try_new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .build()?;
        Ok(Self { client })
    }

    pub async fn check_outdated(&self, dir: &Path) -> Result<Vec<Dependency>> {
        let mut deps_to_check = HashMap::new();

        // 1. package.json (Node/Bun/Yarn/PNPM)
        let package_json_path = dir.join("package.json");
        if package_json_path.exists() {
            if let Ok(content) = tokio::fs::read_to_string(&package_json_path).await {
                if let Ok(parsed) = serde_json::from_str::<PackageJson>(&content) {
                    for (name, ver) in parsed.dependencies {
                        deps_to_check.insert(name, (ver, Ecosystem::Npm));
                    }
                    for (name, ver) in parsed.dev_dependencies {
                        deps_to_check.insert(name, (ver, Ecosystem::Npm));
                    }
                }
            }
        }

        // 2. deno.json / deno.jsonc
        let deno_json_path = dir.join("deno.json");
        let deno_jsonc_path = dir.join("deno.jsonc");
        let deno_path = if deno_json_path.exists() {
            Some(deno_json_path)
        } else if deno_jsonc_path.exists() {
            Some(deno_jsonc_path)
        } else {
            None
        };

        if let Some(path) = deno_path {
            if let Ok(content) = tokio::fs::read_to_string(&path).await {
                let clean_content = if path.extension().map_or(false, |ext| ext == "jsonc") {
                    content.lines()
                        .map(|l| {
                            if let Some(idx) = l.find("//") {
                                &l[..idx]
                            } else {
                                l
                            }
                        })
                        .collect::<Vec<&str>>()
                        .join("\n")
                } else {
                    content
                };

                if let Ok(parsed) = serde_json::from_str::<DenoJson>(&clean_content) {
                    for (_name, import_url) in parsed.imports {
                        if import_url.starts_with("npm:") {
                            let parts: Vec<&str> = import_url["npm:".len()..].split('@').collect();
                            if parts.len() >= 2 {
                                let pkg_name = parts[0].to_string();
                                let pkg_ver = parts[1].to_string();
                                deps_to_check.insert(pkg_name, (pkg_ver, Ecosystem::Npm));
                            } else if parts.len() == 1 {
                                let pkg_name = parts[0].to_string();
                                deps_to_check.insert(pkg_name, ("latest".to_string(), Ecosystem::Npm));
                            }
                        } else if import_url.starts_with("jsr:") {
                            let parts: Vec<&str> = import_url["jsr:".len()..].split('@').collect();
                            if parts.len() >= 2 {
                                let pkg_name = parts[0].to_string();
                                let pkg_ver = parts[1].to_string();
                                deps_to_check.insert(pkg_name, (pkg_ver, Ecosystem::Npm));
                            }
                        }
                    }
                }
            }
        }

        let mut outdated = Vec::new();
        if deps_to_check.is_empty() {
            return Ok(outdated);
        }

        let mut tasks = Vec::new();
        for (name, (current_constraint, ecosystem)) in deps_to_check {
            let client = self.client.clone();
            tasks.push(tokio::spawn(async move {
                let url = format!("https://registry.npmjs.org/{}/latest", name);
                let response = client.get(&url).send().await;
                match response {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            #[derive(Deserialize)]
                            struct RegistryLatest {
                                version: String,
                            }
                            if let Ok(reg_resp) = resp.json::<RegistryLatest>().await {
                                let latest = reg_resp.version;
                                let clean_current = current_constraint.trim_start_matches(|c| c == '^' || c == '~' || c == '*' || c == '=');
                                let clean_latest = latest.split('+').next().unwrap_or(&latest);
                                if clean_current != clean_latest && !clean_latest.is_empty() && clean_current != "latest" {
                                    let is_newer = if let (Ok(cur), Ok(lat)) = (semver::Version::parse(clean_current), semver::Version::parse(clean_latest)) {
                                        lat > cur
                                    } else {
                                        clean_current != clean_latest
                                    };

                                    if is_newer {
                                        return Some(Dependency {
                                            name,
                                            current_version: current_constraint,
                                            latest_version: latest,
                                            ecosystem,
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
