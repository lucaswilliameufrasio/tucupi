use crate::models::{Dependency, Ecosystem};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;
use tokio::process::Command;

pub struct GoAdapter;

impl GoAdapter {
    pub fn try_new() -> Result<Self> {
        Ok(Self)
    }

    pub async fn check_outdated(&self, dir: &Path) -> Result<Vec<Dependency>> {
        let output = Command::new("go")
            .args(["list", "-u", "-m", "-json", "all"])
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

        let mut deps = Vec::new();
        let stdout_str = String::from_utf8_lossy(&output.stdout);

        let stream = serde_json::Deserializer::from_str(&stdout_str).into_iter::<Value>();
        for parsed in stream.flatten() {
            let name = parsed["Path"].as_str().unwrap_or("Unknown").to_string();
            let current = parsed["Version"].as_str().unwrap_or("Unknown").to_string();

            if let Some(update) = parsed.get("Update") {
                let latest = update["Version"].as_str().unwrap_or("Unknown").to_string();
                if !name.is_empty() && name != "Unknown" && current != latest {
                    deps.push(Dependency {
                        name,
                        current_version: current,
                        latest_version: latest,
                        ecosystem: Ecosystem::Go,
                        is_global: false,
                    });
                }
            }
        }

        Ok(deps)
    }
}
