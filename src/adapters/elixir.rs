use crate::models::{Dependency, Ecosystem};
use anyhow::Result;
use std::path::Path;
use tokio::process::Command;

pub struct ElixirAdapter;

impl ElixirAdapter {
    pub fn try_new() -> Result<Self> {
        Ok(Self)
    }

    pub async fn check_outdated(&self, dir: &Path) -> Result<Vec<Dependency>> {
        let output = Command::new("mix")
            .args(["hex.outdated"])
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
        let mut deps = Vec::new();

        let mut in_table = false;
        for line in stdout_str.lines() {
            if line.starts_with("Dependency") {
                in_table = true;
                continue;
            }
            if in_table && line.trim().is_empty() {
                break;
            }

            if in_table {
                let columns: Vec<&str> = line.split_whitespace().collect();
                if columns.len() >= 3 {
                    let name = columns[0].to_string();
                    let current = columns[1].to_string();
                    let latest = columns[2].to_string();
                    if name != "Unknown" && current != latest {
                        deps.push(Dependency {
                            name,
                            current_version: current,
                            latest_version: latest,
                            ecosystem: Ecosystem::Elixir,
                            is_global: false,
                        });
                    }
                }
            }
        }

        Ok(deps)
    }
}
