use crate::models::{Dependency, Ecosystem};
use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize, Debug)]
struct BrewPackage {
    name: String,
    installed_versions: Vec<String>,
    current_version: String,
}

#[derive(Deserialize, Debug)]
struct BrewOutdatedJson {
    #[serde(default)]
    formulae: Vec<BrewPackage>,
    #[serde(default)]
    casks: Vec<BrewPackage>,
}

pub struct HomebrewAdapter;

impl HomebrewAdapter {
    pub fn try_new() -> Result<Self> {
        Ok(Self)
    }

    pub async fn check_outdated(&self, _dir: &Path) -> Result<Vec<Dependency>> {
        let has_brew = tokio::process::Command::new("which")
            .arg("brew")
            .output()
            .await;
        if has_brew.is_err() || !has_brew.unwrap().status.success() {
            return Ok(Vec::new());
        }

        let output = tokio::process::Command::new("brew")
            .args(["outdated", "--json", "--greedy"])
            .output()
            .await?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: BrewOutdatedJson = match serde_json::from_str(&stdout) {
            Ok(p) => p,
            Err(_) => return Ok(Vec::new()),
        };

        let mut deps = Vec::new();

        for pkg in parsed.formulae {
            let current = pkg.installed_versions.first().cloned().unwrap_or_default();
            if !current.is_empty()
                && !pkg.current_version.is_empty()
                && current != pkg.current_version
            {
                deps.push(Dependency {
                    name: pkg.name,
                    current_version: current,
                    latest_version: pkg.current_version,
                    ecosystem: Ecosystem::Homebrew,
                    is_global: true,
                    origin: None,
                });
            }
        }

        for pkg in parsed.casks {
            let current = pkg.installed_versions.first().cloned().unwrap_or_default();
            if !current.is_empty()
                && !pkg.current_version.is_empty()
                && current != pkg.current_version
                && !deps.iter().any(|d: &Dependency| d.name == pkg.name)
            {
                deps.push(Dependency {
                    name: pkg.name,
                    current_version: current,
                    latest_version: pkg.current_version,
                    ecosystem: Ecosystem::Homebrew,
                    is_global: true,
                    origin: None,
                });
            }
        }

        Ok(deps)
    }
}
