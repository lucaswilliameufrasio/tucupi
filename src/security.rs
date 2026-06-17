use crate::config::Config;
use crate::models::{Ecosystem, ProvenanceInfo, VulnerabilityInfo};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    database_specific: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

pub struct SecurityChecker {
    client: Client,
}

impl Default for SecurityChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityChecker {
    pub fn new() -> Self {
        Self::new_with_config(5)
    }

    pub fn new_with_config(timeout_secs: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .unwrap_or_default();
        Self { client }
    }

    pub fn from_config(config: &Config) -> Self {
        Self::new_with_config(config.osv_timeout_secs())
    }

    pub async fn check_vulnerability(
        &self,
        name: &str,
        version: &str,
        ecosystem: Ecosystem,
    ) -> Result<Vec<VulnerabilityInfo>> {
        let url = "https://api.osv.dev/v1/query";
        let payload = json!({
            "package": {
                "name": name,
                "ecosystem": ecosystem.osv_name()
            },
            "version": version
        });

        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send request to OSV.dev")?;

        if !response.status().is_success() {
            let status_code = response.status();
            if status_code == 400 || status_code == 404 {
                return Ok(Vec::new());
            }
            return Err(anyhow::anyhow!(
                "OSV.dev returned status {}",
                response.status()
            ));
        }

        let body = response
            .text()
            .await
            .context("Failed to read response body")?;

        if body.trim() == "{}" || body.trim().is_empty() {
            return Ok(Vec::new());
        }

        let osv_res: OsvResponse =
            serde_json::from_str(&body).context("Failed to parse OSV response JSON")?;

        let vulns = osv_res.vulns.into_iter().map(parse_osv_vuln).collect();
        Ok(vulns)
    }

    pub async fn check_freshness(
        &self,
        name: &str,
        version: &str,
        ecosystem: Ecosystem,
        threshold_days: i64,
    ) -> Option<i64> {
        match ecosystem {
            Ecosystem::Cargo => self.check_cargo_freshness(name, version).await,
            Ecosystem::Npm => self.check_npm_freshness(name, version).await,
            _ => None,
        }
        .map(|published| {
            let now = time::OffsetDateTime::now_utc();
            (now - published).whole_days()
        })
        .filter(|age| *age < threshold_days)
    }

    async fn check_cargo_freshness(
        &self,
        name: &str,
        version: &str,
    ) -> Option<time::OffsetDateTime> {
        let url = format!("https://crates.io/api/v1/crates/{}/versions", name);
        let resp = self.client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body = resp.text().await.ok()?;
        let json: Value = serde_json::from_str(&body).ok()?;
        let versions = json.get("versions")?.as_array()?;
        for v in versions {
            if v.get("num")?.as_str()? == version {
                let created = v.get("created_at")?.as_str()?;
                return time::OffsetDateTime::parse(
                    created,
                    &time::format_description::well_known::Rfc3339,
                )
                .ok();
            }
        }
        None
    }

    async fn check_npm_freshness(&self, name: &str, version: &str) -> Option<time::OffsetDateTime> {
        let url = format!("https://registry.npmjs.org/{}", name);
        let resp = self.client.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body = resp.text().await.ok()?;
        let json: Value = serde_json::from_str(&body).ok()?;
        let time_obj = json.get("time")?.as_object()?;
        let date_str = time_obj.get(version)?.as_str()?;
        time::OffsetDateTime::parse(date_str, &time::format_description::well_known::Rfc3339).ok()
    }
}

fn parse_osv_vuln(v: OsvVulnerability) -> VulnerabilityInfo {
    let (severity, score) = v
        .database_specific
        .as_ref()
        .map(|ds| {
            let severity = ds
                .get("severity")
                .and_then(|s| s.as_str().map(|s| s.to_string()));
            let score = ds
                .get("cvss_score")
                .or_else(|| ds.get("cvss"))
                .and_then(|s| s.as_f64());
            (severity, score)
        })
        .unwrap_or((None, None));

    VulnerabilityInfo {
        id: v.id,
        summary: v
            .summary
            .unwrap_or_else(|| "No summary provided".to_string()),
        details: v
            .details
            .unwrap_or_else(|| "No details provided".to_string()),
        aliases: v.aliases,
        severity,
        score,
    }
}

pub async fn check_provenance(name: &str, ecosystem: Ecosystem) -> ProvenanceInfo {
    match ecosystem {
        Ecosystem::Pacman => check_pacman_provenance(name).await,
        _ => ProvenanceInfo {
            validated_by: None,
            install_date: None,
            pkgbuild_age_days: None,
            signature_verified: false,
        },
    }
}

async fn check_pacman_provenance(name: &str) -> ProvenanceInfo {
    let output = tokio::process::Command::new("pacman")
        .args(["-Qi", name])
        .output()
        .await;

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => {
            return ProvenanceInfo {
                validated_by: None,
                install_date: None,
                pkgbuild_age_days: None,
                signature_verified: false,
            }
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut validated_by = None;
    let mut install_date = None;

    for line in stdout.lines() {
        if let Some(val) = line.strip_prefix("Validated By") {
            validated_by = Some(val.trim().trim_start_matches(':').trim().to_string());
        }
        if let Some(val) = line.strip_prefix("Install Date") {
            install_date = Some(val.trim().trim_start_matches(':').trim().to_string());
        }
    }

    let signature_verified = validated_by
        .as_deref()
        .map(|v| v != "None" && !v.is_empty())
        .unwrap_or(false);

    ProvenanceInfo {
        validated_by,
        install_date,
        pkgbuild_age_days: None,
        signature_verified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_osv_security_checker() {
        let checker = SecurityChecker::new();
        let vulns = checker
            .check_vulnerability("rustls", "0.20.0", Ecosystem::Cargo)
            .await;
        match vulns {
            Ok(v) => {
                assert!(
                    !v.is_empty(),
                    "rustls 0.20.0 should have known vulnerabilities in OSV.dev"
                );
                assert!(v
                    .iter()
                    .any(|item| item.id.contains("GHSA") || item.id.contains("CVE")));
            }
            Err(e) => {
                eprintln!("Warning: OSV lookup failed (probably offline): {}", e);
            }
        }
    }
}
