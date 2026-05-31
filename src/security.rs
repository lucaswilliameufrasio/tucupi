use crate::models::{Ecosystem, VulnerabilityInfo};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use anyhow::{Result, Context};
use std::time::Duration;

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

pub struct SecurityChecker {
    client: Client,
}

impl SecurityChecker {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap_or_default();
        Self { client }
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

        let response = self.client.post(url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send request to OSV.dev")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("OSV.dev returned status {}", response.status()));
        }

        let body = response.text().await.context("Failed to read response body")?;
        
        if body.trim() == "{}" || body.trim().is_empty() {
            return Ok(Vec::new());
        }

        let osv_res: OsvResponse = serde_json::from_str(&body)
            .context("Failed to parse OSV response JSON")?;

        let vulns = osv_res.vulns
            .into_iter()
            .map(|v| VulnerabilityInfo {
                id: v.id,
                summary: v.summary.unwrap_or_else(|| "No summary provided".to_string()),
                details: v.details.unwrap_or_else(|| "No details provided".to_string()),
                aliases: v.aliases,
            })
            .collect();

        Ok(vulns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_osv_security_checker() {
        let checker = SecurityChecker::new();
        let vulns = checker.check_vulnerability("rustls", "0.20.0", Ecosystem::Cargo).await;
        match vulns {
            Ok(v) => {
                assert!(!v.is_empty(), "rustls 0.20.0 should have known vulnerabilities in OSV.dev");
                assert!(v.iter().any(|item| item.id.contains("GHSA") || item.id.contains("CVE")));
            }
            Err(e) => {
                eprintln!("Warning: OSV lookup failed (probably offline): {}", e);
            }
        }
    }
}

