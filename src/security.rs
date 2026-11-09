use crate::cache::{read_cache, write_cache};
use crate::models::{Ecosystem, FreshnessInfo, ProvenanceInfo, VulnerabilityInfo};
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const EXTERNAL_REQUEST_LIMIT: usize = 8;
const VULN_CACHE_TTL_SECS: u64 = 6 * 60 * 60;
const FRESHNESS_CACHE_TTL_SECS: u64 = 24 * 60 * 60;
const PROVENANCE_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

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
    nvd_api_key: Option<String>,
}

/// Incomplete OSV audit with any findings returned by the independent NVD query.
/// This remains an error so callers cannot mistake it for a complete audit.
#[derive(Debug, Clone)]
pub struct PartialAuditError {
    pub osv_error: String,
    pub nvd_findings: Vec<VulnerabilityInfo>,
    pub nvd_error: Option<String>,
}

impl std::fmt::Display for PartialAuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OSV vulnerability audit unavailable: {}", self.osv_error)
    }
}

impl std::error::Error for PartialAuditError {}

#[derive(Debug, Clone)]
pub struct AuditFailure {
    pub message: String,
    pub findings: Vec<VulnerabilityInfo>,
    pub partial: bool,
}

impl From<String> for AuditFailure {
    fn from(message: String) -> Self {
        Self {
            message,
            findings: Vec::new(),
            partial: false,
        }
    }
}

impl From<&str> for AuditFailure {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

impl From<anyhow::Error> for AuditFailure {
    fn from(error: anyhow::Error) -> Self {
        if let Some(partial) = error.downcast_ref::<PartialAuditError>() {
            return Self {
                message: error.to_string(),
                findings: partial.nvd_findings.clone(),
                partial: true,
            };
        }
        error.to_string().into()
    }
}

fn combine_audit_results(
    osv: Result<Vec<VulnerabilityInfo>>,
    nvd: Result<Vec<VulnerabilityInfo>>,
) -> Result<Vec<VulnerabilityInfo>> {
    let mut all_vulns = match osv {
        Ok(vulns) => vulns,
        Err(error) => {
            let (nvd_findings, nvd_error) = match nvd {
                Ok(findings) => (findings, None),
                Err(error) => (Vec::new(), Some(error.to_string())),
            };
            return Err(PartialAuditError {
                osv_error: error.to_string(),
                nvd_findings,
                nvd_error,
            }
            .into());
        }
    };
    if let Ok(nvd_vulns) = nvd {
        for vuln in nvd_vulns {
            if let Some(existing) = all_vulns.iter_mut().find(|v| {
                v.id == vuln.id || v.aliases.contains(&vuln.id) || vuln.aliases.contains(&v.id)
            }) {
                merge_vulnerability(existing, vuln);
            } else {
                all_vulns.push(vuln);
            }
        }
    }
    Ok(all_vulns)
}

impl Default for SecurityChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityChecker {
    pub fn new() -> Self {
        Self::new_with_config(5, None)
    }

    pub fn new_with_config(timeout_secs: u64, nvd_api_key: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .unwrap_or_default();
        Self {
            client,
            nvd_api_key,
        }
    }

    pub async fn check_vulnerability(
        &self,
        name: &str,
        version: &str,
        ecosystem: Ecosystem,
    ) -> Result<Vec<VulnerabilityInfo>> {
        let cache_key = format!(
            "osv-verified-v2:{}:{}:{}",
            ecosystem.as_str(),
            name,
            version
        );
        if let Some(cached) = read_cache(
            "vulnerabilities",
            &cache_key,
            Duration::from_secs(VULN_CACHE_TTL_SECS),
        ) {
            return Ok(cached);
        }

        let osv_future = self.check_osv(name, version, ecosystem);
        let nvd_future = self.check_nvd(name, version);

        let (osv_result, nvd_result) = tokio::join!(osv_future, nvd_future);

        let all_vulns = combine_audit_results(osv_result, nvd_result)?;
        let _ = write_cache("vulnerabilities", &cache_key, &all_vulns);

        Ok(all_vulns)
    }

    async fn check_osv(
        &self,
        name: &str,
        version: &str,
        ecosystem: Ecosystem,
    ) -> Result<Vec<VulnerabilityInfo>> {
        self.check_osv_at("https://api.osv.dev/v1/query", name, version, ecosystem)
            .await
    }

    async fn check_osv_at(
        &self,
        url: &str,
        name: &str,
        version: &str,
        ecosystem: Ecosystem,
    ) -> Result<Vec<VulnerabilityInfo>> {
        let _permit = acquire_external_request().await;
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
            return Err(anyhow::anyhow!(
                "OSV.dev returned status {}",
                response.status()
            ));
        }

        let body = response
            .text()
            .await
            .context("Failed to read response body")?;

        let osv_res: OsvResponse =
            serde_json::from_str(&body).context("Failed to parse OSV response JSON")?;

        let vulns = osv_res.vulns.into_iter().map(parse_osv_vuln).collect();
        Ok(vulns)
    }
    async fn check_nvd(&self, name: &str, version: &str) -> Result<Vec<VulnerabilityInfo>> {
        let _permit = acquire_external_request().await;
        let search = format!("{} {}", name, version);
        let url = reqwest::Url::parse_with_params(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            &[
                ("keywordSearch", &search),
                ("keywordExactMatch", &"true".to_string()),
            ],
        )?;

        let mut request = self.client.get(url);
        if let Some(ref api_key) = self.nvd_api_key {
            request = request.header("apiKey", api_key);
        }

        let response = request.send().await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        #[derive(Deserialize)]
        struct NvdDesc {
            #[serde(default)]
            lang: String,
            #[serde(default)]
            value: String,
        }

        #[derive(Deserialize)]
        struct NvdCve {
            id: String,
            #[serde(default)]
            descriptions: Vec<NvdDesc>,
        }

        #[derive(Deserialize)]
        struct NvdItem {
            cve: NvdCve,
        }

        #[derive(Deserialize)]
        struct NvdResponse {
            #[serde(default)]
            vulnerabilities: Vec<NvdItem>,
        }

        let body = response.text().await.unwrap_or_default();
        let nvd_res: NvdResponse = match serde_json::from_str(&body) {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };

        let lowered_name = name.to_lowercase();
        let vulns = nvd_res
            .vulnerabilities
            .into_iter()
            .filter_map(|item| {
                let summary = item
                    .cve
                    .descriptions
                    .iter()
                    .find(|d| d.lang == "en")
                    .map(|d| d.value.clone())
                    .unwrap_or_default();
                if !summary.to_lowercase().contains(&lowered_name) {
                    return None;
                }
                let truncated: String = summary.chars().take(200).collect();
                Some(VulnerabilityInfo {
                    id: item.cve.id,
                    summary: truncated.clone(),
                    details: summary,
                    aliases: Vec::new(),
                    severity: None,
                    score: None,
                    sources: vec!["NVD".to_string()],
                })
            })
            .collect();

        Ok(vulns)
    }

    pub async fn check_freshness(
        &self,
        name: &str,
        version: &str,
        ecosystem: Ecosystem,
        very_recent_days: i64,
        threshold_days: i64,
    ) -> FreshnessInfo {
        let cache_key = format!("{}:{}:{}", ecosystem.as_str(), name, version);
        if let Some(cached) = read_cache(
            "freshness",
            &cache_key,
            Duration::from_secs(FRESHNESS_CACHE_TTL_SECS),
        ) {
            return cached;
        }

        let published = match ecosystem {
            Ecosystem::Cargo => self.check_cargo_freshness(name, version).await,
            Ecosystem::Npm => self.check_npm_freshness(name, version).await,
            _ => None,
        };

        let Some(published) = published else {
            let freshness = FreshnessInfo::Unavailable;
            let _ = write_cache("freshness", &cache_key, &freshness);
            return freshness;
        };

        let now = time::OffsetDateTime::now_utc();
        let age_days = (now - published).whole_days();

        let freshness = if age_days < very_recent_days {
            FreshnessInfo::VeryRecent(age_days)
        } else if age_days < threshold_days {
            FreshnessInfo::Recent(age_days)
        } else {
            FreshnessInfo::Mature(age_days)
        };

        let _ = write_cache("freshness", &cache_key, &freshness);
        freshness
    }

    async fn check_cargo_freshness(
        &self,
        name: &str,
        version: &str,
    ) -> Option<time::OffsetDateTime> {
        let _permit = acquire_external_request().await;
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
        let _permit = acquire_external_request().await;
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
        sources: vec!["OSV".to_string()],
    }
}

fn merge_vulnerability(existing: &mut VulnerabilityInfo, incoming: VulnerabilityInfo) {
    let VulnerabilityInfo {
        summary,
        details,
        aliases,
        severity,
        score,
        sources,
        ..
    } = incoming;

    for source in sources {
        if !existing.sources.contains(&source) {
            existing.sources.push(source);
        }
    }

    for alias in aliases {
        if !existing.aliases.contains(&alias) {
            existing.aliases.push(alias);
        }
    }

    if existing.summary.is_empty() && !summary.is_empty() {
        existing.summary = summary;
    }

    if existing.details.is_empty() && !details.is_empty() {
        existing.details = details;
    }

    if existing.severity.is_none() {
        existing.severity = severity;
    }

    if existing.score.is_none() {
        existing.score = score;
    }
}

pub async fn check_provenance(name: &str, ecosystem: Ecosystem) -> ProvenanceInfo {
    let cache_key = format!("{}:{}", ecosystem.as_str(), name);
    if let Some(cached) = read_cache(
        "provenance",
        &cache_key,
        Duration::from_secs(PROVENANCE_CACHE_TTL_SECS),
    ) {
        return cached;
    }

    let info = match ecosystem {
        Ecosystem::Pacman => check_pacman_provenance(name).await,
        _ => ProvenanceInfo {
            validated_by: None,
            install_date: None,
            pkgbuild_age_days: None,
            signature_verified: false,
        },
    };

    let _ = write_cache("provenance", &cache_key, &info);
    info
}

fn request_semaphore() -> &'static Arc<Semaphore> {
    static SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEMAPHORE.get_or_init(|| Arc::new(Semaphore::new(EXTERNAL_REQUEST_LIMIT)))
}

async fn acquire_external_request() -> OwnedSemaphorePermit {
    request_semaphore()
        .clone()
        .acquire_owned()
        .await
        .expect("external request semaphore closed")
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

    #[test]
    fn failed_osv_lookup_is_not_a_clean_audit() {
        let result = combine_audit_results(Err(anyhow::anyhow!("network failure")), Ok(Vec::new()));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("OSV vulnerability audit unavailable"));
        assert!(
            combine_audit_results(Ok(Vec::new()), Err(anyhow::anyhow!("nvd unavailable")))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn partial_audit_retains_nvd_findings_without_claiming_completion() {
        let finding = VulnerabilityInfo {
            id: "CVE-TEST".into(),
            summary: "example".into(),
            details: String::new(),
            aliases: Vec::new(),
            severity: None,
            score: None,
            sources: vec!["NVD".into()],
        };
        let error =
            combine_audit_results(Err(anyhow::anyhow!("offline")), Ok(vec![finding])).unwrap_err();
        let partial = error.downcast_ref::<PartialAuditError>().unwrap();
        assert_eq!(partial.nvd_findings.len(), 1);
        assert_eq!(partial.nvd_findings[0].id, "CVE-TEST");
        assert!(partial.nvd_error.is_none());
        let error = combine_audit_results(
            Err(anyhow::anyhow!("offline")),
            Err(anyhow::anyhow!("NVD failed")),
        )
        .unwrap_err();
        let partial = error.downcast_ref::<PartialAuditError>().unwrap();
        assert!(partial.nvd_findings.is_empty());
        assert_eq!(partial.nvd_error.as_deref(), Some("NVD failed"));
    }

    #[tokio::test]
    async fn test_osv_security_checker() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for name in ["synthetic-vulnerable", "synthetic-clean", "synthetic-error"] {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                let (offset, length) = loop {
                    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&chunk[..n]);
                    assert!(request.len() <= 8192);
                    if let Some(end) = request.windows(4).position(|value| value == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end]).unwrap();
                        assert!(headers.starts_with("POST /v1/query HTTP/1.1\r\n"));
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                line.split_once(':').and_then(|(key, value)| {
                                    if key.eq_ignore_ascii_case("content-length") {
                                        value.trim().parse().ok()
                                    } else {
                                        None
                                    }
                                })
                            })
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break (end + 4, length);
                        }
                    }
                };
                let payload: Value =
                    serde_json::from_slice(&request[offset..offset + length]).unwrap();
                assert_eq!(
                    payload,
                    json!({"package": {"name": name, "ecosystem": "crates.io"}, "version": "1.0.0"})
                );
                let (status, body) = match name {
                    "synthetic-vulnerable" => (
                        "200 OK",
                        r#"{"vulns":[{"id":"GHSA-SYNTHETIC","summary":"fixture","details":"synthetic details","aliases":["CVE-SYNTHETIC"],"database_specific":{"severity":"HIGH","cvss_score":7.5}}]}"#,
                    ),
                    "synthetic-clean" => ("200 OK", r#"{"vulns":[]}"#),
                    _ => ("503 Service Unavailable", "{}"),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let checker = SecurityChecker {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
            nvd_api_key: None,
        };
        let endpoint = format!("http://{address}/v1/query");
        let vulns = checker
            .check_osv_at(&endpoint, "synthetic-vulnerable", "1.0.0", Ecosystem::Cargo)
            .await
            .unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].id, "GHSA-SYNTHETIC");
        assert_eq!(vulns[0].aliases, ["CVE-SYNTHETIC"]);
        assert_eq!(vulns[0].severity.as_deref(), Some("HIGH"));
        assert_eq!(vulns[0].score, Some(7.5));
        assert_eq!(vulns[0].sources, ["OSV"]);
        assert!(checker
            .check_osv_at(&endpoint, "synthetic-clean", "1.0.0", Ecosystem::Cargo)
            .await
            .unwrap()
            .is_empty());
        assert!(checker
            .check_osv_at(&endpoint, "synthetic-error", "1.0.0", Ecosystem::Cargo)
            .await
            .is_err());
        server.await.unwrap();
    }
}
