use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;
use tokio::io::AsyncReadExt;

const CONFIG_FILE: &str = "tucupi.toml";
const CONFIG_MAX_BYTES: usize = 1024 * 1024;

pub struct ConfigLoadError;

impl std::fmt::Display for ConfigLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::i18n::tf("config_parse_warning", &[CONFIG_FILE]))
    }
}

impl std::fmt::Debug for ConfigLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for ConfigLoadError {}

/// Configuration intent only: neither mode enables Codex or stores credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexAuthMode {
    Chatgpt,
    ApiKey,
    Invalid,
}

impl<'de> Deserialize<'de> for CodexAuthMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ModeVisitor;
        impl<'de> serde::de::Visitor<'de> for ModeVisitor {
            type Value = CodexAuthMode;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a Codex authentication mode")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(match value {
                    "chatgpt" => CodexAuthMode::Chatgpt,
                    "api_key" => CodexAuthMode::ApiKey,
                    _ => CodexAuthMode::Invalid,
                })
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(CodexAuthMode::Invalid)
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(CodexAuthMode::Invalid)
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(CodexAuthMode::Invalid)
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(CodexAuthMode::Invalid)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(CodexAuthMode::Invalid)
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                while map
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(CodexAuthMode::Invalid)
            }
        }
        deserializer.deserialize_any(ModeVisitor)
    }
}

fn reject_inline_codex_credential<'de, D: serde::Deserializer<'de>>(
    _deserializer: D,
) -> Result<(), D::Error> {
    Err(serde::de::Error::custom(
        "inline Codex credentials are not supported",
    ))
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct SecurityConfig {
    // Recognize dangerous credential field names rather than silently ignoring
    // them. Do not deserialize or retain their values.
    #[serde(
        default,
        rename = "codex_api_key",
        alias = "openai_api_key",
        deserialize_with = "reject_inline_codex_credential"
    )]
    #[doc(hidden)]
    pub _inline_codex_credential: (),
    #[serde(default)]
    pub block_vulnerable: Option<bool>,
    #[serde(default)]
    pub require_online: Option<bool>,
    #[serde(default)]
    pub require_provenance: Option<bool>,
    #[serde(default)]
    pub aur_enabled: Option<bool>,
    #[serde(default)]
    pub confirm_global: Option<bool>,
    #[serde(default)]
    pub ignored_packages: Option<HashSet<String>>,
    #[serde(default)]
    pub ignored_vulnerabilities: Option<HashSet<String>>,
    #[serde(default)]
    pub osv_timeout_secs: Option<u64>,
    #[serde(default)]
    pub pre_scan_security: Option<bool>,
    #[serde(default)]
    pub freshness_threshold_days: Option<i64>,
    #[serde(default)]
    pub block_too_fresh: Option<bool>,
    #[serde(default)]
    pub very_recent_days: Option<i64>,
    #[serde(default)]
    pub pkgbuild_review: Option<bool>,
    #[serde(default)]
    pub review_model: Option<String>,
    #[serde(default)]
    pub review_provider: Option<String>,
    #[serde(default)]
    pub codex_auth_mode: Option<CodexAuthMode>,
    #[serde(default)]
    pub review_llm: Option<bool>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub security: SecurityConfig,
}

impl Config {
    pub async fn load_from_dir<P: AsRef<Path>>(dir: P) -> Result<Self, ConfigLoadError> {
        let config_path = dir.as_ref().join(CONFIG_FILE);
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        // Avoid waiting for a FIFO writer; metadata is checked on the opened
        // descriptor. This flag is not a general device-isolation guarantee.
        #[cfg(unix)]
        options.custom_flags(libc::O_NONBLOCK);
        match options.open(&config_path).await {
            Ok(file) => {
                if !file
                    .metadata()
                    .await
                    .map_err(|_| ConfigLoadError)?
                    .is_file()
                {
                    return Err(ConfigLoadError);
                }
                let mut content = Vec::new();
                file.take((CONFIG_MAX_BYTES + 1) as u64)
                    .read_to_end(&mut content)
                    .await
                    .map_err(|_| ConfigLoadError)?;
                if content.len() > CONFIG_MAX_BYTES {
                    return Err(ConfigLoadError);
                }
                let content = std::str::from_utf8(&content).map_err(|_| ConfigLoadError)?;
                toml::from_str::<Config>(content).map_err(|_| ConfigLoadError)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match tokio::fs::symlink_metadata(&config_path).await {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        Ok(Self::default())
                    }
                    _ => Err(ConfigLoadError),
                }
            }
            Err(_) => Err(ConfigLoadError),
        }
    }

    pub fn block_vulnerable(&self) -> bool {
        self.security.block_vulnerable.unwrap_or(false)
    }

    pub fn require_online(&self) -> bool {
        self.security.require_online.unwrap_or(true)
    }

    pub fn require_provenance(&self) -> bool {
        self.security.require_provenance.unwrap_or(true)
    }

    pub fn aur_enabled(&self) -> bool {
        self.security.aur_enabled.unwrap_or(false)
    }

    pub fn confirm_global(&self) -> bool {
        self.security.confirm_global.unwrap_or(true)
    }

    pub fn is_package_ignored(&self, name: &str) -> bool {
        if let Some(ref ignored) = self.security.ignored_packages {
            ignored.contains(name)
        } else {
            false
        }
    }

    pub fn is_vulnerability_ignored(&self, id: &str) -> bool {
        if let Some(ref ignored) = self.security.ignored_vulnerabilities {
            ignored.contains(id)
        } else {
            false
        }
    }

    pub fn osv_timeout_secs(&self) -> u64 {
        self.security.osv_timeout_secs.unwrap_or(5)
    }

    pub fn pre_scan_security(&self) -> bool {
        self.security.pre_scan_security.unwrap_or(true)
    }

    pub fn freshness_threshold_days(&self) -> i64 {
        self.security.freshness_threshold_days.unwrap_or(7)
    }

    pub fn block_too_fresh(&self) -> bool {
        self.security.block_too_fresh.unwrap_or(false)
    }

    pub fn very_recent_days(&self) -> i64 {
        self.security.very_recent_days.unwrap_or(3)
    }

    pub fn pkgbuild_review(&self) -> bool {
        self.security.pkgbuild_review.unwrap_or(true)
    }

    pub fn review_model(&self) -> String {
        self.security
            .review_model
            .clone()
            .unwrap_or_else(|| crate::review::DEFAULT_REVIEW_MODEL.to_string())
    }

    pub fn review_llm(&self) -> bool {
        self.security.review_llm.unwrap_or(true)
    }

    pub fn review_provider(&self) -> &str {
        self.security
            .review_provider
            .as_deref()
            .unwrap_or("opencode")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn oversized_config_is_rejected_without_disclosing_contents() {
        let directory = tempfile::tempdir().unwrap();
        let mut content = String::from("# synthetic-private-value\n");
        content.push_str(&" ".repeat(1_048_576));
        std::fs::write(directory.path().join(CONFIG_FILE), content).unwrap();
        let error = Config::load_from_dir(directory.path()).await.unwrap_err();
        assert!(!error.to_string().contains("synthetic-private-value"));
    }

    #[tokio::test]
    async fn config_size_boundary_and_invalid_utf8_are_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(CONFIG_FILE);
        std::fs::write(&path, vec![b' '; CONFIG_MAX_BYTES]).unwrap();
        assert!(Config::load_from_dir(directory.path()).await.is_ok());
        std::fs::write(&path, vec![b' '; CONFIG_MAX_BYTES + 1]).unwrap();
        assert!(Config::load_from_dir(directory.path()).await.is_err());
        std::fs::write(&path, [0xff]).unwrap();
        assert!(Config::load_from_dir(directory.path()).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_configuration_is_rejected_without_writer() {
        use std::os::unix::ffi::OsStrExt;
        let directory = tempfile::tempdir().unwrap();
        let path =
            std::ffi::CString::new(directory.path().join(CONFIG_FILE).as_os_str().as_bytes())
                .unwrap();
        // SAFETY: path is a NUL-terminated filename in the private fixture directory.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            Config::load_from_dir(directory.path()),
        )
        .await;
        assert!(result.expect("FIFO config loading must not block").is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn regular_symlink_and_missing_config_keep_existing_behavior() {
        let directory = tempfile::tempdir().unwrap();
        assert!(Config::load_from_dir(directory.path()).await.is_ok());
        let source = directory.path().join("actual.toml");
        std::fs::write(&source, "[security]\nblock_vulnerable = true\n").unwrap();
        std::os::unix::fs::symlink(&source, directory.path().join(CONFIG_FILE)).unwrap();
        assert!(Config::load_from_dir(directory.path())
            .await
            .unwrap()
            .block_vulnerable());
        std::fs::remove_file(source).unwrap();
        assert!(Config::load_from_dir(directory.path()).await.is_err());
    }

    #[tokio::test]
    async fn codex_plaintext_key_fields_reject_configuration_without_disclosure() {
        for field in ["codex_api_key", "openai_api_key"] {
            let directory = tempfile::tempdir().unwrap();
            let synthetic = "synthetic-credential-do-not-display";
            std::fs::write(
                directory.path().join(CONFIG_FILE),
                format!("[security]\nreview_provider = 'codex'\n{field} = '{synthetic}'\n"),
            )
            .unwrap();
            let result = Config::load_from_dir(directory.path()).await;
            assert!(
                result.is_err(),
                "plaintext credential field must not be silently accepted"
            );
            assert!(!result.unwrap_err().to_string().contains(synthetic));
        }
    }

    #[tokio::test]
    async fn invalid_config_warning_is_localized_and_does_not_disclose_input() {
        if let Some(dir) = std::env::var_os("TUCUPI_CONFIG_WARNING_CHILD") {
            let error = Config::load_from_dir(Path::new(&dir)).await.unwrap_err();
            eprintln!("{error}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let synthetic = "synthetic-secret-never-print";
        std::fs::write(
            dir.path().join("tucupi.toml"),
            format!("[security]\nreview_model = \"{synthetic}\n"),
        )
        .unwrap();
        for (locale, expected) in [
            ("pt_BR.UTF-8", "Não foi possível ler a configuração"),
            ("en_US.UTF-8", "Could not read configuration"),
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "config::tests::invalid_config_warning_is_localized_and_does_not_disclose_input", "--nocapture"])
                .env("TUCUPI_CONFIG_WARNING_CHILD", dir.path())
                .env("LC_ALL", locale)
                .output().unwrap();
            assert!(output.status.success());
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.contains(expected), "{stderr}");
            assert!(!stderr.contains(synthetic));
        }
    }

    #[test]
    fn test_config_defaults() {
        let config = Config::default();
        assert!(!config.block_vulnerable());
        assert!(config.require_online());
        assert!(config.require_provenance());
        assert!(!config.aur_enabled());
        assert!(config.confirm_global());
        assert!(!config.is_package_ignored("any-pkg"));
        assert!(!config.is_vulnerability_ignored("GHSA-1234"));
        assert_eq!(config.osv_timeout_secs(), 5);
        assert!(config.pre_scan_security());
        assert_eq!(config.freshness_threshold_days(), 7);
        assert!(!config.block_too_fresh());
        assert_eq!(config.very_recent_days(), 3);
        assert!(config.pkgbuild_review());
        assert_eq!(config.review_model(), crate::review::DEFAULT_REVIEW_MODEL);
        assert!(config.review_llm());
        assert_eq!(config.security.codex_auth_mode, None);
    }

    #[test]
    fn codex_auth_modes_are_distinct_and_invalid_mode_preserves_security_settings() {
        for (value, expected) in [
            ("chatgpt", CodexAuthMode::Chatgpt),
            ("api_key", CodexAuthMode::ApiKey),
            ("unsupported", CodexAuthMode::Invalid),
        ] {
            let content = format!("[security]\nrequire_online = true\nreview_provider = 'codex'\ncodex_auth_mode = '{value}'\n");
            let config: Config = toml::from_str(&content).unwrap();
            assert_eq!(config.security.codex_auth_mode, Some(expected));
            assert!(config.require_online());
            assert_eq!(config.review_provider(), "codex");
        }
        for value in ["false", "7", "[]", "{ unexpected = 'value' }"] {
            let content =
                format!("[security]\nblock_vulnerable = true\ncodex_auth_mode = {value}\n");
            let config: Config = toml::from_str(&content).unwrap();
            assert!(config.block_vulnerable());
            assert_eq!(
                config.security.codex_auth_mode,
                Some(CodexAuthMode::Invalid)
            );
        }
    }

    #[test]
    fn test_config_parsing() {
        let content = r#"
            [security]
            block_vulnerable = true
            require_online = false
            require_provenance = false
            aur_enabled = true
            confirm_global = false
            ignored_packages = ["lodash", "serde"]
            ignored_vulnerabilities = ["GHSA-xxxx-yyyy"]
            osv_timeout_secs = 10
            pre_scan_security = false
            freshness_threshold_days = 14
            block_too_fresh = true
            very_recent_days = 2
        "#;
        let config: Config = toml::from_str(content).unwrap();
        assert!(config.block_vulnerable());
        assert!(!config.require_online());
        assert!(!config.require_provenance());
        assert!(config.aur_enabled());
        assert!(!config.confirm_global());
        assert!(config.is_package_ignored("lodash"));
        assert!(config.is_package_ignored("serde"));
        assert!(!config.is_package_ignored("anyhow"));
        assert!(config.is_vulnerability_ignored("GHSA-xxxx-yyyy"));
        assert!(!config.is_vulnerability_ignored("GHSA-other"));
        assert_eq!(config.osv_timeout_secs(), 10);
        assert!(!config.pre_scan_security());
        assert_eq!(config.freshness_threshold_days(), 14);
        assert!(config.block_too_fresh());
        assert_eq!(config.very_recent_days(), 2);
    }

    #[tokio::test]
    async fn load_from_dir_reads_shared_config_file() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join(CONFIG_FILE),
            "[security]\nblock_vulnerable = true",
        )
        .await
        .unwrap();

        let config = Config::load_from_dir(dir.path()).await.unwrap();

        assert!(config.block_vulnerable());
    }

    #[tokio::test]
    async fn load_from_dir_defaults_without_any_config_file() {
        let dir = tempfile::tempdir().unwrap();

        let config = Config::load_from_dir(dir.path()).await.unwrap();

        assert!(!config.block_vulnerable());
    }
}
