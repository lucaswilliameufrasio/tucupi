use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;
use toml::Value;

const SHARED_CONFIG_FILE: &str = "tucupi.toml";
const LOCAL_CONFIG_FILE: &str = "tucupi.local.toml";

#[derive(Debug, Deserialize, Clone, Default)]
pub struct SecurityConfig {
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
    pub nvd_api_key: Option<String>,
    #[serde(default)]
    pub pkgbuild_review: Option<bool>,
    #[serde(default)]
    pub review_model: Option<String>,
    #[serde(default)]
    pub review_llm: Option<bool>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub security: SecurityConfig,
}

impl Config {
    pub async fn load_from_dir<P: AsRef<Path>>(dir: P) -> Self {
        let dir = dir.as_ref();
        let mut merged = load_config_table(&dir.join(SHARED_CONFIG_FILE)).await;
        let local_overrides = load_config_table(&dir.join(LOCAL_CONFIG_FILE)).await;
        merge_tables(&mut merged, local_overrides);

        match Config::deserialize(merged) {
            Ok(config) => config,
            Err(err) => {
                eprintln!("Warning: Failed to parse tucupi.toml: {}", err);
                Self::default()
            }
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

    pub fn nvd_api_key(&self) -> Option<String> {
        self.security.nvd_api_key.clone()
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
}

async fn load_config_table(path: &Path) -> Value {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => match toml::from_str::<Value>(&content) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("Warning: Failed to parse {}: {}", path.display(), err);
                Value::Table(toml::map::Map::new())
            }
        },
        Err(_) => Value::Table(toml::map::Map::new()),
    }
}

fn merge_tables(base: &mut Value, overrides: Value) {
    match (base, overrides) {
        (Value::Table(base_table), Value::Table(override_table)) => {
            for (key, value) in override_table {
                match base_table.get_mut(&key) {
                    Some(existing) => merge_tables(existing, value),
                    None => {
                        base_table.insert(key, value);
                    }
                }
            }
        }
        (base, overrides) => *base = overrides,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn merge_tables_overrides_nested_keys_and_preserves_base_only_keys() {
        let mut base: Value = toml::from_str(
            r#"
            [security]
            block_vulnerable = false
            ignored_packages = ["left-pad"]
        "#,
        )
        .unwrap();
        let overrides: Value = toml::from_str(
            r#"
            [security]
            block_vulnerable = true
            nvd_api_key = "local-secret-key"
        "#,
        )
        .unwrap();

        merge_tables(&mut base, overrides);

        let config = Config::deserialize(base).unwrap();
        assert!(config.block_vulnerable());
        assert_eq!(config.nvd_api_key().as_deref(), Some("local-secret-key"));
        assert!(config.is_package_ignored("left-pad"));
    }

    #[tokio::test]
    async fn load_from_dir_overlays_local_config_over_shared_config() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join(SHARED_CONFIG_FILE),
            r#"
            [security]
            block_vulnerable = false
            ignored_packages = ["left-pad"]
        "#,
        )
        .await
        .unwrap();
        tokio::fs::write(
            dir.path().join(LOCAL_CONFIG_FILE),
            r#"
            [security]
            block_vulnerable = true
            nvd_api_key = "local-secret-key"
        "#,
        )
        .await
        .unwrap();

        let config = Config::load_from_dir(dir.path()).await;

        assert!(config.block_vulnerable());
        assert_eq!(config.nvd_api_key().as_deref(), Some("local-secret-key"));
        assert!(config.is_package_ignored("left-pad"));
    }

    #[tokio::test]
    async fn load_from_dir_works_without_local_config_file() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join(SHARED_CONFIG_FILE),
            "[security]\nblock_vulnerable = true",
        )
        .await
        .unwrap();

        let config = Config::load_from_dir(dir.path()).await;

        assert!(config.block_vulnerable());
        assert!(config.nvd_api_key().is_none());
    }

    #[tokio::test]
    async fn load_from_dir_defaults_without_any_config_file() {
        let dir = tempfile::tempdir().unwrap();

        let config = Config::load_from_dir(dir.path()).await;

        assert_eq!(config.nvd_api_key(), None);
        assert!(!config.block_vulnerable());
    }
}
