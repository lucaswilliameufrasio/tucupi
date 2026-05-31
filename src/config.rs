use serde::Deserialize;
use std::path::Path;
use std::collections::HashSet;

#[derive(Debug, Deserialize, Clone, Default)]
pub struct SecurityConfig {
    #[serde(default)]
    pub block_vulnerable: Option<bool>,
    #[serde(default)]
    pub ignored_packages: Option<HashSet<String>>,
    #[serde(default)]
    pub ignored_vulnerabilities: Option<HashSet<String>>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Config {
    #[serde(default)]
    pub security: SecurityConfig,
}

impl Config {
    pub async fn load_from_dir<P: AsRef<Path>>(dir: P) -> Self {
        let config_path = dir.as_ref().join("tucupi.toml");
        if !config_path.exists() {
            return Self::default();
        }

        match tokio::fs::read_to_string(&config_path).await {
            Ok(content) => match toml::from_str::<Config>(&content) {
                Ok(config) => config,
                Err(err) => {
                    eprintln!("Warning: Failed to parse tucupi.toml: {}", err);
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    pub fn block_vulnerable(&self) -> bool {
        self.security.block_vulnerable.unwrap_or(false)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = Config::default();
        assert!(!config.block_vulnerable());
        assert!(!config.is_package_ignored("any-pkg"));
        assert!(!config.is_vulnerability_ignored("GHSA-1234"));
    }

    #[test]
    fn test_config_parsing() {
        let content = r#"
            [security]
            block_vulnerable = true
            ignored_packages = ["lodash", "serde"]
            ignored_vulnerabilities = ["GHSA-xxxx-yyyy"]
        "#;
        let config: Config = toml::from_str(content).unwrap();
        assert!(config.block_vulnerable());
        assert!(config.is_package_ignored("lodash"));
        assert!(config.is_package_ignored("serde"));
        assert!(!config.is_package_ignored("anyhow"));
        assert!(config.is_vulnerability_ignored("GHSA-xxxx-yyyy"));
        assert!(!config.is_vulnerability_ignored("GHSA-other"));
    }
}

