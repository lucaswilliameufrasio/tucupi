use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub const KEYCHAIN_SERVICE: &str = "tucupi";
pub const KEYCHAIN_NVD_ACCOUNT: &str = "nvd-api-key";
pub const NVD_KEY_ENV: &str = "TUCUPI_NVD_API_KEY";
pub const TEST_SECRET_STORE_ENV: &str = "TUCUPI_TEST_SECRET_STORE_FILE";

/// API credentials are stored separately from the NVD credential and from one
/// another. These identifiers are not model names or endpoint URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewApiProvider {
    OpenRouter,
    OpenAi,
    Anthropic,
    DeepSeek,
    Zai,
    Kimi,
}

impl ReviewApiProvider {
    pub const ALL: [Self; 6] = [
        Self::OpenRouter,
        Self::OpenAi,
        Self::Anthropic,
        Self::DeepSeek,
        Self::Zai,
        Self::Kimi,
    ];

    pub fn keychain_account(self) -> &'static str {
        match self {
            Self::OpenRouter => "review-openrouter-api-key",
            Self::OpenAi => "review-openai-api-key",
            Self::Anthropic => "review-anthropic-api-key",
            Self::DeepSeek => "review-deepseek-api-key",
            Self::Zai => "review-zai-api-key",
            Self::Kimi => "review-kimi-api-key",
        }
    }

    pub fn from_config(value: &str) -> Option<Self> {
        match value {
            "openrouter" => Some(Self::OpenRouter),
            "openai" => Some(Self::OpenAi),
            "anthropic" => Some(Self::Anthropic),
            "deepseek" => Some(Self::DeepSeek),
            "zai" => Some(Self::Zai),
            "kimi" => Some(Self::Kimi),
            _ => None,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::OpenRouter => "openrouter",
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::DeepSeek => "deepseek",
            Self::Zai => "zai",
            Self::Kimi => "kimi",
        }
    }
}

#[cfg(test)]
mod review_provider_account_tests {
    use super::{KeyringSecretStore, ReviewApiProvider, KEYCHAIN_NVD_ACCOUNT};
    use std::collections::HashSet;

    #[test]
    fn review_accounts_are_distinct_and_do_not_replace_nvd() {
        let mut accounts = HashSet::new();
        for provider in ReviewApiProvider::ALL {
            let store = KeyringSecretStore::for_review_provider(provider);
            assert_ne!(store.account, KEYCHAIN_NVD_ACCOUNT);
            assert!(accounts.insert(store.account));
        }
        assert_eq!(accounts.len(), 6);
    }
}

pub trait SecretStore: Send + Sync {
    fn set_secret(&self, value: &str) -> Result<(), String>;
    fn get_secret(&self) -> Result<Option<String>, String>;
    fn delete_secret(&self) -> Result<(), String>;
}

pub struct KeyringSecretStore {
    service: String,
    account: String,
}

impl KeyringSecretStore {
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn fixture(service: &str, account: &str) -> Self {
        Self {
            service: service.to_owned(),
            account: account.to_owned(),
        }
    }
    pub fn new() -> Self {
        Self {
            service: KEYCHAIN_SERVICE.to_string(),
            account: KEYCHAIN_NVD_ACCOUNT.to_string(),
        }
    }

    pub fn for_review_provider(provider: ReviewApiProvider) -> Self {
        Self {
            service: review_keychain_service(),
            account: provider.keychain_account().to_string(),
        }
    }

    pub fn for_review_selection() -> Self {
        Self {
            service: review_keychain_service(),
            account: "review-provider-selection".to_string(),
        }
    }

    fn entry(&self) -> Result<keyring::Entry, String> {
        keyring::Entry::new(&self.service, &self.account)
            .map_err(|err| format!("system keychain unavailable: {}", err))
    }
}

fn review_keychain_service() -> String {
    #[cfg(all(target_os = "linux", feature = "review-pty-fixture"))]
    if let Some(service) = crate::review_pty_fixture::service() {
        return service;
    }
    KEYCHAIN_SERVICE.to_string()
}

pub fn save_review_selection(
    store: &dyn SecretStore,
    provider: ReviewApiProvider,
    model: &str,
) -> Result<(), String> {
    if model.trim().is_empty() || model.len() > 256 || model.chars().any(char::is_control) {
        return Err("invalid model".into());
    }
    let value = serde_json::json!({"provider": provider.id(), "model": model}).to_string();
    store.set_secret(&value)
}

pub fn read_review_selection(
    store: &dyn SecretStore,
) -> Result<Option<(ReviewApiProvider, String)>, String> {
    let Some(value) = store.get_secret()? else {
        return Ok(None);
    };
    if value.len() > 2048 {
        return Err("invalid review selection".into());
    }
    let value: serde_json::Value =
        serde_json::from_str(&value).map_err(|_| "invalid review selection")?;
    let provider = value
        .get("provider")
        .and_then(serde_json::Value::as_str)
        .and_then(ReviewApiProvider::from_config)
        .ok_or("invalid review selection")?;
    let model = value
        .get("model")
        .and_then(serde_json::Value::as_str)
        .ok_or("invalid review selection")?;
    if model.trim().is_empty() || model.len() > 256 || model.chars().any(char::is_control) {
        return Err("invalid review selection".into());
    }
    Ok(Some((provider, model.to_string())))
}

impl Default for KeyringSecretStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for KeyringSecretStore {
    fn set_secret(&self, value: &str) -> Result<(), String> {
        self.entry()?
            .set_password(value)
            .map_err(|err| format!("failed to store the secret in the system keychain: {}", err))
    }

    fn get_secret(&self) -> Result<Option<String>, String> {
        match self.entry()?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(format!("failed to read the system keychain: {}", err)),
        }
    }

    fn delete_secret(&self) -> Result<(), String> {
        match self.entry()?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(format!(
                "failed to delete the secret from the system keychain: {}",
                err
            )),
        }
    }
}

#[derive(Default)]
pub struct MemorySecretStore {
    value: Mutex<Option<String>>,
}

impl SecretStore for MemorySecretStore {
    fn set_secret(&self, value: &str) -> Result<(), String> {
        *self
            .value
            .lock()
            .expect("memory secret store mutex poisoned") = Some(value.to_string());
        Ok(())
    }

    fn get_secret(&self) -> Result<Option<String>, String> {
        Ok(self
            .value
            .lock()
            .expect("memory secret store mutex poisoned")
            .clone())
    }

    fn delete_secret(&self) -> Result<(), String> {
        *self
            .value
            .lock()
            .expect("memory secret store mutex poisoned") = None;
        Ok(())
    }
}

pub struct FailingSecretStore;

impl SecretStore for FailingSecretStore {
    fn set_secret(&self, _value: &str) -> Result<(), String> {
        Err("system keychain unavailable".to_string())
    }

    fn get_secret(&self) -> Result<Option<String>, String> {
        Err("system keychain unavailable".to_string())
    }

    fn delete_secret(&self) -> Result<(), String> {
        Err("system keychain unavailable".to_string())
    }
}

pub struct FileSecretStore {
    path: PathBuf,
}

impl FileSecretStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn read_all(&self) -> Result<serde_json::Value, String> {
        match std::fs::read_to_string(&self.path) {
            Ok(content) => {
                let value: serde_json::Value = serde_json::from_str(&content)
                    .map_err(|err| format!("invalid secret store file: {}", err))?;
                if !value.is_object() {
                    return Err("invalid secret store file: expected a JSON object".to_string());
                }
                Ok(value)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::json!({})),
            Err(err) => Err(format!("failed to read the secret store file: {}", err)),
        }
    }

    fn write_all(&self, value: &serde_json::Value) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create the secret store directory: {}", err))?;
        }
        let content = serde_json::to_string_pretty(value)
            .map_err(|err| format!("failed to serialize the secret store: {}", err))?;
        std::fs::write(&self.path, content)
            .map_err(|err| format!("failed to write the secret store file: {}", err))
    }
}

impl SecretStore for FileSecretStore {
    fn set_secret(&self, value: &str) -> Result<(), String> {
        let mut all = self.read_all()?;
        all[KEYCHAIN_NVD_ACCOUNT] = serde_json::json!(value);
        self.write_all(&all)
    }

    fn get_secret(&self) -> Result<Option<String>, String> {
        Ok(self
            .read_all()?
            .get(KEYCHAIN_NVD_ACCOUNT)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string))
    }

    fn delete_secret(&self) -> Result<(), String> {
        let mut all = self.read_all()?;
        if let serde_json::Value::Object(map) = &mut all {
            map.remove(KEYCHAIN_NVD_ACCOUNT);
        }
        self.write_all(&all)
    }
}

pub fn default_secret_store() -> Arc<dyn SecretStore> {
    #[cfg(debug_assertions)]
    if let Ok(path) = std::env::var(TEST_SECRET_STORE_ENV) {
        if !path.is_empty() {
            return Arc::new(FileSecretStore::new(PathBuf::from(path)));
        }
    }
    Arc::new(KeyringSecretStore::new())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvdKeyStatus {
    pub stored_in_keychain: Result<bool, String>,
    pub from_environment: bool,
}

impl NvdKeyStatus {
    fn localized_description(&self) -> &'static str {
        let key = match &self.stored_in_keychain {
            Ok(true) => "config_status_keychain",
            Ok(false) if self.from_environment => "config_status_environment",
            Ok(false) => "config_status_missing",
            Err(_) if self.from_environment => "config_status_unavailable_environment",
            Err(_) => "config_status_unavailable",
        };
        crate::i18n::t(key)
    }
    pub fn describe(&self) -> String {
        match &self.stored_in_keychain {
            Ok(true) => "configured (source: system keychain)".to_string(),
            Ok(false) if self.from_environment => {
                "configured (source: environment fallback)".to_string()
            }
            Ok(false) => "not configured".to_string(),
            Err(_) if self.from_environment => {
                "system keychain unavailable; configured via environment fallback".to_string()
            }
            Err(_) => "system keychain unavailable; not configured".to_string(),
        }
    }
}

pub fn nvd_key_status(store: &dyn SecretStore) -> NvdKeyStatus {
    let stored_in_keychain = store
        .get_secret()
        .map(|value| value.is_some_and(|inner| !inner.trim().is_empty()));
    let from_environment = environment_fallback().is_some();
    NvdKeyStatus {
        stored_in_keychain,
        from_environment,
    }
}

pub fn resolve_nvd_api_key(store: &dyn SecretStore) -> Option<String> {
    match store.get_secret() {
        Ok(Some(value)) if !value.trim().is_empty() => return Some(value),
        _ => {}
    }
    environment_fallback()
}

// This fallback exists for CI and headless environments where the system keychain
// is unavailable. It is not recommended for local use because environment variables
// can leak through shell history, process inspection, inherited processes, or CI logs.
// Prefer storing the key in the operating system keychain.
fn environment_fallback() -> Option<String> {
    std::env::var(NVD_KEY_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn mask_secret(value: &str) -> String {
    "•".repeat(value.chars().count())
}

pub fn run_config_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let store = default_secret_store();
    match args.first().map(String::as_str) {
        Some("set-nvd-key") => set_nvd_key_command(&*store),
        Some("remove-nvd-key") => remove_nvd_key_command(&*store),
        Some("status") => status_command(&*store),
        _ => Err(crate::i18n::t("config_invalid").into()),
    }
}

pub fn set_nvd_key_command(store: &dyn SecretStore) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::IsTerminal;

    if std::io::stdin().is_terminal() {
        println!("{}", crate::i18n::t("config_prompt_help"));
        let value = rpassword::prompt_password(crate::i18n::t("config_prompt"))?;
        apply_set_nvd_key(store, value)
    } else {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        apply_set_nvd_key(store, line)
    }
}

pub fn apply_set_nvd_key(
    store: &dyn SecretStore,
    raw: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let value = raw.trim().to_string();
    if value.is_empty() {
        return Err(crate::i18n::t("config_empty").into());
    }
    store
        .set_secret(&value)
        .map_err(|err| -> Box<dyn std::error::Error> {
            crate::i18n::tf("config_store_error", &[&err.to_string()]).into()
        })?;
    println!("{}", crate::i18n::t("config_saved"));
    Ok(())
}

pub fn remove_nvd_key_command(store: &dyn SecretStore) -> Result<(), Box<dyn std::error::Error>> {
    match store.get_secret() {
        Ok(None) => println!("{}", crate::i18n::t("config_no_stored_key")),
        Ok(Some(_)) => {
            store
                .delete_secret()
                .map_err(|err| -> Box<dyn std::error::Error> {
                    crate::i18n::tf("config_remove_error", &[&err.to_string()]).into()
                })?;
            println!("{}", crate::i18n::t("config_removed"));
        }
        Err(err) => {
            return Err(crate::i18n::tf("config_access_error", &[&err.to_string()]).into());
        }
    }
    Ok(())
}

pub fn status_command(store: &dyn SecretStore) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{}",
        crate::i18n::tf(
            "config_status",
            &[nvd_key_status(store).localized_description()]
        )
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an isolated Linux keyutils session; use keyctl session"]
    fn isolated_linux_keyring_roundtrip() {
        let directory = tempfile::tempdir().unwrap();
        let service = format!(
            "tucupi-test-{}",
            directory.path().file_name().unwrap().to_string_lossy()
        );
        let store = KeyringSecretStore {
            service,
            account: "synthetic".into(),
        };
        assert_eq!(store.get_secret().unwrap(), None);
        store.set_secret("synthetic-value").unwrap();
        assert_eq!(
            store.get_secret().unwrap().as_deref(),
            Some("synthetic-value")
        );
        store.delete_secret().unwrap();
        assert_eq!(store.get_secret().unwrap(), None);
    }

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn memory_store_roundtrip_set_get_delete() {
        let store = MemorySecretStore::default();

        assert_eq!(store.get_secret().unwrap(), None);
        store.set_secret("first-key").unwrap();
        assert_eq!(store.get_secret().unwrap(), Some("first-key".to_string()));
        store.delete_secret().unwrap();
        assert_eq!(store.get_secret().unwrap(), None);
    }

    #[test]
    fn file_store_roundtrip_missing_file_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("secrets.json");
        let store = FileSecretStore::new(path);

        assert_eq!(store.get_secret().unwrap(), None);
        store.set_secret("file-key").unwrap();
        assert_eq!(store.get_secret().unwrap(), Some("file-key".to_string()));
        store.delete_secret().unwrap();
        assert_eq!(store.get_secret().unwrap(), None);
    }

    #[test]
    fn file_store_rejects_non_object_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        std::fs::write(&path, "[]").unwrap();
        let store = FileSecretStore::new(path);

        assert!(store.get_secret().is_err());
    }

    #[test]
    fn resolve_prefers_keychain_over_environment() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(NVD_KEY_ENV, "env-key");

        let store = MemorySecretStore::default();
        store.set_secret("keychain-key").unwrap();

        assert_eq!(
            resolve_nvd_api_key(&store),
            Some("keychain-key".to_string())
        );
        std::env::remove_var(NVD_KEY_ENV);
    }

    #[test]
    fn resolve_falls_back_to_environment_without_keychain_secret() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(NVD_KEY_ENV, "env-key");

        let store = MemorySecretStore::default();

        assert_eq!(resolve_nvd_api_key(&store), Some("env-key".to_string()));
        std::env::remove_var(NVD_KEY_ENV);
    }

    #[test]
    fn resolve_falls_back_to_environment_when_keychain_fails() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(NVD_KEY_ENV, "env-key");

        assert_eq!(
            resolve_nvd_api_key(&FailingSecretStore),
            Some("env-key".to_string())
        );
        std::env::remove_var(NVD_KEY_ENV);
    }

    #[test]
    fn resolve_returns_none_without_keychain_and_environment() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var(NVD_KEY_ENV);

        assert_eq!(resolve_nvd_api_key(&FailingSecretStore), None);
        assert_eq!(resolve_nvd_api_key(&MemorySecretStore::default()), None);
    }

    #[test]
    fn status_describe_reports_configuration_without_leaking_value() {
        let store = MemorySecretStore::default();
        store.set_secret("super-secret-value-123").unwrap();

        let status = nvd_key_status(&store);

        assert_eq!(status.describe(), "configured (source: system keychain)");
        assert!(!status.describe().contains("super-secret-value-123"));
    }

    #[test]
    fn status_describe_covers_all_states() {
        let environment_status = NvdKeyStatus {
            stored_in_keychain: Ok(false),
            from_environment: true,
        };
        assert_eq!(
            environment_status.describe(),
            "configured (source: environment fallback)"
        );

        let not_set_status = NvdKeyStatus {
            stored_in_keychain: Ok(false),
            from_environment: false,
        };
        assert_eq!(not_set_status.describe(), "not configured");

        let unavailable_status = NvdKeyStatus {
            stored_in_keychain: Err("boom".to_string()),
            from_environment: false,
        };
        assert_eq!(
            unavailable_status.describe(),
            "system keychain unavailable; not configured"
        );
    }

    #[test]
    fn apply_set_nvd_key_rejects_empty_input() {
        let store = MemorySecretStore::default();

        assert!(apply_set_nvd_key(&store, "   \n".to_string()).is_err());
        assert_eq!(store.get_secret().unwrap(), None);
    }

    #[test]
    fn apply_set_nvd_key_trims_whitespace() {
        let store = MemorySecretStore::default();

        apply_set_nvd_key(&store, "  padded-key  \n".to_string()).unwrap();
        assert_eq!(store.get_secret().unwrap(), Some("padded-key".to_string()));
    }

    #[test]
    fn remove_nvd_key_command_is_idempotent() {
        let store = MemorySecretStore::default();

        assert!(remove_nvd_key_command(&store).is_ok());
        store.set_secret("key").unwrap();
        assert!(remove_nvd_key_command(&store).is_ok());
        assert_eq!(store.get_secret().unwrap(), None);
        assert!(remove_nvd_key_command(&store).is_ok());
    }

    #[test]
    fn mask_secret_replaces_every_character() {
        assert_eq!(mask_secret("abc"), "•••");
        assert_eq!(mask_secret(""), "");
        assert_eq!(mask_secret("k1"), "••");
    }

    #[test]
    #[ignore = "touches the real OS keychain; run manually with --ignored"]
    fn keyring_store_roundtrip_against_real_keychain() {
        let store = KeyringSecretStore::new();

        store.delete_secret().unwrap();
        assert_eq!(store.get_secret().unwrap(), None);
        store.set_secret("tucupi-ci-dummy").unwrap();
        assert_eq!(
            store.get_secret().unwrap(),
            Some("tucupi-ci-dummy".to_string())
        );
        store.delete_secret().unwrap();
        assert_eq!(store.get_secret().unwrap(), None);
    }
}
