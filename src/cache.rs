use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
struct CacheEntry<T> {
    created_at_secs: u64,
    value: T,
}

pub fn read_cache<T: DeserializeOwned>(kind: &str, key: &str, ttl: Duration) -> Option<T> {
    let path = cache_path(kind, key).ok()?;
    let content = fs::read_to_string(path).ok()?;
    let entry: CacheEntry<T> = serde_json::from_str(&content).ok()?;
    let now = now_secs().ok()?;

    if now.saturating_sub(entry.created_at_secs) > ttl.as_secs() {
        return None;
    }

    Some(entry.value)
}

pub fn write_cache<T: Serialize>(kind: &str, key: &str, value: &T) -> Result<()> {
    let path = cache_path(kind, key)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create cache directory")?;
    }

    let entry = CacheEntry {
        created_at_secs: now_secs()?,
        value,
    };

    fs::write(path, serde_json::to_vec(&entry)?).context("failed to write cache file")?;
    Ok(())
}

fn cache_path(kind: &str, key: &str) -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is not set")?;
    let cache_root = PathBuf::from(home).join(".cache").join("tucupi").join(kind);
    Ok(cache_root.join(format!("{}.json", hash_key(key))))
}

fn hash_key(key: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

fn now_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_hash_is_stable() {
        assert_eq!(hash_key("abc"), hash_key("abc"));
    }
}
