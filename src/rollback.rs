use crate::models::{Dependency, Ecosystem};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct BackupEntry {
    original_path: PathBuf,
    backup_path: PathBuf,
    existed_before: bool,
}

pub struct BackupHandle {
    _temp_dir: TempDir,
    entries: Vec<BackupEntry>,
}

pub fn prepare_local_backup(dep: &Dependency, dir: &Path) -> Result<Option<BackupHandle>> {
    if dep.is_global {
        return Ok(None);
    }

    let mut candidates = ecosystem_files(dep.ecosystem, dir);
    candidates.sort();
    candidates.dedup();

    if candidates.is_empty() {
        return Ok(None);
    }

    let temp_dir = tempfile::tempdir().context("failed to create backup temp dir")?;
    let mut entries = Vec::new();

    for relative_path in candidates {
        let original_path = dir.join(&relative_path);
        let backup_path = temp_dir.path().join(&relative_path);
        let existed_before = original_path.exists();

        if let Some(parent) = backup_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create backup directory for {}",
                    relative_path.display()
                )
            })?;
        }

        if existed_before {
            fs::copy(&original_path, &backup_path)
                .with_context(|| format!("failed to back up {}", original_path.display()))?;
        }

        entries.push(BackupEntry {
            original_path,
            backup_path,
            existed_before,
        });
    }

    Ok(Some(BackupHandle {
        _temp_dir: temp_dir,
        entries,
    }))
}

pub fn restore_backup(backup: BackupHandle) -> Result<()> {
    for entry in backup.entries {
        if entry.existed_before {
            if let Some(parent) = entry.original_path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to recreate parent directory for {}",
                        entry.original_path.display()
                    )
                })?;
            }

            fs::copy(&entry.backup_path, &entry.original_path)
                .with_context(|| format!("failed to restore {}", entry.original_path.display()))?;
        } else if entry.original_path.exists() {
            fs::remove_file(&entry.original_path).with_context(|| {
                format!(
                    "failed to remove new file {}",
                    entry.original_path.display()
                )
            })?;
        }
    }

    Ok(())
}

pub fn commit_backup(_backup: BackupHandle) {}

fn ecosystem_files(ecosystem: Ecosystem, dir: &Path) -> Vec<PathBuf> {
    match ecosystem {
        Ecosystem::Cargo => vec![PathBuf::from("Cargo.toml"), PathBuf::from("Cargo.lock")],
        Ecosystem::Go => vec![PathBuf::from("go.mod"), PathBuf::from("go.sum")],
        Ecosystem::Dart => vec![PathBuf::from("pubspec.yaml"), PathBuf::from("pubspec.lock")],
        Ecosystem::Elixir => vec![PathBuf::from("mix.exs"), PathBuf::from("mix.lock")],
        Ecosystem::Npm => npm_related_files(dir),
        Ecosystem::Php => vec![
            PathBuf::from("composer.json"),
            PathBuf::from("composer.lock"),
        ],
        Ecosystem::Ruby => vec![PathBuf::from("Gemfile"), PathBuf::from("Gemfile.lock")],
        Ecosystem::Python => vec![
            PathBuf::from("pyproject.toml"),
            PathBuf::from("requirements.txt"),
            PathBuf::from("Pipfile"),
            PathBuf::from("Pipfile.lock"),
            PathBuf::from("poetry.lock"),
        ],
        Ecosystem::Pacman | Ecosystem::Mise | Ecosystem::Homebrew => Vec::new(),
    }
}

fn npm_related_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = vec![
        PathBuf::from("package.json"),
        PathBuf::from("package-lock.json"),
        PathBuf::from("npm-shrinkwrap.json"),
        PathBuf::from("pnpm-lock.yaml"),
        PathBuf::from("yarn.lock"),
        PathBuf::from("bun.lock"),
        PathBuf::from("bun.lockb"),
        PathBuf::from("deno.json"),
        PathBuf::from("deno.jsonc"),
        PathBuf::from("deno.lock"),
    ];

    if dir.join("package.json").exists() {
        files.push(PathBuf::from("package.json"));
    }

    files
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_original_file_contents() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest = temp_dir.path().join("Cargo.toml");
        fs::write(&manifest, "before").unwrap();

        let dep = Dependency {
            name: "serde".to_string(),
            current_version: "1.0.0".to_string(),
            latest_version: "1.0.1".to_string(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };

        let backup = prepare_local_backup(&dep, temp_dir.path())
            .unwrap()
            .unwrap();
        fs::write(&manifest, "after").unwrap();
        restore_backup(backup).unwrap();

        assert_eq!(fs::read_to_string(manifest).unwrap(), "before");
    }
}
