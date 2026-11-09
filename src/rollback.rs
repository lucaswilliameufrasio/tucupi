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

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn fixture_keep_synthetic_backup(backup: BackupHandle) -> PathBuf {
    // Fixture only: keeping a directory is not an authenticated recovery record.
    backup._temp_dir.keep()
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

    // This drill relies on the system sha256sum command and disposable input;
    // it is not a general backup format or safe for real data.
    #[cfg(target_os = "linux")]
    const FIXTURE_ATTEMPT: &str = "0123456789abcdef0123456789abcdef";

    #[cfg(target_os = "linux")]
    fn fixture_manifest(payload: &[u8]) -> std::io::Result<String> {
        use std::io::{Error, ErrorKind, Write};
        use std::process::{Command, Stdio};
        if payload.len() > 4096 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "fixture payload too large",
            ));
        }
        let mut command = Command::new("/usr/bin/sha256sum")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        command
            .stdin
            .take()
            .ok_or_else(|| Error::other("missing hash stdin"))?
            .write_all(payload)?;
        let output = command.wait_with_output()?;
        let result = std::str::from_utf8(&output.stdout)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid hash"))?;
        let digest = result
            .split_whitespace()
            .next()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing hash"))?;
        if !output.status.success()
            || digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::new(ErrorKind::InvalidData, "invalid hash"));
        }
        Ok(format!(
            "fixture-recovery-v3\nattempt={FIXTURE_ATTEMPT}\nCargo.toml=present:{}:{digest}\nCargo.lock=absent\n",
            payload.len()
        ))
    }

    #[cfg(target_os = "linux")]
    fn fixture_restore_set(set: &Path, target: &Path) -> std::io::Result<()> {
        use std::io::{Error, ErrorKind, Write};
        if fs::read(set.join("complete"))? != b"fixture-complete-v1\n" {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "incomplete fixture publication",
            ));
        }
        if fs::metadata(set.join("manifest"))?.len() > 256
            || fs::metadata(set.join("payload"))?.len() > 4096
        {
            return Err(Error::new(ErrorKind::InvalidData, "oversized fixture"));
        }
        let manifest = fs::read(set.join("manifest"))?;
        let payload = fs::read(set.join("payload"))?;
        if manifest != fixture_manifest(&payload)?.as_bytes() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid synthetic recovery set",
            ));
        }
        // A fresh destination refuses overwrite, including a repeated restore.
        fs::create_dir(target)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target.join("Cargo.toml"))?;
        output.write_all(&payload)?;
        output.sync_all()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn fixture_restore_bound_set(set: &Path, state: &Path, target: &Path) -> std::io::Result<()> {
        let attempt = crate::recovery_state::fixture_read_pending_intent(state)?;
        if attempt != FIXTURE_ATTEMPT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fixture attempt mismatch",
            ));
        }
        // This is a sequential consistency check, not authentication, an
        // atomic snapshot, cleanup evidence, or authorization for live work.
        fixture_restore_set(set, target)
    }

    // Fixture result only: this records a restored copy, never a live rollback
    // or proof of process-tree cleanup. An incomplete file is not success.
    #[cfg(target_os = "linux")]
    fn fixture_recover_to_new_target(
        set: &Path,
        state: &Path,
        target: &Path,
    ) -> std::io::Result<()> {
        use std::io::Write;
        fixture_restore_bound_set(set, state, target)?;
        let mut result = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target.join("fixture-recovery-result"))?;
        write!(result, "fixture-recovery-result-v1\nattempt={FIXTURE_ATTEMPT}\nisolated-copy=restored\ndescendant-cleanup=unknown\noriginal-rollback=unknown\n")?;
        result.sync_all()?;
        fs::File::open(target)?.sync_all()?;
        Ok(())
    }

    // Only for the owned temporary fixture tree. The comparison and rename
    // are not atomic together and provide no protection from concurrent writers.
    #[cfg(target_os = "linux")]
    fn fixture_rollback_file(
        root: &tempfile::TempDir,
        restored: &Path,
        expected: &[u8],
    ) -> std::io::Result<()> {
        fixture_rollback_with_hook(root.path(), restored, expected, |_| {})
    }

    #[cfg(target_os = "linux")]
    fn fixture_rollback_with_hook(
        root: &Path,
        restored: &Path,
        expected: &[u8],
        mut hook: impl FnMut(&str),
    ) -> std::io::Result<()> {
        use std::io::Write;
        let destination = root.join("Cargo.toml");
        let original = fs::read(restored.join("Cargo.toml"))?;
        let current = fs::read(&destination)?;
        if current == original {
            // This fixture is already in its expected synthetic state. It
            // does not establish who wrote it or that descendants are gone.
            fs::File::open(root)?.sync_all()?;
            return Ok(());
        }
        if current != expected {
            return Err(std::io::Error::other("synthetic destination changed"));
        }
        let mut temporary = tempfile::NamedTempFile::new_in(root)?;
        temporary.write_all(&original)?;
        temporary.as_file().sync_all()?;
        hook("prepared");
        temporary
            .persist(&destination)
            .map_err(|error| error.error)?;
        hook("renamed");
        fs::File::open(root)?.sync_all()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn interrupted_synthetic_rollback_keeps_attempt_pending() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        const CHILD: &str = "TUCUPI_ROLLBACK_INTERRUPT_ROOT";
        if let Some(path) = std::env::var_os(CHILD) {
            let root = Path::new(&path);
            let point = std::env::var("TUCUPI_ROLLBACK_INTERRUPT_POINT").unwrap();
            fixture_rollback_with_hook(root, &root.join("restored"), b"modified", |step| {
                if step == point {
                    std::process::exit(77);
                }
            })
            .unwrap();
            panic!("fixture interruption did not occur");
        }
        for point in ["prepared", "renamed"] {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            crate::recovery_state::provision_state_directory(
                root.path(),
                std::ffi::OsStr::new("state"),
            )
            .unwrap();
            let state = root.path().join("state");
            let _pending =
                crate::same_user_supervisor::PendingAttempt::begin(&state, FIXTURE_ATTEMPT)
                    .unwrap();
            fs::write(root.path().join("Cargo.toml"), b"modified").unwrap();
            fs::write(root.path().join("protected"), b"unchanged").unwrap();
            fs::create_dir(root.path().join("restored")).unwrap();
            fs::write(root.path().join("restored/Cargo.toml"), b"original").unwrap();
            let result = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "rollback::tests::interrupted_synthetic_rollback_keeps_attempt_pending",
                ])
                .env_clear()
                .env("HOME", root.path())
                .env("TMPDIR", root.path())
                .env(CHILD, root.path())
                .env("TUCUPI_ROLLBACK_INTERRUPT_POINT", point)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert_eq!(result.code(), Some(77));
            let expected: &[u8] = if point == "prepared" {
                b"modified"
            } else {
                b"original"
            };
            assert_eq!(fs::read(root.path().join("Cargo.toml")).unwrap(), expected);
            assert_eq!(
                fs::read(root.path().join("protected")).unwrap(),
                b"unchanged"
            );
            fixture_rollback_file(&root, &root.path().join("restored"), b"modified").unwrap();
            assert_eq!(
                fs::read(root.path().join("Cargo.toml")).unwrap(),
                b"original"
            );
            fixture_rollback_file(&root, &root.path().join("restored"), b"modified").unwrap();
            assert_eq!(
                fs::read(root.path().join("protected")).unwrap(),
                b"unchanged"
            );
            assert_eq!(
                crate::recovery_state::local_recovery_evidence_at(&state),
                crate::recovery_state::LocalRecoveryEvidence::PendingIntentObserved
            );
            assert!(
                crate::same_user_supervisor::PendingAttempt::begin(&state, FIXTURE_ATTEMPT)
                    .is_err()
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn synthetic_recovery_accepts_variable_binary_content() {
        let root = tempfile::tempdir().unwrap();
        let set = root.path().join("set");
        fs::create_dir(&set).unwrap();
        let content = b"another fixture\0\xff\n";
        fs::write(set.join("payload"), content).unwrap();
        fs::write(set.join("manifest"), fixture_manifest(content).unwrap()).unwrap();
        let target = root.path().join("restore");
        assert!(fixture_restore_set(&set, &target).is_err());
        assert!(!target.exists());
        fs::write(set.join("complete"), b"partial").unwrap();
        assert_eq!(
            fixture_restore_set(&set, &target).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(!target.exists());
        fs::write(set.join("complete"), b"fixture-complete-v1\n").unwrap();
        fixture_restore_set(&set, &target).unwrap();
        assert_eq!(fs::read(target.join("Cargo.toml")).unwrap(), content);
        assert!(!target.join("Cargo.lock").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn synthetic_restore_rejects_missing_partial_and_mismatched_intent() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let set = root.path().join("set");
        fs::create_dir(&set).unwrap();
        let content = b"isolated backup";
        fs::write(set.join("payload"), content).unwrap();
        fs::write(set.join("manifest"), fixture_manifest(content).unwrap()).unwrap();
        fs::write(set.join("complete"), b"fixture-complete-v1\n").unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("state"),
        )
        .unwrap();
        let state = root.path().join("state");
        let target = root.path().join("restored");
        assert!(fixture_restore_bound_set(&set, &state, &target).is_err());
        assert!(!target.exists());
        let directory = crate::recovery_state::open_provisioned_state_directory(&state).unwrap();
        crate::recovery_state::persist_pending_intent(
            &directory,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        assert_eq!(
            fixture_restore_bound_set(&set, &state, &target)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(!target.exists());
        fs::write(state.join("pending-intent"), b"partial").unwrap();
        assert!(fixture_restore_bound_set(&set, &state, &target).is_err());
        assert!(!target.exists());
        assert_eq!(fs::read(set.join("payload")).unwrap(), content);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn synthetic_recovery_set_survives_interruption_and_refuses_corruption() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        const CHILD: &str = "TUCUPI_RECOVERY_SET_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let root = Path::new(&path);
            let set = root.join("recovery-set");
            fs::create_dir(&set).unwrap();
            let mut payload = fs::File::create(set.join("payload")).unwrap();
            let original = fs::read(root.join("Cargo.toml")).unwrap();
            payload.write_all(&original).unwrap();
            payload.sync_all().unwrap();
            let mut manifest = fs::File::create(set.join("manifest")).unwrap();
            manifest
                .write_all(fixture_manifest(&original).unwrap().as_bytes())
                .unwrap();
            manifest.sync_all().unwrap();
            fs::File::open(&set).unwrap().sync_all().unwrap();
            let mut complete = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(set.join("complete"))
                .unwrap();
            complete.write_all(b"fixture-complete-v1\n").unwrap();
            complete.sync_all().unwrap();
            fs::File::open(&set).unwrap().sync_all().unwrap();
            let pending = crate::same_user_supervisor::PendingAttempt::begin(
                &root.join("state"),
                FIXTURE_ATTEMPT,
            )
            .unwrap();
            let mut child = Command::new("/bin/sh")
                .args(["-c", "IFS= read -r line"])
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut observed = pending.bind_child(&mut child).unwrap();
            assert_eq!(observed.poll_and_record_exit().unwrap(), None);
            assert!(!observed.permits_operation());
            fs::write(root.join("Cargo.toml"), b"synthetic modified").unwrap();
            std::process::exit(77);
        }
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        crate::recovery_state::provision_state_directory(
            root.path(),
            std::ffi::OsStr::new("state"),
        )
        .unwrap();
        fs::write(root.path().join("Cargo.toml"), b"synthetic original").unwrap();
        fs::write(root.path().join("protected"), b"unrelated").unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "rollback::tests::synthetic_recovery_set_survives_interruption_and_refuses_corruption"])
            .env_clear().env("HOME", root.path()).env("TMPDIR", root.path()).env(CHILD, root.path())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
        assert_eq!(status.code(), Some(77));
        let state = root.path().join("state");
        assert_eq!(
            crate::recovery_state::local_recovery_evidence_at(&state),
            crate::recovery_state::LocalRecoveryEvidence::PendingChildLocatorObserved
        );
        assert!(!state.join("pending-exit").exists());
        assert!(
            crate::same_user_supervisor::PendingAttempt::begin(&state, FIXTURE_ATTEMPT).is_err()
        );
        let set = root.path().join("recovery-set");
        let target = root.path().join("restored");
        fixture_recover_to_new_target(&set, &state, &target).unwrap();
        assert_eq!(
            fs::read(target.join("Cargo.toml")).unwrap(),
            b"synthetic original"
        );
        assert!(!target.join("Cargo.lock").exists());
        assert_eq!(fs::read_to_string(target.join("fixture-recovery-result")).unwrap(), format!("fixture-recovery-result-v1\nattempt={FIXTURE_ATTEMPT}\nisolated-copy=restored\ndescendant-cleanup=unknown\noriginal-rollback=unknown\n"));
        assert_eq!(
            crate::recovery_state::local_recovery_evidence_at(&state),
            crate::recovery_state::LocalRecoveryEvidence::PendingChildLocatorObserved
        );
        assert_eq!(
            fixture_restore_bound_set(&set, &state, &target)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        let valid_manifest = fs::read(set.join("manifest")).unwrap();
        fs::write(set.join("manifest"), b"fixture-recovery-v3\nCargo.toml=").unwrap();
        let partial = root.path().join("partial");
        assert_eq!(
            fixture_restore_set(&set, &partial).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(!partial.exists());
        fs::write(set.join("manifest"), valid_manifest).unwrap();
        fs::write(set.join("payload"), b"synthetic Original").unwrap();
        let rejected = root.path().join("rejected");
        assert_eq!(
            fixture_restore_set(&set, &rejected).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(!rejected.exists());
        assert_eq!(
            fs::read(root.path().join("Cargo.toml")).unwrap(),
            b"synthetic modified"
        );
        assert_eq!(
            fs::read(root.path().join("protected")).unwrap(),
            b"unrelated"
        );
        assert!(fixture_rollback_file(&root, &target, b"unexpected").is_err());
        assert_eq!(
            fs::read(root.path().join("Cargo.toml")).unwrap(),
            b"synthetic modified"
        );
        fixture_rollback_file(&root, &target, b"synthetic modified").unwrap();
        assert_eq!(
            fs::read(root.path().join("Cargo.toml")).unwrap(),
            b"synthetic original"
        );
        assert_eq!(
            fs::read(root.path().join("protected")).unwrap(),
            b"unrelated"
        );
        assert_eq!(
            crate::recovery_state::local_recovery_evidence_at(&state),
            crate::recovery_state::LocalRecoveryEvidence::PendingChildLocatorObserved
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn interrupted_backup_can_be_restored_to_isolated_fixture() {
        use std::process::{Command, Stdio};
        const CHILD: &str = "TUCUPI_ROLLBACK_DRILL_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = Path::new(&root);
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            let backup = prepare_local_backup(&dep, root).unwrap().unwrap();
            let snapshot = fixture_keep_synthetic_backup(backup);
            fs::write(
                root.join("snapshot-path"),
                snapshot.as_os_str().as_encoded_bytes(),
            )
            .unwrap();
            fs::write(root.join("Cargo.toml"), b"synthetic modified").unwrap();
            std::process::exit(77);
        }
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("Cargo.toml"), b"synthetic original").unwrap();
        fs::write(root.path().join("protected"), b"unrelated").unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "rollback::tests::interrupted_backup_can_be_restored_to_isolated_fixture",
            ])
            .env_clear()
            .env("HOME", root.path())
            .env("TMPDIR", root.path())
            .env(CHILD, root.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77));
        let snapshot =
            PathBuf::from(fs::read_to_string(root.path().join("snapshot-path")).unwrap());
        assert_eq!(
            fs::read(root.path().join("Cargo.toml")).unwrap(),
            b"synthetic modified"
        );
        assert_eq!(
            fs::read(snapshot.join("Cargo.toml")).unwrap(),
            b"synthetic original"
        );

        // Restore into a newly created destination, never the interrupted tree.
        let destination = tempfile::tempdir_in(root.path()).unwrap();
        let staging = tempfile::tempdir_in(root.path()).unwrap();
        fs::copy(
            snapshot.join("Cargo.toml"),
            staging.path().join("Cargo.toml"),
        )
        .unwrap();
        let backup = BackupHandle {
            entries: vec![BackupEntry {
                original_path: destination.path().join("Cargo.toml"),
                backup_path: staging.path().join("Cargo.toml"),
                existed_before: true,
            }],
            _temp_dir: staging,
        };
        restore_backup(backup).unwrap();
        assert_eq!(
            fs::read(destination.path().join("Cargo.toml")).unwrap(),
            b"synthetic original"
        );
        assert_eq!(
            fs::read(root.path().join("Cargo.toml")).unwrap(),
            b"synthetic modified"
        );
        assert_eq!(
            fs::read(root.path().join("protected")).unwrap(),
            b"unrelated"
        );
    }

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
