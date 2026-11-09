use crate::models::{Dependency, Ecosystem};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

const PREVIEW_STREAM_LIMIT: usize = 64_000;

async fn read_preview_stream(
    mut reader: impl AsyncRead + Unpin,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::with_capacity(PREVIEW_STREAM_LIMIT);
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let keep = count.min(PREVIEW_STREAM_LIMIT.saturating_sub(retained.len()));
        retained.extend_from_slice(&buffer[..keep]);
        truncated |= keep < count;
    }
    Ok((retained, truncated))
}

/// A preview is advisory: managers can resolve additional changes at execution.
#[derive(Debug, Clone)]
pub enum ImpactPreview {
    ManagerOutput { text: String, truncated: bool },
    Unavailable,
}

pub async fn preview(dep: &Dependency, dir: &Path) -> ImpactPreview {
    match preview_command(dep, dir) {
        Some((program, args)) => {
            let result = run_preview(Path::new(&program), &args, dir).await;
            if program == "pacman" {
                if let ImpactPreview::ManagerOutput { text, truncated } = result {
                    return ImpactPreview::ManagerOutput {
                        text: format!("{}\n\n{}", crate::i18n::t("impact_pacman_caveat"), text),
                        truncated,
                    };
                }
                return ImpactPreview::Unavailable;
            }
            result
        }
        None => ImpactPreview::Unavailable,
    }
}

fn preview_command(dep: &Dependency, dir: &Path) -> Option<(String, Vec<String>)> {
    if dep.ecosystem == Ecosystem::Homebrew && dep.is_global {
        return Some((
            "brew".into(),
            vec![
                "upgrade".into(),
                "--dry-run".into(),
                "--".into(),
                dep.name.clone(),
            ],
        ));
    }
    if dep.ecosystem == Ecosystem::Npm {
        let (program, mut args) = crate::app::get_upgrade_cmd(dep, dir)?;
        if program == "npm" {
            args.extend(
                [
                    "--dry-run",
                    "--ignore-scripts",
                    "--json",
                    "--no-audit",
                    "--no-fund",
                ]
                .into_iter()
                .map(str::to_string),
            );
            return Some((program, args));
        }
    }
    if dep.ecosystem == Ecosystem::Php && !dep.is_global {
        let (program, mut args) = crate::app::get_upgrade_cmd(dep, dir)?;
        args.extend(
            [
                "--dry-run",
                "--no-scripts",
                "--no-plugins",
                "--no-interaction",
                "--no-ansi",
            ]
            .into_iter()
            .map(str::to_string),
        );
        return Some((program, args));
    }
    if dep.ecosystem == Ecosystem::Python && !dep.is_global {
        let (program, mut args) = crate::app::get_upgrade_cmd(dep, dir)?;
        args.extend(
            [
                "--dry-run",
                "--only-binary=:all:",
                "--no-input",
                "--disable-pip-version-check",
            ]
            .into_iter()
            .map(str::to_string),
        );
        return Some((program, args));
    }
    if dep.ecosystem == Ecosystem::Mise && dep.is_global {
        let (program, mut args) = crate::app::get_upgrade_cmd(dep, dir)?;
        args.push("--dry-run".into());
        return Some((program, args));
    }
    if dep.ecosystem == Ecosystem::Dart && !dep.is_global {
        let (program, mut args) = crate::app::get_upgrade_cmd(dep, dir)?;
        args.extend(["--dry-run".into(), "--no-precompile".into()]);
        return Some((program, args));
    }
    if dep.ecosystem == Ecosystem::Pacman
        && dep.is_global
        && dep.origin == Some(crate::models::PackageOrigin::OfficialRepo)
    {
        return Some((
            "pacman".into(),
            vec![
                "-S".into(),
                "--print".into(),
                "--print-format".into(),
                "%n %v".into(),
                "--noconfirm".into(),
                "--".into(),
                dep.name.clone(),
            ],
        ));
    }
    None
}

pub(crate) async fn run_preview(executable: &Path, args: &[String], dir: &Path) -> ImpactPreview {
    let mut command = Command::new(executable);
    command
        .args(args)
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut attempts = 0;
    let mut child = loop {
        match command.spawn() {
            Ok(child) => break child,
            Err(error) => {
                // Linux ETXTBSY means exec did not start, so retrying cannot
                // repeat a package-manager operation. Keep the delay bounded.
                if cfg!(target_os = "linux") && error.raw_os_error() == Some(26) && attempts < 5 {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                }
                return ImpactPreview::Unavailable;
            }
        }
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return ImpactPreview::Unavailable;
    };
    let operation = async {
        tokio::join!(
            read_preview_stream(stdout),
            read_preview_stream(stderr),
            child.wait()
        )
    };
    match tokio::time::timeout(Duration::from_secs(30), operation).await {
        Ok((Ok((stdout, stdout_truncated)), Ok((stderr, stderr_truncated)), Ok(status)))
            if status.success() =>
        {
            let mut text = String::from_utf8_lossy(&stdout).into_owned();
            if !stderr.is_empty() {
                text.push_str(&String::from_utf8_lossy(&stderr));
            }
            if text.trim().is_empty() {
                ImpactPreview::Unavailable
            } else {
                let mut chars = text.chars();
                let preview: String = chars.by_ref().take(16_000).collect();
                ImpactPreview::ManagerOutput {
                    text: preview,
                    truncated: chars.next().is_some() || stdout_truncated || stderr_truncated,
                }
            }
        }
        _ => ImpactPreview::Unavailable,
    }
}

/// Test-only access to the real preview runner, not a supervision boundary.
#[cfg(feature = "codex-fixture")]
#[doc(hidden)]
pub async fn fixture_run_preview(executable: &Path, args: &[String], dir: &Path) -> ImpactPreview {
    run_preview(executable, args, dir).await
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn preview_retries_only_when_executable_temporarily_busy() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("preview");
        std::fs::write(&executable, "#!/bin/sh\nprintf 'synthetic plan\\n'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&executable)
            .unwrap();
        let error = std::process::Command::new(&executable).spawn().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(26));
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            drop(writer);
        });
        assert!(matches!(
            run_preview(&executable, &[], dir.path()).await,
            ImpactPreview::ManagerOutput { text, .. } if text.contains("synthetic plan")
        ));
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&executable)
            .unwrap();
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                run_preview(&executable, &[], dir.path())
            )
            .await
            .unwrap(),
            ImpactPreview::Unavailable
        ));
        drop(writer);
    }

    #[tokio::test]
    async fn preview_stream_capture_is_bounded_and_drains_input() {
        use tokio::io::AsyncReadExt;
        let input = tokio::io::repeat(b'x').take(1_000_000);
        let (bytes, truncated) = read_preview_stream(input).await.unwrap();
        assert_eq!(bytes.len(), PREVIEW_STREAM_LIMIT);
        assert!(truncated);
        let input = tokio::io::repeat(b'y').take(PREVIEW_STREAM_LIMIT as u64);
        let (bytes, truncated) = read_preview_stream(input).await.unwrap();
        assert_eq!(bytes.len(), PREVIEW_STREAM_LIMIT);
        assert!(!truncated);
    }

    #[tokio::test]
    async fn preview_drains_large_stdout_and_stderr_without_deadlock() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("manager");
        std::fs::write(&executable, "#!/bin/sh\nhead -c 1000000 /dev/zero | tr '\\0' x\nhead -c 1000000 /dev/zero | tr '\\0' y >&2\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_preview(&executable, &[], dir.path()),
        )
        .await
        .unwrap();
        let ImpactPreview::ManagerOutput {
            text: output,
            truncated,
        } = result
        else {
            panic!("expected truncated preview");
        };
        assert!(truncated);
        assert!(output.chars().count() < 17_000);
    }

    #[tokio::test]
    async fn long_preview_explicitly_reports_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("preview");
        std::fs::write(
            &executable,
            "#!/bin/sh\nhead -c 16001 /dev/zero | tr '\\0' x\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = run_preview(&executable, &[], dir.path()).await;
        match result {
            ImpactPreview::ManagerOutput { text, truncated } => {
                assert!(truncated);
                assert_eq!(text.chars().filter(|c| *c == 'x').count(), 16000);
            }
            ImpactPreview::Unavailable => panic!("expected preview"),
        }
    }

    fn dependency() -> Dependency {
        Dependency {
            name: "ca-certificates".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: true,
            origin: None,
        }
    }

    #[tokio::test]
    async fn preview_uses_dry_run_and_preserves_dependents_output() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("brew");
        std::fs::write(&executable, "#!/bin/sh\n[ \"$1\" = upgrade ] && [ \"$2\" = --dry-run ] && [ \"$4\" = ca-certificates ] || exit 1\nprintf 'Would upgrade dependents: a b c\\n'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (_, args) = preview_command(&dependency(), dir.path()).unwrap();
        match run_preview(&executable, &args, dir.path()).await {
            ImpactPreview::ManagerOutput {
                text: output,
                truncated: false,
            } => assert!(output.contains("dependents: a b c")),
            ImpactPreview::ManagerOutput { .. } => panic!("unexpected truncation"),
            ImpactPreview::Unavailable => panic!("expected preview"),
        }
    }

    #[tokio::test]
    async fn preview_failure_is_not_an_empty_plan() {
        let result = run_preview(Path::new("/nonexistent-brew"), &[], Path::new(".")).await;
        assert!(matches!(result, ImpactPreview::Unavailable));
    }

    #[tokio::test]
    async fn successful_empty_output_is_unavailable_not_a_complete_plan() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("manager");
        std::fs::write(&executable, "#!/bin/sh\nprintf '  \\n'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            run_preview(&executable, &[], dir.path()).await,
            ImpactPreview::Unavailable
        ));
    }

    #[test]
    fn npm_preview_matches_upgrade_and_disables_lifecycle_scripts() {
        let mut dep = dependency();
        dep.ecosystem = Ecosystem::Npm;
        dep.is_global = false;
        let dir = tempfile::tempdir().unwrap();
        let (program, args) = preview_command(&dep, dir.path()).unwrap();
        assert_eq!(program, "npm");
        assert_eq!(args[0..2], ["install", "ca-certificates@2"]);
        assert!(args.contains(&"--dry-run".to_string()));
        assert!(args.contains(&"--ignore-scripts".to_string()));
        std::fs::write(dir.path().join("pnpm-lock.yaml"), "").unwrap();
        assert!(preview_command(&dep, dir.path()).is_none());
        dep.is_global = true;
        let (program, args) = preview_command(&dep, dir.path()).unwrap();
        assert_eq!(program, "npm");
        assert!(args.contains(&"-g".to_string()));
    }

    #[tokio::test]
    async fn unsupported_javascript_managers_never_fall_back_to_npm_preview() {
        for marker in [
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lock",
            "bun.lockb",
            "deno.json",
            "deno.jsonc",
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(marker), "{}").unwrap();
            let mut dep = dependency();
            dep.name = "example".into();
            dep.ecosystem = Ecosystem::Npm;
            dep.is_global = false;
            let (program, _) = crate::app::get_upgrade_cmd(&dep, dir.path()).unwrap();
            assert_ne!(program, "npm", "{marker}");
            assert!(preview_command(&dep, dir.path()).is_none(), "{marker}");
            assert!(
                matches!(preview(&dep, dir.path()).await, ImpactPreview::Unavailable),
                "{marker}"
            );
        }
    }

    #[tokio::test]
    async fn unsupported_ecosystems_and_scopes_return_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        for (ecosystem, is_global) in [
            (Ecosystem::Cargo, false),
            (Ecosystem::Cargo, true),
            (Ecosystem::Go, false),
            (Ecosystem::Elixir, false),
            (Ecosystem::Ruby, false),
            (Ecosystem::Python, true),
            (Ecosystem::Dart, true),
        ] {
            let mut dep = dependency();
            dep.ecosystem = ecosystem;
            dep.is_global = is_global;
            assert!(
                preview_command(&dep, dir.path()).is_none(),
                "{ecosystem:?} global={is_global}"
            );
            assert!(
                matches!(preview(&dep, dir.path()).await, ImpactPreview::Unavailable),
                "{ecosystem:?} global={is_global}"
            );
        }
    }

    #[test]
    fn composer_preview_matches_upgrade_and_disables_scripts_and_plugins() {
        let mut dep = dependency();
        dep.name = "example/library".into();
        dep.ecosystem = Ecosystem::Php;
        dep.is_global = false;
        let (program, args) = preview_command(&dep, Path::new(".")).unwrap();
        assert_eq!(program, "composer");
        assert_eq!(args[0..2], ["require", "example/library:^2"]);
        for flag in [
            "--dry-run",
            "--no-scripts",
            "--no-plugins",
            "--no-interaction",
            "--no-ansi",
        ] {
            assert!(args.contains(&flag.to_string()), "missing {flag}");
        }
        dep.is_global = true;
        assert!(preview_command(&dep, Path::new(".")).is_none());
    }

    #[test]
    fn pip_preview_matches_upgrade_and_restricts_source_packages() {
        let mut dep = dependency();
        dep.name = "example".into();
        dep.ecosystem = Ecosystem::Python;
        dep.is_global = false;
        let (program, args) = preview_command(&dep, Path::new(".")).unwrap();
        assert_eq!(program, if cfg!(windows) { "pip" } else { "pip3" });
        assert_eq!(&args[0..3], ["install", "--upgrade", "example==2"]);
        for flag in [
            "--dry-run",
            "--only-binary=:all:",
            "--no-input",
            "--disable-pip-version-check",
        ] {
            assert!(args.contains(&flag.to_string()), "missing {flag}");
        }
        dep.is_global = true;
        assert!(preview_command(&dep, Path::new(".")).is_none());
    }

    #[test]
    fn mise_preview_matches_upgrade_with_bump_and_dry_run() {
        let mut dep = dependency();
        dep.name = "node".into();
        dep.ecosystem = Ecosystem::Mise;
        dep.is_global = true;
        let (program, args) = preview_command(&dep, Path::new(".")).unwrap();
        assert_eq!(program, "mise");
        assert_eq!(args, ["upgrade", "--bump", "node", "--dry-run"]);
        dep.is_global = false;
        assert!(preview_command(&dep, Path::new(".")).is_none());
    }

    #[test]
    fn dart_preview_matches_upgrade_without_writing_or_precompiling() {
        let mut dep = dependency();
        dep.name = "example".into();
        dep.ecosystem = Ecosystem::Dart;
        dep.is_global = false;
        let (program, args) = preview_command(&dep, Path::new(".")).unwrap();
        assert_eq!(program, "dart");
        assert_eq!(
            args,
            ["pub", "add", "example:2", "--dry-run", "--no-precompile"]
        );
        dep.is_global = true;
        assert!(preview_command(&dep, Path::new(".")).is_none());
    }

    #[test]
    fn pacman_preview_is_limited_to_identified_official_packages() {
        let mut dep = dependency();
        dep.name = "example".into();
        dep.ecosystem = Ecosystem::Pacman;
        dep.origin = Some(crate::models::PackageOrigin::OfficialRepo);
        let (program, args) = preview_command(&dep, Path::new(".")).unwrap();
        assert_eq!(program, "pacman");
        assert_eq!(
            args,
            [
                "-S",
                "--print",
                "--print-format",
                "%n %v",
                "--noconfirm",
                "--",
                "example"
            ]
        );
        for origin in [
            Some(crate::models::PackageOrigin::Aur),
            Some(crate::models::PackageOrigin::Unknown),
            None,
        ] {
            dep.origin = origin;
            assert!(preview_command(&dep, Path::new(".")).is_none());
        }
        dep.origin = Some(crate::models::PackageOrigin::OfficialRepo);
        dep.is_global = false;
        assert!(preview_command(&dep, Path::new(".")).is_none());
    }

    #[tokio::test]
    async fn pacman_preview_displays_package_versions_and_handles_failures() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("pacman");
        std::fs::write(&executable, "#!/bin/sh\n[ \"$1\" = -S ] && [ \"$2\" = --print ] && [ \"$3\" = --print-format ] && [ \"$4\" = '%n %v' ] && [ \"$5\" = --noconfirm ] && [ \"$6\" = -- ] && [ \"$7\" = example ] || exit 1\nprintf 'example 2\\nindirect 3\\n'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut dep = dependency();
        dep.name = "example".into();
        dep.ecosystem = Ecosystem::Pacman;
        dep.origin = Some(crate::models::PackageOrigin::OfficialRepo);
        let (_, args) = preview_command(&dep, dir.path()).unwrap();
        assert!(
            matches!(run_preview(&executable, &args, dir.path()).await, ImpactPreview::ManagerOutput { text, .. } if text.contains("indirect 3"))
        );
        assert!(matches!(
            run_preview(Path::new("/nonexistent-pacman"), &args, dir.path()).await,
            ImpactPreview::Unavailable
        ));
    }

    #[tokio::test]
    async fn dart_preview_reports_changes_and_failed_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("dart");
        std::fs::write(&executable, "#!/bin/sh\n[ \"$1\" = pub ] && [ \"$2\" = add ] && [ \"$3\" = example:2 ] && [ \"$4\" = --dry-run ] && [ \"$5\" = --no-precompile ] || exit 1\nprintf 'Would update example and indirect\\n'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut dep = dependency();
        dep.name = "example".into();
        dep.ecosystem = Ecosystem::Dart;
        dep.is_global = false;
        let (_, args) = preview_command(&dep, dir.path()).unwrap();
        assert!(
            matches!(run_preview(&executable, &args, dir.path()).await, ImpactPreview::ManagerOutput { text, .. } if text.contains("indirect"))
        );
        assert!(matches!(
            run_preview(Path::new("/nonexistent-dart"), &args, dir.path()).await,
            ImpactPreview::Unavailable
        ));
    }

    #[tokio::test]
    async fn mise_preview_surfaces_planned_changes_and_failures() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("mise");
        std::fs::write(&executable, "#!/bin/sh\n[ \"$1\" = upgrade ] && [ \"$2\" = --bump ] && [ \"$3\" = node ] && [ \"$4\" = --dry-run ] || exit 1\nprintf 'Would install node@22\\nWould bump node in config\\n'\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut dep = dependency();
        dep.name = "node".into();
        dep.ecosystem = Ecosystem::Mise;
        let (_, args) = preview_command(&dep, dir.path()).unwrap();
        assert!(
            matches!(run_preview(&executable, &args, dir.path()).await, ImpactPreview::ManagerOutput { text, .. } if text.contains("Would bump node"))
        );
        assert!(matches!(
            run_preview(Path::new("/nonexistent-mise"), &args, dir.path()).await,
            ImpactPreview::Unavailable
        ));
    }

    #[tokio::test]
    async fn pip_preview_displays_changes_and_handles_unavailable_wheels() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("pip3");
        std::fs::write(&executable, "#!/bin/sh\ncase \"$*\" in *--dry-run*--only-binary=:all:*) printf 'Would install example-2 indirect-3\\n';; *) exit 1;; esac\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut dep = dependency();
        dep.ecosystem = Ecosystem::Python;
        dep.is_global = false;
        let (_, args) = preview_command(&dep, dir.path()).unwrap();
        assert!(
            matches!(run_preview(&executable, &args, dir.path()).await, ImpactPreview::ManagerOutput { text: output, .. } if output.contains("indirect-3"))
        );
        std::fs::write(
            &executable,
            "#!/bin/sh\nprintf 'No compatible wheel\\n' >&2\nexit 1\n",
        )
        .unwrap();
        assert!(matches!(
            run_preview(&executable, &args, dir.path()).await,
            ImpactPreview::Unavailable
        ));
    }

    #[tokio::test]
    async fn composer_preview_preserves_stderr_and_treats_failure_as_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("composer");
        std::fs::write(
            &executable,
            "#!/bin/sh\nprintf 'Updating example/indirect (1 => 2)\\n' >&2\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut dep = dependency();
        dep.ecosystem = Ecosystem::Php;
        dep.is_global = false;
        let (_, args) = preview_command(&dep, dir.path()).unwrap();
        assert!(
            matches!(run_preview(&executable, &args, dir.path()).await, ImpactPreview::ManagerOutput { text: output, .. } if output.contains("example/indirect"))
        );
        std::fs::write(
            &executable,
            "#!/bin/sh\nprintf 'resolution failed\\n' >&2\nexit 1\n",
        )
        .unwrap();
        assert!(matches!(
            run_preview(&executable, &args, dir.path()).await,
            ImpactPreview::Unavailable
        ));
    }
}
