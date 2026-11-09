use crate::adapters::{check_all_outdated, check_global_outdated};
use crate::app::{get_upgrade_cmd, run_upgrade_process};
use crate::config::Config;
use crate::i18n::{t, tf};
use crate::models::{
    Dependency, Ecosystem, FreshnessInfo, PackageOrigin, ProvenanceInfo, VulnerabilityInfo,
};
use crate::review::{ReviewReport, ReviewVerdict};
use crate::rollback::{commit_backup, prepare_local_backup, restore_backup};
use crate::security::{check_provenance, AuditFailure, SecurityChecker};
use crate::ui;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::{Backend, ClearType, CrosstermBackend, WindowSize};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};

const MAX_LOG_LINES_PER_DEPENDENCY: usize = 10_000;

// Allows Ratatui to clear its internal hidden-cursor flag after a failed
// restoration, without reporting that the real cursor was restored.
struct BatchBackend<B> {
    inner: B,
    skip_cursor_show: bool,
    #[cfg(test)]
    drop_marker: Option<PathBuf>,
}

#[cfg(test)]
impl<B> Drop for BatchBackend<B> {
    fn drop(&mut self) {
        if let Some(path) = &self.drop_marker {
            let _ = std::fs::write(path, "dropped");
        }
    }
}

impl<B: std::io::Write> std::io::Write for BatchBackend<B> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.inner)
    }
}

impl<B: Backend> Backend for BatchBackend<B> {
    type Error = B::Error;
    fn draw<'a, I>(&mut self, content: I) -> Result<(), Self::Error>
    where
        I: Iterator<Item = (u16, u16, &'a ratatui::buffer::Cell)>,
    {
        self.inner.draw(content)
    }
    fn append_lines(&mut self, n: u16) -> Result<(), Self::Error> {
        self.inner.append_lines(n)
    }
    fn hide_cursor(&mut self) -> Result<(), Self::Error> {
        self.inner.hide_cursor()
    }
    fn show_cursor(&mut self) -> Result<(), Self::Error> {
        if self.skip_cursor_show {
            self.skip_cursor_show = false;
            return Ok(());
        }
        self.inner.show_cursor()
    }
    fn get_cursor_position(&mut self) -> Result<ratatui::layout::Position, Self::Error> {
        self.inner.get_cursor_position()
    }
    fn set_cursor_position<P: Into<ratatui::layout::Position>>(
        &mut self,
        position: P,
    ) -> Result<(), Self::Error> {
        self.inner.set_cursor_position(position)
    }
    fn clear(&mut self) -> Result<(), Self::Error> {
        self.inner.clear()
    }
    fn clear_region(&mut self, clear_type: ClearType) -> Result<(), Self::Error> {
        self.inner.clear_region(clear_type)
    }
    fn size(&self) -> Result<ratatui::layout::Size, Self::Error> {
        self.inner.size()
    }
    fn window_size(&mut self) -> Result<WindowSize, Self::Error> {
        self.inner.window_size()
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        self.inner.flush()
    }
}

fn restore_batch_cursor<B: Backend>(
    terminal: &mut Terminal<BatchBackend<B>>,
) -> Result<(), B::Error> {
    let result = terminal.show_cursor();
    if result.is_err() {
        // The first error remains authoritative; this only disarms Drop's retry.
        terminal.backend_mut().skip_cursor_show = true;
        let _ = terminal.show_cursor();
    }
    result
}

/// Synthetic batch admission only. It does not start package operations or
/// establish production recovery. A failed callback never clears the marker.
#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
#[doc(hidden)]
pub fn fixture_guarded_batch_attempt<T>(
    marker: &crate::codex_supervision::FixtureRecoveryMarker,
    attempt_id: &str,
    start_synthetic: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    marker.arm_with_identity(attempt_id)?;
    start_synthetic()
}

#[cfg(test)]
mod impact_tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn synthetic_retained_backup_survives_runtime_exit() {
        if let Some(root) = std::env::var_os("TUCUPI_RETAIN_BACKUP_CHILD") {
            let root = PathBuf::from(root);
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            let backup = prepare_local_backup(&dep, &root).unwrap().unwrap();
            let path = crate::rollback::fixture_keep_synthetic_backup(backup);
            std::fs::write(
                root.join("snapshot-path"),
                path.to_string_lossy().as_bytes(),
            )
            .unwrap();
            let mut child = tokio::process::Command::new(root.join("cargo"))
                .current_dir(&root)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            tokio::time::timeout(Duration::from_secs(8), async {
                while !root.join("exit-runtime").exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(child.try_wait().unwrap().is_none());
            return;
        }
        let status = std::process::Command::new("/usr/bin/python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/batch_upgrade_rollback_fixture.py"
            ))
            .arg(std::env::current_exe().unwrap())
            .arg("retain-fixture")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn synthetic_upgrade_interruption_backup_rollback_fixture() {
        if let Some(root) = std::env::var_os("TUCUPI_ROLLBACK_CHILD") {
            let root = PathBuf::from(root);
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            let (tx, mut rx) = mpsc::unbounded_channel();
            spawn_upgrade(0, 42, &dep, &root, &tx);
            if root.join("runtime-exit-mode").exists() {
                tokio::time::timeout(Duration::from_secs(8), async {
                    while !root.join("exit-runtime").exists() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .unwrap();
            } else {
                let event = tokio::time::timeout(Duration::from_secs(8), rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(matches!(event, BatchEvent::UpgradeFinished(0, 42, Err(_))));
                std::fs::write(root.join("failure-observed"), "ok").unwrap();
            }
            return;
        }
        let status = std::process::Command::new("/usr/bin/python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/batch_upgrade_rollback_fixture.py"
            ))
            .arg(std::env::current_exe().unwrap())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn synthetic_kill_on_drop_runtime_exit_experiment() {
        if let Some(root) = std::env::var_os("TUCUPI_KILL_DROP_CHILD") {
            let root = PathBuf::from(root);
            let mut child = tokio::process::Command::new(root.join("brew"))
                .current_dir(&root)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            tokio::time::timeout(Duration::from_secs(8), async {
                while !root.join("runtime-exit").exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            // Abort the owning task by returning without waiting; no rollback runs.
            assert!(child.try_wait().unwrap().is_none());
            return;
        }
        let status = std::process::Command::new("/usr/bin/python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/batch_upgrade_runtime_exit_fixture.py"
            ))
            .arg(std::env::current_exe().unwrap())
            .arg("kill-on-drop")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn synthetic_batch_upgrade_runtime_exit_process_lifetimes() {
        if let Some(root) = std::env::var_os("TUCUPI_UPGRADE_EXIT_CHILD") {
            let root = PathBuf::from(root);
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: true,
                origin: None,
            };
            let (tx, _rx) = mpsc::unbounded_channel();
            spawn_upgrade(0, 42, &dep, &root, &tx);
            tokio::time::timeout(Duration::from_secs(8), async {
                while !root.join("runtime-exit").exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            return;
        }
        let status = std::process::Command::new("/usr/bin/python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/batch_upgrade_runtime_exit_fixture.py"
            ))
            .arg(std::env::current_exe().unwrap())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn batch_cursor_restoration_preserves_error_and_drops_backend() {
        use std::cell::Cell;
        use std::rc::Rc;
        struct Probe {
            fail: bool,
            shows: Rc<Cell<usize>>,
            drops: Rc<Cell<usize>>,
        }
        impl Drop for Probe {
            fn drop(&mut self) {
                self.drops.set(self.drops.get() + 1);
            }
        }
        impl Backend for Probe {
            type Error = std::io::Error;
            fn draw<'a, I>(&mut self, _: I) -> std::io::Result<()>
            where
                I: Iterator<Item = (u16, u16, &'a ratatui::buffer::Cell)>,
            {
                Ok(())
            }
            fn hide_cursor(&mut self) -> std::io::Result<()> {
                Ok(())
            }
            fn show_cursor(&mut self) -> std::io::Result<()> {
                self.shows.set(self.shows.get() + 1);
                if self.fail {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "synthetic cursor failure",
                    ));
                }
                Ok(())
            }
            fn get_cursor_position(&mut self) -> std::io::Result<ratatui::layout::Position> {
                Ok((0, 0).into())
            }
            fn set_cursor_position<P: Into<ratatui::layout::Position>>(
                &mut self,
                _: P,
            ) -> std::io::Result<()> {
                Ok(())
            }
            fn clear(&mut self) -> std::io::Result<()> {
                Ok(())
            }
            fn clear_region(&mut self, _: ClearType) -> std::io::Result<()> {
                Ok(())
            }
            fn size(&self) -> std::io::Result<ratatui::layout::Size> {
                Ok(ratatui::layout::Size::new(80, 24))
            }
            fn window_size(&mut self) -> std::io::Result<WindowSize> {
                Ok(WindowSize {
                    columns_rows: ratatui::layout::Size::new(80, 24),
                    pixels: ratatui::layout::Size::new(0, 0),
                })
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for fail in [false, true] {
            let shows = Rc::new(Cell::new(0));
            let drops = Rc::new(Cell::new(0));
            let backend = BatchBackend {
                inner: Probe {
                    fail,
                    shows: shows.clone(),
                    drops: drops.clone(),
                },
                skip_cursor_show: false,
                drop_marker: None,
            };
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.hide_cursor().unwrap();
            let result = restore_batch_cursor(&mut terminal);
            if fail {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
                assert_eq!(error.to_string(), "synthetic cursor failure");
            } else {
                assert!(result.is_ok());
            }
            assert_eq!(shows.get(), 1);
            drop(terminal);
            assert_eq!(shows.get(), 1, "drop retried cursor restoration");
            assert_eq!(drops.get(), 1, "backend resources were not dropped");
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn interactive_synthetic_upgrade_pty() {
        if let Some(root) = std::env::var_os("TUCUPI_UPGRADE_PTY_CHILD") {
            let root = PathBuf::from(root);
            let result = run(root.clone(), false).await;
            let text = match result {
                Ok(()) => "ok".to_string(),
                Err(error) => error.to_string(),
            };
            std::fs::write(root.join("result"), text).unwrap();
            return;
        }
        let status = std::process::Command::new("/usr/bin/python3")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/batch_upgrade_pty_fixture.py"
            ))
            .arg(std::env::current_exe().unwrap())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn synthetic_upgrade_blocks_batch_quit_until_completion() {
        use std::os::unix::fs::PermissionsExt;
        if std::env::var_os("TUCUPI_SYNTHETIC_UPGRADE_CHILD").is_none() {
            let dir = tempfile::tempdir().unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "batch::impact_tests::synthetic_upgrade_blocks_batch_quit_until_completion",
                ])
                .env_clear()
                .env("HOME", dir.path())
                .env("TMPDIR", dir.path())
                .env("PATH", dir.path())
                .env("TUCUPI_SYNTHETIC_UPGRADE_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let root = PathBuf::from(std::env::var_os("HOME").unwrap());
        let program = root.join("brew");
        std::fs::write(&program, "#!/usr/bin/python3\nimport pathlib,time\np=pathlib.Path('.')\n(p/'started').touch()\nfor _ in range(500):\n if (p/'proceed').exists(): break\n time.sleep(0.01)\nelse: raise SystemExit(1)\n(p/'finished').touch()\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: true,
            origin: None,
        };
        let item = BatchItem {
            dependency: dep.clone(),
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: Some(42),
            security_pending: None,
            logs: Vec::new(),
        };
        let mut screen = BatchScreen::Executing {
            items: vec![item],
            current_cursor: 0,
            progress_message: String::new(),
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        spawn_upgrade(0, 42, &dep, &root, &tx);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !root.join("started").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let mut running = true;
        screen = handle_key_input(
            screen,
            KeyCode::Char('q'),
            &tx,
            &Config::default(),
            &root,
            false,
            &mut running,
        );
        assert!(running);
        assert!(batch_shutdown_status(&screen).is_err());
        let error = batch_finish_status(
            &screen,
            Err(std::io::Error::other("synthetic terminal failure")),
            [Ok(()), Ok(()), Ok(())],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("synthetic terminal failure"));
        assert!(error.contains(t("batch_upgrade_exit_unknown")));
        assert!(
            matches!(&screen, BatchScreen::Executing { progress_message, .. } if progress_message == t("batch_upgrade_quit_wait"))
        );
        std::fs::write(root.join("proceed"), "").unwrap();
        let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(event, BatchEvent::UpgradeFinished(0, 42, Ok(()))));
        assert!(process_upgrade_finished(&mut screen, 0, 42, Ok(())));
        assert!(root.join("finished").exists());
        assert!(rx.try_recv().is_err());
        screen = handle_key_input(
            screen,
            KeyCode::Char('q'),
            &tx,
            &Config::default(),
            &root,
            false,
            &mut running,
        );
        assert!(!running);
        assert!(batch_shutdown_status(&screen).is_ok());
    }

    #[tokio::test]
    async fn batch_report_rescan_ignores_old_and_duplicate_scan_events() {
        if std::env::var_os("TUCUPI_RESCAN_TEST_CHILD").is_none() {
            let directory = tempfile::tempdir().unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "batch::impact_tests::batch_report_rescan_ignores_old_and_duplicate_scan_events"])
                .env_clear()
                .env("HOME", directory.path())
                .env("TMPDIR", directory.path())
                .env("PATH", directory.path())
                .env("TUCUPI_RESCAN_TEST_CHILD", "1")
                .status().unwrap();
            assert!(status.success());
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let dep = |name: &str| Dependency {
            name: name.into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let item = BatchItem {
            dependency: dep("report"),
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Upgraded,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: vec!["synthetic-log".into()],
        };
        let mut screen = BatchScreen::Report {
            items: vec![item],
            scan_error: false,
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        // A delayed completion must not replace the existing report.
        apply_scan_results(&mut screen, 1, vec![dep("old")]);
        assert!(
            matches!(&screen, BatchScreen::Report { items, scan_error: false } if matches!(items[0].outcome, ItemOutcome::Upgraded) && items[0].logs == ["synthetic-log"])
        );
        let mut running = true;
        screen = handle_key_input(
            screen,
            KeyCode::Char('r'),
            &tx,
            &Config::default(),
            directory.path(),
            false,
            &mut running,
        );
        let attempt = match screen {
            BatchScreen::Scanning(Some(attempt)) => attempt,
            _ => panic!("rescan did not start"),
        };
        let stale = attempt.checked_add(1).unwrap();
        apply_scan_results(&mut screen, stale, vec![dep("old")]);
        assert!(matches!(screen, BatchScreen::Scanning(Some(active)) if active == attempt));
        let event = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let BatchEvent::ScanFinished(finished_attempt, result) = event else {
            panic!("unexpected event")
        };
        assert_eq!(finished_attempt, attempt);
        assert!(result.is_empty());
        apply_scan_results(&mut screen, finished_attempt, result);
        assert!(matches!(&screen, BatchScreen::Select { items, .. } if items.is_empty()));
        apply_scan_results(&mut screen, attempt, vec![dep("duplicate")]);
        apply_scan_results(&mut screen, stale, vec![dep("old")]);
        assert!(matches!(&screen, BatchScreen::Select { items, .. } if items.is_empty()));
        assert!(running);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn exhausted_batch_rescan_reports_error_without_altering_report_or_starting_work() {
        use ratatui::{backend::TestBackend, Terminal};
        for has_item in [false, true] {
            let item = BatchItem {
                dependency: Dependency {
                    name: "synthetic".into(),
                    current_version: "1".into(),
                    latest_version: "2".into(),
                    ecosystem: Ecosystem::Cargo,
                    is_global: false,
                    origin: None,
                },
                selection: SelectionState::Safe,
                vulns: None,
                outcome: ItemOutcome::Upgraded,
                review_pending: None,
                upgrade_pending: None,
                security_pending: None,
                logs: vec!["synthetic-log".into()],
            };
            let items = if has_item { vec![item] } else { Vec::new() };
            let (tx, mut rx) = mpsc::unbounded_channel();
            let counter = std::sync::atomic::AtomicU64::new(u64::MAX);
            let mut screen = begin_rescan(items, &tx, Path::new("."), false, &counter);
            assert!(
                matches!(&screen, BatchScreen::Report { items, scan_error: true } if items.len() == usize::from(has_item) && (!has_item || matches!(items[0].outcome, ItemOutcome::Upgraded) && items[0].logs == ["synthetic-log"]))
            );
            assert!(rx.try_recv().is_err());
            let mut terminal = Terminal::new(TestBackend::new(150, 20)).unwrap();
            terminal
                .draw(|frame| render_batch(frame, &mut screen))
                .unwrap();
            let buffer = terminal.backend().buffer();
            let text = (0..buffer.area.height)
                .map(|y| {
                    (0..buffer.area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains(t("scan_attempt_exhausted")), "{text}");
        }
    }

    #[test]
    fn synthetic_late_batch_scan_result_does_not_replace_newer_selection() {
        let dep = |name: &str| Dependency {
            name: name.into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let mut screen = BatchScreen::Scanning(Some(2));
        apply_scan_results(&mut screen, 1, vec![dep("old")]);
        assert!(matches!(screen, BatchScreen::Scanning(Some(2))));
        apply_scan_results(&mut screen, 2, vec![dep("new")]);
        assert!(
            matches!(&screen, BatchScreen::Select { items, .. } if items[0].dependency.name == "new")
        );
        apply_scan_results(&mut screen, 1, vec![dep("old")]);
        apply_scan_results(&mut screen, 2, vec![dep("duplicate")]);
        assert!(
            matches!(&screen, BatchScreen::Select { items, .. } if items[0].dependency.name == "new")
        );
        let BatchScreen::Select { items, .. } = screen else {
            panic!("expected selection");
        };
        let mut screen = BatchScreen::Executing {
            items,
            current_cursor: 0,
            progress_message: String::new(),
        };
        apply_scan_results(&mut screen, 2, vec![dep("duplicate")]);
        assert!(
            matches!(&screen, BatchScreen::Executing { items, .. } if items[0].dependency.name == "new")
        );
    }

    #[test]
    fn characterize_freshness_policy_in_batch_without_prescan() {
        let mut config = Config::default();
        config.security.pre_scan_security = Some(false);
        config.security.block_too_fresh = Some(true);
        for (ecosystem, provenance, freshness, expected) in [
            (
                Ecosystem::Cargo,
                None,
                FreshnessInfo::Unavailable,
                "audit_partial_blocked",
            ),
            (
                Ecosystem::Cargo,
                None,
                FreshnessInfo::VeryRecent(1),
                "blocked_too_fresh",
            ),
            (
                Ecosystem::Cargo,
                None,
                FreshnessInfo::Recent(5),
                "audit_partial_blocked",
            ),
            (
                Ecosystem::Cargo,
                None,
                FreshnessInfo::Mature(30),
                "audit_partial_blocked",
            ),
            (
                Ecosystem::Pacman,
                Some(false),
                FreshnessInfo::VeryRecent(1),
                "blocked_provenance_required",
            ),
            (
                Ecosystem::Pacman,
                Some(true),
                FreshnessInfo::VeryRecent(1),
                "blocked_too_fresh",
            ),
            (
                Ecosystem::Pacman,
                Some(true),
                FreshnessInfo::Unavailable,
                "audit_partial_blocked",
            ),
        ] {
            config.security.require_provenance = Some(ecosystem == Ecosystem::Pacman);
            let item = BatchItem {
                dependency: Dependency {
                    name: "synthetic".into(),
                    current_version: "1".into(),
                    latest_version: "2".into(),
                    ecosystem,
                    is_global: false,
                    origin: None,
                },
                selection: SelectionState::Safe,
                vulns: None,
                outcome: ItemOutcome::Pending,
                review_pending: None,
                upgrade_pending: None,
                security_pending: None,
                logs: Vec::new(),
            };
            let mut screen = BatchScreen::Executing {
                items: vec![item],
                current_cursor: 0,
                progress_message: String::new(),
            };
            let result = BatchSecurityResult {
                vuln_result: Err(AuditFailure {
                    message: "synthetic".into(),
                    findings: Vec::new(),
                    partial: true,
                }),
                freshness_info: freshness,
                provenance_info: provenance.map(|signature_verified| ProvenanceInfo {
                    validated_by: None,
                    install_date: None,
                    pkgbuild_age_days: None,
                    signature_verified,
                }),
            };
            let (tx, mut rx) = mpsc::unbounded_channel();
            assert!(process_security_checked(
                &mut screen,
                0,
                result,
                &config,
                Path::new("."),
                &tx
            ));
            assert!(
                matches!(&screen, BatchScreen::Executing { items, .. } if matches!(&items[0].outcome, ItemOutcome::Blocked(reason) if if expected == "audit_partial_blocked" { reason == &tf(expected, &[""]) } else { reason == t(expected) }))
            );
            assert!(rx.try_recv().is_err());
        }
    }

    #[test]
    fn space_on_empty_batch_selection_does_not_panic() {
        let screen = BatchScreen::Select {
            items: Vec::new(),
            cursor: 0,
            force_mode: false,
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut running = true;
        let next = handle_key_input(
            screen,
            KeyCode::Char(' '),
            &tx,
            &Config::default(),
            Path::new("."),
            false,
            &mut running,
        );
        assert!(matches!(next, BatchScreen::Select { items, cursor: 0, .. } if items.is_empty()));
        assert!(running);
        assert!(rx.try_recv().is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_batch_pty_disconnect_reports_unknown_cleanup() {
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        if let Some(root) = std::env::var_os("TUCUPI_BATCH_DISCONNECT_FIXTURE") {
            let root = PathBuf::from(root);
            let error = run(root.clone(), false).await.unwrap_err().to_string();
            std::fs::write(root.join("observed-error"), &error).unwrap();
            assert!(error.contains(t("batch_impact_cleanup_unknown")), "{error}");
            assert!(!error.contains("synthetic input failure"));
            std::fs::write(root.join("disconnect-verified"), "ok").unwrap();
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let script = root.join("brew");
        std::fs::write(&script, "#!/usr/bin/python3\nimport pathlib,time\np=pathlib.Path('.')\n(p/'fixture-ready').touch()\ntime.sleep(3)\n(p/'fixture-late').touch()\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (mut master, mut slave) = (-1, -1);
        let size = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty receives valid pointers and creates owned descriptors.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    &size,
                )
            },
            0
        );
        // SAFETY: master is the live descriptor returned by openpty; close it on exec.
        assert_eq!(
            unsafe { libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
        // SAFETY: the descriptors were returned by openpty.
        let master = unsafe { std::fs::File::from_raw_fd(master) };
        // SAFETY: the descriptors were returned by openpty.
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "batch::impact_tests::real_batch_pty_disconnect_reports_unknown_cleanup",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", root)
            .env("TMPDIR", root)
            .env("PATH", root)
            .env("TERM", "xterm")
            .env("TUCUPI_BATCH_TERMINAL_FIXTURE", root)
            .env("TUCUPI_BATCH_DISCONNECT_FIXTURE", root)
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(std::process::Stdio::null());
        // SAFETY: only the child session and controlling terminal are changed before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0
                    || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0
                    || libc::signal(libc::SIGHUP, libc::SIG_IGN) == libc::SIG_ERR
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(command);
        drop(slave);
        let ready = tokio::time::timeout(Duration::from_secs(5), async {
            while !root.join("fixture-ready").exists() {
                if child.try_wait().unwrap().is_some() {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            true
        })
        .await;
        if !matches!(ready, Ok(true)) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("synthetic preview did not start");
        }
        drop(master);
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert!(
            result.is_ok(),
            "batch did not return after disconnect: {result:?}"
        );
        let error = std::fs::read_to_string(root.join("observed-error")).unwrap();
        assert!(
            root.join("disconnect-verified").exists(),
            "observed: {error}"
        );
        tokio::time::sleep(Duration::from_millis(3200)).await;
        assert!(!root.join("fixture-late").exists());
        println!("real pty disconnect: batch returned unknown-cleanup warning; synthetic preview cancelled");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_batch_loop_handles_synthetic_terminal_failures_during_preview() {
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        if let Some(root) = std::env::var_os("TUCUPI_BATCH_TERMINAL_FIXTURE") {
            let root = PathBuf::from(root);
            let error = run(root.clone(), false).await.unwrap_err().to_string();
            assert!(error.contains("synthetic input failure"), "{error}");
            assert!(error.contains("synthetic restoration failure"), "{error}");
            assert!(error.contains(t("batch_impact_cleanup_unknown")), "{error}");
            std::fs::write(root.join("fixture-verified"), "ok").unwrap();
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let script = root.join("brew");
        std::fs::write(&script, "#!/usr/bin/python3\nimport pathlib,time\np=pathlib.Path('.')\n(p/'fixture-ready').touch()\ntime.sleep(2)\n(p/'fixture-late').touch()\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut master = -1;
        let mut slave = -1;
        let size = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: pointers reference initialized descriptors and a valid window size.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    &size,
                )
            },
            0
        );
        // SAFETY: openpty returned newly owned descriptors.
        let master = unsafe { std::fs::File::from_raw_fd(master) };
        // SAFETY: openpty returned newly owned descriptors.
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "batch::impact_tests::real_batch_loop_handles_synthetic_terminal_failures_during_preview", "--nocapture"])
            .env_clear().env("HOME", root).env("TMPDIR", root).env("PATH", root).env("TERM", "xterm")
            .env("TUCUPI_BATCH_TERMINAL_FIXTURE", root)
            .stdin(slave.try_clone().unwrap()).stdout(slave.try_clone().unwrap()).stderr(slave.try_clone().unwrap());
        // SAFETY: setsid and ioctl operate only on the child immediately before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(command);
        drop(slave);
        let reader = std::thread::spawn(move || {
            use std::io::Read;
            let mut master = master;
            let mut bytes = Vec::new();
            let _ = master.read_to_end(&mut bytes);
            bytes
        });
        let status = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        if status.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let output = reader.join().unwrap();
        assert!(
            matches!(status, Ok(status) if status.success()),
            "test terminal failed or timed out: {}",
            String::from_utf8_lossy(&output)
        );
        assert!(root.join("fixture-verified").exists());
        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert!(
            !root.join("fixture-late").exists(),
            "synthetic preview continued"
        );
        println!("real batch loop: injected input and restoration errors retained; preview cancellation requested");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn synthetic_aborted_preview_stops_direct_child_not_detached_descendant() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::time::Duration;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().to_path_buf();
        let script = "import os,pathlib,subprocess,time\np=pathlib.Path('.')\nsubprocess.Popen(['/usr/bin/python3','-c',\"import pathlib,time; time.sleep(0.5); pathlib.Path('child-late').touch()\"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,env={})\n(p/'pid').write_text(str(os.getpid()))\n(p/'ready').touch()\ntime.sleep(2)\n(p/'parent-late').touch()";
        let args = vec!["-c".to_string(), script.to_string()];
        let dir = root.clone();
        let task = tokio::spawn(async move {
            crate::impact::run_preview(Path::new("/usr/bin/python3"), &args, &dir).await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !root.join("ready").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let pid: u32 = std::fs::read_to_string(root.join("pid"))
            .unwrap()
            .parse()
            .unwrap();
        assert!(pid > 1);
        // SAFETY: pidfd_open receives the synthetic child's PID and returns a fresh descriptor.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        assert!(fd >= 0);
        // SAFETY: successful pidfd_open returns a fresh owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd is passed with a bounded timeout.
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 5000) }, 1);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !root.join("child-late").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(!root.join("parent-late").exists());
        println!("synthetic cancellation: direct child exited; detached descendant continued");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn synthetic_batch_runtime_exit_stops_direct_child_but_not_descendant() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::fs::PermissionsExt;
        use std::time::Duration;

        let root = if let Some(path) = std::env::var_os("TUCUPI_BATCH_EXIT_FIXTURE") {
            std::path::PathBuf::from(path)
        } else {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path();
            let script = root.join("brew");
            std::fs::write(&script, "#!/usr/bin/python3\nimport os,pathlib,subprocess,time\np=pathlib.Path('.')\nc=subprocess.Popen(['/usr/bin/python3','-c',\"import pathlib,time; time.sleep(1); pathlib.Path('descendant-late').touch()\"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, env={})\n(p/'parent-pid').write_text(str(os.getpid()))\n(p/'child-pid').write_text(str(c.pid))\n(p/'ready').touch()\ntime.sleep(4)\n(p/'parent-late').touch()\n").unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mut harness = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "batch::impact_tests::synthetic_batch_runtime_exit_stops_direct_child_but_not_descendant", "--nocapture"])
                .env_clear().env("HOME", root).env("TMPDIR", root).env("PATH", root)
                .env("TUCUPI_BATCH_EXIT_FIXTURE", root)
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while !root.join("ready").exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            let parent: u32 = std::fs::read_to_string(root.join("parent-pid"))
                .unwrap()
                .parse()
                .unwrap();
            let child: u32 = std::fs::read_to_string(root.join("child-pid"))
                .unwrap()
                .parse()
                .unwrap();
            assert!(parent > 1 && child > 1 && parent != child);
            let status = std::fs::read_to_string(format!("/proc/{child}/status")).unwrap();
            assert!(status
                .lines()
                .any(|line| line == format!("PPid:\t{parent}")));
            let pin = |pid: u32| {
                // SAFETY: pidfd_open is called with the verified synthetic PID and returns a fresh fd.
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
                assert!(fd >= 0);
                // SAFETY: successful pidfd_open returns an owned descriptor.
                unsafe { OwnedFd::from_raw_fd(fd as i32) }
            };
            let direct = pin(parent);
            let descendant = pin(child);
            std::fs::write(root.join("proceed"), "").unwrap();
            let status = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(status) = harness.try_wait().unwrap() {
                        break status;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(status.success());
            let wait_exit = |fd: &OwnedFd| {
                let mut pollfd = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: pollfd is a single initialized descriptor, with bounded timeout.
                unsafe { libc::poll(&mut pollfd, 1, 5000) }
            };
            assert_eq!(wait_exit(&direct), 1, "direct child did not exit");
            tokio::time::timeout(Duration::from_secs(5), async {
                while !root.join("descendant-late").exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(
                wait_exit(&descendant),
                1,
                "synthetic descendant did not exit"
            );
            assert!(!root.join("parent-late").exists());
            println!("synthetic batch runtime ended: direct child exited; detached descendant wrote after exit and then exited");
            return;
        };
        let item = BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: true,
                origin: None,
            },
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let (tx, _rx) = mpsc::unbounded_channel();
        let screen = begin_impact_preview(vec![item], 0, false, &tx, &root);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !root.join("proceed").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let mut running = true;
        let _screen = handle_key_input(
            screen,
            KeyCode::Char('q'),
            &tx,
            &Config::default(),
            &root,
            false,
            &mut running,
        );
        assert!(!running);
        // Returning ends this isolated test process's Tokio runtime.
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn synthetic_batch_quit_cancels_preview_but_not_descendant() {
        use std::os::unix::fs::PermissionsExt;
        if std::env::var_os("TUCUPI_BATCH_QUIT_FIXTURE").is_none() {
            let dir = tempfile::tempdir().unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "batch::impact_tests::synthetic_batch_quit_cancels_preview_but_not_descendant",
                    "--nocapture",
                ])
                .env_clear()
                .env("HOME", dir.path())
                .env("TMPDIR", dir.path())
                .env("PATH", dir.path())
                .env("TUCUPI_BATCH_QUIT_FIXTURE", "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout)
                .contains("synthetic batch quit requested cancellation; descendant survived"));
            println!("synthetic batch quit requested cancellation; descendant survived");
            return;
        }
        let root = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
        let script = root.join("brew");
        let code = "#!/usr/bin/python3\nimport pathlib,subprocess,time\np=pathlib.Path('.')\nsubprocess.Popen(['/usr/bin/python3','-c',\"import pathlib,time; time.sleep(0.5); pathlib.Path('child-late').touch()\"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, env={})\n(p/'ready').touch()\ntime.sleep(0.5)\n(p/'parent-late').touch()\n";
        std::fs::write(&script, code).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let item = BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: true,
                origin: None,
            },
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        let screen = begin_impact_preview(vec![item], 0, false, &tx, &root);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !root.join("ready").exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let mut running = true;
        let screen = handle_key_input(
            screen,
            KeyCode::Char('q'),
            &tx,
            &Config::default(),
            &root,
            false,
            &mut running,
        );
        assert!(!running);
        assert!(batch_shutdown_status(&screen).is_err());
        drop(screen);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !root.join("child-late").exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!root.join("parent-late").exists());
        assert!(rx.try_recv().is_err());
        assert!(crate::recovery_state::codex_recovery_preflight(&Config::default()).is_ok());
        println!("synthetic batch quit requested cancellation; descendant survived");
    }

    #[test]
    fn invalid_upgrade_log_index_is_ignored() {
        let mut screen = BatchScreen::Report {
            items: Vec::new(),
            scan_error: false,
        };
        assert!(!append_batch_log(&mut screen, 0, 1, "synthetic".into()));
    }

    #[test]
    fn batch_shutdown_reports_unknown_preview_cleanup_only_for_pending_preview() {
        assert!(batch_shutdown_status(&BatchScreen::Scanning(None)).is_ok());
        let screen = BatchScreen::CheckingImpact {
            items: Vec::new(),
            cursor: 0,
            force_mode: false,
            attempt: 1,
            task: None,
        };
        assert_eq!(
            batch_shutdown_status(&screen).unwrap_err().to_string(),
            t("batch_impact_cleanup_unknown")
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn synthetic_batch_io_error_cancels_preview_and_reports_both_failures() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().to_path_buf();
        let script = "import os,pathlib,time\np=pathlib.Path('.')\n(p/'pid').write_text(str(os.getpid()))\n(p/'ready').touch()\ntime.sleep(3)\n(p/'late').touch()";
        let args = vec!["-c".into(), script.into()];
        let dir = root.clone();
        let task = tokio::spawn(async move {
            crate::impact::run_preview(Path::new("/usr/bin/python3"), &args, &dir).await
        });
        let screen = BatchScreen::CheckingImpact {
            items: Vec::new(),
            cursor: 0,
            force_mode: false,
            attempt: 1,
            task: Some(task.abort_handle()),
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while !root.join("ready").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let pid: u32 = std::fs::read_to_string(root.join("pid"))
            .unwrap()
            .parse()
            .unwrap();
        assert!(pid > 1);
        // SAFETY: pidfd_open returns a new descriptor for the synthetic child.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        assert!(fd >= 0);
        // SAFETY: successful pidfd_open returns a fresh owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let restored = std::cell::Cell::new(false);
        let error = finish_batch_session(
            &screen,
            Err(std::io::Error::other("synthetic event error")),
            || {
                restored.set(true);
                [
                    Ok(()),
                    Err(std::io::Error::other("synthetic terminal error")),
                    Ok(()),
                ]
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("synthetic event error"));
        assert!(error.contains("synthetic terminal error"));
        assert!(error.contains(t("batch_impact_cleanup_unknown")));
        assert!(restored.get());
        assert!(task.await.unwrap_err().is_cancelled());
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives one initialized descriptor and bounded timeout.
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 5000) }, 1);
        assert!(!root.join("late").exists());
    }

    #[test]
    fn stale_upgrade_log_is_not_attached_to_new_attempt() {
        let item = BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: Some(2),
            security_pending: None,
            logs: Vec::new(),
        };
        let mut screen = BatchScreen::Executing {
            items: vec![item],
            current_cursor: 0,
            progress_message: String::new(),
        };
        // This log belongs to an older attempt that also used index zero.
        append_batch_log(&mut screen, 0, 1, "old".into());
        assert!(
            matches!(&screen, BatchScreen::Executing { items, .. } if items[0].logs.is_empty())
        );
        assert!(append_batch_log(&mut screen, 0, 2, "current".into()));
        assert!(
            matches!(&screen, BatchScreen::Executing { items, .. } if items[0].logs == ["current"])
        );
    }

    #[tokio::test]
    async fn synthetic_upgrade_logs_are_forwarded_before_completion() {
        let (lines, line_rx) = mpsc::unbounded_channel();
        let (events, mut received) = mpsc::unbounded_channel();
        let task = tokio::spawn(forward_batch_logs(0, 42, line_rx, events.clone()));
        lines.send("one".to_string()).unwrap();
        lines.send("two".to_string()).unwrap();
        drop(lines);
        task.await.unwrap();
        events
            .send(BatchEvent::UpgradeFinished(0, 42, Ok(())))
            .unwrap();
        assert!(
            matches!(received.recv().await, Some(BatchEvent::UpgradeLog(0, 42, line)) if line == "one")
        );
        assert!(
            matches!(received.recv().await, Some(BatchEvent::UpgradeLog(0, 42, line)) if line == "two")
        );
        assert!(matches!(
            received.recv().await,
            Some(BatchEvent::UpgradeFinished(0, 42, Ok(())))
        ));
    }

    #[tokio::test]
    async fn batch_entry_rejects_inline_codex_credential_without_disclosure() {
        for field in ["codex_api_key", "openai_api_key"] {
            let directory = tempfile::tempdir().unwrap();
            let synthetic = "synthetic-private-value";
            std::fs::write(
                directory.path().join("tucupi.toml"),
                format!("[security]\nreview_provider = 'codex'\n{field} = '{synthetic}'\n"),
            )
            .unwrap();
            let error = run(directory.path().to_path_buf(), false)
                .await
                .unwrap_err();
            assert!(!error.to_string().contains(synthetic));
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn real_batch_entry_rejects_codex_when_recovery_is_unreconciled() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("tucupi.toml"),
            "[security]\nreview_provider = 'codex'\n",
        )
        .unwrap();
        let result = run(dir.path().to_path_buf(), false).await;
        assert_eq!(
            result.unwrap_err().to_string(),
            t("codex_recovery_unavailable")
        );
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn synthetic_batch_manager_failure_blocks_new_app_and_batch_attempts() {
        let state = tempfile::tempdir().unwrap();
        let marker = crate::codex_supervision::FixtureRecoveryMarker::open(state.path()).unwrap();
        let started = std::cell::Cell::new(false);
        let first =
            fixture_guarded_batch_attempt(&marker, "0123456789abcdef0123456789abcdef", || {
                started.set(true);
                Err::<(), _>(std::io::Error::other("synthetic manager unavailable"))
            });
        assert!(first.is_err());
        assert!(started.get());
        let app = crate::app::App::new_with_fixture_recovery(
            state.path().to_path_buf(),
            false,
            state.path(),
        );
        assert!(app.fixture_recovery_is_blocked());
        let retry_started = std::cell::Cell::new(false);
        let second =
            fixture_guarded_batch_attempt(&marker, "fedcba9876543210fedcba9876543210", || {
                retry_started.set(true);
                Ok(())
            });
        assert!(second.is_err());
        assert!(!retry_started.get());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn synthetic_app_attempt_blocks_batch_admission() {
        let state = tempfile::tempdir().unwrap();
        let marker = std::sync::Arc::new(
            crate::codex_supervision::FixtureRecoveryMarker::open(state.path()).unwrap(),
        );
        let gate = crate::review::FixtureStartGate::with_fixture_recovery(marker.clone());
        gate.begin_fixture_start().unwrap();
        let called = std::cell::Cell::new(false);
        let result =
            fixture_guarded_batch_attempt(&marker, "0123456789abcdef0123456789abcdef", || {
                called.set(true);
                Ok(())
            });
        assert!(result.is_err());
        assert!(!called.get());
    }

    #[test]
    fn batch_buffers_out_of_order_security_and_skips_unselected_items() {
        let item = |name: &str, selection| BatchItem {
            dependency: Dependency {
                name: name.into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: true,
                origin: None,
            },
            selection,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let mut screen = BatchScreen::Executing {
            items: vec![
                item("skip", SelectionState::None),
                item("first", SelectionState::Force),
                item("second", SelectionState::Safe),
            ],
            current_cursor: 0,
            progress_message: String::new(),
        };
        let failure = || BatchSecurityResult {
            vuln_result: Err(AuditFailure {
                message: "synthetic".into(),
                findings: Vec::new(),
                partial: true,
            }),
            freshness_info: FreshnessInfo::Unavailable,
            provenance_info: None,
        };
        let mut pending = std::collections::HashMap::new();
        let mut processed = std::collections::HashSet::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let config = Config::default();
        pending.insert(2, failure());
        assert!(!advance_buffered_security(
            &mut screen,
            &mut pending,
            &mut processed,
            &config,
            Path::new("."),
            &tx
        ));
        assert!(matches!(
            &screen,
            BatchScreen::Executing {
                current_cursor: 1,
                ..
            }
        ));
        assert!(processed.is_empty());
        pending.insert(1, failure());
        assert!(!advance_buffered_security(
            &mut screen,
            &mut pending,
            &mut processed,
            &config,
            Path::new("."),
            &tx
        ));
        assert!(
            matches!(&screen, BatchScreen::Executing { current_cursor: 2, items, .. } if matches!(items[1].outcome, ItemOutcome::Blocked(_)))
        );
        assert!(advance_buffered_security(
            &mut screen,
            &mut pending,
            &mut processed,
            &config,
            Path::new("."),
            &tx
        ));
        assert!(
            matches!(&screen, BatchScreen::Executing { current_cursor: 3, items, .. } if matches!(items[2].outcome, ItemOutcome::Blocked(_)))
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn security_events_out_of_order_advance_past_exhausted_item() {
        let item = |name: &str, attempt| BatchItem {
            dependency: Dependency {
                name: name.into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: attempt,
            logs: Vec::new(),
        };
        let mut items = vec![
            item("first", Some(10)),
            item("exhausted", None),
            item("last", Some(12)),
        ];
        assert!(reserve_security_attempt(
            &mut items[1],
            &std::sync::atomic::AtomicU64::new(u64::MAX)
        )
        .is_none());
        let mut screen = BatchScreen::Executing {
            items,
            current_cursor: 0,
            progress_message: String::new(),
        };
        let failure = || BatchSecurityResult {
            vuln_result: Err(AuditFailure {
                message: "synthetic offline".into(),
                findings: Vec::new(),
                partial: false,
            }),
            freshness_info: FreshnessInfo::Unavailable,
            provenance_info: None,
        };
        let mut pending = std::collections::HashMap::new();
        let mut processed = std::collections::HashSet::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let config = Config::default();
        buffer_security_event(&screen, &mut pending, &processed, 2, 11, failure());
        assert!(pending.is_empty());
        buffer_security_event(&screen, &mut pending, &processed, 2, 12, failure());
        buffer_security_event(&screen, &mut pending, &processed, 1, 12, failure());
        assert_eq!(pending.len(), 1);
        assert!(!advance_buffered_security(
            &mut screen,
            &mut pending,
            &mut processed,
            &config,
            Path::new("."),
            &tx
        ));
        assert!(matches!(
            &screen,
            BatchScreen::Executing {
                current_cursor: 0,
                ..
            }
        ));
        buffer_security_event(&screen, &mut pending, &processed, 0, 10, failure());
        assert!(!advance_buffered_security(
            &mut screen,
            &mut pending,
            &mut processed,
            &config,
            Path::new("."),
            &tx
        ));
        assert!(
            matches!(&screen, BatchScreen::Executing { current_cursor: 1, items, .. } if matches!(items[0].outcome, ItemOutcome::Blocked(_)) && items[0].security_pending.is_none() && matches!(items[1].outcome, ItemOutcome::Blocked(_)))
        );
        buffer_security_event(&screen, &mut pending, &processed, 0, 10, failure());
        assert!(advance_buffered_security(
            &mut screen,
            &mut pending,
            &mut processed,
            &config,
            Path::new("."),
            &tx
        ));
        assert!(
            matches!(&screen, BatchScreen::Executing { current_cursor: 3, items, .. } if matches!(items[2].outcome, ItemOutcome::Blocked(_)) && items[2].security_pending.is_none())
        );
        assert_eq!(processed.len(), 2);
        assert!(pending.is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn stale_security_result_must_not_enter_new_batch_at_reused_index() {
        let item = BatchItem {
            dependency: Dependency {
                name: "synthetic-new".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: Some(2),
            logs: Vec::new(),
        };
        let screen = BatchScreen::Executing {
            items: vec![item],
            current_cursor: 0,
            progress_message: String::new(),
        };
        let stale = BatchSecurityResult {
            vuln_result: Ok(Vec::new()),
            freshness_info: FreshnessInfo::Unavailable,
            provenance_info: None,
        };
        let mut pending = std::collections::HashMap::new();
        let processed = std::collections::HashSet::new();
        buffer_security_event(&screen, &mut pending, &processed, 0, 1, stale);
        assert!(
            pending.is_empty(),
            "old audit result was accepted for the new item"
        );
        let result = || BatchSecurityResult {
            vuln_result: Err(AuditFailure {
                message: "synthetic".into(),
                findings: Vec::new(),
                partial: false,
            }),
            freshness_info: FreshnessInfo::Unavailable,
            provenance_info: None,
        };
        buffer_security_event(&screen, &mut pending, &processed, usize::MAX, 2, result());
        assert!(pending.is_empty());
        buffer_security_event(&screen, &mut pending, &processed, 0, 2, result());
        buffer_security_event(
            &screen,
            &mut pending,
            &processed,
            0,
            2,
            BatchSecurityResult {
                vuln_result: Ok(Vec::new()),
                freshness_info: FreshnessInfo::Unavailable,
                provenance_info: None,
            },
        );
        assert!(pending.get(&0).unwrap().vuln_result.is_err());
    }

    #[test]
    fn exhausted_security_attempt_is_blocked_and_skipped_without_work() {
        let item = BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let mut screen = BatchScreen::Executing {
            items: vec![item],
            current_cursor: 0,
            progress_message: String::new(),
        };
        if let BatchScreen::Executing { items, .. } = &mut screen {
            assert!(reserve_security_attempt(
                &mut items[0],
                &std::sync::atomic::AtomicU64::new(u64::MAX)
            )
            .is_none());
        }
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(advance_buffered_security(
            &mut screen,
            &mut Default::default(),
            &mut Default::default(),
            &Config::default(),
            Path::new("."),
            &tx
        ));
        assert!(
            matches!(&screen, BatchScreen::Executing { items, .. } if matches!(items[0].outcome, ItemOutcome::Blocked(_)))
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn completion_from_previous_batch_must_not_finish_reused_index() {
        let item = BatchItem {
            dependency: Dependency {
                name: "synthetic-new".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: Some(2),
            security_pending: None,
            logs: Vec::new(),
        };
        let mut screen = BatchScreen::Executing {
            items: vec![item],
            current_cursor: 0,
            progress_message: String::new(),
        };
        // This completion belongs to a previous execution that also used index 0.
        assert!(!process_upgrade_finished(&mut screen, 0, 1, Ok(())));
        assert!(
            matches!(&screen, BatchScreen::Executing { current_cursor: 0, items, .. } if items[0].upgrade_pending == Some(2) && matches!(items[0].outcome, ItemOutcome::Pending))
        );
        assert!(process_upgrade_finished(&mut screen, 0, 2, Ok(())));
    }

    #[test]
    fn exhausted_upgrade_attempt_counter_blocks_without_starting_work() {
        let mut item = BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let counter = std::sync::atomic::AtomicU64::new(u64::MAX);
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(!spawn_item_upgrade_with_counter(
            &mut item,
            0,
            Path::new("."),
            &tx,
            &counter
        ));
        assert!(matches!(item.outcome, ItemOutcome::Blocked(_)));
        assert!(item.upgrade_pending.is_none());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn unsolicited_or_duplicate_upgrade_completion_does_not_bypass_batch_review() {
        let item = || BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Force,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: Some(1),
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let mut screen = BatchScreen::Executing {
            items: vec![item(), item()],
            current_cursor: 0,
            progress_message: "unchanged".into(),
        };
        assert!(!process_upgrade_finished(&mut screen, 0, 1, Ok(())));
        assert!(
            matches!(&screen, BatchScreen::Executing { current_cursor: 0, items, .. } if items[0].review_pending.is_some() && matches!(items[0].outcome, ItemOutcome::Pending))
        );
        if let BatchScreen::Executing {
            items,
            current_cursor,
            ..
        } = &mut screen
        {
            items[0].outcome = ItemOutcome::Upgraded;
            items[0].review_pending = None;
            *current_cursor = 1;
        }
        assert!(!process_upgrade_finished(
            &mut screen,
            0,
            1,
            Err("stale".into())
        ));
        assert!(
            matches!(&screen, BatchScreen::Executing { current_cursor: 1, items, .. } if matches!(items[0].outcome, ItemOutcome::Upgraded) && items[1].review_pending.is_some())
        );
        assert!(!process_upgrade_finished(
            &mut screen,
            usize::MAX,
            1,
            Ok(())
        ));
    }

    #[test]
    fn pending_upgrade_completion_is_consumed_once() {
        let item = BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: Some(1),
            security_pending: None,
            logs: Vec::new(),
        };
        let mut screen = BatchScreen::Executing {
            items: vec![item],
            current_cursor: 0,
            progress_message: String::new(),
        };
        assert!(process_upgrade_finished(&mut screen, 0, 1, Ok(())));
        assert!(!process_upgrade_finished(
            &mut screen,
            0,
            1,
            Err("stale".into())
        ));
        assert!(
            matches!(&screen, BatchScreen::Executing { current_cursor: 1, items, .. } if matches!(items[0].outcome, ItemOutcome::Upgraded) && items[0].upgrade_pending.is_none())
        );
    }

    #[test]
    fn review_from_previous_batch_must_not_consume_reused_index() {
        let item = BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Force,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: Some(2),
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let mut screen = BatchScreen::Executing {
            items: vec![item],
            current_cursor: 0,
            progress_message: String::new(),
        };
        let report = ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "synthetic".into(),
            view_mode: crate::review::ReviewViewMode::Diff,
            residual_line_count: 0,
            hits: Vec::new(),
            origin: crate::review::ReviewOrigin::Unknown,
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(!process_review_checked(
            &mut screen,
            0,
            1,
            report.clone(),
            Path::new("."),
            &tx
        ));
        assert!(!process_review_failure(&mut screen, 0, 1));
        assert!(
            matches!(&screen, BatchScreen::Executing { current_cursor: 0, items, .. } if items[0].review_pending == Some(2) && items[0].upgrade_pending.is_none())
        );
        assert!(rx.try_recv().is_err());
        assert!(!process_review_checked(
            &mut screen,
            0,
            2,
            report,
            Path::new("."),
            &tx
        ));
        assert!(matches!(
            rx.try_recv(),
            Ok(BatchEvent::UpgradeFinished(0, _, Err(_)))
        ));
        assert!(!process_review_failure(&mut screen, 0, 2));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn exhausted_review_attempt_counter_blocks_before_worker_start() {
        let mut item = BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: true,
                origin: None,
            },
            selection: SelectionState::Force,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let counter = std::sync::atomic::AtomicU64::new(u64::MAX);
        assert!(reserve_review_attempt(&mut item, &counter).is_none());
        assert!(matches!(item.outcome, ItemOutcome::Blocked(_)));
        assert!(item.review_pending.is_none());
        assert!(item.upgrade_pending.is_none());
    }

    #[test]
    fn duplicate_batch_review_does_not_start_a_second_upgrade() {
        let item = BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Force,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: Some(1),
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let mut screen = BatchScreen::Executing {
            items: vec![item],
            current_cursor: 0,
            progress_message: String::new(),
        };
        let report = ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "synthetic".into(),
            view_mode: crate::review::ReviewViewMode::Diff,
            residual_line_count: 0,
            hits: Vec::new(),
            origin: crate::review::ReviewOrigin::Unknown,
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(!process_review_checked(
            &mut screen,
            0,
            1,
            report.clone(),
            Path::new("."),
            &tx
        ));
        assert!(matches!(
            rx.try_recv(),
            Ok(BatchEvent::UpgradeFinished(0, _, Err(_)))
        ));
        assert!(!process_review_checked(
            &mut screen,
            0,
            1,
            report,
            Path::new("."),
            &tx
        ));
        assert!(!process_review_failure(&mut screen, 0, 1));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn late_or_out_of_range_batch_review_never_starts_upgrade() {
        let item = || BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Force,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let mut screen = BatchScreen::Executing {
            items: vec![item(), item()],
            current_cursor: 1,
            progress_message: "unchanged".into(),
        };
        let report = ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "synthetic".into(),
            view_mode: crate::review::ReviewViewMode::Diff,
            residual_line_count: 0,
            hits: Vec::new(),
            origin: crate::review::ReviewOrigin::Unknown,
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(!process_review_checked(
            &mut screen,
            0,
            1,
            report.clone(),
            Path::new("."),
            &tx
        ));
        assert!(!process_review_checked(
            &mut screen,
            usize::MAX,
            1,
            report,
            Path::new("."),
            &tx
        ));
        assert!(rx.try_recv().is_err());
        assert!(
            matches!(&screen, BatchScreen::Executing { current_cursor: 1, progress_message, .. } if progress_message == "unchanged")
        );
    }

    #[tokio::test]
    async fn panicked_batch_review_is_inconclusive_even_when_forced() {
        for selection in [SelectionState::Safe, SelectionState::Force] {
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: true,
                origin: None,
            };
            let item = BatchItem {
                dependency: dep,
                selection,
                vulns: None,
                outcome: ItemOutcome::Pending,
                review_pending: Some(1),
                upgrade_pending: None,
                security_pending: None,
                logs: Vec::new(),
            };
            let mut screen = BatchScreen::Executing {
                items: vec![item],
                current_cursor: 0,
                progress_message: String::new(),
            };
            let (tx, mut rx) = mpsc::unbounded_channel();
            spawn_batch_review(0, 1, tx, async { panic!("synthetic review panic") });
            let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(event, BatchEvent::ReviewFailed(0, 1)));
            assert!(process_review_failure(&mut screen, 0, 1));
            assert!(
                matches!(&screen, BatchScreen::Executing { items, .. } if matches!(&items[0].outcome, ItemOutcome::Blocked(reason) if reason == t("review_task_failed")))
            );
            assert!(rx.try_recv().is_err());
            assert!(!process_review_failure(&mut screen, 0, 1));
        }
    }

    #[tokio::test]
    async fn unsupported_scope_reports_failure_without_spawning_upgrade() {
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: false,
            origin: None,
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        spawn_upgrade(0, 1, &dep, Path::new("."), &tx);
        assert!(matches!(
            rx.try_recv(),
            Ok(BatchEvent::UpgradeFinished(0, 1, Err(_)))
        ));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn partial_nvd_findings_block_normal_and_forced_batch() {
        for selection in [SelectionState::Safe, SelectionState::Force] {
            let dep = Dependency {
                name: "example".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: true,
                origin: None,
            };
            let item = BatchItem {
                dependency: dep,
                selection,
                vulns: None,
                outcome: ItemOutcome::Pending,
                review_pending: None,
                upgrade_pending: None,
                security_pending: None,
                logs: Vec::new(),
            };
            let mut screen = BatchScreen::Executing {
                items: vec![item],
                current_cursor: 0,
                progress_message: String::new(),
            };
            let finding = VulnerabilityInfo {
                id: "CVE-TEST".into(),
                summary: "original".into(),
                details: String::new(),
                aliases: Vec::new(),
                severity: None,
                score: None,
                sources: vec!["NVD".into()],
            };
            let result = BatchSecurityResult {
                vuln_result: Err(AuditFailure {
                    message: "OSV offline".into(),
                    findings: vec![finding],
                    partial: true,
                }),
                freshness_info: FreshnessInfo::Unavailable,
                provenance_info: None,
            };
            let (tx, mut rx) = mpsc::unbounded_channel();
            assert!(process_security_checked(
                &mut screen,
                0,
                result,
                &Config::default(),
                Path::new("."),
                &tx
            ));
            assert!(
                matches!(&screen, BatchScreen::Executing { items, .. } if matches!(&items[0].outcome, ItemOutcome::Blocked(reason) if reason.contains("CVE-TEST")) && items[0].vulns.as_ref().is_some_and(|v| v[0].id == "CVE-TEST"))
            );
            assert!(rx.try_recv().is_err());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn safe_source_review_never_bypasses_vulnerability_policy() {
        use std::os::unix::fs::PermissionsExt;
        if std::env::var_os("TUCUPI_BATCH_POLICY_CHILD").is_none() {
            let dir = tempfile::tempdir().unwrap();
            let bin = dir.path().join("bin");
            std::fs::create_dir(&bin).unwrap();
            let fake = bin.join("brew");
            std::fs::write(&fake, "#!/bin/sh\nprintf invoked > \"$HOME/invoked\"\n").unwrap();
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "batch::impact_tests::safe_source_review_never_bypasses_vulnerability_policy",
                ])
                .env("HOME", dir.path())
                .env("PATH", &bin)
                .env("TUCUPI_BATCH_POLICY_CHILD", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let home = PathBuf::from(std::env::var_os("HOME").unwrap());
        let dep = Dependency {
            name: "example".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: true,
            origin: None,
        };
        let mut config = Config::default();
        // This test exercises the vulnerability policy with a cached safe
        // result; the separately tested disabled-provider gate must not replace it.
        config.security.review_provider = Some("apple".into());
        let cached = ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "version bump only, no code changes".into(),
            view_mode: crate::review::ReviewViewMode::Diff,
            residual_line_count: 0,
            hits: Vec::new(),
            origin: crate::review::ReviewOrigin::Unknown,
        };
        crate::cache::write_cache(
            "pkgreview",
            &crate::review::review_cache_key(&dep, &config),
            &cached,
        )
        .unwrap();
        for (blocked, selection) in [
            (true, SelectionState::Safe),
            (true, SelectionState::Force),
            (false, SelectionState::Safe),
            (false, SelectionState::Force),
        ] {
            config.security.block_vulnerable = Some(blocked);
            let item = BatchItem {
                dependency: dep.clone(),
                selection,
                vulns: None,
                outcome: ItemOutcome::Pending,
                review_pending: None,
                upgrade_pending: None,
                security_pending: None,
                logs: Vec::new(),
            };
            let mut screen = BatchScreen::Executing {
                items: vec![item],
                current_cursor: 0,
                progress_message: String::new(),
            };
            let result = BatchSecurityResult {
                vuln_result: Ok(vec![VulnerabilityInfo {
                    id: "TEST-1".into(),
                    summary: "test".into(),
                    details: String::new(),
                    aliases: Vec::new(),
                    severity: None,
                    score: None,
                    sources: Vec::new(),
                }]),
                freshness_info: FreshnessInfo::Unavailable,
                provenance_info: None,
            };
            let (tx, mut rx) = mpsc::unbounded_channel();
            let finished = process_security_checked(&mut screen, 0, result, &config, &home, &tx);
            if blocked || selection == SelectionState::Safe {
                assert!(finished);
                assert!(
                    matches!(&screen, BatchScreen::Executing { items, .. } if if blocked { matches!(items[0].outcome, ItemOutcome::Blocked(_)) } else { matches!(items[0].outcome, ItemOutcome::SkippedVulnerable(_)) })
                );
                assert!(rx.try_recv().is_err());
                assert!(!home.join("invoked").exists());
                continue;
            }
            assert!(!finished);
            let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap();
            let BatchEvent::ReviewChecked(index, attempt, report) = event else {
                panic!("expected review");
            };
            assert_eq!(report.verdict, ReviewVerdict::Safe);
            assert!(!process_review_checked(
                &mut screen,
                index,
                attempt,
                report,
                &home,
                &tx
            ));
            loop {
                let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                if let BatchEvent::UpgradeFinished(index, attempt, result) = event {
                    assert!(result.is_ok());
                    assert!(process_upgrade_finished(
                        &mut screen,
                        index,
                        attempt,
                        result
                    ));
                    break;
                }
            }
            assert!(home.join("invoked").exists());
            assert!(
                matches!(&screen, BatchScreen::Executing { items, .. } if matches!(items[0].outcome, ItemOutcome::ForceUpgraded))
            );
        }
    }

    #[test]
    fn vulnerable_homebrew_package_is_blocked_before_source_review() {
        for selection in [SelectionState::Safe, SelectionState::Force] {
            let dep = Dependency {
                name: "example".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: true,
                origin: None,
            };
            let item = BatchItem {
                dependency: dep,
                selection,
                vulns: None,
                outcome: ItemOutcome::Pending,
                review_pending: None,
                upgrade_pending: None,
                security_pending: None,
                logs: Vec::new(),
            };
            let mut screen = BatchScreen::Executing {
                items: vec![item],
                current_cursor: 0,
                progress_message: String::new(),
            };
            let mut config = Config::default();
            config.security.block_vulnerable = Some(true);
            let result = BatchSecurityResult {
                vuln_result: Ok(vec![VulnerabilityInfo {
                    id: "TEST-1".into(),
                    summary: "test".into(),
                    details: String::new(),
                    aliases: Vec::new(),
                    severity: None,
                    score: None,
                    sources: Vec::new(),
                }]),
                freshness_info: FreshnessInfo::Unavailable,
                provenance_info: None,
            };
            let (tx, mut rx) = mpsc::unbounded_channel();
            assert!(process_security_checked(
                &mut screen,
                0,
                result,
                &config,
                Path::new("."),
                &tx
            ));
            assert!(
                matches!(screen, BatchScreen::Executing { items, .. } if matches!(items[0].outcome, ItemOutcome::Blocked(_)))
            );
            assert!(rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn disabled_provider_cached_safe_review_blocks_batch_without_upgrade() {
        if std::env::var_os("TUCUPI_BATCH_CACHE_TEST_CHILD").is_none() {
            let dir = tempfile::tempdir().unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "batch::impact_tests::disabled_provider_cached_safe_review_blocks_batch_without_upgrade"])
                .env("HOME", dir.path())
                .env("TUCUPI_BATCH_CACHE_TEST_CHILD", "1")
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
        let cached = ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "old AI approval".into(),
            view_mode: crate::review::ReviewViewMode::Diff,
            residual_line_count: 2,
            hits: Vec::new(),
            origin: crate::review::ReviewOrigin::Unknown,
        };
        crate::cache::write_cache(
            "pkgreview",
            &crate::review::review_cache_key(&dep, &config),
            &cached,
        )
        .unwrap();
        let item = BatchItem {
            dependency: dep,
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let mut screen = BatchScreen::Executing {
            items: vec![item],
            current_cursor: 0,
            progress_message: String::new(),
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        let result = BatchSecurityResult {
            vuln_result: Ok(Vec::new()),
            freshness_info: FreshnessInfo::Unavailable,
            provenance_info: None,
        };
        assert!(!process_security_checked(
            &mut screen,
            0,
            result,
            &config,
            Path::new("."),
            &tx
        ));
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let BatchEvent::ReviewChecked(index, attempt, report) = event else {
            panic!("expected review result");
        };
        assert_eq!(report.verdict, ReviewVerdict::Review);
        assert!(process_review_checked(
            &mut screen,
            index,
            attempt,
            report,
            Path::new("."),
            &tx
        ));
        match &screen {
            BatchScreen::Executing {
                items,
                current_cursor,
                ..
            } => {
                assert_eq!(*current_cursor, 1);
                assert!(matches!(items[0].outcome, ItemOutcome::Blocked(_)));
                assert!(items[0].vulns.as_ref().unwrap().is_empty());
            }
            _ => panic!("unexpected screen"),
        }
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn batch_screens_follow_requested_language() {
        if let Ok(language) = std::env::var("TUCUPI_BATCH_TEST_LANGUAGE") {
            use ratatui::{backend::TestBackend, Terminal};
            let mut terminal = Terminal::new(TestBackend::new(150, 20)).unwrap();
            let mut screen = BatchScreen::Report {
                items: vec![BatchItem {
                    dependency: Dependency {
                        name: "example".into(),
                        current_version: "1".into(),
                        latest_version: "2".into(),
                        ecosystem: Ecosystem::Cargo,
                        is_global: false,
                        origin: None,
                    },
                    selection: SelectionState::Safe,
                    vulns: None,
                    outcome: ItemOutcome::Upgraded,
                    review_pending: None,
                    upgrade_pending: None,
                    security_pending: None,
                    logs: Vec::new(),
                }],
                scan_error: false,
            };
            terminal
                .draw(|frame| render_batch(frame, &mut screen))
                .unwrap();
            let buffer = terminal.backend().buffer();
            let text = (0..buffer.area.height)
                .map(|y| {
                    (0..buffer.area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            if language == "pt" {
                assert!(text.contains("Relatório de Atualizações"), "{text}");
                assert!(
                    text.contains("auditoria de vulnerabilidades não verificada"),
                    "{text}"
                );
                assert!(text.contains("Resumo:"), "{text}");
                assert!(text.contains("ATUALIZADOS (1)"), "{text}");
                assert!(!text.contains("COM SEGURANÇA"), "{text}");
                assert!(!text.contains("Summary:"), "{text}");
            } else {
                assert!(text.contains("Upgrade Report"), "{text}");
                assert!(text.contains("vulnerability audit not checked"), "{text}");
                assert!(text.contains("Summary:"), "{text}");
                assert!(text.contains("UPGRADED (1)"), "{text}");
                assert!(!text.contains("SAFELY UPGRADED"), "{text}");
                assert!(!text.contains("Resumo:"), "{text}");
            }
            assert!(!text.contains("{0}"), "{text}");
            if let BatchScreen::Report { items, .. } = &mut screen {
                items[0].outcome = ItemOutcome::Blocked(tf("audit_partial_blocked", &["CVE-TEST"]));
            }
            terminal
                .draw(|frame| render_batch(frame, &mut screen))
                .unwrap();
            let buffer = terminal.backend().buffer();
            let text = (0..buffer.area.height)
                .map(|y| {
                    (0..buffer.area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("CVE-TEST"), "{text}");
            assert!(
                text.contains(if language == "pt" {
                    "Auditoria incompleta"
                } else {
                    "Incomplete audit"
                }),
                "{text}"
            );
            let item = BatchItem {
                dependency: Dependency {
                    name: "example".into(),
                    current_version: "1".into(),
                    latest_version: "2".into(),
                    ecosystem: Ecosystem::Cargo,
                    is_global: false,
                    origin: None,
                },
                selection: SelectionState::Safe,
                vulns: None,
                outcome: ItemOutcome::Blocked("policy".into()),
                review_pending: None,
                upgrade_pending: None,
                security_pending: None,
                logs: Vec::new(),
            };
            let mut screen = BatchScreen::Executing {
                items: vec![item],
                current_cursor: 0,
                progress_message: String::new(),
            };
            terminal
                .draw(|frame| render_batch(frame, &mut screen))
                .unwrap();
            let buffer = terminal.backend().buffer();
            let text = (0..buffer.area.height)
                .map(|y| {
                    (0..buffer.area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(!text.contains("{0}"), "{text}");
            assert!(
                text.contains(if language == "pt" {
                    "[BLOQUEADO] example"
                } else {
                    "[BLOCKED] example"
                }),
                "{text}"
            );
            let item = BatchItem {
                dependency: Dependency {
                    name: "example".into(),
                    current_version: "1".into(),
                    latest_version: "2".into(),
                    ecosystem: Ecosystem::Cargo,
                    is_global: false,
                    origin: None,
                },
                selection: SelectionState::Safe,
                vulns: None,
                outcome: ItemOutcome::Pending,
                review_pending: None,
                upgrade_pending: None,
                security_pending: None,
                logs: Vec::new(),
            };
            let mut screen = BatchScreen::ConfirmImpact {
                items: vec![item],
                cursor: 0,
                force_mode: false,
                previews: vec![
                    (
                        "first".into(),
                        crate::impact::ImpactPreview::ManagerOutput {
                            text: "line\n".repeat(1000),
                            truncated: false,
                        },
                    ),
                    (
                        "second".into(),
                        crate::impact::ImpactPreview::ManagerOutput {
                            text: "line\n".repeat(1000),
                            truncated: true,
                        },
                    ),
                ],
                scroll: 0,
            };
            terminal
                .draw(|frame| render_batch(frame, &mut screen))
                .unwrap();
            let buffer = terminal.backend().buffer();
            let text = (0..buffer.area.height)
                .map(|y| {
                    (0..buffer.area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                text.contains(if language == "pt" {
                    "prévia"
                } else {
                    "previews were truncated"
                }),
                "{text}"
            );
            assert!(
                text.contains(if language == "pt" {
                    "truncadas"
                } else {
                    "previews were truncated"
                }),
                "{text}"
            );
            assert!(
                text.contains(if language == "pt" {
                    "Continuar"
                } else {
                    "Continue"
                }),
                "{text}"
            );
            if let BatchScreen::ConfirmImpact {
                previews, scroll, ..
            } = &mut screen
            {
                *previews = vec![(
                    "external".into(),
                    crate::impact::ImpactPreview::ManagerOutput {
                        text: t("impact_truncated").into(),
                        truncated: false,
                    },
                )];
                *scroll = 0;
            }
            terminal
                .draw(|frame| render_batch(frame, &mut screen))
                .unwrap();
            let buffer = terminal.backend().buffer();
            let text = (0..buffer.area.height)
                .map(|y| {
                    (0..buffer.area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                text.contains(if language == "pt" {
                    "prévia foi truncada"
                } else {
                    "preview was truncated"
                }),
                "{text}"
            );
            assert!(
                !text.contains(if language == "pt" {
                    "prévias foram truncadas"
                } else {
                    "previews were truncated"
                }),
                "{text}"
            );
            return;
        }
        for (language, locale) in [("pt", "pt_BR.UTF-8"), ("en", "en_US.UTF-8")] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "batch::impact_tests::batch_screens_follow_requested_language",
                ])
                .env("TUCUPI_BATCH_TEST_LANGUAGE", language)
                .env("LC_ALL", locale)
                .status()
                .unwrap();
            assert!(status.success(), "locale {locale} failed");
        }
    }

    #[test]
    fn vulnerability_status_distinguishes_unknown_from_zero() {
        assert_eq!(vuln_count_label(None), "?");
        assert_eq!(vuln_count_label(Some(0)), "✓");
        assert_eq!(vuln_count_label(Some(2)), "2");
        assert_eq!(vuln_count_style(None).fg, Some(Color::DarkGray));
    }

    #[tokio::test]
    async fn selected_local_package_requires_impact_confirmation() {
        let item = BatchItem {
            dependency: Dependency {
                name: "example".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut running = true;
        let next = handle_key_input(
            BatchScreen::Select {
                items: vec![item],
                cursor: 0,
                force_mode: false,
            },
            KeyCode::Enter,
            &tx,
            &Config::default(),
            Path::new("."),
            false,
            &mut running,
        );
        assert!(matches!(next, BatchScreen::CheckingImpact { .. }));
        let event = rx.recv().await.unwrap();
        let next = finish_impact_preview(next, event);
        assert!(matches!(next, BatchScreen::ConfirmImpact { .. }));
        let cancelled = handle_key_input(
            next,
            KeyCode::Esc,
            &tx,
            &Config::default(),
            Path::new("."),
            false,
            &mut running,
        );
        assert!(matches!(cancelled, BatchScreen::Select { .. }));
    }

    #[test]
    fn old_impact_result_does_not_open_confirmation_for_new_preview() {
        let screen = BatchScreen::CheckingImpact {
            items: Vec::new(),
            cursor: 0,
            force_mode: false,
            attempt: 2,
            task: None,
        };
        let next = finish_impact_preview(
            screen,
            BatchEvent::ImpactChecked(
                1,
                vec![("old".into(), crate::impact::ImpactPreview::Unavailable)],
            ),
        );
        assert!(matches!(next, BatchScreen::CheckingImpact { .. }));
        let next = finish_impact_preview(
            next,
            BatchEvent::ImpactChecked(
                2,
                vec![("new".into(), crate::impact::ImpactPreview::Unavailable)],
            ),
        );
        assert!(
            matches!(&next, BatchScreen::ConfirmImpact { previews, .. } if previews[0].0 == "new")
        );
        let next = finish_impact_preview(next, BatchEvent::ImpactChecked(2, Vec::new()));
        assert!(
            matches!(&next, BatchScreen::ConfirmImpact { previews, .. } if previews[0].0 == "new")
        );
    }

    #[test]
    fn exhausted_impact_attempt_blocks_before_spawning_preview() {
        let item = BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            },
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        let result = begin_impact_preview_with_counter(
            vec![item],
            0,
            false,
            &tx,
            Path::new("."),
            &std::sync::atomic::AtomicU64::new(u64::MAX),
        );
        assert!(
            matches!(result, BatchScreen::Report { items, .. } if matches!(items[0].outcome, ItemOutcome::Blocked(_)))
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn batch_impact_results_always_require_confirmation_and_allow_cancel() {
        for preview in [
            crate::impact::ImpactPreview::Unavailable,
            crate::impact::ImpactPreview::ManagerOutput {
                text: "partial plan".into(),
                truncated: false,
            },
        ] {
            let item = BatchItem {
                dependency: Dependency {
                    name: "example".into(),
                    current_version: "1".into(),
                    latest_version: "2".into(),
                    ecosystem: Ecosystem::Cargo,
                    is_global: false,
                    origin: None,
                },
                selection: SelectionState::Safe,
                vulns: None,
                outcome: ItemOutcome::Pending,
                review_pending: None,
                upgrade_pending: None,
                security_pending: None,
                logs: Vec::new(),
            };
            let checking = BatchScreen::CheckingImpact {
                items: vec![item],
                cursor: 0,
                force_mode: false,
                attempt: 1,
                task: None,
            };
            let next = finish_impact_preview(
                checking,
                BatchEvent::ImpactChecked(1, vec![("example".into(), preview)]),
            );
            assert!(matches!(next, BatchScreen::ConfirmImpact { .. }));
            let (tx, mut rx) = mpsc::unbounded_channel();
            let mut running = true;
            let cancelled = handle_key_input(
                next,
                KeyCode::Esc,
                &tx,
                &Config::default(),
                Path::new("."),
                false,
                &mut running,
            );
            assert!(matches!(cancelled, BatchScreen::Select { .. }));
            assert!(rx.try_recv().is_err());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectionState {
    None,
    Safe,
    Force,
}

#[derive(Debug, Clone)]
enum ItemOutcome {
    Pending,
    Upgraded,
    ForceUpgraded,
    Failed(String),
    Blocked(String),
    SkippedVulnerable(Vec<VulnerabilityInfo>),
}

#[derive(Debug, Clone)]
struct BatchItem {
    dependency: Dependency,
    selection: SelectionState,
    vulns: Option<Vec<VulnerabilityInfo>>,
    outcome: ItemOutcome,
    review_pending: Option<u64>,
    upgrade_pending: Option<u64>,
    security_pending: Option<u64>,
    logs: Vec<String>,
}

enum BatchScreen {
    Scanning(Option<u64>),
    Select {
        items: Vec<BatchItem>,
        cursor: usize,
        force_mode: bool,
    },
    ConfirmGlobal {
        items: Vec<BatchItem>,
        cursor: usize,
        force_mode: bool,
    },
    CheckingImpact {
        items: Vec<BatchItem>,
        cursor: usize,
        force_mode: bool,
        attempt: u64,
        task: Option<tokio::task::AbortHandle>,
    },
    ConfirmImpact {
        items: Vec<BatchItem>,
        cursor: usize,
        force_mode: bool,
        previews: Vec<(String, crate::impact::ImpactPreview)>,
        scroll: u16,
    },
    Executing {
        items: Vec<BatchItem>,
        current_cursor: usize,
        progress_message: String,
    },
    Report {
        items: Vec<BatchItem>,
        scan_error: bool,
    },
}

struct BatchSecurityResult {
    vuln_result: Result<Vec<VulnerabilityInfo>, AuditFailure>,
    freshness_info: FreshnessInfo,
    provenance_info: Option<ProvenanceInfo>,
}

enum BatchEvent {
    ScanFinished(u64, Vec<Dependency>),
    SecurityChecked(usize, u64, BatchSecurityResult),
    ReviewChecked(usize, u64, ReviewReport),
    ReviewFailed(usize, u64),
    UpgradeFinished(usize, u64, Result<(), String>),
    UpgradeLog(usize, u64, String),
    ImpactChecked(u64, Vec<(String, crate::impact::ImpactPreview)>),
}

pub async fn run(
    target_dir: PathBuf,
    include_global: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load_from_dir(&target_dir).await?;
    let scan_attempt = next_batch_attempt(&NEXT_BATCH_ATTEMPT)
        .ok_or_else(|| std::io::Error::other(t("scan_attempt_exhausted")))?;
    #[cfg(target_os = "linux")]
    {
        let _observation = crate::recovery_state::inspect_configured_codex(&config).await;
        if crate::recovery_state::codex_recovery_preflight(&config).is_err() {
            return Err(std::io::Error::other(t("codex_recovery_unavailable")).into());
        }
    }
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        original_hook(panic_info);
    }));

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = BatchBackend {
        inner: CrosstermBackend::new(stdout),
        skip_cursor_show: false,
        #[cfg(test)]
        drop_marker: std::env::var_os("TUCUPI_UPGRADE_PTY_CHILD")
            .map(|root| PathBuf::from(root).join("backend-dropped")),
    };
    let mut terminal = Terminal::new(backend)?;

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<BatchEvent>();

    let mut screen = BatchScreen::Scanning(Some(scan_attempt));
    #[cfg(test)]
    let terminal_fixture = std::env::var_os("TUCUPI_BATCH_TERMINAL_FIXTURE").is_some()
        || std::env::var_os("TUCUPI_UPGRADE_PTY_CHILD").is_some();
    #[cfg(not(test))]
    let terminal_fixture = false;

    if !terminal_fixture {
        let scan_tx = event_tx.clone();
        let scan_dir = target_dir.to_path_buf();
        tokio::spawn(async move {
            let mut all_dependencies = check_all_outdated(&scan_dir).await;
            if include_global {
                let global_deps = check_global_outdated().await;
                all_dependencies.extend(global_deps);
            }
            let _ = scan_tx.send(BatchEvent::ScanFinished(scan_attempt, all_dependencies));
        });
    }
    #[cfg(test)]
    if terminal_fixture {
        let mut item = BatchItem {
            dependency: Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Homebrew,
                is_global: true,
                origin: None,
            },
            selection: SelectionState::Safe,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        };
        if std::env::var_os("TUCUPI_UPGRADE_PTY_CHILD").is_some() {
            item.upgrade_pending = Some(42);
            spawn_upgrade(0, 42, &item.dependency, &target_dir, &event_tx);
            screen = BatchScreen::Executing {
                items: vec![item],
                current_cursor: 0,
                progress_message: String::new(),
            };
        } else {
            screen = begin_impact_preview(vec![item], 0, false, &event_tx, &target_dir);
        }
    }

    let mut running = true;
    let mut pending_security = std::collections::HashMap::new();
    let mut processed_security = std::collections::HashSet::new();
    let mut logs_popup_open = false;
    let mut logs_popup_tab = 0usize;
    let mut logs_popup_scroll_back = 0usize;

    let loop_result = (|| -> std::io::Result<()> {
        while running {
            if logs_popup_open && log_tab_indices(&screen).is_empty() {
                logs_popup_open = false;
            }
            let tab_count = log_tab_indices(&screen).len();
            if tab_count > 0 {
                logs_popup_tab = logs_popup_tab.min(tab_count - 1);
            }

            terminal.draw(|frame| {
                let terminal_area = frame.area();
                render_batch(frame, &mut screen);
                if logs_popup_open {
                    let tab_indices = log_tab_indices(&screen);
                    let tab_names: Vec<String> = tab_indices
                        .iter()
                        .map(|&index| batch_item_name(&screen, index))
                        .collect();
                    let active_item_index = tab_indices[logs_popup_tab];
                    let active_lines = batch_item_logs(&screen, active_item_index);
                    ui::render_log_popup(
                        frame,
                        terminal_area,
                        &tab_names,
                        logs_popup_tab,
                        active_lines,
                        logs_popup_scroll_back,
                    );
                }
            })?;

            if let Ok(batch_event) = event_rx.try_recv() {
                match batch_event {
                    BatchEvent::ImpactChecked(attempt, previews) => {
                        let previous = std::mem::replace(&mut screen, BatchScreen::Scanning(None));
                        screen = finish_impact_preview(
                            previous,
                            BatchEvent::ImpactChecked(attempt, previews),
                        );
                    }
                    BatchEvent::ScanFinished(attempt, all_deps) => {
                        apply_scan_results(&mut screen, attempt, all_deps);
                    }
                    BatchEvent::SecurityChecked(index, attempt, security_result) => {
                        buffer_security_event(
                            &screen,
                            &mut pending_security,
                            &processed_security,
                            index,
                            attempt,
                            security_result,
                        );
                    }
                    BatchEvent::UpgradeFinished(index, attempt, result) => {
                        let is_done = process_upgrade_finished(&mut screen, index, attempt, result);
                        if is_done {
                            if let BatchScreen::Executing { items, .. } =
                                std::mem::replace(&mut screen, BatchScreen::Scanning(None))
                            {
                                screen = BatchScreen::Report {
                                    items,
                                    scan_error: false,
                                };
                            }
                        }
                    }
                    BatchEvent::ReviewChecked(index, attempt, report) => {
                        let is_done = process_review_checked(
                            &mut screen,
                            index,
                            attempt,
                            report,
                            &target_dir,
                            &event_tx,
                        );
                        if is_done {
                            if let BatchScreen::Executing { items, .. } =
                                std::mem::replace(&mut screen, BatchScreen::Scanning(None))
                            {
                                screen = BatchScreen::Report {
                                    items,
                                    scan_error: false,
                                };
                            }
                        }
                    }
                    BatchEvent::ReviewFailed(index, attempt) => {
                        let is_done = process_review_failure(&mut screen, index, attempt);
                        if is_done {
                            if let BatchScreen::Executing { items, .. } =
                                std::mem::replace(&mut screen, BatchScreen::Scanning(None))
                            {
                                screen = BatchScreen::Report {
                                    items,
                                    scan_error: false,
                                };
                            }
                        }
                    }
                    BatchEvent::UpgradeLog(index, attempt, line) => {
                        let is_first_line = append_batch_log(&mut screen, index, attempt, line);
                        if is_first_line && logs_popup_open {
                            let tab_indices = log_tab_indices(&screen);
                            if let Some(position) = tab_indices
                                .iter()
                                .position(|&item_index| item_index == index)
                            {
                                logs_popup_tab = position;
                                logs_popup_scroll_back = 0;
                            }
                        }
                    }
                }
            }

            if advance_buffered_security(
                &mut screen,
                &mut pending_security,
                &mut processed_security,
                &config,
                &target_dir,
                &event_tx,
            ) {
                if let BatchScreen::Executing { items, .. } =
                    std::mem::replace(&mut screen, BatchScreen::Scanning(None))
                {
                    screen = BatchScreen::Report {
                        items,
                        scan_error: false,
                    };
                }
            }

            #[cfg(test)]
            if terminal_fixture
                && std::env::var_os("TUCUPI_UPGRADE_PTY_CHILD").is_none()
                && std::env::var_os("TUCUPI_BATCH_DISCONNECT_FIXTURE").is_none()
                && target_dir.join("fixture-ready").exists()
            {
                return Err(std::io::Error::other("synthetic input failure"));
            }
            #[cfg(test)]
            if std::env::var_os("TUCUPI_UPGRADE_PTY_CHILD").is_some()
                && target_dir.join("inject-error").exists()
            {
                return Err(std::io::Error::other("synthetic terminal failure"));
            }
            if event::poll(Duration::from_millis(50))? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        let key_code = key.code;
                        if logs_popup_open {
                            match key_code {
                                KeyCode::Esc | KeyCode::Char('l') => logs_popup_open = false,
                                KeyCode::Left => {
                                    logs_popup_tab = logs_popup_tab.saturating_sub(1);
                                    logs_popup_scroll_back = 0;
                                }
                                KeyCode::Right => {
                                    let popup_tab_count = log_tab_indices(&screen).len();
                                    if popup_tab_count > 0 {
                                        logs_popup_tab = (logs_popup_tab + 1) % popup_tab_count;
                                    }
                                    logs_popup_scroll_back = 0;
                                }
                                KeyCode::Up => logs_popup_scroll_back += 1,
                                KeyCode::Down => {
                                    logs_popup_scroll_back =
                                        logs_popup_scroll_back.saturating_sub(1)
                                }
                                KeyCode::Char('q') => {
                                    request_batch_quit(&mut screen, &mut running);
                                    if running {
                                        logs_popup_open = false;
                                    }
                                }
                                _ => {}
                            }
                        } else {
                            let opens_popup = matches!(
                                screen,
                                BatchScreen::Executing { .. } | BatchScreen::Report { .. }
                            ) && key_code == KeyCode::Char('l');
                            let was_executing = matches!(screen, BatchScreen::Executing { .. });
                            let previous_screen =
                                std::mem::replace(&mut screen, BatchScreen::Scanning(None));
                            screen = handle_key_input(
                                previous_screen,
                                key_code,
                                &event_tx,
                                &config,
                                &target_dir,
                                include_global,
                                &mut running,
                            );
                            if !was_executing && matches!(screen, BatchScreen::Executing { .. }) {
                                pending_security.clear();
                                processed_security.clear();
                            }
                            if opens_popup {
                                logs_popup_open = true;
                                logs_popup_scroll_back = 0;
                            }
                            if !was_executing && matches!(screen, BatchScreen::Executing { .. }) {
                                logs_popup_open = true;
                                logs_popup_tab = 0;
                                logs_popup_scroll_back = 0;
                            }
                        }
                    }
                    Event::Mouse(mouse) => match mouse.kind {
                        MouseEventKind::ScrollUp if logs_popup_open => logs_popup_scroll_back += 1,
                        MouseEventKind::ScrollDown if logs_popup_open => {
                            logs_popup_scroll_back = logs_popup_scroll_back.saturating_sub(1)
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }

        Ok(())
    })();

    let result = finish_batch_session(&screen, loop_result, || {
        let raw_result = disable_raw_mode();
        let terminal_result = execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let cursor_result = restore_batch_cursor(&mut terminal);
        #[cfg(test)]
        if cursor_result.is_err() {
            if let Some(root) = std::env::var_os("TUCUPI_UPGRADE_PTY_CHILD") {
                let _ = std::fs::write(PathBuf::from(root).join("cursor-restore-failed"), "failed");
            }
        }
        #[cfg(test)]
        let terminal_result = if terminal_fixture
            && std::env::var_os("TUCUPI_UPGRADE_PTY_CHILD").is_none()
            && std::env::var_os("TUCUPI_BATCH_DISCONNECT_FIXTURE").is_none()
            && terminal_result.is_ok()
        {
            Err(std::io::Error::other("synthetic restoration failure"))
        } else {
            terminal_result
        };
        [raw_result, terminal_result, cursor_result]
    });
    result?;
    Ok(())
}

fn finish_batch_session(
    screen: &BatchScreen,
    loop_result: std::io::Result<()>,
    restore: impl FnOnce() -> [std::io::Result<()>; 3],
) -> std::io::Result<()> {
    cancel_batch_preview(screen);
    batch_finish_status(screen, loop_result, restore())
}

fn apply_scan_results(screen: &mut BatchScreen, attempt: u64, all_deps: Vec<Dependency>) {
    if !matches!(screen, BatchScreen::Scanning(Some(active)) if *active == attempt) {
        return;
    }
    let items = all_deps
        .into_iter()
        .map(|dep| BatchItem {
            dependency: dep,
            selection: SelectionState::None,
            vulns: None,
            outcome: ItemOutcome::Pending,
            review_pending: None,
            upgrade_pending: None,
            security_pending: None,
            logs: Vec::new(),
        })
        .collect();
    *screen = BatchScreen::Select {
        items,
        cursor: 0,
        force_mode: false,
    };
}

fn cancel_batch_preview(screen: &BatchScreen) {
    if let BatchScreen::CheckingImpact {
        task: Some(task), ..
    } = screen
    {
        task.abort();
    }
}

fn batch_finish_status(
    screen: &BatchScreen,
    loop_result: std::io::Result<()>,
    cleanup_results: [std::io::Result<()>; 3],
) -> std::io::Result<()> {
    let mut errors = Vec::new();
    if let Err(error) = loop_result {
        errors.push(error.to_string());
    }
    for result in cleanup_results {
        if let Err(error) = result {
            errors.push(error.to_string());
        }
    }
    if let Err(error) = batch_shutdown_status(screen) {
        errors.push(error.to_string());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(std::io::Error::other(errors.join("; ")))
    }
}

fn batch_shutdown_status(screen: &BatchScreen) -> std::io::Result<()> {
    if matches!(screen, BatchScreen::CheckingImpact { .. }) {
        return Err(std::io::Error::other(t("batch_impact_cleanup_unknown")));
    }
    if batch_upgrade_in_flight(screen) {
        return Err(std::io::Error::other(t("batch_upgrade_exit_unknown")));
    }
    Ok(())
}

fn batch_upgrade_in_flight(screen: &BatchScreen) -> bool {
    matches!(screen, BatchScreen::Executing { items, .. } if items.iter().any(|item| item.upgrade_pending.is_some()))
}

fn request_batch_quit(screen: &mut BatchScreen, running: &mut bool) {
    if batch_upgrade_in_flight(screen) {
        if let BatchScreen::Executing {
            progress_message, ..
        } = screen
        {
            *progress_message = t("batch_upgrade_quit_wait").to_string();
        }
    } else {
        *running = false;
    }
}

fn append_batch_log(screen: &mut BatchScreen, index: usize, attempt: u64, line: String) -> bool {
    match screen {
        BatchScreen::Executing {
            items,
            current_cursor,
            ..
        } if *current_cursor == index => {
            let Some(item) = items.get_mut(index) else {
                return false;
            };
            if item.upgrade_pending != Some(attempt) {
                return false;
            }
            let first = item.logs.is_empty();
            item.logs.push(line);
            retain_recent_log_lines(&mut item.logs);
            first
        }
        _ => false,
    }
}

fn buffer_security_event(
    screen: &BatchScreen,
    pending: &mut std::collections::HashMap<usize, BatchSecurityResult>,
    processed: &std::collections::HashSet<usize>,
    index: usize,
    attempt: u64,
    result: BatchSecurityResult,
) {
    if let BatchScreen::Executing {
        items,
        current_cursor,
        ..
    } = screen
    {
        if index >= *current_cursor
            && items.get(index).is_some_and(|item| {
                item.selection != SelectionState::None && item.security_pending == Some(attempt)
            })
            && !processed.contains(&index)
        {
            pending.entry(index).or_insert(result);
        }
    }
}

fn kick_off_security_checks(
    items: &mut [BatchItem],
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
    config: &Config,
) {
    let secret_store = crate::secrets::default_secret_store();
    let nvd_api_key = crate::secrets::resolve_nvd_api_key(&*secret_store);
    for (index, item) in items.iter_mut().enumerate() {
        if item.selection == SelectionState::None {
            continue;
        }
        let Some(attempt) = reserve_security_attempt(item, &NEXT_BATCH_ATTEMPT) else {
            continue;
        };
        let checker =
            SecurityChecker::new_with_config(config.osv_timeout_secs(), nvd_api_key.clone());
        let dependency_name = item.dependency.name.clone();
        let dependency_latest = item.dependency.latest_version.clone();
        let ecosystem = item.dependency.ecosystem;
        let tx = event_tx.clone();
        let very_recent_days = config.very_recent_days();
        let threshold_days = config.freshness_threshold_days();
        tokio::spawn(async move {
            let (result, freshness_info, provenance_info) = tokio::join!(
                checker.check_vulnerability(&dependency_name, &dependency_latest, ecosystem),
                checker.check_freshness(
                    &dependency_name,
                    &dependency_latest,
                    ecosystem,
                    very_recent_days,
                    threshold_days,
                ),
                async {
                    if ecosystem == Ecosystem::Pacman {
                        Some(check_provenance(&dependency_name, ecosystem).await)
                    } else {
                        None
                    }
                }
            );
            let _ = tx.send(BatchEvent::SecurityChecked(
                index,
                attempt,
                BatchSecurityResult {
                    vuln_result: result.map_err(AuditFailure::from),
                    freshness_info,
                    provenance_info,
                },
            ));
        });
    }
}

fn reserve_security_attempt(
    item: &mut BatchItem,
    counter: &std::sync::atomic::AtomicU64,
) -> Option<u64> {
    let Some(attempt) = next_batch_attempt(counter) else {
        item.outcome = ItemOutcome::Blocked(t("batch_attempt_exhausted").to_string());
        return None;
    };
    item.security_pending = Some(attempt);
    Some(attempt)
}

fn ecosystem_color(ecosystem: Ecosystem) -> Color {
    match ecosystem {
        Ecosystem::Cargo => Color::Red,
        Ecosystem::Go => Color::Green,
        Ecosystem::Dart => Color::Blue,
        Ecosystem::Elixir => Color::Magenta,
        Ecosystem::Npm => Color::Yellow,
        Ecosystem::Php => Color::LightMagenta,
        Ecosystem::Ruby => Color::LightRed,
        Ecosystem::Python => Color::Cyan,
        Ecosystem::Pacman => Color::Cyan,
        Ecosystem::Mise => Color::LightBlue,
        Ecosystem::Homebrew => Color::White,
    }
}

fn vuln_count_label(count: Option<usize>) -> String {
    match count {
        None => "?".to_string(),
        Some(0) => "✓".to_string(),
        Some(n) => n.to_string(),
    }
}

fn vuln_count_style(count: Option<usize>) -> Style {
    match count {
        None => Style::default().fg(Color::DarkGray),
        Some(0) => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        Some(1..=2) => Style::default().fg(Color::Yellow),
        Some(_) => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

fn vuln_count_detail(vulns: Option<&[VulnerabilityInfo]>) -> String {
    match vulns {
        Some(vulns) => tf("batch_vuln_count", &[&vulns.len().to_string()]),
        None => format!("  {}", t("batch_vulns_unknown_short")),
    }
}

fn advance_buffered_security(
    screen: &mut BatchScreen,
    pending: &mut std::collections::HashMap<usize, BatchSecurityResult>,
    processed: &mut std::collections::HashSet<usize>,
    config: &Config,
    target_dir: &Path,
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
) -> bool {
    let index = match screen {
        BatchScreen::Executing {
            items,
            current_cursor,
            ..
        } => {
            while *current_cursor < items.len()
                && (items[*current_cursor].selection == SelectionState::None
                    || matches!(items[*current_cursor].outcome, ItemOutcome::Blocked(_)))
            {
                *current_cursor += 1;
            }
            if *current_cursor >= items.len() {
                return true;
            }
            *current_cursor
        }
        _ => return false,
    };
    if processed.contains(&index) {
        return false;
    }
    let Some(result) = pending.remove(&index) else {
        return false;
    };
    if let BatchScreen::Executing { items, .. } = screen {
        items[index].security_pending = None;
    }
    processed.insert(index);
    process_security_checked(screen, index, result, config, target_dir, event_tx)
}

fn process_security_checked(
    screen: &mut BatchScreen,
    index: usize,
    security_result: BatchSecurityResult,
    config: &Config,
    target_dir: &Path,
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
) -> bool {
    let executing_state = match screen {
        BatchScreen::Executing {
            items,
            current_cursor,
            progress_message,
        } => Some((items, current_cursor, progress_message)),
        _ => None,
    };

    let (items, current_cursor, progress_message) = match executing_state {
        Some(data) => data,
        None => return false,
    };

    let item = &mut items[index];
    let dependency = &item.dependency;

    if matches!(dependency.origin, Some(PackageOrigin::Aur)) && !config.aur_enabled() {
        *progress_message = tf("exec_blocked", &[&dependency.name]);
        item.outcome = ItemOutcome::Blocked(t("blocked_aur_disabled").to_string());
        *current_cursor = current_cursor.saturating_add(1);
        return *current_cursor >= items.len();
    }

    if dependency.ecosystem == Ecosystem::Pacman
        && config.require_provenance()
        && !security_result
            .provenance_info
            .as_ref()
            .is_some_and(|info| info.signature_verified)
    {
        *progress_message = tf("exec_blocked", &[&dependency.name]);
        item.outcome = ItemOutcome::Blocked(t("blocked_provenance_required").to_string());
        *current_cursor = current_cursor.saturating_add(1);
        return *current_cursor >= items.len();
    }

    if config.block_too_fresh() && security_result.freshness_info.is_too_fresh() {
        *progress_message = tf("exec_blocked", &[&dependency.name]);
        item.outcome = ItemOutcome::Blocked(t("blocked_too_fresh").to_string());
        *current_cursor = current_cursor.saturating_add(1);
        return *current_cursor >= items.len();
    }

    let result = match security_result.vuln_result {
        Ok(vulns) => {
            item.vulns = if vulns.is_empty() && !dependency.ecosystem.has_osv_coverage() {
                None
            } else {
                Some(vulns)
            };
            Ok(())
        }
        Err(error_message) if error_message.partial => {
            let ids = error_message
                .findings
                .iter()
                .map(|v| v.id.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            item.vulns = if error_message.findings.is_empty() {
                None
            } else {
                Some(error_message.findings)
            };
            *progress_message = tf("exec_blocked", &[&dependency.name]);
            item.outcome = ItemOutcome::Blocked(tf("audit_partial_blocked", &[&ids]));
            *current_cursor = current_cursor.saturating_add(1);
            return *current_cursor >= items.len();
        }
        Err(error_message) => {
            item.vulns = None;
            if config.require_online() {
                *progress_message = tf("exec_blocked", &[&dependency.name]);
                item.outcome =
                    ItemOutcome::Blocked(tf("blocked_online_required", &[&error_message.message]));
                *current_cursor = current_cursor.saturating_add(1);
                return *current_cursor >= items.len();
            }
            Err(error_message)
        }
    };

    let _ = result;

    let (filtered_vulns, has_blocked_vulns) = match &item.vulns {
        Some(vulns_list) => {
            let filtered: Vec<VulnerabilityInfo> = vulns_list
                .iter()
                .filter(|vuln| !config.is_vulnerability_ignored(&vuln.id))
                .cloned()
                .collect();
            let blocked = config.block_vulnerable() && !filtered.is_empty();
            (filtered, blocked)
        }
        None => (Vec::new(), false),
    };

    let has_policy_issue =
        !filtered_vulns.is_empty() && !config.is_package_ignored(&dependency.name);

    if has_policy_issue && (has_blocked_vulns || item.selection != SelectionState::Force) {
        item.outcome = if has_blocked_vulns {
            *progress_message = tf("exec_blocked", &[&dependency.name]);
            ItemOutcome::Blocked(tf(
                "batch_active_vulns",
                &[&filtered_vulns.len().to_string()],
            ))
        } else {
            *progress_message = tf("exec_skipped", &[&dependency.name]);
            ItemOutcome::SkippedVulnerable(filtered_vulns)
        };
        *current_cursor = current_cursor.saturating_add(1);
        return *current_cursor >= items.len();
    }
    if has_policy_issue {
        item.outcome = ItemOutcome::ForceUpgraded;
    }

    // Source review gate: AUR PKGBUILDs and Homebrew formulae are reviewed
    // (residual diff + deterministic scan + LLM) before any upgrade spawns.
    if crate::review::needs_review(dependency) && config.pkgbuild_review() {
        let review_dep = dependency.clone();
        let Some(attempt) = reserve_review_attempt(item, &NEXT_BATCH_ATTEMPT) else {
            *progress_message = t("batch_attempt_exhausted").to_string();
            *current_cursor = current_cursor.saturating_add(1);
            return *current_cursor >= items.len();
        };
        *progress_message = tf("review_started", &[&review_dep.name]);
        let review_tx = event_tx.clone();
        let review_config = config.clone();
        spawn_batch_review(index, attempt, review_tx, async move {
            crate::review::review_package(&review_dep, &review_config).await
        });
        return false;
    }

    *progress_message = tf(
        if has_policy_issue {
            "exec_upgrading_forced"
        } else {
            "exec_upgrading"
        },
        &[&dependency.name, &dependency.latest_version],
    );
    if !spawn_item_upgrade(item, index, target_dir, event_tx) {
        *current_cursor = current_cursor.saturating_add(1);
        return *current_cursor >= items.len();
    }
    false
}

fn spawn_batch_review(
    index: usize,
    attempt: u64,
    event_tx: mpsc::UnboundedSender<BatchEvent>,
    future: impl std::future::Future<Output = ReviewReport> + Send + 'static,
) {
    tokio::spawn(async move {
        let event = match tokio::spawn(future).await {
            Ok(report) => BatchEvent::ReviewChecked(index, attempt, report),
            Err(_) => BatchEvent::ReviewFailed(index, attempt),
        };
        let _ = event_tx.send(event);
    });
}

fn reserve_review_attempt(
    item: &mut BatchItem,
    counter: &std::sync::atomic::AtomicU64,
) -> Option<u64> {
    let Some(attempt) = next_batch_attempt(counter) else {
        item.outcome = ItemOutcome::Blocked(t("batch_attempt_exhausted").to_string());
        return None;
    };
    item.review_pending = Some(attempt);
    Some(attempt)
}

fn process_review_failure(screen: &mut BatchScreen, index: usize, attempt: u64) -> bool {
    let BatchScreen::Executing {
        items,
        current_cursor,
        progress_message,
    } = screen
    else {
        return false;
    };
    if *current_cursor != index {
        return false;
    }
    let Some(item) = items.get_mut(index) else {
        return false;
    };
    if item.review_pending != Some(attempt) {
        return false;
    }
    item.review_pending = None;
    let message = t("review_task_failed").to_string();
    *progress_message = message.clone();
    item.outcome = ItemOutcome::Blocked(message);
    *current_cursor = current_cursor.saturating_add(1);
    *current_cursor >= items.len()
}

fn process_upgrade_finished(
    screen: &mut BatchScreen,
    index: usize,
    attempt: u64,
    result: Result<(), String>,
) -> bool {
    let executing_state = match screen {
        BatchScreen::Executing {
            items,
            current_cursor,
            progress_message,
        } => Some((items, current_cursor, progress_message)),
        _ => None,
    };

    let (items, current_cursor, progress_message) = match executing_state {
        Some(data) => data,
        None => return false,
    };

    if *current_cursor != index {
        return false;
    }
    let Some(item) = items.get_mut(index) else {
        return false;
    };
    if item.upgrade_pending != Some(attempt) {
        return false;
    }
    item.upgrade_pending = None;
    match result {
        Ok(()) => {
            if let ItemOutcome::ForceUpgraded = &item.outcome {
                *progress_message = tf("exec_forced_msg", &[&item.dependency.name]);
            } else {
                item.outcome = ItemOutcome::Upgraded;
                *progress_message = tf("exec_ok_msg", &[&item.dependency.name]);
            }
        }
        Err(error_message) => {
            item.outcome = ItemOutcome::Failed(error_message.clone());
            *progress_message = tf("exec_failed_msg", &[&item.dependency.name, &error_message]);
        }
    }
    *current_cursor = current_cursor.saturating_add(1);
    *current_cursor >= items.len()
}

static NEXT_BATCH_ATTEMPT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn next_batch_attempt(counter: &std::sync::atomic::AtomicU64) -> Option<u64> {
    let mut current = counter.load(std::sync::atomic::Ordering::Relaxed);
    loop {
        let next = current.checked_add(1)?;
        match counter.compare_exchange_weak(
            current,
            next,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => return Some(next),
            Err(observed) => current = observed,
        }
    }
}

fn spawn_item_upgrade(
    item: &mut BatchItem,
    index: usize,
    target_dir: &Path,
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
) -> bool {
    spawn_item_upgrade_with_counter(item, index, target_dir, event_tx, &NEXT_BATCH_ATTEMPT)
}

fn spawn_item_upgrade_with_counter(
    item: &mut BatchItem,
    index: usize,
    target_dir: &Path,
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
    counter: &std::sync::atomic::AtomicU64,
) -> bool {
    let Some(attempt) = next_batch_attempt(counter) else {
        item.outcome = ItemOutcome::Blocked(t("batch_attempt_exhausted").to_string());
        return false;
    };
    item.upgrade_pending = Some(attempt);
    spawn_upgrade(index, attempt, &item.dependency, target_dir, event_tx);
    true
}

fn spawn_upgrade(
    index: usize,
    attempt: u64,
    dependency: &Dependency,
    target_dir: &Path,
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
) {
    let Some((command, args)) = get_upgrade_cmd(dependency, target_dir) else {
        let _ = event_tx.send(BatchEvent::UpgradeFinished(
            index,
            attempt,
            Err(crate::i18n::t("upgrade_unsupported").to_string()),
        ));
        return;
    };
    let (line_tx, line_rx) = mpsc::unbounded_channel::<String>();
    let log_event_tx = event_tx.clone();
    let log_task = tokio::spawn(forward_batch_logs(index, attempt, line_rx, log_event_tx));
    let upgrade_tx = event_tx.clone();
    let target = target_dir.to_path_buf();
    let dependency_for_backup = dependency.clone();
    tokio::spawn(async move {
        let backup = if dependency_for_backup.is_global {
            None
        } else {
            match prepare_local_backup(&dependency_for_backup, &target) {
                Ok(backup) => backup,
                Err(error) => {
                    drop(line_tx);
                    let _ = log_task.await;
                    let _ = upgrade_tx.send(BatchEvent::UpgradeFinished(
                        index,
                        attempt,
                        Err(tf("backup_prepare_failed", &[&error.to_string()])),
                    ));
                    return;
                }
            }
        };

        let upgrade_result = run_upgrade_process(&command, args, &target, Some(line_tx)).await;
        let _ = log_task.await;
        let upgrade_result = match upgrade_result {
            Ok(()) => {
                if let Some(backup) = backup {
                    commit_backup(backup);
                }
                Ok(())
            }
            Err(error) => {
                if let Some(backup) = backup {
                    if let Err(restore_error) = restore_backup(backup) {
                        Err(tf(
                            "backup_restore_failed",
                            &[&error, &restore_error.to_string()],
                        ))
                    } else {
                        Err(error)
                    }
                } else {
                    Err(error)
                }
            }
        };
        let _ = upgrade_tx.send(BatchEvent::UpgradeFinished(index, attempt, upgrade_result));
    });
}

async fn forward_batch_logs(
    index: usize,
    attempt: u64,
    mut lines: mpsc::UnboundedReceiver<String>,
    events: mpsc::UnboundedSender<BatchEvent>,
) {
    while let Some(line) = lines.recv().await {
        let _ = events.send(BatchEvent::UpgradeLog(index, attempt, line));
    }
}

fn log_tab_indices(screen: &BatchScreen) -> Vec<usize> {
    match screen {
        BatchScreen::Executing { items, .. } => items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.selection != SelectionState::None)
            .map(|(index, _)| index)
            .collect(),
        BatchScreen::Report { items, .. } => items
            .iter()
            .enumerate()
            .filter(|(_, item)| !item.logs.is_empty())
            .map(|(index, _)| index)
            .collect(),
        _ => Vec::new(),
    }
}

fn batch_item_name(screen: &BatchScreen, index: usize) -> String {
    match screen {
        BatchScreen::Executing { items, .. } | BatchScreen::Report { items, .. } => {
            items[index].dependency.name.clone()
        }
        _ => String::new(),
    }
}

fn batch_item_logs(screen: &BatchScreen, index: usize) -> &[String] {
    match screen {
        BatchScreen::Executing { items, .. } | BatchScreen::Report { items, .. } => {
            items[index].logs.as_slice()
        }
        _ => &[],
    }
}

fn retain_recent_log_lines(lines: &mut Vec<String>) {
    let excess = lines.len().saturating_sub(MAX_LOG_LINES_PER_DEPENDENCY);
    if excess > 0 {
        lines.drain(..excess);
    }
}

fn begin_impact_preview(
    items: Vec<BatchItem>,
    cursor: usize,
    force_mode: bool,
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
    target_dir: &Path,
) -> BatchScreen {
    begin_impact_preview_with_counter(
        items,
        cursor,
        force_mode,
        event_tx,
        target_dir,
        &NEXT_BATCH_ATTEMPT,
    )
}

fn begin_impact_preview_with_counter(
    mut items: Vec<BatchItem>,
    cursor: usize,
    force_mode: bool,
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
    target_dir: &Path,
    counter: &std::sync::atomic::AtomicU64,
) -> BatchScreen {
    let Some(attempt) = next_batch_attempt(counter) else {
        for item in &mut items {
            if item.selection != SelectionState::None {
                item.outcome = ItemOutcome::Blocked(t("batch_attempt_exhausted").to_string());
            }
        }
        return BatchScreen::Report {
            items,
            scan_error: false,
        };
    };
    let selected: Vec<Dependency> = items
        .iter()
        .filter(|item| item.selection != SelectionState::None)
        .map(|item| item.dependency.clone())
        .collect();
    let tx = event_tx.clone();
    let dir = target_dir.to_path_buf();
    let task = tokio::spawn(async move {
        let mut previews = Vec::new();
        for dependency in selected {
            let label = format!("{}: {}", dependency.ecosystem.as_str(), dependency.name);
            let result = crate::impact::preview(&dependency, &dir).await;
            previews.push((label, result));
        }
        let _ = tx.send(BatchEvent::ImpactChecked(attempt, previews));
    });
    BatchScreen::CheckingImpact {
        items,
        cursor,
        force_mode,
        attempt,
        task: Some(task.abort_handle()),
    }
}

fn finish_impact_preview(screen: BatchScreen, event: BatchEvent) -> BatchScreen {
    match (screen, event) {
        (
            BatchScreen::CheckingImpact {
                items,
                cursor,
                force_mode,
                attempt,
                task: _,
            },
            BatchEvent::ImpactChecked(event_attempt, previews),
        ) if attempt == event_attempt => BatchScreen::ConfirmImpact {
            items,
            cursor,
            force_mode,
            previews,
            scroll: 0,
        },
        (screen, _) => screen,
    }
}

fn handle_key_input(
    previous_screen: BatchScreen,
    key_code: KeyCode,
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
    config: &Config,
    target_dir: &Path,
    include_global: bool,
    running: &mut bool,
) -> BatchScreen {
    match previous_screen {
        BatchScreen::Scanning(attempt) => {
            if key_code == KeyCode::Char('q') {
                *running = false;
            }
            BatchScreen::Scanning(attempt)
        }
        BatchScreen::Select {
            items,
            cursor,
            force_mode,
        } => match key_code {
            KeyCode::Char('q') => {
                *running = false;
                BatchScreen::Select {
                    items,
                    cursor,
                    force_mode,
                }
            }
            KeyCode::Up => {
                let new_cursor = if cursor > 0 { cursor - 1 } else { cursor };
                BatchScreen::Select {
                    items,
                    cursor: new_cursor,
                    force_mode,
                }
            }
            KeyCode::Down => {
                let max_index = items.len().saturating_sub(1);
                let new_cursor = if cursor < max_index {
                    cursor + 1
                } else {
                    cursor
                };
                BatchScreen::Select {
                    items,
                    cursor: new_cursor,
                    force_mode,
                }
            }
            KeyCode::Char(' ') => {
                let mut updated_items = items;
                if let Some(item) = updated_items.get_mut(cursor) {
                    item.selection = match item.selection {
                        SelectionState::None => SelectionState::Safe,
                        SelectionState::Safe => SelectionState::Force,
                        SelectionState::Force => SelectionState::None,
                    };
                }
                BatchScreen::Select {
                    items: updated_items,
                    cursor,
                    force_mode,
                }
            }
            KeyCode::Enter => {
                let has_selected = items
                    .iter()
                    .any(|item| item.selection != SelectionState::None);
                if has_selected {
                    let has_global = items.iter().any(|item| {
                        item.selection != SelectionState::None && item.dependency.is_global
                    });
                    if has_global && config.confirm_global() {
                        BatchScreen::ConfirmGlobal {
                            items,
                            cursor,
                            force_mode,
                        }
                    } else {
                        begin_impact_preview(items, cursor, force_mode, event_tx, target_dir)
                    }
                } else {
                    BatchScreen::Select {
                        items,
                        cursor,
                        force_mode,
                    }
                }
            }
            _ => BatchScreen::Select {
                items,
                cursor,
                force_mode,
            },
        },
        BatchScreen::ConfirmGlobal {
            items,
            cursor,
            force_mode,
        } => match key_code {
            KeyCode::Esc => BatchScreen::Select {
                items,
                cursor,
                force_mode,
            },
            KeyCode::Enter => begin_impact_preview(items, cursor, force_mode, event_tx, target_dir),
            KeyCode::Char('q') => {
                *running = false;
                BatchScreen::ConfirmGlobal {
                    items,
                    cursor,
                    force_mode,
                }
            }
            _ => BatchScreen::ConfirmGlobal {
                items,
                cursor,
                force_mode,
            },
        },
        BatchScreen::ConfirmImpact {
            mut items,
            cursor,
            force_mode,
            previews,
            scroll,
        } => match key_code {
            KeyCode::Esc => BatchScreen::Select {
                items,
                cursor,
                force_mode,
            },
            KeyCode::Enter => {
                kick_off_security_checks(&mut items, event_tx, config);
                BatchScreen::Executing {
                    items,
                    current_cursor: 0,
                    progress_message: String::new(),
                }
            }
            KeyCode::Char('q') => {
                *running = false;
                BatchScreen::ConfirmImpact {
                    items,
                    cursor,
                    force_mode,
                    previews,
                    scroll,
                }
            }
            KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown => {
                BatchScreen::ConfirmImpact {
                    items,
                    cursor,
                    force_mode,
                    previews,
                    scroll: match key_code {
                        KeyCode::Up => scroll.saturating_sub(1),
                        KeyCode::Down => scroll.saturating_add(1),
                        KeyCode::PageUp => scroll.saturating_sub(5),
                        KeyCode::PageDown => scroll.saturating_add(5),
                        _ => scroll,
                    },
                }
            }
            _ => BatchScreen::ConfirmImpact {
                items,
                cursor,
                force_mode,
                previews,
                scroll,
            },
        },
        BatchScreen::CheckingImpact { .. } => {
            if key_code == KeyCode::Char('q') {
                cancel_batch_preview(&previous_screen);
                *running = false;
            }
            previous_screen
        }
        BatchScreen::Executing { .. } => {
            if key_code == KeyCode::Char('q') {
                let mut screen = previous_screen;
                request_batch_quit(&mut screen, running);
                return screen;
            }
            previous_screen
        }
        BatchScreen::Report { items, scan_error } => match key_code {
            KeyCode::Char('q') => {
                *running = false;
                BatchScreen::Report { items, scan_error }
            }
            KeyCode::Char('r') => begin_rescan(
                items,
                event_tx,
                target_dir,
                include_global,
                &NEXT_BATCH_ATTEMPT,
            ),
            _ => BatchScreen::Report { items, scan_error },
        },
    }
}

fn begin_rescan(
    items: Vec<BatchItem>,
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
    target_dir: &Path,
    include_global: bool,
    counter: &std::sync::atomic::AtomicU64,
) -> BatchScreen {
    let Some(attempt) = next_batch_attempt(counter) else {
        return BatchScreen::Report {
            items,
            scan_error: true,
        };
    };
    let rescan_tx = event_tx.clone();
    let rescan_dir = target_dir.to_path_buf();
    tokio::spawn(async move {
        let mut all_deps = check_all_outdated(&rescan_dir).await;
        if include_global {
            let global_deps = check_global_outdated().await;
            all_deps.extend(global_deps);
        }
        let _ = rescan_tx.send(BatchEvent::ScanFinished(attempt, all_deps));
    });
    BatchScreen::Scanning(Some(attempt))
}

fn render_batch(frame: &mut Frame, screen: &mut BatchScreen) {
    let terminal_area = frame.area();

    let layout_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(terminal_area);

    let title_span = Span::styled(
        t("batch_title"),
        Style::default()
            .fg(Color::Yellow)
            .bg(Color::Rgb(30, 41, 59))
            .add_modifier(Modifier::BOLD),
    );
    let title_widget = Paragraph::new(title_span);
    frame.render_widget(title_widget, layout_chunks[0]);

    match screen {
        BatchScreen::Scanning(_) => {
            let scanning_text = Paragraph::new(t("batch_scanning"))
                .style(Style::default().fg(Color::Yellow))
                .wrap(Wrap { trim: true });
            frame.render_widget(scanning_text, layout_chunks[1]);

            let help_text = t("batch_help_scan");
            let help_widget =
                Paragraph::new(help_text).style(Style::default().fg(Color::Black).bg(Color::Cyan));
            frame.render_widget(help_widget, layout_chunks[2]);
        }

        BatchScreen::ConfirmGlobal { .. } => {
            let confirm_text = Paragraph::new(t("batch_global_confirm"))
                .style(Style::default().fg(Color::Yellow))
                .wrap(Wrap { trim: true });
            frame.render_widget(confirm_text, layout_chunks[1]);

            let help_widget = Paragraph::new(t("batch_help_confirm"))
                .style(Style::default().fg(Color::Black).bg(Color::Cyan));
            frame.render_widget(help_widget, layout_chunks[2]);
        }
        BatchScreen::CheckingImpact { .. } => {
            frame.render_widget(
                Paragraph::new(t("batch_impact_checking")).wrap(Wrap { trim: true }),
                layout_chunks[1],
            );
        }
        BatchScreen::ConfirmImpact {
            previews, scroll, ..
        } => {
            let mut text = format!("{}\n", t("batch_impact_warning"));
            if previews.iter().any(|(_, preview)| {
                matches!(
                    preview,
                    crate::impact::ImpactPreview::ManagerOutput {
                        truncated: true,
                        ..
                    }
                )
            }) {
                text.push_str(t("batch_impact_truncated"));
                text.push('\n');
            }
            for (label, preview) in previews.iter() {
                text.push_str(&format!("\n{label}\n"));
                match preview {
                    crate::impact::ImpactPreview::ManagerOutput {
                        text: output,
                        truncated,
                    } => {
                        text.push_str(t("impact_manager_output"));
                        if *truncated {
                            text.push_str(t("impact_truncated"));
                            text.push_str("\n\n");
                        }
                        text.push_str(output);
                    }
                    crate::impact::ImpactPreview::Unavailable => {
                        text.push_str(t("impact_unavailable"))
                    }
                }
                text.push('\n');
            }
            let paragraph = Paragraph::new(text)
                .style(Style::default().fg(Color::Yellow))
                .wrap(Wrap { trim: false });
            let max = paragraph
                .line_count(layout_chunks[1].width.max(1))
                .saturating_sub(layout_chunks[1].height as usize);
            *scroll = (*scroll as usize).min(max).min(u16::MAX as usize) as u16;
            frame.render_widget(paragraph.scroll((*scroll, 0)), layout_chunks[1]);
            frame.render_widget(Paragraph::new(t("impact_footer")), layout_chunks[2]);
        }

        BatchScreen::Select {
            items,
            cursor,
            force_mode: _force_mode,
        } => {
            let total_items = items.len();
            let selected_count = items
                .iter()
                .filter(|item| item.selection != SelectionState::None)
                .count();
            let force_count = items
                .iter()
                .filter(|item| item.selection == SelectionState::Force)
                .count();

            let list_height = layout_chunks[1].height as usize;
            let max_visible = list_height.saturating_sub(2);
            let scroll_offset = if *cursor >= max_visible {
                cursor.saturating_sub(max_visible).saturating_add(1)
            } else {
                0
            };

            let mut list_lines: Vec<Line> = Vec::new();

            let header_line = Line::from(vec![
                Span::raw(tf("batch_header", &[&total_items.to_string()])),
                Span::raw("    "),
                Span::styled(
                    t("batch_vulns_header"),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            ])
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );
            list_lines.push(header_line);
            list_lines.push(Line::from(""));

            for (index, item) in items.iter().enumerate() {
                if index < scroll_offset {
                    continue;
                }
                if list_lines.len() >= max_visible + 2 {
                    break;
                }

                let is_selected = index == *cursor;
                let eco_color = ecosystem_color(item.dependency.ecosystem);

                let selection_mark = match item.selection {
                    SelectionState::None => " ",
                    SelectionState::Safe => "✓",
                    SelectionState::Force => "⚡",
                };

                let selection_style = match item.selection {
                    SelectionState::None => Style::default().fg(Color::DarkGray),
                    SelectionState::Safe => Style::default().fg(Color::Green),
                    SelectionState::Force => Style::default().fg(Color::Yellow),
                };

                let prefix = if is_selected { " ➜" } else { "  " };

                let vuln_count = item.vulns.as_ref().map(|v| v.len());
                let vuln_label = vuln_count_label(vuln_count);

                let item_line = Line::from(vec![
                    Span::styled(prefix, Style::default().fg(Color::Cyan)),
                    Span::styled(format!(" [{}] ", selection_mark), selection_style),
                    Span::styled(
                        format!("{:8}", item.dependency.ecosystem.as_str()),
                        Style::default().fg(eco_color).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  "),
                    Span::raw(format!("{:26}", item.dependency.name)),
                    Span::raw("  "),
                    Span::styled(
                        format!("{:10}", item.dependency.current_version),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(" ➔ ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        format!("{:10}", item.dependency.latest_version),
                        Style::default().fg(Color::Green),
                    ),
                    Span::styled(format!(" {:>4}", vuln_label), vuln_count_style(vuln_count)),
                ]);

                let styled_line = if is_selected {
                    item_line.style(Style::default().bg(Color::Rgb(30, 41, 59)))
                } else {
                    item_line
                };

                list_lines.push(styled_line);
            }

            let list_paragraph = Paragraph::new(list_lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            );
            frame.render_widget(list_paragraph, layout_chunks[1]);

            let help_text = tf(
                "batch_help_select",
                &[&selected_count.to_string(), &force_count.to_string()],
            );
            let help_widget =
                Paragraph::new(help_text).style(Style::default().fg(Color::Black).bg(Color::Cyan));
            frame.render_widget(help_widget, layout_chunks[2]);
        }

        BatchScreen::Executing {
            items,
            current_cursor,
            progress_message,
        } => {
            let mut execution_lines: Vec<Line> = vec![
                Line::from(Span::styled(
                    tf(
                        "batch_exec_title",
                        &[&current_cursor.to_string(), &items.len().to_string()],
                    ),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    progress_message.as_str(),
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(""),
            ];

            for (index, item) in items.iter().enumerate() {
                if item.selection == SelectionState::None {
                    continue;
                }

                let status_symbol = match &item.outcome {
                    ItemOutcome::Pending => {
                        if *current_cursor <= index {
                            " ⏳"
                        } else {
                            "   "
                        }
                    }
                    ItemOutcome::Upgraded => " ✓",
                    ItemOutcome::ForceUpgraded => " ⚡",
                    ItemOutcome::Failed(_) => " ✗",
                    ItemOutcome::Blocked(_) => " ⊘",
                    ItemOutcome::SkippedVulnerable(_) => " ⊘",
                };

                let status_color = match &item.outcome {
                    ItemOutcome::Pending => {
                        if *current_cursor <= index {
                            Color::Cyan
                        } else {
                            Color::DarkGray
                        }
                    }
                    ItemOutcome::Upgraded => Color::Green,
                    ItemOutcome::ForceUpgraded => Color::Yellow,
                    ItemOutcome::Failed(_) => Color::Red,
                    ItemOutcome::Blocked(_) => Color::Red,
                    ItemOutcome::SkippedVulnerable(_) => Color::DarkGray,
                };

                let outcome_text: String = match &item.outcome {
                    ItemOutcome::Pending => t("batch_pending").to_string(),
                    ItemOutcome::Upgraded => t("batch_done").to_string(),
                    ItemOutcome::ForceUpgraded => t("batch_forced").to_string(),
                    ItemOutcome::Failed(error) => tf("batch_failed_detail", &[error]),
                    ItemOutcome::Blocked(reason) => format!(
                        "{} — {}",
                        tf("exec_blocked", &[&item.dependency.name]),
                        reason
                    ),
                    ItemOutcome::SkippedVulnerable(vulns) => format!(
                        "{} — {}",
                        tf("exec_skipped", &[&item.dependency.name]),
                        tf("batch_active_vulns", &[&vulns.len().to_string()])
                    ),
                };

                let vuln_count = item.vulns.as_ref().map(|v| v.len());
                let vuln_label = vuln_count_label(vuln_count);

                let execution_line = Line::from(vec![
                    Span::styled(
                        format!("{:4} ", status_symbol),
                        Style::default().fg(status_color),
                    ),
                    Span::styled(
                        format!("{:8} ", item.dependency.ecosystem.as_str()),
                        Style::default()
                            .fg(ecosystem_color(item.dependency.ecosystem))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("{:26}  ", item.dependency.name)),
                    Span::styled(
                        format!("{:10}", item.dependency.current_version),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(" ➔ ", Style::default().fg(Color::Cyan)),
                    Span::styled(
                        format!("{:10}", item.dependency.latest_version),
                        Style::default().fg(Color::Green),
                    ),
                    Span::styled(format!(" {:>4}", vuln_label), vuln_count_style(vuln_count)),
                    Span::raw("  "),
                    Span::styled(outcome_text, Style::default().fg(status_color)),
                ]);

                execution_lines.push(execution_line);
            }

            let execution_paragraph = Paragraph::new(execution_lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            );
            frame.render_widget(execution_paragraph, layout_chunks[1]);

            let help_text = t("batch_help_exec");
            let help_widget =
                Paragraph::new(help_text).style(Style::default().fg(Color::Black).bg(Color::Cyan));
            frame.render_widget(help_widget, layout_chunks[2]);
        }

        BatchScreen::Report { items, scan_error } => {
            let mut report_lines: Vec<Line> = Vec::new();

            if *scan_error {
                report_lines.push(Line::from(Span::styled(
                    t("scan_attempt_exhausted"),
                    Style::default().fg(Color::Red),
                )));
            }

            report_lines.push(Line::from(Span::styled(
                t("batch_report_title"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
            report_lines.push(Line::from(""));
            if items.iter().any(|item| item.vulns.is_none()) {
                report_lines.push(Line::from(t("batch_vulns_unknown")));
                report_lines.push(Line::from(""));
            }

            let upgraded_items: Vec<&BatchItem> = items
                .iter()
                .filter(|item| matches!(item.outcome, ItemOutcome::Upgraded))
                .collect();
            let force_upgraded_items: Vec<&BatchItem> = items
                .iter()
                .filter(|item| matches!(item.outcome, ItemOutcome::ForceUpgraded))
                .collect();
            let failed_items: Vec<&BatchItem> = items
                .iter()
                .filter(|item| matches!(item.outcome, ItemOutcome::Failed(_)))
                .collect();
            let blocked_items: Vec<&BatchItem> = items
                .iter()
                .filter(|item| matches!(item.outcome, ItemOutcome::Blocked(_)))
                .collect();
            let skipped_items: Vec<&BatchItem> = items
                .iter()
                .filter(|item| matches!(item.outcome, ItemOutcome::SkippedVulnerable(_)))
                .collect();

            if !upgraded_items.is_empty() {
                report_lines.push(Line::from(Span::styled(
                    tf("batch_report_safe", &[&upgraded_items.len().to_string()]),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )));
                for item in &upgraded_items {
                    let vuln_count = item.vulns.as_ref().map(|list| list.len());
                    report_lines.push(Line::from(vec![
                        Span::raw("     "),
                        Span::styled(
                            format!("{:8}", item.dependency.ecosystem.as_str()),
                            Style::default()
                                .fg(ecosystem_color(item.dependency.ecosystem))
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!("  {:26}", item.dependency.name)),
                        Span::styled(
                            format!(" {:10}", item.dependency.current_version),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(" ➔ ", Style::default().fg(Color::Cyan)),
                        Span::styled(
                            format!("{:10}", item.dependency.latest_version),
                            Style::default().fg(Color::Green),
                        ),
                        Span::raw(format!("  {}", vuln_count_label(vuln_count))),
                    ]));
                }
                report_lines.push(Line::from(""));
            }

            if !force_upgraded_items.is_empty() {
                report_lines.push(Line::from(Span::styled(
                    tf(
                        "batch_report_forced",
                        &[&force_upgraded_items.len().to_string()],
                    ),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )));
                for item in &force_upgraded_items {
                    report_lines.push(Line::from(vec![
                        Span::raw("     "),
                        Span::styled(
                            format!("{:8}", item.dependency.ecosystem.as_str()),
                            Style::default()
                                .fg(ecosystem_color(item.dependency.ecosystem))
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!("  {:26}", item.dependency.name)),
                        Span::styled(
                            format!(" {:10}", item.dependency.current_version),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(" ➔ ", Style::default().fg(Color::Cyan)),
                        Span::styled(
                            format!("{:10}", item.dependency.latest_version),
                            Style::default().fg(Color::Green),
                        ),
                        Span::raw(vuln_count_detail(item.vulns.as_deref())),
                    ]));
                }
                report_lines.push(Line::from(""));
            }

            if !failed_items.is_empty() {
                report_lines.push(Line::from(Span::styled(
                    tf("batch_report_failed", &[&failed_items.len().to_string()]),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));
                for item in &failed_items {
                    let error_message = match &item.outcome {
                        ItemOutcome::Failed(error) => error.as_str(),
                        _ => "",
                    };
                    report_lines.push(Line::from(vec![
                        Span::raw("     "),
                        Span::styled(
                            format!("{:8}", item.dependency.ecosystem.as_str()),
                            Style::default()
                                .fg(ecosystem_color(item.dependency.ecosystem))
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!("  {:26}", item.dependency.name)),
                        Span::raw(format!("  {}", error_message)),
                    ]));
                }
                report_lines.push(Line::from(""));
            }

            if !blocked_items.is_empty() {
                report_lines.push(Line::from(Span::styled(
                    tf("batch_report_blocked", &[&blocked_items.len().to_string()]),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )));
                for item in &blocked_items {
                    report_lines.push(Line::from(vec![
                        Span::raw("     "),
                        Span::styled(
                            format!("{:8}", item.dependency.ecosystem.as_str()),
                            Style::default()
                                .fg(ecosystem_color(item.dependency.ecosystem))
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!("  {:26}", item.dependency.name)),
                        Span::styled(
                            format!(" {:10}", item.dependency.current_version),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(" ➔ ", Style::default().fg(Color::Cyan)),
                        Span::styled(
                            format!("{:10}", item.dependency.latest_version),
                            Style::default().fg(Color::Green),
                        ),
                    ]));
                    if let ItemOutcome::Blocked(reason) = &item.outcome {
                        report_lines.push(Line::from(format!("       {reason}")));
                    }
                }
                report_lines.push(Line::from(""));
            }

            if !skipped_items.is_empty() {
                report_lines.push(Line::from(Span::styled(
                    tf("batch_report_skipped", &[&skipped_items.len().to_string()]),
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )));
                for item in &skipped_items {
                    report_lines.push(Line::from(vec![
                        Span::raw("     "),
                        Span::styled(
                            format!("{:8}", item.dependency.ecosystem.as_str()),
                            Style::default()
                                .fg(ecosystem_color(item.dependency.ecosystem))
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!("  {:26}", item.dependency.name)),
                        Span::styled(
                            format!(" {:10}", item.dependency.current_version),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(" ➔ ", Style::default().fg(Color::Cyan)),
                        Span::styled(
                            format!("{:10}", item.dependency.latest_version),
                            Style::default().fg(Color::Green),
                        ),
                        Span::raw(vuln_count_detail(item.vulns.as_deref())),
                    ]));
                }
                report_lines.push(Line::from(""));
            }

            let total_succeeded = upgraded_items.len() + force_upgraded_items.len();

            report_lines.push(Line::from(Span::styled(
                tf(
                    "batch_report_summary",
                    &[
                        &total_succeeded.to_string(),
                        &failed_items.len().to_string(),
                        &blocked_items.len().to_string(),
                        &skipped_items.len().to_string(),
                    ],
                ),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));

            let report_paragraph = Paragraph::new(report_lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan)),
                )
                .wrap(Wrap { trim: false });
            frame.render_widget(report_paragraph, layout_chunks[1]);

            let help_text = t("batch_help_report");
            let help_widget =
                Paragraph::new(help_text).style(Style::default().fg(Color::Black).bg(Color::Cyan));
            frame.render_widget(help_widget, layout_chunks[2]);
        }
    }
}

fn process_review_checked(
    screen: &mut BatchScreen,
    index: usize,
    attempt: u64,
    report: ReviewReport,
    target_dir: &Path,
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
) -> bool {
    let executing_state = match screen {
        BatchScreen::Executing {
            items,
            current_cursor,
            progress_message,
        } => Some((items, current_cursor, progress_message)),
        _ => None,
    };

    let (items, current_cursor, progress_message) = match executing_state {
        Some(data) => data,
        None => return false,
    };

    if *current_cursor != index {
        return false;
    }
    let Some(item) = items.get_mut(index) else {
        return false;
    };
    if item.review_pending != Some(attempt) {
        return false;
    }
    item.review_pending = None;
    let dependency = item.dependency.clone();

    match report.verdict {
        ReviewVerdict::Safe => {
            *progress_message = tf(
                "exec_upgrading",
                &[&dependency.name, &dependency.latest_version],
            );
            if !spawn_item_upgrade(item, index, target_dir, event_tx) {
                *current_cursor = current_cursor.saturating_add(1);
                return *current_cursor >= items.len();
            }
            false
        }
        ReviewVerdict::Block => {
            // Known IoCs and LLM-blocked sources are hard stops: selection
            // state never overrides a blocked package source.
            let reason = crate::review::display_review_reason(&report.reason);
            *progress_message = tf("review_blocked", &[&reason]);
            item.outcome = ItemOutcome::Blocked(tf("review_blocked", &[&reason]));
            *current_cursor = current_cursor.saturating_add(1);
            *current_cursor >= items.len()
        }
        ReviewVerdict::Review => {
            if item.selection == SelectionState::Force && !report.has_known_ioc() {
                item.outcome = ItemOutcome::ForceUpgraded;
                *progress_message = tf(
                    "exec_upgrading_forced",
                    &[&dependency.name, &dependency.latest_version],
                );
                if !spawn_item_upgrade(item, index, target_dir, event_tx) {
                    *current_cursor = current_cursor.saturating_add(1);
                    return *current_cursor >= items.len();
                }
                false
            } else {
                *progress_message = tf(
                    "review_needs_confirmation",
                    &[&crate::review::display_review_reason(&report.reason)],
                );
                item.outcome = ItemOutcome::Blocked(tf(
                    "review_needs_confirmation",
                    &[&crate::review::display_review_reason(&report.reason)],
                ));
                *current_cursor = current_cursor.saturating_add(1);
                *current_cursor >= items.len()
            }
        }
    }
}
