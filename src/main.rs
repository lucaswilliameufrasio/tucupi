use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::path::PathBuf;
use std::time::Duration;
use tucupi::app::{App, Modal};
use tucupi::batch;
use tucupi::ui;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Parse Arguments
    let args: Vec<String> = std::env::args().collect();
    let mut target_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut boot_global = false;
    let mut interactive = false;

    if args.get(1).map(String::as_str) == Some("config") {
        return tucupi::secrets::run_config_command(&args[2..]);
    }

    if args.get(1).map(String::as_str) == Some("recovery") {
        #[cfg(target_os = "linux")]
        if args.len() == 3 && args[2] == "init" {
            tucupi::recovery_state::provision_default_recovery()?;
            println!("{}", tucupi::i18n::t("recovery_init_done"));
            return Ok(());
        }
        if args.len() == 3 && args[2] == "status" {
            println!("{}", tucupi::i18n::t("recovery_status"));
            #[cfg(target_os = "linux")]
            {
                use tucupi::recovery_state::LocalRecoveryEvidence;
                use tucupi::same_user_supervisor::{
                    inspect_default_recovery, DirectExitObservation, SnapshotObservation,
                };
                let inspection = inspect_default_recovery();
                let key = match inspection.local_evidence {
                    LocalRecoveryEvidence::StateUnavailable => "recovery_local_state_unavailable",
                    LocalRecoveryEvidence::AttemptUnavailableOrInvalid => {
                        "recovery_local_attempt_unknown"
                    }
                    LocalRecoveryEvidence::PendingAttemptObserved => "recovery_local_pending",
                    LocalRecoveryEvidence::PendingIntentObserved => "recovery_local_intent",
                    LocalRecoveryEvidence::PendingChildLocatorObserved => "recovery_local_child",
                    LocalRecoveryEvidence::PendingDirectExitRecorded => "recovery_local_exit",
                    LocalRecoveryEvidence::RecordsInconsistent => "recovery_local_inconsistent",
                };
                println!("{}", tucupi::i18n::t(key));
                let exit_key = match inspection.direct_exit {
                    DirectExitObservation::SuccessRecorded => "recovery_direct_exit_success",
                    DirectExitObservation::FailureRecorded => "recovery_direct_exit_failure",
                    DirectExitObservation::NotRecorded => "recovery_direct_exit_not_recorded",
                    DirectExitObservation::UnavailableOrInvalid => "recovery_direct_exit_unknown",
                };
                println!("{}", tucupi::i18n::t(exit_key));
                let snapshot_key = match inspection.snapshot {
                    SnapshotObservation::ValidEnvelopeObserved => "recovery_snapshot_envelope",
                    SnapshotObservation::UnavailableOrInvalid => "recovery_snapshot_unavailable",
                };
                println!("{}", tucupi::i18n::t(snapshot_key));
            }
            return Ok(());
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            tucupi::i18n::t("recovery_usage"),
        )
        .into());
    }

    for arg in &args[1..] {
        if arg == "--version" || arg == "-V" {
            println!("tucupi {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        } else if arg == "--help" || arg == "-h" {
            println!("{}", tucupi::i18n::t("cli_help"));
            println!("\n{}", tucupi::i18n::t("recovery_help"));
            return Ok(());
        } else if arg == "--global" || arg == "-g" {
            boot_global = true;
        } else if arg == "--interactive" || arg == "-i" {
            interactive = true;
        } else if !arg.starts_with('-') {
            target_dir = PathBuf::from(arg);
        }
    }

    // Convert target_dir to absolute path for safety
    if let Ok(abs) = std::fs::canonicalize(&target_dir) {
        target_dir = abs;
    }

    // Route to interactive batch mode if requested
    if interactive {
        return batch::run(target_dir, boot_global).await;
    }

    let mut app = App::new(target_dir, boot_global);
    app.load_config_sync().await?;
    app.restore_review_settings();

    // 2. Set up Panic Hook to restore terminal state
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        original_hook(panic_info);
    }));

    // 3. Initialize Terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 4. Initialize App
    #[cfg(all(target_os = "linux", feature = "review-pty-fixture"))]
    let fixture = tucupi::review_pty_fixture::endpoint().is_some();
    #[cfg(not(all(target_os = "linux", feature = "review-pty-fixture")))]
    let fixture = false;
    if fixture {
        use tucupi::models::{Dependency, Ecosystem, PackageOrigin};
        app.local_deps.push(Dependency {
            name: "tucupi-synthetic-package".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Pacman,
            is_global: false,
            origin: Some(PackageOrigin::Aur),
        });
        app.local_selection
            .push(tucupi::app::SelectionState::Unselected);
        app.table_state.select(Some(0));
    } else {
        app.trigger_scan();
    }

    // 5. TUI Loop
    let loop_result = (|| -> io::Result<()> {
        loop {
            terminal.draw(|f| ui::render(f, &mut app))?;

            // Poll background async events
            while let Ok(event) = app.event_rx.try_recv() {
                app.handle_event(event);
            }
            app.expire_toasts();

            // Poll UI events (50ms timeout)
            if event::poll(Duration::from_millis(50))? {
                let area = terminal.size()?;
                let detail_start_column = area.width * 55 / 100;
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        if app.log_popup_open {
                            match key.code {
                                KeyCode::Esc | KeyCode::Char('l') => app.close_log_popup(),
                                KeyCode::Left => app.log_popup_prev_tab(),
                                KeyCode::Right => app.log_popup_next_tab(),
                                KeyCode::Up => app.log_popup_scroll_up(),
                                KeyCode::Down => app.log_popup_scroll_down(),
                                KeyCode::Char('y') => app.copy_active_log(),
                                KeyCode::Char('q') => break,
                                _ => {}
                            }
                        } else {
                            match &app.modal {
                                Modal::Help { .. } => match key.code {
                                    KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => {
                                        app.modal = Modal::None;
                                    }
                                    KeyCode::Up
                                    | KeyCode::Down
                                    | KeyCode::PageUp
                                    | KeyCode::PageDown => {
                                        if let Modal::Help { scroll } = &mut app.modal {
                                            *scroll = match key.code {
                                                KeyCode::Up => scroll.saturating_sub(1),
                                                KeyCode::PageUp => scroll.saturating_sub(5),
                                                KeyCode::Down => scroll.saturating_add(1),
                                                KeyCode::PageDown => scroll.saturating_add(5),
                                                _ => *scroll,
                                            };
                                        }
                                    }
                                    _ => {}
                                },
                                Modal::ConfirmForce(_, _)
                                | Modal::ConfirmReview(_, _)
                                | Modal::ConfirmOffline(_, _) => match key.code {
                                    KeyCode::Enter => {
                                        app.confirm_force_upgrade();
                                    }
                                    KeyCode::Esc => {
                                        app.dismiss_modal();
                                    }
                                    _ => {}
                                },
                                Modal::Blocked(_, _) => match key.code {
                                    KeyCode::Enter | KeyCode::Esc => {
                                        app.dismiss_modal();
                                    }
                                    _ => {}
                                },
                                Modal::BlockedPolicy(_, _) => match key.code {
                                    KeyCode::Enter | KeyCode::Esc => {
                                        app.dismiss_modal();
                                    }
                                    _ => {}
                                },
                                Modal::ConfirmGlobal(_, _) => match key.code {
                                    KeyCode::Enter => app.confirm_global_upgrade(),
                                    KeyCode::Esc => {
                                        app.dismiss_modal();
                                    }
                                    _ => {}
                                },
                                Modal::ConfirmImpact { .. } => match key.code {
                                    KeyCode::Enter => app.confirm_impact(),
                                    KeyCode::Esc => app.dismiss_modal(),
                                    KeyCode::Up
                                    | KeyCode::Down
                                    | KeyCode::PageUp
                                    | KeyCode::PageDown => {
                                        if let Modal::ConfirmImpact { scroll, .. } = &mut app.modal
                                        {
                                            *scroll = match key.code {
                                                KeyCode::Up => scroll.saturating_sub(1),
                                                KeyCode::Down => scroll.saturating_add(1),
                                                KeyCode::PageUp => scroll.saturating_sub(5),
                                                KeyCode::PageDown => scroll.saturating_add(5),
                                                _ => *scroll,
                                            };
                                        }
                                    }
                                    _ => {}
                                },
                                Modal::SecretInput { .. } => match key.code {
                                    KeyCode::Enter => app.save_nvd_key_from_input(),
                                    KeyCode::Esc => app.modal = Modal::None,
                                    KeyCode::Backspace => app.secret_input_backspace(),
                                    KeyCode::Char(character) => app.secret_input_push(character),
                                    _ => {}
                                },
                                Modal::ReviewSettings { input, .. } => {
                                    let menu =
                                        matches!(input, tucupi::app::ReviewSettingsInput::Menu);
                                    match key.code {
                                        KeyCode::Esc => app.review_settings_cancel(),
                                        KeyCode::Enter => app.review_settings_submit(),
                                        KeyCode::Left | KeyCode::Up if menu => {
                                            app.review_settings_next_provider(false)
                                        }
                                        KeyCode::Right | KeyCode::Down if menu => {
                                            app.review_settings_next_provider(true)
                                        }
                                        KeyCode::Char('m') if menu => {
                                            app.review_settings_begin_input(false)
                                        }
                                        KeyCode::Char('k') if menu => {
                                            app.review_settings_begin_input(true)
                                        }
                                        KeyCode::Char('d') if menu => {
                                            app.review_settings_remove_key()
                                        }
                                        KeyCode::Backspace if !menu => {
                                            app.review_settings_input_char(None)
                                        }
                                        KeyCode::Char(character) if !menu => {
                                            app.review_settings_input_char(Some(character))
                                        }
                                        _ => {}
                                    }
                                }
                                Modal::None => match key.code {
                                    KeyCode::Char('?') => app.modal = Modal::Help { scroll: 0 },
                                    KeyCode::Char('q') => break,
                                    KeyCode::Up => app.scroll_up(),
                                    KeyCode::Down => app.scroll_down(),
                                    KeyCode::PageUp => app.detail_scroll_up(),
                                    KeyCode::PageDown => app.detail_scroll_down(),
                                    KeyCode::Tab => app.switch_tab(),
                                    KeyCode::Char('r') => app.trigger_scan(),
                                    KeyCode::Char(' ') => app.toggle_selection(),
                                    KeyCode::Char('u') => app.trigger_upgrade_selected(false),
                                    KeyCode::Char('f') => app.trigger_upgrade_selected(true),
                                    KeyCode::Char('c') => app.check_security_selected(),
                                    KeyCode::Char('l') => app.open_log_popup(),
                                    KeyCode::Char('k') => app.open_secret_input(),
                                    KeyCode::Char('K') => app.remove_nvd_key(),
                                    KeyCode::Char('a') => app.open_review_settings(),
                                    _ => {}
                                },
                            }
                        }
                    }
                    Event::Mouse(mouse) => match mouse.kind {
                        MouseEventKind::ScrollUp => {
                            if app.log_popup_open {
                                app.log_popup_scroll_up();
                            } else if let Modal::Help { scroll } = &mut app.modal {
                                *scroll = scroll.saturating_sub(1);
                            } else if let Modal::ConfirmImpact { scroll, .. } = &mut app.modal {
                                *scroll = scroll.saturating_sub(1);
                            } else if !matches!(app.modal, Modal::None) {
                            } else if mouse.column >= detail_start_column {
                                app.detail_scroll_up();
                            } else {
                                app.scroll_up();
                            }
                        }
                        MouseEventKind::ScrollDown => {
                            if app.log_popup_open {
                                app.log_popup_scroll_down();
                            } else if let Modal::Help { scroll } = &mut app.modal {
                                *scroll = scroll.saturating_add(1);
                            } else if let Modal::ConfirmImpact { scroll, .. } = &mut app.modal {
                                *scroll = scroll.saturating_add(1);
                            } else if !matches!(app.modal, Modal::None) {
                            } else if mouse.column >= detail_start_column {
                                app.detail_scroll_down();
                            } else {
                                app.scroll_down();
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    finish_interactive_session(
        loop_result,
        || app.shutdown_review(),
        || {
            restore_terminal_steps(
                &mut terminal,
                |_| disable_raw_mode(),
                |terminal| {
                    execute!(
                        terminal.backend_mut(),
                        LeaveAlternateScreen,
                        DisableMouseCapture
                    )
                },
                |terminal| terminal.show_cursor(),
            )
        },
    )?;
    Ok(())
}

fn restore_terminal_steps<T>(
    target: &mut T,
    disable_raw: impl FnOnce(&mut T) -> io::Result<()>,
    leave_screen: impl FnOnce(&mut T) -> io::Result<()>,
    show_cursor: impl FnOnce(&mut T) -> io::Result<()>,
) -> io::Result<()> {
    let results = [
        disable_raw(target),
        leave_screen(target),
        show_cursor(target),
    ];
    let mut errors = Vec::new();
    let mut kind = io::ErrorKind::Other;
    for result in results {
        if let Err(error) = result {
            if errors.is_empty() {
                kind = error.kind();
            }
            errors.push(error.to_string());
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(kind, errors.join("; ")))
    }
}

fn finish_interactive_session(
    loop_result: io::Result<()>,
    shutdown: impl FnOnce() -> Result<(), String>,
    restore: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let shutdown_result = shutdown();
    let restore_result = restore();
    let mut errors = Vec::new();
    let mut kind = io::ErrorKind::Other;
    if let Err(error) = loop_result {
        kind = error.kind();
        errors.push(error.to_string());
    }
    if let Err(error) = shutdown_result {
        errors.push(error);
    }
    if let Err(error) = restore_result {
        if errors.is_empty() {
            kind = error.kind();
        }
        errors.push(error.to_string());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(kind, errors.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loop_error_still_cancels_and_restores_and_reports_all_errors() {
        let steps = std::cell::RefCell::new(Vec::new());
        let result = finish_interactive_session(
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic loop failure",
            )),
            || {
                steps.borrow_mut().push("shutdown");
                Err("synthetic cleanup failure".into())
            },
            || {
                steps.borrow_mut().push("restore");
                Err(io::Error::other("synthetic restore failure"))
            },
        )
        .unwrap_err();
        assert_eq!(*steps.borrow(), ["shutdown", "restore"]);
        assert_eq!(result.kind(), io::ErrorKind::BrokenPipe);
        assert!(result.to_string().contains("synthetic loop failure"));
        assert!(result.to_string().contains("synthetic cleanup failure"));
        assert!(result.to_string().contains("synthetic restore failure"));
    }

    #[test]
    fn normal_exit_reports_cleanup_failure_after_restoration() {
        let restored = std::cell::Cell::new(false);
        let result = finish_interactive_session(
            Ok(()),
            || Err("synthetic cleanup failure".into()),
            || {
                restored.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(restored.get());
        assert!(result.to_string().contains("synthetic cleanup failure"));
    }

    #[test]
    fn restoration_attempts_every_step_even_after_failures() {
        let mut steps = Vec::new();
        let error = restore_terminal_steps(
            &mut steps,
            |steps| {
                steps.push("raw");
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic raw failure",
                ))
            },
            |steps| {
                steps.push("screen");
                Err(io::Error::other("synthetic screen failure"))
            },
            |steps| {
                steps.push("cursor");
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(steps, ["raw", "screen", "cursor"]);
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(error.to_string().contains("synthetic raw failure"));
        assert!(error.to_string().contains("synthetic screen failure"));
    }
}
