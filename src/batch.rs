use crate::adapters::{check_all_outdated, check_global_outdated};
use crate::app::{get_upgrade_cmd, run_upgrade_process};
use crate::config::Config;
use crate::i18n::{t, tf};
use crate::models::{
    Dependency, Ecosystem, FreshnessInfo, PackageOrigin, ProvenanceInfo, VulnerabilityInfo,
};
use crate::review::{ReviewReport, ReviewVerdict};
use crate::rollback::{commit_backup, prepare_local_backup, restore_backup};
use crate::security::{check_provenance, SecurityChecker};
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
use ratatui::backend::CrosstermBackend;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame, Terminal,
};

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
    logs: Vec<String>,
}

enum BatchScreen {
    Scanning,
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
    Executing {
        items: Vec<BatchItem>,
        current_cursor: usize,
        progress_message: String,
    },
    Report {
        items: Vec<BatchItem>,
    },
}

struct BatchSecurityResult {
    vuln_result: Result<Vec<VulnerabilityInfo>, String>,
    freshness_info: FreshnessInfo,
    provenance_info: Option<ProvenanceInfo>,
}

enum BatchEvent {
    ScanFinished(Vec<Dependency>),
    SecurityChecked(usize, BatchSecurityResult),
    ReviewChecked(usize, ReviewReport),
    UpgradeFinished(usize, Result<(), String>),
    UpgradeLog(usize, String),
}

pub async fn run(
    target_dir: PathBuf,
    include_global: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        original_hook(panic_info);
    }));

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let config = Config::load_from_dir(&target_dir).await;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<BatchEvent>();

    let mut screen = BatchScreen::Scanning;

    let scan_tx = event_tx.clone();
    let scan_dir = target_dir.to_path_buf();
    tokio::spawn(async move {
        let mut all_dependencies = check_all_outdated(&scan_dir).await;
        if include_global {
            let global_deps = check_global_outdated().await;
            all_dependencies.extend(global_deps);
        }
        let _ = scan_tx.send(BatchEvent::ScanFinished(all_dependencies));
    });

    let mut running = true;
    let mut logs_popup_open = false;
    let mut logs_popup_tab = 0usize;
    let mut logs_popup_scroll_back = 0usize;

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
            render_batch(frame, &screen);
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
                BatchEvent::ScanFinished(all_deps) => {
                    let items: Vec<BatchItem> = all_deps
                        .into_iter()
                        .map(|dep| BatchItem {
                            dependency: dep,
                            selection: SelectionState::None,
                            vulns: None,
                            outcome: ItemOutcome::Pending,
                            logs: Vec::new(),
                        })
                        .collect();
                    screen = BatchScreen::Select {
                        items,
                        cursor: 0,
                        force_mode: false,
                    };
                }
                BatchEvent::SecurityChecked(index, security_result) => {
                    let is_done = process_security_checked(
                        &mut screen,
                        index,
                        security_result,
                        &config,
                        &target_dir,
                        &event_tx,
                    );
                    if is_done {
                        if let BatchScreen::Executing { items, .. } =
                            std::mem::replace(&mut screen, BatchScreen::Scanning)
                        {
                            screen = BatchScreen::Report { items };
                        }
                    }
                }
                BatchEvent::UpgradeFinished(index, result) => {
                    let is_done = process_upgrade_finished(&mut screen, index, result);
                    if is_done {
                        if let BatchScreen::Executing { items, .. } =
                            std::mem::replace(&mut screen, BatchScreen::Scanning)
                        {
                            screen = BatchScreen::Report { items };
                        }
                    }
                }
                BatchEvent::ReviewChecked(index, report) => {
                    let is_done =
                        process_review_checked(&mut screen, index, report, &target_dir, &event_tx);
                    if is_done {
                        if let BatchScreen::Executing { items, .. } =
                            std::mem::replace(&mut screen, BatchScreen::Scanning)
                        {
                            screen = BatchScreen::Report { items };
                        }
                    }
                }
                BatchEvent::UpgradeLog(index, line) => {
                    let mut is_first_line = false;
                    match &mut screen {
                        BatchScreen::Executing { items, .. } | BatchScreen::Report { items } => {
                            is_first_line = items[index].logs.is_empty();
                            items[index].logs.push(line);
                        }
                        _ => {}
                    }
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
                                logs_popup_scroll_back = logs_popup_scroll_back.saturating_sub(1)
                            }
                            KeyCode::Char('q') => running = false,
                            _ => {}
                        }
                    } else {
                        let opens_popup = matches!(
                            screen,
                            BatchScreen::Executing { .. } | BatchScreen::Report { .. }
                        ) && key_code == KeyCode::Char('l');
                        let was_executing = matches!(screen, BatchScreen::Executing { .. });
                        let previous_screen = std::mem::replace(&mut screen, BatchScreen::Scanning);
                        screen = handle_key_input(
                            previous_screen,
                            key_code,
                            &event_tx,
                            &config,
                            &target_dir,
                            include_global,
                            &mut running,
                        );
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

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn kick_off_security_checks(
    items: &[BatchItem],
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
    config: &Config,
) {
    for (index, item) in items.iter().enumerate() {
        if item.selection == SelectionState::None {
            continue;
        }
        let checker =
            SecurityChecker::new_with_config(config.osv_timeout_secs(), config.nvd_api_key());
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
                BatchSecurityResult {
                    vuln_result: result.map_err(|error| error.to_string()),
                    freshness_info,
                    provenance_info,
                },
            ));
        });
    }
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

fn vuln_count_label(count: usize) -> String {
    match count {
        0 => "✓".to_string(),
        n => n.to_string(),
    }
}

fn vuln_count_style(count: usize) -> Style {
    match count {
        0 => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        1..=2 => Style::default().fg(Color::Yellow),
        _ => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
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
        *progress_message = format!(
            "[BLOCKED] {} — AUR desabilitado por política",
            dependency.name
        );
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
        *progress_message = format!("[BLOCKED] {} — proveniência obrigatória", dependency.name);
        item.outcome = ItemOutcome::Blocked(t("blocked_provenance_required").to_string());
        *current_cursor = current_cursor.saturating_add(1);
        return *current_cursor >= items.len();
    }

    if config.block_too_fresh() && security_result.freshness_info.is_too_fresh() {
        *progress_message = format!("[BLOCKED] {} — versão muito recente", dependency.name);
        item.outcome = ItemOutcome::Blocked(t("blocked_too_fresh").to_string());
        *current_cursor = current_cursor.saturating_add(1);
        return *current_cursor >= items.len();
    }

    let result = match security_result.vuln_result {
        Ok(vulns) => {
            item.vulns = Some(vulns);
            Ok(())
        }
        Err(error_message) => {
            item.vulns = None;
            if config.require_online() {
                *progress_message = format!(
                    "[BLOCKED] {} — auditoria online obrigatória",
                    dependency.name
                );
                item.outcome =
                    ItemOutcome::Blocked(tf("blocked_online_required", &[&error_message]));
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

    // Source review gate: AUR PKGBUILDs and Homebrew formulae are reviewed
    // (residual diff + deterministic scan + LLM) before any upgrade spawns.
    if crate::review::needs_review(dependency) && config.pkgbuild_review() {
        *progress_message = tf("review_started", &[&dependency.name]);
        let review_tx = event_tx.clone();
        let review_dep = dependency.clone();
        let review_config = config.clone();
        tokio::spawn(async move {
            let report = crate::review::review_package(&review_dep, &review_config).await;
            let _ = review_tx.send(BatchEvent::ReviewChecked(index, report));
        });
        return false;
    }

    if !has_policy_issue {
        *progress_message = format!(
            "Upgrading {} to {}...",
            dependency.name, dependency.latest_version
        );
        spawn_upgrade(index, dependency, target_dir, event_tx);
        return false;
    }

    match item.selection {
        SelectionState::Force if !has_blocked_vulns => {
            item.outcome = ItemOutcome::ForceUpgraded;
            *progress_message = format!(
                "Upgrading {} to {}... (forçado)",
                dependency.name, dependency.latest_version
            );
            spawn_upgrade(index, dependency, target_dir, event_tx);
            false
        }
        _ => {
            item.outcome = if has_blocked_vulns {
                *progress_message = format!(
                    "[BLOCKED] {} — bloqueado por política de segurança",
                    dependency.name
                );
                ItemOutcome::Blocked(format!(
                    "{} vulnerabilidade(s) ativa(s)",
                    filtered_vulns.len()
                ))
            } else {
                *progress_message = format!(
                    "[SKIPPED] {} — vulnerável, sem força habilitada",
                    dependency.name
                );
                ItemOutcome::SkippedVulnerable(filtered_vulns)
            };
            *current_cursor = current_cursor.saturating_add(1);
            *current_cursor >= items.len()
        }
    }
}

fn process_upgrade_finished(
    screen: &mut BatchScreen,
    index: usize,
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

    let item = &mut items[index];
    match result {
        Ok(()) => {
            if let ItemOutcome::ForceUpgraded = &item.outcome {
                *progress_message = format!(
                    "[FORCED] {} — upgrade forçado concluído",
                    item.dependency.name
                );
            } else {
                item.outcome = ItemOutcome::Upgraded;
                *progress_message =
                    format!("[OK] {} — upgrade seguro concluído", item.dependency.name);
            }
        }
        Err(error_message) => {
            item.outcome = ItemOutcome::Failed(error_message.clone());
            *progress_message = format!("[FAILED] {} — {}", item.dependency.name, error_message);
        }
    }
    *current_cursor = current_cursor.saturating_add(1);
    *current_cursor >= items.len()
}

fn spawn_upgrade(
    index: usize,
    dependency: &Dependency,
    target_dir: &Path,
    event_tx: &mpsc::UnboundedSender<BatchEvent>,
) {
    let (command, args) = get_upgrade_cmd(dependency, target_dir);
    let (line_tx, mut line_rx) = mpsc::unbounded_channel::<String>();
    let log_event_tx = event_tx.clone();
    tokio::spawn(async move {
        while let Some(line) = line_rx.recv().await {
            let _ = log_event_tx.send(BatchEvent::UpgradeLog(index, line));
        }
    });
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
                    let _ = upgrade_tx.send(BatchEvent::UpgradeFinished(
                        index,
                        Err(format!("Failed to prepare rollback backup: {}", error)),
                    ));
                    return;
                }
            }
        };

        let upgrade_result = run_upgrade_process(&command, args, &target, Some(line_tx)).await;
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
                        Err(format!("{}\n\nRollback failed: {}", error, restore_error))
                    } else {
                        Err(error)
                    }
                } else {
                    Err(error)
                }
            }
        };
        let _ = upgrade_tx.send(BatchEvent::UpgradeFinished(index, upgrade_result));
    });
}

fn log_tab_indices(screen: &BatchScreen) -> Vec<usize> {
    match screen {
        BatchScreen::Executing { items, .. } => items
            .iter()
            .enumerate()
            .filter(|(_, item)| item.selection != SelectionState::None)
            .map(|(index, _)| index)
            .collect(),
        BatchScreen::Report { items } => items
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
        BatchScreen::Executing { items, .. } | BatchScreen::Report { items } => {
            items[index].dependency.name.clone()
        }
        _ => String::new(),
    }
}

fn batch_item_logs(screen: &BatchScreen, index: usize) -> &[String] {
    match screen {
        BatchScreen::Executing { items, .. } | BatchScreen::Report { items } => {
            items[index].logs.as_slice()
        }
        _ => &[],
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
        BatchScreen::Scanning => {
            if key_code == KeyCode::Char('q') {
                *running = false;
            }
            BatchScreen::Scanning
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
                let item = &mut updated_items[cursor];
                item.selection = match item.selection {
                    SelectionState::None => SelectionState::Safe,
                    SelectionState::Safe => SelectionState::Force,
                    SelectionState::Force => SelectionState::None,
                };
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
                        kick_off_security_checks(&items, event_tx, config);
                        BatchScreen::Executing {
                            items,
                            current_cursor: 0,
                            progress_message: String::new(),
                        }
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
            KeyCode::Enter => {
                kick_off_security_checks(&items, event_tx, config);
                BatchScreen::Executing {
                    items,
                    current_cursor: 0,
                    progress_message: String::new(),
                }
            }
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
        BatchScreen::Executing { .. } => {
            if key_code == KeyCode::Char('q') {
                *running = false;
            }
            previous_screen
        }
        BatchScreen::Report { items } => match key_code {
            KeyCode::Char('q') => {
                *running = false;
                BatchScreen::Report { items }
            }
            KeyCode::Char('r') => {
                let rescan_tx = event_tx.clone();
                let rescan_dir = target_dir.to_path_buf();
                tokio::spawn(async move {
                    let mut all_deps = check_all_outdated(&rescan_dir).await;
                    if include_global {
                        let global_deps = check_global_outdated().await;
                        all_deps.extend(global_deps);
                    }
                    let _ = rescan_tx.send(BatchEvent::ScanFinished(all_deps));
                });
                BatchScreen::Scanning
            }
            _ => BatchScreen::Report { items },
        },
    }
}

fn render_batch(frame: &mut Frame, screen: &BatchScreen) {
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
        " 🍵 TUCUPI :: Modo Interativo ",
        Style::default()
            .fg(Color::Yellow)
            .bg(Color::Rgb(30, 41, 59))
            .add_modifier(Modifier::BOLD),
    );
    let title_widget = Paragraph::new(title_span);
    frame.render_widget(title_widget, layout_chunks[0]);

    match screen {
        BatchScreen::Scanning => {
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

            let help_widget = Paragraph::new(" [Enter] Confirmar | [Esc] Cancelar | [q] Sair ")
                .style(Style::default().fg(Color::Black).bg(Color::Cyan));
            frame.render_widget(help_widget, layout_chunks[2]);
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
                    t("col_vulns"),
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

                let vuln_count = item.vulns.as_ref().map_or(0, |v| v.len());
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
                    progress_message,
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
                    ItemOutcome::Failed(error) => format!("Failed: {}", error),
                    ItemOutcome::Blocked(_vulns) => t("exec_blocked").to_string(),
                    ItemOutcome::SkippedVulnerable(_vulns) => t("exec_skipped").to_string(),
                };

                let vuln_count = item.vulns.as_ref().map_or(0, |v| v.len());
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

            let help_text = " [q] Sair | [l] Logs ";
            let help_widget =
                Paragraph::new(help_text).style(Style::default().fg(Color::Black).bg(Color::Cyan));
            frame.render_widget(help_widget, layout_chunks[2]);
        }

        BatchScreen::Report { items } => {
            let mut report_lines: Vec<Line> = Vec::new();

            report_lines.push(Line::from(Span::styled(
                " Relatório de Atualizações ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
            report_lines.push(Line::from(""));

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
                    format!(" ✓ ATUALIZADOS COM SEGURANÇA ({})", upgraded_items.len()),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )));
                for item in &upgraded_items {
                    let vuln_count = item.vulns.as_ref().map_or(0, |list| list.len());
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
                    format!(" ⚡ ATUALIZADOS COM FORÇA ({})", force_upgraded_items.len()),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )));
                for item in &force_upgraded_items {
                    let vuln_count = item.vulns.as_ref().map_or(0, |list| list.len());
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
                        Span::raw(format!("  {} vulns", vuln_count)),
                    ]));
                }
                report_lines.push(Line::from(""));
            }

            if !failed_items.is_empty() {
                report_lines.push(Line::from(Span::styled(
                    format!(" ✗ FALHARAM ({})", failed_items.len()),
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
                    format!(" ⊘ BLOQUEADOS POR SEGURANÇA ({})", blocked_items.len()),
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
                }
                report_lines.push(Line::from(""));
            }

            if !skipped_items.is_empty() {
                report_lines.push(Line::from(Span::styled(
                    format!(
                        " ⊘ PULADOS (VULNERÁVEIS, SEM FORÇA) ({})",
                        skipped_items.len()
                    ),
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )));
                for item in &skipped_items {
                    let vuln_count = item.vulns.as_ref().map_or(0, |list| list.len());
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
                        Span::raw(format!("  {} vulns", vuln_count)),
                    ]));
                }
                report_lines.push(Line::from(""));
            }

            let total_succeeded = upgraded_items.len() + force_upgraded_items.len();

            report_lines.push(Line::from(Span::styled(
                format!(
                    " Resumo: {} concluídos, {} falharam, {} bloqueados, {} pulados",
                    total_succeeded,
                    failed_items.len(),
                    blocked_items.len(),
                    skipped_items.len(),
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

            let help_text = " [q] Sair | [r] Re-escanear | [l] Logs ";
            let help_widget =
                Paragraph::new(help_text).style(Style::default().fg(Color::Black).bg(Color::Cyan));
            frame.render_widget(help_widget, layout_chunks[2]);
        }
    }
}

fn process_review_checked(
    screen: &mut BatchScreen,
    index: usize,
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

    let item = &mut items[index];
    let dependency = item.dependency.clone();

    match report.verdict {
        ReviewVerdict::Safe => {
            *progress_message = format!(
                "Upgrading {} to {}...",
                dependency.name, dependency.latest_version
            );
            spawn_upgrade(index, &dependency, target_dir, event_tx);
            false
        }
        ReviewVerdict::Block => {
            // Known IoCs and LLM-blocked sources are hard stops: selection
            // state never overrides a blocked package source.
            *progress_message = format!("[BLOCKED] {} — {}", dependency.name, report.reason);
            item.outcome = ItemOutcome::Blocked(tf("review_blocked", &[&report.reason]));
            *current_cursor = current_cursor.saturating_add(1);
            *current_cursor >= items.len()
        }
        ReviewVerdict::Review => {
            if item.selection == SelectionState::Force && !report.has_known_ioc() {
                item.outcome = ItemOutcome::ForceUpgraded;
                *progress_message = format!(
                    "Upgrading {} to {}... (forçado)",
                    dependency.name, dependency.latest_version
                );
                spawn_upgrade(index, &dependency, target_dir, event_tx);
                false
            } else {
                *progress_message = format!("[BLOCKED] {} — {}", dependency.name, report.reason);
                item.outcome =
                    ItemOutcome::Blocked(tf("review_needs_confirmation", &[&report.reason]));
                *current_cursor = current_cursor.saturating_add(1);
                *current_cursor >= items.len()
            }
        }
    }
}
