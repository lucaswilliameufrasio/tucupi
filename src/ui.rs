use crate::app::{App, AppStatus, Modal, Tab};
use crate::i18n::{t, tf};
use crate::models::{Ecosystem, VulnerabilityInfo};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};

fn eco_color(ecosystem: Ecosystem) -> Color {
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

fn vuln_count_style(count: usize) -> Style {
    match count {
        0 => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        1..=2 => Style::default().fg(Color::Yellow),
        _ => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

fn severity_label(severity: Option<&str>) -> String {
    match severity {
        Some(s) => match s.to_uppercase().as_str() {
            "CRITICAL" => t("severity_critical").to_string(),
            "HIGH" => t("severity_high").to_string(),
            "MEDIUM" => t("severity_medium").to_string(),
            "LOW" => t("severity_low").to_string(),
            _ => s.to_string(),
        },
        None => String::new(),
    }
}

pub fn render(f: &mut Frame, app: &mut App) {
    let size = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Min(5),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(size);

    let title = Paragraph::new(t("title")).style(
        Style::default()
            .fg(Color::Yellow)
            .bg(Color::Rgb(30, 41, 59))
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(title, chunks[0]);

    let tab_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let local_span = ratatui::text::Span::styled(
        tf("tab_local", &[&app.local_deps.len().to_string()]),
        if app.active_tab == Tab::Local {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray).bg(Color::Rgb(51, 65, 85))
        },
    );

    let global_span = ratatui::text::Span::styled(
        tf("tab_global", &[&app.global_deps.len().to_string()]),
        if app.active_tab == Tab::Global {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray).bg(Color::Rgb(51, 65, 85))
        },
    );

    let tabs_line = ratatui::text::Line::from(vec![
        local_span,
        ratatui::text::Span::raw(" | "),
        global_span,
    ]);

    let tabs = Paragraph::new(tabs_line)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default().bg(Color::Rgb(15, 23, 42)));
    f.render_widget(tabs, tab_chunks[0]);

    let dir_text = tf("dir_repo", &[&app.target_dir.to_string_lossy()]);
    let dir = Paragraph::new(dir_text)
        .alignment(ratatui::layout::Alignment::Right)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(
            Style::default()
                .fg(Color::Yellow)
                .bg(Color::Rgb(15, 23, 42)),
        );
    f.render_widget(dir, tab_chunks[1]);

    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[2]);

    let deps = app.current_deps().clone();
    let header_cells = vec![
        t("col_ecosystem"),
        t("col_package"),
        t("col_current"),
        t("col_latest"),
        t("col_vulns"),
    ];
    let header = Row::new(header_cells)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .height(1);

    let rows: Vec<Row> = deps
        .iter()
        .map(|dep| {
            let color = eco_color(dep.ecosystem);
            let cache_key = format!(
                "{}_{}_{}",
                dep.ecosystem.as_str(),
                dep.name,
                dep.latest_version
            );
            let vuln_count = app.vuln_cache.get(&cache_key).map_or(0, |res| match res {
                Ok(vulns) => vulns
                    .iter()
                    .filter(|v| !app.config.is_vulnerability_ignored(&v.id))
                    .count(),
                Err(_) => 0,
            });
            let vuln_label =
                if app.batch_scan_pending > 0 && !app.vuln_cache.contains_key(&cache_key) {
                    "…".to_string()
                } else if vuln_count > 0 {
                    vuln_count.to_string()
                } else if dep.ecosystem.has_osv_coverage() {
                    "✓".to_string()
                } else {
                    "-".to_string()
                };

            Row::new(vec![
                Cell::from(dep.ecosystem.as_str().to_string())
                    .style(Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Cell::from(dep.name.clone()),
                Cell::from(dep.current_version.clone()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(dep.latest_version.clone()).style(Style::default().fg(Color::Green)),
                Cell::from(vuln_label).style(vuln_count_style(vuln_count)),
            ])
        })
        .collect();

    let tab_title = match app.active_tab {
        Tab::Local => t("table_title_local"),
        Tab::Global => t("table_title_global"),
    };

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(20),
            Constraint::Percentage(35),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(tab_title)
            .border_style(Style::default().fg(Color::Cyan)),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::Rgb(30, 41, 59))
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(" ➜ ");

    f.render_stateful_widget(table, body_chunks[0], &mut app.table_state);

    let detail_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(t("detail_title"))
        .border_style(Style::default().fg(Color::Cyan));

    if let Some(dep) = app.selected_dep() {
        let cache_key = format!(
            "{}_{}_{}",
            dep.ecosystem.as_str(),
            dep.name,
            dep.latest_version
        );
        let detail_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(2),
                Constraint::Min(5),
            ])
            .split(detail_block.inner(body_chunks[1]));

        f.render_widget(detail_block, body_chunks[1]);

        let metadata_text = format!(
            "{}\n{}\n{}",
            tf("detail_package", &[&dep.name]),
            tf("detail_ecosystem", &[dep.ecosystem.as_str()]),
            tf(
                "detail_version",
                &[&dep.current_version, &dep.latest_version]
            ),
        );
        let metadata = Paragraph::new(metadata_text).style(Style::default().fg(Color::White));
        f.render_widget(metadata, detail_chunks[0]);

        let upgrade_brief = match &app.status {
            AppStatus::Upgrading(msg) if msg.contains(&dep.name) => t("upgrade_in_progress"),
            AppStatus::UpgradeSuccess(ref name) if name == &dep.name => t("upgrade_success"),
            AppStatus::UpgradeFailed(ref name, _) if name == &dep.name => t("upgrade_failed"),
            _ => t("upgrade_none"),
        };
        let status_style = match &app.status {
            AppStatus::Upgrading(_) => Style::default().fg(Color::Cyan),
            AppStatus::UpgradeSuccess(_) => Style::default().fg(Color::Green),
            AppStatus::UpgradeFailed(_, _) => Style::default().fg(Color::Red),
            _ => Style::default().fg(Color::DarkGray),
        };
        let upgrade_brief_widget = Paragraph::new(upgrade_brief).style(status_style);
        f.render_widget(upgrade_brief_widget, detail_chunks[1]);

        let mut vuln_section = String::new();

        if let AppStatus::UpgradeFailed(ref name, ref err) = &app.status {
            if name == &dep.name {
                vuln_section.push_str(&tf("error_details", &[err]));
            }
        }

        let has_limited_audit = !dep.ecosystem.has_osv_coverage();
        let mut has_active_vulns = false;

        if let Some(cached_res) = app.vuln_cache.get(&cache_key) {
            match cached_res {
                Ok(vulns) => {
                    let active_vulns: Vec<&VulnerabilityInfo> = vulns
                        .iter()
                        .filter(|v| !app.config.is_vulnerability_ignored(&v.id))
                        .collect();

                    if active_vulns.is_empty() {
                        if has_limited_audit {
                            vuln_section.push_str(t("secure_limited"));
                        } else {
                            vuln_section.push_str(t("secure_msg"));
                        }
                    } else {
                        has_active_vulns = true;
                        vuln_section
                            .push_str(&tf("vuln_warning", &[&active_vulns.len().to_string()]));
                        for vuln in active_vulns {
                            let sev = severity_label(vuln.severity.as_deref());
                            let score_str =
                                vuln.score.map(|s| format!("{:.1}", s)).unwrap_or_default();
                            let sev_tag = if !sev.is_empty() {
                                format!(" [{}]", sev)
                            } else if !score_str.is_empty() {
                                format!(" [CVSS: {}]", score_str)
                            } else {
                                String::new()
                            };
                            vuln_section.push_str(&tf(
                                "vuln_item",
                                &[
                                    &format!("{}{}", vuln.id, sev_tag),
                                    &vuln.aliases.join(", "),
                                    &vuln.summary,
                                    &vuln.details,
                                ],
                            ));
                        }
                    }
                }
                Err(err_msg) => {
                    vuln_section.push_str(&tf("audit_failed", &[err_msg]));
                }
            }
        } else if app.batch_scan_pending > 0 {
            vuln_section.push_str(" ⏳ Scanning security...");
        } else {
            vuln_section.push_str(t("select_prompt"));
        }

        let vuln_style = if has_active_vulns || has_limited_audit {
            Style::default().fg(Color::Yellow)
        } else if matches!(&app.status, AppStatus::UpgradeFailed(ref n, _) if n == &dep.name) {
            Style::default().fg(Color::LightRed)
        } else if !vuln_section.contains("⬚")
            && (vuln_section.contains("✓") || vuln_section.contains("SECURE"))
        {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let vuln_widget = Paragraph::new(vuln_section)
            .style(vuln_style)
            .wrap(Wrap { trim: true });
        f.render_widget(vuln_widget, detail_chunks[2]);
    } else {
        let no_selection =
            Paragraph::new(t("no_selection")).style(Style::default().fg(Color::DarkGray));
        let inner_area = detail_block.inner(body_chunks[1]);
        f.render_widget(detail_block, body_chunks[1]);
        f.render_widget(no_selection, inner_area);
    }

    let status_style = match app.status {
        AppStatus::Scanning => Style::default()
            .fg(Color::Yellow)
            .bg(Color::Rgb(30, 41, 59)),
        AppStatus::Upgrading(_) => Style::default().fg(Color::Cyan).bg(Color::Rgb(30, 41, 59)),
        AppStatus::UpgradeSuccess(_) => {
            Style::default().fg(Color::Green).bg(Color::Rgb(30, 41, 59))
        }
        AppStatus::UpgradeFailed(_, _) => {
            Style::default().fg(Color::Red).bg(Color::Rgb(30, 41, 59))
        }
        AppStatus::Ready => Style::default().fg(Color::Gray).bg(Color::Rgb(15, 23, 42)),
    };

    let status_text = match &app.status {
        AppStatus::Scanning => t("status_scanning").to_string(),
        AppStatus::Upgrading(msg) => tf("status_upgrading", &[msg]),
        AppStatus::UpgradeSuccess(pkg) => tf("status_success", &[pkg]),
        AppStatus::UpgradeFailed(pkg, err) => tf("status_failed", &[pkg, err]),
        AppStatus::Ready => t("status_ready").to_string(),
    };

    let status_widget = Paragraph::new(status_text).style(status_style);
    f.render_widget(status_widget, chunks[3]);

    let help =
        Paragraph::new(t("help_tui")).style(Style::default().fg(Color::Black).bg(Color::Cyan));
    f.render_widget(help, chunks[4]);

    match &app.modal {
        Modal::ConfirmForce(dep, vulns) => {
            let area = centered_rect(65, 60, size);
            f.render_widget(Clear, area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .title(t("modal_force_title"))
                .border_style(Style::default().fg(Color::Yellow));

            let mut text = tf("modal_force_msg", &[&dep.name, &dep.latest_version]);
            for vuln in vulns {
                text.push_str(&tf("modal_force_item", &[&vuln.id, &vuln.summary]));
            }
            text.push_str(t("modal_force_footer"));

            let paragraph = Paragraph::new(text)
                .block(block)
                .style(Style::default().fg(Color::White))
                .wrap(Wrap { trim: true });

            f.render_widget(paragraph, area);
        }
        Modal::Blocked(dep, vulns) => {
            let area = centered_rect(65, 60, size);
            f.render_widget(Clear, area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .title(t("modal_blocked_title"))
                .border_style(Style::default().fg(Color::Red));

            let mut text = tf("modal_blocked_msg", &[&dep.name, &dep.latest_version]);
            for vuln in vulns {
                text.push_str(&tf("modal_blocked_item", &[&vuln.id, &vuln.summary]));
            }
            text.push_str(t("modal_blocked_footer"));

            let paragraph = Paragraph::new(text)
                .block(block)
                .style(Style::default().fg(Color::White))
                .wrap(Wrap { trim: true });

            f.render_widget(paragraph, area);
        }
        Modal::None => {}
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
