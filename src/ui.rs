use crate::app::{App, AppStatus, Modal, Tab, ToastKind};
use crate::i18n::{t, tf};
use crate::models::{Ecosystem, FreshnessInfo, VulnerabilityInfo};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
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

const NARROW_LAYOUT_THRESHOLD: u16 = 100;

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

    // Responsive: side-by-side on wide terminals, stacked when narrow.
    let body_chunks = if size.width >= NARROW_LAYOUT_THRESHOLD {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(chunks[2])
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[2])
    };

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

    let deps = app.current_deps().clone();
    let header_cells = vec![
        t("col_selection"),
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
        .enumerate()
        .map(|(index, dep)| {
            let color = eco_color(dep.ecosystem);
            let cache_key = format!(
                "{}_{}_{}",
                dep.ecosystem.as_str(),
                dep.name,
                dep.latest_version
            );
            let vuln_count = app.vuln_cache.get(&cache_key).and_then(|res| match res {
                Ok(vulns) => {
                    let count = vulns
                        .iter()
                        .filter(|v| !app.config.is_vulnerability_ignored(&v.id))
                        .count();
                    if count > 0 || dep.ecosystem.has_osv_coverage() {
                        Some(count)
                    } else {
                        None
                    }
                }
                Err(error) => {
                    let count = error
                        .findings
                        .iter()
                        .filter(|v| !app.config.is_vulnerability_ignored(&v.id))
                        .count();
                    if count > 0 {
                        Some(count)
                    } else {
                        None
                    }
                }
            });
            let vuln_label = if dep.ecosystem.has_osv_coverage()
                && app.batch_scan_pending > 0
                && !app.vuln_cache.contains_key(&cache_key)
            {
                "…".to_string()
            } else {
                match vuln_count {
                    None => "?".to_string(),
                    Some(0) => "✓".to_string(),
                    Some(count) => count.to_string(),
                }
            };

            Row::new(vec![
                Cell::from(app.selection_state(index).marker()),
                Cell::from(dep.ecosystem.as_str().to_string())
                    .style(Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Cell::from(dep.name.clone()),
                Cell::from(dep.current_version.clone()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(dep.latest_version.clone()).style(Style::default().fg(Color::Green)),
                Cell::from(vuln_label).style(vuln_count_style(vuln_count)),
            ])
        })
        .collect();

    let tab_title = format!(
        "{} {}",
        t("main_audit_unknown_legend"),
        tf(
            "table_title_selected",
            &[
                match app.active_tab {
                    Tab::Local => t("table_title_local"),
                    Tab::Global => t("table_title_global"),
                },
                &app.selected_count().to_string(),
            ],
        )
    );

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
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
                Constraint::Length(4),
                Constraint::Length(2),
                Constraint::Min(5),
            ])
            .split(detail_block.inner(body_chunks[1]));

        f.render_widget(detail_block, body_chunks[1]);

        let origin_text = dep.origin.map_or_else(
            || t("origin_unknown"),
            |origin| match origin {
                crate::models::PackageOrigin::OfficialRepo => t("origin_official"),
                crate::models::PackageOrigin::Aur => t("origin_aur"),
                crate::models::PackageOrigin::Unknown => t("origin_unknown"),
            },
        );
        let metadata_text = format!(
            "{}\n{}\n{}\n{}",
            tf("detail_package", &[&dep.name]),
            tf("detail_ecosystem", &[dep.ecosystem.as_str()]),
            tf("detail_origin", &[origin_text]),
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

        // Freshness
        if let Some(freshness) = app.freshness_cache.get(&cache_key) {
            match freshness {
                FreshnessInfo::VeryRecent(age) | FreshnessInfo::Recent(age) => {
                    vuln_section.push_str(&tf("freshness_warn", &[&age.to_string()]));
                    vuln_section.push('\n');
                }
                FreshnessInfo::Mature(age) => {
                    vuln_section.push_str(&tf("freshness_ok", &[&age.to_string()]));
                    vuln_section.push('\n');
                }
                FreshnessInfo::Unavailable => {}
            }
        }

        // Provenance
        if let Some(info) = app.provenance_cache.get(&cache_key) {
            vuln_section.push_str(t("provenance_title"));
            vuln_section.push('\n');
            if info.signature_verified {
                if let Some(ref validator) = info.validated_by {
                    vuln_section.push_str(&tf("provenance_signed", &[validator]));
                } else {
                    vuln_section.push_str(t("provenance_signed_unknown"));
                }
            } else {
                vuln_section.push_str(t("provenance_unsigned"));
            }
            if let Some(ref install_date) = info.install_date {
                vuln_section.push('\n');
                vuln_section.push_str(&tf("provenance_install_date", &[install_date]));
            }
            vuln_section.push_str("\n\n");
        }

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
                            let sources_tag = if vuln.sources.is_empty() {
                                String::new()
                            } else {
                                format!(" [src: {}]", vuln.sources.join(","))
                            };
                            vuln_section.push_str(&tf(
                                "vuln_item",
                                &[
                                    &format!("{}{}{}", vuln.id, sev_tag, sources_tag),
                                    &vuln.aliases.join(", "),
                                    &vuln.summary,
                                    &vuln.details,
                                ],
                            ));
                        }
                    }
                }
                Err(err_msg) => {
                    vuln_section.push_str(&tf("audit_failed", &[&err_msg.message]));
                    for vuln in &err_msg.findings {
                        if app.config.is_vulnerability_ignored(&vuln.id) {
                            continue;
                        }
                        has_active_vulns = true;
                        vuln_section.push_str(&tf(
                            "vuln_item",
                            &[
                                &vuln.id,
                                &vuln.aliases.join(", "),
                                &vuln.summary,
                                &vuln.details,
                            ],
                        ));
                    }
                }
            }
        } else if has_limited_audit {
            vuln_section.push_str(t("secure_limited"));
        } else if app.batch_scan_pending > 0 {
            vuln_section.push_str(t("security_scanning"));
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
        let detail_view_height = detail_chunks[2].height as usize;
        let detail_content_height = vuln_widget
            .line_count(detail_chunks[2].width.max(1))
            .max(detail_view_height);
        let detail_max_scroll = detail_content_height.saturating_sub(detail_view_height);
        let detail_offset = app.detail_scroll.min(detail_max_scroll as u16);
        let vuln_widget = vuln_widget.scroll((detail_offset, 0));
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
        _ => Style::default().fg(Color::Gray).bg(Color::Rgb(15, 23, 42)),
    };

    let status_text = match &app.status {
        AppStatus::Scanning => t("status_scanning").to_string(),
        AppStatus::Upgrading(msg) => tf("status_upgrading", &[msg]),
        _ => t("status_ready").to_string(),
    };

    let status_widget = Paragraph::new(status_text).style(status_style);
    f.render_widget(status_widget, chunks[3]);

    let help =
        Paragraph::new(t("help_hint")).style(Style::default().fg(Color::Black).bg(Color::Cyan));
    f.render_widget(help, chunks[4]);

    match &mut app.modal {
        Modal::ConfirmOffline(dep, error) => {
            let area = centered_rect(65, 60, size);
            f.render_widget(Clear, area);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .title(t("modal_offline_title"))
                .border_style(Style::default().fg(Color::Yellow));
            let text = tf("modal_offline_msg", &[&dep.name, error]);
            f.render_widget(
                Paragraph::new(text).block(block).wrap(Wrap { trim: true }),
                area,
            );
        }
        Modal::Help { scroll } => {
            let area = centered_rect(85, 85, size);
            f.render_widget(Clear, area);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(t("help_title"))
                .border_style(Style::default().fg(Color::Cyan));
            let inner = block.inner(area);
            let paragraph = Paragraph::new(t("help_commands"))
                .wrap(Wrap { trim: false })
                .style(Style::default().fg(Color::White));
            let max_scroll = paragraph
                .line_count(inner.width.max(1))
                .saturating_sub(inner.height as usize);
            *scroll = (*scroll as usize).min(max_scroll).min(u16::MAX as usize) as u16;
            f.render_widget(block, area);
            f.render_widget(paragraph.scroll((*scroll, 0)), inner);
        }
        Modal::ConfirmReview(dep, report) => {
            let area = centered_rect(65, 60, size);
            f.render_widget(Clear, area);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .title(t("modal_review_title"))
                .border_style(Style::default().fg(Color::Yellow));
            let reason = crate::review::display_review_reason(&report.reason);
            let text = tf("modal_review_msg", &[&dep.name, &reason]);
            f.render_widget(
                Paragraph::new(text).block(block).wrap(Wrap { trim: true }),
                area,
            );
        }
        Modal::ConfirmImpact {
            dep,
            preview,
            scroll,
        } => {
            let area = centered_rect(85, 85, size);
            f.render_widget(Clear, area);
            let block = Block::default()
                .borders(Borders::ALL)
                .title(t("impact_title"));
            let inner = block.inner(area);
            f.render_widget(block, area);
            let parts = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(1)])
                .split(inner);
            let mut text = tf("impact_warning", &[&dep.name]);
            if let crate::impact::ImpactPreview::ManagerOutput {
                text: output,
                truncated,
            } = preview
            {
                text.push_str(t("impact_manager_output"));
                if *truncated {
                    text.push_str(t("impact_truncated"));
                    text.push_str("\n\n");
                }
                text.push_str(output);
            } else {
                text.push_str(t("impact_unavailable"));
            }
            let paragraph = Paragraph::new(text).wrap(Wrap { trim: false });
            let max = paragraph
                .line_count(parts[0].width.max(1))
                .saturating_sub(parts[0].height as usize);
            *scroll = (*scroll as usize).min(max).min(u16::MAX as usize) as u16;
            f.render_widget(paragraph.scroll((*scroll, 0)), parts[0]);
            f.render_widget(Paragraph::new(t("impact_footer")), parts[1]);
        }
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
        Modal::BlockedPolicy(_dep, message) => {
            let area = centered_rect(65, 50, size);
            f.render_widget(Clear, area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .title(t("modal_policy_title"))
                .border_style(Style::default().fg(Color::Red));

            let mut text = message.clone();
            text.push_str(t("modal_policy_footer"));

            let paragraph = Paragraph::new(text)
                .block(block)
                .style(Style::default().fg(Color::White))
                .wrap(Wrap { trim: true });

            f.render_widget(paragraph, area);
        }
        Modal::ConfirmGlobal(_dep, command_preview) => {
            let area = centered_rect(65, 50, size);
            f.render_widget(Clear, area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .title(t("modal_global_title"))
                .border_style(Style::default().fg(Color::Yellow));

            let text = tf("modal_global_msg", &[command_preview]);

            let paragraph = Paragraph::new(text)
                .block(block)
                .style(Style::default().fg(Color::White))
                .wrap(Wrap { trim: true });

            f.render_widget(paragraph, area);
        }
        Modal::SecretInput { buffer } => {
            let area = centered_rect(50, 20, size);
            f.render_widget(Clear, area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .title(t("secret_input_title"))
                .border_style(Style::default().fg(Color::Yellow));

            let masked = crate::secrets::mask_secret(buffer);
            let text = format!("{}_\n\n{}", masked, t("secret_input_help"));

            let paragraph = Paragraph::new(text)
                .block(block)
                .style(Style::default().fg(Color::White))
                .wrap(Wrap { trim: true });

            f.render_widget(paragraph, area);
        }
        Modal::ReviewSettings {
            provider,
            model,
            input,
        } => {
            let area = centered_rect(75, 45, size);
            f.render_widget(Clear, area);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .title(t("review_settings_title"))
                .border_style(Style::default().fg(Color::Yellow));
            let current = match input {
                crate::app::ReviewSettingsInput::Menu => t("review_settings_menu").to_string(),
                crate::app::ReviewSettingsInput::Model(value) => {
                    format!("{} {}_", t("review_settings_model_input"), value)
                }
                crate::app::ReviewSettingsInput::Key(value) => format!(
                    "{} {}_",
                    t("review_settings_key_input"),
                    crate::secrets::mask_secret(value)
                ),
            };
            let text = format!(
                "{}: {}\n{}: {}\n\n{}\n\n{}",
                t("review_settings_provider"),
                provider.id(),
                t("review_settings_model"),
                model,
                current,
                t("review_settings_warning")
            );
            f.render_widget(
                Paragraph::new(text)
                    .block(block)
                    .style(Style::default().fg(Color::White))
                    .wrap(Wrap { trim: true }),
                area,
            );
        }
        Modal::None => {}
    }

    if app.log_popup_open {
        let tab_names: Vec<String> = app
            .upgrade_logs
            .iter()
            .map(|log| log.name.clone())
            .collect();
        let active_lines: &[String] = app
            .upgrade_logs
            .get(app.log_popup_tab)
            .map_or(&[], |log| log.lines.as_slice());
        render_log_popup(
            f,
            size,
            &tab_names,
            app.log_popup_tab,
            active_lines,
            app.log_popup_scroll_back,
        );
    }

    render_toasts(f, app, size);
}

pub fn render_log_popup(
    f: &mut Frame,
    area: Rect,
    tab_names: &[String],
    active_tab: usize,
    lines: &[String],
    scroll_back: usize,
) {
    let popup_area = centered_rect(80, 70, area);
    f.render_widget(Clear, popup_area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(t("logs_title"))
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(popup_area);
    f.render_widget(block, popup_area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);

    let mut tab_spans: Vec<Span> = Vec::new();
    if tab_names.is_empty() {
        tab_spans.push(Span::styled(
            t("logs_empty"),
            Style::default().fg(Color::DarkGray),
        ));
    } else {
        for (index, name) in tab_names.iter().enumerate() {
            let tab_style = if index == active_tab {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            tab_spans.push(Span::styled(format!(" {} ", name), tab_style));
            if index + 1 < tab_names.len() {
                tab_spans.push(Span::styled("│", Style::default().fg(Color::DarkGray)));
            }
        }
    }
    f.render_widget(Paragraph::new(Line::from(tab_spans)), rows[0]);

    let view_height = rows[1].height as usize;
    let log_lines: Vec<Line> = lines.iter().map(|line| Line::from(line.clone())).collect();
    let logs_paragraph = Paragraph::new(log_lines)
        .style(Style::default().fg(Color::Gray))
        .wrap(Wrap { trim: false });
    let content_height = logs_paragraph
        .line_count(rows[1].width.max(1))
        .max(view_height);
    let bottom_offset = content_height.saturating_sub(view_height);
    let scroll_offset = bottom_offset.saturating_sub(scroll_back);
    let logs_paragraph = logs_paragraph.scroll((scroll_offset as u16, 0));
    f.render_widget(logs_paragraph, rows[1]);

    let help =
        Paragraph::new(t("logs_help")).style(Style::default().fg(Color::Black).bg(Color::Cyan));
    f.render_widget(help, rows[2]);
}

fn render_toasts(f: &mut Frame, app: &App, area: Rect) {
    let visible_toasts: Vec<&crate::app::Toast> = app.toasts.iter().rev().take(4).collect();
    let mut next_y = area.y.saturating_add(1);

    for toast in visible_toasts {
        let max_width = area.width.saturating_sub(4).clamp(24, 64);
        let text_width = toast.message.chars().count() as u16;
        let width = (text_width + 4)
            .clamp(24, max_width)
            .min(area.width.saturating_sub(2).max(10));
        let inner_width = width.saturating_sub(2).max(1);
        let paragraph = Paragraph::new(toast.message.clone()).wrap(Wrap { trim: false });
        let text_lines = paragraph.line_count(inner_width).max(1) as u16;
        let height = text_lines.saturating_add(2);

        if next_y.saturating_add(height) > area.height {
            break;
        }

        let x = area.width.saturating_sub(width.saturating_add(1));
        let toast_area = Rect::new(x, next_y, width, height);
        let border_color = match toast.kind {
            ToastKind::Success => Color::Green,
            ToastKind::Error => Color::Red,
            ToastKind::Info => Color::Cyan,
        };

        f.render_widget(Clear, toast_area);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(
                Style::default()
                    .fg(border_color)
                    .add_modifier(Modifier::BOLD),
            );
        let paragraph = paragraph
            .block(block)
            .style(Style::default().fg(Color::White));
        f.render_widget(paragraph, toast_area);

        next_y = next_y.saturating_add(height);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn review_settings_masks_key_in_rendered_terminal() {
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        let mut app = App::new(std::path::PathBuf::from("."), false);
        app.open_review_settings();
        app.review_settings_begin_input(true);
        for character in "synthetic-private-key".chars() {
            app.review_settings_input_char(Some(character));
        }
        terminal.draw(|frame| render(frame, &mut app)).unwrap();
        let buffer = terminal.backend().buffer();
        let text = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<String>();
        assert!(!text.contains("synthetic-private-key"));
        assert!(text.contains('•'));
    }

    #[test]
    fn main_audit_messages_follow_locale() {
        if let Ok(language) = std::env::var("TUCUPI_MAIN_TEST_LANGUAGE") {
            let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
            let mut app = App::new(std::path::PathBuf::from("."), false);
            let dep = crate::models::Dependency {
                name: "example".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            app.local_deps.push(dep.clone());
            app.batch_scan_pending = 1;
            terminal.draw(|frame| render(frame, &mut app)).unwrap();
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
                    "Auditando segurança"
                } else {
                    "Scanning security"
                }),
                "{text}"
            );
            app.local_deps[0].ecosystem = Ecosystem::Mise;
            terminal.draw(|frame| render(frame, &mut app)).unwrap();
            let buffer = terminal.backend().buffer();
            let rows: Vec<String> = (0..buffer.area.height)
                .map(|y| {
                    (0..buffer.area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect()
                })
                .collect();
            let row = rows
                .iter()
                .find(|row| row.contains("example") && row.contains("mise"))
                .unwrap();
            assert!(row.contains('?'), "{row}");
            assert!(
                rows.iter().any(|row| row.contains(if language == "pt" {
                    "Auditoria indisponível"
                } else {
                    "Security audit unavailable"
                })),
                "{rows:?}"
            );
            app.local_deps[0].ecosystem = Ecosystem::Cargo;
            app.batch_scan_pending = 0;
            let key = "Cargo_example_2".to_string();
            for (result, expected) in [
                (None, "?"),
                (Some(Err("offline".into())), "?"),
                (Some(Ok(Vec::new())), "✓"),
            ] {
                app.vuln_cache.remove(&key);
                if let Some(result) = result {
                    app.vuln_cache.insert(key.clone(), result);
                }
                terminal.draw(|frame| render(frame, &mut app)).unwrap();
                let buffer = terminal.backend().buffer();
                let rows: Vec<String> = (0..buffer.area.height)
                    .map(|y| {
                        (0..buffer.area.width)
                            .map(|x| buffer[(x, y)].symbol())
                            .collect()
                    })
                    .collect();
                let row = rows
                    .iter()
                    .find(|row| row.contains("example") && row.contains("Cargo"))
                    .unwrap();
                assert!(row.contains(expected), "{row}");
                assert!(
                    rows.iter().any(|row| row.contains(if language == "pt" {
                        "? = auditoria indisponível"
                    } else {
                        "? = audit unavailable"
                    })),
                    "{rows:?}"
                );
            }
            app.config.security.require_online = Some(false);
            app.process_security_result(dep.clone(), Err("network error".into()), false);
            assert!(matches!(app.modal, Modal::ConfirmOffline(_, _)));
            terminal.draw(|frame| render(frame, &mut app)).unwrap();
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
                    "AUDITORIA ONLINE INDISPONÍVEL"
                } else {
                    "ONLINE AUDIT UNAVAILABLE"
                }),
                "{text}"
            );
            assert!(!text.contains("OFFLINE_WARNING"), "{text}");
            let vulnerability = VulnerabilityInfo {
                id: "TEST-1".into(),
                summary: "external explanation".into(),
                details: String::new(),
                aliases: Vec::new(),
                severity: None,
                score: None,
                sources: Vec::new(),
            };
            app.modal = Modal::None;
            app.vuln_cache.insert(
                "Cargo_example_2".into(),
                Err(crate::security::AuditFailure {
                    message: "OSV offline".into(),
                    findings: vec![vulnerability.clone()],
                    partial: true,
                }),
            );
            terminal.draw(|frame| render(frame, &mut app)).unwrap();
            let buffer = terminal.backend().buffer();
            let text = (0..buffer.area.height)
                .map(|y| {
                    (0..buffer.area.width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(text.contains("TEST-1"), "{text}");
            assert!(
                text.contains(if language == "pt" {
                    "Falha na auditoria"
                } else {
                    "Security audit failed"
                }),
                "{text}"
            );
            app.modal = Modal::Blocked(dep.clone(), vec![vulnerability.clone()]);
            terminal.draw(|frame| render(frame, &mut app)).unwrap();
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
                    "ATUALIZAÇÃO BLOQUEADA"
                } else {
                    "UPGRADE BLOCKED"
                }),
                "{text}"
            );
            if language == "pt" {
                assert!(!text.to_lowercase().contains("upgrades"), "{text}");
            }
            assert!(
                text.contains(if language == "pt" {
                    "Resumo original:"
                } else {
                    "Original summary:"
                }),
                "{text}"
            );
            app.modal = Modal::ConfirmForce(dep.clone(), vec![vulnerability]);
            terminal.draw(|frame| render(frame, &mut app)).unwrap();
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
                    "Resumo original:"
                } else {
                    "Original summary:"
                }),
                "{text}"
            );
            app.modal = Modal::ConfirmReview(
                dep.clone(),
                crate::review::ReviewReport {
                    verdict: crate::review::ReviewVerdict::Review,
                    reason: "deterministic scan only (LLM review disabled)".into(),
                    view_mode: crate::review::ReviewViewMode::Diff,
                    residual_line_count: 1,
                    hits: Vec::new(),
                    origin: crate::review::ReviewOrigin::Unknown,
                },
            );
            terminal.draw(|frame| render(frame, &mut app)).unwrap();
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
                    "verificação determinística"
                } else {
                    "Deterministic scan only"
                }),
                "{text}"
            );
            if let Modal::ConfirmReview(_, report) = &mut app.modal {
                report.reason = "provider isolation not verified — treat as unreviewed".into();
            }
            terminal.draw(|frame| render(frame, &mut app)).unwrap();
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
                    "O provedor não foi iniciado"
                } else {
                    "The provider was not started"
                }),
                "{text}"
            );
            assert!(
                crate::review::display_review_reason("brew info failed for example").contains(
                    if language == "pt" {
                        "Não foi possível consultar"
                    } else {
                        "Could not query"
                    }
                )
            );
            assert!(
                crate::review::display_review_reason("model explanation").contains(
                    if language == "pt" {
                        "Detalhe original"
                    } else {
                        "Original detail"
                    }
                )
            );
            assert_eq!(
                crate::review::ReviewVerdict::Block.display_label(),
                if language == "pt" {
                    "bloqueado"
                } else {
                    "blocked"
                }
            );
            assert!(
                crate::i18n::tf("backup_prepare_failed", &["sample"]).contains(
                    if language == "pt" {
                        "Falha ao preparar"
                    } else {
                        "Failed to prepare"
                    }
                )
            );
            app.modal = Modal::ConfirmImpact {
                dep,
                preview: crate::impact::ImpactPreview::ManagerOutput {
                    text: "package\n".repeat(3000),
                    truncated: true,
                },
                scroll: 0,
            };
            terminal.draw(|frame| render(frame, &mut app)).unwrap();
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
                text.contains(if language == "pt" {
                    "Continuar"
                } else {
                    "Continue"
                }),
                "{text}"
            );
            return;
        }
        for (language, locale) in [("pt", "pt_BR.UTF-8"), ("en", "en_US.UTF-8")] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "ui::tests::main_audit_messages_follow_locale"])
                .env("TUCUPI_MAIN_TEST_LANGUAGE", language)
                .env("LC_ALL", locale)
                .status()
                .unwrap();
            assert!(status.success(), "locale {locale} failed");
        }
    }

    #[test]
    fn help_panel_scrolls_to_last_command_on_small_terminal() {
        let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
        let mut app = App::new(std::path::PathBuf::from("."), false);
        app.modal = Modal::Help { scroll: u16::MAX };
        terminal.draw(|frame| render(frame, &mut app)).unwrap();
        let buffer = terminal.backend().buffer();
        let text: String = (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Esc"), "{text}");
        assert!(text.contains("mouse"), "{text}");
    }
}
