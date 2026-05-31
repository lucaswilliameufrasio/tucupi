use crate::app::{App, AppStatus, Modal, Tab};
use crate::models::{Ecosystem, VulnerabilityInfo};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};

pub fn render(f: &mut Frame, app: &mut App) {
    let size = f.area();

    // Main layout: Title (1), Tabs/Header (1), Workspace details (1), Body (split), Footer (1)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Title Banner
            Constraint::Length(2), // Tabs / Target Dir
            Constraint::Min(5),    // Body
            Constraint::Length(1), // Status Bar
            Constraint::Length(1), // Help Bar
        ])
        .split(size);

    // 1. Render Title Banner
    let title_text = format!(" 🍵 TUCUPI :: Concurrent Dependency Guard & Upgrader ");
    let title = Paragraph::new(title_text)
        .style(Style::default().fg(Color::Yellow).bg(Color::Rgb(30, 41, 59)).add_modifier(Modifier::BOLD));
    f.render_widget(title, chunks[0]);

    // 2. Render Tabs and Target Directory
    let tab_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let local_span = ratatui::text::Span::styled(
        format!(" [1] Local Project ({}) ", app.local_deps.len()),
        if app.active_tab == Tab::Local {
            Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray).bg(Color::Rgb(51, 65, 85))
        }
    );

    let global_span = ratatui::text::Span::styled(
        format!(" [2] Global Packages ({}) ", app.global_deps.len()),
        if app.active_tab == Tab::Global {
            Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray).bg(Color::Rgb(51, 65, 85))
        }
    );

    let tabs_line = ratatui::text::Line::from(vec![
        local_span,
        ratatui::text::Span::raw(" | "),
        global_span,
    ]);

    let tabs = Paragraph::new(tabs_line)
        .block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(Color::Cyan)))
        .style(Style::default().bg(Color::Rgb(15, 23, 42)));
    f.render_widget(tabs, tab_chunks[0]);

    let dir_text = format!(" Repositório: {} ", app.target_dir.to_string_lossy());
    let dir = Paragraph::new(dir_text)
        .alignment(ratatui::layout::Alignment::Right)
        .block(Block::default().borders(Borders::BOTTOM).border_style(Style::default().fg(Color::Cyan)))
        .style(Style::default().fg(Color::Yellow).bg(Color::Rgb(15, 23, 42)));
    f.render_widget(dir, tab_chunks[1]);

    // 3. Render Body (split table on left, details on right)
    let body_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(chunks[2]);

    // Left Panel: Table of Outdated Dependencies
    let deps = app.current_deps().clone();
    let header_cells = vec!["Ecossistema", "Pacote", "Atual", "Mais Recente"];
    let header = Row::new(header_cells)
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .height(1);

    let rows: Vec<Row> = deps.iter().map(|dep| {
        let eco_color = match dep.ecosystem {
            Ecosystem::Cargo => Color::Red,
            Ecosystem::Go => Color::Green,
            Ecosystem::Dart => Color::Blue,
            Ecosystem::Elixir => Color::Magenta,
            Ecosystem::Npm => Color::Yellow,
        };
        Row::new(vec![
            Cell::from(dep.ecosystem.as_str().to_string()).style(Style::default().fg(eco_color).add_modifier(Modifier::BOLD)),
            Cell::from(dep.name.clone()),
            Cell::from(dep.current_version.clone()).style(Style::default().fg(Color::DarkGray)),
            Cell::from(dep.latest_version.clone()).style(Style::default().fg(Color::Green)),
        ])
    }).collect();

    let tab_title = match app.active_tab {
        Tab::Local => " Dependências Desatualizadas no Repositório ",
        Tab::Global => " Dependências Globais do Sistema ",
    };

    let table = Table::new(rows, [
        Constraint::Percentage(25),
        Constraint::Percentage(45),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).title(tab_title).border_style(Style::default().fg(Color::Cyan)))
    .row_highlight_style(Style::default().bg(Color::Rgb(30, 41, 59)).add_modifier(Modifier::BOLD))
    .highlight_symbol(" ➜ ");

    f.render_stateful_widget(table, body_chunks[0], &mut app.table_state);

    // Right Panel: Details and Security Audit Logs
    let detail_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(" Auditoria de Segurança & Detalhes ")
        .border_style(Style::default().fg(Color::Cyan));

    if let Some(dep) = app.selected_dep() {
        let cache_key = format!("{}_{}_{}", dep.ecosystem.as_str(), dep.name, dep.latest_version);
        let detail_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4), // Package basic metadata
                Constraint::Min(5),    // Vulnerabilities
            ])
            .split(detail_block.inner(body_chunks[1]));

        f.render_widget(detail_block, body_chunks[1]);

        // Draw basic metadata
        let metadata_text = format!(
            "Pacote: {}\nEcossistema: {}\nVersão Atual: {}  ➔  Nova Versão: {}",
            dep.name,
            dep.ecosystem.as_str(),
            dep.current_version,
            dep.latest_version
        );
        let metadata = Paragraph::new(metadata_text)
            .style(Style::default().fg(Color::White));
        f.render_widget(metadata, detail_chunks[0]);

        // Draw vulnerability information
        if let Some(cached_res) = app.vuln_cache.get(&cache_key) {
            match cached_res {
                Ok(vulns) => {
                    let active_vulns: Vec<&VulnerabilityInfo> = vulns.iter()
                        .filter(|v| !app.config.is_vulnerability_ignored(&v.id))
                        .collect();

                    if active_vulns.is_empty() {
                        let secure_text = "\n ✓ SEGURO: Nenhuma vulnerabilidade conhecida foi detectada no banco de dados do OSV.dev para esta versão.";
                        let secure_widget = Paragraph::new(secure_text)
                            .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                            .wrap(Wrap { trim: true });
                        f.render_widget(secure_widget, detail_chunks[1]);
                    } else {
                        let mut vuln_text = format!(" ⚠️ AVISO: {} VULNERABILIDADE(S) ENCONTRADA(S)!\n\n", active_vulns.len());
                        for vuln in active_vulns {
                            vuln_text.push_str(&format!(
                                "ID: {} ({})\nSumário: {}\nDetalhes: {}\n----------------------------------------\n",
                                vuln.id,
                                vuln.aliases.join(", "),
                                vuln.summary,
                                vuln.details
                            ));
                        }
                        let vuln_widget = Paragraph::new(vuln_text)
                            .style(Style::default().fg(Color::Yellow))
                            .wrap(Wrap { trim: true });
                        f.render_widget(vuln_widget, detail_chunks[1]);
                    }
                }
                Err(err_msg) => {
                    let err_text = format!(
                        " ❌ Falha na auditoria de segurança:\n{}\n\nVerifique sua conexão de rede. A política local de segurança pode bloquear upgrades se não for possível validar a segurança.",
                        err_msg
                    );
                    let err_widget = Paragraph::new(err_text)
                        .style(Style::default().fg(Color::LightRed))
                        .wrap(Wrap { trim: true });
                    f.render_widget(err_widget, detail_chunks[1]);
                }
            }
        } else {
            let loading_text = "\n [!] Selecione uma dependência e faça o Upgrade para rodar a auditoria de segurança.";
            let loading = Paragraph::new(loading_text)
                .style(Style::default().fg(Color::DarkGray))
                .wrap(Wrap { trim: true });
            f.render_widget(loading, detail_chunks[1]);
        }
    } else {
        let no_selection = Paragraph::new("\n Nenhuma dependência selecionada.")
            .style(Style::default().fg(Color::DarkGray));
        let inner_area = detail_block.inner(body_chunks[1]);
        f.render_widget(detail_block, body_chunks[1]);
        f.render_widget(no_selection, inner_area);
    }

    // 4. Render Status Bar
    let status_style = match app.status {
        AppStatus::Scanning => Style::default().fg(Color::Yellow).bg(Color::Rgb(30, 41, 59)),
        AppStatus::Upgrading(_) => Style::default().fg(Color::Cyan).bg(Color::Rgb(30, 41, 59)),
        AppStatus::UpgradeSuccess(_) => Style::default().fg(Color::Green).bg(Color::Rgb(30, 41, 59)),
        AppStatus::UpgradeFailed(_, _) => Style::default().fg(Color::Red).bg(Color::Rgb(30, 41, 59)),
        AppStatus::Ready => Style::default().fg(Color::Gray).bg(Color::Rgb(15, 23, 42)),
    };

    let status_text = match &app.status {
        AppStatus::Scanning => " Status: [ Varrendo dependências localmente e globalmente... ] ".to_string(),
        AppStatus::Upgrading(msg) => format!(" Status: [ {} ] ", msg),
        AppStatus::UpgradeSuccess(pkg) => format!(" Status: [ Upgrade de {} realizado com sucesso! ] ", pkg),
        AppStatus::UpgradeFailed(pkg, err) => format!(" Status: [ Falha ao atualizar {}: {} ] ", pkg, err),
        AppStatus::Ready => " Status: [ Pronto ] ".to_string(),
    };

    let status_widget = Paragraph::new(status_text).style(status_style);
    f.render_widget(status_widget, chunks[3]);

    // 5. Render Help Bar
    let help_text = " [q] Sair | [Tab] Alternar Local/Global | [r] Atualizar Lista | [u] Upgrade Seguro | [f] Forçar Upgrade (Alerta) ";
    let help = Paragraph::new(help_text)
        .style(Style::default().fg(Color::Black).bg(Color::Cyan));
    f.render_widget(help, chunks[4]);

    // 6. Draw Modal popups if active
    match &app.modal {
        Modal::ConfirmForce(dep, vulns) => {
            let area = centered_rect(65, 60, size);
            f.render_widget(Clear, area);

            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .title(" ⚠️ ALERTA DE SEGURANÇA: VULNERABILIDADE DETECTADA ")
                .border_style(Style::default().fg(Color::Yellow));

            let mut text = format!(
                "O pacote {} possui vulnerabilidades reportadas na versão alvo ({})!\n\nA política deste repositório permite upgrades forçados após aviso.\n\nVulnerabilidades ativas:\n\n",
                dep.name, dep.latest_version
            );
            for v in vulns {
                text.push_str(&format!("  * ID: {} - {}\n", v.id, v.summary));
            }
            text.push_str("\n\nPressione [Enter] para FORÇAR a instalação.\nPressione [Esc] para CANCELAR.");

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
                .title(" ❌ UPGRADE BLOQUEADO POR POLÍTICA DE SEGURANÇA ")
                .border_style(Style::default().fg(Color::Red));

            let mut text = format!(
                "O pacote {} possui vulnerabilidades de segurança na versão alvo ({}).\n\nDe acordo com a configuração de política em 'tucupi.toml' (block_vulnerable = true), upgrades para versões vulneráveis estão TERMINANTEMENTE PROIBIDOS.\n\nVulnerabilidades impeditivas:\n\n",
                dep.name, dep.latest_version
            );
            for v in vulns {
                text.push_str(&format!("  * ID: {} - {}\n", v.id, v.summary));
            }
            text.push_str("\n\nPressione [Esc] ou [Enter] para fechar este alerta.");

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
