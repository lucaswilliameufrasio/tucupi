use crate::adapters::{check_all_outdated, check_global_outdated};
use crate::config::Config;
use crate::i18n::{t, tf};
use crate::models::FreshnessInfo;
use crate::models::{Dependency, Ecosystem, PackageOrigin, ProvenanceInfo, VulnerabilityInfo};
use crate::review::{self, ReviewReport, ReviewVerdict};
use crate::rollback::{commit_backup, prepare_local_backup, restore_backup};
use crate::secrets::{resolve_nvd_api_key, SecretStore};
use crate::security::{check_provenance, SecurityChecker};
use ratatui::widgets::TableState;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tab {
    Local,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppStatus {
    Ready,
    Scanning,
    Upgrading(String),
    UpgradeSuccess(String),
    UpgradeFailed(String, String),
}

#[derive(Debug, Clone)]
pub enum Modal {
    None,
    Blocked(Dependency, Vec<VulnerabilityInfo>),
    BlockedPolicy(Dependency, String),
    ConfirmForce(Dependency, Vec<VulnerabilityInfo>),
    ConfirmGlobal(Dependency, String),
    SecretInput { buffer: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Info,
    Success,
    Error,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub kind: ToastKind,
    pub message: String,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct DependencyLog {
    pub name: String,
    pub lines: Vec<String>,
}

pub enum AppEvent {
    ScanFinished(Tab, Vec<Dependency>),
    SecurityChecked(Dependency, Result<Vec<VulnerabilityInfo>, String>, bool),
    FreshnessChecked(Dependency, FreshnessInfo),
    ProvenanceChecked(Dependency, ProvenanceInfo),
    ReviewChecked(Dependency, ReviewReport, bool, bool),
    UpgradeFinished(Result<(), String>),
    UpgradeLog(String, String),
}

pub struct App {
    pub target_dir: PathBuf,
    pub active_tab: Tab,
    pub local_deps: Vec<Dependency>,
    pub global_deps: Vec<Dependency>,
    pub table_state: TableState,
    pub config: Config,
    pub security_checker: SecurityChecker,
    pub status: AppStatus,
    pub modal: Modal,
    pub vuln_cache: HashMap<String, Result<Vec<VulnerabilityInfo>, String>>,
    pub review_cache: HashMap<String, ReviewReport>,
    pub freshness_cache: HashMap<String, FreshnessInfo>,
    pub provenance_cache: HashMap<String, ProvenanceInfo>,
    pub security_check_only: bool,
    pub batch_scan_pending: usize,
    pub toasts: Vec<Toast>,
    pub upgrade_logs: Vec<DependencyLog>,
    pub log_popup_open: bool,
    pub log_popup_tab: usize,
    pub log_popup_scroll_back: usize,
    pub detail_scroll: u16,
    pub secret_store: Arc<dyn SecretStore>,

    pub event_tx: mpsc::UnboundedSender<AppEvent>,
    pub event_rx: mpsc::UnboundedReceiver<AppEvent>,
}

impl App {
    pub fn new(target_dir: PathBuf, boot_global: bool) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let active_tab = if boot_global { Tab::Global } else { Tab::Local };

        let mut table_state = TableState::default();
        table_state.select(Some(0));

        Self {
            target_dir,
            active_tab,
            local_deps: Vec::new(),
            global_deps: Vec::new(),
            table_state,
            config: Config::default(),
            security_checker: SecurityChecker::new(),
            status: AppStatus::Ready,
            modal: Modal::None,
            vuln_cache: HashMap::new(),
            review_cache: HashMap::new(),
            freshness_cache: HashMap::new(),
            provenance_cache: HashMap::new(),
            security_check_only: false,
            batch_scan_pending: 0,
            toasts: Vec::new(),
            upgrade_logs: Vec::new(),
            log_popup_open: false,
            log_popup_tab: 0,
            log_popup_scroll_back: 0,
            detail_scroll: 0,
            secret_store: crate::secrets::default_secret_store(),
            event_tx,
            event_rx,
        }
    }

    pub fn current_deps(&self) -> &Vec<Dependency> {
        match self.active_tab {
            Tab::Local => &self.local_deps,
            Tab::Global => &self.global_deps,
        }
    }

    pub fn selected_dep(&self) -> Option<&Dependency> {
        let deps = self.current_deps();
        let idx = self.table_state.selected()?;
        if idx < deps.len() {
            Some(&deps[idx])
        } else {
            None
        }
    }

    pub fn scroll_down(&mut self) {
        let len = self.current_deps().len();
        if len == 0 {
            self.table_state.select(None);
            return;
        }
        let current = self.table_state.selected().unwrap_or(0);
        let next = (current + 1).min(len.saturating_sub(1));
        self.table_state.select(Some(next));
        self.detail_scroll = 0;
    }

    pub fn scroll_up(&mut self) {
        let len = self.current_deps().len();
        if len == 0 {
            self.table_state.select(None);
            return;
        }
        let current = self.table_state.selected().unwrap_or(0);
        let prev = current.saturating_sub(1);
        self.table_state.select(Some(prev));
        self.detail_scroll = 0;
    }

    pub fn detail_scroll_up(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_add(1);
    }

    pub fn detail_scroll_down(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_sub(1);
    }

    pub fn switch_tab(&mut self) {
        self.active_tab = match self.active_tab {
            Tab::Local => Tab::Global,
            Tab::Global => Tab::Local,
        };
        self.table_state.select(if self.current_deps().is_empty() {
            None
        } else {
            Some(0)
        });
        self.detail_scroll = 0;
    }

    pub fn push_toast(&mut self, kind: ToastKind, message: String) {
        let ttl = match kind {
            ToastKind::Error => Duration::from_secs(12),
            ToastKind::Info | ToastKind::Success => Duration::from_secs(6),
        };
        self.toasts.push(Toast {
            kind,
            message,
            expires_at: Instant::now() + ttl,
        });
        if self.toasts.len() > 6 {
            self.toasts.remove(0);
        }
    }

    pub fn expire_toasts(&mut self) {
        let now = Instant::now();
        self.toasts.retain(|toast| toast.expires_at > now);
    }

    pub fn open_log_popup(&mut self) {
        if self.upgrade_logs.is_empty() {
            return;
        }
        self.log_popup_open = true;
        self.log_popup_tab = self.log_popup_tab.min(self.upgrade_logs.len() - 1);
        self.log_popup_scroll_back = 0;
    }

    pub fn close_log_popup(&mut self) {
        self.log_popup_open = false;
    }

    pub fn log_popup_next_tab(&mut self) {
        if self.upgrade_logs.is_empty() {
            return;
        }
        self.log_popup_tab = (self.log_popup_tab + 1) % self.upgrade_logs.len();
        self.log_popup_scroll_back = 0;
    }

    pub fn log_popup_prev_tab(&mut self) {
        if self.upgrade_logs.is_empty() {
            return;
        }
        self.log_popup_tab =
            (self.log_popup_tab + self.upgrade_logs.len() - 1) % self.upgrade_logs.len();
        self.log_popup_scroll_back = 0;
    }

    pub fn log_popup_scroll_up(&mut self) {
        self.log_popup_scroll_back = self.log_popup_scroll_back.saturating_add(1);
    }

    pub fn log_popup_scroll_down(&mut self) {
        self.log_popup_scroll_back = self.log_popup_scroll_back.saturating_sub(1);
    }

    pub fn open_secret_input(&mut self) {
        self.modal = Modal::SecretInput {
            buffer: String::new(),
        };
    }

    pub fn secret_input_push(&mut self, character: char) {
        if let Modal::SecretInput { buffer } = &mut self.modal {
            buffer.push(character);
        }
    }

    pub fn secret_input_backspace(&mut self) {
        if let Modal::SecretInput { buffer } = &mut self.modal {
            buffer.pop();
        }
    }

    pub fn save_nvd_key_from_input(&mut self) {
        let value = match &self.modal {
            Modal::SecretInput { buffer } => buffer.trim().to_string(),
            _ => return,
        };
        self.modal = Modal::None;
        if value.is_empty() {
            self.push_toast(ToastKind::Error, t("toast_secret_empty").to_string());
            return;
        }
        match self.secret_store.set_secret(&value) {
            Ok(()) => self.push_toast(ToastKind::Success, t("toast_secret_saved").to_string()),
            Err(err) => self.push_toast(ToastKind::Error, tf("toast_secret_save_failed", &[&err])),
        }
    }

    pub fn remove_nvd_key(&mut self) {
        match self.secret_store.delete_secret() {
            Ok(()) => self.push_toast(ToastKind::Success, t("toast_secret_removed").to_string()),
            Err(err) => {
                self.push_toast(ToastKind::Error, tf("toast_secret_remove_failed", &[&err]))
            }
        }
    }

    fn append_upgrade_log(&mut self, name: &str, line: String) {
        if let Some(log) = self.upgrade_logs.iter_mut().find(|log| log.name == name) {
            log.lines.push(line);
        } else {
            self.upgrade_logs.push(DependencyLog {
                name: name.to_string(),
                lines: vec![line],
            });
            self.log_popup_tab = self.upgrade_logs.len() - 1;
            self.log_popup_scroll_back = 0;
        }
    }

    fn clear_upgrade_log(&mut self, name: &str) {
        if let Some(log) = self.upgrade_logs.iter_mut().find(|log| log.name == name) {
            log.lines.clear();
        }
    }

    pub fn trigger_scan(&mut self) {
        self.status = AppStatus::Scanning;
        self.local_deps.clear();
        self.global_deps.clear();
        self.vuln_cache.clear();
        self.freshness_cache.clear();
        self.provenance_cache.clear();
        self.batch_scan_pending = 0;
        self.table_state.select(None);

        let tx = self.event_tx.clone();
        let dir = self.target_dir.clone();

        tokio::spawn(async move {
            let deps = check_all_outdated(&dir).await;
            let _ = tx.send(AppEvent::ScanFinished(Tab::Local, deps));
        });

        let tx_global = self.event_tx.clone();
        tokio::spawn(async move {
            let deps = check_global_outdated().await;
            let _ = tx_global.send(AppEvent::ScanFinished(Tab::Global, deps));
        });
    }

    pub async fn load_config_sync(&mut self) {
        self.config = Config::load_from_dir(&self.target_dir).await;
    }

    fn block_with_policy_message(&mut self, dep: Dependency, message: String) {
        let package_name = dep.name.clone();
        self.modal = Modal::BlockedPolicy(dep, message.clone());
        self.status = AppStatus::UpgradeFailed(package_name, message);
    }

    fn policy_block_reason(&self, dep: &Dependency) -> Option<String> {
        if matches!(dep.origin, Some(PackageOrigin::Aur)) && !self.config.aur_enabled() {
            return Some(t("blocked_aur_disabled").to_string());
        }

        if dep.ecosystem == Ecosystem::Pacman && self.config.require_provenance() {
            return match self.provenance_cache.get(&cache_key(dep)) {
                Some(info) if info.signature_verified => None,
                _ => Some(t("blocked_provenance_required").to_string()),
            };
        }

        if self.config.block_too_fresh()
            && self
                .freshness_cache
                .get(&cache_key(dep))
                .is_some_and(FreshnessInfo::is_too_fresh)
        {
            return Some(t("blocked_too_fresh").to_string());
        }

        None
    }

    pub fn confirm_global_upgrade(&mut self) {
        if let Modal::ConfirmGlobal(dep, _) = self.modal.clone() {
            self.modal = Modal::None;
            self.start_upgrade_confirmed(dep);
        }
    }

    fn trigger_batch_security_scan(&mut self) {
        let all_deps: Vec<Dependency> = self
            .local_deps
            .iter()
            .chain(self.global_deps.iter())
            .cloned()
            .collect();

        let timeout = self.config.osv_timeout_secs();
        let threshold = self.config.freshness_threshold_days();
        let very_recent = self.config.very_recent_days();
        let nvd_key = resolve_nvd_api_key(&*self.secret_store);

        for dep in &all_deps {
            let cache_key = format!(
                "{}_{}_{}",
                dep.ecosystem.as_str(),
                dep.name,
                dep.latest_version
            );

            // OSV + NVD check
            if dep.ecosystem.has_osv_coverage() {
                self.batch_scan_pending += 1;
                let tx = self.event_tx.clone();
                let d = dep.clone();
                let key = nvd_key.clone();
                tokio::spawn(async move {
                    let checker = SecurityChecker::new_with_config(timeout, key);
                    let result = checker
                        .check_vulnerability(&d.name, &d.latest_version, d.ecosystem)
                        .await;
                    let _ = tx.send(AppEvent::SecurityChecked(
                        d,
                        result.map_err(|e| e.to_string()),
                        true,
                    ));
                });
            }

            // Freshness check (cargo + npm)
            if matches!(dep.ecosystem, Ecosystem::Cargo | Ecosystem::Npm)
                && !self.freshness_cache.contains_key(&cache_key)
            {
                let tx = self.event_tx.clone();
                let d = dep.clone();
                tokio::spawn(async move {
                    let checker = SecurityChecker::new_with_config(timeout, None);
                    let freshness = checker
                        .check_freshness(
                            &d.name,
                            &d.latest_version,
                            d.ecosystem,
                            very_recent,
                            threshold,
                        )
                        .await;
                    let _ = tx.send(AppEvent::FreshnessChecked(d, freshness));
                });
            }

            // Provenance check (pacman)
            if dep.ecosystem == Ecosystem::Pacman && !self.provenance_cache.contains_key(&cache_key)
            {
                let tx = self.event_tx.clone();
                let d = dep.clone();
                tokio::spawn(async move {
                    let info = check_provenance(&d.name, Ecosystem::Pacman).await;
                    let _ = tx.send(AppEvent::ProvenanceChecked(d, info));
                });
            }
        }
    }

    pub fn trigger_upgrade_selected(&mut self, force: bool) {
        let dep = match self.selected_dep() {
            Some(d) => d.clone(),
            None => return,
        };

        if let Some(message) = self.policy_block_reason(&dep) {
            self.block_with_policy_message(dep, message);
            return;
        }

        if self.status != AppStatus::Ready && !matches!(self.status, AppStatus::UpgradeFailed(_, _))
        {
            return;
        }

        if !dep.is_global && !is_safe_path(&self.target_dir) {
            return;
        }

        let cache_key = format!(
            "{}_{}_{}",
            dep.ecosystem.as_str(),
            dep.name,
            dep.latest_version
        );

        if let Some(cached_result) = self.vuln_cache.get(&cache_key) {
            match cached_result {
                Ok(vulns) => {
                    self.process_upgrade_with_vulns(dep, vulns.clone(), force);
                }
                Err(err_msg) if self.config.require_online() => {
                    self.block_with_policy_message(dep, tf("blocked_online_required", &[err_msg]));
                }
                Err(_) if force => {
                    self.start_upgrade(dep, true);
                }
                Err(err_msg) => {
                    self.status = AppStatus::UpgradeFailed(
                        dep.name.clone(),
                        format!("Security check failed: {}", err_msg),
                    );
                    self.push_toast(
                        ToastKind::Error,
                        tf("toast_security_check_failed", &[&dep.name]),
                    );
                }
            }
            return;
        }

        self.status = AppStatus::Upgrading(format!("Auditing security for {}...", dep.name));
        let tx = self.event_tx.clone();
        let checker = SecurityChecker::new_with_config(
            self.config.osv_timeout_secs(),
            resolve_nvd_api_key(&*self.secret_store),
        );
        let d = dep.clone();

        tokio::spawn(async move {
            match checker
                .check_vulnerability(&d.name, &d.latest_version, d.ecosystem)
                .await
            {
                Ok(vulns) => {
                    let _ = tx.send(AppEvent::SecurityChecked(d, Ok(vulns), false));
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::SecurityChecked(d, Err(e.to_string()), false));
                }
            }
        });
    }

    pub fn check_security_selected(&mut self) {
        let dep = match self.selected_dep() {
            Some(d) => d.clone(),
            None => return,
        };

        if self.status != AppStatus::Ready {
            return;
        }

        if self.batch_scan_pending > 0 {
            return;
        }

        if !dep.is_global && !is_safe_path(&self.target_dir) {
            return;
        }

        let cache_key = format!(
            "{}_{}_{}",
            dep.ecosystem.as_str(),
            dep.name,
            dep.latest_version
        );

        if self.vuln_cache.contains_key(&cache_key) {
            return;
        }

        self.security_check_only = true;
        self.status = AppStatus::Upgrading(format!("Auditing security for {}...", dep.name));
        let tx = self.event_tx.clone();
        let checker = SecurityChecker::new_with_config(
            self.config.osv_timeout_secs(),
            resolve_nvd_api_key(&*self.secret_store),
        );
        let d = dep.clone();

        tokio::spawn(async move {
            match checker
                .check_vulnerability(&d.name, &d.latest_version, d.ecosystem)
                .await
            {
                Ok(vulns) => {
                    let _ = tx.send(AppEvent::SecurityChecked(d, Ok(vulns), false));
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::SecurityChecked(d, Err(e.to_string()), false));
                }
            }
        });

        if review::needs_review(&dep) && self.config.pkgbuild_review() {
            let review_tx = self.event_tx.clone();
            let review_config = self.config.clone();
            let review_dep = dep;
            tokio::spawn(async move {
                let report = review::review_package(&review_dep, &review_config).await;
                let _ = review_tx.send(AppEvent::ReviewChecked(review_dep, report, false, true));
            });
        }
    }

    pub fn process_security_result(
        &mut self,
        dep: Dependency,
        res: Result<Vec<VulnerabilityInfo>, String>,
        from_pre_scan: bool,
    ) {
        let cache_key = format!(
            "{}_{}_{}",
            dep.ecosystem.as_str(),
            dep.name,
            dep.latest_version
        );
        self.vuln_cache.insert(cache_key, res.clone());

        if from_pre_scan {
            if self.batch_scan_pending > 0 {
                self.batch_scan_pending -= 1;
            }
            return;
        }

        if self.security_check_only {
            self.security_check_only = false;
            self.status = AppStatus::Ready;
            return;
        }

        match res {
            Ok(vulns) => {
                self.process_upgrade_with_vulns(dep, vulns, false);
            }
            Err(err_msg) => {
                if self.config.require_online() {
                    self.block_with_policy_message(dep, tf("blocked_online_required", &[&err_msg]));
                } else if self.config.block_vulnerable() {
                    let package_name = dep.name.clone();
                    self.status = AppStatus::UpgradeFailed(
                        package_name.clone(),
                        format!(
                            "Security check failed: {}. Upgrade BLOCKED by repository configuration.",
                            err_msg
                        ),
                    );
                    self.push_toast(
                        ToastKind::Error,
                        tf("toast_security_check_failed", &[&package_name]),
                    );
                } else {
                    self.modal = Modal::ConfirmForce(
                        dep,
                        vec![VulnerabilityInfo {
                            id: "OFFLINE_WARNING".to_string(),
                            summary: "Não foi possível verificar vulnerabilidades online."
                                .to_string(),
                            details: format!(
                                "O erro retornado foi: {}. Deseja forçar o upgrade mesmo assim?",
                                err_msg
                            ),
                            aliases: Vec::new(),
                            severity: None,
                            score: None,
                            sources: vec!["policy".to_string()],
                        }],
                    );
                    self.status = AppStatus::Ready;
                }
            }
        }
    }

    fn review_cache_key(&self, dep: &Dependency) -> String {
        format!(
            "{}_{}_{}_{}",
            dep.ecosystem.as_str(),
            dep.name,
            dep.current_version,
            dep.latest_version
        )
    }

    fn spawn_pkgbuild_review(&mut self, dep: Dependency, force: bool) {
        self.status = AppStatus::Upgrading(tf("review_started", &[&dep.name]));
        let tx = self.event_tx.clone();
        let config = self.config.clone();
        tokio::spawn(async move {
            let report = review::review_package(&dep, &config).await;
            let _ = tx.send(AppEvent::ReviewChecked(dep, report, force, false));
        });
    }

    fn process_review_result(
        &mut self,
        dep: Dependency,
        report: ReviewReport,
        force: bool,
        audit_only: bool,
    ) {
        let cache_key = self.review_cache_key(&dep);
        self.review_cache.insert(cache_key, report.clone());

        if audit_only {
            self.status = AppStatus::Ready;
            if report.verdict != ReviewVerdict::Safe {
                self.modal = Modal::BlockedPolicy(
                    dep,
                    tf(
                        "review_audit_result",
                        &[report.verdict.as_str(), &report.reason],
                    ),
                );
            }
            return;
        }

        match report.verdict {
            ReviewVerdict::Safe => {
                self.status = AppStatus::Ready;
                self.start_upgrade(dep, force);
            }
            ReviewVerdict::Block => {
                self.status = AppStatus::Ready;
                self.block_with_policy_message(dep, tf("review_blocked", &[&report.reason]));
            }
            ReviewVerdict::Review => {
                self.status = AppStatus::Ready;
                if force {
                    self.start_upgrade(dep, true);
                } else {
                    self.modal = Modal::ConfirmForce(dep, vec![review_to_vuln_info(&report)]);
                }
            }
        }
    }

    fn process_upgrade_with_vulns(
        &mut self,
        dep: Dependency,
        vulns: Vec<VulnerabilityInfo>,
        force: bool,
    ) {
        if let Some(message) = self.policy_block_reason(&dep) {
            self.block_with_policy_message(dep, message);
            return;
        }

        let active_vulns: Vec<VulnerabilityInfo> = vulns
            .into_iter()
            .filter(|v| !self.config.is_vulnerability_ignored(&v.id))
            .collect();

        if active_vulns.is_empty() || self.config.is_package_ignored(&dep.name) {
            self.start_upgrade(dep, force);
        } else if self.config.block_vulnerable() {
            self.modal = Modal::Blocked(dep, active_vulns);
            self.status = AppStatus::Ready;
        } else if force {
            self.modal = Modal::None;
            self.start_upgrade(dep, true);
        } else {
            self.modal = Modal::ConfirmForce(dep, active_vulns);
            self.status = AppStatus::Ready;
        }
    }

    fn start_upgrade(&mut self, dep: Dependency, force: bool) {
        if review::needs_review(&dep) && self.config.pkgbuild_review() {
            let cache_key = self.review_cache_key(&dep);
            let cached = self.review_cache.get(&cache_key).cloned();
            match cached {
                Some(report) => match report.verdict {
                    ReviewVerdict::Safe => {}
                    ReviewVerdict::Block => {
                        self.status = AppStatus::Ready;
                        self.block_with_policy_message(
                            dep,
                            tf("review_blocked", &[&report.reason]),
                        );
                        return;
                    }
                    ReviewVerdict::Review => {
                        if !force {
                            self.status = AppStatus::Ready;
                            self.modal =
                                Modal::ConfirmForce(dep, vec![review_to_vuln_info(&report)]);
                            return;
                        }
                    }
                },
                None => {
                    self.spawn_pkgbuild_review(dep, force);
                    return;
                }
            }
        }

        if dep.is_global && self.config.confirm_global() {
            let (command, args) = get_upgrade_cmd(&dep, &self.target_dir);
            let command_line = format!("{} {}", command, args.join(" "));
            self.modal = Modal::ConfirmGlobal(dep, command_line);
            self.status = AppStatus::Ready;
            return;
        }

        self.start_upgrade_confirmed(dep);
    }

    fn start_upgrade_confirmed(&mut self, dep: Dependency) {
        let is_cargo_local = !dep.is_global && dep.ecosystem == Ecosystem::Cargo;
        self.status = AppStatus::Upgrading(format!(
            "Upgrading {} to {}...",
            dep.name, dep.latest_version
        ));
        self.clear_upgrade_log(&dep.name);
        self.log_popup_open = true;
        if let Some(position) = self
            .upgrade_logs
            .iter()
            .position(|log| log.name == dep.name)
        {
            self.log_popup_tab = position;
        }
        self.log_popup_scroll_back = 0;
        let tx = self.event_tx.clone();
        let target_dir = self.target_dir.clone();
        let dep_name = dep.name.clone();
        let dep_for_backup = dep.clone();

        let (line_tx, mut line_rx) = mpsc::unbounded_channel::<String>();
        let log_event_tx = self.event_tx.clone();
        let log_dep_name = dep.name.clone();
        tokio::spawn(async move {
            while let Some(line) = line_rx.recv().await {
                let _ = log_event_tx.send(AppEvent::UpgradeLog(log_dep_name.clone(), line));
            }
        });

        tokio::spawn(async move {
            let backup = if dep_for_backup.is_global {
                None
            } else {
                match prepare_local_backup(&dep_for_backup, &target_dir) {
                    Ok(backup) => backup,
                    Err(error) => {
                        let _ = tx.send(AppEvent::UpgradeFinished(Err(format!(
                            "Failed to prepare rollback backup: {}",
                            error
                        ))));
                        return;
                    }
                }
            };

            let (cmd, args) = get_upgrade_cmd(&dep, &target_dir);
            let mut result =
                run_upgrade_process(&cmd, args, &target_dir, Some(line_tx.clone())).await;

            if result.is_ok() && is_cargo_local {
                let update_args = vec!["update".to_string(), "-p".to_string(), dep_name.clone()];
                let fetch_result =
                    run_upgrade_process("cargo", update_args, &target_dir, Some(line_tx)).await;
                if let Err(e) = fetch_result {
                    result = Err(e
                        .lines()
                        .next()
                        .unwrap_or("cargo update failed")
                        .to_string());
                }
            }

            let result = match result {
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

            let _ = tx.send(AppEvent::UpgradeFinished(result));
        });
    }

    pub fn handle_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::ScanFinished(tab, deps) => {
                match tab {
                    Tab::Local => self.local_deps = deps,
                    Tab::Global => self.global_deps = deps,
                }
                if self.status == AppStatus::Scanning {
                    self.status = AppStatus::Ready;
                    self.table_state.select(if self.current_deps().is_empty() {
                        None
                    } else {
                        Some(0)
                    });
                    self.detail_scroll = 0;
                    self.trigger_batch_security_scan();
                }
            }
            AppEvent::SecurityChecked(dep, res, from_pre_scan) => {
                self.process_security_result(dep, res, from_pre_scan);
            }
            AppEvent::FreshnessChecked(dep, freshness) => {
                let cache_key = format!(
                    "{}_{}_{}",
                    dep.ecosystem.as_str(),
                    dep.name,
                    dep.latest_version
                );
                self.freshness_cache.insert(cache_key, freshness);
            }
            AppEvent::ProvenanceChecked(dep, info) => {
                let cache_key = format!(
                    "{}_{}_{}",
                    dep.ecosystem.as_str(),
                    dep.name,
                    dep.latest_version
                );
                self.provenance_cache.insert(cache_key, info);
            }
            AppEvent::ReviewChecked(dep, report, force, audit_only) => {
                self.process_review_result(dep, report, force, audit_only);
            }
            AppEvent::UpgradeLog(name, line) => {
                self.append_upgrade_log(&name, line);
            }
            AppEvent::UpgradeFinished(res) => match res {
                Ok(_) => {
                    let name = match self.status {
                        AppStatus::Upgrading(ref msg) => msg
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("dependency")
                            .to_string(),
                        _ => "dependency".to_string(),
                    };
                    self.push_toast(ToastKind::Success, tf("toast_upgrade_success", &[&name]));
                    self.status = AppStatus::UpgradeSuccess(name);
                    self.trigger_scan();
                }
                Err(err_msg) => {
                    let name = match self.status {
                        AppStatus::Upgrading(ref msg) => msg
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("dependency")
                            .to_string(),
                        _ => "dependency".to_string(),
                    };
                    self.push_toast(ToastKind::Error, tf("toast_upgrade_failed", &[&name]));
                    self.status = AppStatus::UpgradeFailed(name, err_msg);
                }
            },
        }
    }
}

pub(crate) fn strip_build_metadata(version: &str) -> &str {
    version.split('+').next().unwrap_or(version)
}

const BLOCKED_PATHS: &[&str] = &[
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/lib",
    "/usr/lib",
    "/var",
];

pub(crate) fn is_safe_path(dir: &Path) -> bool {
    let canonical = match dir.canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let path_str = canonical.to_string_lossy();
    for blocked in BLOCKED_PATHS {
        if path_str == *blocked || path_str.starts_with(&format!("{}/", blocked)) {
            return false;
        }
    }
    true
}

pub(crate) fn get_upgrade_cmd(dep: &Dependency, target_dir: &Path) -> (String, Vec<String>) {
    let clean_version = strip_build_metadata(&dep.latest_version).to_string();

    if dep.is_global {
        match dep.ecosystem {
            Ecosystem::Npm => (
                "npm".to_string(),
                vec![
                    "install".to_string(),
                    "-g".to_string(),
                    format!("{}@{}", dep.name, clean_version),
                ],
            ),
            Ecosystem::Cargo => (
                "cargo".to_string(),
                vec![
                    "install".to_string(),
                    dep.name.clone(),
                    "--force".to_string(),
                ],
            ),
            Ecosystem::Pacman => (
                "paru".to_string(),
                vec![
                    "-S".to_string(),
                    "--noconfirm".to_string(),
                    dep.name.clone(),
                ],
            ),
            Ecosystem::Mise => (
                "mise".to_string(),
                vec![
                    "upgrade".to_string(),
                    "--bump".to_string(),
                    dep.name.clone(),
                ],
            ),
            Ecosystem::Homebrew => (
                "brew".to_string(),
                vec!["upgrade".to_string(), dep.name.clone()],
            ),
            _ => (
                "echo".to_string(),
                vec!["Ecosystem not supported globally".to_string()],
            ),
        }
    } else {
        match dep.ecosystem {
            Ecosystem::Cargo => (
                "cargo".to_string(),
                vec!["add".to_string(), format!("{}@{}", dep.name, clean_version)],
            ),
            Ecosystem::Go => (
                "go".to_string(),
                vec!["get".to_string(), format!("{}@{}", dep.name, clean_version)],
            ),
            Ecosystem::Dart => (
                "dart".to_string(),
                vec![
                    "pub".to_string(),
                    "add".to_string(),
                    format!("{}:{}", dep.name, clean_version),
                ],
            ),
            Ecosystem::Elixir => (
                "mix".to_string(),
                vec!["deps.update".to_string(), dep.name.clone()],
            ),
            Ecosystem::Npm => {
                let mut cmd = "npm".to_string();
                let mut args = vec![
                    "install".to_string(),
                    format!("{}@{}", dep.name, clean_version),
                ];

                if target_dir.join("pnpm-lock.yaml").exists() {
                    cmd = "pnpm".to_string();
                    args = vec!["add".to_string(), format!("{}@{}", dep.name, clean_version)];
                } else if target_dir.join("yarn.lock").exists() {
                    cmd = "yarn".to_string();
                    args = vec!["add".to_string(), format!("{}@{}", dep.name, clean_version)];
                } else if target_dir.join("bun.lockb").exists()
                    || target_dir.join("bun.lock").exists()
                {
                    cmd = "bun".to_string();
                    args = vec!["add".to_string(), format!("{}@{}", dep.name, clean_version)];
                } else if target_dir.join("deno.json").exists()
                    || target_dir.join("deno.jsonc").exists()
                {
                    cmd = "deno".to_string();
                    args = vec![
                        "add".to_string(),
                        format!("npm:{}@{}", dep.name, clean_version),
                    ];
                }

                (cmd, args)
            }
            Ecosystem::Php => (
                "composer".to_string(),
                vec![
                    "require".to_string(),
                    format!("{}:^{}", dep.name, clean_version),
                ],
            ),
            Ecosystem::Ruby => (
                "bundle".to_string(),
                vec!["update".to_string(), dep.name.clone()],
            ),
            Ecosystem::Python => {
                let pip = if cfg!(windows) { "pip" } else { "pip3" };
                (
                    pip.to_string(),
                    vec![
                        "install".to_string(),
                        "--upgrade".to_string(),
                        format!("{}=={}", dep.name, clean_version),
                    ],
                )
            }
            Ecosystem::Pacman | Ecosystem::Mise | Ecosystem::Homebrew => (
                "echo".to_string(),
                vec!["Only supported as global packages".to_string()],
            ),
        }
    }
}

fn suggest_fix(stderr: &str) -> String {
    let lower = stderr.to_lowercase();
    if lower.contains("linker") && lower.contains("not found") {
        t("fix_build_tools").to_string()
    } else if lower.contains("openssl") || lower.contains("libssl") {
        t("fix_openssl").to_string()
    } else if lower.contains("permission denied") {
        t("fix_permission").to_string()
    } else if lower.contains("error[e") || lower.contains("could not compile") {
        t("fix_compilation").to_string()
    } else if lower.contains("not found") || lower.contains("no such file") {
        t("fix_not_found").to_string()
    } else if lower.contains("network")
        || lower.contains("timeout")
        || lower.contains("connection refused")
    {
        t("fix_network").to_string()
    } else if lower.contains("rate limit") {
        t("fix_rate_limit").to_string()
    } else {
        t("fix_generic").to_string()
    }
}

const UPGRADE_TIMEOUT_SECS: u64 = 120;

async fn collect_stream_lines<R>(
    reader: R,
    log_tx: Option<mpsc::UnboundedSender<String>>,
) -> Vec<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut lines = tokio::io::BufReader::new(reader).lines();
    let mut collected = Vec::new();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(tx) = &log_tx {
            let _ = tx.send(line.clone());
        }
        collected.push(line);
    }
    collected
}

pub(crate) async fn run_upgrade_process(
    cmd: &str,
    args: Vec<String>,
    dir: &Path,
    log_tx: Option<mpsc::UnboundedSender<String>>,
) -> Result<(), String> {
    // Commands that require root must never spawn an interactive sudo prompt
    // inside the TUI/batch runner: the password prompt cannot be answered
    // (raw mode or piped stdio) and would hang until the timeout.
    const ROOT_REQUIRED_COMMANDS: &[&str] = &["pacman", "paru"];
    if ROOT_REQUIRED_COMMANDS.contains(&cmd) {
        let sudo_cached = tokio::process::Command::new("sudo")
            .args(["-n", "true"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|status| status.success())
            .unwrap_or(false);

        if !sudo_cached {
            return Err(
                "Sudo credentials are not cached. Run 'sudo -v' in your terminal before \
                 launching tucupi, or upgrade this package manually. Refusing to spawn an \
                 interactive sudo prompt inside the TUI."
                    .to_string(),
            );
        }
    }

    let mut child = tokio::process::Command::new(cmd)
        .args(&args)
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start process: {}", e))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Failed to capture process stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Failed to capture process stderr".to_string())?;
    let stdout_reader = tokio::spawn(collect_stream_lines(stdout, log_tx.clone()));
    let stderr_reader = tokio::spawn(collect_stream_lines(stderr, log_tx));

    let wait_result =
        tokio::time::timeout(Duration::from_secs(UPGRADE_TIMEOUT_SECS), child.wait()).await;

    let status = match wait_result {
        Ok(wait_status) => wait_status.map_err(|e| format!("Failed to wait for process: {}", e))?,
        Err(_elapsed) => {
            let _ = child.kill().await;
            let _ = stdout_reader.await;
            let _ = stderr_reader.await;
            return Err("Process timed out after 120 seconds.".to_string());
        }
    };

    let _ = stdout_reader.await;
    let stderr_lines = stderr_reader.await.unwrap_or_default();

    if status.success() {
        return Ok(());
    }

    let exit_code = status
        .code()
        .map_or("unknown".to_string(), |code| code.to_string());
    let stderr_text = stderr_lines.join("\n");
    let error_lines: Vec<&str> = stderr_text
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect();
    let last_error = error_lines
        .iter()
        .rev()
        .take(3)
        .rev()
        .cloned()
        .collect::<Vec<&str>>()
        .join("; ");
    let command_line = format!("{} {}", cmd, args.join(" "));
    let hint = suggest_fix(&stderr_text);
    Err(format!(
        "Comando: {}\n\nSaída: {} (exit: {})\n\n{}",
        command_line, last_error, exit_code, hint
    ))
}

fn cache_key(dep: &Dependency) -> String {
    format!(
        "{}_{}_{}",
        dep.ecosystem.as_str(),
        dep.name,
        dep.latest_version
    )
}

fn review_to_vuln_info(report: &ReviewReport) -> VulnerabilityInfo {
    let hits_summary = report
        .hits
        .iter()
        .map(|hit| format!("[{}] {}", hit.pattern, hit.line))
        .collect::<Vec<_>>()
        .join("; ");

    VulnerabilityInfo {
        id: "SOURCE_REVIEW".to_string(),
        summary: report.reason.clone(),
        details: if hits_summary.is_empty() {
            format!(
                "Residual diff lines: {}. Press Enter to force the upgrade anyway.",
                report.residual_line_count
            )
        } else {
            hits_summary
        },
        aliases: Vec::new(),
        severity: Some("review".to_string()),
        score: None,
        sources: vec!["review".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_upgrade_process_streams_output_lines_to_log_channel() {
        let (line_tx, mut line_rx) = mpsc::unbounded_channel();

        let result = run_upgrade_process(
            "echo",
            vec!["hello".to_string()],
            Path::new("."),
            Some(line_tx),
        )
        .await;

        assert!(result.is_ok());
        let mut lines = Vec::new();
        while let Ok(line) = line_rx.try_recv() {
            lines.push(line);
        }
        assert_eq!(lines, vec!["hello".to_string()]);
    }

    #[tokio::test]
    async fn run_upgrade_process_captures_stderr_on_failure() {
        let (line_tx, mut line_rx) = mpsc::unbounded_channel();

        let result = run_upgrade_process(
            "sh",
            vec!["-c".to_string(), "echo boom >&2; exit 1".to_string()],
            Path::new("."),
            Some(line_tx),
        )
        .await;

        assert!(result.is_err());
        let mut lines = Vec::new();
        while let Ok(line) = line_rx.try_recv() {
            lines.push(line);
        }
        assert!(lines.contains(&"boom".to_string()));
    }

    #[tokio::test]
    async fn run_upgrade_process_works_without_log_channel() {
        let result = run_upgrade_process("true", vec![], Path::new("."), None).await;

        assert!(result.is_ok());
    }
}
