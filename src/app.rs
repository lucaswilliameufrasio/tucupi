use crate::adapters::{check_all_outdated, check_global_outdated};
use crate::config::Config;
use crate::i18n::{t, tf};
use crate::models::FreshnessInfo;
use crate::models::{Dependency, Ecosystem, PackageOrigin, ProvenanceInfo, VulnerabilityInfo};
use crate::review::{self, ReviewReport, ReviewVerdict};
use crate::rollback::{commit_backup, prepare_local_backup, restore_backup};
use crate::secrets::{resolve_nvd_api_key, SecretStore};
use crate::security::{check_provenance, AuditFailure, SecurityChecker};
use ratatui::widgets::TableState;
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionState {
    Unselected,
    Safe,
    Force,
}

impl SelectionState {
    pub fn next(self) -> Self {
        match self {
            Self::Unselected => Self::Safe,
            Self::Safe => Self::Force,
            Self::Force => Self::Unselected,
        }
    }

    pub fn marker(self) -> &'static str {
        match self {
            Self::Unselected => "[ ]",
            Self::Safe => "[✓]",
            Self::Force => "[⚡]",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperationKind {
    Upgrade,
    Audit,
}

#[derive(Clone, Copy)]
enum PreScanMetadataKind {
    Freshness,
    Provenance,
}

#[derive(Debug, Clone)]
struct QueuedOperation {
    dep: Dependency,
    force: bool,
    kind: OperationKind,
}

#[derive(Clone)]
pub enum Modal {
    None,
    Help {
        scroll: u16,
    },
    Blocked(Dependency, Vec<VulnerabilityInfo>),
    BlockedPolicy(Dependency, String),
    ConfirmForce(Dependency, Vec<VulnerabilityInfo>),
    ConfirmReview(Dependency, ReviewReport),
    ConfirmOffline(Dependency, String),
    ConfirmGlobal(Dependency, String),
    ConfirmImpact {
        dep: Dependency,
        preview: crate::impact::ImpactPreview,
        scroll: u16,
    },
    SecretInput {
        buffer: String,
    },
    ReviewSettings {
        provider: crate::secrets::ReviewApiProvider,
        model: String,
        input: ReviewSettingsInput,
    },
}

#[derive(Clone)]
pub enum ReviewSettingsInput {
    Menu,
    Model(String),
    Key(String),
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

const MAX_LOG_LINES_PER_DEPENDENCY: usize = 10_000;
const MAX_DEPENDENCY_LOGS: usize = 20;

fn scan_cache_key(dep: &Dependency) -> String {
    format!(
        "{}_{}_{}",
        dep.ecosystem.as_str(),
        dep.name,
        dep.latest_version
    )
}

// Dropping the outer supervisor must not detach its inner review task.
struct AbortReviewWorker(tokio::task::AbortHandle);

impl Drop for AbortReviewWorker {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub enum AppEvent {
    ScanFinished(u64, Tab, Vec<Dependency>),
    SecurityChecked(
        Option<u64>,
        Dependency,
        Result<Vec<VulnerabilityInfo>, AuditFailure>,
        bool,
    ),
    FreshnessChecked(u64, Dependency, FreshnessInfo),
    ProvenanceChecked(u64, Dependency, ProvenanceInfo),
    ReviewChecked(u64, Dependency, ReviewReport, bool, bool),
    UpgradeFinished(Result<(), String>),
    UpgradeLog(String, String),
    ImpactChecked(u64, Dependency, crate::impact::ImpactPreview),
}

pub struct App {
    pub target_dir: PathBuf,
    pub active_tab: Tab,
    pub local_deps: Vec<Dependency>,
    pub global_deps: Vec<Dependency>,
    pub local_selection: Vec<SelectionState>,
    pub global_selection: Vec<SelectionState>,
    pub table_state: TableState,
    pub config: Config,
    pub security_checker: SecurityChecker,
    pub status: AppStatus,
    pub modal: Modal,
    pub vuln_cache: HashMap<String, Result<Vec<VulnerabilityInfo>, AuditFailure>>,
    pub review_cache: HashMap<String, ReviewReport>,
    pub freshness_cache: HashMap<String, FreshnessInfo>,
    pub provenance_cache: HashMap<String, ProvenanceInfo>,
    pending_operations: VecDeque<QueuedOperation>,
    active_operation: Option<QueuedOperation>,
    next_scan_attempt: u64,
    pending_local_scan: Option<u64>,
    pending_global_scan: Option<u64>,
    next_security_attempt: u64,
    active_security_attempt: Option<u64>,
    pending_pre_scan_security: HashMap<u64, Dependency>,
    pending_pre_scan_freshness: HashMap<u64, Dependency>,
    pending_pre_scan_provenance: HashMap<u64, Dependency>,
    next_review_attempt: u64,
    active_review_attempt: Option<u64>,
    active_review_task: Option<tokio::task::JoinHandle<()>>,
    next_impact_attempt: u64,
    active_impact_attempt: Option<u64>,
    active_impact_task: Option<tokio::task::JoinHandle<()>>,
    impact_cleanup_unverified: bool,
    active_review_gate: Option<Arc<review::FixtureStartGate>>,
    review_cleanup_unverified: bool,
    config_load_failed: bool,
    #[cfg(target_os = "linux")]
    recovery_observation: Option<crate::recovery_state::RecoveryObservation>,
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    fixture_recovery: Option<Arc<crate::codex_supervision::FixtureRecoveryMarker>>,
    pub batch_scan_pending: usize,
    #[cfg(test)]
    pre_scan_test_observations: Option<Vec<Vec<Dependency>>>,
    pub toasts: Vec<Toast>,
    pub upgrade_logs: Vec<DependencyLog>,
    pub log_popup_open: bool,
    pub log_popup_tab: usize,
    pub log_popup_scroll_back: usize,
    pub detail_scroll: u16,
    pub secret_store: Arc<dyn SecretStore>,
    review_session_config: Option<(crate::secrets::ReviewApiProvider, String)>,

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
            local_selection: Vec::new(),
            global_selection: Vec::new(),
            table_state,
            config: Config::default(),
            security_checker: SecurityChecker::new(),
            status: AppStatus::Ready,
            modal: Modal::None,
            vuln_cache: HashMap::new(),
            review_cache: HashMap::new(),
            freshness_cache: HashMap::new(),
            provenance_cache: HashMap::new(),
            pending_operations: VecDeque::new(),
            active_operation: None,
            next_scan_attempt: 0,
            pending_local_scan: None,
            pending_global_scan: None,
            next_security_attempt: 0,
            active_security_attempt: None,
            pending_pre_scan_security: HashMap::new(),
            pending_pre_scan_freshness: HashMap::new(),
            pending_pre_scan_provenance: HashMap::new(),
            next_review_attempt: 0,
            active_review_attempt: None,
            active_review_task: None,
            next_impact_attempt: 0,
            active_impact_attempt: None,
            active_impact_task: None,
            impact_cleanup_unverified: false,
            active_review_gate: None,
            review_cleanup_unverified: false,
            config_load_failed: false,
            #[cfg(target_os = "linux")]
            recovery_observation: None,
            #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
            fixture_recovery: None,
            batch_scan_pending: 0,
            #[cfg(test)]
            pre_scan_test_observations: None,
            toasts: Vec::new(),
            upgrade_logs: Vec::new(),
            log_popup_open: false,
            log_popup_tab: 0,
            log_popup_scroll_back: 0,
            detail_scroll: 0,
            secret_store: crate::secrets::default_secret_store(),
            review_session_config: None,
            event_tx,
            event_rx,
        }
    }

    /// Opt-in fixture experiment only. The supplied state directory must be
    /// private and trusted; no production provider or recovery is enabled.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    pub fn new_with_fixture_recovery(
        target_dir: PathBuf,
        boot_global: bool,
        state_dir: &std::path::Path,
    ) -> Self {
        let mut app = Self::new(target_dir, boot_global);
        match crate::codex_supervision::FixtureRecoveryMarker::open(state_dir) {
            Ok(marker) => {
                app.review_cleanup_unverified = marker.blocked().unwrap_or(true);
                app.fixture_recovery = Some(Arc::new(marker));
            }
            Err(_) => app.review_cleanup_unverified = true,
        }
        app
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[doc(hidden)]
    pub fn fixture_recovery_is_blocked(&self) -> bool {
        self.review_cleanup_unverified
            || self
                .fixture_recovery
                .as_ref()
                .is_some_and(|marker| marker.blocked().unwrap_or(true))
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[doc(hidden)]
    pub fn fixture_production_recovery_observation(
        &self,
    ) -> Option<&crate::recovery_state::RecoveryObservation> {
        self.recovery_observation.as_ref()
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

    pub fn selected_count(&self) -> usize {
        self.current_selection()
            .iter()
            .filter(|state| **state != SelectionState::Unselected)
            .count()
    }

    pub fn selection_state(&self, index: usize) -> SelectionState {
        self.current_selection()
            .get(index)
            .copied()
            .unwrap_or(SelectionState::Unselected)
    }

    pub fn toggle_selection(&mut self) {
        let Some(index) = self.table_state.selected() else {
            return;
        };
        if let Some(state) = self.current_selection_mut().get_mut(index) {
            *state = state.next();
        }
    }

    fn current_selection(&self) -> &Vec<SelectionState> {
        match self.active_tab {
            Tab::Local => &self.local_selection,
            Tab::Global => &self.global_selection,
        }
    }

    fn current_selection_mut(&mut self) -> &mut Vec<SelectionState> {
        match self.active_tab {
            Tab::Local => &mut self.local_selection,
            Tab::Global => &mut self.global_selection,
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

    pub fn copy_active_log(&mut self) {
        let Some(log) = self.upgrade_logs.get(self.log_popup_tab) else {
            return;
        };
        let log_text = log.lines.join("\n");
        match copy_to_clipboard(&log_text) {
            Ok(()) => self.push_toast(ToastKind::Success, t("toast_log_copied").to_string()),
            Err(error) => self.push_toast(ToastKind::Error, tf("toast_log_copy_failed", &[&error])),
        }
    }

    pub fn open_secret_input(&mut self) {
        self.modal = Modal::SecretInput {
            buffer: String::new(),
        };
    }

    pub fn open_review_settings(&mut self) {
        if self.active_review_attempt.is_some()
            || self.active_operation.is_some()
            || !self.pending_operations.is_empty()
        {
            self.push_toast(ToastKind::Error, t("review_settings_busy").into());
            return;
        }
        let provider =
            crate::secrets::ReviewApiProvider::from_config(self.config.review_provider())
                .unwrap_or(crate::secrets::ReviewApiProvider::OpenRouter);
        let model = self
            .config
            .security
            .review_model
            .clone()
            .unwrap_or_default();
        self.modal = Modal::ReviewSettings {
            provider,
            model,
            input: ReviewSettingsInput::Menu,
        };
    }

    pub fn review_settings_next_provider(&mut self, next: bool) {
        if let Modal::ReviewSettings {
            provider,
            model,
            input: ReviewSettingsInput::Menu,
        } = &mut self.modal
        {
            let providers = crate::secrets::ReviewApiProvider::ALL;
            let index = providers
                .iter()
                .position(|item| item == provider)
                .unwrap_or(0);
            *provider = providers[if next {
                (index + 1) % providers.len()
            } else {
                (index + providers.len() - 1) % providers.len()
            }];
            model.clear();
        }
    }

    pub fn review_settings_begin_input(&mut self, key: bool) {
        if let Modal::ReviewSettings { model, input, .. } = &mut self.modal {
            if matches!(input, ReviewSettingsInput::Menu) {
                *input = if key {
                    ReviewSettingsInput::Key(String::new())
                } else {
                    ReviewSettingsInput::Model(model.clone())
                };
            }
        }
    }

    pub fn review_settings_input_char(&mut self, character: Option<char>) {
        if let Modal::ReviewSettings { input, .. } = &mut self.modal {
            match input {
                ReviewSettingsInput::Model(buffer) | ReviewSettingsInput::Key(buffer) => {
                    if let Some(character) = character {
                        if !character.is_control() && buffer.len() < 8192 {
                            buffer.push(character);
                        }
                    } else {
                        buffer.pop();
                    }
                }
                ReviewSettingsInput::Menu => {}
            }
        }
    }

    pub fn review_settings_cancel(&mut self) {
        if let Modal::ReviewSettings { input, .. } = &mut self.modal {
            if !matches!(input, ReviewSettingsInput::Menu) {
                *input = ReviewSettingsInput::Menu;
                return;
            }
        }
        self.modal = Modal::None;
    }

    pub fn review_settings_submit(&mut self) {
        let provider = match &self.modal {
            Modal::ReviewSettings { provider, .. } => *provider,
            _ => return,
        };
        let store = crate::secrets::KeyringSecretStore::for_review_provider(provider);
        let selection = crate::secrets::KeyringSecretStore::for_review_selection();
        self.review_settings_submit_with_store(&store, &selection);
    }

    pub(crate) fn review_settings_submit_with_store(
        &mut self,
        store: &dyn SecretStore,
        selection: &dyn SecretStore,
    ) {
        let Modal::ReviewSettings {
            provider,
            model,
            input,
        } = &mut self.modal
        else {
            return;
        };
        match std::mem::replace(input, ReviewSettingsInput::Menu) {
            ReviewSettingsInput::Model(value) => {
                *model = value.trim().to_string();
            }
            ReviewSettingsInput::Key(value) => {
                if value.is_empty()
                    || value.len() > 8192
                    || !value.bytes().all(|b| (33..=126).contains(&b))
                {
                    self.push_toast(ToastKind::Error, t("review_settings_invalid_key").into());
                    return;
                }
                let message = if store.set_secret(&value).is_ok() {
                    self.review_cache.clear();
                    "review_settings_key_saved"
                } else {
                    "review_settings_key_error"
                };
                self.push_toast(ToastKind::Info, t(message).into());
            }
            ReviewSettingsInput::Menu => {
                if model.trim().is_empty()
                    || model.len() > 256
                    || model.chars().any(char::is_control)
                {
                    self.push_toast(ToastKind::Error, t("review_settings_invalid_model").into());
                    return;
                }
                let provider = *provider;
                let model = model.clone();
                if crate::secrets::save_review_selection(selection, provider, &model).is_err() {
                    self.push_toast(ToastKind::Error, t("review_settings_key_error").into());
                    return;
                }
                self.config.security.review_provider = Some(provider.id().into());
                self.config.security.review_model = Some(model.clone());
                self.review_session_config = Some((provider, model));
                self.review_cache.clear();
                self.modal = Modal::None;
                self.push_toast(ToastKind::Info, t("review_settings_selected").into());
            }
        }
    }

    pub fn restore_review_settings(&mut self) {
        let store = crate::secrets::KeyringSecretStore::for_review_selection();
        self.restore_review_settings_with_store(&store);
    }

    pub(crate) fn restore_review_settings_with_store(&mut self, store: &dyn SecretStore) {
        if self.config.security.review_provider.is_some()
            || self.config.security.review_model.is_some()
        {
            return;
        }
        match crate::secrets::read_review_selection(store) {
            Ok(Some((provider, model))) => {
                self.config.security.review_provider = Some(provider.id().into());
                self.config.security.review_model = Some(model.clone());
                self.review_session_config = Some((provider, model));
            }
            Ok(None) => {}
            Err(_) => self.push_toast(ToastKind::Error, t("review_settings_restore_error").into()),
        }
    }

    pub fn review_settings_remove_key(&mut self) {
        let provider = match &self.modal {
            Modal::ReviewSettings {
                provider,
                input: ReviewSettingsInput::Menu,
                ..
            } => *provider,
            _ => return,
        };
        let store = crate::secrets::KeyringSecretStore::for_review_provider(provider);
        self.review_settings_remove_key_with_store(&store);
    }

    fn review_settings_remove_key_with_store(&mut self, store: &dyn SecretStore) {
        if let Modal::ReviewSettings {
            input: ReviewSettingsInput::Menu,
            ..
        } = &self.modal
        {
            let message = if store.delete_secret().is_ok() {
                self.review_cache.clear();
                "review_settings_key_removed"
            } else {
                "review_settings_key_error"
            };
            self.push_toast(ToastKind::Info, t(message).into());
        }
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
            retain_recent_log_lines(&mut log.lines);
        } else {
            if self.upgrade_logs.len() == MAX_DEPENDENCY_LOGS {
                self.upgrade_logs.remove(0);
            }
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
        if self.active_operation.is_some() {
            return;
        }
        let Some(attempt) = self.reserve_scan_attempt() else {
            return;
        };
        self.status = AppStatus::Scanning;
        self.local_deps.clear();
        self.global_deps.clear();
        self.local_selection.clear();
        self.global_selection.clear();
        self.vuln_cache.clear();
        self.freshness_cache.clear();
        self.provenance_cache.clear();
        self.invalidate_pre_scan_security();
        self.table_state.select(None);

        let tx = self.event_tx.clone();
        let dir = self.target_dir.clone();

        tokio::spawn(async move {
            let deps = check_all_outdated(&dir).await;
            let _ = tx.send(AppEvent::ScanFinished(attempt, Tab::Local, deps));
        });

        let tx_global = self.event_tx.clone();
        tokio::spawn(async move {
            let deps = check_global_outdated().await;
            let _ = tx_global.send(AppEvent::ScanFinished(attempt, Tab::Global, deps));
        });
    }

    fn reserve_scan_attempt(&mut self) -> Option<u64> {
        self.pending_local_scan = None;
        self.pending_global_scan = None;
        let Some(attempt) = self.next_scan_attempt.checked_add(1) else {
            self.status =
                AppStatus::UpgradeFailed(String::new(), t("scan_attempt_exhausted").to_string());
            return None;
        };
        self.next_scan_attempt = attempt;
        self.pending_local_scan = Some(attempt);
        self.pending_global_scan = Some(attempt);
        Some(attempt)
    }

    pub async fn load_config_sync(&mut self) -> Result<(), crate::config::ConfigLoadError> {
        self.config = match Config::load_from_dir(&self.target_dir).await {
            Ok(config) => config,
            Err(error) => {
                self.config_load_failed = true;
                self.pending_local_scan = None;
                self.pending_global_scan = None;
                self.active_security_attempt = None;
                self.invalidate_pre_scan_security();
                self.active_review_attempt = None;
                self.active_impact_attempt = None;
                self.cancel_impact_task();
                let _ = self.cancel_review_gate();
                if let Some(task) = self.active_review_task.take() {
                    task.abort();
                }
                if matches!(
                    self.modal,
                    Modal::ConfirmImpact { .. }
                        | Modal::ConfirmReview(_, _)
                        | Modal::ConfirmForce(_, _)
                        | Modal::ConfirmOffline(_, _)
                        | Modal::ConfirmGlobal(_, _)
                ) {
                    self.modal = Modal::None;
                }
                return Err(error);
            }
        };
        if let Some((provider, model)) = &self.review_session_config {
            self.config.security.review_provider = Some(provider.id().into());
            self.config.security.review_model = Some(model.clone());
        }
        self.config_load_failed = false;
        if !self.config.pre_scan_security() {
            self.invalidate_pre_scan_security();
        }
        #[cfg(target_os = "linux")]
        {
            self.recovery_observation =
                crate::recovery_state::inspect_configured_codex(&self.config).await;
        }
        Ok(())
    }

    fn block_with_policy_message(&mut self, dep: Dependency, message: String) {
        let package_name = dep.name.clone();
        self.modal = Modal::BlockedPolicy(dep, message.clone());
        self.status = AppStatus::UpgradeFailed(package_name, message);
    }

    fn pending_result_block_reason(&self) -> Option<String> {
        if self.config_load_failed {
            return Some(crate::config::ConfigLoadError.to_string());
        }
        if self.review_cleanup_unverified {
            return Some(t("review_cleanup_blocked").to_string());
        }
        if self.impact_cleanup_unverified {
            return Some(t("impact_cleanup_blocked").to_string());
        }
        #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
        if self
            .fixture_recovery
            .as_ref()
            .is_some_and(|marker| marker.blocked().unwrap_or(true))
        {
            return Some(t("review_cleanup_blocked").to_string());
        }
        None
    }

    fn policy_block_reason(&self, dep: &Dependency) -> Option<String> {
        if self.config_load_failed {
            return Some(crate::config::ConfigLoadError.to_string());
        }
        if self.review_cleanup_unverified {
            return Some(t("review_cleanup_blocked").to_string());
        }
        if self.impact_cleanup_unverified {
            return Some(t("impact_cleanup_blocked").to_string());
        }
        #[cfg(target_os = "linux")]
        if crate::review::needs_review(dep)
            && crate::recovery_state::codex_recovery_preflight(&self.config).is_err()
        {
            return Some(t("codex_recovery_unavailable").to_string());
        }
        #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
        if self
            .fixture_recovery
            .as_ref()
            .is_some_and(|marker| marker.blocked().unwrap_or(true))
        {
            return Some(t("review_cleanup_blocked").to_string());
        }
        if matches!(dep.origin, Some(PackageOrigin::Aur)) && !self.config.aur_enabled() {
            return Some(t("blocked_aur_disabled").to_string());
        }

        if dep.ecosystem == Ecosystem::Pacman
            && self.config.require_provenance()
            && !self
                .provenance_cache
                .get(&cache_key(dep))
                .is_some_and(|info| info.signature_verified)
        {
            return Some(t("blocked_provenance_required").to_string());
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
            self.start_impact_preview(dep);
        }
    }

    pub fn confirm_force_upgrade(&mut self) {
        let Some(operation) = self.active_operation.clone() else {
            return;
        };
        if matches!(
            self.modal,
            Modal::ConfirmForce(_, _) | Modal::ConfirmReview(_, _) | Modal::ConfirmOffline(_, _)
        ) {
            self.modal = Modal::None;
            self.start_upgrade(operation.dep, true);
        }
    }

    pub fn dismiss_modal(&mut self) {
        self.modal = Modal::None;
        self.finish_operation(false);
    }

    fn trigger_pre_scan_for_dependencies(&mut self, all_deps: Vec<Dependency>) {
        if !self.config.pre_scan_security() {
            return;
        }
        #[cfg(test)]
        let suppress_workers = if let Some(observations) = &mut self.pre_scan_test_observations {
            observations.push(all_deps.clone());
            true
        } else {
            false
        };
        #[cfg(not(test))]
        let suppress_workers = false;

        let timeout = self.config.osv_timeout_secs();
        let threshold = self.config.freshness_threshold_days();
        let very_recent = self.config.very_recent_days();
        let nvd_key = if suppress_workers {
            None
        } else {
            resolve_nvd_api_key(&*self.secret_store)
        };

        for dep in &all_deps {
            let cache_key = format!(
                "{}_{}_{}",
                dep.ecosystem.as_str(),
                dep.name,
                dep.latest_version
            );

            // OSV + NVD check
            if dep.ecosystem.has_osv_coverage()
                && !self.vuln_cache.contains_key(&cache_key)
                && !self
                    .pending_pre_scan_security
                    .values()
                    .any(|pending| scan_cache_key(pending) == cache_key)
            {
                if let Some(attempt) = self.reserve_pre_scan_security_attempt(dep) {
                    self.batch_scan_pending += 1;
                    if !suppress_workers {
                        let tx = self.event_tx.clone();
                        let d = dep.clone();
                        let key = nvd_key.clone();
                        tokio::spawn(async move {
                            let checker = SecurityChecker::new_with_config(timeout, key);
                            let result = checker
                                .check_vulnerability(&d.name, &d.latest_version, d.ecosystem)
                                .await;
                            let _ = tx.send(AppEvent::SecurityChecked(
                                Some(attempt),
                                d,
                                result.map_err(AuditFailure::from),
                                true,
                            ));
                        });
                    }
                }
            }

            // Freshness check (cargo + npm)
            if matches!(dep.ecosystem, Ecosystem::Cargo | Ecosystem::Npm)
                && !self.freshness_cache.contains_key(&cache_key)
                && !self
                    .pending_pre_scan_freshness
                    .values()
                    .any(|pending| scan_cache_key(pending) == cache_key)
            {
                if let Some(attempt) =
                    self.reserve_pre_scan_metadata(dep, PreScanMetadataKind::Freshness)
                {
                    if !suppress_workers {
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
                            let _ = tx.send(AppEvent::FreshnessChecked(attempt, d, freshness));
                        });
                    }
                }
            }

            // Provenance check (pacman)
            if dep.ecosystem == Ecosystem::Pacman
                && !self.provenance_cache.contains_key(&cache_key)
                && !self
                    .pending_pre_scan_provenance
                    .values()
                    .any(|pending| scan_cache_key(pending) == cache_key)
            {
                if let Some(attempt) =
                    self.reserve_pre_scan_metadata(dep, PreScanMetadataKind::Provenance)
                {
                    if !suppress_workers {
                        let tx = self.event_tx.clone();
                        let d = dep.clone();
                        tokio::spawn(async move {
                            let info = check_provenance(&d.name, Ecosystem::Pacman).await;
                            let _ = tx.send(AppEvent::ProvenanceChecked(attempt, d, info));
                        });
                    }
                }
            }
        }
    }

    pub fn trigger_upgrade_selected(&mut self, force: bool) {
        self.queue_selected_operations(OperationKind::Upgrade, force);
    }

    fn queue_selected_operations(&mut self, kind: OperationKind, force_all: bool) {
        if self.active_operation.is_some()
            || !self.pending_operations.is_empty()
            || (self.status != AppStatus::Ready
                && !matches!(self.status, AppStatus::UpgradeFailed(_, _)))
        {
            return;
        }

        let selected_operations: Vec<QueuedOperation> = self
            .current_deps()
            .iter()
            .enumerate()
            .filter_map(|(index, dep)| {
                let state = self.selection_state(index);
                if state == SelectionState::Unselected {
                    None
                } else {
                    Some(QueuedOperation {
                        dep: dep.clone(),
                        force: force_all || state == SelectionState::Force,
                        kind,
                    })
                }
            })
            .collect();

        if selected_operations.is_empty() {
            let Some(dep) = self.selected_dep().cloned() else {
                return;
            };
            self.pending_operations.push_back(QueuedOperation {
                dep,
                force: force_all,
                kind,
            });
        } else {
            self.pending_operations.extend(selected_operations);
        }
        self.start_next_operation();
    }

    fn start_next_operation(&mut self) {
        if self.review_cleanup_unverified || self.impact_cleanup_unverified {
            return;
        }
        let Some(operation) = self.pending_operations.pop_front() else {
            return;
        };
        self.active_operation = Some(operation.clone());
        match operation.kind {
            OperationKind::Upgrade => self.start_upgrade_operation(operation.dep, operation.force),
            OperationKind::Audit => self.start_security_audit(operation.dep),
        }
    }

    fn finish_operation(&mut self, refresh: bool) {
        let cancellation_ok = self.cancel_review_gate();
        self.active_review_attempt = None;
        self.active_security_attempt = None;
        self.active_impact_attempt = None;
        self.cancel_impact_task();
        if let Some(task) = self.active_review_task.take() {
            // Cancels the async task only; external work and descendants need
            // their own supervisor and may outlive this request.
            task.abort();
        }
        self.active_operation = None;
        if !cancellation_ok || self.review_cleanup_unverified || self.impact_cleanup_unverified {
            return;
        }
        if !self.pending_operations.is_empty() {
            self.status = AppStatus::Ready;
            self.start_next_operation();
        } else if refresh {
            self.trigger_scan();
        } else if !matches!(self.status, AppStatus::UpgradeFailed(_, _)) {
            self.status = AppStatus::Ready;
        }
    }

    fn cancel_impact_task(&mut self) {
        if let Some(task) = self.active_impact_task.take() {
            if !task.is_finished() {
                // Dropping the preview future requests termination of its direct
                // child only; descendants and reaping remain unverified.
                self.impact_cleanup_unverified = true;
                task.abort();
            }
        }
    }

    fn cancel_review_gate(&mut self) -> bool {
        if let Some(gate) = self.active_review_gate.take() {
            let failure_key = match gate.cancel_with_unit() {
                Err(_) => Some("review_cancel_failed"),
                Ok(true) => Some("review_cleanup_unverified"),
                Ok(_) => None,
            };
            if let Some(failure_key) = failure_key {
                self.review_cleanup_unverified = true;
                let message = t(failure_key).to_string();
                let name = self
                    .active_operation
                    .as_ref()
                    .map(|operation| operation.dep.name.clone())
                    .unwrap_or_else(|| t("dependency_fallback").to_string());
                self.status = AppStatus::UpgradeFailed(name, message.clone());
                self.push_toast(ToastKind::Error, message);
                return false;
            }
        }
        true
    }

    /// Request review cancellation before leaving the terminal. A successful
    /// request is not proof that external processes or descendants are gone.
    pub fn shutdown_review(&mut self) -> Result<(), String> {
        let cancellation_ok = self.cancel_review_gate();
        self.active_review_attempt = None;
        self.active_impact_attempt = None;
        self.cancel_impact_task();
        if let Some(task) = self.active_review_task.take() {
            task.abort();
        }
        if !cancellation_ok {
            if let AppStatus::UpgradeFailed(_, message) = &self.status {
                return Err(message.clone());
            }
            return Err(t("review_cleanup_blocked").to_string());
        }
        if self.review_cleanup_unverified {
            return Err(t("review_cleanup_blocked").to_string());
        }
        if self.impact_cleanup_unverified {
            return Err(t("impact_cleanup_blocked").to_string());
        }
        Ok(())
    }

    fn start_upgrade_operation(&mut self, dep: Dependency, force: bool) {
        if let Some(message) = self.policy_block_reason(&dep) {
            self.block_with_policy_message(dep, message);
            return;
        }

        if !dep.is_global && !is_safe_path(&self.target_dir) {
            self.finish_operation(false);
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
                Err(error) if error.partial => {
                    self.block_partial_audit(dep, error.clone());
                }
                Err(err_msg) if self.config.require_online() => {
                    self.block_with_policy_message(
                        dep,
                        tf("blocked_online_required", &[&err_msg.message]),
                    );
                }
                Err(_) if force => {
                    self.start_upgrade(dep, true);
                }
                Err(err_msg) => {
                    self.status = AppStatus::UpgradeFailed(
                        dep.name.clone(),
                        tf("security_check_error", &[&err_msg.message]),
                    );
                    self.push_toast(
                        ToastKind::Error,
                        tf("toast_security_check_failed", &[&dep.name]),
                    );
                    self.finish_operation(false);
                }
            }
            return;
        }

        let Some(attempt) = self.reserve_security_attempt(&dep) else {
            return;
        };
        self.status = AppStatus::Upgrading(tf("audit_label", &[&dep.name]));
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
                    let _ = tx.send(AppEvent::SecurityChecked(
                        Some(attempt),
                        d,
                        Ok(vulns),
                        false,
                    ));
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::SecurityChecked(
                        Some(attempt),
                        d,
                        Err(e.into()),
                        false,
                    ));
                }
            }
        });
    }

    pub fn check_security_selected(&mut self) {
        self.queue_selected_operations(OperationKind::Audit, false);
    }

    fn start_security_audit(&mut self, dep: Dependency) {
        #[cfg(all(target_os = "linux", feature = "review-pty-fixture"))]
        if crate::review_pty_fixture::endpoint().is_some() && dep.name == "tucupi-synthetic-package"
        {
            self.process_security_result(dep, Ok(Vec::new()), false);
            return;
        }
        if !dep.is_global && !is_safe_path(&self.target_dir) {
            self.finish_operation(false);
            return;
        }

        let cache_key = format!(
            "{}_{}_{}",
            dep.ecosystem.as_str(),
            dep.name,
            dep.latest_version
        );

        if self.vuln_cache.contains_key(&cache_key) {
            self.finish_operation(false);
            return;
        }

        let Some(attempt) = self.reserve_security_attempt(&dep) else {
            return;
        };
        self.status = AppStatus::Upgrading(tf("audit_label", &[&dep.name]));
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
                    let _ = tx.send(AppEvent::SecurityChecked(
                        Some(attempt),
                        d,
                        Ok(vulns),
                        false,
                    ));
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::SecurityChecked(
                        Some(attempt),
                        d,
                        Err(e.into()),
                        false,
                    ));
                }
            }
        });
    }

    pub fn process_security_result(
        &mut self,
        dep: Dependency,
        res: Result<Vec<VulnerabilityInfo>, AuditFailure>,
        from_pre_scan: bool,
    ) {
        if !from_pre_scan {
            self.invalidate_matching_pre_scan_security(&dep);
        }
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

        if matches!(
            self.active_operation
                .as_ref()
                .map(|operation| operation.kind),
            Some(OperationKind::Audit)
        ) {
            if review::needs_review(&dep) && self.config.pkgbuild_review() {
                self.spawn_review_task(dep, false, true);
            } else {
                self.finish_operation(false);
            }
            return;
        }

        match res {
            Ok(vulns) => {
                let force = self
                    .active_operation
                    .as_ref()
                    .is_some_and(|operation| operation.force);
                self.process_upgrade_with_vulns(dep, vulns, force);
            }
            Err(err_msg) if err_msg.partial => self.block_partial_audit(dep, err_msg),
            Err(err_msg) => {
                if self.config.require_online() {
                    self.block_with_policy_message(
                        dep,
                        tf("blocked_online_required", &[&err_msg.message]),
                    );
                } else if self.config.block_vulnerable() {
                    let package_name = dep.name.clone();
                    self.status = AppStatus::UpgradeFailed(
                        package_name.clone(),
                        tf("security_check_blocked", &[&err_msg.message]),
                    );
                    self.push_toast(
                        ToastKind::Error,
                        tf("toast_security_check_failed", &[&package_name]),
                    );
                    self.finish_operation(false);
                } else {
                    self.modal = Modal::ConfirmOffline(dep, err_msg.message);
                    self.status = AppStatus::Ready;
                }
            }
        }
    }

    fn reserve_security_attempt(&mut self, dep: &Dependency) -> Option<u64> {
        self.invalidate_matching_pre_scan_security(dep);
        let Some(next) = self.next_security_attempt.checked_add(1) else {
            self.active_security_attempt = None;
            self.block_with_policy_message(dep.clone(), t("batch_attempt_exhausted").to_string());
            return None;
        };
        self.next_security_attempt = next;
        self.active_security_attempt = Some(next);
        Some(next)
    }

    fn reserve_pre_scan_security_attempt(&mut self, dep: &Dependency) -> Option<u64> {
        let next = self.next_security_attempt.checked_add(1)?;
        self.next_security_attempt = next;
        self.pending_pre_scan_security.insert(next, dep.clone());
        Some(next)
    }

    fn invalidate_pre_scan_security(&mut self) {
        self.pending_pre_scan_security.clear();
        self.pending_pre_scan_freshness.clear();
        self.pending_pre_scan_provenance.clear();
        self.batch_scan_pending = 0;
    }

    fn invalidate_matching_pre_scan_security(&mut self, dep: &Dependency) {
        let key = format!(
            "{}_{}_{}",
            dep.ecosystem.as_str(),
            dep.name,
            dep.latest_version
        );
        let before = self.pending_pre_scan_security.len();
        self.pending_pre_scan_security.retain(|_, pending| {
            format!(
                "{}_{}_{}",
                pending.ecosystem.as_str(),
                pending.name,
                pending.latest_version
            ) != key
        });
        let removed = before - self.pending_pre_scan_security.len();
        self.batch_scan_pending = self.batch_scan_pending.saturating_sub(removed);
    }

    fn reserve_pre_scan_metadata(
        &mut self,
        dep: &Dependency,
        kind: PreScanMetadataKind,
    ) -> Option<u64> {
        let next = self.next_security_attempt.checked_add(1)?;
        self.next_security_attempt = next;
        match kind {
            PreScanMetadataKind::Freshness => &mut self.pending_pre_scan_freshness,
            PreScanMetadataKind::Provenance => &mut self.pending_pre_scan_provenance,
        }
        .insert(next, dep.clone());
        Some(next)
    }

    fn block_partial_audit(&mut self, dep: Dependency, error: AuditFailure) {
        let ids = error
            .findings
            .iter()
            .map(|v| v.id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        self.block_with_policy_message(dep, tf("audit_partial_blocked", &[&ids]));
    }

    fn review_cache_key(&self, dep: &Dependency) -> String {
        format!(
            "{}_{}_{}_{}_{}_{:?}_{}_{:?}",
            dep.ecosystem.as_str(),
            dep.name,
            dep.current_version,
            dep.latest_version,
            self.config.review_provider(),
            self.config.security.review_model,
            self.config.review_llm(),
            self.config.security.codex_auth_mode
        )
    }

    fn spawn_pkgbuild_review(&mut self, dep: Dependency, force: bool) {
        self.status = AppStatus::Upgrading(tf("review_started", &[&dep.name]));
        self.spawn_review_task(dep, force, false);
    }

    fn spawn_review_task(&mut self, dep: Dependency, force: bool, audit_only: bool) {
        let config = self.config.clone();
        let review_dep = dep.clone();
        self.spawn_review_future_with_gate(dep, force, audit_only, move |control| async move {
            review::review_package_with_control(&review_dep, &config, &control).await
        });
    }

    #[cfg(test)]
    fn spawn_review_future(
        &mut self,
        dep: Dependency,
        force: bool,
        audit_only: bool,
        future: impl std::future::Future<Output = ReviewReport> + Send + 'static,
    ) {
        self.spawn_review_future_with_gate(dep, force, audit_only, |_| future);
    }

    fn spawn_review_future_with_gate<F, Fut>(
        &mut self,
        dep: Dependency,
        force: bool,
        audit_only: bool,
        make_future: F,
    ) where
        F: FnOnce(Arc<review::FixtureStartGate>) -> Fut,
        Fut: std::future::Future<Output = ReviewReport> + Send + 'static,
    {
        let Some(attempt) = self.next_review_attempt.checked_add(1) else {
            self.active_review_attempt = None;
            self.block_with_policy_message(dep, t("review_unparsable").to_string());
            self.finish_operation(false);
            return;
        };
        self.next_review_attempt = attempt;
        self.active_review_attempt = Some(attempt);
        let cancellation_ok = self.cancel_review_gate();
        if let Some(task) = self.active_review_task.take() {
            task.abort();
        }
        if !cancellation_ok || self.review_cleanup_unverified || self.impact_cleanup_unverified {
            self.active_review_attempt = None;
            return;
        }
        #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
        let gate = Arc::new(match &self.fixture_recovery {
            Some(marker) => review::FixtureStartGate::with_fixture_recovery(marker.clone()),
            None => review::FixtureStartGate::default(),
        });
        #[cfg(not(all(target_os = "linux", feature = "codex-fixture")))]
        let gate = Arc::new(review::FixtureStartGate::default());
        let future = make_future(gate.clone());
        self.active_review_gate = Some(gate);
        let tx = self.event_tx.clone();
        self.active_review_task = Some(tokio::spawn(async move {
            // Do not launch the worker before the supervisor is first polled:
            // an attempt cancelled while queued must not start its work.
            let worker = tokio::spawn(future);
            let abort_worker = AbortReviewWorker(worker.abort_handle());
            let _abort_worker = abort_worker;
            let (report, result_force) = match worker.await {
                Ok(report) => (report, force),
                // A force request made before this failure is not confirmation
                // of the newly discovered inconclusive review.
                Err(_) => (
                    ReviewReport::unavailable("source review task failed — treat as unreviewed"),
                    false,
                ),
            };
            let _ = tx.send(AppEvent::ReviewChecked(
                attempt,
                dep,
                report,
                result_force,
                audit_only,
            ));
        }));
    }

    fn process_review_result(
        &mut self,
        dep: Dependency,
        report: ReviewReport,
        force: bool,
        audit_only: bool,
    ) {
        let report = review::enforce_provider_availability(report, &self.config);
        let cache_key = self.review_cache_key(&dep);
        self.review_cache.insert(cache_key, report.clone());

        if audit_only {
            if report.verdict != ReviewVerdict::Safe {
                self.modal = Modal::BlockedPolicy(
                    dep,
                    tf(
                        "review_audit_result",
                        &[
                            report.verdict.display_label(),
                            &review::display_review_reason(&report.reason),
                        ],
                    ),
                );
            } else {
                self.finish_operation(false);
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
                self.block_with_policy_message(
                    dep,
                    tf(
                        "review_blocked",
                        &[&review::display_review_reason(&report.reason)],
                    ),
                );
            }
            ReviewVerdict::Review => {
                self.status = AppStatus::Ready;
                if force {
                    self.start_upgrade(dep, true);
                } else {
                    self.modal = Modal::ConfirmReview(dep, report);
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
        if let Some(message) = self.pending_result_block_reason() {
            self.block_with_policy_message(dep, message);
            return;
        }
        if review::needs_review(&dep) && self.config.pkgbuild_review() {
            let cache_key = self.review_cache_key(&dep);
            let cached = self
                .review_cache
                .get(&cache_key)
                .cloned()
                .map(|report| review::enforce_provider_availability(report, &self.config));
            match cached {
                Some(report) => match report.verdict {
                    ReviewVerdict::Safe => {}
                    ReviewVerdict::Block => {
                        self.status = AppStatus::Ready;
                        self.block_with_policy_message(
                            dep,
                            tf(
                                "review_blocked",
                                &[&review::display_review_reason(&report.reason)],
                            ),
                        );
                        return;
                    }
                    ReviewVerdict::Review => {
                        if !force {
                            self.status = AppStatus::Ready;
                            self.modal = Modal::ConfirmReview(dep, report);
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
            let Some((command, args)) = get_upgrade_cmd(&dep, &self.target_dir) else {
                self.block_with_policy_message(dep, t("upgrade_unsupported").to_string());
                self.finish_operation(false);
                return;
            };
            let command_line = format!("{} {}", command, args.join(" "));
            self.modal = Modal::ConfirmGlobal(dep, command_line);
            self.status = AppStatus::Ready;
            return;
        }

        self.start_impact_preview(dep);
    }

    fn start_impact_preview(&mut self, dep: Dependency) {
        if let Some(message) = self.policy_block_reason(&dep) {
            self.block_with_policy_message(dep, message);
            return;
        }
        self.cancel_impact_task();
        if self.impact_cleanup_unverified {
            self.block_with_policy_message(dep, t("impact_cleanup_blocked").to_string());
            return;
        }
        let dir = self.target_dir.clone();
        let preview_dep = dep.clone();
        self.spawn_impact_future(dep, async move {
            crate::impact::preview(&preview_dep, &dir).await
        });
    }

    fn spawn_impact_future(
        &mut self,
        dep: Dependency,
        future: impl std::future::Future<Output = crate::impact::ImpactPreview> + Send + 'static,
    ) {
        let Some(attempt) = self.next_impact_attempt.checked_add(1) else {
            self.active_impact_attempt = None;
            self.block_with_policy_message(dep, t("review_unparsable").to_string());
            return;
        };
        self.next_impact_attempt = attempt;
        self.active_impact_attempt = Some(attempt);
        self.status = AppStatus::Upgrading(tf("impact_checking", &[&dep.name]));
        let tx = self.event_tx.clone();
        self.active_impact_task = Some(tokio::spawn(async move {
            let preview = future.await;
            let _ = tx.send(AppEvent::ImpactChecked(attempt, dep, preview));
        }));
    }

    pub fn confirm_impact(&mut self) {
        if let Modal::ConfirmImpact { dep, .. } = self.modal.clone() {
            self.modal = Modal::None;
            self.start_upgrade_confirmed(dep);
        }
    }

    fn start_upgrade_confirmed(&mut self, dep: Dependency) {
        if let Some(message) = self.policy_block_reason(&dep) {
            self.block_with_policy_message(dep, message);
            return;
        }
        let Some((cmd, args)) = get_upgrade_cmd(&dep, &self.target_dir) else {
            self.block_with_policy_message(dep, t("upgrade_unsupported").to_string());
            self.finish_operation(false);
            return;
        };
        let is_cargo_local = !dep.is_global && dep.ecosystem == Ecosystem::Cargo;
        self.status = AppStatus::Upgrading(tf("exec_upgrading", &[&dep.name, &dep.latest_version]));
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
                        let _ = tx.send(AppEvent::UpgradeFinished(Err(tf(
                            "backup_prepare_failed",
                            &[&error.to_string()],
                        ))));
                        return;
                    }
                }
            };

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
                        .unwrap_or(t("cargo_update_failed"))
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

            let _ = tx.send(AppEvent::UpgradeFinished(result));
        });
    }

    pub fn handle_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::ImpactChecked(attempt, dep, preview) => {
                if self.active_impact_attempt != Some(attempt) {
                    return;
                }
                self.active_impact_attempt = None;
                self.active_impact_task = None;
                if let Some(message) = self.pending_result_block_reason() {
                    self.block_with_policy_message(dep, message);
                    return;
                }
                self.status = AppStatus::Ready;
                self.modal = Modal::ConfirmImpact {
                    dep,
                    preview,
                    scroll: 0,
                };
            }
            AppEvent::ScanFinished(attempt, tab, deps) => {
                let pending = match tab {
                    Tab::Local => &mut self.pending_local_scan,
                    Tab::Global => &mut self.pending_global_scan,
                };
                if *pending != Some(attempt) {
                    return;
                }
                *pending = None;
                let pre_scan_deps = deps.clone();
                match tab {
                    Tab::Local => {
                        self.local_selection = vec![SelectionState::Unselected; deps.len()];
                        self.local_deps = deps;
                    }
                    Tab::Global => {
                        self.global_selection = vec![SelectionState::Unselected; deps.len()];
                        self.global_deps = deps;
                    }
                }
                if self.status == AppStatus::Scanning {
                    self.status = AppStatus::Ready;
                    self.table_state.select(if self.current_deps().is_empty() {
                        None
                    } else {
                        Some(0)
                    });
                    self.detail_scroll = 0;
                }
                self.trigger_pre_scan_for_dependencies(pre_scan_deps);
            }
            AppEvent::SecurityChecked(attempt, dep, res, from_pre_scan) => {
                if from_pre_scan {
                    let Some(attempt) = attempt else {
                        return;
                    };
                    if self.pending_result_block_reason().is_some()
                        || self.pending_pre_scan_security.get(&attempt) != Some(&dep)
                    {
                        return;
                    }
                    self.pending_pre_scan_security.remove(&attempt);
                } else {
                    if attempt.is_none()
                        || self.active_security_attempt != attempt
                        || self
                            .active_operation
                            .as_ref()
                            .is_none_or(|operation| operation.dep != dep)
                    {
                        return;
                    }
                    self.active_security_attempt = None;
                    if let Some(message) = self.pending_result_block_reason() {
                        self.block_with_policy_message(dep, message);
                        return;
                    }
                }
                self.process_security_result(dep, res, from_pre_scan);
            }
            AppEvent::FreshnessChecked(attempt, dep, freshness) => {
                if self.pending_result_block_reason().is_some()
                    || self.pending_pre_scan_freshness.get(&attempt) != Some(&dep)
                {
                    return;
                }
                self.pending_pre_scan_freshness.remove(&attempt);
                let cache_key = format!(
                    "{}_{}_{}",
                    dep.ecosystem.as_str(),
                    dep.name,
                    dep.latest_version
                );
                self.freshness_cache.insert(cache_key, freshness);
            }
            AppEvent::ProvenanceChecked(attempt, dep, info) => {
                if self.pending_result_block_reason().is_some()
                    || self.pending_pre_scan_provenance.get(&attempt) != Some(&dep)
                {
                    return;
                }
                self.pending_pre_scan_provenance.remove(&attempt);
                let cache_key = format!(
                    "{}_{}_{}",
                    dep.ecosystem.as_str(),
                    dep.name,
                    dep.latest_version
                );
                self.provenance_cache.insert(cache_key, info);
            }
            AppEvent::ReviewChecked(attempt, dep, report, force, audit_only) => {
                if self.active_review_attempt != Some(attempt) {
                    return;
                }
                self.active_review_attempt = None;
                let cancellation_ok = self.cancel_review_gate();
                if let Some(task) = self.active_review_task.take() {
                    task.abort();
                }
                if cancellation_ok {
                    if let Some(message) = self.pending_result_block_reason() {
                        self.block_with_policy_message(dep, message);
                        return;
                    }
                    self.process_review_result(dep, report, force, audit_only);
                }
            }
            AppEvent::UpgradeLog(name, line) => {
                self.append_upgrade_log(&name, line);
            }
            AppEvent::UpgradeFinished(res) => match res {
                Ok(_) => {
                    let name = self
                        .active_operation
                        .as_ref()
                        .map(|operation| operation.dep.name.clone())
                        .unwrap_or_else(|| t("dependency_fallback").to_string());
                    self.push_toast(ToastKind::Success, tf("toast_upgrade_success", &[&name]));
                    self.status = AppStatus::UpgradeSuccess(name);
                    self.finish_operation(true);
                }
                Err(err_msg) => {
                    let name = self
                        .active_operation
                        .as_ref()
                        .map(|operation| operation.dep.name.clone())
                        .unwrap_or_else(|| t("dependency_fallback").to_string());
                    self.push_toast(ToastKind::Error, tf("toast_upgrade_failed", &[&name]));
                    self.status = AppStatus::UpgradeFailed(name, err_msg);
                    self.finish_operation(false);
                }
            },
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        if let Some(task) = self.active_impact_task.take() {
            task.abort();
        }
        if let Some(gate) = self.active_review_gate.take() {
            let _ = gate.cancel();
        }
        if let Some(task) = self.active_review_task.take() {
            task.abort();
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

pub(crate) fn get_upgrade_cmd(
    dep: &Dependency,
    target_dir: &Path,
) -> Option<(String, Vec<String>)> {
    let clean_version = strip_build_metadata(&dep.latest_version).to_string();

    Some(if dep.is_global {
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
                    "--locked".to_string(),
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
            _ => return None,
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
            Ecosystem::Pacman | Ecosystem::Mise | Ecosystem::Homebrew => return None,
        }
    })
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
            return Err(t("sudo_not_cached").to_string());
        }
    }

    let mut child = tokio::process::Command::new(cmd)
        .args(&args)
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| tf("process_start_failed", &[&e.to_string()]))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| t("process_stdout_failed").to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| t("process_stderr_failed").to_string())?;
    let stdout_reader = tokio::spawn(collect_stream_lines(stdout, log_tx.clone()));
    let stderr_reader = tokio::spawn(collect_stream_lines(stderr, log_tx));

    let wait_result =
        tokio::time::timeout(Duration::from_secs(UPGRADE_TIMEOUT_SECS), child.wait()).await;

    let status = match wait_result {
        Ok(wait_status) => wait_status.map_err(|e| tf("process_wait_failed", &[&e.to_string()]))?,
        Err(_elapsed) => {
            let _ = child.kill().await;
            let _ = stdout_reader.await;
            let _ = stderr_reader.await;
            return Err(tf("process_timeout", &[&UPGRADE_TIMEOUT_SECS.to_string()]));
        }
    };

    let _ = stdout_reader.await;
    let stderr_lines = stderr_reader.await.unwrap_or_default();

    if status.success() {
        return Ok(());
    }

    let exit_code = status.code().map_or_else(
        || t("process_unknown_exit").to_string(),
        |code| code.to_string(),
    );
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
    Err(tf(
        "process_error_details",
        &[&command_line, &last_error, &exit_code, &hint],
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

fn retain_recent_log_lines(lines: &mut Vec<String>) {
    let excess = lines.len().saturating_sub(MAX_LOG_LINES_PER_DEPENDENCY);
    if excess > 0 {
        lines.drain(..excess);
    }
}

fn copy_to_clipboard(text: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut command = Command::new("pbcopy");
    #[cfg(target_os = "windows")]
    let mut command = Command::new("clip");
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = Command::new("xclip");
    #[cfg(all(unix, not(target_os = "macos")))]
    command.args(["-selection", "clipboard"]);

    let mut child = command
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| t("clipboard_input_failed").to_string())?;
    stdin
        .write_all(text.as_bytes())
        .map_err(|error| error.to_string())?;
    let status = child.wait().map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(t("clipboard_command_failed").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn review_settings_restart_and_local_review_journey() {
        use crate::secrets::{MemorySecretStore, ReviewApiProvider};
        use std::io::{Read, Write};
        for provider in ReviewApiProvider::ALL {
            let selection = MemorySecretStore::default();
            let key = MemorySecretStore::default();
            let mut app = App::new(PathBuf::from("."), false);
            app.modal = Modal::ReviewSettings {
                provider,
                model: "synthetic-model".into(),
                input: ReviewSettingsInput::Key("synthetic-key".into()),
            };
            app.review_settings_submit_with_store(&key, &selection);
            app.review_settings_submit_with_store(&key, &selection);
            let mut restarted = App::new(PathBuf::from("."), false);
            restarted.restore_review_settings_with_store(&selection);
            assert_eq!(restarted.config.review_provider(), provider.id());
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = [0; 8192];
                let size = stream.read(&mut bytes).unwrap();
                assert!(String::from_utf8_lossy(&bytes[..size]).contains("synthetic-key"));
                let answer = "VERDICT: review\nREASON: synthetic";
                let body = match provider {
                    ReviewApiProvider::OpenAi => serde_json::json!({"status":"completed","output":[{"type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":answer}]}]}),
                    ReviewApiProvider::Anthropic => serde_json::json!({"stop_reason":"end_turn","content":[{"type":"text","text":answer}]}),
                    _ => serde_json::json!({"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":answer}}]}),
                }.to_string();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            });
            let result = crate::review::llm_api_with(
                &restarted.config,
                "synthetic source",
                &key,
                |provider, model, prompt, key| async move {
                    let client = reqwest::Client::builder().no_proxy().build().unwrap();
                    crate::review_api::request_with_client(
                        &client,
                        &format!("http://{address}/review"),
                        provider,
                        &model,
                        &prompt,
                        &key,
                    )
                    .await
                },
            )
            .await;
            assert_eq!(
                result,
                Some((crate::review::ReviewVerdict::Review, "synthetic".into()))
            );
            server.join().unwrap();
            key.delete_secret().unwrap();
            assert!(crate::review::llm_api_with(
                &restarted.config,
                "synthetic",
                &key,
                |_, _, _, _| async { panic!("missing key dispatched") }
            )
            .await
            .is_none());
        }
    }

    #[test]
    fn review_selection_failure_does_not_activate_provider() {
        let key = crate::secrets::MemorySecretStore::default();
        let selection = crate::secrets::FailingSecretStore;
        let mut app = App::new(PathBuf::from("."), false);
        app.modal = Modal::ReviewSettings {
            provider: crate::secrets::ReviewApiProvider::OpenAi,
            model: "synthetic-model".into(),
            input: ReviewSettingsInput::Menu,
        };
        app.review_settings_submit_with_store(&key, &selection);
        assert_eq!(app.config.review_provider(), "opencode");
    }

    #[test]
    fn review_settings_saves_and_removes_synthetic_keys_for_each_provider() {
        for provider in crate::secrets::ReviewApiProvider::ALL {
            let store = crate::secrets::MemorySecretStore::default();
            let mut app = App::new(std::path::PathBuf::from("."), false);
            app.modal = Modal::ReviewSettings {
                provider,
                model: String::new(),
                input: ReviewSettingsInput::Key("synthetic-key".into()),
            };
            app.review_settings_submit_with_store(&store, &store);
            assert_eq!(
                store.get_secret().unwrap().as_deref(),
                Some("synthetic-key")
            );
            app.review_settings_remove_key_with_store(&store);
            assert_eq!(store.get_secret().unwrap(), None);
        }
    }

    #[tokio::test]
    async fn review_settings_selects_explicit_model_and_survives_config_reload() {
        let directory = tempfile::tempdir().unwrap();
        let mut app = App::new(directory.path().to_path_buf(), false);
        let store = crate::secrets::MemorySecretStore::default();
        app.open_review_settings();
        app.review_settings_next_provider(true);
        app.review_settings_begin_input(false);
        for character in "synthetic-model".chars() {
            app.review_settings_input_char(Some(character));
        }
        app.review_settings_submit_with_store(&store, &store);
        app.review_settings_submit_with_store(&store, &store);
        assert_eq!(app.config.review_provider(), "openai");
        assert_eq!(
            app.config.security.review_model.as_deref(),
            Some("synthetic-model")
        );
        let mut restarted = App::new(directory.path().to_path_buf(), false);
        restarted.restore_review_settings_with_store(&store);
        assert_eq!(restarted.config.review_provider(), "openai");
        assert_eq!(
            restarted.config.security.review_model.as_deref(),
            Some("synthetic-model")
        );
        app.load_config_sync().await.unwrap();
        assert_eq!(app.config.review_provider(), "openai");
        assert_eq!(
            app.config.security.review_model.as_deref(),
            Some("synthetic-model")
        );
    }

    #[test]
    fn review_settings_does_not_select_empty_model_and_cancel_discards_key() {
        let mut app = App::new(std::path::PathBuf::from("."), false);
        app.open_review_settings();
        let store = crate::secrets::MemorySecretStore::default();
        app.review_settings_submit_with_store(&store, &store);
        assert_eq!(app.config.review_provider(), "opencode");
        app.review_settings_begin_input(true);
        for character in "synthetic-key".chars() {
            app.review_settings_input_char(Some(character));
        }
        app.review_settings_cancel();
        assert!(matches!(
            app.modal,
            Modal::ReviewSettings {
                input: ReviewSettingsInput::Menu,
                ..
            }
        ));
    }

    #[test]
    fn characterize_freshness_policy_without_prescan() {
        let mut app = App::new(PathBuf::from("."), false);
        app.config.security.pre_scan_security = Some(false);
        app.config.security.block_too_fresh = Some(true);
        let mut dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        for (freshness, blocked) in [
            (None, false),
            (Some(FreshnessInfo::Unavailable), false),
            (Some(FreshnessInfo::VeryRecent(1)), true),
            (Some(FreshnessInfo::Recent(5)), false),
            (Some(FreshnessInfo::Mature(30)), false),
        ] {
            app.freshness_cache.clear();
            if let Some(value) = freshness {
                app.freshness_cache.insert(cache_key(&dep), value);
            }
            assert_eq!(app.policy_block_reason(&dep).is_some(), blocked);
        }
        dep.ecosystem = Ecosystem::Pacman;
        app.config.security.require_provenance = Some(true);
        app.freshness_cache
            .insert(cache_key(&dep), FreshnessInfo::VeryRecent(1));
        assert_eq!(
            app.policy_block_reason(&dep),
            Some(t("blocked_provenance_required").to_string())
        );
        app.provenance_cache.insert(
            cache_key(&dep),
            ProvenanceInfo {
                validated_by: None,
                install_date: None,
                pkgbuild_age_days: None,
                signature_verified: true,
            },
        );
        assert_eq!(
            app.policy_block_reason(&dep),
            Some(t("blocked_too_fresh").to_string())
        );
        for value in [
            None,
            Some(FreshnessInfo::Unavailable),
            Some(FreshnessInfo::Mature(30)),
        ] {
            app.freshness_cache.clear();
            if let Some(value) = value {
                app.freshness_cache.insert(cache_key(&dep), value);
            }
            assert_eq!(app.policy_block_reason(&dep), None);
        }
    }

    #[test]
    fn disabled_prescan_does_not_schedule_either_tab() {
        let dep = |name: &str, is_global| Dependency {
            name: name.into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global,
            origin: None,
        };
        for first in [Tab::Local, Tab::Global] {
            let mut app = App::new(PathBuf::from("."), false);
            app.config.security.pre_scan_security = Some(false);
            app.pre_scan_test_observations = Some(Vec::new());
            let attempt = app.reserve_scan_attempt().unwrap();
            app.status = AppStatus::Scanning;
            let (first_dep, second, second_dep) = if first == Tab::Local {
                (dep("local", false), Tab::Global, dep("global", true))
            } else {
                (dep("global", true), Tab::Local, dep("local", false))
            };
            app.handle_event(AppEvent::ScanFinished(attempt, first, vec![first_dep]));
            app.handle_event(AppEvent::ScanFinished(attempt, second, vec![second_dep]));
            assert!(app.pre_scan_test_observations.as_ref().unwrap().is_empty());
            assert_eq!(app.batch_scan_pending, 0);
            assert!(app.pending_pre_scan_security.is_empty());
            assert!(app.pending_pre_scan_freshness.is_empty());
            assert!(app.pending_pre_scan_provenance.is_empty());
            assert_eq!(app.status, AppStatus::Ready);
        }
    }

    #[tokio::test]
    async fn disabling_prescan_on_reload_discards_pending_results() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tucupi.toml");
        let mut app = App::new(directory.path().to_path_buf(), false);
        app.load_config_sync().await.unwrap();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let security = app.reserve_pre_scan_security_attempt(&dep).unwrap();
        let freshness = app
            .reserve_pre_scan_metadata(&dep, PreScanMetadataKind::Freshness)
            .unwrap();
        let provenance = app
            .reserve_pre_scan_metadata(&dep, PreScanMetadataKind::Provenance)
            .unwrap();
        app.batch_scan_pending = 1;
        std::fs::write(&path, "[security]\npre_scan_security = false\n").unwrap();
        app.load_config_sync().await.unwrap();
        app.handle_event(AppEvent::SecurityChecked(
            Some(security),
            dep.clone(),
            Ok(Vec::new()),
            true,
        ));
        app.handle_event(AppEvent::FreshnessChecked(
            freshness,
            dep.clone(),
            FreshnessInfo::Mature(30),
        ));
        app.handle_event(AppEvent::ProvenanceChecked(
            provenance,
            dep,
            ProvenanceInfo {
                validated_by: None,
                install_date: None,
                pkgbuild_age_days: None,
                signature_verified: true,
            },
        ));
        assert_eq!(app.batch_scan_pending, 0);
        assert!(app.vuln_cache.is_empty());
        assert!(app.freshness_cache.is_empty());
        assert!(app.provenance_cache.is_empty());
    }

    #[test]
    fn disabled_prescan_still_accepts_explicit_audit_result() {
        let mut app = App::new(PathBuf::from("."), false);
        app.config.security.pre_scan_security = Some(false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.active_operation = Some(QueuedOperation {
            dep: dep.clone(),
            force: false,
            kind: OperationKind::Upgrade,
        });
        let attempt = app.reserve_security_attempt(&dep).unwrap();
        app.handle_event(AppEvent::SecurityChecked(
            Some(attempt),
            dep,
            Err("synthetic offline".into()),
            false,
        ));
        assert!(app.vuln_cache.values().next().unwrap().is_err());
        assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
    }

    #[test]
    fn prescan_covers_local_and_global_in_either_order() {
        let dependency = |name: &str, is_global| Dependency {
            name: name.into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global,
            origin: None,
        };
        for first in [Tab::Local, Tab::Global] {
            let mut app = App::new(PathBuf::from("."), false);
            app.pre_scan_test_observations = Some(Vec::new());
            let attempt = app.reserve_scan_attempt().unwrap();
            app.status = AppStatus::Scanning;
            let (first_dep, second, second_dep) = if first == Tab::Local {
                (
                    dependency("local", false),
                    Tab::Global,
                    dependency("global", true),
                )
            } else {
                (
                    dependency("global", true),
                    Tab::Local,
                    dependency("local", false),
                )
            };
            app.handle_event(AppEvent::ScanFinished(
                attempt,
                first.clone(),
                vec![first_dep.clone()],
            ));
            assert_eq!(
                app.pre_scan_test_observations.as_ref().unwrap()[0],
                vec![first_dep.clone()]
            );
            assert_eq!(app.status, AppStatus::Ready);
            app.handle_event(AppEvent::ScanFinished(
                attempt,
                second,
                vec![second_dep.clone()],
            ));
            let observations = app.pre_scan_test_observations.as_ref().unwrap();
            assert_eq!(observations.len(), 2);
            assert_eq!(observations[1], vec![second_dep]);
            assert_eq!(app.status, AppStatus::Ready);
            let names: std::collections::HashSet<_> = app
                .pending_pre_scan_security
                .values()
                .map(|dep| dep.name.as_str())
                .collect();
            assert_eq!(names, std::collections::HashSet::from(["local", "global"]));
            assert_eq!(app.batch_scan_pending, 2);
            assert_eq!(app.pending_pre_scan_freshness.len(), 2);
            app.handle_event(AppEvent::ScanFinished(attempt, first, vec![first_dep]));
            assert_eq!(app.pre_scan_test_observations.as_ref().unwrap().len(), 2);
            assert_eq!(app.batch_scan_pending, 2);
        }
    }

    #[test]
    fn prescan_does_not_duplicate_same_dependency_across_tabs() {
        let mut app = App::new(PathBuf::from("."), false);
        app.pre_scan_test_observations = Some(Vec::new());
        let mut dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.trigger_pre_scan_for_dependencies(vec![dep.clone()]);
        dep.is_global = true;
        app.trigger_pre_scan_for_dependencies(vec![dep]);
        assert_eq!(app.batch_scan_pending, 1);
        assert_eq!(app.pending_pre_scan_security.len(), 1);
        assert_eq!(app.pending_pre_scan_freshness.len(), 1);
    }

    #[test]
    fn previous_scan_results_must_not_replace_current_tabs() {
        let dep = |name: &str| Dependency {
            name: name.into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let mut app = App::new(PathBuf::from("."), false);
        app.pre_scan_test_observations = Some(Vec::new());
        let old = app.reserve_scan_attempt().unwrap();
        let current = app.reserve_scan_attempt().unwrap();
        app.local_deps = vec![dep("local-current")];
        app.global_deps = vec![dep("global-current")];
        app.handle_event(AppEvent::ScanFinished(old, Tab::Local, vec![dep("old")]));
        app.handle_event(AppEvent::ScanFinished(old, Tab::Global, vec![dep("old")]));
        assert_eq!(app.local_deps[0].name, "local-current");
        assert_eq!(app.global_deps[0].name, "global-current");
        app.handle_event(AppEvent::ScanFinished(
            current,
            Tab::Global,
            vec![dep("global-new")],
        ));
        app.handle_event(AppEvent::ScanFinished(
            current,
            Tab::Local,
            vec![dep("local-new")],
        ));
        app.handle_event(AppEvent::ScanFinished(
            current,
            Tab::Local,
            vec![dep("duplicate")],
        ));
        app.handle_event(AppEvent::ScanFinished(
            current,
            Tab::Global,
            vec![dep("duplicate")],
        ));
        assert_eq!(app.local_deps[0].name, "local-new");
        assert_eq!(app.global_deps[0].name, "global-new");
        assert!(app.pending_local_scan.is_none());
        assert!(app.pending_global_scan.is_none());
    }

    #[test]
    fn exhausted_scan_attempt_does_not_start_or_accept_scan() {
        let mut app = App::new(PathBuf::from("."), false);
        let old = app.reserve_scan_attempt().unwrap();
        app.next_scan_attempt = u64::MAX;
        assert!(app.reserve_scan_attempt().is_none());
        assert!(matches!(app.status, AppStatus::UpgradeFailed(_, _)));
        app.handle_event(AppEvent::ScanFinished(old, Tab::Local, Vec::new()));
        assert!(app.pending_local_scan.is_none());
        assert!(app.pending_global_scan.is_none());
        assert!(app.event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn config_failure_invalidates_scan_results_after_valid_reload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tucupi.toml");
        std::fs::write(&path, "[security]\nreview_provider = 'apple'\n").unwrap();
        let mut app = App::new(directory.path().to_path_buf(), false);
        app.load_config_sync().await.unwrap();
        let old = app.reserve_scan_attempt().unwrap();
        std::fs::write(&path, "[security]\ncodex_api_key = 'synthetic-only'\n").unwrap();
        assert!(app.load_config_sync().await.is_err());
        std::fs::write(&path, "[security]\nreview_provider = 'apple'\n").unwrap();
        app.load_config_sync().await.unwrap();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.handle_event(AppEvent::ScanFinished(old, Tab::Local, vec![dep.clone()]));
        app.handle_event(AppEvent::ScanFinished(old, Tab::Global, vec![dep]));
        assert!(app.local_deps.is_empty());
        assert!(app.global_deps.is_empty());
        assert!(app.event_rx.try_recv().is_err());
    }

    #[test]
    fn late_prescan_does_not_overwrite_newer_explicit_audit_failure() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let background = app.reserve_pre_scan_security_attempt(&dep).unwrap();
        let mut same_key = dep.clone();
        same_key.current_version = "0".into();
        let background_same_key = app.reserve_pre_scan_security_attempt(&same_key).unwrap();
        let mut other = dep.clone();
        other.name = "other".into();
        let unrelated = app.reserve_pre_scan_security_attempt(&other).unwrap();
        app.batch_scan_pending = 3;
        app.active_operation = Some(QueuedOperation {
            dep: dep.clone(),
            force: false,
            kind: OperationKind::Upgrade,
        });
        let explicit = app.reserve_security_attempt(&dep).unwrap();
        assert_eq!(app.batch_scan_pending, 1);
        assert!(app.pending_pre_scan_security.contains_key(&unrelated));
        app.handle_event(AppEvent::SecurityChecked(
            Some(background_same_key),
            same_key,
            Ok(Vec::new()),
            true,
        ));
        assert!(app.vuln_cache.is_empty());
        app.handle_event(AppEvent::SecurityChecked(
            Some(explicit),
            dep.clone(),
            Err("synthetic offline".into()),
            false,
        ));
        assert!(app.vuln_cache.values().next().unwrap().is_err());
        app.handle_event(AppEvent::SecurityChecked(
            Some(background),
            dep,
            Ok(Vec::new()),
            true,
        ));
        assert!(
            app.vuln_cache.values().next().unwrap().is_err(),
            "older pre-scan overwrote explicit failure"
        );
        app.handle_event(AppEvent::SecurityChecked(
            Some(unrelated),
            other,
            Ok(Vec::new()),
            true,
        ));
        assert_eq!(app.batch_scan_pending, 0);
    }

    #[test]
    fn stale_freshness_and_provenance_must_not_update_new_scan() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let info = || ProvenanceInfo {
            validated_by: Some("synthetic".into()),
            install_date: None,
            pkgbuild_age_days: None,
            signature_verified: false,
        };
        let old_freshness = app
            .reserve_pre_scan_metadata(&dep, PreScanMetadataKind::Freshness)
            .unwrap();
        let old_provenance = app
            .reserve_pre_scan_metadata(&dep, PreScanMetadataKind::Provenance)
            .unwrap();
        app.invalidate_pre_scan_security();
        let current_freshness = app
            .reserve_pre_scan_metadata(&dep, PreScanMetadataKind::Freshness)
            .unwrap();
        let current_provenance = app
            .reserve_pre_scan_metadata(&dep, PreScanMetadataKind::Provenance)
            .unwrap();
        app.handle_event(AppEvent::FreshnessChecked(
            old_freshness,
            dep.clone(),
            FreshnessInfo::Mature(30),
        ));
        app.handle_event(AppEvent::ProvenanceChecked(
            old_provenance,
            dep.clone(),
            info(),
        ));
        assert!(app.freshness_cache.is_empty());
        assert!(app.provenance_cache.is_empty());
        let mut wrong = dep.clone();
        wrong.latest_version = "3".into();
        app.handle_event(AppEvent::FreshnessChecked(
            current_freshness,
            wrong.clone(),
            FreshnessInfo::Mature(30),
        ));
        app.handle_event(AppEvent::ProvenanceChecked(
            current_provenance,
            wrong,
            info(),
        ));
        app.handle_event(AppEvent::FreshnessChecked(
            current_provenance,
            dep.clone(),
            FreshnessInfo::Mature(30),
        ));
        assert!(app.freshness_cache.is_empty());
        assert!(app.provenance_cache.is_empty());
        app.handle_event(AppEvent::FreshnessChecked(
            current_freshness,
            dep.clone(),
            FreshnessInfo::VeryRecent(1),
        ));
        app.handle_event(AppEvent::ProvenanceChecked(
            current_provenance,
            dep.clone(),
            info(),
        ));
        app.handle_event(AppEvent::FreshnessChecked(
            current_freshness,
            dep.clone(),
            FreshnessInfo::Mature(30),
        ));
        let mut duplicate = info();
        duplicate.signature_verified = true;
        app.handle_event(AppEvent::ProvenanceChecked(
            current_provenance,
            dep,
            duplicate,
        ));
        assert!(matches!(
            app.freshness_cache.values().next(),
            Some(FreshnessInfo::VeryRecent(1))
        ));
        assert!(
            !app.provenance_cache
                .values()
                .next()
                .unwrap()
                .signature_verified
        );
    }

    #[test]
    fn exhausted_metadata_attempt_does_not_mark_results_as_verified() {
        let mut app = App::new(PathBuf::from("."), false);
        app.next_security_attempt = u64::MAX;
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        assert!(app
            .reserve_pre_scan_metadata(&dep, PreScanMetadataKind::Freshness)
            .is_none());
        assert!(app
            .reserve_pre_scan_metadata(&dep, PreScanMetadataKind::Provenance)
            .is_none());
        assert!(app.pending_pre_scan_freshness.is_empty());
        assert!(app.pending_pre_scan_provenance.is_empty());
        assert!(app.freshness_cache.is_empty());
        assert!(app.provenance_cache.is_empty());
    }

    #[test]
    fn late_pre_scan_security_result_does_not_change_current_scan() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let old = app.reserve_pre_scan_security_attempt(&dep).unwrap();
        app.invalidate_pre_scan_security();
        let current = app.reserve_pre_scan_security_attempt(&dep).unwrap();
        app.batch_scan_pending = 1;
        app.handle_event(AppEvent::SecurityChecked(
            Some(old),
            dep.clone(),
            Ok(Vec::new()),
            true,
        ));
        assert_eq!(app.batch_scan_pending, 1);
        assert!(app.vuln_cache.is_empty());
        let mut wrong = dep.clone();
        wrong.latest_version = "3".into();
        app.handle_event(AppEvent::SecurityChecked(
            Some(current),
            wrong,
            Ok(Vec::new()),
            true,
        ));
        assert_eq!(app.batch_scan_pending, 1);
        app.handle_event(AppEvent::SecurityChecked(
            Some(current),
            dep.clone(),
            Err("synthetic offline".into()),
            true,
        ));
        assert_eq!(app.batch_scan_pending, 0);
        assert_eq!(app.vuln_cache.len(), 1);
        app.handle_event(AppEvent::SecurityChecked(
            Some(current),
            dep,
            Ok(Vec::new()),
            true,
        ));
        assert!(app.vuln_cache.values().next().unwrap().is_err());
        assert_eq!(app.batch_scan_pending, 0);
    }

    #[test]
    fn pre_scan_attempt_exhaustion_does_not_record_pending_result() {
        let mut app = App::new(PathBuf::from("."), false);
        app.next_security_attempt = u64::MAX;
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        assert!(app.reserve_pre_scan_security_attempt(&dep).is_none());
        assert!(app.pending_pre_scan_security.is_empty());
        assert_eq!(app.batch_scan_pending, 0);
        assert!(app.vuln_cache.is_empty());
    }

    #[tokio::test]
    async fn config_failure_invalidates_pre_scan_after_valid_reload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tucupi.toml");
        std::fs::write(&path, "[security]\nreview_provider = 'apple'\n").unwrap();
        let mut app = App::new(directory.path().to_path_buf(), false);
        app.load_config_sync().await.unwrap();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let attempt = app.reserve_pre_scan_security_attempt(&dep).unwrap();
        let freshness = app
            .reserve_pre_scan_metadata(&dep, PreScanMetadataKind::Freshness)
            .unwrap();
        let provenance = app
            .reserve_pre_scan_metadata(&dep, PreScanMetadataKind::Provenance)
            .unwrap();
        app.batch_scan_pending = 1;
        std::fs::write(&path, "[security]\ncodex_api_key = 'synthetic-only'\n").unwrap();
        assert!(app.load_config_sync().await.is_err());
        std::fs::write(&path, "[security]\nreview_provider = 'apple'\n").unwrap();
        app.load_config_sync().await.unwrap();
        app.handle_event(AppEvent::SecurityChecked(
            Some(attempt),
            dep.clone(),
            Ok(Vec::new()),
            true,
        ));
        assert_eq!(app.batch_scan_pending, 0);
        assert!(app.vuln_cache.is_empty());
        app.handle_event(AppEvent::FreshnessChecked(
            freshness,
            dep.clone(),
            FreshnessInfo::Mature(30),
        ));
        app.handle_event(AppEvent::ProvenanceChecked(
            provenance,
            dep,
            ProvenanceInfo {
                validated_by: None,
                install_date: None,
                pkgbuild_age_days: None,
                signature_verified: true,
            },
        ));
        assert!(app.freshness_cache.is_empty());
        assert!(app.provenance_cache.is_empty());
    }

    #[test]
    fn late_security_event_must_not_block_a_new_operation() {
        let dep = |name: &str| Dependency {
            name: name.into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let mut app = App::new(PathBuf::from("."), false);
        app.active_operation = Some(QueuedOperation {
            dep: dep("new"),
            force: false,
            kind: OperationKind::Upgrade,
        });
        app.active_security_attempt = Some(2);
        app.handle_event(AppEvent::SecurityChecked(
            Some(1),
            dep("old"),
            Err("synthetic offline".into()),
            false,
        ));
        app.handle_event(AppEvent::SecurityChecked(
            Some(1),
            dep("new"),
            Err("synthetic offline".into()),
            false,
        ));
        app.handle_event(AppEvent::SecurityChecked(
            Some(2),
            dep("old"),
            Err("synthetic offline".into()),
            false,
        ));
        assert!(matches!(app.modal, Modal::None));
        assert!(app.vuln_cache.is_empty());
        app.handle_event(AppEvent::SecurityChecked(
            Some(2),
            dep("new"),
            Err("synthetic offline".into()),
            false,
        ));
        assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
        app.modal = Modal::None;
        app.handle_event(AppEvent::SecurityChecked(
            Some(2),
            dep("new"),
            Err("duplicate".into()),
            false,
        ));
        assert!(matches!(app.modal, Modal::None));
        assert!(app.event_rx.try_recv().is_err());
    }

    #[test]
    fn exhausted_security_attempt_blocks_without_starting_work() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.next_security_attempt = u64::MAX;
        assert!(app.reserve_security_attempt(&dep).is_none());
        assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
        assert!(app.active_security_attempt.is_none());
        assert!(app.event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn config_failure_invalidates_security_event_after_valid_reload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tucupi.toml");
        std::fs::write(&path, "[security]\nreview_provider = 'apple'\n").unwrap();
        let mut app = App::new(directory.path().to_path_buf(), false);
        app.load_config_sync().await.unwrap();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.active_operation = Some(QueuedOperation {
            dep: dep.clone(),
            force: false,
            kind: OperationKind::Upgrade,
        });
        let attempt = app.reserve_security_attempt(&dep).unwrap();
        std::fs::write(&path, "[security]\ncodex_api_key = 'synthetic-only'\n").unwrap();
        assert!(app.load_config_sync().await.is_err());
        std::fs::write(&path, "[security]\nreview_provider = 'apple'\n").unwrap();
        app.load_config_sync().await.unwrap();
        app.handle_event(AppEvent::SecurityChecked(
            Some(attempt),
            dep,
            Err("synthetic offline".into()),
            false,
        ));
        assert!(app.vuln_cache.is_empty());
        assert!(matches!(app.modal, Modal::None));
        assert!(app.event_rx.try_recv().is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn synthetic_impact_descendant_and_restart_expose_cleanup_limit() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        let case = std::env::var("TUCUPI_SYNTHETIC_IMPACT_CASE").unwrap_or_default();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        if case == "restart" {
            let mut app = App::new(PathBuf::from(std::env::var("HOME").unwrap()), false);
            app.load_config_sync().await.unwrap();
            assert!(!app.impact_cleanup_unverified);
            assert!(app.policy_block_reason(&dep).is_none());
            println!("synthetic new App: prior impact block absent");
            return;
        }
        if case.is_empty() {
            let directory = tempfile::tempdir().unwrap();
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "app::tests::synthetic_impact_descendant_and_restart_expose_cleanup_limit",
                    "--nocapture",
                ])
                .env_clear()
                .env("HOME", directory.path())
                .env("TMPDIR", directory.path())
                .env("PATH", "/usr/bin:/bin")
                .env("TUCUPI_SYNTHETIC_IMPACT_CASE", "run");
            let batch_binary = std::env::var_os("TUCUPI_SYNTHETIC_BATCH_BIN");
            if let Some(path) = &batch_binary {
                command.env("TUCUPI_SYNTHETIC_BATCH_BIN", path);
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "synthetic impact fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("synthetic descendant survived direct-child cancellation"));
            assert!(text.contains("synthetic new App: prior impact block absent"));
            if batch_binary.is_some() {
                assert!(text.contains("synthetic batch passed recovery preflight; no terminal or package work started"));
                println!("synthetic batch passed recovery preflight; no terminal or package work started");
            }
            println!("synthetic descendant survived direct-child cancellation; new App loses in-memory block");
            return;
        }
        assert_eq!(case, "run");
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("tucupi.toml");
        let parent_pid = directory.path().join("parent-pid");
        let child_pid = directory.path().join("child-pid");
        let marker = directory.path().join("descendant-survived");
        std::fs::write(&config, "[security]\nreview_provider = 'apple'\n").unwrap();
        let mut app = App::new(directory.path().to_path_buf(), false);
        app.load_config_sync().await.unwrap();
        let code = "import os,pathlib,subprocess,sys,time\nchild=\"import pathlib,sys,time; time.sleep(1); pathlib.Path(sys.argv[1]).touch(); time.sleep(15)\"\np=subprocess.Popen(['/usr/bin/python3','-c',child,sys.argv[3]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\npathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\npathlib.Path(sys.argv[2]).write_text(str(p.pid))\ntime.sleep(5)";
        let args = vec![
            "-c".to_string(),
            code.to_string(),
            parent_pid.to_string_lossy().into_owned(),
            child_pid.to_string_lossy().into_owned(),
            marker.to_string_lossy().into_owned(),
        ];
        let dir = directory.path().to_path_buf();
        app.spawn_impact_future(dep.clone(), async move {
            crate::impact::run_preview(std::path::Path::new("/usr/bin/python3"), &args, &dir).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !parent_pid.exists() || !child_pid.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let parent: u32 = std::fs::read_to_string(&parent_pid)
            .unwrap()
            .parse()
            .unwrap();
        let child: u32 = std::fs::read_to_string(&child_pid)
            .unwrap()
            .parse()
            .unwrap();
        assert!(child > 1 && child != parent);
        let status = std::fs::read_to_string(format!("/proc/{child}/status")).unwrap();
        assert!(status
            .lines()
            .any(|line| line == format!("PPid:\t{parent}")));
        // SAFETY: the freshly observed child PID is used only to acquire a pidfd.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0u32) };
        assert!(raw >= 0);
        // SAFETY: successful pidfd_open returns an owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        struct StopSynthetic(OwnedFd);
        impl Drop for StopSynthetic {
            fn drop(&mut self) {
                // SAFETY: send only SIGKILL through the fixture's pinned pidfd.
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        self.0.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0u32,
                    );
                }
            }
        }
        let cleanup = StopSynthetic(pidfd);
        std::fs::write(&config, "[security]\ncodex_api_key = 'synthetic-only'\n").unwrap();
        assert!(app.load_config_sync().await.is_err());
        assert!(app.impact_cleanup_unverified);
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            while !marker.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        println!("synthetic descendant survived direct-child cancellation");
        std::fs::write(&config, "[security]\nreview_provider = 'apple'\n").unwrap();
        app.load_config_sync().await.unwrap();
        assert!(app.policy_block_reason(&dep).is_some());
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "app::tests::synthetic_impact_descendant_and_restart_expose_cleanup_limit",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", directory.path())
            .env("TMPDIR", directory.path())
            .env("PATH", "/usr/bin:/bin")
            .env("TUCUPI_SYNTHETIC_IMPACT_CASE", "restart")
            .output()
            .unwrap();
        assert!(output.status.success());
        print!("{}", String::from_utf8(output.stdout).unwrap());
        if let Some(binary) = std::env::var_os("TUCUPI_SYNTHETIC_BATCH_BIN") {
            use std::os::unix::process::CommandExt;
            let mut batch = std::process::Command::new(binary);
            batch
                .args(["-i", directory.path().to_str().unwrap()])
                .env_clear()
                .env("HOME", directory.path())
                .env("XDG_STATE_HOME", directory.path().join("state"))
                .env("LANG", "en_US.UTF-8")
                .env("PATH", "/usr/bin:/bin")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            // SAFETY: setsid is async-signal-safe and only changes the new child.
            unsafe {
                batch.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let batch = batch.output().unwrap();
            let stderr = String::from_utf8(batch.stderr).unwrap();
            assert!(!batch.status.success());
            assert!(
                stderr.contains("code: 6,") || stderr.contains("code: 25,"),
                "batch did not stop at terminal preflight: {stderr}"
            );
            assert!(!stderr.contains("cleanup was not verified"));
            assert!(batch.stdout.is_empty());
            println!(
                "synthetic batch passed recovery preflight; no terminal or package work started"
            );
        }
        // SAFETY: this pidfd pins the synthetic descendant confirmed above.
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    cleanup.0.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                )
            },
            0
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let mut fd = libc::pollfd {
                    fd: cleanup.0.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: poll receives a pointer to one initialized pollfd.
                let result = unsafe { libc::poll(&mut fd, 1, 0) };
                assert!(result >= 0);
                if result > 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn invalid_config_cancels_running_synthetic_impact_and_keeps_cleanup_blocked() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("tucupi.toml");
        let pid_path = directory.path().join("started");
        let late = directory.path().join("late");
        std::fs::write(&config, "[security]\nreview_provider = 'apple'\n").unwrap();
        let mut app = App::new(directory.path().to_path_buf(), false);
        app.load_config_sync().await.unwrap();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let script = "import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(2); pathlib.Path(sys.argv[2]).touch()";
        let args = vec![
            "-c".to_string(),
            script.to_string(),
            pid_path.to_string_lossy().into_owned(),
            late.to_string_lossy().into_owned(),
        ];
        let dir = directory.path().to_path_buf();
        app.spawn_impact_future(dep.clone(), async move {
            crate::impact::run_preview(std::path::Path::new("/usr/bin/python3"), &args, &dir).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !pid_path.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let pid: u32 = std::fs::read_to_string(&pid_path).unwrap().parse().unwrap();
        // SAFETY: pidfd_open returns a fresh descriptor on success.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        assert!(raw >= 0);
        // SAFETY: the successful syscall returned a fresh owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        std::fs::write(&config, "[security]\ncodex_api_key = 'synthetic-only'\n").unwrap();
        assert!(app.load_config_sync().await.is_err());
        assert!(app.impact_cleanup_unverified);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let mut pollfd = libc::pollfd {
                    fd: pidfd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: pollfd references one initialized descriptor.
                if unsafe { libc::poll(&mut pollfd, 1, 0) } > 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        std::fs::write(&config, "[security]\nreview_provider = 'apple'\n").unwrap();
        app.load_config_sync().await.unwrap();
        assert_eq!(
            app.policy_block_reason(&dep),
            Some(t("impact_cleanup_blocked").to_string())
        );
        assert!(app.active_impact_attempt.is_none());
        assert!(app.event_rx.try_recv().is_err());
        tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
        assert!(!late.exists());
    }

    #[tokio::test]
    async fn review_result_from_before_config_failure_is_discarded_after_valid_reload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tucupi.toml");
        std::fs::write(&path, "[security]\nreview_provider = 'apple'\n").unwrap();
        let mut app = App::new(directory.path().to_path_buf(), false);
        app.load_config_sync().await.unwrap();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.active_review_attempt = Some(17);
        std::fs::write(&path, "[security]\ncodex_api_key = 'synthetic-only'\n").unwrap();
        assert!(app.load_config_sync().await.is_err());
        std::fs::write(&path, "[security]\nreview_provider = 'apple'\n").unwrap();
        app.load_config_sync().await.unwrap();
        let report = ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "synthetic".into(),
            view_mode: review::ReviewViewMode::Diff,
            residual_line_count: 0,
            hits: Vec::new(),
            origin: review::ReviewOrigin::Unknown,
        };
        app.handle_event(AppEvent::ReviewChecked(17, dep, report, false, true));
        assert!(app.review_cache.is_empty());
        assert!(app.event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn impact_result_from_before_config_failure_is_discarded_after_valid_reload() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tucupi.toml");
        std::fs::write(&path, "[security]\nreview_provider = 'apple'\n").unwrap();
        let mut app = App::new(directory.path().to_path_buf(), false);
        app.load_config_sync().await.unwrap();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.active_impact_attempt = Some(23);
        std::fs::write(&path, "[security]\ncodex_api_key = 'synthetic-only'\n").unwrap();
        assert!(app.load_config_sync().await.is_err());
        std::fs::write(&path, "[security]\nreview_provider = 'apple'\n").unwrap();
        app.load_config_sync().await.unwrap();
        app.handle_event(AppEvent::ImpactChecked(
            23,
            dep,
            crate::impact::ImpactPreview::Unavailable,
        ));
        assert!(!matches!(app.modal, Modal::ConfirmImpact { .. }));
        assert!(app.event_rx.try_recv().is_err());
    }

    #[test]
    fn late_review_and_impact_results_do_not_override_safety_failures() {
        for failure in ["config", "cleanup"] {
            let directory = tempfile::tempdir().unwrap();
            let mut app = App::new(directory.path().to_path_buf(), false);
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            app.active_review_attempt = Some(1);
            if failure == "config" {
                app.config_load_failed = true;
            } else {
                app.review_cleanup_unverified = true;
            }
            let report = ReviewReport {
                verdict: ReviewVerdict::Safe,
                reason: "synthetic".into(),
                view_mode: review::ReviewViewMode::Diff,
                residual_line_count: 0,
                hits: Vec::new(),
                origin: review::ReviewOrigin::Unknown,
            };
            app.handle_event(AppEvent::ReviewChecked(1, dep.clone(), report, false, true));
            assert!(
                app.review_cache.is_empty(),
                "late review was cached after {failure} failure"
            );
            assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
            app.active_impact_attempt = Some(1);
            app.handle_event(AppEvent::ImpactChecked(
                1,
                dep,
                crate::impact::ImpactPreview::Unavailable,
            ));
            assert!(
                matches!(app.modal, Modal::BlockedPolicy(_, _)),
                "late impact replaced {failure} block"
            );
            assert!(app.event_rx.try_recv().is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_impact_confirmation_rechecks_codex_recovery_before_spawning() {
        let directory = tempfile::tempdir().unwrap();
        let mut app = App::new(directory.path().to_path_buf(), false);
        app.config.security.review_provider = Some("codex".into());
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: true,
            origin: None,
        };
        app.modal = Modal::ConfirmImpact {
            dep,
            preview: crate::impact::ImpactPreview::Unavailable,
            scroll: 0,
        };
        // No Tokio runtime exists: accidentally reaching tokio::spawn panics
        // before any worker or package command can execute.
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| app.confirm_impact()));
        assert!(result.is_ok(), "confirmation reached task spawning");
        assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
        assert!(app.event_rx.try_recv().is_err());
    }

    #[test]
    fn stale_impact_confirmation_rechecks_unverified_cleanup_before_spawning() {
        let directory = tempfile::tempdir().unwrap();
        let mut app = App::new(directory.path().to_path_buf(), false);
        app.review_cleanup_unverified = true;
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.modal = Modal::ConfirmImpact {
            dep,
            preview: crate::impact::ImpactPreview::Unavailable,
            scroll: 0,
        };
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| app.confirm_impact()));
        assert!(result.is_ok(), "confirmation reached task spawning");
        assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
        assert!(app.event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn rejected_codex_credential_config_blocks_existing_app_until_reload_succeeds() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("tucupi.toml");
        std::fs::write(&config, "[security]\nreview_provider = 'apple'\n").unwrap();
        let mut app = App::new(directory.path().to_path_buf(), false);
        app.load_config_sync().await.unwrap();
        std::fs::write(&config, "[security]\ncodex_api_key = 'synthetic-only'\n").unwrap();
        assert!(app.load_config_sync().await.is_err());
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        assert!(app.policy_block_reason(&dep).is_some());
        app.start_upgrade(dep.clone(), true);
        assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
        app.start_impact_preview(dep.clone());
        assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
        app.start_upgrade_confirmed(dep.clone());
        match &app.modal {
            Modal::BlockedPolicy(_, message) => assert!(!message.contains("synthetic-only")),
            _ => panic!("invalid configuration did not block confirmation"),
        }
        std::fs::write(&config, "[security]\nreview_provider = 'apple'\n").unwrap();
        app.load_config_sync().await.unwrap();
        assert!(app.policy_block_reason(&dep).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_app_blocks_codex_review_when_recovery_is_unreconciled() {
        let directory = tempfile::tempdir().unwrap();
        let mut app = App::new(directory.path().to_path_buf(), false);
        app.config.security.review_provider = Some("codex".into());
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: false,
            origin: None,
        };
        assert_eq!(
            app.policy_block_reason(&dep),
            Some(t("codex_recovery_unavailable").to_string())
        );
        app.start_impact_preview(dep);
        assert!(
            matches!(&app.modal, Modal::BlockedPolicy(_, message) if message == t("codex_recovery_unavailable"))
        );
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[test]
    fn opted_in_app_blocks_on_state_directory_replacement() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        std::fs::create_dir(&state).unwrap();
        let app = App::new_with_fixture_recovery(root.path().to_path_buf(), false, &state);
        assert!(!app.fixture_recovery_is_blocked());
        std::fs::rename(&state, root.path().join("old-state")).unwrap();
        std::fs::create_dir(&state).unwrap();
        assert!(app.fixture_recovery_is_blocked());
        let restarted = App::new_with_fixture_recovery(root.path().to_path_buf(), false, &state);
        assert!(!restarted.fixture_recovery_is_blocked());
    }

    // Documents a known limitation, not a recovery guarantee: an App created
    // after a previous instance lost its cleanup state cannot recover it.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    async fn fixture_unverified_cleanup_block_does_not_survive_new_app_instance() {
        let directory = tempfile::tempdir().unwrap();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let mut first = App::new(directory.path().to_path_buf(), false);
        first.spawn_review_future(
            dep.clone(),
            false,
            false,
            std::future::pending::<ReviewReport>(),
        );
        let gate = first.active_review_gate.as_ref().unwrap();
        gate.begin_fixture_start().unwrap();
        let failing_handle = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        gate.attach_synthetic_kill(failing_handle).unwrap();
        assert!(first.shutdown_review().is_err());
        assert!(first.review_cleanup_unverified);
        assert_eq!(
            first.policy_block_reason(&dep),
            Some(t("review_cleanup_blocked").to_string())
        );
        drop(first);

        let restarted = App::new(directory.path().to_path_buf(), false);
        assert!(!restarted.review_cleanup_unverified);
        assert_eq!(restarted.policy_block_reason(&dep), None);
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    async fn opted_in_app_recovers_fixture_marker_and_blocks_manager_outage() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        std::fs::create_dir(&state).unwrap();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let mut first =
            App::new_with_fixture_recovery(directory.path().to_path_buf(), false, &state);
        let mut peer =
            App::new_with_fixture_recovery(directory.path().to_path_buf(), false, &state);
        assert!(first.policy_block_reason(&dep).is_none());
        first.spawn_review_future(
            dep.clone(),
            false,
            false,
            std::future::pending::<ReviewReport>(),
        );
        let gate = first.active_review_gate.as_ref().unwrap();
        gate.begin_fixture_start().unwrap();
        let persisted = std::fs::read_to_string(state.join("unverified")).unwrap();
        let id = persisted
            .trim()
            .strip_prefix("fixture-attempt-v1:")
            .unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|value| value.is_ascii_hexdigit()));
        // A failing synthetic stop handle stands in for an unavailable
        // manager; this does not exercise the real systemd API.
        let unavailable_handle = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        gate.attach_synthetic_kill(unavailable_handle).unwrap();
        assert!(first.shutdown_review().is_err());
        assert!(first.policy_block_reason(&dep).is_some());
        assert!(peer.policy_block_reason(&dep).is_some());
        peer.spawn_review_future(
            dep.clone(),
            false,
            false,
            std::future::pending::<ReviewReport>(),
        );
        assert!(peer
            .active_review_gate
            .as_ref()
            .unwrap()
            .begin_fixture_start()
            .is_err());
        assert!(peer.shutdown_review().is_err());
        drop(first);
        let restarted =
            App::new_with_fixture_recovery(directory.path().to_path_buf(), false, &state);
        assert!(restarted.policy_block_reason(&dep).is_some());
        assert_eq!(
            std::fs::read_to_string(state.join("unverified")).unwrap(),
            persisted
        );
        let unavailable = App::new_with_fixture_recovery(
            directory.path().to_path_buf(),
            false,
            &state.join("unavailable"),
        );
        assert!(unavailable.policy_block_reason(&dep).is_some());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    async fn opted_in_app_blocks_if_fixture_state_disappears_before_start() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        std::fs::create_dir(&state).unwrap();
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let mut app = App::new_with_fixture_recovery(directory.path().to_path_buf(), false, &state);
        app.spawn_review_future(
            dep.clone(),
            false,
            false,
            std::future::pending::<ReviewReport>(),
        );
        std::fs::remove_dir(&state).unwrap();
        assert!(app
            .active_review_gate
            .as_ref()
            .unwrap()
            .begin_fixture_start()
            .is_err());
        assert!(app.shutdown_review().is_err());
        assert!(app.policy_block_reason(&dep).is_some());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    async fn shutdown_reports_failed_or_unverified_fixture_cancellation() {
        for (device, expected) in [
            ("/dev/full", "review_cancel_failed"),
            ("/dev/null", "review_cleanup_unverified"),
        ] {
            let mut app = App::new(PathBuf::from("."), false);
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            app.spawn_review_future(dep, false, false, std::future::pending::<ReviewReport>());
            let gate = app.active_review_gate.as_ref().unwrap();
            gate.begin_fixture_start().unwrap();
            let handle = std::fs::OpenOptions::new()
                .write(true)
                .open(device)
                .unwrap();
            gate.attach_synthetic_kill(handle).unwrap();
            assert_eq!(app.shutdown_review(), Err(t(expected).to_string()));
            assert!(app.active_review_task.is_none());
            assert!(app.active_review_attempt.is_none());
            assert!(app.review_cleanup_unverified);
        }
    }

    #[tokio::test]
    async fn shutdown_without_unit_aborts_pending_review() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.spawn_review_future(dep, false, false, std::future::pending::<ReviewReport>());
        assert_eq!(app.shutdown_review(), Ok(()));
        assert!(app.active_review_task.is_none());
        assert!(app.active_review_attempt.is_none());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    async fn successful_stop_request_does_not_advance_queue_without_cleanup_proof() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.spawn_review_future(
            dep.clone(),
            false,
            false,
            std::future::pending::<ReviewReport>(),
        );
        let sink = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        app.active_review_gate
            .as_ref()
            .unwrap()
            .begin_fixture_start()
            .unwrap();
        app.active_review_gate
            .as_ref()
            .unwrap()
            .attach_synthetic_kill(sink)
            .unwrap();
        app.pending_operations.push_back(QueuedOperation {
            dep,
            force: true,
            kind: OperationKind::Upgrade,
        });
        app.finish_operation(false);
        assert!(app.review_cleanup_unverified);
        assert_eq!(app.pending_operations.len(), 1);
        assert!(app.active_operation.is_none());
        assert!(matches!(app.status, AppStatus::UpgradeFailed(_, _)));
        assert!(app.event_rx.try_recv().is_err());
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    async fn successful_stop_request_does_not_promote_unverified_unit_result() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.spawn_review_future(
            dep.clone(),
            false,
            false,
            std::future::pending::<ReviewReport>(),
        );
        let sink = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        app.active_review_gate
            .as_ref()
            .unwrap()
            .begin_fixture_start()
            .unwrap();
        app.active_review_gate
            .as_ref()
            .unwrap()
            .attach_synthetic_kill(sink)
            .unwrap();
        let report = ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "synthetic".into(),
            view_mode: review::ReviewViewMode::Diff,
            residual_line_count: 0,
            hits: Vec::new(),
            origin: review::ReviewOrigin::Unknown,
        };
        app.handle_event(AppEvent::ReviewChecked(1, dep, report, true, false));
        assert!(app.review_cleanup_unverified);
        assert!(app.review_cache.is_empty());
        assert!(app.active_review_attempt.is_none());
        assert!(matches!(app.status, AppStatus::UpgradeFailed(_, _)));
        assert!(app.toasts.iter().any(|toast| toast.kind == ToastKind::Error
            && toast.message == t("review_cleanup_unverified")));
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    async fn review_cancel_failure_blocks_queue_replacement_and_result() {
        for mode in ["finish", "replace", "result"] {
            let mut app = App::new(PathBuf::from("."), false);
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            app.spawn_review_future(
                dep.clone(),
                false,
                false,
                std::future::pending::<ReviewReport>(),
            );
            let full = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap();
            app.active_review_gate
                .as_ref()
                .unwrap()
                .begin_fixture_start()
                .unwrap();
            app.active_review_gate
                .as_ref()
                .unwrap()
                .attach_synthetic_kill(full)
                .unwrap();
            app.pending_operations.push_back(QueuedOperation {
                dep: dep.clone(),
                force: false,
                kind: OperationKind::Upgrade,
            });
            match mode {
                "finish" => app.finish_operation(false),
                "replace" => app.spawn_review_future(
                    dep.clone(),
                    false,
                    false,
                    std::future::pending::<ReviewReport>(),
                ),
                "result" => app.handle_event(AppEvent::ReviewChecked(
                    1,
                    dep.clone(),
                    ReviewReport::unavailable("synthetic"),
                    true,
                    false,
                )),
                _ => unreachable!(),
            }
            assert!(app.review_cleanup_unverified);
            assert!(matches!(app.status, AppStatus::UpgradeFailed(_, _)));
            assert!(app.toasts.iter().any(|toast| toast.kind == ToastKind::Error
                && toast.message == t("review_cancel_failed")));
            assert_eq!(app.pending_operations.len(), 1);
            assert!(app.active_review_attempt.is_none());
            assert!(app.review_cache.is_empty());
            app.start_next_operation();
            assert_eq!(app.pending_operations.len(), 1);
            app.start_upgrade(dep, true);
            assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
        }
    }

    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires delegated systemd user unit and synthetic Codex fixture"]
    async fn fixture_app_cancel_during_startup_rejects_gate() {
        let directory = PathBuf::from(std::env::var_os("TUCUPI_APP_FIXTURE_DIR").unwrap());
        let codex_dir = PathBuf::from(std::env::var_os("TUCUPI_APP_FIXTURE_CODEX_DIR").unwrap());
        let bridge =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/codex_private_bridge_fixture.py");
        let mode = std::env::var("TUCUPI_APP_FIXTURE_MODE").unwrap();
        let failing_cancel = mode == "startup-cancel-failure";
        let after_release = mode == "startup-after-release" || failing_cancel;
        let before_attach = mode == "startup-before-attach";
        let before_create = mode == "startup-before-create";
        let after_create = mode == "startup-after-create";
        let close_failure = mode == "startup-close-failure";
        let moved_child = mode == "startup-moved-child";
        let moved_after_check = mode == "startup-moved-after-check";
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let mut app = App::new(directory.clone(), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let worker_dir = directory.clone();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        app.spawn_review_future_with_gate(dep, false, false, move |start_gate| {
            if close_failure {
                start_gate
                    .fail_close_range
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if moved_after_check {
                *start_gate.after_verify_checkpoint.lock().unwrap() = Some((ready_tx, resume_rx));
            } else if before_create {
                *start_gate.before_create_checkpoint.lock().unwrap() = Some((ready_tx, resume_rx));
            } else if after_create || close_failure {
                *start_gate.after_create_checkpoint.lock().unwrap() = Some((ready_tx, resume_rx));
            } else if after_release {
                *start_gate.after_release_checkpoint.lock().unwrap() = Some((ready_tx, resume_rx));
            } else if before_attach {
                *start_gate.before_attach_checkpoint.lock().unwrap() = Some((ready_tx, resume_rx));
            } else {
                *start_gate.checkpoint.lock().unwrap() = Some((ready_tx, resume_rx));
            }
            async move {
                let result = review::FixtureSupervisedChild::spawn_fixture_cancellable(
                    &worker_dir,
                    &codex_dir,
                    &bridge,
                    false,
                    &start_gate,
                );
                let expected = if close_failure {
                    matches!(result, Err("fixture child unavailable"))
                } else if moved_after_check {
                    let deadline = std::time::Instant::now() + Duration::from_secs(3);
                    while !worker_dir.join("self-check-rejected").exists()
                        && std::time::Instant::now() < deadline
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    result.is_ok() && worker_dir.join("self-check-rejected").exists()
                } else if moved_child {
                    matches!(result, Err("fixture child membership mismatch"))
                } else if after_release {
                    result.is_ok()
                } else {
                    matches!(result, Err("fixture startup cancelled"))
                };
                drop(result);
                let _ = finished_tx.send(expected);
                ReviewReport::unavailable("synthetic")
            }
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            match ready_rx.try_recv() {
                Ok(()) => break,
                Err(std::sync::mpsc::TryRecvError::Empty)
                    if tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await
                }
                other => panic!("fixture startup checkpoint unavailable: {other:?}"),
            }
        }
        let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .unwrap();
        let group = Path::new("/sys/fs/cgroup")
            .join(relative)
            .join("tucupi-child-fixture");
        if before_create {
            assert!(!group.exists());
            app.finish_operation(false);
            assert!(app.review_cleanup_unverified);
            resume_tx.send(()).unwrap();
            assert!(tokio::time::timeout(Duration::from_secs(5), finished_rx)
                .await
                .unwrap()
                .unwrap());
            assert!(!group.exists());
            assert!(!directory.join("bridge-root-pid").exists());
            assert!(app.event_rx.try_recv().is_err());
            println!(
                "app startup-before-create: cancellation observed; cgroup and worker not created"
            );
            return;
        }
        let watcher = crate::codex_supervision::CgroupObservation::open(&group).unwrap();
        if close_failure {
            assert_eq!(watcher.populated(), Ok(false));
            resume_tx.send(()).unwrap();
            assert!(tokio::time::timeout(Duration::from_secs(5), finished_rx)
                .await
                .unwrap()
                .unwrap());
            assert_eq!(watcher.populated(), Ok(false));
            assert!(!directory.join("bridge-root-pid").exists());
            app.finish_operation(false);
            assert!(app.review_cleanup_unverified);
            println!("app startup-close-failure: exec rejected; cgroup empty; session blocked");
            return;
        }
        if after_create {
            assert_eq!(watcher.populated(), Ok(false));
            std::fs::write(
                directory.join("created-cgroup-path"),
                group.to_str().unwrap(),
            )
            .unwrap();
            app.finish_operation(false);
            assert!(app.review_cleanup_unverified);
            resume_tx.send(()).unwrap();
            assert!(tokio::time::timeout(Duration::from_secs(5), finished_rx)
                .await
                .unwrap()
                .unwrap());
            assert_eq!(watcher.populated(), Ok(false));
            assert!(!directory.join("bridge-root-pid").exists());
            assert!(app.event_rx.try_recv().is_err());
            println!("app startup-after-create: empty cgroup retained; worker not started; session blocked");
            return;
        }
        assert_eq!(watcher.populated(), Ok(true));
        if after_release {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            while !directory.join("request-in-flight").exists() {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "synthetic request did not start"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        let child_pid_path = if after_release {
            directory.join("bridge-root-pid")
        } else {
            group.join("cgroup.procs")
        };
        let child_pid: u32 = std::fs::read_to_string(child_pid_path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        if moved_child || moved_after_check {
            std::fs::write(
                group.parent().unwrap().join("cgroup.procs"),
                child_pid.to_string(),
            )
            .unwrap();
            resume_tx.send(()).unwrap();
            assert!(tokio::time::timeout(Duration::from_secs(5), finished_rx)
                .await
                .unwrap()
                .unwrap());
            assert!(!Path::new(&format!("/proc/{child_pid}")).exists());
            assert!(!directory.join("bridge-root-pid").exists());
            app.finish_operation(false);
            assert!(app.review_cleanup_unverified);
            if moved_after_check {
                assert!(directory.join("self-check-rejected").exists());
                println!("app startup-moved-after-check: child self-check rejected; direct child reaped; session blocked");
            } else {
                println!("app startup-moved-child: membership mismatch rejected; direct child reaped; session blocked");
            }
            return;
        }
        let mut app = Some(app);
        if failing_cancel {
            app.as_ref()
                .unwrap()
                .active_review_gate
                .as_ref()
                .unwrap()
                .inject_fixture_kill_failure();
        }
        if mode == "startup-replace" {
            let replacement = Dependency {
                name: "replacement".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            let app = app.as_mut().unwrap();
            app.spawn_review_future(
                replacement,
                false,
                false,
                std::future::pending::<ReviewReport>(),
            );
            assert!(app.active_review_attempt.is_none());
            assert!(app.review_cleanup_unverified);
        } else if mode == "startup-drop" {
            drop(app.take());
        } else if mode == "startup-shutdown" {
            assert_eq!(
                app.as_mut().unwrap().shutdown_review(),
                Err(t("review_cleanup_unverified").to_string())
            );
        } else {
            assert!(mode == "startup" || after_release || before_attach);
            app.as_mut().unwrap().finish_operation(false);
        }
        if before_attach {
            assert!(app.as_ref().unwrap().review_cleanup_unverified);
            assert_eq!(watcher.populated(), Ok(true));
        }
        if failing_cancel {
            let app = app.as_ref().unwrap();
            assert!(app.review_cleanup_unverified);
            assert!(matches!(app.status, AppStatus::UpgradeFailed(_, _)));
            assert_eq!(watcher.populated(), Ok(true));
        } else if after_release {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                match watcher.populated() {
                    Ok(false) => break,
                    Ok(true) if tokio::time::Instant::now() < deadline => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    other => {
                        panic!("fixture cancellation before startup resumed unverified: {other:?}")
                    }
                }
            }
        }
        resume_tx.send(()).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(5), finished_rx)
            .await
            .unwrap()
            .unwrap());
        let cleanup_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match watcher.populated() {
                Ok(false) => break,
                Ok(true) if tokio::time::Instant::now() < cleanup_deadline => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                other => panic!("fixture cleanup unverified: {other:?}"),
            }
        }
        assert!(!Path::new(&format!("/proc/{child_pid}")).exists());
        if after_release {
            assert!(directory.join("bridge-root-pid").exists());
            tokio::time::sleep(Duration::from_secs(7)).await;
            assert!(!directory.join("survived").exists());
        } else {
            assert!(!directory.join("bridge-root-pid").exists());
        }
        if let Some(app) = app.as_mut() {
            assert!(app.event_rx.try_recv().is_err());
            if failing_cancel {
                assert!(app.review_cleanup_unverified);
                assert!(app
                    .policy_block_reason(&Dependency {
                        name: "synthetic".into(),
                        current_version: "1".into(),
                        latest_version: "2".into(),
                        ecosystem: Ecosystem::Cargo,
                        is_global: false,
                        origin: None,
                    })
                    .is_some());
            }
            if mode == "startup-replace" {
                assert!(app.active_review_attempt.is_none());
                assert!(app.review_cleanup_unverified);
                app.finish_operation(false);
            }
        }
        if failing_cancel {
            println!(
                "app {mode}: failure reported while populated; later cleanup did not clear block"
            );
        } else if after_release {
            println!("app {mode}: cgroup emptied before startup resumed; child reaped; detached marker absent");
        } else {
            println!("app {mode}: admitted child reaped; cgroup empty; worker not started");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_queued_review_does_not_start_synthetic_work() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic-queued".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        app.spawn_review_future(dep, false, false, async move {
            let _ = started_tx.send(());
            ReviewReport::unavailable("synthetic")
        });
        app.finish_operation(false);
        assert!(tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .is_err());
        assert!(app.event_rx.try_recv().is_err());
    }

    // Demonstrates a limitation, not a safety guarantee: Tokio cannot
    // interrupt synchronous startup until the future yields again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_review_can_continue_inside_blocking_startup() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic-startup".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (continued_tx, continued_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        app.spawn_review_future(dep, false, false, async move {
            let _ = started_tx.send(());
            release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            let _ = continued_tx.send(());
            std::future::pending::<ReviewReport>().await
        });
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .unwrap();
        app.finish_operation(false);
        assert!(app.active_review_attempt.is_none());
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), continued_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(app.event_rx.try_recv().is_err());
    }

    /// Run only inside the dedicated delegated unit created by the opt-in
    /// synthetic harness; no real credentials or external services are used.
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    #[tokio::test]
    #[ignore = "requires delegated systemd user unit and synthetic Codex fixture"]
    async fn supervised_review_fixture_stops_on_cancel_or_worker_panic() {
        fn process_identity(pid: u32) -> std::io::Result<Option<(u32, u64)>> {
            let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(stat) => stat,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
            let fields = stat
                .rsplit_once(") ")
                .ok_or(std::io::ErrorKind::InvalidData)?
                .1
                .split_whitespace()
                .collect::<Vec<_>>();
            let parent = fields
                .get(1)
                .ok_or(std::io::ErrorKind::InvalidData)?
                .parse()
                .map_err(|_| std::io::ErrorKind::InvalidData)?;
            let start = fields
                .get(19)
                .ok_or(std::io::ErrorKind::InvalidData)?
                .parse()
                .map_err(|_| std::io::ErrorKind::InvalidData)?;
            Ok(Some((parent, start)))
        }
        let directory = PathBuf::from(std::env::var_os("TUCUPI_APP_FIXTURE_DIR").unwrap());
        let codex_dir = PathBuf::from(std::env::var_os("TUCUPI_APP_FIXTURE_CODEX_DIR").unwrap());
        let mode = std::env::var("TUCUPI_APP_FIXTURE_MODE").unwrap();
        assert!(mode == "cancel" || mode == "panic" || mode == "replace");
        let bridge =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/codex_private_bridge_fixture.py");
        let mut app = App::new(directory.clone(), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (trigger_tx, trigger_rx) = tokio::sync::oneshot::channel();
        let fixture_dir = directory.clone();
        let worker_mode = mode.clone();
        app.spawn_review_future_with_gate(dep, false, false, move |start_gate| async move {
            let supervisor = review::FixtureSupervisedChild::spawn_fixture_cancellable(
                &fixture_dir,
                &codex_dir,
                &bridge,
                false,
                &start_gate,
            )
            .expect("synthetic supervisor did not start");
            let _owned = supervisor;
            let _ = ready_tx.send(());
            let _ = trigger_rx.await;
            if worker_mode == "panic" {
                panic!("synthetic supervisor worker failure");
            }
            std::future::pending::<ReviewReport>().await
        });
        tokio::time::timeout(Duration::from_secs(8), ready_rx)
            .await
            .unwrap()
            .unwrap();
        let marker = directory.join("request-in-flight");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while !marker.exists() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "synthetic request did not start"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let child_pid: u32 = std::fs::read_to_string(directory.join("bridge-root-pid"))
            .unwrap()
            .parse()
            .unwrap();
        let identity = process_identity(child_pid).unwrap().unwrap();
        assert_eq!(identity.0, std::process::id());
        let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .unwrap();
        let group = Path::new("/sys/fs/cgroup")
            .join(relative)
            .join("tucupi-child-fixture");
        let watcher = crate::codex_supervision::CgroupObservation::open(&group).unwrap();
        assert_eq!(watcher.populated(), Ok(true));
        if mode == "cancel" {
            app.finish_operation(false);
        } else if mode == "replace" {
            let replacement = Dependency {
                name: "replacement".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            app.spawn_review_future(replacement, false, false, async {
                std::future::pending::<ReviewReport>().await
            });
            assert!(app.active_review_attempt.is_none());
            assert!(app.review_cleanup_unverified);
        } else {
            trigger_tx.send(()).unwrap();
            let event = tokio::time::timeout(Duration::from_secs(5), app.event_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(&event, AppEvent::ReviewChecked(_, _, report, false, false)
                if report.verdict == ReviewVerdict::Review && report.reason == "source review task failed — treat as unreviewed")
            );
            app.handle_event(event);
            assert!(app.review_cleanup_unverified);
            assert!(matches!(app.status, AppStatus::UpgradeFailed(_, _)));
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match watcher.populated() {
                Ok(false) => break,
                Ok(true) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(10)).await
                }
                result => panic!("synthetic cleanup unverified: {result:?}"),
            }
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while process_identity(child_pid).unwrap() == Some(identity) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "synthetic direct child was not reaped"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_secs(7)).await;
        assert!(!directory.join("survived").exists());
        if mode == "replace" {
            assert!(app.active_review_attempt.is_none());
            assert!(app.review_cleanup_unverified);
            assert!(app.event_rx.try_recv().is_err());
            app.finish_operation(false);
        }
        println!("app {mode}: synthetic cgroup empty; direct child reaped; detached marker absent");
    }

    #[tokio::test]
    async fn ending_operation_or_dropping_app_aborts_review_task() {
        struct OnDrop(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        for (close_app, wait_for_start) in [(false, true), (true, true), (false, false)] {
            let mut app = App::new(PathBuf::from("."), false);
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            let guard = OnDrop(Some(dropped_tx));
            app.spawn_review_future(dep, false, false, async move {
                let _guard = guard;
                let _ = started_tx.send(());
                std::future::pending::<ReviewReport>().await
            });
            if wait_for_start {
                tokio::time::timeout(Duration::from_secs(2), started_rx)
                    .await
                    .unwrap()
                    .unwrap();
            }
            if close_app {
                drop(app);
            } else {
                app.finish_operation(false);
                assert!(app.active_review_attempt.is_none());
                assert!(app.active_review_task.is_none());
            }
            tokio::time::timeout(Duration::from_secs(2), dropped_rx)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn ending_review_drops_inflight_synthetic_http_request() {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut headers = Vec::new();
            let mut byte = [0_u8; 1];
            while !headers.ends_with(b"\r\n\r\n") && headers.len() < 8192 {
                stream.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
            }
            let text = String::from_utf8(headers).unwrap().to_ascii_lowercase();
            assert!(text.contains("authorization: bearer synthetic-only"));
            let _ = started_tx.send(());
            let closed = matches!(stream.read(&mut byte), Ok(0));
            let _ = closed_tx.send(closed);
        });
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.spawn_review_future(dep, false, false, async move {
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let _ = client
                .get(format!("http://{address}/synthetic"))
                .bearer_auth("synthetic-only")
                .send()
                .await;
            ReviewReport::unavailable("synthetic")
        });
        tokio::time::timeout(Duration::from_secs(3), started_rx)
            .await
            .unwrap()
            .unwrap();
        app.finish_operation(false);
        assert!(tokio::time::timeout(Duration::from_secs(4), closed_rx)
            .await
            .unwrap()
            .unwrap());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn review_worker_panic_is_inconclusive_in_upgrade_and_audit() {
        for (audit_only, force) in [(false, false), (false, true), (true, false)] {
            let mut app = App::new(PathBuf::from("."), false);
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            app.spawn_review_future(dep, force, audit_only, async {
                panic!("synthetic review worker panic");
                #[allow(unreachable_code)]
                ReviewReport::unavailable("unreachable")
            });
            let event = tokio::time::timeout(Duration::from_secs(2), app.event_rx.recv())
                .await
                .unwrap()
                .unwrap();
            match &event {
                AppEvent::ReviewChecked(1, _, report, false, flag) => {
                    assert_eq!(*flag, audit_only);
                    assert_eq!(report.verdict, ReviewVerdict::Review);
                    assert_eq!(
                        report.reason,
                        "source review task failed — treat as unreviewed"
                    );
                }
                _ => panic!("unexpected review event"),
            }
            app.handle_event(event);
            if audit_only {
                assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
            } else {
                assert!(matches!(app.modal, Modal::ConfirmReview(_, _)));
            }
            assert!(app.active_review_task.is_none());
            assert!(app.active_review_attempt.is_none());
        }
    }

    #[test]
    fn late_review_event_after_operation_finished_is_ignored() {
        let mut app = App::new(PathBuf::from("."), false);
        app.active_review_attempt = Some(1);
        app.finish_operation(false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: true,
            origin: None,
        };
        let report = ReviewReport {
            verdict: ReviewVerdict::Review,
            reason: "synthetic".into(),
            view_mode: review::ReviewViewMode::Diff,
            residual_line_count: 1,
            hits: Vec::new(),
            origin: review::ReviewOrigin::Unknown,
        };
        app.handle_event(AppEvent::ReviewChecked(1, dep, report, false, false));
        assert!(matches!(app.modal, Modal::None));
        assert!(app.review_cache.is_empty());
    }

    #[test]
    fn review_events_are_bound_to_one_attempt_and_consumed_once() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: true,
            origin: None,
        };
        let report = ReviewReport {
            verdict: ReviewVerdict::Review,
            reason: "synthetic".into(),
            view_mode: review::ReviewViewMode::Diff,
            residual_line_count: 1,
            hits: Vec::new(),
            origin: review::ReviewOrigin::Unknown,
        };
        app.active_review_attempt = Some(2);
        app.handle_event(AppEvent::ReviewChecked(
            1,
            dep.clone(),
            report.clone(),
            false,
            false,
        ));
        assert!(matches!(app.modal, Modal::None));
        assert!(app.review_cache.is_empty());
        assert_eq!(app.active_review_attempt, Some(2));

        app.handle_event(AppEvent::ReviewChecked(
            2,
            dep.clone(),
            report.clone(),
            false,
            false,
        ));
        assert!(matches!(app.modal, Modal::ConfirmReview(_, _)));
        assert_eq!(app.review_cache.len(), 1);
        assert_eq!(app.active_review_attempt, None);

        app.modal = Modal::None;
        app.handle_event(AppEvent::ReviewChecked(2, dep, report, false, false));
        assert!(matches!(app.modal, Modal::None));
        assert_eq!(app.review_cache.len(), 1);
    }

    #[tokio::test]
    async fn spawned_review_delivers_its_attempt_id_for_upgrade_and_audit() {
        for audit_only in [false, true] {
            let mut app = App::new(PathBuf::from("."), false);
            let dep = Dependency {
                name: "synthetic".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            app.spawn_review_task(dep, false, audit_only);
            let event =
                tokio::time::timeout(std::time::Duration::from_secs(2), app.event_rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
            assert!(
                matches!(&event, AppEvent::ReviewChecked(1, _, _, false, flag) if *flag == audit_only)
            );
            app.handle_event(event);
            assert_eq!(app.active_review_attempt, None);
            if audit_only {
                assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
            } else {
                assert!(matches!(app.modal, Modal::ConfirmReview(_, _)));
            }
        }
    }

    #[test]
    fn exhausted_review_attempt_ids_fail_closed_without_spawning() {
        let mut app = App::new(PathBuf::from("."), false);
        app.next_review_attempt = u64::MAX;
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: true,
            origin: None,
        };
        app.spawn_review_task(dep, false, false);
        assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
        assert!(app.active_review_attempt.is_none());
        assert!(app.event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn unsupported_scope_blocks_before_starting_upgrade() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: false,
            origin: None,
        };
        assert!(get_upgrade_cmd(&dep, Path::new(".")).is_none());
        app.start_upgrade_confirmed(dep);
        assert!(matches!(app.modal, Modal::BlockedPolicy(_, _)));
        assert!(app.event_rx.try_recv().is_err());
    }

    #[test]
    fn partial_audit_with_nvd_finding_blocks_even_forced_upgrade() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "example".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: true,
            origin: None,
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
        let failure = AuditFailure {
            message: "OSV offline".into(),
            findings: vec![finding],
            partial: true,
        };
        app.process_security_result(dep.clone(), Err(failure), true);
        app.start_upgrade_operation(dep, true);
        assert!(
            matches!(&app.modal, Modal::BlockedPolicy(_, message) if message.contains("CVE-TEST"))
        );
        assert!(app.event_rx.try_recv().is_err());
    }

    #[test]
    fn inconclusive_source_review_is_not_a_vulnerability() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "example".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: true,
            origin: None,
        };
        let report = ReviewReport {
            verdict: ReviewVerdict::Review,
            reason: "LLM output unparsable — treat as unreviewed".into(),
            view_mode: review::ReviewViewMode::Diff,
            residual_line_count: 1,
            hits: Vec::new(),
            origin: review::ReviewOrigin::Unknown,
        };
        app.process_review_result(dep, report, false, false);
        assert!(matches!(app.modal, Modal::ConfirmReview(_, _)));
    }

    #[test]
    fn stale_safe_review_requires_confirmation_when_provider_disabled() {
        let mut app = App::new(PathBuf::from("."), false);
        app.config.security.review_provider = Some("claude".into());
        let dep = Dependency {
            name: "example".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Homebrew,
            is_global: true,
            origin: None,
        };
        let report = ReviewReport {
            verdict: ReviewVerdict::Safe,
            reason: "old AI approval".into(),
            view_mode: review::ReviewViewMode::Diff,
            residual_line_count: 2,
            hits: Vec::new(),
            origin: review::ReviewOrigin::Unknown,
        };
        app.review_cache.insert(app.review_cache_key(&dep), report);
        app.start_upgrade(dep, false);
        assert!(matches!(
            app.modal,
            Modal::ConfirmReview(
                _,
                ReviewReport {
                    verdict: ReviewVerdict::Review,
                    ..
                }
            )
        ));
    }

    #[test]
    fn impact_event_always_requires_confirmation_and_can_be_cancelled() {
        for preview in [
            crate::impact::ImpactPreview::Unavailable,
            crate::impact::ImpactPreview::ManagerOutput {
                text: "partial plan".into(),
                truncated: false,
            },
        ] {
            let mut app = App::new(PathBuf::from("."), false);
            let dep = Dependency {
                name: "example".into(),
                current_version: "1".into(),
                latest_version: "2".into(),
                ecosystem: Ecosystem::Cargo,
                is_global: false,
                origin: None,
            };
            app.active_impact_attempt = Some(1);
            app.handle_event(AppEvent::ImpactChecked(1, dep, preview));
            assert!(matches!(app.modal, Modal::ConfirmImpact { .. }));
            app.dismiss_modal();
            assert!(matches!(app.modal, Modal::None));
            assert!(app.event_rx.try_recv().is_err());
        }
    }

    #[test]
    fn impact_attempt_ignores_old_and_duplicate_results() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "synthetic".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.active_impact_attempt = Some(2);
        app.handle_event(AppEvent::ImpactChecked(
            1,
            dep.clone(),
            crate::impact::ImpactPreview::Unavailable,
        ));
        assert!(matches!(app.modal, Modal::None));
        app.handle_event(AppEvent::ImpactChecked(
            2,
            dep.clone(),
            crate::impact::ImpactPreview::Unavailable,
        ));
        assert!(matches!(app.modal, Modal::ConfirmImpact { .. }));
        app.modal = Modal::None;
        app.handle_event(AppEvent::ImpactChecked(
            2,
            dep,
            crate::impact::ImpactPreview::Unavailable,
        ));
        assert!(matches!(app.modal, Modal::None));
        assert!(app.event_rx.try_recv().is_err());
    }

    #[test]
    fn upgrade_failure_uses_active_package_not_localized_status_text() {
        let mut app = App::new(PathBuf::from("."), false);
        let dep = Dependency {
            name: "example".into(),
            current_version: "1".into(),
            latest_version: "2".into(),
            ecosystem: Ecosystem::Cargo,
            is_global: false,
            origin: None,
        };
        app.active_operation = Some(QueuedOperation {
            dep,
            force: false,
            kind: OperationKind::Upgrade,
        });
        app.status = AppStatus::Upgrading("arbitrary translated status".into());
        app.handle_event(AppEvent::UpgradeFinished(Err("failure".into())));
        assert!(matches!(&app.status, AppStatus::UpgradeFailed(name, _) if name == "example"));
    }

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

    #[test]
    fn selection_state_cycles_from_unselected_to_safe_to_force() {
        assert_eq!(SelectionState::Unselected.next(), SelectionState::Safe);
        assert_eq!(SelectionState::Safe.next(), SelectionState::Force);
        assert_eq!(SelectionState::Force.next(), SelectionState::Unselected);
    }

    #[test]
    fn retain_recent_log_lines_keeps_the_configured_limit() {
        let mut lines: Vec<String> = (0..=MAX_LOG_LINES_PER_DEPENDENCY)
            .map(|index| index.to_string())
            .collect();

        retain_recent_log_lines(&mut lines);

        assert_eq!(lines.len(), MAX_LOG_LINES_PER_DEPENDENCY);
        assert_eq!(lines.first(), Some(&"1".to_string()));
        assert_eq!(
            lines.last(),
            Some(&MAX_LOG_LINES_PER_DEPENDENCY.to_string())
        );
    }

    #[test]
    fn cargo_global_upgrade_uses_locked_install() {
        let dependency = Dependency {
            name: "cargo-nextest".to_string(),
            current_version: "0.9.143".to_string(),
            latest_version: "0.9.144".to_string(),
            ecosystem: Ecosystem::Cargo,
            is_global: true,
            origin: None,
        };

        let (command, arguments) = get_upgrade_cmd(&dependency, Path::new(".")).unwrap();

        assert_eq!(command, "cargo");
        assert_eq!(
            arguments,
            vec!["install", "cargo-nextest", "--force", "--locked"]
        );
    }
}
