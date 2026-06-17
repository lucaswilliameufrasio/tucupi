use crate::adapters::{check_all_outdated, check_global_outdated};
use crate::config::Config;
use crate::i18n::t;
use crate::models::{Dependency, Ecosystem, VulnerabilityInfo};
use crate::security::SecurityChecker;
use ratatui::widgets::TableState;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
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
    ConfirmForce(Dependency, Vec<VulnerabilityInfo>),
}

pub enum AppEvent {
    ScanFinished(Tab, Vec<Dependency>),
    SecurityChecked(Dependency, Result<Vec<VulnerabilityInfo>, String>, bool),
    UpgradeFinished(Result<(), String>),
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
    pub security_check_only: bool,
    pub batch_scan_pending: usize,

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
            security_check_only: false,
            batch_scan_pending: 0,
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
    }

    pub fn trigger_scan(&mut self) {
        self.status = AppStatus::Scanning;
        self.local_deps.clear();
        self.global_deps.clear();
        self.vuln_cache.clear();
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

    fn trigger_batch_security_scan(&mut self) {
        let all_deps: Vec<Dependency> = self
            .local_deps
            .iter()
            .chain(self.global_deps.iter())
            .cloned()
            .collect();

        let targets: Vec<(Dependency, u64)> = all_deps
            .into_iter()
            .filter(|d| d.ecosystem.has_osv_coverage())
            .map(|d| (d, self.config.osv_timeout_secs()))
            .collect();

        self.batch_scan_pending = targets.len();
        if self.batch_scan_pending == 0 {
            return;
        }

        for (dep, timeout) in targets {
            let tx = self.event_tx.clone();
            tokio::spawn(async move {
                let checker = SecurityChecker::new_with_config(timeout);
                let result = checker
                    .check_vulnerability(&dep.name, &dep.latest_version, dep.ecosystem)
                    .await;
                let _ = tx.send(AppEvent::SecurityChecked(
                    dep,
                    result.map_err(|e| e.to_string()),
                    true,
                ));
            });
        }
    }

    pub fn trigger_upgrade_selected(&mut self, force: bool) {
        let dep = match self.selected_dep() {
            Some(d) => d.clone(),
            None => return,
        };

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
                Err(_) if force => {
                    self.start_upgrade(dep);
                }
                Err(err_msg) => {
                    self.status = AppStatus::UpgradeFailed(
                        dep.name.clone(),
                        format!("Security check failed: {}", err_msg),
                    );
                }
            }
            return;
        }

        self.status = AppStatus::Upgrading(format!("Auditing security for {}...", dep.name));
        let tx = self.event_tx.clone();
        let checker = SecurityChecker::new_with_config(self.config.osv_timeout_secs());
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
        let checker = SecurityChecker::new_with_config(self.config.osv_timeout_secs());
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
                if self.config.block_vulnerable() {
                    self.status = AppStatus::UpgradeFailed(
                        dep.name.clone(),
                        format!(
                            "Security check failed: {}. Upgrade BLOCKED by repository configuration.",
                            err_msg
                        ),
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
                        }],
                    );
                    self.status = AppStatus::Ready;
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
        let active_vulns: Vec<VulnerabilityInfo> = vulns
            .into_iter()
            .filter(|v| !self.config.is_vulnerability_ignored(&v.id))
            .collect();

        if active_vulns.is_empty() || self.config.is_package_ignored(&dep.name) {
            self.start_upgrade(dep);
        } else if self.config.block_vulnerable() {
            self.modal = Modal::Blocked(dep, active_vulns);
            self.status = AppStatus::Ready;
        } else if force {
            self.modal = Modal::None;
            self.start_upgrade(dep);
        } else {
            self.modal = Modal::ConfirmForce(dep, active_vulns);
            self.status = AppStatus::Ready;
        }
    }

    fn start_upgrade(&mut self, dep: Dependency) {
        let is_cargo_local = !dep.is_global && dep.ecosystem == Ecosystem::Cargo;
        let pipe_upgrade = !dep.is_global;
        self.status = AppStatus::Upgrading(format!(
            "Upgrading {} to {}...",
            dep.name, dep.latest_version
        ));
        let tx = self.event_tx.clone();
        let target_dir = self.target_dir.clone();
        let dep_name = dep.name.clone();

        tokio::spawn(async move {
            let (cmd, args) = get_upgrade_cmd(&dep, &target_dir);
            let mut result = run_upgrade_process(&cmd, args, &target_dir, pipe_upgrade).await;

            if result.is_ok() && is_cargo_local {
                let update_args = vec!["update".to_string(), "-p".to_string(), dep_name.clone()];
                let fetch_result =
                    run_upgrade_process("cargo", update_args, &target_dir, true).await;
                if let Err(e) = fetch_result {
                    result = Err(e
                        .lines()
                        .next()
                        .unwrap_or("cargo update failed")
                        .to_string());
                }
            }

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
                    self.trigger_batch_security_scan();
                }
            }
            AppEvent::SecurityChecked(dep, res, from_pre_scan) => {
                self.process_security_result(dep, res, from_pre_scan);
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
                    "install".to_string(),
                    format!("{}@{}", dep.name, clean_version),
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

pub(crate) async fn run_upgrade_process(
    cmd: &str,
    args: Vec<String>,
    dir: &Path,
    pipe: bool,
) -> Result<(), String> {
    if !pipe {
        let mut child = tokio::process::Command::new(cmd)
            .args(&args)
            .current_dir(dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("Failed to start process: {}", e))?;

        let status = tokio::time::timeout(std::time::Duration::from_secs(120), child.wait())
            .await
            .map_err(|_| "Process timed out after 120 seconds.".to_string())?
            .map_err(|e| format!("Failed to wait for process: {}", e))?;

        if status.success() {
            return Ok(());
        }
        let exit_code = status
            .code()
            .map_or("unknown".to_string(), |c| c.to_string());
        return Err(format!("Process failed with exit code {}", exit_code));
    }

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        tokio::process::Command::new(cmd)
            .args(&args)
            .current_dir(dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await;

    let output = match output {
        Ok(out) => out,
        Err(_timeout) => return Err("Process timed out after 120 seconds.".to_string()),
    };

    match output {
        Ok(out) => {
            if out.status.success() {
                Ok(())
            } else {
                let exit_code = out
                    .status
                    .code()
                    .map_or("unknown".to_string(), |code| code.to_string());
                let stderr = String::from_utf8_lossy(&out.stderr);
                let error_lines: Vec<&str> = stderr
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
                let hint = suggest_fix(&stderr);
                Err(format!(
                    "Comando: {}\n\nSaída: {} (exit: {})\n\n{}",
                    command_line, last_error, exit_code, hint
                ))
            }
        }
        Err(e) => Err(format!("Failed to start process: {}", e)),
    }
}
