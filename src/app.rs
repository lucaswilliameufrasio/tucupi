use crate::models::{Dependency, Ecosystem, VulnerabilityInfo};
use crate::config::Config;
use crate::security::SecurityChecker;
use crate::adapters::{check_all_outdated, check_global_outdated};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use ratatui::widgets::TableState;
use tokio::sync::mpsc;
use std::process::Stdio;

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
    SecurityChecked(Dependency, Result<Vec<VulnerabilityInfo>, String>),
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
        let next = (current + 1) % len;
        self.table_state.select(Some(next));
    }

    pub fn scroll_up(&mut self) {
        let len = self.current_deps().len();
        if len == 0 {
            self.table_state.select(None);
            return;
        }
        let current = self.table_state.selected().unwrap_or(0);
        let prev = if current == 0 { len - 1 } else { current - 1 };
        self.table_state.select(Some(prev));
    }

    pub fn switch_tab(&mut self) {
        self.active_tab = match self.active_tab {
            Tab::Local => Tab::Global,
            Tab::Global => Tab::Local,
        };
        self.table_state.select(if self.current_deps().is_empty() { None } else { Some(0) });
    }

    pub fn trigger_scan(&mut self) {
        self.status = AppStatus::Scanning;
        self.local_deps.clear();
        self.global_deps.clear();
        self.table_state.select(None);

        let tx = self.event_tx.clone();
        let dir = self.target_dir.clone();

        // 1. Spawn local scan
        tokio::spawn(async move {
            let deps = check_all_outdated(&dir).await;
            let _ = tx.send(AppEvent::ScanFinished(Tab::Local, deps));
        });

        // 2. Spawn global scan
        let tx_global = self.event_tx.clone();
        tokio::spawn(async move {
            let deps = check_global_outdated().await;
            let _ = tx_global.send(AppEvent::ScanFinished(Tab::Global, deps));
        });
    }

    pub async fn load_config_sync(&mut self) {
        self.config = Config::load_from_dir(&self.target_dir).await;
    }

    pub fn trigger_upgrade_selected(&mut self, force: bool) {
        let dep = match self.selected_dep() {
            Some(d) => d.clone(),
            None => return,
        };

        if self.status == AppStatus::Scanning {
            return;
        }

        // Cache key for OSV check
        let cache_key = format!("{}_{}_{}", dep.ecosystem.as_str(), dep.name, dep.latest_version);

        // Check cache first
        if let Some(cached_result) = self.vuln_cache.get(&cache_key) {
            match cached_result {
                Ok(vulns) => {
                    self.process_upgrade_with_vulns(dep, vulns.clone(), force);
                }
                Err(_) if force => {
                    // Cache lookup returned error (e.g. offline), but user wants to force
                    self.start_upgrade(dep);
                }
                Err(err_msg) => {
                    // Show warning that security checks failed
                    self.status = AppStatus::UpgradeFailed(dep.name.clone(), format!("Security check failed: {}", err_msg));
                }
            }
            return;
        }

        // Trigger security check
        self.status = AppStatus::Upgrading(format!("Auditing security for {}...", dep.name));
        let tx = self.event_tx.clone();
        let checker = SecurityChecker::new();
        let d = dep.clone();

        tokio::spawn(async move {
            match checker.check_vulnerability(&d.name, &d.latest_version, d.ecosystem).await {
                Ok(vulns) => {
                    let _ = tx.send(AppEvent::SecurityChecked(d, Ok(vulns)));
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::SecurityChecked(d, Err(e.to_string())));
                }
            }
        });
    }

    pub fn process_security_result(&mut self, dep: Dependency, res: Result<Vec<VulnerabilityInfo>, String>) {
        let cache_key = format!("{}_{}_{}", dep.ecosystem.as_str(), dep.name, dep.latest_version);
        self.vuln_cache.insert(cache_key, res.clone());

        match res {
            Ok(vulns) => {
                self.process_upgrade_with_vulns(dep, vulns, false);
            }
            Err(err_msg) => {
                // If security check fails (offline/timeout), check policy
                if self.config.block_vulnerable() {
                    self.status = AppStatus::UpgradeFailed(
                        dep.name.clone(),
                        format!("Security check failed: {}. Upgrade BLOCKED by repository configuration.", err_msg)
                    );
                } else {
                    // Warning shown, allow forcing since config doesn't block it
                    self.modal = Modal::ConfirmForce(dep, vec![VulnerabilityInfo {
                        id: "OFFLINE_WARNING".to_string(),
                        summary: "Não foi possível verificar vulnerabilidades online.".to_string(),
                        details: format!("O erro retornado foi: {}. Deseja forçar o upgrade mesmo assim?", err_msg),
                        aliases: Vec::new(),
                    }]);
                    self.status = AppStatus::Ready;
                }
            }
        }
    }

    fn process_upgrade_with_vulns(&mut self, dep: Dependency, vulns: Vec<VulnerabilityInfo>, force: bool) {
        // Filter out ignored vulnerabilities based on config
        let active_vulns: Vec<VulnerabilityInfo> = vulns.into_iter()
            .filter(|v| !self.config.is_vulnerability_ignored(&v.id))
            .collect();

        if active_vulns.is_empty() {
            // Safe to upgrade
            self.start_upgrade(dep);
        } else if self.config.is_package_ignored(&dep.name) {
            // Package is explicitly ignored in configuration, skip security checks
            self.start_upgrade(dep);
        } else if self.config.block_vulnerable() {
            // Blocked by repository rules
            self.modal = Modal::Blocked(dep, active_vulns);
            self.status = AppStatus::Ready;
        } else if force {
            // User confirmed they want to force it
            self.modal = Modal::None;
            self.start_upgrade(dep);
        } else {
            // Present warning modal and prompt to force
            self.modal = Modal::ConfirmForce(dep, active_vulns);
            self.status = AppStatus::Ready;
        }
    }

    fn start_upgrade(&mut self, dep: Dependency) {
        self.status = AppStatus::Upgrading(format!("Upgrading {} to {}...", dep.name, dep.latest_version));
        let tx = self.event_tx.clone();
        let target_dir = self.target_dir.clone();

        tokio::spawn(async move {
            let (cmd, args) = get_upgrade_cmd(&dep, &target_dir);
            let result = run_upgrade_process(&cmd, args, &target_dir).await;
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
                    self.table_state.select(if self.current_deps().is_empty() { None } else { Some(0) });
                }
            }
            AppEvent::SecurityChecked(dep, res) => {
                self.process_security_result(dep, res);
            }
            AppEvent::UpgradeFinished(res) => {
                match res {
                    Ok(_) => {
                        let name = match self.status {
                            AppStatus::Upgrading(ref msg) => {
                                // Extract name from upgrading status message if possible
                                msg.split_whitespace().nth(1).unwrap_or("dependency").to_string()
                            }
                            _ => "dependency".to_string(),
                        };
                        self.status = AppStatus::UpgradeSuccess(name);
                        // Re-trigger scan to show updated dependency list
                        self.trigger_scan();
                    }
                    Err(err_msg) => {
                        let name = match self.status {
                            AppStatus::Upgrading(ref msg) => {
                                msg.split_whitespace().nth(1).unwrap_or("dependency").to_string()
                            }
                            _ => "dependency".to_string(),
                        };
                        self.status = AppStatus::UpgradeFailed(name, err_msg);
                    }
                }
            }
        }
    }
}

fn get_upgrade_cmd(dep: &Dependency, target_dir: &Path) -> (String, Vec<String>) {
    if dep.is_global {
        match dep.ecosystem {
            Ecosystem::Npm => {
                ("npm".to_string(), vec!["install".to_string(), "-g".to_string(), format!("{}@{}", dep.name, dep.latest_version)])
            }
            Ecosystem::Cargo => {
                ("cargo".to_string(), vec!["install".to_string(), dep.name.clone(), "--force".to_string()])
            }
            _ => ("echo".to_string(), vec!["Ecosystem not supported globally".to_string()]),
        }
    } else {
        match dep.ecosystem {
            Ecosystem::Cargo => {
                ("cargo".to_string(), vec!["add".to_string(), format!("{}@{}", dep.name, dep.latest_version)])
            }
            Ecosystem::Go => {
                ("go".to_string(), vec!["get".to_string(), format!("{}@{}", dep.name, dep.latest_version)])
            }
            Ecosystem::Dart => {
                ("dart".to_string(), vec!["pub".to_string(), "add".to_string(), format!("{}:{}", dep.name, dep.latest_version)])
            }
            Ecosystem::Elixir => {
                ("mix".to_string(), vec!["deps.update".to_string(), dep.name.clone()])
            }
            Ecosystem::Npm => {
                let mut cmd = "npm".to_string();
                let mut args = vec!["install".to_string(), format!("{}@{}", dep.name, dep.latest_version)];
                
                if target_dir.join("pnpm-lock.yaml").exists() {
                    cmd = "pnpm".to_string();
                    args = vec!["add".to_string(), format!("{}@{}", dep.name, dep.latest_version)];
                } else if target_dir.join("yarn.lock").exists() {
                    cmd = "yarn".to_string();
                    args = vec!["add".to_string(), format!("{}@{}", dep.name, dep.latest_version)];
                } else if target_dir.join("bun.lockb").exists() || target_dir.join("bun.lock").exists() {
                    cmd = "bun".to_string();
                    args = vec!["add".to_string(), format!("{}@{}", dep.name, dep.latest_version)];
                } else if target_dir.join("deno.json").exists() || target_dir.join("deno.jsonc").exists() {
                    cmd = "deno".to_string();
                    args = vec!["add".to_string(), format!("npm:{}@{}", dep.name, dep.latest_version)];
                }
                
                (cmd, args)
            }
        }
    }
}

async fn run_upgrade_process(cmd: &str, args: Vec<String>, dir: &Path) -> Result<(), String> {
    let output = tokio::process::Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;

    match output {
        Ok(out) => {
            if out.status.success() {
                Ok(())
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Err(format!("Process returned exit code {}: {}", out.status, stderr.trim()))
            }
        }
        Err(e) => Err(format!("Failed to start process: {}", e)),
    }
}
