use std::collections::HashMap;
use std::sync::OnceLock;

fn detect_lang() -> &'static str {
    static LANG: OnceLock<String> = OnceLock::new();
    LANG.get_or_init(|| {
        std::env::var("LANG")
            .or_else(|_| std::env::var("LC_ALL"))
            .unwrap_or_default()
            .split('.')
            .next()
            .unwrap_or("en")
            .to_string()
    })
}

fn is_pt() -> bool {
    detect_lang().starts_with("pt")
}

fn pt_strings() -> &'static HashMap<&'static str, &'static str> {
    static PT: OnceLock<HashMap<&str, &str>> = OnceLock::new();
    PT.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("title", " 🍵 TUCUPI :: Guardião e Atualizador de Dependências ");
        m.insert("tab_local", " [1] Projeto Local ({0}) ");
        m.insert("tab_global", " [2] Pacotes Globais ({0}) ");
        m.insert("dir_repo", " Repositório: {0} ");
        m.insert("col_ecosystem", "Ecossistema");
        m.insert("col_package", "Pacote");
        m.insert("col_current", "Atual");
        m.insert("col_latest", "Mais Recente");
        m.insert("col_vulns", "Vulns");
        m.insert("table_title_local", " Dependências Desatualizadas no Repositório ");
        m.insert("table_title_global", " Dependências Globais do Sistema ");
        m.insert("detail_title", " Auditoria de Segurança & Detalhes ");
        m.insert("detail_package", "Pacote: {0}");
        m.insert("detail_ecosystem", "Ecossistema: {0}");
        m.insert("detail_version", "Versão Atual: {0}  ➔  Nova Versão: {1}");
        m.insert("upgrade_in_progress", " ⏳ Upgrade em andamento...");
        m.insert("upgrade_success", " ✓ Upgrade concluído com sucesso!");
        m.insert("upgrade_failed", " ✗ Upgrade falhou (detalhes abaixo)");
        m.insert("upgrade_none", " Nenhum upgrade em andamento.");
        m.insert("error_details", " ❌ DETALHES DO ERRO DE UPGRADE:\n{0}\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        m.insert("secure_msg", " ✓ SEGURO: Nenhuma vulnerabilidade conhecida foi detectada no banco de dados do OSV.dev para esta versão.");
        m.insert("secure_limited", " ⚠️ Auditoria indisponível para este ecossistema — não foi possível verificar vulnerabilidades.");
        m.insert("vuln_warning", " ⚠️ AVISO: {0} VULNERABILIDADE(S) ENCONTRADA(S)!\n\n");
        m.insert("vuln_item", "ID: {0} ({1})\nSumário: {2}\nDetalhes: {3}\n----------------------------------------\n");
        m.insert("audit_failed", " ❌ Falha na auditoria de segurança:\n{0}\n\nVerifique sua conexão de rede. A política local de segurança pode bloquear upgrades se não for possível validar a segurança.");
        m.insert("select_prompt", " [!] Selecione uma dependência e faça o Upgrade para rodar a auditoria de segurança.");
        m.insert("no_selection", "\n Nenhuma dependência selecionada.");
        m.insert("status_scanning", " Status: [ Varrendo dependências localmente e globalmente... ] ");
        m.insert("status_upgrading", " Status: [ {0} ] ");
        m.insert("status_success", " Status: [ Upgrade de {0} realizado com sucesso! ] ");
        m.insert("status_failed", " Status: [ Falha ao atualizar {0}: {1} ] ");
        m.insert("status_ready", " Status: [ Pronto ] ");
        m.insert("help_tui", " [q] Sair | [Tab] Alternar Local/Global | [r] Atualizar Lista | [u] Upgrade Seguro | [f] Forçar Upgrade | [c] Checar Segurança ");
        m.insert("modal_force_title", " ⚠️ ALERTA DE SEGURANÇA: VULNERABILIDADE DETECTADA ");
        m.insert("modal_force_msg", "O pacote {0} possui vulnerabilidades reportadas na versão alvo ({1})!\n\nA política deste repositório permite upgrades forçados após aviso.\n\nVulnerabilidades ativas:\n\n");
        m.insert("modal_force_item", "  * ID: {0} - {1}\n");
        m.insert("modal_force_footer", "\n\nPressione [Enter] para FORÇAR a instalação.\nPressione [Esc] para CANCELAR.");
        m.insert("modal_blocked_title", " ❌ UPGRADE BLOQUEADO POR POLÍTICA DE SEGURANÇA ");
        m.insert("modal_blocked_msg", "O pacote {0} possui vulnerabilidades de segurança na versão alvo ({1}).\n\nDe acordo com a configuração de política em 'tucupi.toml' (block_vulnerable = true), upgrades para versões vulneráveis estão TERMINANTEMENTE PROIBIDOS.\n\nVulnerabilidades impeditivas:\n\n");
        m.insert("modal_blocked_item", "  * ID: {0} - {1}\n");
        m.insert("modal_blocked_footer", "\n\nPressione [Esc] ou [Enter] para fechar este alerta.");
        // batch mode
        m.insert("batch_title", " 🍵 TUCUPI :: Modo Interativo ");
        m.insert("batch_scanning", " Escaneando dependências em todos os ecossistemas...\n\n Isso pode levar alguns segundos.");
        m.insert("batch_header", " Dependências desatualizadas encontradas: {0}");
        m.insert("batch_help_scan", " [q] Sair ");
        m.insert("batch_help_select", " [↑↓] Navegar | [Espaço] Ciclar ([ ]→[✓]→[⚡]) | [Enter] Executar | [q] Sair     Selecionados: {0}  Forçar: {1}");
        m.insert("batch_help_exec", " [q] Sair ");
        m.insert("batch_help_report", " [q] Sair | [r] Re-escanear ");
        m.insert("batch_exec_title", " Executando upgrades... ({0}/{1})");
        m.insert("batch_report_title", " Relatório de Atualizações ");
        m.insert("batch_report_safe", " ✓ ATUALIZADOS COM SEGURANÇA ({0})");
        m.insert("batch_report_forced", " ⚡ ATUALIZADOS COM FORÇA ({0})");
        m.insert("batch_report_failed", " ✗ FALHARAM ({0})");
        m.insert("batch_report_blocked", " ⊘ BLOQUEADOS POR SEGURANÇA ({0})");
        m.insert("batch_report_skipped", " ⊘ PULADOS (VULNERÁVEIS, SEM FORÇA) ({0})");
        m.insert("batch_report_summary", " Resumo: {0} concluídos, {1} falharam, {2} bloqueados, {3} pulados");
        m.insert("batch_pending", "Pendente");
        m.insert("batch_done", "Concluído");
        m.insert("batch_forced", "Forçado");
        m.insert("exec_blocked", "[BLOCKED] {0} — bloqueado por política de segurança");
        m.insert("exec_skipped", "[SKIPPED] {0} — vulnerável, sem força habilitada");
        m.insert("exec_upgrading", "Upgrading {0} to {1}...");
        m.insert("exec_forced_msg", "[FORCED] {0} — upgrade forçado concluído");
        m.insert("exec_ok_msg", "[OK] {0} — upgrade seguro concluído");
        m.insert("exec_failed_msg", "[FAILED] {0} — {1}");
        m.insert("audit_label", "Auditing security for {0}...");
        m.insert("version_label", "Versão");
        m.insert("details_label", "Detalhes");
        m.insert("separator", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        // severity
        m.insert("severity_critical", "CRÍTICO");
        m.insert("severity_high", "ALTO");
        m.insert("severity_medium", "MÉDIO");
        m.insert("severity_low", "BAIXO");
        m.insert("score_label", "CVSS: {0}");
        // freshness
        m.insert("freshness_warn", " ⚠️ Versão publicada há {0} dias — considerado recente. Verifique a procedência antes de atualizar.");
        m.insert("freshness_ok", " ✓ Versão madura (publicada há mais de {0} dias).");
        // provenance
        m.insert("provenance_title", " 🛡 Proveniência");
        m.insert("provenance_signed", " ✓ Assinado por {0}");
        m.insert("provenance_unsigned", " ✗ Não verificado por assinatura");
        m.insert("provenance_install_date", " 📅 Instalado em: {0}");
        // fix suggestions
        m.insert("fix_build_tools", "🔧 Possível falta de toolchain de compilação.\n  • Ubuntu/Debian: sudo apt install build-essential\n  • Arch: sudo pacman -S base-devel");
        m.insert("fix_openssl", "🔧 Biblioteca OpenSSL ausente.\n  • Ubuntu/Debian: sudo apt install libssl-dev pkg-config\n  • Fedora: sudo dnf install openssl-devel\n  • Arch: sudo pacman -S openssl");
        m.insert("fix_permission", "🔧 Sem permissão. Tente executar o comando com sudo ou verifique permissões do diretório.");
        m.insert("fix_compilation", "🔧 Erro de compilação. Tente:\n  1. Atualizar o toolchain: rustup update\n  2. Executar o comando manualmente para ver detalhes");
        m.insert("fix_not_found", "🔧 Comando ou arquivo não encontrado. Verifique se a ferramenta está instalada e no PATH.");
        m.insert("fix_network", "🔧 Erro de rede. Verifique sua conexão de internet e tente novamente.");
        m.insert("fix_rate_limit", "🔧 Rate limit da API atingido. Aguarde alguns minutos e tente novamente.");
        m.insert("fix_generic", "💡 Execute o comando acima manualmente para ver o erro completo sem truncamento.");
        m
    })
}

fn en_strings() -> &'static HashMap<&'static str, &'static str> {
    static EN: OnceLock<HashMap<&str, &str>> = OnceLock::new();
    EN.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert("title", " 🍵 TUCUPI :: Concurrent Dependency Guard & Upgrader ");
        m.insert("tab_local", " [1] Local Project ({0}) ");
        m.insert("tab_global", " [2] Global Packages ({0}) ");
        m.insert("dir_repo", " Repository: {0} ");
        m.insert("col_ecosystem", "Ecosystem");
        m.insert("col_package", "Package");
        m.insert("col_current", "Current");
        m.insert("col_latest", "Latest");
        m.insert("col_vulns", "Vulns");
        m.insert("table_title_local", " Outdated Repository Dependencies ");
        m.insert("table_title_global", " Outdated Global Packages ");
        m.insert("detail_title", " Security Audit & Details ");
        m.insert("detail_package", "Package: {0}");
        m.insert("detail_ecosystem", "Ecosystem: {0}");
        m.insert("detail_version", "Current: {0}  ➔  Latest: {1}");
        m.insert("upgrade_in_progress", " ⏳ Upgrade in progress...");
        m.insert("upgrade_success", " ✓ Upgrade completed successfully!");
        m.insert("upgrade_failed", " ✗ Upgrade failed (details below)");
        m.insert("upgrade_none", " No upgrade in progress.");
        m.insert("error_details", " ❌ UPGRADE ERROR DETAILS:\n{0}\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        m.insert("secure_msg", " ✓ SECURE: No known vulnerabilities detected in the OSV.dev database for this version.");
        m.insert("secure_limited", " ⚠️ Security audit unavailable for this ecosystem — could not verify vulnerabilities.");
        m.insert("vuln_warning", " ⚠️ WARNING: {0} VULNERABILITIES FOUND!\n\n");
        m.insert("vuln_item", "ID: {0} ({1})\nSummary: {2}\nDetails: {3}\n----------------------------------------\n");
        m.insert("audit_failed", " ❌ Security audit failed:\n{0}\n\nCheck your network connection. The local security policy may block upgrades if security cannot be validated.");
        m.insert("select_prompt", " [!] Select a dependency and run Upgrade to perform the security audit.");
        m.insert("no_selection", "\n No dependency selected.");
        m.insert("status_scanning", " Status: [ Scanning local and global dependencies... ] ");
        m.insert("status_upgrading", " Status: [ {0} ] ");
        m.insert("status_success", " Status: [ Upgrade of {0} completed successfully! ] ");
        m.insert("status_failed", " Status: [ Failed to update {0}: {1} ] ");
        m.insert("status_ready", " Status: [ Ready ] ");
        m.insert("help_tui", " [q] Quit | [Tab] Toggle Local/Global | [r] Refresh | [u] Safe Upgrade | [f] Force Upgrade | [c] Check Security ");
        m.insert("modal_force_title", " ⚠️ SECURITY ALERT: VULNERABILITY DETECTED ");
        m.insert("modal_force_msg", "Package {0} has reported vulnerabilities in the target version ({1})!\n\nThis repository allows forced upgrades after warning.\n\nActive vulnerabilities:\n\n");
        m.insert("modal_force_item", "  * ID: {0} - {1}\n");
        m.insert("modal_force_footer", "\n\nPress [Enter] to FORCE the installation.\nPress [Esc] to CANCEL.");
        m.insert("modal_blocked_title", " ❌ UPGRADE BLOCKED BY SECURITY POLICY ");
        m.insert("modal_blocked_msg", "Package {0} has security vulnerabilities in the target version ({1}).\n\nAccording to the policy in 'tucupi.toml' (block_vulnerable = true), upgrades to vulnerable versions are STRICTLY PROHIBITED.\n\nBlocking vulnerabilities:\n\n");
        m.insert("modal_blocked_item", "  * ID: {0} - {1}\n");
        m.insert("modal_blocked_footer", "\n\nPress [Esc] or [Enter] to close this alert.");
        // batch mode
        m.insert("batch_title", " 🍵 TUCUPI :: Interactive Mode ");
        m.insert("batch_scanning", " Scanning dependencies across all ecosystems...\n\n This may take a few seconds.");
        m.insert("batch_header", " Outdated dependencies found: {0}");
        m.insert("batch_help_scan", " [q] Quit ");
        m.insert("batch_help_select", " [↑↓] Navigate | [Space] Toggle ([ ]→[✓]→[⚡]) | [Enter] Execute | [q] Quit     Selected: {0}  Force: {1}");
        m.insert("batch_help_exec", " [q] Quit ");
        m.insert("batch_help_report", " [q] Quit | [r] Re-scan ");
        m.insert("batch_exec_title", " Executing upgrades... ({0}/{1})");
        m.insert("batch_report_title", " Upgrade Report ");
        m.insert("batch_report_safe", " ✓ SAFELY UPGRADED ({0})");
        m.insert("batch_report_forced", " ⚡ FORCED UPGRADES ({0})");
        m.insert("batch_report_failed", " ✗ FAILED ({0})");
        m.insert("batch_report_blocked", " ⊘ BLOCKED BY SECURITY ({0})");
        m.insert("batch_report_skipped", " ⊘ SKIPPED (VULNERABLE, NO FORCE) ({0})");
        m.insert("batch_report_summary", " Summary: {0} succeeded, {1} failed, {2} blocked, {3} skipped");
        m.insert("batch_pending", "Pending");
        m.insert("batch_done", "Done");
        m.insert("batch_forced", "Forced");
        m.insert("exec_blocked", "[BLOCKED] {0} — blocked by security policy");
        m.insert("exec_skipped", "[SKIPPED] {0} — vulnerable, force not enabled");
        m.insert("exec_upgrading", "Upgrading {0} to {1}...");
        m.insert("exec_forced_msg", "[FORCED] {0} — force upgrade completed");
        m.insert("exec_ok_msg", "[OK] {0} — safe upgrade completed");
        m.insert("exec_failed_msg", "[FAILED] {0} — {1}");
        m.insert("audit_label", "Auditing security for {0}...");
        m.insert("version_label", "Version");
        m.insert("details_label", "Details");
        m.insert("separator", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        // severity
        m.insert("severity_critical", "CRITICAL");
        m.insert("severity_high", "HIGH");
        m.insert("severity_medium", "MEDIUM");
        m.insert("severity_low", "LOW");
        m.insert("score_label", "CVSS: {0}");
        // freshness
        m.insert("freshness_warn", " ⚠️ Version published {0} days ago — considered recent. Verify provenance before upgrading.");
        m.insert("freshness_ok", " ✓ Version is mature (published more than {0} days ago).");
        // provenance
        m.insert("provenance_title", " 🛡 Provenance");
        m.insert("provenance_signed", " ✓ Signed by {0}");
        m.insert("provenance_unsigned", " ✗ Not signature-verified");
        m.insert("provenance_install_date", " 📅 Installed on: {0}");
        // fix suggestions
        m.insert("fix_build_tools", "🔧 Possible missing build toolchain.\n  • Ubuntu/Debian: sudo apt install build-essential\n  • Arch: sudo pacman -S base-devel\n  • Fedora: sudo dnf groupinstall 'Development Tools'");
        m.insert("fix_openssl", "🔧 Missing OpenSSL library.\n  • Ubuntu/Debian: sudo apt install libssl-dev pkg-config\n  • Fedora: sudo dnf install openssl-devel\n  • Arch: sudo pacman -S openssl");
        m.insert("fix_permission", "🔧 Permission denied. Try running the command with sudo or check directory permissions.");
        m.insert("fix_compilation", "🔧 Compilation error. Try:\n  1. Update your toolchain: rustup update\n  2. Run the command manually to see full details");
        m.insert("fix_not_found", "🔧 Command or file not found. Make sure the tool is installed and in your PATH.");
        m.insert("fix_network", "🔧 Network error. Check your internet connection and try again.");
        m.insert("fix_rate_limit", "🔧 API rate limit reached. Wait a few minutes and try again.");
        m.insert("fix_generic", "💡 Run the command above manually to see the full error without truncation.");
        m
    })
}

fn strings() -> &'static HashMap<&'static str, &'static str> {
    if is_pt() {
        pt_strings()
    } else {
        en_strings()
    }
}

pub fn t(key: &str) -> &'static str {
    strings().get(key).copied().unwrap_or("")
}

pub fn tf(key: &str, args: &[&str]) -> String {
    let template = t(key);
    let mut result = template.to_string();
    for (i, arg) in args.iter().enumerate() {
        result = result.replace(&format!("{{{}}}", i), arg);
    }
    result
}
