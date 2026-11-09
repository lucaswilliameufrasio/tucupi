use std::collections::HashMap;
use std::sync::OnceLock;

fn detect_lang() -> &'static str {
    static LANG: OnceLock<String> = OnceLock::new();
    LANG.get_or_init(|| {
        std::env::var("LC_ALL")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                std::env::var("LC_MESSAGES")
                    .ok()
                    .filter(|value| !value.is_empty())
            })
            .or_else(|| std::env::var("LANG").ok())
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
        m.insert("config_invalid", "Comando de configuração desconhecido. Use: tucupi config <set-nvd-key|remove-nvd-key|status>");
        m.insert("config_parse_warning", "Não foi possível ler a configuração {0}; nenhuma atualização foi iniciada. Revise o arquivo antes de continuar.");
        m.insert("config_prompt_help", "Digite a chave da API NVD (entrada oculta):");
        m.insert("config_prompt", "Chave da API NVD: ");
        m.insert("config_empty", "Nenhuma chave informada: operação cancelada.");
        m.insert("config_store_error", "Falha ao salvar a chave da API NVD. Erro original: {0}");
        m.insert("config_saved", "Chave da API NVD salva no chaveiro do sistema.");
        m.insert("config_no_stored_key", "Nenhuma chave da API NVD está armazenada.");
        m.insert("config_remove_error", "Falha ao remover a chave da API NVD. Erro original: {0}");
        m.insert("config_removed", "Chave da API NVD removida do chaveiro do sistema.");
        m.insert("config_access_error", "Falha ao acessar o chaveiro do sistema. Erro original: {0}");
        m.insert("config_status", "Chave da API NVD: {0}");
        m.insert("config_status_keychain", "configurada (origem: chaveiro do sistema)");
        m.insert("config_status_environment", "configurada (origem: variável de ambiente)");
        m.insert("config_status_missing", "não configurada");
        m.insert("config_status_unavailable_environment", "chaveiro do sistema indisponível; configurada via variável de ambiente");
        m.insert("config_status_unavailable", "chaveiro do sistema indisponível; não configurada");
        m.insert("cli_help", "🍵 TUCUPI\n\nUSO:\n  tucupi [opções] [diretório]\n  tucupi config <comando>\n\nOPÇÕES:\n  -g, --global        Abrir na aba de pacotes globais\n  -i, --interactive   Abrir modo interativo em lote\n  -V, --version       Mostrar a versão instalada\n  -h, --help          Mostrar esta ajuda\n\n  diretório           Diretório do projeto (padrão: diretório atual)\n\nCONFIGURAÇÃO:\n  tucupi config set-nvd-key     Salvar a chave da API NVD no chaveiro do sistema\n  tucupi config remove-nvd-key  Remover a chave da API NVD salva\n  tucupi config status          Mostrar onde a chave está armazenada, sem revelar seu valor\n\nEXEMPLOS:\n  tucupi               Verificar diretório atual e abrir a interface\n  tucupi -g            Abrir na aba global\n  tucupi -i            Abrir modo interativo\n  tucupi /caminho/proj  Verificar um projeto\n  tucupi -i /caminho   Modo interativo em um diretório\n  tucupi config set-nvd-key");
        m.insert("title", " 🍵 TUCUPI :: Guardião e Atualizador de Dependências ");
        m.insert("tab_local", " [1] Projeto Local ({0}) ");
        m.insert("tab_global", " [2] Pacotes Globais ({0}) ");
        m.insert("dir_repo", " Repositório: {0} ");
        m.insert("col_ecosystem", "Ecossistema");
        m.insert("col_selection", "Sel.");
        m.insert("col_package", "Pacote");
        m.insert("col_current", "Atual");
        m.insert("col_latest", "Mais Recente");
        m.insert("col_vulns", "Vulns");
        m.insert("table_title_local", " Dependências Desatualizadas no Repositório ");
        m.insert("table_title_global", " Dependências Globais do Sistema ");
        m.insert("table_title_selected", "{0} [{1} selecionados]");
        m.insert("detail_title", " Auditoria de Segurança & Detalhes ");
        m.insert("detail_package", "Pacote: {0}");
        m.insert("detail_ecosystem", "Ecossistema: {0}");
        m.insert("detail_origin", "Origem: {0}");
        m.insert("detail_version", "Versão Atual: {0}  ➔  Nova Versão: {1}");
        m.insert("upgrade_in_progress", " ⏳ Atualização em andamento...");
        m.insert("upgrade_success", " ✓ Atualização concluída com sucesso!");
        m.insert("upgrade_failed", " ✗ Atualização falhou (detalhes abaixo)");
        m.insert("upgrade_none", " Nenhuma atualização em andamento.");
        m.insert("error_details", " ❌ DETALHES DO ERRO DE ATUALIZAÇÃO:\n{0}\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        m.insert("secure_msg", " ✓ Nenhuma vulnerabilidade conhecida foi detectada no banco de dados do OSV.dev para esta versão. Isso não garante ausência de riscos.");
        m.insert("secure_limited", " ⚠️ Auditoria indisponível para este ecossistema — não foi possível verificar vulnerabilidades.");
        m.insert("vuln_warning", " ⚠️ AVISO: {0} VULNERABILIDADE(S) ENCONTRADA(S)!\n\n");
        m.insert("vuln_item", "ID: {0} ({1})\nResumo original: {2}\nDetalhes originais: {3}\n----------------------------------------\n");
        m.insert("audit_failed", " ❌ Falha na auditoria de segurança. Erro original:\n{0}\n\nVerifique sua conexão de rede. A política local de segurança pode bloquear atualizações se não for possível validar a segurança.");
        m.insert("audit_partial_blocked", "Auditoria incompleta: OSV indisponível. Achados NVD: {0}. Atualização bloqueada; consulte os detalhes.");
        m.insert("security_scanning", " ⏳ Auditando segurança...");
        m.insert("security_check_error", "Falha na auditoria de segurança. Erro original: {0}");
        m.insert("security_check_blocked", "Falha na auditoria de segurança. Erro original: {0}. A atualização foi bloqueada pela configuração do repositório.");
        m.insert("dependency_fallback", "dependência");
        m.insert("process_start_failed", "Não foi possível iniciar o processo: {0}");
        m.insert("process_stdout_failed", "Não foi possível capturar a saída do processo");
        m.insert("process_stderr_failed", "Não foi possível capturar os erros do processo");
        m.insert("process_wait_failed", "Não foi possível aguardar o processo: {0}");
        m.insert("process_timeout", "O processo excedeu o limite de {0} segundos.");
        m.insert("process_unknown_exit", "desconhecido");
        m.insert("process_error_details", "Comando: {0}\n\nSaída original: {1} (código: {2})\n\n{3}");
        m.insert("modal_offline_title", " AUDITORIA ONLINE INDISPONÍVEL ");
        m.insert("modal_offline_msg", "Não foi possível verificar vulnerabilidades de {0}. Isso não significa que uma vulnerabilidade tenha sido encontrada.\n\nErro original: {1}\n\n[Enter] Continuar mesmo assim | [Esc] Cancelar");
        m.insert("select_prompt", " [!] Selecione uma dependência e atualize para executar a auditoria de segurança.");
        m.insert("no_selection", "\n Nenhuma dependência selecionada.");
        m.insert("status_scanning", " Status: [ Varrendo dependências localmente e globalmente... ] ");
        m.insert("status_upgrading", " Status: [ {0} ] ");
        m.insert("status_success", " Status: [ Atualização de {0} realizada com sucesso! ] ");
        m.insert("status_failed", " Status: [ Falha ao atualizar {0}: {1} ] ");
        m.insert("status_ready", " Status: [ Pronto ] ");
        m.insert("help_tui", " [q] Sair | [Tab] Alternar Local/Global | [Espaço] Selecionar ([ ]→[✓]→[⚡]) | [u] Atualizar Selecionados | [f] Forçar Selecionados | [c] Auditar Selecionados | [l] Registros | [k] Chave NVD | [PgUp/PgDn] Rolar Detalhes ");
        m.insert("help_hint", " [?] Comandos");
        m.insert("impact_checking", "Verificando impactos de {0}...");
        m.insert("impact_title", " Impacto da atualização ");
        m.insert("impact_warning", "A análise de {0} é incompleta. O gerenciador pode alterar outros pacotes e a auditoria do Tucupi não cobre automaticamente essas alterações. A prévia pode mudar durante a execução.\n\n");
        m.insert("impact_manager_output", "Prévia fornecida pelo gerenciador (texto original). Scripts e plugins podem estar desativados; a prévia do pip aceita somente wheels:\n\n");
        m.insert("impact_unavailable", "Não foi possível obter uma prévia dos outros pacotes afetados.");
        m.insert("impact_truncated", "A prévia foi truncada; outras alterações podem não estar visíveis.");
        m.insert("impact_pacman_caveat", "Prévia parcial do pacman para repositórios oficiais, não do paru: pode omitir remoções, conflitos, scripts e efeitos de outras ferramentas. Atualizações parciais não são suportadas no Arch Linux.");
        m.insert("impact_footer", "[Enter] Continuar | [Esc] Cancelar | ↑↓ Rolar");
        m.insert("help_title", " Comandos — Esc fecha ");
        m.insert("help_commands", "↑ / ↓  Navegar entre pacotes\nTab  Alternar Local/Global\nEspaço  Selecionar: ignorar / seguro / forçar\nr  Verificar novamente\nu  Atualizar selecionados\nf  Forçar atualização\nc  Auditar selecionados\nl  Abrir logs\na  Configurar revisão por API\nk  Definir chave NVD\nK  Remover chave NVD\nPgUp / PgDn  Rolar detalhes\nq  Sair\n\nNeste painel: ↑ / ↓, PgUp / PgDn ou roda do mouse para rolar; Esc ou ? para fechar.");
        m.insert("toast_upgrade_success", " ✓ {0} atualizado com sucesso ");
        m.insert("toast_upgrade_failed", " ✗ Falha ao atualizar {0} — pressione [l] para ver os logs ");
        m.insert("toast_security_check_failed", " ⚠ Auditoria de segurança falhou para {0} ");
        m.insert("toast_secret_saved", " 🔑 Chave da API NVD salva no chaveiro do sistema ");
        m.insert("toast_secret_removed", " 🔑 Chave da API NVD removida do chaveiro do sistema ");
        m.insert("toast_secret_save_failed", " ✗ Falha ao salvar a chave da API NVD: {0} ");
        m.insert("toast_secret_remove_failed", " ✗ Falha ao remover a chave da API NVD: {0} ");
        m.insert("toast_secret_empty", " ✗ A chave não pode ser vazia ");
        m.insert("secret_input_title", " 🔑 Chave da API NVD ");
        m.insert("secret_input_help", " Digite a chave (entrada mascarada). [Enter] Salvar | [Esc] Cancelar ");
        m.insert("review_settings_title", " Revisão por API ");
        m.insert("review_settings_provider", "Provedor");
        m.insert("review_settings_model", "Modelo");
        m.insert("review_settings_menu", "←/→ Provedor | m Modelo | k Salvar chave | d Remover chave | Enter Selecionar | Esc Cancelar");
        m.insert("review_settings_model_input", "Modelo (Enter confirma, Esc cancela):");
        m.insert("review_settings_key_input", "Chave mascarada (Enter salva, Esc cancela):");
        m.insert("review_settings_warning", "Seleção e chave ficam no chaveiro. A configuração do projeto prevalece após reiniciar. A revisão envia código do pacote ao provedor e pode gerar custos.");
        m.insert("review_settings_invalid_key", "Chave inválida; não foi salva.");
        m.insert("review_settings_invalid_model", "Informe um modelo válido.");
        m.insert("review_settings_key_saved", "Chave salva no chaveiro.");
        m.insert("review_settings_key_removed", "Chave removida do chaveiro.");
        m.insert("review_settings_key_error", "Não foi possível acessar o chaveiro.");
        m.insert("review_settings_selected", "Provedor selecionado e salvo no chaveiro.");
        m.insert("review_settings_restore_error", "Não foi possível restaurar a configuração de revisão do chaveiro.");
        m.insert("review_settings_busy", "Aguarde a revisão ou atualização terminar antes de alterar o provedor.");
        m.insert("logs_title", " 📜 Registros de atualização ");
        m.insert("logs_help", " [←/→] Abas | [↑/↓] Rolagem | [y] Copiar | [Esc] Fechar ");
        m.insert("logs_empty", " Nenhum registro de atualização ainda ");
        m.insert("toast_log_copied", " ✓ Log copiado para a área de transferência ");
        m.insert("toast_log_copy_failed", " ✗ Falha ao copiar o log: {0} ");
        m.insert("modal_force_title", " ⚠️ ALERTA DE SEGURANÇA: VULNERABILIDADE DETECTADA ");
        m.insert("modal_review_title", " REVISÃO DE CÓDIGO INCONCLUSIVA ");
        m.insert("modal_review_msg", "Não foi possível concluir a revisão do código-fonte de {0}. Isso não significa que uma vulnerabilidade tenha sido encontrada.\n\nMotivo: {1}\n\n[Enter] Continuar mesmo assim | [Esc] Cancelar");
        m.insert("review_unparsable", "O modelo não estava disponível ou sua resposta não pôde ser interpretada; a revisão permanece inconclusiva.");
        m.insert("review_isolation_unverified", "O provedor não foi iniciado porque seu isolamento ainda não foi verificado; a revisão permanece inconclusiva.");
        m.insert("review_task_failed", "A tarefa de revisão falhou; a revisão permanece inconclusiva.");
        m.insert("review_cancelled", "A revisão foi cancelada e permanece inconclusiva.");
        m.insert("review_cancel_failed", "Não foi possível cancelar a revisão; a limpeza não foi verificada. Atualizações estão bloqueadas nesta sessão.");
        m.insert("review_cleanup_unverified", "A limpeza da tentativa de revisão não foi verificada. Atualizações estão bloqueadas nesta sessão.");
        m.insert("review_cleanup_blocked", "A limpeza da revisão não foi verificada. Atualizações estão bloqueadas nesta sessão.");
        m.insert("codex_recovery_unavailable", "Codex indisponível: a supervisão e a recuperação ainda não estão disponíveis e o estado de tentativas anteriores é desconhecido. A operação permanece bloqueada. Não apague os registros de recuperação; ainda não há recuperação automática disponível.");
        m.insert("recovery_help", "RECUPERAÇÃO:\n  tucupi recovery status  Mostrar o estado de recuperação (somente leitura)\n  tucupi recovery init    Inicializar explicitamente o registro local no Linux");
        m.insert("recovery_usage", "Comando de recuperação desconhecido. Use: tucupi recovery status ou tucupi recovery init (Linux)");
        m.insert("recovery_init_done", "Registro local inicializado. O estado anterior continua desconhecido; Codex permanece BLOQUEADO.");
        m.insert("recovery_status", "Recuperação do Codex: BLOQUEADA.\nA supervisão e a recuperação ainda não estão implementadas; nenhuma consulta autenticada foi realizada.\nA supervisão prevista sob o mesmo usuário não protege contra processos maliciosos desse usuário.\nEstado das tentativas anteriores, execução, limpeza de descendentes e rollback: desconhecidos.\nNão apague nem altere registros para tentar desbloquear. Não há recuperação automática disponível.\nEste diagnóstico não inspeciona processos ou serviços e não altera arquivos.");
        m.insert("recovery_local_state_unavailable", "Registro local indisponível ou inválido; o estado permanece desconhecido.");
        m.insert("recovery_local_attempt_unknown", "Diretório de recuperação observado; tentativa indisponível ou inválida. Isso não significa que o estado esteja limpo.");
        m.insert("recovery_local_pending", "Registro local de tentativa pendente observado; propriedade e limpeza não foram verificadas.");
        m.insert("recovery_local_intent", "Intenção local pendente observada; execução, limpeza de descendentes e rollback são desconhecidos.");
        m.insert("recovery_local_child", "Intenção e localizador de filho observados; não identificam um processo após reinício. Limpeza e rollback são desconhecidos.");
        m.insert("recovery_local_exit", "Saída do filho direto registrada localmente; limpeza de descendentes e rollback continuam desconhecidos.");
        m.insert("recovery_direct_exit_success", "Filho direto: saída bem-sucedida registrada; isso não comprova limpeza de descendentes nem rollback.");
        m.insert("recovery_direct_exit_failure", "Filho direto: saída com falha registrada; limpeza de descendentes e rollback permanecem desconhecidos.");
        m.insert("recovery_direct_exit_not_recorded", "Filho direto: nenhum registro de saída encontrado; isso não comprova que o processo esteja vivo nem que os descendentes estejam limpos.");
        m.insert("recovery_direct_exit_unknown", "Filho direto: resultado indisponível ou inválido; limpeza de descendentes e rollback permanecem desconhecidos.");
        m.insert("recovery_snapshot_envelope", "Envelope do snapshot local verificado; isso não comprova backup completo, autenticidade ou rollback.");
        m.insert("recovery_snapshot_unavailable", "Snapshot local indisponível ou inválido; isso não significa que o estado esteja limpo.");
        m.insert("recovery_local_inconsistent", "Registros locais de recuperação divergentes ou inválidos; o estado permanece desconhecido e bloqueado.");
        m.insert("authority_cli_usage", "Uso: tucupi-authority status <diretório>");
        m.insert("authority_cli_blocked", "Autoridade não autenticada; registro não confiável; processo não observado. Operação BLOQUEADA. Nenhuma recuperação foi executada.");
        m.insert("authority_cli_fixture_blocked", "Diagnóstico sintético concluído; registro não autenticado, limpeza de descendentes e rollback desconhecidos. Operação BLOQUEADA.");
        m.insert("authority_cli_unsupported", "Diagnóstico da autoridade disponível apenas no Linux.");
        m.insert("impact_cleanup_blocked", "A limpeza da prévia de impacto não foi verificada. Atualizações estão bloqueadas nesta sessão.");
        m.insert("batch_impact_cleanup_unknown", "Cancelamento da prévia solicitado; a limpeza dos processos não foi verificada. Não há bloqueio compartilhado persistente após a saída.");
        m.insert("batch_upgrade_quit_wait", "Aguarde a conclusão da atualização antes de sair.");
        m.insert("batch_upgrade_exit_unknown", "Saída com atualização em andamento: conclusão e recuperação não foram verificadas.");
        m.insert("review_codex_auth_missing", "O modo de autenticação do Codex não foi configurado. O provedor permanece desativado porque seu isolamento não foi verificado; a revisão é inconclusiva.");
        m.insert("review_codex_auth_invalid", "O modo de autenticação do Codex é inválido. O provedor permanece desativado porque seu isolamento não foi verificado; a revisão é inconclusiva.");
        m.insert("review_known_ioc", "Indicador de comprometimento conhecido do Atomic Arch encontrado no código-fonte.");
        m.insert("review_version_only", "Apenas alteração de versão, sem mudanças no código.");
        m.insert("review_deterministic_only", "Somente verificação determinística (revisão por IA desativada).");
        m.insert("review_not_applicable", "Revisão de código-fonte não aplicável a este ecossistema.");
        m.insert("review_fetch_pkgbuild_failed", "Não foi possível obter o PKGBUILD atual do AUR.");
        m.insert("review_brew_unavailable", "O Homebrew não está disponível.");
        m.insert("review_brew_info_failed", "Não foi possível consultar o Homebrew para {0}.");
        m.insert("review_unknown_tap", "Tap não reconhecido: {0}");
        m.insert("review_fetch_formula_failed", "Não foi possível obter a fórmula de {0}.");
        m.insert("review_original_detail", "Detalhe original: {0}");
        m.insert("review_verdict_safe", "seguro");
        m.insert("review_verdict_review", "inconclusivo");
        m.insert("review_verdict_block", "bloqueado");
        m.insert("backup_prepare_failed", "Falha ao preparar cópia para restauração: {0}");
        m.insert("backup_restore_failed", "{0}\n\nFalha ao restaurar a cópia: {1}");
        m.insert("cargo_update_failed", "Falha ao atualizar com Cargo");
        m.insert("sudo_not_cached", "Credenciais sudo não estão em cache. Execute 'sudo -v' no terminal antes de iniciar o Tucupi ou atualize manualmente. O Tucupi não abre um pedido interativo de senha.");
        m.insert("clipboard_input_failed", "Não foi possível abrir a entrada da área de transferência");
        m.insert("clipboard_command_failed", "Falha no comando da área de transferência");
        m.insert("modal_force_msg", "O pacote {0} possui vulnerabilidades reportadas na versão alvo ({1})!\n\nA política deste repositório permite atualizações forçadas após aviso.\n\nVulnerabilidades ativas:\n\n");
        m.insert("modal_force_item", "  * ID: {0} - Resumo original: {1}\n");
        m.insert("modal_force_footer", "\n\nPressione [Enter] para FORÇAR a instalação.\nPressione [Esc] para CANCELAR.");
        m.insert("modal_blocked_title", " ❌ ATUALIZAÇÃO BLOQUEADA POR POLÍTICA DE SEGURANÇA ");
        m.insert("modal_blocked_msg", "O pacote {0} possui vulnerabilidades de segurança na versão alvo ({1}).\n\nDe acordo com a configuração de política em 'tucupi.toml' (block_vulnerable = true), atualizações para versões vulneráveis estão TERMINANTEMENTE PROIBIDAS.\n\nVulnerabilidades impeditivas:\n\n");
        m.insert("modal_blocked_item", "  * ID: {0} - Resumo original: {1}\n");
        m.insert("modal_blocked_footer", "\n\nPressione [Esc] ou [Enter] para fechar este alerta.");
        m.insert("modal_policy_title", " ⛔ BLOQUEADO POR POLÍTICA ");
        m.insert("modal_policy_footer", "\n\nPressione [Esc] ou [Enter] para fechar.");
        m.insert("modal_global_title", " ⚠️ CONFIRMAR ATUALIZAÇÃO GLOBAL ");
        m.insert("modal_global_msg", "Você está prestes a atualizar um pacote global ou do sistema.\n\nComando:\n{0}\n\nPressione [Enter] para confirmar ou [Esc] para cancelar.");
        m.insert("blocked_online_required", "A auditoria de segurança online falhou. Erro original: {0}. A política local exige validação online antes de atualizar.");
        m.insert("blocked_aur_disabled", "Pacotes AUR estão desabilitados por política local. Habilite `security.aur_enabled = true` para permitir atualizações AUR.");
        m.insert("blocked_provenance_required", "A procedência do pacote não pôde ser verificada de forma confiável. A política local exige proveniência válida antes de atualizar.");
        m.insert("origin_official", "Repositório Oficial");
        m.insert("origin_aur", "AUR");
        m.insert("origin_unknown", "Desconhecida");
        // batch mode
        m.insert("batch_title", " 🍵 TUCUPI :: Modo Interativo ");
        m.insert("batch_scanning", " Escaneando dependências em todos os ecossistemas...\n\n Isso pode levar alguns segundos.");
        m.insert("batch_header", " Dependências desatualizadas encontradas: {0}");
        m.insert("batch_vulns_header", "Vulns (? = não verificado)");
        m.insert("batch_vulns_unknown", " ? = auditoria de vulnerabilidades não verificada ou indisponível");
        m.insert("batch_vulns_unknown_short", "auditoria indisponível");
        m.insert("main_audit_unknown_legend", "? = auditoria indisponível");
        m.insert("batch_help_scan", " [q] Sair ");
        m.insert("batch_help_select", " [↑↓] Navegar | [Espaço] Ciclar ([ ]→[✓]→[⚡]) | [Enter] Executar | [q] Sair     Selecionados: {0}  Forçar: {1}");
        m.insert("batch_help_exec", " [q] Sair | [l] Logs ");
        m.insert("batch_help_report", " [q] Sair | [r] Re-escanear | [l] Logs ");
        m.insert("batch_help_confirm", " [Enter] Confirmar | [Esc] Cancelar | [q] Sair ");
        m.insert("batch_failed_detail", "Falhou: {0}");
        m.insert("batch_attempt_exhausted", "Atualização bloqueada: identificadores de tentativa esgotados.");
        m.insert("scan_attempt_exhausted", "Varredura bloqueada: identificadores de tentativa esgotados.");
        m.insert("batch_active_vulns", "{0} vulnerabilidade(s) ativa(s)");
        m.insert("batch_vuln_count", "  {0} vulnerabilidade(s)");
        m.insert("exec_upgrading_forced", "Atualizando {0} para {1}... (forçado)");
        m.insert("batch_global_confirm", " Há pacotes globais ou do sistema selecionados.\n\nPressione [Enter] para confirmar a execução do lote ou [Esc] para voltar.");
        m.insert("batch_impact_warning", "A análise das alterações indiretas deste lote é incompleta. O gerenciador pode alterar outros pacotes que não serão auditados automaticamente. Confirme para continuar ou cancele para voltar.");
        m.insert("batch_impact_truncated", "Uma ou mais prévias foram truncadas; outras alterações podem não estar visíveis.");
        m.insert("batch_impact_checking", "Calculando prévias dos pacotes selecionados... [q] Sair");
        m.insert("batch_exec_title", " Executando atualizações... ({0}/{1})");
        m.insert("batch_report_title", " Relatório de Atualizações ");
        m.insert("batch_report_safe", " ✓ ATUALIZADOS ({0})");
        m.insert("batch_report_forced", " ⚡ ATUALIZADOS COM FORÇA ({0})");
        m.insert("batch_report_failed", " ✗ FALHARAM ({0})");
        m.insert("batch_report_blocked", " ⊘ BLOQUEADOS POR SEGURANÇA ({0})");
        m.insert("batch_report_skipped", " ⊘ PULADOS (VULNERÁVEIS, SEM FORÇA) ({0})");
        m.insert("batch_report_summary", " Resumo: {0} concluídos, {1} falharam, {2} bloqueados, {3} pulados");
        m.insert("batch_pending", "Pendente");
        m.insert("batch_done", "Concluído");
        m.insert("batch_forced", "Forçado");
        m.insert("exec_blocked", "[BLOQUEADO] {0} — bloqueado por política de segurança");
        m.insert("review_started", "Revisando código-fonte do pacote {0}...");
        m.insert("review_blocked", "[BLOQUEADO] Código-fonte do pacote bloqueado pela revisão: {0}");
        m.insert("review_needs_confirmation", "Revisão do código-fonte inconclusiva: {0}. Forçar atualização?");
        m.insert("review_clean", "Revisão do código-fonte: seguro ({0})");
        m.insert("review_audit_result", "Revisão de código-fonte [{0}: {1}]");
        m.insert("exec_skipped", "[IGNORADO] {0} — vulnerável, sem força habilitada");
        m.insert("exec_upgrading", "Atualizando {0} para {1}...");
        m.insert("upgrade_unsupported", "Atualização não suportada para este ecossistema e escopo.");
        m.insert("exec_forced_msg", "[FORÇADO] {0} — atualização forçada concluída");
        m.insert("exec_ok_msg", "[OK] {0} — atualização concluída");
        m.insert("exec_failed_msg", "[FALHOU] {0} — {1}");
        m.insert("audit_label", "Auditando segurança de {0}...");
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
        m.insert("freshness_ok", " ✓ Versão madura (publicada há {0} dias).");
        m.insert("blocked_too_fresh", "A versão alvo foi publicada muito recentemente. A política local bloqueia atualizações para versões consideradas recentes demais.");
        // provenance
        m.insert("provenance_title", " 🛡 Proveniência");
        m.insert("provenance_signed", " ✓ Assinado por {0}");
        m.insert("provenance_signed_unknown", " ✓ Assinado (verificado)");
        m.insert("provenance_unsigned", " ✗ Não verificado por assinatura");
        m.insert("provenance_install_date", " 📅 Instalado em: {0}");
        // fix suggestions
        m.insert("fix_build_tools", "🔧 Possível falta de ferramentas de compilação.\n  • Ubuntu/Debian: sudo apt install build-essential\n  • Arch: sudo pacman -S base-devel");
        m.insert("fix_openssl", "🔧 Biblioteca OpenSSL ausente.\n  • Ubuntu/Debian: sudo apt install libssl-dev pkg-config\n  • Fedora: sudo dnf install openssl-devel\n  • Arch: sudo pacman -S openssl");
        m.insert("fix_permission", "🔧 Sem permissão. Tente executar o comando com sudo ou verifique permissões do diretório.");
        m.insert("fix_compilation", "🔧 Erro de compilação. Tente:\n  1. Atualizar as ferramentas: rustup update\n  2. Executar o comando manualmente para ver detalhes");
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
        m.insert("config_invalid", "Unknown config command. Use: tucupi config <set-nvd-key|remove-nvd-key|status>");
        m.insert("config_parse_warning", "Could not read configuration {0}; no updates were started. Review the file before continuing.");
        m.insert("config_prompt_help", "Enter the NVD API key (input is hidden):");
        m.insert("config_prompt", "NVD API key: ");
        m.insert("config_empty", "No key provided: aborted.");
        m.insert("config_store_error", "Failed to store the NVD API key. Original error: {0}");
        m.insert("config_saved", "NVD API key saved to the system keychain.");
        m.insert("config_no_stored_key", "No NVD API key is stored.");
        m.insert("config_remove_error", "Failed to remove the NVD API key. Original error: {0}");
        m.insert("config_removed", "NVD API key removed from the system keychain.");
        m.insert("config_access_error", "Failed to access the system keychain. Original error: {0}");
        m.insert("config_status", "NVD API key: {0}");
        m.insert("config_status_keychain", "configured (source: system keychain)");
        m.insert("config_status_environment", "configured (source: environment fallback)");
        m.insert("config_status_missing", "not configured");
        m.insert("config_status_unavailable_environment", "system keychain unavailable; configured via environment fallback");
        m.insert("config_status_unavailable", "system keychain unavailable; not configured");
        m.insert("cli_help", "🍵 TUCUPI\n\nUSAGE:\n  tucupi [options] [directory]\n  tucupi config <command>\n\nOPTIONS:\n  -g, --global        Start on the Global Packages tab\n  -i, --interactive   Open interactive batch mode (npm-check style)\n  -V, --version       Show the installed version\n  -h, --help          Show this help message\n\n  directory           Target project directory (default: current dir)\n\nCONFIG:\n  tucupi config set-nvd-key     Store the NVD API key in the system keychain\n  tucupi config remove-nvd-key  Remove the stored NVD API key\n  tucupi config status          Show where the NVD API key is stored (never its value)\n\nEXAMPLES:\n  tucupi               Scan current directory and open TUI\n  tucupi -g            Open TUI on Global tab\n  tucupi -i            Interactive batch mode\n  tucupi /path/to/proj  Scan a specific project\n  tucupi -i /path       Interactive mode in a specific directory\n  tucupi config set-nvd-key");
        m.insert("title", " 🍵 TUCUPI :: Concurrent Dependency Guard & Upgrader ");
        m.insert("tab_local", " [1] Local Project ({0}) ");
        m.insert("tab_global", " [2] Global Packages ({0}) ");
        m.insert("dir_repo", " Repository: {0} ");
        m.insert("col_ecosystem", "Ecosystem");
        m.insert("col_selection", "Sel.");
        m.insert("col_package", "Package");
        m.insert("col_current", "Current");
        m.insert("col_latest", "Latest");
        m.insert("col_vulns", "Vulns");
        m.insert("table_title_local", " Outdated Repository Dependencies ");
        m.insert("table_title_global", " Outdated Global Packages ");
        m.insert("table_title_selected", "{0} [{1} selected]");
        m.insert("detail_title", " Security Audit & Details ");
        m.insert("detail_package", "Package: {0}");
        m.insert("detail_ecosystem", "Ecosystem: {0}");
        m.insert("detail_origin", "Origin: {0}");
        m.insert("detail_version", "Current: {0}  ➔  Latest: {1}");
        m.insert("upgrade_in_progress", " ⏳ Upgrade in progress...");
        m.insert("upgrade_success", " ✓ Upgrade completed successfully!");
        m.insert("upgrade_failed", " ✗ Upgrade failed (details below)");
        m.insert("upgrade_none", " No upgrade in progress.");
        m.insert("error_details", " ❌ UPGRADE ERROR DETAILS:\n{0}\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
        m.insert("secure_msg", " ✓ No known vulnerabilities detected in the OSV.dev database for this version. This does not guarantee absence of risks.");
        m.insert("secure_limited", " ⚠️ Security audit unavailable for this ecosystem — could not verify vulnerabilities.");
        m.insert("vuln_warning", " ⚠️ WARNING: {0} VULNERABILITIES FOUND!\n\n");
        m.insert("vuln_item", "ID: {0} ({1})\nOriginal summary: {2}\nOriginal details: {3}\n----------------------------------------\n");
        m.insert("audit_failed", " ❌ Security audit failed. Original error:\n{0}\n\nCheck your network connection. The local security policy may block upgrades if security cannot be validated.");
        m.insert("audit_partial_blocked", "Incomplete audit: OSV unavailable. NVD findings: {0}. Upgrade blocked; see details.");
        m.insert("security_scanning", " ⏳ Scanning security...");
        m.insert("security_check_error", "Security audit failed. Original error: {0}");
        m.insert("security_check_blocked", "Security audit failed. Original error: {0}. The upgrade was blocked by repository configuration.");
        m.insert("dependency_fallback", "dependency");
        m.insert("process_start_failed", "Failed to start process: {0}");
        m.insert("process_stdout_failed", "Failed to capture process stdout");
        m.insert("process_stderr_failed", "Failed to capture process stderr");
        m.insert("process_wait_failed", "Failed to wait for process: {0}");
        m.insert("process_timeout", "Process timed out after {0} seconds.");
        m.insert("process_unknown_exit", "unknown");
        m.insert("process_error_details", "Command: {0}\n\nOriginal output: {1} (exit: {2})\n\n{3}");
        m.insert("modal_offline_title", " ONLINE AUDIT UNAVAILABLE ");
        m.insert("modal_offline_msg", "Could not check vulnerabilities for {0}. This does not mean that a vulnerability was found.\n\nOriginal error: {1}\n\n[Enter] Continue anyway | [Esc] Cancel");
        m.insert("select_prompt", " [!] Select a dependency and run Upgrade to perform the security audit.");
        m.insert("no_selection", "\n No dependency selected.");
        m.insert("status_scanning", " Status: [ Scanning local and global dependencies... ] ");
        m.insert("status_upgrading", " Status: [ {0} ] ");
        m.insert("status_success", " Status: [ Upgrade of {0} completed successfully! ] ");
        m.insert("status_failed", " Status: [ Failed to update {0}: {1} ] ");
        m.insert("status_ready", " Status: [ Ready ] ");
        m.insert("help_tui", " [q] Quit | [Tab] Toggle Local/Global | [Space] Select ([ ]→[✓]→[⚡]) | [u] Upgrade Selected | [f] Force Selected | [c] Audit Selected | [l] Logs | [k] NVD Key | [PgUp/PgDn] Scroll Details ");
        m.insert("help_hint", " [?] Commands");
        m.insert("batch_impact_warning", "Analysis of this batch's indirect changes is incomplete. The package manager may change other packages that will not be audited automatically. Confirm to continue or cancel to go back.");
        m.insert("batch_impact_truncated", "One or more previews were truncated; additional changes may not be visible.");
        m.insert("batch_impact_checking", "Checking previews for selected packages... [q] Quit");
        m.insert("impact_checking", "Checking impact of {0}...");
        m.insert("impact_title", " Upgrade impact ");
        m.insert("impact_warning", "The analysis of {0} is incomplete. The package manager may change other packages, and Tucupi does not automatically audit those changes. The preview may change during execution.\n\n");
        m.insert("impact_manager_output", "Package manager preview (original output). Scripts and plugins may be disabled; pip previews only allow wheels:\n\n");
        m.insert("impact_unavailable", "A preview of other affected packages was not available.");
        m.insert("impact_truncated", "The preview was truncated; additional changes may not be visible.");
        m.insert("impact_pacman_caveat", "Partial pacman preview for official repositories, not paru: removals, conflicts, scripts, and other tool effects may be omitted. Partial upgrades are unsupported on Arch Linux.");
        m.insert("impact_footer", "[Enter] Continue | [Esc] Cancel | ↑↓ Scroll");
        m.insert("help_title", " Commands — Esc closes ");
        m.insert("help_commands", "↑ / ↓  Navigate packages\nTab  Toggle Local/Global\nSpace  Select: skip / safe / force\nr  Scan again\nu  Upgrade selected\nf  Force upgrade\nc  Audit selected\nl  Open logs\na  Configure API review\nk  Set NVD key\nK  Remove NVD key\nPgUp / PgDn  Scroll details\nq  Quit\n\nIn this panel: ↑ / ↓, PgUp / PgDn or mouse wheel to scroll; Esc or ? to close.");
        m.insert("toast_upgrade_success", " ✓ {0} upgraded successfully ");
        m.insert("toast_upgrade_failed", " ✗ Failed to upgrade {0} — press [l] to see logs ");
        m.insert("toast_security_check_failed", " ⚠ Security audit failed for {0} ");
        m.insert("toast_secret_saved", " 🔑 NVD API key saved to the system keychain ");
        m.insert("toast_secret_removed", " 🔑 NVD API key removed from the system keychain ");
        m.insert("toast_secret_save_failed", " ✗ Failed to save the NVD API key: {0} ");
        m.insert("toast_secret_remove_failed", " ✗ Failed to remove the NVD API key: {0} ");
        m.insert("toast_secret_empty", " ✗ The key cannot be empty ");
        m.insert("secret_input_title", " 🔑 NVD API Key ");
        m.insert("secret_input_help", " Type the key (input is masked). [Enter] Save | [Esc] Cancel ");
        m.insert("review_settings_title", " API review ");
        m.insert("review_settings_provider", "Provider");
        m.insert("review_settings_model", "Model");
        m.insert("review_settings_menu", "←/→ Provider | m Model | k Save key | d Remove key | Enter Select | Esc Cancel");
        m.insert("review_settings_model_input", "Model (Enter confirms, Esc cancels):");
        m.insert("review_settings_key_input", "Masked key (Enter saves, Esc cancels):");
        m.insert("review_settings_warning", "Selection and key are stored in the keychain. Project configuration takes precedence after restart. Review sends package code to the provider and may incur charges.");
        m.insert("review_settings_invalid_key", "Invalid key; not saved.");
        m.insert("review_settings_invalid_model", "Enter a valid model.");
        m.insert("review_settings_key_saved", "Key saved to the keychain.");
        m.insert("review_settings_key_removed", "Key removed from the keychain.");
        m.insert("review_settings_key_error", "Unable to access the keychain.");
        m.insert("review_settings_selected", "Provider selected and saved in the keychain.");
        m.insert("review_settings_restore_error", "Unable to restore review settings from the keychain.");
        m.insert("review_settings_busy", "Wait for the review or upgrade to finish before changing providers.");
        m.insert("logs_title", " 📜 Upgrade Logs ");
        m.insert("logs_help", " [←/→] Tabs | [↑/↓] Scroll | [y] Copy | [Esc] Close ");
        m.insert("logs_empty", " No upgrade logs yet ");
        m.insert("toast_log_copied", " ✓ Log copied to clipboard ");
        m.insert("toast_log_copy_failed", " ✗ Failed to copy log: {0} ");
        m.insert("modal_force_title", " ⚠️ SECURITY ALERT: VULNERABILITY DETECTED ");
        m.insert("modal_review_title", " SOURCE REVIEW INCONCLUSIVE ");
        m.insert("modal_review_msg", "The source review for {0} could not be completed. This does not mean a vulnerability was found.\n\nReason: {1}\n\n[Enter] Continue anyway | [Esc] Cancel");
        m.insert("review_unparsable", "The model was unavailable or its response could not be interpreted; the source review remains inconclusive.");
        m.insert("review_isolation_unverified", "The provider was not started because its isolation has not been verified; the source review remains inconclusive.");
        m.insert("review_task_failed", "The review task failed; the source review remains inconclusive.");
        m.insert("review_cancelled", "The review was cancelled and remains inconclusive.");
        m.insert("review_cancel_failed", "Could not cancel the review; cleanup was not verified. Updates are blocked in this session.");
        m.insert("review_cleanup_unverified", "Cleanup of the review attempt was not verified. Updates are blocked in this session.");
        m.insert("review_cleanup_blocked", "Review cleanup was not verified. Updates are blocked in this session.");
        m.insert("codex_recovery_unavailable", "Codex unavailable: supervision and recovery are not yet available and the state of previous attempts is unknown. The operation remains blocked. Do not delete recovery records; automatic recovery is not yet available.");
        m.insert("recovery_help", "RECOVERY:\n  tucupi recovery status  Show recovery state (read-only)\n  tucupi recovery init    Explicitly initialize local recovery state on Linux");
        m.insert("recovery_usage", "Unknown recovery command. Use: tucupi recovery status or tucupi recovery init (Linux)");
        m.insert("recovery_init_done", "Local recovery state initialized. Previous state remains unknown; Codex remains BLOCKED.");
        m.insert("recovery_status", "Codex recovery: BLOCKED.\nSupervision and recovery are not yet implemented; no authenticated query was performed.\nThe planned same-user supervision does not protect against malicious processes running as that user.\nPrevious attempts, execution, descendant cleanup and rollback: unknown.\nDo not delete or change records to try to unlock. Automatic recovery is unavailable.\nThis diagnostic does not inspect processes or services and does not change files.");
        m.insert("recovery_local_state_unavailable", "Local record unavailable or invalid; state remains unknown.");
        m.insert("recovery_local_attempt_unknown", "Recovery directory observed; attempt unavailable or invalid. This does not mean the state is clean.");
        m.insert("recovery_local_pending", "Local pending attempt record observed; ownership and cleanup are unverified.");
        m.insert("recovery_local_intent", "Local pending intent observed; execution, descendant cleanup and rollback are unknown.");
        m.insert("recovery_local_child", "Pending intent and child locator observed; these do not identify a process after restart. Cleanup and rollback are unknown.");
        m.insert("recovery_local_exit", "Direct-child exit recorded locally; descendant cleanup and rollback remain unknown.");
        m.insert("recovery_direct_exit_success", "Direct child: successful exit recorded; this does not prove descendant cleanup or rollback.");
        m.insert("recovery_direct_exit_failure", "Direct child: failed exit recorded; descendant cleanup and rollback remain unknown.");
        m.insert("recovery_direct_exit_not_recorded", "Direct child: no exit record observed; this does not prove the process is alive or descendants are clean.");
        m.insert("recovery_direct_exit_unknown", "Direct child: result unavailable or invalid; descendant cleanup and rollback remain unknown.");
        m.insert("recovery_snapshot_envelope", "Local snapshot envelope verified; this does not prove a complete backup, authenticity or rollback.");
        m.insert("recovery_snapshot_unavailable", "Local snapshot unavailable or invalid; this does not mean the state is clean.");
        m.insert("recovery_local_inconsistent", "Local recovery records are inconsistent or invalid; state remains unknown and blocked.");
        m.insert("authority_cli_usage", "Usage: tucupi-authority status <directory>");
        m.insert("authority_cli_blocked", "Authority unauthenticated; record untrusted; process not observed. Operation BLOCKED. No recovery was performed.");
        m.insert("authority_cli_fixture_blocked", "Synthetic diagnostic completed; record unauthenticated, descendant cleanup and rollback unknown. Operation BLOCKED.");
        m.insert("authority_cli_unsupported", "Authority diagnostic is available only on Linux.");
        m.insert("impact_cleanup_blocked", "Impact preview cleanup was not verified. Updates are blocked in this session.");
        m.insert("batch_impact_cleanup_unknown", "Preview cancellation requested; process cleanup was not verified. There is no shared persistent block after exit.");
        m.insert("batch_upgrade_quit_wait", "Wait for the upgrade to finish before quitting.");
        m.insert("batch_upgrade_exit_unknown", "Exited while an upgrade was in progress: completion and recovery were not verified.");
        m.insert("review_codex_auth_missing", "The Codex authentication mode is not configured. The provider remains disabled because its isolation is unverified; the source review is inconclusive.");
        m.insert("review_codex_auth_invalid", "The Codex authentication mode is invalid. The provider remains disabled because its isolation is unverified; the source review is inconclusive.");
        m.insert("review_known_ioc", "A known Atomic Arch indicator of compromise was found in the package source.");
        m.insert("review_version_only", "Version change only, without code changes.");
        m.insert("review_deterministic_only", "Deterministic scan only (AI review disabled).");
        m.insert("review_not_applicable", "Source review is not applicable to this ecosystem.");
        m.insert("review_fetch_pkgbuild_failed", "Could not fetch the current PKGBUILD from AUR.");
        m.insert("review_brew_unavailable", "Homebrew is unavailable.");
        m.insert("review_brew_info_failed", "Could not query Homebrew for {0}.");
        m.insert("review_unknown_tap", "Unrecognized tap: {0}");
        m.insert("review_fetch_formula_failed", "Could not fetch the formula from {0}.");
        m.insert("review_original_detail", "Original detail: {0}");
        m.insert("review_verdict_safe", "safe");
        m.insert("review_verdict_review", "inconclusive");
        m.insert("review_verdict_block", "blocked");
        m.insert("backup_prepare_failed", "Failed to prepare rollback backup: {0}");
        m.insert("backup_restore_failed", "{0}\n\nFailed to restore backup: {1}");
        m.insert("cargo_update_failed", "Cargo update failed");
        m.insert("sudo_not_cached", "Sudo credentials are not cached. Run 'sudo -v' before launching Tucupi or upgrade manually. Tucupi will not open an interactive password prompt.");
        m.insert("clipboard_input_failed", "Failed to open clipboard input");
        m.insert("clipboard_command_failed", "Clipboard command failed");
        m.insert("modal_force_msg", "Package {0} has reported vulnerabilities in the target version ({1})!\n\nThis repository allows forced upgrades after warning.\n\nActive vulnerabilities:\n\n");
        m.insert("modal_force_item", "  * ID: {0} - Original summary: {1}\n");
        m.insert("modal_force_footer", "\n\nPress [Enter] to FORCE the installation.\nPress [Esc] to CANCEL.");
        m.insert("modal_blocked_title", " ❌ UPGRADE BLOCKED BY SECURITY POLICY ");
        m.insert("modal_blocked_msg", "Package {0} has security vulnerabilities in the target version ({1}).\n\nAccording to the policy in 'tucupi.toml' (block_vulnerable = true), upgrades to vulnerable versions are STRICTLY PROHIBITED.\n\nBlocking vulnerabilities:\n\n");
        m.insert("modal_blocked_item", "  * ID: {0} - Original summary: {1}\n");
        m.insert("modal_blocked_footer", "\n\nPress [Esc] or [Enter] to close this alert.");
        m.insert("modal_policy_title", " ⛔ BLOCKED BY POLICY ");
        m.insert("modal_policy_footer", "\n\nPress [Esc] or [Enter] to close.");
        m.insert("modal_global_title", " ⚠️ CONFIRM GLOBAL UPGRADE ");
        m.insert("modal_global_msg", "You are about to upgrade a global or system package.\n\nCommand:\n{0}\n\nPress [Enter] to confirm or [Esc] to cancel.");
        m.insert("blocked_online_required", "Online security auditing failed. Original error: {0}. Local policy requires online validation before upgrading.");
        m.insert("blocked_aur_disabled", "AUR packages are disabled by local policy. Set `security.aur_enabled = true` to allow AUR upgrades.");
        m.insert("blocked_provenance_required", "Package provenance could not be verified reliably. Local policy requires valid provenance before upgrading.");
        m.insert("origin_official", "Official Repo");
        m.insert("origin_aur", "AUR");
        m.insert("origin_unknown", "Unknown");
        // batch mode
        m.insert("batch_title", " 🍵 TUCUPI :: Interactive Mode ");
        m.insert("batch_scanning", " Scanning dependencies across all ecosystems...\n\n This may take a few seconds.");
        m.insert("batch_header", " Outdated dependencies found: {0}");
        m.insert("batch_vulns_header", "Vulns (? = not checked)");
        m.insert("batch_vulns_unknown", " ? = vulnerability audit not checked or unavailable");
        m.insert("batch_vulns_unknown_short", "audit unavailable");
        m.insert("main_audit_unknown_legend", "? = audit unavailable");
        m.insert("batch_help_scan", " [q] Quit ");
        m.insert("batch_help_select", " [↑↓] Navigate | [Space] Toggle ([ ]→[✓]→[⚡]) | [Enter] Execute | [q] Quit     Selected: {0}  Force: {1}");
        m.insert("batch_help_exec", " [q] Quit | [l] Logs ");
        m.insert("batch_help_report", " [q] Quit | [r] Re-scan | [l] Logs ");
        m.insert("batch_help_confirm", " [Enter] Confirm | [Esc] Cancel | [q] Quit ");
        m.insert("batch_failed_detail", "Failed: {0}");
        m.insert("batch_attempt_exhausted", "Update blocked: attempt identifiers exhausted.");
        m.insert("scan_attempt_exhausted", "Scan blocked: attempt identifiers exhausted.");
        m.insert("batch_active_vulns", "{0} active vulnerability(s)");
        m.insert("batch_vuln_count", "  {0} vulnerabilities");
        m.insert("exec_upgrading_forced", "Upgrading {0} to {1}... (forced)");
        m.insert("batch_global_confirm", " Global or system packages are selected.\n\nPress [Enter] to confirm the batch execution or [Esc] to go back.");
        m.insert("batch_exec_title", " Executing upgrades... ({0}/{1})");
        m.insert("batch_report_title", " Upgrade Report ");
        m.insert("batch_report_safe", " ✓ UPGRADED ({0})");
        m.insert("batch_report_forced", " ⚡ FORCED UPGRADES ({0})");
        m.insert("batch_report_failed", " ✗ FAILED ({0})");
        m.insert("batch_report_blocked", " ⊘ BLOCKED BY SECURITY ({0})");
        m.insert("batch_report_skipped", " ⊘ SKIPPED (VULNERABLE, NO FORCE) ({0})");
        m.insert("batch_report_summary", " Summary: {0} succeeded, {1} failed, {2} blocked, {3} skipped");
        m.insert("batch_pending", "Pending");
        m.insert("batch_done", "Done");
        m.insert("batch_forced", "Forced");
        m.insert("exec_blocked", "[BLOCKED] {0} — blocked by security policy");
        m.insert("review_started", "Reviewing package source of {0}...");
        m.insert("review_blocked", "[BLOCKED] Package source blocked by review: {0}");
        m.insert("review_needs_confirmation", "Source review inconclusive: {0}. Force upgrade?");
        m.insert("review_clean", "Source review: safe ({0})");
        m.insert("review_audit_result", "Source review [{0}: {1}]");
        m.insert("exec_skipped", "[SKIPPED] {0} — vulnerable, force not enabled");
        m.insert("exec_upgrading", "Upgrading {0} to {1}...");
        m.insert("upgrade_unsupported", "Upgrade is not supported for this ecosystem and scope.");
        m.insert("exec_forced_msg", "[FORCED] {0} — force upgrade completed");
        m.insert("exec_ok_msg", "[OK] {0} — upgrade completed");
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
        m.insert("freshness_ok", " ✓ Version is mature (published {0} days ago).");
        m.insert("blocked_too_fresh", "The target version was published very recently. Local policy blocks upgrades to versions considered too fresh.");
        // provenance
        m.insert("provenance_title", " 🛡 Provenance");
        m.insert("provenance_signed", " ✓ Signed by {0}");
        m.insert("provenance_signed_unknown", " ✓ Signed (verified)");
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

#[cfg(test)]
mod catalog_tests {
    use super::*;

    #[test]
    fn portuguese_and_english_catalogs_have_matching_keys() {
        let pt = pt_strings();
        let en = en_strings();
        let mut missing_en: Vec<_> = pt.keys().filter(|key| !en.contains_key(*key)).collect();
        let mut missing_pt: Vec<_> = en.keys().filter(|key| !pt.contains_key(*key)).collect();
        missing_en.sort();
        missing_pt.sort();
        assert!(
            missing_en.is_empty() && missing_pt.is_empty(),
            "missing English: {missing_en:?}; missing Portuguese: {missing_pt:?}"
        );
    }

    #[test]
    fn vulnerability_details_are_labeled_as_original_in_both_languages() {
        assert!(pt_strings()["vuln_item"].contains("Detalhes originais: {3}"));
        assert!(en_strings()["vuln_item"].contains("Original details: {3}"));
        assert!(pt_strings()["upgrade_in_progress"].contains("Atualização"));
        assert!(en_strings()["upgrade_in_progress"].contains("Upgrade"));
        assert!(pt_strings()["secure_msg"].contains("não garante ausência de riscos"));
        assert!(en_strings()["secure_msg"].contains("does not guarantee absence of risks"));
        assert!(pt_strings()["review_isolation_unverified"].contains("não foi iniciado"));
        assert!(en_strings()["review_isolation_unverified"].contains("was not started"));
        assert!(pt_strings()["review_codex_auth_missing"].contains("não foi configurado"));
        assert!(en_strings()["review_codex_auth_missing"].contains("not configured"));
        assert!(pt_strings()["review_codex_auth_invalid"].contains("inválido"));
        assert!(en_strings()["review_codex_auth_invalid"].contains("invalid"));
    }

    #[test]
    fn portuguese_security_and_key_messages_do_not_use_english_terms() {
        for key in [
            "audit_failed",
            "modal_blocked_msg",
            "toast_secret_saved",
            "toast_secret_removed",
            "toast_secret_save_failed",
            "toast_secret_remove_failed",
        ] {
            let message = pt_strings()[key].to_lowercase();
            for term in ["upgrade", "keychain", "api key"] {
                assert!(!message.contains(term), "{key}: {message}");
            }
        }
        assert!(en_strings()["toast_secret_saved"].contains("system keychain"));
        assert!(pt_strings()["toast_secret_saved"].contains("chaveiro do sistema"));
    }
}
