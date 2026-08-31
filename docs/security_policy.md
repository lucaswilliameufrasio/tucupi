# 🛡️ Política de Segurança & Travamento de Upgrades

O `tucupi` foi desenvolvido sob o princípio básico de que **atualizar dependências sem validação de segurança é uma prática de alto risco**. Para isso, implementamos travas e regras que podem ser configuradas no repositório.

---

## ⚙️ O Arquivo de Configuração `tucupi.toml`

Cada projeto que usa o `tucupi` pode (e deve) colocar um arquivo `tucupi.toml` no diretório de onde o `tucupi` é executado. O parser irá ler as chaves descritas abaixo para controlar a liberação ou bloqueio de upgrades. **Não ter arquivo é uma configuração válida** — todas as chaves têm default seguro.

### Referência Completa das Chaves do `[security]`

| Chave | Tipo | Default | Efeito |
|---|---|---|---|
| `block_vulnerable` | bool | `false` | Bloqueia upgrades para versão-alvo com CVE/GHSA ativo (OSV.dev + NVD). Sem isso, vulnerabilidades aparecem só como aviso. |
| `require_online` | bool | `true` | Bloqueia upgrades se a auditoria não conseguir alcançar OSV.dev/NVD. Com `false`, falha de rede permite prosseguir (ou pede força). |
| `require_provenance` | bool | `true` | Pacotes oficiais do pacman precisam de validação GPG (`Validated By` != None). Não afeta AUR. |
| `aur_enabled` | bool | `false` | **Upgrades do AUR são bloqueados por padrão.** Com `true`, passam pelo gate de revisão de código-fonte. |
| `confirm_global` | bool | `true` | Pede confirmação antes de todo upgrade de pacote global. |
| `ignored_packages` | lista | `[]` | Pula as checagens de segurança para esses nomes de pacote. |
| `ignored_vulnerabilities` | lista | `[]` | Ignora CVEs/GHSAs específicos (ex.: mitigados internamente). |
| `osv_timeout_secs` | u64 | `5` | Timeout HTTP das requisições a OSV.dev/NVD. |
| `pre_scan_security` | bool | `true` | Audita todas as dependências listadas em background logo após o scan (em vez de auditar só no upgrade). |
| `freshness_threshold_days` | i64 | `7` | Dias após publicação para a release ser considerada "madura" (informativo). |
| `block_too_fresh` | bool | `false` | Bloqueia upgrades para releases publicadas há menos de `very_recent_days` dias. |
| `very_recent_days` | i64 | `3` | Janela de "fresh demais" usada pelo `block_too_fresh`. |
| `nvd_api_key` | string | — | Chave da API do NVD — sobe o rate limit. Opcional; OSV.dev é a fonte primária. |
| `pkgbuild_review` | bool | `true` | **Gate de revisão de código-fonte** para PKGBUILDs do AUR e formulae/casks do Homebrew: diff residual + scanner determinístico + veredito de LLM antes do upgrade. |
| `review_model` | string | `"openai/gpt-5.6-luna"` | Modelo do opencode usado na triagem (qualquer id do `opencode models`). |
| `review_llm` | bool | `true` | `false` = revisão roda só o scanner determinístico (sem chamadas de API; resultado inconclusivo exige revisão manual). |

### Exemplo Completo de Configuração

```toml
[security]
# Vulnerabilidades
block_vulnerable = true
require_online = true
ignored_packages = [
  "pacote-interno-legado",
  "minha-dependencia-mitigada"
]
ignored_vulnerabilities = [
  "GHSA-p5w5-25g3-ccxp",
  "CVE-2026-9999"
]
nvd_api_key = "sua-chave-nvd"  # opcional

# Freshness
block_too_fresh = true
very_recent_days = 3
freshness_threshold_days = 7

# AUR & pacotes globais
aur_enabled = true
require_provenance = true
confirm_global = true

# Revisão de código-fonte
pkgbuild_review = true
review_model = "openai/gpt-5.6-luna"
review_llm = true
```

---

## 🔍 Como Funciona a Auditoria de Segurança (OSV.dev)

Sempre que você dispara um comando de upgrade para uma versão alvo, o `tucupi` roda uma verificação concorrente contra o banco de dados oficial do **OSV.dev** (Open Source Vulnerabilities).

1. **Mapeamento de Ecossistemas**: O `tucupi` traduz o ecossistema do pacote para os nomes de bancos aceitos no OSV:
   * Cargo (Rust) ➔ `crates.io`
   * Go ➔ `Go`
   * Dart ➔ `Pub`
   * Elixir ➔ `Hex`
   * NPM (Node / Bun / Deno) ➔ `npm`
2. **Consulta Segura**: É disparada uma requisição POST para a API HTTP: `https://api.osv.dev/v1/query`.
3. **Filtro de Segurança**:
   * O `tucupi` coleta os IDs de vulnerabilidades reportadas.
   * Filtra as falhas marcadas em `ignored_vulnerabilities`.
   * Verifica se o pacote está listado em `ignored_packages`.

---

## 🧬 Revisão de Código-Fonte (PKGBUILD / Formula)

Antes de qualquer upgrade de pacote do **AUR** ou do **Homebrew**, o `tucupi` revisa a definição do pacote em três camadas:

1. **Diff residual**: baixa a definição nova e compara com a definição da versão **instalada** (AUR: cache de clones do paru + `cgit` do AUR; Homebrew: commit do tap que corresponde à versão instalada, via API do GitHub). Version bumps e checksums são filtrados — sobra só código novo. Version bump puro = fast path, sem chamada de LLM.
2. **Scanner determinístico**: padrões conhecidos de campanhas de supply chain (ex.: IoCs do Atomic Arch de junho/2026 — `atomic-lockfile`, `js-digest`, `lockfile-js`) geram **bloqueio automático**, sem passar por julgamento de LLM e sem bypass por força. Primitivas de alto risco (`curl|sh`, `base64 -d`, `/dev/tcp/`, `ld.so.preload`, `eval $(...)`, `insmod`, `chattr +i`) são destacadas para o revisor.
3. **LLM como triagem**: o diff residual + scripts `.install`/blocos `post_install` vão para o modelo configurado em `review_model` via `opencode run`, que responde `safe` / `review` / `block`. Saída imparsável = `review` (fail closed). Vereditos ficam em cache por 6 horas por versão do pacote.

### Comportamento do veredito

| Veredito | TUI | Batch (`--interactive`) |
|---|---|---|
| `safe` | Upgrade segue normal | Upgrade segue normal |
| `review` | Modal de confirmação — exige decisão explícita | Só prossegue com seleção de **força** |
| `block` | **Fail closed** — modal sem bypass, nem com força | **Hard stop** — seleção de força nunca sobrepõe |

### Requisitos

- **Diff + scanner**: nenhum além de rede (AUR/GitHub). `GITHUB_TOKEN` no ambiente é opcional (sobe o rate limit da API de commits do Homebrew).
- **LLM**: `opencode` instalado e autenticado. Sem ele, o veredito vira `review` — ou desative a camada com `review_llm = false` para rodar só o determinístico.

---

## 🔐 Sudo (Arch/CachyOS)

Upgrades que exigem root (`pacman`, `paru`) **não** abrem prompt de senha dentro da TUI — em raw mode o prompt quebra e trava até o timeout. Antes de spawnar, o `tucupi` verifica se as credenciais sudo estão em cache (`sudo -n`); sem cache, o upgrade falha com mensagem clara pedindo `sudo -v` no terminal antes de iniciar o `tucupi`.

---

## 🚦 Modos de Alerta e Bloqueio na TUI

Dependendo da configuração de `block_vulnerable` no repositório, o comportamento da interface muda:

### Caso 1: `block_vulnerable = true` (Restrição Rígida)
Ao tentar atualizar um pacote vulnerável:
- A TUI exibe uma **janela modal vermelha de Bloqueio**.
- Lista os IDs de vulnerabilidade impeditivos.
- O botão de forçar instalação (`f`) é **desabilitado** e a ação de upgrade é estritamente impedida.

### Caso 2: `block_vulnerable = false` (Aviso com Forçamento)
Ao tentar atualizar um pacote vulnerável:
- A TUI exibe uma **janela modal amarela de Confirmação**.
- Mostra a lista de vulnerabilidades encontradas e pergunta se você deseja prosseguir.
- Permite forçar o upgrade pressionando `Enter` na modal (ou usando o atalho de teclado `f`).

---

## 🔌 Tratamento Offline

Caso a máquina esteja sem conexão ou a API do OSV.dev sofra um timeout:
- O `tucupi` avisa o usuário que a auditoria de segurança falhou.
- Se `block_vulnerable = true`, o upgrade é bloqueado por segurança, impedindo instalações cegas.
- Se `block_vulnerable = false`, é exibida uma modal de aviso com a opção de prosseguir de forma offline e forçada.
