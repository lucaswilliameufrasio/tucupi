# 🛡️ Política de Segurança & Travamento de Upgrades

O `tucupi` foi desenvolvido sob o princípio básico de que **atualizar dependências sem validação de segurança é uma prática de alto risco**. Para isso, implementamos travas e regras que podem ser configuradas no repositório.

---

## ⚙️ O Arquivo de Configuração `tucupi.toml`

Cada projeto que usa o `tucupi` pode (e deve) colocar um arquivo `tucupi.toml` em sua raiz. O parser irá ler as chaves descritas abaixo para controlar a liberação ou bloqueio de upgrades.

### Exemplo Completo de Configuração

```toml
[security]
# Habilitar restrição rígida contra upgrades inseguros.
# Se for true, impede qualquer upgrade para uma versão vulnerável.
block_vulnerable = true

# Lista de pacotes que estão autorizados a fazer upgrade, mesmo se houver vulnerabilidades.
# Útil para dependências legadas isoladas ou controladas.
ignored_packages = [
  "pacote-interno-legado",
  "minha-dependencia-mitigada"
]

# IDs específicos de vulnerabilidades conhecidas (CVEs ou GHSAs) que você decidiu ignorar.
# Útil quando o time de segurança validou que a falha não afeta o cenário do seu produto.
ignored_vulnerabilities = [
  "GHSA-p5w5-25g3-ccxp",
  "CVE-2026-9999"
]
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
