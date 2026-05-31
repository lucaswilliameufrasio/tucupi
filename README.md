# 🍵 tucupi

**tucupi** é uma ferramenta interativa TUI (Terminal User Interface) desenvolvida em Rust com Ratatui para **verificação concorrente e upgrade de dependências** com auditoria de segurança integrada e travas de política local.

---

## 🇧🇷 O Significado do Nome

No Pará, o **tucupi** é um sumo amarelo extraído da raiz da mandioca brava. Em seu estado natural/cru, o suco contém ácido cianídrico e é extremamente **tóxico** (altamente perigoso para o consumo). Para que possa ser utilizado na culinária nortista (em pratos tradicionais como o *Pato no Tucupi* ou o *Tacacá*), ele precisa ser **fervido por horas para eliminar o veneno** e ser depurado.

Esta é a analogia perfeita para a nossa ferramenta:
- As dependências brutas/desatualizadas de um projeto podem ser "tóxicas" (conter vulnerabilidades graves).
- O **`tucupi`** age como a fervura e depuração: ele verifica, audita as vulnerabilidades no banco de dados da OSV.dev de forma concorrente e só permite o upgrade das dependências quando elas estiverem totalmente purificadas e seguras (ou sob aprovação explícita de travamento).

---

## 🚀 Funcionalidades

- **Auditoria de Segurança Integrada (OSV.dev)**: Consulta o banco de vulnerabilidades do Open Source Vulnerabilities de maneira assíncrona.
- **Multilinguagem (Ecosystem Adapters)**:
  - **Rust (Cargo)**: Lê dependências e devDependencies e consulta a API oficial do crates.io.
  - **Go (Modules)**: Executa `go list -u -m -json all`.
  - **Dart (Pub)**: Executa `dart pub outdated --json`.
  - **Elixir (Hex)**: Executa `mix hex.outdated`.
  - **Node/Bun/Deno (NPM Registry)**: Lê `package.json` ou `deno.json(c)` e resolve concorrentemente direto da API do NPM.
- **Upgrade de Dependências Globais**:
  - Varre e executa upgrades de ferramentas globais do sistema (`npm -g`, `pnpm -g`, `cargo install`).
- **Travamento de Segurança (`tucupi.toml`)**:
  - Se a regra `block_vulnerable = true` for adicionada, atualizações para versões com vulnerabilidades conhecidas serão **terminantemente bloqueadas**.
- **Modo Forçado**:
  - Se o bloqueio não estiver ativo, o usuário é alertado em uma janela modal com as vulnerabilidades encontradas (IDs CVE/GHSA) e pode decidir forçar o upgrade.
- **Execução Concorrente**:
  - Processos e conexões web assíncronas rodando em cima da runtime do `tokio`.

---

## 📂 Configurações de Política (`tucupi.toml`)

Você pode colocar um arquivo `tucupi.toml` na raiz do seu repositório para impor políticas de segurança ao time:

```toml
[security]
# Bloquear o upgrade caso a versão alvo possua vulnerabilidades conhecidas
block_vulnerable = true

# Ignorar checagem para pacotes específicos
ignored_packages = ["algum-pacote-legado"]

# Ignorar CVEs ou GHSAs específicos que já foram mitigados internamente
ignored_vulnerabilities = ["GHSA-xxxx-yyyy-zzzz", "CVE-2026-1234"]
```

---

## 🛠️ Como Executar e Testar

### Pré-requisitos
- Rust & Cargo instalados (Mínimo Rust 1.75+)

### Compilar o projeto
```bash
cargo build --release
```

### Executar os Testes
Para rodar os testes unitários e de integração (que fazem testes reais de scanner e OSV):
```bash
cargo test
```

### Rodar a aplicação
Na pasta raiz de um projeto:
```bash
cargo run
```

Para analisar as dependências globais do sistema ao invés do projeto local:
```bash
cargo run -- --global
```

### Gerenciamento de Releases (`cargo-dist`)
Para configurar a distribuição automatizada e pipelines de release, é altamente recomendado instalar o `cargo-dist` utilizando o `cargo-binstall` de forma segura (garantindo validação de assinaturas e criptografia ponta a ponta):

```bash
# Instalar cargo-dist de forma segura
cargo binstall cargo-dist --secure
```

Para atualizar o setup ou sincronizar as pipelines locais/CI do `tucupi`:
```bash
dist init --yes
```

---

## ⌨️ Atalhos de Navegação na TUI

- `Tab`: Alternar entre a aba **[Local Project]** (dependências do diretório atual) e **[Global Packages]** (pacotes do sistema).
- `Setas Cima / Baixo`: Navegar pela lista de pacotes desatualizados.
- `r`: Recarregar e rodar uma nova varredura concorrente.
- `u`: Iniciar Upgrade Seguro (roda auditoria OSV.dev e instala se seguro).
- `f`: Forçar Upgrade (permite forçar mesmo com alertas, caso não haja bloqueio em `tucupi.toml`).
- `Esc` / `Enter`: Fechar janelas modais de bloqueio ou confirmação.
- `q`: Sair do Tucupi.
