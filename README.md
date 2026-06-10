# 🍵 Tucupi

> A concurrent dependency checker and upgrader with built-in security auditing.

Tucupi scans your local project dependencies and globally installed packages across multiple ecosystems, checks the OSV.dev vulnerability database for target versions, and either safely upgrades or warns/blocks based on your local security policy.

## 🤔 Why "Tucupi"?

In the Amazon region of Pará (Brazil), **tucupi** is a yellow broth extracted from the root of wild manioc. In its raw state, it contains hydrocyanic acid and is extremely **toxic**. To be used in northern cuisine (such as *Pato no Tucupi* or *Tacacá*), it must be **boiled for hours** to eliminate the poison.

This is the perfect metaphor for dependency management:
- Outdated/unmanaged dependencies can be "toxic" (contain severe vulnerabilities).
- **Tucupi** acts as the boiling and purification process: it checks dependencies, audits vulnerabilities against the OSV.dev database concurrently, and only allows upgrades when dependencies are fully verified — or under explicit policy override.

## ✨ Features

- **Multi-Ecosystem Support (8 ecosystems):**
  - **Rust (Cargo)**: reads `Cargo.toml`, queries crates.io API.
  - **Go (Modules)**: runs `go list -u -m -json all`.
  - **Dart (Pub)**: runs `dart pub outdated --json`.
  - **Elixir (Hex)**: runs `mix hex.outdated`.
  - **Node/Bun/Deno/Pnpm/Yarn (NPM Registry)**: reads `package.json` or `deno.json(c)` and resolves concurrently.
  - **PHP (Composer)**: runs `composer outdated --format=json`.
  - **Ruby (Bundler)**: runs `bundle outdated --parseable`.
  - **Python (pip)**: runs `pip3 list --outdated --format=json`.

- **Global Packages & System Tools:**
  - npm/pnpm/bun global packages, cargo installed tools.
  - **Arch Linux**: paru/pacman (official + AUR packages).
  - **mise** (version manager): detects and upgrades outdated tools.

- **Security Auditing (OSV.dev):**
  - Asynchronously queries the Open Source Vulnerabilities database.
  - Blocks upgrades to vulnerable versions when `block_vulnerable = true` in config.
  - Shows a warning modal with CVE/GHSA IDs, allows force upgrade if policy permits.

- **Interactive Batch Mode (`--interactive`):**
  - npm-check-style multi-select checklist using Space/arrows.
  - Three-state selection: `[ ]` skip → `[✓]` safe upgrade → `[⚡]` force upgrade.
  - Runs all selected upgrades and shows a final report.

- **Security-only Check Mode:**
  - Press `c` to audit a dependency without upgrading.

- **Concurrent Execution:**
  - All network requests and upgrade processes run concurrently via `tokio`.
  - Adapter scanning runs in parallel via `tokio::join!`.

- **Configurable Security Policy (`tucupi.toml`):**
  - Place a `tucupi.toml` in your project root to enforce policies.
  - `block_vulnerable`: block upgrades to vulnerable versions.
  - `ignored_packages`: skip security checks for specific packages.
  - `ignored_vulnerabilities`: ignore specific CVEs/GHSAs.

- **Internationalization:**
  - Auto-detects `pt-BR` or `en` from `LANG`/`LC_ALL` environment variables.

## 🚀 Getting Started

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (1.75+)

### Installation

Build from source:

```bash
cargo install --git https://github.com/lucaswilliameufrasio/tucupi
```

Or with cargo-binstall:

```bash
cargo binstall tucupi
```

### Upgrade

Build from the latest source:

```bash
cargo install --git https://github.com/lucaswilliameufrasio/tucupi
```

Verify:

```bash
tucupi --help
```

### Usage

Scan the current directory and open the TUI:

```bash
tucupi
```

Scan a specific project:

```bash
tucupi /path/to/project
```

Analyse global packages instead of local project:

```bash
tucupi --global
```

Interactive batch mode (npm-check style):

```bash
tucupi --interactive
```

## ⌨️ TUI Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Tab` | Toggle Local/Global packages tab |
| `↑` / `↓` | Navigate dependency list |
| `r` | Re-scan dependencies |
| `u` | Safe upgrade (with security audit) |
| `f` | Force upgrade (bypass warnings) |
| `c` | Check security only (no upgrade) |
| `Esc` / `Enter` | Close modal dialogs |
| `q` | Quit |

### Interactive Batch Mode Shortcuts

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate list |
| `Space` | Cycle selection: `[ ]` → `[✓]` → `[⚡]` |
| `Enter` | Execute all selected upgrades |
| `q` | Quit |

## 📂 Security Policy (`tucupi.toml`)

Place a `tucupi.toml` in your project root:

```toml
[security]
# Block upgrades if the target version has known vulnerabilities
block_vulnerable = true

# Skip security checks for specific packages
ignored_packages = ["legacy-package"]

# Ignore specific CVEs or GHSAs already mitigated internally
ignored_vulnerabilities = ["GHSA-xxxx-yyyy-zzzz", "CVE-2026-1234"]
```

## 🔧 Development

### Build

```bash
cargo build --release
```

### Run tests

```bash
cargo test
```

### Code quality

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
```

## 🏗️ Architecture

```
src/
├── main.rs           Entry point, CLI arg parsing, mode routing
├── lib.rs            Library crate exporting all modules
├── app.rs            Application state machine, upgrade orchestration
├── batch.rs          Interactive batch mode (--interactive)
├── ui.rs             TUI rendering (ratatui)
├── config.rs         tucupi.toml parser
├── models.rs         Core types (Ecosystem, Dependency, Vulnerability)
├── security.rs       OSV.dev vulnerability checker
├── i18n.rs           Internationalization (pt-BR / en)
└── adapters/         Ecosystem-specific outdated checkers
    ├── cargo.rs, go.rs, dart.rs, elixir.rs, js_ts.rs
    ├── php.rs, ruby.rs, python.rs, pacman.rs, mise.rs
    └── global.rs     npm/pnpm/bun/cargo global packages
```

## Verify Release Checksums

Each GitHub Release includes `tucupi` binary and a `.sha256` checksum file:

```bash
sha256sum -c tucupi-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz.sha256
```

macOS:

```bash
shasum -a 256 -c tucupi-vX.Y.Z-x86_64-apple-darwin.tar.gz.sha256
```

## Release Process

- Changelog: [CHANGELOG.md](./CHANGELOG.md)
- Architecture docs: [docs/architecture.md](./docs/architecture.md)
- Security policy: [SECURITY.md](./SECURITY.md)
