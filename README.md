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

- **Package Source Review (AUR PKGBUILD + Homebrew formulae/casks):**
  - Before upgrading an AUR package or a Homebrew formula/cask, tucupi diffs
    the package definition against the version you already have installed
    (AUR: paru clone cache; Homebrew: the tap commit matching the installed
    version via the GitHub API).
  - Version bumps and checksum noise are stripped, so only real code changes
    remain. Known-bad patterns from supply-chain campaigns (e.g. the June 2026
    Atomic Arch IoCs `atomic-lockfile`/`js-digest`) are a hard block.
  - The residual diff (plus `.install` scripts / `post_install` blocks) is
    sent to an LLM via `opencode run` for a `safe / review / block` verdict.
    Verdicts are cached for 6 hours per package version.
  - Pure version bumps (empty residual, no scanner hits) skip the LLM call
    entirely — the fast path costs nothing.
  - Block verdicts are fail-closed (force selection never overrides them);
    inconclusive verdicts require explicit force confirmation.
  - Upgrades that require root (`pacman`/`paru`) fail fast when sudo
    credentials are not cached (`sudo -v`) instead of hanging the TUI.

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
- **Optional (package source review):** [`opencode`](https://opencode.ai) installed and
  authenticated (`opencode run` must work in your terminal). Without it, review verdicts
  fall back to `review` (fail closed) — or disable the LLM layer with `review_llm = false`.
- **Optional (brew baseline lookup):** `GITHUB_TOKEN` in the environment raises the
  GitHub API rate limit when resolving the commit matching the installed version.
- **Arch/CachyOS only:** run `sudo -v` before launching tucupi when you plan to upgrade
  pacman/paru packages — root-requiring upgrades fail fast instead of spawning an
  interactive sudo prompt inside the TUI.

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
| `l` | Open upgrade logs popup |
| `k` | Set NVD API key (masked input, stored in the system keychain) |
| `K` | Remove the stored NVD API key |
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

The config file is loaded from the **directory where you launch tucupi** (the target
directory): `./tucupi.toml` next to your project for local scans, or e.g. `~/tucupi.toml`
if you always launch `tucupi -g` from your home. No file at all is a valid setup — every
key below has a safe default.

### Reference — every `[security]` key

| Key | Type | Default | Effect |
|---|---|---|---|
| `block_vulnerable` | bool | `false` | Block upgrades when the **target** version has active CVEs/GHSAs (OSV.dev + NVD). Without it, vulnerabilities are shown as warnings only. |
| `require_online` | bool | `true` | Block upgrades when the security audit cannot reach OSV.dev/NVD. With `false`, audit failures allow upgrades (or ask for force). |
| `require_provenance` | bool | `true` | Official pacman packages must have GPG signature validation (`Validated By` != None). AUR is unaffected. |
| `aur_enabled` | bool | `false` | **AUR upgrades are blocked by default.** Set `true` to allow them (they then pass through the source review gate). |
| `confirm_global` | bool | `true` | Ask for confirmation before every global package upgrade. |
| `ignored_packages` | string list | `[]` | Skip security checks for these package names. |
| `ignored_vulnerabilities` | string list | `[]` | Ignore specific CVE/GHSA ids (e.g. mitigated internally). |
| `osv_timeout_secs` | u64 | `5` | HTTP timeout for OSV.dev/NVD requests. |
| `pre_scan_security` | bool | `true` | Audit all listed dependencies in the background right after a scan (instead of auditing only on upgrade). |
| `freshness_threshold_days` | i64 | `7` | Days after publication before a release is considered "mature" (informational). |
| `block_too_fresh` | bool | `false` | Block upgrades to releases published less than `very_recent_days` ago. |
| `very_recent_days` | i64 | `3` | The "too fresh" window used by `block_too_fresh`. |
| `pkgbuild_review` | bool | `true` | **Package source review gate** for AUR PKGBUILDs and Homebrew formulae/casks: residual diff + deterministic scan + LLM verdict before upgrade. |
| `review_model` | string | `"openai/gpt-5.6-luna"` | opencode model used by the source review triage (any id from `opencode models`). |
| `review_llm` | bool | `true` | `false` = source review runs deterministic scan only (no API calls; inconclusive results require manual review). |

### Example

```toml
[security]
# Vulnerabilities
block_vulnerable = true
require_online = true
ignored_packages = ["legacy-package"]
ignored_vulnerabilities = ["GHSA-xxxx-yyyy-zzzz", "CVE-2026-1234"]

# Freshness
block_too_fresh = true
very_recent_days = 3
freshness_threshold_days = 7

# AUR & global packages
aur_enabled = true
require_provenance = true
confirm_global = true

# Package source review
pkgbuild_review = true
review_model = "openai/gpt-5.6-luna"
review_llm = true
```

### 🔑 Secrets: NVD API key in the system keychain

The NVD API key (raises NVD rate limits; OSV.dev remains the primary source) is
**never stored in `tucupi.toml`** — that file is meant to be committed and
shared. Secrets live in the OS keychain (macOS Keychain, Linux Secret Service,
Windows Credential Manager):

```bash
tucupi config set-nvd-key     # hidden prompt; nothing is echoed
tucupi config status          # shows configured/not configured and the source (never the value)
tucupi config remove-nvd-key  # removes the stored key
```

Inside the TUI, `k` opens a masked input to save the key and `K` removes it.
Both the TUI and the batch mode resolve the key from the keychain automatically
on every audit.

The `TUCUPI_NVD_API_KEY` environment variable exists only as a fallback for CI
and headless environments where no keychain is available — it is not recommended
for local use, since environment variables leak easily (shell history, process
inspection, CI logs).

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
├── review.rs         Package source review (residual diff + scan + LLM)
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

### Before releasing a new version

Run `cargo about init` to regenerate the `about.toml` with the correct list of
accepted third-party licenses based on the current dependency tree:

```bash
cargo about init
```

Commit any changes to `about.toml` before tagging the release.
