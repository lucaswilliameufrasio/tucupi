# Architecture

## Overview

Tucupi is a concurrent TUI dependency checker and upgrader with built-in security auditing via OSV.dev and package source review (AUR PKGBUILD / Homebrew formulae) before upgrades.

## Module Layout

```
src/
├── main.rs           Entry point, CLI arg parsing (incl. `config` subcommand), TUI/Interactive routing
├── lib.rs            Library export
├── app.rs            Application state machine, upgrade flow, security cache
├── batch.rs          Interactive batch mode (--interactive)
├── config.rs         tucupi.toml parser (all [security] keys, see README reference)
├── secrets.rs        SecretStore trait: OS keychain backend (keyring), NVD key resolution (keychain → env fallback), `config` CLI commands
├── i18n.rs           Internationalization (pt-BR / en)
├── models.rs         Core types (Ecosystem, Dependency, VulnerabilityInfo)
├── security.rs       OSV.dev/NVD vulnerability checker, provenance, freshness
├── review.rs         Package source review: residual diff, known-bad scan, LLM verdict
├── cache.rs          Persistent disk cache (vulns, freshness, provenance, review)
├── rollback.rs       Local backup/restore for project dependency upgrades
├── ui.rs             TUI rendering (ratatui)
└── adapters/
    ├── mod.rs        Orchestrator (runs all adapters concurrently via tokio::join!)
    ├── cargo.rs      Cargo (Cargo.toml + crates.io API)
    ├── go.rs         Go (go list -u -m)
    ├── dart.dart     Dart (dart pub outdated)
    ├── elixir.rs     Elixir (mix hex.outdated)
    ├── js_ts.rs      JS/TS (npm/pnpm/yarn/bun outdated, npm registry)
    ├── php.rs        PHP (composer outdated)
    ├── ruby.rs       Ruby (bundle outdated)
    ├── python.rs     Python (pip3 list --outdated)
    ├── pacman.rs     Arch Linux (pacman -Qu, paru -Qua)
    ├── mise.rs       Mise version manager (mise outdated)
    ├── homebrew.rs   Homebrew (brew outdated --json --greedy)
    └── global.rs     Global packages (npm -g, pnpm -g, bun pm -g, cargo install --list)
```

## Flow

1. **Scan**: All adapters run concurrently via `tokio::join!`
2. **Display**: TUI shows the table (left) + detail panel (right)
3. **Upgrade**: User selects dependency → OSV.dev/NVD security check → **package source
   review** (AUR/Homebrew only: residual diff against the installed version's definition,
   deterministic known-bad scan, LLM verdict) → sudo pre-flight for pacman/paru → upgrade
4. **Batch**: `--interactive` mode → multi-select → batch security check → batch source
   review → batch upgrade → report

## Security

- All external commands use `tokio::process::Command` (no shell)
- HTTP clients have 3-second timeouts (review fetches: 15s)
- Root-requiring upgrade commands (`pacman`, `paru`) verify `sudo -n` first and fail
  fast instead of spawning an interactive prompt inside the TUI
- Package source content fetched from AUR/GitHub is treated as text only (diff +
  substring scan) — never executed
- Secrets (NVD API key) are stored in the OS keychain via the `SecretStore`
  abstraction; the environment variable is a CI/headless fallback only and the
  key value is never printed, logged, or persisted to project files
- Configuration files should have `0o600` permissions
- System paths are blocked from operations
