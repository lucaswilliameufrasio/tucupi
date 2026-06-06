# Architecture

## Overview

Tucupi is a concurrent TUI dependency checker and upgrader with built-in security auditing via OSV.dev.

## Module Layout

```
src/
├── main.rs           Entry point, CLI arg parsing, TUI/Interactive routing
├── lib.rs            Library export (future)
├── app.rs            Application state machine, upgrade flow, security cache
├── batch.rs          Interactive batch mode (--interactive)
├── config.rs         tucupi.toml parser (block_vulnerable, ignored packages)
├── i18n.rs           Internationalization (pt-BR / en)
├── models.rs         Core types (Ecosystem, Dependency, VulnerabilityInfo)
├── security.rs       OSV.dev vulnerability checker (async HTTP)
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
    └── global.rs     Global packages (npm -g, pnpm -g, bun pm -g, cargo install --list)
```

## Flow

1. **Scan**: All adapters run concurrently via `tokio::join!`
2. **Display**: TUI shows the table (left) + detail panel (right)
3. **Upgrade**: User selects dependency → OSV.dev security check → Upgrades concurrently
4. **Batch**: `--interactive` mode → multi-select → batch security check → batch upgrade → report

## Security

- All external commands use `tokio::process::Command` (no shell)
- HTTP clients have 3-second timeouts
- Configuration files should have `0o600` permissions
- System paths are blocked from operations
