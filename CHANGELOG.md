# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- i18n system with pt-BR and en locale detection (LANG/LC_ALL)
- Interactive batch mode (`--interactive`/`-i`) with multi-select checklist
- Security-only check mode (press `c` to audit without upgrading)
- Upgrade in progress/failure/success status in right panel
- Troubleshooting suggestions for common upgrade errors
- Ecosystem support: PHP (Composer), Ruby (Bundler), Python (pip3)
- System package support: paru/pacman (Arch Linux), mise (tool version manager)
- Global pnpm and bun package detection
- `--help`/`-h` CLI flag

### Fixed

- Prevented multiple concurrent upgrades from being triggered
- Stripped build metadata (`+spec-1.1`) from upgrade commands
- Fixed semver comparison with build metadata in cargo and JS/TS adapters
- Allowed retry during `UpgradeFailed` status without requiring re-scan
- Cleaned error message formatting in upgrade process output

### Security

- Added MIT license file
- Pinned GitHub Actions to commit SHAs
- Scoped CI permissions to least privilege
- Added security policy (SECURITY.md)
- Added CODEOWNERS for sensitive paths
