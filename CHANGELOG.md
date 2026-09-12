# Changelog

All notable changes to this project will be documented in this file.


### <!-- 0 -->🚀 Features

- Add version flag

### <!-- 0 -->🚀 Features

- Homebrew adapter, batch osv pre-scan, cvss severity, freshness check, aur provenance
- Wire freshness/provenance/NVD into scan flow and detail UI
- Fail closed and block AUR by default
- Require valid provenance for pacman upgrades
- Classify freshness and block very recent releases
- Add local rollback for dependency upgrades
- Add persistent cache and request concurrency limit
- Refine vulnerability source merging and NVD filtering
- Add package source review gate for AUR and Homebrew
- Add toast notifications, upgrade log popup and responsive layout
- Support tucupi.local.toml for secrets
- Store NVD API key in the OS keychain
- Add batch dependency upgrades and bounded logs

### <!-- 1 -->🐛 Bug Fixes

- Restore vuln colors and fix scroll wrapping
- Prevent hanging upgrades, add --noconfirm and timeout
- Filter pacman git versions, handle OSV 400 gracefully
- Mise latest filter, inherit stdout for global pkgs, audit warning
- Use native Linux keyring backend

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Upgrade dependencies
- Add setup/format/lint targets to Makefile

### <!-- 1 -->🐛 Bug Fixes

- Add CDLA-Permissive-2.0 to accepted licenses

### <!-- 0 -->🚀 Features

- Initialize tucupi concurrent dependency guard TUI app
- I18n, batch mode, new ecosystems, troubleshooting, and fixes

### <!-- 1 -->🐛 Bug Fixes

- Use correct GitHub Actions SHAs from acari
- Add required toolchain input to dtolnay/rust-toolchain steps
- Copy prepare-release and release workflows from acari
- Add allow-dirty = ["ci"] to dist-workspace.toml
- Correct about.toml format for cargo-about

### <!-- 3 -->📚 Documentation

- Document cargo-dist secure installation instructions in README
- Add guides for automated distribution and security policies
- Add cargo about init step to release process in README

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Configure cargo-dist automated release workflow and installers
- Upgrade dependencies
- Publish-ready infrastructure, security hardening, and CI
- Add lib.rs, build.rs, enhance CI with convention checks
- Fix fmt, clippy warnings, and action SHAs
- Sync workflows and README with acari
