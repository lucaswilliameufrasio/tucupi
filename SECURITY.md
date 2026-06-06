# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

Tucupi performs system-level package management operations. If you discover a security vulnerability, please report it privately.

**Do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to **lucaseufrasio@gmail.com**.

You should receive a response within 48 hours. If for some reason you do not, please follow up to ensure we received your message.

### What to include

- Type of issue (e.g., command injection, privilege escalation, TOCTOU)
- Full paths of source files related to the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### Process

1. Your report will be acknowledged within 48 hours
2. We will investigate and provide an estimated timeline for a fix
3. A fix will be prepared and released as a patch version
4. You will be notified when the fix is released
5. The vulnerability will be publicly disclosed after the fix is available

## Scope

The following areas are in scope for security research:

- Package version injection via `tucupi.toml` or command-line arguments
- TOCTOU (Time-of-Check Time-of-Use) vulnerabilities in upgrade execution
- Path traversal in target directory handling
- Shell metacharacter injection in upgrade commands
- Unauthorised access to configuration files
- Supply chain attacks via dependency resolution

## Security Measures

- Configuration files should be readable only by the owner (`0o600`)
- System-critical paths (`/etc`, `/proc`, `/sys`, `/dev`) are blocked from upgrade operations
- All GitHub Actions are pinned to specific commit SHAs
- Third-party dependencies are audited for license compliance
