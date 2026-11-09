# Source-review provider status

## Direct model APIs

The main TUI's `a` panel selects OpenRouter, OpenAI, Anthropic, DeepSeek,
Z.ai or Kimi, sets an explicit model, and saves or removes a separate API key
in the system keychain. The selected provider and model are saved in a separate
keychain entry and restored on startup unless the project specifies either
`security.review_provider` or `security.review_model` in `tucupi.toml`.
Selecting a provider in the panel overrides the project for the current session.
Do not put API keys in the project file. Source review sends package
definition data to the selected provider and may incur charges. Missing keys,
failed requests and incomplete or invalid responses are inconclusive.

Local tests exercise synthetic credentials and local HTTP fixtures, including
HTTP failures. On Linux, an opt-in test in a separate `keyctl` session stores
uniquely named synthetic keyring entries, launches a separate test process to
restore them, and runs PKGBUILD review through a loopback-only test transport.
It covers HTTP 200, 401 and 500 for each provider and removes its entries.
The separate Linux PTY fixture runs the actual TUI executable in a private
keyctl session, configures each of the six API providers, restarts the
executable and checks local HTTP 200, 401 and 500 for each one. It uses a
synthetic package, a unique keychain service per provider, and loopback
transport, and removes its entries. Build the deliberately
non-production fixture with `cargo build --features review-pty-fixture --bin
tucupi`, then run `keyctl session - python3 tests/review_tui_pty_fixture.py`.
Do not ship builds with the fixture feature enabled. Neither fixture establishes
live provider compatibility or keychain behavior across OS logins and platforms.

## Codex: disabled

Selecting `security.review_provider = "codex"` does not launch Codex in
Tucupi. The recovery preflight is diagnostic and cannot enable the provider;
AI-dependent reviews remain inconclusive. Existing recovery records are not
deleted or migrated, and `tucupi recovery status` is read-only. Deterministic
review results retain their existing, separate policy.

The experimental supervisor and rollback exercises in
[the trust-boundary document](codex-supervision-trust-boundary.md) use synthetic
inputs and do not establish safe recovery or descendant cleanup for real work.
Re-enabling Codex requires a separately verified boundary and explicit approval.

## OpenCode and Claude Code: investigated, still disabled

The alternatives are not automatically safe replacements for Codex:

- OpenCode normally uses a shared background service and loads configuration,
  plugins and tools. `--standalone` selects a private server but does not by
  itself establish filesystem, network or process-tree isolation. See the
  [OpenCode CLI documentation](https://opencode.ai/docs/cli) and
  [configuration guide](https://opencode.ai/docs/config).
- Claude Code's `--bare` reduces automatic discovery, but still has built-in
  tools unless restricted; the documented bare mode does not use subscription
  login and requires an API key for the Anthropic API. Tool restrictions alone
  are not an OS sandbox. See the [headless guide](https://code.claude.com/docs/en/headless)
  and [CLI reference](https://code.claude.com/docs/en/cli-reference).

On 2026-11-09, a local Linux check started OpenCode v2.2.6 and Claude Code
2.1.319 in a disposable Bubblewrap environment with a private home, cleared
environment and no network. OpenCode `--standalone run` with a deliberately
nonexistent model returned `Model unavailable`; Claude `--bare --tools '' -p`
returned `Not logged in`. Neither check used real credentials or requested a
real model response. These are availability/failure observations, not proof of
safe integration, complete process-tree cleanup or compatibility elsewhere.

The configured OpenCode model catalog also lists `openai/gpt-6-luna`. A
separate `--standalone run --model openai/gpt-6-luna` attempt in the same kind
of credential-free, offline environment returned `Model unavailable`. This
does not establish whether the model is available with the user's configured
provider and authentication; no real model request was made.

On 2026-11-09, a further private `--standalone` attempt used a synthetic prompt,
network access and the legacy `auth.json` file mounted read-only in a disposable
Bubblewrap filesystem without the checkout or shared OpenCode configuration.
Policies denied tools, MCP servers, skills, plugins and web search. OpenCode
returned `Model unavailable: openai/gpt-6-luna`; no model response was obtained.
A subsequent private `auth list` with the same mounted file reported `No
authenticated integrations`, and the private model listing contained no OpenAI
models. OpenCode V2 documents that current accounts reside in the server's
SQLite database, not necessarily in the legacy file; see [provider account
storage](https://opencode.ai/docs/cli/providers#storage). Thus the attempt did
not establish compatibility with the user's configured account. The legacy
file may contain other accounts and was accessible to the private process;
network access was not restricted to a specific endpoint. This attempt does
not establish a production isolation or cleanup boundary.

Tucupi therefore continues to return an inconclusive AI-dependent review for
both providers and does not launch either CLI. Supporting either requires an
explicitly chosen authentication and network policy, an independently verified
execution and cleanup boundary, and tests covering real provider compatibility;
do not silently fall back to an unsandboxed shared service or host credentials.
