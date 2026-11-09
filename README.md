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

Before an upgrade, Tucupi warns that indirect package changes are not fully
audited and asks for confirmation. Both interfaces show Homebrew's
`brew upgrade --dry-run`, npm's `npm install --dry-run --ignore-scripts`, and
Composer's `require --dry-run --no-scripts --no-plugins` output where available.
For mise, the preview uses the same `upgrade --bump` target with `--dry-run`;
it is advisory and does not audit indirectly affected tools or packages.
For Dart, `dart pub add --dry-run --no-precompile` reports dependency changes
without applying them or precompiling executables; actual resolution and
precompilation can differ at upgrade time.
For packages identified as official Arch repository packages, `pacman -S
--print` shows a partial package list without installing. Tucupi actually runs
`paru` for upgrades; its behavior, removals, conflicts, and script effects may
not be represented. AUR and unknown-origin packages have no pacman preview.
Arch Linux does not support partial system upgrades.
Python pip uses `install --dry-run --only-binary=:all:`: it cannot preview
packages without compatible wheels and may report no preview in that case. The
real installation is not restricted to wheels, so its resolution can differ.
Other managers currently have no preview. These previews are advisory: resolution,
plugins, or lifecycle scripts can change the actual outcome,
and Homebrew may repair additional packages during execution. Indirect changes
are not automatically security-audited.
Preview output capture retains at most 64,000 bytes per output stream and
displays at most 16,000 characters, with a warning when output is truncated.
This bounds retained output, not the package manager's own resource use or
its child processes. Truncated previews still require confirmation.
In particular, pnpm, Yarn, Bun and Deno upgrades are not previewed by npm as a
substitute. Bun's documented `add --dry-run` behavior has varied across versions
([1.4.4 fixed creation of `package.json`](https://bun.com/blog/bun-v1.4.4));
Tucupi does not yet verify a safe installed version. A missing preview always
retains the incomplete-analysis warning and confirmation.
Cargo, Go, Mix and Bundler upgrades currently have no impact preview. Cargo's
[`add --dry-run`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) documents
not writing the manifest, but does not establish a full preview of the subsequent
dependency resolution. [`mix deps.update`](https://hexdocs.pm/mix/Mix.Tasks.Deps.Update.html)
does not document an equivalent dry run. These unavailable previews must not be
interpreted as an empty set of changes.

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
  - The residual diff (plus `.install` scripts / `post_install` blocks) can be
    sent to a configured supported model for a `safe / review / block` verdict.
    Configure a direct API provider with `a` in the main TUI, or in project
    configuration as described below. The default OpenCode CLI integration is
    disabled; reviews that need an unavailable provider remain inconclusive.
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
- **Codex is disabled in Tucupi.** Selecting `codex` does not launch the CLI;
  AI-dependent reviews remain inconclusive. Existing recovery records are
  retained and `tucupi recovery status` remains read-only. OpenCode and Claude
  Code are also disabled pending a verified execution boundary. See
  [review provider status](docs/review-provider-status.md).
- **OpenCode source review is temporarily disabled.** The default provider remains
  `opencode` for configuration compatibility, but Tucupi does not run it: its
  shared service can load user/project plugins and tools, and this integration did
  not establish an isolation boundary. When AI review is needed it is inconclusive.
  Cached verdicts from the previous integration are not reused. See the OpenCode
  [CLI](https://opencode.ai/v2/docs/cli) and [plugin](https://opencode.ai/v2/docs/build/plugins) documentation.
- **Optional (on-device Apple review):** set `security.review_provider = "apple"`
  in `tucupi.toml`. This uses `/usr/bin/fm respond --model system` on macOS 27+
  with Apple Intelligence available. The model and any required license acceptance
  must already be configured by the user. Tucupi never accepts Apple's terms or
  switches to Private Cloud Compute. macOS 26's framework is not supported by
  this CLI integration. The model process receives a cleared environment with a
  minimal executable path; compatibility with this restriction on macOS has not
  been validated. If the command fails, the review remains inconclusive.
- **Claude Code source review is temporarily disabled.** `--bare` and the tool
  restrictions reduce available capabilities, but the integration inherited
  the host environment and did not establish an OS isolation boundary. When AI
  review is needed, choosing `claude` remains inconclusive and does not launch
  the CLI. Prior cached verdicts are not reused. See the Claude Code
  [headless documentation](https://code.claude.com/docs/en/headless) and
  [CLI reference](https://code.claude.com/docs/en/cli-reference).
- **Not supported: Codex, agy, and Grok Build.** Selecting these provider names
  leaves the AI review inconclusive; Tucupi does not launch them. A read-only
  Codex sandbox still permits file inspection; agy headless mode respects
  existing permissions; Grok can load user hooks and MCP configuration. These
  controls alone have not been verified to isolate untrusted package content
  from files, credentials, and tools. See the respective documentation for
  [Codex sandboxing](https://developers.openai.com/codex/sandboxing),
  [agy headless permissions](https://antigravity.google/docs/cli/headless/), and
  [Grok hooks](https://docs.x.ai/build/features/hooks). This limitation does not
  establish an OS sandbox for the currently supported providers either.
  An opt-in Linux experiment can be run after
  `cargo build --locked --example codex_protocol_fixture` and
  `cargo build --locked --features codex-fixture --example codex_transport_fixture`,
  with `python3 tests/codex_broker_fixture.py` and `python3 tests/codex_isolated_smoke.py`.
  The latter needs Codex, bubblewrap,
  `unshare`, `ip`, and unprivileged user/network namespaces. It uses only local
  synthetic services and credentials. These fixtures are not production isolation
  or credential handling and do not enable Codex in Tucupi.
  The opt-in `python3 tests/codex_namespace_bypass_probe.py` is a negative
  security check. With the current fixture topology it fails: a sandboxed
  process can reach the synthetic upstream directly on shared loopback and
  bypass broker filtering. This must be fixed before relying on that topology.
  `python3 tests/codex_private_bridge_fixture.py` explores a separate topology:
  a worker in another network namespace reaches the synthetic Rust broker via
  a test-only Unix bridge while direct access to the synthetic upstream fails.
  The synthetic worker also checks that a private test file and a deliberately
  injected outer environment variable are unavailable inside its sandbox.
  It also exercises the Codex CLI against the synthetic broker. It does not
  prove credential custody or process cleanup, or change the insecure topology
  of `codex_isolated_smoke.py`.
  `python3 tests/codex_private_bridge_supervised.py` runs that experiment in
  uniquely named transient user units, including an invalid tool-call response
  and cancellation while the synthetic upstream holds the CLI request. A
  detached test descendant is checked for membership in the unit and must not
  write its delayed marker after cancellation. It also kills the `systemd-run`
  client, then explicitly stops the unit; that is not automatic crash recovery.
  The fixture checks `InvocationID` before stopping and refuses an observed
  mismatch; the check and stop are separate operations, not an atomic guarantee.
  These are fixture checks, not proof of production isolation or cleanup; in
  particular, `systemd-run --wait` can return zero after an explicit stop.
  `python3 tests/codex_supervision_fixture.py` is a separate Linux experiment
  requiring systemd user services and delegated cgroup v2 CPU, memory, and PID
  controllers. It creates temporary uniquely named user services to test limits
  timeout cleanup, CPU throttling, and cleanup after
  a synthetic service main exits unexpectedly; it does not run Codex or prove
  production supervision.
  `python3 tests/codex_memory_limit_fixture.py` separately exercises a 128 MiB
  cgroup limit with a synthetic allocator and reads OOM counters from outside
  the transient service; it does not test the production Codex runner.
  `python3 tests/codex_real_cleanup_observation.py` tests a pinned Rust cgroup
  observer against a unique transient synthetic service. If the events file
  disappears after stopping the unit, the result is unavailable, not cleanup
  proof; the test also probes a previously opened events-file descriptor. On
  the tested Linux environment that descriptor returned `ENODEV` after stop.
  The test does not establish unit ownership or production isolation.
  `python3 tests/codex_delegated_cleanup_fixture.py` is a separate opt-in
  delegated-cgroup experiment. It keeps the synthetic parent alive while
  a Rust method enabled only by `codex-fixture` writes `cgroup.kill` through
  the pinned observer to stop a detached child and grandchild and checks
  `populated 1 -> 0` before removal. Its path restriction is not a production
  unit-ownership guarantee. A loopback fake model and synthetic
  credential exercise the quarantined review result without promoting it.
  `python3 tests/codex_rust_owned_spawn_fixture.py` separately has the Rust
  review fixture object itself create a gated child, admit it through the pinned
  cgroup descriptor, and bind it to the attempt before releasing it; it
  cancels an in-flight synthetic CLI
  request using a feature-gated review object that holds the child and attempt,
  reaps the child and observes an empty group within one deadline. The test
  also closes the child's gate before release and observes the group empty
  after rejection. A test-only gate serializes cancellation against release;
  a pre-cancelled gate rejects startup before creating a group. Once fixture
  startup begins, cancellation is conservatively treated as unverified even
  before its cgroup descriptor is attached.
  The App owns an attempt-specific cancellation gate; only the fixture attaches
  a pinned cgroup.kill descriptor to request group termination after release.
  The experimental gate accepts a dedicated handle type produced by the
  pinned-directory validation; arbitrary file handles are permitted only in
  unit-test builds. The type still does not establish cgroup ownership.
  Immediately before a stop request, the fixture rechecks the pinned directory
  against the expected path and device/inode. A delegated test replaces an
  empty cgroup and confirms the stale handle is rejected without stopping a
  child in the replacement. This is a point-in-time check, not race-free
  ownership verification.
  The fixture carries the creating attempt's gate with its spawned child into
  admission, rather than accepting a separate gate at that boundary. This is
  an internal binding, not proof that the OS cgroup belongs to that attempt.
  Through admission and until transfer to the fixture supervisor, dropping the
  spawned-child guard makes a bounded best-effort attempt to stop and reap its
  direct child; Drop cannot report errors or prove descendant cleanup.
  For a returned admission error, an unsuccessful direct-child reap is reported
  as unverified cleanup; any later Drop retry does not change that result.
  A gate rejects attachment before registered startup and rejects a second
  attachment rather than replacing its original handle; this is not proof that
  the original unit belongs to the attempt.
  The delegated fixture also checks that cancelling a second attempt after an
  exclusive-creation collision does not stop the first synthetic child; this
  is not proof against concurrent adversarial cgroup manipulation.
  It also refuses release before child startup and handle attachment, and
  never retries a release write, including after a failed or partial write.
  The fixture checks the child's reported cgroup membership after admission
  and again before releasing it. A delegated test moves the synthetic child
  between these checks and confirms rejection and direct-child reaping. The
  point-in-time PID-based checks do not prevent a later move or prove process
  or cgroup ownership.
  After the gate opens, the synthetic Python child also checks its own reported
  membership immediately before executing the fixture. A delegated test moves
  it after the controller's check and observes rejection. The controller does
  not receive an authenticated acknowledgement of this check, and a move can
  still occur after the child's check; neither check is an isolation boundary.
  A synthetic concurrency test checks that attachment racing cancellation
  either gets rejected or receives the stop request; it does not establish
  process termination or ownership.
  The fixture reserves one child-spawn attempt without holding its gate lock
  across spawn. Cancellation can be recorded while spawn is blocked; a child
  returned after cancellation is stopped and reaped best-effort before the
  fixture returns. If that explicit attempt fails, cleanup remains unverified
  and the spawned-child guard attempts cleanup again on drop. This does not
  stop the syscall itself, and a child that has
  not yet returned cannot be killed through this mechanism. Startup remains
  cleanup-unverified; this is not a production ownership guarantee.
  This experimental signal does not prove ownership or successful cleanup; the
  gate retains a write failure for later callers. While running, the App
  reports such a failure and blocks further updates in that session; this
  state is not persisted across restart. Normal interactive exit and errors
  in the interactive loop request cancellation before terminal restoration
  and report unverified cleanup; abrupt termination, initialization failures,
  and dropping the App cannot reliably report it.
  In all App review paths, an attached fixture unit makes even a
  successful stop request unverified cleanup: results are not promoted and a
  replacement or queued operation does not start. A separate case kills the Rust
  controller and exits the fixture's unit main; the outer systemd unit then
  stops its remaining processes. A separate controller-only crash test keeps
  the unit main alive and observes a detached synthetic descendant continuing
  long enough to write a marker. Therefore controller failure alone does not
  establish cleanup. This remains an
  opt-in experiment, not a production admission or isolation guarantee.
  The default App's cleanup-unverified block remains in-memory and is lost on
  restart. An opt-in Linux `codex-fixture` App constructor instead uses a
  monotonic recovery marker in a caller-provided private test directory. Its
  actual fixture gate persists a kernel-generated synthetic attempt identifier
  in the marker before starting work and treats
  missing/unavailable state or an existing marker as blocked. Tests cover a
  failing synthetic stop handle, another App instance, a separate App process,
  and a state directory removed before startup. The synthetic handle is not a
  systemd manager failure or restart. The marker is never cleared. This is not
  integrated into the default App, batch mode, or production, and does not
  establish trusted directory ownership, binding of that identifier to a
  systemd unit, reconciliation,
  crash-safe unlock, or a safe production state location. Do not infer cleanup
  or permission to enable a provider from a fresh default instance.
  For the planned production recovery state, an absent registry must not be
  automatically treated as a clean first run: initial provisioning must be
  explicit. The Linux `recovery_state` module provides an exclusive directory
  provisioning primitive under an existing private parent, with a synced format
  marker; existing paths and missing or invalid markers are rejected. It
  never treats the format marker as evidence of clean supervised work. This is
  an initial building block, not a trusted ancestor-path check, a user-facing
  initialization command, manager reconciliation, or integration with the App
  or batch mode for persistent recovery. On Linux, the default App's policy
  gate and the real batch entry now share a narrower Codex-only preflight: a
  missing/invalid state blocks, and even a valid format remains blocked because
  no manager reconciliation exists. This is not a general persistent cleanup
  block for other providers or configurations, nor does it enable Codex.
  `python3 tests/codex_production_preflight_fixture.py` tests the real batch
  entry with isolated missing and provisioned state; no manager is contacted.
  Failed provisioning can leave a partial directory; it is not
  automatically removed or reinitialized. A valid format marker also does not
  prove that the provisioning caller observed successful completion.
  If an interactive impact-preview task is cancelled while still running, the
  App requests termination of its direct child via Tokio's kill-on-drop and
  keeps updates blocked for that session because descendant cleanup is unknown.
  A valid configuration reload does not clear that in-memory block. A synthetic
  direct-child test observes exit with a pidfd; it does not establish process-tree
  cleanup, synchronous reaping, crash recovery, or a persistent cross-process
  block. No production supervisor is implied.
  The Linux test `synthetic_impact_descendant_and_restart_expose_cleanup_limit`
  demonstrates the gap: a detached synthetic descendant can write its delayed
  marker after the direct child is cancelled, while the original App remains
  blocked. After a valid configuration reload, a separate new App process does
  not recover that in-memory block. The test terminates its synthetic descendant
  using a pidfd; it does not establish durable cleanup or recovery.
  The Linux test `synthetic_batch_runtime_exit_stops_direct_child_but_not_descendant`
  invokes the batch preview and quit handler in an isolated test process. After
  its Tokio runtime and process exit, pidfds observe the synthetic direct child
  exit and the detached descendant write a marker before exiting. This is not
  a test of the production terminal entry point or proof of synchronous reaping;
  it exposes a remaining descendant-cleanup gap, not a recovery mechanism.
  The separate `synthetic_aborted_preview_stops_direct_child_not_detached_descendant`
  test evaluates aborting the preview future while its runtime stays alive. A
  pidfd observes the synthetic direct child exit, but its detached descendant
  still writes a marker. This experiment does not connect cancellation to batch
  shutdown, prove descendant cleanup, or add a persistent shared block.
  When `q` is pressed during a batch impact preview, the batch now requests
  cancellation of the preview task and, after restoring the terminal, returns
  an error warning that cleanup is unverified and no shared persistent block
  exists. Cancellation does not establish that descendants have exited.
  Errors from the batch event loop also request preview cancellation, attempt
  each terminal-restoration step, and report the original error together with
  the unknown-cleanup warning. This does not cover forced termination or prove
  that child processes have been reaped.
  The Linux `synthetic_upgrade_blocks_batch_quit_until_completion` test uses a
  synthetic executable to check that `q` cannot exit while an upgrade is in
  flight, and that quitting is possible after its completion is processed.
  An event-loop failure during an upgrade reports unverified completion; this
  does not prove recovery or descendant cleanup after process exit. A stalled
  upgrade may continue to block voluntary exit indefinitely.
  The `interactive_synthetic_upgrade_pty` Linux fixture also disconnects a real
  isolated PTY during a synthetic upgrade with SIGHUP ignored. The batch
  returned the unknown-completion warning while the synthetic direct worker
  was still active; the harness then released and observed that worker exit.
  On cursor-restoration failure the batch preserves the error and disarms
  Ratatui's destructor retry, so the terminal is dropped without retrying a
  write to disconnected stderr. This is not evidence about normal SIGHUP,
  real upgrades, or descendant cleanup.
  The Linux `synthetic_batch_upgrade_runtime_exit_process_lifetimes` test
  observes an isolated test runtime exiting while a synthetic upgrade is in
  flight. In the tested scenario, pidfds show that both its direct child and a
  detached descendant remain active after the runtime exits; both write a
  marker after release and then exit. This characterizes a cleanup gap, not
  the outcome of a real upgrade, rollback, or persistent recovery.
  The separate `synthetic_kill_on_drop_runtime_exit_experiment` drops a
  synthetic Tokio child configured with `kill_on_drop` before the test runtime
  exits. A pidfd observes the direct child exit, while the detached descendant
  continues and writes a marker. This experiment is not wired into the
  production upgrade path, performs no rollback, and does not prove cleanup.
  The Linux `synthetic_upgrade_interruption_backup_rollback_fixture` exercises
  the batch's real local backup and rollback path with a synthetic Cargo
  executable and manifest. Interrupting that direct process while the runtime
  remains active reports failure and restores the manifest. If the test runtime
  exits first, its temporary snapshot is removed and the modified manifest
  remains after interruption. This does not qualify real package updates,
  detached descendants, host-loss recovery, or a persistent backup strategy.
  The test-only `synthetic_retained_backup_survives_runtime_exit` fixture keeps
  a synthetic temporary backup before starting a synthetic child. The copy is
  still readable after runtime exit, while the modified manifest remains
  unchanged and no restore runs. This fixture does not change production
  backups, authenticate the stored copy, establish ownership or persistence
  across host failure, or authorize recovery.
  The Linux `real_batch_pty_disconnect_reports_unknown_cleanup` test closes an
  isolated pseudoterminal master with SIGHUP ignored by the synthetic batch
  process. The Crossterm `use-dev-tty` backend avoids the previously observed
  polling hang in this scenario; the batch returns the unknown-cleanup warning
  and the synthetic direct child does not reach its delayed marker. This does
  not characterize normal SIGHUP handling, other terminal platforms, or
  cleanup of descendants.
  `TMPDIR=... /usr/bin/python3 tests/terminal_keyboard_fixture.py` exercises
  the built production binary in isolated Linux pseudoterminals and an empty
  project: the App opens and closes help and quits; batch handles Space and
  Enter on an empty list and quits. The fixture also sends navigation keys and
  resizes the PTYs but does not assert each navigation or layout change. It
  checks alternate-screen, canonical-input and echo restoration, not every key,
  platform, locale, terminal emulator, or package-upgrade journey.
  Setting `TUCUPI_SYNTHETIC_BATCH_BIN` to the absolute path of a locally built
  `tucupi` binary when running that test additionally starts the real batch
  entry with a synthetic non-Codex configuration while the detached synthetic
  descendant remains alive. The process has no controlling terminal and null
  stdin, so terminal initialization fails before scanning or package work. In
  the tested flow batch passes its Codex-only preflight instead of recovering
  the earlier App's in-memory block. This demonstrates a missing shared guard;
  it does not demonstrate that an update was actually executed.
  `python3 tests/impact_systemd_boundary_fixture.py` is a separate opt-in
  experiment. It persists a fixture marker, runs the real impact-preview runner
  with a synthetic worker in a uniquely named transient systemd user unit, and
  kills the unit's verified MainPID. The harness observes the worker and its
  detached child exit and checks that the delayed marker is absent. A separate
  experimental App process then sees the marker or unavailable state as blocked.
  The marker is not authenticated or bound to the unit, and the default App
  does not use this fixture boundary. The result does not prove protection from
  escape, unit manipulation, manager failure, filesystem substitution, power
  loss, or production recovery.
  The Linux module also parses a bounded pending-attempt identity and classifies
  caller-supplied manager snapshots. Tests simulate outage, changed boot or
  manager generation, missing or mismatched unit, active/populated/unknown
  groups, and an empty observation. None of these outcomes clears the record;
  even an empty group remains unverified. A read-only manager adapter is used
  diagnostically by the default App configuration load and batch entry when
  Codex is selected. It cannot authenticate manager generation, and a match is
  classified as unknown; all cases remain blocked. There is no durable attempt
  writer or production reconciliation that can authorize cleanup. Snapshot fields and persisted identity
  alone are not evidence of ownership or protection from escaped processes.
  A separate opt-in synthetic batch admission helper uses the same marker as
  the experimental App gate. Tests cover both admission orders and a synthetic
  manager failure followed by a new App process; the callback never runs a
  package command. This helper is not called by the real batch runner and is
  not a shared production recovery implementation.
  The fixture pins its state directory and compares its device/inode with the
  original path before reading or writing. A replacement observed by an
  existing App blocks it, but a newly started App can still see a replacement
  empty directory as clear. The comparison is point-in-time and does not make
  the state path trustworthy or prevent a concurrent substitution. The fixture
  also checks after reads and durable writes; a deterministic test replaces
  the directory during marker creation and confirms the operation returns an
  error, while the old marker remains in the renamed directory. Replacement
  after the final check and recovery from a new process remain unresolved.
  `python3 tests/codex_recovery_unit_observation_fixture.py` separately records
  a synthetic unit name and observed `InvocationID` against a fixture attempt
  identifier, and confirms that a new experimental App stays blocked when a
  deliberately invalid manager address makes a query fail. The observation is
  supplied by the caller, not authenticated or tied to actual process
  ownership; it is write-once and cannot unlock recovery. This does not test
  a real manager restart, integrate batch mode, or establish production recovery.
  The Rust diagnostic now uses one zbus connection for the bus ID, systemd
  unique owner and unit properties, checking the bus peer UID and repeating
  bus ID and owner afterward. It does not authenticate the manager credentials
  as an independent authority, observe cgroup cleanup,
  or prove protection against same-user races. It now checks the bus-reported
  manager UID/PID on the same connection and requires the bus-provided
  `ProcessFD` across the query. It validates the descriptor type, reported PID
  and liveness, rejecting missing or inconsistent credentials. This binding
  relies on the bus reporting its connections honestly and does not authenticate
  the bus against a same-user adversary or prove unit ownership;
  matching observations remain blocked as an unknown manager generation.
  `TMPDIR=... /usr/bin/python3 tests/codex_fake_manager_bus_fixture.py` starts
  a private same-UID D-Bus daemon and a synthetic service impersonating the
  systemd interface. When explicitly pointed at that private runtime, the Rust
  adapter accepts a matching synthetic unit and `ProcessFD`; its fixture record
  remains unchanged and reconciliation stays blocked. If `ProcessFD` is not
  available the fixture instead requires rejection. This does not demonstrate
  replacement of the real `/run/user` socket or compromise of the default
  runtime; it shows that matching same-user observations alone are not proof of
  an independent authority or ownership.
  The same fixture supplies its fake runtime through both `XDG_RUNTIME_DIR` and
  `DBUS_SESSION_BUS_ADDRESS` while invoking the default App and real batch
  entry. The App diagnostic still queries its fixed `/run/user/<euid>` runtime,
  and batch remains blocked; the synthetic record is unchanged. This prevents
  those environment overrides from selecting the fixture's bus, but does not
  authenticate the fixed socket or protect the recovery state from same-user
  substitution. A production ownership boundary still needs an independently
  trusted supervisor or equivalent authority that creates the unit, binds its
  identity to durable state, and can prove cleanup; none is implemented here.
  `python3 tests/codex_manager_observation_fixture.py` separately exercises a
  bounded, read-only `systemctl --user show` adapter for a narrowly named
  synthetic unit. It compares the observed unit and invocation with a persisted
  synthetic record and rejects unavailable manager access or mismatched
  invocation. It does not authenticate the manager or its generation, check
  cgroup cleanup or clear the record. The test also drives the default App's
  diagnostic and real batch preflight with a synthetic record; even a matching
  observation remains blocked. Manager unavailability is simulated with an
  invalid runtime and, for the App and batch processes, by hiding the user bus
  and systemd private sockets inside a dedicated test unit. The real manager is
  not restarted. These observations are diagnostic only and do not clear state.
  `python3 tests/codex_manager_bus_candidate_fixture.py` additionally samples
  the boot ID, user-bus ID and the unique owner of the systemd bus name before
  and after a synthetic unit query, comparing them with fixture-persisted data.
  It rejects an altered owner or unavailable runtime. This is only a candidate:
  the bus is not authenticated as an authority and `systemctl` can use a
  different connection; neither the source nor its binding to the unit is a
  trustworthy production manager identity. It is not used to unlock recovery.
  `TMPDIR=... /usr/bin/python3 tests/codex_same_connection_fixture.py` is a
  separate opt-in experiment using the system Python `dbus` module. One private
  D-Bus connection queries the bus ID, unique systemd owner, reported owner
  UID/PID and a narrowly named synthetic unit addressed through that unique
  owner. The fixture checks local socket peer credentials, pins the reported
  manager PID with pidfd, and repeats the bus/owner checks after the unit
  query. Altered synthetic bus, owner, PID and unit invocation records and an
  unavailable runtime are rejected. The record and unit are test resources;
  same-user peer credentials, PID acquisition and repeated observations do not
  authenticate a production authority, prove unit ownership or rule out all
  races. This Python probe is not the Rust production adapter and never clears
  recovery state or enables Codex.
  An optional watchdog experiment keeps an open child-cgroup kill descriptor
  and watches the controller pidfd. It has no disarm channel and requests a
  stop even after normal controller exit. Tests cover startup failure, watchdog
  death after release, controller death before and after release, and a forged
  disarm byte sent to its `/dev/null` stdin. Simultaneously killing both the
  controller and watchdog leaves a synthetic descendant running while the
  outer unit remains alive. This is not production supervision: its readiness
  marker is not authenticated, a window exists before readiness, the watchdog
  cannot handle controller hangs, and ownership, isolation, descriptor
  replacement and complete cleanup remain unverified. A stop request or a
  point-in-time empty group is not proof of complete cleanup.
  A further opt-in test starts a separate synthetic custodian in the outer unit.
  It checks the fixture processes' parent relationships and unit membership,
  opens pidfds for both controller and watchdog and a pinned child-cgroup kill
  descriptor, and requests a stop after observing both processes exit. In the
  tested simultaneous-failure scenario the child group became empty while the
  outer unit remained alive. The unguarded control still leaves a descendant
  alive; a triple-failure test also observes a surviving descendant when the
  custodian is killed. This custodian is test-only, shares the outer unit and user, starts
  after the workload, has unauthenticated readiness and can itself fail; it is
  not a production ownership, isolation, recovery or cleanup guarantee.
  `python3 tests/codex_systemd_main_fixture.py` is a separate opt-in
  experiment: a uniquely named transient user service runs the synthetic Rust
  controller as its MainPID, with `KillMode=control-group` and a runtime limit.
  The test checks the invocation ID, MainPID and cgroup before signalling the
  controller using a pidfd, then observes the unit stopped, its cgroup empty or
  removed, and no delayed descendant marker. It starts the actual synthetic
  watchdog and custodian as children of the controller, verifies their parent and
  unit membership, freezes them, then kills both and the controller using
  pidfds. Neither auxiliary's stop-request marker may appear. Signals are sent
  sequentially with the auxiliaries frozen, not atomically; this tests the
  manager's cleanup without relying on those auxiliaries.
  This only tests the local manager's behavior for processes remaining in that
  unit; it does not establish protection against escaped processes, concurrent
  unit manipulation, manager failure, repopulation, network/filesystem access,
  credential custody, or production cleanup and ownership guarantees.
  `python3 tests/codex_systemd_escape_fixture.py` tests an unprivileged move
  between two uniquely named delegated synthetic user services. When permitted
  on the host, it moves a verified synthetic child to the target service, kills
  the source MainPID, and checks source cleanup and the child's late marker in
  the target. Both fixture services are stopped afterward. A denied move is
  reported separately and does not establish escape resistance. A successful
  move demonstrates that source-unit cleanup does not reach a process already
  moved elsewhere; it does not prove that an untrusted production process can
  or cannot perform the same move under a future isolation policy.
  `python3 tests/codex_systemd_cgroup_boundary_fixture.py` compares synthetic
  self-movement into a dedicated target user service with and without systemd
  `ProtectControlGroups=yes`. On the tested host the unprotected control moved
  itself; the protected process received `EROFS` and its membership stayed
  unchanged. This only tests a pathname write: inherited descriptors, other
  mounts, manager APIs, privileged helpers and other escape routes are not
  ruled out. It does not enable Codex or establish isolation or cleanup.
  `python3 tests/codex_systemd_bus_boundary_fixture.py` tests another route
  using uniquely named synthetic user services: with `ProtectControlGroups=yes`,
  direct cgroup movement was denied, but `systemctl --user stop` through the
  exposed user-manager connection stopped the separately verified test unit.
  Hiding only the user bus socket still allowed a manager query on the tested
  host; hiding both that socket and the systemd private socket denied that
  query. This does not prove which alternate path was used, or that hiding
  those two sockets prevents all manager, descriptor, or filesystem access.
  `python3 tests/codex_combined_boundary_fixture.py` combines the actual Rust
  gated spawn and its close-on-exec helper with a synthetic bubblewrap child.
  The controller receives an open writable target-cgroup descriptor; the child
  checks that descriptor is absent, the cgroup path is read-only, and a user
  manager query fails in a filesystem without the runtime sockets. A control
  outside that filesystem successfully queries the same synthetic target; the
  child group is observed empty after cancellation. The child also runs in a
  separate network namespace and cannot connect to a synthetic TCP loopback
  listener or an abstract Unix listener in the outer namespace; controls connect
  to both and the listeners observe no child connection. The abstract socket is
  a synthetic endpoint, not an actual systemd manager endpoint. This remains a
  synthetic experiment: it does not test all inherited descriptors, actual
  alternative manager endpoints, every network path, credentials, ownership or
  crash cleanup, and does not implement an admission boundary for production.
  `python3 tests/codex_combined_crash_fixture.py` exercises that combined
  synthetic boundary inside a dedicated transient service. It verifies the
  unit invocation, MainPID, parent relationships and cgroup membership, freezes
  the fixture controllers and actual synthetic watchdog/custodian, then sends
  fatal signals via pidfds. The test observes the service stopped and its
  cgroup empty or removed, without auxiliary stop markers or a delayed child
  marker. Signals are sequential while processes are frozen. This does not
  cover escaped processes, manager failure, recovery across sessions, or a
  production result-promotion or cleanup guarantee.
  `python3 tests/codex_inherited_cgroup_fd_fixture.py` separately demonstrates
  an inherited-descriptor bypass of a bubblewrap read-only cgroup mount: a
  synthetic process cannot write the target path but can move itself using a
  writable `cgroup.procs` opened before the mount and passed as stdin. A
  read-only stdin control does not move. This deliberately leaks the descriptor
  to the synthetic process; it does not establish whether a future production
  launcher leaks one, nor does it test systemd manager APIs or all descriptors.
  A synthetic launcher also opens the target descriptor as both stdin and fd 3,
  then spawns bubblewrap with `close_fds=True` and `/dev/null` stdin. The child
  checks its own descriptor links and `/proc/self/fd/3`; neither exposes that
  handle in the tested run. A bounded search of same-cgroup ancestors through
  `/proc` did not observe a reopening bypass in that run. This experiment is not
  the Rust production launcher and does not establish that ancestor access or
  other descriptor, mount, or manager API paths are impossible.
  `python3 tests/codex_rust_descriptor_inheritance_fixture.py` probes a separate
  Rust `std::process::Command` with `env_clear()` and piped stdin. A deliberately
  inheritable synthetic file descriptor reached the child; a control closed it
  before starting the Rust process. The experimental Linux fixture now uses
  `close_range` with `CLOSE_RANGE_CLOEXEC` for descriptors 3 and above before
  exec, and replaces stdout/stderr with `/dev/null`. The same probe checks that
  its inherited synthetic descriptor disappears when this helper is applied;
  failure of the syscall rejects startup. This does not inspect the actual
  fixture's full descriptor set or establish a production mitigation. It
  requires kernel support for the syscall and flag and has no fallback.
  `python3 tests/codex_real_spawn_fd_fixture.py` injects an inheritable
  synthetic file descriptor into the Rust fixture controller, verifies it is
  present there, then checks that the admitted gated child does not inherit it
  and that cancellation observes an empty cgroup. The delegated App fixture
  also injects a `close_range` failure at actual startup and verifies that exec
  is rejected and the session remains blocked. These tests do not establish
  descriptor isolation for production or for paths through other processes.
  `python3 tests/codex_systemd_replacement_fixture.py` recreates a uniquely
  named transient unit and checks that its new invocation differs from the
  original. It attempts to move the replacement's synthetic process using an
  open `cgroup.procs` descriptor from the removed original cgroup, then checks
  the replacement remains active. It also moves that process into and out of a
  live delegated subgroup and observes `populated 0 -> 1 -> 0`. These are
  fixture observations, not race-free authorization or evidence that an
  empty live group cannot later be repopulated.
  `python3 tests/codex_app_supervised_fixture.py` builds the Rust library test
  binary and runs an ignored test in delegated synthetic units. It injects the
  fixture into the actual App review-task controller and observes an empty
  cgroup after cancellation, worker panic, and replacement of an in-flight
  attempt, and checks that the synthetic direct child is reaped. A separate
  barrier-controlled test cancels before or after cgroup creation, before
  descriptor attachment, or cancels or replaces the attempt, shuts down, or drops the App
  after admission but before gate release. The after-creation check is
  cooperative; its empty cgroup is left to the outer fixture unit. After that
  unit exits, the test verifies that the child path is no longer visible.
  Another test cancels after release while initialization
  is paused: the test observes an empty group before the
  pause ends, then checks direct-child reaping after it resumes. A test-only
  injected write failure keeps a populated group blocked until fixture cleanup;
  the App's session block remains after that cleanup. Build both Codex fixture examples first. This does
  not prove descendant reaping, production ownership, isolation, or terminal
  behavior after panic. Fixture drop uses a bounded synchronous wait and cannot
  report timeout or cleanup errors.
  A separate synthetic App test demonstrates that aborting a Tokio task does
  not interrupt synchronous startup: it can continue until its next yield.
  No production supervisor may rely on task abort alone for startup cancellation.
  Main-flow reviews also check the attempt cancellation state before review,
  before model execution and before caching. These cooperative checks do not
  atomically prevent a concurrent process start or prove process cleanup.
  `python3 tests/codex_cgroup_repopulation_fixture.py` uses a delegated
  synthetic cgroup and quarantined synthetic review to check that the bound
  observer rejects a populated → empty → repopulated sequence. It does not
  prevent later repopulation or establish result ownership or promotion.
  The fixture also verifies that an invalid synthetic model response does not
  prevent requesting cancellation and observing the delegated child group empty.
  Its test-only attempt also makes a best-effort cancellation on Rust drop;
  this cannot report cleanup failure and does not run after SIGKILL or abort.
  With `--bridge`, the delegated child runs the private bridge and Codex CLI
  with synthetic services, then the Rust fixture cancels it while its request
  is held. The Rust fixture exclusively creates the child cgroup and pins it
  before the Python test admits the child; this is not a production ownership
  boundary or proof against an actor with equivalent access. The bound attempt
  has received no review response, and a synthetic
  late response is rejected after cancellation; result ownership remains unproven.
  It requires delegated cgroup-v2
  write access and does not prove that an untrusted worker cannot escape or
  repopulate the cgroup; it does not enable Codex.
  `python3 tests/codex_supervised_smoke.py` combines that approach with the
  isolated synthetic Codex flow, including rejection of incorrect cgroup limits and a missing listener,
  a controlled timeout, explicit stop, main-process and controller failures, and detached
  synthetic descendant. This is also an opt-in test, not a production runner.
  Its Rust listener checks its cgroup membership and configuration before binding; that
  check alone does not prove enforcement, network isolation, or process cleanup.
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
| `?` | Open the scrollable commands panel |
| `Tab` | Toggle Local/Global packages tab |
| `↑` / `↓` | Navigate dependency list |
| `Space` | Cycle the focused row: unselected, safe upgrade, forced upgrade |
| `r` | Re-scan dependencies |
| `u` | Upgrade selected rows using their safe/forced state; upgrades the focused row when none are selected |
| `f` | Force upgrade selected rows; force upgrades the focused row when none are selected |
| `c` | Audit selected rows without upgrading; audits the focused row when none are selected |
| `l` | Open upgrade logs popup (`y` copies the active log) |
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
| `pre_scan_security` | bool | `true` | Run background vulnerability, freshness, and provenance checks for eligible dependencies after scanning. `false` disables these automatic checks, not explicit audits or upgrade-time checks. |
| `freshness_threshold_days` | i64 | `7` | Days after publication before a release is considered "mature" (informational). |
| `block_too_fresh` | bool | `false` | Block upgrades to releases published less than `very_recent_days` ago. |
| `very_recent_days` | i64 | `3` | The "too fresh" window used by `block_too_fresh`. |
| `pkgbuild_review` | bool | `true` | **Package source review gate** for AUR PKGBUILDs and Homebrew formulae/casks: residual diff + deterministic scan + LLM verdict before upgrade. |
| `review_provider` | string | `"opencode"` | Direct API providers: `openrouter`, `openai`, `anthropic`, `deepseek`, `zai`, `kimi`; `apple` uses on-device macOS review. The `codex`, `opencode`, and `claude` CLIs remain disabled. Unknown or unavailable providers are inconclusive. |
| `codex_auth_mode` | `"chatgpt"` or `"api_key"` | unset | Reserved selection for the disabled Codex integration. It stores no credential, does not authenticate or start Codex, and does not authorize API charges. Unknown values remain invalid. |

| `review_model` | string | provider-specific | Direct API providers require an explicit model ID supported by the selected provider and account. Apple always uses `system`. |
| `review_llm` | bool | `true` | `false` = source review runs deterministic scan only (no API calls; inconclusive results require manual review). |

The `[security]` fields `codex_api_key` and `openai_api_key` are not supported:
their presence causes configuration loading to fail rather than silently ignoring
an inline credential. This does not detect other field names, erase values from
an existing file, or provide Codex credential storage; never put secrets in
`tucupi.toml`.

Configuration files are limited to 1 MiB. Larger files are rejected rather
than parsed partially; reduce the file size before retrying.

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
