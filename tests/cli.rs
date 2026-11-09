use assert_cmd::Command;
use predicates::prelude::*;

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
#[test]
fn recovery_status_stays_blocked_after_synthetic_rollback() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command as Process, Stdio};
    use std::time::{Duration, Instant};
    const ATTEMPT: &str = "0123456789abcdef0123456789abcdef";
    for successful in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("tucupi");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        tucupi::recovery_state::provision_state_directory(
            &parent,
            std::ffi::OsStr::new("recovery"),
        )
        .unwrap();
        let state = parent.join("recovery");
        let source = tempfile::tempdir_in(root.path()).unwrap();
        let manifest = source.path().join("Cargo.toml");
        std::fs::write(&manifest, b"synthetic original").unwrap();
        let pending = tucupi::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).unwrap();
        pending.capture_synthetic_files(&source).unwrap();
        pending
            .store_synthetic_postimage(b"synthetic modified")
            .unwrap();
        let mut child = Process::new("/bin/sh")
            .args(["-c", "IFS= read -r line; [ \"$line\" = go ] || exit 90; printf 'synthetic modified' > \"$1\"; exit \"$2\"", "fixture"])
            .arg(&manifest).arg(if successful { "0" } else { "7" })
            .env_clear().stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut observed = pending.bind_child(&mut child).unwrap();
        input.write_all(b"go\n").unwrap();
        drop(input);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(result) = observed.poll_and_record_exit().unwrap() {
                assert_eq!(result, successful);
                assert!(!observed.permits_operation());
                break;
            }
            assert!(Instant::now() < deadline, "fixture child did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(std::fs::read(&manifest).unwrap(), b"synthetic modified");
        let _copy =
            tucupi::same_user_supervisor::reopen_synthetic_attempt_after_exit(&state, &source)
                .unwrap();
        assert_eq!(std::fs::read(&manifest).unwrap(), b"synthetic original");
        let records: Vec<_> = [
            "pending-intent",
            "pending-snapshot",
            "pending-fixture-postimage",
            "pending-exit",
            "pending-fixture-rollback",
        ]
        .into_iter()
        .map(|name| (name, std::fs::read(state.join(name)).unwrap()))
        .collect();
        for (locale, blocked, exit, unknown) in [
            (
                "en_US.UTF-8",
                "BLOCKED",
                if successful {
                    "Direct child: successful exit recorded"
                } else {
                    "Direct child: failed exit recorded"
                },
                "descendant cleanup and rollback",
            ),
            (
                "pt_BR.UTF-8",
                "BLOQUEADA",
                if successful {
                    "Filho direto: saída bem-sucedida registrada"
                } else {
                    "Filho direto: saída com falha registrada"
                },
                "limpeza de descendentes e rollback",
            ),
        ] {
            Command::cargo_bin("tucupi")
                .unwrap()
                .args(["recovery", "status"])
                .env_clear()
                .env("HOME", root.path())
                .env("XDG_STATE_HOME", root.path())
                .env("LC_ALL", locale)
                .assert()
                .success()
                .stdout(predicate::str::contains(blocked))
                .stdout(predicate::str::contains(exit))
                .stdout(predicate::str::contains(unknown));
        }
        for (name, bytes) in records {
            assert_eq!(std::fs::read(state.join(name)).unwrap(), bytes);
        }
        assert_eq!(std::fs::read(&manifest).unwrap(), b"synthetic original");
        assert!(tucupi::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).is_err());
        let inspection = tucupi::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.descendant_cleanup,
            tucupi::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            tucupi::same_user_supervisor::RecoveryOutcome::Unknown
        );
    }
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
#[test]
fn recovery_status_preserves_fixture_plan_without_direct_exit() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command as Process, Stdio};
    const SUPERVISOR: &str = "TUCUPI_CLI_PENDING_FIXTURE_SUPERVISOR";
    const ATTEMPT: &str = "0123456789abcdef0123456789abcdef";
    if let Some(root) = std::env::var_os(SUPERVISOR) {
        let state = std::path::Path::new(&root).join("tucupi/recovery");
        let pending = tucupi::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).unwrap();
        pending
            .store_synthetic_files(&tucupi::same_user_supervisor::SyntheticFileSnapshot {
                version: 1,
                cargo_toml: Some(b"synthetic original".to_vec()),
                cargo_lock: None,
            })
            .unwrap();
        pending
            .store_synthetic_postimage(b"synthetic modified")
            .unwrap();
        // Model a pre-binding interruption, not a successful or failed cgroup admission.
        std::process::exit(77);
    }
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("tucupi");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    tucupi::recovery_state::provision_state_directory(&parent, std::ffi::OsStr::new("recovery"))
        .unwrap();
    let child = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "recovery_status_preserves_fixture_plan_without_direct_exit",
        ])
        .env_clear()
        .env("HOME", root.path())
        .env("TMPDIR", root.path())
        .env(SUPERVISOR, root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(child.code(), Some(77));
    let state = parent.join("recovery");
    let records: Vec<_> = [
        "pending-intent",
        "pending-snapshot",
        "pending-fixture-postimage",
    ]
    .into_iter()
    .map(|name| (name, std::fs::read(state.join(name)).unwrap()))
    .collect();
    assert!(!state.join("pending-exit").exists());
    for (locale, pending, snapshot, blocked) in [
        (
            "en_US.UTF-8",
            "Local pending intent observed",
            "Local snapshot envelope verified",
            "BLOCKED",
        ),
        (
            "pt_BR.UTF-8",
            "Intenção local pendente observada",
            "Envelope do snapshot local verificado",
            "BLOQUEADA",
        ),
    ] {
        Command::cargo_bin("tucupi")
            .unwrap()
            .args(["recovery", "status"])
            .env_clear()
            .env("HOME", root.path())
            .env("XDG_STATE_HOME", root.path())
            .env("LC_ALL", locale)
            .assert()
            .success()
            .stdout(predicate::str::contains(pending))
            .stdout(predicate::str::contains(snapshot))
            .stdout(predicate::str::contains(blocked));
    }
    for (name, bytes) in records {
        assert_eq!(std::fs::read(state.join(name)).unwrap(), bytes);
    }
    assert!(!state.join("pending-exit").exists());
    assert!(tucupi::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).is_err());
    let inspection = tucupi::same_user_supervisor::inspect_recovery(&state);
    assert_eq!(
        inspection.descendant_cleanup,
        tucupi::same_user_supervisor::RecoveryOutcome::Unknown
    );
    assert_eq!(
        inspection.rollback,
        tucupi::same_user_supervisor::RecoveryOutcome::Unknown
    );
}

#[cfg(target_os = "linux")]
#[test]
fn interrupted_supervisor_before_locator_remains_pending_on_reopen() {
    use std::io::{Read, Write};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::process::{Command as Process, Stdio};
    const SUPERVISOR: &str = "TUCUPI_PRE_LOCATOR_SUPERVISOR";
    const ATTEMPT: &str = "0123456789abcdef0123456789abcdef";
    if let Some(root) = std::env::var_os(SUPERVISOR) {
        let root = std::path::Path::new(&root);
        let state = root.join("tucupi/recovery");
        let pending = tucupi::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).unwrap();
        pending.store_synthetic_snapshot(b"synthetic only").unwrap();
        // This fixture exits on EOF when the supervisor process closes its pipe.
        let _child = Process::new("/bin/sh")
            .args(["-c", "IFS= read -r line; exit 0"])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::fs::write(root.join("child-created"), b"yes").unwrap();
        // Simulate interruption before bind_child and before any locator exists.
        std::process::exit(77);
    }
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("tucupi");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    tucupi::recovery_state::provision_state_directory(&parent, std::ffi::OsStr::new("recovery"))
        .unwrap();
    let status = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "interrupted_supervisor_before_locator_remains_pending_on_reopen",
        ])
        .env_clear()
        .env("HOME", root.path())
        .env("TMPDIR", root.path())
        .env(SUPERVISOR, root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(77));
    assert_eq!(
        std::fs::read(root.path().join("child-created")).unwrap(),
        b"yes"
    );
    let state = parent.join("recovery");
    let intent = std::fs::read(state.join("pending-intent")).unwrap();
    let snapshot = std::fs::read(state.join("pending-snapshot")).unwrap();
    assert!(!state.join("pending-child").exists());
    assert!(!state.join("pending-exit").exists());
    for (locale, pending, blocked) in [
        ("en_US.UTF-8", "Local pending intent observed", "BLOCKED"),
        (
            "pt_BR.UTF-8",
            "Intenção local pendente observada",
            "BLOQUEADA",
        ),
    ] {
        Command::cargo_bin("tucupi")
            .unwrap()
            .args(["recovery", "status"])
            .env_clear()
            .env("HOME", root.path())
            .env("XDG_STATE_HOME", root.path())
            .env("LC_ALL", locale)
            .assert()
            .success()
            .stdout(predicate::str::contains(pending))
            .stdout(predicate::str::contains(blocked));
    }
    assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
    assert_eq!(
        std::fs::read(state.join("pending-snapshot")).unwrap(),
        snapshot
    );
    assert!(tucupi::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).is_err());
    let inspection = tucupi::same_user_supervisor::inspect_recovery(&state);
    assert_eq!(
        inspection.descendant_cleanup,
        tucupi::same_user_supervisor::RecoveryOutcome::Unknown
    );
    assert_eq!(
        inspection.rollback,
        tucupi::same_user_supervisor::RecoveryOutcome::Unknown
    );

    // A separate fixture models PID reuse: the locator is data, not authority.
    let mut sentinel = Process::new("/bin/sh")
        .args(["-c", "IFS= read -r line; printf alive"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut locator = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(state.join("pending-child"))
        .unwrap();
    write!(
        locator,
        "tucupi-recovery-child-v1\nattempt={ATTEMPT}\npid={}\n",
        sentinel.id()
    )
    .unwrap();
    drop(locator);
    let locator_before = std::fs::read(state.join("pending-child")).unwrap();
    Command::cargo_bin("tucupi")
        .unwrap()
        .args(["recovery", "status"])
        .env_clear()
        .env("HOME", root.path())
        .env("XDG_STATE_HOME", root.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains("BLOCKED"));
    assert_eq!(
        std::fs::read(state.join("pending-child")).unwrap(),
        locator_before
    );
    assert!(sentinel.try_wait().unwrap().is_none());
    sentinel.stdin.take().unwrap().write_all(b"go\n").unwrap();
    let mut output = String::new();
    sentinel
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert!(sentinel.wait().unwrap().success());
    assert_eq!(output, "alive");
    assert!(!state.join("pending-exit").exists());
    assert!(tucupi::same_user_supervisor::PendingAttempt::begin(&state, ATTEMPT).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn recovery_status_reopens_record_after_supervisor_exit() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command as Process, Stdio};
    use std::time::{Duration, Instant};
    const CHILD: &str = "TUCUPI_EXIT_REOPEN_SUPERVISOR";
    if let Some(root) = std::env::var_os(CHILD) {
        let code: i32 = std::env::var("TUCUPI_EXIT_REOPEN_CODE")
            .unwrap()
            .parse()
            .unwrap();
        let state = std::path::Path::new(&root).join("tucupi/recovery");
        let pending = tucupi::same_user_supervisor::PendingAttempt::begin(
            &state,
            "0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        pending.store_synthetic_snapshot(b"synthetic only").unwrap();
        let mut child = Process::new("/bin/sh")
            .args([
                "-c",
                "IFS= read -r line; exit \"$1\"",
                "fixture",
                &code.to_string(),
            ])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut observer = pending.bind_child(&mut child).unwrap();
        input.write_all(b"go\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(success) = observer.poll_and_record_exit().unwrap() {
                assert_eq!(success, code == 0);
                assert!(!observer.permits_operation());
                break;
            }
            assert!(Instant::now() < deadline, "fixture child did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        std::process::exit(77);
    }
    for (code, english, portuguese) in [
        (
            0,
            "successful exit recorded",
            "saída bem-sucedida registrada",
        ),
        (7, "failed exit recorded", "saída com falha registrada"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("tucupi");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        tucupi::recovery_state::provision_state_directory(
            &parent,
            std::ffi::OsStr::new("recovery"),
        )
        .unwrap();
        let status = Process::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery_status_reopens_record_after_supervisor_exit",
            ])
            .env_clear()
            .env("HOME", root.path())
            .env("TMPDIR", root.path())
            .env(CHILD, root.path())
            .env("TUCUPI_EXIT_REOPEN_CODE", code.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(77));
        let state = parent.join("recovery");
        let names = [
            "pending-intent",
            "pending-child",
            "pending-snapshot",
            "pending-exit",
        ];
        let before: Vec<_> = names
            .iter()
            .map(|name| std::fs::read(state.join(name)).unwrap())
            .collect();
        for (locale, expected, blocked) in [
            ("en_US.UTF-8", english, "BLOCKED"),
            ("pt_BR.UTF-8", portuguese, "BLOQUEADA"),
        ] {
            Command::cargo_bin("tucupi")
                .unwrap()
                .args(["recovery", "status"])
                .env_clear()
                .env("HOME", root.path())
                .env("XDG_STATE_HOME", root.path())
                .env("LC_ALL", locale)
                .assert()
                .success()
                .stdout(predicate::str::contains(expected))
                .stdout(predicate::str::contains(blocked));
        }
        for (name, bytes) in names.iter().zip(&before) {
            assert_eq!(&std::fs::read(state.join(name)).unwrap(), bytes);
        }
        let inspection = tucupi::same_user_supervisor::inspect_recovery(&state);
        assert_eq!(
            inspection.descendant_cleanup,
            tucupi::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert_eq!(
            inspection.rollback,
            tucupi::same_user_supervisor::RecoveryOutcome::Unknown
        );
        assert!(tucupi::same_user_supervisor::PendingAttempt::begin(
            &state,
            "0123456789abcdef0123456789abcdef"
        )
        .is_err());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn recovery_status_fails_closed_when_writer_holds_state_lock() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("tucupi");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    tucupi::recovery_state::provision_state_directory(&parent, std::ffi::OsStr::new("recovery"))
        .unwrap();
    let state = parent.join("recovery");
    tucupi::same_user_supervisor::PendingAttempt::begin(&state, "0123456789abcdef0123456789abcdef")
        .unwrap();
    let intent = std::fs::read(state.join("pending-intent")).unwrap();
    let lock = std::fs::File::open(&state).unwrap();
    // SAFETY: the test owns this directory and holds its live descriptor.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    Command::cargo_bin("tucupi")
        .unwrap()
        .args(["recovery", "status"])
        .env_clear()
        .env("HOME", root.path())
        .env("XDG_STATE_HOME", root.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Local record unavailable or invalid; state remains unknown",
        ))
        .stdout(predicate::str::contains("BLOCKED"));
    assert_eq!(std::fs::read(state.join("pending-intent")).unwrap(), intent);
    drop(lock);
    let inspection = tucupi::same_user_supervisor::inspect_recovery(&state);
    assert_eq!(
        inspection.local_evidence,
        tucupi::recovery_state::LocalRecoveryEvidence::PendingIntentObserved
    );
    assert_eq!(
        inspection.descendant_cleanup,
        tucupi::same_user_supervisor::RecoveryOutcome::Unknown
    );
    assert_eq!(
        inspection.rollback,
        tucupi::same_user_supervisor::RecoveryOutcome::Unknown
    );
}

#[cfg(target_os = "linux")]
#[test]
fn recovery_status_distinguishes_direct_exit_without_authorizing() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command as Process, Stdio};
    use std::time::{Duration, Instant};
    for (code, english, portuguese) in [
        (
            0,
            "successful exit recorded",
            "saída bem-sucedida registrada",
        ),
        (7, "failed exit recorded", "saída com falha registrada"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("tucupi");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        tucupi::recovery_state::provision_state_directory(
            &parent,
            std::ffi::OsStr::new("recovery"),
        )
        .unwrap();
        let state = parent.join("recovery");
        let pending = tucupi::same_user_supervisor::PendingAttempt::begin(
            &state,
            "0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let mut child = Process::new("/bin/sh")
            .args([
                "-c",
                "IFS= read -r line; exit \"$1\"",
                "fixture",
                &code.to_string(),
            ])
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut observed = pending.bind_child(&mut child).unwrap();
        for (locale, expected, blocked) in [
            ("en_US.UTF-8", "no exit record observed", "BLOCKED"),
            (
                "pt_BR.UTF-8",
                "nenhum registro de saída encontrado",
                "BLOQUEADA",
            ),
        ] {
            Command::cargo_bin("tucupi")
                .unwrap()
                .args(["recovery", "status"])
                .env_clear()
                .env("HOME", root.path())
                .env("XDG_STATE_HOME", root.path())
                .env("LC_ALL", locale)
                .assert()
                .success()
                .stdout(predicate::str::contains(expected))
                .stdout(predicate::str::contains(blocked));
        }
        assert!(!state.join("pending-exit").exists());
        input.write_all(b"go\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(success) = observed.poll_and_record_exit().unwrap() {
                assert_eq!(success, code == 0);
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let record = state.join("pending-exit");
        let before = std::fs::read(&record).unwrap();
        for (locale, expected, blocked) in [
            ("en_US.UTF-8", english, "BLOCKED"),
            ("pt_BR.UTF-8", portuguese, "BLOQUEADA"),
        ] {
            Command::cargo_bin("tucupi")
                .unwrap()
                .args(["recovery", "status"])
                .env_clear()
                .env("HOME", root.path())
                .env("XDG_STATE_HOME", root.path())
                .env("LC_ALL", locale)
                .assert()
                .success()
                .stdout(predicate::str::contains(expected))
                .stdout(predicate::str::contains(blocked));
            assert_eq!(std::fs::read(&record).unwrap(), before);
        }
        std::fs::write(&record, b"partial").unwrap();
        for (locale, expected) in [
            ("en_US.UTF-8", "result unavailable or invalid"),
            ("pt_BR.UTF-8", "resultado indisponível ou inválido"),
        ] {
            Command::cargo_bin("tucupi")
                .unwrap()
                .args(["recovery", "status"])
                .env_clear()
                .env("HOME", root.path())
                .env("XDG_STATE_HOME", root.path())
                .env("LC_ALL", locale)
                .assert()
                .success()
                .stdout(predicate::str::contains(expected));
            assert_eq!(std::fs::read(&record).unwrap(), b"partial");
        }
        assert!(!observed.permits_operation());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn recovery_status_reports_snapshot_integrity_without_authorizing_work() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("tucupi");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    tucupi::recovery_state::provision_state_directory(&parent, std::ffi::OsStr::new("recovery"))
        .unwrap();
    let state = parent.join("recovery");
    let pending = tucupi::same_user_supervisor::PendingAttempt::begin(
        &state,
        "0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    pending
        .store_synthetic_snapshot(b"synthetic test data")
        .unwrap();
    let path = state.join("pending-snapshot");
    let bytes = std::fs::read(&path).unwrap();
    for (locale, envelope, blocked) in [
        ("en_US.UTF-8", "Local snapshot envelope verified", "BLOCKED"),
        (
            "pt_BR.UTF-8",
            "Envelope do snapshot local verificado",
            "BLOQUEADA",
        ),
    ] {
        Command::cargo_bin("tucupi")
            .unwrap()
            .args(["recovery", "status"])
            .env_clear()
            .env("HOME", root.path())
            .env("XDG_STATE_HOME", root.path())
            .env("LC_ALL", locale)
            .assert()
            .success()
            .stdout(predicate::str::contains(envelope))
            .stdout(predicate::str::contains(blocked));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    let mut corrupt = bytes;
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&path, &corrupt).unwrap();
    for (locale, unavailable) in [
        ("en_US.UTF-8", "Local snapshot unavailable or invalid"),
        ("pt_BR.UTF-8", "Snapshot local indisponível ou inválido"),
    ] {
        Command::cargo_bin("tucupi")
            .unwrap()
            .args(["recovery", "status"])
            .env_clear()
            .env("HOME", root.path())
            .env("XDG_STATE_HOME", root.path())
            .env("LC_ALL", locale)
            .assert()
            .success()
            .stdout(predicate::str::contains(unavailable));
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    }
    assert!(tucupi::same_user_supervisor::PendingAttempt::begin(
        &state,
        "0123456789abcdef0123456789abcdef"
    )
    .is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn authority_executable_is_read_only_and_blocks_unknown_requests() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authority-state.json");
    let record = serde_json::json!({"version":1,"generation":vec![1;16],"state":{"Pending":{"attempt":vec![2;16]}}});
    let bytes = serde_json::to_vec(&record).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    for (locale, blocked) in [("en_US.UTF-8", "BLOCKED"), ("pt_BR.UTF-8", "BLOQUEADA")] {
        Command::cargo_bin("tucupi-authority")
            .unwrap()
            .args(["status"])
            .arg(dir.path())
            .env("LC_ALL", locale)
            .assert()
            .success()
            .stdout(predicate::str::contains(blocked));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    Command::cargo_bin("tucupi-authority")
        .unwrap()
        .arg("unlock")
        .arg(dir.path())
        .assert()
        .failure();
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[cfg(all(target_os = "linux", not(feature = "codex-fixture")))]
#[test]
fn authority_executable_rejects_fixture_mode_without_feature() {
    let dir = tempfile::tempdir().unwrap();
    for mode in ["fixture-status", "fixture-attempt"] {
        Command::cargo_bin("tucupi-authority")
            .unwrap()
            .arg(mode)
            .arg(dir.path())
            .assert()
            .failure();
    }
    Command::cargo_bin("tucupi-authority")
        .unwrap()
        .arg("fixture-user-attempt")
        .arg(dir.path())
        .arg(dir.path())
        .assert()
        .failure();
    assert!(!dir.path().join("authority-state.json").exists());
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
#[test]
fn authority_executable_runs_gated_fixture_once_and_keeps_recovery_blocked() {
    use tucupi::authority_journal_fixture::{self, Fault};
    use tucupi::authority_lifecycle_fixture::{Event, State};
    let missing = tempfile::tempdir().unwrap();
    Command::cargo_bin("tucupi-authority")
        .unwrap()
        .arg("fixture-attempt")
        .arg(missing.path())
        .assert()
        .failure();
    assert!(!missing.path().join("state.json").exists());
    let dir = tempfile::tempdir().unwrap();
    let initial = authority_journal_fixture::initialize(dir.path()).unwrap();
    authority_journal_fixture::publish(dir.path(), initial, Event::Provisioned, Fault::None)
        .unwrap();
    Command::cargo_bin("tucupi-authority")
        .unwrap()
        .arg("fixture-attempt")
        .arg(dir.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains("BLOCKED"));
    let recovered = authority_journal_fixture::load(dir.path()).unwrap();
    assert_eq!(
        recovered.state,
        State::RecoveryRequired {
            attempt: [1; 16],
            incarnation: Some([2; 16])
        }
    );
    assert_eq!(
        recovered.interrupted_phase,
        Some(authority_journal_fixture::InterruptedPhase::DirectChildExited { success: true })
    );
    assert!(!recovered.state.authorizes_real_work());
    Command::cargo_bin("tucupi-authority")
        .unwrap()
        .arg("fixture-attempt")
        .arg(dir.path())
        .assert()
        .failure();
    assert_eq!(
        authority_journal_fixture::load(dir.path()).unwrap(),
        recovered
    );
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
#[test]
fn same_user_fixture_journey_survives_restart_and_stays_blocked() {
    use std::os::unix::fs::PermissionsExt;
    use tucupi::authority_journal_fixture::{self, Fault};
    use tucupi::authority_lifecycle_fixture::{Event, State};
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    Command::cargo_bin("tucupi")
        .unwrap()
        .args(["recovery", "init"])
        .env_clear()
        .env("HOME", root.path())
        .env("XDG_STATE_HOME", root.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success();
    let recovery = root.path().join("tucupi/recovery");
    let journal = root.path().join("journal");
    std::fs::create_dir(&journal).unwrap();
    let initial = authority_journal_fixture::initialize(&journal).unwrap();
    authority_journal_fixture::publish(&journal, initial, Event::Provisioned, Fault::None).unwrap();
    Command::cargo_bin("tucupi-authority")
        .unwrap()
        .arg("fixture-user-attempt")
        .arg(&journal)
        .arg(&recovery)
        .env_clear()
        .env("HOME", root.path())
        .env("TMPDIR", root.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains("BLOCKED"));
    let intent = std::fs::read(recovery.join("pending-intent")).unwrap();
    let binding = std::fs::read(recovery.join("pending-attempt")).unwrap();
    let exit_record = std::fs::read(recovery.join("pending-exit")).unwrap();
    let state = authority_journal_fixture::load(&journal).unwrap();
    assert!(matches!(state.state, State::RecoveryRequired { .. }));
    assert!(!state.state.authorizes_real_work());
    Command::cargo_bin("tucupi")
        .unwrap()
        .args(["recovery", "status"])
        .env_clear()
        .env("HOME", root.path())
        .env("XDG_STATE_HOME", root.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Direct-child exit recorded locally",
        ))
        .stdout(predicate::str::contains(
            "descendant cleanup and rollback: unknown",
        ))
        .stdout(predicate::str::contains("BLOCKED"));
    Command::cargo_bin("tucupi-authority")
        .unwrap()
        .arg("fixture-user-attempt")
        .arg(&journal)
        .arg(&recovery)
        .env_clear()
        .env("HOME", root.path())
        .env("TMPDIR", root.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .failure();
    assert_eq!(
        std::fs::read(recovery.join("pending-intent")).unwrap(),
        intent
    );
    assert_eq!(
        std::fs::read(recovery.join("pending-attempt")).unwrap(),
        binding
    );
    assert_eq!(
        std::fs::read(recovery.join("pending-exit")).unwrap(),
        exit_record
    );
    assert_eq!(authority_journal_fixture::load(&journal).unwrap(), state);
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
#[test]
fn authority_executable_combines_record_and_synthetic_child_without_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authority-state.json");
    let record = serde_json::json!({"version":1,"generation":vec![1;16],"state":{"Pending":{"attempt":vec![2;16]}}});
    let bytes = serde_json::to_vec(&record).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    Command::cargo_bin("tucupi-authority")
        .unwrap()
        .arg("fixture-status")
        .arg(dir.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains("Synthetic diagnostic completed"))
        .stdout(predicate::str::contains("BLOCKED"));
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn recovery_status_is_localized_read_only_and_never_unlocks() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("state.json");
    std::fs::write(&marker, b"synthetic evidence").unwrap();
    for (locale, blocked, unknown, limitation) in [
        (
            "en_US.UTF-8",
            "BLOCKED",
            "unknown",
            "does not protect against malicious processes",
        ),
        (
            "pt_BR.UTF-8",
            "BLOQUEADA",
            "desconhecidos",
            "não protege contra processos maliciosos",
        ),
    ] {
        Command::cargo_bin("tucupi")
            .unwrap()
            .args(["recovery", "status"])
            .current_dir(root.path())
            .env("HOME", root.path())
            .env("XDG_STATE_HOME", root.path())
            .env("LC_ALL", locale)
            .assert()
            .success()
            .stdout(predicate::str::contains(blocked))
            .stdout(predicate::str::contains(unknown))
            .stdout(predicate::str::contains(limitation));
        assert_eq!(std::fs::read(&marker).unwrap(), b"synthetic evidence");
    }
    Command::cargo_bin("tucupi")
        .unwrap()
        .args(["recovery", "unlock"])
        .current_dir(root.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .failure()
        .stderr(predicate::str::contains("recovery status"));
    assert_eq!(std::fs::read(&marker).unwrap(), b"synthetic evidence");
}

#[cfg(target_os = "linux")]
#[test]
fn recovery_init_is_explicit_create_only_and_never_unblocks() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    Command::cargo_bin("tucupi")
        .unwrap()
        .args(["recovery", "init"])
        .env_clear()
        .env("HOME", root.path())
        .env("XDG_STATE_HOME", root.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains("remains BLOCKED"));
    let format = root.path().join("tucupi/recovery/format");
    let before = std::fs::read(&format).unwrap();
    Command::cargo_bin("tucupi")
        .unwrap()
        .args(["recovery", "init"])
        .env_clear()
        .env("HOME", root.path())
        .env("XDG_STATE_HOME", root.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .failure();
    assert_eq!(std::fs::read(format).unwrap(), before);
    Command::cargo_bin("tucupi")
        .unwrap()
        .args(["recovery", "status"])
        .env_clear()
        .env("HOME", root.path())
        .env("XDG_STATE_HOME", root.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains("does not mean the state is clean"))
        .stdout(predicate::str::contains("BLOCKED"));
}

#[cfg(target_os = "linux")]
#[test]
fn recovery_init_refuses_symlinked_parent_without_touching_target() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = root.path().join("unrelated");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("evidence"), b"keep").unwrap();
    symlink(&target, root.path().join("tucupi")).unwrap();
    Command::cargo_bin("tucupi")
        .unwrap()
        .args(["recovery", "init"])
        .env_clear()
        .env("HOME", root.path())
        .env("XDG_STATE_HOME", root.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .failure();
    assert_eq!(std::fs::read(target.join("evidence")).unwrap(), b"keep");
    assert!(!target.join("recovery").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn recovery_status_reports_synthetic_pending_record_without_clearing_it() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("tucupi");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    tucupi::recovery_state::provision_state_directory(&parent, std::ffi::OsStr::new("recovery"))
        .unwrap();
    let path = parent.join("recovery/pending-attempt");
    let id = "0123456789abcdef0123456789abcdef";
    let content = format!("tucupi-recovery-attempt-v1\nattempt={id}\nunit=tucupi-review-{id}.service\ninvocation={id}\nboot={id}\nmanager_epoch={id}\n");
    std::fs::write(&path, &content).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    Command::cargo_bin("tucupi")
        .unwrap()
        .args(["recovery", "status"])
        .env("XDG_STATE_HOME", root.path())
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Local pending attempt record observed",
        ))
        .stdout(predicate::str::contains("BLOCKED"));
    assert_eq!(std::fs::read_to_string(path).unwrap(), content);
}

#[cfg(unix)]
#[test]
fn invalid_config_blocks_normal_and_batch_before_any_manager_runs() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let marker = root.path().join("manager-invoked");
    for program in ["brew", "cargo", "npm", "pip3", "mise", "dart", "paru"] {
        let path = bin.join(program);
        std::fs::write(
            &path,
            format!("#!/bin/sh\nprintf invoked > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for (kind, locale, expected) in [
        (
            "invalid",
            "pt_BR.UTF-8",
            "Não foi possível ler a configuração",
        ),
        ("invalid", "en_US.UTF-8", "Could not read configuration"),
        ("unreadable", "en_US.UTF-8", "Could not read configuration"),
        ("dangling", "en_US.UTF-8", "Could not read configuration"),
    ] {
        let project = root.path().join(format!("{kind}-{locale}"));
        std::fs::create_dir(&project).unwrap();
        let config = project.join("tucupi.toml");
        match kind {
            "invalid" => std::fs::write(
                &config,
                "[security]\nblock_vulnerable = true\nreview_model = \"synthetic-secret\n",
            )
            .unwrap(),
            "unreadable" => std::fs::create_dir(&config).unwrap(),
            "dangling" => std::os::unix::fs::symlink("missing-target", &config).unwrap(),
            _ => unreachable!(),
        }
        for batch in [false, true] {
            let mut command = Command::cargo_bin("tucupi").unwrap();
            command
                .env("PATH", &bin)
                .env("HOME", root.path())
                .env("LC_ALL", locale);
            if batch {
                command.arg("--interactive");
            }
            command
                .arg(&project)
                .assert()
                .failure()
                .stderr(predicate::str::contains(expected))
                .stderr(predicate::str::contains("synthetic-secret").not());
            assert!(
                !marker.exists(),
                "package manager ran with invalid configuration"
            );
        }
    }
}

#[test]
fn test_help_flag() {
    let mut cmd = Command::cargo_bin("tucupi").unwrap();
    cmd.arg("--help")
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE:"))
        .stdout(predicate::str::contains("OPTIONS:"))
        .stdout(predicate::str::contains("CONFIG:"))
        .stdout(predicate::str::contains("set-nvd-key"));
}

#[test]
fn test_short_help_flag() {
    let mut cmd = Command::cargo_bin("tucupi").unwrap();
    cmd.arg("-h")
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE:"));
}

#[test]
fn help_uses_selected_language() {
    Command::cargo_bin("tucupi")
        .unwrap()
        .arg("--help")
        .env("LC_ALL", "pt_BR.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains("USO:"))
        .stdout(predicate::str::contains("OPÇÕES:"))
        .stdout(predicate::str::contains("Diretório do projeto"))
        .stdout(predicate::str::contains("USAGE:").not());
    Command::cargo_bin("tucupi")
        .unwrap()
        .arg("--help")
        .env("LC_ALL", "en_US.UTF-8")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE:"))
        .stdout(predicate::str::contains("Target project directory"))
        .stdout(predicate::str::contains("OPÇÕES:").not());
}

#[test]
fn test_version_flag() {
    let mut cmd = Command::cargo_bin("tucupi").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_short_version_flag() {
    let mut cmd = Command::cargo_bin("tucupi").unwrap();
    cmd.arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

fn command_with_store_path(store_path: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("tucupi").unwrap();
    cmd.env("TUCUPI_TEST_SECRET_STORE_FILE", store_path)
        .env("LC_ALL", "en_US.UTF-8");
    cmd
}

#[test]
fn config_messages_follow_locale_without_disclosing_input() {
    let dir = tempfile::tempdir().unwrap();
    let secret = "synthetic-value-not-a-key";
    for (locale, saved, configured, removed) in [
        (
            "pt_BR.UTF-8",
            "Chave da API NVD salva",
            "configurada (origem: chaveiro do sistema)",
            "Chave da API NVD removida",
        ),
        (
            "en_US.UTF-8",
            "NVD API key saved",
            "configured (source: system keychain)",
            "NVD API key removed",
        ),
    ] {
        let path = dir.path().join(locale);
        command_with_store_path(&path)
            .env("LC_ALL", locale)
            .args(["config", "set-nvd-key"])
            .write_stdin(format!("{secret}\n"))
            .assert()
            .success()
            .stdout(predicate::str::contains(saved))
            .stdout(predicate::str::contains(secret).not());
        command_with_store_path(&path)
            .env("LC_ALL", locale)
            .args(["config", "status"])
            .assert()
            .success()
            .stdout(predicate::str::contains(configured))
            .stdout(predicate::str::contains(secret).not());
        command_with_store_path(&path)
            .env("LC_ALL", locale)
            .args(["config", "remove-nvd-key"])
            .assert()
            .success()
            .stdout(predicate::str::contains(removed))
            .stdout(predicate::str::contains(secret).not());
        let empty = if locale.starts_with("pt") {
            "Nenhuma chave informada"
        } else {
            "No key provided"
        };
        command_with_store_path(&path)
            .env("LC_ALL", locale)
            .args(["config", "set-nvd-key"])
            .write_stdin("\n")
            .assert()
            .failure()
            .stderr(predicate::str::contains(empty));
    }
}

#[test]
fn test_config_set_status_and_remove_nvd_key_flow() {
    let test_key = "test-nvd-key-9876";
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path().join("secrets.json");

    command_with_store_path(&store_path)
        .args(["config", "set-nvd-key"])
        .write_stdin(format!("{}\n", test_key))
        .assert()
        .success()
        .stdout(predicate::str::contains("NVD API key saved"))
        .stdout(predicate::str::contains(test_key).not());

    command_with_store_path(&store_path)
        .args(["config", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "configured (source: system keychain)",
        ));

    command_with_store_path(&store_path)
        .args(["config", "remove-nvd-key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("NVD API key removed"));

    command_with_store_path(&store_path)
        .args(["config", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not configured"));
}

#[test]
fn test_config_set_nvd_key_rejects_empty_input() {
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path().join("secrets.json");

    command_with_store_path(&store_path)
        .args(["config", "set-nvd-key"])
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("No key provided"));
}

#[test]
fn test_config_status_reports_environment_fallback_without_value() {
    let env_key = "env-fallback-key-5544";
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path().join("missing.json");

    command_with_store_path(&store_path)
        .env("TUCUPI_NVD_API_KEY", env_key)
        .args(["config", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "configured (source: environment fallback)",
        ))
        .stdout(predicate::str::contains(env_key).not());
}

#[test]
fn test_config_unknown_command_fails() {
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path().join("secrets.json");

    command_with_store_path(&store_path)
        .args(["config", "frobnicate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown config command"));
}
