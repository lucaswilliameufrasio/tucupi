//! Experimental diagnostic entry point, not an independent authority daemon.
//! It never authorizes, provisions, starts production work, or clears state.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use tucupi::authority_core::AuthorityCore;

    let args: Vec<_> = std::env::args_os().collect();
    #[cfg(feature = "codex-fixture")]
    if args.len() == 2 && args[1] == "--synthetic-child" {
        use std::io::Read;
        let mut gate = [0];
        std::io::stdin().read_exact(&mut gate)?;
        if gate != *b"G" {
            return Err(std::io::Error::other("invalid synthetic gate").into());
        }
        return Ok(());
    }
    #[cfg(feature = "codex-fixture")]
    if args.len() == 4 && args[1] == "fixture-user-attempt" {
        synthetic_user_attempt(
            std::path::Path::new(&args[2]),
            std::path::Path::new(&args[3]),
        )?;
        println!("{}", tucupi::i18n::t("authority_cli_fixture_blocked"));
        return Ok(());
    }
    if args.len() != 3
        || (args[1] != "status" && args[1] != "fixture-status" && args[1] != "fixture-attempt")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            tucupi::i18n::t("authority_cli_usage"),
        )
        .into());
    }
    #[cfg(not(feature = "codex-fixture"))]
    if args[1] == "fixture-status" || args[1] == "fixture-attempt" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            tucupi::i18n::t("authority_cli_usage"),
        )
        .into());
    }
    // The final path component cannot be a symlink. Ancestor provenance and
    // directory identity are not authenticated, so no result can authorize.
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&args[2])?;
    if args[1] == "status" {
        let observation = AuthorityCore::new(directory).inspect(None);
        assert!(!observation.permits_operation());
        println!("{}", tucupi::i18n::t("authority_cli_blocked"));
        return Ok(());
    }
    #[cfg(feature = "codex-fixture")]
    {
        if args[1] == "fixture-attempt" {
            synthetic_attempt(std::path::Path::new(&args[2]))?;
        } else {
            synthetic_check(&directory)?;
        }
        println!("{}", tucupi::i18n::t("authority_cli_fixture_blocked"));
    }
    Ok(())
}

/// Fixture only; the caller must supply disposable directories. The child,
/// unit identity and records are synthetic and do not represent a provider.
#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
fn synthetic_user_attempt(
    journal: &std::path::Path,
    recovery: &std::path::Path,
) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    use tucupi::authority_lifecycle_fixture::{RecordedPhase, State};
    use tucupi::authority_service_fixture::start_synthetic_with_recovery;
    use tucupi::authority_transport_fixture::SyntheticServer;
    let directory = tucupi::recovery_state::open_provisioned_state_directory(recovery)?;
    let child = start_synthetic_with_recovery(&directory, journal, [1; 16], [2; 16], || {
        Command::new(std::env::current_exe()?)
            .arg("--synthetic-child")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    })?;
    if !child.wait()?.success() {
        return Err(std::io::Error::other("synthetic child failed"));
    }
    let server = SyntheticServer::open(journal)?;
    let diagnostic = server.diagnostic()?;
    let snapshot = tucupi::authority_journal_fixture::load(journal)?;
    if diagnostic.phase != RecordedPhase::DirectChildExitRecorded
        || diagnostic.recorded_direct_child_success != Some(true)
        || diagnostic.descendant_cleanup_verified
        || diagnostic.rollback_verified
        || !matches!(snapshot.state, State::RecoveryRequired { .. })
        || snapshot.state.authorizes_real_work()
    {
        return Err(std::io::Error::other(
            "synthetic recovery remains unverified",
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
fn synthetic_attempt(directory: &std::path::Path) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    use tucupi::authority_journal_fixture::Fault;
    use tucupi::authority_lifecycle_fixture::{RecordedPhase, State};
    use tucupi::authority_service_fixture::start_synthetic_attempt;
    use tucupi::authority_transport_fixture::SyntheticServer;

    // IDs are fixed fixture inputs, not unique identifiers or ownership proof.
    // Existing, explicitly initialized fixture state is required; no automatic
    // provisioning or real workload is performed.
    let child = start_synthetic_attempt(
        directory,
        [1; 16],
        [2; 16],
        Fault::None,
        Fault::None,
        || {
            Command::new(std::env::current_exe()?)
                .arg("--synthetic-child")
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        },
    )?;
    if !child.wait()?.success() {
        return Err(std::io::Error::other("synthetic child failed"));
    }
    let server = SyntheticServer::open(directory)?;
    let diagnostic = server.diagnostic()?;
    if diagnostic.phase != RecordedPhase::DirectChildExitRecorded
        || diagnostic.recorded_direct_child_success != Some(true)
        || diagnostic.descendant_cleanup_verified
        || diagnostic.rollback_verified
    {
        return Err(std::io::Error::other(
            "synthetic recovery observation unavailable",
        ));
    }
    let persisted = tucupi::authority_journal_fixture::load(directory)?;
    if !matches!(persisted.state, State::RecoveryRequired { .. })
        || persisted.state.authorizes_real_work()
    {
        return Err(std::io::Error::other("synthetic recovery not blocked"));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
fn synthetic_check(directory: &std::fs::File) -> std::io::Result<()> {
    use std::io::Write;
    use std::process::{Child, Command, Stdio};
    use tucupi::authority_supervision::{
        DirectChildObservation, DirectChildObserver, RecoveryObservation,
    };

    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if self.0.kill().is_ok() {
                let _ = self.0.wait();
            }
        }
    }
    let mut child = OwnedChild(
        Command::new(std::env::current_exe()?)
            .arg("--synthetic-child")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let observer = DirectChildObserver::from_child(&child.0)?;
    let before = RecoveryObservation::inspect(directory, Some(&observer));
    if before.permits_operation()
        || before.direct_child != DirectChildObservation::NotExitedObserved
    {
        return Err(std::io::Error::other(
            "synthetic process observation unavailable",
        ));
    }
    child
        .0
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("synthetic gate unavailable"))?
        .write_all(b"G")?;
    if !child.0.wait()?.success() {
        return Err(std::io::Error::other("synthetic child failed"));
    }
    let after = RecoveryObservation::inspect(directory, Some(&observer));
    if after.permits_operation()
        || after.direct_child != DirectChildObservation::ExitObserved
        || after.record != before.record
    {
        return Err(std::io::Error::other(
            "synthetic observation changed or remained unavailable",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err(std::io::Error::other(tucupi::i18n::t("authority_cli_unsupported")).into())
}
