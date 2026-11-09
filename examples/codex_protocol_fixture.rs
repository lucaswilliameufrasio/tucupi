//! Test-only adapter for the experimental local broker fixture.
//! It performs no networking, authentication, or isolation.
use std::io::{self, Read, Write};

#[cfg(all(target_os = "linux", feature = "codex-fixture"))]
fn start_fixture_watchdog(
    directory: &str,
    fail: bool,
) -> Result<std::process::Child, &'static str> {
    let watcher_script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/codex_fixture_watchdog.py");
    let mut command = if fail {
        std::process::Command::new("/usr/bin/false")
    } else {
        let mut command = std::process::Command::new("/usr/bin/python3");
        command
            .arg(watcher_script)
            .arg(directory)
            .arg(std::process::id().to_string());
        command
    };
    let mut child = command
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| "synthetic watchdog unavailable")?;
    let ready = std::path::Path::new(directory).join("watchdog-ready");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while !ready.exists() {
        match child.try_wait() {
            Ok(Some(_)) => return Err("synthetic watchdog exited before readiness"),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("synthetic watchdog readiness unavailable");
            }
        }
    }
    Ok(child)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("impact-systemd-fixture") {
        let directory = std::env::args().nth(2).ok_or("missing fixture directory")?;
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/impact_synthetic_worker.py");
        let mut args = vec![script.to_string_lossy().into_owned(), directory.clone()];
        if std::env::args().nth(3).as_deref() == Some("gated") {
            args.push("gated".into());
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let _ = runtime.block_on(tucupi::impact::fixture_run_preview(
            std::path::Path::new("/usr/bin/python3"),
            &args,
            std::path::Path::new(&directory),
        ));
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("same-connection-rust-fixture") {
        let unit = std::env::args().nth(2).ok_or("missing unit")?;
        let runtime = std::env::args().nth(3).ok_or("missing runtime")?;
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let observed = executor.block_on(tucupi::manager_observation::observe_same_connection(
            &unit,
            std::path::Path::new(&runtime),
        ))?;
        println!("{} {}", observed.unit, observed.invocation);
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("manager-bus-candidate-fixture") {
        let directory = std::env::args().nth(2).ok_or("missing state directory")?;
        let runtime = std::env::args().nth(3).ok_or("missing manager runtime")?;
        let state =
            tucupi::recovery_state::open_private_state_directory(std::path::Path::new(&directory))?;
        let identity = tucupi::recovery_state::read_attempt_identity(&state)?;
        // Fixture input only. This file is not an authenticated identity source.
        let expected_owner =
            std::fs::read_to_string(std::path::Path::new(&directory).join("manager-owner"))?;
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        executor.block_on(async {
            let runtime = std::path::Path::new(&runtime);
            let before =
                tucupi::manager_observation::observe_manager_bus_candidate(runtime).await?;
            let unit =
                tucupi::manager_observation::observe_user_unit(&identity.unit, runtime).await?;
            let after = tucupi::manager_observation::observe_manager_bus_candidate(runtime).await?;
            if before != after
                || before.boot != identity.boot
                || before.bus_id != identity.manager_epoch
                || before.owner != expected_owner.trim()
                || unit.invocation != identity.invocation
            {
                return Err(std::io::Error::other("synthetic manager binding mismatch"));
            }
            Ok::<(), std::io::Error>(())
        })?;
        println!(
            "synthetic unit and bus candidate matched persisted fixture; recovery remains blocked"
        );
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("app-production-observation-fixture") {
        let project = std::env::args().nth(2).ok_or("missing project directory")?;
        let mut app = tucupi::app::App::new(std::path::PathBuf::from(project), false);
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        executor.block_on(app.load_config_sync())?;
        println!(
            "app-production-observation:{:?}",
            app.fixture_production_recovery_observation()
        );
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("inspect-persisted-fixture") {
        let state = std::env::args().nth(2).ok_or("missing state directory")?;
        let runtime = std::env::args().nth(3).ok_or("missing manager runtime")?;
        let executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let observation = executor.block_on(tucupi::recovery_state::inspect_persisted_attempt(
            std::path::Path::new(&state),
            std::path::Path::new(&runtime),
        ));
        println!("fixture-recovery-observation:{observation:?}");
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("observe-manager-fixture") {
        let directory = std::env::args().nth(2).ok_or("missing state directory")?;
        let runtime = std::env::args().nth(3).ok_or("missing manager runtime")?;
        let directory =
            tucupi::recovery_state::open_private_state_directory(std::path::Path::new(&directory))?;
        let identity = tucupi::recovery_state::read_attempt_identity(&directory)?;
        let runtime_executor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let observation =
            runtime_executor.block_on(tucupi::manager_observation::observe_user_unit(
                &identity.unit,
                std::path::Path::new(&runtime),
            ))?;
        if observation.unit != identity.unit
            || observation.invocation != identity.invocation
            || observation.active_state != "active"
        {
            return Err("synthetic observed identity mismatch".into());
        }
        println!("synthetic manager observation matched persisted unit and invocation; recovery remains blocked");
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("state-provision-fixture") {
        let parent = std::env::args().nth(2).ok_or("missing state parent")?;
        let name = std::env::args().nth(3).unwrap_or_else(|| "state".into());
        tucupi::recovery_state::provision_state_directory(
            std::path::Path::new(&parent),
            std::ffi::OsStr::new(&name),
        )?;
        println!("fixture-state-provisioned");
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("state-inspect-fixture") {
        let parent = std::env::args().nth(2).ok_or("missing state parent")?;
        tucupi::recovery_state::open_provisioned_state_directory(
            &std::path::Path::new(&parent).join("state"),
        )?;
        println!("fixture-state-format-valid-not-clean-proof");
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("batch-fixture-manager-failure") {
        let directory = std::env::args().nth(2).ok_or("missing state directory")?;
        let marker = tucupi::codex_supervision::FixtureRecoveryMarker::open(std::path::Path::new(
            &directory,
        ))?;
        let mut invoked = false;
        let result = tucupi::batch::fixture_guarded_batch_attempt(
            &marker,
            "0123456789abcdef0123456789abcdef",
            || {
                invoked = true;
                Err::<(), _>(std::io::Error::other("synthetic manager unavailable"))
            },
        );
        if result.is_ok() || !invoked || !marker.blocked()? {
            return Err("fixture batch failure was not retained".into());
        }
        println!("batch-fixture-failed-blocked");
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("recovery-marker-bind-unit") {
        let directory = std::env::args()
            .nth(2)
            .ok_or("missing fixture state directory")?;
        let unit = std::env::args().nth(3).ok_or("missing fixture unit")?;
        let invocation = std::env::args()
            .nth(4)
            .ok_or("missing fixture invocation")?;
        let marker = tucupi::codex_supervision::FixtureRecoveryMarker::open(std::path::Path::new(
            &directory,
        ))?;
        marker.bind_fixture_unit("0123456789abcdef0123456789abcdef", &unit, &invocation)?;
        println!("fixture-unit-observed");
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("app-fixture-recovery-check") {
        let directory = std::env::args().nth(2).ok_or("missing state directory")?;
        let app = tucupi::app::App::new_with_fixture_recovery(
            std::path::PathBuf::from(&directory),
            false,
            std::path::Path::new(&directory),
        );
        println!(
            "{}",
            if app.fixture_recovery_is_blocked() {
                "app-fixture-blocked"
            } else {
                "app-fixture-clear"
            }
        );
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("recovery-marker-arm" | "recovery-marker-arm-identity" | "recovery-marker-check")
    ) {
        let mode = std::env::args().nth(1).ok_or("missing mode")?;
        let directory = std::env::args()
            .nth(2)
            .ok_or("missing fixture state directory")?;
        let marker = tucupi::codex_supervision::FixtureRecoveryMarker::open(std::path::Path::new(
            &directory,
        ));
        if mode == "recovery-marker-arm" || mode == "recovery-marker-arm-identity" {
            if mode == "recovery-marker-arm-identity" {
                marker?.arm_with_identity("0123456789abcdef0123456789abcdef")?;
            } else {
                marker?.arm()?;
            }
            println!("fixture-marker-armed");
        } else {
            let blocked = marker.and_then(|value| value.blocked()).unwrap_or(true);
            println!(
                "{}",
                if blocked {
                    "fixture-recovery-blocked"
                } else {
                    "fixture-recovery-clear"
                }
            );
        }
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("descriptor-inheritance-probe") {
        let descriptor = std::env::args()
            .nth(2)
            .ok_or("missing fixture descriptor")?;
        let marker = std::env::args().nth(3).ok_or("missing fixture marker")?;
        let code = "import os,sys\ntry:\n p=os.readlink('/proc/self/fd/'+sys.argv[1])\nexcept FileNotFoundError:\n print('descriptor absent')\nelse:\n print('descriptor inherited' if p == sys.argv[2] else 'descriptor replaced')";
        let mut command = std::process::Command::new("/usr/bin/python3");
        command
            .arg("-c")
            .arg(code)
            .arg(descriptor)
            .arg(marker)
            .env_clear()
            .stdin(std::process::Stdio::piped());
        if std::env::args().nth(4).as_deref() == Some("sanitized") {
            tucupi::review::fixture_close_extra_descriptors_on_exec(&mut command);
        }
        let output = command.output()?;
        if !output.status.success() {
            return Err("synthetic descriptor probe failed".into());
        }
        print!("{}", std::str::from_utf8(&output.stdout)?);
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("observe-repopulation-fixture") {
        let group = std::env::args().nth(2).ok_or("missing group")?;
        let observer =
            tucupi::codex_supervision::CgroupObservation::open(std::path::Path::new(&group))?;
        let sequence = tucupi::codex_supervision::CgroupSequence::new(observer);
        // Synthetic response only: no provenance or ownership is implied.
        let body = b"data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"VERDICT: safe\\nREASON: synthetic\"}]}]}}\n\n";
        let pending =
            tucupi::review::parse_codex_review_response(body).ok_or("invalid synthetic review")?;
        let mut bound = pending.bind_cgroup(sequence)?;
        println!("observed-populated");
        io::stdout().flush()?;
        let mut signal = String::new();
        io::stdin().read_line(&mut signal)?;
        if signal.trim() != "empty"
            || bound.observe_cgroup()?
                != tucupi::codex_supervision::CgroupSequenceState::EmptyAfterPopulated
        {
            return Err("fixture group not empty".into());
        }
        println!("observed-empty");
        io::stdout().flush()?;
        signal.clear();
        io::stdin().read_line(&mut signal)?;
        if signal.trim() != "repopulated"
            || bound.observe_cgroup().is_ok()
            || bound.observe_cgroup().is_ok()
        {
            return Err("fixture repopulation not rejected".into());
        }
        println!("repopulation-rejected");
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("owned-spawn-fixture") {
        let directory = std::env::args().nth(2).ok_or("missing fixture directory")?;
        let codex_dir = std::env::args()
            .nth(3)
            .ok_or("missing fixture CLI directory")?;
        let script = std::env::args().nth(4).ok_or("missing fixture script")?;
        let broken_gate = std::env::args().nth(5).as_deref() == Some("broken-gate");
        let cancelled_gate = std::env::args().nth(5).as_deref() == Some("cancelled-gate");
        let collision_cancel = std::env::args().nth(5).as_deref() == Some("collision-cancel");
        let mode = std::env::args().nth(5);
        if mode.as_deref() == Some("recovery-guarded") {
            let state_directory = std::path::Path::new(&directory).join("recovery-state");
            let marker = tucupi::codex_supervision::FixtureRecoveryMarker::open(&state_directory)?;
            marker.arm()?;
        }
        let watchdog_enabled = matches!(
            mode.as_deref(),
            Some("watchdog" | "watchdog-pause" | "watchdog-fail" | "systemd-main-aux")
        );
        let membership = std::fs::read_to_string("/proc/self/cgroup")?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .ok_or("missing unified cgroup")?;
        let relative = std::path::Path::new(relative);
        if relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err("invalid fixture cgroup".into());
        }
        let group = std::path::Path::new("/sys/fs/cgroup")
            .join(relative)
            .join("tucupi-child-fixture");
        if collision_cancel {
            let gate = tucupi::review::FixtureStartGate::default();
            match tucupi::review::FixtureSupervisedChild::spawn_fixture_cancellable(
                std::path::Path::new(&directory),
                std::path::Path::new(&codex_dir),
                std::path::Path::new(&script),
                false,
                &gate,
            ) {
                Err("fixture cgroup already exists") => {}
                Ok(_) => return Err("colliding fixture was accepted".into()),
                Err(error) => return Err(error.into()),
            }
            gate.cancel()?;
            println!("collision rejected; second attempt cancellation requested");
            return Ok(());
        }
        if cancelled_gate {
            let gate = tucupi::review::FixtureStartGate::default();
            gate.cancel()?;
            match tucupi::review::FixtureSupervisedChild::spawn_fixture_cancellable(
                std::path::Path::new(&directory),
                std::path::Path::new(&codex_dir),
                std::path::Path::new(&script),
                false,
                &gate,
            ) {
                Err("fixture startup cancelled") => {}
                Ok(_) => return Err("cancelled fixture gate was accepted".into()),
                Err(error) => return Err(error.into()),
            }
            if group.exists()
                || std::path::Path::new(&directory)
                    .join("bridge-root-pid")
                    .exists()
            {
                return Err("cancelled fixture did not clean up or ran worker".into());
            }
            println!("cancelled fixture gate rejected; cgroup not created; worker not started");
            return Ok(());
        }
        if broken_gate {
            match tucupi::review::FixtureSupervisedChild::spawn_fixture(
                std::path::Path::new(&directory),
                std::path::Path::new(&codex_dir),
                std::path::Path::new(&script),
                true,
            ) {
                Err("fixture gate release failed") => {}
                Ok(_) => return Err("broken fixture gate was accepted".into()),
                Err(error) => return Err(error.into()),
            }
            let watcher = tucupi::codex_supervision::CgroupObservation::open(&group)?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while watcher.populated()? {
                if std::time::Instant::now() >= deadline {
                    return Err("broken gate fixture remained populated".into());
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            println!("broken fixture gate rejected; cgroup observed empty");
            return Ok(());
        }
        let mut watchdog = None;
        let gate = tucupi::review::FixtureStartGate::default();
        let result = tucupi::review::FixtureSupervisedChild::spawn_fixture_with_startup_check(
            std::path::Path::new(&directory),
            std::path::Path::new(&codex_dir),
            std::path::Path::new(&script),
            false,
            &gate,
            || {
                if watchdog_enabled {
                    watchdog = Some(start_fixture_watchdog(
                        &directory,
                        mode.as_deref() == Some("watchdog-fail"),
                    )?);
                    if mode.as_deref() == Some("systemd-main-aux") {
                        let pid = watchdog.as_ref().ok_or("watchdog unavailable")?.id();
                        let mut custodian = std::process::Command::new("/usr/bin/python3")
                            .arg(
                                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                                    .join("tests/codex_fixture_custodian.py"),
                            )
                            .arg(&directory)
                            .arg(std::process::id().to_string())
                            .arg(pid.to_string())
                            .arg("controller-child")
                            .env_clear()
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .spawn()
                            .map_err(|_| "custodian unavailable")?;
                        let deadline =
                            std::time::Instant::now() + std::time::Duration::from_secs(3);
                        while !std::path::Path::new(&directory)
                            .join("custodian-ready")
                            .exists()
                        {
                            if custodian
                                .try_wait()
                                .map_err(|_| "custodian unavailable")?
                                .is_some()
                            {
                                return Err("custodian exited before readiness");
                            }
                            if std::time::Instant::now() >= deadline {
                                let _ = custodian.kill();
                                let _ = custodian.wait();
                                return Err("custodian readiness timed out");
                            }
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                    }
                    if mode.as_deref() == Some("watchdog-pause") {
                        println!("watchdog-ready-before-release");
                        io::stdout()
                            .flush()
                            .map_err(|_| "fixture output unavailable")?;
                        let mut input = String::new();
                        io::stdin()
                            .read_line(&mut input)
                            .map_err(|_| "fixture input unavailable")?;
                        if input.trim() != "continue" {
                            return Err("fixture startup pause ended");
                        }
                    }
                    if watchdog
                        .as_mut()
                        .ok_or("synthetic watchdog unavailable")?
                        .try_wait()
                        .map_err(|_| "synthetic watchdog unavailable")?
                        .is_some()
                    {
                        return Err("synthetic watchdog died before release");
                    }
                }
                Ok(())
            },
        );
        let mut supervised = match result {
            Err("synthetic watchdog exited before readiness")
                if mode.as_deref() == Some("watchdog-fail") =>
            {
                let observation = tucupi::codex_supervision::CgroupObservation::open(&group)?;
                if observation.populated()?
                    || std::path::Path::new(&directory)
                        .join("bridge-root-pid")
                        .exists()
                {
                    return Err("watchdog failure left synthetic worker running".into());
                }
                println!("watchdog startup failed; synthetic cgroup empty; worker not started");
                return Ok(());
            }
            Err("synthetic watchdog died before release")
                if mode.as_deref() == Some("watchdog-pause") =>
            {
                let observation = tucupi::codex_supervision::CgroupObservation::open(&group)?;
                if observation.populated()?
                    || std::path::Path::new(&directory)
                        .join("bridge-root-pid")
                        .exists()
                {
                    return Err("watchdog death left synthetic worker running".into());
                }
                println!(
                    "watchdog died before release; synthetic cgroup empty; worker not started"
                );
                return Ok(());
            }
            Err(error) => return Err(error.into()),
            Ok(supervised) => supervised,
        };
        println!("rust-created-admitted-before-worker-exec");
        io::stdout().flush()?;
        if matches!(
            mode.as_deref(),
            Some("systemd-main-hold" | "systemd-main-aux")
        ) {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        let signal = if let Some(child) = watchdog.as_mut() {
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut input = String::new();
                let result = io::stdin().read_line(&mut input).map(|_| input);
                let _ = sender.send(result);
            });
            loop {
                match child.try_wait() {
                    Ok(None) => {}
                    _ => {
                        supervised.cancel_and_observe(std::time::Duration::from_secs(2))?;
                        println!("watchdog failure after release; synthetic group stopped; review rejected");
                        return Err("synthetic watchdog failed after release".into());
                    }
                }
                match receiver.try_recv() {
                    Ok(result) => break result?,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        std::thread::sleep(std::time::Duration::from_millis(10))
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Err("fixture input unavailable".into())
                    }
                }
            }
        } else {
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            input
        };
        if signal.trim() != "cancel-fixture" {
            return Err("fixture cancellation required".into());
        }
        supervised.cancel_and_observe(std::time::Duration::from_secs(2))?;
        println!("rust-cancelled-empty-pending");
        return Ok(());
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if std::env::args().nth(1).as_deref() == Some("owned-fixture-attempt") {
        let membership = std::fs::read_to_string("/proc/self/cgroup")?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::/"))
            .ok_or("missing unified cgroup")?;
        let relative = std::path::Path::new(relative);
        if relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err("invalid cgroup".into());
        }
        let group = std::path::Path::new("/sys/fs/cgroup")
            .join(relative)
            .join("tucupi-child-fixture");
        // Exclusive creation: an existing group is never reused by this fixture.
        if let Err(error) = std::fs::create_dir(&group) {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                return Err("fixture cgroup already exists".into());
            }
            return Err(error.into());
        }
        let observation = tucupi::codex_supervision::CgroupObservation::open(&group)?;
        println!("fixture-created");
        io::stdout().flush()?;
        let mut signal = String::new();
        io::stdin().read_line(&mut signal)?;
        if signal.trim() != "bind" {
            return Err("fixture binding required".into());
        }
        let sequence = tucupi::codex_supervision::CgroupSequence::new(observation);
        let mut attempt = tucupi::review::FixtureReviewAttempt::start(sequence)?;
        println!("fixture-bound");
        io::stdout().flush()?;
        signal.clear();
        io::stdin().read_line(&mut signal)?;
        if signal.trim() != "cancel-fixture" {
            return Err("fixture cancellation required".into());
        }
        attempt.cancel()?;
        let late = b"data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"VERDICT: safe\\nREASON: synthetic\"}]}]}}\n\n";
        if tucupi::review::parse_codex_review_response(late).is_none()
            || attempt.receive(late).is_ok()
        {
            return Err("late fixture response was not rejected".into());
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match attempt.observe() {
                Ok(tucupi::codex_supervision::CgroupSequenceState::EmptyAfterPopulated) => {
                    println!("cancelled-empty-pending");
                    return Ok(());
                }
                Ok(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                _ => return Err("fixture cancellation not observed".into()),
            }
        }
    }
    #[cfg(all(target_os = "linux", feature = "codex-fixture"))]
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("attempt-cgroup-watch" | "attempt-cgroup-drop")
    ) {
        let drop_on_invalid = std::env::args().nth(1).as_deref() == Some("attempt-cgroup-drop");
        let group = std::env::args().nth(2).ok_or("missing group")?;
        let response = std::env::args().nth(3).ok_or("missing response")?;
        let observation =
            tucupi::codex_supervision::CgroupObservation::open(std::path::Path::new(&group))?;
        let sequence = tucupi::codex_supervision::CgroupSequence::new(observation);
        let mut attempt = tucupi::review::FixtureReviewAttempt::start(sequence)?;
        let response_valid = if response == "-" {
            None
        } else {
            let mut body = Vec::new();
            std::fs::File::open(response)?
                .take(128_001)
                .read_to_end(&mut body)?;
            Some(attempt.receive(&body).is_ok())
        };
        println!(
            "{}",
            match response_valid {
                None => "ready-no-response",
                Some(true) => "ready-valid",
                Some(false) => "ready-invalid",
            }
        );
        io::stdout().flush()?;
        if drop_on_invalid && response_valid == Some(false) {
            drop(attempt);
            return Err("invalid fixture response".into());
        }
        let mut signal = String::new();
        io::stdin().read_line(&mut signal)?;
        if signal.trim() != "cancel-fixture" {
            return Err("fixture cancellation required".into());
        }
        attempt.cancel()?;
        if response_valid.is_none() {
            let late = b"data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"VERDICT: safe\\nREASON: synthetic\"}]}]}}\n\n";
            if tucupi::review::parse_codex_review_response(late).is_none() {
                return Err("invalid synthetic late response".into());
            }
            if attempt.receive(late).is_ok() {
                return Err("late fixture response accepted".into());
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match attempt.observe() {
                Ok(tucupi::codex_supervision::CgroupSequenceState::EmptyAfterPopulated) => {
                    println!("cancelled-empty-pending");
                    return Ok(());
                }
                Ok(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                _ => return Err("fixture cancellation not observed".into()),
            }
        }
    }
    #[cfg(target_os = "linux")]
    if std::env::args().nth(1).as_deref() == Some("review-cgroup-watch") {
        let group = std::env::args().nth(2).ok_or("missing group")?;
        let response = std::env::args().nth(3).ok_or("missing response")?;
        let mut body = Vec::new();
        std::fs::File::open(response)?
            .take(128_001)
            .read_to_end(&mut body)?;
        let pending = tucupi::review::parse_codex_review_response(&body).ok_or("invalid review")?;
        let observation =
            tucupi::codex_supervision::CgroupObservation::open(std::path::Path::new(&group))?;
        let sequence = tucupi::codex_supervision::CgroupSequence::new(observation);
        let mut bound = pending.bind_cgroup(sequence)?;
        println!("populated");
        io::stdout().flush()?;
        let mut signal = String::new();
        io::stdin().read_line(&mut signal)?;
        #[cfg(feature = "codex-fixture")]
        if signal.trim() == "cancel-fixture" {
            bound.cancel_fixture()?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match bound.observe_cgroup() {
                    Ok(tucupi::codex_supervision::CgroupSequenceState::EmptyAfterPopulated) => {
                        println!("cancelled-empty-pending");
                        return Ok(());
                    }
                    Ok(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    _ => return Err("fixture cancellation not observed".into()),
                }
            }
        }
        match bound.observe_cgroup() {
            Ok(tucupi::codex_supervision::CgroupSequenceState::EmptyAfterPopulated) => {
                println!("empty-pending")
            }
            Ok(_) => println!("populated"),
            Err(_) => println!("unavailable"),
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if std::env::args().nth(1).as_deref() == Some("cgroup-watch") {
        let group = std::env::args().nth(2).ok_or("missing group")?;
        let observation =
            tucupi::codex_supervision::CgroupObservation::open(std::path::Path::new(&group))?;
        let mut sequence = tucupi::codex_supervision::CgroupSequence::new(observation);
        if sequence.observe()? != tucupi::codex_supervision::CgroupSequenceState::Populated {
            return Err("group was not populated".into());
        }
        println!("populated");
        io::stdout().flush()?;
        let mut signal = String::new();
        io::stdin().read_line(&mut signal)?;
        match sequence.observe() {
            Ok(tucupi::codex_supervision::CgroupSequenceState::EmptyAfterPopulated) => {
                println!("empty")
            }
            Ok(_) => println!("populated"),
            Err(_) => println!("unavailable"),
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if std::env::args().nth(1).as_deref() == Some("cgroup-events") {
        let group = std::env::args().nth(2).ok_or("missing group")?;
        let observation =
            tucupi::codex_supervision::CgroupObservation::open(std::path::Path::new(&group))?;
        let mut sequence = tucupi::codex_supervision::CgroupSequence::new(observation);
        let populated =
            sequence.observe()? == tucupi::codex_supervision::CgroupSequenceState::Populated;
        println!("{}", if populated { "populated" } else { "empty" });
        return Ok(());
    }
    let mut bytes = Vec::new();
    io::stdin().lock().take(128_001).read_to_end(&mut bytes)?;
    let mode = std::env::args().nth(1).ok_or("missing mode")?;
    let output = match mode.as_str() {
        "request" => tucupi::codex_protocol::prepare_request(&bytes).ok_or("invalid request")?,
        "response" if tucupi::codex_protocol::validate_response(&bytes) => bytes,
        "response" => return Err("invalid response".into()),
        _ => return Err("invalid mode".into()),
    };
    io::stdout().lock().write_all(&output)?;
    Ok(())
}
