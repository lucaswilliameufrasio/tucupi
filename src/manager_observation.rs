//! Read-only systemd observations. They do not establish ownership, manager
//! generation, isolation, or cleanup and never authorize recovery.
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
#[cfg(test)]
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Component, Path};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[derive(Debug, PartialEq, Eq)]
pub struct UnitObservation {
    pub unit: String,
    pub invocation: String,
    pub active_state: String,
    pub control_group: String,
}

#[cfg(test)]
fn pin_manager_process(pid: u32, uid: u32, expected_uid: u32) -> io::Result<OwnedFd> {
    if uid != expected_uid || pid <= 1 || pid > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid manager credentials",
        ));
    }
    // SAFETY: pidfd_open receives scalar arguments and returns a new owned fd.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful pidfd_open returns a fresh file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

fn manager_is_alive(pidfd: BorrowedFd<'_>) -> io::Result<bool> {
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: pollfd points to one initialized pollfd for the duration of poll.
    let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result == 0)
}

fn validate_manager_descriptor(
    fd: Option<BorrowedFd<'_>>,
    pid: u32,
    uid: u32,
    expected_uid: u32,
) -> io::Result<()> {
    if uid != expected_uid || pid <= 1 || pid > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid manager credentials",
        ));
    }
    let fd = fd.ok_or_else(|| io::Error::other("manager process descriptor missing"))?;
    let target = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
    if target != Path::new("anon_inode:[pidfd]") {
        return Err(io::Error::other("invalid manager process descriptor"));
    }
    use std::io::Read;
    let mut info = String::new();
    std::fs::File::open(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))?
        .take(4097)
        .read_to_string(&mut info)?;
    if info.len() > 4096 {
        return Err(io::Error::other("invalid manager descriptor info"));
    }
    let pids: Vec<_> = info
        .lines()
        .filter_map(|line| line.strip_prefix("Pid:\t"))
        .collect();
    if pids.len() != 1 || pids[0].parse::<u32>().ok() != Some(pid) || !manager_is_alive(fd)? {
        return Err(io::Error::other("manager process identity unavailable"));
    }
    Ok(())
}

/// Diagnostic observation over one D-Bus connection. It does not establish
/// authority, ownership, or cleanup and must never authorize recovery.
pub async fn observe_same_connection(unit: &str, runtime: &Path) -> io::Result<UnitObservation> {
    if !valid_unit(unit) || !runtime.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid manager request",
        ));
    }
    let address = format!("unix:path={}/bus", runtime.display());
    let work = async {
        let connection = zbus::connection::Builder::address(address.as_str())?
            .build()
            .await?;
        let credentials = connection
            .peer_creds()
            .await
            .map_err(|error| zbus::Error::InputOutput(error.into()))?;
        // SAFETY: geteuid has no arguments and no side effects.
        if credentials.unix_user_id() != Some(unsafe { libc::geteuid() }) {
            return Err(zbus::Error::Failure("unexpected bus peer".into()));
        }
        let daemon = zbus::fdo::DBusProxy::new(&connection).await?;
        let bus_id = daemon.get_id().await?.to_string();
        let owner = daemon
            .get_name_owner("org.freedesktop.systemd1".try_into()?)
            .await?;
        let manager_uid = daemon
            .get_connection_unix_user(owner.as_str().try_into()?)
            .await?;
        let manager_pid = daemon
            .get_connection_unix_process_id(owner.as_str().try_into()?)
            .await?;
        let manager_credentials = daemon
            .get_connection_credentials(owner.as_str().try_into()?)
            .await?;
        // SAFETY: geteuid has no arguments and no side effects.
        let expected_uid = unsafe { libc::geteuid() };
        if manager_credentials.unix_user_id() != Some(manager_uid)
            || manager_credentials.process_id() != Some(manager_pid)
        {
            return Err(zbus::Error::Failure("manager credentials changed".into()));
        }
        let pidfd = manager_credentials.process_fd().map(|fd| fd.as_fd());
        validate_manager_descriptor(pidfd, manager_pid, manager_uid, expected_uid)
            .map_err(|error| zbus::Error::InputOutput(error.into()))?;
        let manager = zbus::Proxy::new(
            &connection,
            owner.as_str(),
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
        )
        .await?;
        let path: zbus::zvariant::OwnedObjectPath = manager.call("GetUnit", &(unit,)).await?;
        let unit_proxy = zbus::Proxy::new(
            &connection,
            owner.as_str(),
            path.as_str(),
            "org.freedesktop.systemd1.Unit",
        )
        .await?;
        let observed: String = unit_proxy.get_property("Id").await?;
        let invocation: Vec<u8> = unit_proxy.get_property("InvocationID").await?;
        let active_state: String = unit_proxy.get_property("ActiveState").await?;
        // ControlGroup belongs to a type-specific interface, not Unit. This
        // diagnostic does not observe or assert cgroup membership.
        let control_group = String::new();
        let second_owner = daemon
            .get_name_owner("org.freedesktop.systemd1".try_into()?)
            .await?;
        let second_bus_id = daemon.get_id().await?.to_string();
        let second_uid = daemon
            .get_connection_unix_user(owner.as_str().try_into()?)
            .await?;
        let second_pid = daemon
            .get_connection_unix_process_id(owner.as_str().try_into()?)
            .await?;
        if observed != unit
            || invocation.len() != 16
            || owner != second_owner
            || bus_id != second_bus_id
            || manager_uid != second_uid
            || manager_pid != second_pid
            || validate_manager_descriptor(pidfd, manager_pid, manager_uid, expected_uid).is_err()
        {
            return Err(zbus::Error::Failure("manager observation changed".into()));
        }
        let invocation = invocation
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok::<UnitObservation, zbus::Error>(UnitObservation {
            unit: observed,
            invocation,
            active_state,
            control_group,
        })
    };
    tokio::time::timeout(Duration::from_secs(5), work)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "manager observation timed out"))?
        .map_err(|_| io::Error::other("manager observation unavailable"))
}

/// A candidate only: bus metadata is not authenticated manager identity and
/// systemctl may use a different connection. Never use this to unlock work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerBusCandidate {
    pub boot: String,
    pub bus_id: String,
    pub owner: String,
}

fn parse_bus_string(bytes: &[u8]) -> io::Result<&str> {
    if bytes.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid bus response",
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid bus response"))?;
    let value = text
        .strip_prefix("s \"")
        .and_then(|value| value.strip_suffix("\"\n"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid bus response"))?;
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b'"' || byte == b'\\')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid bus response",
        ));
    }
    Ok(value)
}

async fn bus_string(runtime: &Path, method: &str, argument: Option<&str>) -> io::Result<String> {
    let address = format!("--address=unix:path={}/bus", runtime.display());
    let mut command = tokio::process::Command::new("/usr/bin/busctl");
    command.args([
        address.as_str(),
        "--no-pager",
        "call",
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        method,
    ]);
    if let Some(value) = argument {
        command.args(["s", value]);
    }
    command
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("bus output unavailable"))?;
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        stdout.take(257).read_to_end(&mut bytes).await?;
        if !child.wait().await?.success() {
            return Err(io::Error::other("bus unavailable"));
        }
        Ok(parse_bus_string(&bytes)?.to_owned())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "bus observation timed out"))?
}

/// Observe boot ID, user-bus ID and the manager's unique bus owner, while
/// checking the runtime directory and socket before/after. This is diagnostic
/// only; it does not authenticate the bus or bind a separate systemctl query.
pub async fn observe_manager_bus_candidate(runtime: &Path) -> io::Result<ManagerBusCandidate> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    // SAFETY: geteuid has no arguments and no side effects.
    let uid = unsafe { libc::geteuid() };
    if runtime != Path::new(&format!("/run/user/{uid}")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid manager runtime",
        ));
    }
    let directory = std::fs::symlink_metadata(runtime)?;
    let socket = std::fs::symlink_metadata(runtime.join("bus"))?;
    if !directory.is_dir()
        || directory.uid() != uid
        || directory.mode() & 0o077 != 0
        || !socket.file_type().is_socket()
        || socket.uid() != uid
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted user bus path",
        ));
    }
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let bus_id = bus_string(runtime, "GetId", None).await?;
    let owner = bus_string(runtime, "GetNameOwner", Some("org.freedesktop.systemd1")).await?;
    let hex = |value: &str| {
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    let Some((left, right)) = owner
        .strip_prefix(':')
        .and_then(|value| value.split_once('.'))
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid manager owner",
        ));
    };
    if !hex(&boot)
        || !hex(&bus_id)
        || left.is_empty()
        || right.is_empty()
        || !left.bytes().all(|b| b.is_ascii_digit())
        || !right.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid manager candidate",
        ));
    }
    let current_directory = std::fs::symlink_metadata(runtime)?;
    let current_socket = std::fs::symlink_metadata(runtime.join("bus"))?;
    if (directory.dev(), directory.ino()) != (current_directory.dev(), current_directory.ino())
        || (socket.dev(), socket.ino()) != (current_socket.dev(), current_socket.ino())
    {
        return Err(io::Error::other("user bus path changed"));
    }
    Ok(ManagerBusCandidate {
        boot,
        bus_id,
        owner,
    })
}

fn valid_unit(unit: &str) -> bool {
    let Some(id) = unit
        .strip_prefix("tucupi-review-")
        .and_then(|s| s.strip_suffix(".service"))
    else {
        return false;
    };
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse(unit: &str, bytes: &[u8]) -> io::Result<UnitObservation> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid manager observation");
    if !valid_unit(unit) || bytes.len() > 8192 {
        return Err(invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let mut id = None;
    let mut invocation = None;
    let mut active = None;
    let mut group = None;
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or_else(invalid)?;
        let slot = match key {
            "Id" => &mut id,
            "InvocationID" => &mut invocation,
            "ActiveState" => &mut active,
            "ControlGroup" => &mut group,
            _ => return Err(invalid()),
        };
        if slot.replace(value).is_some() {
            return Err(invalid());
        }
    }
    let (id, invocation, active, group) = (
        id.ok_or_else(invalid)?,
        invocation.ok_or_else(invalid)?,
        active.ok_or_else(invalid)?,
        group.ok_or_else(invalid)?,
    );
    if id != unit
        || invocation.len() != 32
        || !invocation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !matches!(
            active,
            "active" | "inactive" | "failed" | "activating" | "deactivating" | "reloading"
        )
        || !Path::new(group).is_absolute()
        || Path::new(group)
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || Path::new(group).file_name() != Some(std::ffi::OsStr::new(unit))
    {
        return Err(invalid());
    }
    Ok(UnitObservation {
        unit: id.into(),
        invocation: invocation.into(),
        active_state: active.into(),
        control_group: group.into(),
    })
}

/// Read a bounded systemctl response for one narrowly named unit. Runtime and
/// response are untrusted; errors and missing properties remain inconclusive.
pub async fn observe_user_unit(unit: &str, runtime: &Path) -> io::Result<UnitObservation> {
    if !valid_unit(unit) || !runtime.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid manager request",
        ));
    }
    let mut command = tokio::process::Command::new("/usr/bin/systemctl");
    command
        .args([
            "--user",
            "--no-pager",
            "show",
            "--property=Id,InvocationID,ActiveState,ControlGroup",
            unit,
        ])
        .env_clear()
        .env("LC_ALL", "C")
        .env("XDG_RUNTIME_DIR", runtime)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("manager output unavailable"))?;
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::new();
        stdout.take(8193).read_to_end(&mut bytes).await?;
        if bytes.len() > 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "manager output too large",
            ));
        }
        if !child.wait().await?.success() {
            return Err(io::Error::other("manager unavailable"));
        }
        parse(unit, &bytes)
    })
    .await;
    result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "manager observation timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_pidfd_rejects_invalid_credentials_and_detects_exit() {
        // SAFETY: geteuid has no arguments and no side effects.
        let uid = unsafe { libc::geteuid() };
        assert!(pin_manager_process(1, uid, uid).is_err());
        assert!(pin_manager_process(std::process::id(), uid.wrapping_add(1), uid).is_err());
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("10")
            .spawn()
            .unwrap();
        let fd = pin_manager_process(child.id(), uid, uid).unwrap();
        assert!(manager_is_alive(fd.as_fd()).unwrap());
        assert!(validate_manager_descriptor(Some(fd.as_fd()), child.id(), uid, uid).is_ok());
        assert!(validate_manager_descriptor(None, child.id(), uid, uid).is_err());
        assert!(
            validate_manager_descriptor(Some(fd.as_fd()), std::process::id(), uid, uid).is_err()
        );
        let ordinary = std::fs::File::open("/dev/null").unwrap();
        assert!(validate_manager_descriptor(Some(ordinary.as_fd()), child.id(), uid, uid).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!manager_is_alive(fd.as_fd()).unwrap());
        assert!(validate_manager_descriptor(Some(fd.as_fd()), child.id(), uid, uid).is_err());
    }

    #[test]
    fn bus_response_is_strict_and_bounded() {
        assert_eq!(
            parse_bus_string(b"s \"0123456789abcdef0123456789abcdef\"\n").unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
        for input in [
            b"s \"value\"".as_slice(),
            b"s \"value\"\nextra\n",
            b"s \"value\"\ns \"other\"\n",
            b"u 42\n",
            &[0xff],
        ] {
            assert!(parse_bus_string(input).is_err());
        }
        assert!(parse_bus_string(&vec![b'x'; 257]).is_err());
    }

    #[test]
    fn rejects_missing_duplicate_and_mismatched_properties() {
        let unit = "tucupi-review-0123456789abcdef0123456789abcdef.service";
        let valid = format!("Id={unit}\nInvocationID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nActiveState=active\nControlGroup=/user.slice/{unit}\n");
        assert!(parse(unit, valid.as_bytes()).is_ok());
        assert!(parse(unit, valid.replace("ActiveState=active\n", "").as_bytes()).is_err());
        assert!(parse(unit, format!("{valid}ActiveState=failed\n").as_bytes()).is_err());
        assert!(parse(
            unit,
            valid
                .replace("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "")
                .as_bytes()
        )
        .is_err());
        assert!(parse(unit, valid.replace(unit, "other.service").as_bytes()).is_err());
    }

    #[tokio::test]
    async fn manager_outage_and_invalid_unit_fail_closed() {
        let unit = "tucupi-review-0123456789abcdef0123456789abcdef.service";
        assert!(
            observe_user_unit(unit, Path::new("/nonexistent-tucupi-test-runtime"))
                .await
                .is_err()
        );
        assert!(
            observe_user_unit("other.service", Path::new("/nonexistent"))
                .await
                .is_err()
        );
    }
}
