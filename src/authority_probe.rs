//! Fail-closed Linux authority observation. This is not a trusted connector or
//! authorization mechanism: provisioning and authority identity remain open.

use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownReason {
    Unavailable,
    PeerCredentialsUnavailable,
    SameUserPeer,
    AuthorityIdentityUnverified,
    InvalidAuthorityPath,
    AuthorityPathUnavailable,
    AuthorityPathNotRootControlled,
    AuthorityPathIdentityUnverified,
    AuthoritySocketUnavailable,
    AuthoritySocketNotRootControlled,
}

/// Inspect a named Unix socket relative to an already-open directory without
/// connecting. The supplied directory and socket remain untrusted, even if the
/// basic ownership and mode checks pass. This only returns Unknown and cannot
/// authorize recovery or establish that a particular daemon owns the socket.
pub fn observe_authority_socket(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
) -> AuthorityObservation {
    observe_socket_with_owner(directory, name, 0)
}

fn observe_socket_with_owner(
    directory: &std::fs::File,
    name: &std::ffi::OsStr,
    expected_uid: u32,
) -> AuthorityObservation {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
        || name.as_bytes().len() > 255
    {
        return AuthorityObservation::Unknown(UnknownReason::InvalidAuthorityPath);
    }
    let Ok(name) = std::ffi::CString::new(name.as_bytes()) else {
        return AuthorityObservation::Unknown(UnknownReason::InvalidAuthorityPath);
    };
    // SAFETY: directory is a live descriptor and name is NUL terminated. O_PATH
    // inspects the filesystem object and does not connect to the Unix socket.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return AuthorityObservation::Unknown(UnknownReason::AuthoritySocketUnavailable);
    }
    // SAFETY: openat returned a fresh owned descriptor.
    let socket = unsafe { std::fs::File::from_raw_fd(fd) };
    let Ok(metadata) = socket.metadata() else {
        return AuthorityObservation::Unknown(UnknownReason::AuthoritySocketUnavailable);
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o022 != 0
    {
        return AuthorityObservation::Unknown(UnknownReason::AuthoritySocketNotRootControlled);
    }
    AuthorityObservation::Unknown(UnknownReason::AuthorityIdentityUnverified)
}

/// Read-only Linux path screening. Each component is opened relative to the
/// previously opened directory, with symlinks rejected. Root ownership and mode
/// are necessary observations, not proof of trust: ACLs, mounts, namespaces,
/// directory replacement and provisioning identity are not established here.
/// This always returns Unknown and must never be used to authorize operations.
pub fn observe_authority_directory(path: &Path) -> AuthorityObservation {
    match open_absolute_directory(path) {
        Ok(_) => AuthorityObservation::Unknown(UnknownReason::AuthorityPathIdentityUnverified),
        Err(reason) => AuthorityObservation::Unknown(reason),
    }
}

/// Inspect a filesystem endpoint through pinned directory descriptors, without
/// connecting. This is only a diagnostic and cannot authenticate the peer,
/// socket, directory, ACLs, mount, namespace, or subsequent pathname use.
pub fn observe_authority_endpoint(path: &Path) -> AuthorityObservation {
    if path.as_os_str().as_bytes().ends_with(b"/") || !valid_absolute_path(path) {
        return AuthorityObservation::Unknown(UnknownReason::InvalidAuthorityPath);
    }
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return AuthorityObservation::Unknown(UnknownReason::InvalidAuthorityPath);
    };
    match open_absolute_directory(parent) {
        Ok(directory) => observe_authority_socket(&directory, name),
        Err(reason) => AuthorityObservation::Unknown(reason),
    }
}

fn valid_absolute_path(path: &Path) -> bool {
    if !path.is_absolute() || path.as_os_str().as_bytes().len() > 4096 {
        return false;
    }
    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return false;
    }
    // Reject malformed or excessive input before opening any filesystem path.
    let mut count = 0usize;
    for part in parts.clone() {
        let Component::Normal(name) = part else {
            return false;
        };
        count += 1;
        if count > 64 || name.as_bytes().len() > 255 || name.as_bytes().contains(&0) {
            return false;
        }
    }
    true
}

fn open_absolute_directory(path: &Path) -> Result<std::fs::File, UnknownReason> {
    if !valid_absolute_path(path) {
        return Err(UnknownReason::InvalidAuthorityPath);
    }
    let current = std::fs::File::open("/").map_err(|_| UnknownReason::AuthorityPathUnavailable)?;
    let mut parts = path.components();
    let _ = parts.next();
    open_directory_components(current, parts, 0)
}

/// Private helper accepts a synthetic owner in tests; production always passes
/// UID 0 and still returns Unknown even when every component matches.
fn open_directory_components<'a>(
    mut current: std::fs::File,
    parts: impl Iterator<Item = Component<'a>>,
    expected_uid: u32,
) -> Result<std::fs::File, UnknownReason> {
    let invalid = || UnknownReason::InvalidAuthorityPath;
    let safe_metadata = |file: &std::fs::File| -> Option<bool> {
        let meta = file.metadata().ok()?;
        Some(meta.is_dir() && meta.uid() == expected_uid && meta.mode() & 0o022 == 0)
    };
    if safe_metadata(&current) != Some(true) {
        return Err(UnknownReason::AuthorityPathNotRootControlled);
    }
    let mut count = 0usize;
    for part in parts {
        let Component::Normal(name) = part else {
            return Err(invalid());
        };
        count += 1;
        if count > 64 {
            return Err(invalid());
        }
        let Ok(name) = std::ffi::CString::new(name.as_bytes()) else {
            return Err(invalid());
        };
        // SAFETY: current is a live directory fd and name is NUL terminated.
        let fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(UnknownReason::AuthorityPathUnavailable);
        }
        // SAFETY: openat returned a fresh owned file descriptor.
        current = unsafe { std::fs::File::from_raw_fd(fd) };
        if safe_metadata(&current) != Some(true) {
            return Err(UnknownReason::AuthorityPathNotRootControlled);
        }
    }
    Ok(current)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityObservation {
    Unknown(UnknownReason),
}

impl AuthorityObservation {
    /// No observation currently establishes permission to start or recover work.
    pub fn permits_operation(self) -> bool {
        false
    }
}

/// Observe kernel peer credentials on an existing Unix socket, without sending
/// a request or reading a response. `None` represents an unavailable endpoint.
/// An externally supplied socket and its peer remain untrusted. Even a
/// different UID does not prove that the peer is the intended authority.
pub fn observe_authority(stream: Option<&UnixStream>) -> AuthorityObservation {
    let Some(stream) = stream else {
        return AuthorityObservation::Unknown(UnknownReason::Unavailable);
    };
    // SAFETY: ucred is plain kernel output and zero is a valid initial value.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the live socket descriptor and output pointers are valid for
    // getsockopt, which writes at most the supplied buffer length.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() || credentials.pid <= 0
    {
        return AuthorityObservation::Unknown(UnknownReason::PeerCredentialsUnavailable);
    }
    // SAFETY: geteuid is a read-only process query.
    classify_peer(credentials.uid, unsafe { libc::geteuid() })
}

fn classify_peer(peer_uid: u32, own_uid: u32) -> AuthorityObservation {
    if peer_uid == own_uid {
        AuthorityObservation::Unknown(UnknownReason::SameUserPeer)
    } else {
        AuthorityObservation::Unknown(UnknownReason::AuthorityIdentityUnverified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn anchored_socket_observation_stays_on_open_directory_after_rename() {
        use std::os::unix::net::UnixListener;
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("authority");
        std::fs::create_dir(&original).unwrap();
        let socket = original.join("endpoint.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        // SAFETY: geteuid only reads the current effective UID.
        let uid = unsafe { libc::geteuid() };
        let base = std::fs::File::open(root.path()).unwrap();
        let pinned =
            open_directory_components(base, Path::new("authority").components(), uid).unwrap();
        std::fs::rename(&original, root.path().join("moved")).unwrap();
        std::fs::create_dir(&original).unwrap();
        let pinned_result =
            observe_socket_with_owner(&pinned, std::ffi::OsStr::new("endpoint.sock"), uid);
        assert_eq!(
            pinned_result,
            AuthorityObservation::Unknown(UnknownReason::AuthorityIdentityUnverified)
        );
        let replacement = std::fs::File::open(&original).unwrap();
        assert_eq!(
            observe_socket_with_owner(&replacement, std::ffi::OsStr::new("endpoint.sock"), uid),
            AuthorityObservation::Unknown(UnknownReason::AuthoritySocketUnavailable)
        );
        assert!(!pinned_result.permits_operation());
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        for invalid in [
            Path::new("/"),
            Path::new("relative"),
            Path::new("/tmp/../socket"),
            Path::new("/tmp/"),
        ] {
            assert_eq!(
                observe_authority_endpoint(invalid),
                AuthorityObservation::Unknown(UnknownReason::InvalidAuthorityPath)
            );
        }
    }

    #[test]
    fn socket_metadata_probe_uses_kernel_fd_without_connecting_or_authorizing() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("authority.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink("authority.sock", dir.path().join("link")).unwrap();
        std::fs::write(dir.path().join("ordinary"), b"unchanged").unwrap();
        let directory = std::fs::File::open(dir.path()).unwrap();
        // SAFETY: geteuid only reads the current effective UID.
        let uid = unsafe { libc::geteuid() };
        let probe =
            |name: &str| observe_socket_with_owner(&directory, std::ffi::OsStr::new(name), uid);
        assert_eq!(
            probe("authority.sock"),
            AuthorityObservation::Unknown(UnknownReason::AuthorityIdentityUnverified)
        );
        assert_eq!(
            probe("link"),
            AuthorityObservation::Unknown(UnknownReason::AuthoritySocketNotRootControlled)
        );
        assert_eq!(
            probe("ordinary"),
            AuthorityObservation::Unknown(UnknownReason::AuthoritySocketNotRootControlled)
        );
        assert_eq!(
            probe("missing"),
            AuthorityObservation::Unknown(UnknownReason::AuthoritySocketUnavailable)
        );
        assert_eq!(
            probe("../authority.sock"),
            AuthorityObservation::Unknown(UnknownReason::InvalidAuthorityPath)
        );
        assert!(!probe("authority.sock").permits_operation());
        assert_eq!(
            observe_socket_with_owner(
                &directory,
                std::ffi::OsStr::new("authority.sock"),
                uid.wrapping_add(1)
            ),
            AuthorityObservation::Unknown(UnknownReason::AuthoritySocketNotRootControlled)
        );
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            probe("authority.sock"),
            AuthorityObservation::Unknown(UnknownReason::AuthoritySocketNotRootControlled)
        );
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            std::fs::read(dir.path().join("ordinary")).unwrap(),
            b"unchanged"
        );
    }

    #[test]
    fn anchored_directory_screen_rejects_symlinks_files_and_unsafe_modes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        std::fs::write(dir.path().join("file"), b"synthetic").unwrap();
        std::os::unix::fs::symlink("real", dir.path().join("link")).unwrap();
        // SAFETY: geteuid only reads the current effective user ID.
        let uid = unsafe { libc::geteuid() };
        let observe = |path: &str| match open_directory_components(
            std::fs::File::open(dir.path()).unwrap(),
            Path::new(path).components(),
            uid,
        ) {
            Ok(_) => AuthorityObservation::Unknown(UnknownReason::AuthorityPathIdentityUnverified),
            Err(reason) => AuthorityObservation::Unknown(reason),
        };
        assert_eq!(
            observe("real"),
            AuthorityObservation::Unknown(UnknownReason::AuthorityPathIdentityUnverified)
        );
        assert_eq!(
            observe("link"),
            AuthorityObservation::Unknown(UnknownReason::AuthorityPathUnavailable)
        );
        assert_eq!(
            observe("file"),
            AuthorityObservation::Unknown(UnknownReason::AuthorityPathUnavailable)
        );
        assert_eq!(
            observe("../real"),
            AuthorityObservation::Unknown(UnknownReason::InvalidAuthorityPath)
        );
        std::fs::set_permissions(
            dir.path().join("real"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert_eq!(
            observe("real"),
            AuthorityObservation::Unknown(UnknownReason::AuthorityPathNotRootControlled)
        );
        assert!(!observe("real").permits_operation());
        assert_eq!(
            std::fs::read(dir.path().join("file")).unwrap(),
            b"synthetic"
        );
    }

    #[test]
    fn directory_screen_rejects_oversized_or_invalid_input_before_filesystem_lookup() {
        use std::ffi::OsStr;
        let long_path = format!("/{}", vec!["x"; 65].join("/"));
        let long_name = format!("/{}", "x".repeat(256));
        let nul = Path::new(OsStr::from_bytes(b"/synthetic\0path"));
        for path in [
            Path::new(&long_path),
            Path::new(&long_name),
            nul,
            Path::new("/missing/../other"),
        ] {
            let observation = observe_authority_directory(path);
            assert_eq!(
                observation,
                AuthorityObservation::Unknown(UnknownReason::InvalidAuthorityPath)
            );
            assert!(!observation.permits_operation());
        }
    }

    #[test]
    fn directory_screening_is_read_only_and_never_authorizes() {
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("synthetic");
        std::fs::create_dir(&child).unwrap();
        let marker = child.join("marker");
        std::fs::write(&marker, b"unchanged").unwrap();
        for path in [
            Path::new("relative"),
            child.as_path(),
            Path::new("/definitely-missing-tucupi-synthetic"),
        ] {
            assert!(!observe_authority_directory(path).permits_operation());
        }
        assert_eq!(
            observe_authority_directory(Path::new("relative")),
            AuthorityObservation::Unknown(UnknownReason::InvalidAuthorityPath)
        );
        assert_eq!(std::fs::read(marker).unwrap(), b"unchanged");
    }

    #[test]
    fn unavailable_and_unverified_candidates_never_permit_work() {
        let missing = observe_authority(None);
        assert_eq!(
            missing,
            AuthorityObservation::Unknown(UnknownReason::Unavailable)
        );
        assert!(!missing.permits_operation());
        for (peer, own) in [(1000, 1000), (0, 1000), (1001, 1000)] {
            let observed = classify_peer(peer, own);
            assert!(!observed.permits_operation());
            if peer != own {
                assert_eq!(
                    observed,
                    AuthorityObservation::Unknown(UnknownReason::AuthorityIdentityUnverified)
                );
            }
        }
    }

    #[test]
    fn real_same_uid_socket_is_rejected_without_consuming_or_sending_data() {
        let (mut client, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"synthetic").unwrap();
        let observed = observe_authority(Some(&client));
        assert_eq!(
            observed,
            AuthorityObservation::Unknown(UnknownReason::SameUserPeer)
        );
        assert!(!observed.permits_operation());
        let mut input = [0u8; 9];
        client.read_exact(&mut input).unwrap();
        assert_eq!(&input, b"synthetic");
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0u8; 1]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn unconnected_socket_is_unknown() {
        // SAFETY: socket creates a fresh descriptor with no external connection.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        // SAFETY: fd is a freshly created, uniquely owned Unix socket.
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        let observed = observe_authority(Some(&stream));
        assert_eq!(
            observed,
            AuthorityObservation::Unknown(UnknownReason::PeerCredentialsUnavailable)
        );
        assert!(!observed.permits_operation());
    }
}
