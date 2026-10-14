//! Least privilege: bind port 53 as root, then run as an unprivileged account.

use anyhow::Result;

use crate::error::{ErrorCode, coded};

#[cfg(unix)]
pub fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

/// Permanently switch to `user` and its primary group. Fails closed: if root could be
/// regained afterwards, the process refuses to continue.
#[cfg(unix)]
pub fn drop_to(user: &str) -> Result<()> {
    use nix::unistd::{Uid, User, geteuid, setgid, setuid};

    let entry = User::from_name(user)?.ok_or_else(|| {
        coded(
            ErrorCode::InvalidInput,
            format!("invalid user: account {user} does not exist"),
        )
    })?;
    if !geteuid().is_root() {
        if geteuid() == entry.uid {
            return Ok(());
        }
        return Err(coded(
            ErrorCode::PermissionRequired,
            format!("permission required: switching to {user} requires starting as root"),
        ));
    }
    #[cfg(not(target_vendor = "apple"))]
    nix::unistd::setgroups(&[entry.gid])?;
    #[cfg(target_vendor = "apple")]
    nix::unistd::initgroups(&std::ffi::CString::new(user)?, entry.gid)?;
    setgid(entry.gid)?;
    setuid(entry.uid)?;
    if setuid(Uid::from_raw(0)).is_ok() || geteuid().is_root() {
        return Err(coded(
            ErrorCode::Internal,
            "privilege drop failed: root privileges are still available",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn drop_to(_user: &str) -> Result<()> {
    Err(coded(
        ErrorCode::InvalidInput,
        "invalid option: --user is only supported on Unix; run the Windows service under a dedicated account instead",
    ))
}
