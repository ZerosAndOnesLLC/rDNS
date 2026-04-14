/// Drop privileges after binding privileged ports.
/// Switches from root to the specified user/group.
#[cfg(unix)]
pub fn drop_privileges(user: &str, group: &str) -> anyhow::Result<()> {
    use nix::unistd::{Group, Uid, User};
    use std::ffi::CString;

    // Only attempt if running as root
    if !Uid::effective().is_root() {
        tracing::debug!("Not running as root, skipping privilege drop");
        return Ok(());
    }

    let user_cstr =
        CString::new(user).map_err(|_| anyhow::anyhow!("Invalid user name"))?;

    // Look up group and user via NSS
    let grp = Group::from_name(group)?
        .ok_or_else(|| anyhow::anyhow!("Group '{}' not found", group))?;
    let gid = grp.gid;

    let pwd = User::from_name(user)?
        .ok_or_else(|| anyhow::anyhow!("User '{}' not found", user))?;
    let uid = pwd.uid;

    // Set supplementary groups
    nix::unistd::initgroups(&user_cstr, gid)
        .map_err(|e| anyhow::anyhow!("Failed to set supplementary groups: {}", e))?;

    // Set GID first (must be done before dropping UID)
    #[cfg(target_os = "linux")]
    {
        nix::unistd::setresgid(gid, gid, gid)
            .map_err(|e| anyhow::anyhow!("Failed to setresgid to {}: {}", group, e))?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        nix::unistd::setgid(gid)
            .map_err(|e| anyhow::anyhow!("Failed to setgid to {}: {}", group, e))?;
    }

    // Set UID
    #[cfg(target_os = "linux")]
    {
        nix::unistd::setresuid(uid, uid, uid)
            .map_err(|e| anyhow::anyhow!("Failed to setresuid to {}: {}", user, e))?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        nix::unistd::setuid(uid)
            .map_err(|e| anyhow::anyhow!("Failed to setuid to {}: {}", user, e))?;
    }

    // Verify we can't regain root
    if nix::unistd::setuid(Uid::from_raw(0)).is_ok() {
        anyhow::bail!("SECURITY: Able to regain root after privilege drop!");
    }

    tracing::info!(
        user = user,
        uid = uid.as_raw(),
        group = group,
        gid = gid.as_raw(),
        "Dropped privileges"
    );

    Ok(())
}

#[cfg(not(unix))]
pub fn drop_privileges(_user: &str, _group: &str) -> anyhow::Result<()> {
    tracing::warn!("Privilege dropping not supported on this platform");
    Ok(())
}

/// Write a PID file for service management.
pub fn write_pidfile(path: &std::path::Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(path, format!("{}\n", std::process::id()))?;
    tracing::debug!(path = %path.display(), pid = std::process::id(), "Wrote PID file");
    Ok(())
}

/// Remove the PID file on shutdown.
pub fn remove_pidfile(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pidfile_write_remove() {
        let dir = std::env::temp_dir().join("rdns_test_pid");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.pid");

        write_pidfile(&path).unwrap();
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).unwrap();
        let pid: u32 = content.trim().parse().unwrap();
        assert_eq!(pid, std::process::id());

        remove_pidfile(&path);
        assert!(!path.exists());

        std::fs::remove_dir_all(&dir).ok();
    }
}
