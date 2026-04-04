/// Drop privileges after binding privileged ports.
/// Switches from root to the specified user/group.
#[cfg(unix)]
pub fn drop_privileges(user: &str, group: &str) -> anyhow::Result<()> {
    use std::ffi::CString;

    // Only attempt if running as root
    if unsafe { libc::getuid() } != 0 {
        tracing::debug!("Not running as root, skipping privilege drop");
        return Ok(());
    }

    let user_cstr = CString::new(user)
        .map_err(|_| anyhow::anyhow!("Invalid user name"))?;

    let group_cstr = CString::new(group)
        .map_err(|_| anyhow::anyhow!("Invalid group name"))?;

    // Look up group
    let grp = unsafe { libc::getgrnam(group_cstr.as_ptr()) };
    if grp.is_null() {
        anyhow::bail!("Group '{}' not found", group);
    }
    let gid = unsafe { (*grp).gr_gid };

    // Look up user
    let pwd = unsafe { libc::getpwnam(user_cstr.as_ptr()) };
    if pwd.is_null() {
        anyhow::bail!("User '{}' not found", user);
    }
    let uid = unsafe { (*pwd).pw_uid };

    // Set supplementary groups
    if unsafe { libc::initgroups(user_cstr.as_ptr(), gid) } != 0 {
        anyhow::bail!("Failed to set supplementary groups");
    }

    // Set GID first (must be done before dropping UID)
    // Use setresgid to set real, effective, and saved GID
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::setresgid(gid, gid, gid) } != 0 {
            anyhow::bail!("Failed to setresgid to {}", group);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if unsafe { libc::setgid(gid) } != 0 {
            anyhow::bail!("Failed to setgid to {}", group);
        }
    }

    // Set UID
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::setresuid(uid, uid, uid) } != 0 {
            anyhow::bail!("Failed to setresuid to {}", user);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        if unsafe { libc::setuid(uid) } != 0 {
            anyhow::bail!("Failed to setuid to {}", user);
        }
    }

    // Verify we can't regain root
    if unsafe { libc::setuid(0) } == 0 {
        anyhow::bail!("SECURITY: Able to regain root after privilege drop!");
    }

    tracing::info!(
        user = user,
        uid = uid,
        group = group,
        gid = gid,
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
