/// Platform-specific sandboxing after initialization.
/// - FreeBSD: Capsicum capability mode
/// - Linux: seccomp-bpf (stub — requires careful syscall whitelisting)

/// Enter the platform sandbox.
/// This should be called AFTER all ports are bound and files are opened.
pub fn enter_sandbox() -> anyhow::Result<()> {
    #[cfg(target_os = "freebsd")]
    {
        enter_capsicum()?;
    }

    #[cfg(target_os = "linux")]
    {
        apply_linux_hardening()?;
    }

    #[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
    {
        tracing::warn!("No sandbox available for this platform");
    }

    Ok(())
}

/// FreeBSD Capsicum capability mode.
/// Once entered, the process cannot open new files, create new sockets,
/// or access the filesystem. Only pre-opened file descriptors can be used.
#[cfg(target_os = "freebsd")]
fn enter_capsicum() -> anyhow::Result<()> {
    // cap_enter() puts the process into capability mode
    let ret = unsafe { libc::cap_enter() };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("Failed to enter Capsicum capability mode: {}", err);
    }
    tracing::info!("Entered Capsicum capability mode");
    Ok(())
}

/// Linux security hardening.
/// Applies PR_SET_NO_NEW_PRIVS and PR_SET_DUMPABLE to prevent privilege
/// escalation and ptrace/core dump information leaks.
#[cfg(target_os = "linux")]
fn apply_linux_hardening() -> anyhow::Result<()> {
    use nix::sys::prctl;

    // PR_SET_NO_NEW_PRIVS prevents the process (and children) from gaining
    // new privileges. This blocks execve of setuid/setgid binaries and is
    // a prerequisite for unprivileged seccomp filters.
    prctl::set_no_new_privs()
        .map_err(|e| anyhow::anyhow!("Failed to set PR_SET_NO_NEW_PRIVS: {}", e))?;

    // PR_SET_DUMPABLE=0 prevents ptrace attachment and core dumps,
    // which could leak sensitive data (TLS keys, cached records).
    if let Err(e) = prctl::set_dumpable(false) {
        tracing::warn!("Failed to set PR_SET_DUMPABLE=0: {}", e);
    }

    tracing::info!("Linux security: NO_NEW_PRIVS + non-dumpable enabled");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_does_not_panic() {
        // Just verify the function doesn't panic on the test platform
        let _ = enter_sandbox();
    }
}
