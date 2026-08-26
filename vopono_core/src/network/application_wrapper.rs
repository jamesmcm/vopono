use std::{
    ffi::CString,
    io::Write,
    os::fd::{AsFd, OwnedFd},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use anyhow::{Context, bail};
use log::debug;
use nix::{
    fcntl::{OFlag, open},
    mount::{MsFlags, mount},
    sched::{CloneFlags, setns, unshare},
    sys::stat::Mode,
    unistd::close,
};

use super::{etc_overlay::EtcOverlay, netns::NetworkNamespace, port_forwarding::Forwarder};
use crate::util::{
    check_process_running, env_vars::set_env_vars, get_running_process_pids, parse_command_str,
    process_is_in_network_namespace,
};

// NOTE: Known single-instance clients (browsers, and eventually launchers such
// as gnome-terminal-server) are only *warned* about today; fully blocking them
// would also block legitimate separate-profile launches. A blocking policy
// would need per-application profile detection and is deliberately left as
// future work.
const SINGLE_INSTANCE_APPLICATIONS: &[&str] = &[
    "google-chrome-stable",
    "google-chrome-beta",
    "google-chrome",
    "google-chrome-unstable",
    "chromium",
    "chromium-browser",
    "brave",
    "brave-browser",
    "firefox",
    "firefox-developer-edition",
    "firefox-bin",
    "librewolf",
    "vivaldi",
    "vivaldi-stable",
    "opera",
    "microsoft-edge",
    "microsoft-edge-stable",
];

pub struct ApplicationWrapper {
    pub handle: Child,
    pub port_forwarding: Option<Box<dyn Forwarder>>,
    _etc_overlay: Option<EtcOverlay>,
}

impl ApplicationWrapper {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        netns: &NetworkNamespace,
        application: &str,
        user: Option<String>,
        group: Option<String>,
        working_directory: Option<PathBuf>,
        port_forwarding: Option<Box<dyn Forwarder>>,
        silent: bool,
        host_env_vars: &std::collections::HashMap<String, String>,
        pipe_io: bool,
        stdio_fds: Option<(OwnedFd, OwnedFd, OwnedFd)>,
        take_controlling_tty: bool,
    ) -> anyhow::Result<Self> {
        let app_vec = parse_command_str(application)?;
        let warning_stderr = stdio_fds
            .as_ref()
            .map(|(_, _, stderr)| nix::unistd::dup(stderr.as_fd()))
            .transpose()?;

        let shared_process_name = app_vec.first().and_then(|program| {
            Path::new(program)
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| SINGLE_INSTANCE_APPLICATIONS.contains(name))
        });
        let shared_process_pids = shared_process_name
            .map(|name| {
                get_running_process_pids(name)
                    .into_iter()
                    .filter(|pid| {
                        // A matching process already inside this exact netns
                        // cannot cause the host-namespace escape described by
                        // this warning.  If inspection fails, keep the warning
                        // conservative and report the PID to the user.
                        !matches!(process_is_in_network_namespace(*pid, &netns.name), Ok(true))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if let Some(shared_process_name) = shared_process_name
            && !shared_process_pids.is_empty()
        {
            report_warning(
                format!(
                    "{shared_process_name} is already running outside network namespace '{}' (PID(s): {}). It may reuse that process instead of starting inside vopono; use a separate profile/data directory or stop the existing instance.",
                    netns.name,
                    shared_process_pids
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                silent,
                warning_stderr.as_ref(),
            );
        }

        let app_vec_ptrs: Vec<&str> = app_vec.iter().map(|s| s.as_str()).collect();

        let (mut handle, etc_overlay) = Self::run_with_env_in_netns(
            netns,
            app_vec_ptrs.as_slice(),
            user,
            group,
            silent,
            pipe_io,
            pipe_io,
            stdio_fds,
            take_controlling_tty,
            working_directory,
            port_forwarding.as_deref(),
            host_env_vars,
        )?;

        let pid = handle.id();
        if check_process_running(pid) {
            match process_is_in_network_namespace(pid, &netns.name) {
                Ok(true) => {
                    debug!(
                        "Verified application PID {pid} is in network namespace '{}'",
                        netns.name
                    );
                }
                Ok(false) => {
                    let _ = handle.kill();
                    let _ = handle.wait();
                    bail!(
                        "Refusing to launch application: PID {pid} is not in network namespace '{}'",
                        netns.name
                    );
                }
                Err(error) => {
                    log::warn!(
                        "Could not verify that application PID {pid} is in network namespace '{}': {error}",
                        netns.name
                    );
                }
            }
        } else if !shared_process_pids.is_empty() {
            report_warning(
                format!(
                    "Application launcher PID {pid} exited before its network namespace could be verified; the existing process may have handled the request instead."
                ),
                silent,
                warning_stderr.as_ref(),
            );
        }

        Ok(Self {
            handle,
            port_forwarding,
            _etc_overlay: etc_overlay,
        })
    }

    pub fn wait_with_output(self) -> anyhow::Result<std::process::Output> {
        let output = self.handle.wait_with_output()?;
        Ok(output)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_with_env_in_netns(
        netns: &NetworkNamespace,
        command: &[&str],
        user: Option<String>,
        group: Option<String>,
        silent: bool,
        capture_output: bool,
        capture_input: bool,
        stdio_fds: Option<(OwnedFd, OwnedFd, OwnedFd)>,
        take_controlling_tty: bool,
        set_dir: Option<PathBuf>,
        forwarder: Option<&dyn Forwarder>,
        host_env_vars: &std::collections::HashMap<String, String>,
    ) -> anyhow::Result<(Child, Option<EtcOverlay>)> {
        let (prog, args) = command.split_first().context("Command cannot be empty")?;
        let mut handle: Command;

        // The daemon needs direct setns so it can attach the client's stdio and PTY without
        // another process layer.
        let use_direct_setns = nix::unistd::getuid().is_root()
            && (stdio_fds.is_some() || (capture_output && capture_input));
        let etc_overlay;

        if use_direct_setns {
            handle = Command::new(prog);
            handle.args(args);
            // Prepare all data outside the closure
            let user_details = if let Some(user_name) = user {
                debug!(
                    "(daemon) Preparing to run '{}' in netns '{}' as user '{}'",
                    command.join(" "),
                    netns.name,
                    user_name
                );
                let target_user = nix::unistd::User::from_name(&user_name)?
                    .with_context(|| format!("User '{}' not found", user_name))?;

                let target_group = if let Some(group_name) = group {
                    nix::unistd::Group::from_name(&group_name)?
                        .with_context(|| format!("Group '{}' not found", group_name))?
                } else {
                    nix::unistd::Group::from_gid(target_user.gid)?
                        .with_context(|| "Primary group for user not found")?
                };

                //  Before forking, set the DBUS session address environment variable.
                let dbus_socket_path = format!("/run/user/{}/bus", target_user.uid.as_raw());
                if std::path::Path::new(&dbus_socket_path).exists() {
                    let dbus_address = format!("unix:path={}", dbus_socket_path);
                    debug!("Setting DBUS_SESSION_BUS_ADDRESS to {}", dbus_address);
                    handle.env("DBUS_SESSION_BUS_ADDRESS", dbus_address);
                } else {
                    log::warn!(
                        "Could not find user DBus socket at {}. Graphical applications may fail to integrate with the desktop.",
                        dbus_socket_path
                    );
                }

                //  Set environment and working directory on the Command builder itself.
                // This is the safe and correct way to prepare the child's environment.
                handle.env("HOME", &target_user.dir);
                handle.env("USER", &target_user.name);
                handle.env("LOGNAME", &target_user.name);

                if let Some(dir) = set_dir {
                    handle.current_dir(dir);
                } else {
                    handle.current_dir(&target_user.dir);
                }

                Some((
                    target_user.uid,
                    target_group.gid,
                    CString::new(target_user.name)?,
                ))
            } else {
                if let Some(dir) = set_dir {
                    handle.current_dir(dir);
                }
                None
            };

            let netns_path_cstr = CString::new(format!("/var/run/netns/{}", netns.name))?;
            let want_controlling_tty = take_controlling_tty;
            let root_c = CString::new("/").unwrap();
            let overlay = EtcOverlay::prepare(&netns.name)?;
            let overlay_options = overlay.options.clone();
            let overlay_source = overlay.source.clone();
            let overlay_type = overlay.filesystem_type.clone();
            let etc_c = overlay.target.clone();
            let ping_path = CString::new("/proc/sys/net/ipv4/ping_group_range").unwrap();
            etc_overlay = Some(overlay);

            unsafe {
                handle.pre_exec(move || {
                    // The closure now ONLY contains async-signal-safe syscall wrappers.
                    let ns_fd = open(netns_path_cstr.as_c_str(), OFlag::O_RDONLY, Mode::empty())?;
                    setns(
                        ns_fd.try_clone().expect("Clone failed"),
                        CloneFlags::CLONE_NEWNET,
                    )?;
                    close(ns_fd)?;

                    // Create a private mount namespace for the child to safely overlay /etc files
                    unshare(CloneFlags::CLONE_NEWNS)?;
                    // Make mounts private to avoid propagating to the host
                    mount::<std::ffi::CStr, std::ffi::CStr, std::ffi::CStr, std::ffi::CStr>(
                        None,
                        root_c.as_c_str(),
                        None,
                        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                        None,
                    )?;

                    // Give the child a stable private /etc view. Namespace-specific resolver
                    // files in the upper layer cannot be displaced when NetworkManager,
                    // Tailscale, or systemd-resolved atomically replaces the host resolv.conf.
                    //
                    // Tailscale MagicDNS and direct tailnet routes are intentionally unavailable
                    // inside the VPN namespace. Users can currently expose a host-side proxy with
                    // --allow-host-access and connect to it through vopono.host.
                    // Host-side service forwarding remains opt-in; exposing
                    // selected Tailscale services automatically would weaken
                    // the namespace boundary.
                    mount(
                        Some(overlay_source.as_c_str()),
                        etc_c.as_c_str(),
                        Some(overlay_type.as_c_str()),
                        MsFlags::empty(),
                        Some(overlay_options.as_c_str()),
                    )?;

                    // Enable unprivileged ping inside the netns by widening ping_group_range
                    // Write "0 2147483647" to /proc/sys/net/ipv4/ping_group_range via raw syscalls
                    let fd = libc::open(ping_path.as_ptr(), libc::O_WRONLY);
                    if fd >= 0 {
                        let data = b"0 2147483647\n";
                        let _ = libc::write(fd, data.as_ptr() as *const _, data.len());
                        libc::close(fd);
                    }

                    // If the child should be truly interactive, make it a session leader and
                    // set the controlling terminal to stdin (fd 0). This fixes bash job control
                    // and routes signals like Ctrl+C to the child instead of the client.
                    if want_controlling_tty {
                        // Create a new session
                        let _ = libc::setsid();
                        // If stdin is a TTY, take it as controlling terminal
                        // Use TIOCSCTTY with arg 1 to forcibly acquire if already in use
                        let fd0: i32 = 0;
                        if libc::isatty(fd0) == 1 {
                            // Attempt to acquire the TTY as controlling terminal. Only set
                            // the foreground process group if that succeeded.
                            let acquire_res = libc::ioctl(fd0, libc::TIOCSCTTY as _, 1);
                            if acquire_res == 0 {
                                let pgrp = libc::getpgrp();
                                let _ = libc::tcsetpgrp(fd0, pgrp);
                            }
                        }
                    }

                    if let Some((uid, gid, user_name_cstr)) = &user_details {
                        nix::unistd::initgroups(user_name_cstr, *gid)?;
                        nix::unistd::setgid(*gid)?;
                        nix::unistd::setuid(*uid)?;
                    }

                    Ok(())
                });
            }
        } else {
            handle = Command::new("ip");
            handle.args(["netns", "exec", netns.name.as_str()]);

            // `ip netns exec` bind-mounts namespace-specific resolver files,
            // but its mount namespace can still receive host-side unmounts.
            // Tailscale replaces /etc/resolv.conf this way, causing a
            // long-running application to fall back to MagicDNS, which is not
            // reachable through the VPN namespace. Put the sudo path in a
            // private mount namespace and stable /etc overlay before `ip`
            // performs its namespace-specific mounts.
            let overlay = EtcOverlay::prepare(&netns.name)?;
            let overlay_options = overlay.options.clone();
            let overlay_source = overlay.source.clone();
            let overlay_type = overlay.filesystem_type.clone();
            let root_c = CString::new("/").unwrap();
            let etc_c = overlay.target.clone();
            etc_overlay = Some(overlay);

            unsafe {
                handle.pre_exec(move || {
                    unshare(CloneFlags::CLONE_NEWNS)?;
                    mount::<std::ffi::CStr, std::ffi::CStr, std::ffi::CStr, std::ffi::CStr>(
                        None,
                        root_c.as_c_str(),
                        None,
                        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                        None,
                    )?;
                    mount(
                        Some(overlay_source.as_c_str()),
                        etc_c.as_c_str(),
                        Some(overlay_type.as_c_str()),
                        MsFlags::empty(),
                        Some(overlay_options.as_c_str()),
                    )?;
                    Ok(())
                });
            }

            let mut sudo_args: Vec<String> = vec![
                "sudo".to_string(),
                "--preserve-env".to_string(),
                "--set-home".to_string(),
            ];
            if let Some(user_str) = &user {
                sudo_args.push("--user".to_string());
                sudo_args.push(user_str.clone());
            }
            if let Some(group_str) = &group {
                sudo_args.push("--group".to_string());
                sudo_args.push(group_str.clone());
            }

            debug!(
                "ip netns exec {} {} {}",
                netns.name,
                sudo_args.join(" "),
                command.join(" ")
            );
            handle.args(sudo_args);
            handle.args(command);
            if let Some(cdir) = set_dir {
                handle.current_dir(cdir);
            }
        }

        set_env_vars(netns, forwarder, &mut handle, host_env_vars);

        if silent {
            handle.stdout(Stdio::null());
            handle.stderr(Stdio::null());
        }
        match (stdio_fds, capture_input, capture_output) {
            (Some((fd_in, fd_out, fd_err)), _, _) => {
                if silent {
                    // --silent: keep stdin wired to the client but discard the
                    // application's output, even when stdio FDs were provided.
                    handle.stdin(Stdio::from(fd_in));
                    handle.stdout(Stdio::null());
                    handle.stderr(Stdio::null());
                    drop((fd_out, fd_err));
                } else {
                    handle.stdin(Stdio::from(fd_in));
                    handle.stdout(Stdio::from(fd_out));
                    handle.stderr(Stdio::from(fd_err));
                }
            }
            (None, true, true) => {
                handle.stdin(Stdio::piped());
                handle.stdout(Stdio::piped());
                handle.stderr(Stdio::piped());
            }
            (None, true, false) => {
                handle.stdin(Stdio::piped());
            }
            (None, false, true) => {
                handle.stdout(Stdio::piped());
                handle.stderr(Stdio::piped());
            }
            _ => {}
        }

        let child = handle.spawn()?;
        Ok((child, etc_overlay))
    }
}

fn report_warning(message: String, silent: bool, stderr_fd: Option<&OwnedFd>) {
    if silent {
        // --silent suppresses warnings as well as application output.
        return;
    }
    if let Some(stderr_fd) = stderr_fd
        && let Ok(dup_fd) = nix::unistd::dup(stderr_fd.as_fd())
    {
        // Daemon path: the application runs in the daemon, so route warnings
        // back to the client's stderr instead of the daemon's journal.
        let mut stderr = std::fs::File::from(dup_fd);
        let _ = writeln!(stderr, "warning: {message}");
        let _ = stderr.flush();
    } else {
        log::warn!("{message}");
    }
}
