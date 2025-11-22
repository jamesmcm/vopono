use std::{
    ffi::CString,
    os::fd::{BorrowedFd, FromRawFd, IntoRawFd},
    os::unix::{io::RawFd, process::CommandExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use anyhow::Context;
use log::debug;
use nix::{
    fcntl::{OFlag, open},
    mount::{MsFlags, mount},
    sched::{CloneFlags, setns, unshare},
    sys::stat::Mode,
    unistd::close,
};

use super::{netns::NetworkNamespace, port_forwarding::Forwarder};
use crate::util::{env_vars::set_env_vars, get_all_running_process_names, parse_command_str};

pub struct ApplicationWrapper {
    pub handle: Child,
    pub port_forwarding: Option<Box<dyn Forwarder>>,
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
        stdio_fds: Option<(RawFd, RawFd, RawFd)>,
        take_controlling_tty: bool,
    ) -> anyhow::Result<Self> {
        let running_processes = get_all_running_process_names();
        let app_vec = parse_command_str(application)?;

        for shared_process_app in [
            "google-chrome-stable",
            "google-chrome-beta",
            "google-chrome",
            "chromium",
            "firefox",
            "firefox-developer-edition",
        ]
        .iter()
        {
            if app_vec.contains(&shared_process_app.to_string())
                && running_processes.contains(&shared_process_app.to_string())
            {
                log::error!(
                    "{shared_process_app} is already running. You must force it to use a separate profile in order to launch a new process!"
                );
            }
        }

        let app_vec_ptrs: Vec<&str> = app_vec.iter().map(|s| s.as_str()).collect();

        let handle = Self::run_with_env_in_netns(
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
        Ok(Self {
            handle,
            port_forwarding,
        })
    }

    pub fn wait_with_output(self) -> anyhow::Result<std::process::Output> {
        let output = self.handle.wait_with_output()?;
        Ok(output)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_with_env_in_netns(
        netns: &NetworkNamespace,
        command: &[&str],
        user: Option<String>,
        group: Option<String>,
        silent: bool,
        capture_output: bool,
        capture_input: bool,
        stdio_fds: Option<(RawFd, RawFd, RawFd)>,
        take_controlling_tty: bool,
        set_dir: Option<PathBuf>,
        forwarder: Option<&dyn Forwarder>,
        host_env_vars: &std::collections::HashMap<String, String>,
    ) -> anyhow::Result<Child> {
        let is_root = nix::unistd::getuid().is_root();
        let (prog, args) = command.split_first().context("Command cannot be empty")?;
        let mut handle: Command;

        // Use direct setns only for the daemon path. If stdio_fds provided, we must use setns.
        // Otherwise, fall back to ip netns exec (even when root) for non-daemon usage.
        let use_direct_setns =
            is_root && (stdio_fds.is_some() || (capture_output && capture_input));

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
            // Prepare bind-mount sources for /etc overlay
            let etc_ns_dir = format!("/etc/netns/{}", netns.name);
            let resolv_src = CString::new(format!("{}/resolv.conf", &etc_ns_dir)).ok();
            let hosts_src = CString::new(format!("{}/hosts", &etc_ns_dir)).ok();
            let nsswitch_src = CString::new(format!("{}/nsswitch.conf", &etc_ns_dir)).ok();
            let resolv_dst = CString::new("/etc/resolv.conf").unwrap();
            let hosts_dst = CString::new("/etc/hosts").unwrap();
            let nsswitch_dst = CString::new("/etc/nsswitch.conf").unwrap();
            let ping_path = CString::new("/proc/sys/net/ipv4/ping_group_range").unwrap();

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

                    // Helper to bind a file if the source exists
                    let bind_if_exists = |src_opt: &Option<CString>,
                                          dst: &CString|
                     -> Result<(), std::io::Error> {
                        if let Some(src) = src_opt
                            && libc::access(src.as_ptr(), libc::R_OK) == 0
                        {
                            mount::<std::ffi::CStr, std::ffi::CStr, std::ffi::CStr, std::ffi::CStr>(
                                Some(src.as_c_str()),
                                dst.as_c_str(),
                                None,
                                MsFlags::MS_BIND,
                                None,
                            )?;
                        }
                        Ok(())
                    };

                    // Overlay resolv.conf, hosts, nsswitch.conf for proper name resolution within netns
                    bind_if_exists(&resolv_src, &resolv_dst)?;
                    bind_if_exists(&hosts_src, &hosts_dst)?;
                    bind_if_exists(&nsswitch_src, &nsswitch_dst)?;

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
            // This non-daemon path remains unchanged
            handle = Command::new("ip");
            handle.args(["netns", "exec", netns.name.as_str()]);

            let mut sudo_args: Vec<String> = vec!["sudo".to_string(), "--preserve-env".to_string()];
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
            (Some((fd_in, fd_out_orig, fd_err_orig)), _, _) => unsafe {
                // Ensure each Stdio gets a unique owned fd to avoid double-closing.
                let in_fd = fd_in;
                let mut out_fd = fd_out_orig;
                let mut err_fd = fd_err_orig;
                if out_fd == in_fd {
                    out_fd = nix::unistd::dup(BorrowedFd::borrow_raw(out_fd))
                        .map_err(|e| std::io::Error::other(format!("dup stdout failed: {e}")))?
                        .into_raw_fd();
                }
                if err_fd == in_fd || err_fd == out_fd {
                    err_fd = nix::unistd::dup(BorrowedFd::borrow_raw(err_fd))
                        .map_err(|e| std::io::Error::other(format!("dup stderr failed: {e}")))?
                        .into_raw_fd();
                }
                handle.stdin(Stdio::from_raw_fd(in_fd));
                handle.stdout(Stdio::from_raw_fd(out_fd));
                handle.stderr(Stdio::from_raw_fd(err_fd));
            },
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
        Ok(child)
    }
}
