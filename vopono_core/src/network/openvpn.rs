use super::firewall::Firewall;
use super::netns::NetworkNamespace;
use crate::config::vpn::{OpenVpnBackend, OpenVpnProtocol};
use crate::util::{check_process_running, set_config_permissions};
use anyhow::{Context, anyhow};
use log::{debug, error, info};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::File;
#[cfg(feature = "openvpn3")]
use std::io::Write;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::str::FromStr;
use std::time::{Duration, Instant};
#[cfg(feature = "openvpn3")]
use std::{
    os::fd::{AsRawFd, FromRawFd},
    os::unix::net::UnixStream,
    sync::mpsc::{self, Receiver, RecvTimeoutError, Sender},
    thread::JoinHandle,
};

const OPENVPN_STARTUP_TIMEOUT: Duration = Duration::from_secs(120);

#[cfg(feature = "openvpn3")]
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OpenVpn3ControlMessage<'a> {
    Start {
        username: &'a str,
        password: &'a str,
        disable_ipv6: bool,
    },
    Shutdown,
}

#[cfg(feature = "openvpn3")]
#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OpenVpn3HelperMessage {
    Event {
        name: String,
        info: String,
        error: bool,
        fatal: bool,
    },
    Connected {
        server_host: String,
        server_ip: String,
        tun_name: String,
        vpn_ip4: String,
        vpn_ip6: String,
        dns_servers: Vec<IpAddr>,
    },
    Error {
        message: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenVpn {
    pub(crate) pid: u32,
    #[serde(default)]
    pub backend: OpenVpnBackend,
    #[serde(default)]
    pub openvpn_dns_servers: Vec<IpAddr>,
    pub logfile: PathBuf,
    #[serde(skip)]
    child: Option<Child>,
    #[serde(skip)]
    _runtime_dir: Option<tempfile::TempDir>,
    #[cfg(feature = "openvpn3")]
    #[serde(skip)]
    ipc_stream: Option<UnixStream>,
    #[cfg(feature = "openvpn3")]
    #[serde(skip)]
    reader_thread: Option<JoinHandle<()>>,
    #[serde(skip)]
    cleanup_enabled: bool,
    // pub distinct_remotes: Vec<String>, // Unique IP Addresses or hostnames
}

struct OpenVpnRunConfig<'a> {
    profile: PathBuf,
    auth_file: Option<PathBuf>,
    working_dir: PathBuf,
    runtime_dir: tempfile::TempDir,
    logfile: PathBuf,
    verbose: bool,
    network: OpenVpnNetworkSettings<'a>,
}

struct OpenVpnNetworkSettings<'a> {
    dns: &'a [IpAddr],
    use_killswitch: bool,
    open_ports: Option<&'a [u16]>,
    forward_ports: Option<&'a [u16]>,
    firewall: Firewall,
    disable_ipv6: bool,
    remotes: Vec<Remote>,
}

impl OpenVpnNetworkSettings<'_> {
    fn apply_after_connect(&self, netns: &NetworkNamespace) -> anyhow::Result<()> {
        if let Some(open_ports) = self.open_ports {
            crate::util::open_ports(netns, open_ports, self.firewall)?;
        }
        if let Some(forward_ports) = self.forward_ports {
            crate::util::open_ports(netns, forward_ports, self.firewall)?;
        }
        if self.use_killswitch {
            killswitch(
                netns,
                self.dns,
                &self.remotes,
                self.firewall,
                self.disable_ipv6,
            )?;
        }
        Ok(())
    }
}

impl OpenVpn {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_with_backend(
        netns: &NetworkNamespace,
        config_file: PathBuf,
        auth_file: Option<PathBuf>,
        dns: &[IpAddr],
        use_killswitch: bool,
        open_ports: Option<&Vec<u16>>,
        forward_ports: Option<&Vec<u16>>,
        firewall: Firewall,
        disable_ipv6: bool,
        verbose: bool,
        backend: OpenVpnBackend,
    ) -> anyhow::Result<Self> {
        if backend == OpenVpnBackend::OpenVpn2
            && let Err(x) = which::which("openvpn")
        {
            error!("OpenVPN not found. Is OpenVPN installed and on PATH?");
            return Err(anyhow!(
                "OpenVPN not found. Is OpenVPN installed and on PATH?: {:?}",
                x
            ));
        }

        // OpenVPN runs as root and opens its log path itself. Keep that path
        // inside an unpredictable, root-owned runtime directory rather than
        // the client's writable config tree, where a symlink swap could turn
        // it into a privileged file write.
        let runtime_dir = tempfile::Builder::new()
            .prefix("vopono-openvpn-")
            // Do not use the inherited TMPDIR after privilege escalation: its
            // parent may be controlled by the invoking user.
            .tempdir_in("/run")
            .context("Failed to create private OpenVPN runtime directory")?;
        let log_file_path = runtime_dir.path().join("openvpn.log");
        File::create(&log_file_path)?;

        let config_file_path = config_file.canonicalize().context("Invalid path given")?;
        // Daemon model creates each config object with the correct owner/mode
        // up front; the recursive walk runs dropped-privilege and cannot
        // repair root-owned trees, so it must not run here (EPERM, #382).
        if !crate::util::is_daemon_mode() {
            set_config_permissions()?;
        }

        // Check config file for up and down script entries and warn on their presence
        warn_on_scripts_config(&config_file_path)?;

        let ipv6_disabled = std::fs::read_to_string("/sys/module/ipv6/parameters/disable")
            .map(|value| value.trim() == "1")
            .unwrap_or(false);
        if ipv6_disabled {
            debug!("Detected IPv6 disabled in /sys/module/ipv6/parameters/disable");
        } else {
            debug!("Detected IPv6 enabled in /sys/module/ipv6/parameters/disable");
        }

        let remotes = get_remotes_from_config(&config_file)?;
        debug!("Found remotes: {:?}", remotes);
        let working_dir = PathBuf::from(config_file_path.parent().unwrap());
        let run_config = OpenVpnRunConfig {
            profile: config_file_path,
            auth_file,
            working_dir,
            runtime_dir,
            logfile: log_file_path,
            verbose,
            network: OpenVpnNetworkSettings {
                dns,
                use_killswitch,
                open_ports: open_ports.map(Vec::as_slice),
                forward_ports: forward_ports.map(Vec::as_slice),
                firewall,
                disable_ipv6: disable_ipv6 || ipv6_disabled,
                remotes,
            },
        };

        if backend == OpenVpnBackend::OpenVpn3 {
            #[cfg(feature = "openvpn3")]
            {
                return Self::run_openvpn3(netns, run_config);
            }
            #[cfg(not(feature = "openvpn3"))]
            anyhow::bail!(
                "OpenVPN 3 support is disabled in this vopono build; install or rebuild vopono with the `openvpn3` feature"
            );
        }

        let OpenVpnRunConfig {
            profile,
            auth_file,
            working_dir,
            runtime_dir,
            logfile: logfile_path,
            verbose,
            network,
        } = run_config;
        let log_file_str = logfile_path.as_os_str().to_string_lossy().to_string();

        let mut command_vec = ([
            "openvpn",
            "--config",
            profile.to_str().unwrap(),
            "--machine-readable-output",
            "--log",
            log_file_str.as_str(),
            "--ignore-unknown-option",
            "dns-updown",
            "--dns-updown",
            "disable",
        ])
        .to_vec();

        if let Some(af_ref) = auth_file.as_ref() {
            command_vec.push("--auth-user-pass");
            command_vec.push(af_ref.as_os_str().to_str().unwrap());
        }

        // Only try once for DNS resolution / remote host connection
        command_vec.push("--connect-retry-max");
        command_vec.push("1");
        // Ignore Windows-specific command
        command_vec.push("--pull-filter");
        command_vec.push("ignore");
        command_vec.push("block-outside-dns");

        // In daemon mode the config file is client-controlled input, so
        // script hooks (up/down/iproute/...) must never run as root: cap
        // script-security after --config so a config-file directive cannot
        // raise it again (later options win).
        if crate::util::is_daemon_mode() {
            command_vec.push("--script-security");
            command_vec.push("1");
        }

        if network.disable_ipv6 {
            debug!("IPv6 disabled, will pass pull-filter ignore to OpenVPN");
            command_vec.push("--pull-filter");
            command_vec.push("ignore");
            command_vec.push("ifconfig-ipv6");
            command_vec.push("--pull-filter");
            command_vec.push("ignore");
            command_vec.push("route-ipv6");
        }

        info!("Launching OpenVPN...");
        let mut handle = NetworkNamespace::exec_no_block(
            &netns.name,
            &command_vec,
            None,
            None,
            !verbose,
            false,
            false,
            Some(working_dir),
        )
        .context("Failed to launch OpenVPN - is openvpn installed?")?;
        let id = handle.id();
        let mut buffer = String::with_capacity(16384);

        let mut logfile = BufReader::with_capacity(64, File::open(log_file_str)?);
        let mut pos: usize = 0;

        // Parse DNS headers from OpenVPN response
        let dns_regex = Regex::new(r"dhcp-option (?:DNS6|DNS) ([^,\s']+)").unwrap();
        let mut openvpn_dns_servers = Vec::new();
        // `--machine-readable-output` adds timestamps and flags to ordinary
        // log messages. `>STATE:` records belong to the management interface,
        // so readiness must be detected from the log messages themselves.
        let mut connect_state: Option<OpenVpnStartupState> = None;
        let startup_deadline = Instant::now() + OPENVPN_STARTUP_TIMEOUT;
        loop {
            let start = pos;
            let x = logfile.read_line(&mut buffer)?;

            if x > 0 {
                debug!("{}", buffer[pos..].trim_end());
            }

            pos += x;

            for ip in parse_openvpn_dns_servers(&buffer[start..pos], &dns_regex) {
                if (ip.is_ipv4() || !network.disable_ipv6) && !openvpn_dns_servers.contains(&ip) {
                    debug!("Found OpenVPN DNS response: {ip}");
                    openvpn_dns_servers.push(ip);
                }
            }

            if let Some(state) = parse_openvpn_startup_state(&buffer[start..pos]) {
                debug!("OpenVPN startup state: {state:?}");
                connect_state = Some(state);
            }

            if connect_state.is_some() {
                break;
            }

            if let Some(status) = handle.try_wait()? {
                return Err(anyhow!(
                    "OpenVPN exited with {status} before the tunnel was established, use -v for full log output"
                ));
            }

            if Instant::now() >= startup_deadline {
                let _ = handle.kill();
                let _ = handle.wait();
                return Err(anyhow!(
                    "OpenVPN did not establish the tunnel within {} seconds, use -v for full log output",
                    OPENVPN_STARTUP_TIMEOUT.as_secs()
                ));
            }

            if x == 0 {
                std::thread::sleep(Duration::from_millis(50));
            }

            logfile.seek(SeekFrom::Start(pos as u64)).unwrap();
        }

        match connect_state {
            Some(OpenVpnStartupState::AuthFailed) => {
                let _ = handle.kill();
                let _ = handle.wait();
                let auth_path_display = auth_file
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "the auth file".to_string());
                let provider_hint = auth_file
                    .as_ref()
                    .filter(|path| path.components().any(|part| part.as_os_str() == "pia"))
                    .map(|_| {
                        " For PIA, use the VPN service username in the form p1234567 (not an email address), then rerun `vopono sync --protocol openvpn privateinternetaccess` to replace cached credentials."
                    })
                    .unwrap_or_default();
                error!(
                    "OpenVPN server rejected the username/password in {}.{}",
                    auth_path_display, provider_hint
                );
                return Err(anyhow!(
                    "OpenVPN server rejected the username/password in {}. DNS and transport settings do not cause AUTH_FAILED.{}",
                    auth_path_display,
                    provider_hint
                ));
            }
            Some(OpenVpnStartupState::OptionsError) => {
                let _ = handle.kill();
                let _ = handle.wait();
                error!("OpenVPN options error: {buffer}");
                return Err(anyhow!("OpenVPN options error, use -v for full log output"));
            }
            Some(OpenVpnStartupState::Connected) => {}
            None => unreachable!("startup loop only exits with a terminal state"),
        }

        let session = Self {
            pid: id,
            backend: OpenVpnBackend::OpenVpn2,
            openvpn_dns_servers,
            logfile: logfile_path,
            child: Some(handle),
            _runtime_dir: Some(runtime_dir),
            #[cfg(feature = "openvpn3")]
            ipc_stream: None,
            #[cfg(feature = "openvpn3")]
            reader_thread: None,
            cleanup_enabled: true,
        };
        network.apply_after_connect(netns)?;
        Ok(session)
    }

    #[cfg(feature = "openvpn3")]
    fn run_openvpn3(netns: &NetworkNamespace, run: OpenVpnRunConfig<'_>) -> anyhow::Result<Self> {
        let OpenVpnRunConfig {
            profile,
            auth_file,
            working_dir,
            runtime_dir,
            logfile,
            network,
            ..
        } = run;
        let helper = find_openvpn3_helper()?;
        let (username, password, auth_path) = read_openvpn3_credentials(auth_file, &profile)?;
        let (mut stream, helper_stream) =
            UnixStream::pair().context("Failed to create the OpenVPN 3 helper control socket")?;
        let helper_stream = if helper_stream.as_raw_fd() <= libc::STDERR_FILENO {
            // Stdio redirection in Command can replace descriptors 0 through
            // 2, so move the inherited endpoint above that range first.
            let fd = unsafe {
                libc::fcntl(
                    helper_stream.as_raw_fd(),
                    libc::F_DUPFD_CLOEXEC,
                    libc::STDERR_FILENO + 1,
                )
            };
            if fd == -1 {
                return Err(std::io::Error::last_os_error())
                    .context("Moving the OpenVPN 3 control socket descriptor");
            }
            // SAFETY: fcntl returned a new descriptor for this socket, and
            // ownership transfers to the new UnixStream here.
            unsafe { UnixStream::from_raw_fd(fd) }
        } else {
            helper_stream
        };
        let helper_fd = helper_stream.as_raw_fd();
        let helper_arg = helper.as_os_str().to_string_lossy().into_owned();
        let helper_fd_arg = helper_fd.to_string();
        let profile_arg = profile.as_os_str().to_string_lossy().into_owned();
        let command = [
            helper_arg.as_str(),
            "--ipc-fd",
            helper_fd_arg.as_str(),
            "--profile",
            profile_arg.as_str(),
        ];
        info!("Launching OpenVPN 3 Core helper...");
        let mut child = NetworkNamespace::exec_no_block_with_fds(
            &netns.name,
            &command,
            None,
            None,
            true,
            false,
            false,
            Some(working_dir),
            &[helper_fd],
        )
        .context("Failed to launch vopono-openvpn3-helper")?;
        drop(helper_stream);
        let id = child.id();

        let deadline = Instant::now() + OPENVPN_STARTUP_TIMEOUT;

        let start = OpenVpn3ControlMessage::Start {
            username: &username,
            password: &password,
            disable_ipv6: network.disable_ipv6,
        };
        let mut startup_message = match serde_json::to_vec(&start) {
            Ok(message) => message,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("Encoding OpenVPN 3 helper startup message");
            }
        };
        startup_message.push(b'\n');
        if let Err(error) = stream
            .write_all(&startup_message)
            .and_then(|()| stream.flush())
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("Sending startup data to OpenVPN 3 helper");
        }

        let reader_stream = match stream.try_clone() {
            Ok(stream) => stream,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("Cloning OpenVPN 3 helper control socket");
            }
        };
        let (sender, receiver) = mpsc::channel();
        let log_file = match File::options().append(true).open(&logfile) {
            Ok(file) => file,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("Opening OpenVPN 3 event log");
            }
        };
        let reader_thread = match std::thread::Builder::new()
            .name("vopono-openvpn3-ipc".to_string())
            .spawn(move || read_openvpn3_helper_messages(reader_stream, log_file, sender))
        {
            Ok(thread) => thread,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("Starting OpenVPN 3 helper event reader");
            }
        };

        let connection = match wait_for_openvpn3_connection(
            &mut child,
            &receiver,
            deadline,
            auth_path.as_deref(),
        ) {
            Ok(connection) => connection,
            Err(error) => {
                stop_openvpn3_helper(&mut child, Some(&mut stream));
                let _ = reader_thread.join();
                return Err(error);
            }
        };

        let mut openvpn_dns_servers = Vec::new();
        for ip in connection.dns_servers {
            if (ip.is_ipv4() || !network.disable_ipv6) && !openvpn_dns_servers.contains(&ip) {
                debug!("OpenVPN 3 supplied DNS server {ip}");
                openvpn_dns_servers.push(ip);
            }
        }
        info!(
            "OpenVPN 3 connected to {} ({}) on {} with IPv4 {} and IPv6 {}",
            connection.server_host,
            connection.server_ip,
            connection.tun_name,
            connection.vpn_ip4,
            connection.vpn_ip6
        );

        let session = Self {
            pid: id,
            backend: OpenVpnBackend::OpenVpn3,
            openvpn_dns_servers,
            logfile,
            child: Some(child),
            _runtime_dir: Some(runtime_dir),
            ipc_stream: Some(stream),
            reader_thread: Some(reader_thread),
            cleanup_enabled: true,
        };
        network.apply_after_connect(netns)?;
        Ok(session)
    }

    pub fn check_if_running(&self) -> bool {
        check_process_running(self.pid)
    }
}

impl Drop for OpenVpn {
    fn drop(&mut self) {
        if !self.cleanup_enabled {
            return;
        }

        #[cfg(feature = "openvpn3")]
        if self.backend == OpenVpnBackend::OpenVpn3 {
            if let Some(child) = self.child.as_mut() {
                stop_openvpn3_helper(child, self.ipc_stream.as_mut());
                debug!("Stopped OpenVPN 3 helper (pid: {})", self.pid);
            } else {
                kill_openvpn_process(self.pid);
            }
            self.ipc_stream = None;
            if let Some(reader_thread) = self.reader_thread.take() {
                let _ = reader_thread.join();
            }
        } else if let Some(child) = self.child.as_mut() {
            stop_openvpn2_process(child, self.pid);
        } else {
            kill_openvpn_process(self.pid);
        }

        #[cfg(not(feature = "openvpn3"))]
        if let Some(child) = self.child.as_mut() {
            stop_openvpn2_process(child, self.pid);
        } else {
            kill_openvpn_process(self.pid);
        }

        match std::fs::remove_file(&self.logfile) {
            Ok(_) => debug!(
                "Deleted OpenVPN logfile: {}",
                self.logfile.as_os_str().to_string_lossy()
            ),
            Err(e) => error!(
                "Failed to delete OpenVPN logfile: {}: {:?}",
                self.logfile.as_os_str().to_string_lossy(),
                e
            ),
        }
    }
}

fn kill_openvpn_process(pid: u32) {
    match nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGKILL,
    ) {
        Ok(()) => debug!("Killed OpenVPN (pid: {pid})"),
        Err(error) => error!("Failed to kill OpenVPN (pid: {pid}): {error:?}"),
    }
}

fn stop_openvpn2_process(child: &mut Child, pid: u32) {
    match child.try_wait() {
        Ok(Some(status)) => debug!("OpenVPN (pid: {pid}) exited with {status}"),
        Ok(None) => {
            if let Err(error) = child.kill() {
                error!("Failed to kill OpenVPN (pid: {pid}): {error:?}");
            }
            if let Err(error) = child.wait() {
                error!("Failed to reap OpenVPN (pid: {pid}): {error:?}");
            }
            debug!("Killed OpenVPN (pid: {pid})");
        }
        Err(error) => {
            error!("Failed to inspect OpenVPN (pid: {pid}): {error:?}");
            kill_openvpn_process(pid);
        }
    }
}

#[cfg(feature = "openvpn3")]
fn stop_openvpn3_helper(child: &mut Child, stream: Option<&mut UnixStream>) {
    if let Some(stream) = stream {
        let shutdown = OpenVpn3ControlMessage::Shutdown;
        if let Ok(mut message) = serde_json::to_vec(&shutdown) {
            message.push(b'\n');
            let _ = stream.write_all(&message);
            let _ = stream.flush();
        }
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => break,
            Err(error) => {
                debug!("Unable to inspect OpenVPN 3 helper process: {error}");
                break;
            }
        }
    }

    if let Err(error) = child.kill() {
        debug!("Unable to force-stop OpenVPN 3 helper: {error}");
    }
    let _ = child.wait();
}

#[cfg(feature = "openvpn3")]
struct OpenVpn3Connection {
    server_host: String,
    server_ip: String,
    tun_name: String,
    vpn_ip4: String,
    vpn_ip6: String,
    dns_servers: Vec<IpAddr>,
}

#[cfg(feature = "openvpn3")]
fn wait_for_openvpn3_connection(
    child: &mut Child,
    receiver: &Receiver<OpenVpn3HelperMessage>,
    deadline: Instant,
    auth_path: Option<&Path>,
) -> anyhow::Result<OpenVpn3Connection> {
    loop {
        match receiver.recv_timeout(Duration::from_millis(50)) {
            Ok(OpenVpn3HelperMessage::Event {
                name,
                info,
                error: _,
                fatal,
            }) => {
                if name == "AUTH_FAILED" {
                    let auth_path_display = auth_path
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "the supplied OpenVPN credentials".to_string());
                    let provider_hint = auth_path
                        .filter(|path| path.components().any(|part| part.as_os_str() == "pia"))
                        .map(|_| {
                            " For PIA, use the VPN service username in the form p1234567 (not an email address), then rerun `vopono sync --protocol openvpn privateinternetaccess` to replace cached credentials."
                        })
                        .unwrap_or_default();
                    anyhow::bail!(
                        "OpenVPN 3 server rejected the username/password in {auth_path_display}.{provider_hint}"
                    );
                }
                if fatal {
                    anyhow::bail!("OpenVPN 3 {name}: {info}");
                }
            }
            Ok(OpenVpn3HelperMessage::Connected {
                server_host,
                server_ip,
                tun_name,
                vpn_ip4,
                vpn_ip6,
                dns_servers,
            }) => {
                return Ok(OpenVpn3Connection {
                    server_host,
                    server_ip,
                    tun_name,
                    vpn_ip4,
                    vpn_ip6,
                    dns_servers,
                });
            }
            Ok(OpenVpn3HelperMessage::Error { message }) => {
                anyhow::bail!("OpenVPN 3 helper failed: {message}");
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                anyhow::bail!("OpenVPN 3 helper closed its control connection before connecting");
            }
        }

        if let Some(status) = child
            .try_wait()
            .context("Checking OpenVPN 3 helper process")?
        {
            anyhow::bail!(
                "OpenVPN 3 helper exited with {status} before the tunnel was established"
            );
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "OpenVPN 3 did not establish the tunnel within {} seconds",
                OPENVPN_STARTUP_TIMEOUT.as_secs()
            );
        }
    }
}

#[cfg(feature = "openvpn3")]
fn read_openvpn3_helper_messages(
    stream: UnixStream,
    mut log_file: File,
    sender: Sender<OpenVpn3HelperMessage>,
) {
    let mut reader = BufReader::new(stream);
    let mut sender = Some(sender);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                debug!("OpenVPN 3 helper IPC reader stopped: {error}");
                break;
            }
        }

        let message = match serde_json::from_str::<OpenVpn3HelperMessage>(&line) {
            Ok(message) => message,
            Err(error) => {
                error!("Invalid OpenVPN 3 helper message: {error}");
                continue;
            }
        };
        match &message {
            OpenVpn3HelperMessage::Event {
                name,
                info,
                error: is_error,
                fatal,
            } => {
                if *fatal || *is_error {
                    error!("OpenVPN 3 {name}: {info}");
                } else {
                    debug!("OpenVPN 3 {name}: {info}");
                }
            }
            OpenVpn3HelperMessage::Connected { .. } => {}
            OpenVpn3HelperMessage::Error { message } => error!("OpenVPN 3 helper: {message}"),
        }
        if let Err(error) = writeln!(log_file, "{message:?}") {
            debug!("Writing OpenVPN 3 helper log failed: {error}");
        }
        if let Some(tx) = sender.as_ref()
            && tx.send(message).is_err()
        {
            sender = None;
        }
    }
}

#[cfg(feature = "openvpn3")]
fn find_openvpn3_helper() -> anyhow::Result<PathBuf> {
    if let Ok(current_exe) = std::env::current_exe()
        && let Some(parent) = current_exe.parent()
    {
        let sibling = parent.join("vopono-openvpn3-helper");
        if sibling.is_file() {
            return Ok(sibling);
        }
    }

    which::which("vopono-openvpn3-helper").context(
        "OpenVPN 3 was selected but its helper executable is not installed; reinstall vopono with the `openvpn3` feature to install both executables",
    )
}

#[cfg(feature = "openvpn3")]
fn read_openvpn3_credentials(
    auth_file: Option<PathBuf>,
    config_file: &Path,
) -> anyhow::Result<(String, String, Option<PathBuf>)> {
    let auth_file = match auth_file {
        Some(path) => Some(resolve_openvpn_auth_path(path, config_file)),
        None => auth_file_from_config(config_file)?,
    };
    let Some(auth_file) = auth_file else {
        return Ok((String::new(), String::new(), None));
    };

    let auth_file = auth_file
        .canonicalize()
        .with_context(|| format!("OpenVPN auth file not found: {}", auth_file.display()))?;
    let file = File::open(&auth_file)
        .with_context(|| format!("Reading OpenVPN auth file: {}", auth_file.display()))?;
    let mut lines = BufReader::new(file).lines();
    let username = lines
        .next()
        .transpose()?
        .context("OpenVPN auth file is missing its username")?;
    let password = lines.next().transpose()?.unwrap_or_default();
    Ok((username, password, Some(auth_file)))
}

#[cfg(feature = "openvpn3")]
fn resolve_openvpn_auth_path(path: PathBuf, config_file: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        config_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path)
    }
}

#[cfg(feature = "openvpn3")]
fn auth_file_from_config(config_file: &Path) -> anyhow::Result<Option<PathBuf>> {
    let content = std::fs::read_to_string(config_file)
        .with_context(|| format!("Reading OpenVPN config file: {}", config_file.display()))?;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with(';') || trimmed.is_empty() {
            continue;
        }
        if trimmed.split_whitespace().next() != Some("auth-user-pass") {
            continue;
        }
        let words = shell_words::split(trimmed).context("Parsing auth-user-pass directive")?;
        if let Some(path) = words.get(1) {
            return Ok(Some(resolve_openvpn_auth_path(
                PathBuf::from(path),
                config_file,
            )));
        }
    }
    Ok(None)
}

impl OpenVpn {
    pub(crate) fn set_cleanup_enabled(&mut self, enabled: bool) {
        self.cleanup_enabled = enabled;
    }
}

pub fn killswitch(
    netns: &NetworkNamespace,
    _dns: &[IpAddr],
    remotes: &[Remote],
    firewall: Firewall,
    disable_ipv6: bool,
) -> anyhow::Result<()> {
    debug!("Setting OpenVPN killswitch....");
    let endpoints = resolve_remote_endpoints(remotes, disable_ipv6)?;

    match firewall {
        Firewall::IpTables => {
            let ipcmds: &[&str] = if disable_ipv6 {
                crate::network::firewall::disable_ipv6(netns, firewall)?;
                &["iptables"]
            } else {
                &["iptables", "ip6tables"]
            };

            for ipcmd in ipcmds {
                NetworkNamespace::exec(&netns.name, &[ipcmd, "-P", "INPUT", "DROP"])?;
                NetworkNamespace::exec(&netns.name, &[ipcmd, "-P", "FORWARD", "DROP"])?;
                NetworkNamespace::exec(&netns.name, &[ipcmd, "-P", "OUTPUT", "DROP"])?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        ipcmd,
                        "-A",
                        "INPUT",
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "RELATED,ESTABLISHED",
                        "-j",
                        "ACCEPT",
                    ],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[ipcmd, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[ipcmd, "-A", "INPUT", "-i", "tun+", "-j", "ACCEPT"],
                )?;
                NetworkNamespace::exec(
                    &netns.name,
                    &[ipcmd, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                )?;

                for endpoint in &endpoints {
                    let endpoint_ipcmd = if endpoint.address.is_ipv4() {
                        "iptables"
                    } else {
                        "ip6tables"
                    };
                    if endpoint_ipcmd != *ipcmd {
                        continue;
                    }

                    let protocol = endpoint.protocol.to_string();
                    let address = endpoint.address.to_string();
                    let port = endpoint.port.to_string();
                    NetworkNamespace::exec(
                        &netns.name,
                        &[
                            ipcmd,
                            "-A",
                            "OUTPUT",
                            "-p",
                            protocol.as_str(),
                            "-m",
                            protocol.as_str(),
                            "-d",
                            address.as_str(),
                            "--dport",
                            port.as_str(),
                            "-j",
                            "ACCEPT",
                        ],
                    )?;
                }

                if *ipcmd == "ip6tables" {
                    add_iptables_neighbor_discovery_rules(netns)?;
                }

                NetworkNamespace::exec(
                    &netns.name,
                    &[ipcmd, "-A", "OUTPUT", "-o", "tun+", "-j", "ACCEPT"],
                )?;
                let reject_type = if *ipcmd == "ip6tables" {
                    "icmp6-no-route"
                } else {
                    "icmp-net-unreachable"
                };
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        ipcmd,
                        "-A",
                        "OUTPUT",
                        "-j",
                        "REJECT",
                        "--reject-with",
                        reject_type,
                    ],
                )?;
            }
        }
        Firewall::NfTables => {
            if disable_ipv6 {
                crate::network::firewall::disable_ipv6(netns, firewall)?;
            }
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    "input",
                    "ct",
                    "state",
                    "related,established",
                    "counter",
                    "accept",
                ],
            )?;
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    "input",
                    "iifname",
                    "\"tun*\"",
                    "counter",
                    "accept",
                ],
            )?;

            if !disable_ipv6 {
                add_nft_neighbor_discovery_rules(netns)?;
            }

            for endpoint in &endpoints {
                let address_family = if endpoint.address.is_ipv4() {
                    "ip"
                } else {
                    "ip6"
                };
                let address = endpoint.address.to_string();
                let protocol = endpoint.protocol.to_string();
                let port = endpoint.port.to_string();
                NetworkNamespace::exec(
                    &netns.name,
                    &[
                        "nft",
                        "add",
                        "rule",
                        "inet",
                        &netns.name,
                        "output",
                        address_family,
                        "daddr",
                        address.as_str(),
                        protocol.as_str(),
                        "dport",
                        port.as_str(),
                        "counter",
                        "accept",
                    ],
                )?;
            }

            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    "output",
                    "oifname",
                    "\"tun*\"",
                    "counter",
                    "accept",
                ],
            )?;

            // Port-opening rules are inserted before this rule, so --open-ports,
            // --forward, and provider-assigned forwarded ports continue to work
            // while all other traffic remains blocked.
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    "input",
                    "counter",
                    "drop",
                ],
            )?;

            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    "output",
                    "counter",
                    "reject",
                    "with",
                    "icmpx",
                    "type",
                    "admin-prohibited",
                ],
            )?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct RemoteEndpoint {
    address: IpAddr,
    port: u16,
    protocol: OpenVpnProtocol,
}

fn resolve_remote_endpoints(
    remotes: &[Remote],
    disable_ipv6: bool,
) -> anyhow::Result<Vec<RemoteEndpoint>> {
    let mut endpoints = Vec::new();
    for remote in remotes {
        let addresses: Vec<IpAddr> = match &remote.host {
            Host::IPv4(address) => vec![IpAddr::V4(*address)],
            Host::IPv6(address) => vec![IpAddr::V6(*address)],
            Host::Hostname(hostname) => (hostname.as_str(), remote.port)
                .to_socket_addrs()
                .with_context(|| format!("Failed to resolve OpenVPN remote hostname {hostname}"))?
                .map(|address| address.ip())
                .collect(),
        };

        for address in addresses {
            if disable_ipv6 && address.is_ipv6() {
                continue;
            }
            if !endpoints.iter().any(|endpoint: &RemoteEndpoint| {
                endpoint.address == address
                    && endpoint.port == remote.port
                    && endpoint.protocol == remote.protocol
            }) {
                endpoints.push(RemoteEndpoint {
                    address,
                    port: remote.port,
                    protocol: remote.protocol.clone(),
                });
            }
        }
    }

    if endpoints.is_empty() {
        anyhow::bail!("OpenVPN has no usable remote endpoints after applying IPv6 settings");
    }
    Ok(endpoints)
}

fn add_iptables_neighbor_discovery_rules(netns: &NetworkNamespace) -> anyhow::Result<()> {
    let veth_ifname = netns
        .veth_pair
        .as_ref()
        .context("Veth pair not set while configuring OpenVPN IPv6 killswitch")?
        .source
        .as_str();

    for (chain, interface_flag) in [("INPUT", "-i"), ("OUTPUT", "-o")] {
        for icmpv6_type in ["135", "136"] {
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "ip6tables",
                    "-A",
                    chain,
                    interface_flag,
                    veth_ifname,
                    "-p",
                    "icmpv6",
                    "-m",
                    "icmp6",
                    "--icmpv6-type",
                    icmpv6_type,
                    "-j",
                    "ACCEPT",
                ],
            )
            .with_context(|| {
                format!("Allowing IPv6 neighbour discovery type {icmpv6_type} on {veth_ifname}")
            })?;
        }
    }
    Ok(())
}

fn add_nft_neighbor_discovery_rules(netns: &NetworkNamespace) -> anyhow::Result<()> {
    let veth_ifname = netns
        .veth_pair
        .as_ref()
        .context("Veth pair not set while configuring OpenVPN IPv6 killswitch")?
        .source
        .as_str();

    for (chain, interface_keyword) in [("input", "iifname"), ("output", "oifname")] {
        for icmpv6_type in ["nd-neighbor-solicit", "nd-neighbor-advert"] {
            NetworkNamespace::exec(
                &netns.name,
                &[
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    &netns.name,
                    chain,
                    interface_keyword,
                    veth_ifname,
                    "icmpv6",
                    "type",
                    icmpv6_type,
                    "counter",
                    "accept",
                ],
            )
            .with_context(|| {
                format!(
                    "Allowing IPv6 neighbour discovery type {icmpv6_type} on {veth_ifname} in nftables"
                )
            })?;
        }
    }
    Ok(())
}

fn parse_openvpn_dns_servers(log: &str, dns_regex: &Regex) -> Vec<IpAddr> {
    dns_regex
        .captures_iter(log)
        .filter_map(|cap| cap.get(1))
        .filter_map(|ipstr| IpAddr::from_str(ipstr.as_str()).ok())
        .fold(Vec::new(), |mut servers, server| {
            if !servers.contains(&server) {
                servers.push(server);
            }
            servers
        })
}

/// Terminal startup outcomes detected from OpenVPN's ordinary log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenVpnStartupState {
    Connected,
    AuthFailed,
    OptionsError,
}

/// Match stable OpenVPN messages anywhere in a line because
/// `--machine-readable-output` prefixes them with a timestamp and flags.
fn parse_openvpn_startup_state(log: &str) -> Option<OpenVpnStartupState> {
    if log.contains("AUTH_FAILED") {
        Some(OpenVpnStartupState::AuthFailed)
    } else if log.contains("Options error") {
        Some(OpenVpnStartupState::OptionsError)
    } else if log.contains("Initialization Sequence Completed") {
        Some(OpenVpnStartupState::Connected)
    } else {
        None
    }
}

pub fn warn_on_scripts_config(path: &Path) -> anyhow::Result<bool> {
    let mut out = false;
    let file_string =
        std::fs::read_to_string(path).context(format!("Reading OpenVPN config file: {path:?}"))?;
    for line in file_string.lines() {
        if line.trim().starts_with("up ") || line.trim().starts_with("down ") {
            log::error!(
                "up / down scripts detected in OpenVPN config file - remove these or OpenVPN will likely hang in the network namespace. Line: {line}"
            );
            out = true;
        }
    }
    Ok(out)
}

pub fn get_remotes_from_config(path: &Path) -> anyhow::Result<Vec<Remote>> {
    let file_string =
        std::fs::read_to_string(path).context(format!("Reading OpenVPN config file: {path:?}"))?;
    let mut output_vec = Vec::new();
    // Regex extract
    let re = Regex::new(r"(?m)^\s*remote ([^\s]+) ([0-9]+)\s?(tcp|udp|tcp-client)?")?;
    let caps = re.captures_iter(&file_string);

    let re2 = Regex::new(r"(?m)^\s*proto ([a-z\-]+)")?;
    let mut caps2 = re2.captures_iter(&file_string);
    let default_proto = caps2.next().and_then(|x| x.get(1));

    for cap in caps {
        let proto = match (cap.get(3), default_proto) {
            (None, None) => {
                return Err(anyhow!(
                    "No protocol given in OpenVPN config: {}",
                    path.display()
                ));
            }
            (Some(x), _) => OpenVpnProtocol::from_str(x.as_str()),
            (None, Some(x)) => OpenVpnProtocol::from_str(x.as_str()),
        }?;

        output_vec.push(Remote {
            host: Host::from_str(cap.get(1).unwrap().as_str()).expect("Could not convert hostname"),
            port: cap.get(2).unwrap().as_str().parse::<u16>()?,
            protocol: proto,
        });
    }

    if output_vec.is_empty() {
        return Err(anyhow!(
            "Failed to extract remotes from config file: {}",
            path.display()
        ));
    }
    Ok(output_vec)
}

#[derive(Debug)]
pub struct Remote {
    host: Host,
    pub port: u16,
    protocol: OpenVpnProtocol,
}

#[derive(Debug)]
pub enum Host {
    IPv4(std::net::Ipv4Addr),
    IPv6(std::net::Ipv6Addr),
    Hostname(String),
}

impl FromStr for Host {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(x) = s.parse() {
            Ok(Host::IPv4(x))
        } else if let Ok(x) = s.parse() {
            Ok(Host::IPv6(x))
        } else {
            Ok(Host::Hostname(s.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_pushed_ipv4_and_ipv6_dns_servers() {
        let dns_regex = Regex::new(r"dhcp-option (?:DNS6|DNS) ([^,\s']+)").unwrap();
        let log =
            "PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DNS6 fd00::53,route-gateway 10.8.0.1";

        assert_eq!(
            parse_openvpn_dns_servers(log, &dns_regex),
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
                IpAddr::V6("fd00::53".parse::<Ipv6Addr>().unwrap()),
            ]
        );
    }

    #[test]
    fn deduplicates_pushed_dns_servers() {
        let dns_regex = Regex::new(r"dhcp-option (?:DNS6|DNS) ([^,\s']+)").unwrap();
        let log = "PUSH_REPLY,dhcp-option DNS 10.8.0.1,dhcp-option DNS 10.8.0.1";

        assert_eq!(
            parse_openvpn_dns_servers(log, &dns_regex),
            vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1))]
        );
    }

    #[test]
    fn remote_endpoints_keep_only_enabled_address_families() {
        let remotes = vec![
            Remote {
                host: Host::IPv4(Ipv4Addr::new(192, 0, 2, 10)),
                port: 1194,
                protocol: OpenVpnProtocol::UDP,
            },
            Remote {
                host: Host::IPv6("2001:db8::10".parse().unwrap()),
                port: 1194,
                protocol: OpenVpnProtocol::UDP,
            },
        ];

        let endpoints = resolve_remote_endpoints(&remotes, true).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints[0].address,
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );

        let endpoints = resolve_remote_endpoints(&remotes, false).unwrap();
        assert_eq!(endpoints.len(), 2);
    }

    #[test]
    fn remote_endpoints_are_deduplicated() {
        let remotes = vec![
            Remote {
                host: Host::IPv4(Ipv4Addr::new(192, 0, 2, 10)),
                port: 1194,
                protocol: OpenVpnProtocol::UDP,
            },
            Remote {
                host: Host::IPv4(Ipv4Addr::new(192, 0, 2, 10)),
                port: 1194,
                protocol: OpenVpnProtocol::UDP,
            },
        ];

        assert_eq!(resolve_remote_endpoints(&remotes, false).unwrap().len(), 1);
    }

    #[test]
    fn parses_prefixed_connected_log_message() {
        let log = "1787685612.853245 0012 Initialization Sequence Completed";
        assert_eq!(
            parse_openvpn_startup_state(log),
            Some(OpenVpnStartupState::Connected)
        );
    }

    #[test]
    fn parses_prefixed_auth_failed_log_message() {
        let log = "1787685612.853245 0012 AUTH_FAILED";
        assert_eq!(
            parse_openvpn_startup_state(log),
            Some(OpenVpnStartupState::AuthFailed)
        );
    }

    #[test]
    fn parses_prefixed_options_error_log_message() {
        let log = "1787685612.853245 b000 Options error: Unrecognized option";
        assert_eq!(
            parse_openvpn_startup_state(log),
            Some(OpenVpnStartupState::OptionsError)
        );
    }

    #[test]
    fn ignores_non_terminal_log_lines() {
        assert_eq!(
            parse_openvpn_startup_state("TCP connection established"),
            None
        );
    }
}
