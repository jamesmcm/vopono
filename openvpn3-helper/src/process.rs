//! OpenVPN 3 session runtime owned by the isolated helper process.

use std::net::IpAddr;
use std::os::fd::{FromRawFd, RawFd};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use openvpn_connect::tokio::{Client, merge_config_path};
use openvpn_connect::{Config, Credentials, Event};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::watch;

use super::profile::{adapt_for_openvpn3, has_client_certificate_material};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ControlMessage {
    Start {
        username: String,
        password: String,
        disable_ipv6: bool,
    },
    Shutdown,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HelperMessage {
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

struct HelperProcess {
    ipc_fd: RawFd,
    profile: PathBuf,
}

pub(super) async fn run() -> anyhow::Result<()> {
    HelperProcess::parse_args()?.run().await
}

impl HelperProcess {
    fn parse_args() -> anyhow::Result<Self> {
        let mut args = std::env::args_os().skip(1);
        let mut ipc_fd = None;
        let mut profile = None;
        while let Some(option) = args.next() {
            match option.to_str() {
                Some("--ipc-fd") => {
                    ipc_fd = args.next().and_then(|value| {
                        value.to_str().and_then(|value| value.parse::<RawFd>().ok())
                    })
                }
                Some("--profile") => profile = args.next().map(PathBuf::from),
                _ => bail!("unknown or incomplete helper argument: {option:?}"),
            }
        }
        Ok(Self {
            ipc_fd: ipc_fd.context("missing or invalid --ipc-fd")?,
            profile: profile.context("missing --profile")?,
        })
    }

    async fn run(self) -> anyhow::Result<()> {
        // SAFETY: vopono passes one end of an AF_UNIX socketpair as --ipc-fd
        // and clears CLOEXEC on that descriptor before entering this process.
        let control_socket = unsafe { std::os::unix::net::UnixStream::from_raw_fd(self.ipc_fd) };
        control_socket
            .set_nonblocking(true)
            .context("Setting the inherited control socket nonblocking")?;
        let stream = UnixStream::from_std(control_socket)
            .context("Registering the inherited control socket with Tokio")?;
        let (read_half, mut write_half) = stream.into_split();
        let mut control_reader = BufReader::new(read_half);

        let first = Self::read_control_message(&mut control_reader)
            .await?
            .context("vopono closed the control socket before startup")?;
        let ControlMessage::Start {
            username,
            password,
            disable_ipv6,
        } = first
        else {
            bail!("the first helper control message must be Start");
        };

        let result = self
            .run_session(
                username,
                password,
                disable_ipv6,
                control_reader,
                &mut write_half,
            )
            .await;
        if let Err(error) = &result {
            let _ = Self::write_message(
                &mut write_half,
                &HelperMessage::Error {
                    message: format!("{error:#}"),
                },
            )
            .await;
        }
        result
    }

    async fn run_session(
        &self,
        username: String,
        password: String,
        disable_ipv6: bool,
        control_reader: BufReader<OwnedReadHalf>,
        writer: &mut OwnedWriteHalf,
    ) -> anyhow::Result<()> {
        let merged = merge_config_path(self.profile.to_string_lossy().into_owned(), true)
            .await
            .context("Loading OpenVPN profile and referenced files")?;
        if !merged.error_text.is_empty() {
            bail!("Merging OpenVPN profile failed: {}", merged.error_text);
        }
        let mut profile_content = merged.profile_content;
        if disable_ipv6 {
            profile_content
                .push_str("\npull-filter ignore ifconfig-ipv6\npull-filter ignore route-ipv6\n");
        }
        let (profile_content, removed_ping_timer_rem) = adapt_for_openvpn3(&profile_content);
        if removed_ping_timer_rem {
            Self::write_message(
            writer,
            &HelperMessage::Event {
                name: "OPTION_ADAPTED".to_string(),
                info: "Removed ping-timer-rem: it only affects listen-mode profiles without an explicit remote".to_string(),
                error: false,
                fatal: false,
            },
        )
        .await
        .context("Reporting an OpenVPN 3 profile compatibility adjustment")?;
        }

        let mut config = Config::new(profile_content);
        // OpenVPN Core treats a client profile with no cert/key as external PKI
        // unless client-certificate use is explicitly disabled. Many commercial
        // provider profiles, including NordVPN's, use username/password auth and
        // intentionally have no client certificate or key.
        config.disable_client_cert = !has_client_certificate_material(&config.content);
        // Linux Core emits this structured capture after processing pushed route
        // and DNS options. vopono uses those DNS addresses for its namespace DNS
        // configuration while Core owns the native TUN device and routes.
        config.generate_tun_builder_capture_event = true;

        let client = Client::without_callbacks().context("Creating OpenVPN 3 client")?;
        let evaluation = client
            .evaluate(config)
            .await
            .context("Evaluating OpenVPN 3 profile")?;
        if !evaluation.autologin {
            if username.is_empty() {
                bail!(
                    "this profile requires credentials; pass --auth-user-pass or add auth-user-pass <file> to the profile"
                );
            }
            client
                .provide_credentials(Credentials::new(username, password))
                .await
                .context("Providing OpenVPN credentials")?;
        }

        let (shutdown_sender, mut shutdown_receiver) = watch::channel(false);
        tokio::spawn(Self::watch_for_shutdown(control_reader, shutdown_sender));

        let mut events = client.subscribe_events();
        let session = client
            .connect()
            .await
            .context("Starting OpenVPN 3 session")?;
        let handle = session.handle();
        tokio::pin!(session);
        let timeout = tokio::time::sleep(STARTUP_TIMEOUT);
        tokio::pin!(timeout);

        let mut connected = false;
        let mut control_open = true;
        let mut dns_servers = Vec::new();
        loop {
            tokio::select! {
                event = events.recv() => {
                    let event = match event {
                        Ok(event) => event,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            bail!("OpenVPN 3 event stream closed")
                        }
                    };
                    if event.name == "TUN_BUILDER_CAPTURE" {
                        dns_servers = Self::dns_from_tun_capture(&event.info);
                    }
                    if let Err(error) =
                        Self::write_message(writer, &Self::event_message(&event)).await
                        && !connected
                        && control_open
                    {
                        return Err(error);
                    }

                    if event.name == "AUTH_FAILED" {
                        bail!("OpenVPN 3 server rejected the supplied username/password")
                    }
                    if event.fatal {
                        bail!("OpenVPN 3 {}: {}", event.name, event.info)
                    }
                    if event.name == "CONNECTED" && !connected {
                        let info = handle
                            .connection_info()
                            .await
                            .context("Querying OpenVPN 3 connection details")?
                            .context("OpenVPN 3 reported CONNECTED without connection details")?;
                        if let Err(error) = Self::write_message(
                            writer,
                            &HelperMessage::Connected {
                                server_host: info.server_host,
                                server_ip: info.server_ip,
                                tun_name: info.tun_name,
                                vpn_ip4: info.vpn_ip4,
                                vpn_ip6: info.vpn_ip6,
                                dns_servers: std::mem::take(&mut dns_servers),
                            },
                        )
                        .await
                            && control_open
                        {
                            return Err(error);
                        }
                        connected = true;
                    }
                }
                changed = shutdown_receiver.changed(), if control_open => {
                    if changed.is_ok() && *shutdown_receiver.borrow() {
                        let _ = handle.stop().await;
                        let _ = (&mut session).await;
                        return Ok(());
                    }
                    control_open = changed.is_ok();
                }
                result = &mut session => {
                    match result {
                        Ok(status) if connected => {
                            Self::write_message(
                                writer,
                                &HelperMessage::Event {
                                    name: "DISCONNECTED".to_string(),
                                    info: format!("{}: {}", status.status, status.message),
                                    error: false,
                                    fatal: false,
                                },
                            )
                            .await?;
                            return Ok(());
                        }
                        Ok(status) => bail!(
                            "OpenVPN 3 session ended before connecting: {}: {}",
                            status.status,
                            status.message
                        ),
                        Err(error) => return Err(error.into()),
                    }
                }
                _ = &mut timeout, if !connected => {
                    let _ = handle.stop().await;
                    let _ = (&mut session).await;
                    bail!("OpenVPN 3 did not establish the tunnel within {} seconds", STARTUP_TIMEOUT.as_secs())
                }
            }
        }
    }

    async fn watch_for_shutdown(mut reader: BufReader<OwnedReadHalf>, sender: watch::Sender<bool>) {
        loop {
            let message = match Self::read_control_message(&mut reader).await {
                Ok(Some(message)) => message,
                // Closing the control socket detaches the helper. vopono sends
                // an explicit Shutdown message when it owns namespace teardown.
                Ok(None) | Err(_) => return,
            };
            if matches!(message, ControlMessage::Shutdown) {
                let _ = sender.send(true);
                return;
            }
        }
    }

    async fn read_control_message(
        reader: &mut BufReader<OwnedReadHalf>,
    ) -> anyhow::Result<Option<ControlMessage>> {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(None);
        }
        Ok(Some(
            serde_json::from_str(&line).context("Decoding helper control message")?,
        ))
    }

    async fn write_message<W: AsyncWrite + Unpin>(
        writer: &mut W,
        message: &HelperMessage,
    ) -> anyhow::Result<()> {
        let mut line = serde_json::to_vec(message)?;
        line.push(b'\n');
        writer.write_all(&line).await?;
        writer.flush().await?;
        Ok(())
    }

    fn event_message(event: &Event) -> HelperMessage {
        HelperMessage::Event {
            name: event.name.clone(),
            info: event.info.clone(),
            error: event.error,
            fatal: event.fatal,
        }
    }

    fn dns_from_tun_capture(info: &str) -> Vec<IpAddr> {
        let Ok(capture) = serde_json::from_str::<serde_json::Value>(info) else {
            return Vec::new();
        };
        let Some(servers) = capture
            .get("dns_options")
            .and_then(|options| options.get("servers"))
            .and_then(serde_json::Value::as_object)
        else {
            return Vec::new();
        };

        let mut dns_servers = Vec::new();
        for server in servers.values() {
            let Some(addresses) = server
                .get("addresses")
                .and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            for address in addresses {
                let Some(address) = address
                    .get("address")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|address| address.parse::<IpAddr>().ok())
                else {
                    continue;
                };
                if !dns_servers.contains(&address) {
                    dns_servers.push(address);
                }
            }
        }
        dns_servers
    }
}
