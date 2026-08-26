use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread::JoinHandle;
use std::time::Duration;

const MAX_PROXY_CONNECTIONS: usize = 64;

/// Host-side TCP forwarder with bounded connection concurrency.
///
/// Dropping the proxy stops its accept loop and all active relays.
pub struct TcpProxy {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

struct ConnectionSlot(Arc<AtomicUsize>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn relay_stream(
    mut reader: std::net::TcpStream,
    mut writer: std::net::TcpStream,
    stop: &AtomicBool,
) {
    let mut buffer = [0_u8; 16 * 1024];
    let reached_eof = 'relay: loop {
        if stop.load(Ordering::Acquire) {
            break false;
        }
        match reader.read(&mut buffer) {
            Ok(0) => break true,
            Ok(count) => {
                let mut written = 0;
                while written < count && !stop.load(Ordering::Acquire) {
                    match writer.write(&buffer[written..count]) {
                        Ok(0) => break 'relay false,
                        Ok(bytes) => written += bytes,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => break 'relay false,
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break false,
        }
    };

    // EOF in one direction is a TCP half-close, not a reason to discard data
    // still flowing in the other direction. Propagate the FIN and let the
    // connection worker wait for both relays to finish. A fatal I/O error or
    // explicit proxy stop instead closes this side completely, which wakes the
    // opposite relay rather than leaving a worker blocked indefinitely.
    let shutdown = if reached_eof {
        std::net::Shutdown::Write
    } else {
        std::net::Shutdown::Both
    };
    let _ = writer.shutdown(shutdown);
}

impl TcpProxy {
    pub fn new(listen_port: u16, proxy_to: SocketAddr, local_only: bool) -> anyhow::Result<Self> {
        let ip = if local_only {
            Ipv6Addr::LOCALHOST
        } else {
            Ipv6Addr::UNSPECIFIED
        };
        let listener = std::net::TcpListener::bind(SocketAddr::new(IpAddr::V6(ip), listen_port))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let active = Arc::new(AtomicUsize::new(0));
        let workers = Arc::new(Mutex::new(Vec::<JoinHandle<()>>::new()));
        let thread_workers = Arc::clone(&workers);
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                let client = match listener.accept() {
                    Ok((client, _)) => client,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(25));
                        continue;
                    }
                    Err(_) => break,
                };
                let admitted = active
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                        (count < MAX_PROXY_CONNECTIONS).then_some(count + 1)
                    })
                    .is_ok();
                if !admitted {
                    log::warn!(
                        "Rejecting forwarded connection: limit of {MAX_PROXY_CONNECTIONS} reached"
                    );
                    continue;
                }
                let slot = ConnectionSlot(Arc::clone(&active));
                let Ok(upstream) =
                    std::net::TcpStream::connect_timeout(&proxy_to, Duration::from_secs(1))
                else {
                    continue;
                };
                let client_to_upstream = match client.try_clone() {
                    Ok(client) => client,
                    Err(_) => continue,
                };
                let upstream_to_upstream = match upstream.try_clone() {
                    Ok(upstream) => upstream,
                    Err(_) => continue,
                };
                let upstream_to_client = match upstream.try_clone() {
                    Ok(upstream) => upstream,
                    Err(_) => continue,
                };
                let client_to_client = match client.try_clone() {
                    Ok(client) => client,
                    Err(_) => continue,
                };
                for stream in [&client, &upstream] {
                    let timeout = Some(Duration::from_millis(250));
                    let _ = stream.set_read_timeout(timeout);
                    let _ = stream.set_write_timeout(timeout);
                }
                let connection_stop = Arc::clone(&thread_stop);
                let worker = std::thread::spawn(move || {
                    let reverse_stop = Arc::clone(&connection_stop);
                    let reverse = std::thread::spawn(move || {
                        relay_stream(upstream_to_client, client_to_client, &reverse_stop);
                    });
                    relay_stream(client_to_upstream, upstream_to_upstream, &connection_stop);
                    let _ = reverse.join();
                    let _ = client.shutdown(std::net::Shutdown::Both);
                    let _ = upstream.shutdown(std::net::Shutdown::Both);
                    drop(slot);
                });
                let mut handles = thread_workers.lock().expect("proxy worker lock poisoned");
                let mut index = 0;
                while index < handles.len() {
                    if handles[index].is_finished() {
                        let handle = handles.swap_remove(index);
                        let _ = handle.join();
                    } else {
                        index += 1;
                    }
                }
                handles.push(worker);
            }
        });
        Ok(Self {
            stop,
            thread: Some(thread),
            workers,
        })
    }
}

impl Drop for TcpProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        for worker in self
            .workers
            .lock()
            .expect("proxy worker lock poisoned")
            .drain(..)
        {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TcpProxy;
    use std::io::{Read, Write};
    use std::time::Duration;

    #[test]
    fn drop_stops_accept_thread() {
        let Ok(reservation) = std::net::TcpListener::bind("[::1]:0") else {
            // The production proxy is IPv6-based; skip on kernels where IPv6
            // has been disabled entirely.
            return;
        };
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);

        let proxy = TcpProxy::new(port, "[::1]:9".parse().unwrap(), true).unwrap();
        let started = std::time::Instant::now();
        drop(proxy);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn preserves_response_after_client_half_close() {
        let Ok(upstream) = std::net::TcpListener::bind("[::1]:0") else {
            // The production proxy is IPv6-based; skip on kernels where IPv6
            // has been disabled entirely.
            return;
        };
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_thread = std::thread::spawn(move || {
            let (mut connection, _) = upstream.accept().unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            connection.read_to_end(&mut request).unwrap();
            assert_eq!(request, b"request");
            connection.write_all(b"complete response").unwrap();
        });

        let reservation = std::net::TcpListener::bind("[::1]:0").unwrap();
        let proxy_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let proxy = TcpProxy::new(proxy_port, upstream_addr, true).unwrap();

        let mut client = std::net::TcpStream::connect(("::1", proxy_port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"request").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        assert_eq!(response, b"complete response");
        upstream_thread.join().unwrap();
        drop(proxy);
    }
}
