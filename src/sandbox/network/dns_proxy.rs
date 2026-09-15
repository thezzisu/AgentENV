//! Namespace-local DNS sockets with upstream sockets opened in the host network.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};
use nix::sched::{setns, CloneFlags};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::debug;

pub(super) const DNS_PORT: u16 = 1053;
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_IN_FLIGHT: usize = 64;

#[derive(Debug)]
pub(super) struct DnsProxy {
    stop: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl DnsProxy {
    pub(super) fn start(namespace: &Path, tap_ip: Ipv4Addr) -> Result<Self> {
        let namespace = std::fs::File::open(namespace)?;
        let host = super::slot::host_ns_fd();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (stop, stopped) = oneshot::channel();
        let join = thread::Builder::new()
            .name("aenv-dns".into())
            .spawn(move || {
                let setup = (|| -> Result<_> {
                    setns(namespace.as_fd(), CloneFlags::CLONE_NEWNET)?;
                    let udp = std::net::UdpSocket::bind((tap_ip, DNS_PORT))?;
                    let tcp = std::net::TcpListener::bind((tap_ip, DNS_PORT))?;
                    udp.set_nonblocking(true)?;
                    tcp.set_nonblocking(true)?;
                    // Bound sockets retain their namespace. Every upstream socket
                    // below is created after returning to the host namespace.
                    setns(host, CloneFlags::CLONE_NEWNET)?;
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    let _guard = runtime.enter();
                    Ok((
                        UdpSocket::from_std(udp)?,
                        TcpListener::from_std(tcp)?,
                        runtime,
                    ))
                })();
                match setup {
                    Ok((udp, tcp, runtime)) => {
                        let _ = ready_tx.send(Ok(()));
                        runtime.block_on(serve(udp, tcp, stopped));
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                    }
                }
            })
            .context("spawn guest DNS proxy")?;
        let proxy = Self {
            stop: Some(stop),
            join: Some(join),
        };
        ready_rx.recv().context("start guest DNS proxy")??;
        Ok(proxy)
    }
}

impl Drop for DnsProxy {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn nameservers(contents: &str) -> Vec<SocketAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next()? != "nameserver" {
                return None;
            }
            let ip: IpAddr = parts.next()?.parse().ok()?;
            (!ip.is_unspecified()).then_some(SocketAddr::new(ip, 53))
        })
        .collect()
}

async fn host_nameservers() -> Result<Vec<SocketAddr>> {
    // Use the host stub when present: it owns split DNS, including VPN domains.
    // Read for each exchange so resolver changes don't require a sandbox restart.
    let text = tokio::fs::read_to_string("/etc/resolv.conf").await?;
    let servers = nameservers(&text);
    anyhow::ensure!(
        !servers.is_empty(),
        "host resolv.conf contains no DNS servers"
    );
    Ok(servers)
}

async fn exchange(query: &[u8], server: SocketAddr, tcp: bool) -> Result<Vec<u8>> {
    anyhow::ensure!(
        query.len() >= 12 && query[2] & 0x80 == 0,
        "invalid DNS query"
    );
    let response = if tcp {
        let mut stream = TcpStream::connect(server).await?;
        stream.write_u16(query.len() as u16).await?;
        stream.write_all(query).await?;
        let len = stream.read_u16().await? as usize;
        let mut response = vec![0; len];
        stream.read_exact(&mut response).await?;
        response
    } else {
        let bind = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(server).await?;
        socket.send(query).await?;
        let mut response = vec![0; 65535];
        let len = socket.recv(&mut response).await?;
        response.truncate(len);
        response
    };
    anyhow::ensure!(
        response.len() >= 12 && response[..2] == query[..2] && response[2] & 0x80 != 0,
        "invalid DNS response"
    );
    Ok(response)
}

async fn forward(query: &[u8], tcp: bool) -> Result<Vec<u8>> {
    for server in host_nameservers().await? {
        match tokio::time::timeout(QUERY_TIMEOUT, exchange(query, server, tcp)).await {
            Ok(Ok(response)) => return Ok(response),
            result => debug!(%server, ?result, "host DNS exchange failed"),
        }
    }
    anyhow::bail!("host DNS servers unavailable")
}

async fn serve(udp: UdpSocket, tcp: TcpListener, mut stopped: oneshot::Receiver<()>) {
    let udp = Arc::new(udp);
    let mut tasks = JoinSet::new();
    let mut buffer = vec![0; 65535];
    loop {
        tokio::select! {
            _ = &mut stopped => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            result = udp.recv_from(&mut buffer) => {
                let Ok((len, peer)) = result else { break; };
                if tasks.len() >= MAX_IN_FLIGHT { continue; }
                let query = buffer[..len].to_vec();
                let udp = udp.clone();
                tasks.spawn(async move {
                    if let Ok(response) = forward(&query, false).await {
                        let _ = udp.send_to(&response, peer).await;
                    }
                });
            }
            result = tcp.accept() => {
                let Ok((mut stream, _)) = result else { break; };
                if tasks.len() >= MAX_IN_FLIGHT { continue; }
                tasks.spawn(async move {
                    // Bound idle time and connection lifetime, including slow readers.
                    let _ = tokio::time::timeout(Duration::from_secs(30), async move {
                        loop {
                            let len = match stream.read_u16().await {
                                Ok(len) => len as usize,
                                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                                Err(error) => return Err(error.into()),
                            };
                            let mut query = vec![0; len];
                            stream.read_exact(&mut query).await?;
                            let response = forward(&query, true).await?;
                            stream.write_u16(response.len() as u16).await?;
                            stream.write_all(&response).await?;
                        }
                        Ok::<(), anyhow::Error>(())
                    }).await;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_stub_and_ipv6_are_preserved() {
        assert_eq!(
            nameservers("# host DNS\nnameserver 127.0.0.53\nnameserver ::1\nnameserver invalid\n"),
            vec![
                "127.0.0.53:53".parse().unwrap(),
                "[::1]:53".parse().unwrap()
            ]
        );
    }

    #[tokio::test]
    async fn forwards_udp_and_tcp_without_rewriting_records() -> Result<()> {
        let query = vec![0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut response = query.clone();
        response[2] = 0x81;
        response[3] = 0x83; // NXDOMAIN must be preserved.
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let address = udp.local_addr()?;
        let reply = response.clone();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 512];
            let (_, peer) = udp.recv_from(&mut buffer).await.unwrap();
            udp.send_to(&reply, peer).await.unwrap();
        });
        assert_eq!(exchange(&query, address, false).await?, response);
        task.await?;
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let address = tcp.local_addr()?;
        let reply = response.clone();
        let task = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let len = stream.read_u16().await.unwrap();
            let mut data = vec![0; len as usize];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_u16(reply.len() as u16).await.unwrap();
            stream.write_all(&reply).await.unwrap();
        });
        assert_eq!(exchange(&query, address, true).await?, response);
        task.await?;
        Ok(())
    }
}
