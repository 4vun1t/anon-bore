//! A modern, simple TCP tunnel in Rust that exposes local ports to a remote
//! server, bypassing standard NAT connection firewalls.
//!
//! This is the library crate documentation. If you're looking for usage
//! information about the binary, see the command below.
//!
//! ```shell
//! $ bore help
//! ```
//!
//! There are two components to the crate, offering implementations of the
//! server network daemon and client local forwarding proxy. Both are public
//! members and can be run programmatically with a Tokio 1.0 runtime.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod client;
pub mod server;
pub mod shared;

use anyhow::{Context as AnyContext, Result, bail};
use arti_client::{TorClient, TorClientConfig};
use tokio::io::AsyncWriteExt;
use tor_rtcompat::PreferredRuntime;
use tracing::{error, info, warn};
use uuid::Uuid;

use client::{connect_local, connect_remote};
use shared::{ClientMessage, Delimited, ServerMessage, CONTROL_PORT};

/// Expose a local port to the internet via the default bore server (`bore.pub`).
///
/// All traffic between this client and the remote server is routed through
/// the Tor network. Proxying happens automatically in the background; the
/// returned future resolves once the port is registered.
///
/// Returns the `(hostname, port)` of the public endpoint.
pub async fn expose(hostname: &str, port: u16) -> Result<(String, u16)> {
    expose_to(hostname, port, "bore.pub").await
}

/// Like [`expose`], but connects to a custom server address.
pub async fn expose_to(hostname: &str, port: u16, to: &str) -> Result<(String, u16)> {
    let local_host = hostname.to_string();
    let local_port = port;
    let to = to.to_string();

    let tor_config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(tor_config)
        .await
        .context("failed to bootstrap Tor client")?;

    let stream = connect_remote(&tor_client, &to, CONTROL_PORT).await?;
    let mut stream = Delimited::new(stream);

    stream.send(ClientMessage::Hello(0)).await?;
    let remote_port = match stream.recv_timeout().await? {
        Some(ServerMessage::Hello(port)) => port,
        Some(ServerMessage::Error(msg)) => bail!("server error: {msg}"),
        _ => bail!("unexpected response from server"),
    };

    let tc = tor_client.clone();
    let to2 = to.clone();
    tokio::spawn(async move {
        loop {
            match stream.recv().await {
                Ok(Some(ServerMessage::Connection(id))) => {
                    let t = tc.clone();
                    let lh = local_host.clone();
                    if let Err(e) = proxy_one(t, &to2, id, &lh, local_port).await {
                        warn!(%e, "failed to proxy connection");
                    }
                }
                Ok(Some(ServerMessage::Heartbeat)) => {}
                Ok(Some(ServerMessage::Error(e))) => {
                    error!(%e, "server error, shutting down proxy");
                    break;
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(%e, "control connection error");
                    break;
                }
                _ => {}
            }
        }
    });

    info!("exposed {hostname}:{port} at {to}:{remote_port}");
    Ok((to, remote_port))
}

async fn proxy_one(
    tor_client: TorClient<PreferredRuntime>,
    to: &str,
    id: Uuid,
    local_host: &str,
    local_port: u16,
) -> Result<()> {
    let stream = connect_remote(&tor_client, to, CONTROL_PORT).await?;
    let mut remote_conn = Delimited::new(stream);
    remote_conn.send(ClientMessage::Accept(id)).await?;
    let mut local_conn = connect_local(local_host, local_port).await?;
    let mut parts = remote_conn.into_parts();
    local_conn.write_all(&parts.read_buf).await?;
    tokio::io::copy_bidirectional(&mut local_conn, &mut parts.io).await?;
    Ok(())
}
