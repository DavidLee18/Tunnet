//! Inbound stream acceptor: TCP-proxy to the destination in the stream header.
//! Used when a client opens a stream to a subnet/hostname-route target via this gateway.
//!
//! Direct SDK `open_stream("picwmc", 443)` sends this node's mesh hostname in the header.
//! That is not a LAN/hostname-route advertisement; map it (and loopback) to `127.0.0.1`.

use std::sync::Arc;

use tokio::net::TcpStream;

use crate::routing::RoutingTable;
use crate::stream::{AcceptedStream, StreamHandler, splice_bidirectional};

pub fn stream_handler(routes: RoutingTable) -> StreamHandler {
    Arc::new(move |accepted| {
        let routes = routes.clone();
        Box::pin(async move {
            handle_accepted(accepted, &routes).await;
        })
    })
}

/// TCP connect host for an inbound stream header, or `None` to refuse.
pub(crate) fn resolve_connect_host(host: &str, routes: &RoutingTable) -> Option<String> {
    if routes.is_local_stream_target(host) {
        return Some("127.0.0.1".into());
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        if routes.is_advertised_destination(&ip) {
            return Some(host.to_string());
        }
        return None;
    }
    if let Some(info) = routes.lookup_hostname_route(host) {
        if !routes.is_advertised_hostname(host) {
            return None;
        }
        return Some(
            info.target_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| host.to_string()),
        );
    }
    if routes.is_advertised_hostname(host) {
        return Some(host.to_string());
    }
    None
}

async fn handle_accepted(accepted: AcceptedStream, routes: &RoutingTable) {
    let host = accepted.header.host.clone();
    let port = accepted.header.dst_port;
    let peer_hex = accepted.peer_hex;

    if host == crate::ping::PING_HOST {
        let _ =
            crate::ping::handle_inbound_ping(&accepted.header, accepted.send, accepted.recv).await;
        return;
    }

    let Some(connect_host) = resolve_connect_host(&host, routes) else {
        tracing::warn!(%peer_hex, %host, port, "refusing stream: destination not routable here");
        return;
    };

    let addr = format!("{connect_host}:{port}");
    let tcp = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%peer_hex, %addr, ?e, "TCP connect failed for inbound stream");
            return;
        }
    };
    if let Err(e) = tcp.set_nodelay(true) {
        tracing::debug!(?e, "set_nodelay failed");
    }

    tracing::info!(%peer_hex, %addr, "proxying inbound stream to LAN/target");
    let (tcp_read, tcp_write) = tcp.into_split();
    if let Err(e) = splice_bidirectional(accepted.recv, accepted.send, tcp_read, tcp_write).await {
        tracing::debug!(%peer_hex, %addr, ?e, "stream proxy closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnet_common::{DeviceProfile, DnsConfig, PeerEntry};
    use uuid::Uuid;

    use crate::routing::RoutingTable;

    fn peer(endpoint: &str, ip: &str, hostname: &str) -> PeerEntry {
        PeerEntry {
            ip: ip.parse().unwrap(),
            endpoint_id: endpoint.to_string(),
            hostname: hostname.to_string(),
            tags: vec![],
            ssh_host_key: None,
        }
    }

    fn picwmc_table() -> RoutingTable {
        let table = RoutingTable::new();
        let self_id = "a".repeat(64);
        table.replace(
            &[
                peer(&self_id, "100.92.231.93", "picwmc"),
                peer(&"b".repeat(64), "100.105.214.184", "brcwmc"),
            ],
            &[],
            &[],
            &[],
            &DeviceProfile::default(),
            &DnsConfig::default(),
            "lav",
            Uuid::nil(),
            &self_id,
            1,
        );
        table
    }

    #[test]
    fn sdk_open_stream_to_own_hostname_is_loopback() {
        let table = picwmc_table();
        assert_eq!(
            resolve_connect_host("picwmc", &table).as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            resolve_connect_host("picwmc.lav.tunnet", &table).as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            resolve_connect_host("100.92.231.93", &table).as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            resolve_connect_host("127.0.0.1", &table).as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            resolve_connect_host("localhost", &table).as_deref(),
            Some("127.0.0.1")
        );
    }

    #[test]
    fn other_mesh_hostname_is_refused() {
        let table = picwmc_table();
        assert_eq!(resolve_connect_host("brcwmc", &table), None);
        assert_eq!(resolve_connect_host("8.8.8.8", &table), None);
    }
}
