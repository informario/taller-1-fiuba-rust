use std::net::{SocketAddr, ToSocketAddrs};

pub fn discover(dns_server: &str, port: &str) -> Result<Vec<SocketAddr>, std::io::Error> {
    let mut socket_addresses = Vec::<SocketAddr>::new();
    socket_addresses.extend(
        (dns_server.to_string() + ":" + port)
            .to_socket_addrs()?
            .collect::<Vec<_>>(),
    );
    Ok(socket_addresses)
}
