use async_std::prelude::*;
use clap::{Arg, App, SubCommand, crate_name, crate_version, crate_authors};
use std::io;
use std::error::Error;
use async_std::net;
use std::collections::HashMap;
use std::collections::hash_map;

struct Peer {
    last_contact: Option<std::time::Instant>,
    last_addr: net::SocketAddr,
}

struct Kad {
    rx_buf: Vec<u8>,
    socket: net::UdpSocket,

    // XXX: consider if SocketAddr is the right key. We may have Peers that roam (get a different
    // IP address/port). We can identify this by using some features within the emule/kad protocol.
    //
    // Right now, we'll treat independent addresses as independent peers.
    peers: HashMap<net::SocketAddr, Peer>,
}

impl Kad {
    async fn from_addr<A: net::ToSocketAddrs>(addrs: A) -> Result<Kad, io::Error> {
        let socket = net::UdpSocket::bind(addrs).await?;
        Ok(Kad {
            socket,
            rx_buf: vec![0u8;1024],
            peers: HashMap::default(),
        })
    }

    async fn process_rx(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            let (recv, peer) = self.socket.recv_from(&mut self.rx_buf).await?;
            // TODO: on linux we can use SO_TIMESTAMPING and recvmsg() to get more accurate timestamps
            let ts = std::time::Instant::now();
            
            // examine packet and decide if it looks like a valid emule/kad packet
        

            match self.peers.entry(peer) {
                hash_map::Entry::Occupied(occupied) => {},
                hash_map::Entry::Vacant(vacant) => {},
            }
        }
    }

    async fn send_stuff(&mut self) -> Result<(), Box<dyn Error>> {
        // XXX: maybe we can integrate this with the rx loop?
        // Decide when we need to send out information based
    }
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new(crate_name!())
        .author(crate_authors!())
        .version(crate_version!())
        .arg(Arg::with_name("bind-addr")
            .index(1)
            .required(true))
        .get_matches();

    let a = matches.value_of("bind-addr").unwrap();

    let mut kad = Kad::from_addr(a).await?;

    // setup udp port
    // simultaniously:
    //   - wait for incomming data
    //   - start sending probes to other nodes

    kad.process().await?;

    Ok(())
}
