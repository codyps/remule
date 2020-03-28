use async_std::prelude::*;
use clap::{Arg, App, SubCommand, crate_name, crate_version, crate_authors};
use std::io;
use std::error::Error;
use async_std::net;
use std::collections::HashMap;

struct Peer {
    last_contact: std::time::Instant,
}

struct Kad {
    rx_buf: Vec<u8>,
    socket: net::UdpSocket,

    peers: HashMap<net::SocketAddr, Peer>,
}

impl Kad {
    async fn from_addr<A: net::ToSocketAddrs>(addrs: A) -> Result<Kad, io::Error> {
        let socket = net::UdpSocket::bind(addrs).await?;
        Ok(Kad {
            socket,
            rx_buf: vec![0u8;1024],
        })
    }

    async fn process(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            let (recv, peer) = self.socket.recv_from(&mut self.rx_buf).await?;
            
            // track rx timestamp?


        }
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