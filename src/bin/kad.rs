use async_std::prelude::*;
use clap::{Arg, App, SubCommand, crate_name, crate_version, crate_authors};
use std::io;
use std::error::Error;
use async_std::net;
use async_std::stream;
use std::collections::HashMap;
use std::collections::hash_map;
use std::time::Duration;
use std::io::Read;
use std::cell::RefCell;
use futures::FutureExt;
use fmt_extra::Hs;
use rand::prelude::*;

struct Peer {
    // XXX: maybe just use an array of bytes here?
    id: Option<u128>,
    last_contact: Option<std::time::Instant>,
    last_addr: net::SocketAddr,
}

impl From<remule::nodes::Contact> for Peer {
    fn from(c: remule::nodes::Contact) -> Self {
        Peer {
            id: Some(c.id),
            last_contact: None,
            last_addr: net::SocketAddr::from((c.ip, c.udp_port)),
        }
    }
}

struct KadBootstrap {
    bootstrap_idx: usize,
    bootstraps: Vec<Peer>,
    timeout_bootstrap: stream::Interval,
}

struct Kad {
    id: u128,
    rx_buf: RefCell<Vec<u8>>,
    socket: net::UdpSocket,

    bootstrap: RefCell<KadBootstrap>,

    // XXX: consider if SocketAddr is the right key. We may have Peers that roam (get a different
    // IP address/port). We can identify this by using some features within the emule/kad protocol.
    //
    // Right now, we'll treat independent addresses as independent peers.
    peers: RefCell<HashMap<net::SocketAddr, Peer>>,
    // TODO: track peers in buckets by distance from our id
    //buckets: HashMap<u8, Vec<Peer>>,
}

impl Kad {
    async fn from_addr<A: net::ToSocketAddrs>(addrs: A, bootstraps: Vec<Peer>) -> Result<Kad, io::Error> {
        let socket = net::UdpSocket::bind(addrs).await?;
        Ok(Kad {
            id: rand::rngs::OsRng.gen(),
            socket,
            rx_buf: RefCell::new(vec![0u8;1024]),
            peers: RefCell::new(HashMap::default()),

            bootstrap: RefCell::new(KadBootstrap {
                bootstraps,
                bootstrap_idx: 0,
                timeout_bootstrap: stream::interval(Duration::from_secs(2)),
            }),
        })
    }

    async fn process_rx(&self) -> Result<(), Box<dyn Error>> {
        let mut rx_buf = self.rx_buf.borrow_mut();
        let (recv, peer) = self.socket.recv_from(&mut rx_buf[..]).await?;
        // TODO: on linux we can use SO_TIMESTAMPING and recvmsg() to get more accurate timestamps
        let ts = std::time::Instant::now();
        let rx_data = &rx_buf[..recv];
        
        println!("peer: {:?} replied: {:?}", peer, Hs(rx_data));
        // examine packet and decide if it looks like a valid emule/kad packet
        match self.peers.borrow_mut().entry(peer) {
            hash_map::Entry::Occupied(mut occupied) => {
                println!("existing peer, last heard: {:?}", occupied.get().last_contact);
                occupied.get_mut().last_contact = Some(ts);
            },
            hash_map::Entry::Vacant(vacant) => {
                println!("new peer");
                vacant.insert(Peer {
                    // FIXME: pull out of the responce
                    id: None,
                    last_contact: Some(ts),
                    last_addr: peer,
                });
            },
        }

        let packet = remule::udp_proto::Packet::from_slice(rx_data);
        println!("packet: {:?}", packet);

        Ok(())
    }

    // in emule, the system runs the kademlia process every second, then internally it throttles to
    // some amount of time:
    //
    //  - if collecting nodes, probe for a random one every 1 minute (used to generate bootstrap
    //  nodes.dat)
    //  - encodes a state machine around firewall/upnp
    //  - probe ourselves every 4 hours
    //  - find a buddy every 20 minutes
    //  - determine our external port from a contact ever 15 seconds
    //    - (by sending a Null packet to a random contact)
    //  - some "big timer" that runs every 10 seconds & every 1 hour per "zone"
    //  - small timer every 1 minute per "zone" 
    //  - search jumpstart every X seconds
    //  - zone consolidate every 45 minutes
    //  - if unconnected, every 2 or 15 seconds bootstrap from one bootstrap contact.
    //
    //
    //
    //  Timers: (initial, reset)
    //   - next_search_jump_start: (0, ?): 
    //   - next_self_lookup: (3min, ?)
    //   - status_update: (0, ?)
    //   - big_timer: (0, ?)
    //   - next_firewall_check: (1hr, ?)
    //   - next_upnp_check: (1hr - 1min, ?)
    //   - next_find_buddy: (5min, ?)
    //   - consolidate: (45min, ?)
    //   - extern_port_lookup: (0, ?)
    //   - bootstrap: (None, ?)
    async fn process(&self) -> Result<(), Box<dyn Error>> {
        let mut bootstrap = self.bootstrap.borrow_mut();

        // XXX: ideally, we'd just not schedule ourselves when peers is below 5
        if self.peers.borrow().len() < 5 {
            // send out some bootstraps
            if bootstrap.bootstrap_idx >= bootstrap.bootstraps.len() {
                println!("out of clients, restarting");
                // XXX: doesn't immediately restart
                bootstrap.bootstrap_idx = 0;
            }

            bootstrap.bootstrap_idx += 1;
            let bsc = &bootstrap.bootstraps[bootstrap.bootstrap_idx - 1];

            let mut out_buf = Vec::new();
            remule::udp_proto::OperationBuf::BootstrapReq.write_to(&mut out_buf).unwrap();
            // FIXME: this await should be elsewhere, we don't want to block other timers
            self.socket.send_to(&out_buf[..], bsc.last_addr).await?;
        }

        bootstrap.timeout_bootstrap.next().await;

        Ok(())
        // XXX: maybe we can integrate this with the rx loop?
        // Decide when we need to send out information based
        
        // examine our peers. if we haven't heard from them recently, poke them.
        // otherwise, generate a timeout from the least recently heard one and repeat
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
        .arg(Arg::with_name("nodes.dat")
            .index(2)
            .required(true))
        .get_matches();

    let a = matches.value_of("bind-addr").unwrap();

    let nodes = {
        let nodes_path = matches.value_of("nodes.dat").unwrap();
        let mut f_nodes = std::fs::File::open(nodes_path)?;
        let mut b = Vec::default();
        f_nodes.read_to_end(&mut b)?;
        remule::nodes::parse(&mut b)?
    };

    let bs_nodes: Vec<Peer> = nodes.contacts.into_iter().map(From::from).collect();
    let mut kad = Kad::from_addr(a, bs_nodes).await?;

    // setup udp port
    // simultaniously:
    //   - wait for incomming data
    //   - start sending probes to other nodes

    loop {
        futures::select! {
            e = kad.process_rx().fuse() => {
                println!("process-rx?: {:?}", e);
            },
            e = kad.process().fuse() => {
                println!("process?: {:?}", e);
            }
        }
    }
}
