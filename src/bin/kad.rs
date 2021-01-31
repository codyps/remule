use async_std::prelude::*;
use async_std::task;
use async_std::sync::Mutex;
use std::sync::Arc;
use clap::{Arg, App, crate_name, crate_version, crate_authors};
use std::io;
use async_std::net;
use async_std::stream;
use std::collections::HashMap;
//use std::collections::hash_map;
use std::time::Duration;
use std::io::Read;
use fmt_extra::Hs;
use rand::prelude::*;

#[derive(Debug, PartialEq, Eq, Hash)]
struct KadId {
    inner: u128
}

impl From<u128> for KadId {
    fn from(v: u128) -> Self {
        KadId {
            inner: v
        }
    }
}

#[derive(Debug)]
struct Peer {
    // XXX: maybe just use an array of bytes here?
    id: Option<KadId>,
    last_contact: Option<std::time::Instant>,
    last_addr: net::SocketAddr,
}

impl From<remule::nodes::Contact> for Peer {
    fn from(c: remule::nodes::Contact) -> Self {
        Peer {
            id: Some(From::from(c.id)),
            last_contact: None,
            last_addr: net::SocketAddr::from((c.ip, c.udp_port)),
        }
    }
}

#[derive(Debug)]
struct Bootstrap {
    bootstrap_idx: usize,
    bootstraps: Vec<Peer>,
    timeout_bootstrap: stream::Interval,
}

#[derive(Debug, Default)]
struct KadMut {
    // XXX: consider if SocketAddr is the right key. We may have Peers that roam (get a different
    // IP address/port). We can identify this by using some features within the emule/kad protocol.
    //
    // Right now, we'll treat independent addresses as independent peers.
    //  XXX: consider if we want to associate peers with the same KadId and different network
    //  addresses
    peers: HashMap<KadId, Peer>,
    // TODO: track peers in buckets by distance from our id
    //buckets: HashMap<u8, Vec<Peer>>,
    //

}

impl KadMut {
    fn new() -> Self {
        Self {
            peers: HashMap::default(),
        }
    }
}

#[derive(Debug)]
struct Tasks {
    rx_join: task::JoinHandle<()>,
    bootstrap_join: task::JoinHandle<()>,
}

#[derive(Debug)]
struct KadShared {
    id: u128,
    socket: net::UdpSocket,

    // elements we need mutability over
    kad_mut: Mutex<KadMut>,

    tasks: Mutex<Option<Tasks>>,
}

impl KadShared {
    async fn from_addr<A: net::ToSocketAddrs>(addrs: A) -> Result<Self, io::Error> {
        let socket = net::UdpSocket::bind(addrs).await?;
        Ok(Self {
            id: rand::rngs::OsRng.gen(),
            socket,
            kad_mut: Mutex::new(KadMut::new()),
            tasks: Mutex::new(None),
        })
    }
}

#[derive(Debug, Clone)]
struct Kad {
    shared: Arc<KadShared>,
}

impl Kad {
    async fn from_addr<A: net::ToSocketAddrs>(addrs: A, bootstraps: Vec<Peer>) -> Result<Self, io::Error> {
        let kad = Self {
            shared: Arc::new(KadShared::from_addr(addrs).await?)
        };

        // TODO: do we immediately spwan the tasks we require here? or defer them until later?
        let rx_join = {
            let kad = kad.clone();
            task::spawn(async move {
                kad.process_rx().await.unwrap();
            })
        };

        let bootstrap_join = {
            let kad = kad.clone();

            // spawn bootstrapping/timers/etc
            task::spawn(async move {
                kad.bootstrap(Bootstrap {
                    bootstrap_idx: 0,
                    bootstraps,
                    timeout_bootstrap: stream::interval(Duration::from_secs(2)),
                }).await.unwrap();
            })
        };

        kad.shared.tasks.lock().await.replace(Tasks {
            rx_join,
            bootstrap_join,
        });

        Ok(kad)
    }

    async fn wait(&self)  {
        let tasks = self.shared.tasks.lock().await.take().unwrap();
        futures::join!(tasks.rx_join, tasks.bootstrap_join);
    }

    async fn bootstrap(&self, mut bootstrap: Bootstrap) -> Result<(), Box<dyn std::error::Error + 'static>> {
        loop {
            let execute_bootstrap = {
                self.shared.kad_mut.lock().await.peers.len() < 5
            };
            // XXX: ideally, we'd just not schedule ourselves when peers is below 5
            if execute_bootstrap {
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
                self.shared.socket.send_to(&out_buf[..], bsc.last_addr).await?;
            }

            bootstrap.timeout_bootstrap.next().await;
        }
    }

    async fn process_rx(&self) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let mut rx_buf = [0u8;1024];
        let sock = &self.shared.socket;

        loop {
            let (recv, rx_addr) = sock.recv_from(&mut rx_buf[..]).await?;
            // TODO: on linux we can use SO_TIMESTAMPING and recvmsg() to get more accurate timestamps
            let ts = std::time::Instant::now();
            let rx_data = &rx_buf[..recv];
            
            println!("peer: {:?} replied: {:?}", rx_addr, Hs(rx_data));

            /*
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
            */

            let packet = remule::udp_proto::Packet::from_slice(rx_data);
            println!("packet: {:?}", packet);
        }
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
    /*
    async fn process(&self) -> Result<(), Box<dyn Error>> {

        Ok(())
        // XXX: maybe we can integrate this with the rx loop?
        // Decide when we need to send out information based
        
        // examine our peers. if we haven't heard from them recently, poke them.
        // otherwise, generate a timeout from the least recently heard one and repeat
    }
    */
}

#[async_std::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let matches = App::new(crate_name!())
        .author(crate_authors!())
        .version(crate_version!())
        .arg(Arg::with_name("bind-addr")
            .index(1)
            .required(true))
        .arg(Arg::with_name("nodes.dat")
            .short("N")
            .takes_value(true))
        .get_matches();

    let a = matches.value_of("bind-addr").unwrap();

    let mut bs_nodes = Vec::new();

    if let Some(nodes_path) = matches.values_of("nodes.dat") {
        for np in nodes_path {
            let mut f_nodes = std::fs::File::open(np)?;
            let mut b = Vec::default();
            f_nodes.read_to_end(&mut b)?;
            bs_nodes.extend(remule::nodes::parse(&mut b)?.contacts.into_iter().map(From::from));
        };
    }

    let kad = Kad::from_addr(a, bs_nodes).await?;

    // setup udp port
    // simultaniously:
    //   - wait for incomming data
    //   - start sending probes to other nodes
    //

    Ok(())
}
