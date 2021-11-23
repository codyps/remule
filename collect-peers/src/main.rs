use core::fmt;
use tracing::{event, Level};
use emule_proto as remule;
use fmt_extra::Hs;
use rand::prelude::*;
use sqlx::Executor;
use std::collections::{hash_map, HashMap};
use std::io;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use structopt::StructOpt;
use thiserror::Error;
use tokio::{net, task, time};
use either::Either;
use futures::{Stream, StreamExt, TryStreamExt};

#[derive(Debug, Error)]
enum Error {
    #[error("db version unknown: {version:?}, ts = {ts:?}")]
    DbUnknownVersion {
        version: String,
        ts: std::time::SystemTime,
    },

    #[error("db pool {uri} failed to open: {source}")]
    DbPoolOpen { source: sqlx::Error, uri: String },

    #[error("db create table {table} failed: {source}")]
    DbCreateTable {
        source: sqlx::Error,
        table: &'static str,
    },

    #[error("db insert peer failed: {source}")]
    DbInsertPeer { source: sqlx::Error },

    #[error("db peer get failed: {source}")]
    DbFetchPeers { source: sqlx::Error },

    #[error("db version get failed: {source}")]
    DbVersion { source: sqlx::Error },
}

#[derive(Debug)]
struct Store {
    db: sqlx::sqlite::SqlitePool,
}

impl Store {
    pub async fn new(db_uri: &str) -> Result<Self, Error> {
        let db = sqlx::sqlite::SqlitePoolOptions::new()
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::from_str(&db_uri)
                .map_err(|source| Error::DbPoolOpen {
                    source,
                    uri: db_uri.to_owned(),
                })?
                .create_if_missing(true),
            )
            .await
            .map_err(|source| Error::DbPoolOpen {
                source,
                uri: db_uri.to_owned(),
            })?;

        let mut c = db.begin().await.unwrap();
        let v: Option<(String, std::time::SystemTime)> = match sqlx::query_as("SELECT version, ts FROM version").fetch_one(&mut c).await {
                Ok((v, ts)) => {
                    let v: String = v;
                    let ts: i64 = ts;
                    let d = std::time::Duration::from_micros(ts.try_into().unwrap());
                    let ts = std::time::UNIX_EPOCH + d;
                    Some((v, ts))
                },
                Err(e) => {
                    match e {
                        sqlx::Error::Database(dbe) if dbe.message() == "no such table: version" => {
                            None
                        },
                        _ => return Err(Error::DbVersion { source: e }),
                    }
                },
        };

        match v {
            Some((v, ts)) => {
                event!(Level::INFO, "version: {}, ts: {}", v, humantime::format_rfc3339_micros(ts));
                if v == "1" {
                    event!(Level::INFO, "db version latest");
                } else {
                    return Err(Error::DbUnknownVersion { version: v, ts });
                }
            },
            None => {
                c.execute(r"
                CREATE TABLE version (
                    version TEXT NOT NULL,
                    ts INTEGER NOT NULL
                );
                CREATE TABLE peers (
                    id TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    udp_port INTEGER,
                    tcp_port INT,

                    contact_version INTEGER,
                    kad_udp_key_key INTEGER,
                    kad_udp_key_id INTEGER,
                    verified INTEGER, 

                    last_send INTEGER,

                    PRIMARY KEY (id, ip, udp_port, tcp_port)
                );
                ",
                )
                    .await
                    .map_err(|source| Error::DbCreateTable {
                        source,
                        table: "peers",
                    })?;
            },
        }


        Ok(Self { db })
    }

    pub async fn insert_contact(&self, node: remule::nodes::Contact) -> Result<(), Error> {
        sqlx::query("
                INSERT INTO peers (id, ip, udp_port, tcp_port, contact_version, kad_udp_key_key, kad_udp_key_id, verified)
                SELECT $1, $2, $3, $4, $5, $6, $7, $8
                WHERE NOT EXISTS (SELECT 1 FROM peers WHERE id = $1 AND ip = $2 AND udp_port = $3 AND tcp_port = $4)
                ")
            .bind(node.id.to_string())
            .bind(node.ip.to_string())
            .bind(node.udp_port)
            .bind(node.tcp_port)
            .bind(node.contact_version)
            .bind(node.kad_udp_key.map(|x| x.0))
            .bind(node.kad_udp_key.map(|x| x.1))
            .bind(node.verified)
            .execute(&self.db)
            .await
            .map_err(|source| Error::DbInsertPeer { source })?;
        Ok(())
    }

    pub fn peers(&self) -> impl Stream<Item = Result<Either<sqlx::sqlite::SqliteQueryResult, (String, String, u16)>, Error>> + Send + '_ {
        //Pin<Box<dyn futures_core::stream::Stream<Item = Result<either::Either<SqliteQueryResult, SqliteRow>, sqlx::Error>> + Send>> {
        sqlx::query_as("
            SELECT (id, ip, udp_port) FROM peers
            ORDER_BY last_send
        ")
            .fetch_many(&self.db)
            .map_err(|source| Error::DbFetchPeers {
                source
            })
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
struct KadId {
    inner: u128,
}

impl fmt::Display for KadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl From<u128> for KadId {
    fn from(v: u128) -> Self {
        KadId { inner: v }
    }
}

#[derive(Debug)]
struct Peer {
    // XXX: maybe just use an array of bytes here?
    id: Option<KadId>,
    last_contact: Option<std::time::Instant>,
    last_addr: SocketAddr,
}

impl From<remule::nodes::Contact> for Peer {
    fn from(c: remule::nodes::Contact) -> Self {
        Peer {
            id: Some(From::from(c.id)),
            last_contact: None,
            last_addr: SocketAddr::from((c.ip, c.udp_port)),
        }
    }
}

#[derive(Debug)]
struct Bootstrap {
    bootstrap_idx: usize,
    timeout_bootstrap: time::Interval,
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
    store: Store,

    // elements we need mutability over
    kad_mut: std::sync::Mutex<KadMut>,
}

impl KadShared {
    async fn from_addr<A: net::ToSocketAddrs>(addrs: A, store: Store) -> Result<Self, io::Error> {
        let socket = net::UdpSocket::bind(addrs).await?;
        Ok(Self {
            id: rand::rngs::OsRng.gen(),
            socket,
            kad_mut: std::sync::Mutex::new(KadMut::new()),
            store,
        })
    }
}

#[derive(Debug, Clone)]
struct Kad {
    shared: Arc<KadShared>,
}

impl Kad {
    async fn from_addr<A: net::ToSocketAddrs>(addrs: A, store: Store) -> Result<Self, io::Error> {
        let kad = Self {
            shared: Arc::new(KadShared::from_addr(addrs, store).await?),
        };

        Ok(kad)
    }

    async fn run(&self) {
        {
            let kad = self.clone();

            // spawn bootstrapping/timers/etc
            task::spawn(async move {
                kad.bootstrap().await.unwrap();
            });
        }

        self.process_rx().await.unwrap();
    }

    async fn bootstrap(&self) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let mut timeout_bootstrap = time::interval(Duration::from_secs(2));

        loop {
            let mut peers = self.shared.store.peers();

            while let Some(peer) = peers.next().await {
                let peer = peer.unwrap();
                match peer {
                    Either::Left(qr) => panic!("unexpected query result: {:?}", qr),
                    Either::Right((id, ip, udp_port)) => {
                        let mut out_buf = Vec::new();
                        remule::udp_proto::OperationBuf::BootstrapReq
                            .write_to(&mut out_buf)
                            .unwrap();
                        // FIXME: this await should be elsewhere, we don't want to block other timers
                        self.shared
                            .socket
                            .send_to(&out_buf[..], (ip, udp_port))
                            .await?;

                    }
                }

                timeout_bootstrap.tick().await;
            }

            // TODO: rexamine peers?
        }
    }

    fn handle_bootstrap_resp(
        &self,
        ts: std::time::Instant,
        rx_addr: SocketAddr,
        bootstrap_resp: remule::udp_proto::BootstrapResp<'_>,
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let mut kad_mut = self.shared.kad_mut.lock().unwrap();

        let peer_id = KadId::from(bootstrap_resp.client_id());

        let reported_port = bootstrap_resp.client_port();
        if reported_port != rx_addr.port() {
            println!(
                "{}: reported port {} differs from actual",
                rx_addr, reported_port
            );
        }

        // track packet source
        match kad_mut.peers.entry(peer_id) {
            hash_map::Entry::Occupied(mut occupied) => {
                // TODO: update fields
                // TODO: track sources
                println!(
                    "existing peer, last heard: {:?}",
                    occupied.get().last_contact
                );
                occupied.get_mut().last_contact = Some(ts);
            }
            hash_map::Entry::Vacant(vacant) => {
                println!("new peer");
                // TODO: track source
                vacant.insert(Peer {
                    id: Some(peer_id),
                    last_contact: Some(ts),
                    last_addr: rx_addr,
                });
            }
        }

        // track packet reported peers
        for bs_node in bootstrap_resp.contacts()? {
            let bs_node_id = KadId::from(bs_node.client_id());

            match kad_mut.peers.entry(bs_node_id) {
                hash_map::Entry::Occupied(mut occupied) => {
                    // TODO: update fields
                    // TODO: track sources
                    println!(
                        "{} exists, last heard: {:?}",
                        bs_node_id,
                        occupied.get().last_contact
                    );
                    occupied.get_mut().last_contact = Some(ts);
                }
                hash_map::Entry::Vacant(vacant) => {
                    let peer = Peer {
                        // FIXME: pull out of the responce
                        id: Some(bs_node_id),
                        last_contact: Some(ts),
                        last_addr: (bs_node.ip_addr(), bs_node.udp_port()).into(),
                    };
                    println!("new peer: {:?}", peer);
                    // TODO: track sources
                    vacant.insert(peer);
                }
            }
        }

        Ok(())
    }

    fn handle_packet(
        &self,
        ts: std::time::Instant,
        rx_addr: SocketAddr,
        rx_data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        println!("peer: {:?} replied: {:?}", rx_addr, Hs(rx_data));

        let packet = remule::udp_proto::Packet::from_slice(rx_data)?;
        match packet.kind()? {
            remule::udp_proto::Kind::Kad(kad_packet) => match kad_packet.operation() {
                Some(remule::udp_proto::Operation::BootstrapResp(bootstrap_resp)) => {
                    self.handle_bootstrap_resp(ts, rx_addr, bootstrap_resp)
                }
                kad_operation => {
                    println!("unhandled kad op: {:?}", kad_operation);
                    Ok(())
                }
            },
            packet_kind => {
                println!("unhandled packet kind: {:?}", packet_kind);
                Ok(())
            }
        }
    }

    async fn process_rx(&self) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let mut rx_buf = [0u8; 1024];
        let sock = &self.shared.socket;

        loop {
            let (recv, rx_addr) = sock.recv_from(&mut rx_buf[..]).await?;
            // TODO: on linux we can use SO_TIMESTAMPING and recvmsg() to get more accurate timestamps
            let ts = std::time::Instant::now();
            let rx_data = &rx_buf[..recv];

            if let Err(e) = self.handle_packet(ts, rx_addr, rx_data) {
                println!("{}: error handling packet: {}", rx_addr, e);
            }
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

#[derive(Debug, StructOpt)]
struct Opt {
    db_uri: String,

    #[structopt(subcommand)]
    action: Action,
}

#[derive(Debug, StructOpt)]
enum Action {
    /// Take a nodes.dat and feed it's content into our database
    FeedNodesDat { nodes_dat_path: PathBuf },

    /// Use known peers in the database to collect more peers
    Collect { bind_addr: SocketAddr },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let opts = Opt::from_args();


    let store = Store::new(&opts.db_uri).await?;

    match opts.action {
        Action::FeedNodesDat { nodes_dat_path } => {
            let mut f_nodes = std::fs::File::open(nodes_dat_path)?;
            let mut b = Vec::default();
            f_nodes.read_to_end(&mut b)?;
            let nodes = remule::nodes::parse(&mut b)?.contacts.into_iter();

            for node in nodes {
                store.insert_contact(node).await?;
            }

            Ok(())
        }
        Action::Collect { bind_addr } => {
            let kad = Kad::from_addr(bind_addr, store).await?;
            kad.run().await;
            Ok(())
        }
    }
}
