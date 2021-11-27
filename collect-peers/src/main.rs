use core::fmt;
use either::Either;
use emule_proto as remule;
use fmt_extra::Hs;
use futures::{Stream, StreamExt, TryStreamExt};
use sqlx::Executor;
use std::io;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use structopt::StructOpt;
use thiserror::Error;
use tokio::{net, task, time};
use tracing::{event, Level};

#[derive(Debug, Error)]
enum Error {
    #[error("db commit failed while creating: {source}")]
    DbCreateCommit { source: sqlx::Error },

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

    #[error("db insert version failed: {source}")]
    DbInsertVersion { source: sqlx::Error },

    #[error("db peer get failed: {source}")]
    DbFetchPeers { source: sqlx::Error },

    #[error("db version get failed: {source}")]
    DbVersion { source: sqlx::Error },

    #[error("db update last_send failed: {source}")]
    DbUpdateSent { source: sqlx::Error },
}

const CURRENT_STORE_VERSION: &'static str = "remule/collect/1";

#[derive(Debug)]
struct Store {
    db: sqlx::sqlite::SqlitePool,
}

/// For sqlite. i64 supported, but not u64. All our timestamps are encoded this way.
trait UnixMillis {
    fn as_unix_millis(&self) -> i64;
    fn from_unix_millis(ts: i64) -> Self;
}

impl UnixMillis for std::time::SystemTime {
    fn as_unix_millis(&self) -> i64 {
        self.duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap()
    }

    fn from_unix_millis(ts: i64) -> Self {
        let d = std::time::Duration::from_micros(ts.try_into().unwrap());
        let ts = std::time::UNIX_EPOCH + d;
        ts
    }
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
        let v: Option<(String, std::time::SystemTime)> =
            match sqlx::query_as("SELECT version, ts FROM version")
                .fetch_one(&mut c)
                .await
            {
                Ok((v, ts)) => {
                    let v: String = v;
                    let ts = SystemTime::from_unix_millis(ts);
                    Some((v, ts))
                }
                Err(e) => match e {
                    sqlx::Error::Database(dbe) if dbe.message() == "no such table: version" => None,
                    _ => return Err(Error::DbVersion { source: e }),
                },
            };

        match v {
            Some((v, ts)) => {
                event!(
                    Level::INFO,
                    "version: {}, ts: {}",
                    v,
                    humantime::format_rfc3339_micros(ts)
                );
                if v == CURRENT_STORE_VERSION {
                    event!(Level::INFO, "db version latest");
                } else {
                    return Err(Error::DbUnknownVersion { version: v, ts });
                }
            }
            None => {
                c.execute(
                    r"
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
                    sends_without_responce INTEGER,
                    last_heard INTEGER,

                    PRIMARY KEY (id, ip, udp_port, tcp_port)
                );
                ",
                )
                .await
                .map_err(|source| Error::DbCreateTable {
                    source,
                    table: "peers",
                })?;

                sqlx::query(
                    "INSERT INTO version (version, ts)
                    VALUES ($1, $2)",
                )
                .bind(CURRENT_STORE_VERSION)
                .bind(SystemTime::now().as_unix_millis())
                .execute(&mut c)
                .await
                .map_err(|source| Error::DbInsertVersion { source })?;
            }
        }

        c.commit()
            .await
            .map_err(|source| Error::DbCreateCommit { source })?;

        Ok(Self { db })
    }

    pub async fn insert_contact(&self, node: remule::nodes::Contact) -> Result<u64, Error> {
        let insert_res = sqlx::query("
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
        event!(
            Level::TRACE,
            "insert_contact: {:?}: count {}, id: {}",
            node,
            insert_res.rows_affected(),
            insert_res.last_insert_rowid()
        );
        Ok(insert_res.rows_affected())
    }

    pub fn peers(
        &self,
    ) -> impl Stream<
        Item = Result<Either<sqlx::sqlite::SqliteQueryResult, (String, String, u16)>, Error>,
    > + Send
           + '_ {
        //Pin<Box<dyn futures_core::stream::Stream<Item = Result<either::Either<SqliteQueryResult, SqliteRow>, sqlx::Error>> + Send>> {
        sqlx::query_as("SELECT id, ip, udp_port FROM peers ORDER BY last_send ASC")
            .fetch_many(&self.db)
            .map_err(|source| Error::DbFetchPeers { source })
    }

    pub async fn insert_bootstrap_contact(
        &self,
        contact: &remule::udp_proto::BootstrapRespContact<'_>,
        ts: std::time::SystemTime,
    ) -> Result<u64, Error> {
        // XXX: reconsider version tracking
        let insert_res = sqlx::query(
            "INSERT INTO peers (id, ip, udp_port, tcp_port, contact_version, last_heard)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (id, ip, udp_port, tcp_port) DO
            UPDATE SET last_heard = $6, contact_version = $5",
        )
        .bind(contact.client_id().to_string())
        .bind(contact.ip_addr().to_string())
        .bind(contact.udp_port())
        .bind(contact.tcp_port())
        .bind(contact.version())
        .bind(ts.as_unix_millis())
        .execute(&self.db)
        .await
        .map_err(|source| Error::DbInsertPeer { source })?;
        event!(
            Level::TRACE,
            "insert_bootstrap_contact: {:?}: count {}, id: {}",
            contact,
            insert_res.rows_affected(),
            insert_res.last_insert_rowid()
        );
        Ok(insert_res.rows_affected())
    }

    pub async fn insert_recv_contact(
        &self,
        id: u128,
        addr: std::net::SocketAddr,
        ts: std::time::SystemTime,
    ) -> Result<u64, Error> {
        let insert_res = sqlx::query(
            "INSERT INTO peers (id, ip, udp_port, last_heard)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (id, ip, udp_port, tcp_port) DO
            UPDATE SET last_heard = $4",
        )
        .bind(id.to_string())
        .bind(addr.ip().to_string())
        .bind(addr.port().to_string())
        .bind(ts.as_unix_millis())
        .execute(&self.db)
        .await
        .map_err(|source| Error::DbInsertPeer { source })?;
        event!(
            Level::TRACE,
            "insert_bootstrap_contact: {:?}: count {}, id: {}",
            (id, addr),
            insert_res.rows_affected(),
            insert_res.last_insert_rowid()
        );
        Ok(insert_res.rows_affected())
    }

    async fn mark_peer_sent(&self, peer: (&str, &str, u16)) -> Result<(), Error> {
        sqlx::query("UPDATE peers SET last_send = $1 WHERE id = $2 AND ip = $3 AND udp_port = $4")
            .bind(SystemTime::now().as_unix_millis())
            .bind(peer.0)
            .bind(peer.1)
            .bind(peer.2)
            .execute(&self.db)
            .await
            .map_err(|source| Error::DbUpdateSent { source })?;
        Ok(())
    }
}

#[derive(Debug)]
struct KadShared {
    socket: net::UdpSocket,
    store: Store,
}

impl KadShared {
    async fn from_addr<A: net::ToSocketAddrs>(addrs: A, store: Store) -> Result<Self, io::Error> {
        let socket = net::UdpSocket::bind(addrs).await?;
        Ok(Self { socket, store })
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
        let mut timeout_bootstrap = time::interval(Duration::from_secs(1));

        loop {
            let mut peers = self.shared.store.peers();

            while let Some(peer) = peers.next().await {
                let peer = peer.unwrap();
                match peer {
                    Either::Left(qr) => panic!("unexpected query result: {:?}", qr),
                    Either::Right((id, ip_s, udp_port)) => {
                        let mut out_buf = Vec::new();
                        remule::udp_proto::OperationBuf::BootstrapReq
                            .write_to(&mut out_buf)
                            .unwrap();
                        // FIXME: this await should be elsewhere, we don't want to block other timers
                        let ip: std::net::IpAddr = ip_s.parse().unwrap();
                        let dest: std::net::SocketAddr = (ip, udp_port).into();
                        event!(Level::INFO, "sending to {}", dest);
                        self.shared.socket.send_to(&out_buf[..], dest).await?;
                        self.shared
                            .store
                            .mark_peer_sent((&id, &ip_s, udp_port))
                            .await?;
                    }
                }

                timeout_bootstrap.tick().await;
            }

            // TODO: rexamine peers?
        }
    }

    async fn handle_bootstrap_resp(
        &self,
        _ts: std::time::Instant,
        s_time: std::time::SystemTime,
        rx_addr: SocketAddr,
        bootstrap_resp: remule::udp_proto::BootstrapResp<'_>,
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let reported_port = bootstrap_resp.client_port();
        if reported_port != rx_addr.port() {
            event!(
                Level::INFO,
                "{}: reported port {} differs from actual",
                rx_addr,
                reported_port
            );
        }

        self.shared
            .store
            .insert_recv_contact(bootstrap_resp.client_id(), rx_addr, s_time)
            .await?;

        // track packet reported peers
        for bs_node in bootstrap_resp.contacts()? {
            self.shared
                .store
                .insert_bootstrap_contact(&bs_node, s_time)
                .await
                .unwrap();
        }

        Ok(())
    }

    async fn handle_packet(
        &self,
        ts: std::time::Instant,
        s_time: SystemTime,
        rx_addr: SocketAddr,
        rx_data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        event!(
            Level::DEBUG,
            "peer: {:?} replied: {:?}",
            rx_addr,
            Hs(rx_data)
        );

        let packet = remule::udp_proto::Packet::from_slice(rx_data)?;
        match packet.kind()? {
            remule::udp_proto::Kind::Kad(kad_packet) => match kad_packet.operation() {
                Some(remule::udp_proto::Operation::BootstrapResp(bootstrap_resp)) => {
                    // XXX: consider how this async affects things.
                    self.handle_bootstrap_resp(ts, s_time, rx_addr, bootstrap_resp)
                        .await
                }
                kad_operation => {
                    event!(Level::WARN, "unhandled kad op: {:?}", kad_operation);
                    Ok(())
                }
            },
        }
    }

    async fn process_rx(&self) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let mut rx_buf = [0u8; 1024];
        let sock = &self.shared.socket;

        loop {
            let (recv, rx_addr) = match sock.recv_from(&mut rx_buf[..]).await {
                Ok(v) => v,
                Err(e) => {
                    // thread 'tokio-runtime-worker' panicked at 'called `Result::unwrap()` on an `Err` value: Os { code: 50, kind: NetworkDown, message: "Network is down" }', collect-peers/src/main.rs:408:39
                    event!(Level::ERROR, "recv_from error: {}", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            // TODO: on linux we can use SO_TIMESTAMPING and recvmsg() to get more accurate timestamps
            let ts = std::time::Instant::now();
            let s_time = SystemTime::now();
            let rx_data = &rx_buf[..recv];

            if let Err(e) = self.handle_packet(ts, s_time, rx_addr, rx_data).await {
                event!(Level::ERROR, "{}: error handling packet: {}", rx_addr, e);
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Rfc3339;

impl tracing_subscriber::fmt::time::FormatTime for Rfc3339 {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> fmt::Result {
        let time = std::time::SystemTime::now();
        write!(w, "{}", humantime::format_rfc3339_micros(time))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    let opts = Opt::from_args();
    let env_filter = tracing_subscriber::filter::EnvFilter::try_from_env("REMULE_LOG")
        .unwrap_or_else(|_| {
            tracing_subscriber::filter::EnvFilter::from("collect_peers=info,emule_proto=info")
        })
        .add_directive("panic=error".parse().unwrap());

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(io::stderr)
        .with_timer(Rfc3339)
        .with_ansi(atty::is(atty::Stream::Stderr))
        .init();

    let store = Store::new(&opts.db_uri).await?;

    match opts.action {
        Action::FeedNodesDat { nodes_dat_path } => {
            let mut f_nodes = std::fs::File::open(nodes_dat_path)?;
            let mut b = Vec::default();
            f_nodes.read_to_end(&mut b)?;
            let nodes = remule::nodes::parse(&mut b)?.contacts.into_iter();

            let mut insert_ct = 0;
            for node in nodes {
                insert_ct += store.insert_contact(node).await?;
            }

            event!(Level::INFO, "Inserted {} nodes", insert_ct);

            Ok(())
        }
        Action::Collect { bind_addr } => {
            let kad = Kad::from_addr(bind_addr, store).await?;
            kad.run().await;
            Ok(())
        }
    }
}
