use core::fmt;
use either::Either;
use emule_proto as remule;
use fmt_extra::Hs;
use futures::{Stream, StreamExt, TryStreamExt};
use remule::udp_proto::BootstrapRespContact;
use sqlx::Executor;
use std::io;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
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
    #[error("db upgrade from {old_version} to {new_version} failed: {source}")]
    DbUpgrade {
        new_version: &'static str,
        old_version: String,
        source: sqlx::Error,
    },

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

const STORE_V1: &str = "remule/collect/1";
const STORE_V2: &str = "remule/collect/2";
const STORE_V3: &str = "remule/collect/3";

const CURRENT_STORE_VERSION: &str = STORE_V3;

#[derive(Debug, Clone, Copy)]
struct Peer {
    id: u128,
    ip: IpAddr,
    udp_port: u16,
}

#[derive(Debug, Clone, Copy)]
struct PeerStoreId {
    id: i64,
}

#[derive(Debug, Clone, Copy)]
struct ReportStoreId {
    id: i64,
}

/// Something out there that _may_ be connectable
#[derive(Debug, Clone, Copy)]
struct Contact {
    peer: Peer,

    /// tcp port is not known in all cases. For example:
    ///  - when we recv a udp frame, (BootstrapResp) it doesn't tell us the tcp port of the host
    ///    that sent the udp frame
    tcp_port: Option<u16>,

    /// present only in BootstrapRespContact and nodes.dat file
    version: Option<u8>,

    // the below fields basically only show up right now from importing nodes.dat files
    kad_udp_key_ip: Option<u32>,
    kad_udp_key_key: Option<u32>,
    // FIXME: figure out what verified means in detail
    verified: Option<u8>,
}

#[derive(Debug)]
enum ContactSource {
    // UDP packet header for recv'd packets with some of the packet content (deferring to udp
    // header). Similar to `ReportedByRemote`.
    //UdpSource,
    /// UDP packet header for recv'd packets combined with the packet content (deferring to the
    /// packet content). Similar to `UdpSource`.
    ReportedByRemote,
    /// Provided by some peer in a bootstrap response
    ReportedByBootstrap,
    // From some nodes.dat file
    //NodesDat,
}

impl From<remule::nodes::Contact> for Peer {
    fn from(v: remule::nodes::Contact) -> Self {
        Self {
            id: v.id,
            ip: v.ip.into(),
            udp_port: v.udp_port,
        }
    }
}

impl From<remule::nodes::Contact> for Contact {
    fn from(v: remule::nodes::Contact) -> Self {
        Self {
            peer: Peer {
                id: v.id,
                ip: v.ip.into(),
                udp_port: v.udp_port,
            },
            tcp_port: Some(v.tcp_port),
            version: v.contact_version,
            kad_udp_key_key: v.kad_udp_key.map(|x| x.0),
            kad_udp_key_ip: v.kad_udp_key.map(|x| x.1),
            verified: v.verified,
        }
    }
}

impl<'a> From<BootstrapRespContact<'a>> for Contact {
    fn from(v: BootstrapRespContact) -> Self {
        Self {
            peer: Peer {
                id: v.client_id(),
                ip: v.ip_addr().into(),

                udp_port: v.udp_port(),
            },
            tcp_port: Some(v.tcp_port()),

            version: Some(v.version()),

            kad_udp_key_ip: None,
            kad_udp_key_key: None,
            verified: None,
        }
    }
}

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
            match sqlx::query_as("SELECT version, ts FROM version ORDER BY ts DESC LIMIT 1")
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
            Some((mut v, ts)) => {
                event!(
                    Level::INFO,
                    "version: {}, ts: {}",
                    v,
                    humantime::format_rfc3339_micros(ts)
                );
                let mut executed_update = false;
                'version_update: loop {
                    match v.as_str() {
                        CURRENT_STORE_VERSION => {
                            event!(Level::INFO, "db version latest");
                            if executed_update {
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
                            break 'version_update;
                        }
                        STORE_V1 => {
                            let new_version = STORE_V2;
                            executed_update = true;
                            c.execute(
                                "
                                ALTER TABLE peers
                                ADD COLUMN last_recv INTEGER;

                                ALTER TABLE peers
                                RENAME COLUMN last_heard TO last_report;",
                            )
                            .await
                            .map_err(|source| Error::DbUpgrade {
                                new_version,
                                old_version: v.clone(),
                                source,
                            })?;

                            v = new_version.to_owned();
                        }
                        STORE_V2 => {
                            let new_version = STORE_V3;
                            executed_update = true;
                            c.execute(
                                "
                                CREATE TABLE peer (
                                    id INTEGER PRIMARY KEY,

                                    kad_id TEXT NOT NULL,
                                    ip TEXT NOT NULL,
                                    udp_port INTEGER NOT NULL,

                                    last_send_time INTEGER,

                                    CONSTRAINT peer_unique UNIQUE (kad_id, ip, udp_port)
                                );

                                CREATE TABLE report (
                                    id INTEGER PRIMARY KEY,
                                    source_peer INTEGER NOT NULL,

                                    recv_time INTEGER NOT NULL,

                                    FOREIGN KEY(source_peer) REFERENCES peer(id)
                                );

                                CREATE TABLE report_contact (
                                    id INTEGER PRIMARY KEY,

                                    report_id INTEGER NOT NULL,

                                    reported_peer_id INTEGER NOT NULL,

                                    tcp_port INTEGER,

                                    contact_version INTEGER,
                                    verified INTEGER, 

                                    FOREIGN KEY(report_id) REFERENCES report(id),
                                    FOREIGN KEY(reported_peer_id) REFERENCES peer(id)
                                );

                                INSERT INTO peer (kad_id, ip, udp_port, last_send_time) 
                                    SELECT id, ip, udp_port, MAX(last_send) FROM peers GROUP BY id, ip, udp_port;
                                DROP TABLE peers;
                                ",
                            )
                            .await
                            .map_err(|source| Error::DbUpgrade {
                                new_version,
                                old_version: v.clone(),
                                source,
                            })?;

                            v = new_version.to_owned();
                        }
                        _ => {
                            return Err(Error::DbUnknownVersion { version: v, ts });
                        }
                    }
                }
            }
            None => {
                c.execute(
                    r"
                    CREATE TABLE version (
                        version TEXT NOT NULL,
                        ts INTEGER NOT NULL
                    );

                    CREATE TABLE peer (
                        id INTEGER PRIMARY KEY,

                        kad_id TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        udp_port INTEGER NOT NULL,

                        last_send_time INTEGER,

                        CONSTRAINT peer_unqiue UNIQUE (kad_id, ip, udp_port)
                    );

                    CREATE TABLE report (
                        id INTEGER PRIMARY KEY,
                        source_peer INTEGER NOT NULL,

                        recv_time INTEGER NOT NULL,

                        FOREIGN KEY(source_peer) REFERENCES peer(id)
                    );

                    CREATE TABLE report_contact (
                        id INTEGER PRIMARY KEY,

                        report_id INTEGER NOT NULL,

                        reported_peer_id INTEGER NOT NULL,

                        tcp_port INTEGER,

                        contact_version INTEGER,
                        verified INTEGER, 

                        FOREIGN KEY(report_id) REFERENCES report(id),
                        FOREIGN KEY(reported_peer_id) REFERENCES peer(id)
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

    pub async fn insert_peer(&self, peer: &Peer) -> Result<(u64, PeerStoreId), Error> {
        let kad_id = peer.id.to_string();
        let peer_ip = peer.ip.to_string();

        let res =
            sqlx::query("INSERT OR IGNORE INTO peer (kad_id, ip, udp_port) VALUES ($1, $2, $3)")
                .bind(peer.id.to_string())
                .bind(peer.ip.to_string())
                .bind(peer.udp_port)
                .execute(&self.db)
                .await
                .map_err(|source| Error::DbInsertPeer { source })?;

        let ct = res.rows_affected();

        let s =
            sqlx::query_as("SELECT id FROM peer WHERE kad_id = $1 AND ip = $2 AND udp_port = $3")
                .bind(kad_id)
                .bind(peer_ip)
                .bind(peer.udp_port)
                .fetch_one(&self.db)
                .await
                .map_err(|source| Error::DbInsertPeer { source })?;

        let row: (i64,) = s;
        let id = PeerStoreId { id: row.0 };

        if ct != 0 {
            event!(Level::INFO, "unique peer: {:?}: {:?}", peer, id);
        } else {
            event!(Level::TRACE, "insert_peer: {:?}: {:?}", peer, id);
        };
        Ok((ct, id))
    }

    pub async fn insert_report(
        &self,
        source: PeerStoreId,
        recv_time: SystemTime,
    ) -> Result<ReportStoreId, Error> {
        let s: (i64,) = sqlx::query_as(
            "INSERT INTO report (source_peer, recv_time) VALUES ($1, $2) RETURNING id",
        )
        .bind(source.id)
        .bind(recv_time.as_unix_millis())
        .fetch_one(&self.db)
        .await
        .map_err(|source| Error::DbInsertPeer { source })?;

        let id = ReportStoreId { id: s.0 };
        event!(Level::TRACE, "insert_report: {:?}: {:?}", source, id);
        Ok(id)
    }

    pub async fn insert_report_contact(
        &self,
        report: ReportStoreId,
        contact: &Contact,
        _source: ContactSource,
    ) -> Result<u64, Error> {
        // basic process:
        //  1. find peer for this Contact (insert if not exist)
        //  2. insert report contact

        let (ct, peer) = self.insert_peer(&contact.peer).await?;

        let insert_res = sqlx::query(
            "INSERT INTO report_contact (report_id, reported_peer_id, tcp_port, contact_version, verified)
            SELECT $1, $2, $3, $4, $5
            ",
        )
        .bind(report.id)
        .bind(peer.id)
        .bind(contact.tcp_port)
        .bind(contact.version)
        .bind(contact.verified)
        .execute(&self.db)
        .await
        .map_err(|source| Error::DbInsertPeer { source })?;
        event!(
            Level::TRACE,
            "insert_report_contact: {:?}: count {}, id: {}",
            contact,
            insert_res.rows_affected(),
            insert_res.last_insert_rowid()
        );
        Ok(ct)
    }

    pub fn peers(
        &self,
    ) -> impl Stream<Item = Result<Either<sqlx::sqlite::SqliteQueryResult, PeerStoreInfo>, Error>>
           + Send
           + '_ {
        //Pin<Box<dyn futures_core::stream::Stream<Item = Result<either::Either<SqliteQueryResult, SqliteRow>, sqlx::Error>> + Send>> {
        sqlx::query_as("SELECT id, kad_id, ip, udp_port FROM peer ORDER BY last_send_time ASC")
            .fetch_many(&self.db)
            .map_err(|source| Error::DbFetchPeers { source })
            .map_ok(|x| {
                x.map_right(
                    // FIXME: using String is a hack around lifetime issues
                    |(id, kad_id, ip, udp_port): (i64, String, String, u16)| PeerStoreInfo {
                        id: PeerStoreId { id },
                        _kad_id: kad_id.parse().unwrap(),
                        addr: {
                            let ip: std::net::IpAddr = ip.parse().unwrap();
                            (ip, udp_port).into()
                        },
                    },
                )
            })
    }

    async fn mark_peer_sent(&self, peer: PeerStoreId) -> Result<(), Error> {
        sqlx::query("UPDATE peer SET last_send_time = $1 WHERE id = $2")
            .bind(SystemTime::now().as_unix_millis())
            .bind(peer.id)
            .execute(&self.db)
            .await
            .map_err(|source| Error::DbUpdateSent { source })?;
        Ok(())
    }
}

struct PeerStoreInfo {
    id: PeerStoreId,
    _kad_id: u128,
    addr: SocketAddr,
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
                    Either::Right(peer) => {
                        let mut out_buf = Vec::new();
                        remule::udp_proto::OperationBuf::BootstrapReq
                            .write_to(&mut out_buf)
                            .unwrap();
                        // FIXME: this await should be elsewhere, we don't want to block other timers
                        event!(Level::INFO, "sending to {}", peer.addr);
                        match self.shared.socket.send_to(&out_buf[..], peer.addr).await {
                            Ok(_) => {}
                            Err(e) => {
                                event!(Level::ERROR, "send_to failed: {}", e);
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                continue;
                            }
                        }
                        self.shared.store.mark_peer_sent(peer.id).await?;
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
        recv_time: std::time::SystemTime,
        rx_addr: SocketAddr,
        bootstrap_resp: remule::udp_proto::BootstrapResp<'_>,
    ) -> Result<(), Box<dyn std::error::Error + 'static>> {
        let reported_port = bootstrap_resp.client_port();
        if reported_port != rx_addr.port() {
            event!(
                Level::DEBUG,
                "{}: reported port {} differs from actual",
                rx_addr,
                reported_port
            );
        }

        let peer = Peer {
            id: bootstrap_resp.client_id(),
            ip: rx_addr.ip(),
            udp_port: rx_addr.port(),
        };

        let (packet_from_unknown_peer, peer_sid) = self.shared.store.insert_peer(&peer).await?;
        let report = self.shared.store.insert_report(peer_sid, recv_time).await?;

        if packet_from_unknown_peer != 0 {
            event!(Level::INFO, "bootstrap resp from unknown peer: {:?}", peer);
        }

        let self_contact = Contact {
            peer: Peer {
                id: bootstrap_resp.client_id(),
                ip: rx_addr.ip(),
                udp_port: bootstrap_resp.client_port(),
            },

            tcp_port: None,
            version: None,
            kad_udp_key_ip: None,
            kad_udp_key_key: None,
            verified: None,
        };
        let self_report_is_new = self
            .shared
            .store
            .insert_report_contact(report, &self_contact, ContactSource::ReportedByRemote)
            .await?;

        if self_report_is_new != 0 {
            event!(
                Level::INFO,
                "bootstrap resp self report is unknown: {:?}",
                self_contact.peer
            );
        }

        // track packet reported peers
        let mut found_peer_ct = 0;
        let mut total_peers = 0;
        for bs_node in bootstrap_resp.contacts()? {
            total_peers += 1;
            found_peer_ct += self
                .shared
                .store
                .insert_report_contact(report, &bs_node.into(), ContactSource::ReportedByBootstrap)
                .await
                .unwrap();
        }

        event!(
            Level::INFO,
            "bootstrap has {}/{} new peers ({}%)",
            found_peer_ct,
            total_peers,
            found_peer_ct as f64 / total_peers as f64 * 100f64
        );

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

            // FIXME: generalize report sources so we can have a report that represents this
            // nodes.dat file import
            let mut insert_ct = 0;
            for node in nodes {
                insert_ct += store.insert_peer(&node.into()).await?.0;
            }

            event!(Level::INFO, "Inserted {} new peers", insert_ct);

            Ok(())
        }
        Action::Collect { bind_addr } => {
            let kad = Kad::from_addr(bind_addr, store).await?;
            kad.run().await;
            Ok(())
        }
    }
}
