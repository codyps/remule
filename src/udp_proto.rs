use num_traits::FromPrimitive;
use enum_primitive_derive::Primitive;
use std::error::Error;
use std::io;
use std::fmt;
use std::convert::TryInto;

/// The first byte of a emule/kad udp packet _may_ be one of these bytes, which establishes the
/// content of the packet.
///
/// If it is not one of these bytes, it may be an encrypted/obfuscated packet.
#[derive(Debug, PartialEq, Eq, Primitive)]
#[repr(u8)]
pub enum UdpProto {
    Emule = 0xC5,
    /// uncompress [2..] and then process as `KademliaHeader` (op code is uncompressed)
    KademliaPacked = 0xE5,
    KademliaHeader = 0xE4,
    UdpReserved1 = 0xA3,
    UdpReserved2 = 0xB2,
    Packed = 0xD4,
}

pub struct Packet<'a> {
    raw: &'a [u8],
}

pub struct Keys<'a> {
    pub kad_id: &'a [u8],
    pub user_hash: &'a [u8],
    pub source_key: Option<&'a [u8]>,
}

impl<'a> Packet<'a> {
    pub fn from_slice(raw: &'a [u8]) -> Result<Self, Box<dyn Error>> {
        if raw.len() < 1 {
            Err("need at least 1 byte in packet")?;
        }

        Ok(Packet {
            raw
        })
    }

    pub fn udp_proto(&self) -> Option<UdpProto> {
        UdpProto::from_u8(self.raw[0])
    }

    pub fn kind(&self) -> Result<Kind<'a>, Box<dyn Error>> {
        match self.udp_proto() {
            Some(UdpProto::KademliaHeader) => {
                Ok(Kind::Kad(KadPacket::from_slice(&self.raw[1..])?))
            },
            None => { Err("unrecognized udp proto")? },
            _ => { todo!() }
        }
    }

    // modify the packet in place to remove the obfuscation
    pub fn decrypt(&mut self, _keys: &Keys) {
        match self.udp_proto() {
            None => {
                // might be an encrypted packet
            },
            Some(_v) => {
                // non-obfuscated packet
                return;
            }
        }


        todo!();
        // packets are obfuscated via a couple types of keys:
        //  - Kad packets using the KadId of the recieving node as the key
        //  - ed2k packets using a "user hash" as the basis for the key
        //  - kad packets using a per-source ip key sent by the source node
        //
        // all keys are generated with md5 & RC4 is used as encryption
        //
        // TODO: consider if we can be sneaky and not require the keys
        // TODO: consider allowing arbitrary numbers of potential keys to be provided
        // TODO: consider if the nature of the "check" (validating a few bytes) might result in
        // multiple keys being acceptable. Consider how our API should handle this and if it's
        // something we can be cheeky with.
    }
}

impl<'a> fmt::Debug for Packet<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Packet")
            .field("kind", &self.kind())
            .finish()
    }
}

#[derive(Debug)]
pub enum Kind<'a> {
    Kad(KadPacket<'a>),
}

pub struct KadPacket<'a> {
    raw: &'a [u8],
}

impl<'a> KadPacket<'a> {
    pub fn from_slice(raw: &'a [u8]) -> Result<Self, Box<dyn Error>> {
        if raw.len() < 1 {
            Err("kad packet needs at least 1 byte")?
        }

        Ok(Self {
            raw
        })
    }

    pub fn opcode(&self) -> Option<KadOpCode> {
        KadOpCode::from_u8(self.raw[0])
    }

    pub fn operation(&self) -> Option<Operation<'a>> {
        match self.opcode() {
            Some(KadOpCode::BootstrapResp) => {
                Some(Operation::BootstrapResp(
                    BootstrapResp::from_slice(&self.raw[1..]).unwrap()
                ))
            },
            _ => todo!(),
        }
    }
}

impl<'a> fmt::Debug for KadPacket<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("KadPacket")
            .field("operation", &self.operation())
            .finish()
    }
}

/// If `UdpProto::Kad` is the first byte, this is the second byte
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Primitive)]
#[repr(u8)]
pub enum KadOpCode {
    BootstrapReqV0 = 0x00,
    BootstrapReq  = 0x01,
    BootstrapResV0 = 0x08,
    BootstrapResp = 0x09,
    HelloReqV0 = 0x10,
    HelloReq = 0x11,
    HelloResV0 = 0x18,
    HelloRes = 0x19,
    ReqV0 = 0x20,
    Req = 0x21,
    HelloResAck = 0x22,
    ResV0 = 0x28,
    Res = 0x29,
    SearchReqV1 = 0x30,
    SearchNotesReqV1 = 0x32,
    SearchKeyReq = 0x33,
    SearchSourceReq = 0x34,
    SearchNotesReq = 0x35,

    SearchResV1 = 0x38,
    SearchNotesResV1 = 0x3A,
    SearchRes = 0x3b,
    PublishReqV1 = 0x40,
    PublishNotesReqV0 = 0x42,
    PublishKeyReq = 0x43,
    PublishSourceReq = 0x44,
    PublishNotesReq = 0x45,
    PublishResV1 = 0x48,
    PublishNotesResV0 = 0x4A,
    PublishRes = 0x4B,
    PublishResAck = 0x4C,
    FirewalledReqV1 = 0x50,
    FindBuddyReqV1 = 0x51,
    CallbackReqV1 = 0x52,
    Firewalled2ReqV1 = 0x53,
    FirewalledResV1 = 0x58,
    FirewalledAckResV1 = 0x59,
    FindBuddyResV1 = 0x5A,

    Ping = 0x60,
    Pong = 0x61,

    FirewallUdp = 0x62,
}

/// If `UdpProto::Emule` is the first byte, this is the second byte
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Primitive)]
#[repr(u8)]
pub enum EmuleOpCode {
    ReAskCallBackUdp = 0,
    
}

/// Representation of an entire `KadOpCode` with the associated data
///
/// ```norust
/// struct Operation {
///    opcode: u8,
///    // size determined by _packet_ size
///    value: [u8],
/// }
/// ```
#[derive(Debug)]
pub enum Operation<'a> {
    BootstrapResp(BootstrapResp<'a>),
    SearchRes(SearchRes<'a>),

    // placeholder
    Res(&'a [u8]),
}

pub struct BootstrapResp<'a> {
    raw: &'a [u8],
}

/// 
/// ```norust
/// struct BootstrapResp {
///     client_id: le128,
///     client_port: le16,
///     client_version: u8,
///     num_contacts: le16,
///     // `Contact` is fixed size
///     contacts: [Contact;num_contacts],
/// }
/// ```
impl<'a> BootstrapResp<'a> {
    pub fn from_slice(raw: &'a [u8]) -> Result<Self, Box<dyn Error>> {
        if raw.len() < (16 + 2 + 1 + 2) {
            Err("not enough bytes in bootstrap responce")?;
        }

        Ok(BootstrapResp {
            raw
        })
    }

    /// Kad ID of the client that sent this bootstrap responce
    pub fn client_id(&self) -> u128 {
        u128::from_le_bytes(self.raw[..16].try_into().unwrap())
    }

    /// configured udp port for the client that sent this responce
    pub fn client_port(&self) -> u16 {
        u16::from_le_bytes(self.raw[16..(16 + 2)].try_into().unwrap())
    }

    pub fn client_version(&self) -> u8 {
        self.raw[(16 + 2)]
    }

    pub fn num_contacts(&self) -> u16 {
        u16::from_le_bytes(self.raw[(16 + 2 + 1)..(16 + 2 + 1 + 2)].try_into().unwrap())
    }

    pub fn contacts(&self) -> Result<BootstrapRespContacts<'a>, Box<dyn Error>> {
        BootstrapRespContacts::from_slice(self.num_contacts(), &self.raw[(16 + 2 + 1 + 2) ..])
    }
}

impl<'a> fmt::Debug for BootstrapResp<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("BootstrapResp")
            .field("client_id", &self.client_id())
            .field("client_port", &self.client_port())
            .field("client_version", &self.client_version())
            .field("num_contacts", &self.num_contacts())
            .field("contacts", &self.contacts())
            .finish()
    }
}

///
///
/// ```norust
/// struct SearchRes {
///   source_id: le128,
///   target_id: le128,
///   result_ct: le16,
///   // `Result` is variable sized
///   results: [Result; result_ct],
/// }
/// ```
#[derive(Clone)]
pub struct SearchRes<'a> {
    raw: &'a [u8]
}

impl<'a> SearchRes<'a> {
    pub fn from_slice(raw: &'a [u8]) -> Result<Self, Box<dyn Error>> {
        Ok(SearchRes {
            raw
        })
    }

    pub fn source_id(&self) -> u128 {
        u128::from_le_bytes(self.raw[..16].try_into().unwrap())
    }

    pub fn target_id(&self) -> u128 {
        u128::from_le_bytes(self.raw[16..(16+16)].try_into().unwrap())
    }

    pub fn result_ct(&self) -> u16 {
        u16::from_le_bytes(self.raw[(16+16)..(16+16+2)].try_into().unwrap())
    }

    pub fn results(&self) -> Result<(SearchResults<'a>, &'a [u8]), Box<dyn Error>> {
        SearchResults::from_slice(self.result_ct(), &self.raw[(16+16+2)..])
    }
}

impl<'a> fmt::Debug for SearchRes<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("SearchRes")
            .field("source_id", &self.source_id())
            .field("target_id", &self.target_id())
            .field("result_ct", &self.result_ct())
            .field("results", &self.results())
            .finish()
    }
}

/// A series of `SearchResult`s. The size of each is determined by their content
#[derive(Clone)]
pub struct SearchResults<'a> {
    raw: &'a [u8],
}

impl<'a> SearchResults<'a> {
    pub fn from_slice(mut num: u16, raw: &'a [u8]) -> Result<(Self, &'a [u8]), Box<dyn Error>> {
        let mut rem = raw;
        loop {
            if num == 0 {
                return Ok((SearchResults {
                    raw: &raw[..(raw.len() - rem.len())]
                }, rem))
            }

            num -= 1;

            let (_, rr) = SearchResult::from_slice(rem)?;
            rem = rr;
        }
    }
}

impl<'a> fmt::Debug for SearchResults<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: add results here
        fmt.debug_struct("SearchResults")
            .finish()
    }
}

impl<'a> Iterator for SearchResults<'a> {
    type Item = SearchResult<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.len() == 0 {
            return None;
        }

        // NOTE: we require SearchResults to be well formed after construction.
        let (v, rem) = SearchResult::from_slice(self.raw).unwrap();
        self.raw = rem;
        Some(v)
    }
}

#[derive(Clone)]
pub struct SearchResult<'a> {
    raw: &'a [u8]
}

///
/// ```norust
/// struct SearchResult {
///    id: le128,
///    // `TagList` is variable sized (based on content)
///    tags: TagList,
/// }
impl<'a> SearchResult<'a> {
    pub fn from_slice(raw: &'a [u8]) -> Result<(Self, &'a [u8]), Box<dyn Error>> {
        let r = &raw[16..];
        // use taglist to determine the length here
        let (_, rem) = TagList::from_slice(&r)?;
        Ok((Self {
            raw: raw
        }, rem))
    }

    pub fn id(&self) -> u128 {
        u128::from_le_bytes(self.raw[..16].try_into().unwrap())
    }

    pub fn tags(&self) -> TagList<'a> {
        TagList::from_slice(&self.raw[16..]).unwrap().0
    }
}

///
///
/// ```notrust
/// struct TagList {
///    count: le32,
///    // `Tag` size is variable
///    tags: [Tag; count],
/// }
///
/// struct Tag {
///     type: u8,
///     name_len: u16,
///     // not necessarily null terminated
///     name: [u8; name_len];
///     // Value size & interp determined by `type`
///     value: Value(type),
/// }
///
/// union Value {
///     Hash([u8;16]),
///     String(StringUtf8),
///     Uint64(le64),
///     Uint32(le32),
///     Uint16(le16),
///     Uint8(u8),
///     Float32(f32),
///     // comments indicate it is unused
///     Bsob
/// }
/// ```
#[derive(Clone)]
pub struct TagList<'a> {
    raw: &'a [u8],
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Primitive, Debug)]
#[repr(u8)]
pub enum TagType {
    Hash = 0x01,
    String_ = 0x02,
    Uint32 = 0x03,
    Float32 = 0x04,
    /// XXX: unhandled in emule tag list parsing
    Bool = 0x05,
    /// XXX: unhandled in emule tag list parsing
    BoolArray = 0x06,
    /// XXX: unhandled in emule tag list parsing
    Blob = 0x07,
    Uint16 = 0x08,
    Uint8 = 0x09,
    /// XXX: emule comments indicate it is unused
    Bsob = 0x0A,
    Uint64 = 0x0B,
}

impl<'a> TagList<'a> {
    pub fn from_slice(raw: &'a [u8]) -> Result<(Self, &[u8]), Box<dyn Error>> {
        if raw.len() < 4 {
            Err(format!("tag list needs at least space for a count (4 bytes), have {} bytes", raw.len()))?;
        }

        let tl = TagList {
            raw
        };
        
        let mut ct = tl.count();
        let mut rem = tl.item_bytes();
        loop {
            if ct == 0 {
                return Ok((TagList {
                    raw: &raw[..(raw.len() - rem.len())],
                }, rem));
            }

            ct -= 1;
            let (_, rr) = Tag::from_slice(rem)?;
            rem = rr;
        }
    }
}

impl<'a> TagList<'a> {
    pub fn count(&self) -> u16 {
        u16::from_le_bytes(self.raw[..4].try_into().unwrap())
    }

    fn item_bytes(&self) -> &'a [u8] {
        &self.raw[4..]
    }

    pub fn iter(&self) -> TagListIter<'a> {
        TagListIter::from_slice(self.item_bytes())
    }
}

// NOTE: we use a seperate iterator here because the prefixed count would otherwise interfere
pub struct TagListIter<'a> {
    raw: &'a [u8],
}

impl<'a> TagListIter<'a> {
    pub fn from_slice(raw: &'a [u8]) -> Self {
        Self {
            raw
        }
    }
}

impl<'a> Iterator for TagListIter<'a> {
    type Item = Result<Tag<'a>, Box<dyn Error>>;

    fn next(&mut self) -> Option<Self::Item> {

        match Tag::from_slice(self.raw) {
            Ok((i, rem)) => {
                self.raw = rem;
                Some(Ok(i))
            },
            Err(e) => Some(Err(e)),
        }
    }
}

/// ```norust
/// struct Tag {
///     tag_type: u8,
///     name_len: u16,
///     name: [u8;name_len],
///     value: [u8;tag_size(tag_type)],
/// }
/// ```
pub struct Tag<'a> {
    raw: &'a [u8],
}

impl<'a> Tag<'a> {
    pub fn from_slice(raw: &'a [u8]) -> Result<(Self, &'a[u8]), Box<dyn Error>> {
        let need_size = 1 + 2;
        if raw.len() < need_size {
            Err(format!("tag needs at least {} bytes, have {}", need_size, raw.len()))?;
        }

        let name_len = u16::from_le_bytes(raw[1..3].try_into().unwrap()) as usize;
        let need_size = need_size + name_len;
        if raw.len() < need_size {
            Err(format!("tag needs at least {} bytes, have {} (inc name_len {})", need_size, raw.len(), name_len))?;
        }

        let tag_type = match TagType::from_u8(raw[0]) {
            Some(v) => v,
            None => Err(format!("tag type is invalid: {}", raw[0]))?,
        };

        let value_offs = 3 + name_len;
        let content_bytes = match tag_type {
            TagType::Hash => {
                16
            },
            TagType::String_ => {
                let need_size = need_size + 2;
                if raw.len() < need_size {
                    Err(format!("tag needs at least {} bytes, have {} (string value len)", need_size, raw.len()))?;
                }

                let s_len = u16::from_le_bytes(raw[value_offs..(value_offs + 6)].try_into().unwrap()) as usize;

                2 + s_len
            },
            TagType::Uint64 => {
                8
            },
            TagType::Uint32 => {
                4
            },
            TagType::Uint16 => {
                2
            },
            TagType::Uint8 => {
                1 
            },
            TagType::Float32 => {
                4
            },
            TagType::Bsob => {
                todo!()
            },
            o => {
                return Err(format!("unhandled tag type: {:?}", o))?;
            },
        };

        let need_size = need_size + content_bytes;

        if raw.len() < need_size {
            Err(format!("tag needs at least {} bytes, have {} (content inc)",
                need_size, raw.len()))?;
        }

        let (a, rem) = raw.split_at(need_size);

        Ok((Tag {
            raw: a,
        }, rem))
    }

    fn name_len(&self) -> usize {
        u16::from_le_bytes(self.raw[1..3].try_into().unwrap()) as usize 
    }

    pub fn name(&self) -> &'a [u8] {
        &self.raw[3..(3 + self.name_len())]
    }

    pub fn tag_type(&self) -> TagType {
        TagType::from_u8(self.raw[0]).unwrap()
    }

    pub fn value_bytes(&self) -> &'a [u8] {
        &self.raw[(3 + self.name_len())..]
    }

    pub fn value(&self) -> TagValue<'a> {
        match self.tag_type() {
            TagType::Hash => {
                TagValue::Hash(self.value_bytes())
            },
            TagType::String_ => {
                let s_len = u16::from_le_bytes(self.value_bytes()[..2].try_into().unwrap()) as usize;
                TagValue::String_(&self.value_bytes()[2..(2 + s_len)])
            },
            TagType::Uint64 => {
                TagValue::Uint64(u64::from_le_bytes(self.value_bytes().try_into().unwrap()))
            },
            TagType::Uint32 => {
                TagValue::Uint32(u32::from_le_bytes(self.value_bytes().try_into().unwrap()))
            },
            TagType::Uint16 => {
                TagValue::Uint16(u16::from_le_bytes(self.value_bytes().try_into().unwrap()))
            },
            TagType::Uint8 => {
                TagValue::Uint8(self.value_bytes()[0])
            },
            TagType::Float32 => {
                TagValue::Float32(f32::from_le_bytes(self.value_bytes().try_into().unwrap()))
            },
            _ => panic!("unhandled tag_type, sync `Tag::value` and `Tag::from_slice`"),
        }
    }
}

impl<'a> fmt::Debug for Tag<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("Tag")
            .field("name", &self.name())
            .field("tag_type", &self.tag_type())
            .field("value", &self.value())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, PartialOrd, Debug)]
pub enum TagValue<'a> {
    Hash(&'a [u8]),
    String_(&'a [u8]),
    Uint64(u64),
    Uint32(u32),
    Uint16(u16),
    Uint8(u8),
    Float32(f32),
    Bsob(&'a [u8])
}

#[derive(Clone)]
pub struct BootstrapRespContacts<'a> {
    raw: &'a [u8],
}

impl<'a> BootstrapRespContacts<'a> {
    pub fn from_slice(num: u16, raw: &'a [u8]) -> Result<Self, Box<dyn Error>> {
        // We don't use `num` except for validation.
        let each_size = 16 + 4 + 2 + 2 + 1; 
        let need_size = each_size * num as usize;
        if raw.len() != need_size {
            Err(format!("bootstrap respo contacts has wrong size: need {}, have {}", need_size, raw.len()))?;
        }

        Ok(BootstrapRespContacts {
            raw
        })
    }
}

impl<'a> fmt::Debug for BootstrapRespContacts<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_list()
            .entries(self.clone())
            .finish()
    }
}

impl<'a> Iterator for BootstrapRespContacts<'a> {
    type Item = BootstrapRespContact<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.len() > 0 {
            let (r, rem) = BootstrapRespContact::from_slice(self.raw);
            self.raw = rem;
            Some(r)
        } else {
            None
        }
    }
}

pub struct BootstrapRespContact<'a> {
    raw: &'a [u8],
}

impl<'a> BootstrapRespContact<'a> {
    pub fn from_slice(raw: &'a [u8]) -> (Self, &'a[u8]) {
        let n = 16 + 4 + 2 + 2 + 1;
        if raw.len() < n {
            panic!("bad brc len: have: {}, need: {}", raw.len(), n);
        }

        let (raw, rem) = raw.split_at(n);

        (BootstrapRespContact {
            raw
        }, rem)
    }

    pub fn client_id(&self) -> u128 {
        u128::from_le_bytes(self.raw[..16].try_into().unwrap())
    }

    pub fn raw_ip_addr(&self) -> u32 {
        u32::from_le_bytes(self.raw[16..(16 + 4)].try_into().unwrap())
    }

    pub fn ip_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(self.raw_ip_addr())
    }

    pub fn udp_port(&self) -> u16 {
        u16::from_le_bytes(self.raw[(16 + 4)..(16 + 4 + 2)].try_into().unwrap())
    }

    pub fn tcp_port(&self) -> u16 {
        u16::from_le_bytes(self.raw[(16 + 4 + 2)..(16 + 4 + 2 + 2)].try_into().unwrap())
    }

    pub fn version(&self) -> u8 {
        self.raw[16 + 4 + 2 + 2]
    }
}

impl<'a> fmt::Debug for BootstrapRespContact<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("BootstrapRespContact")
            .field("client_id", &self.client_id())
            .field("ip_addr", &self.ip_addr())
            .field("udp_port", &self.udp_port())
            .field("tcp_port", &self.tcp_port())
            .field("version", &self.version())
            .finish()
    }
}

/// Owned, non-parsing version of `Operation`
pub enum OperationBuf {
    BootstrapReq,

    Pong {
        /// udp port the `Ping` was recived from
        recv_port: u16,
    },

    // details packet?
    /// `KADEMLIA2_HELLO_RES`, `KADEMLIA2_HELLO_RES` uses this form
    ///
    /// in the `FindNodeIDByIP` flow, this is sent as a `KAD2_HELLO_REQ`
    Details {
        src_kad_id: u128,
        src_port: u16,
        kad_version: u8,

        // "tag source port"
        // included depedning on configuration (use_extern_kad_port)
        src_port_internal: Option<u16>,

        // "TAG misc options", packed into a u8 bitfield
        // included if kad version new enough and one of:
        //  - ack package requested,
        //  - prefs indicate wirewalled
        //  - firewall test indicates udp firewalled
        misc_options: Option<(bool /* udp_firewalled*/, bool /* tcp_firewalled */, bool /* req ack */)>
    },
    /// PublishReqV1 has a similar form with `1: u16` between the 2 ids
    PublishSourceReq {
        target_id: u128,
        contact_id: u128,
        /* tags: Vec<Tag> */
    },
    FindBuddyReqV1 {
        buddy_id: u128,
        src_client_hash: u128,
        // our port (for reply)
        // XXX: unclear why the source port is not used by the client recieving this.
        src_client_port: u16,

        // if contact version > 6, then include the client's udp key and id
    },
}

impl OperationBuf {
    /// Emit wire encoded data into `w`.
    /// This is done in pieces (not all at once), so be sure to buffer it prior to sending as a udp
    /// packet.
    ///
    /// Note: we don't perform encryption or compression for any operation right now.
    pub fn write_to<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        match self {
            OperationBuf::BootstrapReq => {
                w.write_all(&[UdpProto::KademliaHeader as u8, KadOpCode::BootstrapReq as u8])
            },
            _ => todo!(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TagBuf {
    pub name: Vec<u8>,
    pub value: TagValueBuf,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TagValueBuf {
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
}

impl<'a> PartialEq<Tag<'a>> for TagBuf {
    fn eq(&self, other: &Tag<'a>) -> bool {
        self.name.eq(&other.name())
            && self.value.eq(&other.value())
    }
}

impl<'a> PartialEq<TagBuf> for Tag<'a> {
    fn eq(&self, other: &TagBuf) -> bool {
        other.eq(self)
    }
}

impl<'a> PartialEq<TagValue<'a>> for TagValueBuf {
    fn eq(&self, other: &TagValue<'a>) -> bool {
        match self {
            TagValueBuf::Uint8(a) => match other { TagValue::Uint8(b) if a == b => true, _ => false },
            TagValueBuf::Uint16(a) => match other { TagValue::Uint16(b) if a == b => true, _ => false },
            TagValueBuf::Uint32(a) => match other { TagValue::Uint32(b) if a == b => true, _ => false },
            TagValueBuf::Uint64(a) => match other { TagValue::Uint64(b) if a == b => true, _ => false },
            _ => todo!(),
        }
    }
}

impl<'a> PartialEq<TagValueBuf> for TagValue<'a> {
    fn eq(&self, other: &TagValueBuf) -> bool {
        other.eq(self)
    }
}
