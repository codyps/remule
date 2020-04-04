use num_traits::FromPrimitive;
use enum_primitive_derive::Primitive;
use std::error::Error;
use std::io;

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
    pub fn decrypt(&mut self, keys: &Keys) {
        match self.udp_proto() {
            None => {
                // might be an encrypted packet
            },
            Some(v) => {
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
                    BootstrapResp::from_slice(&self.raw[1..])
                ))
            },
            _ => todo!(),
        }
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
pub enum Operation<'a> {
    BootstrapResp(BootstrapResp<'a>),

    // placeholder
    Res(&'a [u8]),
}

pub struct BootstrapResp<'a> {
    raw: &'a [u8],
}

impl<'a> BootstrapResp<'a> {
    pub fn from_slice(raw: &'a [u8]) -> Self {
        BootstrapResp {
            raw
        }
    }
}

/// Owned, non-parsing version of `Operation`
pub enum OperationBuf {
    BootstrapReq,

    // details packet?
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
            BootstrapReq => {
                w.write_all(&[UdpProto::KademliaHeader as u8, KadOpCode::BootstrapReq as u8])
            },
            _ => todo!(),
        }
    }
}

