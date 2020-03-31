use num_traits::FromPrimitive;
use enum_primitive_derive::Primitive;

/// The first byte of a emule/kad udp packet _may_ be one of these bytes, which establishes the
/// content of the packet.
///
/// If it is not one of these bytes, it may be an encrypted/obfuscated packet.
#[derive(Debug, PartialEq, Eq, Primitive)]
#[repr(u8)]
pub enum UdpProto {
    Emule = 0xC5,
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
    pub fn from_slice(raw: &'a [u8]) -> Self {
        Packet {
            raw
        }
    }

    // modify the packet in place to remove the obfuscation
    pub fn decrypt(&mut self, keys: &Keys) {
        match UdpProto::from_u8(self.raw[0]) {
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
