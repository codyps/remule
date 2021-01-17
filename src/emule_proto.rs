// udp ops
#[derive(Primitive)]
#[repr(u8)]
enum UdpProto {
    EmuleProt = 0xC5,
    KademliaPackedProt = 0xE5,
    KademliaHeader = 0xE4,
    UdpReservedProt1 = 0xA3,
    UdpReservedProt2 = 0xB2,
    PackedProt = 0xD4,

    // MlDonkeyProt = 0x00,
    // EdonkeyHeader = 0xE3,
}