use hex_literal::hex;
use remule::udp_proto::*;

#[test]
fn tag_basic() {
    let v = [ TagType::Uint8 as u8, 1, 0, b'a', 5, 0xff, 0xee ];
    let a = Tag::from_slice(&v).unwrap();
    let b = (TagBuf { name: vec![b'a'], value: TagValueBuf::Uint8(5)}, &[0xff as u8, 0xee][..]);
    assert_eq!(a.0, b.0);
    assert_eq!(a.1, b.1);
}

