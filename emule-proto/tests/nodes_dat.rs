use remule::nodes::*;
use std::fs;

#[test]
fn load_1() {
    let d = fs::read("tests/nodes-dat/1").unwrap();

    let n = parse(&d[..]).unwrap();

    assert_eq!(n.version, 2);
    assert_eq!(n.is_bootstrap, false);
    assert_eq!(n.contacts[0], Contact {
        id: 92080831125886507272668723008887820410,
        ip: "190.215.228.231".parse().unwrap(),
        udp_port: 4672,
        tcp_port: 4662,
        contact_version: Some(8),
        by_type: None,
        kad_udp_key: Some((1182285559, 1289133357)),
        verified: Some(1)
    });

    assert_eq!(n.contacts[n.contacts.len() - 1],  Contact {
        id: 137127252135864945998695557671398454457,
        ip: "70.44.85.250".parse().unwrap(),
        udp_port: 3912,
        tcp_port: 3911,
        contact_version: Some(9),
        by_type: None,
        kad_udp_key: Some((327397447, 1289133357)),
        verified: Some(1)
    });
}
