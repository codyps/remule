use std::error::Error;
use std::convert::TryInto;

// 2 kinds:
//  - normal (50 nodes)
//  - bootstraping (500 - 1000 nodes)

#[derive(Debug)]
pub struct Contact {
    // bootstrap/version 0/1 fields
    pub uid: u128,
    pub ip: u32,
    pub udp_port: u16,
    pub tcp_port: u16,

    // version >= 1
    pub contact_version: Option<u8>,
    // version 0
    pub by_type: Option<u8>,
    // version >= 2
    // (key, ip)
    pub kad_udp_key: Option<(u32, u32)>,
    // version >= 2
    pub verified: Option<u8>,    
}

#[derive(Debug)]
pub struct Nodes {
    pub version: u32,
    pub is_bootstrap: bool,
    pub contacts: Vec<Contact>,
}

// NOTE: requires `inp` to already have the version 3 header removed
pub fn parse_bootstrap(inp: &[u8]) -> Result<Vec<Contact>, Box<dyn Error>> {
    let mut rem = inp;

    if rem.len() < 4 {
        Err(format!("no count, have {} bytes", rem.len()))?;
    }

    let count = u32::from_le_bytes(rem[..4].try_into().unwrap()) as usize;
    rem = &rem[4..];

    let n = count * 25;
    if n != rem.len() {
        Err(format!("not enough data, need {} bytes for {} entries of {} bytes each, have {}",
            n, count, 25, rem.len()))?;
    }

    let mut r = Vec::with_capacity(count);

    for _ in 0..count {
        let uid = u128::from_le_bytes(rem[..8].try_into().unwrap());
        rem = &rem[..8];
        let ip = u32::from_le_bytes(rem[..4].try_into().unwrap());
        rem = &rem[..4];
        let udp_port = u16::from_le_bytes(rem[..2].try_into().unwrap());
        rem = &rem[..2];
        let tcp_port = u16::from_le_bytes(rem[..2].try_into().unwrap());
        rem = &rem[..2];
        let contact_version = Some(rem[0]);
        rem = &rem[..1];

        r.push(Contact {
            uid,
            ip,
            udp_port,
            tcp_port,
            contact_version,
            by_type: None,
            kad_udp_key: None,
            verified: None,
        })
    }

    Ok(r)
}

pub fn parse(inp: &[u8]) -> Result<Nodes, Box<dyn Error>> {
    let mut rem = inp;

    if rem.len() < 4 {
        Err(format!("no count, have {} bytes", rem.len()))?;
    }

    let count = u32::from_le_bytes(rem[..4].try_into().unwrap()) as usize;
    rem = &rem[4..];

    let (version, count) = if count != 0 {
        (0, count)
    } else {
        if rem.len() < 4 {
            Err(format!("no version, have {} bytes", rem.len()))?;
        }

        let version = u32::from_le_bytes(rem[..4].try_into().unwrap());
        rem = &rem[4..];

        if version == 3 {
            let bootstrap_edition = u32::from_le_bytes(rem[..4].try_into().unwrap());
            rem = &rem[4..];

            if bootstrap_edition == 1 {
                // bootstrap node parsing?
                todo!();
            }
        }

        let count = u32::from_le_bytes(rem[..4].try_into().unwrap()) as usize;
        rem = &rem[4..];
        (version, count)
    };

    if version > 3 {
        Err(format!("unknown version {}", version))?;
    }

    let mut r = Vec::with_capacity(count);
    for _ in 0..count {
        let n = 25 + if version >= 2 { 1 + 4 + 4 } else { 0 };
        if rem.len() < n {
            Err(format!("not enough bytes, need {}, have {}, idx: {} of {}",
                n, rem.len(), r.len(), count))?;
        }

        let (mut s, rs) = rem.split_at(n);
        let uid = u128::from_le_bytes(s[..16].try_into().unwrap());
        s = &s[16..];
        let ip = u32::from_le_bytes(s[..4].try_into().unwrap());
        s = &s[4..];
        let udp_port = u16::from_le_bytes(s[..2].try_into().unwrap());
        s = &s[2..];
        let tcp_port = u16::from_le_bytes(s[..2].try_into().unwrap());
        s = &s[2..];

        let mut by_type = None;
        let mut contact_version = None;
        if version >= 1 {
            contact_version = Some(s[0]);
            s = &s[1..];
        } else {
            by_type = Some(s[0]);
            s = &s[1..];
        }

        let mut verified = None;
        let mut kad_udp_key = None;
        if version >= 2 {
            // kad udp key read
            let dw_key = u32::from_le_bytes(s[..4].try_into().unwrap());
            s = &s[4..];
            let dw_ip = u32::from_le_bytes(s[..4].try_into().unwrap());
            s = &s[4..];
            kad_udp_key = Some((dw_key, dw_ip));

            verified = Some(s[0]);
            s = &s[1..];
        }
    
        if s.len() != 0 {
            Err(format!("spare bytes in entry {}: {} bytes, ", r.len(), s.len()))?;
        }

        rem = rs;

        r.push(Contact {
            uid,
            contact_version,
            verified,
            udp_port,
            tcp_port,
            ip,
            by_type,
            kad_udp_key,
        })
    }

    if rem.len() != 0 {
        Err(format!("spare bytes: {}", rem.len()))?;
    }

    Ok(Nodes {
        version: version,
        is_bootstrap: false,
        contacts: r,         
    })
}