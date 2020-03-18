use std::error::Error;
use std::convert::TryInto;

// 2 kinds:
//  - normal (50 nodes)
//  - bootstraping (500 - 1000 nodes)

#[derive(Debug)]
pub struct Contact {
    pub uid: u128,
    pub ip: u32,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub contact_version: u8,
}

pub fn parse_version_1(inp: &[u8]) -> Result<Vec<Contact>, Box<dyn Error>> {
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
        let contact_version = rem[0];
        rem = &rem[..1];

        r.push(Contact {
            uid,
            ip,
            udp_port,
            tcp_port,
            contact_version,
        })
    }

    Ok(r)
}

pub fn parse(inp: &[u8]) -> Result<Vec<Contact>, Box<dyn Error>> {
    let mut rem = inp;

    if rem.len() < 4 {
        Err(format!("no count, have {} bytes", rem.len()))?;
    }

    let count = u32::from_le_bytes(rem[..4].try_into().unwrap()) as usize;
    rem = &rem[4..];

    let version = if count != 0 {
        0
    } else {
        if rem.len() < 4 {
            Err(format!("no version, have {} bytes", rem.len()))?;
        }

        let version = u32::from_le_bytes(rem[..4].try_into().unwrap());
        rem = &rem[4..];
        version
    };

    if version > 3 {
        Err(format!("unknown version {}", version))?;
    }

    todo!()
}