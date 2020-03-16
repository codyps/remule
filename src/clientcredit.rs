// clients.met
// ```notest
// struct Clients {
//    version: u8,
//    count: u32,
//    clients: [CreditStruct;count],
// }
// ```

// current emule 0.51d supports 2 creditfile versions:
const CREDITFILE_VERSION: u8 = 0x12;
const CREDITFILE_VERSION_29: u8 = 0x11;

use std::convert::TryInto;
use std::error::Error;

/*
struct CreditStruct {
    aby_key: [u8;16],
    uploaded_lo: u32,
    downloaded_lo: u32,
    last_seen: u32, // 32-bit seconds since-epoch
    uploaded_hi: u32,
    downloaded_hi: u32,
    reserved: u16,

    // these only exist in version 0x12, not 0x11
    key_size: u8,
    aby_secure_ident: [u8;MAX_PUBKEYSIZE]
}
*/

struct ClientCredit {
    downloaded: u64,
    uploaded: u64,
    last_seen: std::time::SystemTime,
}

pub fn parse(inp: &[u8]) -> Result<Vec<ClientCredit>, Box<dyn Error>> {
    if inp.len() < 1 {
        return Err("no version byte found")?;
    }

    let version = inp[0];
    match version {
        CREDITFILE_VERSION | CREDITFILE_VERSION_29 => {},
        _ => {
            return Err(format!("unhandled version {}", version))?;
        }
    }

    let rem = &inp[1..];

    if rem.len() < 4 {
        return Err(format!("missing count, need 4 bytes, have {}", rem.len()))?;
    }

    let count = u32::from_le_buf(rem[..4].try_into().unwrap());

    match version {
        CREDITFILE_VERSION_29 => {

        },
        CREDITFILE_VERSION => {

        },
        _ => panic!()
    }
}