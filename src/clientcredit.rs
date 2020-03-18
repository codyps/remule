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
use plain::Plain;
use fmt_extra::Hs;

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

// is this actually stored to disk like this? seems like a lot of space to use
// up if we encode the length anyhow.
const MAX_PUBKEYSIZE: usize = 80;

// emule marks these with pragma pack(1), check if we need any explicit padding
#[repr(C, packed)]
 struct CreditData29a {
    key: [u8;16],
    uploaded_lo: u32,
    downloaded_lo: u32,

    last_seen: u32, // 32-bit seconds since-epoch

    uploaded_hi: u32,
    downloaded_hi: u32,
    reserved: u16,
}

unsafe impl Plain for CreditData29a {}

#[repr(C, packed)]
struct CreditData {
    base: CreditData29a,
    // these only exist in version 0x12, not 0x11
    key_size: u8,
    secure_ident: [u8;MAX_PUBKEYSIZE]
}

unsafe impl Plain for CreditData {}

pub fn split_from<P: Plain>(buf: &[u8]) -> (&P, &[u8]) {
    let sz = std::mem::size_of::<P>();
    let (i, rem) = buf.split_at(sz);
    (P::from_bytes(&i).unwrap(), rem)
}

#[derive(Debug)]
pub struct ClientCredit {
    pub key: Hs<[u8;16]>,
    pub downloaded: u64,
    pub uploaded: u64,
    pub last_seen: std::time::SystemTime,
    pub secure_ident: Hs<Vec<u8>>,
}

impl ClientCredit {
    fn from_data(data: &CreditData) -> Self {
        let mut s = Self::from_data_29(&data.base);
        s.secure_ident.extend(&data.secure_ident[..(data.key_size as usize)]);
        s
    }

    fn from_data_29(data: &CreditData29a) -> Self {
        Self {
            key: Hs(data.key),
            downloaded: (u32::from_le(data.downloaded_hi) as u64) << 32 | (u32::from_le(data.downloaded_lo) as u64),
            uploaded: (u32::from_le(data.uploaded_hi) as u64) << 32 | (u32::from_le(data.uploaded_lo) as u64),
            // XXX: Y2038 BUG
            last_seen: std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(u32::from_le(data.last_seen) as u64),
            secure_ident: Hs(Vec::new()),
        }
    }
}

pub fn parse(inp: &[u8]) -> Result<Vec<ClientCredit>, Box<dyn Error>> {
    if inp.len() < 1 {
        return Err("no version byte found")?;
    }

    let version = inp[0];
    let entry_size = match version {
        CREDITFILE_VERSION => {
            std::mem::size_of::<CreditData>()
        },
        CREDITFILE_VERSION_29 => {
            std::mem::size_of::<CreditData29a>()
        }
        _ => {
            return Err(format!("unhandled version {}", version))?;
        }
    };

    let mut rem = &inp[1..];

    if rem.len() < 4 {
        return Err(format!("missing count, need 4 bytes, have {}", rem.len()))?;
    }

    let count = u32::from_le_bytes(rem[..4].try_into().unwrap()) as usize;
    rem = &rem[4..];

    let n = count * entry_size;
    if rem.len() < n {
        return Err(format!("not enough space, need {} bytes ({} entries {} bytes each), have {}",
            n, count, entry_size, rem.len()))?;
    }

    if rem.len() != n {
        return Err(format!("spare bytes {}, ({} entries, {} bytes each, {} buf bytes, {} bytes needed",
            rem.len() - n, count, entry_size, rem.len(), n))?;
    }

    let mut r = Vec::with_capacity(count);
    for _ in 0..count {
        let c = match version {
            CREDITFILE_VERSION_29 => {                
                let (cf, rr) = split_from::<CreditData29a>(rem);
                rem = rr;
                ClientCredit::from_data_29(cf)
            },
            CREDITFILE_VERSION => {
                let (cf, rr) = split_from::<CreditData>(rem);
                rem = rr;
                ClientCredit::from_data(cf)
            },
            _ => panic!()
        };

        r.push(c);
    }

    Ok(r)
}