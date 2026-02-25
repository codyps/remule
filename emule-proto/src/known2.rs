use std::error::Error;
use std::convert::TryInto;
use std::fmt;
use fmt_extra::Hs;

const KNOWN2_MET_VERSION: u8 = 0x02;
const HASHSIZE: usize = 20;

#[derive(Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct CaichHash {
    pub data: [u8; HASHSIZE],
}

impl fmt::Debug for CaichHash {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("CaichHash")
            .field("data", &Hs(self.data))
            .finish()        
    }
}

impl fmt::Display for CaichHash {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "{}", Hs(self.data))
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct CaichTree {
    pub root: CaichHash,
    pub children: Vec<CaichHash>,
}

impl fmt::Display for CaichTree {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "tree:{}", self.root)
    }
}

/// the known2 file (known2_64.dat) contains "masterhashes"

pub fn parse(inp: &[u8]) -> Result<Vec<CaichTree>, Box<dyn Error>> {
    if inp.len() < 1 {
        return Err("no magic marker")?;
    }

    if inp[0] != KNOWN2_MET_VERSION {
        return Err("unknown version")?;
    }

    // every HASHSIZE bytes is a `CAICHHash` followed by a 32-bit count (which
    // is the number of hashes owned by the prefixed hash) emule internally
    // loads only the parent `CAICHHash` and tracks it's offset in the known2
    // file

    // I'm a lazy person, so I'll just load everything
    let mut r = Vec::default();
    let mut rem = &inp[1..];
    let tn = HASHSIZE + 4;
    loop {
        let mut c = CaichTree::default();
        if rem.len() == 0 {
            return Ok(r);
        }

        // XXX: try split?
        if rem.len() < tn {
            return Err(format!("Spare bytes where tree entry expected: need {}, have {}",
                tn, rem.len()))?;
        }

        c.root.data.copy_from_slice(&rem[..HASHSIZE]);
        let ct = u32::from_le_bytes(rem[HASHSIZE..tn].try_into().unwrap());
        eprintln!("tree:{}:{} has {} hashes", c.root, r.len(), ct);
        rem = &rem[tn..];

        let n = HASHSIZE * ct as usize;
        if rem.len() < n {
            return Err(format!("tree {} needs {} bytes, but have {}",
                r.len(), n, rem.len()))?;
        }

        for _ in 0..ct {
            let mut ci = CaichHash::default();
            ci.data.copy_from_slice(&rem[..HASHSIZE]);
            c.children.push(ci);
            rem = &rem[HASHSIZE..];
        }

        r.push(c);
    }
}
