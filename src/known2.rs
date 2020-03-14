use std::error::Error;
use std::io::{self, Read};

const KNOWN2_MET_VERSION: u8 = 0x02;
const HASHSIZE: u32 = 20;

#[derive(Debug)]
pub struct CaichHash {
    pub data: [u8; HASHSIZE];
}

#[derive(Debug)]
pub struct CaichTree {
    pub root: CaichHash,
    pub children: Vec<CaichHash>,
}

/// the known2 file (known2_64.dat) contains "masterhashes"

pub fn read<R: Read>(inp: &mut R) -> Result<Vec<CaichTree>, Box<dyn Error>> {
    let mut buf = [0u8; HASHSIZE];
    inp.read_exact(&mut buf[..1])?;

    if buf[0] != KNOWN2_MET_VERSION {
        return Err("unknown version")?;
    }

    // every HASHSIZE bytes is a `CAICHHash` followed by a 32-bit count (which
    // is the number of hashes owned by the prefixed hash) emule internally
    // loads only the parent `CAICHHash` and tracks it's offset in the known2
    // file

    // I'm a lazy person, so I'll just load everything

    loop {
        match inp.read_exact(&buf[..HASHSIZE]) {
            Ok(v) => {
                
            },
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    // we're done? check the current child count
                } else {

                }
            }
        };


    }
}
