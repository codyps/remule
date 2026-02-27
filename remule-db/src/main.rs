use clap::{Arg, Command};
use emule_proto as remule;
use std::error::Error;
use std::ffi::OsString;
use std::io::Read;

fn main() -> Result<(), Box<dyn Error>> {
    let matches = Command::new("remule-db")
        .subcommand(Command::new("known2").arg(Arg::new("known2-dat").required(true).index(1)))
        .subcommand(Command::new("clients").arg(Arg::new("clients-met").required(true).index(1)))
        .subcommand(Command::new("nodes").arg(Arg::new("nodes-dat").required(true).index(1)))
        .get_matches();

    match matches.subcommand() {
        Some(("known2", submatches)) => {
            for f in submatches.get_many::<OsString>("known2-dat").unwrap() {
                match std::fs::File::open(f) {
                    Ok(mut h) => {
                        let mut b = Vec::default();
                        h.read_to_end(&mut b)?;
                        println!("{:?}", remule::known2::parse(&mut b));
                    }
                    Err(e) => {
                        eprintln!("error: could not open {:?}: {:?}", f, e);
                    }
                }
            }
        }
        Some(("clients", submatches)) => {
            for f in submatches.get_many::<OsString>("clients-met").unwrap() {
                match std::fs::File::open(f) {
                    Ok(mut h) => {
                        let mut b = Vec::default();
                        h.read_to_end(&mut b)?;
                        println!("{:?}", remule::clientcredit::parse(&mut b));
                    }
                    Err(e) => {
                        eprintln!("error: could not open {:?}: {:?}", f, e);
                    }
                }
            }
        }
        Some(("nodes", submatches)) => {
            for f in submatches.get_many::<OsString>("nodes-dat").unwrap() {
                match std::fs::File::open(f) {
                    Ok(mut h) => {
                        let mut b = Vec::default();
                        h.read_to_end(&mut b)?;
                        let nodes = remule::nodes::parse(&mut b)?;

                        println!("{}", serde_json::to_string(&nodes)?);
                    }
                    Err(e) => {
                        eprintln!("error: could not open {:?}: {:?}", f, e);
                    }
                }
            }
        }
        Some((subname, _)) => {
            Err(format!("unknown subcommand {:?}", subname))?;
        }
        None => {
            Err("no subcommand provided")?;
        }
    }

    Ok(())
}
