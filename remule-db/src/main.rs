use clap::{Arg, App, SubCommand, crate_name, crate_version, crate_authors};
use std::error::Error;
use std::io::Read;
use emule_proto as remule;

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new(crate_name!())
        .author(crate_authors!())
        .version(crate_version!())
        .subcommand(SubCommand::with_name("known2")
            .arg(Arg::with_name("known2-dat")
                .required(true)
                .index(1)))
        .subcommand(SubCommand::with_name("clients")
            .arg(Arg::with_name("clients-met")
                .required(true)
                .index(1)))
        .subcommand(SubCommand::with_name("nodes")
            .arg(Arg::with_name("nodes-dat")
                .required(true)
                .index(1)))
        .get_matches();

    match matches.subcommand() {
        ("known2", Some(submatches)) => {
            for f in submatches.values_of_os("known2-dat").unwrap() {
                match std::fs::File::open(f) {
                    Ok(mut h) => {
                        let mut b = Vec::default();
                        h.read_to_end(&mut b)?;
                        println!("{:?}", remule::known2::parse(&mut b));
                    },
                    Err(e) => {
                        eprintln!("error: could not open {:?}: {:?}", f, e);
                    }
                }
            }
        },
        ("clients", Some(submatches)) => {
            for f in submatches.values_of_os("clients-met").unwrap() {
                match std::fs::File::open(f) {
                    Ok(mut h) => {
                        let mut b = Vec::default();
                        h.read_to_end(&mut b)?;
                        println!("{:?}", remule::clientcredit::parse(&mut b));
                    },
                    Err(e) => {
                        eprintln!("error: could not open {:?}: {:?}", f, e);
                    }
                }
            }

        },
        ("nodes", Some(submatches)) => {
            for f in submatches.values_of_os("nodes-dat").unwrap() {
                match std::fs::File::open(f) {
                    Ok(mut h) => {
                        let mut b = Vec::default();
                        h.read_to_end(&mut b)?;
                        let nodes = remule::nodes::parse(&mut b)?;

                        println!("{}", serde_json::to_string(&nodes)?);
                    },
                    Err(e) => {
                        eprintln!("error: could not open {:?}: {:?}", f, e);
                    }
                }
            }

        },
        (subname, _) => {
            Err(format!("unknown subcommand {:?}", subname))?;
        }
    }


    Ok(())
}
