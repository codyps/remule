use clap::{Arg, App, crate_name, crate_version, crate_authors};
use std::error::Error;
use std::io::Read;

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new(crate_name!())
        .author(crate_authors!())
        .version(crate_version!())
        .arg(Arg::with_name("known2-dat")
            .required(true)
            .index(1))
        .get_matches();

    for f in matches.values_of_os("known2-dat").unwrap() {
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

    Ok(())
}