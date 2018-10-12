extern crate byteorder;
extern crate clap;
extern crate ed25519_dalek;
extern crate failure;
extern crate parity_wasm;
extern crate rand;
extern crate sha2;
extern crate wasmsign;

mod app;

use self::app::*;
use self::wasmsign::*;

fn main() -> Result<(), WError> {
    let config = Config::parse_cmdline()?;
    if config.keygen {
        return actions::keygen(&config);
    }
    if config.sign {
        return actions::sign(&config);
    }
    if config.verify {
        return actions::verify(&config);
    }
    eprintln!("No action specified on the command-line");
    Ok(())
}
