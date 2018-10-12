#![feature(nll)]

extern crate byteorder;
extern crate clap;
extern crate ed25519_dalek;
#[macro_use]
extern crate failure;
extern crate parity_wasm;
extern crate rand;
extern crate sha2;

mod actions;
mod config;
mod errors;
mod signature;
mod wasm_signature;

use self::config::*;
use self::errors::*;

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
