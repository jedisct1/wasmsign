use super::errors::*;
use clap::{App, Arg};
use std::path::PathBuf;

pub const DEFAULT_SYMBOL_NAME: &str = "___SIGNATURE";

#[derive(Default, Clone, Debug)]
pub struct Config {
    pub keygen: bool,
    pub sign: bool,
    pub verify: bool,
    pub input_path: Option<PathBuf>,
    pub output_path: Option<PathBuf>,
    pub pk_path: Option<PathBuf>,
    pub sk_path: Option<PathBuf>,
    pub ad: Option<Vec<u8>>,
    pub symbol_name: String,
}

impl Config {
    pub fn parse_cmdline() -> Result<Self, WError> {
        let matches = App::new("wasmsign")
            .version("1.0")
            .about("Sign WASM binaries")
            .arg(
                Arg::with_name("keygen")
                    .short("G")
                    .long("keygen")
                    .takes_value(false)
                    .help("Generate a key pair"),
            )
            .arg(
                Arg::with_name("sign")
                    .short("S")
                    .long("sign")
                    .takes_value(false)
                    .help("Sign a file"),
            )
            .arg(
                Arg::with_name("verify")
                    .short("V")
                    .long("verify")
                    .takes_value(false)
                    .help("Verify a file"),
            )
            .arg(
                Arg::with_name("input-path")
                    .short("i")
                    .long("input")
                    .takes_value(true)
                    .required(false)
                    .help("Path to the wasm input file"),
            )
            .arg(
                Arg::with_name("output-path")
                    .short("o")
                    .long("output")
                    .takes_value(true)
                    .required(false)
                    .help("Path to the wasm output file"),
            )
            .arg(
                Arg::with_name("sk-path")
                    .short("s")
                    .long("sk-path")
                    .takes_value(true)
                    .required(false)
                    .help("Path to the secret key file"),
            )
            .arg(
                Arg::with_name("pk-path")
                    .short("p")
                    .long("pk-path")
                    .takes_value(true)
                    .required(false)
                    .help("Path to the public key file"),
            )
            .arg(
                Arg::with_name("ad")
                    .short("a")
                    .long("ad")
                    .takes_value(true)
                    .required(false)
                    .help("Additional content to authenticate"),
            )
            .arg(
                Arg::with_name("symbol-name")
                    .short("n")
                    .long("symbol-name")
                    .takes_value(true)
                    .required(true)
                    .default_value(DEFAULT_SYMBOL_NAME)
                    .help("Name of the exported symbol containing the signature"),
            )
            .get_matches();
        let keygen = matches.is_present("keygen");
        let sign = matches.is_present("sign");
        let verify = matches.is_present("verify");
        let input_path = matches.value_of("input-path").map(PathBuf::from);
        let output_path = matches.value_of("output-path").map(PathBuf::from);
        let pk_path = matches.value_of("pk-path").map(PathBuf::from);
        let sk_path = matches.value_of("sk-path").map(PathBuf::from);
        let ad = matches.value_of("ad").map(|s| s.as_bytes().to_vec());
        let symbol_name = matches.value_of("symbol-name").unwrap().to_string();
        Ok(Config {
            keygen,
            sign,
            verify,
            input_path,
            output_path,
            pk_path,
            sk_path,
            ad,
            symbol_name,
        })
    }
}
