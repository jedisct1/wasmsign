

mod app;

use app::*;
use wasmsign::*;

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
