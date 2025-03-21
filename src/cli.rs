//! CLI implementation using VRF-03 implementation following
//! [version 03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03)
//! of the draft.
use crate::vrf03::SecretKey03;

use clap::{App, Arg};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::error::Error;

type GenericError = Box<dyn Error + Send + Sync + 'static>;
type CLIResult<T> = Result<T, GenericError>;

/// CLI commands available
#[derive(Debug)]
pub enum Cmd {
    /// Generates 32 bytes secret key
    GenerateSk,
}

/// Config captured that determines what is invoked in CLI
#[derive(Debug)]
pub struct Config {
    cmd: Cmd,
}

/// Determines and invoked VRF-03 functions based on the parsed config
pub fn run(config: Config) -> CLIResult<()> {
    match config.cmd {
        Cmd::GenerateSk => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed)?;
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk = SecretKey03::generate(&mut rng);
            println!("{}", hex::encode(SecretKey03::as_bytes(&sk)));
        }
    }
    Ok(())
}

/// Parses line entered by user into config
pub fn get_args() -> CLIResult<Config> {
    let matches = App::new("vrf_dalek")
        .version("0.1.0")
        .author("CF <????>")
        .about("Rust VRF-03")
        .arg(
            Arg::with_name("generate")
                .short("g")
                .long("generate")
                .help("Generate secret key")
                .takes_value(false),
        )
        .get_matches();

    Ok(Config {
        cmd: if matches.is_present("generate") {
            Cmd::GenerateSk
        } else {
            panic!("wrong cmd")
        },
    })
}
