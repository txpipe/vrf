//! CLI implementation using VRF-03 implementation following
//! [version 03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-03)
//! of the draft.
use crate::vrf03::{PublicKey03, SecretKey03, VrfProof03};

use clap::{App, Arg};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};

type GenericError = Box<dyn Error + Send + Sync + 'static>;
type CLIResult<T> = Result<T, GenericError>;

/// CLI commands available
#[derive(Debug)]
pub enum Cmd {
    /// Generates 32 bytes secret key
    GenerateSk,

    /// Derives 32 bytes public key from a valid secret key
    DerivePk,

    /// Creates 80 bytes proof from an arbitrary message using a valid secret key
    CreateProof,
}

/// Config captured that determines what is invoked in CLI
#[derive(Debug)]
pub struct Config {
    cmd: Cmd,
    file: Option<String>,
}

/// Determines and invoked VRF-03 functions based on the parsed config
pub fn run(config: Config) -> CLIResult<()> {
    match config.cmd {
        Cmd::GenerateSk => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed)?;
            let mut rng = ChaCha20Rng::from_seed(seed);
            let sk = SecretKey03::generate(&mut rng);
            print!("{}", hex::encode(SecretKey03::as_bytes(&sk)));
        }
        Cmd::DerivePk => {
            match config.file {
                None => {
                    eprintln!("No stdin or file was provided to read a secret key");
                }
                Some(sk_source) => match openAny(&sk_source) {
                    Err(err) => {
                        eprintln!("Failed to open {}: {}", sk_source, err);
                    }
                    Ok(sk_handle) => {
                        let mut buffer = [0; 64];
                        let mut handle = sk_handle.take(64);
                        handle.read_exact(&mut buffer)?;
                        match hex::decode(buffer) {
                            Ok(bs) => {
                                let mut sk_array = [0u8; 32];
                                sk_array.copy_from_slice(&bs);
                                let sk = SecretKey03::from_bytes(&sk_array);
                                let pk = PublicKey03::from(&sk);
                                print!("{}", hex::encode(PublicKey03::as_bytes(&pk)));
                            }
                            Err(err) => {
                                eprintln!("Decode error of the secret key: {}", err);
                            }
                        }
                    }
                },
            };
        }
        Cmd::CreateProof => {
            match config.file {
                None => {
                    eprintln!("A secret key must be provided in a file");
                }
                Some(sk_source) => match openBoth(&sk_source) {
                    Err(err) => {
                        eprintln!("Failed to open stdin/file: {}", err);
                    }
                    Ok((mut msg_handle, sk_handle)) => {
                        let mut buffer = [0; 64];
                        let mut handle = sk_handle.take(64);
                        handle.read_exact(&mut buffer)?;
                        match hex::decode(buffer) {
                            Ok(bs) => {
                                let mut sk_array = [0u8; 32];
                                sk_array.copy_from_slice(&bs);
                                let sk = SecretKey03::from_bytes(&sk_array);
                                let pk = PublicKey03::from(&sk);
                                let msg = msg_handle.fill_buf()?;
                                let proof = VrfProof03::generate(&pk, &sk, msg);
                                println!("{}", hex::encode(VrfProof03::to_bytes(&proof)));
                            }
                            Err(err) => {
                                eprintln!("Decode error of the secret key: {}", err);
                            }
                        }
                    }
                },
            };
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
        .arg(
            Arg::with_name("derive")
                .short("d")
                .long("derive")
                .help("Derive public key from secret key")
                .conflicts_with("generate")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("prove")
                .short("p")
                .long("prove")
                .help("Create a proof for a message (stdin) using a secret key (file)")
                .conflicts_with("generate")
                .conflicts_with("derive")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("file")
                .value_name("FILE")
                .help("Input file")
                .multiple(false)
                .default_value("-"),
        )
        .get_matches();

    Ok(if matches.is_present("generate") {
        Config {
            cmd: Cmd::GenerateSk,
            file: None,
        }
    } else if matches.is_present("derive") {
        Config {
            cmd: Cmd::DerivePk,
            file: matches
                .values_of_lossy("file")
                .map(|mut vec| vec.pop().unwrap()),
        }
    } else if matches.is_present("prove") {
        Config {
            cmd: Cmd::CreateProof,
            file: matches
                .values_of_lossy("file")
                .map(|mut vec| vec.pop().unwrap()),
        }
    } else {
        panic!("wrong cmd")
    })
}

fn openAny(filename: &str) -> CLIResult<Box<dyn BufRead>> {
    match filename {
        "-" => Ok(Box::new(BufReader::new(io::stdin()))),
        _ => Ok(Box::new(BufReader::new(File::open(filename)?))),
    }
}

fn openBoth(filename: &str) -> CLIResult<(Box<dyn BufRead>, Box<dyn BufRead>)> {
    Ok((
        Box::new(BufReader::new(io::stdin())),
        Box::new(BufReader::new(File::open(filename)?)),
    ))
}
