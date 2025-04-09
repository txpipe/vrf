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

    /// Converts 80 bytes proof to 64 bytes hash
    ProofToHash,

    /// Verify 80 bytes proof against the message it was created with a 32 bytes public key
    VerifyProof {
        /// proof
        proof: Vec<u8>,
    },
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
                        eprintln!("{}: {}", sk_source, err);
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
                                print!("{}", hex::encode(VrfProof03::to_bytes(&proof)));
                            }
                            Err(err) => {
                                eprintln!("Decode error of the secret key: {}", err);
                            }
                        }
                    }
                },
            };
        }
        Cmd::ProofToHash => {
            match config.file {
                None => {
                    eprintln!("No stdin or file was provided to read a proof");
                }
                Some(proof_source) => match openAny(&proof_source) {
                    Err(err) => {
                        eprintln!("Failed to open {}: {}", proof_source, err);
                    }
                    Ok(proof_handle) => {
                        let mut buffer = [0; 160];
                        let mut handle = proof_handle.take(160);
                        handle.read_exact(&mut buffer)?;
                        match hex::decode(buffer) {
                            Ok(bs) => {
                                let mut proof_array = [0u8; 80];
                                proof_array.copy_from_slice(&bs);
                                let proof = VrfProof03::from_bytes(&proof_array)?;
                                print!("{}", hex::encode(VrfProof03::proof_to_hash(&proof)));
                            }
                            Err(err) => {
                                eprintln!("Decode error of the proof: {}", err);
                            }
                        }
                    }
                },
            };
        }
        Cmd::VerifyProof { proof } => {
            match config.file {
                None => {
                    eprintln!("A proof must be provided in a file");
                }
                Some(proof_source) => match openBoth(&proof_source) {
                    Err(err) => {
                        eprintln!("{}: {}", proof_source, err);
                    }
                    Ok((mut msg_handle, pk_handle)) => {
                        let mut buffer = [0; 64];
                        let mut handle = pk_handle.take(64);
                        handle.read_exact(&mut buffer)?;
                        match hex::decode(buffer) {
                            Ok(bs) => {
                                let mut pk_array = [0u8; 32];
                                pk_array.copy_from_slice(&bs);
                                let pk = PublicKey03::from_bytes(&pk_array);
                                let msg = msg_handle.fill_buf()?;
                                let mut proof_array = [0u8; 80];
                                proof_array.copy_from_slice(&proof);
                                let proof = VrfProof03::from_bytes(&proof_array)?;
                                match proof.verify(&pk, msg) {
                                    Ok(output) => {
                                        print!("{}", hex::encode(output));
                                    }
                                    _ => {
                                        eprintln!("The proof cannot be verified");
                                    }
                                }
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
                .help("Generate a secret key")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("derive")
                .short("d")
                .long("derive")
                .help("Derive a public key from a secret key (stdin/file)")
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
            Arg::with_name("output")
                .short("o")
                .long("output")
                .help("Create an output hash from a proof (stdin/file)")
                .takes_value(false)
                .conflicts_with("generate")
                .conflicts_with("derive")
                .conflicts_with("prove"),
        )
        .arg(
            Arg::with_name("verify")
                .long("verify")
                .help("Create an output for a proof (argument value) using a public key (file) given a message (stdin)")
                .conflicts_with("generate")
                .conflicts_with("derive")
                .conflicts_with("prove")
                .conflicts_with("output")
                .takes_value(true),
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
    } else if matches.is_present("output") {
        Config {
            cmd: Cmd::ProofToHash,
            file: matches
                .values_of_lossy("file")
                .map(|mut vec| vec.pop().unwrap()),
        }
    } else if matches.is_present("verify") {
        let proof_read = match hex::decode(
            matches
                .values_of_lossy("verify")
                .map(|mut vec| vec.pop().unwrap())
                .unwrap(),
        ) {
            Ok(bs) if bs.len() == 80 => Ok(bs),
            _ => Err("not valid proof"),
        };
        Config {
            cmd: Cmd::VerifyProof { proof: proof_read? },
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
