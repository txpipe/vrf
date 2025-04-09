use vrf_dalek::golden::{GoldenTestVector, CARDANO_BASE_TEST_VECTORS};

use assert_cmd::Command;
use getrandom::fill;
use predicates::prelude::*;
use rand::{
    distributions::{Alphanumeric, Uniform},
    Rng,
};
use std::{fs, io::Write};
use tempfile::NamedTempFile;

const PRG: &str = "vrf_dalek";

#[test]
fn correct_output_help_arg() {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE"));
}

#[test]
fn correct_output_version_arg() {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let ver = "vrf_dalek 0.1.0";
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(ver));
}

#[test]
fn correct_length_hex_output_generate_arg() {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let is_32_byte_hex = predicate::str::is_match("^[0-9a-f]{64}$").unwrap();
    cmd.arg("--generate")
        .assert()
        .success()
        .stdout(is_32_byte_hex);
}

#[test]
fn check_publickey_deriving_from_file_with_golden_tests() {
    for filename in CARDANO_BASE_TEST_VECTORS {
        let _ = check_deriving_against_golden_from_file(&filename);
    }
}

#[test]
fn check_publickey_when_nonexistent_file() {
    check_when_nonexistent_file("--derive");
}

#[test]
fn check_publickey_deriving_from_stdin_with_golden_tests() {
    for filename in CARDANO_BASE_TEST_VECTORS {
        let _ = check_deriving_against_golden_from_stdin(&filename);
    }
}

#[test]
fn check_proving_with_golden_tests() {
    for filename in CARDANO_BASE_TEST_VECTORS {
        let _ = check_proving_against_golden(&filename);
    }
}

#[test]
fn check_proving_when_nonexistent_file() {
    let mut rng = rand::thread_rng();
    let num = rng.sample(Uniform::new(1usize, 15));
    let msg: String = rng
        .sample_iter(&Alphanumeric)
        .take(num)
        .map(char::from)
        .collect();

    check_when_nonexistent_file_and_stdin("--prove", None, &msg);
}

#[test]
fn check_hash_output_from_file_with_golden_tests() {
    for filename in CARDANO_BASE_TEST_VECTORS {
        let _ = check_hash_output_against_golden_from_file(&filename);
    }
}

#[test]
fn check_hash_output_from_stdin_with_golden_tests() {
    for filename in CARDANO_BASE_TEST_VECTORS {
        let _ = check_hash_output_against_golden_from_stdin(&filename);
    }
}

#[test]
fn check_hash_output_when_nonexistent_file() {
    check_when_nonexistent_file("--output");
}

#[test]
fn check_verifying_with_golden_tests() {
    for filename in CARDANO_BASE_TEST_VECTORS {
        let _ = check_verifying_against_golden(&filename);
    }
}

#[test]
fn check_verifying_when_nonexistent_file() {
    let mut rng = rand::thread_rng();
    let mut random_bytes = [0u8; 80];
    let _ = fill(&mut random_bytes[..]);
    let proof = hex::encode(&random_bytes);
    let num = rng.sample(Uniform::new(1usize, 15));
    let msg: String = rng
        .sample_iter(&Alphanumeric)
        .take(num)
        .map(char::from)
        .collect();

    check_when_nonexistent_file_and_stdin("--verify", Some(&proof), &msg);
}

fn check_when_nonexistent_file(command: &str) {
    let nonexistent = gen_nonexistent_file();
    let expected = format!("{}: .* [(]os error 2[)]", nonexistent);
    let mut cmd = Command::cargo_bin(PRG).unwrap();

    cmd.args([command, &nonexistent])
        .assert()
        .success()
        .stderr(predicate::str::is_match(expected).unwrap());
}

fn check_when_nonexistent_file_and_stdin(command: &str, arg: Option<&str>, msg: &str) {
    let nonexistent = gen_nonexistent_file();
    let expected = format!("{}: .* [(]os error 2[)]", nonexistent);
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    match arg {
        Some(val) => {
            cmd.args([command, val, &nonexistent])
                .write_stdin(msg)
                .assert()
                .success()
                .stderr(predicate::str::is_match(expected).unwrap());
        }
        None => {
            cmd.args([command, &nonexistent])
                .write_stdin(msg)
                .assert()
                .success()
                .stderr(predicate::str::is_match(expected).unwrap());
        }
    }
}

fn check_deriving_against_golden_from_file(file_path: &str) {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let input = fs::read_to_string(file_path).unwrap();
    let golden = serde_json::from_str::<GoldenTestVector>(&input).unwrap();
    let mut sk_prv = NamedTempFile::new().unwrap();
    write!(sk_prv, "{}", hex::encode(&golden.secret_key)).unwrap();
    let file_name = (*sk_prv.path()).display().to_string();
    let expected_output = hex::encode(golden.public_key);

    cmd.args(["--derive", &file_name])
        .assert()
        .success()
        .stdout(expected_output);
}

fn check_deriving_against_golden_from_stdin(file_path: &str) {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let input = fs::read_to_string(file_path).unwrap();
    let golden = serde_json::from_str::<GoldenTestVector>(&input).unwrap();
    let expected_output = hex::encode(golden.public_key);

    cmd.arg("--derive")
        .write_stdin(hex::encode(golden.secret_key))
        .assert()
        .success()
        .stdout(expected_output);
}

fn check_proving_against_golden(file_path: &str) {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let input = fs::read_to_string(file_path).unwrap();
    let golden = serde_json::from_str::<GoldenTestVector>(&input).unwrap();
    let mut sk_prv = NamedTempFile::new().unwrap();
    write!(sk_prv, "{}", hex::encode(&golden.secret_key)).unwrap();
    let file_name = (*sk_prv.path()).display().to_string();
    let expected_output = hex::encode(golden.proof_expected);

    cmd.args(["--prove", &file_name])
        .write_stdin(golden.message)
        .assert()
        .success()
        .stdout(expected_output);
}

fn check_hash_output_against_golden_from_file(file_path: &str) {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let input = fs::read_to_string(file_path).unwrap();
    let golden = serde_json::from_str::<GoldenTestVector>(&input).unwrap();
    let mut proof = NamedTempFile::new().unwrap();
    write!(proof, "{}", hex::encode(&golden.proof_expected)).unwrap();
    let file_name = (*proof.path()).display().to_string();

    let expected_output = hex::encode(golden.output_expected);

    cmd.args(["--output", &file_name])
        .assert()
        .success()
        .stdout(expected_output);
}

fn check_hash_output_against_golden_from_stdin(file_path: &str) {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let input = fs::read_to_string(file_path).unwrap();
    let golden = serde_json::from_str::<GoldenTestVector>(&input).unwrap();
    let expected_output = hex::encode(golden.output_expected);

    cmd.arg("--output")
        .write_stdin(hex::encode(golden.proof_expected))
        .assert()
        .success()
        .stdout(expected_output);
}

fn check_verifying_against_golden(file_path: &str) {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let input = fs::read_to_string(file_path).unwrap();
    let golden = serde_json::from_str::<GoldenTestVector>(&input).unwrap();
    let mut pk_pub = NamedTempFile::new().unwrap();
    write!(pk_pub, "{}", hex::encode(&golden.public_key)).unwrap();
    let file_name = (*pk_pub.path()).display().to_string();
    let proof = hex::encode(&golden.proof_expected);
    let expected_output = hex::encode(golden.output_expected);

    cmd.args(["--verify", &proof, &file_name])
        .write_stdin(golden.message)
        .assert()
        .success()
        .stdout(expected_output);
}

fn gen_nonexistent_file() -> String {
    loop {
        let filename: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();
        if fs::metadata(&filename).is_err() {
            return filename;
        }
    }
}
