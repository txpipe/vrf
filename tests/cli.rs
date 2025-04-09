use vrf_dalek::golden::{GoldenTestVector, CARDANO_BASE_TEST_VECTORS};

use assert_cmd::Command;
use predicates::prelude::*;
use rand::{distributions::Alphanumeric, Rng};
use std::fs;

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
fn check_publickey_deriving_from_nonexistent_file() {
    let nonexistent = gen_nonexistent_file();
    let expected = format!("{}: .* [(]os error 2[)]", nonexistent);
    let mut cmd = Command::cargo_bin(PRG).unwrap();

    cmd.args(["--derive", &nonexistent])
        .assert()
        .success()
        .stderr(predicate::str::is_match(expected).unwrap());
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
fn check_verifying_with_golden_tests() {
    for filename in CARDANO_BASE_TEST_VECTORS {
        let _ = check_verifying_against_golden(&filename);
    }
}

fn check_deriving_against_golden_from_file(file_path: &str) {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let input = fs::read_to_string(file_path).unwrap();
    let golden = serde_json::from_str::<GoldenTestVector>(&input).unwrap();
    fs::write("sk1.prv", &hex::encode(&golden.secret_key)).unwrap();
    let expected_output = hex::encode(golden.public_key);

    cmd.args(["--derive", "sk1.prv"])
        .assert()
        .success()
        .stdout(expected_output);

    fs::remove_file("sk1.prv").unwrap();
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
    fs::write("sk2.prv", &hex::encode(&golden.secret_key)).unwrap();
    let expected_output = hex::encode(golden.proof_expected);

    cmd.args(["--prove", "sk2.prv"])
        .write_stdin(golden.message)
        .assert()
        .success()
        .stdout(expected_output);

    fs::remove_file("sk2.prv").unwrap();
}

fn check_hash_output_against_golden_from_file(file_path: &str) {
    let mut cmd = Command::cargo_bin(PRG).unwrap();
    let input = fs::read_to_string(file_path).unwrap();
    let golden = serde_json::from_str::<GoldenTestVector>(&input).unwrap();
    fs::write("proof", &hex::encode(&golden.proof_expected)).unwrap();
    let expected_output = hex::encode(golden.output_expected);

    cmd.args(["--output", "proof"])
        .assert()
        .success()
        .stdout(expected_output);

    fs::remove_file("proof").unwrap();
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
    fs::write("pk.pub", &hex::encode(&golden.public_key)).unwrap();
    let proof = hex::encode(&golden.proof_expected);
    let expected_output = hex::encode(golden.output_expected);

    cmd.args(["--verify", &proof, "pk.pub"])
        .write_stdin(golden.message)
        .assert()
        .success()
        .stdout(expected_output);

    fs::remove_file("pk.pub").unwrap();
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
