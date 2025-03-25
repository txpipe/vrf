use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn correct_output_help_arg() {
    let mut cmd = Command::cargo_bin("vrf_dalek").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE"));
}

#[test]
fn correct_output_version_arg() {
    let mut cmd = Command::cargo_bin("vrf_dalek").unwrap();
    let ver = "vrf_dalek 0.1.0";
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(ver));
}

#[test]
fn correct_length_hex_output_generate_arg() {
    let mut cmd = Command::cargo_bin("vrf_dalek").unwrap();
    let is_32_byte_hex = predicate::str::is_match("^[0-9a-f]{64}\\n$").unwrap();
    cmd.arg("--generate")
        .assert()
        .success()
        .stdout(is_32_byte_hex);
}
