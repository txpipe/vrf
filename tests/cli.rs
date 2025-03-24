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
