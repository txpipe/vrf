use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn usage_when_help_arg() {
    let mut cmd = Command::cargo_bin("vrf_dalek").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE"));
}
