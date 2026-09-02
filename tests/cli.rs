use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_help_flag() {
    let mut cmd = Command::cargo_bin("tucupi").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE:"))
        .stdout(predicate::str::contains("OPTIONS:"))
        .stdout(predicate::str::contains("CONFIG:"))
        .stdout(predicate::str::contains("set-nvd-key"));
}

#[test]
fn test_short_help_flag() {
    let mut cmd = Command::cargo_bin("tucupi").unwrap();
    cmd.arg("-h")
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE:"));
}

fn command_with_store_path(store_path: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("tucupi").unwrap();
    cmd.env("TUCUPI_TEST_SECRET_STORE_FILE", store_path);
    cmd
}

#[test]
fn test_config_set_status_and_remove_nvd_key_flow() {
    let test_key = "test-nvd-key-9876";
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path().join("secrets.json");

    command_with_store_path(&store_path)
        .args(["config", "set-nvd-key"])
        .write_stdin(format!("{}\n", test_key))
        .assert()
        .success()
        .stdout(predicate::str::contains("NVD API key saved"))
        .stdout(predicate::str::contains(test_key).not());

    command_with_store_path(&store_path)
        .args(["config", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "configured (source: system keychain)",
        ));

    command_with_store_path(&store_path)
        .args(["config", "remove-nvd-key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("NVD API key removed"));

    command_with_store_path(&store_path)
        .args(["config", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not configured"));
}

#[test]
fn test_config_set_nvd_key_rejects_empty_input() {
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path().join("secrets.json");

    command_with_store_path(&store_path)
        .args(["config", "set-nvd-key"])
        .write_stdin("\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("No key provided"));
}

#[test]
fn test_config_status_reports_environment_fallback_without_value() {
    let env_key = "env-fallback-key-5544";
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path().join("missing.json");

    command_with_store_path(&store_path)
        .env("TUCUPI_NVD_API_KEY", env_key)
        .args(["config", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "configured (source: environment fallback)",
        ))
        .stdout(predicate::str::contains(env_key).not());
}

#[test]
fn test_config_unknown_command_fails() {
    let dir = tempfile::tempdir().unwrap();
    let store_path = dir.path().join("secrets.json");

    command_with_store_path(&store_path)
        .args(["config", "frobnicate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown config command"));
}
