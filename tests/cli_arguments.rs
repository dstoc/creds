use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_creds"))
        .args(args)
        .output()
        .expect("run creds CLI")
}

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after UNIX epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "creds-cli-arguments-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create scratch directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn assert_successful_help(args: &[&str], expected: &[&str]) {
    let output = run(args);
    assert!(output.status.success(), "{args:?}: {:?}", output.stderr);
    assert!(output.stderr.is_empty(), "{args:?}: {:?}", output.stderr);
    let stdout = String::from_utf8(output.stdout).expect("help is UTF-8");
    for text in expected {
        assert!(stdout.contains(text), "{args:?} missing {text:?}: {stdout}");
    }
}

#[test]
fn top_level_help_is_successful_and_describes_the_cli() {
    for flag in ["-h", "--help"] {
        assert_successful_help(
            &[flag],
            &[
                "Usage: creds [OPTIONS] <COMMAND>",
                "setup",
                "check",
                "encrypt",
                "decrypt",
                "--config <PATH>",
                "--version",
                "printf '%s'",
                "stdin",
                "stdout",
            ],
        );
    }
}

#[test]
fn subcommand_help_succeeds_without_loading_configuration() {
    for (command, expected) in [
        ("setup", "Create the local configuration"),
        ("check", "Use --details to show the resolved configuration"),
        ("encrypt", "File to encrypt"),
        ("decrypt", "New plaintext file to create"),
    ] {
        assert_successful_help(
            &["--config", "/path/that/does/not/exist", command, "--help"],
            &[expected, "Examples:"],
        );
    }
    assert_successful_help(
        &["check", "--help"],
        &["--details", "resolved paths", "key fingerprint"],
    );
}

#[test]
fn version_reports_the_package_version() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("creds {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn config_option_after_argument_terminator_is_a_file_operand() {
    let directory = ScratchDirectory::new();
    let config_dir = directory.path().join("xdg-config/creds");
    fs::create_dir_all(&config_dir).expect("create isolated config directory");
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, "").expect("write synthetic invalid config");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))
            .expect("restrict synthetic config permissions");
    }
    fs::write(directory.path().join("--config"), b"synthetic input")
        .expect("write file operand named --config");

    let output = Command::new(env!("CARGO_BIN_EXE_creds"))
        .args(["encrypt", "synthetic-name", "--", "--config"])
        .current_dir(directory.path())
        .env("HOME", directory.path())
        .env("XDG_CONFIG_HOME", directory.path().join("xdg-config"))
        .output()
        .expect("run creds with a file operand after --");

    assert_eq!(output.status.code(), Some(1), "{:?}", output.stderr);
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert!(
        stderr.contains("invalid configuration TOML"),
        "unexpected diagnostic: {stderr}"
    );
    assert!(
        !stderr.contains("--config requires a path"),
        "file operand was interpreted as an option: {stderr}"
    );
}

#[test]
fn invalid_invocations_write_contextual_usage_to_stderr() {
    let cases: &[(&[&str], &[&str])] = &[
        (&["bogus"], &["error:", "bogus", "Usage: creds"]),
        (&["--bad"], &["error:", "--bad", "Usage: creds"]),
        (&[], &["error:", "Usage: creds"]),
        (&["encrypt", "name"], &["error:", "Usage: creds encrypt"]),
        (
            &["decrypt", "name", "output", "extra"],
            &["error:", "Usage: creds decrypt"],
        ),
        (&["check", "extra"], &["error:", "Usage: creds check"]),
        (&["setup", "extra"], &["error:", "Usage: creds setup"]),
        (&["--config"], &["error:", "--config", "Usage: creds"]),
        (
            &["--config", "a", "--config", "b", "check"],
            &["error:", "--config", "Usage: creds"],
        ),
        (&["--config", "-x", "check"], &["error:", "Usage: creds"]),
        (
            &["--config=", "check"],
            &["error:", "--config", "Usage: creds"],
        ),
    ];

    for (args, expected) in cases {
        let output = run(args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {:?}",
            output.stderr
        );
        assert!(output.stdout.is_empty(), "{args:?}: {:?}", output.stdout);
        let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
        for text in *expected {
            assert!(stderr.contains(text), "{args:?} missing {text:?}: {stderr}");
        }
    }
}
