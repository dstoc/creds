use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_creds"))
        .args(args)
        .output()
        .expect("run creds CLI")
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
        ("check", "Validate the configuration"),
        ("encrypt", "File to encrypt"),
        ("decrypt", "New plaintext file to create"),
    ] {
        assert_successful_help(
            &["--config", "/path/that/does/not/exist", command, "--help"],
            &[expected, "Examples:"],
        );
    }
}

#[test]
fn version_reports_the_package_version() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "creds 0.3.0\n");
    assert!(output.stderr.is_empty());
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
