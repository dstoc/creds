use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after UNIX epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "creds-cli-diagnostics-{}-{nonce}",
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

struct ValidConfig {
    config: PathBuf,
    storage: PathBuf,
}

impl ValidConfig {
    fn new(directory: &ScratchDirectory) -> Self {
        let storage = directory.path().join("secrets");
        fs::create_dir(&storage).expect("create synthetic storage directory");
        set_mode(&storage, 0o700);

        let signing_key = SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap();
        let public_key = signing_key.verifying_key().to_public_key_der().unwrap();
        let config = directory.path().join("config.toml");
        let contents = format!(
            "app_url = \"https://keys.example/path\"\nhostname = \"workstation\"\nstorage_dir = \"{}\"\npublic_key = \"{}\"\nlisten_addr = \"127.0.0.1:0\"\n",
            storage.display(),
            URL_SAFE_NO_PAD.encode(public_key.as_bytes())
        );
        fs::write(&config, contents).expect("write synthetic configuration");
        set_mode(&config, 0o600);
        Self { config, storage }
    }
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set file mode");
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_creds"))
        .args(args)
        .output()
        .expect("run creds CLI")
}

fn assert_plain_failure(output: &Output) -> String {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    let stderr = String::from_utf8(output.stderr.clone()).expect("diagnostic is UTF-8");
    assert!(stderr.starts_with("error: "), "{stderr}");
    for debug_wrapper in ["Custom {", "Io(", "Envelope(", "Os {"] {
        assert!(!stderr.contains(debug_wrapper), "{stderr}");
    }
    stderr
}

#[test]
fn missing_and_malformed_config_errors_name_the_config_and_suggest_setup() {
    let directory = ScratchDirectory::new();
    let missing = directory.path().join("missing.toml");
    let output = run(&["--config", missing.to_str().unwrap(), "check"]);
    let stderr = assert_plain_failure(&output);
    assert!(stderr.contains(&format!("Configuration not found at {}", missing.display())));
    assert!(stderr.contains("Run creds setup"));

    let malformed = directory.path().join("malformed.toml");
    fs::write(&malformed, "app_url = [\n").expect("write malformed synthetic TOML");
    set_mode(&malformed, 0o600);
    let output = run(&["--config", malformed.to_str().unwrap(), "check"]);
    let stderr = assert_plain_failure(&output);
    assert!(stderr.contains(&format!("Invalid configuration at {}", malformed.display())));
    assert!(stderr.contains("TOML parse error"));
}

#[test]
fn invalid_qr_mode_reports_the_supported_configuration_values() {
    let directory = ScratchDirectory::new();
    let config = ValidConfig::new(&directory);
    let contents = format!(
        "{}qr_mode = \"pixels\"\n",
        fs::read_to_string(&config.config).expect("read synthetic config")
    );
    fs::write(&config.config, contents).expect("write invalid synthetic QR mode");
    set_mode(&config.config, 0o600);

    let output = run(&["--config", config.config.to_str().unwrap(), "check"]);
    let stderr = assert_plain_failure(&output);
    assert!(stderr.contains("invalid qr_mode \"pixels\""), "{stderr}");
    assert!(stderr.contains("braille, sextant, half, kitty"), "{stderr}");
}

#[test]
fn missing_input_file_has_path_context() {
    let directory = ScratchDirectory::new();
    let missing = directory.path().join("input.bin");
    let output = run(&["encrypt", "synthetic-secret", missing.to_str().unwrap()]);
    let stderr = assert_plain_failure(&output);
    assert!(stderr.contains(&format!("Cannot read input file at {}", missing.display())));
    assert!(stderr.contains("check that the file exists"));
}

#[test]
fn malformed_envelope_and_busy_lock_fail_with_secret_context() {
    let directory = ScratchDirectory::new();
    let config = ValidConfig::new(&directory);
    let envelope = config.storage.join("synthetic-secret.json");
    fs::write(&envelope, b"not-json").expect("write malformed synthetic envelope");
    let output = run(&[
        "--config",
        config.config.to_str().unwrap(),
        "decrypt",
        "synthetic-secret",
        "-",
    ]);
    let stderr = assert_plain_failure(&output);
    assert!(stderr.contains("Cannot read secret \"synthetic-secret\""));
    assert!(stderr.contains(&envelope.display().to_string()));
    assert!(stderr.contains("malformed envelope JSON"));

    fs::remove_file(&envelope).expect("remove malformed synthetic envelope");
    fs::write(directory.path().join("input.bin"), b"synthetic plaintext")
        .expect("write synthetic input");
    let lock_path = config.storage.join("synthetic-secret.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .expect("create synthetic lock file");
    lock.try_lock_exclusive().expect("hold synthetic lock");
    let output = run(&[
        "--config",
        config.config.to_str().unwrap(),
        "encrypt",
        "synthetic-secret",
        directory.path().join("input.bin").to_str().unwrap(),
    ]);
    let stderr = assert_plain_failure(&output);
    assert!(stderr.contains("Secret \"synthetic-secret\" is busy with another encryption"));
    assert!(stderr.contains("synthetic-secret.lock"));
}

#[test]
fn existing_envelope_read_failure_reports_the_envelope_path() {
    let directory = ScratchDirectory::new();
    let config = ValidConfig::new(&directory);
    let envelope = config.storage.join("synthetic-secret.json");
    let lock_path = config.storage.join("synthetic-secret.lock");
    fs::create_dir(&envelope).expect("create synthetic envelope directory");
    let input = directory.path().join("input.bin");
    fs::write(&input, b"synthetic plaintext").expect("write synthetic input");

    let output = run(&[
        "--config",
        config.config.to_str().unwrap(),
        "encrypt",
        "synthetic-secret",
        input.to_str().unwrap(),
    ]);
    let stderr = assert_plain_failure(&output);
    assert!(
        stderr.contains(&format!(
            "Cannot read existing envelope for secret \"synthetic-secret\" at {}",
            envelope.display()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("Is a directory"), "{stderr}");
    assert!(
        !stderr.contains(&lock_path.display().to_string()),
        "{stderr}"
    );
    assert!(
        fs::metadata(lock_path)
            .expect("lock file was created before reading the envelope")
            .is_file()
    );
}

#[test]
fn lock_file_open_failure_reports_the_lock_path() {
    let directory = ScratchDirectory::new();
    let config = ValidConfig::new(&directory);
    let lock_path = config.storage.join("synthetic-secret.lock");
    let envelope = config.storage.join("synthetic-secret.json");
    fs::create_dir(&lock_path).expect("create synthetic lock path directory");
    let input = directory.path().join("input.bin");
    fs::write(&input, b"synthetic plaintext").expect("write synthetic input");

    let output = run(&[
        "--config",
        config.config.to_str().unwrap(),
        "encrypt",
        "synthetic-secret",
        input.to_str().unwrap(),
    ]);
    let stderr = assert_plain_failure(&output);
    assert!(
        stderr.contains(&format!(
            "Cannot open lock file for secret \"synthetic-secret\" at {}",
            lock_path.display()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("Is a directory"), "{stderr}");
    assert!(
        !stderr.contains(&envelope.display().to_string()),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn unreadable_config_error_names_the_path() {
    let directory = ScratchDirectory::new();
    let config = ValidConfig::new(&directory);
    set_mode(&config.config, 0);
    let output = run(&["--config", config.config.to_str().unwrap(), "check"]);
    // Some privileged environments can still read a mode-000 file. In that case
    // there is no permission failure to assert.
    if output.status.success() {
        return;
    }
    let stderr = assert_plain_failure(&output);
    assert!(stderr.contains(&format!(
        "Cannot read configuration at {}",
        config.config.display()
    )));
    assert!(stderr.contains("check file permissions"));
}

#[test]
fn remove_is_local_and_preserves_unrelated_files() {
    let directory = ScratchDirectory::new();
    let config = ValidConfig::new(&directory);
    let contents = String::from(
        "app_url = \"invalid\"\nhostname = \"invalid!\"\nstorage_dir = \"secrets\"\npublic_key = \"invalid\"\nlisten_addr = \"invalid\"\nqr_mode = \"invalid\"\n",
    );
    fs::write(&config.config, &contents).unwrap();
    let target = config.storage.join("synthetic-secret.json");
    fs::write(&target, b"malformed synthetic envelope").unwrap();
    for name in ["other.json", "other.lock", "other.tmp", "unrelated"] {
        fs::write(config.storage.join(name), name).unwrap();
    }
    let args = [
        "--config",
        config.config.to_str().unwrap(),
        "rm",
        "synthetic-secret",
    ];
    let output = run(&args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"Removed \"synthetic-secret\".\n");
    assert!(!target.exists());
    assert!(config.storage.join("synthetic-secret.lock").is_file());
    assert_eq!(fs::read_to_string(&config.config).unwrap(), contents);
    for name in ["other.json", "other.lock", "other.tmp", "unrelated"] {
        assert_eq!(
            fs::read(config.storage.join(name)).unwrap(),
            name.as_bytes()
        );
    }
    let stderr = assert_plain_failure(&run(&args));
    assert!(stderr.contains("not found at"));
    assert!(stderr.contains(&target.display().to_string()));
    let stderr = assert_plain_failure(&run(&[
        "--config",
        config.config.to_str().unwrap(),
        "rm",
        "../other",
    ]));
    assert!(stderr.contains("Invalid secret name"));
    assert!(config.storage.join("other.json").exists());
}

#[test]
fn remove_reports_lock_and_unlink_failures_and_respects_writer() {
    use creds::storage::SecretWriter;
    let directory = ScratchDirectory::new();
    let config = ValidConfig::new(&directory);
    let args = [
        "--config",
        config.config.to_str().unwrap(),
        "rm",
        "synthetic-secret",
    ];
    let writer = SecretWriter::begin(&config.storage, "synthetic-secret").unwrap();
    let stderr = assert_plain_failure(&run(&args));
    assert!(stderr.contains("busy"));
    writer.publish(b"synthetic", &[7; 32]).unwrap();
    assert!(config.storage.join("synthetic-secret.json").exists());
    assert!(run(&args).status.success());
    assert!(!config.storage.join("synthetic-secret.json").exists());
    fs::create_dir(config.storage.join("synthetic-secret.json")).unwrap();
    let stderr = assert_plain_failure(&run(&args));
    assert!(stderr.contains("Cannot remove secret"));
    assert!(stderr.contains("synthetic-secret.json"));
    fs::remove_dir(config.storage.join("synthetic-secret.json")).unwrap();
    fs::remove_file(config.storage.join("synthetic-secret.lock")).unwrap();
    fs::create_dir(config.storage.join("synthetic-secret.lock")).unwrap();
    let stderr = assert_plain_failure(&run(&args));
    assert!(stderr.contains("Cannot open lock file"));
    assert!(stderr.contains("synthetic-secret.lock"));
}
