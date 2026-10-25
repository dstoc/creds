use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};

struct ScratchDirectory(PathBuf);

impl ScratchDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after UNIX epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("creds-cli-setup-{}-{nonce}", std::process::id()));
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

fn run(args: &[&str], input: &[u8], directory: &ScratchDirectory) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_creds"))
        .args(args)
        .env("XDG_DATA_HOME", directory.path().join("xdg-data"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start creds CLI");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(input)
        .expect("write supplied CLI input");
    child.wait_with_output().expect("wait for creds CLI")
}

fn public_key() -> String {
    let signing_key = SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap();
    let public_key = signing_key.verifying_key().to_public_key_der().unwrap();
    URL_SAFE_NO_PAD.encode(public_key.as_bytes())
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

fn write_valid_config(config: &Path, storage: &Path) {
    fs::create_dir_all(storage).expect("create synthetic storage directory");
    set_mode(storage, 0o700);
    let contents = format!(
        "app_url = \"https://keys.example/path\"\nhostname = \"workstation\"\nstorage_dir = \"{}\"\npublic_key = \"{}\"\nlisten_addr = \"127.0.0.1:0\"\n",
        storage.display(),
        public_key()
    );
    fs::write(config, contents).expect("write synthetic configuration");
    set_mode(config, 0o600);
}

#[test]
fn setup_validates_answers_and_retries_before_the_next_field() {
    let directory = ScratchDirectory::new();
    let config = directory.path().join("config/config.toml");
    let storage_file = directory.path().join("storage-file");
    let storage_dir = directory.path().join("secrets");
    fs::write(&storage_file, b"synthetic file").expect("write synthetic non-directory");
    let key = public_key();
    let input = format!(
        "http://keys.example\nhttps://keys.example/path\nbad.host\nworkstation\n{}\n{}\nnot-a-key\n{}\nlocalhost:0\n127.0.0.1:0\ny\n",
        storage_file.display(),
        storage_dir.display(),
        key
    );
    let output = run(
        &["--config", config.to_str().unwrap(), "setup"],
        input.as_bytes(),
        &directory,
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("Setup saved to {}\n", config.display())
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    for (earlier, later) in [
        ("Invalid Trusted app HTTPS URL:", "Machine DNS label"),
        ("Invalid Machine DNS label:", "Secret storage directory"),
        ("Invalid Secret storage directory:", "Passkey public key"),
        ("Invalid Passkey public key:", "UDP listener address"),
        ("Invalid UDP listener address:", "Review setup"),
    ] {
        assert!(
            stderr.find(earlier).unwrap() < stderr.find(later).unwrap(),
            "invalid answer was not corrected before the next field:\n{stderr}"
        );
    }
    assert!(stderr.contains("Trust this pinned passkey key and save? [y/N]:"));
    assert!(!stderr.contains("30 seconds"));
    assert!(config.is_file());
    assert!(storage_dir.is_dir());
}

#[test]
fn setup_eof_cancels_without_saving_or_creating_storage() {
    let directory = ScratchDirectory::new();
    let config = directory.path().join("config.toml");
    let output = run(
        &["--config", config.to_str().unwrap(), "setup"],
        b"",
        &directory,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("Setup cancelled because input ended")
    );
    assert!(!config.exists());
    assert!(!directory.path().join("xdg-data/creds/secrets").exists());
}

#[test]
fn setup_declines_replacement_without_changing_existing_configuration() {
    let directory = ScratchDirectory::new();
    let config = directory.path().join("config.toml");
    fs::write(&config, b"synthetic existing configuration").unwrap();
    let original = fs::read(&config).unwrap();
    let output = run(
        &["--config", config.to_str().unwrap(), "setup"],
        b"n\n",
        &directory,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(&format!(
        "Configuration {} exists. Replace it? [y/N]:",
        config.display()
    )));
    assert!(stderr.contains("Setup cancelled; existing configuration was not changed"));
    assert_eq!(fs::read(config).unwrap(), original);
}

#[test]
fn setup_declines_pinned_key_trust_without_saving_or_creating_storage() {
    let directory = ScratchDirectory::new();
    let config = directory.path().join("config.toml");
    let storage = directory.path().join("secrets");
    let input = format!(
        "https://keys.example/path\nworkstation\n{}\n{}\n127.0.0.1:0\nn\n",
        storage.display(),
        public_key()
    );
    let output = run(
        &["--config", config.to_str().unwrap(), "setup"],
        input.as_bytes(),
        &directory,
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Trust this pinned passkey key and save? [y/N]:"));
    assert!(stderr.contains("Setup cancelled; configuration was not written"));
    assert!(!config.exists());
    assert!(!storage.exists());
}

#[test]
fn check_defaults_to_one_truthful_line_and_details_show_resolved_setup() {
    let directory = ScratchDirectory::new();
    let config = directory.path().join("config.toml");
    let storage = directory.path().join("secrets");
    write_valid_config(&config, &storage);

    let default = run(
        &["--config", config.to_str().unwrap(), "check"],
        b"",
        &directory,
    );
    assert!(default.status.success());
    assert!(default.stderr.is_empty());
    assert_eq!(
        String::from_utf8(default.stdout).unwrap(),
        "Local setup is valid.\n"
    );

    let detailed = run(
        &["--config", config.to_str().unwrap(), "check", "--details"],
        b"",
        &directory,
    );
    assert!(detailed.status.success());
    assert!(detailed.stderr.is_empty());
    let stdout = String::from_utf8(detailed.stdout).unwrap();
    for expected in [
        "Local setup is valid.",
        &format!("Configuration: {}", config.display()),
        &format!("Storage: {}", storage.display()),
        "App origin: https://keys.example",
        "RP ID: keys.example",
        "Machine label: workstation",
        "UDP listener: 127.0.0.1:0",
        "Pinned public-key fingerprint: SHA-256:",
        "does not prove passkey possession, network reachability, or secret decryptability",
    ] {
        assert!(stdout.contains(expected), "missing {expected:?}: {stdout}");
    }
}
