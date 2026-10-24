use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    process::{Child, Command, Output, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use creds::envelope::Envelope;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::{Url, form_urlencoded};
use wtransport::{
    ClientConfig, Endpoint,
    config::{DnsLookupFuture, DnsResolver},
    endpoint::ConnectOptions,
    tls::Sha256Digest,
};

const APP_ORIGIN: &str = "https://keys.example";
const RP_ID: &str = "keys.example";
const MACHINE_DNS_SUFFIX: &str = "tailnet.example.net";
const MAX_STARTUP: Duration = Duration::from_secs(15);
const MAX_COMMAND: Duration = Duration::from_secs(20);

/// This deterministic key stands in for a passkey credential in the protocol fixture.
/// It exercises real signature verification, but it is not a physical authenticator.
fn fixture_signing_key() -> SigningKey {
    SigningKey::from_bytes((&[7_u8; 32]).into()).unwrap()
}

fn wrong_fixture_signing_key() -> SigningKey {
    SigningKey::from_bytes((&[8_u8; 32]).into()).unwrap()
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path =
            std::env::temp_dir().join(format!("creds-command-flow-{}-{nonce}", std::process::id()));
        fs::create_dir(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestConfig {
    path: PathBuf,
    storage: PathBuf,
}

impl TestConfig {
    fn new(directory: &TestDirectory) -> Result<Self, Box<dyn Error>> {
        let storage = directory.path().join("secrets");
        fs::create_dir(&storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&storage, fs::Permissions::from_mode(0o700))?;
        }

        let path = directory.path().join("config.toml");
        let public_key = fixture_signing_key().verifying_key().to_public_key_der()?;
        let contents = format!(
            "app_url = {app_url:?}\nhostname = \"workstation\"\nstorage_dir = {storage:?}\npublic_key = {public_key:?}\nlisten_addr = \"0.0.0.0:0\"\n",
            app_url = "https://keys.example/approval",
            storage = storage.to_string_lossy().as_ref(),
            public_key = URL_SAFE_NO_PAD.encode(public_key.as_bytes()),
        );
        fs::write(&path, contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self { path, storage })
    }
}

struct RunningCommand {
    child: Child,
    stderr_lines: Receiver<std::io::Result<Option<String>>>,
    stderr: String,
    handoff_url: Url,
}

impl RunningCommand {
    fn start(
        config: &TestConfig,
        operation: &str,
        name: &str,
        path: &Path,
        stdin: Option<&[u8]>,
    ) -> Result<Self, Box<dyn Error>> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_creds"));
        command
            .arg("--config")
            .arg(&config.path)
            .arg(operation)
            .arg(name)
            .arg(path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });

        let mut child = command.spawn()?;
        if let Some(bytes) = stdin {
            child
                .stdin
                .take()
                .expect("piped stdin is available")
                .write_all(bytes)?;
        }

        let stderr = child.stderr.take().expect("piped stderr is available");
        let (sender, stderr_lines) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        let _ = sender.send(Ok(None));
                        break;
                    }
                    Ok(_) => {
                        if sender.send(Ok(Some(line))).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        break;
                    }
                }
            }
        });

        let mut captured_stderr = String::new();
        let startup_deadline = Instant::now() + MAX_STARTUP;
        let handoff_url = loop {
            let remaining = startup_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let _ = child.kill();
                let _ = child.wait();
                return Err("command did not print a handoff URL within 15 seconds".into());
            }
            match stderr_lines.recv_timeout(remaining)? {
                Ok(Some(line)) => {
                    captured_stderr.push_str(&line);
                    if let Some(url) = line
                        .strip_prefix("Open this URL on the approval device: ")
                        .and_then(|value| Url::parse(value.trim()).ok())
                    {
                        break url;
                    }
                }
                Ok(None) => {
                    let status = child.wait()?;
                    return Err(format!(
                        "command exited before starting approval (status {status}): {captured_stderr}"
                    )
                    .into());
                }
                Err(error) => return Err(error.into()),
            }
        };

        Ok(Self {
            child,
            stderr_lines,
            stderr: captured_stderr,
            handoff_url,
        })
    }

    fn approve_url(&self) -> &Url {
        &self.handoff_url
    }

    fn interrupt(&mut self) -> Result<(), Box<dyn Error>> {
        let status = Command::new("kill")
            .arg("-INT")
            .arg(self.child.id().to_string())
            .status()?;
        if !status.success() {
            return Err(format!("could not send SIGINT to creds (status {status})").into());
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Output, Box<dyn Error>> {
        let deadline = Instant::now() + MAX_COMMAND;
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return Err("command did not finish within 20 seconds".into());
            }
            thread::sleep(Duration::from_millis(20));
        };

        let mut stdout = Vec::new();
        self.child
            .stdout
            .take()
            .expect("piped stdout is available")
            .read_to_end(&mut stdout)?;
        while let Ok(line) = self.stderr_lines.try_recv() {
            match line {
                Ok(Some(line)) => self.stderr.push_str(&line),
                Ok(None) => break,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(Output {
            status,
            stdout,
            stderr: self.stderr.into_bytes(),
        })
    }
}

#[derive(Debug)]
struct LoopbackResolver;

impl DnsResolver for LoopbackResolver {
    fn resolve(&self, host: &str) -> Pin<Box<dyn DnsLookupFuture>> {
        let port = host
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok());
        Box::pin(async move {
            let Some(port) = port else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "test resolver expected host:port",
                ));
            };
            Ok(Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)))
        })
    }
}

struct ApprovalSession {
    connection: wtransport::Connection,
    send: wtransport::SendStream,
    request: Value,
}

impl ApprovalSession {
    fn revision(&self) -> u64 {
        self.request["revision"].as_u64().unwrap()
    }

    fn approval_timeout_ms(&self) -> u64 {
        self.request["approvalTimeoutMs"].as_u64().unwrap()
    }

    fn assert_request(&self, name: &str, revision: u64, operation: &str) {
        assert_eq!(self.request["type"], "request");
        assert_eq!(self.request["version"], 1);
        assert!((1..=120_000).contains(&self.approval_timeout_ms()));
        assert_eq!(self.request["name"], name);
        assert_eq!(self.revision(), revision);
        assert_eq!(self.request["operation"], operation);
    }

    fn key_message(&self, key: [u8; 32], signer: &SigningKey) -> Result<Vec<u8>, Box<dyn Error>> {
        let challenge = self.request["challenge"].as_str().unwrap();
        let client_data = serde_json::to_vec(&json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": APP_ORIGIN,
        }))?;
        let mut authenticator_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        authenticator_data.extend_from_slice(&[0x05, 0, 0, 0, 1]);
        let mut signed_data = authenticator_data.clone();
        signed_data.extend_from_slice(&Sha256::digest(&client_data));
        let signature: Signature = signer.sign(&signed_data);
        let key_message = serde_json::to_vec(&json!({
            "type": "key",
            "version": 1,
            "key": URL_SAFE_NO_PAD.encode(key),
            "assertion": {
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
                "authenticatorData": URL_SAFE_NO_PAD.encode(authenticator_data),
                "signature": URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
            },
        }))?;
        Ok(key_message)
    }

    async fn send_message(mut self, message: &[u8]) -> Result<(), Box<dyn Error>> {
        write_frame(&mut self.send, message).await?;
        self.send.finish().await?;
        tokio::time::timeout(Duration::from_secs(5), self.connection.closed()).await?;
        Ok(())
    }

    async fn send_duplicate_message(mut self, message: &[u8]) -> Result<(), Box<dyn Error>> {
        write_frame(&mut self.send, message).await?;
        write_frame(&mut self.send, message).await?;
        self.send.finish().await?;
        tokio::time::timeout(Duration::from_secs(5), self.connection.closed()).await?;
        Ok(())
    }

    async fn send_key(self, key: [u8; 32], signer: &SigningKey) -> Result<(), Box<dyn Error>> {
        let message = self.key_message(key, signer)?;
        self.send_message(&message).await
    }
}

async fn connect_approval(url: &Url) -> Result<ApprovalSession, Box<dyn Error>> {
    let parameters = form_urlencoded::parse(url.fragment().unwrap_or_default().as_bytes())
        .into_owned()
        .collect::<std::collections::HashMap<_, _>>();
    let host = parameters.get("host").ok_or("handoff host is missing")?;
    let port = parameters
        .get("port")
        .ok_or("handoff port is missing")?
        .parse::<u16>()?;
    let request_id = parameters
        .get("request")
        .ok_or("handoff request is missing")?;
    let pin_bytes = URL_SAFE_NO_PAD.decode(
        parameters
            .get("cert")
            .ok_or("handoff certificate pin is missing")?,
    )?;
    let pin: [u8; 32] = pin_bytes.try_into().map_err(|_| "invalid pin length")?;
    let endpoint_host = format!("{host}.{MACHINE_DNS_SUFFIX}");

    let mut client_config = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([Sha256Digest::new(pin)])
        .build();
    client_config.set_dns_resolver(LoopbackResolver);
    let endpoint = Endpoint::client(client_config)?;
    let options = ConnectOptions::builder(format!("https://{endpoint_host}:{port}/key"))
        .add_header("origin", APP_ORIGIN)
        .build();
    let connection =
        tokio::time::timeout(Duration::from_secs(10), endpoint.connect(options)).await??;
    let opening = connection.open_bi().await?;
    let (mut send, mut receive) = opening.await?;
    let hello = serde_json::to_vec(&json!({
        "type": "hello",
        "version": 1,
        "request": request_id,
    }))?;
    write_frame(&mut send, &hello).await?;
    let request: Value = serde_json::from_slice(&read_frame(&mut receive).await?)?;
    Ok(ApprovalSession {
        connection,
        send,
        request,
    })
}

async fn write_frame(
    stream: &mut wtransport::SendStream,
    body: &[u8],
) -> Result<(), Box<dyn Error>> {
    stream
        .write_all(&(u32::try_from(body.len())?).to_be_bytes())
        .await?;
    stream.write_all(body).await?;
    Ok(())
}

async fn read_frame(stream: &mut wtransport::RecvStream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut header = [0_u8; 4];
    read_exact(stream, &mut header).await?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > 16 * 1024 {
        return Err("server frame length was outside the v1 bounds".into());
    }
    let mut body = vec![0_u8; size];
    read_exact(stream, &mut body).await?;
    Ok(body)
}

async fn read_exact(
    stream: &mut wtransport::RecvStream,
    output: &mut [u8],
) -> Result<(), Box<dyn Error>> {
    let mut offset = 0;
    while offset < output.len() {
        match stream.read(&mut output[offset..]).await? {
            Some(0) | None => return Err("server closed a truncated frame".into()),
            Some(count) => offset += count,
        }
    }
    Ok(())
}

fn assert_silent_encryption(output: Output, expected_revision: u64) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "encryption wrote to stdout");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("revision {expected_revision}")),
        "{stderr}"
    );
    assert!(
        stderr.contains("Waiting for a browser connection"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Approval request established. Waiting up to two minutes"),
        "{stderr}"
    );
}

#[tokio::test]
async fn encrypt_decrypt_commands_use_authenticated_live_handoffs_and_frozen_snapshots()
-> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let config = TestConfig::new(&directory)?;
    let fixture_signer = fixture_signing_key();
    let wrong_signer = wrong_fixture_signing_key();
    let file_input = directory.path().join("source.bin");
    let file_output = directory.path().join("file-output.bin");
    let binary_one = [0, 0xff, 0x80, b'\n', 0x41, 0];
    let binary_two = [0xf0, 0, 0x7f, 0xfe, b'x'];
    let binary_three = [0x83, b'c', 0, b'r', 0xff];
    let key_one = [0x11; 32];
    let key_two = [0x22; 32];
    let key_three = [0x33; 32];

    fs::write(&file_input, binary_one)?;
    let encrypt_file = RunningCommand::start(&config, "encrypt", "primary", &file_input, None)?;
    let approval = connect_approval(encrypt_file.approve_url()).await?;
    approval.assert_request("primary", 1, "encrypt");
    assert_eq!(approval.approval_timeout_ms(), 120_000);
    approval.send_key(key_one, &fixture_signer).await?;
    assert_silent_encryption(encrypt_file.finish()?, 1);

    let decrypt_file = RunningCommand::start(&config, "decrypt", "primary", &file_output, None)?;
    let approval = connect_approval(decrypt_file.approve_url()).await?;
    approval.assert_request("primary", 1, "decrypt");
    approval.send_key(key_one, &fixture_signer).await?;
    let decrypted = decrypt_file.finish()?;
    assert!(
        decrypted.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypted.stderr)
    );
    assert!(decrypted.stdout.is_empty());
    assert_eq!(fs::read(&file_output)?, binary_one);

    let encrypt_stdin = RunningCommand::start(
        &config,
        "encrypt",
        "primary",
        Path::new("-"),
        Some(&binary_two),
    )?;
    let approval = connect_approval(encrypt_stdin.approve_url()).await?;
    approval.assert_request("primary", 2, "encrypt");
    approval.send_key(key_two, &fixture_signer).await?;
    assert_silent_encryption(encrypt_stdin.finish()?, 2);

    // Start decrypt before replacement, then publish revision 3 before approving it.
    // The immutable request and the encrypted snapshot must both remain at revision 2.
    let decrypt_stdout =
        RunningCommand::start(&config, "decrypt", "primary", Path::new("-"), None)?;
    let frozen_approval = connect_approval(decrypt_stdout.approve_url()).await?;
    frozen_approval.assert_request("primary", 2, "decrypt");

    let replace_while_decrypt_waits = RunningCommand::start(
        &config,
        "encrypt",
        "primary",
        Path::new("-"),
        Some(&binary_three),
    )?;
    let replacement_approval = connect_approval(replace_while_decrypt_waits.approve_url()).await?;
    replacement_approval.assert_request("primary", 3, "encrypt");
    replacement_approval
        .send_key(key_three, &fixture_signer)
        .await?;
    assert_silent_encryption(replace_while_decrypt_waits.finish()?, 3);

    assert_eq!(frozen_approval.revision(), 2);
    frozen_approval.send_key(key_two, &fixture_signer).await?;
    let decrypted_stdout = decrypt_stdout.finish()?;
    assert!(
        decrypted_stdout.status.success(),
        "{}",
        String::from_utf8_lossy(&decrypted_stdout.stderr)
    );
    assert_eq!(decrypted_stdout.stdout, binary_two);

    // Empty stdin is a valid exact payload and first creation uses revision 1.
    let empty_encrypt =
        RunningCommand::start(&config, "encrypt", "empty", Path::new("-"), Some(&[]))?;
    let approval = connect_approval(empty_encrypt.approve_url()).await?;
    approval.assert_request("empty", 1, "encrypt");
    approval.send_key(key_one, &fixture_signer).await?;
    assert_silent_encryption(empty_encrypt.finish()?, 1);

    let empty_stdout = RunningCommand::start(&config, "decrypt", "empty", Path::new("-"), None)?;
    let approval = connect_approval(empty_stdout.approve_url()).await?;
    approval.assert_request("empty", 1, "decrypt");
    approval.send_key(key_one, &fixture_signer).await?;
    let empty_decryption = empty_stdout.finish()?;
    assert!(empty_decryption.status.success());
    assert!(empty_decryption.stdout.is_empty());

    // An invalid signature is rejected by the real listener. Cancelling the CLI then
    // preserves the prior ciphertext and never replaces an existing output file.
    let ciphertext_path = config.storage.join("primary.json");
    let ciphertext_before = fs::read(&ciphertext_path)?;
    let failed_replace = RunningCommand::start(
        &config,
        "encrypt",
        "primary",
        Path::new("-"),
        Some(b"must not publish"),
    )?;
    let rejected = connect_approval(failed_replace.approve_url()).await?;
    rejected.assert_request("primary", 4, "encrypt");
    rejected.send_key(key_one, &wrong_signer).await?;
    let mut failed_replace = failed_replace;
    failed_replace.interrupt()?;
    let cancelled_replace = failed_replace.finish()?;
    assert!(!cancelled_replace.status.success());
    assert!(String::from_utf8_lossy(&cancelled_replace.stderr).contains("cancelled"));
    assert_eq!(fs::read(&ciphertext_path)?, ciphertext_before);

    fs::write(&file_output, b"existing destination")?;
    let failed_decrypt = RunningCommand::start(&config, "decrypt", "primary", &file_output, None)?;
    let rejected = connect_approval(failed_decrypt.approve_url()).await?;
    rejected.assert_request("primary", 3, "decrypt");
    rejected.send_key(key_one, &wrong_signer).await?;
    let mut failed_decrypt = failed_decrypt;
    failed_decrypt.interrupt()?;
    let cancelled_decrypt = failed_decrypt.finish()?;
    assert!(!cancelled_decrypt.status.success());
    assert!(String::from_utf8_lossy(&cancelled_decrypt.stderr).contains("cancelled"));
    assert_eq!(fs::read(&ciphertext_path)?, ciphertext_before);
    assert_eq!(fs::read(&file_output)?, b"existing destination");

    // A valid passkey assertion with a key from the wrong revision must fail before
    // the exclusive output file is created or changed.
    let mismatched_key_decrypt =
        RunningCommand::start(&config, "decrypt", "primary", &file_output, None)?;
    let approval = connect_approval(mismatched_key_decrypt.approve_url()).await?;
    approval.assert_request("primary", 3, "decrypt");
    approval.send_key(key_two, &fixture_signer).await?;
    let mismatched_key = mismatched_key_decrypt.finish()?;
    assert!(!mismatched_key.status.success());
    assert!(mismatched_key.stdout.is_empty());
    assert_eq!(fs::read(&ciphertext_path)?, ciphertext_before);
    assert_eq!(fs::read(&file_output)?, b"existing destination");

    Ok(())
}

#[tokio::test]
async fn simultaneous_sessions_reject_duplicate_and_cross_connection_responses()
-> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let config = TestConfig::new(&directory)?;
    let signer = fixture_signing_key();
    let plaintext = b"only one live session may publish";
    let key_a = [0xa1; 32];
    let key_c = [0xc3; 32];
    let key_d = [0xd4; 32];
    let command =
        RunningCommand::start(&config, "encrypt", "race", Path::new("-"), Some(plaintext))?;

    let session_a = connect_approval(command.approve_url()).await?;
    let session_b = connect_approval(command.approve_url()).await?;
    let session_c = connect_approval(command.approve_url()).await?;
    let session_d = connect_approval(command.approve_url()).await?;
    session_a.assert_request("race", 1, "encrypt");
    session_b.assert_request("race", 1, "encrypt");
    session_c.assert_request("race", 1, "encrypt");
    session_d.assert_request("race", 1, "encrypt");
    let approval_times = [
        session_a.approval_timeout_ms(),
        session_b.approval_timeout_ms(),
        session_c.approval_timeout_ms(),
        session_d.approval_timeout_ms(),
    ];
    assert_eq!(approval_times[0], 120_000);
    assert!(approval_times.windows(2).all(|pair| pair[0] >= pair[1]));
    let challenge_a = session_a.request["challenge"].as_str().unwrap().to_owned();
    let challenge_b = session_b.request["challenge"].as_str().unwrap();
    let challenge_c = session_c.request["challenge"].as_str().unwrap();
    let challenge_d = session_d.request["challenge"].as_str().unwrap();
    assert_ne!(challenge_a, challenge_b);
    assert_ne!(challenge_a, challenge_c);
    assert_ne!(challenge_a, challenge_d);
    assert_ne!(challenge_b, challenge_c);
    assert_ne!(challenge_b, challenge_d);
    assert_ne!(challenge_c, challenge_d);

    let replay = session_a.key_message(key_a, &signer)?;
    let replayed_key = URL_SAFE_NO_PAD.encode(key_c);
    assert!(!command.approve_url().as_str().contains(&replayed_key));
    let key_d_encoded = URL_SAFE_NO_PAD.encode(key_d);
    assert!(!command.approve_url().as_str().contains(&key_d_encoded));

    // A repeated response on session A and A's valid signature replayed on B
    // both fail. The two remaining sessions race with their own valid challenges.
    session_a.send_duplicate_message(&replay).await?;
    session_b.send_message(&replay).await?;
    let (response_c, response_d) = tokio::join!(
        session_c.send_key(key_c, &signer),
        session_d.send_key(key_d, &signer)
    );
    assert!(
        response_c.is_ok() || response_d.is_ok(),
        "both valid concurrent responses failed: {response_c:?}; {response_d:?}"
    );

    let output = command.finish()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains(&replayed_key));
    assert!(!stderr.contains(&replayed_key));
    assert!(!stdout.contains(&key_d_encoded));
    assert!(!stderr.contains(&key_d_encoded));

    let envelope_path = config.storage.join("race.json");
    let envelope = Envelope::parse(&fs::read(&envelope_path)?)?;
    let decrypted_c = envelope.decrypt(&key_c);
    let decrypted_d = envelope.decrypt(&key_d);
    assert_ne!(
        decrypted_c.is_ok(),
        decrypted_d.is_ok(),
        "exactly one concurrent valid response must win"
    );
    if let Ok(decrypted) = decrypted_c {
        assert_eq!(decrypted.as_slice(), plaintext);
    }
    if let Ok(decrypted) = decrypted_d {
        assert_eq!(decrypted.as_slice(), plaintext);
    }
    assert!(envelope.decrypt(&key_a).is_err());

    let files = fs::read_dir(&config.storage)?
        .map(|entry| {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let contents = fs::read(entry.path())?;
            Ok::<_, std::io::Error>((name, contents))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert!(files.iter().any(|(name, _)| name == "race.json"));
    for (name, contents) in files {
        assert!(!name.ends_with(".tmp"), "left a staging file: {name}");
        assert!(
            !String::from_utf8_lossy(&contents).contains(&replayed_key),
            "stored {name} contains the approved key"
        );
        assert!(
            !String::from_utf8_lossy(&contents).contains(&key_d_encoded),
            "stored {name} contains the approved key"
        );
    }
    Ok(())
}
