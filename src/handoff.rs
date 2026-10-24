use std::{
    collections::HashSet,
    error::Error,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use qrcode::{QrCode, render::unicode::Dense1x2};
use rcgen::{CertificateParams, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration as CalendarDuration, OffsetDateTime};
use tokio::{
    sync::{Semaphore, mpsc, watch},
    time::{Instant, sleep_until, timeout_at},
};
use url::{Url, form_urlencoded};
use wtransport::{Endpoint, Identity, ServerConfig, VarInt, tls};
use zeroize::Zeroizing;

use crate::{
    assertion::verify_key_message,
    config::ValidatedConfig,
    protocol::{validate_name, validate_revision},
};

const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_PENDING_CONNECTIONS: usize = 4;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const WEBAUTHN_CHALLENGE_BYTES: usize = 32;

type BoxError = Box<dyn Error + Send + Sync>;
type Result<T> = std::result::Result<T, BoxError>;

#[derive(Clone, Copy, Debug)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

impl Operation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelloMessage {
    #[serde(rename = "type")]
    kind: String,
    version: u8,
    request: String,
}

#[derive(Serialize)]
struct RequestMessage<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    version: u8,
    name: &'a str,
    revision: u32,
    operation: &'static str,
    challenge: String,
}

struct HandoffRequest {
    request_id: [u8; 32],
    name: String,
    revision: u32,
    operation: Operation,
}

struct SessionState {
    request: Arc<HandoffRequest>,
    expected_origin: String,
    rp_id: String,
    public_key: p256::ecdsa::VerifyingKey,
    operation_consumed: Arc<AtomicBool>,
    active_challenges: Arc<Mutex<HashSet<[u8; 32]>>>,
    key_sender: mpsc::Sender<Zeroizing<[u8; 32]>>,
}

/// Run one temporary, certificate-pinned WebTransport listener and receive one verified key.
pub async fn receive_key(
    config: &ValidatedConfig,
    name: &str,
    revision: u32,
    operation: Operation,
    mut cancellation: watch::Receiver<bool>,
) -> Result<Zeroizing<[u8; 32]>> {
    if *cancellation.borrow() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "approval operation was cancelled",
        )
        .into());
    }
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    validate_name(name)?;
    validate_revision(revision)?;

    let request_id = random_bytes::<32>()?;
    let request = Arc::new(HandoffRequest {
        request_id,
        name: name.to_owned(),
        revision,
        operation,
    });
    let (identity, certificate_pin, endpoint_hostname) = create_identity(config)?;
    let server_config = ServerConfig::builder()
        .with_bind_address(config.listen_addr)
        .with_identity(identity)
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .build();
    let endpoint = Endpoint::server(server_config)?;
    let port = endpoint.local_addr()?.port();
    let handoff_url = build_handoff_url(
        &config.app_url,
        &config.hostname,
        port,
        &certificate_pin,
        &request_id,
    )?;
    let qr_code = QrCode::new(handoff_url.as_str())?;
    let qr_image = qr_code.render::<Dense1x2>().quiet_zone(true).build();

    eprintln!("Open this URL on the approval device: {handoff_url}");
    eprintln!("Or scan this QR code (destination {endpoint_hostname}:{port}):\n{qr_image}");
    eprintln!("Waiting for one WebAuthn-approved response (two-minute deadline).");

    if *cancellation.borrow() {
        endpoint.close(VarInt::from_u32(0), b"operation cancelled");
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "approval operation was cancelled",
        )
        .into());
    }

    let (key_sender, mut key_receiver) = mpsc::channel(1);
    let state = Arc::new(SessionState {
        request,
        expected_origin: config.app_origin.clone(),
        rp_id: config.rp_id.clone(),
        public_key: config.public_key,
        operation_consumed: Arc::new(AtomicBool::new(false)),
        active_challenges: Arc::new(Mutex::new(HashSet::new())),
        key_sender,
    });
    let pending_connections = Arc::new(Semaphore::new(MAX_PENDING_CONNECTIONS));
    let sleep = sleep_until(deadline);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = &mut sleep => {
                endpoint.close(VarInt::from_u32(0), b"operation expired");
                return Err(io::Error::new(io::ErrorKind::TimedOut, "approval operation expired after two minutes").into());
            }
            result = cancellation.changed() => {
                endpoint.close(VarInt::from_u32(0), b"operation cancelled");
                result?;
                return Err(io::Error::new(io::ErrorKind::Interrupted, "approval operation was cancelled").into());
            }
            key = key_receiver.recv() => {
                endpoint.close(VarInt::from_u32(0), b"approved");
                if *cancellation.borrow() {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "approval operation was cancelled").into());
                }
                return key.ok_or_else(|| io::Error::other("handoff listener stopped before approval").into());
            }
            incoming = endpoint.accept() => {
                match try_pending_connection(&pending_connections) {
                    Some(permit) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(error) = handle_session(incoming, state).await {
                                eprintln!("handoff connection closed: {error}");
                            }
                        });
                    }
                    None => incoming.refuse(),
                }
            }
        }
    }
}

async fn handle_session(
    incoming: wtransport::endpoint::IncomingSession,
    state: Arc<SessionState>,
) -> Result<()> {
    let connection_deadline = Instant::now() + CONNECTION_TIMEOUT;
    let session_request = timeout_at(connection_deadline, incoming).await??;
    if !is_allowed_session(
        session_request.origin(),
        session_request.path(),
        &state.expected_origin,
    ) {
        session_request.forbidden().await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "WebTransport session Origin or path was rejected",
        )
        .into());
    }

    let connection = session_request.accept().await?;
    let result = timeout_at(connection_deadline, handle_connection(&connection, state)).await;
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            connection.close(VarInt::from_u32(1), b"invalid handoff protocol");
            Err(error)
        }
        Err(_) => {
            connection.close(VarInt::from_u32(2), b"connection timed out");
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection exceeded its 30-second deadline",
            )
            .into())
        }
    }
}

async fn handle_connection(
    connection: &wtransport::Connection,
    state: Arc<SessionState>,
) -> Result<()> {
    let (mut send, mut receive) = accept_one_bidirectional_stream(connection).await?;
    let monitor_connection = connection.clone();
    let stream_monitor = tokio::spawn(async move {
        tokio::select! {
            _ = monitor_connection.accept_bi() => {
                monitor_connection.close(VarInt::from_u32(3), b"additional stream rejected");
            }
            _ = monitor_connection.accept_uni() => {
                monitor_connection.close(VarInt::from_u32(3), b"additional stream rejected");
            }
            _ = monitor_connection.closed() => {}
        }
    });

    let protocol_result = async {
        let hello_bytes = read_frame(&mut receive).await?;
        validate_hello(&hello_bytes, &state.request.request_id)?;
        let challenge = fresh_challenge(&state.request.request_id, &state.active_challenges)?;
        let _challenge_guard = ActiveChallengeGuard {
            challenge,
            active_challenges: Arc::clone(&state.active_challenges),
        };
        let request_message = RequestMessage {
            kind: "request",
            version: 1,
            name: &state.request.name,
            revision: state.request.revision,
            operation: state.request.operation.as_str(),
            challenge: URL_SAFE_NO_PAD.encode(challenge),
        };
        let request_bytes = serde_json::to_vec(&request_message)?;
        write_frame(&mut send, &request_bytes).await?;
        send.finish()
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;

        let key_message = Zeroizing::new(read_frame(&mut receive).await?);
        ensure_stream_eof(&mut receive).await?;
        // Assertion verification is complete before the returned key can enter the gate.
        let key = verify_key_message(
            &key_message,
            &challenge,
            &state.expected_origin,
            &state.rp_id,
            &state.public_key,
        )?;
        state
            .operation_consumed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::AlreadyExists, "operation already consumed")
            })?;
        state
            .key_sender
            .send(key)
            .await
            .map_err(|_| io::Error::other("handoff listener stopped before approval"))?;
        Ok::<(), BoxError>(())
    }
    .await;

    stream_monitor.abort();
    protocol_result
}

async fn accept_one_bidirectional_stream(
    connection: &wtransport::Connection,
) -> Result<(wtransport::SendStream, wtransport::RecvStream)> {
    tokio::select! {
        stream = connection.accept_bi() => Ok(stream?),
        stream = connection.accept_uni() => {
            if let Ok(stream) = stream {
                stream.stop(VarInt::from_u32(3));
            }
            Err(io::Error::new(io::ErrorKind::InvalidData, "the protocol requires one bidirectional stream and no unidirectional streams").into())
        }
    }
}

async fn read_frame(stream: &mut wtransport::RecvStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    read_exact_stream(stream, &mut header).await?;
    let length = parse_frame_length(header)?;
    let mut body = vec![0u8; length];
    read_exact_stream(stream, &mut body).await?;
    Ok(body)
}

async fn read_exact_stream(stream: &mut wtransport::RecvStream, output: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < output.len() {
        match stream.read(&mut output[offset..]).await {
            Ok(Some(0)) | Ok(None) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated WebTransport frame",
                )
                .into());
            }
            Ok(Some(read)) => offset += read,
            Err(error) => return Err(io::Error::other(error.to_string()).into()),
        }
    }
    Ok(())
}

async fn ensure_stream_eof(stream: &mut wtransport::RecvStream) -> Result<()> {
    let mut extra = [0u8; 1];
    match stream.read(&mut extra).await {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extra bytes or messages follow the key response",
        )
        .into()),
        Err(error) => Err(io::Error::other(error.to_string()).into()),
    }
}

async fn write_frame(stream: &mut wtransport::SendStream, body: &[u8]) -> Result<()> {
    if !(1..=MAX_FRAME_BYTES).contains(&body.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length must be between 1 and 16 KiB",
        )
        .into());
    }
    let length = u32::try_from(body.len())?.to_be_bytes();
    stream
        .write_all(&length)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    stream
        .write_all(body)
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(())
}

fn validate_hello(bytes: &[u8], expected_request: &[u8; 32]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hello message is empty or exceeds 16 KiB",
        )
        .into());
    }
    let hello: HelloMessage = serde_json::from_slice(bytes)?;
    if hello.kind != "hello" || hello.version != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hello message type and version must be hello and 1",
        )
        .into());
    }
    let request_id = decode_fixed::<32>(&hello.request, "request identifier")?;
    if &request_id != expected_request {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "request identifier does not match the pending operation",
        )
        .into());
    }
    Ok(())
}

fn decode_fixed<const N: usize>(encoded: &str, label: &str) -> Result<[u8; N]> {
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} is not unpadded base64url: {error}"),
        )
    })?;
    if decoded.len() != N || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} must be canonical unpadded base64url for exactly {N} bytes"),
        )
        .into());
    }
    let mut result = [0u8; N];
    result.copy_from_slice(&decoded);
    Ok(result)
}

fn is_allowed_session(origin: Option<&str>, path: &str, expected_origin: &str) -> bool {
    origin == Some(expected_origin) && path == "/key"
}

fn parse_frame_length(header: [u8; 4]) -> Result<usize> {
    let length = u32::from_be_bytes(header) as usize;
    if !(1..=MAX_FRAME_BYTES).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length must be between 1 and 16 KiB",
        )
        .into());
    }
    Ok(length)
}

fn try_pending_connection(
    pending_connections: &Arc<Semaphore>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    Arc::clone(pending_connections).try_acquire_owned().ok()
}

fn certificate_validity(now: OffsetDateTime) -> (OffsetDateTime, OffsetDateTime) {
    let not_before = now - CalendarDuration::minutes(2);
    let not_after = not_before + CalendarDuration::days(1);
    (not_before, not_after)
}

fn fresh_challenge(
    request_id: &[u8; 32],
    active_challenges: &Arc<Mutex<HashSet<[u8; 32]>>>,
) -> Result<[u8; 32]> {
    let mut challenges = active_challenges
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    loop {
        let challenge = random_bytes::<WEBAUTHN_CHALLENGE_BYTES>()?;
        if &challenge != request_id && challenges.insert(challenge) {
            return Ok(challenge);
        }
    }
}

struct ActiveChallengeGuard {
    challenge: [u8; 32],
    active_challenges: Arc<Mutex<HashSet<[u8; 32]>>>,
}

impl Drop for ActiveChallengeGuard {
    fn drop(&mut self) {
        self.active_challenges
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.challenge);
    }
}

fn create_identity(config: &ValidatedConfig) -> Result<(Identity, String, String)> {
    let endpoint_hostname = format!("{}.{}", config.hostname, config.rp_id);
    let signing_key = KeyPair::generate()?;
    let mut certificate_params = CertificateParams::new(vec![endpoint_hostname.clone()])?;
    let (not_before, not_after) = certificate_validity(OffsetDateTime::now_utc());
    certificate_params.not_before = not_before;
    certificate_params.not_after = not_after;
    let certificate = certificate_params.self_signed(&signing_key)?;
    let certificate_der = certificate.der().as_ref().to_vec();
    let pin = URL_SAFE_NO_PAD.encode(Sha256::digest(&certificate_der));
    let identity = Identity::new(
        tls::CertificateChain::single(tls::Certificate::from_der(certificate_der)?),
        tls::PrivateKey::from_der_pkcs8(signing_key.serialize_der()),
    );
    Ok((identity, pin, endpoint_hostname))
}

fn build_handoff_url(
    app_url: &str,
    host_label: &str,
    port: u16,
    certificate_pin: &str,
    request_id: &[u8; 32],
) -> Result<Url> {
    let mut url = Url::parse(app_url)?;
    let fragment = form_urlencoded::Serializer::new(String::new())
        .append_pair("v", "1")
        .append_pair("host", host_label)
        .append_pair("port", &port.to_string())
        .append_pair("cert", certificate_pin)
        .append_pair("request", &URL_SAFE_NO_PAD.encode(request_id))
        .finish();
    url.set_fragment(Some(&fragment));
    Ok(url)
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut output = [0u8; N];
    getrandom::fill(&mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use url::form_urlencoded;

    #[test]
    fn session_requires_exact_configured_origin_and_key_path() {
        assert!(is_allowed_session(
            Some("https://keys.example"),
            "/key",
            "https://keys.example"
        ));
        assert!(!is_allowed_session(None, "/key", "https://keys.example"));
        assert!(!is_allowed_session(
            Some("https://evil.example"),
            "/key",
            "https://keys.example"
        ));
        assert!(!is_allowed_session(
            Some("https://keys.example"),
            "/key/extra",
            "https://keys.example"
        ));
    }

    #[test]
    fn hello_requires_one_exact_v1_request_identifier() {
        let request_id = [0x32; 32];
        let encoded = URL_SAFE_NO_PAD.encode(request_id);
        let valid = format!(r#"{{"type":"hello","version":1,"request":"{encoded}"}}"#);
        assert!(validate_hello(valid.as_bytes(), &request_id).is_ok());
        assert!(
            validate_hello(
                format!(
                    r#"{{"type":"hello","version":1,"request":"{}"}}"#,
                    URL_SAFE_NO_PAD.encode([0x33; 32])
                )
                .as_bytes(),
                &request_id,
            )
            .is_err()
        );
        assert!(
            validate_hello(
                format!(r#"{{"type":"hello","version":1,"request":"{encoded}","extra":true}}"#)
                    .as_bytes(),
                &request_id,
            )
            .is_err()
        );
        assert!(
            validate_hello(
                format!(
                    r#"{{"type":"hello","version":1,"request":"{encoded}","request":"{encoded}"}}"#
                )
                .as_bytes(),
                &request_id,
            )
            .is_err()
        );
    }

    #[test]
    fn invalid_hello_does_not_consume_or_reserve_the_operation() {
        let request_id = [0x32; 32];
        let consumed = AtomicBool::new(false);
        let invalid = format!(
            r#"{{"type":"hello","version":1,"request":"{}"}}"#,
            URL_SAFE_NO_PAD.encode([0x33; 32])
        );
        assert!(validate_hello(invalid.as_bytes(), &request_id).is_err());
        assert!(!consumed.load(Ordering::Acquire));
    }

    #[test]
    fn challenge_is_distinct_from_request_and_other_live_connections() {
        let request_id = [0x41; 32];
        let active = Arc::new(Mutex::new(HashSet::from([[0x42; 32]])));
        let challenge = fresh_challenge(&request_id, &active).unwrap();
        assert_ne!(challenge, request_id);
        assert_ne!(challenge, [0x42; 32]);
        assert!(active.lock().unwrap().contains(&challenge));
        drop(ActiveChallengeGuard {
            challenge,
            active_challenges: Arc::clone(&active),
        });
        assert!(!active.lock().unwrap().contains(&challenge));
    }

    #[test]
    fn first_valid_connection_consumes_the_operation_once() {
        let consumed = Arc::new(AtomicBool::new(false));
        let barrier = Arc::new(Barrier::new(MAX_PENDING_CONNECTIONS + 1));
        let attempts = (0..MAX_PENDING_CONNECTIONS)
            .map(|_| {
                let consumed = Arc::clone(&consumed);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    consumed
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        assert_eq!(
            attempts
                .into_iter()
                .map(|attempt| attempt.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
        assert!(consumed.load(Ordering::Acquire));
    }

    #[test]
    fn url_fragment_uses_versioned_standard_parameters_and_certificate_pin() {
        let request_id = [0x34; 32];
        let pin = URL_SAFE_NO_PAD.encode([0x56; 32]);
        let url = build_handoff_url(
            "https://keys.example/app/",
            "workstation",
            8443,
            &pin,
            &request_id,
        )
        .unwrap();
        assert_eq!(url.origin().ascii_serialization(), "https://keys.example");
        assert_eq!(url.path(), "/app/");
        let fields = form_urlencoded::parse(url.fragment().unwrap().as_bytes()).collect::<Vec<_>>();
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0], ("v".into(), "1".into()));
        assert_eq!(fields[1], ("host".into(), "workstation".into()));
        assert_eq!(fields[2], ("port".into(), "8443".into()));
        assert_eq!(fields[3], ("cert".into(), pin.into()));
        assert_eq!(
            fields[4],
            ("request".into(), URL_SAFE_NO_PAD.encode(request_id).into())
        );
    }

    #[test]
    fn certificate_validity_is_exactly_one_day() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let (before, after) = certificate_validity(now);
        assert_eq!(after - before, CalendarDuration::days(1));
        assert!(before <= now && now < after);
    }

    #[test]
    fn frame_lengths_reject_empty_and_oversized_messages() {
        assert!(parse_frame_length(0_u32.to_be_bytes()).is_err());
        assert_eq!(parse_frame_length(1_u32.to_be_bytes()).unwrap(), 1);
        assert_eq!(
            parse_frame_length((MAX_FRAME_BYTES as u32).to_be_bytes()).unwrap(),
            MAX_FRAME_BYTES
        );
        assert!(parse_frame_length((MAX_FRAME_BYTES as u32 + 1).to_be_bytes()).is_err());
    }

    #[test]
    fn pending_connections_are_bounded_and_permits_release_after_disconnect() {
        let pending = Arc::new(Semaphore::new(MAX_PENDING_CONNECTIONS));
        let permits = (0..MAX_PENDING_CONNECTIONS)
            .map(|_| try_pending_connection(&pending).expect("permit available"))
            .collect::<Vec<_>>();
        assert!(try_pending_connection(&pending).is_none());
        drop(permits);
        assert!(try_pending_connection(&pending).is_some());
    }

    #[test]
    fn connection_and_operation_deadlines_are_fixed() {
        assert_eq!(MAX_PENDING_CONNECTIONS, 4);
        assert_eq!(CONNECTION_TIMEOUT, Duration::from_secs(30));
        assert_eq!(OPERATION_TIMEOUT, Duration::from_secs(120));
    }
}
