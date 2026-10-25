use std::{
    collections::HashSet,
    error::Error,
    future::Future,
    io::{self, IsTerminal},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use creds_qr_rendering::{Rendered, encode as encode_qr, render as render_qr};
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
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
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
    #[serde(rename = "approvalTimeoutMs")]
    approval_timeout_ms: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationPhase {
    Setup,
    Approval { deadline: Instant },
    Consumed,
    Expired,
    Cancelled,
}

struct OperationWindow {
    phase: Mutex<OperationPhase>,
    phase_changed: watch::Sender<OperationPhase>,
}

impl OperationWindow {
    fn new() -> (Self, watch::Receiver<OperationPhase>) {
        let (phase_changed, receiver) = watch::channel(OperationPhase::Setup);
        (
            Self {
                phase: Mutex::new(OperationPhase::Setup),
                phase_changed,
            },
            receiver,
        )
    }

    #[cfg(test)]
    fn phase(&self) -> OperationPhase {
        *self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn begin_approval(&self) -> Result<Instant> {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *phase {
            OperationPhase::Setup => {
                let deadline = Instant::now() + APPROVAL_TIMEOUT;
                *phase = OperationPhase::Approval { deadline };
                self.phase_changed.send_replace(*phase);
                Ok(deadline)
            }
            OperationPhase::Approval { deadline } if Instant::now() < deadline => Ok(deadline),
            OperationPhase::Approval { .. } => {
                *phase = OperationPhase::Expired;
                self.phase_changed.send_replace(*phase);
                Err(timed_out())
            }
            OperationPhase::Consumed => Err(already_consumed()),
            OperationPhase::Expired => Err(timed_out()),
            OperationPhase::Cancelled => Err(cancelled()),
        }
    }

    fn timeout_for_request(&self) -> Result<u32> {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *phase {
            OperationPhase::Setup => Ok(APPROVAL_TIMEOUT.as_millis() as u32),
            OperationPhase::Approval { deadline } => {
                let now = Instant::now();
                let remaining = deadline.saturating_duration_since(now);
                if !remaining.is_zero() {
                    let remaining_ms = u32::try_from(remaining.as_millis()).unwrap_or(0).max(1);
                    Ok(remaining_ms)
                } else {
                    *phase = OperationPhase::Expired;
                    self.phase_changed.send_replace(*phase);
                    Err(timed_out())
                }
            }
            OperationPhase::Consumed => Err(already_consumed()),
            OperationPhase::Expired => Err(timed_out()),
            OperationPhase::Cancelled => Err(cancelled()),
        }
    }

    fn try_consume(&self) -> Result<()> {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *phase {
            OperationPhase::Approval { deadline } if Instant::now() < deadline => {
                *phase = OperationPhase::Consumed;
                self.phase_changed.send_replace(*phase);
                Ok(())
            }
            OperationPhase::Approval { .. } => {
                *phase = OperationPhase::Expired;
                self.phase_changed.send_replace(*phase);
                Err(timed_out())
            }
            OperationPhase::Consumed => Err(already_consumed()),
            OperationPhase::Expired => Err(timed_out()),
            OperationPhase::Cancelled => Err(cancelled()),
            OperationPhase::Setup => {
                Err(io::Error::other("approval request was not established").into())
            }
        }
    }

    fn expire(&self, deadline: Instant) -> bool {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*phase, OperationPhase::Approval { deadline: active } if active == deadline)
            && Instant::now() >= deadline
        {
            *phase = OperationPhase::Expired;
            self.phase_changed.send_replace(*phase);
            true
        } else {
            false
        }
    }

    fn cancel(&self) {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(
            *phase,
            OperationPhase::Setup | OperationPhase::Approval { .. }
        ) {
            *phase = OperationPhase::Cancelled;
            self.phase_changed.send_replace(*phase);
        }
    }
}

fn timed_out() -> BoxError {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "approval expired after two minutes",
    )
    .into()
}

fn cancelled() -> BoxError {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "approval operation was cancelled",
    )
    .into()
}

fn already_consumed() -> BoxError {
    io::Error::new(io::ErrorKind::AlreadyExists, "operation already consumed").into()
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
    operation_window: Arc<OperationWindow>,
    phase_changed: watch::Receiver<OperationPhase>,
    request_setup_lock: tokio::sync::Mutex<()>,
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
    validate_name(name)?;
    validate_revision(revision)?;

    let request_id = random_bytes::<32>()?;
    let request = Arc::new(HandoffRequest {
        request_id,
        name: name.to_owned(),
        revision,
        operation,
    });
    let (identity, certificate_pin) = create_identity(config)?;
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
    let qr_code = encode_qr(handoff_url.as_str())?;
    let qr_output = render_qr(&qr_code, config.qr_mode);

    eprintln!("Open this URL on the approval device: {handoff_url}");
    eprintln!(
        "Or scan this {} QR code (machine label {}, UDP port {port}; the approval app adds its configured DNS suffix):",
        config.qr_mode, config.hostname
    );
    match qr_output {
        Rendered::Text(qr_image) => eprintln!("{qr_image}"),
        Rendered::KittyProtocol(protocol) if kitty_protocol_supported() => {
            eprintln!("{protocol}");
        }
        Rendered::KittyProtocol(_) => eprintln!(
            "Kitty QR was selected but stderr is not a recognized Kitty graphics terminal; use the URL above."
        ),
    }
    eprintln!("Waiting for approval. Press Ctrl-C to cancel.");

    if *cancellation.borrow() {
        endpoint.close(VarInt::from_u32(0), b"operation cancelled");
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "approval operation was cancelled",
        )
        .into());
    }

    let (key_sender, mut key_receiver) = mpsc::channel(1);
    let (operation_window, mut phase_changed) = OperationWindow::new();
    let operation_window = Arc::new(operation_window);
    let state = Arc::new(SessionState {
        request,
        expected_origin: config.app_origin.clone(),
        rp_id: config.rp_id.clone(),
        public_key: config.public_key,
        operation_window: Arc::clone(&operation_window),
        phase_changed: phase_changed.clone(),
        request_setup_lock: tokio::sync::Mutex::new(()),
        active_challenges: Arc::new(Mutex::new(HashSet::new())),
        key_sender,
    });
    let pending_connections = Arc::new(Semaphore::new(MAX_PENDING_CONNECTIONS));
    loop {
        let phase = *phase_changed.borrow_and_update();
        if phase == OperationPhase::Expired {
            endpoint.close(VarInt::from_u32(0), b"approval expired after two minutes");
            return Err(timed_out());
        }
        if phase == OperationPhase::Cancelled {
            endpoint.close(VarInt::from_u32(0), b"operation cancelled");
            return Err(cancelled());
        }
        let approval_deadline = match phase {
            OperationPhase::Approval { deadline } => Some(deadline),
            _ => None,
        };
        let mut deadline_sleep: Pin<Box<dyn Future<Output = ()> + Send>> = match approval_deadline {
            Some(deadline) => Box::pin(sleep_until(deadline)),
            None => Box::pin(std::future::pending()),
        };
        tokio::select! {
            _ = &mut deadline_sleep => {
                if approval_deadline.is_some_and(|deadline| operation_window.expire(deadline)) {
                    endpoint.close(VarInt::from_u32(0), b"approval expired after two minutes");
                    return Err(timed_out());
                }
            }
            changed = phase_changed.changed() => {
                if changed.is_err() {
                    endpoint.close(VarInt::from_u32(0), b"approval listener stopped");
                    return Err(io::Error::other("approval state stopped unexpectedly").into());
                }
            }
            result = cancellation.changed() => {
                endpoint.close(VarInt::from_u32(0), b"operation cancelled");
                operation_window.cancel();
                if result.is_err() || *cancellation.borrow() {
                    return Err(cancelled());
                }
                return Err(cancelled());
            }
            key = key_receiver.recv() => {
                endpoint.close(VarInt::from_u32(0), b"approved");
                if *cancellation.borrow() {
                    operation_window.cancel();
                    return Err(cancelled());
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

fn kitty_protocol_supported() -> bool {
    let stderr_is_terminal = io::stderr().is_terminal();
    let kitty_window_id = std::env::var_os("KITTY_WINDOW_ID").is_some();
    let wezterm_pane = std::env::var_os("WEZTERM_PANE").is_some();
    let term = std::env::var("TERM").unwrap_or_default();
    let term_program = std::env::var("TERM_PROGRAM").unwrap_or_default();
    recognized_kitty_terminal(
        stderr_is_terminal,
        kitty_window_id,
        wezterm_pane,
        &term,
        &term_program,
    )
}

fn recognized_kitty_terminal(
    stderr_is_terminal: bool,
    kitty_window_id: bool,
    wezterm_pane: bool,
    term: &str,
    term_program: &str,
) -> bool {
    stderr_is_terminal
        && (kitty_window_id
            || wezterm_pane
            || term == "xterm-ghostty"
            || term_program.eq_ignore_ascii_case("ghostty"))
}

async fn handle_session(
    incoming: wtransport::endpoint::IncomingSession,
    state: Arc<SessionState>,
) -> Result<()> {
    let connection_deadline = Instant::now() + CONNECTION_TIMEOUT;
    let setup_state = Arc::clone(&state);
    let setup = async move {
        let session_request = timeout_at(connection_deadline, incoming)
            .await
            .map_err(|_| connection_setup_timeout())??;
        if !is_allowed_session(
            session_request.origin(),
            session_request.path(),
            &setup_state.expected_origin,
        ) {
            session_request.forbidden().await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "WebTransport session Origin or path was rejected",
            )
            .into());
        }

        let connection = match timeout_at(connection_deadline, session_request.accept()).await {
            Ok(result) => result?,
            Err(_) => return Err(connection_setup_timeout()),
        };
        let (established, approval_deadline) = match timeout_at(
            connection_deadline,
            establish_approval_request(&connection, &setup_state),
        )
        .await
        {
            Ok(Ok(established)) => established,
            Ok(Err(error)) => {
                connection.close(VarInt::from_u32(1), b"invalid handoff protocol");
                return Err(error);
            }
            Err(_) => {
                connection.close(VarInt::from_u32(2), b"connection setup timed out");
                return Err(connection_setup_timeout());
            }
        };
        Ok((connection, established, approval_deadline))
    };

    run_session(
        connection_deadline,
        setup,
        |connection, (mut receive, challenge, challenge_guard), _approval_deadline| {
            let stream_rejection = reject_additional_streams(connection);
            let state = Arc::clone(&state);
            let verified_response = async move {
                let _challenge_guard = challenge_guard;
                read_and_verify_key(&mut receive, challenge, &state).await
            };
            (stream_rejection, verified_response)
        },
        &state.operation_window,
        &state.key_sender,
        state.phase_changed.clone(),
        |connection, error| {
            let code = if error
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut)
            {
                2
            } else {
                1
            };
            connection.close(VarInt::from_u32(code), b"approval session closed");
        },
    )
    .await
}

fn connection_setup_timeout() -> BoxError {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "connection did not establish its approval request within 30 seconds",
    )
    .into()
}

async fn establish_approval_request(
    connection: &wtransport::Connection,
    state: &Arc<SessionState>,
) -> Result<(
    (wtransport::RecvStream, [u8; 32], ActiveChallengeGuard),
    Instant,
)> {
    let (mut send, mut receive) = accept_one_bidirectional_stream(connection).await?;
    let hello_bytes = read_frame(&mut receive).await?;
    validate_hello(&hello_bytes, &state.request.request_id)?;
    let _setup_guard = state.request_setup_lock.lock().await;
    let approval_timeout_ms = state.operation_window.timeout_for_request()?;
    let challenge = fresh_challenge(&state.request.request_id, &state.active_challenges)?;
    let challenge_guard = ActiveChallengeGuard {
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
        approval_timeout_ms,
    };
    let request_bytes = serde_json::to_vec(&request_message)?;
    write_frame(&mut send, &request_bytes).await?;
    send.finish()
        .await
        .map_err(|error| io::Error::other(error.to_string()))?;
    let approval_deadline = state.operation_window.begin_approval()?;
    Ok(((receive, challenge, challenge_guard), approval_deadline))
}

async fn read_and_verify_key(
    receive: &mut wtransport::RecvStream,
    challenge: [u8; 32],
    state: &SessionState,
) -> Result<Zeroizing<[u8; 32]>> {
    let key_message = Zeroizing::new(read_frame(receive).await?);
    ensure_stream_eof(receive).await?;
    // Assertion verification is complete before the returned key can enter the gate.
    Ok(verify_key_message(
        &key_message,
        &challenge,
        &state.expected_origin,
        &state.rp_id,
        &state.public_key,
    )?)
}

async fn reject_additional_streams(connection: wtransport::Connection) -> io::Error {
    tokio::select! {
        stream = connection.accept_bi() => match stream {
            Ok(_) => {
                connection.close(VarInt::from_u32(3), b"additional stream rejected");
                io::Error::new(io::ErrorKind::InvalidData, "additional bidirectional stream rejected")
            }
            Err(_) => std::future::pending().await,
        },
        stream = connection.accept_uni() => match stream {
            Ok(_) => {
                connection.close(VarInt::from_u32(3), b"additional stream rejected");
                io::Error::new(io::ErrorKind::InvalidData, "additional unidirectional stream rejected")
            }
            Err(_) => std::future::pending().await,
        },
    }
}

async fn run_session<C, T, SetupFuture, Approval, RejectionFuture, ResponseFuture, Close>(
    setup_deadline: Instant,
    setup: SetupFuture,
    approval: Approval,
    operation_window: &OperationWindow,
    key_sender: &mpsc::Sender<Zeroizing<[u8; 32]>>,
    phase_changed: watch::Receiver<OperationPhase>,
    close: Close,
) -> Result<()>
where
    C: Clone,
    SetupFuture: Future<Output = Result<(C, T, Instant)>>,
    Approval: FnOnce(C, T, Instant) -> (RejectionFuture, ResponseFuture),
    RejectionFuture: Future<Output = io::Error>,
    ResponseFuture: Future<Output = Result<Zeroizing<[u8; 32]>>>,
    Close: FnOnce(C, &BoxError),
{
    let (connection, session, approval_deadline) = timeout_at(setup_deadline, setup)
        .await
        .map_err(|_| connection_setup_timeout())??;
    let (stream_rejection, verified_response) =
        approval(connection.clone(), session, approval_deadline);
    let result = arbitrate_and_consume(
        approval_deadline,
        stream_rejection,
        verified_response,
        operation_window,
        key_sender,
        phase_changed,
    )
    .await;
    if let Err(error) = result {
        close(connection, &error);
        return Err(error);
    }
    Ok(())
}

async fn arbitrate_and_consume(
    approval_deadline: Instant,
    stream_rejection: impl Future<Output = io::Error>,
    verified_response: impl Future<Output = Result<Zeroizing<[u8; 32]>>>,
    operation_window: &OperationWindow,
    key_sender: &mpsc::Sender<Zeroizing<[u8; 32]>>,
    mut phase_changed: watch::Receiver<OperationPhase>,
) -> Result<()> {
    match *phase_changed.borrow_and_update() {
        OperationPhase::Approval { deadline } if deadline == approval_deadline => {}
        OperationPhase::Approval { .. } | OperationPhase::Setup => {
            return Err(io::Error::other("approval request was not established").into());
        }
        OperationPhase::Consumed => return Err(already_consumed()),
        OperationPhase::Expired => return Err(timed_out()),
        OperationPhase::Cancelled => return Err(cancelled()),
    }

    tokio::select! {
        biased;
        _ = sleep_until(approval_deadline) => {
            operation_window.expire(approval_deadline);
            Err(timed_out())
        }
        changed = phase_changed.changed() => {
            if changed.is_err() {
                return Err(io::Error::other("approval state stopped unexpectedly").into());
            }
            match *phase_changed.borrow_and_update() {
                OperationPhase::Approval { .. } => Err(io::Error::other("approval deadline changed unexpectedly").into()),
                OperationPhase::Setup => Err(io::Error::other("approval request was not established").into()),
                OperationPhase::Consumed => Err(already_consumed()),
                OperationPhase::Expired => Err(timed_out()),
                OperationPhase::Cancelled => Err(cancelled()),
            }
        }
        error = stream_rejection => Err(error.into()),
        response = verified_response => {
            let key = response?;
            operation_window.try_consume()?;
            key_sender
                .send(key)
                .await
                .map_err(|_| io::Error::other("handoff listener stopped before approval"))?;
            Ok(())
        }
    }
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

fn create_identity(config: &ValidatedConfig) -> Result<(Identity, String)> {
    let certificate_name = format!("{}.{}", config.hostname, config.rp_id);
    let signing_key = KeyPair::generate()?;
    let mut certificate_params = CertificateParams::new(vec![certificate_name])?;
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
    Ok((identity, pin))
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
    use std::sync::{
        Barrier,
        atomic::{AtomicBool, Ordering},
    };
    use url::form_urlencoded;

    #[test]
    fn kitty_graphics_requires_a_terminal_with_a_recognized_protocol_marker() {
        assert!(!recognized_kitty_terminal(
            false,
            true,
            false,
            "xterm-kitty",
            ""
        ));
        assert!(recognized_kitty_terminal(
            true,
            true,
            false,
            "xterm-kitty",
            ""
        ));
        assert!(recognized_kitty_terminal(
            true,
            false,
            true,
            "xterm-256color",
            ""
        ));
        assert!(recognized_kitty_terminal(
            true,
            false,
            false,
            "xterm-ghostty",
            ""
        ));
        assert!(!recognized_kitty_terminal(
            true,
            false,
            false,
            "xterm-256color",
            ""
        ));
    }

    #[derive(Clone)]
    struct TestConnection(Arc<AtomicBool>);

    fn test_connection() -> (TestConnection, Arc<AtomicBool>) {
        let closed = Arc::new(AtomicBool::new(false));
        (TestConnection(Arc::clone(&closed)), closed)
    }

    async fn establish_test_session(
        window: &OperationWindow,
        connection: TestConnection,
    ) -> Result<(TestConnection, (), Instant)> {
        let approval_deadline = window.begin_approval()?;
        Ok((connection, (), approval_deadline))
    }

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
        let (window, _) = OperationWindow::new();
        let invalid = format!(
            r#"{{"type":"hello","version":1,"request":"{}"}}"#,
            URL_SAFE_NO_PAD.encode([0x33; 32])
        );
        assert!(validate_hello(invalid.as_bytes(), &request_id).is_err());
        assert_eq!(window.phase(), OperationPhase::Setup);
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
        let (window, _) = OperationWindow::new();
        window.begin_approval().unwrap();
        let window = Arc::new(window);
        let barrier = Arc::new(Barrier::new(MAX_PENDING_CONNECTIONS + 1));
        let attempts = (0..MAX_PENDING_CONNECTIONS)
            .map(|_| {
                let window = Arc::clone(&window);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    window.try_consume().is_ok()
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
        assert_eq!(window.phase(), OperationPhase::Consumed);
    }

    #[tokio::test]
    async fn additional_stream_rejection_wins_before_consuming_a_verified_response() {
        let (window, phase_changed) = OperationWindow::new();
        let approval_deadline = window.begin_approval().unwrap();
        let (sender, mut receiver) = mpsc::channel(1);
        let stream_rejection =
            async { io::Error::new(io::ErrorKind::InvalidData, "additional stream rejected") };
        // The valid response is already verified and ready at the session decision point.
        let verified_response = async { Ok(Zeroizing::new([0x6d; 32])) };

        let result = arbitrate_and_consume(
            approval_deadline,
            stream_rejection,
            verified_response,
            &window,
            &sender,
            phase_changed,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(window.phase(), OperationPhase::Approval { .. }));
        assert!(receiver.try_recv().is_err());
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
    fn connection_and_approval_deadlines_are_fixed() {
        assert_eq!(MAX_PENDING_CONNECTIONS, 4);
        assert_eq!(CONNECTION_TIMEOUT, Duration::from_secs(30));
        assert_eq!(APPROVAL_TIMEOUT, Duration::from_secs(120));
    }

    #[tokio::test(start_paused = true)]
    async fn production_session_allows_approval_after_the_setup_deadline() {
        let (window, phase_changed) = OperationWindow::new();
        let window = Arc::new(window);
        let setup_deadline = Instant::now() + CONNECTION_TIMEOUT;
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let (connection, _) = test_connection();
        let (key_sender, mut key_receiver) = mpsc::channel(1);
        let task_window = Arc::clone(&window);
        let setup_window = Arc::clone(&task_window);
        let task = tokio::spawn(async move {
            run_session(
                setup_deadline,
                async move { establish_test_session(&setup_window, connection).await },
                move |_, (), _| {
                    (std::future::pending::<io::Error>(), async move {
                        started_sender.send(()).unwrap();
                        tokio::time::sleep(CONNECTION_TIMEOUT + Duration::from_secs(1)).await;
                        Ok(Zeroizing::new([0x6d; 32]))
                    })
                },
                &task_window,
                &key_sender,
                phase_changed,
                |_, _| {},
            )
            .await
        });

        started_receiver.await.unwrap();
        tokio::time::advance(CONNECTION_TIMEOUT + Duration::from_secs(1)).await;

        task.await.unwrap().unwrap();
        assert_eq!(*key_receiver.try_recv().unwrap(), [0x6d; 32]);
        assert_eq!(window.phase(), OperationPhase::Consumed);
    }

    #[tokio::test(start_paused = true)]
    async fn later_sessions_receive_only_the_remaining_approval_time() {
        let (window, _) = OperationWindow::new();
        assert_eq!(window.timeout_for_request().unwrap(), 120_000);
        let deadline = window.begin_approval().unwrap();

        tokio::time::advance(Duration::from_secs(30)).await;

        assert_eq!(window.timeout_for_request().unwrap(), 90_000);
        assert_eq!(window.begin_approval().unwrap(), deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn production_session_bounds_stalled_setup_and_releases_its_pending_slot() {
        let (window, phase_changed) = OperationWindow::new();
        let window = Arc::new(window);
        let pending = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&pending).try_acquire_owned().unwrap();
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let setup_deadline = Instant::now() + CONNECTION_TIMEOUT;
        let (key_sender, mut key_receiver) = mpsc::channel(1);
        let task_window = Arc::clone(&window);
        let task_key_sender = key_sender.clone();
        let task = tokio::spawn(async move {
            run_session(
                setup_deadline,
                async move {
                    let _permit = permit;
                    started_sender.send(()).unwrap();
                    std::future::pending::<Result<(TestConnection, (), Instant)>>().await
                },
                |_, (), _| {
                    (
                        std::future::pending::<io::Error>(),
                        std::future::pending::<Result<Zeroizing<[u8; 32]>>>(),
                    )
                },
                &task_window,
                &task_key_sender,
                phase_changed,
                |_, _| {},
            )
            .await
        });

        started_receiver.await.unwrap();
        tokio::time::advance(CONNECTION_TIMEOUT).await;

        let error = task.await.unwrap().unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(pending.available_permits(), 1);
        assert_eq!(window.phase(), OperationPhase::Setup);
        assert!(key_receiver.try_recv().is_err());

        let phase_changed = window.phase_changed.subscribe();
        let (connection, _) = test_connection();
        let setup_window = Arc::clone(&window);
        run_session(
            Instant::now() + CONNECTION_TIMEOUT,
            async move { establish_test_session(&setup_window, connection).await },
            |_, (), _| {
                (std::future::pending::<io::Error>(), async {
                    Ok(Zeroizing::new([0x7e; 32]))
                })
            },
            &window,
            &key_sender,
            phase_changed,
            |_, _| {},
        )
        .await
        .unwrap();
        assert_eq!(*key_receiver.try_recv().unwrap(), [0x7e; 32]);
    }

    #[tokio::test(start_paused = true)]
    async fn approval_expiry_at_the_deadline_rejects_late_and_replayed_keys() {
        let (window, _) = OperationWindow::new();
        let deadline = window.begin_approval().unwrap();
        tokio::time::advance(APPROVAL_TIMEOUT).await;
        assert!(window.try_consume().is_err());
        assert_eq!(window.phase(), OperationPhase::Expired);
        assert!(!window.expire(deadline));

        let (window, _) = OperationWindow::new();
        window.begin_approval().unwrap();
        assert!(window.try_consume().is_ok());
        assert!(window.try_consume().is_err());
        assert_eq!(window.phase(), OperationPhase::Consumed);
    }

    #[tokio::test(start_paused = true)]
    async fn production_session_accepts_approval_just_before_expiry() {
        let (window, phase_changed) = OperationWindow::new();
        let window = Arc::new(window);
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let (connection, _) = test_connection();
        let (key_sender, mut key_receiver) = mpsc::channel(1);
        let setup_deadline = Instant::now() + CONNECTION_TIMEOUT;
        let task_window = Arc::clone(&window);
        let setup_window = Arc::clone(&task_window);
        let task = tokio::spawn(async move {
            run_session(
                setup_deadline,
                async move { establish_test_session(&setup_window, connection).await },
                move |_, (), approval_deadline| {
                    (std::future::pending::<io::Error>(), async move {
                        started_sender.send(()).unwrap();
                        tokio::time::sleep_until(approval_deadline - Duration::from_millis(1))
                            .await;
                        Ok(Zeroizing::new([0x6d; 32]))
                    })
                },
                &task_window,
                &key_sender,
                phase_changed,
                |_, _| {},
            )
            .await
        });

        started_receiver.await.unwrap();
        tokio::time::advance(APPROVAL_TIMEOUT - Duration::from_millis(1)).await;

        task.await.unwrap().unwrap();
        assert_eq!(*key_receiver.try_recv().unwrap(), [0x6d; 32]);
        assert_eq!(window.phase(), OperationPhase::Consumed);
    }

    #[tokio::test(start_paused = true)]
    async fn production_session_rejects_a_response_at_expiry() {
        let (window, phase_changed) = OperationWindow::new();
        let window = Arc::new(window);
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let (connection, closed) = test_connection();
        let (key_sender, mut key_receiver) = mpsc::channel(1);
        let setup_deadline = Instant::now() + CONNECTION_TIMEOUT;
        let task_window = Arc::clone(&window);
        let setup_window = Arc::clone(&task_window);
        let task = tokio::spawn(async move {
            run_session(
                setup_deadline,
                async move { establish_test_session(&setup_window, connection).await },
                move |_, (), _| {
                    (std::future::pending::<io::Error>(), async move {
                        started_sender.send(()).unwrap();
                        std::future::pending::<Result<Zeroizing<[u8; 32]>>>().await
                    })
                },
                &task_window,
                &key_sender,
                phase_changed,
                |connection, _| connection.0.store(true, Ordering::SeqCst),
            )
            .await
        });

        started_receiver.await.unwrap();
        tokio::time::advance(APPROVAL_TIMEOUT).await;

        let error = task.await.unwrap().unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(window.phase(), OperationPhase::Expired);
        assert!(closed.load(Ordering::SeqCst));
        assert!(key_receiver.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn listener_cancellation_closes_the_live_session_without_consuming_a_key() {
        let (window, phase_changed) = OperationWindow::new();
        let window = Arc::new(window);
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let (connection, closed) = test_connection();
        let (key_sender, mut key_receiver) = mpsc::channel(1);
        let setup_deadline = Instant::now() + CONNECTION_TIMEOUT;
        let task_window = Arc::clone(&window);
        let setup_window = Arc::clone(&task_window);
        let task = tokio::spawn(async move {
            run_session(
                setup_deadline,
                async move { establish_test_session(&setup_window, connection).await },
                move |_, (), _| {
                    (std::future::pending::<io::Error>(), async move {
                        started_sender.send(()).unwrap();
                        std::future::pending::<Result<Zeroizing<[u8; 32]>>>().await
                    })
                },
                &task_window,
                &key_sender,
                phase_changed,
                |connection, _| connection.0.store(true, Ordering::SeqCst),
            )
            .await
        });

        started_receiver.await.unwrap();
        window.cancel();

        let error = task.await.unwrap().unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(window.phase(), OperationPhase::Cancelled);
        assert!(closed.load(Ordering::SeqCst));
        assert!(key_receiver.try_recv().is_err());
    }
}
