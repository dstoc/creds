use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use wtransport::{Endpoint, Identity, ServerConfig};

const PROBE_MESSAGE: &[u8] = b"creds-browser-transport-probe-v1";
const MAX_PROBE_BYTES: usize = 128;

pub async fn serve() -> Result<(), Box<dyn Error>> {
    let identity = Identity::self_signed(["localhost", "127.0.0.1", "::1"])?;
    let certificate = &identity.certificate_chain().as_slice()[0];
    let certificate_hash = base64url_sha256(certificate.der());

    let config = ServerConfig::builder()
        .with_bind_address(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .with_identity(identity)
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .build();
    let endpoint = Endpoint::server(config)?;
    let port = endpoint.local_addr()?.port();

    println!("server_url=https://127.0.0.1:{port}/key");
    println!("certificate_sha256_base64url={certificate_hash}");
    eprintln!("Waiting for a local browser WebTransport probe. Ctrl-C stops the server.");
    eprintln!("This echo endpoint is a test fixture; it does not implement the creds protocol.");

    loop {
        let incoming_session = endpoint.accept().await;
        tokio::spawn(async move {
            if let Err(error) = handle_session(incoming_session).await {
                eprintln!("probe connection ended: {error}");
            }
        });
    }
}

async fn handle_session(
    incoming_session: wtransport::endpoint::IncomingSession,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let session_request = incoming_session.await?;
    let connection = session_request.accept().await?;
    let (mut send, mut receive) = connection.accept_bi().await?;

    let mut request = Vec::with_capacity(PROBE_MESSAGE.len());
    let mut chunk = [0_u8; MAX_PROBE_BYTES];
    loop {
        let Some(read) = receive.read(&mut chunk).await? else {
            break;
        };
        if request.len() + read > MAX_PROBE_BYTES {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "probe message too large").into(),
            );
        }
        request.extend_from_slice(&chunk[..read]);
    }

    if request != PROBE_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected probe message").into());
    }

    send.write_all(PROBE_MESSAGE).await?;
    send.finish().await?;
    eprintln!("probe stream echoed {} bytes", PROBE_MESSAGE.len());
    Ok(())
}

fn base64url_sha256(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(input))
}

#[cfg(test)]
mod tests {
    use super::base64url_sha256;

    #[test]
    fn certificate_pin_uses_unpadded_base64url_sha256() {
        assert_eq!(
            base64url_sha256(b"abc"),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }
}
