use std::{collections::HashSet, error::Error, fmt, io::Cursor};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::Value;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{
    Deserialize,
    de::{self, IgnoredAny, MapAccess, Visitor},
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_ASSERTION_FIELD_BYTES: usize = 4 * 1024;
const EXPECTED_KEY_BYTES: usize = 32;
const AUTH_DATA_FIXED_BYTES: usize = 37;
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;
const RESERVED_FLAGS: u8 = 0x22;

type Result<T> = std::result::Result<T, AssertionError>;

#[derive(Debug)]
pub struct AssertionError(String);

impl fmt::Display for AssertionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for AssertionError {}

fn invalid(message: impl Into<String>) -> AssertionError {
    AssertionError(message.into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyMessage {
    #[serde(rename = "type")]
    kind: String,
    version: u8,
    key: String,
    assertion: AssertionFields,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertionFields {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
}

struct ClientData {
    kind: Option<String>,
    challenge: Option<String>,
    origin: Option<String>,
    cross_origin: Option<bool>,
    top_origin_seen: bool,
}

impl<'de> Deserialize<'de> for ClientData {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ClientDataVisitor;

        impl<'de> Visitor<'de> for ClientDataVisitor {
            type Value = ClientData;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a WebAuthn client data JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut seen = HashSet::new();
                let mut result = ClientData {
                    kind: None,
                    challenge: None,
                    origin: None,
                    cross_origin: None,
                    top_origin_seen: false,
                };
                while let Some(name) = map.next_key::<String>()? {
                    if !seen.insert(name.clone()) {
                        return Err(de::Error::custom(format!(
                            "duplicate client data field {name}"
                        )));
                    }
                    match name.as_str() {
                        "type" => result.kind = Some(map.next_value()?),
                        "challenge" => result.challenge = Some(map.next_value()?),
                        "origin" => result.origin = Some(map.next_value()?),
                        "crossOrigin" => result.cross_origin = Some(map.next_value()?),
                        "topOrigin" => {
                            result.top_origin_seen = true;
                            map.next_value::<IgnoredAny>()?;
                        }
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(result)
            }
        }

        deserializer.deserialize_map(ClientDataVisitor)
    }
}

fn decode_field(name: &str, encoded: &str) -> Result<Vec<u8>> {
    if encoded.is_empty() || encoded.len() > MAX_ASSERTION_FIELD_BYTES * 2 {
        return Err(invalid(format!(
            "{name} is empty or exceeds its encoded size limit"
        )));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| invalid(format!("{name} is not unpadded base64url: {error}")))?;
    if decoded.is_empty()
        || decoded.len() > MAX_ASSERTION_FIELD_BYTES
        || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(invalid(format!(
            "{name} is empty, too large, or not canonical base64url"
        )));
    }
    Ok(decoded)
}

fn decode_key(encoded: &str) -> Result<Zeroizing<[u8; EXPECTED_KEY_BYTES]>> {
    if encoded.len() != 43 {
        return Err(invalid(
            "key must be canonical base64url for exactly 32 bytes",
        ));
    }
    let mut decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| invalid(format!("key is not unpadded base64url: {error}")))?;
    if decoded.len() != EXPECTED_KEY_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        decoded.zeroize();
        return Err(invalid(
            "key must be canonical base64url for exactly 32 bytes",
        ));
    }
    let mut key = [0; EXPECTED_KEY_BYTES];
    key.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(Zeroizing::new(key))
}

fn parse_client_data(bytes: &[u8]) -> Result<ClientData> {
    if bytes.is_empty() || bytes.len() > MAX_ASSERTION_FIELD_BYTES {
        return Err(invalid("clientDataJSON is empty or exceeds 4 KiB"));
    }
    serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("malformed clientDataJSON: {error}")))
}

fn validate_extension_data(bytes: &[u8]) -> Result<()> {
    let mut cursor = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader_with_recursion_limit(&mut cursor, 16)
        .map_err(|error| invalid(format!("malformed authenticator extension CBOR: {error}")))?;
    if cursor.position() as usize != bytes.len() {
        return Err(invalid("authenticator extension CBOR has trailing data"));
    }
    let Value::Map(entries) = value else {
        return Err(invalid("authenticator extensions must be a CBOR map"));
    };
    let mut names = HashSet::new();
    for (key, _value) in entries {
        let Value::Text(name) = key else {
            return Err(invalid("authenticator extension names must be CBOR text"));
        };
        if !names.insert(name.clone()) {
            return Err(invalid("authenticator extensions contain a duplicate name"));
        }
    }
    Ok(())
}

fn validate_authenticator_data(bytes: &[u8], rp_id: &str) -> Result<()> {
    if bytes.len() < AUTH_DATA_FIXED_BYTES || bytes.len() > MAX_ASSERTION_FIELD_BYTES {
        return Err(invalid(
            "authenticatorData must contain the 37-byte assertion header and fit within 4 KiB",
        ));
    }
    let expected_rp_hash = Sha256::digest(rp_id.as_bytes());
    if bytes[..32] != expected_rp_hash[..] {
        return Err(invalid(
            "authenticatorData RP ID hash does not match the configured RP ID",
        ));
    }
    let flags = bytes[32];
    if flags & RESERVED_FLAGS != 0 {
        return Err(invalid("authenticatorData uses reserved flag bits"));
    }
    if flags & FLAG_UP == 0 {
        return Err(invalid(
            "WebAuthn assertion is missing the user-present flag",
        ));
    }
    if flags & FLAG_UV == 0 {
        return Err(invalid(
            "WebAuthn assertion is missing the user-verified flag",
        ));
    }
    if flags & FLAG_AT != 0 {
        return Err(invalid(
            "assertion authenticatorData must not include attested credential data",
        ));
    }
    if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
        return Err(invalid(
            "authenticator backup-state flag requires the backup-eligible flag",
        ));
    }
    let extension_data = &bytes[AUTH_DATA_FIXED_BYTES..];
    if flags & FLAG_ED != 0 {
        if extension_data.is_empty() {
            return Err(invalid(
                "authenticatorData sets the extension flag without extension data",
            ));
        }
        validate_extension_data(extension_data)?;
    } else if !extension_data.is_empty() {
        return Err(invalid(
            "authenticatorData contains unflagged trailing data",
        ));
    }
    Ok(())
}

pub fn verify_assertion(
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature_der: &[u8],
    expected_challenge: &[u8; 32],
    expected_origin: &str,
    rp_id: &str,
    public_key: &VerifyingKey,
) -> Result<()> {
    let client_data = parse_client_data(client_data_json)?;
    if client_data.kind.as_deref() != Some("webauthn.get") {
        return Err(invalid("clientDataJSON type must be webauthn.get"));
    }
    let expected_challenge = URL_SAFE_NO_PAD.encode(expected_challenge);
    if client_data.challenge.as_deref() != Some(expected_challenge.as_str()) {
        return Err(invalid(
            "clientDataJSON challenge does not match this connection",
        ));
    }
    if client_data.origin.as_deref() != Some(expected_origin) {
        return Err(invalid(
            "clientDataJSON origin does not match the configured app origin",
        ));
    }
    if client_data.cross_origin == Some(true) {
        return Err(invalid("cross-origin WebAuthn ceremonies are not accepted"));
    }
    if client_data.top_origin_seen {
        return Err(invalid(
            "topOrigin is not expected for a top-level WebAuthn ceremony",
        ));
    }
    validate_authenticator_data(authenticator_data, rp_id)?;

    if signature_der.is_empty() || signature_der.len() > MAX_ASSERTION_FIELD_BYTES {
        return Err(invalid("signature is empty or exceeds 4 KiB"));
    }
    let signature = Signature::from_der(signature_der).map_err(|error| {
        invalid(format!(
            "signature is not a valid WebAuthn ES256 DER signature: {error}"
        ))
    })?;
    let client_data_hash = Sha256::digest(client_data_json);
    let mut signed_bytes = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    signed_bytes.extend_from_slice(authenticator_data);
    signed_bytes.extend_from_slice(&client_data_hash);
    public_key
        .verify(&signed_bytes, &signature)
        .map_err(|_| invalid("WebAuthn ES256 signature verification failed"))
}

pub fn verify_key_message(
    bytes: &[u8],
    expected_challenge: &[u8; 32],
    expected_origin: &str,
    rp_id: &str,
    public_key: &VerifyingKey,
) -> Result<Zeroizing<[u8; EXPECTED_KEY_BYTES]>> {
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES {
        return Err(invalid("key message is empty or exceeds 16 KiB"));
    }
    let mut message: KeyMessage = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("malformed key message: {error}")))?;
    let encoded_key = Zeroizing::new(std::mem::take(&mut message.key));
    if message.kind != "key" {
        return Err(invalid("message type must be key"));
    }
    if message.version != 1 {
        return Err(invalid("key message version must be 1"));
    }
    let client_data_json = decode_field("clientDataJSON", &message.assertion.client_data_json)?;
    let authenticator_data =
        decode_field("authenticatorData", &message.assertion.authenticator_data)?;
    let signature = decode_field("signature", &message.assertion.signature)?;
    verify_assertion(
        &client_data_json,
        &authenticator_data,
        &signature,
        expected_challenge,
        expected_origin,
        rp_id,
        public_key,
    )?;
    decode_key(encoded_key.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    const RP_ID: &str = "keys.example";
    const ORIGIN: &str = "https://keys.example";
    const CHALLENGE: [u8; 32] = [0x42; 32];

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
    }

    fn client_data(challenge: &[u8; 32], origin: &str, extra: &str) -> Vec<u8> {
        format!(
            "{{ \"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{}\"{extra} }}",
            URL_SAFE_NO_PAD.encode(challenge),
            origin
        )
        .into_bytes()
    }

    fn authenticator_data(rp_id: &str, flags: u8, trailing: &[u8]) -> Vec<u8> {
        let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
        data.push(flags);
        data.extend_from_slice(&1_u32.to_be_bytes());
        data.extend_from_slice(trailing);
        data
    }

    fn signed_fixture(key: &SigningKey, client_data: &[u8], authenticator_data: &[u8]) -> Vec<u8> {
        let mut message = authenticator_data.to_vec();
        message.extend_from_slice(&Sha256::digest(client_data));
        let signature: Signature = key.sign(&message);
        signature.to_der().as_bytes().to_vec()
    }

    fn valid_fixture() -> (SigningKey, Vec<u8>, Vec<u8>, Vec<u8>) {
        let key = signing_key(7);
        let client = client_data(
            &CHALLENGE,
            ORIGIN,
            ",\"tokenBinding\":{\"status\":\"supported\"}",
        );
        let auth = authenticator_data(RP_ID, FLAG_UP | FLAG_UV, &[]);
        let signature = signed_fixture(&key, &client, &auth);
        (key, client, auth, signature)
    }

    #[test]
    fn accepts_fixed_es256_assertion_over_original_client_data_bytes() {
        let (key, client, auth, signature) = valid_fixture();
        verify_assertion(
            &client,
            &auth,
            &signature,
            &CHALLENGE,
            ORIGIN,
            RP_ID,
            key.verifying_key(),
        )
        .unwrap();
    }

    #[test]
    fn rejects_wrong_signing_key_challenge_origin_and_rp_id() {
        let (key, client, auth, signature) = valid_fixture();
        let other_key = signing_key(8);
        assert!(
            verify_assertion(
                &client,
                &auth,
                &signature,
                &CHALLENGE,
                ORIGIN,
                RP_ID,
                other_key.verifying_key()
            )
            .is_err()
        );

        let wrong_challenge = [0x43; 32];
        assert!(
            verify_assertion(
                &client,
                &auth,
                &signature,
                &wrong_challenge,
                ORIGIN,
                RP_ID,
                key.verifying_key()
            )
            .is_err()
        );
        assert!(
            verify_assertion(
                &client,
                &auth,
                &signature,
                &CHALLENGE,
                "https://evil.example",
                RP_ID,
                key.verifying_key()
            )
            .is_err()
        );
        assert!(
            verify_assertion(
                &client,
                &auth,
                &signature,
                &CHALLENGE,
                ORIGIN,
                "evil.example",
                key.verifying_key()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_missing_up_or_uv_and_malformed_authenticator_data() {
        let key = signing_key(7);
        let client = client_data(&CHALLENGE, ORIGIN, "");
        for flags in [
            FLAG_UV,
            FLAG_UP,
            FLAG_UP | FLAG_UV | FLAG_AT,
            FLAG_UP | FLAG_UV | 0x02,
        ] {
            let auth = authenticator_data(RP_ID, flags, &[]);
            let signature = signed_fixture(&key, &client, &auth);
            assert!(
                verify_assertion(
                    &client,
                    &auth,
                    &signature,
                    &CHALLENGE,
                    ORIGIN,
                    RP_ID,
                    key.verifying_key()
                )
                .is_err()
            );
        }
        let truncated = vec![0_u8; 36];
        assert!(
            verify_assertion(
                &client,
                &truncated,
                &[0x30, 0],
                &CHALLENGE,
                ORIGIN,
                RP_ID,
                key.verifying_key()
            )
            .is_err()
        );
    }

    #[test]
    fn accepts_valid_cbor_extensions_and_rejects_malformed_extension_data() {
        let key = signing_key(7);
        let client = client_data(&CHALLENGE, ORIGIN, "");
        let valid_map = [0xa1, 0x63, b'u', b'v', b'm', 0x80];
        let auth = authenticator_data(RP_ID, FLAG_UP | FLAG_UV | FLAG_ED, &valid_map);
        let signature = signed_fixture(&key, &client, &auth);
        verify_assertion(
            &client,
            &auth,
            &signature,
            &CHALLENGE,
            ORIGIN,
            RP_ID,
            key.verifying_key(),
        )
        .unwrap();

        for extension in [
            &[0xff][..],
            &[0x80][..],
            &[0xa2, 0x63, b'x', 0x01, 0x63, b'x', 0x02][..],
        ] {
            let auth = authenticator_data(RP_ID, FLAG_UP | FLAG_UV | FLAG_ED, extension);
            let signature = signed_fixture(&key, &client, &auth);
            assert!(
                verify_assertion(
                    &client,
                    &auth,
                    &signature,
                    &CHALLENGE,
                    ORIGIN,
                    RP_ID,
                    key.verifying_key()
                )
                .is_err()
            );
        }
        let unflagged = authenticator_data(RP_ID, FLAG_UP | FLAG_UV, &valid_map);
        let signature = signed_fixture(&key, &client, &unflagged);
        assert!(
            verify_assertion(
                &client,
                &unflagged,
                &signature,
                &CHALLENGE,
                ORIGIN,
                RP_ID,
                key.verifying_key()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_cross_origin_top_origin_duplicates_and_altered_signatures() {
        let key = signing_key(7);
        let wrong_ceremony = format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"{}\"}}",
            URL_SAFE_NO_PAD.encode(CHALLENGE),
            ORIGIN,
        )
        .into_bytes();
        let auth = authenticator_data(RP_ID, FLAG_UP | FLAG_UV, &[]);
        let signature = signed_fixture(&key, &wrong_ceremony, &auth);
        assert!(
            verify_assertion(
                &wrong_ceremony,
                &auth,
                &signature,
                &CHALLENGE,
                ORIGIN,
                RP_ID,
                key.verifying_key(),
            )
            .is_err()
        );

        for extra in [
            ",\"crossOrigin\":true",
            ",\"topOrigin\":\"https://embed.example\"",
            ",\"origin\":\"https://keys.example\"",
        ] {
            let client = client_data(&CHALLENGE, ORIGIN, extra);
            let auth = authenticator_data(RP_ID, FLAG_UP | FLAG_UV, &[]);
            let signature = signed_fixture(&key, &client, &auth);
            assert!(
                verify_assertion(
                    &client,
                    &auth,
                    &signature,
                    &CHALLENGE,
                    ORIGIN,
                    RP_ID,
                    key.verifying_key()
                )
                .is_err()
            );
        }
        let (key, client, auth, mut signature) = valid_fixture();
        let last = signature.len() - 1;
        signature[last] ^= 1;
        assert!(Signature::from_der(&signature).is_ok());
        assert!(
            verify_assertion(
                &client,
                &auth,
                &signature,
                &CHALLENGE,
                ORIGIN,
                RP_ID,
                key.verifying_key()
            )
            .is_err()
        );
    }

    #[test]
    fn key_message_requires_exact_top_level_shape_and_validates_before_returning_key() {
        let (key, client, auth, signature) = valid_fixture();
        let json = format!(
            "{{\"type\":\"key\",\"version\":1,\"key\":\"{}\",\"assertion\":{{\"clientDataJSON\":\"{}\",\"authenticatorData\":\"{}\",\"signature\":\"{}\"}}}}",
            URL_SAFE_NO_PAD.encode([9_u8; 32]),
            URL_SAFE_NO_PAD.encode(client),
            URL_SAFE_NO_PAD.encode(auth),
            URL_SAFE_NO_PAD.encode(signature),
        );
        assert_eq!(
            verify_key_message(
                json.as_bytes(),
                &CHALLENGE,
                ORIGIN,
                RP_ID,
                key.verifying_key()
            )
            .unwrap()
            .as_ref(),
            &[9_u8; 32]
        );
        let other_connection_challenge = [0x43; 32];
        let error = verify_key_message(
            json.replace(&URL_SAFE_NO_PAD.encode([9_u8; 32]), "not-valid-base64url")
                .as_bytes(),
            &other_connection_challenge,
            ORIGIN,
            RP_ID,
            key.verifying_key(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("challenge"));
        assert!(
            verify_key_message(
                json.replace(
                    &URL_SAFE_NO_PAD.encode([9_u8; 32]),
                    &URL_SAFE_NO_PAD.encode([9_u8; 31]),
                )
                .as_bytes(),
                &CHALLENGE,
                ORIGIN,
                RP_ID,
                key.verifying_key(),
            )
            .is_err()
        );
        assert!(
            verify_key_message(
                json.replace("\"version\":1", "\"version\":2").as_bytes(),
                &CHALLENGE,
                ORIGIN,
                RP_ID,
                key.verifying_key(),
            )
            .is_err()
        );
        assert!(
            verify_key_message(
                json.replace("\"type\":\"key\"", "\"type\":\"other\"")
                    .as_bytes(),
                &CHALLENGE,
                ORIGIN,
                RP_ID,
                key.verifying_key(),
            )
            .is_err()
        );
        assert!(
            verify_key_message(
                json.replace("\"version\":1", "\"version\":1,\"extra\":true")
                    .as_bytes(),
                &CHALLENGE,
                ORIGIN,
                RP_ID,
                key.verifying_key(),
            )
            .is_err()
        );
        assert!(
            verify_key_message(
                json.replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
                    .as_bytes(),
                &CHALLENGE,
                ORIGIN,
                RP_ID,
                key.verifying_key(),
            )
            .is_err()
        );
    }
}
