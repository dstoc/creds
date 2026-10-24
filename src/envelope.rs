use crate::protocol::{associated_data, validate_name, validate_revision};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};
use zeroize::Zeroizing;

pub const MAX_PLAINTEXT_BYTES: usize = 64 * 1024;
pub const MAX_ENVELOPE_BYTES: usize = 128 * 1024;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeError(String);

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for EnvelopeError {}

impl EnvelopeError {
    pub(crate) fn from_message(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

fn invalid(message: impl Into<String>) -> EnvelopeError {
    EnvelopeError(message.into())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    version: u8,
    name: String,
    revision: u32,
    nonce: String,
    ciphertext: String,
}

impl Envelope {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn revision(&self) -> u32 {
        self.revision
    }

    pub fn encrypt(
        name: &str,
        revision: u32,
        plaintext: &[u8],
        key: &[u8; 32],
    ) -> Result<Self, EnvelopeError> {
        validate_name(name).map_err(|error| invalid(error.to_string()))?;
        validate_revision(revision).map_err(|error| invalid(error.to_string()))?;
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(invalid("plaintext exceeds the 64 KiB limit"));
        }

        let mut nonce = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce)
            .map_err(|error| invalid(format!("random nonce failed: {error}")))?;
        Self::encrypt_with_nonce(name, revision, plaintext, key, nonce)
    }

    fn encrypt_with_nonce(
        name: &str,
        revision: u32,
        plaintext: &[u8],
        key: &[u8; 32],
        nonce: [u8; NONCE_BYTES],
    ) -> Result<Self, EnvelopeError> {
        let aad = associated_data(name, revision).map_err(|error| invalid(error.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| invalid("AES-256-GCM rejected a 32-byte key"))?;
        let nonce = Nonce::try_from(&nonce[..])
            .map_err(|_| invalid("nonce must contain exactly 12 bytes"))?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| invalid("AES-256-GCM encryption failed"))?;
        Ok(Self {
            version: 1,
            name: name.to_owned(),
            revision,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }

    pub fn decrypt(&self, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        let nonce = decode_canonical("nonce", &self.nonce)?;
        if nonce.len() != NONCE_BYTES {
            return Err(invalid("nonce must decode to exactly 12 bytes"));
        }
        let nonce = Nonce::try_from(&nonce[..])
            .map_err(|_| invalid("nonce must contain exactly 12 bytes"))?;
        let ciphertext = decode_canonical("ciphertext", &self.ciphertext)?;
        if ciphertext.len() < TAG_BYTES {
            return Err(invalid(
                "ciphertext must include a 16-byte authentication tag",
            ));
        }
        if ciphertext.len() > MAX_PLAINTEXT_BYTES + TAG_BYTES {
            return Err(invalid("ciphertext exceeds the plaintext size limit"));
        }
        let aad = associated_data(&self.name, self.revision)
            .map_err(|error| invalid(error.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| invalid("AES-256-GCM rejected a 32-byte key"))?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                invalid("authentication failed (key does not match or envelope is damaged)")
            })?;
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(invalid("decrypted plaintext exceeds the 64 KiB limit"));
        }
        Ok(Zeroizing::new(plaintext))
    }

    pub fn to_json(&self) -> Result<Vec<u8>, EnvelopeError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| invalid(format!("could not serialize envelope: {error}")))?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(invalid("serialized envelope exceeds the 128 KiB limit"));
        }
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(invalid("envelope is empty or exceeds the 128 KiB limit"));
        }
        let envelope: Self = serde_json::from_slice(bytes)
            .map_err(|error| invalid(format!("malformed envelope JSON: {error}")))?;
        if envelope.version != 1 {
            return Err(invalid("envelope version must be 1"));
        }
        validate_name(&envelope.name).map_err(|error| invalid(error.to_string()))?;
        validate_revision(envelope.revision).map_err(|error| invalid(error.to_string()))?;
        let nonce = decode_canonical("nonce", &envelope.nonce)?;
        if nonce.len() != NONCE_BYTES {
            return Err(invalid("nonce must decode to exactly 12 bytes"));
        }
        let ciphertext = decode_canonical("ciphertext", &envelope.ciphertext)?;
        if ciphertext.len() < TAG_BYTES {
            return Err(invalid(
                "ciphertext must include a 16-byte authentication tag",
            ));
        }
        if ciphertext.len() > MAX_PLAINTEXT_BYTES + TAG_BYTES {
            return Err(invalid("ciphertext exceeds the plaintext size limit"));
        }
        Ok(envelope)
    }
}

fn decode_canonical(field: &str, encoded: &str) -> Result<Vec<u8>, EnvelopeError> {
    if encoded.is_empty() {
        return Err(invalid(format!("{field} must not be empty")));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| invalid(format!("{field} is not unpadded base64url: {error}")))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(invalid(format!("{field} is not canonical base64url")));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [0x5a; 32]
    }

    #[test]
    fn round_trips_empty_binary_and_maximum_plaintext() {
        for plaintext in [
            Vec::new(),
            vec![0, 255, 0, 1],
            vec![0xa5; MAX_PLAINTEXT_BYTES],
        ] {
            let envelope = Envelope::encrypt("Secret-X", 1, &plaintext, &key()).unwrap();
            let parsed = Envelope::parse(&envelope.to_json().unwrap()).unwrap();
            assert_eq!(parsed.decrypt(&key()).unwrap().as_slice(), plaintext);
        }
    }

    #[test]
    fn generated_nonces_are_fresh() {
        let first = Envelope::encrypt("secret", 1, b"same", &key()).unwrap();
        let second = Envelope::encrypt("secret", 1, b"same", &key()).unwrap();
        assert_ne!(first.nonce, second.nonce);
    }

    #[test]
    fn tampering_with_authenticated_fields_fails() {
        let envelope = Envelope::encrypt("secret", 4, b"secret bytes", &key()).unwrap();
        let mut wrong_name = envelope.clone();
        wrong_name.name = "Secret".into();
        let mut wrong_revision = envelope.clone();
        wrong_revision.revision += 1;
        let mut wrong_nonce = envelope.clone();
        let mut nonce = URL_SAFE_NO_PAD.decode(&wrong_nonce.nonce).unwrap();
        nonce[0] ^= 1;
        wrong_nonce.nonce = URL_SAFE_NO_PAD.encode(nonce);
        let mut wrong_ciphertext = envelope.clone();
        let mut ciphertext = URL_SAFE_NO_PAD
            .decode(&wrong_ciphertext.ciphertext)
            .unwrap();
        ciphertext[0] ^= 1;
        wrong_ciphertext.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
        let mut wrong_tag = envelope.clone();
        let mut ciphertext = URL_SAFE_NO_PAD.decode(&wrong_tag.ciphertext).unwrap();
        *ciphertext.last_mut().unwrap() ^= 1;
        wrong_tag.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
        for damaged in [
            wrong_name,
            wrong_revision,
            wrong_nonce,
            wrong_ciphertext,
            wrong_tag,
        ] {
            assert!(damaged.decrypt(&key()).is_err());
        }
        assert!(envelope.decrypt(&[0; 32]).is_err());
    }

    #[test]
    fn parser_rejects_duplicate_unknown_invalid_and_oversized_fields() {
        let valid_envelope = Envelope::encrypt("secret", 1, b"x", &key()).unwrap();
        let good = String::from_utf8(valid_envelope.to_json().unwrap()).unwrap();
        let duplicate = good.replacen("\"version\":1,", "\"version\":1,\"version\":1,", 1);
        let unknown = good.trim_end_matches('}').to_owned() + ",\"extra\":true}";
        let bad_name = good.replace("\"name\":\"secret\"", "\"name\":\"../secret\"");
        let bad_revision = good.replace("\"revision\":1", "\"revision\":0");
        let out_of_range_revision = good.replace("\"revision\":1", "\"revision\":4294967296");
        let fractional_revision = good.replace("\"revision\":1", "\"revision\":1.5");
        let negative_revision = good.replace("\"revision\":1", "\"revision\":-1");
        let bad_version = good.replace("\"version\":1", "\"version\":2");
        let padded = good.replace("\"nonce\":\"", "\"nonce\":\"=");
        let invalid_encoding = good.replace(&valid_envelope.nonce, "not+base64");
        let short_ciphertext = good.replace(
            &format!("\"ciphertext\":\"{}\"", valid_envelope.ciphertext),
            "\"ciphertext\":\"AA\"",
        );
        for malformed in [
            duplicate,
            unknown,
            bad_name,
            bad_revision,
            out_of_range_revision,
            fractional_revision,
            negative_revision,
            bad_version,
            padded,
            invalid_encoding,
            short_ciphertext,
        ] {
            assert!(
                Envelope::parse(malformed.as_bytes()).is_err(),
                "accepted {malformed}"
            );
        }
        assert!(Envelope::parse(&vec![b' '; MAX_ENVELOPE_BYTES + 1]).is_err());
        assert!(Envelope::encrypt("secret", 1, &vec![0; MAX_PLAINTEXT_BYTES + 1], &key()).is_err());
    }
}
