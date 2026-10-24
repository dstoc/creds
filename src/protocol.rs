use hkdf::Hkdf;
use sha2::Sha256;
use std::{error::Error, fmt};
use zeroize::Zeroizing;

const PRF_DOMAIN: &[u8] = b"creds/prf/v1\0";
const AAD_DOMAIN: &[u8] = b"creds/file/v1\0";
const HKDF_INFO: &[u8] = b"creds/aes-256-gcm/v1";
const KEY_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError(String);

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ProtocolError {}

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError(message.into())
}

/// Validate a v1 logical name without trimming or normalizing it.
pub fn validate_name(name: &str) -> Result<(), ProtocolError> {
    let bytes = name.as_bytes();
    if !(1..=128).contains(&bytes.len())
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(byte))
    {
        return Err(invalid(
            "name must be 1–128 ASCII letters, digits, dots, underscores, or hyphens and start with a letter or digit",
        ));
    }
    Ok(())
}

/// Validate the positive, exactly representable v1 revision range.
pub fn validate_revision(revision: u32) -> Result<(), ProtocolError> {
    if revision == 0 {
        return Err(invalid("revision must be between 1 and 4,294,967,295"));
    }
    Ok(())
}

fn suffix(name: &str, revision: u32) -> Result<[u8; 4], ProtocolError> {
    validate_name(name)?;
    validate_revision(revision)?;
    Ok(revision.to_be_bytes())
}

/// Build the exact v1 input passed to the WebAuthn PRF extension.
pub fn prf_input(name: &str, revision: u32) -> Result<Vec<u8>, ProtocolError> {
    let encoded_revision = suffix(name, revision)?;
    let mut input = Vec::with_capacity(PRF_DOMAIN.len() + name.len() + 1 + 4);
    input.extend_from_slice(PRF_DOMAIN);
    input.extend_from_slice(name.as_bytes());
    input.push(0);
    input.extend_from_slice(&encoded_revision);
    Ok(input)
}

/// Build the exact v1 AES-GCM associated data.
pub fn associated_data(name: &str, revision: u32) -> Result<Vec<u8>, ProtocolError> {
    let encoded_revision = suffix(name, revision)?;
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + name.len() + 1 + 4);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(name.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&encoded_revision);
    Ok(aad)
}

/// Derive the AES-256 key from the 32-byte output of the WebAuthn PRF.
pub fn derive_key(prf_output: &[u8]) -> Result<Zeroizing<[u8; KEY_BYTES]>, ProtocolError> {
    if prf_output.len() != KEY_BYTES {
        return Err(invalid("WebAuthn PRF output must be exactly 32 bytes"));
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), prf_output);
    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    hkdf.expand(HKDF_INFO, key.as_mut())
        .map_err(|_| invalid("HKDF could not derive a 32-byte key"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let digit = |byte| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid hex vector"),
                };
                digit(pair[0]) * 16 + digit(pair[1])
            })
            .collect()
    }

    #[test]
    fn shared_vectors_match_protocol_bytes_and_hkdf() {
        let vectors: Value = serde_json::from_str(include_str!("../test-vectors/envelope-v1.json"))
            .expect("shared vector JSON parses");
        for vector in vectors["vectors"].as_array().expect("vectors array") {
            let name = vector["name"].as_str().expect("name");
            let revision = vector["revision"].as_u64().expect("revision") as u32;
            assert_eq!(
                prf_input(name, revision).expect("valid PRF input"),
                decode_hex(vector["prfInputHex"].as_str().expect("PRF input vector"))
            );
            assert_eq!(
                associated_data(name, revision).expect("valid AAD"),
                decode_hex(vector["aadHex"].as_str().expect("AAD vector"))
            );
            assert_eq!(
                vector["hkdfSaltHex"],
                "0000000000000000000000000000000000000000000000000000000000000000"
            );
            assert_eq!(
                vector["hkdfInfoHex"],
                "63726564732f6165732d3235362d67636d2f7631"
            );
            let prf_output = decode_hex(vector["prfOutputHex"].as_str().expect("PRF output"));
            let derived_key = derive_key(&prf_output).expect("valid key");
            let expected_key = decode_hex(vector["derivedKeyHex"].as_str().expect("key vector"));
            assert_eq!(&derived_key[..], expected_key.as_slice());
        }
    }

    #[test]
    fn names_are_validated_without_normalization() {
        assert!(validate_name("Secret-X").is_ok());
        assert!(validate_name("secret-x-r2").is_ok());
        assert!(validate_name(" Secret-X").is_err());
        assert!(validate_name("Secret-X\n").is_err());
        assert!(validate_name("Secret\0X").is_err());
        assert!(validate_name("é").is_err());
        assert!(validate_name("a/../b").is_err());
        assert!(validate_name(&"a".repeat(129)).is_err());
    }

    #[test]
    fn zero_separator_and_u32_big_endian_revision_are_fixed() {
        let bytes = prf_input("Secret-X_r2", 0x0102_0304).unwrap();
        assert!(bytes.windows(2).any(|pair| pair == [b'2', 0]));
        assert_eq!(&bytes[bytes.len() - 4..], &[1, 2, 3, 4]);
        assert!(validate_revision(0).is_err());
        assert!(validate_revision(u32::MAX).is_ok());
    }

    #[test]
    fn hkdf_requires_exact_prf_length() {
        assert!(derive_key(&[0; 31]).is_err());
        assert!(derive_key(&[0; 33]).is_err());
    }
}
