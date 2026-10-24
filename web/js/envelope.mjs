const PRF_DOMAIN = new TextEncoder().encode("creds/prf/v1\0");
const AAD_DOMAIN = new TextEncoder().encode("creds/file/v1\0");
const HKDF_INFO = new TextEncoder().encode("creds/aes-256-gcm/v1");

export function validateName(name) {
  if (
    typeof name !== "string" ||
    name.length < 1 ||
    name.length > 128 ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(name)
  ) {
    throw new TypeError("Name must be 1–128 valid ASCII characters.");
  }
  return name;
}

export function validateRevision(revision) {
  if (!Number.isInteger(revision) || revision < 1 || revision > 0xffffffff) {
    throw new TypeError("Revision must be an integer from 1 through 4,294,967,295.");
  }
  return revision;
}

function revisionBytes(name, revision) {
  validateName(name);
  validateRevision(revision);
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, revision, false);
  return bytes;
}

function concatenate(...parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

export function prfInput(name, revision) {
  return concatenate(PRF_DOMAIN, new TextEncoder().encode(name), Uint8Array.of(0), revisionBytes(name, revision));
}

export function associatedData(name, revision) {
  return concatenate(AAD_DOMAIN, new TextEncoder().encode(name), Uint8Array.of(0), revisionBytes(name, revision));
}

export async function deriveEncryptionKey(prfOutput, cryptoProvider = globalThis.crypto) {
  const bytes = new Uint8Array(prfOutput);
  if (bytes.length !== 32) throw new TypeError("WebAuthn PRF output must be exactly 32 bytes.");
  const keyMaterial = await cryptoProvider.subtle.importKey("raw", bytes, "HKDF", false, ["deriveBits"]);
  const derived = await cryptoProvider.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: HKDF_INFO },
    keyMaterial,
    256,
  );
  return new Uint8Array(derived);
}
