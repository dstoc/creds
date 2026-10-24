import { encodeBase64Url } from "./encoding.mjs";
import { deriveEncryptionKey, prfInput } from "./envelope.mjs";

const SETUP_PRF_INPUT = new TextEncoder().encode("creds/passkey-setup/v1");

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

async function verifyCreatedCredentialPrf(credentialId) {
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      timeout: 60_000,
      rpId: location.hostname,
      allowCredentials: [{ type: "public-key", id: credentialId }],
      userVerification: "required",
      extensions: { prf: { eval: { first: SETUP_PRF_INPUT } } },
    },
  });
  const result = credential?.getClientExtensionResults?.().prf?.results?.first;
  if (!(result instanceof ArrayBuffer)) {
    throw new Error("This passkey or authenticator did not return a 32-byte PRF result. Setup cannot continue.");
  }
  const output = new Uint8Array(result);
  const validLength = output.byteLength === 32;
  output.fill(0);
  if (!validLength) {
    throw new Error("This passkey or authenticator did not return a 32-byte PRF result. Setup cannot continue.");
  }
}

export async function createPasskey(label) {
  if (!window.isSecureContext) throw new Error("WebAuthn requires a secure context.");
  if (!navigator.credentials?.create || !navigator.credentials?.get || !window.PublicKeyCredential) {
    throw new Error("WebAuthn is unavailable in this browser context.");
  }
  if (typeof label !== "string" || label.length === 0 || label.length > 64) {
    throw new Error("Enter a human-readable passkey label of 1 to 64 characters.");
  }

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      timeout: 60_000,
      rp: { name: "creds", id: location.hostname },
      user: {
        id: randomBytes(32),
        name: label,
        displayName: label,
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      attestation: "none",
      extensions: { prf: {} },
    },
  });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error("The browser did not create a passkey credential.");
  }

  const attestationResponse = credential.response;
  if (typeof attestationResponse.getPublicKeyAlgorithm !== "function") {
    throw new Error("This browser cannot report the exported passkey algorithm. Public-key export is unsupported.");
  }
  if (attestationResponse.getPublicKeyAlgorithm() !== -7) {
    throw new Error("The created passkey did not use ES256 (P-256 with SHA-256).");
  }
  if (typeof attestationResponse.getPublicKey !== "function") {
    throw new Error("This browser does not support WebAuthn public-key export.");
  }
  const publicKeyDer = attestationResponse.getPublicKey();
  if (!(publicKeyDer instanceof ArrayBuffer) || publicKeyDer.byteLength === 0) {
    throw new Error("The browser could not export the passkey public key as DER SubjectPublicKeyInfo.");
  }

  const registrationPrfEnabled = credential.getClientExtensionResults().prf?.enabled === true;
  if (!registrationPrfEnabled) {
    throw new Error("The new passkey did not enable the WebAuthn PRF extension. Setup cannot continue.");
  }
  await verifyCreatedCredentialPrf(credential.rawId);

  return {
    publicKey: encodeBase64Url(new Uint8Array(publicKeyDer)),
    publicKeyAlgorithm: "ES256 (-7)",
    prfSupported: true,
  };
}

export async function createApprovalAssertion(request, signal) {
  if (!window.isSecureContext) throw new Error("WebAuthn requires a secure context.");
  if (!navigator.credentials?.get || !window.PublicKeyCredential) {
    throw new Error("WebAuthn is unavailable in this browser context.");
  }
  if (signal?.aborted) throw new DOMException("Approval was cancelled.", "AbortError");

  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: request.challenge,
      timeout: 120_000,
      rpId: location.hostname,
      userVerification: "required",
      extensions: { prf: { eval: { first: prfInput(request.name, request.revision) } } },
    },
    signal,
  });
  if (!(credential instanceof PublicKeyCredential) || !credential.response) {
    throw new Error("The browser did not return a WebAuthn assertion.");
  }

  const prfResult = credential.getClientExtensionResults?.().prf?.results?.first;
  if (!(prfResult instanceof ArrayBuffer) || prfResult.byteLength !== 32) {
    throw new Error("The passkey did not return a 32-byte PRF result.");
  }
  const prfOutput = new Uint8Array(prfResult);
  let key;
  try {
    if (signal?.aborted) throw new DOMException("Approval was cancelled.", "AbortError");
    key = await deriveEncryptionKey(prfOutput);
  } finally {
    prfOutput.fill(0);
  }

  if (signal?.aborted) {
    key.fill(0);
    throw new DOMException("Approval was cancelled.", "AbortError");
  }
  const { clientDataJSON, authenticatorData, signature } = credential.response;
  const fields = [clientDataJSON, authenticatorData, signature];
  if (fields.some((field) => !(field instanceof ArrayBuffer) || field.byteLength === 0 || field.byteLength > 4096)) {
    key.fill(0);
    throw new Error("The WebAuthn assertion contains an empty or oversized field.");
  }
  return {
    key,
    assertion: { clientDataJSON, authenticatorData, signature },
  };
}
