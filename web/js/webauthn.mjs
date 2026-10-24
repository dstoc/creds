const PRF_INPUT = new TextEncoder().encode("creds/prf/local-probe/v1");
let testCredential;

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

async function evaluatePrf(credentialId) {
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      timeout: 15_000,
      rpId: location.hostname,
      allowCredentials: [{ type: "public-key", id: credentialId }],
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_INPUT } } },
    },
  });
  const result = credential?.getClientExtensionResults?.().prf?.results?.first;
  if (!(result instanceof ArrayBuffer) || result.byteLength !== 32) {
    throw new Error("The authenticator did not return a 32-byte PRF result.");
  }
  return new Uint8Array(result);
}

export async function testPrfApi() {
  if (!window.isSecureContext) throw new Error("WebAuthn requires a secure context.");
  if (!navigator.credentials?.create || !navigator.credentials?.get || !window.PublicKeyCredential) {
    throw new Error("WebAuthn is unavailable in this browser context.");
  }

  if (!testCredential) {
    testCredential = await navigator.credentials.create({
      publicKey: {
        challenge: randomBytes(32),
        timeout: 15_000,
        rp: { name: "creds local compatibility probe", id: location.hostname },
        user: {
          id: randomBytes(16),
          name: "probe@creds.invalid",
          displayName: "creds local PRF probe",
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
        attestation: "none",
        extensions: { prf: {} },
      },
    });
    if (!(testCredential instanceof PublicKeyCredential)) {
      testCredential = undefined;
      throw new Error("No passkey was created.");
    }
  }

  const registrationPrfEnabled = testCredential.getClientExtensionResults().prf?.enabled === true;
  const first = await evaluatePrf(testCredential.rawId);
  let reproducible;
  try {
    const second = await evaluatePrf(testCredential.rawId);
    try {
      reproducible = first.every((byte, index) => byte === second[index]);
    } finally {
      second.fill(0);
    }
  } finally {
    first.fill(0);
  }
  if (!reproducible) throw new Error("Repeated PRF evaluation returned different bytes.");

  return {
    registrationPrfEnabled,
    resultLengthBytes: 32,
    repeatedResultMatched: true,
    rpId: location.hostname,
  };
}
