import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { webcrypto } from "node:crypto";

import { decodeBase64Url } from "./encoding.mjs";
import { createApprovalAssertion, createPasskey } from "./webauthn.mjs";
import { prfInput } from "./envelope.mjs";

const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
const originalWindow = globalThis.window;
const originalLocation = Object.getOwnPropertyDescriptor(globalThis, "location");
const originalCredential = globalThis.PublicKeyCredential;
const originalCrypto = Object.getOwnPropertyDescriptor(globalThis, "crypto");
const credentialId = Uint8Array.of(1, 2, 3, 4).buffer;
const publicKeyDer = Uint8Array.of(0x30, 0x12, 0x01, 0x02, 0x03).buffer;

function installWebAuthn({
  secure = true,
  algorithm = -7,
  exportMethod = true,
  prfEnabled = true,
  prfResult = new Uint8Array(32).fill(0x5a).buffer,
} = {}) {
  let createOptions;
  let getOptions;
  class FakePublicKeyCredential {
    constructor(response, extensions = { prf: { enabled: prfEnabled } }) {
      this.response = response;
      this.rawId = credentialId;
      this.extensions = extensions;
    }

    getClientExtensionResults() {
      return this.extensions;
    }
  }

  const response = {
    getPublicKeyAlgorithm: () => algorithm,
    ...(exportMethod ? { getPublicKey: () => publicKeyDer } : {}),
  };
  const credentials = {
    create: async (options) => {
      createOptions = options;
      return new FakePublicKeyCredential(response);
    },
    get: async (options) => {
      getOptions = options;
      return new FakePublicKeyCredential({
        clientDataJSON: Uint8Array.of(1, 2, 3).buffer,
        authenticatorData: Uint8Array.of(4, 5, 6).buffer,
        signature: Uint8Array.of(7, 8, 9).buffer,
      }, { prf: { results: { first: prfResult } } });
    },
  };

  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { credentials },
  });
  globalThis.window = {
    isSecureContext: secure,
    PublicKeyCredential: FakePublicKeyCredential,
  };
  globalThis.location = { hostname: "keys.example" };
  globalThis.PublicKeyCredential = FakePublicKeyCredential;
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: webcrypto,
  });
  return {
    createOptions: () => createOptions,
    getOptions: () => getOptions,
  };
}

afterEach(() => {
  if (originalNavigator) Object.defineProperty(globalThis, "navigator", originalNavigator);
  else delete globalThis.navigator;
  if (originalWindow === undefined) delete globalThis.window;
  else globalThis.window = originalWindow;
  if (originalLocation === undefined) delete globalThis.location;
  else Object.defineProperty(globalThis, "location", originalLocation);
  if (originalCredential === undefined) delete globalThis.PublicKeyCredential;
  else globalThis.PublicKeyCredential = originalCredential;
  if (originalCrypto === undefined) delete globalThis.crypto;
  else Object.defineProperty(globalThis, "crypto", originalCrypto);
});

test("creates a discoverable ES256 passkey, confirms PRF, and exports SPKI", async () => {
  const api = installWebAuthn();
  const output = await createPasskey("Work laptop");
  const create = api.createOptions().publicKey;
  const get = api.getOptions().publicKey;

  assert.deepEqual(create.pubKeyCredParams, [{ type: "public-key", alg: -7 }]);
  assert.deepEqual(create.authenticatorSelection, {
    residentKey: "required",
    userVerification: "required",
  });
  assert.equal(create.attestation, "none");
  assert.deepEqual(create.extensions, { prf: {} });
  assert.equal(create.user.name, "Work laptop");
  assert.equal(create.user.displayName, "Work laptop");
  assert.equal(create.user.id.byteLength, 32);
  assert.equal(get.userVerification, "required");
  assert.deepEqual(get.allowCredentials, [{ type: "public-key", id: credentialId }]);
  assert.equal(get.extensions.prf.eval.first instanceof Uint8Array, true);
  assert.equal(output.publicKeyAlgorithm, "ES256 (-7)");
  assert.equal(output.prfSupported, true);
  assert.deepEqual(decodeBase64Url(output.publicKey), new Uint8Array(publicKeyDer));
});

test("fails clearly when PRF output is missing or unsupported", async () => {
  installWebAuthn({ prfEnabled: false });
  await assert.rejects(createPasskey("Work laptop"), /did not enable the WebAuthn PRF extension/u);

  installWebAuthn({ prfResult: null });
  await assert.rejects(createPasskey("Work laptop"), /did not return a 32-byte PRF result/u);
});

test("fails clearly when ES256 public-key export is unavailable", async () => {
  installWebAuthn({ exportMethod: false });
  await assert.rejects(createPasskey("Work laptop"), /does not support WebAuthn public-key export/u);
});

test("fails clearly for an unexpected algorithm or an insecure context", async () => {
  installWebAuthn({ algorithm: -257 });
  await assert.rejects(createPasskey("Work laptop"), /did not use ES256/u);

  installWebAuthn({ secure: false });
  await assert.rejects(createPasskey("Work laptop"), /requires a secure context/u);
});

test("approval uses the exact CLI challenge and derives from the v1 PRF input", async () => {
  const prfResult = new Uint8Array(32).fill(0x5a).buffer;
  const api = installWebAuthn({ prfResult });
  const request = {
    challenge: Uint8Array.from({ length: 32 }, (_, index) => index),
    name: "secret-x",
    revision: 3,
  };
  const output = await createApprovalAssertion(request, new AbortController().signal);
  const options = api.getOptions();
  assert.deepEqual(options.publicKey.challenge, request.challenge);
  assert.equal(options.publicKey.rpId, "keys.example");
  assert.equal(options.publicKey.userVerification, "required");
  assert.equal(Object.hasOwn(options.publicKey, "allowCredentials"), false);
  assert.deepEqual(options.publicKey.extensions.prf.eval.first, prfInput("secret-x", 3));
  assert.equal(output.key.byteLength, 32);
  assert.deepEqual(new Uint8Array(output.assertion.clientDataJSON), Uint8Array.of(1, 2, 3));
  assert.deepEqual(new Uint8Array(prfResult), new Uint8Array(32));
  output.key.fill(0);
});

test("approval cancellation and absent PRF output fail before returning a key", async () => {
  installWebAuthn();
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(createApprovalAssertion({ challenge: new Uint8Array(32), name: "x", revision: 1 }, controller.signal), /cancelled/u);

  installWebAuthn({ prfResult: null });
  await assert.rejects(
    createApprovalAssertion({ challenge: new Uint8Array(32), name: "x", revision: 1 }, new AbortController().signal),
    /32-byte PRF result/u,
  );
});
