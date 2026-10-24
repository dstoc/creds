import assert from "node:assert/strict";
import { after, test } from "node:test";
import { webcrypto } from "node:crypto";

import { testPrfApi } from "./webauthn-probe.mjs";

const descriptors = {
  navigator: Object.getOwnPropertyDescriptor(globalThis, "navigator"),
  location: Object.getOwnPropertyDescriptor(globalThis, "location"),
  crypto: Object.getOwnPropertyDescriptor(globalThis, "crypto"),
};
const oldWindow = globalThis.window;
const oldCredential = globalThis.PublicKeyCredential;
const createCalls = [];
const getCalls = [];
const credentialId = Uint8Array.of(1, 2, 3, 4).buffer;

class FakePublicKeyCredential {
  constructor(extensions) {
    this.rawId = credentialId;
    this.extensions = extensions;
  }

  getClientExtensionResults() {
    return this.extensions;
  }
}

const credentials = {
  async create(options) {
    createCalls.push(options);
    return new FakePublicKeyCredential({ prf: { enabled: true } });
  },
  async get(options) {
    getCalls.push(options);
    return new FakePublicKeyCredential({ prf: { results: { first: new Uint8Array(32).fill(0x5a).buffer } } });
  },
};

Object.defineProperty(globalThis, "navigator", { configurable: true, value: { credentials } });
Object.defineProperty(globalThis, "location", { configurable: true, value: { hostname: "localhost" } });
Object.defineProperty(globalThis, "crypto", { configurable: true, value: webcrypto });
globalThis.window = { isSecureContext: true, PublicKeyCredential: FakePublicKeyCredential };
globalThis.PublicKeyCredential = FakePublicKeyCredential;

after(() => {
  for (const [name, descriptor] of Object.entries(descriptors)) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else delete globalThis[name];
  }
  if (oldWindow === undefined) delete globalThis.window;
  else globalThis.window = oldWindow;
  if (oldCredential === undefined) delete globalThis.PublicKeyCredential;
  else globalThis.PublicKeyCredential = oldCredential;
});

test("development PRF probe creates a test credential and checks repeat output", async () => {
  const first = await testPrfApi();
  const second = await testPrfApi();
  assert.deepEqual(first, {
    registrationPrfEnabled: true,
    resultLengthBytes: 32,
    repeatedResultMatched: true,
    rpId: "localhost",
  });
  assert.deepEqual(second, first);
  assert.equal(createCalls.length, 1);
  assert.equal(getCalls.length, 4);

  const create = createCalls[0].publicKey;
  assert.equal(create.rp.id, "localhost");
  assert.deepEqual(create.authenticatorSelection, { residentKey: "required", userVerification: "required" });
  assert.deepEqual(create.extensions, { prf: {} });
  for (const call of getCalls) {
    assert.deepEqual(call.publicKey.allowCredentials, [{ type: "public-key", id: credentialId }]);
    assert.equal(call.publicKey.extensions.prf.eval.first.byteLength > 0, true);
  }
});
