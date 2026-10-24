import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { webcrypto } from "node:crypto";
import { associatedData, deriveEncryptionKey, prfInput, validateName, validateRevision } from "./envelope.mjs";

const fixtureUrl = new URL("../../test-vectors/envelope-v1.json", import.meta.url);
const fixtures = JSON.parse(await readFile(fixtureUrl, "utf8"));
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const fromHex = (value) => Uint8Array.from(Buffer.from(value, "hex"));

test("Rust and JavaScript match the shared v1 PRF, HKDF, and AAD vectors", async () => {
  for (const vector of fixtures.vectors) {
    assert.equal(hex(prfInput(vector.name, vector.revision)), vector.prfInputHex);
    assert.equal(hex(associatedData(vector.name, vector.revision)), vector.aadHex);
    assert.equal(hex(await deriveEncryptionKey(fromHex(vector.prfOutputHex), webcrypto)), vector.derivedKeyHex);
  }
});

test("logical names are validated case-sensitively and literal suffixes remain names", () => {
  assert.equal(validateName("Secret-X"), "Secret-X");
  assert.equal(validateName("secret-x-r2"), "secret-x-r2");
  for (const name of ["", " Secret-X", "Secret-X\n", "Secret\0X", "é", "a/../b", "a".repeat(129)]) {
    assert.throws(() => validateName(name), TypeError);
  }
  assert.notDeepEqual(prfInput("Secret-X", 1), prfInput("secret-x", 1));
});

test("revision encoding uses exactly four unsigned big-endian bytes", () => {
  assert.equal(hex(prfInput("Secret-X_r2", 0x01020304)).slice(-8), "01020304");
  assert.equal(hex(prfInput("secret-x-r2", 1)).slice(-8), "00000001");
  for (const revision of [0, -1, 1.5, 0x100000000, Number.NaN]) {
    assert.throws(() => validateRevision(revision), TypeError);
  }
  assert.equal(validateRevision(0xffffffff), 0xffffffff);
});

test("WebAuthn PRF output must be exactly 32 bytes", async () => {
  await assert.rejects(deriveEncryptionKey(new Uint8Array(31), webcrypto), TypeError);
  await assert.rejects(deriveEncryptionKey(new Uint8Array(33), webcrypto), TypeError);
});
