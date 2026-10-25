import assert from "node:assert/strict";
import test from "node:test";

import { encodeBase64Url } from "./encoding.mjs";
import {
  emptySettings,
  loadSettings,
  MAX_ACCEPTED_PREFIXES,
  MAX_SETTINGS_BYTES,
  normalizePrefix,
  normalizeSuffix,
  resetSettings,
  saveSettings,
  SETTINGS_STORAGE_KEY,
  validateCombinedHostname,
  validatePublicKey,
} from "./settings.mjs";

class MemoryStorage {
  values = new Map();
  getItem(key) { return this.values.get(key) ?? null; }
  setItem(key, value) { this.values.set(key, value); }
  removeItem(key) { this.values.delete(key); }
}

async function publicKey() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return encodeBase64Url(new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)));
}

test("suffix and prefix normalization accepts DNS case variants and rejects URL or label injection", () => {
  assert.equal(normalizeSuffix("  TailNet.Example.Net  "), "tailnet.example.net");
  assert.equal(normalizePrefix(" WorkStation-1 "), "workstation-1");
  assert.equal(validateCombinedHostname("WorkStation", "TailNet.Example").fullHostname, "workstation.tailnet.example");

  for (const suffix of [
    "",
    ".example.net",
    "example..net",
    "example.net.",
    "192.0.2.1",
    "127.1",
    "2130706433",
    "https://example.net",
    "example.net:443",
    "example.net/path",
    "-example.net",
    "example-.net",
    `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.${"e".repeat(5)}`,
  ]) {
    assert.throws(() => normalizeSuffix(suffix), `accepted invalid suffix ${JSON.stringify(suffix)}`);
  }
  for (const prefix of ["", "a.b", "a/b", "-laptop", "laptop-", "a:443", "a_1"]) {
    assert.throws(() => normalizePrefix(prefix), `accepted invalid prefix ${JSON.stringify(prefix)}`);
  }
  assert.throws(
    () => validateCombinedHostname("a".repeat(63), `${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.e`),
    /hostname is too long/u,
  );
});

test("only canonical ECDSA P-256 DER SPKI public keys validate", async () => {
  const key = await publicKey();
  assert.equal(await validatePublicKey(key), key);
  for (const value of ["", "not-base64url", "AA==", encodeBase64Url(new Uint8Array([1, 2, 3]))]) {
    await assert.rejects(validatePublicKey(value));
  }
  const p384 = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
  const p384Spki = encodeBase64Url(new Uint8Array(await crypto.subtle.exportKey("spki", p384.publicKey)));
  await assert.rejects(validatePublicKey(p384Spki), /ECDSA P-256/u);
});

test("save and reload persist exactly the bounded public settings record", async () => {
  const storage = new MemoryStorage();
  const key = await publicKey();
  const saved = await saveSettings({
    version: 1,
    publicKey: key,
    suffix: " TailNet.Example.Net ",
    acceptedPrefixes: ["Workstation", "laptop"],
  }, storage);

  assert.deepEqual(saved, {
    version: 1,
    publicKey: key,
    suffix: "tailnet.example.net",
    acceptedPrefixes: ["workstation", "laptop"],
  });
  assert.deepEqual([...storage.values.keys()], [SETTINGS_STORAGE_KEY]);
  const serialized = storage.getItem(SETTINGS_STORAGE_KEY);
  assert.ok(new TextEncoder().encode(serialized).byteLength <= MAX_SETTINGS_BYTES);
  assert.deepEqual(Object.keys(JSON.parse(serialized)).sort(), ["acceptedPrefixes", "publicKey", "suffix", "version"]);
  for (const forbidden of ["plaintext", "ciphertext", "prf", "derivedKey", "assertion", "handoff", "certificatePin", "requestId"]) {
    assert.equal(Object.hasOwn(JSON.parse(serialized), forbidden), false);
  }

  const loaded = await loadSettings(storage);
  assert.equal(loaded.status, "ok");
  assert.deepEqual(loaded.settings, saved);
  resetSettings(storage);
  assert.equal(storage.getItem(SETTINGS_STORAGE_KEY), null);
  assert.deepEqual((await loadSettings(storage)).settings, emptySettings());
});

test("settings validation rejects unsupported, noncanonical, duplicate, oversized and excessive records", async () => {
  const storage = new MemoryStorage();
  const key = await publicKey();
  for (const record of [
    { version: 2, publicKey: null, suffix: "example.net", acceptedPrefixes: [] },
    { version: 1, publicKey: null, suffix: "Example.net", acceptedPrefixes: [] },
    { version: 1, publicKey: null, suffix: "example.net", acceptedPrefixes: ["Laptop"] },
    { version: 1, publicKey: null, suffix: "example.net", acceptedPrefixes: ["laptop", "laptop"] },
    { version: 1, publicKey: null, suffix: "example.net", acceptedPrefixes: ["a".repeat(64)] },
    { version: 1, publicKey: null, suffix: "example.net", acceptedPrefixes: Array(MAX_ACCEPTED_PREFIXES + 1).fill("laptop") },
    { version: 1, publicKey: key, suffix: "example.net", acceptedPrefixes: [], extra: "field" },
  ]) {
    storage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(record));
    const loaded = await loadSettings(storage);
    assert.equal(loaded.status, "invalid");
    assert.notEqual(storage.getItem(SETTINGS_STORAGE_KEY), null, "invalid records are not overwritten");
  }

  storage.setItem(SETTINGS_STORAGE_KEY, "{" + " ".repeat(MAX_SETTINGS_BYTES) + "}");
  assert.equal((await loadSettings(storage)).status, "invalid");
});

test("storage denial and quota failures are surfaced without losing the page-only settings", async () => {
  const denied = {
    getItem() { throw new DOMException("denied", "SecurityError"); },
    setItem() { throw new DOMException("quota", "QuotaExceededError"); },
    removeItem() { throw new DOMException("denied", "SecurityError"); },
  };
  assert.equal((await loadSettings(denied)).status, "unavailable");
  await assert.rejects(saveSettings({ ...emptySettings(), suffix: "example.net" }, denied), /quota/u);
  assert.throws(() => resetSettings(denied), /denied/u);
});
