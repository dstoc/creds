import { decodeBase64Url } from "./encoding.mjs";

export const SETTINGS_STORAGE_KEY = "creds.settings.v1";
export const MAX_SETTINGS_BYTES = 32 * 1024;
export const MAX_ACCEPTED_PREFIXES = 128;

const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const PREFIX_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u;

export function emptySettings() {
  return { version: 1, publicKey: null, suffix: "", acceptedPrefixes: [] };
}

function isIpLiteral(value) {
  if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/u.test(value)) return true;
  try {
    return new URL(`https://${value}/`).hostname.toLowerCase() !== value;
  } catch {
    return /^(?:[0-9]+\.)*[0-9]+$/u.test(value);
  }
}

export function normalizeSuffix(value) {
  if (typeof value !== "string") throw new TypeError("Enter a DNS suffix as text.");
  const suffix = value.trim().toLowerCase();
  if (
    suffix.length === 0 ||
    suffix.length > 253 ||
    !suffix.split(".").every((label) => DNS_LABEL.test(label)) ||
    isIpLiteral(suffix)
  ) {
    throw new TypeError("Enter a DNS suffix without a URL, address, empty label, port, or path.");
  }
  return suffix;
}

export function normalizePrefix(value) {
  if (typeof value !== "string") throw new TypeError("The machine prefix must be text.");
  const prefix = value.trim();
  if (!PREFIX_LABEL.test(prefix)) throw new TypeError("The machine prefix must be one DNS label.");
  return prefix.toLowerCase();
}

export function validateCombinedHostname(prefix, suffix) {
  const normalizedPrefix = normalizePrefix(prefix);
  const normalizedSuffix = normalizeSuffix(suffix);
  const fullHostname = `${normalizedPrefix}.${normalizedSuffix}`;
  if (fullHostname.length > 253) throw new TypeError("The handoff hostname is too long.");
  return Object.freeze({ prefix: normalizedPrefix, suffix: normalizedSuffix, fullHostname });
}

export async function validatePublicKey(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) {
    throw new TypeError("Enter a canonical base64url DER SPKI public key.");
  }
  const der = decodeBase64Url(value);
  if (der.byteLength > 1024) throw new TypeError("The DER SPKI public key is too large.");
  try {
    await globalThis.crypto.subtle.importKey(
      "spki",
      der,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );
  } catch {
    throw new TypeError("The public key is not a valid ECDSA P-256 DER SPKI key.");
  }
  return value;
}

function exactFields(record) {
  const expected = ["version", "publicKey", "suffix", "acceptedPrefixes"];
  return record !== null && typeof record === "object" && !Array.isArray(record)
    && Object.keys(record).length === expected.length
    && expected.every((field) => Object.hasOwn(record, field));
}

export async function validateSettings(record, { requireCanonical = false } = {}) {
  if (!exactFields(record)) throw new TypeError("Browser settings fields are invalid.");
  if (record.version !== 1) throw new TypeError("Browser settings use an unsupported version.");
  if (typeof record.suffix !== "string" || typeof record.publicKey !== "string" && record.publicKey !== null) {
    throw new TypeError("Browser settings values have invalid types.");
  }
  const suffix = record.suffix === "" ? "" : normalizeSuffix(record.suffix);
  if (requireCanonical && record.suffix !== suffix) throw new TypeError("The stored DNS suffix is not canonical.");
  const publicKey = record.publicKey === null ? null : await validatePublicKey(record.publicKey);
  if (!Array.isArray(record.acceptedPrefixes) || record.acceptedPrefixes.length > MAX_ACCEPTED_PREFIXES) {
    throw new TypeError(`Browser settings can contain at most ${MAX_ACCEPTED_PREFIXES} accepted prefixes.`);
  }
  const acceptedPrefixes = record.acceptedPrefixes.map((prefix) => {
    const normalized = normalizePrefix(prefix);
    if (requireCanonical && prefix !== normalized) throw new TypeError("A stored machine prefix is not canonical.");
    if (suffix) validateCombinedHostname(normalized, suffix);
    return normalized;
  });
  if (!suffix && acceptedPrefixes.length > 0) {
    throw new TypeError("Accepted prefixes require a saved DNS suffix.");
  }
  if (new Set(acceptedPrefixes).size !== acceptedPrefixes.length) {
    throw new TypeError("Browser settings contain duplicate machine prefixes.");
  }
  return { version: 1, publicKey, suffix, acceptedPrefixes };
}

function resolveStorage(storage) {
  return storage === undefined ? globalThis.localStorage : storage;
}

export async function loadSettings(storage) {
  let raw;
  try {
    raw = resolveStorage(storage).getItem(SETTINGS_STORAGE_KEY);
  } catch (error) {
    return { status: "unavailable", settings: emptySettings(), error };
  }
  if (raw === null) return { status: "ok", settings: emptySettings(), error: null };
  if (typeof raw !== "string" || new TextEncoder().encode(raw).byteLength > MAX_SETTINGS_BYTES) {
    return { status: "invalid", settings: null, error: new TypeError("Stored browser settings exceed the 32 KiB limit.") };
  }
  try {
    const settings = await validateSettings(JSON.parse(raw), { requireCanonical: true });
    return { status: "ok", settings, error: null };
  } catch (error) {
    return { status: "invalid", settings: null, error };
  }
}

export async function saveSettings(settings, storage) {
  const valid = await validateSettings(settings);
  const serialized = JSON.stringify(valid);
  if (new TextEncoder().encode(serialized).byteLength > MAX_SETTINGS_BYTES) {
    throw new TypeError("Browser settings exceed the 32 KiB limit.");
  }
  resolveStorage(storage).setItem(SETTINGS_STORAGE_KEY, serialized);
  return valid;
}

export function resetSettings(storage) {
  resolveStorage(storage).removeItem(SETTINGS_STORAGE_KEY);
}

