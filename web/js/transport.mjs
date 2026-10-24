import { decodeBase64Url, encodeBase64Url } from "./encoding.mjs";
import { validateName, validateRevision } from "./envelope.mjs";

const PROBE_MESSAGE = new TextEncoder().encode("creds-browser-transport-probe-v1");
const MAX_FRAME_BYTES = 16 * 1024;

function oneParameter(params, name) {
  const values = params.getAll(name);
  if (values.length !== 1) throw new TypeError(`The handoff URL must contain one ${name} value.`);
  return values[0];
}

export function parseHandoffFragment(fragment, pageLocation = globalThis.location, configuredDnsSuffix) {
  if (pageLocation?.protocol !== "https:") throw new TypeError("The creds approval page must use HTTPS.");
  if (
    typeof configuredDnsSuffix !== "string" ||
    configuredDnsSuffix.length > 253 ||
    configuredDnsSuffix !== configuredDnsSuffix.toLowerCase() ||
    !configuredDnsSuffix.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label)) ||
    /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/u.test(configuredDnsSuffix) ||
    pageLocation.hostname !== configuredDnsSuffix
  ) {
    throw new TypeError("The approval page hostname must match its configured DNS suffix.");
  }
  const params = new URLSearchParams(fragment.startsWith("#") ? fragment.slice(1) : fragment);
  const allowed = new Set(["v", "host", "port", "cert", "request"]);
  for (const name of params.keys()) {
    if (!allowed.has(name)) throw new TypeError(`The handoff URL contains an unknown ${name} field.`);
  }

  const version = oneParameter(params, "v");
  const host = oneParameter(params, "host");
  const portText = oneParameter(params, "port");
  const certificateHash = oneParameter(params, "cert");
  const requestId = oneParameter(params, "request");
  if (version !== "1") throw new TypeError("The handoff URL version must be 1.");
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/u.test(host)) {
    throw new TypeError("The handoff host must be one DNS label.");
  }
  if (!/^[1-9][0-9]{0,4}$/u.test(portText)) throw new TypeError("The handoff port is invalid.");
  const port = Number(portText);
  if (port > 65535) throw new TypeError("The handoff port must be from 1 through 65535.");
  const certificatePin = decodeBase64Url(certificateHash);
  const requestBytes = decodeBase64Url(requestId);
  if (certificatePin.byteLength !== 32) throw new TypeError("The SHA-256 certificate hash must be 32 bytes.");
  if (requestBytes.byteLength !== 32) throw new TypeError("The request identifier must be 32 bytes.");
  return Object.freeze({
    host,
    fullHostname: `${host}.${configuredDnsSuffix}`,
    port,
    certificateHash,
    certificatePin,
    requestId,
    requestBytes,
    endpoint: `https://${host}.${configuredDnsSuffix}:${port}/key`,
  });
}

function scanJsonForDuplicateKeys(source) {
  let offset = 0;
  const whitespace = () => {
    while ([" ", "\t", "\r", "\n"].includes(source[offset])) offset += 1;
  };
  const parseString = () => {
    const start = offset;
    if (source[offset] !== '"') throw new TypeError("Expected a JSON string.");
    offset += 1;
    while (offset < source.length) {
      const character = source[offset];
      if (character === '"') {
        offset += 1;
        return JSON.parse(source.slice(start, offset));
      }
      if (character === "\\") {
        offset += 2;
      } else {
        if (character.charCodeAt(0) < 0x20) throw new TypeError("Invalid JSON string.");
        offset += 1;
      }
    }
    throw new TypeError("Unterminated JSON string.");
  };
  const parseValue = (depth) => {
    if (depth > 16) throw new TypeError("The request JSON is too deeply nested.");
    whitespace();
    if (source[offset] === "{") {
      offset += 1;
      whitespace();
      const names = new Set();
      if (source[offset] === "}") {
        offset += 1;
        return;
      }
      while (offset < source.length) {
        whitespace();
        const name = parseString();
        if (names.has(name)) throw new TypeError(`Duplicate JSON field ${name}.`);
        names.add(name);
        whitespace();
        if (source[offset] !== ":") throw new TypeError("Expected a JSON colon.");
        offset += 1;
        parseValue(depth + 1);
        whitespace();
        if (source[offset] === "}") {
          offset += 1;
          return;
        }
        if (source[offset] !== ",") throw new TypeError("Expected a JSON object separator.");
        offset += 1;
      }
      throw new TypeError("Unterminated JSON object.");
    }
    if (source[offset] === "[") {
      offset += 1;
      whitespace();
      if (source[offset] === "]") {
        offset += 1;
        return;
      }
      while (offset < source.length) {
        parseValue(depth + 1);
        whitespace();
        if (source[offset] === "]") {
          offset += 1;
          return;
        }
        if (source[offset] !== ",") throw new TypeError("Expected a JSON array separator.");
        offset += 1;
      }
      throw new TypeError("Unterminated JSON array.");
    }
    if (source[offset] === '"') {
      parseString();
      return;
    }
    const start = offset;
    while (offset < source.length && ![",", "]", "}", " ", "\t", "\r", "\n"].includes(source[offset])) offset += 1;
    if (offset === start) throw new TypeError("Invalid JSON value.");
  };

  parseValue(0);
  whitespace();
  if (offset !== source.length) throw new TypeError("Unexpected data after request JSON.");
  return JSON.parse(source);
}

export function parseRequestMessage(bytes, requestBytes) {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_FRAME_BYTES) {
    throw new TypeError("The CLI request is empty or exceeds 16 KiB.");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const request = scanJsonForDuplicateKeys(text);
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    throw new TypeError("The CLI request must be a JSON object.");
  }
  const fields = ["type", "version", "name", "revision", "operation", "challenge"];
  if (Object.keys(request).length !== fields.length || fields.some((field) => !Object.hasOwn(request, field))) {
    throw new TypeError("The CLI request fields do not match protocol version 1.");
  }
  if (request.type !== "request" || request.version !== 1) {
    throw new TypeError("The CLI request type and version must be request and 1.");
  }
  validateName(request.name);
  validateRevision(request.revision);
  if (request.operation !== "encrypt" && request.operation !== "decrypt") {
    throw new TypeError("The CLI request operation must be encrypt or decrypt.");
  }
  const challenge = decodeBase64Url(request.challenge);
  if (challenge.byteLength !== 32) throw new TypeError("The WebAuthn challenge must be 32 bytes.");
  if (challenge.every((byte, index) => byte === requestBytes[index])) {
    throw new TypeError("The request identifier and WebAuthn challenge must be distinct.");
  }
  return Object.freeze({
    name: request.name,
    revision: request.revision,
    operation: request.operation,
    challenge,
    challengeText: request.challenge,
  });
}

class FrameReader {
  constructor(reader) {
    this.reader = reader;
    this.pending = new Uint8Array();
  }

  async readExact(length) {
    const result = new Uint8Array(length);
    let written = 0;
    while (written < length) {
      if (this.pending.length === 0) {
        const { value, done } = await this.reader.read();
        if (done) throw new Error("The CLI closed the WebTransport stream unexpectedly.");
        if (!(value instanceof Uint8Array) || value.byteLength === 0) continue;
        this.pending = value;
      }
      const copied = Math.min(length - written, this.pending.byteLength);
      result.set(this.pending.subarray(0, copied), written);
      written += copied;
      this.pending = this.pending.subarray(copied);
    }
    return result;
  }

  async readFrame() {
    const header = await this.readExact(4);
    const length = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(0, false);
    if (length < 1 || length > MAX_FRAME_BYTES) throw new Error("The CLI frame length must be from 1 through 16 KiB.");
    return this.readExact(length);
  }

  async rejectExtraData() {
    if (this.pending.byteLength > 0) throw new Error("The CLI sent extra data after its request message.");
    const { done } = await this.reader.read();
    if (!done) throw new Error("The CLI sent extra data after its request message.");
  }
}

export function encodeFrame(body) {
  if (!(body instanceof Uint8Array) || body.byteLength < 1 || body.byteLength > MAX_FRAME_BYTES) {
    throw new TypeError("A protocol frame must contain from 1 through 16 KiB.");
  }
  const frame = new Uint8Array(4 + body.byteLength);
  new DataView(frame.buffer).setUint32(0, body.byteLength, false);
  frame.set(body, 4);
  return frame;
}

function encodeAssertionField(value, name) {
  const bytes = value instanceof Uint8Array
    ? value
    : value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : null;
  if (!bytes || bytes.byteLength < 1 || bytes.byteLength > 4096) {
    throw new TypeError(`${name} must contain from 1 through 4 KiB.`);
  }
  return encodeBase64Url(bytes);
}

export async function connectHandoff(handoff, signal) {
  if (!("WebTransport" in globalThis)) throw new Error("This browser does not expose WebTransport.");
  const transport = new WebTransport(handoff.endpoint, {
    serverCertificateHashes: [{ algorithm: "sha-256", value: handoff.certificatePin }],
  });
  let active = true;
  let failure = null;
  let resolveFailure;
  const failed = new Promise((resolve) => { resolveFailure = resolve; });
  const setFailure = (error) => {
    if (!failure) failure = error;
    active = false;
    transport.close();
    resolveFailure(failure);
  };
  const closeOnAbort = () => {
    active = false;
    transport.close();
  };
  if (signal?.aborted) closeOnAbort();
  else signal?.addEventListener("abort", closeOnAbort, { once: true });
  transport.closed.then(
    () => { if (active) setFailure(new Error("The CLI closed the approval session.")); },
    (error) => { if (active) setFailure(error instanceof Error ? error : new Error(String(error))); },
  );
  for (const streams of [transport.incomingBidirectionalStreams, transport.incomingUnidirectionalStreams]) {
    const reader = streams?.getReader?.();
    if (reader) {
      reader.read().then(({ done }) => {
        if (!done) setFailure(new Error("The CLI opened an unexpected additional stream."));
      }).catch((error) => setFailure(error instanceof Error ? error : new Error(String(error))));
    }
  }

  try {
    await transport.ready;
    const stream = await transport.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    const frameReader = new FrameReader(stream.readable.getReader());
    const hello = new TextEncoder().encode(JSON.stringify({ type: "hello", version: 1, request: handoff.requestId }));
    await writer.write(encodeFrame(hello));
    const request = parseRequestMessage(await frameReader.readFrame(), handoff.requestBytes);
    const extraData = frameReader.rejectExtraData().catch((error) => setFailure(error));

    return {
      request,
      transport,
      failed,
      isActive() { return active && !failure; },
      failure() { return failure; },
      async sendKey(keyBytes, assertion) {
        if (!active || failure) throw failure ?? new Error("The CLI approval session is closed.");
        if (!(keyBytes instanceof Uint8Array) || keyBytes.byteLength !== 32) {
          throw new TypeError("The encryption key must contain exactly 32 bytes.");
        }
        const message = {
          type: "key",
          version: 1,
          key: encodeBase64Url(keyBytes),
          assertion: {
            clientDataJSON: encodeAssertionField(assertion.clientDataJSON, "clientDataJSON"),
            authenticatorData: encodeAssertionField(assertion.authenticatorData, "authenticatorData"),
            signature: encodeAssertionField(assertion.signature, "signature"),
          },
        };
        let serialized = "";
        let body;
        let frame;
        try {
          serialized = JSON.stringify(message);
          body = new TextEncoder().encode(serialized);
          serialized = "";
          message.key = "";
          frame = encodeFrame(body);
          await writer.write(frame);
          await writer.close();
          active = false;
          transport.close();
          await extraData;
          if (failure) throw failure;
        } catch (error) {
          setFailure(error instanceof Error ? error : new Error(String(error)));
          throw error;
        } finally {
          serialized = "";
          message.key = "";
          body?.fill(0);
          frame?.fill(0);
        }
      },
      close() {
        active = false;
        transport.close();
      },
    };
  } catch (error) {
    active = false;
    transport.close();
    throw error;
  } finally {
    signal?.removeEventListener("abort", closeOnAbort);
  }
}

function validateEndpoint(value) {
  const endpoint = new URL(value);
  if (
    endpoint.protocol !== "https:" ||
    endpoint.hostname !== "127.0.0.1" ||
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    endpoint.pathname !== "/key" ||
    endpoint.search !== "" ||
    endpoint.hash !== ""
  ) {
    throw new TypeError("Use the printed https://127.0.0.1:<port>/key probe URL.");
  }
  return endpoint.href;
}
function validatedHash(value) {
  const hash = decodeBase64Url(value);
  if (hash.byteLength !== 32) throw new TypeError("The SHA-256 certificate hash must be 32 bytes.");
  return hash;
}

export async function testPinnedEcho(endpointValue, hashValue) {
  if (!("WebTransport" in globalThis)) throw new Error("This browser does not expose WebTransport.");
  const endpoint = validateEndpoint(endpointValue);
  const pin = validatedHash(hashValue);
  const transport = new WebTransport(endpoint, {
    serverCertificateHashes: [{ algorithm: "sha-256", value: pin }],
  });
  try {
    await transport.ready;
    const stream = await transport.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    await writer.write(PROBE_MESSAGE);
    await writer.close();

    const reader = stream.readable.getReader();
    const echo = new Uint8Array(PROBE_MESSAGE.byteLength);
    let offset = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value.byteLength > echo.byteLength - offset) {
          throw new Error("The Rust listener returned extra probe data.");
        }
        echo.set(value, offset);
        offset += value.byteLength;
      }
    } finally {
      reader.releaseLock();
    }
    if (offset !== PROBE_MESSAGE.byteLength) {
      throw new Error("The Rust listener returned a truncated echo.");
    }
    const matches = PROBE_MESSAGE.every((byte, index) => echo[index] === byte);
    if (!matches) throw new Error("The Rust listener returned an unexpected echo.");
    transport.close();
    return { matchedPin: true, echoMatched: true };
  } catch (error) {
    transport.close();
    throw error;
  }
}

export async function testMismatchedPin(endpointValue, hashValue) {
  if (!("WebTransport" in globalThis)) throw new Error("This browser does not expose WebTransport.");
  const endpoint = validateEndpoint(endpointValue);
  const mismatchedPin = validatedHash(hashValue);
  mismatchedPin[0] ^= 1;

  let transport;
  try {
    transport = new WebTransport(endpoint, {
      serverCertificateHashes: [{ algorithm: "sha-256", value: mismatchedPin }],
    });
    await transport.ready;
    transport.close();
    return { mismatchRejected: false };
  } catch (error) {
    transport?.close();
    return { mismatchRejected: true, error: error instanceof Error ? `${error.name}: ${error.message}` : String(error) };
  }
}
