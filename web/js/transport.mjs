import { decodeBase64Url, encodeBase64Url } from "./encoding.mjs";
import { validateName, validateRevision } from "./envelope.mjs";

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
    /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/u.test(configuredDnsSuffix)
  ) {
    throw new TypeError("The configured machine DNS suffix is invalid.");
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
  const fullHostname = `${host}.${configuredDnsSuffix}`;
  if (fullHostname.length > 253) throw new TypeError("The handoff hostname is too long.");
  if (!/^[1-9][0-9]{0,4}$/u.test(portText)) throw new TypeError("The handoff port is invalid.");
  const port = Number(portText);
  if (port > 65535) throw new TypeError("The handoff port must be from 1 through 65535.");
  const certificatePin = decodeBase64Url(certificateHash);
  const requestBytes = decodeBase64Url(requestId);
  if (certificatePin.byteLength !== 32) throw new TypeError("The SHA-256 certificate hash must be 32 bytes.");
  if (requestBytes.byteLength !== 32) throw new TypeError("The request identifier must be 32 bytes.");
  return Object.freeze({
    host,
    fullHostname,
    port,
    certificateHash,
    certificatePin,
    requestId,
    requestBytes,
    endpoint: `https://${fullHostname}:${port}/key`,
  });
}

export function parseRequestMessage(bytes, requestBytes) {
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_FRAME_BYTES) {
    throw new TypeError("The CLI request is empty or exceeds 16 KiB.");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  let request;
  try {
    request = JSON.parse(text);
  } catch {
    throw new TypeError("The CLI request is not valid JSON.");
  }
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    throw new TypeError("The CLI request must be a JSON object.");
  }
  const fields = ["type", "version", "name", "revision", "operation", "challenge", "approvalTimeoutMs"];
  if (Object.keys(request).length !== fields.length || fields.some((field) => !Object.hasOwn(request, field))) {
    throw new TypeError("The CLI request fields do not match protocol version 1.");
  }
  const fieldTypes = {
    type: "string",
    version: "number",
    name: "string",
    revision: "number",
    operation: "string",
    challenge: "string",
    approvalTimeoutMs: "number",
  };
  for (const [field, expectedType] of Object.entries(fieldTypes)) {
    if (typeof request[field] !== expectedType) {
      throw new TypeError(`The CLI request ${field} must be a ${expectedType}.`);
    }
  }
  if (request.type !== "request" || request.version !== 1) {
    throw new TypeError("The CLI request type and version must be request and 1.");
  }
  validateName(request.name);
  validateRevision(request.revision);
  if (request.operation !== "encrypt" && request.operation !== "decrypt") {
    throw new TypeError("The CLI request operation must be encrypt or decrypt.");
  }
  if (!Number.isSafeInteger(request.approvalTimeoutMs) || request.approvalTimeoutMs < 1 || request.approvalTimeoutMs > 120_000) {
    throw new TypeError("The CLI approval time must be from 1 through 120000 milliseconds.");
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
    approvalTimeoutMs: request.approvalTimeoutMs,
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
