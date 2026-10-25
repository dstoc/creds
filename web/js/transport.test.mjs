import assert from "node:assert/strict";
import test from "node:test";

import { decodeBase64Url, encodeBase64Url } from "./encoding.mjs";
import {
  buildHandoffDestination,
  connectHandoff,
  encodeFrame,
  parseHandoffFragment,
  parseRequestMessage,
} from "./transport.mjs";

const PIN = encodeBase64Url(new Uint8Array(32));

const requestBytes = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const challengeBytes = Uint8Array.from({ length: 32 }, (_, index) => index + 65);
const pinText = encodeBase64Url(Uint8Array.from({ length: 32 }, (_, index) => index + 129));
const requestText = encodeBase64Url(requestBytes);
const requestBody = new TextEncoder().encode(JSON.stringify({
  type: "request",
  version: 1,
  name: "secret-x",
  revision: 2,
  operation: "decrypt",
  challenge: encodeBase64Url(challengeBytes),
  approvalTimeoutMs: 120_000,
}));

test("handoff parsing captures QR fields and builds a validated DNS destination separately", () => {
  const parsed = parseHandoffFragment(
    `#v=1&host=workstation&port=8443&cert=${pinText}&request=${requestText}`,
    { protocol: "https:", hostname: "approval.example.com" },
  );
  const handoff = buildHandoffDestination(parsed, "tailnet.example.net");
  assert.equal(handoff.endpoint, "https://workstation.tailnet.example.net:8443/key");
  assert.equal(handoff.fullHostname, "workstation.tailnet.example.net");
  assert.deepEqual(handoff.certificatePin, decodeBase64Url(pinText));
  const caseVariant = buildHandoffDestination(parseHandoffFragment(
    `#v=1&host=WorkStation&port=8443&cert=${pinText}&request=${requestText}`,
    { protocol: "https:", hostname: "approval.example.com" },
  ), "TailNet.Example.Net");
  assert.equal(caseVariant.prefix, "workstation");
  assert.equal(caseVariant.suffix, "tailnet.example.net");
  assert.equal(caseVariant.fullHostname, handoff.fullHostname);

  for (const fragment of [
    `#v=2&host=workstation&port=8443&cert=${pinText}&request=${requestText}`,
    `#v=1&host=bad.example&port=8443&cert=${pinText}&request=${requestText}`,
    `#v=1&host=workstation&port=0&cert=${pinText}&request=${requestText}`,
    `#v=1&host=workstation&port=65536&cert=${pinText}&request=${requestText}`,
    `#v=1&host=workstation&port=8443&cert=${pinText}&cert=${pinText}&request=${requestText}`,
    `#v=1&host=workstation&port=8443&cert=${pinText}&request=${requestText}&url=https://evil.example`,
    `#v=1&host=workstation&port=8443&cert=${pinText}&request=${requestText}&destination=https://evil.example`,
    `#v=1&host=workstation&port=8443&cert=${pinText}&request=${requestText}&suffix=evil.example`,
    `#v=1&host=workstation&port=8443&cert=${pinText}&request=${requestText}&path=/evil`,
  ]) {
    assert.throws(() => parseHandoffFragment(
      fragment,
      { protocol: "https:", hostname: "approval.example.com" },
    ));
  }
  assert.throws(() => parseHandoffFragment(
    `#v=1&host=workstation&port=8443&cert=${pinText}&request=${requestText}`,
    { protocol: "http:", hostname: "localhost" },
  ), /HTTPS/u);

  for (const suffix of [
    "",
    ".tailnet.example",
    "tailnet..example",
    "tailnet.example.",
    "-tailnet.example",
    "tailnet-.example",
    "tailnet.example/path",
    "tailnet.example:443",
    "123.456.789.012",
    `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}`,
  ]) {
    assert.throws(() => buildHandoffDestination(parsed, suffix), `accepted malformed machine DNS suffix ${JSON.stringify(suffix)}`);
  }

  const longPrefix = "a".repeat(63);
  const tooLongDestination = parseHandoffFragment(
    `#v=1&host=${longPrefix}&port=8443&cert=${pinText}&request=${requestText}`,
    { protocol: "https:", hostname: "approval.example.com" },
  );
  assert.throws(() => buildHandoffDestination(
    tooLongDestination,
    `${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.e`,
  ), /hostname is too long/u);
});

test("request parser validates JSON, shape, fields, types, and protocol values", () => {
  const parsed = parseRequestMessage(requestBody, requestBytes);
  assert.equal(parsed.name, "secret-x");
  assert.equal(parsed.revision, 2);
  assert.equal(parsed.operation, "decrypt");
  const shorterWindow = parseRequestMessage(
    new TextEncoder().encode(JSON.stringify({ ...JSON.parse(new TextDecoder().decode(requestBody)), approvalTimeoutMs: 90_000 })),
    requestBytes,
  );
  assert.equal(shorterWindow.approvalTimeoutMs, 90_000);

  const good = JSON.parse(new TextDecoder().decode(requestBody));
  const encode = (request) => new TextEncoder().encode(typeof request === "string" ? request : JSON.stringify(request));
  assert.throws(() => parseRequestMessage(encode('{"type":'), requestBytes), /not valid JSON/u);
  for (const shape of ["null", "[]", '"request"', "1", "true"]) {
    assert.throws(() => parseRequestMessage(encode(shape), requestBytes), /JSON object/u);
  }

  assert.throws(() => parseRequestMessage(encode(Object.fromEntries(Object.entries(good).filter(([field]) => field !== "name"))), requestBytes), /fields/u);
  assert.throws(() => parseRequestMessage(new TextEncoder().encode(JSON.stringify({ ...good, extra: true })), requestBytes), /fields/u);
  for (const [field, value] of [
    ["type", 1],
    ["version", "1"],
    ["name", null],
    ["revision", "2"],
    ["operation", false],
    ["challenge", null],
    ["approvalTimeoutMs", "120000"],
  ]) {
    assert.throws(() => parseRequestMessage(encode({ ...good, [field]: value }), requestBytes), new RegExp(`${field} must be a`, "u"));
  }

  assert.throws(() => parseRequestMessage(encode({ ...good, type: "hello" }), requestBytes), /type and version/u);
  assert.throws(() => parseRequestMessage(encode({ ...good, version: 2 }), requestBytes), /type and version/u);
  assert.throws(() => parseRequestMessage(encode({ ...good, name: "bad name" }), requestBytes), /Name/u);
  assert.throws(() => parseRequestMessage(encode({ ...good, revision: 0 }), requestBytes), /Revision/u);
  assert.throws(() => parseRequestMessage(encode({ ...good, operation: "setup" }), requestBytes), /operation must be encrypt or decrypt/u);
  assert.throws(() => parseRequestMessage(new TextEncoder().encode(JSON.stringify({ ...good, approvalTimeoutMs: 0 })), requestBytes), /1 through 120000/u);
  assert.throws(() => parseRequestMessage(new TextEncoder().encode(JSON.stringify({ ...good, approvalTimeoutMs: 120_001 })), requestBytes), /1 through 120000/u);
  assert.throws(() => parseRequestMessage(encode({ ...good, challenge: "not-base64url" }), requestBytes));
  assert.throws(() => parseRequestMessage(encode({ ...good, challenge: encodeBase64Url(new Uint8Array(31)) }), requestBytes), /challenge must be 32 bytes/u);
  assert.throws(() => parseRequestMessage(requestBody, challengeBytes), /distinct/u);
  assert.throws(() => parseRequestMessage(new Uint8Array(0), requestBytes), /empty/u);
  assert.throws(() => parseRequestMessage(new Uint8Array(16 * 1024 + 1), requestBytes), /16 KiB/u);
});

test("request parser follows JSON.parse last-value behavior for duplicate members", () => {
  const duplicateName = new TextEncoder().encode(
    `{"type":"request","version":1,"name":"other","na\\u006de":"secret-x","revision":2,"operation":"decrypt","challenge":"${encodeBase64Url(challengeBytes)}","approvalTimeoutMs":120000}`,
  );
  assert.equal(parseRequestMessage(duplicateName, requestBytes).name, "secret-x");
});

test("length-prefixed frames use a four-byte unsigned big-endian size and enforce bounds", () => {
  const frame = encodeFrame(Uint8Array.of(1, 2, 3));
  assert.deepEqual(frame, Uint8Array.of(0, 0, 0, 3, 1, 2, 3));
  assert.throws(() => encodeFrame(new Uint8Array(0)), /1 through 16 KiB/u);
  assert.throws(() => encodeFrame(new Uint8Array(16 * 1024 + 1)), /1 through 16 KiB/u);
});

test("approval opens one stream with the exact certificate pin and handles split request frames", async () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "WebTransport");
  const requestFrame = encodeFrame(requestBody);
  let endpoint;
  let options;
  let readableController;
  const writes = [];
  class FakeWebTransport {
    constructor(url, transportOptions) {
      endpoint = url;
      options = transportOptions;
      this.ready = Promise.resolve();
      this.closed = new Promise(() => {});
      this.incomingBidirectionalStreams = new ReadableStream({ start(controller) { this.controller = controller; } });
      this.incomingUnidirectionalStreams = new ReadableStream({ start(controller) { this.controller = controller; } });
    }

    async createBidirectionalStream() {
      const readable = new ReadableStream({
        start(controller) {
          readableController = controller;
          controller.enqueue(requestFrame.slice(0, 5));
          controller.enqueue(requestFrame.slice(5, 13));
          controller.enqueue(requestFrame.slice(13));
        },
      });
      const writable = new WritableStream({ write(chunk) { writes.push(chunk.slice()); } });
      return { readable, writable };
    }

    close() {
      try { readableController?.close(); } catch {}
    }
  }
  globalThis.WebTransport = FakeWebTransport;
  try {
    const handoff = buildHandoffDestination(parseHandoffFragment(
      `#v=1&host=workstation&port=8443&cert=${pinText}&request=${requestText}`,
      { protocol: "https:", hostname: "approval.example.com" },
    ), "tailnet.example.net");
    const session = await connectHandoff(handoff);
    assert.equal(endpoint, "https://workstation.tailnet.example.net:8443/key");
    assert.equal(session.request.name, "secret-x");
    assert.deepEqual(options.serverCertificateHashes, [{ algorithm: "sha-256", value: handoff.certificatePin }]);
    const key = new Uint8Array(32).fill(0x7a);
    const assertion = {
      clientDataJSON: Uint8Array.of(1).buffer,
      authenticatorData: Uint8Array.of(2).buffer,
      signature: Uint8Array.of(3).buffer,
    };
    await session.sendKey(key, assertion);
    assert.equal(writes.length, 2);
    assert.deepEqual(writes[0].subarray(0, 4), Uint8Array.of(0, 0, 0, writes[0].byteLength - 4));
    const hello = JSON.parse(new TextDecoder().decode(writes[0].subarray(4)));
    assert.deepEqual(hello, { type: "hello", version: 1, request: requestText });
    const response = JSON.parse(new TextDecoder().decode(writes[1].subarray(4)));
    assert.equal(response.type, "key");
    assert.equal(response.key, encodeBase64Url(key));
  } finally {
    if (originalDescriptor) Object.defineProperty(globalThis, "WebTransport", originalDescriptor);
    else delete globalThis.WebTransport;
  }
});
