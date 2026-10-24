import assert from "node:assert/strict";
import test from "node:test";

import { decodeBase64Url, encodeBase64Url } from "./encoding.mjs";
import {
  connectHandoff,
  encodeFrame,
  parseHandoffFragment,
  parseRequestMessage,
  testMismatchedPin,
  testPinnedEcho,
} from "./transport.mjs";

const MESSAGE = new TextEncoder().encode("creds-browser-transport-probe-v1");
const PIN = encodeBase64Url(new Uint8Array(32));
const ENDPOINT = "https://127.0.0.1:4443/key";

async function withWebTransportChunks(chunks, run) {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "WebTransport");
  globalThis.WebTransport = class {
    constructor() {
      this.ready = Promise.resolve();
    }

    async createBidirectionalStream() {
      return {
        writable: {
          getWriter: () => ({
            write: async () => {},
            close: async () => {},
          }),
        },
        readable: new ReadableStream({
          start(controller) {
            for (const chunk of chunks) controller.enqueue(chunk);
            controller.close();
          },
        }),
      };
    }

    close() {}
  };

  try {
    return await run();
  } finally {
    if (originalDescriptor) {
      Object.defineProperty(globalThis, "WebTransport", originalDescriptor);
    } else {
      delete globalThis.WebTransport;
    }
  }
}

test("pinned echo accepts the complete response across multiple reads", async () => {
  await withWebTransportChunks([MESSAGE.slice(0, 10), MESSAGE.slice(10)], async () => {
    assert.deepEqual(await testPinnedEcho(ENDPOINT, PIN), {
      matchedPin: true,
      echoMatched: true,
    });
  });
});

test("pinned echo rejects a response truncated at EOF", async () => {
  await withWebTransportChunks([MESSAGE.slice(0, -1)], async () => {
    await assert.rejects(testPinnedEcho(ENDPOINT, PIN), /truncated echo/u);
  });
});

test("pinned echo rejects response data beyond the expected message", async () => {
  const extraByte = Uint8Array.of(0);
  await withWebTransportChunks([MESSAGE, extraByte], async () => {
    await assert.rejects(testPinnedEcho(ENDPOINT, PIN), /extra probe data/u);
  });
});

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
}));

test("handoff fragment validates the version, DNS label, port, pin, and request", () => {
  const handoff = parseHandoffFragment(
    `#v=1&host=workstation&port=8443&cert=${pinText}&request=${requestText}`,
    { protocol: "https:", hostname: "keys.example" },
  );
  assert.equal(handoff.endpoint, "https://workstation.keys.example:8443/key");
  assert.equal(handoff.fullHostname, "workstation.keys.example");
  assert.deepEqual(handoff.certificatePin, decodeBase64Url(pinText));

  for (const fragment of [
    `#v=2&host=workstation&port=8443&cert=${pinText}&request=${requestText}`,
    `#v=1&host=bad.example&port=8443&cert=${pinText}&request=${requestText}`,
    `#v=1&host=workstation&port=0&cert=${pinText}&request=${requestText}`,
    `#v=1&host=workstation&port=65536&cert=${pinText}&request=${requestText}`,
    `#v=1&host=workstation&port=8443&cert=${pinText}&cert=${pinText}&request=${requestText}`,
    `#v=1&host=workstation&port=8443&cert=${pinText}&request=${requestText}&url=https://evil.example`,
  ]) {
    assert.throws(() => parseHandoffFragment(fragment, { protocol: "https:", hostname: "keys.example" }));
  }
  assert.throws(() => parseHandoffFragment(
    `#v=1&host=workstation&port=8443&cert=${pinText}&request=${requestText}`,
    { protocol: "http:", hostname: "localhost" },
  ), /HTTPS/u);
});

test("request parser rejects duplicate, unknown, cross-purpose, and malformed fields", () => {
  const parsed = parseRequestMessage(requestBody, requestBytes);
  assert.equal(parsed.name, "secret-x");
  assert.equal(parsed.revision, 2);
  assert.equal(parsed.operation, "decrypt");

  const good = JSON.parse(new TextDecoder().decode(requestBody));
  const duplicate = new TextEncoder().encode(
    `{"type":"request","version":1,"name":"secret-x","na\\u006de":"other","revision":2,"operation":"decrypt","challenge":"${encodeBase64Url(challengeBytes)}"}`,
  );
  assert.throws(() => parseRequestMessage(duplicate, requestBytes), /Duplicate JSON field name/u);
  assert.throws(() => parseRequestMessage(new TextEncoder().encode(JSON.stringify({ ...good, extra: true })), requestBytes), /fields/u);
  assert.throws(() => parseRequestMessage(requestBody, challengeBytes), /distinct/u);
  assert.throws(() => parseRequestMessage(new Uint8Array(0), requestBytes), /empty/u);
  assert.throws(() => parseRequestMessage(new Uint8Array(16 * 1024 + 1), requestBytes), /16 KiB/u);
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
  let options;
  let readableController;
  const writes = [];
  class FakeWebTransport {
    constructor(_url, transportOptions) {
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
    const handoff = parseHandoffFragment(
      `#v=1&host=workstation&port=8443&cert=${pinText}&request=${requestText}`,
      { protocol: "https:", hostname: "keys.example" },
    );
    const session = await connectHandoff(handoff);
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

test("a rejected certificate pin is a terminal connection failure", async () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "WebTransport");
  let options;
  class RejectingWebTransport {
    constructor(_url, transportOptions) {
      options = transportOptions;
      this.ready = Promise.reject(new Error("certificate pin mismatch"));
    }

    close() {}
  }
  globalThis.WebTransport = RejectingWebTransport;
  try {
    const outcome = await testMismatchedPin("https://127.0.0.1:4443/key", pinText);
    assert.equal(outcome.mismatchRejected, true);
    const sentPin = options.serverCertificateHashes[0].value;
    assert.equal(sentPin.byteLength, 32);
    assert.notDeepEqual(sentPin, decodeBase64Url(pinText));
  } finally {
    if (originalDescriptor) Object.defineProperty(globalThis, "WebTransport", originalDescriptor);
    else delete globalThis.WebTransport;
  }
});
