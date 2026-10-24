import assert from "node:assert/strict";
import test from "node:test";

import { testMismatchedPin, testPinnedEcho } from "./transport-probe.mjs";

const MESSAGE = new TextEncoder().encode("creds-browser-transport-probe-v1");
const PIN = btoa(String.fromCharCode(...new Uint8Array(32))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
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
    if (originalDescriptor) Object.defineProperty(globalThis, "WebTransport", originalDescriptor);
    else delete globalThis.WebTransport;
  }
}

test("development echo probe validates the complete response across stream chunks", async () => {
  await withWebTransportChunks([MESSAGE.slice(0, 10), MESSAGE.slice(10)], async () => {
    assert.deepEqual(await testPinnedEcho(ENDPOINT, PIN), {
      matchedPin: true,
      echoMatched: true,
    });
  });
});

test("development echo probe rejects truncated and extra response data", async () => {
  await withWebTransportChunks([MESSAGE.slice(0, -1)], async () => {
    await assert.rejects(testPinnedEcho(ENDPOINT, PIN), /truncated echo/u);
  });
  await withWebTransportChunks([MESSAGE, Uint8Array.of(0)], async () => {
    await assert.rejects(testPinnedEcho(ENDPOINT, PIN), /extra probe data/u);
  });
});

test("development mismatch probe flips a pin bit and reports rejection", async () => {
  const originalDescriptor = Object.getOwnPropertyDescriptor(globalThis, "WebTransport");
  let options;
  globalThis.WebTransport = class {
    constructor(_url, transportOptions) {
      options = transportOptions;
      this.ready = new Promise(() => {});
      this.closed = Promise.reject(new Error("certificate pin mismatch"));
    }

    close() {}
  };
  try {
    const outcome = await testMismatchedPin(ENDPOINT, PIN);
    assert.equal(outcome.mismatchRejected, true);
    const sentPin = options.serverCertificateHashes[0].value;
    assert.equal(sentPin.byteLength, 32);
    assert.equal(sentPin[0], 1);
  } finally {
    if (originalDescriptor) Object.defineProperty(globalThis, "WebTransport", originalDescriptor);
    else delete globalThis.WebTransport;
  }
});
