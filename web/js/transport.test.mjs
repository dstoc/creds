import assert from "node:assert/strict";
import test from "node:test";

import { encodeBase64Url } from "./encoding.mjs";
import { testPinnedEcho } from "./transport.mjs";

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
