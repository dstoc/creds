import { decodeBase64Url } from "./encoding.mjs";

const PROBE_MESSAGE = new TextEncoder().encode("creds-browser-transport-probe-v1");

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
