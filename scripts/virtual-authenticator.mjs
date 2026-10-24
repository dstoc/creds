#!/usr/bin/env node

const port = Number.parseInt(process.argv[2] ?? "9222", 10);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new TypeError("Usage: node scripts/virtual-authenticator.mjs [remote-debugging-port]");
}

const version = await fetch(`http://127.0.0.1:${port}/json/version`).then((response) => response.json());
const pages = await fetch(`http://127.0.0.1:${port}/json/list`).then((response) => response.json());
const page = pages.find((target) => target.type === "page");
if (!page?.webSocketDebuggerUrl) throw new Error("No debuggable page target is available.");

const socket = new WebSocket(page.webSocketDebuggerUrl);
const pending = new Map();
let nextId = 0;

socket.addEventListener("message", (event) => {
  const response = JSON.parse(event.data);
  if (!response.id) return;
  const handlers = pending.get(response.id);
  if (!handlers) return;
  pending.delete(response.id);
  if (response.error) handlers.reject(new Error(response.error.message));
  else handlers.resolve(response.result ?? {});
});

await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});

function call(method, params = {}) {
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
}

console.log(`Chromium ${version.Browser}; enabling a temporary CTAP2.1 virtual authenticator.`);
await call("WebAuthn.enable");
const { authenticatorId } = await call("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    ctap2Version: "ctap2_1",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
    hasPrf: true,
  },
});
console.log(`Virtual authenticator ${authenticatorId} is active for page ${page.id}. Press Ctrl-C to remove it.`);

async function stop() {
  try {
    await call("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
    await call("WebAuthn.disable");
  } finally {
    socket.close();
  }
}

process.once("SIGINT", () => { void stop().then(() => process.exit(0)); });
process.once("SIGTERM", () => { void stop().then(() => process.exit(0)); });
