import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const REQUEST = Object.freeze({
  name: "secret",
  revision: 7,
  operation: "encrypt",
  challenge: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
  approvalTimeoutMs: 120_000,
});

function createSession(request = REQUEST) {
  let resolveFailure;
  let active = true;
  const session = {
    request,
    sent: [],
    closed: false,
    failed: new Promise((resolve) => { resolveFailure = resolve; }),
    isActive: () => active,
    failure: () => (active ? null : new Error("The CLI approval session is closed.")),
    async sendKey(key, assertion) {
      if (!active) throw new Error("The CLI approval session is closed.");
      session.sent.push({ key: key.slice(), assertion });
    },
    close() {
      session.closed = true;
      active = false;
    },
    lose(error = new Error("transport lost")) {
      active = false;
      resolveFailure(error);
    },
  };
  return session;
}

function startApprovalUi({ connectHandoff, createApprovalAssertion = async () => ({
  key: new Uint8Array(32),
  assertion: {},
}) }) {
  const elements = new Map();
  const historyCalls = [];
  const timers = new Map();
  let nextTimerId = 1;
  const setTimeout = (callback, delay) => {
    const id = nextTimerId++;
    timers.set(id, { callback, delay });
    return id;
  };
  const clearTimeout = (id) => { timers.delete(id); };
  const element = (selector) => {
    if (!elements.has(selector)) {
      elements.set(selector, {
        disabled: false,
        hidden: false,
        value: "",
        textContent: "",
        innerHTML: "",
        handlers: {},
        addEventListener(type, handler) { this.handlers[type] = handler; },
        focus() {},
        select() {},
      });
    }
    return elements.get(selector);
  };
  const source = readFileSync(new URL("./main.mjs", import.meta.url), "utf8")
    .replace(/^import[\s\S]*?from ".*?";\n/gm, "");
  const context = vm.createContext({
    document: {
      querySelector: element,
      querySelectorAll: () => [
        "#create-passkey",
        "#copy-public-key",
        "#approve-request",
        "#cancel-request",
      ].map(element),
    },
    location: { hash: "#v=1", pathname: "/", search: "" },
    history: { replaceState(...args) { historyCalls.push(args); } },
    AbortController,
    DOMException,
    setTimeout,
    clearTimeout,
    parseHandoffFragment: () => Object.freeze({ fullHostname: "workstation.tailnet.example.net" }),
    connectHandoff,
    createApprovalAssertion,
    createPasskey: async () => ({}),
  });

  vm.runInContext(source, context);
  return {
    element,
    historyCalls,
    timerDelays: () => [...timers.values()].map(({ delay }) => delay),
    fireTimers() {
      const pending = [...timers.values()];
      timers.clear();
      for (const { callback } of pending) callback();
    },
    async click(selector) {
      const target = element(selector);
      const handler = target.handlers.click;
      assert.ok(handler, `expected a click handler for ${selector}`);
      return handler({ currentTarget: target });
    },
  };
}

async function settle() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

test("approval stays disabled until the pinned request is displayed", async () => {
  let resolveConnection;
  const connectionReady = new Promise((resolve) => { resolveConnection = resolve; });
  const ui = startApprovalUi({ connectHandoff: () => connectionReady });
  await settle();
  assert.equal(ui.element("#approve-request").disabled, true);

  const session = createSession();
  resolveConnection(session);
  await settle();

  assert.equal(ui.element("#request-host").textContent, "workstation.tailnet.example.net");
  assert.equal(ui.element("#request-name").textContent, "secret");
  assert.equal(ui.element("#request-revision").textContent, "7");
  assert.equal(ui.element("#request-operation").textContent, "encrypt");
  assert.deepEqual(ui.historyCalls, [[null, "", "/"]]);
  assert.match(ui.element("#result").textContent, /approve within 2 minutes/u);
  assert.deepEqual(ui.timerDelays(), [120_000]);
  assert.equal(ui.element("#approve-request").disabled, false);
});

test("request fields are inserted as text, including markup-shaped names", async () => {
  const name = '<img src=x onerror="alert(1)">';
  const session = createSession({ ...REQUEST, name });
  const ui = startApprovalUi({ connectHandoff: async () => session });
  await settle();

  assert.equal(ui.element("#request-name").textContent, name);
  assert.equal(ui.element("#request-name").innerHTML, "");
});

test("the static client uses no persistent browser storage or remote assets", () => {
  const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const stylesheet = readFileSync(new URL("../style.css", import.meta.url), "utf8");
  const modules = ["encoding.mjs", "envelope.mjs", "main.mjs", "transport.mjs", "webauthn.mjs"]
    .map((name) => readFileSync(new URL(name, import.meta.url), "utf8"));
  const sources = [html, stylesheet, ...modules].join("\n");

  assert.doesNotMatch(sources, /\b(?:localStorage|sessionStorage|indexedDB|serviceWorker)\b/u);
  assert.doesNotMatch(sources, /document\s*\.\s*cookie/u);
  assert.doesNotMatch(html, /<(?:script|link)\b[^>]+https?:\/\//iu);
  assert.doesNotMatch(stylesheet, /@import\s+url\s*\(|url\s*\(\s*["']?https?:/iu);
  assert.doesNotMatch(modules.join("\n"), /from\s+["']https?:\/\//u);
});

test("production entry points exclude compatibility probes and test-passkey creation", () => {
  const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const modules = ["main.mjs", "transport.mjs", "webauthn.mjs"]
    .map((name) => readFileSync(new URL(name, import.meta.url), "utf8"));
  const cli = readFileSync(new URL("../../src/main.rs", import.meta.url), "utf8");
  const production = [html, ...modules, cli].join("\n");

  assert.match(html, /Create passkey and export public key/u);
  assert.match(modules[2], /export async function createPasskey/u);
  assert.doesNotMatch(production, /probe-server|probe-tools|test-passkey|test credential|testPrfApi|testPinnedEcho|testMismatchedPin/u);

  const devPage = readFileSync(new URL("../../dev/browser-compatibility/index.html", import.meta.url), "utf8");
  const devRust = readFileSync(new URL("../../dev/transport_probe.rs", import.meta.url), "utf8");
  assert.match(devPage, /Create test credential and evaluate PRF/u);
  assert.match(devRust, /WebTransport probe/u);
});

test("cancel during connection setup closes the late session without sending a key", async () => {
  let resolveConnection;
  let connectionSignal;
  const connectionReady = new Promise((resolve) => { resolveConnection = resolve; });
  const ui = startApprovalUi({
    connectHandoff: (_handoff, signal) => {
      connectionSignal = signal;
      return connectionReady;
    },
  });
  await settle();

  await ui.click("#cancel-request");
  assert.equal(connectionSignal.aborted, true);
  const session = createSession();
  resolveConnection(session);
  await settle();

  assert.equal(session.closed, true);
  assert.equal(session.sent.length, 0);
  assert.equal(ui.element("#approve-request").disabled, true);
  assert.match(ui.element("#result").textContent, /cancelled/u);
});

test("an established transport that stalls before the approval request closes after 30 seconds", async () => {
  let connectionSignal;
  const ui = startApprovalUi({
    connectHandoff: (_handoff, signal) => {
      connectionSignal = signal;
      return new Promise(() => {});
    },
  });
  await settle();

  assert.deepEqual(ui.timerDelays(), [30_000]);
  ui.fireTimers();
  await settle();

  assert.equal(connectionSignal.aborted, true);
  assert.equal(ui.element("#approve-request").disabled, true);
  assert.match(ui.element("#result").textContent, /Connection setup expired after 30 seconds/u);
});

test("cancel during the WebAuthn ceremony aborts it and sends no key", async () => {
  const session = createSession();
  let assertionSignal;
  const ui = startApprovalUi({
    connectHandoff: async () => session,
    createApprovalAssertion: (_request, signal) => new Promise((_resolve, reject) => {
      assertionSignal = signal;
      signal.addEventListener("abort", () => reject(new DOMException("cancelled", "AbortError")), { once: true });
    }),
  });
  await settle();

  const approval = ui.click("#approve-request");
  await settle();
  assert.ok(assertionSignal);
  assert.equal(assertionSignal.aborted, false);
  await ui.click("#cancel-request");
  await approval;

  assert.equal(assertionSignal.aborted, true);
  assert.equal(session.closed, true);
  assert.equal(session.sent.length, 0);
  assert.match(ui.element("#result").textContent, /cancelled/u);
});

test("the browser closes an established request when its two-minute approval window expires", async () => {
  const session = createSession();
  const ui = startApprovalUi({ connectHandoff: async () => session });
  await settle();

  assert.deepEqual(ui.timerDelays(), [120_000]);
  ui.fireTimers();

  assert.equal(session.closed, true);
  assert.equal(session.sent.length, 0);
  assert.equal(ui.element("#approve-request").disabled, true);
  assert.equal(ui.element("#cancel-request").disabled, true);
  assert.match(ui.element("#result").textContent, /approval window expired/u);
});

test("approval expiry closes the session and clears the key while transmission is pending", async () => {
  const session = createSession();
  const key = new Uint8Array(32).fill(0x5a);
  let resolveSendStarted;
  let rejectSend;
  let transmittedKey;
  const sendStarted = new Promise((resolve) => { resolveSendStarted = resolve; });
  session.sendKey = (value) => {
    transmittedKey = value;
    resolveSendStarted();
    return new Promise((_resolve, reject) => { rejectSend = reject; });
  };
  const close = session.close.bind(session);
  session.close = () => {
    close();
    rejectSend?.(new Error("transport closed"));
  };
  const ui = startApprovalUi({
    connectHandoff: async () => session,
    createApprovalAssertion: async () => ({ key, assertion: {} }),
  });
  await settle();

  const sending = ui.click("#approve-request");
  await sendStarted;
  assert.deepEqual(ui.timerDelays(), [120_000]);

  ui.fireTimers();
  await sending;

  assert.equal(session.closed, true);
  assert.equal(transmittedKey, key);
  assert.equal(key.every((byte) => byte === 0), true);
  assert.equal(ui.element("#approve-request").disabled, true);
  assert.equal(ui.element("#cancel-request").disabled, true);
  assert.match(ui.element("#result").textContent, /approval window expired/u);
  assert.doesNotMatch(ui.element("#result").textContent, /Approval sent/u);
});

test("approval expiry aborts a pending WebAuthn ceremony before it can send a key", async () => {
  const session = createSession();
  let assertionSignal;
  const ui = startApprovalUi({
    connectHandoff: async () => session,
    createApprovalAssertion: (_request, signal) => new Promise((_resolve, reject) => {
      assertionSignal = signal;
      signal.addEventListener("abort", () => reject(new DOMException("expired", "AbortError")), { once: true });
    }),
  });
  await settle();

  const approval = ui.click("#approve-request");
  await settle();
  ui.fireTimers();
  await settle();
  await approval;

  assert.equal(assertionSignal.aborted, true);
  assert.equal(session.closed, true);
  assert.equal(session.sent.length, 0);
  assert.match(ui.element("#result").textContent, /approval window expired/u);
});

test("a later connection shows and enforces only the remaining approval time", async () => {
  const session = createSession({ ...REQUEST, approvalTimeoutMs: 90_000 });
  const ui = startApprovalUi({ connectHandoff: async () => session });
  await settle();

  assert.match(ui.element("#result").textContent, /approve within 1 minute 30 seconds/u);
  assert.deepEqual(ui.timerDelays(), [90_000]);
});

test("session loss while WebAuthn is pending aborts approval and disables both actions", async () => {
  const session = createSession();
  let assertionSignal;
  const ui = startApprovalUi({
    connectHandoff: async () => session,
    createApprovalAssertion: (_request, signal) => new Promise((_resolve, reject) => {
      assertionSignal = signal;
      signal.addEventListener("abort", () => reject(new DOMException("closed", "AbortError")), { once: true });
    }),
  });
  await settle();

  const approval = ui.click("#approve-request");
  await settle();
  session.lose(new Error("CLI disconnected"));
  await settle();
  await approval;

  assert.equal(assertionSignal.aborted, true);
  assert.equal(ui.element("#approve-request").disabled, true);
  assert.equal(ui.element("#cancel-request").disabled, true);
  assert.equal(session.sent.length, 0);
});

test("one explicit approval runs one ceremony and sends only on its live session", async () => {
  const session = createSession();
  const key = new Uint8Array(32).fill(0x5a);
  const assertion = { signature: new Uint8Array([1, 2, 3]).buffer };
  let ceremonyCalls = 0;
  let approvedRequest;
  const ui = startApprovalUi({
    connectHandoff: async () => session,
    createApprovalAssertion: async (request) => {
      ceremonyCalls += 1;
      approvedRequest = request;
      return { key, assertion };
    },
  });
  await settle();

  await ui.click("#approve-request");

  assert.equal(ceremonyCalls, 1);
  assert.equal(approvedRequest, REQUEST);
  assert.equal(session.sent.length, 1);
  assert.equal(session.sent[0].assertion, assertion);
  assert.deepEqual(session.sent[0].key, new Uint8Array(32).fill(0x5a));
  assert.equal(key.every((byte) => byte === 0), true, "page clears its key reference after sending");
  assert.equal(ui.element("#cancel-request").disabled, true);
});
