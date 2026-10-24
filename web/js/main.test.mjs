import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const REQUEST = Object.freeze({
  name: "secret",
  revision: 7,
  operation: "encrypt",
  challenge: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
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
        "#positive-pin",
        "#negative-pin",
        "#test-prf",
        "#approve-request",
        "#cancel-request",
      ].map(element),
    },
    location: { hash: "#v=1", pathname: "/", search: "" },
    history: { replaceState(...args) { historyCalls.push(args); } },
    AbortController,
    DOMException,
    parseHandoffFragment: () => Object.freeze({ fullHostname: "workstation.keys.example" }),
    connectHandoff,
    createApprovalAssertion,
    createPasskey: async () => ({}),
    testPrfApi: async () => ({}),
    testPinnedEcho: async () => ({}),
    testMismatchedPin: async () => ({}),
  });

  vm.runInContext(source, context);
  return {
    element,
    historyCalls,
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

  assert.equal(ui.element("#request-host").textContent, "workstation.keys.example");
  assert.equal(ui.element("#request-name").textContent, "secret");
  assert.equal(ui.element("#request-revision").textContent, "7");
  assert.equal(ui.element("#request-operation").textContent, "encrypt");
  assert.deepEqual(ui.historyCalls, [[null, "", "/"]]);
  assert.match(ui.element("#result").textContent, /Connected to the pinned CLI/u);
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
