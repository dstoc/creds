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

function startApprovalUi({
  connectHandoff,
  createApprovalAssertion = async () => ({
  key: new Uint8Array(32),
  assertion: {},
  }),
  initialSettings = {
    version: 1,
    publicKey: null,
    suffix: "tailnet.example.net",
    acceptedPrefixes: ["workstation"],
  },
  loadStatus = "ok",
  saveError = null,
  confirmAnswer = true,
  hash = "#v=1",
  createPasskey = async () => ({ publicKey: "public-key", publicKeyAlgorithm: "ES256 (-7)" }),
} = {}) {
  const elements = new Map();
  const historyCalls = [];
  const confirmations = [];
  const writes = [];
  const clipboardWrites = [];
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
        children: [],
        addEventListener(type, handler) { this.handlers[type] = handler; },
        querySelector(selector) { return element(`${selector} in ${this.id ?? this.value ?? this.textContent}`); },
        append(...children) { this.children.push(...children); },
        replaceChildren(...children) { this.children = [...children]; },
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
      querySelectorAll: () => [],
      title: "",
      createElement: (tagName) => Object.assign(element(`generated-${elements.size}`), { tagName }),
    },
    location: { hash, pathname: "/", search: "", protocol: "https:", hostname: "approval.example.com" },
    history: { replaceState(...args) { historyCalls.push(args); } },
    AbortController,
    DOMException,
    setTimeout,
    clearTimeout,
    confirm: (message) => { confirmations.push(message); return confirmAnswer; },
    navigator: { clipboard: { async writeText(value) { clipboardWrites.push(value); } } },
    emptySettings: () => ({ version: 1, publicKey: null, suffix: "", acceptedPrefixes: [] }),
    loadSettings: async () => ({ status: loadStatus, settings: structuredClone(initialSettings), error: null }),
    saveSettings: async (value) => {
      if (saveError) throw saveError;
      writes.push(structuredClone(value));
      return structuredClone(value);
    },
    validateSettings: async (value) => {
      if (value.suffix) value.suffix = value.suffix.trim().toLowerCase();
      return structuredClone(value);
    },
    resetSettings() {},
    validatePublicKey: async (value) => value,
    normalizeSuffix: (value) => {
      const suffix = value.trim().toLowerCase();
      if (!suffix || suffix.includes("/")) throw new TypeError("invalid suffix");
      return suffix;
    },
    MAX_ACCEPTED_PREFIXES: 128,
    parseHandoffFragment: () => Object.freeze({ prefix: "workstation", port: 8443 }),
    buildHandoffDestination: (handoff, suffix) => {
      if (!suffix) throw new TypeError("A machine DNS suffix is required.");
      return Object.freeze({
        ...handoff,
        suffix,
        prefix: handoff.prefix.toLowerCase(),
        fullHostname: `${handoff.prefix.toLowerCase()}.${suffix}`,
        endpoint: `https://${handoff.prefix.toLowerCase()}.${suffix}:${handoff.port}/key`,
      });
    },
    connectHandoff,
    createApprovalAssertion,
    createPasskey,
  });

  vm.runInContext(source, context);
  return {
    element,
    historyCalls,
    confirmations,
    writes,
    clipboardWrites,
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
      return handler({ currentTarget: target, preventDefault() {} });
    },
  };
}

async function settle() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

test("first-time setup offers an existing-passkey path without requiring a saved public key", async () => {
  let creations = 0;
  const ui = startApprovalUi({
    hash: "",
    initialSettings: { version: 1, publicKey: null, suffix: "", acceptedPrefixes: [] },
    connectHandoff: async () => createSession(),
    createPasskey: async () => {
      creations += 1;
      return { publicKey: "new-public-key", publicKeyAlgorithm: "ES256 (-7)" };
    },
  });
  await settle();

  assert.equal(ui.element("#setup-panel").hidden, false);
  assert.equal(ui.element("#ready-panel").hidden, true);
  assert.equal(ui.element("#setup-choice").hidden, false);
  assert.equal(ui.element("#setup-flow").hidden, true);
  assert.equal(ui.element("#setup-title").textContent, "Set up this browser");
  await ui.click("#setup-use-existing");
  assert.equal(ui.element("#setup-title").textContent, "Use existing passkey");
  assert.equal(ui.element("#setup-import-key").hidden, false);
  assert.equal(ui.element("#setup-created-key").hidden, true);
  assert.equal(creations, 0);

  ui.element("#dns-suffix").value = " TailNet.Example.Net ";
  await ui.click("#save-settings");
  await settle();

  assert.equal(ui.writes[0].suffix, "tailnet.example.net");
  assert.equal(ui.writes[0].publicKey, null);
  assert.equal(creations, 0);
  assert.equal(ui.element("#setup-panel").hidden, true);
  assert.equal(ui.element("#ready-panel").hidden, false);
  assert.equal(ui.element("#settings-link").hidden, false);
});

test("existing-passkey setup permits optional public-key import without creating a key", async () => {
  let creations = 0;
  const ui = startApprovalUi({
    hash: "",
    initialSettings: { version: 1, publicKey: null, suffix: "", acceptedPrefixes: [] },
    connectHandoff: async () => createSession(),
    createPasskey: async () => {
      creations += 1;
      return { publicKey: "unexpected-key", publicKeyAlgorithm: "ES256 (-7)" };
    },
  });
  await settle();

  await ui.click("#setup-use-existing");
  assert.equal(ui.element("#setup-import-key").hidden, false);
  ui.element("#setup-public-key-input").value = "saved-public-key";
  await ui.click("#save-setup-public-key");
  await settle();
  assert.equal(ui.writes[0].publicKey, "saved-public-key");
  assert.match(ui.element("#result").textContent, /does not enroll a key with the CLI or prove possession/u);
  assert.equal(creations, 0);

  ui.element("#dns-suffix").value = "tailnet.example.net";
  await ui.click("#save-settings");
  await settle();
  assert.equal(ui.writes[1].suffix, "tailnet.example.net");
  assert.equal(creations, 0);
});

test("create-passkey setup confirms PRF, shows the exported key, and supports copy and suffix setup", async () => {
  let creations = 0;
  let resolveCreatedPasskey;
  const createdPasskey = new Promise((resolve) => { resolveCreatedPasskey = resolve; });
  const ui = startApprovalUi({
    hash: "",
    initialSettings: { version: 1, publicKey: null, suffix: "", acceptedPrefixes: [] },
    connectHandoff: async () => createSession(),
    createPasskey: async () => {
      creations += 1;
      return createdPasskey;
    },
  });
  await settle();

  assert.equal(ui.element("#setup-title").textContent, "Set up this browser");
  const creation = ui.click("#setup-create-passkey");
  await settle();
  assert.equal(creations, 1);
  assert.equal(ui.element("#setup-title").textContent, "Set up this browser");
  assert.equal(ui.element("#setup-created-key").hidden, true);
  resolveCreatedPasskey({ publicKey: "exported-setup-key", publicKeyAlgorithm: "ES256 (-7)" });
  await creation;
  await settle();
  assert.equal(ui.element("#setup-created-key").hidden, false);
  assert.equal(ui.element("#setup-title").textContent, "Passkey created");
  assert.equal(ui.element("#setup-public-key").value, "exported-setup-key");
  assert.equal(ui.element("#result").textContent, "");
  assert.equal(ui.writes[0].publicKey, "exported-setup-key");
  const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  assert.match(html, /<label for="setup-public-key">Public key<\/label>/u);
  assert.match(html, /Run <code>creds setup<\/code> and paste this key\./u);
  assert.doesNotMatch(html, /Choose how you use passkeys with creds\./u);
  assert.doesNotMatch(html, /Passkey created and PRF confirmed\./u);
  assert.doesNotMatch(html, /Your passkey is used when you approve requests\. You do not need to import a public key here\./u);
  assert.doesNotMatch(html, /Exported public key/u);

  await ui.click("#copy-setup-public-key");
  await settle();
  assert.deepEqual(ui.clipboardWrites, ["exported-setup-key"]);
  assert.match(ui.element("#result").textContent, /copied/u);

  ui.element("#dns-suffix").value = " TailNet.Example.Net ";
  await ui.click("#save-settings");
  await settle();
  assert.equal(ui.writes[1].suffix, "tailnet.example.net");
  assert.equal(ui.element("#ready-panel").hidden, false);
});

test("cancelled passkey creation reports the failure and leaves existing setup available", async () => {
  const ui = startApprovalUi({
    hash: "",
    initialSettings: { version: 1, publicKey: null, suffix: "", acceptedPrefixes: [] },
    connectHandoff: async () => createSession(),
    createPasskey: async () => { throw new DOMException("The user cancelled.", "NotAllowedError"); },
  });
  await settle();

  await ui.click("#setup-create-passkey");
  await settle();
  assert.equal(ui.element("#setup-title").textContent, "Set up this browser");
  assert.equal(ui.element("#setup-choice").hidden, false);
  assert.equal(ui.element("#setup-flow").hidden, true);
  assert.match(ui.element("#result").textContent, /NotAllowedError/u);
  assert.equal(ui.writes.length, 0);

  await ui.click("#setup-use-existing");
  ui.element("#dns-suffix").value = "tailnet.example.net";
  await ui.click("#save-settings");
  await settle();
  assert.equal(ui.element("#ready-panel").hidden, false);
});

test("a configured CLI request proceeds without a saved browser public key", async () => {
  let resolveConnection;
  const connectionReady = new Promise((resolve) => { resolveConnection = resolve; });
  const ui = startApprovalUi({ connectHandoff: () => connectionReady });
  await settle();
  assert.equal(ui.element("#approve-request").disabled, true);

  const session = createSession();
  resolveConnection(session);
  await settle();

  assert.equal(ui.element("#request-host").textContent, "workstation.tailnet.example.net:8443");
  assert.equal(ui.element("#request-prefix").textContent, "workstation");
  assert.equal(ui.element("#request-suffix").textContent, "tailnet.example.net");
  assert.equal(ui.element("#request-name").textContent, "secret");
  assert.equal(ui.element("#request-revision").textContent, "7");
  assert.equal(ui.element("#request-operation").textContent, "Encrypt");
  assert.deepEqual(ui.historyCalls, [[null, "", "/"]]);
  assert.match(ui.element("#result-request").textContent, /Approval window: 2 minutes/u);
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

test("an unfamiliar destination needs explicit acceptance before connection and still needs request approval", async () => {
  const session = createSession();
  let connections = 0;
  let ceremonies = 0;
  const ui = startApprovalUi({
    initialSettings: { version: 1, publicKey: null, suffix: "tailnet.example.net", acceptedPrefixes: [] },
    connectHandoff: async () => { connections += 1; return session; },
    createApprovalAssertion: async () => { ceremonies += 1; return { key: new Uint8Array(32), assertion: {} }; },
  });
  await settle();

  assert.deepEqual(ui.historyCalls, [[null, "", "/"]]);
  assert.equal(ui.element("#destination-host").textContent, "workstation.tailnet.example.net:8443");
  assert.equal(ui.element("#destination-panel").hidden, false);
  assert.equal(connections, 0);
  assert.equal(ceremonies, 0);

  await ui.click("#accept-destination");
  await settle();
  assert.equal(connections, 1);
  assert.deepEqual(ui.writes[0].acceptedPrefixes, ["workstation"]);
  assert.equal(ui.element("#approve-request").disabled, false);
  assert.equal(ceremonies, 0, "destination acceptance does not invoke WebAuthn");

  await ui.click("#approve-request");
  assert.equal(ceremonies, 1);
  assert.equal(session.sent.length, 1);
});

test("declining an unfamiliar destination neither connects nor saves an acceptance", async () => {
  let connections = 0;
  const ui = startApprovalUi({
    initialSettings: { version: 1, publicKey: null, suffix: "tailnet.example.net", acceptedPrefixes: [] },
    connectHandoff: async () => { connections += 1; return createSession(); },
  });
  await settle();

  await ui.click("#decline-destination");
  assert.equal(connections, 0);
  assert.equal(ui.writes.length, 0);
  assert.equal(ui.element("#destination-panel").hidden, true);
  assert.match(ui.element("#outcome-message").textContent, /No key was sent/u);
});

test("missing-suffix handoff asks only for the suffix and resumes after it is saved", async () => {
  let connections = 0;
  let creations = 0;
  const ui = startApprovalUi({
    initialSettings: { version: 1, publicKey: null, suffix: "", acceptedPrefixes: [] },
    connectHandoff: async () => { connections += 1; return createSession(); },
    createPasskey: async () => {
      creations += 1;
      return { publicKey: "new-public-key", publicKeyAlgorithm: "ES256 (-7)" };
    },
  });
  await settle();
  assert.equal(connections, 0);
  assert.equal(creations, 0);
  assert.deepEqual(ui.historyCalls, [[null, "", "/"]]);
  assert.equal(ui.element("#needs-settings-panel").hidden, false);
  assert.equal(ui.element("#needs-settings-form").hidden, false);
  assert.equal(ui.element("#needs-settings-invalid").hidden, true);
  assert.match(ui.element("#needs-settings-status").textContent, /handoff stays in this page/u);

  ui.element("#needs-settings-suffix").value = " TailNet.Example.Net ";
  await ui.click("#save-needs-settings");
  await settle();
  assert.equal(ui.writes[0].suffix, "tailnet.example.net");
  assert.equal(creations, 0);
  assert.equal(connections, 0, "saving the suffix resumes at the separate destination decision");
  assert.equal(ui.element("#destination-panel").hidden, false);
  assert.equal(ui.element("#destination-host").textContent, "workstation.tailnet.example.net:8443");

  await ui.click("#accept-destination");
  await settle();
  assert.equal(connections, 1);
  assert.equal(ui.element("#approve-request").disabled, false);
});

test("malformed stored settings block handoff until the user confirms reset", async () => {
  let connections = 0;
  const ui = startApprovalUi({
    loadStatus: "invalid",
    connectHandoff: async () => { connections += 1; return createSession(); },
  });
  await settle();
  assert.equal(connections, 0);
  assert.equal(ui.element("#settings-controls").disabled, true);
  assert.equal(ui.element("#reset-settings").disabled, false);
  assert.equal(ui.element("#needs-settings-form").hidden, true);
  assert.equal(ui.element("#needs-settings-invalid").hidden, false);
  assert.match(ui.element("#needs-settings-status").textContent, /explicit reset/u);

  await ui.click("#reset-settings");
  await settle();
  assert.equal(ui.confirmations.length, 1);
  assert.equal(ui.element("#settings-controls").disabled, false);
  assert.equal(connections, 0);
  assert.match(ui.element("#needs-settings-status").textContent, /save the suffix/u);
});

test("storage write failure accepts only in page memory and does not claim the destination was remembered", async () => {
  const session = createSession();
  let connections = 0;
  const ui = startApprovalUi({
    loadStatus: "unavailable",
    initialSettings: { version: 1, publicKey: null, suffix: "tailnet.example.net", acceptedPrefixes: [] },
    saveError: new DOMException("quota", "QuotaExceededError"),
    connectHandoff: async () => { connections += 1; return session; },
  });
  await settle();
  assert.match(ui.element("#destination-note").textContent, /only for this page/u);

  await ui.click("#accept-destination");
  await settle();
  assert.equal(connections, 1);
  assert.equal(ui.writes.length, 0);
  assert.match(ui.element("#result-request").textContent, /accepted for this page only and was not remembered/u);
});

test("a full accepted-prefix list offers a one-time acceptance without writing it", async () => {
  const acceptedPrefixes = Array.from({ length: 128 }, (_, index) => `machine-${index}`);
  let connections = 0;
  const ui = startApprovalUi({
    initialSettings: { version: 1, publicKey: null, suffix: "tailnet.example.net", acceptedPrefixes },
    connectHandoff: async () => { connections += 1; return createSession(); },
  });
  await settle();
  assert.equal(ui.element("#accept-destination").textContent, "Accept once and continue");
  assert.match(ui.element("#destination-note").textContent, /128-machine list is full/u);

  await ui.click("#accept-destination");
  await settle();
  assert.equal(connections, 1);
  assert.equal(ui.writes.length, 0);
  assert.match(ui.element("#result-request").textContent, /Accepted once/u);
});

test("saving the same canonical suffix preserves accepted prefixes, while changing it clears them", async () => {
  const initialSettings = {
    version: 1,
    publicKey: null,
    suffix: "tailnet.example.net",
    acceptedPrefixes: ["workstation"],
  };
  const ui = startApprovalUi({
    initialSettings,
    hash: "",
    connectHandoff: async () => createSession(),
  });
  await settle();
  await ui.click("#settings-link");
  ui.element("#dns-suffix-settings").value = " TailNet.Example.Net ";
  await ui.click("#save-settings-from-page");
  await settle();
  assert.deepEqual(ui.writes[0].acceptedPrefixes, ["workstation"]);
  assert.equal(ui.confirmations.length, 0);

  ui.element("#dns-suffix-settings").value = "new.example.net";
  await ui.click("#save-settings-from-page");
  await settle();
  assert.equal(ui.confirmations.length, 1);
  assert.deepEqual(ui.writes[1].acceptedPrefixes, []);
});

test("replacing the saved public key requires confirmation and clears accepted prefixes", async () => {
  const ui = startApprovalUi({
    initialSettings: {
      version: 1,
      publicKey: "old-public-key",
      suffix: "tailnet.example.net",
      acceptedPrefixes: ["workstation"],
    },
    hash: "",
    connectHandoff: async () => createSession(),
  });
  await settle();
  await ui.click("#settings-link");
  ui.element("#public-key").value = "new-public-key";
  await ui.click("#save-public-key");
  await settle();
  assert.equal(ui.confirmations.length, 1);
  assert.equal(ui.writes[0].publicKey, "new-public-key");
  assert.deepEqual(ui.writes[0].acceptedPrefixes, []);
  assert.match(ui.element("#settings-status").textContent, /does not enroll a key with the CLI or prove possession/u);
});

test("successful passkey setup saves its exported public key and forgetting removes one prefix", async () => {
  const ui = startApprovalUi({
    initialSettings: {
      version: 1,
      publicKey: null,
      suffix: "tailnet.example.net",
      acceptedPrefixes: ["workstation", "laptop"],
    },
    hash: "",
    createPasskey: async () => ({ publicKey: "exported-public-key", publicKeyAlgorithm: "ES256 (-7)" }),
    connectHandoff: async () => createSession(),
  });
  await settle();

  await ui.click("#settings-link");
  await ui.click("#create-passkey");
  assert.equal(ui.writes[0].publicKey, "exported-public-key");
  assert.deepEqual(ui.writes[0].acceptedPrefixes, ["workstation", "laptop"]);
  assert.match(ui.element("#settings-status").textContent, /public key saved/u);

  const forgetButton = ui.element("#accepted-prefixes").children[0].children[1];
  assert.equal(forgetButton.disabled, false, "Forget is enabled after settings load");
  await forgetButton.handlers.click();
  await settle();
  assert.deepEqual(ui.writes[1].acceptedPrefixes, ["laptop"]);
});

test("live approval freezes settings and keeps its displayed destination snapshot", async () => {
  const session = createSession();
  const ui = startApprovalUi({ connectHandoff: async () => session });
  await settle();

  assert.equal(ui.element("#settings-controls").disabled, true);
  assert.equal(ui.element("#reset-settings").disabled, true);
  await ui.click("#settings-link");
  ui.element("#dns-suffix-settings").value = "other.example.net";
  assert.equal(ui.element("#settings-controls").disabled, true);
  assert.equal(ui.element("#request-host").textContent, "workstation.tailnet.example.net:8443");
  assert.equal(ui.element("#request-suffix").textContent, "tailnet.example.net");

  await ui.click("#cancel-request");
  assert.equal(ui.element("#settings-controls").disabled, false);
});

test("opening Settings during connection keeps the updated request status when returning", async () => {
  let resolveConnection;
  const connectionReady = new Promise((resolve) => { resolveConnection = resolve; });
  const ui = startApprovalUi({ connectHandoff: () => connectionReady });
  await settle();

  await ui.click("#settings-link");
  const session = createSession();
  resolveConnection(session);
  await settle();

  assert.equal(ui.element("#settings-panel").hidden, false);
  assert.equal(ui.element("#settings-controls").disabled, true);
  await ui.click("#done-settings");
  assert.equal(ui.element("#approval-panel").hidden, false);
  assert.match(ui.element("#result-request").textContent, /Approval window: 2 minutes/u);

  await ui.click("#cancel-request");
});

test("the static client persists only the bounded public settings record and uses no remote assets", () => {
  const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const stylesheet = readFileSync(new URL("../style.css", import.meta.url), "utf8");
  const modules = ["encoding.mjs", "envelope.mjs", "main.mjs", "settings.mjs", "transport.mjs", "webauthn.mjs"]
    .map((name) => readFileSync(new URL(name, import.meta.url), "utf8"));
  const sources = [html, stylesheet, ...modules].join("\n");

  assert.match(html, /Open a request from your terminal\./u);
  assert.match(modules[3], /creds\.settings\.v1/u);
  assert.match(modules[3], /MAX_SETTINGS_BYTES\s*=\s*32\s*\*\s*1024/u);
  assert.match(modules[3], /MAX_ACCEPTED_PREFIXES\s*=\s*128/u);
  assert.doesNotMatch(sources, /\b(?:sessionStorage|indexedDB|serviceWorker|largeBlob)\b/iu);
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

  assert.doesNotMatch(html, /state-picker|Prototype states|review-long|sampleKey/u);
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
  assert.match(ui.element("#outcome-message").textContent, /cancelled/u);
});

test("Done keeps a cancelled request dismissed when connection setup rejects later", async () => {
  let rejectConnection;
  const ui = startApprovalUi({
    connectHandoff: () => new Promise((_resolve, reject) => { rejectConnection = reject; }),
  });
  await settle();

  await ui.click("#cancel-request");
  await ui.click("#outcome-done");
  assert.equal(ui.element("#ready-panel").hidden, false);

  rejectConnection(new DOMException("Aborted", "AbortError"));
  await settle();

  assert.equal(ui.element("#ready-panel").hidden, false);
  assert.equal(ui.element("#approval-panel").hidden, true);
  assert.equal(ui.element("#outcome-panel").hidden, true);
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
  assert.match(ui.element("#result-request").textContent, /Connection setup expired after 30 seconds/u);
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
  assert.match(ui.element("#outcome-message").textContent, /cancelled/u);
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
  assert.match(ui.element("#outcome-message").textContent, /Request expired/u);
  assert.equal(ui.element("#settings-controls").disabled, false);
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
  assert.match(ui.element("#outcome-message").textContent, /Request expired/u);
  assert.doesNotMatch(ui.element("#outcome-message").textContent, /Approval sent/u);
});

test("Done keeps an expired request dismissed when transmission settles later", async () => {
  const session = createSession();
  let resolveSend;
  session.sendKey = () => new Promise((resolve) => { resolveSend = resolve; });
  const ui = startApprovalUi({ connectHandoff: async () => session });
  await settle();

  const sending = ui.click("#approve-request");
  await settle();
  assert.ok(resolveSend);
  ui.fireTimers();
  assert.match(ui.element("#outcome-message").textContent, /Request expired/u);
  await ui.click("#outcome-done");
  resolveSend();
  await sending;

  assert.equal(ui.element("#ready-panel").hidden, false);
  assert.equal(ui.element("#outcome-panel").hidden, true);
  assert.match(ui.element("#outcome-message").textContent, /Request expired/u);
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
  assert.match(ui.element("#outcome-message").textContent, /Request expired/u);
});

test("a later connection shows and enforces only the remaining approval time", async () => {
  const session = createSession({ ...REQUEST, approvalTimeoutMs: 90_000 });
  const ui = startApprovalUi({ connectHandoff: async () => session });
  await settle();

  assert.match(ui.element("#result-request").textContent, /Approval window: 1 minute 30 seconds/u);
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
  assert.equal(ui.element("#outcome-message").textContent, "Approval sent. Check your terminal.");

  await ui.click("#outcome-done");
  assert.equal(ui.element("#ready-panel").hidden, false);
});

test("successful transmission restores settings after the session closes without a failure event", async () => {
  const session = createSession();
  session.sendKey = async () => { session.close(); };
  const ui = startApprovalUi({ connectHandoff: async () => session });
  await settle();

  assert.equal(ui.element("#settings-controls").disabled, true);
  await ui.click("#approve-request");

  assert.equal(session.closed, true);
  assert.equal(ui.element("#settings-controls").disabled, false);
});
