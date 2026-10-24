import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

test("approval stays disabled until the pinned request is displayed", async () => {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        disabled: false,
        hidden: false,
        value: "",
        textContent: "",
        handlers: {},
        addEventListener(type, handler) { this.handlers[type] = handler; },
      });
    }
    return elements.get(id);
  };
  let resolveConnection;
  const connectionReady = new Promise((resolve) => { resolveConnection = resolve; });
  const source = readFileSync(new URL("./main.mjs", import.meta.url), "utf8")
    .replace(/^import[\s\S]*?from ".*?";\n/gm, "");
  const context = vm.createContext({
    document: { querySelector: element, querySelectorAll: () => [] },
    location: { hash: "#v=1", pathname: "/", search: "" },
    history: { replaceState() {} },
    AbortController,
    parseHandoffFragment: () => ({ fullHostname: "workstation.keys.example" }),
    connectHandoff: () => connectionReady,
  });

  vm.runInContext(source, context);
  await new Promise((resolve) => setImmediate(resolve));
  const approveButton = element("#approve-request");
  assert.equal(approveButton.disabled, true);

  resolveConnection({
    request: { name: "secret", revision: 7, operation: "encrypt" },
    isActive: () => true,
    failed: new Promise(() => {}),
  });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(element("#request-host").textContent, "workstation.keys.example");
  assert.equal(element("#request-name").textContent, "secret");
  assert.equal(element("#request-revision").textContent, "7");
  assert.equal(element("#request-operation").textContent, "encrypt");
  assert.match(element("#result").textContent, /Connected to the pinned CLI/u);
  assert.equal(approveButton.disabled, false);
});
