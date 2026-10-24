import {
  connectHandoff,
  parseHandoffFragment,
  testMismatchedPin,
  testPinnedEcho,
} from "./transport.mjs";
import { createApprovalAssertion, createPasskey, testPrfApi } from "./webauthn.mjs";

const result = document.querySelector("#result");
const buttons = [...document.querySelectorAll("button")];
const approvalPanel = document.querySelector("#approval-panel");
const probeTools = document.querySelector("#probe-tools");
const approveButton = document.querySelector("#approve-request");
const cancelButton = document.querySelector("#cancel-request");
const endpointInput = document.querySelector("#endpoint");
const hashInput = document.querySelector("#certificate-hash");
const passkeyLabelInput = document.querySelector("#passkey-label");
const publicKeyInput = document.querySelector("#public-key");
let matchingPinTarget = null;
let approvalSession = null;
let approvalController = null;
let connectionController = null;
let approvalCancelled = false;

function show(value) {
  result.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function run(button, action) {
  buttons.forEach((item) => { item.disabled = true; });
  show("Running browser API probe…");
  try {
    show(await action());
  } catch (error) {
    show(`${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}`);
  } finally {
    buttons.forEach((item) => { item.disabled = false; });
    button.focus();
  }
}

document.querySelector("#create-passkey").addEventListener("click", (event) => {
  publicKeyInput.value = "";
  run(event.currentTarget, async () => {
    const created = await createPasskey(passkeyLabelInput.value);
    publicKeyInput.value = created.publicKey;
    return `PASS: ${created.publicKeyAlgorithm} passkey created. PRF returned 32 bytes. Copy the public key above into creds setup.`;
  });
});

document.querySelector("#copy-public-key").addEventListener("click", async () => {
  if (!publicKeyInput.value) {
    show("Create a passkey first. The public key will appear in the field above.");
    return;
  }
  publicKeyInput.select();
  try {
    await navigator.clipboard.writeText(publicKeyInput.value);
    show("Public key copied. Store it for creds setup.");
  } catch (error) {
    show(`Clipboard access failed: ${error instanceof Error ? error.message : String(error)}. Select and copy the public key from the field above.`);
  }
});

document.querySelector("#positive-pin").addEventListener("click", (event) => run(event.currentTarget, async () => {
  const endpoint = endpointInput.value;
  const hash = hashInput.value;
  const value = await testPinnedEcho(endpoint, hash);
  matchingPinTarget = `${endpoint}\0${hash}`;
  return `PASS: Chromium established a pinned WebTransport session and echoed the probe stream.\n${JSON.stringify(value, null, 2)}`;
}));

document.querySelector("#negative-pin").addEventListener("click", (event) => run(event.currentTarget, async () => {
  const endpoint = endpointInput.value;
  const hash = hashInput.value;
  if (matchingPinTarget !== `${endpoint}\0${hash}`) {
    throw new Error("First pass the matching-pin test with this endpoint and certificate hash.");
  }
  const value = await testMismatchedPin(
    endpoint,
    hash,
  );
  if (!value.mismatchRejected) throw new Error("The browser accepted a deliberately mismatched certificate hash.");
  return `PASS: Chromium rejected a WebTransport connection with the altered certificate hash.\n${JSON.stringify(value, null, 2)}`;
}));

for (const input of [endpointInput, hashInput]) {
  input.addEventListener("input", () => { matchingPinTarget = null; });
}

document.querySelector("#test-prf").addEventListener("click", (event) => run(event.currentTarget, testPrfApi));

async function startApprovalFlow() {
  if (!location.hash) return;

  const fragment = location.hash;
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  approvalPanel.hidden = false;
  approveButton.disabled = true;
  probeTools.hidden = true;
  document.querySelector("#eyebrow").textContent = "creds · request approval";
  document.querySelector("#page-title").textContent = "Approve a creds request";
  document.querySelector("#page-intro").textContent = "Review the machine, name, revision, and operation before you approve with your passkey.";
  document.title = "Approve creds request";

  let handoff;
  try {
    handoff = parseHandoffFragment(fragment);
  } catch (error) {
    approveButton.disabled = true;
    cancelButton.disabled = true;
    show(`Invalid handoff URL: ${error instanceof Error ? error.message : String(error)}`);
    return;
  }

  try {
    connectionController = new AbortController();
    show("Connecting to the pinned CLI…");
    approvalSession = await connectHandoff(handoff, connectionController.signal);
    if (approvalCancelled) {
      approvalSession.close();
      return;
    }
    const { request } = approvalSession;
    document.querySelector("#request-host").textContent = handoff.fullHostname;
    document.querySelector("#request-name").textContent = request.name;
    document.querySelector("#request-revision").textContent = String(request.revision);
    document.querySelector("#request-operation").textContent = request.operation;
    show("Connected to the pinned CLI. Check the request details, then select Approve and verify.");
    approveButton.disabled = false;
    approvalSession.failed.then((error) => {
      if (approvalController) approvalController.abort();
      approveButton.disabled = true;
      cancelButton.disabled = true;
      show(`Approval session closed: ${error instanceof Error ? error.message : String(error)}`);
    });
  } catch (error) {
    if (approvalCancelled) return;
    approveButton.disabled = true;
    cancelButton.disabled = true;
    show(`Could not open the pinned CLI session: ${error instanceof Error ? error.message : String(error)}`);
  }
}

approveButton.addEventListener("click", async () => {
  if (!approvalSession?.isActive()) {
    show(approvalSession?.failure()?.message ?? "The CLI approval session is closed.");
    approveButton.disabled = true;
    return;
  }
  approveButton.disabled = true;
  approvalController = new AbortController();
  show("Waiting for passkey user verification…");
  let key;
  try {
    const approved = await createApprovalAssertion(approvalSession.request, approvalController.signal);
    key = approved.key;
    if (!approvalSession.isActive()) {
      throw approvalSession.failure() ?? new Error("The CLI approval session is closed.");
    }
    await approvalSession.sendKey(key, approved.assertion);
    show("Approval sent. Check the CLI for the operation result.");
    cancelButton.disabled = true;
  } catch (error) {
    const cancelled = approvalController.signal.aborted;
    show(cancelled
      ? "Approval cancelled. No key was sent."
      : `Approval failed: ${error instanceof Error ? error.message : String(error)}`);
    if (!approvalSession?.isActive()) cancelButton.disabled = true;
    else approveButton.disabled = false;
  } finally {
    key?.fill(0);
    approvalController = null;
  }
});

cancelButton.addEventListener("click", () => {
  approvalCancelled = true;
  connectionController?.abort();
  approvalController?.abort();
  approvalSession?.close();
  approveButton.disabled = true;
  cancelButton.disabled = true;
  show("Approval cancelled. No key was sent.");
});

void startApprovalFlow();
