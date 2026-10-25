import {
  buildHandoffDestination,
  connectHandoff,
  parseHandoffFragment,
} from "./transport.mjs";
import { createApprovalAssertion, createPasskey } from "./webauthn.mjs";
import {
  emptySettings,
  loadSettings,
  MAX_ACCEPTED_PREFIXES,
  normalizeSuffix,
  resetSettings,
  saveSettings,
  validatePublicKey,
  validateSettings,
} from "./settings.mjs";

const panels = {
  setup: document.querySelector("#setup-panel"),
  ready: document.querySelector("#ready-panel"),
  needsSettings: document.querySelector("#needs-settings-panel"),
  destination: document.querySelector("#destination-panel"),
  request: document.querySelector("#approval-panel"),
  settings: document.querySelector("#settings-panel"),
  outcome: document.querySelector("#outcome-panel"),
};
const statusSelectors = {
  setup: "#result",
  ready: "#result-ready",
  needsSettings: "#needs-settings-status",
  destination: "#result-destination",
  request: "#result-request",
};
const settingsControls = document.querySelector("#settings-controls");
const settingsStatus = document.querySelector("#settings-status");
const destinationPanel = panels.destination;
const approveButton = document.querySelector("#approve-request");
const cancelButton = document.querySelector("#cancel-request");
const acceptDestinationButton = document.querySelector("#accept-destination");
const declineDestinationButton = document.querySelector("#decline-destination");
const retryConnectionButton = document.querySelector("#retry-connection");
const createPasskeyButton = document.querySelector("#create-passkey");
const resetSettingsButton = document.querySelector("#reset-settings");
const passkeyLabelInput = document.querySelector("#passkey-label");
const publicKeyInput = document.querySelector("#public-key");
const suffixInput = document.querySelector("#dns-suffix");
const settingsSuffixInput = document.querySelector("#dns-suffix-settings");
const acceptedPrefixesList = document.querySelector("#accepted-prefixes");
const acceptedEmpty = document.querySelector("#accepted-empty");
const settingsLink = document.querySelector("#settings-link");
const doneSettingsButton = document.querySelector("#done-settings");
const outcomeMessage = document.querySelector("#outcome-message");

let settings = emptySettings();
let settingsInvalid = false;
let storageAvailable = true;
let settingsSaving = false;
let pendingHandoff = null;
let pendingDestination = null;
let approvalSession = null;
let approvalController = null;
let connectionController = null;
let approvalCancelled = false;
let approvalSent = false;
let connectionInProgress = false;
let connectionTimeout = null;
let approvalTimeout = null;
let connectionExpired = false;
let approvalExpired = false;
let approvalKey = null;
let destinationNotice = "";
let activeView = "setup";
let returnView = "ready";
const viewMessages = Object.fromEntries(Object.keys(statusSelectors).map((view) => [view, ""]));
const viewErrors = Object.fromEntries(Object.keys(statusSelectors).map((view) => [view, false]));

const startupFragment = location.hash;
if (startupFragment) history.replaceState(null, "", `${location.pathname}${location.search}`);

function setSettingsStatus(message, { error = false } = {}) {
  settingsStatus.textContent = message;
  settingsStatus.hidden = message === "";
  settingsStatus.className = error ? "status error" : "status";
}

function showIn(view, message, { error = false } = {}) {
  const text = typeof message === "string" ? message : JSON.stringify(message, null, 2);
  if (view === "settings") {
    setSettingsStatus(text, { error });
    return;
  }
  viewMessages[view] = text;
  viewErrors[view] = error;
  if (activeView !== view) return;
  const status = document.querySelector(statusSelectors[view]);
  if (!status) return;
  status.textContent = text;
  status.hidden = text === "";
  status.className = error ? "status error" : "status";
}

function show(message, options = {}) {
  showIn(activeView, message, options);
}

function showView(view, { focus = true } = {}) {
  activeView = view;
  for (const [name, panel] of Object.entries(panels)) panel.hidden = name !== view;
  settingsLink.hidden = view === "settings" || view === "needsSettings";
  doneSettingsButton.hidden = view !== "settings";
  const statusSelector = statusSelectors[view];
  if (statusSelector) {
    const status = document.querySelector(statusSelector);
    status.textContent = viewMessages[view] ?? "";
    status.hidden = !status.textContent;
    status.className = viewErrors[view] ? "status error" : "status";
  }
  document.title = view === "request" ? "Approve request · creds"
    : view === "settings" ? "Settings · creds"
      : "creds";
  const heading = panels[view].querySelector("h1");
  if (focus && heading) heading.focus();
}

function showOutcome(message, { error = false } = {}) {
  outcomeMessage.textContent = message;
  outcomeMessage.className = error ? "error" : "";
  showView("outcome");
}

function approvalTimeLabel(milliseconds) {
  const totalSeconds = Math.ceil(milliseconds / 1_000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes && seconds) {
    return minutes + " minute" + (minutes === 1 ? "" : "s")
      + " " + seconds + " second" + (seconds === 1 ? "" : "s");
  }
  if (minutes) return minutes + " minute" + (minutes === 1 ? "" : "s");
  return seconds + " second" + (seconds === 1 ? "" : "s");
}

function operationLabel(operation) {
  return operation === "encrypt" ? "Encrypt" : "Decrypt";
}

function clearConnectionTimeout() {
  if (connectionTimeout !== null) clearTimeout(connectionTimeout);
  connectionTimeout = null;
}

function clearApprovalTimeout() {
  if (approvalTimeout !== null) clearTimeout(approvalTimeout);
  approvalTimeout = null;
}

function setSettingsEditable(editable) {
  const enabled = editable && !settingsInvalid && !settingsSaving;
  settingsControls.disabled = !enabled;
  suffixInput.disabled = !enabled;
  settingsSuffixInput.disabled = !enabled;
  createPasskeyButton.disabled = !enabled;
  resetSettingsButton.disabled = !editable;
}

function updateDestinationControls() {
  const enabled = !settingsSaving && !connectionInProgress && !destinationPanel.hidden && Boolean(pendingDestination);
  acceptDestinationButton.disabled = !enabled;
  declineDestinationButton.disabled = !enabled;
}

function renderAcceptedPrefixes() {
  acceptedPrefixesList.replaceChildren();
  for (const prefix of settings.acceptedPrefixes) {
    const row = document.createElement("li");
    const label = document.createElement("code");
    label.textContent = `${prefix}.${settings.suffix}`;
    const forget = document.createElement("button");
    forget.type = "button";
    forget.className = "button button-secondary button-small";
    forget.textContent = "Forget";
    forget.ariaLabel = `Forget ${prefix}.${settings.suffix}`;
    forget.addEventListener("click", () => { void forgetPrefix(prefix); });
    row.append(label, forget);
    acceptedPrefixesList.append(row);
  }
  acceptedEmpty.hidden = settings.acceptedPrefixes.length !== 0;
}

function updateDisplayedSettings({ syncInputs = false } = {}) {
  if (syncInputs) {
    suffixInput.value = settings.suffix;
    settingsSuffixInput.value = settings.suffix;
    publicKeyInput.value = settings.publicKey ?? "";
  }
  const hasKey = Boolean(settings.publicKey);
  document.querySelector("#saved-key-preview").textContent = hasKey
    ? `${settings.publicKey.slice(0, 12)}…${settings.publicKey.slice(-8)}`
    : "No key saved";
  document.querySelector("#saved-key-full").textContent = settings.publicKey ?? "No public setup key saved";
  document.querySelector("#copy-public-key").hidden = !hasKey;
  renderAcceptedPrefixes();
  setSettingsEditable(!connectionInProgress && !approvalSession?.isActive());
}

function showPendingPage() {
  showView("request");
  approveButton.disabled = true;
  retryConnectionButton.hidden = true;
  cancelButton.disabled = false;
}

function expireApproval() {
  approvalTimeout = null;
  if (!approvalSession?.isActive()) return;
  approvalExpired = true;
  approvalKey?.fill(0);
  approvalKey = null;
  approvalController?.abort();
  const expiredSession = approvalSession;
  expiredSession.close();
  approvalSession = null;
  approveButton.disabled = true;
  cancelButton.disabled = true;
  setSettingsEditable(true);
  showOutcome("Request expired. Start a new operation from your terminal.", { error: true });
}

async function writeSettings(next, options = {}) {
  settingsSaving = true;
  setSettingsEditable(false);
  updateDestinationControls();
  let valid;
  try {
    valid = await validateSettings(next);
  } catch (error) {
    settingsSaving = false;
    setSettingsEditable(true);
    updateDestinationControls();
    throw error;
  }
  settings = valid;
  try {
    settings = await saveSettings(valid);
    settingsInvalid = false;
    storageAvailable = true;
    setSettingsStatus(options.statusMessage ?? "Settings saved in this browser.");
  } catch {
    settingsInvalid = false;
    storageAvailable = false;
    setSettingsStatus("Settings could not be saved; changes apply to this page only.", { error: true });
  } finally {
    settingsSaving = false;
  }
  updateDisplayedSettings({ syncInputs: options.syncInputs ?? false });
  updateDestinationControls();
}

async function preparePendingHandoff() {
  if (!pendingHandoff || approvalCancelled || settingsInvalid) return;
  if (!settings.suffix) {
    showView("needsSettings");
    show("Save a machine DNS suffix to continue this request. The handoff stays in this page until then.");
    updateDestinationControls();
    return;
  }
  try {
    pendingDestination = buildHandoffDestination(pendingHandoff, settings.suffix);
  } catch (error) {
    showOutcome(`Invalid machine destination: ${error instanceof Error ? error.message : String(error)}`, { error: true });
    return;
  }

  document.querySelector("#destination-host").textContent = `${pendingDestination.fullHostname}:${pendingDestination.port}`;
  if (settings.acceptedPrefixes.includes(pendingDestination.prefix)) {
    destinationPanel.hidden = true;
    await beginConnection();
    return;
  }

  const full = settings.acceptedPrefixes.length >= MAX_ACCEPTED_PREFIXES;
  document.querySelector("#destination-note").textContent = full
    ? `The ${MAX_ACCEPTED_PREFIXES}-machine list is full. Continue once without remembering this machine; every request still needs approval.`
    : storageAvailable
      ? "Remembering skips this prompt; every request still needs approval."
      : "Storage is unavailable, so this choice lasts only for this page. Every request still needs approval.";
  acceptDestinationButton.textContent = full ? "Accept once and continue" : "Remember this machine and continue";
  destinationPanel.hidden = false;
  showView("destination");
  updateDestinationControls();
}

async function beginConnection() {
  if (!pendingHandoff || !pendingDestination || connectionInProgress || approvalSession?.isActive()) return;
  const destination = pendingDestination;
  connectionInProgress = true;
  approvalCancelled = false;
  approvalSent = false;
  approvalExpired = false;
  showView("request");
  destinationPanel.hidden = true;
  retryConnectionButton.hidden = true;
  updateDestinationControls();
  approveButton.disabled = true;
  cancelButton.disabled = false;
  setSettingsEditable(false);
  document.querySelector("#request-host").textContent = `${destination.fullHostname}:${destination.port}`;
  document.querySelector("#request-prefix").textContent = destination.prefix;
  document.querySelector("#request-suffix").textContent = destination.suffix;
  document.querySelector("#request-name").textContent = "Waiting for the CLI request";
  document.querySelector("#request-revision").textContent = "";
  document.querySelector("#request-operation").textContent = "Connecting";

  try {
    connectionController = new AbortController();
    connectionExpired = false;
    show("Connecting…");
    const connectionTimedOut = new Promise((_, reject) => {
      connectionTimeout = setTimeout(() => {
        connectionTimeout = null;
        connectionExpired = true;
        connectionController?.abort();
        reject(new DOMException("Connection setup exceeded 30 seconds.", "TimeoutError"));
      }, 30_000);
    });
    const connectedSession = await Promise.race([
      connectHandoff(destination, connectionController.signal),
      connectionTimedOut,
    ]);
    clearConnectionTimeout();
    if (approvalCancelled) {
      connectedSession.close();
      connectionInProgress = false;
      setSettingsEditable(true);
      return;
    }
    approvalSession = connectedSession;
    const { request } = connectedSession;
    document.querySelector("#request-name").textContent = request.name;
    document.querySelector("#request-revision").textContent = String(request.revision);
    document.querySelector("#request-operation").textContent = operationLabel(request.operation);
    connectionInProgress = false;
    showIn("request", `${destinationNotice ? `${destinationNotice} ` : ""}Approval window: ${approvalTimeLabel(request.approvalTimeoutMs)}.`);
    destinationNotice = "";
    approveButton.disabled = false;
    approvalExpired = false;
    approvalTimeout = setTimeout(expireApproval, request.approvalTimeoutMs);
    connectedSession.failed.then((error) => {
      if (approvalSession !== connectedSession) return;
      clearApprovalTimeout();
      approvalKey?.fill(0);
      approvalKey = null;
      if (approvalController) approvalController.abort();
      approveButton.disabled = true;
      cancelButton.disabled = true;
      connectionInProgress = false;
      approvalSession = null;
      setSettingsEditable(true);
      if (!approvalExpired && !approvalCancelled && !approvalSent) {
        showOutcome(`The CLI connection closed. ${error instanceof Error ? error.message : String(error)}`, { error: true });
      }
    });
  } catch (error) {
    clearConnectionTimeout();
    connectionInProgress = false;
    approvalSession = null;
    setSettingsEditable(true);
    if (approvalCancelled) return;
    showView("request");
    approveButton.disabled = true;
    cancelButton.disabled = false;
    retryConnectionButton.hidden = false;
    const failure = connectionExpired
      ? "Connection setup expired after 30 seconds. Retry if the CLI is still waiting, or cancel."
      : `Could not open the pinned CLI session: ${error instanceof Error ? error.message : String(error)}`;
    showIn("request", destinationNotice ? `${destinationNotice} ${failure}` : failure, { error: true });
  }
}

async function saveSuffix() {
  if (settingsInvalid || settingsSaving || connectionInProgress || approvalSession?.isActive()) return;
  const startedInSetup = activeView === "setup";
  const input = activeView === "settings" ? settingsSuffixInput : suffixInput;
  let suffix;
  try {
    suffix = input.value.trim() === "" ? "" : normalizeSuffix(input.value);
  } catch (error) {
    show(`Invalid machine DNS suffix: ${error instanceof Error ? error.message : String(error)}`, { error: true });
    return;
  }
  const changed = settings.suffix !== suffix;
  if (changed && settings.acceptedPrefixes.length > 0 && !confirm("Changing the machine DNS suffix clears all accepted destinations. Save this suffix?")) {
    return;
  }
  const next = { ...settings, suffix, acceptedPrefixes: changed ? [] : [...settings.acceptedPrefixes] };
  await writeSettings(next, {
    syncInputs: true,
    statusMessage: changed && settings.acceptedPrefixes.length > 0
      ? "Settings saved. Accepted destinations were cleared for the changed suffix."
      : "Settings saved in this browser.",
  });
  if (pendingHandoff) {
    await preparePendingHandoff();
  } else if (startedInSetup && activeView === "setup" && suffix) {
    showView("ready");
    if (!storageAvailable) show("Machine DNS suffix applies to this page only; it was not saved.", { error: true });
  } else {
    show(storageAvailable
      ? suffix ? "Machine DNS suffix saved." : "Machine DNS suffix cleared. Handoff connections are disabled until a suffix is saved."
      : "Settings could not be saved; the machine DNS suffix applies to this page only.", { error: !storageAvailable });
  }
}

async function savePublicKey(value, { created = false } = {}) {
  if (settingsInvalid || settingsSaving || connectionInProgress || approvalSession?.isActive()) return;
  settingsSaving = true;
  setSettingsEditable(false);
  updateDestinationControls();
  try {
    const publicKey = await validatePublicKey(value.trim());
    const replacing = settings.publicKey !== null && settings.publicKey !== publicKey;
    if (replacing && !confirm("Replacing the saved public key clears all accepted destinations. Save this public setup key? The CLI trust configuration will not change.")) {
      if (created) show("Passkey created and public key exported, but the saved browser key was not replaced.");
      return;
    }
    const next = {
      ...settings,
      publicKey,
      acceptedPrefixes: replacing ? [] : [...settings.acceptedPrefixes],
    };
    await writeSettings(next, {
      syncInputs: true,
      statusMessage: replacing
        ? "Public key saved. Accepted destinations were cleared. The CLI trust configuration is unchanged."
        : "Public key saved for future CLI setup. The CLI trust configuration is unchanged.",
    });
    show(storageAvailable
      ? created
        ? "Passkey created, PRF confirmed, and public key saved. Copy it from Settings for creds setup."
        : "Public key validated and saved for future CLI setup. Import does not enroll a passkey or change CLI trust."
      : "Settings could not be saved; the validated public key applies to this page only.", { error: !storageAvailable });
  } finally {
    settingsSaving = false;
    updateDisplayedSettings();
    updateDestinationControls();
  }
}

async function forgetPrefix(prefix) {
  if (settingsControls.disabled || settingsInvalid) return;
  const next = { ...settings, acceptedPrefixes: settings.acceptedPrefixes.filter((item) => item !== prefix) };
  await writeSettings(next, { statusMessage: `Forgot ${prefix}.${settings.suffix}.` });
}

async function acceptDestination() {
  if (!pendingDestination || settingsInvalid || settingsSaving || connectionInProgress) return;
  if (settings.acceptedPrefixes.length >= MAX_ACCEPTED_PREFIXES) {
    destinationPanel.hidden = true;
    destinationNotice = `Accepted once; the ${MAX_ACCEPTED_PREFIXES}-machine list is full, so this destination was not saved.`;
    await beginConnection();
    return;
  }
  const next = {
    ...settings,
    acceptedPrefixes: [...settings.acceptedPrefixes, pendingDestination.prefix],
  };
  acceptDestinationButton.disabled = true;
  declineDestinationButton.disabled = true;
  setSettingsEditable(false);
  await writeSettings(next, {
    statusMessage: storageAvailable
      ? `Remembered ${pendingDestination.fullHostname}. Each request still needs approval.`
      : "Settings could not be saved; changes apply to this page only.",
  });
  destinationPanel.hidden = true;
  updateDestinationControls();
  if (!storageAvailable) {
    destinationNotice = "This machine is accepted for this page only and was not remembered.";
  }
  await beginConnection();
}

function cancelRequest() {
  approvalCancelled = true;
  approvalSent = false;
  clearConnectionTimeout();
  clearApprovalTimeout();
  connectionController?.abort();
  approvalController?.abort();
  approvalSession?.close();
  approvalSession = null;
  pendingHandoff = null;
  pendingDestination = null;
  connectionInProgress = false;
  updateDestinationControls();
  retryConnectionButton.hidden = true;
  approveButton.disabled = true;
  cancelButton.disabled = true;
  setSettingsEditable(true);
  showOutcome("Request cancelled. No key was sent.");
}

function finishOutcome() {
  pendingHandoff = null;
  pendingDestination = null;
  connectionInProgress = false;
  approvalCancelled = false;
  approvalExpired = false;
  approvalSent = false;
  if (!approvalSession?.isActive()) approvalSession = null;
  setSettingsEditable(!approvalSession?.isActive());
  showView(settingsInvalid || !settings.suffix ? "setup" : "ready");
}

async function startApp() {
  const loaded = await loadSettings();
  if (loaded.status === "invalid") {
    settingsInvalid = true;
    settingsControls.disabled = true;
    suffixInput.disabled = true;
    settingsSuffixInput.disabled = true;
    createPasskeyButton.disabled = true;
    resetSettingsButton.disabled = false;
    setSettingsStatus("Stored browser settings need an explicit reset before saving or connecting.", { error: true });
  } else {
    settings = loaded.settings;
    storageAvailable = loaded.status === "ok";
    updateDisplayedSettings({ syncInputs: true });
    if (loaded.status === "unavailable") {
      setSettingsStatus("Settings could not be loaded; changes apply to this page only.", { error: true });
    } else if (settings.publicKey) {
      setSettingsStatus("Saved public settings loaded from this browser.");
    }
  }

  if (!startupFragment) {
    showView(settings.suffix && !settingsInvalid ? "ready" : "setup");
    if (settingsInvalid) show("Stored browser settings need an explicit reset in Settings.", { error: true });
    return;
  }
  showPendingPage();
  try {
    pendingHandoff = parseHandoffFragment(startupFragment, location);
  } catch (error) {
    pendingHandoff = null;
    showOutcome(`This request link is invalid. ${error instanceof Error ? error.message : String(error)}`, { error: true });
    return;
  }
  if (settingsInvalid) {
    showView("needsSettings");
    show("Stored browser settings need an explicit reset in Settings. The request link was removed and is not stored.", { error: true });
    return;
  }
  await preparePendingHandoff();
}

settingsLink.addEventListener("click", (event) => {
  event.preventDefault();
  if (activeView !== "settings") returnView = activeView;
  showView("settings");
  updateDisplayedSettings();
});
document.querySelectorAll("[data-open-settings]").forEach((link) => link.addEventListener("click", (event) => {
  event.preventDefault();
  returnView = activeView;
  showView("settings");
  updateDisplayedSettings();
}));
doneSettingsButton.addEventListener("click", () => showView(returnView));
document.querySelector("#save-settings").addEventListener("click", () => { void saveSuffix(); });
document.querySelector("#save-settings-from-page").addEventListener("click", () => { void saveSuffix(); });

createPasskeyButton.addEventListener("click", async (event) => {
  createPasskeyButton.disabled = true;
  show("Waiting for passkey creation and PRF confirmation…");
  try {
    const created = await createPasskey(passkeyLabelInput.value);
    await savePublicKey(created.publicKey, { created: true });
  } catch (error) {
    show(`${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}`, { error: true });
  } finally {
    createPasskeyButton.disabled = settingsInvalid || connectionInProgress || Boolean(approvalSession?.isActive()) || Boolean(settings.publicKey);
    event.currentTarget?.focus();
  }
});

document.querySelector("#copy-public-key").addEventListener("click", async () => {
  if (!settings.publicKey) {
    show("Create or import a public key first.");
    return;
  }
  try {
    await navigator.clipboard.writeText(settings.publicKey);
    show("Public key copied for creds setup.");
  } catch (error) {
    publicKeyInput.value = settings.publicKey;
    publicKeyInput.select();
    show(`Clipboard access failed: ${error instanceof Error ? error.message : String(error)}. Select and copy the public key from Import or replace public key.`, { error: true });
  }
});

document.querySelector("#save-public-key").addEventListener("click", () => {
  void savePublicKey(publicKeyInput.value).catch((error) => show(`Public key was not saved: ${error instanceof Error ? error.message : String(error)}`, { error: true }));
});
acceptDestinationButton.addEventListener("click", () => { void acceptDestination(); });
declineDestinationButton.addEventListener("click", cancelRequest);
cancelButton.addEventListener("click", cancelRequest);
document.querySelector("#cancel-needs-settings").addEventListener("click", cancelRequest);
retryConnectionButton.addEventListener("click", () => { void preparePendingHandoff(); });
document.querySelector("#outcome-done").addEventListener("click", finishOutcome);

resetSettingsButton.addEventListener("click", () => {
  if (settingsSaving || connectionInProgress || approvalSession?.isActive()) return;
  if (!confirm("Reset the public browser settings saved on this origin? This does not remove the passkey or change CLI setup.")) return;
  settings = emptySettings();
  settingsInvalid = false;
  try {
    resetSettings();
    storageAvailable = true;
    setSettingsStatus("Browser settings reset. Passkeys and CLI setup are unchanged.");
  } catch {
    storageAvailable = false;
    setSettingsStatus("Settings could not be saved; changes apply to this page only. The stored record may reappear after reload.", { error: true });
  }
  updateDisplayedSettings({ syncInputs: true });
  if (pendingHandoff) void preparePendingHandoff();
  else show("Browser settings reset. Configure the machine DNS suffix before using a handoff.");
});

approveButton.addEventListener("click", async () => {
  if (!approvalSession?.isActive()) {
    showIn("request", approvalSession?.failure()?.message ?? "The CLI approval session is closed.", { error: true });
    approveButton.disabled = true;
    return;
  }
  approveButton.disabled = true;
  approvalController = new AbortController();
  showIn("request", "Confirm with your passkey…");
  let key;
  try {
    const approved = await createApprovalAssertion(approvalSession.request, approvalController.signal);
    if (approvalController.signal.aborted) {
      throw new DOMException(approvalExpired ? "Approval window expired." : "Approval was cancelled.", approvalExpired ? "TimeoutError" : "AbortError");
    }
    key = approved.key;
    if (!approvalSession?.isActive()) {
      throw approvalSession?.failure() ?? new Error("The CLI approval session is closed.");
    }
    approvalKey = key;
    cancelButton.disabled = true;
    await approvalSession.sendKey(key, approved.assertion);
    if (approvalExpired) throw new DOMException("Approval window expired.", "TimeoutError");
    clearApprovalTimeout();
    approvalSent = true;
    setSettingsEditable(!approvalSession?.isActive());
    showOutcome("Approval sent. Check your terminal.");
  } catch (error) {
    if (approvalExpired) {
      showOutcome("Request expired. Start a new operation from your terminal.", { error: true });
    } else if (approvalCancelled) {
      showOutcome("Request cancelled. No key was sent.");
    } else {
      showIn("request", `Approval failed: ${error instanceof Error ? error.message : String(error)}`, { error: true });
    }
    if (!approvalSession?.isActive()) cancelButton.disabled = true;
    else approveButton.disabled = false;
  } finally {
    key?.fill(0);
    if (approvalKey === key) approvalKey = null;
    approvalController = null;
  }
});

for (const panel of Object.values(panels)) panel.hidden = true;
setSettingsEditable(false);
void startApp();
