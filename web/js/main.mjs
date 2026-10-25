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
const setupCreatePasskeyButton = document.querySelector("#setup-create-passkey");
const setupUseExistingButton = document.querySelector("#setup-use-existing");
const setupBackButton = document.querySelector("#setup-back");
const setupSaveSettingsButton = document.querySelector("#save-settings");
const needsSettingsSaveButton = document.querySelector("#save-needs-settings");
const setupSavePublicKeyButton = document.querySelector("#save-setup-public-key");
const copySetupPublicKeyButton = document.querySelector("#copy-setup-public-key");
const setupChoice = document.querySelector("#setup-choice");
const setupFlow = document.querySelector("#setup-flow");
const setupTitle = document.querySelector("#setup-title");
const setupCreatedKey = document.querySelector("#setup-created-key");
const setupExistingNote = document.querySelector("#setup-existing-note");
const setupImportKey = document.querySelector("#setup-import-key");
const setupPublicKey = document.querySelector("#setup-public-key");
const setupPublicKeyInput = document.querySelector("#setup-public-key-input");
const needsSettingsForm = document.querySelector("#needs-settings-form");
const needsSettingsInvalid = document.querySelector("#needs-settings-invalid");
const needsSettingsSuffixInput = document.querySelector("#needs-settings-suffix");
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
let requestGeneration = 0;
let destinationNotice = "";
let activeView = "setup";
let returnView = "ready";
let setupMode = "choice";
let createdSetupPublicKey = null;
let setupPasskeyCreating = false;
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

function showSetupMode(mode, { focus = true } = {}) {
  setupMode = mode;
  setupChoice.hidden = mode !== "choice";
  setupFlow.hidden = mode === "choice";
  setupCreatedKey.hidden = mode !== "created";
  setupExistingNote.hidden = mode !== "existing";
  setupImportKey.hidden = mode !== "existing";
  if (mode !== "existing") setupImportKey.open = false;
  setupTitle.textContent = mode === "created" ? "Create passkey"
    : mode === "existing" ? "Use existing passkey"
      : "Set up this browser";
  if (focus && activeView === "setup") setupTitle.focus();
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
  needsSettingsSuffixInput.disabled = !enabled;
  setupCreatePasskeyButton.disabled = !enabled || setupPasskeyCreating;
  setupUseExistingButton.disabled = !enabled || setupPasskeyCreating;
  setupBackButton.disabled = !enabled || setupPasskeyCreating;
  setupSaveSettingsButton.disabled = !enabled;
  needsSettingsSaveButton.disabled = !enabled;
  setupSavePublicKeyButton.disabled = !enabled;
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
    needsSettingsSuffixInput.value = settings.suffix;
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

function expireApproval(session, generation) {
  if (generation !== requestGeneration || approvalSession !== session || !session?.isActive()) return;
  approvalTimeout = null;
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
    needsSettingsForm.hidden = false;
    needsSettingsInvalid.hidden = true;
    needsSettingsSuffixInput.value = settings.suffix;
    showView("needsSettings");
    show("The handoff stays in this page while you save the suffix.");
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
  const generation = ++requestGeneration;
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
    const controller = connectionController;
    connectionExpired = false;
    show("Connecting…");
    const connectionTimedOut = new Promise((_, reject) => {
      connectionTimeout = setTimeout(() => {
        if (generation !== requestGeneration) return;
        connectionTimeout = null;
        connectionExpired = true;
        controller.abort();
        reject(new DOMException("Connection setup exceeded 30 seconds.", "TimeoutError"));
      }, 30_000);
    });
    const connectedSession = await Promise.race([
      connectHandoff(destination, controller.signal),
      connectionTimedOut,
    ]);
    if (generation !== requestGeneration) {
      connectedSession.close();
      return;
    }
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
    approvalTimeout = setTimeout(() => expireApproval(connectedSession, generation), request.approvalTimeoutMs);
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
      if (generation === requestGeneration && !approvalExpired && !approvalCancelled && !approvalSent) {
        showOutcome(`The CLI connection closed. ${error instanceof Error ? error.message : String(error)}`, { error: true });
      }
    });
  } catch (error) {
    if (generation !== requestGeneration) return;
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
  const input = activeView === "settings" ? settingsSuffixInput
    : activeView === "needsSettings" ? needsSettingsSuffixInput
      : suffixInput;
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
      return false;
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
        ? "Passkey created, PRF confirmed, and public key saved."
        : "Public key validated and saved for setup convenience. Import does not enroll a key with the CLI or prove possession."
      : "Settings could not be saved; the validated public key applies to this page only.", { error: !storageAvailable });
    return true;
  } finally {
    settingsSaving = false;
    updateDisplayedSettings();
    updateDestinationControls();
  }
}

async function createSetupPasskey() {
  if (setupPasskeyCreating || settingsInvalid || settingsSaving) return;
  setupPasskeyCreating = true;
  setSettingsEditable(!connectionInProgress && !approvalSession?.isActive());
  show("Waiting for passkey creation and PRF confirmation…");
  try {
    const created = await createPasskey(passkeyLabelInput.value);
    createdSetupPublicKey = created.publicKey;
    setupPublicKey.value = created.publicKey;
    const saved = await savePublicKey(created.publicKey, { created: true });
    showSetupMode("created");
    show(saved
      ? storageAvailable ? "" : "The exported key is available for this page only; browser settings could not be saved."
      : "The saved browser key was kept. The exported key below is available if you want to configure the CLI with the new passkey.",
      { error: !saved || !storageAvailable });
  } catch (error) {
    show(`${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}`, { error: true });
  } finally {
    setupPasskeyCreating = false;
    setSettingsEditable(!connectionInProgress && !approvalSession?.isActive());
    if (activeView === "setup" && setupMode === "choice") setupCreatePasskeyButton.focus();
  }
}

async function copySetupPublicKey() {
  if (!createdSetupPublicKey) {
    show("Create a passkey first to export its public key.");
    return;
  }
  try {
    await navigator.clipboard.writeText(createdSetupPublicKey);
    show("Public key copied. Run creds setup to configure the CLI.");
  } catch (error) {
    setupPublicKey.focus();
    setupPublicKey.select();
    show(`Clipboard access failed: ${error instanceof Error ? error.message : String(error)}. Select and copy the exported public key.`, { error: true });
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
  requestGeneration += 1;
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
  requestGeneration += 1;
  clearConnectionTimeout();
  clearApprovalTimeout();
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
    needsSettingsSuffixInput.disabled = true;
    setupCreatePasskeyButton.disabled = true;
    setupUseExistingButton.disabled = true;
    setupSaveSettingsButton.disabled = true;
    needsSettingsSaveButton.disabled = true;
    setupSavePublicKeyButton.disabled = true;
    createPasskeyButton.disabled = true;
    resetSettingsButton.disabled = false;
    needsSettingsForm.hidden = true;
    needsSettingsInvalid.hidden = false;
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
    showSetupMode("choice", { focus: false });
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
    needsSettingsForm.hidden = true;
    needsSettingsInvalid.hidden = false;
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
setupCreatePasskeyButton.addEventListener("click", () => { void createSetupPasskey(); });
setupUseExistingButton.addEventListener("click", () => {
  suffixInput.value = settings.suffix;
  setupPublicKeyInput.value = "";
  showSetupMode("existing");
});
setupBackButton.addEventListener("click", () => {
  showIn("setup", "");
  showSetupMode("choice");
});
setupSaveSettingsButton.addEventListener("click", () => { void saveSuffix(); });
needsSettingsSaveButton.addEventListener("click", () => { void saveSuffix(); });
copySetupPublicKeyButton.addEventListener("click", () => { void copySetupPublicKey(); });
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
setupSavePublicKeyButton.addEventListener("click", () => {
  void savePublicKey(setupPublicKeyInput.value).catch((error) => show(`Public key was not saved: ${error instanceof Error ? error.message : String(error)}`, { error: true }));
});
acceptDestinationButton.addEventListener("click", () => { void acceptDestination(); });
declineDestinationButton.addEventListener("click", cancelRequest);
cancelButton.addEventListener("click", cancelRequest);
document.querySelector("#cancel-needs-settings").addEventListener("click", cancelRequest);
document.querySelector("#cancel-invalid-settings").addEventListener("click", cancelRequest);
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
  const generation = requestGeneration;
  const session = approvalSession;
  const controller = new AbortController();
  approveButton.disabled = true;
  approvalController = controller;
  showIn("request", "Confirm with your passkey…");
  let key;
  try {
    const approved = await createApprovalAssertion(session.request, controller.signal);
    key = approved.key;
    if (generation !== requestGeneration) return;
    if (controller.signal.aborted) {
      throw new DOMException(approvalExpired ? "Approval window expired." : "Approval was cancelled.", approvalExpired ? "TimeoutError" : "AbortError");
    }
    if (!session.isActive()) {
      throw session.failure() ?? new Error("The CLI approval session is closed.");
    }
    approvalKey = key;
    cancelButton.disabled = true;
    await session.sendKey(key, approved.assertion);
    if (generation !== requestGeneration || approvalSession !== session) return;
    if (approvalExpired) throw new DOMException("Approval window expired.", "TimeoutError");
    clearApprovalTimeout();
    approvalSent = true;
    setSettingsEditable(!approvalSession?.isActive());
    showOutcome("Approval sent. Check your terminal.");
  } catch (error) {
    if (generation !== requestGeneration || approvalSession !== session) return;
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
    if (approvalController === controller) approvalController = null;
  }
});

for (const panel of Object.values(panels)) panel.hidden = true;
setSettingsEditable(false);
void startApp();
