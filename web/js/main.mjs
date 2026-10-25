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

const result = document.querySelector("#result");
const approvalPanel = document.querySelector("#approval-panel");
const destinationPanel = document.querySelector("#destination-panel");
const setupPanel = document.querySelector("#setup-panel");
const settingsControls = document.querySelector("#settings-controls");
const settingsStatus = document.querySelector("#settings-status");
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
const acceptedPrefixesList = document.querySelector("#accepted-prefixes");
const acceptedEmpty = document.querySelector("#accepted-empty");

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
let connectionInProgress = false;
let connectionTimeout = null;
let approvalTimeout = null;
let connectionExpired = false;
let approvalExpired = false;
let approvalKey = null;

const startupFragment = location.hash;
if (startupFragment) history.replaceState(null, "", `${location.pathname}${location.search}`);

function show(value) {
  result.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function setSettingsStatus(message) {
  settingsStatus.textContent = message;
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
    label.textContent = prefix;
    const forget = document.createElement("button");
    forget.type = "button";
    forget.className = "secondary";
    forget.textContent = "Forget";
    forget.disabled = settingsControls.disabled;
    forget.addEventListener("click", () => { void forgetPrefix(prefix); });
    row.append(label, forget);
    acceptedPrefixesList.append(row);
  }
  acceptedEmpty.hidden = settings.acceptedPrefixes.length !== 0;
}

function updateDisplayedSettings({ syncInputs = false } = {}) {
  if (syncInputs) {
    suffixInput.value = settings.suffix;
    publicKeyInput.value = settings.publicKey ?? "";
  }
  renderAcceptedPrefixes();
  setSettingsEditable(!connectionInProgress && !approvalSession?.isActive());
}

function showPendingPage() {
  approvalPanel.hidden = false;
  setupPanel.hidden = true;
  document.querySelector("#eyebrow").textContent = "creds · request approval";
  document.querySelector("#page-title").textContent = "Approve a creds request";
  document.querySelector("#page-intro").textContent = "Review the destination and exact request. A passkey approval is required for every key release.";
  document.title = "Approve creds request";
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
  approvalSession.close();
  approveButton.disabled = true;
  cancelButton.disabled = true;
  show("The CLI approval window expired. Start a new CLI operation.");
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
  } catch (error) {
    settingsInvalid = false;
    storageAvailable = false;
    setSettingsStatus("Settings could not be saved; changes apply to this page only.");
  } finally {
    settingsSaving = false;
  }
  updateDisplayedSettings({ syncInputs: options.syncInputs ?? false });
  updateDestinationControls();
}

async function preparePendingHandoff() {
  if (!pendingHandoff || approvalCancelled || settingsInvalid) return;
  if (!settings.suffix) {
    destinationPanel.hidden = true;
    updateDestinationControls();
    show("Save a machine DNS suffix in Browser settings to continue. The QR handoff stays only in this page until then.");
    return;
  }
  try {
    pendingDestination = buildHandoffDestination(pendingHandoff, settings.suffix);
  } catch (error) {
    destinationPanel.hidden = true;
    updateDestinationControls();
    show(`Invalid machine destination: ${error instanceof Error ? error.message : String(error)}`);
    return;
  }

  document.querySelector("#destination-prefix").textContent = pendingDestination.prefix;
  document.querySelector("#destination-suffix").textContent = pendingDestination.suffix;
  document.querySelector("#destination-host").textContent = `${pendingDestination.fullHostname}:${pendingDestination.port}`;
  if (settings.acceptedPrefixes.includes(pendingDestination.prefix)) {
    destinationPanel.hidden = true;
    await beginConnection();
    return;
  }

  const full = settings.acceptedPrefixes.length >= MAX_ACCEPTED_PREFIXES;
  document.querySelector("#destination-note").textContent = full
    ? `The ${MAX_ACCEPTED_PREFIXES}-prefix list is full. You can accept ${pendingDestination.prefix}.${pendingDestination.suffix} once without remembering it.`
    : storageAvailable
      ? "Accepting remembers this prefix and suffix. It does not approve a secret request."
      : "Storage is unavailable. Acceptance applies to this page only and will not be remembered after it closes.";
  acceptDestinationButton.textContent = full ? "Accept once and continue" : "Accept this destination";
  destinationPanel.hidden = false;
  updateDestinationControls();
  show("Review the unfamiliar destination. Accepting it only allows the pinned connection; it never approves a secret request.");
}

async function beginConnection() {
  if (!pendingHandoff || !pendingDestination || connectionInProgress || approvalSession?.isActive()) return;
  connectionInProgress = true;
  approvalCancelled = false;
  approvalPanel.hidden = false;
  destinationPanel.hidden = true;
  retryConnectionButton.hidden = true;
  updateDestinationControls();
  approveButton.disabled = true;
  cancelButton.disabled = false;
  setSettingsEditable(false);
  document.querySelector("#request-host").textContent = `${pendingDestination.fullHostname}:${pendingDestination.port}`;
  document.querySelector("#request-prefix").textContent = pendingDestination.prefix;
  document.querySelector("#request-suffix").textContent = pendingDestination.suffix;
  document.querySelector("#request-name").textContent = "Waiting for the pinned CLI request";
  document.querySelector("#request-revision").textContent = "";
  document.querySelector("#request-operation").textContent = "";

  try {
    connectionController = new AbortController();
    connectionExpired = false;
    show("Connecting to the pinned CLI. Connection setup must finish within 30 seconds…");
    const connectionTimedOut = new Promise((_, reject) => {
      connectionTimeout = setTimeout(() => {
        connectionTimeout = null;
        connectionExpired = true;
        connectionController?.abort();
        reject(new DOMException("Connection setup exceeded 30 seconds.", "TimeoutError"));
      }, 30_000);
    });
    approvalSession = await Promise.race([
      connectHandoff(pendingDestination, connectionController.signal),
      connectionTimedOut,
    ]);
    clearConnectionTimeout();
    if (approvalCancelled) {
      approvalSession.close();
      approvalSession = null;
      connectionInProgress = false;
      setSettingsEditable(true);
      return;
    }
    const { request } = approvalSession;
    document.querySelector("#request-name").textContent = request.name;
    document.querySelector("#request-revision").textContent = String(request.revision);
    document.querySelector("#request-operation").textContent = request.operation;
    connectionInProgress = false;
    show("Request established with the pinned CLI. Check the hostname, prefix, suffix, name, revision, and operation before you approve within "
      + approvalTimeLabel(request.approvalTimeoutMs) + ".");
    approveButton.disabled = false;
    approvalExpired = false;
    approvalTimeout = setTimeout(expireApproval, request.approvalTimeoutMs);
    approvalSession.failed.then((error) => {
      clearApprovalTimeout();
      approvalKey?.fill(0);
      approvalKey = null;
      if (approvalController) approvalController.abort();
      approveButton.disabled = true;
      cancelButton.disabled = true;
      connectionInProgress = false;
      setSettingsEditable(true);
      if (!approvalExpired && !approvalCancelled) {
        show(`Approval session closed by the CLI. The request may have expired or been cancelled: ${error instanceof Error ? error.message : String(error)}`);
      }
    });
  } catch (error) {
    clearConnectionTimeout();
    connectionInProgress = false;
    approvalSession = null;
    setSettingsEditable(true);
    if (approvalCancelled) return;
    approveButton.disabled = true;
    cancelButton.disabled = false;
    retryConnectionButton.hidden = false;
    show(connectionExpired
      ? "Connection setup expired after 30 seconds. Retry if the CLI is still waiting, or cancel and start a new operation."
      : `Could not open the pinned CLI session: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function saveSuffix() {
  if (settingsInvalid || settingsSaving || connectionInProgress || approvalSession?.isActive()) return;
  let suffix;
  try {
    suffix = suffixInput.value.trim() === "" ? "" : normalizeSuffix(suffixInput.value);
  } catch (error) {
    show(`Invalid machine DNS suffix: ${error instanceof Error ? error.message : String(error)}`);
    return;
  }
  const changed = settings.suffix !== suffix;
  if (changed && settings.acceptedPrefixes.length > 0 && !confirm("Changing the machine DNS suffix clears all accepted destinations. Save this suffix?")) {
    return;
  }
  const next = { ...settings, suffix, acceptedPrefixes: changed ? [] : [...settings.acceptedPrefixes] };
  await writeSettings(next, {
    syncInputs: false,
    statusMessage: changed && settings.acceptedPrefixes.length > 0
      ? "Settings saved. Accepted destinations were cleared for the changed suffix."
      : "Settings saved in this browser.",
  });
  show(storageAvailable
    ? suffix ? "Machine DNS suffix saved." : "Machine DNS suffix cleared. Handoff connections are disabled until a suffix is saved."
    : "Settings could not be saved; the machine DNS suffix applies to this page only.");
  if (pendingHandoff) await preparePendingHandoff();
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
      syncInputs: false,
      statusMessage: replacing
        ? "Public key saved. Accepted destinations were cleared. The CLI trust configuration is unchanged."
        : "Public key saved for future CLI setup. The CLI trust configuration is unchanged.",
    });
    show(storageAvailable
      ? created
        ? "Passkey created, PRF confirmed, and public key exported. The public key is saved for future CLI setup."
        : "Public key validated and saved for future CLI setup. Import does not enroll a passkey or change CLI trust."
      : "Settings could not be saved; the validated public key applies to this page only.");
  } finally {
    settingsSaving = false;
    updateDisplayedSettings();
    updateDestinationControls();
  }
}

async function forgetPrefix(prefix) {
  if (settingsControls.disabled || settingsInvalid) return;
  const next = { ...settings, acceptedPrefixes: settings.acceptedPrefixes.filter((item) => item !== prefix) };
  await writeSettings(next, { statusMessage: `Forgot ${prefix}.` });
  show(`Forgot ${prefix}. Future handoffs from this prefix require acceptance again.`);
}

async function acceptDestination() {
  if (!pendingDestination || settingsInvalid || settingsSaving || connectionInProgress) return;
  if (settings.acceptedPrefixes.length >= MAX_ACCEPTED_PREFIXES) {
    destinationPanel.hidden = true;
    const message = `Accepted ${pendingDestination.prefix}.${pendingDestination.suffix} once. The ${MAX_ACCEPTED_PREFIXES}-prefix list is full, so it was not saved.`;
    setSettingsStatus(message);
    show(message);
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
      ? `Remembered ${pendingDestination.prefix}.${pendingDestination.suffix}. Each request still needs approval.`
      : "Settings could not be saved; changes apply to this page only.",
  });
  destinationPanel.hidden = true;
  updateDestinationControls();
  if (storageAvailable) {
    show(`Accepted and remembered ${pendingDestination.prefix}.${pendingDestination.suffix}. Each request still needs passkey approval.`);
  } else {
    const message = `Accepted ${pendingDestination.prefix}.${pendingDestination.suffix} for this page. Storage failed, so it was not remembered.`;
    setSettingsStatus(message);
    show(message);
  }
  await beginConnection();
}

function cancelRequest() {
  approvalCancelled = true;
  clearConnectionTimeout();
  clearApprovalTimeout();
  connectionController?.abort();
  approvalController?.abort();
  approvalSession?.close();
  pendingHandoff = null;
  pendingDestination = null;
  connectionInProgress = false;
  destinationPanel.hidden = true;
  updateDestinationControls();
  retryConnectionButton.hidden = true;
  approveButton.disabled = true;
  cancelButton.disabled = true;
  setSettingsEditable(true);
  show("Approval cancelled. No key was sent.");
}

async function startApp() {
  const loaded = await loadSettings();
  if (loaded.status === "invalid") {
    settingsInvalid = true;
    settingsControls.disabled = true;
    createPasskeyButton.disabled = true;
    resetSettingsButton.disabled = false;
    setSettingsStatus("Stored browser settings are malformed or use an unsupported version. Reset them explicitly before saving or connecting.");
  } else {
    settings = loaded.settings;
    storageAvailable = loaded.status === "ok";
    updateDisplayedSettings({ syncInputs: true });
    if (loaded.status === "unavailable") {
      setSettingsStatus("Settings could not be loaded; changes apply to this page only.");
    } else if (settings.publicKey) {
      setSettingsStatus("Saved public settings loaded from this browser.");
    }
  }

  if (!startupFragment) return;
  showPendingPage();
  try {
    pendingHandoff = parseHandoffFragment(startupFragment, location);
  } catch (error) {
    pendingHandoff = null;
    cancelButton.disabled = true;
    show(`Invalid handoff URL: ${error instanceof Error ? error.message : String(error)}`);
    return;
  }
  if (settingsInvalid) {
    show("Stored browser settings need an explicit reset before this handoff can continue. The QR fragment has been removed and is not stored.");
    return;
  }
  await preparePendingHandoff();
}

createPasskeyButton.addEventListener("click", async (event) => {
  createPasskeyButton.disabled = true;
  show("Waiting for passkey creation and PRF confirmation…");
  try {
    const created = await createPasskey(passkeyLabelInput.value);
    publicKeyInput.value = created.publicKey;
    await savePublicKey(created.publicKey, { created: true });
  } catch (error) {
    show(`${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}`);
  } finally {
    createPasskeyButton.disabled = settingsInvalid || connectionInProgress || Boolean(approvalSession?.isActive());
    event.currentTarget?.focus();
  }
});

document.querySelector("#copy-public-key").addEventListener("click", async () => {
  if (!publicKeyInput.value) {
    show("Create or enter a public key first. The key will appear in the field above.");
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

document.querySelector("#save-settings").addEventListener("click", () => { void saveSuffix(); });
document.querySelector("#save-public-key").addEventListener("click", () => {
  void savePublicKey(publicKeyInput.value).catch((error) => show(`Public key was not saved: ${error instanceof Error ? error.message : String(error)}`));
});
acceptDestinationButton.addEventListener("click", () => { void acceptDestination(); });
declineDestinationButton.addEventListener("click", cancelRequest);
cancelButton.addEventListener("click", cancelRequest);
retryConnectionButton.addEventListener("click", () => { void preparePendingHandoff(); });

resetSettingsButton.addEventListener("click", () => {
  if (settingsSaving || connectionInProgress || approvalSession?.isActive()) return;
  if (!confirm("Reset the public browser settings saved on this origin? This does not remove the passkey or change CLI setup.")) return;
  settings = emptySettings();
  settingsInvalid = false;
  suffixInput.value = "";
  publicKeyInput.value = "";
  try {
    resetSettings();
    storageAvailable = true;
    setSettingsStatus("Browser settings reset. Passkeys and CLI setup are unchanged.");
  } catch {
    storageAvailable = false;
    setSettingsStatus("Settings could not be saved; changes apply to this page only. The stored record may reappear after reload.");
  }
  updateDisplayedSettings({ syncInputs: true });
  show("Browser settings reset. Configure the machine DNS suffix before using a handoff.");
  if (pendingHandoff) void preparePendingHandoff();
});

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
    if (approvalController.signal.aborted) {
      throw new DOMException(approvalExpired ? "Approval window expired." : "Approval was cancelled.", approvalExpired ? "TimeoutError" : "AbortError");
    }
    key = approved.key;
    if (!approvalSession.isActive()) {
      throw approvalSession.failure() ?? new Error("The CLI approval session is closed.");
    }
    approvalKey = key;
    cancelButton.disabled = true;
    await approvalSession.sendKey(key, approved.assertion);
    if (approvalExpired) throw new DOMException("Approval window expired.", "TimeoutError");
    clearApprovalTimeout();
    show("Approval sent. Check the CLI for the operation result.");
    cancelButton.disabled = true;
  } catch (error) {
    if (approvalExpired) {
      show("The CLI approval window expired. Start a new CLI operation.");
    } else if (approvalCancelled) {
      show("Approval cancelled. No key was sent.");
    } else {
      show(`Approval failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (!approvalSession?.isActive()) cancelButton.disabled = true;
    else approveButton.disabled = false;
  } finally {
    key?.fill(0);
    if (approvalKey === key) approvalKey = null;
    approvalController = null;
  }
});

setSettingsEditable(false);
void startApp();
