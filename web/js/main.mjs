import { testMismatchedPin, testPinnedEcho } from "./transport.mjs";
import { testPrfApi } from "./webauthn.mjs";

const result = document.querySelector("#result");
const buttons = [...document.querySelectorAll("button")];
const endpointInput = document.querySelector("#endpoint");
const hashInput = document.querySelector("#certificate-hash");
let matchingPinTarget = null;

function show(value) {
  result.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function run(button, action) {
  buttons.forEach((item) => { item.disabled = true; });
  show("Running browser API probe…");
  try {
    show(await action());
  } catch (error) {
    show(`${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}\n\nCheck the browser console and confirm the local listener is running.`);
  } finally {
    buttons.forEach((item) => { item.disabled = false; });
    button.focus();
  }
}

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
