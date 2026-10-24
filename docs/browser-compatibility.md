# Local browser compatibility probes

These experiments cover the local browser probes and the first authenticated handoff implementation. The Rust listener and Python static-file server run on loopback. They do not provide an application backend.

## Observed runner results

Run date: 2026-10-24.

| Component | Version |
| --- | --- |
| Chromium | 156.0.8078.47 |
| chrome-devtools | 1.12.0 |
| Rust | 1.98.1 |
| Node.js | 24.17.0 |
| Python | 3.13.5 |

## Automated browser coverage

`./scripts/test.sh` runs the browser-module tests under Node.js. `main.test.mjs` uses a lightweight fake DOM and mocked handoff sessions to cover request display, cancel during connection and WebAuthn, session loss, and the one-approval send path. `transport.test.mjs` uses a mocked WebTransport implementation for framing, pin configuration, extra data, and failure handling. `webauthn.test.mjs` supplies mocked WebAuthn responses for PRF and assertion construction. These tests check application control flow; they do not stand in for a browser or authenticator.

The Rust `command_flow` integration test starts the compiled CLI and connects a Rust WebTransport client to the actual loopback listener. It covers file and stdin/stdout flows, replacement snapshots, rejected assertions, mismatched keys, cancellation, and preservation of existing ciphertext and output files. Its deterministic signing key and generated assertion are protocol fixtures; this test does not exercise browser WebAuthn or a passkey device.

The Chromium experiments below exercise WebTransport, WebAuthn, PRF, and public-key export through Chromium's real APIs with a CDP-controlled virtual CTAP 2.1 authenticator. They remain loopback tests with a virtual authenticator. Physical passkeys, provider-specific PRF behavior, cross-device use, deployment DNS, and deployed UDP reachability remain manual compatibility checks.

### WebTransport and certificate hash

Chromium connected to the Rust `wtransport` listener with the printed SHA-256 certificate hash. It opened a bidirectional stream, sent the fixed probe message, and received the exact echo. This exercised Chromium's WebTransport API and a real local HTTP/3/WebTransport session. The listener does not implement the creds wire protocol.

Chromium then tried the same URL with one bit changed in the expected certificate hash. The session failed with `WebTransportError: Opening handshake failed`; the browser console reported `QUIC_TLS_CERTIFICATE_UNKNOWN`. The positive case completed first against the same live endpoint.

The local self-signed certificate was permitted with the browser's local insecure-certificate test setting (`--ignore-certificate-errors` for direct Chromium launch, and `--acceptInsecureCerts true` in the Chrome DevTools controlled context). The mismatched hash still failed in both checks. These settings permit the local test certificate; they do not replace the `serverCertificateHashes` check. The authenticated handoff below also uses the hash pin and checks the configured Origin.

### WebAuthn PRF

The page created a discoverable ES256 test credential for RP ID `localhost`, then called `navigator.credentials.get()` twice with the same PRF input. Each assertion names the credential held in the current page session with `allowCredentials`. This avoids an authenticator account chooser when the virtual authenticator holds multiple test credentials. Later PRF checks in the same page reuse the in-memory credential. Chromium reported PRF enabled, returned 32 bytes on both assertions, and the page confirmed that both results matched.

This used the real Chromium WebAuthn and PRF APIs with a CDP-controlled virtual CTAP 2.1 authenticator. The virtual authenticator had resident-key, user-verification, automatic-presence, and PRF support enabled. The browser generated the credential and authenticator responses. This was not a JavaScript mock, a physical authenticator, or a real passkey-provider test. The page keeps the test credential object in memory for repeat checks, zeroes its in-page PRF result copies after comparison, and writes nothing to browser storage.

The PRF input in this probe is a local test string. This check does not verify discoverable credential selection without `allowCredentials`, the proposal's production key derivation, assertion verification, or byte-level vectors.

### Passkey creation and public-key export

Run date: 2026-10-24. Chromium 156 created a discoverable ES256 credential through the **Create passkey** action with required user verification, no attestation, and the PRF extension. The page confirmed that PRF returned 32 bytes. `getPublicKeyAlgorithm()` returned `-7`, and `getPublicKey()` returned DER SubjectPublicKeyInfo bytes that the page displayed as unpadded base64url. The exported key was accepted by `creds setup`, and `creds check` reported its SHA-256 fingerprint.

This used the real Chromium WebAuthn APIs with a temporary CDP-controlled CTAP 2.1 virtual authenticator configured for resident keys, user verification, automatic presence, and PRF. This does not establish physical authenticator, passkey-provider, or cross-device compatibility.

### Authenticated handoff

Run date: 2026-10-24. Chromium 156 connected to a per-operation Rust WebTransport listener with the certificate hash from the QR fragment. The page removed the fragment, displayed `workstation.localhost`, the exact name, revision, and operation, and required an explicit approval click. The configured Origin was `https://localhost:8000`. The CLI accepted the assertion from the same connection, encrypted revision 1, then decrypted it in a second approved operation. The decrypted output matched the source byte-for-byte, including a NUL byte.

This used the CDP-controlled CTAP 2.1 virtual authenticator with PRF support. The runner's system resolver did not resolve `workstation.localhost`; Chromium needed `--host-resolver-rules='MAP workstation.localhost 127.0.0.1'`. That local mapping made the loopback smoke test possible. It does not establish that deployment DNS or UDP reachability works.

The installed `chrome-devtools` 1.12.0 CLI returned after `start`, and `status` reported no running daemon in this runner. The page action was exercised through a direct CDP WebSocket connection instead. The runner had no physical authenticator or deployed network to test.

## Reproduce the probes

Use five terminals from the repository root. Keep each long-running process open during the experiment.

1. Start the Rust listener:

   ```sh
   cargo run --locked -- probe-server
   ```

   Copy the printed `server_url` and `certificate_sha256_base64url` values.

2. Serve the static page on loopback. `localhost` is a secure context in Chromium:

   ```sh
   python3 scripts/serve.py
   ```

3. Start Chromium with a temporary profile and a local debugging port:

   ```sh
   chromium --headless --remote-debugging-port=9222 --remote-allow-origins='*' \
     --user-data-dir=/tmp/creds-browser-probe --ignore-certificate-errors \
     --no-first-run --no-default-browser-check about:blank
   ```

   `--ignore-certificate-errors` permits the local self-signed listener certificate. The page still checks the supplied certificate hash, including the negative case below.

4. Enable a virtual authenticator for the browser's current page:

   ```sh
   node scripts/virtual-authenticator.mjs
   ```

   The helper uses Chromium's DevTools Protocol and stays open until Ctrl-C. It enables a CTAP 2.1 virtual authenticator with PRF, resident-key, and user-verification support. It removes the virtual authenticator when stopped. For a fresh test session, stop Chromium and this helper, then start them again.

5. Connect chrome-devtools to that Chromium instance and run both WebTransport cases:

   ```sh
   chrome-devtools start --browserUrl http://127.0.0.1:9222 \
     --usageStatistics false
   chrome-devtools list_pages --output-format json
   chrome-devtools navigate_page 1 --url http://localhost:8000
   chrome-devtools evaluate_script \
     'async () => {
       const endpoint = "https://127.0.0.1:PORT/key";
       const pin = "BASE64URL_HASH_FROM_CREDS";
       document.querySelector("#endpoint").value = endpoint;
       document.querySelector("#certificate-hash").value = pin;
       document.querySelector("#positive-pin").click();
       await new Promise(resolve => setTimeout(resolve, 2000));
       const positive = document.querySelector("#result").textContent;
       document.querySelector("#negative-pin").click();
       await new Promise(resolve => setTimeout(resolve, 2000));
       return { positive, negative: document.querySelector("#result").textContent };
     }' --pageId 1 --output-format json
   ```

   Run these commands in the same terminal session. Replace `PORT` and `BASE64URL_HASH_FROM_CREDS` with the listener output. Both page actions report `PASS` when the matching hash connects and the altered hash fails.

6. Run the PRF check on the same page. For a manual click, get the current button UID from a fresh `take_snapshot` result. Or invoke the page action from `evaluate_script`:

   ```sh
   chrome-devtools evaluate_script \
     'async () => { document.querySelector("#test-prf").click(); await new Promise(resolve => setTimeout(resolve, 8000)); return document.querySelector("#result").textContent; }' \
     --pageId 1 --output-format json
   ```

   The expected result includes `registrationPrfEnabled: true`, `resultLengthBytes: 32`, and `repeatedResultMatched: true`.

7. On the same page, create and export a setup key. Use the current UID from a fresh snapshot and click **Create passkey and export public key**. The browser creates a new discoverable passkey and requests user verification. The page reports success after PRF evaluation and displays the unpadded base64url DER SPKI key in a read-only field. Use **Copy public key** or select the field and copy it into `creds setup`.

The Python server adds CSP, `frame-ancestors 'none'`, `nosniff`, and referrer-policy headers. Automated tests check these headers, the JavaScript module MIME type, and 404 behavior for a missing module. `frame-ancestors` must be sent as an HTTP response header; the HTML meta policy does not replace it. Use the [deployment guide](deployment.md) for production response headers and DNS suffix setup. The server serves only static files from `web/` and listens on loopback port 8000. For a local HTTPS page, pass `--tls-cert` and `--tls-key` to `scripts/serve.py`.

## Limits and later checks

This runner has no real user device, physical authenticator, passkey-provider account, or deployment UDP network. These results establish only the local Chromium behavior listed above.

Before release, manually check passkey creation, public-key export, approval, wrong-passkey failure, and repeat decryption with each intended browser and authenticator combination. Also check local-network permission prompts and UDP reachability from a separate device to the deployed HTTPS origin. Do not infer device or network support from the virtual authenticator or loopback transport tests.
