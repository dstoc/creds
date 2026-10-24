# Development-only browser compatibility checks

The production browser app lives in `web/`. It contains the user-facing Create passkey setup flow and the approval flow. It does not contain compatibility controls or test-passkey creation. The compatibility fixture page and its JavaScript live under `dev/browser-compatibility/`; the WebTransport echo listener is the feature-gated `creds-probe-server` development binary. These tools use loopback only and do not provide an application backend.

Do not publish `dev/`. The default `creds` CLI supports `setup`, `check`, `encrypt`, and `decrypt`. Build the echo fixture only for local experiments with `--features dev-tools`.

## Automated coverage

Run the required CI command from the repository root:

```sh
./scripts/test.sh
```

It checks the production CLI help and rejected `probe-server` command, scans production HTML/modules for test-passkey and probe hooks, exercises the separate dev page and its JavaScript modules, builds and tests the feature-gated Rust echo binary, and runs the normal Rust, Node.js, and static-server tests. The Rust `command_flow` integration tests exercise the production CLI and a real loopback WebTransport client with protocol fixtures. They do not exercise browser WebAuthn or a physical passkey.

## Observed runner results

Run date: 2026-10-24.

| Component | Version |
| --- | --- |
| Chromium | 156.0.8078.47 |
| chrome-devtools | 1.12.0 |
| Rust | 1.98.1 |
| Node.js | 24.17.0 |
| Python | 3.13.5 |

Chromium connected to the local `wtransport` echo server with the printed SHA-256 certificate hash. It opened a bidirectional stream, sent the fixed test message, and received the exact echo. With one bit changed in the expected hash, the session failed with `WebTransportError: Opening handshake failed`; the console reported `QUIC_TLS_CERTIFICATE_UNKNOWN`. The positive case completed first against the same endpoint.

The local self-signed certificate was permitted with Chromium's `--ignore-certificate-errors` test setting. The mismatched pin still failed. The setting permits the local test certificate; it does not replace the `serverCertificateHashes` check.

The development page created a discoverable ES256 test credential for RP ID `localhost`, then requested two PRF assertions with the same input and explicit credential ID. Chromium reported PRF enabled, returned 32 bytes on both assertions, and the outputs matched. The CDP virtual CTAP 2.1 authenticator supported resident keys, user verification, automatic presence, and PRF. This did not test a physical authenticator or passkey provider.

The production Create passkey flow was also exercised with Chromium 156 and the virtual authenticator. It created a discoverable ES256 passkey with required user verification, no attestation, and PRF support. The browser returned algorithm `-7` and DER SubjectPublicKeyInfo bytes; the page displayed the unpadded base64url key. `creds setup` accepted the key and `creds check` reported its fingerprint.

A Chromium virtual-authenticator handoff also completed encryption and decryption through the production approval flow. The browser used the pinned per-operation listener, displayed the request, and required an explicit approval click. These loopback results do not establish physical-device behavior, passkey-provider compatibility, deployment DNS, local-network prompts, or deployed UDP reachability. The runner had no physical authenticator or deployed network. In this runner, `chrome-devtools start` returned without a running daemon; direct CDP WebSocket control was used for the recorded checks.

## Reproduce the development probes

Use separate terminals from the repository root. Keep each server and helper open during the experiment.

1. Start the feature-gated Rust WebTransport echo fixture:

   ```sh
   cargo run --locked --features dev-tools --bin creds-probe-server
   ```

   Copy the printed `server_url` and `certificate_sha256_base64url` values.

2. Serve the development fixture on loopback. `localhost` is a secure context in Chromium:

   ```sh
   python3 scripts/serve.py --root dev/browser-compatibility
   ```

3. Start Chromium with a temporary profile and a local debugging port:

   ```sh
   chromium --headless --remote-debugging-port=9222 --remote-allow-origins='*' \
     --user-data-dir=/tmp/creds-browser-probe --ignore-certificate-errors \
     --no-first-run --no-default-browser-check about:blank
   ```

   The browser flag permits the local self-signed listener certificate. The probe still verifies the supplied pin, including the mismatch case.

4. In another terminal, enable a virtual authenticator:

   ```sh
   node scripts/virtual-authenticator.mjs
   ```

   The helper uses Chromium's DevTools Protocol. It enables a CTAP 2.1 virtual authenticator with PRF, resident-key, and user-verification support, then removes it when stopped. For a fresh test session, restart Chromium and the helper.

5. Connect `chrome-devtools` to Chromium and open the development fixture:

   ```sh
   chrome-devtools start --browserUrl http://127.0.0.1:9222 --usageStatistics false
   chrome-devtools list_pages --output-format json
   chrome-devtools navigate_page 1 --url http://localhost:8000
   ```

   Enter the printed endpoint and certificate hash in the page. Click **Test matching pin and echo**, then **Test mismatched pin**. The first action must report an echoed message. The second must report that Chromium rejected the changed certificate hash.

6. Click **Create test credential and evaluate PRF**. Chromium asks the virtual authenticator to create a test credential on the development page's RP ID. The result should report `registrationPrfEnabled: true`, `resultLengthBytes: 32`, and `repeatedResultMatched: true`. The page holds the test credential only in memory for the page session. A physical authenticator may retain a credential created by this experiment.

## Check the production setup page

Serve the production app separately:

```sh
python3 scripts/serve.py --port 8001
```

Open `http://localhost:8001` in the same Chromium session and use **Create passkey and export public key**. This is the product setup flow, not a test-passkey probe. The page should show the unpadded base64url DER SPKI key after user verification and PRF confirmation. Copy the public key into `creds setup` when testing a local CLI configuration.

The static server adds CSP, `frame-ancestors 'none'`, `nosniff`, and referrer-policy headers. Tests check these headers, JavaScript module MIME types, missing-module 404 behavior, and that the development page is served from an explicit root separate from the default production `web/` root. For production response headers and DNS configuration, use the [deployment guide](deployment.md).

## Limits and later checks

The runner has no physical authenticator, passkey-provider account, or deployment UDP network. Before release, manually check passkey creation and export, approval, wrong-passkey failure, and repeat decryption with each intended browser and authenticator combination. Also check local-network permission prompts and UDP reachability from a separate device on the deployed network. Do not infer device or network support from the virtual authenticator or loopback transport tests.
