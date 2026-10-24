# Deployment and operator guide

creds has two parts:

- A static browser app served from one trusted HTTPS origin.
- A local CLI that stores encrypted files and starts a temporary WebTransport listener for each operation.

The browser app does not need an API server, account service, database, or JavaScript package manager. The CLI does not need an ordinary PKI certificate. It creates a temporary self-signed certificate for each operation and puts that certificate's SHA-256 pin in the handoff URL. The browser verifies that pin before it sends a key.

## Publish the static app

Copy the contents of the repository's web directory to the document root of a static HTTPS host. Serve the files as files. Do not add a service worker, backend route, third-party script, analytics, remote font, or CDN dependency. Keep the approval app on one stable hostname because that hostname is both the browser origin host and the WebAuthn RP ID. Configure the machine DNS suffix separately in the trusted static app deployment.

The `web/` directory contains the production passkey setup and approval app. Development compatibility pages are under `dev/` and must not be copied to the static host. The default `creds` CLI includes setup, check, encrypt, and decrypt; the local WebTransport echo server is a separate feature-gated development binary.

For example, if the app URL is:

    https://keys.example.com/creds/

then use all of these exact settings:

- Set the `creds-dns-suffix` meta value in `index.html` to the tailnet DNS suffix, such as `tailnet.ts.net`.
- Set the `connect-src` CSP source to `https://*.tailnet.ts.net:*` in both the HTML meta CSP and the static host's response header.
- Enter https://keys.example.com/creds/ as the trusted app URL during CLI setup.
- The browser origin is https://keys.example.com. The RP ID is keys.example.com.
- If the CLI machine label is `workstation`, the browser connects to `workstation.tailnet.ts.net`.

The app URL can include a deployment path. Its scheme, host, and port define the exact origin. Its hostname defines the RP ID. Do not add a separate RP ID setting or use a parent domain.

Serve JavaScript module files, including .mjs files, with a JavaScript MIME type such as text/javascript or application/javascript. Do not return index.html for missing JavaScript files. Enable X-Content-Type-Options: nosniff so an incorrect MIME type fails closed.

Send these response headers on every page and asset response:

~~~text
Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; img-src 'self' data:; script-src 'self'; style-src 'self'; connect-src 'self' https://*.tailnet.ts.net:*; object-src 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
~~~

Replace `tailnet.ts.net` with the configured machine DNS suffix in the CSP. Do not derive the suffix from the app hostname. The frame-ancestors directive must be an HTTP response header. The HTML meta CSP does not enforce that directive. Keep the HTML meta CSP in sync with the response CSP for the directives that meta CSP supports.

The default page has an example machine DNS suffix and extra loopback CSP sources for local tests. Set the meta value and both CSP policies to the same machine suffix before publishing. The app hostname remains configured in the CLI's trusted `app_url`; it can differ from this suffix. Review the built static directory and host configuration to confirm that no service worker, third-party assets, or unexpected files are present.

## Route the temporary CLI endpoint

For an operation, the CLI QR fragment carries one machine label, the UDP port, the certificate pin, and the request ID. The approval app combines the label with its configured machine DNS suffix to construct `<machine-label>.<machine-DNS-suffix>`. Configure tailnet DNS so that exact name resolves to the CLI machine from the approval device. Permit the browser device to reach that machine and UDP port. WebTransport uses HTTP/3 over QUIC, so a TCP-only web server rule is not enough. The QR does not supply a suffix, full destination URL, or path.

The default listener address is 0.0.0.0:0. This listens on all local interfaces and lets the operating system choose a UDP port for each operation. On a network that requires a fixed firewall rule, set a fixed port in the setup prompt, then allow that UDP port and route it to the CLI machine. Confirm that the chosen address is reachable from the approval device. A DNS record alone does not provide routing or UDP access.

The label entered during setup is one DNS label, such as `workstation`. The browser validates the configured suffix and the combined hostname, then appends the suffix to this label. Configure the suffix as lowercase ASCII DNS labels without a trailing dot. The suffix is a trusted static app setting and may differ from the approval app hostname. The app URL still defines the expected WebAuthn origin and RP ID. The browser rejects QR fields that try to override the full destination, suffix, or path.

## Configure and use the CLI

Create a discoverable ES256 passkey on the trusted app page. The page confirms PRF support and displays the public key as unpadded base64url DER SubjectPublicKeyInfo. Copy this public key into the local setup prompt. The public key is not secret; the CLI retains it in its configuration so it can verify future assertions. The matching private credential remains with the authenticator or passkey provider.

Build and install the CLI from the repository:

~~~sh
cargo install --path .
creds setup
creds check
~~~

During setup, enter the app URL, one-label machine name, secret storage directory, public key, and UDP listener address. Review the displayed origin, RP ID, advertised hostname, storage path, listener address, and public-key fingerprint before saving. Setup refuses to replace an existing configuration without an explicit confirmation.

The default configuration path is XDG_CONFIG_HOME/creds/config.toml, or ~/.config/creds/config.toml when XDG_CONFIG_HOME is not set. The default secret directory is XDG_DATA_HOME/creds/secrets, or ~/.local/share/creds/secrets when XDG_DATA_HOME is not set. Relative storage paths are resolved from the configuration file's directory. Use --config PATH to select another configuration file.

Run one command for each operation:

~~~sh
creds encrypt NAME INPUT
creds encrypt NAME -
creds decrypt NAME OUTPUT
creds decrypt NAME -
~~~

The hyphen reads encryption input from standard input or writes decrypted plaintext to standard output. Named output files are created exclusively and are not overwritten. The CLI prints a temporary approval URL and terminal QR to standard error and waits for a browser connection. Each connection has 30 seconds to establish the request. The first established request gets two minutes for passkey user verification; later connections receive only the time that remains. The browser closes the request when its timer expires. If no browser connects, use Ctrl-C to cancel the CLI. An operation succeeds only after the CLI verifies the assertion and completes its local storage operation.

Run creds check after setup. It validates local configuration and storage paths. It does not test passkey possession, browser compatibility, DNS, UDP reachability, file permissions for a future operation, or whether a secret can be decrypted.

On Unix, setup creates owner-only configuration and secret directories and a mode 0600 configuration file. The storage directory must remain owner-only (mode 0700). On other operating systems, apply equivalent owner-only filesystem access controls because Unix mode bits are not available to the CLI there. Use a case-sensitive local filesystem that supports exclusive file creation, atomic rename within a directory, file sync, and directory sync. Secret names are case-sensitive, so `Token` and `token` are distinct names that require distinct JSON and lock paths. A case-insensitive filesystem can map both names to the same paths.

## Trust, recovery, and key handling

The trusted browser origin is part of the security boundary. JavaScript delivered by that origin can derive keys after a user-approved WebAuthn ceremony. Protect the static host, deployment credentials, DNS, and release process accordingly.

For one passkey, the same logical name and revision reproduce the same derived encryption key. Each new successful encryption increments that name's revision and derives a different key. Decryption uses the revision in the current file. Restoring an older encrypted file restores its older revision and makes that old derived key usable again. There is no rollback protection, history, recovery key, or built-in backup system. Back up ciphertext and configuration according to the operator's own retention policy; losing the passkey, CLI public-key configuration, or required browser origin can make data unavailable.

The URL and QR carry a short-lived request identifier and the pin for the temporary CLI certificate. They do not carry the encryption key. The CLI verifies a per-connection WebAuthn challenge before it accepts one key response. Do not publish or forward an approval URL as if it were a harmless permanent link.

The CLI keeps derived keys and plaintext in process memory only while needed. Rust-owned key and plaintext buffers use zeroization where supported, and browser-owned byte arrays are cleared after use. JavaScript copies, browser and cryptographic runtime internals, swap, crash dumps, and compiler behavior prevent a promise of complete memory erasure. The design makes no deliberate persistent copy of a key. It does not protect plaintext at the user-selected input/output path or against a compromised approved CLI, browser, authenticator, operating system, or machine.

The browser does not write application keys or setup data to local storage, session storage, IndexedDB, cookies, or application-managed temporary files. The exported public key is public material and must be retained in the CLI configuration. The CLI stores one encrypted JSON file per logical name plus lock and short-lived publication files in the configured secret directory.

## Verification and compatibility limits

Run ./scripts/test.sh. GitHub Actions runs this command in the required workflow and check named test. It runs Rust formatting, clippy, Rust tests, CLI loopback handoff integration, browser JavaScript tests under Node.js, and static-server header tests.

The automated and manual checks map to the proposal as follows:

| Proposal contract | Verification |
| --- | --- |
| Stable v1 PRF, HKDF, AAD, and envelope bytes | Shared fixture in test-vectors/envelope-v1.json; Rust tests in src/protocol.rs; Node tests in web/js/envelope.test.mjs |
| Bounded parsing, malformed fields, tampering, signatures, origin, RP ID, UP/UV, and CBOR extensions | Rust tests in src/envelope.rs and src/assertion.rs; browser request JSON/schema, frame, DNS suffix, and QR override tests in web/js/transport.test.mjs |
| Pinned handoff, URL fields, per-connection challenges, one valid response, and replay rejection | Rust tests in src/handoff.rs and tests/command_flow.rs, including a loopback CLI connection under a machine suffix different from the app RP ID; Node pin and response tests in web/js/transport.test.mjs. Rust rejects duplicate fields in untrusted browser messages. Browser request parsing uses JSON.parse semantics for trusted CLI messages. |
| Approval cancellation, connection loss, and safe request display | Browser tests in web/js/main.test.mjs and web/js/webauthn.test.mjs |
| Concurrent writer exclusion, replacement snapshots, revision overflow, tampered files, and publication failures | Rust tests in src/storage.rs; the CLI snapshot race in tests/command_flow.rs |
| Config parsing, explicit paths, storage checks, and read-only check behavior | Rust tests in src/config.rs |
| Security headers, JavaScript MIME type, and missing-module failure | Python tests in scripts/test_serve.py |
| No browser persistence or remote assets; request fields use text insertion | Source regression checks and UI test in web/js/main.test.mjs |
| Key separation from URLs, CLI output, and published files | CLI integration assertions in tests/command_flow.rs. Code review confirms src/main.rs accepts no key argument or key environment setting; handoff keys arrive only in the bounded, assertion-verified message. |
| One v1 protocol, fixed /key endpoint and algorithms, with no recovery or alternate transport | Source review of src/protocol.rs, src/envelope.rs, src/assertion.rs, and src/handoff.rs. This milestone adds no Rust or JavaScript dependencies. |
| Production/development separation and browser API compatibility | `scripts/test.sh` checks that production HTML/modules and the default CLI exclude probe hooks, then tests the separate development page and feature-gated echo binary. Follow browser-compatibility.md for Chromium virtual-authenticator probes. Physical passkey/provider behavior, local-network prompts, deployed DNS, and UDP reachability remain manual release checks. |

The automated suffix tests use a public-style approval hostname and a different machine DNS suffix. They check configured suffix validation, the combined destination, and rejection of QR destination/suffix/path overrides. They do not resolve tailnet names or test deployed UDP reachability.

The runner has no physical authenticator or deployment network. The Chromium procedure exercises loopback WebTransport and a virtual CTAP 2.1 authenticator only. Do not treat it as evidence for every browser, authenticator, passkey provider, or deployment network.

See browser-compatibility.md for the development-only Chromium and virtual-authenticator procedures and results. Before release, repeat passkey creation and export, approval, wrong-passkey failure, and repeat decryption on each intended physical device and passkey provider. Also test browser local-network permission prompts and UDP reachability from a separate device on the deployed network. Those checks were not available on the implementation runner.
