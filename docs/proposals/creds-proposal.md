# Proposal: creds — browser-approved credential encryption

Status: proposed initial implementation.

## Motivation

Keep stored credentials encrypted, releasing the key to a trusted CLI only when explicitly requested. A browser at a stable HTTPS origin uses a WebAuthn passkey with the PRF extension to reproduce a key for a named secret. The user approves the request in that browser; the browser delivers the key directly to the waiting CLI.

The implementation should be small enough to audit: static web files, one Rust executable, standard cryptographic primitives, and a short protocol. This is a new standalone design; no existing repository layout or migration is assumed.

## Problem statement

The CLI needs to encrypt and decrypt credentials without keeping a reusable encryption key on disk. Approval may happen on another device. Neither a central key service nor publicly trusted certificates for the CLI should be necessary.

Recovery is deliberately unnecessary. Losing the passkey may permanently lose access to the encrypted credentials. The CLI manages revisions internally and keeps only the current encrypted value for each logical secret name.

## Proposal

Build two components:

- A static client served from a fixed, trusted HTTPS origin: `index.html`, a CSS stylesheet, and native JavaScript module files.
- A Rust CLI that starts a temporary WebTransport listener for each encryption or decryption operation.

Use the WebAuthn PRF output to derive a symmetric key for one exact logical name and revision. Deliver that key over a certificate-pinned WebTransport connection. The CLI performs authenticated encryption locally. The browser never needs the credential plaintext or ciphertext.

### Trust and security scope

Trust the browser, authenticator/passkey provider, web app delivery origin, CLI, and receiving machine while an operation is approved. Protect ciphertext at rest when the attacker lacks both the passkey-derived key and access to an approved operation.

The web origin is a security boundary: JavaScript served there can obtain derived keys following a WebAuthn ceremony. Use no third-party scripts, analytics, remote fonts, or service worker. Configure a restrictive Content Security Policy, including `frame-ancestors 'none'`, and render request fields with `textContent` rather than HTML interpolation.

Approval releases a reusable key for that name and revision. A CLI that retains it can decrypt every ciphertext encrypted under that same name, revision and passkey. A new revision derives an independent key; it does not revoke an old key or erase previously exposed plaintext. The operation label describes intent, not a cryptographic restriction on a symmetric key.

The QR code is trusted handoff material. Certificate pinning authenticates the endpoint described by the QR; it does not prove that a substituted QR belongs to the intended machine. Display the destination hostname and complete key name before approval.

### Naming and automatic revisions

Treat the user-supplied name as one opaque logical identifier. Store the revision separately as an integer; never parse or append an `-rN` suffix to identify revisions.

For v1, accept 1–128 ASCII characters matching `[A-Za-z0-9][A-Za-z0-9._-]*`. Names are case-sensitive. Reject invalid names without trimming, case folding or normalization. These limits avoid invisible characters and cross-language normalization rules.

Examples: `github-token`, `secret-x`. A literal name such as `secret-x-r2` remains a distinct logical name, not revision 2 of `secret-x`.

Store only `<storage_dir>/<NAME>.json`. First encryption uses revision 1; each successful replacement increments the stored revision by one. Decryption uses the revision in the current file. There is no history, latest pointer, revision database or revision-selection flag.

Revisions must be JSON integers from 1 through 4,294,967,295 inclusive, represented exactly in Rust and JavaScript. Reject missing, fractional, zero, negative or out-of-range values. Refuse an update at the maximum revision rather than wrapping. A malformed existing envelope fails before approval and is never silently treated as a new secret.

Deleting the file resets the next encryption to revision 1. Restoring an older file can also reuse revision numbers. Accept this limitation: there is no rollback protection or globally monotonic counter. A previously released key can decrypt future ciphertext if that same name/revision is reused. Generate a fresh random nonce for every encryption regardless. Replacing the current file does not erase old copies from backups or snapshots.

### Passkey and CLI setup

The web page has a separate **Create passkey** action. Create a discoverable credential with `residentKey: "required"`, `userVerification: "required"`, `attestation: "none"`, and the PRF extension enabled. Request only ES256 (`alg: -7`, ECDSA P-256 with SHA-256) to keep public-key parsing and signature verification to one algorithm. Use random user-ID bytes and a human-readable label. No account or registration backend is needed.

After creation, run a PRF evaluation to confirm support. Fail explicitly if no result is returned. Obtain the credential public key using `response.getPublicKey()` and check `getPublicKeyAlgorithm() === -7`. Display its DER SubjectPublicKeyInfo bytes as unpadded base64url in a copyable setup field. Fail if the public key cannot be exported. Do not parse attestation or request attestation certificates.

The user runs `creds setup` and enters the app URL, local hostname label, secret storage directory and public-key string through interactive prompts. The CLI validates that it is an ES256 P-256 public key and saves it in local configuration. Derive the expected origin from the configured app URL and fix the RP ID to that URL’s hostname; the web app uses that hostname for its origin and RP ID. Configure the machine DNS suffix separately in the trusted static web app deployment. Show a fingerprint for confirmation. Setup is an explicit local trust decision; never enroll or replace a key through a network operation. Refuse to replace existing configuration unless the user explicitly requests replacement during setup. One trusted credential per CLI configuration is enough for v1.

The web app needs no persistent application storage. The public key is exported during creation and thereafter retained only by the CLI. Normal browser operations omit `allowCredentials`; the user selects the discoverable passkey. Store no credential ID or public key in the encrypted file, and send neither public key nor registration material during normal operations. Selecting a different passkey fails CLI signature verification before encryption or decryption.

Losing the CLI configuration requires importing the same public key from a retained setup string or another configured CLI; an ordinary assertion cannot export it again. This public setup material is safe to retain. Recreating a passkey produces different encryption keys and does not recover existing ciphertext.

The stable origin and RP ID must remain available. Changing RP ID is not a transparent move of the encrypted material. This design makes no guarantee about PRF reproduction across devices or provider migrations; test the intended setup.

### Key derivation

Fix the following byte-level construction for v1:

```text
input = UTF8("creds/prf/v1\0") || UTF8(name) || BYTE(0) || U32BE(revision)
P = navigator.credentials.get(... prf.eval.first = input ...)
    .getClientExtensionResults().prf.results.first
K = HKDF-SHA256(
    IKM = P,
    salt = 32 zero bytes,
    info = UTF8("creds/aes-256-gcm/v1"),
    length = 32 bytes
)
```

Here `\0` and `BYTE(0)` denote one zero byte, and `U32BE(revision)` is exactly four unsigned big-endian bytes. The zero separator cannot occur in a validated name, so the name/revision encoding is unambiguous. Pass `input` directly to the WebAuthn extension; the browser applies WebAuthn's specified internal PRF input transformation. Use Web Crypto for HKDF. Require a 32-byte PRF result. Request `userVerification: "required"` and use the CLI-issued connection challenge in the same `navigator.credentials.get()` call that evaluates PRF. Return the assertion and derived key together; normal approval needs only one WebAuthn ceremony.

The CLI verifies that assertion using its configured public key before accepting the supplied encryption key. AEAD verification additionally detects damaged ciphertext or a mismatching derived key during decryption. WebAuthn authenticates the responding connection; it does not cryptographically attest that the supplied bytes are the correct PRF output. The trusted web app remains responsible for deriving the key correctly.

### Ciphertext format

Use AES-256-GCM with a fresh random 12-byte nonce for every encryption and a 128-bit authentication tag. The Rust implementation must use an established AEAD library, not implement cryptography itself. Limit plaintext credentials to 64 KiB; this is not a bulk-file encryption tool.

Write one UTF-8 JSON object:

```json
{
  "version": 1,
  "name": "secret-x",
  "revision": 2,
  "nonce": "<base64url without padding>",
  "ciphertext": "<base64url without padding, including appended tag>"
}
```

Version 1 fixes the cipher and KDF; do not add algorithm negotiation. Authenticate these exact associated-data bytes:

```text
UTF8("creds/file/v1\0") || UTF8(name) || BYTE(0) || U32BE(revision)
```

Reject unsupported versions, duplicate or unknown fields, invalid names or revisions, invalid encodings, incorrect nonce lengths, short ciphertext, and oversized files before requesting a key. A 128 KiB file limit accommodates the largest supported plaintext and JSON overhead. Never release any plaintext until tag verification succeeds.

### CLI interface

The project and executable are named `creds`:

```sh
creds setup
creds encrypt secret-name from-file.txt
printf '%s' 'from-stdin' | creds encrypt secret-name -
creds decrypt secret-name to-file.txt
creds decrypt secret-name - | cat
creds check
```

`encrypt NAME INPUT` reads plaintext bytes from the named file, or stdin when INPUT is `-`. It writes the encrypted envelope to `<storage_dir>/<NAME>.json`. Create revision 1 if absent; otherwise read the existing valid envelope and encrypt revision N+1. No old decryption key or decryption of the previous value is required. Read and bound the input before starting approval. Never modify or delete the plaintext source.

`decrypt NAME OUTPUT` reads `<storage_dir>/<NAME>.json` and requires its embedded name to equal NAME before requesting a key. It writes authenticated plaintext to the named file, or stdout when OUTPUT is `-`. Refuse an existing destination file. Create a file destination only after successful authentication and decryption, using exclusive creation and Unix mode `0600`; remove any partial file created by this invocation if writing fails. No plaintext temporary file is needed. Stdout writes may be partial on an I/O error; return failure.

Use the exact validated name as the storage basename; never accept separators or path traversal. Because names are case-sensitive, v1 requires a case-sensitive storage filesystem.

Before reading the current envelope for encryption, acquire a nonblocking exclusive OS lock on `<storage_dir>/<NAME>.lock`. Hold it through revision selection, browser approval and final publication. A concurrent encryption for that name fails immediately with a clear busy error; different names can proceed independently. Use a stable sidecar lock file rather than locking the JSON file that will be replaced. Keep the sidecar in place after unlocking so another process cannot lock a different inode for the same name. The lock contains no revision metadata or secrets; the OS releases it on exit or crash. Require a filesystem supporting the chosen lock and atomic replacement semantics; this coordinates cooperating local `creds` processes, not external edits or distributed writers.

Write the complete new envelope to a uniquely created ciphertext-only temporary file in the same directory, flush and sync it, then atomically rename it over `<NAME>.json`. That rename is the commit point. Cancellation or any failure before it preserves the old file byte-for-byte (or leaves the secret absent for a first encryption). Remove temporary ciphertext files on handled failure; a crash may leave an unreferenced temporary file, which is never treated as a secret or revision history. Sync the directory after publication; if this fails, report that replacement occurred but crash durability is uncertain rather than claiming the old file was preserved. Do not retain a backup of the replaced envelope.

Decryption reads one complete bounded envelope into memory before approval and uses that snapshot for the entire operation. Atomic replacement means it observes either the old or new envelope; it never mixes metadata and ciphertext across revisions. It does not need the writer lock. Its browser approval shows the exact snapshot revision even if encryption publishes a newer one meanwhile.

Use owner-only permissions for created configuration and secret files and `0700` for the storage directory on Unix. Diagnostics, approval URL, and terminal QR go to stderr. Successful encryption emits no stdout data. All commands return zero on success and nonzero on failure. Replacement of the current encrypted secret is the default encryption behavior; do not add a separate overwrite flag, shell execution, environment export or daemon mode in v1.

### Local configuration

Use TOML at `$XDG_CONFIG_HOME/creds/config.toml`, defaulting to `~/.config/creds/config.toml` on Linux. Support one global `--config PATH` option for an explicit alternative; do not discover configuration from the working directory. Resolve relative storage paths against the configuration file's directory; do not perform shell or environment-variable expansion inside TOML strings. Setup writes the resolved absolute storage path.

```toml
app_url = "https://keys.example/"
hostname = "workstation"
storage_dir = "/home/user/.local/share/creds/secrets"
public_key = "<unpadded base64url DER SubjectPublicKeyInfo>"

# Optional; default shown. Use a reachable interface for approval from another device.
listen_addr = "0.0.0.0:0"
```

Required fields are `app_url`, `hostname`, `storage_dir`, and `public_key`. Reject unknown or duplicate fields. `hostname` is the single DNS label advertised in the QR; it need not equal the OS hostname. The web app appends its deployment-configured DNS suffix. The suffix remains web-app configuration and is not overridden by the CLI or QR.

Require an HTTPS app URL without credentials, query or fragment; permit a deployment path. Derive the expected WebAuthn origin from its scheme/host/port and RP ID from its hostname. This avoids independent settings that could disagree. Fix RP ID to the exact app hostname in v1 rather than supporting parent-domain RP IDs.

`listen_addr` optionally selects a bind IP and UDP port. Port zero lets the OS allocate a port, which the CLI advertises in the URL. A fixed port can be configured if network policy requires one. The machine label combined with the web app's configured DNS suffix must resolve to a reachable address on the chosen listener. Do not add a CLI DNS-suffix setting, separate port, configurable timeout, algorithm or per-secret settings. Keep the 30-second connection-setup timeout and two-minute approval window fixed.

`creds setup` creates the config and storage directory and accepts the pasted public key. Default the storage directory to `$XDG_DATA_HOME/creds/secrets`, or `~/.local/share/creds/secrets`. Ask before explicitly replacing existing configuration; ordinary commands never modify the pinned key. Setup does not retain browser state, register an account, or write an encryption key.

`creds check` is local and read-only: parse the config; validate URL, hostname, listener and storage-path settings; parse the pinned ES256 public key; and check that the configured storage directory exists and is a directory. Display the resolved config/storage locations, expected app origin/RP ID, advertised hostname, listener and public-key fingerprint. Report missing or invalid setup with a nonzero status. Do not start a listener, prompt for WebAuthn, create files, or claim to have verified browser compatibility, network reachability, passkey possession or secret decryptability. Actual operations report read/write permission and bind failures when attempted.

### Connection and handoff

For each operation the CLI:

1. Validates inputs and freezes one request containing version, name, revision and operation. Encryption freezes the next revision while holding its per-secret lock; decryption freezes the revision from its envelope snapshot.
2. Generates a fresh ephemeral P-256 TLS key and self-signed X.509v3 certificate with a validity period of one day.
3. Starts an HTTP/3 WebTransport listener on an available UDP port on the intended reachable interface.
4. Generates a random 32-byte request identifier and displays a URL and QR.
5. Waits for a browser connection or Ctrl-C. Each connection has 30 seconds to complete its handshake and protocol setup. After a valid request is sent to the browser, the CLI allows two minutes for approval, assertion verification and key response. It then exits and releases key material.

Use a URL fragment with ordinary URL parameter encoding, for example:

```text
https://keys.example/#v=1&host=workstation&port=8443&cert=...&request=...
```

`cert` is unpadded base64url SHA-256 of the complete DER certificate; `request` is unpadded base64url. Avoid a custom compact encoding in v1. The page reads the fragment into memory and immediately removes it with `history.replaceState`. The URL contains connection material, never a derived key or plaintext.

The app accepts only one DNS label for `host`, validates the trusted deployment-configured machine DNS suffix and combined hostname, validates the port, and checks decoded field lengths and version. It constructs `https://<host>.<configured-machine-suffix>:<port>/key`; the machine suffix can differ from the approval app hostname. The QR does not carry the suffix and the app rejects arbitrary destination URLs, path overrides, or suffix overrides. The configured app URL continues to define the expected Origin and RP ID. Both devices must resolve and reach the machine address over UDP; there is no relay or transport fallback.

Use `serverCertificateHashes` to pin the SHA-256 certificate hash. The CLI accepts only the configured app Origin. The request identifier identifies the pending operation; it is not a bearer authorization. Knowing all URL fields does not authorize supplying an encryption key. The pinned WebAuthn public key authenticates the browser response.

### Wire protocol and approval

Use one bidirectional reliable WebTransport stream and three messages, each encoded as a four-byte unsigned big-endian length followed by UTF-8 JSON. Bound each body to 16 KiB and each decoded assertion byte field to 4 KiB; the key is exactly 32 bytes. Reject additional streams, unknown message types, duplicate fields, unexpected messages, invalid lengths and malformed payloads. All binary fields use unpadded base64url.

```text
Browser → CLI: {"type":"hello","version":1,"request":"..."}
CLI → Browser: {"type":"request","version":1,"name":"secret-x","revision":2,"operation":"decrypt","challenge":"<32 random bytes>","approvalTimeoutMs":120000}
Browser → CLI: {"type":"key","version":1,"key":"<32 bytes>","assertion":{"clientDataJSON":"...","authenticatorData":"...","signature":"..."}}
```

An invalid request identifier closes only that connection. For each valid hello, generate a fresh random 32-byte WebAuthn challenge and keep it exclusively in that connection's state. A URL-wide challenge alone is insufficient: an assertion observed on one connection must not authenticate another connection that presents a different encryption key. The URL request identifier replaces the old token; the connection-specific authentication challenge travels in the request message.

Do not reserve the operation for the first unauthenticated connection. Permit at most four pending connections. Each connection has a 30-second deadline that starts when the CLI accepts its WebTransport connection attempt. The deadline covers the transport handshake, first stream, valid hello, and sending the request message. Invalid or stalled setup closes only that connection and does not start the approval window.

After the CLI validates a hello and sends the request message, start one fixed two-minute approval window for the operation. The request message carries the remaining time as `approvalTimeoutMs`; the first request carries 120000 milliseconds. The browser starts its timer when it receives the request. All established sessions share the same CLI deadline. A later connection receives only the remaining time, so it cannot restart or extend the window. The two-minute window covers user approval, the WebAuthn ceremony, assertion verification and the key response. Do not apply the 30-second setup deadline after this transition. On expiry, close the listener and all sessions. A key response that finishes verification at or after the deadline cannot consume the operation. If no browser connects, the CLI waits until Ctrl-C; this wait does not consume the approval window. Network access can still cause denial of service; preventing that is outside v1.

On receiving a key response, validate the assertion before accepting or using any key bytes:

- Parse the original `clientDataJSON` bytes and require `type` equal to `webauthn.get`, the exact connection challenge, and the exact configured app origin. Reject cross-origin ceremonies (`crossOrigin: true`) and unexpected top-origin data; the app runs as a top-level page.
- Check the authenticator data's RP ID hash against SHA-256 of the configured RP ID. Require both UP and UV flags. Parse the assertion authenticator-data structure using a bounded standards-aware parser, including any extension data; reject malformed data.
- Verify the ES256 signature over the original `authenticatorData || SHA256(clientDataJSON)` bytes using the configured public key. Never reserialize the signed client data. Use an established verification library and the WebAuthn DER signature encoding.
- Do not trust an Origin header alone, accept a client-supplied public key, fall back to another algorithm, or enroll unknown credentials.

After successful verification, atomically consume the pending operation and accept that response's key on the same connection. Close all other sessions and the listener. Replays, repeated responses and additional operations fail. No persistent signature-counter tracking is needed; connection challenges provide replay protection. No acknowledgment or automatic reconnect is required: success is reported by the CLI after the local operation completes.

The browser displays the full hostname, exact logical name, revision, and operation from the frozen request. It also shows the time that remains in the shared approval window. Only an explicit **Approve and verify** click starts WebAuthn. Use the challenge in that request for WebAuthn. Keep that exact request in memory while the ceremony runs; do not accept edits or replacement messages. On completion, derive and send the key and assertion only to the same live session before the approval deadline. Never accept a replacement challenge or forward an assertion between sessions. **Cancel** closes the session without deriving or sending a key.

The name need not be duplicated in the QR: the pinned session supplies an immutable request that the browser displays before approval. This avoids a second representation and comparison rule.

### Failure and memory handling

Missing PRF output, declined verification, unsupported APIs, certificate mismatch, failed assertion verification, missing setup, network failure, permission denial, setup timeout, approval expiry, cancellation, or malformed data fails closed. Do not downgrade to an unpinned connection, another cipher, cached key, or another passkey automatically.

A decryption tag failure reports that the key does not match or the file is damaged; it cannot reliably distinguish these cases. Preserve the existing encrypted file until the atomic replacement commit point. A failed or cancelled approval never consumes a revision or changes the current file.

Keep keys out of arguments, environment variables, logs, browser storage and application-managed temporary files. Clear Rust key buffers with `zeroize` and discard browser references promptly. JavaScript copies, runtime internals, swap and crash dumps prevent a promise of complete memory erasure. The goal is no deliberate persistent key storage.

## Implementation shape

The web app consists of static files: `web/index.html`, `web/style.css`, and a small set of native JavaScript ES modules loaded with `<script type="module">`. Serve these files directly over HTTPS, without a frontend framework, bundler, transpiler, package dependencies or build step. Use ordinary relative module imports. There is no Bend 2 compilation path.

Keep modules focused on visible responsibilities: page rendering and approval actions, WebAuthn setup/assertion/PRF operations, key derivation, and WebTransport framing/session handling. Choose file boundaries to keep these responsibilities easy to inspect; do not add a plugin system or generic frontend architecture. The browser uses built-in DOM, WebAuthn, Web Crypto and WebTransport APIs. The static host must serve JavaScript modules with an appropriate JavaScript MIME type and apply the security headers described above.

Use a single Rust crate with small modules for CLI/configuration, envelope/AEAD, and the temporary transport session. Candidate dependencies are `wtransport` with its supported TLS stack, a certificate generator such as `rcgen`, `aes-gcm`, `serde`/`serde_json`, `base64`, `zeroize`, a CLI parser, and a QR encoder. Confirm current crate APIs and security properties during implementation; pin the dependency lockfile. Add a focused assertion-verification module using an established ES256 implementation and bounded WebAuthn parsing. Evaluate a small WebAuthn verification library against this fixed single-credential use case; avoid account/session frameworks. No custom cryptographic primitives, plugin system or generic transport abstraction is needed.

Implement in this order:

1. Prove pinned browser-to-Rust WebTransport and PRF evaluation on the actual intended devices. Check local-network permission prompts, UDP reachability, and passkey support before building the full tool.
2. Implement passkey public-key export, CLI setup, and assertion verification with fixed positive and negative fixtures.
3. Implement envelope encryption/decryption and fixed key-derivation vectors.
4. Join the components with the three-message protocol and approval page.
5. Review parsers, cancellation paths, output handling and dependency footprint.

## Non-goals

- Recovery, backup passkeys, multi-user access or passkey migration.
- Envelope encryption, wrapped data keys, public-key encryption or unattended encryption.
- A central backend, accounts, key database or request broker.
- Revocation of previously released keys, protection from a compromised approved CLI, or remote attestation of the browser.
- Revision history, rollback protection, browser key caching, algorithm negotiation or alternate transports.

## Verification

- Fixed derivation and AAD vectors establish exact bytes, including domain separators. Repeated evaluation with the same passkey, name and revision reproduces the key; a different name, revision or passkey does not. Include fixed revision-encoding vectors and separator-collision checks.
- Round-trip empty, binary and maximum-size credentials. Tampering with name, revision, nonce, ciphertext or tag fails without stdout plaintext. Reject unsupported versions, duplicate fields and oversized inputs.
- Certificate mismatch and unexpected Origin stop the browser session. Wrong request identifiers and invalid assertions never cause the CLI to use a supplied key.
- Reject wrong signing key, challenge, signed origin, RP ID hash, missing UP/UV, malformed assertion data and altered signatures. Verify signature fixtures using original client-data bytes.
- With a leaked URL, an attacker connection supplying its own key cannot encrypt a file or consume the operation. An assertion captured from connection A fails on connection B. Failed unauthenticated connections do not reserve the operation; the first valid response wins atomically. Repeated responses cannot trigger another operation.
- Setup stalls close only the affected connection at 30 seconds and do not start the approval window. A valid request starts one two-minute deadline shared by all sessions. Slow user approval can continue beyond the setup deadline; approval at or after expiry, CLI cancellation, and replay cannot use a key or consume a second operation. The page closes its session at expiry and never sends a key after the approved session has been replaced or closed.
- Named-file and stdin encryption produce decryptable named storage entries. Named-file and stdout decryption preserve exact bytes, including empty and binary input.
- First encryption creates revision 1; replacement produces revision 2 in the same JSON path, and decrypt returns the new plaintext. Only the current envelope and a stable lock sidecar remain after success.
- Cancellation, invalid assertion and write failures before publication preserve the previous envelope byte-for-byte and do not consume a revision. Test the post-rename durability-error report separately.
- A concurrent encryption of the same name fails busy while one waits for approval; different names are independent. Terminating a writer releases its lock. Decryption during replacement uses one consistent snapshot.
- Existing plaintext destination files survive refusal or failure. A stored envelope with a name different from the requested name or an invalid revision fails before approval. Test revision overflow, deleting a file, and restoring an older envelope.
- Diagnostics do not contaminate plaintext stdout; no key appears in logs or persistent browser state.
- `creds check` succeeds for valid local setup and fails for missing config, invalid public keys or invalid storage directories without opening a listener or changing files. Test explicit config paths and relative storage paths independently of the working directory.
- Manually test creation, approval, wrong-passkey failure, and repeat decryption on the supported browser/authenticator combination. Confirm the app can be reloaded with no persistent application storage and complete operations using only CLI-side public-key configuration.
- Setup rejects malformed/non-P-256 public keys and accidental replacement. Unknown credentials fail without a trust prompt or ciphertext output. Confirm only one WebAuthn ceremony is needed per normal operation.

## Success criteria

- A user can encrypt and decrypt a logical secret through explicit browser approval, with automatic revision increments and only one stored encrypted value.
- Successful encryption atomically replaces the current envelope; failures before publication preserve it.
- Only the current ciphertext, public configuration (including the pinned credential public key), and empty lock sidecars need persist between operations.
- Possession of the QR URL alone cannot authorize a key response or inject an encryption key.
- The trusted web app and temporary CLI communicate directly without a backend or normal PKI certificate for the CLI.
- The protocol, KDF and file format each have one version and one implementation path.

## Standards references

- [WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension): credential-specific pseudorandom outputs for key derivation. The same ceremony supplies an assertion for CLI client authentication. See also [public-key export](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-getpublickey) and [assertion verification](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion).
- [WebTransport specification](https://www.w3.org/TR/webtransport/): certificate-hash authentication and custom certificate constraints, plus the distinction between server pinning and client authentication. Browser support and local-network access behavior must be verified in the initial compatibility step.
