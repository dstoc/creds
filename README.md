# creds

`creds` is a Rust CLI and library with a static web client for browser-approved credential encryption. The web client uses plain HTML, CSS, and native JavaScript modules. It has no frontend framework, bundler, transpiler, persistent application backend, or JavaScript package dependencies.

The design and security contracts are in [the proposal](docs/proposals/creds-proposal.md). The CLI supports local setup checks, v1 encryption envelopes, atomic named-secret storage, and temporary browser-approved key handoff. On first visit, the browser offers **Create passkey** or **Use existing passkey**. Creation confirms PRF support and exports a public key for `creds setup`. Existing users can set the machine DNS suffix without importing a public key. Import is optional setup convenience; it does not enroll a key with the CLI or prove possession. The browser stores only the public key, user-configured DNS suffix, and accepted machine prefixes in origin-local settings.

Open the static web client at the trusted deployment origin. To establish CLI setup, copy the exported public key into `creds setup`; setup validates each answer and asks you to trust the pinned key before it saves. Then run `creds check` to validate the local setup. Use `creds check --details` to show resolved paths, app origin, RP ID, listener, and pinned-key fingerprint. The check is local and read-only. It does not prove passkey possession, network reachability, or secret decryptability. Use `creds encrypt NAME INPUT` to encrypt a file, or `creds encrypt NAME -` to read stdin. Use `creds decrypt NAME OUTPUT` to decrypt to a new file, or `creds decrypt NAME -` to write plaintext to stdout. Each operation prints a temporary approval URL and terminal QR to stderr, followed by a short waiting status. Use Ctrl-C to cancel the CLI. Use `creds --config PATH setup`, `check`, `encrypt`, or `decrypt` for an explicit configuration file.

The static host must serve the page over HTTPS, use restrictive response headers, and serve JavaScript modules with a JavaScript MIME type. Follow the [deployment and operator guide](docs/deployment.md) to set the exact app origin, RP ID, CSP, CLI configuration, storage permissions, and UDP route. Users enter the machine DNS suffix in browser settings; deployment no longer sets a suffix allowlist.

See [release operations](docs/releasing.md) for versioned downloads, checksums, static archive layout, and GitHub release procedures.

## Test

Run the same command used by GitHub Actions:

```sh
./scripts/test.sh
```

## Development-only compatibility checks

See [browser compatibility notes](docs/browser-compatibility.md) for local WebTransport certificate-pin checks, test-passkey PRF checks, observed results, and Chromium instructions. The page and feature-gated `creds-probe-server` binary are development tools under `dev/`; they are excluded from the published `web/` directory and the default CLI build. The normal Create passkey setup flow remains in the production browser app.
