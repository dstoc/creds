# creds

`creds` is a Rust CLI and library with a static web client for browser-approved credential encryption. The web client uses plain HTML, CSS, and native JavaScript modules. It has no frontend framework, bundler, transpiler, persistent application backend, or JavaScript package dependencies.

The design and security contracts are in [the proposal](docs/proposals/creds-proposal.md). The CLI supports local setup checks, v1 encryption envelopes, atomic named-secret storage, and temporary browser-approved key handoff. The browser can create an ES256 passkey, confirm PRF support, export its public key, and approve one operation without storing application data.

Open the static web client at the trusted deployment origin and copy its exported key into `creds setup`. Then run `creds check` to validate the local setup. Use `creds encrypt NAME INPUT` to encrypt a file, or `creds encrypt NAME -` to read stdin. Use `creds decrypt NAME OUTPUT` to decrypt to a new file, or `creds decrypt NAME -` to write plaintext to stdout. Each operation prints a temporary approval URL and terminal QR to stderr. A browser connection has 30 seconds to establish its request. The first established request gets a two-minute approval window; later connections receive only the time that remains. If no browser connects, use Ctrl-C to cancel the CLI. Use `creds --config PATH setup`, `check`, `encrypt`, or `decrypt` for an explicit configuration file.

The static host must serve the page over HTTPS, use restrictive response headers, and serve JavaScript modules with a JavaScript MIME type. Follow the [deployment and operator guide](docs/deployment.md) to set the exact app origin, RP ID, DNS suffix, CSP, CLI configuration, storage permissions, and UDP route.

See [release operations](docs/releasing.md) for versioned downloads, checksums, static archive layout, and GitHub release procedures.

## Test

Run the same command used by GitHub Actions:

```sh
./scripts/test.sh
```

## Development-only compatibility checks

See [browser compatibility notes](docs/browser-compatibility.md) for local WebTransport certificate-pin checks, test-passkey PRF checks, observed results, and Chromium instructions. The page and feature-gated `creds-probe-server` binary are development tools under `dev/`; they are excluded from the published `web/` directory and the default CLI build. The normal Create passkey setup flow remains in the production browser app.
