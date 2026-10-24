# creds

`creds` is a Rust CLI and library with a static web client for browser-approved credential encryption. The web client uses plain HTML, CSS, and native JavaScript modules. It has no frontend framework, bundler, transpiler, persistent application backend, or JavaScript package dependencies.

The design and security contracts are in [the proposal](docs/proposals/creds-proposal.md). The CLI supports local setup checks, v1 encryption envelopes, atomic named-secret storage, and temporary browser-approved key handoff. The browser can create an ES256 passkey, confirm PRF support, export its public key, and approve one operation without storing application data.

Open the static web client at the trusted deployment origin and copy its exported key into `creds setup`. Then run `creds check` to validate the local setup. Use `creds encrypt NAME INPUT` to encrypt a file, or `creds encrypt NAME -` to read stdin. Use `creds decrypt NAME OUTPUT` to decrypt to a new file, or `creds decrypt NAME -` to write plaintext to stdout. Each operation prints a temporary approval URL and terminal QR to stderr and waits up to two minutes for a passkey assertion from the configured app origin. Use `creds --config PATH setup`, `check`, `encrypt`, or `decrypt` for an explicit configuration file.

The static host must serve the page over HTTPS and send the security headers described in [the browser compatibility notes](docs/browser-compatibility.md). Replace the `keys.example` suffix in the page and local server CSP rules with the deployed app hostname. A real deployment must also make `<hostname>.<app-hostname>` reachable over UDP for WebTransport.

## Test

Run the same command used by GitHub Actions:

```sh
./scripts/test.sh
```

## Browser compatibility probes

See [browser compatibility notes](docs/browser-compatibility.md) for local WebTransport certificate-pin checks, passkey creation/export and PRF checks, observed versions, and runner limitations. The `creds probe-server` command is a loopback-only echo fixture for that experiment. It is not a production service or an alternate transport.
