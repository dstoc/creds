# creds

`creds` is a Rust CLI and library with a static web client for browser-approved credential encryption. The web client uses plain HTML, CSS, and native JavaScript modules. It has no frontend framework, bundler, transpiler, persistent application backend, or JavaScript package dependencies.

The design and security contracts are in [the proposal](docs/proposals/creds-proposal.md). The CLI supports interactive local setup and read-only setup checks. The browser can create an ES256 passkey, confirm PRF support, and export its public key. The Rust library verifies bounded WebAuthn assertions against the locally pinned key. The library now includes v1 key derivation, AES-256-GCM envelopes, and atomic named-secret storage internals. The CLI commands and browser approval flow that connect those internals remain future work.

Open the static web client at the trusted deployment origin and copy its exported key into `creds setup`. Then run `creds check` to validate the local setup. Use `creds --config PATH setup` or `creds --config PATH check` for an explicit configuration file.

## Test

Run the same command used by GitHub Actions:

```sh
./scripts/test.sh
```

## Browser compatibility probes

See [browser compatibility notes](docs/browser-compatibility.md) for local WebTransport certificate-pin checks, passkey creation/export and PRF checks, observed versions, and runner limitations. The `creds probe-server` command is a loopback-only echo fixture for that experiment. It is not a production service or an alternate transport.
