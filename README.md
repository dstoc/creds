# creds

`creds` is a Rust CLI and static web client for browser-approved credential encryption. The repository starts with one Rust executable and plain HTML, CSS, and native JavaScript modules. It has no frontend framework, bundler, transpiler, persistent application backend, or JavaScript package dependencies.

The design and security contracts are in [the proposal](docs/proposals/creds-proposal.md). This initial milestone adds the crate skeleton and local browser compatibility probes. It does not yet implement setup, assertion verification, credential encryption, or the production approval flow.

## Test

Run the same command used by GitHub Actions:

```sh
./scripts/test.sh
```

## Browser compatibility probes

See [browser compatibility notes](docs/browser-compatibility.md) for local WebTransport certificate-pin checks, WebAuthn PRF checks, observed versions, and runner limitations. The `creds probe-server` command is a loopback-only echo fixture for that experiment. It is not a production service or an alternate transport.
