# creds

Store secrets encrypted on your machine. Approve each encrypt or decrypt request with a passkey in your browser, including from a phone that can reach the CLI machine.

```sh
creds encrypt deploy-token ./token.txt
creds decrypt deploy-token -
```

Each command prints a temporary URL and QR code. Open the URL or scan the code in your trusted browser app, review the request, and approve it with your passkey. The decrypted value in this example goes to standard output.

The optional `qr_mode` configuration setting selects `braille`, `sextant`, `half` (the default), or `kitty` rendering. See the [deployment guide](docs/deployment.md#configure-and-use-the-cli) for examples and terminal requirements.

## How it works

The CLI stores each secret as local ciphertext. The same passkey, name, and revision derive the same key, so you can decrypt a stored revision again after a new approval. Your browser sends that key to the CLI over a direct, encrypted connection pinned to the certificate in the request. The CLI verifies the passkey assertion before it accepts the key and completes the operation. Remembering a machine can skip its destination prompt; every request still needs your approval.

## Why this design

- **A copy of the stored files is not enough.** The ciphertext does not contain its decryption key; the passkey must approve access.
- **There is no central key service.** The browser app is static and does not need a backend to store secrets or keys.
- **A leaked approval URL cannot authorize key delivery.** The CLI requires a valid passkey assertion for the request.
- **Revisions use independent keys.** Each successful replacement increments the revision and derives a separate key. The CLI stages and syncs the new ciphertext, then publishes it with an atomic rename; an error before publication leaves the previous value in place. A key already approved for an older revision can still decrypt matching older ciphertext.

> **Security boundary:** creds protects ciphertext while it is stored. During approval, you trust the browser app, passkey provider, CLI machine, and operating system; a compromised endpoint can expose keys or plaintext. If you lose access to the required passkey, creds has no recovery key and your secrets may be unrecoverable.

## Install

The [GitHub releases](https://github.com/dstoc/creds/releases/latest) provide a prebuilt CLI for **x86_64 Linux with glibc 2.35 or newer**. It is not a musl binary. No prebuilt macOS or Windows CLI is published. Releases also include `creds-web-vX.Y.Z.zip`, the separate static browser app archive for people who host their own deployment.

Download `creds-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` from the latest release, replacing `X.Y.Z` with its version. The archive contains a versioned directory with the `creds` executable, `LICENSE`, and `README.md`. Download and check the archive with the release's `SHA256SUMS`, extract it, then put the executable on your `PATH`:

```sh
VERSION=X.Y.Z
archive="creds-v${VERSION}-x86_64-unknown-linux-gnu.tar.gz"
curl -LO "https://github.com/dstoc/creds/releases/download/v${VERSION}/${archive}"
curl -LO "https://github.com/dstoc/creds/releases/download/v${VERSION}/SHA256SUMS"
grep -F "$archive" SHA256SUMS | sha256sum --check -
tar -xzf "$archive"
mkdir -p "$HOME/.local/bin"
install -m 0755 "creds-v${VERSION}-x86_64-unknown-linux-gnu/creds" "$HOME/.local/bin/creds"
```

Add `$HOME/.local/bin` to your `PATH` if needed, then run `creds --help`.

### Build from source

With a compatible Rust toolchain installed, build and install from a checkout:

```sh
git clone https://github.com/dstoc/creds.git
cd creds
cargo install --locked --path .
```

The source build targets your current Rust target. Check that Rust and the crate dependencies support your operating system.

## Set up

You need a trusted HTTPS deployment of the browser app, a browser and passkey provider that support WebAuthn PRF, and a network path from the approval device to the CLI machine. The web app is separate from the CLI; if you do not already have a trusted deployment, see the [deployment guide](docs/deployment.md).

1. Open the trusted deployment. On first use, choose **Create passkey**, complete the passkey prompt, and enter your **Machine DNS suffix**. Before you choose **Save and continue**, choose **Copy public key** and keep the key for the next step. If you already saved, open **Settings → Saved public key → Copy**. If this passkey is already trusted by your CLI, choose **Use existing passkey**, enter the suffix, and choose **Save and continue**; this path does not export a public key.
2. Run `creds setup` and enter the deployment's exact HTTPS URL, a one-label machine DNS label such as `workstation`, a secret storage directory (the default is suitable for most users), the copied passkey public key, and a UDP listener address (the default is `0.0.0.0:0`). Review the displayed app origin, RP ID, machine label, storage path, listener, and pinned-key fingerprint, then confirm that you trust the key.
3. Run `creds check` to validate the local setup. This read-only check does not test passkey possession or network reachability.

Your approval device must be able to resolve and reach the CLI machine over UDP/QUIC, for example on the same Tailscale network.

## Everyday use

Encrypt from a file or from standard input, and decrypt to a new file or to standard output:

```sh
creds encrypt deploy-token ./token.txt
printf '%s' "$TOKEN" | creds encrypt deploy-token -
creds decrypt deploy-token ./token.out
creds decrypt deploy-token -
```

Encrypting a name that already exists replaces its stored value and increments its revision after approval. Decryption creates output files exclusively and refuses to overwrite an existing file; choose another path or remove the old file yourself. Press **Ctrl-C** in the CLI to cancel a pending operation.

Plaintext input and output files remain your responsibility. Protect them with appropriate file permissions and remove them when you no longer need them.

## Further reading

- [Deployment and CLI configuration](docs/deployment.md)
- [Security and design](docs/proposals/creds-proposal.md)
- [Development, testing, and browser compatibility](docs/browser-compatibility.md)
