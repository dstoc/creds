# Release operations

Release Please reads conventional commits on `main` and opens or updates a reviewed release pull request. The PR updates `Cargo.toml`, `Cargo.lock`, and `CHANGELOG.md`. Merge that PR to create its version tag and a draft GitHub release. The release workflow builds and checks both assets from the tagged commit, uploads them to the draft, downloads and compares every uploaded byte, and publishes the release only after those checks pass.

## Downloads

Download the assets from the project's [GitHub Releases](https://github.com/dstoc/creds/releases). Each release provides:

- `creds-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`, with the `creds` executable, `LICENSE`, and `README.md` in a versioned directory.
- `creds-web-vX.Y.Z.zip`, with the production static site and `LICENSE` in a versioned directory.
- `SHA256SUMS`, with checksums for the executable archive and web archive.

Check downloaded files before use:

```sh
sha256sum --check SHA256SUMS
tar -xzf creds-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
unzip -q creds-web-vX.Y.Z.zip
```

The Linux archive targets `x86_64-unknown-linux-gnu`. CI builds it on Ubuntu 22.04, so it requires x86_64 Linux with glibc 2.35 or newer. It dynamically links to `libc.so.6`, `libm.so.6`, `libgcc_s.so.1`, and the glibc ELF loader at `/lib64/ld-linux-x86-64.so.2`. CI runs `ldd` on the archived executable and fails if a dependency is unresolved. It is not a musl or fully static binary. Run `creds --help` after extraction to check that the executable can start on the target system.

## Deploy the web archive

The ZIP has this layout:

```text
creds-web-vX.Y.Z/
  index.html
  style.css
  favicon.svg
  LICENSE
  js/
    encoding.mjs
    envelope.mjs
    main.mjs
    transport.mjs
    webauthn.mjs
```

Extract the versioned directory and serve its contents from the static site's document root. Keep the relative paths. The page supports a deployment path, such as `https://keys.example.com/creds/`, when its directory structure remains intact.

The archive does not configure HTTP response headers. Serve `.mjs` files with `text/javascript` or `application/javascript`. Return 404 for missing modules. Set `X-Content-Type-Options: nosniff` and the CSP, `Referrer-Policy`, and other headers listed in the [deployment guide](deployment.md). Set the configured machine DNS suffix in the production page and matching `connect-src` policy before deployment.

## Configure GitHub Actions

The release workflow uses its built-in `GITHUB_TOKEN`. Its `release-please` job has write permission for contents, issues, and pull requests. In **Settings → Actions → General**, allow GitHub Actions to create pull requests.

GitHub does not start `push` or `pull_request` workflows for changes made with `GITHUB_TOKEN`. The test workflow supports manual dispatch so you can run the required check named `test` on a Release Please PR:

1. After Release Please creates or updates its PR, open **Actions → test → Run workflow**.
2. Select the PR's head branch and run the workflow. It runs `./scripts/test.sh`, including the release packaging and publication-gate tests.
3. Open the run and confirm its commit SHA matches the PR's current head SHA. Confirm the run's `test` check passed for that commit. Repeat these steps after every PR update; an earlier successful run does not verify a newer head.

Keep the required branch protection check named `test`.

## First release

The manifest starts at the current crate version, `0.1.0`. After this release setup is merged, if a push to `main` does not create the first release PR, run **Actions → release → Run workflow** on `main`, select `first-release`, and enter `0.1.0` in `release_as`. This dispatch invokes the pinned Release Please CLI with the manifest and version override. It uses the same Rust release configuration and opens the normal release PR; the `ci` changelog section lets CI-only setup history produce a non-empty first changelog. Review and merge that PR to create the tag and draft. The dispatch does not create or publish a release directly.

The regular push workflow continues to use `release-please-action@v4`. Keep the CLI package version aligned with the Release Please version bundled by that action when either is updated.

## Recovery

If packaging, upload, or verification fails, the workflow leaves the release as a draft. Fix the cause, then run **Actions → release → Run workflow** on `main`, select `recover`, and enter the existing `vX.Y.Z` draft tag. Recovery requires the tag to point to a commit reachable from `main`, the tag version to match `Cargo.toml`, and the GitHub release to remain a draft. It rebuilds from the tagged commit, removes stale draft assets, uploads the expected files, downloads them, checks the exact asset list and bytes, and then publishes.

Recovery does not create tags or releases and cannot edit a published release. Do not delete or move version tags. Protect `v*` tags with a repository tag ruleset that blocks updates and deletions while allowing the release workflow identity to create new tags. For a failure before the draft exists, correct the workflow or repository configuration and use the reviewed Release Please PR process; do not create a release by hand.
