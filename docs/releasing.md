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
    settings.mjs
    transport.mjs
    webauthn.mjs
```

Extract the versioned directory and serve its contents from the static site's document root. Keep the relative paths. The page supports a deployment path, such as `https://keys.example.com/creds/`, when its directory structure remains intact.

The archive does not configure HTTP response headers. Serve `.mjs` files with `text/javascript` or `application/javascript`. Return 404 for missing modules. Set `X-Content-Type-Options: nosniff` and the CSP, `Referrer-Policy`, and other headers listed in the [deployment guide](deployment.md). Users configure the machine DNS suffix in browser settings; do not edit the production page for each deployment suffix.

## Configure GitHub Actions

The release workflow uses its built-in `GITHUB_TOKEN`. Its `release-please` job has write permission for contents, issues, and pull requests. In **Settings → Actions → General**, allow GitHub Actions to create pull requests.

GitHub [creates approval-required `pull_request` runs](https://docs.github.com/en/actions/concepts/security/github_token#when-github_token-triggers-workflow-runs) for `opened`, `synchronize`, and `reopened` events when a workflow using `GITHUB_TOKEN` creates or updates a pull request. After Release Please creates or updates its PR, review the PR and select **Approve workflows to run** in the PR's merge status box. A user with write access can approve these runs. This starts the test workflow on the eligible `pull_request` event, so its `test` check can satisfy the required branch ruleset check.

The test workflow also supports **Actions → test → Run workflow** on the PR's head branch for a standalone manual run. A [`workflow_dispatch` check](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks#checks-from-some-workflow-jobs-are-not-evaluated) does not appear in the PR checks section and does not satisfy the required check, even when it passes on the current head. Use the approval step above for the required check.

After the approval-required run completes, confirm that `test` passed for the PR's current head SHA and that the PR merge status box recognizes the required check. Repeat the approval and verification after each Release Please PR update; a successful check on an earlier head does not verify a newer one. Keep the required branch protection check named `test`.

## First release

The manifest starts at the current crate version, `0.1.0`. After this release setup is merged, if a push to `main` does not create the first release PR, run **Actions → release → Run workflow** on `main`, select `first-release`, and enter `0.1.0` in `release_as`. This dispatch invokes the pinned Release Please CLI with the manifest and version override. It uses the same Rust release configuration and opens the normal release PR; the `ci` changelog section lets CI-only setup history produce a non-empty first changelog. Review and merge that PR to create the tag and draft. The dispatch does not create or publish a release directly.

The regular push workflow continues to use `release-please-action@v4`. Keep the CLI package version aligned with the Release Please version bundled by that action when either is updated.

## Recovery

If packaging, upload, or verification fails, the workflow leaves the release as a draft. Fix the cause, then run **Actions → release → Run workflow** on `main`, select `recover`, and enter the existing `vX.Y.Z` draft tag. Recovery requires the tag to point to a commit reachable from `main`, the tag version to match `Cargo.toml`, and the GitHub release to remain a draft. It rebuilds from the tagged commit, removes stale draft assets, uploads the expected files, downloads them, checks the exact asset list and bytes, and then publishes.

The workflow resolves the release with GitHub's authenticated, paginated [release listing API](https://docs.github.com/en/rest/releases/releases), selects one exact tag match, and fetches that release by ID. GitHub only lists drafts for users with push access, so the package job needs `contents: write`. If the listing has no match, check the workflow token's permission and the release state. API errors stop the workflow. Asset deletion, upload, download, and publication also use release or asset IDs. The workflow checks the tag and draft before asset cleanup and upload, then checks both again before publication.

Recovery does not create tags or releases and cannot edit a published release. Do not delete or move version tags. Protect `v*` tags with a repository tag ruleset that blocks updates and deletions while allowing the release workflow identity to create new tags. For a failure before the draft exists, correct the workflow or repository configuration and use the reviewed Release Please PR process; do not create a release by hand.
