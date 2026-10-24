#!/bin/sh
set -eu

cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
node --check scripts/virtual-authenticator.mjs
node --check web/js/main.mjs
node --check web/js/transport.mjs
node --check web/js/webauthn.mjs
node --test web/js/encoding.test.mjs
