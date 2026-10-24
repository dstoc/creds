#!/usr/bin/env python3
"""Verify that an unpublished GitHub release has exactly the expected bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


TAG_RE = re.compile(r"\Av(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")


def expected_asset_names(tag: str) -> tuple[str, str, str]:
    match = TAG_RE.fullmatch(tag)
    if not match:
        raise ValueError(f"invalid release tag: {tag!r}")
    version = tag[1:]
    return (
        f"creds-v{version}-x86_64-unknown-linux-gnu.tar.gz",
        f"creds-web-v{version}.zip",
        "SHA256SUMS",
    )


def _read_regular(directory: Path, name: str) -> bytes:
    path = directory / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing regular file {name!r} in {directory}")
    return path.read_bytes()


def verify_assets(tag: str, local_dir: Path, downloaded_dir: Path, release: dict) -> None:
    expected = expected_asset_names(tag)
    if release.get("tag_name") != tag:
        raise ValueError("release tag does not match the selected tag")
    if release.get("draft") is not True:
        raise ValueError("release is not a draft; refusing to modify or publish it")

    remote_names = tuple(sorted(asset.get("name", "") for asset in release.get("assets", [])))
    if remote_names != tuple(sorted(expected)):
        raise ValueError(f"release assets differ from the required set: {remote_names!r}")

    local_names = tuple(sorted(path.name for path in local_dir.iterdir()))
    if local_names != tuple(sorted(expected)):
        raise ValueError(f"local release assets differ from the required set: {local_names!r}")
    downloaded_names = tuple(sorted(path.name for path in downloaded_dir.iterdir()))
    if downloaded_names != tuple(sorted(expected)):
        raise ValueError(f"downloaded release assets differ from the required set: {downloaded_names!r}")

    asset_names = expected[:2]
    checksum_lines = "".join(
        f"{hashlib.sha256(_read_regular(local_dir, name)).hexdigest()}  {name}\n"
        for name in asset_names
    ).encode("ascii")
    if _read_regular(local_dir, "SHA256SUMS") != checksum_lines:
        raise ValueError("local SHA256SUMS does not match the generated assets")
    if _read_regular(downloaded_dir, "SHA256SUMS") != checksum_lines:
        raise ValueError("uploaded SHA256SUMS does not match the generated assets")

    for name in asset_names:
        if _read_regular(downloaded_dir, name) != _read_regular(local_dir, name):
            raise ValueError(f"uploaded asset differs from the generated asset: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--local-dir", required=True, type=Path)
    parser.add_argument("--downloaded-dir", required=True, type=Path)
    parser.add_argument("--release-json", required=True, type=Path)
    args = parser.parse_args()

    try:
        release = json.loads(args.release_json.read_text(encoding="utf-8"))
        verify_assets(args.tag, args.local_dir, args.downloaded_dir, release)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(f"Verified the draft assets for {args.tag}")


if __name__ == "__main__":
    main()
