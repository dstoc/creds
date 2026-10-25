#!/usr/bin/env python3
"""Create the versioned Linux and static-web release archives."""

from __future__ import annotations

import argparse
import gzip
import io
import re
import tarfile
import tomllib
import zipfile
from pathlib import Path


VERSION_RE = re.compile(r"\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
WEB_FILES = (
    "index.html",
    "style.css",
    "favicon.svg",
    "js/encoding.mjs",
    "js/envelope.mjs",
    "js/main.mjs",
    "js/settings.mjs",
    "js/transport.mjs",
    "js/webauthn.mjs",
)


def _regular_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular file: {path}")
    return path.read_bytes()


def _add_tar_file(archive: tarfile.TarFile, source: Path, name: str) -> None:
    data = _regular_file(source)
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o755 if source.stat().st_mode & 0o111 else 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    archive.addfile(info, io.BytesIO(data))


def package_release(version: str, binary: Path, output_dir: Path, repo_root: Path) -> tuple[Path, Path]:
    """Package a tagged checkout. The manifest version must match the tag."""
    if not VERSION_RE.fullmatch(version):
        raise ValueError(f"unsupported release version: {version!r}")

    with (repo_root / "Cargo.toml").open("rb") as manifest_file:
        manifest = tomllib.load(manifest_file)
    manifest_version = manifest.get("package", {}).get("version")
    if manifest_version != version:
        raise ValueError(f"tag version {version} does not match Cargo.toml version {manifest_version!r}")

    _regular_file(binary)
    if not binary.stat().st_mode & 0o111:
        raise ValueError(f"binary is not executable: {binary}")

    web_root = repo_root / "web"
    web_data = {name: _regular_file(web_root / name) for name in WEB_FILES}
    license_data = _regular_file(repo_root / "LICENSE")
    _regular_file(repo_root / "README.md")

    output_dir.mkdir(parents=True, exist_ok=True)
    binary_name = f"creds-v{version}-x86_64-unknown-linux-gnu.tar.gz"
    web_name = f"creds-web-v{version}.zip"
    binary_archive = output_dir / binary_name
    web_archive = output_dir / web_name

    binary_prefix = f"creds-v{version}-x86_64-unknown-linux-gnu"
    with binary_archive.open("wb") as raw_file:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_file, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                _add_tar_file(archive, binary, f"{binary_prefix}/creds")
                _add_tar_file(archive, repo_root / "LICENSE", f"{binary_prefix}/LICENSE")
                _add_tar_file(archive, repo_root / "README.md", f"{binary_prefix}/README.md")

    web_prefix = f"creds-web-v{version}"
    with zipfile.ZipFile(web_archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in [(name, web_data[name]) for name in WEB_FILES]:
            info = zipfile.ZipInfo(f"{web_prefix}/{name}", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 << 16)
            archive.writestr(info, data)
        info = zipfile.ZipInfo(f"{web_prefix}/LICENSE", date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = (0o100644 << 16)
        archive.writestr(info, license_data)

    return binary_archive, web_archive


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="release version without the v prefix")
    parser.add_argument("--binary", required=True, type=Path, help="built creds executable")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()

    try:
        archives = package_release(args.version, args.binary, args.output_dir, args.repo_root)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
        parser.error(str(error))
    for archive in archives:
        print(archive)


if __name__ == "__main__":
    main()
