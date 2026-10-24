from __future__ import annotations

import hashlib
import json
import posixpath
import re
import shutil
import tarfile
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path

import package_release
import verify_release_assets


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_VERSION = "1.2.3"


class ReleasePackagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        shutil.copytree(REPO_ROOT / "web", self.root / "web")
        cargo_manifest = (REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        cargo_manifest, replacements = re.subn(
            r'(?m)^version = "[^"]+"$',
            f'version = "{FIXTURE_VERSION}"',
            cargo_manifest,
            count=1,
        )
        if replacements != 1:
            raise AssertionError("expected one package version in Cargo.toml")
        (self.root / "Cargo.toml").write_text(cargo_manifest, encoding="utf-8")
        shutil.copy2(REPO_ROOT / "LICENSE", self.root / "LICENSE")
        shutil.copy2(REPO_ROOT / "README.md", self.root / "README.md")
        self.binary = self.root / "creds"
        self.binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.binary.chmod(0o755)
        self.output = self.root / "dist"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_release_archives_contain_only_the_production_files(self) -> None:
        binary_archive, web_archive = package_release.package_release(
            FIXTURE_VERSION, self.binary, self.output, self.root
        )
        with tarfile.open(binary_archive, "r:gz") as archive:
            prefix = f"creds-v{FIXTURE_VERSION}-x86_64-unknown-linux-gnu"
            self.assertEqual(
                set(archive.getnames()),
                {f"{prefix}/creds", f"{prefix}/LICENSE", f"{prefix}/README.md"},
            )
            self.assertTrue(archive.getmember(f"{prefix}/creds").mode & 0o111)

        with zipfile.ZipFile(web_archive) as archive:
            prefix = f"creds-web-v{FIXTURE_VERSION}"
            expected = {f"{prefix}/{name}" for name in package_release.WEB_FILES}
            expected.add(f"{prefix}/LICENSE")
            self.assertEqual(set(archive.namelist()), expected)
            self.assertFalse(any("test" in name or "probe" in name for name in archive.namelist()))
            self.assertIn(b"Create passkey", archive.read(f"{prefix}/index.html"))
            self.assertIn(b"Approve", archive.read(f"{prefix}/index.html"))

    def test_package_rejects_a_tag_that_disagrees_with_cargo(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not match Cargo.toml"):
            package_release.package_release("0.2.0", self.binary, self.output, self.root)

    def test_packaged_web_paths_resolve_with_the_extraction_layout(self) -> None:
        _, web_archive = package_release.package_release(
            FIXTURE_VERSION, self.binary, self.output, self.root
        )
        with zipfile.ZipFile(web_archive) as archive:
            names = set(archive.namelist())
            prefix = f"creds-web-v{FIXTURE_VERSION}/"
            html = archive.read(f"{prefix}index.html").decode("utf-8")
            for relative_path in ("style.css", "favicon.svg", "js/main.mjs"):
                self.assertIn(f"{prefix}{relative_path}", names)
                self.assertIn(relative_path, html)
            for module in package_release.WEB_FILES:
                if module.endswith(".mjs"):
                    module_path = f"{prefix}{module}"
                    self.assertIn(module_path, names)
                    source = archive.read(module_path).decode("utf-8")
                    for import_path in re.findall(r'from\s+["\'](\./[^"\']+)["\']', source):
                        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(module), import_path))
                        self.assertIn(f"{prefix}{resolved}", names)


class ReleaseVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.local = self.root / "local"
        self.downloaded = self.root / "downloaded"
        self.local.mkdir()
        self.downloaded.mkdir()
        self.tag = "v1.2.3"
        self.names = verify_release_assets.expected_asset_names(self.tag)
        (self.local / self.names[0]).write_bytes(b"linux executable")
        (self.local / self.names[1]).write_bytes(b"static app")
        self._write_checksums(self.local)
        for name in self.names:
            shutil.copy2(self.local / name, self.downloaded / name)
        self.release = {"tag_name": self.tag, "draft": True, "assets": [{"name": n} for n in self.names]}

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_checksums(self, directory: Path) -> None:
        lines = "".join(
            f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}\n"
            for name in self.names[:2]
        )
        (directory / "SHA256SUMS").write_text(lines, encoding="ascii")

    def test_matching_draft_assets_pass(self) -> None:
        verify_release_assets.verify_assets(self.tag, self.local, self.downloaded, self.release)

    def test_published_release_is_rejected(self) -> None:
        self.release["draft"] = False
        with self.assertRaisesRegex(ValueError, "not a draft"):
            verify_release_assets.verify_assets(self.tag, self.local, self.downloaded, self.release)

    def test_missing_or_stale_remote_assets_are_rejected(self) -> None:
        self.release["assets"].pop()
        with self.assertRaisesRegex(ValueError, "required set"):
            verify_release_assets.verify_assets(self.tag, self.local, self.downloaded, self.release)

    def test_unexpected_remote_assets_are_rejected(self) -> None:
        self.release["assets"].append({"name": "old-release.zip"})
        with self.assertRaisesRegex(ValueError, "required set"):
            verify_release_assets.verify_assets(self.tag, self.local, self.downloaded, self.release)

    def test_tag_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid release tag"):
            verify_release_assets.expected_asset_names("v1.2.3/overwrite")

    def test_corrupt_remote_bytes_are_rejected(self) -> None:
        (self.downloaded / self.names[0]).write_bytes(b"stale executable")
        with self.assertRaisesRegex(ValueError, "differs from the generated asset"):
            verify_release_assets.verify_assets(self.tag, self.local, self.downloaded, self.release)

    def test_bad_checksums_are_rejected(self) -> None:
        (self.downloaded / "SHA256SUMS").write_text("", encoding="ascii")
        with self.assertRaisesRegex(ValueError, "SHA256SUMS"):
            verify_release_assets.verify_assets(self.tag, self.local, self.downloaded, self.release)


class WorkflowContractTests(unittest.TestCase):
    def test_release_please_uses_rust_versioning_and_keeps_releases_in_draft(self) -> None:
        config = json.loads((REPO_ROOT / "release-please-config.json").read_text(encoding="utf-8"))
        manifest = json.loads((REPO_ROOT / ".release-please-manifest.json").read_text(encoding="utf-8"))
        cargo_manifest = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        self.assertEqual(config["release-type"], "rust")
        self.assertIs(config["draft"], True)
        self.assertIs(config["force-tag-creation"], True)
        self.assertEqual(config["packages"]["."]["release-type"], "rust")
        self.assertEqual(manifest, {".": cargo_manifest["package"]["version"]})

    def test_rust_manifest_candidate_tag_matches_the_release_workflow_gate(self) -> None:
        config = json.loads((REPO_ROOT / "release-please-config.json").read_text(encoding="utf-8"))
        package = config["packages"]["."]
        self.assertIs(package["include-component-in-tag"], False)

        cargo_manifest = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        component = package.get("component", cargo_manifest["package"]["name"])
        prefix = f"{component}-" if package["include-component-in-tag"] else ""
        candidate_tag = f"{prefix}v{FIXTURE_VERSION}"
        self.assertEqual(candidate_tag, "v1.2.3")
        self.assertRegex(candidate_tag, r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
        workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn('test "$RELEASE_TAG" = "v$RELEASE_VERSION"', workflow)

    def test_first_release_cli_override_keeps_ci_only_history_in_the_changelog(self) -> None:
        config = json.loads((REPO_ROOT / "release-please-config.json").read_text(encoding="utf-8"))
        visible_types = {
            section["type"]
            for section in config["changelog-sections"]
            if not section.get("hidden", False)
        }
        self.assertIn("ci", visible_types)
        self.assertIn("feat", visible_types)
        self.assertIn("fix", visible_types)

        workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        first_release = workflow.split("      - name: Create first release PR", 1)[1].split(
            "      - uses: googleapis/release-please-action@v4", 1
        )[0]
        self.assertIn("npm exec --yes --package=release-please@17.3.0", first_release)
        self.assertIn("release-please release-pr", first_release)
        self.assertIn("--manifest-file=.release-please-manifest.json", first_release)
        self.assertIn('--release-as="$RELEASE_AS"', first_release)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.operation == 'first-release'", first_release)

        action_step = workflow.split("      - uses: googleapis/release-please-action@v4", 1)[1].split(
            "  package-release:", 1
        )[0]
        self.assertIn("if: ${{ github.event_name == 'push' }}", action_step)
        self.assertNotIn("release-as:", action_step)

    def test_release_prs_use_a_token_that_triggers_the_existing_check(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        test_workflow = (REPO_ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
        self.assertIn("RELEASE_PLEASE_TOKEN", workflow)
        self.assertIn("token: ${{ secrets.RELEASE_PLEASE_TOKEN }}", workflow)
        self.assertIn("name: test", test_workflow)
        self.assertIn("./scripts/test.sh", test_workflow)

    def test_recovery_is_limited_to_existing_drafts_and_publish_follows_verification(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("- recover", workflow)
        self.assertIn("refs/heads/main", workflow)
        self.assertIn("test -z \"$RELEASE_AS\"", workflow)
        self.assertIn("git ls-remote --exit-code --refs", workflow)
        self.assertIn("release.get(\"draft\") is not True", workflow)
        upload = workflow.index("- name: Upload assets to draft")
        verify = workflow.index("- name: Download and verify every uploaded byte")
        publish = workflow.index("- name: Publish verified release")
        self.assertLess(upload, verify)
        self.assertLess(verify, publish)
        self.assertIn("gh release edit \"$RELEASE_TAG\" --draft=false --verify-tag", workflow)


if __name__ == "__main__":
    unittest.main()
