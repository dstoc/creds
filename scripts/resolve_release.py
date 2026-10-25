from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


TAG_PATTERN = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")


def _validate_tag(tag: str) -> None:
    if TAG_PATTERN.fullmatch(tag) is None:
        raise ValueError(f"Invalid release tag: {tag}")


def _release_id(release: dict[str, Any]) -> int:
    release_id = release.get("id")
    if type(release_id) is not int or release_id <= 0:
        raise ValueError("GitHub release response has no valid numeric ID")
    return release_id


def verify_release(
    tag: str,
    release: Any,
    *,
    expected_id: int | None = None,
    expected_state: str = "draft",
) -> int:
    _validate_tag(tag)
    if not isinstance(release, dict):
        raise ValueError("GitHub release response is not an object")

    release_id = _release_id(release)
    if release.get("tag_name") != tag:
        raise ValueError(
            f"Release ID {release_id} has tag {release.get('tag_name')!r}, expected {tag!r}"
        )
    if expected_id is not None and release_id != expected_id:
        raise ValueError(
            f"GitHub returned release ID {release_id}, expected release ID {expected_id}"
        )

    expected_draft = expected_state == "draft"
    if release.get("draft") is not expected_draft:
        if expected_draft and release.get("draft") is False:
            raise ValueError(f"Release {tag} is not a draft; refusing to modify or publish it")
        if expected_draft:
            raise ValueError(f"Release {tag} has no valid draft state")
        raise ValueError(f"Release {tag} is still a draft after publication")
    return release_id


def resolve_draft_release_id(tag: str, pages: Any) -> int:
    _validate_tag(tag)
    if not isinstance(pages, list):
        raise ValueError("Paginated releases response is not an array of pages")

    matches: list[dict[str, Any]] = []
    for page_number, page in enumerate(pages, start=1):
        if not isinstance(page, list):
            raise ValueError(f"Release listing page {page_number} is not an array")
        for release in page:
            if not isinstance(release, dict):
                raise ValueError(f"Release listing page {page_number} has a non-object entry")
            if not isinstance(release.get("tag_name"), str):
                raise ValueError(f"Release listing page {page_number} has an entry without a tag")
            if release["tag_name"] == tag:
                matches.append(release)

    if not matches:
        raise ValueError(
            f"No release with tag {tag} was visible in the authenticated paginated release listing. "
            "Confirm the workflow token has contents: write and push access, and check the release state. "
            "No release was changed."
        )
    if len(matches) != 1:
        raise ValueError(
            f"Found {len(matches)} releases with tag {tag}; refusing an ambiguous release lookup"
        )
    return verify_release(tag, matches[0])


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"Could not read GitHub API response file {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"GitHub API response file {path} is not valid JSON: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve a draft release from a paginated listing or verify a release fetched by ID."
    )
    parser.add_argument("--tag", required=True, help="Expected exact vX.Y.Z release tag")
    response = parser.add_mutually_exclusive_group(required=True)
    response.add_argument("--releases-json", type=Path, help="gh api --paginate --slurp response")
    response.add_argument("--release-json", type=Path, help="GET /releases/{release_id} response")
    parser.add_argument("--expected-id", type=int, help="Require this release ID when verifying a response")
    parser.add_argument("--expected-state", choices=("draft", "published"), default="draft")
    args = parser.parse_args()

    if args.releases_json is not None:
        if args.expected_id is not None or args.expected_state != "draft":
            parser.error("--expected-id and --expected-state apply only with --release-json")
        release_id = resolve_draft_release_id(args.tag, _load_json(args.releases_json))
    else:
        release_id = verify_release(
            args.tag,
            _load_json(args.release_json),
            expected_id=args.expected_id,
            expected_state=args.expected_state,
        )
    print(release_id)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(f"Release lookup failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
