"""Read published release metadata without downloading or installing software."""

from __future__ import annotations

import json
import re
from datetime import datetime
from http.client import HTTPException
from urllib import error, parse, request

CURRENT_VERSION = "0.1.0"
REPOSITORY = "ITherso/monolith-test"
LATEST_RELEASE_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
MAX_RESPONSE_BYTES = 1024 * 1024


def _version_tuple(value: object) -> tuple[int, int, int] | None:
    """Compare stable numeric tags, ignoring an optional v prefix/build metadata."""
    if not isinstance(value, str) or len(value) > 128:
        return None
    match = re.fullmatch(
        r"[vV]?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?"
        r"(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?",
        value,
    )
    if not match:
        return None
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or "0")


def _result(current_version: str, status: str, **fields: object) -> dict[str, object]:
    result: dict[str, object] = {
        "update_available": False,
        "status": status,
        "current_version": current_version,
        "repository": REPOSITORY,
        "latest_version": None,
        "release_name": None,
        "release_notes": "",
        "release_url": None,
        "download_url": None,
        "published_at": None,
    }
    result.update(fields)
    return result


def _release_result(data: object, current_version: str) -> dict[str, object]:
    if not isinstance(data, dict):
        return _result(
            current_version,
            "invalid_response",
            error="Release metadata must be an object.",
        )
    if not all(isinstance(data.get(field), bool) for field in ("draft", "prerelease")):
        return _result(
            current_version,
            "invalid_response",
            error="Release publication flags are missing or invalid.",
        )
    if data["draft"] or data["prerelease"] or data.get("published_at") is None:
        return _result(
            current_version,
            "no_published_release",
            message="The response is not a published stable release.",
        )
    published_at = data.get("published_at")
    if not isinstance(published_at, str):
        return _result(
            current_version,
            "invalid_response",
            error="Release publication date is invalid.",
        )
    try:
        timestamp = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("Publication date must include a timezone")
    except ValueError:
        return _result(
            current_version,
            "invalid_response",
            error="Release publication date is invalid.",
        )

    tag = data.get("tag_name")
    latest = _version_tuple(tag)
    current = _version_tuple(current_version)
    if latest is None or not isinstance(tag, str):
        return _result(
            current_version,
            "unsupported_version",
            error="Release tag is not a supported stable numeric version.",
        )
    if current is None:
        return _result(
            current_version,
            "unsupported_version",
            error="Current version is not a supported stable numeric version.",
        )
    notes = data.get("body")
    if notes is not None and not isinstance(notes, str):
        return _result(
            current_version,
            "invalid_response",
            error="Release notes must be text or null.",
        )
    name = data.get("name")
    if name is not None and not isinstance(name, str):
        return _result(
            current_version,
            "invalid_response",
            error="Release name must be text or null.",
        )

    # These are links only. This helper never follows asset URLs or writes files.
    download_url = None
    assets = data.get("assets", [])
    asset_prefix = f"https://github.com/{REPOSITORY}/releases/download/"
    if isinstance(assets, list):
        for asset in assets:
            candidate = (
                asset.get("browser_download_url") if isinstance(asset, dict) else None
            )
            if isinstance(candidate, str) and candidate.startswith(asset_prefix):
                download_url = candidate
                break
    status = (
        "update_available"
        if latest > current
        else "up_to_date"
        if latest == current
        else "current_newer"
    )
    return _result(
        current_version,
        status,
        update_available=latest > current,
        latest_version=tag,
        release_name=name or tag,
        release_notes=(notes or "No release notes")[:200],
        release_url=f"https://github.com/{REPOSITORY}/releases/tag/{parse.quote(tag, safe='')}",
        download_url=download_url,
        published_at=published_at,
    )


def check_release_updates(current_version: str = CURRENT_VERSION) -> dict[str, object]:
    """Check GitHub's latest published full release; network errors stay distinct."""
    if _version_tuple(current_version) is None:
        return _result(
            current_version,
            "unsupported_version",
            error="Current version is not a supported stable numeric version.",
        )
    req = request.Request(
        LATEST_RELEASE_URL,
        headers={
            "User-Agent": f"Monolith-Release-Check/{CURRENT_VERSION}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
        method="GET",
    )
    try:
        with request.urlopen(req, timeout=10) as response:
            if response.status != 200:
                return _result(
                    current_version,
                    "http_error",
                    error=f"Release metadata returned HTTP {response.status}.",
                )
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                return _result(
                    current_version,
                    "invalid_response",
                    error="Release metadata exceeds the size limit.",
                )
    except error.HTTPError as exc:
        status_code = exc.code
        exc.close()
        if status_code == 404:
            return _result(
                current_version,
                "no_release",
                message="No published stable release was found at the repository endpoint.",
            )
        return _result(
            current_version,
            "http_error",
            http_status=status_code,
            error=f"GitHub returned HTTP {status_code}.",
        )
    except TimeoutError:
        return _result(
            current_version, "unavailable", error="Release metadata check timed out."
        )
    except (error.URLError, OSError, HTTPException):
        return _result(
            current_version,
            "unavailable",
            error="Unable to contact GitHub release metadata.",
        )
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return _result(
            current_version,
            "invalid_response",
            error="Release metadata is not valid JSON.",
        )
    return _release_result(data, current_version)
