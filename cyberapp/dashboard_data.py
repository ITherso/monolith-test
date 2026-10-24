"""Bounded dashboard data reads and executable presence checks; never run tools."""

import json
import math
import os
import shlex
import shutil
import stat
from pathlib import Path

MAX_JSON_BYTES = 1_048_576
COUNTER_FIELDS = (
    "timestomp_count",
    "logs_cleared_count",
    "artifacts_removed_count",
    "payloads_obfuscated_count",
)


def _read_json(path: str | Path):
    """Return data only from a bounded regular file; malformed data is unavailable."""
    if str(path).startswith(("\\\\", "//")):
        return None
    try:
        source = Path(path).resolve(strict=True)
        if str(source).startswith(("\\\\", "//")):
            return None
        source_stat = source.stat()
        if (
            not stat.S_ISREG(source_stat.st_mode)
            or source_stat.st_size > MAX_JSON_BYTES
        ):
            return None
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_JSON_BYTES:
                return None
            content = stream.read(MAX_JSON_BYTES + 1)
        if len(content) > MAX_JSON_BYTES:
            return None
        return json.loads(content.decode("utf-8"))
    except (OSError, ValueError, RecursionError):
        return None


def load_leaderboard(path: str | Path) -> list[dict]:
    """Keep at most ten valid display rows without trusting the JSON's shape."""
    saved = _read_json(path)
    if not isinstance(saved, list):
        return []
    entries = []
    for row in saved:
        if not isinstance(row, dict):
            continue
        user, score = row.get("user"), row.get("score")
        if not isinstance(user, str) or not user.strip() or len(user) > 128:
            continue
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            continue
        if score < 0 or (isinstance(score, float) and not math.isfinite(score)):
            continue
        entries.append({"user": user, "score": score})
        if len(entries) == 10:
            break
    return entries


def load_evasion_stats(path: str | Path) -> dict:
    """Read display counters only; absent telemetry must not assert enablement."""
    stats = {field: 0 for field in COUNTER_FIELDS}
    stats.update(
        last_evasion_action=None, evasion_enabled=False, telemetry_available=False
    )
    saved = _read_json(path)
    if not isinstance(saved, dict):
        return stats
    for field in COUNTER_FIELDS:
        value = saved.get(field)
        if type(value) is int and value >= 0:
            stats[field] = value
            stats["telemetry_available"] = True
    action = saved.get("last_evasion_action")
    if isinstance(action, str) and len(action) <= 512:
        stats["last_evasion_action"] = action
        stats["telemetry_available"] = True
    enabled = saved.get("evasion_enabled")
    if isinstance(enabled, bool):
        stats["evasion_enabled"] = enabled
        stats["telemetry_available"] = True
    return stats


def executable_available(command: object) -> bool:
    """Resolve only the executable token via PATH; arguments are never evaluated."""
    if not isinstance(command, str) or not command.strip():
        return False
    try:
        tokens = shlex.split(command, posix=os.name != "nt")
        if not tokens:
            return False
        executable = tokens[0]
        if os.name == "nt" and executable[:1] in {"'", '"'}:
            executable = executable[1:-1]
        return shutil.which(os.path.expanduser(executable)) is not None
    except (OSError, ValueError):
        return False
