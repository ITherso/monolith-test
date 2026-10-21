"""Fail-closed host protection before any operational modules are imported."""

import os
import platform
import sys


def enforce_host_safety():
    """Refuse operational execution on Windows and Windows-connected WSL hosts.

    There is deliberately no environment flag or command-line bypass. This guard
    is a protective stop, not an isolation boundary or proof of host cleanliness.
    """
    windows = os.name == "nt" or sys.platform.startswith(("win32", "cygwin", "msys"))
    wsl = bool(os.getenv("WSL_INTEROP") or os.getenv("WSL_DISTRO_NAME"))
    if not windows and not wsl:
        release = platform.release().lower()
        wsl = "microsoft" in release or "wsl" in release
    if windows or wsl:
        raise RuntimeError(
            "HOST_SAFETY_BLOCK: operational startup/import is disabled on Windows "
            "and WSL to protect the local computer. No feature modules were loaded "
            "by this entry point. Do not run individual agent or tool scripts on "
            "your personal computer."
        )
