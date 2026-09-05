"""Cross-platform helpers for files containing private OpenBrivo state."""

from __future__ import annotations

import os
from typing import Any


def posix_permissions_are_private(metadata: Any) -> bool:
    """Validate owner and mode bits where POSIX exposes meaningful values.

    Windows protects these files through the ACL inherited from their parent
    directory. Its ``stat`` mode bits do not describe group/world access, and
    ``os.getuid``/``os.fchmod`` are not available there.
    """

    if os.name != "posix" or not hasattr(os, "getuid"):
        return True
    return metadata.st_uid == os.getuid() and not metadata.st_mode & 0o077


def posix_mode_is_private(metadata: Any) -> bool:
    """Validate only group/world mode bits on POSIX platforms."""

    return os.name != "posix" or not metadata.st_mode & 0o077


def restrict_open_descriptor(descriptor: int, mode: int = 0o600) -> None:
    """Apply a restrictive mode when the platform supports descriptor chmod."""

    if hasattr(os, "fchmod"):
        os.fchmod(descriptor, mode)
