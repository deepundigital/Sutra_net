"""Shared filesystem primitives for trusted checkpoint infrastructure.

Internal module: atomic durable writes and owner-only permission checks used
by both the checkpoint store and the trusted key registry.
"""

import os
import stat
import tempfile
from pathlib import Path


class TrustedFsError(ValueError):
    """Raised when a trusted file operation cannot be performed safely."""


def atomic_write_bytes(
    target: Path,
    payload: bytes,
    mode: int = 0o600,
    *,
    temp_prefix: str = ".tmp-",
) -> None:
    """Durably write payload to target via temp file + fsync + atomic rename.

    The temporary file is created inside the target directory so the rename
    never crosses filesystem boundaries, and the directory entry itself is
    fsynced so a completed write survives a crash.
    """

    directory = target.parent
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            dir=directory,
            prefix=temp_prefix,
            suffix=".tmp",
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, target)
        tmp_path = None

        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as exc:
        raise TrustedFsError(
            f"Failed to persist file: {target.name}"
        ) from exc
    finally:
        if tmp_path is not None and os.path.lexists(tmp_path):
            os.unlink(tmp_path)


def require_owner_only_file(path: Path, *, description: str = "file") -> None:
    """Reject symlinked, non-regular or group/world-accessible files."""

    info = os.lstat(path)

    if stat.S_ISLNK(info.st_mode):
        raise TrustedFsError(
            f"{description.capitalize()} must not be a symbolic link: {path.name}"
        )
    if not stat.S_ISREG(info.st_mode):
        raise TrustedFsError(
            f"{description.capitalize()} is not a regular file: {path.name}"
        )
    if info.st_mode & 0o077:
        raise TrustedFsError(
            f"{description.capitalize()} permissions are too open "
            f"(owner-only 0o600 required): {path.name}"
        )


def require_owner_only_directory(path: Path, *, description: str = "directory") -> None:
    """Reject symlinked, non-directory or group/world-accessible directories."""

    info = os.lstat(path)

    if stat.S_ISLNK(info.st_mode):
        raise TrustedFsError(
            f"{description.capitalize()} must not be a symbolic link: {path.name}"
        )
    if not stat.S_ISDIR(info.st_mode):
        raise TrustedFsError(
            f"{description.capitalize()} path is not a directory: {path.name}"
        )
    if info.st_mode & 0o077:
        raise TrustedFsError(
            f"{description.capitalize()} permissions are too open "
            f"(owner-only 0o700 required): {path.name}"
        )
