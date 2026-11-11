from __future__ import annotations

import ctypes
import hashlib
import os
import platform
import plistlib
import secrets
import string
import subprocess
from pathlib import Path

import psutil

DONGLE_FILENAME = "SECUREHUB_DONGLE.key"


def _windows_roots() -> list[Path]:
    roots: list[Path] = []
    mask = ctypes.windll.kernel32.GetLogicalDrives()
    for index, letter in enumerate(string.ascii_uppercase):
        if mask & (1 << index):
            root = f"{letter}:\\"
            # DRIVE_REMOVABLE = 2. Do not treat an ordinary fixed disk as a dongle.
            if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 2:
                roots.append(Path(root))
    return roots


def _linux_is_removable(device: str) -> bool:
    name = Path(device).name
    # Resolve partition to its physical parent (e.g. sdb1 -> sdb).
    sys_entry = Path("/sys/class/block") / name
    try:
        resolved = sys_entry.resolve(strict=True)
        candidates = [resolved / "removable", resolved.parent / "removable"]
        for candidate in candidates:
            if candidate.exists() and candidate.read_text().strip() == "1":
                return True
    except OSError:
        return False
    return False


def _mac_is_removable(mountpoint: str) -> bool:
    try:
        result = subprocess.run(
            ["diskutil", "info", "-plist", mountpoint], capture_output=True, check=True, timeout=4
        )
        info = plistlib.loads(result.stdout)
        return bool(info.get("RemovableMedia", False) or info.get("Ejectable", False))
    except Exception:
        return False


def removable_mounts() -> list[Path]:
    system = platform.system()
    if system == "Windows":
        return _windows_roots()
    mounts: list[Path] = []
    for part in psutil.disk_partitions(all=True):
        if system == "Linux" and _linux_is_removable(part.device):
            mounts.append(Path(part.mountpoint))
        elif system == "Darwin" and _mac_is_removable(part.mountpoint):
            mounts.append(Path(part.mountpoint))
    return mounts


def is_removable_path(path: str) -> bool:
    candidate = Path(path).expanduser().resolve()
    system = platform.system()
    if system == "Windows":
        drive, _ = os.path.splitdrive(str(candidate))
        if not drive:
            return False
        root = drive + "\\"
        return ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 2
    for mount in removable_mounts():
        try:
            candidate.relative_to(mount.resolve())
            return True
        except ValueError:
            continue
    return False


def create_dongle_file(drive_path: str) -> tuple[str, str]:
    """Write a unique token to a removable drive and return (token, sha256 digest)."""
    target = Path(drive_path).expanduser()
    if not target.exists() or not target.is_dir():
        raise ValueError("Lokasi USB tidak ditemukan atau bukan folder/drive.")
    if os.environ.get("SECUREHUB_DEV_ALLOW_VIRTUAL_USB") != "1" and not is_removable_path(str(target)):
        raise ValueError("Lokasi tersebut tidak terdeteksi sebagai USB/removable drive.")
    token = secrets.token_hex(32)
    token_path = target / DONGLE_FILENAME
    token_path.write_text(token, encoding="ascii")
    try:
        os.chmod(token_path, 0o600)
    except OSError:
        pass
    return token, hashlib.sha256(token.encode("ascii")).hexdigest()


def find_connected_dongle(expected_hash: str | None) -> tuple[bool, str]:
    if not expected_hash:
        return False, "USB dongle belum diregistrasikan."
    if os.environ.get("SECUREHUB_DEV_ALLOW_VIRTUAL_USB") == "1":
        # Development-only switch, never enabled by default.
        return True, "Mode pengembangan: pemeriksaan USB virtual aktif."
    for mount in removable_mounts():
        token_path = mount / DONGLE_FILENAME
        try:
            token = token_path.read_text(encoding="ascii").strip()
            digest = hashlib.sha256(token.encode("ascii")).hexdigest()
            if secrets.compare_digest(digest, expected_hash):
                return True, f"USB terverifikasi ({mount})."
        except (OSError, UnicodeError):
            continue
    return False, "USB dongle SecureHub tidak ditemukan. Hubungkan USB yang terdaftar."
