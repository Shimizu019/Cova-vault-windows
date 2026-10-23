"""
Capture a screenshot of the running Cova Vault window.

Used for visual verification during development. The window is located by the
`cova-vault.exe` process (not by title, which can match unrelated windows),
raised to the foreground, and then grabbed from its screen rect.

Usage:
    python scripts/screenshot.py [output.png]
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import sys
import time
from pathlib import Path

from PIL import ImageGrab

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "screenshots" / "cova-vault-window.png"
PROCESS_NAME = "cova-vault.exe"

user32 = ctypes.windll.user32
user32.SetProcessDPIAware()

SW_RESTORE = 9


def find_pids(exe_name: str) -> set[int]:
    """Return the PIDs of running processes whose image name matches."""
    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", ctypes.c_ulong),
            ("cntThreads", ctypes.c_ulong),
            ("th32ParentProcessID", ctypes.c_ulong),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.windll.kernel32
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return set()

    pids: set[int] = set()
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    try:
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return set()
        while True:
            if entry.szExeFile.lower() == exe_name.lower():
                pids.add(int(entry.th32ProcessID))
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)

    return pids


def find_window_for_process(exe_name: str) -> tuple[int, int, int, int, int] | None:
    """Return (hwnd, left, top, right, bottom) for the given process name."""
    wanted = find_pids(exe_name)
    if not wanted:
        return None

    found: list[tuple[int, int, int, int, int]] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def callback(hwnd, _lparam):
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value not in wanted:
            return True
        if not user32.IsWindowVisible(hwnd):
            return True
        rect = ctypes.wintypes.RECT()
        if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            found.append(
                (hwnd, rect.left, rect.top, rect.right, rect.bottom)
            )
        return True

    user32.EnumWindows(callback, None)

    if not found:
        return None

    # Prefer the largest visible window owned by the process.
    found.sort(key=lambda w: (w[3] - w[1]) * (w[4] - w[2]), reverse=True)
    return found[0]


def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTPUT
    output.parent.mkdir(parents=True, exist_ok=True)

    window = find_window_for_process(PROCESS_NAME)
    if window is None:
        raise SystemExit(f"{PROCESS_NAME} window not found.")

    hwnd, left, top, right, bottom = window
    if right - left <= 0 or bottom - top <= 0:
        raise SystemExit(f"Degenerate window rect: {(left, top, right, bottom)}")

    # Raise above any overlapping window so the grab sees the app, not the IDE.
    user32.ShowWindow(hwnd, SW_RESTORE)
    user32.SetForegroundWindow(hwnd)
    user32.BringWindowToTop(hwnd)
    time.sleep(1.5)

    image = ImageGrab.grab(bbox=(left, top, right, bottom), all_screens=True)
    image.save(output, "PNG")

    print(f"Captured {image.width}x{image.height} -> {output}")


if __name__ == "__main__":
    main()
