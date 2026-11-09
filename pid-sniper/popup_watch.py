"""Popup radar for PID Sniper.

Detects NEW top-level windows (dialogs, toasts, browser popups, message boxes)
as they appear, and resolves each one to a PID, process, class and geometry.

Standalone use (prints one JSON object per popup, no GUI):

    python popup_watch.py --seconds 60
    python popup_watch.py --seconds 60 --all

Import use:

    from popup_watch import PopupRadar
    radar = PopupRadar(on_popup=lambda rec: print(rec))
    radar.start() ... radar.stop()
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime
import json
import os
import sys
import threading
import time

if os.name != 'nt':  # pragma: no cover - Windows only by nature
    raise SystemExit('popup_watch requires Windows.')

user32 = ctypes.WinDLL('user32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

user32.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
user32.EnumWindows.restype = wintypes.BOOL
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetWindowLongW.restype = wintypes.LONG
user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
user32.GetWindow.restype = wintypes.HWND
user32.IsWindow.argtypes = [wintypes.HWND]
user32.IsWindow.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

GWL_STYLE = -16
GWL_EXSTYLE = -20
WS_POPUP = 0x80000000
WS_EX_TOPMOST = 0x00000008
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_NOACTIVATE = 0x08000000
GW_OWNER = 4
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Shell furniture that must never be reported as a popup.
SHELL_CLASSES = {
    'Progman', 'WorkerW', 'Shell_TrayWnd', 'Shell_SecondaryTrayWnd',
    'Windows.UI.Core.CoreWindow', 'ApplicationFrameWindow', 'SysShadow',
    'ForegroundStaging', 'MultitaskingViewFrame', 'XamlExplorerHostIslandWindow',
}
# Classes that are almost always real dialogs/popups.
DIALOG_CLASSES = {'#32770', 'TaskDialog', 'MozillaDialogClass', 'Chrome_WidgetWin_1',
                  'Chrome_WidgetWin_0', 'WindowsForms10.Window.8.app.0.141b42a_r6_ad1'}


def process_path(pid: int) -> str:
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ''
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buf))
        if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value
    finally:
        kernel32.CloseHandle(handle)
    return ''


def _text(hwnd, fn, size):
    buf = ctypes.create_unicode_buffer(size)
    fn(hwnd, buf, size)
    return buf.value


def describe_window(hwnd: int) -> dict:
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    style = user32.GetWindowLongW(hwnd, GWL_STYLE) & 0xFFFFFFFF
    ex = user32.GetWindowLongW(hwnd, GWL_EXSTYLE) & 0xFFFFFFFF
    path = process_path(pid.value) if pid.value else ''
    owner = user32.GetWindow(hwnd, GW_OWNER)
    return {
        'hwnd': f'0x{hwnd:X}',
        'pid': pid.value,
        'process': os.path.basename(path) if path else '(unknown)',
        'path': path,
        'title': _text(hwnd, user32.GetWindowTextW, 1024) or '(untitled)',
        'class': _text(hwnd, user32.GetClassNameW, 256) or '(unavailable)',
        'rect': [rect.left, rect.top, rect.right, rect.bottom],
        'size': [rect.right - rect.left, rect.bottom - rect.top],
        'topmost': bool(ex & WS_EX_TOPMOST),
        'tool_window': bool(ex & WS_EX_TOOLWINDOW),
        'no_activate': bool(ex & WS_EX_NOACTIVATE),
        'popup_style': bool(style & WS_POPUP),
        'owner': f'0x{owner:X}' if owner else '',
        'time': datetime.now().strftime('%H:%M:%S'),
        'epoch': time.time(),
    }


def enumerate_visible_windows() -> dict[int, dict]:
    found: dict[int, dict] = {}

    @WNDENUMPROC
    def _cb(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        cls = _text(hwnd, user32.GetClassNameW, 256)
        if cls in SHELL_CLASSES:
            return True
        rect = wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        w, h = rect.right - rect.left, rect.bottom - rect.top
        if w <= 1 or h <= 1:
            return True
        found[hwnd] = {'class': cls, 'w': w, 'h': h}
        return True

    user32.EnumWindows(_cb, 0)
    return found


def is_popup(rec: dict, total_windows: int, allow_all: bool = False) -> bool:
    if allow_all:
        return True
    if rec['pid'] == os.getpid():
        return False
    if rec['class'] in SHELL_CLASSES:
        return False
    if rec['class'] in DIALOG_CLASSES:
        return True
    if rec['popup_style'] or rec['topmost']:
        return True
    # small window that appears late and is not a normal app frame
    if rec['size'][0] < 900 and rec['size'][1] < 700 and rec['title'] != '(untitled)':
        return True
    return False


class PopupRadar(threading.Thread):
    """Polls top-level windows and reports ones that were not there before."""

    def __init__(self, on_popup, interval: float = 0.45, allow_all: bool = False):
        super().__init__(daemon=True, name='popup-radar')
        self.on_popup = on_popup
        self.interval = interval
        self.allow_all = allow_all
        self._stop = threading.Event()
        self._known: set[int] = set()
        self.seen_count = 0

    def prime(self):
        self._known = set(enumerate_visible_windows().keys())

    def run(self):
        self.prime()
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break
            try:
                current = enumerate_visible_windows()
            except Exception:
                continue
            total = len(current)
            for hwnd in current.keys() - self._known:
                try:
                    rec = describe_window(hwnd)
                except Exception:
                    continue
                if is_popup(rec, total, self.allow_all):
                    rec['windows_on_screen'] = total
                    self.seen_count += 1
                    try:
                        self.on_popup(rec)
                    except Exception:
                        pass
            self._known = set(current.keys())

    def stop(self):
        self._stop.set()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='Watch for new popup windows and report PID + details.')
    ap.add_argument('--seconds', type=float, default=30.0)
    ap.add_argument('--all', action='store_true', help='report every new top-level window')
    ap.add_argument('--interval', type=float, default=0.45)
    args = ap.parse_args(argv)

    radar = PopupRadar(lambda rec: print(json.dumps(rec), flush=True),
                       interval=args.interval, allow_all=args.all)
    radar.start()
    print(f'watching for {args.seconds}s ...', file=sys.stderr, flush=True)
    deadline = time.time() + args.seconds
    try:
        while time.time() < deadline:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    radar.stop()
    print(f'popups seen: {radar.seen_count}', file=sys.stderr, flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
