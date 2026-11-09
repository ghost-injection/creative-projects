"""PID Sniper desktop: identify clicked windows and watch for transient consoles.

All captures remain in memory unless the user chooses to copy them.
"""
import ctypes
from ctypes import wintypes
from datetime import datetime
import os
from pathlib import Path
import queue
import sys
import time
import tkinter as tk
from tkinter import messagebox

if os.name != 'nt':
    raise SystemExit('PID Sniper requires Windows.')

user32 = ctypes.WinDLL('user32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
LRESULT = ctypes.c_ssize_t
MOUSEPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
EVENTPROC = ctypes.WINFUNCTYPE(None, wintypes.HANDLE, wintypes.DWORD, wintypes.HWND,
                               wintypes.LONG, wintypes.LONG, wintypes.DWORD, wintypes.DWORD)

class POINT(ctypes.Structure):
    _fields_ = [('x', wintypes.LONG), ('y', wintypes.LONG)]

class MOUSEHOOK(ctypes.Structure):
    _fields_ = [('pt', POINT), ('mouseData', wintypes.DWORD), ('flags', wintypes.DWORD),
                ('time', wintypes.DWORD), ('dwExtraInfo', ctypes.c_size_t)]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD),
                ('th32ProcessID', wintypes.DWORD), ('th32DefaultHeapID', ctypes.c_size_t),
                ('th32ModuleID', wintypes.DWORD), ('cntThreads', wintypes.DWORD),
                ('th32ParentProcessID', wintypes.DWORD), ('pcPriClassBase', wintypes.LONG),
                ('dwFlags', wintypes.DWORD), ('szExeFile', wintypes.WCHAR * 260)]

user32.SetWindowsHookExW.argtypes = [ctypes.c_int, MOUSEPROC, wintypes.HINSTANCE, wintypes.DWORD]
user32.SetWindowsHookExW.restype = wintypes.HANDLE
user32.UnhookWindowsHookEx.argtypes = [wintypes.HANDLE]
user32.UnhookWindowsHookEx.restype = wintypes.BOOL
user32.CallNextHookEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]
user32.CallNextHookEx.restype = LRESULT
user32.SetWinEventHook.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.HMODULE,
                                   EVENTPROC, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
user32.SetWinEventHook.restype = wintypes.HANDLE
user32.UnhookWinEvent.argtypes = [wintypes.HANDLE]
user32.UnhookWinEvent.restype = wintypes.BOOL
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = wintypes.BOOL
user32.WindowFromPoint.argtypes = [POINT]
user32.WindowFromPoint.restype = wintypes.HWND
user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
user32.GetAncestor.restype = wintypes.HWND
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.GetWindowThreadProcessId.restype = wintypes.DWORD
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HMODULE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

def image_path(pid):
    proc = kernel32.OpenProcess(0x1000, False, pid)
    if not proc:
        return ''
    try:
        buf = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(buf))
        return buf.value if kernel32.QueryFullProcessImageNameW(proc, 0, buf, ctypes.byref(length)) else ''
    finally:
        kernel32.CloseHandle(proc)

def parent_process(pid):
    snap = kernel32.CreateToolhelp32Snapshot(2, 0)  # TH32CS_SNAPPROCESS
    if snap == ctypes.c_void_p(-1).value:
        return None, ''
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    parent = None
    names = {}
    try:
        valid = kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while valid:
            names[entry.th32ProcessID] = entry.szExeFile
            if entry.th32ProcessID == pid:
                parent = entry.th32ParentProcessID
            valid = kernel32.Process32NextW(snap, ctypes.byref(entry))
        return parent, names.get(parent, '')
    finally:
        kernel32.CloseHandle(snap)

def get_owner(hwnd):
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value

def describe(hwnd, pid, source, with_parent=True):
    title, cls = ctypes.create_unicode_buffer(1024), ctypes.create_unicode_buffer(256)
    user32.GetWindowTextW(hwnd, title, len(title))
    user32.GetClassNameW(hwnd, cls, len(cls))
    path = image_path(pid)
    parent_pid, parent_name = parent_process(pid) if with_parent else (None, '')
    return {'pid': str(pid), 'process': Path(path).name if path else '(access denied or exited)',
            'title': title.value or '(untitled)', 'class': cls.value or '(unavailable)',
            'path': path or '(access denied or process exited)',
            'parent': (f'{parent_name or "unknown"}  /  PID {parent_pid}' if parent_pid else '(unavailable)'),
            'hwnd': f'0x{int(hwnd):X}', 'time': datetime.now().strftime('%H:%M:%S'), 'source': source}

def looks_like_console(record):
    name = record['process'].lower()
    title = record['title'].lower()
    cls = record['class'].lower()
    return (name in {'powershell.exe', 'pwsh.exe', 'cmd.exe', 'conhost.exe', 'openconsole.exe', 'windowsterminal.exe'}
            or cls == 'consolewindowclass'
            or any(s in title for s in ('powershell', 'command prompt', 'windows terminal')))

class Monitor:
    def __init__(self, emit):
        self.emit = emit
        self.mouse_hook = None
        self.event_hook = None
        self.mouse_cb = MOUSEPROC(self._mouse)
        self.event_cb = EVENTPROC(self._event)
        self.recent = {}

    def arm_click(self):
        if not self.mouse_hook:
            self.mouse_hook = user32.SetWindowsHookExW(14, self.mouse_cb, kernel32.GetModuleHandleW(None), 0)
            if not self.mouse_hook:
                raise ctypes.WinError(ctypes.get_last_error())

    def stop_click(self):
        if self.mouse_hook:
            user32.UnhookWindowsHookEx(self.mouse_hook)
            self.mouse_hook = None

    def start_watch(self):
        if not self.event_hook:
            # EVENT_OBJECT_SHOW, out of context, skip our process. No screen content is recorded.
            self.event_hook = user32.SetWinEventHook(0x8002, 0x8002, None, self.event_cb, 0, 0, 0x0002)
            if not self.event_hook:
                raise ctypes.WinError(ctypes.get_last_error())
            self.recent.clear()

    def stop_watch(self):
        if self.event_hook:
            user32.UnhookWinEvent(self.event_hook)
            self.event_hook = None
        self.recent.clear()

    def _mouse(self, code, wparam, lparam):
        try:
            if code >= 0 and wparam == 0x0201:
                event = ctypes.cast(lparam, ctypes.POINTER(MOUSEHOOK)).contents
                hwnd = user32.WindowFromPoint(event.pt)
                hwnd = user32.GetAncestor(hwnd, 2) or hwnd
                if hwnd:
                    pid = get_owner(hwnd)
                    if pid and pid != os.getpid():
                        self.emit(describe(hwnd, pid, 'CLICK'))
        except Exception:
            pass
        return user32.CallNextHookEx(self.mouse_hook, code, wparam, lparam)

    def _event(self, hook, event, hwnd, obj, child, thread, timestamp):
        try:
            if not hwnd or obj != 0 or child != 0 or not user32.IsWindowVisible(hwnd):
                return
            if user32.GetAncestor(hwnd, 2) != hwnd:
                return
            pid = get_owner(hwnd)
            if not pid or pid == os.getpid():
                return
            marker = (int(hwnd), pid)
            now = time.monotonic()
            if now - self.recent.get(marker, 0) < 2:
                return
            # A shell can be gone before polling; capture metadata at its show event.
            record = describe(hwnd, pid, 'WATCH', with_parent=False)
            if looks_like_console(record):
                parent_pid, parent_name = parent_process(pid)
                if parent_pid:
                    record['parent'] = f'{parent_name or "unknown"}  /  PID {parent_pid}'
                self.recent[marker] = now
                if len(self.recent) > 500:
                    self.recent = {key: value for key, value in self.recent.items() if now - value < 60}
                self.emit(record)
        except Exception:
            # WinEvent callbacks must never throw into the native message loop.
            return

BG = '#0B131F'  # deep glass base
SURFACE = '#111D23'  # raised panel
CARD = '#162231'  # raised card
EDGE = '#102239'  # hairline edge
TEAL = '#58FF78'        # PID Sniper identity accent (kept green)
CYAN = '#40F4DC'        # glass ShellEdge, secondary accent
TEXT = '#E6F2F0'
MUTED = '#7E93A8'
WARN = '#f4bf65'

class App:
    def __init__(self):
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
        self.root = tk.Tk()
        self.root.title('PID SNIPER  //  GHOST TOOLKIT')
        self.root.configure(bg=BG)
        density = max(1.0, self.root.winfo_fpixels('1i') / 96.0)
        width = min(round(880*density), self.root.winfo_screenwidth() - 30)
        height = min(round(760*density), self.root.winfo_screenheight() - 100)
        self.root.geometry(f'{width}x{height}')
        self.root.minsize(min(round(700*density), width), min(round(610*density), height))
        self.root.protocol('WM_DELETE_WINDOW', self.close)
        self.root.bind('<Escape>', lambda e: self.disarm())
        self.root.bind('<Control-c>', lambda e: self.copy_details())
        self.root.bind('<Control-l>', lambda e: self.clear())
        self.events = queue.Queue(maxsize=100)
        self.monitor = Monitor(self.push)
        self.armed = False
        self.watching = False
        self.records = []
        self.selected = None
        self.pin = tk.BooleanVar(value=False)
        self.build()
        self.root.after(35, self.poll)

    def label(self, parent, text='', fg=TEXT, bg=BG, size=10, weight='normal', **kwargs):
        return tk.Label(parent, text=text, bg=bg, fg=fg, font=('Segoe UI', size, weight), **kwargs)

    def button(self, parent, text, command, *, primary=False):
        return tk.Button(parent, text=text, command=command, cursor='hand2', relief='flat', bd=0,
                         highlightthickness=0, bg=TEAL if primary else CARD,
                         fg=BG if primary else TEXT, activebackground=CYAN if primary else '#1E3247',
                         activeforeground=BG if primary else TEXT, disabledforeground='#4A5D70',
                         font=('Consolas', 10, 'bold'), padx=16, pady=9)

    def build(self):
        outer = tk.Frame(self.root, bg=BG, padx=24, pady=18)
        outer.pack(fill='both', expand=True)
        top = tk.Frame(outer, bg=BG)
        top.pack(fill='x')
        self.label(top, 'G H O S T   T O O L K I T    /    S Y S T E M   I N T E L L I G E N C E', fg=MUTED, size=9, weight='bold').pack(side='left')
        tk.Checkbutton(top, text='PIN WINDOW', variable=self.pin,
            command=lambda: self.root.attributes('-topmost', self.pin.get()),
            bg=BG, fg=MUTED, activebackground=BG, activeforeground=TEAL,
            selectcolor=SURFACE, bd=0, font=('Segoe UI', 9, 'bold')).pack(side='right')
        title = tk.Frame(outer, bg=BG)
        title.pack(fill='x', pady=(14, 11))
        self.label(title, 'PID SNIPER', size=25, weight='bold').pack(anchor='w')
        sub = tk.Frame(title, bg=BG)
        sub.pack(anchor='w', pady=(1, 0))
        self.label(sub, '▎', fg=CYAN, size=10, weight='bold').pack(side='left')
        self.label(sub, 'I D E N T I F Y   ·   W A T C H   ·   T R A C E', fg=TEAL, size=9, weight='bold').pack(side='left')
        rule = tk.Frame(outer, bg=BG)
        rule.pack(fill='x', pady=(10, 12))
        tk.Frame(rule, bg=TEAL, height=1).pack(side='left', ipadx=90)
        tk.Frame(rule, bg=EDGE, height=1).pack(side='left', fill='x', expand=True)
        status = tk.Frame(outer, bg=SURFACE, highlightbackground=EDGE, highlightthickness=1, padx=14, pady=9)
        status.pack(fill='x')
        self.status = self.label(status, '●  STANDBY', bg=SURFACE, fg=TEAL, size=10, weight='bold', anchor='w')
        self.status.pack(fill='x')
        self.hint = self.label(status, 'Arm & click a window, or watch for new console windows.', bg=SURFACE, fg=MUTED, size=9, anchor='w')
        self.hint.pack(fill='x', pady=(3, 0))
        controls = tk.Frame(outer, bg=BG)
        controls.pack(fill='x', pady=10)
        self.arm_btn = self.button(controls, '◎  ARM & CLICK', self.arm, primary=True)
        self.arm_btn.pack(side='left', fill='x', expand=True)
        self.cancel_btn = self.button(controls, 'CANCEL', self.disarm)
        self.cancel_btn.pack(side='left', padx=(8, 0))
        self.cancel_btn.config(state='disabled')
        self.watch_btn = self.button(controls, '◉  WATCH POPUPS', self.toggle_watch)
        self.watch_btn.pack(side='left', padx=(8, 0))

        main = tk.Frame(outer, bg=BG)
        main.pack(fill='both', expand=True)
        main.columnconfigure(0, weight=3, uniform='columns')
        main.columnconfigure(1, weight=2, uniform='columns')
        main.rowconfigure(0, weight=1)
        details = tk.Frame(main, bg=CARD, highlightbackground=EDGE, highlightthickness=1, padx=14, pady=11)
        details.grid(row=0, column=0, sticky='nsew', padx=(0, 5))
        details.columnconfigure(1, weight=1)
        self.label(details, 'TARGET DETAILS', bg=CARD, fg=TEAL, size=9, weight='bold').grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 8))
        self.fields = {}
        for row, (key, label) in enumerate([('pid','WINDOW PID'), ('process','PROCESS'), ('parent','PARENT'),
                                            ('title','WINDOW'), ('class','CLASS'), ('path','FILE PATH'),
                                            ('time','CAPTURED')], start=1):
            self.label(details, label, bg=CARD, fg=MUTED, size=8, weight='bold', anchor='nw').grid(row=row, column=0, sticky='nw', padx=(0, 10), pady=4)
            value = self.label(details, '—', bg=CARD, size=9, anchor='nw', justify='left', wraplength=round(290*max(1.0, self.root.winfo_fpixels('1i')/96)))
            value.grid(row=row, column=1, sticky='ew', pady=4)
            self.fields[key] = value
        history = tk.Frame(main, bg=SURFACE, highlightbackground=EDGE, highlightthickness=1, padx=11, pady=11)
        history.grid(row=0, column=1, sticky='nsew', padx=(5, 0))
        self.label(history, 'RECENT CAPTURES', bg=SURFACE, fg=TEAL, size=9, weight='bold').pack(anchor='w')
        self.label(history, 'Select a capture to inspect it', bg=SURFACE, fg=MUTED, size=8).pack(anchor='w', pady=(1, 7))
        self.listbox = tk.Listbox(history, bg=SURFACE, fg=TEXT, selectbackground='#1E3247', selectforeground=TEXT,
                                  relief='flat', bd=0, highlightthickness=0, activestyle='none',
                                  font=('Consolas', 9), exportselection=False)
        self.listbox.pack(fill='both', expand=True)
        self.listbox.bind('<<ListboxSelect>>', self.select_history)
        self.button(history, 'CLEAR HISTORY', self.clear).pack(fill='x', pady=(8, 0))
        bottom = tk.Frame(outer, bg=BG)
        bottom.pack(fill='x', pady=(10, 0))
        self.copy_pid_btn = self.button(bottom, 'COPY PID', self.copy_pid)
        self.copy_pid_btn.pack(side='left')
        self.copy_btn = self.button(bottom, 'COPY DETAILS', self.copy_details)
        self.copy_btn.pack(side='left', padx=(8, 0))
        self.copy_pid_btn.config(state='disabled')
        self.copy_btn.config(state='disabled')
        self.label(bottom, 'LOCAL ONLY  •  NO AUTO-LOG', fg=MUTED, size=8).pack(side='right')

    def push(self, record):
        try:
            self.events.put_nowait(record)
        except queue.Full:
            pass

    def arm(self):
        try:
            self.monitor.arm_click()
        except OSError as exc:
            messagebox.showerror('Cannot arm PID Sniper', str(exc), parent=self.root)
            return
        self.armed = True
        self.arm_btn.config(state='disabled')
        self.cancel_btn.config(state='normal')
        self.update_status('Click any other window. Your click passes through normally.')

    def disarm(self):
        self.monitor.stop_click()
        self.armed = False
        self.arm_btn.config(state='normal')
        self.cancel_btn.config(state='disabled')
        self.update_status()

    def toggle_watch(self):
        if self.watching:
            self.monitor.stop_watch()
            self.watching = False
            self.watch_btn.config(text='◉  WATCH POPUPS', bg='#193144', fg=TEXT)
        else:
            try:
                self.monitor.start_watch()
            except OSError as exc:
                messagebox.showerror('Cannot watch for popups', str(exc), parent=self.root)
                return
            self.watching = True
            self.watch_btn.config(text='■  STOP WATCH', bg='#f4bf65', fg=BG)
        self.update_status()

    def update_status(self, hint=None):
        if self.armed and self.watching:
            state = '●  ARMED  /  WATCHING'
        elif self.armed:
            state = '●  ARMED  /  SELECT A WINDOW'
        elif self.watching:
            state = '●  WATCHING FOR NEW CONSOLES'
        else:
            state = '●  STANDBY'
        self.status.config(text=state, fg=WARN if self.watching else TEAL)
        self.hint.config(text=hint or ('Watch captures visible console windows while this app is running; brief flashes may be missed.' if self.watching
                            else 'Arm & click a window, or watch for new console windows.'))

    def poll(self):
        for _ in range(25):
            try:
                record = self.events.get_nowait()
            except queue.Empty:
                break
            if record['source'] == 'CLICK' and not self.armed:
                continue
            if record['source'] == 'WATCH' and not self.watching:
                continue
            if record['source'] == 'CLICK':
                self.disarm()
            self.records.insert(0, record)
            del self.records[100:]
            self.listbox.insert(0, f"{record['time']}  {record['process']}  [{record['pid']}]")
            if self.listbox.size() > 100:
                self.listbox.delete(100, 'end')
            self.listbox.selection_clear(0, 'end')
            self.listbox.selection_set(0)
            self.show(record)
        self.root.after(35, self.poll)

    def show(self, record):
        self.selected = record
        for key, label in self.fields.items():
            label.config(text=record[key])
        self.copy_pid_btn.config(state='normal')
        self.copy_btn.config(state='normal')
        self.hint.config(text='Captured window owner and parent. A console host PID may differ from the shell PID.')

    def select_history(self, event=None):
        selection = self.listbox.curselection()
        if selection and selection[0] < len(self.records):
            self.show(self.records[selection[0]])

    def clear(self):
        self.records.clear()
        self.selected = None
        self.listbox.delete(0, 'end')
        for label in self.fields.values():
            label.config(text='—')
        self.copy_pid_btn.config(state='disabled')
        self.copy_btn.config(state='disabled')
        self.update_status()

    def copy(self, value):
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.hint.config(text='Copied to clipboard.')

    def copy_pid(self):
        if self.selected:
            self.copy(self.selected['pid'])

    def copy_details(self):
        if self.selected:
            self.copy('\n'.join(f'{key.upper()}: {value}' for key, value in self.selected.items()))

    def close(self):
        self.monitor.stop_click()
        self.monitor.stop_watch()
        self.root.destroy()

if __name__ == '__main__':
    App().root.mainloop()
