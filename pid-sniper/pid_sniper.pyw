"""PID Sniper: one-click window identification without a terminal window."""
import ctypes
from ctypes import wintypes
from datetime import datetime
import os
from pathlib import Path
import queue
import sys
import tkinter as tk
from tkinter import messagebox

import popup_watch

if os.name != 'nt':
    raise SystemExit('PID Sniper requires Windows.')

user32 = ctypes.WinDLL('user32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
LRESULT = ctypes.c_ssize_t
HHOOK = wintypes.HANDLE
HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)

class POINT(ctypes.Structure):
    _fields_ = [('x', wintypes.LONG), ('y', wintypes.LONG)]

class MOUSEHOOK(ctypes.Structure):
    _fields_ = [('pt', POINT), ('mouseData', wintypes.DWORD),
                ('flags', wintypes.DWORD), ('time', wintypes.DWORD),
                ('dwExtraInfo', ctypes.c_size_t)]

user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD]
user32.SetWindowsHookExW.restype = HHOOK
user32.UnhookWindowsHookEx.argtypes = [HHOOK]
user32.UnhookWindowsHookEx.restype = wintypes.BOOL
user32.CallNextHookEx.argtypes = [HHOOK, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]
user32.CallNextHookEx.restype = LRESULT
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
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

def target_at(point):
    hwnd = user32.WindowFromPoint(point)
    if not hwnd:
        return None
    hwnd = user32.GetAncestor(hwnd, 2) or hwnd  # GA_ROOT
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return int(hwnd), pid.value

def describe_target(hwnd, pid):
    title, cls = ctypes.create_unicode_buffer(1024), ctypes.create_unicode_buffer(256)
    user32.GetWindowTextW(hwnd, title, len(title))
    user32.GetClassNameW(hwnd, cls, len(cls))
    path = ''
    proc = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if proc:
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            length = wintypes.DWORD(len(buffer))
            if kernel32.QueryFullProcessImageNameW(proc, 0, buffer, ctypes.byref(length)):
                path = buffer.value
        finally:
            kernel32.CloseHandle(proc)
    return {'pid': str(pid), 'process': Path(path).name if path else '(access denied or exited)',
            'title': title.value or '(untitled)', 'class': cls.value or '(unavailable)',
            'path': path or '(access denied or process exited)', 'hwnd': hex(hwnd).upper().replace('X', 'x'),
            'time': datetime.now().strftime('%H:%M:%S')}

class Sniper:
    def __init__(self, on_target):
        self.hook = None
        self.on_target = on_target
        self.callback = HOOKPROC(self._callback)  # retain the callback until unhooked

    def arm(self):
        if self.hook:
            return
        self.hook = user32.SetWindowsHookExW(14, self.callback, kernel32.GetModuleHandleW(None), 0)
        if not self.hook:
            raise ctypes.WinError(ctypes.get_last_error())

    def disarm(self):
        if self.hook:
            user32.UnhookWindowsHookEx(self.hook)
            self.hook = None

    def _callback(self, code, wparam, lparam):
        if code >= 0 and wparam == 0x0201:  # WM_LBUTTONDOWN
            event = ctypes.cast(lparam, ctypes.POINTER(MOUSEHOOK)).contents
            target = target_at(event.pt)
            if target and target[1] and target[1] != os.getpid():
                self.on_target(target)
        return user32.CallNextHookEx(self.hook, code, wparam, lparam)

BG = '#0B131F'  # deep glass base
PANEL = '#111D23'  # raised panel
INPUT = '#080E18'  # input well
LINE = '#102239'  # hairline edge
GREEN = '#58FF78'       # PID Sniper identity accent (kept)
BRIGHT = '#B7FFB4'
MUTED = '#7E93A8'       # glass muted blue-grey
WHITE = '#E6F2F0'
CYAN = '#40F4DC'        # glass ShellEdge accent, secondary here

class App:
    def __init__(self):
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
        self.root = tk.Tk()
        self.root.title('PID SNIPER // Ghost Toolkit')
        self.root.configure(bg=BG)
        # Tk geometry is in physical pixels while text uses DPI-scaled points.
        # Match the window and wrap lengths to the text scale on high-DPI displays.
        self.density = max(1.0, self.root.winfo_fpixels('1i') / 96.0)
        width, height = round(710 * self.density), round(790 * self.density)
        self.root.geometry(f'{width}x{height}')
        self.root.minsize(round(660 * self.density), round(720 * self.density))
        self.root.protocol('WM_DELETE_WINDOW', self.close)
        self.root.bind('<Escape>', lambda event: self.cancel())
        self.root.bind('<Control-c>', lambda event: self.copy_details())
        self.targets = queue.Queue(maxsize=1)
        self.sniper = Sniper(self._queue_target)
        self.record = None
        self.armed = False
        self.popups = queue.Queue()
        self.popup_records = {}
        self.radar = None
        self.watching = False
        self.build()
        self.root.after(40, self.poll)

    def build(self):
        root = self.root
        frame = tk.Frame(root, bg=BG, padx=26, pady=20)
        frame.pack(fill='both', expand=True)
        header = tk.Frame(frame, bg=BG)
        header.pack(fill='x')
        tk.Label(header, text='G H O S T   T O O L K I T    /    U T I L I T Y   0 1', bg=BG, fg=MUTED,
                 font=('Consolas', 9, 'bold')).pack(side='left')
        self.pin = tk.BooleanVar(value=False)
        tk.Checkbutton(header, text='PIN', variable=self.pin, command=self.toggle_pin,
                       bg=BG, fg=MUTED, activebackground=BG, activeforeground=GREEN,
                       selectcolor=PANEL, font=('Consolas', 9), bd=0).pack(side='right')
        tk.Label(frame, text='PID SNIPER', bg=BG, fg=WHITE, font=('Segoe UI', 27, 'bold')).pack(anchor='w', pady=(16, 0))
        sub = tk.Frame(frame, bg=BG)
        sub.pack(anchor='w', pady=(2, 0))
        tk.Label(sub, text='▎', bg=BG, fg=CYAN, font=('Consolas', 10, 'bold')).pack(side='left')
        tk.Label(sub, text='P O I N T   ·   C L I C K   ·   I D E N T I F Y', bg=BG, fg=GREEN,
                 font=('Consolas', 9, 'bold')).pack(side='left')
        rule = tk.Frame(frame, bg=BG)
        rule.pack(fill='x', pady=(12, 16))
        tk.Frame(rule, bg=GREEN, height=1).pack(side='left', fill='x', expand=False, ipadx=60)
        tk.Frame(rule, bg=LINE, height=1).pack(side='left', fill='x', expand=True)

        status = tk.Frame(frame, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=18, pady=13)
        status.pack(fill='x')
        self.status = tk.Label(status, text='●  STANDBY', bg=PANEL, fg=GREEN, font=('Consolas', 11, 'bold'))
        self.status.pack(anchor='w')
        self.hint = tk.Label(status, text='Arm the cursor, then click the window you want to identify.',
                             bg=PANEL, fg=MUTED, font=('Segoe UI', 10), anchor='w', wraplength=round(580*self.density), justify='left')
        self.hint.pack(fill='x', pady=(6, 0))

        controls = tk.Frame(frame, bg=BG)
        controls.pack(fill='x', pady=(14, 18))
        self.arm_button = self.button(controls, '◎  ARM SNIPER', self.arm, accent=True)
        self.arm_button.pack(side='left', fill='x', expand=True)
        self.cancel_button = self.button(controls, 'CANCEL  /  ESC', self.cancel)
        self.cancel_button.pack(side='left', padx=(10, 0))
        self.cancel_button.configure(state='disabled')

        radar_bar = tk.Frame(frame, bg=BG)
        radar_bar.pack(fill='x', pady=(0, 12))
        self.watch_button = self.button(radar_bar, '◉  WATCH POPUPS', self.toggle_watch)
        self.watch_button.pack(side='left')
        self.watch_status = tk.Label(radar_bar, text='RADAR OFF', bg=BG, fg=MUTED,
                                     font=('Consolas', 9, 'bold'))
        self.watch_status.pack(side='left', padx=(12, 0))

        box = tk.Frame(frame, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=18, pady=14)
        box.pack(fill='both', expand=True)
        box.columnconfigure(1, weight=1)
        tk.Label(box, text='TARGET INTELLIGENCE', bg=PANEL, fg=GREEN,
                 font=('Consolas', 9, 'bold')).grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 11))
        self.values = {}
        for row, (key, name) in enumerate([('pid','PID'),('process','PROCESS'),('title','WINDOW'),
                                            ('class','CLASS'),('hwnd','HANDLE'),('path','FILE PATH'),('time','CAPTURED')], 1):
            tk.Label(box, text=name, bg=PANEL, fg=MUTED, font=('Consolas', 9, 'bold'), anchor='nw').grid(row=row,column=0,sticky='nw',pady=4,padx=(0,16))
            value = tk.Label(box, text='—', bg=PANEL, fg=WHITE, font=('Consolas', 10), anchor='w', justify='left', wraplength=round(470*self.density))
            value.grid(row=row,column=1,sticky='ew',pady=4)
            self.values[key] = value
        popup_box = tk.Frame(frame, bg=PANEL, highlightbackground=LINE, highlightthickness=1, padx=12, pady=10)
        popup_box.pack(fill='x', pady=(10, 0))
        tk.Label(popup_box, text='POPUP LOG  //  DOUBLE-CLICK A ROW TO LOAD', bg=PANEL, fg=GREEN,
                 font=('Consolas', 9, 'bold')).pack(anchor='w')
        self.popup_list = tk.Listbox(popup_box, height=5, bg=INPUT, fg=BRIGHT,
                                     selectbackground=GREEN, selectforeground=BG,
                                     font=('Consolas', 9), bd=0, highlightthickness=0,
                                     activestyle='none')
        self.popup_list.pack(fill='x', pady=(6, 0))
        self.popup_list.bind('<Double-Button-1>', self.load_popup)
        self.popup_list.bind('<Return>', self.load_popup)

        bottom = tk.Frame(frame, bg=BG)
        bottom.pack(fill='x', pady=(14, 0))
        self.copy_pid_button = self.button(bottom, 'COPY PID', self.copy_pid)
        self.copy_pid_button.pack(side='left')
        self.copy_button = self.button(bottom, 'COPY DETAILS', self.copy_details)
        self.copy_button.pack(side='left', padx=8)
        self.copy_pid_button.config(state='disabled'); self.copy_button.config(state='disabled')
        tk.Label(bottom, text='LOCAL ONLY  //  NO AUTO-LOG', bg=BG, fg=MUTED,
                 font=('Consolas', 8)).pack(side='right')

    def button(self, parent, text, command, accent=False):
        return tk.Button(parent, text=text, command=command, cursor='hand2', relief='flat',
                         bg=GREEN if accent else '#162231', fg='#0B131F' if accent else BRIGHT,
                         activebackground=CYAN if accent else '#1E3247', activeforeground='#0B131F' if accent else WHITE,
                         disabledforeground='#4A5D70', font=('Consolas', 10, 'bold'), padx=17, pady=11,
                         highlightthickness=0, bd=0)

    def toggle_pin(self):
        self.root.attributes('-topmost', self.pin.get())

    def _queue_target(self, target):
        try:
            self.targets.put_nowait(target)
        except queue.Full:
            pass

    def arm(self):
        try:
            self.sniper.arm()
        except OSError as exc:
            messagebox.showerror('Unable to arm PID Sniper', str(exc), parent=self.root)
            return
        self.armed = True
        self.arm_button.config(state='disabled')
        self.cancel_button.config(state='normal')
        self.status.config(text='●  ARMED  /  SELECT A WINDOW', fg=BRIGHT)
        self.hint.config(text='Click any other window. Your click still goes through. Press Esc here or Cancel to stop.')

    def cancel(self):
        self.sniper.disarm()
        self.armed = False
        self.arm_button.config(state='normal')
        self.cancel_button.config(state='disabled')
        self.status.config(text='●  STANDBY', fg=GREEN)
        self.hint.config(text='Arm the cursor, then click the window you want to identify.')
        while not self.targets.empty():
            try: self.targets.get_nowait()
            except queue.Empty: break

    def poll(self):
        self._drain_popups()
        try:
            target = self.targets.get_nowait()
        except queue.Empty:
            target = None
        if target and self.armed:
            self.cancel()
            self.record = describe_target(*target)
            for key, label in self.values.items():
                label.config(text=self.record[key])
            self.status.config(text='●  TARGET CAPTURED', fg=BRIGHT)
            self.hint.config(text='Capture complete. Arm again to inspect another window.')
            self.copy_pid_button.config(state='normal'); self.copy_button.config(state='normal')
        self.root.after(40, self.poll)

    def toggle_watch(self):
        if self.watching:
            if self.radar:
                self.radar.stop()
                self.radar = None
            self.watching = False
            self.watch_button.config(text='◉  WATCH POPUPS')
            self.watch_status.config(text='RADAR OFF', fg=MUTED)
            return
        self.radar = popup_watch.PopupRadar(self._queue_popup)
        self.radar.start()
        self.watching = True
        self.watch_button.config(text='■  STOP WATCHING')
        self.watch_status.config(text='RADAR ARMED  //  WATCHING FOR NEW WINDOWS', fg=BRIGHT)
        self.hint.config(text='Radar live. New popups, dialogs and toasts are logged with their PID below.')

    def _queue_popup(self, record):
        try:
            self.popups.put_nowait(record)
        except queue.Full:
            pass

    def _drain_popups(self):
        while True:
            try:
                record = self.popups.get_nowait()
            except queue.Empty:
                return
            index = self.popup_list.size()
            self.popup_records[index] = record
            stamp = record['time']
            line = f"{stamp}  {record['process']}  pid={record['pid']}  {record['class']}  {record['title']}"
            self.popup_list.insert('end', line[:160])
            self.popup_list.see('end')
            self.watch_status.config(text=f"RADAR ARMED  //  {self.popup_list.size()} CAPTURED", fg=BRIGHT)
            self.root.bell()

    def load_popup(self, _event=None):
        selection = self.popup_list.curselection()
        if not selection:
            return
        record = self.popup_records.get(selection[0])
        if not record:
            return
        self.record = {
            'pid': str(record['pid']),
            'process': record['process'],
            'title': record['title'],
            'class': record['class'],
            'hwnd': record['hwnd'],
            'path': record['path'] or '(access denied or process exited)',
            'time': record['time'],
        }
        for key, label in self.values.items():
            label.config(text=self.record[key])
        self.status.config(text='●  POPUP CAPTURED', fg=BRIGHT)
        self.hint.config(text=f"Popup loaded. topmost={record['topmost']} popup={record['popup_style']} "
                              f"size={record['size'][0]}x{record['size'][1]}")
        self.copy_pid_button.config(state='normal')
        self.copy_button.config(state='normal')

    def copy_pid(self):
        if self.record:
            self.root.clipboard_clear(); self.root.clipboard_append(self.record['pid'])
            self.hint.config(text='PID copied to clipboard.')

    def copy_details(self):
        if self.record:
            data = '\n'.join(f'{key.upper()}: {value}' for key, value in self.record.items())
            self.root.clipboard_clear(); self.root.clipboard_append(data)
            self.hint.config(text='Target details copied to clipboard.')

    def close(self):
        self.sniper.disarm()
        if self.radar:
            self.radar.stop()
            self.radar = None
        self.root.destroy()

if __name__ == '__main__':
    App().root.mainloop()
