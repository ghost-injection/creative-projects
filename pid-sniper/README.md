# PID SNIPER

Point at a window, get its PID. No terminal, no task manager archaeology.

A Windows GUI that answers the only question that matters during an incident:
*what process owns this window, and where does it live on disk?*

## What it does

- **Click capture** — arm the sniper, click any window, get PID, process, parent,
  window title, class, handle and full executable path.
- **Popup radar** — watches for *new* top-level windows and logs each one as it
  appears: dialogs, toasts, message boxes, browser popups. Double-click a row to
  load that popup's intelligence.
- **Transient console watch** — catches console windows that flash and vanish,
  which is usually how a stager announces itself.
- **Copy out** — one click for the PID, one for the full detail block.
- **Local only** — nothing is sent anywhere, nothing is auto-logged to disk
  unless you pass a log path to the radar CLI.

## Files

| File | Purpose |
|---|---|
| `pid_sniper.pyw` | Compact GUI: click capture + popup radar log |
| `pid_sniper_desktop.pyw` | Full desktop build: click capture, popup watch, parent PID, capture history |
| `popup_watch.py` | Radar module, also usable headless from the command line |

## Run it

```bat
pythonw pid_sniper.pyw
pythonw pid_sniper_desktop.pyw
```

Headless popup watch, one JSON object per new window, perfect for piping into
your own alerting:

```bat
python popup_watch.py --seconds 60
python popup_watch.py --seconds 60 --all
```

Real output from `popup_watch.py` catching a live dialog:

```json
{"hwnd":"0x9B1D3C","pid":34140,"process":"powershell.exe",
 "title":"INTRUSION DETECTED","class":"#32770",
 "rect":[758,484,965,643],"size":[207,159],
 "topmost":false,"tool_window":false,"no_activate":false,
 "popup_style":true,"owner":"","time":"21:52:15","windows_on_screen":62}
```

## Build a standalone exe

```bat
python -m PyInstaller "PID Sniper.spec" --noconfirm
```

`console=False`, icon included, no external runtime needed.

## Requirements

Windows 10/11, Python 3.10+, standard library only. `ctypes` talks straight to
`user32` and `kernel32`; `tkinter` draws the UI. No pip install.

## Design notes

- Identity is resolved by the window's owning PID, never by its title.
- The radar diffs window handles between polls, so it reports *appearances*,
  not the constant noise of windows that were always there.
- Shell furniture (`Progman`, `Shell_TrayWnd`, taskbar hosts) is filtered out
  so the log stays readable.
- Palette is a deep glass base (`#0B131F`) with a single acid-green accent
  (`#58FF78`) and a cyan secondary (`#40F4DC`); panels sit at `#111D23`.

## License

MIT
