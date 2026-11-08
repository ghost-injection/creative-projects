#!/usr/bin/env python3
"""
PID SNIPER — process hunter for operators who need the exact process, not a guess.

Zero dependencies. Windows + Linux. One file.

  pid-sniper scan                     # full process table, CPU/mem sorted
  pid-sniper find --name chrome       # substring match on name/cmdline
  pid-sniper find --port 8080         # who owns the listening socket
  pid-sniper port 8080                # short form, prints PID + process
  pid-sniper kill --pid 4242          # SIGTERM (Windows: terminate)
  pid-sniper kill --name node --tree  # parent+children, verified
  pid-sniper watch --name x --kill    # reaper loop
  pid-sniper --json scan              # machine-readable

Safety: every kill supports --dry-run and prints the exact target set before firing.
Nothing is killed by pattern without showing you the list first unless --yes is passed.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------- process model
class Proc:
    __slots__ = ("pid", "ppid", "name", "user", "cpu", "mem", "cmd", "ports")

    def __init__(self, pid, ppid, name, user="", cpu=0.0, mem=0.0, cmd=""):
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.user = user
        self.cpu = cpu
        self.mem = mem
        self.cmd = cmd
        self.ports = []

    def as_dict(self):
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "user": self.user,
            "cpu": round(self.cpu, 2),
            "mem": round(self.mem, 2),
            "cmd": self.cmd,
            "ports": self.ports,
        }


def _run(cmd):
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=20,
            encoding="utf-8", errors="replace",
        )
        return out.stdout if out.returncode == 0 else ""
    except Exception:
        return ""


# ------------------------------------------------------------------ collectors
def procs_windows():
    ps = (
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,ParentProcessId,Name,CommandLine,"
        "@{n='cpu';e={0}},@{n='mem';e={0}} | ConvertTo-Json -Compress"
    )
    raw = _run(["powershell", "-NoProfile", "-Command", ps])
    procs = {}
    if raw.strip():
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            for row in data:
                pid = int(row.get("ProcessId") or 0)
                if pid <= 0:
                    continue
                procs[pid] = Proc(
                    pid,
                    int(row.get("ParentProcessId") or 0),
                    row.get("Name") or "?",
                    cpu=float(row.get("cpu") or 0),
                    mem=float(row.get("mem") or 0),
                    cmd=(row.get("CommandLine") or "").strip(),
                )
        except Exception:
            pass
    if not procs:
        for line in _run(["tasklist", "/fo", "csv", "/nh"]).splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                try:
                    pid = int(parts[1])
                except ValueError:
                    continue
                procs[pid] = Proc(pid, 0, parts[0])
    for pid, ports in ports_windows().items():
        if pid in procs:
            procs[pid].ports = sorted(ports)
    return list(procs.values())


def ports_windows():
    """pid -> set(listening ports) from netstat -ano."""
    mapping = {}
    for line in _run(["netstat", "-ano", "-p", "TCP"]).splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        if parts[3].upper() != "LISTENING":
            continue
        local = parts[1]
        port = local.rsplit(":", 1)[-1]
        try:
            pid = int(parts[4])
            mapping.setdefault(pid, set()).add(int(port))
        except ValueError:
            continue
    return mapping


def procs_linux():
    procs = []
    try:
        ticks = os.sysconf("SC_CLK_TCK")
        pages = os.sysconf("SC_PAGE_SIZE")
        total = os.sysconf("SC_PHYS_PAGES") * pages
        meminfo = {}
        with open("/proc/meminfo") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                meminfo[key] = float(rest.strip().split()[0]) * 1024
        total = meminfo.get("MemTotal", total) or total
        uptime = float(open("/proc/uptime").read().split()[0])
    except Exception:
        ticks, total, uptime = 100.0, 1.0, 0.0

    uid_cache = {}
    try:
        import pwd
        uid_cache = {p.pw_uid: p.pw_name for p in pwd.getpwall()}
    except Exception:
        pass

    port_map = ports_linux()

    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        base = "/proc/" + entry
        try:
            with open(base + "/stat", "rb") as fh:
                stat = fh.read().decode("utf-8", "replace")
        except Exception:
            continue
        rparen = stat.rfind(")")
        name = stat[stat.find("(") + 1:rparen]
        fields = stat[rparen + 2:].split()
        try:
            ppid = int(fields[1])
            utime, stime = int(fields[11]), int(fields[12])
            starttime = int(fields[19])
            rss = int(fields[21])
        except (IndexError, ValueError):
            ppid, utime, stime, starttime, rss = 0, 0, 0, 0, 0
        elapsed = max(uptime - (starttime / ticks), 0.01)
        cpu = 100.0 * ((utime + stime) / ticks) / elapsed
        mem = 100.0 * (rss * pages) / total if total else 0.0
        cmd, user = "", ""
        try:
            cmd = open(base + "/cmdline", "rb").read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except Exception:
            pass
        try:
            uid = os.stat(base).st_uid
            user = uid_cache.get(uid, str(uid))
        except Exception:
            pass
        proc = Proc(pid, ppid, name, user, cpu, mem, cmd)
        proc.ports = sorted(port_map.get(pid, ()))
        procs.append(proc)
    return procs


def ports_linux():
    """pid -> set(listening ports) by matching socket inodes to /proc/*/fd."""
    inodes = {}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = open(path).read().splitlines()[1:]
        except Exception:
            continue
        for line in lines:
            cols = line.split()
            if len(cols) < 10 or cols[3] != "0A":  # 0A = LISTEN
                continue
            try:
                port = int(cols[1].rsplit(":", 1)[1], 16)
                inodes.setdefault(cols[9], set()).add(port)
            except (IndexError, ValueError):
                continue
    if not inodes:
        return {}
    by_pid = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        fd_dir = "/proc/" + entry + "/fd"
        try:
            fds = os.listdir(fd_dir)
        except Exception:
            continue
        for fd in fds:
            try:
                target = os.readlink(fd_dir + "/" + fd)
            except Exception:
                continue
            if target.startswith("socket:["):
                ino = target[8:-1]
                if ino in inodes:
                    by_pid.setdefault(int(entry), set()).update(inodes[ino])
    return by_pid


def collect():
    return procs_windows() if IS_WINDOWS else procs_linux()


# --------------------------------------------------------------------- filters
def match(proc, name=None, port=None, user=None, cmd=None):
    if name:
        needle = name.lower()
        if needle not in proc.name.lower() and needle not in proc.cmd.lower():
            return False
    if port is not None and port not in proc.ports:
        return False
    if user and user.lower() not in proc.user.lower():
        return False
    if cmd:
        try:
            if not re.search(cmd, proc.cmd, re.I):
                return False
        except re.error:
            return False
    return True


def descendants(procs, roots):
    """Every PID under the given roots, inclusive."""
    children = {}
    for p in procs:
        children.setdefault(p.ppid, []).append(p.pid)
    out, stack = set(), list(roots)
    while stack:
        pid = stack.pop()
        if pid in out:
            continue
        out.add(pid)
        stack.extend(children.get(pid, []))
    return out


# ---------------------------------------------------------------------- output
def render(rows, limit=None, quiet=False):
    if limit:
        rows = rows[:limit]
    if not rows:
        if not quiet:
            print("no targets")
        return
    if IS_WINDOWS and sys.stdout.isatty():
        pass
    head = f"{'PID':>7}  {'PPID':>7}  {'CPU%':>6}  {'MEM%':>6}  {'PORTS':<16} USER         NAME"
    if not quiet:
        print(head)
        print("-" * len(head))
    for p in rows:
        ports = ",".join(str(x) for x in p.ports[:4]) if p.ports else "-"
        print(f"{p.pid:>7}  {p.ppid:>7}  {p.cpu:>6.1f}  {p.mem:>6.1f}  {ports:<16} "
              f"{(p.user or '-')[:12]:<12} {p.name}")


def emit_json(rows, **extra):
    payload = {"count": len(rows), "processes": [p.as_dict() for p in rows]}
    payload.update(extra)
    print(json.dumps(payload, indent=2))


# ------------------------------------------------------------------------ kill
def kill_pid(pid, sig, force):
    if IS_WINDOWS:
        cmd = ["taskkill", "/PID", str(pid)]
        if force:
            cmd.append("/F")
        out = _run(cmd)
        return out.strip() or f"taskkill exit for {pid}"
    try:
        os.kill(pid, sig)
        return f"signal {sig} sent to {pid}"
    except ProcessLookupError:
        return f"{pid} already gone"
    except PermissionError:
        return f"permission denied for {pid}"


def do_kill(args):
    procs = collect()
    targets = []
    if args.pid:
        targets = [p for p in procs if p.pid in args.pid]
    else:
        targets = [p for p in procs if match(p, args.name, args.port, args.user, args.cmd)]
    if not targets:
        print("no match — nothing killed")
        return 1
    if args.tree:
        pids = descendants(procs, [p.pid for p in targets])
        targets = [p for p in procs if p.pid in pids]
    targets.sort(key=lambda p: p.pid)

    render(targets)
    if args.dry_run:
        print(f"\nDRY RUN — would kill {len(targets)} process(es). Nothing was touched.")
        return 0
    if not args.yes:
        try:
            ans = input(f"\nKill {len(targets)} process(es)? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans not in ("y", "yes"):
            print("aborted")
            return 1

    sig = signal.SIGTERM
    if args.signal and not IS_WINDOWS:
        sig = getattr(signal, args.signal.upper(), signal.SIGTERM)

    results = []
    for p in targets:
        results.append({"pid": p.pid, "name": p.name, "result": kill_pid(p.pid, sig, args.force)})
    if args.json:
        emit_json(targets, killed=results)
    else:
        for r in results:
            print(f"  {r['pid']:>7}  {r['name']:<24} {r['result']}")
    return 0


# ----------------------------------------------------------------------- verbs
def cmd_scan(args):
    procs = collect()
    rows = [p for p in procs if match(p, args.name, args.port, args.user, args.cmd)]
    rows.sort(key=lambda p: (p.cpu, p.mem), reverse=True)
    if args.json:
        emit_json(rows)
    else:
        render(rows, args.limit)
        print(f"\n{len(rows)} process(es) of {len(procs)} total")


def cmd_find(args):
    if not any((args.name, args.port, args.user, args.cmd)):
        print("give me something to hunt: --name, --port, --user, or --cmd", file=sys.stderr)
        return 2
    return cmd_scan(args)


def cmd_port(args):
    args.port = args.port
    procs = [p for p in collect() if args.port in p.ports]
    if args.json:
        emit_json(procs)
        return
    if not procs:
        print(f"port {args.port}: nobody is listening")
        return
    render(procs)


def cmd_watch(args):
    seen_kill = 0
    print(f"watching {args.name or args.port} every {args.interval}s — Ctrl+C to stop")
    try:
        while True:
            hits = [p for p in collect() if match(p, args.name, args.port, args.user, args.cmd)]
            stamp = time.strftime("%H:%M:%S")
            if hits:
                render(hits, quiet=True)
                if args.kill:
                    for p in hits:
                        kill_pid(p.pid, signal.SIGTERM, args.force)
                        seen_kill += 1
                        print(f"{stamp}  killed {p.pid} {p.name}")
                else:
                    print(f"{stamp}  {len(hits)} match(es)")
            elif not args.quiet:
                print(f"{stamp}  clear")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\nstopped — {seen_kill} killed")


def build_parser():
    ap = argparse.ArgumentParser(prog="pid-sniper", description="Hunt and kill processes by PID, name, port, or command line.")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    sub = ap.add_subparsers(dest="verb")

    def common(p):
        p.add_argument("--name", help="substring of process name or command line")
        p.add_argument("--port", type=int, help="listening port")
        p.add_argument("--user", help="owner filter")
        p.add_argument("--cmd", help="regex over command line")
        p.add_argument("--limit", type=int, default=40, help="rows to print (default 40)")

    p_scan = sub.add_parser("scan", help="list processes by CPU")
    common(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    p_find = sub.add_parser("find", help="locate processes")
    common(p_find)
    p_find.set_defaults(func=cmd_find)

    p_port = sub.add_parser("port", help="who owns a port")
    p_port.add_argument("port", type=int)
    p_port.set_defaults(func=cmd_port)

    p_kill = sub.add_parser("kill", help="terminate processes")
    common(p_kill)
    p_kill.add_argument("--pid", type=int, action="append", help="repeatable")
    p_kill.add_argument("--tree", action="store_true", help="include descendants")
    p_kill.add_argument("--force", action="store_true", help="SIGKILL / taskkill /F")
    p_kill.add_argument("--signal", default="SIGTERM")
    p_kill.add_argument("--dry-run", action="store_true")
    p_kill.add_argument("--yes", action="store_true", help="skip confirmation")
    p_kill.set_defaults(func=do_kill)

    p_watch = sub.add_parser("watch", help="poll and optionally reap")
    common(p_watch)
    p_watch.add_argument("--interval", type=float, default=2.0)
    p_watch.add_argument("--kill", action="store_true")
    p_watch.add_argument("--force", action="store_true")
    p_watch.add_argument("--quiet", action="store_true")
    p_watch.set_defaults(func=cmd_watch)
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "verb", None):
        ap.print_help()
        return 2
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
