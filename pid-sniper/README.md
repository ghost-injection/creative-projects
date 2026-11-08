# PID SNIPER

**Find the exact process. Then end it.**

Single-file process hunter for Windows and Linux. No dependencies, no agent, no service to install. One Python file you can drop on a box mid-incident and run.

```
  pid-sniper scan                      # process table, hottest first
  pid-sniper find --name chrome        # name or command-line substring
  pid-sniper find --port 8080          # who owns the socket
  pid-sniper port 8080                 # short form
  pid-sniper kill --pid 4242 --dry-run # see the target set, touch nothing
  pid-sniper kill --name node --tree   # parent + every descendant
  pid-sniper watch --name miner --kill # reaper loop, reaps on sight
  pid-sniper --json scan               # machine-readable
```

## Why it exists

Task Manager lies by omission: it hides command lines, skips elevation-owned rows, and gives you no way to answer *"which PID actually owns port 8080?"* without three tools and a guess.

PID Sniper answers in one call and every kill is shown before it fires.

## What it actually inspects

| Platform | Source | Fields |
|----------|--------|--------|
| Windows | `Get-CimInstance Win32_Process` (fallback `tasklist`) | PID, PPID, name, full command line |
| Windows | `netstat -ano -p TCP` | listening ports → owning PID |
| Linux | `/proc/<pid>/stat`, `cmdline`, ownership | PID, PPID, name, cmdline, user |
| Linux | `/proc/net/tcp{,6}` socket inodes ↔ `/proc/*/fd` | listening ports → owning PID |
| Both | derived | CPU% and MEM% (Linux computed from utime/stime and RSS) |

No `/proc` parsing shortcuts, no `ps` scraping on Linux, no WMI dependency on Windows beyond what ships in the box.

## Safety model

- `--dry-run` prints the full target set and exits. Nothing is signalled.
- Without `--yes`, kills prompt for confirmation.
- `--tree` expands to descendants via PPID walk, so orphaned children don't survive their parent.
- Windows uses `taskkill` (graceful) and adds `/F` only with `--force`.
- Linux sends `SIGTERM` by default; `--signal SIGKILL` when you mean it.
- Processes that vanish between collect and signal are reported as `already gone`, not as errors.

## Examples

```
$ pid-sniper port 18081
    PID     PPID  CPU%    MEM%  PORTS            USER         NAME
  41022     1093   312.4    8.7  18081            hermes       llama-server

$ pid-sniper kill --name llama-server --dry-run
   41022     1093   312.4    8.7  18081            hermes       llama-server
DRY RUN — would kill 1 process(es). Nothing was touched.

$ pid-sniper scan --limit 5
```

## Install

```bash
git clone https://github.com/ghost-injection/creative-projects
cp creative-projects/pid-sniper/pid_sniper.py ~/.local/bin/pid-sniper
chmod +x ~/.local/bin/pid-sniper
```

Windows: drop it anywhere and run `python pid_sniper.py scan`. Optionally `doskey sniper=python C:\tools\pid_sniper.py $*`.

## Exit codes

- `0` success
- `1` no targets matched / aborted
- `2` bad usage

## License

MIT. Do what you want; don't blame the tool.
