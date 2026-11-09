# REAPER

**Find the exact process. Then end it.**

Single-file process hunter for Windows and Linux. No dependencies, no agent, no service to install. One Python file you can drop on a box mid-incident and run.

```
  reaper scan                      # process table, hottest first
  reaper find --name chrome        # name or command-line substring
  reaper find --port 8080          # who owns the socket
  reaper port 8080                 # short form
  reaper kill --pid 4242 --dry-run # see the target set, touch nothing
  reaper kill --name node --tree   # parent + every descendant
  reaper watch --name miner --kill # reaper loop, reaps on sight
  reaper --json scan               # machine-readable
```

## Why it exists

Task Manager lies by omission: it hides command lines, skips elevation-owned rows, and gives you no way to answer *"which PID actually owns port 8080?"* without three tools and a guess.

Reaper answers in one call, and every kill is shown before it fires.

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
- **Self-exclusion:** the running process and every one of its ancestors are never valid targets. A needle like `--name worker` can't match the shell or harness that invoked it.
- Windows uses `taskkill` (graceful) and adds `/F` only with `--force`.
- Linux sends `SIGTERM` by default; `--signal SIGKILL` when you mean it.
- Processes that vanish between collect and signal are reported as `already gone`, not as errors.

## Examples

```
$ reaper port 18081
    PID     PPID  CPU%    MEM%  PORTS            USER         NAME
  41022     1093   312.4    8.7  18081            hermes       llama-server

$ reaper kill --name llama-server --dry-run
   41022     1093   312.4    8.7  18081            hermes       llama-server
DRY RUN — would kill 1 process(es). Nothing was touched.

$ reaper scan --limit 5
```

## Install

```bash
git clone https://github.com/ghost-injection/creative-projects
cp creative-projects/reaper/reaper.py ~/.local/bin/reaper
chmod +x ~/.local/bin/reaper
```

Windows: drop it anywhere and run `python reaper.py scan`. Optionally `doskey reap=python C:\tools\reaper.py $*`.

## Exit codes

- `0` success
- `1` no targets matched / aborted
- `2` bad usage

## License

MIT. Do what you want; don't blame the tool.
