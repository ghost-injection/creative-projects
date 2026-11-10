# CREATIVE PROJECTS

A shelf for tools that exist because the shipped alternative was slower, noisier, or
made a decision for you that you did not agree with. Each directory is self-contained:
its own README, its own license if it differs, no shared library between them.

## On the shelf

| Project | Platform | One line |
|---|---|---|
| [`reaper/`](reaper/) | Windows · Linux | Process hunter: find by name, port, or command line, then kill the exact set - with a dry run first. |

`PID Sniper` used to live here. It moved to
[AI-Research-OffSec](https://github.com/ghost-injection/AI-Research-OffSec) where the
rest of the Windows inspection tooling sits.

### reaper, in four commands

```bash
reaper port 8080                        # which PID actually owns that socket
reaper find --name node --dry-run       # who matches, before anything dies
reaper kill --pid 4242 --tree           # process plus descendants, printed first
reaper watch --name miner --kill        # loop until it stops coming back
```

Windows reads `Win32_Process` through `Get-CimInstance` (with `tasklist` as fallback)
and `netstat -ano` for socket ownership; Linux reads `/proc/<pid>/stat`, `cmdline`,
and file ownership. Both paths are in one 800-line file with no dependencies.

## How a project earns a directory here

1. It solves a problem you hit at 2 a.m., not a problem you imagined at a standup.
2. It runs from a single file or a single build step. Copy it to a host mid-incident
   and it works.
3. Destructive verbs print their target set and support `--dry-run`. Every time.
4. Output shown in its README came from a real run, not a mock-up.

## License

MIT per project. The `LICENSE` at this level covers the shelf; subdirectories may
carry their own.
