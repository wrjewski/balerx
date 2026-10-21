# `balerx guard`

Guard installs a local hook that evaluates `~/.balerx/policy.yaml` before Claude Code or Cursor runs a tool. The decision is also appended to the on-machine activity log.

```bash
balerx guard install claude-code
balerx guard install cursor
balerx guard uninstall claude-code
balerx guard uninstall cursor
```

Hook payload shapes, timeouts, and fail-open behavior are in [HOOKS.md](../HOOKS.md). The policy fields are in [policy.md](policy.md).

## Activity log

```bash
balerx log view
balerx log view --limit 100
balerx log view --agent cursor
balerx log view --event-type tool_call
```

The log file is `activity.jsonl` under the OS local data directory: `~/.local/share/balerx/logs/` on Linux, `~/Library/Application Support/balerx/logs/` on macOS, and `%LOCALAPPDATA%\balerx\logs\` on Windows. `balerx guard install` prints the path on this machine. Tool arguments are not written. The file stays on the machine unless you pass it to `balerx upload`, which also drops tool arguments.

## Canaries

`balerx canary plant` writes a file that looks like a credential and is labeled as fake in the file itself. Guard alerts when a hooked agent reads it. The planted material is not a working credential. See `balerx-sensor/tests/fixtures/README.md` for the related test values.

```bash
balerx canary plant env
balerx canary plant aws --location ~/.balerx/canaries/credentials
balerx canary list
balerx canary check ~/.balerx/canaries/.env
balerx canary remove <canary-id>
```

## Hook process

`balerx hook --event-type <name>` reads one JSON event on stdin and writes an allow or deny decision on stdout. Agents invoke this. You can also pipe a fixture in by hand, as [HOOKS.md](../HOOKS.md) shows.
