# `balerx guard`

Guard installs a local hook that evaluates `~/.balerx/policy.yaml` before Claude Code or Cursor runs a tool. The decision is also appended to the on-machine activity log.

```bash
balerx guard install claude-code
balerx guard install cursor
balerx guard uninstall claude-code
balerx guard uninstall cursor
balerx guard status
```

Claude Code entries are merged into `~/.claude/settings.json` as `{matcher, hooks:[{type, command}]}` groups. An existing project `.claude/settings.json` is updated the same way. Cursor entries are merged into `~/.cursor/hooks.json` under `hooks`, with `"version": 1` when the file has no version. Uninstall removes only commands that contain `balerx` and `hook`. It does not restore an old copy of the file.

`balerx guard status` prints whether those files contain a Balerx hook, the policy `fail_open` and `timeout_ms`, and the activity log path. It exits 1 when nothing is installed.

Hook payload shapes and the native allow, deny, and ask decisions are in [HOOKS.md](../HOOKS.md). The policy fields are in [policy.md](policy.md). `timeout_ms` is enforced by the hook. `fail_open` chooses allow or deny when the budget is exceeded or the input is not JSON.

## Activity log

```bash
balerx log view
balerx log view --limit 100
balerx log view --agent cursor
balerx log view --event-type tool_call
```

The log file is `activity.jsonl` under the OS local data directory: `~/.local/share/balerx/logs/` on Linux, `~/Library/Application Support/balerx/logs/` on macOS, and `%LOCALAPPDATA%\balerx\logs\` on Windows. `balerx guard install` prints the path on this machine. Tool arguments are not written. The file stays on the machine unless you pass it to `balerx upload`, which also drops tool arguments.

## Canaries

`balerx canary plant` writes a file that looks like a normal credential. The file contents do not contain a canary banner. The command itself prints a warning that the material is fake. Guard denies the read when a hooked agent opens that path. The planted material is not a working credential.

```bash
balerx canary plant env
balerx canary plant aws --location ~/.balerx/canaries/credentials
balerx canary list
balerx canary check ~/.balerx/canaries/.env
balerx canary remove <canary-id>
```

`balerx canary check` exits 0 when the path is not a planted canary, 2 when it is, and 1 when the file is missing.

## Hook process

`balerx hook --event-type <name>` reads one JSON event on stdin and writes an allow or deny decision on stdout. Agents invoke this. You can also pipe a fixture in by hand, as [HOOKS.md](../HOOKS.md) shows.
