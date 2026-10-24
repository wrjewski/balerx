# `balerx guard`

Guard installs a local hook that evaluates `~/.balerx/policy.yaml` before Claude Code or Cursor runs a tool. The decision is also appended to the on-machine activity log.

`balerx setup` (the same command as `balerx policy init`) writes `~/.balerx/policy.yaml`. `balerx setup --yes` writes the balanced preset. `--preset strict|balanced|minimal` writes that preset. A missing terminal writes the balanced preset and does not prompt. `--yes` and `--preset` do not replace an existing file. Pass `--replace` to copy it to `policy.yaml.bak` and write a new one. A checklist confirms before it replaces an existing file. `balerx policy show` prints the active policy. `balerx policy edit` opens the checklist again. None of these commands use the network. The interactive checklist prints the rules that are not offered. `--yes`, `--preset`, and a missing terminal do not.

```bash
balerx setup
balerx guard install claude-code
balerx guard install cursor
balerx guard uninstall claude-code
balerx guard uninstall cursor
balerx guard status
```

Guard hooks exist for Claude Code and Cursor. A scan of another agent, such as VS Code with GitHub Copilot or Codex CLI, still reads that agent's config. The agents section then includes a Guard coverage line, for example `Guard hooks are not available for VS Code with GitHub Copilot yet, so its tool calls aren't intercepted. The scan still checks its config.` That line is separate from findings. The finding count and the risk score stay the same, and `--fail-on` ignores it. `HOOK-GAP-002` stays planned. Current scans do not raise it.

Claude Code entries are merged into `~/.claude/settings.json` as `{matcher, hooks:[{type, command}]}` groups. An existing project `.claude/settings.json` is updated the same way when it is a different file. The same path is written once, including when Windows reports it with a `\\?\` prefix. Cursor entries are merged into `~/.cursor/hooks.json` under `hooks`, with `"version": 1` when the file has no version. Uninstall removes only commands that run the `balerx` binary, or `balerx.exe`, with a `hook` argument. It does not restore an old copy of the file. Empty hook lists left behind are removed. Running install again does not add a second Balerx hook. After install, a missing policy file prints `No policy set yet. Run: balerx setup`.

`balerx uninstall` removes Balerx hook commands from both Claude Code and Cursor, then asks before it writes. A command matches when it contains `balerx` and `hook` and it runs the `balerx` binary, or `balerx.exe`, with a separate `hook` argument. `my-balerx-webhook.sh` stays. Empty hook lists left behind are removed. `--yes` skips the question. A pipe without `--yes` changes nothing. Without `--purge`, policy and logs stay. `--purge` deletes known policy files, `canaries.json`, and `logs/activity.jsonl`. Unknown files stay. A custom `BALERX_DATA_DIR` is not removed. Purge exits nonzero when the home directory or the data directory is not an absolute path. `balerx guard uninstall <agent>` still removes one agent and does not ask.

`balerx guard status` prints whether those files contain a Balerx hook, the policy `fail_open` and `timeout_ms`, and the activity log path. On a fresh install it exits 0 and prints `Not installed — run: balerx guard install claude-code` and `Not installed — run: balerx guard install cursor`. `--strict` and `--check` exit 1 when no hook is installed. That is the exit code for a CI script. A machine that already has a Claude Code or Cursor hook exits 0 either way.

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
