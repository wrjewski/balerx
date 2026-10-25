# Agent Hooks Integration

## Overview

Balerx Guard integrates with AI coding agents through their native hook systems. `balerx guard install` merges entries into the agent's settings file. It does not replace other hooks. `balerx guard uninstall` removes only commands that run the `balerx` binary, or `balerx.exe`, with a `hook` argument. It does not restore a backup.

`balerx uninstall` removes those commands from both agents and asks first. A command matches when it contains `balerx` and `hook` and it runs the `balerx` binary, or `balerx.exe`, with a separate `hook` argument. `my-balerx-webhook.sh` stays. Empty hook lists left behind are removed. `balerx guard uninstall <agent>` still removes one agent and does not ask.

The recorded hook command quotes the binary path. POSIX shells use single quotes (`'\''` for an embedded quote). PowerShell always uses `& "path"`, including a plain drive-letter path, and escapes `$` and backtick. `guard status` and `doctor` unescape those PowerShell escapes only on the `& "..."` form. A POSIX hook command whose binary directory contains a backtick is checked as stored.

Check the result with `balerx guard status`. The command prints the Claude and Cursor files, whether a Balerx hook is present, the policy `fail_open` and `timeout_ms` values, and the activity log path. A fresh install exits 0 and prints `Not installed — run: balerx guard install claude-code` and `Not installed — run: balerx guard install cursor`. `--strict` and `--check` exit 1 when no Balerx hook is installed. If a hook is installed but the binary is missing or not executable, `guard status` and `doctor` exit non-zero and say so.

## Claude Code Hooks

**Reference:** https://docs.claude.com/en/docs/claude-code/hooks

`balerx guard install claude-code` merges into `~/.claude/settings.json`. If the current directory already has `.claude/settings.json`, the same entries are merged there. The file is not created only to hold a project hook.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/balerx hook --event-type pre_tool_use"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/balerx hook --event-type post_tool_use"
          }
        ]
      }
    ]
  }
}
```

`command` is one string. Other matchers in the same array are left in place.

### Input

Claude Code sends the tool call on stdin. Guard reads `tool_name` and `tool_input.command`, `tool_input.file_path`, and other path fields.

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "cat .env"
  }
}
```

### Output

PreToolUse writes `hookSpecificOutput` and uses the exit code Claude Code expects:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Access to .env files denied"
  }
}
```

`permissionDecision` is `allow`, `deny`, or `ask`. Deny exits 2. Allow and ask exit 0. PostToolUse records the call and exits 0. It does not block a tool that already ran.

## Cursor Hooks

**Reference:** https://cursor.com/docs/hooks

`balerx guard install cursor` merges into `~/.cursor/hooks.json`. Existing hooks stay. `"version"` stays at 1 when it is missing, and an existing version is kept. Each event is an array under `hooks`.

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "/path/to/balerx hook --event-type before_shell_execution"
      }
    ],
    "beforeMCPExecution": [
      {
        "command": "/path/to/balerx hook --event-type before_mcp_execution"
      }
    ],
    "beforeReadFile": [
      {
        "command": "/path/to/balerx hook --event-type before_read_file"
      }
    ]
  }
}
```

### Input

Guard reads `command`, `cwd`, `file_path`, `mcp_server_name`, and `tool_input`. `tool_input` may be an object or a JSON string.

```json
{
  "command": "cat ~/.ssh/id_ed25519",
  "cwd": "/tmp"
}
```

### Output

Cursor always receives exit code 0 and a permission object:

```json
{
  "permission": "deny",
  "user_message": "Access to SSH private keys denied",
  "agent_message": "Access to SSH private keys denied"
}
```

`permission` is `allow`, `deny`, or `ask`.

## Policy evaluation

`balerx hook`:

1. Reads one JSON event on stdin. A body larger than 1 MB returns `ask` and is not parsed.
2. Loads `~/.balerx/policy.yaml`, or the file in `BALERX_POLICY`. A missing file uses the built-in policy. A present empty or unreadable file fails closed: the hook returns `ask` and writes a warning to stderr. It does not fall back to the built-in fail-open default.
3. Checks whether the resource is a planted canary. A canary is denied.
4. Matches paths, including `.env*` files, `.ssh/id_*`, and `.pem`, plus shell tokens such as `cat .env`.
5. Appends the decision to the activity log. The `agent` field is `claude-code` or `cursor`. The `resource` field is the path or command target, not the whole payload. When `fail_open` allows after a timeout or invalid JSON, that allow is also written to the activity log and stderr.
6. Writes the agent's native decision on stdout.

`global.timeout_ms` (default 50) is a wall-clock budget that starts when the hook process starts and is checked after stdin closes. A stdin that never closes can still hang, as in 0.1.6. When the remaining budget is already gone, or evaluation exceeds what is left, `global.fail_open` chooses the decision: true allows the action, false denies it. The same choice applies when stdin is not valid JSON. Omitting `global` or writing `global: {}` uses `fail_open: true` and `timeout_ms: 50`. An empty, comment-only, or unreadable policy file is not covered by `fail_open`; that case is always `ask`. The activity log is `activity.jsonl` under the OS data directory (`~/.local/share/balerx/logs/` on Linux). `BALERX_DATA_DIR` overrides that directory.

## Host timeout behavior

The numbers below are the agent's own limits, separate from `timeout_ms`.

**Claude Code:**

- A timed-out `PreToolUse` hook does not block the tool call unless the hook config sets `"onFailure": "block"`.
- Source: https://code.claude.com/docs/en/hooks

**Cursor:**

- A crash, timeout, or non-zero exit other than 2 fails open unless the hook sets `"failClosed": true`.
- Source: https://cursor.com/docs/hooks

Guard does not rewrite tool arguments.

## Testing

```bash
printf '%s' '{"tool_name":"Read","tool_input":{"file_path":"/home/user/.ssh/id_rsa"}}' \
  | balerx hook --event-type pre_tool_use
```

A default policy denies that read. Claude output contains `"permissionDecision":"deny"` and the process exits 2.

```bash
printf '%s' '{"command":"git push --force origin main","cwd":"/tmp"}' \
  | balerx hook --event-type before_shell_execution
```

The default policy asks. Cursor output contains `"permission":"ask"` and the process exits 0.

After `balerx guard install`, reopen the agent and confirm `balerx guard status` and `balerx log view`.

## References

- Claude Code hooks: https://docs.claude.com/en/docs/claude-code/hooks
- Cursor hooks: https://cursor.com/docs/hooks
- Implementation: `balerx-sensor/crates/balerx-core/src/guard.rs` and `hook_input.rs`
