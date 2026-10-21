# Agent Hooks Integration

## Overview

Balerx Guard integrates with AI coding agents through their native hook systems to provide real-time policy enforcement. This document describes the hook formats and integration details.

## Claude Code Hooks

**Reference:** https://code.claude.com/docs/en/hooks

Claude Code supports hook configuration in `~/.claude.json`:

```json
{
  "hooks": {
    "PreToolUse": {
      "command": "/path/to/balerx",
      "args": ["hook", "--event-type", "pre_tool_use"]
    },
    "PostToolUse": {
      "command": "/path/to/balerx",
      "args": ["hook", "--event-type", "post_tool_use"]
    }
  }
}
```

### Input Format (stdin JSON)

```json
{
  "agent": "claude-code",
  "tool": "read_file",
  "args": {
    "path": "/path/to/file"
  },
  "server": "filesystem"
}
```

### Output Format (stdout JSON)

**PreToolUse** must return:
```json
{
  "allow": true,
  "reason": "Optional explanation"
}
```

**PostToolUse** is logging-only (no decision required).

### Performance Requirements

- Target: <50ms p95
- Claude Code may timeout hooks that take too long
- Hooks that crash or hang will fail open (by default)

## Cursor Hooks

**Reference:** https://cursor.com/docs/hooks

Cursor supports hook configuration in `~/.cursor/hooks.json`:

```json
{
  "beforeShellExecution": {
    "command": "/path/to/balerx",
    "args": ["hook", "--event-type", "before_shell_execution"]
  },
  "beforeMCPExecution": {
    "command": "/path/to/balerx",
    "args": ["hook", "--event-type", "before_mcp_execution"]
  }
}
```

### Input Formats

**beforeShellExecution:**
```json
{
  "agent": "cursor",
  "command": "git push --force",
  "cwd": "/path/to/repo"
}
```

**beforeMCPExecution:**
```json
{
  "agent": "cursor",
  "server": "filesystem",
  "tool": "read_file",
  "args": {
    "path": "/path/to/file"
  }
}
```

### Output Format

Both hooks must return:
```json
{
  "allow": true,
  "reason": "Optional explanation"
}
```

## Policy Evaluation

The `balerx hook` handler:

1. Receives hook input on stdin
2. Loads policy from `~/.balerx/policy.yaml` (or uses default)
3. Checks if the resource is a canary credential
4. Evaluates policy rules against the event
5. Logs the decision to activity log
6. Returns allow/deny decision on stdout

## Verified Behavior (from Official Documentation)

### Timeout Behavior

**Claude Code** (as of v2.1.295+):
- Default timeouts: 600s for `command` hooks, lowered to 30s for certain events, 10s for `MessageDisplay`
- A timed-out `PreToolUse` hook does **not block** the tool call by default — the call continues through normal permission flow
- To block on timeout, set `"onFailure": "block"` in hook configuration
- Source: https://code.claude.com/docs/en/hooks#timeouts

**Cursor** (as of v0.x):
- `timeout` option sets execution timeout in seconds (platform default if not specified)
- Crash, timeout, or non-zero exit (other than 2) = **fail open by default** (action proceeds)
- Set `"failClosed": true` on the hook to block on crash/timeout
- Invalid JSON or schema mismatch always blocks permission hooks
- Source: https://cursor.com/docs/hooks#per-script-configuration-options

### Crash/Error Handling

**Claude Code:**
- Hooks that can't start (missing script, wrong path) = non-blocking error by default
- Set `"onFailure": "block"` to block when the hook fails
- `PostToolUse` hooks can't undo actions (tool already executed)
- Source: https://code.claude.com/docs/en/hooks#block-the-action-when-a-hook-fails

**Cursor:**
- Exit code `0` = success, use JSON output
- Exit code `2` = block the action (equivalent to `permission: "deny"`)
- Other non-zero exits = fail open unless `failClosed: true`
- Source: https://cursor.com/docs/hooks#command-based-hooks

### Argument Modification

**Claude Code:**
- `PreToolUse` hooks can return `updatedInput` to rewrite a tool's arguments
- When multiple hooks return `updatedInput`, the last to finish wins (non-deterministic order)
- Source: https://code.claude.com/docs/en/hooks-guide#limitations

**Cursor:**
- Current documentation does not specify argument modification capability for `beforeShellExecution`/`beforeMCPExecution`
- Hooks return permission decisions only (`allow`/`deny`/`ask`)
- Balerx Guard does **not** attempt argument modification

### Recommendations

1. **Keep hooks fast** - Target <20ms actual, <50ms p95 (both systems have generous defaults but user experience suffers)
2. **Use `failClosed`/`onFailure: "block"` for security** - Default fail-open is dangerous for policy enforcement
3. **Log everything** - Even when policy allows, log for audit trail
4. **Test crash scenarios** - Ensure your hook binary is on PATH and executable
5. **Handle invalid JSON** - Both systems block on schema mismatch for permission hooks

## Testing

### Manual Hook Testing

```bash
# Simulate a PreToolUse event
echo '{"agent":"claude-code","tool":"read_file","args":{"path":"~/.ssh/id_rsa"},"server":"filesystem"}' \
  | balerx hook --event-type pre_tool_use

# Expected output:
# {"allow":false,"reason":"Access to SSH private keys denied"}
```

### Integration Testing

1. Install hooks: `balerx guard install claude-code`
2. Open Claude Code
3. Ask it to read `~/.ssh/id_rsa`
4. Verify: Access is blocked
5. Check log: `balerx log view`

## Future Enhancements

- **Hooks for other agents**: VS Code Copilot, Windsurf, Codex (when their hook APIs are public)
- **Remote policy**: Fetch policy from team server instead of local file
- **Policy DSL**: More expressive conditions (e.g., "allow if file in git repo")
- **Adaptive throttling**: Slow down agent if it's hammering hooks
- **Hook marketplace**: Community-contributed policies and detections

## References

- Claude Code hooks: https://code.claude.com/docs/en/hooks (version 0.x)
- Cursor hooks: https://cursor.com/docs/hooks (version 0.x)
- Balerx Guard implementation: `balerx-sensor/crates/balerx-core/src/guard.rs`
- Policy engine: `balerx-sensor/crates/balerx-core/src/policy.rs`
