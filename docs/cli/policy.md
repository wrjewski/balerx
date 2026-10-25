# Guard policy reference

The policy file is YAML. `balerx guard` and `balerx hook` load `~/.balerx/policy.yaml`. If that file is missing, the built-in default policy is used.

`balerx setup` prints a Balerx Gate banner, then writes that file from a checklist. `balerx policy init` does the same. `balerx policy edit` does not print the banner. The command stays offline. `balerx setup --yes` writes the balanced preset. `--preset strict` denies the shell, package, and MCP rows that balanced asks about. `--preset minimal` enables only the secret-file rules. When `~/.balerx/policy.yaml` already exists, `--yes` and `--preset` leave it in place and exit with an error. Pass `--replace` to copy the current file to `policy.yaml.bak` and write a new one. `balerx policy show` prints the file, or the built-in policy when the file is missing. `balerx policy edit` opens the checklist pre-filled from the file.

The checklist offers rules the hook engine can match:

| Row | Balanced | Strict | Minimal |
| --- | --- | --- | --- |
| Block reading secret files (`.env`, SSH keys, PEM, and cloud and CLI credential files) | deny | deny | deny |
| `rm -rf`, `git push --force`, and `drop database` or `drop table` | ask | deny | off |
| `curl` or `wget` piped to a shell | ask | deny | off |
| Package install commands (`npm`, `pnpm`, `yarn`, `bun`, `pip`, `uv`, `cargo`, `go get`) | ask | deny | off |
| Every MCP server call | ask | deny | off |

These are not offered. The hook engine cannot enforce them:

- Block writing outside the project folder. A hook does not compare a write with the project directory.
- Block unknown or unpinned MCP servers. A hook sees the server name, not a package pin.
- A switch for the activity log. Each hook call is appended to the log while hooks are installed.

`fail_open` stays true and `timeout_ms` stays 50.

`balerx policy pull` can replace the local file. It does not run unless you pass `--api-url` and set `BALERX_API_KEY`, or pass `--api-key -` to read from stdin. Invalid YAML is rejected and the previous file is left in place. `--output` chooses a path other than `~/.balerx/policy.yaml`.

No API host is compiled in. Use the API URL shown in your Balerx Gate dashboard's onboarding. The client calls `GET {api-url}/v1/ingest/policy` with `Authorization: Bearer <api-key>`.

## Document

```yaml
version: "1.0.0"
global:
  fail_open: true
  timeout_ms: 50
rules:
  - id: deny_ssh_keys
    description: Deny reading SSH private keys
    enabled: true
    action: deny
    conditions:
      - type: path_pattern
        pattern: "**/.ssh/id_*"
```

| Field | Meaning |
| --- | --- |
| `version` | Document version. Default `1.0.0`. |
| `global.fail_open` | When the hook cannot decide, true allows the action and false denies it. That covers invalid JSON and a run that exceeds `timeout_ms`. Default `true`. |
| `global.timeout_ms` | Hook time budget in milliseconds. The hook compares elapsed time with this value. Default `50`. |
| `rules[].id` | Stable rule name. |
| `rules[].enabled` | Skip the rule when false. |
| `rules[].action` | `allow`, `deny`, or `ask`. |
| `rules[].conditions` | All conditions are evaluated with the rule. `type` selects the condition. |

### Condition types

| `type` | Fields | Match |
| --- | --- | --- |
| `path_pattern` | `pattern` | Path glob, such as `**/.env*` or `**/*.pem`. `.env` and `.env.local` both match `**/.env*`. |
| `command_pattern` | `pattern` | Regular expression against the shell command. |
| `server_allowlist` | `servers` | MCP server name is in the list. |
| `server_denylist` | `servers` | MCP server name is in the list. `*` matches any server. |
| `resource_type` | `types` | Resource type is in the list. |

## Default rules

The built-in policy enables these rules:

| Id | Action | Condition |
| --- | --- | --- |
| `deny_ssh_keys` | deny | `path_pattern` `**/.ssh/id_*` |
| `deny_env_files` | deny | `path_pattern` `**/.env*` |
| `deny_pem_files` | deny | `path_pattern` `**/*.pem` |
| `deny_curl_pipe_sh` | deny | `command_pattern` `curl.*\|.*sh` |
| `ask_force_push` | ask | `command_pattern` `git\s+push.*--force` |

`deny_unapproved_mcp` is present and **disabled**. It would deny every MCP server (`server_denylist` `*`) if you enable it.
