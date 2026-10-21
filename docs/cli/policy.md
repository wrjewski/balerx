# Guard policy reference

The policy file is YAML. `balerx guard` and `balerx hook` load `~/.balerx/policy.yaml`. If that file is missing, the built-in default policy is used.

`balerx policy pull` can replace the local file. It does not run unless you pass `--api-url` and `--api-key`, or set `BALERX_API_URL` and `BALERX_API_KEY`. Invalid YAML is rejected and the previous file is left in place. `--output` chooses a path other than `~/.balerx/policy.yaml`.

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
| `global.fail_open` | When true, a hook error allows the action. Default `true`. |
| `global.timeout_ms` | Hook time budget. Default `50`. |
| `rules[].id` | Stable rule name. |
| `rules[].enabled` | Skip the rule when false. |
| `rules[].action` | `allow`, `deny`, or `ask`. |
| `rules[].conditions` | All conditions are evaluated with the rule. `type` selects the condition. |

### Condition types

| `type` | Fields | Match |
| --- | --- | --- |
| `path_pattern` | `pattern` | Path glob, such as `**/.env` or `**/*.pem`. |
| `command_pattern` | `pattern` | Regular expression against the shell command. |
| `server_allowlist` | `servers` | MCP server name is in the list. |
| `server_denylist` | `servers` | MCP server name is in the list. `*` matches any server. |
| `resource_type` | `types` | Resource type is in the list. |

## Default rules

The built-in policy enables these rules:

| Id | Action | Condition |
| --- | --- | --- |
| `deny_ssh_keys` | deny | `path_pattern` `**/.ssh/id_*` |
| `deny_env_files` | deny | `path_pattern` `**/.env` |
| `deny_pem_files` | deny | `path_pattern` `**/*.pem` |
| `deny_curl_pipe_sh` | deny | `command_pattern` `curl.*\|.*sh` |
| `ask_force_push` | ask | `command_pattern` `git\s+push.*--force` |

`deny_unapproved_mcp` is present and **disabled**. It would deny every MCP server (`server_denylist` `*`) if you enable it.
