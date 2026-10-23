# Balerx Gate scanner

This file is the `balerx-sensor` crate README. The same user guide is the root README of https://github.com/wrjewski/balerx.

Balerx Gate's scanner is a local, metadata-only check for AI coding agents. `balerx` looks on your machine for known agents and for risky settings in their config: unpinned MCP packages, plain HTTP endpoints, broad filesystem access, and secrets sitting in those files. It is Apache-2.0. An optional hosted dashboard can receive a scan or a Guard activity log only after you pass an API URL and an ingest key from that dashboard.

The scanner does not start MCP servers. It does not read your prompts. A normal scan never leaves the machine.

## Privacy

`balerx scan` reads agent config files it can open, plus the current directory when it looks for suspicious instruction text. Findings store a redacted secret (a short prefix and `REDACTED`) rather than the secret itself.

Prompt text is not collected. Tool-argument capture is off. The activity log is metadata only: time, agent, action, resource path, and the allow or deny decision. `balerx upload` also deletes `tool_args` from each log line before the request. This version has no flag that turns prompt or tool-argument capture on.

Nothing is uploaded unless you run `balerx upload` or `balerx policy pull` with an API URL and an API key.

## Install

Supported platforms are Windows, macOS, and Linux. Windows is the primary agent platform; macOS and Linux use the same commands. Prebuilt binaries are GitHub Releases. The current scanner version is 0.1.3.

### Build from source

Install [rustup](https://rustup.rs/). The `balerx-sensor/rust-toolchain.toml` file selects nightly, which `rustup` installs when you build inside that directory.

From any directory:

```bash
cargo install --git https://github.com/wrjewski/balerx.git --path balerx-sensor/crates/balerx-cli
```

If you already have the repository, build in this directory (`balerx-sensor`):

```bash
cargo build --locked --release
./target/release/balerx --version
```

On Windows, from `balerx-sensor`:

```powershell
cargo build --locked --release
.\target\release\balerx.exe --version
```

`balerx 0.1.3` is the expected first line. Add `target/release` to your `PATH`, or copy the binary to a directory already on `PATH`.

### Prebuilt binary

`BALERX_REPO` defaults to `wrjewski/balerx`. The scripts download `https://github.com/wrjewski/balerx/releases/latest/download/` and check `SHA256SUMS` before installing. If that checksum is missing, they print the `cargo install` command above and exit.

Linux or macOS, into `$HOME/.local/bin`:

```bash
curl -fsSL "https://raw.githubusercontent.com/wrjewski/balerx/main/install.sh" -o install.sh
sh install.sh
balerx --version
```

Windows, into `%LOCALAPPDATA%\balerx`:

```powershell
Invoke-WebRequest "https://raw.githubusercontent.com/wrjewski/balerx/main/install.ps1" -OutFile install.ps1
powershell -File .\install.ps1
balerx --version
```

The archive names are `balerx-x86_64-unknown-linux-gnu.tar.gz`, `balerx-aarch64-unknown-linux-gnu.tar.gz`, `balerx-x86_64-apple-darwin.tar.gz`, `balerx-aarch64-apple-darwin.tar.gz`, `balerx-x86_64-pc-windows-msvc.zip`, and `balerx-aarch64-pc-windows-msvc.zip`. The Windows executable is not Authenticode-signed. See Troubleshooting for SmartScreen.

## Quick start

Run the scan from a project directory, or from your home directory if you want the scan to see user-level agent configs.

```bash
balerx scan
```

This report is from a real run. The directory contained a Cursor `.cursor/mcp.json` with an unpinned `npx` package and an `http://` MCP URL. The machine name is replaced with `workstation`. Default info logs on stderr are omitted here; set `RUST_LOG=error` to hide them. The process exited 1 because of the high finding.

```text
╔═══════════════════════════════════════════════════════════════════════╗
║             Balerx Gate Security Scan Results                        ║
╚═══════════════════════════════════════════════════════════════════════╝

Device: workstation
Platform: linux Ubuntu 24.04.5 LTS
Scanned: 2026-10-21 02:02:20 UTC

╭─────────────────────────────────────────────────────────────────────╮
│ RISK SCORE: 14/100 [✓ LOW]
├─────────────────────────────────────────────────────────────────────┤
│ Agents Found:    1                                               │
│ Total Findings:  2                                               │
│ Critical:        0                                               │
│ High:            1                                               │
│ Medium:          1                                               │
│ Low:             0                                               │
╰─────────────────────────────────────────────────────────────────────╯

DISCOVERED AGENTS:
  ✓ Cursor (cursor)
      Config: .cursor/mcp.json

FINDINGS:

┌─ [HIGH    ] MCP server 'remote' uses plain HTTP URL: http://example.com/mcp (MCP-REMOTE-001)
│
│  MCP server configuration issue detected
│  Agent: Cursor
│  Resource: .cursor/mcp.json
│
│  💡 Suggested Fix:
│     Use HTTPS instead of plain HTTP for remote connections
└───────────────────────────────────────────────────────────────────────

┌─ [MEDIUM  ] MCP server 'filesystem' uses unpinned package: some-mcp-server (MCP-SUPPLY-001)
│
│  MCP server configuration issue detected
│  Agent: Cursor
│  Resource: .cursor/mcp.json
│
│  💡 Suggested Fix:
│     Pin the package to a specific version, e.g., npx -y package@1.2.3
└───────────────────────────────────────────────────────────────────────
```

Each finding is a box. The first line is the severity, the title, and the rule code in parentheses. `Agent` is the discovered product. `Resource` is the config file. The suggested fix is the next edit to make.

The risk label is a score band, not the exit code. Bands are 0–25 low, 26–50 medium, 51–75 high, and 76–100 critical. The sample scores 14 (low) and still exits 1, because exit codes follow the highest finding severity.

Write files at the same time:

```bash
balerx scan --json scan.json --sarif scan.sarif --html report.html
```

`--quiet` skips the terminal report and still writes the files you named. JSON `rule_id` is the Rust name (`McpRemotePlainHttp`). The terminal and SARIF `ruleId` use the code (`MCP-REMOTE-001`). SARIF is 2.1.0. Its `informationUri` is `https://github.com/wrjewski/balerx`.

## Exit codes

| Code | When |
| --- | --- |
| 0 | No critical or high finding. `balerx diff` also returns 0 when the lockfile matches. `balerx canary check` returns 0 when the path is not a planted canary. |
| 1 | At least one high finding, or `balerx diff` found drift, or the command failed (missing lockfile, missing file, missing API URL). `balerx canary check` returns 1 when the file is missing. `balerx guard status` returns 1 when no hook is installed. |
| 2 | At least one critical finding. Critical wins over high. `balerx canary check` returns 2 when the path is a planted canary. A Claude Code deny also exits 2. |

Medium, low, and info findings stay on exit code 0 unless you pass `--fail-on`. `--fail-on critical|high|medium|low|info` exits 1 when any finding is at or above that severity. These default codes were checked with `balerx scan` against a medium-only config (0), a plain-HTTP config (1), and a config containing an access-key-shaped value (2).

## Commands

Flags below are the ones `balerx <command> --help` prints. `-h` and `--help` exist on every command. `-V` / `--version` exists on `balerx` itself.

| Command | What it does |
| --- | --- |
| `balerx scan [PATH]` | Discover agents and report config findings. A path scans that directory or one config file. Nothing is uploaded. |
| `balerx scan --format json\|sarif\|text` | Write that report to stdout. |
| `balerx scan --fail-on <SEVERITY>` | Exit 1 at or above `critical`, `high`, `medium`, `low`, or `info`. |
| `balerx scan --json <FILE>` | Also write findings JSON. |
| `balerx scan --sarif <FILE>` | Also write SARIF 2.1.0, including `driver.rules` and line regions when known. |
| `balerx scan --html <FILE>` | Also write a single-file HTML report. |
| `balerx scan -q, --quiet` | Skip the terminal report and turn tracing off. Logs go to stderr. Color follows `NO_COLOR` and whether stdout is a terminal. |
| `balerx lock` | Write `balerx.lock` in the current directory. MCP servers, a config content hash, and home-relative paths are recorded. The hostname is omitted. |
| `balerx lock -o, --output <PATH>` | Write the lockfile somewhere else. |
| `balerx diff` | Compare the current machine with `balerx.lock`, including MCP servers that were added, removed, or changed. |
| `balerx diff -l, --lockfile <PATH>` | Compare against another lockfile. |
| `balerx guard install <AGENT>` | Merge local hooks. `<AGENT>` is `claude-code` (`~/.claude/settings.json`) or `cursor` (`~/.cursor/hooks.json`). Existing hooks stay. |
| `balerx guard uninstall <AGENT>` | Remove only Balerx hook commands. Other hooks stay. No backup is restored. |
| `balerx guard status` | Show install state, `fail_open`, `timeout_ms`, and the log path. |
| `balerx hook --event-type <EVENT_TYPE>` | Read one JSON event on stdin and print the agent's native decision (`permissionDecision` for Claude Code, `permission` for Cursor), including `ask`. Agents call this. |
| `balerx log view` | Show the local activity log. Default `--limit` is 50. |
| `balerx log view -l, --limit <N>` | Show at most N entries. |
| `balerx log view -a, --agent <AGENT>` | Keep entries whose agent field equals this string. |
| `balerx log view -t, --event-type <TYPE>` | Keep entries whose event type equals this string. |
| `balerx canary plant <TYPE>` | Write a realistic credential file with no canary banner. `<TYPE>` is `aws`, `env`, `ssh`, or `generic`. The command prints a warning. |
| `balerx canary plant <TYPE> -l, --location <PATH>` | Choose the file path. The default is `~/.balerx/canaries/` plus a type-specific name. |
| `balerx canary list` | List planted canaries. |
| `balerx canary check <PATH>` | Exit 0, 2, or 1: not a canary, a canary, or a missing file. |
| `balerx canary remove <CANARY_ID>` | Delete one canary by the id from `plant` or `list`. |
| `balerx upload --api-url <URL> --api-key <KEY>` | Send data. Also requires `--scan`, `--activity-log`, and/or `--lockfile`. |
| `balerx upload --scan <FILE>` | Upload findings JSON from `balerx scan --json`. |
| `balerx upload --activity-log <FILE>` | Upload a Guard JSONL log. Tool arguments are removed first. |
| `balerx upload --lockfile <FILE>` | Attach lockfile drift to the scan upload. |
| `balerx policy pull --api-url <URL> --api-key <KEY>` | Download the organization policy. |
| `balerx policy pull --output <PATH>` | Write the policy somewhere other than `~/.balerx/policy.yaml`. |

`upload` and `policy pull` accept the same values from `BALERX_API_URL` and `BALERX_API_KEY`. `--api-key -` reads the key from stdin. Any other `--api-key` value prints a warning on stderr. If the URL is missing, the command prints `Pass --api-url or set BALERX_API_URL` and exits 1 without opening a connection. A rejected key mentions HTTP 401. A missing file mentions the path (`Could not read file:`).

More detail: [scan](../docs/cli/scan.md), [guard](../docs/cli/guard.md), [policy](../docs/cli/policy.md), [hooks](../docs/HOOKS.md).

## Connect to the dashboard

1. In Balerx Gate onboarding, copy the ingest key and the API URL the dashboard shows. This repository does not name a host.
2. Save them in the environment, or pass them as flags:

```bash
export BALERX_API_URL
export BALERX_API_KEY
balerx scan --json scan.json
balerx upload --scan scan.json
```

A successful scan upload prints `Uploaded scan scan.json`. A successful activity upload prints `Uploaded N activity events from <path>`. A successful policy pull prints `Wrote organization policy to <path>`. A rejected request prints `Upload failed:` or `Policy pull failed:` and exits 1.

The local Guard policy lives at `~/.balerx/policy.yaml` (your user profile on Windows). Until you pull one, Guard uses a built-in policy. There is no separate scanner config file.

## CI

This workflow checks out the scanner, builds it, and scans the repository that contains the workflow. The job fails when `balerx scan` exits 1 or 2. Code scanning must be enabled on that repository before the upload step can succeed.

```yaml
name: Balerx Gate
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Check out the project
        uses: actions/checkout@v4

      - name: Check out the scanner
        uses: actions/checkout@v4
        with:
          repository: wrjewski/balerx
          path: balerx

      - name: Install the scanner toolchain
        uses: dtolnay/rust-toolchain@nightly

      - name: Build balerx
        working-directory: balerx/balerx-sensor
        run: cargo build --locked --release

      - name: Scan this repository
        run: balerx/balerx-sensor/target/release/balerx scan --json balerx.json --sarif balerx.sarif

      - name: Upload SARIF to code scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: balerx.sarif
```

`github/codeql-action/upload-sarif` is the upload path. The `gh` CLI has no `code-scanning` command.

## Agents and rules

`balerx scan` looks for these agents when a known config file or install path exists:

| Id | Name |
| --- | --- |
| `cursor` | Cursor |
| `claude-code` | Claude Code |
| `claude-desktop` | Claude Desktop |
| `vscode-copilot` | VS Code with GitHub Copilot |
| `windsurf` | Windsurf |
| `cline` | Cline (Roo Code) |
| `roo-code` | Roo Code |
| `codex-cli` | Codex CLI |
| `gemini-cli` | Gemini CLI |
| `aider` | Aider |
| `continue` | Continue |
| `zed` | Zed |
| `goose` | Goose |

`balerx scan` reports these rules. Severity is what this version assigns.

| Code | JSON `rule_id` | Severity | When it fires |
| --- | --- | --- | --- |
| `MCP-SUPPLY-001` | `McpSupplyUnpinned` | medium | `npx`, `uvx`, `pip`, or a Docker image with no version pin. `-y` and `--yes` are flags, not package names. `@scope/pkg@1.2.3` and `uvx`/`pip` `==` specs are pinned. `@latest` is not this rule |
| `MCP-SUPPLY-002` | `McpSupplyLatest` | medium | package or image uses `@latest`, `:latest`, or `*` |
| `MCP-PERM-001` | `McpPermBroadFilesystem` | high | an argument is `/`, `C:\`, `~`, `$HOME`, `/home`, `/Users`, `/root`, or one home directory such as `/home/dev` |
| `MCP-PERM-002` | `McpPermShellExec` | high | the server command is a shell (`bash`, `sh`, `zsh`, `powershell`, `pwsh`, `cmd`) |
| `MCP-PERM-003` | `McpPermDocker` | high | Docker or Podman is started with `--privileged` or a root mount |
| `MCP-PERM-004` | `McpPermDatabase` | medium | the command is a database client, or the URL is a database URL |
| `MCP-REMOTE-001` | `McpRemotePlainHttp` | high | `http://` whose host is not exactly `localhost`, `127.0.0.1`, `::1`, or `0.0.0.0`. `localhost.attacker.example` is not local |
| `MCP-REMOTE-002` | `McpRemoteNoAuth` | medium | a remote `http` or `https` server with no token, key, secret, or auth field |
| `SECRET-001` | `SecretInConfig` | critical, high, or medium | a secret pattern in a config file. AWS-shaped access keys are critical. GitHub, OpenAI (`sk-` and `sk-proj-`), and Anthropic (`sk-ant-`) shapes are high. Slack `xoxb-`, Stripe `sk_live_`, `github_pat_`, and URLs with passwords are detected. Generic assignments are medium |
| `SECRET-002` | `SecretInEnv` | same as SECRET-001 | the same patterns inside an `env` or `environment` field |
| `SECRET-003` | `SecretInArgs` | same as SECRET-001 | the same patterns inside `args` or `arguments` |
| `AGENT-AUTONOMY-001` | `AgentAutonomyAutoApprove` | high | Codex `approval_policy` is `never` |
| `AGENT-AUTONOMY-002` | `AgentAutonomyDangerousPermissions` | high | Claude `bypassPermissions` or `Bash(*)`, or Codex `sandbox_mode` `danger-full-access` |
| `TOOL-POISON-001` | `ToolPoisonHiddenInstructions` | critical, high, or medium | hidden instruction text in the scan directory |
| `TOOL-POISON-002` | `ToolPoisonExfiltration` | critical, high, or medium | a "Data Exfiltration" instruction pattern |
| `HOOK-GAP-001` | `HookGapNoGuard` | medium | Claude Code or Cursor has a config file and no Balerx hook command in it |
| `CONFIG-001` | `ConfigInvalid` | high | a discovered config file is not valid JSON or TOML |

`MCP-SUPPLY-003`, `MCP-SUPPLY-004`, and `HOOK-GAP-002` are planned. This version of `balerx scan` does not emit them. Duplicate findings with the same rule, resource, title, and evidence are collapsed. The risk label is CRITICAL when there is a critical finding or the score is above 75, HIGH when there are 3 or more high findings or the score is above 50, MEDIUM when any high or medium finding remains or the score is above 25, and LOW otherwise. Three high findings are HIGH even though 3 × 10 is 30.

Guard's built-in policy, used when `~/.balerx/policy.yaml` is missing:

| Rule | Action | Match |
| --- | --- | --- |
| `deny_ssh_keys` | deny | `**/.ssh/id_*` |
| `deny_env_files` | deny | `**/.env*` |
| `deny_pem_files` | deny | `**/*.pem` |
| `deny_curl_pipe_sh` | deny | `curl` piped to `sh` |
| `ask_force_push` | ask | `git push --force` |
| `deny_unapproved_mcp` | deny | present, disabled |

`localhost` and `127.0.0.1` HTTP URLs are not `MCP-REMOTE-001`.

## Configuration

There is no ignore file and no `--exclude` flag. `balerx scan` always reads the agent configs it discovers.

Guard policy is `~/.balerx/policy.yaml`. `balerx policy pull` replaces it. Invalid YAML is rejected and the previous file is left in place. The document shape is in [docs/cli/policy.md](../docs/cli/policy.md).

The activity log is `activity.jsonl` under the OS local data directory:

| OS | Path |
| --- | --- |
| Linux | `~/.local/share/balerx/logs/activity.jsonl` (`$XDG_DATA_HOME` when set) |
| macOS | `~/Library/Application Support/balerx/logs/activity.jsonl` |
| Windows | `%LOCALAPPDATA%\balerx\logs\activity.jsonl` |

`balerx guard install` prints the path on this machine. Canary registry data is `canaries.json` in the `balerx` folder next to `logs`. Planted files default to `~/.balerx/canaries/`.

`RUST_LOG` controls the tracing lines. The default level is `info`.

## Troubleshooting

**A config was skipped.** If a file cannot be read, the scan logs `Failed to parse MCP config` or `Failed to scan config` and continues. On Linux and macOS, run as the user who owns the agent profile. Exit code stays 0 when that was the only problem.

**Windows SmartScreen.** Release binaries are unsigned. Windows may say it protected your PC. Choose More info, then Run anyway, or build from source with `cargo build --locked --release` and run `target\release\balerx.exe`.

**Proxy.** `balerx scan` does not use the network. `balerx upload` and `balerx policy pull` use the first of `ALL_PROXY`, `HTTPS_PROXY`, and `HTTP_PROXY` (lowercase names work too). `NO_PROXY` skips matching hosts. The Windows system proxy setting is not read. A proxy that refuses the connection fails the command with `Upload failed:` or `Policy pull failed:`.

**`install.sh` says there is no release.** The checksum download failed. Build from source with the `cargo install` command above.

**Hooks did not fire.** `balerx guard install claude-code` merges `hooks.PreToolUse` and `hooks.PostToolUse` into `~/.claude/settings.json`. `balerx guard install cursor` merges `beforeShellExecution`, `beforeMCPExecution`, and `beforeReadFile` into `~/.cursor/hooks.json` and keeps `"version": 1`. Run `balerx guard status`, then re-open the agent.

## Uninstall

```bash
balerx guard uninstall claude-code
balerx guard uninstall cursor
rm -f "$HOME/.local/bin/balerx"
rm -rf "$HOME/.balerx" "$HOME/.local/share/balerx"
```

On macOS, also remove `~/Library/Application Support/balerx`. On Windows, uninstall the hooks with `balerx.exe guard uninstall`, then delete `%LOCALAPPDATA%\balerx` and `%USERPROFILE%\.balerx`. A source build is removed by deleting the `target` directory or the copied `balerx.exe`.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md).

## Security

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/wrjewski/balerx/security/advisories/new). Do not open a public issue for a security report. Details are in [SECURITY.md](https://github.com/wrjewski/balerx/blob/main/SECURITY.md).

## License

Apache License 2.0. See [LICENSE](./LICENSE) and [NOTICE](https://github.com/wrjewski/balerx/blob/main/NOTICE).

`packages/event-schema` (next to this crate in the public repository) is Apache-2.0 source. It is not published to npm.
