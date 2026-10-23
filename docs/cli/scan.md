# `balerx scan`

`balerx scan` discovers supported AI coding agents, reads their configuration, and reports risky MCP setups and secrets. It does not start those MCP servers. It does not send the scan anywhere unless you upload it yourself.

```bash
balerx scan
balerx scan .
balerx scan ./mcp.json
balerx scan --format json
balerx scan --format sarif
balerx scan --fail-on high
balerx scan --json scan.json --sarif scan.sarif --html report.html
balerx scan --json results.json --quiet
```

`scan` accepts an optional path. A directory is the poison-scan root. A file is scanned as one config. Logs and tracing go to stderr. `--quiet` (`-q`) turns tracing off and skips the terminal report. Color is off when `NO_COLOR` or `--no-color` is set, or stdout is not a terminal. The timestamp is the local clock.

`--exclude PATH` drops findings under that path. Repeat it to skip more than one. `--baseline FILE` reads a JSON file shaped as `{"ignore":[{"rule_id":"MCP-REMOTE-001","resource":".cursor/mcp.json"}]}` and hides those findings. `rule_id` is the rule code.

`--format json`, `--format sarif`, and `--format text` write that report to stdout. `--json`, `--sarif`, and `--html` still write files.

Exit codes without `--fail-on`:

| Code | Meaning |
| --- | --- |
| 0 | No critical or high finding |
| 1 | At least one high finding |
| 2 | At least one critical finding |

`--fail-on critical|high|medium|low|info` exits 1 when any finding is at or above that severity, and 0 otherwise. It replaces the default 2/1/0 codes.

## Lockfile

```bash
balerx lock
balerx lock --output my-team.lock
balerx diff
balerx diff --lockfile my-team.lock
```

`balerx lock` writes `balerx.lock` in the current directory unless `--output` is set. The file records each MCP server and a SHA-256 of the config contents. Paths are home-relative (`~/...`). The hostname field is left empty. `balerx diff` reports servers that were added, removed, or changed (command, arguments, or version), plus the other drift kinds in the hosted lockfile guide.

## Output

- Terminal: summary, findings, and suggested fixes.
- JSON: device, agents, and findings. Secret values are redacted.
- SARIF 2.1.0: for code scanning. The report's `informationUri` is `https://github.com/wrjewski/balerx`. `driver.rules` lists each rule that fired, with that rule's summary. Result locations use a path relative to the working directory when the file is under it. A file under the home directory and outside the working directory is `~/...` rather than an absolute path. `region.startLine` is set when the finding has a line.
- HTML: a single-file report.

## Upload

Upload is opt-in. There is no default API URL.

```bash
balerx upload \
  --api-url "$BALERX_API_URL" \
  --api-key "$BALERX_API_KEY" \
  --scan scan.json
```

`--api-url` overrides `BALERX_API_URL`. The API key comes from `BALERX_API_KEY`. `--api-key -` reads one line from stdin. A literal `--api-key VALUE` is rejected, because that value shows up in the process list and shell history. The command stays offline until both a URL and a key are set. Sign up at https://balerxgate.com, then copy the ingest URL from Settings or Onboarding. This repository does not publish the API hostname.

A rejected key prints `Upload failed: the server rejected the API key (HTTP 401). Check BALERX_API_KEY.` A missing upload file prints `Could not read file:` and the path.

`--activity-log` uploads Guard metadata. Tool arguments are removed before the request. `--lockfile` attaches drift to a scan upload.

## What the rules cover

Rules are compiled into `balerx-core` (`RuleId` in `crates/balerx-core/src/rules.rs`). There is no separate downloadable rule pack in this repository yet.

| Family | Examples |
| --- | --- |
| `MCP-SUPPLY` | Unpinned packages, `@latest` or `:latest`. Git URLs without a commit (`MCP-SUPPLY-003`) and local scripts (`MCP-SUPPLY-004`) are planned |
| `MCP-PERM` | Broad filesystem access, a shell command, privileged Docker, database clients |
| `MCP-REMOTE` | Plain HTTP, missing auth |
| `SECRET` | Keys and tokens in config, env, and args. Values are redacted in output |
| `AGENT-AUTONOMY` | `approval_policy: never`, `bypassPermissions`, `Bash(*)`, `danger-full-access` |
| `TOOL-POISON` | Hidden instructions and exfiltration wording in the scan directory |
| `HOOK-GAP` | Claude Code or Cursor configured without a Balerx hook. Missing telemetry (`HOOK-GAP-002`) is planned |
| `CONFIG` | A discovered config file that is not valid JSON or TOML (`CONFIG-001`) |
