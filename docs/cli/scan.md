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

When `~/.balerx/policy.yaml` is missing, stderr includes `No policy set yet. Run: balerx setup`. `--quiet` hides that line. The scan does not open the checklist.

HOOK-GAP-001's suggested fix is `Run: balerx guard install claude-code` or `Run: balerx guard install cursor`, plus `More: https://balerxgate.com/docs/guard`. An empty, whitespace-only, or BOM-only JSON, TOML, or YAML config is info and the message is `Configuration file is empty`. The suggested fix matches the file: `{ "servers": {} }` for a VS Code `mcp.json`, `{ "mcpServers": {} }` for Cursor, Claude, Windsurf, Cline, Roo, and Gemini JSON, and `[mcp_servers]` or `[mcp_servers.<name>]` for Codex TOML. Claude Code `settings.json` and VS Code `settings.json` suggest `{}`. Aider, Continue, and Goose suggest YAML. Malformed JSON or TOML stays high and includes the parser line and column.

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

`balerx lock` writes `balerx.lock` in the current directory unless `--output` is set. The file records each MCP server and a SHA-256 of the raw config contents. Command, args, and package name and version are stored after URL redaction, so userinfo and sensitive query parameters do not remain when a git or tarball URL is the package spec. Command and args also redact credential-like long flags (`--` names containing token, secret, password, passwd, key, auth, credential, or cookie, with a following value or `=value`), `-H` / `--header` values that carry Authorization, Cookie, X-Api-Key, or X-Auth*, and inline shell `-c` strings when the shell is `command` or an arg. Benign query parameters such as `authSource`, `sslmode`, and `mode` stay. Paths are home-relative (`~/...`). The hostname field is left empty. `balerx diff` reports servers that were added, removed, or changed (command, arguments, or version), plus the other drift kinds in the hosted lockfile guide. Command-change and version-change messages run through the same redactor, including scheme-less fragments such as a host path with a query string, so an older lockfile does not print raw userinfo or query credentials. Userinfo is taken from the `@` in the authority only, so a path such as `/pkg@latest` stays. A `/` inside what looks like userinfo ends the authority, so that value is a path and is not redacted. Because the hash uses the raw config, upgrading the scanner does not report command, args, or version drift for the same machine. A lockfile written by this version shows spurious command/args drift when read by an older scanner (v0.1.5 and earlier). Run `balerx lock` with the same version everywhere.

## Output

- Terminal: summary, findings, and suggested fixes.
- JSON: device, agents, and findings. Secret values are redacted.
- SARIF 2.1.0: for code scanning. The report's `informationUri` is `https://github.com/wrjewski/balerx`. `driver.rules` lists each rule that fired, with that rule's summary. Result locations use a path relative to the working directory when the file is under it. A file under the home directory and outside the working directory is `~/...` rather than an absolute path. `region.startLine` is set when the finding has a line.
- HTML: a single-file report.

Credentials in MCP server URLs, meaning userinfo and sensitive query parameters, are redacted in terminal, JSON, SARIF, HTML (including unpinned and latest-tag finding titles and evidence), the lockfile (command, args, and package name/version), and upload. Credential-like flags, Authorization / Cookie / X-Api-Key / X-Auth* headers, and inline shell `-c` strings are redacted in lockfile command and args. Benign query parameters stay. Userinfo is taken from the `@` in the authority only, so a path such as `/pkg@latest` stays. A `/` inside what looks like userinfo ends the authority, so that value is a path and is not redacted. Values that appear only in a URL path are not redacted. Upload runs the same redactor over the whole scan JSON and lockfile drift payload, so an older report file is scrubbed before it is posted.

## Upload

Upload is opt-in. There is no default API URL.

```bash
export BALERX_API_KEY
balerx upload \
  --api-url "$BALERX_API_URL" \
  --scan scan.json
```

`--api-url` overrides `BALERX_API_URL`. The API key comes from `BALERX_API_KEY`. `--api-key -` reads one line from stdin. A literal `--api-key VALUE` is rejected, because that value shows up in the process list and shell history.

PowerShell:

```powershell
$env:BALERX_API_KEY = "<key>"
balerx upload --api-url "$env:BALERX_API_URL" --scan scan.json
```

Or read from stdin:

```bash
printf '%s' "$BALERX_API_KEY" | balerx upload --api-url "$BALERX_API_URL" --api-key - --scan scan.json
```

PowerShell stdin:

```powershell
"$env:BALERX_API_KEY" | balerx upload --api-url "$env:BALERX_API_URL" --api-key - --scan scan.json
```

The command stays offline until both a URL and a key are set. Sign up at https://balerxgate.com, then copy the ingest URL from Settings or Onboarding. This repository does not publish the API hostname.

A rejected key prints `Upload failed: the server rejected the API key (HTTP 401). Check BALERX_API_KEY.` A missing upload file prints `Could not read file:` and the path.

`--activity-log` uploads Guard metadata. Tool arguments are removed before the request. `--lockfile` attaches drift to a scan upload.

## What the rules cover

Rules are compiled into `balerx-core` (`RuleId` in `crates/balerx-core/src/rules.rs`). There is no separate downloadable rule pack in this repository yet.

| Family | Examples |
| --- | --- |
| `MCP-SUPPLY` | Unpinned packages, `@latest` or `:latest`. Git and tarball specs that contain `://` and an `@` raise MCP-SUPPLY-001 (v0.1.5 missed those). Specs that contain `://` and no `@` were already flagged. A dedicated git-commit rule (`MCP-SUPPLY-003`) and local scripts (`MCP-SUPPLY-004`) stay planned |
| `MCP-PERM` | Broad filesystem access, a shell command, privileged Docker, database clients |
| `MCP-REMOTE` | Plain HTTP, missing auth |
| `SECRET` | Keys and tokens in config, env, and args. Values are redacted in output. Credentials in MCP server URLs (userinfo and sensitive query parameters) are also redacted in terminal, JSON, SARIF, HTML (including unpinned and latest-tag finding titles), the lockfile (including package name/version), and upload. Credential-like flags and Authorization / Cookie / X-Api-Key / X-Auth* headers are redacted in lockfile command and args. Userinfo is taken from the `@` in the authority only, so a path such as `/pkg@latest` stays. A `/` inside what looks like userinfo ends the authority, so that value is a path and is not redacted. Values in a URL path are not |
| `AGENT-AUTONOMY` | `approval_policy: never`, `bypassPermissions`, `Bash(*)`, `danger-full-access` |
| `TOOL-POISON` | Hidden instructions and exfiltration wording in the scan directory |
| `HOOK-GAP` | Claude Code or Cursor configured without a Balerx hook. Missing telemetry (`HOOK-GAP-002`) is planned and current scans do not raise it. Other discovered agents get a Guard coverage line in the agents section. That line is separate from findings, leaves the risk score unchanged, and does not trip `--fail-on` |
| `CONFIG` | An empty config file is info. A file that is not valid JSON or TOML is high (`CONFIG-001`) |
