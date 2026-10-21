# `balerx scan`

`balerx scan` discovers supported AI coding agents, reads their configuration, and reports risky MCP setups and secrets. It does not start those MCP servers. It does not send the scan anywhere unless you upload it yourself.

```bash
balerx scan
balerx scan --json scan.json --sarif scan.sarif --html report.html
balerx scan --json results.json --quiet
```

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | No critical or high finding |
| 1 | At least one high finding |
| 2 | At least one critical finding |

## Lockfile

```bash
balerx lock
balerx lock --output my-team.lock
balerx diff
balerx diff --lockfile my-team.lock
```

`balerx lock` writes `balerx.lock` in the current directory unless `--output` is set. `balerx diff` compares the current machine with that file.

## Output

- Terminal: summary, findings, and suggested fixes.
- JSON: device, agents, and findings. Secret values are redacted.
- SARIF 2.1.0: for code scanning. The report's `informationUri` is `https://github.com/wrjewski/balerx`.
- HTML: a single-file report.

## Upload

Upload is opt-in. There is no default API URL.

```bash
balerx upload \
  --api-url "$BALERX_API_URL" \
  --api-key "$BALERX_API_KEY" \
  --scan scan.json
```

`--api-url` overrides `BALERX_API_URL`. `--api-key` overrides `BALERX_API_KEY`. The command stays offline until both are set. Use the API URL shown in your Balerx Gate dashboard's onboarding. This repository does not name a host.

`--activity-log` uploads Guard metadata. Tool arguments are removed before the request. `--lockfile` attaches drift to a scan upload.

## What the rules cover

Rules are compiled into `balerx-core` (`RuleId` in `crates/balerx-core/src/rules.rs`). There is no separate downloadable rule pack in this repository yet.

| Family | Examples |
| --- | --- |
| `MCP-SUPPLY` | Unpinned packages, `@latest`, Git URLs without a commit |
| `MCP-PERM` | Broad filesystem access, shell or exec servers |
| `MCP-REMOTE` | Plain HTTP, missing auth |
| `SECRET` | Keys and tokens in config. Values are redacted in output |
| `AGENT-AUTONOMY` | Auto-approve and dangerous permission settings |
| `TOOL-POISON` | Hidden instructions in skill files |
| `HOOK-GAP` | Guard hooks missing, telemetry disabled |
