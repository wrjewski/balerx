# Changelog

## [0.1.5]

- `balerx --version` prints `balerx 0.1.5`.
- Windows `install.ps1` adds `%LOCALAPPDATA%\balerx` to the current process `Path`, so `irm ... | iex` can run `balerx` in that window. The message is `balerx is ready to use in this window. New terminals will pick it up automatically.` On macOS and Linux, `install.sh` prints `export PATH="$HOME/.local/bin:$PATH"` when that directory is not already on `PATH`.
- HOOK-GAP-001 names the command: `Run: balerx guard install claude-code` or `Run: balerx guard install cursor`, plus `More: https://balerxgate.com/docs/guard`.
- CONFIG-001 treats an empty, whitespace-only, or BOM-only JSON, TOML, or YAML file as info. The message is `Configuration file is empty`. The suggested contents follow the file: `{ "servers": {} }` for VS Code `mcp.json`, `{ "mcpServers": {} }` for Cursor, Claude, Windsurf, Cline, Roo, and Gemini JSON, `[mcp_servers]` for Codex TOML, `{}` for Claude Code settings and VS Code `settings.json`, and YAML text for Aider, Continue, and Goose. Malformed JSON and TOML stay high and include the parser line and column.
- `balerx guard status` exits 0 on a fresh install and prints `Not installed — run: balerx guard install claude-code` and `balerx guard install cursor`. `--strict` and `--check` exit 1 when no hook is installed, which is the exit code a CI script can use.
- `balerx version --check` and `balerx self-update --check` compare this build with the latest stable GitHub release. The check is one HTTPS GET and runs only when `--check` is set. A matching release prints `balerx 0.1.5 is up to date`. A local build newer than that release prints `balerx 0.1.5 is ahead of the latest release (0.1.4)`. `doctor`, `completions`, `balerx --version`, `-V`, and `self-update` without `--check` stay offline. A timeout, rate limit, or missing network prints a message and exits 0.
- `balerx --help` lists `version` and `self-update` with short one-line descriptions. `--check` stays on `version --help` and `self-update --help`. The footer lists the common commands, including `balerx setup` and `balerx self-update --check`.
- A discovered agent other than Claude Code or Cursor gets a Guard coverage line. The line says Guard hooks are not available for that agent yet and that the scan still checks its config. It is separate from findings, leaves the risk score unchanged, and does not trip `--fail-on`. `HOOK-GAP-002` stays planned.
- `balerx guard install claude-code` lists each settings file once, including a Windows `\\?\` path. A second install does not add another hook.
- `balerx setup` and `balerx policy init` print a Balerx Gate banner before the checklist. A color terminal at least 70 columns wide shows the dragon mark and a BALERX GATE wordmark with the tagline `Security for AI agents` and `v0.1.5`. Narrower terminals print one line. Width comes from `COLUMNS`, then the terminal size. On Windows, the block glyphs are used for Windows Terminal, VS Code, and ConEmu. `NO_COLOR`, `--no-color`, and a pipe print plain text. `scan`, `hook`, `--help`, `--version`, and machine-readable output leave the banner out. `install.sh` and `install.ps1` print the same banner on the Installed screen.
- A `v0.1.5` tag publishes the six release archives, `SHA256SUMS`, `SHA256SUMS.bundle`, and `balerx.spdx.json`. It does not attach a Homebrew formula or winget manifests. Filling those checksums from `SHA256SUMS` and submitting the tap and winget-pkgs is a step after the release.
- `balerx uninstall` removes Balerx hook commands from Claude Code and Cursor and leaves every other hook. A command matches when it contains `balerx` and `hook` and it runs the `balerx` binary, or `balerx.exe`, with a separate `hook` argument. `my-balerx-webhook.sh` stays. Empty hook lists left behind are removed. It prints each path and asks before changing anything. `--yes` skips the question. A pipe without `--yes` changes nothing and prints `Run: balerx uninstall --yes`. Without `--purge`, policy files and the activity log stay, and the command says `Policy and logs stay. Pass --purge to delete them.` `--purge` deletes known files only: `policy.yaml`, `policy.yaml.bak` copies, planted canary files in `~/.balerx/canaries`, `canaries.json`, and `logs/activity.jsonl`. Unknown files stay. A directory is removed only when it is empty afterward and its name is `.balerx` or `balerx`. A custom `BALERX_DATA_DIR` is never removed wholesale. Purge does nothing and exits nonzero when the home directory or the data directory is not an absolute path. Symlinks are left in place. On macOS and Linux it removes `$HOME/.local/bin/balerx` only when that file is the running binary. On Windows it deletes known data files and does not delete `balerx.exe`. It prints `Remove-Item -Recurse -Force "$env:LOCALAPPDATA\balerx"` and the PowerShell that drops that folder from the user Path. The command stays offline.
- `balerx setup` writes `~/.balerx/policy.yaml`. `balerx policy init` is the same command. `--yes` and a missing terminal write the balanced preset. `--preset strict|balanced|minimal` selects a preset. `--yes` and `--preset` leave an existing file in place and say that `--replace` is required. A checklist confirms before it replaces an existing file. The previous file is copied to `policy.yaml.bak`. The notes for rules that are not in the checklist print only in that interactive checklist. `balerx policy show` and `balerx policy edit` read that file. The command stays offline. Scan and `guard install` print `No policy set yet. Run: balerx setup` when the file is missing.

## [0.1.4]

- Lockfile package names are the package, not the flag string, and the same config file is recorded once.
- Cursor is reported when `~/.cursor` exists. Process names match exactly. Instruction files deeper than three directories are scanned, with an agent name when the path implies one.
- Terminal report borders share one width. The scan clock is local.
- SARIF paths outside the working directory and under home are `~/...`.
- `scan` accepts `--exclude`, `--no-color`, and `--baseline`. `doctor`, `completions`, and `self-update` are offline. Passing the ingest key as a literal flag value is rejected.
- Release checksums are signed with keyless Sigstore. Installers verify that bundle when cosign is installed. A composite GitHub Action runs a prebuilt `balerx scan` and uploads SARIF.

## [0.1.3]

- Claude Code hooks use the documented matcher and command list. Cursor hooks keep version 1 and event arrays.
- Deny and ask follow each agent's own decision. `timeout_ms` and `fail_open` are honored.
- `balerx diff` reports MCP servers that were added, removed, or changed.
- Detection covers package pins, VS Code, Codex, Windsurf, Cline, and Roo, and the risk label matches the score.
- SARIF includes rules and locations. Missing files and HTTP 401 name the problem. The ingest key can be read from stdin.

## [0.1.2]

- The `v0.1.1` release binary still reported `0.1.0`. This version makes the tag and `balerx --version` agree: both are 0.1.2.

## [0.1.1]

- Scanner version matches the published `v0.1.1` release. `balerx --version` prints `balerx 0.1.1`.
- Windows release archives pass POSIX paths to `bsdtar`. Release notes say the binaries are unsigned.

## [0.1.0]

- Cross-platform `balerx` scanner, Guard hooks, lockfile drift, and optional upload.
- GitHub Release workflow for Windows, macOS, and Linux binaries with checksums, a CycloneDX SBOM, and artifact attestations.
- Install scripts for macOS, Linux, and Windows.
- Public landing page, user documentation, and a signup walkthrough.
