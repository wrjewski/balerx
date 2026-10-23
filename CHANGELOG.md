# Changelog

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
