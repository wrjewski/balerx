# Balerx Gate scanner

These pages describe the open-source `balerx` command. `balerx setup` prints a Balerx Gate banner before the checklist. The scanner runs on your machine. It does not call a hosted API unless you set an API URL yourself. `balerx version --check` and `balerx self-update --check` are the other network commands: one public GitHub release lookup, and only when you pass `--check`.

| Topic | Page |
| --- | --- |
| Scan, lockfile, output formats | [scan.md](scan.md) |
| Guard hooks and the local activity log | [guard.md](guard.md) |
| Policy file | [policy.md](policy.md) |
| Hook payload shapes | [../HOOKS.md](../HOOKS.md) |

`balerx upload` and `balerx policy pull` accept `--api-url` or `BALERX_API_URL`, and `--api-key -` to read the key from stdin or `BALERX_API_KEY` from the environment. A literal `--api-key VALUE` is rejected for security. No API host is compiled into the binary. Sign up at https://balerxgate.com and copy the ingest URL from Settings or Onboarding.

## Other commands

The current scanner version is 0.1.6. `balerx --version` and `balerx version` print it. `balerx doctor` prints the version, data directory, Guard hook status, and policy. It does not use the network.

`balerx completions bash`, `balerx completions zsh`, `balerx completions fish`, and `balerx completions powershell` print a completion script. The script lists every subcommand, including `setup`, `policy`, `version`, `self-update`, `doctor`, and `uninstall`.

`balerx uninstall` removes Balerx hook commands from Claude Code and Cursor. A command matches when it contains `balerx` and `hook` and it runs the `balerx` binary, or `balerx.exe`, with a separate `hook` argument. `my-balerx-webhook.sh` stays. Empty hook lists left behind are removed. It prints each path and asks before it changes anything. `--yes` skips the question. A pipe without `--yes` changes nothing and prints `Run: balerx uninstall --yes`. Without `--purge`, policy files and the activity log stay, and the command says `Policy and logs stay. Pass --purge to delete them.` `--purge` deletes known files only and leaves unknown files. A custom `BALERX_DATA_DIR` is never removed wholesale. Purge exits nonzero when the home directory or the data directory is not an absolute path. On macOS and Linux, `$HOME/.local/bin/balerx` is removed only when that file is the running binary. On Windows the command prints `Remove-Item -Recurse -Force "$env:LOCALAPPDATA\balerx"` and the PowerShell that drops that folder from the user Path. It does not delete the running `balerx.exe`. The command stays offline.

`balerx self-update` prints the install command and does not download a binary. `balerx version --check` and `balerx self-update --check` compare this build with the latest stable GitHub release. They stay offline unless you pass `--check`. A matching release prints `balerx 0.1.6 is up to date`. A local build newer than that release prints `balerx 0.1.6 is ahead of the latest release (0.1.5)`.

`balerx help` and `balerx --help` print the command list. The footer is:

```text
Common commands:
  balerx scan
  balerx setup
  balerx guard install claude-code
  balerx guard install cursor
  balerx guard status
  balerx uninstall
  balerx doctor
  balerx self-update --check

Docs: https://balerxgate.com/docs/cli
```
