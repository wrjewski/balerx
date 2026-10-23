# Balerx Gate scanner

These pages describe the open-source `balerx` command. The scanner runs on your machine. It does not call a hosted API unless you set an API URL yourself.

| Topic | Page |
| --- | --- |
| Scan, lockfile, output formats | [scan.md](scan.md) |
| Guard hooks and the local activity log | [guard.md](guard.md) |
| Policy file | [policy.md](policy.md) |
| Hook payload shapes | [../HOOKS.md](../HOOKS.md) |

`balerx upload` and `balerx policy pull` accept `--api-url` or `BALERX_API_URL`, and `--api-key` or `BALERX_API_KEY`. No API host is compiled into the binary. Sign up at https://balerxgate.com and copy the ingest URL from Settings or Onboarding.
