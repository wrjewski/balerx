# Security policy

## Supported surface

This repository is the Balerx Gate scanner (`balerx`), the `balerx-core` and `balerx-cli` crates, and the SecurityEvent schema. Report problems in that code here.

## Reporting

Do not open a public GitHub issue for a suspected vulnerability.

Use [private vulnerability reporting](https://github.com/wrjewski/balerx/security/advisories/new) on this repository.

Please include the scanner version, the operating system, and a minimal way to reproduce the issue. Do not include live secrets, customer data, or production configuration. If a scan output is useful, redact it first.

## Response

We will acknowledge a report, investigate, and coordinate a fix and a release note. We do not run a paid bug bounty in this repository yet.

## Scanner expectations

- `balerx scan` does not start MCP servers and does not upload results.
- `balerx setup`, `balerx policy show`, and `balerx policy edit` stay on the machine.
- `balerx upload` and `balerx policy pull` require an explicit API URL and API key.
- `balerx version --check` and `balerx self-update --check` send one HTTPS GET to the public GitHub releases API. They run only when `--check` is set and send no account or machine data.
- Secret values are redacted in findings.
- Files under `balerx-sensor/tests/fixtures/` and the strings planted by `balerx canary` are fake.
