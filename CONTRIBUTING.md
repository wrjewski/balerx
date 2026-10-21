# Contributing to the Balerx Gate scanner

Thanks for looking at the scanner. This repository is the Apache-2.0 `balerx` CLI, the Rust crates behind it, the SecurityEvent schema, and the user docs.

By submitting a contribution you agree that it is licensed under the Apache License 2.0, the same license as the rest of this repository. There is no separate contributor license agreement.

## Build and test

```bash
cd balerx-sensor
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --locked
```

The toolchain file in `balerx-sensor/rust-toolchain.toml` selects the Rust channel and includes rustfmt and clippy.

The SecurityEvent package is independent of the Rust workspace. From `packages/event-schema`, install its declared dependencies, then `npx tsc --project tsconfig.json` and `node --test test/*.test.mjs`.

## Changes that help

- New or updated agent fingerprints, with fixtures that contain no real configuration from your machine.
- Detection rules, with tests.
- Platform-specific path coverage on Windows, macOS, and Linux.
- Output formats and docs.

## Secrets in changes

Do not commit real credentials, tokens, private keys, `.env` files, or production configuration. Test values must be obviously fake and noted in `balerx-sensor/tests/fixtures/README.md`. The AWS documentation examples already used there are placeholders, not accounts.

## Reports

Use a public issue for bugs and features. Use the process in [SECURITY.md](SECURITY.md) for vulnerabilities. Do not put exploit detail in a public issue.

## Pull requests

Open a pull request against `main`. Describe the behavior change and the tests you ran. Keep the change focused.
