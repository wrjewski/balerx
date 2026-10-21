# Scanner fixtures are not credentials

Committed files in this directory do not contain a complete provider key. Values such as `not-a-provider-key` are placeholders so config-parsing tests can read the files.

Detection tests build AWS, OpenAI, Anthropic, and GitHub-shaped strings in memory from short fragments in `crates/balerx-core/src/canary.rs`. The joined value exists only while the test or `balerx canary plant` is running. Those strings are synthetic. They are not issued credentials.

`balerx canary plant` writes the same kind of labeled fake material onto disk at the path you choose. Do not point it at a real credential file.
