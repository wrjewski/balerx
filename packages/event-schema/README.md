# Balerx Gate event schema

`@balerx/event-schema` owns the canonical, versioned `SecurityEvent` contract shared by endpoint and SaaS sources.

## Source of truth

[`schema/security-event-v1.schema.json`](schema/security-event-v1.schema.json) is the source of truth for SecurityEvent v1. It declares the JSON Schema 2020-12 dialect, a versioned `$id`, a closed event envelope, and the core context objects for endpoint and integration events. This package does not import any other Balerx package.

The schema deliberately allows source-specific extension data only under `attributes` and `enrichment.attributes`. Prompts, source-file contents, credentials, tokens, and other prohibited content are not canonical event fields. JSON Schema cannot determine whether an extension value is sensitive, so producers must still apply the TDD's collection limits and local redaction before creating an event.

TypeScript declarations in `src/generated/security-event-v1.ts` are generated from the JSON Schema. Do not edit that file directly. Regenerate it with:

```powershell
pnpm --filter @balerx/event-schema generate
```

Runtime consumers should use `validateSecurityEventV1` before treating unknown input as `SecurityEventV1`.

Version 1 validates the canonical envelope and context shapes. It does not infer agent attribution, calculate confidence or severity, or enforce cross-field detection semantics; those behaviors belong to later normalization and detection tasks.

## Versioning and compatibility

`schemaVersion` uses semantic versioning and is part of every event. A schema file and its `$id` are immutable after release; corrections that change accepted event instances require a new schema version.

| Change | Version impact | Examples |
| --- | --- | --- |
| Breaking or narrowing | Major | Remove or rename a field, change a field's type or meaning, add a required field, tighten a constraint, remove an enum value. |
| Backward-compatible widening | Minor | Add an optional field, relax a constraint, or add an enum/action/category/source value. |
| Contract-neutral | Patch | Clarify descriptions or examples, or change generation/tooling without changing accepted instances. |

Enum additions are accepted by the newer schema but rejected by older strict validators. They therefore require a consumer-first rollout: deploy consumers that understand the new minor schema before producers emit its new values. Producers must emit the exact schema version they implement, and consumers must route or reject unsupported versions rather than silently coercing them.

Keep older schema versions and validators available while stored events, queued sensor batches, or integrations may still produce them. Breaking changes require a new major schema alongside migration and replay coverage.

## Validation

Representative endpoint and GitHub events live in `fixtures`. They are synthetic. See [fixtures/README.md](fixtures/README.md).

From this directory, with the dependencies declared in `package.json` installed:

```bash
npx tsc --project tsconfig.json
node --test test/*.test.mjs
```

The JSON Schema file is the contract. The open-source export replaces `tsconfig.json` with a standalone config so this package does not extend a parent file. Regenerating `src/generated` is optional and does not require any other Balerx package.

When a pnpm workspace is present, the same checks are:

```powershell
pnpm --filter @balerx/event-schema lint
pnpm --filter @balerx/event-schema typecheck
pnpm --filter @balerx/event-schema test
```
