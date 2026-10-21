import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  getSecurityEventV1ValidationErrors,
  SECURITY_EVENT_SCHEMA_VERSION,
  validateSecurityEventV1,
} from '../dist/index.js';

function loadFixture(name) {
  return JSON.parse(readFileSync(new URL(`../fixtures/${name}`, import.meta.url), 'utf8'));
}

for (const fixture of ['endpoint-process-started.json', 'github-repository-pushed.json']) {
  test(`validates representative fixture: ${fixture}`, () => {
    const event = loadFixture(fixture);

    assert.equal(
      validateSecurityEventV1(event),
      true,
      JSON.stringify(getSecurityEventV1ValidationErrors()),
    );
    assert.equal(event.schemaVersion, SECURITY_EVENT_SCHEMA_VERSION);
  });
}

test('rejects an event without a required envelope field', () => {
  const event = loadFixture('endpoint-process-started.json');
  delete event.action;

  assert.equal(validateSecurityEventV1(event), false);
  assert.equal(
    getSecurityEventV1ValidationErrors().some(
      (error) => error.keyword === 'required' && error.params.missingProperty === 'action',
    ),
    true,
  );
});

test('rejects event identifiers that are not UUIDv7', () => {
  const event = loadFixture('github-repository-pushed.json');
  event.eventId = '33333333-3333-4333-8333-333333333333';

  assert.equal(validateSecurityEventV1(event), false);
  assert.equal(
    getSecurityEventV1ValidationErrors().some(
      (error) => error.instancePath === '/eventId' && error.keyword === 'pattern',
    ),
    true,
  );
});

test('rejects undeclared top-level content', () => {
  const event = loadFixture('endpoint-process-started.json');
  event.promptContent = 'must never enter the canonical event envelope';

  assert.equal(validateSecurityEventV1(event), false);
  assert.equal(
    getSecurityEventV1ValidationErrors().some(
      (error) =>
        error.keyword === 'additionalProperties' &&
        error.params.additionalProperty === 'promptContent',
    ),
    true,
  );
});
