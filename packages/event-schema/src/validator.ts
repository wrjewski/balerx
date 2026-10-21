import Ajv2020, { type ErrorObject } from 'ajv/dist/2020';
import addFormats from 'ajv-formats';

import type { SecurityEventV1 } from './generated/security-event-v1';
import { SECURITY_EVENT_V1_SCHEMA } from './schema';

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);

const validate = ajv.compile<SecurityEventV1>(SECURITY_EVENT_V1_SCHEMA);

export function validateSecurityEventV1(value: unknown): value is SecurityEventV1 {
  return validate(value);
}

export function getSecurityEventV1ValidationErrors(): readonly ErrorObject[] {
  return validate.errors ?? [];
}
