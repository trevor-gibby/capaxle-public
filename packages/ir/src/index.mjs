import { readFileSync } from "node:fs";

import {
  semanticHash,
  semanticHashDetails,
  validateDocument,
} from "./implementation.mjs";

export {
  IR_VERSION,
  JSON_SCHEMA_DIALECT,
  canonicalizeInput,
  jcs,
  metaValidateDraft202012Schema,
  normalizeDocument,
  validateDocument,
  validateSemantics,
  validateStructure,
  validateSchemaValue,
} from "./implementation.mjs";

export const CAPABILITY_IR_SCHEMA = Object.freeze(
  JSON.parse(
    readFileSync(
      new URL("../capability-ir.schema.json", import.meta.url),
      "utf8",
    ),
  ),
);

export function validateCapabilityDocument(document, options = {}) {
  return validateDocument(document, CAPABILITY_IR_SCHEMA, options);
}

export function capabilitySemanticHashDetails(document) {
  return semanticHashDetails(document, CAPABILITY_IR_SCHEMA);
}

export function capabilitySemanticHash(document) {
  return semanticHash(document, CAPABILITY_IR_SCHEMA);
}
