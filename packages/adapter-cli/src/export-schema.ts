import { Buffer } from "node:buffer";
import { jcs } from "@capaxle/ir";
import type { JsonSchema, JsonValue } from "@capaxle/ir";

type JsonObject = { [key: string]: JsonValue };

const SCHEMA_MAP_KEYWORDS = new Set([
  "$defs",
  "dependentSchemas",
  "patternProperties",
  "properties",
]);
const SCHEMA_ARRAY_KEYWORDS = new Set([
  "allOf",
  "anyOf",
  "oneOf",
  "prefixItems",
]);
const SCHEMA_KEYWORDS = new Set([
  "additionalProperties",
  "contains",
  "contentSchema",
  "else",
  "if",
  "items",
  "not",
  "propertyNames",
  "then",
  "unevaluatedItems",
  "unevaluatedProperties",
]);
const LITERAL_KEYWORDS = new Set(["const", "default", "enum", "examples"]);

const object = (value: JsonValue | undefined): JsonObject | null =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : null;

const clone = (value: JsonValue): JsonValue =>
  JSON.parse(JSON.stringify(value)) as JsonValue;

const pointerToken = (reference: JsonValue | undefined, prefix: string) => {
  if (typeof reference !== "string" || !reference.startsWith(prefix))
    return null;
  const token = reference.slice(prefix.length);
  if (token.length === 0 || token.includes("/")) return null;
  return token.replaceAll("~1", "/").replaceAll("~0", "~");
};

const encoded = (value: string) => Buffer.from(value).toString("base64url");
const sharedKey = (name: string) => `CapabilitySharedEncoded.${encoded(name)}`;
const localKey = (owner: string, name: string) =>
  `CapabilityLocal.${encoded(owner)}.${encoded(name)}`;

function define(target: JsonObject, key: string, value: JsonValue) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

function compareCodePoint(left: string, right: string) {
  const a = Array.from(left);
  const b = Array.from(right);
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const difference = a[index]!.codePointAt(0)! - b[index]!.codePointAt(0)!;
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

function sortValue(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(sortValue);
  const source = object(value);
  if (!source) return value;
  const result: JsonObject = {};
  for (const key of Object.keys(source).sort(compareCodePoint))
    define(result, key, sortValue(source[key]!));
  return result;
}

interface Owner {
  readonly key: string;
  readonly root: JsonObject;
}

/** Hoists every reachable shared/owner-local definition into one standalone schema. */
export function projectStandaloneSchema(
  schema: JsonSchema,
  sharedSchemas: Readonly<Record<string, JsonSchema>>,
  ownerKey: string,
  options: { readonly requireObject?: boolean } = {},
): JsonSchema | null {
  const definitions = new Map<string, JsonObject>();
  const signatures = new Map<string, string>();
  const states = new Map<string, "processing" | "done">();
  let failed = false;

  const fail = () => {
    failed = true;
    return null;
  };

  const sharedOwner = (name: string): Owner | null => {
    const root = object(sharedSchemas[name]);
    return Object.hasOwn(sharedSchemas, name) && root
      ? { key: `shared\u0000${name}`, root }
      : fail();
  };

  const ensureDefinition = (
    key: string,
    source: JsonObject,
    owner: Owner,
  ): boolean => {
    const signature = jcs(source);
    if (signatures.has(key) && signatures.get(key) !== signature) {
      fail();
      return false;
    }
    if (states.has(key)) return true;
    signatures.set(key, signature);
    states.set(key, "processing");
    const rewritten = rewriteSchema(source, owner, source === owner.root);
    if (!rewritten) return false;
    definitions.set(key, rewritten);
    states.set(key, "done");
    return true;
  };

  const rewriteReference = (reference: JsonValue, owner: Owner) => {
    const sharedName = pointerToken(reference, "#/schemas/");
    if (sharedName !== null) {
      const target = sharedOwner(sharedName);
      if (!target) return null;
      const key = sharedKey(sharedName);
      return ensureDefinition(key, target.root, target)
        ? `#/$defs/${key}`
        : null;
    }
    const localName = pointerToken(reference, "#/$defs/");
    if (localName !== null) {
      const localDefinitions = object(owner.root.$defs);
      const source = object(localDefinitions?.[localName]);
      if (
        !localDefinitions ||
        !Object.hasOwn(localDefinitions, localName) ||
        !source
      )
        return fail();
      const key = localKey(owner.key, localName);
      return ensureDefinition(key, source, owner) ? `#/$defs/${key}` : null;
    }
    return fail();
  };

  function rewriteSchema(
    value: JsonValue,
    owner: Owner,
    omitOwnerDefinitions = false,
  ): JsonObject | null {
    const source = object(value);
    if (!source) return fail();
    const result: JsonObject = {};
    for (const key of Object.keys(source).sort(compareCodePoint)) {
      const item = source[key]!;
      if (omitOwnerDefinitions && key === "$defs") continue;
      if (LITERAL_KEYWORDS.has(key)) {
        define(result, key, clone(item));
      } else if (key === "$ref") {
        const rewritten = rewriteReference(item, owner);
        if (!rewritten) return null;
        define(result, key, rewritten);
      } else if (SCHEMA_MAP_KEYWORDS.has(key)) {
        const entries = object(item);
        if (!entries) return fail();
        const mapped: JsonObject = {};
        for (const name of Object.keys(entries).sort(compareCodePoint)) {
          const rewritten = rewriteSchema(entries[name]!, owner);
          if (!rewritten) return null;
          define(mapped, name, rewritten);
        }
        define(result, key, mapped);
      } else if (SCHEMA_ARRAY_KEYWORDS.has(key)) {
        if (!Array.isArray(item)) return fail();
        const mapped: JsonValue[] = [];
        for (const entry of item) {
          const rewritten = rewriteSchema(entry, owner);
          if (!rewritten) return null;
          mapped.push(rewritten);
        }
        define(result, key, mapped);
      } else if (SCHEMA_KEYWORDS.has(key) && typeof item !== "boolean") {
        const rewritten = rewriteSchema(item, owner);
        if (!rewritten) return null;
        define(result, key, rewritten);
      } else {
        define(result, key, clone(item));
      }
    }
    return result;
  }

  const rootObject = object(schema as JsonValue);
  if (!rootObject) return null;
  const owner = { key: ownerKey, root: rootObject };
  const root = rewriteSchema(rootObject, owner, true);
  if (!root || failed) return null;
  define(root, "$schema", "https://json-schema.org/draft/2020-12/schema");
  if (options.requireObject) define(root, "type", "object");
  if (definitions.size > 0) {
    const emitted: JsonObject = {};
    for (const key of [...definitions.keys()].sort(compareCodePoint))
      define(emitted, key, definitions.get(key)!);
    define(root, "$defs", emitted);
  }
  return sortValue(root) as JsonSchema;
}
