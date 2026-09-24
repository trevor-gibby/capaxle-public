import { Buffer } from "node:buffer";
import { jcs } from "@capaxle/ir";
import type { JsonSchema, JsonValue } from "@capaxle/ir";
import type { RuntimeDocument } from "@capaxle/runtime";
import { cloneJson, compareText, ProjectionError } from "./shared.js";

type Capability = RuntimeDocument["capabilities"][number];
type ObjectSchema = Record<string, JsonValue>;
type Owner = { key: string; root: ObjectSchema };

const objectSchema = (value: unknown): ObjectSchema | null =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as ObjectSchema)
    : null;

const unpointer = (value: string) =>
  value.replaceAll("~1", "/").replaceAll("~0", "~");
const pointerToken = (ref: unknown, prefix: string): string | null => {
  if (typeof ref !== "string" || !ref.startsWith(prefix)) return null;
  const token = ref.slice(prefix.length);
  return token.length > 0 && !token.includes("/") ? unpointer(token) : null;
};
const encoded = (value: string) => Buffer.from(value).toString("base64url");
const sharedKey = (name: string) => `CapabilitySharedEncoded.${encoded(name)}`;
const localKey = (owner: string, name: string) =>
  `CapabilityLocal.${encoded(owner)}.${encoded(name)}`;
const defineData = (object: ObjectSchema, key: string, value: JsonValue) => {
  Object.defineProperty(object, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
};

function schemaValue(value: Capability["input"]): ObjectSchema {
  const record = objectSchema(value);
  const inline = objectSchema(record?.schema);
  return inline ?? record ?? {};
}

function createProjector(sharedSchemas: RuntimeDocument["schemas"]) {
  const definitions = new Map<string, ObjectSchema>();
  const signatures = new Map<string, string>();
  const states = new Set<string>();

  const ensure = (key: string, source: ObjectSchema, owner: Owner): void => {
    const signature = jcs(source);
    if (signatures.has(key) && signatures.get(key) !== signature)
      throw new ProjectionError("CAP_MCP_SCHEMA_UNREPRESENTABLE", {
        reason: "generated_key_collision",
      });
    if (states.has(key)) return;
    signatures.set(key, signature);
    states.add(key);
    definitions.set(key, rewrite(source, owner, source === owner.root));
  };

  const reference = (ref: unknown, owner: Owner): string => {
    const sharedName = pointerToken(ref, "#/schemas/");
    if (sharedName !== null) {
      const root = objectSchema(sharedSchemas[sharedName]);
      if (!root)
        throw new ProjectionError("CAP_MCP_SCHEMA_UNREPRESENTABLE", {
          reason: "unresolved_shared_reference",
          reference: String(ref),
        });
      const key = sharedKey(sharedName);
      ensure(key, root, { key: `shared\0${sharedName}`, root });
      return `#/$defs/${key}`;
    }
    const localName = pointerToken(ref, "#/$defs/");
    const localDefinitions = objectSchema(owner.root.$defs);
    const source =
      localName === null ? null : objectSchema(localDefinitions?.[localName]);
    if (localName === null || !source)
      throw new ProjectionError("CAP_MCP_SCHEMA_UNREPRESENTABLE", {
        reason: "unsupported_or_unresolved_reference",
        reference: String(ref),
      });
    const key = localKey(owner.key, localName);
    ensure(key, source, owner);
    return `#/$defs/${key}`;
  };

  const rewrite = (
    value: ObjectSchema,
    owner: Owner,
    omitOwnerDefinitions = false,
  ): ObjectSchema => {
    const output: ObjectSchema = {};
    for (const key of Object.keys(value).sort(compareText)) {
      const child = value[key]!;
      if (omitOwnerDefinitions && key === "$defs") continue;
      if (key === "$ref") output[key] = reference(child, owner);
      else if (key === "$defs" || key === "properties") {
        const source = objectSchema(child);
        if (!source)
          throw new ProjectionError("CAP_MCP_SCHEMA_UNREPRESENTABLE");
        const mapped: ObjectSchema = {};
        for (const name of Object.keys(source).sort(compareText)) {
          const schema = objectSchema(source[name]);
          if (!schema)
            throw new ProjectionError("CAP_MCP_SCHEMA_UNREPRESENTABLE");
          defineData(mapped, name, rewrite(schema, owner));
        }
        defineData(output, key, mapped);
      } else if (key === "items") {
        const schema = objectSchema(child);
        if (!schema)
          throw new ProjectionError("CAP_MCP_SCHEMA_UNREPRESENTABLE");
        output[key] = rewrite(schema, owner);
      } else if (key === "oneOf") {
        if (!Array.isArray(child))
          throw new ProjectionError("CAP_MCP_SCHEMA_UNREPRESENTABLE");
        output[key] = child.map((branch) => {
          const schema = objectSchema(branch);
          if (!schema)
            throw new ProjectionError("CAP_MCP_SCHEMA_UNREPRESENTABLE");
          return rewrite(schema, owner);
        });
      } else output[key] = cloneJson(child);
    }
    return output;
  };

  return {
    project(schema: ObjectSchema, ownerKey: string): ObjectSchema {
      return rewrite(schema, { key: ownerKey, root: schema }, true);
    },
    finish(root: ObjectSchema, requireObject = false): JsonSchema {
      const output: ObjectSchema = {
        ...root,
        $schema: "https://json-schema.org/draft/2020-12/schema",
      };
      if (requireObject) output.type = "object";
      if (definitions.size > 0) {
        const defs: ObjectSchema = {};
        for (const key of [...definitions.keys()].sort(compareText))
          defineData(defs, key, definitions.get(key)!);
        output.$defs = defs;
      }
      return output;
    },
  };
}

export function projectInputSchema(
  document: RuntimeDocument,
  capability: Capability,
): JsonSchema {
  const projector = createProjector(document.schemas);
  const schema = schemaValue(capability.input);
  return projector.finish(
    projector.project(
      schema,
      `inline\0${capability.id}\0${capability.version}\0input`,
    ),
    true,
  );
}

const STATUSES = [
  "invalid_argument",
  "unauthenticated",
  "permission_denied",
  "not_found",
  "already_exists",
  "failed_precondition",
  "conflict",
  "resource_exhausted",
  "cancelled",
  "deadline_exceeded",
  "unavailable",
  "internal",
] as const;

export function projectOutputSchema(
  document: RuntimeDocument,
  capability: Capability,
): JsonSchema {
  const projector = createProjector(document.schemas);
  const output = projector.project(
    schemaValue(capability.output),
    `inline\0${capability.id}\0${capability.version}\0output`,
  );
  const declared: JsonValue[] = [];
  for (const code of Object.keys(capability.errors).sort(compareText)) {
    const definition = capability.errors[code]!;
    const properties: ObjectSchema = {
      code: { const: code },
      correlationId: { type: "string" },
      message: { type: "string" },
      retryable: { const: definition.retryable },
      status: { const: definition.status },
    };
    if (definition.details)
      properties.details = projector.project(
        schemaValue(definition.details as Capability["input"]),
        `inline\0${capability.id}\0${capability.version}\0error:${code}`,
      );
    declared.push({
      type: "object",
      additionalProperties: false,
      required: ["code", "correlationId", "message", "retryable", "status"],
      properties,
    });
  }
  const framework: JsonValue = {
    type: "object",
    additionalProperties: false,
    required: ["code", "correlationId", "message", "retryable", "status"],
    properties: {
      code: { type: "string", pattern: "^CAP_" },
      correlationId: { type: "string" },
      details: {},
      message: { type: "string" },
      retryable: { type: "boolean" },
      status: { enum: STATUSES },
    },
  };
  return projector.finish({
    oneOf: [
      {
        type: "object",
        additionalProperties: false,
        required: ["correlationId", "ok", "value"],
        properties: {
          correlationId: { type: "string" },
          ok: { const: true },
          value: output,
        },
      },
      {
        type: "object",
        additionalProperties: false,
        required: ["error", "ok"],
        properties: {
          error: { oneOf: [...declared, framework] },
          ok: { const: false },
        },
      },
    ],
  });
}
