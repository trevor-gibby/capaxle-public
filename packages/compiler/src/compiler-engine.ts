import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { types } from "node:util";
import ts from "typescript";
import {
  isCapability,
  type Capability,
  type RuntimeValidator,
  type RuntimeBindingHandle,
  type SchemaProvider,
} from "@capaxle/core";
import type { SharedSchema } from "@capaxle/core";
import {
  capabilitySemanticHash,
  jcs,
  normalizeDocument,
  validateCapabilityDocument,
  type Diagnostic,
  type JsonSchema,
  type JsonValue,
} from "@capaxle/ir";
import { discoverCapabilities } from "./discovery.js";
import {
  compileAuthenticatedSchemaBatch,
  schemaBatchOccurrenceEvidence,
  type SchemaBatchCompilationResult,
  type SchemaOccurrenceEvidence,
  type CompilerSchemaUse,
} from "./schema-compiler.js";
import {
  adaptDiscoveryDiagnostic,
  compilationDiagnostic,
  sortCompilationDiagnostics,
} from "./compilation-diagnostics.js";
import { compareText } from "./diagnostics.js";
import {
  loadFullCompilerConfig,
  httpHeaderToken,
  reservedHttpHeader,
  type Exposure,
  type ProjectionOverrides,
  type ResolvedCompilerConfig,
} from "./full-config.js";
import {
  ModuleGraphLoadError,
  runModuleLoadTransaction,
  type ModuleLoadTrace,
  type ModulePackageImport,
} from "./module-loader.js";
import type {
  ArtifactBuildContext,
  ArtifactProducerDiagnostic,
  CapabilityDocument,
  CompilationDiagnostic,
  CompilationDiagnosticSubphase,
  CompilationResult,
  CompilationSuccess,
  CompilationUpdate,
  CompiledArtifact,
  CompilerArtifactProducer,
  CompilerRootPublication,
  CompilerGraphNodeReport,
  CompilerGraphReport,
  CompilerOptions,
  CompilerSession,
  ProducerDependencyId,
  ProvenanceEntry,
  ResolvedCompilerCapability,
  ResolvedCompilerRegistry,
  RuntimeValidatorBindings,
  Sha256,
} from "./compilation-types.js";

export const COMPILER_VERSION = "0.1.0-alpha.2";
// Package-private framework construction path, never an application import.
const { getBindingHandle } = createRequire(import.meta.url)(
  fileURLToPath(
    new URL("./internal-bindings.js", import.meta.resolve("@capaxle/core")),
  ),
) as {
  readonly getBindingHandle: (
    descriptor: unknown,
    identity: {
      readonly id: string;
      readonly version: string;
      readonly irHash: Sha256;
    },
  ) => RuntimeBindingHandle | undefined;
};
const COMPILER = Object.freeze({
  name: "@capaxle/compiler",
  version: COMPILER_VERSION,
});
const PROJECT_SOURCE: CompilationDiagnostic["source"] = Object.freeze({
  file: ".",
  line: 1,
  column: 1,
});
const surfaces = ["http", "cli", "mcp", "internal"] as const;
const artifactToken = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const semver =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const successIdentity = new WeakMap<
  object,
  {
    readonly projectRoot: string;
    readonly outputDirectory: string;
    readonly outputExplicit: boolean;
    readonly outputSource: CompilationDiagnostic["source"];
    readonly cliBinary: string | undefined;
    readonly toolchain: Sha256;
    current: boolean;
  }
>();
const sha = (value: Uint8Array | string): Sha256 =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;
const bytes = (value: JsonValue): Uint8Array => Buffer.from(jcs(value), "utf8");
const encode = (value: string): string =>
  [...Buffer.from(value)]
    .map((byte) =>
      /[A-Za-z0-9._~-]/.test(String.fromCharCode(byte))
        ? String.fromCharCode(byte)
        : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`,
    )
    .join("");
const pointerToken = (value: string): string =>
  value.replaceAll("~", "~0").replaceAll("/", "~1");

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value))
    return value;
  Object.freeze(value);
  for (const child of Object.values(value as Record<string, unknown>))
    deepFreeze(child);
  return value;
}

function plainDataRecord(value: unknown): Record<string, unknown> | undefined {
  try {
    if (
      typeof value !== "object" ||
      value === null ||
      Array.isArray(value) ||
      types.isProxy(value)
    )
      return undefined;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return undefined;
    const output: Record<string, unknown> = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") return undefined;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
        return undefined;
      output[key] = descriptor.value;
    }
    return output;
  } catch {
    return undefined;
  }
}

function denseArrayValues(value: unknown): readonly unknown[] | undefined {
  try {
    if (
      !Array.isArray(value) ||
      types.isProxy(value) ||
      Object.getPrototypeOf(value) !== Array.prototype ||
      Reflect.ownKeys(value).length !== value.length + 1
    )
      return undefined;
    const output: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
        return undefined;
      output.push(descriptor.value);
    }
    return output;
  } catch {
    return undefined;
  }
}

function validJsonPointer(path: string): boolean {
  return (
    validIJsonString(path) &&
    (path === "" || /^(?:\/(?:[^~]|~[01])*)*$/.test(path))
  );
}

function pointerExists(value: unknown, path: string): boolean {
  if (!validJsonPointer(path)) return false;
  if (path === "") return true;
  let cursor = value;
  for (const rawToken of path.slice(1).split("/")) {
    const token = rawToken.replaceAll("~1", "/").replaceAll("~0", "~");
    try {
      if (Array.isArray(cursor)) {
        if (!/^(?:0|[1-9]\d*)$/.test(token)) return false;
        const index = Number(token);
        if (!Number.isSafeInteger(index) || index >= cursor.length)
          return false;
        const descriptor = Object.getOwnPropertyDescriptor(cursor, token);
        if (!descriptor || !("value" in descriptor)) return false;
        cursor = descriptor.value;
      } else {
        if (
          typeof cursor !== "object" ||
          cursor === null ||
          types.isProxy(cursor)
        )
          return false;
        const descriptor = Object.getOwnPropertyDescriptor(cursor, token);
        if (!descriptor || !("value" in descriptor)) return false;
        cursor = descriptor.value;
      }
    } catch {
      return false;
    }
  }
  return true;
}

function validIJsonString(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function portableCopy(
  value: unknown,
  ancestors = new WeakSet<object>(),
): { readonly ok: true; readonly value: JsonValue } | { readonly ok: false } {
  if (value === null || typeof value === "boolean") return { ok: true, value };
  if (typeof value === "string")
    return validIJsonString(value) ? { ok: true, value } : { ok: false };
  if (typeof value === "number")
    return Number.isFinite(value) &&
      (!Number.isInteger(value) || Number.isSafeInteger(value))
      ? { ok: true, value }
      : { ok: false };
  if (typeof value !== "object" || types.isProxy(value)) return { ok: false };
  if (ancestors.has(value)) return { ok: false };
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const entries = denseArrayValues(value);
      if (!entries) return { ok: false };
      const output: JsonValue[] = [];
      for (const entry of entries) {
        const copied = portableCopy(entry, ancestors);
        if (!copied.ok) return copied;
        output.push(copied.value);
      }
      return { ok: true, value: output };
    }
    const inspected = plainDataRecord(value);
    if (!inspected) return { ok: false };
    const output: Record<string, JsonValue> = {};
    for (const [key, entry] of Object.entries(inspected)) {
      if (!validIJsonString(key)) return { ok: false };
      const copied = portableCopy(entry, ancestors);
      if (!copied.ok) return copied;
      Object.defineProperty(output, key, {
        value: copied.value,
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return { ok: true, value: output };
  } catch {
    return { ok: false };
  } finally {
    ancestors.delete(value);
  }
}

function authoredExampleCopy(value: JsonValue): JsonValue {
  const copied = portableCopy(value);
  if (!copied.ok)
    throw new TypeError("Core supplied a non-portable capability example.");
  return copied.value;
}
function diagnostic(
  code: `CAP_${string}`,
  phase: CompilationDiagnostic["phase"],
  subphase: CompilationDiagnosticSubphase,
  message: string,
  source = PROJECT_SOURCE,
  path?: string,
  details?: JsonValue,
): CompilationDiagnostic {
  return compilationDiagnostic({
    code,
    severity: "error",
    phase,
    subphase,
    message,
    source,
    ...(path === undefined ? {} : { path }),
    ...(details === undefined ? {} : { details }),
  });
}
function info(
  rule: string,
  source: CompilationDiagnostic["source"],
  path: string,
): CompilationDiagnostic {
  return compilationDiagnostic({
    code: "CAP_PROJECTION_INFERRED",
    severity: "info",
    phase: "projection",
    subphase: path.includes("/http")
      ? "projection-http"
      : path.includes("/cli")
        ? "projection-cli"
        : path.includes("/mcp")
          ? "projection-mcp"
          : path.includes("/docs")
            ? "projection-docs"
            : "projection-sdk",
    message:
      "Projection metadata was inferred from the canonical capability contract.",
    source,
    path,
    details: { rule },
  });
}
function provenance(
  kind: ProvenanceEntry["kind"],
  source: CompilationDiagnostic["source"],
  sourcePath?: string,
  rule?: string,
): ProvenanceEntry {
  return Object.freeze({
    kind,
    source,
    ...(sourcePath === undefined ? {} : { sourcePath }),
    ...(rule === undefined ? {} : { rule }),
  });
}
function leafPointers(value: JsonValue, base = ""): readonly string[] {
  if (Array.isArray(value))
    return value.length
      ? value.flatMap((entry, index) =>
          leafPointers(entry, `${base}/${String(index)}`),
        )
      : [base];
  if (typeof value === "object" && value !== null) {
    const entries = Object.entries(value);
    return entries.length
      ? entries.flatMap(([key, entry]) =>
          leafPointers(entry, `${base}/${pointerToken(key)}`),
        )
      : [base];
  }
  return [base];
}

function firstIJsonIssue(
  value: JsonValue,
  path = "",
): { readonly path: string; readonly message: string } | undefined {
  if (typeof value === "string")
    return validIJsonString(value)
      ? undefined
      : { path, message: "String contains a lone UTF-16 surrogate." };
  if (typeof value === "number")
    return Number.isFinite(value) &&
      (!Number.isInteger(value) || Number.isSafeInteger(value))
      ? undefined
      : { path, message: "Number is outside the I-JSON numeric domain." };
  if (value === null || typeof value === "boolean") return undefined;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const issue = firstIJsonIssue(value[index]!, `${path}/${index}`);
      if (issue) return issue;
    }
    return undefined;
  }
  for (const [key, entry] of Object.entries(value)) {
    if (!validIJsonString(key))
      return { path, message: "Object key contains a lone UTF-16 surrogate." };
    const issue = firstIJsonIssue(entry, `${path}/${pointerToken(key)}`);
    if (issue) return issue;
  }
  return undefined;
}
function sharedReferences(value: JsonValue): readonly string[] {
  const names = new Set<string>();
  const visit = (entry: JsonValue): void => {
    if (Array.isArray(entry)) {
      for (const child of entry) visit(child);
      return;
    }
    if (typeof entry !== "object" || entry === null) return;
    const object = entry as Record<string, JsonValue>;
    if (typeof object.$ref === "string" && object.$ref.startsWith("#/schemas/"))
      names.add(
        object.$ref
          .slice("#/schemas/".length)
          .replaceAll("~1", "/")
          .replaceAll("~0", "~"),
      );
    for (const child of Object.values(object)) visit(child);
  };
  visit(value);
  return Object.freeze([...names].sort(compareText));
}
function diagnoseModuleCycles(
  sources: ReadonlyMap<string, ProjectSource>,
  diagnostics: CompilationDiagnostic[],
): ReadonlySet<string> {
  let nextIndex = 0;
  const index = new Map<string, number>();
  const low = new Map<string, number>();
  const stack: string[] = [];
  const stacked = new Set<string>();
  const cyclic = new Set<string>();
  const visit = (path: string): void => {
    index.set(path, nextIndex);
    low.set(path, nextIndex++);
    stack.push(path);
    stacked.add(path);
    for (const dependency of sources.get(path)?.imports ?? []) {
      if (!index.has(dependency)) {
        visit(dependency);
        low.set(path, Math.min(low.get(path)!, low.get(dependency)!));
      } else if (stacked.has(dependency))
        low.set(path, Math.min(low.get(path)!, index.get(dependency)!));
    }
    if (low.get(path) !== index.get(path)) return;
    const component: string[] = [];
    let member: string;
    do {
      member = stack.pop()!;
      stacked.delete(member);
      component.push(member);
    } while (member !== path);
    if (
      component.length > 1 ||
      sources.get(path)?.imports.includes(path) === true
    ) {
      const members = component.sort(compareText);
      for (const item of members) cyclic.add(item);
      const [primary, ...related] = members;
      diagnostics.push(
        compilationDiagnostic({
          code: "CAP_GRAPH_CYCLE",
          severity: "error",
          phase: "graph",
          subphase: "graph-cycle",
          message: "Project-local module dependency graph contains a cycle.",
          source: { file: primary!, line: 1, column: 1 },
          ...(related.length
            ? {
                related: related.map((file) => ({
                  message: "Another module in this dependency cycle.",
                  source: { file, line: 1, column: 1 },
                })),
              }
            : {}),
        }),
      );
    }
  };
  for (const path of [...sources.keys()].sort(compareText))
    if (!index.has(path)) visit(path);
  return cyclic;
}
function defaultHttpPath(prefix: string, id: string, version: string): string {
  return `${prefix}/capabilities/v${version.split(".")[0]}/${id.replaceAll(".", "/")}`;
}
interface SchemaResource {
  readonly schema: JsonSchema;
  readonly root: JsonSchema;
}
function resolveSchemaResource(
  schema: unknown,
  sharedSchemas: Readonly<Record<string, JsonSchema>>,
  root: JsonSchema | null = null,
  seen = new Set<unknown>(),
): SchemaResource | null {
  if (
    typeof schema !== "object" ||
    schema === null ||
    Array.isArray(schema) ||
    seen.has(schema)
  )
    return null;
  const value = schema as JsonSchema;
  const owner = root ?? value;
  if (!("$ref" in value)) return { schema: value, root: owner };
  const reference = value.$ref;
  if (typeof reference !== "string") return null;
  const prefix = reference.startsWith("#/schemas/") ? "#/schemas/" : "#/$defs/";
  if (!reference.startsWith(prefix)) return null;
  const token = reference.slice(prefix.length);
  if (!token || token.includes("/") || /~(?![01])/.test(token)) return null;
  const name = token.replaceAll("~1", "/").replaceAll("~0", "~");
  const table = prefix === "#/schemas/" ? sharedSchemas : owner.$defs;
  if (
    typeof table !== "object" ||
    table === null ||
    Array.isArray(table) ||
    !Object.hasOwn(table, name)
  )
    return null;
  const target = (table as Record<string, JsonSchema>)[name];
  return resolveSchemaResource(
    target,
    sharedSchemas,
    prefix === "#/schemas/" ? target! : owner,
    new Set([...seen, schema]),
  );
}
function inputSchemaResource(
  schemaRef: unknown,
  sharedSchemas: Readonly<Record<string, JsonSchema>>,
): SchemaResource | null {
  if (typeof schemaRef !== "object" || schemaRef === null) return null;
  return resolveSchemaResource(
    "schema" in schemaRef ? schemaRef.schema : schemaRef,
    sharedSchemas,
  );
}
function stableObjectSchema(
  schemaRef: unknown,
  sharedSchemas: Readonly<Record<string, JsonSchema>>,
): JsonSchema | null {
  const schema = inputSchemaResource(schemaRef, sharedSchemas)?.schema;
  if (!schema) return null;
  return schema.type === "object" &&
    schema.additionalProperties === false &&
    typeof schema.properties === "object" &&
    schema.properties !== null &&
    !Array.isArray(schema.properties)
    ? schema
    : null;
}
function stableProperties(
  schemaRef: unknown,
  sharedSchemas: Readonly<Record<string, JsonSchema>>,
): readonly string[] | null {
  const schema = stableObjectSchema(schemaRef, sharedSchemas);
  return schema
    ? Object.keys(schema.properties as JsonSchema).sort(compareText)
    : null;
}
type TextualScalar = "string" | "integer" | "number" | "boolean";
function directCliDefaultTrueBoolean(schema: unknown): boolean {
  if (typeof schema !== "object" || schema === null || Array.isArray(schema))
    return false;
  const value = schema as JsonSchema;
  if (
    "$ref" in value ||
    "oneOf" in value ||
    "anyOf" in value ||
    "allOf" in value ||
    value.default !== true
  )
    return false;
  if (value.type === "boolean") return true;
  if (value.type !== undefined) return false;
  if (Object.hasOwn(value, "const")) return typeof value.const === "boolean";
  return (
    Array.isArray(value.enum) &&
    value.enum.length > 0 &&
    value.enum.every((entry) => typeof entry === "boolean")
  );
}
function scalarKind(
  schema: unknown,
  sharedSchemas: Readonly<Record<string, JsonSchema>>,
  root: JsonSchema,
  seen = new Set<unknown>(),
): TextualScalar | null {
  if (seen.has(schema)) return null;
  const resolved = resolveSchemaResource(schema, sharedSchemas, root);
  if (!resolved || seen.has(resolved.schema)) return null;
  const value = resolved.schema;
  const scalar = (kind: unknown): kind is TextualScalar =>
    typeof kind === "string" &&
    ["string", "integer", "number", "boolean"].includes(kind);
  if (scalar(value.type)) return value.type;
  const jsonType = (item: JsonValue): string =>
    typeof item === "number" && Number.isInteger(item)
      ? "integer"
      : item === null
        ? "null"
        : typeof item;
  if (Object.hasOwn(value, "const")) {
    const type = jsonType(value.const!);
    return scalar(type) ? type : null;
  }
  if (Array.isArray(value.enum) && value.enum.length > 0) {
    const kinds = new Set(value.enum.map(jsonType));
    const [type] = kinds;
    return kinds.size === 1 && scalar(type) ? type : null;
  }
  if (Array.isArray(value.oneOf) && value.oneOf.length > 0) {
    const kinds = new Set(
      value.oneOf.map((branch) =>
        scalarKind(
          branch,
          sharedSchemas,
          resolved.root,
          new Set([...seen, value]),
        ),
      ),
    );
    const [type] = kinds;
    return kinds.size === 1 && scalar(type) ? type : null;
  }
  return null;
}
function textualBindingEligible(
  schema: JsonSchema,
  kind: "path" | "query" | "header",
  required: boolean,
  sharedSchemas: Readonly<Record<string, JsonSchema>>,
  root: JsonSchema,
): boolean {
  const scalar = scalarKind(schema, sharedSchemas, root);
  if (scalar)
    return (
      kind !== "path" ||
      (required && (scalar === "string" || scalar === "integer"))
    );
  const resolved = resolveSchemaResource(schema, sharedSchemas, root);
  return (
    kind === "query" &&
    resolved?.schema.type === "array" &&
    typeof resolved.schema.minItems === "number" &&
    resolved.schema.minItems >= 1 &&
    scalarKind(resolved.schema.items, sharedSchemas, resolved.root) !== null
  );
}
function kebabProperty(value: string): string | null {
  let result = "";
  for (let index = 0; index < value.length; index++) {
    const character = value[index]!;
    if (character === "_") result += "-";
    else if (/[A-Z]/.test(character))
      result += `${index === 0 ? "" : "-"}${character.toLowerCase()}`;
    else if (/[a-z0-9-]/.test(character)) result += character;
    else return null;
  }
  return result &&
    !result.startsWith("-") &&
    !result.endsWith("-") &&
    !result.includes("--")
    ? `--${result}`
    : null;
}
const reservedCli = new Set([
  "--json",
  "--no-input",
  "--input",
  "--input-file",
  "--correlation-id",
  "--idempotency-key",
  "--confirm",
  "--timeout",
  "--help",
  "--version",
]);
const cliCommandToken = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const reservedFrameworkHttpRoutes = Object.freeze([
  "/openapi.json",
  "/health",
  "/healthz",
  "/ready",
  "/readyz",
  "/readiness",
]);
const parameterSegment = /^\{[A-Za-z_][A-Za-z0-9_.-]*\}$/;
function httpPathsOverlap(left: string, right: string): boolean {
  const leftSegments = left.split("/");
  const rightSegments = right.split("/");
  return (
    leftSegments.length === rightSegments.length &&
    leftSegments.every(
      (segment, index) =>
        segment === rightSegments[index] ||
        parameterSegment.test(segment) ||
        parameterSegment.test(rightSegments[index]!),
    )
  );
}
function overlapsReservedFrameworkRoute(
  method: string,
  path: string,
  config: ResolvedCompilerConfig,
): boolean {
  return (
    (method === "GET" &&
      [
        ...reservedFrameworkHttpRoutes,
        ...Object.values(config.discovery.http),
      ].some((reserved) => httpPathsOverlap(path, reserved))) ||
    (method === "POST" && httpPathsOverlap(path, config.discovery.mcp.endpoint))
  );
}

class ImmutableMap<Key, Value> implements ReadonlyMap<Key, Value> {
  readonly #map: Map<Key, Value>;
  readonly #copy: (value: Value) => Value;
  constructor(
    entries: Iterable<readonly [Key, Value]>,
    copy: (value: Value) => Value = (value) => value,
  ) {
    this.#map = new Map(entries);
    this.#copy = copy;
    Object.freeze(this);
  }
  get size(): number {
    return this.#map.size;
  }
  has(key: Key): boolean {
    return this.#map.has(key);
  }
  get(key: Key): Value | undefined {
    const value = this.#map.get(key);
    return value === undefined ? undefined : this.#copy(value);
  }
  forEach(
    callbackfn: (value: Value, key: Key, map: ReadonlyMap<Key, Value>) => void,
    thisArg?: unknown,
  ): void {
    for (const [key, value] of this.#map)
      callbackfn.call(thisArg, this.#copy(value), key, this);
  }
  *entries(): MapIterator<[Key, Value]> {
    for (const [key, value] of this.#map) yield [key, this.#copy(value)];
  }
  *keys(): MapIterator<Key> {
    yield* this.#map.keys();
  }
  *values(): MapIterator<Value> {
    for (const value of this.#map.values()) yield this.#copy(value);
  }
  [Symbol.iterator](): MapIterator<[Key, Value]> {
    return this.entries();
  }
  get [Symbol.toStringTag](): string {
    return "ImmutableMap";
  }
}

interface ResolvedCapability {
  readonly ir: Record<string, JsonValue>;
  readonly registry: Omit<ResolvedCompilerCapability, "source">;
  readonly validators: RuntimeValidatorBindings;
  readonly source: CompilationDiagnostic["source"];
  readonly sourceHash: Sha256;
  readonly configDependencies: readonly string[];
  readonly sourceObject: Capability;
}

function validateOverrideObject(
  surface: string,
  raw: unknown,
  source: CompilationDiagnostic["source"],
  base: string,
  diagnostics: CompilationDiagnostic[],
): Record<string, unknown> | false | undefined {
  if (raw === undefined || raw === false) return raw;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    diagnostics.push(
      diagnostic(
        "CAP_CONFIG_PROJECTION_INVALID",
        "configuration",
        "config-value",
        "Projection overrides must be false or a plain object.",
        source,
        base,
      ),
    );
    return undefined;
  }
  const object = raw as Record<string, unknown>;
  const allowed =
    surface === "http"
      ? new Set(["method", "path", "bindings"])
      : surface === "cli"
        ? new Set(["command", "bindings"])
        : surface === "mcp"
          ? new Set(["toolName"])
          : surface === "docs"
            ? new Set(["group"])
            : new Set(["path"]);
  const policyKeys = new Set([
    "authentication",
    "permissions",
    "exposure",
    "effects",
    "confirmation",
    "idempotency",
    "retry",
    "limits",
    "requirements",
  ]);
  for (const key of Object.keys(object))
    if (!allowed.has(key))
      diagnostics.push(
        diagnostic(
          policyKeys.has(key)
            ? "CAP_IR_PROJECTION_POLICY_OVERRIDE"
            : "CAP_CONFIG_PROJECTION_INVALID",
          policyKeys.has(key) ? "ir" : "configuration",
          policyKeys.has(key) ? "ir-projection" : "config-value",
          policyKeys.has(key)
            ? "Projection overrides cannot restate or weaken canonical policy."
            : "Projection override contains an unsupported field.",
          source,
          `${base}/${pointerToken(key)}`,
        ),
      );
  return object;
}

function configSource(
  config: ResolvedCompilerConfig,
  path: string,
): CompilationDiagnostic["source"] {
  let cursor = path;
  while (cursor) {
    const source = config.sourceLocations[cursor];
    if (source) return source;
    cursor = cursor.slice(0, cursor.lastIndexOf("/"));
  }
  return config.sourceLocations[""] ?? config.source;
}

interface CapabilityAuthoringPresence {
  readonly effects: {
    readonly idempotency: boolean;
    readonly confirmation: boolean;
    readonly retry: boolean;
  };
  readonly errorRetryable: readonly string[];
  readonly secretOptional: readonly number[];
  readonly rateLimitCost: boolean;
  readonly sharedSchemas: readonly {
    readonly path: string;
    readonly schema: SharedSchema<string>;
  }[];
}

function capabilityAuthoringPresence(
  descriptor: Capability,
): CapabilityAuthoringPresence | undefined {
  const authentic = isCapability(descriptor);
  const query = (
    globalThis as typeof globalThis & {
      readonly [key: symbol]:
        | {
            readonly get: (
              value: unknown,
            ) => CapabilityAuthoringPresence | undefined;
          }
        | undefined;
    }
  )[Symbol.for("@capaxle/core/authoring-presence-registry@1")];
  if (!authentic) return undefined;
  return query?.get(descriptor);
}

function resolveCapability(
  capability: {
    id: string;
    derivedId: string;
    descriptor: Capability;
    source: CompilationDiagnostic["source"];
    sourceHash: string;
  },
  config: ResolvedCompilerConfig,
  compiled: Readonly<
    Record<string, { readonly schema: JsonSchema } | { readonly $ref: string }>
  >,
  sharedSchemas: Readonly<Record<string, JsonSchema>>,
  useValidators: ReadonlyMap<string, RuntimeValidator>,
  diagnostics: CompilationDiagnostic[],
): ResolvedCapability {
  const { id, descriptor, source } = capability;
  const projectionBase = `/projections/${pointerToken(id)}`;
  const exposure = Object.fromEntries(
    surfaces.map((surface) => [
      surface,
      descriptor.exposure?.[surface] ?? config.exposureDefaults[surface],
    ]),
  ) as Record<(typeof surfaces)[number], Exposure>;
  const provenanceMap: Record<string, ProvenanceEntry> = {};
  const configDependencies: string[] = [];
  for (const surface of surfaces) {
    if (descriptor.exposure?.[surface] === undefined) {
      configDependencies.push(`config:exposure-default/${surface}`);
      provenanceMap[`/access/exposure/${surface}`] = provenance(
        "application-default",
        configSource(config, `/exposureDefaults/${surface}`),
        `/exposureDefaults/${surface}`,
      );
    } else
      provenanceMap[`/access/exposure/${surface}`] = provenance(
        "author",
        source,
        `/exposure/${surface}`,
      );
  }
  provenanceMap["/access/authentication"] =
    descriptor.authentication === undefined
      ? provenance(
          "compiler-default",
          source,
          undefined,
          "capaxle:authentication:required@1",
        )
      : provenance("author", source, "/authentication");
  provenanceMap["/version"] =
    descriptor.version === undefined
      ? provenance(
          "compiler-default",
          source,
          undefined,
          "capaxle:capability-version@1",
        )
      : provenance("author", source, "/version");
  const override = config.projections[id];
  if (descriptor.id !== undefined && descriptor.id !== capability.derivedId)
    configDependencies.push("config:discovery/allow-id-override");
  const interfaces: Record<string, JsonValue> = {};
  const input = compiled[`${id}/input`]!;
  const properties = stableProperties(input, sharedSchemas);
  const resolvedInput = stableObjectSchema(input, sharedSchemas);
  const inputSchema =
    resolvedInput &&
    !("oneOf" in resolvedInput) &&
    !("const" in resolvedInput) &&
    !("enum" in resolvedInput)
      ? resolvedInput
      : null;
  const httpProperties = inputSchema ? properties : null;
  for (const surface of ["http", "cli", "mcp", "docs", "sdk"] as const) {
    const raw = validateOverrideObject(
      surface,
      override?.[surface],
      configSource(config, `${projectionBase}/${surface}`),
      `${projectionBase}/${surface}`,
      diagnostics,
    );
    if (override && surface in override)
      configDependencies.push(`config:projection/${encode(id)}/${surface}`);
    const canonicalDisabled =
      surface === "http" || surface === "cli" || surface === "mcp"
        ? exposure[surface] === "disabled"
        : false;
    if (raw === false || (raw === undefined && canonicalDisabled)) {
      interfaces[surface] = { enabled: false };
      provenanceMap[`/interfaces/${surface}/enabled`] =
        raw === false
          ? provenance(
              "projection-override",
              configSource(config, `${projectionBase}/${surface}`),
              `${projectionBase}/${surface}`,
            )
          : provenance(
              "inferred",
              source,
              undefined,
              `capaxle:projection:${surface}-disabled@1`,
            );
      continue;
    }
    if (raw && canonicalDisabled) {
      diagnostics.push(
        diagnostic(
          "CAP_IR_PROJECTION_WEAKENING",
          "ir",
          "ir-projection",
          "An enabled projection cannot broaden disabled canonical exposure.",
          configSource(config, `${projectionBase}/${surface}`),
          `${projectionBase}/${surface}`,
        ),
      );
      interfaces[surface] = { enabled: false };
      continue;
    }
    const object = raw || {};
    const overridden = raw !== undefined;
    const overrideSource = (suffix = "") =>
      overridden
        ? configSource(config, `${projectionBase}/${surface}${suffix}`)
        : source;
    const projectedPath = (suffix = "") =>
      overridden
        ? `${projectionBase}/${surface}${suffix}`
        : `/interfaces/${surface}${suffix}`;
    if (surface === "http") {
      const method = typeof object.method === "string" ? object.method : "POST";
      const path =
        typeof object.path === "string"
          ? object.path
          : defaultHttpPath(
              config.httpPrefix,
              id,
              descriptor.version ?? "1.0.0",
            );
      if (object.path === undefined)
        configDependencies.push("config:http-prefix");
      const bindings =
        object.bindings === undefined
          ? Object.fromEntries(
              (httpProperties ?? []).map((key) => [key, "body"]),
            )
          : object.bindings;
      if (!/^(GET|HEAD|POST|PUT|PATCH|DELETE)$/.test(method))
        diagnostics.push(
          diagnostic(
            "CAP_HTTP_METHOD_UNSUPPORTED",
            "projection",
            "projection-http",
            "HTTP method is unsupported.",
            overrideSource("/method"),
            projectedPath("/method"),
          ),
        );
      if (method === "HEAD")
        diagnostics.push(
          diagnostic(
            "CAP_HTTP_HEAD_UNSUPPORTED",
            "projection",
            "projection-http",
            "HEAD cannot preserve an MVP unary JSON result.",
            overrideSource("/method"),
            projectedPath("/method"),
          ),
        );
      if (
        !/^\/(?:[A-Za-z0-9._~-]+|\{[A-Za-z_][A-Za-z0-9_.-]*\})(?:\/(?:[A-Za-z0-9._~-]+|\{[A-Za-z_][A-Za-z0-9_.-]*\}))*$/.test(
          path,
        ) ||
        path.includes("//") ||
        path
          .split("/")
          .some((segment) => segment === "." || segment === "..") ||
        new Set(
          [...path.matchAll(/\{([A-Za-z_][A-Za-z0-9_.-]*)\}/g)].map(
            (match) => match[1],
          ),
        ).size !== [...path.matchAll(/\{([A-Za-z_][A-Za-z0-9_.-]*)\}/g)].length
      )
        diagnostics.push(
          diagnostic(
            "CAP_HTTP_PATH_INVALID",
            "projection",
            "projection-http",
            "HTTP path template is invalid.",
            overrideSource("/path"),
            projectedPath("/path"),
          ),
        );
      const allowedImpact =
        method === "GET"
          ? ["read"]
          : method === "DELETE"
            ? ["destructive"]
            : method === "POST"
              ? ["read", "write", "destructive"]
              : ["write", "destructive"];
      if (!allowedImpact.includes(descriptor.effects.impact))
        diagnostics.push(
          diagnostic(
            "CAP_HTTP_METHOD_EFFECT_CONFLICT",
            "projection",
            "projection-http",
            "HTTP method conflicts with canonical effects.",
            overrideSource("/method"),
            projectedPath("/method"),
          ),
        );
      if (
        typeof bindings !== "object" ||
        bindings === null ||
        Array.isArray(bindings)
      )
        diagnostics.push(
          diagnostic(
            "CAP_HTTP_BINDING_INVALID",
            "projection",
            "projection-http",
            "HTTP bindings must be a complete property map.",
            overrideSource("/bindings"),
            projectedPath("/bindings"),
          ),
        );
      else if (
        httpProperties === null
          ? Object.keys(bindings).length > 0
          : httpProperties.join("\0") !==
              Object.keys(bindings).sort(compareText).join("\0") ||
            Object.values(bindings).some(
              (value) =>
                !["path", "query", "header", "body"].includes(value as string),
            )
      )
        diagnostics.push(
          diagnostic(
            "CAP_HTTP_BINDING_INVALID",
            "projection",
            "projection-http",
            "HTTP bindings must cover each stable input property exactly once.",
            overrideSource("/bindings"),
            projectedPath("/bindings"),
          ),
        );
      if (
        typeof bindings === "object" &&
        bindings !== null &&
        !Array.isArray(bindings)
      ) {
        const bindingMap = bindings as Record<string, unknown>;
        const variables = [...path.matchAll(/\{([A-Za-z_][A-Za-z0-9_.-]*)\}/g)]
          .map((match) => match[1]!)
          .sort(compareText);
        const pathBindings = Object.entries(bindingMap)
          .filter(([, kind]) => kind === "path")
          .map(([name]) => name)
          .sort(compareText);
        if (variables.join("\0") !== pathBindings.join("\0"))
          diagnostics.push(
            diagnostic(
              "CAP_HTTP_PATH_VARIABLE_MISMATCH",
              "projection",
              "projection-http",
              "HTTP path variables must exactly match path-bound input properties.",
              overrideSource("/path"),
              projectedPath("/path"),
            ),
          );
        const propertySchemas =
          (inputSchema?.properties as Record<string, JsonSchema> | undefined) ??
          {};
        const required = new Set(
          Array.isArray(inputSchema?.required) ? inputSchema.required : [],
        );
        const headerNames = new Set<string>();
        for (const [name, kind] of Object.entries(bindingMap)) {
          if (kind === "header") {
            if (!configDependencies.includes("config:http-header-allowlist"))
              configDependencies.push("config:http-header-allowlist");
            const wireName = `X-Cap-Input-${name}`;
            const lower = wireName.toLowerCase();
            const reserved =
              reservedHttpHeader(name) ||
              name.toLowerCase().startsWith("x-cap-") ||
              reservedHttpHeader(wireName);
            if (
              reserved ||
              !httpHeaderToken.test(wireName) ||
              !config.httpHeaderAllowlist.includes(lower) ||
              headerNames.has(lower)
            )
              diagnostics.push(
                diagnostic(
                  reserved
                    ? "CAP_HTTP_HEADER_RESERVED"
                    : "CAP_HTTP_HEADER_FORBIDDEN",
                  "projection",
                  "projection-http",
                  "Header binding must use a unique allowlisted, non-reserved field-name token.",
                  overrideSource(`/bindings/${pointerToken(name)}`),
                  projectedPath(`/bindings/${pointerToken(name)}`),
                ),
              );
            headerNames.add(lower);
          }
          if (
            (kind === "path" || kind === "query" || kind === "header") &&
            (!Object.hasOwn(propertySchemas, name) ||
              !textualBindingEligible(
                propertySchemas[name]!,
                kind,
                required.has(name),
                sharedSchemas,
                inputSchemaResource(input, sharedSchemas)!.root,
              ))
          )
            diagnostics.push(
              diagnostic(
                "CAP_HTTP_BINDING_INELIGIBLE",
                "projection",
                "projection-http",
                "Input property schema is ineligible for this textual binding.",
                overrideSource(`/bindings/${pointerToken(name)}`),
                projectedPath(`/bindings/${pointerToken(name)}`),
              ),
            );
        }
      }
      if (
        (method === "GET" || method === "DELETE") &&
        Object.values((bindings ?? {}) as Record<string, unknown>).includes(
          "body",
        )
      )
        diagnostics.push(
          diagnostic(
            "CAP_HTTP_BODY_FORBIDDEN",
            "projection",
            "projection-http",
            "This HTTP method cannot carry body-bound input.",
            overrideSource("/bindings"),
            projectedPath("/bindings"),
          ),
        );
      if ((method === "GET" || method === "DELETE") && inputSchema === null)
        diagnostics.push(
          diagnostic(
            "CAP_HTTP_BINDING_INVALID",
            "projection",
            "projection-http",
            "Opaque input roots require the canonical JSON body carrier.",
            overrideSource("/bindings"),
            projectedPath("/bindings"),
          ),
        );
      if (overlapsReservedFrameworkRoute(method, path, config))
        diagnostics.push(
          diagnostic(
            "CAP_HTTP_ROUTE_COLLISION",
            "projection",
            "projection-collision",
            "HTTP route overlaps a reserved framework route.",
            overrideSource("/path"),
            projectedPath("/path"),
          ),
        );
      interfaces.http = {
        enabled: true,
        method,
        path,
        bindings: bindings as JsonValue,
      };
    } else if (surface === "cli") {
      const command =
        object.command === undefined ? id.split(".") : object.command;
      const bindingObject =
        object.bindings === undefined && properties
          ? Object.fromEntries(
              properties.map((key) => [
                key,
                { kind: "option", name: kebabProperty(key) },
              ]),
            )
          : (object.bindings ?? {});
      if (
        !Array.isArray(command) ||
        !command.length ||
        command.some(
          (entry) => typeof entry !== "string" || !cliCommandToken.test(entry),
        )
      )
        diagnostics.push(
          diagnostic(
            "CAP_CLI_BINDING_INVALID",
            "projection",
            "projection-cli",
            "CLI command must contain valid application-relative tokens.",
            overrideSource("/command"),
            projectedPath("/command"),
          ),
        );
      let validBindings =
        typeof bindingObject === "object" &&
        bindingObject !== null &&
        !Array.isArray(bindingObject);
      if (
        validBindings &&
        properties &&
        properties.join("\0") !==
          Object.keys(bindingObject).sort(compareText).join("\0")
      )
        validBindings = false;
      if (validBindings) {
        const names = new Set<string>();
        const negativeNames = new Set<string>();
        const positions = new Set<number>();
        for (const [property, binding] of Object.entries(
          bindingObject as Record<string, unknown>,
        )) {
          if (
            typeof binding !== "object" ||
            binding === null ||
            Array.isArray(binding)
          ) {
            validBindings = false;
            continue;
          }
          const item = binding as Record<string, unknown>;
          if (item.kind === "option") {
            if (
              typeof item.name !== "string" ||
              !/^--[a-z0-9][a-z0-9-]*$/.test(item.name) ||
              reservedCli.has(item.name) ||
              names.has(item.name)
            )
              validBindings = false;
            else {
              names.add(item.name);
              if (
                inputSchema &&
                directCliDefaultTrueBoolean(
                  (inputSchema.properties as Record<string, JsonSchema>)[
                    property
                  ],
                )
              )
                negativeNames.add(`--no-${item.name.slice(2)}`);
            }
          } else if (item.kind === "positional") {
            if (
              !Number.isSafeInteger(item.index) ||
              (item.index as number) < 0 ||
              positions.has(item.index as number)
            )
              validBindings = false;
            else positions.add(item.index as number);
          } else validBindings = false;
        }
        if (
          [...negativeNames].some(
            (name) => names.has(name) || reservedCli.has(name),
          )
        )
          validBindings = false;
      }
      if (!validBindings)
        diagnostics.push(
          diagnostic(
            "CAP_CLI_BINDING_INVALID",
            "projection",
            "projection-cli",
            "CLI bindings must completely and uniquely map stable input properties.",
            overrideSource("/bindings"),
            projectedPath("/bindings"),
          ),
        );
      interfaces.cli = {
        enabled: true,
        command: command as JsonValue,
        bindings: bindingObject as JsonValue,
      };
    } else if (surface === "mcp") {
      const explicitToolName = typeof object.toolName === "string";
      const toolName = explicitToolName
        ? (object.toolName as string)
        : id.replaceAll(".", "_");
      const validToolName = explicitToolName
        ? /^[a-z][a-z0-9_.-]{0,127}$/.test(toolName)
        : /^[a-z][a-z0-9_-]{0,127}$/.test(toolName);
      if (!validToolName)
        diagnostics.push(
          diagnostic(
            toolName.length > 128
              ? "CAP_MCP_TOOL_NAME_TOO_LONG"
              : "CAP_MCP_TOOL_NAME_INVALID",
            "projection",
            "projection-mcp",
            "MCP tool name is invalid.",
            overrideSource("/toolName"),
            projectedPath("/toolName"),
          ),
        );
      interfaces.mcp = { enabled: true, toolName };
    } else if (surface === "docs") {
      if (
        "group" in object &&
        (typeof object.group !== "string" || !object.group)
      )
        diagnostics.push(
          diagnostic(
            "CAP_CONFIG_PROJECTION_INVALID",
            "projection",
            "projection-docs",
            "Docs group must be a nonempty string.",
            overrideSource("/group"),
            projectedPath("/group"),
          ),
        );
      interfaces.docs = {
        enabled: true,
        ...(typeof object.group === "string" ? { group: object.group } : {}),
      };
    } else {
      const sdkPath = object.path === undefined ? id.split(".") : object.path;
      if (
        !Array.isArray(sdkPath) ||
        !sdkPath.length ||
        sdkPath.some((entry) => typeof entry !== "string" || !entry)
      )
        diagnostics.push(
          diagnostic(
            "CAP_CONFIG_PROJECTION_INVALID",
            "projection",
            "projection-sdk",
            "SDK path must contain nonempty string segments.",
            overrideSource("/path"),
            projectedPath("/path"),
          ),
        );
      interfaces.sdk = { enabled: true, path: sdkPath as JsonValue };
    }
    provenanceMap[`/interfaces/${surface}/enabled`] = provenance(
      overridden ? "projection-override" : "inferred",
      overrideSource(),
      overridden ? `${projectionBase}/${surface}` : undefined,
      overridden ? undefined : `capaxle:projection:${surface}-default@1`,
    );
    if (!overridden)
      diagnostics.push(
        info(
          `capaxle:projection:${surface}-default@1`,
          source,
          `/interfaces/${surface}`,
        ),
      );
  }
  const errors: Record<string, JsonValue> = {};
  const errorValidators = new Map<string, RuntimeValidator>();
  for (const [code, error] of Object.entries(descriptor.errors)) {
    const details = compiled[`${id}/errors/${code}/details`];
    errors[code] = {
      status: error.status,
      message: error.message,
      retryable: error.retryable,
      ...(details ? { details } : {}),
    } as JsonValue;
    const validator = useValidators.get(`${id}/errors/${code}/details`);
    if (validator) errorValidators.set(code, validator);
  }
  const secretRequirements = (descriptor.requirements?.secrets ?? [])
    .map((secret, authorIndex) => ({ secret, authorIndex }))
    .sort((left, right) => compareText(left.secret.name, right.secret.name));
  const ir: Record<string, JsonValue> = {
    id,
    version: descriptor.version ?? "1.0.0",
    summary: descriptor.summary,
    ...(descriptor.description === undefined
      ? {}
      : { description: descriptor.description }),
    tags: [...(descriptor.tags ?? [])],
    input,
    output: compiled[`${id}/output`]!,
    errors,
    access: {
      authentication: descriptor.authentication ?? "required",
      permissions:
        descriptor.permissions === "public"
          ? { public: true }
          : {
              ...(descriptor.permissions.allOf
                ? { allOf: [...descriptor.permissions.allOf] }
                : {}),
              ...(descriptor.permissions.anyOf
                ? { anyOf: [...descriptor.permissions.anyOf] }
                : {}),
            },
      exposure,
    },
    effects: {
      impact: descriptor.effects.impact,
      idempotency: descriptor.effects.idempotency,
      confirmation: descriptor.effects.confirmation,
      retry: { mode: descriptor.effects.retry.mode },
    },
    execution: { mode: "inline", result: "unary", cancellable: false },
    requirements: {
      secrets: secretRequirements.map(({ secret }) => ({ ...secret })),
      resources: [],
      environment: [],
    },
    limits: descriptor.limits?.rateLimit
      ? { rateLimit: { ...descriptor.limits.rateLimit } }
      : {},
    lifecycle: { status: "experimental" },
    interfaces,
    examples:
      descriptor.examples?.map((example) => ({
        name: example.name,
        ...(example.description === undefined
          ? {}
          : { description: example.description }),
        input: authoredExampleCopy(example.input),
        ...(example.output === undefined
          ? {}
          : { output: authoredExampleCopy(example.output) }),
        ...(example.error === undefined
          ? {}
          : {
              error: {
                code: example.error.code,
                ...(example.error.details === undefined
                  ? {}
                  : { details: authoredExampleCopy(example.error.details) }),
              },
            }),
      })) ?? [],
  };
  const compilerDefaults = [
    "/execution",
    "/requirements/resources",
    "/requirements/environment",
    ...(descriptor.requirements === undefined ? ["/requirements/secrets"] : []),
    ...(descriptor.limits?.rateLimit === undefined ? ["/limits"] : []),
    "/lifecycle",
    ...(descriptor.examples === undefined ? ["/examples"] : []),
  ];
  const presence = capabilityAuthoringPresence(descriptor);
  for (const pointer of leafPointers(ir)) {
    if (provenanceMap[pointer]) continue;
    if (pointer.startsWith("/interfaces/")) {
      const [, , surface, field] = pointer.split("/");
      const raw = override?.[surface as keyof ProjectionOverrides];
      if (
        raw &&
        typeof raw === "object" &&
        typeof field === "string" &&
        field !== "enabled" &&
        Object.prototype.hasOwnProperty.call(raw, field)
      ) {
        const sourcePath = `/projections/${pointerToken(id)}/${surface}${pointer.slice(
          `/interfaces/${surface}`.length,
        )}`;
        provenanceMap[pointer] = provenance(
          "projection-override",
          configSource(config, sourcePath),
          sourcePath,
        );
      } else
        provenanceMap[pointer] = provenance(
          "inferred",
          source,
          undefined,
          `capaxle:projection:${surface}-default@1`,
        );
    } else if (
      compilerDefaults.some(
        (prefix) => pointer === prefix || pointer.startsWith(`${prefix}/`),
      ) ||
      (pointer === "/tags" && descriptor.tags === undefined)
    )
      provenanceMap[pointer] = provenance(
        "compiler-default",
        source,
        undefined,
        `capaxle:default:${pointer.split("/")[1]}@1`,
      );
    else if (
      (pointer === "/limits/rateLimit/cost" &&
        presence?.rateLimitCost === false) ||
      (/^\/requirements\/secrets\/\d+\/optional$/.test(pointer) &&
        !presence?.secretOptional.includes(
          secretRequirements[Number(pointer.split("/")[3])]!.authorIndex,
        )) ||
      (pointer === "/effects/idempotency" &&
        presence?.effects.idempotency === false) ||
      (pointer === "/effects/confirmation" &&
        presence?.effects.confirmation === false) ||
      (pointer === "/effects/retry/mode" &&
        presence?.effects.retry === false) ||
      (/^\/errors\/[^/]+\/retryable$/.test(pointer) &&
        !presence?.errorRetryable.includes(
          pointer.split("/")[2]!.replaceAll("~1", "/").replaceAll("~0", "~"),
        ))
    )
      provenanceMap[pointer] = provenance(
        "compiler-default",
        source,
        undefined,
        `capaxle:default:${pointer.replace(/^\//, "").replaceAll("/", ":")}@1`,
      );
    else if (pointer === "/id" && descriptor.id === undefined)
      provenanceMap[pointer] = provenance(
        "inferred",
        source,
        undefined,
        "capaxle:capability-id:derived-path@1",
      );
    else {
      const sourcePath = pointer.startsWith("/requirements/secrets/")
        ? pointer.replace(
            /^\/requirements\/secrets\/\d+/,
            `/requirements/secrets/${secretRequirements[Number(pointer.split("/")[3])]!.authorIndex}`,
          )
        : pointer.startsWith("/input/")
          ? "/input"
          : pointer.startsWith("/output/")
            ? "/output"
            : pointer.startsWith("/access/permissions")
              ? pointer.replace("/access/permissions", "/permissions")
              : pointer.replace(/^(\/errors\/[^/]+\/details)(?:\/.*)?$/, "$1");
      provenanceMap[pointer] = provenance("author", source, sourcePath);
    }
  }
  return {
    ir,
    registry: {
      id,
      version: ir.version as string,
      summary: descriptor.summary,
      exposure,
      interfaces: interfaces as Readonly<Record<string, JsonValue>>,
      provenance: Object.freeze(provenanceMap),
    },
    validators: Object.freeze({
      input: useValidators.get(`${id}/input`)!,
      output: useValidators.get(`${id}/output`)!,
      errors: new ImmutableMap(errorValidators),
    }),
    source,
    sourceObject: descriptor,
    sourceHash: capability.sourceHash as Sha256,
    configDependencies: Object.freeze(
      [...new Set(configDependencies)].sort(compareText),
    ),
  };
}

function mapIrDiagnostic(
  item: Diagnostic,
  source: CompilationDiagnostic["source"],
): CompilationDiagnostic {
  const subphase: CompilationDiagnosticSubphase =
    item.code.includes("UNKNOWN_FIELD") ||
    item.code.includes("UNSUPPORTED") ||
    item.code.includes("FORBIDDEN")
      ? "ir-unsupported"
      : item.code.includes("VERSION") || item.code.includes("DUPLICATE")
        ? "ir-identity"
        : item.code.includes("SCHEMA") ||
            item.code.includes("REF_") ||
            item.code.includes("INPUT_ROOT") ||
            item.code.includes("DEFAULT") ||
            item.code.includes("EXAMPLE")
          ? "ir-schema"
          : item.code.includes("PROJECTION")
            ? "ir-projection"
            : item.code.includes("EFFECT") || item.code.includes("PERMISSIONS")
              ? "ir-policy"
              : item.code.includes("REQUIREMENT")
                ? "ir-execution"
                : item.code.includes("NORMALIZED")
                  ? "ir-normalization"
                  : "ir-structure";
  return diagnostic(
    item.code as `CAP_${string}`,
    "ir",
    subphase,
    item.message,
    source,
    item.path,
  );
}

function closestIrDiagnosticSource(
  item: Diagnostic,
  document: CapabilityDocument,
  resolved: readonly ResolvedCapability[],
  config: ResolvedCompilerConfig,
  fallback: CompilationDiagnostic["source"],
): CompilationDiagnostic["source"] {
  if (item.path === "/service" || item.path.startsWith("/service/"))
    return configSource(config, item.path);
  const match = /^\/capabilities\/(0|[1-9]\d*)(\/.*)?$/.exec(item.path);
  if (!match) return fallback;
  const capability = document.capabilities[Number(match[1])];
  const resolvedCapability = capability
    ? resolved.find((entry) => entry.registry.id === capability.id)
    : undefined;
  if (!resolvedCapability) return fallback;
  let pointer = match[2] ?? "";
  while (pointer) {
    const entry = resolvedCapability.registry.provenance[pointer];
    if (entry) return entry.source;
    pointer = pointer.slice(0, pointer.lastIndexOf("/"));
  }
  return resolvedCapability.source;
}

function collisionDiagnostics(
  resolved: readonly ResolvedCapability[],
  diagnostics: CompilationDiagnostic[],
): void {
  const projection = (
    item: ResolvedCapability,
    name: string,
  ): Record<string, JsonValue> => {
    const interfaces = item.ir.interfaces;
    if (
      typeof interfaces !== "object" ||
      interfaces === null ||
      Array.isArray(interfaces)
    )
      return {};
    const value = (interfaces as Record<string, JsonValue>)[name];
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? (value as Record<string, JsonValue>)
      : {};
  };
  const checks: Array<
    [
      string,
      `CAP_${string}`,
      CompilationDiagnosticSubphase,
      (item: ResolvedCapability) => string | undefined,
    ]
  > = [
    [
      "HTTP route",
      "CAP_HTTP_ROUTE_COLLISION",
      "projection-collision",
      (item) => {
        const value = projection(item, "http");
        return value.enabled === true &&
          typeof value.method === "string" &&
          typeof value.path === "string"
          ? `${value.method} ${value.path.replace(/\{[^}]+\}/g, "{}")}`
          : undefined;
      },
    ],
    [
      "MCP tool name",
      "CAP_MCP_TOOL_NAME_COLLISION",
      "projection-collision",
      (item) => {
        const value = projection(item, "mcp");
        return value.enabled === true && typeof value.toolName === "string"
          ? value.toolName
          : undefined;
      },
    ],
    [
      "SDK path",
      "CAP_SDK_PATH_COLLISION",
      "projection-collision",
      (item) => {
        const value = projection(item, "sdk");
        return value.enabled === true &&
          Array.isArray(value.path) &&
          value.path.every((entry) => typeof entry === "string")
          ? value.path.join("\0")
          : undefined;
      },
    ],
  ];
  for (const [label, code, subphase, key] of checks) {
    const seen = new Map<string, ResolvedCapability>();
    for (const item of resolved) {
      const value = key(item);
      if (value === undefined) continue;
      const prior = seen.get(value);
      if (prior)
        diagnostics.push(
          diagnostic(
            code,
            "projection",
            subphase,
            `${label} collides with another capability.`,
            item.source,
            "/interfaces",
          ),
        );
      else seen.set(value, item);
    }
  }
  const enabledCli = resolved.flatMap((item) => {
    const value = projection(item, "cli");
    return value.enabled === true &&
      Array.isArray(value.command) &&
      value.command.length > 0 &&
      value.command.every(
        (entry) => typeof entry === "string" && cliCommandToken.test(entry),
      )
      ? [{ item, command: value.command as string[] }]
      : [];
  });
  const commandIsPrefix = (
    prefix: readonly string[],
    command: readonly string[],
  ): boolean =>
    prefix.length <= command.length &&
    prefix.every((segment, index) => segment === command[index]);
  for (const entry of enabledCli) {
    if (entry.command[0] === "capabilities")
      diagnostics.push(
        diagnostic(
          "CAP_CLI_COMMAND_COLLISION",
          "projection",
          "projection-collision",
          "CLI command collides with the reserved capabilities discovery namespace.",
          entry.item.source,
          "/interfaces",
        ),
      );
  }
  for (let left = 0; left < enabledCli.length; left++)
    for (let right = left + 1; right < enabledCli.length; right++) {
      const a = enabledCli[left]!;
      const b = enabledCli[right]!;
      if (
        commandIsPrefix(a.command, b.command) ||
        commandIsPrefix(b.command, a.command)
      )
        diagnostics.push(
          diagnostic(
            "CAP_CLI_COMMAND_COLLISION",
            "projection",
            "projection-collision",
            "CLI command collides with another capability.",
            b.item.source,
            "/interfaces",
          ),
        );
    }
  const enabledHttp = resolved.filter(
    (item) => projection(item, "http").enabled === true,
  );
  for (let left = 0; left < enabledHttp.length; left++)
    for (let right = left + 1; right < enabledHttp.length; right++) {
      const a = projection(enabledHttp[left]!, "http");
      const b = projection(enabledHttp[right]!, "http");
      const overlaps =
        typeof a.method === "string" &&
        a.method === b.method &&
        typeof a.path === "string" &&
        typeof b.path === "string" &&
        httpPathsOverlap(a.path, b.path);
      if (overlaps)
        diagnostics.push(
          diagnostic(
            "CAP_HTTP_ROUTE_COLLISION",
            "projection",
            "projection-collision",
            "HTTP route overlaps another capability.",
            enabledHttp[right]!.source,
            "/interfaces/http/path",
          ),
        );
    }
}

interface CacheEntry {
  readonly input: Sha256;
  readonly output: Sha256;
  readonly bytes: Uint8Array;
  readonly warnings?: readonly CompilationDiagnostic[];
}
type Cache = Map<string, CacheEntry>;
interface NodeDraft {
  id: string;
  dependencies: string[];
  output?: Uint8Array;
  input?: Sha256;
  failure?: `CAP_${string}`[];
  blocked?: string[];
  executed?: boolean;
}

function nodeInputFingerprint(
  id: string,
  transform: string,
  localInputs: JsonValue,
  dependencies: readonly string[],
  drafts: readonly NodeDraft[],
): Sha256 {
  return sha(
    jcs({
      dependencies: [...dependencies].sort(compareText).map((dependencyId) => ({
        id: dependencyId,
        outputDigest: sha(
          drafts.find((candidate) => candidate.id === dependencyId)?.output ??
            "",
        ),
      })),
      kind: id.slice(0, id.indexOf(":")),
      localInputs,
      transform,
    }),
  );
}

function graphReport(
  generation: number,
  drafts: readonly NodeDraft[],
  previous: Cache | undefined,
): CompilerGraphReport {
  const currentIds = new Set(drafts.map((node) => node.id));
  const nodes: CompilerGraphNodeReport[] = [];
  const invalidated: string[] = [],
    executed: string[] = [],
    changed: string[] = [],
    failed: string[] = [],
    blocked: string[] = [],
    reused: string[] = [];
  for (const draft of [...drafts].sort((a, b) => compareText(a.id, b.id))) {
    if (draft.blocked?.length) {
      blocked.push(draft.id);
      nodes.push(
        Object.freeze({
          id: draft.id,
          dependencies: Object.freeze(
            [...draft.dependencies].sort(compareText),
          ),
          status: "blocked",
          blockedByNodeIds: Object.freeze([...draft.blocked].sort(compareText)),
        }),
      );
      continue;
    }
    if (draft.failure?.length) {
      failed.push(draft.id);
      if (draft.executed) executed.push(draft.id);
      invalidated.push(draft.id);
      nodes.push(
        Object.freeze({
          id: draft.id,
          dependencies: Object.freeze(
            [...draft.dependencies].sort(compareText),
          ),
          status: "failed",
          ...(draft.input ? { inputFingerprint: draft.input } : {}),
          failureDiagnosticCodes: Object.freeze(
            [...new Set(draft.failure)].sort(compareText),
          ),
        }),
      );
      continue;
    }
    const output = sha(draft.output!);
    const input =
      draft.input ??
      sha(
        jcs({
          dependencies: [...draft.dependencies].sort(compareText).map((id) => ({
            id,
            outputDigest: sha(
              drafts.find((candidate) => candidate.id === id)?.output ?? "",
            ),
          })),
          id: draft.id,
        }),
      );
    const old = previous?.get(draft.id);
    if (
      old &&
      old.input === input &&
      old.output === output &&
      !draft.executed
    ) {
      reused.push(draft.id);
      nodes.push(
        Object.freeze({
          id: draft.id,
          dependencies: Object.freeze(
            [...draft.dependencies].sort(compareText),
          ),
          status: "reused",
          inputFingerprint: input,
          outputDigest: output,
        }),
      );
    } else {
      invalidated.push(draft.id);
      executed.push(draft.id);
      if (!old || old.output !== output) changed.push(draft.id);
      nodes.push(
        Object.freeze({
          id: draft.id,
          dependencies: Object.freeze(
            [...draft.dependencies].sort(compareText),
          ),
          status: "succeeded",
          inputFingerprint: input,
          outputDigest: output,
        }),
      );
    }
  }
  const removed = previous
    ? [...previous.keys()].filter((id) => !currentIds.has(id)).sort(compareText)
    : [];
  const freezeSort = (items: string[]) =>
    Object.freeze([...new Set(items)].sort(compareText));
  return Object.freeze({
    generation,
    nodes: Object.freeze(nodes),
    invalidatedNodeIds: freezeSort(invalidated),
    executedNodeIds: freezeSort(executed),
    changedNodeIds: freezeSort(changed),
    failedNodeIds: freezeSort(failed),
    blockedNodeIds: freezeSort(blocked),
    removedNodeIds: Object.freeze(removed),
    reusedNodeIds: freezeSort(reused),
  });
}

function artifact(
  id: string,
  path: string,
  mediaType: string,
  target: string,
  producer: { id: string; version: string },
  content: Uint8Array,
): CompiledArtifact {
  const copy = new Uint8Array(content);
  const value: Record<string, unknown> = {
    id,
    path,
    mediaType,
    target,
    producer: Object.freeze({ ...producer }),
    sha256: sha(copy),
  };
  Object.defineProperty(value, "bytes", {
    enumerable: true,
    get: () => new Uint8Array(copy),
  });
  return Object.freeze(value) as unknown as CompiledArtifact;
}

function validateProducers(
  producers: unknown,
  diagnostics: CompilationDiagnostic[],
): readonly CompilerArtifactProducer[] {
  const accepted: CompilerArtifactProducer[] = [];
  const invalid = (message: string): void => {
    diagnostics.push(
      diagnostic("CAP_GRAPH_NODE_INVALID", "graph", "graph-input", message),
    );
  };
  const producerValues = denseArrayValues(producers);
  if (!producerValues) {
    invalid("Artifact producer registrations must be an array.");
    return Object.freeze(accepted);
  }
  const ids = new Set([
    "capaxle.ir",
    "capaxle.compiler-registry",
    "capaxle.artifact-index",
  ]);
  const paths = new Set([
    "capabilities.ir.json",
    "capabilities.registry.json",
    "artifacts.json",
  ]);
  const producerIds = new Set<string>();
  let rootPublicationRegistered = false;
  for (const candidate of producerValues) {
    try {
      const raw = plainDataRecord(candidate);
      if (!raw) {
        invalid("Artifact producer registration is invalid.");
        continue;
      }
      const id = raw.id;
      const version = raw.version;
      let valid = true;
      if (
        typeof id !== "string" ||
        !artifactToken.test(id) ||
        typeof version !== "string" ||
        !semver.test(version) ||
        producerIds.has(id)
      ) {
        invalid("Artifact producer registration is invalid.");
        valid = false;
      }
      if (typeof id === "string") producerIds.add(id);

      const staticInputs = portableCopy(
        Object.hasOwn(raw, "staticInputs") ? raw.staticInputs : {},
      );
      const staticInputObject =
        staticInputs.ok &&
        typeof staticInputs.value === "object" &&
        staticInputs.value !== null &&
        !Array.isArray(staticInputs.value);
      if (!staticInputObject) {
        invalid("Artifact producer static inputs must be portable JSON data.");
        valid = false;
      }

      const declarations: Array<{
        readonly code: `CAP_${string}`;
        readonly severities: readonly ("warning" | "error")[];
      }> = [];
      const rawDeclarations = raw.diagnosticCodes;
      const declarationValues = denseArrayValues(rawDeclarations);
      if (!declarationValues) {
        invalid("Artifact producer diagnostic declarations must be an array.");
        valid = false;
      } else {
        let previousCode: string | undefined;
        for (const candidateDeclaration of declarationValues) {
          const declaration = plainDataRecord(candidateDeclaration);
          const code = declaration?.code;
          const severities = declaration?.severities;
          const severityValues = denseArrayValues(severities);
          const severityOrderValid =
            severityValues !== undefined &&
            (severityValues.length === 1
              ? severityValues[0] === "warning" || severityValues[0] === "error"
              : severityValues.length === 2 &&
                severityValues[0] === "warning" &&
                severityValues[1] === "error");
          if (
            typeof code !== "string" ||
            !/^CAP_[A-Z0-9_]+$/.test(code) ||
            (previousCode !== undefined &&
              compareText(previousCode, code) >= 0) ||
            !severityOrderValid
          ) {
            invalid("Artifact producer diagnostic declaration is invalid.");
            valid = false;
          } else {
            declarations.push(
              Object.freeze({
                code: code as `CAP_${string}`,
                severities: Object.freeze([
                  ...(severityValues as ("warning" | "error")[]),
                ]),
              }),
            );
          }
          if (typeof code === "string") previousCode = code;
        }
      }

      const artifacts: CompilerArtifactProducer["artifacts"][number][] = [];
      const rawArtifacts = raw.artifacts;
      const artifactValues = denseArrayValues(rawArtifacts);
      if (!artifactValues) {
        invalid("Artifact producer artifacts must be an array.");
        valid = false;
      } else
        for (const candidateArtifact of artifactValues) {
          const item = plainDataRecord(candidateArtifact);
          if (!item) {
            invalid("Artifact descriptor is invalid.");
            valid = false;
            continue;
          }
          const artifactId = item.id;
          const path = item.path;
          const mediaType = item.mediaType;
          const target = item.target;
          const dependencies = item.dependencies;
          const produce = item.produce;
          let artifactValid = true;
          if (
            typeof artifactId !== "string" ||
            !artifactToken.test(artifactId) ||
            ids.has(artifactId)
          ) {
            diagnostics.push(
              diagnostic(
                "CAP_ARTIFACT_ID_COLLISION",
                "graph",
                "graph-input",
                "Public artifact ID is invalid or duplicated.",
                PROJECT_SOURCE,
                "/artifactProducers",
              ),
            );
            artifactValid = false;
          }
          if (typeof artifactId === "string") ids.add(artifactId);
          if (
            typeof path !== "string" ||
            [...paths].some(
              (entry) =>
                entry === path ||
                entry.startsWith(`${path}/`) ||
                path.startsWith(`${entry}/`),
            )
          ) {
            diagnostics.push(
              diagnostic(
                "CAP_ARTIFACT_PATH_COLLISION",
                "graph",
                "graph-input",
                "Public artifact path is duplicated.",
                PROJECT_SOURCE,
                "/artifactProducers",
              ),
            );
            artifactValid = false;
          }
          if (typeof path === "string") paths.add(path);
          if (typeof path !== "string" || !validArtifactPath(path)) {
            invalid("Artifact path must be a normalized relative POSIX path.");
            artifactValid = false;
          }
          if (
            typeof mediaType !== "string" ||
            mediaType.length === 0 ||
            !validIJsonString(mediaType)
          ) {
            invalid("Artifact media type is invalid.");
            artifactValid = false;
          }
          if (
            typeof target !== "string" ||
            !/^[A-Za-z0-9][!-~]{0,255}$/.test(target)
          ) {
            invalid("Artifact target is invalid.");
            artifactValid = false;
          }
          const dependencyIds = new Set<string>();
          const dependencyValues = denseArrayValues(dependencies);
          if (!dependencyValues) {
            invalid("Artifact dependencies must be an array.");
            artifactValid = false;
          } else
            for (const dependency of dependencyValues) {
              if (
                typeof dependency !== "string" ||
                dependencyIds.has(dependency) ||
                dependency === `artifact:${artifactId}` ||
                dependency === "artifact:capaxle.artifact-index" ||
                !/^(?:document:capability-ir|capability:.+|schema:.+|artifact:.+)$/.test(
                  dependency,
                )
              ) {
                invalid("Artifact dependency declaration is invalid.");
                artifactValid = false;
              }
              if (typeof dependency === "string") dependencyIds.add(dependency);
            }
          if (typeof produce !== "function") {
            invalid("Artifact producer callback is invalid.");
            artifactValid = false;
          }
          valid &&= artifactValid;
          if (artifactValid)
            artifacts.push(
              Object.freeze({
                id: artifactId as string,
                path: path as string,
                mediaType: mediaType as string,
                target: target as string,
                dependencies: Object.freeze(
                  [...(dependencyValues as ProducerDependencyId[])].sort(
                    compareText,
                  ),
                ),
                produce:
                  produce as CompilerArtifactProducer["artifacts"][number]["produce"],
              }),
            );
        }

      let rootPublication: CompilerRootPublication | undefined;
      if (Object.hasOwn(raw, "rootPublication")) {
        const publication = plainDataRecord(raw.rootPublication);
        const publicationKeys = publication
          ? Object.keys(publication).sort()
          : [];
        const assembler = publication?.assemble;
        const structurallyValid = Boolean(
          publication &&
          publicationKeys.length === 4 &&
          publicationKeys[0] === "assemble" &&
          publicationKeys[1] === "legacyPath" &&
          publicationKeys[2] === "payloadArtifactId" &&
          publicationKeys[3] === "rootPath" &&
          publication.payloadArtifactId === "capaxle.agent-manifest" &&
          publication.rootPath === "capaxle.manifest.json" &&
          publication.legacyPath === "capabuild.manifest.json" &&
          typeof assembler === "function" &&
          artifacts.some(
            (item) =>
              item.id === publication.payloadArtifactId &&
              item.path === "agent-manifest.json" &&
              item.mediaType === "application/json" &&
              (item.target === "capaxle:agent-manifest@0.1" ||
                item.target === "capaxle:agent-manifest@0.2"),
          ),
        );
        if (!structurallyValid || rootPublicationRegistered) {
          invalid(
            rootPublicationRegistered
              ? "Only one root publication registration is permitted."
              : "Root publication registration is invalid.",
          );
          valid = false;
        } else {
          rootPublicationRegistered = true;
          rootPublication = Object.freeze({
            payloadArtifactId: publication!.payloadArtifactId as string,
            rootPath: publication!.rootPath as string,
            legacyPath: publication!.legacyPath as string,
            assemble: assembler as CompilerRootPublication["assemble"],
          });
        }
      }

      if (
        valid &&
        typeof id === "string" &&
        typeof version === "string" &&
        staticInputObject
      )
        accepted.push(
          Object.freeze({
            id,
            version,
            staticInputs: deepFreeze(
              staticInputs.value as Record<string, JsonValue>,
            ),
            diagnosticCodes: Object.freeze(declarations),
            artifacts: Object.freeze(artifacts),
            ...(rootPublication ? { rootPublication } : {}),
          }),
        );
    } catch {
      invalid("Artifact producer registration is invalid.");
    }
  }
  return Object.freeze(accepted);
}
function validArtifactPath(path: string): boolean {
  return (
    path.length > 0 &&
    validIJsonString(path) &&
    !path.startsWith("/") &&
    !path.includes("\\") &&
    !path.includes("\0") &&
    path.split("/").every((part) => part && part !== "." && part !== "..") &&
    path !== "artifacts.json" &&
    path !== "capabilities.ir.json" &&
    path !== "capabilities.registry.json"
  );
}

type ValidatedProducerResult =
  | {
      readonly ok: true;
      readonly bytes: Uint8Array;
      readonly diagnostics: readonly ArtifactProducerDiagnostic[];
    }
  | {
      readonly ok: false;
      readonly diagnostics: readonly ArtifactProducerDiagnostic[];
    };

function validatedProducerResult(
  value: unknown,
  target: string,
  declared: ReadonlyMap<string, ReadonlySet<string>>,
  capabilitySources: ReadonlyMap<
    string,
    Pick<ResolvedCapability, "sourceObject" | "ir">
  >,
): ValidatedProducerResult | undefined {
  const result = plainDataRecord(value);
  if (!result || typeof result.ok !== "boolean") return undefined;
  const expectedKeys = result.ok
    ? new Set(["ok", "bytes", "diagnostics"])
    : new Set(["ok", "diagnostics"]);
  const keys = Object.keys(result);
  if (
    keys.length !== expectedKeys.size ||
    keys.some((key) => !expectedKeys.has(key))
  )
    return undefined;
  const diagnosticValues = denseArrayValues(result.diagnostics);
  if (!diagnosticValues) return undefined;
  const diagnostics: ArtifactProducerDiagnostic[] = [];
  for (const value of diagnosticValues) {
    const item = plainDataRecord(value);
    if (!item) return undefined;
    const allowed = new Set([
      "code",
      "severity",
      "message",
      "target",
      "capabilityId",
      "path",
      "details",
    ]);
    const itemKeys = Object.keys(item);
    if (
      !["code", "severity", "message", "target"].every((key) =>
        Object.hasOwn(item, key),
      ) ||
      itemKeys.some((key) => !allowed.has(key))
    )
      return undefined;
    const { code, severity, message, capabilityId, path } = item;
    if (
      typeof code !== "string" ||
      !/^CAP_[A-Z0-9_]+$/.test(code) ||
      (severity !== "warning" && severity !== "error") ||
      !declared.get(code)?.has(severity) ||
      item.target !== target ||
      typeof message !== "string" ||
      !validIJsonString(message) ||
      (capabilityId !== undefined &&
        (typeof capabilityId !== "string" ||
          !capabilitySources.has(capabilityId))) ||
      (path !== undefined &&
        (typeof path !== "string" ||
          !validJsonPointer(path) ||
          (typeof capabilityId === "string" &&
            !pointerExists(
              capabilitySources.get(capabilityId)?.sourceObject,
              path,
            ) &&
            !pointerExists(capabilitySources.get(capabilityId)?.ir, path))))
    )
      return undefined;
    const copiedDetails = Object.hasOwn(item, "details")
      ? portableCopy(item.details)
      : undefined;
    if (copiedDetails && !copiedDetails.ok) return undefined;
    diagnostics.push(
      deepFreeze({
        code: code as `CAP_${string}`,
        severity,
        message,
        target,
        ...(capabilityId === undefined ? {} : { capabilityId }),
        ...(path === undefined ? {} : { path }),
        ...(copiedDetails?.ok ? { details: copiedDetails.value } : {}),
      }),
    );
  }
  if (
    (result.ok && diagnostics.some((item) => item.severity !== "warning")) ||
    (!result.ok && !diagnostics.some((item) => item.severity === "error"))
  )
    return undefined;
  if (!result.ok) return Object.freeze({ ok: false, diagnostics });
  if (!types.isUint8Array(result.bytes) || types.isProxy(result.bytes))
    return undefined;
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(result.bytes as Uint8Array);
  } catch {
    return undefined;
  }
  return Object.freeze({
    ok: true,
    bytes,
    diagnostics: Object.freeze(diagnostics),
  });
}

interface ProjectSource {
  readonly path: string;
  readonly sourceHash: Sha256;
  readonly imports: readonly string[];
  readonly importsPackage: boolean;
  readonly unavailable?: true;
  readonly packageImports: readonly {
    readonly specifier: string;
    readonly source: CompilationDiagnostic["source"];
  }[];
}

async function projectSourcesFromTrace(
  trace: ModuleLoadTrace,
  packageImports: readonly ModulePackageImport[],
  projectRoot: string,
  diagnostics: CompilationDiagnostic[],
): Promise<ReadonlyMap<string, ProjectSource>> {
  const importsByPath = new Map<string, Set<string>>();
  for (const module of trace.modules) importsByPath.set(module.path, new Set());
  for (const edge of trace.edges)
    importsByPath.get(edge.importer)?.add(edge.target);
  const packagesByPath = new Map<
    string,
    Array<{
      readonly specifier: string;
      readonly source: CompilationDiagnostic["source"];
    }>
  >();
  for (const item of packageImports) {
    const packages = packagesByPath.get(item.importer) ?? [];
    packages.push({
      specifier: item.specifier,
      source: { file: item.importer, line: 1, column: 1 },
    });
    packagesByPath.set(item.importer, packages);
  }
  return new Map(
    await Promise.all(
      trace.modules.map(async (module) => {
        const packages = packagesByPath.get(module.path) ?? [];
        let unavailable = false;
        try {
          unavailable =
            sha(await readFile(resolve(projectRoot, module.path))) !==
            module.sha256;
        } catch {
          unavailable = true;
        }
        if (unavailable)
          diagnostics.push(
            diagnostic(
              "CAP_GRAPH_NODE_INVALID",
              "graph",
              "graph-input",
              "A loaded project source could not be fingerprinted.",
              { file: module.path, line: 1, column: 1 },
            ),
          );
        return [
          module.path,
          Object.freeze({
            path: module.path,
            sourceHash: module.sha256,
            imports: Object.freeze(
              [...(importsByPath.get(module.path) ?? [])].sort(compareText),
            ),
            importsPackage: packages.length > 0,
            packageImports: Object.freeze(packages),
            ...(unavailable ? { unavailable: true as const } : {}),
          }),
        ] as const;
      }),
    ),
  );
}

function moduleFailureDrafts(
  sourceFile: string,
  code: `CAP_${string}`,
): readonly NodeDraft[] {
  if (sourceFile === "." || sourceFile === "capaxle.config.ts")
    return [
      {
        id: "config:service",
        dependencies: [],
        failure: [code],
      },
    ];
  const moduleId = `module:${encode(sourceFile)}`;
  const match = /^src\/capabilities\/(.+)\.(?:ts|mts|js|mjs)$/.exec(sourceFile);
  if (!match)
    return [
      { id: moduleId, dependencies: [], failure: [code] },
      {
        id: "source:manifest",
        dependencies: [moduleId],
        blocked: [moduleId],
      },
    ];
  const capability = match[1]!.split("/").join(".");
  const input = `schema:${encode(capability)}/input`;
  const output = `schema:${encode(capability)}/output`;
  const capabilityId = `capability:${capability}`;
  const provenance = `provenance:${capability}`;
  return [
    { id: moduleId, dependencies: [], failure: [code] },
    {
      id: "source:manifest",
      dependencies: [moduleId],
      blocked: [moduleId],
    },
    { id: input, dependencies: [moduleId], blocked: [moduleId] },
    { id: output, dependencies: [moduleId], blocked: [moduleId] },
    {
      id: capabilityId,
      dependencies: [moduleId, input, output],
      blocked: [moduleId, input, output],
    },
    {
      id: provenance,
      dependencies: [capabilityId, moduleId],
      blocked: [capabilityId, moduleId],
    },
    {
      id: "document:capability-ir",
      dependencies: [capabilityId, "source:manifest"],
      blocked: [capabilityId, "source:manifest"],
    },
    {
      id: "artifact:capaxle.ir",
      dependencies: ["document:capability-ir"],
      blocked: ["document:capability-ir"],
    },
    {
      id: "artifact:capaxle.compiler-registry",
      dependencies: [capabilityId, provenance],
      blocked: [capabilityId, provenance],
    },
    {
      id: "artifact:capaxle.artifact-index",
      dependencies: [
        "artifact:capaxle.compiler-registry",
        "artifact:capaxle.ir",
      ],
      blocked: ["artifact:capaxle.compiler-registry", "artifact:capaxle.ir"],
    },
  ];
}

function loaderFailureDrafts(
  error: ModuleGraphLoadError,
): readonly NodeDraft[] {
  return moduleFailureDrafts(error.sourceFile, error.code);
}

function tracedModuleFailureDrafts(
  trace: ModuleLoadTrace,
  sourceFile: string,
  code: `CAP_${string}`,
): readonly NodeDraft[] {
  const failedId = `module:${encode(sourceFile)}`;
  const dependencies = new Map<string, string[]>();
  for (const module of trace.modules) dependencies.set(module.path, []);
  for (const edge of trace.edges)
    dependencies.get(edge.importer)?.push(`module:${encode(edge.target)}`);
  const moduleDrafts: NodeDraft[] = trace.modules.map((module) => {
    const id = `module:${encode(module.path)}`;
    const moduleDependencies = [
      ...new Set(dependencies.get(module.path) ?? []),
    ].sort(compareText);
    return id === failedId
      ? {
          id,
          dependencies: moduleDependencies,
          failure: [code],
          executed: true,
        }
      : {
          id,
          dependencies: moduleDependencies,
          output: bytes({
            sourceHash: module.sha256,
            imports: moduleDependencies,
          }),
          executed: true,
        };
  });
  if (!moduleDrafts.some(({ id }) => id === failedId))
    moduleDrafts.push({
      id: failedId,
      dependencies: [],
      failure: [code],
      executed: true,
    });
  const downstream = moduleFailureDrafts(sourceFile, code).filter(
    ({ id }) => id !== failedId,
  );
  const sourceManifest = downstream.find(({ id }) => id === "source:manifest");
  if (sourceManifest) {
    sourceManifest.dependencies = moduleDrafts.map(({ id }) => id);
    sourceManifest.blocked = [failedId];
  }
  return [...moduleDrafts, ...downstream];
}

interface SchemaProviderValidation {
  readonly providers: readonly SchemaProvider<unknown>[];
  readonly ids: readonly string[];
  readonly diagnostics: readonly CompilationDiagnostic[];
}

class ProviderDiagnosticsError extends Error {
  readonly diagnostics: readonly Diagnostic[];

  constructor(diagnostics: readonly Diagnostic[]) {
    super("Schema provider reported portability diagnostics.");
    this.name = "ProviderDiagnosticsError";
    this.diagnostics = diagnostics;
  }
}

function copyProviderDiagnostics(
  value: unknown,
  root: string,
): readonly Diagnostic[] | undefined {
  const entries = denseArrayValues(value);
  if (!entries) return undefined;
  const diagnostics: Diagnostic[] = [];
  for (const entry of entries) {
    const item = plainDataRecord(entry);
    if (!item || Object.keys(item).length !== 4) return undefined;
    const { code, severity, path, message } = item;
    if (
      typeof code !== "string" ||
      !/^CAP_[A-Z0-9_]+$/.test(code) ||
      severity !== "error" ||
      typeof path !== "string" ||
      !validJsonPointer(path) ||
      (path !== root && !path.startsWith(`${root}/`)) ||
      typeof message !== "string" ||
      !validIJsonString(message)
    )
      return undefined;
    diagnostics.push(Object.freeze({ code, severity, path, message }));
  }
  return Object.freeze(diagnostics);
}

function copyThrownProviderDiagnostics(
  error: unknown,
  root: string,
): readonly Diagnostic[] | undefined {
  try {
    if (typeof error !== "object" || error === null || types.isProxy(error))
      return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(error, "diagnostics");
    if (!descriptor || !("value" in descriptor)) return undefined;
    return copyProviderDiagnostics(descriptor.value, root);
  } catch {
    return undefined;
  }
}

function validateSchemaProviders(
  options: CompilerOptions,
): SchemaProviderValidation {
  const providers: SchemaProvider<unknown>[] = [];
  const diagnostics: CompilationDiagnostic[] = [];
  const ids = new Set<string>();
  const invalid = (): void => {
    diagnostics.push(
      diagnostic(
        "CAP_SCHEMA_PROVIDER_FAILED",
        "schema",
        "schema-provider",
        "Schema provider registration is invalid.",
      ),
    );
  };
  try {
    const candidates: unknown = options.schemaProviders;
    if (!Array.isArray(candidates)) {
      invalid();
      return {
        providers: Object.freeze(providers),
        ids: Object.freeze([]),
        diagnostics: sortCompilationDiagnostics(diagnostics),
      };
    }
    for (const candidate of candidates) {
      try {
        if (
          typeof candidate !== "object" ||
          candidate === null ||
          Array.isArray(candidate) ||
          types.isProxy(candidate)
        ) {
          invalid();
          continue;
        }
        const raw = candidate as Record<string, unknown>;
        const id = raw.id;
        const canHandle = raw.canHandle;
        const portabilityDiagnostics = raw.portabilityDiagnostics;
        const toJsonSchema = raw.toJsonSchema;
        const createValidator = raw.createValidator;
        if (
          typeof id !== "string" ||
          id.length === 0 ||
          !validIJsonString(id) ||
          ids.has(id) ||
          typeof canHandle !== "function" ||
          typeof portabilityDiagnostics !== "function" ||
          typeof toJsonSchema !== "function" ||
          typeof createValidator !== "function"
        ) {
          invalid();
          if (typeof id === "string" && id.length > 0 && validIJsonString(id))
            ids.add(id);
          continue;
        }
        ids.add(id);
        const provider: SchemaProvider<unknown> = {
          id,
          canHandle(value): value is unknown {
            try {
              const result = Reflect.apply(canHandle, candidate, [value]);
              if (typeof result !== "boolean") throw new Error();
              return result;
            } catch {
              throw new Error("Schema provider callback failed.");
            }
          },
          portabilityDiagnostics(value, context) {
            try {
              const result = Reflect.apply(portabilityDiagnostics, candidate, [
                value,
                context,
              ]);
              const copied = copyProviderDiagnostics(result, context.path);
              if (!copied) throw new Error();
              return copied;
            } catch {
              throw new Error("Schema provider callback failed.");
            }
          },
          toJsonSchema(value, context) {
            try {
              const result = portableCopy(
                Reflect.apply(toJsonSchema, candidate, [value, context]),
              );
              if (
                !result.ok ||
                typeof result.value !== "object" ||
                result.value === null ||
                Array.isArray(result.value)
              )
                throw new Error();
              return deepFreeze(result.value) as JsonSchema;
            } catch (error) {
              const providerDiagnostics = copyThrownProviderDiagnostics(
                error,
                context.path,
              );
              if (providerDiagnostics)
                throw new ProviderDiagnosticsError(providerDiagnostics);
              throw new Error("Schema provider callback failed.");
            }
          },
          createValidator(value) {
            try {
              const result = safeRuntimeValidator(
                Reflect.apply(createValidator, candidate, [value]),
              );
              if (!result) throw new Error();
              return result;
            } catch {
              throw new Error("Schema provider callback failed.");
            }
          },
        };
        providers.push(Object.freeze(provider));
      } catch {
        invalid();
      }
    }
  } catch {
    invalid();
  }
  return {
    providers: Object.freeze(providers),
    ids: Object.freeze([...ids].sort(compareText)),
    diagnostics: sortCompilationDiagnostics(diagnostics),
  };
}

function safeRuntimeValidator(value: unknown): RuntimeValidator | undefined {
  try {
    if (
      typeof value !== "object" ||
      value === null ||
      types.isProxy(value) ||
      typeof (value as { readonly validate?: unknown }).validate !== "function"
    )
      return undefined;
    const validate = (value as RuntimeValidator).validate;
    return Object.freeze({ validate: validate.bind(value) });
  } catch {
    return undefined;
  }
}

function safeSchemaBatch(
  providers: readonly SchemaProvider<unknown>[],
  uses: readonly CompilerSchemaUse[],
  source: CompilationDiagnostic["source"],
  path: string,
  diagnostics: CompilationDiagnostic[],
):
  | (SchemaBatchCompilationResult & {
      readonly occurrenceEvidence: readonly SchemaOccurrenceEvidence[];
    })
  | undefined {
  try {
    const result = compileAuthenticatedSchemaBatch({ providers, uses });
    const schemas = portableCopy(result.schemas);
    const compiled = portableCopy(result.compiled);
    const batchDiagnostics = portableCopy(result.diagnostics);
    const occurrences = portableCopy(schemaBatchOccurrenceEvidence(result));
    if (
      typeof result.ok !== "boolean" ||
      typeof result.normalizedRegistryBytes !== "string" ||
      !schemas.ok ||
      typeof schemas.value !== "object" ||
      schemas.value === null ||
      Array.isArray(schemas.value) ||
      !compiled.ok ||
      typeof compiled.value !== "object" ||
      compiled.value === null ||
      Array.isArray(compiled.value) ||
      !batchDiagnostics.ok ||
      !Array.isArray(batchDiagnostics.value) ||
      !occurrences.ok ||
      !Array.isArray(occurrences.value)
    )
      throw new Error();
    for (const item of batchDiagnostics.value) {
      if (
        typeof item !== "object" ||
        item === null ||
        Array.isArray(item) ||
        typeof item.code !== "string" ||
        !/^CAP_[A-Z0-9_]+$/.test(item.code) ||
        item.severity !== "error" ||
        typeof item.path !== "string" ||
        (item.path !== "" && !item.path.startsWith("/")) ||
        typeof item.message !== "string" ||
        typeof item.source !== "object" ||
        item.source === null ||
        Array.isArray(item.source) ||
        typeof item.source.file !== "string" ||
        !Number.isSafeInteger(item.source.line) ||
        item.source.line < 1 ||
        !Number.isSafeInteger(item.source.column) ||
        item.source.column < 1
      )
        throw new Error();
    }
    const copyValidators = (
      values: ReadonlyMap<string, RuntimeValidator>,
    ): ReadonlyMap<string, RuntimeValidator> => {
      const copied = new Map<string, RuntimeValidator>();
      for (const [key, value] of values) {
        const validator = safeRuntimeValidator(value);
        if (typeof key !== "string" || !validator) throw new Error();
        copied.set(key, validator);
      }
      return copied;
    };
    return Object.freeze({
      ok: result.ok,
      schemas: deepFreeze(
        schemas.value as Record<string, JsonSchema>,
      ) as Readonly<Record<string, JsonSchema>>,
      compiled: deepFreeze(compiled.value) as Readonly<
        Record<
          string,
          { readonly schema: JsonSchema } | { readonly $ref: string }
        >
      >,
      validators: Object.freeze({
        uses: copyValidators(result.validators.uses),
      }),
      diagnostics: deepFreeze(
        batchDiagnostics.value,
      ) as unknown as SchemaBatchCompilationResult["diagnostics"],
      normalizedRegistryBytes: result.normalizedRegistryBytes,
      occurrenceEvidence: deepFreeze(
        occurrences.value,
      ) as unknown as readonly SchemaOccurrenceEvidence[],
    });
  } catch {
    diagnostics.push(
      diagnostic(
        "CAP_SCHEMA_PROVIDER_FAILED",
        "schema",
        "schema-provider",
        "Schema provider compilation failed unexpectedly.",
        source,
        path,
      ),
    );
    return undefined;
  }
}

function sourceSchemaPath(capabilityId: string, internalPath: string): string {
  const roles = [
    ["input", "/input"],
    ["output", "/output"],
  ] as const;
  for (const [internalRole, publicRoot] of roles) {
    const prefix = `/${pointerToken(`${capabilityId}/${internalRole}`)}`;
    if (internalPath === prefix || internalPath.startsWith(`${prefix}/`))
      return `${publicRoot}${internalPath.slice(prefix.length)}`;
  }
  const errorsPrefix = `/${pointerToken(`${capabilityId}/errors/`)}`;
  if (internalPath.startsWith(errorsPrefix)) {
    const remainder = internalPath.slice(errorsPrefix.length);
    const marker = "~1details";
    const markerIndex = remainder.indexOf(marker);
    if (markerIndex >= 0) {
      const code = remainder.slice(0, markerIndex);
      return `/errors/${code}/details${remainder.slice(markerIndex + marker.length)}`;
    }
  }
  return internalPath;
}

function schemaUseKey(capabilityId: string, role: string): string {
  if (role === "input" || role === "output") return `${capabilityId}/${role}`;
  return `${capabilityId}/errors/${decodeURIComponent(role.slice("error/".length))}/details`;
}

const projectPath = (root: string, path: string) =>
  relative(root, path).split(sep).join("/");

async function regularFile(path: string): Promise<boolean> {
  try {
    const info = await lstat(path);
    return info.isFile() && !info.isSymbolicLink();
  } catch {
    return false;
  }
}

async function resolveLocalImport(
  projectRoot: string,
  importer: string,
  specifier: string,
): Promise<string | undefined> {
  let candidate = specifier.startsWith("file:")
    ? fileURLToPath(specifier)
    : resolve(dirname(resolve(projectRoot, importer)), specifier);
  const choices = [candidate];
  if (candidate.endsWith(".js")) choices.push(`${candidate.slice(0, -3)}.ts`);
  else if (candidate.endsWith(".mjs"))
    choices.push(`${candidate.slice(0, -4)}.mts`);
  else if (!/\.[^/]+$/.test(candidate))
    choices.push(
      `${candidate}.ts`,
      `${candidate}.mts`,
      `${candidate}.js`,
      `${candidate}.mjs`,
    );
  for (const choice of choices)
    if (await regularFile(choice)) {
      candidate = choice;
      break;
    }
  const path = projectPath(projectRoot, candidate);
  return path === ".." || path.startsWith("../") || isAbsolute(path)
    ? undefined
    : path;
}

function staticImportSpecifier(expression: ts.Expression): string | undefined {
  if (ts.isStringLiteralLike(expression)) return expression.text;
  if (ts.isParenthesizedExpression(expression))
    return staticImportSpecifier(expression.expression);
  if (
    ts.isBinaryExpression(expression) &&
    expression.operatorToken.kind === ts.SyntaxKind.PlusToken
  ) {
    const left = staticImportSpecifier(expression.left);
    const right = staticImportSpecifier(expression.right);
    return left === undefined || right === undefined ? undefined : left + right;
  }
  return undefined;
}

function hasRuntimeModuleEdge(
  declaration: ts.ImportDeclaration | ts.ExportDeclaration,
): boolean {
  if (ts.isImportDeclaration(declaration)) {
    const clause = declaration.importClause;
    if (!clause) return true;
    if (clause.isTypeOnly) return false;
    return !(
      !clause.name &&
      clause.namedBindings &&
      ts.isNamedImports(clause.namedBindings) &&
      clause.namedBindings.elements.length > 0 &&
      clause.namedBindings.elements.every((element) => element.isTypeOnly)
    );
  }
  if (declaration.isTypeOnly) return false;
  return !(
    declaration.exportClause &&
    ts.isNamedExports(declaration.exportClause) &&
    declaration.exportClause.elements.length > 0 &&
    declaration.exportClause.elements.every((element) => element.isTypeOnly)
  );
}

async function collectProjectSources(
  projectRoot: string,
  initial: readonly string[],
  diagnostics: CompilationDiagnostic[],
): Promise<ReadonlyMap<string, ProjectSource>> {
  const sources = new Map<string, ProjectSource>();
  const queue = [...new Set(initial)].sort(compareText);
  while (queue.length) {
    const path = queue.shift()!;
    if (sources.has(path)) continue;
    let sourceBytes: Uint8Array;
    try {
      sourceBytes = await readFile(resolve(projectRoot, path));
    } catch {
      diagnostics.push(
        diagnostic(
          "CAP_GRAPH_NODE_INVALID",
          "graph",
          "graph-input",
          "A loaded project source could not be fingerprinted.",
          { file: path, line: 1, column: 1 },
        ),
      );
      sources.set(
        path,
        Object.freeze({
          path,
          sourceHash: sha(new Uint8Array()),
          imports: Object.freeze([]),
          importsPackage: false,
          unavailable: true,
          packageImports: Object.freeze([]),
        }),
      );
      continue;
    }
    const parsed = ts.createSourceFile(
      path,
      Buffer.from(sourceBytes).toString("utf8"),
      ts.ScriptTarget.Latest,
      false,
      path.endsWith(".ts") || path.endsWith(".mts")
        ? ts.ScriptKind.TS
        : ts.ScriptKind.JS,
    );
    const createRequireNames = new Set<string>();
    for (const statement of parsed.statements) {
      if (
        !ts.isImportDeclaration(statement) ||
        !ts.isStringLiteral(statement.moduleSpecifier) ||
        !["module", "node:module"].includes(statement.moduleSpecifier.text) ||
        !statement.importClause
      )
        continue;
      if (statement.importClause.name)
        createRequireNames.add(
          `${statement.importClause.name.text}.createRequire`,
        );
      const bindings = statement.importClause.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings))
        createRequireNames.add(`${bindings.name.text}.createRequire`);
      else if (bindings)
        for (const element of bindings.elements)
          if ((element.propertyName ?? element.name).text === "createRequire")
            createRequireNames.add(element.name.text);
    }
    const specifiers: Array<{
      readonly value: string;
      readonly source: CompilationDiagnostic["source"];
    }> = [];
    const addSpecifier = (value: string, node: ts.Node): void => {
      const start = parsed.getLineAndCharacterOfPosition(node.getStart(parsed));
      specifiers.push({
        value,
        source: {
          file: path,
          line: start.line + 1,
          column: start.character + 1,
        },
      });
    };
    const rejectCommonJsLoad = (node: ts.Node): void => {
      const start = parsed.getLineAndCharacterOfPosition(node.getStart(parsed));
      diagnostics.push(
        diagnostic(
          "CAP_GRAPH_NODE_INVALID",
          "graph",
          "graph-input",
          "CommonJS module loading cannot be represented in the compiler artifact graph.",
          {
            file: path,
            line: start.line + 1,
            column: start.character + 1,
          },
        ),
      );
    };
    const visit = (node: ts.Node): void => {
      if (
        (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
        node.moduleSpecifier &&
        ts.isStringLiteral(node.moduleSpecifier) &&
        hasRuntimeModuleEdge(node)
      )
        addSpecifier(node.moduleSpecifier.text, node.moduleSpecifier);
      else if (
        ts.isImportEqualsDeclaration(node) &&
        ts.isExternalModuleReference(node.moduleReference) &&
        !node.isTypeOnly
      )
        rejectCommonJsLoad(node);
      else if (
        ts.isCallExpression(node) &&
        node.expression.kind === ts.SyntaxKind.ImportKeyword
      ) {
        const specifier =
          node.arguments.length === 1
            ? staticImportSpecifier(node.arguments[0]!)
            : undefined;
        if (specifier !== undefined)
          addSpecifier(specifier, node.arguments[0]!);
        else {
          const start = parsed.getLineAndCharacterOfPosition(
            node.getStart(parsed),
          );
          diagnostics.push(
            diagnostic(
              "CAP_GRAPH_NODE_INVALID",
              "graph",
              "graph-input",
              "A dynamic module import cannot be represented in the compiler artifact graph.",
              {
                file: path,
                line: start.line + 1,
                column: start.character + 1,
              },
            ),
          );
        }
      } else if (ts.isCallExpression(node)) {
        const expression = node.expression;
        const name = ts.isIdentifier(expression)
          ? expression.text
          : ts.isPropertyAccessExpression(expression)
            ? `${expression.expression.getText(parsed)}.${expression.name.text}`
            : ts.isElementAccessExpression(expression) &&
                expression.argumentExpression &&
                ts.isStringLiteralLike(expression.argumentExpression)
              ? `${expression.expression.getText(parsed)}.${expression.argumentExpression.text}`
              : undefined;
        if (
          name === "require" ||
          name?.endsWith(".require") ||
          name?.endsWith(".createRequire") ||
          (name !== undefined && createRequireNames.has(name))
        )
          rejectCommonJsLoad(node);
      }
      ts.forEachChild(node, visit);
    };
    visit(parsed);
    const imports: string[] = [];
    const packageImports: Array<{
      readonly specifier: string;
      readonly source: CompilationDiagnostic["source"];
    }> = [];
    let importsPackage = false;
    const uniqueSpecifiers = new Map<
      string,
      CompilationDiagnostic["source"][]
    >();
    for (const item of specifiers) {
      const locations = uniqueSpecifiers.get(item.value) ?? [];
      locations.push(item.source);
      uniqueSpecifiers.set(item.value, locations);
    }
    for (const [specifier, importSources] of [...uniqueSpecifiers].sort(
      (left, right) => compareText(left[0], right[0]),
    )) {
      importSources.sort(
        (left, right) => left.line - right.line || left.column - right.column,
      );
      const [importSource, ...relatedSources] = importSources;
      if (!validIJsonString(specifier)) {
        diagnostics.push(
          diagnostic(
            "CAP_GRAPH_NODE_INVALID",
            "graph",
            "graph-input",
            "A module specifier contains malformed Unicode.",
            importSource!,
            "/imports",
          ),
        );
        continue;
      }
      if (!specifier.startsWith(".") && !specifier.startsWith("file:")) {
        if (!specifier.startsWith("node:"))
          packageImports.push(
            ...importSources.map((source) => ({ specifier, source })),
          );
        importsPackage = true;
        continue;
      }
      const target = await resolveLocalImport(projectRoot, path, specifier);
      if (!target) {
        diagnostics.push(
          compilationDiagnostic({
            code: "CAP_GRAPH_INPUT_OUTSIDE_PROJECT",
            severity: "error",
            phase: "graph",
            subphase: "graph-input",
            message:
              "A project-local module dependency resolves outside the project root.",
            source: importSource!,
            path: "/imports",
            ...(relatedSources.length
              ? {
                  related: relatedSources.map((source) => ({
                    message:
                      "The same outside-project dependency is imported here.",
                    source,
                    path: "/imports",
                  })),
                }
              : {}),
          }),
        );
        continue;
      }
      imports.push(target);
      if (!sources.has(target)) queue.push(target);
    }
    queue.sort(compareText);
    sources.set(
      path,
      Object.freeze({
        path,
        sourceHash: sha(sourceBytes),
        imports: Object.freeze(imports.sort(compareText)),
        importsPackage,
        packageImports: Object.freeze(packageImports),
      }),
    );
  }
  return sources;
}

// Retained only as migration-local reference code while runtime traces replace
// static edge reconstruction; no compiler entry point invokes this function.
void collectProjectSources;

function packageName(specifier: string): string {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0]!;
}

async function toolchainFingerprint(
  projectRoot: string,
  providerIds: readonly string[],
  packageImports: readonly {
    readonly specifier: string;
    readonly source: CompilationDiagnostic["source"];
  }[] = [],
  diagnostics?: CompilationDiagnostic[],
): Promise<Sha256> {
  let lockfile: Sha256 | "missing" = "missing";
  let parsed: Record<string, unknown> | undefined;
  try {
    const lockBytes = await readFile(resolve(projectRoot, "package-lock.json"));
    lockfile = sha(lockBytes);
    const value = JSON.parse(Buffer.from(lockBytes).toString("utf8"));
    if (typeof value === "object" && value !== null && !Array.isArray(value))
      parsed = value as Record<string, unknown>;
  } catch {
    // The literal missing state is part of the accepted fingerprint.
  }
  const packages =
    parsed &&
    typeof parsed.packages === "object" &&
    parsed.packages !== null &&
    !Array.isArray(parsed.packages)
      ? (parsed.packages as Record<string, unknown>)
      : undefined;
  const importerBySpecifier = new Map<
    string,
    CompilationDiagnostic["source"][]
  >();
  for (const item of packageImports) {
    const values = importerBySpecifier.get(item.specifier) ?? [];
    values.push(item.source);
    importerBySpecifier.set(item.specifier, values);
  }
  const imports = [...importerBySpecifier.keys()]
    .sort(compareText)
    .map((specifier) => {
      const name = packageName(specifier);
      const raw = packages?.[`node_modules/${name}`];
      const entry =
        typeof raw === "object" && raw !== null && !Array.isArray(raw)
          ? (raw as Record<string, unknown>)
          : undefined;
      const linked =
        entry?.link === true && typeof entry.resolved === "string"
          ? packages?.[entry.resolved]
          : undefined;
      const resolvedEntry =
        typeof linked === "object" && linked !== null && !Array.isArray(linked)
          ? (linked as Record<string, unknown>)
          : entry;
      if (!entry || typeof resolvedEntry?.version !== "string") {
        if (diagnostics) {
          const sources = importerBySpecifier
            .get(specifier)!
            .sort(
              (left, right) =>
                compareText(left.file, right.file) ||
                left.line - right.line ||
                left.column - right.column,
            );
          const [primary, ...related] = sources;
          diagnostics.push(
            compilationDiagnostic({
              code: "CAP_GRAPH_NODE_INVALID",
              severity: "error",
              phase: "graph",
              subphase: "graph-input",
              message:
                "A package import lacks a project-root package-lock.json resolution.",
              source: primary!,
              path: "/imports",
              ...(related.length
                ? {
                    related: related.map((source) => ({
                      message: "The unresolved package is also imported here.",
                      source,
                      path: "/imports",
                    })),
                  }
                : {}),
            }),
          );
        }
      }
      return {
        integrity:
          typeof resolvedEntry?.integrity === "string"
            ? resolvedEntry.integrity
            : null,
        specifier,
        version:
          typeof resolvedEntry?.version === "string"
            ? resolvedEntry.version
            : null,
      };
    });
  return sha(
    jcs({
      compiler: COMPILER,
      imports,
      lockfile,
      providers: [...providerIds],
    }),
  );
}

function moduleEvidence(
  entry: ProjectSource,
  imports: readonly { readonly id: string; readonly outputDigest: Sha256 }[],
): Uint8Array {
  return bytes({ sourceHash: entry.sourceHash, imports });
}

async function compileGeneration(
  options: CompilerOptions,
  generation: number,
  previous?: Cache,
  sessionToolchain?: Sha256,
  previousSuccess?: CompilationSuccess,
  sessionProviderValidation?: SchemaProviderValidation,
): Promise<{ result: CompilationResult; cache: Cache }> {
  const diagnostics: CompilationDiagnostic[] = [];
  const drafts: NodeDraft[] = [];
  let rawProducers: unknown = [];
  try {
    const descriptor = Object.getOwnPropertyDescriptor(
      options,
      "artifactProducers",
    );
    if (descriptor)
      rawProducers = "value" in descriptor ? descriptor.value : undefined;
  } catch {
    rawProducers = undefined;
  }
  const providerValidation =
    sessionProviderValidation ?? validateSchemaProviders(options);
  diagnostics.push(...providerValidation.diagnostics);
  let configResult;
  let discovery;
  let moduleTrace: ModuleLoadTrace;
  let tracedPackageImports: readonly ModulePackageImport[];
  try {
    const loaded = await runModuleLoadTransaction(
      options.projectRoot,
      async (loaderGeneration) =>
        Promise.all([
          loadFullCompilerConfig(options.projectRoot, loaderGeneration),
          discoverCapabilities(
            { projectRoot: options.projectRoot },
            loaderGeneration,
            true,
          ),
        ]),
    );
    [configResult, discovery] = loaded.value;
    moduleTrace = loaded.trace;
    tracedPackageImports = loaded.packageImports;
  } catch (error) {
    const loaderError =
      error instanceof ModuleGraphLoadError ? error : undefined;
    diagnostics.push(
      diagnostic(
        loaderError?.code ?? "CAP_GRAPH_NODE_INVALID",
        "graph",
        "graph-input",
        loaderError
          ? "A project module could not be admitted to the authoritative runtime trace."
          : "Compilation failed unexpectedly while reading project inputs.",
        loaderError
          ? { file: loaderError.sourceFile, line: 1, column: 1 }
          : PROJECT_SOURCE,
        "/imports",
        loaderError ? { reason: loaderError.reason } : undefined,
      ),
    );
    const graph = graphReport(
      generation,
      loaderError
        ? loaderFailureDrafts(loaderError)
        : [
            {
              id: "config:service",
              dependencies: [],
              failure: ["CAP_GRAPH_NODE_INVALID"],
            },
          ],
      previous,
    );
    return {
      result: Object.freeze({
        ok: false,
        graph,
        diagnostics: sortCompilationDiagnostics(diagnostics),
      }),
      cache: new Map(),
    };
  }
  diagnostics.push(...discovery.diagnostics.map(adaptDiscoveryDiagnostic));
  if (!configResult.ok) diagnostics.push(...configResult.diagnostics);
  if (!configResult.ok || !discovery.ok) {
    const moduleFailure = diagnostics.find(
      (item) =>
        item.code === "CAP_DISCOVERY_MODULE_LOAD_FAILED" &&
        /^src\/capabilities\/.+\.(?:ts|mts|js|mjs)$/.test(item.source.file),
    );
    if (moduleFailure) {
      const graph = graphReport(
        generation,
        tracedModuleFailureDrafts(
          moduleTrace,
          moduleFailure.source.file,
          moduleFailure.code,
        ),
        previous,
      );
      return {
        result: Object.freeze({
          ok: false,
          graph,
          diagnostics: sortCompilationDiagnostics(diagnostics),
        }),
        cache: new Map(),
      };
    }
    const codes = diagnostics
      .filter((item) => item.severity === "error")
      .map((item) => item.code);
    drafts.push({
      id: "config:service",
      dependencies: [],
      failure: codes.length ? codes : ["CAP_CONFIG_SERVICE_INVALID"],
    });
    const graph = graphReport(generation, drafts, previous);
    return {
      result: Object.freeze({
        ok: false,
        graph,
        diagnostics: sortCompilationDiagnostics(diagnostics),
      }),
      cache: new Map(),
    };
  }
  try {
    const descriptor = Object.getOwnPropertyDescriptor(
      options,
      Symbol.for("@capaxle/compiler/test-post-load@1"),
    );
    if (
      descriptor &&
      "value" in descriptor &&
      typeof descriptor.value === "function"
    )
      await (descriptor.value as () => void | Promise<void>)();
  } catch {
    diagnostics.push(
      diagnostic(
        "CAP_GRAPH_NODE_INVALID",
        "graph",
        "graph-input",
        "A post-load compiler resource failed unexpectedly.",
      ),
    );
  }
  const config = configResult.config;
  const projectSources = await projectSourcesFromTrace(
    moduleTrace,
    tracedPackageImports,
    options.projectRoot,
    diagnostics,
  );
  const packageImports = [...projectSources.values()].flatMap(
    (source) => source.packageImports,
  );
  const currentToolchain = await toolchainFingerprint(
    options.projectRoot,
    providerValidation.ids,
    packageImports,
    diagnostics,
  );
  if (sessionToolchain && currentToolchain !== sessionToolchain)
    diagnostics.push(
      diagnostic(
        "CAP_GRAPH_SESSION_RESTART_REQUIRED",
        "graph",
        "graph-input",
        "The compiler toolchain changed after this incremental session started.",
      ),
    );
  const cyclicModules = diagnoseModuleCycles(projectSources, diagnostics);
  const cycleReachability = new Map<string, boolean>();
  const reachesModuleCycle = (
    path: string,
    visiting = new Set<string>(),
  ): boolean => {
    const known = cycleReachability.get(path);
    if (known !== undefined) return known;
    if (cyclicModules.has(path)) return true;
    if (visiting.has(path)) return false;
    visiting.add(path);
    const reaches = (projectSources.get(path)?.imports ?? []).some(
      (dependency) => reachesModuleCycle(dependency, visiting),
    );
    visiting.delete(path);
    cycleReachability.set(path, reaches);
    return reaches;
  };
  const moduleOutputs = new Map<string, Uint8Array>();
  const moduleInputs = new Map<string, Sha256>();
  const executedModules = new Set<string>();
  const resolveModuleEvidence = (path: string): Uint8Array => {
    const known = moduleOutputs.get(path);
    if (known) return known;
    const source = projectSources.get(path)!;
    const imports = source.imports.map((dependencyPath) => ({
      id: `module:${encode(dependencyPath)}`,
      outputDigest: sha(resolveModuleEvidence(dependencyPath)),
    }));
    const input = sha(
      jcs({
        dependencies: imports,
        kind: "module",
        localInputs: {
          sourceHash: source.sourceHash,
          toolchainFingerprint: source.importsPackage ? currentToolchain : null,
        },
        transform: "capaxle:module-evidence@1",
      }),
    );
    const id = `module:${encode(path)}`;
    const cached = previous?.get(id);
    const output =
      cached?.input === input
        ? new Uint8Array(cached.bytes)
        : moduleEvidence(source, imports);
    executedModules.add(path);
    const hook = (
      options as CompilerOptions & {
        readonly [key: symbol]: ((path: string) => void) | undefined;
      }
    )[Symbol.for("@capaxle/compiler/test-module-transform@1")];
    hook?.(path);
    moduleInputs.set(path, input);
    moduleOutputs.set(path, output);
    return output;
  };
  for (const source of projectSources.values())
    if (!source.unavailable && !reachesModuleCycle(source.path))
      resolveModuleEvidence(source.path);
  for (const id of Object.keys(config.projections))
    if (!discovery.capabilities.some((item) => item.id === id))
      diagnostics.push(
        diagnostic(
          "CAP_PROJECTION_CAPABILITY_UNKNOWN",
          "projection",
          "projection-collision",
          "Projection override names an unknown capability.",
          configSource(config, `/projections/${pointerToken(id)}`),
          `/projections/${pointerToken(id)}`,
        ),
      );
  const schemaUses: CompilerSchemaUse[] = [];
  const sharedUseByKey = new Map<string, string>();
  const useKeysByCapability = new Map<string, readonly string[]>();
  for (const capability of [...discovery.capabilities].sort((left, right) =>
    compareText(left.id, right.id),
  )) {
    const sharedByPath = new Map(
      (
        capabilityAuthoringPresence(capability.descriptor)?.sharedSchemas ?? []
      ).map((occurrence) => [occurrence.path, occurrence.schema] as const),
    );
    const addUse = (
      key: string,
      path: string,
      schema: unknown,
      direction: "input" | "output",
    ): void => {
      const shared = sharedByPath.get(path);
      const canonicalOrder = schemaUses.length;
      schemaUses.push({
        key,
        schema: shared?.authorSchema ?? schema,
        direction,
        source: capability.source,
        canonicalOrder,
        ...(shared ? { sharedName: shared.name } : {}),
      });
      if (shared) sharedUseByKey.set(key, shared.name);
    };
    addUse(
      `${capability.id}/input`,
      "/input",
      capability.descriptor.input,
      "input",
    );
    addUse(
      `${capability.id}/output`,
      "/output",
      capability.descriptor.output,
      "output",
    );
    for (const [code, error] of Object.entries(
      capability.descriptor.errors,
    ).sort(([left], [right]) => compareText(left, right)))
      if (error.details !== undefined)
        addUse(
          `${capability.id}/errors/${code}/details`,
          `/errors/${pointerToken(code)}/details`,
          error.details,
          "output",
        );
    useKeysByCapability.set(
      capability.id,
      Object.freeze(
        schemaUses
          .filter(({ key }) => key.startsWith(`${capability.id}/`))
          .map(({ key }) => key),
      ),
    );
  }
  schemaUses.sort((left, right) => compareText(left.key, right.key));
  const executedSchemaUseKeys = new Set(schemaUses.map(({ key }) => key));
  const schemaBatch = providerValidation.diagnostics.length
    ? undefined
    : safeSchemaBatch(
        providerValidation.providers,
        schemaUses,
        PROJECT_SOURCE,
        "/schemas",
        diagnostics,
      );
  const sourceSchemaPathForBatch = (internalPath: string): string => {
    for (const capability of discovery.capabilities) {
      const mapped = sourceSchemaPath(capability.id, internalPath);
      if (mapped !== internalPath) return mapped;
    }
    return internalPath;
  };
  if (schemaBatch)
    diagnostics.push(
      ...schemaBatch.diagnostics.map((item) =>
        compilationDiagnostic({
          code: item.code as `CAP_${string}`,
          severity: "error",
          phase: "schema",
          subphase:
            item.code.includes("REF") || item.code.includes("SHARED")
              ? "schema-reference"
              : item.code.startsWith("CAP_SCHEMA_PROVIDER")
                ? "schema-provider"
                : "schema-portability",
          message: item.message,
          source: item.source,
          path: sourceSchemaPathForBatch(item.path),
          ...(item.related ? { related: item.related } : {}),
        }),
      ),
    );
  const schemaOccurrenceByKey = new Map(
    (schemaBatch?.occurrenceEvidence ?? []).map(
      (item) => [item.key, item] as const,
    ),
  );
  const sharedNames = Object.freeze(
    [...new Set(sharedUseByKey.values())].sort(compareText),
  );
  const sharedGraphData = (name: string) => {
    const uses = schemaUses.filter(
      (use) => sharedUseByKey.get(use.key) === name,
    );
    const dependencies = Object.freeze(
      [...new Set(uses.map((use) => `module:${encode(use.source.file)}`))].sort(
        compareText,
      ),
    );
    const occurrences = uses.map((use) => {
      const evidence = schemaOccurrenceByKey.get(use.key);
      return {
        key: use.key,
        direction: use.direction,
        providerId: evidence?.providerId ?? null,
        normalizedSchema: evidence?.jsonSchema ?? null,
      };
    });
    return {
      dependencies,
      complete: occurrences.every(
        (occurrence) =>
          occurrence.providerId !== null &&
          occurrence.normalizedSchema !== null,
      ),
      localInputs: {
        name,
        occurrences,
        toolchainFingerprint: currentToolchain,
      } as unknown as JsonValue,
    };
  };
  const resolved: ResolvedCapability[] = [];
  if (schemaBatch)
    for (const capability of discovery.capabilities) {
      if (
        projectSources.get(capability.source.file)?.unavailable ||
        reachesModuleCycle(capability.source.file)
      )
        continue;
      const keys = useKeysByCapability.get(capability.id) ?? [];
      if (
        keys.some(
          (key) =>
            schemaBatch.compiled[key] === undefined ||
            !schemaBatch.validators.uses.has(key),
        )
      )
        continue;
      resolved.push(
        resolveCapability(
          capability,
          config,
          schemaBatch.compiled,
          schemaBatch.schemas,
          schemaBatch.validators.uses,
          diagnostics,
        ),
      );
    }
  const schemas: Readonly<{
    ok: boolean;
    schemas: Readonly<Record<string, JsonSchema>>;
  }> = Object.freeze({
    ok: schemaBatch?.ok === true,
    schemas: schemaBatch?.schemas ?? Object.freeze({}),
  });
  collisionDiagnostics(resolved, diagnostics);
  const cliProjectionEnabled = resolved.some(
    (item) =>
      (item.ir.interfaces as Record<string, Record<string, JsonValue>>).cli
        ?.enabled === true,
  );
  if (cliProjectionEnabled && !config.cliBinary) {
    if (config.cliRemoteOnly && options.requireLocalCliBinary)
      diagnostics.push(
        diagnostic(
          "CAP_CLI_REMOTE_APP_CONTEXT_REQUIRED",
          "configuration",
          "config-value",
          "A remote-only CLI requires an application deployment context. Use buildDeployment with an enabled CLI registration instead of standalone capaxle build.",
          configSource(config, "/adapters/cli/remoteOnly"),
          "/adapters/cli/remoteOnly",
          { reason: "application-context-required" },
        ),
      );
    else if (!config.cliRemoteOnly)
      diagnostics.push(
        diagnostic(
          "CAP_BUILD_CONTEXT_INVALID",
          "configuration",
          "config-value",
          "adapters.cli.binaryName is required when a CLI projection is enabled.",
          configSource(config, "/adapters/cli/binaryName"),
          "/adapters/cli/binaryName",
          { reason: "missing" },
        ),
      );
  }
  const sources = [...projectSources.values()]
    .map((item) => ({ path: item.path, sha256: item.sourceHash }))
    .sort((a, b) => compareText(a.path, b.path));
  const sourceManifest = {
    sourceHash: sha(jcs(sources as unknown as JsonValue)),
    sources,
  };
  const sourceManifestBytes = bytes(sourceManifest as unknown as JsonValue);
  const sourceManifestDigest = sha(sourceManifestBytes);
  const rawDocument = {
    irVersion: "0.1",
    service: config.service,
    schemas: schemas.schemas,
    capabilities: resolved.map((item) => item.ir),
    metadata: { generator: COMPILER, sourceHash: sourceManifest.sourceHash },
  } as unknown as CapabilityDocument;
  const iJsonIssue = firstIJsonIssue(rawDocument as unknown as JsonValue);
  let normalizationFailed = false;
  let document = rawDocument;
  if (!iJsonIssue)
    try {
      document = normalizeDocument(
        rawDocument,
      ) as unknown as CapabilityDocument;
    } catch {
      normalizationFailed = true;
    }
  const irDiagnostics = iJsonIssue
    ? [
        {
          code: "CAP_IR_DOCUMENT_INVALID",
          severity: "error" as const,
          path: iJsonIssue.path,
          message: iJsonIssue.message,
        },
      ]
    : normalizationFailed
      ? [
          {
            code: "CAP_IR_DOCUMENT_INVALID",
            severity: "error" as const,
            path: "",
            message: "Capability document normalization failed unexpectedly.",
          },
        ]
      : validateCapabilityDocument(document, { requireNormalized: true });
  for (const item of irDiagnostics)
    diagnostics.push(
      mapIrDiagnostic(
        item,
        closestIrDiagnosticSource(
          item,
          document,
          resolved,
          config,
          config.source,
        ),
      ),
    );
  const producerList = validateProducers(rawProducers, diagnostics);
  const rootPublication = producerList.find(
    (producer) => producer.rootPublication !== undefined,
  )?.rootPublication;
  const earlyErrors = diagnostics.some((item) => item.severity === "error");
  if (cyclicModules.size) {
    const pushConfig = (id: string, value: JsonValue): void => {
      const input = nodeInputFingerprint(
        id,
        "capaxle:config-leaf@1",
        value,
        [],
        drafts,
      );
      drafts.push({
        id,
        dependencies: [],
        output: bytes(value),
        input,
        executed: previous?.get(id)?.input !== input,
      });
    };
    pushConfig("config:service", config.service as JsonValue);
    pushConfig("config:discovery/root", discovery.config.root);
    pushConfig("config:discovery/ignore", [...discovery.config.ignore]);
    pushConfig(
      "config:discovery/allow-id-override",
      discovery.config.allowIdOverride,
    );
    for (const surface of surfaces)
      pushConfig(
        `config:exposure-default/${surface}`,
        config.exposureDefaults[surface],
      );
    pushConfig("config:http-prefix", config.httpPrefix);
    pushConfig("config:http-header-allowlist", [...config.httpHeaderAllowlist]);
    pushConfig(
      "config:http-discovery/collection",
      config.discovery.http.collection,
    );
    pushConfig(
      "config:http-discovery/detail-template",
      config.discovery.http.detailTemplate,
    );
    pushConfig(
      "config:http-discovery/schema-template",
      config.discovery.http.schemaTemplate,
    );
    pushConfig("config:mcp-endpoint", config.discovery.mcp.endpoint);
    for (const [capabilityId, override] of Object.entries(config.projections))
      for (const surface of ["http", "cli", "mcp", "docs", "sdk"] as const)
        if (surface in override)
          pushConfig(
            `config:projection/${encode(capabilityId)}/${surface}`,
            override[surface] as JsonValue,
          );
    const unavailableModules = new Set<string>();
    for (const item of projectSources.values()) {
      const id = `module:${encode(item.path)}`;
      const directBlocked = item.imports
        .filter(
          (dependency) =>
            cyclicModules.has(dependency) ||
            unavailableModules.has(dependency) ||
            reachesModuleCycle(dependency),
        )
        .map((dependency) => `module:${encode(dependency)}`);
      if (cyclicModules.has(item.path)) unavailableModules.add(item.path);
      else if (reachesModuleCycle(item.path)) unavailableModules.add(item.path);
      drafts.push({
        id,
        dependencies: item.imports.map(
          (dependency) => `module:${encode(dependency)}`,
        ),
        ...(cyclicModules.has(item.path)
          ? { failure: ["CAP_GRAPH_CYCLE" as const] }
          : directBlocked.length
            ? { blocked: directBlocked }
            : {
                output: moduleOutputs.get(item.path)!,
                input: moduleInputs.get(item.path)!,
                executed: executedModules.has(item.path),
              }),
      });
    }
    const affectedModuleIds = drafts
      .filter(
        (draft) =>
          draft.id.startsWith("module:") && (draft.failure || draft.blocked),
      )
      .map((draft) => draft.id);
    drafts.push({
      id: "source:manifest",
      dependencies: [
        "config:discovery/root",
        "config:discovery/ignore",
        ...[...projectSources.values()].map(
          (item) => `module:${encode(item.path)}`,
        ),
      ],
      blocked: affectedModuleIds,
    });
    const resolvedById = new Map(
      resolved.map((item) => [item.registry.id, item] as const),
    );
    const sharedSchemaNodeIds = sharedNames.map((name) => {
      const id = `schema:shared/${encode(name)}`;
      const schema = schemas.schemas[name];
      const { dependencies, complete, localInputs } = sharedGraphData(name);
      const directBlockers = dependencies.filter((dependency) =>
        drafts.some(
          (draft) =>
            draft.id === dependency && (draft.failure || draft.blocked),
        ),
      );
      if (directBlockers.length)
        drafts.push({
          id,
          dependencies: [...dependencies],
          blocked: directBlockers,
        });
      else if (schema && complete)
        drafts.push({
          id,
          dependencies: [...dependencies],
          output: bytes(schema),
          input: nodeInputFingerprint(
            id,
            "capaxle:shared-schema@1",
            localInputs,
            dependencies,
            drafts,
          ),
          executed: true,
        });
      else
        drafts.push({
          id,
          dependencies: [...dependencies],
          failure: ["CAP_SCHEMA_PROVIDER_FAILED"],
          executed: true,
        });
      return id;
    });
    const capabilityIds: string[] = [];
    const provenanceIds: string[] = [];
    for (const capability of discovery.capabilities) {
      const moduleId = `module:${encode(capability.source.file)}`;
      const resolvedCapability = resolvedById.get(capability.id);
      const roles: Array<{ role: string; schema?: JsonValue }> = [
        {
          role: "input",
          ...(resolvedCapability
            ? { schema: resolvedCapability.ir.input }
            : {}),
        },
        {
          role: "output",
          ...(resolvedCapability
            ? { schema: resolvedCapability.ir.output }
            : {}),
        },
        ...Object.entries(capability.descriptor.errors)
          .filter(([, error]) => error.details !== undefined)
          .map(([code]) => {
            const schema = resolvedCapability
              ? (
                  resolvedCapability.ir.errors as Record<
                    string,
                    Record<string, JsonValue>
                  >
                )[code]?.details
              : undefined;
            return {
              role: `error/${encode(code)}`,
              ...(schema === undefined ? {} : { schema }),
            };
          }),
      ];
      const schemaIds: string[] = [];
      for (const { role, schema } of roles) {
        const schemaId = `schema:${encode(capability.id)}/${role}`;
        const useKey = schemaUseKey(capability.id, role);
        const sharedName = sharedUseByKey.get(useKey);
        const sharedId = sharedName
          ? `schema:shared/${encode(sharedName)}`
          : undefined;
        const schemaDependencies = [moduleId, ...(sharedId ? [sharedId] : [])];
        schemaIds.push(schemaId);
        const schemaBlockers = schemaDependencies.filter((dependency) =>
          drafts.some(
            (draft) =>
              draft.id === dependency && (draft.failure || draft.blocked),
          ),
        );
        const schemaInput =
          resolvedCapability && schema && schemaBlockers.length === 0
            ? nodeInputFingerprint(
                schemaId,
                "capaxle:schema@1",
                (sharedName
                  ? { reference: schema }
                  : {
                      providerId:
                        schemaOccurrenceByKey.get(useKey)?.providerId ?? null,
                      schema,
                      toolchainFingerprint: currentToolchain,
                    }) as JsonValue,
                schemaDependencies,
                drafts,
              )
            : undefined;
        drafts.push({
          id: schemaId,
          dependencies: schemaDependencies,
          ...(resolvedCapability && schema && schemaInput
            ? {
                output: bytes(schema as JsonValue),
                input: schemaInput,
                executed: executedSchemaUseKeys.has(useKey),
              }
            : {
                blocked: schemaBlockers.length
                  ? schemaBlockers
                  : schemaDependencies,
              }),
        });
      }
      const capabilityId = `capability:${capability.id}`;
      capabilityIds.push(capabilityId);
      const dependencies = [
        moduleId,
        ...schemaIds,
        ...new Set(
          (useKeysByCapability.get(capability.id) ?? []).flatMap((key) => {
            const name = sharedUseByKey.get(key);
            return name ? [`schema:shared/${encode(name)}`] : [];
          }),
        ),
        ...(resolvedCapability?.configDependencies ?? []),
      ];
      const directBlockers = dependencies.filter((dependency) =>
        drafts.some(
          (draft) =>
            draft.id === dependency && (draft.failure || draft.blocked),
        ),
      );
      const capabilityInput = resolvedCapability
        ? nodeInputFingerprint(
            capabilityId,
            "capaxle:capability-resolution@1",
            { capability: resolvedCapability.ir } as unknown as JsonValue,
            dependencies,
            drafts,
          )
        : undefined;
      drafts.push({
        id: capabilityId,
        dependencies,
        ...(resolvedCapability && capabilityInput
          ? {
              output: bytes(resolvedCapability.ir as JsonValue),
              input: capabilityInput,
              executed: previous?.get(capabilityId)?.input !== capabilityInput,
            }
          : { blocked: directBlockers.length ? directBlockers : dependencies }),
      });
      const provenanceId = `provenance:${capability.id}`;
      provenanceIds.push(provenanceId);
      const provenanceDependencies = [
        capabilityId,
        moduleId,
        ...(resolvedCapability?.configDependencies ?? []),
      ];
      const provenanceLocalInputs = resolvedCapability
        ? ({
            source: {
              file: resolvedCapability.source.file,
              sourceHash: resolvedCapability.sourceHash,
            },
            provenance: resolvedCapability.registry.provenance,
          } as unknown as JsonValue)
        : undefined;
      drafts.push({
        id: provenanceId,
        dependencies: provenanceDependencies,
        ...(resolvedCapability && provenanceLocalInputs
          ? {
              output: bytes(provenanceLocalInputs),
              input: nodeInputFingerprint(
                provenanceId,
                "capaxle:provenance@1",
                provenanceLocalInputs,
                provenanceDependencies,
                drafts,
              ),
              executed: true,
            }
          : { blocked: [capabilityId, moduleId] }),
      });
    }
    const documentDependencies = [
      "config:service",
      "source:manifest",
      ...capabilityIds,
      ...sharedSchemaNodeIds,
    ];
    drafts.push({
      id: "document:capability-ir",
      dependencies: documentDependencies,
      blocked: documentDependencies.filter((id) =>
        drafts.some(
          (draft) => draft.id === id && (draft.failure || draft.blocked),
        ),
      ),
    });
    drafts.push({
      id: "artifact:capaxle.ir",
      dependencies: ["document:capability-ir"],
      blocked: ["document:capability-ir"],
    });
    drafts.push({
      id: "artifact:capaxle.compiler-registry",
      dependencies: ["document:capability-ir", ...provenanceIds],
      blocked: [
        "document:capability-ir",
        ...provenanceIds.filter((id) =>
          drafts.some(
            (draft) => draft.id === id && (draft.failure || draft.blocked),
          ),
        ),
      ],
    });
    drafts.push({
      id: "artifact:capaxle.artifact-index",
      dependencies: [
        "artifact:capaxle.ir",
        "artifact:capaxle.compiler-registry",
      ],
      blocked: ["artifact:capaxle.ir", "artifact:capaxle.compiler-registry"],
    });
    const graph = graphReport(generation, drafts, previous);
    return {
      result: Object.freeze({
        ok: false,
        graph,
        diagnostics: sortCompilationDiagnostics(diagnostics),
      }),
      cache: new Map(),
    };
  }
  if (earlyErrors) {
    const errorDiagnostics = diagnostics.filter(
      (item) => item.severity === "error",
    );
    const assignedDiagnostics = new Set<CompilationDiagnostic>();
    const uniqueCodes = (items: readonly CompilationDiagnostic[]) =>
      [...new Set(items.map((item) => item.code))].sort(compareText);
    const pushConfig = (id: string, value: JsonValue): void => {
      const input = nodeInputFingerprint(
        id,
        "capaxle:config-leaf@1",
        value,
        [],
        drafts,
      );
      drafts.push({
        id,
        dependencies: [],
        output: bytes(value),
        input,
        executed: previous?.get(id)?.input !== input,
      });
    };
    pushConfig("config:service", config.service as JsonValue);
    pushConfig("config:discovery/root", discovery.config.root);
    pushConfig("config:discovery/ignore", [...discovery.config.ignore]);
    pushConfig(
      "config:discovery/allow-id-override",
      discovery.config.allowIdOverride,
    );
    for (const surface of surfaces)
      pushConfig(
        `config:exposure-default/${surface}`,
        config.exposureDefaults[surface],
      );
    pushConfig("config:http-prefix", config.httpPrefix);
    pushConfig("config:http-header-allowlist", [...config.httpHeaderAllowlist]);
    pushConfig(
      "config:http-discovery/collection",
      config.discovery.http.collection,
    );
    pushConfig(
      "config:http-discovery/detail-template",
      config.discovery.http.detailTemplate,
    );
    pushConfig(
      "config:http-discovery/schema-template",
      config.discovery.http.schemaTemplate,
    );
    pushConfig("config:mcp-endpoint", config.discovery.mcp.endpoint);
    for (const [capabilityId, override] of Object.entries(config.projections))
      for (const surface of ["http", "cli", "mcp", "docs", "sdk"] as const)
        if (surface in override)
          pushConfig(
            `config:projection/${encode(capabilityId)}/${surface}`,
            override[surface] as JsonValue,
          );
    const moduleErrors = new Map<string, CompilationDiagnostic[]>();
    for (const item of errorDiagnostics) {
      if (item.phase !== "graph" || item.subphase !== "graph-input") continue;
      const source = projectSources.get(item.source.file);
      if (!source) continue;
      const owned = moduleErrors.get(source.path) ?? [];
      owned.push(item);
      moduleErrors.set(source.path, owned);
      assignedDiagnostics.add(item);
    }
    const unavailableModules = new Map<string, boolean>();
    const moduleUnavailable = (path: string): boolean => {
      const known = unavailableModules.get(path);
      if (known !== undefined) return known;
      const source = projectSources.get(path);
      const unavailable =
        moduleErrors.has(path) ||
        (source?.imports ?? []).some((dependency) =>
          moduleUnavailable(dependency),
        );
      unavailableModules.set(path, unavailable);
      return unavailable;
    };
    for (const item of projectSources.values()) {
      const ownedErrors = moduleErrors.get(item.path) ?? [];
      const blockedBy = item.imports
        .filter((path) => moduleUnavailable(path))
        .map((path) => `module:${encode(path)}`);
      drafts.push({
        id: `module:${encode(item.path)}`,
        dependencies: item.imports.map((path) => `module:${encode(path)}`),
        input: moduleInputs.get(item.path)!,
        ...(ownedErrors.length
          ? { failure: uniqueCodes(ownedErrors), executed: false }
          : blockedBy.length
            ? { blocked: blockedBy }
            : {
                output: moduleOutputs.get(item.path)!,
                executed: executedModules.has(item.path),
              }),
      });
    }
    const manifestDependencies = [
      "config:discovery/root",
      "config:discovery/ignore",
      ...[...projectSources.values()].map(
        (item) => `module:${encode(item.path)}`,
      ),
    ];
    const manifestInput = nodeInputFingerprint(
      "source:manifest",
      "capaxle:source-manifest@1",
      { sources: sourceManifest.sources } as unknown as JsonValue,
      manifestDependencies,
      drafts,
    );
    const manifestBlockers = manifestDependencies.filter((id) =>
      drafts.some(
        (draft) =>
          draft.id === id && (draft.failure !== undefined || draft.blocked),
      ),
    );
    drafts.push({
      id: "source:manifest",
      dependencies: manifestDependencies,
      ...(manifestBlockers.length
        ? { blocked: manifestBlockers }
        : {
            output: sourceManifestBytes,
            input: manifestInput,
            executed: previous?.get("source:manifest")?.input !== manifestInput,
          }),
    });
    const resolvedById = new Map(
      resolved.map((item) => [item.registry.id, item] as const),
    );
    const sharedSchemaNodeIds = sharedNames.map((name) => {
      const id = `schema:shared/${encode(name)}`;
      const schema = schemas.schemas[name];
      const { dependencies, complete, localInputs } = sharedGraphData(name);
      const dependencyBlockers = dependencies.filter((dependency) =>
        drafts.some(
          (draft) =>
            draft.id === dependency &&
            (draft.failure !== undefined || draft.blocked),
        ),
      );
      const failureCodes = [
        ...new Set(
          (schemaBatch?.diagnostics ?? [])
            .filter(
              (item) =>
                item.path === `/schemas/${pointerToken(name)}` ||
                schemaUses.some(
                  (use) =>
                    sharedUseByKey.get(use.key) === name &&
                    (item.path === `/${pointerToken(use.key)}` ||
                      item.path.startsWith(`/${pointerToken(use.key)}/`)),
                ),
            )
            .map((item) => item.code as `CAP_${string}`),
        ),
      ].sort(compareText);
      if (dependencyBlockers.length) {
        drafts.push({
          id,
          dependencies: [...dependencies],
          blocked: dependencyBlockers,
          executed: true,
        });
      } else if (schema && complete) {
        const input = nodeInputFingerprint(
          id,
          "capaxle:shared-schema@1",
          localInputs,
          dependencies,
          drafts,
        );
        drafts.push({
          id,
          dependencies: [...dependencies],
          output: bytes(schema),
          input,
          executed: true,
        });
      } else
        drafts.push({
          id,
          dependencies: [...dependencies],
          failure: failureCodes.length
            ? failureCodes
            : ["CAP_SCHEMA_PROVIDER_FAILED"],
          executed: true,
        });
      for (const item of errorDiagnostics)
        if (
          item.path === `/schemas/${pointerToken(name)}` ||
          schemaUses.some(
            (use) =>
              sharedUseByKey.get(use.key) === name &&
              item.source.file === use.source.file &&
              (item.path ===
                sourceSchemaPathForBatch(`/${pointerToken(use.key)}`) ||
                item.path?.startsWith(
                  `${sourceSchemaPathForBatch(`/${pointerToken(use.key)}`)}/`,
                )),
          )
        )
          assignedDiagnostics.add(item);
      return id;
    });
    const capabilityNodeIds: string[] = [];
    const provenanceNodeIds: string[] = [];
    for (const [
      capabilityIndex,
      capability,
    ] of discovery.capabilities.entries()) {
      const moduleId = `module:${encode(capability.source.file)}`;
      const resolvedCapability = resolvedById.get(capability.id);
      const capabilityErrors = errorDiagnostics.filter(
        (item) =>
          !assignedDiagnostics.has(item) &&
          (item.source.file === capability.source.file ||
            item.path?.startsWith(`/capabilities/${capabilityIndex}/`) ||
            item.path?.startsWith(
              `/projections/${pointerToken(capability.id)}/`,
            )),
      );
      const moduleDraft = drafts.find((draft) => draft.id === moduleId)!;
      const moduleIsUnavailable = Boolean(
        moduleDraft.failure || moduleDraft.blocked,
      );
      const schemaEntries: Array<{
        readonly role: string;
        readonly sourceRoot: string;
        readonly irRoot: string;
        readonly schema?: JsonValue;
      }> = [
        {
          role: "input",
          sourceRoot: "/input",
          irRoot: `/capabilities/${capabilityIndex}/input`,
          ...(resolvedCapability
            ? { schema: resolvedCapability.ir.input as JsonValue }
            : {}),
        },
        {
          role: "output",
          sourceRoot: "/output",
          irRoot: `/capabilities/${capabilityIndex}/output`,
          ...(resolvedCapability
            ? { schema: resolvedCapability.ir.output as JsonValue }
            : {}),
        },
        ...Object.entries(capability.descriptor.errors)
          .filter(([, error]) => error.details !== undefined)
          .map(([code]) => {
            const schema = resolvedCapability
              ? (
                  resolvedCapability.ir.errors as Record<
                    string,
                    Record<string, JsonValue>
                  >
                )[code]?.details
              : undefined;
            return {
              role: `error/${encode(code)}`,
              sourceRoot: `/errors/${pointerToken(code)}/details`,
              irRoot: `/capabilities/${capabilityIndex}/errors/${pointerToken(code)}/details`,
              ...(schema === undefined ? {} : { schema }),
            };
          }),
      ];
      const schemaNodeIds: string[] = [];
      const schemaDiagnostics = new Set<CompilationDiagnostic>();
      for (const { role, sourceRoot, irRoot, schema } of schemaEntries) {
        const schemaId = `schema:${encode(capability.id)}/${role}`;
        const useKey = schemaUseKey(capability.id, role);
        const compiledSchema =
          schema ?? (schemaBatch?.compiled[useKey] as JsonValue | undefined);
        const sharedName = sharedUseByKey.get(useKey);
        const sharedId = sharedName
          ? `schema:shared/${encode(sharedName)}`
          : undefined;
        const schemaDependencies = [moduleId, ...(sharedId ? [sharedId] : [])];
        schemaNodeIds.push(schemaId);
        const roleErrors = capabilityErrors.filter(
          (item) =>
            item.path === sourceRoot ||
            item.path?.startsWith(`${sourceRoot}/`) ||
            item.path === irRoot ||
            item.path?.startsWith(`${irRoot}/`),
        );
        for (const item of roleErrors) {
          schemaDiagnostics.add(item);
          assignedDiagnostics.add(item);
        }
        const schemaDependencyBlockers = schemaDependencies.filter(
          (dependency) =>
            drafts.some(
              (draft) =>
                draft.id === dependency &&
                (draft.failure !== undefined || draft.blocked),
            ),
        );
        if (schemaDependencyBlockers.length) {
          drafts.push({
            id: schemaId,
            dependencies: schemaDependencies,
            blocked: schemaDependencyBlockers,
          });
          continue;
        }
        if (roleErrors.length || compiledSchema === undefined) {
          const failureCodes = uniqueCodes(
            roleErrors.length ? roleErrors : capabilityErrors,
          );
          drafts.push({
            id: schemaId,
            dependencies: schemaDependencies,
            failure: failureCodes.length
              ? failureCodes
              : ["CAP_GRAPH_NODE_INVALID"],
            executed: executedSchemaUseKeys.has(useKey),
          });
          continue;
        }
        const schemaInput = nodeInputFingerprint(
          schemaId,
          "capaxle:schema@1",
          (sharedName
            ? { reference: compiledSchema }
            : {
                providerId:
                  schemaOccurrenceByKey.get(useKey)?.providerId ?? null,
                schema: compiledSchema,
                toolchainFingerprint: currentToolchain,
              }) as JsonValue,
          schemaDependencies,
          drafts,
        );
        drafts.push({
          id: schemaId,
          dependencies: schemaDependencies,
          output: bytes(compiledSchema),
          input: schemaInput,
          executed:
            (!sharedUseByKey.has(useKey) &&
              executedSchemaUseKeys.has(useKey)) ||
            previous?.get(schemaId)?.input !== schemaInput,
        });
      }
      const semanticErrors = capabilityErrors.filter(
        (item) => !schemaDiagnostics.has(item),
      );
      for (const item of semanticErrors) assignedDiagnostics.add(item);
      const capabilityId = `capability:${capability.id}`;
      capabilityNodeIds.push(capabilityId);
      const capabilityDependencies = [
        moduleId,
        ...schemaNodeIds,
        ...new Set(
          (useKeysByCapability.get(capability.id) ?? []).flatMap((key) => {
            const name = sharedUseByKey.get(key);
            return name ? [`schema:shared/${encode(name)}`] : [];
          }),
        ),
        ...(resolvedCapability?.configDependencies ?? []),
      ];
      const schemaBlockers = schemaNodeIds.filter((id) =>
        drafts.some(
          (draft) =>
            draft.id === id && (draft.failure !== undefined || draft.blocked),
        ),
      );
      const capabilityBlockers = [
        ...(moduleIsUnavailable ? [moduleId] : []),
        ...schemaBlockers,
      ];
      const capabilityCanSucceed =
        semanticErrors.length === 0 && capabilityBlockers.length === 0;
      const capabilityOutput =
        resolvedCapability && capabilityCanSucceed
          ? bytes(resolvedCapability.ir as JsonValue)
          : undefined;
      const capabilityInput =
        resolvedCapability && capabilityCanSucceed
          ? nodeInputFingerprint(
              capabilityId,
              "capaxle:capability-resolution@1",
              { capability: resolvedCapability.ir } as unknown as JsonValue,
              capabilityDependencies,
              drafts,
            )
          : undefined;
      const capabilityDraft: NodeDraft = {
        id: capabilityId,
        dependencies: capabilityDependencies,
        ...(semanticErrors.length
          ? { failure: uniqueCodes(semanticErrors), executed: true }
          : capabilityBlockers.length
            ? { blocked: capabilityBlockers }
            : resolvedCapability && capabilityOutput && capabilityInput
              ? {
                  output: capabilityOutput,
                  input: capabilityInput,
                  executed:
                    previous?.get(capabilityId)?.input !== capabilityInput,
                }
              : {
                  failure: ["CAP_GRAPH_NODE_INVALID" as const],
                  executed: true,
                }),
      };
      drafts.push(capabilityDraft);
      const provenanceId = `provenance:${capability.id}`;
      provenanceNodeIds.push(provenanceId);
      const provenanceDependencies = [
        capabilityId,
        moduleId,
        ...(resolvedCapability?.configDependencies ?? []),
      ];
      const provenanceBlockers = provenanceDependencies.filter((id) =>
        drafts.some(
          (draft) =>
            draft.id === id && (draft.failure !== undefined || draft.blocked),
        ),
      );
      if (provenanceBlockers.length)
        drafts.push({
          id: provenanceId,
          dependencies: provenanceDependencies,
          blocked: provenanceBlockers,
        });
      else if (resolvedCapability) {
        const provenanceLocalInputs = {
          source: {
            file: resolvedCapability.source.file,
            sourceHash: resolvedCapability.sourceHash,
          },
          provenance: resolvedCapability.registry.provenance,
        } as unknown as JsonValue;
        const provenanceInput = nodeInputFingerprint(
          provenanceId,
          "capaxle:provenance@1",
          provenanceLocalInputs,
          provenanceDependencies,
          drafts,
        );
        drafts.push({
          id: provenanceId,
          dependencies: provenanceDependencies,
          output: bytes(provenanceLocalInputs),
          input: provenanceInput,
          executed: previous?.get(provenanceId)?.input !== provenanceInput,
        });
      }
    }
    const unassignedErrors = errorDiagnostics.filter(
      (item) => !assignedDiagnostics.has(item),
    );
    const documentDependencies = [
      "config:service",
      "source:manifest",
      ...capabilityNodeIds,
      ...sharedSchemaNodeIds,
    ];
    const documentBlockers = documentDependencies.filter((id) =>
      drafts.some(
        (draft) =>
          draft.id === id && (draft.failure !== undefined || draft.blocked),
      ),
    );
    drafts.push({
      id: "document:capability-ir",
      dependencies: documentDependencies,
      ...(documentBlockers.length
        ? { blocked: documentBlockers }
        : {
            failure: uniqueCodes(unassignedErrors).length
              ? uniqueCodes(unassignedErrors)
              : ["CAP_GRAPH_NODE_INVALID"],
          }),
    });
    drafts.push({
      id: "artifact:capaxle.ir",
      dependencies: ["document:capability-ir"],
      blocked: ["document:capability-ir"],
    });
    const registryDependencies = [
      "document:capability-ir",
      ...provenanceNodeIds,
    ];
    drafts.push({
      id: "artifact:capaxle.compiler-registry",
      dependencies: registryDependencies,
      blocked: registryDependencies.filter((id) =>
        drafts.some(
          (draft) =>
            draft.id === id && (draft.failure !== undefined || draft.blocked),
        ),
      ),
    });
    drafts.push({
      id: "artifact:capaxle.artifact-index",
      dependencies: [
        "artifact:capaxle.ir",
        "artifact:capaxle.compiler-registry",
      ],
      blocked: ["artifact:capaxle.ir", "artifact:capaxle.compiler-registry"],
    });
    const graph = graphReport(generation, drafts, previous);
    return {
      result: Object.freeze({
        ok: false,
        graph,
        diagnostics: sortCompilationDiagnostics(diagnostics),
      }),
      cache: new Map(),
    };
  }
  const irHash = capabilitySemanticHash(document) as Sha256;
  const irBytes = bytes(document as unknown as JsonValue);
  const registryCaps = resolved
    .map((item) =>
      Object.freeze({
        ...item.registry,
        source: { file: item.source.file, sourceHash: item.sourceHash },
      }),
    )
    .sort((a, b) => compareText(a.id, b.id));
  const registry: ResolvedCompilerRegistry = deepFreeze({
    registryVersion: "0.1",
    irVersion: "0.1",
    irHash,
    capabilities: registryCaps,
  });
  const registryBytes = bytes(registry as unknown as JsonValue);
  const pushConfigNode = (id: string, value: JsonValue): void => {
    const output = bytes(value);
    const input = nodeInputFingerprint(
      id,
      "capaxle:config-leaf@1",
      value,
      [],
      drafts,
    );
    drafts.push({
      id,
      dependencies: [],
      output,
      input,
      executed: previous?.get(id)?.input !== input,
    });
  };
  pushConfigNode("config:service", config.service as JsonValue);
  pushConfigNode("config:discovery/root", discovery.config.root);
  pushConfigNode("config:discovery/ignore", [...discovery.config.ignore]);
  pushConfigNode(
    "config:discovery/allow-id-override",
    discovery.config.allowIdOverride,
  );
  for (const surface of surfaces)
    pushConfigNode(
      `config:exposure-default/${surface}`,
      config.exposureDefaults[surface],
    );
  pushConfigNode("config:http-prefix", config.httpPrefix);
  pushConfigNode("config:http-header-allowlist", [
    ...config.httpHeaderAllowlist,
  ]);
  pushConfigNode(
    "config:http-discovery/collection",
    config.discovery.http.collection,
  );
  pushConfigNode(
    "config:http-discovery/detail-template",
    config.discovery.http.detailTemplate,
  );
  pushConfigNode(
    "config:http-discovery/schema-template",
    config.discovery.http.schemaTemplate,
  );
  pushConfigNode("config:mcp-endpoint", config.discovery.mcp.endpoint);
  for (const [capabilityId, override] of Object.entries(config.projections))
    for (const surface of ["http", "cli", "mcp", "docs", "sdk"] as const)
      if (surface in override)
        pushConfigNode(
          `config:projection/${encode(capabilityId)}/${surface}`,
          override[surface] as JsonValue,
        );
  for (const item of projectSources.values()) {
    const output = moduleOutputs.get(item.path)!;
    const id = `module:${encode(item.path)}`;
    const input = moduleInputs.get(item.path)!;
    drafts.push({
      id,
      dependencies: item.imports.map((path) => `module:${encode(path)}`),
      output,
      input,
      executed: executedModules.has(item.path),
    });
  }
  const sourceManifestDependencies = [
    "config:discovery/root",
    "config:discovery/ignore",
    ...[...projectSources.values()].map(
      (item) => `module:${encode(item.path)}`,
    ),
  ];
  const sourceManifestInput = nodeInputFingerprint(
    "source:manifest",
    "capaxle:source-manifest@1",
    { sources: sourceManifest.sources } as unknown as JsonValue,
    sourceManifestDependencies,
    drafts,
  );
  drafts.push({
    id: "source:manifest",
    dependencies: sourceManifestDependencies,
    output: sourceManifestBytes,
    input: sourceManifestInput,
    executed: previous?.get("source:manifest")?.input !== sourceManifestInput,
  });
  const sharedSchemaIds = sharedNames.map((name) => {
    const schema = schemas.schemas[name]!;
    const id = `schema:shared/${encode(name)}`;
    const output = bytes(schema);
    const { dependencies, localInputs } = sharedGraphData(name);
    const input = nodeInputFingerprint(
      id,
      "capaxle:shared-schema@1",
      localInputs,
      dependencies,
      drafts,
    );
    drafts.push({
      id,
      dependencies: [...dependencies],
      output,
      input,
      executed: true,
    });
    return id;
  });
  for (const item of resolved) {
    const schemaEntries: Array<readonly [string, JsonValue]> = [
      ["input", item.ir.input!],
      ["output", item.ir.output!],
      ...Object.entries(item.ir.errors as Record<string, JsonValue>)
        .filter(([, error]) =>
          Object.prototype.hasOwnProperty.call(error, "details"),
        )
        .map(
          ([code, error]) =>
            [
              `error/${encode(code)}`,
              (error as Record<string, JsonValue>).details!,
            ] as const,
        ),
    ];
    const schemaDependencies = schemaEntries.map(
      ([role]) => `schema:${encode(item.registry.id)}/${role}`,
    );
    for (const [role, schema] of schemaEntries) {
      const schemaId = `schema:${encode(item.registry.id)}/${role}`;
      const useKey = schemaUseKey(item.registry.id, role);
      const sharedName = sharedUseByKey.get(useKey);
      const schemaNodeDependencies = [
        `module:${encode(item.source.file)}`,
        ...(sharedName ? [`schema:shared/${encode(sharedName)}`] : []),
      ];
      const schemaBytes = bytes(schema);
      const schemaInput = nodeInputFingerprint(
        schemaId,
        "capaxle:schema@1",
        (sharedName
          ? { reference: schema }
          : {
              providerId: schemaOccurrenceByKey.get(useKey)?.providerId ?? null,
              schema,
              toolchainFingerprint: currentToolchain,
            }) as JsonValue,
        schemaNodeDependencies,
        drafts,
      );
      const oldSchema = previous?.get(schemaId);
      drafts.push({
        id: schemaId,
        dependencies: schemaNodeDependencies,
        output: schemaBytes,
        input: schemaInput,
        executed:
          (!sharedUseByKey.has(useKey) && executedSchemaUseKeys.has(useKey)) ||
          !(oldSchema && oldSchema.input === schemaInput),
      });
    }
    const referencedSharedSchemas = sharedReferences(item.ir as JsonValue).map(
      (name) => `schema:shared/${encode(name)}`,
    );
    const deps = [
      `module:${encode(item.source.file)}`,
      ...schemaDependencies,
      ...referencedSharedSchemas,
      ...item.configDependencies,
    ];
    const nodeBytes = bytes(item.ir as JsonValue);
    const id = `capability:${item.registry.id}`;
    const input = nodeInputFingerprint(
      id,
      "capaxle:capability-resolution@1",
      { capability: item.ir } as unknown as JsonValue,
      deps,
      drafts,
    );
    const old = previous?.get(id);
    drafts.push({
      id,
      dependencies: deps,
      output: nodeBytes,
      input,
      executed: !(old && old.input === input),
    });
    const provenanceId = `provenance:${item.registry.id}`;
    const provenanceDependencies = [
      id,
      `module:${encode(item.source.file)}`,
      ...item.configDependencies,
    ];
    const provenanceLocalInputs = {
      source: { file: item.source.file, sourceHash: item.sourceHash },
      provenance: item.registry.provenance,
    } as unknown as JsonValue;
    const provenanceInput = nodeInputFingerprint(
      provenanceId,
      "capaxle:provenance@1",
      provenanceLocalInputs,
      provenanceDependencies,
      drafts,
    );
    drafts.push({
      id: provenanceId,
      dependencies: provenanceDependencies,
      output: bytes(provenanceLocalInputs),
      input: provenanceInput,
      executed: previous?.get(provenanceId)?.input !== provenanceInput,
    });
  }
  const documentDependencies = [
    "config:service",
    "source:manifest",
    ...resolved.map((item) => `capability:${item.registry.id}`),
    ...sharedSchemaIds,
  ];
  const documentInput = nodeInputFingerprint(
    "document:capability-ir",
    "capaxle:capability-document@1",
    { irVersion: "0.1", metadata: document.metadata } as JsonValue,
    documentDependencies,
    drafts,
  );
  drafts.push({
    id: "document:capability-ir",
    dependencies: documentDependencies,
    output: irBytes,
    input: documentInput,
    executed: previous?.get("document:capability-ir")?.input !== documentInput,
  });
  let artifacts: CompiledArtifact[] = [
    artifact(
      "capaxle.ir",
      "capabilities.ir.json",
      "application/json",
      "capaxle:capability-ir@0.1",
      { id: "capaxle.compiler", version: COMPILER_VERSION },
      irBytes,
    ),
    artifact(
      "capaxle.compiler-registry",
      "capabilities.registry.json",
      "application/json",
      "capaxle:compiler-registry@0.1",
      { id: "capaxle.compiler", version: COMPILER_VERSION },
      registryBytes,
    ),
  ];
  const pushBuiltinArtifact = (
    id: string,
    output: Uint8Array,
    dependencies: readonly string[],
    target: string,
  ): void => {
    const input = nodeInputFingerprint(
      id,
      "capaxle:builtin-artifact@1",
      {
        producer: { id: "capaxle.compiler", version: COMPILER_VERSION },
        target,
      },
      dependencies,
      drafts,
    );
    drafts.push({
      id,
      dependencies: [...dependencies],
      output,
      input,
      executed: previous?.get(id)?.input !== input,
    });
  };
  pushBuiltinArtifact(
    "artifact:capaxle.ir",
    irBytes,
    ["document:capability-ir"],
    "capaxle:capability-ir@0.1",
  );
  pushBuiltinArtifact(
    "artifact:capaxle.compiler-registry",
    registryBytes,
    [
      "document:capability-ir",
      ...resolved.map((item) => `provenance:${item.registry.id}`),
    ],
    "capaxle:compiler-registry@0.1",
  );
  const available = new Map<string, Uint8Array>(
    drafts.filter((item) => item.output).map((item) => [item.id, item.output!]),
  );
  const pending = producerList
    .flatMap((producer) =>
      producer.artifacts.map((item) => ({ producer, item })),
    )
    .sort((left, right) => compareText(left.item.id, right.item.id));
  const allArtifactNodeIds = Object.freeze(
    [
      "artifact:capaxle.ir",
      "artifact:capaxle.compiler-registry",
      ...pending.map(({ item }) => `artifact:${item.id}`),
    ].sort(compareText),
  );
  const publicIds = new Set([
    ...available.keys(),
    ...pending.map(({ item }) => `artifact:${item.id}`),
  ]);
  for (let index = 0; index < pending.length;) {
    const { item } = pending[index]!;
    if (item.dependencies.some((id) => !publicIds.has(id))) {
      diagnostics.push(
        diagnostic(
          "CAP_GRAPH_DEPENDENCY_UNKNOWN",
          "graph",
          "graph-dependency",
          "Artifact dependency does not exist.",
          PROJECT_SOURCE,
          "/artifactProducers",
        ),
      );
      drafts.push({
        id: `artifact:${item.id}`,
        dependencies: [...item.dependencies],
        failure: ["CAP_GRAPH_DEPENDENCY_UNKNOWN"],
      });
      pending.splice(index, 1);
    } else index++;
  }
  const pendingById = new Map<string, (typeof pending)[number]>(
    pending.map((entry) => [`artifact:${entry.item.id}`, entry] as const),
  );
  const cyclicProducerNodes = new Set<string>();
  let producerIndex = 0;
  const producerIndices = new Map<string, number>();
  const producerLows = new Map<string, number>();
  const producerStack: string[] = [];
  const stackedProducerNodes = new Set<string>();
  const visitProducer = (id: string): void => {
    producerIndices.set(id, producerIndex);
    producerLows.set(id, producerIndex++);
    producerStack.push(id);
    stackedProducerNodes.add(id);
    for (const dependency of pendingById.get(id)!.item.dependencies) {
      if (!pendingById.has(dependency)) continue;
      if (!producerIndices.has(dependency)) {
        visitProducer(dependency);
        producerLows.set(
          id,
          Math.min(producerLows.get(id)!, producerLows.get(dependency)!),
        );
      } else if (stackedProducerNodes.has(dependency))
        producerLows.set(
          id,
          Math.min(producerLows.get(id)!, producerIndices.get(dependency)!),
        );
    }
    if (producerLows.get(id) !== producerIndices.get(id)) return;
    const component: string[] = [];
    let member: string;
    do {
      member = producerStack.pop()!;
      stackedProducerNodes.delete(member);
      component.push(member);
    } while (member !== id);
    if (
      component.length > 1 ||
      pendingById
        .get(id)!
        .item.dependencies.includes(id as ProducerDependencyId)
    )
      for (const nodeId of component) cyclicProducerNodes.add(nodeId);
  };
  for (const id of [...pendingById.keys()].sort(compareText))
    if (!producerIndices.has(id)) visitProducer(id);
  if (cyclicProducerNodes.size) {
    diagnostics.push(
      diagnostic(
        "CAP_GRAPH_CYCLE",
        "graph",
        "graph-cycle",
        "Artifact dependency graph contains a cycle.",
      ),
    );
    for (let index = 0; index < pending.length;) {
      const { item } = pending[index]!;
      const nodeId = `artifact:${item.id}`;
      if (!cyclicProducerNodes.has(nodeId)) {
        index++;
        continue;
      }
      drafts.push({
        id: nodeId,
        dependencies: [...item.dependencies],
        failure: ["CAP_GRAPH_CYCLE"],
      });
      pending.splice(index, 1);
    }
  }
  while (pending.length) {
    let progressed = false;
    for (let index = 0; index < pending.length;) {
      const { producer, item } = pending[index]!;
      const nodeId = `artifact:${item.id}`;
      const invalidDependency = item.dependencies.find(
        (id) => !publicIds.has(id),
      );
      if (invalidDependency) {
        diagnostics.push(
          diagnostic(
            "CAP_GRAPH_DEPENDENCY_UNKNOWN",
            "graph",
            "graph-dependency",
            "Artifact dependency does not exist.",
            PROJECT_SOURCE,
            "/artifactProducers",
          ),
        );
        drafts.push({
          id: nodeId,
          dependencies: [...item.dependencies],
          failure: ["CAP_GRAPH_DEPENDENCY_UNKNOWN"],
        });
        pending.splice(index, 1);
        progressed = true;
        continue;
      }
      const blockedBy = item.dependencies.filter((id) =>
        drafts.some(
          (draft) => draft.id === id && (draft.failure || draft.blocked),
        ),
      );
      if (blockedBy.length) {
        drafts.push({
          id: nodeId,
          dependencies: [...item.dependencies],
          blocked: blockedBy,
        });
        pending.splice(index, 1);
        progressed = true;
        continue;
      }
      if (!item.dependencies.every((id) => available.has(id))) {
        index++;
        continue;
      }
      const dependencyDigests = new ImmutableMap(
        item.dependencies.map((id) => [id, sha(available.get(id)!)] as const),
      ) as ReadonlyMap<ProducerDependencyId, Sha256>;
      const dependencyBytes = new ImmutableMap(
        item.dependencies.map(
          (id) => [id, new Uint8Array(available.get(id)!)] as const,
        ),
        (value) => new Uint8Array(value),
      ) as ReadonlyMap<ProducerDependencyId, Uint8Array>;
      const buildContext = {
        irHash,
        discovery: config.discovery,
        ...(config.cliBinary ? { cliBinary: config.cliBinary } : {}),
      };
      const inputObject = {
        artifact: {
          id: item.id,
          mediaType: item.mediaType,
          path: item.path,
          target: item.target,
        },
        buildContext: {
          cliBinary: config.cliBinary ?? null,
          discovery: config.discovery,
          irHash,
        },
        contractVersion: "0.1",
        dependencies: [...dependencyDigests]
          .map(([id, outputDigest]) => ({ id, outputDigest }))
          .sort((a, b) => compareText(a.id, b.id)),
        diagnosticCodes: [...producer.diagnosticCodes]
          .map((entry) => ({
            code: entry.code,
            severities: [...new Set(entry.severities)].sort((a, b) =>
              a === b ? 0 : a === "warning" ? -1 : 1,
            ),
          }))
          .sort((a, b) => compareText(a.code, b.code)),
        producer: { id: producer.id, version: producer.version },
        sourceManifestDigest,
        staticInputs: producer.staticInputs ?? {},
      };
      const input = sha(jcs(inputObject as unknown as JsonValue));
      const cached = previous?.get(nodeId);
      if (cached && cached.input === input) {
        available.set(nodeId, cached.bytes);
        artifacts.push(
          artifact(
            item.id,
            item.path,
            item.mediaType,
            item.target,
            { id: producer.id, version: producer.version },
            cached.bytes,
          ),
        );
        diagnostics.push(...(cached.warnings ?? []));
        drafts.push({
          id: nodeId,
          dependencies: [...item.dependencies],
          input,
          output: cached.bytes,
          executed: false,
        });
        pending.splice(index, 1);
        progressed = true;
        continue;
      }
      let result;
      let producerThrew = false;
      try {
        const context: ArtifactBuildContext = deepFreeze({
          buildContext,
          producer: { id: producer.id, version: producer.version },
          artifact: {
            id: item.id,
            path: item.path,
            mediaType: item.mediaType,
            target: item.target,
          },
          staticInputs: producer.staticInputs ?? {},
          dependencyDigests,
          dependencyBytes,
        });
        result = await item.produce(context);
      } catch {
        producerThrew = true;
        result = undefined;
      }
      const declared = new Map(
        producer.diagnosticCodes.map((entry) => [
          entry.code,
          new Set(entry.severities),
        ]),
      );
      const valid = validatedProducerResult(
        result,
        item.target,
        declared,
        new Map(
          resolved.map((capability) => [capability.registry.id, capability]),
        ),
      );
      if (!valid) {
        diagnostics.push(
          diagnostic(
            "CAP_ARTIFACT_GENERATION_FAILED",
            "emission",
            "emission-producer",
            "Artifact producer returned an invalid result or failed unexpectedly.",
            PROJECT_SOURCE,
            undefined,
            {
              artifactId: item.id,
              producerId: producer.id,
              target: item.target,
              reason: producerThrew ? "unexpected" : "invalid-result",
            },
          ),
        );
        drafts.push({
          id: nodeId,
          dependencies: [...item.dependencies],
          input,
          failure: ["CAP_ARTIFACT_GENERATION_FAILED"],
          executed: true,
        });
        pending.splice(index, 1);
        progressed = true;
        continue;
      }
      const adapted = valid.diagnostics.map((entry) => {
        const producerDetails =
          entry.details === undefined ? undefined : portableCopy(entry.details);
        return compilationDiagnostic({
          code: entry.code,
          severity: entry.severity,
          phase: "emission",
          subphase: "emission-producer",
          message: entry.message,
          source: entry.capabilityId
            ? resolved.find((cap) => cap.registry.id === entry.capabilityId)!
                .source
            : PROJECT_SOURCE,
          ...(entry.path === undefined ? {} : { path: entry.path }),
          details: {
            artifactId: item.id,
            producerId: producer.id,
            ...(producerDetails?.ok !== true
              ? {}
              : { producerDetails: producerDetails.value }),
            target: item.target,
          },
        });
      });
      diagnostics.push(...adapted);
      if (!valid.ok) {
        drafts.push({
          id: nodeId,
          dependencies: [...item.dependencies],
          input,
          failure: valid.diagnostics
            .filter((entry) => entry.severity === "error")
            .map((entry) => entry.code),
          executed: true,
        });
        pending.splice(index, 1);
        progressed = true;
        continue;
      }
      const produced = new Uint8Array(valid.bytes);
      available.set(nodeId, produced);
      artifacts.push(
        artifact(
          item.id,
          item.path,
          item.mediaType,
          item.target,
          { id: producer.id, version: producer.version },
          produced,
        ),
      );
      drafts.push({
        id: nodeId,
        dependencies: [...item.dependencies],
        input,
        output: produced,
        executed: true,
      });
      pending.splice(index, 1);
      progressed = true;
    }
    if (!progressed) break;
  }
  if (pending.length) {
    diagnostics.push(
      diagnostic(
        "CAP_GRAPH_NODE_INVALID",
        "graph",
        "graph-execution",
        "Artifact dependency scheduling did not make progress.",
      ),
    );
    for (const { item } of pending)
      drafts.push({
        id: `artifact:${item.id}`,
        dependencies: [...item.dependencies],
        failure: ["CAP_GRAPH_NODE_INVALID"],
      });
  }
  const hasProducerError = diagnostics.some(
    (item) => item.severity === "error",
  );
  if (hasProducerError)
    drafts.push({
      id: "artifact:capaxle.artifact-index",
      dependencies: [...allArtifactNodeIds],
      blocked: allArtifactNodeIds.filter((id) =>
        drafts.some((item) => item.id === id && (item.failure || item.blocked)),
      ),
    });
  else {
    const indexEntries = artifacts
      .map((item) => ({
        id: item.id,
        mediaType: item.mediaType,
        path: item.path,
        sha256: item.sha256,
        target: item.target,
        irVersion: "0.1" as const,
        irHash,
        service: {
          name: config.service.name as string,
          version: config.service.version as string,
        },
        producer: item.producer,
      }))
      .sort((a, b) => compareText(a.id, b.id));
    const artifactGraphVersion = rootPublication ? "0.2" : "0.1";
    const preimage = {
      artifactGraphVersion,
      artifacts: indexEntries,
      compiler: COMPILER,
      irHash,
      irVersion: "0.1",
      service: {
        name: config.service.name as string,
        version: config.service.version as string,
      },
    };
    const buildId = sha(jcs(preimage as unknown as JsonValue));
    const indexBytes = bytes({ ...preimage, buildId } as unknown as JsonValue);
    const indexInput = nodeInputFingerprint(
      "artifact:capaxle.artifact-index",
      "capaxle:artifact-index@1",
      {
        compiler: COMPILER,
        irVersion: "0.1",
        service: preimage.service,
      } as unknown as JsonValue,
      allArtifactNodeIds,
      drafts,
    );
    artifacts.push(
      artifact(
        "capaxle.artifact-index",
        "artifacts.json",
        "application/json",
        `capaxle:artifact-index@${artifactGraphVersion}`,
        { id: "capaxle.compiler", version: COMPILER_VERSION },
        indexBytes,
      ),
    );
    drafts.push({
      id: "artifact:capaxle.artifact-index",
      dependencies: [...allArtifactNodeIds],
      output: indexBytes,
      input: indexInput,
      executed:
        previous?.get("artifact:capaxle.artifact-index")?.input !== indexInput,
    });
  }
  const graph = graphReport(generation, drafts, previous);
  const cache = new Map<string, CacheEntry>();
  for (const node of graph.nodes)
    if (
      (node.status === "succeeded" || node.status === "reused") &&
      node.inputFingerprint &&
      node.outputDigest
    ) {
      const draft = drafts.find((item) => item.id === node.id)!;
      cache.set(node.id, {
        input: node.inputFingerprint,
        output: node.outputDigest,
        bytes: new Uint8Array(draft.output!),
        warnings: diagnostics.filter(
          (item) =>
            node.id.startsWith("artifact:") &&
            item.severity === "warning" &&
            item.subphase === "emission-producer" &&
            typeof item.details === "object" &&
            item.details !== null &&
            !Array.isArray(item.details) &&
            (item.details as Record<string, JsonValue>).artifactId ===
              node.id.slice("artifact:".length),
        ),
      });
    }
  const sortedDiagnostics = sortCompilationDiagnostics(diagnostics);
  if (sortedDiagnostics.some((item) => item.severity === "error"))
    return {
      result: Object.freeze({
        ok: false,
        graph,
        diagnostics: sortedDiagnostics,
      }),
      cache,
    };
  artifacts = artifacts.sort((a, b) => compareText(a.id, b.id));
  const validators = new ImmutableMap(
    resolved.map((item) => [item.registry.id, item.validators] as const),
  );
  const runtimeBindings = new ImmutableMap(
    resolved.map((item) => {
      const identity = {
        id: item.registry.id,
        version: item.ir.version as string,
        irHash,
      };
      const binding = getBindingHandle(item.sourceObject, identity);
      if (!binding) {
        const error = new Error(
          "Compiler-authentic capability lost its private binding.",
        );
        Object.defineProperty(error, "code", {
          enumerable: true,
          value: "CAP_COMPILER_BINDING_MISSING",
        });
        throw error;
      }
      return [identity.id, Object.freeze({ ...identity, binding })] as const;
    }),
  );
  const value: Record<string, unknown> = {
    ok: true,
    document: deepFreeze(document),
    irHash,
    discovery: config.discovery,
    ...(config.cliRemoteOnly ? { cliRemoteOnly: true } : {}),
    registry,
    validators,
    runtimeBindings,
    artifacts: Object.freeze(artifacts),
    ...(rootPublication ? { rootPublication } : {}),
    graph,
    diagnostics: sortedDiagnostics,
  };
  const irCopy = new Uint8Array(irBytes);
  Object.defineProperty(value, "irBytes", {
    enumerable: true,
    get: () => new Uint8Array(irCopy),
  });
  const success = Object.freeze(value) as unknown as CompilationSuccess;
  successIdentity.set(success, {
    projectRoot: options.projectRoot,
    outputDirectory: config.outputDirectory,
    outputExplicit: config.outputExplicit,
    outputSource: config.outputSource,
    cliBinary: config.cliBinary,
    toolchain: currentToolchain,
    current: true,
  });
  return { result: success, cache };
}

export async function compileProject(
  options: CompilerOptions,
): Promise<CompilationResult> {
  if (!isAbsolute(options.projectRoot))
    throw new TypeError("projectRoot must be an absolute filesystem path.");
  return (await compileGeneration(options, 1)).result;
}

export class CompilerSessionClosedError extends Error {
  readonly code = "CAP_COMPILER_SESSION_CLOSED" as const;
  constructor() {
    super("Compiler session is closing or closed.");
    this.name = "CompilerSessionClosedError";
  }
}
export class CompilerSessionCloseError extends Error {
  readonly code = "CAP_COMPILER_SESSION_CLOSE_FAILED" as const;
  constructor() {
    super("Compiler session cleanup failed.");
    this.name = "CompilerSessionCloseError";
  }
}

const SESSION_CLEANUP_HOOK = Symbol.for(
  "@capaxle/compiler/test-session-cleanup@1",
);

export async function createCompilerSession(
  options: CompilerOptions,
): Promise<CompilerSession> {
  if (!isAbsolute(options.projectRoot))
    throw new TypeError("projectRoot must be an absolute filesystem path.");
  let sessionOptions: CompilerOptions | undefined = options;
  let sessionProviderValidation: SchemaProviderValidation | undefined =
    validateSchemaProviders(options);
  let sessionToolchain: Sha256 | undefined;
  let state: "open" | "closing" | "closed" = "open";
  let snapshot: CompilationUpdate | undefined;
  let generation = 0;
  let cache: Cache | undefined;
  let active: CompilationSuccess | undefined;
  const authorizedSuccesses = new Set<CompilationSuccess>();
  type Job = {
    readonly resolve: (value: CompilationUpdate) => void;
    readonly reject: (error: Error) => void;
  };
  const queue: Job[] = [];
  let running = false;
  let closePromise: Promise<void> | undefined;
  let closeResolve: (() => void) | undefined;
  let closeReject: ((error: CompilerSessionCloseError) => void) | undefined;
  let cleanupHook: (() => void | Promise<void>) | undefined;
  try {
    const descriptor = Object.getOwnPropertyDescriptor(
      options,
      SESSION_CLEANUP_HOOK,
    );
    if (
      descriptor &&
      "value" in descriptor &&
      typeof descriptor.value === "function"
    )
      cleanupHook = descriptor.value as () => void | Promise<void>;
  } catch {
    cleanupHook = undefined;
  }
  const finishClose = async (): Promise<void> => {
    for (const success of authorizedSuccesses) {
      const identity = successIdentity.get(success);
      if (identity) identity.current = false;
      successIdentity.delete(success);
    }
    authorizedSuccesses.clear();
    active = undefined;
    cache?.clear();
    cache = undefined;
    sessionOptions = undefined;
    sessionProviderValidation = undefined;
    sessionToolchain = undefined;
    state = "closed";
    try {
      await cleanupHook?.();
      cleanupHook = undefined;
      closeResolve?.();
    } catch {
      cleanupHook = undefined;
      closeReject?.(new CompilerSessionCloseError());
    } finally {
      closeResolve = undefined;
      closeReject = undefined;
    }
  };
  const session: CompilerSession = {
    get snapshot() {
      return snapshot;
    },
    compile(compileOptions = {}) {
      if (state !== "open")
        return Promise.reject(new CompilerSessionClosedError());
      if (
        compileOptions.changedPaths &&
        (!Array.isArray(compileOptions.changedPaths) ||
          compileOptions.changedPaths.some(
            (path) =>
              typeof path !== "string" ||
              path.startsWith("/") ||
              path.includes("\\") ||
              path
                .split("/")
                .some((part) => !part || part === "." || part === ".."),
          ))
      )
        return Promise.reject(
          new TypeError(
            "changedPaths must contain project-relative POSIX paths.",
          ),
        );
      return new Promise<CompilationUpdate>((resolveJob, rejectJob) => {
        queue.push({ resolve: resolveJob, reject: rejectJob });
        void drain();
      });
    },
    close() {
      if (closePromise) return closePromise;
      state = "closing";
      closePromise = new Promise<void>((resolveClose, rejectClose) => {
        closeResolve = resolveClose;
        closeReject = rejectClose;
      });
      while (queue.length)
        queue.shift()!.reject(new CompilerSessionClosedError());
      if (!running) void finishClose();
      return closePromise;
    },
  };
  async function drain(): Promise<void> {
    if (running || state !== "open") return;
    const job = queue.shift();
    if (!job) return;
    running = true;
    try {
      const built = await compileGeneration(
        sessionOptions!,
        generation + 1,
        cache,
        sessionToolchain,
        active,
        sessionProviderValidation,
      );
      generation++;
      cache = built.cache;
      if (built.result.ok) {
        sessionToolchain ??= successIdentity.get(built.result)?.toolchain;
        authorizedSuccesses.add(built.result);
        if (active && active !== built.result)
          successIdentity.get(active)!.current = false;
        active = built.result;
      } else if (active) successIdentity.get(active)!.current = false;
      const update = Object.freeze({
        generation,
        result: built.result,
        ...(active ? { active } : {}),
        stale: !built.result.ok && active !== undefined,
      });
      snapshot = update;
      job.resolve(update);
    } catch {
      if (active) successIdentity.get(active)!.current = false;
      generation++;
      const update = Object.freeze({
        generation,
        result: Object.freeze({
          ok: false,
          graph: graphReport(generation, [], cache),
          diagnostics: Object.freeze([
            diagnostic(
              "CAP_GRAPH_NODE_INVALID",
              "graph",
              "graph-execution",
              "Compilation failed unexpectedly.",
            ),
          ]),
        }),
        ...(active ? { active } : {}),
        stale: active !== undefined,
      });
      snapshot = update;
      job.resolve(update);
    } finally {
      running = false;
      if ((state as string) === "closing") {
        while (queue.length)
          queue.shift()!.reject(new CompilerSessionClosedError());
        void finishClose();
      } else void drain();
    }
  }
  return Object.freeze(session);
}

export function compilerSuccessAuthorization(value: CompilationSuccess):
  | {
      readonly projectRoot: string;
      readonly outputDirectory: string;
      readonly outputExplicit: boolean;
      readonly outputSource: CompilationDiagnostic["source"];
      readonly current: boolean;
    }
  | undefined {
  return successIdentity.get(value);
}
