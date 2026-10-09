import type { JsonSchema, JsonValue } from "@capaxle/ir";

export const INTERNAL_FACADE_PRODUCER_ID =
  "capaxle.internal-facade-ts" as const;
export const INTERNAL_FACADE_PRODUCER_VERSION = "0.1.0-alpha.3" as const;
export const INTERNAL_FACADE_ARTIFACT_ID =
  "capaxle.internal-facade-ts" as const;
export const INTERNAL_FACADE_ARTIFACT_PATH = "internal-facade.d.ts" as const;
export const INTERNAL_FACADE_MEDIA_TYPE = "text/typescript" as const;
export const INTERNAL_FACADE_TARGET = "capaxle:internal-facade-ts@0.1" as const;

export const INTERNAL_FACADE_DIAGNOSTIC_CODES = Object.freeze([
  Object.freeze({
    code: "CAP_INTERNAL_FACADE_NAME_COLLISION" as const,
    severities: Object.freeze(["error" as const]),
  }),
  Object.freeze({
    code: "CAP_INTERNAL_FACADE_NAME_INVALID" as const,
    severities: Object.freeze(["error" as const]),
  }),
  Object.freeze({
    code: "CAP_INTERNAL_FACADE_SCHEMA_UNREPRESENTABLE" as const,
    severities: Object.freeze(["error" as const]),
  }),
]);

type ErrorStatus =
  | "invalid_argument"
  | "unauthenticated"
  | "permission_denied"
  | "not_found"
  | "already_exists"
  | "failed_precondition"
  | "conflict"
  | "resource_exhausted"
  | "cancelled"
  | "deadline_exceeded"
  | "unavailable"
  | "internal";

interface SchemaBinding {
  readonly schema?: JsonSchema;
  readonly $ref?: string;
}

export interface InternalFacadeCapabilityDocument {
  readonly irVersion: "0.1";
  readonly service: {
    readonly name: string;
    readonly version: string;
  };
  readonly schemas: Readonly<Record<string, JsonSchema>>;
  readonly capabilities: readonly {
    readonly id: string;
    readonly version: string;
    readonly input: SchemaBinding;
    readonly output: SchemaBinding;
    readonly errors: Readonly<
      Record<
        string,
        {
          readonly status: ErrorStatus;
          readonly message: string;
          readonly retryable: boolean;
          readonly details?: SchemaBinding;
        }
      >
    >;
    readonly access: {
      readonly exposure: { readonly internal: string };
    };
  }[];
}

export type InternalFacadeDiagnosticCode =
  (typeof INTERNAL_FACADE_DIAGNOSTIC_CODES)[number]["code"];

export interface InternalFacadeDiagnostic {
  readonly code: InternalFacadeDiagnosticCode;
  readonly severity: "error";
  readonly message: string;
  readonly target: typeof INTERNAL_FACADE_TARGET;
  readonly capabilityId?: string;
  readonly path?: string;
  readonly details?: JsonValue;
}

export type InternalFacadeGenerationResult =
  | {
      readonly ok: true;
      readonly bytes: Uint8Array;
      readonly diagnostics: readonly [];
    }
  | {
      readonly ok: false;
      readonly diagnostics: readonly InternalFacadeDiagnostic[];
    };

interface SelectedCapability {
  readonly capability: InternalFacadeCapabilityDocument["capabilities"][number];
  readonly index: number;
}

interface AliasSpec {
  readonly identity: AliasIdentity;
  readonly schema: JsonSchema;
  readonly root: AliasRootIdentity;
  readonly path: string;
  readonly capabilityId?: string;
}

type AliasRootIdentity =
  | { readonly kind: "schema"; readonly name: string }
  | {
      readonly kind: "capability";
      readonly id: string;
      readonly version: string;
      readonly binding: "input" | "output" | "error-details";
      readonly errorCode?: string;
    };

interface AliasIdentity {
  readonly root: AliasRootIdentity;
  readonly definition?: string;
}

interface LeafType {
  readonly input: string;
  readonly output: string;
  readonly error: string;
}

interface FacadeNode {
  readonly children: Map<string, FacadeNode>;
  leaf?: LeafType;
}

const reservedSegments = new Set([
  "__proto__",
  "prototype",
  "constructor",
  "then",
  "toJSON",
  "toString",
  "valueOf",
  "inspect",
]);
const capabilityIdPattern = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*$/u;
const identifierPattern = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
const hashPattern = /^sha256:[a-f0-9]{64}$/u;
const semverPattern =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const schemaTypes = new Set([
  "null",
  "boolean",
  "object",
  "array",
  "number",
  "string",
  "integer",
]);
const schemaKeys = new Set([
  "$schema",
  "$ref",
  "$defs",
  "type",
  "enum",
  "const",
  "properties",
  "required",
  "additionalProperties",
  "items",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "multipleOf",
  "minLength",
  "maxLength",
  "pattern",
  "format",
  "minItems",
  "maxItems",
  "uniqueItems",
  "description",
  "default",
  "examples",
  "oneOf",
]);

class SchemaEmissionError extends Error {
  constructor(
    readonly path: string,
    readonly capabilityId?: string,
  ) {
    super("Schema cannot be represented by the internal facade generator.");
  }
}

function compareCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (value) => value.codePointAt(0)!);
  const rightPoints = Array.from(right, (value) => value.codePointAt(0)!);
  for (
    let index = 0;
    index < Math.min(leftPoints.length, rightPoints.length);
    index++
  ) {
    const difference = leftPoints[index]! - rightPoints[index]!;
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

function compareSemVer(left: string, right: string): number {
  const leftMatch = semverPattern.exec(left);
  const rightMatch = semverPattern.exec(right);
  if (!leftMatch || !rightMatch) return compareCodePoints(left, right);
  for (const index of [1, 2, 3]) {
    const difference = BigInt(leftMatch[index]!) - BigInt(rightMatch[index]!);
    if (difference !== 0n) return difference < 0n ? -1 : 1;
  }
  const leftPre = leftMatch[4]?.split(".");
  const rightPre = rightMatch[4]?.split(".");
  if (!leftPre || !rightPre) return leftPre ? -1 : rightPre ? 1 : 0;
  for (
    let index = 0;
    index < Math.min(leftPre.length, rightPre.length);
    index++
  ) {
    const leftPart = leftPre[index]!;
    const rightPart = rightPre[index]!;
    const leftNumeric = /^[0-9]+$/u.test(leftPart);
    const rightNumeric = /^[0-9]+$/u.test(rightPart);
    if (leftNumeric && rightNumeric) {
      const difference = BigInt(leftPart) - BigInt(rightPart);
      if (difference !== 0n) return difference < 0n ? -1 : 1;
    } else if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    else {
      const difference = compareCodePoints(leftPart, rightPart);
      if (difference !== 0) return difference;
    }
  }
  return leftPre.length - rightPre.length;
}

function pointerToken(value: string): string {
  return value.replaceAll("~", "~0").replaceAll("/", "~1");
}

function decodePointerToken(value: string): string {
  return value.replaceAll("~1", "/").replaceAll("~0", "~");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function propertyName(value: string): string {
  return identifierPattern.test(value) ? value : JSON.stringify(value);
}

function literalType(value: JsonValue): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return String(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new SchemaEmissionError("");
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (Array.isArray(value))
    return `readonly [${value.map(literalType).join(", ")}]`;
  const record = value as Readonly<Record<string, JsonValue>>;
  return `{ ${Object.keys(record)
    .sort(compareCodePoints)
    .map(
      (key) => `readonly ${JSON.stringify(key)}: ${literalType(record[key]!)}`,
    )
    .join("; ")} }`;
}

function asJsonValue(value: unknown, path: string): JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  )
    return value;
  if (Array.isArray(value))
    return value.map((item, index) => asJsonValue(item, `${path}/${index}`));
  if (isRecord(value))
    return Object.fromEntries(
      Object.keys(value).map((key) => [
        key,
        asJsonValue(value[key], `${path}/${pointerToken(key)}`),
      ]),
    );
  throw new SchemaEmissionError(path);
}

function diagnostic(
  code: InternalFacadeDiagnosticCode,
  message: string,
  options: {
    readonly capabilityId?: string;
    readonly path?: string;
    readonly details?: JsonValue;
  } = {},
): InternalFacadeDiagnostic {
  return Object.freeze({
    code,
    severity: "error" as const,
    message,
    target: INTERNAL_FACADE_TARGET,
    ...options,
  });
}

function aliasName(index: number): string {
  return `__CapaxleSchema${String(index).padStart(4, "0")}`;
}

function aliasIdentityKey(identity: AliasIdentity): string {
  const { root } = identity;
  return JSON.stringify(
    root.kind === "schema"
      ? ["schema", root.name, identity.definition ?? null]
      : [
          "capability",
          root.id,
          root.version,
          root.binding,
          root.errorCode ?? null,
          identity.definition ?? null,
        ],
  );
}

function rootIdentityKey(root: AliasRootIdentity): string {
  return aliasIdentityKey({ root });
}

function referenceAliasIdentity(
  reference: unknown,
  root: AliasRootIdentity,
): AliasIdentity | undefined {
  if (
    typeof reference === "string" &&
    /^#\/schemas\/(?:[^~/]|~0|~1)+$/u.test(reference)
  )
    return {
      root: {
        kind: "schema",
        name: decodePointerToken(reference.slice(10)),
      },
    };
  if (
    typeof reference === "string" &&
    /^#\/\$defs\/(?:[^~/]|~0|~1)+$/u.test(reference)
  )
    return {
      root,
      definition: decodePointerToken(reference.slice(8)),
    };
  return undefined;
}

function collectAliases(
  document: InternalFacadeCapabilityDocument,
  selected: readonly SelectedCapability[],
): {
  readonly specs: readonly AliasSpec[];
  readonly aliases: ReadonlyMap<string, string>;
} {
  const roots: AliasSpec[] = [];
  for (const name of Object.keys(document.schemas).sort(compareCodePoints)) {
    const root: AliasRootIdentity = { kind: "schema", name };
    roots.push({
      identity: { root },
      schema: document.schemas[name]!,
      root,
      path: `/schemas/${pointerToken(name)}`,
    });
  }
  const addBinding = (
    binding: SchemaBinding,
    root: AliasRootIdentity,
    path: string,
    capabilityId: string,
  ): void => {
    if (binding.schema !== undefined)
      roots.push({
        identity: { root },
        schema: binding.schema,
        root,
        path: `${path}/schema`,
        capabilityId,
      });
  };
  for (const { capability, index } of selected) {
    const base = `/capabilities/${index}`;
    addBinding(
      capability.input,
      {
        kind: "capability",
        id: capability.id,
        version: capability.version,
        binding: "input",
      },
      `${base}/input`,
      capability.id,
    );
    addBinding(
      capability.output,
      {
        kind: "capability",
        id: capability.id,
        version: capability.version,
        binding: "output",
      },
      `${base}/output`,
      capability.id,
    );
    for (const code of Object.keys(capability.errors).sort(compareCodePoints)) {
      const details = capability.errors[code]!.details;
      if (details)
        addBinding(
          details,
          {
            kind: "capability",
            id: capability.id,
            version: capability.version,
            binding: "error-details",
            errorCode: code,
          },
          `${base}/errors/${pointerToken(code)}/details`,
          capability.id,
        );
    }
  }
  const specs = [...roots];
  for (const root of roots) {
    const definitions = root.schema.$defs;
    if (definitions === undefined) continue;
    if (!isRecord(definitions))
      throw new SchemaEmissionError(`${root.path}/$defs`, root.capabilityId);
    for (const name of Object.keys(definitions).sort(compareCodePoints)) {
      const value = definitions[name];
      if (!isRecord(value))
        throw new SchemaEmissionError(
          `${root.path}/$defs/${pointerToken(name)}`,
          root.capabilityId,
        );
      specs.push({
        identity: { root: root.root, definition: name },
        schema: value as JsonSchema,
        root: root.root,
        path: `${root.path}/$defs/${pointerToken(name)}`,
        ...(root.capabilityId === undefined
          ? {}
          : { capabilityId: root.capabilityId }),
      });
    }
  }
  specs.sort((left, right) =>
    compareCodePoints(
      aliasIdentityKey(left.identity),
      aliasIdentityKey(right.identity),
    ),
  );
  return {
    specs,
    aliases: new Map(
      specs.map((spec, index) => [
        aliasIdentityKey(spec.identity),
        aliasName(index),
      ]),
    ),
  };
}

function assertRepresentableAliasCycles(
  specs: readonly AliasSpec[],
  aliases: ReadonlyMap<string, string>,
): void {
  const edges = new Map<string, Set<string>>();
  const specByKey = new Map(
    specs.map((spec) => [aliasIdentityKey(spec.identity), spec]),
  );
  const collectReferences = (
    schema: JsonSchema,
    root: AliasRootIdentity,
    path: string,
    capabilityId: string | undefined,
    guarded: boolean,
    dependencies: Set<string>,
  ): void => {
    if (!isRecord(schema)) throw new SchemaEmissionError(path, capabilityId);
    if (schema.$ref !== undefined) {
      const identity = referenceAliasIdentity(schema.$ref, root);
      const key =
        identity === undefined ? undefined : aliasIdentityKey(identity);
      if (key === undefined || !aliases.has(key))
        throw new SchemaEmissionError(`${path}/$ref`, capabilityId);
      if (!guarded) dependencies.add(key);
      return;
    }
    if (schema.properties !== undefined) {
      if (!isRecord(schema.properties))
        throw new SchemaEmissionError(`${path}/properties`, capabilityId);
      for (const name of Object.keys(schema.properties).sort(
        compareCodePoints,
      )) {
        const child = schema.properties[name];
        if (!isRecord(child))
          throw new SchemaEmissionError(
            `${path}/properties/${pointerToken(name)}`,
            capabilityId,
          );
        collectReferences(
          child as JsonSchema,
          root,
          `${path}/properties/${pointerToken(name)}`,
          capabilityId,
          true,
          dependencies,
        );
      }
    }
    if (schema.items !== undefined) {
      if (!isRecord(schema.items))
        throw new SchemaEmissionError(`${path}/items`, capabilityId);
      collectReferences(
        schema.items as JsonSchema,
        root,
        `${path}/items`,
        capabilityId,
        true,
        dependencies,
      );
    }
    if (schema.oneOf !== undefined) {
      if (!Array.isArray(schema.oneOf))
        throw new SchemaEmissionError(`${path}/oneOf`, capabilityId);
      for (const [index, branch] of schema.oneOf.entries()) {
        if (!isRecord(branch))
          throw new SchemaEmissionError(`${path}/oneOf/${index}`, capabilityId);
        collectReferences(
          branch as JsonSchema,
          root,
          `${path}/oneOf/${index}`,
          capabilityId,
          guarded,
          dependencies,
        );
      }
    }
  };
  for (const spec of specs) {
    const dependencies = new Set<string>();
    collectReferences(
      spec.schema,
      spec.root,
      spec.path,
      spec.capabilityId,
      false,
      dependencies,
    );
    edges.set(aliasIdentityKey(spec.identity), dependencies);
  }
  const state = new Map<string, "visiting" | "visited">();
  const visit = (key: string): void => {
    const current = state.get(key);
    if (current === "visited") return;
    if (current === "visiting") {
      const spec = specByKey.get(key);
      throw new SchemaEmissionError(spec?.path ?? "/", spec?.capabilityId);
    }
    state.set(key, "visiting");
    for (const dependency of edges.get(key) ?? []) visit(dependency);
    state.set(key, "visited");
  };
  for (const key of [...specByKey.keys()].sort(compareCodePoints)) visit(key);
}

function schemaTypeEmitter(
  aliases: ReadonlyMap<string, string>,
  specs: readonly AliasSpec[],
) {
  const specByKey = new Map(
    specs.map((spec) => [aliasIdentityKey(spec.identity), spec]),
  );
  const allRuntimeTypes = new Set([
    "null",
    "boolean",
    "number",
    "string",
    "array",
    "object",
  ]);
  const runtimeType = (value: JsonValue): string => {
    if (value === null) return "null";
    if (Array.isArray(value)) return "array";
    if (typeof value === "object") return "object";
    return typeof value === "number" ? "number" : typeof value;
  };
  const intersect = (left: Set<string>, right: Set<string>): Set<string> =>
    new Set([...left].filter((value) => right.has(value)));
  const referencedSpec = (
    reference: unknown,
    root: AliasRootIdentity,
    path: string,
    capabilityId?: string,
  ): AliasSpec => {
    const identity = referenceAliasIdentity(reference, root);
    const spec =
      identity === undefined
        ? undefined
        : specByKey.get(aliasIdentityKey(identity));
    if (!spec) throw new SchemaEmissionError(path, capabilityId);
    return spec;
  };
  const admittedTypes = (
    schema: JsonSchema,
    root: AliasRootIdentity,
    path: string,
    capabilityId?: string,
    seen: ReadonlySet<string> = new Set(),
  ): Set<string> => {
    if (!isRecord(schema)) throw new SchemaEmissionError(path, capabilityId);
    if (schema.$ref !== undefined) {
      const spec = referencedSpec(
        schema.$ref,
        root,
        `${path}/$ref`,
        capabilityId,
      );
      const key = aliasIdentityKey(spec.identity);
      if (seen.has(key)) return new Set(allRuntimeTypes);
      return admittedTypes(
        spec.schema,
        spec.root,
        spec.path,
        spec.capabilityId,
        new Set([...seen, key]),
      );
    }
    let admitted = new Set(allRuntimeTypes);
    if (schema.type !== undefined) {
      const raw = Array.isArray(schema.type) ? schema.type : [schema.type];
      admitted = intersect(
        admitted,
        new Set(
          raw
            .filter((value): value is string => typeof value === "string")
            .map((value) => (value === "integer" ? "number" : value)),
        ),
      );
    }
    if (Object.hasOwn(schema, "const"))
      admitted = intersect(
        admitted,
        new Set([runtimeType(asJsonValue(schema.const, `${path}/const`))]),
      );
    if (Array.isArray(schema.enum))
      admitted = intersect(
        admitted,
        new Set(
          schema.enum.map((value, index) =>
            runtimeType(asJsonValue(value, `${path}/enum/${index}`)),
          ),
        ),
      );
    if (Array.isArray(schema.oneOf)) {
      const branchTypes = new Set<string>();
      for (const [index, branch] of schema.oneOf.entries()) {
        if (!isRecord(branch))
          throw new SchemaEmissionError(`${path}/oneOf/${index}`, capabilityId);
        for (const type of admittedTypes(
          branch as JsonSchema,
          root,
          `${path}/oneOf/${index}`,
          capabilityId,
          seen,
        ))
          branchTypes.add(type);
      }
      admitted = intersect(admitted, branchTypes);
    }
    return admitted;
  };
  type SchemaConstraint = {
    readonly schema: JsonSchema;
    readonly root: AliasRootIdentity;
    readonly path: string;
    readonly capabilityId: string | undefined;
  };
  type ConstraintAlternatives = readonly (readonly SchemaConstraint[])[];
  type ExpansionState = { remainingWork: number };
  const maxConstraintAlternatives = 256;
  const maxExpansionWork = 8192;
  const maxExpansionDepth = 128;
  const maxExclusivityProofWork = 65_536;
  const canonicalSchemaCache = new WeakMap<object, string>();
  const expansionMemo = new Map<string, ConstraintAlternatives>();
  const referenceExpansionMemo = new Map<string, ConstraintAlternatives>();
  const spendExpansionWork = (
    state: ExpansionState,
    amount: number,
    path: string,
    capabilityId?: string,
  ): void => {
    if (amount > state.remainingWork)
      throw new SchemaEmissionError(path, capabilityId);
    state.remainingWork -= amount;
  };
  const canonicalJson = (
    value: JsonValue,
    state: ExpansionState,
    path: string,
    capabilityId?: string,
    depth = 0,
  ): string => {
    if (depth > maxExpansionDepth)
      throw new SchemaEmissionError(path, capabilityId);
    spendExpansionWork(state, 1, path, capabilityId);
    if (value === null || typeof value !== "object")
      return JSON.stringify(value);
    const cached = canonicalSchemaCache.get(value);
    if (cached !== undefined) return cached;
    let result: string;
    if (Array.isArray(value)) {
      if (value.length > state.remainingWork)
        throw new SchemaEmissionError(path, capabilityId);
      const items: string[] = [];
      for (const item of value)
        items.push(canonicalJson(item, state, path, capabilityId, depth + 1));
      result = `[${items.join(",")}]`;
    } else {
      const keys = Object.keys(value).sort(compareCodePoints);
      if (keys.length > state.remainingWork)
        throw new SchemaEmissionError(path, capabilityId);
      const members: string[] = [];
      for (const key of keys)
        members.push(
          `${JSON.stringify(key)}:${canonicalJson((value as Readonly<Record<string, JsonValue>>)[key]!, state, path, capabilityId, depth + 1)}`,
        );
      result = `{${members.join(",")}}`;
    }
    canonicalSchemaCache.set(value, result);
    return result;
  };
  const constraintKey = (
    constraint: SchemaConstraint,
    state: ExpansionState,
  ): string =>
    JSON.stringify([
      rootIdentityKey(constraint.root),
      constraint.capabilityId ?? null,
      canonicalJson(
        constraint.schema,
        state,
        constraint.path,
        constraint.capabilityId,
      ),
    ]);
  const normalizedAlternative = (
    constraints: readonly SchemaConstraint[],
    state: ExpansionState,
  ): {
    readonly constraints: readonly SchemaConstraint[];
    readonly key: string;
  } => {
    const unique = new Map<string, SchemaConstraint>();
    for (const constraint of constraints) {
      const key = constraintKey(constraint, state);
      if (!unique.has(key)) unique.set(key, constraint);
    }
    return {
      constraints: [...unique.values()],
      key: [...unique.keys()].sort(compareCodePoints).join("\u0000"),
    };
  };
  const finiteLiterals = (
    schema: JsonSchema,
    root: AliasRootIdentity,
    path: string,
    capabilityId?: string,
    seen: ReadonlySet<string> = new Set(),
  ): Map<string, JsonValue> | undefined => {
    if (!isRecord(schema)) throw new SchemaEmissionError(path, capabilityId);
    if (schema.$ref !== undefined) {
      const spec = referencedSpec(
        schema.$ref,
        root,
        `${path}/$ref`,
        capabilityId,
      );
      const key = aliasIdentityKey(spec.identity);
      if (seen.has(key)) return undefined;
      return finiteLiterals(
        spec.schema,
        spec.root,
        spec.path,
        spec.capabilityId,
        new Set([...seen, key]),
      );
    }
    let finite: Map<string, JsonValue> | undefined;
    if (Object.hasOwn(schema, "const")) {
      const value = asJsonValue(schema.const, `${path}/const`);
      finite = new Map([[literalType(value), value]]);
    }
    if (Array.isArray(schema.enum)) {
      const enumeration = new Map(
        schema.enum.map((value, index) => {
          const literal = asJsonValue(value, `${path}/enum/${index}`);
          return [literalType(literal), literal] as const;
        }),
      );
      finite =
        finite === undefined
          ? enumeration
          : new Map([...finite].filter(([key]) => enumeration.has(key)));
    }
    if (Array.isArray(schema.oneOf)) {
      const union = new Map<string, JsonValue>();
      for (const [index, branch] of schema.oneOf.entries()) {
        if (!isRecord(branch))
          throw new SchemaEmissionError(`${path}/oneOf/${index}`, capabilityId);
        const branchFinite = finiteLiterals(
          branch as JsonSchema,
          root,
          `${path}/oneOf/${index}`,
          capabilityId,
          seen,
        );
        if (branchFinite === undefined) return finite;
        for (const [key, value] of branchFinite) union.set(key, value);
      }
      finite =
        finite === undefined
          ? union
          : new Map([...finite].filter(([key]) => union.has(key)));
    }
    return finite;
  };
  const dereference = (
    schema: JsonSchema,
    root: AliasRootIdentity,
    path: string,
    capabilityId?: string,
    seen: ReadonlySet<string> = new Set(),
  ):
    | {
        readonly schema: JsonSchema;
        readonly root: AliasRootIdentity;
        readonly path: string;
        readonly capabilityId: string | undefined;
      }
    | undefined => {
    if (schema.$ref === undefined) return { schema, root, path, capabilityId };
    const spec = referencedSpec(
      schema.$ref,
      root,
      `${path}/$ref`,
      capabilityId,
    );
    const key = aliasIdentityKey(spec.identity);
    if (seen.has(key)) return undefined;
    return dereference(
      spec.schema,
      spec.root,
      spec.path,
      spec.capabilityId,
      new Set([...seen, key]),
    );
  };
  const effectiveTypes = (
    constraints: readonly SchemaConstraint[],
  ): Set<string> =>
    constraints.reduce(
      (types, constraint) =>
        intersect(
          types,
          admittedTypes(
            constraint.schema,
            constraint.root,
            constraint.path,
            constraint.capabilityId,
          ),
        ),
      new Set(allRuntimeTypes),
    );
  const effectiveFiniteLiterals = (
    constraints: readonly SchemaConstraint[],
  ): Map<string, JsonValue> | undefined => {
    let effective: Map<string, JsonValue> | undefined;
    for (const constraint of constraints) {
      const finite = finiteLiterals(
        constraint.schema,
        constraint.root,
        constraint.path,
        constraint.capabilityId,
      );
      if (finite === undefined) continue;
      effective =
        effective === undefined
          ? new Map(finite)
          : new Map([...effective].filter(([key]) => finite.has(key)));
    }
    if (effective === undefined) return undefined;
    const types = effectiveTypes(constraints);
    return new Map(
      [...effective].filter(([, value]) => types.has(runtimeType(value))),
    );
  };
  const requiredDiscriminators = (
    constraints: readonly SchemaConstraint[],
  ): ReadonlyMap<string, Set<string>> => {
    const resolved = constraints.flatMap((constraint) => {
      const value = dereference(
        constraint.schema,
        constraint.root,
        constraint.path,
        constraint.capabilityId,
      );
      return value === undefined ? [] : [value];
    });
    const required = new Set<string>();
    for (const constraint of resolved) {
      if (!Array.isArray(constraint.schema.required)) continue;
      for (const name of constraint.schema.required)
        if (typeof name === "string") required.add(name);
    }
    const result = new Map<string, Set<string>>();
    for (const name of required) {
      const propertyConstraints: SchemaConstraint[] = [];
      for (const constraint of resolved) {
        if (!isRecord(constraint.schema.properties)) continue;
        const property = constraint.schema.properties[name];
        if (!isRecord(property)) continue;
        propertyConstraints.push({
          schema: property as JsonSchema,
          root: constraint.root,
          path: `${constraint.path}/properties/${pointerToken(name)}`,
          capabilityId: constraint.capabilityId,
        });
      }
      const finite = effectiveFiniteLiterals(propertyConstraints);
      if (finite !== undefined) result.set(name, new Set(finite.keys()));
    }
    return result;
  };
  const schemaConstraint = (
    schema: JsonSchema,
    root: AliasRootIdentity,
    path: string,
    capabilityId?: string,
  ): SchemaConstraint => ({ schema, root, path, capabilityId });
  const withoutOneOf = (schema: JsonSchema): JsonSchema => {
    const result = { ...schema };
    delete result.oneOf;
    return result;
  };
  const impossible = (constraints: readonly SchemaConstraint[]): boolean => {
    const types = effectiveTypes(constraints);
    if (types.size === 0) return true;
    const finite = effectiveFiniteLiterals(constraints);
    if (finite !== undefined && finite.size === 0) return true;
    if (types.size !== 1 || !types.has("object")) return false;
    return [...requiredDiscriminators(constraints).values()].some(
      (values) => values.size === 0,
    );
  };
  const expandConstraint = (
    constraint: SchemaConstraint,
    state: ExpansionState,
    seen: ReadonlySet<string> = new Set(),
    depth = 0,
  ): ConstraintAlternatives => {
    if (depth > maxExpansionDepth)
      throw new SchemaEmissionError(constraint.path, constraint.capabilityId);
    const memoKey =
      seen.size === 0 ? constraintKey(constraint, state) : undefined;
    if (memoKey !== undefined) {
      const cached = expansionMemo.get(memoKey);
      if (cached !== undefined) {
        spendExpansionWork(state, 1, constraint.path, constraint.capabilityId);
        return cached;
      }
    }
    spendExpansionWork(state, 1, constraint.path, constraint.capabilityId);
    let result: ConstraintAlternatives;
    if (constraint.schema.$ref !== undefined) {
      const spec = referencedSpec(
        constraint.schema.$ref,
        constraint.root,
        `${constraint.path}/$ref`,
        constraint.capabilityId,
      );
      const key = aliasIdentityKey(spec.identity);
      if (seen.has(key)) result = [[constraint]];
      else {
        const cached = referenceExpansionMemo.get(key);
        if (cached !== undefined) {
          spendExpansionWork(
            state,
            1,
            constraint.path,
            constraint.capabilityId,
          );
          result = cached;
        } else {
          result = expandConstraint(
            schemaConstraint(
              spec.schema,
              spec.root,
              spec.path,
              spec.capabilityId,
            ),
            state,
            new Set([...seen, key]),
            depth + 1,
          );
          referenceExpansionMemo.set(key, result);
        }
      }
    } else if (!Array.isArray(constraint.schema.oneOf)) {
      result = [[constraint]];
    } else {
      const base = schemaConstraint(
        withoutOneOf(constraint.schema),
        constraint.root,
        constraint.path,
        constraint.capabilityId,
      );
      const expanded: SchemaConstraint[][] = [];
      const keys = new Set<string>();
      for (const [index, branch] of constraint.schema.oneOf.entries()) {
        if (!isRecord(branch))
          throw new SchemaEmissionError(
            `${constraint.path}/oneOf/${index}`,
            constraint.capabilityId,
          );
        const choices = expandConstraint(
          schemaConstraint(
            branch as JsonSchema,
            constraint.root,
            `${constraint.path}/oneOf/${index}`,
            constraint.capabilityId,
          ),
          state,
          seen,
          depth + 1,
        );
        for (const choice of choices) {
          spendExpansionWork(
            state,
            1,
            `${constraint.path}/oneOf/${index}`,
            constraint.capabilityId,
          );
          const normalized = normalizedAlternative([base, ...choice], state);
          if (keys.has(normalized.key)) continue;
          if (expanded.length >= maxConstraintAlternatives)
            throw new SchemaEmissionError(
              constraint.path,
              constraint.capabilityId,
            );
          keys.add(normalized.key);
          expanded.push([...normalized.constraints]);
        }
      }
      result = expanded;
    }
    if (memoKey !== undefined) expansionMemo.set(memoKey, result);
    return result;
  };
  const expandAlternatives = (
    alternatives: ConstraintAlternatives,
    state: ExpansionState,
  ): ConstraintAlternatives => {
    const result: SchemaConstraint[][] = [];
    const resultKeys = new Set<string>();
    for (const alternative of alternatives) {
      let expanded = [{ constraints: [] as SchemaConstraint[], key: "" }];
      for (const constraint of alternative) {
        const choices = expandConstraint(constraint, state);
        const next: typeof expanded = [];
        const nextKeys = new Set<string>();
        for (const existing of expanded) {
          for (const choice of choices) {
            spendExpansionWork(
              state,
              1,
              constraint.path,
              constraint.capabilityId,
            );
            const normalized = normalizedAlternative(
              [...existing.constraints, ...choice],
              state,
            );
            if (nextKeys.has(normalized.key)) continue;
            if (next.length >= maxConstraintAlternatives)
              throw new SchemaEmissionError(
                constraint.path,
                constraint.capabilityId,
              );
            nextKeys.add(normalized.key);
            next.push({
              constraints: [...normalized.constraints],
              key: normalized.key,
            });
          }
        }
        expanded = next;
      }
      for (const entry of expanded) {
        if (resultKeys.has(entry.key)) continue;
        if (result.length >= maxConstraintAlternatives) {
          const first = alternative[0];
          throw new SchemaEmissionError(
            first?.path ?? "/",
            first?.capabilityId,
          );
        }
        resultKeys.add(entry.key);
        result.push(entry.constraints);
      }
    }
    return result;
  };
  const compatibleAlternatives = (
    alternatives: ConstraintAlternatives,
    current: SchemaConstraint,
  ): ConstraintAlternatives => {
    const state = { remainingWork: maxExpansionWork };
    return expandAlternatives(alternatives, state).filter((alternative) => {
      spendExpansionWork(state, 1, current.path, current.capabilityId);
      return !impossible([...alternative, current]);
    });
  };
  const deduplicateAlternatives = (
    alternatives: ConstraintAlternatives,
    path: string,
    capabilityId?: string,
  ): ConstraintAlternatives => {
    const state = { remainingWork: maxExpansionWork };
    const result: SchemaConstraint[][] = [];
    const keys = new Set<string>();
    for (const alternative of alternatives) {
      const normalized = normalizedAlternative(alternative, state);
      if (keys.has(normalized.key)) continue;
      if (result.length >= maxConstraintAlternatives)
        throw new SchemaEmissionError(path, capabilityId);
      keys.add(normalized.key);
      result.push([...normalized.constraints]);
    }
    return result;
  };
  const disjoint = (left: Set<string>, right: Set<string>): boolean =>
    [...left].every((value) => !right.has(value));
  const branchesProvablyDisjoint = (
    left: SchemaConstraint,
    right: SchemaConstraint,
    enclosing: readonly SchemaConstraint[],
  ): boolean => {
    const leftConstraints = [...enclosing, left];
    const rightConstraints = [...enclosing, right];
    if (impossible(leftConstraints) || impossible(rightConstraints))
      return true;
    const leftTypes = effectiveTypes(leftConstraints);
    const rightTypes = effectiveTypes(rightConstraints);
    const commonTypes = intersect(leftTypes, rightTypes);
    if (commonTypes.size === 0) return true;
    const leftFinite = effectiveFiniteLiterals(leftConstraints);
    const rightFinite = effectiveFiniteLiterals(rightConstraints);
    if (
      leftFinite !== undefined &&
      rightFinite !== undefined &&
      disjoint(new Set(leftFinite.keys()), new Set(rightFinite.keys()))
    )
      return true;
    if (commonTypes.size !== 1 || !commonTypes.has("object")) return false;
    const leftDiscriminators = requiredDiscriminators(leftConstraints);
    const rightDiscriminators = requiredDiscriminators(rightConstraints);
    for (const [name, leftValues] of leftDiscriminators) {
      const rightValues = rightDiscriminators.get(name);
      if (rightValues && disjoint(leftValues, rightValues)) return true;
    }
    return false;
  };
  const assertExclusiveOneOf = (
    branches: readonly JsonValue[],
    enclosing: ConstraintAlternatives,
    root: AliasRootIdentity,
    path: string,
    capabilityId?: string,
  ): void => {
    const pairCount = (branches.length * (branches.length - 1)) / 2;
    if (
      branches.length > maxConstraintAlternatives ||
      enclosing.length > maxConstraintAlternatives ||
      pairCount * Math.max(1, enclosing.length) > maxExclusivityProofWork
    )
      throw new SchemaEmissionError(path, capabilityId);
    for (let leftIndex = 0; leftIndex < branches.length; leftIndex++) {
      const left = branches[leftIndex];
      if (!isRecord(left))
        throw new SchemaEmissionError(`${path}/${leftIndex}`, capabilityId);
      for (
        let rightIndex = leftIndex + 1;
        rightIndex < branches.length;
        rightIndex++
      ) {
        const right = branches[rightIndex];
        if (!isRecord(right)) throw new SchemaEmissionError(path, capabilityId);
        const leftConstraint = schemaConstraint(
          left as JsonSchema,
          root,
          `${path}/${leftIndex}`,
          capabilityId,
        );
        const rightConstraint = schemaConstraint(
          right as JsonSchema,
          root,
          `${path}/${rightIndex}`,
          capabilityId,
        );
        if (
          enclosing.some(
            (alternative) =>
              !branchesProvablyDisjoint(
                leftConstraint,
                rightConstraint,
                alternative,
              ),
          )
        )
          throw new SchemaEmissionError(path, capabilityId);
      }
    }
  };

  const renderReference = (
    reference: unknown,
    root: AliasRootIdentity,
    path: string,
    capabilityId?: string,
  ): string => {
    if (typeof reference !== "string")
      throw new SchemaEmissionError(path, capabilityId);
    const identity = referenceAliasIdentity(reference, root);
    const alias =
      identity === undefined
        ? undefined
        : aliases.get(aliasIdentityKey(identity));
    if (alias === undefined) throw new SchemaEmissionError(path, capabilityId);
    return alias;
  };

  const projectedPropertyConstraints = (
    enclosing: ConstraintAlternatives,
    name: string,
  ): ConstraintAlternatives =>
    deduplicateAlternatives(
      enclosing.map((alternative) =>
        alternative.flatMap((constraint) => {
          const resolved = dereference(
            constraint.schema,
            constraint.root,
            constraint.path,
            constraint.capabilityId,
          );
          if (!resolved || !isRecord(resolved.schema.properties)) return [];
          const property = resolved.schema.properties[name];
          if (!isRecord(property)) return [];
          return [
            schemaConstraint(
              property as JsonSchema,
              resolved.root,
              `${resolved.path}/properties/${pointerToken(name)}`,
              resolved.capabilityId,
            ),
          ];
        }),
      ),
      enclosing[0]?.[0]?.path ?? "/",
      enclosing[0]?.[0]?.capabilityId,
    );
  const projectedItemConstraints = (
    enclosing: ConstraintAlternatives,
  ): ConstraintAlternatives =>
    deduplicateAlternatives(
      enclosing.map((alternative) =>
        alternative.flatMap((constraint) => {
          const resolved = dereference(
            constraint.schema,
            constraint.root,
            constraint.path,
            constraint.capabilityId,
          );
          if (!resolved || !isRecord(resolved.schema.items)) return [];
          return [
            schemaConstraint(
              resolved.schema.items as JsonSchema,
              resolved.root,
              `${resolved.path}/items`,
              resolved.capabilityId,
            ),
          ];
        }),
      ),
      enclosing[0]?.[0]?.path ?? "/",
      enclosing[0]?.[0]?.capabilityId,
    );

  const renderObject = (
    schema: JsonSchema,
    root: AliasRootIdentity,
    path: string,
    capabilityId?: string,
    enclosing: ConstraintAlternatives = [[]],
    renderDepth = 0,
  ): string => {
    const rawProperties = schema.properties;
    if (rawProperties !== undefined && !isRecord(rawProperties))
      throw new SchemaEmissionError(`${path}/properties`, capabilityId);
    const properties = (rawProperties ?? {}) as Record<string, unknown>;
    const requiredValue = schema.required;
    if (
      requiredValue !== undefined &&
      (!Array.isArray(requiredValue) ||
        requiredValue.some((value) => typeof value !== "string"))
    )
      throw new SchemaEmissionError(`${path}/required`, capabilityId);
    const required = new Set((requiredValue ?? []) as readonly string[]);
    if ([...required].some((name) => !Object.hasOwn(properties, name)))
      throw new SchemaEmissionError(`${path}/required`, capabilityId);
    if (
      schema.additionalProperties !== undefined &&
      typeof schema.additionalProperties !== "boolean"
    )
      throw new SchemaEmissionError(
        `${path}/additionalProperties`,
        capabilityId,
      );
    const members = Object.keys(properties)
      .sort(compareCodePoints)
      .map((name) => {
        const child = properties[name];
        if (!isRecord(child))
          throw new SchemaEmissionError(
            `${path}/properties/${pointerToken(name)}`,
            capabilityId,
          );
        return `readonly ${JSON.stringify(name)}${required.has(name) ? "" : "?"}: ${renderSchema(child as JsonSchema, root, `${path}/properties/${pointerToken(name)}`, capabilityId, projectedPropertyConstraints(enclosing, name), renderDepth + 1)};`;
      });
    const shape =
      members.length === 0
        ? "Readonly<Record<string, never>>"
        : `{ ${members.join(" ")} }`;
    if (schema.additionalProperties === false) return shape;
    if (members.length === 0)
      return "Readonly<Record<string, __CapaxleJsonValue>>";
    return `Readonly<Record<string, __CapaxleJsonValue>> & ${shape}`;
  };

  const renderBase = (
    schema: JsonSchema,
    root: AliasRootIdentity,
    path: string,
    capabilityId?: string,
    enclosing: ConstraintAlternatives = [[]],
    renderDepth = 0,
  ): string => {
    const rawType = schema.type;
    let types: readonly string[];
    if (rawType === undefined)
      types = ["null", "boolean", "number", "string", "array", "object"];
    else if (typeof rawType === "string") types = [rawType];
    else if (
      Array.isArray(rawType) &&
      rawType.length === 2 &&
      rawType.every((value) => typeof value === "string")
    )
      types = rawType;
    else throw new SchemaEmissionError(`${path}/type`, capabilityId);
    if (types.some((value) => !schemaTypes.has(value)))
      throw new SchemaEmissionError(`${path}/type`, capabilityId);
    const unique = [
      ...new Set(
        types.map((value) => (value === "integer" ? "number" : value)),
      ),
    ];
    const rendered = unique.map((type) => {
      if (
        type === "null" ||
        type === "boolean" ||
        type === "number" ||
        type === "string"
      )
        return type;
      if (type === "array") {
        if (schema.items === undefined) return "readonly __CapaxleJsonValue[]";
        if (!isRecord(schema.items))
          throw new SchemaEmissionError(`${path}/items`, capabilityId);
        return `readonly (${renderSchema(schema.items as JsonSchema, root, `${path}/items`, capabilityId, projectedItemConstraints(enclosing), renderDepth + 1)})[]`;
      }
      return renderObject(
        schema,
        root,
        path,
        capabilityId,
        enclosing,
        renderDepth,
      );
    });
    if (
      rawType === undefined &&
      schema.properties === undefined &&
      schema.required === undefined &&
      schema.additionalProperties === undefined &&
      schema.items === undefined
    )
      return "__CapaxleJsonValue";
    return rendered.length === 1 ? rendered[0]! : `(${rendered.join(" | ")})`;
  };

  const renderSchema = (
    schema: JsonSchema,
    root: AliasRootIdentity,
    path: string,
    capabilityId?: string,
    enclosing: ConstraintAlternatives = [[]],
    renderDepth = 0,
  ): string => {
    if (renderDepth > maxExpansionDepth)
      throw new SchemaEmissionError(path, capabilityId);
    if (!isRecord(schema)) throw new SchemaEmissionError(path, capabilityId);
    if (Object.keys(schema).some((key) => !schemaKeys.has(key)))
      throw new SchemaEmissionError(path, capabilityId);
    if (
      schema.$schema !== undefined &&
      schema.$schema !== "https://json-schema.org/draft/2020-12/schema"
    )
      throw new SchemaEmissionError(`${path}/$schema`, capabilityId);
    if (schema.$ref !== undefined) {
      if (Object.keys(schema).length !== 1)
        throw new SchemaEmissionError(path, capabilityId);
      return renderReference(schema.$ref, root, `${path}/$ref`, capabilityId);
    }
    const localConstraint = schemaConstraint(
      withoutOneOf(schema),
      root,
      path,
      capabilityId,
    );
    const compatible = compatibleAlternatives(enclosing, localConstraint);
    const components = [
      renderBase(schema, root, path, capabilityId, compatible, renderDepth),
    ];
    if (Object.hasOwn(schema, "const"))
      components.push(literalType(asJsonValue(schema.const, `${path}/const`)));
    if (schema.enum !== undefined) {
      if (!Array.isArray(schema.enum) || schema.enum.length === 0)
        throw new SchemaEmissionError(`${path}/enum`, capabilityId);
      components.push(
        `(${schema.enum
          .map((value, index) =>
            literalType(asJsonValue(value, `${path}/enum/${index}`)),
          )
          .join(" | ")})`,
      );
    }
    if (schema.oneOf !== undefined) {
      if (!Array.isArray(schema.oneOf) || schema.oneOf.length < 2)
        throw new SchemaEmissionError(`${path}/oneOf`, capabilityId);
      const effectiveEnclosing = compatible.map((alternative) => [
        ...alternative,
        localConstraint,
      ]);
      assertExclusiveOneOf(
        schema.oneOf,
        effectiveEnclosing,
        root,
        `${path}/oneOf`,
        capabilityId,
      );
      components.push(
        `(${schema.oneOf
          .map((branch, index) => {
            if (!isRecord(branch))
              throw new SchemaEmissionError(
                `${path}/oneOf/${index}`,
                capabilityId,
              );
            return renderSchema(
              branch as JsonSchema,
              root,
              `${path}/oneOf/${index}`,
              capabilityId,
              effectiveEnclosing,
              renderDepth + 1,
            );
          })
          .join(" | ")})`,
      );
    }
    return components.length === 1
      ? components[0]!
      : components.map((component) => `(${component})`).join(" & ");
  };

  const renderBinding = (
    binding: SchemaBinding,
    root: AliasRootIdentity,
    path: string,
    capabilityId: string,
  ): string => {
    if (binding.schema !== undefined && binding.$ref === undefined) {
      const alias = aliases.get(rootIdentityKey(root));
      if (alias !== undefined) return alias;
    }
    if (binding.$ref !== undefined && binding.schema === undefined)
      return renderReference(binding.$ref, root, `${path}/$ref`, capabilityId);
    throw new SchemaEmissionError(path, capabilityId);
  };

  return { renderSchema, renderBinding };
}

function renderDeclaredErrors(
  capability: InternalFacadeCapabilityDocument["capabilities"][number],
  capabilityPath: string,
  renderBinding: ReturnType<typeof schemaTypeEmitter>["renderBinding"],
): string {
  const errors = Object.keys(capability.errors).sort(compareCodePoints);
  if (errors.length === 0) return "never";
  return errors
    .map((code) => {
      const error = capability.errors[code]!;
      if (
        typeof error.message !== "string" ||
        typeof error.retryable !== "boolean" ||
        typeof error.status !== "string"
      )
        throw new SchemaEmissionError(
          `${capabilityPath}/errors/${pointerToken(code)}`,
          capability.id,
        );
      const details = error.details
        ? ` readonly details: ${renderBinding(
            error.details,
            {
              kind: "capability",
              id: capability.id,
              version: capability.version,
              binding: "error-details",
              errorCode: code,
            },
            `${capabilityPath}/errors/${pointerToken(code)}/details`,
            capability.id,
          )};`
        : "";
      return `{ readonly code: ${JSON.stringify(code)}; readonly status: ${JSON.stringify(error.status)}; readonly message: ${JSON.stringify(error.message)}; readonly retryable: ${String(error.retryable)}; readonly correlationId: string;${details} }`;
    })
    .join(" | ");
}

function renderFacadeNode(node: FacadeNode, indent: string): string {
  const entries = [...node.children.entries()].sort(([left], [right]) =>
    compareCodePoints(left, right),
  );
  if (entries.length === 0) return "Readonly<Record<string, never>>";
  const nextIndent = `${indent}  `;
  return `Readonly<{\n${entries
    .map(([name, child]) => {
      const value = child.leaf
        ? `(input: ${child.leaf.input}, options?: import("@capaxle/core").InternalInvocationOptions) => Promise<import("@capaxle/core").CapabilityInvocationResult<${child.leaf.output}, ${child.leaf.error}>>`
        : renderFacadeNode(child, nextIndent);
      return `${nextIndent}readonly ${propertyName(name)}: ${value};`;
    })
    .join("\n")}\n${indent}}>`;
}

function selectedCapabilities(
  document: InternalFacadeCapabilityDocument,
): readonly SelectedCapability[] {
  return document.capabilities
    .map((capability, index) => ({ capability, index }))
    .filter(
      ({ capability }) => capability.access.exposure.internal !== "disabled",
    )
    .sort(
      (left, right) =>
        compareCodePoints(left.capability.id, right.capability.id) ||
        compareSemVer(left.capability.version, right.capability.version),
    );
}

function validateSelection(
  selected: readonly SelectedCapability[],
): readonly InternalFacadeDiagnostic[] {
  const diagnostics: InternalFacadeDiagnostic[] = [];
  const seen = new Map<string, SelectedCapability>();
  for (const item of selected) {
    const { id, version } = item.capability;
    const path = `/capabilities/${item.index}/id`;
    const segments = typeof id === "string" ? id.split(".") : [];
    if (
      typeof id !== "string" ||
      !capabilityIdPattern.test(id) ||
      segments.some((segment) => reservedSegments.has(segment))
    ) {
      diagnostics.push(
        diagnostic(
          "CAP_INTERNAL_FACADE_NAME_INVALID",
          "Internal facade capability paths must be canonical and contain no reserved segment.",
          {
            ...(typeof id === "string" ? { capabilityId: id } : {}),
            path,
          },
        ),
      );
      continue;
    }
    const previous = seen.get(id);
    if (previous) {
      diagnostics.push(
        diagnostic(
          "CAP_INTERNAL_FACADE_NAME_COLLISION",
          "Internal facade selection contains a duplicate path or multiple selected versions.",
          {
            capabilityId: id,
            path,
            details: {
              conflictingVersion: previous.capability.version,
              selectedVersion: version,
            },
          },
        ),
      );
    } else seen.set(id, item);
  }
  const ids = [...seen.keys()].sort(compareCodePoints);
  for (const id of ids) {
    const prefix = ids.find((candidate) => id.startsWith(`${candidate}.`));
    if (prefix)
      diagnostics.push(
        diagnostic(
          "CAP_INTERNAL_FACADE_NAME_COLLISION",
          "Internal facade selection contains a leaf and namespace collision.",
          {
            capabilityId: id,
            path: `/capabilities/${seen.get(id)!.index}/id`,
            details: { prefix },
          },
        ),
      );
  }
  return diagnostics.sort(
    (left, right) =>
      compareCodePoints(left.capabilityId ?? "", right.capabilityId ?? "") ||
      compareCodePoints(left.path ?? "", right.path ?? "") ||
      compareCodePoints(left.code, right.code),
  );
}

export function generateInternalFacade(options: {
  readonly document: InternalFacadeCapabilityDocument;
  readonly irHash: `sha256:${string}`;
}): InternalFacadeGenerationResult {
  const { document, irHash } = options;
  if (
    !isRecord(document) ||
    document.irVersion !== "0.1" ||
    !isRecord(document.service) ||
    typeof document.service.name !== "string" ||
    typeof document.service.version !== "string" ||
    !isRecord(document.schemas) ||
    !Array.isArray(document.capabilities) ||
    !hashPattern.test(irHash)
  )
    return Object.freeze({
      ok: false,
      diagnostics: Object.freeze([
        diagnostic(
          "CAP_INTERNAL_FACADE_SCHEMA_UNREPRESENTABLE",
          "The normalized Capability IR dependency is invalid.",
          { path: "/" },
        ),
      ]),
    });
  const selected = selectedCapabilities(document);
  const selectionDiagnostics = validateSelection(selected);
  if (selectionDiagnostics.length > 0)
    return Object.freeze({
      ok: false,
      diagnostics: Object.freeze(selectionDiagnostics),
    });
  try {
    const { specs, aliases } = collectAliases(document, selected);
    assertRepresentableAliasCycles(specs, aliases);
    const { renderSchema, renderBinding } = schemaTypeEmitter(aliases, specs);
    const root: FacadeNode = { children: new Map() };
    for (const { capability, index } of selected) {
      const capabilityPath = `/capabilities/${index}`;
      const leaf: LeafType = {
        input: renderBinding(
          capability.input,
          {
            kind: "capability",
            id: capability.id,
            version: capability.version,
            binding: "input",
          },
          `${capabilityPath}/input`,
          capability.id,
        ),
        output: renderBinding(
          capability.output,
          {
            kind: "capability",
            id: capability.id,
            version: capability.version,
            binding: "output",
          },
          `${capabilityPath}/output`,
          capability.id,
        ),
        error: renderDeclaredErrors(capability, capabilityPath, renderBinding),
      };
      let node = root;
      for (const segment of capability.id.split(".")) {
        let child = node.children.get(segment);
        if (!child) {
          child = { children: new Map() };
          node.children.set(segment, child);
        }
        node = child;
      }
      node.leaf = leaf;
    }
    const aliasesSource = specs
      .map((spec) => {
        const alias = aliases.get(aliasIdentityKey(spec.identity))!;
        return `type ${alias} = ${renderSchema(spec.schema, spec.root, spec.path, spec.capabilityId)};`;
      })
      .join("\n");
    const facade = renderFacadeNode(root, "");
    const topLevel = [...root.children.keys()].sort(compareCodePoints);
    const serviceMarker = `${document.service.name}@${document.service.version}`;
    const augmentationMembers = [
      ...topLevel.map(
        (name) =>
          `    readonly ${propertyName(name)}: InternalCapabilities[${JSON.stringify(name)}];`,
      ),
      `    readonly __capaxleGeneratedFacadeService__?: ${JSON.stringify(serviceMarker)};`,
    ].join("\n");
    const source = [
      `// @generated producer=${INTERNAL_FACADE_PRODUCER_ID} version=${INTERNAL_FACADE_PRODUCER_VERSION} target=${INTERNAL_FACADE_TARGET} irVersion=${document.irVersion} irHash=${irHash} service=${JSON.stringify(serviceMarker)}`,
      "type __CapaxleJsonValue = null | boolean | number | string | readonly __CapaxleJsonValue[] | { readonly [key: string]: __CapaxleJsonValue };",
      ...(aliasesSource === "" ? [] : [aliasesSource]),
      `export type InternalCapabilities = ${facade};`,
      'declare module "@capaxle/core" {',
      "  interface GeneratedCapabilityFacade {",
      augmentationMembers,
      "  }",
      "}",
      "",
    ].join("\n");
    return Object.freeze({
      ok: true,
      bytes: new TextEncoder().encode(source),
      diagnostics: Object.freeze([] as const),
    });
  } catch (error) {
    const failure =
      error instanceof SchemaEmissionError
        ? error
        : new SchemaEmissionError("/");
    return Object.freeze({
      ok: false,
      diagnostics: Object.freeze([
        diagnostic(
          "CAP_INTERNAL_FACADE_SCHEMA_UNREPRESENTABLE",
          "An accepted Capability IR schema cannot be represented truthfully as TypeScript.",
          {
            ...(failure.capabilityId === undefined
              ? {}
              : { capabilityId: failure.capabilityId }),
            path: failure.path || "/",
          },
        ),
      ]),
    });
  }
}

// The HTTP SDK is a separate artifact from the internal facade. It shares only
// the pure schema-to-TypeScript emitter above; no internal invocation code enters
// the generated client.
export const SDK_HTTP_PRODUCER_ID = "capaxle.sdk-http-ts" as const;
export const SDK_HTTP_PRODUCER_VERSION = "0.1.0-alpha.3" as const;
export const SDK_HTTP_ARTIFACT_ID = "capaxle.sdk-http-ts" as const;
export const SDK_HTTP_ARTIFACT_PATH = "capaxle-sdk.ts" as const;
export const SDK_HTTP_MEDIA_TYPE = "text/typescript" as const;
export const SDK_HTTP_TARGET = "capaxle:sdk-http-ts@0.1" as const;
export const SDK_HTTP_DIAGNOSTIC_CODES = Object.freeze([
  Object.freeze({
    code: "CAP_SDK_HTTP_BINDING_INVALID" as const,
    severities: Object.freeze(["error" as const]),
  }),
  Object.freeze({
    code: "CAP_SDK_NAME_COLLISION" as const,
    severities: Object.freeze(["error" as const]),
  }),
  Object.freeze({
    code: "CAP_SDK_NAME_INVALID" as const,
    severities: Object.freeze(["error" as const]),
  }),
  Object.freeze({
    code: "CAP_SDK_SCHEMA_UNREPRESENTABLE" as const,
    severities: Object.freeze(["error" as const]),
  }),
]);

export interface SdkHttpCapabilityDocument extends Omit<
  InternalFacadeCapabilityDocument,
  "capabilities"
> {
  readonly capabilities: readonly (Omit<
    InternalFacadeCapabilityDocument["capabilities"][number],
    "access"
  > & {
    readonly access: { readonly exposure: { readonly http: string } };
    readonly interfaces: {
      readonly sdk:
        | { readonly enabled: false }
        | { readonly enabled: true; readonly path: readonly string[] };
      readonly http:
        | { readonly enabled: false }
        | {
            readonly enabled: true;
            readonly method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
            readonly path: string;
            readonly bindings: Readonly<
              Record<string, "path" | "query" | "header" | "body">
            >;
          };
    };
    readonly lifecycle?: {
      readonly status?: string;
      readonly replacement?: string;
    };
  })[];
}

export type SdkHttpDiagnosticCode =
  (typeof SDK_HTTP_DIAGNOSTIC_CODES)[number]["code"];
export interface SdkHttpDiagnostic {
  readonly code: SdkHttpDiagnosticCode;
  readonly severity: "error";
  readonly message: string;
  readonly target: typeof SDK_HTTP_TARGET;
  readonly capabilityId?: string;
  readonly path?: string;
  readonly details?: JsonValue;
}
export type SdkHttpGenerationResult =
  | {
      readonly ok: true;
      readonly bytes: Uint8Array;
      readonly diagnostics: readonly [];
    }
  | { readonly ok: false; readonly diagnostics: readonly SdkHttpDiagnostic[] };

interface SdkSelected {
  readonly capability: SdkHttpCapabilityDocument["capabilities"][number];
  readonly index: number;
}

function sdkDiagnostic(
  code: SdkHttpDiagnosticCode,
  message: string,
  path: string,
  capabilityId?: string,
): SdkHttpDiagnostic {
  return {
    code,
    severity: "error",
    message,
    target: SDK_HTTP_TARGET,
    path,
    ...(capabilityId ? { capabilityId } : {}),
  };
}

function sdkTypeName(path: readonly string[], suffix: string): string {
  return `Capability_${path
    .map((segment) => {
      const bytes = new TextEncoder().encode(segment);
      return `${bytes.length}_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    })
    .join("__")}_${suffix}`;
}

function sdkReadableTypeName(path: readonly string[], suffix: string): string {
  return `Capability${path
    .map((segment) =>
      Array.from(segment)
        .map((letter, index) => (index === 0 ? letter.toUpperCase() : letter))
        .join("")
        .replace(
          /[^A-Za-z0-9_$]/gu,
          (character) => `_u${character.codePointAt(0)!.toString(16)}_`,
        ),
    )
    .join("")}${suffix}`;
}

function sdkValidSegment(segment: unknown): segment is string {
  return (
    typeof segment === "string" &&
    segment.length > 0 &&
    !reservedSegments.has(segment)
  );
}

interface SdkNode {
  readonly children: Map<string, SdkNode>;
  leaf?: {
    readonly input: string;
    readonly output: string;
    readonly error: string;
    readonly index: number;
    readonly deprecated?: string;
  };
}

function sdkNodeType(node: SdkNode, indent: string): string {
  const entries = [...node.children.entries()].sort(([a], [b]) =>
    compareCodePoints(a, b),
  );
  return `Readonly<{\n${entries
    .map(([name, child]) => {
      const type = child.leaf
        ? `CapaxleSdkMethod<${child.leaf.input}, ${child.leaf.output}, ${child.leaf.error}>`
        : sdkNodeType(child, `${indent}  `);
      const annotation = child.leaf?.deprecated
        ? `${indent}  /** @deprecated ${child.leaf.deprecated} */\n`
        : "";
      return `${annotation}${indent}  readonly ${propertyName(name)}: ${type};`;
    })
    .join("\n")}\n${indent}}>`;
}

function sdkNodeValue(node: SdkNode, indent: string): string {
  const entries = [...node.children.entries()].sort(([a], [b]) =>
    compareCodePoints(a, b),
  );
  return `{\n${entries.map(([name, child]) => `${indent}  [${JSON.stringify(name)}]: ${child.leaf ? `makeMethod<${child.leaf.input}, ${child.leaf.output}, ${child.leaf.error}>(routes[${child.leaf.index}]!)` : sdkNodeValue(child, `${indent}  `)},`).join("\n")}\n${indent}}`;
}

function sdkInputOpaque(
  document: SdkHttpCapabilityDocument,
  binding: SchemaBinding,
): boolean {
  let resource: JsonSchema | undefined = binding.schema;
  let schema: JsonSchema | undefined = resource;
  if (binding.$ref?.startsWith("#/schemas/")) {
    resource = document.schemas[decodePointerToken(binding.$ref.slice(10))];
    schema = resource;
  }
  const seen = new Set<JsonSchema>();
  while (schema && !seen.has(schema)) {
    seen.add(schema);
    const ref = schema.$ref;
    if (typeof ref !== "string") break;
    if (ref.startsWith("#/schemas/")) {
      resource = document.schemas[decodePointerToken(ref.slice(10))];
      schema = resource;
    } else if (ref.startsWith("#/$defs/") && isRecord(resource?.$defs)) {
      const candidate: unknown =
        resource.$defs[decodePointerToken(ref.slice(8))];
      schema = isRecord(candidate) ? (candidate as JsonSchema) : undefined;
    } else break;
  }
  return !(
    schema?.type === "object" &&
    schema.additionalProperties === false &&
    isRecord(schema.properties) &&
    schema.const === undefined &&
    schema.enum === undefined &&
    schema.oneOf === undefined
  );
}

function sdkValidHttpPath(path: unknown): path is string {
  if (
    typeof path !== "string" ||
    !/^\/(?:[A-Za-z0-9._~-]+|\{[A-Za-z_][A-Za-z0-9_.-]*\})(?:\/(?:[A-Za-z0-9._~-]+|\{[A-Za-z_][A-Za-z0-9_.-]*\}))*$/u.test(
      path,
    ) ||
    path.includes("//") ||
    path.split("/").some((segment) => segment === "." || segment === "..")
  )
    return false;
  const variables = [...path.matchAll(/\{([A-Za-z_][A-Za-z0-9_.-]*)\}/gu)].map(
    (match) => match[1],
  );
  return new Set(variables).size === variables.length;
}

function renderSdkDeclaredErrors(
  capability: SdkHttpCapabilityDocument["capabilities"][number],
  capabilityPath: string,
  renderBinding: ReturnType<typeof schemaTypeEmitter>["renderBinding"],
): string {
  const codes = Object.keys(capability.errors).sort(compareCodePoints);
  if (codes.length === 0) return "never";
  return codes
    .map((code) => {
      const definition = capability.errors[code]!;
      const details = definition.details
        ? ` readonly details: ${renderBinding(definition.details, { kind: "capability", id: capability.id, version: capability.version, binding: "error-details", errorCode: code }, `${capabilityPath}/errors/${pointerToken(code)}/details`, capability.id)};`
        : "";
      return `{ readonly code: ${JSON.stringify(code)}; readonly status: ${JSON.stringify(definition.status)}; readonly message: string; readonly retryable: ${String(definition.retryable)}; readonly correlationId: string;${details} }`;
    })
    .join(" | ");
}

const SDK_HTTP_RUNTIME_SOURCE = String.raw`
export type CapaxleErrorStatus = "invalid_argument" | "unauthenticated" | "permission_denied" | "not_found" | "already_exists" | "failed_precondition" | "conflict" | "resource_exhausted" | "cancelled" | "deadline_exceeded" | "unavailable" | "internal";
export interface CapaxleCanonicalError {
  readonly code: string;
  readonly status: CapaxleErrorStatus;
  readonly message: string;
  readonly retryable: boolean;
  readonly correlationId: string;
  readonly details?: __CapaxleJsonValue;
}
export class CapaxleClientError<Declared = never> extends Error {
  readonly name = "CapaxleClientError";
  readonly code: string;
  readonly status: CapaxleErrorStatus;
  readonly retryable: boolean;
  readonly correlationId: string;
  readonly details?: __CapaxleJsonValue;
  readonly httpStatus?: number;
  readonly origin: "server" | "client";
  readonly capabilityId?: string;
  readonly capabilityVersion?: string;
  readonly declared: Declared | null;
  constructor(error: CapaxleCanonicalError, origin: "server" | "client", httpStatus?: number, declaredErrors: readonly { readonly code: string; readonly status: CapaxleErrorStatus; readonly retryable: boolean }[] = [], capabilityId?: string, capabilityVersion?: string) {
    super(error.message);
    this.code = error.code;
    this.status = error.status;
    this.retryable = error.retryable;
    this.correlationId = error.correlationId;
    if (error.details !== undefined) this.details = error.details;
    if (httpStatus !== undefined) this.httpStatus = httpStatus;
    this.origin = origin;
    if (capabilityId !== undefined) this.capabilityId = capabilityId;
    if (capabilityVersion !== undefined) this.capabilityVersion = capabilityVersion;
    this.declared = origin === "server" && declaredErrors.some((definition) => definition.code === error.code && definition.status === error.status && definition.retryable === error.retryable) ? error as unknown as Declared : null;
  }
}
export interface CapaxleCallOptions {
  readonly idempotencyKey?: string;
  readonly confirmationToken?: string;
  readonly correlationId?: string;
  readonly deadlineMs?: number;
  readonly signal?: AbortSignal;
}
export interface CapaxleClientConfig {
  readonly baseUrl: string;
  readonly fetch?: typeof globalThis.fetch;
  readonly headers?: HeadersInit;
  readonly auth?: () => HeadersInit | Promise<HeadersInit>;
  readonly credentials?: RequestCredentials;
}
export interface CapaxleSdkMethod<Input, Output, DeclaredError> {
  (input: Input, options?: CapaxleCallOptions): Promise<Output>;
  readonly raw: (input: Input, options?: CapaxleCallOptions) => Promise<{ readonly value: Output; readonly response: Response }>;
  readonly isDeclaredError: (error: unknown) => error is CapaxleClientError<DeclaredError> & { readonly declared: DeclaredError };
}
interface Route {
  readonly id: string;
  readonly version: string;
  readonly method: string;
  readonly path: string;
  readonly bindings: Readonly<Record<string, "path" | "query" | "header" | "body">>;
  readonly opaque: boolean;
  readonly declaredErrors: readonly { readonly code: string; readonly status: CapaxleErrorStatus; readonly retryable: boolean }[];
}
const canonicalStatuses = new Set<string>(["invalid_argument", "unauthenticated", "permission_denied", "not_found", "already_exists", "failed_precondition", "conflict", "resource_exhausted", "cancelled", "deadline_exceeded", "unavailable", "internal"]);
function clientFailure(code: string, status: CapaxleErrorStatus, message: string): CapaxleClientError {
  return new CapaxleClientError({ code, status, message, retryable: false, correlationId: "" }, "client");
}
function canonicalError(value: unknown): CapaxleCanonicalError | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const envelope = value as Record<string, unknown>;
  if (envelope.ok !== false || typeof envelope.error !== "object" || envelope.error === null || Array.isArray(envelope.error)) return null;
  const error = envelope.error as Record<string, unknown>;
  if (typeof error.code !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(error.code) ||
      typeof error.status !== "string" || !canonicalStatuses.has(error.status) ||
      typeof error.message !== "string" || typeof error.retryable !== "boolean" ||
      typeof error.correlationId !== "string") return null;
  return error as unknown as CapaxleCanonicalError;
}
function wireValue(value: unknown): string {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  throw clientFailure("CAP_SDK_INPUT_INVALID", "invalid_argument", "HTTP-bound input must be scalar.");
}
function interruptible<T>(start: () => T | Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    if (signal.aborted) { reject(new Error("aborted")); return; }
    const abort = () => reject(new Error("aborted"));
    signal.addEventListener("abort", abort, { once: true });
    Promise.resolve().then(() => {
      if (signal.aborted) throw new Error("aborted");
      return start();
    }).then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}
function makeMethodFactory(config: CapaxleClientConfig) {
  if (typeof config.baseUrl !== "string" || config.baseUrl.length === 0) throw new TypeError("baseUrl is required");
  const transport = config.fetch ?? globalThis.fetch;
  if (typeof transport !== "function") throw new TypeError("fetch is required");
  const base = new URL(config.baseUrl);
  return function makeMethod<Input, Output, DeclaredError>(route: Route): CapaxleSdkMethod<Input, Output, DeclaredError> {
    async function request(input: Input, options: CapaxleCallOptions = {}, preserveResponse = false): Promise<{ value: Output; response: Response }> {
      if (typeof input !== "object" || input === null || Array.isArray(input)) throw clientFailure("CAP_SDK_INPUT_INVALID", "invalid_argument", "Capability input must be an object.");
      const record = input as Record<string, unknown>;
      let path = route.path;
      const headers = new Headers(config.headers);
      const body: Record<string, unknown> = Object.create(null);
      let bodyFields = 0;
      for (const [name, binding] of Object.entries(route.bindings)) {
        if (!Object.hasOwn(record, name) || record[name] === undefined) continue;
        const value = record[name];
        if (binding === "body") { body[name] = value; bodyFields++; }
        else if (binding === "path") {
          const marker = "{" + name + "}";
          if (!path.includes(marker)) throw clientFailure("CAP_SDK_ROUTE_INVALID", "internal", "Generated route binding is invalid.");
          const wire = wireValue(value);
          if (wire === "." || wire === "..") throw clientFailure("CAP_SDK_INPUT_INVALID", "invalid_argument", "Path input cannot be a dot segment.");
          path = path.replace(marker, encodeURIComponent(wire));
        }
      }
      if (path.includes("{")) throw clientFailure("CAP_SDK_INPUT_INVALID", "invalid_argument", "Required path input is missing.");
      const url = new URL(path, base);
      if (url.origin !== base.origin) throw clientFailure("CAP_SDK_ROUTE_INVALID", "internal", "Generated route changes the configured origin.");
      for (const [name, binding] of Object.entries(route.bindings)) {
        if (binding !== "query" || !Object.hasOwn(record, name) || record[name] === undefined) continue;
        const value = record[name];
        if (Array.isArray(value)) for (const element of value) url.searchParams.append(name, wireValue(element));
        else url.searchParams.append(name, wireValue(value));
      }
      for (const [name, value] of Object.entries(record)) if (!Object.hasOwn(route.bindings, name)) { body[name] = value; bodyFields++; }
      const opaque = route.opaque;
      const hasBody = opaque || bodyFields > 0;
      if (hasBody && (route.method === "GET" || route.method === "DELETE")) throw clientFailure("CAP_SDK_INPUT_INVALID", "invalid_argument", "This HTTP route cannot carry a body.");
      if (options.deadlineMs !== undefined && (!Number.isFinite(options.deadlineMs) || options.deadlineMs < 0))
        throw clientFailure("CAP_SDK_INPUT_INVALID", "invalid_argument", "deadlineMs must be a nonnegative finite number.");
      const controller = new AbortController();
      let timedOut = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      const abort = () => controller.abort();
      if (options.signal?.aborted) controller.abort();
      else options.signal?.addEventListener("abort", abort, { once: true });
      if (options.deadlineMs !== undefined) {
        timer = setTimeout(() => { timedOut = true; controller.abort(); }, options.deadlineMs);
      }
      let response: Response;
      let rawResponse: Response | undefined;
      let decoded: unknown;
      try {
        if (config.auth) {
          const authHeaders = new Headers(await interruptible(() => config.auth!(), controller.signal));
          authHeaders.forEach((value, key) => headers.set(key, value));
        }
        for (const [name, binding] of Object.entries(route.bindings))
          if (binding === "header" && Object.hasOwn(record, name) && record[name] !== undefined)
            headers.set("X-Cap-Input-" + name, wireValue(record[name]));
        if (hasBody) headers.set("Content-Type", "application/json");
        if (options.idempotencyKey !== undefined) headers.set("Idempotency-Key", options.idempotencyKey);
        if (options.confirmationToken !== undefined) headers.set("X-Cap-Confirmation", options.confirmationToken);
        if (options.correlationId !== undefined) headers.set("X-Correlation-Id", options.correlationId);
        response = await interruptible(() => transport(url, { method: route.method, headers, ...(hasBody ? { body: JSON.stringify(body) } : {}), ...(config.credentials ? { credentials: config.credentials } : {}), signal: controller.signal }), controller.signal);
        if (preserveResponse) rawResponse = response.clone();
        try { decoded = await interruptible(() => response.json(), controller.signal); }
        catch {
          if (timedOut) throw clientFailure("CAP_DEADLINE_EXCEEDED", "deadline_exceeded", "Client deadline exceeded.");
          if (controller.signal.aborted) throw clientFailure("CAP_CANCELLED", "cancelled", "Client request cancelled.");
          throw clientFailure("CAP_SDK_PROTOCOL_ERROR", "unavailable", "HTTP response is not valid JSON.");
        }
      } catch (error) {
        if (error instanceof CapaxleClientError) throw error;
        if (timedOut) throw clientFailure("CAP_DEADLINE_EXCEEDED", "deadline_exceeded", "Client deadline exceeded.");
        if (controller.signal.aborted) throw clientFailure("CAP_CANCELLED", "cancelled", "Client request cancelled.");
        throw clientFailure("CAP_SDK_TRANSPORT_ERROR", "unavailable", "HTTP transport failed.");
      } finally {
        if (timer !== undefined) clearTimeout(timer);
        options.signal?.removeEventListener("abort", abort);
      }
      if (!response.ok) {
        const canonical = canonicalError(decoded);
        if (canonical === null) throw clientFailure("CAP_SDK_PROTOCOL_ERROR", "unavailable", "HTTP error lacks a canonical envelope.");
        throw new CapaxleClientError<DeclaredError>(canonical, "server", response.status, route.declaredErrors, route.id, route.version);
      }
      return { value: decoded as Output, response: rawResponse ?? response };
    }
    const method = ((input: Input, options?: CapaxleCallOptions) => request(input, options).then((result) => result.value)) as CapaxleSdkMethod<Input, Output, DeclaredError>;
    Object.defineProperty(method, "raw", { value: (input: Input, options?: CapaxleCallOptions) => request(input, options, true), enumerable: true });
    Object.defineProperty(method, "isDeclaredError", { value: (error: unknown) => error instanceof CapaxleClientError && error.declared !== null && error.capabilityId === route.id && error.capabilityVersion === route.version && route.declaredErrors.some((definition) => definition.code === error.code && definition.status === error.status && definition.retryable === error.retryable), enumerable: true });
    return method;
  };
}
`;

export function generateSdkHttp(options: {
  readonly document: SdkHttpCapabilityDocument;
  readonly irHash: `sha256:${string}`;
}): SdkHttpGenerationResult {
  const { document, irHash } = options;
  if (
    !isRecord(document) ||
    document.irVersion !== "0.1" ||
    !isRecord(document.service) ||
    typeof document.service.name !== "string" ||
    typeof document.service.version !== "string" ||
    !isRecord(document.schemas) ||
    !Array.isArray(document.capabilities) ||
    !hashPattern.test(irHash)
  )
    return {
      ok: false,
      diagnostics: [
        sdkDiagnostic(
          "CAP_SDK_SCHEMA_UNREPRESENTABLE",
          "The normalized Capability IR dependency is invalid.",
          "/",
        ),
      ],
    };
  const selected: SdkSelected[] = document.capabilities
    .map((capability, index) => ({ capability, index }))
    .filter(
      ({ capability }) =>
        capability?.access?.exposure?.http !== "disabled" &&
        capability?.interfaces?.http?.enabled === true &&
        capability?.interfaces?.sdk?.enabled === true,
    )
    .sort(
      (a, b) =>
        compareCodePoints(a.capability.id, b.capability.id) ||
        compareSemVer(a.capability.version, b.capability.version),
    );
  const diagnostics: SdkHttpDiagnostic[] = [];
  const root: SdkNode = { children: new Map() };
  const typeNames = new Set<string>();
  for (const { capability, index } of selected) {
    const path = capability.interfaces.sdk.enabled
      ? capability.interfaces.sdk.path
      : [];
    if (
      !Array.isArray(path) ||
      path.length === 0 ||
      path.some((segment) => !sdkValidSegment(segment))
    ) {
      diagnostics.push(
        sdkDiagnostic(
          "CAP_SDK_NAME_INVALID",
          "SDK path must contain nonempty, safe property names.",
          `/capabilities/${index}/interfaces/sdk/path`,
          capability.id,
        ),
      );
      continue;
    }
    const inputName = sdkTypeName(path, "Input");
    if (typeNames.has(inputName))
      diagnostics.push(
        sdkDiagnostic(
          "CAP_SDK_NAME_COLLISION",
          "SDK type names collide.",
          `/capabilities/${index}/interfaces/sdk/path`,
          capability.id,
        ),
      );
    typeNames.add(inputName);
    let node = root;
    for (const segment of path) {
      let child = node.children.get(segment);
      if (!child) {
        child = { children: new Map() };
        node.children.set(segment, child);
      }
      node = child;
    }
    if (node.leaf || node.children.size > 0)
      diagnostics.push(
        sdkDiagnostic(
          "CAP_SDK_NAME_COLLISION",
          "SDK paths collide.",
          `/capabilities/${index}/interfaces/sdk/path`,
          capability.id,
        ),
      );
    node.leaf = {
      input: inputName,
      output: sdkTypeName(path, "Output"),
      error: sdkTypeName(path, "DeclaredError"),
      index: selected.findIndex((item) => item.index === index),
      ...(capability.lifecycle?.status === "deprecated"
        ? {
            deprecated: capability.lifecycle.replacement
              ? `Use ${capability.lifecycle.replacement}.`
              : "This capability is deprecated.",
          }
        : {}),
    };
    const http = capability.interfaces.http;
    if (
      !http.enabled ||
      !/^(GET|POST|PUT|PATCH|DELETE)$/u.test(http.method) ||
      !sdkValidHttpPath(http.path) ||
      !isRecord(http.bindings)
    )
      diagnostics.push(
        sdkDiagnostic(
          "CAP_SDK_HTTP_BINDING_INVALID",
          "Resolved HTTP route is invalid.",
          `/capabilities/${index}/interfaces/http`,
          capability.id,
        ),
      );
    else if (
      Object.values(http.bindings).some(
        (binding) => !["path", "query", "header", "body"].includes(binding),
      ) ||
      (() => {
        const variables = [
          ...http.path.matchAll(/\{([A-Za-z_][A-Za-z0-9_.-]*)\}/gu),
        ].map((match) => match[1]!);
        const bound = Object.entries(http.bindings)
          .filter(([, binding]) => binding === "path")
          .map(([name]) => name);
        return (
          variables.length !== bound.length ||
          variables.some((name) => !bound.includes(name))
        );
      })()
    )
      diagnostics.push(
        sdkDiagnostic(
          "CAP_SDK_HTTP_BINDING_INVALID",
          "Resolved HTTP bindings are invalid.",
          `/capabilities/${index}/interfaces/http/bindings`,
          capability.id,
        ),
      );
  }
  for (const { capability, index } of selected) {
    const path = capability.interfaces.sdk.enabled
      ? capability.interfaces.sdk.path
      : [];
    if (
      !Array.isArray(path) ||
      path.length === 0 ||
      path.some((segment) => !sdkValidSegment(segment))
    )
      continue;
    for (let length = 1; length < path.length; length++) {
      let node = root;
      for (const segment of path.slice(0, length))
        node = node.children.get(segment)!;
      if (node.leaf)
        diagnostics.push(
          sdkDiagnostic(
            "CAP_SDK_NAME_COLLISION",
            "SDK leaf collides with namespace.",
            `/capabilities/${index}/interfaces/sdk/path`,
            capability.id,
          ),
        );
    }
  }
  if (diagnostics.length)
    return {
      ok: false,
      diagnostics: diagnostics.sort(
        (a, b) =>
          compareCodePoints(a.path ?? "", b.path ?? "") ||
          compareCodePoints(a.code, b.code),
      ),
    };
  try {
    const facadeSelected = selected as unknown as readonly SelectedCapability[];
    const { specs, aliases } = collectAliases(
      document as unknown as InternalFacadeCapabilityDocument,
      facadeSelected,
    );
    assertRepresentableAliasCycles(specs, aliases);
    const { renderSchema, renderBinding } = schemaTypeEmitter(aliases, specs);
    const aliasesSource = specs
      .map(
        (spec) =>
          `type ${aliases.get(aliasIdentityKey(spec.identity))!} = ${renderSchema(spec.schema, spec.root, spec.path, spec.capabilityId)};`,
      )
      .join("\n");
    const types: string[] = [];
    const routes: string[] = [];
    const canonicalNames = new Set<string>();
    const readableCounts = new Map<string, number>();
    for (const { capability } of selected) {
      const path = capability.interfaces.sdk.enabled
        ? capability.interfaces.sdk.path
        : [];
      for (const suffix of ["Input", "Output", "DeclaredError"]) {
        canonicalNames.add(sdkTypeName(path, suffix));
        if (path.every((segment) => identifierPattern.test(segment))) {
          const readable = sdkReadableTypeName(path, suffix);
          readableCounts.set(readable, (readableCounts.get(readable) ?? 0) + 1);
        }
      }
    }
    const readableAlias = (
      path: readonly string[],
      suffix: string,
    ): string | undefined => {
      if (!path.every((segment) => identifierPattern.test(segment)))
        return undefined;
      const name = sdkReadableTypeName(path, suffix);
      return readableCounts.get(name) === 1 && !canonicalNames.has(name)
        ? `export type ${name} = ${sdkTypeName(path, suffix)};`
        : undefined;
    };
    for (const { capability, index } of selected) {
      const path = capability.interfaces.sdk.enabled
        ? capability.interfaces.sdk.path
        : [];
      const base = `/capabilities/${index}`;
      const input = sdkTypeName(path, "Input");
      const output = sdkTypeName(path, "Output");
      const error = sdkTypeName(path, "DeclaredError");
      types.push(
        `export type ${input} = ${renderBinding(capability.input, { kind: "capability", id: capability.id, version: capability.version, binding: "input" }, `${base}/input`, capability.id)};`,
      );
      types.push(
        `export type ${output} = ${renderBinding(capability.output, { kind: "capability", id: capability.id, version: capability.version, binding: "output" }, `${base}/output`, capability.id)};`,
      );
      types.push(
        `export type ${error} = ${renderSdkDeclaredErrors(capability, base, renderBinding)};`,
      );
      for (const suffix of ["Input", "Output", "DeclaredError"]) {
        const alias = readableAlias(path, suffix);
        if (alias) types.push(alias);
      }
      const http = capability.interfaces.http;
      if (!http.enabled)
        throw new SchemaEmissionError(`${base}/interfaces/http`, capability.id);
      routes.push(
        JSON.stringify({
          id: capability.id,
          version: capability.version,
          method: http.method,
          path: http.path,
          bindings: http.bindings,
          opaque: sdkInputOpaque(document, capability.input),
          declaredErrors: Object.keys(capability.errors)
            .sort(compareCodePoints)
            .map((code) => ({
              code,
              status: capability.errors[code]!.status,
              retryable: capability.errors[code]!.retryable,
            })),
        }),
      );
    }
    const source = [
      `// @generated producer=${SDK_HTTP_PRODUCER_ID} version=${SDK_HTTP_PRODUCER_VERSION} target=${SDK_HTTP_TARGET} irVersion=${document.irVersion} irHash=${irHash} service=${JSON.stringify(`${document.service.name}@${document.service.version}`)}`,
      "type __CapaxleJsonValue = null | boolean | number | string | readonly __CapaxleJsonValue[] | { readonly [key: string]: __CapaxleJsonValue };",
      aliasesSource,
      ...types,
      SDK_HTTP_RUNTIME_SOURCE,
      `export type CapaxleClient = ${sdkNodeType(root, "")};`,
      `const routes: readonly Route[] = [${routes.join(",")}] as const;`,
      `export function createCapaxleClient(config: CapaxleClientConfig): CapaxleClient {\n  const makeMethod = makeMethodFactory(config);\n  return ${sdkNodeValue(root, "  ")} as CapaxleClient;\n}`,
      "",
    ].join("\n");
    return {
      ok: true,
      bytes: new TextEncoder().encode(source),
      diagnostics: [],
    };
  } catch (error) {
    const failure =
      error instanceof SchemaEmissionError
        ? error
        : new SchemaEmissionError("/");
    return {
      ok: false,
      diagnostics: [
        sdkDiagnostic(
          "CAP_SDK_SCHEMA_UNREPRESENTABLE",
          "An accepted Capability IR schema cannot be represented truthfully as TypeScript.",
          failure.path || "/",
          failure.capabilityId,
        ),
      ],
    };
  }
}
