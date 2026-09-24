import { Buffer } from "node:buffer";
import { capabilitySemanticHash, jcs } from "@capaxle/ir";
import type { JsonSchema, JsonValue } from "@capaxle/ir";
import type { RuntimeDocument } from "@capaxle/runtime";
import { projectStandaloneSchema } from "./export-schema.js";

export const OPENCLI_DIALECT = "bcdxn";
export const OPENCLI_VERSION = "1.0.0-alpha.13";
export const OPENCLI_SELECTOR =
  `opencli:${OPENCLI_DIALECT}@${OPENCLI_VERSION}` as const;
export const OPENCLI_EXTENSION_VERSION = "0.2";
export const OPENCLI_TARGET =
  `${OPENCLI_SELECTOR}+capaxle-cli@${OPENCLI_EXTENSION_VERSION}` as const;

export const RESERVED_CLI_OPTIONS = Object.freeze([
  "--confirm",
  "--correlation-id",
  "--help",
  "--idempotency-key",
  "--input",
  "--input-file",
  "--json",
  "--no-input",
  "--timeout",
  "--version",
] as const);

export const OPENCLI_EXIT_CODES = Object.freeze([
  { code: 0, status: "OK", summary: "Invocation succeeded." },
  {
    code: 2,
    status: "BAD_USER_INPUT_ERROR",
    summary: "CLI syntax or canonical input was invalid.",
  },
  {
    code: 3,
    status: "UNAUTHORIZED_ERROR",
    summary: "Authentication or authorization denied the invocation.",
  },
  {
    code: 4,
    status: "INTERNAL_CLI_ERROR",
    summary:
      "Confirmation or another precondition is required; inspect the canonical error.",
  },
  {
    code: 5,
    status: "INTERNAL_CLI_ERROR",
    summary: "A declared domain failure occurred; inspect the canonical error.",
  },
  {
    code: 6,
    status: "INTERNAL_CLI_ERROR",
    summary:
      "The invocation was limited, unavailable, or exceeded its deadline; inspect the canonical error.",
  },
  {
    code: 7,
    status: "INTERNAL_CLI_ERROR",
    summary: "The framework or application failed internally.",
  },
  {
    code: 130,
    status: "CANCELED_ERROR",
    summary: "The invocation was cancelled by an interrupt.",
  },
] as const);

const IR_HASH = /^sha256:[0-9a-f]{64}$/u;
const CLI_BINARY = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const RESERVED = new Set<string>(RESERVED_CLI_OPTIONS);

type JsonObject = { [key: string]: JsonValue };
type Capability = RuntimeDocument["capabilities"][number];

export interface OpenCliBuildContext {
  readonly irHash: string;
  readonly cliBinary?: string;
}

export interface OpenCliExportOptions {
  readonly target?: string;
  readonly extensions?: boolean;
  readonly extensionVersion?: string;
  readonly rootExtensions?: Readonly<Record<string, JsonValue>>;
  readonly buildContext?: OpenCliBuildContext;
}

export interface OpenCliDiagnostic {
  readonly code:
    | "CAP_BUILD_CONTEXT_INVALID"
    | "CAP_OPENCLI_DIALECT_UNSUPPORTED"
    | "CAP_OPENCLI_VERSION_UNSUPPORTED"
    | "CAP_OPENCLI_LOSSY_PROJECTION"
    | "CAP_OPENCLI_BINDING_UNREPRESENTABLE"
    | "CAP_OPENCLI_SCHEMA_UNREPRESENTABLE"
    | "CAP_OPENCLI_EXTENSION_COLLISION";
  readonly severity: "warning" | "error";
  readonly message: string;
  readonly target: string;
  readonly capabilityId?: string;
  readonly path?: string;
  readonly details?: JsonValue;
}

export interface OpenCliExportResult {
  readonly artifact: JsonValue | null;
  readonly diagnostics: readonly OpenCliDiagnostic[];
}

const object = (value: unknown): JsonObject | null =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : null;

const clone = <T extends JsonValue>(value: T): T =>
  JSON.parse(JSON.stringify(value)) as T;

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

function sorted(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(sorted);
  const source = object(value);
  if (!source) return value;
  const result: JsonObject = {};
  for (const key of Object.keys(source).sort(compareCodePoint))
    define(result, key, sorted(source[key]!));
  return result;
}

function diagnostic(
  code: OpenCliDiagnostic["code"],
  input: Omit<OpenCliDiagnostic, "code" | "severity"> & {
    readonly severity?: OpenCliDiagnostic["severity"];
  },
): OpenCliDiagnostic {
  return {
    code,
    severity: input.severity ?? "error",
    message: input.message,
    target: input.target,
    ...(input.capabilityId === undefined
      ? {}
      : { capabilityId: input.capabilityId }),
    ...(input.path === undefined ? {} : { path: input.path }),
    ...(input.details === undefined ? {} : { details: input.details }),
  };
}

function sortDiagnostics(
  diagnostics: readonly OpenCliDiagnostic[],
): readonly OpenCliDiagnostic[] {
  const compare = (left: string | undefined, right: string | undefined) =>
    compareCodePoint(left ?? "", right ?? "");
  return [...diagnostics].sort(
    (left, right) =>
      compare(left.target, right.target) ||
      compare(left.capabilityId, right.capabilityId) ||
      compare(left.path, right.path) ||
      compare(left.code, right.code) ||
      compare(left.message, right.message),
  );
}

function targetDiagnostic(target: string): OpenCliDiagnostic | null {
  if (target === OPENCLI_SELECTOR) return null;
  if (target.startsWith(`opencli:${OPENCLI_DIALECT}@`))
    return diagnostic("CAP_OPENCLI_VERSION_UNSUPPORTED", {
      target,
      path: "/target",
      message: `Unsupported bcdxn OpenCLI version in ${target}; expected ${OPENCLI_SELECTOR}.`,
    });
  return diagnostic("CAP_OPENCLI_DIALECT_UNSUPPORTED", {
    target,
    path: "/target",
    message: `Unsupported OpenCLI dialect in ${target}.`,
  });
}

function buildContextDiagnostics(
  document: RuntimeDocument,
  target: string,
  buildContext: OpenCliBuildContext | undefined,
) {
  const diagnostics: OpenCliDiagnostic[] = [];
  const suppliedHash = buildContext?.irHash;
  if (suppliedHash === undefined)
    diagnostics.push(
      diagnostic("CAP_BUILD_CONTEXT_INVALID", {
        target,
        path: "/buildContext/irHash",
        details: { reason: "missing" },
        message: "buildContext.irHash is required.",
      }),
    );
  else if (!IR_HASH.test(suppliedHash))
    diagnostics.push(
      diagnostic("CAP_BUILD_CONTEXT_INVALID", {
        target,
        path: "/buildContext/irHash",
        details: { reason: "format" },
        message:
          "buildContext.irHash must be sha256: followed by 64 lowercase hexadecimal characters.",
      }),
    );
  else {
    let computed: string | null = null;
    try {
      computed = capabilitySemanticHash(document);
    } catch {
      // Invalid IR is rejected as an authority mismatch at this boundary.
    }
    if (computed !== suppliedHash)
      diagnostics.push(
        diagnostic("CAP_BUILD_CONTEXT_INVALID", {
          target,
          path: "/buildContext/irHash",
          details: { reason: "mismatch" },
          message:
            "buildContext.irHash does not match the locally recomputed Capability IR semantic hash.",
        }),
      );
  }
  const binary = buildContext?.cliBinary;
  if (binary === undefined)
    diagnostics.push(
      diagnostic("CAP_BUILD_CONTEXT_INVALID", {
        target,
        path: "/buildContext/cliBinary",
        details: { reason: "missing" },
        message: "buildContext.cliBinary is required for OpenCLI export.",
      }),
    );
  else if (!CLI_BINARY.test(binary))
    diagnostics.push(
      diagnostic("CAP_BUILD_CONTEXT_INVALID", {
        target,
        path: "/buildContext/cliBinary",
        details: { reason: "format" },
        message: "buildContext.cliBinary must be one collision-safe CLI token.",
      }),
    );
  return sortDiagnostics(diagnostics);
}

const schemaValue = (value: unknown) => {
  const candidate = object(value);
  return (object(candidate?.schema) ?? candidate) as JsonSchema | null;
};

function cliProjection(capability: Capability) {
  return object((capability.interfaces as unknown as JsonObject).cli);
}

function resolveSchemaView(
  schema: JsonSchema | null,
  schemas: Readonly<Record<string, JsonSchema>>,
  ownerRoot: JsonSchema | null = schema,
  seen = new Set<JsonSchema>(),
): JsonSchema | null {
  if (!schema || seen.has(schema)) return schema;
  const nextSeen = new Set(seen).add(schema);
  const source = schema as JsonObject;
  const reference = source.$ref;
  if (typeof reference !== "string") return schema;
  const decode = (token: string) =>
    token.replaceAll("~1", "/").replaceAll("~0", "~");
  if (
    reference.startsWith("#/schemas/") &&
    !reference.slice(10).includes("/")
  ) {
    const name = decode(reference.slice(10));
    return Object.hasOwn(schemas, name)
      ? resolveSchemaView(schemas[name]!, schemas, schemas[name]!, nextSeen)
      : null;
  }
  if (reference.startsWith("#/$defs/") && !reference.slice(8).includes("/")) {
    const name = decode(reference.slice(8));
    const definitions = object((ownerRoot as JsonObject | null)?.$defs);
    const target = definitions?.[name];
    return definitions && Object.hasOwn(definitions, name) && object(target)
      ? resolveSchemaView(target as JsonSchema, schemas, ownerRoot, nextSeen)
      : null;
  }
  return null;
}

function inputPropertyView(
  capability: Capability,
  schemas: Readonly<Record<string, JsonSchema>>,
) {
  const schema = resolveSchemaView(schemaValue(capability.input), schemas);
  const source = object(schema as JsonValue);
  const properties = object(source?.properties);
  if (source?.type !== "object" || !properties) return null;
  return {
    properties,
    required: new Set(
      Array.isArray(source.required)
        ? source.required.filter(
            (value): value is string => typeof value === "string",
          )
        : [],
    ),
  };
}

type ScalarKind = "string" | "integer" | "number" | "boolean";

function primitiveKind(value: JsonValue): ScalarKind | null {
  if (typeof value === "string") return "string";
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "number")
    return Number.isInteger(value) ? "integer" : "number";
  return null;
}

function hasRichScalarBoundary(schema: JsonObject): boolean {
  return ["$ref", "oneOf", "anyOf", "allOf"].some((key) =>
    Object.hasOwn(schema, key),
  );
}

function scalarLeafProjection(
  schema: JsonValue | undefined,
): JsonObject | null {
  const source = object(schema);
  if (!source) return null;
  if (hasRichScalarBoundary(source)) return null;
  const explicit = source.type;
  const explicitKind: ScalarKind | null =
    explicit === "string" ||
    explicit === "integer" ||
    explicit === "number" ||
    explicit === "boolean"
      ? explicit
      : null;
  if (explicit !== undefined && !explicitKind) return null;
  let kind = explicitKind;
  if (!kind && Object.hasOwn(source, "const"))
    kind = primitiveKind(source.const!);
  if (!kind && Array.isArray(source.enum) && source.enum.length > 0) {
    const kinds = source.enum.map(primitiveKind);
    if (kinds.every((value): value is ScalarKind => value !== null)) {
      const unique = new Set(kinds);
      if (unique.size === 1) kind = kinds[0]!;
      else if (
        [...unique].every((value) => value === "integer" || value === "number")
      )
        kind = "number";
    }
  }
  if (!kind) return null;
  const result: JsonObject = { type: kind };
  if (Array.isArray(source.enum))
    result.choices = source.enum.map((value) => ({ value }));
  if (Object.hasOwn(source, "default")) result.default = source.default!;
  return result;
}

function scalarProjection(schema: JsonValue | undefined): JsonObject | null {
  const source = object(schema);
  if (!source) return null;
  if (hasRichScalarBoundary(source)) return null;
  const leaf = scalarLeafProjection(source);
  if (leaf) return leaf;
  if (source.type === "array") {
    const item = scalarLeafProjection(source.items);
    if (item && !Object.hasOwn(item, "default"))
      return { ...item, variadic: true };
  }
  return null;
}

function defaultTrueBoolean(schema: JsonValue | undefined): boolean {
  const projection = scalarLeafProjection(schema);
  return projection?.type === "boolean" && projection.default === true;
}

function projectSchemas(
  capability: Capability,
  schemas: Readonly<Record<string, JsonSchema>>,
) {
  const prefix = `inline\u0000${capability.id}\u0000${capability.version}\u0000`;
  const input = schemaValue(capability.input);
  const output = schemaValue(capability.output);
  if (!input || !output) return null;
  const inputSchema = projectStandaloneSchema(
    input,
    schemas,
    `${prefix}input`,
    {
      requireObject: true,
    },
  );
  const outputSchema = projectStandaloneSchema(
    output,
    schemas,
    `${prefix}output`,
  );
  if (!inputSchema || !outputSchema) return null;
  const errors: JsonObject = {};
  for (const code of Object.keys(capability.errors).sort(compareCodePoint)) {
    const error = capability.errors[code]!;
    const projected: JsonObject = {
      status: error.status,
      message: error.message,
      retryable: error.retryable,
    };
    const raw = error as unknown as JsonObject;
    if (raw.docs !== undefined) projected.docs = clone(raw.docs);
    if (error.details !== undefined) {
      const details = schemaValue(error.details);
      if (!details) return null;
      const projectedDetails = projectStandaloneSchema(
        details,
        schemas,
        `${prefix}error:${code}`,
      );
      if (!projectedDetails) return null;
      projected.details = projectedDetails;
    }
    define(errors, code, projected);
  }
  return { inputSchema, outputSchema, errors: sorted(errors) };
}

function extensionFor(
  capability: Capability,
  irHash: string,
  projected: NonNullable<ReturnType<typeof projectSchemas>>,
): JsonValue {
  const raw = capability as unknown as JsonObject;
  const projection = cliProjection(capability)!;
  return sorted({
    access: clone(capability.access as unknown as JsonValue),
    bindings: clone((projection.bindings ?? {}) as JsonValue),
    canonical: { id: capability.id, version: capability.version },
    encodings: {
      canonicalInput: {
        defaults: "kernel-after-adapter-coercion",
        fileOption: "--input-file",
        inlineOption: "--input",
        merge: "none",
        occurrence: "at-most-one-source",
        scalarMixing: "forbidden",
        stdinSentinel: "-",
        value: "whole-canonical-json-object",
      },
      confirmationToken: "--confirm",
      correlationId: "--correlation-id",
      idempotencyKey: "--idempotency-key",
      machine: ["--json", "--no-input"],
      noInput: {
        affectsBusinessInput: false,
        option: "--no-input",
        semantics: "disable-prompts",
      },
      scalarBindings: {
        assembly: "top-level-object-properties",
        omission: "missing",
        source: "bindings",
      },
      timeout: "--timeout",
    },
    envelope: {
      error: { discriminator: { ok: false }, required: ["error", "ok"] },
      success: {
        discriminator: { ok: true },
        required: ["correlationId", "ok", "value"],
      },
    },
    errors: projected.errors,
    execution: clone(capability.execution as unknown as JsonValue),
    effects: clone(capability.effects as unknown as JsonValue),
    inputSchema: projected.inputSchema,
    irHash,
    lifecycle: clone(raw.lifecycle ?? ({} as JsonValue)),
    outputSchema: projected.outputSchema,
  });
}

function lossSet(
  capability: Capability,
  schemas: Readonly<Record<string, JsonSchema>>,
) {
  const loss = new Set([
    "effects",
    "error_schemas",
    "idempotency",
    "output_schema",
    "permissions",
  ]);
  if (capability.effects.confirmation === "required") loss.add("confirmation");
  const view = inputPropertyView(capability, schemas);
  if (!view) loss.add("nested_input");
  else
    for (const schema of Object.values(view.properties)) {
      if (!scalarProjection(schema)) loss.add("nested_input");
      if (defaultTrueBoolean(schema)) loss.add("boolean_negation");
    }
  return [...loss].sort(compareCodePoint);
}

function baseCommand(
  capability: Capability,
  schemas: Readonly<Record<string, JsonSchema>>,
): JsonObject {
  const command: JsonObject = { kind: "action", summary: capability.summary };
  const view = inputPropertyView(capability, schemas);
  const projection = cliProjection(capability)!;
  const bindings = object(projection.bindings) ?? {};
  const args: (JsonObject & { index: number })[] = [];
  const flags: JsonObject[] = [];
  if (view)
    for (const property of Object.keys(bindings).sort(compareCodePoint)) {
      const binding = object(bindings[property]);
      const scalar = scalarProjection(view.properties[property]);
      if (!binding || !scalar) continue;
      const item: JsonObject = {
        name:
          binding.kind === "option" && typeof binding.name === "string"
            ? binding.name.replace(/^--/u, "")
            : property,
        required: view.required.has(property),
        ...scalar,
      };
      if (binding.kind === "positional" && typeof binding.index === "number")
        args.push({ ...item, index: binding.index });
      else if (binding.kind === "option") flags.push(item);
    }
  if (args.length > 0)
    command.args = args
      .sort((left, right) => left.index - right.index)
      .map(({ index, ...item }) => {
        void index;
        return item;
      });
  if (flags.length > 0) command.flags = flags;
  return command;
}

function extensionCollisionDiagnostics(
  rootExtensions: Readonly<Record<string, JsonValue>>,
  target: string,
) {
  const diagnostics: OpenCliDiagnostic[] = [];
  const carriers: [string, JsonObject][] = [];
  const root = object(rootExtensions as JsonValue);
  if (root) carriers.push(["", root]);
  const commands = object(root?.commands);
  if (commands)
    for (const command of Object.keys(commands).sort(compareCodePoint)) {
      const carrier = object(commands[command]);
      if (carrier)
        carriers.push([
          `/commands/${command.replaceAll("~", "~0").replaceAll("/", "~1")}`,
          carrier,
        ]);
    }
  for (const [path, carrier] of carriers)
    for (const key of ["x-capabuild", "x-capaxle"])
      if (Object.hasOwn(carrier, key))
        diagnostics.push(
          diagnostic("CAP_OPENCLI_EXTENSION_COLLISION", {
            target,
            path: `${path}/${key}`,
            message:
              "Caller metadata cannot supply current or legacy framework OpenCLI extensions.",
          }),
        );
  return sortDiagnostics(diagnostics);
}

export function exportOpenCli(
  document: RuntimeDocument,
  options: OpenCliExportOptions = {},
): OpenCliExportResult {
  const target = options.target ?? OPENCLI_SELECTOR;
  const targetFailure = targetDiagnostic(target);
  if (targetFailure) return { artifact: null, diagnostics: [targetFailure] };
  if (
    (options.extensionVersion ?? OPENCLI_EXTENSION_VERSION) !==
    OPENCLI_EXTENSION_VERSION
  )
    return {
      artifact: null,
      diagnostics: [
        diagnostic("CAP_OPENCLI_VERSION_UNSUPPORTED", {
          target,
          path: "/x-capaxle/contractVersion",
          message: `Unsupported Capaxle OpenCLI extension version ${String(options.extensionVersion)}.`,
        }),
      ],
    };

  const rootExtensions = options.rootExtensions ?? {};
  const collisions = extensionCollisionDiagnostics(rootExtensions, target);
  if (collisions.length > 0) return { artifact: null, diagnostics: collisions };
  const contextDiagnostics = buildContextDiagnostics(
    document,
    target,
    options.buildContext,
  );
  if (contextDiagnostics.length > 0)
    return { artifact: null, diagnostics: contextDiagnostics };

  const capabilities = [...document.capabilities]
    .filter((capability) => cliProjection(capability)?.enabled === true)
    .sort((left, right) => compareCodePoint(left.id, right.id));
  const diagnostics: OpenCliDiagnostic[] = [];
  for (const capability of capabilities) {
    const bindings = object(cliProjection(capability)?.bindings) ?? {};
    const view = inputPropertyView(capability, document.schemas);
    const optionOwners = new Map<string, string>();
    for (const property of Object.keys(bindings).sort(compareCodePoint)) {
      const binding = object(bindings[property]);
      if (binding?.kind === "option" && typeof binding.name === "string")
        optionOwners.set(binding.name, property);
    }
    for (const property of Object.keys(bindings).sort(compareCodePoint)) {
      const binding = object(bindings[property]);
      if (
        binding?.kind === "option" &&
        typeof binding.name === "string" &&
        RESERVED.has(binding.name)
      )
        diagnostics.push(
          diagnostic("CAP_OPENCLI_BINDING_UNREPRESENTABLE", {
            target,
            capabilityId: capability.id,
            path: `/interfaces/cli/bindings/${property.replaceAll("~", "~0").replaceAll("/", "~1")}`,
            details: { option: binding.name },
            message: `${binding.name} is reserved by the Capaxle CLI host.`,
          }),
        );
      if (
        binding?.kind === "option" &&
        typeof binding.name === "string" &&
        defaultTrueBoolean(view?.properties[property])
      ) {
        const negative = `--no-${binding.name.slice(2)}`;
        if (RESERVED.has(negative) || optionOwners.has(negative))
          diagnostics.push(
            diagnostic("CAP_OPENCLI_BINDING_UNREPRESENTABLE", {
              target,
              capabilityId: capability.id,
              path: `/interfaces/cli/bindings/${property.replaceAll("~", "~0").replaceAll("/", "~1")}`,
              details: {
                option: negative,
                reason: "derived-option-collision",
              },
              message: `${negative} collides with a bound or reserved CLI option.`,
            }),
          );
      }
    }
  }
  if (diagnostics.length > 0)
    return { artifact: null, diagnostics: sortDiagnostics(diagnostics) };

  const projectedSchemas = new Map<
    string,
    NonNullable<ReturnType<typeof projectSchemas>>
  >();
  for (const capability of capabilities) {
    const projected = projectSchemas(capability, document.schemas);
    if (!projected)
      diagnostics.push(
        diagnostic("CAP_OPENCLI_SCHEMA_UNREPRESENTABLE", {
          target,
          capabilityId: capability.id,
          path: "/input",
          message:
            "The selected OpenCLI extension could not emit a self-contained capability schema graph.",
        }),
      );
    else projectedSchemas.set(capability.id, projected);
  }
  if (diagnostics.length > 0)
    return { artifact: null, diagnostics: sortDiagnostics(diagnostics) };

  const binary = options.buildContext!.cliBinary!;
  const irHash = options.buildContext!.irHash;
  const commands: JsonObject = {};
  const groups = new Set<string>();
  for (const capability of capabilities) {
    const command = cliProjection(capability)!.command as readonly JsonValue[];
    const tokens = command.filter(
      (value): value is string => typeof value === "string",
    );
    for (let length = 1; length < tokens.length; length += 1)
      groups.add(tokens.slice(0, length).join(" "));
  }
  for (const group of [...groups].sort(compareCodePoint))
    define(commands, `${binary} ${group} {command} [flags]`, { kind: "group" });

  const extensions = options.extensions ?? true;
  for (const capability of capabilities) {
    const projection = cliProjection(capability)!;
    const tokens = (projection.command as readonly JsonValue[]).filter(
      (value): value is string => typeof value === "string",
    );
    const key = `${binary} ${tokens.join(" ")} [flags]`;
    diagnostics.push(
      diagnostic("CAP_OPENCLI_LOSSY_PROJECTION", {
        target,
        capabilityId: capability.id,
        path: `/commands/${key}`,
        severity: extensions ? "warning" : "error",
        details: {
          unrepresented: lossSet(capability, document.schemas),
          preservationPath: `commands[${JSON.stringify(key)}]["x-capaxle"]`,
        },
        message: extensions
          ? "The base OpenCLI dialect is lossy; x-capaxle preserves canonical semantics."
          : "The base OpenCLI dialect is lossy and extensions are disabled.",
      }),
    );
    const command: JsonObject = baseCommand(capability, document.schemas);
    if (extensions)
      command["x-capaxle"] = extensionFor(
        capability,
        irHash,
        projectedSchemas.get(capability.id)!,
      );
    define(commands, key, command);
  }
  if (!extensions)
    return { artifact: null, diagnostics: sortDiagnostics(diagnostics) };

  const service = object((document as unknown as JsonObject).service) ?? {};
  const irVersion = (document as unknown as JsonObject).irVersion;
  const artifact = sorted({
    ...clone(rootExtensions as JsonObject),
    commands,
    global: {
      exitCodes: OPENCLI_EXIT_CODES as unknown as JsonValue,
      flags: RESERVED_CLI_OPTIONS.filter(
        (name) => name !== "--help" && name !== "--version",
      ).map((name) => ({
        name: name.slice(2),
        type: name === "--json" || name === "--no-input" ? "boolean" : "string",
      })),
    },
    info: {
      binary,
      ...(service.title !== undefined || service.name !== undefined
        ? { title: service.title ?? service.name }
        : {}),
      ...(service.version === undefined ? {} : { version: service.version }),
    },
    opencliVersion: OPENCLI_VERSION,
    "x-capaxle": {
      contractVersion: OPENCLI_EXTENSION_VERSION,
      exporterTarget: OPENCLI_TARGET,
      irHash,
      ...(irVersion === undefined ? {} : { irVersion }),
      machineMode: {
        jsonFlag: "--json",
        noInputFlag: "--no-input",
        stderr: "diagnostics",
        stdout: "single-envelope",
      },
      semanticsAuthority: "capability-ir",
    },
  });
  return { artifact, diagnostics: sortDiagnostics(diagnostics) };
}

function frozen<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) frozen(item);
    Object.freeze(value);
  }
  return value;
}

function producerDiagnostics(
  diagnostics: readonly OpenCliDiagnostic[],
): readonly OpenCliDiagnostic[] {
  return sortDiagnostics(
    diagnostics.map((item) => ({
      ...item,
      target: OPENCLI_TARGET,
      ...(item.code === "CAP_OPENCLI_LOSSY_PROJECTION" && item.capabilityId
        ? { path: "/interfaces/cli" }
        : {}),
    })),
  );
}

/** Structural compiler plugin; the adapter never imports the compiler. */
export function createOpenCliArtifactProducer(
  options: Omit<OpenCliExportOptions, "buildContext"> = {},
) {
  const snapshot = frozen(
    clone(
      Object.fromEntries(
        Object.entries(options).filter((entry) => entry[1] !== undefined),
      ) as JsonObject,
    ),
  ) as Omit<OpenCliExportOptions, "buildContext">;
  return frozen({
    id: "capaxle.opencli",
    version: "0.2.0",
    staticInputs: snapshot as Readonly<Record<string, JsonValue>>,
    diagnosticCodes: [
      {
        code: "CAP_BUILD_CONTEXT_INVALID" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_OPENCLI_BINDING_UNREPRESENTABLE" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_OPENCLI_DIALECT_UNSUPPORTED" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_OPENCLI_EXTENSION_COLLISION" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_OPENCLI_LOSSY_PROJECTION" as const,
        severities: ["warning" as const, "error" as const],
      },
      {
        code: "CAP_OPENCLI_SCHEMA_UNREPRESENTABLE" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_OPENCLI_VERSION_UNSUPPORTED" as const,
        severities: ["error" as const],
      },
    ],
    artifacts: [
      {
        id: "opencli",
        path: "opencli.json",
        mediaType: "application/json",
        target: OPENCLI_TARGET,
        dependencies: ["document:capability-ir" as const],
        produce(context: {
          readonly buildContext?: OpenCliBuildContext;
          readonly dependencyBytes: ReadonlyMap<string, Uint8Array>;
        }) {
          const bytes = context.dependencyBytes.get("document:capability-ir");
          if (!bytes)
            return {
              ok: false as const,
              diagnostics: [
                diagnostic("CAP_OPENCLI_SCHEMA_UNREPRESENTABLE", {
                  target: OPENCLI_TARGET,
                  path: "/document",
                  message: "Capability IR artifact dependency is missing.",
                }),
              ],
            };
          let document: RuntimeDocument;
          try {
            document = JSON.parse(
              Buffer.from(bytes).toString("utf8"),
            ) as RuntimeDocument;
          } catch {
            return {
              ok: false as const,
              diagnostics: [
                diagnostic("CAP_OPENCLI_SCHEMA_UNREPRESENTABLE", {
                  target: OPENCLI_TARGET,
                  path: "/document",
                  message: "Capability IR artifact dependency is invalid JSON.",
                }),
              ],
            };
          }
          const result = exportOpenCli(document, {
            ...snapshot,
            ...(context.buildContext === undefined
              ? {}
              : { buildContext: context.buildContext }),
          });
          if (!result.artifact)
            return {
              ok: false as const,
              diagnostics: producerDiagnostics(result.diagnostics),
            };
          return {
            ok: true as const,
            bytes: Buffer.from(`${jcs(result.artifact)}\n`),
            diagnostics: producerDiagnostics(result.diagnostics),
          };
        },
      },
    ],
  });
}
