import type {
  AdapterIngress,
  InvocationResult,
  RuntimeDocument,
} from "@capaxle/runtime";
import { capabilitySemanticHash, jcs } from "@capaxle/ir";
import type { JsonValue } from "@capaxle/ir";
import { projectStandaloneSchema } from "./export-schema.js";

type ObjectData = Record<string, JsonValue>;
type Capability = RuntimeDocument["capabilities"][number];

interface CliBinding {
  readonly kind: "option" | "positional";
  readonly name?: string;
  readonly index?: number;
}

interface CliProjection {
  readonly enabled: boolean;
  readonly command: readonly string[];
  readonly bindings: Readonly<Record<string, CliBinding>>;
}

export interface CliAdapterOptions {
  readonly document: RuntimeDocument;
  readonly irHash: string;
  readonly cliBinary: string;
  readonly ingress: AdapterIngress;
  readonly version?: string;
}

export interface CliRunRequest {
  readonly argv: readonly string[];
  readonly credentials?: unknown;
  readonly signal?: AbortSignal;
  readonly readFile?: (path: string) => string | Promise<string>;
  readonly readStdin?: () => string | Promise<string>;
}

export interface CliRunResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

export interface CliAdapter {
  readonly cliBinary: string;
  readonly irHash: string;
  readonly version: string;
  run(request: CliRunRequest): Promise<CliRunResult>;
}

export const CLI_EXIT_CODES = Object.freeze({
  success: 0,
  invalidInput: 2,
  accessDenied: 3,
  precondition: 4,
  declaredError: 5,
  unavailable: 6,
  internal: 7,
  cancelled: 130,
});

const RESERVED_OPTIONS = new Set([
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

const object = (value: unknown): ObjectData =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as ObjectData)
    : {};

const projection = (capability: Capability): CliProjection =>
  capability.interfaces.cli as unknown as CliProjection;

const unpointer = (value: string) =>
  value.replaceAll("~1", "/").replaceAll("~0", "~");

function rootSchema(
  value: Capability["input"] | Capability["output"],
  document: RuntimeDocument,
): { readonly schema: ObjectData; readonly root: ObjectData } {
  const candidate = object(value);
  if (
    typeof candidate.$ref === "string" &&
    candidate.$ref.startsWith("#/schemas/")
  ) {
    const schema = object(
      document.schemas[unpointer(candidate.$ref.slice(10))],
    );
    return { schema, root: schema };
  }
  const schema = object(candidate.schema);
  return { schema, root: schema };
}

function resolveSchema(
  value: JsonValue | undefined,
  root: ObjectData,
  document: RuntimeDocument,
  seen = new Set<ObjectData>(),
): ObjectData {
  const schema = object(value);
  const ref = schema.$ref;
  if (typeof ref !== "string") return schema;
  if (seen.has(schema)) throw new Error("CAP_CLI_SCHEMA_INVALID");
  seen.add(schema);
  if (ref.startsWith("#/$defs/"))
    return resolveSchema(
      object(root.$defs)[unpointer(ref.slice(8))],
      root,
      document,
      seen,
    );
  if (ref.startsWith("#/schemas/")) {
    const shared = object(document.schemas[unpointer(ref.slice(10))]);
    return resolveSchema(shared, shared, document, seen);
  }
  throw new Error("CAP_CLI_SCHEMA_INVALID");
}

type ScalarKind = "string" | "integer" | "number" | "boolean";
interface ScalarShape {
  readonly kind: ScalarKind;
  readonly array: boolean;
  readonly defaultTrue: boolean;
}

function hasRichBoundary(schema: ObjectData): boolean {
  return (
    Object.hasOwn(schema, "$ref") ||
    Object.hasOwn(schema, "oneOf") ||
    Object.hasOwn(schema, "anyOf") ||
    Object.hasOwn(schema, "allOf")
  );
}

function scalarLeaf(schema: ObjectData): Omit<ScalarShape, "array"> | null {
  if (hasRichBoundary(schema)) return null;
  const explicit = schema.type;
  const scalar = (candidate: unknown): candidate is ScalarKind =>
    typeof candidate === "string" &&
    ["string", "integer", "number", "boolean"].includes(candidate);
  if (explicit !== undefined && !scalar(explicit)) return null;
  let kind: ScalarKind | undefined = scalar(explicit) ? explicit : undefined;
  if (!kind && Object.hasOwn(schema, "const")) {
    const value = schema.const;
    kind =
      typeof value === "boolean"
        ? "boolean"
        : typeof value === "string"
          ? "string"
          : typeof value === "number"
            ? Number.isInteger(value)
              ? "integer"
              : "number"
            : undefined;
  }
  if (!kind && Array.isArray(schema.enum) && schema.enum.length) {
    if (schema.enum.every((value) => typeof value === "number"))
      kind = schema.enum.every((value) => Number.isInteger(value))
        ? "integer"
        : "number";
    else {
      const kinds = new Set(schema.enum.map((value) => typeof value));
      const [only] = kinds;
      if (kinds.size === 1 && scalar(only)) kind = only;
    }
  }
  if (!kind) return null;
  return {
    kind,
    defaultTrue: kind === "boolean" && schema.default === true,
  };
}

function scalarShape(value: JsonValue | undefined): ScalarShape | null {
  const schema = object(value);
  if (hasRichBoundary(schema)) return null;
  if (schema.type === "array") {
    const item = scalarLeaf(object(schema.items));
    return item ? { ...item, array: true, defaultTrue: false } : null;
  }
  const leaf = scalarLeaf(schema);
  return leaf ? { ...leaf, array: false } : null;
}

function coerce(text: string, kind: ScalarKind): JsonValue {
  if (kind === "string") return text;
  if (kind === "boolean") {
    if (text === "true") return true;
    if (text === "false") return false;
    throw new Error("boolean");
  }
  if (!/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(text))
    throw new Error("number");
  const value = Number(text);
  if (
    !Number.isFinite(value) ||
    (kind === "integer" && !Number.isInteger(value))
  )
    throw new Error("number");
  return value;
}

function jsonObject(text: string): Record<string, unknown> {
  const value = JSON.parse(text) as unknown;
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("object");
  return value as Record<string, unknown>;
}

function duration(value: string): number {
  const match = /^(0|[1-9][0-9]*)(ms|s|m|h)$/.exec(value);
  if (!match) throw new Error("duration");
  const unit = { ms: 1, s: 1000, m: 60000, h: 3600000 }[
    match[2] as "ms" | "s" | "m" | "h"
  ];
  const milliseconds = Number(match[1]) * unit;
  if (!Number.isSafeInteger(milliseconds)) throw new Error("duration");
  return milliseconds;
}

function copyJson(value: JsonValue): JsonValue {
  return JSON.parse(jcs(value)) as JsonValue;
}

function standaloneSchema(
  binding: Capability["input"] | Capability["output"],
  document: RuntimeDocument,
  owner: string,
): JsonValue {
  const value = object(binding);
  const schema =
    typeof value.$ref === "string"
      ? (value as unknown as JsonValue)
      : value.schema;
  const projected = projectStandaloneSchema(
    object(schema),
    document.schemas,
    owner,
  );
  if (!projected) throw new Error("CAP_CLI_SCHEMA_INVALID");
  return projected;
}

function errorExit(
  result: Extract<InvocationResult, { readonly ok: false }>,
  capability?: Capability,
) {
  const { code, status } = result.error;
  if (code === "CAP_CANCELLED" || status === "cancelled")
    return CLI_EXIT_CODES.cancelled;
  if (code === "CAP_INPUT_INVALID" || status === "invalid_argument")
    return CLI_EXIT_CODES.invalidInput;
  if (status === "unauthenticated" || status === "permission_denied")
    return CLI_EXIT_CODES.accessDenied;
  if (capability && Object.hasOwn(capability.errors, code))
    return CLI_EXIT_CODES.declaredError;
  if (code === "CAP_CONFIRMATION_REQUIRED" || status === "failed_precondition")
    return CLI_EXIT_CODES.precondition;
  if (
    status === "resource_exhausted" ||
    status === "unavailable" ||
    status === "deadline_exceeded"
  )
    return CLI_EXIT_CODES.unavailable;
  return CLI_EXIT_CODES.internal;
}

function render(
  result: InvocationResult,
  json: boolean,
  capability?: Capability,
): CliRunResult {
  if (json)
    return {
      exitCode: result.ok
        ? CLI_EXIT_CODES.success
        : errorExit(result, capability),
      stdout: `${jcs(copyJson(result as unknown as JsonValue))}\n`,
      stderr: "",
    };
  if (result.ok)
    return {
      exitCode: CLI_EXIT_CODES.success,
      stdout: `${JSON.stringify(copyJson(result.value), null, 2)}\n`,
      stderr: "",
    };
  return {
    exitCode: errorExit(result, capability),
    stdout: "",
    stderr: `${result.error.code}: ${result.error.message}\n`,
  };
}

function discoveryResult(value: JsonValue, json: boolean): CliRunResult {
  return {
    exitCode: 0,
    stdout: `${json ? jcs(value) : JSON.stringify(value, null, 2)}\n`,
    stderr: "",
  };
}

function parseGlobals(argv: readonly string[]) {
  let json = false;
  let noInput = false;
  let inline: string | undefined;
  let inputFile: string | undefined;
  let correlationId: string | undefined;
  let idempotencyKey: string | undefined;
  let confirmationToken: string | undefined;
  let timeoutMs: number | undefined;
  let help = false;
  let version = false;
  let invalid = false;
  const rest: string[] = [];
  const seen = new Set<string>();
  const valued = new Set([
    "--input",
    "--input-file",
    "--correlation-id",
    "--idempotency-key",
    "--confirm",
    "--timeout",
  ]);
  for (let index = 0; index < argv.length; index++) {
    const token = argv[index]!;
    if (!RESERVED_OPTIONS.has(token)) {
      rest.push(token);
      continue;
    }
    if (seen.has(token)) {
      invalid = true;
      continue;
    }
    seen.add(token);
    if (valued.has(token)) {
      const value = argv[++index];
      if (value === undefined || value.startsWith("--")) {
        invalid = true;
        continue;
      }
      try {
        if (token === "--input") inline = value;
        else if (token === "--input-file") inputFile = value;
        else if (token === "--correlation-id") correlationId = value;
        else if (token === "--idempotency-key") idempotencyKey = value;
        else if (token === "--confirm") confirmationToken = value;
        else timeoutMs = duration(value);
      } catch {
        invalid = true;
      }
    } else if (token === "--json") json = true;
    else if (token === "--no-input") noInput = true;
    else if (token === "--help") help = true;
    else if (token === "--version") version = true;
  }
  if (inline !== undefined && inputFile !== undefined) invalid = true;
  return {
    json,
    noInput,
    inline,
    inputFile,
    correlationId,
    idempotencyKey,
    confirmationToken,
    timeoutMs,
    help,
    version,
    invalid,
    rest,
  };
}

function validateTree(document: RuntimeDocument): Capability[] {
  const capabilities = document.capabilities.filter(
    (capability) =>
      projection(capability).enabled &&
      capability.access.exposure.cli !== "disabled",
  );
  const paths = new Map<string, string>();
  for (const capability of capabilities) {
    const cli = projection(capability);
    if (
      !cli.command.length ||
      cli.command.some((part) => typeof part !== "string" || !part)
    )
      throw new Error("CAP_CLI_COMMAND_INVALID");
    if (cli.command[0] === "capabilities")
      throw new Error("CAP_CLI_COMMAND_COLLISION");
    const command = cli.command.join("\0");
    if (paths.has(command)) throw new Error("CAP_CLI_COMMAND_COLLISION");
    for (const other of paths.keys())
      if (command.startsWith(`${other}\0`) || other.startsWith(`${command}\0`))
        throw new Error("CAP_CLI_COMMAND_COLLISION");
    paths.set(command, capability.id);
    const root = rootSchema(capability.input, document);
    const schema = resolveSchema(root.schema, root.root, document);
    const properties = object(schema.properties);
    const bindings = Object.entries(cli.bindings);
    if (
      Object.keys(properties).sort().join("\0") !==
      bindings
        .map(([name]) => name)
        .sort()
        .join("\0")
    )
      throw new Error("CAP_CLI_BINDING_INVALID");
    const options = new Set<string>();
    const negativeOptions = new Set<string>();
    const positions = new Set<number>();
    let variadic: number | undefined;
    for (const [property, binding] of bindings) {
      const shape = scalarShape(properties[property]);
      if (binding.kind === "option") {
        if (
          !binding.name ||
          RESERVED_OPTIONS.has(binding.name) ||
          options.has(binding.name)
        )
          throw new Error("CAP_CLI_BINDING_INVALID");
        options.add(binding.name);
        if (shape?.kind === "boolean" && shape.defaultTrue)
          negativeOptions.add(`--no-${binding.name.slice(2)}`);
      } else if (
        binding.kind !== "positional" ||
        !Number.isSafeInteger(binding.index) ||
        binding.index! < 0 ||
        positions.has(binding.index!)
      )
        throw new Error("CAP_CLI_BINDING_INVALID");
      else {
        positions.add(binding.index!);
        if (shape?.array) {
          if (variadic !== undefined)
            throw new Error("CAP_CLI_BINDING_INVALID");
          variadic = binding.index;
        }
      }
    }
    const sorted = [...positions].sort((left, right) => left - right);
    if (sorted.some((position, index) => position !== index))
      throw new Error("CAP_CLI_BINDING_INVALID");
    if (variadic !== undefined && variadic !== sorted.at(-1))
      throw new Error("CAP_CLI_BINDING_INVALID");
    if (
      [...negativeOptions].some(
        (name) => options.has(name) || RESERVED_OPTIONS.has(name),
      )
    )
      throw new Error("CAP_CLI_BINDING_INVALID");
  }
  return capabilities;
}

async function invalid(
  ingress: AdapterIngress,
  json: boolean,
  credentials: unknown,
  signal: AbortSignal | undefined,
  capability = "",
): Promise<CliRunResult> {
  const result = await ingress.invoke({
    capability,
    ...(credentials !== undefined ? { credentials } : {}),
    ...(signal ? { signal } : {}),
    adapterCandidate: {
      ok: false,
      code: "CAP_INPUT_INVALID",
      status: "invalid_argument",
    },
  });
  const rendered = render(result, json);
  return capability === "" ? { ...rendered, exitCode: 2 } : rendered;
}

export function createCliAdapter(options: CliAdapterOptions): CliAdapter {
  if (capabilitySemanticHash(options.document) !== options.irHash)
    throw new Error("CAP_CLI_IR_HASH_MISMATCH");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(options.cliBinary))
    throw new Error("CAP_BUILD_CONTEXT_INVALID");
  const capabilities = validateTree(options.document);
  const publicCapabilities = capabilities.filter(
    (capability) => capability.access.exposure.cli === "public",
  );
  const byId = new Map(
    publicCapabilities.map((capability) => [capability.id, capability]),
  );
  const version = options.version ?? "0.0.0";
  return Object.freeze({
    cliBinary: options.cliBinary,
    irHash: options.irHash,
    version,
    async run(request: CliRunRequest): Promise<CliRunResult> {
      const versionRequested = request.argv.includes("--version");
      const helpRequested = request.argv.includes("--help");
      const globals = parseGlobals(request.argv);
      if (versionRequested)
        return discoveryResult(
          { binary: options.cliBinary, version, irHash: options.irHash },
          globals.json,
        );
      if (
        helpRequested &&
        (globals.rest.length === 0 || globals.rest[0] === "capabilities")
      )
        return discoveryResult(
          {
            binary: options.cliBinary,
            usage: `${options.cliBinary} <command> [flags]`,
            discovery: [
              "capabilities list",
              "capabilities describe",
              "capabilities schema",
              "capabilities interfaces",
            ],
            irHash: options.irHash,
          },
          globals.json,
        );
      if (helpRequested) {
        const publicCapability = publicCapabilities.find((candidate) => {
          const command = projection(candidate).command;
          return command.every((token, index) => globals.rest[index] === token);
        });
        if (!publicCapability)
          return invalid(
            options.ingress,
            globals.json,
            request.credentials,
            request.signal,
          );
        const cli = projection(publicCapability);
        const lifecycle = (publicCapability as unknown as ObjectData).lifecycle;
        return discoveryResult(
          {
            irHash: options.irHash,
            id: publicCapability.id,
            summary: publicCapability.summary,
            ...(lifecycle === undefined ? {} : { lifecycle }),
            command: cli.command,
            bindings: cli.bindings as unknown as JsonValue,
          },
          globals.json,
        );
      }
      if (globals.invalid) {
        const target = capabilities.find((candidate) =>
          projection(candidate).command.every(
            (token, index) => globals.rest[index] === token,
          ),
        );
        return invalid(
          options.ingress,
          globals.json,
          request.credentials,
          request.signal,
          target?.id ?? "",
        );
      }
      if (globals.rest[0] === "capabilities") {
        const action = globals.rest[1];
        const id = globals.rest[2];
        if (action === "list" && globals.rest.length === 2)
          return discoveryResult(
            {
              irHash: options.irHash,
              capabilities: publicCapabilities.map((capability) => ({
                id: capability.id,
                version: capability.version,
                summary: capability.summary,
                command: projection(capability).command,
              })),
            },
            globals.json,
          );
        const capability = typeof id === "string" ? byId.get(id) : undefined;
        if (!capability || globals.rest.length !== 3)
          return invalid(
            options.ingress,
            globals.json,
            request.credentials,
            request.signal,
          );
        if (action === "describe")
          return discoveryResult(
            {
              irHash: options.irHash,
              capability: {
                id: capability.id,
                version: capability.version,
                summary: capability.summary,
                effects: capability.effects as unknown as JsonValue,
                command: projection(capability).command,
              },
            },
            globals.json,
          );
        if (action === "schema")
          return discoveryResult(
            {
              irHash: options.irHash,
              id: capability.id,
              version: capability.version,
              input: standaloneSchema(
                capability.input,
                options.document,
                `input:${capability.id}:${capability.version}`,
              ),
              output: standaloneSchema(
                capability.output,
                options.document,
                `output:${capability.id}:${capability.version}`,
              ),
            },
            globals.json,
          );
        if (action === "interfaces")
          return discoveryResult(
            {
              irHash: options.irHash,
              id: capability.id,
              version: capability.version,
              interfaces: capability.interfaces as unknown as JsonValue,
            },
            globals.json,
          );
        return invalid(
          options.ingress,
          globals.json,
          request.credentials,
          request.signal,
        );
      }

      const capability = capabilities.find((candidate) => {
        const command = projection(candidate).command;
        return command.every((token, index) => globals.rest[index] === token);
      });
      if (!capability)
        return invalid(
          options.ingress,
          globals.json,
          request.credentials,
          request.signal,
        );
      const cli = projection(capability);
      const args = globals.rest.slice(cli.command.length);
      const whole =
        globals.inline !== undefined || globals.inputFile !== undefined;
      if (whole && args.length)
        return invalid(
          options.ingress,
          globals.json,
          request.credentials,
          request.signal,
          capability.id,
        );
      let input: Record<string, unknown> = Object.create(null) as Record<
        string,
        unknown
      >;
      try {
        if (globals.inline !== undefined) input = jsonObject(globals.inline);
        else if (globals.inputFile !== undefined) {
          const text =
            globals.inputFile === "-"
              ? await request.readStdin?.()
              : await request.readFile?.(globals.inputFile);
          if (typeof text !== "string") throw new Error("reader");
          input = jsonObject(text);
        } else {
          const root = rootSchema(capability.input, options.document);
          const schema = resolveSchema(
            root.schema,
            root.root,
            options.document,
          );
          const properties = object(schema.properties);
          const optionBindings = new Map<
            string,
            { property: string; shape: ScalarShape }
          >();
          const negativeBindings = new Map<
            string,
            { property: string; shape: ScalarShape }
          >();
          const positionals: {
            property: string;
            index: number;
            shape: ScalarShape;
          }[] = [];
          let richPositional = false;
          for (const [property, binding] of Object.entries(cli.bindings)) {
            const shape = scalarShape(properties[property]);
            if (!shape) {
              if (binding.kind === "positional") richPositional = true;
              continue;
            }
            if (binding.kind === "option") {
              optionBindings.set(binding.name!, { property, shape });
              if (shape.kind === "boolean" && shape.defaultTrue)
                negativeBindings.set(`--no-${binding.name!.slice(2)}`, {
                  property,
                  shape,
                });
            } else positionals.push({ property, index: binding.index!, shape });
          }
          if (richPositional) positionals.length = 0;
          positionals.sort((left, right) => left.index - right.index);
          const positionalValues: string[] = [];
          for (let index = 0; index < args.length; index++) {
            const token = args[index]!;
            const binding =
              optionBindings.get(token) ?? negativeBindings.get(token);
            if (!binding) {
              if (token.startsWith("--")) throw new Error("unknown option");
              positionalValues.push(token);
              continue;
            }
            if (Object.hasOwn(input, binding.property) && !binding.shape.array)
              throw new Error("duplicate option");
            let value: JsonValue;
            if (binding.shape.kind === "boolean")
              value = negativeBindings.has(token) ? false : true;
            else {
              const raw = args[++index];
              if (raw === undefined || raw.startsWith("--"))
                throw new Error("missing value");
              value = coerce(raw, binding.shape.kind);
            }
            if (binding.shape.array) {
              const existing = input[binding.property];
              input[binding.property] = Array.isArray(existing)
                ? [...existing, value]
                : [value];
            } else input[binding.property] = value;
          }
          let consumed = 0;
          for (const binding of positionals) {
            if (binding.shape.array) {
              const remaining = positionalValues.slice(consumed);
              if (remaining.length)
                input[binding.property] = remaining.map((value) =>
                  coerce(value, binding.shape.kind),
                );
              consumed = positionalValues.length;
            } else if (positionalValues[consumed] !== undefined)
              input[binding.property] = coerce(
                positionalValues[consumed++]!,
                binding.shape.kind,
              );
          }
          if (consumed !== positionalValues.length)
            throw new Error("extra positional");
        }
      } catch {
        return invalid(
          options.ingress,
          globals.json,
          request.credentials,
          request.signal,
          capability.id,
        );
      }
      const result = await options.ingress.invoke({
        capability: capability.id,
        input,
        ...(request.credentials !== undefined
          ? { credentials: request.credentials }
          : {}),
        ...(globals.correlationId !== undefined
          ? { correlationId: globals.correlationId }
          : {}),
        ...(globals.idempotencyKey !== undefined
          ? { idempotencyKey: globals.idempotencyKey }
          : {}),
        ...(globals.confirmationToken !== undefined
          ? { confirmationToken: globals.confirmationToken }
          : {}),
        ...(globals.timeoutMs !== undefined
          ? { deadline: new Date(Date.now() + globals.timeoutMs) }
          : {}),
        ...(request.signal ? { signal: request.signal } : {}),
      });
      return render(result, globals.json, capability);
    },
  });
}
