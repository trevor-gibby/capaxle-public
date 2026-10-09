import { fail, integer, object, finiteJson } from "./common.js";
import type { Data } from "./common.js";

export interface InputCapability {
  readonly input: unknown;
  readonly bindings: Readonly<
    Record<
      string,
      | { readonly kind: "option"; readonly name: string }
      | { readonly kind: "positional"; readonly index: number }
    >
  >;
}
export interface InputReaders {
  readonly readFile?: (path: string) => string | Promise<string>;
  readonly readStdin?: () => string | Promise<string>;
}
type ScalarKind = "string" | "integer" | "number" | "boolean";
interface Shape {
  kind: ScalarKind;
  array: boolean;
  defaultTrue: boolean;
}
const data = (value: unknown): Data => (object(value) ? value : {});
function leaf(value: unknown): Omit<Shape, "array"> | null {
  const schema = data(value);
  if (
    ["$ref", "oneOf", "anyOf", "allOf"].some((key) =>
      Object.hasOwn(schema, key),
    )
  )
    return null;
  const scalar = (value: unknown): value is ScalarKind =>
    typeof value === "string" &&
    ["string", "integer", "number", "boolean"].includes(value);
  if (schema.type !== undefined && !scalar(schema.type)) return null;
  let kind = scalar(schema.type) ? schema.type : undefined;
  if (!kind && Object.hasOwn(schema, "const")) {
    const v = schema.const;
    kind =
      typeof v === "number"
        ? Number.isInteger(v)
          ? "integer"
          : "number"
        : scalar(typeof v)
          ? (typeof v as ScalarKind)
          : undefined;
  }
  if (!kind && Array.isArray(schema.enum) && schema.enum.length) {
    if (schema.enum.every((v) => typeof v === "number"))
      kind = schema.enum.every(Number.isInteger) ? "integer" : "number";
    else {
      const kinds = new Set(schema.enum.map((v) => typeof v));
      const [only] = kinds;
      if (kinds.size === 1 && scalar(only)) kind = only;
    }
  }
  return kind
    ? { kind, defaultTrue: kind === "boolean" && schema.default === true }
    : null;
}
function shape(value: unknown): Shape | null {
  const schema = data(value);
  if (
    ["$ref", "oneOf", "anyOf", "allOf"].some((key) =>
      Object.hasOwn(schema, key),
    )
  )
    return null;
  const result = leaf(schema.type === "array" ? schema.items : schema);
  return result
    ? {
        ...result,
        array: schema.type === "array",
        ...(schema.type === "array" ? { defaultTrue: false } : {}),
      }
    : null;
}
function root(
  value: unknown,
  schema = data(value),
  seen = new Set<unknown>(),
): Data {
  if (typeof schema.$ref !== "string") return schema;
  if (seen.has(schema) || !schema.$ref.startsWith("#/$defs/")) fail();
  seen.add(schema);
  const key = schema.$ref.slice(8).replaceAll("~1", "/").replaceAll("~0", "~");
  return root(value, data(data(data(value).$defs)[key]), seen);
}
function coerce(raw: string, kind: ScalarKind): unknown {
  if (kind === "string") return raw;
  if (kind === "boolean") {
    if (raw === "true") return true;
    if (raw === "false") return false;
    fail();
  }
  if (!/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/u.test(raw))
    fail();
  const number = Number(raw);
  if (
    !Number.isFinite(number) ||
    (kind === "integer" && !Number.isInteger(number))
  )
    fail();
  return number;
}
export function parseRemoteGlobals(argv: readonly string[]) {
  const valued = new Set([
    "--input",
    "--input-file",
    "--correlation-id",
    "--idempotency-key",
    "--confirm",
    "--timeout",
  ]);
  const flags = new Set(["--json", "--no-input", "--help", "--version"]);
  const values: Record<string, string> = Object.create(null) as Record<
    string,
    string
  >;
  const seen = new Set<string>();
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (!valued.has(arg) && !flags.has(arg)) {
      rest.push(arg);
      continue;
    }
    if (seen.has(arg)) fail();
    seen.add(arg);
    if (valued.has(arg)) {
      const value = argv[++i];
      if (value === undefined || value.startsWith("--")) fail();
      values[arg] = value;
    }
  }
  if (seen.has("--input") && seen.has("--input-file")) fail();
  const controls: {
    confirmationToken?: string;
    idempotencyKey?: string;
    correlationId?: string;
    timeoutMs?: number;
  } = {};
  for (const [flag, key] of [
    ["--confirm", "confirmationToken"],
    ["--idempotency-key", "idempotencyKey"],
    ["--correlation-id", "correlationId"],
  ] as const)
    if (values[flag] !== undefined) controls[key] = values[flag];
  if (values["--timeout"] !== undefined) {
    const match = /^(0|[1-9][0-9]*)(ms|s|m|h)$/u.exec(values["--timeout"]);
    if (!match) fail();
    const timeout =
      Number(match[1]) *
      { ms: 1, s: 1000, m: 60000, h: 3600000 }[
        match[2] as "ms" | "s" | "m" | "h"
      ];
    if (!integer(timeout, 1, 300000)) fail();
    controls.timeoutMs = timeout;
  }
  return {
    json: seen.has("--json"),
    noInput: seen.has("--no-input"),
    help: seen.has("--help"),
    version: seen.has("--version"),
    rest,
    controls,
    inline: values["--input"],
    inputFile: values["--input-file"],
  };
}
export async function parseRemoteInput(
  capability: InputCapability,
  argv: readonly string[],
  readers: InputReaders = {},
  commandLength = 0,
) {
  const globals = parseRemoteGlobals(argv);
  const args = globals.rest.slice(commandLength);
  const input: Data = Object.create(null) as Data;
  if (globals.inline !== undefined || globals.inputFile !== undefined) {
    if (args.length) fail();
    try {
      const raw =
        globals.inline ??
        (globals.inputFile === "-"
          ? await readers.readStdin?.()
          : await readers.readFile?.(globals.inputFile!));
      if (typeof raw !== "string") fail();
      const candidate: unknown = JSON.parse(raw);
      if (!object(candidate) || !finiteJson(candidate)) fail();
      return { ...globals, input: candidate };
    } catch {
      fail();
    }
  }
  const properties = data(root(capability.input).properties);
  const options = new Map<
    string,
    { property: string; shape: Shape; negative?: boolean }
  >();
  const positionals: { property: string; index: number; shape: Shape }[] = [];
  let rich = false;
  for (const [property, binding] of Object.entries(capability.bindings)) {
    const scalar = shape(properties[property]);
    if (!scalar) {
      if (binding.kind === "positional") rich = true;
      continue;
    }
    if (binding.kind === "option") {
      options.set(binding.name, { property, shape: scalar });
      if (scalar.kind === "boolean" && scalar.defaultTrue)
        options.set(`--no-${binding.name.slice(2)}`, {
          property,
          shape: scalar,
          negative: true,
        });
    } else positionals.push({ property, index: binding.index, shape: scalar });
  }
  if (rich) positionals.length = 0;
  positionals.sort((a, b) => a.index - b.index);
  const positionalValues: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const token = args[i]!;
    const binding = options.get(token);
    if (!binding) {
      if (token.startsWith("--")) fail();
      positionalValues.push(token);
      continue;
    }
    if (Object.hasOwn(input, binding.property) && !binding.shape.array) fail();
    let value: unknown;
    if (binding.shape.kind === "boolean") value = !binding.negative;
    else {
      const raw = args[++i];
      if (raw === undefined || raw.startsWith("--")) fail();
      value = coerce(raw, binding.shape.kind);
    }
    if (binding.shape.array) {
      const previous = input[binding.property];
      input[binding.property] = Array.isArray(previous)
        ? [...previous, value]
        : [value];
    } else input[binding.property] = value;
  }
  let consumed = 0;
  for (const binding of positionals) {
    if (binding.shape.array) {
      const remaining = positionalValues.slice(consumed);
      if (remaining.length)
        input[binding.property] = remaining.map((v) =>
          coerce(v, binding.shape.kind),
        );
      consumed = positionalValues.length;
    } else if (positionalValues[consumed] !== undefined)
      input[binding.property] = coerce(
        positionalValues[consumed++]!,
        binding.shape.kind,
      );
  }
  if (consumed !== positionalValues.length) fail();
  return { ...globals, input: { ...input } };
}
