import { createHash } from "node:crypto";
import { types } from "node:util";
import { RuntimeConfigurationError } from "./registry.js";

export interface BearerSegmentDescriptor {
  readonly name: string;
  readonly alphabet: "ascii-upper" | "base64url-token" | "base64url-256";
  readonly minLength: number;
  readonly maxLength: number;
}
export interface BearerNamespaceDescriptor {
  readonly namespaceType: string;
  readonly version: number;
  readonly separator: ".";
  readonly segments: readonly BearerSegmentDescriptor[];
  readonly reconstructibleComponents: readonly (readonly string[])[];
}
export interface ParsedBearer {
  readonly identity: string;
  readonly namespaceType: string;
  readonly version: number;
  readonly segments: Readonly<Record<string, string>>;
}
export interface CompiledBearerGuard {
  readonly identity: string;
  readonly descriptors: readonly BearerNamespaceDescriptor[];
  parse(value: unknown): ParsedBearer | null;
  detects(value: string): boolean;
  redactString(value: string): string;
  redactValue(value: unknown): unknown;
  validateCorrelationHint(
    value: unknown,
    supplied?: boolean,
  ): Readonly<{ valid: boolean }>;
}
const REDACTED = "[!]";
const VALID = Object.freeze({ valid: true });
const INVALID = Object.freeze({ valid: false });
const rootKeys = [
  "namespaceType",
  "version",
  "separator",
  "segments",
  "reconstructibleComponents",
];
const segmentKeys = ["name", "alphabet", "minLength", "maxLength"];

/** Recursively inspect the complete carrier before reading any semantic field. */
function inspectCarrier(
  value: unknown,
  budget = { left: 4096 },
  depth = 0,
): void {
  if (--budget.left < 0 || depth > 8) throw new Error("bounds");
  if (value === null || typeof value !== "object") {
    if (!["string", "number"].includes(typeof value))
      throw new Error("primitive");
    return;
  }
  if (types.isProxy(value)) throw new Error("proxy");
  const array = Array.isArray(value);
  if (
    Object.getPrototypeOf(value) !==
    (array ? Array.prototype : Object.prototype)
  )
    throw new Error("prototype");
  const keys = Reflect.ownKeys(value);
  if (keys.length > 65) throw new Error("bounds");
  if (array) {
    const length = Object.getOwnPropertyDescriptor(value, "length");
    if (
      !length ||
      !("value" in length) ||
      !Number.isInteger(length.value) ||
      length.value > 64 ||
      length.enumerable ||
      length.configurable ||
      !length.writable ||
      keys.length !== length.value + 1
    )
      throw new Error("array");
    for (let i = 0; i < length.value; i++)
      if (!Object.hasOwn(value, String(i))) throw new Error("hole");
  }
  for (const key of keys) {
    if (typeof key !== "string") throw new Error("symbol");
    if (array && key === "length") continue;
    if (array && !/^(0|[1-9][0-9]*)$/.test(key)) throw new Error("index");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      !descriptor ||
      !("value" in descriptor) ||
      !descriptor.enumerable ||
      !descriptor.configurable ||
      !descriptor.writable
    )
      throw new Error("property");
    inspectCarrier(descriptor.value, budget, depth + 1);
  }
}
function exactRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key))
  )
    throw new Error("record");
  return value as Record<string, unknown>;
}
function normalize(value: unknown): BearerNamespaceDescriptor {
  const root = exactRecord(value, rootKeys);
  if (
    typeof root.namespaceType !== "string" ||
    !/^[a-z][a-z0-9-]{0,15}$/.test(root.namespaceType) ||
    !Number.isInteger(root.version) ||
    Number(root.version) < 1 ||
    Number(root.version) > 999999 ||
    root.separator !== "." ||
    !Array.isArray(root.segments) ||
    root.segments.length < 1 ||
    root.segments.length > 8 ||
    !Array.isArray(root.reconstructibleComponents) ||
    root.reconstructibleComponents.length > 36
  )
    throw new Error("namespace");
  const names = new Set<string>();
  const segments = root.segments.map((value: unknown) => {
    const segment = exactRecord(value, segmentKeys);
    const { name, alphabet, minLength, maxLength } = segment;
    if (
      typeof name !== "string" ||
      !/^[A-Za-z][A-Za-z0-9]{0,31}$/.test(name) ||
      names.has(name) ||
      typeof alphabet !== "string" ||
      !["ascii-upper", "base64url-token", "base64url-256"].includes(alphabet) ||
      !Number.isInteger(minLength) ||
      !Number.isInteger(maxLength) ||
      Number(minLength) < 1 ||
      Number(maxLength) > 64 ||
      Number(minLength) > Number(maxLength) ||
      (alphabet === "base64url-256" && (minLength !== 43 || maxLength !== 43))
    )
      throw new Error("segment");
    names.add(name);
    return Object.freeze({
      name,
      alphabet: alphabet as BearerSegmentDescriptor["alphabet"],
      minLength: Number(minLength),
      maxLength: Number(maxLength),
    });
  });
  const prefix = `${root.namespaceType}${root.version}.`;
  if (
    prefix.length +
      segments.reduce((size, segment) => size + segment.maxLength, 0) +
      segments.length -
      1 >
    256
  )
    throw new Error("artifact bounds");
  const components = root.reconstructibleComponents.map((value: unknown) => {
    if (
      !Array.isArray(value) ||
      value.length < 1 ||
      value.length > segments.length ||
      value.some((name) => typeof name !== "string")
    )
      throw new Error("component");
    const start = segments.findIndex((segment) => segment.name === value[0]);
    if (
      start < 0 ||
      value.some((name, i) => name !== segments[start + i]?.name)
    )
      throw new Error("contiguous");
    return Object.freeze([...value]) as readonly string[];
  });
  if (
    new Set(components.map((component) => component.join("."))).size !==
    components.length
  )
    throw new Error("duplicate component");
  return Object.freeze({
    namespaceType: root.namespaceType,
    version: Number(root.version),
    separator: ".",
    segments: Object.freeze(segments),
    reconstructibleComponents: Object.freeze(components),
  });
}
function defaultDescriptor(namespaceType: string): BearerNamespaceDescriptor {
  return {
    namespaceType,
    version: 1,
    separator: ".",
    segments: [
      {
        name: "keyId",
        alphabet: "base64url-token",
        minLength: 1,
        maxLength: 32,
      },
      {
        name: "nonce",
        alphabet: "base64url-256",
        minLength: 43,
        maxLength: 43,
      },
      { name: "tag", alphabet: "base64url-256", minLength: 43, maxLength: 43 },
    ],
    reconstructibleComponents: [
      ["keyId", "nonce", "tag"],
      ["nonce", "tag"],
    ],
  };
}
function pattern(segment: BearerSegmentDescriptor, canonical: boolean): string {
  if (segment.alphabet === "base64url-256" && canonical)
    return "[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]";
  const alphabet =
    segment.alphabet === "ascii-upper" ? "[A-Z]" : "[A-Za-z0-9_-]";
  return `${alphabet}{${segment.minLength},${segment.maxLength}}`;
}
function sample(
  segment: BearerSegmentDescriptor,
  max: boolean,
  varied: boolean,
): string {
  const size = max ? segment.maxLength : segment.minLength;
  if (segment.alphabet === "base64url-256")
    return Buffer.from(
      Array.from({ length: 32 }, (_, i) => (varied ? (i * 19 + 7) % 256 : 0)),
    ).toString("base64url");
  const alphabet = segment.alphabet === "ascii-upper" ? "AZQ" : "aZ0_-";
  return Array.from(
    { length: size },
    (_, i) => alphabet[varied ? i % alphabet.length : 0],
  ).join("");
}

/** One compiler owns every detection/redaction surface; configuration cannot supply matchers. */
export function compileBearerDescriptors(
  additionalDescriptors: readonly unknown[] = [],
): CompiledBearerGuard {
  try {
    inspectCarrier(additionalDescriptors);
    if (
      !Array.isArray(additionalDescriptors) ||
      additionalDescriptors.length > 30
    )
      throw new Error("descriptor bounds");
    const descriptors = Object.freeze(
      [
        normalize(defaultDescriptor("capc")),
        normalize(defaultDescriptor("capa")),
        ...additionalDescriptors.map(normalize),
      ].sort((a, b) => {
        const left = `${a.namespaceType}${a.version}`;
        const right = `${b.namespaceType}${b.version}`;
        return left < right ? -1 : left > right ? 1 : 0;
      }),
    );
    const prefixes = descriptors.map(
      (descriptor) => `${descriptor.namespaceType}${descriptor.version}`,
    );
    if (new Set(prefixes).size !== prefixes.length)
      throw new Error("collision");
    const identity = `capbd1.${createHash("sha256").update(JSON.stringify(descriptors)).digest("hex")}`;
    const parsers = descriptors.map(
      (descriptor) =>
        new RegExp(
          `^${descriptor.namespaceType}${descriptor.version}\\.${descriptor.segments.map((segment) => pattern(segment, true)).join("\\.")}$`,
        ),
    );
    const sources = descriptors.flatMap((descriptor) => {
      const full = `${descriptor.namespaceType}${descriptor.version}\\.${descriptor.segments.map((segment) => pattern(segment, false)).join("\\.")}`;
      const components = descriptor.reconstructibleComponents.map((component) =>
        component
          .map((name) =>
            pattern(
              descriptor.segments.find((segment) => segment.name === name)!,
              false,
            ),
          )
          .join("\\."),
      );
      // Prefixes alone remain suspicious, including malformed bearer artifacts.
      return [
        full,
        ...components,
        `${descriptor.namespaceType}${descriptor.version}\\.`,
      ];
    });
    const detector = new RegExp(sources.join("|"), "i");
    const redactor = new RegExp(sources.join("|"), "gi");
    const parse = (value: unknown): ParsedBearer | null => {
      if (typeof value !== "string" || value.length > 256) return null;
      const index = parsers.findIndex((parser) => parser.test(value));
      if (index < 0) return null;
      const descriptor = descriptors[index]!;
      const parts = value.split(".").slice(1);
      return Object.freeze({
        identity,
        namespaceType: descriptor.namespaceType,
        version: descriptor.version,
        segments: Object.freeze(
          Object.fromEntries(
            descriptor.segments.map((segment, i) => [segment.name, parts[i]!]),
          ),
        ),
      });
    };
    const detects = (value: string): boolean => detector.test(value);
    const redactString = (value: string): string =>
      value.replace(redactor, REDACTED);
    const redactValue = (value: unknown): unknown => {
      const active = new Set<object>();
      let budget = 10000;
      const copy = (value: unknown, depth: number): unknown => {
        if (--budget < 0 || depth > 32) return REDACTED;
        if (typeof value === "string") return redactString(value);
        if (
          value === null ||
          typeof value === "boolean" ||
          typeof value === "number"
        )
          return value;
        if (
          typeof value !== "object" ||
          types.isProxy(value) ||
          active.has(value)
        )
          return REDACTED;
        try {
          const array = Array.isArray(value);
          if (
            Object.getPrototypeOf(value) !==
            (array ? Array.prototype : Object.prototype)
          )
            return REDACTED;
          const keys = Reflect.ownKeys(value);
          if (keys.length > budget) return REDACTED;
          const output: Record<string, unknown> | unknown[] = array ? [] : {};
          active.add(value);
          for (const key of keys) {
            if (array && key === "length") continue;
            if (typeof key !== "string") return REDACTED;
            const property = Object.getOwnPropertyDescriptor(value, key);
            if (!property || !("value" in property) || !property.enumerable)
              return REDACTED;
            const safeKey = redactString(key);
            Object.defineProperty(output, safeKey, {
              value: copy(property.value, depth + 1),
              enumerable: true,
              configurable: true,
              writable: true,
            });
          }
          active.delete(value);
          return output;
        } catch {
          return REDACTED;
        }
      };
      return copy(value, 0);
    };
    const validateCorrelationHint = (
      value: unknown,
      supplied = true,
    ): Readonly<{ valid: boolean }> =>
      !supplied ||
      (typeof value === "string" &&
        value.length <= 128 &&
        /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value) &&
        !detects(value))
        ? VALID
        : INVALID;
    // Mechanically generated startup witnesses cover bounds, shape variation and projections.
    for (const descriptor of descriptors)
      for (const max of [false, true])
        for (const varied of [false, true]) {
          const parts = descriptor.segments.map((segment) =>
            sample(segment, max, varied),
          );
          const artifact = `${descriptor.namespaceType}${descriptor.version}.${parts.join(".")}`;
          if (
            !parse(artifact) ||
            !detects(artifact) ||
            !detects(`wrapper:${artifact.toUpperCase()}:end`) ||
            detects(redactString(artifact))
          )
            throw new Error("inclusion");
          for (const component of descriptor.reconstructibleComponents) {
            const projection = component
              .map(
                (name) =>
                  parts[
                    descriptor.segments.findIndex(
                      (segment) => segment.name === name,
                    )
                  ],
              )
              .join(".");
            if (
              !detects(`wrapper:${projection}:end`) ||
              detects(redactString(projection))
            )
              throw new Error("component inclusion");
          }
        }
    return Object.freeze({
      identity,
      descriptors,
      parse,
      detects,
      redactString,
      redactValue,
      validateCorrelationHint,
    });
  } catch {
    throw new RuntimeConfigurationError("CAP_BEARER_DESCRIPTOR_INVALID");
  }
}
