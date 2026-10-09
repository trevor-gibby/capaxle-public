import { capabilitySemanticHash, jcs } from "@capaxle/ir";
import type { JsonValue } from "@capaxle/ir";
import type { RuntimeDocument } from "@capaxle/runtime";

export const MCP_TARGET =
  "mcp@2026-07-28/streamable-http/tools-unary-v3" as const;
export const MCP_PROTOCOL_VERSION = "2026-07-28" as const;
export const MCP_LEGACY_PROTOCOL_VERSION = "2025-11-25" as const;
export const MCP_LEGACY_TARGET =
  "mcp@2025-11-25/streamable-http/tools-unary-v3" as const;
export const MCP_SUPPORTED_VERSIONS = [
  MCP_PROTOCOL_VERSION,
  MCP_LEGACY_PROTOCOL_VERSION,
] as const;
export const MCP_TARGETS = [MCP_TARGET, MCP_LEGACY_TARGET] as const;
export const MCP_PROFILE_VERSION = "0.3" as const;
export const MCP_INVOCATION_META = "com.capaxle/invocation" as const;
export const MCP_TOOL_META = "com.capaxle/tool" as const;
export const LEGACY_MCP_INVOCATION_META =
  "io.github.trevor-gibby.capabuild/invocation" as const;
export const GENERATOR_NAME = "@capaxle/adapter-mcp" as const;
export const GENERATOR_VERSION = "0.1.0-alpha.3.mcp-profile.0.3" as const;

const IR_HASH = /^sha256:[0-9a-f]{64}$/;
const CLI_BINARY = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export type JsonObject = { [key: string]: JsonValue };

export const dataObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

export function compareText(left: string, right: string): number {
  const a = Array.from(left);
  const b = Array.from(right);
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const difference = a[index]!.codePointAt(0)! - b[index]!.codePointAt(0)!;
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

export function cloneJson<T extends JsonValue>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** Copy only inert JSON own-data; never execute accessors or inherited hooks. */
export function copyJsonData(
  value: unknown,
  seen = new Set<object>(),
): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "object" || seen.has(value))
    throw new ProjectionError("CAP_INPUT_INVALID", {
      reason: "non_json_input",
    });
  seen.add(value);
  let descriptors: PropertyDescriptorMap;
  try {
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    throw new ProjectionError("CAP_INPUT_INVALID", {
      reason: "non_json_input",
    });
  }
  if (Object.getOwnPropertySymbols(value).length > 0)
    throw new ProjectionError("CAP_INPUT_INVALID", {
      reason: "non_json_input",
    });
  if (Array.isArray(value)) {
    const output: JsonValue[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !("value" in descriptor))
        throw new ProjectionError("CAP_INPUT_INVALID", {
          reason: "non_json_input",
        });
      output.push(copyJsonData(descriptor.value, seen));
    }
    seen.delete(value);
    return output;
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    throw new ProjectionError("CAP_INPUT_INVALID", {
      reason: "non_json_input",
    });
  const output: Record<string, JsonValue> = {};
  for (const key of Object.keys(descriptors).sort(compareText)) {
    const descriptor = descriptors[key]!;
    if (!("value" in descriptor) || !descriptor.enumerable)
      throw new ProjectionError("CAP_INPUT_INVALID", {
        reason: "non_json_input",
      });
    Object.defineProperty(output, key, {
      value: copyJsonData(descriptor.value, seen),
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  seen.delete(value);
  return output;
}

export function canonicalBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(jcs(value));
}

export function verifyDocumentHash(
  document: RuntimeDocument,
  irHash: unknown,
): asserts irHash is `sha256:${string}` {
  if (typeof irHash !== "string" || !IR_HASH.test(irHash))
    throw new ProjectionError("CAP_BUILD_CONTEXT_INVALID", {
      path: "/buildContext/irHash",
      reason: irHash === undefined ? "missing" : "format",
    });
  let computed: string | null = null;
  try {
    computed = capabilitySemanticHash(document);
  } catch {
    // A non-canonical or invalid document cannot establish build authority.
  }
  if (computed !== irHash)
    throw new ProjectionError("CAP_BUILD_CONTEXT_INVALID", {
      path: "/buildContext/irHash",
      reason: "mismatch",
    });
}

export function verifyCliBinary(value: unknown): asserts value is string {
  if (typeof value !== "string" || !CLI_BINARY.test(value))
    throw new ProjectionError("CAP_BUILD_CONTEXT_INVALID", {
      path: "/buildContext/cliBinary",
      reason: value === undefined ? "missing" : "format",
    });
}

export class ProjectionError extends Error {
  readonly code: `CAP_${string}`;
  readonly details: JsonValue;

  constructor(code: `CAP_${string}`, details: JsonValue = {}) {
    super(code);
    this.name = "ProjectionError";
    this.code = code;
    this.details = details;
  }
}

export function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export interface DiscoveryContext {
  readonly http: {
    readonly collection: string;
    readonly detailTemplate: string;
    readonly schemaTemplate: string;
  };
  readonly mcp: { readonly endpoint: string };
}

export const DEFAULT_DISCOVERY_CONTEXT: DiscoveryContext = deepFreeze({
  http: {
    collection: "/.well-known/capabilities",
    detailTemplate: "/.well-known/capabilities/{id}",
    schemaTemplate: "/.well-known/capabilities/{id}/schema",
  },
  mcp: { endpoint: "/mcp" },
});

function validPath(value: string, template: boolean): boolean {
  if (
    !value.startsWith("/") ||
    value.startsWith("//") ||
    /[\u0000-\u0020\u007f-\u009f]/.test(value) ||
    /[?#\\\0]/.test(value) ||
    value
      .split("/")
      .slice(1)
      .some((part) => part === "" || part === "." || part === "..") ||
    /%(?![0-9A-F]{2})/.test(value) ||
    /%(?:2D|2E|30|31|32|33|34|35|36|37|38|39|41|42|43|44|45|46|47|48|49|4A|4B|4C|4D|4E|4F|50|51|52|53|54|55|56|57|58|59|5A|5F|61|62|63|64|65|66|67|68|69|6A|6B|6C|6D|6E|6F|70|71|72|73|74|75|76|77|78|79|7A|7E)/.test(
      value,
    )
  )
    return false;
  const tokens = value.split("/").filter((part) => part === "{id}").length;
  const remaining = value.replaceAll("{id}", "");
  return template
    ? tokens === 1 && !/[{}]/.test(remaining)
    : tokens === 0 && !/[{}]/.test(value);
}

function pathsOverlap(left: string, right: string): boolean {
  const a = left.split("/");
  const b = right.split("/");
  return (
    a.length === b.length &&
    a.every(
      (segment, index) =>
        segment === b[index] || segment === "{id}" || b[index] === "{id}",
    )
  );
}

export function validateDiscoveryContext(value: unknown): DiscoveryContext {
  if (
    !dataObject(value) ||
    Object.keys(value).some((key) => key !== "http" && key !== "mcp")
  )
    throw new ProjectionError("CAP_DISCOVERY_CONTEXT_MISMATCH");
  const http = value.http;
  const mcp = value.mcp;
  if (!dataObject(http) || !dataObject(mcp))
    throw new ProjectionError("CAP_DISCOVERY_CONTEXT_MISMATCH");
  if (
    Object.keys(http).sort().join("\0") !==
      ["collection", "detailTemplate", "schemaTemplate"].sort().join("\0") ||
    Object.keys(mcp).join("\0") !== "endpoint"
  )
    throw new ProjectionError("CAP_DISCOVERY_CONTEXT_MISMATCH");
  const { collection, detailTemplate, schemaTemplate } = http;
  const { endpoint } = mcp;
  if (
    typeof collection !== "string" ||
    typeof detailTemplate !== "string" ||
    typeof schemaTemplate !== "string" ||
    typeof endpoint !== "string" ||
    !validPath(collection, false) ||
    !validPath(detailTemplate, true) ||
    !validPath(schemaTemplate, true) ||
    !validPath(endpoint, false) ||
    pathsOverlap(collection, detailTemplate) ||
    pathsOverlap(collection, schemaTemplate) ||
    pathsOverlap(detailTemplate, schemaTemplate)
  )
    throw new ProjectionError("CAP_DISCOVERY_CONTEXT_MISMATCH");
  return deepFreeze({
    http: { collection, detailTemplate, schemaTemplate },
    mcp: { endpoint },
  });
}

export function equalDiscoveryContext(
  left: DiscoveryContext,
  right: DiscoveryContext,
): boolean {
  return (
    left.http.collection === right.http.collection &&
    left.http.detailTemplate === right.http.detailTemplate &&
    left.http.schemaTemplate === right.http.schemaTemplate &&
    left.mcp.endpoint === right.mcp.endpoint
  );
}

export function resolvedDiscoveryContext(
  resolved: unknown,
  assertion?: unknown,
): DiscoveryContext {
  const context = validateDiscoveryContext(resolved);
  if (
    assertion !== undefined &&
    !equalDiscoveryContext(context, validateDiscoveryContext(assertion))
  )
    throw new ProjectionError("CAP_DISCOVERY_CONTEXT_MISMATCH");
  return context;
}
