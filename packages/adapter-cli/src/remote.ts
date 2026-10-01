import { Buffer } from "node:buffer";
import { createHash, randomUUID } from "node:crypto";
import { TextDecoder } from "node:util";
import type { IncomingMessage, ServerResponse } from "node:http";
import type {
  AdapterIngress,
  AdapterInvocationCandidate,
  AdapterDisclosureResult,
  InvocationResult,
  RuntimeDocument,
} from "@capaxle/runtime";
import { capabilitySemanticHash, jcs } from "@capaxle/ir";
import type { JsonSchema, JsonValue } from "@capaxle/ir";
import { OPENCLI_TARGET } from "./opencli.js";
import { projectStandaloneSchema } from "./export-schema.js";

export const REMOTE_CLI_PROTOCOL = "0.1" as const;
export const DEFAULT_REMOTE_CLI_ENDPOINTS = Object.freeze({
  collection: "/cli",
  detailTemplate: "/cli/capabilities/{id}",
  schemaTemplate: "/cli/capabilities/{id}/schema",
  invoke: "/cli/invoke",
});
export const DEFAULT_REMOTE_CLI_PAYLOAD_LIMITS = Object.freeze({
  requestBytes: 1048576,
  responseBytes: 8388608,
});

type Capability = RuntimeDocument["capabilities"][number];
type JsonObject = Record<string, JsonValue>;
type ErrorStatus = InvocationResult extends infer T
  ? T extends { ok: false; error: { status: infer S } }
    ? S
    : never
  : never;

export interface RemoteCliEndpoints {
  readonly collection: string;
  readonly detailTemplate: string;
  readonly schemaTemplate: string;
  readonly invoke: string;
}
export interface RemoteCliPayloadLimits {
  readonly requestBytes: number;
  readonly responseBytes: number;
}
export interface RemoteCliDisclosureSelection {
  /** Process-local restriction; IDs outside the canonical CLI projection are ignored. */
  readonly ids?: readonly string[];
  readonly visibilityKey: string;
  readonly ttlMs?: number;
}
export interface RemoteCliOptions {
  readonly document: RuntimeDocument;
  readonly irHash: string;
  readonly serviceId: string;
  /** Application-owned mount. Endpoint values are canonical paths before this mount. */
  readonly basePath?: string;
  readonly endpoints?: RemoteCliEndpoints;
  readonly externalUrl?: string;
  /** Explicitly trusted local development deployment only. */
  readonly allowLoopbackHttp?: boolean;
  readonly payloadLimits?: RemoteCliPayloadLimits;
  readonly ingress: AdapterIngress;
  /** Required to disclose private entries from a separately configured private boundary. */
  readonly allowPrivateDiscovery?: boolean;
  readonly disclosureSelector?: (
    disclosure: AdapterDisclosureResult,
  ) => RemoteCliDisclosureSelection | Promise<RemoteCliDisclosureSelection>;
}
export interface RemoteCliRequest {
  readonly method: string;
  readonly path: string;
  readonly headers?: Readonly<
    Record<string, string | readonly string[] | undefined>
  >;
  /** Raw UTF-8 JSON, bounded before parsing. */
  readonly body?: string | Uint8Array;
  readonly credentials?: unknown;
  readonly signal?: AbortSignal;
}
export interface RemoteCliResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: JsonValue;
}
export interface RemoteCliAdapter {
  readonly endpoints: RemoteCliEndpoints;
  readonly contractHash: string;
  readonly irHash: string;
  readonly payloadLimits: RemoteCliPayloadLimits;
  matches(request: Pick<RemoteCliRequest, "method" | "path">): boolean;
  handle(request: RemoteCliRequest): Promise<RemoteCliResponse>;
  handleNode(
    request: IncomingMessage,
    response: ServerResponse,
    credentials?: unknown,
  ): Promise<boolean>;
}

export interface RemoteCliRegistrationOptions {
  readonly providerId?: string;
  readonly endpoints?: RemoteCliEndpoints;
  /** Optional process-local limits may only tighten the pinned deployment limits. */
  readonly payloadLimits?: Partial<RemoteCliPayloadLimits>;
  readonly disclosureSelector?: RemoteCliOptions["disclosureSelector"];
  readonly allowPrivateDiscovery?: boolean;
}
export interface RemoteCliPrepareContext {
  readonly generation: Readonly<{ document: RuntimeDocument; irHash: string }>;
  readonly deploymentContext: Readonly<{
    serviceId: string;
    basePath: string;
    externalUrl?: string;
    transport?: {
      cli?: {
        requestBytes: number;
        responseBytes: number;
        allowPrivateDiscovery: boolean;
      };
    };
  }>;
  readonly ingress: AdapterIngress;
}
export interface RemoteCliRegistration {
  readonly kind: "cli";
  readonly reservations: readonly Readonly<{ method: string; path: string }>[];
  readonly requiredProviderIds: readonly string[];
  prepare(context: RemoteCliPrepareContext): Promise<{
    handle(req: IncomingMessage, res: ServerResponse): Promise<boolean>;
    activate(): Promise<void>;
    drain(context: {
      readonly deadline: Date;
      readonly signal: AbortSignal;
    }): Promise<void>;
    close(): Promise<void>;
  }>;
}

const HASH = /^sha256:[0-9a-f]{64}$/u;
const SERVICE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/u;
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const STATUS_HTTP: Record<ErrorStatus, number> = {
  invalid_argument: 400,
  unauthenticated: 401,
  permission_denied: 403,
  not_found: 404,
  already_exists: 409,
  failed_precondition: 412,
  conflict: 409,
  resource_exhausted: 429,
  cancelled: 499,
  deadline_exceeded: 504,
  unavailable: 503,
  internal: 500,
};
const ERROR_MESSAGE: Record<string, string> = {
  CAP_INPUT_INVALID: "Invalid remote CLI request.",
  CAP_NOT_FOUND: "Capability not found.",
  CAP_UNAUTHENTICATED: "Authentication failed.",
  CAP_CLI_PROTOCOL_UNSUPPORTED: "Unsupported remote CLI protocol.",
  CAP_CLI_SERVICE_MISMATCH: "Remote CLI service identity changed.",
  CAP_CLI_IR_MISMATCH: "Capability IR identity changed.",
  CAP_CLI_CONTRACT_MISMATCH: "Remote CLI transport contract changed.",
  CAP_CLI_PAYLOAD_TOO_LARGE: "Remote CLI request exceeds the configured limit.",
  CAP_CLI_RESPONSE_TOO_LARGE:
    "Remote CLI response exceeds the configured limit.",
  CAP_OPENCLI_SCHEMA_UNREPRESENTABLE: "Capability schema cannot be projected.",
};

const object = (value: unknown): Record<string, unknown> | null =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
const own = (value: Record<string, unknown>, keys: readonly string[]) =>
  Object.keys(value).every((key) => keys.includes(key));
const clone = <T extends JsonValue>(value: T): T => JSON.parse(jcs(value)) as T;
const hash = (value: JsonValue) =>
  `sha256:${createHash("sha256").update(jcs(value), "utf8").digest("hex")}`;
const compare = (left: string, right: string) =>
  left < right ? -1 : left > right ? 1 : 0;

function validPath(path: string, template: boolean): boolean {
  if (
    !path.startsWith("/") ||
    path.startsWith("//") ||
    /[\u0000-\u0020\u007f-\u009f?#\\]/u.test(path) ||
    path
      .split("/")
      .slice(1)
      .some((part) => part === "" || part === "." || part === "..") ||
    /%(?![0-9A-F]{2})/u.test(path)
  )
    return false;
  const segments = path.split("/").slice(1);
  for (const part of segments) {
    if (part === "{id}") continue;
    let decoded: string;
    try {
      decoded = decodeURIComponent(part);
    } catch {
      return false;
    }
    if (
      decoded === "." ||
      decoded === ".." ||
      decoded.includes("/") ||
      decoded.includes("\\") ||
      /[\u0000-\u001f\u007f-\u009f]/u.test(decoded)
    )
      return false;
    for (const match of part.matchAll(/%([0-9A-F]{2})/gu)) {
      const char = String.fromCharCode(parseInt(match[1]!, 16));
      if (/[A-Za-z0-9._~-]/u.test(char)) return false;
    }
  }
  return template
    ? segments.filter((part) => part === "{id}").length === 1 &&
        segments.every((part) => part === "{id}" || !/[{}]/u.test(part))
    : !/[{}]/u.test(path);
}

function mounted(basePath: string, endpoint: string): string {
  return basePath === "/" ? endpoint : `${basePath}${endpoint}`;
}

function resolveEndpoints(
  base: string,
  source: RemoteCliEndpoints,
): RemoteCliEndpoints {
  if (!validPath(base, false) && base !== "/")
    throw new Error("CAP_CLI_ROUTE_INVALID");
  const keys = [
    "collection",
    "detailTemplate",
    "schemaTemplate",
    "invoke",
  ] as const;
  if (
    !own(source as unknown as Record<string, unknown>, keys) ||
    keys.some(
      (key) =>
        typeof source[key] !== "string" ||
        !validPath(source[key], key.endsWith("Template")),
    )
  )
    throw new Error("CAP_CLI_ROUTE_INVALID");
  const paths = keys.map((key) => source[key]);
  const overlaps = (left: string, right: string) => {
    const a = left.split("/");
    const b = right.split("/");
    return (
      a.length === b.length &&
      a.every(
        (part, index) =>
          part === b[index] || part === "{id}" || b[index] === "{id}",
      )
    );
  };
  if (
    new Set(paths).size !== paths.length ||
    paths.some((path, i) =>
      paths.some((other, j) => i < j && overlaps(path, other)),
    )
  )
    throw new Error("CAP_CLI_ROUTE_INVALID");
  return Object.freeze(
    Object.fromEntries(
      keys.map((key) => [key, mounted(base, source[key])]),
    ) as unknown as RemoteCliEndpoints,
  );
}

function validateExternalUrl(
  value: string | undefined,
  basePath: string,
  loopbackDevelopment: boolean,
): void {
  if (value === undefined) return;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("CAP_CLI_EXTERNAL_URL_INVALID");
  }
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";
  if (
    (url.protocol !== "https:" &&
      !(loopbackDevelopment && loopback && url.protocol === "http:")) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== basePath ||
    (!validPath(url.pathname, false) && basePath !== "/")
  )
    throw new Error("CAP_CLI_EXTERNAL_URL_INVALID");
}

function schemaValue(
  binding: Capability["input"] | Capability["output"],
  document: RuntimeDocument,
): JsonSchema | null {
  if ("schema" in binding) return binding.schema;
  const ref = binding.$ref;
  if (!ref.startsWith("#/schemas/") || ref.slice(10).includes("/")) return null;
  const name = ref.slice(10).replaceAll("~1", "/").replaceAll("~0", "~");
  return document.schemas[name] ?? null;
}

function projectedSchemas(capability: Capability, document: RuntimeDocument) {
  const prefix = `remote\u0000${capability.id}\u0000${capability.version}\u0000`;
  const input = schemaValue(capability.input, document);
  const output = schemaValue(capability.output, document);
  if (!input || !output) return null;
  const inputSchema = projectStandaloneSchema(
    input,
    document.schemas,
    `${prefix}input`,
    { requireObject: true },
  );
  const outputSchema = projectStandaloneSchema(
    output,
    document.schemas,
    `${prefix}output`,
  );
  if (!inputSchema || !outputSchema) return null;
  const errors: JsonObject = {};
  for (const code of Object.keys(capability.errors).sort(compare)) {
    const error = capability.errors[code]!;
    const projected: JsonObject = {
      status: error.status,
      message: error.message,
      retryable: error.retryable,
    };
    const docs = (error as unknown as Record<string, unknown>).docs;
    if (typeof docs === "string") projected.docs = docs;
    if (error.details) {
      const details = schemaValue(error.details, document);
      const standalone =
        details &&
        projectStandaloneSchema(
          details,
          document.schemas,
          `${prefix}error:${code}`,
        );
      if (!standalone) return null;
      projected.details = standalone;
    }
    Object.defineProperty(errors, code, { value: projected, enumerable: true });
  }
  return { input: inputSchema, output: outputSchema, errors };
}

function capabilityProjection(capability: Capability) {
  return capability.interfaces.cli as unknown as {
    readonly enabled: boolean;
    readonly command: readonly string[];
    readonly bindings: Readonly<Record<string, JsonValue>>;
  };
}

function wireError(
  code: string,
  status: ErrorStatus,
  details?: JsonValue,
): InvocationResult {
  return {
    ok: false,
    error: {
      code,
      status,
      message: ERROR_MESSAGE[code] ?? "Remote CLI request failed.",
      retryable: false,
      correlationId: randomUUID(),
      ...(details === undefined ? {} : { details }),
    },
  };
}

function response(
  status: number,
  body: JsonValue,
  headers: Record<string, string> = {},
): RemoteCliResponse {
  return {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "capaxle-cli-protocol": REMOTE_CLI_PROTOCOL,
      "cache-control": "no-store",
      ...headers,
    },
    body,
  };
}

function parsePath(
  raw: string,
): { pathname: string; query: URLSearchParams } | null {
  const question = raw.indexOf("?");
  const pathname = question < 0 ? raw : raw.slice(0, question);
  const queryString = question < 0 ? "" : raw.slice(question + 1);
  if (!pathname.startsWith("/") || pathname.includes("#")) return null;
  return { pathname, query: new URLSearchParams(queryString) };
}

function reservedTemplate(template: string, pathname: string): boolean {
  const [before, after] = template.split("{id}");
  if (
    before === undefined ||
    after === undefined ||
    !pathname.startsWith(before) ||
    !pathname.endsWith(after)
  )
    return false;
  const segment = pathname.slice(before.length, pathname.length - after.length);
  return segment.length > 0 && !segment.includes("/");
}

function idAt(template: string, pathname: string): string | null {
  if (!reservedTemplate(template, pathname)) return null;
  const [before, after] = template.split("{id}");
  if (before === undefined || after === undefined) return null;
  const encoded = pathname.slice(before.length, pathname.length - after.length);
  try {
    const decoded = decodeURIComponent(encoded);
    if (
      decoded === "." ||
      decoded === ".." ||
      decoded.includes("/") ||
      decoded.includes("\\") ||
      encodeURIComponent(decoded) !== encoded
    )
      return null;
    return decoded;
  } catch {
    return null;
  }
}

function headersFor(request: RemoteCliRequest, name: string): string | null {
  const entries = Object.entries(request.headers ?? {}).filter(
    ([key]) => key.toLowerCase() === name,
  );
  if (entries.length !== 1) return null;
  const value = entries[0]![1];
  return typeof value === "string" ? value : null;
}

function selectionFor(
  disclosure: AdapterDisclosureResult,
  selected: RemoteCliDisclosureSelection | undefined,
) {
  const visibilityKey =
    selected?.visibilityKey ??
    (disclosure.visibility === "public" ? "public" : randomUUID());
  if (!/^[\x21-\x7e]{1,128}$/u.test(visibilityKey))
    throw new Error("CAP_CLI_DISCLOSURE_INVALID");
  const ttlMs = selected?.ttlMs ?? 0;
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 0 || ttlMs > 30000)
    throw new Error("CAP_CLI_DISCLOSURE_INVALID");
  if (
    selected?.ids !== undefined &&
    (!Array.isArray(selected.ids) ||
      !selected.ids.every((id) => typeof id === "string"))
  )
    throw new Error("CAP_CLI_DISCLOSURE_INVALID");
  return {
    ids: selected?.ids ? new Set(selected.ids) : undefined,
    cache: {
      scope: disclosure.visibility === "public" ? "public" : "private",
      ttlMs,
      visibilityKey,
    } as const,
  };
}

function versionParts(value: string): {
  major: bigint;
  minor: bigint;
  patch: bigint;
  prerelease: string[];
} | null {
  const match = SEMVER.exec(value);
  if (!match) return null;
  const prerelease = match[4]?.split(".") ?? [];
  if (
    prerelease.some(
      (part) => /^\d+$/u.test(part) && part.length > 1 && part.startsWith("0"),
    )
  )
    return null;
  return {
    major: BigInt(match[1]!),
    minor: BigInt(match[2]!),
    patch: BigInt(match[3]!),
    prerelease,
  };
}

function compareVersions(left: string, right: string): number {
  const a = versionParts(left)!;
  const b = versionParts(right)!;
  for (const key of ["major", "minor", "patch"] as const) {
    if (a[key] !== b[key]) return a[key] < b[key] ? -1 : 1;
  }
  if (!a.prerelease.length && b.prerelease.length) return 1;
  if (a.prerelease.length && !b.prerelease.length) return -1;
  for (let i = 0; i < Math.max(a.prerelease.length, b.prerelease.length); i++) {
    const x = a.prerelease[i];
    const y = b.prerelease[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const numericX = /^(0|[1-9]\d*)$/u.test(x);
    const numericY = /^(0|[1-9]\d*)$/u.test(y);
    if (numericX && numericY) return BigInt(x) < BigInt(y) ? -1 : 1;
    if (numericX) return -1;
    if (numericY) return 1;
    return compare(x, y);
  }
  return 0;
}

function chooseVersion(
  candidates: readonly Capability[],
  requested: string | undefined,
): Capability | undefined {
  if (requested === undefined)
    return [...candidates].sort((a, b) =>
      compareVersions(b.version, a.version),
    )[0];
  if (/^(0|[1-9]\d*)$/u.test(requested))
    return [...candidates]
      .filter((capability) => capability.version.startsWith(`${requested}.`))
      .sort((a, b) => compareVersions(b.version, a.version))[0];
  return candidates.find((capability) => capability.version === requested);
}

function discoveryVisible(
  capability: Capability,
  disclosure: AdapterDisclosureResult,
  allowPrivate: boolean,
): boolean {
  if (!capabilityProjection(capability).enabled) return false;
  const exposure = capability.access.exposure.cli;
  if (exposure === "disabled") return false;
  if (exposure === "private")
    return allowPrivate && disclosure.visibility === "private";
  if (exposure === "authenticated" && disclosure.visibility === "public")
    return false;
  if (capability.access.authentication === "required" && !disclosure.principal)
    return false;
  return true;
}

function fixedErrorFromThrown(cause: unknown): InvocationResult {
  const code = object(cause)?.code;
  if (code === "CAP_UNAUTHENTICATED")
    return wireError("CAP_UNAUTHENTICATED", "unauthenticated");
  if (code === "CAP_CANCELLED") return wireError("CAP_CANCELLED", "cancelled");
  if (code === "CAP_DEADLINE_EXCEEDED")
    return wireError("CAP_DEADLINE_EXCEEDED", "deadline_exceeded");
  return wireError("CAP_DEPENDENCY_UNAVAILABLE", "unavailable");
}

function decodeBody(
  body: string | Uint8Array | undefined,
  limit: number,
): Record<string, unknown> | "large" | null {
  if (body === undefined) return null;
  const bytes =
    typeof body === "string" ? Buffer.from(body, "utf8") : Buffer.from(body);
  if (bytes.byteLength > limit) return "large";
  try {
    return object(JSON.parse(UTF8.decode(bytes)));
  } catch {
    return null;
  }
}

function closedInvocation(value: Record<string, unknown>): {
  capability: string;
  version?: string;
  input: Record<string, unknown>;
  controls?: {
    confirmationToken?: string;
    idempotencyKey?: string;
    correlationId?: string;
    timeoutMs?: number;
  };
  protocolVersion: unknown;
  serviceId: unknown;
  irHash: unknown;
  contractHash: unknown;
} | null {
  if (
    !own(value, [
      "protocolVersion",
      "serviceId",
      "irHash",
      "contractHash",
      "capability",
      "version",
      "input",
      "controls",
    ]) ||
    ![
      "protocolVersion",
      "serviceId",
      "irHash",
      "contractHash",
      "capability",
      "input",
    ].every((key) => Object.hasOwn(value, key)) ||
    typeof value.protocolVersion !== "string" ||
    typeof value.serviceId !== "string" ||
    typeof value.irHash !== "string" ||
    typeof value.contractHash !== "string" ||
    typeof value.capability !== "string" ||
    !object(value.input) ||
    (value.version !== undefined && typeof value.version !== "string")
  )
    return null;
  const controls =
    value.controls === undefined ? undefined : object(value.controls);
  if (value.controls !== undefined && !controls) return null;
  if (
    controls &&
    (!own(controls, [
      "confirmationToken",
      "idempotencyKey",
      "correlationId",
      "timeoutMs",
    ]) ||
      ["confirmationToken", "idempotencyKey", "correlationId"].some(
        (key) =>
          controls[key] !== undefined && typeof controls[key] !== "string",
      ) ||
      (controls.timeoutMs !== undefined &&
        (!Number.isInteger(controls.timeoutMs) ||
          (controls.timeoutMs as number) <= 0 ||
          (controls.timeoutMs as number) > 300000)))
  )
    return null;
  return value as ReturnType<typeof closedInvocation> & Record<string, unknown>;
}

function candidate(
  code: string,
  status: ErrorStatus,
  safeDetails?: JsonValue,
): AdapterInvocationCandidate {
  return {
    ok: false,
    code,
    status,
    ...(safeDetails === undefined ? {} : { safeDetails }),
  } as AdapterInvocationCandidate;
}

export function createRemoteCliAdapter(
  options: RemoteCliOptions,
): RemoteCliAdapter {
  if (
    !HASH.test(options.irHash) ||
    capabilitySemanticHash(options.document) !== options.irHash
  )
    throw new Error("CAP_CLI_IR_HASH_MISMATCH");
  if (!SERVICE_ID.test(options.serviceId))
    throw new Error("CAP_CLI_SERVICE_INVALID");
  if (
    [...options.document.service.name].length < 1 ||
    [...options.document.service.name].length > 128 ||
    Buffer.byteLength(options.document.service.version, "utf8") > 256 ||
    !versionParts(options.document.service.version)
  )
    throw new Error("CAP_CLI_SERVICE_INVALID");
  const endpoints = resolveEndpoints(
    options.basePath ?? "/",
    options.endpoints ?? DEFAULT_REMOTE_CLI_ENDPOINTS,
  );
  validateExternalUrl(
    options.externalUrl,
    options.basePath ?? "/",
    options.allowLoopbackHttp === true,
  );
  const payloadLimits =
    options.payloadLimits ?? DEFAULT_REMOTE_CLI_PAYLOAD_LIMITS;
  if (
    !Number.isInteger(payloadLimits.requestBytes) ||
    payloadLimits.requestBytes < 1024 ||
    payloadLimits.requestBytes > 1048576 ||
    !Number.isInteger(payloadLimits.responseBytes) ||
    payloadLimits.responseBytes < 8192 ||
    payloadLimits.responseBytes > 8388608
  )
    throw new Error("CAP_CLI_PAYLOAD_LIMIT_INVALID");
  const identity = Object.freeze({
    protocolVersion: REMOTE_CLI_PROTOCOL,
    service: {
      id: options.serviceId,
      name: options.document.service.name,
      version: options.document.service.version,
    },
    irHash: options.irHash,
  });
  const contractHash = hash({
    protocolVersion: REMOTE_CLI_PROTOCOL,
    serviceId: options.serviceId,
    irVersion: "0.1",
    cliTarget: OPENCLI_TARGET,
    basePath: options.basePath ?? "/",
    resolvedCliEndpoints: endpoints as unknown as JsonValue,
    payloadLimits: payloadLimits as unknown as JsonValue,
  });
  const fullIdentity = { ...identity, contractHash };
  const all = options.document.capabilities.filter(
    (capability) => capabilityProjection(capability).enabled,
  );
  const schemaCache = new Map<
    Capability,
    ReturnType<typeof projectedSchemas>
  >();
  for (const capability of all) {
    if (!versionParts(capability.version))
      throw new Error("CAP_CLI_VERSION_INVALID");
    const projected = projectedSchemas(capability, options.document);
    if (!projected) throw new Error("CAP_OPENCLI_SCHEMA_UNREPRESENTABLE");
    schemaCache.set(capability, projected);
  }
  const encodedId = (template: string, id: string) =>
    template.replace("{id}", encodeURIComponent(id));
  const summary = (capability: Capability) => ({
    id: capability.id,
    version: capability.version,
    summary: capability.summary,
    command: clone(
      capabilityProjection(capability).command as unknown as JsonValue,
    ),
    detailUrl: encodedId(endpoints.detailTemplate, capability.id),
    schemaUrl: encodedId(endpoints.schemaTemplate, capability.id),
  });
  const visible = (
    disclosure: AdapterDisclosureResult,
    ids: Set<string> | undefined,
  ) =>
    all.filter(
      (capability) =>
        discoveryVisible(
          capability,
          disclosure,
          options.allowPrivateDiscovery === true &&
            options.disclosureSelector !== undefined &&
            disclosure.principal !== undefined,
        ) &&
        (ids === undefined || ids.has(capability.id)),
    );
  const details = (capability: Capability) => ({
    id: capability.id,
    version: capability.version,
    summary: capability.summary,
    ...((capability as unknown as Record<string, unknown>).description ===
    undefined
      ? {}
      : {
          description: (capability as unknown as Record<string, unknown>)
            .description,
        }),
    command: clone(
      capabilityProjection(capability).command as unknown as JsonValue,
    ),
    bindings: clone(
      capabilityProjection(capability).bindings as unknown as JsonValue,
    ),
    ...schemaCache.get(capability)!,
    examples: clone(
      ((capability as unknown as Record<string, unknown>).examples ??
        []) as JsonValue,
    ),
    access: {
      authentication: capability.access.authentication,
      permissions: clone(capability.access.permissions as unknown as JsonValue),
      exposure: capability.access.exposure.cli,
    },
    effects: clone(capability.effects as unknown as JsonValue),
    execution: clone(capability.execution as unknown as JsonValue),
    controls: {
      confirmation:
        capability.effects.confirmation === "required"
          ? "opaque-evidence"
          : "none",
      idempotency: capability.effects.idempotency,
      correlation: "untrusted-hint",
      maxTimeoutMs: Math.min(300000, capability.execution.timeoutMs ?? 300000),
    },
  });

  function bounded(
    status: number,
    body: JsonValue,
    headers?: Record<string, string>,
  ): RemoteCliResponse {
    const result = response(status, body, headers);
    if (Buffer.byteLength(jcs(body), "utf8") <= payloadLimits.responseBytes)
      return result;
    const fallback = {
      ...fullIdentity,
      ...wireError("CAP_CLI_RESPONSE_TOO_LARGE", "internal", {
        executionMayHaveOccurred: true,
      }),
    } as JsonValue;
    if (Buffer.byteLength(jcs(fallback), "utf8") > payloadLimits.responseBytes)
      throw new Error("CAP_CLI_PAYLOAD_LIMIT_INVALID");
    return response(500, fallback);
  }
  const failed = (
    result: InvocationResult,
    withIdentity = true,
    statusOverride?: number,
  ) =>
    bounded(
      statusOverride ?? (result.ok ? 200 : STATUS_HTTP[result.error.status]),
      { ...(withIdentity ? fullIdentity : {}), ...result } as JsonValue,
    );
  // The minimum advertised limit must fit the largest fixed diagnostic.
  if (
    Buffer.byteLength(
      jcs({
        ...fullIdentity,
        ok: false,
        error: {
          code: "CAP_CLI_RESPONSE_TOO_LARGE",
          status: "internal",
          message: ERROR_MESSAGE.CAP_CLI_RESPONSE_TOO_LARGE!,
          retryable: false,
          correlationId: "x".repeat(128),
          details: { executionMayHaveOccurred: true },
        },
      }),
      "utf8",
    ) > payloadLimits.responseBytes
  )
    throw new Error("CAP_CLI_PAYLOAD_LIMIT_INVALID");
  const publicCapabilities = all.filter(
    (capability) =>
      capability.access.exposure.cli === "public" &&
      capability.access.authentication !== "required",
  );
  const publicCache = { scope: "public", ttlMs: 0, visibilityKey: "public" };
  const publicCollection = {
    ...fullIdentity,
    kind: "collection",
    irVersion: "0.1",
    cliTarget: OPENCLI_TARGET,
    endpoints,
    ...(options.externalUrl ? { externalUrl: options.externalUrl } : {}),
    payloadLimits,
    cache: publicCache,
    capabilities: publicCapabilities.map(summary),
  } as unknown as JsonValue;
  if (
    Buffer.byteLength(jcs(publicCollection), "utf8") >
    payloadLimits.responseBytes
  )
    throw new Error("CAP_CLI_DISCOVERY_TOO_LARGE");
  for (const capability of publicCapabilities) {
    const publicDetail = {
      ...fullIdentity,
      kind: "detail",
      capability: details(capability),
      cache: publicCache,
    } as JsonValue;
    const publicSchema = {
      ...fullIdentity,
      kind: "schema",
      capability: { id: capability.id, version: capability.version },
      schemas: schemaCache.get(capability)!,
      cache: publicCache,
    } as JsonValue;
    if (
      Buffer.byteLength(jcs(publicDetail), "utf8") >
        payloadLimits.responseBytes ||
      Buffer.byteLength(jcs(publicSchema), "utf8") > payloadLimits.responseBytes
    )
      throw new Error("CAP_CLI_DISCOVERY_TOO_LARGE");
  }

  const matches = (request: Pick<RemoteCliRequest, "method" | "path">) => {
    const parsed = parsePath(request.path);
    if (!parsed) return false;
    return (
      parsed.pathname === endpoints.collection ||
      parsed.pathname === endpoints.invoke ||
      reservedTemplate(endpoints.detailTemplate, parsed.pathname) ||
      reservedTemplate(endpoints.schemaTemplate, parsed.pathname)
    );
  };

  async function handleCore(
    request: RemoteCliRequest,
  ): Promise<RemoteCliResponse> {
    const parsed = parsePath(request.path);
    if (!parsed || !matches(request))
      return failed(wireError("CAP_NOT_FOUND", "not_found"), false);
    const route =
      parsed.pathname === endpoints.collection
        ? "collection"
        : parsed.pathname === endpoints.invoke
          ? "invoke"
          : reservedTemplate(endpoints.schemaTemplate, parsed.pathname)
            ? "schema"
            : "detail";
    const allow = route === "invoke" ? "POST" : "GET";
    if (request.method !== allow)
      return bounded(
        405,
        { ...wireError("CAP_NOT_FOUND", "not_found") } as JsonValue,
        { allow },
      );
    const header = headersFor(request, "capaxle-cli-protocol");
    if (header !== REMOTE_CLI_PROTOCOL && route !== "invoke")
      return failed(
        wireError("CAP_CLI_PROTOCOL_UNSUPPORTED", "failed_precondition", {
          supportedProfiles: [REMOTE_CLI_PROTOCOL],
        }),
        false,
      );
    const queryKeys = [...parsed.query.keys()];
    if (
      route === "collection" || route === "invoke"
        ? queryKeys.length > 0
        : queryKeys.some((key) => key !== "version") || queryKeys.length > 1
    )
      return failed(wireError("CAP_NOT_FOUND", "not_found"), false);
    let disclosure: AdapterDisclosureResult;
    try {
      disclosure = await options.ingress.disclose({
        ...(request.credentials === undefined
          ? {}
          : { credentials: request.credentials }),
        ...(request.signal === undefined ? {} : { signal: request.signal }),
      });
    } catch (cause) {
      return failed(fixedErrorFromThrown(cause), false);
    }
    let selection: ReturnType<typeof selectionFor>;
    try {
      selection = selectionFor(
        disclosure,
        await options.disclosureSelector?.(disclosure),
      );
    } catch {
      return failed(
        wireError("CAP_DEPENDENCY_UNAVAILABLE", "unavailable"),
        false,
      );
    }
    const selected = visible(disclosure, selection.ids);
    const knownParseRejection = async (
      raw: Record<string, unknown> | null,
      code: "CAP_INPUT_INVALID" | "CAP_CLI_PROTOCOL_UNSUPPORTED",
    ): Promise<RemoteCliResponse> => {
      const named =
        raw && typeof raw.capability === "string"
          ? chooseVersion(
              selected.filter((entry) => entry.id === raw.capability),
              typeof raw.version === "string" ? raw.version : undefined,
            )
          : undefined;
      if (!named)
        return failed(
          wireError(
            code,
            code === "CAP_INPUT_INVALID"
              ? "invalid_argument"
              : "failed_precondition",
            code === "CAP_CLI_PROTOCOL_UNSUPPORTED"
              ? { supportedProfiles: [REMOTE_CLI_PROTOCOL] }
              : undefined,
          ),
          false,
        );
      const rejection = await options.ingress.invoke({
        capability: named.id,
        adapterCandidate: candidate(
          code,
          code === "CAP_INPUT_INVALID"
            ? "invalid_argument"
            : "failed_precondition",
          code === "CAP_CLI_PROTOCOL_UNSUPPORTED"
            ? { supportedProfiles: [REMOTE_CLI_PROTOCOL] }
            : undefined,
        ),
        ...(request.credentials === undefined
          ? {}
          : { credentials: request.credentials }),
        ...(request.signal === undefined ? {} : { signal: request.signal }),
      });
      return failed(rejection);
    };
    if (route === "collection") {
      const capabilities = selected
        .map(summary)
        .sort(
          (a, b) =>
            compare(a.id, b.id) || compareVersions(a.version, b.version),
        );
      return bounded(200, {
        ...fullIdentity,
        kind: "collection",
        irVersion: "0.1",
        cliTarget: OPENCLI_TARGET,
        endpoints,
        ...(options.externalUrl ? { externalUrl: options.externalUrl } : {}),
        payloadLimits,
        cache: selection.cache,
        capabilities,
      } as unknown as JsonValue);
    }
    if (route === "detail" || route === "schema") {
      const id = idAt(
        route === "detail"
          ? endpoints.detailTemplate
          : endpoints.schemaTemplate,
        parsed.pathname,
      );
      if (id === null)
        return failed(wireError("CAP_NOT_FOUND", "not_found"), false);
      const capability = chooseVersion(
        selected.filter((candidate) => candidate.id === id),
        parsed.query.get("version") ?? undefined,
      );
      if (!capability) return failed(wireError("CAP_NOT_FOUND", "not_found"));
      return route === "detail"
        ? bounded(200, {
            ...fullIdentity,
            kind: "detail",
            capability: details(capability),
            cache: selection.cache,
          } as JsonValue)
        : bounded(200, {
            ...fullIdentity,
            kind: "schema",
            capability: { id: capability.id, version: capability.version },
            schemas: schemaCache.get(capability)!,
            cache: selection.cache,
          } as JsonValue);
    }
    if (header !== REMOTE_CLI_PROTOCOL) {
      const raw = decodeBody(request.body, payloadLimits.requestBytes);
      if (raw === "large")
        return failed(
          wireError("CAP_CLI_PAYLOAD_TOO_LARGE", "invalid_argument"),
          false,
          413,
        );
      return knownParseRejection(raw, "CAP_CLI_PROTOCOL_UNSUPPORTED");
    }
    if (
      !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(
        headersFor(request, "content-type") ?? "",
      )
    ) {
      const raw = decodeBody(request.body, payloadLimits.requestBytes);
      if (raw === "large")
        return failed(
          wireError("CAP_CLI_PAYLOAD_TOO_LARGE", "invalid_argument"),
          false,
          413,
        );
      return knownParseRejection(raw, "CAP_INPUT_INVALID");
    }
    const raw = decodeBody(request.body, payloadLimits.requestBytes);
    if (raw === "large")
      return failed(
        wireError("CAP_CLI_PAYLOAD_TOO_LARGE", "invalid_argument"),
        false,
        413,
      );
    const invocation = raw && closedInvocation(raw);
    if (!invocation) return knownParseRejection(raw, "CAP_INPUT_INVALID");
    const capability = chooseVersion(
      selected.filter((entry) => entry.id === invocation.capability),
      invocation.version,
    );
    if (!capability) {
      const result = await options.ingress.invoke({
        capability: "",
        input: {},
        ...(request.credentials === undefined
          ? {}
          : { credentials: request.credentials }),
        ...(request.signal === undefined ? {} : { signal: request.signal }),
      });
      return failed(result);
    }
    const rejection =
      invocation.protocolVersion !== REMOTE_CLI_PROTOCOL
        ? candidate("CAP_CLI_PROTOCOL_UNSUPPORTED", "failed_precondition", {
            supportedProfiles: [REMOTE_CLI_PROTOCOL],
          })
        : invocation.serviceId !== options.serviceId
          ? candidate("CAP_CLI_SERVICE_MISMATCH", "failed_precondition")
          : invocation.irHash !== options.irHash
            ? candidate(
                "CAP_CLI_IR_MISMATCH",
                "failed_precondition",
                HASH.test(invocation.irHash as string)
                  ? {
                      expectedHash: options.irHash,
                      currentHash: invocation.irHash as string,
                    }
                  : undefined,
              )
            : invocation.contractHash !== contractHash
              ? candidate(
                  "CAP_CLI_CONTRACT_MISMATCH",
                  "failed_precondition",
                  HASH.test(invocation.contractHash as string)
                    ? {
                        expectedHash: contractHash,
                        currentHash: invocation.contractHash as string,
                      }
                    : undefined,
                )
              : null;
    const result = await options.ingress.invoke({
      capability: capability.id,
      ...(invocation.version === undefined
        ? {}
        : { version: invocation.version }),
      adapterCandidate: rejection ?? {
        ok: true,
        input: invocation.input,
        ...(invocation.controls === undefined
          ? {}
          : { controls: invocation.controls }),
      },
      ...(request.credentials === undefined
        ? {}
        : { credentials: request.credentials }),
      ...(request.signal === undefined ? {} : { signal: request.signal }),
    });
    return failed(result);
  }

  async function handle(request: RemoteCliRequest): Promise<RemoteCliResponse> {
    const result = await handleCore(request);
    const cache = object(object(result.body)?.cache);
    if (request.credentials === undefined && cache?.scope !== "private")
      return result;
    return {
      ...result,
      headers: { ...result.headers, "cache-control": "private, no-store" },
    };
  }

  async function handleNode(
    request: IncomingMessage,
    res: ServerResponse,
    credentials?: unknown,
  ): Promise<boolean> {
    const method = request.method ?? "";
    const path = request.url ?? "";
    if (!matches({ method, path })) return false;
    const controller = new AbortController();
    const abort = () => controller.abort();
    request.on("aborted", abort);
    res.on("close", abort);
    try {
      let body: Uint8Array | undefined;
      if (method === "POST") {
        const chunks: Buffer[] = [];
        let length = 0;
        for await (const chunk of request) {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          length += bytes.byteLength;
          if (length > payloadLimits.requestBytes) {
            const tooLarge = failed(
              wireError("CAP_CLI_PAYLOAD_TOO_LARGE", "invalid_argument"),
              false,
              413,
            );
            if (!res.writableEnded && !res.destroyed) {
              res.writeHead(
                tooLarge.status,
                credentials === undefined
                  ? tooLarge.headers
                  : {
                      ...tooLarge.headers,
                      "cache-control": "private, no-store",
                    },
              );
              res.end(jcs(tooLarge.body));
            }
            return true;
          }
          chunks.push(bytes);
        }
        body = Buffer.concat(chunks);
      }
      const headers: Record<string, string | readonly string[] | undefined> =
        request.headers;
      const result = await handle({
        method,
        path,
        headers,
        ...(body === undefined ? {} : { body }),
        ...(credentials === undefined ? {} : { credentials }),
        signal: controller.signal,
      });
      if (!res.writableEnded && !res.destroyed) {
        res.writeHead(result.status, result.headers);
        res.end(jcs(result.body));
      }
      return true;
    } finally {
      request.off("aborted", abort);
      res.off("close", abort);
    }
  }
  return Object.freeze({
    endpoints,
    contractHash,
    irHash: options.irHash,
    payloadLimits,
    matches,
    handle,
    handleNode,
  });
}

/** Structural application registration; no application package dependency. */
const remoteRegistrations = new WeakMap<object, RemoteCliEndpoints>();

export function isRemoteCliRegistration(
  value: unknown,
): value is RemoteCliRegistration {
  return (
    typeof value === "object" &&
    value !== null &&
    remoteRegistrations.has(value)
  );
}

export function getRemoteCliRegistrationEndpoints(
  value: unknown,
): RemoteCliEndpoints | undefined {
  return typeof value === "object" && value !== null
    ? remoteRegistrations.get(value)
    : undefined;
}

export function createRemoteCliRegistration(
  options: RemoteCliRegistrationOptions = {},
): RemoteCliRegistration {
  if (options.providerId !== undefined && !SERVICE_ID.test(options.providerId))
    throw new Error("CAP_CLI_PROVIDER_INVALID");
  const local = resolveEndpoints(
    "/",
    options.endpoints ?? DEFAULT_REMOTE_CLI_ENDPOINTS,
  );
  const reservations = Object.freeze([
    Object.freeze({ method: "GET", path: local.collection }),
    Object.freeze({ method: "GET", path: local.detailTemplate }),
    Object.freeze({ method: "GET", path: local.schemaTemplate }),
    Object.freeze({ method: "POST", path: local.invoke }),
  ]);
  const registration = Object.freeze({
    kind: "cli" as const,
    reservations,
    requiredProviderIds: Object.freeze(
      options.providerId ? [options.providerId] : [],
    ),
    async prepare(context: RemoteCliPrepareContext) {
      const pinned = context.deploymentContext.transport?.cli;
      // The application verifies deploymentContext.externalUrl against its mode.
      // Standalone createRemoteCliAdapter still requires explicit loopback opt-in.
      const external = context.deploymentContext.externalUrl;
      let externalLocation: URL | undefined;
      try {
        externalLocation =
          external === undefined ? undefined : new URL(external);
      } catch {
        throw new Error("CAP_CLI_EXTERNAL_URL_INVALID");
      }
      const validatedDevelopmentLoopback =
        externalLocation?.protocol === "http:" &&
        (externalLocation.hostname === "localhost" ||
          externalLocation.hostname === "127.0.0.1" ||
          externalLocation.hostname === "[::1]");
      const requestBytes = Math.min(
        pinned?.requestBytes ?? DEFAULT_REMOTE_CLI_PAYLOAD_LIMITS.requestBytes,
        options.payloadLimits?.requestBytes ??
          DEFAULT_REMOTE_CLI_PAYLOAD_LIMITS.requestBytes,
      );
      const responseBytes = Math.min(
        pinned?.responseBytes ??
          DEFAULT_REMOTE_CLI_PAYLOAD_LIMITS.responseBytes,
        options.payloadLimits?.responseBytes ??
          DEFAULT_REMOTE_CLI_PAYLOAD_LIMITS.responseBytes,
      );
      const adapter = createRemoteCliAdapter({
        document: context.generation.document,
        irHash: context.generation.irHash,
        serviceId: context.deploymentContext.serviceId,
        basePath: context.deploymentContext.basePath,
        endpoints: local,
        ...(context.deploymentContext.externalUrl === undefined
          ? {}
          : { externalUrl: context.deploymentContext.externalUrl }),
        allowLoopbackHttp: validatedDevelopmentLoopback,
        payloadLimits: { requestBytes, responseBytes },
        allowPrivateDiscovery:
          options.allowPrivateDiscovery === true &&
          pinned?.allowPrivateDiscovery === true,
        ...(options.disclosureSelector === undefined
          ? {}
          : { disclosureSelector: options.disclosureSelector }),
        ingress: context.ingress,
      });
      return Object.freeze({
        handle: (req: IncomingMessage, res: ServerResponse) =>
          adapter.handleNode(req, res, req.headers.authorization),
        async activate() {},
        async drain() {},
        async close() {},
      });
    },
  });
  remoteRegistrations.set(registration, local);
  return registration;
}
