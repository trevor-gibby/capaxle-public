import type { JsonSchema, JsonValue } from "@capaxle/ir";
import { jcs } from "@capaxle/ir";
import type {
  AdapterIngress,
  AdapterInvocationCandidate,
  InvocationResult,
  RuntimeDocument,
} from "@capaxle/runtime";
import { projectInputSchema, projectOutputSchema } from "./schema.js";
import {
  canonicalBytes,
  compareText,
  copyJsonData,
  dataObject,
  deepFreeze,
  GENERATOR_NAME,
  GENERATOR_VERSION,
  LEGACY_MCP_INVOCATION_META,
  MCP_INVOCATION_META,
  MCP_PROFILE_VERSION,
  MCP_PROTOCOL_VERSION,
  MCP_TARGET,
  MCP_TOOL_META,
  ProjectionError,
  resolvedDiscoveryContext,
  validateDiscoveryContext,
  verifyDocumentHash,
  type DiscoveryContext,
} from "./shared.js";

type Capability = RuntimeDocument["capabilities"][number];
type Exposure = "disabled" | "private" | "authenticated" | "public";
type DisclosureProfile = "private" | "public";

interface McpProjection {
  readonly enabled: boolean;
  readonly toolName?: string;
}

export interface McpToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: JsonSchema;
  readonly outputSchema: JsonSchema;
  readonly annotations: Readonly<Record<string, boolean>>;
  readonly _meta: {
    readonly [MCP_TOOL_META]: {
      readonly profileVersion: typeof MCP_PROFILE_VERSION;
      readonly id: string;
      readonly version: string;
      readonly irHash: string;
      readonly confirmation: string;
      readonly idempotency: string;
      readonly invocationMetadataKey: typeof MCP_INVOCATION_META;
    };
  };
}

export interface McpToolResult {
  readonly resultType: "complete";
  readonly isError: boolean;
  readonly structuredContent: InvocationResult;
  readonly content: readonly [{ readonly type: "text"; readonly text: string }];
}

export interface McpJsonRpcError {
  readonly jsonrpcError: { readonly code: number; readonly message: string };
}

export interface McpCallParams {
  readonly name: string;
  readonly arguments: Readonly<Record<string, unknown>>;
  readonly _meta?: Readonly<Record<string, unknown>>;
}

export interface McpRequestContext {
  readonly credentials?: unknown;
  readonly signal?: AbortSignal;
  readonly clientCanSendInvocationMetadata?: boolean;
  readonly discovery?: McpTrustedDiscoveryContext;
}

export interface McpTrustedDiscoveryContext {
  readonly visibility: "authenticated" | "private";
  readonly principal?: JsonValue;
}

export interface McpToolVisibilityContext {
  readonly visibility: "public" | "authenticated" | "private";
  readonly principal?: JsonValue;
}

export interface McpAdapterOptions {
  readonly document: RuntimeDocument;
  readonly irHash: string;
  readonly ingress: AdapterIngress;
  readonly discovery: DiscoveryContext;
  readonly target?: string;
  readonly profile?: DisclosureProfile;
  readonly isToolVisible?: (
    capability: Readonly<{
      id: string;
      version: string;
      exposure: Exposure;
    }>,
    context: McpToolVisibilityContext,
  ) => boolean | Promise<boolean>;
}

export interface McpAdapter {
  readonly target: typeof MCP_TARGET;
  readonly endpoint: string;
  readonly irHash: string;
  readonly discoveryContext: DiscoveryContext;
  listTools(context?: McpRequestContext): Promise<readonly McpToolDefinition[]>;
  callTool(
    params: unknown,
    context?: McpRequestContext,
  ): Promise<McpToolResult | McpJsonRpcError>;
}

const projection = (capability: Capability): McpProjection =>
  capability.interfaces.mcp as unknown as McpProjection;

const httpProjection = (capability: Capability) =>
  capability.interfaces.http as unknown as {
    readonly enabled: boolean;
    readonly method?: string;
    readonly path?: string;
  };

const capabilityRecord = (capability: Capability) =>
  capability as unknown as Record<string, unknown>;

function exposure(capability: Capability): Exposure {
  return capability.access.exposure.mcp;
}

function pathsOverlap(left: string, right: string): boolean {
  const a = left.split("/");
  const b = right.split("/");
  const variable = /^\{[A-Za-z_][A-Za-z0-9_.-]*\}$/;
  return (
    a.length === b.length &&
    a.every(
      (segment, index) =>
        segment === b[index] ||
        variable.test(segment) ||
        variable.test(b[index]!),
    )
  );
}

function validateEndpointReservation(
  document: RuntimeDocument,
  discovery: DiscoveryContext,
): void {
  if (
    document.capabilities.some((capability) => {
      const http = httpProjection(capability);
      return (
        http.enabled === true &&
        http.method === "POST" &&
        typeof http.path === "string" &&
        pathsOverlap(http.path, discovery.mcp.endpoint)
      );
    })
  )
    throw new ProjectionError("CAP_HTTP_ROUTE_COLLISION");
}

function visibilityContext(
  context: McpRequestContext,
): McpToolVisibilityContext {
  const trusted = context.discovery;
  if (trusted === undefined) return deepFreeze({ visibility: "public" });
  let inert: JsonValue;
  try {
    inert = copyJsonData(trusted);
  } catch {
    throw new ProjectionError("CAP_INPUT_INVALID");
  }
  if (
    !dataObject(inert) ||
    (inert.visibility !== "authenticated" && inert.visibility !== "private") ||
    Object.keys(inert).some(
      (key) => key !== "visibility" && key !== "principal",
    )
  )
    throw new ProjectionError("CAP_INPUT_INVALID");
  return deepFreeze({
    visibility: inert.visibility,
    ...(Object.hasOwn(inert, "principal")
      ? { principal: inert.principal }
      : {}),
  });
}

function permitsExposure(
  value: Exposure,
  context: McpToolVisibilityContext,
): boolean {
  return (
    value === "public" ||
    (value === "authenticated" && context.visibility !== "public") ||
    (value === "private" && context.visibility === "private")
  );
}

function included(capability: Capability, profile: DisclosureProfile): boolean {
  if (
    projection(capability).enabled !== true ||
    exposure(capability) === "disabled"
  )
    return false;
  return profile === "private" || exposure(capability) === "public";
}

export function mcpAnnotations(
  effects: Capability["effects"],
): Readonly<Record<string, boolean>> {
  return deepFreeze({
    openWorldHint: true,
    ...(effects.impact === "read"
      ? { readOnlyHint: true }
      : { destructiveHint: true }),
    ...(effects.idempotency === "intrinsic" ? { idempotentHint: true } : {}),
  });
}

function toolDefinition(
  document: RuntimeDocument,
  capability: Capability,
  irHash: string,
): McpToolDefinition {
  const name = projection(capability).toolName;
  if (
    typeof name !== "string" ||
    name.length === 0 ||
    name.length > 128 ||
    !/^[a-z][a-z0-9_.-]{0,127}$/.test(name)
  )
    throw new ProjectionError(
      name !== undefined && name.length > 128
        ? "CAP_MCP_TOOL_NAME_TOO_LONG"
        : "CAP_MCP_TOOL_NAME_INVALID",
      { capabilityId: capability.id },
    );
  const record = capabilityRecord(capability);
  const description =
    typeof record.description === "string"
      ? record.description
      : capability.summary;
  return deepFreeze({
    name,
    description:
      dataObject(record.lifecycle) && record.lifecycle.status === "deprecated"
        ? `Deprecated. ${description}`
        : description,
    inputSchema: projectInputSchema(document, capability),
    outputSchema: projectOutputSchema(document, capability),
    annotations: mcpAnnotations(capability.effects),
    _meta: {
      [MCP_TOOL_META]: {
        profileVersion: MCP_PROFILE_VERSION,
        id: capability.id,
        version: capability.version,
        irHash,
        confirmation: capability.effects.confirmation,
        idempotency: capability.effects.idempotency,
        invocationMetadataKey: MCP_INVOCATION_META,
      },
    },
  });
}

function projectedEntries(
  document: RuntimeDocument,
  irHash: string,
  profile: DisclosureProfile,
): readonly Readonly<{ capability: Capability; tool: McpToolDefinition }>[] {
  const names = new Map<string, string>();
  const entries = document.capabilities
    .filter((capability) => included(capability, profile))
    .map((capability) => {
      const tool = toolDefinition(document, capability, irHash);
      const other = names.get(tool.name);
      if (other)
        throw new ProjectionError("CAP_MCP_TOOL_NAME_COLLISION", {
          name: tool.name,
          capabilityIds: [other, capability.id].sort(compareText),
        });
      names.set(tool.name, capability.id);
      return deepFreeze({ capability, tool });
    });
  return deepFreeze(entries);
}

export interface McpSnapshotOptions {
  readonly document: RuntimeDocument;
  readonly irHash: string;
  readonly discovery: DiscoveryContext;
  readonly target?: string;
  readonly profile?: DisclosureProfile;
}

export function generateMcpSnapshot(options: McpSnapshotOptions): JsonValue {
  if ((options.target ?? MCP_TARGET) !== MCP_TARGET)
    throw new ProjectionError("CAP_MCP_TARGET_UNSUPPORTED", {
      target: options.target ?? "",
    });
  verifyDocumentHash(options.document, options.irHash);
  const discovery = validateDiscoveryContext(options.discovery);
  validateEndpointReservation(options.document, discovery);
  const entries = projectedEntries(
    options.document,
    options.irHash,
    options.profile ?? "private",
  );
  return deepFreeze({
    generatedBy: { name: GENERATOR_NAME, version: GENERATOR_VERSION },
    irHash: options.irHash,
    profileVersion: MCP_PROFILE_VERSION,
    protocolVersion: MCP_PROTOCOL_VERSION,
    target: MCP_TARGET,
    transport: {
      endpoint: discovery.mcp.endpoint,
      mode: "stateless",
      toolsCallResponse: "request-scoped-sse",
    },
    response: {
      resultType: "complete",
      tools: entries.map((entry) => entry.tool),
    },
  } as unknown as JsonValue);
}

export function toMcpToolResult(result: InvocationResult): McpToolResult {
  const envelope = copyJsonData(result) as unknown as InvocationResult;
  return deepFreeze({
    resultType: "complete",
    isError: envelope.ok === false,
    structuredContent: envelope,
    content: [{ type: "text", text: jcs(envelope as unknown as JsonValue) }],
  });
}

const CONTROL_KEYS = new Set([
  "confirmationToken",
  "correlationId",
  "idempotencyKey",
  "profileVersion",
  "timeoutMs",
]);

type Candidate = AdapterInvocationCandidate;

function invalidMetadata(): Candidate {
  return {
    ok: false,
    code: "CAP_INPUT_INVALID",
    status: "invalid_argument",
    safeDetails: { reason: "invalid_invocation_metadata" },
  };
}

function invalidCorrelation(): Candidate {
  return {
    ok: false,
    code: "CAP_INPUT_INVALID",
    status: "invalid_argument",
    safeDetails: { path: "/correlationId" },
  };
}

function ownRecord(value: unknown): Record<string, unknown> | null {
  if (!dataObject(value)) return null;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const result: Record<string, unknown> = Object.create(null) as Record<
      string,
      unknown
    >;
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key]!;
      if (!("value" in descriptor) || !descriptor.enumerable) return null;
      Object.defineProperty(result, key, {
        value: descriptor.value,
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return result;
  } catch {
    return null;
  }
}

function candidateFor(
  capability: Capability,
  params: Record<string, unknown>,
  canSendMetadata: boolean,
): Candidate {
  const rawContainer = params._meta;
  const container =
    rawContainer === undefined ? undefined : ownRecord(rawContainer);
  if (rawContainer !== undefined && !container) return invalidMetadata();
  if (container && Object.hasOwn(container, LEGACY_MCP_INVOCATION_META))
    return invalidMetadata();
  const rawValue = container?.[MCP_INVOCATION_META];
  if (rawValue === undefined)
    return !canSendMetadata && capability.effects.confirmation === "required"
      ? {
          ok: false,
          code: "CAP_MCP_CLIENT_METADATA_REQUIRED",
          status: "failed_precondition",
          safeDetails: { metadataKey: MCP_INVOCATION_META },
        }
      : {
          ok: true,
          input: copyJsonData(params.arguments),
          controls: {},
        };
  const value = ownRecord(rawValue);
  if (!value) return invalidMetadata();
  if (Object.keys(value).some((key) => !CONTROL_KEYS.has(key)))
    return invalidMetadata();
  if (value.profileVersion !== MCP_PROFILE_VERSION) return invalidMetadata();
  if (
    Object.hasOwn(value, "correlationId") &&
    typeof value.correlationId !== "string"
  )
    return invalidCorrelation();
  for (const key of ["confirmationToken", "correlationId", "idempotencyKey"])
    if (value[key] !== undefined && typeof value[key] !== "string")
      return invalidMetadata();
  if (
    value.timeoutMs !== undefined &&
    (!Number.isInteger(value.timeoutMs) || (value.timeoutMs as number) <= 0)
  )
    return invalidMetadata();
  if (!canSendMetadata && capability.effects.confirmation === "required")
    return {
      ok: false,
      code: "CAP_MCP_CLIENT_METADATA_REQUIRED",
      status: "failed_precondition",
      safeDetails: { metadataKey: MCP_INVOCATION_META },
    };
  const controls: Record<string, unknown> = {};
  for (const key of [
    "confirmationToken",
    "correlationId",
    "idempotencyKey",
    "timeoutMs",
  ])
    if (value[key] !== undefined) controls[key] = value[key];
  return {
    ok: true,
    input: copyJsonData(params.arguments),
    controls,
  };
}

function baseParams(value: unknown): Record<string, unknown> | null {
  const record = ownRecord(value);
  if (!record || typeof record.name !== "string") return null;
  if (!dataObject(record.arguments)) return null;
  if (
    Object.keys(record).some(
      (key) => !["name", "arguments", "_meta"].includes(key),
    )
  )
    return null;
  return record;
}

export function createMcpAdapter(options: McpAdapterOptions): McpAdapter {
  if ((options.target ?? MCP_TARGET) !== MCP_TARGET)
    throw new ProjectionError("CAP_MCP_TARGET_UNSUPPORTED");
  verifyDocumentHash(options.document, options.irHash);
  const discovery = validateDiscoveryContext(options.discovery);
  validateEndpointReservation(options.document, discovery);
  const disclosureProfile = options.profile ?? "private";
  const entries = projectedEntries(options.document, options.irHash, "private");

  const visible = async (
    entry: (typeof entries)[number],
    context: McpRequestContext,
  ): Promise<boolean> =>
    options.isToolVisible
      ? options.isToolVisible(
          {
            id: entry.capability.id,
            version: entry.capability.version,
            exposure: exposure(entry.capability),
          },
          visibilityContext(context),
        )
      : true;

  return deepFreeze({
    target: MCP_TARGET,
    endpoint: discovery.mcp.endpoint,
    irHash: options.irHash,
    discoveryContext: discovery,
    async listTools(context: McpRequestContext = {}) {
      const visibility = visibilityContext(context);
      const tools: McpToolDefinition[] = [];
      for (const entry of entries)
        if (
          included(entry.capability, disclosureProfile) &&
          permitsExposure(exposure(entry.capability), visibility) &&
          (await visible(entry, context))
        )
          tools.push(entry.tool);
      return deepFreeze(tools);
    },
    async callTool(params: unknown, context: McpRequestContext = {}) {
      const parsed = baseParams(params);
      if (!parsed)
        return {
          jsonrpcError: {
            code: -32602,
            message: "Invalid tools/call parameters.",
          },
        };
      const entry = entries.find(
        (candidate) => candidate.tool.name === parsed.name,
      );
      if (!entry)
        return { jsonrpcError: { code: -32602, message: "Unknown tool." } };
      let adapterCandidate: Candidate;
      try {
        adapterCandidate = candidateFor(
          entry.capability,
          parsed,
          context.clientCanSendInvocationMetadata !== false,
        );
      } catch {
        adapterCandidate = invalidMetadata();
      }
      const request = {
        capability: entry.capability.id,
        version: entry.capability.version,
        ...(context.credentials === undefined
          ? {}
          : { credentials: context.credentials }),
        ...(context.signal === undefined ? {} : { signal: context.signal }),
        adapterCandidate,
      };
      const result = await options.ingress.invoke(request);
      return toMcpToolResult(result);
    },
  });
}

interface ArtifactContext {
  readonly buildContext: {
    readonly irHash: string;
    readonly discovery: DiscoveryContext;
  };
  readonly dependencyBytes: ReadonlyMap<string, Uint8Array>;
}

export function createMcpSnapshotArtifactProducer(
  options: Readonly<{
    discovery?: DiscoveryContext;
    profile?: DisclosureProfile;
  }> = {},
) {
  const discoveryAssertion =
    options.discovery === undefined
      ? undefined
      : validateDiscoveryContext(options.discovery);
  const profile = options.profile ?? "private";
  return deepFreeze({
    id: "capaxle.mcp-snapshot",
    version: GENERATOR_VERSION,
    staticInputs: {
      profile,
      ...(discoveryAssertion === undefined ? {} : { discoveryAssertion }),
    },
    diagnosticCodes: [
      {
        code: "CAP_BUILD_CONTEXT_INVALID" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_DISCOVERY_CONTEXT_MISMATCH" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_HTTP_ROUTE_COLLISION" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_MCP_CLIENT_METADATA_REQUIRED" as const,
        severities: ["warning" as const],
      },
      {
        code: "CAP_MCP_SCHEMA_UNREPRESENTABLE" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_MCP_TARGET_UNSUPPORTED" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_MCP_TOOL_NAME_COLLISION" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_MCP_TOOL_NAME_INVALID" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_MCP_TOOL_NAME_TOO_LONG" as const,
        severities: ["error" as const],
      },
    ],
    artifacts: [
      {
        id: "mcp-tool-snapshot",
        path: "mcp-tools.json",
        mediaType: "application/json",
        target: MCP_TARGET,
        dependencies: ["document:capability-ir" as const],
        produce(context: ArtifactContext) {
          try {
            const discovery = resolvedDiscoveryContext(
              context.buildContext.discovery,
              discoveryAssertion,
            );
            const bytes = context.dependencyBytes.get("document:capability-ir");
            if (!bytes)
              throw new ProjectionError("CAP_MCP_SCHEMA_UNREPRESENTABLE");
            const document = JSON.parse(
              new TextDecoder().decode(bytes),
            ) as RuntimeDocument;
            return {
              ok: true as const,
              bytes: canonicalBytes(
                generateMcpSnapshot({
                  document,
                  irHash: context.buildContext.irHash,
                  discovery,
                  profile,
                }),
              ),
              diagnostics: document.capabilities
                .filter(
                  (capability) =>
                    included(capability, profile) &&
                    capability.effects.confirmation === "required",
                )
                .map((capability) => ({
                  code: "CAP_MCP_CLIENT_METADATA_REQUIRED" as const,
                  severity: "warning" as const,
                  message: `Clients must support ${MCP_INVOCATION_META} to submit confirmation evidence.`,
                  target: MCP_TARGET,
                  capabilityId: capability.id,
                  path: "/interfaces/mcp",
                })),
            };
          } catch (error) {
            const failure =
              error instanceof ProjectionError
                ? error
                : new ProjectionError("CAP_MCP_SCHEMA_UNREPRESENTABLE");
            return {
              ok: false as const,
              diagnostics: [
                {
                  code: failure.code,
                  severity: "error" as const,
                  message: "MCP tool snapshot generation failed.",
                  target: MCP_TARGET,
                  details: failure.details,
                },
              ],
            };
          }
        },
      },
    ],
  });
}
