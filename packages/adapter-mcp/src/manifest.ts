import { createHash } from "node:crypto";
import type { JsonValue } from "@capaxle/ir";
import type { RuntimeDocument } from "@capaxle/runtime";
import {
  canonicalBytes,
  compareText,
  dataObject,
  deepFreeze,
  GENERATOR_NAME,
  GENERATOR_VERSION,
  MCP_TARGET,
  ProjectionError,
  resolvedDiscoveryContext,
  validateDiscoveryContext,
  verifyCliBinary,
  verifyDocumentHash,
  type DiscoveryContext,
} from "./shared.js";

type Capability = RuntimeDocument["capabilities"][number];
export type ManifestProfile = "private" | "public" | "live";
export type ManifestInterface = "http" | "cli" | "mcp";
type Exposure = "private" | "authenticated" | "public";

export interface ManifestVisibilityEntry {
  readonly id: string;
  readonly version: string;
  readonly interface: ManifestInterface;
}

export interface AgentManifestBuildLocatorV01 {
  readonly artifactGraphVersion: "0.2";
  readonly buildId: `sha256:${string}`;
  readonly index: string;
  readonly indexSha256: `sha256:${string}`;
  readonly payloadArtifactId: "capaxle.agent-manifest";
  readonly payloadSha256: `sha256:${string}`;
}

export interface AgentManifestV01 {
  readonly manifestVersion: "0.1";
  readonly profile: ManifestProfile;
  readonly service: { readonly name: string; readonly version: string };
  readonly irVersion: "0.1";
  readonly irHash: `sha256:${string}`;
  readonly generatedBy: { readonly name: string; readonly version: string };
  readonly discovery: {
    readonly http: DiscoveryContext["http"];
    readonly mcp: {
      readonly endpoint: string;
      readonly target: typeof MCP_TARGET;
    };
  };
  readonly namespaces: readonly string[];
  readonly capabilities: readonly JsonValue[];
  readonly build?: AgentManifestBuildLocatorV01;
}

export interface AgentManifestOptions {
  readonly document: RuntimeDocument;
  readonly irHash: string;
  readonly discovery: DiscoveryContext;
  readonly profile?: ManifestProfile;
  readonly visibility?: readonly ManifestVisibilityEntry[];
  readonly cliBinary?: string;
}

const projection = (capability: Capability, name: ManifestInterface) =>
  capability.interfaces[name] as unknown as Record<string, unknown>;

function compareSemver(left: string, right: string): number {
  const parse = (value: string) => {
    const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/.exec(value);
    return match
      ? {
          core: [Number(match[1]), Number(match[2]), Number(match[3])],
          pre: match[4]?.split(".") ?? null,
        }
      : null;
  };
  const a = parse(left);
  const b = parse(right);
  if (!a || !b) return compareText(left, right);
  for (let index = 0; index < 3; index += 1) {
    const difference = a.core[index]! - b.core[index]!;
    if (difference !== 0) return difference;
  }
  if (a.pre === null || b.pre === null)
    return a.pre === b.pre ? compareText(left, right) : a.pre === null ? 1 : -1;
  const length = Math.max(a.pre.length, b.pre.length);
  for (let index = 0; index < length; index += 1) {
    const x = a.pre[index];
    const y = b.pre[index];
    if (x === undefined || y === undefined)
      return x === y ? 0 : x === undefined ? -1 : 1;
    if (x === y) continue;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn !== yn) return xn ? -1 : 1;
    return xn ? Number(x) - Number(y) : compareText(x, y);
  }
  return compareText(left, right);
}

function lifecycle(capability: Capability): JsonValue {
  const source = (capability as unknown as Record<string, unknown>).lifecycle;
  if (!dataObject(source) || typeof source.status !== "string")
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED", {
      reason: "invalid_lifecycle",
      capabilityId: capability.id,
    });
  const allowed =
    source.status === "deprecated"
      ? new Set(["status", "since", "deprecatedAt", "sunsetAt", "replacement"])
      : source.status === "experimental" || source.status === "stable"
        ? new Set(["status", "since"])
        : null;
  if (
    !allowed ||
    Object.keys(source).some((key) => !allowed.has(key)) ||
    Object.entries(source).some(
      ([key, value]) => key !== "status" && typeof value !== "string",
    )
  )
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED", {
      reason: "invalid_lifecycle",
      capabilityId: capability.id,
    });
  const result: Record<string, JsonValue> = { status: source.status };
  for (const key of ["since", "deprecatedAt", "sunsetAt", "replacement"])
    if (source[key] !== undefined) result[key] = source[key] as string;
  return result;
}

function validateVisibility(
  document: RuntimeDocument,
  visibility: readonly ManifestVisibilityEntry[] | undefined,
): Set<string> {
  if (!visibility)
    throw new ProjectionError("CAP_MANIFEST_VISIBILITY_INVALID", {
      reason: "missing",
    });
  const result = new Set<string>();
  for (const entry of visibility) {
    if (
      !dataObject(entry) ||
      Object.keys(entry).sort().join("\0") !== "id\0interface\0version" ||
      typeof entry.id !== "string" ||
      typeof entry.version !== "string" ||
      !["http", "cli", "mcp"].includes(entry.interface)
    )
      throw new ProjectionError("CAP_MANIFEST_VISIBILITY_INVALID", {
        reason: "shape",
      });
    const key = `${entry.id}\0${entry.version}\0${entry.interface}`;
    if (result.has(key))
      throw new ProjectionError("CAP_MANIFEST_VISIBILITY_INVALID", {
        reason: "duplicate",
      });
    const capability = document.capabilities.find(
      (candidate) =>
        candidate.id === entry.id && candidate.version === entry.version,
    );
    if (
      !capability ||
      projection(capability, entry.interface).enabled !== true ||
      capability.access.exposure[entry.interface] === "disabled"
    )
      throw new ProjectionError("CAP_MANIFEST_VISIBILITY_INVALID", {
        reason: "unknown_or_disabled",
      });
    result.add(key);
  }
  return result;
}

const rfc3986 = (value: string) =>
  encodeURIComponent(value).replace(
    /[!'()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`,
  );

function manifestCapability(
  capability: Capability,
  profile: ManifestProfile,
  live: Set<string> | null,
  discovery: DiscoveryContext,
  cliBinary: string | undefined,
): JsonValue | null {
  const exposure: Record<string, JsonValue> = {};
  const interfaces: Record<string, JsonValue> = {};
  const describe: Record<string, JsonValue> = {};
  for (const name of ["http", "cli", "mcp"] as const) {
    const item = projection(capability, name);
    const canonicalExposure = capability.access.exposure[name];
    const selected =
      item.enabled === true &&
      canonicalExposure !== "disabled" &&
      (profile === "private" ||
        (profile === "public" && canonicalExposure === "public") ||
        (profile === "live" &&
          live!.has(`${capability.id}\0${capability.version}\0${name}`)));
    if (!selected) continue;
    exposure[name] = canonicalExposure as Exposure;
    if (name === "http") {
      if (typeof item.method !== "string" || typeof item.path !== "string")
        throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
      interfaces.http = { method: item.method, path: item.path };
      describe.http = discovery.http.detailTemplate.replace(
        "{id}",
        rfc3986(capability.id),
      );
    } else if (name === "cli") {
      verifyCliBinary(cliBinary);
      if (
        !Array.isArray(item.command) ||
        item.command.some((part) => typeof part !== "string")
      )
        throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
      interfaces.cli = { command: [cliBinary, ...item.command] };
      describe.cli = [
        cliBinary,
        "capabilities",
        "describe",
        capability.id,
        "--json",
      ];
    } else {
      if (typeof item.toolName !== "string")
        throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
      interfaces.mcp = { toolName: item.toolName };
    }
  }
  if (profile !== "private" && Object.keys(interfaces).length === 0)
    return null;
  const effects = capability.effects;
  if (
    !["read", "write", "destructive"].includes(effects.impact) ||
    !["none", "required"].includes(effects.confirmation) ||
    !["none", "intrinsic", "key"].includes(effects.idempotency)
  )
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED", {
      reason: "unsupported_effects",
    });
  return {
    id: capability.id,
    version: capability.version,
    summary: capability.summary,
    lifecycle: lifecycle(capability),
    exposure,
    effects: {
      impact: effects.impact,
      confirmation: effects.confirmation,
      idempotency: effects.idempotency,
    },
    interfaces,
    describe,
  };
}

export function generateAgentManifest(
  options: AgentManifestOptions,
): AgentManifestV01 {
  verifyDocumentHash(options.document, options.irHash);
  const discovery = validateDiscoveryContext(options.discovery);
  const profile = options.profile ?? "private";
  if (!["private", "public", "live"].includes(profile))
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED", {
      reason: "invalid_profile",
    });
  const live =
    profile === "live"
      ? validateVisibility(options.document, options.visibility)
      : null;
  if (profile !== "live" && options.visibility !== undefined)
    throw new ProjectionError("CAP_MANIFEST_VISIBILITY_INVALID", {
      reason: "unexpected",
    });
  const capabilities = [...options.document.capabilities]
    .sort(
      (left, right) =>
        compareText(left.id, right.id) ||
        compareSemver(left.version, right.version) ||
        compareText(left.version, right.version),
    )
    .map((capability) =>
      manifestCapability(
        capability,
        profile,
        live,
        discovery,
        options.cliBinary,
      ),
    )
    .filter((value): value is JsonValue => value !== null);
  const namespaces = [
    ...new Set(
      capabilities.map(
        (entry) =>
          String((entry as Record<string, JsonValue>).id).split(".")[0]!,
      ),
    ),
  ].sort(compareText);
  const service = (options.document as unknown as Record<string, unknown>)
    .service;
  if (
    !dataObject(service) ||
    typeof service.name !== "string" ||
    typeof service.version !== "string"
  )
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
  return deepFreeze({
    manifestVersion: "0.1",
    profile,
    service: { name: service.name, version: service.version },
    irVersion: "0.1",
    irHash: options.irHash as `sha256:${string}`,
    generatedBy: { name: GENERATOR_NAME, version: GENERATOR_VERSION },
    discovery: {
      http: discovery.http,
      mcp: { endpoint: discovery.mcp.endpoint, target: MCP_TARGET },
    },
    namespaces,
    capabilities,
  });
}

const SHA256 = /^sha256:[0-9a-f]{64}$/;
function verifyLocator(
  build: unknown,
  payload: Uint8Array,
): asserts build is AgentManifestBuildLocatorV01 {
  if (!dataObject(build))
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
  const keys = Object.keys(build).sort().join("\0");
  if (
    keys !==
      [
        "artifactGraphVersion",
        "buildId",
        "index",
        "indexSha256",
        "payloadArtifactId",
        "payloadSha256",
      ]
        .sort()
        .join("\0") ||
    build.artifactGraphVersion !== "0.2" ||
    build.payloadArtifactId !== "capaxle.agent-manifest" ||
    typeof build.buildId !== "string" ||
    typeof build.indexSha256 !== "string" ||
    typeof build.payloadSha256 !== "string" ||
    !SHA256.test(build.buildId) ||
    !SHA256.test(build.indexSha256) ||
    !SHA256.test(build.payloadSha256) ||
    typeof build.index !== "string" ||
    build.index.startsWith("/") ||
    build.index
      .split("/")
      .some((part) => part === "" || part === "." || part === "..") ||
    build.index.split("/").includes("current.json") ||
    `sha256:${createHash("sha256").update(payload).digest("hex")}` !==
      build.payloadSha256
  )
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED", {
      reason: "invalid_build_locator",
    });
}

export function assembleAgentManifestRoot(context: {
  readonly payload: Uint8Array;
  readonly build: unknown;
}): Uint8Array {
  verifyLocator(context.build, context.payload);
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(context.payload));
  } catch {
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
  }
  if (
    !dataObject(payload) ||
    payload.manifestVersion !== "0.1" ||
    Object.hasOwn(payload, "build")
  )
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
  return canonicalBytes({
    ...payload,
    build: context.build,
  } as unknown as JsonValue);
}

interface ArtifactContext {
  readonly buildContext: {
    readonly irHash: string;
    readonly cliBinary?: string;
    readonly discovery: DiscoveryContext;
  };
  readonly dependencyBytes: ReadonlyMap<string, Uint8Array>;
}

export function createAgentManifestArtifactProducer(
  options: Readonly<{
    discovery?: DiscoveryContext;
    profile?: Exclude<ManifestProfile, "live">;
  }> = {},
) {
  const discoveryAssertion =
    options.discovery === undefined
      ? undefined
      : validateDiscoveryContext(options.discovery);
  const profile = options.profile ?? "private";
  return deepFreeze({
    id: "capaxle.agent-manifest",
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
        code: "CAP_MANIFEST_GENERATION_FAILED" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_MANIFEST_VISIBILITY_INVALID" as const,
        severities: ["error" as const],
      },
    ],
    artifacts: [
      {
        id: "capaxle.agent-manifest",
        path: "agent-manifest.json",
        mediaType: "application/json",
        target: "capaxle:agent-manifest@0.1",
        dependencies: ["document:capability-ir" as const],
        produce(context: ArtifactContext) {
          try {
            const discovery = resolvedDiscoveryContext(
              context.buildContext.discovery,
              discoveryAssertion,
            );
            const bytes = context.dependencyBytes.get("document:capability-ir");
            if (!bytes)
              throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
            const document = JSON.parse(
              new TextDecoder().decode(bytes),
            ) as RuntimeDocument;
            return {
              ok: true as const,
              bytes: canonicalBytes(
                generateAgentManifest({
                  document,
                  irHash: context.buildContext.irHash,
                  discovery,
                  profile,
                  ...(context.buildContext.cliBinary === undefined
                    ? {}
                    : { cliBinary: context.buildContext.cliBinary }),
                }) as unknown as JsonValue,
              ),
              diagnostics: [],
            };
          } catch (error) {
            const failure =
              error instanceof ProjectionError
                ? error
                : new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
            return {
              ok: false as const,
              diagnostics: [
                {
                  code: failure.code,
                  severity: "error" as const,
                  message: "Agent manifest generation failed.",
                  target: "capaxle:agent-manifest@0.1",
                  details: failure.details,
                },
              ],
            };
          }
        },
      },
    ],
    rootPublication: {
      payloadArtifactId: "capaxle.agent-manifest",
      rootPath: "capaxle.manifest.json",
      legacyPath: "capabuild.manifest.json",
      assemble: assembleAgentManifestRoot,
    },
  });
}
