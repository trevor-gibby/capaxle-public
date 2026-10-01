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
  MCP_LEGACY_TARGET,
  MCP_LEGACY_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION,
  MCP_PROFILE_VERSION,
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
      readonly target: "mcp@2026-07-28/streamable-http/tools-unary-v2";
    };
  };
  readonly namespaces: readonly string[];
  readonly capabilities: readonly JsonValue[];
  readonly build?: AgentManifestBuildLocatorV01;
}

export interface AgentManifestV02 extends Omit<
  AgentManifestV01,
  "manifestVersion" | "discovery"
> {
  readonly manifestVersion: "0.2";
  readonly discovery: {
    readonly http: DiscoveryContext["http"];
    readonly mcp?: {
      readonly endpoint: string;
      readonly profiles: readonly Readonly<{
        protocolVersion:
          typeof MCP_PROTOCOL_VERSION | typeof MCP_LEGACY_PROTOCOL_VERSION;
        target: typeof MCP_TARGET | typeof MCP_LEGACY_TARGET;
        profileVersion: typeof MCP_PROFILE_VERSION;
      }>[];
    };
    readonly cli?: ManifestCliLocator;
  };
}

export interface ManifestCliLocator {
  readonly protocolVersion: "0.1";
  readonly endpoints: Readonly<{
    collection: string;
    detailTemplate: string;
    schemaTemplate: string;
    invoke: string;
  }>;
  readonly externalUrl?: string;
}

export type ManifestRemoteCli = Omit<ManifestCliLocator, "protocolVersion">;

const cliCommandToken = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export interface AgentManifestOptions {
  readonly document: RuntimeDocument;
  readonly irHash: string;
  readonly discovery: DiscoveryContext;
  readonly profile?: ManifestProfile;
  readonly visibility?: readonly ManifestVisibilityEntry[];
  readonly cliBinary?: string;
  readonly mcpEnabled?: boolean;
  readonly remoteCli?: ManifestRemoteCli;
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

function validateRemoteCli(value: unknown): ManifestRemoteCli {
  if (
    !dataObject(value) ||
    Object.keys(value).some(
      (key) => key !== "endpoints" && key !== "externalUrl",
    ) ||
    !dataObject(value.endpoints) ||
    Object.keys(value.endpoints).sort().join("\0") !==
      ["collection", "detailTemplate", "schemaTemplate", "invoke"]
        .sort()
        .join("\0")
  )
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
  const endpoints = value.endpoints;
  if (
    ["collection", "detailTemplate", "schemaTemplate", "invoke"].some(
      (key) => typeof endpoints[key] !== "string",
    )
  )
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
  try {
    validateDiscoveryContext({
      http: {
        collection: endpoints.collection,
        detailTemplate: endpoints.detailTemplate,
        schemaTemplate: endpoints.schemaTemplate,
      },
      mcp: { endpoint: endpoints.invoke },
    });
  } catch {
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
  }
  const paths = [
    endpoints.collection as string,
    endpoints.detailTemplate as string,
    endpoints.schemaTemplate as string,
    endpoints.invoke as string,
  ];
  for (const path of paths) {
    for (const segment of path.split("/").slice(1)) {
      if (segment === "{id}") continue;
      let decoded: string;
      try {
        decoded = decodeURIComponent(segment);
      } catch {
        throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
      }
      if (
        decoded === "." ||
        decoded === ".." ||
        decoded.includes("/") ||
        decoded.includes("\\") ||
        /[\u0000-\u001f\u007f-\u009f]/u.test(decoded)
      )
        throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
    }
  }
  for (let left = 0; left < paths.length; left++) {
    for (let right = left + 1; right < paths.length; right++) {
      const a = paths[left]!.split("/");
      const b = paths[right]!.split("/");
      if (
        a.length === b.length &&
        a.every(
          (part, index) =>
            part === b[index] || part === "{id}" || b[index] === "{id}",
        )
      )
        throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
    }
  }
  const externalUrl = value.externalUrl;
  if (externalUrl !== undefined) {
    if (typeof externalUrl !== "string")
      throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
    let url: URL;
    try {
      url = new URL(externalUrl);
    } catch {
      throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
    }
    const loopback =
      url.hostname === "localhost" ||
      url.hostname === "127.0.0.1" ||
      url.hostname === "[::1]";
    const mount = url.pathname;
    const rawLocation = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*(\/[^?#]*)?/.exec(
      externalUrl,
    );
    const rawMount = rawLocation?.[1] ?? "/";
    const validMount =
      mount === "/" ||
      (mount.startsWith("/") &&
        !mount.startsWith("//") &&
        !mount.endsWith("/") &&
        !/[?#\\\0%]/.test(mount) &&
        mount
          .split("/")
          .slice(1)
          .every((part) => part !== "" && part !== "." && part !== ".."));
    if (
      !rawLocation ||
      (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      rawMount !== mount ||
      !validMount ||
      (mount !== "/" &&
        Object.values(endpoints).some(
          (path) => typeof path !== "string" || !path.startsWith(`${mount}/`),
        ))
    )
      throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
  }
  return deepFreeze({
    endpoints: {
      collection: endpoints.collection as string,
      detailTemplate: endpoints.detailTemplate as string,
      schemaTemplate: endpoints.schemaTemplate as string,
      invoke: endpoints.invoke as string,
    },
    ...(externalUrl === undefined ? {} : { externalUrl }),
  });
}

function manifestCapability(
  capability: Capability,
  profile: ManifestProfile,
  live: Set<string> | null,
  discovery: DiscoveryContext,
  cliBinary: string | undefined,
  mcpEnabled: boolean,
  remoteCliEnabled: boolean,
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
    if (!selected || (name === "mcp" && !mcpEnabled)) continue;
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
      if (cliBinary === undefined && !remoteCliEnabled)
        throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
      if (cliBinary !== undefined) verifyCliBinary(cliBinary);
      if (
        !Array.isArray(item.command) ||
        item.command.length === 0 ||
        item.command.some(
          (part) => typeof part !== "string" || !cliCommandToken.test(part),
        )
      )
        throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED");
      interfaces.cli = {
        ...(cliBinary === undefined
          ? {}
          : { command: [cliBinary, ...item.command] }),
        ...(remoteCliEnabled ? { remoteCommand: [...item.command] } : {}),
      };
      if (cliBinary !== undefined)
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
): AgentManifestV02 {
  verifyDocumentHash(options.document, options.irHash);
  const discovery = validateDiscoveryContext(options.discovery);
  const remoteCli =
    options.remoteCli === undefined
      ? undefined
      : validateRemoteCli(options.remoteCli);
  const profile = options.profile ?? "private";
  if (
    options.mcpEnabled !== undefined &&
    typeof options.mcpEnabled !== "boolean"
  )
    throw new ProjectionError("CAP_MANIFEST_GENERATION_FAILED", {
      reason: "invalid_mcp_enabled",
    });
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
        options.mcpEnabled === true,
        remoteCli !== undefined,
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
    manifestVersion: "0.2",
    profile,
    service: { name: service.name, version: service.version },
    irVersion: "0.1",
    irHash: options.irHash as `sha256:${string}`,
    generatedBy: { name: GENERATOR_NAME, version: GENERATOR_VERSION },
    discovery: {
      http: discovery.http,
      ...(options.mcpEnabled === true
        ? {
            mcp: {
              endpoint: discovery.mcp.endpoint,
              profiles: [
                {
                  protocolVersion: MCP_LEGACY_PROTOCOL_VERSION,
                  target: MCP_LEGACY_TARGET,
                  profileVersion: MCP_PROFILE_VERSION,
                },
                {
                  protocolVersion: MCP_PROTOCOL_VERSION,
                  target: MCP_TARGET,
                  profileVersion: MCP_PROFILE_VERSION,
                },
              ],
            },
          }
        : {}),
      ...(remoteCli === undefined
        ? {}
        : { cli: { protocolVersion: "0.1" as const, ...remoteCli } }),
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

const closed = (
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = [],
): value is Record<string, unknown> =>
  dataObject(value) &&
  required.every((key) => Object.hasOwn(value, key)) &&
  Object.keys(value).every(
    (key) => required.includes(key) || optional.includes(key),
  );
const strings = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === "string");
const enumValue = (
  value: unknown,
  choices: readonly string[],
): value is string => typeof value === "string" && choices.includes(value);

function validManifestPayload(
  payload: unknown,
): payload is Record<string, unknown> {
  if (
    !closed(payload, [
      "manifestVersion",
      "profile",
      "service",
      "irVersion",
      "irHash",
      "generatedBy",
      "discovery",
      "namespaces",
      "capabilities",
    ]) ||
    (payload.manifestVersion !== "0.1" && payload.manifestVersion !== "0.2") ||
    !enumValue(payload.profile, ["private", "public", "live"]) ||
    payload.irVersion !== "0.1" ||
    typeof payload.irHash !== "string" ||
    !SHA256.test(payload.irHash) ||
    !closed(payload.service, ["name", "version"]) ||
    typeof payload.service.name !== "string" ||
    typeof payload.service.version !== "string" ||
    !closed(payload.generatedBy, ["name", "version"]) ||
    payload.generatedBy.name !== GENERATOR_NAME ||
    typeof payload.generatedBy.version !== "string" ||
    !closed(payload.discovery, ["http"], ["mcp", "cli"]) ||
    !strings(payload.namespaces) ||
    !Array.isArray(payload.capabilities)
  )
    return false;
  try {
    validateDiscoveryContext({
      http: payload.discovery.http,
      mcp: {
        endpoint: dataObject(payload.discovery.mcp)
          ? payload.discovery.mcp.endpoint
          : "/mcp",
      },
    });
  } catch {
    return false;
  }
  const mcp = payload.discovery.mcp;
  const cli = payload.discovery.cli;
  if (payload.manifestVersion === "0.1") {
    if (
      cli !== undefined ||
      !closed(mcp, ["endpoint", "target"]) ||
      mcp.target !== "mcp@2026-07-28/streamable-http/tools-unary-v2"
    )
      return false;
  } else if (mcp !== undefined) {
    if (
      !closed(mcp, ["endpoint", "profiles"]) ||
      !Array.isArray(mcp.profiles) ||
      mcp.profiles.length !== 2
    )
      return false;
    const expected = [
      [MCP_LEGACY_PROTOCOL_VERSION, MCP_LEGACY_TARGET],
      [MCP_PROTOCOL_VERSION, MCP_TARGET],
    ];
    if (
      !mcp.profiles.every(
        (profile, index) =>
          closed(profile, ["protocolVersion", "target", "profileVersion"]) &&
          profile.protocolVersion === expected[index]![0] &&
          profile.target === expected[index]![1] &&
          profile.profileVersion === MCP_PROFILE_VERSION,
      )
    )
      return false;
  }
  if (cli !== undefined) {
    if (
      payload.manifestVersion !== "0.2" ||
      !closed(cli, ["protocolVersion", "endpoints"], ["externalUrl"]) ||
      cli.protocolVersion !== "0.1"
    )
      return false;
    try {
      validateRemoteCli({
        endpoints: cli.endpoints,
        ...(cli.externalUrl === undefined
          ? {}
          : { externalUrl: cli.externalUrl }),
      });
    } catch {
      return false;
    }
  }
  return payload.capabilities.every((capability) => {
    if (
      !closed(capability, [
        "id",
        "version",
        "summary",
        "lifecycle",
        "exposure",
        "effects",
        "interfaces",
        "describe",
      ]) ||
      [capability.id, capability.version, capability.summary].some(
        (value) => typeof value !== "string",
      ) ||
      !dataObject(capability.lifecycle) ||
      !dataObject(capability.exposure) ||
      !dataObject(capability.interfaces) ||
      !dataObject(capability.describe) ||
      !closed(capability.effects, ["impact", "confirmation", "idempotency"]) ||
      !enumValue(capability.effects.impact, ["read", "write", "destructive"]) ||
      !enumValue(capability.effects.confirmation, ["none", "required"]) ||
      !enumValue(capability.effects.idempotency, ["none", "intrinsic", "key"])
    )
      return false;
    try {
      lifecycle({
        id: capability.id,
        lifecycle: capability.lifecycle,
      } as unknown as Capability);
    } catch {
      return false;
    }
    const names = Object.keys(capability.interfaces);
    if (
      !names.every((name) => ["http", "cli", "mcp"].includes(name)) ||
      Object.keys(capability.exposure).sort().join("\0") !==
        names.sort().join("\0") ||
      Object.values(capability.exposure).some(
        (value) => !enumValue(value, ["private", "authenticated", "public"]),
      )
    )
      return false;
    if (
      capability.interfaces.http !== undefined &&
      (!closed(capability.interfaces.http, ["method", "path"]) ||
        typeof capability.interfaces.http.method !== "string" ||
        typeof capability.interfaces.http.path !== "string")
    )
      return false;
    const cliEntry = capability.interfaces.cli;
    if (cliEntry !== undefined) {
      if (payload.manifestVersion === "0.1") {
        if (!closed(cliEntry, ["command"]) || !strings(cliEntry.command))
          return false;
      } else {
        if (
          !closed(cliEntry, [], ["command", "remoteCommand"]) ||
          (cliEntry.command === undefined &&
            cliEntry.remoteCommand === undefined) ||
          (cliEntry.command !== undefined &&
            (!strings(cliEntry.command) ||
              cliEntry.command.length < 2 ||
              cliEntry.command
                .slice(1)
                .some((part) => !cliCommandToken.test(part)))) ||
          (cliEntry.remoteCommand !== undefined &&
            (!strings(cliEntry.remoteCommand) ||
              cliEntry.remoteCommand.length === 0 ||
              cliEntry.remoteCommand.some(
                (part) => !cliCommandToken.test(part),
              ))) ||
          (cli !== undefined) !== (cliEntry.remoteCommand !== undefined) ||
          (cliEntry.command !== undefined) !==
            (capability.describe.cli !== undefined)
        )
          return false;
        if (cliEntry.command !== undefined) {
          try {
            verifyCliBinary(cliEntry.command[0]);
          } catch {
            return false;
          }
        }
      }
    } else if (
      payload.manifestVersion === "0.2" &&
      capability.describe.cli !== undefined
    )
      return false;
    if (
      capability.interfaces.mcp !== undefined &&
      (mcp === undefined ||
        !closed(capability.interfaces.mcp, ["toolName"]) ||
        typeof capability.interfaces.mcp.toolName !== "string")
    )
      return false;
    return (
      closed(capability.describe, [], ["http", "cli"]) &&
      (capability.describe.http === undefined ||
        typeof capability.describe.http === "string") &&
      (capability.describe.cli === undefined ||
        strings(capability.describe.cli))
    );
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
  if (!validManifestPayload(payload))
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
    mcpEnabled?: boolean;
    remoteCli?: ManifestRemoteCli;
  }> = {},
) {
  const discoveryAssertion =
    options.discovery === undefined
      ? undefined
      : validateDiscoveryContext(options.discovery);
  const profile = options.profile ?? "private";
  const remoteCli =
    options.remoteCli === undefined
      ? undefined
      : validateRemoteCli(options.remoteCli);
  return deepFreeze({
    id: "capaxle.agent-manifest",
    version: GENERATOR_VERSION,
    staticInputs: {
      profile,
      mcpEnabled: options.mcpEnabled === true,
      ...(discoveryAssertion === undefined ? {} : { discoveryAssertion }),
      ...(remoteCli === undefined ? {} : { remoteCli }),
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
        target: "capaxle:agent-manifest@0.2",
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
                  mcpEnabled: options.mcpEnabled === true,
                  ...(remoteCli === undefined ? {} : { remoteCli }),
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
                  target: "capaxle:agent-manifest@0.2",
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
