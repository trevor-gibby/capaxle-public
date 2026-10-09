import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  generateDocsSchemaArchive,
  DOCS_SCHEMA_GENERATOR_VERSION,
  DOCS_SCHEMA_TARGET,
} from "@capaxle/generator-docs";
import {
  renderDocumentationPage,
  validateDocumentationStylesheet,
  projectDocumentationView,
  projectDocumentationModel,
  validateDocumentationBundle,
  type DocumentationModel,
  type DocumentationBundle,
  type DocumentationConnection,
} from "@capaxle/generator-docs/browser";
import { jcs, type JsonValue } from "@capaxle/ir";
import type {
  CompilerArtifactProducer,
  CompilationSuccess,
  CompiledArtifact,
} from "@capaxle/compiler";
import type { AdapterIngress, AdapterDisclosureResult } from "@capaxle/runtime";
import { HTTP_ERROR_STATUS } from "@capaxle/adapter-http";
import { CLI_EXIT_CODES } from "@capaxle/adapter-cli";
import { MCP_SUPPORTED_VERSIONS } from "@capaxle/adapter-mcp";
import type { DeploymentContext } from "./deployment.js";
import { ApplicationError } from "./errors.js";

export interface DocumentationOptions {
  readonly enabled: true;
  readonly path?: string;
  readonly externalUrl?: string;
  readonly providerId?: string;
  /** A restriction of authenticated canonical exposure; never disclosure authority. */
  readonly disclosureSelector?: (
    disclosure: AdapterDisclosureResult,
  ) => readonly string[] | Promise<readonly string[]>;
}
export interface DocumentationDeploymentContext {
  readonly path: string;
  readonly externalUrl?: string;
}

export function resolveDocumentationContext(
  enabled: boolean,
  basePath: string,
  applicationUrl?: string,
  supplied?: Readonly<{ path?: string; externalUrl?: string }>,
  allowHttpLoopback = false,
): DocumentationDeploymentContext | undefined {
  if (!enabled) {
    if (supplied !== undefined)
      throw new ApplicationError(
        "CAP_APP_MOUNT_INVALID",
        "Disabled documentation has deployment settings.",
      );
    return undefined;
  }
  if (
    supplied !== undefined &&
    (!supplied ||
      typeof supplied !== "object" ||
      Array.isArray(supplied) ||
      Object.keys(supplied).some(
        (key) => key !== "path" && key !== "externalUrl",
      ) ||
      (supplied.path !== undefined && typeof supplied.path !== "string") ||
      (supplied.externalUrl !== undefined &&
        typeof supplied.externalUrl !== "string"))
  )
    throw new ApplicationError(
      "CAP_APP_MOUNT_INVALID",
      "Invalid documentation deployment settings.",
    );
  const path = supplied?.path ?? "/docs";
  if (
    typeof path !== "string" ||
    path === "/" ||
    !path.startsWith("/") ||
    path.startsWith("//") ||
    path.endsWith("/") ||
    /[?#%\\\0{}\u0000-\u0020\u007f<>"]/.test(path) ||
    path
      .split("/")
      .slice(1)
      .some((segment) => !segment || segment === "." || segment === "..")
  )
    throw new ApplicationError(
      "CAP_APP_MOUNT_INVALID",
      "Invalid documentation mount path.",
    );
  const externalUrl =
    supplied?.externalUrl ??
    (applicationUrl ? `${applicationUrl}${path}` : undefined);
  if (externalUrl === undefined) return Object.freeze({ path });
  let url: URL;
  try {
    url = new URL(externalUrl);
  } catch {
    throw new ApplicationError(
      "CAP_APP_MOUNT_INVALID",
      "Invalid documentation external URL.",
    );
  }
  if (
    /[?#]/.test(externalUrl) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.protocol !== "https:" &&
      !(
        allowHttpLoopback &&
        url.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
      ))
  )
    throw new ApplicationError(
      "CAP_APP_MOUNT_INVALID",
      "Invalid documentation external URL.",
    );
  return Object.freeze({ path, externalUrl: url.href.replace(/\/$/, "") });
}

export const documentationTransportFacts = Object.freeze({
  httpErrorStatus: HTTP_ERROR_STATUS,
  cliExitCodes: CLI_EXIT_CODES,
  mcpProtocolErrors: {
    "parse error": -32700,
    "unknown method": -32601,
    "malformed or unknown tool": -32602,
  },
});

/** Match browser pathname serialization; keep the reservation token structural. */
export function documentationWirePath(path: string): string {
  const template = path.endsWith("/{path+}") ? "/{path+}" : "";
  const literal = template ? path.slice(0, -template.length) : path;
  return `${new URL(literal, "https://documentation.invalid").pathname}${template}`;
}

const sensitiveNames = (document: CompilationSuccess["document"]): string[] =>
  document.capabilities.flatMap((cap) =>
    (cap.requirements.secrets as unknown as { name: string }[]).map(
      (secret) => secret.name,
    ),
  );
const fail = (): never => {
  throw new ApplicationError(
    "CAP_APP_DEPLOYMENT_INVALID",
    "Invalid verified documentation bundle.",
  );
};
const sha = (bytes: Uint8Array): string =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const shellQuote = (value: string): string =>
  `'${value.replaceAll("'", "'\\''")}'`;
const safe = (path: string): boolean =>
  /^[A-Za-z0-9_.\-/]+$/.test(path) &&
  path.split("/").every((part) => part !== "" && part !== "." && part !== "..");
/** Parse only canonical regular USTAR members in memory; never extract to disk. */
export function readDocumentationArchive(
  bytes: Uint8Array,
  irHash: string,
  profile: "private" | "public",
): DocumentationBundle {
  if (
    bytes.length % 512 ||
    bytes.length < 1024 ||
    bytes.length > 32 * 1024 * 1024
  )
    fail();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const entries: { path: string; text: string }[] = [];
  const seen = new Set<string>();
  let cursor = 0,
    terminated = false;
  const field = (header: Uint8Array, start: number, length: number): string => {
    const data = header.slice(start, start + length);
    const end = data.indexOf(0);
    if (end !== -1 && data.slice(end).some((byte) => byte !== 0)) fail();
    return decoder.decode(end === -1 ? data : data.slice(0, end));
  };
  const octal = (header: Uint8Array, start: number, length: number): number => {
    const value = field(header, start, length).trim();
    if (!/^[0-7]+$/.test(value)) fail();
    const result = parseInt(value, 8);
    if (!Number.isSafeInteger(result)) fail();
    return result;
  };
  try {
    while (cursor < bytes.length) {
      const header = bytes.slice(cursor, cursor + 512);
      if (header.every((byte) => byte === 0)) {
        if (
          bytes.length - cursor < 1024 ||
          bytes.slice(cursor).some((byte) => byte !== 0)
        )
          fail();
        terminated = true;
        break;
      }
      const checksum = header.reduce(
        (sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte),
        0,
      );
      if (
        octal(header, 148, 8) !== checksum ||
        field(header, 257, 6) !== "ustar" ||
        field(header, 263, 2) !== "00" ||
        field(header, 156, 1) !== "0" ||
        field(header, 157, 100) !== "" ||
        octal(header, 100, 8) !== 0o644 ||
        octal(header, 108, 8) !== 0 ||
        octal(header, 116, 8) !== 0 ||
        octal(header, 136, 12) !== 0
      )
        fail();
      const name = field(header, 0, 100),
        prefix = field(header, 345, 155);
      const path = prefix ? `${prefix}/${name}` : name;
      const size = octal(header, 124, 12);
      if (
        !safe(path) ||
        seen.has(path) ||
        (entries.length && path <= entries[entries.length - 1]!.path)
      )
        fail();
      cursor += 512;
      const next = cursor + Math.ceil(size / 512) * 512;
      if (
        next > bytes.length ||
        bytes.slice(cursor + size, next).some((byte) => byte !== 0)
      )
        fail();
      entries.push({
        path,
        text: decoder.decode(bytes.slice(cursor, cursor + size)),
      });
      seen.add(path);
      cursor = next;
    }
    if (!terminated) fail();
    const manifest = JSON.parse(
      entries.find((entry) => entry.path === "manifest.json")?.text ?? "null",
    ) as Record<string, unknown>;
    if (
      !manifest ||
      manifest.irHash !== irHash ||
      manifest.profile !== profile ||
      manifest.generatorVersion !== DOCS_SCHEMA_GENERATOR_VERSION ||
      manifest.irVersion !== "0.1" ||
      !Array.isArray(manifest.capabilities)
    )
      fail();
    const references = (value: unknown): void => {
      if (typeof value === "string") {
        if (!seen.has(value)) fail();
      } else if (value && typeof value === "object")
        for (const part of Object.values(value)) references(part);
      else fail();
    };
    for (const item of manifest.capabilities as Record<string, unknown>[]) {
      if (typeof item.id !== "string" || typeof item.version !== "string")
        fail();
      if (item.page !== undefined) references(item.page);
      references(item.schemas);
    }
    for (const entry of entries) {
      if (entry.path === "manifest.json") continue;
      if (entry.path.endsWith(".json")) {
        const value = JSON.parse(entry.text) as Record<string, unknown>;
        const provenance =
          entry.path === "fixtures/examples.json"
            ? value
            : (value["x-capaxle"] as Record<string, unknown>);
        if (
          !provenance ||
          provenance.irHash !== irHash ||
          provenance.generatorVersion !== DOCS_SCHEMA_GENERATOR_VERSION
        )
          fail();
      } else if (
        !entry.path.endsWith(".md") ||
        !entry.text.includes(irHash) ||
        !entry.text.includes(DOCS_SCHEMA_GENERATOR_VERSION)
      )
        fail();
    }
    const bundle = { manifest: manifest as JsonValue, entries };
    validateDocumentationBundle(bundle);
    return Object.freeze({
      manifest: bundle.manifest,
      entries: Object.freeze(entries.map((entry) => Object.freeze(entry))),
    });
  } catch {
    return fail();
  }
}

const DOCS_STYLES_ID = "capaxle.app.docs-styles";
const DOCS_STYLES_VERSION = "0.1.0-alpha.3";
const DOCS_STYLES_TARGET = "capaxle:documentation-styles@0.1";

/** Snapshot installed package bytes once per candidate; serving never resolves files. */
function createDocumentationStylesProducer(): CompilerArtifactProducer {
  try {
    const stylesheetUrl = new URL(
      import.meta.resolve("@capaxle/docs-styles/docs.css"),
    );
    const identity = JSON.parse(
      readFileSync(new URL("./package.json", stylesheetUrl), "utf8"),
    ) as { name?: unknown; version?: unknown };
    if (
      identity.name !== "@capaxle/docs-styles" ||
      identity.version !== DOCS_STYLES_VERSION
    )
      return fail();
    const bytes = new Uint8Array(readFileSync(stylesheetUrl));
    validateDocumentationStylesheet(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
    return {
      id: DOCS_STYLES_ID,
      version: DOCS_STYLES_VERSION,
      staticInputs: {
        package: identity.name,
        version: identity.version,
        sha256: sha(bytes),
      },
      diagnosticCodes: [],
      artifacts: [
        {
          id: DOCS_STYLES_ID,
          path: "docs/docs.css",
          mediaType: "text/css; charset=utf-8",
          target: DOCS_STYLES_TARGET,
          dependencies: ["document:capability-ir"],
          produce: () => ({ ok: true, bytes, diagnostics: [] }),
        },
      ],
    };
  } catch {
    return fail();
  }
}

export function verifyDocumentationStyles(
  artifacts: readonly CompiledArtifact[],
): string {
  const selected = artifacts.filter(
    (artifact) => artifact.id === DOCS_STYLES_ID,
  );
  const item = selected[0];
  if (
    selected.length !== 1 ||
    !item ||
    item.path !== "docs/docs.css" ||
    item.producer?.id !== DOCS_STYLES_ID ||
    item.producer.version !== DOCS_STYLES_VERSION ||
    item.target !== DOCS_STYLES_TARGET ||
    item.mediaType !== "text/css; charset=utf-8" ||
    sha(item.bytes) !== item.sha256
  )
    fail();
  try {
    const stylesheet = new TextDecoder("utf-8", { fatal: true }).decode(
      item!.bytes,
    );
    validateDocumentationStylesheet(stylesheet);
    return stylesheet;
  } catch {
    return fail();
  }
}

function createDocumentationArchiveProducers(
  context: Pick<DeploymentContext, "surfaces" | "documentation">,
): readonly CompilerArtifactProducer[] {
  return (["private", "public"] as const).map((profile) => ({
    id:
      profile === "private"
        ? "capaxle.docs-schema-bundle"
        : "capaxle.app.public-docs",
    version: DOCS_SCHEMA_GENERATOR_VERSION,
    staticInputs: {
      profile,
      surfaces: context.surfaces,
      documentation: (context.documentation ?? null) as unknown as JsonValue,
      transportFacts: documentationTransportFacts,
    },
    diagnosticCodes: [
      "CAP_BUILD_CONTEXT_INVALID",
      "CAP_DOCS_EXAMPLE_INVALID",
      "CAP_DOCS_SCHEMA_INVALID",
    ].map((code) => ({ code: code as `CAP_${string}`, severities: ["error"] })),
    artifacts: [
      {
        id:
          profile === "private"
            ? "capaxle.docs-schema-bundle"
            : "capaxle.app.public-docs",
        path:
          profile === "private"
            ? "docs/capability-bundle.tar"
            : "docs/public-bundle.tar",
        mediaType: "application/x-tar",
        target: DOCS_SCHEMA_TARGET,
        dependencies: ["document:capability-ir"],
        produce: ({ dependencyBytes, buildContext }) => {
          const document = JSON.parse(
            new TextDecoder().decode(
              dependencyBytes.get("document:capability-ir"),
            ),
          ) as CompilationSuccess["document"];
          const irHash = buildContext.irHash;
          const result = generateDocsSchemaArchive(document, {
            irHash,
            profile,
            ...(buildContext.cliBinary
              ? { cliBinary: buildContext.cliBinary }
              : {}),
            ...(profile === "public"
              ? {
                  enabledInterfaces: ["http", "mcp", "cli"].filter(
                    (kind) => context.surfaces[kind as "http" | "mcp" | "cli"],
                  ) as ("http" | "mcp" | "cli")[],
                  sensitiveRequirementNames: sensitiveNames(document),
                }
              : {}),
          });
          return result.ok
            ? { ok: true, bytes: result.bytes, diagnostics: [] }
            : {
                ok: false,
                diagnostics: result.diagnostics.map((diagnostic) => ({
                  ...diagnostic,
                  target: DOCS_SCHEMA_TARGET,
                })),
              };
        },
      },
      ...(profile === "public"
        ? [
            {
              id: "capaxle.app.docs-context",
              path: "docs/browser-context.json",
              mediaType: "application/json",
              target: "capaxle:documentation-context@0.1",
              dependencies: ["document:capability-ir" as const],
              produce: ({
                buildContext,
              }: Parameters<
                CompilerArtifactProducer["artifacts"][number]["produce"]
              >[0]) => ({
                ok: true as const,
                bytes: new TextEncoder().encode(
                  jcs({
                    irHash: buildContext.irHash,
                    ...(buildContext.cliBinary
                      ? { cliBinary: buildContext.cliBinary }
                      : {}),
                  }),
                ),
                diagnostics: [],
              }),
            },
            {
              id: "capaxle.app.browser-model",
              path: "docs/browser-model.json",
              mediaType: "application/json",
              target: "capaxle:documentation-model@0.1",
              dependencies: ["document:capability-ir" as const],
              produce: ({
                dependencyBytes,
                buildContext,
              }: Parameters<
                CompilerArtifactProducer["artifacts"][number]["produce"]
              >[0]) => {
                const document = JSON.parse(
                  new TextDecoder().decode(
                    dependencyBytes.get("document:capability-ir"),
                  ),
                ) as CompilationSuccess["document"];
                const result = projectDocumentationModel(document, {
                  irHash: buildContext.irHash,
                  profile: "public",
                  enabledInterfaces: ["http", "cli", "mcp"].filter(
                    (kind) => context.surfaces[kind as "http" | "cli" | "mcp"],
                  ) as ("http" | "cli" | "mcp")[],
                  ...(buildContext.cliBinary
                    ? { cliBinary: buildContext.cliBinary }
                    : {}),
                  sensitiveRequirementNames: sensitiveNames(document),
                });
                return result.ok
                  ? {
                      ok: true as const,
                      bytes: new TextEncoder().encode(
                        jcs(result.model as unknown as JsonValue),
                      ),
                      diagnostics: [],
                    }
                  : {
                      ok: false as const,
                      diagnostics: result.diagnostics.map((diagnostic) => ({
                        ...diagnostic,
                        target: DOCS_SCHEMA_TARGET,
                      })),
                    };
              },
            },
          ]
        : []),
    ],
  }));
}

export function createDocumentationProducers(
  context: Pick<DeploymentContext, "surfaces" | "documentation">,
): readonly CompilerArtifactProducer[] {
  return [
    ...createDocumentationArchiveProducers(context),
    createDocumentationStylesProducer(),
  ];
}

export function documentationCliBinary(
  artifacts: readonly CompiledArtifact[],
  irHash: string,
): string | undefined {
  const selected = artifacts.filter(
    (artifact) => artifact.id === "capaxle.app.docs-context",
  );
  const item = selected[0];
  if (
    selected.length !== 1 ||
    !item ||
    item.path !== "docs/browser-context.json" ||
    item.producer?.id !== "capaxle.app.public-docs" ||
    item.producer.version !== DOCS_SCHEMA_GENERATOR_VERSION ||
    item.target !== "capaxle:documentation-context@0.1" ||
    item.mediaType !== "application/json" ||
    sha(item.bytes) !== item.sha256
  )
    fail();
  let context: { irHash?: unknown; cliBinary?: unknown };
  try {
    context = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(item!.bytes),
    );
  } catch {
    return fail();
  }
  if (
    !context ||
    typeof context !== "object" ||
    Array.isArray(context) ||
    Object.keys(context).some(
      (key) => key !== "irHash" && key !== "cliBinary",
    ) ||
    context.irHash !== irHash ||
    (context.cliBinary !== undefined &&
      (typeof context.cliBinary !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(context.cliBinary)))
  )
    fail();
  return context.cliBinary as string | undefined;
}

export function verifyDocumentationArtifacts(
  artifacts: readonly CompiledArtifact[],
  irHash: string,
  service?: { readonly name: string; readonly version: string },
): DocumentationBundle {
  documentationCliBinary(artifacts, irHash);
  let publicBundle: DocumentationBundle | undefined;
  for (const profile of ["private", "public"] as const) {
    const id =
      profile === "private"
        ? "capaxle.docs-schema-bundle"
        : "capaxle.app.public-docs";
    const selected = artifacts.filter((artifact) => artifact.id === id);
    const item = selected[0];
    if (
      selected.length !== 1 ||
      !item ||
      item.path !==
        (profile === "private"
          ? "docs/capability-bundle.tar"
          : "docs/public-bundle.tar") ||
      !item.producer ||
      item.producer.id !== id ||
      item.producer.version !== DOCS_SCHEMA_GENERATOR_VERSION ||
      item.mediaType !== "application/x-tar" ||
      item.target !== DOCS_SCHEMA_TARGET ||
      sha(item.bytes) !== item.sha256
    )
      fail();
    const bundle = readDocumentationArchive(item!.bytes, irHash, profile);
    const identity = (
      bundle.manifest as { service: { name: string; version: string } }
    ).service;
    if (
      service &&
      (identity?.name !== service.name || identity?.version !== service.version)
    )
      fail();
    if (profile === "public") publicBundle = bundle;
  }
  return publicBundle!;
}

export function verifyDocumentationModel(
  artifacts: readonly CompiledArtifact[],
  irHash: string,
  bundle: DocumentationBundle,
  context: DeploymentContext,
): DocumentationModel {
  const selected = artifacts.filter(
    (artifact) => artifact.id === "capaxle.app.browser-model",
  );
  const item = selected[0];
  if (
    selected.length !== 1 ||
    !item ||
    item.path !== "docs/browser-model.json" ||
    item.producer?.id !== "capaxle.app.public-docs" ||
    item.producer.version !== DOCS_SCHEMA_GENERATOR_VERSION ||
    item.target !== "capaxle:documentation-model@0.1" ||
    item.mediaType !== "application/json" ||
    sha(item.bytes) !== item.sha256
  )
    fail();
  let model: DocumentationModel;
  try {
    model = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(item!.bytes),
    );
  } catch {
    return fail();
  }
  if (!model || model.irHash !== irHash || model.profile !== "public") fail();
  try {
    renderDocumentationPage({
      bundle,
      model,
      pageId: "index",
      connection: documentationConnection(
        context,
        context.documentation?.path ?? "/docs",
      ),
    });
  } catch {
    return fail();
  }
  return Object.freeze(model);
}

export function documentationConnection(
  context: DeploymentContext,
  path: string,
  document?: CompilationSuccess["document"],
  cliBinary?: string,
): DocumentationConnection {
  const mount = (local: string): string =>
    context.basePath === "/" ? local : `${context.basePath}${local}`;
  const absolute = (local: string): string =>
    context.externalUrl ? `${context.externalUrl}${local}` : mount(local);
  const remote = (local: string): string =>
    `${context.externalUrl ?? "<APPLICATION_URL>"}${local}`;
  const surfaces: DocumentationConnection["surfaces"][number][] = [];
  const auth =
    "Provision application credentials through your deployment. Replace credential placeholders; never paste secrets into saved examples." +
    (context.externalUrl
      ? ""
      : ` Configure externalUrl or replace <APPLICATION_URL> with the HTTPS application URL including its mounted path (${context.basePath}); do not use a relative URL in remote client configuration.`);
  if (context.surfaces.http) {
    const example = document?.capabilities.find(
      (capability) =>
        capability.interfaces.http.enabled &&
        capability.access.exposure.http === "public" &&
        capability.interfaces.sdk.enabled &&
        capability.effects.impact === "read" &&
        capability.effects.confirmation === "none" &&
        capability.examples.some(
          (value) =>
            typeof value === "object" &&
            value !== null &&
            !Array.isArray(value) &&
            Object.hasOwn(value, "input") &&
            !Object.hasOwn(value, "error"),
        ),
    );
    const sdkPath =
      (example?.interfaces.sdk as unknown as { path?: string[] })?.path ?? [];
    const suppliedExample = example?.examples.find(
      (value) =>
        typeof value === "object" &&
        value !== null &&
        !Array.isArray(value) &&
        Object.hasOwn(value, "input") &&
        !Object.hasOwn(value, "error"),
    ) as { input: JsonValue } | undefined;
    const sdkUse =
      example && suppliedExample && sdkPath.length
        ? `\nconst value = await client${sdkPath.map((part) => `[${JSON.stringify(part)}]`).join("")}(${JSON.stringify(suppliedExample.input)});`
        : "\n// No public read example is available. Supply canonical inputs and required confirmation controls before invoking other capabilities.";
    const sdkConfig =
      context.basePath === "/"
        ? `baseUrl: ${JSON.stringify(context.externalUrl ?? "<APPLICATION_URL>")}`
        : `baseUrl: ${JSON.stringify(context.externalUrl ? new URL(context.externalUrl).origin : "<APPLICATION_ORIGIN>")},\n  fetch: (input, init) => {\n    const url = new URL(input instanceof Request ? input.url : String(input));\n    url.pathname = ${JSON.stringify(context.basePath)} + url.pathname;\n    return fetch(url, init);\n  }`;
    surfaces.push({
      id: "api",
      label: "HTTP API",
      url: absolute(context.discovery!.http.collection),
      guidance: auth,
      snippets: [
        {
          id: "api-discovery",
          label: "List capabilities",
          language: "sh",
          text: `curl --header 'Authorization: Bearer <APPLICATION_TOKEN>' ${shellQuote(remote(context.discovery!.http.collection))}`,
        },
      ],
    });
    surfaces.push({
      id: "sdk",
      label: "TypeScript HTTP SDK",
      guidance:
        "Emit capaxle-sdk.ts with the developer CLI capaxle build, then import the generated file into your HTTP consumer.",
      snippets: [
        {
          id: "sdk-use",
          label: "Import the generated SDK",
          language: "typescript",
          text: `import { createCapaxleClient } from './capaxle-sdk.js';\nconst client = createCapaxleClient({ ${sdkConfig},\n  headers: { Authorization: "Bearer <APPLICATION_TOKEN>" }\n});${sdkUse}`,
        },
      ],
    });
  }
  if (context.surfaces.mcp) {
    const url = remote(context.discovery!.mcp.endpoint);
    surfaces.push({
      id: "mcp",
      label: "MCP",
      url: absolute(context.discovery!.mcp.endpoint),
      protocols: MCP_SUPPORTED_VERSIONS,
      guidance: `${auth} The client supplies protocol headers through its HTTP transport.`,
      snippets: [
        {
          id: "mcp-codex",
          label: "Codex config.toml",
          language: "toml",
          text: `[mcp_servers.capaxle]\nurl = ${JSON.stringify(url)}\nbearer_token_env_var = "CAPAXLE_MCP_BEARER"\nstartup_timeout_sec = 20\ntool_timeout_sec = 45`,
        },
        {
          id: "mcp-json",
          label: "HTTP MCP server configuration",
          language: "json",
          text: JSON.stringify(
            {
              mcpServers: {
                capaxle: {
                  type: "http",
                  url,
                  headers: { Authorization: "Bearer <APPLICATION_TOKEN>" },
                },
              },
            },
            null,
            2,
          ),
        },
      ],
    });
  }
  if (context.surfaces.cli) {
    const url = context.externalUrl ?? "<APPLICATION_URL>";
    const loopback = context.externalUrl?.startsWith("http:")
      ? " --allow-http-loopback"
      : "";
    const collection = context.cliEndpoints!.collection;
    const mcpDoctorOptions =
      context.surfaces.mcp && context.discovery
        ? ` --mcp-path ${shellQuote(context.discovery.mcp.endpoint)} --mcp-protocol ${shellQuote(MCP_SUPPORTED_VERSIONS[0]!)}`
        : "";
    surfaces.push({
      id: "cli",
      label: "Remote CLI",
      url: absolute(collection),
      protocols: ["0.1"],
      guidance: `${auth} Install the approved package release. This source version is verified from a packed tarball; registry publication follows release approval. APPLICATION_TOKEN names an environment variable and never embeds token bytes.`,
      snippets: [
        {
          id: "cli-install",
          label: "Install the client",
          language: "sh",
          text: "npm install @capaxle/client@0.1.0-alpha.3",
        },
        {
          id: "cli-list",
          label: "List remote capabilities",
          language: "sh",
          text: `capaxle-client --url ${shellQuote(url)}${loopback} --collection-path ${shellQuote(collection)} --credential-env APPLICATION_TOKEN -- capabilities list --json --no-input`,
        },
        {
          id: "cli-doctor",
          label: "Check this connection",
          language: "sh",
          text: `capaxle-client --url ${shellQuote(url)}${loopback} --collection-path ${shellQuote(collection)} --credential-env APPLICATION_TOKEN doctor --json --no-input${mcpDoctorOptions}`,
        },
      ],
    });
  }
  return {
    docsPath: mount(path),
    ...(context.documentation?.externalUrl
      ? { docsUrl: context.documentation.externalUrl }
      : {}),
    serviceId: context.serviceId,
    applicationBasePath: context.basePath,
    ...(context.externalUrl ? { applicationUrl: context.externalUrl } : {}),
    ...(cliBinary ? { cliBinary } : {}),
    surfaces,
    transportFacts: documentationTransportFacts,
  };
}

export function createDocumentationHandler(
  options: DocumentationOptions,
  document: CompilationSuccess["document"],
  irHash: string,
  publicBundle: DocumentationBundle,
  context: DeploymentContext,
  ingress: AdapterIngress,
  cliBinary: string | undefined,
  publicModel: DocumentationModel,
  stylesheet: string,
) {
  const path = context.documentation?.path ?? "/docs";
  const connection = documentationConnection(
    context,
    path,
    document,
    cliBinary,
  );
  renderDocumentationPage({
    bundle: publicBundle,
    model: publicModel,
    stylesheet,
    pageId: "connection",
    connection,
  });
  const root = documentationWirePath(connection.docsPath);
  return async (
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<boolean> => {
    const raw = (req.url ?? "/").split("?")[0]!;
    if (raw !== root && !raw.startsWith(`${root}/`)) return false;
    res.setHeader("cache-control", "no-store");
    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader(
      "content-security-policy",
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    );
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.statusCode = 405;
      res.setHeader("allow", "GET, HEAD");
      res.end();
      return true;
    }
    let bundle = publicBundle;
    let model = publicModel;
    try {
      const disclosure = await ingress.disclose(
        req.headers.authorization === undefined
          ? undefined
          : { credentials: req.headers.authorization },
      );
      if (disclosure.visibility === "authenticated") {
        const chosen = await options.disclosureSelector?.(disclosure);
        if (
          options.disclosureSelector !== undefined &&
          (!Array.isArray(chosen) ||
            new Set(chosen!).size !== chosen!.length ||
            chosen!.some(
              (id) => !document.capabilities.some((cap) => cap.id === id),
            ))
        )
          throw new Error("Invalid disclosure selection");
        const visibleInterfaces = document.capabilities.flatMap((cap) =>
          ["http", "mcp", "cli"]
            .filter(
              (kind) =>
                context.surfaces[kind as "http" | "mcp" | "cli"] &&
                cap.interfaces[kind as "http" | "mcp" | "cli"].enabled &&
                (cap.access.exposure[kind as "http" | "mcp" | "cli"] ===
                  "public" ||
                  (cap.access.exposure[kind as "http" | "mcp" | "cli"] ===
                    "authenticated" &&
                    (chosen === undefined || chosen.includes(cap.id)))),
            )
            .map((kind) => ({
              id: cap.id,
              version: cap.version,
              interface: kind as "http" | "mcp" | "cli",
            })),
        );
        const result = projectDocumentationView(document, {
          irHash,
          visibleInterfaces,
          ...(cliBinary ? { cliBinary } : {}),
          sensitiveRequirementNames: sensitiveNames(document),
        });
        if (!result.ok) throw new Error("Disclosure generation failed");
        bundle = result.bundle;
        const projectedModel = projectDocumentationModel(document, {
          irHash,
          profile: "live",
          visibleInterfaces,
          ...(cliBinary ? { cliBinary } : {}),
          sensitiveRequirementNames: sensitiveNames(document),
        });
        if (!projectedModel.ok)
          throw new Error("Disclosure model generation failed");
        model = projectedModel.model;
      }
    } catch (error) {
      const denied =
        error instanceof Error &&
        "code" in error &&
        error.code === "CAP_UNAUTHENTICATED";
      res.statusCode = denied ? 401 : 503;
      res.setHeader("content-type", "application/json");
      res.end(
        JSON.stringify({
          code: denied ? "CAP_UNAUTHENTICATED" : "CAP_DEPENDENCY_UNAVAILABLE",
        }),
      );
      return true;
    }
    const pageId =
      raw === root || raw === `${root}/` ? "index" : raw.slice(root.length + 1);
    if (pageId.startsWith("schemas/")) {
      const entry = bundle.entries.find((item) => item.path === pageId);
      if (!entry) {
        res.statusCode = 404;
        res.end("Not Found");
        return true;
      }
      res.setHeader("content-type", "application/schema+json; charset=utf-8");
      res.end(req.method === "HEAD" ? undefined : entry.text);
      return true;
    }
    try {
      const { html } = renderDocumentationPage({
        bundle,
        model,
        stylesheet,
        pageId,
        connection,
      });
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.end(req.method === "HEAD" ? undefined : html);
    } catch {
      res.statusCode = 404;
      res.end("Not Found");
    }
    return true;
  };
}

export function documentationReservations(
  path = "/docs",
): readonly Readonly<{ method: string; path: string }>[] {
  return Object.freeze(
    ["GET", "HEAD"]
      .flatMap((method) => [
        { method, path },
        { method, path: `${path}/{path+}` },
      ])
      .map((route) => Object.freeze(route)),
  );
}
