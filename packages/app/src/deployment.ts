import {
  routeReservations,
  resolvedBasePath,
  resolvedExternalUrl,
} from "./mounts.js";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  writeFile,
} from "node:fs/promises";
import {
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";
import {
  compileProject,
  emitCompilerArtifacts,
  type CompilationSuccess,
  type CompiledArtifact,
  type CompilerArtifactProducer,
  type DiscoveryContext,
} from "@capaxle/compiler";
import { loadDeploymentBindings } from "@capaxle/compiler/deployment";
import { type SchemaProvider } from "@capaxle/core";
import { zodSchemaProvider } from "@capaxle/schema-zod";
import { capabilitySemanticHash, jcs } from "@capaxle/ir";
import { createAgentManifestArtifactProducer } from "@capaxle/adapter-mcp";
import {
  createRemoteCliRegistration,
  getRemoteCliRegistrationEndpoints,
  isRemoteCliRegistration,
} from "@capaxle/adapter-cli/remote";
import { ApplicationError } from "./errors.js";
import {
  createDocumentationProducers,
  documentationReservations,
  verifyDocumentationArtifacts,
  verifyDocumentationModel,
  verifyDocumentationStyles,
  resolveDocumentationContext,
  type DocumentationDeploymentContext,
} from "./documentation.js";

export interface DeploymentContext {
  readonly serviceId: string;
  readonly basePath: string;
  readonly externalUrl?: string;
  readonly surfaces: Readonly<{
    http: boolean;
    mcp: boolean;
    cli: boolean;
    docs: boolean;
  }>;
  readonly transport?: DeploymentTransport;
  readonly reservations?: DeploymentReservations;
  readonly cliEndpoints?: CliEndpoints;
  readonly discovery?: DiscoveryContext;
  readonly documentation?: DocumentationDeploymentContext;
}

export interface DeploymentReservations {
  readonly cli?: readonly Readonly<{ method: string; path: string }>[];
  readonly docs?: readonly Readonly<{ method: string; path: string }>[];
}

export interface CliEndpoints {
  readonly collection: string;
  readonly detailTemplate: string;
  readonly schemaTemplate: string;
  readonly invoke: string;
}

export const defaultCliEndpoints: CliEndpoints = Object.freeze({
  collection: "/cli",
  detailTemplate: "/cli/capabilities/{id}",
  schemaTemplate: "/cli/capabilities/{id}/schema",
  invoke: "/cli/invoke",
});

export function cliReservations(
  endpoints: CliEndpoints,
): readonly Readonly<{ method: string; path: string }>[] {
  return Object.freeze([
    Object.freeze({ method: "GET", path: endpoints.collection }),
    Object.freeze({ method: "GET", path: endpoints.detailTemplate }),
    Object.freeze({ method: "GET", path: endpoints.schemaTemplate }),
    Object.freeze({ method: "POST", path: endpoints.invoke }),
  ]);
}

export function resolveDeploymentCliEndpoints(
  surfaces: DeploymentContext["surfaces"],
  supplied?: CliEndpoints,
): CliEndpoints | undefined {
  if (!surfaces.cli) {
    if (supplied !== undefined)
      invalid("Disabled CLI surface has endpoint roles.");
    return undefined;
  }
  const value = supplied ?? defaultCliEndpoints;
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join("\0") !==
      ["collection", "detailTemplate", "schemaTemplate", "invoke"]
        .sort()
        .join("\0")
  )
    invalid("Invalid CLI endpoint role map.");
  const paths = Object.values(value);
  if (
    paths.some(
      (path) =>
        typeof path !== "string" ||
        !path.startsWith("/") ||
        path.startsWith("//") ||
        (path !== "/" && path.endsWith("/")) ||
        /[?#\\\0%]/u.test(path) ||
        path
          .split("/")
          .slice(1)
          .some((part) => part === "" || part === "." || part === ".."),
    )
  )
    invalid("Invalid CLI endpoint path.");
  const placeholders = (path: string): readonly string[] =>
    path.split("/").filter((part) => /[{}]/u.test(part));
  if (
    placeholders(value.collection).length !== 0 ||
    placeholders(value.invoke).length !== 0 ||
    JSON.stringify(placeholders(value.detailTemplate)) !== '["{id}"]' ||
    JSON.stringify(placeholders(value.schemaTemplate)) !== '["{id}"]'
  )
    invalid("Invalid CLI endpoint template.");
  return Object.freeze({ ...value });
}

function remoteCliLocator(
  context: DeploymentContext,
): Readonly<{ endpoints: CliEndpoints; externalUrl?: string }> | undefined {
  if (!context.surfaces.cli) return undefined;
  const roles = resolveDeploymentCliEndpoints(
    context.surfaces,
    context.cliEndpoints,
  )!;
  const expected = resolveDeploymentReservations(
    { http: false, mcp: false, cli: true, docs: false },
    { cli: cliReservations(roles) },
    roles,
  ).cli;
  if (
    jcs(
      context.reservations?.cli as unknown as import("@capaxle/ir").JsonValue,
    ) !== jcs(expected as unknown as import("@capaxle/ir").JsonValue)
  )
    throw new ApplicationError(
      "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
      "Remote CLI route reservations differ from endpoint roles.",
    );
  const mount = (path: string): string =>
    context.basePath === "/" ? path : `${context.basePath}${path}`;
  return Object.freeze({
    endpoints: Object.freeze({
      collection: mount(roles.collection),
      detailTemplate: mount(roles.detailTemplate),
      schemaTemplate: mount(roles.schemaTemplate),
      invoke: mount(roles.invoke),
    }),
    ...(context.externalUrl === undefined
      ? {}
      : { externalUrl: context.externalUrl }),
  });
}

export function resolveDeploymentReservations(
  surfaces: DeploymentContext["surfaces"],
  supplied?: DeploymentReservations,
  cliEndpoints?: CliEndpoints,
  documentationPath = "/docs",
): DeploymentReservations {
  if (
    supplied &&
    Object.keys(supplied).some((key) => key !== "cli" && key !== "docs")
  )
    invalid("Unknown surface route reservation.");
  const roles = resolveDeploymentCliEndpoints(surfaces, cliEndpoints);
  const result: {
    cli?: readonly Readonly<{ method: string; path: string }>[];
    docs?: readonly Readonly<{ method: string; path: string }>[];
  } = {};
  for (const kind of ["cli", "docs"] as const) {
    const routes =
      supplied?.[kind] ??
      (kind === "cli" && surfaces.cli
        ? cliReservations(roles!)
        : kind === "docs" && surfaces.docs
          ? documentationReservations(documentationPath)
          : undefined);
    if (!surfaces[kind]) {
      if (routes?.length) invalid("Disabled surface has route reservations.");
      continue;
    }
    if (!Array.isArray(routes) || routes.length === 0)
      invalid("Enabled surface requires route reservations.");
    const copied = routes!.map((route) => {
      if (
        !route ||
        typeof route.method !== "string" ||
        !/^[A-Z]+$/.test(route.method) ||
        typeof route.path !== "string" ||
        !route.path.startsWith("/") ||
        (route.path !== "/" &&
          (route.path.startsWith("//") || route.path.endsWith("/"))) ||
        /[?#\\\0%]/.test(route.path) ||
        (route.path !== "/" &&
          route.path
            .split("/")
            .slice(1)
            .some((part) => part === "" || part === "." || part === ".."))
      )
        invalid("Invalid surface route reservation.");
      return Object.freeze({ method: route.method, path: route.path });
    });
    const compare = (a: string, b: string): number =>
      a < b ? -1 : a > b ? 1 : 0;
    copied.sort((a, b) =>
      a.method === b.method
        ? compare(a.path, b.path)
        : compare(a.method, b.method),
    );
    if (
      copied.some(
        (route, index) =>
          index > 0 &&
          route.method === copied[index - 1]!.method &&
          route.path === copied[index - 1]!.path,
      )
    )
      invalid("Duplicate surface route reservation.");
    result[kind] = Object.freeze(copied);
  }
  if (surfaces.cli) {
    const expected = [...cliReservations(roles!)].sort((a, b) =>
      a.method === b.method
        ? a.path < b.path
          ? -1
          : a.path > b.path
            ? 1
            : 0
        : a.method < b.method
          ? -1
          : 1,
    );
    if (JSON.stringify(result.cli) !== JSON.stringify(expected))
      throw new ApplicationError(
        "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
        "CLI reservations differ from endpoint roles.",
      );
  }
  return Object.freeze(result);
}

export interface DeploymentTransport {
  readonly cli?: Readonly<{
    requestBytes: number;
    responseBytes: number;
    allowPrivateDiscovery: boolean;
  }>;
  readonly http?: Readonly<{
    maxBodyBytes: number;
    requestTimeoutMs: number;
  }>;
  readonly mcp?: Readonly<{
    allowedHosts?: readonly string[];
    allowedOrigins: readonly string[];
    clientCanSendInvocationMetadata: boolean;
    requestBodyLimitBytes: number;
    responseBodyLimitBytes: number;
    maxSessions: number;
    maxActiveRequestsPerSession: number;
    sessionIdleTimeoutMs: number;
    sessionAbsoluteTimeoutMs: number;
  }>;
}

const transportDefaults = {
  cli: {
    requestBytes: 1_048_576,
    responseBytes: 8_388_608,
    allowPrivateDiscovery: false,
  },
  http: { maxBodyBytes: 1_048_576, requestTimeoutMs: 30_000 },
  mcp: {
    allowedOrigins: [] as readonly string[],
    clientCanSendInvocationMetadata: false,
    requestBodyLimitBytes: 1_048_576,
    responseBodyLimitBytes: 8_388_608,
    maxSessions: 1_024,
    maxActiveRequestsPerSession: 32,
    sessionIdleTimeoutMs: 600_000,
    sessionAbsoluteTimeoutMs: 3_600_000,
  },
};

export function resolveDeploymentTransport(
  surfaces: DeploymentContext["surfaces"],
  supplied?: DeploymentTransport,
): DeploymentTransport {
  if (
    supplied &&
    (Object.keys(supplied).some(
      (key) => key !== "http" && key !== "mcp" && key !== "cli",
    ) ||
      (supplied.cli &&
        Object.keys(supplied.cli).some(
          (key) =>
            ![
              "requestBytes",
              "responseBytes",
              "allowPrivateDiscovery",
            ].includes(key),
        )) ||
      (supplied.http &&
        Object.keys(supplied.http).some(
          (key) => !["maxBodyBytes", "requestTimeoutMs"].includes(key),
        )) ||
      (supplied.mcp &&
        Object.keys(supplied.mcp).some(
          (key) =>
            ![
              "allowedHosts",
              "allowedOrigins",
              "clientCanSendInvocationMetadata",
              "requestBodyLimitBytes",
              "responseBodyLimitBytes",
              "maxSessions",
              "maxActiveRequestsPerSession",
              "sessionIdleTimeoutMs",
              "sessionAbsoluteTimeoutMs",
            ].includes(key),
        )))
  )
    invalid("Unknown deployment transport setting.");
  if (
    supplied?.mcp?.allowedHosts !== undefined &&
    !Array.isArray(supplied.mcp.allowedHosts)
  )
    invalid("Deployment Host policy must be a fixed array.");
  if (
    (supplied?.http !== undefined && !surfaces.http) ||
    (supplied?.mcp !== undefined && !surfaces.mcp) ||
    (supplied?.cli !== undefined && !surfaces.cli)
  )
    invalid("Disabled surface has transport settings.");
  const http = surfaces.http
    ? { ...transportDefaults.http, ...supplied?.http }
    : undefined;
  const cli = surfaces.cli
    ? { ...transportDefaults.cli, ...supplied?.cli }
    : undefined;
  const mcp = surfaces.mcp
    ? {
        ...transportDefaults.mcp,
        ...supplied?.mcp,
        allowedOrigins: [...(supplied?.mcp?.allowedOrigins ?? [])],
        ...(supplied?.mcp?.allowedHosts === undefined
          ? {}
          : { allowedHosts: [...supplied.mcp.allowedHosts] }),
      }
    : undefined;
  const validNumber = (value: number, min: number, max: number): boolean =>
    Number.isSafeInteger(value) && value >= min && value <= max;
  if (
    (cli &&
      (!validNumber(cli.requestBytes, 1_024, 1_048_576) ||
        !validNumber(cli.responseBytes, 8_192, 8_388_608) ||
        typeof cli.allowPrivateDiscovery !== "boolean")) ||
    (http &&
      (!validNumber(http.maxBodyBytes, 1, Number.MAX_SAFE_INTEGER) ||
        !validNumber(http.requestTimeoutMs, 1, Number.MAX_SAFE_INTEGER))) ||
    (mcp &&
      (!validNumber(mcp.requestBodyLimitBytes, 1_024, 1_048_576) ||
        !validNumber(mcp.responseBodyLimitBytes, 8_192, 8_388_608) ||
        !validNumber(mcp.maxSessions, 1, 1_024) ||
        !validNumber(mcp.maxActiveRequestsPerSession, 1, 32) ||
        !validNumber(mcp.sessionIdleTimeoutMs, 1, 600_000) ||
        !validNumber(mcp.sessionAbsoluteTimeoutMs, 1, 3_600_000) ||
        typeof mcp.clientCanSendInvocationMetadata !== "boolean" ||
        !Array.isArray(mcp.allowedOrigins) ||
        mcp.allowedOrigins.some((value) => typeof value !== "string") ||
        (mcp.allowedHosts !== undefined &&
          (!Array.isArray(mcp.allowedHosts) ||
            mcp.allowedHosts.some((value) => typeof value !== "string")))))
  )
    invalid("Invalid deployment transport settings.");
  return Object.freeze({
    ...(cli ? { cli: Object.freeze(cli) } : {}),
    ...(http ? { http: Object.freeze(http) } : {}),
    ...(mcp
      ? {
          mcp: Object.freeze({
            ...mcp,
            allowedOrigins: Object.freeze([...mcp.allowedOrigins]),
            ...(mcp.allowedHosts
              ? { allowedHosts: Object.freeze([...mcp.allowedHosts]) }
              : {}),
          }),
        }
      : {}),
  });
}

export interface BuildDeploymentOptions {
  readonly projectRoot: string;
  readonly executableRoot: string;
  readonly outDir: string;
  readonly deploymentContext: DeploymentContext;
  readonly schemaProviders?: readonly SchemaProvider<unknown>[];
}

interface ManifestModule {
  readonly source: string;
  readonly path: string;
  readonly sha256: string;
}
interface DeploymentManifest {
  readonly deploymentVersion: "0.1";
  readonly service: Readonly<{
    serviceId: string;
    name: string;
    version: string;
  }>;
  readonly irVersion: "0.1";
  readonly irHash: string;
  readonly frameworkVersion: "0.1.0-alpha.3";
  readonly artifactGraphVersion: "0.2";
  readonly buildId: string;
  readonly sourceManifestHash: string;
  readonly deploymentContext: DeploymentContext;
  readonly artifactIndex: Readonly<{ path: string; sha256: string }>;
  readonly ir: Readonly<{ path: string; sha256: string }>;
  readonly loader: Readonly<{ path: string; sha256: string }>;
  readonly modules: readonly ManifestModule[];
}

export interface LoadedDeployment extends Pick<
  CompilationSuccess,
  "document" | "irHash" | "discovery" | "runtimeBindings" | "validators"
> {
  readonly deploymentContext: DeploymentContext;
  readonly artifacts?: CompilationSuccess["artifacts"];
}

export interface DeploymentExpectations {
  readonly serviceId: string;
  readonly basePath?: string;
  readonly externalUrl?: string;
  readonly surfaces: DeploymentContext["surfaces"];
  readonly transport?: Readonly<{
    cli?: Readonly<Record<string, unknown>>;
    http?: Readonly<Record<string, unknown>>;
    mcp?: Readonly<Record<string, unknown>>;
  }>;
  readonly reservations?: DeploymentReservations;
  readonly cliEndpoints?: CliEndpoints;
  readonly documentation?: Readonly<{ path?: string; externalUrl?: string }>;
  readonly adoptDocumentationReservations?: boolean;
}

const sha = (bytes: Uint8Array | string): string =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const invalid = (message: string): never => {
  throw new ApplicationError("CAP_APP_DEPLOYMENT_INVALID", message);
};
const own = (object: object, names: readonly string[]): boolean =>
  Object.keys(object).sort().join("\0") === [...names].sort().join("\0");
const safeRelative = (value: string): boolean =>
  typeof value === "string" &&
  value !== "" &&
  !isAbsolute(value) &&
  !value.includes("\\") &&
  value
    .split("/")
    .every((part) => part !== "" && part !== "." && part !== "..") &&
  !value.includes("\0") &&
  !value.includes("%") &&
  !value.startsWith("/");
const inside = (root: string, path: string): boolean =>
  path === root ||
  (!relative(root, path).startsWith("..") && !isAbsolute(relative(root, path)));

async function readVerified(
  root: string,
  name: string,
  expected?: string,
): Promise<Uint8Array> {
  if (!safeRelative(name)) invalid("Unsafe deployment path.");
  let cursor = root;
  const parts = name.split("/");
  for (let i = 0; i < parts.length - 1; i++) {
    cursor = join(cursor, parts[i]!);
    const info = await lstat(cursor).catch(() =>
      invalid("Deployment directory is missing."),
    );
    if (!info.isDirectory() || info.isSymbolicLink())
      invalid("Deployment path is not a directory.");
  }
  const path = join(root, name);
  const info = await lstat(path).catch(() =>
    invalid("Deployment file is missing."),
  );
  if (!info.isFile() || info.isSymbolicLink())
    invalid("Deployment path is not a regular file.");
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await file.stat();
    if (opened.dev !== info.dev || opened.ino !== info.ino || !opened.isFile())
      invalid("Deployment file changed during verification.");
    const bytes = new Uint8Array(await file.readFile());
    if (expected && sha(bytes) !== expected)
      invalid("Deployment file digest mismatch.");
    return bytes;
  } finally {
    await file.close();
  }
}

async function allEmittedFiles(root: string, prefix = ""): Promise<string[]> {
  const names: string[] = [];
  for (const name of await readdir(join(root, prefix))) {
    const relativePath = prefix ? `${prefix}/${name}` : name;
    const info = await lstat(join(root, relativePath));
    if (info.isSymbolicLink())
      invalid("Executable output contains a symbolic link.");
    if (info.isDirectory())
      names.push(...(await allEmittedFiles(root, relativePath)));
    else if (info.isFile()) names.push(relativePath);
    else invalid("Executable output contains an unsupported entry.");
  }
  return names.sort();
}

function emittedFor(source: string, files: readonly string[]): string {
  const extension = extname(source);
  const targetExtension =
    extension === ".mts" ? ".mjs" : extension === ".cts" ? ".cjs" : ".js";
  const stem = source.slice(0, -extension.length);
  const candidates = [
    `${stem}${targetExtension}`,
    `${stem.replace(/^src\//, "")}${targetExtension}`,
  ];
  const found = [...new Set(candidates)].filter((candidate) =>
    files.includes(candidate),
  );
  if (found.length !== 1)
    invalid("Emitted capability module mapping is missing or ambiguous.");
  return found[0]!;
}

async function supportedBuildProfile(root: string): Promise<string> {
  const file = join(root, "tsconfig.json");
  const bytes = await readFile(file).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return undefined;
    throw error;
  });
  if (!bytes) return `typescript@${ts.version}:no-tsconfig:esnext-es2022`;
  let config: unknown;
  try {
    config = JSON.parse(bytes.toString("utf8"));
  } catch {
    return invalid("Unsupported TypeScript build configuration.");
  }
  if (!config || typeof config !== "object" || Array.isArray(config))
    invalid("Unsupported TypeScript build configuration.");
  const record = config as Record<string, unknown>;
  if (
    Object.keys(record).some(
      (key) => !["compilerOptions", "include", "exclude"].includes(key),
    ) ||
    !record.compilerOptions ||
    typeof record.compilerOptions !== "object" ||
    Array.isArray(record.compilerOptions)
  )
    invalid("Unsupported TypeScript build configuration.");
  const options = record.compilerOptions as Record<string, unknown>;
  if (
    Object.keys(options).some(
      (key) =>
        ![
          "target",
          "module",
          "moduleResolution",
          "strict",
          "noEmit",
          "skipLibCheck",
          "types",
        ].includes(key),
    ) ||
    options.target !== "ES2022" ||
    !["ESNext", "NodeNext"].includes(options.module as string) ||
    (options.moduleResolution !== undefined &&
      !["Bundler", "NodeNext"].includes(options.moduleResolution as string)) ||
    (options.types !== undefined &&
      (!Array.isArray(options.types) || options.types.length !== 0))
  )
    invalid("Unsupported TypeScript build configuration.");
  return `typescript@${ts.version}:${sha(bytes)}`;
}

async function verifyExecutableCorrespondence(
  root: string,
  sources: readonly Readonly<{ file: string; sourceHash: string }>[],
  emitted: readonly string[],
  snapshot: ReadonlyMap<string, Uint8Array>,
): Promise<void> {
  const sourceHashes = new Map(
    sources.map((source) => [source.file, source.sourceHash]),
  );
  const expected = new Set<string>();
  const visited = new Set<string>();
  const visit = async (source: string): Promise<void> => {
    if (!safeRelative(source) || !/\.m?ts$/.test(source) || visited.has(source))
      invalid("Unsupported executable source mapping.");
    visited.add(source);
    const sourceBytes = await readVerified(root, source);
    if (
      sourceHashes.has(source) &&
      sha(sourceBytes) !== sourceHashes.get(source)
    )
      invalid("Executable source changed after compilation.");
    const text = Buffer.from(sourceBytes).toString("utf8");
    const module = emittedFor(source, emitted);
    const output = ts.transpileModule(text, {
      compilerOptions: {
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.ESNext,
      },
      fileName: source,
      reportDiagnostics: true,
    });
    if (
      output.diagnostics?.some(
        (item) => item.category === ts.DiagnosticCategory.Error,
      )
    )
      invalid("TypeScript executable source cannot be emitted.");
    if (
      Buffer.compare(
        Buffer.from(output.outputText),
        Buffer.from(
          snapshot.get(module) ?? invalid("Executable module is missing."),
        ),
      ) !== 0
    )
      invalid("Executable module bytes do not match current source.");
    expected.add(module);
    const parsed = ts.createSourceFile(
      module,
      output.outputText,
      ts.ScriptTarget.ES2022,
      true,
    );
    const relativeImports: string[] = [];
    const scan = (node: ts.Node): void => {
      if (
        (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
        node.moduleSpecifier &&
        ts.isStringLiteral(node.moduleSpecifier)
      )
        relativeImports.push(node.moduleSpecifier.text);
      if (ts.isCallExpression(node)) {
        if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
          const argument = node.arguments[0];
          if (
            node.arguments.length !== 1 ||
            !argument ||
            !ts.isStringLiteral(argument)
          )
            invalid("Dynamic executable import cannot be verified.");
          relativeImports.push((argument as ts.StringLiteral).text);
        } else if (
          ts.isIdentifier(node.expression) &&
          node.expression.text === "require"
        )
          invalid("CommonJS executable imports are unsupported.");
      }
      ts.forEachChild(node, scan);
    };
    scan(parsed);
    for (const specifier of relativeImports) {
      if (!specifier.startsWith(".")) continue;
      const target = resolve(dirname(join(root, source)), specifier);
      if (!inside(root, target))
        invalid("Local executable import leaves project.");
      const variants = /\.(js|mjs)$/.test(target)
        ? [
            target.replace(/\.m?js$/, (extension) =>
              extension === ".mjs" ? ".mts" : ".ts",
            ),
          ]
        : [target, `${target}.ts`, `${target}.mts`, join(target, "index.ts")];
      const found: string[] = [];
      for (const variant of variants) {
        const info = await lstat(variant).catch(() => undefined);
        if (info?.isFile() && !info.isSymbolicLink()) found.push(variant);
      }
      if (found.length !== 1)
        invalid("Local executable import is missing or ambiguous.");
      const relativeSource = relative(root, found[0]!).split(sep).join("/");
      if (!visited.has(relativeSource)) await visit(relativeSource);
    }
  };
  for (const source of sources)
    if (!visited.has(source.file)) await visit(source.file);
  const actual = emitted.filter((name) => /\.(js|mjs|cjs)$/.test(name));
  if (
    emitted.some(
      (name) => !/\.(js|mjs|cjs)$/.test(name) && name !== "package.json",
    ) ||
    JSON.stringify([...expected].sort()) !== JSON.stringify(actual.sort())
  )
    invalid("Executable module set does not match current source.");
  const packageJson = JSON.parse(
    Buffer.from(
      snapshot.get("package.json") ?? invalid("Executable package is missing."),
    ).toString("utf8"),
  ) as { type?: unknown };
  if (packageJson.type !== "module")
    invalid("Executable output must be an ESM package.");
}

function validateDeploymentIdentity(context: DeploymentContext): void {
  if (
    !context ||
    typeof context !== "object" ||
    Array.isArray(context) ||
    typeof context.serviceId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(context.serviceId) ||
    typeof context.basePath !== "string" ||
    !context.surfaces ||
    typeof context.surfaces !== "object" ||
    Array.isArray(context.surfaces) ||
    !own(context.surfaces, ["http", "mcp", "cli", "docs"]) ||
    Object.values(context.surfaces).some(
      (value) => typeof value !== "boolean",
    ) ||
    (context.externalUrl !== undefined &&
      typeof context.externalUrl !== "string")
  )
    invalid("Invalid deployment context identity or surface selection.");
  try {
    if (
      resolvedBasePath(context.basePath) !== context.basePath ||
      resolvedExternalUrl(context.externalUrl, context.basePath, true) !==
        context.externalUrl
    )
      invalid("Noncanonical deployment location.");
  } catch {
    invalid("Invalid deployment context location.");
  }
}

/** Prepare a verified prebuilt deployment; this does not invoke business handlers. */
export async function buildDeployment(
  options: BuildDeploymentOptions,
): Promise<{ readonly manifest: string; readonly buildId: string }> {
  validateDeploymentIdentity(options.deploymentContext);
  const root = resolve(options.projectRoot),
    executable = resolve(options.executableRoot),
    output = resolve(options.outDir);
  if (
    !isAbsolute(options.projectRoot) ||
    !isAbsolute(options.executableRoot) ||
    !isAbsolute(options.outDir) ||
    output === executable ||
    inside(executable, output) ||
    inside(output, executable) ||
    !inside(root, output)
  )
    invalid(
      "Deployment roots must be distinct absolute directories within the project.",
    );
  if (
    !own(options.deploymentContext, [
      "serviceId",
      "basePath",
      "surfaces",
      ...(options.deploymentContext.externalUrl === undefined
        ? []
        : ["externalUrl"]),
      ...(options.deploymentContext.transport === undefined
        ? []
        : ["transport"]),
      ...(options.deploymentContext.reservations === undefined
        ? []
        : ["reservations"]),
      ...(options.deploymentContext.cliEndpoints === undefined
        ? []
        : ["cliEndpoints"]),
      ...(options.deploymentContext.discovery === undefined
        ? []
        : ["discovery"]),
      ...(options.deploymentContext.documentation === undefined
        ? []
        : ["documentation"]),
    ]) ||
    !own(options.deploymentContext.surfaces, ["http", "mcp", "cli", "docs"])
  )
    invalid("Deployment context has unknown or missing fields.");
  const resolvedCliEndpoints = resolveDeploymentCliEndpoints(
    options.deploymentContext.surfaces,
    options.deploymentContext.cliEndpoints,
  );
  const documentation = resolveDocumentationContext(
    options.deploymentContext.surfaces.docs,
    options.deploymentContext.basePath,
    options.deploymentContext.externalUrl,
    options.deploymentContext.documentation,
  );
  const contextInputs = {
    serviceId: options.deploymentContext.serviceId,
    basePath: options.deploymentContext.basePath,
    ...(options.deploymentContext.externalUrl === undefined
      ? {}
      : { externalUrl: options.deploymentContext.externalUrl }),
    surfaces: Object.freeze({ ...options.deploymentContext.surfaces }),
    ...(documentation ? { documentation } : {}),
    ...(resolvedCliEndpoints ? { cliEndpoints: resolvedCliEndpoints } : {}),
    transport: resolveDeploymentTransport(
      options.deploymentContext.surfaces,
      options.deploymentContext.transport,
    ),
    reservations: resolveDeploymentReservations(
      options.deploymentContext.surfaces,
      options.deploymentContext.reservations,
      resolvedCliEndpoints,
      documentation?.path,
    ),
  };
  if (resolvedCliEndpoints) {
    let registration;
    try {
      registration = createRemoteCliRegistration({
        endpoints: resolvedCliEndpoints,
      });
    } catch {
      invalid("Remote CLI registration cannot serve deployment endpoints.");
    }
    const factoryEndpoints = getRemoteCliRegistrationEndpoints(registration);
    const routes = (values: readonly { method: string; path: string }[]) =>
      values.map(({ method, path }) => `${method} ${path}`).sort();
    if (
      !isRemoteCliRegistration(registration) ||
      !factoryEndpoints ||
      jcs(factoryEndpoints as unknown as import("@capaxle/ir").JsonValue) !==
        jcs(
          resolvedCliEndpoints as unknown as import("@capaxle/ir").JsonValue,
        ) ||
      JSON.stringify(routes(registration.reservations)) !==
        JSON.stringify(routes(contextInputs.reservations.cli ?? []))
    )
      throw new ApplicationError(
        "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
        "Remote CLI factory routes differ from deployment reservations.",
      );
  }
  const remoteCli = remoteCliLocator(contextInputs);
  const { rootPublication: _manifestRootPublication, ...manifestProducer } =
    createAgentManifestArtifactProducer({
      mcpEnabled: contextInputs.surfaces.mcp,
      ...(remoteCli ? { remoteCli } : {}),
    });
  void _manifestRootPublication;
  const buildProfile = await supportedBuildProfile(root);
  const schemaProviders = options.schemaProviders ?? [zodSchemaProvider];
  const preliminary = await compileProject({
    projectRoot: root,
    schemaProviders,
  });
  if (preliminary.ok === false) invalid("Capability compilation failed.");
  if (
    (preliminary as CompilationSuccess).cliRemoteOnly === true &&
    !contextInputs.surfaces.cli
  )
    invalid(
      "Remote-only CLI source requires an enabled application CLI surface.",
    );
  const sourceManifestHash =
    preliminary.graph.nodes.find((node) => node.id === "source:manifest")
      ?.outputDigest ?? invalid("Compiler source manifest is missing.");
  const contextProducer: CompilerArtifactProducer = {
    id: "capaxle.app.deployment-context",
    version: "0.1.0",
    staticInputs: {
      deploymentContext:
        contextInputs as unknown as import("@capaxle/ir").JsonValue,
      buildProfile,
      sourceManifestHash,
    },
    diagnosticCodes: [],
    artifacts: [
      {
        id: "capaxle.deployment-context",
        path: "deployment-context.json",
        mediaType: "application/json",
        target: "capaxle:deployment-context@0.1",
        dependencies: ["document:capability-ir"],
        produce: ({ buildContext }) => ({
          ok: true,
          bytes: Buffer.from(
            jcs({
              ...contextInputs,
              discovery: buildContext.discovery,
              sourceManifestHash,
              buildProfile,
            } as unknown as import("@capaxle/ir").JsonValue),
          ),
          diagnostics: [],
        }),
      },
    ],
  };
  const compiled = await compileProject({
    projectRoot: root,
    schemaProviders,
    artifactProducers: [
      contextProducer,
      manifestProducer as unknown as CompilerArtifactProducer,
      ...(contextInputs.surfaces.docs
        ? createDocumentationProducers(contextInputs)
        : []),
    ],
  });
  if (compiled.ok === false)
    throw new ApplicationError(
      "CAP_APP_DEPLOYMENT_INVALID",
      "Capability compilation failed.",
    );
  if (
    (compiled as CompilationSuccess).cliRemoteOnly !==
    (preliminary as CompilationSuccess).cliRemoteOnly
  )
    invalid(
      "Capability CLI source mode changed during deployment preparation.",
    );
  if (
    compiled.graph.nodes.find((node) => node.id === "source:manifest")
      ?.outputDigest !== sourceManifestHash
  )
    invalid("Capability source changed during deployment preparation.");
  if (
    options.deploymentContext.discovery !== undefined &&
    jcs(
      options.deploymentContext
        .discovery as unknown as import("@capaxle/ir").JsonValue,
    ) !== jcs(compiled.discovery as unknown as import("@capaxle/ir").JsonValue)
  )
    invalid("Deployment discovery context differs from compiled discovery.");
  const emitted = await allEmittedFiles(executable);
  const executableSnapshot = new Map<string, Uint8Array>();
  for (const name of emitted)
    executableSnapshot.set(name, await readVerified(executable, name));
  await verifyExecutableCorrespondence(
    root,
    compiled.registry.capabilities.map((capability) => capability.source),
    emitted,
    executableSnapshot,
  );
  if ((await supportedBuildProfile(root)) !== buildProfile)
    invalid("TypeScript build configuration changed during preparation.");
  const snapshotBoundary = (
    options as BuildDeploymentOptions & {
      readonly [key: symbol]: (() => void | Promise<void>) | undefined;
    }
  )[Symbol.for("@capaxle/app/test-executable-snapshot-boundary@1")];
  await snapshotBoundary?.();
  const emission = await emitCompilerArtifacts({
    projectRoot: root,
    compilation: compiled,
    outputDirectory: relative(root, output).split(sep).join("/"),
  });
  if (!emission.ok)
    throw new ApplicationError(
      "CAP_APP_DEPLOYMENT_INVALID",
      `Artifact graph publication failed: ${emission.diagnostics.map((entry) => entry.code).join(", ")}.`,
    );
  const modules: ManifestModule[] = [];
  await mkdir(join(output, "executable"), { recursive: true });
  for (const source of emitted) {
    const path = `executable/${source}`;
    const verifiedBytes = executableSnapshot.get(source)!;
    await mkdir(dirname(join(output, path)), { recursive: true });
    await writeFile(join(output, path), verifiedBytes);
    modules.push({
      source,
      path,
      sha256: sha(verifiedBytes),
    });
  }
  const descriptorModules = compiled.registry.capabilities.map(
    (capability) => ({
      id: capability.id,
      path: emittedFor(capability.source.file, emitted),
    }),
  );
  const imports = descriptorModules
    .map(
      (entry, index) =>
        `import c${index} from ${JSON.stringify(`./executable/${entry.path}`)};`,
    )
    .join("\n");
  const loaderSource = `${imports}\nexport const descriptors = Object.freeze({${descriptorModules.map((entry, index) => `${JSON.stringify(entry.id)}: c${index}`).join(",")}});\n`;
  const loaderPath = "capaxle.binding-loader.mjs";
  await writeFile(join(output, loaderPath), loaderSource);
  const irPath = "capaxle.capability-ir.json";
  await writeFile(join(output, irPath), compiled.irBytes);
  const absoluteIndexPath = resolve(root, emission.current);
  const indexPath = relative(output, absoluteIndexPath).split(sep).join("/");
  if (!safeRelative(indexPath))
    invalid("Artifact index is outside deployment root.");
  const indexBytes = await readFile(absoluteIndexPath);
  const manifest: DeploymentManifest = {
    deploymentVersion: "0.1",
    service: {
      serviceId: options.deploymentContext.serviceId,
      name: compiled.document.service.name,
      version: compiled.document.service.version,
    },
    irVersion: compiled.document.irVersion,
    irHash: compiled.irHash,
    frameworkVersion: "0.1.0-alpha.3",
    artifactGraphVersion: "0.2",
    buildId: emission.buildId,
    sourceManifestHash,
    deploymentContext: { ...contextInputs, discovery: compiled.discovery },
    artifactIndex: { path: indexPath, sha256: sha(indexBytes) },
    ir: { path: irPath, sha256: sha(compiled.irBytes) },
    loader: { path: loaderPath, sha256: sha(loaderSource) },
    modules,
  };
  const manifestPath = join(output, "capaxle.deployment.json");
  await writeFile(
    manifestPath,
    jcs(manifest as unknown as import("@capaxle/ir").JsonValue),
  );
  return Object.freeze({ manifest: manifestPath, buildId: emission.buildId });
}

const parseJson = (bytes: Uint8Array): unknown => {
  try {
    return JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    return invalid("Deployment JSON is malformed.");
  }
};

export interface InspectedDeployment extends Pick<
  LoadedDeployment,
  "document" | "irHash" | "discovery" | "deploymentContext"
> {
  readonly artifacts?: readonly Omit<CompiledArtifact, "bytes">[];
}

/** Verify existing deployment bytes without importing executable application code.
 * Omitted expectations establish pinned self-consistency, not agreement with a live host.
 */
export async function inspectDeployment(
  manifestFile: string,
  expectations?: DeploymentExpectations,
): Promise<InspectedDeployment> {
  const { document, irHash, discovery, deploymentContext, artifacts } =
    await verifyDeployment(manifestFile, expectations);
  return Object.freeze({
    document,
    irHash,
    discovery,
    deploymentContext,
    ...(artifacts === undefined
      ? {}
      : {
          artifacts: Object.freeze(
            artifacts.map(({ id, path, mediaType, target, producer, sha256 }) =>
              Object.freeze({ id, path, mediaType, target, producer, sha256 }),
            ),
          ),
        }),
  });
}

async function verifyDeployment(
  manifestFile: string,
  expectations?: DeploymentExpectations,
): Promise<
  Omit<InspectedDeployment, "artifacts"> & {
    readonly artifacts?: CompilationSuccess["artifacts"];
    readonly loader: string;
  }
> {
  const manifestPath = resolve(manifestFile),
    root = dirname(manifestPath);
  const raw = parseJson(
    await readVerified(root, relative(root, manifestPath).split(sep).join("/")),
  );
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    invalid("Deployment manifest is invalid.");
  const value = raw as Record<string, unknown>;
  if (
    !own(value, [
      "deploymentVersion",
      "service",
      "irVersion",
      "irHash",
      "frameworkVersion",
      "artifactGraphVersion",
      "buildId",
      "sourceManifestHash",
      "deploymentContext",
      "artifactIndex",
      "ir",
      "loader",
      "modules",
    ]) ||
    value.deploymentVersion !== "0.1" ||
    value.irVersion !== "0.1" ||
    value.frameworkVersion !== "0.1.0-alpha.3" ||
    value.artifactGraphVersion !== "0.2" ||
    !Array.isArray(value.modules)
  )
    invalid("Unsupported deployment manifest shape.");
  const service = value.service;
  if (
    !service ||
    typeof service !== "object" ||
    Array.isArray(service) ||
    !own(service, ["serviceId", "name", "version"]) ||
    Object.values(service).some((entry) => typeof entry !== "string")
  )
    invalid("Invalid deployment service identity.");
  const manifest = value as unknown as DeploymentManifest;
  if (
    typeof manifest.irHash !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(manifest.irHash)
  )
    invalid("Invalid IR hash.");
  const pinned = manifest.deploymentContext;
  validateDeploymentIdentity(pinned);
  expectations ??= {
    serviceId: pinned?.serviceId,
    surfaces: pinned?.surfaces,
    ...(pinned?.cliEndpoints === undefined
      ? {}
      : { cliEndpoints: pinned.cliEndpoints }),
    ...(pinned?.reservations === undefined
      ? {}
      : { reservations: pinned.reservations }),
  };
  if (
    !pinned ||
    typeof pinned !== "object" ||
    Array.isArray(pinned) ||
    !own(pinned, [
      "serviceId",
      "basePath",
      "surfaces",
      "transport",
      "reservations",
      "discovery",
      ...(pinned.externalUrl === undefined ? [] : ["externalUrl"]),
      ...(pinned.cliEndpoints === undefined ? [] : ["cliEndpoints"]),
      ...(pinned.documentation === undefined ? [] : ["documentation"]),
    ]) ||
    !["/", ""].includes(pinned.basePath?.slice(0, 1) ?? "") ||
    pinned.serviceId !== manifest.service.serviceId ||
    pinned.serviceId !== expectations.serviceId ||
    !pinned.surfaces ||
    ["http", "mcp", "cli", "docs"].some(
      (kind) =>
        pinned.surfaces[kind as keyof typeof pinned.surfaces] !==
        expectations.surfaces[kind as keyof typeof expectations.surfaces],
    ) ||
    (expectations.basePath !== undefined &&
      expectations.basePath !== pinned.basePath) ||
    (expectations.externalUrl !== undefined &&
      expectations.externalUrl !== pinned.externalUrl) ||
    (pinned.surfaces?.cli === true && pinned.cliEndpoints === undefined) ||
    (pinned.surfaces?.cli === false && pinned.cliEndpoints !== undefined) ||
    (!expectations.surfaces.cli && expectations.cliEndpoints !== undefined)
  )
    throw new ApplicationError(
      "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
      "Runtime deployment context differs from the verified manifest.",
    );
  let resolvedDocumentation: DocumentationDeploymentContext | undefined;
  try {
    resolvedDocumentation = resolveDocumentationContext(
      pinned.surfaces.docs,
      pinned.basePath,
      pinned.externalUrl,
      pinned.documentation,
    );
  } catch {
    return invalid("Invalid documentation deployment context.");
  }
  if (
    (pinned.surfaces.docs && !pinned.documentation) ||
    jcs(
      (resolvedDocumentation ??
        null) as unknown as import("@capaxle/ir").JsonValue,
    ) !==
      jcs(
        (pinned.documentation ??
          null) as unknown as import("@capaxle/ir").JsonValue,
      )
  )
    invalid("Documentation deployment context is incomplete.");
  if (expectations.documentation !== undefined) {
    const requestedPath =
      expectations.documentation.path ?? resolvedDocumentation?.path;
    const requestedUrl =
      expectations.documentation.externalUrl ??
      resolvedDocumentation?.externalUrl;
    const requested = resolveDocumentationContext(
      expectations.surfaces.docs,
      pinned.basePath,
      pinned.externalUrl,
      {
        ...(requestedPath === undefined ? {} : { path: requestedPath }),
        ...(requestedUrl === undefined ? {} : { externalUrl: requestedUrl }),
      },
    );
    if (
      jcs((requested ?? null) as unknown as import("@capaxle/ir").JsonValue) !==
      jcs(
        (resolvedDocumentation ??
          null) as unknown as import("@capaxle/ir").JsonValue,
      )
    )
      throw new ApplicationError(
        "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
        "Runtime documentation context differs from the verified manifest.",
      );
  }
  const resolvedTransport = resolveDeploymentTransport(
    pinned.surfaces,
    pinned.transport,
  );
  const resolvedCliEndpoints = resolveDeploymentCliEndpoints(
    pinned.surfaces,
    pinned.cliEndpoints,
  );
  if (
    pinned.surfaces.cli &&
    (jcs(pinned.cliEndpoints as unknown as import("@capaxle/ir").JsonValue) !==
      jcs(resolvedCliEndpoints as unknown as import("@capaxle/ir").JsonValue) ||
      jcs(
        resolvedCliEndpoints as unknown as import("@capaxle/ir").JsonValue,
      ) !==
        jcs(
          resolveDeploymentCliEndpoints(
            expectations.surfaces,
            expectations.cliEndpoints,
          ) as unknown as import("@capaxle/ir").JsonValue,
        ))
  )
    throw new ApplicationError(
      "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
      "Runtime CLI endpoint roles differ from the verified deployment.",
    );
  const resolvedReservations = resolveDeploymentReservations(
    pinned.surfaces,
    pinned.reservations,
    resolvedCliEndpoints,
    resolvedDocumentation?.path,
  );
  if (
    pinned.reservations === undefined ||
    jcs(pinned.reservations as unknown as import("@capaxle/ir").JsonValue) !==
      jcs(resolvedReservations as unknown as import("@capaxle/ir").JsonValue) ||
    jcs({
      ...(expectations.reservations ?? {}),
      ...(expectations.adoptDocumentationReservations
        ? { docs: resolvedReservations.docs }
        : {}),
    } as unknown as import("@capaxle/ir").JsonValue) !==
      jcs(resolvedReservations as unknown as import("@capaxle/ir").JsonValue)
  )
    throw new ApplicationError(
      "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
      "Runtime surface routes differ from the prepared deployment.",
    );
  const pinnedTransport = pinned.transport;
  if (!pinnedTransport) invalid("Deployment transport context is incomplete.");
  if (
    jcs(pinnedTransport as unknown as import("@capaxle/ir").JsonValue) !==
    jcs(resolvedTransport as unknown as import("@capaxle/ir").JsonValue)
  )
    invalid("Deployment transport context is incomplete.");
  for (const kind of ["http", "mcp", "cli"] as const)
    for (const [key, supplied] of Object.entries(
      expectations.transport?.[kind] ?? {},
    )) {
      const pinnedValue = pinnedTransport![kind]?.[key as never];
      let equal = false;
      try {
        equal =
          pinnedValue !== undefined &&
          jcs(supplied as import("@capaxle/ir").JsonValue) ===
            jcs(pinnedValue as import("@capaxle/ir").JsonValue);
      } catch {
        // Callback-valued Host policies cannot be pinned in a deployment.
      }
      if (!equal)
        throw new ApplicationError(
          "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
          "Runtime transport settings differ from the prepared deployment.",
        );
    }
  const verifyLocator = (
    candidate: unknown,
  ): candidate is { path: string; sha256: string } =>
    !!candidate &&
    typeof candidate === "object" &&
    !Array.isArray(candidate) &&
    own(candidate, ["path", "sha256"]) &&
    safeRelative((candidate as { path: string }).path) &&
    /^sha256:[a-f0-9]{64}$/.test((candidate as { sha256: string }).sha256);
  if (
    !verifyLocator(manifest.ir) ||
    !verifyLocator(manifest.artifactIndex) ||
    !verifyLocator(manifest.loader) ||
    !manifest.modules.every(
      (entry) =>
        !!entry &&
        own(entry, ["source", "path", "sha256"]) &&
        safeRelative(entry.source) &&
        entry.path === `executable/${entry.source}` &&
        /^sha256:[a-f0-9]{64}$/.test(entry.sha256),
    )
  )
    invalid("Invalid deployment file index.");
  const paths = [
    manifest.ir.path,
    manifest.artifactIndex.path,
    manifest.loader.path,
    ...manifest.modules.map((entry) => entry.path),
  ];
  if (new Set(paths).size !== paths.length)
    invalid("Duplicate deployment path.");
  const [irBytes, indexBytes] = await Promise.all([
    readVerified(root, manifest.ir.path, manifest.ir.sha256),
    readVerified(
      root,
      manifest.artifactIndex.path,
      manifest.artifactIndex.sha256,
    ),
  ]);
  if (!/^sha256:[a-f0-9]{64}$/.test(manifest.sourceManifestHash))
    invalid("Source manifest hash is invalid.");
  const pointer = parseJson(indexBytes) as {
    buildId?: string;
    index?: string;
    indexSha256?: string;
    irHash?: string;
  };
  if (
    !pointer ||
    typeof pointer !== "object" ||
    Array.isArray(pointer) ||
    pointer.buildId !== manifest.buildId ||
    pointer.irHash !== manifest.irHash ||
    typeof pointer.index !== "string" ||
    typeof pointer.indexSha256 !== "string"
  )
    invalid("Artifact graph identity mismatch.");
  const graphIndex = parseJson(
    await readVerified(root, pointer.index!, pointer.indexSha256!),
  ) as {
    buildId?: string;
    irHash?: string;
    artifacts?: readonly {
      id?: string;
      path?: string;
      sha256?: string;
      producer?: { id?: string; version?: string };
      irHash?: string;
      irVersion?: string;
    }[];
  };
  if (
    !graphIndex ||
    typeof graphIndex !== "object" ||
    Array.isArray(graphIndex) ||
    graphIndex.buildId !== manifest.buildId ||
    graphIndex.irHash !== manifest.irHash
  )
    invalid("Artifact graph index mismatch.");
  const contextEntries = graphIndex.artifacts?.filter(
    (entry) => entry.id === "capaxle.deployment-context",
  );
  const contextEntry = contextEntries?.[0];
  if (
    contextEntries?.length !== 1 ||
    contextEntry?.path !== "deployment-context.json" ||
    contextEntry.producer?.id !== "capaxle.app.deployment-context" ||
    contextEntry.producer.version !== "0.1.0" ||
    typeof contextEntry.sha256 !== "string"
  )
    invalid("Deployment context artifact is missing from the build graph.");
  const contextBytes = await readVerified(
    root,
    `${dirname(pointer.index!)}/${contextEntry!.path}`,
    contextEntry!.sha256,
  );
  const contextPayload = parseJson(contextBytes);
  if (
    !contextPayload ||
    typeof contextPayload !== "object" ||
    Array.isArray(contextPayload) ||
    !own(contextPayload, [
      ...Object.keys(manifest.deploymentContext),
      "sourceManifestHash",
      "buildProfile",
    ])
  )
    invalid("Deployment context artifact has invalid shape.");
  const { buildProfile, ...artifactContext } = contextPayload as Record<
    string,
    unknown
  >;
  if (
    typeof buildProfile !== "string" ||
    !/^typescript@\d+\.\d+\.\d+:(?:no-tsconfig:esnext-es2022|sha256:[a-f0-9]{64})$/.test(
      buildProfile,
    ) ||
    Buffer.compare(
      Buffer.from(contextBytes),
      Buffer.from(jcs(contextPayload as import("@capaxle/ir").JsonValue)),
    ) !== 0
  )
    invalid("Deployment context artifact has invalid build profile.");
  const declaredContext = (() => {
    try {
      return jcs({
        ...manifest.deploymentContext,
        sourceManifestHash: manifest.sourceManifestHash,
      } as unknown as import("@capaxle/ir").JsonValue);
    } catch {
      return invalid("Deployment context is not canonical JSON.");
    }
  })();
  if (
    jcs(artifactContext as import("@capaxle/ir").JsonValue) !== declaredContext
  )
    invalid("Deployment context differs from the prepared artifact graph.");
  const manifestEntries = graphIndex.artifacts?.filter(
    (entry) => entry.id === "capaxle.agent-manifest",
  );
  const manifestEntry = manifestEntries?.[0];
  if (manifestEntries?.length === 0 && !pinned.surfaces.cli) {
    // CLI-disabled deployments prepared before CAP-116 have no agent manifest artifact.
  } else {
    if (
      manifestEntries?.length !== 1 ||
      manifestEntry?.path !== "agent-manifest.json" ||
      manifestEntry.producer?.id !== "capaxle.agent-manifest" ||
      typeof manifestEntry.sha256 !== "string"
    )
      invalid("Agent manifest artifact is missing from the build graph.");
    const agentBytes = await readVerified(
      root,
      `${dirname(pointer.index!)}/${manifestEntry!.path}`,
      manifestEntry!.sha256,
    );
    const agentManifest = parseJson(agentBytes) as Record<string, unknown>;
    const agentDiscovery = agentManifest?.discovery as
      Record<string, unknown> | undefined;
    const expectedCliLocator = remoteCliLocator(pinned);
    const actualCliLocator = agentDiscovery?.cli;
    if (
      agentManifest?.manifestVersion !== "0.2" ||
      agentManifest.irHash !== manifest.irHash ||
      !agentDiscovery ||
      typeof agentDiscovery !== "object" ||
      (expectedCliLocator === undefined
        ? actualCliLocator !== undefined
        : actualCliLocator === undefined ||
          jcs(actualCliLocator as import("@capaxle/ir").JsonValue) !==
            jcs({
              protocolVersion: "0.1",
              ...expectedCliLocator,
            } as unknown as import("@capaxle/ir").JsonValue))
    )
      throw new ApplicationError(
        "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
        "Agent manifest CLI locator differs from the verified deployment.",
      );
  }
  const documentationArtifacts: CompilationSuccess["artifacts"][number][] = [];
  if (pinned.surfaces.docs) {
    for (const id of [
      "capaxle.docs-schema-bundle",
      "capaxle.app.public-docs",
      "capaxle.app.docs-context",
      "capaxle.app.browser-model",
      "capaxle.app.docs-styles",
    ]) {
      const selected = graphIndex.artifacts?.filter((entry) => entry.id === id);
      if (selected?.length !== 1)
        invalid("Documentation artifact is missing from the build graph.");
      const entry = selected![0]!;
      if (
        entry.irHash !== manifest.irHash ||
        entry.irVersion !== "0.1" ||
        entry.path !==
          (id === "capaxle.docs-schema-bundle"
            ? "docs/capability-bundle.tar"
            : id === "capaxle.app.public-docs"
              ? "docs/public-bundle.tar"
              : id === "capaxle.app.docs-context"
                ? "docs/browser-context.json"
                : id === "capaxle.app.docs-styles"
                  ? "docs/docs.css"
                  : "docs/browser-model.json") ||
        !entry.producer ||
        entry.producer.id !==
          (id === "capaxle.app.docs-context" ||
          id === "capaxle.app.browser-model"
            ? "capaxle.app.public-docs"
            : id) ||
        entry.producer.version !== "0.1.0-alpha.3" ||
        typeof entry.sha256 !== "string" ||
        !/^sha256:[a-f0-9]{64}$/.test(entry.sha256)
      )
        invalid("Invalid documentation artifact index entry.");
      const bytes = await readVerified(
        root,
        `${dirname(pointer.index!)}/${entry.path}`,
        entry.sha256,
      );
      documentationArtifacts.push({
        ...entry,
        bytes,
      } as CompilationSuccess["artifacts"][number]);
    }
    verifyDocumentationStyles(documentationArtifacts);
    const publicBundle = verifyDocumentationArtifacts(
      documentationArtifacts,
      manifest.irHash,
      manifest.service,
    );
    verifyDocumentationModel(
      documentationArtifacts,
      manifest.irHash,
      publicBundle,
      pinned,
    );
  }
  const actualModules = await allEmittedFiles(join(root, "executable"));
  if (
    JSON.stringify(actualModules) !==
    JSON.stringify(manifest.modules.map((entry) => entry.source).sort())
  )
    invalid("Executable module index is incomplete.");
  for (const entry of manifest.modules)
    await readVerified(root, entry.path, entry.sha256);
  await readVerified(root, manifest.loader.path, manifest.loader.sha256);
  const document = parseJson(irBytes) as CompilationSuccess["document"];
  if (
    document.irVersion !== "0.1" ||
    document.service.name !== manifest.service.name ||
    document.service.version !== manifest.service.version
  )
    invalid("Service or IR identity mismatch.");
  if (capabilitySemanticHash(document) !== manifest.irHash)
    invalid("IR semantic hash mismatch.");
  routeReservations(
    { document, discovery: manifest.deploymentContext.discovery! },
    pinned.basePath,
    {
      http: { enabled: pinned.surfaces.http },
      mcp: { enabled: pinned.surfaces.mcp },
    },
    (["cli", "docs"] as const).flatMap((kind) =>
      pinned.surfaces[kind]
        ? [{ kind, reservations: pinned.reservations?.[kind] ?? [] }]
        : [],
    ),
  );
  return Object.freeze({
    document,
    irHash: manifest.irHash as `sha256:${string}`,
    discovery: manifest.deploymentContext.discovery!,
    deploymentContext: manifest.deploymentContext,
    artifacts: documentationArtifacts,
    loader: join(root, manifest.loader.path),
  });
}

/** Verify every byte and topology value before importing trusted application code. */
export async function loadDeployment(
  manifestFile: string,
  expectations: DeploymentExpectations,
  schemaProviders: readonly SchemaProvider<unknown>[] = [zodSchemaProvider],
): Promise<LoadedDeployment> {
  if (
    !expectations ||
    typeof expectations !== "object" ||
    Array.isArray(expectations) ||
    typeof expectations.serviceId !== "string" ||
    !expectations.surfaces ||
    typeof expectations.surfaces !== "object" ||
    Array.isArray(expectations.surfaces) ||
    !own(expectations.surfaces, ["http", "mcp", "cli", "docs"]) ||
    Object.values(expectations.surfaces).some(
      (value) => typeof value !== "boolean",
    )
  )
    throw new ApplicationError(
      "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
      "Explicit runtime deployment expectations are required.",
    );
  const verified = await verifyDeployment(manifestFile, expectations);
  const imported: unknown = await import(pathToFileURL(verified.loader).href);
  const descriptors = (imported as { descriptors?: unknown }).descriptors;
  if (
    !descriptors ||
    typeof descriptors !== "object" ||
    Array.isArray(descriptors)
  )
    invalid("Binding loader did not export descriptors.");
  const irHash = verified.irHash;
  const document = verified.document;
  const bindings = loadDeploymentBindings({
    document,
    irHash,
    descriptors: descriptors as Readonly<Record<string, unknown>>,
    schemaProviders,
  });
  return Object.freeze({
    document,
    irHash,
    discovery: verified.discovery,
    deploymentContext: verified.deploymentContext,
    ...(verified.artifacts === undefined
      ? {}
      : { artifacts: verified.artifacts }),
    ...bindings,
  });
}
