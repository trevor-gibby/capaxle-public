import {
  routeReservations,
  overlaps,
  resolvedBasePath,
  resolvedExternalUrl,
} from "./mounts.js";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
  type Server,
} from "node:http";
import { isIP } from "node:net";
import {
  createCompilerSession,
  watchCapabilities,
  type CompilationSuccess,
  type CompilerSession,
  type DiscoveryWatcher,
} from "@capaxle/compiler";
import { zodSchemaProvider } from "@capaxle/schema-zod";
import { jcs, type JsonValue } from "@capaxle/ir";
import type { SchemaProvider } from "@capaxle/core";
import {
  createRuntimeKernel,
  createRuntimeRegistry,
  type AdapterIngress,
  type RuntimeKernelOptions,
} from "@capaxle/runtime";
import {
  createHttpAdapter,
  createHttpNodeHandler,
  type HttpHostOptions,
  type HttpNodeHandler,
} from "@capaxle/adapter-http";
import {
  createMcpAdapter,
  createMcpNodeHandler,
  type McpNodeHandler,
  type McpNodeHandlerOptions,
} from "@capaxle/adapter-mcp";
import {
  createRemoteCliAdapter,
  createRemoteCliRegistration,
  getRemoteCliRegistrationEndpoints,
  isRemoteCliRegistration,
} from "@capaxle/adapter-cli/remote";
import {
  loadDeployment,
  resolveDeploymentCliEndpoints,
  resolveDeploymentReservations,
  resolveDeploymentTransport,
  type DeploymentContext,
  type DeploymentReservations,
  type DeploymentTransport,
  type CliEndpoints,
  type LoadedDeployment,
} from "./deployment.js";
import { ApplicationError } from "./errors.js";
import {
  createDocumentationProducers,
  verifyDocumentationArtifacts,
  documentationCliBinary,
  verifyDocumentationModel,
  verifyDocumentationStyles,
  resolveDocumentationContext,
  createDocumentationHandler,
  documentationReservations,
  documentationWirePath,
  type DocumentationOptions,
} from "./documentation.js";

type Disabled = { readonly enabled: false };
type EnabledHttp = {
  readonly enabled: true;
  readonly providerId?: string;
} & Pick<HttpHostOptions, "maxBodyBytes" | "requestTimeoutMs">;
type EnabledMcp = {
  readonly enabled: true;
  readonly providerId?: string;
  readonly allowedHosts?: McpNodeHandlerOptions["allowedHosts"];
} & Omit<
  McpNodeHandlerOptions,
  "adapter" | "discovery" | "basePath" | "port" | "hostname" | "allowedHosts"
>;
type EnabledCli = {
  readonly enabled: true;
  readonly providerId?: string;
  readonly endpoints?: CliEndpoints;
  readonly payloadLimits?: Readonly<{
    requestBytes?: number;
    responseBytes?: number;
  }>;
  readonly allowPrivateDiscovery?: boolean;
  readonly disclosureSelector?: NonNullable<
    Parameters<typeof createRemoteCliAdapter>[0]["disclosureSelector"]
  >;
};

export interface ApplicationSurfaces {
  readonly http?: Disabled | EnabledHttp;
  readonly mcp?: Disabled | EnabledMcp;
  readonly cli?: Disabled | EnabledCli;
  readonly docs?: Disabled | DocumentationOptions;
}

export interface ManagedProvider {
  readonly id: string;
  prepare?(): void | Promise<void>;
  activate?(): void | Promise<void>;
  drain?(context: {
    readonly deadline: Date;
    readonly signal: AbortSignal;
  }): void | Promise<void>;
  close?(): void | Promise<void>;
}

export type ApplicationProviders = Omit<
  RuntimeKernelOptions,
  "registry" | "adapters" | "services"
> & {
  readonly lifecycle?: readonly ManagedProvider[];
};

export interface ReadinessCheck {
  readonly id: string;
  readonly ready: boolean;
  readonly code?: string;
}

export interface SurfaceRegistration {
  readonly kind: "cli" | "docs";
  readonly reservations: readonly {
    readonly method: string;
    readonly path: string;
  }[];
  readonly requiredProviderIds: readonly string[];
  prepare(context: {
    readonly generation: Readonly<{
      document: CompilationSuccess["document"];
      irHash: string;
    }>;
    readonly deploymentContext: DeploymentContext;
    readonly ingress: AdapterIngress;
  }): Promise<PreparedSurface>;
}

export interface PreparedSurface {
  handle(req: IncomingMessage, res: ServerResponse): Promise<boolean>;
  activate(): Promise<void>;
  drain(context: {
    readonly deadline: Date;
    readonly signal: AbortSignal;
  }): Promise<void>;
  close(): Promise<void>;
}

interface CommonApplicationOptions {
  readonly serviceId: string;
  readonly basePath?: string;
  readonly externalUrl?: string;
  readonly providers: ApplicationProviders;
  readonly schemaProviders?: readonly SchemaProvider<unknown>[];
  readonly services?: Readonly<Record<string, unknown>>;
  readonly surfaces: ApplicationSurfaces;
  readonly surfaceRegistrations?: readonly SurfaceRegistration[];
}

export type ApplicationOptions = CommonApplicationOptions &
  (
    | { readonly mode: "development"; readonly projectRoot: string }
    | {
        readonly mode: "production";
        readonly deployment: { readonly manifest: string };
      }
  );

export interface ApplicationListener {
  readonly url: string;
  close(options?: { readonly drainTimeoutMs?: number }): Promise<void>;
}

export interface Application {
  middleware(
    req: IncomingMessage,
    res: ServerResponse,
    next?: (error?: Error) => void,
  ): void;
  listen(options: {
    readonly host: string;
    readonly port: number;
  }): Promise<ApplicationListener>;
  readiness(): {
    readonly ready: boolean;
    readonly generation?: string;
    readonly checks: ReadonlyArray<ReadinessCheck>;
  };
  close(options?: { readonly drainTimeoutMs?: number }): Promise<void>;
}

const fail = (code: string, message: string): never => {
  throw new ApplicationError(code, message);
};
const validId = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const join = (base: string, path: string): string =>
  base === "/" ? path : path === "/" ? base : `${base}${path}`;
function selectedProviderId(
  providers: ApplicationProviders,
  id?: string,
): string {
  const entries = providers.authenticationProviders ?? [];
  const selected = id ?? (entries.length === 1 ? entries[0]!.id : undefined);
  if (!selected || !entries.some((entry) => entry.id === selected))
    fail(
      "CAP_APP_PROVIDER_REQUIRED",
      "A registered authentication provider must be selected for each enabled capability surface.",
    );
  return selected!;
}

function validatePolicyProviders(
  compilation: Pick<CompilationSuccess, "document">,
  providers: ApplicationProviders,
): void {
  for (const capability of compilation.document.capabilities) {
    const effects = capability.effects;
    if (effects.confirmation === "required" && !providers.confirmationProvider)
      fail("CAP_APP_PROVIDER_REQUIRED", "A confirmation provider is required.");
    if (effects.idempotency === "key" && !providers.idempotencyProvider)
      fail("CAP_APP_PROVIDER_REQUIRED", "An idempotency provider is required.");
    if (
      capability.requirements.secrets.some(
        (entry) =>
          typeof entry === "object" &&
          entry !== null &&
          (entry as { optional?: boolean }).optional !== true,
      ) &&
      !providers.secretProvider
    )
      fail("CAP_APP_PROVIDER_REQUIRED", "A secret provider is required.");
    const rate = capability.limits.rateLimit as { policy?: string } | undefined;
    if (
      rate &&
      (!providers.rateLimitProvider ||
        !providers.rateLimitProvider.policies.includes(rate.policy ?? ""))
    )
      fail(
        "CAP_APP_PROVIDER_REQUIRED",
        "A matching rate provider is required.",
      );
    if (
      capability.requirements.resources.length ||
      capability.requirements.environment.length
    )
      fail(
        "CAP_APP_DEPLOYMENT_INVALID",
        "Resource and environment requirements are not supported.",
      );
  }
}

interface Generation {
  readonly id: string;
  readonly http?: HttpNodeHandler;
  readonly mcp?: McpNodeHandler;
  readonly extensions: readonly {
    readonly registration: SurfaceRegistration;
    readonly surface: PreparedSurface;
  }[];
  active: number;
  retiring: boolean;
  closed: boolean;
}

function normalizedOptions(
  options: ApplicationOptions,
  registrations: readonly SurfaceRegistration[],
  cliEndpointRoles?: CliEndpoints,
  pinned?: DeploymentContext,
): DeploymentContext {
  const basePath = resolvedBasePath(options.basePath ?? pinned?.basePath);
  const externalUrl = resolvedExternalUrl(
    options.externalUrl ?? pinned?.externalUrl,
    basePath,
    options.mode === "development",
  );
  const surfaces = Object.freeze({
    http: options.surfaces.http?.enabled === true,
    mcp: options.surfaces.mcp?.enabled === true,
    cli: options.surfaces.cli?.enabled === true,
    docs: options.surfaces.docs?.enabled === true,
  });
  const requestedTransport = transportOverrides(options.surfaces);
  const resolvedCliEndpoints = resolveDeploymentCliEndpoints(
    surfaces,
    cliEndpointRoles,
  );
  const requestedDocsPath = options.surfaces.docs?.enabled
    ? (options.surfaces.docs.path ?? pinned?.documentation?.path)
    : undefined;
  const requestedDocsUrl = options.surfaces.docs?.enabled
    ? (options.surfaces.docs.externalUrl ?? pinned?.documentation?.externalUrl)
    : undefined;
  const documentation = resolveDocumentationContext(
    surfaces.docs,
    basePath,
    externalUrl,
    options.surfaces.docs?.enabled
      ? {
          ...(requestedDocsPath === undefined
            ? {}
            : { path: requestedDocsPath }),
          ...(requestedDocsUrl === undefined
            ? {}
            : { externalUrl: requestedDocsUrl }),
        }
      : undefined,
    options.mode === "development",
  );
  const requestedReservations = registrationReservations(
    options.surfaces,
    registrations,
    resolvedCliEndpoints,
  );
  if (
    pinned &&
    JSON.stringify(requestedReservations) !==
      JSON.stringify(
        resolveDeploymentReservations(
          surfaces,
          pinned.reservations,
          pinned.cliEndpoints,
          pinned.documentation?.path,
        ),
      )
  )
    fail(
      "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
      "Runtime surface routes differ from the verified deployment.",
    );
  if (!validId.test(options.serviceId))
    fail("CAP_APP_MOUNT_INVALID", "Invalid serviceId.");
  const context: DeploymentContext = Object.freeze({
    serviceId: options.serviceId,
    basePath,
    ...(externalUrl ? { externalUrl } : {}),
    ...(documentation ? { documentation } : {}),
    surfaces,
    ...(resolvedCliEndpoints ? { cliEndpoints: resolvedCliEndpoints } : {}),
    transport: resolveDeploymentTransport(
      surfaces,
      pinned?.transport ?? (requestedTransport as DeploymentTransport),
    ),
    reservations: resolveDeploymentReservations(
      surfaces,
      pinned?.reservations ?? requestedReservations,
      resolvedCliEndpoints,
      documentation?.path,
    ),
    ...(pinned?.discovery
      ? {
          discovery: Object.freeze({
            http: Object.freeze({ ...pinned.discovery.http }),
            mcp: Object.freeze({ ...pinned.discovery.mcp }),
          }),
        }
      : {}),
  });
  if (
    pinned &&
    (context.serviceId !== pinned.serviceId ||
      context.basePath !== pinned.basePath ||
      context.externalUrl !== pinned.externalUrl ||
      (context.cliEndpoints !== undefined &&
        pinned.cliEndpoints !== undefined &&
        jcs(context.cliEndpoints as unknown as JsonValue) !==
          jcs(pinned.cliEndpoints as unknown as JsonValue)) ||
      ["http", "mcp", "cli", "docs"].some(
        (kind) =>
          context.surfaces[kind as keyof typeof context.surfaces] !==
          pinned.surfaces[kind as keyof typeof pinned.surfaces],
      ))
  )
    fail(
      "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
      "Runtime deployment context differs from the verified manifest.",
    );
  return context;
}

function registrationReservations(
  surfaces: ApplicationSurfaces,
  registrations: readonly SurfaceRegistration[],
  cliEndpointRoles?: CliEndpoints,
): DeploymentReservations {
  const selection = {
    http: surfaces.http?.enabled === true,
    mcp: surfaces.mcp?.enabled === true,
    cli: surfaces.cli?.enabled === true,
    docs: surfaces.docs?.enabled === true,
  };
  const raw: DeploymentReservations = Object.fromEntries(
    registrations.map((registration) => [
      registration.kind,
      registration.reservations,
    ]),
  );
  return resolveDeploymentReservations(selection, raw, cliEndpointRoles);
}

function transportOverrides(
  surfaces: ApplicationSurfaces,
  preserveHostCallback = false,
): Readonly<{
  http?: Readonly<Record<string, unknown>>;
  mcp?: Readonly<Record<string, unknown>>;
  cli?: Readonly<Record<string, unknown>>;
}> {
  const select = (
    source: Record<string, unknown>,
    keys: readonly string[],
  ): Record<string, unknown> =>
    Object.fromEntries(
      keys
        .filter((key) => source[key] !== undefined)
        .map((key) => [key, source[key]]),
    );
  const http = surfaces.http?.enabled
    ? select(surfaces.http, ["maxBodyBytes", "requestTimeoutMs"])
    : undefined;
  const mcp = surfaces.mcp?.enabled
    ? select(surfaces.mcp, [
        "allowedHosts",
        "allowedOrigins",
        "clientCanSendInvocationMetadata",
        "requestBodyLimitBytes",
        "responseBodyLimitBytes",
        "maxSessions",
        "maxActiveRequestsPerSession",
        "sessionIdleTimeoutMs",
        "sessionAbsoluteTimeoutMs",
      ])
    : undefined;
  const cli = surfaces.cli?.enabled
    ? {
        ...surfaces.cli.payloadLimits,
        ...(surfaces.cli.allowPrivateDiscovery === undefined
          ? {}
          : { allowPrivateDiscovery: surfaces.cli.allowPrivateDiscovery }),
      }
    : undefined;
  if (mcp && typeof mcp.allowedHosts === "function" && !preserveHostCallback)
    delete mcp.allowedHosts;
  return {
    ...(http ? { http } : {}),
    ...(mcp ? { mcp } : {}),
    ...(cli ? { cli } : {}),
  };
}

export async function createApplication(
  options: ApplicationOptions,
): Promise<Application> {
  if (options.surfaces.docs !== undefined) {
    const docs = options.surfaces.docs;
    if (
      !docs ||
      typeof docs !== "object" ||
      Array.isArray(docs) ||
      (docs.enabled !== true && docs.enabled !== false) ||
      Object.keys(docs).some(
        (key) =>
          !(
            docs.enabled
              ? [
                  "enabled",
                  "providerId",
                  "disclosureSelector",
                  "path",
                  "externalUrl",
                ]
              : ["enabled"]
          ).includes(key),
      ) ||
      (docs.enabled &&
        ((docs.disclosureSelector !== undefined &&
          typeof docs.disclosureSelector !== "function") ||
          (docs.path !== undefined && typeof docs.path !== "string") ||
          (docs.externalUrl !== undefined &&
            typeof docs.externalUrl !== "string")))
    )
      fail(
        "CAP_APP_SURFACE_UNAVAILABLE",
        "Invalid documentation surface configuration.",
      );
    options = {
      ...options,
      surfaces: { ...options.surfaces, docs: Object.freeze({ ...docs }) },
    };
  }
  if (
    options.surfaces.cli?.enabled &&
    options.surfaces.cli.allowPrivateDiscovery === true &&
    !options.surfaces.cli.disclosureSelector
  )
    fail(
      "CAP_APP_SURFACE_UNAVAILABLE",
      "Private CLI discovery requires a trusted disclosure selector.",
    );
  if (options.surfaces.cli?.enabled) {
    const cli = options.surfaces.cli;
    options = {
      ...options,
      surfaces: {
        ...options.surfaces,
        cli: Object.freeze({
          ...cli,
          ...(cli.endpoints
            ? { endpoints: Object.freeze({ ...cli.endpoints }) }
            : {}),
          ...(cli.payloadLimits
            ? { payloadLimits: Object.freeze({ ...cli.payloadLimits }) }
            : {}),
        }),
      },
    };
  }
  const explicitCliRegistration = options.surfaceRegistrations?.find(
    (entry) => entry.kind === "cli",
  );
  const explicitCli = explicitCliRegistration !== undefined;
  if (
    options.surfaces.cli?.enabled &&
    explicitCliRegistration &&
    !isRemoteCliRegistration(explicitCliRegistration)
  )
    fail(
      "CAP_APP_SURFACE_UNAVAILABLE",
      "The CLI registration does not implement the remote protocol.",
    );
  const registeredCliEndpoints = explicitCliRegistration
    ? getRemoteCliRegistrationEndpoints(explicitCliRegistration)
    : undefined;
  if (
    options.surfaces.cli?.enabled &&
    options.surfaces.cli.endpoints &&
    registeredCliEndpoints &&
    jcs(options.surfaces.cli.endpoints as unknown as JsonValue) !==
      jcs(registeredCliEndpoints as unknown as JsonValue)
  )
    fail(
      "CAP_APP_DEPLOYMENT_CONTEXT_MISMATCH",
      "CLI registration endpoints differ from application endpoints.",
    );
  const cliEndpointRoles = options.surfaces.cli?.enabled
    ? resolveDeploymentCliEndpoints(
        { http: false, mcp: false, cli: true, docs: false },
        registeredCliEndpoints ?? options.surfaces.cli.endpoints,
      )
    : undefined;
  if (
    explicitCli &&
    options.surfaces.cli?.enabled &&
    options.surfaces.cli.allowPrivateDiscovery === true
  )
    fail(
      "CAP_APP_SURFACE_UNAVAILABLE",
      "Private CLI discovery requires the built-in remote integration.",
    );
  const builtInCli: SurfaceRegistration | undefined =
    options.surfaces.cli?.enabled && !explicitCli
      ? createRemoteCliRegistration({
          ...(options.surfaces.cli.providerId
            ? { providerId: options.surfaces.cli.providerId }
            : {}),
          ...(cliEndpointRoles ? { endpoints: cliEndpointRoles } : {}),
          ...(options.surfaces.cli.payloadLimits
            ? { payloadLimits: options.surfaces.cli.payloadLimits }
            : {}),
          ...(options.surfaces.cli.allowPrivateDiscovery === undefined
            ? {}
            : {
                allowPrivateDiscovery:
                  options.surfaces.cli.allowPrivateDiscovery,
              }),
          ...(options.surfaces.cli.disclosureSelector
            ? { disclosureSelector: options.surfaces.cli.disclosureSelector }
            : {}),
        })
      : undefined;
  const builtinDocs =
    options.surfaces.docs?.enabled === true &&
    !options.surfaceRegistrations?.some((entry) => entry.kind === "docs");
  const requestedDocsPath = options.surfaces.docs?.enabled
    ? options.surfaces.docs.path
    : undefined;
  const docsRegistration: SurfaceRegistration | undefined = builtinDocs
    ? {
        kind: "docs",
        reservations: documentationReservations(
          resolveDocumentationContext(
            true,
            resolvedBasePath(options.basePath),
            undefined,
            requestedDocsPath === undefined
              ? undefined
              : { path: requestedDocsPath },
          )!.path,
        ),
        requiredProviderIds:
          options.surfaces.docs?.enabled && options.surfaces.docs.providerId
            ? [options.surfaces.docs.providerId]
            : [],
        prepare: async () => {
          throw new ApplicationError(
            "CAP_APP_SURFACE_UNAVAILABLE",
            "Documentation preparation requires verified artifacts.",
          );
        },
      }
    : undefined;
  let registrations = Object.freeze(
    [
      ...(options.surfaceRegistrations ?? []),
      ...(builtInCli ? [builtInCli] : []),
      ...(docsRegistration ? [docsRegistration] : []),
    ].map((registration) =>
      Object.freeze({
        kind: registration.kind,
        reservations: Object.freeze(
          registration.reservations.map((route) =>
            Object.freeze({ method: route.method, path: route.path }),
          ),
        ),
        requiredProviderIds: Object.freeze([
          ...registration.requiredProviderIds,
        ]),
        prepare: registration.prepare,
      }),
    ),
  );
  for (const kind of ["cli", "docs"] as const) {
    const enabled = options.surfaces[kind]?.enabled === true;
    const matches = registrations.filter(
      (registration) => registration.kind === kind,
    );
    if (matches.length > 1 || (enabled && matches.length !== 1))
      fail(
        "CAP_APP_SURFACE_UNAVAILABLE",
        `The ${kind} surface integration is unavailable.`,
      );
    if (!enabled && matches.length)
      fail("CAP_APP_SURFACE_UNAVAILABLE", `The ${kind} surface is disabled.`);
  }
  if (
    registrations.some(
      (registration) =>
        registration.kind !== "cli" && registration.kind !== "docs",
    )
  )
    fail("CAP_APP_SURFACE_UNAVAILABLE", "Unknown surface integration.");
  const preparedProviders: ManagedProvider[] = [];
  const controller = new AbortController();
  let session: CompilerSession | undefined;
  let watcher: DiscoveryWatcher | undefined;
  let listener: Server | undefined;
  let listenerStarting: Promise<void> | undefined;
  let active: Generation | undefined;
  let closing = false;
  let closePromise: Promise<void> | undefined;
  let refresh: Promise<void> = Promise.resolve();
  let diagnostic: string | undefined;
  let generationSequence = 0;
  const inFlight = new Set<{ req: IncomingMessage; res: ServerResponse }>();
  const idleWaiters = new Set<() => void>();
  const all = new Set<Generation>();
  const closeGeneration = async (generation: Generation): Promise<void> => {
    if (generation.closed) return;
    generation.closed = true;
    const errors = await Promise.allSettled([
      generation.mcp?.close(),
      ...[...generation.extensions]
        .reverse()
        .map(({ surface }) => surface.close()),
    ]);
    generation.http?.close();
    all.delete(generation);
    if (errors.some((entry) => entry.status === "rejected"))
      fail("CAP_APP_SHUTDOWN_FAILED", "A surface failed to close.");
  };
  const buildGeneration = async (
    compilation: Pick<
      CompilationSuccess,
      "document" | "irHash" | "discovery" | "runtimeBindings" | "validators"
    > & { readonly artifacts?: CompilationSuccess["artifacts"] },
    context: DeploymentContext,
  ): Promise<Generation> => {
    const generationContext: DeploymentContext = Object.freeze({
      ...context,
      discovery: Object.freeze({
        http: Object.freeze({ ...compilation.discovery.http }),
        mcp: Object.freeze({ ...compilation.discovery.mcp }),
      }),
    });
    validatePolicyProviders(compilation, options.providers);
    routeReservations(
      compilation,
      context.basePath,
      options.surfaces,
      registrations,
    );
    const registry = createRuntimeRegistry({
      document: compilation.document,
      irHash: compilation.irHash,
      bindings: compilation.runtimeBindings,
      validators: compilation.validators,
    });
    const adapters = [];
    if (options.surfaces.http?.enabled)
      adapters.push({
        id: "capaxle.app.http",
        source: "http" as const,
        providerId: selectedProviderId(
          options.providers,
          options.surfaces.http.providerId,
        ),
        capabilities: registry.capabilities.map(({ id }) => id),
      });
    if (options.surfaces.mcp?.enabled)
      adapters.push({
        id: "capaxle.app.mcp",
        source: "mcp" as const,
        providerId: selectedProviderId(
          options.providers,
          options.surfaces.mcp.providerId,
        ),
        capabilities: registry.capabilities.map(({ id }) => id),
      });
    for (const registration of registrations) {
      for (const providerId of registration.requiredProviderIds)
        selectedProviderId(options.providers, providerId);
      const providerId = selectedProviderId(
        options.providers,
        registration.requiredProviderIds[0],
      );
      const privateCliBoundary =
        registration.kind === "cli" &&
        builtInCli !== undefined &&
        options.surfaces.cli?.enabled === true &&
        options.surfaces.cli.allowPrivateDiscovery === true &&
        options.surfaces.cli.disclosureSelector !== undefined &&
        context.transport?.cli?.allowPrivateDiscovery === true;
      if (
        privateCliBoundary &&
        typeof options.providers.authenticationProviders?.find(
          (provider) => provider.id === providerId,
        )?.authenticateDisclosure !== "function"
      )
        fail(
          "CAP_APP_PROVIDER_REQUIRED",
          "Private CLI discovery requires provider disclosure authentication.",
        );
      adapters.push({
        id: `capaxle.app.${registration.kind}`,
        source:
          registration.kind === "cli" ? ("cli" as const) : ("http" as const),
        providerId,
        ...(privateCliBoundary ? { privateBoundary: true } : {}),
        capabilities:
          registration.kind === "cli"
            ? registry.capabilities.map(({ id }) => id)
            : [],
      });
    }
    const { lifecycle: _lifecycle, ...kernelProviders } = options.providers;
    void _lifecycle;
    const kernel = createRuntimeKernel({
      ...kernelProviders,
      ...(options.services === undefined ? {} : { services: options.services }),
      registry,
      adapters,
    });
    const prepared: {
      registration: SurfaceRegistration;
      surface: PreparedSurface;
    }[] = [];
    let http: HttpNodeHandler | undefined, mcp: McpNodeHandler | undefined;
    try {
      if (options.surfaces.http?.enabled) {
        const headerAllowlist = [
          ...new Set(
            compilation.document.capabilities.flatMap((capability) => {
              const projection = capability.interfaces.http as {
                enabled: boolean;
                bindings?: Readonly<Record<string, string>>;
              };
              return projection.enabled
                ? Object.entries(projection.bindings ?? {})
                    .filter(([, binding]) => binding === "header")
                    .map(([property]) =>
                      `x-cap-input-${property}`.toLowerCase(),
                    )
                : [];
            }),
          ),
        ];
        const adapter = createHttpAdapter({
          document: compilation.document,
          irHash: compilation.irHash,
          discovery: compilation.discovery,
          basePath: context.basePath,
          ...(context.externalUrl ? { externalUrl: context.externalUrl } : {}),
          ingress: kernel.createAdapterIngress("capaxle.app.http"),
          headerAllowlist,
        });
        http = createHttpNodeHandler({
          adapter,
          discovery: compilation.discovery,
          basePath: context.basePath,
          ...context.transport?.http,
        });
      }
      if (options.surfaces.mcp?.enabled) {
        const surface = options.surfaces.mcp;
        const adapter = createMcpAdapter({
          document: compilation.document,
          irHash: compilation.irHash,
          discovery: compilation.discovery,
          ingress: kernel.createAdapterIngress("capaxle.app.mcp"),
        });
        const allowedHosts =
          (options.mode === "development"
            ? surface.allowedHosts
            : context.transport?.mcp?.allowedHosts) ??
          (() => {
            if (context.externalUrl) return [new URL(context.externalUrl).host];
            const address = listener?.address();
            return address && typeof address !== "string"
              ? [
                  `${address.address.includes(":") ? `[${address.address}]` : address.address}:${address.port}`,
                ]
              : [];
          });
        mcp = createMcpNodeHandler({
          ...surface,
          ...context.transport?.mcp,
          adapter,
          discovery: compilation.discovery,
          basePath: context.basePath,
          allowedHosts,
        });
      }
      for (const registration of registrations) {
        const surface =
          builtinDocs && registration.kind === "docs"
            ? {
                handle: createDocumentationHandler(
                  options.surfaces.docs as DocumentationOptions,
                  compilation.document,
                  compilation.irHash,
                  verifyDocumentationArtifacts(
                    compilation.artifacts ?? [],
                    compilation.irHash,
                    compilation.document.service,
                  ),
                  generationContext,
                  kernel.createAdapterIngress("capaxle.app.docs"),
                  documentationCliBinary(
                    compilation.artifacts ?? [],
                    compilation.irHash,
                  ),
                  verifyDocumentationModel(
                    compilation.artifacts ?? [],
                    compilation.irHash,
                    verifyDocumentationArtifacts(
                      compilation.artifacts ?? [],
                      compilation.irHash,
                      compilation.document.service,
                    ),
                    generationContext,
                  ),
                  verifyDocumentationStyles(compilation.artifacts ?? []),
                ),
                activate: async () => {},
                drain: async () => {},
                close: async () => {},
              }
            : await registration.prepare({
                generation: Object.freeze({
                  document: compilation.document,
                  irHash: compilation.irHash,
                }),
                deploymentContext: generationContext,
                ingress: kernel.createAdapterIngress(
                  `capaxle.app.${registration.kind}`,
                ),
              });
        prepared.push({ registration, surface });
      }
      for (const entry of prepared) await entry.surface.activate();
      return {
        id: `${compilation.irHash}:${++generationSequence}`,
        ...(http ? { http } : {}),
        ...(mcp ? { mcp } : {}),
        extensions: Object.freeze(prepared),
        active: 0,
        retiring: false,
        closed: false,
      };
    } catch (error) {
      await Promise.allSettled(
        [...prepared].reverse().map(({ surface }) => surface.close()),
      );
      await mcp?.close();
      http?.close();
      throw error;
    }
  };
  let context!: DeploymentContext;
  let loadedProduction: LoadedDeployment | undefined;
  try {
    if (options.mode === "production") {
      loadedProduction = await loadDeployment(
        options.deployment.manifest,
        {
          serviceId: options.serviceId,
          ...(options.basePath === undefined
            ? {}
            : { basePath: options.basePath }),
          ...(options.externalUrl === undefined
            ? {}
            : { externalUrl: options.externalUrl }),
          surfaces: {
            http: options.surfaces.http?.enabled === true,
            mcp: options.surfaces.mcp?.enabled === true,
            cli: options.surfaces.cli?.enabled === true,
            docs: options.surfaces.docs?.enabled === true,
          },
          transport: transportOverrides(options.surfaces, true),
          ...(cliEndpointRoles ? { cliEndpoints: cliEndpointRoles } : {}),
          reservations: registrationReservations(
            options.surfaces,
            registrations,
            cliEndpointRoles,
          ),
          ...(options.surfaces.docs?.enabled
            ? {
                documentation: {
                  ...(options.surfaces.docs.path === undefined
                    ? {}
                    : { path: options.surfaces.docs.path }),
                  ...(options.surfaces.docs.externalUrl === undefined
                    ? {}
                    : { externalUrl: options.surfaces.docs.externalUrl }),
                },
              }
            : {}),
          ...(builtinDocs &&
          options.surfaces.docs?.enabled &&
          options.surfaces.docs.path === undefined
            ? { adoptDocumentationReservations: true }
            : {}),
        },
        options.schemaProviders ?? [zodSchemaProvider],
      );
      if (
        builtinDocs &&
        options.surfaces.docs?.enabled &&
        options.surfaces.docs.path === undefined
      )
        registrations = Object.freeze(
          registrations.map((registration) =>
            registration.kind === "docs"
              ? Object.freeze({
                  ...registration,
                  reservations: documentationReservations(
                    loadedProduction!.deploymentContext.documentation!.path,
                  ),
                })
              : registration,
          ),
        );
      context = normalizedOptions(
        options,
        registrations,
        cliEndpointRoles,
        loadedProduction.deploymentContext,
      );
    }
    for (const provider of options.providers.lifecycle ?? []) {
      preparedProviders.push(provider);
      await provider.prepare?.();
    }
    for (const provider of preparedProviders) await provider.activate?.();
    if (options.mode === "development") {
      context = normalizedOptions(options, registrations, cliEndpointRoles);
      const documentationProducers = builtinDocs
        ? [...createDocumentationProducers(context)]
        : undefined;
      session = await createCompilerSession({
        projectRoot: options.projectRoot,
        schemaProviders: options.schemaProviders ?? [zodSchemaProvider],
        ...(documentationProducers
          ? { artifactProducers: documentationProducers }
          : {}),
      });
      const first = await session.compile();
      if (!first.result.ok)
        throw new ApplicationError(
          "CAP_APP_COMPILATION_FAILED",
          `Initial capability compilation failed: ${first.result.diagnostics
            .filter((entry) => entry.severity === "error")
            .map(
              (entry) => `${entry.code}@${entry.source.file}: ${entry.message}`,
            )
            .join(", ")}.`,
        );
      active = await buildGeneration(first.result, context);
      all.add(active);
      watcher = await watchCapabilities(
        { projectRoot: options.projectRoot },
        () => {
          refresh = refresh.then(async () => {
            if (closing || !session) return;
            try {
              // Resolve and validate a complete style snapshot before candidate compilation.
              if (documentationProducers)
                documentationProducers.splice(
                  0,
                  documentationProducers.length,
                  ...createDocumentationProducers(context),
                );
              const update = await session.compile();
              if (!update.result.ok) {
                diagnostic = "CAP_APP_COMPILATION_FAILED";
                return;
              }
              const candidate = await buildGeneration(update.result, context);
              if (closing) {
                await closeGeneration(candidate);
                return;
              }
              all.add(candidate);
              const prior = active;
              active = candidate;
              diagnostic = undefined;
              if (prior) {
                prior.retiring = true;
                if (prior.active === 0) await closeGeneration(prior);
              }
            } catch {
              diagnostic = "CAP_APP_COMPILATION_FAILED";
            }
          });
          return refresh;
        },
      );
    } else {
      active = await buildGeneration(loadedProduction!, context);
      all.add(active);
    }
  } catch (error) {
    await watcher?.close().catch(() => {});
    await session?.close().catch(() => {});
    for (const generation of all)
      await closeGeneration(generation).catch(() => {});
    await Promise.allSettled(
      preparedProviders.reverse().map((provider) => provider.close?.()),
    );
    throw error;
  }
  const middleware: Application["middleware"] = (req, res, next) => {
    let called = false;
    const proceed = (error?: Error) => {
      if (called) return;
      called = true;
      if (res.headersSent) {
        res.destroy();
        return;
      }
      if (next) {
        next(error);
        return;
      }
      res.statusCode = error ? 500 : 404;
      if (error) res.setHeader("content-type", "application/json");
      res.end(error ? JSON.stringify({ code: "CAP_INTERNAL" }) : "Not Found");
    };
    const generation = active;
    if (closing || !generation) {
      res.writeHead(503, {
        "content-type": "application/json",
        "cache-control": "no-store",
      });
      res.end(JSON.stringify({ code: "CAP_DEPENDENCY_UNAVAILABLE" }));
      return;
    }
    const record = { req, res };
    generation.active++;
    inFlight.add(record);
    void (async () => {
      try {
        if (generation.http && (await generation.http.handle(req, res))) return;
        if (generation.mcp && (await generation.mcp.handle(req, res))) return;
        for (const { registration, surface } of generation.extensions) {
          const route = registration.reservations.some(
            (item) =>
              (item.method === req.method ||
                (builtInCli !== undefined && registration.kind === "cli") ||
                (builtinDocs && registration.kind === "docs")) &&
              overlaps(
                builtinDocs && registration.kind === "docs"
                  ? documentationWirePath(join(context.basePath, item.path))
                  : join(context.basePath, item.path),
                (req.url ?? "/").split("?")[0]!,
              ),
          );
          if (route) {
            if (!(await surface.handle(req, res)))
              fail(
                "CAP_APP_MOUNT_INVALID",
                "Registered surface declined a reserved request.",
              );
            return;
          }
        }
        proceed();
      } catch (error) {
        proceed(
          error instanceof Error
            ? error
            : new ApplicationError(
                "CAP_INTERNAL",
                "Application request failed.",
              ),
        );
      } finally {
        inFlight.delete(record);
        generation.active--;
        if (inFlight.size === 0) {
          for (const wake of idleWaiters) wake();
          idleWaiters.clear();
        }
        if (generation.retiring && generation.active === 0)
          await closeGeneration(generation).catch(() => {});
      }
    })();
  };
  const close = (settings?: {
    readonly drainTimeoutMs?: number;
  }): Promise<void> => {
    if (closePromise) return closePromise;
    const timeout = settings?.drainTimeoutMs ?? 10000;
    if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 300000)
      return Promise.reject(
        new ApplicationError("CAP_APP_DRAIN_INVALID", "Invalid drain timeout."),
      );
    closing = true;
    closePromise = (async () => {
      const errors: unknown[] = [];
      const deadline = new Date(Date.now() + timeout);
      const bounded = async (pending: Promise<unknown>): Promise<void> => {
        const remaining = Math.max(1, deadline.getTime() - Date.now());
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          await Promise.race([
            pending,
            new Promise<never>((_resolve, reject) => {
              timer = setTimeout(
                () =>
                  reject(
                    new ApplicationError(
                      "CAP_APP_SHUTDOWN_FAILED",
                      "Application drain deadline expired.",
                    ),
                  ),
                remaining,
              );
            }),
          ]);
        } finally {
          if (timer) clearTimeout(timer);
        }
      };
      await bounded(
        Promise.allSettled([watcher?.close(), session?.close(), refresh]).then(
          (settled) =>
            settled.forEach((entry) => {
              if (entry.status === "rejected") errors.push(entry.reason);
            }),
        ),
      ).catch((error) => errors.push(error));
      const drained = Promise.allSettled(
        [...all].flatMap((generation) =>
          generation.extensions.map(({ surface }) =>
            surface.drain({ deadline, signal: controller.signal }),
          ),
        ),
      );
      const listenerDone = (async () => {
        await listenerStarting?.catch(() => {});
        if (!listener) return;
        await new Promise<void>((resolve, reject) => {
          listener!.close((error) => (error ? reject(error) : resolve()));
          listener!.closeIdleConnections();
        });
      })();
      const requestsDone =
        inFlight.size === 0
          ? Promise.resolve()
          : new Promise<void>((resolve) => idleWaiters.add(resolve));
      await bounded(
        Promise.allSettled([drained, listenerDone, requestsDone]),
      ).catch(() => {});
      if (inFlight.size) {
        controller.abort();
        for (const generation of all) generation.http?.abortActive();
        for (const { res } of inFlight) res.destroy();
      }
      await bounded(listenerDone).catch((error) => errors.push(error));
      await bounded(
        drained.then((settled) =>
          settled.forEach((entry) => {
            if (entry.status === "rejected") errors.push(entry.reason);
          }),
        ),
      ).catch((error) => errors.push(error));
      await bounded(
        Promise.allSettled(
          [...preparedProviders]
            .reverse()
            .map((provider) =>
              provider.drain?.({ deadline, signal: controller.signal }),
            ),
        ).then((settled) =>
          settled.forEach((entry) => {
            if (entry.status === "rejected") errors.push(entry.reason);
          }),
        ),
      ).catch((error) => errors.push(error));
      await bounded(
        Promise.allSettled(
          [...all].map((generation) => closeGeneration(generation)),
        ).then((settled) =>
          settled.forEach((entry) => {
            if (entry.status === "rejected") errors.push(entry.reason);
          }),
        ),
      ).catch((error) => errors.push(error));
      await bounded(
        Promise.allSettled(
          [...preparedProviders]
            .reverse()
            .map((provider) => provider.close?.()),
        ).then((settled) =>
          settled.forEach((entry) => {
            if (entry.status === "rejected") errors.push(entry.reason);
          }),
        ),
      ).catch((error) => errors.push(error));
      if (errors.length)
        fail("CAP_APP_SHUTDOWN_FAILED", "Application shutdown failed.");
    })();
    return closePromise;
  };
  return Object.freeze({
    get middleware() {
      if (
        options.surfaces.mcp?.enabled &&
        options.surfaces.mcp.allowedHosts === undefined &&
        context.externalUrl === undefined &&
        !listener
      )
        fail(
          "CAP_APP_MOUNT_INVALID",
          "Embedded MCP requires trusted allowedHosts or externalUrl.",
        );
      return middleware;
    },
    async listen(settings: {
      readonly host: string;
      readonly port: number;
    }): Promise<ApplicationListener> {
      if (listener || listenerStarting || closing)
        fail(
          "CAP_APP_LISTENER_UNAVAILABLE",
          "Application listener is already owned or closing.",
        );
      if (
        !settings.host ||
        !Number.isSafeInteger(settings.port) ||
        settings.port < 0 ||
        settings.port > 65535
      )
        fail("CAP_APP_MOUNT_INVALID", "Invalid listener settings.");
      const server = createServer(middleware);
      const starting = new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(settings.port, settings.host, () => {
          server.off("error", reject);
          listener = server;
          resolve();
        });
      });
      listenerStarting = starting;
      try {
        await starting;
      } catch (error) {
        server.close();
        throw error;
      } finally {
        listenerStarting = undefined;
      }
      if (closing)
        fail("CAP_APP_LISTENER_UNAVAILABLE", "Application is closing.");
      const address = server.address();
      if (!address || typeof address === "string")
        throw new ApplicationError(
          "CAP_APP_LISTENER_UNAVAILABLE",
          "Listener address unavailable.",
        );
      const host =
        isIP(settings.host) === 6 ? `[${settings.host}]` : settings.host;
      return Object.freeze({ url: `http://${host}:${address.port}`, close });
    },
    readiness() {
      const ready = !closing && !!active;
      return Object.freeze({
        ready,
        ...(active ? { generation: active.id } : {}),
        checks: Object.freeze([
          {
            id: "application",
            ready,
            ...(diagnostic ? { code: diagnostic } : {}),
          },
        ]),
      });
    },
    close,
  });
}
