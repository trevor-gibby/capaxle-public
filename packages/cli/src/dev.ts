import {
  createCompilerSession,
  watchCapabilities,
  type CompilationDiagnostic,
  type CompilationUpdate,
  type CompilerOptions,
  type CompilerSession,
  type DiscoveryListener,
  type DiscoveryOptions,
  type DiscoveryWatcher,
} from "@capaxle/compiler";
import { createHttpAdapter, startHttpHost } from "@capaxle/adapter-http";
import {
  createRuntimeKernel,
  createRuntimeRegistry,
  RuntimeConfigurationError,
  type RuntimeKernelOptions,
} from "@capaxle/runtime";
import { zodSchemaProvider } from "@capaxle/schema-zod";
import { createApplication } from "@capaxle/app";
import type {
  FrameworkCliDependencies,
  FrameworkCliIo,
  FrameworkCliResult,
  ParsedFrameworkCommand,
} from "./framework-cli.js";

export interface FrameworkDevSnapshot {
  readonly generation: number;
  readonly stale: boolean;
  readonly irHash?: string;
  readonly diagnostics: readonly CompilationDiagnostic[];
}
export interface FrameworkDevOptions extends CompilerOptions {
  readonly host?: string;
  readonly port?: number;
  readonly strict?: boolean;
  /** Existing runtime providers and registrations are supplied by the composition root. */
  readonly runtimeOptions?: Omit<RuntimeKernelOptions, "registry">;
  readonly adapterId?: string;
  readonly onUpdate?: (
    snapshot: FrameworkDevSnapshot,
    url: string | undefined,
  ) => void;
}
export interface FrameworkDevDependencies {
  readonly createCompilerSession: (
    options: CompilerOptions,
  ) => Promise<CompilerSession>;
  readonly watchCapabilities: (
    options: DiscoveryOptions,
    listener: DiscoveryListener,
  ) => Promise<DiscoveryWatcher>;
  readonly createHttpAdapter: typeof createHttpAdapter;
  readonly startHttpHost: typeof startHttpHost;
}
export interface FrameworkDevHost {
  readonly url: string;
  readonly snapshot: FrameworkDevSnapshot;
  close(): Promise<void>;
}

export class FrameworkDevStartError extends Error {
  readonly code = "CAP_CLI_DEV_START_FAILED";
  constructor(readonly diagnostics: readonly CompilationDiagnostic[]) {
    super("The development host could not start.");
    this.name = "FrameworkDevStartError";
  }
}

export const defaultFrameworkDevDependencies: FrameworkDevDependencies =
  Object.freeze({
    createCompilerSession,
    watchCapabilities,
    createHttpAdapter,
    startHttpHost,
  });

function lifecycleDiagnostic(error: unknown): CompilationDiagnostic {
  return Object.freeze({
    code:
      error instanceof RuntimeConfigurationError
        ? (error.code as `CAP_${string}`)
        : "CAP_CLI_DEV_START_FAILED",
    severity: "error",
    phase: "emission",
    subphase: "emission-producer",
    message: "The development host generation could not be activated.",
    source: Object.freeze({ file: ".", line: 1, column: 1 }),
  });
}

/** Publish an entire adapter/kernel generation only after all its construction succeeds. */
export async function startFrameworkDev(
  options: FrameworkDevOptions,
  dependencies: FrameworkDevDependencies = defaultFrameworkDevDependencies,
): Promise<FrameworkDevHost> {
  const session = await dependencies.createCompilerSession({
    projectRoot: options.projectRoot,
    schemaProviders: options.schemaProviders,
    ...(options.artifactProducers === undefined
      ? {}
      : { artifactProducers: options.artifactProducers }),
  });
  let watcher: DiscoveryWatcher | undefined;
  let host: Awaited<ReturnType<typeof startHttpHost>> | undefined;
  let closing = false;
  let closePromise: Promise<void> | undefined;
  let work: Promise<void> = Promise.resolve();
  let snapshot: FrameworkDevSnapshot = Object.freeze({
    generation: 0,
    stale: false,
    diagnostics: Object.freeze([]),
  });

  const close = (): Promise<void> => {
    if (closePromise) return closePromise;
    closing = true;
    closePromise = (async () => {
      // Stop observation and compilation and drain requests; finish every cleanup after a failure.
      const failures = await Promise.allSettled([
        watcher?.close(),
        session.close(),
        work,
        host?.close(),
      ]);
      if (failures.some((result) => result.status === "rejected"))
        throw new FrameworkDevStartError([lifecycleDiagnostic(undefined)]);
    })();
    return closePromise;
  };

  const publish = (
    update: CompilationUpdate,
    diagnostics: readonly CompilationDiagnostic[],
    activeHash?: string,
  ): void => {
    snapshot = Object.freeze({
      generation: update.generation,
      stale:
        activeHash !== undefined &&
        (!update.result.ok ||
          diagnostics.some(({ severity }) => severity === "error") ||
          (options.strict === true &&
            diagnostics.some(({ severity }) => severity === "warning"))),
      ...(activeHash === undefined ? {} : { irHash: activeHash }),
      diagnostics: Object.freeze([...diagnostics]),
    });
    // Reporting errors must never discard or roll back a valid running generation.
    try {
      options.onUpdate?.(snapshot, host?.url);
    } catch {
      /* Consumer callback. */
    }
  };

  const rebuild = async (): Promise<void> => {
    if (closing) return;
    const update = await session.compile();
    if (closing) return;
    if (
      !update.result.ok ||
      (options.strict === true &&
        update.result.diagnostics.some(
          ({ severity }) => severity === "warning",
        ))
    ) {
      publish(update, update.result.diagnostics, snapshot.irHash);
      return;
    }
    try {
      const compilation = update.result;
      const registry = createRuntimeRegistry({
        document: compilation.document,
        irHash: compilation.irHash,
        bindings: compilation.runtimeBindings,
        validators: compilation.validators,
      });
      const adapterId = options.adapterId ?? "capaxle.dev.http";
      const kernel = createRuntimeKernel({
        authenticationProviders: [
          { id: "capaxle.dev.anonymous", authenticate: () => null },
        ],
        adapters: [
          {
            id: adapterId,
            source: "http" as const,
            providerId: "capaxle.dev.anonymous",
            capabilities: registry.capabilities.map(({ id }) => id),
          },
        ],
        ...options.runtimeOptions,
        registry,
      });
      const ingress = kernel.createAdapterIngress(adapterId);
      // Only successful compilation authorizes these canonical fixed input carriers.
      const headerAllowlist = [
        ...new Set(
          compilation.document.capabilities.flatMap((capability) => {
            const http = capability.interfaces.http as unknown as {
              enabled: boolean;
              bindings: Readonly<Record<string, string>>;
            };
            return http.enabled
              ? Object.entries(http.bindings)
                  .filter(([, binding]) => binding === "header")
                  .map(([property]) => `x-cap-input-${property}`.toLowerCase())
              : [];
          }),
        ),
      ];
      const adapter = dependencies.createHttpAdapter({
        document: compilation.document,
        irHash: compilation.irHash,
        ingress,
        headerAllowlist,
      });
      if (host) host.update(adapter);
      else
        host = await dependencies.startHttpHost({
          adapter,
          ...(options.host === undefined ? {} : { host: options.host }),
          ...(options.port === undefined ? {} : { port: options.port }),
        });
      publish(update, compilation.diagnostics, compilation.irHash);
    } catch (error) {
      publish(
        update,
        [...update.result.diagnostics, lifecycleDiagnostic(error)],
        snapshot.irHash,
      );
    }
  };

  try {
    watcher = await dependencies.watchCapabilities(
      { projectRoot: options.projectRoot },
      (discovery) => {
        const lostObservation = discovery.result?.diagnostics.find(
          ({ code }) => code === "CAP_DISCOVERY_WATCH_FAILED",
        );
        if (lostObservation && !closing) {
          snapshot = Object.freeze({
            generation: snapshot.generation,
            stale: snapshot.irHash !== undefined,
            ...(snapshot.irHash === undefined
              ? {}
              : { irHash: snapshot.irHash }),
            diagnostics: Object.freeze([
              {
                code: lostObservation.code,
                severity: "error" as const,
                phase: "discovery" as const,
                subphase: "discovery-watch" as const,
                message: lostObservation.message,
                source: lostObservation.source,
              },
            ]),
          });
          try {
            options.onUpdate?.(snapshot, host?.url);
          } catch {
            /* Consumer callback. */
          }
          return work;
        }
        work = work.then(rebuild);
        return work;
      },
    );
    await work;
    if (!host) throw new FrameworkDevStartError(snapshot.diagnostics);
    return Object.freeze({
      get url() {
        return host!.url;
      },
      get snapshot() {
        return snapshot;
      },
      close,
    });
  } catch (error) {
    await close();
    throw error;
  }
}

export async function runFrameworkDev(
  options: ParsedFrameworkCommand,
  projectRoot: string,
  dependencies: FrameworkCliDependencies,
  io?: FrameworkCliIo,
): Promise<FrameworkCliResult> {
  let stop = false;
  let reported = false;
  let wake!: () => void;
  const stopped = new Promise<void>((resolve) => {
    wake = resolve;
  });
  const onSignal = (): void => {
    stop = true;
    wake();
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  let host: { close(): Promise<void> } | undefined;
  let devPoll: ReturnType<typeof setInterval> | undefined;
  try {
    if (
      dependencies.dev ||
      options.strict ||
      (dependencies.schemaProviders !== undefined &&
        (dependencies.schemaProviders.length !== 1 ||
          dependencies.schemaProviders[0] !== zodSchemaProvider))
    )
      host = await startFrameworkDev(
        {
          projectRoot,
          schemaProviders: dependencies.schemaProviders ?? [zodSchemaProvider],
          strict: options.strict,
          ...(options.host === undefined ? {} : { host: options.host }),
          ...(options.port === undefined ? {} : { port: options.port }),
          onUpdate: (snapshot, url) => {
            reported = io !== undefined;
            if (options.json)
              io?.stdout.write(
                `${JSON.stringify({ command: "dev", ok: snapshot.irHash !== undefined, url: url ?? null, ...snapshot })}\n`,
              );
            else {
              if (url)
                io?.stdout.write(
                  `Capaxle dev ${url}${snapshot.stale ? " (stale)" : ""}\n`,
                );
              for (const diagnostic of snapshot.diagnostics)
                io?.stderr.write(
                  `${diagnostic.severity.toUpperCase()} ${diagnostic.code} ${diagnostic.source.file}:${diagnostic.source.line}:${diagnostic.source.column}: ${diagnostic.message}\n`,
                );
            }
          },
        },
        dependencies.dev ?? defaultFrameworkDevDependencies,
      );
    else {
      const app = await createApplication({
        mode: "development",
        projectRoot,
        serviceId: "capaxle.dev",
        providers: {
          authenticationProviders: [
            { id: "capaxle.dev.anonymous", authenticate: () => null },
          ],
        },
        surfaces: {
          http: { enabled: true, providerId: "capaxle.dev.anonymous" },
          mcp: { enabled: true, providerId: "capaxle.dev.anonymous" },
        },
      });
      let listener;
      try {
        listener = await app.listen({
          host: options.host ?? "127.0.0.1",
          port: options.port ?? 3000,
        });
      } catch (error) {
        await app.close();
        throw error;
      }
      host = app;
      let lastGeneration: string | undefined;
      let lastCode: string | undefined;
      let generationNumber = 0;
      const report = (): void => {
        const readiness = app.readiness();
        const code = readiness.checks.find((check) => check.code)?.code;
        if (readiness.generation === lastGeneration && code === lastCode)
          return;
        if (readiness.generation !== lastGeneration) generationNumber++;
        lastGeneration = readiness.generation;
        lastCode = code;
        const diagnostics: readonly CompilationDiagnostic[] = code
          ? [
              {
                code: code as `CAP_${string}`,
                severity: "error",
                phase: "emission",
                subphase: "emission-producer",
                message:
                  "The development host retained its last valid generation.",
                source: { file: ".", line: 1, column: 1 },
              },
            ]
          : [];
        const snapshot = {
          generation: generationNumber,
          stale: code !== undefined,
          irHash: readiness.generation?.replace(/:\d+$/, ""),
          diagnostics,
        };
        reported = io !== undefined;
        if (options.json)
          io?.stdout.write(
            `${JSON.stringify({ command: "dev", ok: readiness.ready, url: listener.url, ...snapshot })}\n`,
          );
        else {
          io?.stdout.write(
            `Capaxle dev ${listener.url}${snapshot.stale ? " (stale)" : ""}\n`,
          );
          for (const diagnostic of diagnostics)
            io?.stderr.write(
              `${diagnostic.severity.toUpperCase()} ${diagnostic.code}: ${diagnostic.message}\n`,
            );
        }
      };
      report();
      devPoll = setInterval(report, 25);
      devPoll.unref();
    }
    if (!stop) await stopped;
    await host!.close();
    return Object.freeze({
      exitCode: 0,
      json: false,
      envelope: Object.freeze({ command: "dev", ok: true }),
      stdout: "",
      diagnostics: Object.freeze([]),
    });
  } catch (error) {
    const diagnostics =
      error instanceof FrameworkDevStartError
        ? error.diagnostics
        : [lifecycleDiagnostic(error)];
    return Object.freeze({
      exitCode: 3,
      json: options.json && !reported,
      envelope: Object.freeze({
        command: "dev",
        ok: false,
        diagnostics,
      }) as unknown as FrameworkCliResult["envelope"],
      stdout: "",
      diagnostics: reported ? Object.freeze([]) : diagnostics,
    });
  } finally {
    if (devPoll) clearInterval(devPoll);
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
    if (host) await host.close();
  }
}
