import { resolve } from "node:path";
import {
  createOpenCliArtifactProducer,
  OPENCLI_SELECTOR,
} from "@capaxle/adapter-cli";
import { createOpenApiArtifactProducer } from "@capaxle/adapter-http";
import {
  DOCS_SCHEMA_DIAGNOSTIC_CODES,
  DOCS_SCHEMA_GENERATOR_VERSION,
  DOCS_SCHEMA_TARGET,
  generateDocsSchemaArchive,
} from "@capaxle/generator-docs";
import {
  createAgentManifestArtifactProducer,
  createMcpSnapshotArtifactProducer,
} from "@capaxle/adapter-mcp";
import { runFrameworkDev, type FrameworkDevDependencies } from "./dev.js";
import {
  compileProject,
  emitCompilerArtifacts,
  type ArtifactBuildContext,
  type CompilationDiagnostic,
  type CompilationResult,
  type CompilationSuccess,
  type CompilerArtifactProducer,
  type CompilerOptions,
  type EmissionResult,
} from "@capaxle/compiler";
import {
  generateInternalFacade,
  INTERNAL_FACADE_ARTIFACT_ID,
  INTERNAL_FACADE_ARTIFACT_PATH,
  INTERNAL_FACADE_DIAGNOSTIC_CODES,
  INTERNAL_FACADE_MEDIA_TYPE,
  INTERNAL_FACADE_PRODUCER_ID,
  INTERNAL_FACADE_PRODUCER_VERSION,
  INTERNAL_FACADE_TARGET,
  type InternalFacadeCapabilityDocument,
  generateSdkHttp,
  SDK_HTTP_ARTIFACT_ID,
  SDK_HTTP_ARTIFACT_PATH,
  SDK_HTTP_DIAGNOSTIC_CODES,
  SDK_HTTP_MEDIA_TYPE,
  SDK_HTTP_PRODUCER_ID,
  SDK_HTTP_PRODUCER_VERSION,
  SDK_HTTP_TARGET,
  type SdkHttpCapabilityDocument,
} from "@capaxle/generator-sdk-ts";
import { jcs, type JsonValue } from "@capaxle/ir";
import { zodSchemaProvider } from "@capaxle/schema-zod";
import {
  createRuntimeKernel,
  createRuntimeRegistry,
  type InvocationRequest,
} from "@capaxle/runtime";

export type FrameworkCommand =
  "check" | "build" | "list" | "describe" | "invoke" | "dev";
export type CommandDiagnosticCode =
  | "CAP_CLI_USAGE"
  | "CAP_CLI_COMMAND_UNKNOWN"
  | "CAP_CLI_CAPABILITY_NOT_FOUND"
  | "CAP_CLI_INTERNAL";
export type CommandDiagnosticReason =
  | "missing-command"
  | "unknown-command"
  | "unknown-option"
  | "duplicate-option"
  | "missing-option-value"
  | "option-not-allowed"
  | "missing-id"
  | "missing-input"
  | "extra-positional"
  | "invalid-option-value"
  | "invalid-id"
  | "capability-not-found"
  | "unexpected";

type ParseDetails =
  | { readonly reason: "missing-command" | "missing-id" | "missing-input" }
  | {
      readonly reason: "unknown-command" | "extra-positional" | "invalid-id";
      readonly token: string;
    }
  | {
      readonly reason:
        | "unknown-option"
        | "duplicate-option"
        | "missing-option-value"
        | "option-not-allowed"
        | "invalid-option-value";
      readonly option: string;
    };

export interface CommandDiagnostic {
  readonly code: CommandDiagnosticCode;
  readonly severity: "error";
  readonly phase: "command";
  readonly subphase: "parse" | "lookup" | "internal";
  readonly message: string;
  readonly argumentIndex?: number;
  readonly details:
    | ParseDetails
    | { readonly reason: "capability-not-found"; readonly id: string }
    | { readonly reason: "unexpected" };
}

export interface ParsedFrameworkCommand {
  readonly command: FrameworkCommand;
  readonly project?: string;
  readonly output?: string;
  readonly outputArgumentIndex?: number;
  readonly format?: string;
  readonly strict: boolean;
  readonly json: boolean;
  readonly id?: string;
  readonly idArgumentIndex?: number;
  /** JSON text supplied by the required invoke-only --input option. */
  readonly input?: string;
  readonly host?: string;
  readonly port?: number;
}

export type ParseResult =
  | { readonly ok: true; readonly value: ParsedFrameworkCommand }
  | {
      readonly ok: false;
      readonly command: string | null;
      readonly json: boolean;
      readonly diagnostics: readonly CommandDiagnostic[];
    };

export interface FrameworkCliDependencies {
  readonly cwd: () => string;
  readonly schemaProviders: CompilerOptions["schemaProviders"];
  readonly artifactProducers?: readonly CompilerArtifactProducer[];
  readonly openCliArtifactProducer?: CompilerArtifactProducer;
  readonly sdkHttpArtifactProducer?: CompilerArtifactProducer;
  readonly dev?: FrameworkDevDependencies;
  readonly compileProject: (
    options: CompilerOptions,
  ) => Promise<CompilationResult>;
  readonly emitCompilerArtifacts: (options: {
    readonly projectRoot: string;
    readonly compilation: CompilationSuccess;
    readonly outputDirectory?: string;
    readonly outputDiagnosticSource?: {
      readonly kind: "command-option";
      readonly command: "build";
      readonly option: "--output";
      readonly argumentIndex: number;
    };
  }) => Promise<EmissionResult>;
}

export interface FrameworkCliIo {
  readonly stdout: { write(value: string): unknown };
  readonly stderr: { write(value: string): unknown };
}

export function createInternalFacadeArtifactProducer(): CompilerArtifactProducer {
  return Object.freeze({
    id: INTERNAL_FACADE_PRODUCER_ID,
    version: INTERNAL_FACADE_PRODUCER_VERSION,
    staticInputs: Object.freeze({ contractVersion: "0.1" }),
    diagnosticCodes: INTERNAL_FACADE_DIAGNOSTIC_CODES,
    artifacts: Object.freeze([
      Object.freeze({
        id: INTERNAL_FACADE_ARTIFACT_ID,
        path: INTERNAL_FACADE_ARTIFACT_PATH,
        mediaType: INTERNAL_FACADE_MEDIA_TYPE,
        target: INTERNAL_FACADE_TARGET,
        dependencies: Object.freeze(["document:capability-ir" as const]),
        produce(context: Readonly<ArtifactBuildContext>) {
          const bytes = context.dependencyBytes.get("document:capability-ir");
          if (!bytes)
            return Object.freeze({
              ok: false as const,
              diagnostics: Object.freeze([
                Object.freeze({
                  code: "CAP_INTERNAL_FACADE_SCHEMA_UNREPRESENTABLE" as const,
                  severity: "error" as const,
                  message:
                    "The normalized Capability IR dependency is missing.",
                  target: INTERNAL_FACADE_TARGET,
                  path: "/",
                }),
              ]),
            });
          let document: InternalFacadeCapabilityDocument;
          try {
            document = JSON.parse(
              new TextDecoder().decode(bytes),
            ) as InternalFacadeCapabilityDocument;
          } catch {
            return Object.freeze({
              ok: false as const,
              diagnostics: Object.freeze([
                Object.freeze({
                  code: "CAP_INTERNAL_FACADE_SCHEMA_UNREPRESENTABLE" as const,
                  severity: "error" as const,
                  message:
                    "The normalized Capability IR dependency is invalid JSON.",
                  target: INTERNAL_FACADE_TARGET,
                  path: "/",
                }),
              ]),
            });
          }
          return generateInternalFacade({
            document,
            irHash: context.buildContext.irHash,
          });
        },
      }),
    ]),
  });
}

export function createSdkHttpArtifactProducer(): CompilerArtifactProducer {
  return Object.freeze({
    id: SDK_HTTP_PRODUCER_ID,
    version: SDK_HTTP_PRODUCER_VERSION,
    staticInputs: Object.freeze({ contractVersion: "0.1" }),
    diagnosticCodes: SDK_HTTP_DIAGNOSTIC_CODES,
    artifacts: Object.freeze([
      Object.freeze({
        id: SDK_HTTP_ARTIFACT_ID,
        path: SDK_HTTP_ARTIFACT_PATH,
        mediaType: SDK_HTTP_MEDIA_TYPE,
        target: SDK_HTTP_TARGET,
        dependencies: Object.freeze(["document:capability-ir" as const]),
        produce(context: Readonly<ArtifactBuildContext>) {
          const bytes = context.dependencyBytes.get("document:capability-ir");
          if (!bytes)
            return Object.freeze({
              ok: false as const,
              diagnostics: Object.freeze([
                Object.freeze({
                  code: "CAP_SDK_SCHEMA_UNREPRESENTABLE" as const,
                  severity: "error" as const,
                  message:
                    "The normalized Capability IR dependency is missing.",
                  target: SDK_HTTP_TARGET,
                  path: "/",
                }),
              ]),
            });
          let document: SdkHttpCapabilityDocument;
          try {
            document = JSON.parse(
              new TextDecoder("utf-8", { fatal: true }).decode(bytes),
            ) as SdkHttpCapabilityDocument;
          } catch {
            return Object.freeze({
              ok: false as const,
              diagnostics: Object.freeze([
                Object.freeze({
                  code: "CAP_SDK_SCHEMA_UNREPRESENTABLE" as const,
                  severity: "error" as const,
                  message:
                    "The normalized Capability IR dependency is invalid JSON.",
                  target: SDK_HTTP_TARGET,
                  path: "/",
                }),
              ]),
            });
          }
          return generateSdkHttp({
            document,
            irHash: context.buildContext.irHash,
          });
        },
      }),
    ]),
  });
}

export function createDocsSchemaArtifactProducer(
  options: Readonly<{
    profile?: "private" | "public";
    sensitiveRequirementNames?: readonly string[];
  }> = {},
): CompilerArtifactProducer {
  const profile = options.profile ?? "private";
  const sensitiveRequirementNames = Object.freeze([
    ...(options.sensitiveRequirementNames ?? []),
  ]);
  const target = DOCS_SCHEMA_TARGET;
  return Object.freeze({
    id: "capaxle.docs-schema-bundle",
    version: DOCS_SCHEMA_GENERATOR_VERSION,
    staticInputs: Object.freeze({ profile, sensitiveRequirementNames }),
    diagnosticCodes: Object.freeze(
      [...DOCS_SCHEMA_DIAGNOSTIC_CODES].sort().map((code) =>
        Object.freeze({
          code,
          severities: Object.freeze(["error" as const]),
        }),
      ),
    ),
    artifacts: Object.freeze([
      Object.freeze({
        id: "capaxle.docs-schema-bundle",
        path: "docs/capability-bundle.tar",
        mediaType: "application/x-tar",
        target,
        dependencies: Object.freeze(["document:capability-ir" as const]),
        produce(context: Readonly<ArtifactBuildContext>) {
          const bytes = context.dependencyBytes.get("document:capability-ir");
          if (!bytes)
            return Object.freeze({
              ok: false as const,
              diagnostics: Object.freeze([
                Object.freeze({
                  code: "CAP_DOCS_SCHEMA_INVALID" as const,
                  severity: "error" as const,
                  message:
                    "The normalized Capability IR dependency is missing.",
                  target,
                  path: "/",
                }),
              ]),
            });
          let document: Parameters<typeof generateDocsSchemaArchive>[0];
          try {
            document = JSON.parse(
              new TextDecoder().decode(bytes),
            ) as typeof document;
          } catch {
            return Object.freeze({
              ok: false as const,
              diagnostics: Object.freeze([
                Object.freeze({
                  code: "CAP_DOCS_SCHEMA_INVALID" as const,
                  severity: "error" as const,
                  message:
                    "The normalized Capability IR dependency is invalid JSON.",
                  target,
                  path: "/",
                }),
              ]),
            });
          }
          const generated = generateDocsSchemaArchive(document, {
            irHash: context.buildContext.irHash,
            profile,
            sensitiveRequirementNames,
            ...(context.buildContext.cliBinary === undefined
              ? {}
              : { cliBinary: context.buildContext.cliBinary }),
          });
          if (generated.ok)
            return Object.freeze({
              ok: true as const,
              bytes: generated.bytes,
              diagnostics: Object.freeze([]),
            });
          return Object.freeze({
            ok: false as const,
            diagnostics: Object.freeze(
              generated.diagnostics.map((diagnostic) =>
                Object.freeze({ ...diagnostic, target }),
              ),
            ),
          });
        },
      }),
    ]),
  });
}

type FrameworkEnvelope = Readonly<Record<string, JsonValue>>;
export interface FrameworkCliResult {
  readonly exitCode: 0 | 2 | 3 | 4 | 5 | 6 | 7 | 70 | 130;
  readonly json: boolean;
  readonly envelope: FrameworkEnvelope;
  readonly stdout: string;
  readonly diagnostics: readonly (CompilationDiagnostic | CommandDiagnostic)[];
}

const commands = new Set<FrameworkCommand>([
  "check",
  "build",
  "list",
  "describe",
  "invoke",
  "dev",
]);
const idPattern = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*$/;
const optionNames = new Set([
  "--project",
  "--output",
  "--format",
  "--strict",
  "--json",
  "--input",
  "--host",
  "--port",
]);

function commandDiagnostic(
  code: CommandDiagnosticCode,
  subphase: CommandDiagnostic["subphase"],
  message: string,
  details: CommandDiagnostic["details"],
  argumentIndex?: number,
): CommandDiagnostic {
  return Object.freeze({
    code,
    severity: "error",
    phase: "command",
    subphase,
    message,
    ...(argumentIndex === undefined ? {} : { argumentIndex }),
    details: Object.freeze(details),
  });
}

function parseIssue(
  details: ParseDetails,
  message: string,
  argumentIndex?: number,
): CommandDiagnostic {
  return commandDiagnostic(
    details.reason === "unknown-command"
      ? "CAP_CLI_COMMAND_UNKNOWN"
      : "CAP_CLI_USAGE",
    "parse",
    message,
    details,
    argumentIndex,
  );
}

function compareCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (item) => item.codePointAt(0)!);
  const rightPoints = Array.from(right, (item) => item.codePointAt(0)!);
  for (
    let index = 0;
    index < Math.min(leftPoints.length, rightPoints.length);
    index++
  ) {
    const difference = leftPoints[index]! - rightPoints[index]!;
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

function compareOptionalString(left?: string, right?: string): number {
  return compareCodePoints(left ?? "", right ?? "");
}

function sortCommandDiagnostics(
  diagnostics: readonly CommandDiagnostic[],
): readonly CommandDiagnostic[] {
  const subphaseRank = { parse: 0, lookup: 1, internal: 2 } as const;
  const sorted = [...diagnostics].sort((left, right) => {
    const phase = subphaseRank[left.subphase] - subphaseRank[right.subphase];
    if (phase !== 0) return phase;
    const leftIndex = left.argumentIndex ?? Number.POSITIVE_INFINITY;
    const rightIndex = right.argumentIndex ?? Number.POSITIVE_INFINITY;
    if (leftIndex !== rightIndex) return leftIndex - rightIndex;
    return (
      compareCodePoints(left.code, right.code) ||
      compareCodePoints(
        jcs(left.details as unknown as JsonValue),
        jcs(right.details as unknown as JsonValue),
      ) ||
      compareCodePoints(left.message, right.message)
    );
  });
  return Object.freeze(
    sorted.filter(
      (item, index) =>
        index === 0 ||
        jcs(item as unknown as JsonValue) !==
          jcs(sorted[index - 1] as unknown as JsonValue),
    ),
  );
}

export function parseFrameworkArguments(argv: readonly string[]): ParseResult {
  const commandToken = argv[0];
  if (commandToken === undefined) {
    return Object.freeze({
      ok: false,
      command: null,
      json: false,
      diagnostics: Object.freeze([
        parseIssue(
          { reason: "missing-command" },
          "A framework command is required.",
        ),
      ]),
    });
  }
  if (!commands.has(commandToken as FrameworkCommand)) {
    return Object.freeze({
      ok: false,
      command: commandToken,
      json: argv.slice(1).includes("--json"),
      diagnostics: Object.freeze([
        parseIssue(
          { reason: "unknown-command", token: commandToken },
          "The framework command is not recognized.",
          0,
        ),
      ]),
    });
  }

  const command = commandToken as FrameworkCommand;
  const diagnostics: CommandDiagnostic[] = [];
  const seen = new Set<string>();
  let project: string | undefined;
  let output: string | undefined;
  let outputArgumentIndex: number | undefined;
  let format: string | undefined;
  let input: string | undefined;
  let host: string | undefined;
  let port: number | undefined;
  let strict = false;
  let json = command === "invoke";
  let id: string | undefined;
  let idArgumentIndex: number | undefined;

  for (let index = 1; index < argv.length; index++) {
    const token = argv[index]!;
    if (token.startsWith("-")) {
      if (!optionNames.has(token)) {
        diagnostics.push(
          parseIssue(
            { reason: "unknown-option", option: token },
            "The framework option is not recognized.",
            index,
          ),
        );
        continue;
      }
      if (
        (token === "--output" && command !== "build") ||
        (token === "--format" && command !== "build") ||
        (token === "--input" && command !== "invoke") ||
        ((token === "--port" || token === "--host") && command !== "dev")
      ) {
        diagnostics.push(
          parseIssue(
            { reason: "option-not-allowed", option: token },
            "The option is not allowed for this command.",
            index,
          ),
        );
      }
      if (seen.has(token)) {
        diagnostics.push(
          parseIssue(
            { reason: "duplicate-option", option: token },
            "A framework option may occur at most once.",
            index,
          ),
        );
      }
      seen.add(token);
      if (token === "--strict" || token === "--json") {
        if (token === "--strict") strict = true;
        else json = true;
        continue;
      }
      const value = argv[index + 1];
      if (value === undefined) {
        diagnostics.push(
          parseIssue(
            { reason: "missing-option-value", option: token },
            "The framework option requires a value.",
            index,
          ),
        );
        continue;
      }
      if (token === "--project") project = value;
      else if (token === "--format") {
        format = value;
        if (value !== OPENCLI_SELECTOR && value !== SDK_HTTP_TARGET)
          diagnostics.push(
            parseIssue(
              { reason: "invalid-option-value", option: token },
              `The format must be ${OPENCLI_SELECTOR} or ${SDK_HTTP_TARGET}.`,
              index,
            ),
          );
      } else if (token === "--input") input = value;
      else if (token === "--host") {
        host = value;
        if (!value || value.startsWith("-"))
          diagnostics.push(
            parseIssue(
              { reason: "invalid-option-value", option: token },
              "The host must be a non-empty hostname or address.",
              index,
            ),
          );
      } else if (token === "--port") {
        if (!/^\d+$/.test(value) || Number(value) > 65535)
          diagnostics.push(
            parseIssue(
              { reason: "invalid-option-value", option: token },
              "The port must be an integer from 0 through 65535.",
              index,
            ),
          );
        else port = Number(value);
      } else {
        output = value;
        outputArgumentIndex = index;
      }
      index++;
      continue;
    }

    if ((command === "describe" || command === "invoke") && id === undefined) {
      id = token;
      idArgumentIndex = index;
      if (!idPattern.test(token)) {
        diagnostics.push(
          parseIssue(
            { reason: "invalid-id", token },
            "The capability ID is invalid.",
            index,
          ),
        );
      }
      continue;
    }
    diagnostics.push(
      parseIssue(
        { reason: "extra-positional", token },
        "The command has an extra positional argument.",
        index,
      ),
    );
  }
  if ((command === "describe" || command === "invoke") && id === undefined) {
    diagnostics.push(
      parseIssue(
        { reason: "missing-id" },
        `The ${command} command requires an ID.`,
      ),
    );
  }
  if (command === "invoke" && input === undefined && !seen.has("--input")) {
    diagnostics.push(
      parseIssue(
        { reason: "missing-input" },
        "The invoke command requires --input with a JSON value.",
      ),
    );
  }
  if (diagnostics.length > 0) {
    return Object.freeze({
      ok: false,
      command,
      json,
      diagnostics: sortCommandDiagnostics(diagnostics),
    });
  }
  return Object.freeze({
    ok: true,
    value: Object.freeze({
      command,
      ...(project === undefined ? {} : { project }),
      ...(output === undefined
        ? {}
        : { output, outputArgumentIndex: outputArgumentIndex! }),
      ...(format === undefined ? {} : { format }),
      strict,
      json,
      ...(input === undefined ? {} : { input }),
      ...(host === undefined ? {} : { host }),
      ...(port === undefined ? {} : { port }),
      ...(id === undefined ? {} : { id, idArgumentIndex: idArgumentIndex! }),
    }),
  });
}

const subphaseRanks = new Map(
  [
    "config-name",
    "config-load",
    "config-value",
    "discovery-root",
    "discovery-identity",
    "discovery-module-load",
    "discovery-module-export",
    "discovery-override",
    "discovery-duplicate",
    "discovery-watch",
    "authoring-descriptor",
    "schema-provider",
    "schema-portability",
    "schema-reference",
    "ir-structure",
    "ir-unsupported",
    "ir-identity",
    "ir-schema",
    "ir-policy",
    "ir-execution",
    "ir-projection",
    "ir-normalization",
    "projection-http",
    "projection-cli",
    "projection-mcp",
    "projection-docs",
    "projection-sdk",
    "projection-collision",
    "graph-input",
    "graph-dependency",
    "graph-cycle",
    "graph-execution",
    "emission-producer",
    "emission-stage",
    "emission-commit",
    "emission-cleanup",
  ].map((subphase, index) => [subphase, index]),
);
const severityRanks = { error: 0, warning: 1, info: 2 } as const;

function compareSource(
  left: CompilationDiagnostic["source"],
  right: CompilationDiagnostic["source"],
): number {
  return (
    compareCodePoints(left.file, right.file) ||
    left.line - right.line ||
    left.column - right.column ||
    (left.endLine ?? left.line) - (right.endLine ?? right.line) ||
    (left.endColumn ?? left.column) - (right.endColumn ?? right.column)
  );
}

function normalizedRelated(
  diagnostic: CompilationDiagnostic,
): NonNullable<CompilationDiagnostic["related"]> {
  return [...(diagnostic.related ?? [])].sort(
    (left, right) =>
      compareSource(left.source, right.source) ||
      compareOptionalString(left.path, right.path) ||
      compareCodePoints(left.message, right.message),
  );
}

function sortCompilationDiagnostics(
  diagnostics: readonly CompilationDiagnostic[],
): readonly CompilationDiagnostic[] {
  const normalized: CompilationDiagnostic[] = diagnostics.map((diagnostic) => {
    if (!diagnostic.related) return diagnostic;
    return {
      ...diagnostic,
      related: normalizedRelated(diagnostic),
    };
  });
  normalized.sort(
    (left, right) =>
      (subphaseRanks.get(left.subphase) ?? Number.POSITIVE_INFINITY) -
        (subphaseRanks.get(right.subphase) ?? Number.POSITIVE_INFINITY) ||
      compareSource(left.source, right.source) ||
      compareOptionalString(left.path, right.path) ||
      compareCodePoints(left.code, right.code) ||
      severityRanks[left.severity] - severityRanks[right.severity] ||
      compareCodePoints(
        jcs((left.details ?? null) as JsonValue),
        jcs((right.details ?? null) as JsonValue),
      ) ||
      compareCodePoints(left.message, right.message) ||
      compareOptionalString(left.remediation, right.remediation) ||
      compareCodePoints(
        jcs(normalizedRelated(left) as unknown as JsonValue),
        jcs(normalizedRelated(right) as unknown as JsonValue),
      ),
  );
  return Object.freeze(
    normalized.filter(
      (item, index) =>
        index === 0 ||
        jcs(item as unknown as JsonValue) !==
          jcs(normalized[index - 1] as unknown as JsonValue),
    ),
  );
}

function sortedDiagnostics(
  compilation: readonly CompilationDiagnostic[],
  command: readonly CommandDiagnostic[] = [],
): readonly (CompilationDiagnostic | CommandDiagnostic)[] {
  return Object.freeze([
    ...sortCompilationDiagnostics(compilation),
    ...sortCommandDiagnostics(command),
  ]);
}

function failure(
  command: string | null,
  exitCode: FrameworkCliResult["exitCode"],
  json: boolean,
  diagnostics: readonly (CompilationDiagnostic | CommandDiagnostic)[],
): FrameworkCliResult {
  return Object.freeze({
    exitCode,
    json,
    envelope: Object.freeze({
      command,
      ok: false,
      diagnostics,
    } as unknown as FrameworkEnvelope),
    stdout: "",
    diagnostics,
  });
}

function success(
  json: boolean,
  envelope: FrameworkEnvelope,
  stdout: string,
  diagnostics: readonly CompilationDiagnostic[],
): FrameworkCliResult {
  return Object.freeze({ exitCode: 0, json, envelope, stdout, diagnostics });
}

function capabilitiesOf(
  compilation: CompilationSuccess,
): readonly Record<string, JsonValue>[] {
  const document = compilation.document;
  if (
    typeof document !== "object" ||
    document === null ||
    Array.isArray(document)
  ) {
    throw new TypeError("Compiler returned an invalid document shape.");
  }
  const capabilities = (document as Readonly<Record<string, JsonValue>>)[
    "capabilities"
  ];
  if (
    !Array.isArray(capabilities) ||
    !capabilities.every(
      (item) =>
        typeof item === "object" && item !== null && !Array.isArray(item),
    )
  ) {
    throw new TypeError("Compiler returned an invalid document shape.");
  }
  return capabilities as readonly Record<string, JsonValue>[];
}

function strictFailure(
  compilation: CompilationSuccess,
  strict: boolean,
): boolean {
  return (
    strict &&
    compilation.diagnostics.some(({ severity }) => severity === "warning")
  );
}

function compileFailureExit(result: CompilationResult): 3 | 5 {
  const diagnostics = sortCompilationDiagnostics(result.diagnostics);
  const firstError = diagnostics.find(({ severity }) => severity === "error");
  return firstError?.subphase === "emission-producer" ? 5 : 3;
}

function invocationFailureExit(code: string): FrameworkCliResult["exitCode"] {
  if (code === "CAP_INPUT_INVALID") return 2;
  if (code === "CAP_UNAUTHENTICATED" || code === "CAP_PERMISSION_DENIED")
    return 3;
  if (
    code === "CAP_CONFIRMATION_REQUIRED" ||
    code === "CAP_CONFIRMATION_INVALID" ||
    code === "CAP_IDEMPOTENCY_KEY_REQUIRED" ||
    code === "CAP_IDEMPOTENCY_CONFLICT"
  )
    return 4;
  if (
    code === "CAP_RATE_LIMITED" ||
    code === "CAP_DEPENDENCY_UNAVAILABLE" ||
    code === "CAP_DEADLINE_EXCEEDED"
  )
    return 6;
  if (code === "CAP_CANCELLED") return 130;
  return code.startsWith("CAP_") ? 7 : 5;
}

export async function executeFrameworkCli(
  argv: readonly string[],
  dependencies: FrameworkCliDependencies,
  io?: FrameworkCliIo,
): Promise<FrameworkCliResult> {
  const parsed = parseFrameworkArguments(argv);
  if (!parsed.ok) {
    return failure(parsed.command, 2, parsed.json, parsed.diagnostics);
  }
  const options = parsed.value;
  let accumulatedCompilationDiagnostics: readonly CompilationDiagnostic[] = [];
  try {
    const projectRoot = resolve(dependencies.cwd(), options.project ?? ".");
    if (options.command === "dev") {
      return await runFrameworkDev(options, projectRoot, dependencies, io);
    }
    const artifactProducers =
      options.command !== "build"
        ? undefined
        : options.format === OPENCLI_SELECTOR
          ? Object.freeze([
              dependencies.openCliArtifactProducer ??
                createOpenCliArtifactProducer(),
            ])
          : options.format === SDK_HTTP_TARGET
            ? Object.freeze([
                dependencies.sdkHttpArtifactProducer ??
                  createSdkHttpArtifactProducer(),
              ])
            : dependencies.artifactProducers;
    const compilation = await dependencies.compileProject({
      projectRoot,
      schemaProviders: dependencies.schemaProviders,
      ...(artifactProducers === undefined ? {} : { artifactProducers }),
    });
    accumulatedCompilationDiagnostics = sortCompilationDiagnostics(
      compilation.diagnostics,
    );
    if (!compilation.ok) {
      return failure(
        options.command,
        compileFailureExit(compilation),
        options.json,
        sortCompilationDiagnostics(compilation.diagnostics),
      );
    }
    if (strictFailure(compilation, options.strict)) {
      return failure(
        options.command,
        3,
        options.json,
        sortCompilationDiagnostics(compilation.diagnostics),
      );
    }

    if (options.command === "invoke") {
      const registry = createRuntimeRegistry({
        document: compilation.document,
        irHash: compilation.irHash,
        bindings: compilation.runtimeBindings,
        validators: compilation.validators,
      });
      let adapterCandidate: InvocationRequest["adapterCandidate"];
      try {
        const input: unknown = JSON.parse(options.input!);
        if (
          typeof input !== "object" ||
          input === null ||
          Array.isArray(input)
        ) {
          adapterCandidate = {
            ok: false,
            code: "CAP_INPUT_INVALID",
            status: 400,
            safeDetails: { path: "/input", reason: "object-required" },
          };
        } else {
          adapterCandidate = { ok: true, input };
        }
      } catch {
        adapterCandidate = {
          ok: false,
          code: "CAP_INPUT_INVALID",
          status: 400,
          safeDetails: { path: "/input", reason: "invalid-json" },
        };
      }
      const result = await createRuntimeKernel({ registry }).invoke({
        capability: options.id!,
        source: "cli",
        adapterCandidate,
      });
      return Object.freeze({
        exitCode: result.ok ? 0 : invocationFailureExit(result.error.code),
        json: true,
        envelope: result as unknown as FrameworkEnvelope,
        stdout: "",
        diagnostics: Object.freeze([]),
      });
    }

    if (options.command === "check") {
      const diagnostics = sortCompilationDiagnostics(compilation.diagnostics);
      const envelope = Object.freeze({
        command: "check",
        ok: true,
        irHash: compilation.irHash,
        summary: Object.freeze({
          capabilities: capabilitiesOf(compilation).length,
          warnings: diagnostics.filter(({ severity }) => severity === "warning")
            .length,
          infos: diagnostics.filter(({ severity }) => severity === "info")
            .length,
        }),
        diagnostics,
      } as unknown as FrameworkEnvelope);
      return success(options.json, envelope, "", diagnostics);
    }

    if (options.command === "list") {
      const diagnostics = sortCompilationDiagnostics(compilation.diagnostics);
      const capabilities = [...compilation.registry.capabilities]
        .sort((left, right) => compareCodePoints(left.id, right.id))
        .map(({ id, version, summary, exposure }) => ({
          id,
          version,
          summary,
          exposure,
        }));
      const envelope = Object.freeze({
        command: "list",
        ok: true,
        irHash: compilation.irHash,
        capabilities,
        diagnostics,
      } as unknown as FrameworkEnvelope);
      return success(
        options.json,
        envelope,
        capabilities.map(({ id, version }) => `${id}@${version}\n`).join(""),
        diagnostics,
      );
    }

    if (options.command === "describe") {
      const diagnostics = sortCompilationDiagnostics(compilation.diagnostics);
      const capabilities = capabilitiesOf(compilation);
      const capability = capabilities.find((item) => item.id === options.id);
      const registryCapability = compilation.registry.capabilities.find(
        ({ id }) => id === options.id,
      );
      if (!capability || !registryCapability) {
        const lookup = commandDiagnostic(
          "CAP_CLI_CAPABILITY_NOT_FOUND",
          "lookup",
          "The capability ID was not found.",
          { reason: "capability-not-found", id: options.id! },
          options.idArgumentIndex,
        );
        return failure(
          "describe",
          4,
          options.json,
          sortedDiagnostics(diagnostics, [lookup]),
        );
      }
      const provenance = registryCapability.provenance;
      const envelope = Object.freeze({
        command: "describe",
        ok: true,
        irHash: compilation.irHash,
        capability,
        provenance,
        diagnostics,
      } as unknown as FrameworkEnvelope);
      const described = recursivelySorted({
        capability,
        provenance,
      } as unknown as JsonValue);
      return success(
        options.json,
        envelope,
        `${JSON.stringify(described, null, 2)}\n`,
        diagnostics,
      );
    }

    const emission = await dependencies.emitCompilerArtifacts({
      projectRoot,
      compilation,
      ...(options.output === undefined
        ? {}
        : {
            outputDirectory: options.output,
            outputDiagnosticSource: {
              kind: "command-option",
              command: "build",
              option: "--output",
              argumentIndex: options.outputArgumentIndex!,
            },
          }),
    });
    accumulatedCompilationDiagnostics = sortCompilationDiagnostics([
      ...compilation.diagnostics,
      ...emission.diagnostics,
    ]);
    const diagnostics = sortCompilationDiagnostics([
      ...compilation.diagnostics,
      ...emission.diagnostics,
    ]);
    if (!emission.ok) {
      return failure("build", 5, options.json, diagnostics);
    }
    const artifacts = [...emission.artifacts].sort((left, right) =>
      compareCodePoints(left.id, right.id),
    );
    const envelope = Object.freeze({
      command: "build",
      ok: true,
      buildId: emission.buildId,
      irHash: compilation.irHash,
      current: emission.current,
      artifacts,
      diagnostics,
    } as unknown as FrameworkEnvelope);
    return success(
      options.json,
      envelope,
      `${emission.current}\n`,
      diagnostics,
    );
  } catch {
    const diagnostic = commandDiagnostic(
      "CAP_CLI_INTERNAL",
      "internal",
      "The framework command failed unexpectedly.",
      { reason: "unexpected" },
    );
    return failure(
      options.command,
      70,
      options.json,
      sortedDiagnostics(accumulatedCompilationDiagnostics, [diagnostic]),
    );
  }
}

function recursivelySorted(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(recursivelySorted);
  if (typeof value !== "object" || value === null) return value;
  const record = value as Readonly<Record<string, JsonValue>>;
  return Object.fromEntries(
    Object.keys(record)
      .sort(compareCodePoints)
      .map((key) => [key, recursivelySorted(record[key]!)]),
  );
}

function singleLine(message: string): string {
  return message.replace(/[\r\n]+/gu, " ");
}

function humanDiagnostic(
  diagnostic: CompilationDiagnostic | CommandDiagnostic,
): string {
  if (diagnostic.phase === "command") {
    return `ERROR ${diagnostic.code} argv[${diagnostic.argumentIndex ?? "-"}]: ${singleLine(diagnostic.message)}\n`;
  }
  return `${diagnostic.severity.toUpperCase()} ${diagnostic.code} ${diagnostic.source.file}:${diagnostic.source.line}:${diagnostic.source.column} ${diagnostic.path ?? "-"}: ${singleLine(diagnostic.message)}\n`;
}

export function renderFrameworkResult(result: FrameworkCliResult): {
  readonly stdout: string;
  readonly stderr: string;
} {
  if (result.json) {
    return Object.freeze({
      stdout: `${jcs(result.envelope as unknown as JsonValue)}\n`,
      stderr: "",
    });
  }
  return Object.freeze({
    stdout: result.exitCode === 0 ? result.stdout : "",
    stderr: result.diagnostics.map(humanDiagnostic).join(""),
  });
}

export async function runFrameworkCli(
  argv: readonly string[],
  dependencies: FrameworkCliDependencies,
  io: FrameworkCliIo,
): Promise<FrameworkCliResult["exitCode"]> {
  const result = await executeFrameworkCli(argv, dependencies, io);
  const rendered = renderFrameworkResult(result);
  if (rendered.stdout) io.stdout.write(rendered.stdout);
  if (rendered.stderr) io.stderr.write(rendered.stderr);
  return result.exitCode;
}

export const defaultFrameworkCliDependencies: FrameworkCliDependencies =
  Object.freeze({
    cwd: () => process.cwd(),
    schemaProviders: Object.freeze([zodSchemaProvider]),
    artifactProducers: Object.freeze([
      createOpenApiArtifactProducer(),
      createMcpSnapshotArtifactProducer({
        profile: "private",
      }) as unknown as CompilerArtifactProducer,
      createAgentManifestArtifactProducer({
        profile: "private",
      }) as unknown as CompilerArtifactProducer,
      createInternalFacadeArtifactProducer(),
      createSdkHttpArtifactProducer(),
      createDocsSchemaArtifactProducer(),
    ]),
    openCliArtifactProducer: createOpenCliArtifactProducer(),
    sdkHttpArtifactProducer: createSdkHttpArtifactProducer(),
    compileProject,
    emitCompilerArtifacts,
  });
