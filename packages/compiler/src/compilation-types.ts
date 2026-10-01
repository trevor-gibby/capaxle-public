import type {
  ExposureLevel,
  RuntimeBindingHandle,
  RuntimeValidator,
  SchemaProvider,
} from "@capaxle/core";
import type { JsonSchema, JsonValue } from "@capaxle/ir";

export type Sha256 = `sha256:${string}`;
export type CompilationDiagnosticPhase =
  | "configuration"
  | "discovery"
  | "authoring"
  | "schema"
  | "ir"
  | "projection"
  | "graph"
  | "emission";

export type CompilationDiagnosticSubphase =
  | "config-name"
  | "config-load"
  | "config-value"
  | "discovery-root"
  | "discovery-identity"
  | "discovery-module-load"
  | "discovery-module-export"
  | "discovery-override"
  | "discovery-duplicate"
  | "discovery-watch"
  | "authoring-descriptor"
  | "schema-provider"
  | "schema-portability"
  | "schema-reference"
  | "ir-structure"
  | "ir-unsupported"
  | "ir-identity"
  | "ir-schema"
  | "ir-policy"
  | "ir-execution"
  | "ir-projection"
  | "ir-normalization"
  | "projection-http"
  | "projection-cli"
  | "projection-mcp"
  | "projection-docs"
  | "projection-sdk"
  | "projection-collision"
  | "graph-input"
  | "graph-dependency"
  | "graph-cycle"
  | "graph-execution"
  | "emission-producer"
  | "emission-stage"
  | "emission-commit"
  | "emission-cleanup";

export interface CompilationSourceLocation {
  readonly file: string;
  readonly line: number;
  readonly column: number;
  readonly endLine?: number;
  readonly endColumn?: number;
}

export interface CompilationDiagnostic {
  readonly code: `CAP_${string}`;
  readonly severity: "error" | "warning" | "info";
  readonly phase: CompilationDiagnosticPhase;
  readonly subphase: CompilationDiagnosticSubphase;
  readonly message: string;
  readonly path?: string;
  readonly source: CompilationSourceLocation;
  readonly related?: readonly {
    readonly message: string;
    readonly source: CompilationSourceLocation;
    readonly path?: string;
  }[];
  readonly remediation?: string;
  readonly details?: JsonValue;
}

export interface CompilerGraphNodeReport {
  readonly id: string;
  readonly dependencies: readonly string[];
  readonly status: "succeeded" | "reused" | "failed" | "blocked";
  readonly inputFingerprint?: Sha256;
  readonly outputDigest?: Sha256;
  readonly failureDiagnosticCodes?: readonly `CAP_${string}`[];
  readonly blockedByNodeIds?: readonly string[];
}

export interface CompilerGraphReport {
  readonly generation: number;
  readonly nodes: readonly CompilerGraphNodeReport[];
  readonly invalidatedNodeIds: readonly string[];
  readonly executedNodeIds: readonly string[];
  readonly changedNodeIds: readonly string[];
  readonly failedNodeIds: readonly string[];
  readonly blockedNodeIds: readonly string[];
  readonly removedNodeIds: readonly string[];
  readonly reusedNodeIds: readonly string[];
}

export interface ProvenanceEntry {
  readonly kind:
    | "author"
    | "application-default"
    | "compiler-default"
    | "inferred"
    | "projection-override";
  readonly source: CompilationSourceLocation;
  readonly sourcePath?: string;
  readonly rule?: string;
}

export interface ResolvedCompilerCapability {
  readonly id: string;
  readonly version: string;
  readonly summary: string;
  readonly source: { readonly file: string; readonly sourceHash: Sha256 };
  readonly exposure: Readonly<
    Record<"http" | "cli" | "mcp" | "internal", ExposureLevel>
  >;
  readonly interfaces: Readonly<Record<string, JsonValue>>;
  readonly provenance: Readonly<Record<string, ProvenanceEntry>>;
}

export type CapabilityDocument = Readonly<Record<string, JsonValue>> & {
  readonly irVersion: "0.1";
  readonly service: {
    readonly name: string;
    readonly version: string;
    readonly title?: string;
    readonly description?: string;
    readonly homepage?: string;
    readonly contact?: {
      readonly name?: string;
      readonly url?: string;
      readonly email?: string;
    };
    readonly tags: readonly string[];
  };
  readonly schemas: Readonly<Record<string, JsonSchema>>;
  readonly capabilities: readonly {
    readonly id: string;
    readonly version: string;
    readonly summary: string;
    readonly description?: string;
    readonly tags: readonly string[];
    readonly input: { readonly schema: JsonSchema } | { readonly $ref: string };
    readonly output:
      { readonly schema: JsonSchema } | { readonly $ref: string };
    readonly errors: Readonly<
      Record<
        string,
        {
          readonly status:
            | "invalid_argument"
            | "unauthenticated"
            | "permission_denied"
            | "not_found"
            | "already_exists"
            | "failed_precondition"
            | "conflict"
            | "resource_exhausted"
            | "cancelled"
            | "deadline_exceeded"
            | "unavailable"
            | "internal";
          readonly message: string;
          readonly retryable: boolean;
          readonly details?:
            { readonly schema: JsonSchema } | { readonly $ref: string };
        }
      >
    >;
    readonly access: {
      readonly authentication: "public" | "optional" | "required";
      readonly permissions:
        | { readonly public: true }
        | {
            readonly allOf?: readonly string[];
            readonly anyOf?: readonly string[];
          };
      readonly exposure: Readonly<
        Record<"http" | "cli" | "mcp" | "internal", ExposureLevel>
      >;
    };
    readonly effects: {
      readonly impact: "read" | "write" | "destructive";
      readonly idempotency: "none" | "intrinsic" | "key";
      readonly confirmation: "none" | "required";
      readonly retry: { readonly mode: "never" | "safe" };
    };
    readonly execution: {
      readonly mode: "inline";
      readonly result: "unary";
      readonly cancellable: false;
    };
    readonly requirements: {
      readonly secrets: readonly string[];
      readonly resources: readonly string[];
      readonly environment: readonly string[];
    };
    readonly limits: Readonly<Record<string, never>>;
    readonly lifecycle: { readonly status: "experimental" };
    readonly interfaces: {
      readonly http:
        | { readonly enabled: false }
        | {
            readonly enabled: true;
            readonly method:
              "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE";
            readonly path: string;
            readonly bindings: Readonly<
              Record<string, "path" | "query" | "header" | "body">
            >;
          };
      readonly cli:
        | { readonly enabled: false }
        | {
            readonly enabled: true;
            readonly command: readonly string[];
            readonly bindings: Readonly<Record<string, JsonValue>>;
          };
      readonly mcp:
        | { readonly enabled: false }
        | { readonly enabled: true; readonly toolName: string };
      readonly docs:
        | { readonly enabled: false }
        | { readonly enabled: true; readonly group?: string };
      readonly sdk:
        | { readonly enabled: false }
        | { readonly enabled: true; readonly path: readonly string[] };
    };
    readonly examples: readonly JsonValue[];
  }[];
  readonly metadata?: {
    readonly generator?: { readonly name: string; readonly version: string };
    readonly sourceHash?: string;
    readonly generatedAt?: string;
    readonly sourceRepository?: string;
  };
};

export interface ResolvedCompilerRegistry {
  readonly registryVersion: "0.1";
  readonly irVersion: "0.1";
  readonly irHash: Sha256;
  readonly capabilities: readonly ResolvedCompilerCapability[];
}

export interface RuntimeValidatorBindings {
  readonly input: RuntimeValidator;
  readonly output: RuntimeValidator;
  readonly errors: ReadonlyMap<string, RuntimeValidator>;
}

export type ProducerDependencyId =
  | "document:capability-ir"
  | `capability:${string}`
  | `schema:${string}`
  | `artifact:${string}`;

export interface ArtifactProducerDiagnostic {
  readonly code: `CAP_${string}`;
  readonly severity: "warning" | "error";
  readonly message: string;
  readonly target: string;
  readonly capabilityId?: string;
  readonly path?: string;
  readonly details?: JsonValue;
}

export type ArtifactProducerResult =
  | {
      readonly ok: true;
      readonly bytes: Uint8Array;
      readonly diagnostics: readonly ArtifactProducerDiagnostic[];
    }
  | {
      readonly ok: false;
      readonly diagnostics: readonly ArtifactProducerDiagnostic[];
    };

export interface ArtifactBuildContext {
  readonly buildContext: {
    readonly irHash: Sha256;
    readonly cliBinary?: string;
    readonly discovery: DiscoveryContext;
  };
  readonly producer: { readonly id: string; readonly version: string };
  readonly artifact: {
    readonly id: string;
    readonly path: string;
    readonly mediaType: string;
    readonly target: string;
  };
  readonly staticInputs: Readonly<Record<string, JsonValue>>;
  readonly dependencyDigests: ReadonlyMap<ProducerDependencyId, Sha256>;
  readonly dependencyBytes: ReadonlyMap<ProducerDependencyId, Uint8Array>;
}

export interface DiscoveryContext {
  readonly http: {
    readonly collection: string;
    readonly detailTemplate: string;
    readonly schemaTemplate: string;
  };
  readonly mcp: { readonly endpoint: string };
}

export interface RootPublicationBuildLocator {
  readonly artifactGraphVersion: "0.2";
  readonly buildId: Sha256;
  readonly index: string;
  readonly indexSha256: Sha256;
  readonly payloadArtifactId: string;
  readonly payloadSha256: Sha256;
}

export interface RootPublicationAssemblyContext {
  /** Defensive copy of the exact indexed payload bytes. */
  readonly payload: Uint8Array;
  /** Compiler-issued closed locator; assemblers cannot select paths or hashes. */
  readonly build: Readonly<RootPublicationBuildLocator>;
}

export interface CompilerRootPublication {
  readonly payloadArtifactId: string;
  readonly rootPath: string;
  readonly legacyPath: string;
  assemble(
    context: Readonly<RootPublicationAssemblyContext>,
  ): Promise<Uint8Array> | Uint8Array;
}

export interface CompilerArtifactProducer {
  readonly id: string;
  readonly version: string;
  readonly staticInputs?: Readonly<Record<string, JsonValue>>;
  readonly diagnosticCodes: readonly {
    readonly code: `CAP_${string}`;
    readonly severities: readonly ("warning" | "error")[];
  }[];
  readonly artifacts: readonly {
    readonly id: string;
    readonly path: string;
    readonly mediaType: string;
    readonly target: string;
    readonly dependencies: readonly ProducerDependencyId[];
    produce(
      context: Readonly<ArtifactBuildContext>,
    ): Promise<ArtifactProducerResult> | ArtifactProducerResult;
  }[];
  readonly rootPublication?: CompilerRootPublication;
}

export interface CompilerOptions {
  readonly projectRoot: string;
  readonly schemaProviders: readonly SchemaProvider<unknown>[];
  readonly artifactProducers?: readonly CompilerArtifactProducer[];
  /** Standalone publication requires a local executable for CLI projections. */
  readonly requireLocalCliBinary?: true;
}

export interface CompiledArtifact {
  readonly id: string;
  readonly path: string;
  readonly mediaType: string;
  readonly target: string;
  readonly producer: { readonly id: string; readonly version: string };
  /** Exact emitted artifact bytes. */
  readonly bytes: Uint8Array;
  /** Digest of this artifact's exact emitted bytes, not semantic IR identity. */
  readonly sha256: Sha256;
}

/** Framework-issued binding identity; never serialized into portable artifacts. */
export interface CompilerRuntimeBinding {
  readonly id: string;
  readonly version: string;
  readonly irHash: Sha256;
  readonly binding: RuntimeBindingHandle;
}

export interface CompilationSuccess {
  readonly ok: true;
  readonly document: CapabilityDocument;
  /** Exact serialized IR document bytes, including informative metadata. */
  readonly irBytes: Uint8Array;
  /** Semantic IR identity, excluding top-level informative metadata. */
  readonly irHash: Sha256;
  /** Resolved process-local transport discovery paths; excluded from Capability IR. */
  readonly discovery: DiscoveryContext;
  /** Process-local authoring mode; excluded from portable Capability IR. */
  readonly cliRemoteOnly?: true;
  readonly registry: ResolvedCompilerRegistry;
  readonly validators: ReadonlyMap<string, RuntimeValidatorBindings>;
  readonly runtimeBindings: ReadonlyMap<string, CompilerRuntimeBinding>;
  readonly artifacts: readonly CompiledArtifact[];
  /** Process-local publication request; never serialized into portable artifacts. */
  readonly rootPublication?: CompilerRootPublication;
  readonly graph: CompilerGraphReport;
  readonly diagnostics: readonly CompilationDiagnostic[];
}

export interface CompilationFailure {
  readonly ok: false;
  readonly graph: CompilerGraphReport;
  readonly diagnostics: readonly CompilationDiagnostic[];
}

export type CompilationResult = CompilationSuccess | CompilationFailure;
export interface CompilationUpdate {
  readonly generation: number;
  readonly result: CompilationResult;
  readonly active?: CompilationSuccess;
  readonly stale: boolean;
}
export interface CompilerSession {
  readonly snapshot: CompilationUpdate | undefined;
  compile(options?: {
    readonly changedPaths?: readonly string[];
  }): Promise<CompilationUpdate>;
  close(): Promise<void>;
}

export interface ArtifactIndexEntry {
  readonly id: string;
  readonly mediaType: string;
  readonly path: string;
  readonly sha256: Sha256;
  readonly target: string;
  readonly irVersion: "0.1";
  readonly irHash: Sha256;
  readonly service: { readonly name: string; readonly version: string };
  readonly producer: { readonly id: string; readonly version: string };
}

export type EmissionResult =
  | {
      readonly ok: true;
      readonly status: "committed";
      readonly durable: true;
      readonly buildId: Sha256;
      readonly current: string;
      readonly artifacts: readonly ArtifactIndexEntry[];
      readonly diagnostics: readonly CompilationDiagnostic[];
    }
  | {
      readonly ok: false;
      readonly status: "not-committed";
      readonly durable: false;
      readonly attemptedBuildId?: Sha256;
      readonly authoritativeBuildId?: Sha256;
      readonly diagnostics: readonly CompilationDiagnostic[];
    }
  | {
      readonly ok: false;
      readonly status: "commit-uncertain";
      readonly durable: false;
      readonly attemptedBuildId: Sha256;
      readonly observedBuildId?: Sha256;
      readonly diagnostics: readonly CompilationDiagnostic[];
    };
