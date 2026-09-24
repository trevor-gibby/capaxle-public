import type { Capability } from "@capaxle/core";

export type DiscoveryDiagnosticCode =
  | "CAP_CONFIG_LEGACY_NAME"
  | "CAP_CONFIG_NAME_CONFLICT"
  | "CAP_CONFIG_LOAD_FAILED"
  | "CAP_CONFIG_EXPORT_INVALID"
  | "CAP_CONFIG_DISCOVERY_INVALID"
  | "CAP_DISCOVERY_ROOT_INVALID"
  | "CAP_DISCOVERY_ID_INVALID"
  | "CAP_DISCOVERY_ID_OVERRIDE"
  | "CAP_DISCOVERY_ID_DUPLICATE"
  | "CAP_DISCOVERY_MODULE_LOAD_FAILED"
  | "CAP_DISCOVERY_MODULE_EXPORT_INVALID"
  | "CAP_DISCOVERY_WATCH_FAILED";

export interface SourceLocation {
  readonly file: string;
  readonly line: number;
  readonly column: number;
}

export interface RelatedLocation {
  readonly message: string;
  readonly source: SourceLocation;
}

export interface CompilerDiagnostic {
  readonly code:
    | DiscoveryDiagnosticCode
    | `CAP_AUTHORING_${string}`
    | "CAP_SCHEMA_NAME_INVALID";
  readonly severity: "error" | "warning";
  readonly message: string;
  readonly source: SourceLocation;
  readonly pointer?: string;
  readonly related?: readonly RelatedLocation[];
}

export interface ResolvedDiscoveryConfig {
  readonly projectRoot: string;
  readonly root: string;
  readonly ignore: readonly string[];
  readonly allowIdOverride: boolean;
  readonly configFile: "capaxle.config.ts" | null;
}

export type DiscoveryConfigResult =
  | {
      readonly ok: true;
      readonly config: ResolvedDiscoveryConfig;
      readonly diagnostics: readonly CompilerDiagnostic[];
    }
  | {
      readonly ok: false;
      readonly diagnostics: readonly CompilerDiagnostic[];
    };

export interface DiscoveredCapability {
  readonly id: string;
  readonly derivedId: string;
  readonly descriptor: Capability;
  readonly source: SourceLocation;
  readonly sourceHash: string;
}

export interface SuccessfulDiscoveryResult {
  readonly ok: true;
  readonly config: ResolvedDiscoveryConfig;
  readonly capabilities: readonly DiscoveredCapability[];
  readonly diagnostics: readonly CompilerDiagnostic[];
}

export interface FailedDiscoveryResult {
  readonly ok: false;
  readonly config?: ResolvedDiscoveryConfig;
  readonly capabilities: readonly [];
  readonly diagnostics: readonly CompilerDiagnostic[];
}

export type DiscoveryResult = SuccessfulDiscoveryResult | FailedDiscoveryResult;

export interface DiscoveryUpdate {
  readonly generation: number;
  readonly result: DiscoveryResult;
  readonly active?: SuccessfulDiscoveryResult;
  readonly stale: boolean;
}

export interface DiscoveryWatcher {
  readonly snapshot: DiscoveryUpdate;
  close(): Promise<void>;
}

export interface DiscoveryOptions {
  readonly projectRoot: string;
}

export type DiscoveryListener = (
  update: DiscoveryUpdate,
) => void | Promise<void>;
