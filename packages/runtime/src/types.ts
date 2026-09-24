import type { ConfirmationProvider } from "./confirmation-types.js";
import type { IdempotencyProvider } from "./idempotency-types.js";
import type {
  RuntimeBindingHandle,
  RuntimeValidator,
  ErrorStatus,
  PrincipalSnapshot,
  IdentityContext,
} from "@capaxle/core";
import type { JsonValue, JsonSchema } from "@capaxle/ir";

export type RuntimeDocument = Readonly<Record<string, JsonValue>> & {
  readonly service: Readonly<{
    readonly name: string;
    readonly version: string;
  }>;
  readonly schemas: Readonly<Record<string, JsonSchema>>;
  readonly capabilities: readonly RuntimeCapability[];
};
export interface RuntimeCapability {
  readonly id: string;
  readonly version: string;
  readonly summary: string;
  readonly input: { readonly schema: JsonSchema } | { readonly $ref: string };
  readonly output: { readonly schema: JsonSchema } | { readonly $ref: string };
  readonly errors: Readonly<
    Record<
      string,
      {
        readonly status: ErrorStatus;
        readonly message: string;
        readonly retryable: boolean;
        readonly details?:
          { readonly schema: JsonSchema } | { readonly $ref: string };
      }
    >
  >;
  readonly access: {
    readonly authentication: "public" | "optional" | "required";
    readonly permissions: {
      readonly public?: true;
      readonly allOf?: readonly string[];
      readonly anyOf?: readonly string[];
    };
    readonly exposure: Readonly<
      Record<
        "http" | "cli" | "mcp" | "internal",
        "disabled" | "private" | "authenticated" | "public"
      >
    >;
  };
  readonly effects: {
    readonly impact: string;
    readonly idempotency: string;
    readonly confirmation: string;
  };
  readonly execution: {
    readonly timeoutMs?: number;
    readonly mode: string;
    readonly result: string;
  };
  readonly requirements: {
    readonly secrets: readonly unknown[];
    readonly resources: readonly unknown[];
    readonly environment: readonly unknown[];
  };
  readonly limits: Readonly<Record<string, unknown>>;
  readonly interfaces: Readonly<
    Record<"http" | "cli" | "mcp" | "sdk", { readonly enabled: boolean }>
  >;
}
export interface RuntimeBindingEntry {
  readonly id: string;
  readonly version: string;
  readonly irHash: string;
  readonly binding: RuntimeBindingHandle;
}
export interface RuntimeValidators {
  readonly input: RuntimeValidator;
  readonly output: RuntimeValidator;
  readonly errors: ReadonlyMap<string, RuntimeValidator>;
}
declare const registryBrand: unique symbol;
export interface RuntimeRegistry {
  readonly [registryBrand]: true;
  readonly irHash: string;
  readonly capabilities: readonly {
    readonly id: string;
    readonly version: string;
  }[];
}
export interface RuntimeRegistryOptions {
  readonly document: RuntimeDocument;
  readonly irHash: string;
  readonly bindings: ReadonlyMap<string, RuntimeBindingEntry>;
  readonly validators: ReadonlyMap<string, RuntimeValidators>;
}
export interface InvocationRequest {
  readonly capability: string;
  readonly version?: string;
  readonly input?: unknown;
  readonly source: "http" | "cli" | "mcp" | "internal" | "sdk";
  readonly correlationId?: string;
  readonly signal?: AbortSignal;
  readonly deadline?: Date;
  readonly principal?: unknown;
  readonly idempotencyKey?: string;
  readonly confirmationToken?: string;
  readonly metadata?: Readonly<Record<string, string>>;
  readonly adapterCandidate?: AdapterInvocationCandidate;
}
export interface AdapterInvocationControls {
  readonly confirmationToken?: string;
  readonly idempotencyKey?: string;
  readonly correlationId?: string;
  readonly timeoutMs?: number;
}
export type AdapterInvocationCandidate =
  | {
      readonly ok: true;
      readonly input: unknown;
      readonly controls?: AdapterInvocationControls;
    }
  | {
      readonly ok: false;
      readonly code: "CAP_INPUT_INVALID";
      /** @deprecated Use the canonical `invalid_argument` status. */
      readonly status: "invalid_argument" | 400;
      readonly safeDetails?: JsonValue;
    }
  | {
      readonly ok: false;
      readonly code: "CAP_MCP_CLIENT_METADATA_REQUIRED";
      readonly status: "failed_precondition";
      readonly safeDetails?: JsonValue;
    };
export type InvocationResult =
  | {
      readonly ok: true;
      readonly value: JsonValue;
      readonly correlationId: string;
    }
  | {
      readonly ok: false;
      readonly error: {
        readonly code: string;
        readonly status: ErrorStatus;
        readonly message: string;
        readonly retryable: boolean;
        readonly correlationId: string;
        readonly details?: JsonValue;
      };
    };
export interface RuntimeStageEvent {
  readonly stage: string;
  readonly skipped: boolean;
  readonly capability: string;
  readonly version: string;
  readonly source: InvocationRequest["source"];
  readonly correlationId: string;
}
export interface RuntimeTelemetryEvent {
  readonly kind: "completion" | "diagnostic";
  readonly code: string;
  readonly correlationId: string;
  readonly severity?: "error";
}
export interface RuntimeKernelOptions {
  readonly registry: RuntimeRegistry;
  readonly bearerDescriptors?: readonly unknown[];
  readonly confirmationProvider?: ConfirmationProvider;
  readonly idempotencyProvider?: IdempotencyProvider;
  readonly authenticationProviders?: readonly AuthenticationProvider[];
  readonly adapters?: readonly AdapterRegistration[];
  readonly authorizationProvider?: AuthorizationProvider;
  readonly identityFingerprintProvider?: IdentityFingerprintProvider;
  readonly internalInvocationSecurity?: InternalInvocationSecurityOptions;
  readonly disclosure?: "explicit" | "conceal";
  readonly maxInternalDepth?: number;
  readonly onStage?: (event: RuntimeStageEvent) => void;
  readonly telemetry?: (event: RuntimeTelemetryEvent) => void;
  readonly rateLimitProvider?: RateLimitProvider;
  readonly secretProvider?: SecretProvider;
  readonly failOpenPrivateReads?: readonly string[];
  readonly redactionPaths?: Readonly<Record<string, readonly string[]>>;
  readonly onTrace?: (event: RuntimeTraceEvent) => void;
  readonly onMetric?: (event: RuntimeMetricEvent) => void;
  readonly onLog?: (event: RuntimeLogEvent) => void;
}
export type RuntimeConfirmationDecisionResult =
  | {
      readonly ok: true;
      readonly outcome: "approved";
      readonly confirmationToken: string;
      readonly expiresAt: string;
      readonly correlationId: string;
    }
  | {
      readonly ok: true;
      readonly outcome: "denied";
      readonly correlationId: string;
    }
  | Extract<InvocationResult, { readonly ok: false }>;
export interface RuntimeKernel {
  invoke(request: InvocationRequest): Promise<InvocationResult>;
  createAdapterIngress(adapterId: string): AdapterIngress;
  decideConfirmation(
    command: {
      readonly challenge: unknown;
      readonly decision: unknown;
      readonly correlationId?: unknown;
    },
    approvalRequest: unknown,
  ): Promise<RuntimeConfirmationDecisionResult>;
}

export interface OperationView {
  readonly capability: Readonly<{
    id: string;
    version: string;
    access: RuntimeCapability["access"];
  }>;
  readonly identity: IdentityContext;
  readonly sourceChain: readonly Readonly<{
    source: InvocationRequest["source"];
    capability: string;
    exactVersion: string;
  }>[];
  readonly correlationId: string;
  readonly traceId: string;
  readonly spanId: string;
  readonly parentSpanId?: string;
  readonly deadlineMs: number;
  readonly signal: AbortSignal;
}
export interface InternalInvocationNode {
  readonly service: string;
  readonly capability: string;
  readonly exactVersion: string;
}
export interface InternalInvocationTrace {
  readonly traceId: string;
  readonly spanId: string;
  readonly parentSpanId: string;
}
export type InternalInvocationSourceEntry =
  OperationView["sourceChain"][number];
export type InternalInvocationTenant =
  | { readonly present: false }
  | { readonly present: true; readonly value: string };
export interface InternalInvocationTransitionView {
  readonly caller: InternalInvocationNode;
  readonly target: InternalInvocationNode;
  readonly mode: "derive" | "service";
  readonly policyId: string;
  readonly identity: IdentityContext;
  readonly tenant: InternalInvocationTenant;
  readonly service: string;
  readonly deployment: string;
  readonly sourceChain: readonly InternalInvocationSourceEntry[];
  readonly correlationId: string;
  readonly trace: InternalInvocationTrace;
  readonly deadlineMs: number;
  readonly signal: AbortSignal;
}
export type DeriveDecision =
  | { readonly allowed: false }
  | { readonly allowed: true; readonly principal: unknown };
export interface DerivePolicyRegistration {
  readonly id: string;
  readonly providerId: string;
  derive(
    view: Readonly<InternalInvocationTransitionView>,
  ): DeriveDecision | Promise<DeriveDecision>;
}
export interface ServicePolicyRegistration {
  readonly id: string;
  evaluate(
    view: Readonly<InternalInvocationTransitionView>,
  ): boolean | Promise<boolean>;
}
export interface ServiceIdentityProvider {
  readonly id: string;
  resolve(
    view: Readonly<InternalInvocationTransitionView>,
  ): unknown | Promise<unknown>;
}
export interface IdentityFingerprintSet {
  readonly generationId: string;
  readonly originatingFingerprint: string;
  readonly effectiveFingerprint: string;
  readonly requesterFingerprint: string;
  readonly tenantFingerprint: string;
}
export interface InternalInvocationOperationControls {
  readonly deadlineMs: number;
  readonly signal: AbortSignal;
}
export interface IdentityFingerprintProvider {
  readonly id: string;
  fingerprint(
    identity: Readonly<IdentityContext>,
    controls: Readonly<InternalInvocationOperationControls>,
  ): IdentityFingerprintSet | Promise<IdentityFingerprintSet>;
}
export interface InternalInvocationJournal {
  readonly id: string;
  commit(
    event: Readonly<InternalInvocationAuditEvent>,
    controls: Readonly<InternalInvocationOperationControls>,
  ): void | Promise<void>;
}
export interface InternalInvocationSecurityOptions {
  readonly deployment: string;
  readonly derivePolicies?: readonly DerivePolicyRegistration[];
  readonly servicePolicies?: readonly ServicePolicyRegistration[];
  readonly serviceIdentityProvider?: ServiceIdentityProvider;
  readonly journal?: InternalInvocationJournal;
}
export type InternalInvocationAuditReason =
  | "authority_chain_denied"
  | "derive_policy_absent"
  | "derive_policy_denied"
  | "derive_provider_failed"
  | "authorization_provider_failed"
  | "service_policy_absent"
  | "service_policy_denied"
  | "service_policy_failed"
  | "service_identity_unavailable"
  | "service_audit_unavailable"
  | "tenant_transition_forbidden"
  | "cycle_detected"
  | "depth_exceeded";
export type InternalInvocationAuditStage =
  | "cycle_check"
  | "depth_check"
  | "derive_policy"
  | "derive_identity"
  | "service_policy"
  | "service_identity"
  | "service_audit_identity"
  | "service_audit_fingerprint"
  | "service_audit_commit"
  | "service_identity_transition"
  | "authorization";
export interface InternalInvocationAuditBase {
  readonly eventId: string;
  readonly service: string;
  readonly ownerType: "internal_invocation";
  readonly ownerId: string;
  readonly transitionOrdinal: 1 | 2;
  readonly stage: InternalInvocationAuditStage;
  readonly policyId?: string;
  readonly caller: InternalInvocationNode;
  readonly target: InternalInvocationNode;
  readonly deployment: string;
  readonly trace: InternalInvocationTrace;
  readonly originatingFingerprint: string;
  readonly effectiveFingerprint: string;
  readonly requesterFingerprint: string;
  readonly tenantFingerprint: string;
  readonly fingerprintGenerationId: string;
  readonly sourceChain: readonly InternalInvocationSourceEntry[];
  readonly correlationId: string;
}
export type InternalInvocationAuditEvent =
  | (InternalInvocationAuditBase & {
      readonly eventType: "service_identity_assumed";
      readonly outcome: "allowed";
      readonly policyId: string;
      readonly transitionOrdinal: 1;
      readonly stage: "service_identity_transition";
    })
  | (InternalInvocationAuditBase & {
      readonly eventType: "internal_invocation_rejected";
      readonly outcome: "rejected" | "denied" | "unavailable";
      readonly reason: InternalInvocationAuditReason;
    });
export interface AuthenticationProvider {
  readonly id: string;
  readonly authenticate: (
    credentials: unknown,
    view: OperationView,
  ) => unknown | Promise<unknown>;
}
export type AuthorizationProvider = (
  view: OperationView,
  principal: PrincipalSnapshot,
) => boolean | Promise<boolean>;
export interface AdapterRegistration {
  readonly id: string;
  readonly source: InvocationRequest["source"];
  readonly providerId: string;
  readonly capabilities: readonly string[];
  readonly privateBoundary?: boolean;
}
declare const principalTokenBrand: unique symbol;
export interface PrincipalTrustToken {
  readonly [principalTokenBrand]: true;
}
export interface AdapterInvocationRequest extends Omit<
  InvocationRequest,
  "source" | "principal"
> {
  readonly credentials?: unknown;
  readonly principal?: PrincipalTrustToken;
}
export interface AdapterIngress {
  invoke(request: AdapterInvocationRequest): Promise<InvocationResult>;
  authenticate(
    capability: string,
    credentials: unknown,
    options?: { readonly deadline?: Date; readonly signal?: AbortSignal },
  ): Promise<PrincipalTrustToken>;
}

export interface RateLimitView extends OperationView {
  readonly policy: string;
  readonly cost: number;
}
export type RateLimitDecision =
  | { readonly allowed: true }
  | {
      readonly allowed: false;
      readonly retryAfterMs: number;
      readonly limit?: number;
      readonly remaining?: number;
      readonly resetAt?: string;
    };
export interface RateLimitProvider {
  readonly policies: readonly string[];
  readonly check: (view: RateLimitView) => unknown | Promise<unknown>;
}
export interface SecretProvider {
  readonly resolve: (
    name: string,
    view: OperationView,
  ) => unknown | Promise<unknown>;
}
export interface RuntimeMetricEvent {
  readonly capability: string;
  readonly version: string;
  readonly source: InvocationRequest["source"];
  readonly code: string;
  readonly durationMs: number;
}
export interface RuntimeTraceEvent extends RuntimeMetricEvent {
  readonly correlationId: string;
  readonly traceId: string;
  readonly spanId: string;
  readonly parentSpanId?: string;
}
export interface RuntimeLogEvent {
  readonly capability: string;
  readonly version: string;
  readonly source: InvocationRequest["source"];
  readonly correlationId: string;
  readonly traceId: string;
  readonly spanId: string;
  readonly level: "info" | "warn" | "error";
  readonly code: string;
}
