import type { JsonValue } from "@capaxle/ir";

interface ConfirmationActionBase {
  readonly irHash: string;
  readonly capabilityId: string;
  readonly version: string;
  readonly impact: string;
  readonly summary: string;
  readonly kernelInvocationId?: string;
  readonly input: JsonValue;
  readonly idempotencyKey?: string;
  readonly correlationId?: string;
  readonly sourceChain?: JsonValue;
}
export interface ConfirmationAction extends ConfirmationActionBase {
  readonly requesterFingerprint: string;
  readonly tenantFingerprint: string;
  readonly fingerprintGenerationId: string;
}
export interface ConfirmationError {
  readonly code: string;
  readonly status:
    | "failed_precondition"
    | "unavailable"
    | "unauthenticated"
    | "permission_denied"
    | "invalid_argument";
  readonly message: string;
  readonly retryable: boolean;
}
export type ConfirmationResult<T> =
  | ({ readonly ok: true } & T)
  | { readonly ok: false; readonly error: ConfirmationError };
export interface ConfirmationChallenge {
  readonly challenge: string;
  readonly capability: { readonly id: string; readonly version: string };
  readonly summary: string;
  readonly impact: string;
  readonly expiresAt: string;
}
declare const receiptBrand: unique symbol;
declare const attemptBrand: unique symbol;
export interface ConfirmationReceipt {
  readonly [receiptBrand]: true;
  readonly recordId: string;
  readonly confirmationRef: string;
}
export interface ConfirmationAttempt extends ConfirmationReceipt {
  readonly [attemptBrand]: true;
  readonly executionAttemptId: string;
}
export interface ConfirmationApprovalContext {
  readonly providerAuthenticated: boolean;
  readonly approvalAuthorized: boolean;
  readonly approverRef: string;
  readonly assurance: string;
}
/** Executable, independently authenticating host boundary. Never invocation assertions. */
export interface ConfirmationApprovalProvider {
  authenticate(
    request: unknown,
    challenge: Readonly<ConfirmationChallenge>,
  ): Promise<ConfirmationApprovalContext> | ConfirmationApprovalContext;
}
export type ConfirmationEventType =
  | "challenge_issued"
  | "approval_granted"
  | "approval_denied"
  | "challenge_expired"
  | "challenge_revoked"
  | "verification_rejected"
  | "evidence_consumed"
  | "generation_retired"
  | "generation_revoked"
  | "provider_failed"
  | "execution_audit_started"
  | "execution_audit_completed";
export interface ConfirmationEvent {
  readonly eventId: string;
  readonly eventType: ConfirmationEventType;
  readonly protocolVersion: "1";
  readonly occurredAt: number;
  readonly stage: string;
  readonly outcome: string;
  readonly service: string;
  readonly deployment: string;
  readonly ownerType:
    | "confirmation_record"
    | "execution_attempt"
    | "key_generation"
    | "kernel_invocation";
  readonly ownerId: string;
  readonly transitionOrdinal: number;
  readonly context: Readonly<Record<string, JsonValue>>;
}
export interface ConfirmationGeneration {
  id: string;
  key: Uint8Array;
  state: "ACTIVE" | "RETIRED" | "REVOKED";
  retired: boolean;
  revoked: boolean;
  quarantined: boolean;
  pendingTransition?: "RETIRED" | "REVOKED";
  ownerId: string;
}
export interface ConfirmationStoredAction {
  irHash: string;
  capabilityId: string;
  version: string;
  impact: string;
  summary: string;
  requesterFingerprint: string;
  tenantFingerprint: string;
  correlationId?: string;
  sourceChain?: JsonValue;
}
export interface ConfirmationRecord {
  id: string;
  confirmationRef: string;
  state: "PENDING" | "APPROVED" | "CONSUMED" | "DENIED" | "EXPIRED" | "REVOKED";
  challengeLookup: string;
  evidenceLookup?: string;
  challengeHandleGeneration: string;
  bindingFingerprintGeneration: string;
  evidenceHandleGeneration?: string;
  auditReferenceGeneration: string;
  bindingDigest: string;
  inputFingerprint: string;
  idempotencyFingerprint?: string;
  summaryDigest: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  purgeAt: number;
  action: ConfirmationStoredAction;
  approver?: ConfirmationApprovalContext;
  expiryEventId?: string;
  executionAttemptId?: string;
}
export interface ConfirmationExecution {
  id: string;
  recordId: string;
  state: "HANDLER_ENTRY_AUTHORIZED" | "COMPLETION_PENDING" | "COMPLETED";
  completion?: "succeeded" | "failed" | "ambiguous_after_handler_entry";
}
export interface ConfirmationState {
  service: string;
  deployment: string;
  timeFloor: number;
  unhealthy: boolean;
  unhealthyReason?: string;
  activeGeneration: string;
  generations: Record<string, ConfirmationGeneration>;
  records: Record<string, ConfirmationRecord>;
  challengeIndex: Record<string, string>;
  evidenceIndex: Record<string, string>;
  executions: Record<string, ConfirmationExecution>;
  randomReservations: Record<string, true>;
  pendingEvents: Record<string, ConfirmationEvent>;
  durableEvents: Record<string, true>;
  /** Retained authoritative journal completion proofs, independent of challenge purge. */
  completionProofs: Record<
    string,
    {
      recordId: string;
      confirmationRef: string;
      outcome: "succeeded" | "failed" | "ambiguous_after_handler_entry";
    }
  >;
}
/** Host MUST persist each atomic callback linearizably and durably across instances.
 * State, pendingEvents, timeFloor, reservations, quarantine and completion barriers
 * survive journal/export failure and process loss. No process-local production default.
 * commitJournal durably deduplicates by eventId; external export is separate.
 * incident uses storage-owned unique identity/time, never failed engine providers.
 */
export interface ConfirmationIncident {
  readonly service: string;
  readonly deployment: string;
  readonly protocolVersion: "1";
  readonly eventType: "provider_failed";
  readonly stage: "confirmation";
  readonly outcome: "unavailable";
  readonly providerKind: "confirmation" | "identity_fingerprint";
  readonly operation: string;
  readonly reason: string;
}
export interface IdentityFingerprintFailureIncident {
  readonly providerKind: "identity_fingerprint";
  readonly operation: "fingerprint";
  readonly reason:
    "provider_missing" | "provider_failed" | "provider_malformed";
}
export interface ConfirmationStore {
  /** Immediately before durable commit linearization, call trusted
   * refreshCancellation when present, then check the genuine private signal and
   * deadline. Reject queued canceled work without mutation/append. A commit
   * accepted while live may acknowledge later; never undo an accepted barrier.
   * This same checkpoint is mandatory for commitJournal. */
  atomic<T>(
    operation: (state: ConfirmationState) => T,
    controls?: ConfirmationOperationControls,
  ): Promise<T>;
  commitJournal(
    events: readonly ConfirmationEvent[],
    controls?: ConfirmationOperationControls,
  ): Promise<void>;
  /** Persists full provider_failed base event using storage-owned unique marker,
   * monotonic time and owner-derived cape1 ID independent of engine providers. */
  incident(
    incident: ConfirmationIncident,
    controls?: ConfirmationOperationControls,
  ): Promise<void>;
}
export interface ConfirmationProviderOptions {
  readonly store: ConfirmationStore;
  readonly bearerDescriptors?: readonly unknown[];
  readonly service: string;
  readonly deployment: string;
  readonly ttlMs: number;
  readonly maxClockSkewMs: number;
  readonly approvalProvider: ConfirmationApprovalProvider;
  readonly clock?: () => number;
  readonly randomBytes?: (length: number) => Uint8Array;
  readonly summaryRenderer?: {
    readonly pointers: readonly string[];
    readonly render: (leaves: Readonly<Record<string, JsonValue>>) => unknown;
  };
}
export interface ConfirmationOperationControls {
  /** Trusted kernel closure snapshots native caller/ancestor cancellation into
   * the private signal. Never accept this callback from an external carrier.
   * Engines and durable hosts call it before checking signal/deadline at every
   * pre-handler checkpoint and actual commit linearization. Throwing fails closed.
   * Post-entry completion and recovery do not inherit invocation controls. */
  readonly refreshCancellation?: () => void;
  readonly signal?: AbortSignal;
  readonly deadlineMs?: number;
  readonly kernelInvocationId?: string;
  readonly correlationId?: string;
}
export interface ConfirmationProvider {
  /** Optional independent ADR-0004 incident boundary. Implementations must not
   * derive incident identity or time from the failed fingerprint provider. */
  reportProviderFailure?(
    incident: Readonly<IdentityFingerprintFailureIncident>,
    controls?: ConfirmationOperationControls,
  ): void | Promise<void>;
  /** Read-only durable proof for the exact original attempt, reference and outcome.
   * Does not grant invocation trust, consume approval, or create execution. */
  queryExecutionCompletion(
    linkage: {
      readonly recordId: string;
      readonly confirmationRef: string;
      readonly executionAttemptId: string;
    },
    outcome: "succeeded" | "failed",
  ): Promise<ConfirmationResult<{ completed: boolean }>>;
  allocateKernelInvocationId(
    controls?: ConfirmationOperationControls,
  ): Promise<ConfirmationResult<{ kernelInvocationId: string }>>;
  issue(
    action: ConfirmationAction,
    controls?: ConfirmationOperationControls,
  ): Promise<ConfirmationResult<{ challenge: ConfirmationChallenge }>>;
  decideConfirmation(
    command: { readonly challenge: unknown; readonly decision: unknown },
    approvalRequest: unknown,
    controls?: ConfirmationOperationControls,
  ): Promise<
    ConfirmationResult<
      | { outcome: "approved"; confirmationToken: string; expiresAt: string }
      | { outcome: "denied" }
    >
  >;
  consume(
    action: ConfirmationAction,
    evidence: unknown,
    controls?: ConfirmationOperationControls,
  ): Promise<ConfirmationResult<{ receipt: ConfirmationReceipt }>>;
  beginExecution(
    receipt: ConfirmationReceipt,
    controls?: ConfirmationOperationControls,
  ): Promise<ConfirmationResult<{ attempt: ConfirmationAttempt }>>;
  completeExecution(
    attempt: ConfirmationAttempt,
    outcome: "succeeded" | "failed",
  ): Promise<ConfirmationResult<Record<never, never>>>;
  transitionGeneration(
    id: string,
    transition: "RETIRED" | "REVOKED",
  ): Promise<ConfirmationResult<Record<never, never>>>;
  revoke(challenge: unknown): Promise<ConfirmationResult<Record<never, never>>>;
  /** Recovery caller must fence listed lost attempts against their original process. */
  reconcile(options?: {
    readonly lostExecutionAttemptIds?: readonly string[];
  }): Promise<ConfirmationResult<Record<never, never>>>;
  health(): Promise<boolean>;
}
