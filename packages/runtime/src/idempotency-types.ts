import type { IdentityContext } from "@capaxle/core";
import type { JsonValue } from "@capaxle/ir";
import type {
  ConfirmationOperationControls,
  ConfirmationProvider,
} from "./confirmation-types.js";

export interface IdempotencyAction {
  readonly capabilityId: string;
  readonly version: string;
  readonly irHash: string;
  readonly impact: string;
  readonly confirmation: string;
  readonly identity: Pick<
    IdentityContext,
    "originating" | "effective" | "authorityChain"
  >;
  readonly input: JsonValue;
  readonly key: string;
}
export type IdempotencyTerminal =
  | { readonly kind: "success"; readonly value: JsonValue }
  | {
      readonly kind: "declared_error" | "unexpected_error";
      readonly error: {
        readonly code: string;
        readonly status: string;
        readonly message: string;
        readonly retryable: boolean;
        readonly details?: JsonValue;
      };
    };
export interface IdempotencyConfirmation {
  readonly recordId: string;
  readonly confirmationRef: string;
  readonly executionAttemptId: string;
}
declare const claimBrand: unique symbol;
export interface IdempotencyClaim {
  readonly [claimBrand]: true;
  readonly index: string;
  readonly ownerId: string;
}
export type IdempotencyResult<T> =
  | ({ readonly ok: true } & T)
  | {
      readonly ok: false;
      readonly error: {
        readonly code: string;
        readonly status:
          | "failed_precondition"
          | "invalid_argument"
          | "unavailable"
          | "cancelled"
          | "deadline_exceeded";
        readonly message: string;
        readonly retryable: boolean;
      };
    };
export type IdempotencyInspection =
  | { readonly outcome: "absent" }
  | {
      readonly outcome: "replay";
      readonly terminal: IdempotencyTerminal;
      readonly confirmation?: IdempotencyConfirmation;
    };
export interface IdempotencyRecord {
  index: string;
  fingerprint: string;
  ownerId: string;
  requiresConfirmation: boolean;
  /** Keyed authentication of all persisted record fields. */
  integrityTag: string;
  state:
    | "CLAIMED"
    | "HANDLER_ENTRY_AUTHORIZED"
    | "COMPLETION_PENDING"
    | "COMPLETED"
    | "BLOCKED_TERMINAL"
    | "AMBIGUOUS";
  confirmation?: IdempotencyConfirmation;
  classification?: "succeeded" | "failed";
  /** Authenticated equality proof, retained even when failure payloads are not cached. */
  terminalDigest?: string;
  payload?: string;
  replayable?: boolean;
  completedAt?: number;
  resultExpiresAt?: number;
  keyExpiresAt?: number;
}
export interface IdempotencyState {
  service: string;
  deployment: string;
  timeFloor: number;
  records: Record<string, IdempotencyRecord>;
  ownerReservations: Record<string, true>;
}
export interface IdempotencyStore {
  /** Durable linearizable transaction: refresh cancellation and check the genuine
   * signal/deadline immediately at commit. No partial mutation on rejection. */
  atomic<T>(
    operation: (state: IdempotencyState) => T,
    controls?: ConfirmationOperationControls,
  ): Promise<T>;
}
export interface IdempotencyProviderOptions {
  readonly service: string;
  readonly deployment: string;
  readonly digestKey: Uint8Array;
  readonly store: IdempotencyStore;
  /** Host authenticated encryption at rest; never a plaintext identity codec. */
  readonly codec: {
    encrypt(value: JsonValue): Promise<string>;
    decrypt(payload: string): Promise<JsonValue>;
  };
  readonly policy: {
    readonly keyRetentionMs: number;
    readonly resultRetentionMs: number;
    readonly maxKeyBytes: number;
    readonly maxResultBytes: number;
    readonly maxPayloadBytes: number;
    readonly maxRecords: number;
    readonly maxOwnerReservations: number;
    readonly cacheDeclaredErrors: boolean;
    readonly cacheUnexpectedErrors: boolean;
  };
  readonly confirmationProvider?: Pick<
    ConfirmationProvider,
    "queryExecutionCompletion"
  >;
  /** Real host process/effect fencing. Owner comparison or lease expiry alone
   * cannot establish loss. This hook never authorizes another handler attempt. */
  readonly fenceLostOwner?: (ownerId: string) => Promise<boolean>;
  readonly clock?: () => number;
  readonly randomBytes?: (size: number) => Uint8Array;
}
export interface IdempotencyProvider {
  inspect(
    action: IdempotencyAction,
    controls?: ConfirmationOperationControls,
  ): Promise<IdempotencyResult<IdempotencyInspection>>;
  claim(
    action: IdempotencyAction,
    controls?: ConfirmationOperationControls,
  ): Promise<
    IdempotencyResult<
      | { outcome: "claimed"; claim: IdempotencyClaim }
      | Exclude<IdempotencyInspection, { outcome: "absent" }>
    >
  >;
  enter(
    claim: IdempotencyClaim,
    confirmation?: IdempotencyConfirmation,
    controls?: ConfirmationOperationControls,
  ): Promise<IdempotencyResult<Record<never, never>>>;
  release(
    claim: IdempotencyClaim,
  ): Promise<IdempotencyResult<Record<never, never>>>;
  complete(
    claim: IdempotencyClaim,
    terminal: IdempotencyTerminal,
  ): Promise<IdempotencyResult<Record<never, never>>>;
  reconcile(options?: {
    readonly lostOwnerIds?: readonly string[];
  }): Promise<IdempotencyResult<Record<never, never>>>;
}
