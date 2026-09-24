import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { RuntimeConfigurationError, ownData } from "./registry.js";
import {
  compileBearerDescriptors,
  type CompiledBearerGuard,
} from "./ingress.js";
import { decodeCanonicalBase64Url256 } from "./base64url.js";
import { jcs, type JsonValue } from "@capaxle/ir";
import type {
  ConfirmationAction,
  ConfirmationApprovalContext,
  ConfirmationAttempt,
  ConfirmationChallenge,
  ConfirmationEvent,
  ConfirmationEventType,
  ConfirmationGeneration,
  ConfirmationIncident,
  ConfirmationProvider,
  ConfirmationProviderOptions,
  ConfirmationReceipt,
  ConfirmationOperationControls,
  ConfirmationRecord,
  ConfirmationResult,
  ConfirmationState,
} from "./confirmation-types.js";

const MAX_TIME = 253402300799999;
const actionKeys = [
  "irHash",
  "capabilityId",
  "version",
  "impact",
  "summary",
  "requesterFingerprint",
  "tenantFingerprint",
  "fingerprintGenerationId",
  "kernelInvocationId",
  "input",
  "idempotencyKey",
  "correlationId",
  "sourceChain",
] as const;
class Failure extends Error {
  constructor(readonly reason: string) {
    super("Confirmation dependency unavailable.");
  }
}
class Invalid extends Error {
  constructor(readonly audited = false) {
    super("Confirmation evidence is invalid.");
  }
}
class Interrupted extends Error {
  constructor(readonly code: "CAP_CANCELLED" | "CAP_TIMEOUT") {
    super("Confirmation interrupted.");
  }
}
const unavailable = (retryable = true): ConfirmationResult<never> => ({
  ok: false,
  error: {
    code: "CAP_DEPENDENCY_UNAVAILABLE",
    status: "unavailable",
    message: "Confirmation dependency unavailable.",
    retryable,
  },
});
const invalid = (): ConfirmationResult<never> => ({
  ok: false,
  error: {
    code: "CAP_CONFIRMATION_INVALID",
    status: "failed_precondition",
    message: "Confirmation evidence is invalid.",
    retryable: false,
  },
});
function digest(value: unknown): Buffer {
  try {
    return decodeCanonicalBase64Url256(value);
  } catch {
    throw new Invalid();
  }
}
function persisted(value: unknown): Buffer {
  try {
    return digest(value);
  } catch {
    throw new Failure("noncanonical_stored_digest");
  }
}
const hash = (value: JsonValue): string =>
  createHash("sha256").update(jcs(value)).digest("base64url");
function keyed(key: Uint8Array, domain: string, value: string): string {
  const subkey = createHmac("sha256", key)
    .update(`capaxle.confirmation.v1.${domain}`)
    .digest();
  return createHmac("sha256", subkey).update(value, "utf8").digest("base64url");
}
function generation(
  state: ConfirmationState,
  id: string,
  active = false,
  permitTerminalTransition = false,
): ConfirmationGeneration {
  let g: ConfirmationGeneration;
  let data: Record<string, unknown>;
  try {
    const entries = ownData(state.generations);
    g = entries[id] as ConfirmationGeneration;
    data = ownData(g, [
      "id",
      "key",
      "state",
      "retired",
      "revoked",
      "quarantined",
      "ownerId",
      "pendingTransition",
    ]);
  } catch {
    throw new Failure("generation_integrity");
  }
  if (
    data.id !== id ||
    typeof data.retired !== "boolean" ||
    typeof data.revoked !== "boolean" ||
    typeof data.quarantined !== "boolean" ||
    !(data.key instanceof Uint8Array) ||
    data.key.length !== 32 ||
    !Uint8Array.prototype.some.call(data.key, (v: number) => v !== 0) ||
    !["ACTIVE", "RETIRED", "REVOKED"].includes(data.state as string) ||
    data.retired !== (data.state === "RETIRED") ||
    data.revoked !== (data.state === "REVOKED") ||
    (Object.hasOwn(data, "pendingTransition") &&
      !["RETIRED", "REVOKED"].includes(data.pendingTransition as string))
  )
    throw new Failure("generation_integrity");
  persisted(data.ownerId);
  if (
    g.quarantined ||
    g.revoked ||
    (active && (g.state !== "ACTIVE" || id !== state.activeGeneration))
  ) {
    if (active) throw new Failure("active_generation_unavailable");
    if (!permitTerminalTransition) throw new Invalid();
  }
  return g;
}
function safeSummary(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value) > 512 ||
    /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u.test(
      value,
    )
  )
    return false;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = value.charCodeAt(++i);
      if (!(n >= 0xdc00 && n <= 0xdfff)) return false;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}
function bearerGuardPointer(
  pointer: string,
  guard: CompiledBearerGuard,
): boolean {
  return (
    (pointer !== "" && !/^\/(?:[^~]|~[01])*$/.test(pointer)) ||
    guard.detects(pointer)
  );
}
function summary(
  action: ConfirmationAction,
  options: ConfirmationProviderOptions,
  guard: CompiledBearerGuard,
): string {
  if (!safeSummary(action.summary) || guard.detects(action.summary))
    throw new Failure("invalid_canonical_summary");
  if (!options.summaryRenderer) return action.summary;
  try {
    const leaves: Record<string, JsonValue> = Object.create(null) as Record<
      string,
      JsonValue
    >;
    for (const pointer of options.summaryRenderer.pointers) {
      if (bearerGuardPointer(pointer, guard)) continue;
      let value: JsonValue | undefined = action.input;
      for (const part of pointer === "" ? [] : pointer.slice(1).split("/")) {
        const key = part.replace(/~1/g, "/").replace(/~0/g, "~");
        if (!value || typeof value !== "object" || !Object.hasOwn(value, key)) {
          value = undefined;
          break;
        }
        value = (value as Record<string, JsonValue>)[key];
      }
      if (
        value === null ||
        ["string", "number", "boolean"].includes(typeof value)
      )
        if (typeof value !== "string" || !guard.detects(value))
          leaves[pointer] = value as JsonValue;
    }
    const rendered = options.summaryRenderer.render(Object.freeze(leaves));
    return safeSummary(rendered) && !guard.detects(rendered)
      ? rendered
      : action.summary;
  } catch {
    return action.summary;
  }
}
/** Initializes data for a host's durable store; this is not a persistence implementation.
 * Keys and generation owner IDs must be securely provisioned by the host. */
export function createConfirmationState(
  service: string,
  deployment: string,
  generations: readonly ConfirmationGeneration[],
  activeGeneration: string,
): ConfirmationState {
  const state: ConfirmationState = {
    service,
    deployment,
    timeFloor: 0,
    unhealthy: false,
    activeGeneration,
    generations: Object.create(null) as Record<string, ConfirmationGeneration>,
    records: Object.create(null) as Record<string, ConfirmationRecord>,
    challengeIndex: Object.create(null) as Record<string, string>,
    evidenceIndex: Object.create(null) as Record<string, string>,
    executions: Object.create(null) as ConfirmationState["executions"],
    randomReservations: Object.create(null) as Record<string, true>,
    pendingEvents: Object.create(null) as Record<string, ConfirmationEvent>,
    durableEvents: Object.create(null) as Record<string, true>,
    completionProofs: Object.create(
      null,
    ) as ConfirmationState["completionProofs"],
  };
  for (const g of generations) {
    if (
      !/^[A-Za-z0-9_-]{1,32}$/.test(g.id) ||
      Object.hasOwn(state.generations, g.id)
    )
      throw new RuntimeConfigurationError(
        "CAP_CONFIRMATION_CONFIGURATION_INVALID",
      );
    persisted(g.ownerId);
    if (Object.hasOwn(state.randomReservations, g.ownerId))
      throw new RuntimeConfigurationError(
        "CAP_CONFIRMATION_CONFIGURATION_INVALID",
      );
    state.generations[g.id] = { ...g, key: new Uint8Array(g.key) };
    state.randomReservations[g.ownerId] = true;
  }
  generation(state, activeGeneration, true);
  return state;
}

export function createConfirmationProvider(
  options: ConfirmationProviderOptions,
): ConfirmationProvider {
  const { store } = options;
  const bearerGuard = compileBearerDescriptors(options.bearerDescriptors);
  if (
    !store ||
    typeof store.atomic !== "function" ||
    typeof store.commitJournal !== "function" ||
    typeof store.incident !== "function" ||
    !options.service ||
    !options.deployment ||
    !Number.isSafeInteger(options.ttlMs) ||
    options.ttlMs <= 0 ||
    options.ttlMs > 300000 ||
    !Number.isSafeInteger(options.maxClockSkewMs) ||
    options.maxClockSkewMs < 0 ||
    options.maxClockSkewMs > 30000 ||
    !options.approvalProvider ||
    typeof options.approvalProvider.authenticate !== "function"
  )
    throw new RuntimeConfigurationError(
      "CAP_CONFIRMATION_CONFIGURATION_INVALID",
    );
  const random = options.randomBytes ?? randomBytes;
  const clock = options.clock ?? Date.now;
  const receipts = new WeakSet<ConfirmationReceipt>();
  const attempts = new WeakSet<ConfirmationAttempt>();
  const pendingCompletions = new Map<
    string,
    { attempt: ConfirmationAttempt; outcome: "succeeded" | "failed" }
  >();

  function checked(state: ConfirmationState): void {
    if (
      state.service !== options.service ||
      state.deployment !== options.deployment ||
      !Number.isSafeInteger(state.timeFloor) ||
      state.timeFloor < 0 ||
      state.timeFloor > MAX_TIME ||
      !state.completionProofs ||
      typeof state.completionProofs !== "object"
    )
      throw new Failure("store_integrity");
    if (
      state.unhealthy &&
      ![
        "journal_unavailable",
        "store_unavailable",
        "post_handler_persistence_unavailable",
      ].includes(state.unhealthyReason ?? "")
    )
      throw new Failure("provider_unhealthy");
  }
  function unique(state: ConfirmationState): string {
    let value: Uint8Array;
    try {
      value = random(32);
    } catch {
      throw new Failure("random_unavailable");
    }
    if (
      !(value instanceof Uint8Array) ||
      value.length !== 32 ||
      !value.some((v) => v !== 0)
    )
      throw new Failure("random_invalid");
    const id = Buffer.from(value).toString("base64url");
    if (Object.hasOwn(state.randomReservations, id))
      throw new Failure("random_collision");
    state.randomReservations[id] = true;
    return id;
  }
  function now(state: ConfirmationState): number {
    let raw: number;
    try {
      raw = clock();
    } catch {
      throw new Failure("clock_unavailable");
    }
    if (
      !Number.isSafeInteger(raw) ||
      raw < -8640000000000000 ||
      raw > 8640000000000000
    )
      throw new Failure("clock_invalid");
    const effective = Math.max(raw, state.timeFloor);
    if (effective > MAX_TIME) throw new Failure("derived_time_out_of_range");
    state.timeFloor = effective;
    return effective;
  }
  function event(
    state: ConfirmationState,
    eventType: ConfirmationEventType,
    ownerType: ConfirmationEvent["ownerType"],
    ownerId: string,
    transitionOrdinal: number,
    occurredAt: number,
    context: Record<string, JsonValue> = {},
  ): string {
    const eventId = `cape1.${hash({ service: options.service, deployment: options.deployment, ownerType, ownerId, eventType, transitionOrdinal })}`;
    if (!state.durableEvents[eventId] && !state.pendingEvents[eventId])
      state.pendingEvents[eventId] = {
        eventId,
        eventType,
        protocolVersion: "1",
        occurredAt,
        stage: "confirmation",
        outcome: eventType,
        service: options.service,
        deployment: options.deployment,
        ownerType,
        ownerId,
        transitionOrdinal,
        context,
      };
    return eventId;
  }
  function context(record: ConfirmationRecord): Record<string, JsonValue> {
    return {
      confirmationRef: record.confirmationRef,
      capabilityId: record.action.capabilityId,
      version: record.action.version,
      irHash: record.action.irHash,
      impact: record.action.impact,
      requesterFingerprint: record.action.requesterFingerprint,
      tenantFingerprint: record.action.tenantFingerprint,
      inputFingerprint: record.inputFingerprint,
      idempotencyPresent: record.idempotencyFingerprint !== undefined,
      ...(record.idempotencyFingerprint
        ? { idempotencyFingerprint: record.idempotencyFingerprint }
        : {}),
      challengeHandleGeneration: record.challengeHandleGeneration,
      bindingFingerprintGeneration: record.bindingFingerprintGeneration,
      auditReferenceGeneration: record.auditReferenceGeneration,
      ...(record.evidenceHandleGeneration
        ? { evidenceHandleGeneration: record.evidenceHandleGeneration }
        : {}),
      state: record.state,
      ...(record.action.correlationId
        ? { correlationId: record.action.correlationId }
        : {}),
      ...(record.action.sourceChain
        ? { sourceChain: record.action.sourceChain }
        : {}),
    };
  }
  function recordEvent(
    state: ConfirmationState,
    record: ConfirmationRecord,
    type: ConfirmationEventType,
    ordinal: number,
    time: number,
    extra: Record<string, JsonValue> = {},
  ): string {
    return event(state, type, "confirmation_record", record.id, ordinal, time, {
      ...context(record),
      ...extra,
    });
  }
  async function fail(reason: string): Promise<ConfirmationResult<never>> {
    try {
      await store.atomic((s) => {
        s.unhealthy = true;
        if (
          !s.unhealthyReason ||
          [
            "journal_unavailable",
            "store_unavailable",
            "post_handler_persistence_unavailable",
          ].includes(s.unhealthyReason)
        )
          s.unhealthyReason = reason;
      });
    } catch {
      /* independent incident path below */
    }
    try {
      await store.incident({
        service: options.service,
        deployment: options.deployment,
        protocolVersion: "1",
        eventType: "provider_failed",
        stage: "confirmation",
        outcome: "unavailable",
        providerKind: "confirmation",
        operation: "confirmation_operation",
        reason,
      });
    } catch {
      /* no recursive provider dependency */
    }
    return unavailable();
  }
  function checkControls(controls?: ConfirmationOperationControls): void {
    if (controls?.refreshCancellation !== undefined) {
      try {
        if (typeof controls.refreshCancellation !== "function")
          throw new Failure("cancellation_refresh_invalid");
        controls.refreshCancellation();
      } catch {
        throw new Failure("cancellation_refresh_unavailable");
      }
    }
    if (controls?.signal?.aborted) throw new Interrupted("CAP_CANCELLED");
    if (controls?.deadlineMs !== undefined) {
      if (!Number.isSafeInteger(controls.deadlineMs))
        throw new Failure("deadline_invalid");
      if (Date.now() >= controls.deadlineMs)
        throw new Interrupted("CAP_TIMEOUT");
    }
  }
  async function operation<T>(
    fn: (state: ConfirmationState, time: number, invocationId: string) => T,
    controls?: ConfirmationOperationControls,
  ): Promise<ConfirmationResult<T>> {
    try {
      const outcome = await store.atomic((state) => {
        checked(state);
        const time = now(state);
        checkControls(controls);
        const invocationId = controls?.kernelInvocationId ?? unique(state);
        if (
          controls?.kernelInvocationId &&
          !state.randomReservations[controls.kernelInvocationId]
        )
          throw new Failure("invocation_owner_invalid");
        try {
          return { value: fn(state, time, invocationId) };
        } catch (error) {
          if (error instanceof Invalid) {
            if (!error.audited)
              event(
                state,
                "verification_rejected",
                "kernel_invocation",
                invocationId,
                1,
                time,
                {
                  providerKind: "confirmation",
                  operation: "verification",
                  reason: "invalid_evidence",
                },
              );
            return { invalid: true as const };
          }
          throw error;
        }
      }, controls);
      checkControls(controls);
      try {
        await flush(controls);
      } catch {
        throw new Failure("journal_unavailable");
      }
      checkControls(controls);
      if ("invalid" in outcome) return invalid();
      return { ok: true, ...outcome.value };
    } catch (error) {
      try {
        checkControls(controls);
      } catch (interrupted) {
        if (
          interrupted instanceof Interrupted ||
          interrupted instanceof Failure
        )
          error = interrupted;
      }
      if (error instanceof Invalid) return invalid();
      if (error instanceof Interrupted)
        return {
          ok: false,
          error: {
            code: error.code,
            status: "unavailable",
            message: "Confirmation interrupted.",
            retryable: false,
          },
        };
      return fail(
        error instanceof Failure ? error.reason : "store_unavailable",
      );
    }
  }
  async function flush(
    controls?: ConfirmationOperationControls,
  ): Promise<void> {
    const events = await store.atomic(
      (state) => Object.values(state.pendingEvents),
      controls,
    );
    if (!events.length) return;
    checkControls(controls);
    await store.commitJournal(events, controls);
    checkControls(controls);
    await store.atomic((state) => {
      if (
        [
          "journal_unavailable",
          "store_unavailable",
          "post_handler_persistence_unavailable",
        ].includes(state.unhealthyReason ?? "")
      ) {
        state.unhealthy = false;
        delete state.unhealthyReason;
      }
      for (const e of events) {
        state.durableEvents[e.eventId] = true;
        delete state.pendingEvents[e.eventId];
      }
      for (const g of Object.values(state.generations))
        if (g.pendingTransition) {
          const kind =
            g.pendingTransition === "REVOKED"
              ? "generation_revoked"
              : "generation_retired";
          const eid = `cape1.${hash({ service: options.service, deployment: options.deployment, ownerType: "key_generation", ownerId: g.ownerId, eventType: kind, transitionOrdinal: g.pendingTransition === "REVOKED" ? 2 : 1 })}`;
          if (state.durableEvents[eid]) {
            g.quarantined = false;
            delete g.pendingTransition;
          }
        }
      for (const x of Object.values(state.executions))
        if (x.state === "COMPLETION_PENDING") {
          const eid = `cape1.${hash({ service: options.service, deployment: options.deployment, ownerType: "execution_attempt", ownerId: x.id, eventType: "execution_audit_completed", transitionOrdinal: 2 })}`;
          if (state.durableEvents[eid]) {
            x.state = "COMPLETED";
            const r = state.records[x.recordId];
            if (r && x.completion)
              state.completionProofs[x.id] = {
                recordId: r.id,
                confirmationRef: r.confirmationRef,
                outcome: x.completion,
              };
          }
        }
    }, controls);
  }
  function handle(
    state: ConfirmationState,
    prefix: "capc1" | "capa1",
    g: ConfirmationGeneration,
  ): { text: string; lookup: string; nonce: string } {
    const nonce = unique(state);
    const unsigned = `${prefix}.${g.id}.${nonce}`;
    // The normative tag signs the unsigned ASCII prefix directly.
    const tag = createHmac("sha256", g.key)
      .update(unsigned, "ascii")
      .digest("base64url");
    const text = `${unsigned}.${tag}`;
    return { text, nonce, lookup: keyed(g.key, `${prefix}-lookup`, text) };
  }
  function lookup(
    state: ConfirmationState,
    text: unknown,
    prefix: "capc1" | "capa1",
  ): ConfirmationRecord {
    if (typeof text !== "string" || text.length > 180) throw new Invalid();
    const parts = text.split(".");
    if (
      parts.length !== 4 ||
      parts[0] !== prefix ||
      !/^[A-Za-z0-9_-]{1,32}$/.test(parts[1]!)
    )
      throw new Invalid();
    digest(parts[2]);
    const tag = digest(parts[3]);
    if (!Object.hasOwn(state.generations, parts[1]!)) throw new Invalid();
    const g = generation(state, parts[1]!);
    const expected = createHmac("sha256", g.key)
      .update(parts.slice(0, 3).join("."), "ascii")
      .digest();
    if (!timingSafeEqual(tag, expected)) throw new Invalid();
    const key = keyed(g.key, `${prefix}-lookup`, text);
    const index =
      prefix === "capc1" ? state.challengeIndex : state.evidenceIndex;
    const id = index[key];
    if (!id || !Object.hasOwn(state.records, id)) throw new Invalid();
    const r = state.records[id]!;
    if (
      ![r.issuedAt, r.expiresAt, r.purgeAt].every(
        (t) => Number.isSafeInteger(t) && t >= 0 && t <= MAX_TIME,
      ) ||
      r.issuedAt >= r.expiresAt ||
      r.expiresAt > r.purgeAt ||
      ![
        "PENDING",
        "APPROVED",
        "CONSUMED",
        "DENIED",
        "EXPIRED",
        "REVOKED",
      ].includes(r.state)
    )
      throw new Failure("record_integrity");
    persisted(r.id);
    persisted(r.nonce);
    if (
      r.id !== id ||
      !timingSafeEqual(
        persisted(prefix === "capc1" ? r.challengeLookup : r.evidenceLookup),
        digest(key),
      )
    )
      throw new Failure("lookup_integrity");
    persisted(r.bindingDigest);
    persisted(r.inputFingerprint);
    if (
      !timingSafeEqual(
        persisted(r.summaryDigest),
        digest(hash(r.action.summary)),
      )
    )
      throw new Failure("stored_summary_integrity");
    persisted(r.action.requesterFingerprint);
    persisted(r.action.tenantFingerprint);
    persisted(r.challengeLookup);
    if (r.evidenceLookup !== undefined) persisted(r.evidenceLookup);
    if (r.idempotencyFingerprint !== undefined)
      persisted(r.idempotencyFingerprint);
    for (const ref of [
      r.challengeHandleGeneration,
      r.bindingFingerprintGeneration,
      r.auditReferenceGeneration,
      ...(r.evidenceHandleGeneration ? [r.evidenceHandleGeneration] : []),
    ])
      generation(state, ref);
    return r;
  }
  function expire(
    state: ConfirmationState,
    r: ConfirmationRecord,
    time: number,
  ): void {
    if (r.expiryEventId || r.state === "EXPIRED" || time >= r.expiresAt) {
      if (["PENDING", "APPROVED"].includes(r.state)) {
        r.state = "EXPIRED";
        r.expiryEventId = recordEvent(state, r, "challenge_expired", 4, time, {
          reason: "expired",
        });
      }
      throw new Invalid();
    }
  }
  function identity(action: ConfirmationAction): {
    requesterFingerprint: string;
    tenantFingerprint: string;
  } {
    try {
      decodeCanonicalBase64Url256(action.requesterFingerprint);
      decodeCanonicalBase64Url256(action.tenantFingerprint);
      return {
        requesterFingerprint: action.requesterFingerprint,
        tenantFingerprint: action.tenantFingerprint,
      };
    } catch {
      throw new Failure("identity_invalid");
    }
  }
  function validatedAction(action: ConfirmationAction): ConfirmationAction {
    try {
      const data = ownData(action, actionKeys);
      if (
        !Object.hasOwn(data, "fingerprintGenerationId") ||
        typeof data.fingerprintGenerationId !== "string" ||
        !/^[A-Za-z0-9_-]{1,32}$/.test(data.fingerprintGenerationId)
      )
        throw new Error("fingerprint_generation");
      return data as unknown as ConfirmationAction;
    } catch {
      throw new Failure("identity_generation_invalid");
    }
  }
  function binding(
    action: ConfirmationAction,
    r: Pick<
      ConfirmationRecord,
      "nonce" | "issuedAt" | "expiresAt" | "summaryDigest"
    >,
    key: Uint8Array,
    generationId: string,
  ): { digest: string; input: string; idempotency?: string } {
    if (action.fingerprintGenerationId !== generationId)
      throw new Failure("identity_generation_mismatch");
    const input = keyed(key, "input", jcs(action.input));
    const idempotency =
      action.idempotencyKey === undefined
        ? undefined
        : keyed(key, "idempotency", action.idempotencyKey);
    const value: Record<string, JsonValue> = {
      protocolVersion: "1",
      service: options.service,
      deployment: options.deployment,
      irHash: action.irHash,
      capabilityId: action.capabilityId,
      version: action.version,
      impact: action.impact,
      requester: keyed(key, "requester", identity(action).requesterFingerprint),
      tenant: keyed(key, "tenant", identity(action).tenantFingerprint),
      input,
      idempotencyPresent: idempotency !== undefined,
      ...(idempotency ? { idempotency } : {}),
      summaryDigest: r.summaryDigest,
      issuedAt: r.issuedAt,
      expiresAt: r.expiresAt,
      nonce: r.nonce,
    };
    return {
      digest: keyed(key, "action-binding", jcs(value)),
      input,
      ...(idempotency ? { idempotency } : {}),
    };
  }
  function details(
    r: ConfirmationRecord,
    challenge: string,
  ): ConfirmationChallenge {
    return {
      challenge,
      capability: { id: r.action.capabilityId, version: r.action.version },
      summary: r.action.summary,
      impact: r.action.impact,
      expiresAt: new Date(r.expiresAt).toISOString(),
    };
  }
  const provider: ConfirmationProvider = {
    async reportProviderFailure(incident, controls) {
      try {
        checkControls(controls);
        const data = ownData(incident, ["providerKind", "operation", "reason"]);
        if (
          Object.keys(data).length !== 3 ||
          data.providerKind !== "identity_fingerprint" ||
          data.operation !== "fingerprint" ||
          ![
            "provider_missing",
            "provider_failed",
            "provider_malformed",
          ].includes(data.reason as string)
        )
          throw new Error("incident");
        await store.incident(
          {
            service: options.service,
            deployment: options.deployment,
            protocolVersion: "1",
            eventType: "provider_failed",
            stage: "confirmation",
            outcome: "unavailable",
            providerKind: data.providerKind,
            operation: data.operation,
            reason: data.reason,
          } as ConfirmationIncident,
          controls,
        );
        checkControls(controls);
      } catch {
        /* Independent incident reporting is contained and never recursive. */
      }
    },
    async queryExecutionCompletion(linkage, outcome) {
      try {
        const data = ownData(linkage, [
          "recordId",
          "confirmationRef",
          "executionAttemptId",
        ]);
        if (
          !["succeeded", "failed"].includes(outcome) ||
          typeof data.confirmationRef !== "string" ||
          !data.confirmationRef.startsWith("capr1.")
        )
          return invalid();
        digest(data.recordId);
        digest(data.executionAttemptId);
        digest(data.confirmationRef.slice(6));
        const completed = await store.atomic((state) => {
          checked(state);
          ownData(state.completionProofs);
          const stored = Object.hasOwn(
            state.completionProofs,
            data.executionAttemptId as string,
          )
            ? state.completionProofs[data.executionAttemptId as string]
            : undefined;
          const proof = stored
            ? ownData(stored, ["recordId", "confirmationRef", "outcome"])
            : undefined;
          const eid = `cape1.${hash({ service: options.service, deployment: options.deployment, ownerType: "execution_attempt", ownerId: data.executionAttemptId as string, eventType: "execution_audit_completed", transitionOrdinal: 2 })}`;
          return (
            !!proof &&
            Object.hasOwn(state.durableEvents, eid) &&
            state.durableEvents[eid] === true &&
            proof.recordId === data.recordId &&
            proof.confirmationRef === data.confirmationRef &&
            proof.outcome === outcome
          );
        });
        return { ok: true, completed };
      } catch {
        return unavailable(false);
      }
    },
    async allocateKernelInvocationId(controls) {
      return operation(
        (_state, _time, id) => ({ kernelInvocationId: id }),
        controls,
      );
    },
    async issue(action, controls) {
      return operation((state, time) => {
        const checkedAction = validatedAction(action);
        if (time > MAX_TIME - options.ttlMs - options.maxClockSkewMs)
          throw new Failure("derived_time_out_of_range");
        const g = generation(state, state.activeGeneration, true);
        if (checkedAction.fingerprintGenerationId !== g.id)
          throw new Failure("identity_generation_mismatch");
        const rendered = summary(checkedAction, options, bearerGuard);
        const h = handle(state, "capc1", g);
        const id = unique(state);
        const fingerprints = identity(checkedAction);
        const safeAction = {
          irHash: checkedAction.irHash,
          capabilityId: checkedAction.capabilityId,
          version: checkedAction.version,
          impact: checkedAction.impact,
          summary: rendered,
          ...fingerprints,
          ...(checkedAction.correlationId
            ? { correlationId: checkedAction.correlationId }
            : {}),
          ...(checkedAction.sourceChain
            ? { sourceChain: checkedAction.sourceChain }
            : {}),
        };
        const r: ConfirmationRecord = {
          id,
          confirmationRef: `capr1.${keyed(g.key, "audit-reference", id)}`,
          state: "PENDING",
          challengeLookup: h.lookup,
          challengeHandleGeneration: g.id,
          bindingFingerprintGeneration: g.id,
          auditReferenceGeneration: g.id,
          bindingDigest: "",
          inputFingerprint: "",
          summaryDigest: hash(rendered),
          nonce: h.nonce,
          issuedAt: time,
          expiresAt: time + options.ttlMs,
          purgeAt: time + options.ttlMs + options.maxClockSkewMs,
          action: { ...safeAction, summary: rendered },
        };
        const b = binding(checkedAction, r, g.key, g.id);
        r.bindingDigest = b.digest;
        r.inputFingerprint = b.input;
        if (b.idempotency) r.idempotencyFingerprint = b.idempotency;
        state.records[id] = r;
        state.challengeIndex[h.lookup] = id;
        recordEvent(state, r, "challenge_issued", 1, time);
        return { challenge: details(r, h.text) };
      }, controls);
    },
    async decideConfirmation(command, approvalRequest, controls) {
      const allocated = await provider.allocateKernelInvocationId(controls);
      if (!allocated.ok) return allocated;
      try {
        command = ownData(command, [
          "challenge",
          "decision",
        ]) as unknown as typeof command;
      } catch {
        return {
          ok: false,
          error: {
            code: "CAP_INPUT_INVALID",
            status: "invalid_argument",
            message: "Invalid confirmation decision.",
            retryable: false,
          },
        };
      }
      if (
        !Object.hasOwn(command, "decision") ||
        !["approve", "deny"].includes(command.decision as string)
      )
        return {
          ok: false,
          error: {
            code: "CAP_INPUT_INVALID",
            status: "invalid_argument",
            message: "Invalid confirmation decision.",
            retryable: false,
          },
        };
      let trusted: ConfirmationApprovalContext;
      try {
        const inspected = await store.atomic((state) => {
          checked(state);
          const time = now(state);
          checkControls(controls);
          const ownerId = unique(state);
          try {
            const r = lookup(state, command.challenge, "capc1");
            expire(state, r, time);
            if (
              r.state !== "PENDING" ||
              Object.values(state.pendingEvents).some((e) => e.ownerId === r.id)
            )
              throw new Invalid();
            return { view: details(r, command.challenge as string) };
          } catch (error) {
            if (!(error instanceof Invalid)) throw error;
            event(
              state,
              "verification_rejected",
              "kernel_invocation",
              ownerId,
              1,
              time,
              {
                providerKind: "confirmation",
                operation: "decision",
                reason: "invalid_challenge",
              },
            );
            return { invalid: true as const };
          }
        }, controls);
        checkControls(controls);
        try {
          await flush(controls);
        } catch {
          throw new Failure("journal_unavailable");
        }
        if ("invalid" in inspected) return invalid();
        const view = inspected.view;
        trusted = await options.approvalProvider.authenticate(
          approvalRequest,
          Object.freeze({
            ...view,
            capability: Object.freeze({ ...view.capability }),
          }),
        );
      } catch (error) {
        try {
          checkControls(controls);
        } catch (interrupted) {
          if (
            interrupted instanceof Interrupted ||
            interrupted instanceof Failure
          )
            error = interrupted;
        }
        if (error instanceof Interrupted)
          return {
            ok: false,
            error: {
              code: error.code,
              status: "unavailable",
              message: "Confirmation interrupted.",
              retryable: false,
            },
          };
        if (error instanceof Invalid) {
          try {
            await flush(controls);
          } catch {
            return fail("journal_unavailable");
          }
          return invalid();
        }
        return fail(
          error instanceof Failure
            ? error.reason
            : "approval_provider_unavailable",
        );
      }
      try {
        trusted = ownData(trusted, [
          "providerAuthenticated",
          "approvalAuthorized",
          "approverRef",
          "assurance",
        ]) as unknown as ConfirmationApprovalContext;
      } catch {
        return fail("approval_context_invalid");
      }
      if (trusted.providerAuthenticated !== true)
        return {
          ok: false,
          error: {
            code: "CAP_UNAUTHENTICATED",
            status: "unauthenticated",
            message: "Approval authentication required.",
            retryable: false,
          },
        };
      if (trusted.approvalAuthorized === false)
        return {
          ok: false,
          error: {
            code: "CAP_PERMISSION_DENIED",
            status: "permission_denied",
            message: "Approval permission required.",
            retryable: false,
          },
        };
      if (
        trusted.approvalAuthorized !== true ||
        typeof trusted.approverRef !== "string" ||
        !trusted.approverRef.trim() ||
        typeof trusted.assurance !== "string" ||
        !trusted.assurance.trim() ||
        !safeSummary(trusted.approverRef) ||
        !safeSummary(trusted.assurance) ||
        bearerGuard.detects(trusted.approverRef) ||
        bearerGuard.detects(trusted.assurance)
      )
        return fail("approval_context_invalid");
      // Copy only the four contracted trusted fields, never provider credentials.
      trusted = {
        providerAuthenticated: true,
        approvalAuthorized: true,
        approverRef: trusted.approverRef,
        assurance: trusted.assurance,
      };
      return operation((state, time) => {
        const r = lookup(state, command.challenge, "capc1");
        expire(state, r, time);
        if (r.state !== "PENDING") throw new Invalid();
        r.approver = trusted;
        if (controls?.correlationId)
          r.action = { ...r.action, correlationId: controls.correlationId };
        if (command.decision === "deny") {
          r.state = "DENIED";
          recordEvent(state, r, "approval_denied", 2, time, {
            approverRef: trusted.approverRef,
            assurance: trusted.assurance,
            decision: "deny",
          });
          return { outcome: "denied" as const };
        }
        const g = generation(state, state.activeGeneration, true);
        const h = handle(state, "capa1", g);
        r.evidenceHandleGeneration = g.id;
        r.evidenceLookup = h.lookup;
        r.state = "APPROVED";
        state.evidenceIndex[h.lookup] = r.id;
        recordEvent(state, r, "approval_granted", 2, time, {
          approverRef: trusted.approverRef,
          assurance: trusted.assurance,
          decision: "approve",
        });
        return {
          outcome: "approved" as const,
          confirmationToken: h.text,
          expiresAt: new Date(r.expiresAt).toISOString(),
        };
      }, controls);
    },
    async consume(action, evidence, controls) {
      const result = await operation((state, time, invocationId) => {
        const checkedAction = validatedAction(action);
        const r = lookup(state, evidence, "capa1");
        if (
          checkedAction.fingerprintGenerationId !==
          r.bindingFingerprintGeneration
        )
          throw new Failure("identity_generation_mismatch");
        const reject = (reason: string): never => {
          event(
            state,
            "verification_rejected",
            "kernel_invocation",
            invocationId,
            1,
            time,
            {
              ...context(r),
              reason,
              ...(checkedAction.correlationId
                ? { correlationId: checkedAction.correlationId }
                : {}),
              ...(checkedAction.sourceChain
                ? { sourceChain: checkedAction.sourceChain }
                : {}),
            },
          );
          throw new Invalid(true);
        };
        try {
          expire(state, r, time);
        } catch (error) {
          if (error instanceof Invalid) reject("expired");
          throw error;
        }
        if (
          r.state !== "APPROVED" ||
          Object.values(state.pendingEvents).some((e) => e.ownerId === r.id)
        )
          reject("record_ineligible");
        const b = binding(
          checkedAction,
          r,
          generation(state, r.bindingFingerprintGeneration).key,
          r.bindingFingerprintGeneration,
        );
        if (!timingSafeEqual(persisted(r.bindingDigest), digest(b.digest))) {
          reject("binding_mismatch");
        }
        r.state = "CONSUMED";
        recordEvent(state, r, "evidence_consumed", 3, time);
        return {
          receipt: Object.freeze({
            recordId: r.id,
            confirmationRef: r.confirmationRef,
          }) as ConfirmationReceipt,
        };
      }, controls);
      if (result.ok) receipts.add(result.receipt);
      return result;
    },
    async beginExecution(receipt, controls) {
      if (!receipts.has(receipt)) return invalid();
      const result = await operation((state, time) => {
        const r = state.records[receipt.recordId];
        if (
          !r ||
          r.state !== "CONSUMED" ||
          r.executionAttemptId ||
          r.confirmationRef !== receipt.confirmationRef ||
          Object.values(state.pendingEvents).some((e) => e.ownerId === r.id)
        )
          throw new Invalid();
        for (const ref of [
          r.challengeHandleGeneration,
          r.bindingFingerprintGeneration,
          r.auditReferenceGeneration,
          r.evidenceHandleGeneration!,
        ])
          generation(state, ref);
        const id = unique(state);
        r.executionAttemptId = id;
        state.executions[id] = {
          id,
          recordId: r.id,
          state: "HANDLER_ENTRY_AUTHORIZED",
        };
        event(
          state,
          "execution_audit_started",
          "execution_attempt",
          id,
          1,
          time,
          { ...context(r), executionAttemptId: id },
        );
        return {
          attempt: Object.freeze({
            ...receipt,
            executionAttemptId: id,
          }) as ConfirmationAttempt,
        };
      }, controls);
      if (result.ok) attempts.add(result.attempt);
      return result;
    },
    async completeExecution(attempt, outcome) {
      if (!attempts.has(attempt) || !["succeeded", "failed"].includes(outcome))
        return invalid();

      if (pendingCompletions.has(attempt.executionAttemptId))
        return unavailable(false);
      pendingCompletions.set(attempt.executionAttemptId, { attempt, outcome });
      try {
        await store.atomic((state) => {
          const x = state.executions[attempt.executionAttemptId];
          const r = state.records[attempt.recordId];
          if (
            !x ||
            !r ||
            x.recordId !== r.id ||
            x.state !== "HANDLER_ENTRY_AUTHORIZED"
          )
            throw new Invalid();
          x.state = "COMPLETION_PENDING";
          x.completion = outcome;
          // Completion uses the durable floor: a failed host clock cannot erase the fence.
          event(
            state,
            "execution_audit_completed",
            "execution_attempt",
            x.id,
            2,
            state.timeFloor,
            { ...context(r), completion: outcome, executionAttemptId: x.id },
          );
        });
        await flush();
        pendingCompletions.delete(attempt.executionAttemptId);
        attempts.delete(attempt);
        return { ok: true };
      } catch (error) {
        if (error instanceof Invalid) {
          pendingCompletions.delete(attempt.executionAttemptId);
          return invalid();
        }
        await fail("post_handler_persistence_unavailable");
        return unavailable(false);
      }
    },
    async transitionGeneration(id, transition) {
      if (!["RETIRED", "REVOKED"].includes(transition)) return invalid();
      return operation((state, time) => {
        if (!Object.hasOwn(state.generations, id)) throw new Invalid();
        const g = generation(state, id, false, true);
        if (g.quarantined) {
          if (g.pendingTransition !== transition) throw new Invalid();
          return {};
        }
        if (g.state === transition) return {};
        if (transition === "RETIRED" && g.state !== "ACTIVE")
          throw new Invalid();
        g.state = transition;
        g.retired = transition === "RETIRED";
        g.revoked = transition === "REVOKED";
        g.quarantined = true;
        g.pendingTransition = transition;
        event(
          state,
          transition === "REVOKED"
            ? "generation_revoked"
            : "generation_retired",
          "key_generation",
          g.ownerId,
          transition === "REVOKED" ? 2 : 1,
          time,
          { generation: id },
        );
        return {};
      });
    },
    async revoke(challenge) {
      return operation((state, time) => {
        const r = lookup(state, challenge, "capc1");
        if (!["PENDING", "APPROVED", "REVOKED"].includes(r.state))
          throw new Invalid();
        r.state = "REVOKED";
        recordEvent(state, r, "challenge_revoked", 5, time, {
          reason: "explicit_revocation",
        });
        return {};
      });
    },
    async reconcile(recovery = {}) {
      const result = await operation((state, time) => {
        for (const { attempt, outcome } of pendingCompletions.values()) {
          const x = state.executions[attempt.executionAttemptId];
          const r = state.records[attempt.recordId];
          if (
            x &&
            r &&
            x.state === "HANDLER_ENTRY_AUTHORIZED" &&
            x.recordId === r.id &&
            r.executionAttemptId === x.id
          ) {
            x.state = "COMPLETION_PENDING";
            x.completion = outcome;
            event(
              state,
              "execution_audit_completed",
              "execution_attempt",
              x.id,
              2,
              time,
              { ...context(r), completion: outcome, executionAttemptId: x.id },
            );
          }
        }
        for (const r of Object.values(state.records)) {
          if (["PENDING", "APPROVED"].includes(r.state)) {
            const refs = [
              r.challengeHandleGeneration,
              r.bindingFingerprintGeneration,
              r.auditReferenceGeneration,
              ...(r.evidenceHandleGeneration
                ? [r.evidenceHandleGeneration]
                : []),
            ];
            if (refs.some((id) => state.generations[id]?.state === "REVOKED")) {
              r.state = "REVOKED";
              recordEvent(state, r, "challenge_revoked", 5, time, {
                reason: "generation_revoked",
              });
            } else if (time >= r.expiresAt || r.expiryEventId) {
              r.state = "EXPIRED";
              r.expiryEventId = recordEvent(
                state,
                r,
                "challenge_expired",
                4,
                time,
                { reason: "expired" },
              );
            }
          }
          const x = r.executionAttemptId
            ? state.executions[r.executionAttemptId]
            : undefined;
          if (
            x?.state === "HANDLER_ENTRY_AUTHORIZED" &&
            recovery.lostExecutionAttemptIds?.includes(x.id)
          ) {
            x.state = "COMPLETION_PENDING";
            x.completion = "ambiguous_after_handler_entry";
            event(
              state,
              "execution_audit_completed",
              "execution_attempt",
              x.id,
              2,
              time,
              {
                ...context(r),
                completion: x.completion,
                executionAttemptId: x.id,
              },
            );
          }
          if (
            time >= r.purgeAt &&
            !["PENDING", "APPROVED"].includes(r.state) &&
            (!x || x.state === "COMPLETED") &&
            !Object.values(state.pendingEvents).some(
              (e) => e.ownerId === r.id || e.ownerId === x?.id,
            )
          ) {
            delete state.challengeIndex[r.challengeLookup];
            if (r.evidenceLookup) delete state.evidenceIndex[r.evidenceLookup];
            delete state.records[r.id];
            if (x) delete state.executions[x.id];
          }
        }
        return {};
      });
      if (result.ok) pendingCompletions.clear();
      return result;
    },
    async health() {
      try {
        return await store.atomic((s) => !s.unhealthy);
      } catch {
        return false;
      }
    },
  };
  return Object.freeze(provider);
}
