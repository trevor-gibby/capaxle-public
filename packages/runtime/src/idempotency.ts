import { createHmac, randomBytes } from "node:crypto";
import { types } from "node:util";
import { jcs, type JsonValue } from "@capaxle/ir";
import { copyJson, ownData, RuntimeConfigurationError } from "./registry.js";
import type { ConfirmationOperationControls } from "./confirmation-types.js";
import type {
  IdempotencyAction,
  IdempotencyClaim,
  IdempotencyConfirmation,
  IdempotencyInspection,
  IdempotencyProvider,
  IdempotencyProviderOptions,
  IdempotencyRecord,
  IdempotencyResult,
  IdempotencyState,
  IdempotencyTerminal,
} from "./idempotency-types.js";
const MAX_TIME = 253402300799999;
const digestPattern = /^[A-Za-z0-9_-]{43}$/;
class Rejection extends Error {
  constructor(
    readonly code: string,
    readonly status:
      | "failed_precondition"
      | "invalid_argument"
      | "unavailable"
      | "cancelled"
      | "deadline_exceeded" = "failed_precondition",
  ) {
    super(code);
  }
}
class StaleCompletion extends Error {}
class CompletionMismatch extends Error {}
const rejected = (
  code: string,
  status: Rejection["status"] = "failed_precondition",
  retryable = false,
): IdempotencyResult<never> => ({
  ok: false,
  error: {
    code,
    status,
    message: "Idempotency admission or persistence failed.",
    retryable,
  },
});
function controlsLive(controls?: ConfirmationOperationControls): void {
  if (!controls) return;
  const data = ownData(controls, [
    "signal",
    "deadlineMs",
    "refreshCancellation",
    "kernelInvocationId",
    "correlationId",
  ]);
  if (data.refreshCancellation !== undefined) {
    if (typeof data.refreshCancellation !== "function")
      throw new Error("controls");
    data.refreshCancellation();
  }
  if (data.signal !== undefined) {
    if (types.isProxy(data.signal)) throw new Error("signal");
    const aborted = Object.getOwnPropertyDescriptor(
      AbortSignal.prototype,
      "aborted",
    )!.get!.call(data.signal);
    if (aborted) throw new Rejection("CAP_CANCELLED", "cancelled");
  }
  if (data.deadlineMs !== undefined) {
    if (!Number.isSafeInteger(data.deadlineMs)) throw new Error("deadline");
    if (Date.now() >= (data.deadlineMs as number))
      throw new Rejection("CAP_DEADLINE_EXCEEDED", "deadline_exceeded");
  }
}
async function native<T>(work: Promise<T>): Promise<T> {
  if (types.isProxy(work) || !types.isPromise(work))
    throw new Error("provider_promise");
  return await work;
}
export function createIdempotencyState(
  service: string,
  deployment: string,
): IdempotencyState {
  if (!service || !deployment)
    throw new RuntimeConfigurationError(
      "CAP_IDEMPOTENCY_CONFIGURATION_INVALID",
    );
  return {
    service,
    deployment,
    timeFloor: 0,
    records: Object.create(null) as IdempotencyState["records"],
    ownerReservations: Object.create(
      null,
    ) as IdempotencyState["ownerReservations"],
  };
}
export function createIdempotencyProvider(
  options: IdempotencyProviderOptions,
): IdempotencyProvider {
  let o: Record<string, unknown>;
  let policy: IdempotencyProviderOptions["policy"];
  try {
    o = ownData(options, [
      "service",
      "deployment",
      "digestKey",
      "store",
      "codec",
      "policy",
      "confirmationProvider",
      "fenceLostOwner",
      "clock",
      "randomBytes",
    ]);
    const p = ownData(o.policy, [
      "keyRetentionMs",
      "resultRetentionMs",
      "maxKeyBytes",
      "maxResultBytes",
      "maxPayloadBytes",
      "maxRecords",
      "maxOwnerReservations",
      "cacheDeclaredErrors",
      "cacheUnexpectedErrors",
    ]);
    for (const name of [
      "keyRetentionMs",
      "resultRetentionMs",
      "maxKeyBytes",
      "maxResultBytes",
      "maxPayloadBytes",
      "maxRecords",
      "maxOwnerReservations",
    ])
      if (
        !Number.isSafeInteger(p[name]) ||
        (p[name] as number) <= 0 ||
        (p[name] as number) > MAX_TIME
      )
        throw new Error("bounds");
    if (
      (p.resultRetentionMs as number) > (p.keyRetentionMs as number) ||
      typeof p.cacheDeclaredErrors !== "boolean" ||
      typeof p.cacheUnexpectedErrors !== "boolean"
    )
      throw new Error("policy");
    policy = Object.freeze(
      p,
    ) as unknown as IdempotencyProviderOptions["policy"];
    const codec = ownData(o.codec);
    const store = ownData(o.store);
    if (
      typeof o.service !== "string" ||
      !o.service ||
      typeof o.deployment !== "string" ||
      !o.deployment ||
      types.isProxy(o.digestKey) ||
      !(o.digestKey instanceof Uint8Array) ||
      o.digestKey.length !== 32 ||
      !o.digestKey.some((v) => v !== 0) ||
      typeof store.atomic !== "function" ||
      typeof codec.encrypt !== "function" ||
      typeof codec.decrypt !== "function"
    )
      throw new Error("options");
    if (
      o.confirmationProvider !== undefined &&
      typeof ownData(o.confirmationProvider).queryExecutionCompletion !==
        "function"
    )
      throw new Error("confirmation");
    for (const name of ["clock", "randomBytes", "fenceLostOwner"])
      if (o[name] !== undefined && typeof o[name] !== "function")
        throw new Error("function");
  } catch {
    throw new RuntimeConfigurationError(
      "CAP_IDEMPOTENCY_CONFIGURATION_INVALID",
    );
  }
  const key = Buffer.from(o.digestKey as Uint8Array);
  const store = o.store as IdempotencyProviderOptions["store"];
  const codec = o.codec as IdempotencyProviderOptions["codec"];
  const clock = (o.clock as IdempotencyProviderOptions["clock"]) ?? Date.now;
  const random =
    (o.randomBytes as IdempotencyProviderOptions["randomBytes"]) ?? randomBytes;
  const confirmationProvider =
    o.confirmationProvider as IdempotencyProviderOptions["confirmationProvider"];
  const fenceLostOwner =
    o.fenceLostOwner as IdempotencyProviderOptions["fenceLostOwner"];
  const claims = new WeakSet<object>();
  const enteredClaims = new WeakSet<object>();
  const pending = new Map<
    string,
    { claim: IdempotencyClaim; terminal: IdempotencyTerminal }
  >();
  let unhealthy = false;
  function checked(state: IdempotencyState): void {
    const s = ownData(state, [
      "service",
      "deployment",
      "timeFloor",
      "records",
      "ownerReservations",
    ]);
    if (
      s.service !== o.service ||
      s.deployment !== o.deployment ||
      !Number.isSafeInteger(s.timeFloor) ||
      (s.timeFloor as number) < 0 ||
      (s.timeFloor as number) > MAX_TIME
    )
      throw new Error("state");
    ownData(s.records);
    ownData(s.ownerReservations);
    if (
      Object.keys(state.records).length > policy.maxRecords ||
      Object.keys(state.ownerReservations).length > policy.maxOwnerReservations
    )
      throw new Error("capacity_integrity");
    for (const [id, reserved] of Object.entries(ownData(s.ownerReservations)))
      if (!digestPattern.test(id) || reserved !== true)
        throw new Error("reservation_integrity");
  }
  function time(state: IdempotencyState): number {
    const t = clock();
    if (!Number.isSafeInteger(t) || t < 0 || t > MAX_TIME) {
      unhealthy = true;
      throw new Error("clock");
    }
    state.timeFloor = Math.max(t, state.timeFloor);
    return state.timeFloor;
  }
  async function atomic<T>(
    fn: (state: IdempotencyState, time: number) => T,
    controls?: ConfirmationOperationControls,
    postEntry = false,
  ): Promise<T> {
    if (unhealthy && !postEntry) throw new Error("unhealthy");
    controlsLive(controls);
    const outcome = await native(
      store.atomic((state) => {
        checked(state);
        controlsLive(controls);
        try {
          return {
            value: fn(state, postEntry ? state.timeFloor : time(state)),
          };
        } catch (error) {
          // Semantic denial may follow durable payload expiration. Commit that
          // safe housekeeping; dependency/cancellation failures still abort.
          if (error instanceof Rejection) return { rejection: error };
          throw error;
        }
      }, controls),
    );
    if ("rejection" in outcome) throw outcome.rejection;
    return outcome.value;
  }
  function failure(
    error: unknown,
    postEntry = false,
  ): IdempotencyResult<never> {
    return error instanceof Rejection
      ? rejected(error.code, error.status)
      : rejected("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", !postEntry);
  }
  function hash(domain: string, value: JsonValue): string {
    return createHmac("sha256", key)
      .update(`capaxle.idempotency.v1.${domain}\0`)
      .update(jcs(value))
      .digest("base64url");
  }
  function action(value: IdempotencyAction): {
    index: string;
    fingerprint: string;
  } {
    const a = ownData(value, [
      "capabilityId",
      "version",
      "irHash",
      "impact",
      "confirmation",
      "identity",
      "input",
      "key",
    ]);
    if (
      typeof a.key !== "string" ||
      !a.key ||
      Buffer.byteLength(a.key) > policy.maxKeyBytes ||
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(
        a.key,
      )
    )
      throw new Rejection("CAP_IDEMPOTENCY_KEY_REQUIRED", "invalid_argument");
    for (const name of [
      "capabilityId",
      "version",
      "irHash",
      "impact",
      "confirmation",
    ])
      if (typeof a[name] !== "string" || !a[name]) throw new Error("action");
    if (
      !/^\d+\.\d+\.\d+(?:[-+].*)?$/.test(a.version as string) ||
      !["read", "write", "destructive"].includes(a.impact as string) ||
      !["none", "required"].includes(a.confirmation as string)
    )
      throw new Error("action");
    const identity = ownData(a.identity, [
      "originating",
      "effective",
      "authorityChain",
    ]);
    const identifier = (principal: unknown): JsonValue => {
      const p = ownData(principal);
      for (const name of ["providerId", "type", "subject"])
        if (typeof p[name] !== "string" || !p[name])
          throw new Error("identity");
      if (p.tenant !== undefined && typeof p.tenant !== "string")
        throw new Error("tenant");
      return {
        providerId: p.providerId as string,
        type: p.type as string,
        subject: p.subject as string,
        tenant:
          p.tenant === undefined
            ? { present: false }
            : { present: true, value: p.tenant as string },
      };
    };
    if (
      !Array.isArray(identity.authorityChain) ||
      types.isProxy(identity.authorityChain) ||
      !identity.authorityChain.length
    )
      throw new Error("identity");
    const chain = (copyJson(identity.authorityChain) as JsonValue[]).map(
      identifier,
    );
    return {
      index: hash("index", {
        service: o.service as string,
        deployment: o.deployment as string,
        capabilityId: a.capabilityId as string,
        major: (a.version as string).split(".")[0]!,
        key: a.key,
        originating: identifier(identity.originating),
        effective: identifier(identity.effective),
        authorityChain: chain,
      }),
      fingerprint: hash("action", {
        capabilityId: a.capabilityId as string,
        version: a.version as string,
        irHash: a.irHash as string,
        impact: a.impact as string,
        confirmation: a.confirmation as string,
        input: copyJson(a.input),
      }),
    };
  }
  function record(
    state: IdempotencyState,
    index: string,
  ): IdempotencyRecord | undefined {
    if (!Object.hasOwn(state.records, index)) return undefined;
    const r = state.records[index]!;
    const data = ownData(r, [
      "index",
      "fingerprint",
      "ownerId",
      "requiresConfirmation",
      "state",
      "confirmation",
      "classification",
      "terminalDigest",
      "payload",
      "replayable",
      "completedAt",
      "resultExpiresAt",
      "keyExpiresAt",
      "integrityTag",
    ]);
    if (
      typeof data.integrityTag !== "string" ||
      !digestPattern.test(data.integrityTag) ||
      data.integrityTag !== integrity(r)
    )
      throw new Error("record_integrity");
    if (
      data.index !== index ||
      typeof data.requiresConfirmation !== "boolean" ||
      typeof data.fingerprint !== "string" ||
      !digestPattern.test(data.fingerprint) ||
      typeof data.ownerId !== "string" ||
      !digestPattern.test(data.ownerId) ||
      !Object.hasOwn(state.ownerReservations, data.ownerId) ||
      state.ownerReservations[data.ownerId] !== true ||
      ![
        "CLAIMED",
        "HANDLER_ENTRY_AUTHORIZED",
        "COMPLETION_PENDING",
        "COMPLETED",
        "BLOCKED_TERMINAL",
        "AMBIGUOUS",
      ].includes(data.state as string)
    )
      throw new Error("record");
    if (
      r.payload !== undefined &&
      (typeof r.payload !== "string" ||
        Buffer.byteLength(r.payload) > policy.maxPayloadBytes)
    )
      throw new Error("payload");
    if (r.confirmation) linkage(r.confirmation);
    if (
      ["COMPLETION_PENDING", "COMPLETED", "BLOCKED_TERMINAL"].includes(
        r.state,
      ) &&
      (!["succeeded", "failed"].includes(r.classification ?? "") ||
        typeof r.terminalDigest !== "string" ||
        !digestPattern.test(r.terminalDigest) ||
        typeof r.replayable !== "boolean" ||
        (r.requiresConfirmation && !r.confirmation))
    )
      throw new Error("terminal_integrity");
    if (["COMPLETED", "BLOCKED_TERMINAL"].includes(r.state)) {
      for (const name of [
        "completedAt",
        "resultExpiresAt",
        "keyExpiresAt",
      ] as const)
        if (
          !Number.isSafeInteger(r[name]) ||
          r[name]! < 0 ||
          r[name]! > MAX_TIME
        )
          throw new Error("retention");
      if (
        r.resultExpiresAt! > r.keyExpiresAt! ||
        r.completedAt! > r.resultExpiresAt!
      )
        throw new Error("retention");
    }
    return r;
  }
  function linkage(value: IdempotencyConfirmation): IdempotencyConfirmation {
    const data = ownData(value, [
      "recordId",
      "confirmationRef",
      "executionAttemptId",
    ]);
    if (
      typeof data.recordId !== "string" ||
      !digestPattern.test(data.recordId) ||
      typeof data.executionAttemptId !== "string" ||
      !digestPattern.test(data.executionAttemptId) ||
      typeof data.confirmationRef !== "string" ||
      !/^capr1\.[A-Za-z0-9_-]{43}$/.test(data.confirmationRef)
    )
      throw new Error("linkage");
    return Object.freeze({ ...data }) as unknown as IdempotencyConfirmation;
  }
  function terminal(value: unknown): IdempotencyTerminal {
    const data = ownData(copyJson(value), ["kind", "value", "error"]);
    if (data.kind === "success") {
      if (!Object.hasOwn(data, "value") || Object.hasOwn(data, "error"))
        throw new Error("terminal");
    } else {
      if (
        !["declared_error", "unexpected_error"].includes(data.kind as string) ||
        Object.hasOwn(data, "value")
      )
        throw new Error("terminal");
      const error = ownData(data.error, [
        "code",
        "status",
        "message",
        "retryable",
        "details",
      ]);
      for (const name of ["code", "status", "message"])
        if (typeof error[name] !== "string" || !error[name])
          throw new Error("error");
      if (typeof error.retryable !== "boolean") throw new Error("error");
    }
    if (Buffer.byteLength(jcs(copyJson(data))) > policy.maxResultBytes)
      throw new Error("size");
    return copyJson(data) as unknown as IdempotencyTerminal;
  }
  function integrity(r: IdempotencyRecord): string {
    const data = ownData(r);
    delete data.integrityTag;
    return hash("record-integrity", copyJson(data));
  }
  function seal(r: IdempotencyRecord): void {
    r.integrityTag = integrity(r);
  }
  async function decode(r: IdempotencyRecord): Promise<IdempotencyTerminal> {
    if (!r.payload) throw new Error("payload");
    const data = ownData(copyJson(await native(codec.decrypt(r.payload))), [
      "index",
      "fingerprint",
      "ownerId",
      "classification",
      "requiresConfirmation",
      "confirmation",
      "terminal",
    ]);
    if (
      data.index !== r.index ||
      data.fingerprint !== r.fingerprint ||
      data.ownerId !== r.ownerId ||
      data.classification !== r.classification ||
      data.requiresConfirmation !== r.requiresConfirmation ||
      jcs(copyJson(data.confirmation)) !== jcs(copyJson(r.confirmation ?? null))
    )
      throw new Error("payload_binding");
    const value = terminal(data.terminal);
    if (
      (value.kind === "success" ? "succeeded" : "failed") !==
        r.classification ||
      hash("terminal", copyJson(value)) !== r.terminalDigest
    )
      throw new Error("terminal_classification");
    return value;
  }
  function expire(state: IdempotencyState, t: number): void {
    for (const index of Object.keys(state.records)) {
      const r = record(state, index)!;
      if (["COMPLETED", "BLOCKED_TERMINAL"].includes(r.state)) {
        if (t >= r.keyExpiresAt!) delete state.records[index];
        else if (t >= r.resultExpiresAt!) {
          delete r.payload;
          r.state = "BLOCKED_TERMINAL";
          seal(r);
        }
      }
    }
  }
  function owner(
    state: IdempotencyState,
    claim: IdempotencyClaim,
  ): IdempotencyRecord {
    if (!claims.has(claim)) throw new Error("claim");
    const r = record(state, claim.index);
    if (!r || r.ownerId !== claim.ownerId) throw new Error("fence");
    return r;
  }
  async function proof(r: IdempotencyRecord): Promise<boolean> {
    if (!r.confirmation) return !r.requiresConfirmation;
    if (!confirmationProvider || !r.classification) return false;
    const result = ownData(
      await native(
        confirmationProvider.queryExecutionCompletion(
          r.confirmation,
          r.classification,
        ),
      ),
      ["ok", "completed", "error"],
    );
    if (result.ok === false) throw new Error("confirmation");
    if (
      result.ok !== true ||
      typeof result.completed !== "boolean" ||
      Object.hasOwn(result, "error")
    )
      throw new Error("proof");
    return result.completed;
  }
  async function promote(index: string): Promise<void> {
    const snapshot = await atomic(
      (state) =>
        record(state, index)
          ? (copyJson(record(state, index)) as unknown as IdempotencyRecord)
          : undefined,
      undefined,
      true,
    );
    if (
      !snapshot ||
      snapshot.state !== "COMPLETION_PENDING" ||
      !snapshot.classification
    )
      return;
    if (snapshot.replayable) await decode(snapshot);
    if (!(await proof(snapshot))) return;
    await atomic(
      (state, t) => {
        const r = record(state, index);
        // Another observer may have promoted or safely expired this snapshot.
        // Never rewrite settled retention or touch a replacement owner.
        if (!r || r.ownerId !== snapshot.ownerId) return;
        if (
          r.fingerprint !== snapshot.fingerprint ||
          r.terminalDigest !== snapshot.terminalDigest ||
          r.requiresConfirmation !== snapshot.requiresConfirmation ||
          r.replayable !== snapshot.replayable ||
          r.classification !== snapshot.classification ||
          jcs(copyJson(r.confirmation ?? null)) !==
            jcs(copyJson(snapshot.confirmation ?? null))
        )
          throw new Error("fence");
        if (r.state === "COMPLETED" || r.state === "BLOCKED_TERMINAL") return;
        if (r.state !== "COMPLETION_PENDING" || r.payload !== snapshot.payload)
          throw new Error("fence");
        // Retention begins after the authoritative confirmation completion gate.
        t = time(state);
        if (t + policy.keyRetentionMs > MAX_TIME) throw new Error("overflow");
        r.completedAt = t;
        r.resultExpiresAt = t + policy.resultRetentionMs;
        r.keyExpiresAt = t + policy.keyRetentionMs;
        r.state = r.replayable ? "COMPLETED" : "BLOCKED_TERMINAL";
        seal(r);
      },
      undefined,
      true,
    );
  }
  async function inspect(
    value: IdempotencyAction,
    controls?: ConfirmationOperationControls,
  ): Promise<IdempotencyResult<IdempotencyInspection>> {
    try {
      const a = action(value);
      controlsLive(controls);
      await promote(a.index);
      controlsLive(controls);
      const r = await atomic((state, t) => {
        expire(state, t);
        const r = record(state, a.index);
        if (!r) return undefined;
        if (r.fingerprint !== a.fingerprint)
          throw new Rejection("CAP_IDEMPOTENCY_CONFLICT");
        if (r.state === "AMBIGUOUS")
          throw new Rejection("CAP_IDEMPOTENCY_AMBIGUOUS");
        if (r.state === "BLOCKED_TERMINAL")
          throw new Rejection("CAP_IDEMPOTENCY_RESULT_UNAVAILABLE");
        if (r.state !== "COMPLETED")
          throw new Rejection("CAP_IDEMPOTENCY_IN_PROGRESS");
        if (!r.payload || r.replayable !== true) throw new Error("completion");
        return copyJson(r) as unknown as IdempotencyRecord;
      }, controls);
      if (!r) return { ok: true, outcome: "absent" };
      const replayed = await decode(r);
      controlsLive(controls);
      return {
        ok: true,
        outcome: "replay",
        terminal: replayed,
        ...(r.confirmation ? { confirmation: r.confirmation } : {}),
      };
    } catch (e) {
      return failure(e);
    }
  }
  async function persist(
    claim: IdempotencyClaim,
    value: IdempotencyTerminal,
  ): Promise<void> {
    const normalized = terminal(value);
    const terminalDigest = hash("terminal", copyJson(normalized));
    const completionOwner = (state: IdempotencyState): IdempotencyRecord => {
      if (!claims.has(claim)) throw new StaleCompletion();
      const r = record(state, claim.index);
      if (!r || r.ownerId !== claim.ownerId) throw new StaleCompletion();
      if (
        r.state !== "HANDLER_ENTRY_AUTHORIZED" &&
        (!["COMPLETION_PENDING", "COMPLETED", "BLOCKED_TERMINAL"].includes(
          r.state,
        ) ||
          r.terminalDigest !== terminalDigest)
      )
        throw new CompletionMismatch();
      return r;
    };
    const replayable =
      normalized.kind === "success" ||
      (normalized.kind === "declared_error"
        ? policy.cacheDeclaredErrors
        : policy.cacheUnexpectedErrors);
    const snapshot = await atomic(
      (state) => {
        const r = completionOwner(state);
        return copyJson(r) as unknown as IdempotencyRecord;
      },
      undefined,
      true,
    );
    if (snapshot.state !== "HANDLER_ENTRY_AUTHORIZED") {
      // A durable commit can lose its acknowledgement. Equality is authenticated
      // even without a cached payload; never replace an outcome or extend TTLs.
      pending.delete(claim.ownerId);
      await promote(claim.index);
      return;
    }
    const classification =
      normalized.kind === "success" ? "succeeded" : "failed";
    const payload = replayable
      ? await native(
          codec.encrypt({
            index: claim.index,
            ownerId: claim.ownerId,
            fingerprint: snapshot.fingerprint,
            classification,
            requiresConfirmation: snapshot.requiresConfirmation,
            confirmation: copyJson(snapshot.confirmation ?? null),
            terminal: copyJson(normalized),
          }),
        )
      : undefined;
    if (
      payload !== undefined &&
      (typeof payload !== "string" ||
        !payload ||
        Buffer.byteLength(payload) > policy.maxPayloadBytes)
    )
      throw new Error("payload");
    await atomic(
      (state) => {
        const r = completionOwner(state);
        if (r.state !== "HANDLER_ENTRY_AUTHORIZED") return;
        r.state = "COMPLETION_PENDING";
        r.classification = classification;
        r.terminalDigest = terminalDigest;
        r.replayable = replayable;
        if (payload !== undefined) r.payload = payload;
        seal(r);
      },
      undefined,
      true,
    );
    pending.delete(claim.ownerId);
    await promote(claim.index);
  }
  const provider: IdempotencyProvider = {
    inspect,
    async claim(value, controls) {
      const inspected = await inspect(value, controls);
      if (!inspected.ok || inspected.outcome === "replay") return inspected;
      try {
        const a = action(value);
        const result = await atomic((state, t) => {
          expire(state, t);
          const existing = record(state, a.index);
          if (existing) {
            if (existing.fingerprint !== a.fingerprint)
              throw new Rejection("CAP_IDEMPOTENCY_CONFLICT");
            throw new Rejection("CAP_IDEMPOTENCY_IN_PROGRESS");
          }
          if (Object.keys(state.records).length >= policy.maxRecords)
            throw new Error("capacity");
          if (
            Object.keys(state.ownerReservations).length >=
            policy.maxOwnerReservations
          )
            throw new Error("reservation_capacity");
          const bytes = random(32);
          if (
            types.isProxy(bytes) ||
            !(bytes instanceof Uint8Array) ||
            bytes.length !== 32 ||
            !bytes.some((v) => v !== 0)
          ) {
            unhealthy = true;
            throw new Error("random");
          }
          const ownerId = Buffer.from(bytes).toString("base64url");
          if (Object.hasOwn(state.ownerReservations, ownerId)) {
            unhealthy = true;
            throw new Error("collision");
          }
          state.ownerReservations[ownerId] = true;
          state.records[a.index] = {
            ...a,
            ownerId,
            requiresConfirmation: value.confirmation === "required",
            state: "CLAIMED",
            integrityTag: "",
          };
          seal(state.records[a.index]!);
          return Object.freeze({ index: a.index, ownerId }) as IdempotencyClaim;
        }, controls);
        claims.add(result);
        return { ok: true, outcome: "claimed", claim: result };
      } catch (e) {
        // A winner may have completed during the final atomic recheck.
        if (e instanceof Rejection && e.code === "CAP_IDEMPOTENCY_IN_PROGRESS")
          return (await inspect(value, controls)) as IdempotencyResult<
            Exclude<IdempotencyInspection, { outcome: "absent" }>
          >;
        return failure(e);
      }
    },
    async enter(claim, confirmation, controls) {
      try {
        await atomic((state) => {
          const r = owner(state, claim);
          if (r.state !== "CLAIMED") throw new Error("entry");
          if (
            r.requiresConfirmation &&
            (!confirmation || !confirmationProvider)
          )
            throw new Error("confirmation");
          if (confirmation) r.confirmation = linkage(confirmation);
          r.state = "HANDLER_ENTRY_AUTHORIZED";
          seal(r);
        }, controls);
        enteredClaims.add(claim);
        return { ok: true };
      } catch (e) {
        return failure(e);
      }
    },
    async release(claim) {
      try {
        await atomic(
          (state) => {
            const r = owner(state, claim);
            if (r.state !== "CLAIMED") throw new Error("entry");
            delete state.records[r.index];
          },
          undefined,
          true,
        );
        claims.delete(claim);
        return { ok: true };
      } catch (e) {
        return failure(e);
      }
    },
    async complete(claim, value) {
      try {
        if (!claims.has(claim) || !enteredClaims.has(claim))
          throw new Error("claim");
        const normalized = terminal(value);
        const existing = pending.get(claim.ownerId);
        if (
          existing &&
          hash("terminal", copyJson(existing.terminal)) !==
            hash("terminal", copyJson(normalized))
        )
          throw new Error("completion_mismatch");
        if (!existing)
          pending.set(claim.ownerId, { claim, terminal: normalized });
        await persist(claim, pending.get(claim.ownerId)!.terminal);
        return { ok: true };
      } catch (e) {
        if (e instanceof StaleCompletion || e instanceof CompletionMismatch)
          pending.delete(claim.ownerId);
        return failure(e, true);
      }
    },
    async reconcile(recovery = {}) {
      try {
        const controls = ownData(recovery, ["lostOwnerIds"]);
        let lostOwnerIds: readonly string[] = [];
        if (controls.lostOwnerIds !== undefined) {
          if (
            types.isProxy(controls.lostOwnerIds) ||
            !Array.isArray(controls.lostOwnerIds) ||
            Object.getPrototypeOf(controls.lostOwnerIds) !== Array.prototype
          )
            throw new Error("lost_owners");
          const length = Object.getOwnPropertyDescriptor(
            controls.lostOwnerIds,
            "length",
          )?.value;
          if (
            !Number.isSafeInteger(length) ||
            length > policy.maxOwnerReservations
          )
            throw new Error("lost_owners");
          const values = copyJson(controls.lostOwnerIds) as JsonValue[];
          for (const id of values)
            if (typeof id !== "string" || !digestPattern.test(id))
              throw new Error("lost_owners");
          lostOwnerIds = values as string[];
        }
        if (lostOwnerIds.length && !fenceLostOwner) throw new Error("fencing");
        for (const entry of pending.values()) {
          try {
            await persist(entry.claim, entry.terminal);
          } catch (error) {
            if (
              error instanceof StaleCompletion ||
              error instanceof CompletionMismatch
            )
              pending.delete(entry.claim.ownerId);
            else throw error;
          }
        }
        if (lostOwnerIds.length) {
          if (!fenceLostOwner) throw new Error("fencing");
          for (const id of lostOwnerIds) {
            if (
              typeof id !== "string" ||
              !digestPattern.test(id) ||
              (await native(fenceLostOwner(id))) !== true
            )
              throw new Error("fencing");
            await atomic(
              (state) => {
                for (const index of Object.keys(state.records)) {
                  const r = record(state, index)!;
                  if (
                    r.ownerId === id &&
                    ["CLAIMED", "HANDLER_ENTRY_AUTHORIZED"].includes(r.state)
                  ) {
                    r.state = "AMBIGUOUS";
                    seal(r);
                  }
                }
              },
              undefined,
              true,
            );
          }
        }
        const indexes = await atomic(
          (state) => Object.keys(state.records),
          undefined,
          true,
        );
        for (const index of indexes) await promote(index);
        return { ok: true };
      } catch (e) {
        return failure(e, true);
      }
    },
  };
  return Object.freeze(provider);
}
