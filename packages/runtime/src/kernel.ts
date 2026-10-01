import type {
  ConfirmationAction,
  ConfirmationAttempt,
  ConfirmationOperationControls,
  ConfirmationReceipt,
  ConfirmationResult,
  IdentityFingerprintFailureIncident,
} from "./confirmation-types.js";
import type {
  IdempotencyAction,
  IdempotencyClaim,
  IdempotencyProvider,
  IdempotencyResult,
  IdempotencyInspection,
  IdempotencyTerminal,
} from "./idempotency-types.js";
import {
  addSensitiveString,
  captureRedactionPaths,
  compileRedactionPaths,
  createRedactionState,
  equalJson,
  redactJson,
} from "./redaction.js";
import type { RedactionState } from "./redaction.js";
import { Buffer } from "node:buffer";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { types } from "node:util";
import { canonicalizeInput, jcs, validateSchemaValue } from "@capaxle/ir";
import type { JsonValue } from "@capaxle/ir";
import { compileBearerDescriptors } from "./ingress.js";
import { authorizePrincipals } from "./authorization.js";
import { decodeCanonicalBase64Url256 } from "./base64url.js";
import {
  anonymousPrincipal,
  canonicalIdentityId,
  normalizePrincipal,
  rootIdentity,
} from "./principal.js";
import type { IdentityContext } from "@capaxle/core";
import type { ErrorStatus } from "@capaxle/core";
import {
  copyJson,
  ownData,
  registryState,
  RuntimeConfigurationError,
} from "./registry.js";
import type {
  InvocationRequest,
  InvocationResult,
  RuntimeKernel,
  RuntimeKernelOptions,
  RuntimeTelemetryEvent,
  AdapterRegistration,
  AdapterIngress,
  AdapterInvocationRequest,
  OperationView,
  InternalInvocationAuditEvent,
  InternalInvocationAuditReason,
  InternalInvocationAuditStage,
  InternalInvocationNode,
  InternalInvocationTransitionView,
  IdentityFingerprintSet,
  PrincipalTrustToken,
  AdapterDisclosureAuthenticationView,
  AdapterDisclosureRequest,
  AdapterDisclosureResult,
  RequesterOwnershipToken,
} from "./types.js";

const adapterControlKeys = [
  "confirmationToken",
  "idempotencyKey",
  "correlationId",
  "timeoutMs",
] as const;
const adapterCandidateKeys = [
  "ok",
  "input",
  "controls",
  "code",
  "status",
  "safeDetails",
] as const;
const cliAdapterRejections = {
  CAP_CLI_PROTOCOL_UNSUPPORTED: {
    status: "failed_precondition",
    message: "CLI protocol is unsupported.",
  },
  CAP_CLI_IR_MISMATCH: {
    status: "failed_precondition",
    message: "Capability metadata is stale.",
  },
  CAP_CLI_CONTRACT_MISMATCH: {
    status: "failed_precondition",
    message: "CLI transport contract is stale.",
  },
  CAP_CLI_SERVICE_MISMATCH: {
    status: "failed_precondition",
    message: "CLI service identity does not match.",
  },
  CAP_CLI_TLS_REQUIRED: {
    status: "failed_precondition",
    message: "TLS is required.",
  },
  CAP_CLI_PAYLOAD_TOO_LARGE: {
    status: "invalid_argument",
    message: "CLI request payload is too large.",
  },
} as const;
type CliAdapterRejectionCode = keyof typeof cliAdapterRejections;
const CLI_HASH = /^sha256:[0-9a-f]{64}$/u;
const ADAPTER_DETAIL_MAX_DEPTH = 8;
const ADAPTER_DETAIL_MAX_NODES = 128;
const ADAPTER_DETAIL_MAX_STRING = 1024;
const ADAPTER_DETAIL_MAX_KEY = 128;
const ADAPTER_DETAIL_MAX_JSON = 4096;

function boundedAdapterDetails(value: unknown): JsonValue {
  const state = { nodes: 0 };
  const visit = (item: unknown, depth: number): JsonValue => {
    state.nodes++;
    if (
      state.nodes > ADAPTER_DETAIL_MAX_NODES ||
      depth > ADAPTER_DETAIL_MAX_DEPTH
    )
      throw new Error("adapter_details");
    if (item === null || typeof item === "boolean") return item;
    if (typeof item === "string") {
      if (item.length > ADAPTER_DETAIL_MAX_STRING)
        throw new Error("adapter_details");
      return item;
    }
    if (typeof item === "number" && Number.isFinite(item)) return item;
    if (Array.isArray(item)) {
      if (
        item.length > ADAPTER_DETAIL_MAX_NODES ||
        types.isProxy(item) ||
        Object.getPrototypeOf(item) !== Array.prototype ||
        Reflect.ownKeys(item).length !== item.length + 1
      )
        throw new Error("adapter_details");
      return Object.freeze(
        Array.from({ length: item.length }, (_, index) => {
          const descriptor = Object.getOwnPropertyDescriptor(
            item,
            String(index),
          );
          if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
            throw new Error("adapter_details");
          return visit(descriptor.value, depth + 1);
        }),
      );
    }
    const data = ownData(item);
    if (Object.keys(data).length > ADAPTER_DETAIL_MAX_NODES)
      throw new Error("adapter_details");
    const result: Record<string, JsonValue> = {};
    for (const [key, member] of Object.entries(data)) {
      if (key.length > ADAPTER_DETAIL_MAX_KEY)
        throw new Error("adapter_details");
      Object.defineProperty(result, key, {
        value: visit(member, depth + 1),
        enumerable: true,
        writable: false,
        configurable: false,
      });
    }
    return Object.freeze(result);
  };
  const result = visit(value, 0);
  if (JSON.stringify(result).length > ADAPTER_DETAIL_MAX_JSON)
    throw new Error("adapter_details");
  return result;
}

function boundedCliAdapterDetails(
  code: CliAdapterRejectionCode,
  value: unknown,
): JsonValue {
  const details = boundedAdapterDetails(value);
  if (details === null || typeof details !== "object" || Array.isArray(details))
    throw new Error("cli_adapter_details");
  const fields = details as Readonly<Record<string, JsonValue>>;
  const keys = Object.keys(fields);
  if (code === "CAP_CLI_PROTOCOL_UNSUPPORTED") {
    const profiles = fields.supportedProfiles;
    if (
      keys.length !== 1 ||
      keys[0] !== "supportedProfiles" ||
      !Array.isArray(profiles) ||
      profiles.length !== 1 ||
      profiles[0] !== "0.1"
    )
      throw new Error("cli_adapter_details");
  } else if (
    code === "CAP_CLI_IR_MISMATCH" ||
    code === "CAP_CLI_CONTRACT_MISMATCH"
  ) {
    if (
      keys.length !== 2 ||
      !keys.includes("expectedHash") ||
      !keys.includes("currentHash") ||
      typeof fields.expectedHash !== "string" ||
      typeof fields.currentHash !== "string" ||
      !CLI_HASH.test(fields.expectedHash) ||
      !CLI_HASH.test(fields.currentHash)
    )
      throw new Error("cli_adapter_details");
  } else throw new Error("cli_adapter_details");
  return details;
}

/** Normative stages; adapter serialization follows the returned canonical result. */
export const RUNTIME_STAGES = Object.freeze([
  "resolve",
  "context",
  "authenticate",
  "authorize",
  "admission",
  "parse",
  "input_validation",
  "quota_preconditions",
  "idempotency_inspect",
  "confirmation",
  "approval_consume",
  "idempotency_claim",
  "resources",
  "audit_start",
  "handler",
  "output_validation",
  "finalize",
  "telemetry_audit",
] as const);
const requestKeys = [
  "capability",
  "version",
  "input",
  "source",
  "correlationId",
  "signal",
  "deadline",
  "principal",
  "idempotencyKey",
  "confirmationToken",
  "metadata",
  "adapterCandidate",
];
const abortedGetter = Object.getOwnPropertyDescriptor(
  AbortSignal.prototype,
  "aborted",
)?.get;
const addListener = AbortSignal.prototype.addEventListener;
const removeListener = AbortSignal.prototype.removeEventListener;
const getDateTime = Date.prototype.getTime;

type NativeSignalKind =
  "map" | "set" | "weakref" | "boolean" | "number" | "opaque";
type NativeSignalSlot = {
  kinds: Set<NativeSignalKind>;
  prototypes: Set<object>;
  allowsUndefined: boolean;
};
const nativeSignalSlots = new Map<PropertyKey, NativeSignalSlot>();
const nativeEventMaps = new Set<PropertyKey>();
let nativeListenerPrototype: object;
let nativeWeakGetter: (this: object) => boolean;
const nativeWeakRefPrototypes = new Set<object>([WeakRef.prototype]);
const exemplarController = new AbortController();
const exemplarSignal = exemplarController.signal;
addListener.call(exemplarSignal, "abort", () => undefined);
const handlerExemplar = new AbortController().signal;
handlerExemplar.onabort = () => undefined;
const freshExemplar = new AbortController().signal;
const abortedExemplar = AbortSignal.abort(new Error("Native signal profile."));
const compositeExemplar = AbortSignal.any([exemplarSignal]);
const registeredCompositeSourceExemplar = new AbortController().signal;
const registeredCompositeExemplar = AbortSignal.any([
  registeredCompositeSourceExemplar,
]);
addListener.call(registeredCompositeExemplar, "abort", () => undefined);
function nativeWeakRefValue(value: unknown): boolean {
  if (typeof value !== "object" || value === null || types.isProxy(value))
    return false;
  try {
    WeakRef.prototype.deref.call(value);
    return true;
  } catch {
    return false;
  }
}
const timeoutExemplar = AbortSignal.timeout(1);
for (const exemplar of [
  freshExemplar,
  exemplarSignal,
  handlerExemplar,
  abortedExemplar,
  compositeExemplar,
  registeredCompositeExemplar,
  registeredCompositeSourceExemplar,
  timeoutExemplar,
]) {
  for (const key of Reflect.ownKeys(exemplar)) {
    const value: unknown = Object.getOwnPropertyDescriptor(
      exemplar,
      key,
    )?.value;
    const slot = nativeSignalSlots.get(key) ?? {
      kinds: new Set<NativeSignalKind>(),
      prototypes: new Set<object>(),
      allowsUndefined: false,
    };
    if (value === undefined) slot.allowsUndefined = true;
    else {
      const kind: NativeSignalKind = types.isMap(value)
        ? "map"
        : types.isSet(value)
          ? "set"
          : nativeWeakRefValue(value)
            ? "weakref"
            : typeof value === "boolean"
              ? "boolean"
              : typeof value === "number"
                ? "number"
                : "opaque";
      slot.kinds.add(kind);
      if (kind === "weakref")
        nativeWeakRefPrototypes.add(Object.getPrototypeOf(value) as object);
      if (kind === "map" || kind === "set" || kind === "weakref")
        slot.prototypes.add(Object.getPrototypeOf(value) as object);
    }
    nativeSignalSlots.set(key, slot);
    if (types.isMap(value))
      Map.prototype.forEach.call(value, (header: unknown) => {
        if (typeof header !== "object" || header === null) return;
        const next: unknown = Object.getOwnPropertyDescriptor(
          header,
          "next",
        )?.value;
        if (typeof next !== "object" || next === null) return;
        nativeEventMaps.add(key);
        nativeListenerPrototype = Object.getPrototypeOf(next) as object;
        nativeWeakGetter = Object.getOwnPropertyDescriptor(
          nativeListenerPrototype,
          "weak",
        )?.get as (this: object) => boolean;
      });
    if (types.isSet(value))
      Set.prototype.forEach.call(value, (reference: object) =>
        nativeWeakRefPrototypes.add(Object.getPrototypeOf(reference) as object),
      );
  }
}
const weakRefDeref = WeakRef.prototype.deref;
function validWeakRef(value: unknown): boolean {
  if (
    typeof value !== "object" ||
    value === null ||
    types.isProxy(value) ||
    !nativeWeakRefPrototypes.has(Object.getPrototypeOf(value) as object) ||
    Reflect.ownKeys(value).length
  )
    return false;
  try {
    weakRefDeref.call(value);
    return true;
  } catch {
    return false;
  }
}
/** Validate only native event-list structure; registered callbacks stay opaque. */
function validEventHeader(value: unknown, inactiveHandler?: unknown): boolean {
  const header = ownData(value, ["size", "next", "resistStopPropagation"]);
  if (
    !Number.isInteger(header.size) ||
    (header.size as number) < 0 ||
    (header.size as number) > 1024 ||
    typeof header.resistStopPropagation !== "boolean"
  )
    return false;
  const seen = new Set<object>();
  let active = 0;
  let previous: unknown = value;
  let next: unknown = header.next;
  while (next !== undefined) {
    if (
      typeof next !== "object" ||
      next === null ||
      types.isProxy(next) ||
      seen.has(next) ||
      seen.size >= 1024 ||
      Object.getPrototypeOf(next) !== nativeListenerPrototype
    )
      return false;
    seen.add(next);
    const node: Record<string, unknown> = Object.create(null) as Record<
      string,
      unknown
    >;
    for (const key of Reflect.ownKeys(next)) {
      if (
        typeof key !== "string" ||
        !["next", "previous", "listener", "flags", "callback"].includes(key)
      )
        return false;
      const descriptor = Object.getOwnPropertyDescriptor(next, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
        return false;
      node[key] = descriptor.value;
    }
    if (
      node.previous !== previous ||
      !Number.isInteger(node.flags) ||
      (node.flags as number) < 0 ||
      (node.flags as number) > 127
    )
      return false;
    if (nativeWeakGetter.call(next)) {
      if (!validWeakRef(node.listener) || !validWeakRef(node.callback))
        return false;
    } else if (
      typeof node.callback !== "function" ||
      types.isProxy(node.callback) ||
      (typeof node.listener !== "function" &&
        (typeof node.listener !== "object" || node.listener === null)) ||
      types.isProxy(node.listener)
    )
      return false;
    if (node.listener !== inactiveHandler) active++;
    previous = next;
    next = node.next;
  }
  // Native onabort wrappers may retain their count when initially assigned null.
  return seen.size === header.size || active === header.size;
}
function validSignal(
  signal: unknown,
  establishedEvents?: ReadonlyMap<PropertyKey, object>,
): signal is AbortSignal {
  if (signal === null || typeof signal !== "object" || types.isProxy(signal))
    return false;
  try {
    if (Object.getPrototypeOf(signal) !== AbortSignal.prototype) return false;
    if (establishedEvents)
      for (const [key, eventMap] of establishedEvents) {
        const descriptor = Object.getOwnPropertyDescriptor(signal, key);
        if (
          !descriptor ||
          !("value" in descriptor) ||
          descriptor.value !== eventMap
        )
          return false;
      }
    const signalKeys = Reflect.ownKeys(signal);
    if (signalKeys.length > 128) return false;
    const inactiveHandlers = new Map<string, unknown>();
    for (const [key, slot] of nativeSignalSlots) {
      if (!slot.kinds.has("map") || nativeEventMaps.has(key)) continue;
      const descriptor = Object.getOwnPropertyDescriptor(signal, key);
      const value: unknown = descriptor?.value;
      if (
        descriptor &&
        "value" in descriptor &&
        value === undefined &&
        slot.allowsUndefined
      )
        continue;
      if (
        !descriptor ||
        !("value" in descriptor) ||
        types.isProxy(value) ||
        !types.isMap(value) ||
        !slot.prototypes.has(Object.getPrototypeOf(value) as object) ||
        Reflect.ownKeys(value).length
      )
        return false;
      let entries = 0;
      Map.prototype.forEach.call(value, (handler: unknown, event: unknown) => {
        if (
          ++entries > 1024 ||
          typeof handler !== "function" ||
          types.isProxy(handler) ||
          typeof event !== "string"
        )
          throw new Error("event_handlers");
        const data = Object.getOwnPropertyDescriptor(handler, "handler");
        if (data && !("value" in data)) throw new Error("event_handler");
        if (data && typeof data.value !== "function")
          inactiveHandlers.set(event, handler);
      });
    }
    for (const key of signalKeys) {
      const descriptor = Object.getOwnPropertyDescriptor(signal, key);
      if (
        !descriptor ||
        !("value" in descriptor) ||
        types.isProxy(descriptor.value) ||
        typeof key === "string"
      )
        return false;
      const value: unknown = descriptor.value;
      const slot = nativeSignalSlots.get(key);
      if (!slot) {
        if (typeof value === "object" || typeof value === "function")
          return false;
        continue;
      }
      if (value === undefined) {
        if (!slot.allowsUndefined) return false;
        continue;
      }
      const kind: NativeSignalKind = types.isMap(value)
        ? "map"
        : types.isSet(value)
          ? "set"
          : slot.kinds.has("weakref") && nativeWeakRefValue(value)
            ? "weakref"
            : typeof value === "boolean"
              ? "boolean"
              : typeof value === "number"
                ? "number"
                : "opaque";
      if (!slot.kinds.has("opaque") && !slot.kinds.has(kind)) return false;
      if (
        kind === "number" &&
        !slot.kinds.has("opaque") &&
        (typeof value !== "number" || !Number.isFinite(value) || value < 0)
      )
        return false;
      if (kind === "weakref" && !validWeakRef(value)) return false;
      if (kind === "map" && !slot.kinds.has("opaque")) {
        if (
          !types.isMap(value) ||
          !slot.prototypes.has(Object.getPrototypeOf(value) as object) ||
          Reflect.ownKeys(value).length
        )
          return false;
        let entries = 0;
        let valid = true;
        Map.prototype.forEach.call(value, (entry: unknown, event: unknown) => {
          if (++entries > 1024) throw new Error("event_bounds");
          if (
            typeof event !== "string" ||
            (nativeEventMaps.has(key)
              ? !validEventHeader(entry, inactiveHandlers.get(event as string))
              : typeof entry !== "function" || types.isProxy(entry))
          )
            valid = false;
        });
        if (!valid) return false;
      }
      if (kind === "set" && !slot.kinds.has("opaque")) {
        if (
          !types.isSet(value) ||
          !slot.prototypes.has(Object.getPrototypeOf(value) as object) ||
          Reflect.ownKeys(value).length
        )
          return false;
        let entries = 0;
        let valid = true;
        Set.prototype.forEach.call(value, (entry: unknown) => {
          if (++entries > 1024) throw new Error("signal_bounds");
          if (!validWeakRef(entry)) valid = false;
        });
        if (!valid) return false;
      }
    }
    for (const [key, slot] of nativeSignalSlots)
      if (slot.kinds.has("map") && !Object.hasOwn(signal, key)) return false;
    return typeof abortedGetter?.call(signal) === "boolean";
  } catch {
    return false;
  }
}
/** Registration materializes lazy event storage; retain that exact caller listener map. */
function establishedSignalEvents(
  signal: AbortSignal,
): ReadonlyMap<PropertyKey, object> {
  const established = new Map<PropertyKey, object>();
  for (const key of nativeEventMaps) {
    const descriptor = Object.getOwnPropertyDescriptor(signal, key);
    const value: unknown = descriptor?.value;
    if (
      !descriptor ||
      !("value" in descriptor) ||
      types.isProxy(value) ||
      !types.isMap(value)
    )
      throw new Error("signal_event_state");
    established.set(key, value);
  }
  return established;
}

function safelyNotify<Value>(
  callback: ((value: Value) => void) | undefined,
  value: Value,
): void {
  try {
    const returned: unknown = callback?.(Object.freeze(value));
    if (types.isPromise(returned) && !types.isProxy(returned))
      nativePromiseThen.call(
        returned,
        () => undefined,
        () => undefined,
      );
  } catch {
    /* Telemetry loss cannot authorize or alter an invocation. */
  }
}

/** Semantic confirmation responses use own data; trusted provider execution stays separate. */
type ConfirmationOperation =
  | "allocation"
  | "issue"
  | "consume"
  | "begin"
  | "complete"
  | "decision"
  | "query";
const canonical256 = (value: unknown): value is string => {
  try {
    decodeCanonicalBase64Url256(value);
    return true;
  } catch {
    return false;
  }
};
function confirmationResponse<T>(
  value: unknown,
  operation: ConfirmationOperation,
  expected?: ConfirmationAction | ConfirmationReceipt,
): T {
  try {
    const result = ownData(value, [
      "ok",
      "error",
      "challenge",
      "receipt",
      "attempt",
      "kernelInvocationId",
      "outcome",
      "confirmationToken",
      "expiresAt",
      "completed",
    ]);
    if (result.ok !== true && result.ok !== false)
      throw new Error("confirmation_response");
    const exact = (
      data: Record<string, unknown>,
      keys: readonly string[],
    ): void => {
      if (
        Object.keys(data).length !== keys.length ||
        keys.some((key) => !Object.hasOwn(data, key))
      )
        throw new Error("confirmation_response");
    };
    const handle = (artifact: unknown, prefix: string): boolean => {
      if (typeof artifact !== "string") return false;
      const segments = artifact.split(".");
      return (
        segments.length === 4 &&
        segments[0] === prefix &&
        /^[A-Za-z0-9_-]{1,32}$/.test(segments[1]!) &&
        canonical256(segments[2]) &&
        canonical256(segments[3])
      );
    };
    const timestamp = (value: unknown): boolean =>
      typeof value === "string" &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
      Number.isFinite(Date.parse(value)) &&
      new Date(value).toISOString() === value;
    const receipt = (
      value: unknown,
      attempt = false,
    ): Record<string, unknown> => {
      const data = ownData(
        value,
        attempt
          ? ["recordId", "confirmationRef", "executionAttemptId"]
          : ["recordId", "confirmationRef"],
      );
      exact(
        data,
        attempt
          ? ["recordId", "confirmationRef", "executionAttemptId"]
          : ["recordId", "confirmationRef"],
      );
      if (
        !Object.isFrozen(value) ||
        !canonical256(data.recordId) ||
        typeof data.confirmationRef !== "string" ||
        !data.confirmationRef.startsWith("capr1.") ||
        !canonical256(data.confirmationRef.slice(6)) ||
        (attempt && !canonical256(data.executionAttemptId))
      )
        throw new Error("confirmation_response");
      return data;
    };
    if (result.ok === false) {
      exact(result, ["ok", "error"]);
      const error = ownData(result.error, [
        "code",
        "status",
        "message",
        "retryable",
      ]);
      exact(error, ["code", "status", "message", "retryable"]);
      if (
        typeof error.code !== "string" ||
        typeof error.message !== "string" ||
        typeof error.retryable !== "boolean" ||
        ![
          "failed_precondition",
          "unavailable",
          "unauthenticated",
          "permission_denied",
          "invalid_argument",
        ].includes(error.status as string)
      )
        throw new Error("confirmation_response");
      const safeErrors: Readonly<
        Record<
          string,
          { status: string; message: string; retryable: boolean | undefined }
        >
      > = {
        CAP_CONFIRMATION_INVALID: {
          status: "failed_precondition",
          message: "Approval evidence is invalid.",
          retryable: false,
        },
        CAP_DEPENDENCY_UNAVAILABLE: {
          status: "unavailable",
          message: "Required runtime provider is unavailable.",
          retryable: undefined,
        },
        CAP_UNAUTHENTICATED: {
          status: "unauthenticated",
          message: "Invocation failed.",
          retryable: false,
        },
        CAP_PERMISSION_DENIED: {
          status: "permission_denied",
          message: "Invocation failed.",
          retryable: false,
        },
        CAP_INPUT_INVALID: {
          status: "invalid_argument",
          message: "Confirmation operation failed.",
          retryable: false,
        },
      };
      const safe = Object.hasOwn(safeErrors, error.code)
        ? safeErrors[error.code]
        : undefined;
      if (
        !safe ||
        safe.status !== error.status ||
        (safe.retryable !== undefined && safe.retryable !== error.retryable)
      )
        throw new Error("confirmation_response");
      result.error = { ...error, message: safe.message };
    }
    if (result.ok === true) {
      if (operation === "allocation") {
        exact(result, ["ok", "kernelInvocationId"]);
        if (!canonical256(result.kernelInvocationId))
          throw new Error("confirmation_response");
      } else if (operation === "consume") {
        exact(result, ["ok", "receipt"]);
        receipt(result.receipt);
      } else if (operation === "begin") {
        exact(result, ["ok", "attempt"]);
        const data = receipt(result.attempt, true);
        const consumed = receipt(expected);
        if (
          data.recordId !== consumed.recordId ||
          data.confirmationRef !== consumed.confirmationRef
        )
          throw new Error("confirmation_response");
      } else if (operation === "issue") {
        exact(result, ["ok", "challenge"]);
        const challenge = ownData(result.challenge, [
          "challenge",
          "capability",
          "summary",
          "impact",
          "expiresAt",
        ]);
        exact(challenge, [
          "challenge",
          "capability",
          "summary",
          "impact",
          "expiresAt",
        ]);
        const capability = ownData(challenge.capability, ["id", "version"]);
        exact(capability, ["id", "version"]);
        const action = expected as ConfirmationAction;
        if (
          !handle(challenge.challenge, "capc1") ||
          capability.id !== action.capabilityId ||
          capability.version !== action.version ||
          challenge.impact !== action.impact ||
          !timestamp(challenge.expiresAt) ||
          typeof challenge.summary !== "string" ||
          challenge.summary.length === 0 ||
          Buffer.byteLength(challenge.summary, "utf8") > 512 ||
          /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u.test(
            challenge.summary,
          ) ||
          /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(
            challenge.summary,
          )
        )
          throw new Error("confirmation_response");
        result.challenge = copyJson(result.challenge);
      } else if (operation === "decision") {
        if (result.outcome === "denied") exact(result, ["ok", "outcome"]);
        else if (result.outcome === "approved") {
          exact(result, ["ok", "outcome", "confirmationToken", "expiresAt"]);
          if (
            !handle(result.confirmationToken, "capa1") ||
            !timestamp(result.expiresAt)
          )
            throw new Error("confirmation_response");
        } else throw new Error("confirmation_response");
      } else if (operation === "query") {
        exact(result, ["ok", "completed"]);
        if (typeof result.completed !== "boolean")
          throw new Error("confirmation_response");
      } else exact(result, ["ok"]);
    }
    return result as T;
  } catch {
    return {
      ok: false,
      error: {
        code: "CAP_DEPENDENCY_UNAVAILABLE",
        status: "unavailable",
        message: "Required runtime provider is unavailable.",
        retryable: true,
      },
    } as T;
  }
}

const nativePromiseThen = Promise.prototype.then;
/** Semantic results stay opaque; trusted provider native Promise machinery is contained. */
function providerValue(
  callback: () => unknown,
): Promise<{ value: unknown } | { failed: true }> {
  return new Promise((resolve) => {
    queueMicrotask(() => {
      try {
        const returned = callback();
        if (types.isPromise(returned) && !types.isProxy(returned)) {
          nativePromiseThen.call(
            returned,
            (value) => resolve({ value }),
            () => resolve({ failed: true }),
          );
        } else resolve({ value: returned });
      } catch {
        resolve({ failed: true });
      }
    });
  });
}

function idempotencyResponse<T>(
  value: unknown,
  operation: "inspect" | "claim" | "complete",
): IdempotencyResult<T> {
  const unavailable = (): IdempotencyResult<T> => ({
    ok: false,
    error: {
      code: "CAP_DEPENDENCY_UNAVAILABLE",
      status: "unavailable",
      message: "Required runtime provider is unavailable.",
      retryable: operation !== "complete",
    },
  });
  try {
    const data = ownData(value, [
      "ok",
      "error",
      "outcome",
      "claim",
      "terminal",
      "confirmation",
    ]);
    const exact = (
      value: Record<string, unknown>,
      fields: readonly string[],
    ) => {
      if (
        Object.keys(value).length !== fields.length ||
        fields.some((field) => !Object.hasOwn(value, field))
      )
        throw new Error("response");
    };
    if (data.ok === false) {
      exact(data, ["ok", "error"]);
      const error = ownData(data.error, [
        "code",
        "status",
        "message",
        "retryable",
      ]);
      exact(error, ["code", "status", "message", "retryable"]);
      const codes: Record<string, string> = {
        CAP_DEPENDENCY_UNAVAILABLE: "unavailable",
        CAP_IDEMPOTENCY_KEY_REQUIRED: "invalid_argument",
        CAP_IDEMPOTENCY_CONFLICT: "failed_precondition",
        CAP_IDEMPOTENCY_IN_PROGRESS: "failed_precondition",
        CAP_IDEMPOTENCY_RESULT_UNAVAILABLE: "failed_precondition",
        CAP_IDEMPOTENCY_AMBIGUOUS: "failed_precondition",
      };
      if (
        typeof error.code !== "string" ||
        !Object.hasOwn(codes, error.code) ||
        codes[error.code] !== error.status ||
        typeof error.message !== "string" ||
        typeof error.retryable !== "boolean" ||
        (error.code !== "CAP_DEPENDENCY_UNAVAILABLE" &&
          error.retryable !== false)
      )
        throw new Error("error");
      return {
        ok: false,
        error: {
          code: error.code,
          status: error.status as "unavailable",
          message: "Idempotency admission or persistence failed.",
          retryable: operation === "complete" ? false : error.retryable,
        },
      };
    }
    if (data.ok !== true) throw new Error("response");
    if (operation === "complete") {
      exact(data, ["ok"]);
      return value as IdempotencyResult<T>;
    }
    if (data.outcome === "absent" && operation === "inspect")
      exact(data, ["ok", "outcome"]);
    else if (data.outcome === "claimed" && operation === "claim") {
      exact(data, ["ok", "outcome", "claim"]);
      const claim = ownData(data.claim, ["index", "ownerId"]);
      exact(claim, ["index", "ownerId"]);
      if (
        !Object.isFrozen(data.claim) ||
        !canonical256(claim.index) ||
        !canonical256(claim.ownerId)
      )
        throw new Error("claim");
    } else if (data.outcome === "replay") {
      exact(
        data,
        data.confirmation === undefined
          ? ["ok", "outcome", "terminal"]
          : ["ok", "outcome", "terminal", "confirmation"],
      );
      const snapshot = redactJson(data.terminal, createRedactionState());
      const terminal = ownData(snapshot, ["kind", "value", "error"]);
      if (terminal.kind === "success") exact(terminal, ["kind", "value"]);
      else {
        if (
          !["declared_error", "unexpected_error"].includes(
            terminal.kind as string,
          )
        )
          throw new Error("terminal");
        exact(terminal, ["kind", "error"]);
        const error = ownData(terminal.error, [
          "code",
          "status",
          "message",
          "retryable",
          "details",
        ]);
        exact(
          error,
          Object.hasOwn(error, "details")
            ? ["code", "status", "message", "retryable", "details"]
            : ["code", "status", "message", "retryable"],
        );
        if (
          typeof error.code !== "string" ||
          typeof error.status !== "string" ||
          typeof error.message !== "string" ||
          typeof error.retryable !== "boolean"
        )
          throw new Error("terminal");
      }
      if (data.confirmation !== undefined) {
        const link = ownData(data.confirmation, [
          "recordId",
          "confirmationRef",
          "executionAttemptId",
        ]);
        exact(link, ["recordId", "confirmationRef", "executionAttemptId"]);
        if (
          !canonical256(link.recordId) ||
          !canonical256(link.executionAttemptId) ||
          typeof link.confirmationRef !== "string" ||
          !link.confirmationRef.startsWith("capr1.") ||
          !canonical256(link.confirmationRef.slice(6))
        )
          throw new Error("linkage");
      }
      return {
        ok: true,
        outcome: "replay",
        terminal: snapshot,
        ...(data.confirmation
          ? { confirmation: copyJson(data.confirmation) }
          : {}),
      } as IdempotencyResult<T>;
    } else throw new Error("response");
    return value as IdempotencyResult<T>;
  } catch {
    return unavailable();
  }
}

export function createRuntimeKernel(
  options: RuntimeKernelOptions,
): RuntimeKernel {
  let carrier: Record<string, unknown>;
  try {
    carrier = ownData(options, [
      "registry",
      "services",
      "onStage",
      "telemetry",
      "authenticationProviders",
      "adapters",
      "authorizationProvider",
      "identityFingerprintProvider",
      "internalInvocationSecurity",
      "disclosure",
      "maxInternalDepth",
      "confirmationProvider",
      "idempotencyProvider",
      "bearerDescriptors",
      "rateLimitProvider",
      "secretProvider",
      "failOpenPrivateReads",
      "redactionPaths",
      "onTrace",
      "onMetric",
      "onLog",
    ]);
  } catch {
    throw new RuntimeConfigurationError("CAP_RUNTIME_CONFIGURATION_INVALID");
  }
  const registry = registryState(carrier.registry);
  if (
    !registry ||
    (carrier.onStage !== undefined && typeof carrier.onStage !== "function") ||
    (carrier.telemetry !== undefined && typeof carrier.telemetry !== "function")
  )
    throw new RuntimeConfigurationError("CAP_RUNTIME_CONFIGURATION_INVALID");
  const onStage = carrier.onStage as RuntimeKernelOptions["onStage"];
  const telemetry = carrier.telemetry as RuntimeKernelOptions["telemetry"];
  let services: Readonly<Record<string, unknown>>;
  try {
    services = Object.freeze(
      carrier.services === undefined
        ? Object.create(null)
        : ownData(carrier.services),
    ) as Readonly<Record<string, unknown>>;
  } catch {
    throw new RuntimeConfigurationError("CAP_RUNTIME_CONFIGURATION_INVALID");
  }
  const onTrace = carrier.onTrace as RuntimeKernelOptions["onTrace"];
  const onMetric = carrier.onMetric as RuntimeKernelOptions["onMetric"];
  const onLog = carrier.onLog as RuntimeKernelOptions["onLog"];
  let rateCheck:
    ((view: import("./types.js").RateLimitView) => unknown) | undefined;
  let secretResolve:
    ((name: string, view: OperationView) => unknown) | undefined;
  const failOpen = new Set<string>();
  try {
    for (const hook of [onTrace, onMetric, onLog])
      if (
        hook !== undefined &&
        (typeof hook !== "function" || types.isProxy(hook))
      )
        throw new Error("hook");
    let policyNames: unknown[] = [];
    const array = (value: unknown): unknown[] => {
      if (
        types.isProxy(value) ||
        !Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Array.prototype
      )
        throw new Error("array");
      if (
        value.length > 1024 ||
        Reflect.ownKeys(value).length !== value.length + 1
      )
        throw new Error("array");
      return Array.from({ length: value.length }, (_, index) => {
        const descriptor = Object.getOwnPropertyDescriptor(
          value,
          String(index),
        );
        if (!descriptor || !("value" in descriptor)) throw new Error("array");
        return descriptor.value as unknown;
      });
    };
    if (carrier.rateLimitProvider !== undefined) {
      const data = ownData(carrier.rateLimitProvider, ["policies", "check"]);
      policyNames = array(data.policies);
      if (
        typeof data.check !== "function" ||
        types.isProxy(data.check) ||
        policyNames.some(
          (name) => typeof name !== "string" || !name || name.length > 128,
        ) ||
        new Set(policyNames).size !== policyNames.length
      )
        throw new Error("rate");
      const check = data.check as NonNullable<
        RuntimeKernelOptions["rateLimitProvider"]
      >["check"];
      rateCheck = (view) => check.call(carrier.rateLimitProvider, view);
    }
    if (carrier.secretProvider !== undefined) {
      const data = ownData(carrier.secretProvider, ["resolve"]);
      if (typeof data.resolve !== "function" || types.isProxy(data.resolve))
        throw new Error("secret");
      const resolve = data.resolve as NonNullable<
        RuntimeKernelOptions["secretProvider"]
      >["resolve"];
      secretResolve = (name, view) =>
        resolve.call(carrier.secretProvider, name, view);
    }
    for (const { capability } of registry.entries.values()) {
      const rate = capability.limits.rateLimit as
        { policy: string } | undefined;
      if (rate && (!rateCheck || !policyNames.includes(rate.policy)))
        throw new RuntimeConfigurationError("CAP_RUNTIME_PROVIDER_UNAVAILABLE");
      if (
        (
          capability.requirements.secrets as readonly { optional: boolean }[]
        ).some((declaration) => !declaration.optional) &&
        !secretResolve
      )
        throw new RuntimeConfigurationError("CAP_RUNTIME_PROVIDER_UNAVAILABLE");
    }
    if (carrier.failOpenPrivateReads !== undefined)
      for (const id of array(carrier.failOpenPrivateReads)) {
        if (typeof id !== "string" || failOpen.has(id))
          throw new Error("failopen");
        const capability = registry.entries.get(id)?.capability;
        if (
          !capability ||
          !capability.limits.rateLimit ||
          capability.effects.impact !== "read" ||
          Object.values(capability.access.exposure).some(
            (exposure) => exposure !== "disabled" && exposure !== "private",
          )
        )
          throw new Error("failopen");
        failOpen.add(id);
      }
  } catch (error) {
    if (error instanceof RuntimeConfigurationError) throw error;
    throw new RuntimeConfigurationError("CAP_RUNTIME_CONFIGURATION_INVALID");
  }
  const redactionPaths = compileRedactionPaths(
    carrier.redactionPaths,
    new Set(registry.entries.keys()),
  );
  const bearerGuard = compileBearerDescriptors(
    carrier.bearerDescriptors as readonly unknown[] | undefined,
  );
  let reportFingerprintFailure:
    | ((
        incident: Readonly<IdentityFingerprintFailureIncident>,
        controls: ConfirmationOperationControls,
      ) => unknown)
    | undefined;
  const confirmationProvider =
    carrier.confirmationProvider as RuntimeKernelOptions["confirmationProvider"];
  if (confirmationProvider !== undefined) {
    try {
      const provider = ownData(confirmationProvider);
      for (const name of [
        "allocateKernelInvocationId",
        "issue",
        "consume",
        "decideConfirmation",
        "beginExecution",
        "completeExecution",
      ])
        if (typeof provider[name] !== "function") throw new Error("provider");
      if (provider.reportProviderFailure !== undefined) {
        if (
          typeof provider.reportProviderFailure !== "function" ||
          types.isProxy(provider.reportProviderFailure)
        )
          throw new Error("provider");
        const report = provider.reportProviderFailure as NonNullable<
          NonNullable<
            RuntimeKernelOptions["confirmationProvider"]
          >["reportProviderFailure"]
        >;
        reportFingerprintFailure = (incident, controls) =>
          report.call(confirmationProvider, incident, controls);
      }
    } catch {
      throw new RuntimeConfigurationError("CAP_RUNTIME_CONFIGURATION_INVALID");
    }
  }
  const unhealthyConfirmationPolicies = new Set<string>();
  const idempotencyProvider = carrier.idempotencyProvider as
    IdempotencyProvider | undefined;
  if (idempotencyProvider !== undefined) {
    try {
      const provider = ownData(idempotencyProvider);
      for (const name of [
        "inspect",
        "claim",
        "enter",
        "release",
        "complete",
        "reconcile",
      ])
        if (typeof provider[name] !== "function") throw new Error("provider");
    } catch {
      throw new RuntimeConfigurationError("CAP_RUNTIME_CONFIGURATION_INVALID");
    }
  }
  let identityUnavailable = false;

  const allocateCorrelation = (): string => {
    if (identityUnavailable)
      throw new RuntimeConfigurationError("CAP_RUNTIME_IDENTITY_UNAVAILABLE");
    try {
      return randomUUID();
    } catch {
      identityUnavailable = true;
      throw new RuntimeConfigurationError("CAP_RUNTIME_IDENTITY_UNAVAILABLE");
    }
  };
  const providers = new Map<
    string,
    {
      authenticate: (credentials: unknown, view: OperationView) => unknown;
      authenticateDisclosure?: (
        credentials: unknown,
        view: AdapterDisclosureAuthenticationView,
      ) => unknown;
    }
  >();
  const principalIssuerIds = new Set<string>();
  const adapters = new Map<string, AdapterRegistration>();
  const tokens = new WeakMap<
    object,
    {
      adapter: AdapterRegistration;
      capability: string;
      identity: IdentityContext;
    }
  >();
  const requesters = new WeakMap<
    object,
    {
      readonly adapter: AdapterRegistration;
      readonly identity: JsonValue;
    }
  >();
  const authorizationProvider =
    carrier.authorizationProvider as RuntimeKernelOptions["authorizationProvider"];
  const derivePolicies = new Map<
    string,
    {
      readonly providerId: string;
      readonly derive: (view: InternalInvocationTransitionView) => unknown;
    }
  >();
  const servicePolicies = new Map<
    string,
    { readonly evaluate: (view: InternalInvocationTransitionView) => unknown }
  >();
  let deployment: string | undefined;
  let serviceIdentity:
    | {
        readonly id: string;
        readonly resolve: (view: InternalInvocationTransitionView) => unknown;
      }
    | undefined;
  let fingerprintProvider:
    | {
        readonly id: string;
        readonly fingerprint: NonNullable<
          RuntimeKernelOptions["identityFingerprintProvider"]
        >["fingerprint"];
      }
    | undefined;
  let journal:
    | {
        readonly id: string;
        readonly commit: NonNullable<
          NonNullable<
            RuntimeKernelOptions["internalInvocationSecurity"]
          >["journal"]
        >["commit"];
      }
    | undefined;
  const conceal = carrier.disclosure === "conceal";
  const maxDepth = carrier.maxInternalDepth ?? 32;
  try {
    if (
      (carrier.disclosure !== undefined &&
        !["explicit", "conceal"].includes(carrier.disclosure as string)) ||
      (authorizationProvider !== undefined &&
        typeof authorizationProvider !== "function") ||
      !Number.isInteger(maxDepth) ||
      (maxDepth as number) < 1 ||
      (maxDepth as number) > 32
    )
      throw new Error("configuration");
    const list = (value: unknown): unknown[] => {
      if (value === undefined) return [];
      if (
        typeof value !== "object" ||
        value === null ||
        types.isProxy(value) ||
        !Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Array.prototype ||
        Reflect.ownKeys(value).length !== value.length + 1 ||
        value.length > 256
      )
        throw new Error("list");
      const output: unknown[] = [];
      for (let i = 0; i < value.length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
          throw new Error("list");
        output.push(descriptor.value);
      }
      return output;
    };
    for (const provider of list(carrier.authenticationProviders)) {
      const data = ownData(provider, [
        "id",
        "authenticate",
        "authenticateDisclosure",
      ]);
      if (
        !canonicalIdentityId(data.id) ||
        typeof data.authenticate !== "function" ||
        (data.authenticateDisclosure !== undefined &&
          (typeof data.authenticateDisclosure !== "function" ||
            types.isProxy(data.authenticateDisclosure))) ||
        principalIssuerIds.has(data.id)
      )
        throw new Error("provider");
      providers.set(data.id, {
        authenticate: data.authenticate as (
          credentials: unknown,
          view: OperationView,
        ) => unknown,
        ...(data.authenticateDisclosure === undefined
          ? {}
          : {
              authenticateDisclosure: data.authenticateDisclosure as (
                credentials: unknown,
                view: AdapterDisclosureAuthenticationView,
              ) => unknown,
            }),
      });
      principalIssuerIds.add(data.id);
    }
    if (carrier.identityFingerprintProvider !== undefined) {
      const provider = ownData(carrier.identityFingerprintProvider, [
        "id",
        "fingerprint",
      ]);
      if (
        Object.keys(provider).length !== 2 ||
        !canonicalIdentityId(provider.id) ||
        typeof provider.fingerprint !== "function" ||
        types.isProxy(provider.fingerprint)
      )
        throw new Error("fingerprint");
      const fingerprint = provider.fingerprint as NonNullable<
        RuntimeKernelOptions["identityFingerprintProvider"]
      >["fingerprint"];
      fingerprintProvider = {
        id: provider.id,
        fingerprint: (identity, controls) =>
          fingerprint.call(
            carrier.identityFingerprintProvider,
            identity,
            controls,
          ),
      };
    }
    if (carrier.internalInvocationSecurity !== undefined) {
      const security = ownData(carrier.internalInvocationSecurity, [
        "deployment",
        "derivePolicies",
        "servicePolicies",
        "serviceIdentityProvider",
        "journal",
      ]);
      if (!canonicalIdentityId(security.deployment))
        throw new Error("deployment");
      deployment = security.deployment;
      for (const registration of list(security.derivePolicies)) {
        const data = ownData(registration, ["id", "providerId", "derive"]);
        if (
          Object.keys(data).length !== 3 ||
          !canonicalIdentityId(data.id) ||
          derivePolicies.has(data.id) ||
          !canonicalIdentityId(data.providerId) ||
          principalIssuerIds.has(data.providerId) ||
          typeof data.derive !== "function" ||
          types.isProxy(data.derive)
        )
          throw new Error("derive");
        const derive = data.derive as (
          view: InternalInvocationTransitionView,
        ) => unknown;
        derivePolicies.set(data.id, {
          providerId: data.providerId,
          derive: (view) => derive.call(registration, view),
        });
        principalIssuerIds.add(data.providerId);
      }
      for (const registration of list(security.servicePolicies)) {
        const data = ownData(registration, ["id", "evaluate"]);
        if (
          Object.keys(data).length !== 2 ||
          !canonicalIdentityId(data.id) ||
          servicePolicies.has(data.id) ||
          typeof data.evaluate !== "function" ||
          types.isProxy(data.evaluate)
        )
          throw new Error("service_policy");
        const evaluate = data.evaluate as (
          view: InternalInvocationTransitionView,
        ) => unknown;
        servicePolicies.set(data.id, {
          evaluate: (view) => evaluate.call(registration, view),
        });
      }
      if (security.serviceIdentityProvider !== undefined) {
        const provider = ownData(security.serviceIdentityProvider, [
          "id",
          "resolve",
        ]);
        if (
          Object.keys(provider).length !== 2 ||
          !canonicalIdentityId(provider.id) ||
          principalIssuerIds.has(provider.id) ||
          typeof provider.resolve !== "function" ||
          types.isProxy(provider.resolve)
        )
          throw new Error("service_identity");
        const resolve = provider.resolve as (
          view: InternalInvocationTransitionView,
        ) => unknown;
        serviceIdentity = {
          id: provider.id,
          resolve: (view) =>
            resolve.call(security.serviceIdentityProvider, view),
        };
        principalIssuerIds.add(provider.id);
      }
      if (security.journal !== undefined) {
        const provider = ownData(security.journal, ["id", "commit"]);
        if (
          Object.keys(provider).length !== 2 ||
          !canonicalIdentityId(provider.id) ||
          typeof provider.commit !== "function" ||
          types.isProxy(provider.commit)
        )
          throw new Error("journal");
        const commit = provider.commit as NonNullable<
          NonNullable<
            RuntimeKernelOptions["internalInvocationSecurity"]
          >["journal"]
        >["commit"];
        journal = {
          id: provider.id,
          commit: (event, controls) =>
            commit.call(security.journal, event, controls),
        };
      }
      if (
        fingerprintProvider &&
        journal &&
        fingerprintProvider.id === journal.id
      )
        throw new Error("provider_id");
    }
    for (const registration of list(carrier.adapters)) {
      const data = ownData(registration, [
        "id",
        "source",
        "providerId",
        "capabilities",
        "privateBoundary",
      ]);
      const ids = copyJson(data.capabilities);
      if (
        !canonicalIdentityId(data.id) ||
        adapters.has(data.id) ||
        !canonicalIdentityId(data.providerId) ||
        !providers.has(data.providerId) ||
        !["http", "cli", "mcp", "internal", "sdk"].includes(
          data.source as string,
        ) ||
        !Array.isArray(ids) ||
        ids.some((id) => typeof id !== "string" || !registry.entries.has(id)) ||
        (data.privateBoundary !== undefined &&
          typeof data.privateBoundary !== "boolean")
      )
        throw new Error("adapter");
      adapters.set(
        data.id,
        Object.freeze({
          ...data,
          capabilities: ids,
        }) as unknown as AdapterRegistration,
      );
    }
  } catch {
    throw new RuntimeConfigurationError("CAP_RUNTIME_CONFIGURATION_INVALID");
  }
  type SourceChain = OperationView["sourceChain"];
  interface ParentState {
    observeCancellation: () => void;
    privateBoundary: boolean;
    redactionState: RedactionState;
    identity: IdentityContext;
    sourceChain: SourceChain;
    ancestry: readonly string[];
    deadlineMs: number;
    signal: AbortSignal;
    traceId: string;
    spanId: string;
    depth: number;
    caller: InternalInvocationNode;
  }
  interface IngressState {
    adapter: AdapterRegistration;
    credentials?: unknown;
    hasCredentials: boolean;
  }
  const invoke = async (
    request: InvocationRequest,
    ingress?: IngressState,
    parent?: ParentState,
    invalid = false,
    transition?: Readonly<{
      mode: "delegate" | "derive" | "service";
      policyId?: string;
    }>,
  ): Promise<InvocationResult> => {
    const correlationId = allocateCorrelation();
    const startedAt = Date.now();
    const redactionState = parent?.redactionState ?? createRedactionState();
    const redactionValues = redactionState.strings;
    const redactSecrets = (value: unknown): JsonValue =>
      redactJson(value, redactionState);
    const hasSensitiveString = (value: string): boolean =>
      [...redactionValues].some((pattern) =>
        pattern === "" ? value === "" : value.includes(pattern),
      );
    const notify = <Value>(
      callback: ((value: Value) => void) | undefined,
      value: Value,
    ): void => {
      if (
        Object.values(value as Record<string, unknown>).some(
          (field) => typeof field === "string" && hasSensitiveString(field),
        )
      )
        return;
      safelyNotify(callback, value);
    };
    const failure = (
      code: string,
      status: ErrorStatus,
      details?: JsonValue,
      message = "Invocation failed.",
      retryable = false,
    ): InvocationResult => ({
      ok: false,
      error: {
        code,
        status,
        message,
        retryable,
        correlationId,
        ...(details === undefined ? {} : { details }),
      },
    });
    const invalidInput = (): InvocationResult =>
      failure("CAP_INPUT_INVALID", "invalid_argument", {
        path: "/input",
        code: "schema_constraint",
      });
    const diagnostic = (code: string): void =>
      notify(telemetry, {
        kind: "diagnostic",
        code,
        correlationId,
        severity: "error",
      } satisfies RuntimeTelemetryEvent);
    if (invalid) return failure("CAP_INTERNAL_INVOCATION_INVALID", "internal");
    let root: Record<string, unknown>;
    try {
      root = ownData(request, requestKeys);
    } catch {
      return failure("CAP_INTERNAL_INVOCATION_INVALID", "internal");
    }
    let adapterCandidate:
      | { readonly ok: true; readonly input: unknown }
      | {
          readonly ok: false;
          readonly code:
            | "CAP_INPUT_INVALID"
            | "CAP_MCP_CLIENT_METADATA_REQUIRED"
            | CliAdapterRejectionCode;
          readonly status: "invalid_argument" | "failed_precondition";
          readonly safeDetails?: JsonValue;
        }
      | {
          readonly ok: false;
          readonly code: "CAP_INTERNAL";
          readonly status: "internal";
        }
      | undefined;
    let adapterTimeoutMs: number | undefined;
    const rootControlPresence = {
      confirmationToken: Object.hasOwn(root, "confirmationToken"),
      idempotencyKey: Object.hasOwn(root, "idempotencyKey"),
      correlationId: Object.hasOwn(root, "correlationId"),
    };
    if (
      !bearerGuard.validateCorrelationHint(
        root.correlationId,
        Object.hasOwn(root, "correlationId"),
      ).valid
    )
      return failure("CAP_INPUT_INVALID", "invalid_argument", {
        path: "/correlationId",
      });
    // The ingress hint is intentionally excluded from every later operation value.
    delete root.correlationId;
    if (
      typeof root.capability !== "string" ||
      !["http", "cli", "mcp", "internal", "sdk"].includes(
        root.source as string,
      ) ||
      (root.version !== undefined && typeof root.version !== "string")
    )
      return failure("CAP_INTERNAL_INVOCATION_INVALID", "internal");
    const entry = registry.entries.get(root.capability);
    if (!entry) return failure("CAP_NOT_FOUND", "not_found");
    const { capability, validators, handler } = entry;
    const source = root.source as InvocationRequest["source"];
    const stage = (
      name: (typeof RUNTIME_STAGES)[number],
      skipped = false,
    ): void =>
      notify(onStage, {
        stage: name,
        skipped,
        capability: capability.id,
        version: capability.version,
        source,
        correlationId,
      });
    stage("resolve");
    const protectedTarget =
      capability.access.authentication !== "public" ||
      capability.access.permissions.public !== true ||
      capability.access.exposure[source === "sdk" ? "http" : source] !==
        "public";
    const denial = (
      code: string,
      status: ErrorStatus,
      unavailable = false,
    ): InvocationResult =>
      conceal && protectedTarget
        ? failure("CAP_NOT_FOUND", "not_found")
        : failure(
            code,
            status,
            undefined,
            unavailable
              ? "Required runtime provider is unavailable."
              : "Invocation failed.",
            unavailable,
          );
    if (root.version !== undefined && root.version !== capability.version)
      return conceal && protectedTarget
        ? failure("CAP_NOT_FOUND", "not_found")
        : failure("CAP_VERSION_UNSUPPORTED", "failed_precondition");
    if (ingress && !ingress.adapter.capabilities.includes(capability.id))
      return denial("CAP_UNAUTHENTICATED", "unauthenticated");
    const exposure =
      capability.access.exposure[source === "sdk" ? "http" : source];
    if (exposure === "disabled") return failure("CAP_NOT_FOUND", "not_found");
    if (
      source !== "internal" &&
      (!capability.interfaces[source].enabled ||
        (source === "sdk" && !capability.interfaces.http.enabled))
    )
      return failure("CAP_NOT_FOUND", "not_found");
    if (root.adapterCandidate !== undefined) {
      try {
        const candidate = ownData(root.adapterCandidate, adapterCandidateKeys);
        if (candidate.ok === true) {
          if (
            !Object.hasOwn(candidate, "input") ||
            Object.keys(candidate).some(
              (key) => !["ok", "input", "controls"].includes(key),
            )
          )
            throw new Error("adapter_candidate");
          if (Object.hasOwn(candidate, "controls")) {
            const controls = ownData(candidate.controls, adapterControlKeys);
            for (const key of [
              "confirmationToken",
              "idempotencyKey",
              "correlationId",
            ] as const) {
              if (!Object.hasOwn(controls, key)) continue;
              if (typeof controls[key] !== "string" || rootControlPresence[key])
                throw new Error("adapter_controls");
              root[key] = controls[key];
            }
            if (Object.hasOwn(controls, "timeoutMs")) {
              if (
                !Number.isSafeInteger(controls.timeoutMs) ||
                (controls.timeoutMs as number) <= 0
              )
                throw new Error("adapter_controls");
              adapterTimeoutMs = controls.timeoutMs as number;
            }
          }
          adapterCandidate = Object.freeze({
            ok: true,
            input: candidate.input,
          });
        } else if (candidate.ok === false) {
          if (
            !Object.hasOwn(candidate, "code") ||
            !Object.hasOwn(candidate, "status") ||
            Object.keys(candidate).some(
              (key) => !["ok", "code", "status", "safeDetails"].includes(key),
            )
          )
            throw new Error("adapter_candidate");
          const inputInvalid =
            candidate.code === "CAP_INPUT_INVALID" &&
            (candidate.status === "invalid_argument" ||
              candidate.status === 400);
          const metadataRequired =
            candidate.code === "CAP_MCP_CLIENT_METADATA_REQUIRED" &&
            candidate.status === "failed_precondition";
          const cliCode =
            typeof candidate.code === "string" &&
            Object.hasOwn(cliAdapterRejections, candidate.code)
              ? (candidate.code as CliAdapterRejectionCode)
              : undefined;
          const cliRejection =
            cliCode === undefined ? undefined : cliAdapterRejections[cliCode];
          const cliFailure =
            source === "cli" &&
            cliRejection !== undefined &&
            candidate.status === cliRejection.status;
          const internalFailure =
            candidate.code === "CAP_INTERNAL" &&
            candidate.status === "internal";
          if (
            !inputInvalid &&
            !metadataRequired &&
            !cliFailure &&
            !internalFailure
          )
            throw new Error("adapter_rejection");
          if (internalFailure) {
            if (Object.keys(candidate).length !== 3)
              throw new Error("adapter_rejection");
            adapterCandidate = Object.freeze({
              ok: false,
              code: "CAP_INTERNAL",
              status: "internal",
            });
          } else {
            adapterCandidate = Object.freeze({
              ok: false,
              code: candidate.code as
                | "CAP_INPUT_INVALID"
                | "CAP_MCP_CLIENT_METADATA_REQUIRED"
                | CliAdapterRejectionCode,
              status:
                inputInvalid || cliCode === "CAP_CLI_PAYLOAD_TOO_LARGE"
                  ? "invalid_argument"
                  : "failed_precondition",
              ...(Object.hasOwn(candidate, "safeDetails")
                ? {
                    safeDetails: cliFailure
                      ? boundedCliAdapterDetails(
                          cliCode!,
                          candidate.safeDetails,
                        )
                      : boundedAdapterDetails(candidate.safeDetails),
                  }
                : {}),
            });
          }
        } else throw new Error("adapter_candidate");
      } catch {
        return failure("CAP_INTERNAL_INVOCATION_INVALID", "internal");
      }
      delete root.adapterCandidate;
    }
    if (
      !bearerGuard.validateCorrelationHint(
        root.correlationId,
        Object.hasOwn(root, "correlationId"),
      ).valid
    )
      return failure("CAP_INPUT_INVALID", "invalid_argument", {
        path: "/correlationId",
      });
    delete root.correlationId;
    stage("context");
    if (root.signal !== undefined && !validSignal(root.signal))
      return failure("CAP_INTERNAL_INVOCATION_INVALID", "internal");
    let requestedDeadline = Infinity;
    if (root.deadline !== undefined) {
      try {
        if (
          typeof root.deadline !== "object" ||
          root.deadline === null ||
          types.isProxy(root.deadline)
        )
          throw new Error("deadline");
        requestedDeadline = getDateTime.call(root.deadline);
        if (!Number.isFinite(requestedDeadline)) throw new Error("deadline");
      } catch {
        return failure("CAP_INTERNAL_INVOCATION_INVALID", "internal");
      }
    }
    if (adapterTimeoutMs !== undefined)
      requestedDeadline = Math.min(
        requestedDeadline,
        startedAt + adapterTimeoutMs,
      );
    const deadlineMs = Math.min(
      requestedDeadline,
      parent?.deadlineMs ?? Infinity,
      Date.now() + Math.min(capability.execution.timeoutMs ?? 30_000, 30_000),
    );
    const controller = new AbortController();
    let interrupted: "CAP_CANCELLED" | "CAP_DEADLINE_EXCEEDED" | undefined;
    let started = false;
    let confirmationAttempt: ConfirmationAttempt | undefined;
    let idempotencyClaim: IdempotencyClaim | undefined;
    let idempotencyEntered = false;
    let terminalCompletion: Promise<boolean> | undefined;
    let settleInterrupt: ((result: InvocationResult) => void) | undefined;
    const interruption = new Promise<InvocationResult>((resolve) => {
      settleInterrupt = resolve;
    });
    const interrupt = (
      code: "CAP_CANCELLED" | "CAP_DEADLINE_EXCEEDED",
    ): void => {
      if (interrupted) return;
      interrupted = code;
      controller.abort();
      settleInterrupt?.(
        failure(
          code,
          code === "CAP_CANCELLED" ? "cancelled" : "deadline_exceeded",
          { executionState: started ? "started" : "not_started" },
        ),
      );
    };
    const parentSignal = root.signal as AbortSignal | undefined;
    const ancestorSignal = parent?.signal;
    const cancel = (): void => interrupt("CAP_CANCELLED");
    let establishedParentEvents: ReadonlyMap<PropertyKey, object> | undefined;
    const observeCancellation = (): void => {
      parent?.observeCancellation();
      if (
        parentSignal &&
        (!validSignal(parentSignal, establishedParentEvents) ||
          abortedGetter?.call(parentSignal))
      )
        interrupt("CAP_CANCELLED");
    };
    try {
      if (parentSignal) {
        addListener.call(parentSignal, "abort", cancel, { once: true });
        establishedParentEvents = establishedSignalEvents(parentSignal);
      }
    } catch {
      try {
        if (parentSignal && validSignal(parentSignal, establishedParentEvents))
          removeListener.call(parentSignal, "abort", cancel);
      } catch {
        /* Malformed native event state is contained. */
      }
      return failure("CAP_INTERNAL_INVOCATION_INVALID", "internal");
    }
    if (ancestorSignal)
      addListener.call(ancestorSignal, "abort", cancel, { once: true });
    const timer = setTimeout(
      () => interrupt("CAP_DEADLINE_EXCEEDED"),
      Math.max(0, deadlineMs - Date.now()),
    );
    // A pending invocation is real work: retain the timer until it settles.
    observeCancellation();
    if (
      (parentSignal &&
        (!validSignal(parentSignal, establishedParentEvents) ||
          abortedGetter?.call(parentSignal))) ||
      (ancestorSignal && abortedGetter?.call(ancestorSignal))
    )
      cancel();
    if (deadlineMs <= Date.now()) interrupt("CAP_DEADLINE_EXCEEDED");
    let result: InvocationResult;
    try {
      result = await (async (): Promise<InvocationResult> => {
        if (interrupted) return await interruption;
        const serviceName = registry.document.service.name;
        const currentNode: InternalInvocationNode = Object.freeze({
          service: serviceName,
          capability: capability.id,
          exactVersion: capability.version,
        });
        const node = `${serviceName}@${capability.id}@${capability.version}`;
        let identity = parent
          ? Object.freeze({
              ...parent.identity,
              provenance: Object.freeze([
                ...parent.identity.provenance,
                Object.freeze({
                  mode: transition?.mode ?? "delegate",
                  caller: parent.caller.capability,
                  target: capability.id,
                }),
              ]),
            })
          : rootIdentity(anonymousPrincipal);
        const sourceChain: SourceChain = Object.freeze([
          ...(parent?.sourceChain ?? []),
          Object.freeze({
            source,
            capability: capability.id,
            exactVersion: capability.version,
          }),
        ]);
        const traceId = parent?.traceId ?? correlationId;
        const spanId = correlationId;
        const operationView = (): OperationView => {
          const follower = new AbortController();
          const follow = (): void => {
            try {
              follower.abort();
            } catch {
              /* An isolated provider signal cannot compromise control. */
            }
          };
          addListener.call(controller.signal, "abort", follow, { once: true });
          if (abortedGetter?.call(controller.signal)) follow();
          return Object.freeze({
            capability: Object.freeze({
              id: capability.id,
              version: capability.version,
              access: capability.access,
            }),
            identity,
            sourceChain,
            correlationId,
            traceId,
            spanId,
            ...(parent ? { parentSpanId: parent.spanId } : {}),
            deadlineMs,
            signal: follower.signal,
          });
        };
        const awaitProvider = async (
          callback: () => unknown,
        ): Promise<
          { value: unknown } | { failed: true } | InvocationResult
        > => {
          observeCancellation();
          if (interrupted) return await interruption;
          const pending = providerValue(callback);
          const outcome = await Promise.race([pending, interruption]);
          observeCancellation();
          if (interrupted || deadlineMs <= Date.now()) {
            if (!interrupted) interrupt("CAP_DEADLINE_EXCEEDED");
            return await interruption;
          }
          return outcome;
        };
        let auditOwnerId: string | undefined;
        let cachedFingerprint:
          | {
              readonly identity: IdentityContext;
              readonly set: IdentityFingerprintSet;
            }
          | undefined;
        let serviceAssumed = false;
        const operationControls = () =>
          Object.freeze({
            deadlineMs,
            signal: operationView().signal,
          });
        type FingerprintFailureReason =
          "provider_missing" | "provider_failed" | "provider_malformed";
        const acquireFingerprint = async (): Promise<
          | { readonly value: IdentityFingerprintSet }
          | {
              readonly failed: true;
              readonly reason: FingerprintFailureReason;
            }
          | InvocationResult
        > => {
          if (cachedFingerprint?.identity === identity)
            return { value: cachedFingerprint.set } as const;
          if (!fingerprintProvider)
            return { failed: true, reason: "provider_missing" } as const;
          const acquired = await awaitProvider(() =>
            fingerprintProvider!.fingerprint(identity, operationControls()),
          );
          if ("ok" in acquired) return acquired;
          if ("failed" in acquired)
            return { failed: true, reason: "provider_failed" } as const;
          try {
            const value = ownData(acquired.value, [
              "generationId",
              "originatingFingerprint",
              "effectiveFingerprint",
              "requesterFingerprint",
              "tenantFingerprint",
            ]);
            if (
              Object.keys(value).length !== 5 ||
              !canonicalIdentityId(value.generationId) ||
              [
                value.originatingFingerprint,
                value.effectiveFingerprint,
                value.requesterFingerprint,
                value.tenantFingerprint,
              ].some((item) => {
                try {
                  decodeCanonicalBase64Url256(item);
                  return false;
                } catch {
                  return true;
                }
              })
            )
              throw new Error("fingerprint");
            const set = Object.freeze({
              generationId: value.generationId,
              originatingFingerprint: value.originatingFingerprint,
              effectiveFingerprint: value.effectiveFingerprint,
              requesterFingerprint: value.requesterFingerprint,
              tenantFingerprint: value.tenantFingerprint,
            }) as IdentityFingerprintSet;
            cachedFingerprint = { identity, set };
            return { value: set } as const;
          } catch {
            return { failed: true, reason: "provider_malformed" } as const;
          }
        };
        const recordFingerprintIncident = async (
          reason: FingerprintFailureReason,
        ): Promise<InvocationResult | undefined> => {
          observeCancellation();
          if (interrupted) return await interruption;
          if (deadlineMs <= Date.now()) {
            interrupt("CAP_DEADLINE_EXCEEDED");
            return await interruption;
          }
          if (!reportFingerprintFailure) return undefined;
          const reported = await awaitProvider(() =>
            reportFingerprintFailure!(
              Object.freeze({
                providerKind: "identity_fingerprint",
                operation: "fingerprint",
                reason,
              }),
              operationControls(),
            ),
          );
          if ("ok" in reported) return reported;
          return undefined;
        };
        const owner = (mandatory: boolean): string | undefined => {
          if (auditOwnerId) return auditOwnerId;
          try {
            auditOwnerId = randomBytes(32).toString("base64url");
            return auditOwnerId;
          } catch {
            if (mandatory) identityUnavailable = true;
            return undefined;
          }
        };
        const eventId = (
          ownerId: string,
          eventType:
            "service_identity_assumed" | "internal_invocation_rejected",
          transitionOrdinal: 1 | 2,
        ): string =>
          `cape1.${createHash("sha256")
            .update(
              jcs({
                service: serviceName,
                deployment: deployment!,
                ownerType: "internal_invocation",
                ownerId,
                eventType,
                transitionOrdinal,
              }),
            )
            .digest("base64url")}`;
        const buildAuditEvent = (
          ownerId: string,
          fingerprints: IdentityFingerprintSet,
          event:
            | {
                readonly eventType: "service_identity_assumed";
                readonly outcome: "allowed";
                readonly reason?: never;
                readonly stage: "service_identity_transition";
                readonly transitionOrdinal: 1;
              }
            | {
                readonly eventType: "internal_invocation_rejected";
                readonly outcome: "rejected" | "denied" | "unavailable";
                readonly reason: InternalInvocationAuditReason;
                readonly stage: InternalInvocationAuditStage;
                readonly transitionOrdinal: 1 | 2;
              },
        ): InternalInvocationAuditEvent =>
          Object.freeze({
            eventId: eventId(ownerId, event.eventType, event.transitionOrdinal),
            eventType: event.eventType,
            outcome: event.outcome,
            ...(event.reason === undefined ? {} : { reason: event.reason }),
            service: serviceName,
            ownerType: "internal_invocation",
            ownerId,
            transitionOrdinal: event.transitionOrdinal,
            stage: event.stage,
            ...(transition?.policyId === undefined
              ? {}
              : { policyId: transition.policyId }),
            caller: parent!.caller,
            target: currentNode,
            deployment: deployment!,
            trace: Object.freeze({
              traceId,
              spanId,
              parentSpanId: parent!.spanId,
            }),
            originatingFingerprint: fingerprints.originatingFingerprint,
            effectiveFingerprint: fingerprints.effectiveFingerprint,
            requesterFingerprint: fingerprints.requesterFingerprint,
            tenantFingerprint: fingerprints.tenantFingerprint,
            fingerprintGenerationId: fingerprints.generationId,
            sourceChain,
            correlationId,
          }) as InternalInvocationAuditEvent;
        const rejection = async (
          selected: InvocationResult,
          reason: InternalInvocationAuditReason,
          auditStage: InternalInvocationAuditStage,
          outcome: "rejected" | "denied" | "unavailable",
        ): Promise<InvocationResult> => {
          if (!parent) return selected;
          if (!journal || !fingerprintProvider || !deployment) {
            diagnostic("rejection_audit_unavailable");
            return selected;
          }
          const ownerId = owner(false);
          if (!ownerId) {
            diagnostic("rejection_audit_unavailable");
            return selected;
          }
          const fingerprint = await acquireFingerprint();
          if ("ok" in fingerprint) return fingerprint;
          if ("failed" in fingerprint) {
            diagnostic("rejection_audit_unavailable");
            return selected;
          }
          const event = buildAuditEvent(ownerId, fingerprint.value, {
            eventType: "internal_invocation_rejected",
            outcome,
            reason,
            stage: auditStage,
            transitionOrdinal: serviceAssumed ? 2 : 1,
          });
          const committed = await awaitProvider(() =>
            journal!.commit(event, operationControls()),
          );
          if ("ok" in committed) return committed;
          if ("failed" in committed || committed.value !== undefined)
            diagnostic("rejection_audit_unavailable");
          return selected;
        };
        if (parent?.ancestry.includes(node))
          return await rejection(
            failure("CAP_INTERNAL_INVOCATION_CYCLE", "failed_precondition"),
            "cycle_detected",
            "cycle_check",
            "rejected",
          );
        if (parent && parent.depth + 1 > (maxDepth as number))
          return await rejection(
            failure(
              "CAP_INTERNAL_INVOCATION_DEPTH_EXCEEDED",
              "resource_exhausted",
            ),
            "depth_exceeded",
            "depth_check",
            "rejected",
          );
        if (parent && transition && transition.mode !== "delegate") {
          const transitionRequest = transition;
          const transitionView = (): InternalInvocationTransitionView => {
            const view = operationView();
            return Object.freeze({
              caller: parent.caller,
              target: currentNode,
              mode: transitionRequest.mode as "derive" | "service",
              policyId: transitionRequest.policyId!,
              identity,
              tenant:
                identity.effective.tenant === undefined
                  ? Object.freeze({ present: false as const })
                  : Object.freeze({
                      present: true as const,
                      value: identity.effective.tenant,
                    }),
              service: serviceName,
              deployment: deployment!,
              sourceChain: Object.freeze([...sourceChain]),
              correlationId,
              trace: Object.freeze({
                traceId,
                spanId,
                parentSpanId: parent.spanId,
              }),
              deadlineMs,
              signal: view.signal,
            });
          };
          if (transitionRequest.mode === "derive") {
            const policy = derivePolicies.get(transitionRequest.policyId!);
            if (!policy || !deployment)
              return await rejection(
                denial("CAP_PERMISSION_DENIED", "permission_denied"),
                "derive_policy_absent",
                "derive_policy",
                "denied",
              );
            const decided = await awaitProvider(() =>
              policy.derive(transitionView()),
            );
            if ("ok" in decided) return decided;
            if ("failed" in decided)
              return await rejection(
                denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true),
                "derive_provider_failed",
                "derive_policy",
                "unavailable",
              );
            let decision: Record<string, unknown>;
            try {
              decision = ownData(decided.value, ["allowed", "principal"]);
            } catch {
              decision = Object.create(null) as Record<string, unknown>;
            }
            if (
              decision.allowed === false &&
              Object.keys(decision).length === 1
            )
              return await rejection(
                denial("CAP_PERMISSION_DENIED", "permission_denied"),
                "derive_policy_denied",
                "derive_policy",
                "denied",
              );
            if (
              decision.allowed !== true ||
              Object.keys(decision).length !== 2 ||
              !Object.hasOwn(decision, "principal")
            )
              return await rejection(
                denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true),
                "derive_provider_failed",
                "derive_policy",
                "unavailable",
              );
            let derived;
            try {
              derived = normalizePrincipal(
                decision.principal,
                policy.providerId,
              );
            } catch {
              return await rejection(
                denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true),
                "derive_provider_failed",
                "derive_identity",
                "unavailable",
              );
            }
            if (derived.tenant !== identity.effective.tenant)
              return await rejection(
                denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true),
                "tenant_transition_forbidden",
                "derive_identity",
                "unavailable",
              );
            identity = Object.freeze({
              ...identity,
              effective: derived,
              authorityChain: Object.freeze([
                ...identity.authorityChain,
                derived,
              ]),
            });
          } else {
            const policy = servicePolicies.get(transitionRequest.policyId!);
            if (!policy || !deployment)
              return await rejection(
                denial("CAP_PERMISSION_DENIED", "permission_denied"),
                "service_policy_absent",
                "service_policy",
                "denied",
              );
            const decided = await awaitProvider(() =>
              policy.evaluate(transitionView()),
            );
            if ("ok" in decided) return decided;
            if ("failed" in decided || typeof decided.value !== "boolean")
              return await rejection(
                denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true),
                "service_policy_failed",
                "service_policy",
                "unavailable",
              );
            if (!decided.value)
              return await rejection(
                denial("CAP_PERMISSION_DENIED", "permission_denied"),
                "service_policy_denied",
                "service_policy",
                "denied",
              );
            if (!serviceIdentity)
              return await rejection(
                denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true),
                "service_identity_unavailable",
                "service_identity",
                "unavailable",
              );
            const resolved = await awaitProvider(() =>
              serviceIdentity!.resolve(transitionView()),
            );
            if ("ok" in resolved) return resolved;
            let servicePrincipal;
            try {
              if ("failed" in resolved) throw new Error("provider");
              const supplied = normalizePrincipal(
                resolved.value,
                serviceIdentity.id,
              );
              if (supplied.tenant !== undefined) throw new Error("tenant");
              servicePrincipal = Object.freeze({
                ...supplied,
                ...(identity.effective.tenant === undefined
                  ? {}
                  : { tenant: identity.effective.tenant }),
              });
            } catch {
              return await rejection(
                denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true),
                "service_identity_unavailable",
                "service_identity",
                "unavailable",
              );
            }
            identity = Object.freeze({
              ...identity,
              effective: servicePrincipal,
              authorityChain: Object.freeze([servicePrincipal]),
            });
            const ownerId = owner(true);
            if (!ownerId)
              return await rejection(
                denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true),
                "service_audit_unavailable",
                "service_audit_identity",
                "unavailable",
              );
            const fingerprint = await acquireFingerprint();
            if ("ok" in fingerprint) return fingerprint;
            if ("failed" in fingerprint)
              return await rejection(
                denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true),
                "service_audit_unavailable",
                "service_audit_fingerprint",
                "unavailable",
              );
            if (!journal)
              return denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true);
            const event = buildAuditEvent(ownerId, fingerprint.value, {
              eventType: "service_identity_assumed",
              outcome: "allowed",
              stage: "service_identity_transition",
              transitionOrdinal: 1,
            });
            const committed = await awaitProvider(() =>
              journal!.commit(event, operationControls()),
            );
            if ("ok" in committed) return committed;
            if ("failed" in committed || committed.value !== undefined)
              return await rejection(
                denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true),
                "service_audit_unavailable",
                "service_audit_commit",
                "unavailable",
              );
            serviceAssumed = true;
          }
        }
        stage(
          "authenticate",
          !parent &&
            !ingress &&
            root.principal === undefined &&
            capability.access.authentication === "public",
        );
        if (!parent && root.principal !== undefined) {
          const held =
            typeof root.principal === "object" &&
            root.principal !== null &&
            !types.isProxy(root.principal)
              ? tokens.get(root.principal)
              : undefined;
          if (
            !held ||
            !ingress ||
            held.adapter !== ingress.adapter ||
            held.capability !== capability.id ||
            ingress.hasCredentials
          )
            return denial("CAP_UNAUTHENTICATED", "unauthenticated");
          identity = held.identity;
        } else if (ingress?.hasCredentials) {
          const authenticate = providers.get(
            ingress.adapter.providerId,
          )!.authenticate;
          const outcome = await awaitProvider(() =>
            authenticate(ingress.credentials, operationView()),
          );
          if ("ok" in outcome) return outcome;
          if ("failed" in outcome) {
            diagnostic("authentication_provider_failed");
            return denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true);
          }
          if (outcome.value === null)
            return denial("CAP_UNAUTHENTICATED", "unauthenticated");
          try {
            identity = rootIdentity(
              normalizePrincipal(outcome.value, ingress.adapter.providerId),
            );
          } catch {
            diagnostic("authentication_provider_failed");
            return denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true);
          }
        }
        if (
          (capability.access.authentication === "required" ||
            exposure === "authenticated") &&
          identity.effective.type === "anonymous"
        )
          return denial("CAP_UNAUTHENTICATED", "unauthenticated");
        stage(
          "authorize",
          capability.access.permissions.public === true &&
            exposure === "public" &&
            !authorizationProvider,
        );
        if (
          exposure === "private" &&
          !(parent?.privateBoundary ?? ingress?.adapter.privateBoundary)
        )
          return parent
            ? await rejection(
                denial("CAP_PERMISSION_DENIED", "permission_denied"),
                "authority_chain_denied",
                "authorization",
                "denied",
              )
            : denial("CAP_PERMISSION_DENIED", "permission_denied");
        const authorization = await authorizePrincipals(
          identity.authorityChain,
          capability.access.permissions,
          authorizationProvider
            ? (principal) =>
                awaitProvider(() =>
                  authorizationProvider(operationView(), principal),
                )
            : undefined,
        );
        if ("ok" in authorization) return authorization;
        if (authorization.kind === "failed") {
          diagnostic("authorization_provider_failed");
          const selected = denial(
            "CAP_DEPENDENCY_UNAVAILABLE",
            "unavailable",
            true,
          );
          return parent
            ? await rejection(
                selected,
                "authorization_provider_failed",
                "authorization",
                "unavailable",
              )
            : selected;
        }
        if (authorization.kind === "deny")
          return parent
            ? await rejection(
                denial("CAP_PERMISSION_DENIED", "permission_denied"),
                "authority_chain_denied",
                "authorization",
                "denied",
              )
            : denial("CAP_PERMISSION_DENIED", "permission_denied");
        if (interrupted) return await interruption;
        let kernelInvocationId: string | undefined;
        if (confirmationProvider) {
          const allocated = await awaitProvider(() =>
            confirmationProvider.allocateKernelInvocationId({
              signal: operationView().signal,
              refreshCancellation: observeCancellation,
              deadlineMs,
              correlationId,
            }),
          );
          if ("ok" in allocated) return allocated;
          if ("failed" in allocated)
            return denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true);
          const result = confirmationResponse<
            Awaited<
              ReturnType<typeof confirmationProvider.allocateKernelInvocationId>
            >
          >(allocated.value, "allocation");
          if (!result.ok)
            return denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true);
          kernelInvocationId = result.kernelInvocationId;
        }
        const rate = capability.limits.rateLimit as
          { policy: string; cost?: number } | undefined;
        stage("admission", !rate);
        if (rate) {
          const checked = await awaitProvider(() =>
            rateCheck!(
              Object.freeze({
                ...operationView(),
                policy: rate.policy,
                cost: rate.cost ?? 1,
              }),
            ),
          );
          if ("ok" in checked) return checked;
          if ("failed" in checked) {
            if (!(
              failOpen.has(capability.id) &&
              (parent?.privateBoundary ?? ingress?.adapter.privateBoundary) ===
                true
            ))
              return denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true);
            diagnostic("rate_limit_provider_failed_open");
          } else {
            try {
              const decision = ownData(checked.value, [
                "allowed",
                "retryAfterMs",
                "limit",
                "remaining",
                "resetAt",
              ]);
              if (
                decision.allowed === true &&
                Object.keys(decision).length === 1
              ) {
                /* admitted */
              } else if (decision.allowed === false) {
                if (
                  !Number.isSafeInteger(decision.retryAfterMs) ||
                  (decision.retryAfterMs as number) < 0
                )
                  throw new Error("retry");
                for (const key of ["limit", "remaining"])
                  if (
                    decision[key] !== undefined &&
                    (!Number.isSafeInteger(decision[key]) ||
                      (decision[key] as number) < 0)
                  )
                    throw new Error("metadata");
                if (
                  decision.remaining !== undefined &&
                  decision.limit !== undefined &&
                  (decision.remaining as number) > (decision.limit as number)
                )
                  throw new Error("metadata");
                if (
                  decision.resetAt !== undefined &&
                  (typeof decision.resetAt !== "string" ||
                    decision.resetAt.length > 32 ||
                    !Number.isFinite(Date.parse(decision.resetAt)) ||
                    new Date(decision.resetAt).toISOString() !==
                      decision.resetAt)
                )
                  throw new Error("reset");
                return failure(
                  "CAP_RATE_LIMITED",
                  "resource_exhausted",
                  copyJson({
                    retryAfterMs: decision.retryAfterMs,
                    ...(decision.limit === undefined
                      ? {}
                      : { limit: decision.limit }),
                    ...(decision.remaining === undefined
                      ? {}
                      : { remaining: decision.remaining }),
                    ...(decision.resetAt === undefined
                      ? {}
                      : { resetAt: decision.resetAt }),
                  }),
                  "Rate limit exceeded.",
                  true,
                );
              } else throw new Error("decision");
            } catch {
              return denial("CAP_DEPENDENCY_UNAVAILABLE", "unavailable", true);
            }
          }
        }
        stage("parse");
        let input = root.input;
        if (adapterCandidate !== undefined) {
          if (
            !adapterCandidate.ok &&
            adapterCandidate.code === "CAP_INTERNAL"
          ) {
            diagnostic("CAP_INTERNAL");
            return failure("CAP_INTERNAL", "internal", {
              executionState: "not_started",
            });
          }
          if (!adapterCandidate.ok) {
            const safeDetails =
              adapterCandidate.safeDetails === undefined ||
              adapterCandidate.code === "CAP_INPUT_INVALID" ||
              adapterCandidate.code === "CAP_MCP_CLIENT_METADATA_REQUIRED"
                ? adapterCandidate.safeDetails
                : redactSecrets(
                    bearerGuard.redactValue(adapterCandidate.safeDetails),
                  );
            return failure(
              adapterCandidate.code,
              adapterCandidate.status,
              safeDetails,
              adapterCandidate.code === "CAP_INPUT_INVALID"
                ? "Invocation input is invalid."
                : adapterCandidate.code === "CAP_MCP_CLIENT_METADATA_REQUIRED"
                  ? "Required client metadata is unavailable."
                  : cliAdapterRejections[adapterCandidate.code].message,
            );
          }
          if (Object.hasOwn(root, "input"))
            return failure("CAP_INTERNAL_INVOCATION_INVALID", "internal");
          input = adapterCandidate.input;
        }
        stage("input_validation");
        let canonical: ReturnType<typeof canonicalizeInput>;
        try {
          canonical = canonicalizeInput(
            registry.document,
            capability,
            copyJson(input),
          );
        } catch {
          return invalidInput();
        }
        if (
          !canonical.valid ||
          !validators.input.validate(canonical.value).accepted
        )
          return invalidInput();
        try {
          captureRedactionPaths(
            canonical.value!,
            redactionPaths.get(capability.id) ?? [],
            redactionState,
          );
        } catch {
          redactionState.failed = true;
          return failure(
            "CAP_DEPENDENCY_UNAVAILABLE",
            "unavailable",
            undefined,
            "Required runtime provider is unavailable.",
            false,
          );
        }
        stage("quota_preconditions", true);
        const keyed = capability.effects.idempotency === "key";
        stage(
          "idempotency_inspect",
          !keyed && !Object.hasOwn(root, "idempotencyKey"),
        );
        if (!keyed && Object.hasOwn(root, "idempotencyKey"))
          return failure("CAP_INPUT_INVALID", "invalid_argument", {
            path: "/idempotencyKey",
            code: "unsupported_control",
          });
        if (
          !keyed &&
          !["none", "intrinsic"].includes(capability.effects.idempotency)
        )
          return failure("CAP_DEPENDENCY_UNAVAILABLE", "unavailable");
        let idempotencyAction: IdempotencyAction | undefined;
        const providerFailure = (result: {
          error: {
            code: string;
            status: ErrorStatus;
            message: string;
            retryable: boolean;
          };
        }): InvocationResult => {
          if (result.error.code === "CAP_DEPENDENCY_UNAVAILABLE")
            diagnostic("CAP_DEPENDENCY_UNAVAILABLE");
          return failure(
            result.error.code,
            result.error.status,
            undefined,
            result.error.message,
            result.error.retryable,
          );
        };
        const replay = async (
          result: Extract<IdempotencyInspection, { outcome: "replay" }>,
        ): Promise<InvocationResult> => {
          const terminal = result.terminal;
          if (capability.effects.confirmation === "required") {
            if (!result.confirmation || !confirmationProvider)
              return failure(
                "CAP_DEPENDENCY_UNAVAILABLE",
                "unavailable",
                undefined,
                "Required runtime provider is unavailable.",
                false,
              );
            const queried = await awaitProvider(() =>
              confirmationProvider.queryExecutionCompletion(
                result.confirmation!,
                terminal.kind === "success" ? "succeeded" : "failed",
              ),
            );
            if ("ok" in queried) return queried;
            const proof = confirmationResponse<
              ConfirmationResult<{ completed: boolean }>
            >("failed" in queried ? undefined : queried.value, "query");
            if (!proof.ok) return providerFailure(proof);
            if (!proof.completed)
              return failure(
                "CAP_IDEMPOTENCY_IN_PROGRESS",
                "failed_precondition",
              );
          }
          stage("output_validation");
          try {
            if (terminal.kind === "success") {
              const storedValue = terminal.value;
              const value = redactSecrets(storedValue);
              if (
                !equalJson(storedValue, value) ||
                !validateSchemaValue(
                  registry.document,
                  capability.output,
                  value,
                ).valid ||
                !validators.output.validate(value).accepted
              ) {
                diagnostic("CAP_INVALID_HANDLER_OUTPUT");
                return failure("CAP_INVALID_HANDLER_OUTPUT", "internal");
              }
              stage("finalize", true);
              return { ok: true, value, correlationId };
            }
            const error = terminal.error;
            if (terminal.kind === "unexpected_error") {
              if (
                !["CAP_INTERNAL", "CAP_INVALID_HANDLER_OUTPUT"].includes(
                  error.code,
                ) ||
                error.status !== "internal" ||
                error.message !== "Invocation failed." ||
                error.retryable !== false ||
                error.details !== undefined
              )
                throw new Error("terminal");
              stage("finalize", true);
              return failure(error.code, "internal");
            }
            const declaration = Object.hasOwn(capability.errors, error.code)
              ? capability.errors[error.code]
              : undefined;
            if (
              !declaration ||
              error.status !== declaration.status ||
              error.message !== declaration.message ||
              error.retryable !== declaration.retryable
            )
              throw new Error("declaration");
            if (
              hasSensitiveString(error.code) ||
              hasSensitiveString(error.message)
            )
              return failure("CAP_INTERNAL", "internal");
            let details: JsonValue | undefined;
            if (declaration.details) {
              details = redactJson(error.details, createRedactionState());
              const storedDetails = details;
              if (
                !validateSchemaValue(
                  registry.document,
                  declaration.details,
                  details,
                ).valid ||
                !validators.errors.get(error.code)?.validate(details).accepted
              )
                throw new Error("details");
              details = redactSecrets(bearerGuard.redactValue(details));
              if (
                !equalJson(storedDetails, details) ||
                !validateSchemaValue(
                  registry.document,
                  declaration.details,
                  details,
                ).valid ||
                !validators.errors.get(error.code)?.validate(details).accepted
              )
                throw new Error("details");
            } else if (error.details !== undefined) throw new Error("details");
            const safeMessage = bearerGuard.redactString(declaration.message);
            if (safeMessage !== error.message)
              throw new Error("replay_privacy");
            stage("finalize", true);
            return failure(
              error.code,
              declaration.status,
              details,
              safeMessage,
              declaration.retryable,
            );
          } catch {
            const code =
              terminal.kind === "success"
                ? "CAP_INVALID_HANDLER_OUTPUT"
                : "CAP_INTERNAL";
            diagnostic(code);
            return failure(code, "internal");
          }
        };
        if (keyed) {
          if (
            typeof root.idempotencyKey !== "string" ||
            !root.idempotencyKey ||
            /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(
              root.idempotencyKey,
            )
          )
            return failure("CAP_IDEMPOTENCY_KEY_REQUIRED", "invalid_argument");
          if (!idempotencyProvider)
            return failure(
              "CAP_DEPENDENCY_UNAVAILABLE",
              "unavailable",
              undefined,
              "Required runtime provider is unavailable.",
              true,
            );
          idempotencyAction = Object.freeze({
            capabilityId: capability.id,
            version: capability.version,
            irHash: (carrier.registry as RuntimeKernelOptions["registry"])
              .irHash,
            impact: capability.effects.impact,
            confirmation: capability.effects.confirmation,
            identity: Object.freeze({
              originating: identity.originating,
              effective: identity.effective,
              authorityChain: identity.authorityChain,
            }),
            input: canonical.value!,
            key: root.idempotencyKey,
          });
          const inspected = await awaitProvider(() =>
            idempotencyProvider.inspect(idempotencyAction!, {
              signal: operationView().signal,
              deadlineMs,
              refreshCancellation: observeCancellation,
            }),
          );
          if ("ok" in inspected) return inspected;
          const result = idempotencyResponse<IdempotencyInspection>(
            "failed" in inspected ? undefined : inspected.value,
            "inspect",
          );
          if (!result.ok) return providerFailure(result);
          if (result.outcome === "replay") return await replay(result);
        }
        const confirmationPolicy = capability.effects.confirmation;
        stage(
          "confirmation",
          confirmationPolicy === "none" &&
            !Object.hasOwn(root, "confirmationToken"),
        );
        if (
          unhealthyConfirmationPolicies.has(capability.id) ||
          (confirmationPolicy !== "none" && confirmationPolicy !== "required")
        ) {
          unhealthyConfirmationPolicies.add(capability.id);
          diagnostic("CAP_CONFIRMATION_POLICY_INVALID");
          return failure(
            "CAP_CONFIRMATION_POLICY_INVALID",
            "internal",
            undefined,
            "Confirmation policy is invalid or unsupported.",
          );
        }
        if (
          confirmationPolicy === "none" &&
          Object.hasOwn(root, "confirmationToken")
        )
          return failure("CAP_CONFIRMATION_INVALID", "failed_precondition");
        let confirmationReceipt: ConfirmationReceipt | undefined;
        if (confirmationPolicy === "required") {
          if (
            identity.effective.type === "anonymous" ||
            identity.originating.type === "anonymous"
          )
            return denial("CAP_UNAUTHENTICATED", "unauthenticated");
          if (!confirmationProvider)
            return failure(
              "CAP_DEPENDENCY_UNAVAILABLE",
              "unavailable",
              undefined,
              "Required runtime provider is unavailable.",
              true,
            );
          const confirmationFingerprint = await acquireFingerprint();
          if ("ok" in confirmationFingerprint) return confirmationFingerprint;
          if ("failed" in confirmationFingerprint) {
            diagnostic("confirmation_fingerprint");
            const incident = await recordFingerprintIncident(
              confirmationFingerprint.reason,
            );
            if (incident) return incident;
            return failure(
              "CAP_DEPENDENCY_UNAVAILABLE",
              "unavailable",
              undefined,
              "Required runtime provider is unavailable.",
              true,
            );
          }
          const action: ConfirmationAction = {
            irHash: (carrier.registry as RuntimeKernelOptions["registry"])
              .irHash,
            capabilityId: capability.id,
            version: capability.version,
            impact: capability.effects.impact,
            summary: capability.summary,
            requesterFingerprint:
              confirmationFingerprint.value.requesterFingerprint,
            tenantFingerprint: confirmationFingerprint.value.tenantFingerprint,
            fingerprintGenerationId: confirmationFingerprint.value.generationId,
            kernelInvocationId: kernelInvocationId!,
            input: canonical.value!,
            ...(keyed ? { idempotencyKey: root.idempotencyKey as string } : {}),
            correlationId,
            sourceChain: copyJson(sourceChain),
          };
          if (!Object.hasOwn(root, "confirmationToken")) {
            const issued = await awaitProvider(() =>
              confirmationProvider.issue(action, {
                signal: operationView().signal,
                refreshCancellation: observeCancellation,
                deadlineMs,
                kernelInvocationId: kernelInvocationId!,
                correlationId,
              }),
            );
            if ("ok" in issued) return issued;
            if ("failed" in issued)
              return failure(
                "CAP_DEPENDENCY_UNAVAILABLE",
                "unavailable",
                undefined,
                "Required runtime provider is unavailable.",
                true,
              );
            const result = confirmationResponse<
              Awaited<ReturnType<typeof confirmationProvider.issue>>
            >(issued.value, "issue", action);
            if (!result.ok)
              return failure(
                result.error.code,
                result.error.status,
                undefined,
                result.error.message,
                result.error.retryable,
              );
            return failure(
              "CAP_CONFIRMATION_REQUIRED",
              "failed_precondition",
              copyJson(result.challenge),
              "Approval is required before this action can run.",
            );
          }
          stage("approval_consume");
          const consumed = await awaitProvider(() =>
            confirmationProvider.consume(action, root.confirmationToken, {
              signal: operationView().signal,
              refreshCancellation: observeCancellation,
              deadlineMs,
              kernelInvocationId: kernelInvocationId!,
              correlationId,
            }),
          );
          if ("ok" in consumed) return consumed;
          if ("failed" in consumed)
            return failure(
              "CAP_DEPENDENCY_UNAVAILABLE",
              "unavailable",
              undefined,
              "Required runtime provider is unavailable.",
              true,
            );
          const result = confirmationResponse<
            Awaited<ReturnType<typeof confirmationProvider.consume>>
          >(consumed.value, "consume");
          if (!result.ok)
            return failure(
              result.error.code,
              result.error.status,
              undefined,
              result.error.message,
              result.error.retryable,
            );
          confirmationReceipt = result.receipt;
        } else stage("approval_consume", true);
        stage("idempotency_claim", !keyed);
        if (keyed) {
          // Observe a late accepted claim even when the interruption race wins.
          // This kernel proves no handler can enter using that unreturned claim.
          const pendingClaim = providerValue(() =>
            idempotencyProvider!.claim(idempotencyAction!, {
              signal: operationView().signal,
              deadlineMs,
              refreshCancellation: observeCancellation,
            }),
          ).then((outcome) => {
            const result = idempotencyResponse<
              | { outcome: "claimed"; claim: IdempotencyClaim }
              | Exclude<IdempotencyInspection, { outcome: "absent" }>
            >("failed" in outcome ? undefined : outcome.value, "claim");
            if (result.ok && result.outcome === "claimed") {
              idempotencyClaim = result.claim;
              if (interrupted)
                void providerValue(() =>
                  idempotencyProvider!.release(result.claim),
                );
            }
            return result;
          });
          const claimed = await Promise.race([pendingClaim, interruption]);
          observeCancellation();
          if (interrupted || deadlineMs <= Date.now()) {
            if (!interrupted) interrupt("CAP_DEADLINE_EXCEEDED");
            return await interruption;
          }
          if (!claimed.ok) return providerFailure(claimed);
          if (!("outcome" in claimed)) return claimed;
          if (claimed.outcome === "replay") return await replay(claimed);
        }
        stage("resources", capability.requirements.secrets.length === 0);
        const secrets = new Map<string, string>();
        for (const declaration of capability.requirements.secrets as readonly {
          name: string;
          optional: boolean;
        }[]) {
          const resolved = await awaitProvider(() =>
            secretResolve
              ? secretResolve(declaration.name, operationView())
              : undefined,
          );
          if ("ok" in resolved) return resolved;
          if (
            "failed" in resolved ||
            (resolved.value === undefined
              ? !declaration.optional
              : typeof resolved.value !== "string" ||
                resolved.value.length === 0 ||
                resolved.value.length > 16384)
          )
            return failure(
              "CAP_DEPENDENCY_UNAVAILABLE",
              "unavailable",
              undefined,
              "Required runtime provider is unavailable.",
              true,
            );
          if (typeof resolved.value === "string") {
            secrets.set(declaration.name, resolved.value);
            try {
              addSensitiveString(redactionState, resolved.value);
            } catch {
              return failure("CAP_DEPENDENCY_UNAVAILABLE", "unavailable");
            }
          }
        }
        stage(
          "audit_start",
          confirmationPolicy !== "required" ||
            (capability.effects.impact !== "destructive" && !keyed),
        );
        if (
          confirmationPolicy === "required" &&
          (capability.effects.impact === "destructive" || keyed)
        ) {
          const begun = await awaitProvider(() =>
            confirmationProvider!.beginExecution(confirmationReceipt!, {
              signal: operationView().signal,
              refreshCancellation: observeCancellation,
              deadlineMs,
              kernelInvocationId: kernelInvocationId!,
              correlationId,
            }),
          );
          if ("ok" in begun) return begun;
          if ("failed" in begun)
            return failure(
              "CAP_DEPENDENCY_UNAVAILABLE",
              "unavailable",
              undefined,
              "Required runtime provider is unavailable.",
              true,
            );
          const result = confirmationResponse<
            Awaited<
              ReturnType<
                NonNullable<typeof confirmationProvider>["beginExecution"]
              >
            >
          >(begun.value, "begin", confirmationReceipt);
          if (!result.ok)
            return failure(
              result.error.code,
              result.error.status,
              undefined,
              result.error.message,
              result.error.retryable,
            );
          confirmationAttempt = result.attempt;
        }
        if (idempotencyClaim) {
          const entry = await awaitProvider(() =>
            idempotencyProvider!.enter(
              idempotencyClaim!,
              confirmationAttempt
                ? {
                    recordId: confirmationAttempt.recordId,
                    confirmationRef: confirmationAttempt.confirmationRef,
                    executionAttemptId: confirmationAttempt.executionAttemptId,
                  }
                : undefined,
              {
                signal: operationView().signal,
                deadlineMs,
                refreshCancellation: observeCancellation,
              },
            ),
          );
          if ("ok" in entry) return entry;
          const result = idempotencyResponse<Record<never, never>>(
            "failed" in entry ? undefined : entry.value,
            "complete",
          );
          if (!result.ok) return providerFailure(result);
          idempotencyEntered = true;
        }
        observeCancellation();

        if (interrupted || deadlineMs <= Date.now()) {
          if (!interrupted) interrupt("CAP_DEADLINE_EXCEEDED");
          return await interruption;
        }
        const declaredErrors = new WeakMap<
          object,
          { code: string; details?: unknown }
        >();
        const invokeChild = (
          target: string,
          input: unknown,
          childOptions?: unknown,
          boundVersion?: string,
        ): Promise<InvocationResult> => {
          let child: Record<string, unknown>;
          try {
            child =
              childOptions === undefined
                ? (Object.create(null) as Record<string, unknown>)
                : ownData(childOptions, [
                    "version",
                    "mode",
                    "deadline",
                    "signal",
                    "idempotencyKey",
                    "confirmationToken",
                    "policyId",
                  ]);
            if (
              typeof target !== "string" ||
              (child.mode !== undefined &&
                !["delegate", "derive", "service"].includes(
                  child.mode as string,
                )) ||
              ((child.mode === "derive" || child.mode === "service") &&
                !canonicalIdentityId(child.policyId)) ||
              (child.mode !== "derive" &&
                child.mode !== "service" &&
                Object.hasOwn(child, "policyId"))
            )
              throw new Error("options");
          } catch {
            return invoke(
              { capability: "", source: "internal" },
              undefined,
              undefined,
              true,
            );
          }
          if (boundVersion !== undefined && child.version === undefined)
            child.version = boundVersion;
          const childTransition = Object.freeze({
            mode: (child.mode ?? "delegate") as
              "delegate" | "derive" | "service",
            ...(typeof child.policyId === "string"
              ? { policyId: child.policyId }
              : {}),
          });
          delete child.mode;
          delete child.policyId;
          return invoke(
            {
              capability: target,
              input,
              source: "internal",
              ...child,
            } as InvocationRequest,
            undefined,
            {
              observeCancellation,
              redactionState,
              privateBoundary:
                parent?.privateBoundary ??
                ingress?.adapter.privateBoundary ??
                false,
              identity,
              sourceChain,
              ancestry: Object.freeze([...(parent?.ancestry ?? []), node]),
              deadlineMs,
              signal: controller.signal,
              traceId,
              spanId,
              depth: (parent?.depth ?? -1) + 1,
              caller: currentNode,
            },
            false,
            childTransition,
          );
        };
        const facade = Object.create(null) as Record<string, unknown>;
        for (const selected of [...registry.entries.values()]
          .filter(
            ({ capability: item }) =>
              item.access.exposure.internal !== "disabled",
          )
          .sort((left, right) =>
            left.capability.id < right.capability.id
              ? -1
              : left.capability.id > right.capability.id
                ? 1
                : left.capability.version < right.capability.version
                  ? -1
                  : left.capability.version > right.capability.version
                    ? 1
                    : 0,
          )) {
          const segments = selected.capability.id.split(".");
          let namespace = facade;
          for (const [index, segment] of segments.entries()) {
            if (index === segments.length - 1) {
              const target = selected.capability.id;
              const exactVersion = selected.capability.version;
              Object.defineProperty(namespace, segment, {
                value: Object.freeze((input: unknown, options?: unknown) =>
                  invokeChild(target, input, options, exactVersion),
                ),
                enumerable: true,
                configurable: false,
                writable: false,
              });
            } else {
              if (!Object.hasOwn(namespace, segment))
                Object.defineProperty(namespace, segment, {
                  value: Object.create(null),
                  enumerable: true,
                  configurable: false,
                  writable: false,
                });
              namespace = namespace[segment] as Record<string, unknown>;
            }
          }
        }
        const freezeFacade = (value: Record<string, unknown>): void => {
          for (const child of Object.values(value))
            if (typeof child === "object" && child !== null)
              freezeFacade(child as Record<string, unknown>);
          Object.freeze(value);
        };
        freezeFacade(facade);
        const context = Object.freeze({
          services,
          secrets: Object.freeze({
            get: (name: string): string | undefined =>
              typeof name === "string" ? secrets.get(name) : undefined,
          }),
          trace: Object.freeze({
            traceId,
            spanId,
            ...(parent ? { parentSpanId: parent.spanId } : {}),
          }),
          logger: Object.freeze(
            Object.fromEntries(
              (["info", "warn", "error"] as const).map((level) => [
                level,
                (code: string): void => {
                  const safeCode =
                    typeof code === "string" &&
                    [
                      "CAP_HANDLER_DIAGNOSTIC",
                      "CAP_HANDLER_WARNING",
                      "CAP_HANDLER_ERROR",
                    ].includes(code) &&
                    !hasSensitiveString(code)
                      ? code
                      : "CAP_HANDLER_DIAGNOSTIC";
                  notify(onLog, {
                    level,
                    code: safeCode,
                    capability: capability.id,
                    version: capability.version,
                    source,
                    correlationId,
                    traceId,
                    spanId,
                  });
                },
              ]),
            ),
          ),
          identity,
          invoke: invokeChild,
          capabilities: facade,
          signal: operationView().signal,
          deadline: Object.freeze(new Date(deadlineMs)),
          correlationId,
          error: (code: string, details?: unknown): Error => {
            const error = new Error("Capability error.");
            // Undeclared names are remembered, then safely mapped to CAP_INTERNAL.
            declaredErrors.set(error, {
              code,
              ...(details === undefined ? {} : { details }),
            });
            Object.defineProperties(error, {
              code: { value: code, enumerable: true },
              details: { value: details },
            });
            return Object.freeze(error);
          },
        });
        const declared = (
          value: unknown,
          observe = true,
        ): InvocationResult | undefined => {
          const raised =
            typeof value === "object" && value !== null
              ? declaredErrors.get(value)
              : undefined;
          if (!raised) return undefined;
          const declaration = Object.hasOwn(capability.errors, raised.code)
            ? capability.errors[raised.code]
            : undefined;
          if (!declaration) return failure("CAP_INTERNAL", "internal");
          let details: JsonValue | undefined;
          if (declaration.details) {
            try {
              details = redactJson(raised.details, createRedactionState());
              const checked = validateSchemaValue(
                registry.document,
                declaration.details,
                details,
              );
              if (
                !checked.valid ||
                !validators.errors.get(raised.code)?.validate(details).accepted
              )
                return failure("CAP_INTERNAL", "internal");
              details = redactSecrets(bearerGuard.redactValue(details));
              const sanitized = validateSchemaValue(
                registry.document,
                declaration.details,
                details,
              );
              if (
                !sanitized.valid ||
                !validators.errors.get(raised.code)?.validate(details).accepted
              )
                return failure("CAP_INTERNAL", "internal");
            } catch {
              if (observe && !interrupted) diagnostic("CAP_INTERNAL");
              return failure("CAP_INTERNAL", "internal");
            }
          } else if (raised.details !== undefined)
            return failure("CAP_INTERNAL", "internal");
          if (
            hasSensitiveString(raised.code) ||
            hasSensitiveString(declaration.message)
          )
            return failure("CAP_INTERNAL", "internal");
          return failure(
            raised.code,
            declaration.status,
            details,
            declaration.message,
            declaration.retryable,
          );
        };
        type HandlerOutcome =
          | { kind: "value"; value: unknown }
          | { kind: "exception"; exception: unknown };
        const validateOutcome = (
          outcome: HandlerOutcome,
          observe: boolean,
        ): InvocationResult => {
          const domainResult = declared(
            outcome.kind === "value" ? outcome.value : outcome.exception,
            observe,
          );
          if (domainResult) return domainResult;
          if (outcome.kind === "exception") {
            if (observe && !interrupted) diagnostic("CAP_INTERNAL");
            return failure("CAP_INTERNAL", "internal");
          }
          try {
            const value = redactSecrets(outcome.value);
            const checked = validateSchemaValue(
              registry.document,
              capability.output,
              value,
            );
            if (!checked.valid || !validators.output.validate(value).accepted) {
              if (observe && !interrupted)
                diagnostic("CAP_INVALID_HANDLER_OUTPUT");
              return failure("CAP_INVALID_HANDLER_OUTPUT", "internal");
            }
            return { ok: true, value, correlationId };
          } catch {
            if (observe && !interrupted)
              diagnostic("CAP_INVALID_HANDLER_OUTPUT");
            return failure("CAP_INVALID_HANDLER_OUTPUT", "internal");
          }
        };
        const persistTerminal = async (
          validated: InvocationResult,
        ): Promise<boolean> => {
          try {
            let persisted = true;
            if (idempotencyClaim) {
              const terminal: IdempotencyTerminal = validated.ok
                ? { kind: "success", value: validated.value }
                : {
                    kind: Object.hasOwn(capability.errors, validated.error.code)
                      ? "declared_error"
                      : "unexpected_error",
                    error: {
                      code: validated.error.code,
                      status: validated.error.status,
                      message: validated.error.message,
                      retryable: validated.error.retryable,
                      ...(validated.error.details === undefined
                        ? {}
                        : { details: validated.error.details }),
                    },
                  };
              const completion = await providerValue(() =>
                idempotencyProvider!.complete(idempotencyClaim!, terminal),
              );
              if (
                !idempotencyResponse<Record<never, never>>(
                  "failed" in completion ? undefined : completion.value,
                  "complete",
                ).ok
              )
                persisted = false;
            }
            if (confirmationAttempt) {
              const completion = await providerValue(() =>
                confirmationProvider!.completeExecution(
                  confirmationAttempt!,
                  validated.ok ? "succeeded" : "failed",
                ),
              );
              if (
                "failed" in completion ||
                !confirmationResponse<ConfirmationResult<Record<never, never>>>(
                  completion.value,
                  "complete",
                ).ok
              )
                persisted = false;
            }
            if (idempotencyClaim && persisted) {
              const reconciled = await providerValue(() =>
                idempotencyProvider!.reconcile(),
              );
              if (
                !idempotencyResponse<Record<never, never>>(
                  "failed" in reconciled ? undefined : reconciled.value,
                  "complete",
                ).ok
              )
                return false;
            }
            return persisted;
          } catch {
            return false;
          }
        };
        stage("handler");
        if (interrupted) return await interruption;
        const execution = Promise.resolve()
          .then(() => {
            observeCancellation();
            if (!interrupted && deadlineMs <= Date.now())
              interrupt("CAP_DEADLINE_EXCEEDED");
            if (interrupted) return interruption;
            started = true;
            return handler(canonical.value, context);
          })
          .then(
            (value) => ({ kind: "value" as const, value }),
            (exception: unknown) => ({ kind: "exception" as const, exception }),
          );
        // Confirmed effects retain a settlement observer after the caller returns.
        // Only durable terminal classification continues; the caller result and
        // ordinary completion telemetry remain owned by the interruption race.
        const settledExecution = execution.then((outcome) => {
          if ((!confirmationAttempt && !idempotencyClaim) || !started)
            return { outcome };
          observeCancellation();
          if (!interrupted && deadlineMs <= Date.now())
            interrupt("CAP_DEADLINE_EXCEEDED");
          if (!interrupted) stage("output_validation");
          let validated: InvocationResult;
          try {
            validated = validateOutcome(outcome, !interrupted);
          } catch {
            validated = failure("CAP_INTERNAL", "internal");
          }
          terminalCompletion = persistTerminal(validated);
          observeCancellation();
          if (!interrupted && deadlineMs <= Date.now())
            interrupt("CAP_DEADLINE_EXCEEDED");
          if (!interrupted) stage("finalize", true);
          return { outcome, validated };
        });
        const settled = await Promise.race([settledExecution, interruption]);
        if ("ok" in settled) return settled;
        if (interrupted || deadlineMs <= Date.now()) {
          if (!interrupted) interrupt("CAP_DEADLINE_EXCEEDED");
          return await interruption;
        }
        if (settled.validated) return settled.validated;
        stage("output_validation");
        if (interrupted) return await interruption;
        const validated = validateOutcome(settled.outcome, true);
        stage("finalize", true);
        if (interrupted) return await interruption;
        return validated;
      })();
    } catch {
      diagnostic("CAP_INTERNAL");
      result = failure("CAP_INTERNAL", "internal");
    } finally {
      // Terminal persistence has no invocation abort controls. Await it only
      // while the caller remains live; late settlement still commits once.
      if (terminalCompletion && !interrupted) {
        const completion = await Promise.race([
          terminalCompletion,
          interruption,
        ]);
        if (completion === false)
          result = failure(
            "CAP_DEPENDENCY_UNAVAILABLE",
            "unavailable",
            undefined,
            "Required runtime provider is unavailable.",
            false,
          );
      } else if (confirmationAttempt && !started && !interrupted) {
        const completion = await Promise.race([
          providerValue(() =>
            confirmationProvider!.completeExecution(
              confirmationAttempt!,
              "failed",
            ),
          ),
          interruption,
        ]);
        if (
          !("ok" in completion) &&
          ("failed" in completion ||
            !confirmationResponse<ConfirmationResult<Record<never, never>>>(
              completion.value,
              "complete",
            ).ok)
        )
          result = failure(
            "CAP_DEPENDENCY_UNAVAILABLE",
            "unavailable",
            undefined,
            "Required runtime provider is unavailable.",
            true,
          );
      }
      if (idempotencyClaim && !idempotencyEntered && !started) {
        // A rejected/late entry can still have committed its durable fence.
        // The provider releases only CLAIMED; an accepted entry remains blocked.
        const release = providerValue(() =>
          idempotencyProvider!.release(idempotencyClaim!),
        );
        if (!interrupted) await Promise.race([release, interruption]);
      }
      clearTimeout(timer);
      try {
        if (parentSignal && validSignal(parentSignal, establishedParentEvents))
          removeListener.call(parentSignal, "abort", cancel);
      } catch {
        /* Caller native state mutation is contained. */
      }
      if (ancestorSignal) removeListener.call(ancestorSignal, "abort", cancel);
    }
    stage("telemetry_audit", true);
    // Synchronous validators and terminal observers can exhaust the budget
    // before the event loop delivers an abort/deadline notification.
    if (!interrupted) observeCancellation();
    if (!interrupted && deadlineMs <= Date.now())
      interrupt("CAP_DEADLINE_EXCEEDED");
    if (interrupted) result = await interruption;
    notify(telemetry, {
      kind: "completion",
      code: result.ok ? "OK" : result.error.code,
      correlationId,
    } satisfies RuntimeTelemetryEvent);
    const metric = Object.freeze({
      capability: capability.id,
      version: capability.version,
      source,
      code: result.ok ? "OK" : result.error.code,
      durationMs: Math.max(0, Date.now() - startedAt),
    });
    notify(onMetric, metric);
    notify(onTrace, {
      ...metric,
      correlationId,
      traceId: parent?.traceId ?? correlationId,
      spanId: correlationId,
      ...(parent ? { parentSpanId: parent.spanId } : {}),
    });
    return result;
  };
  const createAdapterIngress = (adapterId: string): AdapterIngress => {
    if (identityUnavailable)
      throw new RuntimeConfigurationError("CAP_RUNTIME_IDENTITY_UNAVAILABLE");
    const adapter = adapters.get(adapterId);
    if (!adapter)
      throw new RuntimeConfigurationError("CAP_RUNTIME_ADAPTER_UNREGISTERED");
    const invokeIngress = (
      request: AdapterInvocationRequest,
    ): Promise<InvocationResult> => {
      let data: Record<string, unknown>;
      try {
        data = ownData(request, [
          ...requestKeys.filter((key) => key !== "source"),
          "credentials",
        ]);
      } catch {
        return invoke(
          { capability: "", source: adapter.source },
          undefined,
          undefined,
          true,
        );
      }
      const credentials = data.credentials;
      const hasCredentials = Object.hasOwn(data, "credentials");
      delete data.credentials;
      return invoke(
        { ...data, source: adapter.source } as unknown as InvocationRequest,
        { adapter, credentials, hasCredentials },
      );
    };
    const authenticateIdentity = async (
      capabilityId: string | undefined,
      credentials: unknown,
      authenticationOptions?: {
        readonly deadline?: Date;
        readonly signal?: AbortSignal;
      },
      disclosureHasCredentials = true,
    ): Promise<{
      readonly identity: IdentityContext;
      readonly refresh: () => void;
      readonly dispose: () => void;
    }> => {
      if (identityUnavailable)
        throw new RuntimeConfigurationError("CAP_RUNTIME_IDENTITY_UNAVAILABLE");
      const entry =
        capabilityId === undefined
          ? undefined
          : registry.entries.get(capabilityId);
      if (
        capabilityId !== undefined &&
        (!entry || !adapter.capabilities.includes(capabilityId))
      )
        throw new RuntimeConfigurationError("CAP_UNAUTHENTICATED");
      let controls: Record<string, unknown>;
      let deadlineMs = Date.now() + 30000;
      try {
        controls =
          authenticationOptions === undefined
            ? (Object.create(null) as Record<string, unknown>)
            : ownData(authenticationOptions, ["deadline", "signal"]);
        if (controls.signal !== undefined && !validSignal(controls.signal))
          throw new Error("signal");
        if (controls.deadline !== undefined) {
          if (
            typeof controls.deadline !== "object" ||
            controls.deadline === null ||
            types.isProxy(controls.deadline)
          )
            throw new Error("deadline");
          const requested = getDateTime.call(controls.deadline);
          if (!Number.isFinite(requested)) throw new Error("deadline");
          deadlineMs = Math.min(deadlineMs, requested);
        }
      } catch {
        throw new RuntimeConfigurationError("CAP_INTERNAL_INVOCATION_INVALID");
      }
      const signal = controls.signal as AbortSignal | undefined;
      const follower = new AbortController();
      const correlationId = allocateCorrelation();
      const view: OperationView | AdapterDisclosureAuthenticationView =
        Object.freeze({
          ...(entry
            ? {
                capability: Object.freeze({
                  id: entry.capability.id,
                  version: entry.capability.version,
                  access: entry.capability.access,
                }),
              }
            : {
                purpose: "disclosure" as const,
                adapter: Object.freeze({
                  id: adapter.id,
                  source: adapter.source,
                }),
              }),
          identity: rootIdentity(anonymousPrincipal),
          sourceChain: entry
            ? Object.freeze([
                Object.freeze({
                  source: adapter.source,
                  capability: entry.capability.id,
                  exactVersion: entry.capability.version,
                }),
              ])
            : Object.freeze([] as const),
          correlationId,
          traceId: correlationId,
          spanId: correlationId,
          deadlineMs,
          signal: follower.signal,
        }) as OperationView | AdapterDisclosureAuthenticationView;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let rejectInterrupt: ((value: "cancel" | "deadline") => void) | undefined;
      const cancel = (): void => {
        try {
          follower.abort();
        } catch {
          /* Isolated native signal mutation is contained. */
        }
        rejectInterrupt?.("cancel");
      };
      let establishedEvents: ReadonlyMap<PropertyKey, object> | undefined;
      const dispose = (): void => {
        clearTimeout(timer);
        try {
          if (signal && validSignal(signal, establishedEvents))
            removeListener.call(signal, "abort", cancel);
        } catch {
          /* Malformed caller event state is contained. */
        }
      };
      const refresh = (): void => {
        if (
          signal &&
          (!validSignal(signal, establishedEvents) ||
            abortedGetter?.call(signal))
        ) {
          cancel();
          throw new RuntimeConfigurationError("CAP_CANCELLED");
        }
        if (deadlineMs <= Date.now()) {
          try {
            follower.abort();
          } catch {
            /* isolated */
          }
          rejectInterrupt?.("deadline");
          throw new RuntimeConfigurationError("CAP_DEADLINE_EXCEEDED");
        }
      };
      let retained = false;
      try {
        const interruption = new Promise<"cancel" | "deadline">((resolve) => {
          rejectInterrupt = resolve;
          timer = setTimeout(
            () => {
              try {
                follower.abort();
              } catch {
                /* isolated */
              }
              resolve("deadline");
            },
            Math.max(0, deadlineMs - Date.now()),
          );
        });
        try {
          if (signal) {
            addListener.call(signal, "abort", cancel, { once: true });
            establishedEvents = establishedSignalEvents(signal);
          }
        } catch {
          throw new RuntimeConfigurationError(
            "CAP_INTERNAL_INVOCATION_INVALID",
          );
        }
        refresh();
        const pending = providerValue(() => {
          refresh();
          const { authenticate, authenticateDisclosure } = providers.get(
            adapter.providerId,
          )!;
          if (capabilityId !== undefined)
            return authenticate(credentials, view as OperationView);
          if (!authenticateDisclosure) {
            if (disclosureHasCredentials)
              throw new Error("disclosure_provider_missing");
            return null;
          }
          return authenticateDisclosure(
            credentials,
            view as AdapterDisclosureAuthenticationView,
          );
        });
        const outcome = await Promise.race([pending, interruption]);
        refresh();
        if (outcome === "cancel")
          throw new RuntimeConfigurationError("CAP_CANCELLED");
        if (outcome === "deadline")
          throw new RuntimeConfigurationError("CAP_DEADLINE_EXCEEDED");
        if ("failed" in outcome)
          throw new RuntimeConfigurationError("CAP_DEPENDENCY_UNAVAILABLE");
        let identity: IdentityContext;
        if (outcome.value === null) {
          if (capabilityId !== undefined || disclosureHasCredentials)
            throw new RuntimeConfigurationError("CAP_UNAUTHENTICATED");
          identity = rootIdentity(anonymousPrincipal);
        } else {
          try {
            identity = rootIdentity(
              normalizePrincipal(outcome.value, adapter.providerId),
            );
          } catch {
            throw new RuntimeConfigurationError("CAP_DEPENDENCY_UNAVAILABLE");
          }
        }
        refresh();
        retained = true;
        return Object.freeze({ identity, refresh, dispose });
      } finally {
        // Successful verification retains interruption ownership until token issuance.
        if (!retained) dispose();
      }
    };
    return Object.freeze({
      invoke: invokeIngress,
      disclose: async (
        request?: AdapterDisclosureRequest,
      ): Promise<AdapterDisclosureResult> => {
        let data: Record<string, unknown>;
        try {
          data =
            request === undefined
              ? (Object.create(null) as Record<string, unknown>)
              : ownData(request, ["credentials", "deadline", "signal"]);
        } catch {
          throw new RuntimeConfigurationError(
            "CAP_INTERNAL_INVOCATION_INVALID",
          );
        }
        const credentials = data.credentials;
        const hasCredentials = Object.hasOwn(data, "credentials");
        delete data.credentials;
        const verification = await authenticateIdentity(
          undefined,
          credentials,
          data,
          hasCredentials,
        );
        try {
          verification.refresh();
          const identity = verification.identity;
          const requester = Object.freeze({}) as RequesterOwnershipToken;
          const requesterIdentity = copyJson(identity);
          const result = Object.freeze({
            visibility:
              adapter.privateBoundary === true
                ? ("private" as const)
                : identity.effective.type === "anonymous"
                  ? ("public" as const)
                  : ("authenticated" as const),
            ...(identity.effective.type === "anonymous"
              ? {}
              : { principal: identity.effective }),
            requester,
          });
          verification.refresh();
          requesters.set(requester, { adapter, identity: requesterIdentity });
          return result;
        } finally {
          verification.dispose();
        }
      },
      sameRequester: (
        left: RequesterOwnershipToken,
        right: RequesterOwnershipToken,
      ): boolean => {
        const held = (token: unknown) =>
          typeof token === "object" && token !== null && !types.isProxy(token)
            ? requesters.get(token)
            : undefined;
        const leftState = held(left);
        const rightState = held(right);
        return (
          leftState !== undefined &&
          rightState !== undefined &&
          leftState.adapter === adapter &&
          rightState.adapter === adapter &&
          equalJson(leftState.identity, rightState.identity)
        );
      },
      authenticate: async (
        capabilityId: string,
        credentials: unknown,
        authenticationOptions?: {
          readonly deadline?: Date;
          readonly signal?: AbortSignal;
        },
      ): Promise<PrincipalTrustToken> => {
        if (
          typeof capabilityId !== "string" ||
          !registry.entries.has(capabilityId) ||
          !adapter.capabilities.includes(capabilityId)
        )
          throw new RuntimeConfigurationError("CAP_UNAUTHENTICATED");
        const verification = await authenticateIdentity(
          capabilityId,
          credentials,
          authenticationOptions,
        );
        try {
          const token = Object.freeze({}) as PrincipalTrustToken;
          verification.refresh();
          tokens.set(token, {
            adapter,
            capability: capabilityId,
            identity: verification.identity,
          });
          return token;
        } finally {
          verification.dispose();
        }
      },
    });
  };
  return Object.freeze({
    invoke: (request: InvocationRequest) => invoke(request),
    createAdapterIngress,
    decideConfirmation: async (
      command: Parameters<RuntimeKernel["decideConfirmation"]>[0],
      approvalRequest: unknown,
    ) => {
      const correlationId = allocateCorrelation();
      const invalid = (
        code: string,
        status: "invalid_argument" | "unavailable",
        details?: JsonValue,
      ) => ({
        ok: false as const,
        error: {
          code,
          status,
          message: "Confirmation operation failed.",
          retryable: status === "unavailable",
          correlationId,
          ...(details === undefined ? {} : { details }),
        },
      });
      let data: Record<string, unknown>;
      try {
        data = ownData(command, ["challenge", "decision", "correlationId"]);
      } catch {
        return invalid("CAP_INPUT_INVALID", "invalid_argument");
      }
      if (
        !bearerGuard.validateCorrelationHint(
          data.correlationId,
          Object.hasOwn(data, "correlationId"),
        ).valid
      )
        return invalid("CAP_INPUT_INVALID", "invalid_argument", {
          path: "/correlationId",
        });
      delete data.correlationId;
      if (!confirmationProvider)
        return invalid("CAP_DEPENDENCY_UNAVAILABLE", "unavailable");
      const controller = new AbortController();
      const deadlineMs = Date.now() + 30_000;
      let timedOut = false;
      let expire: (() => void) | undefined;
      const timeout = new Promise<{ failed: true }>((resolve) => {
        expire = () => {
          timedOut = true;
          controller.abort();
          resolve({ failed: true });
        };
      });
      const timer = setTimeout(() => expire?.(), 30_000);
      const observe = (callback: () => unknown) =>
        Promise.race([providerValue(callback), timeout]);
      try {
        const allocated = await observe(() =>
          confirmationProvider.allocateKernelInvocationId({
            signal: controller.signal,
            deadlineMs,
            correlationId,
          }),
        );
        if ("failed" in allocated)
          return invalid("CAP_DEPENDENCY_UNAVAILABLE", "unavailable");
        const allocation = confirmationResponse<
          Awaited<
            ReturnType<typeof confirmationProvider.allocateKernelInvocationId>
          >
        >(allocated.value, "allocation");
        if (!allocation.ok)
          return {
            ...allocation,
            error: { ...allocation.error, correlationId },
          };
        const outcome = await observe(() =>
          confirmationProvider.decideConfirmation(
            { challenge: data.challenge, decision: data.decision },
            approvalRequest,
            {
              signal: controller.signal,
              deadlineMs,
              kernelInvocationId: allocation.kernelInvocationId,
              correlationId,
            },
          ),
        );
        if ("failed" in outcome || timedOut)
          return invalid("CAP_DEPENDENCY_UNAVAILABLE", "unavailable");
        const result = confirmationResponse<
          Awaited<ReturnType<typeof confirmationProvider.decideConfirmation>>
        >(outcome.value, "decision");
        return result.ok
          ? { ...result, correlationId }
          : { ...result, error: { ...result.error, correlationId } };
      } catch {
        return invalid("CAP_DEPENDENCY_UNAVAILABLE", "unavailable");
      } finally {
        clearTimeout(timer);
      }
    },
  });
}
