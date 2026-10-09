import { randomUUID } from "node:crypto";
import { jcs } from "@capaxle/ir";
import type { JsonValue } from "@capaxle/ir";

export type Data = Record<string, unknown>;
export const object = (value: unknown): value is Data =>
  value !== null && typeof value === "object" && !Array.isArray(value);
export const closed = (
  value: unknown,
  required: string[],
  optional: string[] = [],
): value is Data =>
  object(value) &&
  required.every((key) => Object.hasOwn(value, key)) &&
  Object.keys(value).every(
    (key) => required.includes(key) || optional.includes(key),
  );
export const text = (value: unknown, max = 1024): value is string =>
  typeof value === "string" &&
  value.length > 0 &&
  Buffer.byteLength(value) <= max;
export const integer = (
  value: unknown,
  min: number,
  max: number,
): value is number =>
  Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max;
export const hash = (value: unknown): value is string =>
  typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value);
export const semver = (value: unknown): value is string =>
  text(value, 256) &&
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u.test(
    value,
  );
export const capabilityId = (value: unknown): value is string =>
  text(value, 256) && /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*$/u.test(value);
export const json = (value: unknown): string => jcs(value as JsonValue);
export interface ClientResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}
export class ClientFailure extends Error {
  constructor(
    readonly code: string,
    readonly status: string,
    readonly exitCode: number,
    message: string,
  ) {
    super(message);
    this.name = "ClientFailure";
  }
}
export function fail(
  code = "CAP_INPUT_INVALID",
  status = "invalid_argument",
  exit = 2,
  message = "Invalid client syntax or configuration.",
): never {
  throw new ClientFailure(code, status, exit, message);
}
export function invalidReply(): never {
  return fail(
    "CAP_CLI_RESPONSE_INVALID",
    "internal",
    7,
    "Invalid remote CLI response.",
  );
}
export function failureResult(
  error: unknown,
  signal?: AbortSignal,
): ClientResult {
  const failure = signal?.aborted
    ? new ClientFailure(
        "CAP_CANCELLED",
        "cancelled",
        130,
        "Client request cancelled; execution may already have occurred.",
      )
    : error instanceof ClientFailure
      ? error
      : new ClientFailure(
          "CAP_CLI_INTERNAL",
          "internal",
          7,
          "Client operation failed.",
        );
  return {
    exitCode: failure.exitCode,
    stdout:
      json({
        ok: false,
        error: {
          code: failure.code,
          status: failure.status,
          message: failure.message,
          retryable: false,
          correlationId: randomUUID(),
        },
      }) + "\n",
    stderr: "",
  };
}
export function success(value: unknown): ClientResult {
  return {
    exitCode: 0,
    stdout: json({ ok: true, value, correlationId: randomUUID() }) + "\n",
    stderr: "",
  };
}

export function finiteJson(value: unknown): boolean {
  const pending: unknown[] = [value];
  while (pending.length) {
    const current = pending.pop();
    if (typeof current === "number") {
      if (!Number.isFinite(current)) return false;
    } else if (
      current === null ||
      typeof current === "string" ||
      typeof current === "boolean"
    )
      continue;
    else if (Array.isArray(current))
      for (const value of current) pending.push(value);
    else if (object(current))
      for (const value of Object.values(current)) pending.push(value);
    else return false;
  }
  return true;
}
