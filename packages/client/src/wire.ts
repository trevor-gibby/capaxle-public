import { createHash } from "node:crypto";
import { metaValidateDraft202012Schema } from "@capaxle/ir";
import type { JsonSchema } from "@capaxle/ir";
import {
  capabilityId,
  closed,
  hash,
  integer,
  invalidReply,
  json,
  object,
  semver,
  text,
  fail,
} from "./common.js";
import type { Data } from "./common.js";
import type { InputCapability } from "./input.js";
export const CLI_TARGET = "opencli:bcdxn@1.0.0-alpha.13+capaxle-cli@0.2";
export const PROTOCOL = "0.1";
export interface RemoteIdentity {
  protocolVersion: "0.1";
  service: { id: string; name: string; version: string };
  irHash: string;
  contractHash: string;
}
export interface CachePolicy {
  scope: "public" | "private";
  ttlMs: number;
  visibilityKey: string;
}
export interface Summary {
  id: string;
  version: string;
  summary: string;
  command: string[];
  detailUrl: string;
  schemaUrl: string;
}
export interface Collection extends RemoteIdentity {
  kind: "collection";
  irVersion: "0.1";
  cliTarget: string;
  endpoints: {
    collection: string;
    detailTemplate: string;
    schemaTemplate: string;
    invoke: string;
  };
  externalUrl?: string;
  payloadLimits: { requestBytes: number; responseBytes: number };
  cache: CachePolicy;
  capabilities: Summary[];
}
export interface PublishedCapability extends InputCapability {
  id: string;
  version: string;
  summary: string;
  command: string[];
  errors: Data;
  [key: string]: unknown;
}
export interface Detail extends RemoteIdentity {
  kind: "detail";
  capability: PublishedCapability;
  cache: CachePolicy;
}
export interface Schema extends RemoteIdentity {
  kind: "schema";
  capability: { id: string; version: string };
  schemas: Data;
  cache: CachePolicy;
}
export interface CanonicalError {
  code: string;
  status: string;
  message: string;
  retryable: boolean;
  details?: unknown;
  correlationId: string;
}
export type RemoteResult =
  | { ok: true; value: unknown; correlationId: string }
  | { ok: false; error: CanonicalError };
const identityKeys = ["protocolVersion", "service", "irHash", "contractHash"];
export const statuses = [
  "invalid_argument",
  "unauthenticated",
  "permission_denied",
  "not_found",
  "already_exists",
  "failed_precondition",
  "conflict",
  "resource_exhausted",
  "cancelled",
  "deadline_exceeded",
  "unavailable",
  "internal",
];
const serviceId = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value);
const command = (value: unknown): value is string[] =>
  Array.isArray(value) &&
  value.length > 0 &&
  value.every((v) => typeof v === "string" && /^[a-z0-9][a-z0-9-]*$/u.test(v));
export function path(
  value: unknown,
  mount: string,
  template = false,
): value is string {
  if (
    typeof value !== "string" ||
    value.length > 8192 ||
    !value.startsWith(mount) ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    /[?#\\\s]/u.test(value)
  )
    return false;
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return false;
  }
  if (
    decoded.includes("\\") ||
    /[\u0000-\u0020\u007f]/u.test(decoded) ||
    /%[0-9a-f]{2}/iu.test(decoded) ||
    /%(?:2f|5c)/iu.test(value)
  )
    return false;
  const segments = decoded.split("/");
  if (segments.slice(1).some((v) => v === "." || v === ".." || v === ""))
    return false;
  const tokens = segments.filter((v) => v === "{id}");
  return template
    ? tokens.length === 1 &&
        segments.every((v) => !/[{}]/u.test(v) || v === "{id}")
    : !/[{}]/u.test(decoded);
}
function identity(value: Data): value is Data & RemoteIdentity {
  return (
    value.protocolVersion === PROTOCOL &&
    closed(value.service, ["id", "name", "version"]) &&
    serviceId(value.service.id) &&
    typeof value.service.name === "string" &&
    [...value.service.name].length >= 1 &&
    [...value.service.name].length <= 128 &&
    semver(value.service.version) &&
    hash(value.irHash) &&
    hash(value.contractHash)
  );
}
function cache(value: unknown): value is CachePolicy {
  return (
    closed(value, ["scope", "ttlMs", "visibilityKey"]) &&
    ["public", "private"].includes(String(value.scope)) &&
    integer(value.ttlMs, 0, 30000) &&
    typeof value.visibilityKey === "string" &&
    /^[\x21-\x7e]{1,128}$/u.test(value.visibilityKey)
  );
}
export function schema(value: unknown): boolean {
  if (!object(value)) return false;
  try {
    if (metaValidateDraft202012Schema(value as JsonSchema).length) return false;
    const maps = new Set([
      "properties",
      "$defs",
      "patternProperties",
      "dependentSchemas",
    ]);
    const singles = new Set([
      "items",
      "additionalProperties",
      "unevaluatedProperties",
      "propertyNames",
      "contains",
      "not",
      "if",
      "then",
      "else",
      "unevaluatedItems",
    ]);
    const arrays = new Set(["oneOf", "anyOf", "allOf", "prefixItems"]);
    const visit = (node: unknown): boolean => {
      if (!object(node)) return typeof node === "boolean";
      if (node.$ref !== undefined) {
        if (
          typeof node.$ref !== "string" ||
          !/^#\/\$defs\/(?:[^~/]|~0|~1)+$/u.test(node.$ref)
        )
          return false;
        const target = node.$ref
          .slice(8)
          .replaceAll("~1", "/")
          .replaceAll("~0", "~");
        if (!object(value.$defs) || !Object.hasOwn(value.$defs, target))
          return false;
      }
      for (const [key, child] of Object.entries(node)) {
        if (
          maps.has(key) &&
          (!object(child) || !Object.values(child).every(visit))
        )
          return false;
        if (singles.has(key) && !visit(child)) return false;
        if (arrays.has(key) && (!Array.isArray(child) || !child.every(visit)))
          return false;
      }
      return true;
    };
    return visit(value);
  } catch {
    return false;
  }
}
function errors(value: unknown): value is Data {
  return (
    object(value) &&
    Object.entries(value).every(
      ([key, error]) =>
        /^(?!CAP_)[A-Z][A-Z0-9_]*$/u.test(key) &&
        closed(
          error,
          ["status", "message", "retryable"],
          ["details", "docs"],
        ) &&
        statuses.includes(String(error.status)) &&
        text(error.message, 65536) &&
        typeof error.retryable === "boolean" &&
        (error.details === undefined || schema(error.details)) &&
        (error.docs === undefined || typeof error.docs === "string"),
    )
  );
}
function schemas(value: unknown): value is Data {
  return (
    closed(value, ["input", "output", "errors"]) &&
    schema(value.input) &&
    schema(value.output) &&
    errors(value.errors)
  );
}
function published(value: unknown): value is PublishedCapability {
  if (
    !closed(
      value,
      [
        "id",
        "version",
        "summary",
        "command",
        "bindings",
        "input",
        "output",
        "errors",
        "examples",
        "access",
        "effects",
        "execution",
        "controls",
      ],
      ["description"],
    ) ||
    !capabilityId(value.id) ||
    !semver(value.version) ||
    !text(value.summary, 65536) ||
    !command(value.command) ||
    !object(value.bindings) ||
    !schema(value.input) ||
    !schema(value.output) ||
    !errors(value.errors) ||
    (value.description !== undefined && typeof value.description !== "string")
  )
    return false;
  const positions: number[] = [];
  const options: string[] = [];
  for (const binding of Object.values(value.bindings)) {
    if (
      closed(binding, ["kind", "name"]) &&
      binding.kind === "option" &&
      typeof binding.name === "string" &&
      /^--[a-z0-9][a-z0-9-]*$/u.test(binding.name)
    )
      options.push(binding.name);
    else if (
      closed(binding, ["kind", "index"]) &&
      binding.kind === "positional" &&
      integer(binding.index, 0, 10000)
    )
      positions.push(binding.index);
    else return false;
  }
  if (
    new Set(options).size !== options.length ||
    positions.sort((a, b) => a - b).some((v, i) => v !== i) ||
    options.some((v) =>
      [
        "--json",
        "--no-input",
        "--input",
        "--input-file",
        "--confirm",
        "--correlation-id",
        "--idempotency-key",
        "--timeout",
        "--help",
        "--version",
      ].includes(v),
    )
  )
    return false;
  if (
    !Array.isArray(value.examples) ||
    !value.examples.every(
      (v) =>
        closed(v, ["name", "input"], ["description", "output", "error"]) &&
        text(v.name) &&
        (v.description === undefined || typeof v.description === "string") &&
        (v.error === undefined ||
          (closed(v.error, ["code"], ["details"]) && text(v.error.code))),
    )
  )
    return false;
  if (
    !closed(value.access, ["authentication", "permissions", "exposure"]) ||
    !["public", "optional", "required"].includes(
      String(value.access.authentication),
    ) ||
    !["public", "authenticated", "private"].includes(
      String(value.access.exposure),
    )
  )
    return false;
  const permission = value.access.permissions;
  if (!(
    (closed(permission, ["public"]) && permission.public === true) ||
    (closed(permission, [], ["allOf", "anyOf"]) &&
      Object.values(permission).every(
        (v) => Array.isArray(v) && v.every((x) => text(x)),
      ))
  ))
    return false;
  if (
    !closed(value.effects, [
      "impact",
      "idempotency",
      "confirmation",
      "retry",
    ]) ||
    !["read", "write", "destructive"].includes(String(value.effects.impact)) ||
    !["none", "intrinsic", "key"].includes(String(value.effects.idempotency)) ||
    !["none", "required"].includes(String(value.effects.confirmation)) ||
    !closed(value.effects.retry, ["mode"]) ||
    !["never", "safe"].includes(String(value.effects.retry.mode)) ||
    (value.effects.impact === "destructive" &&
      value.effects.confirmation !== "required")
  )
    return false;
  if (
    !closed(
      value.execution,
      ["mode", "result", "cancellable"],
      ["timeoutMs"],
    ) ||
    value.execution.mode !== "inline" ||
    value.execution.result !== "unary" ||
    typeof value.execution.cancellable !== "boolean" ||
    (value.execution.timeoutMs !== undefined &&
      !integer(value.execution.timeoutMs, 1, Number.MAX_SAFE_INTEGER))
  )
    return false;
  if (
    !closed(value.controls, [
      "confirmation",
      "idempotency",
      "correlation",
      "maxTimeoutMs",
    ]) ||
    value.controls.confirmation !==
      (value.effects.confirmation === "required"
        ? "opaque-evidence"
        : "none") ||
    value.controls.idempotency !== value.effects.idempotency ||
    value.controls.correlation !== "untrusted-hint" ||
    !integer(value.controls.maxTimeoutMs, 1, 300000)
  )
    return false;
  return true;
}
export function validateCollection(
  value: unknown,
  url: string,
  collectionPath = `${new URL(url).pathname}cli`,
): Collection {
  const mount = new URL(url).pathname;
  if (
    !closed(
      value,
      [
        ...identityKeys,
        "kind",
        "irVersion",
        "cliTarget",
        "endpoints",
        "payloadLimits",
        "cache",
        "capabilities",
      ],
      ["externalUrl"],
    ) ||
    !identity(value) ||
    value.kind !== "collection" ||
    value.irVersion !== "0.1" ||
    value.cliTarget !== CLI_TARGET ||
    !closed(value.endpoints, [
      "collection",
      "detailTemplate",
      "schemaTemplate",
      "invoke",
    ]) ||
    !path(value.endpoints.collection, mount) ||
    value.endpoints.collection !== collectionPath ||
    !path(value.endpoints.invoke, mount) ||
    !path(value.endpoints.detailTemplate, mount, true) ||
    !path(value.endpoints.schemaTemplate, mount, true) ||
    !closed(value.payloadLimits, ["requestBytes", "responseBytes"]) ||
    !integer(value.payloadLimits.requestBytes, 1024, 1048576) ||
    !integer(value.payloadLimits.responseBytes, 8192, 8388608) ||
    !cache(value.cache) ||
    !Array.isArray(value.capabilities)
  )
    invalidReply();
  if (value.externalUrl !== undefined) {
    try {
      if (typeof value.externalUrl !== "string") invalidReply();
      const external = new URL(value.externalUrl);
      const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(
        external.hostname,
      );
      if (
        (external.protocol !== "https:" &&
          !(external.protocol === "http:" && loopback)) ||
        external.username ||
        external.password ||
        external.hash ||
        external.search ||
        external.pathname !== (mount === "/" ? "/" : mount.slice(0, -1))
      )
        invalidReply();
    } catch {
      invalidReply();
    }
  }
  const endpoints = value.endpoints;
  if (
    !value.capabilities.every(
      (v) =>
        closed(v, [
          "id",
          "version",
          "summary",
          "command",
          "detailUrl",
          "schemaUrl",
        ]) &&
        capabilityId(v.id) &&
        semver(v.version) &&
        text(v.summary, 65536) &&
        command(v.command) &&
        v.detailUrl ===
          String(endpoints.detailTemplate).replace(
            "{id}",
            encodeURIComponent(v.id),
          ) &&
        v.schemaUrl ===
          String(endpoints.schemaTemplate).replace(
            "{id}",
            encodeURIComponent(v.id),
          ),
    )
  )
    invalidReply();
  const expected =
    "sha256:" +
    createHash("sha256")
      .update(
        json({
          protocolVersion: PROTOCOL,
          serviceId: value.service.id,
          irVersion: "0.1",
          cliTarget: CLI_TARGET,
          basePath: mount === "/" ? "/" : mount.slice(0, -1),
          resolvedCliEndpoints: endpoints,
          payloadLimits: value.payloadLimits,
        }),
        "utf8",
      )
      .digest("hex");
  if (expected !== value.contractHash) invalidReply();
  const seen = new Set<string>();
  for (const entry of value.capabilities as Summary[]) {
    const key = `${entry.id}@${entry.version}`;
    if (seen.has(key)) invalidReply();
    seen.add(key);
  }
  return value as unknown as Collection;
}
export function ensureIdentity(
  value: RemoteIdentity,
  expected: RemoteIdentity,
): void {
  if (value.service.id !== expected.service.id)
    fail(
      "CAP_CLI_SERVICE_MISMATCH",
      "failed_precondition",
      4,
      "Remote service identity changed; refresh discovery explicitly.",
    );
  if (value.contractHash !== expected.contractHash)
    fail(
      "CAP_CLI_CONTRACT_MISMATCH",
      "failed_precondition",
      4,
      "Remote transport contract changed; refresh discovery explicitly.",
    );
  if (value.irHash !== expected.irHash)
    fail(
      "CAP_CLI_IR_MISMATCH",
      "failed_precondition",
      4,
      "Remote capability contract changed; refresh discovery explicitly.",
    );
  if (
    value.service.name !== expected.service.name ||
    value.service.version !== expected.service.version
  )
    invalidReply();
}
export function validateDetail(
  value: unknown,
  expected: Collection,
  summary: Summary,
): Detail {
  if (
    !closed(value, [...identityKeys, "kind", "capability", "cache"]) ||
    !identity(value) ||
    value.kind !== "detail" ||
    !cache(value.cache) ||
    !published(value.capability)
  )
    invalidReply();
  ensureIdentity(value, expected);
  if (
    value.capability.id !== summary.id ||
    value.capability.version !== summary.version ||
    json(value.capability.command) !== json(summary.command) ||
    value.capability.summary !== summary.summary
  )
    invalidReply();
  return value as unknown as Detail;
}
export function validateSchema(
  value: unknown,
  expected: Collection,
  summary: Summary,
): Schema {
  if (
    !closed(value, [
      ...identityKeys,
      "kind",
      "capability",
      "schemas",
      "cache",
    ]) ||
    !identity(value) ||
    value.kind !== "schema" ||
    !cache(value.cache) ||
    !closed(value.capability, ["id", "version"]) ||
    value.capability.id !== summary.id ||
    value.capability.version !== summary.version ||
    !schemas(value.schemas)
  )
    invalidReply();
  ensureIdentity(value, expected);
  return value as unknown as Schema;
}
export function validateResult(
  value: unknown,
  expected?: RemoteIdentity,
): RemoteResult {
  if (!object(value) || typeof value.ok !== "boolean") invalidReply();
  const hasIdentity = identityKeys.some((key) => Object.hasOwn(value, key));
  if ((hasIdentity && !identity(value)) || (value.ok && !hasIdentity))
    invalidReply();
  if (value.ok) {
    if (
      !closed(value, [...identityKeys, "ok", "value", "correlationId"]) ||
      !text(value.correlationId, 128)
    )
      invalidReply();
  } else if (
    !closed(value, [...(hasIdentity ? identityKeys : []), "ok", "error"]) ||
    !closed(
      value.error,
      ["code", "status", "message", "retryable", "correlationId"],
      ["details"],
    ) ||
    !text(value.error.code, 256) ||
    !statuses.includes(String(value.error.status)) ||
    !text(value.error.message, 65536) ||
    typeof value.error.retryable !== "boolean" ||
    !text(value.error.correlationId, 128)
  )
    invalidReply();
  const canonicalMismatch =
    value.ok === false &&
    object(value.error) &&
    value.error.status === "failed_precondition" &&
    [
      "CAP_CLI_IR_MISMATCH",
      "CAP_CLI_CONTRACT_MISMATCH",
      "CAP_CLI_SERVICE_MISMATCH",
    ].includes(String(value.error.code));
  if (expected && hasIdentity && !canonicalMismatch)
    ensureIdentity(value as unknown as RemoteIdentity, expected);
  return value as unknown as RemoteResult;
}
export function resultExit(result: RemoteResult, declared: Data = {}): number {
  if (result.ok) return 0;
  const { code, status } = result.error;
  if (status === "cancelled") return 130;
  if (status === "invalid_argument") return 2;
  if (["unauthenticated", "permission_denied"].includes(status)) return 3;
  if (Object.hasOwn(declared, code)) return 5;
  if (status === "failed_precondition") return 4;
  if (
    ["resource_exhausted", "unavailable", "deadline_exceeded"].includes(status)
  )
    return 6;
  return 7;
}
