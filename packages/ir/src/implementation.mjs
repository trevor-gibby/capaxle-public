import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";

export const IR_VERSION = "0.1";
export const JSON_SCHEMA_DIALECT =
  "https://json-schema.org/draft/2020-12/schema";

const SEMVER_PATTERN =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const ALLOWED_SCHEMA_KEYS = new Set([
  "$schema",
  "$ref",
  "$defs",
  "type",
  "enum",
  "const",
  "properties",
  "required",
  "additionalProperties",
  "items",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "multipleOf",
  "minLength",
  "maxLength",
  "pattern",
  "format",
  "minItems",
  "maxItems",
  "uniqueItems",
  "description",
  "default",
  "examples",
  "oneOf",
]);
const ALLOWED_FORMATS = new Set([
  "date-time",
  "date",
  "time",
  "duration",
  "email",
  "hostname",
  "ipv4",
  "ipv6",
  "uri",
  "uuid",
]);
const LANGUAGE_KEYS = new Set([
  "zod",
  "zodSchema",
  "typescriptType",
  "tsType",
  "typescript",
]);
const EXECUTABLE_KEYS = new Set([
  "handler",
  "runtimeValidator",
  "validator",
  "provider",
  "resolver",
  "function",
]);
const REQUIREMENT_SECRET_KEYS = new Set([
  "value",
  "path",
  "token",
  "credential",
]);
const PROJECTION_POLICY_KEYS = new Set([
  "authentication",
  "permissions",
  "exposure",
  "effects",
  "impact",
  "idempotency",
  "confirmation",
  "retry",
  "limits",
  "rateLimit",
  "requirements",
  "secrets",
]);

const CORE_KEYS = {
  document: new Set([
    "irVersion",
    "service",
    "schemas",
    "capabilities",
    "metadata",
  ]),
  service: new Set([
    "name",
    "version",
    "title",
    "description",
    "homepage",
    "contact",
    "tags",
  ]),
  contact: new Set(["name", "url", "email"]),
  metadata: new Set([
    "generator",
    "sourceHash",
    "generatedAt",
    "sourceRepository",
  ]),
  generator: new Set(["name", "version"]),
  capability: new Set([
    "id",
    "version",
    "summary",
    "description",
    "tags",
    "input",
    "output",
    "errors",
    "access",
    "effects",
    "execution",
    "requirements",
    "limits",
    "lifecycle",
    "interfaces",
    "examples",
  ]),
  schemaRef: new Set(["schema", "$ref"]),
  error: new Set(["status", "message", "details", "retryable", "docs"]),
  access: new Set(["authentication", "permissions", "exposure"]),
  permissions: new Set(["public", "allOf", "anyOf"]),
  exposure: new Set(["http", "cli", "mcp", "internal"]),
  effects: new Set(["impact", "idempotency", "confirmation", "retry"]),
  retry: new Set(["mode"]),
  execution: new Set(["mode", "result", "timeoutMs", "cancellable"]),
  requirements: new Set(["secrets", "resources", "environment"]),
  secretRequirement: new Set(["name", "optional", "description"]),
  resourceRequirement: new Set(["name", "kind", "optional"]),
  environmentRequirement: new Set(["name", "presence", "sensitive"]),
  limits: new Set(["rateLimit"]),
  rateLimit: new Set(["policy", "cost", "description"]),
  lifecycle: new Set([
    "status",
    "since",
    "deprecatedAt",
    "sunsetAt",
    "replacement",
  ]),
  interfaces: new Set(["http", "cli", "mcp", "docs", "sdk"]),
  httpProjection: new Set(["enabled", "method", "path", "bindings"]),
  cliProjection: new Set(["enabled", "command", "bindings"]),
  mcpProjection: new Set(["enabled", "toolName"]),
  docsProjection: new Set(["enabled", "group"]),
  sdkProjection: new Set(["enabled", "path"]),
  cliBinding: new Set(["kind", "name", "index"]),
  example: new Set(["name", "description", "input", "output", "error"]),
  exampleError: new Set(["code", "details"]),
};

const PLAN_KEYS = {
  document: new Set(["defaults"]),
  capability: new Set(["pagination", "files", "extensions"]),
  permissions: new Set(["expression"]),
  effects: new Set(["scope", "dryRun", "audit", "conditionalConfirmation"]),
  retry: new Set(["attempts", "maxAttempts", "backoff", "policy"]),
  execution: new Set([
    "progress",
    "concurrency",
    "transactions",
    "transaction",
  ]),
  lifecycle: new Set(["removed", "aliases"]),
  error: new Set(["httpStatus"]),
};

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function escapePointerToken(value) {
  return String(value).replaceAll("~", "~0").replaceAll("/", "~1");
}

function childPath(path, key) {
  return `${path}/${escapePointerToken(key)}`;
}

function decodePointerToken(value) {
  if (/(?:~[^01]|~$)/u.test(value)) return undefined;
  return value.replaceAll("~1", "/").replaceAll("~0", "~");
}

function diagnostic(code, path, message) {
  return { code, severity: "error", path, message };
}

function deepEqual(left, right) {
  try {
    return jcs(left) === jcs(right);
  } catch {
    return false;
  }
}

function unicodeCodePointCompare(left, right) {
  const a = Array.from(left, (character) => character.codePointAt(0));
  const b = Array.from(right, (character) => character.codePointAt(0));
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1;
  }
  return a.length - b.length;
}

function uniqueSortedStrings(values) {
  return [...new Set(values)].sort(unicodeCodePointCompare);
}

function parseSemVer(value) {
  const match = typeof value === "string" ? SEMVER_PATTERN.exec(value) : null;
  if (!match) return undefined;
  return {
    major: BigInt(match[1]),
    minor: BigInt(match[2]),
    patch: BigInt(match[3]),
    prerelease: match[4] === undefined ? undefined : match[4].split("."),
  };
}

function semVerCompare(left, right) {
  const a = parseSemVer(left);
  const b = parseSemVer(right);
  if (!a || !b) return unicodeCodePointCompare(String(left), String(right));
  for (const key of ["major", "minor", "patch"]) {
    if (a[key] !== b[key]) return a[key] < b[key] ? -1 : 1;
  }
  if (a.prerelease === undefined && b.prerelease === undefined) return 0;
  if (a.prerelease === undefined) return 1;
  if (b.prerelease === undefined) return -1;
  for (
    let index = 0;
    index < Math.min(a.prerelease.length, b.prerelease.length);
    index += 1
  ) {
    const x = a.prerelease[index];
    const y = b.prerelease[index];
    if (x === y) continue;
    const xNumeric = /^[0-9]+$/u.test(x);
    const yNumeric = /^[0-9]+$/u.test(y);
    if (xNumeric && yNumeric) return BigInt(x) < BigInt(y) ? -1 : 1;
    if (xNumeric !== yNumeric) return xNumeric ? -1 : 1;
    return unicodeCodePointCompare(x, y);
  }
  return a.prerelease.length - b.prerelease.length;
}

function assertPortableJson(value, path = "", ancestors = new Set()) {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    assertValidUnicode(value, path);
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new TypeError(`Non-finite number at ${path || "/"}`);
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new TypeError(`Non-I-JSON integer at ${path || "/"}`);
    }
    return;
  }
  if (typeof value !== "object") {
    throw new TypeError(`Non-JSON ${typeof value} value at ${path || "/"}`);
  }
  if (ancestors.has(value))
    throw new TypeError(`Cyclic value at ${path || "/"}`);
  let array;
  let descriptors;
  try {
    array = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if (
      (array && prototype !== Array.prototype) ||
      (!array && prototype !== Object.prototype)
    )
      throw new TypeError(`Non-plain object at ${path || "/"}`);
    if (Object.getOwnPropertySymbols(value).length)
      throw new TypeError(`Symbol property at ${path || "/"}`);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch (error) {
    if (error instanceof TypeError) throw error;
    throw new TypeError(`Malformed object at ${path || "/"}`);
  }
  const entries = Object.entries(descriptors).filter(
    ([key]) => !array || key !== "length",
  );
  const arrayLength = array ? descriptors.length?.value : undefined;
  if (
    array &&
    (!Number.isSafeInteger(arrayLength) ||
      arrayLength < 0 ||
      entries.length !== arrayLength)
  )
    throw new TypeError(`Sparse or extended array at ${path || "/"}`);
  ancestors.add(value);
  try {
    for (const [index, [key, descriptor]] of entries.entries()) {
      const entryPath = childPath(path, key);
      assertValidUnicode(key, entryPath);
      if (
        !("value" in descriptor) ||
        !descriptor.enumerable ||
        (array && key !== String(index))
      )
        throw new TypeError(`Non-data property at ${entryPath}`);
      assertPortableJson(descriptor.value, entryPath, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

function assertValidUnicode(value, path) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(`Lone high surrogate at ${path || "/"}`);
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError(`Lone low surrogate at ${path || "/"}`);
    }
  }
}

function deepClone(value) {
  assertPortableJson(value);
  return copyPortableJson(value);
}

function copyPortableJson(value) {
  if (value === null || typeof value !== "object") return value;
  const array = Array.isArray(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const entries = Object.entries(descriptors).filter(
    ([key]) => !array || key !== "length",
  );
  const copy = array ? [] : {};
  for (const [key, descriptor] of entries) {
    Object.defineProperty(copy, key, {
      value: copyPortableJson(descriptor.value),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return copy;
}

function normalizeSchema(schema) {
  if (!isObject(schema)) return schema;
  const normalized = {};
  for (const [key, value] of Object.entries(schema)) {
    if (key === "$defs" || key === "properties") {
      normalized[key] = Object.fromEntries(
        Object.entries(value).map(([name, child]) => [
          name,
          normalizeSchema(child),
        ]),
      );
    } else if (key === "items") {
      normalized[key] = normalizeSchema(value);
    } else if (key === "oneOf" && Array.isArray(value)) {
      normalized[key] = value
        .map((branch) => normalizeSchema(branch))
        .sort((left, right) => unicodeCodePointCompare(jcs(left), jcs(right)));
    } else if (key === "required" && Array.isArray(value)) {
      normalized[key] = uniqueSortedStrings(value);
    } else if (key === "type" && Array.isArray(value)) {
      normalized[key] = uniqueSortedStrings(value);
    } else if (key === "enum" && Array.isArray(value)) {
      normalized[key] = [...value].sort((left, right) =>
        unicodeCodePointCompare(jcs(left), jcs(right)),
      );
    } else {
      normalized[key] = value;
    }
  }
  return normalized;
}

function normalizeSchemaRef(reference) {
  if (isObject(reference) && isObject(reference.schema)) {
    reference.schema = normalizeSchema(reference.schema);
  }
}

function normalizeRequirementEntries(entries) {
  return entries.sort((left, right) =>
    unicodeCodePointCompare(String(left.name), String(right.name)),
  );
}

export function normalizeDocument(source) {
  const document = deepClone(source);
  document.schemas ??= {};
  document.service ??= {};
  document.service.tags ??= [];
  document.service.tags = uniqueSortedStrings(document.service.tags);
  document.schemas = Object.fromEntries(
    Object.entries(document.schemas).map(([name, schema]) => [
      name,
      normalizeSchema(schema),
    ]),
  );
  document.capabilities ??= [];
  for (const capability of document.capabilities) {
    capability.tags ??= [];
    capability.tags = uniqueSortedStrings(capability.tags);
    capability.errors ??= {};
    capability.examples ??= [];
    normalizeSchemaRef(capability.input);
    normalizeSchemaRef(capability.output);
    for (const error of Object.values(capability.errors)) {
      error.retryable ??= false;
      normalizeSchemaRef(error.details);
    }
    capability.effects ??= {};
    if (
      capability.effects.idempotency === undefined &&
      capability.effects.impact === "read"
    ) {
      capability.effects.idempotency = "intrinsic";
    }
    if (capability.effects.confirmation === undefined) {
      capability.effects.confirmation =
        capability.effects.impact === "destructive" ? "required" : "none";
    }
    capability.effects.retry ??= { mode: "never" };
    capability.execution ??= {
      mode: "inline",
      result: "unary",
      cancellable: false,
    };
    capability.execution.mode ??= "inline";
    capability.execution.result ??= "unary";
    capability.execution.cancellable ??= false;
    capability.requirements ??= {};
    capability.requirements.secrets ??= [];
    capability.requirements.resources ??= [];
    capability.requirements.environment ??= [];
    for (const requirement of capability.requirements.secrets)
      requirement.optional ??= false;
    for (const requirement of capability.requirements.resources)
      requirement.optional ??= false;
    for (const requirement of capability.requirements.environment)
      requirement.sensitive ??= false;
    capability.requirements.secrets = normalizeRequirementEntries(
      capability.requirements.secrets,
    );
    capability.requirements.resources = normalizeRequirementEntries(
      capability.requirements.resources,
    );
    capability.requirements.environment = normalizeRequirementEntries(
      capability.requirements.environment,
    );
    capability.limits ??= {};
    capability.lifecycle ??= {};
    capability.lifecycle.status ??= "experimental";
    if (isObject(capability.access?.permissions)) {
      for (const key of ["allOf", "anyOf"]) {
        if (Array.isArray(capability.access.permissions[key])) {
          capability.access.permissions[key] = uniqueSortedStrings(
            capability.access.permissions[key],
          );
        }
      }
    }
  }
  document.capabilities.sort((left, right) => {
    const idOrder = unicodeCodePointCompare(String(left.id), String(right.id));
    if (idOrder !== 0) return idOrder;
    const precedence = semVerCompare(left.version, right.version);
    return precedence !== 0
      ? precedence
      : unicodeCodePointCompare(String(left.version), String(right.version));
  });
  return document;
}

function serializeJcs(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new TypeError("JCS cannot serialize a non-finite number");
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    assertValidUnicode(value, "");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(serializeJcs).join(",")}]`;
  if (isObject(value)) {
    const members = Object.keys(value)
      .sort()
      .map((key) => {
        assertValidUnicode(key, "");
        return `${JSON.stringify(key)}:${serializeJcs(value[key])}`;
      });
    return `{${members.join(",")}}`;
  }
  throw new TypeError(`JCS cannot serialize ${typeof value}`);
}

export function jcs(value) {
  assertPortableJson(value);
  return serializeJcs(value);
}

const NORMATIVE_SCHEMA_DIGEST =
  "sha256:3178a17e30adb0cf2b7f129d8db10b38b9f4f1c6b0ae381303d83763916146db";
const NORMATIVE_SCHEMA = JSON.parse(
  readFileSync(
    new URL("../capability-ir.schema.json", import.meta.url),
    "utf8",
  ),
);

function canonicalSha256(value) {
  return `sha256:${createHash("sha256")
    .update(Buffer.from(jcs(value), "utf8"))
    .digest("hex")}`;
}

if (canonicalSha256(NORMATIVE_SCHEMA) !== NORMATIVE_SCHEMA_DIGEST) {
  throw new Error(
    "The bundled Capability IR 0.1 structural schema does not match its normative digest.",
  );
}

function exactNormativeSchema(supplied) {
  if (supplied !== undefined) {
    let digest;
    try {
      digest = canonicalSha256(supplied);
    } catch {
      digest = undefined;
    }
    if (digest !== NORMATIVE_SCHEMA_DIGEST) {
      throw new TypeError(
        "The exact normative Capability IR 0.1 structural schema is required for semantic hashing.",
      );
    }
  }
  return NORMATIVE_SCHEMA;
}

function resolveLocalRef(root, ref) {
  if (typeof ref !== "string" || !ref.startsWith("#/")) return undefined;
  let current = root;
  for (const encodedToken of ref.slice(2).split("/")) {
    const token = decodePointerToken(encodedToken);
    if (
      token === undefined ||
      !isObject(current) ||
      !Object.hasOwn(current, token)
    )
      return undefined;
    current = current[token];
  }
  return isObject(current) ? current : undefined;
}

function valueMatchesType(value, type) {
  if (type === "null") return value === null;
  if (type === "array") return Array.isArray(value);
  if (type === "object") return isObject(value);
  if (type === "integer")
    return typeof value === "number" && Number.isInteger(value);
  if (type === "number")
    return typeof value === "number" && Number.isFinite(value);
  return typeof value === type;
}

function isLeapYear(year) {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function validFullDate(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/u.exec(value);
  if (!match) return undefined;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const monthLengths = [
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  if (month < 1 || month > 12 || day < 1 || day > monthLengths[month - 1])
    return undefined;
  return { year, month, day };
}

function validFullTime(value, date) {
  const match =
    /^(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/iu.exec(value);
  if (!match) return false;
  const hour = Number(match[1]);
  const minute = Number(match[2]);
  const second = Number(match[3]);
  if (hour > 23 || minute > 59 || second > 60) return false;
  let offsetMinutes = 0;
  if (match[5].toUpperCase() !== "Z") {
    const sign = match[5][0] === "+" ? 1 : -1;
    const offsetHour = Number(match[5].slice(1, 3));
    const offsetMinute = Number(match[5].slice(4, 6));
    if (offsetHour > 23 || offsetMinute > 59) return false;
    offsetMinutes = sign * (offsetHour * 60 + offsetMinute);
  }
  if (second !== 60) return true;
  const utcMinuteOfDay =
    (((hour * 60 + minute - offsetMinutes) % 1440) + 1440) % 1440;
  if (utcMinuteOfDay !== 23 * 60 + 59) return false;
  if (!date) return true;
  const local = new Date(0);
  local.setUTCFullYear(date.year, date.month - 1, date.day);
  local.setUTCHours(hour, minute, 59, 0);
  const utc = new Date(local.getTime() - offsetMinutes * 60_000);
  return (
    (utc.getUTCMonth() === 5 && utc.getUTCDate() === 30) ||
    (utc.getUTCMonth() === 11 && utc.getUTCDate() === 31)
  );
}

const DURATION_TIME_PRODUCTION = String.raw`(?:\d+H(?:\d+M(?:\d+S)?)?|\d+M(?:\d+S)?|\d+S)`;
const DURATION_DATE_PRODUCTION = String.raw`(?:\d+Y(?:\d+M(?:\d+D)?)?|\d+M(?:\d+D)?|\d+D)`;
const DURATION_PATTERN = new RegExp(
  String.raw`^P(?:\d+W|${DURATION_DATE_PRODUCTION}(?:T${DURATION_TIME_PRODUCTION})?|T${DURATION_TIME_PRODUCTION})$`,
  "u",
);

function validDuration(value) {
  return DURATION_PATTERN.test(value);
}

const URI_PATH_PATTERN = /^[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$/u;
const URI_QUERY_OR_FRAGMENT_PATTERN = /^[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$/u;
const URI_USERINFO_PATTERN = /^[A-Za-z0-9._~!$&'()*+,;=:%-]*$/u;
const URI_REG_NAME_PATTERN = /^[A-Za-z0-9._~!$&'()*+,;=%-]*$/u;

function validUriAuthority(value) {
  const at = value.lastIndexOf("@");
  if (at !== -1) {
    if (!URI_USERINFO_PATTERN.test(value.slice(0, at))) return false;
    value = value.slice(at + 1);
  }
  if (value.startsWith("[")) {
    const close = value.indexOf("]");
    if (close === -1) return false;
    const literal = value.slice(1, close);
    const suffix = value.slice(close + 1);
    const validLiteral =
      validIpv6(literal) ||
      /^v[0-9A-F]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+$/iu.test(literal);
    return validLiteral && (suffix === "" || /^:\d*$/u.test(suffix));
  }
  if (value.includes("[") || value.includes("]")) return false;
  const colon = value.lastIndexOf(":");
  if (colon !== -1) {
    if (value.indexOf(":") !== colon || !/^\d*$/u.test(value.slice(colon + 1)))
      return false;
    value = value.slice(0, colon);
  }
  return URI_REG_NAME_PATTERN.test(value);
}

function validUri(value) {
  if (!/^[\x21-\x7e]*$/u.test(value) || /%(?![0-9A-Fa-f]{2})/u.test(value))
    return false;
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):(.*)$/u.exec(value);
  if (!scheme) return false;
  let remainder = scheme[2];
  const hash = remainder.indexOf("#");
  const fragment = hash === -1 ? undefined : remainder.slice(hash + 1);
  if (hash !== -1) remainder = remainder.slice(0, hash);
  const question = remainder.indexOf("?");
  const query = question === -1 ? undefined : remainder.slice(question + 1);
  if (question !== -1) remainder = remainder.slice(0, question);
  if (
    (query !== undefined && !URI_QUERY_OR_FRAGMENT_PATTERN.test(query)) ||
    (fragment !== undefined && !URI_QUERY_OR_FRAGMENT_PATTERN.test(fragment))
  )
    return false;
  if (remainder.startsWith("//")) {
    const slash = remainder.indexOf("/", 2);
    const authority = remainder.slice(2, slash === -1 ? undefined : slash);
    const path = slash === -1 ? "" : remainder.slice(slash);
    return validUriAuthority(authority) && URI_PATH_PATTERN.test(path);
  }
  return URI_PATH_PATTERN.test(remainder);
}

function validIpv6(value) {
  return /^[0-9A-Fa-f:.]+$/u.test(value) && isIP(value) === 6;
}

function formatMatches(value, format) {
  if (typeof value !== "string") return true;
  switch (format) {
    case "date-time": {
      const match = /^(\d{4}-\d{2}-\d{2})[Tt](.+)$/u.exec(value);
      if (!match) return false;
      const date = validFullDate(match[1]);
      return Boolean(date) && validFullTime(match[2], date);
    }
    case "date":
      return validFullDate(value) !== undefined;
    case "time":
      return validFullTime(value);
    case "duration":
      return validDuration(value);
    case "email":
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(value);
    case "hostname":
      return (
        value.length <= 253 &&
        value
          .split(".")
          .every((part) => /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/u.test(part))
      );
    case "ipv4":
      return isIP(value) === 4;
    case "ipv6":
      return validIpv6(value);
    case "uri":
      return validUri(value);
    case "uuid":
      return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(
        value,
      );
    default:
      return false;
  }
}

function evaluateWithSchema(
  instance,
  schema,
  root,
  sharedSchemas,
  applyDefaults,
  context = {
    defaultEdges: new Set(),
    position: "",
    trail: [],
  },
) {
  if (!isObject(schema))
    return { valid: false, value: instance, reason: "schema" };
  if (
    context.trail.some(
      (entry) => entry.schema === schema && entry.position === context.position,
    )
  ) {
    return { valid: true, value: instance };
  }
  const nextContext = {
    ...context,
    trail: [...context.trail, { schema, position: context.position }],
  };
  if (typeof schema.$ref === "string") {
    let target;
    let targetRoot = root;
    if (schema.$ref.startsWith("#/schemas/")) {
      const name = decodePointerToken(schema.$ref.slice("#/schemas/".length));
      target =
        name !== undefined &&
        isObject(sharedSchemas) &&
        Object.hasOwn(sharedSchemas, name) &&
        isObject(sharedSchemas[name])
          ? sharedSchemas[name]
          : undefined;
      targetRoot = target;
    } else if (schema.$ref.startsWith("#/$defs/")) {
      const name = decodePointerToken(schema.$ref.slice("#/$defs/".length));
      const definitions = isObject(root) ? root.$defs : undefined;
      target =
        name !== undefined &&
        isObject(definitions) &&
        Object.hasOwn(definitions, name) &&
        isObject(definitions[name])
          ? definitions[name]
          : undefined;
    }
    if (!isObject(target))
      return { valid: false, value: instance, reason: "ref" };
    return evaluateWithSchema(
      instance,
      target,
      targetRoot,
      sharedSchemas,
      applyDefaults,
      nextContext,
    );
  }
  let candidate = instance;
  if (schema.oneOf) {
    const matches = schema.oneOf
      .map((branch) =>
        evaluateWithSchema(
          deepClone(candidate),
          branch,
          root,
          sharedSchemas,
          applyDefaults,
          nextContext,
        ),
      )
      .filter(({ valid }) => valid);
    if (matches.length !== 1) {
      return {
        valid: false,
        value: candidate,
        reason: matches.length === 0 ? "oneOf_no_match" : "oneOf_ambiguous",
      };
    }
    candidate = matches[0].value;
  }
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((type) => valueMatchesType(candidate, type)))
      return { valid: false, value: candidate, reason: "type" };
  }
  if (schema.enum && !schema.enum.some((entry) => deepEqual(entry, candidate)))
    return { valid: false, value: candidate, reason: "enum" };
  if (Object.hasOwn(schema, "const") && !deepEqual(schema.const, candidate))
    return { valid: false, value: candidate, reason: "const" };
  if (typeof candidate === "number") {
    if (schema.minimum !== undefined && candidate < schema.minimum)
      return { valid: false, value: candidate, reason: "minimum" };
    if (schema.maximum !== undefined && candidate > schema.maximum)
      return { valid: false, value: candidate, reason: "maximum" };
    if (
      schema.exclusiveMinimum !== undefined &&
      candidate <= schema.exclusiveMinimum
    )
      return { valid: false, value: candidate, reason: "exclusiveMinimum" };
    if (
      schema.exclusiveMaximum !== undefined &&
      candidate >= schema.exclusiveMaximum
    )
      return { valid: false, value: candidate, reason: "exclusiveMaximum" };
    if (schema.multipleOf !== undefined) {
      const quotient = candidate / schema.multipleOf;
      if (
        Math.abs(quotient - Math.round(quotient)) >
        Number.EPSILON * Math.abs(quotient)
      ) {
        return { valid: false, value: candidate, reason: "multipleOf" };
      }
    }
  }
  if (typeof candidate === "string") {
    if (
      schema.minLength !== undefined &&
      Array.from(candidate).length < schema.minLength
    )
      return { valid: false, value: candidate, reason: "minLength" };
    if (
      schema.maxLength !== undefined &&
      Array.from(candidate).length > schema.maxLength
    )
      return { valid: false, value: candidate, reason: "maxLength" };
    if (
      schema.pattern !== undefined &&
      !new RegExp(schema.pattern, "u").test(candidate)
    )
      return { valid: false, value: candidate, reason: "pattern" };
    if (schema.format !== undefined && !formatMatches(candidate, schema.format))
      return { valid: false, value: candidate, reason: "format" };
  }
  if (Array.isArray(candidate)) {
    if (schema.minItems !== undefined && candidate.length < schema.minItems)
      return { valid: false, value: candidate, reason: "minItems" };
    if (schema.maxItems !== undefined && candidate.length > schema.maxItems)
      return { valid: false, value: candidate, reason: "maxItems" };
    if (
      schema.uniqueItems &&
      new Set(candidate.map(jcs)).size !== candidate.length
    )
      return { valid: false, value: candidate, reason: "uniqueItems" };
    if (schema.items) {
      const values = [];
      for (const [index, entry] of candidate.entries()) {
        const evaluated = evaluateWithSchema(
          entry,
          schema.items,
          root,
          sharedSchemas,
          applyDefaults,
          {
            ...nextContext,
            position: childPath(context.position, index),
          },
        );
        if (!evaluated.valid) return evaluated;
        values.push(evaluated.value);
      }
      candidate = values;
    }
  }
  if (isObject(candidate)) {
    const value = { ...candidate };
    for (const [key, propertySchema] of Object.entries(
      schema.properties ?? {},
    )) {
      if (Object.hasOwn(value, key)) {
        const evaluated = evaluateWithSchema(
          value[key],
          propertySchema,
          root,
          sharedSchemas,
          applyDefaults,
          {
            ...nextContext,
            position: childPath(context.position, key),
          },
        );
        if (!evaluated.valid) return evaluated;
        Object.defineProperty(value, key, {
          value: evaluated.value,
          enumerable: true,
          configurable: true,
          writable: true,
        });
      } else if (applyDefaults && Object.hasOwn(propertySchema, "default")) {
        if (context.defaultEdges.has(propertySchema)) {
          return { valid: false, value, reason: "recursive_default" };
        }
        const defaultEdges = new Set(context.defaultEdges);
        defaultEdges.add(propertySchema);
        const evaluated = evaluateWithSchema(
          deepClone(propertySchema.default),
          propertySchema,
          root,
          sharedSchemas,
          true,
          {
            ...nextContext,
            defaultEdges,
            position: childPath(context.position, key),
          },
        );
        if (!evaluated.valid) return evaluated;
        Object.defineProperty(value, key, {
          value: evaluated.value,
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }
    }
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required))
        return { valid: false, value, reason: "required" };
    }
    for (const key of Object.keys(value)) {
      if (schema.properties && Object.hasOwn(schema.properties, key)) {
      } else if (schema.additionalProperties === false) {
        return { valid: false, value, reason: "additionalProperties" };
      }
    }
    candidate = value;
  }
  return { valid: true, value: candidate };
}

function validateWithSchema(
  instance,
  schema,
  root,
  sharedSchemas,
  { applyDefaults = false } = {},
) {
  return evaluateWithSchema(
    deepClone(instance),
    schema,
    root,
    sharedSchemas,
    applyDefaults,
  ).valid;
}

/** Validate canonical output/details without applying input-only defaults. */
export function validateSchemaValue(document, binding, value) {
  const resolved = resolveSchemaReference(binding, document);
  if (!resolved) return { valid: false, reason: "schema" };
  try {
    assertPortableJson(value);
    const result = evaluateWithSchema(
      deepClone(value),
      resolved.schema,
      resolved.root,
      document.schemas,
      false,
    );
    return result.valid
      ? { valid: true }
      : { valid: false, reason: result.reason };
  } catch {
    return { valid: false, reason: "portable_json" };
  }
}

export function canonicalizeInput(document, capability, input) {
  const definition =
    typeof capability === "string"
      ? document.capabilities?.find(({ id }) => id === capability)
      : capability;
  if (!definition) return { valid: false, value: input, reason: "capability" };
  const resolved = resolveSchemaReference(definition.input, document);
  if (!resolved) return { valid: false, value: input, reason: "schema" };
  try {
    assertPortableJson(input);
    return evaluateWithSchema(
      deepClone(input),
      resolved.schema,
      resolved.root,
      document.schemas,
      true,
    );
  } catch {
    return { valid: false, value: input, reason: "portable_json" };
  }
}

function structuralErrors(instance, schema, root, path = "") {
  if (!isObject(schema)) return [];
  if (schema.$ref) {
    const target = resolveLocalRef(root, schema.$ref);
    return target
      ? structuralErrors(instance, target, root, path)
      : [{ path, message: `Unresolved schema ref ${schema.$ref}` }];
  }
  if (schema.oneOf) {
    const branches = schema.oneOf.map((branch) =>
      structuralErrors(instance, branch, root, path),
    );
    if (branches.filter((errors) => errors.length === 0).length !== 1)
      return [{ path, message: "Expected exactly one matching schema branch" }];
    return [];
  }
  if (schema.anyOf) {
    if (
      !schema.anyOf.some(
        (branch) => structuralErrors(instance, branch, root, path).length === 0,
      )
    ) {
      return [{ path, message: "Expected a matching schema branch" }];
    }
  }
  if (schema.allOf) {
    const failures = schema.allOf.flatMap((branch) =>
      structuralErrors(instance, branch, root, path),
    );
    if (failures.length > 0) return failures;
  }
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((type) => valueMatchesType(instance, type)))
      return [{ path, message: `Expected ${types.join(" or ")}` }];
  }
  if (schema.enum && !schema.enum.some((entry) => deepEqual(entry, instance)))
    return [{ path, message: "Value is not in enum" }];
  if (Object.hasOwn(schema, "const") && !deepEqual(schema.const, instance))
    return [{ path, message: "Value does not match const" }];
  const errors = [];
  if (typeof instance === "string") {
    if (
      schema.minLength !== undefined &&
      Array.from(instance).length < schema.minLength
    )
      errors.push({ path, message: "String is too short" });
    if (
      schema.maxLength !== undefined &&
      Array.from(instance).length > schema.maxLength
    )
      errors.push({ path, message: "String is too long" });
    if (
      schema.pattern !== undefined &&
      !new RegExp(schema.pattern, "u").test(instance)
    )
      errors.push({ path, message: "String does not match pattern" });
    if (schema.format !== undefined && !formatMatches(instance, schema.format))
      errors.push({ path, message: `Invalid ${schema.format}` });
  }
  if (typeof instance === "number") {
    if (schema.minimum !== undefined && instance < schema.minimum)
      errors.push({ path, message: "Number is below minimum" });
    if (
      schema.exclusiveMinimum !== undefined &&
      instance <= schema.exclusiveMinimum
    )
      errors.push({ path, message: "Number is below exclusive minimum" });
  }
  if (Array.isArray(instance)) {
    if (schema.minItems !== undefined && instance.length < schema.minItems)
      errors.push({ path, message: "Array is too short" });
    if (schema.maxItems !== undefined && instance.length > schema.maxItems)
      errors.push({ path, message: "Array is too long" });
    if (
      schema.uniqueItems &&
      new Set(instance.map(jcs)).size !== instance.length
    )
      errors.push({ path, message: "Array items are not unique" });
    if (schema.items)
      instance.forEach((entry, index) =>
        errors.push(
          ...structuralErrors(
            entry,
            schema.items,
            root,
            childPath(path, index),
          ),
        ),
      );
  }
  if (isObject(instance)) {
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(instance, required))
        errors.push({
          path: childPath(path, required),
          message: "Required property is missing",
        });
    }
    if (schema.propertyNames) {
      for (const key of Object.keys(instance))
        errors.push(
          ...structuralErrors(
            key,
            schema.propertyNames,
            root,
            childPath(path, key),
          ),
        );
    }
    for (const [key, value] of Object.entries(instance)) {
      if (schema.properties && Object.hasOwn(schema.properties, key)) {
        errors.push(
          ...structuralErrors(
            value,
            schema.properties[key],
            root,
            childPath(path, key),
          ),
        );
      } else if (schema.additionalProperties === false) {
        errors.push({
          path: childPath(path, key),
          message: "Additional property is not allowed",
        });
      } else if (isObject(schema.additionalProperties)) {
        errors.push(
          ...structuralErrors(
            value,
            schema.additionalProperties,
            root,
            childPath(path, key),
          ),
        );
      }
    }
  }
  return errors;
}

export function validateStructure(document, schema) {
  return structuralErrors(document, schema, schema).map((error) =>
    diagnostic("CAP_IR_DOCUMENT_INVALID", error.path, error.message),
  );
}

function reportObjectKeys(object, kind, path, category) {
  if (!isObject(object)) return;
  const allowed = CORE_KEYS[kind];
  const planned = PLAN_KEYS[kind] ?? new Set();
  for (const key of Object.keys(object)) {
    if (allowed.has(key)) continue;
    if (kind.endsWith("Requirement") && REQUIREMENT_SECRET_KEYS.has(key))
      continue;
    if (kind.endsWith("Projection") && PROJECTION_POLICY_KEYS.has(key))
      continue;
    const keyPath = childPath(path, key);
    if (LANGUAGE_KEYS.has(key)) {
      category.push(
        diagnostic(
          "CAP_IR_LANGUAGE_BINDING_FORBIDDEN",
          keyPath,
          "Language-specific contract data is forbidden in portable IR.",
        ),
      );
    } else if (EXECUTABLE_KEYS.has(key)) {
      category.push(
        diagnostic(
          "CAP_IR_EXECUTABLE_BINDING_FORBIDDEN",
          keyPath,
          "Executable bindings are forbidden in portable IR.",
        ),
      );
    } else if (planned.has(key)) {
      category.push(
        diagnostic(
          "CAP_IR_UNSUPPORTED_FEATURE",
          keyPath,
          "This planned field is unsupported in IR 0.1.",
        ),
      );
    } else {
      category.push(
        diagnostic("CAP_IR_UNKNOWN_FIELD", keyPath, "Unknown core IR field."),
      );
    }
  }
}

function scanSchemaUnknownKeys(schema, path, category) {
  if (!isObject(schema)) return;
  for (const key of Object.keys(schema)) {
    if (ALLOWED_SCHEMA_KEYS.has(key)) continue;
    const keyPath = childPath(path, key);
    if (LANGUAGE_KEYS.has(key)) {
      category.push(
        diagnostic(
          "CAP_IR_LANGUAGE_BINDING_FORBIDDEN",
          keyPath,
          "Language-specific schema data is forbidden.",
        ),
      );
    } else if (EXECUTABLE_KEYS.has(key)) {
      category.push(
        diagnostic(
          "CAP_IR_EXECUTABLE_BINDING_FORBIDDEN",
          keyPath,
          "Executable schema data is forbidden.",
        ),
      );
    } else {
      category.push(
        diagnostic(
          "CAP_IR_SCHEMA_PROFILE_UNSUPPORTED",
          keyPath,
          "JSON Schema keyword is outside the IR 0.1 profile.",
        ),
      );
    }
  }
  for (const [name, child] of Object.entries(schema.$defs ?? {}))
    scanSchemaUnknownKeys(
      child,
      childPath(childPath(path, "$defs"), name),
      category,
    );
  for (const [name, child] of Object.entries(schema.properties ?? {}))
    scanSchemaUnknownKeys(
      child,
      childPath(childPath(path, "properties"), name),
      category,
    );
  if (isObject(schema.items))
    scanSchemaUnknownKeys(schema.items, childPath(path, "items"), category);
  if (Array.isArray(schema.oneOf))
    schema.oneOf.forEach((branch, index) =>
      scanSchemaUnknownKeys(
        branch,
        childPath(childPath(path, "oneOf"), index),
        category,
      ),
    );
}

function scanForbiddenAndUnsupported(document, category) {
  reportObjectKeys(document, "document", "", category);
  reportObjectKeys(document?.service, "service", "/service", category);
  reportObjectKeys(
    document?.service?.contact,
    "contact",
    "/service/contact",
    category,
  );
  reportObjectKeys(document?.metadata, "metadata", "/metadata", category);
  reportObjectKeys(
    document?.metadata?.generator,
    "generator",
    "/metadata/generator",
    category,
  );
  for (const [name, schema] of Object.entries(document?.schemas ?? {}))
    scanSchemaUnknownKeys(schema, childPath("/schemas", name), category);
  for (const [index, capability] of (document?.capabilities ?? []).entries()) {
    const base = childPath("/capabilities", index);
    reportObjectKeys(capability, "capability", base, category);
    for (const field of ["input", "output"]) {
      const reference = capability?.[field];
      reportObjectKeys(
        reference,
        "schemaRef",
        childPath(base, field),
        category,
      );
      if (isObject(reference?.schema))
        scanSchemaUnknownKeys(
          reference.schema,
          `${base}/${field}/schema`,
          category,
        );
    }
    for (const [code, error] of Object.entries(capability?.errors ?? {})) {
      const errorPath = `${base}/errors/${escapePointerToken(code)}`;
      reportObjectKeys(error, "error", errorPath, category);
      reportObjectKeys(
        error?.details,
        "schemaRef",
        `${errorPath}/details`,
        category,
      );
      if (isObject(error?.details?.schema))
        scanSchemaUnknownKeys(
          error.details.schema,
          `${errorPath}/details/schema`,
          category,
        );
    }
    reportObjectKeys(capability?.access, "access", `${base}/access`, category);
    reportObjectKeys(
      capability?.access?.permissions,
      "permissions",
      `${base}/access/permissions`,
      category,
    );
    reportObjectKeys(
      capability?.access?.exposure,
      "exposure",
      `${base}/access/exposure`,
      category,
    );
    reportObjectKeys(
      capability?.effects,
      "effects",
      `${base}/effects`,
      category,
    );
    reportObjectKeys(
      capability?.effects?.retry,
      "retry",
      `${base}/effects/retry`,
      category,
    );
    if (capability?.effects?.confirmation === "conditional") {
      category.push(
        diagnostic(
          "CAP_IR_UNSUPPORTED_FEATURE",
          `${base}/effects/confirmation`,
          "Conditional confirmation is unsupported in IR 0.1.",
        ),
      );
    }
    reportObjectKeys(
      capability?.execution,
      "execution",
      `${base}/execution`,
      category,
    );
    if (
      capability?.execution?.mode !== undefined &&
      capability.execution.mode !== "inline"
    ) {
      category.push(
        diagnostic(
          "CAP_IR_UNSUPPORTED_FEATURE",
          `${base}/execution/mode`,
          "Jobs are unsupported in IR 0.1.",
        ),
      );
    }
    if (
      capability?.execution?.result !== undefined &&
      capability.execution.result !== "unary"
    ) {
      category.push(
        diagnostic(
          "CAP_IR_UNSUPPORTED_FEATURE",
          `${base}/execution/result`,
          "Streams are unsupported in IR 0.1.",
        ),
      );
    }
    reportObjectKeys(
      capability?.requirements,
      "requirements",
      `${base}/requirements`,
      category,
    );
    for (const [kind, objectKind] of [
      ["secrets", "secretRequirement"],
      ["resources", "resourceRequirement"],
      ["environment", "environmentRequirement"],
    ]) {
      for (const [requirementIndex, requirement] of (
        capability?.requirements?.[kind] ?? []
      ).entries()) {
        const requirementPath = `${base}/requirements/${kind}/${requirementIndex}`;
        reportObjectKeys(requirement, objectKind, requirementPath, category);
        for (const key of Object.keys(requirement ?? {})) {
          if (REQUIREMENT_SECRET_KEYS.has(key)) {
            category.push(
              diagnostic(
                "CAP_IR_SECRET_VALUE_FORBIDDEN",
                childPath(requirementPath, key),
                "Resolved secret, credential, token, or path is forbidden in IR.",
              ),
            );
          }
        }
      }
    }
    reportObjectKeys(capability?.limits, "limits", `${base}/limits`, category);
    reportObjectKeys(
      capability?.limits?.rateLimit,
      "rateLimit",
      `${base}/limits/rateLimit`,
      category,
    );
    reportObjectKeys(
      capability?.lifecycle,
      "lifecycle",
      `${base}/lifecycle`,
      category,
    );
    reportObjectKeys(
      capability?.interfaces,
      "interfaces",
      `${base}/interfaces`,
      category,
    );
    for (const [projection, kind] of [
      ["http", "httpProjection"],
      ["cli", "cliProjection"],
      ["mcp", "mcpProjection"],
      ["docs", "docsProjection"],
      ["sdk", "sdkProjection"],
    ]) {
      const value = capability?.interfaces?.[projection];
      const projectionPath = `${base}/interfaces/${projection}`;
      if (isObject(value)) {
        for (const key of Object.keys(value)) {
          if (PROJECTION_POLICY_KEYS.has(key)) {
            category.push(
              diagnostic(
                "CAP_IR_PROJECTION_POLICY_OVERRIDE",
                childPath(projectionPath, key),
                "Projection cannot restate canonical policy.",
              ),
            );
          }
        }
      }
      reportObjectKeys(value, kind, projectionPath, category);
      if (projection === "cli") {
        for (const [name, binding] of Object.entries(value?.bindings ?? {})) {
          reportObjectKeys(
            binding,
            "cliBinding",
            `${projectionPath}/bindings/${escapePointerToken(name)}`,
            category,
          );
        }
      }
    }
    for (const [exampleIndex, example] of (
      capability?.examples ?? []
    ).entries()) {
      const examplePath = `${base}/examples/${exampleIndex}`;
      reportObjectKeys(example, "example", examplePath, category);
      reportObjectKeys(
        example?.error,
        "exampleError",
        `${examplePath}/error`,
        category,
      );
    }
  }
  const repository = document?.metadata?.sourceRepository;
  if (typeof repository === "string") {
    let forbidden = /^(?:file:|\/|[A-Za-z]:[\\/])/u.test(repository);
    try {
      const url = new URL(repository);
      forbidden ||= Boolean(url.username || url.password);
    } catch {
      // A non-URL repository locator is checked structurally; only host paths are secret here.
    }
    if (forbidden)
      category.push(
        diagnostic(
          "CAP_IR_SECRET_VALUE_FORBIDDEN",
          "/metadata/sourceRepository",
          "Host paths and URL credentials are forbidden in metadata.",
        ),
      );
  }
}

function resolveSchemaReference(reference, document) {
  if (!isObject(reference)) return undefined;
  if (isObject(reference.schema))
    return { schema: reference.schema, root: reference.schema };
  if (
    typeof reference.$ref === "string" &&
    reference.$ref.startsWith("#/schemas/")
  ) {
    const name = decodePointerToken(reference.$ref.slice("#/schemas/".length));
    const schemas = document.schemas;
    const schema =
      name !== undefined && isObject(schemas) && Object.hasOwn(schemas, name)
        ? schemas[name]
        : undefined;
    return isObject(schema) ? { schema, root: schema } : undefined;
  }
  return undefined;
}

function schemaRefTarget(ref, root, document) {
  if (ref.startsWith("#/schemas/")) {
    const name = decodePointerToken(ref.slice("#/schemas/".length));
    const schemas = document.schemas;
    return name !== undefined &&
      isObject(schemas) &&
      Object.hasOwn(schemas, name) &&
      isObject(schemas[name])
      ? schemas[name]
      : undefined;
  }
  if (ref.startsWith("#/$defs/")) {
    const name = decodePointerToken(ref.slice("#/$defs/".length));
    const definitions = isObject(root) ? root.$defs : undefined;
    return name !== undefined &&
      isObject(definitions) &&
      Object.hasOwn(definitions, name) &&
      isObject(definitions[name])
      ? definitions[name]
      : undefined;
  }
  return undefined;
}

function validateSchemaProfile(
  schema,
  root,
  document,
  path,
  category,
  visited = new WeakSet(),
) {
  if (!isObject(schema) || visited.has(schema)) return;
  visited.add(schema);
  if (schema.$schema !== undefined && schema.$schema !== JSON_SCHEMA_DIALECT) {
    category.push(
      diagnostic(
        "CAP_IR_SCHEMA_PROFILE_UNSUPPORTED",
        childPath(path, "$schema"),
        "Only Draft 2020-12 is supported.",
      ),
    );
  }
  if (schema.$ref !== undefined) {
    if (
      typeof schema.$ref !== "string" ||
      !/^#\/(?:schemas|\$defs)\/(?:[^~/]|~0|~1)+$/u.test(schema.$ref)
    ) {
      category.push(
        diagnostic(
          "CAP_IR_SCHEMA_PROFILE_UNSUPPORTED",
          childPath(path, "$ref"),
          "Reference form is outside the IR 0.1 profile.",
        ),
      );
    } else if (!schemaRefTarget(schema.$ref, root, document)) {
      category.push(
        diagnostic(
          "CAP_IR_REF_UNRESOLVED",
          childPath(path, "$ref"),
          "Local schema reference does not resolve.",
        ),
      );
    }
    if (Object.keys(schema).length !== 1) {
      category.push(
        diagnostic(
          "CAP_IR_SCHEMA_PROFILE_UNSUPPORTED",
          childPath(path, "$ref"),
          "$ref objects cannot have siblings in IR 0.1.",
        ),
      );
    }
  }
  if (Array.isArray(schema.type)) {
    const types = new Set(schema.type);
    if (schema.type.length !== 2 || types.size !== 2 || !types.has("null")) {
      category.push(
        diagnostic(
          "CAP_IR_SCHEMA_PROFILE_UNSUPPORTED",
          childPath(path, "type"),
          "A type array must contain null and exactly one other type.",
        ),
      );
    }
  }
  if (schema.format !== undefined && !ALLOWED_FORMATS.has(schema.format)) {
    category.push(
      diagnostic(
        "CAP_IR_SCHEMA_PROFILE_UNSUPPORTED",
        childPath(path, "format"),
        "Format is outside the IR 0.1 profile.",
      ),
    );
  }
  if (Array.isArray(schema.enum)) {
    const encoded = schema.enum.map((value) => jcs(value));
    if (schema.enum.length === 0 || new Set(encoded).size !== encoded.length) {
      category.push(
        diagnostic(
          "CAP_IR_SCHEMA_PROFILE_UNSUPPORTED",
          childPath(path, "enum"),
          "enum must be non-empty with unique JSON values.",
        ),
      );
    }
  }
  if (Array.isArray(schema.oneOf) && schema.oneOf.length < 2) {
    category.push(
      diagnostic(
        "CAP_IR_SCHEMA_PROFILE_UNSUPPORTED",
        childPath(path, "oneOf"),
        "oneOf requires at least two branches.",
      ),
    );
  }
  if (
    Object.hasOwn(schema, "default") &&
    !validateWithSchema(schema.default, schema, root, document.schemas, {
      applyDefaults: true,
    })
  ) {
    category.push(
      diagnostic(
        "CAP_IR_DEFAULT_INVALID",
        childPath(path, "default"),
        "Schema default does not validate at this location.",
      ),
    );
  }
  for (const [index, example] of (schema.examples ?? []).entries()) {
    if (
      !validateWithSchema(example, schema, root, document.schemas, {
        applyDefaults: true,
      })
    ) {
      category.push(
        diagnostic(
          "CAP_IR_EXAMPLE_INVALID",
          childPath(childPath(path, "examples"), index),
          "Schema example does not validate at this location.",
        ),
      );
    }
  }
  for (const [name, child] of Object.entries(schema.$defs ?? {}))
    validateSchemaProfile(
      child,
      root,
      document,
      childPath(childPath(path, "$defs"), name),
      category,
      visited,
    );
  for (const [name, child] of Object.entries(schema.properties ?? {}))
    validateSchemaProfile(
      child,
      root,
      document,
      childPath(childPath(path, "properties"), name),
      category,
      visited,
    );
  if (isObject(schema.items))
    validateSchemaProfile(
      schema.items,
      root,
      document,
      childPath(path, "items"),
      category,
      visited,
    );
  for (const [index, branch] of (schema.oneOf ?? []).entries())
    validateSchemaProfile(
      branch,
      root,
      document,
      childPath(childPath(path, "oneOf"), index),
      category,
      visited,
    );
}

const JSON_RUNTIME_TYPES = new Set([
  "null",
  "boolean",
  "number",
  "string",
  "array",
  "object",
]);

function jsonRuntimeType(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (isObject(value)) return "object";
  if (typeof value === "number") return "number";
  return typeof value;
}

function intersectTypes(left, right) {
  return new Set([...left].filter((type) => right.has(type)));
}

function unionTypes(sets) {
  return new Set(sets.flatMap((set) => [...set]));
}

function declaredTypeSet(type) {
  if (type === undefined) return new Set(JSON_RUNTIME_TYPES);
  const values = Array.isArray(type) ? type : [type];
  return new Set(
    values.map((value) => (value === "integer" ? "number" : value)),
  );
}

function schemaGraphProfileResolved(
  schema,
  root,
  document,
  visited = new Set(),
) {
  if (!isObject(schema)) return false;
  if (visited.has(schema)) return true;
  visited.add(schema);
  if (Object.keys(schema).some((key) => !ALLOWED_SCHEMA_KEYS.has(key)))
    return false;
  if (schema.$schema !== undefined && schema.$schema !== JSON_SCHEMA_DIALECT)
    return false;
  if (schema.$ref !== undefined) {
    if (
      typeof schema.$ref !== "string" ||
      !/^#\/(?:schemas|\$defs)\/(?:[^~/]|~0|~1)+$/u.test(schema.$ref) ||
      Object.keys(schema).length !== 1
    )
      return false;
    const target = schemaRefTarget(schema.$ref, root, document);
    if (!target) return false;
    return schemaGraphProfileResolved(
      target,
      schema.$ref.startsWith("#/schemas/") ? target : root,
      document,
      visited,
    );
  }
  const jsonTypes = new Set([
    "null",
    "boolean",
    "object",
    "array",
    "number",
    "string",
    "integer",
  ]);
  if (schema.type !== undefined) {
    const values = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (values.some((value) => !jsonTypes.has(value))) return false;
    if (
      Array.isArray(schema.type) &&
      (values.length !== 2 ||
        new Set(values).size !== 2 ||
        !values.includes("null"))
    )
      return false;
  }
  if (schema.format !== undefined && !ALLOWED_FORMATS.has(schema.format))
    return false;
  if (schema.enum !== undefined) {
    if (!Array.isArray(schema.enum) || schema.enum.length === 0) return false;
    const encoded = schema.enum.map((value) => jcs(value));
    if (new Set(encoded).size !== encoded.length) return false;
  }
  if (
    schema.oneOf !== undefined &&
    (!Array.isArray(schema.oneOf) || schema.oneOf.length < 2)
  )
    return false;
  for (const child of Object.values(schema.$defs ?? {})) {
    if (!schemaGraphProfileResolved(child, root, document, visited))
      return false;
  }
  for (const child of Object.values(schema.properties ?? {})) {
    if (!schemaGraphProfileResolved(child, root, document, visited))
      return false;
  }
  if (
    schema.items !== undefined &&
    !schemaGraphProfileResolved(schema.items, root, document, visited)
  )
    return false;
  for (const branch of schema.oneOf ?? []) {
    if (!schemaGraphProfileResolved(branch, root, document, visited))
      return false;
  }
  return true;
}

function inferAdmittedJsonTypes(schema, root, document) {
  const nodes = new Map();
  let unresolved = false;
  function collect(node, ownerRoot) {
    if (!isObject(node) || nodes.has(node)) return;
    const info = {
      schema: node,
      root: ownerRoot,
      refTarget: undefined,
      branches: [],
    };
    nodes.set(node, info);
    if (typeof node.$ref === "string") {
      const target = schemaRefTarget(node.$ref, ownerRoot, document);
      if (!target) {
        unresolved = true;
      } else {
        info.refTarget = target;
        collect(
          target,
          node.$ref.startsWith("#/schemas/") ? target : ownerRoot,
        );
      }
    }
    for (const branch of node.oneOf ?? []) {
      if (isObject(branch)) {
        info.branches.push(branch);
        collect(branch, ownerRoot);
      }
    }
  }
  collect(schema, root);
  const admitted = new Map(
    [...nodes.keys()].map((node) => [node, new Set(JSON_RUNTIME_TYPES)]),
  );
  let changed;
  do {
    changed = false;
    for (const [node, info] of nodes) {
      let next = new Set(JSON_RUNTIME_TYPES);
      next = intersectTypes(next, declaredTypeSet(node.type));
      if (Object.hasOwn(node, "const"))
        next = intersectTypes(next, new Set([jsonRuntimeType(node.const)]));
      if (Array.isArray(node.enum))
        next = intersectTypes(next, new Set(node.enum.map(jsonRuntimeType)));
      if (info.refTarget)
        next = intersectTypes(next, admitted.get(info.refTarget));
      if (info.branches.length > 0) {
        next = intersectTypes(
          next,
          unionTypes(info.branches.map((branch) => admitted.get(branch))),
        );
      }
      const previous = admitted.get(node);
      if (
        next.size !== previous.size ||
        [...next].some((type) => !previous.has(type))
      ) {
        admitted.set(node, next);
        changed = true;
      }
    }
  } while (changed);
  return {
    types: admitted.get(schema) ?? new Set(JSON_RUNTIME_TYPES),
    unresolved,
  };
}

function validateSchemas(document, category) {
  for (const [name, schema] of Object.entries(document.schemas ?? {})) {
    validateSchemaProfile(
      schema,
      schema,
      document,
      childPath("/schemas", name),
      category,
    );
  }
  for (const [index, capability] of (document.capabilities ?? []).entries()) {
    const base = childPath("/capabilities", index);
    for (const field of ["input", "output"]) {
      const path = childPath(base, field);
      if (
        !isObject(capability[field]) ||
        (!isObject(capability[field].schema) &&
          typeof capability[field].$ref !== "string")
      ) {
        category.push(
          diagnostic(
            "CAP_IR_SCHEMA_REQUIRED",
            path,
            `${field} schema is required.`,
          ),
        );
        continue;
      }
      const resolved = resolveSchemaReference(capability[field], document);
      if (!resolved) {
        category.push(
          diagnostic(
            "CAP_IR_REF_UNRESOLVED",
            `${path}/$ref`,
            "Schema reference does not resolve.",
          ),
        );
        continue;
      }
      validateSchemaProfile(
        resolved.schema,
        resolved.root,
        document,
        isObject(capability[field].schema)
          ? `${path}/schema`
          : childPath(
              "/schemas",
              decodePointerToken(
                capability[field].$ref.slice("#/schemas/".length),
              ),
            ),
        category,
      );
      const profileResolved = schemaGraphProfileResolved(
        resolved.schema,
        resolved.root,
        document,
      );
      if (field === "input" && profileResolved) {
        const admitted = inferAdmittedJsonTypes(
          resolved.schema,
          resolved.root,
          document,
        );
        if (
          !admitted.unresolved &&
          (admitted.types.size !== 1 || !admitted.types.has("object"))
        ) {
          category.push(
            diagnostic(
              "CAP_IR_INPUT_ROOT_INVALID",
              path,
              "Input root type analysis must resolve to exactly object.",
            ),
          );
        }
      }
    }
    for (const [code, error] of Object.entries(capability.errors ?? {})) {
      if (error.details !== undefined) {
        const resolved = resolveSchemaReference(error.details, document);
        if (!resolved)
          category.push(
            diagnostic(
              "CAP_IR_REF_UNRESOLVED",
              `${base}/errors/${escapePointerToken(code)}/details/$ref`,
              "Error details schema reference does not resolve.",
            ),
          );
        else
          validateSchemaProfile(
            resolved.schema,
            resolved.root,
            document,
            `${base}/errors/${escapePointerToken(code)}/details/schema`,
            category,
          );
      }
    }
    const input = resolveSchemaReference(capability.input, document);
    const output = resolveSchemaReference(capability.output, document);
    for (const [exampleIndex, example] of (
      capability.examples ?? []
    ).entries()) {
      const examplePath = `${base}/examples/${exampleIndex}`;
      if (
        input &&
        !validateWithSchema(
          example.input,
          input.schema,
          input.root,
          document.schemas,
          { applyDefaults: true },
        )
      ) {
        category.push(
          diagnostic(
            "CAP_IR_EXAMPLE_INVALID",
            `${examplePath}/input`,
            "Capability example input does not validate.",
          ),
        );
      }
      if (
        Object.hasOwn(example, "output") &&
        output &&
        !validateWithSchema(
          example.output,
          output.schema,
          output.root,
          document.schemas,
        )
      ) {
        category.push(
          diagnostic(
            "CAP_IR_EXAMPLE_INVALID",
            `${examplePath}/output`,
            "Capability example output does not validate.",
          ),
        );
      }
      if (
        example.error?.code !== undefined &&
        !Object.hasOwn(capability.errors ?? {}, example.error.code)
      ) {
        category.push(
          diagnostic(
            "CAP_IR_EXAMPLE_INVALID",
            `${examplePath}/error/code`,
            "Capability example error code is undeclared.",
          ),
        );
      } else if (example.error && Object.hasOwn(example.error, "details")) {
        const declaredError = capability.errors?.[example.error.code];
        const details = resolveSchemaReference(
          declaredError?.details,
          document,
        );
        if (
          !details ||
          !validateWithSchema(
            example.error.details,
            details.schema,
            details.root,
            document.schemas,
          )
        )
          category.push(
            diagnostic(
              "CAP_IR_EXAMPLE_INVALID",
              `${examplePath}/error/details`,
              "Capability example error details do not validate against the declared error schema.",
            ),
          );
      }
    }
  }
}

function validateIdentityAndVersions(document, category) {
  if (
    document?.service?.version !== undefined &&
    !parseSemVer(document.service.version)
  ) {
    category.push(
      diagnostic(
        "CAP_IR_VERSION_INVALID",
        "/service/version",
        "Service version must be SemVer 2.0.0.",
      ),
    );
  }
  if (
    document?.metadata?.generator?.version !== undefined &&
    !parseSemVer(document.metadata.generator.version)
  ) {
    category.push(
      diagnostic(
        "CAP_IR_VERSION_INVALID",
        "/metadata/generator/version",
        "Generator version must be SemVer 2.0.0.",
      ),
    );
  }
  const seen = new Set();
  for (const [index, capability] of (document?.capabilities ?? []).entries()) {
    const base = childPath("/capabilities", index);
    if (capability.version !== undefined && !parseSemVer(capability.version)) {
      category.push(
        diagnostic(
          "CAP_IR_VERSION_INVALID",
          `${base}/version`,
          "Capability version must be SemVer 2.0.0.",
        ),
      );
    }
    if (
      capability.lifecycle?.since !== undefined &&
      !parseSemVer(capability.lifecycle.since)
    ) {
      category.push(
        diagnostic(
          "CAP_IR_VERSION_INVALID",
          `${base}/lifecycle/since`,
          "Lifecycle since must be SemVer 2.0.0.",
        ),
      );
    }
    if (seen.has(capability.id)) {
      category.push(
        diagnostic(
          "CAP_IR_DUPLICATE_CAPABILITY",
          `${base}/id`,
          "Capability IDs are unique regardless of version in IR 0.1.",
        ),
      );
    }
    seen.add(capability.id);
  }
}

function validateAccessAndEffects(document, category) {
  for (const [index, capability] of (document.capabilities ?? []).entries()) {
    const base = childPath("/capabilities", index);
    const permissions = capability.access?.permissions;
    if (isObject(permissions) && permissions.public !== true) {
      const allOf = permissions.allOf;
      const anyOf = permissions.anyOf;
      if (
        (!Array.isArray(allOf) || allOf.length === 0) &&
        (!Array.isArray(anyOf) || anyOf.length === 0)
      ) {
        category.push(
          diagnostic(
            "CAP_IR_PERMISSIONS_EMPTY",
            `${base}/access/permissions`,
            "Permissions require public: true or a non-empty allOf/anyOf rule.",
          ),
        );
      } else {
        if (Array.isArray(allOf) && allOf.length === 0)
          category.push(
            diagnostic(
              "CAP_IR_PERMISSIONS_EMPTY",
              `${base}/access/permissions/allOf`,
              "allOf cannot be empty.",
            ),
          );
        if (Array.isArray(anyOf) && anyOf.length === 0)
          category.push(
            diagnostic(
              "CAP_IR_PERMISSIONS_EMPTY",
              `${base}/access/permissions/anyOf`,
              "anyOf cannot be empty.",
            ),
          );
      }
    }
    const effects = capability.effects ?? {};
    if (effects.impact === "read" && effects.idempotency !== "intrinsic") {
      category.push(
        diagnostic(
          "CAP_IR_EFFECT_CONTRADICTION",
          `${base}/effects/idempotency`,
          "Read capabilities require intrinsic idempotency.",
        ),
      );
    }
    if (
      effects.impact === "destructive" &&
      effects.confirmation !== "required"
    ) {
      category.push(
        diagnostic(
          "CAP_IR_EFFECT_CONTRADICTION",
          `${base}/effects/confirmation`,
          "Destructive capabilities require confirmation.",
        ),
      );
    }
    if (
      effects.retry?.mode === "safe" &&
      effects.impact !== "read" &&
      effects.idempotency === "none"
    ) {
      category.push(
        diagnostic(
          "CAP_IR_EFFECT_CONTRADICTION",
          `${base}/effects/retry/mode`,
          "Safe retry requires read impact or idempotency.",
        ),
      );
    }
  }
}

function validateExecutionRequirementsLifecycle(document, category) {
  for (const [index, capability] of (document.capabilities ?? []).entries()) {
    const base = childPath("/capabilities", index);
    for (const kind of ["secrets", "resources", "environment"]) {
      const seen = new Map();
      for (const [entryIndex, entry] of (
        capability.requirements?.[kind] ?? []
      ).entries()) {
        if (seen.has(entry.name) && !deepEqual(seen.get(entry.name), entry)) {
          category.push(
            diagnostic(
              "CAP_IR_REQUIREMENT_DUPLICATE",
              `${base}/requirements/${kind}/${entryIndex}/name`,
              "Requirement name has conflicting declarations.",
            ),
          );
        } else {
          seen.set(entry.name, entry);
        }
      }
    }
    const lifecycle = capability.lifecycle ?? {};
    if (lifecycle.status !== "deprecated") {
      for (const field of ["deprecatedAt", "sunsetAt", "replacement"]) {
        if (lifecycle[field] !== undefined) {
          category.push(
            diagnostic(
              "CAP_IR_DOCUMENT_INVALID",
              `${base}/lifecycle/${field}`,
              `${field} requires deprecated status.`,
            ),
          );
        }
      }
    }
  }
}

function inputPropertyNames(capability, document, projection) {
  const resolved = resolveSchemaReference(capability.input, document);
  if (!resolved) return undefined;
  let schema = resolved.schema;
  let root = resolved.root;
  const visited = new WeakSet();
  while (schema?.$ref && !visited.has(schema)) {
    visited.add(schema);
    const target = schemaRefTarget(schema.$ref, root, document);
    if (!target) return undefined;
    if (schema.$ref.startsWith("#/schemas/")) root = target;
    schema = target;
  }
  if (
    projection === "http" &&
    (schema?.type !== "object" ||
      schema.additionalProperties !== false ||
      !isObject(schema.properties) ||
      Object.hasOwn(schema, "oneOf") ||
      Object.hasOwn(schema, "const") ||
      Object.hasOwn(schema, "enum"))
  )
    return [];
  return isObject(schema?.properties)
    ? Object.keys(schema.properties).sort(unicodeCodePointCompare)
    : [];
}

function validateProjections(document, category) {
  const collisions = { http: new Map(), cli: new Map(), mcp: new Map() };
  for (const [index, capability] of (document.capabilities ?? []).entries()) {
    const base = childPath("/capabilities", index);
    for (const projection of ["http", "cli", "mcp"]) {
      const value = capability.interfaces?.[projection];
      if (
        value?.enabled === true &&
        capability.access?.exposure?.[projection] === "disabled"
      ) {
        category.push(
          diagnostic(
            "CAP_IR_PROJECTION_WEAKENING",
            `${base}/interfaces/${projection}/enabled`,
            "Enabled projection cannot broaden disabled canonical exposure.",
          ),
        );
      }
    }
    for (const projection of ["http", "cli"]) {
      const properties = inputPropertyNames(capability, document, projection);
      const value = capability.interfaces?.[projection];
      if (value?.enabled === true && properties) {
        const bound = Object.keys(value.bindings ?? {}).sort(
          unicodeCodePointCompare,
        );
        if (!deepEqual(bound, properties)) {
          category.push(
            diagnostic(
              "CAP_IR_PROJECTION_INVALID",
              `${base}/interfaces/${projection}/bindings`,
              "Bindings must map every top-level input property exactly once.",
            ),
          );
        }
      }
    }
    const http = capability.interfaces?.http;
    if (http?.enabled === true) {
      const placeholders = [...http.path.matchAll(/\{([^{}]+)\}/gu)]
        .map((match) => match[1])
        .sort(unicodeCodePointCompare);
      const pathBindings = Object.entries(http.bindings ?? {})
        .filter(([, binding]) => binding === "path")
        .map(([name]) => name)
        .sort(unicodeCodePointCompare);
      if (!deepEqual(placeholders, pathBindings)) {
        category.push(
          diagnostic(
            "CAP_IR_PROJECTION_INVALID",
            `${base}/interfaces/http/path`,
            "Path placeholders must exactly match path bindings.",
          ),
        );
      }
      const collisionKey = `${http.method} ${http.path}`;
      if (collisions.http.has(collisionKey))
        category.push(
          diagnostic(
            "CAP_IR_PROJECTION_INVALID",
            `${base}/interfaces/http/path`,
            "HTTP projection collides with another capability.",
          ),
        );
      else collisions.http.set(collisionKey, capability.id);
    }
    const cli = capability.interfaces?.cli;
    if (cli?.enabled === true) {
      const positional = Object.values(cli.bindings ?? {})
        .filter((binding) => binding.kind === "positional")
        .map((binding) => binding.index);
      const options = Object.values(cli.bindings ?? {})
        .filter((binding) => binding.kind === "option")
        .map((binding) => binding.name);
      if (
        new Set(positional).size !== positional.length ||
        new Set(options).size !== options.length
      ) {
        category.push(
          diagnostic(
            "CAP_IR_PROJECTION_INVALID",
            `${base}/interfaces/cli/bindings`,
            "CLI binding names and positions must be unique.",
          ),
        );
      }
      const collisionKey = cli.command.join("\u0000");
      if (collisions.cli.has(collisionKey))
        category.push(
          diagnostic(
            "CAP_IR_PROJECTION_INVALID",
            `${base}/interfaces/cli/command`,
            "CLI projection collides with another capability.",
          ),
        );
      else collisions.cli.set(collisionKey, capability.id);
    }
    const mcp = capability.interfaces?.mcp;
    if (mcp?.enabled === true) {
      if (collisions.mcp.has(mcp.toolName))
        category.push(
          diagnostic(
            "CAP_IR_PROJECTION_INVALID",
            `${base}/interfaces/mcp/toolName`,
            "MCP projection collides with another capability.",
          ),
        );
      else collisions.mcp.set(mcp.toolName, capability.id);
    }
  }
}

export function validateSemantics(
  document,
  { requireNormalized = false } = {},
) {
  const categories = Array.from({ length: 9 }, () => []);
  if (document?.irVersion !== IR_VERSION) {
    categories[0].push(
      diagnostic(
        "CAP_IR_VERSION_UNSUPPORTED",
        "/irVersion",
        "Only IR version 0.1 is supported.",
      ),
    );
  }
  scanForbiddenAndUnsupported(document, categories[1]);
  validateIdentityAndVersions(document, categories[2]);
  validateSchemas(document, categories[3]);
  validateAccessAndEffects(document, categories[4]);
  validateExecutionRequirementsLifecycle(document, categories[5]);
  validateProjections(document, categories[6]);
  if (requireNormalized) {
    try {
      if (jcs(document) !== jcs(normalizeDocument(document))) {
        categories[8].push(
          diagnostic(
            "CAP_IR_NOT_NORMALIZED",
            "",
            "Document is not in canonical normalized form.",
          ),
        );
      }
    } catch {
      categories[8].push(
        diagnostic(
          "CAP_IR_NOT_NORMALIZED",
          "",
          "Document cannot be normalized as portable JSON.",
        ),
      );
    }
  }
  const ordered = categories.flatMap((category) =>
    category.sort((left, right) => {
      const pathOrder = unicodeCodePointCompare(left.path, right.path);
      return pathOrder !== 0
        ? pathOrder
        : unicodeCodePointCompare(left.code, right.code);
    }),
  );
  const seen = new Set();
  return ordered.filter(({ code, path }) => {
    const key = `${code}\u0000${path}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function validateDocument(document, schema, options = {}) {
  let semantics;
  try {
    assertPortableJson(document);
    semantics = validateSemantics(document, options);
  } catch (error) {
    return [diagnostic("CAP_IR_DOCUMENT_INVALID", "", error.message)];
  }
  const structure = validateStructure(document, schema);
  if (semantics.length > 0) return semantics;
  if (structure.length > 0) {
    const first = structure.sort((left, right) =>
      unicodeCodePointCompare(left.path, right.path),
    )[0];
    return [diagnostic("CAP_IR_DOCUMENT_INVALID", first.path, first.message)];
  }
  return [];
}

export function semanticHashDetails(source, schema) {
  const normativeSchema = exactNormativeSchema(schema);
  const normalizedDocument = normalizeDocument(source);
  const diagnostics = validateDocument(normalizedDocument, normativeSchema, {
    requireNormalized: true,
  });
  if (diagnostics.length > 0) {
    const error = new Error(
      `Cannot hash non-conforming IR: ${diagnostics[0].code} ${diagnostics[0].path}`,
    );
    error.diagnostics = diagnostics;
    throw error;
  }
  const semanticSource = deepClone(source);
  delete semanticSource.metadata;
  const normalized = normalizeDocument(semanticSource);
  const canonicalJson = jcs(normalized);
  const bytes = Buffer.from(canonicalJson, "utf8");
  return {
    normalized,
    canonicalJson,
    utf8ByteLength: bytes.length,
    hash: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
  };
}

export function semanticHash(source, schema) {
  return semanticHashDetails(source, schema).hash;
}

const META_KEY_TYPES = {
  $schema: "string",
  $ref: "string",
  title: "string",
  description: "string",
  type: ["string", "array"],
  required: "array",
  properties: "object",
  $defs: "object",
  additionalProperties: ["boolean", "object"],
  propertyNames: "object",
  items: "object",
  oneOf: "array",
  anyOf: "array",
  allOf: "array",
  enum: "array",
  pattern: "string",
  format: "string",
  minLength: "number",
  maxLength: "number",
  minItems: "number",
  maxItems: "number",
  minimum: "number",
  maximum: "number",
  exclusiveMinimum: "number",
  exclusiveMaximum: "number",
  multipleOf: "number",
  uniqueItems: "boolean",
};

function metaTypeMatches(value, expected) {
  const actual = Array.isArray(value)
    ? "array"
    : value === null
      ? "null"
      : typeof value;
  return (Array.isArray(expected) ? expected : [expected]).includes(actual);
}

export function metaValidateDraft202012Schema(schema) {
  const errors = [];
  const known = new Set([
    ...Object.keys(META_KEY_TYPES),
    "const",
    "default",
    "examples",
  ]);
  function visit(node, path) {
    if (!isObject(node)) {
      errors.push({ path, message: "Schema node must be an object" });
      return;
    }
    for (const [key, value] of Object.entries(node)) {
      if (!known.has(key))
        errors.push({
          path: childPath(path, key),
          message: `Unknown Draft 2020-12 schema keyword used by the IR meta-schema: ${key}`,
        });
      const expected = META_KEY_TYPES[key];
      if (expected && !metaTypeMatches(value, expected))
        errors.push({
          path: childPath(path, key),
          message: `Invalid keyword value type for ${key}`,
        });
    }
    if (node.$ref && !resolveLocalRef(schema, node.$ref))
      errors.push({
        path: childPath(path, "$ref"),
        message: "Unresolved local meta-schema reference",
      });
    for (const keyword of ["properties", "$defs"])
      for (const [name, child] of Object.entries(node[keyword] ?? {}))
        visit(child, childPath(childPath(path, keyword), name));
    for (const keyword of ["additionalProperties", "propertyNames", "items"])
      if (isObject(node[keyword]))
        visit(node[keyword], childPath(path, keyword));
    for (const keyword of ["oneOf", "anyOf", "allOf"])
      for (const [index, child] of (node[keyword] ?? []).entries())
        visit(child, childPath(childPath(path, keyword), index));
  }
  if (schema?.$schema !== JSON_SCHEMA_DIALECT)
    errors.push({
      path: "/$schema",
      message: "Schema must declare Draft 2020-12",
    });
  visit(schema, "");
  return errors;
}

export async function loadJson(url) {
  return JSON.parse(await readFile(url, "utf8"));
}
