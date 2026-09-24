import type {
  AuthorSchema,
  Capability,
  CapabilitySchema,
  CapabilityDefinition,
  ErrorDeclarations,
  SharedSchema,
} from "./types.js";
import {
  isBoundDescriptor,
  registerDescriptorBinding,
} from "./internal-bindings.js";

export interface AuthoringDiagnostic {
  readonly code:
    | "CAP_AUTHORING_FIELD_REQUIRED"
    | "CAP_AUTHORING_FIELD_INVALID"
    | "CAP_AUTHORING_FIELD_UNSUPPORTED"
    | "CAP_AUTHORING_POLICY_INVALID"
    | "CAP_SCHEMA_NAME_INVALID";
  readonly severity: "error";
  readonly path: string;
  readonly message: string;
}

export class CapabilityDefinitionError extends Error {
  readonly diagnostics: readonly AuthoringDiagnostic[];

  constructor(diagnostics: readonly AuthoringDiagnostic[]) {
    super(
      "Invalid capability definition; inspect diagnostics for fields to correct.",
    );
    this.name = "CapabilityDefinitionError";
    this.diagnostics = Object.freeze(
      diagnostics.map((diagnostic) => Object.freeze({ ...diagnostic })),
    );
  }
}

const sharedSchemas = new WeakSet<object>();
const sharedSchemaHas = sharedSchemas.has.bind(sharedSchemas);
const sharedSchemaAdd = sharedSchemas.add.bind(sharedSchemas);
interface SharedSchemaOccurrence {
  readonly path: string;
  readonly schema: SharedSchema<string, AuthorSchema>;
}
interface AuthoringPresence {
  readonly effects: {
    readonly idempotency: boolean;
    readonly confirmation: boolean;
    readonly retry: boolean;
  };
  readonly errorRetryable: readonly string[];
  readonly secretOptional: readonly number[];
  readonly rateLimitCost: boolean;
  readonly sharedSchemas: readonly SharedSchemaOccurrence[];
}
const authoringPresenceKey = Symbol.for(
  "@capaxle/core/authoring-presence-registry@1",
);
const authoringPresenceGlobal = globalThis as typeof globalThis & {
  [authoringPresenceKey]?: {
    readonly get: (value: unknown) => AuthoringPresence | undefined;
  };
};
const authoringPresence = new WeakMap<object, AuthoringPresence>();
const authoringPresenceGet = authoringPresence.get.bind(authoringPresence);
const authoringPresenceSet = authoringPresence.set.bind(authoringPresence);
const statuses = new Set([
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
]);
const topFields = new Set([
  "id",
  "version",
  "description",
  "tags",
  "authentication",
  "exposure",
  "requirements",
  "limits",
  "summary",
  "input",
  "output",
  "permissions",
  "effects",
  "errors",
  "examples",
  "handler",
]);
const pointer = (path: string, key: string) =>
  `${path}/${key.replaceAll("~", "~0").replaceAll("/", "~1")}`;

/** True only for a descriptor issued by this loaded core module. */
export function isCapability(value: unknown): value is Capability {
  return isBoundDescriptor(value);
}

const isSharedSchema = (
  value: unknown,
): value is SharedSchema<string, AuthorSchema> =>
  typeof value === "object" && value !== null && sharedSchemaHas(value);

const descriptorSchemaAt = (descriptor: Capability, path: string): unknown => {
  if (path === "/input") return descriptor.input;
  if (path === "/output") return descriptor.output;
  const match = /^\/errors\/([^/]+)\/details$/u.exec(path);
  if (!match) return undefined;
  const code = match[1]!.replaceAll("~1", "/").replaceAll("~0", "~");
  return descriptor.errors[code]?.details;
};

const authoringPresenceQuery = Object.freeze({
  get(value: unknown): AuthoringPresence | undefined {
    if (!isCapability(value)) return undefined;
    const presence = authoringPresenceGet(value);
    if (
      !presence ||
      presence.sharedSchemas.some(
        ({ path, schema }) =>
          !isSharedSchema(schema) || descriptorSchemaAt(value, path) !== schema,
      )
    )
      return undefined;
    return presence;
  },
});
if (
  Object.getOwnPropertyDescriptor(authoringPresenceGlobal, authoringPresenceKey)
) {
  const error = new Error(
    "The process-local core authoring authenticity query was already initialized.",
  );
  error.name = "CapabilityAuthoringIntegrityError";
  Object.defineProperty(error, "code", {
    enumerable: true,
    value: "CAP_CORE_AUTHORING_QUERY_CONFLICT",
  });
  throw error;
}
Object.defineProperty(authoringPresenceGlobal, authoringPresenceKey, {
  configurable: false,
  enumerable: false,
  writable: false,
  value: authoringPresenceQuery,
});

const validUnicodeScalarString = (value: unknown): value is string => {
  if (typeof value !== "string" || value.length === 0) return false;
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
};

/** Name one whole capability schema without inspecting its provider-owned value. */
export function defineSharedSchema<
  const Name extends string,
  Schema extends AuthorSchema,
>(name: Name, authorSchema: Schema): SharedSchema<Name, Schema> {
  const diagnostics: AuthoringDiagnostic[] = [];
  if (!validUnicodeScalarString(name))
    diagnostics.push({
      code: "CAP_SCHEMA_NAME_INVALID",
      severity: "error",
      path: "/name",
      message:
        "Supply a nonempty shared-schema name containing only Unicode scalar values.",
    });
  if (
    ((typeof authorSchema !== "object" || authorSchema === null) &&
      typeof authorSchema !== "function") ||
    isSharedSchema(authorSchema)
  )
    diagnostics.push({
      code: "CAP_AUTHORING_FIELD_INVALID",
      severity: "error",
      path: "/authorSchema",
      message:
        "Supply one provider-owned author schema, not another shared-schema wrapper.",
    });
  if (diagnostics.length) throw new CapabilityDefinitionError(diagnostics);

  const wrapper = Object.assign(Object.create(null), { name, authorSchema });
  Object.freeze(wrapper);
  sharedSchemaAdd(wrapper);
  return wrapper as SharedSchema<Name, Schema>;
}

/** Validate author metadata and retain the handler privately, without invoking it. */
export function defineCapability<
  Input extends CapabilitySchema,
  Output extends CapabilitySchema,
  const Errors extends ErrorDeclarations = Record<never, never>,
  Services = Readonly<Record<string, never>>,
>(
  definition: CapabilityDefinition<Input, Output, Errors, Services>,
): Capability<Input, Output, Errors> {
  const diagnostics: AuthoringDiagnostic[] = [];
  const sharedSchemaOccurrences: SharedSchemaOccurrence[] = [];
  const report = (
    code: AuthoringDiagnostic["code"],
    path: string,
    message: string,
  ) => diagnostics.push({ code, severity: "error", path, message });
  const invalid = (path: string, message: string) =>
    report("CAP_AUTHORING_FIELD_INVALID", path, message);
  const required = (path: string, message: string) =>
    report("CAP_AUTHORING_FIELD_REQUIRED", path, message);
  const record = (value: unknown, path: string, allowed?: Set<string>) => {
    const result: Record<string, unknown> = Object.create(null);
    try {
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        invalid(path, "Supply an object with own data properties.");
        return result;
      }
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        invalid(path, "Supply a plain object with own data properties.");
        return result;
      }
      if (Object.getOwnPropertySymbols(value).length)
        invalid(path, "Symbol metadata is unsupported.");
      for (const [key, descriptor] of Object.entries(
        Object.getOwnPropertyDescriptors(value),
      )) {
        const at = pointer(path, key);
        if (!descriptor.enumerable || !("value" in descriptor)) {
          invalid(
            at,
            "Use an enumerable data property; metadata accessors are unsupported.",
          );
        } else if (allowed && !allowed.has(key)) {
          report(
            "CAP_AUTHORING_FIELD_UNSUPPORTED",
            at,
            "This field is outside the implemented authoring subset.",
          );
        } else {
          result[key] = descriptor.value;
        }
      }
    } catch {
      invalid(path, "Capability metadata could not be inspected safely.");
    }
    return result;
  };
  const text = (value: unknown, path: string) => {
    if (typeof value !== "string" || value.trim().length === 0)
      invalid(path, "Supply a nonempty string.");
  };
  const choice = (value: unknown, path: string, values: readonly string[]) => {
    if (!values.includes(value as string))
      invalid(path, `Choose one of: ${values.join(", ")}.`);
  };
  const list = (value: unknown, path: string, nonempty: boolean) => {
    const copy: string[] = [];
    try {
      if (!Array.isArray(value) || (nonempty && !value.length)) {
        invalid(path, "Supply a nonempty array of permission strings.");
        return Object.freeze(copy);
      }
      const properties = Object.getOwnPropertyDescriptors(value);
      if (
        Object.getOwnPropertySymbols(value).length ||
        Object.keys(properties).length !== value.length + 1
      )
        invalid(path, "Supply a dense array without extra properties.");
      for (let index = 0; index < value.length; index++) {
        const property = properties[String(index)];
        if (!property || !("value" in property) || !property.enumerable) {
          invalid(
            pointer(path, String(index)),
            "Supply a data element without holes or accessors.",
          );
          continue;
        }
        text(property.value, pointer(path, String(index)));
        copy.push(property.value as string);
      }
    } catch {
      invalid(path, "The array could not be inspected safely.");
    }
    return Object.freeze(copy);
  };
  const schema = (value: unknown, path: string) => {
    if (isSharedSchema(value)) {
      sharedSchemaOccurrences.push(Object.freeze({ path, schema: value }));
      return;
    }
    if (
      (typeof value !== "object" || value === null) &&
      typeof value !== "function"
    )
      invalid(
        path,
        "Supply an author schema; provider portability checks run during compilation.",
      );
  };

  const activeJson = new WeakSet<object>();
  const json = (value: unknown, path: string): unknown => {
    if (
      value === null ||
      typeof value === "string" ||
      typeof value === "boolean" ||
      (typeof value === "number" && Number.isFinite(value))
    )
      return value;
    if (typeof value !== "object") {
      invalid(path, "Supply a finite, strictly serializable JSON value.");
      return undefined;
    }
    if (activeJson.has(value)) {
      invalid(path, "Cyclic example data cannot be serialized as JSON.");
      return undefined;
    }
    activeJson.add(value);
    try {
      const descriptors = Object.getOwnPropertyDescriptors(value);
      if (Object.getOwnPropertySymbols(value).length)
        invalid(path, "JSON example data cannot contain symbol properties.");
      if (Array.isArray(value)) {
        const copy: unknown[] = [];
        if (Object.keys(descriptors).length !== value.length + 1) {
          invalid(path, "Supply a dense JSON array without extra properties.");
          return Object.freeze(copy);
        }
        for (let index = 0; index < value.length; index++) {
          const at = pointer(path, String(index));
          const property = descriptors[String(index)];
          if (!property || !property.enumerable || !("value" in property)) {
            invalid(
              at,
              "Supply an enumerable JSON data element without holes or accessors.",
            );
            continue;
          }
          copy.push(json(property.value, at));
        }
        return Object.freeze(copy);
      }
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        invalid(path, "Supply a plain JSON object.");
        return undefined;
      }
      const copy: Record<string, unknown> = Object.create(null);
      for (const [key, property] of Object.entries(descriptors)) {
        const at = pointer(path, key);
        if (!property.enumerable || !("value" in property)) {
          invalid(
            at,
            "Supply an enumerable JSON data property without accessors.",
          );
          continue;
        }
        copy[key] = json(property.value, at);
      }
      return Object.freeze(copy);
    } catch {
      invalid(path, "Example JSON data could not be inspected safely.");
      return undefined;
    } finally {
      activeJson.delete(value);
    }
  };

  const source = record(definition, "", topFields);
  for (const key of [
    "summary",
    "input",
    "output",
    "permissions",
    "effects",
    "handler",
  ])
    if (!(key in source)) required(`/${key}`, `Declare ${key} explicitly.`);
  if ("summary" in source) text(source.summary, "/summary");
  for (const key of ["input", "output"])
    if (key in source) schema(source[key], `/${key}`);
  if ("handler" in source && typeof source.handler !== "function")
    invalid("/handler", "Supply a handler function.");
  for (const key of ["id", "version", "description"])
    if (key in source) text(source[key], `/${key}`);
  if ("authentication" in source)
    choice(source.authentication, "/authentication", [
      "public",
      "optional",
      "required",
    ]);

  if ("exposure" in source) {
    const exposure = record(
      source.exposure,
      "/exposure",
      new Set(["http", "cli", "mcp", "internal"]),
    );
    for (const [surface, value] of Object.entries(exposure))
      choice(value, `/exposure/${surface}`, [
        "disabled",
        "private",
        "authenticated",
        "public",
      ]);
    source.exposure = Object.freeze(exposure);
  }

  const explicitSecretOptional: number[] = [];
  let explicitRateLimitCost = false;
  if ("requirements" in source) {
    const requirements = record(
      source.requirements,
      "/requirements",
      new Set(["secrets"]),
    );
    if (!("secrets" in requirements))
      required(
        "/requirements/secrets",
        "Declare the logical secret requirement array.",
      );
    const secrets: Readonly<Record<string, unknown>>[] = [];
    try {
      const raw = requirements.secrets;
      if (!Array.isArray(raw))
        invalid(
          "/requirements/secrets",
          "Supply a dense secret requirement array.",
        );
      else {
        const properties = Object.getOwnPropertyDescriptors(raw);
        if (
          Object.getOwnPropertySymbols(raw).length ||
          Object.keys(properties).length !== raw.length + 1
        )
          invalid(
            "/requirements/secrets",
            "Supply a dense array without extra properties.",
          );
        for (let index = 0; index < raw.length; index++) {
          const path = `/requirements/secrets/${index}`;
          const property = properties[String(index)];
          if (!property || !("value" in property) || !property.enumerable) {
            invalid(path, "Supply a data element without holes or accessors.");
            continue;
          }
          const secret = record(
            property.value,
            path,
            new Set(["name", "optional", "description"]),
          );
          text(secret.name, `${path}/name`);
          if (!("optional" in secret)) secret.optional = false;
          else if (typeof secret.optional !== "boolean")
            invalid(`${path}/optional`, "Supply a boolean.");
          else explicitSecretOptional.push(index);
          if ("description" in secret)
            text(secret.description, `${path}/description`);
          secrets.push(Object.freeze(secret));
        }
      }
    } catch {
      invalid(
        "/requirements/secrets",
        "The array could not be inspected safely.",
      );
    }
    requirements.secrets = Object.freeze(secrets);
    source.requirements = Object.freeze(requirements);
  }
  if ("limits" in source) {
    const limits = record(source.limits, "/limits", new Set(["rateLimit"]));
    if ("rateLimit" in limits) {
      const path = "/limits/rateLimit";
      const rateLimit = record(
        limits.rateLimit,
        path,
        new Set(["policy", "cost", "description"]),
      );
      text(rateLimit.policy, `${path}/policy`);
      explicitRateLimitCost = "cost" in rateLimit;
      if (!explicitRateLimitCost) rateLimit.cost = 1;
      else if (
        !Number.isSafeInteger(rateLimit.cost) ||
        (rateLimit.cost as number) <= 0
      )
        invalid(
          `${path}/cost`,
          "Supply a positive safe integer rate-limit cost.",
        );
      if ("description" in rateLimit)
        text(rateLimit.description, `${path}/description`);
      limits.rateLimit = Object.freeze(rateLimit);
    }
    source.limits = Object.freeze(limits);
  }

  let permissions: unknown = source.permissions;
  if ("permissions" in source && permissions !== "public") {
    const clauses = record(
      permissions,
      "/permissions",
      new Set(["allOf", "anyOf"]),
    );
    if (!("allOf" in clauses) && !("anyOf" in clauses))
      required(
        "/permissions",
        'Declare "public" or a nonempty allOf/anyOf permission clause.',
      );
    for (const key of Object.keys(clauses))
      clauses[key] = list(clauses[key], `/permissions/${key}`, true);
    permissions = Object.freeze(clauses);
  }

  const effects = record(
    source.effects,
    "/effects",
    new Set(["impact", "idempotency", "confirmation", "retry"]),
  );
  const effectPresence = Object.freeze({
    idempotency: "idempotency" in effects,
    confirmation: "confirmation" in effects,
    retry: "retry" in effects,
  });
  if (!("impact" in effects))
    required(
      "/effects/impact",
      "Declare read, write, or destructive impact explicitly.",
    );
  else
    choice(effects.impact, "/effects/impact", ["read", "write", "destructive"]);
  if (!("idempotency" in effects)) {
    if (effects.impact === "read") effects.idempotency = "intrinsic";
    else
      required(
        "/effects/idempotency",
        "Declare none, intrinsic, or key for a non-read capability.",
      );
  } else
    choice(effects.idempotency, "/effects/idempotency", [
      "none",
      "intrinsic",
      "key",
    ]);
  if (!("confirmation" in effects))
    effects.confirmation =
      effects.impact === "destructive" ? "required" : "none";
  else
    choice(effects.confirmation, "/effects/confirmation", ["none", "required"]);
  const retry =
    "retry" in effects
      ? record(effects.retry, "/effects/retry", new Set(["mode"]))
      : { mode: "never" };
  choice(retry.mode, "/effects/retry/mode", ["never", "safe"]);
  effects.retry = Object.freeze(retry);
  if (effects.impact === "read" && effects.idempotency !== "intrinsic")
    report(
      "CAP_AUTHORING_POLICY_INVALID",
      "/effects/idempotency",
      "Read capabilities require intrinsic idempotency.",
    );
  if (effects.impact === "destructive" && effects.confirmation !== "required")
    report(
      "CAP_AUTHORING_POLICY_INVALID",
      "/effects/confirmation",
      "Destructive capabilities require confirmation.",
    );
  if (effects.idempotency === "none" && retry.mode === "safe")
    report(
      "CAP_AUTHORING_POLICY_INVALID",
      "/effects/retry/mode",
      "A non-idempotent capability cannot promise safe retry.",
    );

  const errors =
    "errors" in source
      ? record(source.errors, "/errors")
      : (Object.create(null) as Record<string, unknown>);
  const explicitErrorRetryable = new Set<string>();
  for (const [code, value] of Object.entries(errors)) {
    const path = pointer("/errors", code);
    if (!/^[A-Z][A-Z0-9_]*$/.test(code) || code.startsWith("CAP_"))
      invalid(
        path,
        "Use an uppercase domain error code without the reserved CAP_ prefix.",
      );
    const error = record(
      value,
      path,
      new Set(["status", "message", "details", "retryable"]),
    );
    if (!statuses.has(error.status as string))
      invalid(`${path}/status`, "Supply a canonical error status.");
    text(error.message, `${path}/message`);
    if ("details" in error) schema(error.details, `${path}/details`);
    if (!("retryable" in error)) error.retryable = false;
    else if (typeof error.retryable !== "boolean")
      invalid(`${path}/retryable`, "Supply a boolean.");
    else explicitErrorRetryable.add(code);
    errors[code] = Object.freeze(error);
  }
  const tags = "tags" in source ? list(source.tags, "/tags", false) : undefined;
  if ("examples" in source) {
    const examples: Readonly<Record<string, unknown>>[] = [];
    const raw = source.examples;
    try {
      if (!Array.isArray(raw))
        invalid("/examples", "Supply a dense capability example array.");
      else {
        const properties = Object.getOwnPropertyDescriptors(raw);
        const dense =
          !Object.getOwnPropertySymbols(raw).length &&
          Object.keys(properties).length === raw.length + 1;
        if (!dense)
          invalid(
            "/examples",
            "Supply a dense array without extra properties.",
          );
        if (dense)
          for (let index = 0; index < raw.length; index++) {
            const path = `/examples/${index}`;
            const property = properties[String(index)];
            if (!property || !property.enumerable || !("value" in property)) {
              invalid(
                path,
                "Supply a data element without holes or accessors.",
              );
              continue;
            }
            const example = record(
              property.value,
              path,
              new Set(["name", "description", "input", "output", "error"]),
            );
            if (!("name" in example))
              required(`${path}/name`, "Name the example.");
            else text(example.name, `${path}/name`);
            if ("description" in example)
              text(example.description, `${path}/description`);
            if (!("input" in example))
              required(`${path}/input`, "Supply example input as JSON data.");
            else example.input = json(example.input, `${path}/input`);
            if ("output" in example)
              example.output = json(example.output, `${path}/output`);
            if ("error" in example) {
              const errorPath = `${path}/error`;
              const error = record(
                example.error,
                errorPath,
                new Set(["code", "details"]),
              );
              if (!("code" in error))
                required(`${errorPath}/code`, "Name the declared error code.");
              else text(error.code, `${errorPath}/code`);
              if ("details" in error)
                error.details = json(error.details, `${errorPath}/details`);
              example.error = Object.freeze(error);
            }
            examples.push(Object.freeze(example));
          }
      }
    } catch {
      invalid("/examples", "The example array could not be inspected safely.");
    }
    source.examples = Object.freeze(examples);
  }
  if (diagnostics.length) {
    diagnostics.sort((a, b) =>
      a.path < b.path ? -1 : a.path > b.path ? 1 : a.code < b.code ? -1 : 1,
    );
    throw new CapabilityDefinitionError(diagnostics);
  }
  const descriptor = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of Object.entries(source))
    if (key !== "handler") descriptor[key] = value;
  descriptor.permissions = permissions;
  descriptor.effects = Object.freeze(effects);
  descriptor.errors = Object.freeze(errors);
  if (tags) descriptor.tags = tags;
  authoringPresenceSet(
    descriptor,
    Object.freeze({
      effects: effectPresence,
      errorRetryable: Object.freeze([...explicitErrorRetryable]),
      secretOptional: Object.freeze(explicitSecretOptional),
      rateLimitCost: explicitRateLimitCost,
      sharedSchemas: Object.freeze([...sharedSchemaOccurrences]),
    }),
  );
  Object.freeze(descriptor);
  registerDescriptorBinding(descriptor, source.handler);
  return descriptor as unknown as Capability<Input, Output, Errors>;
}
