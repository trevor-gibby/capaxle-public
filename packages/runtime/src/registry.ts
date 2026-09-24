import "@capaxle/core";
import { types } from "node:util";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import {
  capabilitySemanticHash,
  validateCapabilityDocument,
} from "@capaxle/ir";
import type { JsonValue } from "@capaxle/ir";
import type {
  RuntimeRegistry,
  RuntimeRegistryOptions,
  RuntimeDocument,
  RuntimeCapability,
  RuntimeValidators,
} from "./types.js";

export class RuntimeConfigurationError extends Error {
  constructor(readonly code: string) {
    super("Invalid runtime configuration.");
    this.name = "RuntimeConfigurationError";
  }
}

/** Inspect carriers without invoking getters or proxy reflection traps. */
export function ownData(
  value: unknown,
  allowed?: readonly string[],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || types.isProxy(value))
    throw new Error("carrier");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    throw new Error("prototype");
  const output: Record<string, unknown> = Object.create(null) as Record<
    string,
    unknown
  >;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || (allowed && !allowed.includes(key)))
      throw new Error("key");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
      throw new Error("descriptor");
    output[key] = descriptor.value as unknown;
  }
  return output;
}

export function copyJson(
  value: unknown,
  active = new Set<object>(),
): JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string")
    return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (
    typeof value !== "object" ||
    value === null ||
    types.isProxy(value) ||
    active.has(value)
  )
    throw new Error("json");
  active.add(value);
  try {
    if (Array.isArray(value)) {
      if (
        Object.getPrototypeOf(value) !== Array.prototype ||
        Reflect.ownKeys(value).length !== value.length + 1
      )
        throw new Error("array");
      const result: JsonValue[] = [];
      for (let index = 0; index < value.length; index++) {
        const descriptor = Object.getOwnPropertyDescriptor(
          value,
          String(index),
        );
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
          throw new Error("array");
        result.push(copyJson(descriptor.value, active));
      }
      return Object.freeze(result);
    }
    const result: Record<string, JsonValue> = {};
    for (const [key, item] of Object.entries(ownData(value)))
      Object.defineProperty(result, key, {
        value: copyJson(item, active),
        enumerable: true,
      });
    return Object.freeze(result);
  } finally {
    active.delete(value);
  }
}

interface RuntimeEntry {
  readonly capability: RuntimeCapability;
  readonly validators: RuntimeValidators;
  readonly handler: (input: unknown, context: unknown) => unknown;
}
interface RegistryState {
  readonly document: RuntimeDocument;
  readonly entries: ReadonlyMap<string, RuntimeEntry>;
}
const registries = new WeakMap<object, RegistryState>();
const requirePrivate = createRequire(import.meta.url);
const bindingModulePath = fileURLToPath(
  new URL("./internal-bindings.js", import.meta.resolve("@capaxle/core")),
);
export function registryState(registry: unknown): RegistryState | undefined {
  return typeof registry === "object" && registry !== null
    ? registries.get(registry)
    : undefined;
}

export function createRuntimeRegistry(
  options: RuntimeRegistryOptions,
): RuntimeRegistry {
  try {
    const carrier = ownData(options, [
      "document",
      "irHash",
      "bindings",
      "validators",
    ]);
    const document = copyJson(carrier.document) as RuntimeDocument;
    if (
      validateCapabilityDocument(document, { requireNormalized: true }).length
    )
      throw new RuntimeConfigurationError("CAP_RUNTIME_IR_INVALID");
    if (
      typeof carrier.irHash !== "string" ||
      capabilitySemanticHash(document) !== carrier.irHash
    )
      throw new RuntimeConfigurationError("CAP_RUNTIME_IR_HASH_MISMATCH");
    const bindings = carrier.bindings as RuntimeRegistryOptions["bindings"];
    const validators =
      carrier.validators as RuntimeRegistryOptions["validators"];
    // Private sibling module shares core's process-local identity WeakMaps.
    // It has no public package export and never enters portable IR.
    const query = requirePrivate(bindingModulePath) as {
      resolveBindingHandle: (
        value: unknown,
      ) =>
        | { id: string; version: string; irHash: string; handler: unknown }
        | undefined;
    };
    const entries = new Map<string, RuntimeEntry>();
    const facadePaths = new Set<string>();
    const facadeLeaves = new Set<string>();
    const reservedFacadeSegments = new Set([
      "__proto__",
      "prototype",
      "constructor",
      "then",
      "toJSON",
      "toString",
      "valueOf",
      "inspect",
    ]);
    for (const capability of document.capabilities) {
      if (entries.has(capability.id))
        throw new RuntimeConfigurationError("CAP_RUNTIME_DUPLICATE_CAPABILITY");
      if (capability.access.exposure.internal !== "disabled") {
        const segments = capability.id.split(".");
        if (
          segments.some(
            (segment) =>
              segment.length === 0 || reservedFacadeSegments.has(segment),
          )
        )
          throw new RuntimeConfigurationError(
            "CAP_INTERNAL_FACADE_NAME_INVALID",
          );
        let path = "";
        for (let index = 0; index < segments.length; index++) {
          path = path ? `${path}.${segments[index]}` : segments[index]!;
          if (facadeLeaves.has(path))
            throw new RuntimeConfigurationError(
              "CAP_INTERNAL_FACADE_NAME_COLLISION",
            );
          facadePaths.add(path);
          if (index === segments.length - 1) {
            if (
              facadeLeaves.has(path) ||
              [...facadePaths].some((item) => item.startsWith(`${path}.`))
            )
              throw new RuntimeConfigurationError(
                "CAP_INTERNAL_FACADE_NAME_COLLISION",
              );
            facadeLeaves.add(path);
          }
        }
      }
      const binding = bindings.get(capability.id);
      if (!binding)
        throw new RuntimeConfigurationError("CAP_RUNTIME_BINDING_MISSING");
      const bound = ownData(binding, ["id", "version", "irHash", "binding"]);
      const resolved = query?.resolveBindingHandle?.(bound.binding);
      if (
        !resolved ||
        typeof resolved.handler !== "function" ||
        bound.id !== capability.id ||
        resolved.id !== capability.id ||
        bound.version !== capability.version ||
        resolved.version !== capability.version ||
        bound.irHash !== carrier.irHash ||
        resolved.irHash !== carrier.irHash
      )
        throw new RuntimeConfigurationError("CAP_RUNTIME_BINDING_MISMATCH");
      const validator = validators.get(capability.id);
      if (
        !validator ||
        typeof validator.input?.validate !== "function" ||
        typeof validator.output?.validate !== "function"
      )
        throw new RuntimeConfigurationError("CAP_RUNTIME_VALIDATOR_MISSING");
      const errors = new Map(validator.errors);
      for (const [code, declaration] of Object.entries(capability.errors))
        if (
          declaration.details &&
          typeof errors.get(code)?.validate !== "function"
        )
          throw new RuntimeConfigurationError("CAP_RUNTIME_VALIDATOR_MISSING");
      if (
        Object.keys(capability.limits).some((key) => key !== "rateLimit") ||
        capability.requirements.resources.length ||
        capability.requirements.environment.length
      )
        throw new RuntimeConfigurationError("CAP_RUNTIME_PROVIDER_UNAVAILABLE");
      entries.set(capability.id, {
        capability,
        handler: resolved.handler as RuntimeEntry["handler"],
        validators: {
          input: { validate: validator.input.validate.bind(validator.input) },
          output: {
            validate: validator.output.validate.bind(validator.output),
          },
          errors: new Map(
            [...errors].map(([code, value]) => [
              code,
              { validate: value.validate.bind(value) },
            ]),
          ),
        },
      });
    }
    if (bindings.size !== entries.size || validators.size !== entries.size)
      throw new RuntimeConfigurationError("CAP_RUNTIME_BINDING_MISMATCH");
    const registry = Object.freeze({
      irHash: carrier.irHash,
      capabilities: Object.freeze(
        [...entries.values()].map(({ capability }) =>
          Object.freeze({ id: capability.id, version: capability.version }),
        ),
      ),
    }) as RuntimeRegistry;
    registries.set(registry, { document, entries });
    return registry;
  } catch (error) {
    if (error instanceof RuntimeConfigurationError) throw error;
    throw new RuntimeConfigurationError("CAP_RUNTIME_CONFIGURATION_INVALID");
  }
}
