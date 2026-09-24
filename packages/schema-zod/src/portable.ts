import { z } from "zod";

type JsonLiteral =
  | null
  | boolean
  | number
  | string
  | readonly JsonLiteral[]
  | { readonly [key: string]: JsonLiteral };

// Provider-local provenance. CAP-013 will consume these records inside this
// package; neither schema shape nor a public marker can confer provenance.
const defaults = new WeakMap<object, JsonLiteral>();
const lazies = new WeakMap<object, { resolve: () => z.ZodType }>();

export class SchemaAuthoringError extends Error {
  readonly severity = "error";

  constructor(
    readonly code:
      "CAP_ZOD_DEFAULT_UNREPRESENTABLE" | "CAP_ZOD_REF_UNREPRESENTABLE",
    readonly path: string,
    message: string,
  ) {
    super(message);
    this.name = "SchemaAuthoringError";
  }
}

function hasValidUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function copyLiteral(
  value: unknown,
  ancestors = new Set<object>(),
): JsonLiteral {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string" && hasValidUnicode(value)) return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "object" || ancestors.has(value)) throw new Error();
  const array = Array.isArray(value);
  if (!array && Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length) throw new Error();
  ancestors.add(value);
  try {
    const entries = Object.entries(descriptors).filter(
      ([key]) => !array || key !== "length",
    );
    if (array && entries.length !== value.length) throw new Error();
    const copy: Record<string, JsonLiteral> | JsonLiteral[] = array ? [] : {};
    for (const [index, [key, descriptor]] of entries.entries()) {
      if (
        !hasValidUnicode(key) ||
        !("value" in descriptor) ||
        !descriptor.enumerable ||
        (array && key !== String(index))
      )
        throw new Error();
      Object.defineProperty(copy, key, {
        value: copyLiteral(descriptor.value, ancestors),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return copy;
  } finally {
    ancestors.delete(value);
  }
}

/** Record a literal JSON default. Placement and schema agreement are CAP-013 checks. */
export function portableDefault<Schema extends z.ZodType>(
  schema: Schema,
  literal: NoInfer<Exclude<z.output<Schema>, undefined>> & JsonLiteral,
): z.ZodDefault<Schema> {
  let recorded: JsonLiteral;
  try {
    recorded = copyLiteral(literal);
  } catch {
    throw new SchemaAuthoringError(
      "CAP_ZOD_DEFAULT_UNREPRESENTABLE",
      "/default",
      "Supply a finite literal JSON value without accessors, cycles, or callable defaults.",
    );
  }
  // A fresh deep copy for each parse prevents one parsed default from changing
  // later inputs. The executable copy operation is provider-owned, not authored.
  const defaulted = schema.default(
    () => copyLiteral(recorded) as Exclude<z.output<Schema>, undefined>,
  );
  defaults.set(defaulted, recorded);
  return defaulted;
}

/** Resolve a local lazy schema once, preserving the first target or thrown error. */
export function portableLazy<Schema extends z.ZodType>(
  getter: () => Schema,
): z.ZodLazy<Schema> {
  let state: "unresolved" | "resolving" | "resolved" | "failed" = "unresolved";
  let target: Schema;
  let failure: unknown;
  const resolve = (): Schema => {
    if (state === "resolving") {
      throw new SchemaAuthoringError(
        "CAP_ZOD_REF_UNREPRESENTABLE",
        "/$ref",
        "A lazy getter must return its local schema without resolving itself.",
      );
    }
    if (state === "unresolved") {
      state = "resolving";
      try {
        target = getter();
        state = "resolved";
      } catch (error) {
        failure = error;
        state = "failed";
      }
    }
    if (state === "failed") throw failure;
    return target;
  };
  const lazy = z.lazy(resolve);
  // The pinned Zod accessor otherwise retains its evaluation sentinel on throws.
  Object.defineProperty(lazy._zod, "innerType", {
    configurable: true,
    get: resolve,
  });
  lazies.set(lazy, { resolve });
  return lazy;
}
