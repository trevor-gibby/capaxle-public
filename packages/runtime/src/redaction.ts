import { types } from "node:util";
import type { JsonValue } from "@capaxle/ir";
import { ownData, RuntimeConfigurationError } from "./registry.js";

const MARKER = "[REDACTED]";
const MAX_ATOMS = 256;
const MAX_PATTERN_UNITS = 65_536;
const MAX_NODES = 10_000;
const MAX_DEPTH = 64;
const MAX_TEXT_UNITS = 1_048_576;
const MAX_SCAN_WORK = 16_777_216;
class RedactionBoundsError extends Error {}
type Primitive = number | boolean | null;
export interface RedactionState {
  readonly strings: Set<string>;
  readonly primitives: Set<Primitive>;
  patternUnits: number;
  failed: boolean;
}
export function createRedactionState(): RedactionState {
  return {
    strings: new Set(),
    primitives: new Set(),
    patternUnits: 0,
    failed: false,
  };
}
export function addSensitiveString(state: RedactionState, value: string): void {
  if (state.strings.has(value)) return;
  if (
    state.strings.size + state.primitives.size >= MAX_ATOMS ||
    state.patternUnits + value.length > MAX_PATTERN_UNITS
  ) {
    state.failed = true;
    throw new RedactionBoundsError("redaction_bounds");
  }
  state.strings.add(value);
  state.patternUnits += value.length;
}
function addSensitivePrimitive(state: RedactionState, value: Primitive): void {
  if (!state.primitives.has(value)) {
    if (state.strings.size + state.primitives.size >= MAX_ATOMS) {
      state.failed = true;
      throw new RedactionBoundsError("redaction_bounds");
    }
    state.primitives.add(value);
  }
  addSensitiveString(state, String(value));
}
function arrayData(value: unknown, maximum: number): unknown[] {
  if (
    types.isProxy(value) ||
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length > maximum ||
    Reflect.ownKeys(value).length !== value.length + 1
  )
    throw new Error("array");
  const output: unknown[] = [];
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
      throw new Error("array");
    output.push(descriptor.value as unknown);
  }
  return output;
}
export function compileRedactionPaths(
  value: unknown,
  identities: ReadonlySet<string>,
): ReadonlyMap<string, readonly (readonly string[])[]> {
  try {
    const output = new Map<string, readonly (readonly string[])[]>();
    if (value === undefined) return output;
    const declarations = ownData(value);
    if (Object.keys(declarations).length > 128) throw new Error("paths");
    for (const [id, pointers] of Object.entries(declarations)) {
      if (!identities.has(id)) throw new Error("identity");
      const paths: (readonly string[])[] = [];
      const seen = new Set<string>();
      for (const pointer of arrayData(pointers, 32)) {
        if (
          typeof pointer !== "string" ||
          pointer.length > 1024 ||
          (pointer !== "" && !pointer.startsWith("/")) ||
          /~(?:[^01]|$)/.test(pointer)
        )
          throw new Error("pointer");
        if (seen.has(pointer)) continue;
        seen.add(pointer);
        const tokens =
          pointer === ""
            ? []
            : pointer
                .slice(1)
                .split("/")
                .map((token) =>
                  token.replaceAll("~1", "/").replaceAll("~0", "~"),
                );
        if (tokens.length > 64) throw new Error("pointer");
        paths.push(Object.freeze(tokens));
      }
      output.set(id, Object.freeze(paths));
    }
    return output;
  } catch {
    throw new RuntimeConfigurationError("CAP_RUNTIME_CONFIGURATION_INVALID");
  }
}
interface Budget {
  nodes: number;
  units: number;
  scan: number;
}
function node(budget: Budget, depth: number): void {
  if (++budget.nodes > MAX_NODES || depth > MAX_DEPTH)
    throw new RedactionBoundsError("redaction_bounds");
}
function text(budget: Budget, units: number): void {
  if (units > MAX_TEXT_UNITS - budget.units)
    throw new RedactionBoundsError("redaction_bounds");
  budget.units += units;
}
/** Canonical input only; retain atoms, never input containers. Missing own matches skip. */
export function captureRedactionPaths(
  input: JsonValue,
  paths: readonly (readonly string[])[],
  state: RedactionState,
): void {
  if (state.failed) throw new RedactionBoundsError("redaction_bounds");
  const budget: Budget = { nodes: 0, units: 0, scan: 0 };
  const capture = (value: JsonValue, depth: number): void => {
    node(budget, depth);
    if (typeof value === "string") {
      text(budget, value.length);
      addSensitiveString(state, value);
    } else if (
      value === null ||
      typeof value === "boolean" ||
      typeof value === "number"
    ) {
      if (typeof value === "number" && !Number.isFinite(value))
        throw new Error("number");
      text(budget, String(value).length);
      addSensitivePrimitive(state, value);
    } else if (types.isProxy(value)) throw new Error("proxy");
    else if (Array.isArray(value)) {
      const entries = arrayData(value, MAX_NODES - budget.nodes);
      for (let index = 0; index < entries.length; index++)
        capture(entries[index] as JsonValue, depth + 1);
    } else {
      if (
        Object.getPrototypeOf(value) !== Object.prototype &&
        Object.getPrototypeOf(value) !== null
      )
        throw new Error("prototype");
      let keys = 0;
      for (const key in value)
        if (Object.hasOwn(value, key)) {
          keys++;
          node(budget, depth + 1);
          text(budget, key.length);
          addSensitiveString(state, key);
          const descriptor = Object.getOwnPropertyDescriptor(value, key);
          if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
            throw new Error("descriptor");
          capture(descriptor.value as JsonValue, depth + 1);
        }
      if (Reflect.ownKeys(value).length !== keys) throw new Error("descriptor");
    }
  };
  const seen = new Set<JsonValue>();
  for (const tokens of paths) {
    let selected: JsonValue | undefined = input;
    for (const token of tokens) {
      node(budget, 0);
      text(budget, token.length);
      if (
        typeof selected === "object" &&
        selected !== null &&
        types.isProxy(selected)
      )
        throw new Error("proxy");
      if (
        selected === null ||
        typeof selected !== "object" ||
        (Array.isArray(selected) && !/^(0|[1-9][0-9]*)$/.test(token))
      ) {
        selected = undefined;
        break;
      }
      if (
        types.isProxy(selected) ||
        (Object.getPrototypeOf(selected) !== Object.prototype &&
          Object.getPrototypeOf(selected) !== null &&
          Object.getPrototypeOf(selected) !== Array.prototype)
      )
        throw new Error("carrier");
      const descriptor = Object.getOwnPropertyDescriptor(selected, token);
      if (descriptor && (!("value" in descriptor) || !descriptor.enumerable))
        throw new Error("descriptor");
      selected =
        descriptor && "value" in descriptor
          ? (descriptor.value as JsonValue)
          : undefined;
      if (selected === undefined) break;
    }
    if (selected !== undefined && !seen.has(selected)) {
      seen.add(selected);
      capture(selected, 0);
    }
  }
}
/** Bounded own-data JSON copy, redaction, and deep freezing before export or caching. */
export function redactJson(value: unknown, state: RedactionState): JsonValue {
  if (state.failed) throw new RedactionBoundsError("redaction_bounds");
  const budget: Budget = { nodes: 0, units: 0, scan: 0 };
  const active = new Set<object>();
  const patterns = [...state.strings].sort(
    (left, right) =>
      right.length - left.length || (left < right ? -1 : left > right ? 1 : 0),
  );
  let replacement = MARKER;
  for (const pattern of patterns) {
    if (pattern === "") continue;
    budget.scan += MARKER.length;
    if (MARKER.includes(pattern)) replacement = "";
  }
  const ensureReplacement = (): void => {
    if (replacement === "" && state.strings.has(""))
      throw new Error("redaction_unrepresentable");
  };
  const redactText = (value: string): string => {
    text(budget, value.length);
    let safe = value;
    for (;;) {
      let replacements = 0;
      for (const pattern of patterns) {
        if (pattern === "") {
          if (safe === "") {
            ensureReplacement();
            text(budget, replacement.length);
            safe = replacement;
            replacements++;
          }
          continue;
        }
        if (safe.length > MAX_SCAN_WORK - budget.scan)
          throw new RedactionBoundsError("redaction_bounds");
        budget.scan += safe.length;
        let occurrences = 0;
        let index = 0;
        while ((index = safe.indexOf(pattern, index)) !== -1) {
          occurrences++;
          index += pattern.length;
        }
        if (!occurrences) continue;
        ensureReplacement();
        const size =
          safe.length + occurrences * (replacement.length - pattern.length);
        text(budget, size);
        safe = safe.replaceAll(pattern, replacement);
        replacements += occurrences;
      }
      if (replacements === 0) break;
    }
    text(budget, safe.length);
    return safe;
  };
  const copy = (value: unknown, depth: number): JsonValue => {
    node(budget, depth);
    if (typeof value === "string") return redactText(value);
    if (
      value === null ||
      typeof value === "boolean" ||
      (typeof value === "number" && Number.isFinite(value))
    ) {
      if (state.primitives.has(value)) {
        ensureReplacement();
        return redactText(replacement);
      }
      return value;
    }
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
        const entries = arrayData(value, MAX_NODES - budget.nodes);
        return Object.freeze(entries.map((entry) => copy(entry, depth + 1)));
      }
      if (
        Object.getPrototypeOf(value) !== Object.prototype &&
        Object.getPrototypeOf(value) !== null
      )
        throw new Error("prototype");
      const output: Record<string, JsonValue> = {};
      for (const key in value)
        if (Object.hasOwn(value, key)) {
          node(budget, depth + 1);
          const descriptor = Object.getOwnPropertyDescriptor(value, key);
          if (!descriptor || !("value" in descriptor))
            throw new Error("descriptor");
          const name = redactText(key);
          if (Object.hasOwn(output, name))
            throw new Error("redaction_collision");
          Object.defineProperty(output, name, {
            value: copy(descriptor.value, depth + 1),
            enumerable: true,
          });
        }
      // Reject symbols and hidden own data without reading their values.
      if (Reflect.ownKeys(value).length !== Object.keys(output).length)
        throw new Error("descriptor");
      return Object.freeze(output);
    } finally {
      active.delete(value);
    }
  };
  try {
    return copy(value, 0);
  } catch (error) {
    if (error instanceof RedactionBoundsError) state.failed = true;
    throw new Error("redaction_invalid");
  }
}

/** Equality of already copied canonical JSON domain data, independent of object key order. */
export function equalJson(left: JsonValue, right: JsonValue): boolean {
  let nodes = 0;
  const equal = (left: JsonValue, right: JsonValue, depth: number): boolean => {
    if (++nodes > MAX_NODES || depth > MAX_DEPTH)
      throw new RedactionBoundsError("redaction_bounds");
    if (left === right) return true;
    if (
      left === null ||
      right === null ||
      typeof left !== "object" ||
      typeof right !== "object"
    )
      return false;
    if (Array.isArray(left) !== Array.isArray(right)) return false;
    const leftKeys = Object.keys(left);
    if (leftKeys.length !== Object.keys(right).length) return false;
    for (const key of leftKeys) {
      if (!Object.hasOwn(right, key)) return false;
      const leftValue = Object.getOwnPropertyDescriptor(left, key)
        ?.value as JsonValue;
      const rightValue = Object.getOwnPropertyDescriptor(right, key)
        ?.value as JsonValue;
      if (!equal(leftValue, rightValue, depth + 1)) return false;
    }
    return true;
  };
  return equal(left, right, 0);
}
