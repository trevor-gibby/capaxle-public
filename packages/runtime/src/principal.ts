import { types } from "node:util";
import type { IdentityContext, PrincipalSnapshot } from "@capaxle/core";
import type { JsonValue } from "@capaxle/ir";
import { ownData } from "./registry.js";

const credentialKey =
  /^(?:password|passphrase|credentials?|authorization|cookie|(?:access|refresh|id)[_-]?token|api[_-]?key|secret|token|bearer)$/i;
const wellFormed = (value: string): boolean =>
  !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(
    value,
  );
const unicode = (value: unknown, max = 1024): value is string =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= max &&
  wellFormed(value);

export const canonicalIdentityId = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);

/** Bounded own-data copying never executes accessors or proxy traps. */
export function normalizePrincipal(
  value: unknown,
  providerId: string,
): PrincipalSnapshot {
  const root = ownData(value, [
    "providerId",
    "type",
    "subject",
    "tenant",
    "scopes",
    "roles",
    "authMethod",
    "assurance",
    "claims",
  ]);
  if (
    !canonicalIdentityId(providerId) ||
    !canonicalIdentityId(root.providerId) ||
    root.providerId !== providerId ||
    !["user", "service", "agent", "anonymous"].includes(root.type as string) ||
    !unicode(root.subject)
  )
    throw new Error("principal");
  for (const key of ["tenant", "authMethod", "assurance"])
    if (Object.hasOwn(root, key) && !unicode(root[key]))
      throw new Error("principal");
  let nodes = 0;
  let bytes = 0;
  const active = new Set<object>();
  const copy = (item: unknown, depth: number): JsonValue => {
    if (++nodes > 2048 || depth > 16) throw new Error("bounds");
    if (typeof item === "string") {
      bytes += item.length;
      if (!wellFormed(item) || bytes > 32768) throw new Error("bounds");
      return item;
    }
    if (
      item === null ||
      typeof item === "boolean" ||
      (typeof item === "number" && Number.isFinite(item))
    )
      return item;
    if (
      typeof item !== "object" ||
      item === null ||
      types.isProxy(item) ||
      active.has(item)
    )
      throw new Error("json");
    active.add(item);
    try {
      if (Array.isArray(item)) {
        if (
          Object.getPrototypeOf(item) !== Array.prototype ||
          item.length > 2048 ||
          Reflect.ownKeys(item).length !== item.length + 1
        )
          throw new Error("array");
        const result: JsonValue[] = [];
        for (let i = 0; i < item.length; i++) {
          const descriptor = Object.getOwnPropertyDescriptor(item, String(i));
          if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
            throw new Error("array");
          result.push(copy(descriptor.value, depth + 1));
        }
        return Object.freeze(result);
      }
      const result: Record<string, JsonValue> = {};
      for (const [key, entry] of Object.entries(ownData(item))) {
        bytes += key.length;
        if (credentialKey.test(key) || !wellFormed(key) || bytes > 32768)
          throw new Error("claims");
        Object.defineProperty(result, key, {
          value: copy(entry, depth + 1),
          enumerable: true,
        });
      }
      return Object.freeze(result);
    } finally {
      active.delete(item);
    }
  };
  const members = (item: unknown): readonly string[] => {
    const result = copy(item, 0);
    if (
      !Array.isArray(result) ||
      result.length > 256 ||
      result.some(
        (entry) =>
          typeof entry !== "string" ||
          !/^[A-Za-z0-9][A-Za-z0-9:_./-]{0,127}$/.test(entry),
      )
    )
      throw new Error("members");
    return Object.freeze([...new Set(result as string[])].sort());
  };
  const claims = copy(root.claims, 0);
  if (claims === null || typeof claims !== "object" || Array.isArray(claims))
    throw new Error("claims");
  return Object.freeze({
    providerId,
    type: root.type as PrincipalSnapshot["type"],
    subject: root.subject,
    ...(root.tenant === undefined ? {} : { tenant: root.tenant as string }),
    scopes: members(root.scopes),
    roles: members(root.roles),
    ...(root.authMethod === undefined
      ? {}
      : { authMethod: root.authMethod as string }),
    ...(root.assurance === undefined
      ? {}
      : { assurance: root.assurance as string }),
    claims: claims as Readonly<Record<string, JsonValue>>,
  });
}
export const anonymousPrincipal: PrincipalSnapshot = Object.freeze({
  providerId: "anonymous",
  type: "anonymous",
  subject: "anonymous",
  scopes: Object.freeze([]),
  roles: Object.freeze([]),
  claims: Object.freeze({}),
});
export function rootIdentity(principal: PrincipalSnapshot): IdentityContext {
  return Object.freeze({
    originating: principal,
    effective: principal,
    authorityChain: Object.freeze([principal]),
    provenance: Object.freeze([]),
  });
}
