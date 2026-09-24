import type { PrincipalSnapshot } from "@capaxle/core";
import type { InvocationResult, RuntimeCapability } from "./types.js";

export type ProviderOutcome =
  { readonly value: unknown } | { readonly failed: true } | InvocationResult;
/** Private trusted-chain evaluator: every member independently restricts access. */
export async function authorizePrincipals(
  principals: readonly PrincipalSnapshot[],
  permissions: RuntimeCapability["access"]["permissions"],
  evaluate?: (principal: PrincipalSnapshot) => Promise<ProviderOutcome>,
): Promise<{ readonly kind: "allow" | "deny" | "failed" } | InvocationResult> {
  for (const principal of principals) {
    if (
      permissions.public !== true &&
      ((permissions.allOf?.some(
        (permission) => !principal.scopes.includes(permission),
      ) ??
        false) ||
        (permissions.anyOf &&
          !permissions.anyOf.some((permission) =>
            principal.scopes.includes(permission),
          )))
    )
      return { kind: "deny" };
    if (evaluate) {
      const outcome = await evaluate(principal);
      if ("ok" in outcome) return outcome;
      if (
        "failed" in outcome ||
        (outcome.value !== true && outcome.value !== false)
      )
        return { kind: "failed" };
      if (outcome.value === false) return { kind: "deny" };
    }
  }
  return { kind: "allow" };
}
