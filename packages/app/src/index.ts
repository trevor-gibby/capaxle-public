export { ApplicationError } from "./errors.js";
export async function createApplication(
  options: import("./application.js").ApplicationOptions,
): Promise<import("./application.js").Application> {
  const implementation = await import("./application.js");
  return implementation.createApplication(options);
}
export type {
  Application,
  ApplicationListener,
  ApplicationOptions,
  ApplicationProviders,
  ApplicationSurfaces,
  SurfaceRegistration,
  ReadinessCheck,
} from "./application.js";
export type { DocumentationOptions } from "./documentation.js";
export type { CliEndpoints } from "./deployment.js";
export { defineCapability } from "@capaxle/core";
export type {
  AuthorSchema,
  SharedSchema,
  CapabilitySchema,
  SchemaInput,
  SchemaOutput,
  Permissions,
  ExposureLevel,
  CapabilityExposure,
  CapabilityEffects,
  CapabilityRequirements,
  CapabilityLimits,
  CapabilityExample,
  ErrorStatus,
  DeclaredError,
  ErrorDeclarations,
  CapabilityError,
  CapabilityContext,
  PrincipalSnapshot,
  IdentityContext,
  InternalInvocationOptions,
  GeneratedCapabilityFacade,
  CapabilityInvocationResult,
  CapabilityDefinition,
  Capability,
} from "@capaxle/core";
