export {
  defineCapability,
  defineSharedSchema,
  isCapability,
  CapabilityDefinitionError,
} from "./define-capability.js";
export type { AuthoringDiagnostic } from "./define-capability.js";
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
  CapabilityInvocationSuccess,
  CapabilityInvocationFailure,
  DeclaredCapabilityError,
  DynamicDeclaredCapabilityError,
  FrameworkCapabilityError,
  CapabilityInvocationResult,
  CapabilityDefinition,
  Capability,
  RuntimeBindingHandle,
} from "./types.js";
export {
  selectSchemaProvider,
  SchemaProviderSelectionError,
} from "./schema-provider.js";
export type {
  SchemaConversionContext,
  RuntimeValidator,
  SchemaProvider,
  SchemaProviderSelectionCode,
} from "./schema-provider.js";
