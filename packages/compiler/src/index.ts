export { loadDiscoveryConfig } from "./config.js";
export { discoverCapabilities } from "./discovery.js";
export { watchCapabilities } from "./watch.js";
export { compileSchemaBatch } from "./schema-compiler.js";
export {
  compileProject,
  createCompilerSession,
  CompilerSessionClosedError,
  CompilerSessionCloseError,
} from "./compiler-engine.js";
export { emitCompilerArtifacts } from "./emission.js";
export type {
  SourceLocation,
  RelatedLocation,
  CompilerDiagnostic,
  ResolvedDiscoveryConfig,
  DiscoveryConfigResult,
  DiscoveredCapability,
  SuccessfulDiscoveryResult,
  FailedDiscoveryResult,
  DiscoveryResult,
  DiscoveryUpdate,
  DiscoveryWatcher,
  DiscoveryOptions,
  DiscoveryListener,
} from "./types.js";
export type {
  SchemaUse,
  SchemaCompilationDiagnostic,
  CompiledSchemaReference,
  SchemaBatchCompilationRequest,
  SchemaBatchCompilationResult,
} from "./schema-compiler.js";
export type {
  Sha256,
  CompilationDiagnosticPhase,
  CompilationDiagnosticSubphase,
  CompilationSourceLocation,
  CompilationDiagnostic,
  CompilerGraphNodeReport,
  CompilerGraphReport,
  ProvenanceEntry,
  CapabilityDocument,
  ResolvedCompilerCapability,
  ResolvedCompilerRegistry,
  RuntimeValidatorBindings,
  ProducerDependencyId,
  ArtifactProducerDiagnostic,
  ArtifactProducerResult,
  ArtifactBuildContext,
  DiscoveryContext,
  RootPublicationBuildLocator,
  RootPublicationAssemblyContext,
  CompilerRootPublication,
  CompilerArtifactProducer,
  CompilerOptions,
  CompiledArtifact,
  CompilationSuccess,
  CompilerRuntimeBinding,
  CompilationFailure,
  CompilationResult,
  CompilationUpdate,
  CompilerSession,
  ArtifactIndexEntry,
  EmissionResult,
} from "./compilation-types.js";
