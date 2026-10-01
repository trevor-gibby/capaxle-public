export {
  defaultFrameworkCliDependencies,
  createDocsSchemaArtifactProducer,
  createInternalFacadeArtifactProducer,
  createSdkHttpArtifactProducer,
  executeFrameworkCli,
  parseFrameworkArguments,
  renderFrameworkResult,
  runFrameworkCli,
} from "./framework-cli.js";
export type {
  CommandDiagnostic,
  CommandDiagnosticCode,
  CommandDiagnosticReason,
  FrameworkCliDependencies,
  FrameworkCliIo,
  FrameworkCliResult,
  FrameworkCommand,
  ParseResult,
  ParsedFrameworkCommand,
} from "./framework-cli.js";

export {
  startFrameworkDev,
  defaultFrameworkDevDependencies,
  FrameworkDevStartError,
} from "./dev.js";
export type {
  FrameworkDevOptions,
  FrameworkDevDependencies,
  FrameworkDevHost,
  FrameworkDevSnapshot,
} from "./dev.js";

export { diagnoseLocalProject } from "./doctor.js";
export type {
  LocalDoctorCheck,
  LocalDoctorOptions,
  LocalDoctorReport,
} from "./doctor.js";
