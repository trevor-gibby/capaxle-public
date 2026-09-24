import type {
  Diagnostic,
  JsonSchema,
  RuntimeValidationResult,
} from "@capaxle/ir";

export interface SchemaConversionContext {
  /** RFC 6901 path to the source schema in compiler diagnostics. */
  readonly path: string;
  readonly direction: "input" | "output";
}

export interface RuntimeValidator {
  validate(value: unknown): RuntimeValidationResult;
}

export interface SchemaProvider<TAuthorSchema = unknown> {
  readonly id: string;
  canHandle(value: unknown): value is TAuthorSchema;
  portabilityDiagnostics(
    value: TAuthorSchema,
    context: SchemaConversionContext,
  ): readonly Diagnostic[];
  toJsonSchema(
    value: TAuthorSchema,
    context: SchemaConversionContext,
  ): JsonSchema;
  createValidator(value: TAuthorSchema): RuntimeValidator;
}

export type SchemaProviderSelectionCode =
  "CAP_SCHEMA_PROVIDER_NOT_FOUND" | "CAP_SCHEMA_PROVIDER_AMBIGUOUS";

export class SchemaProviderSelectionError extends Error {
  readonly diagnostics: readonly Diagnostic[];

  constructor(code: SchemaProviderSelectionCode, path: string, count: number) {
    super(
      count === 0
        ? "No configured schema provider accepts this author schema."
        : `Exactly one schema provider must accept this author schema; ${count} matched.`,
    );
    this.name = "SchemaProviderSelectionError";
    this.diagnostics = Object.freeze([
      Object.freeze({
        code,
        severity: "error" as const,
        path,
        message: this.message,
      }),
    ]);
  }
}

/** Select exactly one injected frontend without inspecting its author value. */
export function selectSchemaProvider<TAuthorSchema>(
  providers: readonly SchemaProvider<TAuthorSchema>[],
  value: unknown,
  path = "/schema",
): SchemaProvider<TAuthorSchema> {
  const matches = providers.filter((provider) => provider.canHandle(value));
  if (matches.length !== 1) {
    throw new SchemaProviderSelectionError(
      matches.length === 0
        ? "CAP_SCHEMA_PROVIDER_NOT_FOUND"
        : "CAP_SCHEMA_PROVIDER_AMBIGUOUS",
      path,
      matches.length,
    );
  }
  return matches[0] as SchemaProvider<TAuthorSchema>;
}
