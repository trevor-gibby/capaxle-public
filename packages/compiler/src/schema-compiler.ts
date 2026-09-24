import {
  SchemaProviderSelectionError,
  selectSchemaProvider,
  type RuntimeValidator,
  type SchemaProvider,
} from "@capaxle/core";
import { jcs, type Diagnostic, type JsonSchema } from "@capaxle/ir";

import type { RelatedLocation, SourceLocation } from "./types.js";

export interface SchemaUse {
  /** Stable caller-owned key, such as `capability-id/input`. */
  readonly key: string;
  readonly schema: unknown;
  readonly direction: "input" | "output";
  readonly source: SourceLocation;
}

/** Direct-module compiler input. This type is intentionally absent from package exports. */
export interface CompilerSchemaUse extends SchemaUse {
  readonly canonicalOrder: number;
  readonly sharedName?: string;
}

export interface SchemaCompilationDiagnostic {
  readonly code: string;
  readonly severity: "error";
  readonly path: string;
  readonly message: string;
  readonly source: SourceLocation;
  readonly related?: readonly RelatedLocation[];
}

export type CompiledSchemaReference =
  { readonly schema: JsonSchema } | { readonly $ref: string };

export interface SchemaBatchCompilationRequest {
  readonly providers: readonly SchemaProvider<unknown>[];
  readonly uses?: readonly SchemaUse[];
}

/** Direct-module compiler input. This type is intentionally absent from package exports. */
export interface CompilerAuthenticatedSchemaBatchRequest {
  readonly providers: readonly SchemaProvider<unknown>[];
  readonly uses: readonly CompilerSchemaUse[];
}

export interface SchemaBatchCompilationResult {
  readonly ok: boolean;
  readonly schemas: Readonly<Record<string, JsonSchema>>;
  readonly compiled: Readonly<Record<string, CompiledSchemaReference>>;
  /** Executable bindings are process-local and never enter `schemas` or `compiled`. */
  readonly validators: {
    readonly uses: ReadonlyMap<string, RuntimeValidator>;
  };
  readonly diagnostics: readonly SchemaCompilationDiagnostic[];
  readonly normalizedRegistryBytes: string;
}

export interface SchemaOccurrenceEvidence {
  readonly key: string;
  readonly direction: "input" | "output";
  readonly providerId: string;
  readonly jsonSchema: JsonSchema;
  readonly source: SourceLocation;
  readonly sharedName?: string;
  readonly canonicalOrder?: number;
}

const occurrenceEvidence = new WeakMap<
  SchemaBatchCompilationResult,
  readonly SchemaOccurrenceEvidence[]
>();

/** Internal compiler graph evidence; not exported from the package entry point. */
export function schemaBatchOccurrenceEvidence(
  result: SchemaBatchCompilationResult,
): readonly SchemaOccurrenceEvidence[] {
  return occurrenceEvidence.get(result) ?? Object.freeze([]);
}

const codePointCompare = (left: string, right: string): number => {
  const a = Array.from(left, (character) => character.codePointAt(0) ?? 0);
  const b = Array.from(right, (character) => character.codePointAt(0) ?? 0);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) return (a[index] ?? 0) - (b[index] ?? 0);
  }
  return a.length - b.length;
};

const escapePointerToken = (value: string): string =>
  value.replaceAll("~", "~0").replaceAll("/", "~1");

const validUnicodeScalarString = (value: string): boolean => {
  if (value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
};

const compareSource = (left: SourceLocation, right: SourceLocation): number =>
  codePointCompare(left.file, right.file) ||
  left.line - right.line ||
  left.column - right.column;

function fromProviderDiagnostic(
  item: Diagnostic,
  source: SourceLocation,
): SchemaCompilationDiagnostic {
  return { ...item, source };
}

function compileOne(
  providers: readonly SchemaProvider<unknown>[],
  schema: unknown,
  direction: "input" | "output",
  path: string,
  source: SourceLocation,
):
  | {
      readonly ok: true;
      readonly jsonSchema: JsonSchema;
      readonly validator: RuntimeValidator;
      readonly providerId: string;
    }
  | {
      readonly ok: false;
      readonly diagnostics: readonly SchemaCompilationDiagnostic[];
    } {
  let provider: SchemaProvider<unknown>;
  try {
    provider = selectSchemaProvider(providers, schema, path);
  } catch (error) {
    if (error instanceof SchemaProviderSelectionError) {
      return {
        ok: false,
        diagnostics: error.diagnostics.map((item) =>
          fromProviderDiagnostic(item, source),
        ),
      };
    }
    return {
      ok: false,
      diagnostics: [
        {
          code: "CAP_SCHEMA_PROVIDER_FAILED",
          severity: "error",
          path,
          message: "Schema provider selection failed unexpectedly.",
          source,
        },
      ],
    };
  }
  try {
    const jsonSchema = provider.toJsonSchema(schema, { path, direction });
    const validator = provider.createValidator(schema);
    return { ok: true, jsonSchema, validator, providerId: provider.id };
  } catch (error) {
    const diagnostics =
      typeof error === "object" &&
      error !== null &&
      "diagnostics" in error &&
      Array.isArray(error.diagnostics)
        ? (error.diagnostics as readonly Diagnostic[])
        : [
            {
              code: "CAP_SCHEMA_PROVIDER_FAILED",
              severity: "error" as const,
              path,
              message: "Schema provider conversion failed unexpectedly.",
            },
          ];
    return {
      ok: false,
      diagnostics: diagnostics.map((item) =>
        fromProviderDiagnostic(item, source),
      ),
    };
  }
}

function compileBatch(
  request:
    SchemaBatchCompilationRequest | CompilerAuthenticatedSchemaBatchRequest,
  authenticated: boolean,
): SchemaBatchCompilationResult {
  const diagnostics: SchemaCompilationDiagnostic[] = [];
  const useValidators = new Map<string, RuntimeValidator>();
  const candidates = new Map<
    string,
    Array<{
      readonly schema: JsonSchema;
      readonly source: SourceLocation;
      readonly key: string;
      readonly canonicalOrder: number;
    }>
  >();
  const occurrences: SchemaOccurrenceEvidence[] = [];
  const sharedUseResults = new Map<
    string,
    {
      readonly name: string;
      readonly schema: JsonSchema;
      readonly source: SourceLocation;
      readonly validator: RuntimeValidator;
    }
  >();
  const declarationNamespaces = new Map<string, SourceLocation>();

  const authenticatedUses = authenticated
    ? (request.uses as readonly CompilerSchemaUse[])
    : [];
  for (const use of authenticatedUses)
    if (typeof use.sharedName === "string")
      declarationNamespaces.set(`schemas/${use.sharedName}`, use.source);

  const compiled = new Map<string, CompiledSchemaReference>();
  const uses = [...(request.uses ?? [])].sort(
    (left, right) =>
      (authenticated
        ? (left as CompilerSchemaUse).canonicalOrder -
          (right as CompilerSchemaUse).canonicalOrder
        : codePointCompare(left.key, right.key)) ||
      compareSource(left.source, right.source),
  );
  const seenUses = new Map<string, SourceLocation>();
  for (const use of uses) {
    const path = `/${escapePointerToken(use.key)}`;
    if (use.key.length === 0) {
      diagnostics.push({
        code: "CAP_SCHEMA_USE_KEY_INVALID",
        severity: "error",
        path,
        message: "Schema use keys must be nonempty.",
        source: use.source,
      });
      continue;
    }
    const shared =
      authenticated && typeof (use as CompilerSchemaUse).sharedName === "string"
        ? (use as CompilerSchemaUse & { readonly sharedName: string })
        : undefined;
    if (shared && !validUnicodeScalarString(shared.sharedName)) {
      diagnostics.push({
        code: "CAP_SCHEMA_NAME_INVALID",
        severity: "error",
        path: `${path}/$ref`,
        message: "Referenced shared schema names must be nonempty.",
        source: use.source,
      });
      continue;
    }
    const firstUse = seenUses.get(use.key);
    if (firstUse) {
      diagnostics.push({
        code: "CAP_SCHEMA_USE_KEY_COLLISION",
        severity: "error",
        path,
        message: `Schema use key ${JSON.stringify(use.key)} is declared more than once.`,
        source: use.source,
        related: [
          { message: "The first schema use is here.", source: firstUse },
        ],
      });
      continue;
    }
    seenUses.set(use.key, use.source);
    const declarationSource = declarationNamespaces.get(use.key);
    if (declarationSource) {
      diagnostics.push({
        code: "CAP_SCHEMA_BINDING_KEY_COLLISION",
        severity: "error",
        path,
        message: `Schema use key ${JSON.stringify(use.key)} collides with a shared-schema binding namespace.`,
        source: use.source,
        related: [
          {
            message: "The shared-schema declaration is here.",
            source: declarationSource,
          },
        ],
      });
      continue;
    }
    const result = compileOne(
      request.providers,
      use.schema,
      use.direction,
      path,
      use.source,
    );
    if (!result.ok) {
      diagnostics.push(...result.diagnostics);
      continue;
    }
    occurrences.push(
      Object.freeze({
        key: use.key,
        direction: use.direction,
        providerId: result.providerId,
        jsonSchema: result.jsonSchema,
        source: use.source,
        ...(shared
          ? {
              sharedName: shared.sharedName,
              canonicalOrder: shared.canonicalOrder,
            }
          : {}),
      }),
    );
    if (shared) {
      const values = candidates.get(shared.sharedName) ?? [];
      values.push({
        schema: result.jsonSchema,
        source: use.source,
        key: use.key,
        canonicalOrder: shared.canonicalOrder,
      });
      candidates.set(shared.sharedName, values);
      sharedUseResults.set(use.key, {
        name: shared.sharedName,
        schema: result.jsonSchema,
        source: use.source,
        validator: result.validator,
      });
    } else {
      compiled.set(use.key, { schema: result.jsonSchema });
      useValidators.set(use.key, result.validator);
    }
  }

  const registry = new Map<string, JsonSchema>();
  const collidingNames = new Set<string>();
  for (const [name, unsorted] of [...candidates].sort(([left], [right]) =>
    codePointCompare(left, right),
  )) {
    const values = [...unsorted].sort(
      (left, right) =>
        left.canonicalOrder - right.canonicalOrder ||
        codePointCompare(left.key, right.key) ||
        compareSource(left.source, right.source),
    );
    const first = values[0]!;
    const unequal = values
      .slice(1)
      .filter((value) => jcs(value.schema) !== jcs(first.schema));
    if (unequal.length) {
      collidingNames.add(name);
      diagnostics.push({
        code: "CAP_SCHEMA_NAME_COLLISION",
        severity: "error",
        path: `/schemas/${escapePointerToken(name)}`,
        message: `Shared schema ${JSON.stringify(name)} has unequal definitions.`,
        source: first.source,
        related: unequal.map((value) => ({
          message: "A conflicting shared-schema occurrence is here.",
          source: value.source,
        })),
      });
      continue;
    }
    registry.set(name, first.schema);
  }
  for (const [key, use] of [...sharedUseResults].sort(([left], [right]) =>
    codePointCompare(left, right),
  )) {
    const shared = registry.get(use.name);
    if (
      collidingNames.has(use.name) ||
      !shared ||
      jcs(shared) !== jcs(use.schema)
    ) {
      if (!collidingNames.has(use.name))
        diagnostics.push({
          code: "CAP_SCHEMA_SHARED_REFERENCE_MISMATCH",
          severity: "error",
          path: `/${escapePointerToken(key)}`,
          message: `Schema use does not match shared schema ${JSON.stringify(use.name)}.`,
          source: use.source,
        });
      continue;
    }
    compiled.set(key, {
      $ref: `#/schemas/${escapePointerToken(use.name)}`,
    });
    useValidators.set(key, use.validator);
  }

  diagnostics.sort(
    (left, right) =>
      codePointCompare(left.path, right.path) ||
      codePointCompare(left.code, right.code) ||
      compareSource(left.source, right.source),
  );
  const schemas = Object.freeze(
    Object.fromEntries(
      [...registry.entries()]
        .sort(([left], [right]) => codePointCompare(left, right))
        .map(([name, value]) => [name, value]),
    ),
  );
  const compiledObject = Object.freeze(
    Object.fromEntries(
      [...compiled.entries()].sort(([left], [right]) =>
        codePointCompare(left, right),
      ),
    ),
  );
  const result: SchemaBatchCompilationResult = {
    ok: diagnostics.length === 0,
    schemas,
    compiled: compiledObject,
    validators: {
      uses: useValidators,
    },
    diagnostics: Object.freeze(diagnostics),
    normalizedRegistryBytes: jcs(schemas),
  };
  occurrenceEvidence.set(
    result,
    Object.freeze(
      [...occurrences].sort((left, right) =>
        codePointCompare(left.key, right.key),
      ),
    ),
  );
  return result;
}

/** Compile raw service-local schema uses without creating shared declarations. */
export function compileSchemaBatch(
  request: SchemaBatchCompilationRequest,
): SchemaBatchCompilationResult {
  return compileBatch(request, false);
}

/** Compiler-only batch after capability authenticity and wrapper metadata checks. */
export function compileAuthenticatedSchemaBatch(
  request: CompilerAuthenticatedSchemaBatchRequest,
): SchemaBatchCompilationResult {
  return compileBatch(request, true);
}
