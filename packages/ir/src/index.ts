export type JsonPrimitive = null | boolean | number | string;
export type JsonValue =
  JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };
export type JsonSchema = { readonly [key: string]: JsonValue };

export interface Diagnostic {
  readonly code: string;
  readonly severity: "error";
  readonly path: string;
  readonly message: string;
}

export interface RuntimeValidationResult {
  readonly accepted: boolean;
  readonly value?: JsonValue;
}

export interface CanonicalizationResult {
  readonly valid: boolean;
  readonly value?: JsonValue;
  readonly reason?: string;
}

export interface MetaValidationIssue {
  readonly path: string;
  readonly message: string;
}

export declare const IR_VERSION: "0.1";
export declare const JSON_SCHEMA_DIALECT: string;
export declare const CAPABILITY_IR_SCHEMA: JsonSchema;
export declare function normalizeDocument<T>(source: T): T;
export declare function jcs(value: JsonValue): string;
export declare function canonicalizeInput(
  document: {
    readonly schemas: Readonly<Record<string, JsonSchema>>;
    readonly capabilities?: readonly {
      readonly id: string;
      readonly input:
        { readonly schema: JsonSchema } | { readonly $ref: string };
    }[];
  },
  capability:
    | string
    | {
        readonly input:
          { readonly schema: JsonSchema } | { readonly $ref: string };
      },
  input: unknown,
): CanonicalizationResult;
/** Canonical validation only; never applies defaults or mutates the value. */
export declare function validateSchemaValue(
  document: { readonly schemas: Readonly<Record<string, JsonSchema>> },
  binding: { readonly schema: JsonSchema } | { readonly $ref: string },
  value: unknown,
): { readonly valid: boolean; readonly reason?: string };
export declare function validateStructure(
  document: unknown,
  schema: JsonSchema,
): readonly Diagnostic[];
export declare function validateSemantics(
  document: unknown,
  options?: { readonly requireNormalized?: boolean },
): readonly Diagnostic[];
export declare function validateDocument(
  document: unknown,
  schema: JsonSchema,
  options?: { readonly requireNormalized?: boolean },
): readonly Diagnostic[];
export declare function validateCapabilityDocument(
  document: unknown,
  options?: { readonly requireNormalized?: boolean },
): readonly Diagnostic[];
export declare function capabilitySemanticHashDetails(document: unknown): {
  readonly normalized: JsonValue;
  readonly canonicalJson: string;
  readonly utf8ByteLength: number;
  readonly hash: string;
};
export declare function capabilitySemanticHash(document: unknown): string;
export declare function metaValidateDraft202012Schema(
  schema: JsonSchema,
): readonly MetaValidationIssue[];
