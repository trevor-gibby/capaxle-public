import type { SchemaConversionContext, SchemaProvider } from "@capaxle/core";
import type { Diagnostic, JsonSchema } from "@capaxle/ir";
import type { z } from "zod";

export type ZodSchema = z.ZodType;

export type ZodConversionResult =
  | {
      readonly accepted: true;
      readonly diagnostics: readonly [];
      readonly jsonSchema: JsonSchema;
    }
  | {
      readonly accepted: false;
      readonly diagnostics: readonly Diagnostic[];
    };

export declare function portabilityDiagnostics(
  schema: ZodSchema,
  context: SchemaConversionContext,
): readonly Diagnostic[];
export declare function validatePortableProfile(
  schema: JsonSchema,
  context: SchemaConversionContext,
): readonly Diagnostic[];
export declare function convertZodSchema(
  schema: ZodSchema,
  context: SchemaConversionContext,
): ZodConversionResult;
export declare function validatePortableValue(
  schema: JsonSchema,
  value: unknown,
): { readonly valid: boolean; readonly value?: unknown };
export declare const zodSchemaProvider: SchemaProvider<ZodSchema>;
export declare const DIALECT: string;
