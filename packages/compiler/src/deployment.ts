import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import {
  isCapability,
  type RuntimeBindingHandle,
  type SchemaProvider,
} from "@capaxle/core";
import {
  capabilitySemanticHash,
  jcs,
  normalizeDocument,
  type JsonValue,
} from "@capaxle/ir";
import {
  compileAuthenticatedSchemaBatch,
  type CompilerSchemaUse,
} from "./schema-compiler.js";
import type {
  CapabilityDocument,
  RuntimeValidatorBindings,
  Sha256,
} from "./compilation-types.js";

const { getBindingHandle } = createRequire(import.meta.url)(
  fileURLToPath(
    new URL("./internal-bindings.js", import.meta.resolve("@capaxle/core")),
  ),
) as {
  readonly getBindingHandle: (
    descriptor: unknown,
    identity: {
      readonly id: string;
      readonly version: string;
      readonly irHash: string;
    },
  ) => RuntimeBindingHandle | undefined;
};

interface AuthoringPresence {
  readonly sharedSchemas: readonly {
    readonly path: string;
    readonly schema: { readonly name: string; readonly authorSchema: unknown };
  }[];
}

const codePointCompare = (left: string, right: string): number => {
  const a = Array.from(left, (character) => character.codePointAt(0) ?? 0);
  const b = Array.from(right, (character) => character.codePointAt(0) ?? 0);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1)
    if (a[index] !== b[index]) return (a[index] ?? 0) - (b[index] ?? 0);
  return a.length - b.length;
};

const uniqueSortedStrings = (values: readonly string[]): string[] =>
  [...new Set(values)].sort(codePointCompare);

export interface DeploymentBindingRequest {
  readonly document: CapabilityDocument;
  readonly irHash: Sha256;
  readonly descriptors: Readonly<Record<string, unknown>>;
  readonly schemaProviders: readonly SchemaProvider<unknown>[];
}

export interface DeploymentBindings {
  readonly runtimeBindings: ReadonlyMap<
    string,
    {
      readonly id: string;
      readonly version: string;
      readonly irHash: Sha256;
      readonly binding: RuntimeBindingHandle;
    }
  >;
  readonly validators: ReadonlyMap<string, RuntimeValidatorBindings>;
}

/** Rebind only verified, already imported deployment descriptors to prebuilt IR. */
export function loadDeploymentBindings(
  request: DeploymentBindingRequest,
): DeploymentBindings {
  const invalid = (): never => {
    const error = new Error(
      "Verified deployment bindings disagree with capability IR.",
    );
    Object.defineProperty(error, "code", {
      value: "CAP_APP_DEPLOYMENT_INVALID",
      enumerable: true,
    });
    throw error;
  };
  try {
    const { document, irHash, descriptors, schemaProviders } = request;
    if (
      capabilitySemanticHash(document) !== irHash ||
      !descriptors ||
      typeof descriptors !== "object" ||
      Array.isArray(descriptors) ||
      !Array.isArray(schemaProviders)
    )
      invalid();
    const capabilities = document.capabilities;
    const expectedIds = new Set(capabilities.map(({ id }) => id));
    if (
      expectedIds.size !== capabilities.length ||
      Object.keys(descriptors).length !== expectedIds.size ||
      Object.keys(descriptors).some((id) => !expectedIds.has(id))
    )
      invalid();

    const uses: CompilerSchemaUse[] = [];
    const bindings = new Map<
      string,
      DeploymentBindings["runtimeBindings"] extends ReadonlyMap<string, infer T>
        ? T
        : never
    >();
    for (const capability of capabilities) {
      const descriptor = descriptors[capability.id];
      if (!isCapability(descriptor)) return invalid();
      if (
        (descriptor.id !== undefined && descriptor.id !== capability.id) ||
        (descriptor.version ?? "1.0.0") !== capability.version ||
        descriptor.summary !== capability.summary ||
        Object.keys(descriptor.errors).sort().join("\0") !==
          Object.keys(capability.errors).sort().join("\0")
      )
        invalid();
      const authorMetadata = {
        description: descriptor.description ?? null,
        tags: uniqueSortedStrings(descriptor.tags ?? []),
        authentication: descriptor.authentication ?? "required",
        permissions:
          descriptor.permissions === "public"
            ? { public: true }
            : {
                ...(descriptor.permissions.allOf
                  ? { allOf: uniqueSortedStrings(descriptor.permissions.allOf) }
                  : {}),
                ...(descriptor.permissions.anyOf
                  ? { anyOf: uniqueSortedStrings(descriptor.permissions.anyOf) }
                  : {}),
              },
        effects: descriptor.effects,
        secrets: [...(descriptor.requirements?.secrets ?? [])].sort((a, b) =>
          codePointCompare(a.name, b.name),
        ),
        limits: descriptor.limits ?? {},
        examples: descriptor.examples ?? [],
        errors: Object.fromEntries(
          Object.entries(descriptor.errors).map(([code, error]) => [
            code,
            {
              status: error.status,
              message: error.message,
              retryable: error.retryable,
            },
          ]),
        ),
      };
      const pinnedMetadata = {
        description: capability.description ?? null,
        tags: capability.tags,
        authentication: capability.access.authentication,
        permissions: capability.access.permissions,
        effects: capability.effects,
        secrets: capability.requirements.secrets,
        limits: capability.limits,
        examples: capability.examples,
        errors: Object.fromEntries(
          Object.entries(capability.errors).map(([code, error]) => [
            code,
            {
              status: error.status,
              message: error.message,
              retryable: error.retryable,
            },
          ]),
        ),
      };
      if (
        jcs(structuredClone(authorMetadata) as unknown as JsonValue) !==
        jcs(pinnedMetadata as JsonValue)
      )
        invalid();
      for (const surface of ["http", "cli", "mcp", "internal"] as const)
        if (
          descriptor.exposure?.[surface] !== undefined &&
          descriptor.exposure[surface] !== capability.access.exposure[surface]
        )
          invalid();
      const identity = {
        id: capability.id,
        version: capability.version,
        irHash,
      };
      const binding = getBindingHandle(descriptor, identity);
      if (!binding) return invalid();
      bindings.set(capability.id, Object.freeze({ ...identity, binding }));

      const query = (
        globalThis as typeof globalThis & {
          readonly [key: symbol]:
            | {
                readonly get: (value: unknown) => AuthoringPresence | undefined;
              }
            | undefined;
        }
      )[Symbol.for("@capaxle/core/authoring-presence-registry@1")];
      const presence = query?.get(descriptor);
      if (!presence) return invalid();
      const shared = new Map(
        presence.sharedSchemas.map(({ path, schema }) => [path, schema]),
      );
      const add = (
        role: string,
        path: string,
        schema: unknown,
        direction: "input" | "output",
      ) => {
        const wrapper = shared.get(path);
        uses.push({
          key: `${capability.id}/${role}`,
          schema: wrapper?.authorSchema ?? schema,
          direction,
          source: { file: ".", line: 1, column: 1 },
          canonicalOrder: uses.length,
          ...(wrapper ? { sharedName: wrapper.name } : {}),
        });
      };
      add("input", "/input", descriptor.input, "input");
      add("output", "/output", descriptor.output, "output");
      for (const [code, error] of Object.entries(descriptor.errors).sort(
        ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0),
      ))
        if (error.details !== undefined)
          add(
            `errors/${code}/details`,
            `/errors/${code.replaceAll("~", "~0").replaceAll("/", "~1")}/details`,
            error.details,
            "output",
          );
    }
    const batch = compileAuthenticatedSchemaBatch({
      providers: schemaProviders,
      uses,
    });
    if (
      !batch.ok ||
      jcs(
        normalizeDocument({ schemas: batch.schemas }).schemas as JsonValue,
      ) !== jcs(document.schemas as JsonValue)
    )
      invalid();
    const validators = new Map<string, RuntimeValidatorBindings>();
    for (const capability of capabilities) {
      const id = capability.id;
      const matches = (role: string, expected: JsonValue): boolean => {
        const actual = batch.compiled[`${id}/${role}`];
        if (actual === undefined) return false;
        const normalized = normalizeDocument({
          capabilities: [{ input: actual }],
        }).capabilities[0]?.input;
        return jcs(normalized as JsonValue) === jcs(expected);
      };
      if (
        !matches("input", capability.input) ||
        !matches("output", capability.output)
      )
        invalid();
      const input = batch.validators.uses.get(`${id}/input`);
      const output = batch.validators.uses.get(`${id}/output`);
      if (!input || !output) return invalid();
      const errors = new Map<string, typeof input>();
      for (const [code, error] of Object.entries(capability.errors)) {
        const role = `errors/${code}/details`;
        if (error.details === undefined) {
          if (batch.compiled[`${id}/${role}`] !== undefined) invalid();
          continue;
        }
        if (!matches(role, error.details)) invalid();
        const validator = batch.validators.uses.get(`${id}/${role}`);
        if (!validator) return invalid();
        errors.set(code, validator);
      }
      validators.set(id, Object.freeze({ input, output, errors }));
    }
    return Object.freeze({ runtimeBindings: bindings, validators });
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      error.code === "CAP_APP_DEPLOYMENT_INVALID"
    )
      throw error;
    return invalid();
  }
}
