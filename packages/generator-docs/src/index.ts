/// <reference types="node" />
import { createHash } from "node:crypto";
import {
  CAPABILITY_IR_SCHEMA,
  JSON_SCHEMA_DIALECT,
  canonicalizeInput,
  capabilitySemanticHash,
  jcs,
  validateCapabilityDocument,
  validateSchemaValue,
  type JsonSchema,
  type JsonValue,
} from "@capaxle/ir";

export const DOCS_SCHEMA_GENERATOR_VERSION = "0.1.0-alpha.2";
export const DOCS_SCHEMA_TARGET = "capaxle:docs-schema-bundle@0.1";
export const DOCS_SCHEMA_DIAGNOSTIC_CODES = [
  "CAP_BUILD_CONTEXT_INVALID",
  "CAP_DOCS_SCHEMA_INVALID",
  "CAP_DOCS_EXAMPLE_INVALID",
] as const;

type Binding = { readonly schema: JsonSchema } | { readonly $ref: string };
type RecordData = Record<string, JsonValue>;
type Capability = {
  readonly id: string;
  readonly version: string;
  readonly summary: string;
  readonly description?: string;
  readonly tags: readonly string[];
  readonly input: Binding;
  readonly output: Binding;
  readonly errors: Readonly<
    Record<
      string,
      {
        readonly status: string;
        readonly message: string;
        readonly retryable: boolean;
        readonly details?: Binding;
      }
    >
  >;
  readonly access: {
    readonly authentication: string;
    readonly permissions: JsonValue;
    readonly exposure: Readonly<Record<string, string>>;
  };
  readonly effects: RecordData;
  readonly execution: JsonValue;
  readonly requirements: {
    readonly secrets: readonly {
      readonly name: string;
      readonly optional: boolean;
      readonly description?: string;
    }[];
    readonly resources: readonly {
      readonly name: string;
      readonly kind: string;
      readonly optional: boolean;
    }[];
    readonly environment: readonly {
      readonly name: string;
      readonly presence: string;
      readonly sensitive: boolean;
    }[];
  };
  readonly limits: JsonValue;
  readonly lifecycle: {
    readonly status: string;
    readonly since?: string;
    readonly deprecatedAt?: string;
    readonly sunsetAt?: string;
    readonly replacement?: string;
  };
  readonly interfaces: Readonly<Record<string, RecordData>>;
  readonly examples: readonly {
    readonly name: string;
    readonly description?: string;
    readonly input: JsonValue;
    readonly output?: JsonValue;
    readonly error?: { readonly code: string; readonly details?: JsonValue };
  }[];
};
type Document = {
  readonly irVersion: string;
  readonly service: { readonly name: string; readonly version: string };
  readonly schemas: Readonly<Record<string, JsonSchema>>;
  readonly capabilities: readonly Capability[];
};
export interface DocsSchemaOptions {
  readonly irHash: string;
  readonly profile?: "private" | "public";
  readonly sensitiveRequirementNames?: readonly string[];
  readonly cliBinary?: string;
}
export interface DocsSchemaDiagnostic {
  readonly code: (typeof DOCS_SCHEMA_DIAGNOSTIC_CODES)[number];
  readonly severity: "error";
  readonly message: string;
  readonly path?: string;
  readonly capabilityId?: string;
}
export type DocsSchemaResult =
  | {
      readonly ok: true;
      readonly bytes: Uint8Array;
      readonly entries: readonly {
        readonly path: string;
        readonly bytes: Uint8Array;
      }[];
    }
  | {
      readonly ok: false;
      readonly diagnostics: readonly DocsSchemaDiagnostic[];
    };

const encoder = new TextEncoder();
const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const json = (value: JsonValue) => encoder.encode(jcs(value));
const clone = <T extends JsonValue>(value: T): T => JSON.parse(jcs(value)) as T;
const pointer = (value: string) =>
  value.replaceAll("~", "~0").replaceAll("/", "~1");
const unpointer = (value: string) =>
  value.replaceAll("~1", "/").replaceAll("~0", "~");
const segment = (value: string) => {
  const encoded = encodeURIComponent(value).replaceAll("%", "_");
  return encoded.length <= 48
    ? encoded
    : `h-${createHash("sha256").update(value, "utf8").digest("hex").slice(0, 48)}`;
};
const issue = (
  code: DocsSchemaDiagnostic["code"],
  message: string,
  path?: string,
  capabilityId?: string,
): DocsSchemaResult => ({
  ok: false,
  diagnostics: [
    {
      code,
      severity: "error",
      message,
      ...(path === undefined ? {} : { path }),
      ...(capabilityId === undefined ? {} : { capabilityId }),
    },
  ],
});

function exposed(
  capability: Capability,
  name: string,
  profile: "private" | "public",
): RecordData | undefined {
  const projection = capability.interfaces[name];
  if (projection?.enabled !== true) return undefined;
  if (name === "sdk") return projection;
  const level = capability.access.exposure[name];
  return profile === "public"
    ? level === "public"
      ? projection
      : undefined
    : level !== "disabled"
      ? projection
      : undefined;
}

function visible(
  capability: Capability,
  profile: "private" | "public",
): boolean {
  return (
    profile === "private" ||
    ["http", "cli", "mcp"].some((name) => exposed(capability, name, profile))
  );
}

function selectedShared(
  document: Document,
  capabilities: readonly Capability[],
): Document["schemas"] {
  const names = new Set<string>();
  const scanReference = (reference: string) => {
    if (reference.startsWith("#/schemas/")) {
      const name = unpointer(reference.slice(10));
      if (!Object.hasOwn(document.schemas, name))
        throw new Error("unresolved shared reference");
      if (!names.has(name)) {
        names.add(name);
        scanSchema(document.schemas[name]!);
      }
    }
  };
  const scanSchema = (schema: JsonSchema): void => {
    if (typeof schema.$ref === "string") scanReference(schema.$ref);
    for (const child of Object.values(schema.$defs ?? {}))
      scanSchema(child as JsonSchema);
    for (const child of Object.values(schema.properties ?? {}))
      scanSchema(child as JsonSchema);
    if (schema.items && typeof schema.items === "object")
      scanSchema(schema.items as JsonSchema);
    for (const child of (schema.oneOf ?? []) as readonly JsonSchema[])
      scanSchema(child);
  };
  const scanBinding = (binding: Binding) => {
    if ("$ref" in binding) scanReference(binding.$ref);
    else scanSchema(binding.schema);
  };
  for (const capability of capabilities) {
    scanBinding(capability.input);
    scanBinding(capability.output);
    for (const error of Object.values(capability.errors))
      if (error.details) scanBinding(error.details);
  }
  return Object.fromEntries(
    [...names].sort(compare).map((name) => [name, document.schemas[name]!]),
  );
}

function rewrite(
  schema: JsonSchema,
  shared: Document["schemas"],
  root: string,
): JsonSchema {
  const out = clone(schema) as RecordData;
  if (typeof out.$ref === "string") {
    const ref = out.$ref;
    if (ref.startsWith("#/schemas/")) {
      const name = unpointer(ref.slice(10));
      if (!Object.hasOwn(shared, name))
        throw new Error("unresolved shared reference");
      out.$ref = `#/$defs/${pointer(`shared_${name}`)}`;
    } else if (ref.startsWith("#/$defs/")) {
      out.$ref = `#/$defs/${pointer(root)}/$defs/${ref.slice(8)}`;
    } else throw new Error("unsupported reference");
  }
  for (const key of ["properties", "$defs"] as const) {
    const children = out[key];
    if (children && typeof children === "object" && !Array.isArray(children))
      out[key] = Object.fromEntries(
        Object.entries(children).map(([name, child]) => [
          name,
          rewrite(child as JsonSchema, shared, root),
        ]),
      );
  }
  if (out.items && typeof out.items === "object" && !Array.isArray(out.items))
    out.items = rewrite(out.items as JsonSchema, shared, root);
  if (Array.isArray(out.oneOf))
    out.oneOf = out.oneOf.map((child) =>
      rewrite(child as JsonSchema, shared, root),
    );
  return out;
}

function definitions(
  binding: Binding,
  shared: Document["schemas"],
): RecordData {
  const defs: RecordData = {};
  for (const name of Object.keys(shared).sort(compare)) {
    const key = `shared_${name}`;
    defs[key] = rewrite(shared[name]!, shared, key);
  }
  defs.root = rewrite(
    "schema" in binding ? binding.schema : { $ref: binding.$ref },
    shared,
    "root",
  );
  return defs;
}

function standalone(
  binding: Binding,
  shared: Document["schemas"],
  identity: JsonValue,
): JsonSchema {
  return {
    $schema: JSON_SCHEMA_DIALECT,
    $ref: "#/$defs/root",
    $defs: definitions(binding, shared),
    "x-capaxle": identity,
  } as JsonSchema;
}

function cliResult(
  output: Binding,
  shared: Document["schemas"],
  identity: JsonValue,
): JsonSchema {
  const statuses = [
    "invalid_argument",
    "unauthenticated",
    "permission_denied",
    "not_found",
    "already_exists",
    "failed_precondition",
    "conflict",
    "resource_exhausted",
    "cancelled",
    "deadline_exceeded",
    "unavailable",
    "internal",
  ];
  return {
    $schema: JSON_SCHEMA_DIALECT,
    $defs: definitions(output, shared),
    oneOf: [
      {
        type: "object",
        additionalProperties: false,
        required: ["ok", "value", "correlationId"],
        properties: {
          ok: { const: true },
          value: { $ref: "#/$defs/root" },
          correlationId: { type: "string" },
        },
      },
      {
        type: "object",
        additionalProperties: false,
        required: ["ok", "error"],
        properties: {
          ok: { const: false },
          error: {
            type: "object",
            additionalProperties: false,
            required: [
              "code",
              "status",
              "message",
              "retryable",
              "correlationId",
            ],
            properties: {
              code: { type: "string" },
              status: { enum: statuses },
              message: { type: "string" },
              retryable: { type: "boolean" },
              correlationId: { type: "string" },
              details: {},
            },
          },
        },
      },
    ],
    "x-capaxle": identity,
  } as JsonSchema;
}

function disclosedRequirements(
  capability: Capability,
  hidden: ReadonlySet<string>,
  profile: "private" | "public",
): JsonValue {
  if (profile === "private")
    return clone(capability.requirements as unknown as JsonValue);
  return {
    secrets: capability.requirements.secrets
      .filter((item) => !hidden.has(item.name))
      .map((item) => clone(item as unknown as JsonValue)),
    resources: capability.requirements.resources
      .filter((item) => !hidden.has(item.name))
      .map((item) => clone(item as unknown as JsonValue)),
    environment: capability.requirements.environment
      .filter((item) => !item.sensitive && !hidden.has(item.name))
      .map((item) => clone(item as unknown as JsonValue)),
  };
}

function markdown(
  capability: Capability,
  document: Document,
  options: DocsSchemaOptions,
  hidden: ReadonlySet<string>,
  profile: "private" | "public",
  included: readonly Capability[],
): string {
  const base = `${segment(capability.id)}/${segment(capability.version)}`;
  const lines = [
    `# ${capability.id}@${capability.version}`,
    "",
    capability.summary,
    ...(capability.description ? ["", capability.description] : []),
    "",
    `- Lifecycle: ${capability.lifecycle.status}${capability.lifecycle.since === undefined ? "" : ` (since ${capability.lifecycle.since})`}`,
    `- Impact: ${capability.effects.impact}`,
    `- Confirmation: ${capability.effects.confirmation}`,
    `- Authentication: ${capability.access.authentication}`,
    "- Dry-run: unavailable in Capability IR 0.1",
    `- Permissions: \`${jcs(capability.access.permissions)}\``,
    `- Generator version: ${DOCS_SCHEMA_GENERATOR_VERSION}`,
    `- IR hash: ${options.irHash}`,
    `- Service: ${document.service.name}@${document.service.version}`,
  ];
  if (capability.effects.impact === "destructive")
    lines.push("- Warning: destructive capability");
  if (capability.effects.confirmation === "required")
    lines.push("- Warning: confirmation required");
  if (capability.lifecycle.status === "deprecated")
    lines.push("- Warning: deprecated capability");
  if (
    !["http", "cli", "mcp"].some((name) => exposed(capability, name, "public"))
  )
    lines.push("- Visibility: private");
  const sections: [string, JsonValue][] = [
    ["Lifecycle", clone(capability.lifecycle as unknown as JsonValue)],
    ["Effects", capability.effects],
    ["Execution", capability.execution],
    ["Rate limits", capability.limits],
    ["Requirements", disclosedRequirements(capability, hidden, profile)],
    ["Declared errors", clone(capability.errors as unknown as JsonValue)],
  ];
  for (const [title, data] of sections)
    lines.push("", `## ${title}`, "", "```json", jcs(data), "```");
  lines.push(
    "",
    "## Schemas",
    "",
    `- [Input](../../../schemas/capabilities/${base}/input.schema.json)`,
    `- [Output payload](../../../schemas/capabilities/${base}/output.schema.json)`,
    `- [CLI JSON result](../../../schemas/capabilities/${base}/cli-result.schema.json)`,
    "- [Shared schemas](../../../schemas/shared.schema.json)",
  );
  lines.push("", "## Interfaces", "");
  for (const name of ["http", "cli", "mcp", "sdk"]) {
    const item = exposed(capability, name, profile);
    if (!item) continue;
    const form =
      name === "http"
        ? `${item.method} ${item.path}`
        : name === "cli"
          ? `${options.cliBinary ?? "<application-cli>"} ${(item.command as string[]).join(" ")}`
          : name === "mcp"
            ? String(item.toolName)
            : (item.path as string[]).join(".");
    const level =
      name === "sdk" ? "projection" : capability.access.exposure[name];
    lines.push(`- ${name.toUpperCase()} (${level}): \`${form}\``);
    if (name === "cli" && options.cliBinary === undefined)
      lines.push(
        "  - Replace `<application-cli>` with the configured application CLI binary.",
      );
  }
  const related = included.filter(
    (other) =>
      other !== capability &&
      other.interfaces.docs?.enabled === true &&
      other.tags.some((tag) => capability.tags.includes(tag)),
  );
  if (related.length) {
    lines.push("", "## Related capabilities", "");
    for (const other of related)
      lines.push(
        `- [${other.id}@${other.version}](../${segment(other.id)}/${segment(other.version)}.md)`,
      );
  }
  if (capability.examples.length) {
    lines.push("", "## Verified examples", "");
    for (const example of capability.examples) {
      lines.push(`### ${example.name}`, "");
      if (example.description) lines.push(example.description, "");
      lines.push("Input:", "", "```json", jcs(example.input), "```");
      if (example.output !== undefined)
        lines.push("", "Output:", "", "```json", jcs(example.output), "```");
      if (example.error !== undefined)
        lines.push(
          "",
          "Error:",
          "",
          "```json",
          jcs(example.error as unknown as JsonValue),
          "```",
        );
    }
  }
  return `${lines.join("\n")}\n`;
}

function tar(
  entries: readonly { readonly path: string; readonly bytes: Uint8Array }[],
): Uint8Array {
  const chunks: Uint8Array[] = [];
  const write = (
    header: Uint8Array,
    start: number,
    length: number,
    value: string,
  ) => {
    const bytes = encoder.encode(value);
    if (bytes.length > length) throw new Error("archive path too long");
    header.set(bytes, start);
  };
  const octal = (value: number, length: number) =>
    value.toString(8).padStart(length - 1, "0") + "\0";
  for (const entry of entries) {
    if (
      entry.path.startsWith("/") ||
      entry.path
        .split("/")
        .some((part) => !part || part === "." || part === "..")
    )
      throw new Error("unsafe archive path");
    const header = new Uint8Array(512);
    const pathBytes = encoder.encode(entry.path);
    let name = entry.path;
    let prefix = "";
    if (pathBytes.length > 100) {
      const parts = entry.path.split("/");
      name = parts.pop()!;
      prefix = parts.join("/");
      if (
        encoder.encode(name).length > 100 ||
        encoder.encode(prefix).length > 155
      )
        throw new Error("archive path too long");
    }
    write(header, 0, 100, name);
    if (prefix) write(header, 345, 155, prefix);
    write(header, 100, 8, octal(0o644, 8));
    write(header, 108, 8, octal(0, 8));
    write(header, 116, 8, octal(0, 8));
    write(header, 124, 12, octal(entry.bytes.length, 12));
    write(header, 136, 12, octal(0, 12));
    write(header, 148, 8, "        ");
    write(header, 156, 1, "0");
    write(header, 257, 6, "ustar\0");
    write(header, 263, 2, "00");
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    write(header, 148, 8, octal(checksum, 8));
    chunks.push(
      header,
      entry.bytes,
      new Uint8Array((512 - (entry.bytes.length % 512)) % 512),
    );
  }
  chunks.push(new Uint8Array(1024));
  const result = new Uint8Array(
    chunks.reduce((sum, chunk) => sum + chunk.length, 0),
  );
  let cursor = 0;
  for (const chunk of chunks) {
    result.set(chunk, cursor);
    cursor += chunk.length;
  }
  return result;
}

/** Projects normalized Capability IR into deterministic, separate archive members. */
export function generateDocsSchemaArchive(
  source: unknown,
  options: DocsSchemaOptions,
): DocsSchemaResult {
  if (
    !options ||
    typeof options.irHash !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(options.irHash)
  )
    return issue(
      "CAP_BUILD_CONTEXT_INVALID",
      "Missing or malformed IR hash.",
      "/buildContext/irHash",
    );
  const validation = validateCapabilityDocument(source, {
    requireNormalized: true,
  });
  if (validation.length)
    return issue(
      "CAP_DOCS_SCHEMA_INVALID",
      "Capability IR validation failed.",
      validation[0]?.path ?? "",
    );
  if (capabilitySemanticHash(source) !== options.irHash)
    return issue(
      "CAP_BUILD_CONTEXT_INVALID",
      "IR hash does not match Capability IR.",
      "/buildContext/irHash",
    );
  if (
    options.profile !== undefined &&
    options.profile !== "private" &&
    options.profile !== "public"
  )
    return issue(
      "CAP_DOCS_SCHEMA_INVALID",
      "Unsupported disclosure profile.",
      "/profile",
    );
  if (
    options.cliBinary !== undefined &&
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(options.cliBinary)
  )
    return issue(
      "CAP_BUILD_CONTEXT_INVALID",
      "Invalid CLI binary.",
      "/buildContext/cliBinary",
    );
  if (
    options.sensitiveRequirementNames !== undefined &&
    (!Array.isArray(options.sensitiveRequirementNames) ||
      options.sensitiveRequirementNames.some(
        (name) => typeof name !== "string" || !name,
      ))
  )
    return issue(
      "CAP_DOCS_SCHEMA_INVALID",
      "Invalid sensitive requirement names.",
      "/sensitiveRequirementNames",
    );
  const document = source as Document;
  const profile = options.profile ?? "private";
  const hidden = new Set(options.sensitiveRequirementNames ?? []);
  const provenance = {
    generatorVersion: DOCS_SCHEMA_GENERATOR_VERSION,
    irHash: options.irHash,
    irVersion: document.irVersion,
    service: document.service,
  };
  const entries: { path: string; bytes: Uint8Array }[] = [];
  const add = (path: string, bytes: Uint8Array) =>
    entries.push({ path, bytes });
  const addJson = (path: string, value: JsonValue) => add(path, json(value));
  const examples: JsonValue[] = [];
  const manifest: JsonValue[] = [];
  try {
    const included = document.capabilities.filter((item) =>
      visible(item, profile),
    );
    if (profile === "public")
      for (const capability of included)
        for (const item of capability.requirements.environment)
          if (item.sensitive) hidden.add(item.name);
    const shared =
      profile === "private"
        ? document.schemas
        : selectedShared(document, included);
    addJson("schemas/capability-ir.schema.json", {
      ...clone(CAPABILITY_IR_SCHEMA),
      "x-capaxle": provenance,
    });
    const sharedDefs: RecordData = {};
    for (const name of Object.keys(shared).sort(compare)) {
      const key = `shared_${name}`;
      sharedDefs[key] = rewrite(shared[name]!, shared, key);
    }
    addJson("schemas/shared.schema.json", {
      $schema: JSON_SCHEMA_DIALECT,
      $defs: sharedDefs,
      "x-capaxle": provenance,
    });
    for (const capability of included) {
      const base = `${segment(capability.id)}/${segment(capability.version)}`;
      const schemaBase = `schemas/capabilities/${base}`;
      const page = `docs/capabilities/${base}.md`;
      const identity = {
        capabilityId: capability.id,
        capabilityVersion: capability.version,
        ...provenance,
      };
      addJson(
        `${schemaBase}/input.schema.json`,
        standalone(capability.input, shared, { ...identity, role: "input" }),
      );
      addJson(
        `${schemaBase}/output.schema.json`,
        standalone(capability.output, shared, { ...identity, role: "output" }),
      );
      addJson(
        `${schemaBase}/cli-result.schema.json`,
        cliResult(capability.output, shared, {
          ...identity,
          role: "cli-result",
        }),
      );
      const errors: Record<string, string> = {};
      for (const code of Object.keys(capability.errors).sort(compare)) {
        const binding = capability.errors[code]!.details;
        if (!binding) continue;
        const path = `${schemaBase}/errors/${segment(code)}.schema.json`;
        addJson(
          path,
          standalone(binding, shared, {
            ...identity,
            role: "error-detail",
            errorCode: code,
          }),
        );
        errors[code] = path;
      }
      for (const example of capability.examples) {
        if (
          !canonicalizeInput(document, capability, example.input).valid ||
          (example.output !== undefined &&
            !validateSchemaValue(document, capability.output, example.output)
              .valid) ||
          (example.error !== undefined &&
            (!Object.hasOwn(capability.errors, example.error.code) ||
              (example.error.details !== undefined &&
                (!capability.errors[example.error.code]!.details ||
                  !validateSchemaValue(
                    document,
                    capability.errors[example.error.code]!.details!,
                    example.error.details,
                  ).valid))))
        )
          return issue(
            "CAP_DOCS_EXAMPLE_INVALID",
            "Example does not validate against canonical schemas.",
            "/examples",
            capability.id,
          );
        examples.push({
          capabilityId: capability.id,
          capabilityVersion: capability.version,
          name: example.name,
          ...(example.description === undefined
            ? {}
            : { description: example.description }),
          input: example.input,
          ...(example.output === undefined ? {} : { output: example.output }),
          ...(example.error === undefined
            ? {}
            : { error: example.error as unknown as JsonValue }),
        });
      }
      if (capability.interfaces.docs?.enabled === true)
        add(
          page,
          encoder.encode(
            markdown(capability, document, options, hidden, profile, included),
          ),
        );
      manifest.push({
        id: capability.id,
        version: capability.version,
        ...(capability.interfaces.docs?.enabled === true ? { page } : {}),
        schemas: {
          input: `${schemaBase}/input.schema.json`,
          output: `${schemaBase}/output.schema.json`,
          cliResult: `${schemaBase}/cli-result.schema.json`,
          errors,
        },
      });
    }
    addJson("fixtures/examples.json", { ...provenance, examples });
    addJson("manifest.json", {
      ...provenance,
      profile,
      capabilities: manifest,
    });
    entries.sort((a, b) => compare(a.path, b.path));
    if (new Set(entries.map((entry) => entry.path)).size !== entries.length)
      throw new Error("duplicate archive path");
    if (profile === "public") {
      const decoder = new TextDecoder();
      for (const entry of entries) {
        const contents = decoder.decode(entry.bytes);
        if (
          [...hidden].some(
            (name) => entry.path.includes(name) || contents.includes(name),
          )
        )
          return issue(
            "CAP_DOCS_SCHEMA_INVALID",
            "Sensitive requirement name occurs outside redacted declarations.",
            "/sensitiveRequirementNames",
          );
      }
    }
    return { ok: true, bytes: tar(entries), entries };
  } catch {
    return issue(
      "CAP_DOCS_SCHEMA_INVALID",
      "Schema or archive generation failed.",
    );
  }
}
