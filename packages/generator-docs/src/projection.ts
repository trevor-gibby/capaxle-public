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

export const DOCS_SCHEMA_GENERATOR_VERSION = "0.1.0-alpha.3";
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
  readonly service: {
    readonly name: string;
    readonly version: string;
    readonly title?: string;
    readonly description?: string;
  };
  readonly schemas: Readonly<Record<string, JsonSchema>>;
  readonly capabilities: readonly Capability[];
};

export interface DocumentationCapability {
  readonly id: string;
  readonly version: string;
  readonly page: string;
  readonly groupPath: readonly string[];
  readonly summary: string;
  readonly description?: string;
  readonly authentication: string;
  readonly permissionsSummary: string;
  readonly impact: string;
  readonly confirmation: string;
  readonly idempotency: string;
  readonly lifecycle: Capability["lifecycle"];
  readonly inputSchema: JsonValue;
  readonly outputSchema: JsonValue;
  readonly errors: readonly {
    readonly code: string;
    readonly status: string;
    readonly message: string;
    readonly retryable: boolean;
    readonly detailsSchema?: JsonValue;
  }[];
  readonly interfaces: Readonly<Record<string, JsonValue>>;
  readonly examples: Capability["examples"];
}
export interface DocumentationModel {
  readonly modelVersion: "0.1";
  readonly irHash: string;
  readonly profile: "public" | "private" | "live";
  readonly service: Document["service"];
  readonly capabilities: readonly DocumentationCapability[];
}

/** Structured consumer data, separate from the stable Markdown archive contract. */
export function projectDocumentationModel(
  source: unknown,
  options: {
    readonly irHash: string;
    readonly profile: "public" | "private" | "live";
    readonly enabledInterfaces?: readonly ("http" | "cli" | "mcp")[];
    readonly visibleInterfaces?: readonly DocumentationVisibility[];
    readonly cliBinary?: string;
    readonly sensitiveRequirementNames?: readonly string[];
  },
):
  | { readonly ok: true; readonly model: DocumentationModel }
  | Extract<DocsSchemaResult, { readonly ok: false }> {
  if (
    !options ||
    !["public", "private", "live"].includes(options.profile) ||
    (options.profile === "live"
      ? !Array.isArray(options.visibleInterfaces)
      : options.visibleInterfaces !== undefined)
  )
    return issue(
      "CAP_DOCS_SCHEMA_INVALID",
      "Invalid browser model disclosure profile or selection.",
      "/profile",
    ) as Extract<DocsSchemaResult, { readonly ok: false }>;
  const { profile, visibleInterfaces, ...common } = options;
  const generated = generateDocumentationEntries(
    source,
    { ...common, profile: profile === "live" ? "public" : profile },
    profile === "live" ? visibleInterfaces : undefined,
  );
  if (!generated.ok) return generated;
  const decoder = new TextDecoder();
  const entries = new Map(
    generated.entries.map(({ path, bytes }) => [path, decoder.decode(bytes)]),
  );
  const manifest = JSON.parse(entries.get("manifest.json")!) as {
    capabilities: {
      id: string;
      version: string;
      page?: string;
      schemas: {
        input: string;
        output: string;
        errors: Record<string, string>;
      };
    }[];
  };
  const document = source as Document;
  const enabled =
    options.enabledInterfaces === undefined
      ? new Set(["http", "cli", "mcp"])
      : new Set(options.enabledInterfaces);
  const selected =
    visibleInterfaces === undefined
      ? undefined
      : new Set(
          visibleInterfaces.map((item) =>
            visibilityKey(item.id, item.version, item.interface),
          ),
        );
  const capabilities: DocumentationCapability[] = [];
  const hidden = new Set(options.sensitiveRequirementNames ?? []);
  if (profile !== "private")
    for (const member of manifest.capabilities)
      for (const environment of document.capabilities.find(
        (item) => item.id === member.id && item.version === member.version,
      )!.requirements.environment)
        if (environment.sensitive) hidden.add(environment.name);
  for (const member of manifest.capabilities) {
    if (member.page === undefined) continue;
    const capability = document.capabilities.find(
      (item) => item.id === member.id && item.version === member.version,
    )!;
    const interfaces: Record<string, JsonValue> = {};
    for (const name of ["http", "cli", "mcp"] as const) {
      const projection = capability.interfaces[name];
      const exposure = capability.access.exposure[name];
      if (
        projection?.enabled !== true ||
        !enabled.has(name) ||
        exposure === "disabled" ||
        (profile === "public" && exposure !== "public") ||
        (profile === "live" &&
          (exposure === "private" ||
            !selected?.has(
              visibilityKey(capability.id, capability.version, name),
            )))
      )
        continue;
      interfaces[name] = clone(projection);
    }
    if (profile !== "private" && !Object.keys(interfaces).length) continue;
    if (interfaces.http && capability.interfaces.sdk?.enabled === true)
      interfaces.sdk = clone(capability.interfaces.sdk);
    const group =
      typeof capability.interfaces.docs?.group === "string"
        ? capability.interfaces.docs.group
            .split("/")
            .map((label) => label.trim())
            .filter(Boolean)
        : [];
    capabilities.push({
      id: capability.id,
      version: capability.version,
      page: member.page,
      groupPath: group.length ? group : capability.id.split(".").slice(0, -1),
      summary: capability.summary,
      ...(capability.description === undefined
        ? {}
        : { description: capability.description }),
      authentication: capability.access.authentication,
      permissionsSummary: Object.values(
        capability.access.permissions as Record<string, JsonValue>,
      ).some((value) => Array.isArray(value) && value.length)
        ? "Application authorization required."
        : "No additional application permissions declared.",
      impact: String(capability.effects.impact),
      confirmation: String(capability.effects.confirmation),
      idempotency: String(capability.effects.idempotency),
      lifecycle: clone(
        capability.lifecycle as unknown as JsonValue,
      ) as unknown as Capability["lifecycle"],
      inputSchema: JSON.parse(entries.get(member.schemas.input)!) as JsonValue,
      outputSchema: JSON.parse(
        entries.get(member.schemas.output)!,
      ) as JsonValue,
      errors: Object.entries(capability.errors)
        .sort(([a], [b]) => compare(a, b))
        .map(([code, error]) => ({
          code,
          status: error.status,
          message: error.message,
          retryable: error.retryable,
          ...(member.schemas.errors[code] === undefined
            ? {}
            : {
                detailsSchema: JSON.parse(
                  entries.get(member.schemas.errors[code])!,
                ) as JsonValue,
              }),
        })),
      interfaces,
      examples: clone(
        capability.examples as unknown as JsonValue,
      ) as unknown as Capability["examples"],
    });
  }
  const model: DocumentationModel = {
    modelVersion: "0.1",
    irHash: options.irHash,
    profile,
    service: {
      name: document.service.name,
      version: document.service.version,
      ...(document.service.title === undefined
        ? {}
        : { title: document.service.title }),
      ...(document.service.description === undefined
        ? {}
        : { description: document.service.description }),
    },
    capabilities,
  };
  if (
    profile !== "private" &&
    [...hidden].some((name) => JSON.stringify(model).includes(name))
  )
    return issue(
      "CAP_DOCS_SCHEMA_INVALID",
      "Sensitive name occurs in browser consumer data.",
      "/sensitiveRequirementNames",
    ) as Extract<DocsSchemaResult, { readonly ok: false }>;
  return { ok: true, model };
}
export interface DocsSchemaOptions {
  readonly irHash: string;
  readonly profile?: "private" | "public";
  readonly sensitiveRequirementNames?: readonly string[];
  readonly cliBinary?: string;
  readonly enabledInterfaces?: readonly ("http" | "cli" | "mcp")[];
}
export interface DocumentationVisibility {
  readonly id: string;
  readonly version: string;
  readonly interface: "http" | "cli" | "mcp";
}
type Profile = "private" | "public" | "live";
interface Selection {
  readonly enabled?: ReadonlySet<string>;
  readonly visible?: ReadonlySet<string>;
}
const visibilityKey = (id: string, version: string, name: string) =>
  `${id}\u0000${version}\u0000${name}`;
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
type DocumentationEntriesResult =
  | {
      readonly ok: true;
      readonly entries: readonly {
        readonly path: string;
        readonly bytes: Uint8Array;
      }[];
    }
  | Extract<DocsSchemaResult, { readonly ok: false }>;

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
): DocumentationEntriesResult => ({
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
  profile: Profile,
  selection: Selection,
): RecordData | undefined {
  const projection = capability.interfaces[name];
  if (projection?.enabled !== true) return undefined;
  if (name === "sdk")
    return selection.enabled !== undefined || selection.visible !== undefined
      ? exposed(capability, "http", profile, selection)
        ? projection
        : undefined
      : projection;
  if (selection.enabled !== undefined && !selection.enabled.has(name))
    return undefined;
  if (
    selection.visible !== undefined &&
    !selection.visible.has(
      visibilityKey(capability.id, capability.version, name),
    )
  )
    return undefined;
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
  profile: Profile,
  selection: Selection,
): boolean {
  return (
    profile === "private" ||
    ["http", "cli", "mcp"].some((name) =>
      exposed(capability, name, profile, selection),
    )
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
  profile: Profile,
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
  profile: Profile,
  included: readonly Capability[],
  selection: Selection,
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
    !["http", "cli", "mcp"].some((name) =>
      exposed(capability, name, "public", selection),
    )
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
    const item = exposed(capability, name, profile, selection);
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

/** Projects normalized Capability IR into deterministic, separate archive members. */
export function generateDocumentationEntries(
  source: unknown,
  options: DocsSchemaOptions,
  requestVisibility?: readonly DocumentationVisibility[],
): DocumentationEntriesResult {
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
  if (
    options.enabledInterfaces !== undefined &&
    (!Array.isArray(options.enabledInterfaces) ||
      options.enabledInterfaces.some(
        (name) => !["http", "cli", "mcp"].includes(name),
      ) ||
      new Set(options.enabledInterfaces).size !==
        options.enabledInterfaces.length)
  )
    return issue(
      "CAP_DOCS_SCHEMA_INVALID",
      "Invalid enabled documentation interfaces.",
      "/enabledInterfaces",
    );
  const enabled =
    options.enabledInterfaces === undefined
      ? undefined
      : new Set(options.enabledInterfaces);
  let selected: Set<string> | undefined;
  if (requestVisibility !== undefined) {
    if (!Array.isArray(requestVisibility))
      return issue(
        "CAP_DOCS_SCHEMA_INVALID",
        "Invalid documentation visibility selection.",
        "/visibleInterfaces",
      );
    selected = new Set();
    for (const item of requestVisibility) {
      if (
        !item ||
        typeof item !== "object" ||
        Object.keys(item).some(
          (key) => !["id", "version", "interface"].includes(key),
        ) ||
        typeof item.id !== "string" ||
        typeof item.version !== "string" ||
        !["http", "cli", "mcp"].includes(item.interface)
      )
        return issue(
          "CAP_DOCS_SCHEMA_INVALID",
          "Invalid documentation visibility identity.",
          "/visibleInterfaces",
        );
      const capability = document.capabilities.find(
        (capability) =>
          capability.id === item.id && capability.version === item.version,
      );
      const key = visibilityKey(item.id, item.version, item.interface);
      if (
        !capability ||
        capability.interfaces[item.interface]?.enabled !== true ||
        capability.access.exposure[item.interface] === "disabled" ||
        capability.access.exposure[item.interface] === "private" ||
        (enabled !== undefined && !enabled.has(item.interface)) ||
        selected.has(key)
      )
        return issue(
          "CAP_DOCS_SCHEMA_INVALID",
          "Unknown, duplicate or disabled documentation visibility selection.",
          "/visibleInterfaces",
        );
      selected.add(key);
    }
  }
  const selection: Selection = {
    ...(enabled === undefined ? {} : { enabled }),
    ...(selected === undefined ? {} : { visible: selected }),
  };
  const profile: Profile =
    selected === undefined ? (options.profile ?? "private") : "live";
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
      visible(item, profile, selection),
    );
    if (profile !== "private")
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
            markdown(
              capability,
              document,
              options,
              hidden,
              profile,
              included,
              selection,
            ),
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
    if (profile !== "private") {
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
    return { ok: true, entries };
  } catch {
    return issue(
      "CAP_DOCS_SCHEMA_INVALID",
      "Schema or archive generation failed.",
    );
  }
}
