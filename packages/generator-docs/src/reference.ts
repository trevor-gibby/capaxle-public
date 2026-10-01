import { jcs, type JsonValue } from "@capaxle/ir";
import { createHash } from "node:crypto";
import type {
  DocumentationCapability,
  DocumentationModel,
} from "./projection.js";
import {
  DocumentationBrowserError,
  type DocumentationBundle,
  type DocumentationConnection,
} from "./browser.js";

const escape = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ]!,
  );
const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const record = (value: JsonValue | undefined): Record<string, JsonValue> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, JsonValue>)
    : {};
const json = (value: JsonValue) =>
  `<pre><code>${escape(JSON.stringify(value, null, 2))}</code></pre>`;
const plainObject = (value: unknown): value is Record<string, unknown> =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(value));
const closed = (
  value: unknown,
  allowed: readonly string[],
  required: readonly string[] = [],
) =>
  plainObject(value) &&
  Object.keys(value).every((key) => allowed.includes(key)) &&
  required.every((key) => Object.hasOwn(value, key));
const strings = (
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
) =>
  required.every((key) => typeof value[key] === "string") &&
  optional.every(
    (key) => !Object.hasOwn(value, key) || typeof value[key] === "string",
  );
const jsonData = (value: unknown, ancestors = new Set<object>()): boolean => {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (
    typeof value !== "object" ||
    (!Array.isArray(value) && !plainObject(value)) ||
    ancestors.has(value)
  )
    return false;
  const next = new Set(ancestors);
  next.add(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return Reflect.ownKeys(value).every((key) => {
    if (Array.isArray(value) && key === "length") return true;
    if (typeof key !== "string") return false;
    const descriptor = descriptors[key]!;
    return (
      descriptor.enumerable === true &&
      Object.hasOwn(descriptor, "value") &&
      jsonData(descriptor.value, next)
    );
  });
};
const schemaShape = (value: unknown): boolean => {
  if (typeof value === "boolean") return true;
  if (
    !plainObject(value) ||
    !closed(value, [
      "$schema",
      "$ref",
      "$defs",
      "type",
      "enum",
      "const",
      "properties",
      "required",
      "additionalProperties",
      "items",
      "minimum",
      "maximum",
      "exclusiveMinimum",
      "exclusiveMaximum",
      "multipleOf",
      "minLength",
      "maxLength",
      "pattern",
      "format",
      "minItems",
      "maxItems",
      "uniqueItems",
      "description",
      "default",
      "examples",
      "oneOf",
      "x-capaxle",
    ])
  )
    return false;
  for (const key of ["$schema", "$ref", "pattern", "format", "description"])
    if (Object.hasOwn(value, key) && typeof value[key] !== "string")
      return false;
  const types = [
    "null",
    "boolean",
    "object",
    "array",
    "number",
    "string",
    "integer",
  ];
  if (
    Object.hasOwn(value, "type") &&
    !(typeof value.type === "string"
      ? types.includes(value.type)
      : Array.isArray(value.type) &&
        value.type.length > 0 &&
        value.type.every(
          (type) => typeof type === "string" && types.includes(type),
        ))
  )
    return false;
  for (const key of ["$defs", "properties"])
    if (
      Object.hasOwn(value, key) &&
      (!plainObject(value[key]) ||
        !Object.values(value[key]).every(schemaShape))
    )
      return false;
  if (
    Object.hasOwn(value, "required") &&
    (!Array.isArray(value.required) ||
      !value.required.every(
        (field) => typeof field === "string" && field.length > 0,
      ))
  )
    return false;
  if (Object.hasOwn(value, "items") && !schemaShape(value.items)) return false;
  if (
    Object.hasOwn(value, "oneOf") &&
    (!Array.isArray(value.oneOf) ||
      value.oneOf.length < 2 ||
      !value.oneOf.every(schemaShape))
  )
    return false;
  for (const key of [
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
  ])
    if (Object.hasOwn(value, key) && typeof value[key] !== "number")
      return false;
  for (const key of ["additionalProperties", "uniqueItems"])
    if (Object.hasOwn(value, key) && typeof value[key] !== "boolean")
      return false;
  for (const key of ["enum", "examples"])
    if (Object.hasOwn(value, key) && !Array.isArray(value[key])) return false;
  if (Object.hasOwn(value, "x-capaxle") && !plainObject(value["x-capaxle"]))
    return false;
  return true;
};
const statusNames = [
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
function interfaceShape(name: string, value: unknown): boolean {
  if (!plainObject(value) || value.enabled !== true) return false;
  if (name === "http")
    return (
      closed(
        value,
        ["enabled", "method", "path", "bindings"],
        ["enabled", "method", "path", "bindings"],
      ) &&
      typeof value.method === "string" &&
      ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(value.method) &&
      typeof value.path === "string" &&
      value.path.startsWith("/") &&
      plainObject(value.bindings) &&
      Object.values(value.bindings).every(
        (binding) =>
          typeof binding === "string" &&
          ["path", "query", "header", "body"].includes(binding),
      )
    );
  if (name === "mcp")
    return (
      closed(value, ["enabled", "toolName"], ["enabled", "toolName"]) &&
      typeof value.toolName === "string" &&
      value.toolName.length > 0
    );
  if (name === "sdk")
    return (
      closed(value, ["enabled", "path"], ["enabled", "path"]) &&
      Array.isArray(value.path) &&
      value.path.length > 0 &&
      value.path.every((part) => typeof part === "string" && part.length > 0)
    );
  if (
    name !== "cli" ||
    !closed(
      value,
      ["enabled", "command", "bindings"],
      ["enabled", "command", "bindings"],
    ) ||
    !Array.isArray(value.command) ||
    !value.command.length ||
    !value.command.every(
      (part) => typeof part === "string" && part.length > 0,
    ) ||
    !plainObject(value.bindings)
  )
    return false;
  return Object.values(value.bindings).every(
    (binding) =>
      plainObject(binding) &&
      (binding.kind === "option"
        ? closed(binding, ["kind", "name"], ["kind", "name"]) &&
          typeof binding.name === "string" &&
          /^--[a-z0-9][a-z0-9-]*$/.test(binding.name)
        : binding.kind === "positional" &&
          closed(binding, ["kind", "index"], ["kind", "index"]) &&
          typeof binding.index === "number" &&
          Number.isInteger(binding.index) &&
          binding.index >= 0),
  );
}
export function validateConsumerModel(
  model: DocumentationModel,
  bundle: DocumentationBundle,
): boolean {
  if (!jsonData(model)) return false;
  try {
    jcs(model as unknown as JsonValue);
  } catch {
    return false;
  }
  if (
    !plainObject(model) ||
    !closed(
      model,
      ["modelVersion", "irHash", "profile", "service", "capabilities"],
      ["modelVersion", "irHash", "profile", "service", "capabilities"],
    )
  )
    return false;
  const manifest = record(bundle.manifest);
  if (
    model.modelVersion !== "0.1" ||
    typeof model.irHash !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(model.irHash) ||
    model.irHash !== manifest.irHash ||
    typeof model.profile !== "string" ||
    !["private", "public", "live"].includes(model.profile) ||
    model.profile !== manifest.profile ||
    !plainObject(model.service) ||
    !closed(
      model.service,
      ["name", "version", "title", "description"],
      ["name", "version"],
    ) ||
    !strings(model.service, ["name", "version"], ["title", "description"]) ||
    !Array.isArray(model.capabilities)
  )
    return false;
  const service = record(manifest.service);
  if (
    (["name", "version", "title", "description"] as const).some(
      (key) => model.service[key] !== service[key],
    )
  )
    return false;
  const entries = Array.isArray(manifest.capabilities)
    ? manifest.capabilities.map(record)
    : [];
  const seen = new Set<string>();
  const capabilityKeys = [
    "id",
    "version",
    "page",
    "groupPath",
    "summary",
    "description",
    "authentication",
    "permissionsSummary",
    "impact",
    "confirmation",
    "idempotency",
    "lifecycle",
    "inputSchema",
    "outputSchema",
    "errors",
    "interfaces",
    "examples",
  ];
  for (const capability of model.capabilities as unknown[]) {
    if (
      !plainObject(capability) ||
      !closed(
        capability,
        capabilityKeys,
        capabilityKeys.filter((key) => key !== "description"),
      ) ||
      !strings(
        capability,
        [
          "id",
          "version",
          "page",
          "summary",
          "authentication",
          "permissionsSummary",
          "impact",
          "confirmation",
          "idempotency",
        ],
        ["description"],
      ) ||
      !Array.isArray(capability.groupPath) ||
      !capability.groupPath.every(
        (label) => typeof label === "string" && label.length > 0,
      ) ||
      !schemaShape(capability.inputSchema) ||
      !schemaShape(capability.outputSchema) ||
      !Array.isArray(capability.errors) ||
      !Array.isArray(capability.examples) ||
      !plainObject(capability.interfaces) ||
      !closed(capability.interfaces, ["http", "cli", "mcp", "sdk"]) ||
      Object.entries(capability.interfaces).some(
        ([name, value]) => !interfaceShape(name, value),
      )
    )
      return false;
    if (
      !["public", "optional", "required"].includes(
        String(capability.authentication),
      ) ||
      !["read", "write", "destructive"].includes(String(capability.impact)) ||
      !["none", "required"].includes(String(capability.confirmation)) ||
      !["none", "intrinsic", "key"].includes(String(capability.idempotency))
    )
      return false;
    if (
      !plainObject(capability.lifecycle) ||
      !closed(
        capability.lifecycle,
        ["status", "since", "deprecatedAt", "sunsetAt", "replacement"],
        ["status"],
      ) ||
      !strings(
        capability.lifecycle,
        ["status"],
        ["since", "deprecatedAt", "sunsetAt", "replacement"],
      ) ||
      !["experimental", "stable", "deprecated"].includes(
        String(capability.lifecycle.status),
      )
    )
      return false;
    const codes = new Set<string>();
    for (const error of capability.errors as unknown[]) {
      if (
        !plainObject(error) ||
        !closed(
          error,
          ["code", "status", "message", "retryable", "detailsSchema"],
          ["code", "status", "message", "retryable"],
        ) ||
        !strings(error, ["code", "status", "message"]) ||
        typeof error.retryable !== "boolean" ||
        !statusNames.includes(String(error.status)) ||
        (Object.hasOwn(error, "detailsSchema") &&
          !schemaShape(error.detailsSchema)) ||
        codes.has(String(error.code))
      )
        return false;
      codes.add(String(error.code));
    }
    for (const example of capability.examples as unknown[]) {
      if (
        !plainObject(example) ||
        !closed(
          example,
          ["name", "description", "input", "output", "error"],
          ["name", "input"],
        ) ||
        !strings(example, ["name"], ["description"]) ||
        (Object.hasOwn(example, "output") && Object.hasOwn(example, "error"))
      )
        return false;
      if (
        Object.hasOwn(example, "error") &&
        (!plainObject(example.error) ||
          !closed(example.error, ["code", "details"], ["code"]) ||
          typeof example.error.code !== "string" ||
          !codes.has(example.error.code))
      )
        return false;
    }
    if (
      !entries.some(
        (entry) =>
          entry.id === capability.id &&
          entry.version === capability.version &&
          entry.page === capability.page,
      ) ||
      seen.has(String(capability.page))
    )
      return false;
    seen.add(String(capability.page));
  }
  return (
    seen.size ===
    entries.filter((entry) => typeof entry.page === "string").length
  );
}

interface Group {
  readonly label: string;
  readonly depth: number;
  readonly parent: Group | undefined;
  readonly page: string;
  readonly children: Group[];
  readonly capabilities: DocumentationCapability[];
}
function groupLabels(group: Group): string[] {
  const labels: string[] = [];
  let current: Group | undefined = group;
  while (current !== undefined) {
    labels.push(current.label);
    current = current.parent;
  }
  return labels.reverse();
}
function tree(model: DocumentationModel) {
  const roots: Group[] = [];
  const groups = new Map<string, Group>();
  const ungrouped: DocumentationCapability[] = [];
  for (const capability of model.capabilities) {
    let children = roots;
    let parent: Group | undefined;
    const prefix = createHash("sha256").update("[");
    for (let i = 0; i < capability.groupPath.length; i++) {
      const label = capability.groupPath[i]!;
      if (i) prefix.update(",");
      prefix.update(jcs(label));
      // The copied prefix plus ']' hashes exactly jcs(the complete label path).
      const page = `groups/${prefix.copy().update("]").digest("hex")}`;
      let group = groups.get(page);
      if (
        group !== undefined &&
        (group.label !== label || group.parent?.page !== parent?.page)
      )
        throw new DocumentationBrowserError(
          "CAP_DOCS_BROWSER_INVALID",
          "Documentation group identity collision.",
        );
      if (!group) {
        group = {
          label,
          depth: i + 1,
          parent,
          page,
          children: [],
          capabilities: [],
        };
        groups.set(page, group);
        children.push(group);
      }
      parent = group;
      children = group.children;
    }
    if (parent) parent.capabilities.push(capability);
    else ungrouped.push(capability);
  }
  for (const group of groups.values()) {
    group.children.sort((a, b) => compare(a.label, b.label));
    group.capabilities.sort(
      (a, b) => compare(a.id, b.id) || compare(a.version, b.version),
    );
  }
  roots.sort((a, b) => compare(a.label, b.label));
  return { roots, groups, ungrouped };
}
type LinkContext = { readonly id?: string; readonly describedBy?: string };
type Link = (
  label: string,
  path: string,
  active?: boolean,
  context?: LinkContext,
) => string;
export function referenceNavigation(
  model: DocumentationModel,
  pageId: string,
  link: Link,
) {
  const data = tree(model);
  const labelId = (group: Group) =>
    `resource-${group.page.slice("groups/".length)}`;
  const capability = (item: DocumentationCapability, parent?: Group) =>
    `<li class="resource-item" data-depth="${parent ? parent.depth + 1 : 0}"${parent ? ` data-parent="${parent.page}"` : ""} style="--group-depth:${Math.min(parent?.depth ?? 0, 8)}">${link(`${item.id.split(".").at(-1)} @${item.version}`, item.page, pageId === item.page, parent ? { describedBy: labelId(parent) } : undefined)}</li>`;
  const items: string[] = [];
  const pending = [...data.roots].reverse();
  while (pending.length) {
    const group = pending.pop()!;
    items.push(
      `<li class="resource-item" data-depth="${group.depth}"${group.parent ? ` data-parent="${group.parent.page}"` : ""} style="--group-depth:${Math.min(group.depth - 1, 8)}">${link(group.label, group.page, pageId === group.page, { id: labelId(group), ...(group.parent ? { describedBy: labelId(group.parent) } : {}) })}${group.depth > 8 ? `<span class="resource-level">Level ${group.depth}</span>` : ""}</li>`,
    );
    for (const item of group.capabilities) items.push(capability(item, group));
    for (let i = group.children.length - 1; i >= 0; i--)
      pending.push(group.children[i]!);
  }
  return `<aside class="sidebar"><h2>Browse capabilities</h2><nav aria-label="Capability navigation"><span class="service-name">${escape(model.service.title ?? model.service.name)}</span><ul><li>${link("Overview", "", pageId === "index")}</li><li>${link("Connection", "connection", pageId === "connection")}</li>${data.ungrouped.map((item) => capability(item)).join("")}${items.join("")}</ul></nav></aside>`;
}
const schemaData = (value: JsonValue): JsonValue => {
  const schema = record(value);
  return Object.fromEntries(
    Object.entries(schema).filter(([key]) => key !== "x-capaxle"),
  );
};
function schema(value: JsonValue, title: string, download: string, link: Link) {
  if (typeof value === "boolean")
    return `<section class="schema"><h3>${escape(title)}</h3><p>${value ? "Any JSON value is accepted." : "No JSON value satisfies this schema."}</p>${json(value)}<p>${link(`Download ${title.toLowerCase()} schema`, download)}</p></section>`;
  const root = record(schemaData(value));
  const rows: string[] = [];
  const resolve = (reference: string) => {
    if (!reference.startsWith("#/")) return undefined;
    let current: JsonValue | undefined = root;
    for (const part of reference.slice(2).split("/"))
      current =
        record(current)[part.replaceAll("~1", "/").replaceAll("~0", "~")];
    return current;
  };
  const scan = (
    node: JsonValue,
    name: string,
    required: boolean,
    seen: ReadonlySet<string>,
  ) => {
    const data = record(node);
    const ref = typeof data.$ref === "string" ? data.$ref : undefined;
    let resolved = data;
    const next = new Set(seen);
    let recursive = false;
    while (typeof resolved.$ref === "string") {
      const reference = resolved.$ref;
      const target = resolve(reference);
      if (next.has(reference)) {
        recursive = true;
        break;
      }
      if (target === undefined) break;
      next.add(reference);
      resolved = {
        ...record(target),
        ...Object.fromEntries(
          Object.entries(resolved).filter(([key]) => key !== "$ref"),
        ),
      };
    }
    const constraints = Object.fromEntries(
      Object.entries({ ...resolved, ...data }).filter(
        ([key]) =>
          ![
            "$schema",
            "$defs",
            "$ref",
            "x-capaxle",
            "properties",
            "items",
            "required",
            "type",
            "description",
            "title",
          ].includes(key),
      ),
    );
    rows.push(
      `<tr><th scope="row"><code>${escape(name)}</code></th><td>${escape(String(resolved.type ?? data.type ?? "reference"))}</td><td>${required ? "Required" : "Optional"}</td><td>${escape(typeof resolved.description === "string" ? resolved.description : "")}${Object.keys(constraints).length ? `<code>${escape(JSON.stringify(constraints))}</code>` : ""}${ref === undefined ? "" : ` <a href="${escape(download + ref)}">${escape(ref)}</a>`}${recursive ? " (recursive reference)" : ""}</td></tr>`,
    );
    if (recursive) return;
    const fields = record(resolved.properties);
    for (const property of Object.keys(fields).sort(compare))
      scan(
        fields[property]!,
        name === "$" ? property : `${name}.${property}`,
        Array.isArray(resolved.required) &&
          resolved.required.includes(property),
        next,
      );
    if (resolved.items !== undefined && typeof resolved.items === "object")
      scan(resolved.items, `${name}[]`, false, next);
  };
  scan(root, "$", true, new Set());
  return `<section class="schema"><h3>${escape(title)}</h3><div class="table-scroll"><table><thead><tr><th>Field</th><th>Type</th><th>Presence</th><th>Description and constraints</th></tr></thead><tbody>${rows.join("")}</tbody></table></div><details><summary>Schema JSON</summary>${json(root)}</details><p>${link(`Download ${title.toLowerCase()} schema`, download)}</p></section>`;
}
function cliExit(
  error: DocumentationCapability["errors"][number],
  facts: Readonly<Record<string, number>>,
) {
  if (error.code === "CAP_CANCELLED" || error.status === "cancelled")
    return facts.cancelled;
  if (error.code === "CAP_INPUT_INVALID" || error.status === "invalid_argument")
    return facts.invalidInput;
  if (
    error.status === "unauthenticated" ||
    error.status === "permission_denied"
  )
    return facts.accessDenied;
  return facts.declaredError;
}
function interfaceReference(
  capability: DocumentationCapability,
  connection: DocumentationConnection,
) {
  const facts = connection.transportFacts;
  const sections: string[] = [];
  for (const name of ["http", "cli", "mcp", "sdk"] as const) {
    const projection = record(capability.interfaces[name]);
    if (!Object.keys(projection).length) continue;
    let body = "";
    if (name === "http") {
      const mounted =
        connection.applicationBasePath && connection.applicationBasePath !== "/"
          ? `${connection.applicationBasePath}${projection.path}`
          : String(projection.path);
      const endpoint = connection.applicationUrl
        ? connection.applicationUrl.replace(/\/$/, "") + projection.path
        : undefined;
      body = `<p class="invocation"><code>${escape(`${projection.method} ${mounted}`)}</code>${endpoint === undefined ? "" : `<br><code>${escape(endpoint)}</code>`}</p><h4>Input bindings</h4><div class="table-scroll"><table><thead><tr><th>Input field</th><th>HTTP location</th><th>Transport name</th></tr></thead><tbody>${Object.entries(
        record(projection.bindings),
      )
        .sort(([a], [b]) => compare(a, b))
        .map(
          ([field, binding]) =>
            `<tr><th scope="row"><code>${escape(field)}</code></th><td>${escape(String(binding))}</td><td><code>${escape(binding === "header" ? `X-Cap-Input-${field}` : field)}</code>${binding === "query" ? " (form, repeated keys)" : ""}</td></tr>`,
        )
        .join(
          "",
        )}</tbody></table></div><p>Success: HTTP <strong>200</strong>, JSON output payload. Failures: canonical <code>{ ok: false, error: { code, status, message, retryable, correlationId, details? } }</code> envelope.</p>`;
      if (!Object.keys(record(projection.bindings)).length)
        body +=
          "<p>Opaque root input: send the entire canonical JSON input as the request body.</p>";
      if (facts)
        body += `<h4>Declared errors</h4><table><thead><tr><th>Code</th><th>Canonical status</th><th>HTTP status</th></tr></thead><tbody>${capability.errors.map((error) => `<tr><td><code>${escape(error.code)}</code></td><td>${escape(error.status)}</td><td>${facts.httpErrorStatus[error.status] ?? "Unspecified"}</td></tr>`).join("")}</tbody></table><details><summary>Framework error statuses</summary><table><thead><tr><th>Canonical status</th><th>HTTP status</th></tr></thead><tbody>${Object.entries(
          facts.httpErrorStatus,
        )
          .sort(([a], [b]) => compare(a, b))
          .map(
            ([status, number]) =>
              `<tr><td>${escape(status)}</td><td>${number}</td></tr>`,
          )
          .join("")}</tbody></table></details>`;
    } else if (name === "cli") {
      const command = Array.isArray(projection.command)
        ? projection.command
            .map((part) =>
              /^[A-Za-z0-9._-]+$/.test(String(part))
                ? String(part)
                : `'${String(part).replaceAll("'", "'\\''")}'`,
            )
            .join(" ")
        : "";
      body = `<p><code>${escape(`${connection.cliBinary ?? "<application-cli>"} ${command}`)} --json --no-input</code></p><h4>Input bindings</h4><table><thead><tr><th>Input field</th><th>CLI argument</th></tr></thead><tbody>${Object.entries(
        record(projection.bindings),
      )
        .sort(([a], [b]) => compare(a, b))
        .map(([field, value]) => {
          const binding = record(value);
          return `<tr><td><code>${escape(field)}</code></td><td><code>${escape(binding.kind === "positional" ? `positional ${binding.index}` : String(binding.name))}</code></td></tr>`;
        })
        .join(
          "",
        )}</tbody></table><p>With <code>--json</code>, stdout contains the canonical success <code>{ ok: true, value, correlationId }</code> or failure <code>{ ok: false, error }</code> envelope. Ordinary output prints the success payload on stdout and failures on stderr. Remote CLI preserves the canonical JSON envelope; exit classes are CLI outcomes, independent of HTTP status.</p>`;
      if (facts)
        body += `<p>Success exit: <strong>${facts.cliExitCodes.success}</strong>.</p><table><thead><tr><th>Declared code</th><th>CLI exit</th></tr></thead><tbody>${capability.errors.map((error) => `<tr><td><code>${escape(error.code)}</code></td><td>${cliExit(error, facts.cliExitCodes)}</td></tr>`).join("")}</tbody></table><details><summary>Framework CLI exit classes</summary><table><thead><tr><th>Class</th><th>Exit</th></tr></thead><tbody>${Object.entries(
          facts.cliExitCodes,
        )
          .map(
            ([name, number]) =>
              `<tr><td>${escape(name)}</td><td>${number}</td></tr>`,
          )
          .join(
            "",
          )}</tbody></table><p>Cancellation, invalid input and access denial take precedence over declared-error classification. Confirmation/precondition failures use the precondition class; resource exhaustion, unavailable and deadline failures use unavailable.</p></details>`;
    } else if (name === "mcp") {
      body = `<p>Tool: <code>${escape(String(projection.toolName))}</code>; arguments use the canonical input object.</p><p>Success returns the canonical envelope in <code>structuredContent</code> and a canonical JSON text copy. Application errors set <code>isError: true</code> and preserve the canonical failure envelope. Malformed or unknown tool requests use JSON-RPC protocol errors, distinct from canonical application statuses and HTTP statuses. Modern results additionally use <code>resultType: "complete"</code>; legacy results omit that field.</p>`;
      if (facts?.mcpProtocolErrors)
        body += `<table><thead><tr><th>Protocol failure</th><th>JSON-RPC code</th></tr></thead><tbody>${Object.entries(
          facts.mcpProtocolErrors,
        )
          .sort(([a], [b]) => compare(a, b))
          .map(
            ([label, code]) =>
              `<tr><td>${escape(label)}</td><td>${code}</td></tr>`,
          )
          .join("")}</tbody></table>`;
    } else
      body = `<p>Client method: <code>${escape(Array.isArray(projection.path) ? projection.path.join(".") : "")}</code>.</p><p>SDK calls accept canonical inputs and return the unwrapped output value. HTTP failures throw <code>CapaxleClientError</code> containing the canonical error code, status, details, retryability and correlation ID.</p>`;
    const examples = capability.examples
      .map((example) => {
        let result: JsonValue | undefined;
        if (example.output !== undefined)
          result =
            name === "http" || name === "sdk"
              ? example.output
              : name === "mcp"
                ? {
                    structuredContent: {
                      ok: true,
                      value: example.output,
                      correlationId: "<FRAMEWORK_CORRELATION_ID>",
                    },
                    isError: false,
                  }
                : {
                    ok: true,
                    value: example.output,
                    correlationId: "<FRAMEWORK_CORRELATION_ID>",
                  };
        else if (example.error !== undefined) {
          const error = capability.errors.find(
            (item) => item.code === example.error!.code,
          )!;
          const envelope: JsonValue = {
            ok: false,
            error: {
              code: error.code,
              status: error.status,
              message: error.message,
              retryable: error.retryable,
              correlationId: "<FRAMEWORK_CORRELATION_ID>",
              ...(example.error.details === undefined
                ? {}
                : { details: example.error.details }),
            },
          };
          result =
            name === "mcp"
              ? { structuredContent: envelope, isError: true }
              : envelope;
        }
        return result === undefined
          ? ""
          : `<details><summary>${escape(example.name)}: ${name === "sdk" && example.error !== undefined ? "underlying HTTP error (SDK throws CapaxleClientError)" : "response framing"}</summary><p>Response illustration using supplied example values; correlation ID is a placeholder.</p>${json(result)}</details>`;
      })
      .join("");
    sections.push(
      `<section><h3>${name.toUpperCase()}</h3>${body}${examples}</section>`,
    );
  }
  return `<section><h2>Interfaces and responses</h2>${sections.join("")}</section>`;
}
export function renderReference(
  model: DocumentationModel,
  bundle: DocumentationBundle,
  pageId: string,
  connection: DocumentationConnection,
  link: Link,
  url: (path: string) => string,
): { title: string; content: string } | undefined {
  const data = tree(model);
  const entries = (capabilities: readonly DocumentationCapability[]) =>
    `<ul class="capability-list">${capabilities
      .map((capability) => {
        const http = record(capability.interfaces.http);
        const path =
          connection.applicationBasePath &&
          connection.applicationBasePath !== "/"
            ? `${connection.applicationBasePath}${http.path}`
            : String(http.path);
        return `<li>${link(`${capability.id} @${capability.version}`, capability.page)}<p>${escape(capability.summary)}</p>${Object.keys(http).length ? `<code>${escape(`${http.method} ${path}`)}</code>` : ""}</li>`;
      })
      .join("")}</ul>`;
  const groups = (items: readonly Group[]) =>
    `<ul class="group-list">${items.map((group) => `<li>${link(group.label, group.page)}</li>`).join("")}</ul>`;
  if (pageId === "index")
    return {
      title: model.service.title ?? model.service.name,
      content: `<h1>${escape(model.service.title ?? model.service.name)}</h1><p>Version ${escape(model.service.version)}</p>${model.service.description ? `<p>${escape(model.service.description)}</p>` : ""}<p>Explore capability inputs, outputs and interface responses. ${link("Connection instructions", "connection")}</p><h2>Resources</h2>${groups(data.roots)}${entries(data.ungrouped)}<h2>Capabilities</h2>${entries(model.capabilities)}`,
    };
  const group = data.groups.get(pageId);
  if (group) {
    const labels = groupLabels(group);
    const descendants = model.capabilities.filter((capability) =>
      labels.every((label, index) => capability.groupPath[index] === label),
    );
    return {
      title: labels.join(" / "),
      content: `<h1>${escape(labels.join(" / "))}</h1>${group.children.length ? `<h2>Child resources</h2>${groups(group.children)}` : ""}<h2>Capabilities</h2>${entries(descendants)}`,
    };
  }
  const capability = model.capabilities.find((item) => item.page === pageId);
  if (!capability) return undefined;
  const member = (record(bundle.manifest).capabilities as readonly JsonValue[])
    .map(record)
    .find((item) => item.page === capability.page)!;
  const schemas = record(member.schemas);
  const errors = record(schemas.errors);
  const lifecycle = capability.lifecycle;
  const meta = `<dl class="consumer-facts"><dt>Authentication</dt><dd>${escape(capability.authentication)}</dd><dt>Authorization</dt><dd>${escape(capability.permissionsSummary)}</dd><dt>Effect</dt><dd>${escape(capability.impact)}</dd><dt>Confirmation</dt><dd>${escape(capability.confirmation)}</dd><dt>Idempotency</dt><dd>${escape(capability.idempotency)}</dd></dl>`;
  const notices = `${capability.confirmation === "required" ? '<p class="notice">Confirmation required before invocation. Approval evidence is distinct from the challenge; obtain it through the application confirmation flow.</p>' : ""}${capability.impact === "destructive" ? '<p class="notice">Destructive capability: review the intended effect before invoking.</p>' : ""}${lifecycle.status === "deprecated" ? `<p class="notice">Deprecated${lifecycle.deprecatedAt ? ` since ${escape(lifecycle.deprecatedAt)}` : ""}${lifecycle.sunsetAt ? `; sunset ${escape(lifecycle.sunsetAt)}` : ""}${lifecycle.replacement ? `; replacement ${escape(lifecycle.replacement)}` : ""}.</p>` : ""}`;
  const examples = capability.examples.length
    ? capability.examples
        .map(
          (example) =>
            `<section><h3>${escape(example.name)}</h3>${example.description ? `<p>${escape(example.description)}</p>` : ""}<h4>Input</h4>${json(example.input)}${example.output === undefined ? "" : `<h4>Output</h4>${json(example.output)}`}${example.error === undefined ? "" : `<h4>Declared error</h4>${json(example.error as unknown as JsonValue)}`}</section>`,
        )
        .join("")
    : "<p>No example supplied for this capability.</p>";
  const declared = capability.errors.length
    ? capability.errors
        .map(
          (error) =>
            `<section><h3><code>${escape(error.code)}</code></h3><p>${escape(error.message)}</p><p>Canonical status: <code>${escape(error.status)}</code>. Retryable: ${error.retryable ? "yes" : "no"}.</p>${error.detailsSchema === undefined ? "" : schema(error.detailsSchema, `${error.code} details`, url(String(errors[error.code])), link)}</section>`,
        )
        .join("")
    : "<p>No capability-specific errors are declared. Framework validation, authentication and policy failures may still occur.</p>";
  const schemaLink: Link = (label, path) => link(label, path);
  // Schema reference anchors use the trusted documentation root as well.
  const schemaHtml = (value: JsonValue, title: string, path: string) =>
    schema(value, title, url(path), (label, target) =>
      schemaLink(label, target),
    );
  return {
    title: `${capability.id} @${capability.version}`,
    content: `<h1>${escape(capability.id)} <small>@${escape(capability.version)}</small></h1><p class="summary">${escape(capability.summary)}</p>${capability.description ? `<p>${escape(capability.description)}</p>` : ""}${notices}${meta}<section><h2>Inputs and outputs</h2>${schemaHtml(capability.inputSchema, "Input", String(schemas.input))}${schemaHtml(capability.outputSchema, "Output", String(schemas.output))}</section><section><h2>Examples</h2>${examples}</section><section><h2>Declared errors</h2>${declared}</section>${interfaceReference(capability, connection)}<details><summary>Schema downloads</summary><ul>${[schemas.input, schemas.output, schemas.cliResult, ...Object.values(errors)].map((path) => `<li>${link(String(path), String(path))}</li>`).join("")}</ul></details>`,
  };
}
