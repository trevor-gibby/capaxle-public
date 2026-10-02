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
  const activeGroups = new Set<string>();
  let selected =
    data.groups.get(pageId) ??
    [...data.groups.values()].find((group) =>
      group.capabilities.some((item) => item.page === pageId),
    );
  while (selected) {
    activeGroups.add(selected.page);
    selected = selected.parent;
  }
  const capability = (item: DocumentationCapability, parent?: Group) =>
    `<li class="resource-item" data-depth="${parent ? parent.depth + 1 : 0}"${parent ? ` data-parent="${parent.page}"` : ""} style="--group-depth:${Math.min(parent?.depth ?? 0, 8)}">${link(`${item.id.split(".").at(-1)} @${item.version}`, item.page, pageId === item.page, parent ? { describedBy: labelId(parent) } : undefined)}</li>`;
  const items: string[] = [];
  type Item = { group: Group; flat?: boolean } | { html: string };
  const pending: Item[] = [...data.roots].reverse().map((group) => ({ group }));
  while (pending.length) {
    const item = pending.pop()!;
    if ("html" in item) {
      items.push(item.html);
      continue;
    }
    const { group, flat } = item;
    items.push(
      `<li class="resource-item" data-depth="${group.depth}"${group.parent ? ` data-parent="${group.parent.page}"` : ""} style="--group-depth:${Math.min(group.depth - 1, 8)}"><details class="resource-group" data-group="${group.page}"${activeGroups.has(group.page) ? " open" : ""}><summary>${link(group.label, group.page, pageId === group.page, { id: labelId(group), ...(group.parent ? { describedBy: labelId(group.parent) } : {}) })}${group.depth > 8 ? `<span class="resource-level">Level ${group.depth}</span>` : ""}</summary><ul>`,
    );
    for (const member of group.capabilities)
      items.push(capability(member, group));
    pending.push({ html: "</ul></details></li>" });
    if (flat) {
      // Beyond eight native levels, retain a complete flat directory with explicit parent context.
      for (const child of group.children)
        items.push(
          `<li class="resource-context">${link(`Explore ${child.label}`, child.page, false, { describedBy: labelId(group) })}</li>`,
        );
    } else if (group.depth === 8 && group.children.length) {
      items.push(
        '<li class="resource-continuation"><p>Further resource groups</p><ul>',
      );
      pending.push({ html: "</ul></li>" });
      const continued: Group[] = [];
      const descendants = [...group.children].reverse();
      while (descendants.length) {
        const child = descendants.pop()!;
        continued.push(child);
        for (let i = child.children.length - 1; i >= 0; i--)
          descendants.push(child.children[i]!);
      }
      for (let i = continued.length - 1; i >= 0; i--)
        pending.push({ group: continued[i]!, flat: true });
    } else {
      for (let i = group.children.length - 1; i >= 0; i--)
        pending.push({ group: group.children[i]! });
    }
  }
  return `<aside class="sidebar"><details class="docs-sidebar" open><summary>Browse capabilities</summary><nav class="docs-tree" aria-label="Capability navigation"><span class="service-name">${escape(model.service.title ?? model.service.name)}</span><ul><li>${link("Overview", "", pageId === "index")}</li><li>${link("Connection", "connection", pageId === "connection")}</li>${data.ungrouped.map((item) => capability(item)).join("")}${items.join("")}</ul></nav></details></aside>`;
}
const schemaData = (value: JsonValue): JsonValue => {
  const schema = record(value);
  return Object.fromEntries(
    Object.entries(schema).filter(([key]) => key !== "x-capaxle"),
  );
};
function schema(value: JsonValue, title: string, download: string, link: Link) {
  if (typeof value === "boolean")
    return `<section class="schema docs-schema"><h3>${escape(title)}</h3><p>${value ? "Any JSON value is accepted." : "No JSON value satisfies this schema."}</p>${json(value)}<p>${link(`Download ${title.replace(/ schema$/i, "").toLowerCase()} schema`, download)}</p></section>`;
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
  return `<section class="schema docs-schema"><h3>${escape(title)}</h3><div class="table-scroll" tabindex="0" role="region" aria-label="${escape(`${title}${title.endsWith(" schema") ? "" : " schema"} fields`)}"><table><thead><tr><th>Field</th><th>Type</th><th>Presence</th><th>Description and constraints</th></tr></thead><tbody>${rows.join("")}</tbody></table></div><details><summary>Schema JSON</summary>${json(root)}</details><p>${link(`Download ${title.replace(/ schema$/i, "").toLowerCase()} schema`, download)}</p></section>`;
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
function resolvedSchema(node: JsonValue, root: Record<string, JsonValue>) {
  let value = record(node);
  const seen = new Set<string>();
  while (
    typeof value.$ref === "string" &&
    value.$ref.startsWith("#/") &&
    !seen.has(value.$ref)
  ) {
    const reference = value.$ref;
    seen.add(reference);
    let target: JsonValue | undefined = root;
    for (const part of reference.slice(2).split("/"))
      target = record(target)[part.replaceAll("~1", "/").replaceAll("~0", "~")];
    if (target === undefined) break;
    value = {
      ...record(target),
      ...Object.fromEntries(
        Object.entries(value).filter(([key]) => key !== "$ref"),
      ),
    };
  }
  return value;
}
function bindingField(
  capability: DocumentationCapability,
  field: string,
  transportName: string,
  inputDownload: string,
) {
  const root = record(capability.inputSchema);
  const input = resolvedSchema(capability.inputSchema, root);
  const node = record(input.properties)[field];
  if (node === undefined)
    return `<article class="docs-field"><h4><code>${escape(transportName)}</code></h4><p>Canonical field: <code>${escape(field)}</code>. See the canonical input schema.</p></article>`;
  const data = resolvedSchema(node, root);
  const required =
    Array.isArray(input.required) && input.required.includes(field);
  const constraints = Object.entries(data).filter(
    ([key]) =>
      ![
        "$schema",
        "$defs",
        "$ref",
        "x-capaxle",
        "type",
        "properties",
        "items",
        "required",
        "description",
        "title",
      ].includes(key),
  );
  const reference = record(node).$ref;
  return `<article class="docs-field"><div class="docs-field-heading"><h4><code>${escape(transportName)}</code></h4><span class="docs-field-type">${escape(typeof node === "boolean" ? (node ? "any JSON value" : "no accepted value") : String(data.type ?? "reference"))}</span><span class="docs-field-presence">${required ? "Required" : "Optional"}</span></div><p class="docs-field-origin">Canonical field: <code>${escape(field)}</code>.</p>${typeof data.description === "string" ? `<p>${escape(data.description)}</p>` : ""}${constraints.length ? `<details class="docs-field-constraints"><summary>Constraints</summary><p>${constraints.map(([key, value]) => `<code>${escape(`${key}: ${JSON.stringify(value)}`)}</code>`).join(" ")}</p></details>` : ""}${typeof reference === "string" ? `<p><a href="${escape(inputDownload + reference)}">${escape(reference)}</a></p>` : ""}</article>`;
}
function httpBindings(
  capability: DocumentationCapability,
  projection: Record<string, JsonValue>,
  inputDownload: string,
  canonicalBody: () => string,
) {
  const bindings = record(projection.bindings);
  const root = resolvedSchema(
    capability.inputSchema,
    record(capability.inputSchema),
  );
  const stableRoot =
    root.type === "object" &&
    root.additionalProperties === false &&
    root.properties !== undefined &&
    root.oneOf === undefined &&
    root.const === undefined &&
    root.enum === undefined;
  const opaque = !Object.keys(bindings).length && !stableRoot;
  return (
    [
      ["path", "Path parameters"],
      ["query", "Query parameters"],
      ["header", "Header parameters"],
      ["body", "Request body"],
    ] as const
  )
    .map(([binding, title]) => {
      const fields = Object.entries(bindings)
        .filter(([, location]) => location === binding)
        .sort(([a], [b]) => compare(a, b));
      const content = fields.length
        ? fields
            .map(([field]) =>
              bindingField(
                capability,
                field,
                binding === "header" ? `X-Cap-Input-${field}` : field,
                inputDownload,
              ),
            )
            .join("")
        : binding === "body" && opaque
          ? `<p>Opaque root input: send the entire canonical JSON input as the request body.</p>${canonicalBody()}`
          : `<p>No ${binding === "body" ? "body-bound fields. Omit the request body" : `${binding} parameters`}.</p>`;
      return `<section class="docs-binding-group" data-binding="${binding}"><h3>${title}</h3>${binding === "query" && fields.length ? "<p>Scalar values use one key; arrays use repeated keys (form encoding).</p>" : ""}${content}</section>`;
    })
    .join("");
}

// Encode executable source before HTML text encoding. Computed __proto__ keys
// retain own canonical data properties at every object depth.
const sourceLiteral = (value: string) =>
  JSON.stringify(value).replace(
    /[<>&\u2028\u2029]/gu,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
const inputSource = (value: JsonValue) =>
  JSON.stringify(value, null, 2)
    .replace(
      /[<>&\u2028\u2029]/gu,
      (character) =>
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
    )
    .replace(/^(\s*)"__proto__":/gm, '$1["__proto__"]:');
const sdkCode = (id: string, label: string, text: string) =>
  `<div class="docs-sdk-code-block"><div class="docs-sdk-code-header"><label for="${id}">${escape(label)}</label><span class="docs-sdk-language">TypeScript</span><button type="button" data-copy="${id}" aria-label="Copy ${escape(label)}">Copy</button></div><textarea class="docs-sdk-code" id="${id}" readonly spellcheck="false" data-language="typescript" rows="${Math.min(24, text.split("\n").length)}">${escape(text)}</textarea></div>`;

function sdkReference(
  capability: DocumentationCapability,
  projection: Record<string, JsonValue>,
  connection: DocumentationConnection,
  schemas: Record<string, JsonValue>,
  schemaHtml: (value: JsonValue, title: string, path: string) => string,
) {
  const method = `client${(projection.path as readonly string[]).map((part) => (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(part) ? `.${part}` : `[${sourceLiteral(part)}]`)).join("")}`;
  const mount = connection.applicationBasePath ?? "/";
  const applicationUrl = connection.applicationUrl?.startsWith("/")
    ? undefined
    : connection.applicationUrl;
  const origin = applicationUrl
    ? new URL(applicationUrl).origin
    : "<APPLICATION_ORIGIN>";
  const setup = `import { createCapaxleClient, CapaxleClientError } from './capaxle-sdk.js';\n\nconst client = createCapaxleClient({\n  baseUrl: ${sourceLiteral(origin)},${mount === "/" ? "" : `\n  fetch: (input, init) => {\n    const url = new URL(input instanceof Request ? input.url : String(input));\n    url.pathname = ${sourceLiteral(mount)} + url.pathname;\n    return fetch(url, init);\n  },`}${capability.authentication === "required" ? '\n  headers: { Authorization: "Bearer <APPLICATION_TOKEN>" },' : ""}\n});`;
  const errorCode = `function rethrowCapabilityError(error: unknown): never {\n  if (error instanceof CapaxleClientError) {\n    console.error({\n      code: error.code,\n      status: error.status,\n      details: error.details,\n      retryable: error.retryable,\n      correlationId: error.correlationId,\n    });\n  }\n  throw error;\n}`;
  const controls = [
    ...(capability.idempotency === "key"
      ? ['idempotencyKey: "<CALLER_IDEMPOTENCY_KEY>"']
      : []),
    ...(capability.confirmation === "required"
      ? ['confirmationToken: "<APPLICATION_CONFIRMATION_APPROVAL>"']
      : []),
  ];
  const first = capability.examples[0];
  const callOptions = controls.length
    ? `, {\n  ${controls.join(",\n  ")},\n}`
    : "";
  const usage = first
    ? `const input: Parameters<typeof ${method}>[0] = ${inputSource(first.input)};\n\nconst value = await ${method}(input${callOptions}).catch(rethrowCapabilityError);`
    : `async function invokeCapability(input: Parameters<typeof ${method}>[0]) {\n  const value = await ${method}(input${callOptions.replaceAll("\n", "\n  ")}).catch(rethrowCapabilityError);\n  return value;\n}\n\n// No authored input supplied. Call invokeCapability with your canonical input.`;
  return `<section class="docs-sdk-setup" id="docs-sdk-setup"><h3>Setup</h3><p><code>capaxle build</code> emits <code>capaxle-sdk.ts</code>. Compile it in your consuming TypeScript project, then import <code>./capaxle-sdk.js</code>.</p>${applicationUrl ? "" : "<p>Replace <code>&lt;APPLICATION_ORIGIN&gt;</code> with the application origin before using this code. The documentation URL does not establish the application origin.</p>"}${mount === "/" ? "" : "<p>The generated routes are absolute. This configured fetch preserves the known application mount; a mounted base URL alone would lose that prefix.</p>"}${capability.authentication === "required" ? "<p>Authentication required: obtain an application token through the application's authentication flow and replace <code>&lt;APPLICATION_TOKEN&gt;</code>. This placeholder is not a credential.</p>" : `<p>Authentication is ${escape(capability.authentication)}. Configure credentials only when your application requires them.</p>`}${sdkCode("docs-sdk-setup-code", "SDK setup", setup)}</section><section class="docs-sdk-usage" id="docs-sdk-request"><h3>Usage</h3><p>Client method: <code>${escape(Array.isArray(projection.path) ? projection.path.join(".") : "")}</code>. SDK calls accept canonical inputs and return the unwrapped output value.</p>${first ? `<p>Uses the supplied canonical input from <strong>${escape(first.name)}</strong>; the code is static and has not been executed.</p>` : "<p>No authored input supplied. This callable template accepts the generated method's actual input type; supply your own canonical input.</p>"}${capability.idempotency === "key" ? "<p>Replace <code>&lt;CALLER_IDEMPOTENCY_KEY&gt;</code> with a caller-generated key identifying this operation; reuse it for retries of the same operation.</p>" : ""}${capability.confirmation === "required" ? "<p>Replace <code>&lt;APPLICATION_CONFIRMATION_APPROVAL&gt;</code> with approval evidence obtained through the application confirmation flow. A challenge or this placeholder is not approval evidence.</p>" : ""}${sdkCode("docs-sdk-usage-code", "SDK usage", usage)}<details class="docs-sdk-details"><summary>Canonical input schema</summary>${schemaHtml(capability.inputSchema, "Canonical input", String(schemas.input))}</details></section><section class="docs-sdk-errors" id="docs-sdk-errors"><h3>Typed errors</h3><p>HTTP failures throw <code>CapaxleClientError</code> containing the canonical error code, status, details, retryability and correlation ID. Narrow unknown errors before reading these fields; rethrow failures to preserve them.</p>${sdkCode("docs-sdk-errors-code", "SDK error handling", errorCode)}</section>`;
}

function interfaceReference(
  capability: DocumentationCapability,
  connection: DocumentationConnection,
  schemas: Record<string, JsonValue>,
  schemaHtml: (value: JsonValue, title: string, path: string) => string,
  url: (path: string) => string,
) {
  const facts = connection.transportFacts;
  const sections: { name: "http" | "cli" | "mcp" | "sdk"; html: string }[] = [];
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
      body = `<section class="docs-request" id="docs-${name}-request"><h3>Request</h3><p class="invocation"><span class="docs-method" data-method="${escape(String(projection.method))}">${escape(String(projection.method))}</span> <code class="docs-endpoint">${escape(mounted)}</code>${endpoint === undefined ? "" : `<br><code>${escape(endpoint)}</code>`}</p>${httpBindings(capability, projection, url(String(schemas.input)), () => schemaHtml(capability.inputSchema, "Canonical JSON body", String(schemas.input)))}</section><p>Success: HTTP <strong>200</strong>, JSON output payload. Failures: canonical <code>{ ok: false, error: { code, status, message, retryable, correlationId, details? } }</code> envelope.</p>`;
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
      body = `<section class="docs-request" id="docs-${name}-request"><h3>Request</h3><p><code>${escape(`${connection.cliBinary ?? "<application-cli>"} ${command}`)} --json --no-input</code></p><h4>Options and positionals</h4><div class="table-scroll" tabindex="0" role="region" aria-label="CLI input bindings"><table><thead><tr><th>Input field</th><th>CLI argument</th></tr></thead><tbody>${Object.entries(
        record(projection.bindings),
      )
        .sort(([a], [b]) => compare(a, b))
        .map(([field, value]) => {
          const binding = record(value);
          return `<tr><td><code>${escape(field)}</code></td><td><code>${escape(binding.kind === "positional" ? `positional ${binding.index}` : String(binding.name))}</code></td></tr>`;
        })
        .join(
          "",
        )}</tbody></table></div>${schemaHtml(capability.inputSchema, "Canonical input", String(schemas.input))}</section><p>With <code>--json</code>, stdout contains the canonical success <code>{ ok: true, value, correlationId }</code> or failure <code>{ ok: false, error }</code> envelope. Ordinary output prints the success payload on stdout and failures on stderr. Remote CLI preserves the canonical JSON envelope; exit classes are CLI outcomes, independent of HTTP status.</p>`;
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
      body = `<section class="docs-request" id="docs-${name}-request"><h3>Request</h3><p>Tool: <code>${escape(String(projection.toolName))}</code>; arguments use the canonical input object.</p>${schemaHtml(capability.inputSchema, "Canonical JSON arguments", String(schemas.input))}</section><p>Success returns the canonical envelope in <code>structuredContent</code> and a canonical JSON text copy. Application errors set <code>isError: true</code> and preserve the canonical failure envelope. Malformed or unknown tool requests use JSON-RPC protocol errors, distinct from canonical application statuses and HTTP statuses. Modern results additionally use <code>resultType: "complete"</code>; legacy results omit that field.</p>`;
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
      body = sdkReference(
        capability,
        projection,
        connection,
        schemas,
        schemaHtml,
      );
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
          : `<details><summary>${escape(example.name)}: ${name === "sdk" && example.error !== undefined ? "underlying HTTP error (SDK throws CapaxleClientError)" : "response framing"}</summary><p>Response illustration using supplied example values; correlation ID is a placeholder.</p>${name === "sdk" ? `<h4>Canonical input</h4>${json(example.input)}<h4>${example.error === undefined ? "Returned value" : "Underlying HTTP error"}</h4>` : ""}${json(result)}</details>`;
      })
      .join("");
    const responseTitle =
      name === "http"
        ? "Response body"
        : name === "sdk"
          ? "Returns"
          : "Response value";
    const responseGuidance =
      name === "http"
        ? "The response body is the unwrapped canonical output."
        : name === "mcp"
          ? "The schema describes structuredContent.value, not the entire MCP result or canonical envelope."
          : name === "cli"
            ? "The schema describes value within the JSON success envelope, or the ordinary-output payload; it is not the envelope schema."
            : "The SDK returns this unwrapped value.";
    const outputSchema = schemaHtml(
      capability.outputSchema,
      name === "http" ? "Response body schema" : "Output value schema",
      String(schemas.output),
    );
    const response = `<section class="docs-response${name === "sdk" ? " docs-sdk-returns" : ""}" id="docs-${name}-response"><h3>${responseTitle}</h3><p>${responseGuidance}</p>${name === "sdk" ? `<details class="docs-sdk-details"><summary>Returned value schema</summary>${outputSchema}</details>` : outputSchema}<h4 id="docs-${name}-examples">Authored response examples</h4>${examples || "<p>No authored response example supplied.</p>"}</section>`;
    const label = name === "http" ? "API" : name.toUpperCase();
    sections.push({
      name,
      html: `<section class="interface-panel docs-interface-panel${name === "sdk" ? " docs-sdk" : ""}" id="docs-panel-${name}" data-interface="${name}" aria-labelledby="docs-label-${name}"><h2>${label}</h2><nav class="docs-on-page docs-interface-jump" aria-label="${label} page sections">${name === "sdk" ? '<a href="#docs-sdk-setup">Setup</a>' : ""}<a href="#docs-${name}-request">${name === "sdk" ? "Usage" : "Request"}</a><a href="#docs-${name}-response">${responseTitle}</a>${name === "sdk" ? '<a href="#docs-sdk-errors">Typed errors</a>' : ""}<a href="#docs-${name}-examples">Authored examples</a></nav>${body}${response}</section>`,
    });
  }
  const controls = sections
    .map(
      ({ name }, index) =>
        `<input type="radio" name="docs-interface" id="docs-view-${name === "http" ? "api" : name}" aria-controls="docs-panel-${name}"${index === 0 ? " checked" : ""}><label id="docs-label-${name}" for="docs-view-${name === "http" ? "api" : name}">${name === "http" ? "API" : name.toUpperCase()}</label>`,
    )
    .join("");
  return `${sections.length ? `<fieldset class="interface-switch docs-interface-switch"><legend>Interface</legend>${controls}<div class="interface-panels docs-interface-panels">${sections.map(({ html }) => html).join("")}</div></fieldset>` : "<p>No API, CLI, MCP or SDK projection is enabled for this capability.</p>"}`;
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
  const meta = `<dl class="consumer-facts"><div class="docs-fact"><dt>Authentication</dt><dd>${escape(capability.authentication)}</dd></div><div class="docs-fact"><dt>Authorization</dt><dd>${escape(capability.permissionsSummary)}</dd></div><div class="docs-fact"><dt>Effect</dt><dd>${escape(capability.impact)}</dd></div><div class="docs-fact"><dt>Confirmation</dt><dd>${escape(capability.confirmation)}</dd></div><div class="docs-fact"><dt>Idempotency</dt><dd>${escape(capability.idempotency)}</dd></div></dl>`;
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
    content: `<section class="docs-overview"><h1>${escape(capability.id)} <small>@${escape(capability.version)}</small></h1><p class="summary">${escape(capability.summary)}</p>${capability.description ? `<p>${escape(capability.description)}</p>` : ""}<div class="docs-safety">${notices}${meta}</div></section><details class="docs-canonical-schemas"><summary>Canonical input and output schemas</summary><section><h2>Inputs and outputs</h2>${schemaHtml(capability.inputSchema, "Input", String(schemas.input))}${schemaHtml(capability.outputSchema, "Output", String(schemas.output))}</section></details>${interfaceReference(capability, connection, schemas, schemaHtml, url)}<section><h2>Examples</h2>${examples}</section><details class="docs-declared-errors"><summary>Declared errors</summary>${declared}</details><details class="docs-downloads"><summary>Schema downloads</summary><ul>${[schemas.input, schemas.output, schemas.cliResult, ...Object.values(errors)].map((path) => `<li>${link(String(path), String(path))}</li>`).join("")}</ul></details>`,
  };
}
