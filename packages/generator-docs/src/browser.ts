import type { JsonValue } from "@capaxle/ir";
import {
  renderReference,
  referenceNavigation,
  validateConsumerModel,
} from "./reference.js";
export { projectDocumentationModel } from "./projection.js";
export type {
  DocumentationCapability,
  DocumentationModel,
} from "./projection.js";
import type { DocumentationModel } from "./projection.js";
import {
  generateDocumentationEntries,
  type DocsSchemaDiagnostic,
  type DocumentationVisibility,
} from "./projection.js";

/** Request-local disclosure projection; never emits a static archive. */
export function projectDocumentationView(
  source: unknown,
  options: {
    readonly irHash: string;
    readonly cliBinary?: string;
    readonly sensitiveRequirementNames?: readonly string[];
    readonly enabledInterfaces?: readonly ("http" | "cli" | "mcp")[];
    readonly visibleInterfaces: readonly DocumentationVisibility[];
  },
):
  | { readonly ok: true; readonly bundle: DocumentationBundle }
  | {
      readonly ok: false;
      readonly diagnostics: readonly DocsSchemaDiagnostic[];
    } {
  if (!options || !Array.isArray(options.visibleInterfaces))
    return {
      ok: false,
      diagnostics: [
        {
          code: "CAP_DOCS_SCHEMA_INVALID",
          severity: "error",
          message: "Missing documentation visibility selection.",
          path: "/visibleInterfaces",
        },
      ],
    };
  const result = generateDocumentationEntries(
    source,
    options,
    options.visibleInterfaces,
  );
  if (!result.ok) return result;
  const decoder = new TextDecoder();
  const entries = result.entries.map(({ path, bytes }) => ({
    path,
    text: decoder.decode(bytes),
  }));
  const manifest = JSON.parse(
    entries.find((entry) => entry.path === "manifest.json")!.text,
  ) as JsonValue;
  return { ok: true, bundle: { manifest, entries } };
}

/** Plain, verified archive data supplied by the application host. */
export interface DocumentationBundle {
  readonly manifest: JsonValue;
  readonly entries: readonly { readonly path: string; readonly text: string }[];
}

/** Deployment locations and verified client instructions supplied by the host. */
export interface DocumentationConnection {
  readonly docsPath: string;
  readonly docsUrl?: string;
  readonly serviceId: string;
  readonly applicationBasePath?: string;
  readonly applicationUrl?: string;
  readonly cliBinary?: string;
  readonly transportFacts?: {
    readonly httpErrorStatus: Readonly<Record<string, number>>;
    readonly cliExitCodes: Readonly<Record<string, number>>;
    readonly mcpProtocolErrors?: Readonly<Record<string, number>>;
  };
  readonly surfaces: readonly {
    readonly id: "api" | "sdk" | "mcp" | "cli";
    readonly label: string;
    readonly url?: string;
    readonly protocols?: readonly string[];
    readonly guidance?: string;
    readonly snippets: readonly {
      readonly id: string;
      readonly label: string;
      readonly language: "sh" | "json" | "toml" | "typescript";
      readonly text: string;
    }[];
  }[];
}

export class DocumentationBrowserError extends Error {
  constructor(
    readonly code: "CAP_DOCS_BROWSER_INVALID" | "CAP_DOCS_BROWSER_NOT_FOUND",
    message: string,
  ) {
    super(message);
    this.name = "DocumentationBrowserError";
  }
}

const invalid = (message: string): never => {
  throw new DocumentationBrowserError("CAP_DOCS_BROWSER_INVALID", message);
};
const escape = (text: string) =>
  text.replace(/[&<>"']/g, (character) => {
    return {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[character]!;
  });
const object = (value: JsonValue | undefined): Record<string, JsonValue> => {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return invalid("Expected an object in the documentation manifest.");
  return value as Record<string, JsonValue>;
};
const string = (value: JsonValue | undefined): string => {
  if (typeof value !== "string")
    return invalid("Expected a string in the documentation manifest.");
  return value;
};
const archivePath = (path: string) => {
  if (
    !/^[a-zA-Z0-9._-]+(?:\/[a-zA-Z0-9._-]+)*$/.test(path) ||
    path.split("/").some((part) => part === "." || part === "..")
  )
    invalid("Unsafe documentation archive path.");
  return path;
};

function readBundle(bundle: DocumentationBundle) {
  const manifest = object(bundle.manifest);
  if (!Array.isArray(manifest.capabilities))
    return invalid("Missing documentation capabilities.");
  const allowed = new Set([
    "manifest.json",
    "fixtures/examples.json",
    "schemas/shared.schema.json",
    "schemas/capability-ir.schema.json",
  ]);
  const pages = new Map<string, string>();
  const identities = new Set<string>();
  const capabilities = manifest.capabilities.map((value) => {
    const capability = object(value);
    const id = string(capability.id);
    const version = string(capability.version);
    const identity = `${id}@${version}`;
    if (identities.has(identity))
      invalid("Duplicate documentation capability.");
    identities.add(identity);
    const schemas = object(capability.schemas);
    const links: { label: string; path: string }[] = [];
    const add = (label: string, value: JsonValue | undefined) => {
      const path = archivePath(string(value));
      if (!path.startsWith("schemas/") || !path.endsWith(".schema.json"))
        invalid("Invalid documentation schema reference.");
      if (allowed.has(path))
        invalid("Duplicate documentation schema reference.");
      allowed.add(path);
      links.push({ label, path });
    };
    add("Input", schemas.input);
    add("Output payload", schemas.output);
    add("CLI JSON result", schemas.cliResult);
    for (const [code, path] of Object.entries(object(schemas.errors)).sort(
      ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0),
    ))
      add(`Error ${code}`, path);
    let page: string | undefined;
    if (capability.page !== undefined) {
      page = archivePath(string(capability.page));
      if (!page.startsWith("docs/capabilities/") || !page.endsWith(".md"))
        invalid("Invalid documentation page reference.");
      if (allowed.has(page)) invalid("Duplicate documentation page reference.");
      allowed.add(page);
      pages.set(page, identity);
    }
    return { identity, page, links };
  });
  const entries = new Map<string, string>();
  for (const entry of bundle.entries) {
    const path = archivePath(entry.path);
    if (
      !allowed.has(path) ||
      entries.has(path) ||
      typeof entry.text !== "string"
    )
      invalid("Unknown or duplicate documentation archive entry.");
    entries.set(path, entry.text);
  }
  for (const path of allowed)
    if (!entries.has(path)) invalid("Missing documentation archive entry.");
  // A caller cannot accidentally combine a manifest with a different generation.
  let archived: unknown;
  try {
    archived = JSON.parse(entries.get("manifest.json")!);
  } catch {
    invalid("Malformed documentation manifest entry.");
  }
  if (JSON.stringify(archived) !== JSON.stringify(bundle.manifest)) {
    // Object property order is irrelevant to JSON data.
    const canonical = (value: unknown): string => {
      if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
      if (value && typeof value === "object")
        return `{${Object.entries(value)
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([key, child]) => `${JSON.stringify(key)}:${canonical(child)}`)
          .join(",")}}`;
      return JSON.stringify(value);
    };
    if (canonical(archived) !== canonical(bundle.manifest))
      invalid("Documentation manifest does not match its archive entry.");
  }
  return { entries, pages, capabilities };
}

/** Verify archive paths and references independently of consumer presentation. */
export function validateDocumentationBundle(bundle: DocumentationBundle): void {
  readBundle(bundle);
}

function connectionPath(path: string) {
  if (
    !path.startsWith("/") ||
    path.startsWith("//") ||
    /[\\\s\u0000-\u001f\u007f?#%<>"]/.test(path) ||
    path.endsWith("/") ||
    path
      .split("/")
      .slice(1)
      .some((part) => !part || part === "." || part === "..")
  )
    invalid("Unsafe documentation mount path.");
  return path;
}

function externalUrl(text: string) {
  if (text.includes("?") || text.includes("#"))
    invalid(
      "Documentation connection URLs cannot contain query or fragment delimiters.",
    );
  if (text.startsWith("/") && !text.startsWith("//")) {
    // Local locations are valid when no operator external URL is configured.
    return connectionPath(text);
  }
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return invalid("Invalid documentation connection URL.");
  }
  if (
    url.username ||
    url.password ||
    url.hash ||
    url.search ||
    (url.protocol !== "https:" &&
      !(
        url.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
      ))
  )
    invalid("Unsafe documentation connection URL.");
  return text;
}

const styles = `.documentation-layout{display:grid;grid-template-columns:minmax(14rem,19rem) minmax(0,1fr);max-width:90rem;margin:auto}.sidebar{padding:1.25rem;border-right:1px solid GrayText;align-self:start;position:sticky;top:0;max-height:100vh;overflow:auto}.sidebar nav{display:block}.sidebar ul{list-style:none;padding-left:1rem}.sidebar .resource-item{padding-inline-start:calc(var(--group-depth)*.65rem)}.resource-level{font-size:.75rem}.sidebar a{display:block;padding:.3rem}.sidebar [aria-current=page]{font-weight:700;background:ButtonFace}.documentation-layout main{min-width:0;width:100%}.table-scroll{max-width:100%;overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{text-align:left;vertical-align:top;padding:.5rem;border-bottom:1px solid GrayText;overflow-wrap:anywhere}td code{white-space:pre-wrap}details{margin:1rem 0}summary{cursor:pointer;min-height:44px;padding:.5rem}.consumer-facts{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:.5rem 1rem}.consumer-facts dd{margin:0}.notice{border-left:4px solid Highlight;padding:.75rem}.capability-list li,.group-list li{margin-block:1rem}.summary{font-size:1.15rem}@media(max-width:48rem){.documentation-layout{grid-template-columns:1fr}.sidebar{position:static;max-height:16rem;overflow:auto;border-right:0;border-bottom:1px solid GrayText}.consumer-facts{grid-template-columns:1fr}.consumer-facts dt{font-weight:700}}:root{color-scheme:light dark;font-family:system-ui,sans-serif;line-height:1.55}*{box-sizing:border-box}body{margin:0;background:Canvas;color:CanvasText}header,main,footer{max-width:72rem;margin:auto;padding:1.25rem}nav{display:flex;flex-wrap:wrap;gap:1rem}a{color:LinkText;overflow-wrap:anywhere}a:focus-visible,button:focus-visible,textarea:focus-visible{outline:3px solid Highlight;outline-offset:3px}.skip{position:absolute;left:-10000px}.skip:focus{position:static}h1,h2,h3,p,li{overflow-wrap:anywhere}pre,textarea{max-width:100%;white-space:pre-wrap;overflow-wrap:anywhere;tab-size:2;font-family:monospace}pre{padding:1rem;border:1px solid GrayText;border-radius:.4rem}textarea{display:block;width:100%;min-height:8rem;padding:.75rem;resize:vertical;background:Canvas;color:CanvasText}button{font:inherit;min-height:44px;padding:.5rem 1rem;cursor:pointer}section{margin-block:2rem}footer{border-top:1px solid GrayText}ul{padding-left:1.5rem}@media(max-width:30rem){header,main,footer{padding:1rem}nav{gap:.75rem}pre{padding:.75rem}}`;
// Fixed code only: authored content stays in escaped text nodes / textarea values.
const copyScript = `document.querySelectorAll('button[data-copy]').forEach(function(button){button.addEventListener('click',async function(){var field=document.getElementById(button.dataset.copy);var status=document.getElementById('copy-status');try{if(!navigator.clipboard)throw new Error('Clipboard unavailable');await navigator.clipboard.writeText(field.value);status.textContent='Copied to clipboard.';}catch{field.focus();field.select();status.textContent='Select and copy the highlighted snippet.';}});});`;

/** Conservative inline-only CSS: no HTML escapes, CSS escapes or resource loaders. */
export function validateDocumentationStylesheet(
  stylesheet: unknown,
): asserts stylesheet is string {
  if (
    typeof stylesheet !== "string" ||
    !stylesheet.trim() ||
    /[<>\\\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(stylesheet)
  )
    return invalid("Invalid inline documentation stylesheet.");
  // Remove comments before checking tokens: comments may split unsafe identifiers.
  const tokens = stylesheet.replace(/\/\*[\s\S]*?\*\//g, "");
  if (
    /@\s*(?:import|charset|namespace)\b/i.test(tokens) ||
    /(?:url|src|image|image-set|-webkit-image-set|expression|attr)\s*\(/i.test(
      tokens,
    ) ||
    /(?:-moz-binding|behavior)\s*:/i.test(tokens) ||
    /(?:https?:|data:|javascript:)/i.test(tokens)
  )
    invalid("Unsupported inline documentation stylesheet resource.");
}

export function renderDocumentationPage(options: {
  readonly bundle: DocumentationBundle;
  readonly pageId: string;
  readonly connection: DocumentationConnection;
  readonly model: DocumentationModel;
  readonly stylesheet?: string;
}): { html: string } {
  const { bundle, pageId, connection, model } = options;
  if (options.stylesheet !== undefined)
    validateDocumentationStylesheet(options.stylesheet);
  readBundle(bundle);
  const docsPath = connectionPath(connection.docsPath);
  if (
    connection.applicationBasePath !== undefined &&
    connection.applicationBasePath !== "/"
  )
    connectionPath(connection.applicationBasePath);
  if (connection.applicationUrl !== undefined)
    externalUrl(connection.applicationUrl);
  if (
    connection.cliBinary !== undefined &&
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(connection.cliBinary)
  )
    invalid("Invalid application CLI binary.");
  if (!validateConsumerModel(model, bundle))
    invalid("Invalid or mismatched documentation consumer model.");
  if (connection.transportFacts !== undefined) {
    const facts = connection.transportFacts;
    const numeric = (
      values: Readonly<Record<string, number>>,
      minimum: number,
      maximum: number,
    ) =>
      values &&
      typeof values === "object" &&
      !Array.isArray(values) &&
      Object.values(values).every(
        (value) =>
          Number.isInteger(value) && value >= minimum && value <= maximum,
      );
    if (
      !numeric(facts.httpErrorStatus, 100, 599) ||
      !numeric(facts.cliExitCodes, 0, 255) ||
      (facts.mcpProtocolErrors !== undefined &&
        !numeric(facts.mcpProtocolErrors, -32768, -32000))
    )
      invalid("Invalid documentation transport facts.");
  }
  const root =
    connection.docsUrl === undefined
      ? docsPath
      : externalUrl(connection.docsUrl);
  const docsRoot = root.replace(/\/$/, "") + "/";
  const url = (path: string) =>
    path.startsWith(docsRoot) ? path : `${docsRoot}${path}`;
  const link = (
    label: string,
    path: string,
    active = false,
    context?: { readonly id?: string; readonly describedBy?: string },
  ) =>
    `<a href="${escape(url(path))}"${active ? ' aria-current="page"' : ""}${context?.id ? ` id="${escape(context.id)}"` : ""}${context?.describedBy ? ` aria-describedby="${escape(context.describedBy)}"` : ""}>${escape(label)}</a>`;
  const surfaceIds = new Set<string>();
  for (const surface of connection.surfaces) {
    if (
      !["api", "sdk", "mcp", "cli"].includes(surface.id) ||
      surfaceIds.has(surface.id)
    )
      invalid("Unknown or duplicate documentation connection surface.");
    surfaceIds.add(surface.id);
    if (surface.url !== undefined) externalUrl(surface.url);
    const snippetIds = new Set<string>();
    for (const snippet of surface.snippets) {
      if (
        !snippet.id ||
        snippetIds.has(snippet.id) ||
        !["sh", "json", "toml", "typescript"].includes(snippet.language)
      )
        invalid("Invalid documentation connection snippet.");
      snippetIds.add(snippet.id);
    }
  }
  let content: string;
  let title: string;
  if (pageId === "connection") {
    title = `Connect to ${connection.serviceId}`;
    let index = 0;
    content = `<h1>${escape(title)}</h1>${connection.surfaces
      .map((surface) => {
        const snippets = surface.snippets
          .map((snippet) => {
            const target = `snippet-${index++}`;
            return `<section><h3><label for="${target}">${escape(snippet.label)}</label></h3><textarea id="${target}" readonly spellcheck="false" data-language="${snippet.language}">${escape(snippet.text)}</textarea><button type="button" data-copy="${target}" aria-label="${escape(`Copy ${snippet.label}`)}">Copy</button></section>`;
          })
          .join("");
        return `<section><h2>${escape(surface.label)}</h2>${surface.url === undefined ? "" : `<p>Location: <a href="${escape(surface.url)}">${escape(surface.url)}</a></p>`}${surface.protocols === undefined ? "" : `<p>Protocols: ${escape(surface.protocols.join(", "))}</p>`}${surface.guidance === undefined ? "" : `<p>${escape(surface.guidance)}</p>`}${snippets}</section>`;
      })
      .join("")}`;
  } else {
    const reference = renderReference(
      model,
      bundle,
      pageId,
      connection,
      link,
      url,
    );
    if (reference === undefined)
      throw new DocumentationBrowserError(
        "CAP_DOCS_BROWSER_NOT_FOUND",
        "Unknown documentation page.",
      );
    title = reference.title;
    content = reference.content;
  }
  // Both page kinds use the same fixed copy handler. Only renderer-owned
  // controls with matching readonly textareas activate it; authored text is
  // HTML-escaped and cannot introduce a control or executable snippet.
  const copyTargets = [
    ...content.matchAll(/<button type="button" data-copy="([^"]+)"/g),
  ];
  const copyEnabled =
    copyTargets.length > 0 &&
    copyTargets.every(([, id]) => content.includes(`id="${id}" readonly`));
  if (copyEnabled)
    content += '<p id="copy-status" role="status" aria-live="polite"></p>';
  const sidebar = referenceNavigation(model, pageId, link);
  return {
    html: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escape(title)}</title><style>${options.stylesheet ?? styles}</style></head><body><a class="skip" href="#content">Skip to content</a><header class="docs-header"><nav aria-label="Documentation">${link(connection.serviceId, "")}${link("Connection", "connection")}</nav></header><div class="documentation-layout docs-layout">${sidebar}<main class="docs-main" id="content" tabindex="-1">${content}</main></div><footer>Capaxle capability documentation</footer>${copyEnabled ? `<script>${copyScript}</script>` : ""}</body></html>`,
  };
}
