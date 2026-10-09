import { Buffer } from "node:buffer";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { isIP } from "node:net";
import type {
  AdapterIngress,
  RuntimeDocument,
  InvocationResult,
} from "@capaxle/runtime";
import { capabilitySemanticHash, jcs, JSON_SCHEMA_DIALECT } from "@capaxle/ir";
import type { JsonValue } from "@capaxle/ir";

type ObjectData = Record<string, JsonValue>;
type Capability = RuntimeDocument["capabilities"][number];
interface Projection {
  enabled: boolean;
  method: string;
  path: string;
  bindings: Record<string, string>;
}
export interface DiscoveryContext {
  readonly http: {
    readonly collection: string;
    readonly detailTemplate: string;
    readonly schemaTemplate: string;
  };
  readonly mcp: { readonly endpoint: string };
}
export const DEFAULT_DISCOVERY_CONTEXT: DiscoveryContext = Object.freeze({
  http: Object.freeze({
    collection: "/.well-known/capabilities",
    detailTemplate: "/.well-known/capabilities/{id}",
    schemaTemplate: "/.well-known/capabilities/{id}/schema",
  }),
  mcp: Object.freeze({ endpoint: "/mcp" }),
});
export interface HttpProjectionOptions {
  readonly document: RuntimeDocument;
  readonly irHash: string;
  readonly securitySchemes?: Readonly<Record<string, JsonValue>>;
  readonly security?: readonly Readonly<Record<string, readonly string[]>>[];
  readonly profile?: "public" | "internal";
  readonly discovery?: DiscoveryContext;
  /** Trusted deployment mount; excluded from portable Capability IR. */
  readonly basePath?: string;
  readonly externalUrl?: string;
}
export interface HttpAdapterOptions extends HttpProjectionOptions {
  readonly ingress: AdapterIngress;
  readonly headerAllowlist?: readonly string[];
}
export interface HttpRequest {
  readonly method: string;
  readonly path: string;
  readonly headers?: Readonly<
    Record<string, string | readonly string[] | undefined>
  >;
  readonly body?: unknown;
  readonly signal?: AbortSignal;
  readonly deadline?: Date;
  readonly invalidBody?: boolean;
}
export interface HttpResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: JsonValue;
}
export interface HttpAdapter {
  readonly openapi: JsonValue;
  readonly discovery: JsonValue;
  readonly discoveryContext: DiscoveryContext;
  matches(request: Pick<HttpRequest, "method" | "path">): boolean;
  handle(request: HttpRequest): Promise<HttpResponse>;
}
export const HTTP_ERROR_STATUS = Object.freeze({
  invalid_argument: 400,
  unauthenticated: 401,
  permission_denied: 403,
  not_found: 404,
  already_exists: 409,
  failed_precondition: 412,
  conflict: 409,
  resource_exhausted: 429,
  cancelled: 499,
  deadline_exceeded: 504,
  unavailable: 503,
  internal: 500,
});
const object = (value: unknown): ObjectData =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as ObjectData)
    : {};
const projection = (cap: Capability): Projection =>
  cap.interfaces.http as unknown as Projection;
const validDiscoveryPath = (value: string, template: boolean): boolean => {
  if (
    !value.startsWith("/") ||
    value.startsWith("//") ||
    /[\u0000-\u0020\u007f-\u009f]/.test(value) ||
    /[?#\\\0]/.test(value) ||
    value
      .split("/")
      .slice(1)
      .some((part) => part === "" || part === "." || part === "..") ||
    /%(?![0-9A-F]{2})/.test(value) ||
    /%(?:2D|2E|30|31|32|33|34|35|36|37|38|39|41|42|43|44|45|46|47|48|49|4A|4B|4C|4D|4E|4F|50|51|52|53|54|55|56|57|58|59|5A|5F|61|62|63|64|65|66|67|68|69|6A|6B|6C|6D|6E|6F|70|71|72|73|74|75|76|77|78|79|7A|7E)/.test(
      value,
    )
  )
    return false;
  const tokens = value.split("/").filter((part) => part === "{id}").length;
  const remaining = value.replaceAll("{id}", "");
  return template
    ? tokens === 1 && !/[{}]/.test(remaining)
    : tokens === 0 && !/[{}]/.test(value);
};
export function validateDiscoveryContext(value: unknown): DiscoveryContext {
  const root = object(value);
  const http = object(root.http);
  const mcp = object(root.mcp);
  if (
    Object.keys(root).sort().join("\0") !== "http\0mcp" ||
    Object.keys(http).sort().join("\0") !==
      "collection\0detailTemplate\0schemaTemplate" ||
    Object.keys(mcp).join("\0") !== "endpoint" ||
    typeof http.collection !== "string" ||
    typeof http.detailTemplate !== "string" ||
    typeof http.schemaTemplate !== "string" ||
    typeof mcp.endpoint !== "string" ||
    !validDiscoveryPath(http.collection, false) ||
    !validDiscoveryPath(http.detailTemplate, true) ||
    !validDiscoveryPath(http.schemaTemplate, true) ||
    !validDiscoveryPath(mcp.endpoint, false) ||
    pathsOverlap(http.collection, http.detailTemplate) ||
    pathsOverlap(http.collection, http.schemaTemplate) ||
    pathsOverlap(http.detailTemplate, http.schemaTemplate)
  )
    throw new Error("CAP_DISCOVERY_CONTEXT_MISMATCH");
  return Object.freeze({
    http: Object.freeze({
      collection: http.collection,
      detailTemplate: http.detailTemplate,
      schemaTemplate: http.schemaTemplate,
    }),
    mcp: Object.freeze({ endpoint: mcp.endpoint }),
  });
}
const equalDiscovery = (left: DiscoveryContext, right: DiscoveryContext) =>
  left.http.collection === right.http.collection &&
  left.http.detailTemplate === right.http.detailTemplate &&
  left.http.schemaTemplate === right.http.schemaTemplate &&
  left.mcp.endpoint === right.mcp.endpoint;
const resolvedDiscovery = (
  resolved: unknown,
  assertion?: unknown,
): DiscoveryContext => {
  const context = validateDiscoveryContext(resolved);
  if (
    assertion !== undefined &&
    !equalDiscovery(context, validateDiscoveryContext(assertion))
  )
    throw new Error("CAP_DISCOVERY_CONTEXT_MISMATCH");
  return context;
};
const pointer = (value: string) =>
  value.replaceAll("~", "~0").replaceAll("/", "~1");
const unpointer = (value: string) =>
  value.replaceAll("~1", "/").replaceAll("~0", "~");
const encoded = (value: string) => Buffer.from(value).toString("base64url");
function rootSchema(
  ref: unknown,
  document: RuntimeDocument,
): { schema: ObjectData; owner: string } {
  const r = object(ref);
  if (typeof r.$ref === "string" && r.$ref.startsWith("#/schemas/")) {
    const name = unpointer(r.$ref.slice(10));
    return { schema: object(document.schemas[name]), owner: `shared:${name}` };
  }
  return { schema: object(r.schema), owner: "inline" };
}
interface SchemaResource {
  readonly schema: ObjectData;
  readonly root: ObjectData;
  readonly owner: string;
}
function resolveSchema(
  value: JsonValue | undefined,
  root: ObjectData,
  document: RuntimeDocument,
  owner = "inline",
  seen = new Set<ObjectData>(),
): SchemaResource {
  const schema = object(value);
  const ref = schema.$ref;
  if (typeof ref !== "string") return { schema, root, owner };
  if (seen.has(schema)) throw new Error("CAP_HTTP_SCHEMA_INVALID");
  seen.add(schema);
  if (ref.startsWith("#/$defs/"))
    return resolveSchema(
      object(root.$defs)[unpointer(ref.slice(8))],
      root,
      document,
      owner,
      seen,
    );
  if (ref.startsWith("#/schemas/")) {
    const name = unpointer(ref.slice(10));
    if (!Object.hasOwn(document.schemas, name))
      throw new Error("CAP_HTTP_SCHEMA_INVALID");
    const next = object(document.schemas[name]);
    return resolveSchema(next, next, document, `shared:${name}`, seen);
  }
  throw new Error("CAP_HTTP_SCHEMA_INVALID");
}
type ScalarKind = "string" | "integer" | "number" | "boolean";
function scalarKind(
  value: JsonValue | undefined,
  root: ObjectData,
  document: RuntimeDocument,
  owner: string,
  seen = new Set<ObjectData>(),
): ScalarKind | null {
  const resource = resolveSchema(value, root, document, owner);
  const schema = resource.schema;
  if (seen.has(schema)) return null;
  const scalar = (kind: unknown): kind is ScalarKind =>
    typeof kind === "string" &&
    ["string", "integer", "number", "boolean"].includes(kind);
  if (scalar(schema.type)) return schema.type;
  const jsonType = (item: JsonValue) =>
    typeof item === "number" && Number.isInteger(item)
      ? "integer"
      : item === null
        ? "null"
        : typeof item;
  if (Object.hasOwn(schema, "const")) {
    const kind = jsonType(schema.const!);
    return scalar(kind) ? kind : null;
  }
  if (Array.isArray(schema.enum) && schema.enum.length > 0) {
    const kinds = new Set(schema.enum.map(jsonType));
    const [kind] = kinds;
    return kinds.size === 1 && scalar(kind) ? kind : null;
  }
  if (Array.isArray(schema.oneOf) && schema.oneOf.length > 0) {
    const kinds = new Set(
      schema.oneOf.map((branch) =>
        scalarKind(
          branch,
          resource.root,
          document,
          resource.owner,
          new Set([...seen, schema]),
        ),
      ),
    );
    const [kind] = kinds;
    return kinds.size === 1 && scalar(kind) ? kind : null;
  }
  return null;
}
function validateSecurityConfiguration(
  schemes: Readonly<Record<string, JsonValue>>,
  requirements: HttpProjectionOptions["security"],
) {
  const fail = () => {
    throw new Error("CAP_HTTP_SECURITY_CONFIG_INVALID");
  };
  const record = (value: unknown): ObjectData => {
    if (
      value === null ||
      typeof value !== "object" ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Reflect.ownKeys(value).some(
        (key) =>
          typeof key !== "string" ||
          !("value" in Object.getOwnPropertyDescriptor(value, key)!) ||
          !Object.getOwnPropertyDescriptor(value, key)!.enumerable,
      )
    )
      return fail();
    return value as ObjectData;
  };
  const shape = (value: ObjectData, keys: readonly string[]) => {
    if (
      Object.keys(value).some((key) => !keys.includes(key) && !/^x-/.test(key))
    )
      fail();
  };
  const text = (value: unknown) => {
    if (typeof value !== "string") fail();
  };
  record(schemes);
  try {
    jcs(schemes as JsonValue);
  } catch {
    fail();
  }
  for (const [name, item] of Object.entries(schemes)) {
    if (!/^[A-Za-z0-9._-]+$/.test(name)) fail();
    const scheme = record(item);
    if (scheme.description !== undefined) text(scheme.description);
    switch (scheme.type) {
      case "apiKey":
        shape(scheme, ["type", "description", "name", "in"]);
        text(scheme.name);
        if (
          typeof scheme.in !== "string" ||
          !["header", "query", "cookie"].includes(scheme.in)
        )
          fail();
        break;
      case "http":
        shape(scheme, [
          "type",
          "description",
          "scheme",
          ...(typeof scheme.scheme === "string" &&
          /^bearer$/i.test(scheme.scheme)
            ? ["bearerFormat"]
            : []),
        ]);
        text(scheme.scheme);
        if (scheme.bearerFormat !== undefined) text(scheme.bearerFormat);
        break;
      case "mutualTLS":
        shape(scheme, ["type", "description"]);
        break;
      case "openIdConnect":
        shape(scheme, ["type", "description", "openIdConnectUrl"]);
        text(scheme.openIdConnectUrl);
        break;
      case "oauth2": {
        shape(scheme, ["type", "description", "flows"]);
        const flows = record(scheme.flows);
        shape(flows, [
          "implicit",
          "password",
          "clientCredentials",
          "authorizationCode",
        ]);
        for (const [kind, item] of Object.entries(flows)) {
          if (kind.startsWith("x-")) continue;
          const flow = record(item);
          const auth = kind === "implicit" || kind === "authorizationCode";
          const token = kind !== "implicit";
          shape(flow, [
            "scopes",
            "refreshUrl",
            ...(auth ? ["authorizationUrl"] : []),
            ...(token ? ["tokenUrl"] : []),
          ]);
          if (auth) text(flow.authorizationUrl);
          if (token) text(flow.tokenUrl);
          if (flow.refreshUrl !== undefined) text(flow.refreshUrl);
          for (const value of Object.values(record(flow.scopes))) text(value);
        }
        break;
      }
      default:
        fail();
    }
  }
  if (requirements !== undefined) {
    if (!Array.isArray(requirements)) fail();
    for (const item of requirements) {
      const requirement = record(item);
      for (const [name, scopes] of Object.entries(requirement)) {
        if (
          !Object.hasOwn(schemes, name) ||
          !Array.isArray(scopes) ||
          scopes.some((scope) => typeof scope !== "string")
        )
          fail();
      }
    }
  }
}
function exposed(
  document: RuntimeDocument,
  profile: "public" | "internal" = "public",
) {
  return document.capabilities.filter(
    (c) =>
      projection(c).enabled &&
      c.access.exposure.http !== "disabled" &&
      (profile === "internal" || c.access.exposure.http === "public"),
  );
}
function verifyDocument(options: HttpProjectionOptions) {
  if (capabilitySemanticHash(options.document) !== options.irHash)
    throw new Error("CAP_HTTP_IR_HASH_MISMATCH");
  if (
    options.profile !== undefined &&
    options.profile !== "public" &&
    options.profile !== "internal"
  )
    throw new Error("CAP_HTTP_PROFILE_INVALID");
}
const errorSchema: JsonValue = {
  type: "object",
  required: ["ok", "error"],
  additionalProperties: false,
  properties: {
    ok: { const: false },
    error: {
      type: "object",
      required: ["code", "status", "message", "retryable", "correlationId"],
      properties: {
        code: { type: "string" },
        status: { type: "string", enum: Object.keys(HTTP_ERROR_STATUS) },
        message: { type: "string" },
        retryable: { type: "boolean" },
        correlationId: { type: "string" },
        details: {},
      },
      additionalProperties: false,
    },
  },
};
/** Project canonical schema resources; owner-scoped definitions never lose their reference base. */
export function generateOpenApi(options: HttpProjectionOptions): {
  readonly filename: "openapi.json";
  readonly document: JsonValue;
  readonly content: string;
} {
  verifyDocument(options);
  const discoveryContext = validateDiscoveryContext(
    options.discovery ?? DEFAULT_DISCOVERY_CONTEXT,
  );
  const basePath = options.basePath ?? "/";
  if (
    basePath !== "/" &&
    (!basePath.startsWith("/") ||
      basePath.startsWith("//") ||
      basePath.endsWith("/") ||
      /[?#\\\0%]/.test(basePath) ||
      basePath
        .split("/")
        .slice(1)
        .some((part) => !part || part === "." || part === ".."))
  )
    throw new Error("CAP_APP_MOUNT_INVALID");
  const mounted = (path: string) =>
    basePath === "/" ? path : `${basePath}${path}`;
  let externalOrigin: string | undefined;
  if (options.externalUrl !== undefined) {
    let parsed: URL;
    try {
      parsed = new URL(options.externalUrl);
    } catch {
      throw new Error("CAP_APP_MOUNT_INVALID");
    }
    if (
      parsed.pathname !== basePath ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash ||
      !["http:", "https:"].includes(parsed.protocol)
    )
      throw new Error("CAP_APP_MOUNT_INVALID");
    externalOrigin = parsed.origin;
  }
  const components: ObjectData = Object.assign(Object.create(null), {
    CapabilityError: errorSchema,
  });
  const sharedName = (name: string) =>
    /^[A-Za-z0-9._-]+$/.test(name) && !name.startsWith("Capability")
      ? name
      : `CapabilitySharedEncoded.${encoded(name)}`;
  const defName = (owner: string, name: string) =>
    `CapabilityDef.${encoded(owner)}.${encoded(name)}`;
  const hoisted = new Set<string>();
  const schemes = options.securitySchemes ?? {
    capaxleAuthorization: {
      type: "apiKey",
      in: "header",
      name: "Authorization",
      description:
        "Opaque Authorization header forwarded unchanged to the configured runtime authentication provider.",
    },
  };
  if (
    (options.securitySchemes === undefined) !==
    (options.security === undefined)
  )
    throw new Error("CAP_HTTP_SECURITY_CONFIG_INVALID");
  validateSecurityConfiguration(schemes, options.security);
  function project(value: JsonValue, owner: string): JsonValue {
    if (Array.isArray(value)) return value.map((v) => project(v, owner));
    if (value === null || typeof value !== "object") return value;
    const result: ObjectData = Object.create(null);
    for (const [key, item] of Object.entries(value)) {
      if (key === "$defs") continue;
      if (["const", "enum", "default", "examples"].includes(key)) {
        result[key] = item;
        continue;
      }
      if (
        ["properties", "patternProperties", "dependentSchemas"].includes(key)
      ) {
        const dictionary: ObjectData = Object.create(null);
        for (const [name, entry] of Object.entries(object(item)))
          dictionary[name] = project(entry, owner);
        result[key] = dictionary;
        continue;
      }
      if (key === "$ref" && typeof item === "string") {
        if (item.startsWith("#/$defs/"))
          result[key] =
            `#/components/schemas/${pointer(defName(owner, unpointer(item.slice(8))))}`;
        else if (item.startsWith("#/schemas/")) {
          const name = unpointer(item.slice(10));
          hoistShared(name);
          result[key] = `#/components/schemas/${pointer(sharedName(name))}`;
        } else throw new Error("CAP_HTTP_SCHEMA_INVALID");
      } else result[key] = project(item, owner);
    }
    return result;
  }
  function hoist(schema: ObjectData, owner: string) {
    if (hoisted.has(owner)) return;
    hoisted.add(owner);
    for (const [name, definition] of Object.entries(object(schema.$defs)))
      components[defName(owner, name)] = project(definition, owner);
  }
  function hoistShared(name: string) {
    const schema = object(options.document.schemas[name]);
    if (!Object.hasOwn(options.document.schemas, name))
      throw new Error("CAP_HTTP_SCHEMA_INVALID");
    const owner = `shared:${name}`;
    if (hoisted.has(owner)) return;
    hoist(schema, owner);
    components[sharedName(name)] = project(schema, owner);
  }
  function resource(ref: unknown, owner: string) {
    const root = rootSchema(ref, options.document);
    const actual = root.owner === "inline" ? owner : root.owner;
    if (root.owner !== "inline") hoistShared(actual.slice(7));
    else hoist(root.schema, actual);
    return { schema: root.schema, root: root.schema, owner: actual };
  }
  const paths: ObjectData = Object.create(null);
  if (
    options.document.capabilities.some((capability) => {
      const value = projection(capability);
      return (
        value.enabled === true &&
        reservedRouteCollision(value, discoveryContext)
      );
    })
  )
    throw new Error("CAP_HTTP_ROUTE_COLLISION");
  for (const cap of exposed(options.document, options.profile)) {
    const p = projection(cap);
    const input = resource(cap.input, `input:${cap.id}:${cap.version}`);
    const output = resource(cap.output, `output:${cap.id}:${cap.version}`);
    const resolvedInput = resolveSchema(
      input.schema,
      input.root,
      options.document,
      input.owner,
    );
    const schema = resolvedInput.schema;
    const properties = object(schema.properties);
    const required = Array.isArray(schema.required) ? schema.required : [];
    const parameters: JsonValue[] = [
      {
        name: "X-Correlation-Id",
        in: "header",
        required: false,
        schema: { type: "string", maxLength: 128 },
        description:
          "Untrusted hint; each result carries a fresh trusted correlation ID.",
      },
      ...(cap.effects.idempotency === "key"
        ? [
            {
              name: "Idempotency-Key",
              in: "header",
              required: true,
              schema: { type: "string", minLength: 1 },
            },
          ]
        : []),
      ...(cap.effects.confirmation === "required"
        ? [
            {
              name: "X-Cap-Confirmation",
              in: "header",
              required: false,
              schema: { type: "string" },
              description:
                "Opaque single-use approval evidence from the independent confirmation decision operation.",
            },
          ]
        : []),
    ];
    const bodyProperties: ObjectData = Object.create(null);
    const bodyRequired: JsonValue[] = [];
    for (const [name, binding] of Object.entries(p.bindings).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    )) {
      const property = project(properties[name] ?? {}, resolvedInput.owner);
      if (binding === "body") {
        bodyProperties[name] = property;
        if (required.includes(name)) bodyRequired.push(name);
      } else {
        const parameter: ObjectData = {
          name: binding === "header" ? `X-Cap-Input-${name}` : name,
          in: binding,
          required: binding === "path" || required.includes(name),
          schema: property,
        };
        if (binding === "query") {
          parameter.style = "form";
          parameter.explode = true;
        }
        parameters.push(parameter);
      }
    }
    const responses: ObjectData = {
      "200": {
        description: "Canonical capability result",
        content: {
          "application/json": { schema: project(output.schema, output.owner) },
        },
      },
    };
    for (const status of new Set(Object.values(HTTP_ERROR_STATUS)))
      responses[String(status)] = {
        description: "Canonical capability error",
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/CapabilityError" },
          },
        },
      };
    const operation: ObjectData = {
      operationId: `capability.v${cap.version.split(".")[0]}.${cap.id}`,
      summary: cap.summary,
      parameters,
      responses,
      "x-capability-id": cap.id,
      "x-capability-version": cap.version,
      "x-capability-major": Number(cap.version.split(".")[0]),
      "x-capability-effects": cap.effects as unknown as JsonValue,
      "x-capability-permissions": cap.access
        .permissions as unknown as JsonValue,
      "x-capability-ir-hash": options.irHash,
      "x-capability-idempotency": cap.effects.idempotency,
      "x-capability-confirmation": cap.effects.confirmation,
    };
    const metadata = cap as unknown as ObjectData;
    for (const key of ["description", "tags", "examples", "lifecycle"])
      if (metadata[key] !== undefined)
        operation[
          key === "lifecycle"
            ? "x-capability-lifecycle"
            : key === "examples"
              ? "x-capability-examples"
              : key
        ] = metadata[key]!;
    if (object(metadata.lifecycle).status === "deprecated")
      operation.deprecated = true;
    const protectedOperation =
      cap.access.authentication === "required" ||
      cap.access.exposure.http === "authenticated" ||
      cap.access.permissions.public !== true;
    if (
      protectedOperation &&
      options.security &&
      (options.security.length === 0 ||
        options.security.some((item) => Object.keys(item).length === 0))
    )
      throw new Error("CAP_HTTP_SECURITY_CONFIG_INVALID");
    operation.security = protectedOperation
      ? ((options.security as unknown as JsonValue) ?? [
          { capaxleAuthorization: [] },
        ])
      : cap.access.authentication === "optional"
        ? [
            {},
            ...((options.security as unknown as JsonValue[]) ?? [
              { capaxleAuthorization: [] },
            ]),
          ]
        : [];
    const opaque = !(
      schema.type === "object" &&
      schema.additionalProperties === false &&
      schema.properties !== undefined &&
      schema.const === undefined &&
      schema.enum === undefined &&
      schema.oneOf === undefined
    );
    if (opaque || Object.keys(bodyProperties).length > 0)
      operation.requestBody = {
        required: opaque || bodyRequired.length > 0,
        content: {
          "application/json": {
            schema: opaque
              ? project(input.schema, input.owner)
              : {
                  type: "object",
                  properties: bodyProperties,
                  required: bodyRequired,
                  additionalProperties: false,
                },
          },
        },
      };
    operation["x-capability-errors"] = Object.fromEntries(
      Object.entries(cap.errors).map(([code, error]) => {
        const details = error.details
          ? resource(error.details, `error:${cap.id}:${cap.version}:${code}`)
          : undefined;
        return [
          code,
          {
            status: error.status,
            message: error.message,
            retryable: error.retryable,
            ...(details
              ? { detailsSchema: project(details.schema, details.owner) }
              : {}),
          },
        ];
      }),
    ) as JsonValue;
    const fullPath = mounted(p.path);
    const path = object(paths[fullPath]);
    path[p.method.toLowerCase()] = operation;
    paths[fullPath] = path;
  }
  for (const [path, summary, parameter] of [
    [discoveryContext.http.collection, "List public capabilities", false],
    [
      discoveryContext.http.detailTemplate,
      "Describe one public capability",
      true,
    ],
    [
      discoveryContext.http.schemaTemplate,
      "Describe one public capability schema",
      true,
    ],
  ] as const) {
    const fullPath = mounted(path);
    const pathItem = object(paths[fullPath]);
    if (Object.hasOwn(pathItem, "get"))
      throw new Error("CAP_HTTP_ROUTE_COLLISION");
    pathItem.get = {
      summary,
      operationId:
        path === discoveryContext.http.collection
          ? "capaxle.discovery.list"
          : path === discoveryContext.http.detailTemplate
            ? "capaxle.discovery.describe"
            : "capaxle.discovery.schema",
      parameters: parameter
        ? [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "string" },
            },
          ]
        : [],
      responses: {
        "200": {
          description: "Capability discovery response",
          content: { "application/json": { schema: {} } },
        },
        "404": {
          description: "Capability not found",
          content: { "application/json": { schema: {} } },
        },
      },
      security: [],
    };
    paths[fullPath] = pathItem;
  }
  const rawDocument: JsonValue = {
    openapi: "3.1.1",
    "x-capaxle-discovery": {
      list: mounted(discoveryContext.http.collection),
      describe: mounted(discoveryContext.http.detailTemplate),
      schema: mounted(discoveryContext.http.schemaTemplate),
    },
    info: { title: "Capaxle capabilities", version: "0.1" },
    ...(externalOrigin === undefined
      ? {}
      : { servers: [{ url: externalOrigin }] }),
    paths,
    components: {
      schemas: components,
      securitySchemes: schemes as JsonValue,
    },
  };
  const document = JSON.parse(JSON.stringify(rawDocument)) as JsonValue;
  return { filename: "openapi.json", document, content: `${jcs(document)}\n` };
}
function pathsOverlap(left: string, right: string): boolean {
  const a = left.split("/");
  const b = right.split("/");
  const variable = /^\{[A-Za-z_][A-Za-z0-9_.-]*\}$/;
  return (
    a.length === b.length &&
    a.every(
      (segment, index) =>
        segment === b[index] ||
        variable.test(segment) ||
        variable.test(b[index]!),
    )
  );
}
function reservedRouteCollision(
  value: Projection,
  discovery: DiscoveryContext,
): boolean {
  return (
    (value.method === "GET" &&
      [
        "/health",
        "/healthz",
        "/ready",
        "/readyz",
        "/readiness",
        "/openapi.json",
        discovery.http.collection,
        discovery.http.detailTemplate,
        discovery.http.schemaTemplate,
      ].some((path) => pathsOverlap(value.path, path))) ||
    (value.method === "POST" &&
      pathsOverlap(value.path, discovery.mcp.endpoint))
  );
}
function matchPath(
  pattern: string,
  path: string,
): Record<string, string> | null {
  const parts = pattern.split("/");
  const actual = path.split("/");
  if (parts.length !== actual.length) return null;
  const params: Record<string, string> = Object.create(null);
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]!;
    if (part.startsWith("{") && part.endsWith("}"))
      params[part.slice(1, -1)] = actual[i]!;
    else if (part !== actual[i]) return null;
  }
  return params;
}
function coerce(text: string, kind: ScalarKind | null): JsonValue {
  if (kind === "string") return text;
  if (kind === "boolean") {
    if (text === "true") return true;
    if (text === "false") return false;
    throw new Error();
  }
  if (!/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(text))
    throw new Error();
  const number = Number(text);
  if (
    !Number.isFinite(number) ||
    (kind === "integer" && !Number.isInteger(number)) ||
    (kind !== "number" && kind !== "integer")
  )
    throw new Error();
  return number;
}
export function serializeHttpResult(result: InvocationResult): HttpResponse {
  const headers: Record<string, string> = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-correlation-id": result.ok
      ? result.correlationId
      : result.error.correlationId,
  };
  if (
    !result.ok &&
    (result.error.status === "resource_exhausted" ||
      result.error.status === "unavailable")
  ) {
    const ms = object(result.error.details).retryAfterMs;
    if (typeof ms === "number" && Number.isFinite(ms) && ms >= 0)
      headers["retry-after"] = String(Math.ceil(ms / 1000));
  }
  return {
    status: result.ok ? 200 : HTTP_ERROR_STATUS[result.error.status],
    headers,
    body: result.ok ? result.value : (result as unknown as JsonValue),
  };
}
/** Detach one canonical schema resource with only its reachable reference closure. */
function discoverySchema(
  ref: unknown,
  document: RuntimeDocument,
  inlineOwner: string,
): JsonValue {
  const original = rootSchema(ref, document);
  const owner = original.owner === "inline" ? inlineOwner : original.owner;
  const definitions: ObjectData = Object.create(null);
  const visited = new Set<string>();
  function referenced(
    value: JsonValue | undefined,
    root: ObjectData,
    owner: string,
    name: string,
  ): string {
    if (value === undefined) throw new Error("CAP_HTTP_SCHEMA_INVALID");
    if (!visited.has(name)) {
      visited.add(name);
      definitions[name] = project(value, root, owner);
    }
    return `#/$defs/${pointer(name)}`;
  }
  function project(
    value: JsonValue,
    root: ObjectData,
    owner: string,
  ): JsonValue {
    if (Array.isArray(value))
      return value.map((item) => project(item, root, owner));
    if (value === null || typeof value !== "object") return value;
    const result: ObjectData = Object.create(null);
    for (const [key, item] of Object.entries(value)) {
      if (key === "$defs") continue;
      if (["default", "const", "enum", "examples"].includes(key)) {
        result[key] = item;
        continue;
      }
      if (
        ["properties", "patternProperties", "dependentSchemas"].includes(key)
      ) {
        const dictionary: ObjectData = Object.create(null);
        for (const [name, schema] of Object.entries(object(item)))
          dictionary[name] = project(schema, root, owner);
        result[key] = dictionary;
        continue;
      }
      if (key === "$ref" && typeof item === "string") {
        if (item.startsWith("#/$defs/")) {
          const name = unpointer(item.slice(8));
          result[key] = referenced(
            object(root.$defs)[name],
            root,
            owner,
            `CapabilityLocal.${encoded(owner)}.${encoded(name)}`,
          );
        } else if (item.startsWith("#/schemas/")) {
          const name = unpointer(item.slice(10));
          const target = document.schemas[name];
          result[key] = referenced(
            target,
            object(target),
            `shared:${name}`,
            `CapabilityShared.${encoded(name)}`,
          );
        } else throw new Error("CAP_HTTP_SCHEMA_INVALID");
      } else result[key] = project(item, root, owner);
    }
    return result;
  }
  const schema = object(project(original.schema, original.schema, owner));
  schema.$schema = JSON_SCHEMA_DIALECT;
  if (Object.keys(definitions).length) schema.$defs = definitions;
  return JSON.parse(
    jcs(JSON.parse(JSON.stringify(schema)) as JsonValue),
  ) as JsonValue;
}
/** This reference adapter extracts only the complete Authorization header. */
function validateConnectedSecurity(
  schemes: HttpProjectionOptions["securitySchemes"],
) {
  for (const value of Object.values(schemes ?? {})) {
    const scheme = object(value);
    if (
      scheme.type === "apiKey" &&
      (scheme.in !== "header" ||
        typeof scheme.name !== "string" ||
        scheme.name.toLowerCase() !== "authorization")
    )
      throw new Error("CAP_HTTP_SECURITY_INVALID");
    if (scheme.type === "mutualTLS")
      throw new Error("CAP_HTTP_SECURITY_INVALID");
  }
}
const reservedHeaders = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "host",
  "content-length",
  "content-type",
  "idempotency-key",
  "traceparent",
  "tracestate",
  "forwarded",
  "x-correlation-id",
]);
function reservedHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    reservedHeaders.has(lower) ||
    lower.startsWith("proxy-") ||
    lower.startsWith("sec-") ||
    lower.startsWith("x-forwarded-") ||
    (lower.startsWith("x-cap-") && !lower.startsWith("x-cap-input-")) ||
    (lower.startsWith("x-cap-input-") &&
      (lower.slice(12).startsWith("x-cap-") || reservedHeader(lower.slice(12))))
  );
}
export function createHttpAdapter(options: HttpAdapterOptions): HttpAdapter {
  verifyDocument(options);
  const discoveryContext = validateDiscoveryContext(
    options.discovery ?? DEFAULT_DISCOVERY_CONTEXT,
  );
  if (options.securitySchemes)
    validateSecurityConfiguration(options.securitySchemes, options.security);
  validateConnectedSecurity(options.securitySchemes);
  const capabilities = exposed(options.document, "internal");
  const allowlist = new Set(options.headerAllowlist ?? []);
  for (const cap of capabilities) {
    const p = projection(cap);
    if (reservedRouteCollision(p, discoveryContext))
      throw new Error("CAP_HTTP_ROUTE_COLLISION");
    const headerNames = new Set<string>();
    for (const [property, binding] of Object.entries(p.bindings)) {
      if (binding !== "header") continue;
      const wire = `X-Cap-Input-${property}`;
      const lower = wire.toLowerCase();
      if (
        reservedHeader(property) ||
        property.toLowerCase().startsWith("x-cap-") ||
        reservedHeader(wire)
      )
        throw new Error("CAP_HTTP_HEADER_RESERVED");
      if (
        !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(wire) ||
        !allowlist.has(lower) ||
        headerNames.has(lower)
      )
        throw new Error("CAP_HTTP_HEADER_FORBIDDEN");
      headerNames.add(lower);
    }
  }
  const openapi = generateOpenApi({ ...options, profile: "public" }).document;
  const publicCaps = exposed(options.document, "public");
  const schemas = new Map(
    publicCaps.map((cap) => [
      cap.id,
      {
        id: cap.id,
        version: cap.version,
        irHash: options.irHash,
        input: {
          schema: discoverySchema(
            cap.input,
            options.document,
            `input:${cap.id}:${cap.version}`,
          ),
        },
        output: {
          schema: discoverySchema(
            cap.output,
            options.document,
            `output:${cap.id}:${cap.version}`,
          ),
        },
      },
    ]),
  );
  const discovery: JsonValue = {
    irHash: options.irHash,
    capabilities: publicCaps.map((c) => ({
      id: c.id,
      version: c.version,
      summary: c.summary,
      effects: c.effects as unknown as JsonValue,
    })),
  };
  return {
    openapi,
    discovery,
    discoveryContext,
    matches(request) {
      const pathname = request.path.split("?")[0]!.split("#")[0]!;
      return (
        (request.method === "GET" &&
          ([
            "/healthz",
            "/readyz",
            "/openapi.json",
            discoveryContext.http.collection,
          ].includes(pathname) ||
            matchPath(discoveryContext.http.detailTemplate, pathname) !==
              null ||
            matchPath(discoveryContext.http.schemaTemplate, pathname) !==
              null)) ||
        capabilities.some(
          (capability) =>
            projection(capability).method === request.method &&
            matchPath(projection(capability).path, pathname) !== null,
        )
      );
    },
    async handle(request) {
      let url: URL;
      let invalidUrl = false;
      const pathname = request.path.split("?")[0]!.split("#")[0]!;
      try {
        if (
          !request.path.startsWith("/") ||
          request.path.startsWith("//") ||
          request.path.includes("#")
        )
          throw new Error();
        url = new URL(request.path, "http://capaxle.invalid");
      } catch {
        invalidUrl = true;
        url = new URL("http://capaxle.invalid");
      }
      if (request.method === "GET") {
        if (pathname === "/healthz" || pathname === "/readyz")
          return {
            status: 200,
            headers: { "cache-control": "no-store" },
            body: { ok: true },
          };
        if (pathname === "/openapi.json")
          return {
            status: 200,
            headers: { "cache-control": "no-store" },
            body: openapi,
          };
        if (pathname === discoveryContext.http.collection)
          return {
            status: 200,
            headers: { "cache-control": "no-store" },
            body: discovery,
          };
        const schemaMatch = matchPath(
          discoveryContext.http.schemaTemplate,
          pathname,
        );
        const detailMatch = matchPath(
          discoveryContext.http.detailTemplate,
          pathname,
        );
        if (schemaMatch || detailMatch) {
          const schema = schemaMatch !== null;
          let id: string;
          try {
            id = decodeURIComponent((schemaMatch ?? detailMatch)!.id!);
          } catch {
            id = "";
          }
          const cap = publicCaps.find((c) => c.id === id);
          if (cap)
            return {
              status: 200,
              headers: { "cache-control": "no-store" },
              body: schema
                ? schemas.get(cap.id)!
                : object(discovery).capabilities instanceof Array
                  ? (object(discovery).capabilities as JsonValue[]).find(
                      (c) => object(c).id === id,
                    )!
                  : {},
            };
        }
      }
      const cap = capabilities.find(
        (c) =>
          projection(c).method === request.method &&
          matchPath(projection(c).path, pathname) !== null,
      );
      if (!cap)
        return serializeHttpResult(
          await options.ingress.invoke({
            capability: "",
            adapterCandidate: {
              ok: false,
              code: "CAP_INPUT_INVALID",
              status: "invalid_argument",
            },
          }),
        );
      const p = projection(cap);
      const params = matchPath(p.path, pathname)!;
      const headers: Record<string, string | readonly string[] | undefined> =
        Object.create(null);
      let invalid = request.invalidBody === true || invalidUrl;
      for (const [name, value] of Object.entries(request.headers ?? {})) {
        const key = name.toLowerCase();
        if (Object.hasOwn(headers, key)) invalid = true;
        headers[key] = value;
      }
      const root = rootSchema(cap.input, options.document);
      const resolvedInput = resolveSchema(
        root.schema,
        root.schema,
        options.document,
        root.owner,
      );
      const schema = resolvedInput.schema;
      const properties = object(schema.properties);
      const opaque = !(
        schema.type === "object" &&
        schema.additionalProperties === false &&
        schema.properties !== undefined &&
        schema.const === undefined &&
        schema.enum === undefined &&
        schema.oneOf === undefined
      );
      let input: Record<string, unknown> = Object.create(null);
      try {
        if (opaque && request.body === undefined) throw new Error();
        if (request.body !== undefined) {
          if (
            request.body === null ||
            typeof request.body !== "object" ||
            Array.isArray(request.body)
          )
            throw new Error();
          for (const [key, value] of Object.entries(request.body))
            Object.defineProperty(input, key, {
              value,
              enumerable: true,
              writable: true,
              configurable: true,
            });
        }
        if (
          !opaque &&
          !Object.values(p.bindings).includes("body") &&
          Object.keys(input).length > 0
        )
          throw new Error();
        if (
          !opaque &&
          !Object.values(p.bindings).includes("body") &&
          Object.keys(properties).length > 0 &&
          request.body !== undefined
        )
          throw new Error();
        for (const [property, binding] of Object.entries(p.bindings)) {
          if (binding === "body") continue;
          if (Object.hasOwn(input, property)) throw new Error();
          const definition = resolveSchema(
            properties[property],
            resolvedInput.root,
            options.document,
            resolvedInput.owner,
          );
          let values: readonly string[];
          if (binding === "path")
            values = [decodeURIComponent(params[property]!)];
          else if (binding === "query")
            values = url.searchParams.getAll(property);
          else {
            const value = headers[`x-cap-input-${property}`.toLowerCase()];
            values =
              value === undefined
                ? []
                : typeof value === "string"
                  ? [value]
                  : value;
          }
          if (values.length === 0) continue;
          let value: JsonValue;
          if (definition.schema.type === "array" && binding === "query")
            value = values.map((v) =>
              coerce(
                v,
                scalarKind(
                  definition.schema.items,
                  definition.root,
                  options.document,
                  definition.owner,
                ),
              ),
            );
          else {
            if (values.length !== 1) throw new Error();
            value = coerce(
              values[0]!,
              scalarKind(
                definition.schema,
                definition.root,
                options.document,
                definition.owner,
              ),
            );
          }
          Object.defineProperty(input, property, {
            value,
            enumerable: true,
            writable: true,
            configurable: true,
          });
        }
      } catch {
        invalid = true;
        input = Object.create(null);
      }
      const control: Record<string, unknown> = {};
      let invalidCorrelation = false;
      for (const [header, key] of [
        ["x-correlation-id", "correlationId"],
        ["idempotency-key", "idempotencyKey"],
        ["x-cap-confirmation", "confirmationToken"],
      ]) {
        const value = headers[header!];
        if (
          value !== undefined ||
          (key === "correlationId" && Object.hasOwn(headers, header!))
        ) {
          if (typeof value !== "string") {
            invalid = true;
            if (key === "correlationId") invalidCorrelation = true;
          } else control[key!] = value;
        }
      }
      const result = await options.ingress.invoke({
        capability: cap.id,
        version: cap.version,
        ...(headers.authorization === undefined
          ? {}
          : { credentials: headers.authorization }),
        ...control,
        ...(request.signal ? { signal: request.signal } : {}),
        ...(request.deadline ? { deadline: request.deadline } : {}),
        adapterCandidate: invalid
          ? {
              ok: false,
              code: "CAP_INPUT_INVALID",
              status: "invalid_argument",
              ...(invalidCorrelation
                ? { safeDetails: { path: "/correlationId" } }
                : {}),
            }
          : { ok: true, input },
      });
      return serializeHttpResult(result);
    },
  };
}
export interface HttpHostOptions {
  readonly adapter: HttpAdapter;
  readonly discovery?: DiscoveryContext;
  readonly basePath?: string;
  readonly port?: number;
  readonly host?: string;
  readonly maxBodyBytes?: number;
  readonly requestTimeoutMs?: number;
}
export interface HttpNodeHandlerOptions extends HttpHostOptions {
  readonly fallthrough?: boolean;
}
export interface HttpHost {
  readonly url: string;
  update(adapter: HttpAdapter): void;
  close(): Promise<void>;
}
export interface HttpNodeHandler {
  handle(req: IncomingMessage, res: ServerResponse): Promise<boolean>;
  update(adapter: HttpAdapter): void;
  close(): void;
  abortActive(): void;
}

/** Reusable Node request handler; unmatched requests remain unread. */
export function createHttpNodeHandler(
  options: HttpNodeHandlerOptions,
): HttpNodeHandler {
  const discoveryAssertion =
    options.discovery === undefined
      ? undefined
      : validateDiscoveryContext(options.discovery);
  if (
    discoveryAssertion !== undefined &&
    !equalDiscovery(options.adapter.discoveryContext, discoveryAssertion)
  )
    throw new Error("CAP_DISCOVERY_CONTEXT_MISMATCH");
  if (
    options.fallthrough !== false &&
    typeof options.adapter.matches !== "function"
  )
    throw new Error("CAP_HTTP_HOST_CONFIG_INVALID");
  let adapter = options.adapter;
  let closing = false;
  const active = new Set<AbortController>();
  const max = options.maxBodyBytes ?? 1048576;
  const timeout = options.requestTimeoutMs ?? 30000;
  const basePath = options.basePath ?? "/";
  if (
    !Number.isSafeInteger(max) ||
    max < 1 ||
    !Number.isSafeInteger(timeout) ||
    timeout < 1 ||
    !basePath.startsWith("/") ||
    (basePath !== "/" && (basePath.endsWith("/") || basePath.startsWith("//")))
  )
    throw new Error("CAP_HTTP_HOST_CONFIG_INVALID");
  return {
    async handle(req, res) {
      const currentPath = req.url ?? "/";
      const localPath =
        basePath === "/"
          ? currentPath
          : currentPath.startsWith(`${basePath}/`)
            ? currentPath.slice(basePath.length)
            : currentPath === basePath
              ? "/"
              : "";
      const current = adapter;
      if (
        !localPath ||
        (options.fallthrough !== false &&
          !current.matches({ method: req.method ?? "GET", path: localPath }))
      )
        return false;
      const controller = new AbortController();
      active.add(controller);
      req.on("aborted", () => controller.abort());
      res.on("close", () => {
        if (!res.writableEnded) controller.abort();
      });
      const deadline = new Date(Date.now() + timeout);
      const timer = setTimeout(() => {
        if (!req.complete) controller.abort();
      }, timeout);
      timer.unref();
      try {
        if (closing) {
          res.writeHead(503, { "cache-control": "no-store" });
          res.end(JSON.stringify({ code: "CAP_DEPENDENCY_UNAVAILABLE" }));
          return true;
        }
        let size = 0;
        const chunks: Buffer[] = [];
        let invalidBody = false;
        for await (const chunk of req) {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          size += bytes.length;
          if (size <= max) chunks.push(bytes);
          else invalidBody = true;
        }
        let body: unknown;
        if (size > 0 && !invalidBody) {
          try {
            body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          } catch {
            invalidBody = true;
          }
        }
        const headers: Record<string, string | readonly string[]> =
          Object.create(null);
        for (let i = 0; i < req.rawHeaders.length; i += 2) {
          const name = req.rawHeaders[i]!.toLowerCase(),
            value = req.rawHeaders[i + 1]!;
          const old = headers[name];
          headers[name] =
            old === undefined
              ? value
              : typeof old === "string"
                ? [old, value]
                : [...old, value];
        }
        const response = await current.handle({
          method: req.method ?? "GET",
          path: localPath,
          headers,
          ...(body === undefined ? {} : { body }),
          invalidBody,
          signal: controller.signal,
          deadline,
        });
        if (!res.destroyed) {
          res.writeHead(response.status, {
            "content-type": "application/json; charset=utf-8",
            ...response.headers,
          });
          res.end(JSON.stringify(response.body));
        }
      } catch (error) {
        if (res.headersSent || res.writableEnded || res.destroyed) {
          if (!res.destroyed && !res.writableEnded) res.destroy();
          return true;
        }
        throw error;
      } finally {
        clearTimeout(timer);
        active.delete(controller);
      }
      return true;
    },
    update(next) {
      if (closing) throw new Error("CAP_HTTP_HOST_CLOSED");
      if (
        discoveryAssertion !== undefined &&
        !equalDiscovery(next.discoveryContext, discoveryAssertion)
      )
        throw new Error("CAP_DISCOVERY_CONTEXT_MISMATCH");
      if (options.fallthrough !== false && typeof next.matches !== "function")
        throw new Error("CAP_HTTP_HOST_CONFIG_INVALID");
      adapter = next;
    },
    close() {
      closing = true;
    },
    abortActive() {
      for (const controller of active) controller.abort();
    },
  };
}

/** Reference Node host; each request captures one immutable adapter generation. */
export async function startHttpHost(
  options: HttpHostOptions,
): Promise<HttpHost> {
  const handler = createHttpNodeHandler({ ...options, fallthrough: false });
  const server = createServer(async (req, res) => {
    try {
      const handled = await handler.handle(req, res);
      if (!handled) {
        res.writeHead(404, { "cache-control": "no-store" });
        res.end(JSON.stringify({ code: "CAP_INPUT_INVALID" }));
      }
    } catch {
      if (res.headersSent || res.writableEnded || res.destroyed) {
        if (!res.destroyed && !res.writableEnded) res.destroy();
        return;
      }
      res.writeHead(500, { "cache-control": "no-store" });
      res.end(JSON.stringify({ code: "CAP_INTERNAL" }));
    }
  });
  const timeout = options.requestTimeoutMs ?? 30000;
  server.requestTimeout = timeout;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 3000, options.host ?? "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("CAP_HTTP_HOST_CONFIG_INVALID");
  return {
    url: `http://${isIP(options.host ?? "127.0.0.1") === 6 ? `[${options.host}]` : (options.host ?? "127.0.0.1")}:${address.port}`,
    update: handler.update,
    async close() {
      handler.close();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeIdleConnections();
      });
    },
  };
}
/** Structural compiler plugin; no compiler dependency crosses the adapter boundary. */
export function createOpenApiArtifactProducer(
  options: Omit<HttpProjectionOptions, "document" | "irHash"> = {},
) {
  const snapshot = JSON.parse(jcs(options as JsonValue)) as typeof options;
  if (
    snapshot.profile !== undefined &&
    snapshot.profile !== "public" &&
    snapshot.profile !== "internal"
  )
    throw new Error("CAP_HTTP_PROFILE_INVALID");
  if (
    (snapshot.security === undefined) !==
    (snapshot.securitySchemes === undefined)
  )
    throw new Error("CAP_HTTP_SECURITY_CONFIG_INVALID");
  if (snapshot.securitySchemes)
    validateSecurityConfiguration(snapshot.securitySchemes, snapshot.security);
  const freeze = <T>(value: T): T => {
    if (value !== null && typeof value === "object") {
      for (const item of Object.values(value)) freeze(item);
      Object.freeze(value);
    }
    return value;
  };
  freeze(snapshot);
  return freeze({
    id: "capaxle.openapi",
    version: "0.1.0-alpha.3",
    staticInputs: freeze({
      ...(snapshot.discovery === undefined
        ? {}
        : { discoveryAssertion: snapshot.discovery }),
      profile: snapshot.profile ?? "public",
      securityMode:
        snapshot.security === undefined &&
        snapshot.securitySchemes === undefined
          ? "default"
          : "explicit",
      securitySchemes: snapshot.securitySchemes ?? {},
      security: snapshot.security ?? [],
    } as unknown as Readonly<Record<string, JsonValue>>),
    diagnosticCodes: [
      {
        code: "CAP_DISCOVERY_CONTEXT_MISMATCH" as const,
        severities: ["error" as const],
      },
      {
        code: "CAP_OPENAPI_GENERATION_FAILED" as const,
        severities: ["error" as const],
      },
    ],
    artifacts: [
      {
        id: "openapi",
        path: "openapi.json",
        mediaType: "application/json",
        target: "http",
        dependencies: ["document:capability-ir" as const],
        produce(context: {
          readonly buildContext: {
            readonly irHash: string;
            readonly discovery: DiscoveryContext;
          };
          readonly dependencyBytes: ReadonlyMap<string, Uint8Array>;
        }) {
          try {
            const discovery = resolvedDiscovery(
              context.buildContext.discovery,
              snapshot.discovery,
            );
            const bytes = context.dependencyBytes.get("document:capability-ir");
            if (!bytes) throw new Error();
            const document = JSON.parse(
              Buffer.from(bytes).toString("utf8"),
            ) as RuntimeDocument;
            return {
              ok: true as const,
              bytes: Buffer.from(
                generateOpenApi({
                  ...snapshot,
                  document,
                  irHash: context.buildContext.irHash,
                  discovery,
                }).content,
              ),
              diagnostics: [],
            };
          } catch (error) {
            const mismatch =
              error instanceof Error &&
              error.message === "CAP_DISCOVERY_CONTEXT_MISMATCH";
            return {
              ok: false as const,
              diagnostics: [
                {
                  code: mismatch
                    ? ("CAP_DISCOVERY_CONTEXT_MISMATCH" as const)
                    : ("CAP_OPENAPI_GENERATION_FAILED" as const),
                  severity: "error" as const,
                  message: mismatch
                    ? "OpenAPI discovery context does not match the compiler-resolved context."
                    : "OpenAPI generation failed.",
                  target: "http",
                },
              ],
            };
          }
        },
      },
    ],
  });
}
