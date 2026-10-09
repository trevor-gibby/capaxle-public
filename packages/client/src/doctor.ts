import { createHash, randomUUID } from "node:crypto";
import {
  ClientFailure,
  capabilityId,
  closed,
  fail,
  finiteJson,
  hash,
  integer,
  json,
  object,
  semver,
} from "./common.js";
import type { ClientResult, Data } from "./common.js";
import {
  configPath,
  loadConfig,
  localCollectionPath,
  readCredential,
  selectConnection,
} from "./config.js";
import type { Selection } from "./config.js";
import type { ClientOptions } from "./client.js";
import {
  CLI_TARGET,
  PROTOCOL,
  schema,
  statuses,
  validateCollection,
  validateDetail,
  validateResult,
  validateSchema,
} from "./wire.js";
import type { Collection } from "./wire.js";

export interface DoctorCheck {
  id: string;
  status: "pass" | "fail" | "skipped";
  location?: string;
  message: string;
  remediation?: string;
  code?: string;
  details?: Readonly<Record<string, string | number | boolean>>;
}
const ids = [
  "configuration",
  "credentials",
  "connectivity",
  "discovery",
  "protocol",
  "service",
  "ir",
  "contract",
  "cli-details",
  "cli-schemas",
  "mcp-discovery",
  "mcp-tools",
  "mcp-session",
] as const;
type CheckId = (typeof ids)[number];
class DiagnosticFailure extends ClientFailure {
  constructor(
    readonly check: CheckId,
    code: string,
    exit: number,
    readonly action: string,
    message: string,
  ) {
    super(code, "failed_precondition", exit, message);
  }
}
function diagnostic(
  check: CheckId,
  code: string,
  exit: number,
  action: string,
  message: string,
): never {
  throw new DiagnosticFailure(check, code, exit, action, message);
}
const modern = "2026-07-28";
const legacy = "2025-11-25";
const protocolMeta = {
  "io.modelcontextprotocol/protocolVersion": modern,
  "io.modelcontextprotocol/clientCapabilities": {},
};
const authAction =
  "Provision a valid environment/private-file credential, or run auth login separately in an interactive terminal.";
const replyAction =
  "Check the selected endpoint and deploy a compatible Capaxle service; inspect server logs locally.";

/** The selected MCP profile projects a closed canonical invocation envelope. */
function canonicalOutputSchema(value: unknown): boolean {
  const required = (value: unknown, keys: readonly string[]) =>
    Array.isArray(value) &&
    value.length === keys.length &&
    keys.every((key) => value.includes(key));
  const string = (value: unknown) =>
    closed(value, ["type"]) && value.type === "string";
  const discriminator = (value: unknown, expected: boolean) =>
    closed(value, ["const"]) && value.const === expected;
  const branch = (value: unknown, keys: readonly string[]) =>
    closed(value, ["type", "additionalProperties", "required", "properties"]) &&
    value.type === "object" &&
    value.additionalProperties === false &&
    required(value.required, keys) &&
    closed(value.properties, [...keys]);
  if (
    !closed(value, ["type", "oneOf", "$schema"], ["$defs"]) ||
    value.type !== "object" ||
    !Array.isArray(value.oneOf) ||
    value.oneOf.length !== 2
  )
    return false;
  const [success, failure] = value.oneOf;
  if (
    !branch(success, ["correlationId", "ok", "value"]) ||
    !object(success) ||
    !object(success.properties) ||
    !string(success.properties.correlationId) ||
    !discriminator(success.properties.ok, true) ||
    !branch(failure, ["error", "ok"]) ||
    !object(failure) ||
    !object(failure.properties) ||
    !discriminator(failure.properties.ok, false)
  )
    return false;
  const error = failure.properties.error;
  if (
    !closed(error, ["oneOf"]) ||
    !Array.isArray(error.oneOf) ||
    error.oneOf.length === 0
  )
    return false;
  const variants = error.oneOf;
  return variants.every((entry, index) => {
    const keys = ["code", "correlationId", "message", "retryable", "status"];
    if (
      !closed(entry, [
        "type",
        "additionalProperties",
        "required",
        "properties",
      ]) ||
      entry.type !== "object" ||
      entry.additionalProperties !== false ||
      !required(entry.required, keys) ||
      !closed(entry.properties, keys, ["details"]) ||
      !string(entry.properties.correlationId) ||
      !string(entry.properties.message)
    )
      return false;
    const properties = entry.properties;
    if (index === variants.length - 1)
      return (
        closed(properties.code, ["type", "pattern"]) &&
        properties.code.type === "string" &&
        properties.code.pattern === "^CAP_" &&
        closed(properties.retryable, ["type"]) &&
        properties.retryable.type === "boolean" &&
        closed(properties.status, ["enum"]) &&
        Array.isArray(properties.status.enum) &&
        required(properties.status.enum, statuses) &&
        closed(properties.details, [])
      );
    return (
      closed(properties.code, ["const"]) &&
      typeof properties.code.const === "string" &&
      closed(properties.retryable, ["const"]) &&
      typeof properties.retryable.const === "boolean" &&
      closed(properties.status, ["const"]) &&
      statuses.includes(String(properties.status.const))
    );
  });
}

/** Read-only transport diagnostics: no login, profile writes, cache writes or invocation. */
export async function doctor(
  flags: Readonly<Record<string, string>>,
  allowHttp: boolean,
  machine: boolean,
  options: ClientOptions,
): Promise<ClientResult> {
  const checks = new Map<CheckId, DoctorCheck>(
    ids.map((id) => [
      id,
      {
        id: `remote.${id}`,
        status: "skipped",
        message: "Not checked because a prerequisite did not pass.",
        remediation: "Resolve the preceding failure and rerun doctor.",
      },
    ]),
  );
  const exits = new Map<CheckId, number>();
  const set = (
    id: CheckId,
    status: DoctorCheck["status"],
    message: string,
    location?: string,
    extra: Partial<DoctorCheck> = {},
  ) => {
    if (status === "pass") checkpoint();
    checks.set(id, {
      id: `remote.${id}`,
      status,
      message,
      ...(location ? { location } : {}),
      ...extra,
    });
  };
  let current: CheckId = "configuration";
  let location: string | undefined;
  let selection: Selection | undefined;
  let credential: string | undefined;
  const controller = new AbortController();
  const signal = options.signal
    ? AbortSignal.any([controller.signal, options.signal])
    : controller.signal;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let deadlineAt = 0;
  let cleanupReserve = 0;
  const timeoutFailure = () =>
    new DiagnosticFailure(
      current,
      options.signal?.aborted ? "CAP_CANCELLED" : "CAP_CLI_DIAGNOSTIC_DEADLINE",
      options.signal?.aborted ? 130 : 6,
      "Restore service availability or increase --timeout-ms (maximum 10000), then rerun doctor.",
      options.signal?.aborted
        ? "Diagnostic cancelled; remaining checks were skipped."
        : "Diagnostic deadline expired; remaining checks were skipped.",
    );
  function checkpoint() {
    if (deadlineAt > 0 && Date.now() >= deadlineAt) controller.abort();
    if (signal.aborted) throw timeoutFailure();
  }
  function validate<T>(work: () => T): T {
    checkpoint();
    try {
      return work();
    } finally {
      checkpoint();
    }
  }
  function bounded<T>(
    work: Promise<T>,
    cancel?: () => void,
    boundSignal = signal,
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const abort = () => {
        cancel?.();
        reject(timeoutFailure());
      };
      if (boundSignal.aborted) {
        work.catch(() => {});
        abort();
        return;
      }
      boundSignal.addEventListener("abort", abort, { once: true });
      work
        .then(resolve, reject)
        .finally(() => boundSignal.removeEventListener("abort", abort))
        .catch(() => {});
    });
  }
  function transportFailure(error: unknown): never {
    if (signal.aborted) throw timeoutFailure();
    let node: unknown = error;
    let kind = "connectivity";
    for (let depth = 0; depth < 5 && object(node); depth++) {
      const code = typeof node.code === "string" ? node.code : "";
      if (["ENOTFOUND", "EAI_AGAIN", "EAI_FAIL"].includes(code)) kind = "dns";
      else if (
        /^(?:ERR_TLS|ERR_SSL|CERT_|DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_VERIFY|UNABLE_TO_GET_ISSUER)/u.test(
          code,
        )
      )
        kind = "tls";
      node = node.cause;
    }
    diagnostic(
      "connectivity",
      `CAP_CLI_${kind.toUpperCase()}_FAILED`,
      6,
      kind === "dns"
        ? "Check the configured hostname and DNS resolver."
        : kind === "tls"
          ? "Check the hostname, certificate chain and trusted certificate authority; retain TLS verification."
          : "Check the configured host, port, mount and service availability.",
      `${kind === "dns" ? "DNS resolution" : kind === "tls" ? "TLS verification" : "Connection"} failed.`,
    );
  }
  async function request(
    path: string,
    init: RequestInit,
    limit = 8388608,
    reserve = 0,
    onResponse?: (response: Response) => void,
  ): Promise<{ value?: unknown; response: Response }> {
    checkpoint();
    const requestSignal =
      reserve > 0
        ? AbortSignal.any([
            signal,
            AbortSignal.timeout(Math.max(1, deadlineAt - Date.now() - reserve)),
          ])
        : signal;
    const headers = new Headers(init.headers);
    if (credential !== undefined)
      headers.set("authorization", `Bearer ${credential}`);
    const work = (options.fetch ?? globalThis.fetch)(
      new URL(path, selection!.url),
      { ...init, headers, redirect: "manual", signal: requestSignal },
    );
    // An injected fetch may ignore abort; discard any late response without exposing it.
    work.then(
      (response) => {
        if (requestSignal.aborted) void response.body?.cancel().catch(() => {});
      },
      () => {},
    );
    let response: Response;
    try {
      response = await bounded(work, undefined, requestSignal);
    } catch (error) {
      if (error instanceof DiagnosticFailure) throw error;
      if (requestSignal.aborted) throw timeoutFailure();
      transportFailure(error);
    }
    if (checks.get("connectivity")?.status !== "fail")
      set(
        "connectivity",
        "pass",
        "The configured service responded.",
        selection!.url,
      );
    if (response.status >= 300 && response.status < 400) {
      void response.body?.cancel().catch(() => {});
      diagnostic(
        current,
        "CAP_CLI_REDIRECT_REFUSED",
        7,
        "Configure the final trusted endpoint explicitly; diagnostic requests do not follow redirects.",
        "Endpoint returned a redirect.",
      );
    }
    if ([401, 403].includes(response.status)) {
      void response.body?.cancel().catch(() => {});
      diagnostic(
        current,
        response.status === 401
          ? "CAP_UNAUTHENTICATED"
          : "CAP_PERMISSION_DENIED",
        3,
        authAction,
        "The service rejected diagnostic authentication or discovery permission.",
      );
    }
    if (response.status === 404 || response.status === 405) {
      void response.body?.cancel().catch(() => {});
      diagnostic(
        current,
        "CAP_CLI_ENDPOINT_UNAVAILABLE",
        7,
        "Enable the requested surface and verify its explicitly configured mounted path.",
        "The diagnostic endpoint is disabled, undisclosed or unavailable.",
      );
    }
    if (response.status >= 500) {
      void response.body?.cancel().catch(() => {});
      diagnostic(
        current,
        "CAP_CLI_SERVICE_UNAVAILABLE",
        6,
        "Restore the service and its required providers, then rerun doctor.",
        "The service could not complete discovery.",
      );
    }
    try {
      onResponse?.(response);
    } catch (error) {
      void response.body?.cancel().catch(() => {});
      throw error;
    }
    if (init.method === "DELETE") {
      void response.body?.cancel().catch(() => {});
      return { response };
    }
    if (response.status === 202) {
      const reader = response.body?.getReader();
      if (reader) {
        try {
          while (true) {
            const chunk = await bounded(
              reader.read(),
              () => {
                void reader.cancel().catch(() => {});
              },
              requestSignal,
            );
            if (chunk.done) break;
            if (chunk.value.length > 0)
              diagnostic(
                current,
                "CAP_MCP_LIFECYCLE_INVALID",
                7,
                replyAction,
                "MCP notifications must return an empty 202 response.",
              );
          }
        } finally {
          void reader.cancel().catch(() => {});
        }
      }
      return { response };
    }
    if (
      !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(
        response.headers.get("content-type") ?? "",
      ) ||
      (response.headers.has("content-encoding") &&
        response.headers.get("content-encoding") !== "identity")
    ) {
      void response.body?.cancel().catch(() => {});
      diagnostic(
        current,
        "CAP_CLI_RESPONSE_INVALID",
        7,
        replyAction,
        "Discovery did not return uncompressed UTF-8 JSON.",
      );
    }
    const length = response.headers.get("content-length");
    if (length !== null && (!/^\d+$/u.test(length) || Number(length) > limit)) {
      void response.body?.cancel().catch(() => {});
      diagnostic(
        current,
        "CAP_CLI_RESPONSE_INVALID",
        7,
        replyAction,
        "Discovery response exceeds the supported byte limit.",
      );
    }
    const reader = response.body?.getReader();
    if (!reader)
      diagnostic(
        current,
        "CAP_CLI_RESPONSE_INVALID",
        7,
        replyAction,
        "Discovery response body is missing.",
      );
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    try {
      while (true) {
        const chunk = await bounded(
          reader.read(),
          () => {
            void reader.cancel().catch(() => {});
          },
          requestSignal,
        );
        if (chunk.done) break;
        bytes += chunk.value.length;
        if (bytes > limit)
          diagnostic(
            current,
            "CAP_CLI_RESPONSE_INVALID",
            7,
            replyAction,
            "Discovery response exceeds the supported byte limit.",
          );
        chunks.push(chunk.value);
      }
      const value: unknown = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)),
      );
      if (!finiteJson(value)) throw new Error("json");
      return { value, response };
    } catch (error) {
      void reader.cancel().catch(() => {});
      if (error instanceof ClientFailure) throw error;
      if (requestSignal.aborted) throw timeoutFailure();
      diagnostic(
        current,
        "CAP_CLI_RESPONSE_INVALID",
        7,
        replyAction,
        "Discovery response is malformed or incomplete.",
      );
    }
  }
  async function cli(path: string, limit?: number) {
    const found = await request(
      path,
      { method: "GET", headers: { "Capaxle-CLI-Protocol": PROTOCOL } },
      limit,
    );
    if (found.response.headers.get("capaxle-cli-protocol") !== PROTOCOL)
      diagnostic(
        "protocol",
        "CAP_CLI_PROTOCOL_UNSUPPORTED",
        4,
        "Deploy remote CLI protocol 0.1 or select a compatible client.",
        "Remote CLI protocol header is missing or unsupported.",
      );
    if (found.response.status !== 200) {
      const result = validateResult(found.value);
      if (result.ok) fail();
      const code = result.error.code;
      if (code === "CAP_CLI_PROTOCOL_UNSUPPORTED")
        diagnostic(
          "protocol",
          code,
          4,
          replyAction,
          "Remote CLI protocol is unsupported.",
        );
      if (
        [
          "CAP_CLI_SERVICE_MISMATCH",
          "CAP_CLI_IR_MISMATCH",
          "CAP_CLI_CONTRACT_MISMATCH",
        ].includes(code)
      )
        throw new ClientFailure(
          code,
          "failed_precondition",
          4,
          "Remote identity is incompatible.",
        );
      diagnostic(
        current,
        "CAP_CLI_RESPONSE_INVALID",
        7,
        replyAction,
        "Remote discovery returned an unsuccessful response.",
      );
    }
    if (
      credential !== undefined &&
      found.response.headers.get("cache-control") !== "private, no-store"
    )
      diagnostic(
        current,
        "CAP_CLI_RESPONSE_INVALID",
        7,
        replyAction,
        "Credential-bearing discovery must disable shared caches.",
      );
    return found.value;
  }
  function collection(value: unknown): Collection {
    if (object(value)) {
      if (value.protocolVersion !== PROTOCOL || value.cliTarget !== CLI_TARGET)
        diagnostic(
          "protocol",
          "CAP_CLI_PROTOCOL_UNSUPPORTED",
          4,
          "Deploy CLI protocol 0.1 and the supported OpenCLI target.",
          "Remote CLI protocol or target is unsupported.",
        );
      if (value.irVersion !== "0.1")
        diagnostic(
          "ir",
          "CAP_CLI_IR_MISMATCH",
          4,
          "Deploy supported Capability IR 0.1 and refresh discovery.",
          "Capability IR version is unsupported.",
        );
      if (
        closed(value.service, ["id", "name", "version"]) &&
        typeof value.service.id === "string" &&
        object(value.endpoints) &&
        object(value.payloadLimits) &&
        hash(value.contractHash)
      ) {
        const mount = new URL(selection!.url).pathname;
        const expected =
          "sha256:" +
          createHash("sha256")
            .update(
              json({
                protocolVersion: PROTOCOL,
                serviceId: value.service.id,
                irVersion: "0.1",
                cliTarget: CLI_TARGET,
                basePath: mount === "/" ? "/" : mount.slice(0, -1),
                resolvedCliEndpoints: value.endpoints,
                payloadLimits: value.payloadLimits,
              }),
            )
            .digest("hex");
        if (expected !== value.contractHash)
          diagnostic(
            "contract",
            "CAP_CLI_CONTRACT_MISMATCH",
            4,
            "Check the mounted endpoint configuration and deploy a self-consistent transport contract.",
            "Discovered transport contract hash does not match its disclosed configuration.",
          );
      }
    }
    const result = validate(() =>
      validateCollection(value, selection!.url, selection!.collectionPath),
    );
    if (
      selection!.serviceId !== undefined &&
      result.service.id !== selection!.serviceId
    )
      diagnostic(
        "service",
        "CAP_CLI_SERVICE_MISMATCH",
        4,
        "Select the intended service or correct the trusted profile serviceId.",
        "Discovered service differs from the selected profile.",
      );
    return result;
  }
  function privateCache(value: { cache: { scope: string } }) {
    if (credential !== undefined && value.cache.scope !== "private")
      diagnostic(
        current,
        "CAP_CLI_RESPONSE_INVALID",
        7,
        replyAction,
        "Credential-bearing discovery must use private cache metadata.",
      );
  }
  function recordFailure(error: unknown) {
    const id: CheckId =
      error instanceof DiagnosticFailure
        ? error.check
        : error instanceof ClientFailure && error.code === "CAP_CLI_IR_MISMATCH"
          ? "ir"
          : error instanceof ClientFailure &&
              error.code === "CAP_CLI_CONTRACT_MISMATCH"
            ? "contract"
            : error instanceof ClientFailure &&
                error.code === "CAP_CLI_SERVICE_MISMATCH"
              ? "service"
              : current;
    const failure =
      error instanceof ClientFailure
        ? error
        : new ClientFailure(
            "CAP_CLI_RESPONSE_INVALID",
            "internal",
            7,
            "Diagnostic validation failed.",
          );
    set(id, "fail", failure.message, location, {
      code: failure.code,
      remediation:
        error instanceof DiagnosticFailure
          ? error.action
          : id === "credentials"
            ? authAction
            : id === "configuration"
              ? "Correct the selected client configuration and trusted connection flags, then rerun doctor."
              : replyAction,
    });
    exits.set(id, failure.exitCode);
  }
  async function mcp(
    path: string,
    revision: string,
    expected: Collection | undefined,
  ) {
    let rpcId = 0;
    let session: string | undefined;
    let discoveredServerInfo: unknown;
    let listIrHash = expected?.irHash;
    const headers = () => ({
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "MCP-Protocol-Version": revision,
      ...(session ? { "MCP-Session-Id": session } : {}),
    });
    async function rpc(
      method: string,
      params: Data = {},
      notification = false,
    ) {
      const id = ++rpcId;
      const body = {
        jsonrpc: "2.0",
        ...(notification ? {} : { id }),
        method,
        params:
          revision === modern ? { ...params, _meta: protocolMeta } : params,
      };
      const found = await request(
        path,
        {
          method: "POST",
          headers: {
            ...headers(),
            ...(revision === modern ? { "Mcp-Method": method } : {}),
          },
          body: json(body),
        },
        8388608,
        revision === legacy ? cleanupReserve : 0,
        (response) => {
          if (method !== "initialize" || response.status !== 200) return;
          const raw = response.headers.get("mcp-session-id");
          if (raw !== null) {
            if (
              !/^[A-Za-z0-9_-]{43}$/u.test(raw) ||
              Buffer.from(raw, "base64url").length !== 32 ||
              Buffer.from(raw, "base64url").toString("base64url") !== raw
            )
              diagnostic(
                current,
                "CAP_MCP_LIFECYCLE_INVALID",
                7,
                replyAction,
                "Legacy MCP session locator is malformed.",
              );
            session = raw;
          }
        },
      );
      if (notification) {
        if (found.response.status !== 202 || found.value !== undefined)
          diagnostic(
            current,
            "CAP_MCP_LIFECYCLE_INVALID",
            7,
            replyAction,
            "MCP initialized notification was not accepted.",
          );
        return {};
      }
      const value = found.value;
      if (object(value) && object(value.error) && value.error.code === -32022)
        diagnostic(
          current,
          "CAP_MCP_PROTOCOL_UNSUPPORTED",
          4,
          "Select --mcp-protocol 2026-07-28 or 2025-11-25 matching the deployed MCP endpoint.",
          "Selected MCP revision is unsupported.",
        );
      if (
        found.response.status !== 200 ||
        !closed(value, ["jsonrpc", "id", "result"]) ||
        value.jsonrpc !== "2.0" ||
        value.id !== id ||
        !object(value.result)
      )
        diagnostic(
          current,
          "CAP_MCP_RESPONSE_INVALID",
          7,
          replyAction,
          "MCP JSON-RPC response or lifecycle envelope is malformed.",
        );
      if (revision === modern && found.response.headers.has("mcp-session-id"))
        diagnostic(
          current,
          "CAP_MCP_LIFECYCLE_INVALID",
          7,
          replyAction,
          "Modern MCP must not issue a session locator.",
        );
      return value.result;
    }
    function serverInfo(value: unknown): boolean {
      return (
        closed(value, ["name", "version"]) &&
        typeof value.name === "string" &&
        value.name.length > 0 &&
        Buffer.byteLength(value.name) <= 65536 &&
        (discoveredServerInfo === undefined ||
          json(value) === json(discoveredServerInfo)) &&
        semver(value.version) &&
        (expected === undefined ||
          (value.name === expected.service.name &&
            value.version === expected.service.version))
      );
    }
    function modernEnvelope(value: Data): boolean {
      return (
        value.resultType === "complete" &&
        value.ttlMs === 0 &&
        value.cacheScope === "private" &&
        object(value._meta) &&
        serverInfo(value._meta["io.modelcontextprotocol/serverInfo"])
      );
    }
    current = "mcp-discovery";
    location = new URL(path, selection!.url).href;
    try {
      if (revision === modern) {
        const found = await rpc("server/discover");
        if (
          !closed(
            found,
            [
              "resultType",
              "supportedVersions",
              "capabilities",
              "ttlMs",
              "cacheScope",
              "_meta",
            ],
            ["instructions"],
          ) ||
          (found.instructions !== undefined &&
            (typeof found.instructions !== "string" ||
              Buffer.byteLength(found.instructions) > 65536)) ||
          !modernEnvelope(found) ||
          !Array.isArray(found.supportedVersions) ||
          json(found.supportedVersions) !== json([modern, legacy]) ||
          !closed(found.capabilities, ["tools"]) ||
          !closed(found.capabilities.tools, [])
        )
          diagnostic(
            current,
            "CAP_MCP_DISCOVERY_INVALID",
            7,
            replyAction,
            "Modern MCP discovery metadata is incompatible.",
          );
        discoveredServerInfo = (found._meta as Data)[
          "io.modelcontextprotocol/serverInfo"
        ];
      } else {
        const found = await rpc("initialize", {
          protocolVersion: legacy,
          capabilities: {},
          clientInfo: {
            name: "capaxle-client-doctor",
            version: "0.1.0-alpha.3",
          },
        });
        if (found.protocolVersion !== legacy)
          diagnostic(
            current,
            "CAP_MCP_PROTOCOL_UNSUPPORTED",
            4,
            replyAction,
            "Legacy MCP negotiated an unsupported revision.",
          );
        if (
          !session ||
          !closed(
            found,
            ["protocolVersion", "capabilities", "serverInfo"],
            ["instructions"],
          ) ||
          (found.instructions !== undefined &&
            (typeof found.instructions !== "string" ||
              Buffer.byteLength(found.instructions) > 65536)) ||
          !closed(found.capabilities, ["tools"]) ||
          !closed(found.capabilities.tools, []) ||
          !serverInfo(found.serverInfo)
        )
          diagnostic(
            current,
            "CAP_MCP_LIFECYCLE_INVALID",
            7,
            replyAction,
            "Legacy MCP initialization or server identity is incompatible.",
          );
        discoveredServerInfo = found.serverInfo;
        await rpc("notifications/initialized", {}, true);
      }
      set(
        "mcp-discovery",
        "pass",
        "Selected MCP lifecycle and server metadata are compatible.",
        location,
        { details: { protocolVersion: revision } },
      );
      current = "mcp-tools";
      const list = await rpc("tools/list");
      if (
        !closed(
          list,
          revision === modern
            ? ["tools", "resultType", "ttlMs", "cacheScope", "_meta"]
            : ["tools"],
        ) ||
        !Array.isArray(list.tools) ||
        (revision === modern && !modernEnvelope(list))
      )
        diagnostic(
          current,
          "CAP_MCP_SCHEMA_INVALID",
          7,
          replyAction,
          "MCP tools/list metadata is incompatible.",
        );
      const names = new Set<string>();
      for (const tool of list.tools) {
        checkpoint();
        if (
          !closed(tool, [
            "name",
            "description",
            "inputSchema",
            "outputSchema",
            "annotations",
            "_meta",
          ]) ||
          typeof tool.name !== "string" ||
          !/^[A-Za-z0-9_.-]{1,128}$/u.test(tool.name) ||
          names.has(tool.name) ||
          typeof tool.description !== "string" ||
          !object(tool.annotations) ||
          !Object.values(tool.annotations).every(
            (v) => typeof v === "boolean",
          ) ||
          !object(tool.inputSchema) ||
          tool.inputSchema.type !== "object" ||
          !validate(() => schema(tool.inputSchema)) ||
          !object(tool.outputSchema) ||
          tool.outputSchema.type !== "object" ||
          !validate(() => schema(tool.outputSchema)) ||
          !validate(() => canonicalOutputSchema(tool.outputSchema)) ||
          !closed(tool._meta, ["com.capaxle/tool"])
        )
          diagnostic(
            current,
            "CAP_MCP_SCHEMA_INVALID",
            7,
            replyAction,
            "MCP tool metadata or self-contained object schemas are incompatible.",
          );
        names.add(tool.name);
        const meta = tool._meta["com.capaxle/tool"];
        if (
          !closed(meta, [
            "profileVersion",
            "id",
            "version",
            "irHash",
            "confirmation",
            "idempotency",
            "invocationMetadataKey",
          ]) ||
          meta.profileVersion !== "0.3" ||
          !capabilityId(meta.id) ||
          !semver(meta.version) ||
          !hash(meta.irHash) ||
          !["none", "required"].includes(String(meta.confirmation)) ||
          !["intrinsic", "key", "none"].includes(String(meta.idempotency)) ||
          meta.invocationMetadataKey !== "com.capaxle/invocation"
        )
          diagnostic(
            current,
            "CAP_MCP_SCHEMA_INVALID",
            7,
            replyAction,
            "MCP Capaxle metadata profile is incompatible.",
          );
        if (listIrHash !== undefined && meta.irHash !== listIrHash)
          diagnostic(
            current,
            "CAP_CLI_IR_MISMATCH",
            4,
            "Deploy CLI and MCP from the same verified generation, then rerun doctor.",
            "MCP Capability IR identities disagree with the disclosed generation.",
          );
        listIrHash = meta.irHash;
      }
      set(
        "mcp-tools",
        "pass",
        "Disclosed MCP tool schemas and metadata are compatible.",
        location,
        { details: { checkedTools: list.tools.length } },
      );
      if (revision === modern)
        set(
          "mcp-session",
          "pass",
          "Modern MCP is request-scoped and requires no session cleanup.",
          location,
        );
    } catch (error) {
      recordFailure(error);
    } finally {
      if (session) {
        current = "mcp-session";
        try {
          const found = await request(path, {
            method: "DELETE",
            headers: headers(),
          });
          if (found.response.status !== 200 && found.response.status !== 204)
            diagnostic(
              current,
              "CAP_MCP_LIFECYCLE_INVALID",
              7,
              "Inspect MCP session expiry/cleanup and rerun with a healthy endpoint.",
              "Legacy MCP session cleanup was rejected.",
            );
          set(
            "mcp-session",
            "pass",
            "Legacy MCP diagnostic session was terminated.",
            location,
          );
        } catch (error) {
          recordFailure(error);
        }
      }
    }
  }
  try {
    const timeout =
      flags["--timeout-ms"] === undefined
        ? 10000
        : /^\d+$/u.test(flags["--timeout-ms"])
          ? Number(flags["--timeout-ms"])
          : NaN;
    if (
      !integer(timeout, 1, 10000) ||
      (flags["--mcp-path"] !== undefined &&
        !localCollectionPath(flags["--mcp-path"])) ||
      (flags["--mcp-protocol"] !== undefined &&
        ![modern, legacy].includes(flags["--mcp-protocol"])) ||
      (flags["--mcp-protocol"] !== undefined &&
        flags["--mcp-path"] === undefined)
    )
      fail();
    deadlineAt = Date.now() + timeout;
    cleanupReserve = Math.min(500, Math.floor(timeout / 5));
    timer = setTimeout(() => controller.abort(), timeout);
    const env = options.env ?? process.env;
    const path = configPath(env, flags["--config"]);
    location = path;
    const config = await bounded(loadConfig(path));
    selection = selectConnection(config, env, flags, allowHttp);
    location = selection.url;
    set(
      "configuration",
      "pass",
      "Trusted connection configuration is valid.",
      location,
    );
    current = "credentials";
    credential = await bounded(
      readCredential(
        selection.credentialRef,
        path,
        env,
        selection.expiresAt,
        (options.now ?? Date.now)(),
      ),
    );
    if (
      credential === undefined &&
      (selection.credentialRef !== undefined ||
        selection.authHook !== undefined)
    )
      diagnostic(
        current,
        "CAP_UNAUTHENTICATED",
        3,
        authAction,
        "No provisioned credential is available; doctor does not run login hooks.",
      );
    set(
      "credentials",
      "pass",
      credential === undefined
        ? "No credential reference is configured; only anonymous discovery is tested."
        : "A provisioned credential is available; server authentication remains to be checked.",
      location,
    );
    let discovered: Collection | undefined;
    try {
      current = "discovery";
      location = new URL(selection.collectionPath, selection.url).href;
      const collectionValue = await cli(selection.collectionPath);
      discovered = validate(() => collection(collectionValue));
      privateCache(discovered);
      if (
        Buffer.byteLength(json(discovered)) >
        discovered.payloadLimits.responseBytes
      )
        fail();
      set(
        "discovery",
        "pass",
        "Remote CLI collection discovery is valid.",
        location,
        { details: { disclosedCapabilities: discovered.capabilities.length } },
      );
      set(
        "protocol",
        "pass",
        "CLI protocol 0.1 and target are compatible.",
        location,
      );
      set(
        "service",
        "pass",
        "Discovered service identity matches the trusted connection.",
        location,
      );
      // Identity checks stay skipped until every disclosed detail/schema has passed.
      let detailCount = 0;
      let schemaCount = 0;
      for (const summary of discovered.capabilities) {
        const query = `?version=${encodeURIComponent(summary.version)}`;
        current = "cli-details";
        location = new URL(summary.detailUrl, selection.url).href;
        const detailValue = await cli(
          summary.detailUrl + query,
          discovered.payloadLimits.responseBytes,
        );
        const detail = validate(() =>
          validateDetail(detailValue, discovered!, summary),
        );
        privateCache(detail);
        detailCount++;
        current = "cli-schemas";
        location = new URL(summary.schemaUrl, selection.url).href;
        const schemaValue = await cli(
          summary.schemaUrl + query,
          discovered.payloadLimits.responseBytes,
        );
        const schemas = validate(() =>
          validateSchema(schemaValue, discovered!, summary),
        );
        privateCache(schemas);
        if (
          json(schemas.schemas.input) !== json(detail.capability.input) ||
          json(schemas.schemas.output) !== json(detail.capability.output) ||
          json(schemas.schemas.errors) !== json(detail.capability.errors)
        )
          diagnostic(
            current,
            "CAP_CLI_SCHEMA_MISMATCH",
            7,
            replyAction,
            "CLI detail and schema projections disagree.",
          );
        schemaCount++;
      }
      location = new URL(selection.collectionPath, selection.url).href;
      set(
        "cli-details",
        "pass",
        "Every disclosed capability detail passed validation.",
        location,
        { details: { checkedCapabilities: detailCount } },
      );
      set(
        "cli-schemas",
        "pass",
        "Every disclosed capability schema passed validation and matches its detail.",
        location,
        { details: { checkedCapabilities: schemaCount } },
      );
      set(
        "ir",
        "pass",
        "Capability IR 0.1 identity agrees across all disclosed CLI resources.",
        location,
      );
      set(
        "contract",
        "pass",
        "Transport contract hash is reproducible and agrees across all disclosed CLI resources.",
        location,
      );
    } catch (error) {
      recordFailure(error);
    }
    if (flags["--mcp-path"] !== undefined)
      await mcp(
        new URL(selection.url).pathname + flags["--mcp-path"].slice(1),
        flags["--mcp-protocol"] ?? modern,
        discovered,
      );
    else
      for (const id of ["mcp-discovery", "mcp-tools", "mcp-session"] as const)
        set(
          id,
          "skipped",
          "MCP compatibility was not checked; no trusted MCP location was supplied.",
          selection.url,
          {
            remediation:
              "Provide --mcp-path with the operator-configured local endpoint path; select --mcp-protocol for a legacy lifecycle check.",
          },
        );
  } catch (error) {
    recordFailure(error);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    controller.abort();
  }
  const ordered = ids.map((id) => checks.get(id)!);
  const failed = ordered.find((check) => check.status === "fail");
  const exitCode = failed ? exits.get(failed.id.slice(7) as CheckId)! : 0;
  const value = {
    doctorVersion: "0.1",
    mode: "remote",
    complete: ordered.every((check) => check.status === "pass"),
    checks: ordered,
  };
  return {
    exitCode,
    stdout: machine
      ? json({ ok: !failed, value, correlationId: randomUUID() }) + "\n"
      : ordered
          .map(
            (check) =>
              `${check.status.toUpperCase()} ${check.id}${check.location ? ` (${check.location})` : ""}: ${check.message}${check.remediation ? `\n  Action: ${check.remediation}` : ""}`,
          )
          .join("\n") + "\n",
    stderr: "",
  };
}
