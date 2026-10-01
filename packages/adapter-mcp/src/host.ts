import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { isNativeError, isProxy } from "node:util/types";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import {
  Server as ModernServer,
  createMcpHandler,
  isLegacyRequest,
  ProtocolError as ModernError,
  type ListToolsResult,
  type CallToolResult,
} from "@modelcontextprotocol/server";
import { Server as LegacyServer } from "@modelcontextprotocol/sdk/server/index.js";
import type { Transport as LegacyTransport } from "@modelcontextprotocol/sdk/shared/transport.js";

interface LegacyNodeTransport extends LegacyTransport {
  handleRequest(
    request: IncomingMessage,
    response: ServerResponse,
    parsedBody?: unknown,
  ): Promise<void>;
}
// SDK 1.30.1 exposes a declaration incompatible with exact optional types.
// Isolate that upstream declaration at this typed public-API boundary.
const { StreamableHTTPServerTransport } = createRequire(import.meta.url)(
  "@modelcontextprotocol/sdk/server/streamableHttp.js",
) as {
  StreamableHTTPServerTransport: new (options: {
    sessionIdGenerator: () => string;
    enableJsonResponse: boolean;
  }) => LegacyNodeTransport;
};
import {
  CallToolRequestSchema as LegacyCallSchema,
  ListToolsRequestSchema as LegacyListSchema,
  InitializeRequestSchema,
  InitializedNotificationSchema,
  CancelledNotificationSchema,
  McpError as LegacyError,
} from "@modelcontextprotocol/sdk/types.js";
import type { RequesterOwnershipToken } from "@capaxle/runtime";
import type {
  McpAdapter,
  McpRequestContext,
  McpTrustedDiscoveryContext,
} from "./mcp.js";
import {
  equalDiscoveryContext,
  MCP_LEGACY_PROTOCOL_VERSION,
  MCP_PROTOCOL_VERSION,
  MCP_TARGETS,
  ProjectionError,
  validateDiscoveryContext,
  type DiscoveryContext,
} from "./shared.js";
import {
  MCP_REQUEST_BYTES,
  MCP_RESPONSE_BYTES,
  payloadFailure,
  readBody,
  record,
  rpcError,
  safeRpc,
  sendJson,
  sendWebResponse,
  transportLimit,
  webRequest,
} from "./protocol.js";

export interface McpHostOptions {
  readonly adapter: McpAdapter;
  readonly discovery?: DiscoveryContext;
  readonly hostname?: string;
  readonly port?: number;
  readonly allowedOrigins?: readonly string[];
  readonly allowedHosts?: readonly string[];
  readonly clientCanSendInvocationMetadata?: boolean;
  readonly requestBodyLimitBytes?: number;
  readonly responseBodyLimitBytes?: number;
  readonly maxSessions?: number;
  readonly maxActiveRequestsPerSession?: number;
  readonly sessionIdleTimeoutMs?: number;
  readonly sessionAbsoluteTimeoutMs?: number;
  readonly credentials?: (
    request: IncomingMessage,
  ) => unknown | Promise<unknown>;
  readonly authenticateDiscovery?: (
    request: IncomingMessage,
    credentials: unknown,
  ) =>
    | McpTrustedDiscoveryContext
    | null
    | Promise<McpTrustedDiscoveryContext | null>;
}

export interface McpHost {
  readonly hostname: string;
  readonly port: number;
  close(): Promise<void>;
}

export interface McpNodeHandlerOptions extends Omit<
  McpHostOptions,
  "allowedHosts"
> {
  readonly allowedHosts: readonly string[] | (() => readonly string[]);
  readonly basePath?: string;
}

export interface McpNodeHandler {
  handle(request: IncomingMessage, response: ServerResponse): Promise<boolean>;
  close(): Promise<void>;
}

interface ActiveRequest {
  readonly controller: AbortController;
  readonly settled: Promise<void>;
}

interface Session {
  readonly id: string;
  readonly owner: RequesterOwnershipToken;
  readonly created: number;
  lastSeen: number;
  initialized: boolean;
  readonly active: Map<string | number, ActiveRequest>;
  readonly responses: Set<ServerResponse>;
  readonly server: LegacyServer;
  readonly transport: LegacyNodeTransport;
}

async function awaitCallback<T>(
  signal: AbortSignal,
  callback: () => T | Promise<T>,
): Promise<T> {
  if (signal.aborted) throw new Error("CAP_CANCELLED");
  let cancel: () => void = () => {};
  const interrupted = new Promise<never>((_resolve, reject) => {
    cancel = () => reject(new Error("CAP_CANCELLED"));
    signal.addEventListener("abort", cancel, { once: true });
  });
  try {
    const pending = Promise.resolve().then(() => {
      if (signal.aborted) throw new Error("CAP_CANCELLED");
      return callback();
    });
    const result = await Promise.race([pending, interrupted]);
    if (signal.aborted) throw new Error("CAP_CANCELLED");
    return result;
  } finally {
    signal.removeEventListener("abort", cancel);
  }
}

function safeRequestFailureCode(
  error: unknown,
):
  | "CAP_CANCELLED"
  | "CAP_MCP_RESPONSE_TOO_LARGE"
  | "CAP_MCP_PAYLOAD_TOO_LARGE"
  | undefined {
  try {
    if (isProxy(error) || !isNativeError(error)) return;
    const descriptor = Object.getOwnPropertyDescriptor(error, "message");
    if (!descriptor || !Object.hasOwn(descriptor, "value")) return;
    const value: unknown = descriptor.value;
    if (
      value === "CAP_CANCELLED" ||
      value === "CAP_MCP_RESPONSE_TOO_LARGE" ||
      value === "CAP_MCP_PAYLOAD_TOO_LARGE"
    )
      return value;
  } catch {
    return;
  }
}

function safeListFailureCode(error: unknown): string {
  const code = safeRequestFailureCode(error);
  return code === "CAP_CANCELLED" || code === "CAP_MCP_RESPONSE_TOO_LARGE"
    ? code
    : "CAP_DEPENDENCY_UNAVAILABLE";
}

function boundedPositive(
  value: number | undefined,
  defaultValue: number,
): number {
  const selected = value ?? defaultValue;
  if (
    !Number.isSafeInteger(selected) ||
    selected <= 0 ||
    selected > defaultValue
  )
    throw new Error("CAP_MCP_LIMIT_INVALID");
  return selected;
}

// The legacy SDK uses a JSON response per request. Calls are translated to a
// single SSE message only after the complete bounded response is available.
function legacyResponse(
  response: ServerResponse,
  call: boolean,
  limit: number,
): void {
  const originalWrite = response.write.bind(response);
  const originalEnd = response.end.bind(response);
  const originalHead = response.writeHead.bind(response);
  let status = 200;
  let headers: Record<string, string | number | readonly string[]> = {};
  const chunks: Buffer[] = [];
  let bytes = 0;
  let overflow = false;
  response.writeHead = ((
    code: number,
    messageOrHeaders?: unknown,
    otherHeaders?: unknown,
  ) => {
    status = code;
    const supplied =
      typeof messageOrHeaders === "string" ? otherHeaders : messageOrHeaders;
    if (supplied && !Array.isArray(supplied))
      headers = supplied as typeof headers;
    return response;
  }) as typeof response.writeHead;
  response.write = ((chunk: string | Uint8Array) => {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += data.length;
    if (bytes > limit) overflow = true;
    else chunks.push(data);
    return true;
  }) as typeof response.write;
  response.end = ((chunk?: string | Uint8Array) => {
    if (chunk !== undefined && typeof chunk !== "function")
      response.write(chunk);
    response.write = originalWrite;
    response.end = originalEnd;
    response.writeHead = originalHead;
    if (response.destroyed) return response;
    if (overflow) {
      payloadFailure(response, 500, "CAP_MCP_RESPONSE_TOO_LARGE");
      return response;
    }
    const body = Buffer.concat(chunks);
    const content =
      call && status === 200
        ? Buffer.from(`event: message\ndata: ${body.toString("utf8")}\n\n`)
        : body;
    if (content.length > limit) {
      payloadFailure(response, 500, "CAP_MCP_RESPONSE_TOO_LARGE");
      return response;
    }
    response.removeHeader("content-length");
    headers = Object.fromEntries(
      Object.entries(headers).filter(
        ([key]) => key.toLowerCase() !== "content-length",
      ),
    );
    originalHead(status, {
      ...headers,
      "cache-control": "no-store",
      ...(call && status === 200
        ? { "content-type": "text/event-stream; charset=utf-8" }
        : {}),
    });
    originalEnd(content);
    return response;
  }) as typeof response.end;
}

export function createMcpNodeHandler(
  options: McpNodeHandlerOptions,
): McpNodeHandler {
  if (!MCP_TARGETS.includes(options.adapter.target))
    throw new Error("CAP_MCP_TARGET_UNSUPPORTED");
  if (
    options.discovery !== undefined &&
    !equalDiscoveryContext(
      options.adapter.discoveryContext,
      validateDiscoveryContext(options.discovery),
    )
  )
    throw new ProjectionError("CAP_DISCOVERY_CONTEXT_MISMATCH");
  const requestLimit = transportLimit(
    options.requestBodyLimitBytes,
    1024,
    MCP_REQUEST_BYTES,
  );
  const responseLimit = transportLimit(
    options.responseBodyLimitBytes,
    8192,
    MCP_RESPONSE_BYTES,
  );
  options.adapter.validateResponseLimit(responseLimit);
  const maxSessions = boundedPositive(options.maxSessions, 1024);
  const maxActive = boundedPositive(options.maxActiveRequestsPerSession, 32);
  const idleTimeout = boundedPositive(options.sessionIdleTimeoutMs, 600_000);
  const absoluteTimeout = boundedPositive(
    options.sessionAbsoluteTimeoutMs,
    3_600_000,
  );
  const origins = new Set(options.allowedOrigins ?? []);
  const basePath = options.basePath ?? "/";
  if (
    !basePath.startsWith("/") ||
    (basePath !== "/" && (basePath.endsWith("/") || basePath.startsWith("//")))
  )
    throw new Error("CAP_MCP_HOST_CONFIG_INVALID");
  const endpoint =
    basePath === "/"
      ? options.adapter.endpoint
      : `${basePath}${options.adapter.endpoint}`;
  const contexts = new AsyncLocalStorage<McpRequestContext>();
  const sessions = new Map<string, Session>();
  const modernControllers = new Set<AbortController>();
  const pendingControllers = new Set<AbortController>();
  let initializingSessions = 0;
  let closing = false;

  const boundedResult = (result: unknown, id: unknown): unknown => {
    // Includes the JSON-RPC framing and SSE envelope. The SDK adds no large
    // data fields to these already-complete results.
    if (
      Buffer.byteLength(JSON.stringify({ jsonrpc: "2.0", id, result })) + 64 >
      responseLimit
    )
      throw new Error("CAP_MCP_RESPONSE_TOO_LARGE");
    return result;
  };
  const modern = createMcpHandler(
    () => {
      const server = new ModernServer(
        {
          name: options.adapter.serverInfo.name,
          version: options.adapter.serverInfo.version,
        },
        { capabilities: { tools: {} } },
      );
      server.setRequestHandler("tools/list", async (_request, extra) => {
        try {
          return boundedResult(
            await options.adapter.listToolsResult(contexts.getStore()),
            extra.mcpReq.id,
          ) as ListToolsResult;
        } catch (error) {
          throw new ModernError(-32603, "MCP response unavailable.", {
            capaxleCode: safeListFailureCode(error),
          });
        }
      });
      server.setRequestHandler("tools/call", async (request, extra) => {
        let result: Awaited<ReturnType<McpAdapter["callTool"]>>;
        try {
          result = await options.adapter.callTool(
            request.params,
            contexts.getStore(),
          );
        } catch {
          throw new ModernError(-32603, "MCP response unavailable.", {
            capaxleCode: "CAP_INTERNAL",
          });
        }
        if ("jsonrpcError" in result)
          throw new ModernError(
            result.jsonrpcError.code,
            result.jsonrpcError.message,
          );
        try {
          return boundedResult(result, extra.mcpReq.id) as CallToolResult;
        } catch {
          throw new ModernError(
            -32603,
            "MCP response exceeds the configured limit.",
            {
              capaxleCode: "CAP_MCP_RESPONSE_TOO_LARGE",
              executionState: "unknown",
              executionMayHaveOccurred: true,
            },
          );
        }
      });
      server.removeRequestHandler("ping");
      return server;
    },
    {
      legacy: "reject",
      responseMode: "sse",
      keepAliveMs: 0,
      maxRequestBodySize: requestLimit,
    },
  );

  const retire = async (session: Session) => {
    sessions.delete(session.id);
    const active = [...session.active.values()];
    for (const request of active) request.controller.abort();
    // The pinned SDK must deliver each kernel terminal result before close():
    // JSON response cleanup otherwise leaves handleRequest() unresolved.
    await Promise.allSettled(active.map((request) => request.settled));
    session.active.clear();
    for (const response of session.responses) response.destroy();
    session.responses.clear();
    await session.server.close();
  };
  const expired = (session: Session, now: number) =>
    now - session.created >= absoluteTimeout ||
    now - session.lastSeen >= idleTimeout;
  const cleanup = setInterval(
    () => {
      const now = Date.now();
      for (const session of sessions.values())
        if (expired(session, now)) void retire(session).catch(() => {});
    },
    Math.min(idleTimeout, absoluteTimeout, 30_000),
  );
  cleanup.unref();

  const createSession = async (
    owner: RequesterOwnershipToken,
  ): Promise<Session> => {
    const id = randomBytes(32).toString("base64url");
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => id,
      enableJsonResponse: true,
    });
    const server = new LegacyServer(
      {
        name: options.adapter.serverInfo.name,
        version: options.adapter.serverInfo.version,
      },
      { capabilities: { tools: {} } },
    );
    const session: Session = {
      id,
      owner,
      created: Date.now(),
      lastSeen: Date.now(),
      initialized: false,
      active: new Map(),
      responses: new Set(),
      server,
      transport,
    };
    server.oninitialized = () => {
      session.initialized = true;
    };
    server.setRequestHandler(LegacyListSchema, async (request, extra) => {
      try {
        return boundedResult(
          await options.adapter.listToolsResult(contexts.getStore()),
          extra.requestId,
        ) as Record<string, unknown>;
      } catch (error) {
        throw new LegacyError(-32603, "MCP response unavailable.", {
          capaxleCode: safeListFailureCode(error),
        });
      }
    });
    server.setRequestHandler(LegacyCallSchema, async (request, extra) => {
      let result: Awaited<ReturnType<McpAdapter["callTool"]>>;
      try {
        result = await options.adapter.callTool(
          request.params,
          contexts.getStore(),
        );
      } catch {
        throw new LegacyError(-32603, "MCP response unavailable.", {
          capaxleCode: "CAP_INTERNAL",
        });
      }
      if ("jsonrpcError" in result)
        throw new LegacyError(
          result.jsonrpcError.code,
          result.jsonrpcError.message,
        );
      try {
        return boundedResult(result, extra.requestId) as typeof result;
      } catch {
        throw new LegacyError(
          -32603,
          "MCP response exceeds the configured limit.",
          {
            capaxleCode: "CAP_MCP_RESPONSE_TOO_LARGE",
            executionState: "unknown",
            executionMayHaveOccurred: true,
          },
        );
      }
    });
    await server.connect(transport);
    if (closing) {
      await server.close();
      throw new Error("CAP_MCP_HOST_CLOSED");
    }
    sessions.set(id, session);
    return session;
  };

  const onRequest = async (
    request: IncomingMessage,
    response: ServerResponse,
  ) => {
    response.setHeader("cache-control", "no-store");
    if (closing) {
      sendJson(
        response,
        503,
        rpcError(null, -32603, "MCP endpoint unavailable."),
      );
      return;
    }
    const authority = request.headers.host;
    const allowedHosts = new Set(
      typeof options.allowedHosts === "function"
        ? options.allowedHosts()
        : options.allowedHosts,
    );
    if (typeof authority !== "string" || !allowedHosts.has(authority)) {
      sendJson(response, 403, rpcError(null, -32000, "Host is not allowed."));
      return;
    }
    const origin = request.headers.origin;
    if (
      origin !== undefined &&
      (Array.isArray(origin) || !origins.has(origin))
    ) {
      sendJson(response, 403, rpcError(null, -32000, "Origin is not allowed."));
      return;
    }
    if (request.method !== "POST" && request.method !== "DELETE") {
      response.writeHead(405, {
        allow: "POST, DELETE",
        "cache-control": "no-store",
      });
      response.end();
      return;
    }
    if (
      request.method === "DELETE" &&
      request.headers["mcp-protocol-version"] === MCP_PROTOCOL_VERSION
    ) {
      response.writeHead(405, { allow: "POST", "cache-control": "no-store" });
      response.end();
      return;
    }
    let parsed: unknown;
    if (request.method === "POST") {
      if (
        !/^application\/json(?:\s*;|$)/i.test(
          String(request.headers["content-type"] ?? ""),
        )
      ) {
        sendJson(
          response,
          415,
          rpcError(null, -32600, "Content-Type must be application/json."),
        );
        return;
      }
      const accept = String(request.headers.accept ?? "");
      if (
        !accept
          .split(",")
          .some((value) => value.trim().split(";")[0] === "application/json") ||
        !accept
          .split(",")
          .some((value) => value.trim().split(";")[0] === "text/event-stream")
      ) {
        sendJson(
          response,
          406,
          rpcError(
            null,
            -32600,
            "Accept must include application/json and text/event-stream.",
          ),
        );
        return;
      }
      try {
        parsed = await readBody(request, requestLimit);
      } catch (error) {
        const code = safeRequestFailureCode(error);
        if (code === "CAP_MCP_PAYLOAD_TOO_LARGE")
          payloadFailure(response, 413, code);
        else sendJson(response, 400, rpcError(null, -32700, "Parse error."));
        return;
      }
    }
    const controller = new AbortController();
    const web = webRequest(request, controller.signal);
    const legacy = await isLegacyRequest(web, parsed, {
      maxRequestBodySize: requestLimit,
    });
    const rpc = request.method === "POST" ? safeRpc(parsed) : undefined;
    if (request.method === "POST" && !rpc) {
      sendJson(response, 400, rpcError(null, -32600, "Invalid Request."));
      return;
    }
    const id = rpc?.id ?? null;
    if (
      rpc &&
      [
        "initialize",
        "server/discover",
        "tools/list",
        "tools/call",
        "ping",
      ].includes(String(rpc.method)) &&
      !Object.hasOwn(rpc, "id")
    ) {
      sendJson(response, 400, rpcError(null, -32600, "Invalid Request."));
      return;
    }
    if (rpc?.method === "initialize") {
      const metadata = record(record(rpc.params)?._meta);
      // The public SDK predicate special-cases initialize as legacy. Reject
      // discovery-era claims before that classification can mint a session.
      if (
        request.headers["mcp-protocol-version"] === MCP_PROTOCOL_VERSION ||
        Object.hasOwn(request.headers, "mcp-method") ||
        Object.hasOwn(request.headers, "mcp-name") ||
        (metadata &&
          (Object.hasOwn(metadata, "io.modelcontextprotocol/protocolVersion") ||
            Object.hasOwn(
              metadata,
              "io.modelcontextprotocol/clientCapabilities",
            )))
      ) {
        sendJson(
          response,
          400,
          rpcError(
            id,
            -32602,
            "Initialization carries incompatible protocol metadata.",
            {
              capaxleCode: "CAP_MCP_PROTOCOL_INVALID",
            },
          ),
        );
        return;
      }
    }
    pendingControllers.add(controller);
    let settleActiveRequest: (() => void) | undefined;
    const disconnect = () => {
      if (!response.writableEnded) controller.abort();
    };
    if (!legacy) {
      request.once("aborted", disconnect);
      response.once("close", disconnect);
      if (response.destroyed || request.aborted) controller.abort();
    }
    let credentials: unknown;
    try {
      credentials = options.credentials
        ? await awaitCallback(controller.signal, () =>
            options.credentials!(request),
          )
        : request.headers.authorization;
    } catch {
      pendingControllers.delete(controller);
      request.off("aborted", disconnect);
      response.off("close", disconnect);
      sendJson(response, 401, rpcError(id, -32001, "Authentication failed."));
      return;
    }
    const context: McpRequestContext = {
      ...(credentials === undefined ? {} : { credentials }),
      signal: controller.signal,
      protocolVersion: legacy
        ? MCP_LEGACY_PROTOCOL_VERSION
        : MCP_PROTOCOL_VERSION,
      clientCanSendInvocationMetadata:
        options.clientCanSendInvocationMetadata !== false,
    };
    try {
      if (closing || controller.signal.aborted) return;
      if (!legacy) {
        if (
          (rpc?.method === "tools/list" || rpc?.method === "server/discover") &&
          options.authenticateDiscovery
        ) {
          const restriction = await awaitCallback(controller.signal, () =>
            options.authenticateDiscovery!(request, credentials),
          );
          if (restriction !== null)
            Object.assign(context, { discovery: restriction });
        }
        modernControllers.add(controller);
        try {
          // Discovery/list are JSON; only capability calls select SSE.
          const result = await contexts.run(context, () =>
            modern.fetch(web, { parsedBody: parsed }),
          );
          if (rpc?.method === "server/discover" && result.status === 200) {
            await result.body?.cancel();
            const discovery = await options.adapter.discover(context);
            boundedResult(discovery, id);
            sendJson(response, 200, { jsonrpc: "2.0", id, result: discovery });
            return;
          }
          if (
            rpc?.method !== "tools/call" &&
            result.headers.get("content-type")?.startsWith("text/event-stream")
          ) {
            const text = await result.text();
            const data = text
              .split("\n")
              .filter((line) => line.startsWith("data: "))
              .map((line) => line.slice(6))
              .at(-1);
            if (data === undefined)
              sendJson(response, 500, rpcError(id, -32603, "Internal error."));
            else if (Buffer.byteLength(data) > responseLimit)
              payloadFailure(response, 500, "CAP_MCP_RESPONSE_TOO_LARGE");
            else sendJson(response, result.status, JSON.parse(data));
          } else await sendWebResponse(response, result, responseLimit);
        } finally {
          request.off("aborted", disconnect);
          response.off("close", disconnect);
          modernControllers.delete(controller);
        }
        return;
      }
      const disclosure = await options.adapter.discloseRequester(context);
      const sessionHeader = request.headers["mcp-session-id"];
      if (rpc?.method === "initialize") {
        if (
          sessionHeader !== undefined ||
          !InitializeRequestSchema.safeParse(parsed).success
        ) {
          sendJson(
            response,
            400,
            rpcError(id, -32602, "Invalid initialization."),
          );
          return;
        }
        const now = Date.now();
        for (const session of sessions.values())
          if (expired(session, now)) await retire(session);
        if (sessions.size + initializingSessions >= maxSessions) {
          sendJson(
            response,
            503,
            rpcError(id, -32603, "MCP session capacity unavailable."),
          );
          return;
        }
        initializingSessions += 1;
        let session: Session;
        try {
          session = await createSession(disclosure.requester);
        } finally {
          initializingSessions -= 1;
        }
        legacyResponse(response, false, responseLimit);
        const initial = {
          ...rpc,
          params: {
            ...record(rpc.params),
            protocolVersion: MCP_LEGACY_PROTOCOL_VERSION,
          },
        };
        await contexts.run(context, () =>
          session.transport.handleRequest(request, response, initial),
        );
        if (response.statusCode >= 400) await retire(session);
        return;
      }
      if (
        typeof sessionHeader !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(sessionHeader)
      ) {
        sendJson(
          response,
          404,
          rpcError(null, -32001, "MCP session unavailable."),
        );
        return;
      }
      const session = sessions.get(sessionHeader);
      if (!session || expired(session, Date.now())) {
        if (session) await retire(session);
        sendJson(
          response,
          404,
          rpcError(null, -32001, "MCP session unavailable."),
        );
        return;
      }
      if (!options.adapter.sameRequester(session.owner, disclosure.requester)) {
        sendJson(
          response,
          404,
          rpcError(null, -32001, "MCP session unavailable."),
        );
        return;
      }
      if (
        request.headers["mcp-protocol-version"] !== MCP_LEGACY_PROTOCOL_VERSION
      ) {
        sendJson(
          response,
          400,
          rpcError(id, -32600, "Unsupported MCP protocol version.", {
            capaxleCode: "CAP_MCP_PROTOCOL_UNSUPPORTED",
          }),
        );
        return;
      }
      session.lastSeen = Date.now();
      if (request.method === "DELETE") {
        await retire(session);
        response.writeHead(200, { "cache-control": "no-store" });
        response.end();
        return;
      }
      if (rpc?.method === "notifications/cancelled") {
        if (
          Object.hasOwn(rpc, "id") ||
          !CancelledNotificationSchema.safeParse(parsed).success
        ) {
          sendJson(
            response,
            400,
            rpcError(null, -32602, "Invalid cancellation notification."),
          );
          return;
        }
        if (!session.initialized) {
          sendJson(
            response,
            400,
            rpcError(null, -32600, "MCP session is not initialized."),
          );
          return;
        }
        const target = record(rpc.params)?.requestId;
        if (typeof target === "string" || typeof target === "number")
          session.active.get(target)?.controller.abort();
        response.writeHead(202, { "cache-control": "no-store" });
        response.end();
        return;
      }
      if (rpc?.method === "notifications/initialized") {
        if (
          Object.hasOwn(rpc, "id") ||
          !InitializedNotificationSchema.safeParse(parsed).success
        ) {
          sendJson(
            response,
            400,
            rpcError(null, -32602, "Invalid initialized notification."),
          );
          return;
        }
        await contexts.run(context, () =>
          session.transport.handleRequest(request, response, parsed),
        );
        return;
      }
      if (!Object.hasOwn(rpc ?? {}, "id")) {
        response.writeHead(202, { "cache-control": "no-store" });
        response.end();
        return;
      }
      if (!session.initialized && rpc?.method !== "ping") {
        sendJson(
          response,
          400,
          rpcError(id, -32600, "MCP session is not initialized."),
        );
        return;
      }
      if (
        rpc?.method !== "tools/call" &&
        rpc?.method !== "tools/list" &&
        rpc?.method !== "ping"
      ) {
        sendJson(response, 404, rpcError(id, -32601, "Method not found."));
        return;
      }
      const requestId = rpc.id as string | number;
      if (session.active.has(requestId)) {
        sendJson(
          response,
          409,
          rpcError(id, -32600, "Request ID is already active."),
        );
        return;
      }
      if (session.active.size >= maxActive) {
        sendJson(
          response,
          429,
          rpcError(id, -32603, "MCP request capacity unavailable."),
        );
        return;
      }
      const settled = new Promise<void>((resolve) => {
        settleActiveRequest = resolve;
      });
      session.active.set(requestId, { controller, settled });
      session.responses.add(response);
      try {
        if (rpc.method === "tools/list" && options.authenticateDiscovery) {
          const restriction = await awaitCallback(controller.signal, () =>
            options.authenticateDiscovery!(request, credentials),
          );
          if (restriction !== null)
            Object.assign(context, { discovery: restriction });
        }
        legacyResponse(response, rpc.method === "tools/call", responseLimit);
        await contexts.run(context, () =>
          session.transport.handleRequest(request, response, parsed),
        );
      } finally {
        session.active.delete(requestId);
        session.responses.delete(response);
      }
    } catch (error) {
      const code = safeRequestFailureCode(error);
      if (code === "CAP_MCP_RESPONSE_TOO_LARGE")
        payloadFailure(response, 500, code);
      else if (code === "CAP_CANCELLED")
        sendJson(
          response,
          400,
          rpcError(id, -32603, "MCP request cancelled.", {
            capaxleCode: "CAP_CANCELLED",
          }),
        );
      else if (!response.destroyed && !response.writableEnded)
        sendJson(
          response,
          401,
          rpcError(id, -32001, "Authentication or MCP request failed."),
        );
    } finally {
      request.off("aborted", disconnect);
      response.off("close", disconnect);
      pendingControllers.delete(controller);
      settleActiveRequest?.();
    }
  };
  let closePromise: Promise<void> | undefined;
  return {
    async handle(request, response) {
      if (request.url !== endpoint) return false;
      await onRequest(request, response);
      return true;
    },
    close: () =>
      (closePromise ??= (async () => {
        closing = true;
        clearInterval(cleanup);
        for (const controller of pendingControllers) controller.abort();
        for (const controller of modernControllers) controller.abort();
        await modern.close();
        await Promise.all([...sessions.values()].map(retire));
      })()),
  };
}

export async function startMcpHost(options: McpHostOptions): Promise<McpHost> {
  const hostname = options.hostname ?? "127.0.0.1";
  const listener = createServer(async (request, response) => {
    const handled = await handler.handle(request, response);
    if (!handled) sendJson(response, 404, rpcError(null, -32601, "Not found."));
  });
  const handler = createMcpNodeHandler({
    ...options,
    allowedHosts:
      options.allowedHosts ??
      (() => {
        const actual = listener.address();
        const port = actual && typeof actual !== "string" ? actual.port : 0;
        return [
          `${hostname}:${port}`,
          `localhost:${port}`,
          `127.0.0.1:${port}`,
          `[::1]:${port}`,
        ];
      }),
  });
  await new Promise<void>((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(options.port ?? 0, hostname, () => {
      listener.off("error", reject);
      resolve();
    });
  });
  const address = listener.address();
  if (!address || typeof address === "string")
    throw new Error("CAP_MCP_HOST_FAILED");
  let closePromise: Promise<void> | undefined;
  return {
    hostname,
    port: address.port,
    close: () =>
      (closePromise ??= (async () => {
        await handler.close();
        listener.closeAllConnections();
        await new Promise<void>((resolve, reject) =>
          listener.close((error) => (error ? reject(error) : resolve())),
        );
      })()),
  };
}
