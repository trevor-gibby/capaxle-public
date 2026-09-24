import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { JsonValue } from "@capaxle/ir";
import type {
  McpAdapter,
  McpRequestContext,
  McpTrustedDiscoveryContext,
} from "./mcp.js";
import {
  equalDiscoveryContext,
  MCP_PROTOCOL_VERSION,
  MCP_TARGET,
  ProjectionError,
  validateDiscoveryContext,
  type DiscoveryContext,
} from "./shared.js";

export interface McpHostOptions {
  readonly adapter: McpAdapter;
  readonly discovery?: DiscoveryContext;
  readonly hostname?: string;
  readonly port?: number;
  readonly allowedOrigins?: readonly string[];
  readonly clientCanSendInvocationMetadata?: boolean;
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

const json = (
  response: ServerResponse,
  status: number,
  body: unknown,
): void => {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
  });
  response.end(JSON.stringify(body));
};

const rpcError = (id: unknown, code: number, message: string) => ({
  jsonrpc: "2.0",
  id: id ?? null,
  error: { code, message },
});

async function readBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Uint8Array[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
    length += bytes.byteLength;
    if (length > 1_048_576) throw new Error("too_large");
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function requestRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return null;
  const record = value as Record<string, unknown>;
  if (
    record.jsonrpc !== "2.0" ||
    typeof record.method !== "string" ||
    (!Object.hasOwn(record, "id") && record.method === "tools/call")
  )
    return null;
  return record;
}

export async function startMcpHost(options: McpHostOptions): Promise<McpHost> {
  if (options.adapter.target !== MCP_TARGET)
    throw new Error("CAP_MCP_TARGET_UNSUPPORTED");
  if (
    options.discovery !== undefined &&
    !equalDiscoveryContext(
      options.adapter.discoveryContext,
      validateDiscoveryContext(options.discovery),
    )
  )
    throw new ProjectionError("CAP_DISCOVERY_CONTEXT_MISMATCH");
  const origins = new Set(options.allowedOrigins ?? []);
  const server = createServer(async (request, response) => {
    if (request.method !== "POST" || request.url !== options.adapter.endpoint) {
      response.writeHead(405, { allow: "POST", "cache-control": "no-store" });
      response.end();
      return;
    }
    const origin = request.headers.origin;
    if (origin !== undefined && !origins.has(origin)) {
      json(response, 403, rpcError(null, -32000, "Origin is not allowed."));
      return;
    }
    const protocol = request.headers["mcp-protocol-version"];
    if (
      protocol !== undefined &&
      (Array.isArray(protocol) || protocol !== MCP_PROTOCOL_VERSION)
    ) {
      json(
        response,
        400,
        rpcError(null, -32600, "Unsupported MCP protocol version."),
      );
      return;
    }
    let parsed: unknown;
    try {
      parsed = await readBody(request);
    } catch {
      json(response, 400, rpcError(null, -32700, "Parse error."));
      return;
    }
    const rpc = requestRecord(parsed);
    if (!rpc) {
      json(response, 400, rpcError(null, -32600, "Invalid Request."));
      return;
    }
    const id = rpc.id ?? null;
    let credentials: unknown;
    let discovery: McpTrustedDiscoveryContext | undefined;
    try {
      credentials = options.credentials
        ? await options.credentials(request)
        : request.headers.authorization;
      const disclosureRequest =
        rpc.method === "server/discover" || rpc.method === "tools/list";
      const trusted =
        disclosureRequest && options.authenticateDiscovery
          ? await options.authenticateDiscovery(request, credentials)
          : null;
      if (trusted !== null) discovery = trusted;
    } catch {
      json(response, 401, rpcError(id, -32001, "Authentication failed."));
      return;
    }
    const controller = new AbortController();
    const disconnect = () =>
      controller.abort(new Error("MCP request disconnected"));
    request.once("aborted", disconnect);
    response.once("close", disconnect);
    const context: McpRequestContext = {
      ...(credentials === undefined ? {} : { credentials }),
      ...(discovery === undefined ? {} : { discovery }),
      signal: controller.signal,
      clientCanSendInvocationMetadata:
        options.clientCanSendInvocationMetadata !== false,
    };
    try {
      if (rpc.method === "server/discover") {
        json(response, 200, {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: MCP_PROTOCOL_VERSION,
            target: MCP_TARGET,
            endpoint: options.adapter.endpoint,
            irHash: options.adapter.irHash,
            capabilities: ["server/discover", "tools/list", "tools/call"],
          },
        });
        return;
      }
      if (rpc.method === "tools/list") {
        const tools = await options.adapter.listTools(context);
        json(response, 200, { jsonrpc: "2.0", id, result: { tools } });
        return;
      }
      if (rpc.method !== "tools/call") {
        json(response, 404, rpcError(id, -32601, "Method not found."));
        return;
      }
      const result = await options.adapter.callTool(rpc.params, context);
      if ("jsonrpcError" in result) {
        json(
          response,
          400,
          rpcError(id, result.jsonrpcError.code, result.jsonrpcError.message),
        );
        return;
      }
      if (controller.signal.aborted || response.destroyed) return;
      response.writeHead(200, {
        "cache-control": "no-store",
        connection: "close",
        "content-type": "text/event-stream; charset=utf-8",
      });
      const event = {
        jsonrpc: "2.0",
        id,
        result: result as unknown as JsonValue,
      };
      response.end(`event: message\ndata: ${JSON.stringify(event)}\n\n`);
    } catch {
      if (!controller.signal.aborted && !response.headersSent)
        json(response, 500, rpcError(id, -32603, "Internal error."));
      else if (!response.destroyed) response.destroy();
    } finally {
      request.off("aborted", disconnect);
      response.off("close", disconnect);
    }
  });
  const hostname = options.hostname ?? "127.0.0.1";
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, hostname, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("CAP_MCP_HOST_FAILED");
  return {
    hostname,
    port: address.port,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}
