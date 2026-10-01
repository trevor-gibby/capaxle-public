import type { IncomingMessage, ServerResponse } from "node:http";

export const MCP_REQUEST_BYTES = 1_048_576;
export const MCP_RESPONSE_BYTES = 8_388_608;

export function transportLimit(
  value: number | undefined,
  minimum: number,
  maximum: number,
): number {
  const selected = value ?? maximum;
  if (
    !Number.isSafeInteger(selected) ||
    selected < minimum ||
    selected > maximum
  )
    throw new Error("CAP_MCP_LIMIT_INVALID");
  return selected;
}

export function rpcError(
  id: unknown,
  code: number,
  message: string,
  data?: unknown,
) {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    error: { code, message, ...(data === undefined ? {} : { data }) },
  };
}

export function sendJson(
  response: ServerResponse,
  status: number,
  body: unknown,
): void {
  if (response.destroyed || response.writableEnded) return;
  if (response.headersSent) {
    response.destroy();
    return;
  }
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
  });
  response.end(JSON.stringify(body));
}

export function payloadFailure(
  response: ServerResponse,
  status: number,
  code: string,
): void {
  if (status === 413) response.setHeader("connection", "close");
  sendJson(
    response,
    status,
    rpcError(null, -32603, "MCP payload exceeds the configured limit.", {
      capaxleCode: code,
      ...(status === 500
        ? { executionState: "unknown", executionMayHaveOccurred: true }
        : {}),
    }),
  );
}

export async function readBody(
  request: IncomingMessage,
  limit: number,
): Promise<unknown> {
  const chunks: Uint8Array[] = [];
  let length = 0;
  for await (const chunk of request.iterator({ destroyOnReturn: false })) {
    const bytes =
      typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Uint8Array);
    length += bytes.byteLength;
    if (length > limit) throw new Error("CAP_MCP_PAYLOAD_TOO_LARGE");
    chunks.push(bytes);
  }
  return JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)),
  );
}

export function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

export function safeRpc(value: unknown): Record<string, unknown> | undefined {
  const rpc = record(value);
  if (!rpc || rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string") return;
  if (
    Object.hasOwn(rpc, "id") &&
    !(
      (typeof rpc.id === "string" && rpc.id.length <= 128) ||
      (typeof rpc.id === "number" && Number.isSafeInteger(rpc.id))
    )
  )
    return;
  return rpc;
}

export function webRequest(
  request: IncomingMessage,
  signal: AbortSignal,
): Request {
  const headers = new Headers();
  for (const [key, value] of Object.entries(request.headers)) {
    if (Array.isArray(value))
      for (const entry of value) headers.append(key, entry);
    else if (value !== undefined) headers.set(key, value);
  }
  // Authority is fixed transport scaffolding; never used as an external URL.
  return new Request(`http://127.0.0.1${request.url ?? "/"}`, {
    method: request.method ?? "POST",
    headers,
    signal,
  });
}

export async function sendWebResponse(
  response: ServerResponse,
  result: Response,
  limit: number,
): Promise<void> {
  const headers = Object.fromEntries(result.headers.entries());
  headers["cache-control"] = "no-store";
  const sse = result.headers
    .get("content-type")
    ?.startsWith("text/event-stream");
  if (!result.body) {
    response.writeHead(result.status, headers);
    response.end();
    return;
  }
  const reader = result.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  const cancel = () => {
    void reader.cancel().catch(() => {});
  };
  response.once("close", cancel);
  try {
    if (sse) {
      response.writeHead(result.status, headers);
      response.flushHeaders();
    }
    while (!response.destroyed) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.byteLength;
      if (length > limit) {
        await reader.cancel();
        if (response.headersSent) response.destroy();
        else payloadFailure(response, 500, "CAP_MCP_RESPONSE_TOO_LARGE");
        return;
      }
      if (sse) response.write(part.value);
      else chunks.push(part.value);
    }
    if (!response.destroyed) {
      if (!sse) response.writeHead(result.status, headers);
      response.end(sse ? undefined : Buffer.concat(chunks));
    }
  } finally {
    response.off("close", cancel);
    reader.releaseLock();
  }
}
