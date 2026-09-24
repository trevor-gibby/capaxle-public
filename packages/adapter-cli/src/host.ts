import { readFile } from "node:fs/promises";
import type { CliAdapter } from "./adapter.js";

export interface CliProcessHostOptions {
  readonly argv?: readonly string[];
  readonly credentials?: unknown;
  readonly signal?: AbortSignal;
  readonly stdin?: NodeJS.ReadableStream;
  readonly stdout?: NodeJS.WritableStream;
  readonly stderr?: NodeJS.WritableStream;
}

async function readStream(
  stream: NodeJS.ReadableStream,
  signal: AbortSignal,
): Promise<string> {
  if (signal.aborted) throw new Error("cancelled");
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const cleanup = () => {
      stream.removeListener("data", data);
      stream.removeListener("end", end);
      stream.removeListener("error", error);
      signal.removeEventListener("abort", abort);
    };
    const data = (chunk: unknown) =>
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
    const end = () => {
      cleanup();
      resolve(Buffer.concat(chunks).toString("utf8"));
    };
    const error = (cause: unknown) => {
      cleanup();
      reject(cause);
    };
    const abort = () => {
      cleanup();
      stream.pause();
      reject(new Error("cancelled"));
    };
    stream.on("data", data);
    stream.once("end", end);
    stream.once("error", error);
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
}

/** Application-owned process entry; generated binaries call this after composing the runtime. */
export async function runCliProcess(
  adapter: CliAdapter,
  options: CliProcessHostOptions = {},
): Promise<number> {
  const controller = new AbortController();
  const external = options.signal;
  const cancel = () => controller.abort();
  external?.addEventListener("abort", cancel, { once: true });
  if (external?.aborted) cancel();
  process.once("SIGINT", cancel);
  try {
    const result = await adapter.run({
      argv: options.argv ?? process.argv.slice(2),
      ...(options.credentials !== undefined
        ? { credentials: options.credentials }
        : {}),
      signal: controller.signal,
      readFile: (path) =>
        readFile(path, { encoding: "utf8", signal: controller.signal }),
      readStdin: () =>
        readStream(options.stdin ?? process.stdin, controller.signal),
    });
    (options.stdout ?? process.stdout).write(result.stdout);
    (options.stderr ?? process.stderr).write(result.stderr);
    return result.exitCode;
  } finally {
    process.removeListener("SIGINT", cancel);
    external?.removeEventListener("abort", cancel);
  }
}
