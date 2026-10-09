#!/usr/bin/env node
import { executeClient } from "./index.js";
const controller = new AbortController();
const interrupt = () => controller.abort();
process.on("SIGINT", interrupt);
async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  const cancel = () => process.stdin.destroy(new Error("cancelled"));
  controller.signal.addEventListener("abort", cancel, { once: true });
  if (controller.signal.aborted) cancel();
  try {
    for await (const chunk of process.stdin) {
      const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += data.length;
      if (bytes > 1048576) throw new Error("input");
      if (controller.signal.aborted) throw new Error("cancelled");
      chunks.push(data);
    }
  } finally {
    controller.signal.removeEventListener("abort", cancel);
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(
    Buffer.concat(chunks),
  );
}
const result = await executeClient(process.argv.slice(2), {
  signal: controller.signal,
  readStdin,
});
process.removeListener("SIGINT", interrupt);
process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
process.exitCode = result.exitCode;
