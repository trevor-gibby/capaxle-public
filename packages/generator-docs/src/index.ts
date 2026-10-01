import { generateDocumentationEntries } from "./projection.js";
import type { DocsSchemaOptions, DocsSchemaResult } from "./projection.js";

export {
  DOCS_SCHEMA_GENERATOR_VERSION,
  DOCS_SCHEMA_TARGET,
  DOCS_SCHEMA_DIAGNOSTIC_CODES,
} from "./projection.js";
export type {
  DocsSchemaOptions,
  DocsSchemaDiagnostic,
  DocsSchemaResult,
} from "./projection.js";

const encoder = new TextEncoder();

function tar(
  entries: readonly { readonly path: string; readonly bytes: Uint8Array }[],
): Uint8Array {
  const chunks: Uint8Array[] = [];
  const write = (
    header: Uint8Array,
    start: number,
    length: number,
    value: string,
  ) => {
    const bytes = encoder.encode(value);
    if (bytes.length > length) throw new Error("archive path too long");
    header.set(bytes, start);
  };
  const octal = (value: number, length: number) =>
    value.toString(8).padStart(length - 1, "0") + "\0";
  for (const entry of entries) {
    if (
      entry.path.startsWith("/") ||
      entry.path
        .split("/")
        .some((part) => !part || part === "." || part === "..")
    )
      throw new Error("unsafe archive path");
    const header = new Uint8Array(512);
    const pathBytes = encoder.encode(entry.path);
    let name = entry.path;
    let prefix = "";
    if (pathBytes.length > 100) {
      const parts = entry.path.split("/");
      name = parts.pop()!;
      prefix = parts.join("/");
      if (
        encoder.encode(name).length > 100 ||
        encoder.encode(prefix).length > 155
      )
        throw new Error("archive path too long");
    }
    write(header, 0, 100, name);
    if (prefix) write(header, 345, 155, prefix);
    write(header, 100, 8, octal(0o644, 8));
    write(header, 108, 8, octal(0, 8));
    write(header, 116, 8, octal(0, 8));
    write(header, 124, 12, octal(entry.bytes.length, 12));
    write(header, 136, 12, octal(0, 12));
    write(header, 148, 8, "        ");
    write(header, 156, 1, "0");
    write(header, 257, 6, "ustar\0");
    write(header, 263, 2, "00");
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    write(header, 148, 8, octal(checksum, 8));
    chunks.push(
      header,
      entry.bytes,
      new Uint8Array((512 - (entry.bytes.length % 512)) % 512),
    );
  }
  chunks.push(new Uint8Array(1024));
  const result = new Uint8Array(
    chunks.reduce((sum, chunk) => sum + chunk.length, 0),
  );
  let cursor = 0;
  for (const chunk of chunks) {
    result.set(chunk, cursor);
    cursor += chunk.length;
  }
  return result;
}

/** Projects normalized Capability IR into a deterministic USTAR archive. */
export function generateDocsSchemaArchive(
  source: unknown,
  options: DocsSchemaOptions,
): DocsSchemaResult {
  const result = generateDocumentationEntries(source, options);
  if (!result.ok) return result;
  try {
    return { ok: true, bytes: tar(result.entries), entries: result.entries };
  } catch {
    return {
      ok: false,
      diagnostics: [
        {
          code: "CAP_DOCS_SCHEMA_INVALID",
          severity: "error",
          message: "Archive generation failed.",
        },
      ],
    };
  }
}
