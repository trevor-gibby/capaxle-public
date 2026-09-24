import { jcs, type JsonValue } from "@capaxle/ir";
import { compareText } from "./diagnostics.js";
import type {
  CompilationDiagnostic,
  CompilationDiagnosticSubphase,
  CompilationSourceLocation,
} from "./compilation-types.js";
import type { CompilerDiagnostic } from "./types.js";

const subphases: readonly CompilationDiagnosticSubphase[] = [
  "config-name",
  "config-load",
  "config-value",
  "discovery-root",
  "discovery-identity",
  "discovery-module-load",
  "discovery-module-export",
  "discovery-override",
  "discovery-duplicate",
  "discovery-watch",
  "authoring-descriptor",
  "schema-provider",
  "schema-portability",
  "schema-reference",
  "ir-structure",
  "ir-unsupported",
  "ir-identity",
  "ir-schema",
  "ir-policy",
  "ir-execution",
  "ir-projection",
  "ir-normalization",
  "projection-http",
  "projection-cli",
  "projection-mcp",
  "projection-docs",
  "projection-sdk",
  "projection-collision",
  "graph-input",
  "graph-dependency",
  "graph-cycle",
  "graph-execution",
  "emission-producer",
  "emission-stage",
  "emission-commit",
  "emission-cleanup",
];
const subphaseRank = new Map(subphases.map((value, index) => [value, index]));
const severityRank = { error: 0, warning: 1, info: 2 } as const;
const source = (value: CompilationSourceLocation) =>
  Object.freeze({ ...value });

function frozenJson(value: JsonValue): JsonValue {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value))
    return Object.freeze(value.map((entry) => frozenJson(entry)));
  return Object.freeze(
    Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, frozenJson(entry)]),
    ),
  );
}

export function compilationDiagnostic(
  item: CompilationDiagnostic,
): CompilationDiagnostic {
  const related = item.related
    ? Object.freeze(
        item.related.map((entry) =>
          Object.freeze({ ...entry, source: source(entry.source) }),
        ),
      )
    : undefined;
  return Object.freeze({
    ...item,
    source: source(item.source),
    ...(related ? { related } : {}),
    ...(item.details === undefined
      ? {}
      : { details: frozenJson(item.details) }),
  });
}

function compareSource(
  left: CompilationSourceLocation,
  right: CompilationSourceLocation,
): number {
  return (
    compareText(left.file, right.file) ||
    left.line - right.line ||
    left.column - right.column ||
    (left.endLine ?? left.line) - (right.endLine ?? right.line) ||
    (left.endColumn ?? left.column) - (right.endColumn ?? right.column)
  );
}

function normalizedRelated(item: CompilationDiagnostic): readonly unknown[] {
  return [...(item.related ?? [])]
    .sort(
      (a, b) =>
        compareSource(a.source, b.source) ||
        compareText(a.path ?? "", b.path ?? "") ||
        compareText(a.message, b.message),
    )
    .map((entry) => ({
      message: entry.message,
      ...(entry.path === undefined ? {} : { path: entry.path }),
      source: entry.source,
    }));
}

function canonicalPublic(item: CompilationDiagnostic): JsonValue {
  return JSON.parse(
    JSON.stringify({
      ...item,
      ...(item.related ? { related: normalizedRelated(item) } : {}),
    }),
  ) as JsonValue;
}

export function sortCompilationDiagnostics(
  input: readonly CompilationDiagnostic[],
): readonly CompilationDiagnostic[] {
  const sorted = input
    .map((item) =>
      compilationDiagnostic(
        item.related
          ? {
              ...item,
              related: normalizedRelated(item) as NonNullable<
                CompilationDiagnostic["related"]
              >,
            }
          : item,
      ),
    )
    .sort(
      (a, b) =>
        (subphaseRank.get(a.subphase) ?? 999) -
          (subphaseRank.get(b.subphase) ?? 999) ||
        compareSource(a.source, b.source) ||
        compareText(a.path ?? "", b.path ?? "") ||
        compareText(a.code, b.code) ||
        severityRank[a.severity] - severityRank[b.severity] ||
        compareText(
          jcs((a.details ?? null) as JsonValue),
          jcs((b.details ?? null) as JsonValue),
        ) ||
        compareText(a.message, b.message) ||
        compareText(a.remediation ?? "", b.remediation ?? "") ||
        compareText(
          jcs(normalizedRelated(a) as JsonValue),
          jcs(normalizedRelated(b) as JsonValue),
        ),
    );
  return Object.freeze(
    sorted.filter(
      (item, index) =>
        index === 0 ||
        jcs(canonicalPublic(item)) !== jcs(canonicalPublic(sorted[index - 1]!)),
    ),
  );
}

const discoverySubphase = (
  item: CompilerDiagnostic,
): CompilationDiagnosticSubphase => {
  if (
    item.code === "CAP_CONFIG_LEGACY_NAME" ||
    item.code === "CAP_CONFIG_NAME_CONFLICT"
  )
    return "config-name";
  if (item.code === "CAP_CONFIG_LOAD_FAILED") return "config-load";
  if (item.code.startsWith("CAP_CONFIG_")) return "config-value";
  if (item.code === "CAP_DISCOVERY_ROOT_INVALID") return "discovery-root";
  if (item.code === "CAP_DISCOVERY_ID_INVALID") return "discovery-identity";
  if (
    item.code === "CAP_DISCOVERY_MODULE_LOAD_FAILED" ||
    item.code.startsWith("CAP_AUTHORING_")
  )
    return "discovery-module-load";
  if (item.code === "CAP_DISCOVERY_MODULE_EXPORT_INVALID")
    return "discovery-module-export";
  if (item.code === "CAP_DISCOVERY_ID_OVERRIDE") return "discovery-override";
  if (item.code === "CAP_DISCOVERY_ID_DUPLICATE") return "discovery-duplicate";
  return "discovery-watch";
};

export function adaptDiscoveryDiagnostic(
  item: CompilerDiagnostic,
): CompilationDiagnostic {
  const subphase = discoverySubphase(item);
  const phase = subphase.startsWith("config-")
    ? ("configuration" as const)
    : ("discovery" as const);
  return compilationDiagnostic({
    code: item.code,
    severity: item.severity,
    phase,
    subphase,
    message: item.message,
    source: item.source,
    ...(item.pointer === undefined ? {} : { path: item.pointer }),
    ...(item.related === undefined ? {} : { related: item.related }),
  });
}
