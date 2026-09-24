import type {
  CompilerDiagnostic,
  DiscoveryDiagnosticCode,
  RelatedLocation,
  SourceLocation,
} from "./types.js";

export type DiagnosticPhase =
  | "config-name"
  | "config-load"
  | "config-value"
  | "root"
  | "identity"
  | "module-load"
  | "module-export"
  | "override"
  | "duplicate"
  | "watch";

const phaseOrder: Readonly<Record<DiagnosticPhase, number>> = Object.freeze({
  "config-name": 0,
  "config-load": 1,
  "config-value": 2,
  root: 3,
  identity: 4,
  "module-load": 5,
  "module-export": 6,
  override: 7,
  duplicate: 8,
  watch: 9,
});

export interface PendingDiagnostic extends CompilerDiagnostic {
  readonly phase: DiagnosticPhase;
}

export const location = (file: string): SourceLocation =>
  Object.freeze({ file, line: 1, column: 1 });

export function diagnostic(
  phase: DiagnosticPhase,
  code: CompilerDiagnostic["code"],
  severity: CompilerDiagnostic["severity"],
  message: string,
  source: SourceLocation,
  options: {
    readonly pointer?: string;
    readonly related?: readonly RelatedLocation[];
  } = {},
): PendingDiagnostic {
  const related = options.related
    ? Object.freeze(
        [...options.related]
          .sort((left, right) =>
            compareText(left.source.file, right.source.file),
          )
          .map((item) =>
            Object.freeze({ message: item.message, source: item.source }),
          ),
      )
    : undefined;
  return Object.freeze({
    phase,
    code,
    severity,
    message,
    source,
    ...(options.pointer === undefined ? {} : { pointer: options.pointer }),
    ...(related === undefined ? {} : { related }),
  });
}

export function compareText(left: string, right: string): number {
  const leftPoints = Array.from(left, (value) => value.codePointAt(0)!);
  const rightPoints = Array.from(right, (value) => value.codePointAt(0)!);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index++) {
    const difference = leftPoints[index]! - rightPoints[index]!;
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

export function sortDiagnostics(
  diagnostics: readonly PendingDiagnostic[],
): readonly CompilerDiagnostic[] {
  return Object.freeze(
    [...diagnostics]
      .sort(
        (left, right) =>
          phaseOrder[left.phase] - phaseOrder[right.phase] ||
          compareText(left.source.file, right.source.file) ||
          left.source.line - right.source.line ||
          left.source.column - right.source.column ||
          compareText(left.pointer ?? "", right.pointer ?? "") ||
          compareText(left.code, right.code),
      )
      .map((item) => {
        const { phase, ...copy } = item;
        void phase;
        return Object.freeze(copy);
      }),
  );
}

export function watchFailure(source: SourceLocation): PendingDiagnostic {
  return diagnostic(
    "watch",
    "CAP_DISCOVERY_WATCH_FAILED" satisfies DiscoveryDiagnosticCode,
    "error",
    "Capability discovery could not watch this path; correct its accessibility and restart the watcher.",
    source,
  );
}
