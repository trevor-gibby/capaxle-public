import { compareText } from "./diagnostics.js";
import { Buffer } from "node:buffer";
import { constants } from "node:fs";
import { lstat, open, readFile, readdir, statfs } from "node:fs/promises";
import { resolve } from "node:path";
import { types } from "node:util";
import ts from "typescript";
import type { JsonValue } from "@capaxle/ir";
import { canonicalConfig, validRoot } from "./config.js";
import {
  loadFreshModule,
  ModuleGraphLoadError,
  runModuleLoadTransaction,
  type LoaderGeneration,
} from "./module-loader.js";
import { compilationDiagnostic } from "./compilation-diagnostics.js";
import type {
  CompilationDiagnostic,
  CompilationSourceLocation,
  DiscoveryContext,
} from "./compilation-types.js";

export const EXPOSURES = [
  "disabled",
  "private",
  "authenticated",
  "public",
] as const;
export type Exposure = (typeof EXPOSURES)[number];
export interface ProjectionOverrides {
  readonly http?:
    | false
    | {
        readonly method?: string;
        readonly path?: string;
        readonly bindings?: Readonly<Record<string, string>>;
      };
  readonly cli?:
    | false
    | {
        readonly command?: readonly string[];
        readonly bindings?: Readonly<Record<string, JsonValue>>;
      };
  readonly mcp?: false | { readonly toolName?: string };
  readonly docs?: false | { readonly group?: string };
  readonly sdk?: false | { readonly path?: readonly string[] };
}
export const httpHeaderToken = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const reservedHttpHeaders = new Set([
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
export function reservedHttpHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    reservedHttpHeaders.has(lower) ||
    lower.startsWith("proxy-") ||
    lower.startsWith("sec-") ||
    lower.startsWith("x-forwarded-") ||
    (lower.startsWith("x-cap-") && !lower.startsWith("x-cap-input-")) ||
    (lower.startsWith("x-cap-input-") &&
      (lower.slice(12).startsWith("x-cap-") ||
        reservedHttpHeader(lower.slice(12))))
  );
}
export interface ResolvedCompilerConfig {
  readonly service: Readonly<Record<string, JsonValue>>;
  readonly exposureDefaults: Readonly<
    Record<"http" | "cli" | "mcp" | "internal", Exposure>
  >;
  readonly httpPrefix: string;
  readonly httpHeaderAllowlist: readonly string[];
  readonly discovery: DiscoveryContext;
  readonly cliBinary?: string;
  readonly projections: Readonly<Record<string, ProjectionOverrides>>;
  readonly outputDirectory: string;
  readonly outputExplicit: boolean;
  readonly outputSource: CompilationSourceLocation;
  readonly source: CompilationSourceLocation;
  readonly sourceLocations: Readonly<Record<string, CompilationSourceLocation>>;
  readonly configFile: "capaxle.config.ts";
}

const defaultDiscoveryContext: DiscoveryContext = Object.freeze({
  http: Object.freeze({
    collection: "/.well-known/capabilities",
    detailTemplate: "/.well-known/capabilities/{id}",
    schemaTemplate: "/.well-known/capabilities/{id}/schema",
  }),
  mcp: Object.freeze({ endpoint: "/mcp" }),
});

function validDiscoveryPath(
  value: unknown,
  template: boolean,
): value is string {
  if (
    typeof value !== "string" ||
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
}

function discoveryPathsOverlap(left: string, right: string): boolean {
  const a = left.split("/");
  const b = right.split("/");
  return (
    a.length === b.length &&
    a.every(
      (segment, index) =>
        segment === b[index] || segment === "{id}" || b[index] === "{id}",
    )
  );
}

const at: CompilationSourceLocation = Object.freeze({
  file: canonicalConfig,
  line: 1,
  column: 1,
});
const projectAt: CompilationSourceLocation = Object.freeze({
  file: ".",
  line: 1,
  column: 1,
});
const allowedTop = new Set([
  "service",
  "discovery",
  "exposureDefaults",
  "adapters",
  "projections",
  "compiler",
]);
const semver =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const pointerToken = (value: string): string =>
  value.replaceAll("~", "~0").replaceAll("/", "~1");

function validIJsonString(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function record(value: unknown): Record<string, unknown> | null {
  try {
    if (
      typeof value !== "object" ||
      value === null ||
      Array.isArray(value) ||
      types.isProxy(value)
    )
      return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const output: Record<string, unknown> = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string" || !validIJsonString(key)) return null;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
        return null;
      output[key] = descriptor.value;
    }
    return output;
  } catch {
    return null;
  }
}
function strings(value: unknown): readonly string[] | null {
  const entries = arrayData(value);
  if (
    !entries ||
    !entries.every(
      (entry) => typeof entry === "string" && validIJsonString(entry),
    )
  )
    return null;
  return Object.freeze(entries as string[]);
}
function arrayData(value: unknown): readonly unknown[] | null {
  try {
    if (
      !Array.isArray(value) ||
      types.isProxy(value) ||
      Object.getPrototypeOf(value) !== Array.prototype ||
      Reflect.ownKeys(value).length !== value.length + 1
    )
      return null;
    const output: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable)
        return null;
      output.push(descriptor.value);
    }
    return output;
  } catch {
    return null;
  }
}
function data(
  value: unknown,
): { readonly ok: true; readonly value: JsonValue } | { readonly ok: false } {
  if (value === null || typeof value === "boolean") return { ok: true, value };
  if (typeof value === "string")
    return validIJsonString(value) ? { ok: true, value } : { ok: false };
  if (typeof value === "number")
    return Number.isFinite(value) &&
      (!Number.isInteger(value) || Number.isSafeInteger(value))
      ? { ok: true, value }
      : { ok: false };
  if (Array.isArray(value)) {
    const entries = arrayData(value);
    if (!entries) return { ok: false };
    const output: JsonValue[] = [];
    for (const entry of entries) {
      const copied = data(entry);
      if (!copied.ok) return copied;
      output.push(copied.value);
    }
    return { ok: true, value: output };
  }
  const inspected = record(value);
  if (!inspected) return { ok: false };
  const output: Record<string, JsonValue> = {};
  for (const [key, entry] of Object.entries(inspected)) {
    if (!validIJsonString(key)) return { ok: false };
    const copied = data(entry);
    if (!copied.ok) return copied;
    Object.defineProperty(output, key, {
      value: copied.value,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return { ok: true, value: output };
}
function configIssue(
  code: `CAP_${string}`,
  message: string,
  path: string,
  source: CompilationSourceLocation,
  details?: JsonValue,
): CompilationDiagnostic {
  return compilationDiagnostic({
    code,
    severity: "error",
    phase: "configuration",
    subphase: "config-value",
    message,
    path,
    source,
    ...(details === undefined ? {} : { details }),
  });
}

function configValueLocations(
  sourceText: string,
): ReadonlyMap<string, CompilationSourceLocation> {
  const parsed = ts.createSourceFile(
    canonicalConfig,
    sourceText,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const bindings = new Map<string, ts.Expression>();
  for (const statement of parsed.statements)
    if (
      ts.isVariableStatement(statement) &&
      (statement.declarationList.flags & ts.NodeFlags.Const) !== 0 &&
      statement.declarationList.declarations.length === 1
    )
      for (const declaration of statement.declarationList.declarations)
        if (ts.isIdentifier(declaration.name) && declaration.initializer)
          bindings.set(declaration.name.text, declaration.initializer);
  const declaresName = (name: ts.BindingName, expected: string): boolean =>
    ts.isIdentifier(name)
      ? name.text === expected
      : name.elements.some(
          (element) =>
            !ts.isOmittedExpression(element) &&
            declaresName(element.name, expected),
        );
  const objectIsDeclared = parsed.statements.some((statement) => {
    if (ts.isVariableStatement(statement))
      return statement.declarationList.declarations.some((declaration) =>
        declaresName(declaration.name, "Object"),
      );
    if (
      ts.isClassDeclaration(statement) ||
      ts.isFunctionDeclaration(statement) ||
      ts.isEnumDeclaration(statement) ||
      ts.isModuleDeclaration(statement) ||
      ts.isInterfaceDeclaration(statement) ||
      ts.isTypeAliasDeclaration(statement)
    )
      return statement.name?.text === "Object";
    if (ts.isImportEqualsDeclaration(statement))
      return statement.name.text === "Object";
    if (!ts.isImportDeclaration(statement) || !statement.importClause)
      return false;
    const clause = statement.importClause;
    if (clause.name?.text === "Object") return true;
    const bindings = clause.namedBindings;
    if (!bindings) return false;
    if (ts.isNamespaceImport(bindings)) return bindings.name.text === "Object";
    return bindings.elements.some((element) => element.name.text === "Object");
  });
  let objectReferencesAreIntrinsic = true;
  const inspectObjectReferences = (node: ts.Node): void => {
    if (
      ts.isPropertyAccessExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "globalThis" &&
      node.name.text === "Object"
    )
      objectReferencesAreIntrinsic = false;
    if (ts.isIdentifier(node) && node.text === "Object") {
      const parent = node.parent;
      const propertyName =
        ts.isPropertyAccessExpression(parent) && parent.name === node;
      const exactFreezeCall =
        ts.isPropertyAccessExpression(parent) &&
        parent.expression === node &&
        parent.name.text === "freeze" &&
        ts.isCallExpression(parent.parent) &&
        parent.parent.expression === parent &&
        parent.parent.arguments.length === 1;
      if (!propertyName && !exactFreezeCall)
        objectReferencesAreIntrinsic = false;
    }
    ts.forEachChild(node, inspectObjectReferences);
  };
  inspectObjectReferences(parsed);
  const objectIsUnshadowed = !objectIsDeclared && objectReferencesAreIntrinsic;
  const exactFreezeCall = (
    call: ts.CallExpression,
    argument: ts.Expression,
  ): boolean =>
    objectIsUnshadowed &&
    call.arguments.length === 1 &&
    call.arguments[0] === argument &&
    ts.isPropertyAccessExpression(call.expression) &&
    ts.isIdentifier(call.expression.expression) &&
    call.expression.expression.text === "Object" &&
    call.expression.name.text === "freeze";
  const containerUseIsTracked = (
    initial: ts.ObjectLiteralExpression | ts.ArrayLiteralExpression,
  ): boolean => {
    let value: ts.Expression = initial;
    for (;;) {
      const parent = value.parent;
      if (
        ts.isParenthesizedExpression(parent) ||
        ts.isAsExpression(parent) ||
        ts.isTypeAssertionExpression(parent) ||
        ts.isSatisfiesExpression(parent) ||
        ts.isNonNullExpression(parent)
      ) {
        value = parent;
        continue;
      }
      if (ts.isCallExpression(parent) && exactFreezeCall(parent, value)) {
        value = parent;
        continue;
      }
      if (ts.isExportAssignment(parent) && parent.expression === value)
        return true;
      if (
        ts.isVariableDeclaration(parent) &&
        parent.initializer === value &&
        ts.isIdentifier(parent.name) &&
        bindings.get(parent.name.text) === parent.initializer
      )
        return true;
      if (
        ts.isPropertyAssignment(parent) &&
        parent.initializer === value &&
        ts.isObjectLiteralExpression(parent.parent)
      ) {
        value = parent.parent;
        continue;
      }
      if (
        ts.isArrayLiteralExpression(parent) &&
        parent.elements.includes(value)
      ) {
        value = parent;
        continue;
      }
      return false;
    }
  };
  const unsafeAliases = new Set<string>();
  const inspectReferences = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && bindings.has(node.text)) {
      const parent = node.parent;
      const declarationName =
        ts.isVariableDeclaration(parent) && parent.name === node;
      const nonReferenceName =
        ((ts.isPropertyAssignment(parent) || ts.isMethodDeclaration(parent)) &&
          parent.name === node) ||
        (ts.isPropertyAccessExpression(parent) && parent.name === node);
      const exportSpecifierName =
        ts.isExportSpecifier(parent) &&
        (parent.name === node || parent.propertyName === node);
      if (declarationName || nonReferenceName || exportSpecifierName) {
        ts.forEachChild(node, inspectReferences);
        return;
      }
      let reference: ts.Expression = node;
      while (
        ts.isParenthesizedExpression(reference.parent) ||
        ts.isAsExpression(reference.parent) ||
        ts.isTypeAssertionExpression(reference.parent) ||
        ts.isSatisfiesExpression(reference.parent) ||
        ts.isNonNullExpression(reference.parent)
      )
        reference = reference.parent;
      const referenceParent = reference.parent;
      const allowedFreezeArgument =
        ts.isCallExpression(referenceParent) &&
        exactFreezeCall(referenceParent, reference);
      const allowedAliasInitializer =
        ts.isVariableDeclaration(referenceParent) &&
        referenceParent.initializer === reference &&
        ts.isIdentifier(referenceParent.name) &&
        bindings.get(referenceParent.name.text) === referenceParent.initializer;
      const container =
        ts.isPropertyAssignment(referenceParent) &&
        referenceParent.initializer === reference &&
        ts.isObjectLiteralExpression(referenceParent.parent)
          ? referenceParent.parent
          : ts.isShorthandPropertyAssignment(referenceParent) &&
              ts.isObjectLiteralExpression(referenceParent.parent)
            ? referenceParent.parent
            : ts.isArrayLiteralExpression(referenceParent) &&
                referenceParent.elements.includes(reference)
              ? referenceParent
              : undefined;
      const allowedValuePosition =
        (ts.isExportAssignment(referenceParent) &&
          referenceParent.expression === reference) ||
        (container !== undefined && containerUseIsTracked(container));
      if (
        !allowedFreezeArgument &&
        !allowedAliasInitializer &&
        !allowedValuePosition
      )
        unsafeAliases.add(node.text);
    }
    ts.forEachChild(node, inspectReferences);
  };
  inspectReferences(parsed);
  let expanded = true;
  while (expanded) {
    expanded = false;
    for (const name of [...unsafeAliases]) {
      const initializer = bindings.get(name);
      if (!initializer) continue;
      const markUpstream = (node: ts.Node): void => {
        if (
          ts.isIdentifier(node) &&
          bindings.has(node.text) &&
          !unsafeAliases.has(node.text)
        ) {
          unsafeAliases.add(node.text);
          expanded = true;
        }
        ts.forEachChild(node, markUpstream);
      };
      markUpstream(initializer);
    }
  }
  for (const name of unsafeAliases) bindings.delete(name);
  const unwrap = (
    value: ts.Expression,
    seen = new Set<ts.Expression>(),
  ): ts.Expression => {
    if (seen.has(value)) return value;
    seen.add(value);
    let expression = value;
    while (
      ts.isParenthesizedExpression(expression) ||
      ts.isAsExpression(expression) ||
      ts.isTypeAssertionExpression(expression) ||
      ts.isSatisfiesExpression(expression) ||
      ts.isNonNullExpression(expression)
    )
      expression = expression.expression;
    if (
      ts.isCallExpression(expression) &&
      expression.arguments.length === 1 &&
      ts.isPropertyAccessExpression(expression.expression) &&
      exactFreezeCall(expression, expression.arguments[0]!)
    )
      return unwrap(expression.arguments[0]!, seen);
    if (ts.isIdentifier(expression) && bindings.has(expression.text))
      return unwrap(bindings.get(expression.text)!, seen);
    return expression;
  };
  const propertyName = (name: ts.PropertyName): string | undefined => {
    if (
      ts.isIdentifier(name) ||
      ts.isStringLiteralLike(name) ||
      ts.isNumericLiteral(name)
    )
      return name.text;
    return undefined;
  };
  const unambiguousObject = (expression: ts.ObjectLiteralExpression): boolean =>
    !expression.properties.some(
      (property) =>
        ts.isSpreadAssignment(property) ||
        ts.isMethodDeclaration(property) ||
        ts.isGetAccessorDeclaration(property) ||
        ts.isSetAccessorDeclaration(property) ||
        ((ts.isPropertyAssignment(property) ||
          ts.isShorthandPropertyAssignment(property)) &&
          ts.isComputedPropertyName(property.name)),
    );
  const exactValue = (
    raw: ts.Expression,
    seen = new Set<ts.Expression>(),
  ): boolean => {
    if (seen.has(raw)) return false;
    seen.add(raw);
    let expression = raw;
    while (
      ts.isParenthesizedExpression(expression) ||
      ts.isAsExpression(expression) ||
      ts.isTypeAssertionExpression(expression) ||
      ts.isSatisfiesExpression(expression) ||
      ts.isNonNullExpression(expression)
    )
      expression = expression.expression;
    if (ts.isIdentifier(expression)) {
      const value = bindings.get(expression.text);
      return value !== undefined && exactValue(value, seen);
    }
    if (
      ts.isCallExpression(expression) &&
      expression.arguments.length === 1 &&
      ts.isPropertyAccessExpression(expression.expression) &&
      exactFreezeCall(expression, expression.arguments[0]!)
    )
      return exactValue(expression.arguments[0]!, seen);
    if (ts.isObjectLiteralExpression(expression))
      return unambiguousObject(expression);
    if (ts.isArrayLiteralExpression(expression))
      return !expression.elements.some(ts.isSpreadElement);
    if (
      ts.isStringLiteralLike(expression) ||
      ts.isNumericLiteral(expression) ||
      ts.isNoSubstitutionTemplateLiteral(expression) ||
      expression.kind === ts.SyntaxKind.TrueKeyword ||
      expression.kind === ts.SyntaxKind.FalseKeyword ||
      expression.kind === ts.SyntaxKind.NullKeyword
    )
      return true;
    return (
      ts.isPrefixUnaryExpression(expression) &&
      (expression.operator === ts.SyntaxKind.PlusToken ||
        expression.operator === ts.SyntaxKind.MinusToken) &&
      ts.isNumericLiteral(expression.operand)
    );
  };
  const locations = new Map<string, CompilationSourceLocation>();
  const location = (node: ts.Node): CompilationSourceLocation => {
    const start = parsed.getLineAndCharacterOfPosition(node.getStart(parsed));
    return Object.freeze({
      file: canonicalConfig,
      line: start.line + 1,
      column: start.character + 1,
    });
  };
  const visited = new Set<ts.Expression>();
  const visit = (raw: ts.Expression, base: string): void => {
    const expression = unwrap(raw);
    if (visited.has(expression)) return;
    visited.add(expression);
    if (ts.isArrayLiteralExpression(expression)) {
      if (!expression.elements.some(ts.isSpreadElement))
        for (const [index, element] of expression.elements.entries())
          if (ts.isExpression(element) && exactValue(element)) {
            const path = `${base}/${index}`;
            locations.set(path, location(element));
            visit(element, path);
          }
      visited.delete(expression);
      return;
    }
    if (!ts.isObjectLiteralExpression(expression)) {
      visited.delete(expression);
      return;
    }
    if (!unambiguousObject(expression)) {
      visited.delete(expression);
      return;
    }
    const counts = new Map<string, number>();
    for (const property of expression.properties) {
      if (
        !ts.isPropertyAssignment(property) &&
        !ts.isShorthandPropertyAssignment(property)
      )
        continue;
      const name = propertyName(property.name);
      if (name !== undefined) counts.set(name, (counts.get(name) ?? 0) + 1);
    }
    for (const property of expression.properties) {
      if (ts.isPropertyAssignment(property)) {
        const name = propertyName(property.name);
        if (
          name === undefined ||
          counts.get(name) !== 1 ||
          !exactValue(property.initializer)
        )
          continue;
        const path = `${base}/${pointerToken(name)}`;
        locations.set(path, location(property.initializer));
        visit(property.initializer, path);
      } else if (ts.isShorthandPropertyAssignment(property)) {
        const value = bindings.get(property.name.text);
        if (
          counts.get(property.name.text) !== 1 ||
          value === undefined ||
          !exactValue(value)
        )
          continue;
        const path = `${base}/${pointerToken(property.name.text)}`;
        locations.set(path, location(property.name));
        visit(value, path);
      }
    }
    visited.delete(expression);
  };
  const exported = parsed.statements.find(
    (statement): statement is ts.ExportAssignment =>
      ts.isExportAssignment(statement) && !statement.isExportEquals,
  );
  if (exported) {
    locations.set("", location(exported.expression));
    visit(exported.expression, "");
  } else {
    const declaration = parsed.statements.find(
      (statement): statement is ts.ExportDeclaration =>
        ts.isExportDeclaration(statement) &&
        !!statement.exportClause &&
        ts.isNamedExports(statement.exportClause) &&
        statement.exportClause.elements.some(
          (element) => element.name.text === "default",
        ),
    );
    if (declaration) {
      locations.set("", location(declaration));
      if (!declaration.moduleSpecifier) {
        const specifier = (
          declaration.exportClause as ts.NamedExports
        ).elements.find((element) => element.name.text === "default");
        const localName = specifier?.propertyName?.text;
        if (localName && bindings.has(localName))
          visit(bindings.get(localName)!, "");
      }
    }
  }
  return locations;
}
function unsupported(
  object: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  base: string,
  diagnostics: CompilationDiagnostic[],
  report: (
    code: `CAP_${string}`,
    message: string,
    path: string,
    details?: JsonValue,
  ) => CompilationDiagnostic,
): boolean {
  let found = false;
  for (const key of Object.keys(object))
    if (!allowed.has(key)) {
      found = true;
      diagnostics.push(
        report(
          "CAP_CONFIG_FIELD_UNSUPPORTED",
          "This configuration field is outside the implemented compiler subset.",
          `${base}/${pointerToken(key)}`,
        ),
      );
    }
  return found;
}

export function validOutputDirectory(value: string): boolean {
  return (
    validRoot(value) &&
    !value.split("/").some((part) => part.includes("*") || part.includes("?"))
  );
}
function aliasKey(value: string): string {
  return value
    .normalize("NFD")
    .replace(/[A-Z]/g, (character) => character.toLowerCase())
    .replace(/[. ]+$/u, "");
}
export interface VolumeNamingProfile {
  readonly device: number | bigint;
  readonly inode: number | bigint;
  readonly filesystemType: number | bigint;
  readonly asciiCaseSensitive: false;
  readonly unicodeNormalization: "nfc-nfd-equivalent";
  readonly ignoresTrailingDotsAndSpaces: true;
  readonly sameDirectoryAtomicRename: true;
  readonly durableDirectorySync: true;
}
const knownDarwinFilesystems = new Set([0x1a, 0x4244]); // APFS, HFS
const knownLinuxFilesystems = new Set([
  0xef53, // ext2/3/4
  0x58465342, // XFS
  0x9123683e, // Btrfs
  0x794c7630, // overlayfs
  0x01021994, // tmpfs
  0x2fc12fc1, // ZFS
]);

export async function readVolumeNamingProfile(
  projectRoot: string,
  expectedIdentity?: Readonly<{
    device: number | bigint;
    inode: number | bigint;
  }>,
): Promise<VolumeNamingProfile | undefined> {
  let handle;
  try {
    handle = await open(
      projectRoot,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const [opened, lexical, filesystem] = await Promise.all([
      handle.stat({ bigint: true }),
      lstat(projectRoot, { bigint: true }),
      statfs(projectRoot, { bigint: true }),
    ]);
    if (
      !opened.isDirectory() ||
      !lexical.isDirectory() ||
      lexical.isSymbolicLink() ||
      opened.dev !== lexical.dev ||
      opened.ino !== lexical.ino ||
      (expectedIdentity &&
        (BigInt(expectedIdentity.device) !== opened.dev ||
          BigInt(expectedIdentity.inode) !== opened.ino))
    )
      return undefined;
    const filesystemType = Number(filesystem.type);
    const known =
      (process.platform === "darwin" &&
        knownDarwinFilesystems.has(filesystemType)) ||
      (process.platform === "linux" &&
        knownLinuxFilesystems.has(filesystemType));
    if (!known) return undefined;
    return Object.freeze({
      device: opened.dev,
      inode: opened.ino,
      filesystemType: filesystem.type,
      // These conservative rules are a safe superset of documented lookup
      // equivalences for the recognized filesystem families.
      asciiCaseSensitive: false,
      unicodeNormalization: "nfc-nfd-equivalent",
      ignoresTrailingDotsAndSpaces: true,
      // Admission is allowlisted above; the live transaction probe verifies
      // behavior but is not treated as crash-property evidence by itself.
      sameDirectoryAtomicRename: true,
      durableDirectorySync: true,
    });
  } catch {
    return undefined;
  } finally {
    await handle?.close().catch(() => {});
  }
}

export function reservedOutputReason(
  value: string,
  profile?: VolumeNamingProfile,
): "reserved-lock-namespace" | "reserved-lock-alias" | undefined {
  const first = value.split("/")[0]!;
  const exact =
    first === ".capaxle-build.lock" ||
    first.startsWith(".capaxle-build.lock.recovering-");
  if (exact) return "reserved-lock-namespace";
  if (!profile) return undefined;
  const key = aliasKey(first);
  if (
    key === ".capaxle-build.lock" ||
    key.startsWith(".capaxle-build.lock.recovering-")
  )
    return "reserved-lock-alias";
  return undefined;
}

export async function outputNamespaceReason(
  projectRoot: string,
  output: string,
  expectedIdentity?: Readonly<{
    device: number | bigint;
    inode: number | bigint;
  }>,
): Promise<
  | "reserved-lock-namespace"
  | "reserved-lock-alias"
  | "namespace-disjointness-unproven"
  | undefined
> {
  const profile = await readVolumeNamingProfile(projectRoot, expectedIdentity);
  if (!profile) return "namespace-disjointness-unproven";
  const requested = reservedOutputReason(output, profile);
  if (requested) return requested;
  const first = output.split("/")[0]!;
  try {
    const requestedInfo = await lstat(resolve(projectRoot, first), {
      bigint: true,
    });
    for (const actual of await readdir(projectRoot)) {
      if (aliasKey(actual) !== aliasKey(first)) continue;
      const actualInfo = await lstat(resolve(projectRoot, actual), {
        bigint: true,
      });
      if (
        actualInfo.dev === requestedInfo.dev &&
        actualInfo.ino === requestedInfo.ino
      )
        return reservedOutputReason(
          `${actual}/${output.split("/").slice(1).join("/")}`,
          profile,
        );
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT")
      return "namespace-disjointness-unproven";
  }
  return undefined;
}

export async function validateExistingOutputPrefix(
  projectRoot: string,
  output: string,
): Promise<"symlink" | undefined> {
  let cursor = projectRoot;
  for (const component of output.split("/")) {
    cursor = resolve(cursor, component);
    try {
      const info = await lstat(cursor);
      if (info.isSymbolicLink()) return "symlink";
      if (!info.isDirectory()) return "symlink";
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      return "symlink";
    }
  }
  return undefined;
}

export async function readOutputVolumeProfile(
  projectRoot: string,
  output: string,
): Promise<VolumeNamingProfile | undefined> {
  let cursor = projectRoot;
  for (const component of output.split("/")) {
    const next = resolve(cursor, component);
    try {
      const info = await lstat(next);
      if (info.isSymbolicLink() || !info.isDirectory()) return undefined;
      cursor = next;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") break;
      return undefined;
    }
  }
  return readVolumeNamingProfile(cursor);
}

export async function loadFullCompilerConfig(
  projectRoot: string,
  generation?: LoaderGeneration,
): Promise<
  | { readonly ok: true; readonly config: ResolvedCompilerConfig }
  | {
      readonly ok: false;
      readonly diagnostics: readonly CompilationDiagnostic[];
    }
> {
  if (generation === undefined)
    return (
      await runModuleLoadTransaction(projectRoot, (ownedGeneration) =>
        loadFullCompilerConfig(projectRoot, ownedGeneration),
      )
    ).value;
  let locations = new Map<string, CompilationSourceLocation>();
  const issue = (
    code: `CAP_${string}`,
    message: string,
    path: string,
    details?: JsonValue,
  ): CompilationDiagnostic =>
    configIssue(
      code,
      message,
      path,
      locations.get(path) ??
        locations.get("") ??
        (path === "/compiler/outputDirectory" ? projectAt : at),
      details,
    );
  const volumeProfile = await readVolumeNamingProfile(projectRoot);
  if (!volumeProfile) {
    return {
      ok: false,
      diagnostics: [
        issue(
          "CAP_CONFIG_OUTPUT_INVALID",
          "Project-root volume identity and output namespace disjointness could not be proven.",
          "/compiler/outputDirectory",
          { reason: "namespace-disjointness-unproven" },
        ),
      ],
    };
  }
  let namespace: unknown;
  try {
    const configPath = resolve(projectRoot, canonicalConfig);
    const before = await readFile(configPath);
    const parsedLocations = configValueLocations(
      Buffer.from(before).toString("utf8"),
    );
    locations = new Map(parsedLocations);
    namespace = await loadFreshModule(configPath, generation);
    const after = await readFile(configPath);
    if (!Buffer.from(before).equals(Buffer.from(after))) throw new Error();
  } catch (error) {
    if (error instanceof ModuleGraphLoadError) throw error;
    return {
      ok: false,
      diagnostics: [
        issue(
          "CAP_CONFIG_SERVICE_INVALID",
          "Full compilation requires capaxle.config.ts with a valid service declaration.",
          "/service",
        ),
      ],
    } as const;
  }
  let exported: unknown;
  try {
    if (
      typeof namespace === "object" &&
      namespace !== null &&
      !types.isProxy(namespace)
    ) {
      const descriptor = Object.getOwnPropertyDescriptor(namespace, "default");
      exported =
        descriptor && "value" in descriptor ? descriptor.value : undefined;
    }
  } catch {
    exported = undefined;
  }
  const root = record(exported);
  if (!root)
    return {
      ok: false,
      diagnostics: [
        issue(
          "CAP_CONFIG_SERVICE_INVALID",
          "Full compilation requires a plain configuration object.",
          "/service",
        ),
      ],
    };
  const diagnostics: CompilationDiagnostic[] = [];
  unsupported(root, allowedTop, "", diagnostics, issue);
  const rawService = record(root.service);
  const serviceAllowed = new Set([
    "name",
    "version",
    "title",
    "description",
    "homepage",
    "contact",
    "tags",
  ]);
  if (!rawService)
    diagnostics.push(
      issue(
        "CAP_CONFIG_SERVICE_INVALID",
        "service must be a plain object.",
        "/service",
      ),
    );
  else {
    unsupported(rawService, serviceAllowed, "/service", diagnostics, issue);
    if (typeof rawService.name !== "string" || !rawService.name.trim())
      diagnostics.push(
        issue(
          "CAP_CONFIG_SERVICE_INVALID",
          "service.name must be a nonempty string.",
          "/service/name",
        ),
      );
    if (
      typeof rawService.version !== "string" ||
      !semver.test(rawService.version)
    )
      diagnostics.push(
        issue(
          "CAP_CONFIG_SERVICE_INVALID",
          "service.version must be an exact SemVer value.",
          "/service/version",
        ),
      );
    for (const key of ["title", "description", "homepage"] as const)
      if (
        key in rawService &&
        (typeof rawService[key] !== "string" ||
          !validIJsonString(rawService[key]))
      )
        diagnostics.push(
          issue(
            "CAP_CONFIG_SERVICE_INVALID",
            `service.${key} must be a string.`,
            `/service/${key}`,
          ),
        );
    if ("tags" in rawService && strings(rawService.tags) === null)
      diagnostics.push(
        issue(
          "CAP_CONFIG_SERVICE_INVALID",
          "service.tags must be a dense string array.",
          "/service/tags",
        ),
      );
    if ("contact" in rawService) {
      const contact = record(rawService.contact);
      if (!contact)
        diagnostics.push(
          issue(
            "CAP_CONFIG_SERVICE_INVALID",
            "service.contact must be a plain object.",
            "/service/contact",
          ),
        );
      else {
        unsupported(
          contact,
          new Set(["name", "url", "email"]),
          "/service/contact",
          diagnostics,
          issue,
        );
        for (const key of Object.keys(contact))
          if (
            typeof contact[key] !== "string" ||
            !validIJsonString(contact[key])
          )
            diagnostics.push(
              issue(
                "CAP_CONFIG_SERVICE_INVALID",
                "Contact values must be strings.",
                `/service/contact/${key}`,
              ),
            );
      }
    }
  }
  const exposureDefaults: Record<
    "http" | "cli" | "mcp" | "internal",
    Exposure
  > = {
    http: "disabled",
    cli: "disabled",
    mcp: "disabled",
    internal: "disabled",
  };
  if ("exposureDefaults" in root) {
    const values = record(root.exposureDefaults);
    if (!values)
      diagnostics.push(
        issue(
          "CAP_CONFIG_EXPOSURE_INVALID",
          "exposureDefaults must be a plain object.",
          "/exposureDefaults",
        ),
      );
    else {
      unsupported(
        values,
        new Set(Object.keys(exposureDefaults)),
        "/exposureDefaults",
        diagnostics,
        issue,
      );
      for (const [surface, value] of Object.entries(values))
        if (!EXPOSURES.includes(value as Exposure))
          diagnostics.push(
            issue(
              "CAP_CONFIG_EXPOSURE_INVALID",
              "Exposure defaults must use a supported level.",
              `/exposureDefaults/${surface}`,
            ),
          );
        else
          exposureDefaults[surface as keyof typeof exposureDefaults] =
            value as Exposure;
    }
  }
  let httpPrefix = "/api";
  let httpHeaderAllowlist: string[] = [];
  let cliBinary: string | undefined;
  const httpDiscovery = { ...defaultDiscoveryContext.http };
  const authoredHttpDiscovery = new Set<string>();
  let mcpEndpoint = defaultDiscoveryContext.mcp.endpoint;
  if ("adapters" in root) {
    const adapters = record(root.adapters);
    if (!adapters)
      diagnostics.push(
        issue(
          "CAP_CONFIG_FIELD_UNSUPPORTED",
          "adapters must be a plain object.",
          "/adapters",
        ),
      );
    else {
      unsupported(
        adapters,
        new Set(["http", "cli", "mcp"]),
        "/adapters",
        diagnostics,
        issue,
      );
      if ("http" in adapters) {
        const http = record(adapters.http);
        if (!http)
          diagnostics.push(
            issue(
              "CAP_CONFIG_FIELD_UNSUPPORTED",
              "adapters.http must be a plain object.",
              "/adapters/http",
            ),
          );
        else {
          unsupported(
            http,
            new Set(["prefix", "headerAllowlist", "discovery"]),
            "/adapters/http",
            diagnostics,
            issue,
          );
          if ("discovery" in http) {
            const value = record(http.discovery);
            if (!value) {
              diagnostics.push(
                issue(
                  "CAP_CONFIG_HTTP_DISCOVERY_INVALID",
                  "adapters.http.discovery must be a plain object.",
                  "/adapters/http/discovery",
                ),
              );
            } else {
              const fields = [
                ["collection", false],
                ["detailTemplate", true],
                ["schemaTemplate", true],
              ] as const;
              for (const key of Object.keys(value))
                if (!fields.some(([field]) => field === key))
                  diagnostics.push(
                    issue(
                      "CAP_CONFIG_HTTP_DISCOVERY_INVALID",
                      "adapters.http.discovery contains an unsupported field.",
                      `/adapters/http/discovery/${pointerToken(key)}`,
                    ),
                  );
              for (const [key, template] of fields)
                if (key in value) {
                  if (!validDiscoveryPath(value[key], template))
                    diagnostics.push(
                      issue(
                        "CAP_CONFIG_HTTP_DISCOVERY_INVALID",
                        "HTTP discovery paths must be canonical same-origin absolute paths with the required template shape.",
                        `/adapters/http/discovery/${key}`,
                      ),
                    );
                  else httpDiscovery[key] = value[key];
                  if (validDiscoveryPath(value[key], template))
                    authoredHttpDiscovery.add(key);
                }
            }
          }
          if ("headerAllowlist" in http) {
            const values = http.headerAllowlist;
            if (
              !Array.isArray(values) ||
              values.some(
                (value) =>
                  typeof value !== "string" ||
                  value !== value.toLowerCase() ||
                  !httpHeaderToken.test(value),
              ) ||
              new Set(values).size !== values.length
            )
              diagnostics.push(
                issue(
                  "CAP_HTTP_HEADER_FORBIDDEN",
                  "HTTP header allowlist must contain unique lowercase field-name tokens.",
                  "/adapters/http/headerAllowlist",
                ),
              );
            else {
              httpHeaderAllowlist = [...values].sort(compareText);
              for (const [index, value] of values.entries())
                if (reservedHttpHeader(value))
                  diagnostics.push(
                    issue(
                      "CAP_HTTP_HEADER_RESERVED",
                      "HTTP header allowlist cannot authorize reserved control headers.",
                      `/adapters/http/headerAllowlist/${index}`,
                    ),
                  );
            }
          }
          if ("prefix" in http) {
            if (
              typeof http.prefix !== "string" ||
              (http.prefix !== "" &&
                http.prefix !== "/" &&
                !/^\/[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*\/?$/.test(
                  http.prefix,
                )) ||
              (typeof http.prefix === "string" &&
                http.prefix
                  .split("/")
                  .some((segment) => segment === "." || segment === ".."))
            )
              diagnostics.push(
                issue(
                  "CAP_HTTP_PREFIX_INVALID",
                  "HTTP prefix must be empty or an absolute path of unreserved literal segments.",
                  "/adapters/http/prefix",
                ),
              );
            else
              httpPrefix =
                http.prefix === "/" ? "" : http.prefix.replace(/\/$/, "");
          }
        }
      }
      if ("cli" in adapters) {
        const cli = record(adapters.cli);
        if (!cli)
          diagnostics.push(
            issue(
              "CAP_CONFIG_FIELD_UNSUPPORTED",
              "adapters.cli must be a plain object.",
              "/adapters/cli",
            ),
          );
        else {
          unsupported(
            cli,
            new Set(["binaryName"]),
            "/adapters/cli",
            diagnostics,
            issue,
          );
          if (
            typeof cli.binaryName !== "string" ||
            !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(cli.binaryName)
          )
            diagnostics.push(
              issue(
                "CAP_CONFIG_FIELD_UNSUPPORTED",
                "adapters.cli.binaryName must be a valid single token.",
                "/adapters/cli/binaryName",
              ),
            );
          else cliBinary = cli.binaryName;
        }
      }
      if ("mcp" in adapters) {
        const mcp = record(adapters.mcp);
        if (!mcp)
          diagnostics.push(
            issue(
              "CAP_CONFIG_MCP_ENDPOINT_INVALID",
              "adapters.mcp must be a plain object.",
              "/adapters/mcp",
            ),
          );
        else {
          for (const key of Object.keys(mcp))
            if (key !== "endpoint")
              diagnostics.push(
                issue(
                  "CAP_CONFIG_MCP_ENDPOINT_INVALID",
                  "adapters.mcp contains an unsupported field.",
                  `/adapters/mcp/${pointerToken(key)}`,
                ),
              );
          if ("endpoint" in mcp) {
            if (!validDiscoveryPath(mcp.endpoint, false))
              diagnostics.push(
                issue(
                  "CAP_CONFIG_MCP_ENDPOINT_INVALID",
                  "adapters.mcp.endpoint must be a canonical same-origin absolute path.",
                  "/adapters/mcp/endpoint",
                ),
              );
            else mcpEndpoint = mcp.endpoint;
          }
        }
      }
    }
  }
  const discoveryRoutes = [
    httpDiscovery.collection,
    httpDiscovery.detailTemplate,
    httpDiscovery.schemaTemplate,
  ];
  for (let left = 0; left < discoveryRoutes.length; left++)
    for (let right = left + 1; right < discoveryRoutes.length; right++)
      if (
        discoveryPathsOverlap(discoveryRoutes[left]!, discoveryRoutes[right]!)
      ) {
        const fields = ["collection", "detailTemplate", "schemaTemplate"];
        const leftField = fields[left]!;
        const rightField = fields[right]!;
        const blamed = authoredHttpDiscovery.has(rightField)
          ? rightField
          : leftField;
        diagnostics.push(
          issue(
            "CAP_CONFIG_HTTP_DISCOVERY_INVALID",
            "HTTP discovery routes must be distinct.",
            `/adapters/http/discovery/${blamed}`,
          ),
        );
      }
  const projections: Record<string, ProjectionOverrides> = Object.create(null);
  if ("projections" in root) {
    const map = record(root.projections);
    if (!map)
      diagnostics.push(
        issue(
          "CAP_CONFIG_PROJECTION_INVALID",
          "projections must be a plain object map.",
          "/projections",
        ),
      );
    else
      for (const [id, raw] of Object.entries(map)) {
        const projectionPath = `/projections/${pointerToken(id)}`;
        const value = record(raw);
        if (!value) {
          diagnostics.push(
            issue(
              "CAP_CONFIG_PROJECTION_INVALID",
              "Each projection entry must be a plain object.",
              projectionPath,
            ),
          );
          continue;
        }
        unsupported(
          value,
          new Set(["http", "cli", "mcp", "docs", "sdk"]),
          projectionPath,
          diagnostics,
          issue,
        );
        const copied = data(value);
        if (!copied.ok) {
          diagnostics.push(
            issue(
              "CAP_CONFIG_PROJECTION_INVALID",
              "Projection overrides must contain only portable data properties.",
              projectionPath,
            ),
          );
          continue;
        }
        projections[id] = copied.value as ProjectionOverrides;
      }
  }
  let outputDirectory = "build/capaxle";
  let outputExplicit = false;
  if ("compiler" in root) {
    const compiler = record(root.compiler);
    if (!compiler)
      diagnostics.push(
        issue(
          "CAP_CONFIG_FIELD_UNSUPPORTED",
          "compiler must be a plain object.",
          "/compiler",
        ),
      );
    else {
      unsupported(
        compiler,
        new Set(["outputDirectory"]),
        "/compiler",
        diagnostics,
        issue,
      );
      if ("outputDirectory" in compiler) {
        outputExplicit = true;
        if (
          typeof compiler.outputDirectory !== "string" ||
          !validOutputDirectory(compiler.outputDirectory)
        )
          diagnostics.push(
            issue(
              "CAP_CONFIG_OUTPUT_INVALID",
              "Compiler output selection is invalid.",
              "/compiler/outputDirectory",
              { reason: "format" },
            ),
          );
        else outputDirectory = compiler.outputDirectory;
      }
    }
  }
  const reserved = await outputNamespaceReason(projectRoot, outputDirectory, {
    device: volumeProfile.device,
    inode: volumeProfile.inode,
  });
  if (reserved)
    diagnostics.push(
      issue(
        "CAP_CONFIG_OUTPUT_INVALID",
        "Compiler output selection conflicts with the reserved build-lock namespace.",
        "/compiler/outputDirectory",
        { reason: reserved },
      ),
    );
  else if (await validateExistingOutputPrefix(projectRoot, outputDirectory))
    diagnostics.push(
      issue(
        "CAP_CONFIG_OUTPUT_INVALID",
        "Compiler output selection contains an unsupported filesystem component.",
        "/compiler/outputDirectory",
        { reason: "symlink" },
      ),
    );
  else if (!(await readOutputVolumeProfile(projectRoot, outputDirectory)))
    diagnostics.push(
      issue(
        "CAP_CONFIG_OUTPUT_INVALID",
        "Compiler output volume cannot prove the required naming, atomic-replacement, and durability profile.",
        "/compiler/outputDirectory",
        { reason: "namespace-disjointness-unproven" },
      ),
    );
  if (diagnostics.length || !rawService) return { ok: false, diagnostics };
  const service: Record<string, JsonValue> = {
    name: rawService.name as string,
    version: rawService.version as string,
  };
  for (const key of ["title", "description", "homepage"] as const)
    if (typeof rawService[key] === "string") service[key] = rawService[key];
  if (rawService.contact)
    service.contact = {
      ...(record(rawService.contact) as Record<string, JsonValue>),
    };
  if (rawService.tags) service.tags = [...(rawService.tags as string[])];
  if (!("tags" in service)) service.tags = [];
  const fallback = locations.get("") ?? at;
  const visitedConfigValues = new WeakSet<object>();
  const completeSourceLocations = (value: unknown, base: string): void => {
    if (typeof value !== "object" || value === null) return;
    if (visitedConfigValues.has(value)) return;
    visitedConfigValues.add(value);
    const entries = Array.isArray(value)
      ? arrayData(value)?.map((entry, index) => [String(index), entry] as const)
      : Object.entries(record(value) ?? {});
    for (const [key, entry] of entries ?? []) {
      const path = `${base}/${pointerToken(key)}`;
      if (!locations.has(path)) locations.set(path, fallback);
      completeSourceLocations(entry, path);
    }
  };
  completeSourceLocations(root, "");
  return {
    ok: true,
    config: Object.freeze({
      service: Object.freeze(service),
      exposureDefaults: Object.freeze(exposureDefaults),
      httpPrefix,
      httpHeaderAllowlist: Object.freeze(httpHeaderAllowlist),
      discovery: Object.freeze({
        http: Object.freeze(httpDiscovery),
        mcp: Object.freeze({ endpoint: mcpEndpoint }),
      }),
      ...(cliBinary ? { cliBinary } : {}),
      projections: Object.freeze(projections),
      outputDirectory,
      outputExplicit,
      outputSource: outputExplicit
        ? (locations.get("/compiler/outputDirectory") ??
          locations.get("") ??
          at)
        : projectAt,
      source: locations.get("") ?? at,
      sourceLocations: Object.freeze(Object.fromEntries(locations)),
      configFile: canonicalConfig,
    }),
  };
}
