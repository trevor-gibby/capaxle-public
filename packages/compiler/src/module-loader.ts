import { AsyncLocalStorage } from "node:async_hooks";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import {
  createRequire,
  isBuiltin,
  register,
  registerHooks,
  syncBuiltinESMExports,
  type ResolveFnOutput,
  type ResolveHookContext,
} from "node:module";
import {
  dirname,
  extname,
  isAbsolute,
  parse,
  relative,
  resolve as resolvePath,
  sep,
} from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

const generationKey = "capaxle-discovery-generation";
const supportedExtensions = new Set([
  ".ts",
  ".mts",
  ".js",
  ".mjs",
  ".cjs",
  ".json",
]);
const localRequire = createRequire(import.meta.url);
const nativeRegisterHooks = registerHooks;
const moduleBuiltin = localRequire("node:module") as {
  register: typeof register;
  registerHooks: typeof registerHooks;
  _cache: Record<string, NodeJS.Module>;
};
const moduleLoadBoundary = Symbol.for(
  "@capaxle/compiler/test-module-load-boundary@1",
);
const commonJsOwnerBoundary = Symbol.for("@capaxle/compiler/commonjs-owner@1");

export type LoaderGeneration = string;
export type ModuleLoadFormat = "module" | "commonjs" | "json";
export type ModuleLoadMechanism = "import" | "dynamic-import" | "require";

export interface ModuleLoadTrace {
  readonly traceVersion: "0.1";
  readonly entries: readonly string[];
  readonly modules: readonly {
    readonly path: string;
    readonly format: ModuleLoadFormat;
    readonly sha256: `sha256:${string}`;
  }[];
  readonly edges: readonly {
    readonly importer: string;
    readonly target: string;
    readonly mechanism: ModuleLoadMechanism;
  }[];
  readonly packages: readonly {
    readonly specifier: string;
    readonly packageName: string;
    readonly version: string;
    readonly integrity: string | null;
  }[];
}

export interface ModulePackageImport {
  readonly specifier: string;
  readonly packageName: string;
  readonly version: string;
  readonly integrity: string | null;
  readonly importer: string;
}

export class ModuleGraphLoadError extends Error {
  readonly code: "CAP_GRAPH_INPUT_OUTSIDE_PROJECT" | "CAP_GRAPH_NODE_INVALID";
  readonly reason:
    | "runtime-hook-unavailable"
    | "module-format-unsupported"
    | "module-url-unsupported"
    | "module-classification-ambiguous"
    | "module-trace-incomplete"
    | "module-format-conflict"
    | "module-cache-unsafe"
    | "loader-chain-unsupported"
    | "nested-compilation-unsupported"
    | "closed-transaction-import"
    | "outside-project";
  readonly sourceFile: string;

  constructor(
    code: ModuleGraphLoadError["code"],
    reason: ModuleGraphLoadError["reason"],
    sourceFile: string,
  ) {
    super("A compiler module-graph input could not be loaded safely.");
    this.name = "ModuleGraphLoadError";
    this.code = code;
    this.reason = reason;
    this.sourceFile = sourceFile;
  }
}

interface MutableTransaction {
  readonly generation: LoaderGeneration;
  readonly root: string;
  readonly modules: Map<string, ModuleLoadTrace["modules"][number]>;
  readonly edges: Map<string, ModuleLoadTrace["edges"][number]>;
  readonly entries: Set<string>;
  readonly packages: Map<string, ModuleLoadTrace["packages"][number]>;
  readonly packageImports: Map<string, ModulePackageImport>;
  readonly lockPackages: ReadonlyMap<
    string,
    { readonly version: string; readonly integrity: string | null }
  >;
  readonly commonJsLoads: Map<string, number>;
  readonly commonJsOwners: Map<string, object>;
  readonly packageOwners: Map<string, PackageOwner>;
  readonly bridgeLoads: Set<string>;
  readonly directCacheLoads: Set<string>;
  closed: boolean;
}

interface PackageOwner {
  readonly root: string;
  readonly packageName: string;
  readonly version: string;
  readonly integrity: string | null;
}

const owner = new AsyncLocalStorage<MutableTransaction>();
const entryOwner = new AsyncLocalStorage<string>();
let active: MutableTransaction | undefined;
let loaderRegistered = false;
let nextGeneration = 0;
let fifo: Promise<void> = Promise.resolve();
const completedCommonJs = new Set<string>();
const completedGenerations = new Set<string>();
let guardedRegisterHooks: typeof registerHooks | undefined;
let guardedRegister: typeof register | undefined;

const compareText = (left: string, right: string): number =>
  left < right ? -1 : left > right ? 1 : 0;

function sha256(bytes: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function projectPath(root: string, file: string): string {
  const path = relative(root, file).split(sep).join("/");
  return path || ".";
}

function contains(root: string, file: string): boolean {
  const path = relative(root, file);
  return (
    path === "" ||
    (!path.startsWith(`..${sep}`) && path !== ".." && !isAbsolute(path))
  );
}

interface PackageLockEntry {
  readonly version: string;
  readonly integrity: string | null;
}

function dataRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function packageNameOf(specifier: string): string | undefined {
  const parts = specifier.split("/");
  const name = specifier.startsWith("@")
    ? parts.slice(0, 2).join("/")
    : parts[0];
  return name && name !== "@" ? name : undefined;
}

function parsedLockPackages(file: string): Record<string, unknown> | undefined {
  try {
    const lock = dataRecord(JSON.parse(readFileSync(file, "utf8")));
    return dataRecord(lock?.packages);
  } catch {
    return undefined;
  }
}

function lockEntry(
  packages: Record<string, unknown>,
  key: string,
): PackageLockEntry | undefined {
  const entry = dataRecord(packages[key]);
  if (!entry) return undefined;
  const linked =
    entry.link === true && typeof entry.resolved === "string"
      ? dataRecord(packages[entry.resolved])
      : undefined;
  const resolved = linked ?? entry;
  if (typeof resolved.version !== "string") return undefined;
  const integrity =
    resolved.integrity === undefined
      ? null
      : typeof resolved.integrity === "string"
        ? resolved.integrity
        : undefined;
  if (
    integrity === undefined ||
    (integrity !== null && !/^sha512-[A-Za-z0-9+/]+={0,2}$/u.test(integrity))
  )
    return undefined;
  return Object.freeze({ version: resolved.version, integrity });
}

function projectLockPackages(
  root: string,
): ReadonlyMap<string, PackageLockEntry> {
  const packages = parsedLockPackages(resolvePath(root, "package-lock.json"));
  const entries = new Map<string, PackageLockEntry>();
  if (!packages) return entries;
  for (const key of Object.keys(packages)) {
    const marker = "node_modules/";
    const index = key.lastIndexOf(marker);
    if (index < 0) continue;
    const specifier = key.slice(index + marker.length);
    const name = packageNameOf(specifier);
    if (!name || specifier !== name) continue;
    const entry = lockEntry(packages, key);
    if (entry) entries.set(key, entry);
  }
  return entries;
}

function packageRootFor(
  file: string,
  expectedName: string,
): string | undefined {
  let cursor = dirname(file);
  const volumeRoot = parse(cursor).root;
  while (true) {
    try {
      const manifest = dataRecord(
        JSON.parse(readFileSync(resolvePath(cursor, "package.json"), "utf8")),
      );
      if (manifest?.name === expectedName) return cursor;
    } catch {
      // Continue to the filesystem root without exposing package paths.
    }
    if (cursor === volumeRoot) return undefined;
    cursor = dirname(cursor);
  }
}

function nearestPackageRoot(file: string): string | undefined {
  let cursor = dirname(file);
  const volumeRoot = parse(cursor).root;
  while (true) {
    try {
      const manifest = dataRecord(
        JSON.parse(readFileSync(resolvePath(cursor, "package.json"), "utf8")),
      );
      if (typeof manifest?.name === "string") return cursor;
    } catch {
      // Continue to the filesystem root without exposing package paths.
    }
    if (cursor === volumeRoot) return undefined;
    cursor = dirname(cursor);
  }
}

function installedLockEntry(
  packageRoot: string,
  packageName: string,
): PackageLockEntry | undefined {
  let cursor = dirname(packageRoot);
  const volumeRoot = parse(cursor).root;
  while (true) {
    for (const name of [
      "node_modules/.package-lock.json",
      "package-lock.json",
    ]) {
      const packages = parsedLockPackages(resolvePath(cursor, name));
      if (!packages) continue;
      const relativeRoot = relative(cursor, packageRoot).split(sep).join("/");
      const direct = lockEntry(packages, relativeRoot);
      if (direct) return direct;
      const topLevel = lockEntry(packages, `node_modules/${packageName}`);
      if (topLevel) return topLevel;
    }
    if (cursor === volumeRoot) return undefined;
    cursor = dirname(cursor);
  }
}

function packageAttribution(
  specifier: string,
  resolvedFile: string,
  transaction: MutableTransaction,
  parentURL?: string,
): ModulePackageImport & { readonly packageRoot: string } {
  const packageName = packageNameOf(specifier);
  const packageRoot = packageName
    ? packageRootFor(resolvedFile, packageName)
    : undefined;
  const lockKey =
    packageRoot && contains(transaction.root, packageRoot)
      ? projectPath(transaction.root, packageRoot)
      : packageName
        ? `node_modules/${packageName}`
        : undefined;
  const expected = lockKey ? transaction.lockPackages.get(lockKey) : undefined;
  let actualVersion: string | undefined;
  if (packageRoot) {
    try {
      actualVersion = dataRecord(
        JSON.parse(
          readFileSync(resolvePath(packageRoot, "package.json"), "utf8"),
        ),
      )?.version as string | undefined;
    } catch {
      actualVersion = undefined;
    }
  }
  const installed =
    packageRoot && packageName
      ? installedLockEntry(packageRoot, packageName)
      : undefined;
  if (
    !packageName ||
    !expected ||
    !packageRoot ||
    typeof actualVersion !== "string" ||
    actualVersion !== expected.version ||
    (installed !== undefined &&
      (installed.version !== expected.version ||
        installed.integrity !== expected.integrity))
  )
    fail(
      transaction,
      "CAP_GRAPH_NODE_INVALID",
      "module-classification-ambiguous",
      parentURL,
    );
  return Object.freeze({
    specifier,
    packageName,
    version: expected.version,
    integrity: expected.integrity,
    importer: sourceFor(transaction, parentURL),
    packageRoot,
  });
}

function markerOf(url: string | undefined): string | null {
  if (!url?.startsWith("file:")) return null;
  try {
    return new URL(url).searchParams.get(generationKey);
  } catch {
    return null;
  }
}

function stripMarker(url: string): string {
  const parsed = new URL(url);
  parsed.searchParams.delete(generationKey);
  return parsed.href;
}

function sourceFor(
  transaction: MutableTransaction,
  parentURL?: string,
): string {
  if (!parentURL?.startsWith("file:")) return ".";
  try {
    return projectPath(
      transaction.root,
      realpathSync(fileURLToPath(stripMarker(parentURL))),
    );
  } catch {
    return ".";
  }
}

function canonicalParent(
  transaction: MutableTransaction,
  parentURL: string | undefined,
): string | undefined {
  if (!parentURL?.startsWith("file:")) return undefined;
  try {
    return realpathSync(fileURLToPath(stripMarker(parentURL)));
  } catch {
    return undefined;
  }
}

function parentIsLocal(
  transaction: MutableTransaction,
  parentURL: string | undefined,
): boolean {
  const file = canonicalParent(transaction, parentURL);
  if (!file) return false;
  return (
    contains(transaction.root, file) &&
    !projectPath(transaction.root, file).split("/").includes("node_modules")
  );
}

function parentPackageOwner(
  transaction: MutableTransaction,
  parentURL: string | undefined,
): PackageOwner | undefined {
  const file = canonicalParent(transaction, parentURL);
  const packageRoot = file ? nearestPackageRoot(file) : undefined;
  return packageRoot ? transaction.packageOwners.get(packageRoot) : undefined;
}

function fail(
  transaction: MutableTransaction,
  code: ModuleGraphLoadError["code"],
  reason: ModuleGraphLoadError["reason"],
  parentURL?: string,
): never {
  throw new ModuleGraphLoadError(
    code,
    reason,
    sourceFor(transaction, parentURL),
  );
}

function assertRegularWithoutSymlink(
  file: string,
  transaction: MutableTransaction,
  parentURL?: string,
): string {
  const lexical = resolvePath(file);
  const volumeRoot = parse(lexical).root;
  const segments = relative(volumeRoot, lexical).split(sep).filter(Boolean);
  let cursor = volumeRoot;
  try {
    for (let index = 0; index < segments.length; index++) {
      cursor = resolvePath(cursor, segments[index]!);
      const info = lstatSync(cursor);
      if (info.isSymbolicLink())
        fail(
          transaction,
          "CAP_GRAPH_INPUT_OUTSIDE_PROJECT",
          "outside-project",
          parentURL,
        );
      if (index < segments.length - 1 ? !info.isDirectory() : !info.isFile())
        fail(
          transaction,
          "CAP_GRAPH_NODE_INVALID",
          "module-classification-ambiguous",
          parentURL,
        );
    }
    const canonical = realpathSync(lexical);
    if (!contains(transaction.root, canonical))
      fail(
        transaction,
        "CAP_GRAPH_INPUT_OUTSIDE_PROJECT",
        "outside-project",
        parentURL,
      );
    if (!statSync(canonical).isFile())
      fail(
        transaction,
        "CAP_GRAPH_NODE_INVALID",
        "module-classification-ambiguous",
        parentURL,
      );
    return canonical;
  } catch (error) {
    if (error instanceof ModuleGraphLoadError) throw error;
    fail(
      transaction,
      "CAP_GRAPH_NODE_INVALID",
      "module-classification-ambiguous",
      parentURL,
    );
  }
}

function fileIdentity(file: string): {
  readonly device: bigint;
  readonly inode: bigint;
  readonly mode: bigint;
  readonly size: bigint;
  readonly modified: bigint;
  readonly changed: bigint;
} {
  const info = lstatSync(file, { bigint: true });
  if (info.isSymbolicLink() || !info.isFile()) throw new Error();
  return {
    device: info.dev,
    inode: info.ino,
    mode: info.mode,
    size: info.size,
    modified: info.mtimeNs,
    changed: info.ctimeNs,
  };
}

function sameIdentity(
  left: ReturnType<typeof fileIdentity>,
  right: ReturnType<typeof fileIdentity>,
): boolean {
  return (
    left.device === right.device &&
    left.inode === right.inode &&
    left.mode === right.mode &&
    left.size === right.size &&
    left.modified === right.modified &&
    left.changed === right.changed
  );
}

function invokeModuleLoadBoundary(path: string): void {
  const descriptor = Object.getOwnPropertyDescriptor(
    globalThis,
    moduleLoadBoundary,
  );
  if (
    descriptor &&
    "value" in descriptor &&
    typeof descriptor.value === "function"
  )
    (descriptor.value as (path: string) => void)(path);
}

function assertLoaderOwnership(transaction: MutableTransaction): void {
  if (
    !guardedRegister ||
    !guardedRegisterHooks ||
    moduleBuiltin.register !== guardedRegister ||
    moduleBuiltin.registerHooks !== guardedRegisterHooks
  )
    fail(
      transaction,
      "CAP_GRAPH_NODE_INVALID",
      "loader-chain-unsupported",
      entryOwner.getStore()
        ? pathToFileURL(resolvePath(transaction.root, entryOwner.getStore()!))
            .href
        : undefined,
    );
}

function rejectLoaderRegistration(): never {
  const transaction = active;
  if (transaction)
    fail(
      transaction,
      "CAP_GRAPH_NODE_INVALID",
      "loader-chain-unsupported",
      entryOwner.getStore()
        ? pathToFileURL(resolvePath(transaction.root, entryOwner.getStore()!))
            .href
        : undefined,
    );
  throw new ModuleGraphLoadError(
    "CAP_GRAPH_NODE_INVALID",
    "loader-chain-unsupported",
    ".",
  );
}

function assertCacheOwnership(transaction: MutableTransaction): void {
  for (const [file, count] of transaction.commonJsLoads) {
    if (count !== 1)
      fail(transaction, "CAP_GRAPH_NODE_INVALID", "module-cache-unsafe");
    const cached = moduleBuiltin._cache[file];
    const expected = transaction.commonJsOwners.get(file);
    const format = transaction.modules.get(
      projectPath(transaction.root, file),
    )?.format;
    const legitimateUncachedBridge =
      format === "json" &&
      !expected &&
      transaction.bridgeLoads.has(file) &&
      !transaction.directCacheLoads.has(file);
    if (
      cached === undefined
        ? !legitimateUncachedBridge
        : expected === undefined || cached !== expected
    )
      fail(transaction, "CAP_GRAPH_NODE_INVALID", "module-cache-unsafe");
  }
}

function guardedModuleCache(
  cache: Record<string, NodeJS.Module>,
  transaction: MutableTransaction,
): Record<string, NodeJS.Module> {
  const localCachePath = (key: PropertyKey): string | undefined => {
    if (typeof key !== "string" || !isAbsolute(key)) return undefined;
    try {
      const canonical = realpathSync(key);
      return contains(transaction.root, canonical) ? canonical : undefined;
    } catch {
      return undefined;
    }
  };
  return new Proxy(cache, {
    set(target, key, value, receiver) {
      const path = localCachePath(key);
      const existing = path ? Reflect.get(target, key, receiver) : undefined;
      if (
        path &&
        transaction.commonJsLoads.has(path) &&
        existing !== undefined &&
        existing !== value
      )
        fail(transaction, "CAP_GRAPH_NODE_INVALID", "module-cache-unsafe");
      if (path && typeof value === "object" && value !== null) {
        const previous = transaction.commonJsOwners.get(path);
        if (previous && previous !== value)
          fail(transaction, "CAP_GRAPH_NODE_INVALID", "module-cache-unsafe");
        transaction.commonJsOwners.set(path, value);
      }
      return Reflect.set(target, key, value, receiver);
    },
    deleteProperty(target, key) {
      const path = localCachePath(key);
      if (
        path &&
        transaction.commonJsLoads.has(path) &&
        Reflect.has(target, key)
      )
        fail(transaction, "CAP_GRAPH_NODE_INVALID", "module-cache-unsafe");
      return Reflect.deleteProperty(target, key);
    },
    defineProperty(target, key, descriptor) {
      const path = localCachePath(key);
      const value = descriptor.value;
      if (
        path &&
        transaction.commonJsLoads.has(path) &&
        Reflect.has(target, key) &&
        value !== undefined &&
        Reflect.get(target, key) !== value
      )
        fail(transaction, "CAP_GRAPH_NODE_INVALID", "module-cache-unsafe");
      if (path && typeof value === "object" && value !== null) {
        const previous = transaction.commonJsOwners.get(path);
        if (previous && previous !== value)
          fail(transaction, "CAP_GRAPH_NODE_INVALID", "module-cache-unsafe");
        transaction.commonJsOwners.set(path, value);
      }
      return Reflect.defineProperty(target, key, descriptor);
    },
  });
}

function commonJsOwner(file: string, module: object): void {
  const transaction = active;
  if (!transaction || transaction.closed) return;
  const canonical = realpathSync(file);
  if (!contains(transaction.root, canonical)) return;
  const previous = transaction.commonJsOwners.get(canonical);
  if (previous && previous !== module)
    fail(transaction, "CAP_GRAPH_NODE_INVALID", "module-cache-unsafe");
  transaction.commonJsOwners.set(canonical, module);
}

function instrumentCommonJs(source: string, file: string): string {
  const parsed = ts.createSourceFile(
    file,
    source,
    ts.ScriptTarget.ES2022,
    false,
    ts.ScriptKind.JS,
  );
  let insertion = source.startsWith("#!") ? source.indexOf("\n") + 1 : 0;
  for (const statement of parsed.statements) {
    if (
      !ts.isExpressionStatement(statement) ||
      !ts.isStringLiteral(statement.expression)
    )
      break;
    insertion = statement.end;
  }
  const observer =
    ';globalThis[Symbol.for("@capaxle/compiler/commonjs-owner@1")](__filename,module);\n';
  return `${source.slice(0, insertion)}${observer}${source.slice(insertion)}`;
}

function localFormat(
  file: string,
  resolvedFormat: string | null | undefined,
  transaction: MutableTransaction,
  parentURL?: string,
): ModuleLoadFormat {
  const extension = extname(file);
  if (!supportedExtensions.has(extension))
    fail(
      transaction,
      "CAP_GRAPH_NODE_INVALID",
      "module-format-unsupported",
      parentURL,
    );
  if (extension === ".cjs" || resolvedFormat === "commonjs") return "commonjs";
  if (extension === ".json" || resolvedFormat === "json") return "json";
  if (extension === ".js") {
    let cursor = dirname(file);
    while (contains(transaction.root, cursor)) {
      const packageFile = resolvePath(cursor, "package.json");
      try {
        const info = lstatSync(packageFile);
        if (info.isSymbolicLink() || !info.isFile())
          fail(
            transaction,
            "CAP_GRAPH_NODE_INVALID",
            "module-classification-ambiguous",
            parentURL,
          );
        const packageData: unknown = JSON.parse(
          readFileSync(packageFile, "utf8"),
        );
        if (
          typeof packageData === "object" &&
          packageData !== null &&
          !Array.isArray(packageData)
        ) {
          const type = (packageData as { readonly type?: unknown }).type;
          if (type === "commonjs") return "commonjs";
          if (type === "module") return "module";
        }
        break;
      } catch (error) {
        if (error instanceof ModuleGraphLoadError) throw error;
        if ((error as NodeJS.ErrnoException).code !== "ENOENT")
          fail(
            transaction,
            "CAP_GRAPH_NODE_INVALID",
            "module-classification-ambiguous",
            parentURL,
          );
      }
      if (cursor === transaction.root) break;
      cursor = dirname(cursor);
    }
  }
  return "module";
}

function requestPath(
  specifier: string,
  parentURL: string | undefined,
): string | undefined {
  try {
    if (specifier.startsWith("file:")) return fileURLToPath(specifier);
    if (isAbsolute(specifier)) return specifier;
    if (specifier.startsWith(".") && parentURL?.startsWith("file:"))
      return resolvePath(
        dirname(fileURLToPath(stripMarker(parentURL))),
        specifier,
      );
  } catch {
    return undefined;
  }
  return undefined;
}

function ensureNoAuthoredUrlState(
  specifier: string,
  transaction: MutableTransaction,
  parentURL?: string,
): void {
  if (
    !specifier.startsWith("file:") &&
    !specifier.startsWith(".") &&
    !isAbsolute(specifier)
  )
    return;
  try {
    const parsed = specifier.startsWith("file:")
      ? new URL(specifier)
      : new URL(
          specifier,
          parentURL ? stripMarker(parentURL) : pathToFileURL(transaction.root),
        );
    const ownGeneration = parsed.searchParams.get(generationKey);
    if (ownGeneration !== null) parsed.searchParams.delete(generationKey);
    if (
      parsed.search ||
      parsed.hash ||
      (ownGeneration !== null && ownGeneration !== transaction.generation)
    )
      fail(
        transaction,
        "CAP_GRAPH_NODE_INVALID",
        "module-url-unsupported",
        parentURL,
      );
  } catch (error) {
    if (error instanceof ModuleGraphLoadError) throw error;
    fail(
      transaction,
      "CAP_GRAPH_NODE_INVALID",
      "module-url-unsupported",
      parentURL,
    );
  }
}

function withGeneration(url: string, generation: string): string {
  const parsed = new URL(url);
  parsed.searchParams.set(generationKey, generation);
  return parsed.href;
}

function hasResolutionCondition(conditions: unknown, value: string): boolean {
  if (Array.isArray(conditions)) return conditions.includes(value);
  if (typeof conditions !== "object" || conditions === null) return false;
  const has = Reflect.get(conditions, "has");
  return typeof has === "function" && has.call(conditions, value) === true;
}

function resolveWithFallback(
  specifier: string,
  context: ResolveHookContext,
  nextResolve: (
    specifier: string,
    context?: Partial<ResolveHookContext>,
  ) => ResolveFnOutput,
): ResolveFnOutput {
  const cleanContext = context.parentURL
    ? { ...context, parentURL: stripMarker(context.parentURL) }
    : context;
  try {
    return nextResolve(specifier, cleanContext);
  } catch (originalError) {
    const requested = requestPath(specifier, context.parentURL);
    if (!requested) throw originalError;
    const extension = extname(requested);
    const candidates =
      extension === ".js"
        ? [requested.slice(0, -3) + ".ts"]
        : extension === ".mjs"
          ? [requested.slice(0, -4) + ".mts"]
          : extension
            ? []
            : [".ts", ".mts", ".js", ".mjs"].map(
                (suffix) => requested + suffix,
              );
    for (const candidate of candidates) {
      try {
        if (lstatSync(candidate).isFile())
          return { url: pathToFileURL(candidate).href };
      } catch {
        // Continue through the accepted closed fallback order.
      }
    }
    throw originalError;
  }
}

function ensureLoader(): void {
  if (loaderRegistered) return;
  if (typeof nativeRegisterHooks !== "function")
    throw new ModuleGraphLoadError(
      "CAP_GRAPH_NODE_INVALID",
      "runtime-hook-unavailable",
      ".",
    );
  const existingObserver = Object.getOwnPropertyDescriptor(
    globalThis,
    commonJsOwnerBoundary,
  );
  if (existingObserver && existingObserver.value !== commonJsOwner)
    throw new ModuleGraphLoadError(
      "CAP_GRAPH_NODE_INVALID",
      "loader-chain-unsupported",
      ".",
    );
  if (!existingObserver)
    Object.defineProperty(globalThis, commonJsOwnerBoundary, {
      value: commonJsOwner,
      enumerable: false,
      configurable: false,
      writable: false,
    });
  nativeRegisterHooks({
    resolve(specifier, context, nextResolve) {
      const transaction = active;
      const inheritedGeneration = markerOf(context.parentURL);
      const requestedGeneration = markerOf(specifier);
      if (!transaction) {
        if (
          inheritedGeneration &&
          completedGenerations.has(inheritedGeneration)
        )
          throw new ModuleGraphLoadError(
            "CAP_GRAPH_NODE_INVALID",
            "closed-transaction-import",
            ".",
          );
        return nextResolve(specifier, context);
      }
      if (
        transaction.closed ||
        (inheritedGeneration && inheritedGeneration !== transaction.generation)
      )
        fail(
          transaction,
          "CAP_GRAPH_NODE_INVALID",
          "closed-transaction-import",
          context.parentURL,
        );
      assertLoaderOwnership(transaction);
      const packageParent = parentPackageOwner(transaction, context.parentURL);
      if (
        inheritedGeneration === null &&
        requestedGeneration !== transaction.generation &&
        !parentIsLocal(transaction, context.parentURL) &&
        !packageParent
      )
        return nextResolve(specifier, context);
      if (isBuiltin(specifier)) return nextResolve(specifier, context);
      if (
        /^[A-Za-z][A-Za-z0-9+.-]*:/.test(specifier) &&
        !specifier.startsWith("file:")
      )
        fail(
          transaction,
          "CAP_GRAPH_NODE_INVALID",
          "module-url-unsupported",
          context.parentURL,
        );
      ensureNoAuthoredUrlState(specifier, transaction, context.parentURL);
      const requested = requestPath(specifier, context.parentURL);
      if (
        requested &&
        !packageParent &&
        !contains(transaction.root, resolvePath(requested))
      )
        fail(
          transaction,
          "CAP_GRAPH_INPUT_OUTSIDE_PROJECT",
          "outside-project",
          context.parentURL,
        );
      if (requested && !packageParent)
        try {
          lstatSync(requested);
          assertRegularWithoutSymlink(
            requested,
            transaction,
            context.parentURL,
          );
        } catch (error) {
          if (error instanceof ModuleGraphLoadError) throw error;
          // A missing exact request may still match the closed TS fallback.
        }
      const resolved = resolveWithFallback(specifier, context, nextResolve);
      if (!resolved.url.startsWith("file:"))
        fail(
          transaction,
          "CAP_GRAPH_NODE_INVALID",
          "module-url-unsupported",
          context.parentURL,
        );
      const cleanUrl = stripMarker(resolved.url);
      const resolvedLexicalPath = fileURLToPath(cleanUrl);
      const resolvedPath = realpathSync(resolvedLexicalPath);
      const importer = sourceFor(transaction, context.parentURL);
      const relativePath = projectPath(transaction.root, resolvedPath);
      const local =
        contains(transaction.root, resolvedPath) &&
        !relativePath.split("/").includes("node_modules");
      if (!local) {
        if (
          packageParent &&
          contains(packageParent.root, resolvedPath) &&
          nearestPackageRoot(resolvedPath) === packageParent.root
        ) {
          return resolved;
        }
        if (requested || specifier.startsWith("#"))
          fail(
            transaction,
            packageParent
              ? "CAP_GRAPH_NODE_INVALID"
              : "CAP_GRAPH_INPUT_OUTSIDE_PROJECT",
            packageParent
              ? "module-classification-ambiguous"
              : "outside-project",
            context.parentURL,
          );
        const attribution = packageAttribution(
          specifier,
          resolvedPath,
          transaction,
          context.parentURL,
        );
        transaction.packageOwners.set(attribution.packageRoot, {
          root: attribution.packageRoot,
          packageName: attribution.packageName,
          version: attribution.version,
          integrity: attribution.integrity,
        });
        transaction.packages.set(
          `${attribution.packageName}\0${attribution.specifier}\0${attribution.version}\0${attribution.integrity ?? ""}`,
          Object.freeze({
            specifier: attribution.specifier,
            packageName: attribution.packageName,
            version: attribution.version,
            integrity: attribution.integrity,
          }),
        );
        transaction.packageImports.set(
          `${attribution.importer}\0${attribution.specifier}`,
          Object.freeze({
            specifier: attribution.specifier,
            packageName: attribution.packageName,
            version: attribution.version,
            integrity: attribution.integrity,
            importer: attribution.importer,
          }),
        );
        return resolved;
      }
      if (packageParent)
        fail(
          transaction,
          "CAP_GRAPH_NODE_INVALID",
          "module-classification-ambiguous",
          context.parentURL,
        );
      if (!requested && !specifier.startsWith("#"))
        fail(
          transaction,
          "CAP_GRAPH_NODE_INVALID",
          "module-classification-ambiguous",
          context.parentURL,
        );
      const canonical = assertRegularWithoutSymlink(
        resolvedLexicalPath,
        transaction,
        context.parentURL,
      );
      const target = projectPath(transaction.root, canonical);
      const format = localFormat(
        canonical,
        resolved.format,
        transaction,
        context.parentURL,
      );
      const previous = transaction.modules.get(target);
      if (previous && previous.format !== format)
        fail(
          transaction,
          "CAP_GRAPH_NODE_INVALID",
          "module-format-conflict",
          context.parentURL,
        );
      const importerFormat = transaction.modules.get(importer)?.format;
      const importerCanonical =
        importer === "."
          ? undefined
          : resolvePath(transaction.root, ...importer.split("/"));
      const importerUsesBridge =
        importerCanonical !== undefined &&
        transaction.bridgeLoads.has(importerCanonical);
      const requireResolution = hasResolutionCondition(
        context.conditions,
        "require",
      );
      const commonJsBridge =
        importerFormat === "commonjs" &&
        !requireResolution &&
        specifier.startsWith("file:");
      const mechanism: ModuleLoadMechanism =
        requireResolution || commonJsBridge ? "require" : "import";
      if (importer !== ".") {
        const edgeKey = `${importer}\0${target}\0${mechanism}`;
        transaction.edges.set(edgeKey, {
          importer,
          target,
          mechanism,
        });
      }
      if (format === "commonjs" || format === "json") {
        if (!requireResolution || importerUsesBridge)
          transaction.bridgeLoads.add(canonical);
        else transaction.directCacheLoads.add(canonical);
      }
      return {
        ...resolved,
        url: withGeneration(
          pathToFileURL(canonical).href,
          transaction.generation,
        ),
        format,
        shortCircuit: true,
      };
    },
    load(url, context, nextLoad) {
      const generation = markerOf(url);
      if (!generation) return nextLoad(url, context);
      const transaction = active;
      if (
        !transaction ||
        transaction.closed ||
        generation !== transaction.generation
      )
        throw new ModuleGraphLoadError(
          "CAP_GRAPH_NODE_INVALID",
          "closed-transaction-import",
          ".",
        );
      assertLoaderOwnership(transaction);
      const cleanUrl = stripMarker(url);
      const canonical = assertRegularWithoutSymlink(
        fileURLToPath(cleanUrl),
        transaction,
      );
      const path = projectPath(transaction.root, canonical);
      let before: ReturnType<typeof fileIdentity>;
      try {
        before = fileIdentity(canonical);
      } catch {
        fail(
          transaction,
          "CAP_GRAPH_NODE_INVALID",
          "module-classification-ambiguous",
        );
      }
      const bytes = readFileSync(canonical);
      invokeModuleLoadBoundary(path);
      try {
        const after = fileIdentity(canonical);
        if (
          !sameIdentity(before, after) ||
          realpathSync(canonical) !== canonical
        )
          fail(
            transaction,
            "CAP_GRAPH_NODE_INVALID",
            "module-classification-ambiguous",
          );
      } catch (error) {
        if (error instanceof ModuleGraphLoadError) throw error;
        fail(
          transaction,
          "CAP_GRAPH_NODE_INVALID",
          "module-classification-ambiguous",
        );
      }
      const format = localFormat(canonical, context.format, transaction);
      const previous = transaction.modules.get(path);
      if (previous && previous.format !== format)
        fail(transaction, "CAP_GRAPH_NODE_INVALID", "module-format-conflict");
      transaction.modules.set(
        path,
        Object.freeze({ path, format, sha256: sha256(bytes) }),
      );
      if (format === "commonjs" || format === "json") {
        const loads = (transaction.commonJsLoads.get(canonical) ?? 0) + 1;
        transaction.commonJsLoads.set(canonical, loads);
        if (loads !== 1)
          fail(transaction, "CAP_GRAPH_NODE_INVALID", "module-cache-unsafe");
      }
      if (
        format === "module" &&
        (canonical.endsWith(".ts") || canonical.endsWith(".mts"))
      ) {
        const transpiled = ts.transpileModule(bytes.toString("utf8"), {
          compilerOptions: {
            module: ts.ModuleKind.ESNext,
            target: ts.ScriptTarget.ES2022,
            sourceMap: false,
            inlineSourceMap: false,
            inlineSources: false,
          },
          fileName: canonical,
          reportDiagnostics: false,
        });
        return {
          format: "module",
          source: transpiled.outputText,
          shortCircuit: true,
        };
      }
      return {
        format,
        source:
          format === "commonjs"
            ? instrumentCommonJs(bytes.toString("utf8"), canonical)
            : bytes.toString("utf8"),
        shortCircuit: true,
      };
    },
  });
  guardedRegister = ((...parameters: Parameters<typeof register>) => {
    void parameters;
    return rejectLoaderRegistration();
  }) as typeof register;
  guardedRegisterHooks = ((
    ...parameters: Parameters<typeof nativeRegisterHooks>
  ) => {
    void parameters;
    return rejectLoaderRegistration();
  }) as typeof registerHooks;
  moduleBuiltin.register = guardedRegister;
  moduleBuiltin.registerHooks = guardedRegisterHooks;
  syncBuiltinESMExports();
  loaderRegistered = true;
}

function freezeTrace(transaction: MutableTransaction): ModuleLoadTrace {
  const modules = [...transaction.modules.values()].sort((a, b) =>
    compareText(a.path, b.path),
  );
  const modulePaths = new Set(modules.map((item) => item.path));
  const edges = [...transaction.edges.values()]
    .filter(
      (edge) => modulePaths.has(edge.importer) && modulePaths.has(edge.target),
    )
    .sort(
      (a, b) =>
        compareText(a.importer, b.importer) ||
        compareText(a.target, b.target) ||
        compareText(a.mechanism, b.mechanism),
    );
  const entries = [...transaction.entries].sort(compareText);
  if (
    entries.some((entry) => !modulePaths.has(entry)) ||
    edges.some(
      (edge) =>
        !modulePaths.has(edge.importer) || !modulePaths.has(edge.target),
    )
  )
    fail(transaction, "CAP_GRAPH_NODE_INVALID", "module-trace-incomplete");
  return Object.freeze({
    traceVersion: "0.1",
    entries: Object.freeze(entries),
    modules: Object.freeze(modules),
    edges: Object.freeze(edges),
    packages: Object.freeze(
      [...transaction.packages.values()].sort(
        (a, b) =>
          compareText(a.packageName, b.packageName) ||
          compareText(a.specifier, b.specifier) ||
          compareText(a.version, b.version) ||
          compareText(a.integrity ?? "", b.integrity ?? ""),
      ),
    ),
  });
}

function assertRegularRoot(projectRoot: string): string {
  const root = resolvePath(projectRoot);
  try {
    const info = lstatSync(root);
    if (info.isSymbolicLink() || !info.isDirectory()) throw new Error();
    return realpathSync(root);
  } catch {
    throw new ModuleGraphLoadError(
      "CAP_GRAPH_NODE_INVALID",
      "module-classification-ambiguous",
      ".",
    );
  }
}

export async function runModuleLoadTransaction<T>(
  projectRoot: string,
  work: (generation: LoaderGeneration) => Promise<T>,
): Promise<{
  readonly value: T;
  readonly trace: ModuleLoadTrace;
  readonly packageImports: readonly ModulePackageImport[];
}> {
  if (!isAbsolute(projectRoot))
    throw new TypeError("projectRoot must be an absolute filesystem path.");
  if (owner.getStore())
    throw new ModuleGraphLoadError(
      "CAP_GRAPH_NODE_INVALID",
      "nested-compilation-unsupported",
      ".",
    );
  ensureLoader();
  const root = assertRegularRoot(projectRoot);
  let release!: () => void;
  const predecessor = fifo;
  fifo = new Promise<void>((resolve) => {
    release = resolve;
  });
  await predecessor;
  const transaction: MutableTransaction = {
    generation: `${process.pid}-${String(++nextGeneration)}`,
    root,
    modules: new Map(),
    edges: new Map(),
    entries: new Set(),
    packages: new Map(),
    packageImports: new Map(),
    lockPackages: projectLockPackages(root),
    commonJsLoads: new Map(),
    commonJsOwners: new Map(),
    packageOwners: new Map(),
    bridgeLoads: new Set(),
    directCacheLoads: new Set(),
    closed: false,
  };
  if (
    !guardedRegister ||
    !guardedRegisterHooks ||
    moduleBuiltin.register !== guardedRegister ||
    moduleBuiltin.registerHooks !== guardedRegisterHooks
  ) {
    transaction.closed = true;
    release();
    throw new ModuleGraphLoadError(
      "CAP_GRAPH_NODE_INVALID",
      "loader-chain-unsupported",
      ".",
    );
  }
  for (const file of completedCommonJs) {
    try {
      if (moduleBuiltin._cache[file]) delete moduleBuiltin._cache[file];
      if (moduleBuiltin._cache[file]) throw new Error();
    } catch {
      transaction.closed = true;
      release();
      throw new ModuleGraphLoadError(
        "CAP_GRAPH_NODE_INVALID",
        "module-cache-unsafe",
        ".",
      );
    }
  }
  const originalModuleCache = moduleBuiltin._cache;
  moduleBuiltin._cache = guardedModuleCache(originalModuleCache, transaction);
  active = transaction;
  try {
    let value: T;
    try {
      value = await owner.run(transaction, () => work(transaction.generation));
    } catch (error) {
      assertLoaderOwnership(transaction);
      throw error;
    }
    assertLoaderOwnership(transaction);
    assertCacheOwnership(transaction);
    const trace = freezeTrace(transaction);
    return Object.freeze({
      value,
      trace,
      packageImports: Object.freeze(
        [...transaction.packageImports.values()].sort(
          (a, b) =>
            compareText(a.importer, b.importer) ||
            compareText(a.packageName, b.packageName) ||
            compareText(a.specifier, b.specifier),
        ),
      ),
    });
  } finally {
    completedCommonJs.clear();
    for (const module of transaction.modules.values())
      if (module.format === "commonjs" || module.format === "json")
        completedCommonJs.add(resolvePath(root, ...module.path.split("/")));
    transaction.closed = true;
    completedGenerations.add(transaction.generation);
    active = undefined;
    moduleBuiltin._cache = originalModuleCache;
    release();
  }
}

export async function loadFreshModule(
  file: string,
  generation: LoaderGeneration,
): Promise<unknown> {
  const transaction = active;
  if (
    !transaction ||
    transaction.generation !== generation ||
    transaction.closed
  )
    throw new ModuleGraphLoadError(
      "CAP_GRAPH_NODE_INVALID",
      "closed-transaction-import",
      ".",
    );
  const canonical = assertRegularWithoutSymlink(file, transaction);
  const path = projectPath(transaction.root, canonical);
  transaction.entries.add(path);
  const url = new URL(pathToFileURL(canonical));
  url.searchParams.set(generationKey, generation);
  return entryOwner.run(path, async () => {
    return import(url.href);
  });
}
