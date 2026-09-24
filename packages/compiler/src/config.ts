import { lstat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { types } from "node:util";
import {
  diagnostic,
  location,
  sortDiagnostics,
  type PendingDiagnostic,
} from "./diagnostics.js";
import {
  loadFreshModule,
  ModuleGraphLoadError,
  runModuleLoadTransaction,
  type LoaderGeneration,
} from "./module-loader.js";
import type {
  DiscoveryConfigResult,
  DiscoveryOptions,
  ResolvedDiscoveryConfig,
} from "./types.js";

export const canonicalConfig = "capaxle.config.ts";
export const legacyConfig = "capabuild.config.ts";
export const defaultDiscoveryRoot = "src/capabilities";

export function assertProjectRoot(projectRoot: string): string {
  if (typeof projectRoot !== "string" || !isAbsolute(projectRoot))
    throw new TypeError("projectRoot must be an absolute filesystem path.");
  return resolve(projectRoot);
}

export function projectPath(projectRoot: string, path: string): string {
  const value = relative(projectRoot, path).split(sep).join("/");
  return value.length === 0 ? "." : value;
}

type ConfigPathState =
  | { readonly kind: "missing" }
  | { readonly kind: "file" }
  | { readonly kind: "other" }
  | { readonly kind: "inaccessible" };

async function pathState(path: string): Promise<ConfigPathState> {
  try {
    const info = await lstat(path);
    return Object.freeze({
      kind: info.isFile() && !info.isSymbolicLink() ? "file" : "other",
    });
  } catch (error) {
    return Object.freeze({
      kind:
        (error as NodeJS.ErrnoException).code === "ENOENT"
          ? "missing"
          : "inaccessible",
    });
  }
}

function inspectRecord(
  value: unknown,
  allowed: ReadonlySet<string> | undefined,
): Record<string, unknown> | null {
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
    const result: Record<string, unknown> = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string" || (allowed && !allowed.has(key)))
        return null;
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (!property || !("value" in property) || !property.enumerable)
        return null;
      result[key] = property.value;
    }
    return result;
  } catch {
    return null;
  }
}

function moduleDefault(namespace: unknown): unknown {
  try {
    if (
      typeof namespace !== "object" ||
      namespace === null ||
      types.isProxy(namespace)
    )
      return undefined;
    const property = Object.getOwnPropertyDescriptor(namespace, "default");
    return property && "value" in property ? property.value : undefined;
  } catch {
    return undefined;
  }
}

function inspectStrings(value: unknown): readonly string[] | null {
  try {
    if (!Array.isArray(value) || types.isProxy(value)) return null;
    if (Object.getPrototypeOf(value) !== Array.prototype) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(value).length !== value.length + 1) return null;
    const result: string[] = [];
    for (let index = 0; index < value.length; index++) {
      const property = descriptors[String(index)];
      if (
        !property ||
        !("value" in property) ||
        !property.enumerable ||
        typeof property.value !== "string"
      )
        return null;
      result.push(property.value);
    }
    return Object.freeze(result);
  } catch {
    return null;
  }
}

export function validRoot(root: string): boolean {
  if (
    root.length === 0 ||
    root === "." ||
    isAbsolute(root) ||
    root.includes("\\")
  )
    return false;
  const segments = root.split("/");
  return segments.every(
    (segment) =>
      segment.length > 0 &&
      segment !== "." &&
      segment !== ".." &&
      !segment.includes("*") &&
      !segment.includes("?"),
  );
}

export function validIgnorePattern(pattern: string): boolean {
  if (
    pattern.length === 0 ||
    pattern.startsWith("!") ||
    pattern.startsWith("/") ||
    pattern.includes("\\") ||
    !/^[A-Za-z0-9._/*?-]+$/.test(pattern)
  )
    return false;
  const segments = pattern.split("/");
  return segments.every(
    (segment) =>
      segment.length > 0 &&
      segment !== "." &&
      segment !== ".." &&
      (!segment.includes("**") || segment === "**"),
  );
}

function immutableConfig(
  projectRoot: string,
  root: string,
  ignore: readonly string[],
  allowIdOverride: boolean,
  configFile: "capaxle.config.ts" | null,
): ResolvedDiscoveryConfig {
  return Object.freeze({
    projectRoot,
    root,
    ignore: Object.freeze([...ignore]),
    allowIdOverride,
    configFile,
  });
}

export async function loadDiscoveryConfigForGeneration(
  options: DiscoveryOptions,
  generation: LoaderGeneration,
): Promise<DiscoveryConfigResult> {
  const projectRoot = assertProjectRoot(options.projectRoot);
  const canonicalPath = resolve(projectRoot, canonicalConfig);
  const legacyPath = resolve(projectRoot, legacyConfig);
  const [canonicalState, legacyState] = await Promise.all([
    pathState(canonicalPath),
    pathState(legacyPath),
  ]);
  const diagnostics: PendingDiagnostic[] = [];

  for (const [name, state] of [
    [canonicalConfig, canonicalState],
    [legacyConfig, legacyState],
  ] as const)
    if (state.kind === "inaccessible")
      diagnostics.push(
        diagnostic(
          "config-load",
          "CAP_CONFIG_LOAD_FAILED",
          "error",
          "The configuration path could not be inspected; correct the project-root path structure and permissions before loading.",
          location(name),
        ),
      );

  if (diagnostics.length > 0) {
    return Object.freeze({
      ok: false,
      diagnostics: sortDiagnostics(diagnostics),
    });
  }

  if (canonicalState.kind !== "missing" && legacyState.kind !== "missing") {
    diagnostics.push(
      diagnostic(
        "config-name",
        "CAP_CONFIG_NAME_CONFLICT",
        "error",
        "Both canonical and legacy configuration names are present; keep only capaxle.config.ts.",
        location(canonicalConfig),
        {
          related: [
            {
              message: "Remove or archive this legacy configuration file.",
              source: location(legacyConfig),
            },
          ],
        },
      ),
    );
  } else if (legacyState.kind !== "missing") {
    diagnostics.push(
      diagnostic(
        "config-name",
        "CAP_CONFIG_LEGACY_NAME",
        "error",
        "The legacy configuration name is unsupported; rename it to capaxle.config.ts before loading.",
        location(legacyConfig),
      ),
    );
  } else if (canonicalState.kind === "other") {
    diagnostics.push(
      diagnostic(
        "config-load",
        "CAP_CONFIG_LOAD_FAILED",
        "error",
        "capaxle.config.ts must be a regular project-root file and cannot be a symlink.",
        location(canonicalConfig),
      ),
    );
  }

  if (diagnostics.length > 0)
    return Object.freeze({
      ok: false,
      diagnostics: sortDiagnostics(diagnostics),
    });

  if (canonicalState.kind === "missing")
    return Object.freeze({
      ok: true,
      config: immutableConfig(
        projectRoot,
        defaultDiscoveryRoot,
        [],
        false,
        null,
      ),
      diagnostics: Object.freeze([]),
    });

  let namespace: unknown;
  try {
    namespace = await loadFreshModule(canonicalPath, generation);
  } catch (error) {
    if (error instanceof ModuleGraphLoadError) throw error;
    diagnostics.push(
      diagnostic(
        "config-load",
        "CAP_CONFIG_LOAD_FAILED",
        "error",
        "capaxle.config.ts could not be evaluated in the trusted compiler process.",
        location(canonicalConfig),
      ),
    );
    return Object.freeze({
      ok: false,
      diagnostics: sortDiagnostics(diagnostics),
    });
  }

  const exported = moduleDefault(namespace);
  const config = inspectRecord(exported, undefined);
  if (config === null) {
    diagnostics.push(
      diagnostic(
        "config-value",
        "CAP_CONFIG_EXPORT_INVALID",
        "error",
        "capaxle.config.ts must default-export a plain object with own data properties.",
        location(canonicalConfig),
      ),
    );
    return Object.freeze({
      ok: false,
      diagnostics: sortDiagnostics(diagnostics),
    });
  }

  let root = defaultDiscoveryRoot;
  let ignore: readonly string[] = Object.freeze([]);
  let allowIdOverride = false;
  if ("discovery" in config) {
    const discovery = inspectRecord(
      config.discovery,
      new Set(["root", "ignore", "allowIdOverride"]),
    );
    if (discovery === null) {
      diagnostics.push(
        diagnostic(
          "config-value",
          "CAP_CONFIG_DISCOVERY_INVALID",
          "error",
          "discovery must be a plain object containing only root, ignore, and allowIdOverride data properties.",
          location(canonicalConfig),
          { pointer: "/discovery" },
        ),
      );
    } else {
      if ("root" in discovery) {
        if (typeof discovery.root !== "string" || !validRoot(discovery.root))
          diagnostics.push(
            diagnostic(
              "config-value",
              "CAP_CONFIG_DISCOVERY_INVALID",
              "error",
              "discovery.root must be a nonempty project-relative POSIX path below the project root.",
              location(canonicalConfig),
              { pointer: "/discovery/root" },
            ),
          );
        else root = discovery.root;
      }
      if ("ignore" in discovery) {
        const inspected = inspectStrings(discovery.ignore);
        if (
          inspected === null ||
          inspected.some((pattern) => !validIgnorePattern(pattern))
        )
          diagnostics.push(
            diagnostic(
              "config-value",
              "CAP_CONFIG_DISCOVERY_INVALID",
              "error",
              "discovery.ignore must contain supported root-relative POSIX ignore globs without negation.",
              location(canonicalConfig),
              { pointer: "/discovery/ignore" },
            ),
          );
        else ignore = inspected;
      }
      if ("allowIdOverride" in discovery) {
        if (typeof discovery.allowIdOverride !== "boolean")
          diagnostics.push(
            diagnostic(
              "config-value",
              "CAP_CONFIG_DISCOVERY_INVALID",
              "error",
              "discovery.allowIdOverride must be a boolean.",
              location(canonicalConfig),
              { pointer: "/discovery/allowIdOverride" },
            ),
          );
        else allowIdOverride = discovery.allowIdOverride;
      }
    }
  }

  if (diagnostics.length > 0)
    return Object.freeze({
      ok: false,
      diagnostics: sortDiagnostics(diagnostics),
    });
  return Object.freeze({
    ok: true,
    config: immutableConfig(
      projectRoot,
      root,
      ignore,
      allowIdOverride,
      canonicalConfig,
    ),
    diagnostics: Object.freeze([]),
  });
}

export async function loadDiscoveryConfig(
  options: DiscoveryOptions,
): Promise<DiscoveryConfigResult> {
  const projectRoot = assertProjectRoot(options.projectRoot);
  try {
    if (!(await lstat(projectRoot)).isDirectory())
      return loadDiscoveryConfigForGeneration(options, "no-module-load");
  } catch {
    return loadDiscoveryConfigForGeneration(options, "no-module-load");
  }
  return (
    await runModuleLoadTransaction(options.projectRoot, (generation) =>
      loadDiscoveryConfigForGeneration(options, generation),
    )
  ).value;
}
