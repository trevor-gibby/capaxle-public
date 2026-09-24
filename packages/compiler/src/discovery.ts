import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { types } from "node:util";
import {
  CapabilityDefinitionError,
  isCapability,
  type Capability,
} from "@capaxle/core";
import {
  assertProjectRoot,
  loadDiscoveryConfigForGeneration,
  projectPath,
} from "./config.js";
import {
  compareText,
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
  DiscoveredCapability,
  DiscoveryOptions,
  DiscoveryResult,
  ResolvedDiscoveryConfig,
  SourceLocation,
  SuccessfulDiscoveryResult,
} from "./types.js";

const extensions = [".mts", ".mjs", ".ts", ".js"] as const;
const segmentPattern = /^[a-z][a-z0-9-]*$/;
const idPattern = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*$/;

function globExpression(pattern: string): RegExp {
  const segments = pattern.split("/");
  let expression = "^";
  for (let index = 0; index < segments.length; index++) {
    const segment = segments[index]!;
    if (segment === "**") {
      expression += index === segments.length - 1 ? ".*" : "(?:[^/]+/)*";
      continue;
    }
    for (const character of segment) {
      if (character === "*") expression += "[^/]*";
      else if (character === "?") expression += "[^/]";
      else expression += character.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
    }
    if (index < segments.length - 1) expression += "/";
  }
  return new RegExp(`${expression}$`);
}

function supportedExtension(path: string): (typeof extensions)[number] | null {
  for (const extension of extensions)
    if (path.endsWith(extension)) return extension;
  return null;
}

function builtInIgnored(path: string, extension: string): boolean {
  const segments = path.split("/");
  if (segments.some((segment) => segment.startsWith("_"))) return true;
  const basename = segments.at(-1)!;
  if (basename.endsWith(".d.ts") || basename.endsWith(".d.mts")) return true;
  const stem = basename.slice(0, -extension.length);
  return stem.endsWith(".test") || stem.endsWith(".spec");
}

function sourceHash(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function scanFiles(
  config: ResolvedDiscoveryConfig,
  diagnostics: PendingDiagnostic[],
): Promise<readonly string[] | null> {
  const rootPath = resolve(config.projectRoot, ...config.root.split("/"));
  let cursor = config.projectRoot;
  for (const segment of config.root.split("/")) {
    cursor = resolve(cursor, segment);
    try {
      const component = await lstat(cursor);
      if (component.isSymbolicLink() || !component.isDirectory()) {
        diagnostics.push(
          diagnostic(
            "root",
            "CAP_DISCOVERY_ROOT_INVALID",
            "error",
            "Every discovery-root path component must be an existing directory below the project root and cannot be a symlink.",
            location(projectPath(config.projectRoot, cursor)),
          ),
        );
        return null;
      }
    } catch {
      diagnostics.push(
        diagnostic(
          "root",
          "CAP_DISCOVERY_ROOT_INVALID",
          "error",
          "Every discovery-root path component must be an existing directory below the project root and cannot be a symlink.",
          location(projectPath(config.projectRoot, cursor)),
        ),
      );
      return null;
    }
  }

  const files: string[] = [];
  let invalidTree = false;
  async function walk(directory: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      invalidTree = true;
      diagnostics.push(
        diagnostic(
          "root",
          "CAP_DISCOVERY_ROOT_INVALID",
          "error",
          "A discovery directory could not be read; correct its accessibility before compiling.",
          location(projectPath(config.projectRoot, directory)),
        ),
      );
      return;
    }
    entries.sort((left, right) => compareText(left.name, right.name));
    for (const entry of entries) {
      const absolute = resolve(directory, entry.name);
      const relative = projectPath(rootPath, absolute);
      let info;
      try {
        info = await lstat(absolute);
      } catch {
        invalidTree = true;
        diagnostics.push(
          diagnostic(
            "root",
            "CAP_DISCOVERY_ROOT_INVALID",
            "error",
            "A discovery-tree entry could not be inspected; correct its accessibility before compiling.",
            location(projectPath(config.projectRoot, absolute)),
          ),
        );
        continue;
      }
      if (info.isSymbolicLink()) {
        invalidTree = true;
        diagnostics.push(
          diagnostic(
            "root",
            "CAP_DISCOVERY_ROOT_INVALID",
            "error",
            "Symlinks inside the discovery tree are unsupported and are never followed.",
            location(projectPath(config.projectRoot, absolute)),
          ),
        );
      } else if (info.isDirectory()) await walk(absolute);
      else if (info.isFile()) files.push(relative);
      else {
        invalidTree = true;
        diagnostics.push(
          diagnostic(
            "root",
            "CAP_DISCOVERY_ROOT_INVALID",
            "error",
            "Only regular files and directories are supported inside the discovery tree.",
            location(projectPath(config.projectRoot, absolute)),
          ),
        );
      }
    }
  }
  await walk(rootPath);
  return invalidTree ? null : Object.freeze(files);
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

function freezeCapability(
  id: string,
  derivedId: string,
  descriptor: Capability,
  source: SourceLocation,
  hash: string,
): DiscoveredCapability {
  return Object.freeze({
    id,
    derivedId,
    descriptor,
    source,
    sourceHash: hash,
  });
}

function freezeResult(
  config: ResolvedDiscoveryConfig | undefined,
  capabilities: readonly DiscoveredCapability[],
  diagnostics: readonly PendingDiagnostic[],
): DiscoveryResult {
  const sorted = sortDiagnostics(diagnostics);
  if (sorted.some((item) => item.severity === "error"))
    return Object.freeze({
      ok: false,
      ...(config === undefined ? {} : { config }),
      capabilities: Object.freeze([]) as readonly [],
      diagnostics: sorted,
    });
  if (config === undefined)
    throw new Error("A successful discovery result requires resolved config.");
  return Object.freeze({
    ok: true,
    config,
    capabilities: Object.freeze([...capabilities]),
    diagnostics: sorted,
  });
}

export async function discoverCapabilities(
  options: DiscoveryOptions,
  generation?: LoaderGeneration,
  propagateLoaderErrors = false,
): Promise<DiscoveryResult> {
  if (generation === undefined)
    return (
      await runModuleLoadTransaction(options.projectRoot, (ownedGeneration) =>
        discoverCapabilities(options, ownedGeneration, false),
      )
    ).value;
  const projectRoot = assertProjectRoot(options.projectRoot);
  const configResult = await loadDiscoveryConfigForGeneration(
    { projectRoot },
    generation,
  );
  const diagnostics: PendingDiagnostic[] = configResult.diagnostics.map(
    (item) =>
      Object.freeze({
        ...item,
        phase:
          item.code.startsWith("CAP_CONFIG_NAME") ||
          item.code === "CAP_CONFIG_LEGACY_NAME"
            ? "config-name"
            : item.code === "CAP_CONFIG_LOAD_FAILED"
              ? "config-load"
              : "config-value",
      }) as PendingDiagnostic,
  );
  if (!configResult.ok) return freezeResult(undefined, [], diagnostics);
  const config = configResult.config;

  const files = await scanFiles(config, diagnostics);
  if (files === null) return freezeResult(config, [], diagnostics);
  const ignores = config.ignore.map(globExpression);
  const candidates: {
    readonly absolute: string;
    readonly relative: string;
    readonly source: SourceLocation;
    readonly derivedId: string;
  }[] = [];
  const rootPath = resolve(projectRoot, ...config.root.split("/"));

  for (const relative of files) {
    const extension = supportedExtension(relative);
    if (
      extension === null ||
      builtInIgnored(relative, extension) ||
      ignores.some((pattern) => pattern.test(relative))
    )
      continue;
    const withoutExtension = relative.slice(0, -extension.length);
    const segments = withoutExtension.split("/");
    const source = location(
      projectPath(projectRoot, resolve(rootPath, relative)),
    );
    if (segments.some((segment) => !segmentPattern.test(segment))) {
      diagnostics.push(
        diagnostic(
          "identity",
          "CAP_DISCOVERY_ID_INVALID",
          "error",
          "Capability path segments must already use lowercase kebab-case and begin with a letter.",
          source,
        ),
      );
      continue;
    }
    candidates.push({
      absolute: resolve(rootPath, relative),
      relative,
      source,
      derivedId: segments.join("."),
    });
  }

  candidates.sort((left, right) => compareText(left.relative, right.relative));
  const prepared: {
    readonly candidate: (typeof candidates)[number];
    readonly bytes: Uint8Array;
  }[] = [];
  for (const candidate of candidates) {
    try {
      const before = await lstat(candidate.absolute);
      if (!before.isFile() || before.isSymbolicLink()) throw new Error();
      const bytes = await readFile(candidate.absolute);
      const after = await lstat(candidate.absolute);
      if (!after.isFile() || after.isSymbolicLink()) throw new Error();
      prepared.push({ candidate, bytes });
    } catch {
      diagnostics.push(
        diagnostic(
          "module-load",
          "CAP_DISCOVERY_MODULE_LOAD_FAILED",
          "error",
          "The capability module could not be read or evaluated in the trusted compiler process.",
          candidate.source,
        ),
      );
    }
  }
  if (diagnostics.some((item) => item.severity === "error"))
    return freezeResult(config, [], diagnostics);

  const capabilities: DiscoveredCapability[] = [];
  for (const { candidate, bytes } of prepared) {
    let namespace: unknown;
    try {
      namespace = await loadFreshModule(candidate.absolute, generation);
    } catch (error) {
      if (error instanceof ModuleGraphLoadError && propagateLoaderErrors)
        throw error;
      if (error instanceof CapabilityDefinitionError) {
        for (const authoring of error.diagnostics)
          diagnostics.push(
            diagnostic(
              "module-load",
              authoring.code,
              "error",
              authoring.message,
              candidate.source,
              { pointer: authoring.path },
            ),
          );
      } else {
        diagnostics.push(
          diagnostic(
            "module-load",
            "CAP_DISCOVERY_MODULE_LOAD_FAILED",
            "error",
            "The capability module could not be read or evaluated in the trusted compiler process.",
            candidate.source,
          ),
        );
      }
      continue;
    }
    const descriptor = moduleDefault(namespace);
    if (!isCapability(descriptor)) {
      diagnostics.push(
        diagnostic(
          "module-export",
          "CAP_DISCOVERY_MODULE_EXPORT_INVALID",
          "error",
          "The capability module must default-export one descriptor created by this loaded @capaxle/core module.",
          candidate.source,
        ),
      );
      continue;
    }
    const explicitId = descriptor.id;
    if (explicitId !== undefined && !idPattern.test(explicitId)) {
      diagnostics.push(
        diagnostic(
          "identity",
          "CAP_DISCOVERY_ID_INVALID",
          "error",
          "The explicit capability ID must use lowercase dot-separated IR identifier segments.",
          candidate.source,
          { pointer: "/id" },
        ),
      );
      continue;
    }
    const id = explicitId ?? candidate.derivedId;
    if (
      explicitId !== undefined &&
      explicitId !== candidate.derivedId &&
      !config.allowIdOverride
    )
      diagnostics.push(
        diagnostic(
          "override",
          "CAP_DISCOVERY_ID_OVERRIDE",
          "warning",
          "The explicit capability ID differs from its path-derived ID; set discovery.allowIdOverride only for a reviewed migration.",
          candidate.source,
          { pointer: "/id" },
        ),
      );
    capabilities.push(
      freezeCapability(
        id,
        candidate.derivedId,
        descriptor,
        candidate.source,
        sourceHash(bytes),
      ),
    );
  }

  capabilities.sort(
    (left, right) =>
      compareText(left.id, right.id) ||
      compareText(left.source.file, right.source.file),
  );
  for (let start = 0; start < capabilities.length;) {
    let end = start + 1;
    while (
      end < capabilities.length &&
      capabilities[end]!.id === capabilities[start]!.id
    )
      end++;
    if (end - start > 1) {
      const group = capabilities.slice(start, end);
      diagnostics.push(
        diagnostic(
          "duplicate",
          "CAP_DISCOVERY_ID_DUPLICATE",
          "error",
          `Capability ID ${JSON.stringify(group[0]!.id)} is declared by multiple source modules.`,
          group[0]!.source,
          {
            related: group.slice(1).map((item) => ({
              message: "This source declares the same effective capability ID.",
              source: item.source,
            })),
          },
        ),
      );
    }
    start = end;
  }
  return freezeResult(config, capabilities, diagnostics);
}

export const discoveryHasErrors = (result: DiscoveryResult): boolean =>
  !result.ok;

export const successfulDiscovery = (
  result: DiscoveryResult,
): SuccessfulDiscoveryResult | undefined => (result.ok ? result : undefined);
