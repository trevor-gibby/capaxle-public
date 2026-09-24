import { randomBytes, createHash } from "node:crypto";
import { constants } from "node:fs";
import { hostname } from "node:os";
import {
  open,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  rmdir,
  lstat,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { jcs, type JsonValue } from "@capaxle/ir";
import {
  compilationDiagnostic,
  sortCompilationDiagnostics,
} from "./compilation-diagnostics.js";
import {
  COMPILER_VERSION,
  compilerSuccessAuthorization,
} from "./compiler-engine.js";
import {
  reservedOutputReason,
  outputNamespaceReason,
  readOutputVolumeProfile,
  validOutputDirectory,
  validateExistingOutputPrefix,
} from "./full-config.js";
import type {
  ArtifactIndexEntry,
  CompilationDiagnostic,
  CompilationSuccess,
  CompilerRootPublication,
  EmissionResult,
  RootPublicationBuildLocator,
  Sha256,
} from "./compilation-types.js";

const LOCK = ".capaxle-build.lock";
const LOCK_RECOVERY_AGE_MS = 30_000;
const sourceDefault = Object.freeze({ file: ".", line: 1, column: 1 });
const sha = (value: Uint8Array | string): Sha256 =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;
const pause = (ms: number) =>
  new Promise<void>((resolvePause) => setTimeout(resolvePause, ms));
const safeJson = (bytes: Uint8Array): unknown => {
  try {
    return JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    return undefined;
  }
};
const directoryPaths = new WeakMap<FileHandle, string>();
const directoryFlags =
  constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const at = (directory: FileHandle, name = "") =>
  name
    ? resolve(directoryPaths.get(directory)!, name)
    : directoryPaths.get(directory)!;

async function openDirectoryNoFollow(path: string): Promise<FileHandle> {
  const handle = await open(path, directoryFlags);
  const [entry, opened] = await Promise.all([lstat(path), handle.stat()]);
  if (
    entry.isSymbolicLink() ||
    !entry.isDirectory() ||
    !opened.isDirectory() ||
    entry.dev !== opened.dev ||
    entry.ino !== opened.ino
  ) {
    await handle.close();
    throw new Error("type");
  }
  directoryPaths.set(handle, resolve(path));
  return handle;
}

async function verifyDirectoryEntry(
  parent: FileHandle,
  name: string,
  child: FileHandle,
): Promise<void> {
  const [entry, opened] = await Promise.all([
    lstat(at(parent, name)),
    child.stat(),
  ]);
  if (
    entry.isSymbolicLink() ||
    !entry.isDirectory() ||
    entry.dev !== opened.dev ||
    entry.ino !== opened.ino
  )
    throw new Error("identity");
}

function issue(
  code: `CAP_${string}`,
  subphase: "emission-stage" | "emission-commit" | "emission-cleanup",
  message: string,
  source: CompilationDiagnostic["source"],
  path: string,
  details?: JsonValue,
  severity: "error" | "warning" = "error",
): CompilationDiagnostic {
  return compilationDiagnostic({
    code,
    severity,
    phase: "emission",
    subphase,
    message,
    source,
    path,
    ...(details === undefined ? {} : { details }),
  });
}
async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}
async function writeSynced(
  path: string,
  value: Uint8Array,
  flag: "wx" | "w" | number = constants.O_WRONLY |
    constants.O_CREAT |
    constants.O_EXCL |
    constants.O_NOFOLLOW,
): Promise<void> {
  const handle = await open(path, flag);
  try {
    await handle.writeFile(value);
    await handle.sync();
  } finally {
    await handle.close();
  }
}
async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function readSafeRelativeFile(
  root: string,
  relativePath: string,
): Promise<Uint8Array> {
  const components = relativePath.split("/");
  let cursor = root;
  for (let index = 0; index < components.length; index++) {
    cursor = resolve(cursor, components[index]!);
    const info = await lstat(cursor);
    if (info.isSymbolicLink()) throw new Error("symlink");
    if (index < components.length - 1) {
      if (!info.isDirectory()) throw new Error("type");
    } else if (!info.isFile()) throw new Error("type");
  }
  return readFile(cursor);
}

interface Owner {
  version: "0.1";
  outputDirectory: string;
  token: string;
  host: string;
  pid: number;
  processStart: string;
  createdAt: string;
  heartbeatAt: string;
  released: boolean;
}

interface ProjectLock {
  readonly token: string;
  readonly path: string;
  readonly handle: FileHandle;
  readonly projectRoot: FileHandle;
}

async function readRegularFileNoFollow(path: string): Promise<Uint8Array> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await handle.stat();
    if (!info.isFile()) throw new Error("type");
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

async function ownerAt(lockPath: string): Promise<Owner | undefined> {
  const value = safeJson(
    await readRegularFileNoFollow(resolve(lockPath, "owner.json")).catch(
      () => new Uint8Array(),
    ),
  );
  if (!value || typeof value !== "object") return undefined;
  const item = value as Partial<Owner>;
  return item.version === "0.1" &&
    typeof item.outputDirectory === "string" &&
    validOutputDirectory(item.outputDirectory) &&
    typeof item.token === "string" &&
    /^[0-9a-f]{32}$/.test(item.token) &&
    typeof item.host === "string" &&
    item.host.length > 0 &&
    Number.isSafeInteger(item.pid) &&
    (item.pid as number) > 0 &&
    typeof item.processStart === "string" &&
    item.processStart.length > 0 &&
    typeof item.createdAt === "string" &&
    Number.isFinite(Date.parse(item.createdAt)) &&
    typeof item.heartbeatAt === "string" &&
    Number.isFinite(Date.parse(item.heartbeatAt)) &&
    typeof item.released === "boolean"
    ? (item as Owner)
    : undefined;
}

async function verifyLockIdentity(lock: ProjectLock): Promise<boolean> {
  try {
    await verifyDirectoryEntry(lock.projectRoot, LOCK, lock.handle);
    return true;
  } catch {
    return false;
  }
}

async function removeKnownLockDirectory(
  projectRoot: FileHandle,
  lockPath: string,
): Promise<void> {
  const entries = await readdir(lockPath);
  if (entries.length !== 1 || entries[0] !== "owner.json")
    throw new Error("unknown-lock-entry");
  const releasedOwner = await readRegularFileNoFollow(
    resolve(lockPath, "owner.json"),
  );
  await unlink(resolve(lockPath, "owner.json"));
  try {
    await rmdir(lockPath);
  } catch (error) {
    await writeSynced(resolve(lockPath, "owner.json"), releasedOwner).catch(
      () => {},
    );
    await syncDirectory(lockPath).catch(() => {});
    throw error;
  }
  await syncDirectory(at(projectRoot));
}

async function acquireLock(
  projectRoot: FileHandle,
  outputDirectory: string,
  timeoutMs: number,
  recoveryBoundaryHook?: (boundary: string) => void | Promise<void>,
): Promise<
  | { readonly ok: true; readonly lock: ProjectLock }
  | { readonly ok: false; readonly reason: "timeout" | "access" }
> {
  const projectRootPath = at(projectRoot);
  const lockPath = resolve(projectRootPath, LOCK);
  const start = performance.now();
  while (true) {
    const token = randomBytes(16).toString("hex");
    let createdHandle: FileHandle | undefined;
    try {
      await mkdir(lockPath);
      createdHandle = await openDirectoryNoFollow(lockPath);
      await verifyDirectoryEntry(projectRoot, LOCK, createdHandle);
      const now = new Date().toISOString();
      const owner: Owner = {
        version: "0.1",
        outputDirectory,
        token,
        host: hostname(),
        pid: process.pid,
        processStart: String(Date.now() - Math.floor(process.uptime() * 1000)),
        createdAt: now,
        heartbeatAt: now,
        released: false,
      };
      await writeSynced(
        resolve(lockPath, "owner.json"),
        Buffer.from(jcs(owner as unknown as JsonValue)),
      );
      await syncDirectory(lockPath);
      await syncDirectory(projectRootPath);
      const lock = {
        token,
        path: lockPath,
        handle: createdHandle,
        projectRoot,
      } satisfies ProjectLock;
      if (!(await verifyLockIdentity(lock)) || !(await owns(lock))) {
        await createdHandle.close().catch(() => {});
        return { ok: false, reason: "access" };
      }
      return { ok: true, lock };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        await createdHandle?.close().catch(() => {});
        return { ok: false, reason: "access" };
      }
      let priorHandle: FileHandle | undefined;
      let prior: Owner | undefined;
      try {
        priorHandle = await openDirectoryNoFollow(lockPath);
        await verifyDirectoryEntry(projectRoot, LOCK, priorHandle);
        prior = await ownerAt(lockPath);
      } catch {
        prior = undefined;
      }
      const heartbeatTime = prior ? Date.parse(prior.heartbeatAt) : Number.NaN;
      const recoveryAge = Date.now() - heartbeatTime;
      if (
        prior?.released &&
        Number.isFinite(heartbeatTime) &&
        recoveryAge >= LOCK_RECOVERY_AGE_MS
      ) {
        const quarantine = resolve(
          projectRootPath,
          `${LOCK}.recovering-${prior.token}`,
        );
        try {
          await recoveryBoundaryHook?.("before-recovery-rename");
          await rename(lockPath, quarantine);
          if (!priorHandle) throw new Error("identity");
          const [quarantineEntry, opened] = await Promise.all([
            lstat(quarantine),
            priorHandle.stat(),
          ]);
          if (
            quarantineEntry.isSymbolicLink() ||
            !quarantineEntry.isDirectory() ||
            quarantineEntry.dev !== opened.dev ||
            quarantineEntry.ino !== opened.ino
          )
            throw new Error("identity");
          const reread = await ownerAt(quarantine);
          if (reread && reread.token === prior.token && reread.released) {
            await syncDirectory(projectRootPath);
            await removeKnownLockDirectory(projectRoot, quarantine);
            continue;
          }
          // The releasing owner may have removed owner.json between our first
          // read and quarantine rename. Never restore that now-unverifiable
          // directory to the live lock name; leave it quarantined and retry.
        } catch {
          /* wait without stealing */
        } finally {
          await priorHandle?.close().catch(() => {});
        }
      } else {
        await priorHandle?.close().catch(() => {});
      }
      if (performance.now() - start >= timeoutMs)
        return { ok: false, reason: "timeout" };
      await pause(Math.min(25, Math.max(1, timeoutMs)));
    }
  }
}
async function owns(lock: ProjectLock): Promise<boolean> {
  return (
    (await verifyLockIdentity(lock)) &&
    (await ownerAt(lock.path))?.token === lock.token
  );
}
async function heartbeat(lock: ProjectLock): Promise<boolean> {
  try {
    const owner = await ownerAt(lock.path);
    if (!owner || owner.token !== lock.token || owner.released) return false;
    const temp = resolve(lock.path, `owner.${lock.token}.heartbeat`);
    await writeSynced(
      temp,
      Buffer.from(
        jcs({
          ...owner,
          heartbeatAt: new Date().toISOString(),
        } as unknown as JsonValue),
      ),
    );
    await rename(temp, resolve(lock.path, "owner.json"));
    await syncDirectory(lock.path);
    return owns(lock);
  } catch {
    return false;
  }
}
async function release(
  lock: ProjectLock,
  boundaryHook?: (boundary: string) => void | Promise<void>,
): Promise<boolean> {
  try {
    await boundaryHook?.("before-lock-release");
    if (!(await verifyLockIdentity(lock))) return false;
    const owner = await ownerAt(lock.path);
    if (!owner || owner.token !== lock.token || owner.released) return false;
    const released = {
      ...owner,
      heartbeatAt: new Date().toISOString(),
      released: true,
    };
    const temp = resolve(lock.path, `owner.${lock.token}.tmp`);
    await writeSynced(temp, Buffer.from(jcs(released as unknown as JsonValue)));
    await rename(temp, resolve(lock.path, "owner.json"));
    await syncDirectory(lock.path);
    await boundaryHook?.("after-lock-released-marker");
    if (!(await verifyLockIdentity(lock))) return false;
    const durable = await ownerAt(lock.path);
    if (!durable || durable.token !== lock.token || !durable.released)
      return false;
    await boundaryHook?.("before-lock-directory-removal");
    if (!(await verifyLockIdentity(lock))) return false;
    await lock.handle.close();
    await removeKnownLockDirectory(lock.projectRoot, lock.path);
    await boundaryHook?.("after-lock-directory-removal");
    return true;
  } catch {
    return false;
  } finally {
    await lock.handle.close().catch(() => {});
  }
}

interface ParsedIndex {
  buildId: Sha256;
  irHash: string;
  artifacts: ArtifactIndexEntry[];
  [key: string]: unknown;
}
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ARTIFACT_TOKEN = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const SEMVER_PATTERN =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const TARGET_PATTERN = /^[A-Za-z0-9][!-~]{0,255}$/;
function validIJsonString(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}
const codePointCompare = (left: string, right: string): number => {
  const a = Array.from(left, (character) => character.codePointAt(0) ?? 0);
  const b = Array.from(right, (character) => character.codePointAt(0) ?? 0);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1)
    if (a[index] !== b[index]) return a[index]! - b[index]!;
  return a.length - b.length;
};
function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const keys = Object.keys(value).sort();
  return (
    keys.length === expected.length &&
    keys.every((key, index) => key === [...expected].sort()[index])
  );
}
function closedStringPair(
  value: unknown,
  first: string,
  second: string,
): value is Record<string, string> {
  const object = objectValue(value);
  return Boolean(
    object &&
    hasExactKeys(object, [first, second]) &&
    typeof object[first] === "string" &&
    typeof object[second] === "string",
  );
}
function validIndexEntry(value: unknown): value is ArtifactIndexEntry {
  const item = objectValue(value);
  return Boolean(
    item &&
    hasExactKeys(item, [
      "id",
      "irHash",
      "irVersion",
      "mediaType",
      "path",
      "producer",
      "service",
      "sha256",
      "target",
    ]) &&
    typeof item.id === "string" &&
    ARTIFACT_TOKEN.test(item.id) &&
    item.id !== "capaxle.artifact-index" &&
    typeof item.mediaType === "string" &&
    item.mediaType.length > 0 &&
    validIJsonString(item.mediaType) &&
    validGenerationPath(item.path) &&
    typeof item.target === "string" &&
    TARGET_PATTERN.test(item.target) &&
    item.irVersion === "0.1" &&
    typeof item.irHash === "string" &&
    SHA256_PATTERN.test(item.irHash) &&
    typeof item.sha256 === "string" &&
    SHA256_PATTERN.test(item.sha256) &&
    closedStringPair(item.service, "name", "version") &&
    closedStringPair(item.producer, "id", "version") &&
    ARTIFACT_TOKEN.test((item.producer as Record<string, string>).id!) &&
    SEMVER_PATTERN.test((item.producer as Record<string, string>).version!),
  );
}
function validClosedIndex(value: unknown): value is ParsedIndex {
  const index = objectValue(value);
  if (
    !index ||
    !hasExactKeys(index, [
      "artifactGraphVersion",
      "artifacts",
      "buildId",
      "compiler",
      "irHash",
      "irVersion",
      "service",
    ]) ||
    (index.artifactGraphVersion !== "0.1" &&
      index.artifactGraphVersion !== "0.2") ||
    index.irVersion !== "0.1" ||
    typeof index.buildId !== "string" ||
    !SHA256_PATTERN.test(index.buildId) ||
    typeof index.irHash !== "string" ||
    !SHA256_PATTERN.test(index.irHash) ||
    !closedStringPair(index.compiler, "name", "version") ||
    index.compiler.name !== "@capaxle/compiler" ||
    index.compiler.version !== COMPILER_VERSION ||
    !closedStringPair(index.service, "name", "version") ||
    !Array.isArray(index.artifacts) ||
    !index.artifacts.every(validIndexEntry)
  )
    return false;
  const artifacts = index.artifacts as ArtifactIndexEntry[];
  const service = index.service as Record<string, string>;
  if (
    artifacts.some(
      (entry, position) =>
        (position > 0 &&
          codePointCompare(artifacts[position - 1]!.id, entry.id) >= 0) ||
        entry.irHash !== index.irHash ||
        entry.service.name !== service.name ||
        entry.service.version !== service.version,
    )
  )
    return false;
  for (let left = 0; left < artifacts.length; left++)
    for (let right = left + 1; right < artifacts.length; right++) {
      const a = artifacts[left]!.path;
      const b = artifacts[right]!.path;
      if (a === b || a.startsWith(`${b}/`) || b.startsWith(`${a}/`))
        return false;
    }
  const builtins = new Map(artifacts.map((entry) => [entry.id, entry]));
  const ir = builtins.get("capaxle.ir");
  const registry = builtins.get("capaxle.compiler-registry");
  return Boolean(
    ir &&
    ir.path === "capabilities.ir.json" &&
    ir.mediaType === "application/json" &&
    ir.target === "capaxle:capability-ir@0.1" &&
    ir.producer.id === "capaxle.compiler" &&
    ir.producer.version === COMPILER_VERSION &&
    registry &&
    registry.path === "capabilities.registry.json" &&
    registry.mediaType === "application/json" &&
    registry.target === "capaxle:compiler-registry@0.1" &&
    registry.producer.id === "capaxle.compiler" &&
    registry.producer.version === COMPILER_VERSION,
  );
}
function validGenerationPath(path: unknown): path is string {
  return (
    typeof path === "string" &&
    path.length > 0 &&
    validIJsonString(path) &&
    !path.startsWith("/") &&
    !path.includes("\\") &&
    !path.includes("\0") &&
    path.split("/").every((part) => part && part !== "." && part !== "..")
  );
}
function objectValue(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

async function validateExistingCurrent(
  outputRoot: string,
): Promise<Sha256 | undefined | null> {
  const currentPath = resolve(outputRoot, "current.json");
  if (!(await exists(currentPath))) return undefined;
  try {
    const pointerBytes = await readSafeRelativeFile(outputRoot, "current.json");
    const pointer = objectValue(safeJson(pointerBytes));
    if (
      !pointer ||
      !hasExactKeys(pointer, [
        "artifactGraphVersion",
        "buildId",
        "index",
        "indexSha256",
        "irHash",
      ]) ||
      pointer.artifactGraphVersion !== "0.1" ||
      typeof pointer.buildId !== "string" ||
      !SHA256_PATTERN.test(pointer.buildId) ||
      typeof pointer.indexSha256 !== "string" ||
      !SHA256_PATTERN.test(pointer.indexSha256) ||
      typeof pointer.irHash !== "string" ||
      !SHA256_PATTERN.test(pointer.irHash) ||
      typeof pointer.index !== "string" ||
      pointer.index !== `generations/${pointer.buildId.slice(7)}/artifacts.json`
    )
      return null;
    if (
      Buffer.compare(
        Buffer.from(pointerBytes),
        Buffer.from(jcs(pointer as unknown as JsonValue)),
      ) !== 0
    )
      return null;
    const indexBytes = await readSafeRelativeFile(outputRoot, pointer.index);
    if (sha(indexBytes) !== pointer.indexSha256) return null;
    const index = safeJson(indexBytes);
    if (
      !validClosedIndex(index) ||
      index.artifactGraphVersion !== "0.1" ||
      index.buildId !== pointer.buildId ||
      index.irHash !== pointer.irHash ||
      Buffer.compare(
        Buffer.from(indexBytes),
        Buffer.from(jcs(index as unknown as JsonValue)),
      ) !== 0
    )
      return null;
    const { buildId, ...preimage } = index;
    if (sha(jcs(preimage as JsonValue)) !== buildId) return null;
    for (const item of index.artifacts)
      if (
        !validGenerationPath(item.path) ||
        sha(
          await readSafeRelativeFile(
            outputRoot,
            `generations/${pointer.buildId.slice(7)}/${item.path}`,
          ),
        ) !== item.sha256
      )
        return null;
    return pointer.buildId as Sha256;
  } catch {
    return null;
  }
}

function validateCompilation(
  compilation: CompilationSuccess,
):
  | { buildId: Sha256; index: ParsedIndex; artifacts: Map<string, Uint8Array> }
  | undefined {
  const authorization = compilerSuccessAuthorization(compilation);
  if (!authorization?.current || !compilation.ok) return undefined;
  const artifacts = new Map<string, Uint8Array>();
  for (const item of compilation.artifacts) {
    const value = item.bytes;
    if (
      !(value instanceof Uint8Array) ||
      sha(value) !== item.sha256 ||
      artifacts.has(item.id)
    )
      return undefined;
    artifacts.set(item.id, new Uint8Array(value));
  }
  if (
    sha(compilation.irBytes) !==
    compilation.artifacts.find((item) => item.id === "capaxle.ir")?.sha256
  )
    return undefined;
  const indexBytes = artifacts.get("capaxle.artifact-index");
  if (!indexBytes) return undefined;
  const index = safeJson(indexBytes);
  const expectedGraphVersion = compilation.rootPublication ? "0.2" : "0.1";
  if (
    !validClosedIndex(index) ||
    index.artifactGraphVersion !== expectedGraphVersion ||
    Buffer.compare(
      Buffer.from(indexBytes),
      Buffer.from(jcs(index as unknown as JsonValue)),
    ) !== 0
  )
    return undefined;
  const { buildId, ...preimage } = index;
  if (sha(jcs(preimage as JsonValue)) !== buildId) return undefined;
  for (const entry of index.artifacts) {
    const item = compilation.artifacts.find(
      (candidate) => candidate.id === entry.id,
    );
    if (
      !item ||
      !validGenerationPath(entry.path) ||
      item.path !== entry.path ||
      item.sha256 !== entry.sha256 ||
      item.mediaType !== entry.mediaType ||
      item.target !== entry.target ||
      !artifacts.has(entry.id)
    )
      return undefined;
  }
  return { buildId, index, artifacts };
}

type RootEntryState =
  | { readonly kind: "missing" }
  | {
      readonly kind: "file";
      readonly device: bigint;
      readonly inode: bigint;
      readonly digest: Sha256;
    }
  | {
      readonly kind: "invalid";
      readonly reason: "inaccessible" | "symlink" | "non-regular";
    };

async function rootEntryState(path: string): Promise<RootEntryState> {
  try {
    const lexical = await lstat(path, { bigint: true });
    if (lexical.isSymbolicLink()) return { kind: "invalid", reason: "symlink" };
    if (!lexical.isFile()) return { kind: "invalid", reason: "non-regular" };
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const opened = await handle.stat({ bigint: true });
      if (
        !opened.isFile() ||
        opened.dev !== lexical.dev ||
        opened.ino !== lexical.ino
      )
        return { kind: "invalid", reason: "inaccessible" };
      return {
        kind: "file",
        device: lexical.dev,
        inode: lexical.ino,
        digest: sha(await handle.readFile()),
      };
    } finally {
      await handle.close();
    }
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT"
      ? { kind: "missing" }
      : { kind: "invalid", reason: "inaccessible" };
  }
}

function sameRootEntry(left: RootEntryState, right: RootEntryState): boolean {
  return left.kind === "missing"
    ? right.kind === "missing"
    : left.kind === "file" && right.kind === "file"
      ? left.device === right.device &&
        left.inode === right.inode &&
        left.digest === right.digest
      : false;
}

function validRootBuild(value: unknown): value is RootPublicationBuildLocator {
  const build = objectValue(value);
  return Boolean(
    build &&
    hasExactKeys(build, [
      "artifactGraphVersion",
      "buildId",
      "index",
      "indexSha256",
      "payloadArtifactId",
      "payloadSha256",
    ]) &&
    build.artifactGraphVersion === "0.2" &&
    typeof build.buildId === "string" &&
    SHA256_PATTERN.test(build.buildId) &&
    typeof build.index === "string" &&
    validGenerationPath(build.index) &&
    typeof build.indexSha256 === "string" &&
    SHA256_PATTERN.test(build.indexSha256) &&
    typeof build.payloadArtifactId === "string" &&
    ARTIFACT_TOKEN.test(build.payloadArtifactId) &&
    typeof build.payloadSha256 === "string" &&
    SHA256_PATTERN.test(build.payloadSha256),
  );
}

async function validateExistingRootPublication(
  projectRoot: string,
  output: string,
  publication: CompilerRootPublication,
  expectedPayload: Pick<
    ArtifactIndexEntry,
    "id" | "path" | "mediaType" | "target"
  >,
): Promise<Sha256 | undefined | null> {
  const rootPath = resolve(projectRoot, publication.rootPath);
  if (!(await exists(rootPath))) return undefined;
  try {
    const rootBytes = await readRegularFileNoFollow(rootPath);
    const root = objectValue(safeJson(rootBytes));
    if (!root || !Object.hasOwn(root, "build") || !validRootBuild(root.build))
      return null;
    const build = root.build;
    const expectedIndex = `${output}/generations/${build.buildId.slice(7)}/artifacts.json`;
    if (
      build.index !== expectedIndex ||
      build.payloadArtifactId !== publication.payloadArtifactId ||
      Buffer.compare(
        Buffer.from(rootBytes),
        Buffer.from(jcs(root as JsonValue)),
      ) !== 0
    )
      return null;
    const indexBytes = await readSafeRelativeFile(projectRoot, build.index);
    const index = safeJson(indexBytes);
    if (
      sha(indexBytes) !== build.indexSha256 ||
      !validClosedIndex(index) ||
      index.artifactGraphVersion !== "0.2" ||
      index.buildId !== build.buildId ||
      Buffer.compare(
        Buffer.from(indexBytes),
        Buffer.from(jcs(index as unknown as JsonValue)),
      ) !== 0
    )
      return null;
    const { buildId, ...preimage } = index;
    if (sha(jcs(preimage as JsonValue)) !== buildId) return null;
    const payloadEntry = index.artifacts.find(
      (entry) => entry.id === publication.payloadArtifactId,
    );
    if (
      !payloadEntry ||
      payloadEntry.id !== expectedPayload.id ||
      payloadEntry.path !== expectedPayload.path ||
      payloadEntry.mediaType !== expectedPayload.mediaType ||
      payloadEntry.target !== expectedPayload.target ||
      payloadEntry.irHash !== index.irHash ||
      payloadEntry.sha256 !== build.payloadSha256
    )
      return null;
    const generationRoot = `${output}/generations/${build.buildId.slice(7)}`;
    for (const item of index.artifacts)
      if (
        sha(
          await readSafeRelativeFile(
            projectRoot,
            `${generationRoot}/${item.path}`,
          ),
        ) !== item.sha256
      )
        return null;
    const payloadBytes = await readSafeRelativeFile(
      projectRoot,
      `${generationRoot}/${payloadEntry.path}`,
    );
    if (sha(payloadBytes) !== payloadEntry.sha256) return null;
    const assembled = await publication.assemble(
      Object.freeze({
        payload: new Uint8Array(payloadBytes),
        build: Object.freeze({ ...build }),
      }),
    );
    if (
      !(assembled instanceof Uint8Array) ||
      Buffer.compare(Buffer.from(assembled), Buffer.from(rootBytes)) !== 0
    )
      return null;
    return build.buildId;
  } catch {
    return null;
  }
}

async function invalidRootPublicationReason(
  projectRoot: string,
  publication: CompilerRootPublication,
): Promise<"invalid-json" | "version" | "unowned"> {
  try {
    const bytes = await readRegularFileNoFollow(
      resolve(projectRoot, publication.rootPath),
    );
    const parsed = safeJson(bytes);
    if (parsed === undefined) return "invalid-json";
    const root = objectValue(parsed);
    if (
      !root ||
      (objectValue(root.build)?.artifactGraphVersion !== undefined &&
        objectValue(root.build)?.artifactGraphVersion !== "0.2")
    )
      return "version";
    return "unowned";
  } catch {
    return "unowned";
  }
}

async function migrationLocatorFromRoot(
  projectRoot: string,
  output: string,
  publication: CompilerRootPublication,
  expectedPayload: Pick<
    ArtifactIndexEntry,
    "id" | "path" | "mediaType" | "target"
  >,
  expectedCanonical: RootEntryState,
): Promise<JsonValue | undefined> {
  try {
    const beforeCanonical = await rootEntryState(
      resolve(projectRoot, publication.rootPath),
    );
    if (
      !sameRootEntry(expectedCanonical, beforeCanonical) ||
      (await rootEntryState(resolve(projectRoot, publication.legacyPath)))
        .kind !== "missing"
    )
      return undefined;
    const root = objectValue(
      safeJson(
        await readRegularFileNoFollow(
          resolve(projectRoot, publication.rootPath),
        ),
      ),
    );
    if (!root || !validRootBuild(root.build)) return undefined;
    const indexBytes = await readSafeRelativeFile(
      projectRoot,
      root.build.index,
    );
    const index = objectValue(safeJson(indexBytes));
    if (
      !index ||
      sha(indexBytes) !== root.build.indexSha256 ||
      !validClosedIndex(index) ||
      index.artifactGraphVersion !== "0.2" ||
      index.buildId !== root.build.buildId ||
      typeof index.irHash !== "string" ||
      !SHA256_PATTERN.test(index.irHash) ||
      Buffer.compare(
        Buffer.from(indexBytes),
        Buffer.from(jcs(index as JsonValue)),
      ) !== 0
    )
      return undefined;
    const { buildId, ...preimage } = index;
    if (sha(jcs(preimage as JsonValue)) !== buildId) return undefined;
    const relativeIndex = root.build.index.startsWith(`${output}/`)
      ? root.build.index.slice(output.length + 1)
      : undefined;
    if (!relativeIndex) return undefined;
    const locator = {
      artifactGraphVersion: "0.2",
      buildId: root.build.buildId,
      index: relativeIndex,
      indexSha256: root.build.indexSha256,
      irHash: index.irHash,
    };
    if (
      (await validateExistingRootPublication(
        projectRoot,
        output,
        publication,
        expectedPayload,
      )) !== root.build.buildId
    )
      return undefined;
    const afterCanonical = await rootEntryState(
      resolve(projectRoot, publication.rootPath),
    );
    if (
      !sameRootEntry(expectedCanonical, afterCanonical) ||
      (await rootEntryState(resolve(projectRoot, publication.legacyPath)))
        .kind !== "missing"
    )
      return undefined;
    return locator;
  } catch {
    return undefined;
  }
}

function legacyManifestIssue(
  legacyPath: string,
  canonicalPath: string,
  canonicalExists: boolean,
): CompilationDiagnostic {
  const reason = canonicalExists ? "name-conflict" : "legacy-only";
  return compilationDiagnostic({
    code: "CAP_MANIFEST_LEGACY_NAME",
    severity: "error",
    phase: "emission",
    subphase: "emission-stage",
    message: canonicalExists
      ? `Canonical and legacy manifest paths both exist; only ${JSON.stringify(canonicalPath)} may be canonical.`
      : `Legacy manifest ${JSON.stringify(legacyPath)} is unsupported; regenerate ${JSON.stringify(canonicalPath)} from the current Capability IR.`,
    path: "/manifest",
    source: { file: legacyPath, line: 1, column: 1 },
    remediation:
      "Update consumers to the canonical manifest, regenerate and verify it, then manually archive or remove the legacy file; Capaxle will not modify the legacy file.",
    details: { reason, legacyPath, canonicalPath },
  });
}

function invalidManifestIssue(
  canonicalPath: string,
  reason:
    | "inaccessible"
    | "symlink"
    | "non-regular"
    | "invalid-json"
    | "version"
    | "unowned"
    | "identity-changed",
): CompilationDiagnostic {
  return compilationDiagnostic({
    code: "CAP_MANIFEST_PATH_INVALID",
    severity: "error",
    phase: "emission",
    subphase: "emission-stage",
    message:
      "The canonical manifest path is not a verified Capaxle-generated regular file and was not modified.",
    path: "/manifest",
    source: { file: canonicalPath, line: 1, column: 1 },
    remediation:
      "Move the unverified entry aside manually, verify the project root, and rerun generation; Capaxle will not overwrite or delete it.",
    details: { reason, canonicalPath },
  });
}

export async function emitCompilerArtifacts(options: {
  readonly projectRoot: string;
  readonly compilation: CompilationSuccess;
  readonly outputDirectory?: string;
  readonly outputDiagnosticSource?: {
    readonly kind: "command-option";
    readonly command: "build";
    readonly option: "--output";
    readonly argumentIndex: number;
  };
  readonly lockTimeoutMs?: number;
}): Promise<EmissionResult> {
  if (!isAbsolute(options.projectRoot))
    throw new TypeError("projectRoot must be an absolute filesystem path.");
  const direct = options.outputDirectory !== undefined;
  const cliSource = options.outputDiagnosticSource;
  const auth = compilerSuccessAuthorization(options.compilation);
  const source = cliSource
    ? { file: ".", line: 1, column: cliSource.argumentIndex + 1 }
    : !direct && auth?.outputExplicit
      ? auth.outputSource
      : sourceDefault;
  const path = cliSource
    ? "/command/options/output"
    : direct
      ? "/outputDirectory"
      : "/compiler/outputDirectory";
  const diagnostics: CompilationDiagnostic[] = [];
  let freezeFailuresImmediately = true;
  let deferredFailure:
    | (Record<string, unknown> & {
        diagnostics: readonly CompilationDiagnostic[];
      })
    | undefined;
  const fail = (
    code: `CAP_${string}`,
    subphase: "emission-stage" | "emission-commit",
    message: string,
    details?: JsonValue,
    extras: Partial<Extract<EmissionResult, { ok: false }>> = {},
  ): EmissionResult => {
    const result = {
      ok: false,
      status: "not-committed",
      durable: false,
      ...extras,
      diagnostics: sortCompilationDiagnostics([
        ...diagnostics,
        issue(code, subphase, message, source, path, details),
      ]),
    };
    if (freezeFailuresImmediately)
      return Object.freeze(result) as EmissionResult;
    deferredFailure = result;
    return result as EmissionResult;
  };
  if (!auth || !auth.current || auth.projectRoot !== options.projectRoot)
    return fail(
      "CAP_BUILD_RESULT_INVALID",
      "emission-stage",
      "Compilation result is stale, foreign, failed, or not compiler-authentic.",
    );
  if (
    cliSource &&
    (!direct ||
      cliSource.kind !== "command-option" ||
      cliSource.command !== "build" ||
      cliSource.option !== "--output" ||
      !Number.isSafeInteger(cliSource.argumentIndex) ||
      cliSource.argumentIndex < 0)
  )
    return fail(
      "CAP_BUILD_RESULT_INVALID",
      "emission-stage",
      "Output diagnostic provenance is invalid.",
    );
  const lockTimeoutMs = options.lockTimeoutMs ?? 30_000;
  if (
    !Number.isInteger(lockTimeoutMs) ||
    lockTimeoutMs < 0 ||
    lockTimeoutMs > 300_000
  )
    return fail(
      "CAP_BUILD_RESULT_INVALID",
      "emission-stage",
      "Lock timeout is invalid.",
    );
  const output = options.outputDirectory ?? auth.outputDirectory;
  if (
    (process.platform !== "darwin" && process.platform !== "linux") ||
    constants.O_DIRECTORY === undefined ||
    constants.O_NOFOLLOW === undefined
  )
    return fail(
      "CAP_CONFIG_OUTPUT_INVALID",
      "emission-stage",
      "This platform cannot prove the portable artifact-emission baseline.",
      { reason: "namespace-disjointness-unproven" },
    );
  if (!validOutputDirectory(output))
    return fail(
      "CAP_CONFIG_OUTPUT_INVALID",
      "emission-stage",
      "Output directory selection is invalid.",
      { reason: "format" },
    );
  const reserved = reservedOutputReason(output);
  if (reserved)
    return fail(
      "CAP_CONFIG_OUTPUT_INVALID",
      "emission-stage",
      "Output directory conflicts with a reserved build namespace.",
      { reason: reserved },
    );
  let projectRootHandle: FileHandle;
  try {
    projectRootHandle = await openDirectoryNoFollow(options.projectRoot);
    const lexical = await lstat(options.projectRoot);
    const opened = await projectRootHandle.stat();
    if (
      lexical.isSymbolicLink() ||
      lexical.dev !== opened.dev ||
      lexical.ino !== opened.ino
    )
      throw new Error();
  } catch {
    return fail(
      "CAP_CONFIG_OUTPUT_INVALID",
      "emission-stage",
      "Project-root volume identity and output namespace disjointness could not be proven.",
      { reason: "namespace-disjointness-unproven" },
    );
  }
  const openedDirectories: FileHandle[] = [projectRootHandle];
  const openedEntries: Array<{
    parent: FileHandle;
    name: string;
    child: FileHandle;
  }> = [];
  const verifyProjectRootIdentity = async (): Promise<boolean> => {
    try {
      const [projectEntry, projectOpened] = await Promise.all([
        lstat(options.projectRoot),
        projectRootHandle.stat(),
      ]);
      return (
        !projectEntry.isSymbolicLink() &&
        projectEntry.isDirectory() &&
        projectEntry.dev === projectOpened.dev &&
        projectEntry.ino === projectOpened.ino
      );
    } catch {
      return false;
    }
  };
  const verifyOpenedEntries = async (): Promise<boolean> => {
    try {
      if (!(await verifyProjectRootIdentity())) return false;
      for (const entry of openedEntries)
        await verifyDirectoryEntry(entry.parent, entry.name, entry.child);
      return true;
    } catch {
      return false;
    }
  };
  const boundaryHook = (
    options as typeof options & {
      readonly [key: symbol]:
        ((boundary: string) => void | Promise<void>) | undefined;
    }
  )[Symbol.for("@capaxle/compiler/test-transaction-boundary@1")];
  const anchoredProjectRoot = at(projectRootHandle);
  const openedProjectRoot = await projectRootHandle.stat({ bigint: true });
  const namespaceReason = await outputNamespaceReason(
    anchoredProjectRoot,
    output,
    { device: openedProjectRoot.dev, inode: openedProjectRoot.ino },
  );
  if (namespaceReason) {
    await projectRootHandle.close();
    return fail(
      "CAP_CONFIG_OUTPUT_INVALID",
      "emission-stage",
      "Output directory namespace disjointness could not be proven.",
      { reason: namespaceReason },
    );
  }
  const prefixError = await validateExistingOutputPrefix(
    anchoredProjectRoot,
    output,
  );
  if (prefixError) {
    await projectRootHandle.close();
    return fail(
      "CAP_CONFIG_OUTPUT_INVALID",
      "emission-stage",
      "Output directory ancestry is invalid.",
      { reason: prefixError },
    );
  }
  const outputVolumeProfile = await readOutputVolumeProfile(
    anchoredProjectRoot,
    output,
  );
  const outputVolumeProfileHook = (
    options as typeof options & {
      readonly [key: symbol]:
        ((profile: unknown) => boolean | void) | undefined;
    }
  )[Symbol.for("@capaxle/compiler/test-output-volume-profile@1")];
  if (
    !outputVolumeProfile ||
    outputVolumeProfileHook?.(outputVolumeProfile) === false
  ) {
    await projectRootHandle.close();
    return fail(
      "CAP_CONFIG_OUTPUT_INVALID",
      "emission-stage",
      "Output volume cannot prove the required naming, atomic-replacement, and durability profile.",
      { reason: "namespace-disjointness-unproven" },
    );
  }
  const validated = validateCompilation(options.compilation);
  if (!validated) {
    await projectRootHandle.close();
    return fail(
      "CAP_BUILD_RESULT_INVALID",
      "emission-stage",
      "Compilation artifacts failed identity or byte verification.",
    );
  }
  const publication = options.compilation.rootPublication;
  let initialCanonical: RootEntryState | undefined;
  let assembledRoot: Uint8Array | undefined;
  let publicationPayloadEntry: ArtifactIndexEntry | undefined;
  if (publication) {
    const payloadEntry = validated.index.artifacts.find(
      (entry) => entry.id === publication.payloadArtifactId,
    );
    const payloadBytes = validated.artifacts.get(publication.payloadArtifactId);
    if (!payloadEntry || !payloadBytes) {
      await projectRootHandle.close();
      return fail(
        "CAP_BUILD_RESULT_INVALID",
        "emission-stage",
        "Root publication payload is absent from the validated artifact index.",
      );
    }
    publicationPayloadEntry = payloadEntry;
    const canonicalAbsolute = resolve(
      options.projectRoot,
      publication.rootPath,
    );
    const legacyAbsolute = resolve(options.projectRoot, publication.legacyPath);
    const [canonicalState, legacyState] = await Promise.all([
      rootEntryState(canonicalAbsolute),
      rootEntryState(legacyAbsolute),
    ]);
    initialCanonical = canonicalState;
    if (legacyState.kind !== "missing") {
      await projectRootHandle.close();
      return Object.freeze({
        ok: false,
        status: "not-committed",
        durable: false,
        diagnostics: sortCompilationDiagnostics([
          legacyManifestIssue(
            publication.legacyPath,
            publication.rootPath,
            canonicalState.kind !== "missing",
          ),
        ]),
      });
    }
    if (canonicalState.kind === "invalid") {
      await projectRootHandle.close();
      return Object.freeze({
        ok: false,
        status: "not-committed",
        durable: false,
        diagnostics: sortCompilationDiagnostics([
          invalidManifestIssue(publication.rootPath, canonicalState.reason),
        ]),
      });
    }
    if (
      canonicalState.kind === "file" &&
      (await validateExistingRootPublication(
        options.projectRoot,
        output,
        publication,
        payloadEntry,
      )) === null
    ) {
      const reason = await invalidRootPublicationReason(
        options.projectRoot,
        publication,
      );
      await projectRootHandle.close();
      return Object.freeze({
        ok: false,
        status: "not-committed",
        durable: false,
        diagnostics: sortCompilationDiagnostics([
          invalidManifestIssue(publication.rootPath, reason),
        ]),
      });
    }
    const locator = Object.freeze({
      artifactGraphVersion: "0.2" as const,
      buildId: validated.buildId,
      index: `${output}/generations/${validated.buildId.slice(7)}/artifacts.json`,
      indexSha256: sha(validated.artifacts.get("capaxle.artifact-index")!),
      payloadArtifactId: publication.payloadArtifactId,
      payloadSha256: payloadEntry.sha256,
    });
    try {
      const payload = objectValue(safeJson(payloadBytes));
      if (
        !payload ||
        Object.hasOwn(payload, "build") ||
        Buffer.compare(
          Buffer.from(payloadBytes),
          Buffer.from(jcs(payload as JsonValue)),
        ) !== 0
      )
        throw new Error("payload");
      const assembled = await publication.assemble(
        Object.freeze({
          payload: new Uint8Array(payloadBytes),
          build: locator,
        }),
      );
      if (!(assembled instanceof Uint8Array)) throw new Error("result");
      const root = objectValue(safeJson(assembled));
      const expected = { ...payload, build: locator };
      if (
        !root ||
        Buffer.compare(
          Buffer.from(assembled),
          Buffer.from(jcs(expected as JsonValue)),
        ) !== 0
      )
        throw new Error("bytes");
      assembledRoot = new Uint8Array(assembled);
    } catch {
      await projectRootHandle.close();
      return fail(
        "CAP_BUILD_RESULT_INVALID",
        "emission-stage",
        "Root publication assembler returned invalid or non-equivalent bytes.",
      );
    }
  }
  const recoveryBoundaryHook = (
    options as typeof options & {
      readonly [key: symbol]:
        ((boundary: string) => void | Promise<void>) | undefined;
    }
  )[Symbol.for("@capaxle/compiler/test-lock-recovery-boundary@1")];
  const acquired = await acquireLock(
    projectRootHandle,
    output,
    lockTimeoutMs,
    recoveryBoundaryHook,
  );
  if (!acquired.ok) {
    await projectRootHandle.close();
    return fail(
      acquired.reason === "timeout"
        ? "CAP_BUILD_LOCK_TIMEOUT"
        : "CAP_BUILD_LOCK_LOST",
      "emission-commit",
      acquired.reason === "timeout"
        ? "Project build lock could not be acquired before the timeout."
        : "Project build lock could not be established safely.",
      acquired.reason === "timeout" ? { timeoutMs: lockTimeoutMs } : undefined,
    );
  }
  const lock = acquired.lock;
  freezeFailuresImmediately = false;
  let heartbeatLost = false;
  let heartbeatStopped = false;
  let heartbeatWork = Promise.resolve(true);
  const queueHeartbeat = () => {
    heartbeatWork = heartbeatWork.then(async (prior) => {
      if (!prior || heartbeatStopped) return prior;
      const owned = await heartbeat(lock);
      if (!owned) heartbeatLost = true;
      return owned;
    });
    return heartbeatWork;
  };
  const heartbeatTimer = setInterval(() => {
    void queueHeartbeat();
  }, 4_000);
  heartbeatTimer.unref();
  const stopHeartbeat = async (): Promise<void> => {
    heartbeatStopped = true;
    clearInterval(heartbeatTimer);
    await heartbeatWork.catch(() => false);
  };
  const maintainLock = async (): Promise<boolean> => {
    await heartbeatWork;
    return !heartbeatLost && (await heartbeat(lock));
  };
  const attemptedBuildId = validated.buildId;
  const failureAfterLock = (
    result: Extract<EmissionResult, { ok: false }>,
  ): EmissionResult => {
    deferredFailure = result as Extract<EmissionResult, { ok: false }> &
      Record<string, unknown>;
    return result;
  };
  const transactionBoundary = async (
    boundary: string,
  ): Promise<"project-root" | "ancestry" | "lock" | undefined> => {
    await boundaryHook?.(boundary);
    if (!(await verifyProjectRootIdentity())) return "project-root";
    if (!(await verifyOpenedEntries())) return "ancestry";
    return (await maintainLock()) ? undefined : "lock";
  };
  const boundaryFailure = (
    boundary: string,
    reason: "project-root" | "ancestry" | "lock",
  ): EmissionResult => {
    if (publication && reason === "project-root") {
      if (!committed)
        return failureAfterLock({
          ok: false,
          status: "not-committed",
          durable: false,
          attemptedBuildId,
          diagnostics: sortCompilationDiagnostics([
            invalidManifestIssue(publication.rootPath, "identity-changed"),
          ]),
        });
      return failureAfterLock({
        ok: false,
        status: "commit-uncertain",
        durable: false,
        attemptedBuildId,
        diagnostics: sortCompilationDiagnostics([
          issue(
            "CAP_BUILD_COMMIT_UNCERTAIN",
            "emission-commit",
            "Project-root identity changed after manifest replacement.",
            source,
            path,
            { boundary: "manifest-identity" },
          ),
        ]),
      });
    }
    if (committed)
      return failureAfterLock({
        ok: false,
        status: "commit-uncertain",
        durable: false,
        attemptedBuildId,
        diagnostics: sortCompilationDiagnostics([
          issue(
            "CAP_BUILD_COMMIT_UNCERTAIN",
            "emission-commit",
            "Emission authority changed after pointer replacement.",
            source,
            path,
          ),
        ]),
      });
    return fail(
      reason === "ancestry" || reason === "project-root"
        ? "CAP_BUILD_ANCESTRY_FAILED"
        : "CAP_BUILD_LOCK_LOST",
      reason === "ancestry" || reason === "project-root"
        ? "emission-stage"
        : "emission-commit",
      reason === "ancestry" || reason === "project-root"
        ? "Opened output ancestry changed at an emission transaction boundary."
        : "Project build lock ownership was lost at an emission transaction boundary.",
      reason === "ancestry" || reason === "project-root"
        ? { componentIndex: output.split("/").length, reason: "recheck" }
        : undefined,
      { attemptedBuildId },
    );
  };
  let committed = false;
  let durable = false;
  let observedBuildId: Sha256 | undefined;
  let rootTemporary:
    { readonly path: string; readonly state: RootEntryState } | undefined;
  try {
    if (publication) {
      const [lockedCanonical, lockedLegacy] = await Promise.all([
        rootEntryState(resolve(options.projectRoot, publication.rootPath)),
        rootEntryState(resolve(options.projectRoot, publication.legacyPath)),
      ]);
      if (lockedLegacy.kind !== "missing")
        return failureAfterLock({
          ok: false,
          status: "not-committed",
          durable: false,
          diagnostics: sortCompilationDiagnostics([
            legacyManifestIssue(
              publication.legacyPath,
              publication.rootPath,
              lockedCanonical.kind !== "missing",
            ),
          ]),
        });
      if (lockedCanonical.kind === "invalid")
        return failureAfterLock({
          ok: false,
          status: "not-committed",
          durable: false,
          diagnostics: sortCompilationDiagnostics([
            invalidManifestIssue(publication.rootPath, lockedCanonical.reason),
          ]),
        });
      if (!(await verifyProjectRootIdentity()))
        return failureAfterLock({
          ok: false,
          status: "not-committed",
          durable: false,
          diagnostics: sortCompilationDiagnostics([
            invalidManifestIssue(publication.rootPath, "identity-changed"),
          ]),
        });
      if (lockedCanonical.kind === "file") {
        const lockedAuthority = await validateExistingRootPublication(
          options.projectRoot,
          output,
          publication,
          publicationPayloadEntry!,
        );
        if (lockedAuthority === null) {
          return failureAfterLock({
            ok: false,
            status: "not-committed",
            durable: false,
            diagnostics: sortCompilationDiagnostics([
              invalidManifestIssue(
                publication.rootPath,
                await invalidRootPublicationReason(
                  options.projectRoot,
                  publication,
                ),
              ),
            ]),
          });
        }
      }
      initialCanonical = lockedCanonical;
    }
    const beforeAncestry = await transactionBoundary(
      "before-output-ancestry-mutation",
    );
    if (beforeAncestry)
      return boundaryFailure("before-output-ancestry-mutation", beforeAncestry);
    const components = output.split("/");
    let parentHandle = projectRootHandle;
    for (let index = 0; index < components.length; index++) {
      const name = components[index]!;
      const childPath = at(parentHandle, name);
      let created = false;
      if (!(await exists(childPath))) {
        try {
          const beforeComponent = await transactionBoundary(
            `before-output-component-${index}`,
          );
          if (beforeComponent)
            return boundaryFailure(
              `before-output-component-${index}`,
              beforeComponent,
            );
          await mkdir(childPath);
          created = true;
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST")
            return fail(
              "CAP_BUILD_ANCESTRY_FAILED",
              "emission-stage",
              "Output directory ancestry could not be established durably.",
              { componentIndex: index, reason: "create" },
              { attemptedBuildId },
            );
        }
      }
      let child: FileHandle;
      try {
        child = await openDirectoryNoFollow(childPath);
        await verifyDirectoryEntry(parentHandle, name, child);
        if (created) await syncDirectory(at(parentHandle));
        openedDirectories.push(child);
        openedEntries.push({ parent: parentHandle, name, child });
      } catch (error) {
        const reason =
          created && (error as Error).message !== "type"
            ? "parent-fsync"
            : "type";
        return fail(
          "CAP_BUILD_ANCESTRY_FAILED",
          "emission-stage",
          "Output directory ancestry type or durability is invalid.",
          { componentIndex: index, reason },
          { attemptedBuildId },
        );
      }
      if (created) {
        const afterComponent = await transactionBoundary(
          `after-output-component-${index}`,
        );
        if (afterComponent)
          return boundaryFailure(
            `after-output-component-${index}`,
            afterComponent,
          );
      }
      parentHandle = child;
    }
    const outputHandle = parentHandle;
    const outputRoot = at(outputHandle);
    const generationsPath = at(outputHandle, "generations");
    let generationsCreated = false;
    if (!(await exists(generationsPath))) {
      try {
        const beforeGenerations = await transactionBoundary(
          "before-generations-directory",
        );
        if (beforeGenerations)
          return boundaryFailure(
            "before-generations-directory",
            beforeGenerations,
          );
        await mkdir(generationsPath);
        generationsCreated = true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") {
          generationsCreated = false;
        } else {
          return fail(
            "CAP_BUILD_ANCESTRY_FAILED",
            "emission-stage",
            "Generation directory ancestry could not be established durably.",
            { componentIndex: components.length, reason: "create" },
            { attemptedBuildId },
          );
        }
      }
    }
    let generationsHandle: FileHandle;
    try {
      generationsHandle = await openDirectoryNoFollow(generationsPath);
      await verifyDirectoryEntry(
        outputHandle,
        "generations",
        generationsHandle,
      );
      if (generationsCreated) await syncDirectory(outputRoot);
      openedDirectories.push(generationsHandle);
      openedEntries.push({
        parent: outputHandle,
        name: "generations",
        child: generationsHandle,
      });
    } catch (error) {
      const reason =
        generationsCreated && (error as Error).message !== "type"
          ? "parent-fsync"
          : "type";
      return fail(
        "CAP_BUILD_ANCESTRY_FAILED",
        "emission-stage",
        "Generation directory ancestry type or durability is invalid.",
        { componentIndex: components.length, reason },
        { attemptedBuildId },
      );
    }
    if (generationsCreated) {
      const afterGenerations = await transactionBoundary(
        "after-generations-directory",
      );
      if (afterGenerations)
        return boundaryFailure("after-generations-directory", afterGenerations);
    }
    const generations = at(generationsHandle);
    const afterAncestry = await transactionBoundary(
      "after-output-ancestry-mutation",
    );
    if (afterAncestry)
      return boundaryFailure("after-output-ancestry-mutation", afterAncestry);
    const authoritative = publication
      ? await validateExistingRootPublication(
          options.projectRoot,
          output,
          publication,
          publicationPayloadEntry!,
        )
      : await validateExistingCurrent(outputRoot);
    if (authoritative === null)
      return failureAfterLock({
        ok: false,
        status: "commit-uncertain",
        durable: false,
        attemptedBuildId,
        diagnostics: sortCompilationDiagnostics([
          issue(
            "CAP_BUILD_COMMIT_UNCERTAIN",
            "emission-commit",
            "Existing artifact pointer or generation could not be verified.",
            source,
            path,
          ),
        ]),
      });
    const beforeAtomic = await transactionBoundary(
      "before-atomicity-transaction",
    );
    if (beforeAtomic)
      return boundaryFailure("before-atomicity-transaction", beforeAtomic);
    const probeA = resolve(outputRoot, `.atomic-${lock.token}.a`),
      probeB = resolve(outputRoot, `.atomic-${lock.token}.b`);
    try {
      await writeSynced(probeA, Buffer.from("a"));
      await writeSynced(probeB, Buffer.from("b"));
      await rename(probeA, probeB);
      if (Buffer.from(await readFile(probeB)).toString("utf8") !== "a")
        throw new Error("replace");
      await rm(probeB);
      await syncDirectory(outputRoot);
    } catch {
      await rm(probeA, { force: true }).catch(() => {});
      await rm(probeB, { force: true }).catch(() => {});
      return fail(
        "CAP_BUILD_ATOMIC_UNSUPPORTED",
        "emission-stage",
        "Filesystem could not prove same-directory atomic replacement.",
        undefined,
        {
          attemptedBuildId,
          ...(authoritative ? { authoritativeBuildId: authoritative } : {}),
        },
      );
    }
    const afterAtomic = await transactionBoundary(
      "after-atomicity-transaction",
    );
    if (afterAtomic)
      return boundaryFailure("after-atomicity-transaction", afterAtomic);
    if (publication && authoritative) {
      const recoveryIdentityFailure = async (): Promise<EmissionResult> => {
        const [canonicalState, legacyState] = await Promise.all([
          rootEntryState(resolve(options.projectRoot, publication.rootPath)),
          rootEntryState(resolve(options.projectRoot, publication.legacyPath)),
        ]);
        return failureAfterLock({
          ok: false,
          status: "not-committed",
          durable: false,
          attemptedBuildId,
          authoritativeBuildId: authoritative,
          diagnostics: sortCompilationDiagnostics([
            legacyState.kind !== "missing"
              ? legacyManifestIssue(
                  publication.legacyPath,
                  publication.rootPath,
                  canonicalState.kind !== "missing",
                )
              : invalidManifestIssue(publication.rootPath, "identity-changed"),
          ]),
        });
      };
      const recoveredLocator = await migrationLocatorFromRoot(
        options.projectRoot,
        output,
        publication,
        publicationPayloadEntry!,
        initialCanonical!,
      );
      if (!recoveredLocator) return recoveryIdentityFailure();
      const recoveredBytes = Buffer.from(jcs(recoveredLocator));
      const currentPath = resolve(outputRoot, "current.json");
      const currentMatches = await readRegularFileNoFollow(currentPath).then(
        (value) => Buffer.compare(Buffer.from(value), recoveredBytes) === 0,
        () => false,
      );
      if (!currentMatches) {
        const recoveryTemp = resolve(
          outputRoot,
          `.current-recovery-${lock.token}.tmp`,
        );
        let recoveryBoundary = "current-temp";
        try {
          const beforeRecovery = await transactionBoundary(
            "before-recovery-current-temp",
          );
          if (beforeRecovery)
            return boundaryFailure(
              "before-recovery-current-temp",
              beforeRecovery,
            );
          const [immediateCanonical, immediateLegacy] = await Promise.all([
            rootEntryState(resolve(options.projectRoot, publication.rootPath)),
            rootEntryState(
              resolve(options.projectRoot, publication.legacyPath),
            ),
          ]);
          if (
            !sameRootEntry(initialCanonical!, immediateCanonical) ||
            immediateLegacy.kind !== "missing"
          )
            return recoveryIdentityFailure();
          await writeSynced(recoveryTemp, recoveredBytes);
          recoveryBoundary = "current-readback";
          const recoveryReadback = await readRegularFileNoFollow(recoveryTemp);
          if (
            Buffer.compare(Buffer.from(recoveryReadback), recoveredBytes) !== 0
          )
            throw new Error("readback");
          recoveryBoundary = "current-rename";
          await rename(recoveryTemp, currentPath);
          recoveryBoundary = "current-root-fsync";
          await syncDirectory(outputRoot);
        } catch {
          return fail(
            "CAP_BUILD_WRITE_FAILED",
            "emission-commit",
            "The migration locator could not be reset to canonical root authority.",
            { boundary: recoveryBoundary },
            { attemptedBuildId, authoritativeBuildId: authoritative },
          );
        }
      }
    }
    const hex = attemptedBuildId.slice(7);
    const generation = at(generationsHandle, hex);
    const stagingName = `.staging-${lock.token}`;
    const staging = at(generationsHandle, stagingName);
    const beforeGenerationPublication = await transactionBoundary(
      "before-generation-publication",
    );
    if (beforeGenerationPublication)
      return boundaryFailure(
        "before-generation-publication",
        beforeGenerationPublication,
      );
    if (await exists(generation)) {
      try {
        const generationHandle = await openDirectoryNoFollow(generation);
        await verifyDirectoryEntry(generationsHandle, hex, generationHandle);
        openedDirectories.push(generationHandle);
        openedEntries.push({
          parent: generationsHandle,
          name: hex,
          child: generationHandle,
        });
        for (const item of options.compilation.artifacts)
          if (
            sha(await readSafeRelativeFile(at(generationHandle), item.path)) !==
            item.sha256
          )
            throw new Error();
      } catch {
        return fail(
          "CAP_BUILD_ID_COLLISION",
          "emission-commit",
          "Existing immutable generation differs from compiled artifact bytes.",
          undefined,
          {
            attemptedBuildId,
            ...(authoritative ? { authoritativeBuildId: authoritative } : {}),
          },
        );
      }
    } else {
      const beforeStaging = await transactionBoundary(
        "before-staging-directory",
      );
      if (beforeStaging)
        return boundaryFailure("before-staging-directory", beforeStaging);
      try {
        await mkdir(staging);
        const stagingHandle = await openDirectoryNoFollow(staging);
        await verifyDirectoryEntry(
          generationsHandle,
          stagingName,
          stagingHandle,
        );
        openedDirectories.push(stagingHandle);
        const stagingEntry = {
          parent: generationsHandle,
          name: stagingName,
          child: stagingHandle,
        };
        openedEntries.push(stagingEntry);
        await syncDirectory(generations);
        const afterStaging = await transactionBoundary(
          "after-staging-directory",
        );
        if (afterStaging)
          return boundaryFailure("after-staging-directory", afterStaging);
        for (const item of options.compilation.artifacts) {
          let artifactParent = stagingHandle;
          for (const component of item.path.split("/").slice(0, -1)) {
            const childPath = at(artifactParent, component);
            if (!(await exists(childPath))) {
              const beforeArtifactDirectory = await transactionBoundary(
                `before-artifact-directory-${item.id}`,
              );
              if (beforeArtifactDirectory)
                return boundaryFailure(
                  `before-artifact-directory-${item.id}`,
                  beforeArtifactDirectory,
                );
              await mkdir(childPath);
            }
            const child = await openDirectoryNoFollow(childPath);
            await verifyDirectoryEntry(artifactParent, component, child);
            await syncDirectory(at(artifactParent));
            openedDirectories.push(child);
            openedEntries.push({
              parent: artifactParent,
              name: component,
              child,
            });
            const afterArtifactDirectory = await transactionBoundary(
              `after-artifact-directory-${item.id}`,
            );
            if (afterArtifactDirectory)
              return boundaryFailure(
                `after-artifact-directory-${item.id}`,
                afterArtifactDirectory,
              );
            artifactParent = child;
          }
          const fileName = item.path.split("/").at(-1)!;
          const beforeArtifact = await transactionBoundary(
            `before-artifact-write-${item.id}`,
          );
          if (beforeArtifact)
            return boundaryFailure(
              `before-artifact-write-${item.id}`,
              beforeArtifact,
            );
          await writeSynced(
            at(artifactParent, fileName),
            validated.artifacts.get(item.id)!,
          );
          await syncDirectory(at(artifactParent));
          const afterArtifact = await transactionBoundary(
            `after-artifact-write-${item.id}`,
          );
          if (afterArtifact)
            return boundaryFailure(
              `after-artifact-write-${item.id}`,
              afterArtifact,
            );
        }
        const beforeStagingSync = await transactionBoundary(
          "before-staging-directory-sync",
        );
        if (beforeStagingSync)
          return boundaryFailure(
            "before-staging-directory-sync",
            beforeStagingSync,
          );
        await syncDirectory(at(stagingHandle));
        const afterStagingSync = await transactionBoundary(
          "after-staging-directory-sync",
        );
        if (afterStagingSync)
          return boundaryFailure(
            "after-staging-directory-sync",
            afterStagingSync,
          );
        const beforeGenerationRename = await transactionBoundary(
          "before-generation-rename",
        );
        if (beforeGenerationRename)
          return boundaryFailure(
            "before-generation-rename",
            beforeGenerationRename,
          );
        await rename(staging, generation);
        stagingEntry.name = hex;
        for (const handle of openedDirectories) {
          const priorPath = directoryPaths.get(handle);
          if (priorPath === staging || priorPath?.startsWith(`${staging}/`))
            directoryPaths.set(
              handle,
              `${generation}${priorPath.slice(staging.length)}`,
            );
        }
      } catch {
        return fail(
          "CAP_BUILD_WRITE_FAILED",
          "emission-stage",
          "Artifact generation could not be written and synchronized.",
          undefined,
          {
            attemptedBuildId,
            ...(authoritative ? { authoritativeBuildId: authoritative } : {}),
          },
        );
      }
    }
    try {
      await syncDirectory(generations);
    } catch {
      return fail(
        "CAP_BUILD_WRITE_FAILED",
        "emission-commit",
        "Immutable generation could not be made durable before pointer creation.",
        undefined,
        {
          attemptedBuildId,
          ...(authoritative ? { authoritativeBuildId: authoritative } : {}),
        },
      );
    }
    const afterGenerationPublication = await transactionBoundary(
      "after-generation-publication",
    );
    if (afterGenerationPublication)
      return boundaryFailure(
        "after-generation-publication",
        afterGenerationPublication,
      );
    const indexBytes = validated.artifacts.get("capaxle.artifact-index")!;
    const pointer = {
      artifactGraphVersion: publication ? "0.2" : "0.1",
      buildId: attemptedBuildId,
      index: `generations/${hex}/artifacts.json`,
      indexSha256: sha(indexBytes),
      irHash: options.compilation.irHash,
    };
    const tempPointer = resolve(outputRoot, `.current-${lock.token}.tmp`);
    const writeFailure = (boundary: string): EmissionResult =>
      fail(
        "CAP_BUILD_WRITE_FAILED",
        "emission-commit",
        "Artifact publication could not be completed durably.",
        publication ? { boundary } : undefined,
        {
          attemptedBuildId,
          ...(authoritative ? { authoritativeBuildId: authoritative } : {}),
        },
      );
    const manifestStatesUnchanged = async (): Promise<
      "legacy" | "canonical" | undefined
    > => {
      if (!publication || !initialCanonical) return undefined;
      const [canonicalState, legacyState] = await Promise.all([
        rootEntryState(resolve(options.projectRoot, publication.rootPath)),
        rootEntryState(resolve(options.projectRoot, publication.legacyPath)),
      ]);
      if (legacyState.kind !== "missing") return "legacy";
      return sameRootEntry(initialCanonical, canonicalState)
        ? undefined
        : "canonical";
    };
    const manifestStateFailure = (
      reason: "legacy" | "canonical",
    ): EmissionResult =>
      failureAfterLock({
        ok: false,
        status: "not-committed",
        durable: false,
        attemptedBuildId,
        ...(authoritative ? { authoritativeBuildId: authoritative } : {}),
        diagnostics: sortCompilationDiagnostics([
          reason === "legacy"
            ? legacyManifestIssue(
                publication!.legacyPath,
                publication!.rootPath,
                initialCanonical!.kind !== "missing",
              )
            : invalidManifestIssue(publication!.rootPath, "identity-changed"),
        ]),
      });
    const beforeCurrentState = await manifestStatesUnchanged();
    if (beforeCurrentState) return manifestStateFailure(beforeCurrentState);
    if (publication && !(await verifyProjectRootIdentity()))
      return manifestStateFailure("canonical");
    let pointerBoundary = "current-temp";
    try {
      const beforePointer = await transactionBoundary(
        "before-pointer-temporary",
      );
      if (beforePointer)
        return boundaryFailure("before-pointer-temporary", beforePointer);
      const immediateCurrentState = await manifestStatesUnchanged();
      if (immediateCurrentState)
        return manifestStateFailure(immediateCurrentState);
      await writeSynced(tempPointer, Buffer.from(jcs(pointer as JsonValue)));
      pointerBoundary = "current-readback";
      if (publication) {
        const pointerReadback = await readRegularFileNoFollow(tempPointer);
        if (
          Buffer.compare(
            Buffer.from(pointerReadback),
            Buffer.from(jcs(pointer as JsonValue)),
          ) !== 0
        )
          return writeFailure("current-readback");
      }
      const afterPointerTemporary = await transactionBoundary(
        "after-pointer-temporary",
      );
      if (afterPointerTemporary)
        return boundaryFailure(
          "after-pointer-temporary",
          afterPointerTemporary,
        );
      pointerBoundary = "current-rename";
      const beforePointerRename = await transactionBoundary(
        "before-pointer-rename",
      );
      if (beforePointerRename)
        return boundaryFailure("before-pointer-rename", beforePointerRename);
      await rename(tempPointer, resolve(outputRoot, "current.json"));
      if (!publication) committed = true;
      const afterPointer = await transactionBoundary("after-pointer-rename");
      if (afterPointer)
        return boundaryFailure("after-pointer-rename", afterPointer);
      if (publication) {
        pointerBoundary = "current-root-fsync";
        await boundaryHook?.("before-current-root-fsync");
        await syncDirectory(outputRoot);
      }
    } catch {
      if (committed)
        return failureAfterLock({
          ok: false,
          status: "commit-uncertain",
          durable: false,
          attemptedBuildId,
          diagnostics: sortCompilationDiagnostics([
            issue(
              "CAP_BUILD_COMMIT_UNCERTAIN",
              "emission-commit",
              "Pointer replacement occurred but emission authority could not be verified.",
              source,
              path,
            ),
          ]),
        });
      return fail(
        "CAP_BUILD_WRITE_FAILED",
        "emission-commit",
        "Artifact pointer could not be replaced atomically.",
        publication ? { boundary: pointerBoundary } : undefined,
        {
          attemptedBuildId,
          ...(authoritative ? { authoritativeBuildId: authoritative } : {}),
        },
      );
    }
    if (publication) {
      const beforeTempState = await manifestStatesUnchanged();
      if (beforeTempState) return manifestStateFailure(beforeTempState);
      if (!(await verifyProjectRootIdentity()))
        return manifestStateFailure("canonical");
      const manifestTemp = resolve(
        options.projectRoot,
        `.capaxle-manifest-${lock.token}.tmp`,
      );
      try {
        await boundaryHook?.("before-manifest-temp");
        if (!(await verifyProjectRootIdentity()))
          return manifestStateFailure("canonical");
        const immediateTempState = await manifestStatesUnchanged();
        if (immediateTempState) return manifestStateFailure(immediateTempState);
        await writeSynced(manifestTemp, assembledRoot!);
        rootTemporary = {
          path: manifestTemp,
          state: await rootEntryState(manifestTemp),
        };
      } catch {
        return writeFailure("manifest-temp");
      }
      try {
        await boundaryHook?.("before-manifest-readback");
        const readback = await readRegularFileNoFollow(manifestTemp);
        if (
          Buffer.compare(Buffer.from(readback), Buffer.from(assembledRoot!)) !==
          0
        )
          throw new Error("bytes");
      } catch {
        return writeFailure("manifest-readback");
      }
      try {
        await boundaryHook?.("before-manifest-temp-entry-fsync");
        await syncDirectory(options.projectRoot);
      } catch {
        return writeFailure("manifest-temp-entry-fsync");
      }
      const beforeReplaceState = await manifestStatesUnchanged();
      if (beforeReplaceState) return manifestStateFailure(beforeReplaceState);
      if (!(await verifyProjectRootIdentity()))
        return manifestStateFailure("canonical");
      const beforeReplace = await transactionBoundary("before-manifest-rename");
      if (beforeReplace)
        return boundaryFailure("before-manifest-rename", beforeReplace);
      let postRenameHookFailed = false;
      try {
        await boundaryHook?.("before-manifest-replacement");
        if (!(await verifyProjectRootIdentity()))
          return manifestStateFailure("canonical");
        const immediateReplaceState = await manifestStatesUnchanged();
        if (immediateReplaceState)
          return manifestStateFailure(immediateReplaceState);
        await rename(
          manifestTemp,
          resolve(options.projectRoot, publication.rootPath),
        );
        committed = true;
        await boundaryHook?.("after-manifest-rename");
      } catch {
        if (!committed) return writeFailure("manifest-rename");
        postRenameHookFailed = true;
      }
      const uncertain = async (boundary: string): Promise<EmissionResult> => {
        const observed = await validateExistingRootPublication(
          options.projectRoot,
          output,
          publication,
          publicationPayloadEntry!,
        );
        if (observed) observedBuildId = observed;
        return failureAfterLock({
          ok: false,
          status: "commit-uncertain",
          durable: false,
          attemptedBuildId,
          ...(observedBuildId ? { observedBuildId } : {}),
          diagnostics: sortCompilationDiagnostics([
            issue(
              "CAP_BUILD_COMMIT_UNCERTAIN",
              "emission-commit",
              "Manifest replacement occurred but canonical authority could not be proven durable.",
              source,
              path,
              { boundary },
            ),
          ]),
        });
      };
      if (postRenameHookFailed) return uncertain("lock-loss");
      if (!(await maintainLock())) return uncertain("lock-loss");
      let rootReadback: Uint8Array;
      try {
        await boundaryHook?.("before-manifest-post-readback");
        rootReadback = await readRegularFileNoFollow(
          resolve(options.projectRoot, publication.rootPath),
        );
      } catch {
        return uncertain("manifest-readback");
      }
      if (
        Buffer.compare(
          Buffer.from(rootReadback),
          Buffer.from(assembledRoot!),
        ) !== 0
      )
        return uncertain("manifest-bytes");
      const postCanonical = await rootEntryState(
        resolve(options.projectRoot, publication.rootPath),
      );
      if (
        !rootTemporary ||
        rootTemporary.state.kind !== "file" ||
        !sameRootEntry(rootTemporary.state, postCanonical)
      )
        return uncertain("manifest-identity");
      if (
        (
          await rootEntryState(
            resolve(options.projectRoot, publication.legacyPath),
          )
        ).kind !== "missing"
      )
        return uncertain("legacy-entry");
      observedBuildId = attemptedBuildId;
      try {
        await boundaryHook?.("before-project-root-fsync");
        await syncDirectory(options.projectRoot);
      } catch {
        return uncertain("project-root-fsync");
      }
      let durableReadback: Uint8Array;
      try {
        durableReadback = await readRegularFileNoFollow(
          resolve(options.projectRoot, publication.rootPath),
        );
      } catch {
        return uncertain("manifest-readback");
      }
      if (
        Buffer.compare(
          Buffer.from(durableReadback),
          Buffer.from(assembledRoot!),
        ) !== 0
      )
        return uncertain("manifest-bytes");
      const durableCanonical = await rootEntryState(
        resolve(options.projectRoot, publication.rootPath),
      );
      if (
        !rootTemporary ||
        rootTemporary.state.kind !== "file" ||
        !sameRootEntry(rootTemporary.state, durableCanonical)
      )
        return uncertain("manifest-identity");
      if (
        (
          await rootEntryState(
            resolve(options.projectRoot, publication.legacyPath),
          )
        ).kind !== "missing"
      )
        return uncertain("legacy-entry");
      durable = true;
    } else {
      const beforeReadback = await transactionBoundary(
        "before-pointer-readback",
      );
      if (beforeReadback)
        return boundaryFailure("before-pointer-readback", beforeReadback);
      const readback = await validateExistingCurrent(outputRoot);
      if (readback) observedBuildId = readback;
      if (readback !== attemptedBuildId)
        return failureAfterLock({
          ok: false,
          status: "commit-uncertain",
          durable: false,
          attemptedBuildId,
          ...(observedBuildId ? { observedBuildId } : {}),
          diagnostics: sortCompilationDiagnostics([
            issue(
              "CAP_BUILD_COMMIT_UNCERTAIN",
              "emission-commit",
              "Pointer replacement occurred but authoritative state could not be verified.",
              source,
              path,
            ),
          ]),
        });
      const afterReadback = await transactionBoundary("after-pointer-readback");
      if (afterReadback)
        return boundaryFailure("after-pointer-readback", afterReadback);
      try {
        const beforeDurability = await transactionBoundary(
          "before-output-durability-sync",
        );
        if (beforeDurability)
          return boundaryFailure(
            "before-output-durability-sync",
            beforeDurability,
          );
        await syncDirectory(outputRoot);
        const afterDurability = await transactionBoundary(
          "after-output-durability-sync",
        );
        if (afterDurability)
          return boundaryFailure(
            "after-output-durability-sync",
            afterDurability,
          );
        durable = true;
      } catch {
        return failureAfterLock({
          ok: false,
          status: "commit-uncertain",
          durable: false,
          attemptedBuildId,
          ...(observedBuildId ? { observedBuildId } : {}),
          diagnostics: sortCompilationDiagnostics([
            issue(
              "CAP_BUILD_COMMIT_UNCERTAIN",
              "emission-commit",
              "Pointer replacement occurred but output-root durability could not be proven.",
              source,
              path,
            ),
          ]),
        });
      }
    }
    try {
      await boundaryHook?.("before-retention-cleanup");
      if (!(await verifyOpenedEntries()) || !(await owns(lock)))
        throw new Error("authority");
      const generationEntries = await readdir(generations);
      if (!generationEntries.includes(hex)) throw new Error("generation");
      await boundaryHook?.("after-retention-cleanup");
      if (!(await verifyOpenedEntries()) || !(await owns(lock)))
        throw new Error("authority");
    } catch {
      diagnostics.push(
        issue(
          "CAP_BUILD_CLEANUP_FAILED",
          "emission-cleanup",
          "Durable build completed but retention cleanup could not be verified.",
          source,
          path,
          undefined,
          "warning",
        ),
      );
    }
    await stopHeartbeat();
    const released = await release(lock, boundaryHook);
    if (!released)
      diagnostics.push(
        issue(
          "CAP_BUILD_LOCK_RELEASE_FAILED",
          "emission-cleanup",
          "Durable build completed but project lock release needs recovery.",
          source,
          path,
          undefined,
          "warning",
        ),
      );
    return Object.freeze({
      ok: true,
      status: "committed",
      durable: true,
      buildId: attemptedBuildId,
      current: publication ? publication.rootPath : `${output}/current.json`,
      artifacts: Object.freeze(
        validated.index.artifacts as readonly ArtifactIndexEntry[],
      ),
      diagnostics: sortCompilationDiagnostics(diagnostics),
    });
  } catch {
    return committed
      ? Object.freeze({
          ok: false,
          status: "commit-uncertain",
          durable: false,
          attemptedBuildId,
          ...(observedBuildId ? { observedBuildId } : {}),
          diagnostics: sortCompilationDiagnostics([
            issue(
              "CAP_BUILD_COMMIT_UNCERTAIN",
              "emission-commit",
              "Artifact visibility changed but durability could not be established.",
              source,
              path,
            ),
          ]),
        })
      : fail(
          "CAP_BUILD_WRITE_FAILED",
          "emission-stage",
          "Artifact emission failed before pointer replacement.",
          undefined,
          { attemptedBuildId },
        );
  } finally {
    await stopHeartbeat();
    if (!durable) {
      const released = await release(lock, boundaryHook).catch(() => false);
      if (!released && deferredFailure)
        deferredFailure.diagnostics = sortCompilationDiagnostics([
          ...deferredFailure.diagnostics,
          issue(
            "CAP_BUILD_LOCK_RELEASE_FAILED",
            "emission-cleanup",
            "Failed emission could not safely release the project lock.",
            source,
            path,
            undefined,
            "warning",
          ),
        ]);
    }
    if (deferredFailure) Object.freeze(deferredFailure);
    if (!committed && rootTemporary?.state.kind === "file") {
      const currentTemporary = await rootEntryState(rootTemporary.path);
      if (sameRootEntry(rootTemporary.state, currentTemporary))
        await unlink(rootTemporary.path).catch(() => {});
    }
    for (const handle of openedDirectories.reverse())
      await handle.close().catch(() => {});
  }
}
