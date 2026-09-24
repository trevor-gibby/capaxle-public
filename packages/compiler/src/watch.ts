import { watch as watchPath, type FSWatcher } from "node:fs";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import {
  assertProjectRoot,
  canonicalConfig,
  legacyConfig,
  projectPath,
} from "./config.js";
import { compareText, diagnostic, location } from "./diagnostics.js";
import { discoverCapabilities } from "./discovery.js";
import type {
  DiscoveryListener,
  DiscoveryOptions,
  DiscoveryResult,
  DiscoveryUpdate,
  DiscoveryWatcher,
  SuccessfulDiscoveryResult,
} from "./types.js";

const debounceMilliseconds = 25;
const fallbackPollMilliseconds = 75;

function update(
  generation: number,
  result: DiscoveryResult,
  active: SuccessfulDiscoveryResult | undefined,
): DiscoveryUpdate {
  return Object.freeze({
    generation,
    result,
    ...(active === undefined ? {} : { active }),
    stale: !result.ok && active !== undefined,
  });
}

async function directoriesToWatch(
  projectRoot: string,
  result: DiscoveryResult,
): Promise<readonly string[]> {
  const directories = new Set<string>([projectRoot]);
  const root = result.config?.root;
  if (root === undefined) return Object.freeze([...directories]);
  let cursor = projectRoot;
  let complete = true;
  for (const segment of root.split("/")) {
    cursor = resolve(cursor, segment);
    try {
      const info = await lstat(cursor);
      if (!info.isDirectory() || info.isSymbolicLink()) {
        complete = false;
        break;
      }
      directories.add(cursor);
    } catch {
      complete = false;
      break;
    }
  }
  if (!complete) return Object.freeze([...directories]);

  async function descend(directory: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
      const child = resolve(directory, entry.name);
      directories.add(child);
      await descend(child);
    }
  }
  await descend(cursor);
  return Object.freeze([...directories].sort(compareText));
}

async function watchFingerprint(
  projectRoot: string,
  result: DiscoveryResult,
  active: SuccessfulDiscoveryResult | undefined,
): Promise<string> {
  const hash = createHash("sha256");
  const addPath = async (path: string): Promise<void> => {
    const relative = projectPath(projectRoot, path);
    let info;
    try {
      info = await lstat(path);
    } catch {
      hash.update(`missing\0${relative}\0`);
      return;
    }
    if (info.isSymbolicLink()) {
      hash.update(`symlink\0${relative}\0`);
      return;
    }
    if (info.isDirectory()) {
      hash.update(`directory\0${relative}\0`);
      let entries;
      try {
        entries = await readdir(path, { withFileTypes: true });
      } catch {
        hash.update("unreadable\0");
        return;
      }
      entries.sort((left, right) => compareText(left.name, right.name));
      for (const entry of entries) await addPath(resolve(path, entry.name));
      return;
    }
    if (info.isFile()) {
      hash.update(`file\0${relative}\0`);
      try {
        hash.update(await readFile(path));
      } catch {
        hash.update("unreadable\0");
      }
      hash.update("\0");
      return;
    }
    hash.update(`other\0${relative}\0`);
  };

  await addPath(resolve(projectRoot, canonicalConfig));
  await addPath(resolve(projectRoot, legacyConfig));
  const root = result.config?.root ?? active?.config.root;
  if (root !== undefined)
    await addPath(resolve(projectRoot, ...root.split("/")));
  return hash.digest("hex");
}

export async function watchCapabilities(
  options: DiscoveryOptions,
  listener: DiscoveryListener,
): Promise<DiscoveryWatcher> {
  const projectRoot = assertProjectRoot(options.projectRoot);
  if (typeof listener !== "function")
    throw new TypeError("listener must be a function.");

  let generation = 0;
  let currentResult = await discoverCapabilities({ projectRoot });
  let active = currentResult.ok ? currentResult : undefined;
  let current = update(generation, currentResult, active);
  let closed = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let pollTimer: ReturnType<typeof setInterval> | undefined;
  let rerun = false;
  let activeRun: Promise<void> | undefined;
  let activeScan: Promise<void> | undefined;
  let watchers: FSWatcher[] = [];
  let nativeWatchUnavailable = false;
  let observationUnavailable = false;
  let observationQueued = false;
  let observationRun: Promise<void> | undefined;
  let closePromise: Promise<void> | undefined;
  let fingerprint = await watchFingerprint(projectRoot, currentResult, active);

  const deliver = async (value: DiscoveryUpdate): Promise<void> => {
    if (closed) return;
    try {
      await listener(value);
    } catch {
      // Listener failures are consumer failures and must not terminate discovery.
    }
  };

  const closeWatches = (): void => {
    for (const watcher of watchers) watcher.close();
    watchers = [];
  };

  const disableNativeWatch = (): void => {
    if (nativeWatchUnavailable) return;
    nativeWatchUnavailable = true;
    closeWatches();
  };

  const observationFailure = async (): Promise<void> => {
    if (closed || observationUnavailable) return;
    observationUnavailable = true;
    observationQueued = false;
    rerun = false;
    if (timer !== undefined) {
      clearTimeout(timer);
      timer = undefined;
    }
    if (pollTimer !== undefined) {
      clearInterval(pollTimer);
      pollTimer = undefined;
    }
    closeWatches();
    const failure = diagnostic(
      "watch",
      "CAP_DISCOVERY_WATCH_FAILED",
      "error",
      "Capability discovery lost filesystem observation; correct project accessibility and restart the watcher.",
      location("."),
    );
    currentResult = Object.freeze({
      ok: false,
      ...(currentResult.config === undefined
        ? {}
        : { config: currentResult.config }),
      capabilities: Object.freeze([]) as readonly [],
      diagnostics: Object.freeze([
        ...currentResult.diagnostics,
        Object.freeze({
          code: failure.code,
          severity: failure.severity,
          message: failure.message,
          source: failure.source,
        }),
      ]),
    });
    current = update(++generation, currentResult, active);
    await deliver(current);
  };

  const rebuildWatches = async (): Promise<void> => {
    closeWatches();
    if (closed || observationUnavailable || nativeWatchUnavailable) return;
    for (const directory of await directoriesToWatch(
      projectRoot,
      currentResult,
    )) {
      if (closed || observationUnavailable || nativeWatchUnavailable) return;
      try {
        const watcher = watchPath(directory, () => requestObservation());
        watcher.on("error", disableNativeWatch);
        watchers.push(watcher);
      } catch {
        disableNativeWatch();
      }
    }
  };

  const run = async (): Promise<void> => {
    if (closed || observationUnavailable) return;
    do {
      rerun = false;
      const attemptPromise = discoverCapabilities({ projectRoot });
      const scan = attemptPromise.then(
        () => undefined,
        () => undefined,
      );
      activeScan = scan;
      let attempt: DiscoveryResult;
      try {
        attempt = await attemptPromise;
      } finally {
        if (activeScan === scan) activeScan = undefined;
      }
      if (closed || observationUnavailable) return;
      if (attempt.ok) active = attempt;
      currentResult = attempt;
      current = update(++generation, currentResult, active);
      await rebuildWatches();
      if (closed || observationUnavailable) return;
      await deliver(current);
    } while (rerun && !closed && !observationUnavailable);
  };

  const startRun = (): void => {
    if (closed || observationUnavailable) return;
    if (activeRun !== undefined) {
      rerun = true;
      return;
    }
    activeRun = run().finally(() => {
      activeRun = undefined;
      if (rerun && !closed && !observationUnavailable) startRun();
    });
  };

  function schedule(): void {
    if (closed || observationUnavailable) return;
    if (timer !== undefined) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = undefined;
      startRun();
    }, debounceMilliseconds);
  }

  const observe = async (): Promise<void> => {
    if (closed || observationUnavailable) return;
    try {
      const next = await watchFingerprint(projectRoot, currentResult, active);
      if (closed || next === fingerprint) return;
      fingerprint = next;
      schedule();
    } catch {
      await observationFailure();
    }
  };

  function requestObservation(): void {
    if (closed || observationUnavailable) return;
    if (observationRun !== undefined) {
      observationQueued = true;
      return;
    }
    observationRun = observe().finally(() => {
      observationRun = undefined;
      if (observationQueued && !closed && !observationUnavailable) {
        observationQueued = false;
        requestObservation();
      }
    });
  }

  await deliver(current);
  await rebuildWatches();
  if (!closed && !observationUnavailable)
    pollTimer = setInterval(requestObservation, fallbackPollMilliseconds);

  const close = (): Promise<void> => {
    if (closePromise !== undefined) return closePromise;
    closed = true;
    if (timer !== undefined) clearTimeout(timer);
    if (pollTimer !== undefined) {
      clearInterval(pollTimer);
      pollTimer = undefined;
    }
    closeWatches();
    closePromise = activeScan ?? Promise.resolve();
    return closePromise;
  };

  return Object.freeze({
    get snapshot() {
      return current;
    },
    close,
  });
}
