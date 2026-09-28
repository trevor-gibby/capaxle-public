import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  appendFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import {
  assertExactKeys,
  distTag,
  packageNames,
  publicationOrder,
  registry,
  sha256,
  validateCandidate,
  validatePackageManifest,
  validateSource,
} from "./policy.mjs";

const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const archiveDirectory = resolve(root, ".release", "tarballs");
const candidatePath = resolve(
  root,
  "tooling/public-release/release-candidate.json",
);
const sourcePath = resolve(root, "PUBLIC_SOURCE.json");
const recoveryPath = resolve(
  root,
  "tooling/public-release/recovery-alpha2.json",
);
const packageName = (name) => `@capaxle/${name}`;
const run = (command, args, cwd = root) =>
  execFileSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, npm_config_registry: registry },
  });
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const archiveName = (name, version) => `capaxle-${name}-${version}.tgz`;
const archivePath = (name, version) =>
  resolve(archiveDirectory, archiveName(name, version));
const tarFile = (archive, path) =>
  execFileSync("tar", ["-xOf", archive, `package/${path}`]);

export function assertPublishContext(env, candidate) {
  if (
    env.GITHUB_ACTIONS !== "true" ||
    env.GITHUB_EVENT_NAME !== "workflow_dispatch" ||
    env.GITHUB_REF !== "refs/heads/main" ||
    env.GITHUB_REPOSITORY !== candidate.publicRepository ||
    env.RELEASE_VERSION !== candidate.version ||
    !/^[a-f0-9]{40}$/.test(env.RELEASE_SOURCE_COMMIT ?? "") ||
    !/^[a-f0-9]{40}$/.test(env.RELEASE_MIRROR_COMMIT ?? "") ||
    !/^[a-f0-9]{64}$/.test(env.RELEASE_MANIFEST_SHA256 ?? "") ||
    !/^[a-f0-9]{40}$/.test(env.GITHUB_SHA ?? "") ||
    env.GITHUB_SHA !== env.RELEASE_MIRROR_COMMIT ||
    !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID ?? "") ||
    !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT ?? "") ||
    !env.ACTIONS_ID_TOKEN_REQUEST_URL ||
    !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  )
    throw new Error(
      "CAP_RELEASE_CONTEXT_INVALID: manual public main OIDC run required",
    );
  const major = Number(process.versions.node.split(".")[0]);
  if (major !== 24)
    throw new Error("CAP_RELEASE_NODE_INVALID: Node 24 required");
  const npmVersion = run("npm", ["--version"]).trim().split(".").map(Number);
  if (npmVersion[0] < 11 || (npmVersion[0] === 11 && npmVersion[1] < 5))
    throw new Error("CAP_RELEASE_NPM_INVALID: npm >=11.5.1 required");
  if (npmVersion[0] === 11 && npmVersion[1] === 5 && npmVersion[2] < 1)
    throw new Error("CAP_RELEASE_NPM_INVALID: npm >=11.5.1 required");
}

export function validateArchiveInventory(files, name) {
  const paths = files.map(({ path }) => path);
  if (new Set(paths).size !== paths.length)
    throw new Error(`${packageName(name)}: duplicate tarball path`);
  for (const required of ["LICENSE", "README.md", "package.json"])
    if (!paths.includes(required))
      throw new Error(`${packageName(name)}: missing ${required}`);
  if (!paths.some((path) => path.startsWith("dist/")))
    throw new Error(`${packageName(name)}: missing built output`);
  for (const path of paths)
    if (
      !/^(?:LICENSE|README\.md|package\.json|capability-ir\.schema\.json|dist\/[\w./-]+\.(?:js|mjs|cjs|ts|mts|cts|map|json))$/.test(
        path,
      ) ||
      path.includes("..")
    )
      throw new Error(`${packageName(name)}: unexpected tarball path ${path}`);
}

function inspectArchive(name, version, repository, archive, expectedDigest) {
  const sourceManifest = readJson(
    resolve(root, "packages", name, "package.json"),
  );
  validatePackageManifest(sourceManifest, name, version, repository);
  if (!existsSync(archive))
    throw new Error(`${packageName(name)}: missing tarball`);
  const digest = sha256(readFileSync(archive));
  if (expectedDigest && digest !== expectedDigest)
    throw new Error(`${packageName(name)}: approved SHA-256 changed`);
  const packedManifest = JSON.parse(
    tarFile(archive, "package.json").toString(),
  );
  assert.deepEqual(packedManifest, sourceManifest);
  const files = run("tar", ["-tzf", archive])
    .trim()
    .split("\n")
    .filter((path) => path.startsWith("package/") && !path.endsWith("/"))
    .map((path) => ({ path: path.slice("package/".length) }));
  validateArchiveInventory(files, name);
  assert.deepEqual(
    tarFile(archive, "LICENSE"),
    readFileSync(resolve(root, "LICENSE")),
  );
  for (const value of Object.values(sourceManifest.exports ?? {})) {
    const targets = typeof value === "string" ? [value] : Object.values(value);
    for (const target of targets)
      if (!files.some(({ path }) => path === target.replace(/^\.\//, "")))
        throw new Error(`${packageName(name)}: missing export ${target}`);
  }
  for (const target of Object.values(sourceManifest.bin ?? {}))
    if (!files.some(({ path }) => path === target.replace(/^\.\//, "")))
      throw new Error(`${packageName(name)}: missing binary ${target}`);
  return digest;
}

async function cleanInstall(version) {
  const directory = mkdtempSync(resolve(tmpdir(), "capaxle-public-release-"));
  try {
    writeFileSync(
      resolve(directory, "package.json"),
      JSON.stringify({ private: true, type: "module" }),
    );
    const archives = packageNames.map((name) => archivePath(name, version));
    run(
      "npm",
      ["install", "--ignore-scripts", "--no-audit", "--no-fund", ...archives],
      directory,
    );
    const lock = readJson(resolve(directory, "package-lock.json"));
    for (const name of packageNames) {
      const entry = lock.packages[`node_modules/${packageName(name)}`];
      if (
        entry?.version !== version ||
        !entry.resolved?.startsWith("file:") ||
        entry.link
      )
        throw new Error(
          `${packageName(name)}: clean install did not use approved tarball`,
        );
    }
    run(
      "node",
      [
        "--input-type=module",
        "-e",
        `await Promise.all(${JSON.stringify(packageNames.map(packageName))}.map((name) => import(name)));`,
      ],
      directory,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export async function cleanRegistryInstall(
  version,
  names = packageNames,
  { execute = run } = {},
) {
  const directory = mkdtempSync(resolve(tmpdir(), "capaxle-registry-release-"));
  try {
    writeFileSync(
      resolve(directory, "package.json"),
      JSON.stringify({ private: true, type: "module" }),
    );
    execute(
      "npm",
      [
        "install",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        ...names.map((name) => `${packageName(name)}@${version}`),
      ],
      directory,
    );
    const lock = readJson(resolve(directory, "package-lock.json"));
    for (const name of names) {
      const entry = lock.packages[`node_modules/${packageName(name)}`];
      if (
        entry?.version !== version ||
        !entry.resolved?.startsWith(`${registry}@capaxle/`) ||
        entry.link
      )
        throw new Error(`${packageName(name)}: registry install drifted`);
    }
    execute("npm", ["audit", "signatures", "--registry", registry], directory);
    execute(
      "node",
      [
        "--input-type=module",
        "-e",
        `await Promise.all(${JSON.stringify(names.map(packageName))}.map((name) => import(name)));`,
      ],
      directory,
    );
    if (names.includes("cli")) checkInstalledCli(directory, { execute });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export function installedCliCommand(
  directory,
  project,
  platform = process.platform,
) {
  const bin = resolve(
    directory,
    "node_modules/.bin",
    platform === "win32" ? "capaxle.cmd" : "capaxle",
  );
  return platform === "win32"
    ? {
        command: "cmd.exe",
        args: [
          "/d",
          "/s",
          "/c",
          `""${bin}" check --project "${project}" --json"`,
        ],
      }
    : { command: bin, args: ["check", "--project", project, "--json"] };
}

export function checkInstalledCli(directory, { execute = run } = {}) {
  // Keep installed dependencies inside the authoritative project boundary.
  const project = realpathSync(directory);
  const source = resolve(project, "src");
  const config = resolve(project, "capaxle.config.ts");
  if (existsSync(source) || existsSync(config))
    throw new Error("CAP_RELEASE_CLI_SMOKE_PROJECT_NOT_ISOLATED");
  try {
    const capabilities = resolve(source, "capabilities/hello");
    mkdirSync(capabilities, { recursive: true });
    writeFileSync(
      config,
      'export default { service: { name: "release-smoke", version: "1.0.0" }, adapters: { cli: { binaryName: "release-smoke" } } };\n',
    );
    writeFileSync(
      resolve(capabilities, "greet.ts"),
      [
        'import { defineCapability } from "@capaxle/core";',
        'import { z } from "@capaxle/schema-zod";',
        "export default defineCapability({",
        '  summary: "Verify installed CLI",',
        "  input: z.strictObject({ name: z.string() }),",
        "  output: z.strictObject({ greeting: z.string() }),",
        '  authentication: "public", permissions: "public", exposure: { cli: "public" },',
        '  effects: { impact: "read" },',
        "  handler: ({ name }) => ({ greeting: `Hello, ${name}!` }),",
        "});",
        "",
      ].join("\n"),
    );
    const { command, args } = installedCliCommand(directory, project);
    const stdout = execute(command, args, directory);
    let result;
    try {
      result = JSON.parse(stdout);
    } catch {
      throw new Error("CAP_RELEASE_CLI_SMOKE_INVALID: check must return JSON");
    }
    if (
      result?.command !== "check" ||
      result.ok !== true ||
      result.summary?.capabilities !== 1
    )
      throw new Error(
        "CAP_RELEASE_CLI_SMOKE_INVALID: expected successful one-capability check",
      );
    return result;
  } finally {
    rmSync(source, { recursive: true, force: true });
    rmSync(config, { force: true });
  }
}

function readLocalVersion() {
  const version = readJson(resolve(root, "packages/ir/package.json")).version;
  if (!/^0\.\d+\.\d+-alpha\.\d+$/.test(version))
    throw new Error("CAP_RELEASE_VERSION_INVALID: expected alpha train");
  return version;
}

async function pack() {
  const repository = process.env.GITHUB_REPOSITORY;
  if (!repository)
    throw new Error("CAP_RELEASE_REPOSITORY_MISSING: set GITHUB_REPOSITORY");
  const version = readLocalVersion();
  mkdirSync(archiveDirectory, { recursive: true });
  const digests = {};
  for (const name of publicationOrder()) {
    const manifest = readJson(resolve(root, "packages", name, "package.json"));
    validatePackageManifest(manifest, name, version, repository);
    const [packed] = JSON.parse(
      run("npm", [
        "pack",
        resolve(root, "packages", name),
        "--json",
        "--ignore-scripts",
        "--pack-destination",
        archiveDirectory,
      ]),
    );
    if (
      packed.name !== packageName(name) ||
      packed.version !== version ||
      packed.filename !== archiveName(name, version)
    )
      throw new Error(`${packageName(name)}: npm pack identity changed`);
    validateArchiveInventory(packed.files, name);
    digests[packageName(name)] = inspectArchive(
      name,
      version,
      repository,
      archivePath(name, version),
    );
  }
  await cleanInstall(version);
  writeFileSync(
    resolve(root, ".release", "package-digests.json"),
    `${JSON.stringify({ version, packages: digests }, null, 2)}\n`,
  );
  console.log(JSON.stringify({ status: "PACKED", version, packages: digests }));
}

function packageUrl(name) {
  return `${registry}${encodeURIComponent(packageName(name))}`;
}

async function getPackument(name, timeoutMs = 30_000) {
  const response = await registryRead(
    packageUrl(name),
    globalThis.fetch,
    timeoutMs,
  );
  if (response.status === 404) return null;
  assertReadableResponse(response, name, "metadata");
  return response.json();
}

let registryReadSequence = 0;
export async function registryRead(
  url,
  fetch = globalThis.fetch,
  timeoutMs = 30_000,
) {
  const target = new URL(url);
  if (target.origin !== new URL(registry).origin)
    throw new Error("CAP_RELEASE_REGISTRY_URL_INVALID");
  target.searchParams.set(
    "capaxle_verify",
    `${Date.now()}-${++registryReadSequence}`,
  );
  try {
    return await fetch(target.toString(), {
      headers: {
        accept: "application/json",
        "cache-control": "no-cache, no-store, max-age=0",
        pragma: "no-cache",
      },
      cache: "no-store",
      signal: globalThis.AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    if (
      error instanceof TypeError ||
      ["TimeoutError", "AbortError"].includes(error.name)
    )
      error.transient = true;
    throw error;
  }
}

const recoveryVersion = "0.1.0-alpha.2";
const previousVersion = "0.1.0-alpha.1";
const recoveryManifestSha256 =
  "b45f479d247763b87d73b8e616af989cc2afc87f9d495087f08bdaac10417839";
const recoverySourceCommit = "b3d776686b1e56fbb1a64a86c42ca461f998e8e7";
const recoveryMirrorCommit = "7108cfad85623225d6f429aa6c43078da758d236";
const recoveryRunUrl =
  "https://github.com/trevor-gibby/capaxle-public/actions/runs/36022752069/attempts/1";
const recoverySecondSourceCommit = "344ac56794a68b3ba15f1ef303c4a996781a6464";
const recoverySecondMirrorCommit = "776dac445e239b12d72ff41a893d0a268bfffb2f";
const recoverySecondRunUrl =
  "https://github.com/trevor-gibby/capaxle-public/actions/runs/36034621296/attempts/1";

export function validateRecoveryRecord(record, candidate, candidateDigest) {
  assertExactKeys(
    record,
    [
      "version",
      "registry",
      "distTag",
      "publicRepository",
      "candidateSha256",
      "previousVersion",
      "publishedPrefix",
    ],
    "alpha.2 recovery record",
  );
  if (
    candidate.version !== recoveryVersion ||
    candidateDigest !== recoveryManifestSha256 ||
    record.version !== recoveryVersion ||
    record.registry !== registry ||
    record.distTag !== distTag ||
    record.publicRepository !== candidate.publicRepository ||
    record.candidateSha256 !== candidateDigest ||
    record.previousVersion !== previousVersion
  )
    throw new Error(
      "CAP_RELEASE_RECOVERY_RECORD_INVALID: approved source or candidate changed",
    );
  assert.deepEqual(
    record.publishedPrefix,
    publicationOrder()
      .slice(0, 10)
      .map((name) => ({
        name: packageName(name),
        sha256: candidate.packages[packageName(name)],
        sourceCommit:
          name === "ir" ? recoverySourceCommit : recoverySecondSourceCommit,
        mirrorCommit:
          name === "ir" ? recoveryMirrorCommit : recoverySecondMirrorCommit,
        runUrl: name === "ir" ? recoveryRunUrl : recoverySecondRunUrl,
      })),
  );
  return record;
}

export function validateRecoveryInventory(packuments, candidate, record) {
  const order = publicationOrder();
  const expectedPrefix = record.publishedPrefix.map(({ name }) => name);
  assert.deepEqual(
    expectedPrefix,
    order.slice(0, expectedPrefix.length).map(packageName),
  );
  const missing = [];
  for (const name of order) {
    const packument = packuments.get(name);
    const fullName = packageName(name);
    if (!packument || packument.name !== fullName)
      throw new Error(`${fullName}: package is unavailable`);
    const exists = versionExists(packument, candidate.version);
    if (expectedPrefix.includes(fullName)) {
      if (
        !exists ||
        !packument.versions[candidate.version] ||
        typeof packument.versions[candidate.version] !== "object" ||
        packument["dist-tags"]?.[distTag] !== candidate.version ||
        packument["dist-tags"]?.latest !== record.previousVersion
      )
        throw new Error(`${fullName}: published prefix or tags changed`);
    } else {
      if (
        exists ||
        packument["dist-tags"]?.[distTag] !== record.previousVersion ||
        packument["dist-tags"]?.latest !== record.previousVersion
      )
        throw new Error(`${fullName}: missing suffix or tags changed`);
      missing.push(name);
    }
  }
  return missing;
}

function attestationUrl(name, version) {
  return `${registry}-/npm/v1/attestations/@capaxle%2f${name}@${version}`;
}

function versionExists(packument, version) {
  const versions = packument?.versions;
  if (!versions || typeof versions !== "object" || Array.isArray(versions))
    throw new Error(
      `${packument?.name ?? "registry package"}: invalid versions map`,
    );
  return Object.hasOwn(versions, version);
}

export function validateProvenance(
  attestations,
  name,
  version,
  bytes,
  sourceCommit,
  runUrl,
  repository,
) {
  const statement = attestations?.attestations?.find(
    ({ predicateType }) => predicateType === "https://slsa.dev/provenance/v1",
  );
  const envelope = statement?.bundle?.dsseEnvelope;
  if (
    envelope?.payloadType !== "application/vnd.in-toto+json" ||
    !Array.isArray(envelope.signatures) ||
    envelope.signatures.length === 0
  )
    throw new Error(`${packageName(name)}: provenance envelope missing`);
  let payload;
  try {
    payload = JSON.parse(
      Buffer.from(envelope.payload, "base64").toString("utf8"),
    );
  } catch {
    throw new Error(`${packageName(name)}: provenance payload invalid`);
  }
  const expectedSha512 = createHash("sha512").update(bytes).digest("hex");
  const workflow =
    payload.predicate?.buildDefinition?.externalParameters?.workflow;
  const dependencies = payload.predicate?.buildDefinition?.resolvedDependencies;
  if (
    payload.predicateType !== "https://slsa.dev/provenance/v1" ||
    payload.subject?.length !== 1 ||
    payload.subject[0]?.name !== `pkg:npm/%40capaxle/${name}@${version}` ||
    payload.subject[0]?.digest?.sha512 !== expectedSha512 ||
    workflow?.repository !== `https://github.com/${repository}` ||
    workflow?.ref !== "refs/heads/main" ||
    workflow?.path !== ".github/workflows/publish.yml" ||
    !Array.isArray(dependencies) ||
    !dependencies.some(
      (dependency) =>
        dependency.uri ===
          `git+https://github.com/${repository}@refs/heads/main` &&
        dependency.digest?.gitCommit === sourceCommit,
    ) ||
    payload.predicate?.runDetails?.metadata?.invocationId !== runUrl
  )
    throw new Error(
      `${packageName(name)}: provenance differs from approved run`,
    );
}

export async function verifyRegistryPackage(
  name,
  approval,
  latest,
  sourceCommit,
  runUrl,
  {
    readPackument = getPackument,
    read,
    now = Date.now,
    sleep = delay,
    timeoutMs = 12 * 60_000,
    previousAlpha = latest,
    report = console.log,
  } = {},
) {
  const expected = approval.packages[packageName(name)];
  const deadline = now() + timeoutMs;
  const remaining = () => Math.max(1, Math.min(30_000, deadline - now()));
  const readVisible =
    read ?? ((url) => registryRead(url, globalThis.fetch, remaining()));
  let interval = 2_500;
  let phase;
  let detail;
  let lastReportedState;
  do {
    phase = "metadata";
    detail = "version not visible";
    try {
      const packument = await readPackument(name, remaining());
      if (packument && packument.name !== packageName(name))
        throw new Error(
          `${packageName(name)}: registry package identity changed`,
        );
      if (packument) {
        const exists = versionExists(packument, approval.version);
        const version = exists ? packument.versions[approval.version] : null;
        if (exists && (!version || typeof version !== "object"))
          throw new Error(
            `${packageName(name)}: invalid published version metadata`,
          );
        if (packument["dist-tags"]?.latest !== latest)
          throw new Error(`${packageName(name)}: latest tag changed`);
        const alpha = packument["dist-tags"]?.[distTag];
        if (alpha !== approval.version && alpha !== previousAlpha)
          throw new Error(
            `${packageName(name)}: alpha tag changed unexpectedly`,
          );
        if (version) {
          phase = "tarball";
          detail = "tarball not visible";
          const tarball = version.dist?.tarball;
          if (
            typeof tarball !== "string" ||
            !tarball.startsWith(`${registry}@capaxle/`)
          )
            throw new Error(
              `${packageName(name)}: unexpected registry tarball URL`,
            );
          if (now() >= deadline) break;
          const response = await readVisible(tarball);
          assertReadableResponse(response, name, phase);
          const bytes = Buffer.from(await response.arrayBuffer());
          if (sha256(bytes) !== expected)
            throw new Error(
              `${packageName(name)}: registry bytes differ from approval`,
            );
          phase = alpha === approval.version ? "provenance" : "alpha-tag";
          detail =
            alpha === approval.version
              ? "provenance not visible"
              : `alpha=${alpha ?? "absent"}; expected ${approval.version}`;
          if (alpha === approval.version && version.dist?.attestations) {
            if (
              version.dist.attestations.url !==
                attestationUrl(name, approval.version) ||
              version.dist.attestations.provenance?.predicateType !==
                "https://slsa.dev/provenance/v1"
            )
              throw new Error(
                `${packageName(name)}: provenance reference changed`,
              );
            if (now() >= deadline) break;
            const attestations = await readVisible(
              attestationUrl(name, approval.version),
            );
            assertReadableResponse(attestations, name, "provenance");
            validateProvenance(
              await attestations.json(),
              name,
              approval.version,
              bytes,
              sourceCommit,
              runUrl,
              approval.publicRepository,
            );
            return;
          }
        }
      } else {
        detail = "package metadata unavailable";
      }
    } catch (error) {
      if (!error.transient) throw error;
      detail = error.message;
    }
    const state = `${phase}: ${detail}`;
    if (state !== lastReportedState) {
      report(
        `${packageName(name)}: waiting for registry visibility (${state}); upload will not be retried`,
      );
      lastReportedState = state;
    }
    if (now() >= deadline) break;
    await sleep(Math.min(interval, deadline - now()));
    interval = Math.min(15_000, interval * 1.5);
  } while (now() < deadline);
  throw new Error(
    `${packageName(name)}: registry visibility deadline expired (${phase}: ${detail}); accepted or uncertain upload must not be replayed`,
  );
}

function assertReadableResponse(response, name, phase) {
  if (response.ok) return;
  const error = new Error(
    `${packageName(name)}: ${phase} HTTP ${response.status}`,
  );
  error.transient = [404, 408, 429, 500, 502, 503, 504].includes(
    response.status,
  );
  throw error;
}

function uploadArchive(name, version) {
  const result = spawnSync(
    "npm",
    [
      "publish",
      archivePath(name, version),
      "--tag",
      distTag,
      "--access",
      "public",
      "--provenance",
      "--registry",
      registry,
    ],
    { cwd: root, env: process.env, stdio: "inherit" },
  );
  if (result.status !== 0)
    throw new Error(`${packageName(name)}: publish failed; stop partial train`);
}

async function inventoryAfterFailure(candidate, readPackument) {
  const packages = {};
  for (const name of packageNames) {
    const fullName = packageName(name);
    try {
      const packument = await readPackument(name);
      if (!packument || packument.name !== fullName) {
        packages[fullName] = { state: "unknown" };
        continue;
      }
      packages[fullName] = {
        state: versionExists(packument, candidate.version)
          ? "present-unverified"
          : "absent",
        alpha: packument["dist-tags"]?.[distTag] ?? null,
        latest: packument["dist-tags"]?.latest ?? null,
      };
    } catch {
      packages[fullName] = { state: "unknown" };
    }
  }
  return packages;
}

export async function publishTrain(
  candidate,
  recovery,
  {
    readPackument = getPackument,
    verifyPackage = verifyRegistryPackage,
    installRegistry = cleanRegistryInstall,
    assertCheckout = () => assertFrozenCheckout(env),
    plan,
    upload,
    env = process.env,
    report = console.error,
  } = {},
) {
  if (typeof upload !== "function")
    throw new Error(
      "CAP_RELEASE_UPLOAD_UNAUTHORIZED: validated CLI entry required",
    );
  if (!plan || !Array.isArray(plan.packages))
    throw new Error(
      "CAP_RELEASE_PLAN_REQUIRED: validated frozen plan required",
    );
  try {
    assertCheckout();
    const inventory = new Map();
    for (const name of packageNames)
      inventory.set(name, await readPackument(name));
    const order = recovery
      ? validateRecoveryInventory(inventory, candidate, recovery)
      : publicationOrder();
    const previousLatest = new Map();
    const previousAlpha = new Map();
    assert.deepEqual(
      plan.packages.map(({ name }) => name),
      publicationOrder().map(packageName),
    );
    for (const entry of plan.packages) {
      const name = entry.name.slice("@capaxle/".length);
      const state = inventory.get(name);
      if (
        entry.sha256 !== candidate.packages[entry.name] ||
        entry.targetAlpha !== candidate.version ||
        !state ||
        state.name !== entry.name ||
        versionExists(state, candidate.version) !== !entry.pendingUpload ||
        (state["dist-tags"]?.latest ?? null) !== entry.latest ||
        (state["dist-tags"]?.[distTag] ?? null) !== entry.previousAlpha
      )
        throw new Error(`${entry.name}: registry changed from frozen plan`);
      previousLatest.set(name, entry.latest ?? undefined);
      previousAlpha.set(name, entry.previousAlpha ?? undefined);
    }
    if (recovery) {
      for (const entry of recovery.publishedPrefix)
        await verifyPackage(
          entry.name.slice("@capaxle/".length),
          candidate,
          recovery.previousVersion,
          entry.mirrorCommit,
          entry.runUrl,
        );
      await installRegistry(
        candidate.version,
        recovery.publishedPrefix.map(({ name }) =>
          name.slice("@capaxle/".length),
        ),
      );
    } else {
      for (const name of packageNames) {
        const packument = inventory.get(name);
        if (
          !packument ||
          packument.name !== packageName(name) ||
          versionExists(packument, candidate.version)
        )
          throw new Error(
            `${packageName(name)}: version exists or package is unavailable`,
          );
      }
    }
    const currentRunUrl =
      `https://github.com/${candidate.publicRepository}/actions/runs/` +
      `${env.GITHUB_RUN_ID}/attempts/${env.GITHUB_RUN_ATTEMPT}`;
    for (const name of order) {
      const before = await readPackument(name);
      if (
        !before ||
        before.name !== packageName(name) ||
        versionExists(before, candidate.version) ||
        before["dist-tags"]?.latest !== previousLatest.get(name) ||
        before["dist-tags"]?.[distTag] !== previousAlpha.get(name)
      )
        throw new Error(`${packageName(name)}: registry changed before upload`);
      await upload(name, candidate.version);
      await verifyPackage(
        name,
        candidate,
        previousLatest.get(name),
        env.RELEASE_MIRROR_COMMIT,
        currentRunUrl,
        { previousAlpha: previousAlpha.get(name) },
      );
      console.log(
        `${packageName(name)}@${candidate.version}: registry bytes, tags, and provenance verified`,
      );
    }
    for (const name of packageNames) {
      const original = recovery?.publishedPrefix.find(
        (entry) => entry.name === packageName(name),
      );
      await verifyPackage(
        name,
        candidate,
        previousLatest.get(name),
        original ? original.mirrorCommit : env.RELEASE_MIRROR_COMMIT,
        original ? original.runUrl : currentRunUrl,
      );
    }
    await installRegistry(candidate.version);
    console.log(
      `CAP_RELEASE_COMPLETE ${candidate.version}: all eleven packages and registry install verified`,
    );
  } catch (error) {
    const packages = await inventoryAfterFailure(candidate, readPackument);
    report(
      JSON.stringify({
        code: "CAP_RELEASE_STOPPED",
        version: candidate.version,
        failure: error.message,
        packages,
      }),
    );
    throw error;
  }
}

export function canonicalJson(value) {
  const sorted = (item) =>
    Array.isArray(item)
      ? item.map(sorted)
      : item && typeof item === "object"
        ? Object.fromEntries(
            Object.keys(item)
              .sort()
              .map((key) => [key, sorted(item[key])]),
          )
        : item;
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

export function assertPrepareContext(env, repository) {
  if (
    env.GITHUB_ACTIONS !== "true" ||
    env.GITHUB_EVENT_NAME !== "workflow_dispatch" ||
    env.GITHUB_REF !== "refs/heads/main" ||
    env.GITHUB_REPOSITORY !== repository ||
    env.GITHUB_WORKFLOW_REF !==
      `${repository}/.github/workflows/publish.yml@refs/heads/main` ||
    !/^[a-f0-9]{40}$/.test(env.GITHUB_SHA ?? "") ||
    !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID ?? "") ||
    !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT ?? "")
  )
    throw new Error(
      "CAP_RELEASE_PREPARE_CONTEXT_INVALID: manual public main run required",
    );
}

function validateOrdinaryInventory(inventory, candidate) {
  for (const name of packageNames) {
    const packument = inventory.get(name);
    if (
      !packument ||
      packument.name !== packageName(name) ||
      versionExists(packument, candidate.version)
    )
      throw new Error(
        `${packageName(name)}: version exists or package is unavailable`,
      );
  }
}

export function createReleasePlan(
  candidate,
  recovery,
  source,
  env,
  inventory,
  candidateDigest,
  recoveryDigest,
) {
  assertPrepareContext(env, candidate.publicRepository);
  validateSource(source, source.sourceCommit, candidate.publicRepository);
  if (
    !/^[a-f0-9]{64}$/.test(candidateDigest) ||
    (recovery
      ? !/^[a-f0-9]{64}$/.test(recoveryDigest)
      : recoveryDigest !== null)
  )
    throw new Error("CAP_RELEASE_PLAN_DIGEST_INVALID");
  if (recovery) {
    validateRecoveryRecord(recovery, candidate, candidateDigest);
    validateRecoveryInventory(inventory, candidate, recovery);
  } else validateOrdinaryInventory(inventory, candidate);
  return {
    schemaVersion: 1,
    workflow: ".github/workflows/publish.yml",
    publicRepository: candidate.publicRepository,
    version: candidate.version,
    registry,
    distTag,
    sourceCommit: source.sourceCommit,
    mirrorCommit: env.GITHUB_SHA,
    candidateSha256: candidateDigest,
    recoverySha256: recoveryDigest,
    runId: env.GITHUB_RUN_ID,
    runAttempt: env.GITHUB_RUN_ATTEMPT,
    approval:
      "Review this exact record before approving npm-publish; approval authorizes only its pending npm uploads. Git tags require separate approval.",
    packages: publicationOrder().map((name) => {
      const existing = recovery?.publishedPrefix.find(
        (entry) => entry.name === packageName(name),
      );
      return {
        name: packageName(name),
        sha256: candidate.packages[packageName(name)],
        archive: archiveName(name, candidate.version),
        pendingUpload: !existing,
        existingOrigin: existing
          ? {
              sourceCommit: existing.sourceCommit,
              mirrorCommit: existing.mirrorCommit,
              runUrl: existing.runUrl,
            }
          : null,
        previousAlpha: inventory.get(name)["dist-tags"]?.[distTag] ?? null,
        latest: inventory.get(name)["dist-tags"]?.latest ?? null,
        targetAlpha: candidate.version,
      };
    }),
  };
}

export function validatePreparedPlan(bytes, expectedDigest, expectedPlan) {
  if (
    !/^[a-f0-9]{64}$/.test(expectedDigest ?? "") ||
    sha256(bytes) !== expectedDigest
  )
    throw new Error(
      "CAP_RELEASE_PLAN_CHANGED: same-run prepared plan SHA-256 changed",
    );
  const plan = JSON.parse(bytes.toString());
  assert.deepEqual(
    plan,
    expectedPlan,
    "CAP_RELEASE_PLAN_CHANGED: frozen source, artifacts, run, or registry changed",
  );
  if (bytes.toString() !== canonicalJson(plan))
    throw new Error("CAP_RELEASE_PLAN_CHANGED: canonical record required");
  return plan;
}

function inspectSourceFiles(source) {
  for (const [path, expected] of Object.entries(source.filesSha256)) {
    if (
      !/^[\w./-]+$/.test(path) ||
      path.startsWith("/") ||
      path.split("/").some((part) => part === ".." || part === ".git")
    )
      throw new Error("CAP_RELEASE_SOURCE_PATH_INVALID");
    if (sha256(readFileSync(resolve(root, path))) !== expected)
      throw new Error(`CAP_RELEASE_SOURCE_CHANGED: ${path}`);
  }
}

export function validateReleaseArtifact(directory, version, hasPlan) {
  const assertDirectory = (path) => {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || !stat.isDirectory())
      throw new Error(
        "CAP_RELEASE_ARTIFACT_INVALID: regular directory required",
      );
  };
  assertDirectory(directory);
  assert.deepEqual(
    readdirSync(directory).sort(),
    [
      "package-digests.json",
      "tarballs",
      ...(hasPlan ? ["plan.json"] : []),
    ].sort(),
    "CAP_RELEASE_ARTIFACT_INVALID: unexpected artifact inventory",
  );
  const tarballs = resolve(directory, "tarballs");
  assertDirectory(tarballs);
  const archives = packageNames.map((name) => archiveName(name, version));
  assert.deepEqual(
    readdirSync(tarballs).sort(),
    [...archives].sort(),
    "CAP_RELEASE_ARTIFACT_INVALID: unexpected tarball inventory",
  );
  for (const path of [
    resolve(directory, "package-digests.json"),
    ...(hasPlan ? [resolve(directory, "plan.json")] : []),
    ...archives.map((name) => resolve(tarballs, name)),
  ]) {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || !stat.isFile())
      throw new Error(
        "CAP_RELEASE_ARTIFACT_INVALID: regular artifact file required",
      );
  }
}

export function assertFrozenCheckout(env, { execute = run } = {}) {
  if (execute("git", ["rev-parse", "HEAD"]).trim() !== env.GITHUB_SHA)
    throw new Error(
      "CAP_RELEASE_CHECKOUT_CHANGED: dispatched public SHA required",
    );
  for (const args of [
    ["diff", "--quiet", "--"],
    ["diff", "--cached", "--quiet", "--"],
  ]) {
    try {
      execute("git", args);
    } catch {
      throw new Error(
        "CAP_RELEASE_CHECKOUT_DIRTY: tracked worktree and index must match dispatched HEAD",
      );
    }
  }
}

function loadRelease(hasPlan) {
  assertFrozenCheckout(process.env);
  if (!existsSync(candidatePath))
    throw new Error(
      "CAP_RELEASE_CANDIDATE_MISSING: reviewed release-candidate.json required",
    );
  const candidate = validateCandidate(
    readJson(candidatePath),
    process.env.GITHUB_REPOSITORY,
  );
  assertPrepareContext(process.env, candidate.publicRepository);
  const source = readJson(sourcePath);
  validateSource(source, source.sourceCommit, candidate.publicRepository);
  inspectSourceFiles(source);
  const candidateDigest = sha256(readFileSync(candidatePath));
  if (readLocalVersion() !== candidate.version)
    throw new Error(
      "CAP_RELEASE_VERSION_CHANGED: package train differs from approval",
    );
  validateReleaseArtifact(
    resolve(root, ".release"),
    candidate.version,
    hasPlan,
  );
  const packedDigests = readJson(
    resolve(root, ".release", "package-digests.json"),
  );
  assert.deepEqual(packedDigests, {
    version: candidate.version,
    packages: candidate.packages,
  });
  for (const name of packageNames)
    inspectArchive(
      name,
      candidate.version,
      candidate.publicRepository,
      archivePath(name, candidate.version),
      candidate.packages[packageName(name)],
    );
  const recovery =
    candidate.version === recoveryVersion
      ? validateRecoveryRecord(
          readJson(recoveryPath),
          candidate,
          candidateDigest,
        )
      : null;
  return {
    candidate,
    source,
    candidateDigest,
    recovery,
    recoveryDigest: recovery ? sha256(readFileSync(recoveryPath)) : null,
  };
}

async function readInventory() {
  const inventory = new Map();
  for (const name of packageNames)
    inventory.set(name, await getPackument(name));
  return inventory;
}

async function prepare() {
  const { candidate, recovery, source, candidateDigest, recoveryDigest } =
    loadRelease(false);
  const inventory = await readInventory();
  const plan = createReleasePlan(
    candidate,
    recovery,
    source,
    process.env,
    inventory,
    candidateDigest,
    recoveryDigest,
  );
  if (recovery) {
    for (const entry of recovery.publishedPrefix)
      await verifyRegistryPackage(
        entry.name.slice("@capaxle/".length),
        candidate,
        recovery.previousVersion,
        entry.mirrorCommit,
        entry.runUrl,
      );
    await cleanRegistryInstall(
      candidate.version,
      recovery.publishedPrefix.map(({ name }) =>
        name.slice("@capaxle/".length),
      ),
    );
  }
  const bytes = canonicalJson(plan);
  writeFileSync(resolve(root, ".release", "plan.json"), bytes);
  if (process.env.GITHUB_OUTPUT)
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `plan_sha256=${sha256(bytes)}\nmirror_commit=${plan.mirrorCommit}\n`,
    );
  if (process.env.GITHUB_STEP_SUMMARY)
    appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      [
        `## Exact npm release approval: ${plan.version}`,
        plan.approval,
        "An authenticated local audit of all eleven npm trusted publishers must precede approval. Dispatch alone does not authorize upload.",
        `- Destination: ${registry}; dist-tag: ${distTag}; latest remains at the recorded values below.`,
        `- Private source: ${plan.sourceCommit}`,
        `- Public source: ${plan.mirrorCommit}`,
        `- Candidate SHA-256: ${plan.candidateSha256}`,
        `- Recovery SHA-256: ${plan.recoverySha256 ?? "none"}`,
        `- Frozen plan SHA-256: ${sha256(bytes)}`,
        `- Run/attempt: ${plan.runId}/${plan.runAttempt}`,
        "",
        "| Package | Action | Tarball SHA-256 | Observed alpha | Target alpha | Preserve latest | Existing public provenance |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        ...plan.packages.map(
          (entry) =>
            `| ${entry.name} | ${entry.pendingUpload ? "Upload" : "Verify only"} | ${entry.sha256} | ${entry.previousAlpha ?? "absent"} | ${entry.targetAlpha} | ${entry.latest ?? "absent"} | ${entry.existingOrigin ? `${entry.existingOrigin.mirrorCommit} ([run](${entry.existingOrigin.runUrl})); private ${entry.existingOrigin.sourceCommit}` : "This frozen public source and run"} |`,
        ),
        "",
        "No Git tag is created by this workflow.",
        "",
      ].join("\n"),
    );
  console.log(`CAP_RELEASE_PREPARED ${candidate.version}: ${sha256(bytes)}`);
}

async function publish() {
  const { candidate, recovery, source, candidateDigest, recoveryDigest } =
    loadRelease(true);
  const expectedPlan = createReleasePlan(
    candidate,
    recovery,
    source,
    process.env,
    await readInventory(),
    candidateDigest,
    recoveryDigest,
  );
  const plan = validatePreparedPlan(
    readFileSync(resolve(root, ".release", "plan.json")),
    process.env.RELEASE_PLAN_SHA256,
    expectedPlan,
  );
  const env = {
    ...process.env,
    RELEASE_VERSION: plan.version,
    RELEASE_SOURCE_COMMIT: plan.sourceCommit,
    RELEASE_MIRROR_COMMIT: plan.mirrorCommit,
    RELEASE_MANIFEST_SHA256: plan.candidateSha256,
  };
  assertPublishContext(env, candidate);
  await publishTrain(candidate, recovery, { upload: uploadArchive, env, plan });
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const command = process.argv[2];
  if (command === "pack") await pack();
  else if (command === "prepare") await prepare();
  else if (command === "publish") await publish();
  else throw new Error("usage: release.mjs pack|prepare|publish");
}
