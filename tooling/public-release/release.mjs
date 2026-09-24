import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import {
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

async function getPackument(name) {
  const response = await globalThis.fetch(packageUrl(name), {
    headers: { accept: "application/vnd.npm.install-v1+json" },
    cache: "no-store",
    signal: globalThis.AbortSignal.timeout(30_000),
  });
  if (response.status === 404) return null;
  if (!response.ok)
    throw new Error(
      `${packageName(name)}: registry read HTTP ${response.status}`,
    );
  return response.json();
}

async function verifyPublished(name, approval, previousLatest) {
  const expected = approval.packages[packageName(name)];
  for (let attempt = 0; attempt < 24; attempt++) {
    const packument = await getPackument(name);
    const version = packument?.versions?.[approval.version];
    if (
      version &&
      packument["dist-tags"]?.[distTag] === approval.version &&
      packument["dist-tags"]?.latest === previousLatest
    ) {
      const tarball = version.dist?.tarball;
      if (
        typeof tarball !== "string" ||
        !tarball.startsWith(`${registry}@capaxle/`)
      )
        throw new Error(
          `${packageName(name)}: unexpected registry tarball URL`,
        );
      const response = await globalThis.fetch(tarball, {
        cache: "no-store",
        signal: globalThis.AbortSignal.timeout(30_000),
      });
      if (!response.ok)
        throw new Error(
          `${packageName(name)}: tarball HTTP ${response.status}`,
        );
      if (sha256(Buffer.from(await response.arrayBuffer())) !== expected)
        throw new Error(
          `${packageName(name)}: registry bytes differ from approval`,
        );
      return;
    }
    await delay(2_500);
  }
  throw new Error(`${packageName(name)}: registry version/tags did not verify`);
}

async function publish() {
  if (!existsSync(candidatePath))
    throw new Error(
      "CAP_RELEASE_CANDIDATE_MISSING: reviewed release-candidate.json required",
    );
  const candidate = validateCandidate(
    readJson(candidatePath),
    process.env.GITHUB_REPOSITORY,
  );
  assertPublishContext(process.env, candidate);
  validateSource(
    readJson(sourcePath),
    process.env.RELEASE_SOURCE_COMMIT,
    candidate.publicRepository,
  );
  if (
    sha256(readFileSync(candidatePath)) !== process.env.RELEASE_MANIFEST_SHA256
  )
    throw new Error(
      "CAP_RELEASE_CANDIDATE_CHANGED: manifest SHA-256 differs from approval",
    );
  if (readLocalVersion() !== candidate.version)
    throw new Error(
      "CAP_RELEASE_VERSION_CHANGED: package train differs from approval",
    );
  const packedDigests = readJson(
    resolve(root, ".release", "package-digests.json"),
  );
  if (packedDigests.version !== candidate.version)
    throw new Error("CAP_RELEASE_PACKED_VERSION_CHANGED");
  for (const name of packageNames) {
    const expected = candidate.packages[packageName(name)];
    if (packedDigests.packages[packageName(name)] !== expected)
      throw new Error(
        `${packageName(name)}: pack record differs from approval`,
      );
    inspectArchive(
      name,
      candidate.version,
      candidate.publicRepository,
      archivePath(name, candidate.version),
      expected,
    );
  }
  const previousLatest = new Map();
  for (const name of packageNames) {
    const packument = await getPackument(name);
    if (!packument || packument.versions?.[candidate.version])
      throw new Error(
        `${packageName(name)}: version exists or package is unavailable`,
      );
    previousLatest.set(name, packument["dist-tags"]?.latest);
  }
  for (const name of publicationOrder()) {
    const archive = archivePath(name, candidate.version);
    const result = spawnSync(
      "npm",
      [
        "publish",
        archive,
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
      throw new Error(
        `${packageName(name)}: publish failed; stop partial train`,
      );
    await verifyPublished(name, candidate, previousLatest.get(name));
    console.log(
      `${packageName(name)}@${candidate.version}: registry bytes and tags verified`,
    );
  }
  console.log(
    `CAP_RELEASE_COMPLETE ${candidate.version}: all eleven packages verified`,
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const command = process.argv[2];
  if (command === "pack") await pack();
  else if (command === "publish") await publish();
  else throw new Error("usage: release.mjs pack|publish");
}
