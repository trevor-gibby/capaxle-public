import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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

async function cleanRegistryInstall(version, names = packageNames) {
  const directory = mkdtempSync(resolve(tmpdir(), "capaxle-registry-release-"));
  try {
    writeFileSync(
      resolve(directory, "package.json"),
      JSON.stringify({ private: true, type: "module" }),
    );
    run(
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
    run("npm", ["audit", "signatures", "--registry", registry], directory);
    run(
      "node",
      [
        "--input-type=module",
        "-e",
        `await Promise.all(${JSON.stringify(names.map(packageName))}.map((name) => import(name)));`,
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

const recoveryVersion = "0.1.0-alpha.2";
const previousVersion = "0.1.0-alpha.1";
const recoveryManifestSha256 =
  "b45f479d247763b87d73b8e616af989cc2afc87f9d495087f08bdaac10417839";
const recoverySourceCommit = "b3d776686b1e56fbb1a64a86c42ca461f998e8e7";
const recoveryMirrorCommit = "7108cfad85623225d6f429aa6c43078da758d236";
const recoveryRunUrl =
  "https://github.com/trevor-gibby/capaxle-public/actions/runs/36022752069/attempts/1";

export function validateRecoveryRecord(record, candidate, candidateDigest) {
  assertExactKeys(
    record,
    [
      "version",
      "registry",
      "distTag",
      "publicRepository",
      "candidateSha256",
      "originalSourceCommit",
      "originalMirrorCommit",
      "originalRunUrl",
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
    record.originalSourceCommit !== recoverySourceCommit ||
    record.originalMirrorCommit !== recoveryMirrorCommit ||
    record.originalRunUrl !== recoveryRunUrl ||
    record.previousVersion !== previousVersion
  )
    throw new Error(
      "CAP_RELEASE_RECOVERY_RECORD_INVALID: approved source or candidate changed",
    );
  assert.deepEqual(record.publishedPrefix, [
    {
      name: packageName("ir"),
      sha256: candidate.packages[packageName("ir")],
    },
  ]);
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

async function verifyRegistryPackage(
  name,
  approval,
  latest,
  sourceCommit,
  runUrl,
  attempts = 96,
) {
  const expected = approval.packages[packageName(name)];
  for (let attempt = 0; attempt < attempts; attempt++) {
    const packument = await getPackument(name);
    if (!packument || packument.name !== packageName(name))
      throw new Error(`${packageName(name)}: package is unavailable`);
    const exists = versionExists(packument, approval.version);
    const version = exists ? packument.versions[approval.version] : null;
    if (exists && (!version || typeof version !== "object"))
      throw new Error(
        `${packageName(name)}: invalid published version metadata`,
      );
    if (packument["dist-tags"]?.latest !== latest)
      throw new Error(`${packageName(name)}: latest tag changed`);
    if (version) {
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
      const bytes = Buffer.from(await response.arrayBuffer());
      if (sha256(bytes) !== expected)
        throw new Error(
          `${packageName(name)}: registry bytes differ from approval`,
        );
      if (
        packument["dist-tags"]?.[distTag] === approval.version &&
        version.dist?.attestations
      ) {
        if (
          version.dist.attestations.url !==
            attestationUrl(name, approval.version) ||
          version.dist.attestations.provenance?.predicateType !==
            "https://slsa.dev/provenance/v1"
        )
          throw new Error(`${packageName(name)}: provenance reference changed`);
        const attestationResponse = await globalThis.fetch(
          version.dist.attestations.url,
          {
            cache: "no-store",
            signal: globalThis.AbortSignal.timeout(30_000),
          },
        );
        if (attestationResponse.status === 404) {
          await delay(2_500);
          continue;
        }
        if (!attestationResponse.ok)
          throw new Error(
            `${packageName(name)}: provenance HTTP ${attestationResponse.status}`,
          );
        validateProvenance(
          await attestationResponse.json(),
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
    await delay(2_500);
  }
  throw new Error(`${packageName(name)}: registry version/tags did not verify`);
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
    upload,
    env = process.env,
    report = console.error,
  } = {},
) {
  if (typeof upload !== "function")
    throw new Error(
      "CAP_RELEASE_UPLOAD_UNAUTHORIZED: validated CLI entry required",
    );
  try {
    const inventory = new Map();
    for (const name of packageNames)
      inventory.set(name, await readPackument(name));
    const order = recovery
      ? validateRecoveryInventory(inventory, candidate, recovery)
      : publicationOrder();
    const previousLatest = new Map();
    const previousAlpha = new Map();
    if (recovery) {
      await verifyPackage(
        "ir",
        candidate,
        recovery.previousVersion,
        recovery.originalMirrorCommit,
        recovery.originalRunUrl,
      );
      await installRegistry(candidate.version, ["ir"]);
      for (const name of packageNames)
        previousLatest.set(name, recovery.previousVersion);
      for (const name of packageNames)
        previousAlpha.set(name, recovery.previousVersion);
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
        previousLatest.set(name, packument["dist-tags"]?.latest);
        previousAlpha.set(name, packument["dist-tags"]?.[distTag]);
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
      );
      console.log(
        `${packageName(name)}@${candidate.version}: registry bytes, tags, and provenance verified`,
      );
    }
    for (const name of packageNames) {
      const fromOriginalRun = recovery?.publishedPrefix.some(
        (entry) => entry.name === packageName(name),
      );
      await verifyPackage(
        name,
        candidate,
        previousLatest.get(name),
        fromOriginalRun
          ? recovery.originalMirrorCommit
          : env.RELEASE_MIRROR_COMMIT,
        fromOriginalRun ? recovery.originalRunUrl : currentRunUrl,
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
  const recovery =
    candidate.version === recoveryVersion
      ? validateRecoveryRecord(
          readJson(recoveryPath),
          candidate,
          process.env.RELEASE_MANIFEST_SHA256,
        )
      : null;
  await publishTrain(candidate, recovery, { upload: uploadArchive });
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
