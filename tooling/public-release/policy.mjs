import { createHash } from "node:crypto";

export const historicalPackageEdges = Object.freeze({
  ir: [],
  core: ["ir"],
  "schema-zod": ["core", "ir"],
  compiler: ["core", "ir"],
  runtime: ["core", "ir"],
  "adapter-http": ["runtime", "ir"],
  "adapter-cli": ["runtime", "ir"],
  "adapter-mcp": ["runtime", "ir"],
  "generator-docs": ["ir"],
  "generator-sdk-ts": ["ir"],
  cli: [
    "ir",
    "schema-zod",
    "compiler",
    "runtime",
    "adapter-http",
    "adapter-cli",
    "adapter-mcp",
    "generator-docs",
    "generator-sdk-ts",
  ],
});

export const historicalPackageNames = Object.freeze(
  Object.keys(historicalPackageEdges),
);
export const packageEdges = Object.freeze({
  ...historicalPackageEdges,
  "docs-styles": [],
  app: [
    "core",
    "ir",
    "schema-zod",
    "compiler",
    "runtime",
    "adapter-http",
    "adapter-cli",
    "adapter-mcp",
    "generator-docs",
    "docs-styles",
  ],
  client: ["ir"],
  create: [],
  cli: [...historicalPackageEdges.cli, "app"],
});
export const packageNames = Object.freeze(Object.keys(packageEdges));
export const packageNamesForVersion = (version) =>
  ["0.1.0-alpha.1", "0.1.0-alpha.2"].includes(version)
    ? historicalPackageNames
    : packageNames;
const edgesForVersion = (version) =>
  ["0.1.0-alpha.1", "0.1.0-alpha.2"].includes(version)
    ? historicalPackageEdges
    : packageEdges;
export const registry = "https://registry.npmjs.org/";
export const distTag = "alpha";
const hex40 = /^[a-f0-9]{40}$/;
const hex64 = /^[a-f0-9]{64}$/;
const alphaVersion = /^0\.\d+\.\d+-alpha\.\d+$/;

export function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function assertExactKeys(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label}: expected object`);
  const actual = Object.keys(value).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...keys].sort()))
    throw new Error(`${label}: unexpected or missing keys`);
}

export function validateCandidate(candidate, repository) {
  assertExactKeys(
    candidate,
    ["publicRepository", "version", "registry", "distTag", "packages"],
    "release candidate",
  );
  if (!alphaVersion.test(candidate.version))
    throw new Error("release candidate: invalid alpha version");
  if (candidate.registry !== registry || candidate.distTag !== distTag)
    throw new Error("release candidate: registry or dist-tag changed");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository))
    throw new Error("release candidate: invalid public repository");
  if (candidate.publicRepository !== repository)
    throw new Error("release candidate: public repository changed");
  assertExactKeys(
    candidate.packages,
    packageNamesForVersion(candidate.version).map((name) => `@capaxle/${name}`),
    "release candidate packages",
  );
  for (const [name, digest] of Object.entries(candidate.packages))
    if (!hex64.test(digest))
      throw new Error(`release candidate: invalid SHA-256 for ${name}`);
  return candidate;
}

export function validateSource(source, approvedCommit, repository) {
  assertExactKeys(
    source,
    ["sourceCommit", "publicRepository", "preview", "filesSha256"],
    "public source record",
  );
  if (!hex40.test(approvedCommit) || source.sourceCommit !== approvedCommit)
    throw new Error("release approval: source commit changed");
  if (
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) ||
    source.publicRepository !== repository
  )
    throw new Error("release approval: public repository changed");
  if (source.preview !== false)
    throw new Error("public source record: preview snapshot cannot publish");
  const files = source.filesSha256;
  if (
    !files ||
    typeof files !== "object" ||
    Array.isArray(files) ||
    Object.keys(files).length === 0 ||
    Object.entries(files).some(
      ([path, digest]) => path.length === 0 || !hex64.test(digest),
    )
  )
    throw new Error("public source record: invalid file SHA-256 map");
}

export function validatePackageManifest(manifest, name, version, repository) {
  const fullName = `@capaxle/${name}`;
  if (manifest.name !== fullName || manifest.version !== version)
    throw new Error(`${fullName}: package identity or version changed`);
  if (manifest.private !== undefined || manifest.license !== "Apache-2.0")
    throw new Error(`${fullName}: package must be public and Apache-2.0`);
  if (
    manifest.publishConfig?.access !== "public" ||
    manifest.publishConfig?.tag !== distTag
  )
    throw new Error(`${fullName}: publish configuration changed`);
  if (
    manifest.repository?.type !== "git" ||
    manifest.repository?.url !== `https://github.com/${repository}.git` ||
    manifest.repository?.directory !== `packages/${name}`
  )
    throw new Error(
      `${fullName}: repository provenance does not match public repo`,
    );

  if (name === "docs-styles") {
    if (
      JSON.stringify(manifest.exports) !==
        JSON.stringify({ "./docs.css": "./docs.css" }) ||
      JSON.stringify(manifest.files) !==
        JSON.stringify(["docs.css", "README.md", "LICENSE"]) ||
      [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
        "bin",
        "main",
        "types",
        "scripts",
      ].some((field) => manifest[field] !== undefined)
    )
      throw new Error(`${fullName}: CSS-only package surface changed`);
  }
  if (["app", "client", "create"].includes(name)) {
    const entries = name === "app" ? [".", "./zod", "./build"] : ["."];
    assertExactKeys(manifest.exports, entries, `${fullName} exports`);
    for (const entry of entries) {
      const stem = entry === "." ? "index" : entry.slice(2);
      assertExactKeys(
        manifest.exports[entry],
        ["types", "import"],
        `${fullName} export ${entry}`,
      );
      if (
        manifest.exports[entry].types !== `./dist/${stem}.d.ts` ||
        manifest.exports[entry].import !== `./dist/${stem}.js`
      )
        throw new Error(`${fullName}: export target changed`);
    }
    if (
      name === "app"
        ? manifest.bin !== undefined
        : JSON.stringify(manifest.bin) !==
          JSON.stringify({
            [name === "client" ? "capaxle-client" : "create-capaxle"]:
              "./dist/bin.js",
          })
    )
      throw new Error(`${fullName}: binary surface changed`);
  }

  if (
    ["create", "client"].includes(name) &&
    Object.keys(manifest.dependencies ?? {}).some(
      (dependency) => !dependency.startsWith("@capaxle/"),
    )
  )
    throw new Error(`${fullName}: unexpected external dependency`);

  const actualEdges = Object.entries(manifest.dependencies ?? {})
    .filter(([dependency]) => dependency.startsWith("@capaxle/"))
    .map(([dependency, pinned]) => {
      if (pinned !== version)
        throw new Error(`${fullName}: ${dependency} must pin ${version}`);
      return dependency.slice("@capaxle/".length);
    })
    .sort();
  if (
    JSON.stringify(actualEdges) !==
    JSON.stringify([...edgesForVersion(version)[name]].sort())
  )
    throw new Error(`${fullName}: internal dependency graph changed`);
  for (const field of [
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
  ])
    if (
      Object.keys(manifest[field] ?? {}).some((dependency) =>
        dependency.startsWith("@capaxle/"),
      )
    )
      throw new Error(`${fullName}: unexpected internal ${field}`);
}

export function publicationOrder(version) {
  const edges = edgesForVersion(version);
  const sorted = [];
  const visited = new Set();
  const visit = (name) => {
    if (visited.has(name)) return;
    for (const dependency of edges[name]) visit(dependency);
    visited.add(name);
    sorted.push(name);
  };
  for (const name of packageNamesForVersion(version)) visit(name);
  return sorted;
}
