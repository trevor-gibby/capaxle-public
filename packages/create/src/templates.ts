export const frameworkVersion = "0.1.0-alpha.3";
export const templates = ["default", "protected", "existing-server"] as const;
export type Template = (typeof templates)[number];

const json = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;

export function templateFiles(
  name: string,
  template: Template,
): Readonly<Record<string, string>> {
  const protectedExample = template === "protected";
  const embedded = template === "existing-server";
  const basePath = embedded ? "/capabilities" : "/";
  const files: Record<string, string> = {
    "package.json": json({
      name,
      version: "0.0.0",
      private: true,
      type: "module",
      engines: { node: "^22.15.0 || ^24.0.0" },
      scripts: {
        dev: "node --env-file-if-exists=.env server.mjs",
        build: "node --env-file-if-exists=.env scripts/build.mjs",
        start: "node --env-file-if-exists=.env server.mjs --production",
        check: "tsc --noEmit --types node && capaxle check",
        doctor: "capaxle doctor --json",
      },
      dependencies: { "@capaxle/app": frameworkVersion },
      devDependencies: {
        "@capaxle/client": frameworkVersion,
        "@capaxle/cli": frameworkVersion,
        "@types/node": "22.20.1",
        typescript: "6.0.3",
      },
    }),
    ".gitignore": "node_modules/\n.env\nexecutable/\ndeployment/\n.capaxle/\n",
    ".env.example": `HOST=127.0.0.1\nPORT=3000\n# Set the operator-controlled URL when deploying behind a proxy.\n# EXTERNAL_URL=https://application.example${embedded ? basePath : ""}\n${protectedExample ? "# Supply an externally provisioned credential; this example does not issue tokens.\nAPPLICATION_TOKEN=\n" : ""}`,
    "tsconfig.json": json({
      compilerOptions: {
        target: "ES2022",
        module: "ESNext",
        moduleResolution: "Bundler",
        strict: true,
        noEmit: true,
      },
      include: ["src/**/*.ts"],
    }),
    "capaxle.config.ts": `export default {\n  service: { name: ${JSON.stringify(name)}, version: "0.0.0", title: ${JSON.stringify(name)} },\n  exposureDefaults: { http: "public", cli: "public", mcp: "public", internal: "private" },\n  adapters: { cli: { remoteOnly: true } },\n};\n`,
    "config.mjs": `// Process-local example data: lost on restart, separate in each process. No database.\nexport const notes = new Map([["example", "Hello Capaxle"]]);\nexport const serviceId = ${JSON.stringify(name)};\nexport const basePath = ${JSON.stringify(basePath)};\nexport const host = process.env.HOST ?? "127.0.0.1";\nexport const port = Number(process.env.PORT ?? 3000);\nexport const localUrl = \`http://\${host.includes(":") ? "[" + host + "]" : host}:\${port}\${basePath === "/" ? "" : basePath}\`;\nexport const externalUrl = process.env.EXTERNAL_URL;\nexport const developmentUrl = externalUrl ?? localUrl;\n// Trusted MCP host policy comes from configured locations, never request headers.\nif (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be an integer from 1 to 65535.");\nconst mcpHosts = [...new Set([new URL(localUrl).host, ...(externalUrl ? [new URL(externalUrl).host] : [])])];\nexport const surfaces = Object.fromEntries(["http", "mcp", "cli", "docs"].map(kind => [kind, { enabled: true, providerId: "example.auth" }]));\nsurfaces.mcp.allowedHosts = mcpHosts;\nexport const deploymentContext = { serviceId, basePath, ...(externalUrl ? { externalUrl } : {}), surfaces: { http: true, mcp: true, cli: true, docs: true }, transport: { mcp: { allowedHosts: mcpHosts } } };\nexport function providers() {\n${protectedExample ? `  const token = process.env.APPLICATION_TOKEN;\n  if (!token) throw new Error("APPLICATION_TOKEN must be provisioned before starting the protected example.");\n  const authenticate = credentials => credentials === \`Bearer \${token}\` ? {\n    providerId: "example.auth", type: "service", subject: "example-agent", roles: [], scopes: [], claims: {}\n  } : null;\n` : "  // Anonymous example only; deploy with a real authentication provider.\n  const authenticate = () => null;\n"}  return { authenticationProviders: [{ id: "example.auth", authenticate, authenticateDisclosure: authenticate }] };\n}\n`,
    "src/capabilities/notes/get.ts": `import { defineCapability, type CapabilityContext } from "@capaxle/app";\nimport { z } from "@capaxle/app/zod";\n${embedded ? 'import { readNote } from "../../lib/business.js";\n' : ""}\nexport default defineCapability({\n  summary: "Read one process-local note",\n  authentication: "${protectedExample ? "required" : "public"}",\n  permissions: "public",\n  input: z.strictObject({ noteId: z.string().min(1) }),\n  output: z.strictObject({ text: z.string() }),\n  effects: { impact: "read" },\n  examples: [{ name: "Read sample", input: { noteId: "example" }, output: { text: "Hello Capaxle" } }],\n  handler: ({ noteId }, ctx: CapabilityContext<{ notes: Map<string, string> }>) => ({\n    text: ${embedded ? "readNote(ctx.services.notes, noteId)" : 'ctx.services.notes.get(noteId) ?? ""'},\n  }),\n});\n`,
    "src/capabilities/notes/set.ts": `import { defineCapability, type CapabilityContext } from "@capaxle/app";\nimport { z } from "@capaxle/app/zod";\n\nexport default defineCapability({\n  summary: "Write one process-local note",\n  authentication: "${protectedExample ? "required" : "public"}",\n  permissions: "public",\n  input: z.strictObject({ noteId: z.string().min(1), text: z.string() }),\n  output: z.strictObject({ text: z.string() }),\n  effects: { impact: "write", confirmation: "none", idempotency: "none" },\n  handler: ({ noteId, text }, ctx: CapabilityContext<{ notes: Map<string, string> }>) => {\n    ctx.services.notes.set(noteId, text);\n    return { text };\n  },\n});\n`,
    "scripts/build.mjs": `import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";\nimport { resolve, join, dirname } from "node:path";\nimport ts from "typescript";\nimport { buildDeployment } from "@capaxle/app/build";\nimport { deploymentContext } from "../config.mjs";\nconst projectRoot = resolve(import.meta.dirname, "..");\nconst executableRoot = join(projectRoot, "executable");\nawait rm(executableRoot, { recursive: true, force: true });\nawait mkdir(executableRoot);\nawait writeFile(join(executableRoot, "package.json"), '{"type":"module"}\\n');\nasync function emit(relative = "") {\n  for (const entry of await readdir(join(projectRoot, "src", relative), { withFileTypes: true })) {\n    const source = join(relative, entry.name);\n    if (entry.isDirectory()) { await emit(source); continue; }\n    if (!entry.isFile() || !source.endsWith(".ts")) throw new Error("Unsupported executable source.");\n    const output = ts.transpileModule(await readFile(join(projectRoot, "src", source), "utf8"), {\n      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext }, fileName: source,\n    }).outputText;\n    const destination = join(executableRoot, source.replace(/\\.ts$/, ".js"));\n    await mkdir(dirname(destination), { recursive: true });\n    await writeFile(destination, output);\n  }\n}\nawait emit();\nconst built = await buildDeployment({ projectRoot, executableRoot, outDir: join(projectRoot, "deployment"), deploymentContext });\nconsole.log(built.manifest);\n`,
    "server.mjs": `import { createApplication } from "@capaxle/app";\n${embedded ? 'import { createServer } from "node:http";\n' : ""}import { notes, serviceId, basePath, host, port, externalUrl, developmentUrl, localUrl, surfaces, providers } from "./config.mjs";\nconst projectRoot = import.meta.dirname;\nconst app = await createApplication({\n  ...(process.argv.includes("--production") ? { mode: "production", deployment: { manifest: \`\${projectRoot}/deployment/capaxle.deployment.json\` }, ...(externalUrl ? { externalUrl } : {}) } : { mode: "development", projectRoot, externalUrl: developmentUrl }),\n  serviceId, basePath, surfaces, providers: providers(), services: { notes },\n});\n${embedded ? `// Mount before body parsers/fallbacks. Unmatched request bodies remain untouched.\n// Existing routes keep their own authentication; req.user never authenticates capabilities.\nconst server = createServer((req, res) => app.middleware(req, res, error => {\n  if (error) { res.writeHead(500).end("Existing application failure"); return; }\n  if (req.url === "/existing" && req.method === "GET") {\n    res.setHeader("Content-Type", "application/json");\n    res.end(JSON.stringify({ existing: true })); return;\n  }\n  if (req.url === "/echo" && req.method === "POST") {\n    // The original application's authentication and body handling still own this route.\n    if (req.headers.authorization !== "Bearer existing-application") { res.writeHead(401).end(); return; }\n    const chunks = [];\n    req.on("data", chunk => chunks.push(chunk));\n    req.on("end", () => { res.setHeader("Content-Type", "application/json"); res.end(Buffer.concat(chunks)); });\n    return;\n  }\n  res.writeHead(404).end();\n}));\nawait new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, resolve); });\n` : "await app.listen({ host, port });\n"}console.log(\`Ready: \${localUrl}/.well-known/capabilities (API), \${localUrl}/mcp, \${localUrl}/cli, \${localUrl}/docs/connection\`);\nlet closing = false;\nasync function close() {\n  if (closing) return;\n  closing = true;\n${embedded ? "  const listenerClosed = new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));\n  await Promise.all([listenerClosed, app.close()]);\n" : "  await app.close();\n"}}\nprocess.once("SIGINT", close);\nprocess.once("SIGTERM", close);\n`,
  };
  if (embedded)
    files["src/lib/business.ts"] =
      '// Stand-in for an existing business function. The capability wraps it.\nexport function readNote(notes: Map<string, string>, noteId: string): string {\n  return notes.get(noteId) ?? "";\n}\n';
  files["README.md"] = readme(name, template, basePath);
  return Object.freeze(files);
}

function readme(name: string, template: Template, basePath: string): string {
  const protectedExample = template === "protected";
  const embedded = template === "existing-server";
  const url = `http://127.0.0.1:3000${embedded ? basePath : ""}`;
  return `# ${name}

Node 22.15+ on the Node 22 line or Node 24.0+ on the Node 24 line.
One JavaScript server hosts TypeScript capabilities through the shared kernel.
The Map is process-local: restart loses data, multiple processes do not share it.
This example has no database, durable storage, tenant isolation or production authentication.
${protectedExample ? "The protected example accepts an externally provisioned APPLICATION_TOKEN. It does not issue credentials or implement managed login. Both capabilities require canonical authentication; denied callers never enter their handlers." : "The default capabilities are public. Add a real authentication provider and require canonical authentication before exposing sensitive operations."}

\`\`\`sh
npm install
cp .env.example .env
${protectedExample ? "# Provision APPLICATION_TOKEN in .env through your existing credential mechanism.\n" : ""}npm run check
npm run dev
\`\`\`

From another terminal (the shell must also have APPLICATION_TOKEN for protected calls):

\`\`\`sh
npx capaxle-client profiles add local --url ${url} --allow-http-loopback${protectedExample ? " --credential-env APPLICATION_TOKEN" : ""}
npx capaxle-client --profile local -- capabilities list --json --no-input
npx capaxle-client --profile local -- notes set --note-id example --text Updated --json --no-input
npx capaxle-client --profile local -- notes get --note-id example --json --no-input
npx capaxle-client --profile local doctor --json --no-input --mcp-path /mcp --mcp-protocol 2026-07-28
npm run doctor
\`\`\`

The exact @capaxle/client dependency installs the generic client locally.
For a remote consumer after approved publication: \`npm install -g @capaxle/client@${frameworkVersion}\`.
The source package set remains unpublished until its separately approved release;
source acceptance installs the matching packed dependency closure instead.
Use credential references (env/file), never token values in argv. Agent use is
non-interactive. Human login requires your own configured trusted auth hook;
\`capaxle-client --profile local auth login\` is supported only after configuring it.

Browser reference: ${url}/docs/ and connection guidance: ${url}/docs/connection.
API discovery: ${url}/.well-known/capabilities; MCP: ${url}/mcp; remote CLI: ${url}/cli.
Configure an MCP client using:

\`\`\`json
{ "mcpServers": { "${name}": { "type": "http", "url": "${url}/mcp"${protectedExample ? ', "headers": { "Authorization": "Bearer <APPLICATION_TOKEN>" }' : ""} } } }
\`\`\`

Replace the credential placeholder with your client application's secret reference
mechanism. Never commit a credential. The connection page shows the trusted locations;
the host does not infer them from request headers. Set EXTERNAL_URL explicitly for a
reverse proxy, with HTTPS for deployed services. Change PORT/HOST in .env as needed.
The default development listener supplies a trusted local URL. Production build/start
omit advertised authority unless EXTERNAL_URL is explicitly set to an operator-owned
HTTPS URL; the production connection page then explains the unconfigured location.
The printed local listener URL and the local client commands still work. Configure
EXTERNAL_URL before build/start when publishing verified deployed connection guidance.

All templates require an integer PORT from 1 to 65535. MCP trusts only the configured
listener and optional operator EXTERNAL_URL authorities; no request headers determine
trusted hosts. Build pins the same host policy used at startup. Rebuild after changing
HOST, PORT or EXTERNAL_URL; production rejects host-policy drift. Wildcard/public
listeners require an explicit reachable authority through EXTERNAL_URL.

Stop the development server before production startup:

\`\`\`sh
npm run check
npm run build
npm start
\`\`\`

Build emits TypeScript modules in executable/ and verifies a deployment in deployment/.
Start loads the verified manifest and rejects modified modules. Build and start load
the same .env settings to pin PORT/EXTERNAL_URL consistently.
Keep both output directories and installed dependencies together. Production still
uses process-local data and this example provider; these scripts do not confer production readiness.
Local doctor checks source configuration; remote doctor verifies discovery/schema/MCP
on the configured listener. JSON diagnostics expose stable machine-readable codes.
${
  embedded
    ? `
## Existing-server integration

This directory is an isolated integration example. The initializer has not modified
your host routes, package scripts, dependencies or authentication. Install the exact
@capaxle/app dependency in your host; TypeScript 6.0.3 and @capaxle/cli@${frameworkVersion}
provide the check/build workflow. Adapt server.mjs into your server deliberately:
create the application once, mount app.middleware before generic body parsing/fallback,
and retain your existing listener and routes. Close app when your listener shuts down.
The notes/get capability wraps src/lib/business.ts, representing one existing business
function. The original GET /existing and authenticated POST /echo routes remain owned
by the host. /echo requires the illustrative existing-application bearer credential;
its body is untouched by unmatched Capaxle middleware. Capabilities mount at /capabilities
so host routes remain separate. Embedded MCP uses an explicit allowedHosts array from
the configured listener and optional operator external URL; build pins the same policy.
Use a nonzero PORT (1–65535). Rebuild after changing HOST, PORT or EXTERNAL_URL;
production rejects host-policy drift. Wildcard/public listeners require an explicit
reachable authority through EXTERNAL_URL. No
request headers determine trusted hosts. A trusted authentication provider must verify your
existing identity carrier; req.user and a parsed body are never trusted as capability identity.
`
    : ""
}`;
}
