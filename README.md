# Capaxle

This repository is a read-only source mirror for the public packages. Its
contents are updated from the project's development repository after checks
pass; direct changes here are not part of the release source.

Capaxle is a TypeScript framework for describing an application operation once
and using it through several interfaces. We call each operation a **capability**.
For example, an application might define `notes.get` once and let a web app, a
command line, or an AI agent call it through HTTP, CLI, or MCP.

The same runtime checks the input and applies the capability's access and safety
rules each time it runs. That means the HTTP endpoint and the agent tool do not
need separate copies of your business logic.

> **Alpha:** the eleven framework packages are published as
> `0.1.0-alpha.1`. This source mirror contains an unpublished
> `0.1.0-alpha.2` candidate. APIs can change. Pin an exact version when
> installing.

## Getting started

Capaxle currently targets Node.js 22.15 or later in the 22.x line, or Node.js
24 or later in the 24.x line. The authoring API uses TypeScript and Zod.

Install the packages for authoring and compiling a project. Pinning this
example to the currently published version makes it repeatable; use a newer
exact version after a later alpha is published.

```sh
npm init -y
npm pkg set type=module
npm install @capaxle/core@0.1.0-alpha.1 @capaxle/schema-zod@0.1.0-alpha.1 @capaxle/compiler@0.1.0-alpha.1 @capaxle/cli@0.1.0-alpha.1
```

Here is a small capability that greets a reader. Save it in your project's
capabilities directory, for example as `src/capabilities/hello/greet.ts`:

```ts
import { defineCapability } from "@capaxle/core";
import { z } from "@capaxle/schema-zod";

export default defineCapability({
  summary: "Greet a reader",
  input: z.strictObject({ name: z.string() }),
  output: z.strictObject({ greeting: z.string() }),
  authentication: "public",
  permissions: "public",
  exposure: { cli: "public" },
  effects: { impact: "read" },
  handler(input) {
    return { greeting: `Hello, ${input.name}!` };
  },
});
```

Create `capaxle.config.ts` in the project root:

```ts
export default {
  service: { name: "hello", version: "1.0.0" },
  adapters: { cli: { binaryName: "hello" } },
};
```

Then check the project and invoke the capability:

```sh
npx capaxle check
npx capaxle invoke hello.greet --input '{"name":"Ada"}' --json
```

The framework derives the capability ID `hello.greet` from the file path. The
input and output schemas describe the JSON values that callers send and receive.
The handler contains the application behavior; interface adapters forward
requests to the shared runtime.

The command line package includes `capaxle check`, `build`, `list`, `describe`,
`invoke`, and `dev`. It needs a project configuration and its compiler/schema
providers. Start with `check` to catch invalid definitions before invoking a
capability.

## Packages

The packages below are published separately on one version train. Most
applications start with the authoring and compiler packages and add interfaces
as needed.
Every package is currently an alpha release.

<a id="package-core"></a>

### `@capaxle/core`

Defines capabilities and the public TypeScript context and type contracts.
Use `defineCapability` in each capability source file.

```ts
import { defineCapability } from "@capaxle/core";
```

For a full definition, see the [greeting example above](#getting-started).

[npm package](https://www.npmjs.com/package/@capaxle/core)

<a id="package-schema-zod"></a>

### `@capaxle/schema-zod`

Provides Zod and Capaxle's portable schema helpers and compiler provider. Use
`z` to define strict input and output schemas; use `portableDefault` when a
portable default is needed.

```ts
import { portableDefault, z } from "@capaxle/schema-zod";

const input = z.strictObject({ name: portableDefault(z.string(), "reader") });
```

Use a schema created with `z` as a capability's `input` or `output`.

[npm package](https://www.npmjs.com/package/@capaxle/schema-zod)

<a id="package-ir"></a>

### `@capaxle/ir`

Defines the JSON-only Capability IR and helpers for validating, canonicalizing,
and hashing capability documents. Most application authors do not need to
construct IR directly.

```ts
import { capabilitySemanticHash, validateCapabilityDocument } from "@capaxle/ir";

const issues = validateCapabilityDocument(document);
if (issues.length === 0) console.log(capabilitySemanticHash(document));
```

Here `document` is a normalized Capability IR document.

[npm package](https://www.npmjs.com/package/@capaxle/ir)

<a id="package-compiler"></a>

### `@capaxle/compiler`

Finds capability files, checks their schemas, compiles the project, and creates
the artifact graph consumed by the runtime and generators.

```ts
import { compileProject } from "@capaxle/compiler";
import { zodSchemaProvider } from "@capaxle/schema-zod";

const result = await compileProject({
  projectRoot: process.cwd(),
  schemaProviders: [zodSchemaProvider],
});
if (!result.ok) console.error(result.diagnostics);
```

Projects need a Capaxle configuration and a schema provider.
[npm package](https://www.npmjs.com/package/@capaxle/compiler)

<a id="package-runtime"></a>

### `@capaxle/runtime`

Builds a runtime registry and the shared policy-enforcing invocation kernel.
Hosts use it to validate calls and execute capabilities consistently.

Given a successful `compileProject` result named `compiled`:

```ts
import { createRuntimeKernel, createRuntimeRegistry } from "@capaxle/runtime";

const registry = createRuntimeRegistry({
  document: compiled.document,
  irHash: compiled.irHash,
  bindings: compiled.runtimeBindings,
  validators: compiled.validators,
});
const kernel = createRuntimeKernel({ registry });
```

Add the host providers required by the policies used in your capabilities.

Host composition requires compiled artifacts and appropriate providers for the
policies your capabilities use.
[npm package](https://www.npmjs.com/package/@capaxle/runtime)

<a id="package-adapter-http"></a>

### `@capaxle/adapter-http`

Projects capabilities as HTTP requests and produces OpenAPI and discovery data.
Every invocation goes through the shared runtime kernel.

```ts
import { createHttpAdapter, startHttpHost } from "@capaxle/adapter-http";

const http = createHttpAdapter({ document, irHash, ingress });
```

The runtime kernel creates `ingress` for the registered host adapter.

[npm package](https://www.npmjs.com/package/@capaxle/adapter-http)

<a id="package-adapter-cli"></a>

### `@capaxle/adapter-cli`

Creates an application command line interface from compiled capabilities and
can export an OpenCLI description. Application hosts compose it with the
compiler and runtime.

```ts
import { createCliAdapter, runCliProcess } from "@capaxle/adapter-cli";

const cli = createCliAdapter({ document, irHash, cliBinary: "hello", ingress });
```

[npm package](https://www.npmjs.com/package/@capaxle/adapter-cli)

<a id="package-adapter-mcp"></a>

### `@capaxle/adapter-mcp`

Exposes capabilities to MCP clients as tools and can produce agent manifests.
MCP calls are handled by the shared runtime.

```ts
import { createMcpAdapter, startMcpHost } from "@capaxle/adapter-mcp";

const mcp = createMcpAdapter({ document, irHash, ingress, discovery });
```

[npm package](https://www.npmjs.com/package/@capaxle/adapter-mcp)

<a id="package-generator-docs"></a>

### `@capaxle/generator-docs`

Generates a documentation and JSON Schema bundle from compiled capabilities.
It includes capability descriptions and examples for people and tools.

```ts
import { generateDocsSchemaArchive } from "@capaxle/generator-docs";

const archive = generateDocsSchemaArchive(document, { irHash });
```

The compiler-facing producer is re-exported by the CLI package for project
builds.
[npm package](https://www.npmjs.com/package/@capaxle/generator-docs)

<a id="package-generator-sdk-ts"></a>

### `@capaxle/generator-sdk-ts`

Generates TypeScript declarations for the internal capability facade and the
HTTP TypeScript SDK from compiled capabilities.

```ts
import { generateSdkHttp, generateInternalFacade } from "@capaxle/generator-sdk-ts";

const sdk = generateSdkHttp({ document, irHash });
```

Compiler-facing producers are re-exported by the CLI package for project
builds.
[npm package](https://www.npmjs.com/package/@capaxle/generator-sdk-ts)

<a id="package-cli"></a>

### `@capaxle/cli`

Provides the `capaxle` project command line: `check`, `build`, `list`,
`describe`, `invoke`, and the HTTP development host command `dev`.

```sh
npx capaxle check
npx capaxle describe hello.greet
```

Run these from a configured Capaxle project.
[npm package](https://www.npmjs.com/package/@capaxle/cli)

## How Capaxle fits together

You describe a capability in TypeScript. The compiler converts that description
to the language-neutral Capability IR. Adapters turn the same compiled
capability into HTTP, CLI, and MCP interfaces, while documentation and SDK
generators create useful artifacts. Calls from every interface reach the same
runtime, which validates inputs and enforces the capability's runtime policies.

```text
TypeScript capability -> compiler -> Capability IR -> interfaces and artifacts
                                                -> shared runtime -> handler
```

The IR is plain JSON data. It does not contain executable handlers, secrets, or
transport request objects. Adapters do not implement application policy.

## Explore the source

To build the public source mirror locally, run:

```sh
npm ci --ignore-scripts
npm run check:public
```

`check:public` typechecks the public package source. Release checks also run in
the project's development repository before a mirror update.
