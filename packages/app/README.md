# @capaxle/app

Application composition and lifecycle for Capaxle capabilities. `createApplication`
prepares one shared runtime generation for the enabled HTTP, MCP, CLI, and browser documentation surfaces.
See the repository examples for a standalone listener and embedded middleware.

Enable remote CLI with `surfaces: { cli: { enabled: true, providerId } }`. The
application mounts collection, detail, schema, and invocation routes under
`basePath` and uses the selected authentication provider for CLI ingress.
Credential-bearing discovery requires that provider's `authenticateDisclosure`
hook. Without it, anonymous public discovery remains available, while a
discovery request presenting credentials fails closed with
`CAP_DEPENDENCY_UNAVAILABLE`. Invocation authenticates separately through
`authenticate`. CLI routes and payload limits are part of the verified
deployment context; an operator may set `externalUrl` for advertised location.
Private CLI discovery requires `allowPrivateDiscovery: true`, a process-local
`disclosureSelector`, and the selected provider's `authenticateDisclosure` hook.
Production deployments must pin the private flag in their transport context.
Only verified callers selected by that restriction can discover private entries;
the kernel still authenticates and authorizes each invocation.

`buildDeployment` includes an agent manifest `0.2` artifact. When remote CLI is
enabled, its CLI locator uses the same mounted paths and external URL as the
production host. `deploymentContext.cliEndpoints` pins custom unmounted CLI
paths by role; omission selects the four defaults. The four CLI reservations
must match that role map. A local CLI command appears only when the project
declares a real CLI binary; the remote locator does not create one.

`buildDeployment` verifies a narrow TypeScript 6 ESM build profile before
packaging executable modules. The emitted tree must contain `package.json`
with `type: "module"` and exact ESNext/ES2022 TypeScript output for every
capability source and its runtime relative imports. A project `tsconfig.json`,
when present, must use ES2022 and ESNext or NodeNext with only the supported
non-emission options; `noEmit` is overridden for this proof. Bundled output,
custom transforms, extra executable modules, and stale emitted bytes are
rejected. Rebuild `executableRoot` from current source before calling
`buildDeployment`. Production startup reads only the verified deployment.
The read-only `inspectDeployment` API is exported from `@capaxle/app/build` for
diagnostic tooling. It verifies the manifest and packaged artifact consistency;
pass deployment expectations to check host agreement. Self-consistency alone
does not prove runtime provider registration, readiness or host configuration.

Enable browser reference pages with `surfaces: { docs: { enabled: true, providerId } }`.
The application mounts `/docs/`, `/docs/connection`, grouped capability pages and
linked JSON Schemas under `basePath`; no per-file registration is required.
Set `docs.path` to a canonical unmounted non-root path such as `/reference`.
Set `docs.externalUrl` to an independent public documentation root such as
`https://docs.example/` when an operator reverse proxy routes that origin to the
same application listener. API, MCP and CLI connection instructions continue to
use the application `externalUrl`. Request Host and forwarding headers never
supply advertised authority. Production pins both documentation settings;
omitted runtime settings adopt the verified deployment values.

For a deployed application, run the detached client against its saved
connection before invoking capabilities:

```sh
capaxle-client --profile production doctor --json --no-input \
  --mcp-path /mcp --mcp-protocol 2026-07-28
```

Use the operator's actual unmounted MCP path and supported server protocol when
known. Omit the MCP options when that transport is not configured; the result
will mark MCP checks `skipped` and `complete: false`, which is not a
compatibility success. Configure the profile with a credential reference such
as an environment variable name; never put token bytes in the command.

Development prepares and verifies the original private documentation archive and
a separate indexed public archive for each accepted generation. Failed updates
retain the previous complete generation. `buildDeployment` prepares both
archives; production verifies their indexed digests, canonical USTAR paths,
manifest references and provenance before executable loading. A separate indexed
browser context preserves the configured application CLI binary, and an indexed
consumer model supplies groups, authored examples and readable schemas. Both are
verified before executable loading. Production serves the prebuilt public bundle
and model without regenerating them. The private archive is never served as a
download.

Public pages and schemas include only configured public projections. Authenticated
requests use the selected provider's `authenticateDisclosure` hook and the shared
runtime ingress. The optional process-local `docs.disclosureSelector` returns
canonical capability IDs to restrict authenticated exposure for that caller.
Private exposure remains omitted. Authenticated views are generated in memory
for that request, never persisted or reused for another caller. All documentation
responses use `Cache-Control: no-store`. Secret requirement names and sensitive
environment declarations are omitted, and residual occurrences fail closed.
