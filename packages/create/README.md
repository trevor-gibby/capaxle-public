# @capaxle/create

Initializer for a database-free Capaxle application. Node 22.15+ on Node 22 or
24.0+ on Node 24. Generated projects pin the compatible 0.1.0-alpha.3 framework
train, use one JavaScript server and TypeScript read/write capabilities, and
expose HTTP, MCP, remote CLI and browser reference on one listener.

After approved publication:

```sh
npx @capaxle/create my-app
npx @capaxle/create my-app --template protected --no-input
npx @capaxle/create capability-integration --template existing-server --no-input
```

The package remains source-ready and unpublished pending the separate release
gate. Source acceptance uses `npx --offline --package <packed-create-tarball>
create-capaxle ...` and installs the matching packed framework dependency closure.
There are no direct framework dependencies or imports in this initializer.

Interactive and non-interactive selections emit the same files. Non-interactive
mode defaults to the `default` template. Names are lowercase letters, digits and
hyphens, starting with a letter, up to 64 characters. Existing destinations,
including symlinks and empty directories, are rejected. There is no overwrite
option. Interruptions roll back unchanged generated files while preserving
concurrently added or modified user files.

The default Map store is process-local and public, with no database provisioning.
The protected example uses externally supplied `APPLICATION_TOKEN`, canonical
required authentication, and the shared runtime kernel. Neither template issues
credentials, supplies a database, or constitutes production authentication.

Existing-server mode creates an isolated example directory and does not rewrite
the existing host. It wraps one business function with a capability and mounts
middleware before existing routes/body handling; host authentication and listener
remain explicitly host-owned. Follow the generated README to integrate deliberately.

Generated README commands cover install, dev, check, build, verified production
start, client profiles, credentials, MCP connection configuration and diagnostics.
