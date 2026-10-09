# @capaxle/adapter-mcp

Exposes compiled capabilities as MCP tools and produces agent-manifest artifacts.

The `/mcp` host supports discovery-era `2026-07-28` and initialization-era
`2025-11-25` Streamable HTTP unary tools on the same endpoint. The exact targets
are `mcp@2026-07-28/streamable-http/tools-unary-v3` and
`mcp@2025-11-25/streamable-http/tools-unary-v3`, both with Capaxle metadata
profile `0.3`. Server/core SDK packages are pinned to `2.2.0`, with the compatible
node package at `2.1.0`; the legacy server transport is pinned to
`@modelcontextprotocol/sdk@1.32.1`.

Modern requests carry the standard protocol-version and client-capabilities
metadata plus matching MCP headers. Legacy clients initialize, send the
initialized notification, and retain their server-issued session ID. Both eras
list the same caller-filtered tools and invoke the registered runtime kernel.
Authentication for discovery uses the provider's `authenticateDisclosure`
callback; client metadata and sessions never supply principal trust.

Tool results retain the canonical success/error object envelope in
`structuredContent`, with one canonical JSON text copy. Business primitives,
arrays, and `null` remain inside the success envelope's `value`. Controls use
the closed `params._meta["com.capaxle/invocation"]` profile `0.3` object.
Superseded metadata profile `0.2` and old-only or mixed legacy invocation
metadata fail with canonical
`CAP_INPUT_INVALID` before handler entry.

MCP inspection snapshots use profile `0.3` and a sorted `profiles` array with
stateless modern and sessionful legacy transport descriptions. Agent manifests
use the explicit closed `0.2` successor while Capability IR remains `0.1` and
artifact graphs remain `0.2`. `generateAgentManifest` and
`createAgentManifestArtifactProducer` advertise the resolved MCP endpoint,
supported profiles, and capability MCP interfaces only with `mcpEnabled: true`.
Omission defaults to disabled; generating a snapshot does not prove a listener
is enabled. Historical manifest `0.1` and MCP snapshot `0.2` evidence remains
distinct from these successors.

This is an alpha package; APIs may change between alpha releases. The `alpha`
dist-tag follows the latest published alpha, so it can point to a newer version over time.

```sh
npm install @capaxle/adapter-mcp@alpha
```

See the [project overview and @capaxle/adapter-mcp guide](https://github.com/trevor-gibby/capaxle-public#package-adapter-mcp)
for its place in Capaxle and a basic usage example.

License: Apache-2.0.
