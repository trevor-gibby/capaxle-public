# @capaxle/generator-docs

Generates capability documentation and JSON Schema bundles from compiled project artifacts.

This is an alpha package; APIs may change between alpha releases. The `alpha`
dist-tag follows the latest published alpha, so it can point to a newer version over time.

```sh
npm install @capaxle/generator-docs@alpha
```

See the [project overview and @capaxle/generator-docs guide](https://github.com/trevor-gibby/capaxle-public#package-generator-docs)
for its place in Capaxle and a basic usage example.

License: Apache-2.0.

## Browser documentation

`@capaxle/generator-docs/browser` exports `renderDocumentationPage({ bundle,
model, pageId, connection })`, returning `{ html }`. It consumes a verified
archive and a separate versioned consumer model. `pageId` is `index`,
`connection`, an exact manifest capability page, or an allowed group page from
the resource tree. Every page includes navigation through arbitrarily nested
resources. Default groups use capability ID namespaces; `interfaces.docs.group`
overrides grouping with slash-separated labels. Group routes use a fixed-length
SHA-256 digest of the complete label path, retaining authored labels as display
data. A digest collision between different paths fails closed.

`DocumentationConnection` supplies local `docsPath`, optional independent
trusted `docsUrl`, application locations, verified CLI binary, transport facts,
enabled surfaces and connection snippets. The application host owns archive and
model verification, disclosure, deployment locations and client instructions.

The renderer escapes authored content and renders consumer descriptions, schema
tables and constraints, declared errors, examples and interface response formats
from structured data. It does not parse Markdown to recover canonical facts.
Recursive schemas terminate with reference links; examples never execute.
Unknown or malformed archive
entries fail with `CAP_DOCS_BROWSER_INVALID`; unknown pages fail with
`CAP_DOCS_BROWSER_NOT_FOUND`. Connection copy buttons support keyboard activation
and select the snippet if clipboard access is unavailable. Rendering is pure and
deterministic, with no transport, runtime or secret access.

`projectDocumentationModel(source, options)` produces the serializable consumer
model from verified normalized IR. Options require the original `irHash` and
`profile` (`public`, `private`, or request-local `live`), and accept the same
restrictive interface/redaction inputs below. Live models require exact
`visibleInterfaces` triples. Return values are `{ ok: true, model }` or
`{ ok: false, diagnostics }`. The app indexes public model bytes separately from
the unchanged Markdown/schema archive; production reads verified prebuilt models.
`validateDocumentationBundle(bundle)` checks archive member paths and references
independently of HTML presentation.

The same browser entry exports `projectDocumentationView(source, options)` for
request-local disclosure. Options contain the original `irHash`, required exact
`visibleInterfaces` triples (`id`, `version`, `interface`), and optional
`enabledInterfaces`, `sensitiveRequirementNames`, and `cliBinary`. The helper
returns `{ ok: true, bundle }` or `{ ok: false, diagnostics }`; it preserves the
original canonical hash and semantics, restricts projection forms, redacts
sensitive declarations and retains only reachable shared schemas. It emits no
archive and grants no invocation authority. Its transient manifest uses `live`;
`generateDocsSchemaArchive` still accepts only `private` and `public`.
Both live projection APIs reject selected private or disabled external
projections before emitting schemas or consumer data.

Static archive options also accept a unique, closed `enabledInterfaces` list
(`http`, `cli`, `mcp`). Public output requires a configured public projection;
SDK forms require a disclosed HTTP projection when this restriction is supplied.
Omitting the option preserves existing archive behavior. Hosts must fingerprint
this static producer option alongside the other archive options.
