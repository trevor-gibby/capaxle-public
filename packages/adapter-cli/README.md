# @capaxle/adapter-cli

Projects compiled capabilities as application CLI commands and can export an OpenCLI description.

This is an alpha package; APIs may change between alpha releases. The `alpha`
dist-tag follows the latest published alpha, so it can point to a newer version over time.

```sh
npm install @capaxle/adapter-cli@alpha
```

See the [project overview and @capaxle/adapter-cli guide](https://github.com/trevor-gibby/capaxle-public#package-adapter-cli)
for its place in Capaxle and a basic usage example.

The server-side remote CLI protocol is exported from
`@capaxle/adapter-cli/remote`. `createRemoteCliRegistration` returns a
structural application registration with reserved routes and a prepare hook.
For a standalone Node host, `createRemoteCliAdapter` accepts a verified
Capability IR document, its semantic hash, an operator service ID, and a
registered CLI ingress from the runtime kernel. The returned `endpoints` are
mounted paths to reserve before startup. `handleNode` handles those routes and
returns `false` for unrelated paths. Credentials are extracted by the host and
passed as its third argument; the adapter never accepts caller-provided
principal or adapter identity fields. The host must register the ingress with
source `cli` and its authentication provider. Optional `disclosureSelector` is
a process-local restriction on discovery and invocation. Private CLI discovery
additionally requires `allowPrivateDiscovery`, that selector, and a verified
private-boundary caller.

License: Apache-2.0.
