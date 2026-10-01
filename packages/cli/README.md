# @capaxle/cli

Provides the `capaxle` project command: check, build, list, describe, invoke,
doctor, and dev.

This is an alpha package; APIs may change between alpha releases. The `alpha`
dist-tag follows the latest published alpha, so it can point to a newer version over time.

```sh
npm install @capaxle/cli@alpha
```

See the [project overview and @capaxle/cli guide](https://github.com/trevor-gibby/capaxle-public#package-cli)
for its place in Capaxle and a basic usage example.

`capaxle doctor [--project <root>] [--deployment <manifest>] [--json]`
checks the local Node/package environment, configuration, capability discovery,
compiler output, artifact identity, provider setup and configured mount
collisions. It never invokes a business capability. `--project` defaults to the
current directory. A trusted deployment manifest enables checks that cannot be
proved from source alone.

JSON mode returns the normal `{ok, command, value, diagnostics}` envelope; the
doctor value has `doctorVersion: "0.1"`, `mode: "local"`, `complete`, and
checks with stable IDs `local.node`, `local.packages`, `local.configuration`,
`local.discovery`, `local.compilation`, `local.artifacts`, `local.providers`,
and `local.mounts`. Each check status is `pass`, `fail`, or `skipped`. Skipped
checks make `complete` false and mean compatibility remains unproven. Failures
use the first failed check in that fixed order: environment/deadline exit 6,
configuration/schema exit 3, module-load exit 4, and artifact exit 5. A skipped
check alone exits 0 while retaining `complete: false`.

License: Apache-2.0.
