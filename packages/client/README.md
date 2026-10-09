# @capaxle/client

`@capaxle/client` provides `capaxle-client`, a generic network client for a
separately hosted Capaxle application. The developer package `@capaxle/cli`
provides `capaxle` for checking, building and developing application source.
The two binaries have distinct roles. A detached client needs a deployment URL
and supported credentials; it does not need an application checkout, compiler,
runtime, adapters, schema frontend, handler bindings, database driver or database secrets.
Its only Capaxle dependency is the pure-data `@capaxle/ir` package.

The client uses remote CLI protocol `0.1` and the published CLI target
`opencli:bcdxn@1.0.0-alpha.13+capaxle-cli@0.2`. The server owns authentication,
authorization, schema defaults, confirmation and execution through its kernel.
Discovery cannot select local executables or authorize an operation.

## Installation and connection

The package supports npm installation and ephemeral `npx` execution. Source
validation uses locally packed tarballs; registry publication follows the
separate approved release process. The registry commands below apply to a published
release; use locally packed tarballs for source validation.

```sh
npm install @capaxle/client@alpha
npx @capaxle/client@alpha --help
capaxle-client profiles add production --url https://application.example --credential-env APPLICATION_TOKEN
capaxle-client profiles use production
capaxle-client --profile production -- capabilities list --json --no-input
capaxle-client --profile production -- notes get --name Ada --json --no-input
```

Provision `APPLICATION_TOKEN` through your application's authentication
mechanism. The flag names the environment variable; it never takes token bytes.
The bearer token is sent only as an Authorization header. HTTPS is required;
development on a loopback HTTP URL requires `--allow-http-loopback` or that
profile's explicit `allowHttpLoopback: true`, on localhost, 127.0.0.0/8 or ::1 only.
Redirected requests are rejected.

Use mandatory `--` before remote commands. Global configuration flags stay
before the separator, and application bindings stay after it. An application's
own `--url` flag therefore remains business input. Provision credentials through
your application's authentication mechanism before running these commands.

## Profiles and precedence

Configuration is a closed JSON object with `configVersion: "0.1"`, optional
`activeProfile`, and a `profiles` map. Profile names are 1–64 characters: an
alphanumeric first character followed by alphanumerics, `.`, `_` or `-`.
`profiles add`, `profiles list`, `profiles use` and `profiles remove` manage
references and connection settings without printing credentials. `profiles list`
omits credential references and hook details. Add a connection with
`profiles add NAME --url URL [--collection-path /commands] [--credential-env NAME] [--allow-http-loopback]`.

The default file is `$XDG_CONFIG_HOME/capaxle/client.json` or
`~/.config/capaxle/client.json` on POSIX, and `%APPDATA%/Capaxle/client.json`
on Windows. Project-local executable configuration is never loaded.

| Setting                          | Precedence, highest first                                                                                     |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Configuration file               | `--config`, `CAPAXLE_CLIENT_CONFIG`, platform default                                                         |
| Profile                          | `--profile`, `CAPAXLE_PROFILE`, `activeProfile`                                                               |
| URL                              | `--url`, `CAPAXLE_URL`, selected profile                                                                      |
| Collection bootstrap path        | `--collection-path`, `CAPAXLE_CLI_COLLECTION_PATH`, profile `collectionPath` at the same origin/mount, `/cli` |
| Credential environment reference | `--credential-env`, `CAPAXLE_CREDENTIAL_ENV`, profile `credentialRef`                                         |

A profile has `url`, `protocolVersion: "0.1"`, optional expected `serviceId`,
optional `collectionPath`, optional `credentialRef`, optional `authHook`, optional `cache: { enabled:
boolean }`, optional `allowHttpLoopback: boolean`, and optional credential
`expiresAt` as an RFC 3339 UTC timestamp ending in `Z`. Cache configuration
cannot expand server TTL or visibility permissions. An expired reference fails
safely. Cache defaults to enabled and loopback HTTP defaults to disabled. Unknown
configuration fields fail. References, expected service identity, expiry and hooks
are bound to the profile's normalized origin and
mounted path: overriding the URL to another location requires an explicit new
credential reference or profile.

`collectionPath` is a canonical unmounted absolute local path, such as
`/commands`. Rebase it once under the URL's mounted path: URL
`https://application.example/nested/application` and `--collection-path /commands`
request `/nested/application/commands`. Paths reject dot segments, invalid escaping,
query strings and fragments. A profile's path does not transfer to an overridden
origin or mount. The advertised collection endpoint must match the requested
bootstrap path; detail, schema and invocation then follow discovered endpoints
within the same mount. There is no redirect, bootstrap, HTTP API or manifest fallback.

Credential references are `{ kind: "env", name: "APPLICATION_TOKEN" }` or
`{ kind: "file", path: "/absolute/private/token" }`. A relative path stored in
a profile resolves against the configuration directory. Credential files must
be private, caller-owned regular files; symlinks and unsafe permissions fail
without printing contents. Atomic configuration writes use private mode.
Neither configuration nor help contains token values.

## Diagnose a connection

Run diagnostics against the selected saved connection with:

```sh
capaxle-client --profile production doctor --json --no-input
```

For MCP checks, provide the trusted unmounted MCP path and protocol explicitly;
these locations are taken from deployment configuration or operator guidance,
not guessed from the remote server. The path rebases once under the selected
connection mount, just like `--collection-path`:

```sh
capaxle-client --profile production doctor --json --no-input \
  --mcp-path /mcp --mcp-protocol 2026-07-28
```

Provision credentials through the profile's env/file reference before running
in automation. Replace `production` and the example MCP values with the saved
profile and deployment's actual values. Doctor never prompts or runs an auth
hook; provision credentials before running it. JSON returns the normal `{ok, value, correlationId}`
envelope; `value` contains `doctorVersion: "0.1"`,
`mode: "remote"`, `complete`, and checks. Stable IDs are `remote.configuration`,
`remote.credentials`, `remote.connectivity`, `remote.discovery`,
`remote.protocol`, `remote.service`, `remote.ir`, `remote.contract`,
`remote.cli-details`, `remote.cli-schemas`, `remote.mcp-discovery`,
`remote.mcp-tools`, and `remote.mcp-session`. Statuses are `pass`, `fail`, or
`skipped`. A skipped check makes `complete` false; it does not claim that the
unavailable interface is compatible. Failure exit precedence follows the first
failed check in the listed order, using existing client classes: syntax/config
2, credentials/auth 3, protocol/identity/TLS requirement 4,
DNS/TLS/connectivity/deadline/unavailable 6, malformed/disabled/schema 7;
interrupt exits 130. The probe sequence has a ten-second deadline. Network and
body waits abort at the deadline; synchronous JSON/schema validation observes
expiry at the next checkpoint, so one bounded validation operation can finish
after expiry. Expired checks fail and cannot report complete compatibility.

## Human authentication and agent use

`auth login` uses a locally configured hook of the form
`{ executable: "/absolute/path", args: [], timeoutMs: 120000 }`. The executable
is application/user-owned, invoked with an argv array and shell disabled.
The hook receives one JSON request on stdin:

```json
{
  "authRequestVersion": "0.1",
  "action": "login",
  "url": "https://application.example"
}
```

The request additionally contains `serviceId` when configured. The hook exits
zero and returns one JSON object naming a credential reference:

```json
{
  "authResultVersion": "0.1",
  "credentialRef": { "kind": "file", "path": "/absolute/private/token" }
}
```

The result is a closed object encoded as valid UTF-8. File results must be absolute.
Explicit login atomically persists only the reference and expiry to the selected
profile. The result may include `expiresAt`. Its credential bytes stay in the referenced
carrier. A returned environment reference must already exist in the client
process; a child cannot provision its parent's environment. Newly acquired
credentials belong in the private file written by the trusted hook. Input,
stdout and stderr are capped at 16,384 bytes; timeout is 1–120,000 ms. Malformed,
expired, oversized, nonzero-exit or timed-out results fail with sanitized
`CAP_CLI_AUTH_HOOK_FAILED`. Raw hook output is never forwarded.

An interactive TTY may use its configured hook automatically. `--no-input` and
non-TTY execution never prompt, open a browser or run login hooks. Agents use
pre-provisioned env/file credentials. Missing credentials produce
`CAP_UNAUTHENTICATED` with setup guidance. `doctor` checks the selected connection.

## Discovery and input

Discovery is bounded and validated against closed protocol `0.1` shapes and the
transport contract hash. Remote help, examples, command trees, resolved flag bindings and
`capabilities list`, `capabilities describe ID`, and `capabilities schema ID`
come from caller-visible server discovery. `--version` before `--` reports the
client version; after `--` it reports the discovered service and protocol identity.
Descriptions and examples remain inert data. Private capability metadata is never
shared across credentials. Each invocation uses fresh compatible discovery;
an IR or transport contract mismatch rejects before handler entry.

Scalar options and positionals assemble top-level properties. Repeated scalar
array options are variadic; booleans are valueless flags, with `--no-FLAG`
negation for a default-true boolean. Missing values remain missing until kernel
validation. Rich input uses one whole JSON object:

```sh
capaxle-client --profile production -- notes get --input '{"payload":{"value":"nested"}}' --json --no-input
capaxle-client --profile production -- notes get --input-file payload.json --json --no-input
capaxle-client --profile production -- notes get --input-file - --json --no-input < payload.json
```

Inline and file carriers may each occur once, are mutually exclusive, and
cannot mix with scalar options or positionals. There is no merging or overlay.
`--no-input` disables interaction and permits explicit stdin input.

`--confirm TOKEN`, `--idempotency-key KEY`, `--timeout 10s` and
`--correlation-id HINT` carry controls to the server. Confirmation is opaque
application-owned evidence; a client prompt or `--yes` cannot approve an operation.
Timeout must be positive and at most 300,000 ms, subject to stricter server
policy. Correlation hints do not select trusted kernel correlations.

## Results, cancellation and caching

`--json --no-input` writes exactly one canonical success/error envelope to
stdout, including local syntax, configuration and network failures, with no progress
output. Human-readable diagnostics use stderr. Successful remote envelopes include
protocol, service, IR and
contract identity. Inspect `error.code` and `error.status`; canonical remote errors
remain intact and authoritative.

| Exit | Meaning                                                    |
| ---: | ---------------------------------------------------------- |
|    0 | Success                                                    |
|    2 | Syntax, invalid canonical input, request too large         |
|    3 | Authentication or permission failure                       |
|    4 | Confirmation, protocol, TLS or other precondition          |
|    5 | Declared application error                                 |
|    6 | Rate, deadline, unavailable or connection failure          |
|    7 | Framework/internal, unknown capability or invalid response |
|  130 | Local SIGINT cancellation                                  |

SIGINT aborts the request and reaches the server kernel's cancellation signal.
Cancellation does not guarantee that a write rolled back. Every invocation
makes one network submission: the client never retries a read or write after an
ambiguous transport failure. Discovery alone permits at most two attempts for
connection/503 failures within a ten-second deadline.

Discovery caches are in-memory and partitioned by server origin/mount, profile,
service, protocol, IR hash, transport contract hash, random local credential epoch and
server visibility key. Credential changes rotate the epoch; URL/profile changes
clear private partitions. Private responses are never persisted. Unknown
visibility context disables caching; server TTL is at most 30 seconds.

## Programmatic API

`executeClient(argv, options?)` returns `{exitCode,stdout,stderr}`;
`createClient(options?).execute(argv)` preserves bounded in-memory cache state.
`parseRemoteInput(capability, argv, readers?)` exposes the production input assembler
for local/remote conformance vectors. `options` can supply environment, fetch, signal,
stdin reader and TTY state for embedding and tests. The executable binds SIGINT and
bounded standard input.
