import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import {
  ClientFailure,
  fail,
  failureResult,
  invalidReply,
  finiteJson,
  json,
  object,
  success,
} from "./common.js";
import type { ClientResult } from "./common.js";
import {
  configPath,
  credentialRef,
  loadConfig,
  localCollectionPath,
  login,
  normalizeUrl,
  profileName,
  readCredential,
  readInputFile,
  selectConnection,
  writeConfig,
} from "./config.js";
import type { Environment, Selection } from "./config.js";
import { parseRemoteGlobals, parseRemoteInput } from "./input.js";
import {
  PROTOCOL,
  resultExit,
  validateCollection,
  validateDetail,
  validateResult,
  validateSchema,
} from "./wire.js";
import type { Collection, Detail, Summary } from "./wire.js";
import { doctor } from "./doctor.js";

export interface ClientOptions {
  readonly env?: Environment;
  readonly fetch?: typeof globalThis.fetch;
  readonly signal?: AbortSignal;
  readonly readStdin?: () => string | Promise<string>;
  readonly isTTY?: boolean;
  readonly now?: () => number;
  readonly random?: () => number;
}
export interface Client {
  execute(argv: readonly string[]): Promise<ClientResult>;
}
function split(argv: readonly string[]) {
  const separator = argv.indexOf("--");
  const local = separator < 0 ? [...argv] : argv.slice(0, separator);
  const remote = separator < 0 ? undefined : argv.slice(separator + 1);
  const flags: Record<string, string> = Object.create(null) as Record<
    string,
    string
  >;
  const rest: string[] = [];
  let allowHttp = false;
  let noInput = false;
  let machine = false;
  let help = false;
  let version = false;
  for (let i = 0; i < local.length; i++) {
    const token = local[i]!;
    if (
      [
        "--config",
        "--profile",
        "--url",
        "--credential-env",
        "--collection-path",
        "--mcp-path",
        "--mcp-protocol",
        "--timeout-ms",
      ].includes(token)
    ) {
      if (Object.hasOwn(flags, token)) fail();
      const value = local[++i];
      if (value === undefined || value.startsWith("--")) fail();
      flags[token] = value;
    } else if (token === "--allow-http-loopback") {
      if (allowHttp) fail();
      allowHttp = true;
    } else if (token === "--no-input") noInput = true;
    else if (token === "--json") machine = true;
    else if (token === "--help") help = true;
    else if (token === "--version") version = true;
    else {
      if (token.startsWith("--")) fail();
      rest.push(token);
    }
  }
  if (remote !== undefined && rest.length) fail();
  return { flags, rest, remote, allowHttp, noInput, machine, help, version };
}
const guidance = () =>
  fail(
    "CAP_UNAUTHENTICATED",
    "unauthenticated",
    3,
    "Provision an environment/private-file credential reference, or run auth login from an interactive terminal.",
  );
export function createClient(options: ClientOptions = {}): Client {
  const env = options.env ?? process.env;
  const fetcher = options.fetch ?? globalThis.fetch;
  const now = options.now ?? Date.now;
  const random = options.random ?? Math.random;
  const cache = new Map<
    string,
    { expires: number; value: Collection | Detail }
  >();
  let currentLocation = "";
  let currentCredential: string | undefined;
  let epoch = randomUUID();
  function partition(selection: Selection, credential: string | undefined) {
    const location = `${selection.url}\0${selection.profileName ?? ""}`;
    if (location !== currentLocation || credential !== currentCredential) {
      cache.clear();
      epoch = randomUUID();
      currentLocation = location;
      currentCredential = credential;
    }
    return epoch;
  }
  const cacheKey = (
    selection: Selection,
    collection: Collection,
    resource: string,
    partitionEpoch: string,
  ) =>
    json({
      location: selection.url,
      profile: selection.profileName ?? "",
      serviceId: collection.service.id,
      protocol: PROTOCOL,
      contractHash: collection.contractHash,
      irHash: collection.irHash,
      epoch: partitionEpoch,
      visibilityKey: collection.cache.visibilityKey,
      resource,
    });
  function save(
    key: string,
    value: Collection | Detail,
    enabled: boolean,
    partitionEpoch: string,
  ) {
    if (partitionEpoch === epoch && enabled && value.cache.ttlMs > 0) {
      if (cache.size >= 128) cache.delete(cache.keys().next().value!);
      cache.set(key, {
        expires: now() + value.cache.ttlMs,
        value: structuredClone(value),
      });
    }
  }
  async function request(
    selection: Selection,
    credential: string | undefined,
    path: string,
    body?: unknown,
    limit = 8388608,
    timeoutMs = 10000,
  ): Promise<{ value: unknown; status: number; headers: Headers }> {
    const signal = options.signal;
    const timeout = AbortSignal.timeout(timeoutMs);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
    let response: Response;
    try {
      const encoded = body === undefined ? undefined : json(body);
      response = await fetcher(new URL(path, selection.url), {
        method: body === undefined ? "GET" : "POST",
        redirect: "manual",
        headers: {
          "Capaxle-CLI-Protocol": PROTOCOL,
          ...(credential === undefined
            ? {}
            : { authorization: `Bearer ${credential}` }),
          ...(encoded === undefined
            ? {}
            : { "content-type": "application/json" }),
        },
        ...(encoded === undefined ? {} : { body: encoded }),
        signal: combined,
      });
    } catch {
      if (signal?.aborted)
        throw new ClientFailure(
          "CAP_CANCELLED",
          "cancelled",
          130,
          "Client request cancelled; execution may already have occurred.",
        );
      fail(
        "CAP_CLI_CONNECTION_FAILED",
        "unavailable",
        6,
        body === undefined
          ? "Cannot connect to the application."
          : "Connection failed; execution may already have occurred. Retry explicitly only under the application idempotency policy.",
      );
    }
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      invalidReply();
    }
    if (
      !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(
        response.headers.get("content-type") ?? "",
      ) ||
      response.headers.get("capaxle-cli-protocol") !== PROTOCOL ||
      (response.headers.has("content-encoding") &&
        response.headers.get("content-encoding") !== "identity")
    ) {
      await response.body?.cancel();
      invalidReply();
    }
    const length = response.headers.get("content-length");
    if (length !== null && (!/^\d+$/u.test(length) || Number(length) > limit)) {
      await response.body?.cancel();
      invalidReply();
    }
    const reader = response.body?.getReader();
    if (!reader) invalidReply();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    try {
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        bytes += chunk.value.length;
        if (bytes > limit) {
          await reader.cancel();
          invalidReply();
        }
        chunks.push(chunk.value);
      }
    } catch (error) {
      if (error instanceof ClientFailure) throw error;
      if (signal?.aborted) throw error;
      fail(
        "CAP_CLI_CONNECTION_FAILED",
        "unavailable",
        6,
        body === undefined
          ? "Cannot read application response."
          : "Connection failed; execution may already have occurred.",
      );
    }
    let value: unknown;
    try {
      value = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)),
      );
    } catch {
      invalidReply();
    }
    if (!finiteJson(value)) invalidReply();
    return { value, status: response.status, headers: response.headers };
  }
  async function discoveryRequest(
    selection: Selection,
    credential: string | undefined,
    path: string,
    limit = 8388608,
  ) {
    const started = Date.now();
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const response = await request(
          selection,
          credential,
          path,
          undefined,
          limit,
          Math.max(1, 10000 - (Date.now() - started)),
        );
        if (response.status === 503 && attempt === 0) {
          const failure = validateResult(response.value);
          if (failure.ok) invalidReply();
          const excluded = new Set([
            "CAP_UNAUTHENTICATED",
            "CAP_PERMISSION_DENIED",
            "CAP_CLI_PROTOCOL_UNSUPPORTED",
            "CAP_CLI_IR_MISMATCH",
            "CAP_CLI_CONTRACT_MISMATCH",
            "CAP_CLI_SERVICE_MISMATCH",
          ]);
          if (
            failure.error.status === "unavailable" &&
            !excluded.has(failure.error.code) &&
            Date.now() - started < 9750
          ) {
            await delay(
              100 + Math.floor(Math.max(0, Math.min(1, random())) * 150),
              undefined,
              { ...(options.signal ? { signal: options.signal } : {}) },
            );
            continue;
          }
        }
        if (response.status !== 200) {
          const result = validateResult(response.value);
          if (result.ok) invalidReply();
          return { error: result };
        }
        if (
          credential !== undefined &&
          response.headers.get("cache-control") !== "private, no-store"
        )
          invalidReply();
        return { response };
      } catch (error) {
        if (
          attempt === 0 &&
          error instanceof ClientFailure &&
          error.code === "CAP_CLI_CONNECTION_FAILED" &&
          Date.now() - started < 9750 &&
          !options.signal?.aborted
        ) {
          await delay(
            100 + Math.floor(Math.max(0, Math.min(1, random())) * 150),
            undefined,
            { ...(options.signal ? { signal: options.signal } : {}) },
          );
          continue;
        }
        throw error;
      }
    }
    invalidReply();
  }
  const rendered = (value: unknown, exitCode = 0): ClientResult => ({
    exitCode,
    stdout: json(value) + "\n",
    stderr: "",
  });
  async function run(argv: readonly string[]): Promise<ClientResult> {
    const args = split(argv);
    if (args.version)
      return success({
        binary: "capaxle-client",
        version: "0.1.0-alpha.3",
        protocolVersion: PROTOCOL,
      });
    if (args.help || (!args.remote && args.rest.length === 0))
      return success({
        binary: "capaxle-client",
        usage:
          "capaxle-client [--profile NAME | --url URL] -- <application command> [flags]",
        commands: [
          "profiles add NAME --url URL",
          "profiles list",
          "profiles use NAME",
          "profiles remove NAME",
          "auth login",
          "doctor",
        ],
        credentials:
          "Environment/private-file references only; --credential-env names an existing variable.",
      });
    if (args.rest.length === 1 && args.rest[0] === "doctor")
      return doctor(args.flags, args.allowHttp, args.machine, {
        ...options,
        env,
        fetch: fetcher,
      });
    if (
      ["--mcp-path", "--mcp-protocol", "--timeout-ms"].some(
        (flag) => args.flags[flag] !== undefined,
      )
    )
      fail();
    const path = configPath(env, args.flags["--config"]);
    const config = await loadConfig(path);
    if (args.rest[0] === "profiles") {
      const action = args.rest[1];
      const name = args.rest[2];
      if (action === "list" && args.rest.length === 2)
        return success({
          activeProfile: config.activeProfile ?? null,
          profiles: Object.entries(config.profiles)
            .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
            .map(([name, p]) => ({
              name,
              url: normalizeUrl(p.url, p.allowHttpLoopback === true),
              protocolVersion: p.protocolVersion,
              ...(p.serviceId ? { serviceId: p.serviceId } : {}),
            })),
        });
      if (!profileName(name) || args.rest.length !== 3) fail();
      if (action === "add") {
        if (
          Object.hasOwn(config.profiles, name) ||
          args.flags["--url"] === undefined
        )
          fail();
        const collectionPath = args.flags["--collection-path"];
        if (
          collectionPath !== undefined &&
          !localCollectionPath(collectionPath)
        )
          fail();
        const ref =
          args.flags["--credential-env"] === undefined
            ? undefined
            : { kind: "env" as const, name: args.flags["--credential-env"] };
        if (ref && !credentialRef(ref)) fail();
        Object.defineProperty(config.profiles, name, {
          value: {
            url: normalizeUrl(args.flags["--url"], args.allowHttp),
            protocolVersion: PROTOCOL,
            ...(collectionPath === undefined ? {} : { collectionPath }),
            ...(ref ? { credentialRef: ref } : {}),
            ...(args.allowHttp ? { allowHttpLoopback: true } : {}),
          },
          enumerable: true,
          writable: true,
          configurable: true,
        });
      } else if (action === "use") {
        if (!Object.hasOwn(config.profiles, name)) fail();
        config.activeProfile = name;
      } else if (action === "remove") {
        if (!Object.hasOwn(config.profiles, name)) fail();
        delete config.profiles[name];
        if (config.activeProfile === name) delete config.activeProfile;
      } else fail();
      await writeConfig(path, config);
      cache.clear();
      return success({ profile: name, action });
    }
    const globals = parseRemoteGlobals(args.remote ?? []);
    const selection = selectConnection(config, env, args.flags, args.allowHttp);
    const nonInteractive =
      args.noInput ||
      globals.noInput ||
      !(options.isTTY ?? Boolean(process.stdin.isTTY && process.stdout.isTTY));
    if (
      args.rest[0] === "auth" &&
      args.rest[1] === "login" &&
      args.rest.length === 2
    ) {
      if (nonInteractive) guidance();
      const result = await login(selection, env, options.signal, now());
      const credential = await readCredential(
        result.credentialRef,
        path,
        env,
        result.expiresAt,
        now(),
      );
      if (credential === undefined) guidance();
      if (!selection.profileName || !selection.profile)
        fail(
          "CAP_INPUT_INVALID",
          "invalid_argument",
          2,
          "Select a profile to persist an authentication reference.",
        );
      selection.profile.credentialRef = result.credentialRef;
      if (result.expiresAt === undefined) delete selection.profile.expiresAt;
      else selection.profile.expiresAt = result.expiresAt;
      await writeConfig(path, config);
      cache.clear();
      return success({ authenticated: true, profile: selection.profileName });
    }
    if (
      args.rest.length &&
      !(args.rest.length === 1 && args.rest[0] === "doctor")
    )
      fail();
    if (args.remote === undefined && args.rest[0] !== "doctor") fail();
    let credential = await readCredential(
      selection.credentialRef,
      path,
      env,
      selection.expiresAt,
      now(),
    );
    if (
      credential === undefined &&
      (selection.credentialRef !== undefined ||
        selection.authHook !== undefined)
    ) {
      if (nonInteractive || !selection.authHook) guidance();
      const result = await login(selection, env, options.signal, now());
      credential = await readCredential(
        result.credentialRef,
        path,
        env,
        result.expiresAt,
        now(),
      );
      if (credential === undefined) guidance();
    }
    const executionEpoch = partition(selection, credential);
    const collectionPath = selection.collectionPath;
    const found = await discoveryRequest(selection, credential, collectionPath);
    if (found.error) return rendered(found.error, resultExit(found.error));
    const collection = validateCollection(
      found.response!.value,
      selection.url,
      collectionPath,
    );
    if (
      Buffer.byteLength(json(collection)) >
        collection.payloadLimits.responseBytes ||
      (credential !== undefined && collection.cache.scope !== "private")
    )
      invalidReply();
    if (
      selection.serviceId !== undefined &&
      collection.service.id !== selection.serviceId
    )
      fail(
        "CAP_CLI_SERVICE_MISMATCH",
        "failed_precondition",
        4,
        "Discovered service does not match the selected profile.",
      );
    save(
      cacheKey(selection, collection, "collection", executionEpoch),
      collection,
      selection.cacheEnabled,
      executionEpoch,
    );
    if (globals.version)
      return success({
        service: collection.service,
        protocolVersion: PROTOCOL,
        irHash: collection.irHash,
      });
    const rest = globals.rest;
    if (
      (rest.length === 0 && globals.help) ||
      (rest[0] === "capabilities" && rest[1] === "list" && rest.length === 2)
    )
      return success(collection);
    let summary: Summary | undefined;
    let discoveryAction: string | undefined;
    if (rest[0] === "capabilities") {
      discoveryAction = rest[1];
      if (
        !["describe", "schema"].includes(discoveryAction ?? "") ||
        rest.length !== 3
      )
        fail();
      summary = collection.capabilities.filter((v) => v.id === rest[2]).at(-1);
    } else
      summary = collection.capabilities.find((v) =>
        v.command.every((token, i) => rest[i] === token),
      );
    if (!summary)
      fail("CAP_NOT_FOUND", "not_found", 7, "Capability not found.");
    const versionQuery = `?version=${encodeURIComponent(summary.version)}`;
    if (discoveryAction === "schema") {
      const found = await discoveryRequest(
        selection,
        credential,
        summary.schemaUrl + versionQuery,
        collection.payloadLimits.responseBytes,
      );
      if (found.error) return rendered(found.error, resultExit(found.error));
      const schema = validateSchema(found.response!.value, collection, summary);
      if (credential !== undefined && schema.cache.scope !== "private")
        invalidReply();
      return success(schema);
    }
    const key = cacheKey(
      selection,
      collection,
      summary.detailUrl + versionQuery,
      executionEpoch,
    );
    const cached = selection.cacheEnabled ? cache.get(key) : undefined;
    let detail: Detail;
    if (cached && cached.expires > now())
      detail = validateDetail(
        structuredClone(cached.value),
        collection,
        summary,
      );
    else {
      const found = await discoveryRequest(
        selection,
        credential,
        summary.detailUrl + versionQuery,
        collection.payloadLimits.responseBytes,
      );
      if (found.error) return rendered(found.error, resultExit(found.error));
      detail = validateDetail(found.response!.value, collection, summary);
      if (credential !== undefined && detail.cache.scope !== "private")
        invalidReply();
      if (
        detail.cache.visibilityKey === collection.cache.visibilityKey &&
        detail.cache.scope === collection.cache.scope
      )
        save(key, detail, selection.cacheEnabled, executionEpoch);
    }
    if (discoveryAction || globals.help) return success(detail);
    if (
      detail.capability.access &&
      object(detail.capability.access) &&
      detail.capability.access.authentication === "required" &&
      credential === undefined
    )
      guidance();
    const invocation = await parseRemoteInput(
      detail.capability,
      args.remote!,
      {
        readFile: (p) =>
          readInputFile(p, collection.payloadLimits.requestBytes),
        ...(options.readStdin ? { readStdin: options.readStdin } : {}),
      },
      summary.command.length,
    );
    const body = {
      protocolVersion: PROTOCOL,
      serviceId: collection.service.id,
      irHash: collection.irHash,
      contractHash: collection.contractHash,
      capability: summary.id,
      version: summary.version,
      input: invocation.input,
      ...(Object.keys(invocation.controls).length
        ? { controls: invocation.controls }
        : {}),
    };
    if (Buffer.byteLength(json(body)) > collection.payloadLimits.requestBytes)
      fail(
        "CAP_CLI_PAYLOAD_TOO_LARGE",
        "invalid_argument",
        2,
        "Input exceeds the request limit.",
      );
    const response = await request(
      selection,
      credential,
      collection.endpoints.invoke,
      body,
      collection.payloadLimits.responseBytes,
      invocation.controls.timeoutMs ?? 10000,
    );
    const result = validateResult(response.value, collection);
    if (
      (result.ok && response.status !== 200) ||
      (!result.ok && response.status < 400)
    )
      invalidReply();
    if (
      !result.ok &&
      [
        "CAP_CLI_IR_MISMATCH",
        "CAP_CLI_CONTRACT_MISMATCH",
        "CAP_CLI_SERVICE_MISMATCH",
      ].includes(result.error.code)
    )
      cache.clear();
    return rendered(result, resultExit(result, detail.capability.errors));
  }
  return {
    async execute(argv) {
      try {
        return await run(argv);
      } catch (error) {
        return failureResult(error, options.signal);
      }
    },
  };
}
export async function executeClient(
  argv: readonly string[],
  options: ClientOptions = {},
): Promise<ClientResult> {
  return createClient(options).execute(argv);
}
