import { constants } from "node:fs";
import { mkdir, open, rename, unlink } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { path as validPath } from "./wire.js";
import { closed, fail, integer, json, object, text } from "./common.js";

export type CredentialRef =
  { kind: "env"; name: string } | { kind: "file"; path: string };
export interface AuthHook {
  executable: string;
  args: string[];
  timeoutMs?: number;
}
export interface ConnectionProfile {
  url: string;
  collectionPath?: string;
  protocolVersion: "0.1";
  serviceId?: string;
  credentialRef?: CredentialRef;
  authHook?: AuthHook;
  cache?: { enabled: boolean };
  allowHttpLoopback?: boolean;
  expiresAt?: string;
}
export interface ClientConfig {
  configVersion: "0.1";
  activeProfile?: string;
  profiles: Record<string, ConnectionProfile>;
}
export type Environment = Readonly<Record<string, string | undefined>>;
export const profileName = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(value);
export function credentialRef(
  value: unknown,
  absolute = false,
): value is CredentialRef {
  return (
    (closed(value, ["kind", "name"]) &&
      value.kind === "env" &&
      typeof value.name === "string" &&
      /^[A-Za-z_][A-Za-z0-9_]*$/u.test(value.name)) ||
    (closed(value, ["kind", "path"]) &&
      value.kind === "file" &&
      text(value.path, 4096) &&
      (!absolute || isAbsolute(value.path)))
  );
}
function timestamp(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const match =
    /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z$/u.exec(value);
  if (!match) return undefined;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return undefined;
  const canonical = new Date(parsed).toISOString();
  if (canonical.slice(0, 19) !== value.slice(0, 19)) return undefined;
  return parsed;
}
export function expiry(value: unknown, now: number): value is string {
  const parsed = timestamp(value);
  return parsed !== undefined && parsed > now;
}
function validExpiry(value: unknown): value is string {
  return timestamp(value) !== undefined;
}
export function localCollectionPath(value: unknown): value is string {
  if (!validPath(value, "/")) return false;
  try {
    return encodeURI(decodeURIComponent(value)) === value;
  } catch {
    return false;
  }
}
export function normalizeUrl(raw: string, allowHttp = false): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    fail();
  }
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !["http:", "https:"].includes(url.protocol) ||
    /%(?:2f|5c|2e)/iu.test(url.pathname) ||
    url.pathname.includes("\\") ||
    /(?:^|\/)\.{1,2}(?:\/|$)/u.test(
      raw.split("?")[0]!.replace(/^https?:\/\/[^/]+/u, ""),
    )
  )
    fail();
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "[::1]" ||
    /^127(?:\.\d{1,3}){3}$/u.test(url.hostname);
  if (url.protocol !== "https:" && (!allowHttp || !loopback))
    fail(
      "CAP_CLI_TLS_REQUIRED",
      "failed_precondition",
      4,
      "TLS is required; configure loopback development HTTP explicitly.",
    );
  url.pathname = url.pathname.replace(/\/+$/u, "") + "/";
  return url.href;
}
function validateProfile(value: unknown): value is ConnectionProfile {
  if (
    !closed(
      value,
      ["url", "protocolVersion"],
      [
        "collectionPath",
        "serviceId",
        "credentialRef",
        "authHook",
        "cache",
        "allowHttpLoopback",
        "expiresAt",
      ],
    ) ||
    !text(value.url, 8192) ||
    value.protocolVersion !== "0.1" ||
    (value.collectionPath !== undefined &&
      !localCollectionPath(value.collectionPath)) ||
    (value.serviceId !== undefined && !text(value.serviceId, 128)) ||
    (value.credentialRef !== undefined &&
      !credentialRef(value.credentialRef)) ||
    (value.allowHttpLoopback !== undefined &&
      typeof value.allowHttpLoopback !== "boolean") ||
    (value.cache !== undefined &&
      (!closed(value.cache, ["enabled"]) ||
        typeof value.cache.enabled !== "boolean")) ||
    (value.expiresAt !== undefined &&
      (!validExpiry(value.expiresAt) || value.credentialRef === undefined))
  )
    return false;
  if (
    value.authHook !== undefined &&
    (!closed(value.authHook, ["executable", "args"], ["timeoutMs"]) ||
      !text(value.authHook.executable, 4096) ||
      !isAbsolute(value.authHook.executable) ||
      !Array.isArray(value.authHook.args) ||
      !value.authHook.args.every(
        (v) => typeof v === "string" && Buffer.byteLength(v) <= 4096,
      ) ||
      (value.authHook.timeoutMs !== undefined &&
        !integer(value.authHook.timeoutMs, 1, 120000)))
  )
    return false;
  normalizeUrl(value.url, value.allowHttpLoopback === true);
  return true;
}
export function configPath(env: Environment, flag?: string): string {
  return resolve(
    flag ??
      env.CAPAXLE_CLIENT_CONFIG ??
      (process.platform === "win32"
        ? join(env.APPDATA ?? homedir(), "Capaxle", "client.json")
        : join(
            env.XDG_CONFIG_HOME ?? join(homedir(), ".config"),
            "capaxle",
            "client.json",
          )),
  );
}
async function boundedFile(handle: FileHandle, max: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  while (true) {
    const buffer = Buffer.alloc(Math.min(65536, max + 1 - bytes));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
    if (!bytesRead) break;
    bytes += bytesRead;
    if (bytes > max)
      fail(
        "CAP_CLI_PAYLOAD_TOO_LARGE",
        "invalid_argument",
        2,
        "Local input exceeds its byte limit.",
      );
    chunks.push(buffer.subarray(0, bytesRead));
  }
  return Buffer.concat(chunks);
}
export async function loadConfig(path: string): Promise<ClientConfig> {
  let bytes: Buffer;
  try {
    const handle = await open(path, "r");
    try {
      if ((await handle.stat()).size > 1048576) fail();
      bytes = await boundedFile(handle, 1048576);
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (object(error) && error.code === "ENOENT")
      return { configVersion: "0.1", profiles: {} };
    throw error;
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    fail();
  }
  if (
    !closed(value, ["configVersion", "profiles"], ["activeProfile"]) ||
    value.configVersion !== "0.1" ||
    !object(value.profiles) ||
    (value.activeProfile !== undefined &&
      (!profileName(value.activeProfile) ||
        !Object.hasOwn(value.profiles, value.activeProfile))) ||
    !Object.entries(value.profiles).every(
      ([name, profile]) => profileName(name) && validateProfile(profile),
    )
  )
    fail();
  return value as unknown as ClientConfig;
}
export async function writeConfig(
  path: string,
  config: ClientConfig,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.${randomUUID()}.tmp`;
  const handle = await open(temp, "wx", 0o600);
  try {
    await handle.writeFile(json(config) + "\n");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temp, path);
  } finally {
    await unlink(temp).catch(() => undefined);
  }
}
export interface Selection {
  url: string;
  collectionPath: string;
  profileName?: string;
  profile?: ConnectionProfile;
  credentialRef?: CredentialRef;
  expiresAt?: string;
  authHook?: AuthHook;
  serviceId?: string;
  cacheEnabled: boolean;
}
export function selectConnection(
  config: ClientConfig,
  env: Environment,
  flags: Readonly<Record<string, string>>,
  allowHttp: boolean,
): Selection {
  const name =
    flags["--profile"] ?? env.CAPAXLE_PROFILE ?? config.activeProfile;
  if (
    name !== undefined &&
    (!profileName(name) || !Object.hasOwn(config.profiles, name))
  )
    fail();
  const profile = name === undefined ? undefined : config.profiles[name];
  const rawUrl = flags["--url"] ?? env.CAPAXLE_URL ?? profile?.url;
  if (rawUrl === undefined)
    fail(
      "CAP_INPUT_INVALID",
      "invalid_argument",
      2,
      "Configure a profile or provide --url.",
    );
  const url = normalizeUrl(
    rawUrl,
    allowHttp || profile?.allowHttpLoopback === true,
  );
  const sameHost =
    profile !== undefined &&
    normalizeUrl(profile.url, profile.allowHttpLoopback === true) === url;
  const bootstrap =
    flags["--collection-path"] ??
    env.CAPAXLE_CLI_COLLECTION_PATH ??
    (sameHost ? profile?.collectionPath : undefined) ??
    "/cli";
  if (!localCollectionPath(bootstrap)) fail();
  const collectionPath = new URL(url).pathname + bootstrap.slice(1);
  const credentialEnv = flags["--credential-env"] ?? env.CAPAXLE_CREDENTIAL_ENV;
  const ref =
    credentialEnv !== undefined
      ? { kind: "env" as const, name: credentialEnv }
      : sameHost
        ? profile?.credentialRef
        : undefined;
  if (ref !== undefined && !credentialRef(ref)) fail();
  return {
    url,
    collectionPath,
    ...(name === undefined ? {} : { profileName: name }),
    ...(profile === undefined ? {} : { profile }),
    ...(ref === undefined ? {} : { credentialRef: ref }),
    ...(sameHost &&
    credentialEnv === undefined &&
    profile?.expiresAt !== undefined
      ? { expiresAt: profile.expiresAt }
      : {}),
    ...(sameHost && profile?.authHook !== undefined
      ? { authHook: profile.authHook }
      : {}),
    ...(sameHost && profile?.serviceId !== undefined
      ? { serviceId: profile.serviceId }
      : {}),
    cacheEnabled: profile?.cache?.enabled !== false,
  };
}
export async function readCredential(
  ref: CredentialRef | undefined,
  path: string,
  env: Environment,
  expiresAt?: string,
  now = Date.now(),
): Promise<string | undefined> {
  if (!ref) return undefined;
  if (expiresAt !== undefined && !expiry(expiresAt, now))
    fail(
      "CAP_UNAUTHENTICATED",
      "unauthenticated",
      3,
      "Credentials expired; provision credentials or run auth login interactively.",
    );
  let value: string | undefined;
  if (ref.kind === "env") value = env[ref.name];
  else {
    let handle;
    try {
      handle = await open(
        resolve(dirname(path), ref.path),
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
      const stat = await handle.stat();
      if (
        !stat.isFile() ||
        stat.size > 16384 ||
        (process.platform !== "win32" &&
          (stat.mode & 0o077 ||
            (process.getuid && stat.uid !== process.getuid())))
      )
        fail(
          "CAP_CLI_CREDENTIAL_UNSAFE",
          "failed_precondition",
          4,
          "Credential file must be private and caller-owned.",
        );
      const bytes = await boundedFile(handle, 16384);
      if (bytes.length > 16384) fail();
      value = new TextDecoder("utf-8", { fatal: true }).decode(bytes).trim();
    } catch (error) {
      if (object(error) && error.code === "ENOENT") return undefined;
      if (error instanceof Error && error.name === "ClientFailure") throw error;
      fail(
        "CAP_CLI_CREDENTIAL_UNSAFE",
        "failed_precondition",
        4,
        "Credential file must be readable, private and caller-owned.",
      );
    } finally {
      await handle?.close();
    }
  }
  if (value === undefined || value === "") return undefined;
  if (
    !/^[A-Za-z0-9\-._~+/]+=*$/u.test(value) ||
    Buffer.byteLength(value) > 16384
  )
    fail(
      "CAP_UNAUTHENTICATED",
      "unauthenticated",
      3,
      "Provision a valid credential through an environment or private file reference.",
    );
  return value;
}
export async function login(
  selection: Selection,
  env: Environment,
  signal: AbortSignal | undefined,
  now: number,
): Promise<{ credentialRef: CredentialRef; expiresAt?: string }> {
  const hook = selection.authHook;
  if (!hook)
    fail(
      "CAP_UNAUTHENTICATED",
      "unauthenticated",
      3,
      "Configure a local authentication hook or provision credentials.",
    );
  const request =
    json({
      authRequestVersion: "0.1",
      action: "login",
      url: selection.url,
      ...(selection.serviceId ? { serviceId: selection.serviceId } : {}),
    }) + "\n";
  if (Buffer.byteLength(request) > 16384) fail();
  const result = await new Promise<unknown>((resolveResult, reject) => {
    const child = spawn(hook.executable, hook.args, {
      shell: false,
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let output: Buffer[] = [];
    let outputBytes = 0;
    let errorBytes = 0;
    let done = false;
    const failed = () => {
      if (done) return;
      done = true;
      child.kill("SIGKILL");
      clearTimeout(timer);
      signal?.removeEventListener("abort", failed);
      reject(new Error("hook"));
    };
    const timer = setTimeout(failed, hook.timeoutMs ?? 120000);
    signal?.addEventListener("abort", failed, { once: true });
    if (signal?.aborted) failed();
    child.once("error", failed);
    child.stdin.on("error", failed);
    child.stdout.on("data", (bytes: Buffer) => {
      outputBytes += bytes.length;
      if (outputBytes > 16384) {
        output = [];
        failed();
      } else if (!done) output.push(bytes);
    });
    child.stderr.on("data", (bytes: Buffer) => {
      errorBytes += bytes.length;
      if (errorBytes > 16384) failed();
    });
    child.once("close", (code) => {
      if (done) return;
      if (code !== 0) {
        failed();
        return;
      }
      done = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", failed);
      try {
        resolveResult(
          JSON.parse(
            new TextDecoder("utf-8", { fatal: true }).decode(
              Buffer.concat(output),
            ),
          ),
        );
      } catch {
        reject(new Error("hook"));
      }
    });
    child.stdin.end(request);
  }).catch(() =>
    fail(
      "CAP_CLI_AUTH_HOOK_FAILED",
      "failed_precondition",
      4,
      "Local authentication hook failed; check its private configuration.",
    ),
  );
  if (
    !closed(result, ["authResultVersion", "credentialRef"], ["expiresAt"]) ||
    result.authResultVersion !== "0.1" ||
    !credentialRef(result.credentialRef, true) ||
    (result.expiresAt !== undefined && !expiry(result.expiresAt, now))
  )
    fail(
      "CAP_CLI_AUTH_HOOK_FAILED",
      "failed_precondition",
      4,
      "Local authentication hook returned an invalid result.",
    );
  if (result.credentialRef.kind === "env" && !env[result.credentialRef.name])
    fail(
      "CAP_CLI_AUTH_HOOK_FAILED",
      "failed_precondition",
      4,
      "Hook environment reference must already exist in the client process.",
    );
  return {
    credentialRef: result.credentialRef,
    ...(result.expiresAt === undefined ? {} : { expiresAt: result.expiresAt }),
  };
}
export async function readInputFile(
  path: string,
  max = 1048576,
): Promise<string> {
  const handle = await open(path, "r");
  try {
    if ((await handle.stat()).size > max)
      fail(
        "CAP_CLI_PAYLOAD_TOO_LARGE",
        "invalid_argument",
        2,
        "Input exceeds the request limit.",
      );
    const bytes = await boundedFile(handle, max);
    if (bytes.length > max)
      fail(
        "CAP_CLI_PAYLOAD_TOO_LARGE",
        "invalid_argument",
        2,
        "Input exceeds the request limit.",
      );
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } finally {
    await handle.close();
  }
}
