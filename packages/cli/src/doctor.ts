import { findPackageJSON } from "node:module";
import { lstat, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import {
  Worker,
  isMainThread,
  parentPort,
  workerData,
} from "node:worker_threads";
import { compileProject } from "@capaxle/compiler";
import { inspectDeployment } from "@capaxle/app/build";
import { zodSchemaProvider } from "@capaxle/schema-zod";
import type { JsonValue } from "@capaxle/ir";

export interface LocalDoctorCheck {
  readonly id: string;
  readonly status: "pass" | "fail" | "skipped";
  readonly message: string;
  readonly location?: string;
  readonly remediation?: string;
  readonly code?: string;
  readonly details?: JsonValue;
}
export interface LocalDoctorOptions {
  readonly projectRoot: string;
  readonly deployment?: string;
  readonly deadlineMs?: number;
}
export interface LocalDoctorReport {
  readonly doctorVersion: "0.1";
  readonly mode: "local";
  readonly complete: boolean;
  readonly checks: readonly LocalDoctorCheck[];
}
const ids = [
  "node",
  "packages",
  "configuration",
  "discovery",
  "compilation",
  "artifacts",
  "providers",
  "mounts",
] as const;
type CheckName = (typeof ids)[number];
type Progress = { check: LocalDoctorCheck; exitCode?: 3 | 4 | 5 | 6 };

/** Trusted module evaluation runs in an owned worker which is terminated on deadline. */
export async function diagnoseLocalProject(
  options: LocalDoctorOptions,
): Promise<{
  report: LocalDoctorReport;
  exitCode: 0 | 3 | 4 | 5 | 6;
}> {
  const checks = new Map<string, LocalDoctorCheck>();
  let exitCode: 0 | 3 | 4 | 5 | 6 = 0;
  const worker = new Worker(new URL("./doctor.js", import.meta.url), {
    workerData: { capaxleDoctor: true, options },
    stdout: true,
    stderr: true,
  });
  // Application-authored console output can contain secrets; never forward it.
  worker.stdout.resume();
  worker.stderr.resume();
  await new Promise<void>((finish) => {
    let settled = false;
    const stop = async (failed?: "deadline" | "worker") => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (failed) {
        const pending =
          ids.find((id) => !checks.has(`local.${id}`)) ?? "compilation";
        checks.set(`local.${pending}`, {
          id: `local.${pending}`,
          status: "fail",
          code:
            failed === "deadline"
              ? "CAP_DOCTOR_DEADLINE"
              : "CAP_DOCTOR_WORKER_FAILED",
          message:
            failed === "deadline"
              ? "Diagnostic deadline expired; remaining evidence is unavailable."
              : "The isolated diagnostic process failed.",
          location: "project",
          remediation:
            "Check trusted configuration and capability module evaluation; retry with a larger --deadline-ms budget.",
        });
        if (exitCode === 0) exitCode = 6;
      }
      await worker.terminate();
      finish();
    };
    const timer = setTimeout(() => {
      void stop("deadline");
    }, options.deadlineMs ?? 10000);
    worker.on("message", (value: Progress | { done: true }) => {
      if (settled) return;
      if ("done" in value) {
        void stop();
        return;
      }
      checks.set(value.check.id, value.check);
      if (exitCode === 0 && value.exitCode) exitCode = value.exitCode;
    });
    worker.on("error", () => {
      void stop("worker");
    });
    worker.on("exit", () => {
      if (!settled) void stop("worker");
    });
  });
  const ordered = ids.map(
    (name) =>
      checks.get(`local.${name}`) ?? {
        id: `local.${name}`,
        status: "skipped" as const,
        message: "Prerequisite evidence is unavailable.",
        location: "project",
        remediation: "Resolve earlier failed checks and rerun doctor.",
      },
  );
  return {
    exitCode,
    report: {
      doctorVersion: "0.1",
      mode: "local",
      complete: ordered.every((check) => check.status === "pass"),
      checks: ordered,
    },
  };
}

async function inspectInstalledPackages(projectRoot: string): Promise<boolean> {
  const own = JSON.parse(
    await readFile(new URL("../package.json", import.meta.url), "utf8"),
  ) as { version: string };
  const projectFile = join(projectRoot, "package.json");
  const project = JSON.parse(await readFile(projectFile, "utf8")) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  const queue = [
    ...new Set([
      "@capaxle/cli",
      ...Object.keys({
        ...project.dependencies,
        ...project.devDependencies,
      }).filter((name) => name.startsWith("@capaxle/")),
    ]),
  ].map((name) => ({ name, from: projectFile }));
  const visited = new Set<string>();
  while (queue.length) {
    const { name, from } = queue.shift()!;
    const path = findPackageJSON(name, pathToFileURL(from));
    if (!path) return false;
    if (visited.has(path)) continue;
    visited.add(path);
    const installed = JSON.parse(await readFile(path, "utf8")) as {
      name?: string;
      version?: string;
      dependencies?: Record<string, string>;
    };
    if (installed.name !== name || installed.version !== own.version)
      return false;
    queue.push(
      ...Object.keys(installed.dependencies ?? {})
        .filter((entry) => entry.startsWith("@capaxle/"))
        .map((entry) => ({ name: entry, from: path })),
    );
  }
  return true;
}

async function runDiagnosticWorker(options: LocalDoctorOptions): Promise<void> {
  const post = (
    name: CheckName,
    status: LocalDoctorCheck["status"],
    message: string,
    extra: Omit<LocalDoctorCheck, "id" | "status" | "message"> = {},
    exitCode?: Progress["exitCode"],
  ) => {
    parentPort!.postMessage({
      check: { id: `local.${name}`, status, message, ...extra },
      ...(exitCode ? { exitCode } : {}),
    });
  };
  const [major, minor] = process.versions.node.split(".").map(Number);
  const supported = (major === 22 && minor! >= 15) || major === 24;
  post(
    "node",
    supported ? "pass" : "fail",
    supported ? "Node version is supported." : "Node version is unsupported.",
    { location: "node", remediation: "Use Node ^22.15.0 or ^24.0.0." },
    supported ? undefined : 6,
  );
  try {
    const compatible = await inspectInstalledPackages(options.projectRoot);
    post(
      "packages",
      compatible ? "pass" : "fail",
      compatible
        ? "Installed Capaxle packages share the CLI version train."
        : "Installed Capaxle packages do not match the CLI version train.",
      {
        location: "package.json",
        code: compatible
          ? "CAP_DOCTOR_PACKAGES_MATCH"
          : "CAP_DOCTOR_PACKAGES_MISMATCH",
        remediation:
          "Install matching versions of all declared @capaxle packages and refresh the lockfile.",
      },
      compatible ? undefined : 6,
    );
  } catch {
    post(
      "packages",
      "fail",
      "Project package dependencies could not be resolved.",
      {
        location: "package.json",
        code: "CAP_DOCTOR_PACKAGES_UNAVAILABLE",
        remediation:
          "Add a project package.json and install the declared Capaxle dependencies.",
      },
      6,
    );
  }
  try {
    const info = await lstat(join(options.projectRoot, "capaxle.config.ts"));
    if (!info.isFile() || info.isSymbolicLink()) throw new Error();
  } catch {
    post(
      "configuration",
      "fail",
      "Canonical configuration is missing or is not a regular file.",
      {
        location: "capaxle.config.ts",
        code: "CAP_DOCTOR_CONFIG_MISSING",
        remediation:
          "Create capaxle.config.ts with a default exported service configuration; avoid symlinks.",
      },
      3,
    );
    return;
  }
  const compilation = await compileProject({
    projectRoot: options.projectRoot,
    schemaProviders: [zodSchemaProvider],
  });
  let prerequisiteFailed = false;
  for (const name of ["configuration", "discovery", "compilation"] as const) {
    const diagnostic = compilation.diagnostics.find(
      (entry) =>
        entry.severity === "error" &&
        (name === "compilation"
          ? !["configuration", "discovery"].includes(entry.phase)
          : entry.phase === name),
    );
    const unavailable = prerequisiteFailed && !diagnostic;
    if (diagnostic) prerequisiteFailed = true;
    post(
      name,
      diagnostic ? "fail" : unavailable ? "skipped" : "pass",
      diagnostic
        ? "Compiler rejected this diagnostic stage."
        : unavailable
          ? "Compilation could not complete because a prerequisite failed."
          : "Compiler diagnostic stage passed.",
      {
        location: diagnostic
          ? `${diagnostic.source.file.replace(/[\r\n\x00-\x1f]/g, "?")}:${diagnostic.source.line}:${diagnostic.source.column}`
          : name === "configuration"
            ? "capaxle.config.ts"
            : "src/capabilities",
        ...(diagnostic ? { code: diagnostic.code } : {}),
        remediation: diagnostic
          ? "Correct the indicated source using the compiler diagnostic code; rerun capaxle check for trusted local detail."
          : unavailable
            ? "Resolve earlier compiler failures and rerun doctor."
            : "",
      },
      diagnostic ? (diagnostic.subphase.includes("load") ? 4 : 3) : undefined,
    );
  }
  if (!compilation.ok) return;
  const required = new Set<string>();
  for (const capability of compilation.document.capabilities) {
    if (capability.effects.confirmation === "required")
      required.add("confirmationProvider");
    if (capability.effects.idempotency === "key")
      required.add("idempotencyProvider");
    if (
      capability.requirements.secrets.some(
        (secret) =>
          typeof secret !== "object" ||
          secret === null ||
          (secret as { optional?: boolean }).optional !== true,
      )
    )
      required.add("secretProvider");
    if (capability.limits.rateLimit) required.add("rateLimitProvider");
    if (
      Object.values(capability.access.exposure).some(
        (exposure) => exposure === "authenticated" || exposure === "private",
      )
    )
      required.add("authenticationProviders");
    if ((capability.access.permissions as { public?: boolean }).public !== true)
      required.add("authorizationProvider");
  }
  post(
    "providers",
    "skipped",
    "Process-local provider registration cannot be proved without application execution.",
    {
      location: "ApplicationOptions.providers",
      details: { required: [...required].sort() },
      remediation:
        "Register the listed canonical policy providers and surface authentication providers in ApplicationOptions; verify readiness through application startup separately.",
    },
  );
  if (options.deployment) {
    const artifactLocation = relative(
      options.projectRoot,
      options.deployment,
    ).replace(/[\r\n\x00-\x1f]/g, "?");
    try {
      const inspected = await inspectDeployment(options.deployment);
      if (inspected.irHash !== compilation.irHash) throw new Error();
      post(
        "artifacts",
        "pass",
        "Existing deployment bytes and canonical IR identity are verified.",
        {
          location: artifactLocation,
          details: { irHash: inspected.irHash },
        },
      );
      post(
        "mounts",
        "pass",
        "Pinned configured surface topology is verified.",
        { location: "deploymentContext" },
      );
    } catch (error) {
      const mountCode = (error as { code?: string }).code;
      if (
        mountCode === "CAP_APP_MOUNT_COLLISION" ||
        mountCode === "CAP_APP_MOUNT_INVALID"
      ) {
        post(
          "artifacts",
          "skipped",
          "Artifact inspection could not finish because configured topology is invalid.",
          {
            location: artifactLocation,
            remediation: "Correct the deployment topology and rerun doctor.",
          },
        );
        post(
          "mounts",
          "fail",
          "Configured application mounts collide or have invalid syntax.",
          {
            location: "deploymentContext",
            code: mountCode,
            remediation:
              "Assign distinct method-sensitive capability and surface paths, then rebuild the deployment.",
          },
          3,
        );
        return;
      }
      post(
        "artifacts",
        "fail",
        "Existing deployment artifact bytes, identity or context are invalid or stale.",
        {
          location: artifactLocation,
          code: "CAP_DOCTOR_ARTIFACT_INVALID",
          remediation:
            "Rebuild the deployment from the current source and verify its manifest/module/artifact digests.",
        },
        5,
      );
      post("mounts", "skipped", "Deployment topology could not be verified.", {
        location: "deploymentContext",
        remediation: "Correct the deployment manifest and rerun doctor.",
      });
    }
  } else {
    post(
      "artifacts",
      "skipped",
      "Existing deployment artifact identity has not been supplied.",
      {
        location: "capaxle.deployment.json",
        remediation:
          "Pass --deployment <manifest> to verify existing bytes without rebuilding.",
      },
    );
    post(
      "mounts",
      "skipped",
      "Application surface topology is unavailable; compiler-known projection checks passed.",
      {
        location: "ApplicationOptions.surfaces",
        remediation:
          "Pass a prepared --deployment manifest to inspect configured mounts; server entries are never imported.",
      },
    );
  }
}

if (
  !isMainThread &&
  (workerData as { capaxleDoctor?: boolean })?.capaxleDoctor
) {
  try {
    await runDiagnosticWorker(
      (workerData as { options: LocalDoctorOptions }).options,
    );
    parentPort!.postMessage({ done: true });
  } catch {
    throw new Error("CAP_DOCTOR_WORKER_FAILED");
  }
}
