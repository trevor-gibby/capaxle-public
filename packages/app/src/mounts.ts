import type { CompilationSuccess } from "@capaxle/compiler";
import { ApplicationError } from "./errors.js";
const mountFailure = (code: string, message: string): never => {
  throw new ApplicationError(code, message);
};
export const validPath = (path: string): boolean =>
  path === "/" ||
  (path.startsWith("/") &&
    !path.startsWith("//") &&
    !path.endsWith("/") &&
    !/[?#\\\0%]/.test(path) &&
    path
      .split("/")
      .slice(1)
      .every((part) => part !== "" && part !== "." && part !== ".."));
const segments = (path: string): readonly string[] => path.split("/").slice(1);
export const overlaps = (left: string, right: string): boolean => {
  const a = segments(left),
    b = segments(right);
  if (a.at(-1) === "{path+}" || b.at(-1) === "{path+}") {
    const glob = a.at(-1) === "{path+}" ? a : b;
    const other = glob === a ? b : a;
    return (
      other.length >= glob.length &&
      glob
        .slice(0, -1)
        .every(
          (part, index) =>
            part === other[index] ||
            /^\{[^/{}]+\}$/.test(part) ||
            /^\{[^/{}]+\}$/.test(other[index]!),
        )
    );
  }
  return (
    a.length === b.length &&
    a.every(
      (part, index) =>
        part === b[index] ||
        /^\{[^/{}]+\}$/.test(part) ||
        /^\{[^/{}]+\}$/.test(b[index]!),
    )
  );
};

export interface Route {
  readonly method: string;
  readonly path: string;
  readonly owner: string;
}

export function validateReservations(routes: readonly Route[]): void {
  for (let i = 0; i < routes.length; i++) {
    const route = routes[i]!;
    if (
      (!(route.owner === "mcp" && route.method === "*") &&
        !/^[A-Z]+$/.test(route.method)) ||
      !validPath(route.path)
    )
      mountFailure("CAP_APP_MOUNT_INVALID", "Invalid surface reservation.");
    for (let j = 0; j < i; j++)
      if (
        (routes[j]!.method === route.method ||
          routes[j]!.method === "*" ||
          route.method === "*") &&
        overlaps(routes[j]!.path, route.path)
      )
        mountFailure(
          "CAP_APP_MOUNT_COLLISION",
          `Surface route collision: ${route.method} ${route.path}.`,
        );
  }
}

const join = (base: string, path: string): string =>
  base === "/" ? path : path === "/" ? base : `${base}${path}`;
export function routeReservations(
  compilation: Pick<CompilationSuccess, "document" | "discovery">,
  basePath: string,
  surfaces: {
    readonly http?: { readonly enabled: boolean };
    readonly mcp?: { readonly enabled: boolean };
  },
  registrations: readonly {
    readonly kind: string;
    readonly reservations: readonly {
      readonly method: string;
      readonly path: string;
    }[];
  }[],
): Route[] {
  const routes: Route[] = [];
  const add = (method: string, path: string, owner: string) =>
    routes.push({ method, path: join(basePath, path), owner });
  if (surfaces.http?.enabled) {
    for (const path of [
      "/healthz",
      "/readyz",
      "/openapi.json",
      compilation.discovery.http.collection,
      compilation.discovery.http.detailTemplate,
      compilation.discovery.http.schemaTemplate,
    ])
      add("GET", path, "http");
    for (const capability of compilation.document.capabilities) {
      const projection = capability.interfaces.http as {
        enabled: boolean;
        method?: string;
        path?: string;
      };
      if (projection.enabled && projection.method && projection.path)
        add(projection.method, projection.path, "http");
    }
  }
  if (surfaces.mcp?.enabled)
    add("*", compilation.discovery.mcp.endpoint, "mcp");
  for (const registration of registrations)
    for (const reservation of registration.reservations)
      add(reservation.method, reservation.path, registration.kind);
  validateReservations(routes);
  return routes;
}

export function resolvedBasePath(path: string | undefined): string {
  const value = path ?? "/";
  if (!validPath(value))
    mountFailure("CAP_APP_MOUNT_INVALID", "Invalid application base path.");
  return value;
}

export function resolvedExternalUrl(
  value: string | undefined,
  basePath: string,
  development: boolean,
): string | undefined {
  if (value === undefined) return;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return mountFailure("CAP_APP_MOUNT_INVALID", "Invalid external URL.");
  }
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";
  if (
    (url.protocol !== "https:" &&
      !(development && loopback && url.protocol === "http:")) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== basePath ||
    !validPath(url.pathname)
  )
    mountFailure("CAP_APP_MOUNT_INVALID", "Invalid external URL.");
  return url.href.replace(/\/$/, basePath === "/" ? "" : "/");
}
