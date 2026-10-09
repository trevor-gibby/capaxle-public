import { lstat, mkdir, open, readFile, rmdir, unlink } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { templateFiles, templates, type Template } from "./templates.js";
export {
  frameworkVersion,
  templateFiles,
  templates,
  type Template,
} from "./templates.js";

export class CreateError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}
export function validateName(name: string): void {
  if (
    !/^[a-z][a-z0-9-]{0,63}$/.test(name) ||
    ["node_modules", "con", "prn", "aux", "nul"].includes(name) ||
    /^(com|lpt)[1-9]$/.test(name)
  )
    throw new CreateError(
      "CAP_CREATE_NAME_INVALID",
      "Use 1–64 lowercase letters, digits or hyphens, starting with a letter; reserved names are unavailable.",
    );
}

/** Exclusive creation only. Rollback removes only files with our unchanged bytes. */
export async function createProject(options: {
  name: string;
  template: Template;
  cwd?: string;
  signal?: AbortSignal;
}): Promise<string> {
  validateName(options.name);
  if (!templates.includes(options.template))
    throw new CreateError("CAP_CREATE_TEMPLATE_INVALID", "Unknown template.");
  const destination = resolve(options.cwd ?? process.cwd(), options.name);
  const files = templateFiles(options.name, options.template);
  const created: Array<{
    path: string;
    text: string;
    dev: number;
    ino: number;
  }> = [];
  const directories: string[] = [];
  const directoryIdentity = new Map<string, { dev: number; ino: number }>();
  const trustedAncestors = async (path: string): Promise<boolean> => {
    for (
      let parent = dirname(path);
      parent.length >= destination.length;
      parent = dirname(parent)
    ) {
      const expected = directoryIdentity.get(parent);
      const actual = await lstat(parent).catch(() => undefined);
      if (
        !expected ||
        !actual?.isDirectory() ||
        actual.isSymbolicLink() ||
        actual.dev !== expected.dev ||
        actual.ino !== expected.ino
      )
        return false;
      if (parent === destination) break;
    }
    return true;
  };
  const aborted = () => {
    if (options.signal?.aborted)
      throw new CreateError(
        "CAP_CREATE_INTERRUPTED",
        "Generation interrupted; existing files were preserved.",
      );
  };
  try {
    aborted();
    try {
      await mkdir(destination, { mode: 0o700 });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST")
        throw new CreateError(
          "CAP_CREATE_DESTINATION_EXISTS",
          "Destination already exists; choose a new directory. Overwrite is not supported.",
        );
      throw error;
    }
    directories.push(destination);
    directoryIdentity.set(destination, await lstat(destination));
    for (const [relative, text] of Object.entries(files)) {
      aborted();
      const path = join(destination, relative);
      const ancestors: string[] = [];
      for (
        let parent = dirname(path);
        parent !== destination;
        parent = dirname(parent)
      )
        ancestors.unshift(parent);
      for (const parent of ancestors) {
        if (directories.includes(parent)) continue;
        if (!(await trustedAncestors(parent)))
          throw new CreateError(
            "CAP_CREATE_DESTINATION_CHANGED",
            "Destination changed during generation.",
          );
        await mkdir(parent);
        directories.push(parent);
        directoryIdentity.set(parent, await lstat(parent));
        if (!(await trustedAncestors(join(parent, ".guard"))))
          throw new CreateError(
            "CAP_CREATE_DESTINATION_CHANGED",
            "Destination changed during generation.",
          );
      }
      // wx rejects user files and symlinks created during generation.
      if (!(await trustedAncestors(path)))
        throw new CreateError(
          "CAP_CREATE_DESTINATION_CHANGED",
          "Destination changed during generation.",
        );
      const handle = await open(path, "wx");
      try {
        const identity = await handle.stat();
        // A swapped parent cannot redirect payload writes after this post-open guard:
        // write through the owned handle rather than reopening the pathname.
        if (!(await trustedAncestors(path))) {
          const actual = await lstat(path).catch(() => undefined);
          if (
            actual?.isFile() &&
            actual.dev === identity.dev &&
            actual.ino === identity.ino
          )
            await unlink(path).catch(() => undefined);
          throw new CreateError(
            "CAP_CREATE_DESTINATION_CHANGED",
            "Destination changed during generation.",
          );
        }
        created.push({ path, text, dev: identity.dev, ino: identity.ino });
        await handle.writeFile(text);
      } finally {
        await handle.close();
      }
    }
    aborted();
    return destination;
  } catch (error) {
    for (const file of created.reverse()) {
      if (!(await trustedAncestors(file.path))) continue;
      const info = await lstat(file.path).catch(() => undefined);
      if (
        info?.isFile() &&
        !info.isSymbolicLink() &&
        info.dev === file.dev &&
        info.ino === file.ino &&
        (await readFile(file.path, "utf8").catch(() => undefined)) === file.text
      )
        await unlink(file.path).catch(() => undefined);
    }
    for (const directory of directories.reverse()) {
      const expected = directoryIdentity.get(directory);
      const actual = await lstat(directory).catch(() => undefined);
      if (
        actual?.isDirectory() &&
        !actual.isSymbolicLink() &&
        expected?.dev === actual.dev &&
        expected.ino === actual.ino
      )
        await rmdir(directory).catch(() => undefined);
    }
    throw error;
  }
}
