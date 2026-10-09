#!/usr/bin/env node
import { createInterface } from "node:readline/promises";
import {
  createProject,
  CreateError,
  templates,
  type Template,
} from "./index.js";

const usage =
  "create-capaxle NAME --template default|protected|existing-server --no-input\nInteractive: create-capaxle (select name and template)\n";
const controller = new AbortController();
process.once("SIGINT", () => controller.abort());
process.once("SIGTERM", () => controller.abort());
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 1 && ["--help", "-h"].includes(args[0]!)) {
    process.stdout.write(usage);
    return;
  }
  let name: string | undefined;
  let template: Template | undefined;
  let noInput = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "--no-input" && !noInput) noInput = true;
    else if (arg === "--template" && !template) {
      const value = args[++index];
      if (!templates.includes(value as Template))
        throw new CreateError("CAP_CREATE_TEMPLATE_INVALID", usage);
      template = value as Template;
    } else if (!arg.startsWith("-") && !name) name = arg;
    else throw new CreateError("CAP_CREATE_ARGUMENT_INVALID", usage);
  }
  if (!noInput && (!name || !template)) {
    // Explicit scripted stdin is also supported; EOF is an interruption, never a default answer.
    const readline = createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: Boolean(process.stdin.isTTY),
    });
    const iterator = readline[Symbol.asyncIterator]();
    const close = () => readline.close();
    controller.signal.addEventListener("abort", close, { once: true });
    const answer = async (prompt: string): Promise<string> => {
      process.stdout.write(prompt);
      const line = await iterator.next();
      if (line.done || controller.signal.aborted)
        throw new CreateError(
          "CAP_CREATE_INTERRUPTED",
          "Interactive generation interrupted.",
        );
      return line.value;
    };
    try {
      name ??= await answer("Project name: ");
      const selected =
        template ??
        (await answer(
          "Template (default, protected, existing-server) [default]: ",
        ));
      template = (selected || "default") as Template;
    } finally {
      controller.signal.removeEventListener("abort", close);
      readline.close();
    }
  }
  if (!name)
    throw new CreateError(
      "CAP_CREATE_NAME_INVALID",
      "A project name is required.\n" + usage,
    );
  template ??= "default";
  if (!templates.includes(template))
    throw new CreateError("CAP_CREATE_TEMPLATE_INVALID", usage);
  await createProject({ name, template, signal: controller.signal });
  const url = `http://127.0.0.1:3000${template === "existing-server" ? "/capabilities" : ""}`;
  process.stdout.write(
    `Created ${name} (${template}).\nNext: cd ${name}\nnpm install\ncp .env.example .env\n${template === "protected" ? "Provision APPLICATION_TOKEN in .env before startup.\n" : ""}npm run check\nnpm run dev\nAPI ${url}/.well-known/capabilities\nMCP ${url}/mcp\nRemote CLI ${url}/cli\nBrowser ${url}/docs/connection\n`,
  );
}
main().catch((error) => {
  const interrupted =
    controller.signal.aborted ||
    error?.name === "AbortError" ||
    error?.code === "ERR_USE_AFTER_CLOSE" ||
    error?.code === "CAP_CREATE_INTERRUPTED";
  process.stderr.write(
    `${interrupted ? "CAP_CREATE_INTERRUPTED" : error instanceof CreateError ? error.code : "CAP_CREATE_FAILED"}: ${interrupted ? "Generation interrupted; existing files preserved." : error instanceof CreateError ? error.message : "Could not create project; existing files preserved."}\n`,
  );
  process.exitCode = interrupted ? 130 : 2;
});
