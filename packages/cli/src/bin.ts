#!/usr/bin/env node
import {
  defaultFrameworkCliDependencies,
  runFrameworkCli,
} from "./framework-cli.js";

process.exitCode = await runFrameworkCli(
  process.argv.slice(2),
  defaultFrameworkCliDependencies,
  { stdout: process.stdout, stderr: process.stderr },
);
