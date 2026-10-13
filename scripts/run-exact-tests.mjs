import { lstat, realpath } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { createVitest, parseCLI } from "vitest/node";

// CLI file filters are substring matches. Select discovered specifications by
// identity instead, retaining each project's include/exclude and runner settings.
const { filter, options } = parseCLI(["vitest", ...process.argv.slice(2)]);
const vitest = await createVitest({ ...options, watch: false });
const signalExitCodes = { SIGINT: 130, SIGTERM: 143 };
let shutdownSignal;
let closePromise;
const close = () => (closePromise ??= vitest.close());
for (const signal of Object.keys(signalExitCodes))
  process.on(signal, () => {
    if (shutdownSignal !== undefined) return;
    shutdownSignal = signal;
    void close().catch((cause) => {
      console.error(cause instanceof Error ? cause.message : String(cause));
      process.exitCode = 1;
    });
  });
try {
  if (shutdownSignal === undefined) await vitest.standalone();
  if (shutdownSignal === undefined) {
    const discovered = new Map();
    for (const specification of await vitest.globTestSpecifications()) {
      const path = resolve(specification.moduleId);
      const specifications = discovered.get(path) ?? [];
      specifications.push(specification);
      discovered.set(path, specifications);
    }
    const selected = new Set();
    const missing = [];
    for (const path of filter) {
      const absolute = resolve(path);
      let matches = discovered.get(absolute) ?? [];
      if (matches.length === 0 && process.platform === "win32") {
        let selectedEntry;
        try {
          selectedEntry = await lstat(absolute);
        } catch (cause) {
          if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") {
            missing.push(path);
            continue;
          }
          throw cause;
        }
        if (selectedEntry.isSymbolicLink()) {
          missing.push(path);
          continue;
        }
        if (await hasSymbolicLinkInPath(absolute)) {
          missing.push(path);
          continue;
        }
        const canonical = await realpath(absolute);
        for (const [candidate, specifications] of discovered) {
          // Confirm filesystem identity: Windows directories may opt into case
          // sensitivity. Do not collapse distinct symlink entries to one target.
          if (candidate.toLowerCase() !== absolute.toLowerCase()) continue;
          let candidateEntry;
          try {
            candidateEntry = await lstat(candidate);
          } catch (cause) {
            if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") continue;
            throw cause;
          }
          if (
            !candidateEntry.isSymbolicLink() &&
            !(await hasSymbolicLinkInPath(candidate)) &&
            (await realpath(candidate)) === canonical
          )
            matches = [...matches, ...specifications];
        }
      }
      if (matches.length === 0) missing.push(path);
      for (const specification of matches) selected.add(specification);
    }
    if (missing.length > 0 || selected.size === 0)
      throw new Error(
        `Selected test files were not discovered: ${missing.join(", ")}`,
      );
    if (shutdownSignal === undefined)
      await vitest.runTestSpecifications([...selected]);
  }
} finally {
  await close();
}
if (shutdownSignal !== undefined)
  process.exitCode = signalExitCodes[shutdownSignal];

async function hasSymbolicLinkInPath(path) {
  let current = resolve(path);
  for (;;) {
    try {
      if ((await lstat(current)).isSymbolicLink()) return true;
    } catch (cause) {
      if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") return false;
      throw cause;
    }
    const parent = dirname(current);
    if (parent === current) return false;
    current = parent;
  }
}
