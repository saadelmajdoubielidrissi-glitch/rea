import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";

it("keeps the caller working directory when launching the Windows GUI", async () => {
  const entrypoint = await readFile(
    new URL("../../../windows-gui/rea-gui.mjs", import.meta.url),
    "utf8",
  );

  expect(entrypoint).toContain("cwd: process.cwd()");
});
