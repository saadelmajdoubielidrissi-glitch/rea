import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { assertClientConfig } from "../../../scripts/verify-package-setup.mjs";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

it("rejects a backup replaced with the successfully registered client configuration", async () => {
  const directory = await createTestTempDirectory("rea-client-backup-");
  const path = join(directory, "claude_desktop_config.json");
  const original = Buffer.from('{"existing":true,"model":"caller-selected"}\n');
  const configured = JSON.stringify({
    existing: true,
    model: "caller-selected",
    mcpServers: { rea: { command: process.execPath, args: ["mcp"] } },
  });
  await writeFile(path, configured);
  await writeFile(`${path}.rea.backup`, original);
  await assertClientConfig(process.execPath, path, original);

  await writeFile(`${path}.rea.backup`, configured);
  await expect(
    assertClientConfig(process.execPath, path, original),
  ).rejects.toThrow("packaged client backup failed");
  expect(await readFile(path, "utf8")).toBe(configured);
});

it("requires exact backup text while still validating the live registration", async () => {
  const directory = await createTestTempDirectory("rea-client-backup-text-");
  const path = join(directory, "settings.json");
  const original = Buffer.from('{"existing":true}\n');
  const configured = JSON.stringify({
    existing: true,
    mcpServers: { rea: { command: process.execPath, args: ["mcp"] } },
  });
  await writeFile(path, configured);
  await writeFile(`${path}.rea.backup`, original.toString("utf8").trimEnd());
  await expect(
    assertClientConfig(process.execPath, path, original),
  ).rejects.toThrow("packaged client backup failed");
  await writeFile(`${path}.rea.backup`, original);
  await writeFile(
    path,
    JSON.stringify({
      existing: true,
      mcpServers: { rea: { command: "foreign", args: ["mcp"] } },
    }),
  );
  await expect(
    assertClientConfig(process.execPath, path, original),
  ).rejects.toThrow("packaged client readback failed");
});

it("rejects changed backup bytes even when UTF-8 replacement decoding looks equal", async () => {
  const directory = await createTestTempDirectory("rea-client-backup-bytes-");
  const path = join(directory, "settings.json");
  const original = Buffer.from('{"existing":true,"note":"\uFFFD"}\n');
  const configured = JSON.stringify({
    existing: true,
    mcpServers: { rea: { command: process.execPath, args: ["mcp"] } },
  });
  await writeFile(path, configured);
  const changed = Buffer.concat([
    Buffer.from('{"existing":true,"note":"'),
    Buffer.from([0xff]),
    Buffer.from('"}\n'),
  ]);
  expect(changed.toString("utf8")).toBe(original.toString("utf8"));
  await writeFile(`${path}.rea.backup`, changed);
  await expect(
    assertClientConfig(process.execPath, path, original),
  ).rejects.toThrow("packaged client backup failed");
});
