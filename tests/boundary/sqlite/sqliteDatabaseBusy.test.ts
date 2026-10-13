import { spawn } from "node:child_process";
import { readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { expect, it, onTestFinished, vi } from "vitest";

import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { SqliteDatabaseProvider } from "../../../src/sqlite/SqliteDatabaseProvider.js";
import { createSqliteDatabaseFixture } from "../../fixtures/sqlite/database.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../support/workspace/workspaceFixture.js";

const busy = vi.hoisted(() => ({ path: "" }));

// Node opens files with full sharing, so a test process cannot hold one without read sharing
// itself. This injects the error Windows returns for that sharing violation.
vi.mock("node:fs/promises", async (importOriginal) => {
  const filesystem = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...filesystem,
    open: async (...args: Parameters<typeof filesystem.open>) => {
      if (busy.path !== "" && args[0] === busy.path)
        throw Object.assign(
          new Error(`EBUSY: resource busy or locked, open '${busy.path}'`),
          { code: "EBUSY", errno: -4082, syscall: "open", path: busy.path },
        );
      return filesystem.open(...args);
    },
  };
});

const privateRoots = async () =>
  (await readdir(tmpdir())).filter((name) =>
    name.startsWith("rea-sqlite-database-"),
  );

const expectRetryableBusy = (
  error: Parameters<typeof projectAnalysisError>[0],
  path: string,
) =>
  expect(projectAnalysisError(error)).toMatchObject({
    code: "capability_unavailable",
    category: "unavailable",
    retryable: true,
    message:
      "The selected SQLite database is held open by another process without read sharing. Close that application or inspect a copy, then retry.",
    details: {
      provider_id: "sqlite",
      operation: "inspect_sqlite_database",
      reason: expect.stringContaining(`(EBUSY): ${path}`),
    },
  });

it("reports a selected database held by another process as retryable and unavailable", async () => {
  const workspace = await createTestWorkspace("rea-sqlite-busy-");
  onTestFinished(() => removeTestWorkspace(workspace.root));
  const database = createSqliteDatabaseFixture(workspace.root);
  database.close();
  const before = await privateRoots();
  busy.path = database.path;
  onTestFinished(() => {
    busy.path = "";
  });
  const provider = new SqliteDatabaseProvider(process.env);
  onTestFinished(() => provider.close());

  const result = await provider.inspect({ path: database.path });
  if (result.ok) throw new Error("Expected a busy database rejection");
  expectRetryableBusy(result.error, database.path);
  expect(await privateRoots()).toEqual(before);
});

it.runIf(process.platform === "win32")(
  "reports a database that another Windows process holds without sharing as retryable",
  async () => {
    const workspace = await createTestWorkspace("rea-sqlite-busy-native-");
    onTestFinished(() => removeTestWorkspace(workspace.root));
    const database = createSqliteDatabaseFixture(workspace.root);
    database.close();
    const literal = database.path.replaceAll("'", "''");
    const holder = spawn(
      "powershell.exe",
      [
        "-NoProfile",
        "-Command",
        `$f = [System.IO.File]::Open('${literal}', 'Open', 'ReadWrite', 'None'); Write-Output ready; Start-Sleep -Seconds 60; $f.Close()`,
      ],
      { stdio: ["ignore", "pipe", "ignore"], windowsHide: true },
    );
    onTestFinished(() => {
      holder.kill();
    });
    await new Promise<void>((resolve, reject) => {
      holder.stdout.once("data", () => resolve());
      holder.once("exit", (code) =>
        reject(
          new Error(`Holder exited before opening the file (${String(code)})`),
        ),
      );
    });
    const provider = new SqliteDatabaseProvider(process.env);
    onTestFinished(() => provider.close());

    const result = await provider.inspect({ path: database.path });
    if (result.ok) throw new Error("Expected a busy database rejection");
    expectRetryableBusy(result.error, database.path);
  },
  20_000,
);
