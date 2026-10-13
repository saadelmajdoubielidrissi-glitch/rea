import { expect, it, vi } from "vitest";
import { cleanupOwnedProcessGroup, type ProcessOwnershipHost } from "./ProcessOwnership.js";

it.each(["revalidation", "signal-error", "success"])("retains observation on %s", async (mode) => {
  const rows = [
    {pid: 100, parentPid: 1, processGroupId: 100, state: "S", command: "fixture"},
    {pid: 900, parentPid: 1, processGroupId: 900, state: "S", command: "opaque"},
  ];
  let rootReads = 0;
  const signalGroup = vi.fn(() => {
    if (mode === "signal-error") throw Object.assign(new Error("signal denied"), {code: "EACCES"});
  });
  const host: ProcessOwnershipHost = {
    listProcesses: async () => rows,
    environment: async () => ({}),
    runTokens: async (members) => new Map(members.map(({pid}) => {
      if (pid === 900) return [pid, {state: "unavailable" as const,
        reason: "platform_binary_environment_withheld"}];
      rootReads += 1;
      return [pid, {state: "readable" as const,
        runId: mode === "revalidation" && rootReads > 2 ? "other-run" : "run-token"}];
    })),
    signalGroup,
  };
  const result = await cleanupOwnedProcessGroup({runId: "run-token",
    leaderPid: 100, processGroupId: 100, sweepTokenOwnedProcesses: true,
    captureBaseline: []}, host);
  expect(result.cleaned).toBe(mode === "success");
  expect(signalGroup).toHaveBeenCalledTimes(mode === "revalidation" ? 0 : 1);
  expect(result.unverified).toEqual([{pid: 900,
    diagnostic: "platform_binary_environment_withheld"}]);
});
