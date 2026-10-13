import { expect, it, vi } from "vitest";
import {
  cleanupOwnedProcessGroup,
  type ProcessOwnershipHost,
} from "./ProcessOwnership.js";

it.each([
  { mode: "revalidation", includeWithheld: true },
  { mode: "signal-error", includeWithheld: true },
  { mode: "success", includeWithheld: true },
  { mode: "revalidation", includeWithheld: false },
  { mode: "signal-error", includeWithheld: false },
])(
  "retains observations on $mode with withheld=$includeWithheld",
  async ({ mode, includeWithheld }) => {
    const rows = [
      {
        pid: 100,
        parentPid: 1,
        processGroupId: 100,
        state: "S",
        command: "fixture",
      },
      ...(includeWithheld
        ? [
            {
              pid: 900,
              parentPid: 1,
              processGroupId: 900,
              state: "S",
              command: "opaque",
            },
          ]
        : []),
    ];
    let rootReads = 0;
    const signalGroup = vi.fn(() => {
      if (mode === "signal-error")
        throw Object.assign(new Error("signal denied"), { code: "EACCES" });
    });
    const host: ProcessOwnershipHost = {
      listProcesses: async () => rows,
      environment: async () => ({}),
      runTokens: async (members) =>
        new Map(
          members.map(({ pid }) => {
            if (pid === 900)
              return [
                pid,
                {
                  state: "unavailable" as const,
                  reason: "platform_binary_environment_withheld",
                },
              ];
            rootReads += 1;
            return [
              pid,
              {
                state: "readable" as const,
                runId:
                  mode === "revalidation" && rootReads > 2
                    ? "other-run"
                    : "run-token",
              },
            ];
          }),
        ),
      signalGroup,
    };
    const result = await cleanupOwnedProcessGroup(
      {
        runId: "run-token",
        leaderPid: 100,
        processGroupId: 100,
        sweepTokenOwnedProcesses: true,
        captureBaseline: [],
      },
      host,
    );
    expect(result.cleaned).toBe(mode === "success");
    expect(signalGroup).toHaveBeenCalledTimes(mode === "revalidation" ? 0 : 1);
    if (includeWithheld)
      expect(result.unverified).toEqual([
        { pid: 900, diagnostic: "platform_binary_environment_withheld" },
      ]);
    else expect(result).not.toHaveProperty("unverified");
    if (mode === "revalidation")
      expect(result).toMatchObject({
        reason: "process ownership token mismatch for PID(s): 100",
        failures: [{ pid: 100, reason: "run-token-mismatch" }],
      });
    if (mode === "signal-error")
      expect(result.reason).toBe(
        "owned process group signal failed: signal denied",
      );
  },
);
