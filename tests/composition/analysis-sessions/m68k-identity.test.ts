import { describe, expect, it } from "vitest";
import type { BinaryTarget } from "../../../src/domain/binaryTargetTypes.js";
import { createAnalysisProfile } from "../../../src/domain/analysisProfile.js";
import { createEvidence, parseEvidence } from "../../../src/domain/evidence.js";
import { createEvidenceBundle } from "../../../src/domain/evidenceBundle.js";
import {
  createAnalysisSnapshotEntry,
  parseAnalysisSnapshot,
  serializeAnalysisSnapshot,
  snapshotBinding,
  snapshotTarget,
  snapshotMatchesProfile,
} from "../../../src/domain/analysisSnapshot.js";
import { sessionOutputSchemas } from "../../../src/contracts/toolOutputSchemaGroups.js";

const target: BinaryTarget = {
  path: "/source-owned.elf",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "m68k",
  availableArchitectures: ["m68k"],
  m68k: { elfClass: 32, byteOrder: "big", type: 2, flags: 0x01000000 },
};
const provider = { id: "ghidra", name: "Ghidra", version: "12.1.4" };
const profile = createAnalysisProfile(provider, {
  m68k_elf: { elf_class: 32, byte_order: "big", type: 2, flags: 0x01000000 },
});

describe("m68k identity through lifecycle, Evidence and snapshot consumers", () => {
  it("round-trips query bindings without relaxing integrity", () => {
    const result = [{ address: "0x10000", value: "rea_m68k_entry" }];
    const parameters = {};
    const evidence = createEvidence(target, provider, {
      operation: "list_procedures",
      parameters,
      result,
      analysisProfile: profile,
    });
    const binding = snapshotBinding(profile);
    const entry = createAnalysisSnapshotEntry({
      target: snapshotTarget(target),
      binding,
      operation: "list_procedures",
      parameters,
      execution: {
        result,
        rawResult: null,
        provider,
        analysisProfile: profile,
        limitations: [],
        locations: [],
        subject: target,
      },
    });
    const snapshot = {
      target: snapshotTarget(target),
      binding,
      entries: [entry],
      workflow_entries: [],
      evidence_bundle: createEvidenceBundle([evidence]),
    };
    const restored = parseAnalysisSnapshot(
      JSON.parse(serializeAnalysisSnapshot(snapshot)),
    );
    expect(restored.target.architecture).toBe("m68k");
    expect(restored.evidence_bundle.records[0]?.subject?.architecture).toBe(
      "m68k",
    );
    expect(restored.entries[0]?.execution.subject?.architecture).toBe("m68k");
    expect(
      sessionOutputSchemas.open_binary.parse({ result: target }).result
        .architecture,
    ).toBe("m68k");
    expect(() =>
      parseEvidence({
        ...evidence,
        subject: { ...evidence.subject, architecture: "x86" },
      }),
    ).toThrow("semantic identifier");
    const changed = createAnalysisProfile(provider, {
      m68k_elf: {
        elf_class: 32,
        byte_order: "big",
        type: 2,
        flags: 0x01000001,
      },
    });
    expect(snapshotMatchesProfile(binding, changed)).toBe(false);
  });
});
