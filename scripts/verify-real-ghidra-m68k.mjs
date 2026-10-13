#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseBinaryTarget } from "../dist/application/BinaryTargetResolver.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { parseAnalysisSnapshot } from "../dist/domain/analysisSnapshot.js";
import { functionDossierSchema } from "../dist/domain/hopperValues.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import {
  assertM68kGlobal,
  assertM68kLoadedImage,
  assertM68kMarker,
  assertM68kProbe,
  parseM68kFixture,
} from "../tests/conformance/ghidra/m68k-checks.mjs";
import {
  buildM68kFixture,
  M68K_FIXTURE,
} from "../tests/conformance/ghidra/m68k-fixture.mjs";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

// Optional source-owned lane. No tool acquisition and no target execution.
if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-m68k.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "m68k verification requires a supported Linux/macOS Ghidra host",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error("Missing prerequisite: caller-supplied GHIDRA_INSTALL_DIR");
const installation = inspectGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
if (installation.status !== "available")
  throw new Error(
    `Ghidra prerequisite unavailable: ${JSON.stringify(installation)}`,
  );
const execute = promisify(execFile);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-m68k-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  GHIDRA_INSTALL_DIR: installation.installDir,
  JAVA_HOME: installation.javaHome,
  HOPPER_LAUNCHER_PATH: "/rea-unconfigured-deep-provider/hopper",
};
for (const setting of ["GHIDRA_HEADLESS_MAXMEM", "GHIDRA_MAXMEM"]) {
  if (process.env[setting] !== undefined) env[setting] = process.env[setting];
}
const reports = [];
let primaryFailure;
try {
  const fixture = await buildM68kFixture(workspace);
  const independent = parseM68kFixture(fixture.bytes);
  assert.equal(independent.sha256, fixture.sha256);
  const resolved = await parseBinaryTarget(fixture.path);
  if (!resolved.ok) throw resolved.error;
  assert.deepEqual(
    resolved.value.m68k,
    {
      elfClass: 32,
      byteOrder: "big",
      type: 2,
      flags: M68K_FIXTURE.flags,
    },
    "REA ELF interpretation disagrees with the source-owned fixture",
  );
  assert.equal(resolved.value.sha256, fixture.sha256);
  const snapshotPath = join(workspace, "m68k.snapshot.json");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "mcp"],
    env,
    stderr: "pipe",
  });
  const client = new Client({ name: "rea-real-m68k-proof", version: "1" });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-65536);
  });
  const call = async (name, args = {}) => {
    const reply = await client.callTool(
      { name, arguments: args },
      { timeout: 180000 },
    );
    return requireMcpOperationResult(reply, name);
  };
  try {
    await client.connect(transport);
    const target = await call("open_binary", {
      path: fixture.path,
      provider_id: "ghidra",
    });
    assert.equal(target.architecture, "m68k");
    assert.equal(target.sha256, fixture.sha256);
    const image = await call("inspect_native_load_image");
    assertM68kLoadedImage(image.observations, fixture.sha256);
    const move = await call("inspect_native_instruction", {
      address: `0x${M68K_FIXTURE.probe.move.address.toString(16)}`,
    });
    const branch = await call("inspect_native_instruction", {
      address: `0x${M68K_FIXTURE.probe.branch.address.toString(16)}`,
    });
    assertM68kProbe(move, branch);
    const global = await call("read_bytes", {
      address: `0x${M68K_FIXTURE.global.address.toString(16)}`,
      length: 4,
    });
    assert.equal(global.returned_bytes, 4);
    assertM68kGlobal(global.bytes_hex);
    const marker = await call("read_bytes", {
      address: `0x${M68K_FIXTURE.marker.address.toString(16)}`,
      length: M68K_FIXTURE.marker.text.length + 1,
    });
    assert.equal(marker.returned_bytes, M68K_FIXTURE.marker.text.length + 1);
    assertM68kMarker(marker.bytes_hex);
    const procedures = await call("list_procedures");
    const entry = procedures.find(
      (procedure) => BigInt(procedure.address) === BigInt(M68K_FIXTURE.entry),
    );
    assert.ok(entry, "Entry function missing from real Ghidra inventory");
    const assembly = await call("procedure_assembly", {
      procedure: entry.address,
    });
    assert.ok(assembly.trim().length > 0);
    const dossier = functionDossierSchema.parse(
      await call("analyze_function", { procedure: entry.address }),
    );
    assert.ok(dossier.pseudocode.trim().length > 0);
    const mapping = await call("address_to_file_offset", {
      address: entry.address,
    });
    const memory = await call("read_bytes", {
      address: entry.address,
      length: 16,
    });
    const sourceBytes = await readFile(fixture.path);
    assert.equal(memory.returned_bytes, 16);
    assert.equal(
      memory.bytes_hex,
      sourceBytes
        .subarray(mapping.file_offset, mapping.file_offset + 16)
        .toString("hex"),
      "Loaded bytes disagree with the original artifact mapping",
    );
    const saved = await call("close_binary", { snapshot_path: snapshotPath });
    assert.ok(saved.evidence_records > 0);
    const snapshot = parseAnalysisSnapshot(
      JSON.parse(await readFile(snapshotPath, "utf8")),
    );
    assert.equal(snapshot.target.architecture, "m68k");
    assert.equal(
      snapshot.binding.analysis_profile.parameters.m68k_elf.flags,
      M68K_FIXTURE.flags,
    );
    assert.equal(
      snapshot.binding.analysis_profile.parameters.m68k_support_lane,
      "elf32-exec-m68000-family-v1",
    );
    assert.equal(
      snapshot.binding.analysis_profile.parameters.language_selection,
      "provider-pinned-v1",
    );
    assert.equal(
      snapshot.binding.analysis_profile.parameters.language_id,
      M68K_FIXTURE.language_id,
    );
    assert.equal(
      snapshot.binding.analysis_profile.parameters.compiler_spec_id,
      M68K_FIXTURE.compiler_spec_id,
    );
    assert.ok(snapshot.evidence_bundle.records.length > 0);
    for (const evidence of snapshot.evidence_bundle.records)
      assert.equal(parseEvidence(evidence).subject?.architecture, "m68k");
    await call("open_binary", {
      path: fixture.path,
      provider_id: "ghidra",
      snapshot_path: snapshotPath,
    });
    assert.deepEqual(await call("list_procedures"), procedures);
    await call("close_binary");

    // Same public operation through CLI, not a private injected provider.
    const cli = await execute(
      process.execPath,
      [
        entrypoint,
        "instructions",
        fixture.path,
        entry.address,
        "--provider",
        "ghidra",
        "--json",
      ],
      { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
    );
    const evidence = parseEvidence(JSON.parse(cli.stdout));
    assert.equal(evidence.subject?.architecture, "m68k");
    assert.equal(evidence.subject?.digest.sha256, fixture.sha256);
    assert.ok(evidence.normalized_result.instructions.length > 0);
    assert.ok(
      evidence.normalized_result.instructions.some((instruction) =>
        /0x12345678/iu.test(instruction),
      ),
      "CLI instruction listing lost the source-owned immediate",
    );
    assert.equal(
      createHash("sha256")
        .update(await readFile(fixture.path))
        .digest("hex"),
      fixture.sha256,
      "Analysis modified the source executable",
    );
    reports.push({
      path: fixture.path,
      sha256: fixture.sha256,
      independent_reader: independent,
      effective_language: image.observations.language_id,
      effective_compiler_spec: image.observations.compiler_spec_id,
      checks: [
        "independent ELF and segment bytes",
        "loaded Ghidra identity and mapping",
        "fixed MOVE.L/short BRA bytes, immediate and destination",
        "global word and marker bytes",
        "CLI/MCP and snapshot identity",
      ],
      procedures: procedures.length,
      status: "passed",
    });
  } catch (cause) {
    throw new Error(`m68k verification failed; MCP stderr: ${stderr}`, {
      cause,
    });
  } finally {
    try {
      await client.close();
    } finally {
      await transport.close();
    }
  }
} catch (cause) {
  primaryFailure = cause;
}
const completed = await completeVerifierRun(run);
if (
  completed.process_lineage.status !== "verified" ||
  completed.process_lineage.descendants.length !== 0
)
  throw new Error(
    `Cleanup unverified; retained diagnostic workspace: ${workspace}`,
    { cause: primaryFailure },
  );
if (primaryFailure !== undefined)
  throw new Error(
    `m68k verification failed; retained workspace: ${workspace}`,
    {
      cause: primaryFailure,
    },
  );
await rm(workspace, { recursive: true, force: true });
console.log(JSON.stringify({ ...completed, fixtures: reports }, null, 2));
