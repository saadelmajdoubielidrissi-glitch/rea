#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { buildMips1Fixture } from "../tests/conformance/ghidra/mips1-fixture.mjs";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { functionDossierSchema } from "../dist/domain/hopperValues.js";
import { parseEvidence } from "../dist/domain/evidence.js";
import { parseAnalysisSnapshot } from "../dist/domain/analysisSnapshot.js";

// Static inspection only. No MIPS compiler, acquisition or target execution.
if (!process.env.GHIDRA_INSTALL_DIR || !process.env.JAVA_HOME)
  throw new Error("Supply GHIDRA_INSTALL_DIR and JAVA_HOME.");
const execute = promisify(execFile);
const root = await mkdtemp(join(tmpdir(), "rea-ghidra-mips1-"));
const reports = [];
try {
  for (const byteOrder of ["little", "big"]) {
    const fixture = await buildMips1Fixture(root, byteOrder);
    const { stdout: headers } = await execute(
      process.env.REA_READELF ?? "readelf",
      ["-h", "-s", fixture.path],
    );
    assert.match(headers, /ELF32/u);
    assert.match(headers, /0x1001.*o32.*mips1/u);
    assert.match(headers, /00401000.*rea_mips1_entry/u);
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [fileURLToPath(new URL("./rea.mjs", import.meta.url)), "mcp"],
      env: {
        ...process.env,
        REA_ANALYSIS_PROVIDER: "ghidra",
        REA_LOG_LEVEL: "silent",
        TMPDIR: root,
      },
      stderr: "inherit",
    });
    const client = new Client({ name: "rea-mips1-verifier", version: "1" });
    const call = async (name, args = {}) =>
      requireMcpOperationResult(
        await client.callTool({ name, arguments: args }, { timeout: 240_000 }),
        name,
      );
    try {
      await client.connect(transport);
      const selected = await call("open_binary", {
        path: fixture.path,
        provider_id: "ghidra",
      });
      assert.equal(selected.sha256, fixture.sha256);
      const image = await call("inspect_native_load_image");
      assert.equal(
        image.observations.language_id,
        `MIPS:${byteOrder === "little" ? "LE" : "BE"}:32:default`,
      );
      const first = await call("inspect_native_instruction", {
        address: fixture.entry,
      });
      const delay = await call("inspect_native_instruction", {
        address: "0x401008",
      });
      const branch = await call("inspect_native_instruction", {
        address: "0x401004",
      });
      assert.equal(first.status, "decoded");
      assert.match(first.mnemonic, /^addiu$/iu);
      assert.match(delay.mnemonic, /^_?sll$/iu);
      assert.equal(branch.status, "decoded");
      assert.match(branch.mnemonic, /^beq$/iu);
      assert.equal(branch.flow.kind, "jump");
      assert.equal(branch.flow.conditional, true);
      assert.deepEqual(branch.flow.direct_destinations, ["0x401010"]);
      const loaded = await call("read_bytes", {
        address: fixture.entry,
        length: 24,
      });
      assert.equal(loaded.returned_bytes, 24);
      const bytes = Buffer.from(loaded.bytes_hex, "hex");
      const words = Array.from({ length: 6 }, (_, index) =>
        byteOrder === "little"
          ? bytes.readUInt32LE(index * 4)
          : bytes.readUInt32BE(index * 4),
      );
      assert.deepEqual(words, fixture.words);
      const dossier = functionDossierSchema.parse(
        await call("analyze_function", { procedure: fixture.entry }),
      );
      assert.ok(dossier.pseudocode.trim().length > 0);
      assert.ok(dossier.assembly.some((line) => /sll/iu.test(line)));

      const snapshotPath = join(root, `snapshot-${byteOrder}.json`);
      await call("close_binary", { snapshot_path: snapshotPath });
      const snapshot = parseAnalysisSnapshot(
        JSON.parse(await readFile(snapshotPath, "utf8")),
      );
      assert.ok(
        snapshot.evidence_bundle.records.some((record) =>
          parseEvidence(record).limitations.some((text) =>
            /Floating-point ABI behavior remains unverified/u.test(text),
          ),
        ),
      );
      assert.equal(
        snapshot.binding.analysis_profile.parameters.mips_support_lane,
        "elf32-exec-mips1-recordless-pinned-v1",
      );
      await call("open_binary", {
        path: fixture.path,
        provider_id: "ghidra",
        snapshot_path: snapshotPath,
      });
      const replay = await call("analyze_function", {
        procedure: fixture.entry,
      });
      assert.deepEqual(replay, dossier);
      await call("close_binary");
      if (byteOrder === "little") {
        const { stdout } = await execute(
          process.execPath,
          [
            fileURLToPath(new URL("./rea.mjs", import.meta.url)),
            "function",
            fixture.path,
            fixture.entry,
            "--provider",
            "ghidra",
            "--full-output",
            "--json",
          ],
          { env: process.env, timeout: 240_000, maxBuffer: 32 * 1024 ** 2 },
        );
        const envelope = JSON.parse(stdout);
        assert.equal(envelope.ok, true);
        const cliEvidence = parseEvidence(envelope.data);
        assert.equal(cliEvidence.subject?.digest.sha256, fixture.sha256);
        const cliDossier = functionDossierSchema.parse(
          cliEvidence.normalized_result,
        );
        assert.equal(cliDossier.pseudocode, dossier.pseudocode);
      }
      assert.equal(
        createHash("sha256")
          .update(await readFile(fixture.path))
          .digest("hex"),
        fixture.sha256,
      );
      reports.push({
        byte_order: byteOrder,
        sha256: fixture.sha256,
        language: image.observations.language_id,
        source_unchanged: true,
        loaded_bytes: true,
        cli: byteOrder === "little" ? "verified" : "not-run",
        instruction_decode: true,
        conditional_branch_destination: true,
        expected_delay_slot_instruction_decoded: true,
        delay_slot_relationship: "not-exposed-by-instruction-contract",
        dossier: true,
        snapshot_replay: true,
        fp_semantics: "unverified",
        target_executed: false,
      });
    } finally {
      try {
        await client.close();
      } finally {
        await transport.close();
      }
    }
  }
  console.log(JSON.stringify({ status: "passed", reports }, null, 2));
} finally {
  await rm(root, { recursive: true, force: true });
}
