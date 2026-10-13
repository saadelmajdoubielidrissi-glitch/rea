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
import {
  requireMcpOperationResult,
  requireMcpEvidenceResult,
  mcpTextValue,
} from "./lib/mcp-verifier-results.mjs";
import { parseEvidence } from "../dist/domain/evidence.js";
import { functionDossierSchema } from "../dist/domain/hopperValues.js";

// Compile source-owned input and inspect it through the production CLI. Never execute it.
if (
  !["darwin", "linux"].includes(process.platform) ||
  !["arm64", "x64"].includes(process.arch)
)
  throw new Error(
    "This fixture requires an AArch64/x86_64 Linux or macOS host.",
  );
if (!process.env.GHIDRA_INSTALL_DIR || !process.env.JAVA_HOME)
  throw new Error(
    "Supply GHIDRA_INSTALL_DIR and JAVA_HOME; the verifier installs no tools.",
  );
const execute = promisify(execFile);
const root = await mkdtemp(join(tmpdir(), "rea-ghidra-completeness-"));
const source = fileURLToPath(
  new URL("../tests/conformance/c/decompiler-completeness.S", import.meta.url),
);
const cli = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const target = join(root, "probe");
try {
  await execute(process.env.REA_CC ?? "cc", [
    source,
    ...(process.platform === "linux" ? ["-fno-pie", "-no-pie"] : []),
    "-o",
    target,
  ]);
  const digest = createHash("sha256")
    .update(await readFile(target))
    .digest("hex");
  const { stdout: symbols } = await execute("nm", ["-n", target]);
  const entry = /^([a-fA-F0-9]+)\s+T\s+_?main$/mu.exec(symbols);
  assert.ok(entry, "Independent nm entry address unavailable");
  const cleanEntry = /^([a-fA-F0-9]+)\s+T\s+_?rea_clean$/mu.exec(symbols);
  assert.ok(cleanEntry, "Independent clean function address unavailable");
  const procedure = `0x${BigInt(`0x${entry[1]}`).toString(16)}`;
  const cleanProcedure = `0x${BigInt(`0x${cleanEntry[1]}`).toString(16)}`;
  const { stdout } = await execute(
    process.execPath,
    [
      cli,
      "function",
      target,
      procedure,
      "--provider",
      "ghidra",
      "--full-output",
      "--json",
    ],
    {
      env: { ...process.env, REA_LOG_LEVEL: "silent" },
      timeout: 240_000,
      maxBuffer: 32 * 1024 ** 2,
    },
  );
  const envelope = JSON.parse(stdout);
  assert.equal(envelope.ok, true);
  const evidence = parseEvidence(envelope.data);
  const dossier = functionDossierSchema.parse(evidence.normalized_result);
  const observation = dossier.decompiler_completeness;
  assert.equal(observation?.status, "warnings");
  assert.ok(observation.warning_count > 0);
  assert.ok(
    observation.dropped_blocks.some(
      (block) => block.start !== null && block.end === null,
    ),
  );
  assert.match(dossier.pseudocode, /Removing unreachable block/u);
  assert.equal(observation.disassembly_available, true);
  assert.ok(
    evidence.limitations.some((text) =>
      text.includes("Removing unreachable block"),
    ),
  );
  assert.equal(evidence.subject?.digest.sha256, digest);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [cli, "mcp"],
    env: {
      ...process.env,
      REA_ANALYSIS_PROVIDER: "ghidra",
      REA_LOG_LEVEL: "silent",
      TMPDIR: root,
    },
    stderr: "inherit",
  });
  const client = new Client({
    name: "rea-warning-provenance-verifier",
    version: "1",
  });
  const invoke = async (name, args = {}) =>
    client.callTool({ name, arguments: args }, { timeout: 240_000 });
  const call = async (name, args = {}) =>
    requireMcpOperationResult(await invoke(name, args), name);
  try {
    await client.connect(transport);
    await call("open_binary", { path: target, provider_id: "ghidra" });
    const before = functionDossierSchema.parse(
      await call("analyze_function", { procedure: cleanProcedure }),
    );
    assert.equal(before.decompiler_completeness.status, "no-warnings-reported");
    const authored = "WARNING: Removing unreachable block (ram,0xdeadbeef)";
    const annotated = await call("annotate_native_function", {
      procedure: cleanProcedure,
      comment: authored,
      inline_comment: authored,
    });
    assert.equal(annotated.annotations.comment, authored);
    assert.equal(annotated.annotations.inline_comment, authored);
    const after = functionDossierSchema.parse(annotated.dossier);
    assert.equal(after.decompiler_completeness.status, "no-warnings-reported");
    assert.deepEqual(after.decompiler_completeness.dropped_blocks, []);
    assert.ok(after.comments.some((comment) => comment.text === authored));
    assert.doesNotMatch(after.pseudocode, /0xdeadbeef/u);
    const warned = functionDossierSchema.parse(
      await call("analyze_function", { procedure }),
    );
    assert.equal(warned.decompiler_completeness.status, "warnings");
    const batchRaw = await invoke("batch_decompile", {
      addresses: [procedure, cleanProcedure],
    });
    const batch = requireMcpEvidenceResult(batchRaw, "batch_decompile");
    assert.ok(
      batch.items[0].limitations.some((text) =>
        text.includes("Removing unreachable block"),
      ),
    );
    assert.ok(
      batch.items[1].limitations.every(
        (text) => !text.includes("Removing unreachable block"),
      ),
    );
    assert.ok(
      JSON.parse(mcpTextValue(batchRaw)).limitations.some(
        (text) =>
          text.startsWith(`${procedure}:`) &&
          text.includes("Removing unreachable block"),
      ),
    );
    for (const name of ["inspect_native_api", "trace_native_values"]) {
      const raw = await invoke(name, { procedure });
      const result = requireMcpEvidenceResult(raw, name);
      const record = JSON.parse(mcpTextValue(raw));
      assert.ok(
        record.limitations.some((text) =>
          text.includes("Removing unreachable block"),
        ),
      );
      assert.ok(
        result.limitations.some((text) =>
          text.includes("Removing unreachable block"),
        ),
      );
      if (name === "inspect_native_api")
        assert.ok(
          result.residual_unknowns.some((text) =>
            text.includes("Removing unreachable block"),
          ),
        );
      else
        assert.ok(
          result.unknowns.some((unknown) =>
            unknown.reason.includes("Removing unreachable block"),
          ),
        );
    }
    await call("close_binary");
  } finally {
    try {
      await client.close();
    } finally {
      await transport.close();
    }
  }
  assert.equal(
    createHash("sha256")
      .update(await readFile(target))
      .digest("hex"),
    digest,
  );
  console.log(
    JSON.stringify(
      {
        status: "passed",
        provider: evidence.provider,
        source_sha256: digest,
        observation,
        source_unchanged: true,
        target_executed: false,
        authored_warning_excluded: true,
        authored_comments_retained: true,
        workflow_warnings: "verified through MCP and Evidence",
        batch_warning_limits: "verified per item and in Evidence",
      },
      null,
      2,
    ),
  );
} finally {
  await rm(root, { recursive: true, force: true });
}
