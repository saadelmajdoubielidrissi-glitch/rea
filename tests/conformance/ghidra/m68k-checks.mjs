import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { M68K_FIXTURE } from "./m68k-fixture.mjs";

const address = (value) => `0x${BigInt(value).toString(16)}`;

/**
 * Read the declared ELF and segment facts straight from the fixture bytes.
 * This independent reader shares no code with the production target resolver.
 */
export function parseM68kFixture(bytes) {
  assert.ok(bytes.length >= 52, "Fixture is shorter than an ELF32 header");
  assert.equal(bytes.toString("hex", 0, 4), "7f454c46", "Missing ELF magic");
  assert.equal(bytes[4], 1, "Fixture must be ELF32");
  assert.equal(bytes[5], 2, "Fixture must be big-endian");
  assert.equal(bytes[6], 1, "Fixture must declare ELF version 1");
  assert.equal(bytes.readUInt16BE(16), 2, "Fixture must be ET_EXEC");
  assert.equal(bytes.readUInt16BE(18), 4, "Fixture must be EM_68K");
  assert.equal(bytes.readUInt32BE(20), 1, "Fixture ELF version changed");
  const entry = bytes.readUInt32BE(24);
  assert.equal(entry, M68K_FIXTURE.entry, "Fixture entry changed");
  const programOffset = bytes.readUInt32BE(28);
  assert.equal(programOffset, 52, "Fixture program header offset changed");
  assert.equal(bytes.readUInt32BE(32), 0, "Fixture must not declare sections");
  const flags = bytes.readUInt32BE(36);
  assert.equal(flags, M68K_FIXTURE.flags, "Fixture e_flags changed");
  assert.equal(bytes.readUInt16BE(40), 52, "Fixture ELF header size changed");
  assert.equal(
    bytes.readUInt16BE(42),
    32,
    "Fixture program header size changed",
  );
  assert.equal(bytes.readUInt16BE(44), 1, "Fixture must declare one segment");
  assert.equal(
    bytes.readUInt16BE(46),
    40,
    "Fixture section header size changed",
  );
  assert.equal(bytes.readUInt16BE(48), 0, "Fixture must not declare sections");
  assert.equal(bytes.readUInt16BE(50), 0, "Fixture must not declare sections");
  const header = programOffset;
  assert.equal(bytes.readUInt32BE(header), 1, "Fixture must map PT_LOAD");
  const fileOffset = bytes.readUInt32BE(header + 4);
  assert.equal(fileOffset, M68K_FIXTURE.file_offset, "Segment offset changed");
  assert.equal(bytes.readUInt32BE(header + 8), entry, "Segment vaddr changed");
  assert.equal(bytes.readUInt32BE(header + 12), entry, "Segment paddr changed");
  assert.equal(
    bytes.readUInt32BE(header + 16),
    M68K_FIXTURE.segment_size,
    "Segment file size changed",
  );
  assert.equal(
    bytes.readUInt32BE(header + 20),
    M68K_FIXTURE.segment_size,
    "Segment memory size changed",
  );
  assert.equal(bytes.readUInt32BE(header + 24), 5, "Segment flags changed");
  assert.equal(
    bytes.readUInt32BE(header + 28),
    fileOffset,
    "Segment align changed",
  );
  assert.ok(
    fileOffset + M68K_FIXTURE.segment_size <= bytes.length,
    "Segment extends beyond the fixture",
  );
  const segment = bytes.subarray(
    fileOffset,
    fileOffset + M68K_FIXTURE.segment_size,
  );
  assert.equal(
    segment.toString("hex", 0, 6),
    M68K_FIXTURE.probe.move.bytes,
    "MOVE.L encoding changed",
  );
  assert.equal(
    segment.toString("hex", 6, 8),
    M68K_FIXTURE.probe.branch.bytes,
    "Short BRA encoding changed",
  );
  assert.equal(segment.toString("hex", 8, 14), "4e714e714e75");
  assert.equal(
    segment.toString("hex", 16, 20),
    M68K_FIXTURE.global.bytes,
    "Global encoding changed",
  );
  assert.equal(
    segment.toString("utf8", 20, 20 + M68K_FIXTURE.marker.text.length + 1),
    `${M68K_FIXTURE.marker.text}\0`,
    "Marker encoding changed",
  );
  return {
    architecture: M68K_FIXTURE.architecture,
    flags,
    entry: address(entry),
    file_offset: fileOffset,
    segment_size: M68K_FIXTURE.segment_size,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

/** Check effective Ghidra observations, not the requested analysis profile. */
export function assertM68kLoadedImage(observations, sha256) {
  assert.equal(observations.language_id, M68K_FIXTURE.language_id);
  assert.equal(observations.compiler_spec_id, M68K_FIXTURE.compiler_spec_id);
  assert.ok(
    observations.source_files.some(
      (file) =>
        file.original_sha256 === sha256 && file.modified_sha256 === sha256,
    ),
    "Ghidra loaded source identity changed",
  );
  const entry = BigInt(M68K_FIXTURE.entry);
  const mapping = observations.mappings.find(
    (value) => BigInt(value.start) <= entry && BigInt(value.end) >= entry,
  );
  assert.ok(mapping, "Ghidra did not load a mapping containing the entry");
  assert.equal(mapping.initialized, true);
  assert.equal(mapping.loaded, true);
  // Mapping end addresses are inclusive; the measured length is authoritative.
  assert.ok(
    mapping.length >= M68K_FIXTURE.segment_size,
    "Loaded mapping is smaller than the declared segment",
  );
}

/** Verify the fixed MOVE.L/short BRA encodings, immediate and branch destination. */
export function assertM68kProbe(move, branch) {
  assert.equal(move.status, "decoded");
  assert.equal(BigInt(move.address), BigInt(M68K_FIXTURE.probe.move.address));
  assert.equal(move.architecture, M68K_FIXTURE.language_id);
  assert.equal(move.length, 6);
  assert.equal(move.bytes, M68K_FIXTURE.probe.move.bytes);
  assert.match(move.mnemonic, /^MOVE(?:\.L)?$/iu);
  const immediate = (move.operands ?? [])
    .flatMap((operand) => operand.components ?? [])
    .find((part) => part.kind === "immediate" && part.value !== null);
  assert.ok(
    immediate !== undefined && BigInt(immediate.value) === 0x12345678n,
    "MOVE.L immediate was not recovered",
  );
  assert.equal(branch.status, "decoded");
  assert.equal(
    BigInt(branch.address),
    BigInt(M68K_FIXTURE.probe.branch.address),
  );
  assert.equal(branch.architecture, M68K_FIXTURE.language_id);
  assert.equal(branch.length, 2);
  assert.equal(branch.bytes, M68K_FIXTURE.probe.branch.bytes);
  assert.match(branch.mnemonic, /^BRA(?:\.(?:B|S))?$/iu);
  assert.equal(branch.flow.kind, "jump");
  assert.equal(branch.flow.conditional, false);
  assert.equal(branch.flow.computed, false);
  assert.deepEqual(
    branch.flow.direct_destinations.map((value) => BigInt(value)),
    [BigInt(M68K_FIXTURE.probe.branch.target)],
  );
}

/** Four bytes must encode the known source-owned global exactly. */
export function assertM68kGlobal(bytes) {
  assert.equal(bytes, M68K_FIXTURE.global.bytes);
}

/** The marker bytes are source-owned and must round-trip without changes. */
export function assertM68kMarker(bytes) {
  assert.equal(
    bytes,
    Buffer.from(`${M68K_FIXTURE.marker.text}\0`).toString("hex"),
  );
}
