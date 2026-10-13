import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

/** Fixed source-owned big-endian ELF32 image; the lane never executes it. */
export const M68K_FIXTURE = Object.freeze({
  file_name: "m68k-fixture.elf",
  architecture: "m68k",
  language_id: "68000:BE:32:default",
  compiler_spec_id: "default",
  flags: 0x01000000,
  entry: 0x10000,
  file_offset: 0x1000,
  segment_size: 0x24,
  probe: Object.freeze({
    move: Object.freeze({ address: 0x10000, bytes: "203c12345678" }),
    branch: Object.freeze({
      address: 0x10006,
      bytes: "6004",
      target: 0x1000c,
    }),
  }),
  global: Object.freeze({ address: 0x10010, bytes: "deadbeef" }),
  marker: Object.freeze({ address: 0x10014, text: "rea_m68k_marker" }),
});

/** Segment payload: MOVE.L immediate, short BRA over two NOPs, RTS, global, marker. */
const segmentBytes = () => {
  const segment = Buffer.alloc(M68K_FIXTURE.segment_size);
  segment.write(M68K_FIXTURE.probe.move.bytes, 0, "hex");
  segment.write(M68K_FIXTURE.probe.branch.bytes, 6, "hex");
  segment.write("4e71", 8, "hex");
  segment.write("4e71", 10, "hex");
  segment.write("4e75", 12, "hex");
  segment.write(M68K_FIXTURE.global.bytes, 16, "hex");
  segment.write(`${M68K_FIXTURE.marker.text}\0`, 20, "ascii");
  return segment;
};

/** Build the declared ELF32 `EM_68K` `EF_M68K_M68000` ET_EXEC image. */
export const m68kFixtureBytes = () => {
  const bytes = Buffer.alloc(
    M68K_FIXTURE.file_offset + M68K_FIXTURE.segment_size,
  );
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 1, 2, 1, 0], 0);
  bytes.writeUInt16BE(2, 16); // ET_EXEC
  bytes.writeUInt16BE(4, 18); // EM_68K
  bytes.writeUInt32BE(1, 20);
  bytes.writeUInt32BE(M68K_FIXTURE.entry, 24);
  bytes.writeUInt32BE(52, 28);
  bytes.writeUInt32BE(0, 32);
  bytes.writeUInt32BE(M68K_FIXTURE.flags, 36);
  bytes.writeUInt16BE(52, 40);
  bytes.writeUInt16BE(32, 42);
  bytes.writeUInt16BE(1, 44);
  bytes.writeUInt16BE(40, 46);
  bytes.writeUInt16BE(0, 48);
  bytes.writeUInt16BE(0, 50);
  const header = 52;
  bytes.writeUInt32BE(1, header); // PT_LOAD
  bytes.writeUInt32BE(M68K_FIXTURE.file_offset, header + 4);
  bytes.writeUInt32BE(M68K_FIXTURE.entry, header + 8);
  bytes.writeUInt32BE(M68K_FIXTURE.entry, header + 12);
  bytes.writeUInt32BE(M68K_FIXTURE.segment_size, header + 16);
  bytes.writeUInt32BE(M68K_FIXTURE.segment_size, header + 20);
  bytes.writeUInt32BE(5, header + 24);
  bytes.writeUInt32BE(M68K_FIXTURE.file_offset, header + 28);
  segmentBytes().copy(bytes, M68K_FIXTURE.file_offset);
  return bytes;
};

/** Write the fixture and retain the exact bytes the lane analyzes. */
export async function buildM68kFixture(directory) {
  const path = join(directory, M68K_FIXTURE.file_name);
  const bytes = m68kFixtureBytes();
  await writeFile(path, bytes);
  const observed = await readFile(path);
  if (!observed.equals(bytes))
    throw new Error("Fixture write changed the source-owned m68k bytes");
  return {
    path,
    bytes,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}
