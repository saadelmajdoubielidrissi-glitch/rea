import { describe, expect, it } from "vitest";
import { parseExecutableHeader } from "./binaryTarget.js";

const header = (
  little: boolean,
  bits: 32 | 64 = 32,
  flags = 0x01000000,
): Buffer => {
  const bytes = Buffer.alloc(bits === 32 ? 52 : 64);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, bits === 32 ? 1 : 2, little ? 1 : 2, 1]);
  if (little) {
    bytes.writeUInt16LE(2, 16);
    bytes.writeUInt16LE(4, 18);
    bytes.writeUInt32LE(1, 20);
    bytes.writeUInt32LE(flags, bits === 32 ? 36 : 48);
    bytes.writeUInt16LE(bits === 32 ? 52 : 64, bits === 32 ? 40 : 52);
  } else {
    bytes.writeUInt16BE(2, 16);
    bytes.writeUInt16BE(4, 18);
    bytes.writeUInt32BE(1, 20);
    bytes.writeUInt32BE(flags, bits === 32 ? 36 : 48);
    bytes.writeUInt16BE(bits === 32 ? 52 : 64, bits === 32 ? 40 : 52);
  }
  return bytes;
};

describe("m68k ELF header boundaries", () => {
  it("retains the M68000 family declaration for big-endian ELF32", () => {
    const parsed = parseExecutableHeader(header(false), "x64");
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.value).toEqual({
      format: "elf",
      architecture: "m68k",
      availableArchitectures: ["m68k"],
      m68k: {
        elfClass: 32,
        byteOrder: "big",
        type: 2,
        flags: 0x01000000,
      },
    });
  });

  it("retains little-endian source values without claiming a provider lane", () => {
    const parsed = parseExecutableHeader(header(true, 32, 0x00810000), "x64");
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.value).toMatchObject({
      architecture: "m68k",
      m68k: {
        elfClass: 32,
        byteOrder: "little",
        type: 2,
        flags: 0x00810000,
      },
    });
  });

  it("reads ELF64 m68k flags at their own offset", () => {
    const bytes = header(false, 64);
    bytes.writeUInt32BE(0xfeedface, 36);
    bytes.writeUInt32BE(0x02000000, 48);
    const parsed = parseExecutableHeader(bytes, "x64");
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.value).toMatchObject({
      architecture: "m68k",
      m68k: { elfClass: 64, byteOrder: "big", type: 2, flags: 0x02000000 },
    });
  });

  it("rejects a truncated header before reading flags", () => {
    const parsed = parseExecutableHeader(header(false).subarray(0, 51), "x64");
    expect(parsed).toEqual({
      ok: false,
      error:
        "truncated ELF header: an ELF32 header needs 52 bytes; the file has 51",
    });
  });
});
