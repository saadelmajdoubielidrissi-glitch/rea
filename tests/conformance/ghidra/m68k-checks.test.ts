import { describe, expect, it } from "vitest";

import { parseBinaryTarget } from "../../../src/application/BinaryTargetResolver.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  assertM68kGlobal,
  assertM68kLoadedImage,
  assertM68kMarker,
  assertM68kProbe,
  parseM68kFixture,
} from "./m68k-checks.mjs";
import { buildM68kFixture, m68kFixtureBytes } from "./m68k-fixture.mjs";

const mutate = (damage: (bytes: Buffer) => unknown): Buffer => {
  const bytes = m68kFixtureBytes();
  const changed = damage(bytes);
  return Buffer.isBuffer(changed) ? changed : bytes;
};

const sha256 = "a".repeat(64);
const image = {
  language_id: "68000:BE:32:default",
  compiler_spec_id: "default",
  source_files: [{ original_sha256: sha256, modified_sha256: sha256 }],
  mappings: [
    {
      start: "0x10000",
      end: "0x10023",
      length: 0x24,
      initialized: true,
      loaded: true,
    },
  ],
};
const move = {
  address: "0x10000",
  status: "decoded",
  architecture: "68000:BE:32:default",
  length: 6,
  bytes: "203c12345678",
  mnemonic: "move.l",
  operands: [
    { index: 1, components: [{ kind: "immediate", value: "0x12345678" }] },
  ],
};
const branch = {
  address: "0x10006",
  status: "decoded",
  architecture: "68000:BE:32:default",
  length: 2,
  bytes: "6004",
  mnemonic: "bra.b",
  flow: {
    kind: "jump",
    conditional: false,
    computed: false,
    direct_destinations: ["0x1000c"],
  },
};

describe("m68k real-verifier independent expectations", () => {
  it("reads the declared fixture header and segment without REA parsing", () => {
    const facts = parseM68kFixture(m68kFixtureBytes());
    expect(facts).toMatchObject({
      architecture: "m68k",
      flags: 0x01000000,
      entry: "0x10000",
      file_offset: 0x1000,
      segment_size: 0x24,
    });
  });

  it.each([
    ["wrong machine", (bytes: Buffer) => bytes.writeUInt16BE(8, 18)],
    [
      "wrong family flags",
      (bytes: Buffer) => bytes.writeUInt32BE(0x00810000, 36),
    ],
    ["wrong entry", (bytes: Buffer) => bytes.writeUInt32BE(0x10004, 24)],
    ["wrong segment size", (bytes: Buffer) => bytes.writeUInt32BE(0x20, 68)],
    ["corrupt MOVE.L", (bytes: Buffer) => bytes.writeUInt8(0, 0x1000)],
    [
      "corrupt branch displacement",
      (bytes: Buffer) => bytes.writeUInt8(0, 0x1007),
    ],
    ["corrupt global", (bytes: Buffer) => bytes.writeUInt8(0, 0x1010)],
    ["corrupt marker", (bytes: Buffer) => bytes.writeUInt8(0, 0x1014)],
    ["truncated image", (bytes: Buffer) => bytes.subarray(0, 40)],
  ])(
    "rejects %s instead of returning a guessed fixture interpretation",
    (_name, damage) => {
      expect(() => parseM68kFixture(mutate(damage))).toThrow();
    },
  );

  it("admits the source-owned fixture through production target resolution", async () => {
    const directory = await createTestTempDirectory("rea-m68k-fixture-");
    const fixture = await buildM68kFixture(directory);
    const resolved = await parseBinaryTarget(fixture.path);
    if (!resolved.ok) throw resolved.error;
    expect(resolved.value).toMatchObject({
      kind: "executable",
      format: "elf",
      architecture: "m68k",
      availableArchitectures: ["m68k"],
      sha256: fixture.sha256,
      m68k: {
        elfClass: 32,
        byteOrder: "big",
        type: 2,
        flags: 0x01000000,
      },
    });
  });
});

describe("m68k real-verifier observation checks", () => {
  it("checks the effective loaded image, not requested profile metadata", () => {
    assertM68kLoadedImage(image, sha256);
    expect(() =>
      assertM68kLoadedImage(
        { ...image, language_id: "68000:LE:32:default" },
        sha256,
      ),
    ).toThrow();
    expect(() =>
      assertM68kLoadedImage({ ...image, compiler_spec_id: "other" }, sha256),
    ).toThrow();
    expect(() =>
      assertM68kLoadedImage(
        {
          ...image,
          source_files: [
            { original_sha256: sha256, modified_sha256: "b".repeat(64) },
          ],
        },
        sha256,
      ),
    ).toThrow();
    expect(() =>
      assertM68kLoadedImage(
        {
          ...image,
          mappings: [
            {
              start: "0x20000",
              end: "0x20023",
              length: 0x24,
              initialized: true,
              loaded: true,
            },
          ],
        },
        sha256,
      ),
    ).toThrow();
    expect(() =>
      assertM68kLoadedImage(
        {
          ...image,
          mappings: [
            {
              start: "0x10000",
              end: "0x10023",
              length: 0x24,
              initialized: false,
              loaded: true,
            },
          ],
        },
        sha256,
      ),
    ).toThrow();
    expect(() =>
      assertM68kLoadedImage(
        {
          ...image,
          mappings: [{ ...image.mappings[0], length: 0x20 }],
        },
        sha256,
      ),
    ).toThrow();
  });

  it("checks exact probe bytes, immediate and branch destination", () => {
    assertM68kProbe(move, branch);
  });

  it("rejects plausible nonempty but incorrect instruction observations", () => {
    expect(() =>
      assertM68kProbe({ ...move, bytes: "203c12345679" }, branch),
    ).toThrow();
    expect(() => assertM68kProbe({ ...move, length: 4 }, branch)).toThrow();
    expect(() =>
      assertM68kProbe({ ...move, mnemonic: "moveq" }, branch),
    ).toThrow();
    expect(() =>
      assertM68kProbe(
        {
          ...move,
          operands: [
            {
              index: 1,
              components: [{ kind: "immediate", value: "0x12345679" }],
            },
          ],
        },
        branch,
      ),
    ).toThrow();
    expect(() => assertM68kProbe(move, { ...branch, bytes: "6604" })).toThrow();
    expect(() =>
      assertM68kProbe(move, { ...branch, mnemonic: "bne.s" }),
    ).toThrow();
    expect(() =>
      assertM68kProbe(move, {
        ...branch,
        flow: { ...branch.flow, conditional: true },
      }),
    ).toThrow();
    expect(() =>
      assertM68kProbe(move, {
        ...branch,
        flow: { ...branch.flow, direct_destinations: ["0x10010"] },
      }),
    ).toThrow();
  });

  it("checks the source-owned global and marker bytes exactly", () => {
    assertM68kGlobal("deadbeef");
    assertM68kMarker(Buffer.from("rea_m68k_marker\0").toString("hex"));
    expect(() => assertM68kGlobal("deadbeee")).toThrow();
    expect(() => assertM68kGlobal("deadbe")).toThrow();
    expect(() => assertM68kMarker("00")).toThrow();
  });
});
