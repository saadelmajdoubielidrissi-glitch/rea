import type { GhidraLanguageOverride } from "../config/ghidraLanguageOverride.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";

/**
 * Motorola m68k `e_flags` declarations from binutils `include/elf/m68k.h`.
 * The top bits name the family; the low byte names a ColdFire ISA variant.
 */
const EF_M68K_CPU32 = 0x00810000;
const EF_M68K_M68000 = 0x01000000;
const EF_M68K_CFV4E = 0x00008000;
const EF_M68K_FIDO = 0x02000000;
const EF_M68K_ARCH_MASK =
  EF_M68K_M68000 | EF_M68K_CPU32 | EF_M68K_CFV4E | EF_M68K_FIDO;
const EF_M68K_CF_MASK = 0xff;

/**
 * Ghidra's `68000.opinion` names only the processor for ELF `EM_68K`, so its
 * constraint resolves to the ColdFire variant, which is not an M68000-family
 * superset. The lane pins the MC68040-based default language instead.
 */
const GHIDRA_M68K_LANGUAGE_ID = "68000:BE:32:default";
const GHIDRA_M68K_COMPILER_SPEC_ID = "default";

/** Keep family recognition separate from the deliberately bounded Ghidra lane. */
export const ghidraM68kUnsupportedReason = (
  target: BinaryTarget,
): string | null => {
  if (target.kind !== "executable" || target.architecture !== "m68k")
    return null;
  const metadata = target.m68k;
  if (target.format !== "elf" || metadata === undefined)
    return "m68k analysis requires ELF header metadata; a family name alone does not select an instruction set.";
  if (metadata.elfClass !== 32)
    return "This Ghidra m68k lane supports ELF32 only; m68k ELF64 has no verified load profile.";
  if (metadata.byteOrder !== "big")
    return "This Ghidra m68k lane requires big-endian ELF; little-endian ColdFire images need a separately verified processor profile.";
  if (metadata.type !== 2)
    return "This Ghidra m68k lane supports ET_EXEC only; relocatable objects, shared images and PIE need separate load verification.";
  const flags = metadata.flags;
  if ((flags & EF_M68K_ARCH_MASK) !== EF_M68K_M68000)
    return "This Ghidra m68k lane requires an EF_M68K_M68000 family declaration; CPU32, ColdFire, FIDO and unspecified variants need separately verified processor profiles.";
  if ((flags & EF_M68K_CF_MASK) !== 0)
    return "m68k e_flags declare a ColdFire ISA variant outside this M68000-family lane.";
  if ((flags & ~(EF_M68K_ARCH_MASK | EF_M68K_CF_MASK)) !== 0)
    return "m68k e_flags contain unverified architecture bits outside the declared M68000 family.";
  return null;
};

/** Pin the MC68040-based language only for declarations admitted by the lane. */
export const ghidraM68kLanguageOverride = (
  target: BinaryTarget,
): GhidraLanguageOverride | undefined =>
  target.kind === "executable" &&
  target.architecture === "m68k" &&
  ghidraM68kUnsupportedReason(target) === null
    ? {
        languageId: GHIDRA_M68K_LANGUAGE_ID,
        compilerSpecId: GHIDRA_M68K_COMPILER_SPEC_ID,
      }
    : undefined;

/** Commit source ELF interpretation without confusing target ISA with host CPU. */
export const ghidraM68kProfileParameters = (
  target: BinaryTarget,
): Readonly<Record<string, JsonValue>> => {
  if (
    target.kind !== "executable" ||
    target.architecture !== "m68k" ||
    target.m68k === undefined
  )
    return {};
  return {
    m68k_elf: {
      elf_class: target.m68k.elfClass,
      byte_order: target.m68k.byteOrder,
      type: target.m68k.type,
      flags: target.m68k.flags,
    },
    m68k_support_lane: "elf32-exec-m68000-family-v1",
  };
};

/**
 * Ghidra build and host the m68k lane was exercised against. Other admitted
 * builds and host-native lanes keep a lane-specific caveat even when the
 * generic bridge limitation is absent for the verified release line.
 */
const GHIDRA_M68K_VERIFIED_BUILD = "12.1.2";
const GHIDRA_M68K_VERIFIED_HOST = {
  platform: "linux",
  architecture: "x64",
} as const;

/** The pinned language is an analysis convention, not proof of the producer. */
export const ghidraM68kLimitations = (
  target: BinaryTarget,
  host: {
    readonly providerVersion: string;
    readonly platform: NodeJS.Platform;
    readonly architecture: NodeJS.Architecture;
  },
): readonly string[] => {
  if (target.kind !== "executable" || target.architecture !== "m68k") return [];
  const exercised =
    host.providerVersion === GHIDRA_M68K_VERIFIED_BUILD &&
    host.platform === GHIDRA_M68K_VERIFIED_HOST.platform &&
    host.architecture === GHIDRA_M68K_VERIFIED_HOST.architecture;
  return [
    "m68k ELF: REA pins Ghidra's `68000:BE:32:default` language instead of accepting the loader's header-based choice, which resolves `EM_68K` to the ColdFire variant on Ghidra 12.1.x.",
    "ELF `e_flags` declares only the M68000 family, not an exact processor generation, so the pinned MC68040 model is an analysis choice rather than a declared ISA. Instructions removed in the 68040 (for example `CALLM` and `RTM` from the 68020/030) and instructions added after it are not verified by this lane, and decoding such code can lose instruction boundaries.",
    "The pinned `default` compiler specification models the MC68040 C calling convention. ELF `e_flags` does not declare a calling convention, so parameter and return storage in decompiler output is an analysis convention, not an observed ABI.",
    "Admission reads ELF class, byte order, `e_type` and `e_flags` only; program headers, sections, linkage and runtime behavior are not inspected by this lane.",
    ...(exercised
      ? []
      : [
          `The m68k lane's real-provider run covers Ghidra ${GHIDRA_M68K_VERIFIED_BUILD} on ${GHIDRA_M68K_VERIFIED_HOST.platform}/${GHIDRA_M68K_VERIFIED_HOST.architecture}; this session uses Ghidra ${host.providerVersion} on ${host.platform}/${host.architecture}, so m68k decoding and load behavior remain unverified here.`,
        ]),
  ];
};
