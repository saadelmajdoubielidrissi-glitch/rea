import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, parse, relative } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseConfig } from "../config/parseConfig.js";
import type {
  BinaryTarget,
  M68kElfMetadata,
} from "../domain/binaryTargetTypes.js";
import { silentLogger } from "../logger.js";
import { HopperProvider } from "../hopper/HopperProvider.js";
import { hopperLoaderArgsForTarget } from "../hopper/HopperAnalysisProfile.js";
import { IdaProvider } from "../ida/IdaProvider.js";
import { GhidraProvider } from "./GhidraProvider.js";
import { ghidraM68kLimitations } from "./GhidraM68kProfile.js";
import {
  ghidraPinnedLanguage,
  ghidraProfileLanguageOverride,
  sameGhidraLanguageOverride,
} from "./GhidraAnalysisProfile.js";
import type { GhidraInstallationHost } from "./GhidraInstallation.js";

// Abbreviated from Ghidra 12.1.x Processors/68000/data/languages/68000.ldefs.
const M68K_LDEFS = `<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language processor="68000"
            endian="big"
            size="32"
            variant="default"
            version="1.1"
            slafile="68040.sla"
            processorspec="68000.pspec"
            id="68000:BE:32:default">
    <description>Motorola 32-bit 68040</description>
    <compiler name="default" spec="68000.cspec" id="default"/>
  </language>
</language_definitions>
`;

// Fake installation inspection tests admission/profile contracts, not Ghidra.
const host: GhidraInstallationHost = {
  platform: "linux",
  architecture: "x64",
  readText: () => "application.version=12.1.4\napplication.java.min=21\n",
  executable: () => true,
  probeJava: () => ({
    version: "21.0.11",
    major: 21,
    home: "/jdk-21",
    bits: 64,
    runtime: "jdk",
  }),
};
let installDir = "";
beforeAll(async () => {
  const root =
    process.platform === "win32" ? join(process.cwd(), "build") : tmpdir();
  await mkdir(root, { recursive: true });
  installDir = await mkdtemp(join(root, "rea-ghidra-m68k-languages-"));
  // The simulated Linux host needs a POSIX absolute path. A current-drive root
  // path also reaches this real fixture on Windows without changing admission.
  if (process.platform === "win32")
    installDir = `/${relative(parse(installDir).root, installDir).replaceAll("\\", "/")}`;
  const languages = join(installDir, "Ghidra/Processors/68000/data/languages");
  await mkdir(languages, { recursive: true });
  await writeFile(join(languages, "68000.ldefs"), M68K_LDEFS);
});
afterAll(async () => {
  await rm(installDir, { recursive: true, force: true });
});
const configOf = (environment: Record<string, string> = {}) => {
  const parsed = parseConfig({
    GHIDRA_INSTALL_DIR: installDir,
    ...environment,
  });
  if (!parsed.ok) throw parsed.error;
  return parsed.value;
};
const target = (change: Partial<M68kElfMetadata> = {}): BinaryTarget => ({
  path: "/fixture.elf",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "m68k",
  availableArchitectures: ["m68k"],
  m68k: {
    elfClass: 32,
    byteOrder: "big",
    type: 2,
    flags: 0x01000000,
    ...change,
  },
});

describe("bounded Ghidra m68k admission", () => {
  it("pins the MC68040-based language instead of the loader header guess", async () => {
    const provider = new GhidraProvider(configOf(), silentLogger, {}, host);
    const family = target();
    expect(provider.inspectTargetSupport(family)).toMatchObject({
      status: "supported",
    });
    // Ghidra's own opinion resolves EM_68K to the ColdFire variant; the lane
    // owns the pin so the committed profile and readback agree.
    expect(ghidraPinnedLanguage(family)).toEqual({
      languageId: "68000:BE:32:default",
      compilerSpecId: "default",
    });
    const resolved = await provider.resolveAnalysisProfile(family);
    if (!resolved.ok || resolved.value.profile === null)
      throw new Error("expected an admitted m68k profile");
    expect(resolved.value.profile?.parameters.m68k_elf).toEqual({
      elf_class: 32,
      byte_order: "big",
      type: 2,
      flags: 0x01000000,
    });
    expect(resolved.value.profile?.parameters.m68k_support_lane).toBe(
      "elf32-exec-m68000-family-v1",
    );
    expect(resolved.value.profile?.parameters.language_selection).toBe(
      "provider-pinned-v1",
    );
    expect(resolved.value.profile?.parameters.language_id).toBe(
      "68000:BE:32:default",
    );
    expect(resolved.value.profile?.parameters.compiler_spec_id).toBe("default");
    expect(
      sameGhidraLanguageOverride(
        ghidraProfileLanguageOverride(resolved.value.profile.parameters),
        ghidraPinnedLanguage(family),
      ),
    ).toBe(true);
    const exercisedHost = {
      providerVersion: "12.1.2",
      platform: "linux",
      architecture: "x64",
    } as const;
    const limitations = ghidraM68kLimitations(family, exercisedHost).join(" ");
    expect(limitations).toContain("MC68040");
    expect(limitations).toContain("calling convention");
    expect(limitations).not.toContain("unverified here");
    expect(
      ghidraM68kLimitations(family, {
        ...exercisedHost,
        providerVersion: "12.1.4",
      }).join(" "),
    ).toContain("unverified here");
    expect(
      ghidraM68kLimitations(family, {
        ...exercisedHost,
        platform: "darwin",
      }).join(" "),
    ).toContain("unverified here");
    expect(
      ghidraM68kLimitations(family, {
        ...exercisedHost,
        architecture: "arm64",
      }).join(" "),
    ).toContain("unverified here");
    const windows = new GhidraProvider(
      configOf(),
      silentLogger,
      {},
      {
        ...host,
        platform: "win32",
      },
    );
    expect(windows.inspectTargetSupport(family).status).toBe("unsupported");
  });

  it.each([
    [{ elfClass: 64 }, "ELF32"],
    [{ byteOrder: "little" }, "big-endian"],
    [{ type: 1 }, "ET_EXEC"],
    [{ type: 3 }, "ET_EXEC"],
    [{ type: 4 }, "ET_EXEC"],
    [{ flags: 0x00810000 }, "EF_M68K_M68000"],
    [{ flags: 0x02000000 }, "EF_M68K_M68000"],
    [{ flags: 0x00008000 }, "EF_M68K_M68000"],
    [{ flags: 0 }, "EF_M68K_M68000"],
    [{ flags: 0x01020000 }, "unverified architecture bits"],
    [{ flags: 0x01000001 }, "ColdFire ISA"],
  ] satisfies [Partial<M68kElfMetadata>, string][])(
    "refuses an unverified m68k interpretation %j",
    async (change, reason) => {
      const provider = new GhidraProvider(configOf(), silentLogger, {}, host);
      const value = target(change);
      expect(provider.inspectTargetSupport(value)).toMatchObject({
        status: "unsupported",
        code: "architecture_unsupported",
        reason: expect.stringContaining(reason),
      });
      const resolved = await provider.resolveAnalysisProfile(value);
      expect(resolved.ok).toBe(false);
      expect(ghidraPinnedLanguage(value)).toBeUndefined();
    },
  );
});

describe("m68k pinned overrides and declined provider lanes", () => {
  it("refuses a caller-selected processor outside the pinned m68k lane", async () => {
    const provider = new GhidraProvider(
      configOf({ REA_GHIDRA_LANGUAGE_ID: "68000:BE:32:MC68020" }),
      silentLogger,
      {},
      host,
    );
    const resolved = await provider.resolveAnalysisProfile(target());
    expect(resolved.ok).toBe(false);
    if (resolved.ok) throw new Error("expected a refusal");
    expect(resolved.error.message).toContain("pinned big-endian M68000-family");
  });

  it("preserves the pinned compiler when a matching override omits it", async () => {
    const provider = new GhidraProvider(
      configOf({ REA_GHIDRA_LANGUAGE_ID: "68000:BE:32:default" }),
      silentLogger,
      {},
      host,
    );
    const resolved = await provider.resolveAnalysisProfile(target());
    if (!resolved.ok || resolved.value.profile === null)
      throw new Error("expected an admitted m68k profile");
    expect(resolved.value.profile.parameters.language_selection).toBe(
      "configured-v1",
    );
    expect(resolved.value.profile.parameters.language_id).toBe(
      "68000:BE:32:default",
    );
    expect(resolved.value.profile.parameters.compiler_spec_id).toBe("default");
    expect(
      sameGhidraLanguageOverride(
        ghidraProfileLanguageOverride(resolved.value.profile.parameters),
        ghidraPinnedLanguage(target()),
      ),
    ).toBe(true);
  });

  it("keeps m68k out of unverified Hopper and IDA adapter lanes", () => {
    const hopper = new HopperProvider(configOf(), silentLogger, {}, "linux");
    expect(hopper.inspectTargetSupport(target())).toMatchObject({
      status: "unsupported",
      reason: expect.stringContaining("m68k"),
    });
    expect(hopperLoaderArgsForTarget(target()).ok).toBe(false);
    const ida = new IdaProvider(configOf(), {});
    expect(ida.inspectTargetSupport(target())).toMatchObject({
      status: "unsupported",
      reason: expect.stringContaining("m68k"),
    });
  });
});
