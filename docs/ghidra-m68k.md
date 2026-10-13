# Motorola 68k ELF analysis through Ghidra

This lane extends native ELF analysis with the Motorola 68000 family. It does
not execute m68k code and does not rehost firmware or retro platforms.

## Admission boundary

ELF `EM_68K` is retained as the provider-neutral `m68k` family. The target also
retains class, byte order, `e_type`, and raw `e_flags`. Recognition does not
mean every provider or m68k variant is supported: Hopper and IDA adapters do
not gain an m68k lane, and Windows Ghidra P0 remains PE x86/x86-64 only.

The first Ghidra lane admits big-endian ELF32 `ET_EXEC` with an
`EF_M68K_M68000` family declaration and no other architecture bits. The flag
layout follows binutils `include/elf/m68k.h`: the top bits name CPU32, the
M68000 family, ColdFire V4E, or FIDO, and the low byte names a ColdFire ISA
variant. ELF64, little-endian images, relocatable objects, shared images and
PIE, CPU32, ColdFire, FIDO, unspecified `e_flags`, and unknown architecture
bits are refused with the specific unsupported constraint instead of being
mapped to a guessed processor profile.

Ghidra's own ELF loader opinion resolves `EM_68K` to the ColdFire variant,
whose instruction set is not an M68000 superset. REA therefore pins the
admitted import language to `68000:BE:32:default`, whose processor definition
models the MC68040, and the session handshake refuses any other observed
language or compiler specification. ELF `e_flags` declares only the M68000
family, not an exact processor generation, so the MC68040 definition is an
analysis choice: instructions removed in the 68040 (for example `CALLM` and
`RTM` from the 68020/030) and instructions added after it are not verified by
this lane, and decoding such code can lose instruction boundaries. MC68060-only
semantics are likewise not established and remain an explicit limitation.
The pinned `default` compiler specification models the MC68040 C calling
convention; ELF `e_flags` does not declare one, so parameter and return storage
in decompiler output is an analysis convention rather than an observed ABI.
The pinned selection is committed as `language_selection:
provider-pinned-v1`; a caller-selected `REA_GHIDRA_LANGUAGE_ID` that differs
from the pin is refused with the requested configuration left unchanged, and
the header gate is never relaxed.

The m68k header and `e_flags` facts are committed in the analysis profile so
interpretation changes invalidate profile-bound snapshots. The support-lane
identity is versioned independently of file identity. Evidence, lifecycle
outputs and saved snapshots preserve the `m68k` family.

## Use

With a caller-installed Ghidra and compatible JDK on a supported Linux/macOS
host:

```bash
rea analyze /absolute/path/to/m68k.elf --provider ghidra --json
rea instructions /absolute/path/to/m68k.elf 0x10000 --provider ghidra --json
```

MCP uses the existing tools, including `open_binary` with an absolute path and
`provider_id: "ghidra"`. No m68k-specific tool catalog or emulator is
introduced.

## Verification

The source-owned fixture is `tests/conformance/ghidra/m68k-fixture.mjs`: a
hand-built ELF32 `EM_68K` ET_EXEC image with fixed MOVE.L immediate, short branch,
RTS, global and marker bytes. It requires no compiler and never executes the
target. `tests/conformance/ghidra/m68k-checks.mjs` independently parses the
fixture bytes and checks Ghidra observations of the effective language,
mapping, instruction encodings, immediate, branch destination and data bytes;
`m68k-checks.test.ts` exercises those checks and runs production target
resolution over the built fixture.

The optional real-Ghidra lane mirrors the MIPS lane:

```bash
GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra npm run verify:ghidra:m68k
```

It opens the fixture through real stdio MCP, checks the observed language and
loaded bytes, inspects the fixed instructions and data, retains Evidence and a
snapshot, repeats the analysis through a real CLI command, and verifies final
process cleanup.

The lane has been executed against Ghidra 12.1.2 and JDK 21.0.12.1 with the
source-owned fixture. It verified the pinned effective language and compiler
specification, loaded source identity and mapping, the fixed MOVE.L/short BRA
bytes, immediate and branch destination, global and marker bytes,
Evidence/snapshot identity, CLI/MCP agreement, and final process cleanup
without retained descendants. Provider admission still accepts the Ghidra
12.1.x line; every other build and host-native lane records a lane-specific
limitation until its own run is reported (the executed run is Linux x64).

The first real run also established why the language must be pinned: Ghidra's
own ELF import selected `68000:BE:32:Coldfire` for this fixture, and the
handshake refused that unadmitted interpretation.

Instruction decoding and reader agreement do not establish runtime semantics
or complete floating-point behavior.

Classic m68k containers (Amiga Hunk, Atari TOS, classic Mac PEF, headerless
ROMs) are not covered by this lane.
