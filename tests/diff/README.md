# Differential test vectors from Zydis and Capstone

This directory converts test data from the [Zydis](https://github.com/zyantific/zydis)
and [Capstone](https://github.com/capstone-engine/capstone) projects into
differential vectors for lendiza, and runs a comparison against the decoder.
It mirrors xendiza's `test/diff/` (which carries mnemonic/operand
expectations), reduced to the one axis a length-disassembler exposes.

## Why external vectors

The hand-written suites assert lengths against `lzmodel::modrm_span()` — an
independent statement of the ModRM/SIB/displacement rules — plus recorded
behaviour baselines. These vectors assert lendiza against two independent,
widely validated decoders on real-world and fuzzer-derived byte streams.
Length is the natural common axis: both upstreams publish an exact
per-instruction size (ZydisInfo `LENGTH`, capstone `size`), and for a length
decoder that expectation is complete ground truth, not a summary.
Registered with ctest as `lendiza_diff` (label `diff`): the harness builds as
the `lendiza_diff_harness` target and the test runs `compare.py --gen`,
failing on any suspect mismatch and reporting "Skipped" (exit 77) when PyYAML
or the third_party data is unavailable.

## Layout

- `gen_vectors.py` — parses `third_party/` YAML / ZydisInfo dumps into
  `out/streams.jsonl` (byte stream + expected per-instruction lengths).
- `harness.cpp` — decodes each stream linearly through the `extern "C"` ABI
  (one decode per expected instruction, like a real linear-sweep consumer)
  and prints per-step results. Builds with MSVC (`build.bat`) or
  MinGW/GCC (`build.sh`); no CMake/GTest needed.
- `compare.py` — runs the harness, diffs lengths, buckets divergences into
  documented by-design policies vs. suspect mismatches, writes
  `out/report.json`. Exit code is 0 only with zero suspect mismatches.

All generated artifacts live in `out/` (gitignored).

Because the decoder is header-only, the `lendiza_diff_harness` target
re-links on every core change - so its POST_BUILD step re-runs this check
automatically and fails the build on any suspect mismatch (missing
PyYAML/data downgrades to a STATUS line; see `build_check.cmake`). Building
the library is itself the gate; the ctest entry below is the explicit rerun.

## Usage

From the repo root, either through ctest (harness built as the
`lendiza_diff_harness` CMake target; fails on any suspect mismatch, reports
"Skipped" when PyYAML or the third_party data is unavailable):

```bash
cmake -S . -B build -G Ninja && cmake --build build
ctest --test-dir build -R lendiza_diff --output-on-failure
```

or standalone (harness built by the script, not CMake):

```bash
python tests/diff/gen_vectors.py     # rebuild out/streams.jsonl from third_party/
cmd //c tests/diff/build.bat         # build out/harness.exe (MSVC dev environment)
sh tests/diff/build.sh               # ... or with MinGW/GCC
python tests/diff/compare.py         # run and report
```

`compare.py --gen` fuses the first and last step; that is exactly what the
ctest entry invokes.

## Ground-truth derivation (`how` field)

- `size` — capstone cases whose every expected instruction carries an
  explicit `size` (`x86-bitscan-prefixes.yaml`, `x86_jcc_mode.yaml`).
- `length` — zydis regression cases: `LENGTH` of the first instruction from
  the `.out` ZydisInfo dump (`default_*.in/.out`, fuzzer-derived edge cases).
- `bytes` — single-instruction capstone cases with no explicit size
  (`x86.yaml`, the `tests/MC/X86/*.s.yaml` ports): the input byte count *is*
  the instruction length, which is how those tests are constructed.
  Multi-instruction cases without per-instruction sizes are skipped (37), as
  are 16-bit-mode cases (22) — lendiza targets 32/64-bit only.

## Current results (2026-10-28)

- 356 streams / 384 sized steps from 13 capstone files + 63 zydis cases
  (39 exact duplicates across files deduped).
- **Agreement: 343/384 (89.3%); suspect mismatches: 0.**
- The 41 by-design divergences, all traced to a documented policy or a
  data artifact:

| bucket | n | explanation |
|---|---:|---|
| `row-0f-0d` | 28 | `0F 0D/0E/0F` (PREFETCH/EMMS/3DNow!) are not decoded; asserted undefined in `TwoByteOpcodeTest` (scope gap, same policy as xendiza) |
| `vex-evex` | 5 | EVEX (`0x62`) encodings are not decoded in long mode and return `0xE1` (README "Prefix semantics"; unit-tested) |
| `branch-66-amd` | 3 | lendiza shrinks `rel32→rel16` under `0x66` in 64-bit (AMD-style, pinned by `Prefix66Test.CALL_0xE8_relz`); zydis default and these `x86_jcc_mode.yaml` vectors ignore the prefix (Intel SDM) |
| `rex2` | 2 | AMD REX2/APX prefix (`0xD5`) not decoded; two zydis regression cases use it (`.out` shows `[ENC: REX2]`) |
| `ia32-vex-lds` | 1 | in IA-32, `C5` decodes as legacy `LDS` by policy (README: "In IA-32 those bytes are ordinary opcodes"); capstone reads VEX when the legacy form would be `#UD` (mod=11) |
| `tsx-xbegin` | 1 | `C7 /7` mod=11 (`XBEGIN`, TSX) not modeled; zydis decodes it even without the mandatory `F3` |
| `derived-bytes` | 1 | expectation is the total byte count of a single-instruction case whose real encoding is shorter — `x86-mandatory-prefixes.yaml#13` (`F3 3E 66 67 0F A4 84 17 ...`): 16-bit addressing (`0x67` in IA-32) makes mod=10 a disp16, so lendiza's 10 is correct and the buffer carries a trailing byte |

## License note

`third_party/zydis/*` is MIT (see `third_party/zydis/LICENSE`).
`third_party/capstone/*` is BSD-3-Clause; the MC-derived files trace to LLVM
test data (see `third_party/capstone/LICENSE_LLVM.TXT`). Both are compatible
with lendiza's Apache-2.0; keep the license files alongside any data you keep.
