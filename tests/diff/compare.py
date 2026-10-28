#!/usr/bin/env python3
"""Run the lendiza diff harness and compare against expected lengths.

Usage (from the repository root):
    python tests/diff/compare.py [--gen] [--harness PATH]

With --gen the vectors are regenerated first; the ctest entry `lendiza_diff`
calls exactly that. Writes tests/diff/out/report.json and prints
match/mismatch statistics. Mismatches are bucketed into *by-design*
divergences (documented lendiza policies that upstream vectors legitimately
disagree with) and *suspect* mismatches (worth a human look). Exit code is 0
only when there are no suspect mismatches; 77 reports a skipped run to ctest
(missing third_party data or PyYAML).
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # repo root (tests/diff -> tests -> root)
OUT = os.path.join(HERE, "out")

# ctest SKIP_RETURN_CODE: reported as "Skipped" instead of failed.
SKIP = 77

LEGACY_PREFIXES = {0x66, 0x67, 0xF0, 0xF2, 0xF3,
                   0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65}


def opcode_at(buf, mode):
    """Skip prefixes/REX and return (has66, opc1, opc2-or-None)."""
    i, has66 = 0, False
    while i < len(buf):
        b = buf[i]
        if b in LEGACY_PREFIXES:
            has66 = has66 or b == 0x66
            i += 1
            continue
        if mode == 64 and 0x40 <= b <= 0x4F:
            i += 1
            continue
        break
    if i >= len(buf):
        return has66, None, None
    if buf[i] == 0x0F and i + 1 < len(buf):
        return has66, 0x0F, buf[i + 1]
    return has66, buf[i], None


def skip_to_modrm(buf, mode):
    i = 0
    while i < len(buf):
        b = buf[i]
        if b in LEGACY_PREFIXES or (mode == 64 and 0x40 <= b <= 0x4F):
            i += 1
        else:
            break
    return i  # index of the opcode byte


def classify(stream, step, expected, actual, buf):
    """Return (bucket, reason). bucket in {"by-design", "suspect"}."""
    mode = stream["mode"]
    if actual == "E1":
        if expected > 15:
            return "by-design", "len-cap-15: encoding longer than 15 bytes"
        if mode == 64 and buf and buf[0] in (0xC4, 0xC5, 0x62):
            return "by-design", "vex-evex: not decoded in long mode"
        if mode == 64 and buf and buf[0] == 0xD5:
            return ("by-design",
                    "rex2: AMD REX2/APX prefix not decoded (scope gap)")
        _, o1, o2 = opcode_at(buf, mode)
        if o1 == 0x0F and o2 in (0x0D, 0x0E, 0x0F):
            return ("by-design",
                    "row-0f-0d: 0F 0D/0E/0F (PREFETCH/EMMS/3DNow!) not "
                    "decoded, asserted undefined in TwoByteOpcodeTest")
        if o1 == 0xC7:
            # mod=11 reg=/7 is XBEGIN (TSX), not modeled (scope gap);
            # zydis decodes it even without the mandatory F3.
            i = skip_to_modrm(buf, mode)
            if i + 1 < len(buf) and buf[i + 1] >> 6 == 3 \
                    and (buf[i + 1] >> 3) & 7 == 7:
                return "by-design", "tsx-xbegin: C7 /7 mod=11 not decoded"
        if o1 == 0x8D:
            # mod=11 names a register where LEA requires memory -> 0xE1 by design.
            i = skip_to_modrm(buf, mode)
            if i + 1 < len(buf) and buf[i + 1] >> 6 == 3:
                return "by-design", "reg-operand-invalid: LEA mod=11"
        return "suspect", "undefined-instruction mismatch"
    if actual == "E0":
        return "suspect", "insufficient-buffer on a complete vector"
    if actual == "E2":
        return "suspect", "internal error"
    # numeric length mismatch
    if mode == 64:
        has66, o1, o2 = opcode_at(buf, mode)
        near_branch = (o1 in (0xE8, 0xE9)) or (o1 == 0x0F and o2 is not None
                                               and 0x80 <= o2 <= 0x8F)
        if has66 and near_branch:
            return ("by-design",
                    "branch-66-amd: lendiza shrinks rel32->rel16 under 0x66 "
                    "in 64-bit (pinned by Prefix66Test); zydis default and "
                    "these capstone vectors ignore the prefix (Intel SDM)")
    if mode == 32 and buf and buf[0] in (0xC4, 0xC5):
        return ("by-design",
                "ia32-vex-lds: in IA-32 lendiza decodes C4/C5 as legacy "
                "LES/LDS by policy (README); capstone/zydis read VEX when "
                "the legacy form would be #UD (mod=11)")
    if stream.get("how") == "bytes" and step == len(stream["sizes"]) - 1 \
            and actual < expected:
        return ("by-design",
                "derived-bytes: expectation is the total byte count of a "
                "single-instruction case; the real encoding is shorter and "
                "the buffer carries trailing bytes (manually verified for "
                "the capstone vectors in this bucket)")
    return "suspect", f"length mismatch (expected {expected}, got {actual})"


def regenerate():
    """Run gen_vectors.py. Return None on success, or a skip reason."""
    tp = os.path.join(ROOT, "third_party")
    if not (os.path.isdir(os.path.join(tp, "zydis"))
            and os.path.isdir(os.path.join(tp, "capstone"))):
        return "third_party/ test data (zydis, capstone) not present"
    gen = subprocess.run([sys.executable, os.path.join(HERE, "gen_vectors.py")],
                         capture_output=True, text=True, cwd=HERE)
    if gen.returncode != 0:
        if "No module named 'yaml'" in gen.stderr:
            return "PyYAML not installed for " + sys.executable
        sys.exit(f"gen_vectors.py failed:\n{gen.stderr.strip()}")
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gen", action="store_true",
                    help="regenerate out/streams.jsonl before comparing")
    ap.add_argument("--harness", help="path to the harness binary "
                    "(default: out/harness.exe next to this script)")
    args = ap.parse_args()

    if args.gen:
        skip = regenerate()
        if skip:
            print(f"SKIP: {skip}")
            return SKIP

    harness = args.harness or os.path.join(OUT, "harness.exe")
    if not os.path.exists(harness):
        alt = os.path.join(OUT, "harness")
        if os.path.exists(alt):
            harness = alt
    if not os.path.exists(harness):
        sys.exit("harness not found - build the lendiza_diff_harness target "
                 "or run tests/diff/build.bat / build.sh")

    streams = [json.loads(l) for l in
               open(os.path.join(OUT, "streams.jsonl"), encoding="utf-8")]

    proc = subprocess.run(
        [harness, os.path.join(OUT, "streams.tsv")],
        capture_output=True, text=True, cwd=OUT)
    if proc.returncode != 0:
        sys.exit(f"harness exited {proc.returncode}: {proc.stderr.strip()}")

    actuals = {}
    for line in proc.stdout.splitlines():
        srcid, step, res = line.split("\t")
        actuals.setdefault(srcid, {})[int(step)] = res

    n_steps = ok = 0
    by_design, suspect = [], []
    for s in streams:
        srcid = f"{s['src']}:{s['id']}"
        raw = bytes.fromhex(s["bytes"])
        offset = 0
        for step, expected in enumerate(s["sizes"]):
            n_steps += 1
            got = actuals.get(srcid, {}).get(step)
            if got is None:
                suspect.append({"id": srcid, "step": step, "expected": expected,
                                "actual": "missing",
                                "reason": "no harness result (stream stopped early)",
                                "bytes": s["bytes"]})
                break
            got_v = got if got in ("E0", "E1", "E2") else int(got)
            if got_v == expected:
                ok += 1
            else:
                bucket, reason = classify(s, step, expected, got_v, raw[offset:])
                entry = {"id": srcid, "step": step, "expected": expected,
                         "actual": got_v, "reason": reason, "bytes": s["bytes"]}
                (by_design if bucket == "by-design" else suspect).append(entry)
            if isinstance(got_v, int):
                offset += got_v
            else:
                break

    report = {
        "streams": len(streams),
        "sized_steps": n_steps,
        "agree": ok,
        "by_design": by_design,
        "suspect": suspect,
    }
    with open(os.path.join(OUT, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"streams: {len(streams)}  sized steps: {n_steps}")
    print(f"agree:   {ok} ({100.0 * ok / max(1, n_steps):.1f}%)")
    print(f"by-design divergences: {len(by_design)}")
    buckets = {}
    for e in by_design:
        buckets[e["reason"].split(":")[0]] = buckets.get(e["reason"].split(":")[0], 0) + 1
    for k, v in sorted(buckets.items()):
        print(f"  {k}: {v}")
    print(f"suspect mismatches:    {len(suspect)}")
    for e in suspect[:20]:
        print(f"  {e['id']} step {e['step']}: expected {e['expected']}, "
              f"got {e['actual']} - {e['reason']} [{e['bytes'][:40]}]")
    if len(suspect) > 20:
        print(f"  ... and {len(suspect) - 20} more (out/report.json)")
    return 1 if suspect else 0


if __name__ == "__main__":
    sys.exit(main())
