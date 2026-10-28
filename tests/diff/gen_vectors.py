#!/usr/bin/env python3
"""Convert Zydis / Capstone test cases into lendiza differential test vectors.

lendiza is a *length*-disassembler, so unlike xendiza's test/diff the vectors
carry no mnemonic/operand expectations - only the per-instruction length
ground truth both upstream projects publish:

- Capstone YAMLs (`third_party/capstone/*.yaml`): `expected.insns[].size`,
  only present in `x86.yaml`, `x86-bitscan-prefixes.yaml` and
  `x86_jcc_mode.yaml`. A case becomes a stream vector only when *every*
  expected instruction carries a size and the sizes fit inside the input
  bytes; the harness then decodes the stream linearly, one step per
  expected instruction.
- Zydis regression cases (`third_party/zydis/default_*.in/.out`): the
  `.out` ZydisInfo dump of the *first* instruction carries `LENGTH`.
  One vector per case: decode a single instruction at offset 0.

Output: tests/diff/out/streams.jsonl
  {src, id, mode, bytes (hex), sizes ([int, ...])}
And tests/diff/out/streams.tsv for the harness:
  mode TAB hex TAB srcid TAB count
"""
import glob
import json
import os
import re
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # repo root (tests/diff -> tests -> root)
TP = os.path.join(ROOT, "third_party")
OUT = os.path.join(HERE, "out")


def load_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def parse_capstone_yaml(path, streams, skipped):
    """All capstone YAMLs share the test_cases schema; build stream vectors.

    Two kinds of length ground truth are used:
    - cases whose every expected instruction carries an explicit `size`
      (x86-bitscan-prefixes.yaml, x86_jcc_mode.yaml) - kept per-instruction;
    - single-instruction cases with no explicit size (x86.yaml, the
      `tests/MC/X86/*.s.yaml` ports) - the instruction length is the byte
      count of the input, which is how those tests are constructed.
    Multi-instruction cases without per-instruction sizes are unusable for
    a length-only decoder and are skipped.
    """
    data = load_yaml(path)
    for ci, case in enumerate(data.get("test_cases", []) or []):
        inp = case.get("input", {}) or {}
        opts = inp.get("options", []) or []
        if "CS_MODE_64" in opts:
            mode = 64
        elif "CS_MODE_32" in opts:
            mode = 32
        else:
            skipped["mode16"] += 1
            continue
        raw = inp.get("bytes", []) or []
        insns = (case.get("expected", {}) or {}).get("insns", []) or []
        if not raw or not insns or not insns[0].get("asm_text"):
            skipped["empty"] += 1
            continue
        if all(i.get("asm_text") and i.get("size") is not None for i in insns):
            sizes = [int(i["size"]) for i in insns]
            how = "size"
        elif len(insns) == 1:
            sizes = [len(raw)]
            how = "bytes"
        else:
            skipped["no_size"] += 1
            continue
        if sum(sizes) > len(raw):
            skipped["size_overrun"] += 1
            continue
        streams.append({"src": "capstone",
                        "id": f"{os.path.basename(path)}#{ci}",
                        "mode": mode, "bytes": bytes(raw).hex(),
                        "sizes": sizes, "how": how})


ZYDIS_BASIC_RE = re.compile(r"^== \[    BASIC \]", re.M)
MN_RE = re.compile(r"MNEMONIC:\s+(\S+)")
LEN_RE = re.compile(r"LENGTH:\s+(\d+)")


def parse_zydis(streams, skipped):
    for inf in sorted(glob.glob(os.path.join(TP, "zydis", "default_*.in"))):
        outf = inf[:-3] + ".out"
        if not os.path.exists(outf):
            skipped["no_out"] += 1
            continue
        args = open(inf).read().strip()
        mode, hexs = None, ""
        for p in args.split():
            if p.startswith("-"):
                mode = {"-64": 64, "-32": 32, "-16": 16}.get(p, mode)
            else:
                hexs = p
        if mode is None or not hexs:
            skipped["bad_in"] += 1
            continue
        if mode == 16:
            skipped["mode16"] += 1
            continue
        text = open(outf, encoding="utf-8", errors="replace").read()
        m = MN_RE.search(text)
        l = LEN_RE.search(text)
        if not m or not l or m.group(1).lower() == "invalid":
            skipped["bad_out"] += 1
            continue
        streams.append({"src": "zydis", "id": os.path.basename(inf)[:-3],
                        "mode": mode, "bytes": hexs,
                        "sizes": [int(l.group(1))], "how": "length"})


def main():
    streams = []
    skipped = {"mode16": 0, "empty": 0, "no_size": 0, "size_overrun": 0,
               "no_out": 0, "bad_in": 0, "bad_out": 0}
    files = sorted(glob.glob(os.path.join(TP, "capstone", "*.yaml")))
    seen = set()
    for f in files:
        base = os.path.basename(f)
        if base in seen:  # x86.yaml would appear twice via a manual + glob list
            continue
        seen.add(base)
        before = len(streams)
        parse_capstone_yaml(f, streams, skipped)
        print(f"{base}: +{len(streams) - before}", file=sys.stderr)
    before = len(streams)
    parse_zydis(streams, skipped)
    print(f"zydis: +{len(streams) - before}", file=sys.stderr)
    print(f"skipped: {skipped}", file=sys.stderr)

    # Identical (mode, bytes, sizes) vectors occur across capstone files
    # (e.g. an MC test duplicated in x86.yaml); keep the first, preferring
    # explicit size ground truth over the derived single-insn one.
    def rank(s):
        return {"size": 0, "length": 1, "bytes": 2}[s["how"]]
    dedup = {}
    for s in streams:
        key = (s["mode"], s["bytes"], tuple(s["sizes"]))
        if key not in dedup or rank(s) < rank(dedup[key]):
            dedup[key] = s
    if len(dedup) != len(streams):
        print(f"dedup: {len(streams) - len(dedup)} duplicate vectors",
              file=sys.stderr)
    streams = list(dedup.values())

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "streams.jsonl"), "w") as f:
        for s in streams:
            f.write(json.dumps(s) + "\n")
    with open(os.path.join(OUT, "streams.tsv"), "w") as f:
        for s in streams:
            f.write(f"{s['mode']}\t{s['bytes']}\t{s['src']}:{s['id']}\t{len(s['sizes'])}\n")
    n_steps = sum(len(s["sizes"]) for s in streams)
    print(f"streams: {len(streams)}, sized steps: {n_steps}", file=sys.stderr)


if __name__ == "__main__":
    main()
