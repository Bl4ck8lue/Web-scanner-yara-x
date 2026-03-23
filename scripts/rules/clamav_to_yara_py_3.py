#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clamav_to_yara_py3.py

Modernized ClamAV (.ndb/.sig) -> YARA converter
- Python 3
- argparse instead of optparse
- better rule-name sanitization
- improved handling of ClamAV jump operators ({n}, {n-}, {n-m}, {-n})
- outputs well-formed YARA rules
- verbose / quiet logging

Usage example:
    python3 clamav_to_yara_py3.py -f main.ndb -o output.yar -s Trojan

This is a single-file utility intended for local, offline processing of
ClamAV signature files produced by e.g. sigtool or legacy .ndb files.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from typing import Dict, List

LOG = logging.getLogger("clamav2yara")

YARA_RULE_TMPL = """rule {name}
{{
    meta:
        source = "clamav"
        original_name = "{orig}"

    strings:
{strings}

    condition:
        {condition}
}}

"""


def sane_rulename(name: str) -> str:
    # replace non-alnum/_ with _ and remove leading digits
    s = re.sub(r"[^0-9A-Za-z_]", "_", name)
    s = re.sub(r"^([0-9]+)", "", s)
    if not s:
        s = "rule_unnamed"
    return s


def format_hex_string(hexstr: str) -> str:
    """Turn an unspaced hex string like '6A40FF' into '6A 40 FF'.
    If the input already contains spaces or braces, leave bytes groups intact.
    """
    # remove any non-hex chars to test
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", hexstr)
    if len(cleaned) == 0:
        return hexstr
    # if it looks like continuous hex (even length), split into byte pairs
    if len(cleaned) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", cleaned):
        pairs = [cleaned[i : i + 2] for i in range(0, len(cleaned), 2)]
        return " ".join(pairs)
    return hexstr


def translate_jumps(signature: str, verbose: bool = False) -> str:
    """Translate ClamAV jump operators into YARA-friendly fragments.

    ClamAV uses patterns like:
      {n}     -> exactly n bytes
      {n-}    -> n or more bytes
      {-n}    -> up to n bytes
      {n-m}   -> from n to m bytes

    YARA supports constructs like:
      [N]     -> exactly N bytes
      [N-M]   -> range N..M
      *       -> wildcard (used here for large ranges >255)

    We aim to keep jumps <=255 as explicit ranges; otherwise replace with '*'.
    """

    # {-n} -> {0-n}
    signature = re.sub(r"\{-(\d+)\}", r"{0-\1}", signature)

    # {n-} -> [0-n] if small, otherwise '*'
    def repl_n_dash(m):
        n = int(m.group(1))
        if n < 256:
            return f"[0-{n}]"
        return "*"

    signature = re.sub(r"\{(\d+)-\}", repl_n_dash, signature)

    # {n-m} -> [n-m] if (m <256 and m-n <256), else '*'
    def repl_n_m(m):
        n = int(m.group(1))
        mm = int(m.group(2))
        if mm < 256 and (mm - n) < 256:
            return f"[{n}-{mm}]"
        return "*"

    signature = re.sub(r"\{(\d+)-(\d+)\}", repl_n_m, signature)

    # {n} -> [n] if <256 else '*'
    def repl_n(m):
        n = int(m.group(1))
        if n < 256:
            return f"[{n}]"
        return "*"

    signature = re.sub(r"\{(\d+)\}", repl_n, signature)

    return signature


def split_on_wildcard(signature: str) -> List[str]:
    # split by '*' but keep non-empty parts
    parts = [p.strip() for p in signature.split("*") if p.strip()]
    return parts


def normalize_part(part: str) -> str:
    # remove leading/trailing parentheses
    p = part.strip()
    if p.startswith("(") and p.endswith(")"):
        p = p[1:-1].strip()
    # turn continuous hex into spaced bytes
    # if part looks like hex (no spaces, only hex), format it
    hex_candidate = re.sub(r"[^0-9A-Fa-f]", "", p)
    if len(hex_candidate) >= 2 and len(hex_candidate) % 2 == 0 and len(hex_candidate) == len(p):
        return format_hex_string(p)
    # otherwise, return as-is (YARA supports ASCII strings too)
    return p


def parse_clamav_file(path: str, search: str = "", verbose: bool = False) -> Dict[str, List[str]]:
    rules: Dict[str, List[str]] = {}

    with open(path, "rb") as fh:
        raw = fh.read()

    # quick check for compressed db
    if (path.endswith(".cvd") or path.endswith(".cld")) and raw.startswith(b"ClamAV"):
        LOG.error("It seems you're passing a compressed ClamAV database. Decompress with sigtool -u first.")
        sys.exit(2)

    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode(errors="replace")

    lines = text.splitlines()
    LOG.info("Read %d lines from %s", len(lines), path)

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # ClamAV legacy/ndb format: name:sigtype:offset:signature[:optional fields]
        parts = line.split(":")
        if len(parts) < 4:
            if verbose:
                LOG.debug("Skipping non-signature line: %s", line)
            continue

        name, sigtype, offset, signature = parts[0], parts[1], parts[2], parts[3]

        if search and search not in name:
            continue

        rulename = sane_rulename(name)
        if rulename not in rules:
            rules[rulename] = []

        # perform translations
        sig = signature.strip()

        # translate ClamAV-style jumps into YARA style
        sig = translate_jumps(sig, verbose=verbose)

        # break into parts on '*'
        if "*" in sig:
            parts = split_on_wildcard(sig)
            for p in parts:
                norm = normalize_part(p)
                if norm:
                    rules[rulename].append(norm)
        else:
            norm = normalize_part(sig)
            if norm:
                rules[rulename].append(norm)

    return rules


def build_yara(rules: Dict[str, List[str]]) -> str:
    """Build YARA rules text from parsed rules dict.

    This implementation avoids f-string issues with literal braces by using
    str.format() for all template insertions when braces are needed.
    """
    out: List[str] = []
    for rulename, detects in sorted(rules.items()):
        if not detects:
            LOG.debug("Skipping empty rule %s", rulename)
            continue

        strs: List[str] = []
        cond_elems: List[str] = []
        for idx, d in enumerate(detects):
            # If d looks like hex bytes (pairs separated by spaces or not), wrap in { ... }
            if re.fullmatch(r"[0-9A-Fa-f\s\[\]\-]+", d):
                bytebody = format_hex_string(d)
                # use .format() to safely insert byte list inside literal braces
                strs.append('        $a{} = {{ {} }}'.format(idx, bytebody))
            else:
                # treat as literal string — escape internal quotes
                escaped = d.replace('"', '\\"')
                strs.append('        $a{} = \"{}\"'.format(idx, escaped))
            cond_elems.append("$a{}".format(idx))

        condition = " or ".join(cond_elems) if cond_elems else "false"
        rule_text = YARA_RULE_TMPL.format(
            name=rulename,
            orig=rulename,
            strings="\n".join(strs),
            condition=condition
        )
        out.append(rule_text)

    return "".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Convert ClamAV legacy signatures (.ndb/.sig) to YARA rules (Python 3)")
    parser.add_argument("-f", "--file", required=True, help="Input ClamAV signature file")
    parser.add_argument("-o", "--output-file", required=True, help="YARA output file")
    parser.add_argument("-s", "--search", default="", help="Optional substring filter for signature names")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    if not os.path.isfile(args.file):
        LOG.error("Input file does not exist: %s", args.file)
        sys.exit(2)

    rules = parse_clamav_file(args.file, search=args.search, verbose=args.verbose)
    yara_text = build_yara(rules)

    if yara_text:
        with open(args.output_file, "w", encoding="utf-8") as fo:
            fo.write(yara_text)
        LOG.info("Wrote %d rules to %s", len(rules), args.output_file)
    else:
        LOG.warning("No rules generated; check your input / search filter")


if __name__ == "__main__":
    main()
