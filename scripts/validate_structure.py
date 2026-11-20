#!/usr/bin/env python3
"""Structural validation for BECETTI SECURITY source (no .NET SDK required).

Checks:
- XAML / csproj / appxmanifest files are well-formed XML
- JSON files parse
- C# files have balanced braces/brackets/parentheses (naive, string/comment aware)
- Resw XML has expected structure
- No obvious placeholder leaks (hardcoded secrets patterns) in committed code
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors = []
warns = []

try:
    import xml.etree.ElementTree as ET
except ImportError:  # pragma: no cover
    ET = None


def check_xml(path: Path):
    if ET is None:
        warns.append(f"{path}: xml.etree not available, skipping")
        return
    try:
        ET.parse(str(path))
    except ET.ParseError as e:
        errors.append(f"{path}: XML parse error: {e}")


def check_json(path: Path):
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        errors.append(f"{path}: JSON parse error: {e}")


def strip_cs_literals(text: str) -> str:
    """Remove C# string/char literals and comments, replacing with spaces.

    Handles regular, verbatim (@"...") and interpolated ($"..." / @"$..." /
    $@"...") strings including nested interpolation braces, char literals,
    line comments and block comments. Returns a same-length string so line
    numbers stay meaningful for downstream checks.
    """
    out = list(text)
    n = len(text)
    i = 0

    def spans(a: int, b: int):
        for k in range(a, b):
            out[k] = " "

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        # line comment
        if c == "/" and nxt == "/":
            j = i
            while j < n and text[j] != "\n":
                j += 1
            spans(i, j)
            i = j
            continue
        # block comment
        if c == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            if j == -1:
                spans(i, n)
                i = n
                continue
            spans(i, j + 2)
            i = j + 2
            continue
        # char literal
        if c == "'":
            j = i + 1
            if j < n and text[j] == "\\":
                j += 2
            elif j < n:
                j += 1
            if j < n and text[j] == "'":
                spans(i, j + 1)
                i = j + 1
                continue
            spans(i, i + 1)
            i += 1
            continue

        # string literal opening: optional @/$ prefix, then one or more quotes
        prefix_len = 0
        interp = False
        verbatim = False
        is_string = False
        if c == '@' and nxt == '$' and i + 2 < n and text[i + 2] == '"':
            prefix_len = 2; interp = True; verbatim = True; is_string = True   # @$
        elif c == '$' and nxt == '@' and i + 2 < n and text[i + 2] == '"':
            prefix_len = 2; interp = True; verbatim = True; is_string = True   # $@
        elif c == '@' and nxt == '"':
            prefix_len = 1; verbatim = True; is_string = True                   # @
        elif c == '$' and nxt == '"':
            prefix_len = 1; interp = True; is_string = True                     # $
        elif c == '"':
            prefix_len = 0; is_string = True                                    # "

        if is_string:
            lit_start = i
            quote_pos = i + prefix_len
            qcount = 0
            while quote_pos + qcount < n and text[quote_pos + qcount] == '"':
                qcount += 1
            if qcount == 0:
                i += 1
                continue
            if qcount >= 3:
                # ---- raw string literal (C# 11) ----
                raw_n = qcount
                i = quote_pos + raw_n
                j = i
                close = '"' * raw_n
                while j + raw_n <= n:
                    if text[j:j + raw_n] == close:
                        break
                    j += 1
                end = j + raw_n if j + raw_n <= n else n
                spans(lit_start, end)
                i = end
                continue
            elif qcount == 2:
                # empty regular string literal ""
                spans(lit_start, quote_pos + 2)
                i = quote_pos + 2
                continue
            else:  # qcount == 1
                i = quote_pos + 1
                j = i
                depth = 0
                while j < n:
                    ch = text[j]
                    if ch == "\\" and j + 1 < n:
                        j += 2
                        continue
                    if verbatim:
                        if ch == '"':
                            if j + 1 < n and text[j + 1] == '"':
                                j += 2
                                continue
                            break
                        j += 1
                        continue
                    if interp:
                        if ch == "{" and j + 1 < n and text[j + 1] == "{":
                            j += 2
                            continue  # literal { (escaped)
                        if ch == "}" and j + 1 < n and text[j + 1] == "}":
                            j += 2
                            continue  # literal } (escaped)
                        if ch == "{":
                            depth += 1
                        elif ch == "}":
                            if depth > 0:
                                depth -= 1
                            # depth-0 } is a literal brace in string content;
                            # keep scanning until the closing " at depth 0
                        elif ch == '"' and depth == 0:
                            break
                    else:
                        if ch == '"':
                            break
                    j += 1
                end = j + 1 if j < n else n
                spans(lit_start, end)
                i = end
                continue

        i += 1

    return "".join(out)


def check_braces(path: Path):
    """Brace balance on C# with literals/comments removed (same-length output)."""
    text = path.read_text(encoding="utf-8", errors="replace")
    text = strip_cs_literals(text)

    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = []
    for i, ch in enumerate(text):
        if ch in pairs:
            stack.append((ch, i))
        elif ch in pairs.values():
            if not stack:
                errors.append(f"{path}:{i+1}: unmatched closing {ch}")
                return
            open_ch, open_i = stack.pop()
            if pairs[open_ch] != ch:
                errors.append(f"{path}:{open_i+1}: {open_ch} closed by {ch}")
                return
    for open_ch, open_i in stack:
        errors.append(f"{path}:{open_i+1}: unclosed {open_ch}")


def main():
    xml_files = list(ROOT.rglob("*.xaml")) + list(ROOT.rglob("*.csproj")) + \
                list(ROOT.rglob("*.appxmanifest")) + list(ROOT.rglob("*.resw"))
    json_files = list(ROOT.rglob("*.json"))
    cs_files = list(ROOT.rglob("*.cs"))

    for p in xml_files:
        check_xml(p)
    for p in json_files:
        check_json(p)
    for p in cs_files:
        check_braces(p)

    # Placeholder / secret scan (heuristic) across committed source
    secret_patterns = [
        (r"sk_live_[0-9a-zA-Z]{20,}", "Stripe-like live key"),
        (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
        (r"(?i)(api[_-]?key|secret)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9]{20,}[\"']", "hardcoded API key/secret"),
    ]
    for p in cs_files:
        t = p.read_text(encoding="utf-8", errors="replace")
        for pat, label in secret_patterns:
            if re.search(pat, t):
                warns.append(f"{p}: possible hardcoded secret ({label}) — verify it is env-driven")

    print(f"XML/JSON/CS files checked: {len(xml_files)} xml-ish, {len(json_files)} json, {len(cs_files)} cs")
    if errors:
        print(f"\n{len(errors)} ERROR(S):")
        for e in errors:
            print("  ", e)
    if warns:
        print(f"\n{len(warns)} WARNING(S):")
        for w in warns:
            print("  ", w)
    if not errors and not warns:
        print("\nAll structural checks passed.")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
