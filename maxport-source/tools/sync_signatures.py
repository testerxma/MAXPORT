#!/usr/bin/env python3
"""Regenerates the remote-access signatures from the public LOLRMM catalogue.

The single most predictable way this tool fails is quietly, months from now,
when an operator uses a product released after the signature list was
written. A hand-maintained list of remote-access tools starts wrong and gets
worse.

LOLRMM is a community catalogue of remote monitoring and management software
and how each one is used against people — the same set CISA and the FBI name
in their advisories. It carries the process names, install paths and vendor
domains this scanner needs, and it is maintained by people who watch these
campaigns full time.

    python3 tools/sync_signatures.py            # refresh from the network
    python3 tools/sync_signatures.py --dry-run  # show what would change

Run deliberately, never at scan time. A security tool that reaches out to
the internet and rewrites its own detection logic on a machine that may be
compromised has built the supply-chain problem it exists to find. The output
is source code, reviewed in a diff like anything else.
"""

from __future__ import annotations

import argparse
import io
import os
import re
import sys
import tarfile
import urllib.request

ARCHIVE = ("https://codeload.github.com/magicsword-io/LOLRMM/"
           "tar.gz/refs/heads/main")

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = os.path.join(HERE, "..", "maxport", "rmm_catalogue.py")

# Products so widely installed on purpose that treating them as inherently
# suspicious would bury the report. They stay in the catalogue; the engine
# decides severity.
COMMON = {
    "teamviewer", "anydesk", "chrome remote desktop", "windows remote desktop",
    "splashtop", "logmein", "gotoassist", "zoho assist", "quick assist",
}


def fetch() -> bytes:
    request = urllib.request.Request(
        ARCHIVE, headers={"User-Agent": "maxport-signature-sync"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def _block(text: str, key: str) -> str:
    """The indented body under a top-level YAML key.

    A deliberate small parser rather than a YAML dependency: this file runs
    on a maintainer's machine, and adding a third-party import to the tree
    for one offline script is a poor trade.
    """
    match = re.search(rf"^{key}:\s*$", text, re.M)
    if not match:
        return ""
    rest = text[match.end():]
    lines = []
    for line in rest.splitlines():
        if line.strip() and not line.startswith((" ", "\t")):
            break
        lines.append(line)
    return "\n".join(lines)


def parse(text: str) -> dict | None:
    name = re.search(r"^Name:\s*(.+)$", text, re.M)
    if not name:
        return None
    tool = name.group(1).strip().strip("'\"")

    def clean(value: str) -> str:
        """Strips YAML quoting and rejects anything that is not a filename.

        The catalogue is written by many hands, so values arrive quoted,
        doubly quoted, as 'N/A', or empty. An entry like "''" became a
        dictionary key that matched a process whose name was two quote
        marks — never, which is the harmless failure, but it also meant the
        real name was missing.
        """
        v = value.strip().strip("'\"").strip()
        if not v or v.lower() in ("n/a", "na", "none", "-", "unknown"):
            return ""
        if "*" in v or "\\" in v or "/" in v:
            return ""
        # A filename: letters, digits and the usual separators, nothing else
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{1,60}", v):
            return ""
        return v.lower()

    executables = sorted({
        cleaned
        for m in re.finditer(r"^\s*-?\s*(?:Filename|OriginalFileName):\s*(.+)$",
                             text, re.M)
        if (cleaned := clean(m.group(1)))
    })

    domains = set()
    for m in re.finditer(r"^\s+-\s+'?\*?\.?([a-z0-9.-]+\.[a-z]{2,})'?\s*$",
                         _block(text, "Artifacts"), re.M | re.I):
        candidate = m.group(1).strip().lower()
        # Regex fragments and wildcards appear in this field; keep only what
        # is usable as a domain suffix.
        if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", candidate):
            parts = candidate.split(".")
            domains.add(".".join(parts[-2:]) if len(parts) > 2 else candidate)

    paths = sorted({
        m.group(1).strip()
        for m in re.finditer(r"^\s*-\s*([A-Za-z]:\\\\?[^\n]+|/[^\n]+)$",
                             _block(text, "Details"), re.M)
    })[:6]

    if not executables and not domains:
        return None
    return {"name": tool, "executables": executables,
            "domains": sorted(domains), "paths": paths}


def render(tools: list[dict]) -> str:
    lines = [
        '"""Remote-access products, generated from the LOLRMM catalogue.',
        "",
        "DO NOT EDIT BY HAND. Regenerate with:",
        "",
        "    python3 tools/sync_signatures.py",
        "",
        "Hand-written signatures in signatures.py take precedence; this file",
        "widens the net rather than replacing judgement. Being listed here",
        "means a product exists and is known to be abused, never that its",
        "presence is proof of anything — most entries are legitimate software",
        "someone may have installed deliberately.",
        '"""',
        "",
        f"# {len(tools)} products",
        "CATALOGUE_SIZE = %d" % len(tools),
        "",
        "# process name -> product",
        "CATALOGUE_EXECUTABLES = {",
    ]
    seen: dict[str, str] = {}
    for tool in tools:
        for exe in tool["executables"]:
            key = exe.lower().removesuffix(".exe")
            if key and key not in seen:
                seen[key] = tool["name"]
    for key in sorted(seen):
        lines.append(f'    "{key}": "{seen[key]}",')
    lines += ["}", "", "# product -> domains its own infrastructure uses",
              "CATALOGUE_DOMAINS = {"]
    for tool in sorted(tools, key=lambda t: t["name"]):
        if tool["domains"]:
            joined = ", ".join(f'"{d}"' for d in tool["domains"])
            lines.append(f'    "{tool["name"]}": ({joined},),')
    lines += ["}", "",
              "# Products common enough that their presence alone is not news",
              "CATALOGUE_COMMON = {"]
    for tool in sorted(tools, key=lambda t: t["name"]):
        if tool["name"].lower() in COMMON:
            lines.append(f'    "{tool["name"]}",')
    lines += ["}", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would change, write nothing")
    args = parser.parse_args()

    print("Fetching the LOLRMM catalogue…")
    try:
        raw = fetch()
    except Exception as e:
        print(f"Could not fetch: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    tools = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive.getmembers():
            if "/yaml/" not in member.name or not member.name.endswith(
                    (".yaml", ".yml")):
                continue
            handle = archive.extractfile(member)
            if not handle:
                continue
            parsed = parse(handle.read().decode("utf-8", "replace"))
            if parsed:
                tools.append(parsed)

    if not tools:
        print("No tools parsed — the catalogue layout has changed. "
              "Not overwriting the existing file.", file=sys.stderr)
        return 1

    rendered = render(tools)
    executables = rendered.count('": "')
    print(f"Parsed {len(tools)} products, {executables} process names.")

    target = os.path.abspath(OUTPUT)
    previous = ""
    if os.path.exists(target):
        with open(target, encoding="utf-8") as f:
            previous = f.read()

    if previous == rendered:
        print("No change.")
        return 0

    if args.dry_run:
        print(f"Would rewrite {target}")
        print(f"  {len(previous.splitlines())} lines -> "
              f"{len(rendered.splitlines())} lines")
        return 0

    with open(target, "w", encoding="utf-8") as f:
        f.write(rendered)
    print(f"Wrote {target}")
    print("Review the diff before committing — this is detection logic.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
