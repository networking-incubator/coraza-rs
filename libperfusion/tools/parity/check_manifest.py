#!/usr/bin/env python3
"""Check the pinned libinjection-go source, the C reference pin and the SQL dispatch.

This script is the only writer of ``tests/parity/differential.json``
(``--update --go-source``). It does not re-derive the facts other tools own:
``cargo xtask corpus-check`` owns the Go module pin and the fixture inventory
in ``tests/parity/manifest.json`` (written only by ``cargo xtask
corpus-refresh``), and ``data/tables.json`` owns the table hashes and the C
revision they came from (written by ``cargo xtask tables-refresh``, checked by
``cargo xtask tables-check``). ``differential.json`` repeats the module pin
from ``manifest.json``, so a module bump fails here until ``--update`` rewrites
it, and ``C_REFERENCE`` must name the commit ``data/tables.json`` records.

Scope: every table comparison here is against the *upstream-generated*
``data/sqli_keywords.txt`` and ``data/xss_tables.txt``. Those two files stay
byte-for-byte what the pinned revision produces, so comparing them to the
pinned Go source for exact equality is correct and must stay strict.

The compiled tables are deliberately larger: ``build.rs`` merges
``data/sqli_keywords_local.txt`` and ``data/xss_tables_local.txt`` into them.
Those supplements are this project's own additions, are pinned by the
``local`` section of ``data/tables.json``, and are verified by
``cargo xtask tables-check``; they are intentionally absent from the parity
metadata, which describes upstream alone. What this script does check about
them is that they cannot silently change the meaning of an upstream row --
see :func:`check_local_supplements`.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tests/parity/manifest.json"
DIFFERENTIAL = ROOT / "tests/parity/differential.json"
TABLES = ROOT / "data/tables.json"
GO_MODULE = "github.com/corazawaf/libinjection-go"
GO_REPOSITORY = "https://github.com/corazawaf/libinjection-go"
# A C revision bump edits this commit (check_c_reference requires it to equal
# data/tables.json) and reruns --update --go-source.
C_REFERENCE = {
    "repository": "https://github.com/libinjection/libinjection",
    "commit": "1b9f5f077fc10754e7e4b6498cdaa8fbee53d707",
    "driver": "tests/c_oracle_driver.c",
    "results": "SQLi verdict and fingerprint; XSS verdict",
    # Was 24; the local MATH tag row closed four of them. See
    # tests/parity/mismatch-ledger.md.
    "reviewed_xss_differences": 20,
}
GO_TOOLS = ROOT.parent / "xtask/tools"
EXPECTED_KEYWORDS = 9_359
EXPECTED_FINGERPRINTS = 8_367
EXPECTED_XSS = {"tags": 20, "events": 432, "attributes": 20}
EXPECTED_ORACLE_ERRORS: list[dict[str, object]] = []
GO_KIND_TO_RUST = {
    "attributeTypeBlack": "Deny",
    "attributeTypeAttrURL": "Url",
    "attributeTypeStyle": "Style",
    "attributeTypeAttrIndirect": "Indirect",
}
RUST_XSS_KIND = {"Black": "Deny", "Url": "Url", "Style": "Style", "Indirect": "Indirect"}
LOCAL_RUST_XSS_KINDS = {*RUST_XSS_KIND, "UrlScheme"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fail(message: str) -> None:
    raise SystemExit(message)


def compare_fixtures(source: Path) -> None:
    upstream_dir = source / "tests"
    upstream = {path.name: path.read_bytes() for path in upstream_dir.glob("test-*.txt")}
    vendored_dir = ROOT / "tests/corpus"
    vendored = {path.name: path.read_bytes() for path in vendored_dir.glob("test-*.txt")}
    if upstream != vendored:
        missing = sorted(set(upstream) - set(vendored))[:5]
        extra = sorted(set(vendored) - set(upstream))[:5]
        different = sorted(name for name in upstream.keys() & vendored.keys() if upstream[name] != vendored[name])[:5]
        fail(f"vendored corpus differs from pinned Go tests: missing={missing}, extra={extra}, different={different}")


def parse_go_keywords(source: Path) -> dict[str, str]:
    text = (source / "sqli_data.go").read_text(encoding="utf-8")
    match = re.search(r"var sqlKeywords = map\[string\]byte\s*\{(.*?)\n\}", text, re.S)
    if not match:
        fail("could not find pinned Go sqlKeywords map")
    entries: dict[str, str] = {}
    row = re.compile(r'^\s*("(?:\\.|[^"\\])*")\s*:\s*([^,]+),\s*$', re.M)
    for line in match.group(1).splitlines():
        parsed = row.match(line)
        if not parsed:
            if line.strip():
                fail(f"unrecognized sqlKeywords row: {line!r}")
            continue
        key = ast.literal_eval(parsed.group(1))
        value = parsed.group(2).strip()
        if len(value) < 3 or value[0] != "'" or value[-1] != "'":
            fail(f"unsupported Go byte literal for {key!r}: {value!r}")
        decoded_value = bytes(value[1:-1], "utf-8").decode("unicode_escape")
        if len(decoded_value) != 1 or ord(decoded_value) > 255:
            fail(f"non-byte Go map value for {key!r}: {value!r}")
        if key in entries:
            fail(f"duplicate key in pinned Go map: {key!r}")
        entries[key] = decoded_value
    return entries


def parse_rust_keywords(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 2 or len(parts[1]) != 1:
            fail(f"malformed keyword row at {path}:{line_number}: {line!r}")
        key, value = parts
        if not key or not key.isascii() or any(c.isalpha() and not c.isupper() for c in key):
            fail(f"invalid keyword key at {path}:{line_number}: {key!r}")
        if key in entries:
            fail(f"duplicate Rust keyword key at {path}:{line_number}: {key!r}")
        entries[key] = value
    return entries


def extract_keywords(source: Path, version: str) -> None:
    entries = parse_go_keywords(source)
    if len(entries) != EXPECTED_KEYWORDS:
        fail(f"expected {EXPECTED_KEYWORDS} upstream SQL entries, found {len(entries)}")
    if any(not value.isascii() for value in entries.values()):
        fail("the pinned SQL keyword table contains a non-ASCII value")
    output = [
        f"# Auto-extracted from libinjection-go {version} sqli_data.go",
        f"# Total entries: {len(entries)}",
        "# Format: KEY<TAB>VALUE_BYTE",
    ]
    output.extend(f"{key}\t{entries[key]}" for key in sorted(entries))
    (ROOT / "data/sqli_keywords.txt").write_text("\n".join(output) + "\n", encoding="ascii")


def parse_go_dispatch(source: Path) -> list[str]:
    text = (source / "sqli_data.go").read_text(encoding="utf-8")
    body_match = re.search(r"func buildByteParsers\(\) \[\]\w+\s*\{(.*?)\n\treturn parsers", text, re.S)
    if not body_match:
        fail("could not find pinned Go buildByteParsers switch")
    body = body_match.group(1)
    mapping: list[str | None] = [None] * 256
    case_re = re.compile(r"case\s+([0-9,\s]+):\s*parsers\[i\]\s*=\s*(\w+)", re.S)
    for case, parser in case_re.findall(body):
        values = [int(value) for value in re.findall(r"\d+", case)]
        for value in values:
            if not 0 <= value < 256 or mapping[value] is not None:
                fail(f"invalid/duplicate byte dispatch value {value}")
            mapping[value] = parser
    if "default:" in body:
        mapping = [value or "parseWord" for value in mapping]
    elif any(value is None for value in mapping):
        missing = [f"{value:#04x}" for value, parser in enumerate(mapping) if parser is None]
        fail("pinned Go dispatch leaves bytes unassigned without a default branch: " + ", ".join(missing[:8]))
    if len(mapping) != 256:
        fail("pinned Go dispatch is not 256 bytes")
    return [str(value) for value in mapping]


def parse_rust_dispatch() -> list[str]:
    text = (ROOT / "src/sqli/lexer.rs").read_text(encoding="utf-8")
    match = re.search(r"pub const fn for_byte\(ch: u8\) -> Self \{\s*match ch \{(.*?)\n        \}", text, re.S)
    if not match:
        fail("could not find libperfusion SQL byte dispatch")
    rust_to_go = {
        "White": "parseWhite",
        "Operator1": "parseOperator1",
        "Operator2": "parseOperator2",
        "Other": "parseOther",
        "Char": "parseByte",
        "Hash": "parseHash",
        "Dash": "parseDash",
        "Slash": "parseSlash",
        "Backslash": "parseBackSlash",
        "String": "parseString",
        "Word": "parseWord",
        "Var": "parseVar",
        "Number": "parseNumber",
        "Tick": "parseTick",
        "Ustring": "parseUString",
        "Qstring": "parseQString",
        "Nqstring": "parseNqString",
        "Xstring": "parseXString",
        "Bstring": "parseBString",
        "Estring": "parseEString",
        "Bword": "parseBWord",
        "Money": "parseMoney",
    }
    mapping: list[str | None] = [None] * 256

    def value_of(atom: str) -> int:
        atom = atom.strip()
        byte_literal = re.fullmatch(r"b('(?:\\.|[^'\\])*')", atom)
        if byte_literal:
            value = ast.literal_eval(byte_literal.group(1))
            if len(value) != 1:
                fail(f"invalid byte pattern {atom!r}")
            return ord(value)
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", atom):
            return int(atom, 16)
        if atom.isdecimal():
            return int(atom)
        fail(f"unsupported Rust SQL dispatch pattern: {atom!r}")

    def split_alternatives(pattern: str) -> list[str]:
        atom = r"(?:b'(?:\\.|[^'\\])*'|0[xX][0-9a-fA-F]+|\d+)"
        alternative_re = re.compile(rf"(?:{atom}\s*\.\.=\s*{atom}|{atom}|_)")
        alternatives: list[str] = []
        position = 0
        while position < len(pattern):
            while position < len(pattern) and pattern[position].isspace():
                position += 1
            if position == len(pattern):
                break
            alternative = alternative_re.match(pattern, position)
            if not alternative:
                fail(f"unsupported Rust SQL dispatch pattern: {pattern!r}")
            alternatives.append(alternative.group(0))
            position = alternative.end()
            while position < len(pattern) and pattern[position].isspace():
                position += 1
            if position < len(pattern):
                if pattern[position] != "|":
                    fail(f"unsupported Rust SQL dispatch pattern: {pattern!r}")
                position += 1
        return alternatives

    for line in match.group(1).splitlines():
        line = line.strip()
        if not line:
            continue
        arm = re.fullmatch(r"(.+?)\s*=>\s*Parser::(\w+)(?:\([^)]*\))?,", line)
        if not arm:
            fail(f"unrecognized libperfusion SQL dispatch arm: {line!r}")
        pattern, parser = arm.groups()
        if parser not in rust_to_go:
            fail(f"no Go parser mapping for libperfusion {parser}")
        go_parser = rust_to_go[parser]
        if pattern == "_":
            values = [value for value, selected in enumerate(mapping) if selected is None]
        else:
            values_list: list[int] = []
            for alternative in split_alternatives(pattern):
                alternative = alternative.strip()
                range_match = re.fullmatch(r"(.+?)\s*\.\.=\s*(.+)", alternative)
                if range_match:
                    start = value_of(range_match.group(1))
                    end = value_of(range_match.group(2))
                    values_list.extend(range(start, end + 1))
                else:
                    values_list.append(value_of(alternative))
            values = values_list
        for value in values:
            if not 0 <= value < 256:
                fail(f"invalid Rust byte dispatch value {value}")
            # Rust match arms are ordered; the broad word range follows the
            # special B/E/N/Q/U/X string-prefix arms.
            if mapping[value] is None:
                mapping[value] = go_parser
    if any(value is None for value in mapping):
        fail("libperfusion SQL dispatch does not cover all 256 bytes")
    return [str(value) for value in mapping]


def go_table_entries(source: Path, var_name: str, type_name: str | None = None) -> list[tuple[str, str | None]]:
    text = (source / "xss_decls.go").read_text(encoding="utf-8")
    type_suffix = r"\[\]stringType" if type_name else r"\[\]string"
    match = re.search(rf"var {var_name} = {type_suffix}\s*\{{(.*?)\n\}}", text, re.S)
    if not match:
        fail(f"could not find pinned Go {var_name} table")
    if type_name:
        rows = re.findall(r'\{"([^"]+)",\s*(\w+)\}', match.group(1))
        return [(name, kind) for name, kind in rows]
    return [(name, None) for name in re.findall(r'"([^"]+)"', match.group(1))]


def rust_xss_tables() -> tuple[list[str], list[str], list[tuple[str, str]]]:
    events: list[str] = []
    tags: list[str] = []
    attrs: list[tuple[str, str]] = []
    for line in (ROOT / "data/xss_tables.txt").read_text(encoding="ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        match fields:
            case ["event", name]:
                events.append(name)
            case ["tag", name]:
                tags.append(name)
            case ["attr", name, kind] if kind in RUST_XSS_KIND:
                attrs.append((name, RUST_XSS_KIND[kind]))
            case _:
                fail(f"invalid libperfusion XSS table row: {line!r}")
    return events, tags, attrs


def parse_local_xss_rows() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    path = ROOT / "data/xss_tables_local.txt"
    for line_number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        match fields:
            case ["event" | "tag", name] if name:
                rows.append((fields[0], name))
            case ["attr", name, kind] if name and kind in LOCAL_RUST_XSS_KINDS:
                rows.append(("attr", name))
            case _:
                fail(f"invalid local XSS table row at {path}:{line_number}: {line!r}")
    return rows


def check_local_supplements() -> None:
    """Verify the local additions only ever extend the upstream tables.

    The upstream records (``sql``/``xss`` in ``data/tables.json`` and the
    Go source comparison) describe upstream alone, so a local row that repeats
    or redefines an upstream row would change the compiled tables while leaving
    every recorded hash intact. ``build.rs`` rejects such a merge at compile
    time; this repeats the check here so the parity gate reports it as a
    provenance problem rather than as a build failure.
    """
    upstream_keywords = parse_rust_keywords(ROOT / "data/sqli_keywords.txt")
    local_keywords = parse_rust_keywords(ROOT / "data/sqli_keywords_local.txt")
    collisions = sorted(set(local_keywords) & set(upstream_keywords))[:5]
    if collisions:
        fail(f"data/sqli_keywords_local.txt redefines upstream SQL keywords: {collisions}")

    upstream_events, upstream_tags, upstream_attrs = rust_xss_tables()
    upstream_xss = (
        {("event", name) for name in upstream_events}
        | {("tag", name) for name in upstream_tags}
        | {("attr", name) for name, _ in upstream_attrs}
    )
    local_xss = parse_local_xss_rows()
    duplicates = sorted({row for row in local_xss if local_xss.count(row) > 1})[:5]
    if duplicates:
        fail(f"data/xss_tables_local.txt repeats rows: {duplicates}")
    overlaps = sorted(set(local_xss) & upstream_xss)[:5]
    if overlaps:
        fail(f"data/xss_tables_local.txt redefines upstream XSS rows: {overlaps}")


def compare_data(source: Path) -> dict[str, str]:
    go_keywords = parse_go_keywords(source)
    rust_keywords = parse_rust_keywords(ROOT / "data/sqli_keywords.txt")
    if go_keywords != rust_keywords:
        missing = sorted(set(go_keywords) - set(rust_keywords))[:5]
        extra = sorted(set(rust_keywords) - set(go_keywords))[:5]
        mismatched = sorted(k for k in set(go_keywords) & set(rust_keywords) if go_keywords[k] != rust_keywords[k])[:5]
        fail(f"SQL keyword table differs: missing={missing}, extra={extra}, mismatched={mismatched}")
    if len(go_keywords) != EXPECTED_KEYWORDS:
        fail(f"expected {EXPECTED_KEYWORDS} SQL table entries, found {len(go_keywords)}")
    fingerprints = sum(value == "F" for value in go_keywords.values())
    if fingerprints != EXPECTED_FINGERPRINTS:
        fail(f"expected {EXPECTED_FINGERPRINTS} fingerprints, found {fingerprints}")

    go_dispatch = parse_go_dispatch(source)
    rust_dispatch = parse_rust_dispatch()
    if go_dispatch != rust_dispatch:
        differences = [f"{byte:#04x}: Go {go_dispatch[byte]}, Rust {rust_dispatch[byte]}" for byte in range(256) if go_dispatch[byte] != rust_dispatch[byte]]
        fail("SQL byte dispatch differs: " + "; ".join(differences[:8]))

    go_tags = go_table_entries(source, "blackTags")
    go_events = go_table_entries(source, "blackEvents", "stringType")
    go_attrs = go_table_entries(source, "blacks", "stringType")
    mapped_go_attrs = [(name, GO_KIND_TO_RUST.get(kind, f"unknown:{kind}")) for name, kind in go_attrs]
    rust_event_names, rust_tag_names, rust_attrs = rust_xss_tables()
    rust_tags = [(name, None) for name in rust_tag_names]
    rust_events = [(name, "attributeTypeBlack") for name in rust_event_names]
    if sorted(go_tags) != sorted(rust_tags):
        fail("XSS tag table differs from pinned Go source")
    if sorted(go_events) != sorted(rust_events):
        fail("XSS event names/classifications differ from pinned Go source")
    if sorted(mapped_go_attrs) != sorted(rust_attrs):
        fail("XSS named attribute names/classifications differ from pinned Go source")
    actual_xss = {"tags": len(go_tags), "events": len(go_events), "attributes": len(go_attrs)}
    if actual_xss != EXPECTED_XSS:
        fail(f"unexpected XSS table counts: {actual_xss}")

    source_names = [
        "sqli_data.go",
        "sqli_parse.go",
        "sqli_token.go",
        "sqli.go",
        "xss_decls.go",
        "xss_helpers.go",
        "html5.go",
        "xss.go",
        "LICENSE",
    ]
    hashes = {name: sha256((source / name).read_bytes()) for name in source_names}
    copied_license = ROOT / "LICENSES/libinjection-go-BSD-3-Clause.txt"
    if copied_license.read_bytes() != (source / "LICENSE").read_bytes():
        fail("copied libinjection-go license differs from the pinned upstream LICENSE")
    return hashes


def check_c_reference() -> None:
    """The C revision CI fetches is the one ``data/tables.json`` was refreshed from."""
    source = json.loads(TABLES.read_text(encoding="utf-8")).get("source")
    recorded = (source.get("repository"), source.get("commit")) if isinstance(source, dict) else None
    if recorded != (C_REFERENCE["repository"], C_REFERENCE["commit"]):
        fail(
            f"C_REFERENCE in check_manifest.py names {C_REFERENCE['commit']}, but data/tables.json "
            f"records {recorded}; after a C revision bump update C_REFERENCE, then rerun --update --go-source"
        )


def module_pin() -> tuple[str, str]:
    """The Go module pin ``cargo xtask corpus-check`` verifies against go.mod and go.sum."""
    source = json.loads(MANIFEST.read_text(encoding="utf-8")).get("source")
    version = source.get("version") if isinstance(source, dict) else None
    module_sum = source.get("module_sum") if isinstance(source, dict) else None
    if not isinstance(version, str) or not isinstance(module_sum, str) or not version or not module_sum:
        fail(f"{MANIFEST.relative_to(ROOT)} records no Go module pin; run cargo xtask corpus-refresh")
    return version, module_sum


def pinned_source(path_text: str | None) -> Path | None:
    if not path_text:
        return None
    source = Path(path_text).resolve()
    result = subprocess.run(
        ["go", "list", "-m", "-json", GO_MODULE],
        cwd=GO_TOOLS,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail(f"could not resolve {GO_MODULE} from {GO_TOOLS / 'go.mod'}: {result.stderr.strip()}")
    metadata = json.loads(result.stdout)
    version, module_sum = module_pin()
    if metadata.get("Version") != version or metadata.get("Sum") != module_sum:
        fail(f"resolved Go module differs from the pin in {MANIFEST.relative_to(ROOT)}; run cargo xtask corpus-refresh")
    if Path(metadata.get("Dir", "")).resolve() != source:
        fail(f"Go source must be the module selected by xtask/tools/go.mod: {source}")
    return source


def expected_differential(source: Path | None) -> dict[str, object]:
    # Runs on both paths: the upstream-versus-source comparison below stays
    # exact, and this is what keeps the local supplements from quietly
    # changing what those exact tables describe.
    check_local_supplements()
    check_c_reference()
    version, module_sum = module_pin()
    # Offline, this hash is the only tie between the compiled dispatch and the
    # last --go-source comparison; the table rows are pinned by data/tables.json.
    dispatch = parse_rust_dispatch()

    data_hashes: dict[str, str] = {}
    if source is not None:
        compare_fixtures(source)
        data_hashes = compare_data(source)
        local_bsd_hash = sha256((ROOT / "LICENSES/libinjection-go-BSD-3-Clause.txt").read_bytes())
        if data_hashes.get("LICENSE") != local_bsd_hash:
            fail("crate-local BSD license text differs from the pinned Go source LICENSE")

    return {
        "schema": 1,
        "oracle": {
            "repository": GO_REPOSITORY,
            # Offline, the only tie between the source hashes below and the
            # module pin corpus-check verifies; a bump fails until --update.
            "version": version,
            "module_sum": module_sum,
            "go_toolchain_flavors": [
                {"version": "go1.27.x", "minimum_patch": 1, "go_experiment": ""},
                {
                    "version": "go1.27.x-X:nodwarf5",
                    "minimum_patch": 1,
                    "go_experiment": "nodwarf5",
                },
            ],
            "goos": "linux",
            "goarch": "amd64",
            "driver": "tools/parity/oracle_driver_test.go",
            "transport": "tab-separated case id and hex input; binary outputs are hex fields",
        },
        "c_reference": C_REFERENCE,
        "sql_dispatch": {"bytes": len(dispatch), "sha256": sha256("\n".join(dispatch).encode("ascii"))},
        "source_sha256": data_hashes,
        "exceptions": [],
        "expected_oracle_errors": EXPECTED_ORACLE_ERRORS,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-source", help="module cache path selected by xtask/tools/go.mod")
    parser.add_argument("--update", action="store_true", help="write tests/parity/differential.json from the selected module")
    parser.add_argument("--extract-keywords", action="store_true", help="recreate the checked-in SQL keyword table from the selected module")
    args = parser.parse_args()

    source = pinned_source(args.go_source)
    if args.extract_keywords:
        if source is None:
            fail("--extract-keywords requires --go-source")
        extract_keywords(source, module_pin()[0])
        if not args.update:
            print("extracted data/sqli_keywords.txt from the selected module")
            return
    current = expected_differential(source)
    if args.update:
        # Without the module source the Go hashes would be dropped, not refreshed.
        if source is None:
            fail("--update requires --go-source")
        DIFFERENTIAL.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        print(f"updated {DIFFERENTIAL.relative_to(ROOT)}")
        return

    recorded = json.loads(DIFFERENTIAL.read_text(encoding="utf-8"))
    if not isinstance(recorded, dict):
        fail(f"{DIFFERENTIAL.relative_to(ROOT)} is not a JSON object")
    if source is None:
        recorded_hashes = recorded.get("source_sha256")
        if not isinstance(recorded_hashes, dict):
            fail("source hashes are missing from the differential metadata")
        local_bsd_hash = sha256((ROOT / "LICENSES/libinjection-go-BSD-3-Clause.txt").read_bytes())
        if recorded_hashes.get("LICENSE") != local_bsd_hash:
            fail("crate-local BSD license text differs from the pinned differential metadata")
        current["source_sha256"] = recorded_hashes
    if current != recorded:
        print("parity differential mismatch; rerun with --update only after reviewing source/data changes", file=sys.stderr)
        raise SystemExit(1)
    print(f"parity differential verified: {DIFFERENTIAL.relative_to(ROOT)} matches the C pin, SQL dispatch and source hashes")


if __name__ == "__main__":
    main()
