#!/usr/bin/env python3
"""Check the pinned libinjection provenance, data tables, and corpus inventory."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tests/parity/manifest.json"
PIN = "f6c336efc0ddac2597fd27d3b1b7db9c87613e8d"
GO_REPOSITORY = "https://github.com/corazawaf/libinjection-go"
FAMILY_COUNTS = {"sqli": 54, "folding": 118, "tokens": 249, "html5": 68, "xss": 7}
EXPECTED_KEYWORDS = 9_352
EXPECTED_FINGERPRINTS = 8_367
EXPECTED_XSS = {"tags": 20, "events": 432, "attributes": 20}
EXPECTED_ORACLE_ERRORS: list[dict[str, object]] = []
GO_KIND_TO_RUST = {
    "attributeTypeBlack": "Deny",
    "attributeTypeAttrURL": "Url",
    "attributeTypeStyle": "Style",
    "attributeTypeAttrIndirect": "Indirect",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fail(message: str) -> None:
    raise SystemExit(message)


def fixture_inventory() -> tuple[dict[str, int], list[dict[str, object]]]:
    counts = dict.fromkeys(FAMILY_COUNTS, 0)
    files: list[dict[str, object]] = []
    for path in sorted((ROOT / "tests/corpus").glob("test-*.txt")):
        match = re.match(r"test-(sqli|folding|tokens|html5|xss)-", path.name)
        if not match:
            fail(f"unrecognized fixture family: {path.name}")
        family = match.group(1)
        counts[family] += 1
        data = path.read_bytes()
        files.append({"name": path.name, "size": len(data), "sha256": sha256(data)})
    return counts, files


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


def extract_keywords(source: Path) -> None:
    entries = parse_go_keywords(source)
    if len(entries) != EXPECTED_KEYWORDS:
        fail(f"expected {EXPECTED_KEYWORDS} upstream SQL entries, found {len(entries)}")
    if any(not value.isascii() for value in entries.values()):
        fail("the pinned SQL keyword table contains a non-ASCII value")
    output = [
        "# Auto-extracted from libinjection-go v0.3.3 sqli_data.go",
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
    text = (ROOT / "src/sqli/legacy/parse.rs").read_text(encoding="utf-8")
    match = re.search(r"pub\(crate\) fn dispatch\(.*?match ch \{(.*?)\n    \}\n\}", text, re.S)
    if not match:
        fail("could not find Rust SQL dispatch match")
    rust_to_go = {
        "parse_white": "parseWhite",
        "parse_operator1": "parseOperator1",
        "parse_operator2": "parseOperator2",
        "parse_string": "parseString",
        "parse_hash": "parseHash",
        "parse_money": "parseMoney",
        "parse_byte": "parseByte",
        "parse_dash": "parseDash",
        "parse_number": "parseNumber",
        "parse_slash": "parseSlash",
        "parse_other": "parseOther",
        "parse_var": "parseVar",
        "parse_bstring": "parseBString",
        "parse_estring": "parseEString",
        "parse_nqstring": "parseNqString",
        "parse_qstring": "parseQString",
        "parse_ustring": "parseUString",
        "parse_xstring": "parseXString",
        "parse_bword": "parseBWord",
        "parse_backslash": "parseBackSlash",
        "parse_tick": "parseTick",
        "parse_word": "parseWord",
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
        if atom.isdecimal():
            return int(atom)
        fail(f"unsupported Rust SQL dispatch pattern: {atom!r}")

    def split_alternatives(pattern: str) -> list[str]:
        atom = r"(?:b'(?:\\.|[^'\\])*'|\d+)"
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
        arm = re.fullmatch(r"(.+?)\s*=>\s*(parse_\w+)\(s\),", line)
        if not arm:
            fail(f"unrecognized Rust SQL dispatch arm: {line!r}")
        pattern, parser = arm.groups()
        if parser not in rust_to_go:
            fail(f"no Go parser mapping for Rust {parser}")
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
            if not 0 <= value < 256 or mapping[value] is not None:
                fail(f"invalid/duplicate Rust byte dispatch value {value}")
            mapping[value] = go_parser
    if any(value is None for value in mapping):
        fail("Rust SQL dispatch does not cover all 256 bytes")
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


def rust_table_entries(source_path: Path, constant: str, typed: bool = False) -> list[tuple[str, str | None]]:
    text = source_path.read_text(encoding="utf-8")
    match = re.search(rf"const {constant}:.*?=\s*&\[(.*?)\n\];", text, re.S)
    if not match:
        fail(f"could not find Rust {constant} table")
    if typed:
        return re.findall(r'\(b"([^"]+)",\s*DenyAttrKind::(\w+)\)', match.group(1))
    return [(name, None) for name in re.findall(r'b"([^"]+)"', match.group(1))]


def semantic_table_hash(rows: list[tuple[str, str | None]]) -> str:
    normalized = [name if kind is None else f"{name}\t{kind}" for name, kind in rows]
    return sha256("\n".join(sorted(normalized)).encode("ascii"))


def local_table_summary() -> dict[str, object]:
    rust_dispatch = parse_rust_dispatch()
    rust_xss_source = ROOT / "src/xss/legacy/deny_list.rs"
    tags = rust_table_entries(rust_xss_source, "DENY_TAGS")
    events = [(name, "Deny") for name, _ in rust_table_entries(rust_xss_source, "DENY_EVENTS")]
    attrs = rust_table_entries(rust_xss_source, "DENY_ATTRS", typed=True)
    counts = {"tags": len(tags), "events": len(events), "attributes": len(attrs)}
    if counts != EXPECTED_XSS:
        fail(f"unexpected Rust XSS table counts: {counts}")
    return {
        "sql_keyword_entries": EXPECTED_KEYWORDS,
        "sql_fingerprint_entries": EXPECTED_FINGERPRINTS,
        "sql_dispatch_bytes": len(rust_dispatch),
        "sql_dispatch_sha256": sha256("\n".join(rust_dispatch).encode("ascii")),
        "xss_tables": counts,
        "xss_table_sha256": {
            "tags": semantic_table_hash(tags),
            "events": semantic_table_hash(events),
            "attributes": semantic_table_hash(attrs),
        },
    }


def compare_data(source: Path) -> tuple[dict[str, object], dict[str, str]]:
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

    xss_source = source / "xss_decls.go"
    rust_xss_source = ROOT / "src/xss/legacy/deny_list.rs"
    go_tags = go_table_entries(source, "blackTags")
    rust_tags = rust_table_entries(rust_xss_source, "DENY_TAGS")
    go_events = go_table_entries(source, "blackEvents", "stringType")
    rust_events = [(name, "attributeTypeBlack") for name, _ in rust_table_entries(rust_xss_source, "DENY_EVENTS")]
    go_attrs = go_table_entries(source, "blacks", "stringType")
    mapped_go_attrs = [(name, GO_KIND_TO_RUST.get(kind, f"unknown:{kind}")) for name, kind in go_attrs]
    rust_attrs = rust_table_entries(rust_xss_source, "DENY_ATTRS", typed=True)
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
    summary = {
        "sql_keyword_entries": len(go_keywords),
        "sql_fingerprint_entries": fingerprints,
        "sql_dispatch_bytes": len(go_dispatch),
        "sql_dispatch_sha256": sha256("\n".join(go_dispatch).encode("ascii")),
        "xss_tables": actual_xss,
        "xss_table_sha256": {
            "tags": semantic_table_hash(go_tags),
            "events": semantic_table_hash([(name, "Deny") for name, _ in go_events]),
            "attributes": semantic_table_hash(mapped_go_attrs),
        },
    }
    return summary, hashes


def pinned_source(path_text: str | None) -> Path | None:
    if path_text:
        source = Path(path_text).resolve()
    elif os.environ.get("LIBINJECTION_GO_SOURCE"):
        source = Path(os.environ["LIBINJECTION_GO_SOURCE"]).resolve()
    else:
        return None
    revision = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    if revision.returncode != 0 or revision.stdout.strip() != PIN:
        fail(f"Go source checkout must be at {PIN}: {source}")
    return source


def expected_manifest(source: Path | None) -> dict[str, object]:
    counts, files = fixture_inventory()
    if counts != FAMILY_COUNTS:
        fail(f"fixture family counts differ: expected {FAMILY_COUNTS}, found {counts}")
    if len(files) != 496:
        fail(f"expected 496 test fixtures, found {len(files)}")

    if source is None:
        data_hashes = {"data/sqli_keywords.txt": sha256((ROOT / "data/sqli_keywords.txt").read_bytes())}
        table_summary: dict[str, object] | None = local_table_summary()
    else:
        compare_fixtures(source)
        table_summary, upstream_hashes = compare_data(source)
        data_hashes = {**upstream_hashes, "data/sqli_keywords.txt": sha256((ROOT / "data/sqli_keywords.txt").read_bytes())}
        local_bsd_hash = sha256((ROOT / "LICENSES/libinjection-go-BSD-3-Clause.txt").read_bytes())
        if upstream_hashes.get("LICENSE") != local_bsd_hash:
            fail("crate-local BSD license text differs from the pinned Go source LICENSE")

    return {
        "schema": 1,
        "oracle": {
            "repository": GO_REPOSITORY,
            "revision": PIN,
            "go_toolchain_flavors": [
                {"version": "go1.27.1", "go_experiment": ""},
                {"version": "go1.27.1-X:nodwarf5", "go_experiment": "nodwarf5"},
            ],
            "goos": "linux",
            "goarch": "amd64",
            "driver": "tools/parity/oracle_driver_test.go",
            "transport": "tab-separated case id and hex input; binary outputs are hex fields",
        },
        "tables": table_summary,
        "source_sha256": data_hashes,
        "fixtures": {"total": len(files), "families": counts, "files": files},
        "exceptions": [],
        "expected_oracle_errors": EXPECTED_ORACLE_ERRORS,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-source", help="pinned libinjection-go checkout (may also use LIBINJECTION_GO_SOURCE)")
    parser.add_argument("--update", action="store_true", help="write manifest from current pinned source and corpus")
    parser.add_argument("--extract-keywords", action="store_true", help="recreate the checked-in SQL keyword table from pinned Go source")
    args = parser.parse_args()

    source = pinned_source(args.go_source)
    if args.extract_keywords:
        if source is None:
            fail("--extract-keywords requires --go-source or LIBINJECTION_GO_SOURCE")
        extract_keywords(source)
    current = expected_manifest(source)
    if args.update:
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"updated {MANIFEST.relative_to(ROOT)}")
        return

    recorded = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if source is None:
        if recorded["source_sha256"].get("data/sqli_keywords.txt") != current["source_sha256"].get("data/sqli_keywords.txt"):
            fail("SQL keyword source hash differs from the pinned manifest")
        local_bsd_hash = sha256((ROOT / "LICENSES/libinjection-go-BSD-3-Clause.txt").read_bytes())
        if recorded["source_sha256"].get("LICENSE") != local_bsd_hash:
            fail("crate-local BSD license text differs from the pinned manifest")
        current["source_sha256"] = recorded["source_sha256"]
    if current != recorded:
        print("parity manifest mismatch; rerun with --update only after reviewing source/data changes", file=sys.stderr)
        raise SystemExit(1)
    print("parity manifest verified: 496 fixtures and recorded source/table hashes")


if __name__ == "__main__":
    main()
