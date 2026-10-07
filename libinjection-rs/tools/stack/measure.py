#!/usr/bin/env python3
"""Build optimized probes and report detector stack frames and call paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import struct


ROOT = Path(__file__).resolve().parents[2]
PROBE = Path(__file__).resolve().parent
TARGETS = ("x86_64-unknown-linux-gnu", "wasm32-wasip1")
PROFILES = {
    "minimal": ("--no-default-features",),
    "legacy": ("--no-default-features", "--features", "legacy"),
}
ANALYSIS_ENTRIES = (
    "libinjection::analyze_sqli",
    "libinjection::analyze_xss",
)
DETECTOR_ENTRIES = (
    "libinjection::detect_sqli",
    "libinjection::detect_xss",
)
LIMIT = 4096
REPORT_PROGRESS: dict[str, object] | None = None
REPORT_OUTPUT: Path | None = None


def budget_status(stack_bytes_upper_bound: int | None, limit: int = LIMIT) -> str:
    """Describe the optional budget result without treating an open bound as zero."""
    if stack_bytes_upper_bound is None:
        return "open"
    return "within_limit" if stack_bytes_upper_bound <= limit else "over_limit"


def build_budget_status(
    rows: list[dict[str, object]], proof_bindings_complete: bool
) -> str:
    statuses = [str(row.get("budget_status", "open")) for row in rows]
    if not proof_bindings_complete or any(status == "open" for status in statuses):
        return "open"
    if any(status == "over_limit" for status in statuses):
        return "over_limit"
    return "within_limit"


def strict_budget_exit_code(builds: list[dict[str, object]], strict_budget: bool) -> int:
    """Return nonzero for an open or over-budget result only in explicit strict mode."""
    return int(strict_budget and not all(bool(build.get("passed")) for build in builds))


def run(argv: list[str], *, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(argv, check=True, text=True, capture_output=True, env=env)
    return result.stdout


def version(argv: list[str]) -> str:
    return run(argv).strip().splitlines()[0]


def elf_relocations(readobj_output: str) -> dict[int, dict[str, object]]:
    relocations: dict[int, dict[str, object]] = {}
    for line in readobj_output.splitlines():
        match = re.match(
            r"\s*0x([0-9a-fA-F]+)\s+(R_X86_64_[A-Z0-9_]+)\s+(\S+)\s+0x([0-9a-fA-F]+)",
            line,
        )
        if match is None:
            continue
        address, kind, symbol, addend = match.groups()
        relocations[int(address, 16)] = {
            "kind": kind,
            "symbol": symbol,
            "addend": int(addend, 16),
        }
    return relocations


def elf_data_at_vaddr(binary: bytes, address: int, length: int) -> bytes | None:
    if binary[:4] != b"\x7fELF" or binary[4] != 2 or binary[5] != 1:
        return None
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", binary, 0)
    program_header_offset = header[5]
    program_header_size = header[9]
    program_header_count = header[10]
    for index in range(program_header_count):
        offset = program_header_offset + index * program_header_size
        kind, flags, file_offset, virtual_address, _, file_size, _, _ = struct.unpack_from("<IIQQQQQQ", binary, offset)
        if kind != 1 or not (flags & 4) or flags & 1:
            continue
        if virtual_address <= address and address + length <= virtual_address + file_size:
            start = file_offset + address - virtual_address
            return binary[start : start + length]
    return None


def elf_instruction_rows(block: dict[str, object]) -> list[dict[str, object]]:
    rows = []
    for line in block["lines"]:
        decoded = re.match(
            r"\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)\s*([a-z][a-z0-9.]*)\s*(.*?)\s*$",
            line,
        )
        if decoded is None:
            continue
        address, encoded, mnemonic, operands = decoded.groups()
        rows.append(
            {
                "address": int(address, 16),
                "bytes": bytes.fromhex(encoded),
                "mnemonic": mnemonic,
                "operands": operands.split("#", 1)[0].strip(),
                "line": line,
            }
        )
    return rows


def elf_reg(name: str) -> str:
    register = name.strip().lstrip("%")
    aliases = {
        "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
        "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
        "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
        "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
        "esi": "rsi", "si": "rsi", "sil": "rsi",
        "edi": "rdi", "di": "rdi", "dil": "rdi",
        "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
        "esp": "rsp", "sp": "rsp", "spl": "rsp",
    }
    if register in aliases:
        return aliases[register]
    match = re.fullmatch(r"r(\d+)(?:d|w|b)?", register)
    return f"r{match.group(1)}" if match else register


def elf_relative_destination(instruction: dict[str, object]) -> int | None:
    machine = instruction["bytes"]
    if not machine:
        return None
    mnemonic = str(instruction["mnemonic"])
    operands = str(instruction["operands"])
    offset: int | None = None
    if mnemonic.startswith("call") and machine[0] == 0xE8 and len(machine) >= 5:
        offset = int.from_bytes(machine[1:5], "little", signed=True)
    elif mnemonic.startswith("jmp") and machine[0] == 0xE9 and len(machine) >= 5:
        offset = int.from_bytes(machine[1:5], "little", signed=True)
    elif mnemonic.startswith("jmp") and machine[0] == 0xEB and len(machine) >= 2:
        offset = int.from_bytes(machine[1:2], "little", signed=True)
    elif mnemonic.startswith("j") and machine[0] in range(0x70, 0x80) and len(machine) >= 2:
        offset = int.from_bytes(machine[1:2], "little", signed=True)
    elif mnemonic.startswith("j") and len(machine) >= 6 and machine[:1] == b"\x0f" and machine[1] in range(0x80, 0x90):
        offset = int.from_bytes(machine[2:6], "little", signed=True)
    elif mnemonic.startswith("loop") and machine[0] in range(0xE0, 0xE4) and len(machine) >= 2:
        offset = int.from_bytes(machine[1:2], "little", signed=True)
    if offset is None:
        return None
    return int(instruction["address"]) + len(machine) + offset


def local_jump_table_proof(
    block: dict[str, object], call: dict[str, object], binary: bytes
) -> dict[str, object] | None:
    """Prove one x86 indexed relative jump table stays inside this function."""
    rows = elf_instruction_rows(block)
    addresses = {int(row["address"]): index for index, row in enumerate(rows)}
    jump_index = addresses.get(int(call["address"]))
    operands = str(call["operands"])
    target_match = re.fullmatch(r"\*%([a-z0-9]+)", operands)
    if jump_index is None or target_match is None or jump_index < 2:
        return None
    target_register = elf_reg(target_match.group(1))
    jump = rows[jump_index]
    add = rows[jump_index - 1]
    load = rows[jump_index - 2]
    add_operands = [part.strip() for part in str(add["operands"]).split(",")]
    if (
        not str(add["mnemonic"]).startswith("add")
        or len(add_operands) != 2
        or elf_reg(add_operands[1]) != target_register
    ):
        return None
    load_match = re.fullmatch(
        r"(-?(?:0x[0-9a-fA-F]+|\d+))?\((%[a-z0-9]+),\s*(%[a-z0-9]+),\s*4\),\s*(%[a-z0-9]+)",
        str(load["operands"]),
    )
    if not str(load["mnemonic"]).startswith("movsl") or load_match is None:
        return None
    displacement_text, base_text, index_text, result_text = load_match.groups()
    base_register = elf_reg(base_text)
    index_register = elf_reg(index_text)
    if elf_reg(result_text) != target_register or elf_reg(add_operands[0]) != base_register:
        return None

    # Identify the unique most recent RIP-relative LEA defining the base.
    base_address = None
    lea_index = None
    for index in range(jump_index - 3, -1, -1):
        row = rows[index]
        row_operands = str(row["operands"])
        destination = row_operands.rsplit(",", 1)[-1].strip()
        if destination.startswith("%") and elf_reg(destination) == base_register:
            lea = re.fullmatch(r"(-?(?:0x[0-9a-fA-F]+|\d+))\(%rip\),\s*(%[a-z0-9]+)", row_operands)
            if not str(row["mnemonic"]).startswith("lea") or lea is None:
                return None
            displacement = int(lea.group(1), 0)
            base_address = int(row["address"]) + len(row["bytes"]) + displacement
            lea_index = index
            break
    if base_address is None or lea_index is None:
        return None
    for row in rows[lea_index + 1 : jump_index - 2]:
        destination = str(row["operands"]).rsplit(",", 1)[-1].strip()
        if destination.startswith("%") and elf_reg(destination) == base_register:
            return None

    # A prior unsigned bound check must dominate the indexed load and leave
    # the valid case on the fall-through edge.
    bound = None
    for compare_index in range(jump_index - 3):
        compare = rows[compare_index]
        if not str(compare["mnemonic"]).startswith("cmp"):
            continue
        compare_operands = [part.strip() for part in str(compare["operands"]).split(",")]
        if len(compare_operands) != 2 or not compare_operands[0].startswith("$"):
            continue
        if elf_reg(compare_operands[1]) != index_register:
            continue
        try:
            compared = int(compare_operands[0][1:], 0)
        except ValueError:
            continue
        for guard_index in range(compare_index + 1, jump_index - 1):
            guard = rows[guard_index]
            condition = str(guard["mnemonic"])
            if condition not in ("ja", "jae"):
                continue
            # For this proof the checked branch must immediately precede the
            # table load. That excludes intervening writes and control-flow
            # edges which would break dominance of the unsigned bounds check.
            if guard_index + 1 != jump_index - 2:
                continue
            guard_destination = elf_relative_destination(guard)
            if condition == "ja":
                entry_count = compared + 1
            else:
                entry_count = compared
            if 0 < entry_count <= 4096:
                bound = {
                    "compare_address": int(compare["address"]),
                    "guard_address": int(guard["address"]),
                    "guard": condition,
                    "compared_unsigned_index": compared,
                    "entry_count": entry_count,
                    "guard_target_address": guard_destination,
                }
                break
        if bound is not None:
            break
    if bound is None:
        return None

    table_bytes = elf_data_at_vaddr(binary, base_address, int(bound["entry_count"]) * 4)
    if table_bytes is None:
        return None
    destinations = [
        base_address + int.from_bytes(table_bytes[offset : offset + 4], "little", signed=True)
        for offset in range(0, len(table_bytes), 4)
    ]
    local_instructions = set(block.get("instruction_addresses", []))
    if not destinations or any(address not in local_instructions for address in destinations):
        return None
    return {
        "call_site_address": int(call["address"]),
        "table_base_address": base_address,
        "index_register": index_register,
        "target_register": target_register,
        "bounds_check": bound,
        "entry_target_addresses": destinations,
        "method": "decoded signed-relative table entries are all instruction starts in this function; unsigned compare/branch bounds-check the index",
    }


def elf_blocks(
    disassembly: str,
    relocations: dict[int, dict[str, object]],
    binary: bytes = b"",
) -> dict[str, dict[str, object]]:
    blocks: dict[str, dict[str, object]] = {}
    current: dict[str, object] | None = None
    decoded_calls: list[tuple[dict[str, object], dict[str, object]]] = []
    for line in disassembly.splitlines():
        heading = re.match(r"^([0-9a-fA-F]+) <(.+)>:$", line)
        if heading:
            symbol = heading.group(2)
            address = int(heading.group(1), 16)
            name = symbol if symbol not in blocks else f"{symbol}@0x{address:x}"
            current = {
                "name": name,
                "symbol": symbol,
                "address": address,
                "lines": [],
                "calls": [],
                "instruction_addresses": [],
            }
            blocks[name] = current
            continue
        if current is None:
            continue
        current["lines"].append(line)

        decoded = re.match(
            r"\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)\s*([^\n]+)$", line
        )
        if decoded is None:
            continue
        address_text, byte_text, assembly = decoded.groups()
        current["instruction_addresses"].append(int(address_text, 16))
        instruction = re.search(r"\b(callq?|jmpq?)\s+(.+)$", assembly)
        if instruction is None:
            continue
        operation, operands = instruction.groups()
        indirect = operands.lstrip().startswith("*")
        target_match = re.search(r"<(.+)>\s*$", operands)
        target = target_match.group(1) if target_match else None
        if target is not None:
            target = re.sub(r"\+0x[0-9a-fA-F]+$", "", target)
        is_jump = operation.startswith("jmp")
        call = {
            "target": target,
            "indirect": indirect,
            "tail": is_jump,
            "operands": operands.strip(),
            "address": int(address_text, 16),
            "bytes": bytes.fromhex(byte_text),
        }
        call["instruction_bytes_hex"] = call["bytes"].hex()
        current["calls"].append(call)
        decoded_calls.append((current, call))

    # The linker resolves internal function pointers and PLT/GOT slots through
    # dynamic relocations. For a RIP-relative x86-64 call/jump, recover the
    # slot from the emitted instruction bytes, then resolve its relocation.
    starts = sorted(
        (int(block["address"]), name)
        for name, block in blocks.items()
    )
    start_addresses: dict[int, str] = {}
    for address, name in starts:
        start_addresses.setdefault(address, name)

    def function_at(address: int) -> str | None:
        # Only exact symbol entries count as function targets. Mapping an
        # arbitrary address to the nearest preceding symbol can hide an
        # unresolved tail call or function-pointer target.
        return start_addresses.get(address)

    def relocation_target(relocation: dict[str, object]) -> str | None:
        if relocation["kind"] == "R_X86_64_RELATIVE":
            return start_addresses.get(int(relocation["addend"]))
        if relocation["kind"] in ("R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"):
            return f"external:{relocation['symbol']}"
        return None

    for block, call in decoded_calls:
        if not call["indirect"]:
            continue
        machine = call["bytes"]
        ff_positions = [index for index, byte in enumerate(machine[:-1]) if byte == 0xFF]
        for index in reversed(ff_positions):
            modrm = machine[index + 1]
            if modrm >> 6 == 0 and modrm & 7 == 5 and len(machine) >= index + 6:
                displacement = int.from_bytes(machine[index + 2 : index + 6], "little", signed=True)
                slot = int(call["address"]) + len(machine) + displacement
                relocation = relocations.get(slot)
                if relocation is None:
                    continue
                if relocation["kind"] == "R_X86_64_RELATIVE":
                    target = function_at(int(relocation["addend"]))
                    if target is not None:
                        call["target"] = target
                        call["indirect"] = False
                        call["resolved_via"] = {
                            "slot": slot,
                            "relocation": relocation["kind"],
                            "target_address": relocation["addend"],
                        }
                elif relocation["kind"] in ("R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"):
                    call["target"] = f"external:{relocation['symbol']}"
                    call["resolved_via"] = {
                        "slot": slot,
                        "relocation": relocation["kind"],
                    }
                break
    def direct_destination(call: dict[str, object]) -> int | None:
        machine = call["bytes"]
        if not machine:
            return None
        if call["tail"] and machine[0] == 0xE9 and len(machine) >= 5:
            offset = int.from_bytes(machine[1:5], "little", signed=True)
        elif call["tail"] and machine[0] == 0xEB and len(machine) >= 2:
            offset = int.from_bytes(machine[1:2], "little", signed=True)
        elif not call["tail"] and machine[0] == 0xE8 and len(machine) >= 5:
            offset = int.from_bytes(machine[1:5], "little", signed=True)
        else:
            return None
        return int(call["address"]) + len(machine) + offset

    # Direct call/jump edges are accepted only when the encoded branch target
    # is an exact function entry or, for a tail branch, an instruction in this
    # function. Symbols and function address ranges alone are not proof.
    for block in blocks.values():
        kept_calls = []
        for call in block["calls"]:
            if call.get("resolved_via") is not None or call["indirect"]:
                kept_calls.append(call)
                continue
            target_address = direct_destination(call)
            local_instructions = set(block.get("instruction_addresses", []))
            if call["tail"] and target_address is not None and target_address in local_instructions:
                block.setdefault("local_controlflow_proofs", []).append(
                    {"address": call["address"], "target_address": target_address, "method": "direct target equals decoded instruction in same function"}
                )
                continue
            if target_address is not None:
                target_name = function_at(target_address)
                if target_name is not None:
                    call["target"] = target_name
                else:
                    call["target"] = None
                kept_calls.append(call)
                continue
            call["target"] = None
            kept_calls.append(call)
        block["calls"] = kept_calls
    for block in blocks.values():
        kept_calls = []
        for call in block["calls"]:
            if call["indirect"] and call["tail"]:
                proof = local_jump_table_proof(block, call, binary)
                if proof is not None:
                    block.setdefault("local_controlflow_proofs", []).append(proof)
                    continue
            kept_calls.append(call)
        block["calls"] = kept_calls
    return blocks


def apply_audited_native_bindings(
    blocks: dict[str, dict[str, object]],
    *,
    profile: str,
    binary_sha256: str,
    code_sha256: str,
    source_sha256: str,
) -> list[dict[str, object]]:
    """Apply binary/address-specific native indirect target sets."""
    proof_path = PROBE / "audited_native_edges.json"
    if not proof_path.exists():
        return []
    document = json.loads(proof_path.read_text())
    if document.get("schema_version") != 1:
        raise RuntimeError("unsupported audited native edge proof schema")
    profiles = document.get("profiles", {})
    profile_record = profiles.get(profile)
    if profile_record is None:
        return []
    if (
        profile_record.get("binary_sha256") != binary_sha256
        or profile_record.get("code_section_sha256") != code_sha256
        or profile_record.get("source_sha256") != source_sha256
    ):
        return [
            {
                "profile": profile,
                "binary_sha256": binary_sha256,
                "code_section_sha256": code_sha256,
                "applied": False,
                "reason": "optimized ELF, .text, or Rust source hash changed",
            }
        ]
    for source in profile_record.get("source_files", []):
        source_path = ROOT / source["path"]
        if not source_path.is_file() or hashlib.sha256(source_path.read_bytes()).hexdigest() != source["sha256"]:
            return [
                {
                    "profile": profile,
                    "binary_sha256": binary_sha256,
                    "code_section_sha256": code_sha256,
                    "applied": False,
                "reason": f"audited source changed or unavailable: {source['path']}",
            }
            ]
    external = profile_record.get("external_sources", {})
    lock_path = ROOT.parent / "Cargo.lock"
    if (
        not lock_path.is_file()
        or hashlib.sha256(lock_path.read_bytes()).hexdigest() != external.get("cargo_lock_sha256")
    ):
        return [{
            "profile": profile,
            "binary_sha256": binary_sha256,
            "code_section_sha256": code_sha256,
            "applied": False,
            "reason": "audited Cargo.lock changed or unavailable",
        }]
    lock_text = lock_path.read_text()
    checksum = re.search(
        r'\[\[package\]\]\s+name = "memchr"\s+version = "2\.8\.3"\s+source = "registry\+https://github\.com/rust-lang/crates\.io-index"\s+checksum = "([0-9a-f]+)"',
        lock_text,
    )
    if checksum is None or checksum.group(1) != external.get("memchr_package_checksum"):
        return [{
            "profile": profile,
            "binary_sha256": binary_sha256,
            "code_section_sha256": code_sha256,
            "applied": False,
            "reason": "audited memchr package checksum changed or unavailable",
        }]
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    for source_name, expected in (
        ("arch_source", external.get("memchr_arch_source_sha256")),
        ("searcher_source", external.get("memchr_searcher_source_sha256")),
    ):
        matches = list((cargo_home / "registry" / "src").glob(
            f"*/memchr-2.8.3/src/{'arch/x86_64/memchr.rs' if source_name == 'arch_source' else 'memmem/searcher.rs'}"
        ))
        if not expected or not any(hashlib.sha256(path.read_bytes()).hexdigest() == expected for path in matches):
            return [{
                "profile": profile,
                "binary_sha256": binary_sha256,
                "code_section_sha256": code_sha256,
                "applied": False,
                "reason": f"audited memchr {source_name} is changed or unavailable",
            }]
    address_to_block = {int(block["address"]): (key, block) for key, block in blocks.items()}
    target_families: dict[str, list[str]] = {}
    for family, records in profile_record.get("target_families", {}).items():
        resolved = []
        for target in records:
            pair = address_to_block.get(int(str(target["address"]), 16))
            if pair is None:
                resolved = []
                break
            key, block = pair
            if block.get("symbol") != target.get("symbol"):
                resolved = []
                break
            resolved.append(key)
        target_families[family] = resolved
    applied: list[dict[str, object]] = []
    for binding in profile_record.get("bindings", []):
        site = int(str(binding["address"]), 16)
        key = {
            "profile": profile,
            "caller": binding["caller"],
            "address": binding["address"],
            "family": binding["family"],
            "binary_sha256": binary_sha256,
            "code_section_sha256": code_sha256,
        }
        matching_blocks = [
            (name, block)
            for name, block in blocks.items()
            if block.get("symbol") == binding["caller"]
            and any(call.get("address") == site for call in block["calls"])
        ]
        if len(matching_blocks) != 1:
            applied.append({**key, "applied": False, "reason": f"expected one caller/site block, found {len(matching_blocks)}"})
            continue
        name, block = matching_blocks[0]
        calls = [call for call in block["calls"] if call.get("address") == site]
        candidates = target_families.get(binding["family"], [])
        if len(calls) != 1 or not candidates:
            applied.append({**key, "applied": False, "reason": "callsite or exact target family is unresolved"})
            continue
        call = calls[0]
        if not call.get("indirect") or call.get("instruction_bytes_hex") != binding.get("instruction_bytes_hex"):
            applied.append({**key, "applied": False, "reason": "call instruction bytes or indirect-call form changed"})
            continue
        call["target_candidates"] = candidates
        call["target_candidates_proven"] = True
        call["audited_proof"] = {
            "proof_id": binding.get("proof_id"),
            "source_method": binding.get("source_method"),
            "caller_symbol": binding["caller"],
            "call_site_address": site,
            "target_family": binding["family"],
            "target_addresses": [int(str(record["address"]), 16) for record in profile_record["target_families"][binding["family"]]],
            "source_files": profile_record.get("source_files", []),
            "binary_sha256": binary_sha256,
            "code_section_sha256": code_sha256,
        }
        applied.append({**key, "applied": True, "target_count": len(candidates), "proof_id": binding.get("proof_id")})
    return applied


def apply_audited_native_local_jump_tables(
    blocks: dict[str, dict[str, object]],
    binary: bytes,
    *,
    profile: str,
    binary_sha256: str,
    code_sha256: str,
    source_sha256: str,
) -> list[dict[str, object]]:
    """Apply reviewer-audited local tables after decoding every emitted entry."""
    proof_path = ROOT / "docs" / "evidence" / "STACK_NATIVE_XSS_PROOFS.json"
    document = json.loads(proof_path.read_text())
    if document.get("source", {}).get("libinjection_tree_sha256") != source_sha256:
        return [{"profile": profile, "applied": False, "reason": "Rust source hash changed"}]
    profile_proof = document.get("profiles", {}).get(profile)
    if profile_proof is not None and (
        profile_proof.get("elf_sha256") != binary_sha256
        or profile_proof.get("text_sha256") != code_sha256
    ):
        return [{"profile": profile, "applied": False, "reason": "optimized ELF or .text hash changed"}]
    records = [
        record
        for record in document.get("local_xss_jump_tables", {}).get(profile, [])
    ]
    results: list[dict[str, object]] = []
    for record in records:
        site = int(record["site"], 16)
        base = int(record["base"], 16)
        count = int(record["count"])
        matches = [
            (name, block, call)
            for name, block in blocks.items()
            for call in block["calls"]
            if call.get("address") == site
            and call.get("indirect")
            and call.get("tail")
            and record["function"].replace("<", "").replace(">", "")
            in str(block.get("symbol")).replace("<", "").replace(">", "").replace("legacy::", "")
        ]
        key = {"profile": profile, "site": site, "base": base, "count": count, "binary_sha256": binary_sha256}
        if len(matches) != 1:
            prior = [
                (block, proof)
                for block in blocks.values()
                for proof in block.get("local_controlflow_proofs", [])
                if proof.get("address") == site
            ]
            if len(matches) == 0 and len(prior) == 1:
                block, proof = prior[0]
                expected = {int(target, 16) for target in record.get("targets", [])}
                proven = {int(target) for target in proof.get("entry_target_addresses", [])}
                if (
                    proof.get("table_base_address") == base
                    and proof.get("entry_count") == count
                    and expected == proven
                ):
                    results.append({**key, "applied": True, "already_proven_by": "emitted-code local table verifier"})
                    continue
            results.append({**key, "applied": False, "reason": f"expected one local jump callsite, found {len(matches)}"})
            continue
        name, block, call = matches[0]
        table = elf_data_at_vaddr(binary, base, count * 4)
        expected = {int(target, 16) for target in record.get("targets", [])}
        if table is None:
            results.append({**key, "applied": False, "reason": "local jump table bytes are not file-backed"})
            continue
        targets = [base + int.from_bytes(table[offset:offset + 4], "little", signed=True) for offset in range(0, len(table), 4)]
        actual = set(targets)
        local_instructions = set(block.get("instruction_addresses", []))
        if (
            not expected
            or actual != expected
            or any(target not in local_instructions for target in targets)
        ):
            results.append({**key, "applied": False, "reason": "decoded table target set differs from review or leaves the caller's instruction stream"})
            continue
        block["calls"].remove(call)
        block.setdefault("local_controlflow_proofs", []).append({
            "address": site,
            "table_base_address": base,
            "entry_count": count,
            "entry_target_addresses": targets,
            "unique_target_count": len(actual),
            "method": record.get("guard", "reviewer-verified source guard") + "; all decoded signed-relative entries match the reviewed set and are instruction starts in this exact function",
            "proof_source": "docs/evidence/STACK_NATIVE_XSS_PROOFS.json",
        })
        results.append({**key, "applied": True, "unique_target_count": len(actual), "decoded_entry_count": len(targets)})
    return results


def apply_audited_native_stack_slots(
    blocks: dict[str, dict[str, object]],
    *,
    profile: str,
    binary_sha256: str,
    code_sha256: str,
    source_sha256: str,
) -> list[dict[str, object]]:
    """Validate exact fixed-buffer indexed RSP accesses against source bounds."""
    proof_path = PROBE / "audited_native_stack_slots.json"
    document = json.loads(proof_path.read_text())
    if document.get("schema_version") != 1:
        raise RuntimeError("unsupported native indexed-stack proof schema")
    profile_record = document.get("profiles", {}).get(profile)
    if profile_record is None:
        return []
    key = {"profile": profile, "binary_sha256": binary_sha256, "code_section_sha256": code_sha256}
    if (
        profile_record.get("binary_sha256") != binary_sha256
        or profile_record.get("code_section_sha256") != code_sha256
        or profile_record.get("source_sha256") != source_sha256
    ):
        return [{**key, "applied": False, "reason": "indexed-stack proof ELF, .text, or source hash changed"}]
    for source in profile_record.get("source_files", []):
        source_path = ROOT / source["path"]
        if not source_path.is_file() or hashlib.sha256(source_path.read_bytes()).hexdigest() != source["sha256"]:
            return [{**key, "applied": False, "reason": f"indexed-stack source changed: {source['path']}"}]
    applied = []
    for record in profile_record.get("sites", []):
        address = int(record["address"], 16)
        matches = []
        for block in blocks.values():
            if block.get("symbol") != record.get("function") or int(block.get("address", -1)) != int(record["function_address"], 16):
                continue
            matches.extend(
                instruction
                for instruction in elf_instruction_rows(block)
                if int(instruction["address"]) == address
                and instruction["bytes"].hex() == record.get("instruction_bytes_hex")
            )
        item_key = {**key, "function": record["function"], "address": address, "proof_id": record["proof_id"]}
        if len(matches) != 1:
            applied.append({**item_key, "applied": False, "reason": f"expected one exact indexed RSP instruction, found {len(matches)}"})
            continue
        instruction = matches[0]
        operands = str(instruction["operands"])
        access = re.search(r"(-(?:0x[0-9a-fA-F]+|\d+))\(%rsp,\s*%([a-z0-9]+)(?:,\s*(\d+))?\)", operands)
        if access is None:
            applied.append({**item_key, "applied": False, "reason": "instruction no longer has the audited indexed RSP operand"})
            continue
        displacement = int(access.group(1), 0)
        register = access.group(2)
        scale = int(access.group(3) or "1")
        index_max = int(record["index_value_max"])
        array_size = int(record["array_size_bytes"])
        width = int(record["access_width_bytes"])
        field_offset = int(record["field_offset_bytes"])
        base_displacement = int(record["base_displacement_bytes"])
        max_end = base_displacement + index_max * scale + field_offset + width
        if (
            displacement != base_displacement + field_offset
            or register != record["index_register"]
            or scale != int(record["index_scale"])
            or index_max < 0
            or width <= 0
            or base_displacement + array_size > 0
            or max_end > base_displacement + array_size
            or int(record["redzone_depth_bytes"]) != -base_displacement
            or -base_displacement > 128
        ):
            applied.append({**item_key, "applied": False, "reason": "indexed access bounds escape the fixed buffer or SysV redzone"})
            continue
        block = next(block for block in blocks.values() if block.get("symbol") == record["function"] and int(block.get("address", -1)) == int(record["function_address"], 16))
        block.setdefault("audited_indexed_stack_slots", {})[address] = {
            **record,
            "source_files": profile_record.get("source_files", []),
            "maximum_access_end_relative_to_rsp": max_end,
        }
        block.setdefault("audited_stack_slot_proofs", []).append({
            "proof_id": record["proof_id"],
            "instruction_address": address,
            "index_max": index_max,
            "array_size_bytes": array_size,
            "maximum_access_end_relative_to_rsp": max_end,
            "method": record["method"],
        })
        applied.append({**item_key, "applied": True, "max_index": index_max, "maximum_access_end_relative_to_rsp": max_end})
    return applied


def native_static_frame_proof(block: dict[str, object]) -> tuple[int | None, str | None]:
    """Bound a prebuilt function only when all stack growth is in its prologue.

    Counting every decrement once is conservative only if none can execute in
    a loop. This deliberately uses the stronger rule that every stack-growth
    instruction precedes every branch and call. It overcounts mutually
    exclusive prologue paths, but cannot count a loop allocation once.
    """
    total = 0
    control_seen = False
    for line in block["lines"]:
        decoded = re.match(
            r"\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)\s*([a-z][a-z0-9.]*)\s*(.*?)\s*$",
            line,
        )
        if decoded is None:
            continue
        _, _, mnemonic, operands = decoded.groups()
        operands = operands.split("#", 1)[0].strip()
        destination = operands.rsplit(",", 1)[-1].strip()
        destination_register = destination.lstrip("%")
        stack_destination = destination_register in ("rsp", "esp", "sp", "spl")
        if destination_register in ("esp", "sp", "spl"):
            return None, f"native stack-pointer alias write is unresolved: {line.strip()}"
        if mnemonic.startswith("xchg") and re.search(r"%(?:rsp|esp|sp|spl)\b", operands):
            return None, f"native exchange involving stack pointer is unresolved: {line.strip()}"
        is_control = (
            mnemonic.startswith(("call", "jmp", "ret", "loop"))
            or re.fullmatch(r"j[a-z]+", mnemonic) is not None
        )

        growth = 0
        if mnemonic.startswith(("push", "pushf")):
            growth = 8
        elif mnemonic.startswith("enter"):
            return None, f"unsupported native ENTER stack allocation: {line.strip()}"
        elif mnemonic.startswith("sub") and stack_destination:
            amount = re.match(r"\$(-?(?:0x[0-9a-fA-F]+|\d+)),", operands)
            if amount is None:
                return None, f"dynamic native RSP decrement: {line.strip()}"
            signed_amount = int(amount.group(1), 0)
            growth = signed_amount if signed_amount > 0 else 0
        elif mnemonic.startswith("add") and stack_destination:
            amount = re.match(r"\$(-?(?:0x[0-9a-fA-F]+|\d+)),", operands)
            if amount is None:
                return None, f"dynamic native RSP adjustment: {line.strip()}"
            signed_amount = int(amount.group(1), 0)
            if signed_amount < 0:
                return None, f"negative-immediate native add to RSP is unresolved: {line.strip()}"
        elif mnemonic.startswith("lea") and stack_destination:
            source = operands.split(",", 1)[0].strip()
            offset = re.match(r"(-?(?:0x[0-9a-fA-F]+|\d+))\(%rsp\)", source)
            if offset is None or int(offset.group(1), 0) >= 0:
                return None, f"unproved native RSP adjustment: {line.strip()}"
            growth = abs(int(offset.group(1), 0))
        elif mnemonic.startswith("and") and stack_destination:
            # The ABI guarantees only 16-byte alignment here. Other masks
            # could discard an unbounded amount of stack and stay unresolved.
            mask = re.match(r"\$(-?(?:0x[0-9a-fA-F]+|\d+)),", operands)
            if mask is None or int(mask.group(1), 0) != -16:
                return None, f"unproved native RSP alignment: {line.strip()}"
            growth = 15
        elif stack_destination and not (
            mnemonic.startswith("add")
            or mnemonic == "leave"
            or (mnemonic.startswith("mov") and operands == "%rbp, %rsp")
        ):
            return None, f"unclassified native RSP write: {line.strip()}"
        elif mnemonic.startswith("pop") and stack_destination:
            return None, f"pop into stack pointer is unresolved: {line.strip()}"

        if growth and control_seen:
            return None, f"stack growth after control flow (possible loop/reentry): {line.strip()}"
        total += growth
        if is_control:
            control_seen = True

    return total, None


def native_frame(block: dict[str, object], stack_sizes: dict[int, int]) -> int | None:
    address = int(block["address"])
    raw = stack_sizes.get(address)
    if raw is not None:
        if raw > 1024 * 1024:
            block["frame_error"] = f"LLVM stack-size sentinel or implausible frame size: {raw}"
            return None
        adjustment_error = native_metadata_stack_write_audit(block)
        if adjustment_error is not None:
            block["frame_error"] = adjustment_error
            block["frame_source"] = "LLVM .stack_sizes present; unclassified or dynamic RSP write"
            return None
        alignment, error = native_alignment_extra(block)
        if error is not None:
            block["frame_error"] = error
            block["frame_source"] = "LLVM .stack_sizes present; stack alignment could not be bounded"
            return None
        redzone, error = native_redzone_extra(block, raw + alignment)
        if error is not None:
            block["frame_error"] = error
            block["frame_source"] = "LLVM .stack_sizes present; stack access could not be bounded"
            return None
        block["frame_source"] = "LLVM .stack_sizes fixed-frame record plus SysV leaf redzone allowance"
        block["raw_stack_size_bytes"] = raw
        block["emitted_frame_bytes"] = raw
        block["alignment_adjustment_bytes"] = alignment
        block["redzone_bytes"] = redzone
        block["additional_frame_allowance_bytes"] = alignment + redzone
        return raw + alignment + redzone

    proven, error = native_static_frame_proof(block)
    if error is not None or proven is None:
        block["frame_error"] = error or "native static prologue proof failed"
        block["frame_source"] = "unresolved prebuilt function: no LLVM stack metadata and conservative prologue proof failed"
        return None
    alignment, error = native_alignment_extra(block)
    if error is not None:
        block["frame_error"] = error
        block["frame_source"] = "conservative prologue size proven; stack alignment could not be bounded"
        return None
    redzone, error = native_redzone_extra(block, proven + alignment)
    if error is not None:
        block["frame_error"] = error
        block["frame_source"] = "conservative prologue size proven; redzone stack access could not be bounded"
        return None
    block["frame_source"] = "conservative emitted-code prologue sum plus proven leaf redzone slots"
    block["emitted_frame_bytes"] = proven
    block["alignment_adjustment_bytes"] = alignment
    block["redzone_bytes"] = redzone
    block["additional_frame_allowance_bytes"] = alignment + redzone
    return proven + alignment + redzone


def native_alignment_extra(block: dict[str, object]) -> tuple[int, str | None]:
    """Bound aligned RSP movement by its mask, only for one-shot prologues."""
    total = 0
    control_seen = False
    for instruction in elf_instruction_rows(block):
        mnemonic = str(instruction["mnemonic"])
        operands = str(instruction["operands"])
        parts = [part.strip() for part in operands.split(",")]
        destination = parts[-1] if len(parts) > 1 else ""
        if mnemonic.startswith(("call", "jmp", "ret", "loop")) or re.fullmatch(r"j[a-z]+", mnemonic):
            control_seen = True
        if mnemonic.startswith("and") and destination == "%rsp":
            mask = re.match(r"\$(-?(?:0x[0-9a-fA-F]+|\d+)),", operands)
            if mask is None:
                return 0, f"dynamic native RSP alignment: {instruction['line'].strip()}"
            value = int(mask.group(1), 0)
            if value not in (-16, -32):
                return 0, f"unproved native RSP alignment mask: {instruction['line'].strip()}"
            if control_seen:
                return 0, f"native RSP alignment after control flow: {instruction['line'].strip()}"
            total += abs(value) - 1
    return total, None


def native_metadata_stack_write_audit(block: dict[str, object]) -> str | None:
    """Reject dynamic or unrecognized RSP writes alongside LLVM fixed frames."""
    for instruction in elf_instruction_rows(block):
        operands = str(instruction["operands"])
        mnemonic = str(instruction["mnemonic"])
        parts = [part.strip() for part in operands.split(",")]
        destination = parts[-1] if len(parts) > 1 else ""
        destination_reg = elf_reg(destination) if destination.startswith("%") else ""
        aliases = {
            elf_reg(part)
            for part in parts
            if part.startswith("%")
        }
        if mnemonic.startswith("pop") and parts and parts[-1].startswith("%") and elf_reg(parts[-1]) == "rsp":
            return f"pop into stack pointer is unresolved: {instruction['line'].strip()}"
        if mnemonic.startswith("enter"):
            return f"unsupported native ENTER stack allocation: {instruction['line'].strip()}"
        if mnemonic.startswith("xchg") and "rsp" in aliases:
            return f"exchange involving stack pointer is unresolved: {instruction['line'].strip()}"
        if destination_reg != "rsp":
            continue
        if destination != "%rsp":
            return f"native stack-pointer alias write is unresolved: {instruction['line'].strip()}"
        if mnemonic.startswith(("sub", "add")):
            immediate = re.match(r"\$(-?(?:0x[0-9a-fA-F]+|\d+)),", operands)
            if immediate is None:
                return f"dynamic native RSP adjustment: {instruction['line'].strip()}"
            value = int(immediate.group(1), 0)
            if (mnemonic.startswith("sub") and value <= 0) or (mnemonic.startswith("add") and value < 0):
                return f"negative or unproved immediate native RSP adjustment: {instruction['line'].strip()}"
            continue
        if mnemonic.startswith("lea"):
            if len(parts) == 2 and re.fullmatch(r"-?(?:0x[0-9a-fA-F]+|\d+)\(%rsp\)", parts[0]):
                continue
            return f"unproved native RSP LEA adjustment: {instruction['line'].strip()}"
        if mnemonic.startswith("and"):
            mask = re.match(r"\$(-?(?:0x[0-9a-fA-F]+|\d+)),", operands)
            if mask is not None and int(mask.group(1), 0) in (-16, -32):
                continue
            return f"unproved native RSP alignment: {instruction['line'].strip()}"
        if mnemonic.startswith("leave") or (mnemonic.startswith("mov") and operands == "%rbp, %rsp"):
            continue
        if mnemonic.startswith("pop"):
            return f"pop into stack pointer is unresolved: {instruction['line'].strip()}"
        return f"unclassified native RSP write: {instruction['line'].strip()}"
    return None


def native_redzone_extra(block: dict[str, object], allocated_frame_bytes: int) -> tuple[int, str | None]:
    """Bound ABI redzone use and validate anchored frame-pointer accesses."""
    negative_rsp_slots: list[int] = []
    instructions = elf_instruction_rows(block)
    rbp_is_stack_base = False
    stack_depth = 0
    rbp_depth: int | None = None
    rbp_stack_accesses: list[tuple[int, int]] = []
    audited_slots = block.get("audited_indexed_stack_slots", {})
    for instruction in instructions:
        operands = str(instruction["operands"])
        mnemonic = str(instruction["mnemonic"])
        parts = [part.strip() for part in operands.split(",")]
        destination = parts[-1] if len(parts) > 1 else ""
        destination_reg = elf_reg(destination) if destination.startswith("%") else ""

        for match in re.finditer(r"(-(?:0x[0-9a-fA-F]+|\d+))\(%(rsp|rbp)([^)]*)\)", operands):
            amount = abs(int(match.group(1), 0))
            register, suffix = match.group(2), match.group(3)
            if register == "rsp":
                if suffix.strip():
                    proof = audited_slots.get(int(instruction["address"])) if isinstance(audited_slots, dict) else None
                    expected_displacement = (
                        int(proof.get("base_displacement_bytes", 0))
                        + int(proof.get("field_offset_bytes", 0))
                        if proof is not None
                        else 0
                    )
                    if (
                        proof is None
                        or int(proof.get("redzone_depth_bytes", 129)) != -int(proof.get("base_displacement_bytes", 0))
                        or amount != -expected_displacement
                    ):
                        return 0, f"indexed or otherwise nonconstant RSP-relative stack slot: {instruction['line'].strip()}"
                    negative_rsp_slots.append(int(proof["redzone_depth_bytes"]))
                    continue
                negative_rsp_slots.append(amount)
            elif rbp_is_stack_base:
                if suffix.strip():
                    return 0, f"indexed RBP-relative stack slot needs an index bound: {instruction['line'].strip()}"
                if rbp_depth is None:
                    return 0, "RBP-relative stack access has no proven frame-base depth"
                rbp_stack_accesses.append((amount, rbp_depth))

        # Track only an exact emitted RSP-to-RBP frame-base establishment.
        # RBP is also a callee-saved general register, so an unanchored RBP
        # memory operand is not evidence of stack use.
        if destination_reg == "rbp":
            if mnemonic.startswith("mov") and operands == "%rsp, %rbp":
                rbp_is_stack_base = True
                rbp_depth = stack_depth
            elif mnemonic.startswith("lea") and len(parts) == 2 and parts[1] == "%rbp":
                anchor = re.fullmatch(r"(-?(?:0x[0-9a-fA-F]+|\d+))\(%rsp\)", parts[0])
                if anchor is None:
                    rbp_is_stack_base = False
                    rbp_depth = None
                else:
                    offset = int(anchor.group(1), 0)
                    rbp_is_stack_base = True
                    rbp_depth = stack_depth - offset
            else:
                rbp_is_stack_base = False
                rbp_depth = None

        # The anchor's distance to the deepest fixed frame slot is bounded by
        # LLVM's finalized MachineFrameInfo frame size. This small tracker is
        # used only to account for pushes/subtractions preceding the anchor.
        if mnemonic.startswith(("call", "jmp", "ret", "loop")) or re.fullmatch(r"j[a-z]+", mnemonic):
            pass
        elif mnemonic.startswith(("push", "pushf")):
            stack_depth += 8
        elif mnemonic.startswith("sub") and destination_reg == "rsp" and parts:
            amount = re.match(r"\$(-?(?:0x[0-9a-fA-F]+|\d+)),", operands)
            if amount is not None:
                stack_depth += max(0, int(amount.group(1), 0))
        elif mnemonic.startswith("add") and destination_reg == "rsp" and parts:
            amount = re.match(r"\$(-?(?:0x[0-9a-fA-F]+|\d+)),", operands)
            if amount is not None:
                stack_depth -= max(0, int(amount.group(1), 0))
        elif mnemonic.startswith("lea") and destination_reg == "rsp" and parts:
            adjustment = re.fullmatch(r"(-?(?:0x[0-9a-fA-F]+|\d+))\(%rsp\)", parts[0])
            if adjustment is not None:
                stack_depth -= int(adjustment.group(1), 0)
        elif mnemonic.startswith("and") and destination_reg == "rsp":
            mask = re.match(r"\$(-?(?:0x[0-9a-fA-F]+|\d+)),", operands)
            if mask is not None:
                stack_depth += abs(int(mask.group(1), 0)) - 1

    calls = block.get("calls", [])
    if any(
        depth < 0
        or depth > allocated_frame_bytes
        or amount > allocated_frame_bytes - depth
        for amount, depth in rbp_stack_accesses
    ):
        return 0, "anchored RBP-relative stack slot exceeds the LLVM fixed frame"
    if not negative_rsp_slots:
        return 0, None
    if calls:
        return 0, "negative RSP-relative slots in a function with a call edge lack a proven call-safe lifetime"
    if max(negative_rsp_slots) > 128:
        return 0, "negative RSP-relative access exceeds the 128-byte SysV red zone"
    # Use the full ABI allowance, rather than a single observed displacement,
    # to cover any compiler-generated temporary within the red zone.
    return 128, None


def wasm_imports(module: bytes) -> tuple[list[str], int]:
    def read_uleb(data: bytes, offset: int) -> tuple[int, int]:
        value = 0
        shift = 0
        while True:
            byte = data[offset]
            offset += 1
            value |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                return value, offset
            shift += 7

    def read_name(data: bytes, offset: int) -> tuple[str, int]:
        size, offset = read_uleb(data, offset)
        return data[offset : offset + size].decode("utf-8"), offset + size

    if module[:8] != b"\x00asm\x01\x00\x00\x00":
        raise RuntimeError("stack probe output is not a core wasm v1 module")
    offset = 8
    while offset < len(module):
        section_id = module[offset]
        size, payload_start = read_uleb(module, offset + 1)
        payload_end = payload_start + size
        if section_id == 2:
            imports: list[str] = []
            imported_globals = 0
            count, cursor = read_uleb(module, payload_start)
            for _ in range(count):
                module_name, cursor = read_name(module, cursor)
                field_name, cursor = read_name(module, cursor)
                kind = module[cursor]
                cursor += 1
                if kind == 0:
                    _, cursor = read_uleb(module, cursor)
                    imports.append(f"{module_name}.{field_name}")
                elif kind == 1:
                    cursor += 1  # reference type
                    flags, cursor = read_uleb(module, cursor)
                    _, cursor = read_uleb(module, cursor)
                    if flags & 1:
                        _, cursor = read_uleb(module, cursor)
                elif kind == 2:
                    flags, cursor = read_uleb(module, cursor)
                    _, cursor = read_uleb(module, cursor)
                    if flags & 1:
                        _, cursor = read_uleb(module, cursor)
                elif kind == 3:
                    cursor += 2  # value type and mutability
                    imported_globals += 1
                elif kind == 4:
                    cursor += 1  # tag attribute
                    _, cursor = read_uleb(module, cursor)
                else:
                    raise RuntimeError(f"unknown wasm import kind {kind}")
            return imports, imported_globals
        offset = payload_end
    return [], 0


def wasm_function_types(
    module: bytes,
) -> tuple[list[tuple[bytes, bytes]], list[str], list[int], dict[int, set[int]], dict[str, object]]:
    def read_uleb(data: bytes, offset: int) -> tuple[int, int]:
        value = 0
        shift = 0
        while True:
            byte = data[offset]
            offset += 1
            value |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                return value, offset
            shift += 7

    def read_name(data: bytes, offset: int) -> tuple[str, int]:
        size, offset = read_uleb(data, offset)
        return data[offset : offset + size].decode("utf-8"), offset + size

    sections: dict[int, bytes] = {}
    offset = 8
    while offset < len(module):
        section_id = module[offset]
        size, payload_start = read_uleb(module, offset + 1)
        sections[section_id] = module[payload_start : payload_start + size]
        offset = payload_start + size

    types: list[tuple[bytes, bytes]] = []
    data = sections.get(1, b"")
    count, cursor = read_uleb(data, 0)
    for _ in range(count):
        if data[cursor] != 0x60:
            raise RuntimeError("WASM type section contains a non-function type")
        cursor += 1
        parameter_count, cursor = read_uleb(data, cursor)
        parameters = data[cursor : cursor + parameter_count]
        cursor += parameter_count
        result_count, cursor = read_uleb(data, cursor)
        results = data[cursor : cursor + result_count]
        cursor += result_count
        types.append((parameters, results))

    function_import_types: list[int] = []
    function_import_names: list[str] = []
    imported_globals = 0
    imported_tables = 0
    data = sections.get(2, b"")
    count, cursor = read_uleb(data, 0) if data else (0, 0)
    for _ in range(count):
        module_name, cursor = read_name(data, cursor)
        field_name, cursor = read_name(data, cursor)
        kind = data[cursor]
        cursor += 1
        if kind == 0:
            type_index, cursor = read_uleb(data, cursor)
            function_import_types.append(type_index)
            function_import_names.append(f"{module_name}.{field_name}")
        elif kind == 1:
            imported_tables += 1
            cursor += 1
            flags, cursor = read_uleb(data, cursor)
            _, cursor = read_uleb(data, cursor)
            if flags & 1:
                _, cursor = read_uleb(data, cursor)
        elif kind == 2:
            flags, cursor = read_uleb(data, cursor)
            _, cursor = read_uleb(data, cursor)
            if flags & 1:
                _, cursor = read_uleb(data, cursor)
        elif kind == 3:
            cursor += 2
            imported_globals += 1
        elif kind == 4:
            cursor += 1
            _, cursor = read_uleb(data, cursor)
        else:
            raise RuntimeError(f"unknown WASM import kind {kind}")

    defined_function_types: list[int] = []
    data = sections.get(3, b"")
    count, cursor = read_uleb(data, 0) if data else (0, 0)
    for _ in range(count):
        type_index, cursor = read_uleb(data, cursor)
        defined_function_types.append(type_index)
    function_types = function_import_types + defined_function_types

    defined_tables = 0
    data = sections.get(4, b"")
    if data:
        count, cursor = read_uleb(data, 0)
        defined_tables = count
        for _ in range(count):
            cursor += 1  # reference type
            flags, cursor = read_uleb(data, cursor)
            _, cursor = read_uleb(data, cursor)
            if flags & 1:
                _, cursor = read_uleb(data, cursor)

    def skip_const_expr(data: bytes, cursor: int) -> int:
        while True:
            opcode = data[cursor]
            cursor += 1
            if opcode == 0x0B:
                return cursor
            if opcode == 0x41 or opcode == 0x42:
                while data[cursor] & 0x80:
                    cursor += 1
                cursor += 1
            elif opcode == 0x23 or opcode == 0xD2:
                _, cursor = read_uleb(data, cursor)
            elif opcode in (0x43, 0x44):
                cursor += 4 if opcode == 0x43 else 8
            elif opcode == 0xD0:
                cursor += 1
            else:
                raise RuntimeError(f"unsupported WASM element offset expression opcode 0x{opcode:02x}")

    table_targets: dict[int, set[int]] = {}
    element_flags: list[int] = []
    data = sections.get(9, b"")
    if data:
        count, cursor = read_uleb(data, 0)
        for _ in range(count):
            flags, cursor = read_uleb(data, cursor)
            element_flags.append(flags)
            table_index = 0
            if flags in (2, 6):
                table_index, cursor = read_uleb(data, cursor)
            if flags in (0, 2, 4, 6):
                cursor = skip_const_expr(data, cursor)
            if flags in (1, 2, 3, 5, 6, 7):
                cursor += 1  # elemkind or reftype
            vector_count, cursor = read_uleb(data, cursor)
            targets = table_targets.setdefault(table_index, set())
            for _ in range(vector_count):
                if flags in (0, 1, 2, 3):
                    function_index, cursor = read_uleb(data, cursor)
                    targets.add(function_index)
                else:
                    opcode = data[cursor]
                    cursor += 1
                    if opcode == 0xD2:
                        function_index, cursor = read_uleb(data, cursor)
                        targets.add(function_index)
                    elif opcode == 0xD0:
                        cursor += 1
                    else:
                        raise RuntimeError(f"unsupported WASM element expression opcode 0x{opcode:02x}")
                    if data[cursor] != 0x0B:
                        raise RuntimeError("unterminated WASM element expression")
                    cursor += 1
    exported_tables = 0
    data = sections.get(7, b"")
    if data:
        count, cursor = read_uleb(data, 0)
        for _ in range(count):
            _, cursor = read_name(data, cursor)
            kind = data[cursor]
            cursor += 1
            _, cursor = read_uleb(data, cursor)
            if kind == 1:
                exported_tables += 1

    table_proof = {
        "imported_table_count": imported_tables,
        "defined_table_count": defined_tables,
        "table_count": imported_tables + defined_tables,
        "exported_table_count": exported_tables,
        "element_segment_flags": element_flags,
        "all_element_segments_overapproximated": True,
        "mutating_instructions": [],
        "candidates_complete": imported_tables == 0 and exported_tables == 0,
    }
    return types, function_import_names, function_types, table_targets, table_proof


def wasm_blocks(
    disassembly: str,
    import_names: list[str],
    function_types: list[int],
    function_type_signatures: list[tuple[bytes, bytes]],
    table_targets: dict[int, set[int]],
    table_candidates_complete: bool,
    table_count: int,
) -> dict[str, dict[str, object]]:
    # Defined function bodies are disassembled in function index order. Direct
    # call operands use the module's function index, so parse import ordering
    # from the wasm binary instead of relying on tool symbol ordering.
    imports = len(import_names)
    blocks: dict[str, dict[str, object]] = {}
    ordered: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for line in disassembly.splitlines():
        heading = re.match(r"^([0-9a-fA-F]+) <(.+)>:$", line)
        if heading:
            if heading.group(2) == "CODE":
                current = None  # llvm-objdump's section banner is not a function body
                continue
            function_index = imports + len(ordered)
            symbol = heading.group(2)
            key = f"{symbol} [wasm function {function_index}]"
            current = {
                "name": key,
                "symbol": symbol,
                "function_index": function_index,
                "address": int(heading.group(1), 16),
                "lines": [],
                "calls": [],
            }
            ordered.append(current)
            blocks[key] = current
            continue
        if current is None:
            continue
        current["lines"].append(line)

    function_by_index = {int(block["function_index"]): str(block["name"]) for block in ordered}
    for current in ordered:
        for line in current["lines"]:
            encoded = re.match(
                r"\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}\s+)+)", line
            )
            address = int(encoded.group(1), 16) if encoded is not None else None
            instruction_bytes = bytes.fromhex(encoded.group(2)) if encoded is not None else b""
            call = re.search(
                r"\b(return_call_indirect|return_call_ref|call_indirect|call_ref|return_call|call)\b\s*(\d+)?(?:\s+(\d+))?",
                line,
            )
            if call is None:
                continue
            operation, index, indirect_table = call.groups()
            if operation in ("call_indirect", "return_call_indirect"):
                type_index = int(index) if index is not None else None
                table_index = int(indirect_table) if indirect_table is not None else 0
                candidates = []
                if type_index is not None and type_index < len(function_type_signatures):
                    wanted_signature = function_type_signatures[type_index]
                    for target_index in sorted(table_targets.get(table_index, set())):
                        if target_index >= len(function_types):
                            continue
                        target_type = function_types[target_index]
                        if target_type >= len(function_type_signatures) or function_type_signatures[target_type] != wanted_signature:
                            continue
                        if target_index < imports:
                            candidates.append(f"import:{import_names[target_index]}")
                        elif target_index in function_by_index:
                            candidates.append(function_by_index[target_index])
                current["calls"].append(
                    {
                        "target": None,
                        "target_candidates": candidates,
                        "target_candidates_proven": table_candidates_complete and table_index < table_count,
                        "indirect": True,
                        "tail": operation == "return_call_indirect",
                        "operands": line.strip(),
                        "address": address,
                        "instruction_bytes_hex": instruction_bytes.hex(),
                        "type_index": type_index,
                        "table_index": table_index,
                        # Signature-matched table entries are a complete
                        # module-wide candidate universe, not a proof that
                        # this particular function pointer can name each one.
                        # Source/binary-keyed call-site bindings below are
                        # required before an indirect edge can close.
                        "target_candidates_proven": False,
                    }
                )
            elif operation in ("call_ref", "return_call_ref"):
                current["calls"].append(
                    {
                        "target": None,
                        "target_candidates": [],
                        "target_candidates_proven": False,
                        "indirect": True,
                        "tail": operation == "return_call_ref",
                        "operands": line.strip(),
                        "address": address,
                        "instruction_bytes_hex": instruction_bytes.hex(),
                        "type_index": int(index) if index is not None else None,
                        "target_candidates_proven": False,
                    }
                )
            elif index is not None:
                function_index = int(index)
                current["calls"].append(
                    {
                        "target": None,
                        "function_index": function_index,
                        "indirect": False,
                        "tail": operation == "return_call",
                        "operands": str(function_index),
                        "address": address,
                        "instruction_bytes_hex": instruction_bytes.hex(),
                    }
                )
    for block in blocks.values():
        for call in block["calls"]:
            if call.get("indirect") or call.get("target") is not None:
                continue
            function_index = call.get("function_index")
            if not isinstance(function_index, int):
                continue
            if function_index < imports:
                call["target"] = f"import:{import_names[function_index]}"
            else:
                defined_index = function_index - imports
                if defined_index < len(ordered):
                    call["target"] = ordered[defined_index]["name"]
    return blocks


def apply_audited_wasm_bindings(
    blocks: dict[str, dict[str, object]],
    *,
    profile: str,
    binary_sha256: str,
    code_sha256: str,
    table_proof: dict[str, object],
) -> list[dict[str, object]]:
    """Apply narrowly scoped WASM indirect-call proofs, failing closed."""
    proof_path = PROBE / "audited_wasm_edges.json"
    if not proof_path.exists():
        return []
    document = json.loads(proof_path.read_text())
    if document.get("schema_version") != 1:
        raise RuntimeError("unsupported audited WASM edge proof schema")
    lock_path = ROOT.parent / "Cargo.lock"
    lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    source_candidates = list(
        (cargo_home / "registry" / "src").glob(
            "*/memchr-2.8.3/src/memmem/searcher.rs"
        )
    )
    applied: list[dict[str, object]] = []
    for binding in document.get("bindings", []):
        if binding.get("profile") != profile or binding.get("target") != "wasm32-wasip1":
            continue
        key = {
            "profile": profile,
            "target": "wasm32-wasip1",
            "binary_sha256": binary_sha256,
            "code_section_sha256": code_sha256,
            "caller": binding.get("caller"),
            "function_index": binding.get("function_index"),
            "address": binding.get("address"),
            "instruction_bytes_hex": binding.get("instruction_bytes_hex"),
            "type_index": binding.get("type_index"),
            "table_index": binding.get("table_index"),
        }
        if binding.get("binary_sha256") != binary_sha256 or binding.get("code_section_sha256") != code_sha256:
            applied.append({**key, "applied": False, "reason": "optimized module or code-section hash changed"})
            continue
        provenance = binding.get("source_provenance", {})
        if provenance.get("cargo_lock_sha256") != lock_sha256:
            applied.append({**key, "applied": False, "reason": "Cargo.lock hash changed"})
            continue
        lock_text = lock_path.read_text()
        package_checksum = re.search(
            r'\[\[package\]\]\s+name = "memchr"\s+version = "2\.8\.3"\s+source = "registry\+https://github\.com/rust-lang/crates\.io-index"\s+checksum = "([0-9a-f]+)"',
            lock_text,
        )
        if package_checksum is None or package_checksum.group(1) != provenance.get("package_checksum"):
            applied.append({**key, "applied": False, "reason": "locked memchr package checksum changed"})
            continue
        source_sha = provenance.get("source_file_sha256")
        if not any(
            hashlib.sha256(path.read_bytes()).hexdigest() == source_sha
            for path in source_candidates
        ):
            applied.append({**key, "applied": False, "reason": "pinned memchr source file is unavailable or has changed"})
            continue
        if not table_proof.get("candidates_complete"):
            applied.append({**key, "applied": False, "reason": "module table closure proof is incomplete"})
            continue
        caller = str(binding.get("caller"))
        block = blocks.get(caller)
        if block is None or int(block.get("function_index", -1)) != int(binding.get("function_index", -2)):
            applied.append({**key, "applied": False, "reason": "caller function identity changed"})
            continue
        address = int(str(binding.get("address", "0")), 16)
        matches = [
            call
            for call in block["calls"]
            if call.get("indirect")
            and call.get("address") == address
            and call.get("instruction_bytes_hex") == binding.get("instruction_bytes_hex")
            and call.get("type_index") == binding.get("type_index")
            and call.get("table_index") == binding.get("table_index")
        ]
        if len(matches) != 1:
            applied.append({**key, "applied": False, "reason": f"expected one matching call site, found {len(matches)}"})
            continue
        call = matches[0]
        targets = list(binding.get("targets", []))
        module_candidates = set(call.get("target_candidates", []))
        if not targets or not set(targets).issubset(module_candidates):
            applied.append({**key, "applied": False, "reason": "audited targets are empty or not in the complete module candidate universe"})
            continue
        if any(target not in blocks for target in targets):
            applied.append({**key, "applied": False, "reason": "audited target function is absent from this module"})
            continue
        call["target_candidates"] = targets
        call["target_candidates_proven"] = True
        call["audited_proof"] = {
            "proof_id": binding.get("proof_id"),
            "method": binding.get("method"),
            "source_provenance": provenance,
            "module_sha256": binary_sha256,
            "code_section_sha256": code_sha256,
            "instruction_bytes_hex": binding.get("instruction_bytes_hex"),
        }
        applied.append({**key, "applied": True, "targets": targets, "proof_id": binding.get("proof_id")})
    return applied


def apply_audited_wasm_panic_origins(
    blocks: dict[str, dict[str, object]],
    *,
    profile: str,
    binary_sha256: str,
    code_sha256: str,
    source_sha256: str,
) -> list[dict[str, object]]:
    """Remove only exact dependency panic origins with pinned-source guards."""
    proof_path = ROOT / "docs" / "evidence" / "STACK_WASM_PANIC_PROOFS.json"
    document = json.loads(proof_path.read_text())
    binding = document.get("binding", {})
    key = {
        "profile": profile,
        "target": "wasm32-wasip1",
        "module_sha256": binary_sha256,
        "code_section_sha256": code_sha256,
    }
    if profile != "legacy":
        return []
    if (
        binding.get("profile") != profile
        or binding.get("target") != "wasm32-wasip1"
        or binding.get("module_sha256") != binary_sha256
        or binding.get("code_section_sha256") != code_sha256
        or binding.get("libinjection_tree_sha256") != source_sha256
    ):
        return [{**key, "applied": False, "reason": "panic-origin module, code, or Rust source hash changed"}]
    lock_path = ROOT.parent / "Cargo.lock"
    if not lock_path.is_file() or hashlib.sha256(lock_path.read_bytes()).hexdigest() != binding.get("cargo_lock_sha256"):
        return [{**key, "applied": False, "reason": "panic-origin Cargo.lock hash changed"}]
    lock_text = lock_path.read_text()
    checksum = re.search(
        r'\[\[package\]\]\s+name = "memchr"\s+version = "2\.8\.3"\s+source = "registry\+https://github\.com/rust-lang/crates\.io-index"\s+checksum = "([0-9a-f]+)"',
        lock_text,
    )
    if checksum is None or checksum.group(1) != binding.get("memchr_package_checksum"):
        return [{**key, "applied": False, "reason": "panic-origin memchr package checksum changed"}]
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    registry = cargo_home / "registry" / "src"
    for source in binding.get("memchr_sources", []):
        candidates = list(registry.glob(f"*/memchr-2.8.3/{source['path']}"))
        if not any(hashlib.sha256(path.read_bytes()).hexdigest() == source["sha256"] for path in candidates):
            return [{**key, "applied": False, "reason": f"pinned memchr source unavailable or changed: {source['path']}"}]
    results = []
    for function in document.get("panic_sites", []):
        caller = function["function"]
        block = blocks.get(caller)
        site_records = function.get("sites", [])
        for group in site_records:
            if isinstance(group, str):
                offsets = [group]
                target = function.get("panic_target")
                source_text = function.get("source", "")
                guard = function.get("guard_proof", "")
            else:
                offsets = group.get("offsets", [group.get("offset")])
                target = group.get("panic_target", function.get("panic_target"))
                source_text = group.get("source", function.get("source", ""))
                guard = group.get("guard_proof", function.get("guard_proof", ""))
            for offset_text in offsets:
                if not offset_text:
                    continue
                address = int(offset_text, 16)
                item = {**key, "caller": caller, "address": address, "panic_target": target}
                if block is None:
                    results.append({**item, "applied": False, "reason": "panic-origin caller identity changed"})
                    continue
                matches = [
                    call for call in block["calls"]
                    if call.get("address") == address and call.get("target") == target and not call.get("indirect")
                ]
                if len(matches) != 1:
                    results.append({**item, "applied": False, "reason": f"expected one exact panic-origin call, found {len(matches)}"})
                    continue
                block["calls"].remove(matches[0])
                proof = {
                    "proof_file": "docs/evidence/STACK_WASM_PANIC_PROOFS.json",
                    "source": source_text,
                    "guard_proof": guard,
                    "module_sha256": binary_sha256,
                    "code_section_sha256": code_sha256,
                    "cargo_lock_sha256": binding["cargo_lock_sha256"],
                }
                block.setdefault("audited_panic_origin_proofs", []).append({**item, **proof})
                results.append({**item, "applied": True})
    return results


def wasm_stack_pointer_global(module: bytes) -> int:
    def read_uleb(data: bytes, offset: int) -> tuple[int, int]:
        value = 0
        shift = 0
        while True:
            byte = data[offset]
            offset += 1
            value |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                return value, offset
            shift += 7

    def read_name(data: bytes, offset: int) -> tuple[str, int]:
        size, offset = read_uleb(data, offset)
        return data[offset : offset + size].decode("utf-8"), offset + size

    offset = 8
    while offset < len(module):
        section_id = module[offset]
        size, payload_start = read_uleb(module, offset + 1)
        payload_end = payload_start + size
        if section_id == 0:
            custom_name, cursor = read_name(module, payload_start)
            if custom_name == "name":
                while cursor < payload_end:
                    subsection_id = module[cursor]
                    subsection_size, names_start = read_uleb(module, cursor + 1)
                    names_end = names_start + subsection_size
                    if subsection_id == 7:  # global-name subsection
                        count, names_cursor = read_uleb(module, names_start)
                        for _ in range(count):
                            global_index, names_cursor = read_uleb(module, names_cursor)
                            name, names_cursor = read_name(module, names_cursor)
                            if name == "__stack_pointer":
                                return global_index
                    cursor = names_end
        offset = payload_end
    raise RuntimeError("optimized wasm module has no named __stack_pointer global")


def wasm_table_mutators(disassembly: str) -> list[str]:
    operations = set(
        re.findall(r"\b(table\.(?:set|init|copy|grow|fill)|elem\.drop)\b", disassembly)
    )
    return sorted(operations)


def wasm_unknown_call_ops(disassembly: str) -> list[str]:
    known = {"call", "call_indirect", "call_ref", "return_call", "return_call_indirect", "return_call_ref"}
    observed: set[str] = set()
    for line in disassembly.splitlines():
        decoded = re.match(
            r"\s*[0-9a-fA-F]+:\s*(?:[0-9a-fA-F]{2}\s+)+\s*([a-z][a-z0-9_.]*)\b",
            line,
        )
        if decoded is None:
            continue
        operation = decoded.group(1)
        if operation.startswith(("call", "return_call")) and operation not in known:
            observed.add(operation)
    return sorted(observed - known)


def wasm_section(module: bytes, wanted: int) -> bytes:
    def read_uleb(data: bytes, offset: int) -> tuple[int, int]:
        value = 0
        shift = 0
        while True:
            byte = data[offset]
            offset += 1
            value |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                return value, offset
            shift += 7

    offset = 8
    while offset < len(module):
        section_id = module[offset]
        size, payload_start = read_uleb(module, offset + 1)
        payload_end = payload_start + size
        if section_id == wanted:
            return module[payload_start:payload_end]
        offset = payload_end
    return b""


def native_section(binary: Path, objcopy: str, section: str, artifact: Path) -> bytes:
    output = artifact / f"{binary.name}.{section.lstrip('.')}.bin"
    subprocess.run(
        [objcopy, "--dump-section", f"{section}={output}", str(binary)],
        check=True,
        text=True,
        capture_output=True,
    )
    return output.read_bytes()


def native_stack_size_map(binary: Path, objcopy: str, blocks: dict[str, dict[str, object]]) -> tuple[dict[int, int], int]:
    with tempfile.TemporaryDirectory(prefix="libinjection-stack-") as temporary:
        section_path = Path(temporary) / "stack_sizes.bin"
        subprocess.run(
            [objcopy, "--dump-section", f".stack_sizes={section_path}", str(binary)],
            check=True,
            text=True,
            capture_output=True,
        )
        data = section_path.read_bytes()
    sizes: dict[int, int] = {}
    offset = 0
    while offset < len(data):
        if len(data) - offset < 9:
            raise RuntimeError("truncated ELF .stack_sizes record")
        address = int.from_bytes(data[offset : offset + 8], "little")
        offset += 8
        size = 0
        shift = 0
        while True:
            if offset >= len(data):
                raise RuntimeError("truncated ULEB128 in ELF .stack_sizes record")
            byte = data[offset]
            offset += 1
            size |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                break
            shift += 7
            if shift > 63:
                raise RuntimeError("oversized ULEB128 in ELF .stack_sizes record")
        sizes[address] = size
    known_addresses = {int(block["address"]) for block in blocks.values()}
    matched = len(known_addresses & set(sizes))
    return sizes, matched


def wasm_frame(block: dict[str, object], stack_global_index: int) -> int:
    # Match full emitted instruction sequences. No filtered-window inference:
    # the input pointer must be the SP global itself and each restore must be
    # the exact inverse of a proven allocation in this function.
    instructions: list[tuple[str, str, int]] = []
    for line_index, line in enumerate(block["lines"]):
        decoded = re.match(
            r"\s*[0-9a-fA-F]+:\s*(?:[0-9a-fA-F]{2}\s+)+\s*([a-z][a-z0-9_.]*)\s*(.*?)\s*$",
            line,
        )
        if decoded:
            operation, operands = decoded.groups()
            instructions.append((operation, operands.split("#", 1)[0].strip(), line_index))

    def number(item: tuple[str, str, int]) -> int | None:
        try:
            return int(item[1], 0)
        except ValueError:
            return None

    frame = 0
    errors: list[str] = []
    allocation_lines: set[int] = set()
    allocation_sizes: list[int] = []
    allocated_locals: dict[int, int] = {}
    control_flow_seen = False
    control_operations = {
        "block", "loop", "if", "else", "br", "br_if", "br_table", "call",
        "call_indirect", "call_ref", "return_call", "return_call_indirect",
        "return_call_ref", "return", "try", "catch", "catch_all", "throw",
        "throw_ref", "rethrow", "delegate",
    }
    for index, (operation, operands, line_index) in enumerate(instructions):
        if operation in ("local.set", "local.tee"):
            written_local = number((operation, operands, line_index))
            if written_local is not None:
                allocated_locals.pop(written_local, None)
        if operation == "global.set" and number((operation, operands, line_index)) == stack_global_index:
            before = instructions[max(0, index - 4) : index]
            ops = [item[0] for item in before]
            args = [item[1] for item in before]
            amount: int | None = None
            local: int | None = None
            allocation = False

            # direct: global.get SP; const N; sub; global.set SP
            if len(before) >= 3 and ops[-3:] == ["global.get", "i32.const", "i32.sub"]:
                if number(before[-3]) == stack_global_index:
                    amount = number(before[-2])
                    allocation = True
            # rustc: global.get SP; const N; sub; local.tee L; global.set SP
            elif len(before) >= 4 and ops[-4:] == ["global.get", "i32.const", "i32.sub", "local.tee"]:
                if number(before[-4]) == stack_global_index:
                    amount = number(before[-3])
                    local = number(before[-1])
                    allocation = True

            if allocation:
                if amount is None or amount < 0:
                    errors.append(f"negative or nonconstant WASM frame size before {block['lines'][line_index].strip()}")
                elif control_flow_seen:
                    errors.append(f"WASM frame allocation follows control flow: {block['lines'][line_index].strip()}")
                else:
                    frame += amount
                    allocation_sizes.append(amount)
                    allocation_lines.add(line_index)
                    if local is not None:
                        allocated_locals[local] = amount
            else:
                # inverse direct: global.get SP; const N; add; global.set SP
                restored: int | None = None
                if len(before) >= 3 and ops[-3:] == ["global.get", "i32.const", "i32.add"]:
                    if number(before[-3]) == stack_global_index:
                        restored = number(before[-2])
                # inverse saved: local.get L; const N; add; global.set SP
                elif len(before) >= 3 and ops[-3:] == ["local.get", "i32.const", "i32.add"]:
                    local_index = number(before[-3])
                    constant = number(before[-2])
                    if local_index in allocated_locals and allocated_locals[local_index] == constant:
                        restored = constant
                if restored is None or restored < 0 or restored not in allocation_sizes:
                    errors.append(f"unclassified __stack_pointer write at {block['lines'][line_index].strip()}")

        if operation in control_operations or operation.startswith(("br", "call", "return_call", "throw", "rethrow", "delegate")):
            control_flow_seen = True
    if errors:
        block["frame_error"] = "; ".join(errors)
        block["frame_source"] = "WASM __stack_pointer sequence; allocation proof incomplete"
        return 0
    block["frame_source"] = "exact optimized WASM __stack_pointer allocation/restore instruction sequences"
    block["emitted_frame_bytes"] = frame
    block["additional_frame_allowance_bytes"] = 0
    return frame


def calculate(blocks: dict[str, dict[str, object]], frame_fn, entry: str, arch: str) -> dict[str, object]:
    names: dict[str, str] = {}
    for key, block in blocks.items():
        names.setdefault(str(block.get("symbol", key)).split("@", 1)[0], key)
        names.setdefault(key, key)
    root = names.get(entry)
    if root is None:
        raise RuntimeError(f"missing public detector symbol {entry!r}")
    active: list[str] = []
    memo: dict[str, tuple[int, list[tuple[str, int]], list[dict[str, str]]]] = {}
    unresolved: set[tuple[str, str]] = set()

    def visit(name: str) -> tuple[int, list[tuple[str, int]], list[dict[str, str]]]:
        if name in active:
            cycle = " -> ".join(active[active.index(name) :] + [name])
            unresolved.add((active[-1], f"recursive callgraph cycle: {cycle}"))
            return 0, [], []
        if name in memo:
            return memo[name]
        active.append(name)
        block = blocks[name]
        own = frame_fn(block)
        if block.get("frame_error"):
            unresolved.add((name, str(block["frame_error"])))
        if own is None:
            unresolved.add((name, str(block.get("frame_error", "frame size is not measured"))))
            own = 0
        best_bytes = own
        best_path = [(name, 0)]
        best_tail_transitions: list[dict[str, str]] = []
        for call in block["calls"]:
            candidates = call.get("target_candidates")
            if candidates is None:
                candidates = [call["target"]]
            if call.get("target_candidates_proven") is False:
                unresolved.add((name, f"incomplete indirect target set: {call['operands']}"))
            candidates = [candidate for candidate in candidates if candidate is not None]
            if not candidates:
                unresolved.add((name, str(call["operands"])))
                continue
            for target in candidates:
                if target.startswith("external:"):
                    unresolved.add((name, f"external dynamic call {target[9:]}"))
                    continue
                if target.startswith("import:"):
                    unresolved.add((name, f"external wasm call {target[7:]}"))
                    continue
                callee = target if target in blocks else names.get(target.split("@", 1)[0])
                if callee is None:
                    unresolved.add((name, f"unresolved call target {target}"))
                    continue
                child_bytes, child_path, child_tail_transitions = visit(callee)
                tail = bool(call.get("tail", False))
                edge = 8 if arch == "elf" and not tail else 0
                candidate_bytes = max(own, child_bytes) if tail else own + edge + child_bytes
                if tail and own >= child_bytes:
                    candidate_path = [(name, 0)]
                    candidate_tail_transitions = []
                elif tail and child_path:
                    # A tail call unwinds this frame before entering the callee.
                    candidate_path = child_path
                    candidate_tail_transitions = [{"from": name, "to": callee}, *child_tail_transitions]
                elif child_path:
                    candidate_path = [(name, 0), (child_path[0][0], edge), *child_path[1:]]
                    candidate_tail_transitions = child_tail_transitions
                else:
                    candidate_path = [(name, 0)]
                    candidate_tail_transitions = []
                if candidate_bytes > best_bytes:
                    best_bytes = candidate_bytes
                    best_path = candidate_path
                    best_tail_transitions = candidate_tail_transitions
        active.pop()
        memo[name] = (best_bytes, best_path, best_tail_transitions)
        return memo[name]

    stack_bytes, path, tail_transitions = visit(root)
    reached = set(memo)
    issues = [
        {"function": name, "edge_or_frame": description}
        for name, description in sorted(unresolved)
        if name in reached
    ]
    upper_bound = stack_bytes if not issues else None

    def frame_report(block: dict[str, object]) -> dict[str, object]:
        measured = frame_fn(block)
        return {
            "frame_bytes_upper_bound": measured,
            "emitted_frame_bytes": block.get("emitted_frame_bytes"),
            "additional_frame_allowance_bytes": block.get("additional_frame_allowance_bytes"),
            "alignment_adjustment_bytes": block.get("alignment_adjustment_bytes"),
            "redzone_bytes": block.get("redzone_bytes"),
            "audited_stack_slot_proofs": block.get("audited_stack_slot_proofs", []),
            "raw_stack_size_metadata_bytes": block.get("raw_stack_size_bytes"),
            "frame_error": block.get("frame_error"),
            "frame_source": block.get("frame_source"),
        }

    return {
        "entry": entry,
        "stack_bytes_resolved_path_estimate": stack_bytes,
        "resolved_path_estimate_scope": "sum of emitted per-frame sizes, conservative native redzone allowances, and ordinary-call return-address allowances along one resolved path; unresolved edges elsewhere may exceed this value",
        "stack_bytes_upper_bound": upper_bound,
        "limit_bytes": LIMIT,
        "budget_status": budget_status(upper_bound),
        "passed": upper_bound is not None and upper_bound <= LIMIT,
        "full_call_stack_bound": False,
        "scope": "library detector and internal callee frames only; entry caller, arbitrary callback frames, and WASM engine call-stack overhead are excluded",
        "path": [
            {
                "symbol": name,
                **frame_report(blocks[name]),
                "incoming_call_frame_bytes": incoming_bytes,
                "incoming_return_address_bytes": incoming_bytes if arch == "elf" else 0,
            }
            for name, incoming_bytes in path
        ],
        "tail_call_transitions": tail_transitions,
        "unresolved_calls": issues,
        "reachable_functions": len(reached),
        "reachable_callgraph": {
            name: {
                **frame_report(blocks[name]),
                "calls": [
                    {
                        "target": call["target"],
                        "target_candidates": call.get("target_candidates"),
                        "target_candidates_proven": call.get("target_candidates_proven"),
                        "indirect": call["indirect"],
                        "tail": bool(call.get("tail", False)),
                        "resolved_via": call.get("resolved_via"),
                        "address": call.get("address"),
                        "instruction_bytes_hex": call.get("instruction_bytes_hex"),
                        "audited_proof": call.get("audited_proof"),
                        "operands": call.get("operands"),
                    }
                    for call in blocks[name]["calls"]
                ],
                "local_controlflow_proofs": blocks[name].get("local_controlflow_proofs", []),
            }
            for name in sorted(reached)
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust", default="1.97.1", help="production Rust toolchain (default: 1.97.1)")
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--llvm-objdump", default="llvm-objdump")
    parser.add_argument("--llvm-objcopy", default="llvm-objcopy")
    parser.add_argument("--artifact-dir", type=Path, default=Path("/tmp/libinjection-stack-phase5"))
    parser.add_argument("--output", type=Path, help="write JSON report at this path (default: stdout)")
    parser.add_argument("--target", action="append", choices=TARGETS, help="measure only this target (repeatable)")
    parser.add_argument("--profile", action="append", choices=tuple(PROFILES), help="measure only this feature profile (repeatable)")
    parser.add_argument(
        "--strict-budget",
        action="store_true",
        help="exit nonzero unless every requested detector entry has a proven bound within 4096 bytes",
    )
    args = parser.parse_args()

    artifact_dir = args.artifact_dir.resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    probe_source = PROBE / "src" / "main.rs"
    report: dict[str, object] = {
        "method": "pinned optimized code; native LLVM .stack_sizes metadata with byte-identical .text validation and conservative prebuilt prologue fallback; WASM linear-memory stack-pointer frame proof; reachable call-path bound only when every reachable frame and edge is resolved",
        "stack_budget_policy": "informational by default; --strict-budget opts into a nonzero result for open or over-limit detector library-frame bounds",
        "strict_budget_requested": args.strict_budget,
        "analysis_status": "in_progress",
        "strict_budget_exit_code": None,
        "full_call_stack_bound": False,
        "bound_scope": "detector and library callee frames only; excludes entry caller, arbitrary callback frames, native OS/runtime entry, and WASM engine call-stack overhead",
        "caller_and_callback_stack_included": False,
        "wasm_metric": "Rust linear-memory __stack_pointer frames; WASM engine call-stack overhead is runtime-specific and excluded",
        "rustc": run(["rustc", f"+{args.rust}", "--version", "--verbose"]).strip(),
        "llvm_objdump": version([args.llvm_objdump, "--version"]),
        "llvm_objcopy": version([args.llvm_objcopy, "--version"]),
        "limit_bytes": LIMIT,
        "source_sha256": hashlib.sha256(
            b"".join(
                path.relative_to(ROOT / "src").as_posix().encode()
                + b"\0"
                + hashlib.sha256(path.read_bytes()).digest()
                for path in sorted((ROOT / "src").rglob("*"))
                if path.is_file()
            )
        ).hexdigest(),
        "probe_source": {
            "path": probe_source.relative_to(ROOT).as_posix(),
            "sha256": hashlib.sha256(probe_source.read_bytes()).hexdigest(),
            "local_shims": ["bcmp", "memcmp", "memcpy", "memset"],
        },
        "runtime_scope": "The probe driver is no_std/no_main and panic=abort; the libinjection library always links its Rust std/memchr dependencies. Local C ABI memory shims are compiled from the hashed probe source and included in the emitted call graph. No reachable external, imported, indirect, or panic/error-path frame is treated as zero; unresolved detector-reachable runtime edges keep the bound open.",
        "stack_instrumentation": "native instrumented builds use RUSTC_BOOTSTRAP=1 and -Z emit-stack-sizes; final native .text bytes must equal an uninstrumented pinned release build. Native frames use raw LLVM .stack_sizes values and add only emitted, proven leaf redzone slots; ambiguous redzone accesses keep the frame unresolved. Ordinary native calls add 8 bytes for the return address; tail calls do not. WASM uses uninstrumented pinned release code and exact __stack_pointer frame sequences.",
        "native_frame_metadata_contract": {
            "compiler": "LLVM 22.1.6 backend bundled with pinned rustc 1.97.1",
            "authority": [
                "https://www.llvm.org/docs/CommandGuide/llc.html#cmdoption-llc-stack-size-section",
                "https://llvm.org/docs/doxygen/classllvm_1_1MachineFrameInfo.html#getStackSize",
            ],
            "semantics": "LLVM .stack_sizes values record prologue stack allocation for fixed-size frame objects after frame layout; MachineFrameInfo::getStackSize is the bytes required for all fixed-size frame objects after prologue/epilogue insertion finalizes layout.",
            "dynamic_allocation": "LLVM documents functions with dynamic stack allocations as omitted from .stack_sizes. Such functions are handled only by the emitted-RSP-adjustment audit/fallback; an unknown or dynamic adjustment stays unresolved.",
            "artifact_check": "The instrumented and ordinary optimized native .text sections are compared byte-for-byte for every profile before these metadata values are accepted.",
        },
        "native_redzone_contract": {
            "abi_allowance_bytes": 128,
            "authority": "https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/master/x86-64-ABI/low-level-sys-info.tex",
            "application": "Only a bounded constant RSP-relative negative access no farther than 128 bytes can trigger the allowance, and only in a function with no call or tail-call edges. The analyzer then adds the full 128-byte ABI allowance, not the observed displacement. Calls, indexed operands, accesses beyond 128 bytes, and ambiguous frame-pointer slots remain unresolved.",
        },
        "builds": [],
    }
    global REPORT_PROGRESS, REPORT_OUTPUT
    REPORT_PROGRESS = report
    REPORT_OUTPUT = args.output or artifact_dir / "report.json"
    profiles = args.profile or list(PROFILES)
    targets = args.target or list(TARGETS)
    for profile in profiles:
        feature_args = PROFILES[profile]
        for target in targets:
            build_dir = artifact_dir / "builds" / profile / target
            build_dir.mkdir(parents=True, exist_ok=True)
            build = [
                args.cargo,
                f"+{args.rust}",
                "build",
                "--offline",
                "--locked",
                "--manifest-path",
                str(PROBE / "Cargo.toml"),
                "--release",
                "--target",
                target,
                *feature_args,
            ]
            executable_name = "libinjection-stack-probe.wasm" if target == "wasm32-wasip1" else "libinjection-stack-probe"
            build_env = os.environ.copy()
            for key in ("RUSTFLAGS", "RUSTC_BOOTSTRAP", "CARGO_ENCODED_RUSTFLAGS"):
                build_env.pop(key, None)
            build_env["CARGO_TARGET_DIR"] = str(build_dir)
            plain_command = [*build]
            plain_env = build_env.copy()
            native_link_flags = "-C panic=abort -C link-arg=-nostartfiles -C link-arg=-Wl,-e,_start"
            if target == "x86_64-unknown-linux-gnu":
                plain_env["RUSTFLAGS"] = native_link_flags
            subprocess.run(plain_command, check=True, env=plain_env)
            cargo_executable = build_dir / target / "release" / executable_name
            plain_copy = build_dir / f"plain-{executable_name}"
            plain_copy.write_bytes(cargo_executable.read_bytes())
            instrumented_copy: Path | None = None
            code_identical: bool | None = None
            instrumented_command: list[str] | None = None
            if target == "x86_64-unknown-linux-gnu":
                instrumented_env = build_env.copy()
                instrumented_env["RUSTC_BOOTSTRAP"] = "1"
                instrumented_env["RUSTFLAGS"] = f"-Z emit-stack-sizes {native_link_flags}"
                instrumented_command = [*build]
                subprocess.run(instrumented_command, check=True, env=instrumented_env)
                instrumented_copy = build_dir / f"stack-sizes-{executable_name}"
                instrumented_copy.write_bytes(cargo_executable.read_bytes())
                code_identical = (
                    native_section(plain_copy, args.llvm_objcopy, ".text", build_dir)
                    == native_section(instrumented_copy, args.llvm_objcopy, ".text", build_dir)
                )
                executable = instrumented_copy
            else:
                executable = plain_copy
            if target == "wasm32-wasip1":
                disassembly = run([args.llvm_objdump, "-d", "--demangle", str(executable)])
                module = executable.read_bytes()
                imports, _ = wasm_imports(module)
                stack_global_index = wasm_stack_pointer_global(module)
                function_type_signatures, import_names, function_types, table_targets, table_proof = wasm_function_types(module)
                mutators = wasm_table_mutators(disassembly)
                unknown_calls = wasm_unknown_call_ops(disassembly)
                table_proof["mutating_instructions"] = mutators
                table_proof["unsupported_call_instructions"] = unknown_calls
                table_proof["candidates_complete"] = bool(
                    table_proof["candidates_complete"] and not mutators and not unknown_calls
                )
                blocks = wasm_blocks(
                    disassembly,
                    import_names,
                    function_types,
                    function_type_signatures,
                    table_targets,
                    bool(table_proof["candidates_complete"]),
                    int(table_proof["table_count"]),
                )
                frame_fn = lambda block: wasm_frame(block, stack_global_index)
                arch = "wasm"
                code_identical = None
                binary_sha256 = hashlib.sha256(module).hexdigest()
                binary_code_sha256 = hashlib.sha256(wasm_section(module, 10)).hexdigest()
                audited_wasm_bindings = apply_audited_wasm_bindings(
                    blocks,
                    profile=profile,
                    binary_sha256=binary_sha256,
                    code_sha256=binary_code_sha256,
                    table_proof=table_proof,
                )
                audited_native_bindings = []
                audited_native_local_jump_tables = []
                audited_native_stack_slots = []
                audited_wasm_panic_origins = apply_audited_wasm_panic_origins(
                    blocks,
                    profile=profile,
                    binary_sha256=binary_sha256,
                    code_sha256=binary_code_sha256,
                    source_sha256=str(report["source_sha256"]),
                )
                table_proof_report: dict[str, object] | None = table_proof
            else:
                disassembly = run([args.llvm_objdump, "-d", "--demangle", str(executable)])
                readobj = run(["llvm-readobj", "--relocations", str(executable)])
                blocks = elf_blocks(
                    disassembly,
                    elf_relocations(readobj),
                    executable.read_bytes(),
                )
                stack_sizes, matched_stack_size_functions = native_stack_size_map(
                    executable, args.llvm_objcopy, blocks
                )
                frame_fn = lambda block: native_frame(block, stack_sizes)
                arch = "elf"
                binary_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
                binary_code_sha256 = hashlib.sha256(native_section(executable, args.llvm_objcopy, ".text", build_dir)).hexdigest()
                table_proof_report = None
                audited_wasm_bindings = []
                audited_native_bindings = apply_audited_native_bindings(
                    blocks,
                    profile=profile,
                    binary_sha256=binary_sha256,
                    code_sha256=binary_code_sha256,
                    source_sha256=str(report["source_sha256"]),
                )
                audited_native_local_jump_tables = apply_audited_native_local_jump_tables(
                    blocks,
                    executable.read_bytes(),
                    profile=profile,
                    binary_sha256=binary_sha256,
                    code_sha256=binary_code_sha256,
                    source_sha256=str(report["source_sha256"]),
                )
                audited_native_stack_slots = apply_audited_native_stack_slots(
                    blocks,
                    profile=profile,
                    binary_sha256=binary_sha256,
                    code_sha256=binary_code_sha256,
                    source_sha256=str(report["source_sha256"]),
                )
                audited_wasm_panic_origins = []
            has_legacy = "--features" in feature_args and "legacy" in feature_args[feature_args.index("--features") + 1].split(",")
            entries = ANALYSIS_ENTRIES + (DETECTOR_ENTRIES if has_legacy else ())
            rows = [calculate(blocks, frame_fn, entry, arch) for entry in entries]
            proof_bindings_complete = (
                all(bool(item.get("applied")) for item in audited_native_bindings)
                and all(bool(item.get("applied")) for item in audited_native_local_jump_tables)
                and all(bool(item.get("applied")) for item in audited_native_stack_slots)
                and all(bool(item.get("applied")) for item in audited_wasm_panic_origins)
            )
            build_report = {
                "profile": profile,
                "target": target,
                "features": [arg for arg in feature_args if arg != "--features"],
                "build_command": shlex.join(plain_command),
                "instrumented_build_command": shlex.join(instrumented_command) if instrumented_command else None,
                "instrumented_code_identical_to_plain": code_identical,
                "binary": str(executable),
                "plain_binary_sha256": hashlib.sha256(plain_copy.read_bytes()).hexdigest(),
                "binary_sha256": binary_sha256,
                "code_section_sha256": binary_code_sha256,
                "disassembly_sha256": hashlib.sha256(disassembly.encode("utf-8")).hexdigest(),
                "stack_size_metadata_function_count": len(stack_sizes) if target == "x86_64-unknown-linux-gnu" else None,
                "matched_stack_size_function_count": matched_stack_size_functions if target == "x86_64-unknown-linux-gnu" else None,
                "wasm_table_proof": table_proof_report,
                "audited_wasm_bindings": audited_wasm_bindings,
                "audited_native_bindings": audited_native_bindings,
                "audited_native_local_jump_tables": audited_native_local_jump_tables,
                "audited_native_stack_slots": audited_native_stack_slots,
                "audited_wasm_panic_origins": audited_wasm_panic_origins,
                "entries": rows,
                "budget_status": build_budget_status(rows, proof_bindings_complete),
                "proof_bindings_complete": proof_bindings_complete,
                "passed": all(bool(row["passed"]) for row in rows)
                and (code_identical is not False)
                and proof_bindings_complete,
            }
            report["builds"].append(build_report)

    report["analysis_status"] = "complete"
    report["strict_budget_exit_code"] = strict_budget_exit_code(
        report["builds"], args.strict_budget
    )
    output = json.dumps(report, indent=2) + "\n"
    output_path = REPORT_OUTPUT
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output)
    else:
        print(output, end="")
    return int(report["strict_budget_exit_code"])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"stack measurement failed: {error}", file=sys.stderr)
        if REPORT_PROGRESS is not None and REPORT_OUTPUT is not None:
            REPORT_PROGRESS["fatal_error"] = str(error)
            REPORT_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
            REPORT_OUTPUT.write_text(json.dumps(REPORT_PROGRESS, indent=2) + "\n")
        sys.exit(2)
