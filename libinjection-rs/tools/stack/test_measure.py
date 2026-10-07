#!/usr/bin/env python3
"""Fail-closed regression tests for emitted-code stack analysis."""

# Copyright Coraza Kubernetes Operator contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).with_name("measure.py")
SPEC = importlib.util.spec_from_file_location("stack_measure", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
measure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measure)


def wasm_line(address: int, opcode: int, mnemonic: str, operands: str = "") -> str:
    return f" {address:x}: {opcode:02x}  {mnemonic}\t{operands}"


class WasmFrameTests(unittest.TestCase):
    def block(self, lines: list[str]) -> dict[str, object]:
        return {"name": "wasm_fn", "lines": lines}

    def test_exact_stack_pointer_frame_and_restore(self) -> None:
        block = self.block(
            [
                wasm_line(0, 0x23, "global.get", "0"),
                wasm_line(2, 0x41, "i32.const", "16"),
                wasm_line(4, 0x6B, "i32.sub"),
                wasm_line(5, 0x22, "local.tee", "2"),
                wasm_line(7, 0x24, "global.set", "0"),
                wasm_line(9, 0x20, "local.get", "2"),
                wasm_line(11, 0x41, "i32.const", "16"),
                wasm_line(13, 0x6A, "i32.add"),
                wasm_line(14, 0x24, "global.set", "0"),
                wasm_line(16, 0x0B, "end"),
            ]
        )
        self.assertEqual(measure.wasm_frame(block, 0), 16)
        self.assertNotIn("frame_error", block)

    def test_unknown_call_scan_uses_instruction_mnemonics_not_symbol_names(self) -> None:
        disassembly = """\
00000100 <calloc>:
 100: 00 00  call 7
 102: 00 00  call_on_null
"""
        self.assertEqual(measure.wasm_unknown_call_ops(disassembly), ["call_on_null"])

    def test_indirect_wasm_call_records_site_identity_and_stays_unproven(self) -> None:
        disassembly = """\
00000000 <caller>:
 10: 11 80  call_indirect 1
00000020 <callee>:
 20: 0b     end
"""
        blocks = measure.wasm_blocks(
            disassembly,
            [],
            [0, 1],
            [(b"", b""), (b"", b"")],
            {0: {0, 1}},
            True,
            1,
        )
        call = blocks["caller [wasm function 0]"]["calls"][0]
        self.assertEqual(call["address"], 0x10)
        self.assertEqual(call["instruction_bytes_hex"], "1180")
        self.assertEqual(call["type_index"], 1)
        self.assertEqual(call["table_index"], 0)
        self.assertFalse(call["target_candidates_proven"])

    def test_negative_stack_add_is_unresolved(self) -> None:
        block = self.block(
            [
                wasm_line(0, 0x41, "i32.const", "-4096"),
                wasm_line(2, 0x6A, "i32.add"),
                wasm_line(3, 0x24, "global.set", "0"),
            ]
        )
        self.assertEqual(measure.wasm_frame(block, 0), 0)
        self.assertIn("unclassified __stack_pointer write", block["frame_error"])

    def test_non_adjacent_allocation_is_unresolved(self) -> None:
        block = self.block(
            [
                wasm_line(0, 0x23, "global.get", "0"),
                wasm_line(2, 0x41, "i32.const", "16"),
                wasm_line(4, 0x01, "nop"),
                wasm_line(5, 0x6B, "i32.sub"),
                wasm_line(6, 0x24, "global.set", "0"),
            ]
        )
        measure.wasm_frame(block, 0)
        self.assertIn("unclassified __stack_pointer write", block["frame_error"])


class BudgetPolicyTests(unittest.TestCase):
    def test_open_and_over_limit_bounds_are_advisory_by_default(self) -> None:
        builds = [
            {"passed": False, "budget_status": "open"},
            {"passed": False, "budget_status": "over_limit"},
        ]
        self.assertEqual(measure.budget_status(None), "open")
        self.assertEqual(measure.budget_status(4096), "within_limit")
        self.assertEqual(measure.budget_status(4097), "over_limit")
        self.assertEqual(measure.build_budget_status(builds, True), "open")
        self.assertEqual(measure.strict_budget_exit_code(builds, False), 0)

    def test_explicit_strict_budget_rejects_open_or_over_limit_builds(self) -> None:
        self.assertEqual(measure.strict_budget_exit_code([], True), 0)
        self.assertEqual(measure.strict_budget_exit_code([{"passed": True}], True), 0)
        self.assertEqual(measure.strict_budget_exit_code([{"passed": False}], True), 1)

    def test_unapplied_proof_keeps_build_budget_open(self) -> None:
        rows = [{"budget_status": "within_limit"}]
        self.assertEqual(measure.build_budget_status(rows, False), "open")

class NativeFrameTests(unittest.TestCase):
    def prove(self, line: str) -> tuple[int | None, str | None]:
        return measure.native_static_frame_proof({"name": "native_fn", "lines": [line]})

    def test_negative_add_remains_unresolved(self) -> None:
        _, error = self.prove("  100: 48 83 c4 f0  addq $-0x10, %rsp")
        self.assertIn("negative-immediate native add", error)

    def test_stack_pointer_alias_write_remains_unresolved(self) -> None:
        _, error = self.prove("  100: 48 83 ec 10  subq $0x10, %esp")
        self.assertIn("stack-pointer alias write", error)

    def test_enter_remains_unresolved(self) -> None:
        _, error = self.prove("  100: c8 10 00 00  enterq $0x10, $0x0")
        self.assertIn("ENTER", error)

    def test_positive_rsp_alignment_mask_remains_unresolved(self) -> None:
        _, error = self.prove("  100: 48 83 e4 10  andq $0x10, %rsp")
        self.assertIn("RSP alignment", error)

    def test_only_exact_rbp_to_rsp_restore_is_accepted(self) -> None:
        _, error = self.prove("  100: 48 89 ec  movq %rbp, %esp")
        self.assertIn("stack-pointer alias write", error)

    def test_exchange_involving_rsp_remains_unresolved(self) -> None:
        _, error = self.prove("  100: 48 87 e4  xchgq %rsp, %rax")
        self.assertIn("exchange involving stack pointer", error)

    def test_metadata_audit_accepts_recognized_fixed_adjustments_after_branch(self) -> None:
        block = {
            "name": "split_prologue",
            "lines": [
                "  100: 74 02  je 0x104",
                "  102: 55  pushq %rbp",
                "  103: 48 83 ec 10  subq $0x10, %rsp",
            ],
        }
        self.assertIsNone(measure.native_metadata_stack_write_audit(block))

    def test_llvm_frame_metadata_accepts_fixed_split_prologue(self) -> None:
        block = {
            "name": "split_prologue",
            "address": 0x100,
            "lines": [
                "  100: 74 02  je 0x104",
                "  102: 55  pushq %rbp",
                "  103: 48 83 ec 10  subq $0x10, %rsp",
            ],
            "calls": [],
        }
        self.assertEqual(measure.native_frame(block, {0x100: 24}), 24)
        self.assertEqual(block["raw_stack_size_bytes"], 24)

    def test_native_alignment_mask_has_bounded_one_shot_adjustment(self) -> None:
        block = {
            "name": "aligned_avx2",
            "lines": ["  100: 48 83 e4 e0  andq $-0x20, %rsp"],
        }
        self.assertIsNone(measure.native_metadata_stack_write_audit(block))
        self.assertEqual(measure.native_alignment_extra(block), (31, None))

    def test_native_alignment_after_branch_stays_unresolved(self) -> None:
        block = {
            "name": "loop_alignment",
            "lines": [
                "  100: 74 02 je 0x104",
                "  102: 48 83 e4 e0 andq $-0x20, %rsp",
            ],
        }
        _, error = measure.native_alignment_extra(block)
        self.assertIn("after control flow", error)

    def test_exact_audited_fixed_buffer_index_uses_full_leaf_redzone(self) -> None:
        address = 0x100
        block = {
            "name": "deny_tag_leaf",
            "lines": ["  100: 88 54 0c c0  movb %dl, -0x40(%rsp,%rcx)"],
            "calls": [],
            "audited_indexed_stack_slots": {
                address: {
                    "base_displacement_bytes": -64,
                    "redzone_depth_bytes": 64,
                    "index_register": "rcx",
                    "index_value_max": 63,
                    "index_scale": 1,
                    "field_offset_bytes": 0,
                    "access_width_bytes": 1,
                    "array_size_bytes": 64,
                    "proof_id": "fixed-64-byte-buffer",
                }
            },
        }
        self.assertEqual(measure.native_redzone_extra(block, 0), (128, None))

    def test_metadata_audit_rejects_dynamic_rsp_adjustment(self) -> None:
        block = {"name": "dynamic", "lines": ["  100: 48 29 c4  subq %rax, %rsp"]}
        self.assertIn("dynamic native RSP adjustment", measure.native_metadata_stack_write_audit(block))

    def test_metadata_audit_rejects_rsp_alias_and_exchange_writes(self) -> None:
        alias = {"name": "alias", "lines": ["  100: 48 83 ec 10  subq $0x10, %esp"]}
        exchange = {"name": "exchange", "lines": ["  100: 48 87 e4  xchgq %rsp, %rax"]}
        pop = {"name": "pop", "lines": ["  100: 5c  popq %rsp"]}
        self.assertIn("stack-pointer alias write", measure.native_metadata_stack_write_audit(alias))
        self.assertIn("exchange involving stack pointer", measure.native_metadata_stack_write_audit(exchange))
        self.assertIn("pop into stack pointer", measure.native_metadata_stack_write_audit(pop))

    def test_only_actual_leaf_redzone_slot_is_counted(self) -> None:
        block = {
            "name": "leaf",
            "lines": ["  100: 48 89 44 24 e0  movq %rax, -0x20(%rsp)"],
            "calls": [],
        }
        self.assertEqual(measure.native_redzone_extra(block, 0), (128, None))

    def test_redzone_slot_with_call_remains_unresolved(self) -> None:
        block = {
            "name": "nonleaf",
            "lines": ["  100: 48 89 44 24 e0  movq %rax, -0x20(%rsp)"],
            "calls": [{"tail": False}],
        }
        _, error = measure.native_redzone_extra(block, 0)
        self.assertIn("function with a call edge", error)

    def test_redzone_slot_with_tail_call_remains_unresolved(self) -> None:
        block = {
            "name": "tail_caller",
            "lines": ["  100: 48 89 44 24 e0  movq %rax, -0x20(%rsp)"],
            "calls": [{"tail": True}],
        }
        _, error = measure.native_redzone_extra(block, 0)
        self.assertIn("function with a call edge", error)

    def test_indexed_redzone_slot_remains_unresolved(self) -> None:
        block = {
            "name": "indexed_leaf",
            "lines": ["  100: 48 89 44 cc f8  movq %rax, -0x8(%rsp,%rcx,8)"],
            "calls": [],
        }
        _, error = measure.native_redzone_extra(block, 0)
        self.assertIn("indexed or otherwise nonconstant", error)

    def test_unanchored_rbp_data_access_is_not_a_stack_access(self) -> None:
        block = {
            "name": "rbp_leaf",
            "lines": ["  100: 48 89 45 f0  movq %rax, -0x10(%rbp)"],
            "calls": [],
        }
        self.assertEqual(measure.native_redzone_extra(block, 32), (0, None))

    def test_anchored_rbp_slot_inside_fixed_frame_is_bounded(self) -> None:
        block = {
            "name": "rbp_frame",
            "lines": [
                "  100: 48 89 e5  movq %rsp, %rbp",
                "  103: 48 83 ec 20  subq $0x20, %rsp",
                "  107: 48 89 45 f0  movq %rax, -0x10(%rbp)",
            ],
            "calls": [],
        }
        self.assertEqual(measure.native_redzone_extra(block, 32), (0, None))

    def test_anchored_rbp_slot_outside_fixed_frame_is_unresolved(self) -> None:
        block = {
            "name": "rbp_frame",
            "lines": [
                "  100: 48 89 e5  movq %rsp, %rbp",
                "  103: 48 83 ec 20  subq $0x20, %rsp",
                "  107: 48 89 45 e0  movq %rax, -0x20(%rbp)",
            ],
            "calls": [],
        }
        _, error = measure.native_redzone_extra(block, 16)
        self.assertIn("exceeds the LLVM fixed frame", error)

    def test_anchored_indexed_rbp_slot_is_unresolved(self) -> None:
        block = {
            "name": "rbp_indexed",
            "lines": [
                "  100: 48 89 e5  movq %rsp, %rbp",
                "  103: 48 83 ec 20  subq $0x20, %rsp",
                "  107: 48 89 44 cd f0  movq %rax, -0x10(%rbp,%rcx,8)",
            ],
            "calls": [],
        }
        _, error = measure.native_redzone_extra(block, 32)
        self.assertIn("indexed RBP-relative", error)

    def test_rbp_anchor_into_caller_stack_is_unresolved(self) -> None:
        block = {
            "name": "rbp_caller_frame",
            "lines": [
                "  100: 48 8d 6c 24 10  leaq 0x10(%rsp), %rbp",
                "  105: 48 89 45 f0  movq %rax, -0x10(%rbp)",
            ],
            "calls": [],
        }
        _, error = measure.native_redzone_extra(block, 32)
        self.assertIn("exceeds the LLVM fixed frame", error)


class ElfEdgeTests(unittest.TestCase):
    def test_bare_jump_outside_decoded_function_stays_unresolved(self) -> None:
        disassembly = """\
00000100 <caller>:
 100: e9 7b 00 00 00 jmp 0x180
 105: c3 retq
00000200 <other>:
 200: c3 retq
"""
        blocks = measure.elf_blocks(disassembly, {})
        caller = blocks["caller"]
        self.assertEqual(len(caller["calls"]), 1)
        self.assertIsNone(caller["calls"][0]["target"])

    def test_register_indirect_edge_never_reuses_stale_target(self) -> None:
        disassembly = """\
00000100 <caller>:
 100: 48 8d 05 10 00 00 00 leaq 0x10(%rip), %rax
 107: 48 c7 c0 00 00 00 00 movq $0x0, %rax
 10e: ff d0 callq *%rax
 110: c3 retq
00000200 <callee>:
 200: c3 retq
"""
        blocks = measure.elf_blocks(disassembly, {})
        edge = blocks["caller"]["calls"][0]
        self.assertTrue(edge["indirect"])
        self.assertIsNone(edge["target"])

    def test_duplicate_symbols_keep_exact_function_entries(self) -> None:
        disassembly = """\
00000100 <caller>:
 100: e8 fb 01 00 00 callq 0x300 <callee>
 105: c3 retq
00000200 <callee>:
 200: c3 retq
00000300 <callee>:
 300: c3 retq
"""
        blocks = measure.elf_blocks(disassembly, {})
        self.assertIn("callee", blocks)
        self.assertIn("callee@0x300", blocks)
        self.assertEqual(blocks["caller"]["calls"][0]["target"], "callee@0x300")


if __name__ == "__main__":
    unittest.main()
