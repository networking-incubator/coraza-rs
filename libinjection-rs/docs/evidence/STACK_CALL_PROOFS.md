# Native SQL call and panic-path evidence (scoped)

Status: **partial source/binary evidence; informational only**. This audit is
scoped to the exact `final_attempt6` SQL x86-64 `legacy` and `legacy_std`
binaries. The WASM section is scoped to the exact report/module hashes stated
there. These measurements do not establish a stack guarantee or gate crate
completion. This is a source and binary inspection record, not a general
assertion that Rust panic paths are impossible.

## Binding

- Report: `/tmp/libinjection-stack-phase5/final_attempt6/report.json`
- Rust source digest in that report:
  `7958e70c1107af787d5a3362d77864dd517a8bad26cfd29e44136b47ec17eb2f`
- Probe source: `libinjection-rs/tools/stack/src/main.rs`, SHA-256
  `367c39af96cf17131b11d3a05c6479676c0691f06410466b07439aa58253c7b0`.
- `legacy` ELF: SHA-256
  `24f09d61d5f1623b59c66d7acfedaea0751a3427a5e8d96307f5bc0cbc7425ca`.
- `legacy_std` ELF: SHA-256
  `cfb8fd8d57179b32abb2b3e1d217a5c768ce4013744c9e5147c5abdbc0a0c25f`.
- Both are report-validated byte-identical `.text` to their uninstrumented
  release binaries. Rust compiler is pinned 1.97.1 in report.
- `Cargo.lock` pins `memchr 2.8.3`, registry checksum
  `cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98`.

## Verified input invariants for the quoted-string memmem path

`SqliToken::parse_string_core` calls `memchr::memmem::find(haystack,
remaining_suffix)` only after `memchr::memchr` returned a delimiter position
`abs`. Thus `abs < haystack.len()` and `remaining_suffix` is exactly
`haystack[abs..]`, a nonempty suffix whose length is at most `haystack.len()`.
The guarded `get` calls cannot introduce an invalid slice. `cursor + rel == abs
<= haystack.len() - 1`; the `abs + 1` close return is therefore in bounds, and
the `abs + 2` doubled-delimiter branch is reached only after a two-byte slice
comparison succeeds.

Its callers bind `length` to `input.len()` (`SqliState::new`, `parse_string`,
`parse_tick`, `parse_estring`). The ordinary string/tick parsers invoke it at
`pos < length` with `offset=1`; escaped strings check `pos + 2 < length` before
`offset=2`; simulated quoting uses `(pos,offset)=(0,0)`. Therefore
`start=pos+offset <= length` on detector-reachable calls and `length-start`
cannot underflow. This proof depends on the current tokenizer’s cursor invariant
`pos <= length` and call guards; it does not bless arbitrary internal calls with
fabricated `length/pos/offset`.

## memchr 2.8.3 panic sites inspected

For the exact SQL chain, final_attempt6 reports panic/error edges in
`FinderBuilder::build_forward_with_ranker`, `Shift::forward`, and their pinned
Rust core panic helpers. The source guards below justify excluding only these
specific error branches if the analyzer keys exclusions to exact callsite
addresses and this ELF hash:

- `Pair::with_ranker` in `src/arch/all/packedpair/mod.rs`: it returns before
  `needle[0]`/`needle[1]` if `needle.len() <= 1`. For longer needles those two
  indices are valid. It initializes distinct indices `(0,1)`. Its iterator is
  `.enumerate().take(255).skip(2)`, so every index converted by either
  `u8::try_from(i).unwrap()` is in `2..=254`; conversion cannot fail. When it
  replaces either pair index, the new index is the current monotonically
  increasing iterator index and the other index is an earlier index; therefore
  `assert_ne!(index1,index2)` cannot fail.
- The two `u8::try_from(i).unwrap()` panic blocks in the optimized Builder are
  call sites at `0x4ef69` and `0x4ef93`; their error blocks are entered by `i >=
  256` branches at `0x4eaa9` and `0x4eaed`. The `.take(255).skip(2)` source
  bound means those branches are unreachable.
- `Pair` offsets remain within the needle: initialization is 0 and 1 after a
  `len>1` check; replacements use enumerated offsets below
  `min(needle.len(),255)`. The packedpair constructors consuming the pair
  therefore cannot index outside `needle`.
- The assert panic call at `0x4efb1` is guarded by the equality branch at
  `0x4eb57`; equality is impossible under the pair-index invariant above.
- In `Suffix::forward`, `candidate_start` starts at 1, and suffix position
  starts at 0. Each transition preserves `suffix.pos <= candidate_start`.
  The loop guard `candidate_start + offset < needle.len()` proves
  `needle[candidate_start + offset]` valid. By the ordering invariant, it also
  proves `needle[suffix.pos + offset]` valid. The `Push` transition increases
  `offset` only while the guard is true; `Accept` and `Skip` advance
  `candidate_start` by at most the just-checked candidate position plus one.
  The optimized `FinderBuilder` bounds panic blocks at `0x4efc4`, `0x4efd4`,
  `0x4efe7`, and `0x4effa` correspond to these guarded accesses and the pair
  offset accesses.
- `Shift::forward` receives `critical_pos` and period from the two
  `Suffix::forward` results. Both suffix positions are within
  `0..needle.len()`. For a nonempty needle, `needle.len() - critical_pos` is
  valid; `critical_pos * 2` cannot overflow because a Rust slice length is at
  most `isize::MAX`. The branch that slices `v[..period_lower_bound]` is
  entered only when `critical_pos * 2 < needle.len()`. `Suffix::forward`'s
  period starts at 1; each reassignment sets period to
  `new_candidate_start - suffix.pos`, with `new_candidate_start <= needle.len()`,
  so `period_lower_bound <= needle.len() - critical_pos`. Thus both
  `split_at(critical_pos)` and that prefix slice are in range. The exact checked
  panic branches in this ELF are `Shift::forward` at `0x5e33d` (critical
  position out of range) and `0x5e356` (period beyond right-suffix length).
- `is_suffix` in `src/arch/all/mod.rs` checks its length relation before forming
  the suffix slice; it does not add another panic source for these inputs.

The addresses above are exact only for the stated `legacy` ELF. `legacy_std` has
a distinct linked image and must have its own address allowlist before filtering
any edge. The downstream `core::panicking::*`, `panic_fmt`, and standard
panic-hook frames are reachable only if an originating branch above is taken;
excluding `core::panicking` globally would be unsound.

## Source-bounded indirect target sets established so far

- `SqliState::check` calls at `0x59b65` and `0x59bbf` load the one-byte memchr
  IFUNC cell through `0x9bbd0 -> RELATIVE 0x9cc60 -> memchr_raw::detect at
  0x5f5d0`. In pinned `src/arch/x86_64/memchr.rs`, the target detector selects
  `find_avx2` when runtime AVX2 is available, otherwise `find_sse2`; this exact
  x86_64 target is compiled with the baseline SSE2 feature, so the
  architecture-independent fallback arm is not available in this binary.
  `memchr2`/`memchr3` use separate corresponding `FN` cells (`0x9cc68`,
  `0x9cc70`) and the same finite AVX2/SSE2 selection pattern.
- `contains_sp_password` uses a fixed 11-byte needle. Its `<64`-byte path uses
  the statically bound `memchr::arch::all::rabinkarp::is_equal_raw` at `0x5f570`
  (`GOT 0x9bbd8`). Its `>=64` path invokes a Finder’s searcher pointer at
  `0x53749`; because the needle length is 11 (within `do_packed_search` 2..=32),
  `Searcher::new` can choose the AVX2 or SSE2 packed searcher in this target,
  not a Two-Way prefilter target.
- `parse::find_subslice` uses one fixed callback: its call at `0x5c24a` loads
  `0x9bb18`, whose relative relocation targets the exact probe `bcmp` shim at
  `0x4e6b0`. Its source is `windows(needle.len()).position(|w| w == needle)`, so
  the callback compares equal-length windows. The shim is in the hashed probe
  body and included in the callgraph.
- `parse_string_core` has memchr pointer calls at `0x521da` and `0x5225c` and
  the memmem Searcher pointer call at `0x524a3`. For memmem, pinned
  `memchr::memmem::find` bypasses FinderBuilder when `haystack.len()<64`;
  otherwise `remaining_suffix` is nonempty. In `Searcher::new`, len 1 chooses
  one-byte; len 2..=32 chooses a packed AVX2/SSE2 searcher when available; len
  >32 chooses Two-Way with AVX2/SSE2 prefilter under default Auto configuration.
  This gives a source-level finite candidate set, but target addresses and frame
  proof for every candidate in both exact ELFs remain to be bound.

## Still unresolved analysis edges

- The local jump tables listed below are now independently checked in both exact
  native binaries. The earlier statement that their target sets were pending is
  superseded by the verification table in the addendum.
- `parse::parse_money` and `parse_xstring` call
  `core::slice::memchr::memchr_aligned` through a fixed relocation, not the
  `memchr` crate IFUNC. All other listed parser raw-byte searches are bound to
  the pinned `memchr` one-byte selector cell as shown below.
- Modern prefilter callback sites (and XSS) are not included in this legacy-only
  proof.
- Several searcher function-pointer paths, std/runtime callbacks,
  panic-hook/external calls, and other detector roots remain unresolved in the
  native graph. Native `legacy` and `legacy_std` have no complete graph totals
  in final_attempt6 (`stack_bytes_upper_bound: null`; resolved-path estimates
  2592 and 4728). The std 4728 path includes a `Pair::with_ranker` assertion
  whose source guard is described above. These are diagnostic values, not a
  stack guarantee or migration gate.
- WASM `legacy,std` and its host/import/call-indirect proof were not
  independently closed here. No WASM engine-stack bound is claimed.

## Addendum: exact profile bindings and control-flow closure

This addendum was checked against the exact `final_attempt6` artifacts named
above. It is restricted to the two x86-64 SQL binaries; it is not a proof for
other compiler versions, linkers, CPUs, source hashes, profiles, targets, or the
WASM engine stack.

### Per-profile binary and lock bindings

- **Profile:** `legacy`
  - **ELF SHA-256:** `24f09d61d5f1623b59c66d7acfedaea0751a3427a5e8d96307f5bc0cbc7425ca`
  - **`.text` SHA-256:** `662f22899576a6fed3555151728400157b85a42395d8b54ef2ebba1f556c4268`
  - **Rust / target:** pinned Rust 1.97.1, `x86_64-unknown-linux-gnu`, no `std`
    feature

- **Profile:** `legacy_std`
  - **ELF SHA-256:** `cfb8fd8d57179b32abb2b3e1d217a5c768ce4013744c9e5147c5abdbc0a0c25f`
  - **`.text` SHA-256:** `d422899c5b23ca6a762066c47fcc723e3e46213393d12131edd891fe5c1f44d5`
  - **Rust / target:** pinned Rust 1.97.1, `x86_64-unknown-linux-gnu`, `std`
    feature

The source digest is
`7958e70c1107af787d5a3362d77864dd517a8bad26cfd29e44136b47ec17eb2f`; the
probe-source SHA-256 is
`367c39af96cf17131b11d3a05c6479676c0691f06410466b07439aa58253c7b0`. Workspace
`Cargo.lock` SHA-256 is
`870b1ca1175524cd2690aee84d444ab4b85357206f8d1f24bb08bebab643d24e`. It pins
`memchr 2.8.3`, package checksum
`cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98`; the relevant
`memmem/searcher.rs` SHA-256 is
`84f6a23bef907696cb672e6898c15fb87008058abc100dde58519d8ec5ebca5d`. Every
address below is a virtual address in the ELF associated with that column. The
instrumentation build had byte-identical `.text` to its plain release companion,
as recorded in the report.

### Verified non-table indirect calls

The x86-64 `memchr` function pointer begins at its detector address, selects a
target once, then stores the chosen function in the cell. Because the no-std
binary is built for x86-64 with baseline SSE2, its source `cfg` excludes
fallback selection. The `std` binary also has AVX2 compiled in and the runtime
feature check selects AVX2 or SSE2. The detector itself remains a possible
first-call target and is included.

- **Source operation / callsite:** `SqliState::check` byte scans: `0x59b65`,
  `0x59bbf` / `0x63e55`, `0x63eaf`
  - **`legacy` target binding:** cell `0x9cc60`; initial `memchr_raw::detect`
    `0x5f5d0`, then SSE2 `find_sse2` `0x5f7b0`
  - **`legacy_std` target binding:** cell `0xe75e8`; initial `detect` `0x6fc20`
    then SSE2 `0x6fcc0` or AVX2 `0x6fc80`

- **Source operation / callsite:** `parse_string_core` delimiter scans:
  `0x521da`, `0x5225c` / `0x63f5a`, `0x63fdc`
  - **`legacy` target binding:** same one-byte selector cell and candidates
    above
  - **`legacy_std` target binding:** same one-byte selector cell and candidates
    above

- **Source operation / callsite:** `parse_dash` newline scans: `0x5ab49`,
  `0x5ac6e`, `0x5ad7c` / `0x6bd19`, `0x6be3e`, `0x6bf4c`
  - **`legacy` target binding:** same one-byte selector cell and candidates
    above
  - **`legacy_std` target binding:** same one-byte selector cell and candidates
    above

- **Source operation / callsite:** `parse_hash` newline scan: `0x5af26` /
  `0x6c0f6`
  - **`legacy` target binding:** same one-byte selector cell and candidates
    above
  - **`legacy_std` target binding:** same one-byte selector cell and candidates
    above

- **Source operation / callsite:** `parse_bword` closing bracket scan: `0x5b3d7`
  / `0x6c5a7`
  - **`legacy` target binding:** same one-byte selector cell and candidates
    above
  - **`legacy_std` target binding:** same one-byte selector cell and candidates
    above

- **Source operation / callsite:** `parse_money`, `parse_xstring` membership
  scans: `0x5b7cc`, `0x5c5c8` / `0x6c99c`, `0x6d798`
  - **`legacy` target binding:** fixed cell `0x9bbc8` relocates to
    `core::slice::memchr::memchr_aligned` at `0x61710`
  - **`legacy_std` target binding:** fixed cell `0xe5e90` relocates to
    `core::slice::memchr::memchr_aligned` at `0xa8830`

- **Source operation / callsite:** `SqliState::fold` tokenization callback:
  `0x57974` / `0x62044`
  - **`legacy` target binding:** fixed cell `0x9bb60` relocates to
    `SqliState::tokenize` at `0x59280`
  - **`legacy_std` target binding:** fixed cell `0xe5e50` relocates to
    `SqliState::tokenize` at `0x63640`

- **Source operation / callsite:** `parse::find_subslice` equal-window callback:
  `0x5c24a` / `0x6d41a`
  - **`legacy` target binding:** fixed cell `0x9bb18` relocates to probe `bcmp`
    shim at `0x4e6b0`
  - **`legacy_std` target binding:** fixed cell `0xe5db0` relocates to probe
    `bcmp` shim at `0x5df50`

For `parse_money` and `parse_xstring`, the Rust source loops over a fixed accept
byte slice and calls `accept.contains(&byte)`. The optimized call uses the core
slice membership routine; the relocation above is the exact target, distinct
from the `memchr` crate’s CPU selector. The C `bcmp` target is part of the
hashed probe body; the shim compares the same-length windows supplied by
`windows(needle.len())`.

Two function pointers select memmem search routines. The quote path calls
`memchr::memmem::find(haystack, remaining_suffix)` at `0x524a3` / `0x6423a`;
`remaining_suffix` is nonempty because it begins at the delimiter index returned
by `memchr`. For haystacks shorter than 64 bytes, pinned `memchr 2.8.3` uses the
direct Rabin-Karp path. For longer haystacks, the finite `Searcher::new`
candidates are:

- **`Searcher::new` routine:** `searcher_kind_one_byte`
  - **`legacy` address:** `0x5eef0`
  - **`legacy_std` address:** `0x71c90`
  - **Input condition:** one-byte needle

- **`Searcher::new` routine:** `searcher_kind_sse2`
  - **`legacy` address:** `0x5e360`
  - **`legacy_std` address:** `0x70f10`
  - **Input condition:** packed search, 2–32-byte needle; SSE2

- **`Searcher::new` routine:** `searcher_kind_avx2`
  - **`legacy` address:** unavailable in this build
  - **`legacy_std` address:** `0x70df0`
  - **Input condition:** packed search, 2–32-byte needle; runtime AVX2

- **`Searcher::new` routine:** `searcher_kind_two_way`
  - **`legacy` address:** `0x5eac0`
  - **`legacy_std` address:** `0x71860`
  - **Input condition:** Two-Way without prefilter if pair/strategy setup
    declines acceleration

- **`Searcher::new` routine:** `searcher_kind_two_way_with_prefilter`
  - **`legacy` address:** `0x5ef20`
  - **`legacy_std` address:** `0x71cc0`
  - **Input condition:** longer needle with a selected prefilter

- **`Searcher::new` routine:** `prefilter_kind_sse2`
  - **`legacy` address:** `0x5e810`
  - **`legacy_std` address:** `0x715b0`
  - **Input condition:** Two-Way prefilter dispatch

- **`Searcher::new` routine:** `prefilter_kind_avx2`
  - **`legacy` address:** unavailable in this build
  - **`legacy_std` address:** `0x713c0`
  - **Input condition:** Two-Way prefilter dispatch with runtime AVX2

The separate `contains_sp_password` call at `0x53749` / `0x663a1` has fixed
needle `b"sp_password"` (11 bytes), so its Finder callback can select only
`searcher_kind_sse2` (`0x5e360` / `0x70f10`) or `searcher_kind_avx2` (std only,
`0x70df0`); the 2–32 byte `do_packed_search` rule applies. Its preceding
equality callback at `0x536e8` / `0x66318` is the fixed
`memchr::arch::all::rabinkarp::is_equal_raw` target (`0x5f570` / `0x72310`). The
candidate set bounds the callback identities, but every transitive frame/call
beneath these routines still has to be closed by the analyzer before claiming a
stack upper bound.

### WASM `Searcher` and `Prefilter` call-dataflow proof

The exact `legacy_std` WASM module SHA-256 is
`e8f68b7391baa21b629326e58292f6ecdfedf69b63a3f6a092fb927a3dfef8b0`; its
code-section SHA-256 is
`e5b46010e508a7d84bed2e2a80b58ba75111cb318eb2e9efa56ea5bb3bfbb135`. The
attempt6/final_final module proof records zero imported tables, one defined
table, zero exported tables, one active element segment with flags `[0]`, no
table mutators, and no unsupported call opcodes. Under those exact module facts,
a host cannot replace the table entries and no runtime table mutation is
present.

The pinned source has a closed set of writes to the private function-pointer
fields in `memchr::memmem::Searcher` and `Prefilter` (`memmem/searcher.rs`
above):

- `Searcher::new` assigns `searcher_kind_empty` only for an empty needle and
  `searcher_kind_one_byte` only for a one-byte needle. Its nonempty multi-byte
  path selects a target-specific packed searcher or calls `Searcher::twoway`.
- For this exact WASM build, the SIMD128 target-feature variants are not
  compiled. The remaining non-x86/non-AArch64 constructor branch calls
  `Searcher::twoway`; that constructor assigns either `searcher_kind_two_way`
  for `None` or `searcher_kind_two_way_with_prefilter` for `Some(Prefilter)`.
- The only compiled WASM `Prefilter` constructor is `Prefilter::fallback`. It
  writes `prefilter_kind_fallback`; if the rank heuristic rejects the prefilter,
  it returns `None` and the `Searcher` callback is `searcher_kind_two_way`
  instead. No std I/O function writes either private function-pointer field.

Consequently the possible `Searcher` targets at the exact WASM table-0 site
`parse_string_core` function 86, call offset `0x1443f`, are
`searcher_kind_one_byte` function 92, `searcher_kind_two_way` function 90, and
`searcher_kind_two_way_with_prefilter` function 94. The source
`remaining_suffix` is nonempty, so `searcher_kind_empty` function 64 is
impossible. At `contains_sp_password` function 69, call offset `0x12afd`, the
fixed 11-byte needle rules out both empty and one-byte kinds, leaving functions
90 and 94. Table 0 has only four type-compatible candidates in the report; these
source guards further reduce them.

At call offsets `0x155fc` and `0x15912` inside
`searcher_kind_two_way_with_prefilter` function 94, the disassembly is
`call_indirect 1`: 1 is the type index and the omitted table index defaults to
table 0. The source flow is `TwoWayWithPrefilter.prestrat` → `Prefilter::call` →
`Prefilter::find`. The constructor proof above binds both calls to
`prefilter_kind_fallback`, function 93. The report's 11 table-0/type-1
candidates include std `Write` methods because their Wasm function signatures
happen to match; there is no assignment path from those methods to the private
`Prefilter::call` field. This narrows those calls only for the exact locked
source and module hash above.

This closes the two listed WASM searcher/prefilter callback sets for
`legacy_std`; it does not establish a WASM engine call-stack bound. The WASM
`legacy_std` detector bound remains open in attempt6 because recursive
panic/allocator/std runtime paths remain in the callgraph, and the analyzer
still has not proved all panic origins unreachable. The `legacy` WASM module has
the same `Searcher` constructor proof and only one table-0/type-1 candidate
(`prefilter_kind_fallback`), but this is not a claim that every runtime edge for
either WASM profile is closed.

### Local relative jump tables: both binaries

The table entries are signed 32-bit displacements from the emitted table base.
For each table, the immediately preceding machine-code path computes an unsigned
bounded index and branches to the fallback when the index exceeds the stated
maximum. I decoded every in-range target from each ELF and confirmed it is an
instruction start within the named function. These entries are local control
flow, not function-pointer calls, and add no call frame.

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy`
  - **Indirect jump:** `0x57660`
  - **Table base:** `0x494d0`
  - **Dominating index bound:** `index <= 0x4e`
  - **In-range entries:** 79
  - **Target validation:** every target is a decoded instruction start inside
    `fold`

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy`
  - **Indirect jump:** `0x57a66`
  - **Table base:** `0x4960c`
  - **Dominating index bound:** `index <= 0x0d`
  - **In-range entries:** 14
  - **Target validation:** same

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy`
  - **Indirect jump:** `0x5868d`
  - **Table base:** `0x49644`
  - **Dominating index bound:** `index <= 0x0d`
  - **In-range entries:** 14
  - **Target validation:** same

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy`
  - **Indirect jump:** `0x58a4d`
  - **Table base:** `0x4967c`
  - **Dominating index bound:** `index <= 0x3a`
  - **In-range entries:** 59
  - **Target validation:** same

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy`
  - **Indirect jump:** `0x58ed5`
  - **Table base:** `0x49768`
  - **Dominating index bound:** `index <= 0x4a`
  - **In-range entries:** 75
  - **Target validation:** same

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy`
  - **Indirect jump:** `0x58f18`
  - **Table base:** `0x49894`
  - **Dominating index bound:** `index <= 0x45`
  - **In-range entries:** 70
  - **Target validation:** same

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy`
  - **Indirect jump:** `0x58f5c`
  - **Table base:** `0x499ac`
  - **Dominating index bound:** `index <= 0x2c`
  - **In-range entries:** 45
  - **Target validation:** same

- **Function:** `parse::dispatch`
  - **ELF profile:** `legacy`
  - **Indirect jump:** `0x5caf2`
  - **Table base:** `0x4b25c`
  - **Dominating index bound:** `index <= 0x7f`
  - **In-range entries:** 128
  - **Target validation:** every target is a decoded instruction start inside
    `dispatch`

- **Function:** `parse::parse_number`
  - **ELF profile:** `legacy`
  - **Indirect jump:** `0x5bf6c`
  - **Table base:** `0x4b104`
  - **Dominating index bound:** `input_byte <= 0x55`
  - **In-range entries:** 86
  - **Target validation:** every in-range target is a decoded instruction start
    inside `parse_number`

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy_std`
  - **Indirect jump:** `0x61d2c`
  - **Table base:** `0x4cb08`
  - **Dominating index bound:** `index <= 0x4e`
  - **In-range entries:** 79
  - **Target validation:** every target is a decoded instruction start inside
    `fold`

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy_std`
  - **Indirect jump:** `0x620a4`
  - **Table base:** `0x4cc44`
  - **Dominating index bound:** `index <= 0x0d`
  - **In-range entries:** 14
  - **Target validation:** same

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy_std`
  - **Indirect jump:** `0x62c7f`
  - **Table base:** `0x4cd68`
  - **Dominating index bound:** `index <= 0x4a`
  - **In-range entries:** 75
  - **Target validation:** same

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy_std`
  - **Indirect jump:** `0x62cc0`
  - **Table base:** `0x4ce94`
  - **Dominating index bound:** `index <= 0x45`
  - **In-range entries:** 70
  - **Target validation:** same

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy_std`
  - **Indirect jump:** `0x62d02`
  - **Table base:** `0x4cfac`
  - **Dominating index bound:** `index <= 0x2c`
  - **In-range entries:** 45
  - **Target validation:** same

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy_std`
  - **Indirect jump:** `0x62e25`
  - **Table base:** `0x4cc7c`
  - **Dominating index bound:** `index <= 0x3a`
  - **In-range entries:** 59
  - **Target validation:** same

- **Function:** `SqliState::fold`
  - **ELF profile:** `legacy_std`
  - **Indirect jump:** `0x633ba`
  - **Table base:** `0x4d060`
  - **Dominating index bound:** `index <= 0x10`
  - **In-range entries:** 17
  - **Target validation:** same

- **Function:** `parse::dispatch`
  - **ELF profile:** `legacy_std`
  - **Indirect jump:** `0x6dcc2`
  - **Table base:** `0x4fbb0`
  - **Dominating index bound:** `index <= 0x7f`
  - **In-range entries:** 128
  - **Target validation:** every target is a decoded instruction start inside
    `dispatch`

- **Function:** `parse::parse_number`
  - **ELF profile:** `legacy_std`
  - **Indirect jump:** `0x6d13c`
  - **Table base:** `0x4fa58`
  - **Dominating index bound:** `input_byte <= 0x55`
  - **In-range entries:** 86
  - **Target validation:** every in-range target is a decoded instruction start
    inside `parse_number`

For `parse_number`, the table has a further physical entry after the 86 in-range
entries, but the decoded input byte is rejected by the `cmp $0x55` / `ja
fallback` guard before the indexed load. That out-of-range table word is not a
reachable target and is not included in the proof.

### legacy_std panic-site mapping

These are the distinct callsite addresses in the `legacy_std` ELF. The
conditions and source invariants are the same as the `legacy` proof above; this
profile has its own address set and must not reuse legacy exclusions.

- **Source panic condition:** `u8::try_from(i).unwrap()` in `Pair::with_ranker`
  - **legacy_std callsite(s):** `FinderBuilder` calls `0x65895`, `0x658c5`;
    error branches at `0x6562c`, `0x6566f`
  - **Guard / invariant:** source iterator is `.enumerate().take(255).skip(2)`,
    so `i` is at most 254 and cannot fail conversion to `u8`

- **Source panic condition:** `assert_ne!(pair.index1(), pair.index2())`
  - **legacy_std callsite(s):** `FinderBuilder` call `0x658e9`; equality branch
    in pair update
  - **Guard / invariant:** indices start as `(0, 1)`; replacements use a new
    monotonically increasing iterator index while the other index is earlier, so
    equality is unreachable

- **Source panic condition:** guarded packedpair needle indexing
  - **legacy_std callsite(s):** `FinderBuilder` bounds panic calls `0x65c9d`,
    `0x65cad`, `0x65cbd`; AVX2 `Finder::with_pair_impl` calls `0x6617e`,
    `0x66194`
  - **Guard / invariant:** Pair indices are valid: initial indices follow
    `needle.len() > 1`; updated indices are below `min(needle.len(), 255)`

- **Source panic condition:** `Suffix::forward` and `Shift::forward` guarded
  slice/index operations
  - **legacy_std callsite(s):** `Finder::new` call `0x660d7`; `Shift::forward`
    calls `0x70dcd`, `0x70de6`
  - **Guard / invariant:** suffix position remains at or before candidate start,
    the loop checks `candidate_start + offset < needle.len()`, critical
    position is in range, and the period lower bound is at most the right-suffix
    length

Only these exact, source-checked origin branches may be excluded, and only for
the `legacy_std` ELF hash above. Panic helpers, Rust standard panic hooks, or
runtime panic frames must never be globally removed. This artifact has not yet
proven that every detector-reachable panic origin in every dependency is
impossible.

### Frame metadata and redzone review

The attempt6 analyzer reads pinned Rust 1.97.1 `-Z emit-stack-sizes` records,
associates each record with an exact function entry address, and confirms the
instrumented and plain release `.text` byte strings match. For native ordinary
calls it adds 8 bytes for the machine return address; tail transfers omit that
charge. The report treats missing metadata as open unless the conservative
prologue proof succeeds.

The SysV redzone implementation is fail-closed: it only charges a redzone
function when the emitted LLVM frame size is zero, there are no ordinary calls,
and all negative `%rsp` offsets are constant; it charges the deepest observed
negative offset. Indexed/nonconstant `%rsp` accesses, negative `%rbp` slots, or
negative `%rsp` slots with a nonzero allocated frame remain unresolved. This is
a conservative restriction, not evidence that every frame is known. A
resolved-path estimate is still not a full-call upper bound while any indirect
target, runtime/external edge, panic origin, cycle, or frame remains unresolved.

### Prior matrix snapshot and freshness gap

`/tmp/libinjection-stack-phase5/current-proof/report.json` uses the same Rust
source digest, probe-source digest, pinned compiler, native ELF hashes, and WASM
module hashes listed above. It records complete WASM table candidate extraction
(no imported/exported tables, no table-mutating instructions, no unsupported
call opcodes), and its declared metric excludes the detector's entry caller,
arbitrary callback frames, native OS/runtime entry, and WASM engine call-stack
overhead. However, that report predates the addition of
`tools/stack/audited_wasm_edges.json` and the corresponding source/hash-keyed
rules in `tools/stack/measure.py`: its `audited_wasm_bindings` arrays are empty.
Treat the outcomes below as a prior analyzer snapshot only; rerun the analyzer
and confirm each applicable binding is marked applied before accepting its WASM
callback closure as final evidence.

- **Profile / target:** `legacy` / `wasm32-wasip1`
  - **Entry:** SQL detector
  - **Archived frame result:** 864 bytes
  - **Archived tool status (diagnostic only):** pass

- **Profile / target:** `legacy` / `wasm32-wasip1`
  - **Entry:** XSS detector
  - **Archived frame result:** 160 bytes
  - **Archived tool status (diagnostic only):** pass

- **Profile / target:** `legacy_std` / `wasm32-wasip1`
  - **Entry:** SQL analysis API
  - **Archived frame result:** 912 bytes
  - **Archived tool status (diagnostic only):** pass

- **Profile / target:** `legacy_std` / `wasm32-wasip1`
  - **Entry:** XSS analysis API
  - **Archived frame result:** 816 bytes
  - **Archived tool status (diagnostic only):** pass

- **Profile / target:** `legacy_std` / `wasm32-wasip1`
  - **Entry:** SQL detector
  - **Archived frame result:** unresolved (2,384-byte resolved-path estimate)
  - **Archived tool status (diagnostic only):** open; 65 unresolved edges

- **Profile / target:** `legacy_std` / `wasm32-wasip1`
  - **Entry:** XSS detector
  - **Archived frame result:** 160 bytes
  - **Archived tool status (diagnostic only):** pass

- **Profile / target:** `legacy` / `x86_64-unknown-linux-gnu`
  - **Entry:** SQL detector
  - **Archived frame result:** unresolved (2,064-byte resolved-path estimate)
  - **Archived tool status (diagnostic only):** open; 25 unresolved edges

- **Profile / target:** `legacy` / `x86_64-unknown-linux-gnu`
  - **Entry:** XSS detector
  - **Archived frame result:** unresolved (360-byte resolved-path estimate)
  - **Archived tool status (diagnostic only):** open; 10 unresolved edges

- **Profile / target:** `legacy_std` / `x86_64-unknown-linux-gnu`
  - **Entry:** SQL detector
  - **Archived frame result:** unresolved (3,472-byte resolved-path estimate)
  - **Archived tool status (diagnostic only):** open; 72 unresolved edges

- **Profile / target:** `legacy_std` / `x86_64-unknown-linux-gnu`
  - **Entry:** XSS detector
  - **Archived frame result:** unresolved (360-byte resolved-path estimate)
  - **Archived tool status (diagnostic only):** open; 10 unresolved edges

The archived WASM “pass” labels refer only to the then-current analyzer's Rust
linear-memory `__stack_pointer` frame calculation for its enumerated detector
call graph. They do not describe WASM engine or native host call stacks and are
not a release verdict. Native SQL still has unresolved indirect callbacks,
parser/tokenizer frame cases, and panic/runtime edges; native XSS still has
indirect callbacks and unresolved frame paths. A resolved-path estimate is
not a complete graph total while any such edge is unresolved.
