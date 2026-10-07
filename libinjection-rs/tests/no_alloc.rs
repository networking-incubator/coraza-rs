// Copyright Coraza Kubernetes Operator contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Zero-allocation regression guard for the legacy compatibility hot paths.
#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(unsafe_code, reason = "counting #[global_allocator] for no-alloc regression test")]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicUsize, Ordering},
};

use libinjection::{XssHtmlContext, detect_sqli, detect_xss, html5_visit};

static ALLOCATION_CALLS: AtomicUsize = AtomicUsize::new(0);

struct CountingAlloc;

// SAFETY: delegates allocation accounting to the system allocator.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATION_CALLS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: forwards to the platform default allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwards to the platform default allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

const CONTEXTS: [XssHtmlContext; 5] = [
    XssHtmlContext::Data,
    XssHtmlContext::AttrUnquoted,
    XssHtmlContext::AttrSingle,
    XssHtmlContext::AttrDouble,
    XssHtmlContext::AttrBacktick,
];

fn long_comment() -> Vec<u8> {
    let mut input = Vec::with_capacity(65_537);
    input.extend_from_slice(b"/*");
    input.resize(65_535, b'x');
    input.extend_from_slice(b"*/");
    input
}

fn assert_no_alloc(label: &str, operation: impl FnOnce()) {
    let before = ALLOCATION_CALLS.load(Ordering::SeqCst);
    operation();
    let after = ALLOCATION_CALLS.load(Ordering::SeqCst);
    assert_eq!(
        after,
        before,
        "{label} allocated {delta} time(s)",
        delta = after - before
    );
}

fn check_compatibility_hot_paths_and_html_contexts() {
    static BENIGN: &[u8] = b"ordinary request value without parser markers";
    static SQL_ATTACK: &[u8] = b"1' UNION SELECT password FROM users WHERE '1'='1";
    static XSS_ATTACK: &[u8] = b"<a href=javascript:alert(1) onerror=alert(1)>";
    static BINARY: &[u8] = &[0xFF, 0x00, b'\'', 0x80, b'<', b'>'];
    static LONG_UNARY: [u8; 65_537] = [b'+'; 65_537];
    static LONG_HTML: [u8; 65_537] = [b'/'; 65_537];
    let long_comment = long_comment();

    for input in [
        black_box(BENIGN),
        black_box(SQL_ATTACK),
        black_box(BINARY),
        black_box(&LONG_UNARY[..]),
        black_box(long_comment.as_slice()),
        black_box(&LONG_HTML[..]),
    ] {
        assert_no_alloc("detect_sqli", || {
            black_box(detect_sqli(black_box(input)));
        });
        assert_no_alloc("detect_xss", || {
            black_box(detect_xss(black_box(input)));
        });
    }

    for context in CONTEXTS {
        let input = black_box(XSS_ATTACK);
        assert_no_alloc("html5_visit context", || {
            let mut token_count = 0_usize;
            html5_visit(black_box(input), black_box(context), |kind, value| {
                token_count = token_count.wrapping_add(usize::from(kind as u8));
                token_count = token_count.wrapping_add(value.len());
                black_box(token_count);
            });
            black_box(token_count);
        });
    }
}

// Keep a single test case in this binary: independent Rust test threads would
// include their harness allocations in the process-global allocation count.
#[test]
fn legacy_hot_paths_do_not_allocate() {
    check_compatibility_hot_paths_and_html_contexts();
}
