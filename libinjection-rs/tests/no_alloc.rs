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

//! Zero-allocation gate for legacy `detect_*` hot paths.
//! This is used only on the test to guarantee that no heap allocation happens
//! on hot path

#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(unsafe_code, reason = "counting #[global_allocator] for no-alloc regression test")]
#![expect(
    clippy::let_underscore_must_use,
    reason = "verdict return value intentionally discarded in alloc gate"
)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
};

use libinjection::{AnalyzeOptions, analyze_sqli, analyze_xss, detect_sqli, detect_sqli_with, detect_xss};

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

fn assert_no_alloc<F: FnOnce()>(f: F) {
    let before = ALLOCATION_CALLS.load(Ordering::SeqCst);
    f();
    assert_eq!(
        ALLOCATION_CALLS.load(Ordering::SeqCst),
        before,
        "unexpected heap allocation on hot path"
    );
}

#[test]
fn legacy_hot_paths_no_alloc() {
    assert_no_alloc(|| {
        let _ = detect_sqli(b"1' OR '1'='1");
    });
    assert_no_alloc(|| {
        let _ = detect_xss(b"<script>alert(1)</script>");
    });
    assert_no_alloc(|| {
        let input = [b'a'; 9000];
        let _ = detect_sqli_with(&input, AnalyzeOptions::default());
    });
    assert_no_alloc(|| {
        let _ = analyze_sqli(b"1' UNION SELECT 1");
    });
    assert_no_alloc(|| {
        let _ = analyze_xss(b"<script>x</script>");
    });
}
