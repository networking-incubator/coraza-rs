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

#![no_std]
#![no_main]

//! Minimal standalone roots for optimized detector stack measurement.
//! The driver stays `no_std`/`no_main` to avoid a standard process entrypoint;
//! the libinjection library under measurement always uses `std`.

use core::hint::black_box;

static INPUT: [u8; 1024] = [b'x'; 1024];

#[inline(never)]
#[cfg(feature = "legacy")]
fn stack_entry_detect_sqli(input: &[u8]) {
    black_box(libinjection::detect_sqli(black_box(input)));
}

#[inline(never)]
#[cfg(feature = "legacy")]
fn stack_entry_detect_xss(input: &[u8]) {
    black_box(libinjection::detect_xss(black_box(input)));
}

#[inline(never)]
fn stack_entry_analyze_sqli(input: &[u8]) {
    black_box(libinjection::analyze_sqli(black_box(input)));
}

#[inline(never)]
fn stack_entry_analyze_xss(input: &[u8]) {
    black_box(libinjection::analyze_xss(black_box(input)));
}

fn run_detector_roots() -> ! {
    let input = black_box(&INPUT);

    #[cfg(feature = "legacy")]
    {
        stack_entry_detect_sqli(input);
        stack_entry_detect_xss(input);
    }
    stack_entry_analyze_sqli(input);
    stack_entry_analyze_xss(input);

    loop {
        core::hint::spin_loop();
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    run_detector_roots()
}

// wasi's self-contained command CRT owns `_start` and calls this C main shim.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn __main_void() -> i32 {
    run_detector_roots()
}

// The linked production code can lower slice comparisons and aggregate
// initialization to these C ABI helpers. Keep their bodies visible to the
// call-graph and stack analyzer instead of adding libc to this probe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(left: *const u8, right: *const u8, count: usize) -> i32 {
    for index in 0..count {
        let (left_byte, right_byte) = unsafe { (*left.add(index), *right.add(index)) };
        if left_byte != right_byte {
            return 1;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, count: usize) -> i32 {
    for index in 0..count {
        let (left_byte, right_byte) = unsafe { (*left.add(index), *right.add(index)) };
        if left_byte != right_byte {
            return i32::from(left_byte) - i32::from(right_byte);
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(destination: *mut u8, source: *const u8, count: usize) -> *mut u8 {
    for index in 0..count {
        let byte = unsafe { source.add(index).read_volatile() };
        unsafe { destination.add(index).write_volatile(byte) };
    }
    destination
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(destination: *mut u8, value: i32, count: usize) -> *mut u8 {
    for index in 0..count {
        unsafe { destination.add(index).write(value as u8) };
    }
    destination
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn __wasi_init_tp() {}
