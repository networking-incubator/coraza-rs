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

use std::{hint::black_box, process, time::Instant};

use libinjection::{AnalyzeOptions, analyze_sqli_with, analyze_xss_with, limits::DEFAULT_MAX_INPUT_LEN};

#[cfg(feature = "count-allocations")]
mod allocations {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    static ACTIVE: AtomicBool = AtomicBool::new(false);
    static ALLOCATION_CALLS: AtomicUsize = AtomicUsize::new(0);
    static ALLOCATED_BYTES: AtomicUsize = AtomicUsize::new(0);
    static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
    static PEAK_LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

    pub struct CountingAllocator;

    #[global_allocator]
    static GLOBAL: CountingAllocator = CountingAllocator;

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: This forwards the allocation request unchanged to the system allocator.
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() && ACTIVE.load(Ordering::Relaxed) {
                record_allocation(layout.size());
            }
            pointer
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: This forwards the allocation request unchanged to the system allocator.
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() && ACTIVE.load(Ordering::Relaxed) {
                record_allocation(layout.size());
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            if ACTIVE.load(Ordering::Relaxed) {
                LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
            }
            // SAFETY: The pointer and layout are passed through from the caller unchanged.
            unsafe { System.dealloc(pointer, layout) };
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            // SAFETY: This forwards the original allocation and requested size unchanged.
            let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
            if !new_pointer.is_null() && ACTIVE.load(Ordering::Relaxed) {
                ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
                ALLOCATED_BYTES.fetch_add(new_size, Ordering::Relaxed);
                if new_size >= layout.size() {
                    let live =
                        LIVE_BYTES.fetch_add(new_size - layout.size(), Ordering::Relaxed) + (new_size - layout.size());
                    update_peak(live);
                } else {
                    LIVE_BYTES.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
                }
            }
            new_pointer
        }
    }

    fn record_allocation(size: usize) {
        ALLOCATION_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(size, Ordering::Relaxed);
        let live = LIVE_BYTES.fetch_add(size, Ordering::Relaxed) + size;
        update_peak(live);
    }

    fn update_peak(live: usize) {
        let mut peak = PEAK_LIVE_BYTES.load(Ordering::Relaxed);
        while live > peak {
            match PEAK_LIVE_BYTES.compare_exchange_weak(peak, live, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => break,
                Err(current) => peak = current,
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub struct Stats {
        pub calls: usize,
        pub bytes: usize,
        pub peak_live_bytes: usize,
    }

    pub fn measure<T>(run: impl FnOnce() -> T) -> (T, Stats) {
        ALLOCATION_CALLS.store(0, Ordering::Relaxed);
        ALLOCATED_BYTES.store(0, Ordering::Relaxed);
        LIVE_BYTES.store(0, Ordering::Relaxed);
        PEAK_LIVE_BYTES.store(0, Ordering::Relaxed);
        ACTIVE.store(true, Ordering::Relaxed);
        let output = run();
        ACTIVE.store(false, Ordering::Relaxed);
        let stats = Stats {
            calls: ALLOCATION_CALLS.load(Ordering::Relaxed),
            bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
            peak_live_bytes: PEAK_LIVE_BYTES.load(Ordering::Relaxed),
        };
        (output, stats)
    }
}

#[cfg(not(feature = "count-allocations"))]
mod allocations {
    #[derive(Clone, Copy, Debug)]
    pub struct Stats {
        pub calls: usize,
        pub bytes: usize,
        pub peak_live_bytes: usize,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Latency,
    Allocations,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("analysis scaling driver failed: {error}");
        process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut rounds = 11_usize;
    let mut mode = Mode::Latency;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--rounds" => {
                rounds = args
                    .next()
                    .ok_or("--rounds needs a value")?
                    .parse()
                    .map_err(|_| "--rounds must be an integer")?;
            },
            "--mode" => {
                mode = match args.next().as_deref() {
                    Some("latency") => Mode::Latency,
                    Some("allocations") => Mode::Allocations,
                    _ => return Err("--mode must be latency or allocations".into()),
                };
            },
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    if !(3..=101).contains(&rounds) {
        return Err("--rounds must be between 3 and 101".into());
    }
    if mode == Mode::Allocations && !cfg!(feature = "count-allocations") {
        return Err("allocation mode requires --features count-allocations".into());
    }

    println!(
        "detector\tencoding\tinput_bytes\tscan_limit\tmedian_ns\talloc_calls\talloc_bytes\tpeak_live_bytes\tdistinct_spans"
    );
    for (detector, encoding, pattern, sizes) in workloads() {
        for input_bytes in sizes {
            let input = repeat_exact(pattern, input_bytes);
            let scan_limit = input.len().max(DEFAULT_MAX_INPUT_LEN);
            match mode {
                Mode::Latency => {
                    let (median_ns, evidence_count) = measure_latency(detector, &input, scan_limit, rounds);
                    println!(
                        "{detector}\t{encoding}\t{input_bytes}\t{scan_limit}\t{median_ns}\t-\t-\t-\t{evidence_count}"
                    );
                },
                Mode::Allocations => {
                    let (stats, evidence_count) = measure_allocations(detector, &input, scan_limit, rounds);
                    println!(
                        "{detector}\t{encoding}\t{input_bytes}\t{scan_limit}\t-\t{}\t{}\t{}\t{evidence_count}",
                        median(stats.iter().map(|sample| sample.calls).collect()),
                        median(stats.iter().map(|sample| sample.bytes).collect()),
                        median(stats.iter().map(|sample| sample.peak_live_bytes).collect()),
                    );
                },
            }
        }
    }
    Ok(())
}

fn workloads() -> Vec<(&'static str, &'static str, &'static [u8], Vec<usize>)> {
    vec![
        ("sqli", "raw", b"OR 1=1", vec![1024, 2048, 4096, 8192, 16384]),
        (
            "sqli",
            "percent_encoded",
            b"%4F%52%20%31%3D%31",
            vec![1536, 3072, 6144, 12288, 24576],
        ),
        ("xss", "raw", b"<script>", vec![1024, 2048, 4096, 8192, 16384]),
        (
            "xss",
            "percent_encoded",
            b"%3Cscript%3E",
            vec![1536, 3072, 6144, 12288, 24576],
        ),
    ]
}

fn repeat_exact(pattern: &[u8], len: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(len);
    while input.len() < len {
        input.extend_from_slice(pattern);
    }
    input.truncate(len);
    input
}

fn run_analyzer(detector: &str, input: &[u8], scan_limit: usize) -> usize {
    let options = AnalyzeOptions {
        max_input_len: scan_limit,
    };
    let snapshot = match detector {
        "sqli" => analyze_sqli_with(input, options),
        "xss" => analyze_xss_with(input, options),
        _ => unreachable!("workload detector is fixed above"),
    };
    let evidence_count = snapshot.evidence.spans.len();
    black_box(&snapshot);
    drop(snapshot);
    evidence_count
}

fn measure_latency(detector: &str, input: &[u8], scan_limit: usize, rounds: usize) -> (usize, usize) {
    for _ in 0..3 {
        black_box(run_analyzer(detector, input, scan_limit));
    }
    let mut samples = Vec::with_capacity(rounds);
    let mut evidence_count = 0;
    for _ in 0..rounds {
        let start = Instant::now();
        evidence_count = run_analyzer(detector, input, scan_limit);
        samples.push(start.elapsed().as_nanos() as usize);
        black_box(evidence_count);
    }
    (median(samples), evidence_count)
}

#[cfg(feature = "count-allocations")]
fn measure_allocations(
    detector: &str,
    input: &[u8],
    scan_limit: usize,
    rounds: usize,
) -> (Vec<allocations::Stats>, usize) {
    let mut samples = Vec::with_capacity(rounds);
    let mut evidence_count = 0;
    for _ in 0..rounds {
        let (count, stats) = allocations::measure(|| run_analyzer(detector, input, scan_limit));
        evidence_count = count;
        samples.push(stats);
        black_box(evidence_count);
    }
    (samples, evidence_count)
}

#[cfg(not(feature = "count-allocations"))]
fn measure_allocations(
    _detector: &str,
    _input: &[u8],
    _scan_limit: usize,
    _rounds: usize,
) -> (Vec<allocations::Stats>, usize) {
    unreachable!("allocation mode is rejected before workloads run")
}

fn median(mut values: Vec<usize>) -> usize {
    values.sort_unstable();
    values[values.len() / 2]
}
