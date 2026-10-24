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

#![no_main]

use coraza::transaction::Transaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (mode, target) = data.split_first().map_or((0, data), |(mode, rest)| (*mode, rest));

    // The connector hands over the request target as raw bytes; the parser itself
    // takes the text form, so non-UTF-8 inputs take the same lossy conversion a
    // connector performs.
    let mut tx = Transaction::new("uri-fuzz");
    tx.set_request_uri(target);
    let target = String::from_utf8_lossy(target);

    let (method, protocol) = match mode % 5 {
        0 => ("GET", "HTTP/1.1"),
        1 => ("POST", "HTTP/1.1"),
        2 => ("OPTIONS", "HTTP/1.1"),
        3 => ("PROPFIND", "HTTP/1.1"),
        _ => ("GET", "HTTP/2.0"),
    };
    tx.process_uri(&target, method, protocol);
    let _ = std::hint::black_box(tx.last_phase());
});
