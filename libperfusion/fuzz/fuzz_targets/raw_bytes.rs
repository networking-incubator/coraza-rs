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

use libfuzzer_sys::fuzz_target;

mod support;

/// Upper bound on generated inputs.  Pass `-max_len=262144` to the fuzzer to
/// match.  This is 4× [`libperfusion::MAX_INPUT_LEN`] so the rejection path
/// is exercised with a variety of overlarge payloads.
const MAX_LEN: usize = 262_144;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_LEN {
        return;
    }
    support::exercise_raw(data);
});
