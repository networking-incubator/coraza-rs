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

use std::sync::OnceLock;

use coraza::{seclang::Parser, waf::Waf};
use libfuzzer_sys::fuzz_target;

/// Select the JSON request body processor the way a connector rule does: phase 1 runs
/// before the body phase and applies the `ctl` action to every transaction.
const JSON_RULES: &str = "SecRequestBodyAccess On\n\
                          SecAction \"id:1,phase:1,ctl:requestBodyProcessor=JSON,pass\"";

/// The compiled WAF is immutable, so build it once instead of compiling rules per input.
fn json_waf() -> &'static Waf {
    static WAF: OnceLock<Waf> = OnceLock::new();
    WAF.get_or_init(|| {
        let mut parser = Parser::new();
        parser.from_string(JSON_RULES).expect("fuzz JSON rules compile");
        parser.into_waf().expect("fuzz JSON WAF is valid")
    })
}

fuzz_target!(|data: &[u8]| {
    let mut tx = json_waf().new_transaction();
    tx.process_request_headers();
    let _ = tx.process_request_body(data);
});
