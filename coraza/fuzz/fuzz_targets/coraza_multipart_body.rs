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

/// Select the multipart processor with a phase 1 `ctl`, as a connector rule does, so the
/// parser also sees content types the automatic selection rejects.
const MULTIPART_RULES: &str = "SecRequestBodyAccess On\n\
                               SecAction \"id:1,phase:1,ctl:requestBodyProcessor=MULTIPART,pass\"";

/// The compiled WAF is immutable, so build it once instead of compiling rules per input.
fn multipart_waf() -> &'static Waf {
    static WAF: OnceLock<Waf> = OnceLock::new();
    WAF.get_or_init(|| {
        let mut parser = Parser::new();
        parser
            .from_string(MULTIPART_RULES)
            .expect("fuzz multipart rules compile");
        parser.into_waf().expect("fuzz multipart WAF is valid")
    })
}

fuzz_target!(|data: &[u8]| {
    let (mode, rest) = data.split_first().map_or((0, data), |(mode, rest)| (*mode, rest));
    // Split the boundary from the body at the first newline so the seed corpus can pair
    // a boundary with a body that uses it. Malformed pairs stay interesting.
    let (boundary, body) = rest
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or((rest, &[][..]), |newline| {
            (
                rest.get(..newline).unwrap_or_default(),
                rest.get(newline.saturating_add(1)..).unwrap_or_default(),
            )
        });
    let boundary = String::from_utf8_lossy(boundary);

    // Vary the content type so the parser sees quoted boundaries, non-form-data
    // multipart types, and types it must reject.
    let content_type = match mode % 4 {
        0 => format!("multipart/form-data; boundary={boundary}"),
        1 => format!("multipart/form-data; boundary=\"{boundary}\""),
        2 => format!("multipart/mixed; boundary={boundary}"),
        _ => format!("text/plain; boundary={boundary}"),
    };

    let mut tx = multipart_waf().new_transaction();
    tx.add_request_header("Content-Type", content_type);
    tx.process_request_headers();
    let _ = tx.process_request_body(body);
});
