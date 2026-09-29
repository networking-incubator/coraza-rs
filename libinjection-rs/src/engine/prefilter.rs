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

//! Fast prefilter: skip obviously benign inputs before normalization.

use memchr::memchr3;

use crate::engine::ascii::find_ignore_ascii_case;

/// True if the input may contain SQLi-relevant bytes.
#[must_use]
pub(crate) fn sqli_may_be_interesting(input: &[u8]) -> bool {
    if input.is_empty() {
        return false;
    }
    if memchr3(b'\'', b'"', b';', input).is_some() {
        return true;
    }
    // Secondary scan for comment/keyword triggers.
    memchr::memchr2(b'-', b'#', input).is_some()
        || memchr::memchr(b'/', input).is_some()
        || memchr::memchr(b'\\', input).is_some()
        || memchr::memchr(b'(', input).is_some()
        || memchr::memchr(b')', input).is_some()
        || memchr::memchr(b'=', input).is_some()
        || memchr::memchr(b'[', input).is_some()
        || find_ignore_ascii_case(input, b"union").is_some()
        || find_ignore_ascii_case(input, b"select").is_some()
        || find_ignore_ascii_case(input, b" or ").is_some()
        || find_ignore_ascii_case(input, b" and ").is_some()
        || find_ignore_ascii_case(input, b"exec").is_some()
        || find_ignore_ascii_case(input, b"xp_cmdshell").is_some()
        || find_ignore_ascii_case(input, b"waitfor delay").is_some()
        || find_ignore_ascii_case(input, b"dual").is_some()
        || find_ignore_ascii_case(input, b"q'").is_some()
}

/// True if the input may contain XSS-relevant bytes.
#[must_use]
pub(crate) fn xss_may_be_interesting(input: &[u8]) -> bool {
    if input.is_empty() {
        return false;
    }
    memchr::memchr(b'<', input).is_some()
        || memchr::memchr(b'>', input).is_some()
        || memchr::memchr(b'&', input).is_some()
        || memchr::memchr(b'\'', input).is_some()
        || memchr::memchr(b'"', input).is_some()
        || memchr::memchr(b'`', input).is_some()
        || find_ignore_ascii_case(input, b"javascript:").is_some()
        || find_ignore_ascii_case(input, b"data:").is_some()
        || find_ignore_ascii_case(input, b"vbscript:").is_some()
        || find_ignore_ascii_case(input, b"view-source:").is_some()
        || find_ignore_ascii_case(input, b"java:").is_some()
        || find_ignore_ascii_case(input, b"%3c").is_some()
        || find_ignore_ascii_case(input, b"<script").is_some()
        || find_ignore_ascii_case(input, b"onerror").is_some()
        || memchr::memchr2(b'=', b'(', input).is_some()
}
