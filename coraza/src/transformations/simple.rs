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
//
// This port is based on the original Coraza, created by Juan Pablo Tosso and
// the OWASP Coraza contributors.
//
// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! Simple byte-oriented transformations.

use crate::{transformations::TransformationResult, utils::strings::x2c};

/// ASCII whitespace bytes trimmed by these transformations.
const TRIM_SPACES: &[u8] = b" \t\n\r\x0c\x0b";

/// Converts UTF-8 text to lowercase and preserves malformed input bytes.
///
/// Valid UTF-8 segments use Unicode lowercase rules. Invalid byte sequences
/// are copied unchanged.
pub fn lowercase(input: &[u8]) -> TransformationResult {
    let transformed = map_case(input, true);
    let changed = transformed.as_slice() != input;
    (transformed, changed, None)
}

/// Converts UTF-8 text to uppercase and preserves malformed input bytes.
///
/// Valid UTF-8 segments use Unicode uppercase rules. Invalid byte sequences
/// are copied unchanged.
pub fn uppercase(input: &[u8]) -> TransformationResult {
    let transformed = map_case(input, false);
    let changed = transformed.as_slice() != input;
    (transformed, changed, None)
}

/// Removes leading and trailing ASCII whitespace.
pub fn trim(input: &[u8]) -> TransformationResult {
    let start = input
        .iter()
        .position(|byte| !is_trim_space(*byte))
        .unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|byte| !is_trim_space(*byte))
        .map_or(start, |position| position + 1);
    let transformed = input.get(start..end).unwrap_or_default().to_vec();
    let changed = start != 0 || end != input.len();
    (transformed, changed, None)
}

/// Removes leading ASCII whitespace.
pub fn trim_left(input: &[u8]) -> TransformationResult {
    let start = input
        .iter()
        .position(|byte| !is_trim_space(*byte))
        .unwrap_or(input.len());
    let transformed = input.get(start..).unwrap_or_default().to_vec();
    (transformed, start != 0, None)
}

/// Removes trailing ASCII whitespace.
pub fn trim_right(input: &[u8]) -> TransformationResult {
    let end = input
        .iter()
        .rposition(|byte| !is_trim_space(*byte))
        .map_or(0, |position| position + 1);
    let transformed = input.get(..end).unwrap_or_default().to_vec();
    (transformed, end != input.len(), None)
}

/// Removes Unicode whitespace from valid UTF-8 and preserves malformed bytes.
pub fn remove_whitespace(input: &[u8]) -> TransformationResult {
    let mut transformed = Vec::with_capacity(input.len());
    for_each_utf8(input, |item| match item {
        Ok(character) if !character.is_whitespace() => {
            let mut buffer = [0; 4];
            transformed.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
        },
        Ok(_) => {},
        Err(byte) => transformed.push(byte),
    });
    let changed = transformed.as_slice() != input;
    (transformed, changed, None)
}

/// Compresses each run of Unicode whitespace to one space byte.
///
/// Malformed UTF-8 bytes are copied unchanged.
pub fn compress_whitespace(input: &[u8]) -> TransformationResult {
    let mut transformed = Vec::with_capacity(input.len());
    let mut in_whitespace = false;
    for_each_utf8(input, |item| match item {
        Ok(character) if character.is_whitespace() => {
            if !in_whitespace {
                transformed.push(b' ');
            }
            in_whitespace = true;
        },
        Ok(character) => {
            let mut buffer = [0; 4];
            transformed.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            in_whitespace = false;
        },
        Err(byte) => {
            transformed.push(byte);
            in_whitespace = false;
        },
    });

    let changed = transformed.as_slice() != input;
    (transformed, changed, None)
}

/// Decodes percent escapes and changes plus bytes to spaces.
///
/// Invalid percent escapes are copied unchanged. The result may contain any
/// byte value, including zero and bytes that are not valid UTF-8.
pub fn url_decode(input: &[u8]) -> TransformationResult {
    let Some(start) = input.iter().position(|byte| matches!(*byte, b'%' | b'+')) else {
        return (input.to_vec(), false, None);
    };

    let mut transformed = Vec::with_capacity(input.len());
    transformed.extend_from_slice(input.get(..start).unwrap_or_default());
    let mut offset = start;
    while let Some(&byte) = input.get(offset) {
        match byte {
            b'%' => {
                let decoded = offset
                    .checked_add(3)
                    .and_then(|end| input.get(offset + 1..end))
                    .and_then(x2c);
                if let Some(decoded) = decoded {
                    transformed.push(decoded);
                    offset += 3;
                } else {
                    transformed.push(byte);
                    offset += 1;
                }
            },
            b'+' => {
                transformed.push(b' ');
                offset += 1;
            },
            _ => {
                transformed.push(byte);
                offset += 1;
            },
        }
    }

    (transformed, true, None)
}

/// Maps valid UTF-8 segments and copies malformed bytes unchanged.
fn map_case(input: &[u8], lowercase: bool) -> Vec<u8> {
    let mut transformed = Vec::with_capacity(input.len());
    for_each_utf8(input, |item| match item {
        Ok(character) => {
            if lowercase {
                for mapped in character.to_lowercase() {
                    let mut buffer = [0; 4];
                    transformed.extend_from_slice(mapped.encode_utf8(&mut buffer).as_bytes());
                }
            } else {
                for mapped in character.to_uppercase() {
                    let mut buffer = [0; 4];
                    transformed.extend_from_slice(mapped.encode_utf8(&mut buffer).as_bytes());
                }
            }
        },
        Err(byte) => transformed.push(byte),
    });
    transformed
}

/// Visits valid UTF-8 characters and reports malformed bytes individually.
fn for_each_utf8(input: &[u8], mut visit: impl FnMut(Result<char, u8>)) {
    let mut offset = 0;
    while let Some(remaining) = input.get(offset..) {
        if remaining.is_empty() {
            break;
        }

        match std::str::from_utf8(remaining) {
            Ok(text) => {
                for character in text.chars() {
                    visit(Ok(character));
                }
                break;
            },
            Err(error) => {
                let valid_len = error.valid_up_to();
                if let Some(valid) = remaining
                    .get(..valid_len)
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                {
                    for character in valid.chars() {
                        visit(Ok(character));
                    }
                }

                let invalid_len = error
                    .error_len()
                    .unwrap_or_else(|| remaining.len().saturating_sub(valid_len));
                let invalid_end = valid_len.saturating_add(invalid_len).min(remaining.len());
                if let Some(invalid) = remaining.get(valid_len..invalid_end) {
                    for byte in invalid {
                        visit(Err(*byte));
                    }
                }
                offset = offset.saturating_add(invalid_end);
            },
        }
    }
}

/// Returns whether `byte` is one of the supported ASCII whitespace bytes.
fn is_trim_space(byte: u8) -> bool {
    TRIM_SPACES.contains(&byte)
}
