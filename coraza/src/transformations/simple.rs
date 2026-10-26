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

use crate::{
    transformations::TransformationResult,
    utils::{lowercase_char, strings::x2c, uppercase_char},
};

/// ASCII whitespace bytes trimmed by these transformations.
const TRIM_SPACES: &[u8] = b" \t\n\r\x0c\x0b";

/// Converts UTF-8 text to lowercase the way Go's `strings.ToLower` does.
///
/// Valid UTF-8 uses Go's simple case mapping. Each byte that is not part of a
/// valid UTF-8 sequence becomes U+FFFD, as Go's rune iteration does.
pub fn lowercase(input: &[u8]) -> TransformationResult {
    let transformed = map_case(input, true);
    let changed = transformed.as_slice() != input;
    (transformed, changed, None)
}

/// Converts UTF-8 text to uppercase the way Go's `strings.ToUpper` does.
///
/// Valid UTF-8 uses Go's simple case mapping. Each byte that is not part of a
/// valid UTF-8 sequence becomes U+FFFD, as Go's rune iteration does.
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

/// Compresses each run of Latin-1 whitespace to one space byte.
///
/// Only ASCII whitespace, U+0085, U+00A0 and a stray `0xA0` byte collapse.
/// Other Unicode space characters such as U+3000 and malformed bytes are
/// copied unchanged.
pub fn compress_whitespace(input: &[u8]) -> TransformationResult {
    let mut transformed = Vec::with_capacity(input.len());
    let mut changed = false;
    let mut in_whitespace = false;
    for_each_utf8(input, |item| {
        let whitespace = match item {
            Ok(character) => is_latin_space(character),
            Err(byte) => byte == 0xA0,
        };
        if whitespace {
            if in_whitespace {
                changed = true;
            } else {
                in_whitespace = true;
                changed |= item != Ok(' ');
                transformed.push(b' ');
            }
            return;
        }

        in_whitespace = false;
        match item {
            Ok(character) => {
                let mut buffer = [0; 4];
                transformed.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            },
            Err(byte) => transformed.push(byte),
        }
    });

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

/// Normalizes a command line as Go Coraza's `t:cmdLine` does.
///
/// Removes quotes, backslashes and carets, drops the space before `/` and `(`,
/// replaces `,` and `;` with a space, collapses whitespace runs to one space,
/// and lowercases ASCII letters.
pub fn cmd_line(input: &[u8]) -> TransformationResult {
    let Some(start) = input.iter().position(|byte| needs_cmd_line(*byte)) else {
        return (input.to_vec(), false, None);
    };

    let mut transformed = Vec::with_capacity(input.len());
    transformed.extend_from_slice(input.get(..start).unwrap_or_default());
    let mut changed = false;
    let mut space = false;
    let mut offset = start;
    while let Some(&byte) = input.get(offset) {
        match byte {
            b'"' | b'\'' | b'\\' | b'^' => changed = true,
            b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                if space {
                    changed = true;
                } else {
                    changed |= byte != b' ';
                    transformed.push(b' ');
                    space = true;
                }
            },
            b'/' | b'(' => {
                if space && transformed.pop().is_some() {
                    changed = true;
                }
                space = false;
                transformed.push(byte);
            },
            _ => {
                let lowered = byte.to_ascii_lowercase();
                changed |= lowered != byte;
                transformed.push(lowered);
                space = false;
            },
        }
        offset += 1;
    }
    (transformed, changed, None)
}

/// Removes C-style, HTML, `--` and `#` comments as Go Coraza's
/// `t:removeComments` does.
///
/// A comment terminator consumes the marker and copies the byte that follows
/// it, matching Go's padded-input implementation. An unterminated comment
/// becomes one trailing space.
pub fn remove_comments(input: &[u8]) -> TransformationResult {
    let mut transformed = Vec::with_capacity(input.len());
    let mut in_comment = false;
    let mut changed = false;
    let mut offset = 0;
    while let Some(&byte) = input.get(offset) {
        if in_comment {
            if starts_with_at(input, offset, b"*/") {
                in_comment = false;
                offset += 2;
                // Go pads the input with NUL and copies the byte after the
                // terminator, including that pad at end of input.
                transformed.push(input.get(offset).copied().unwrap_or_default());
                offset += 1;
            } else if starts_with_at(input, offset, b"-->") {
                in_comment = false;
                offset += 3;
                transformed.push(input.get(offset).copied().unwrap_or_default());
                offset += 1;
            } else {
                offset += 1;
            }
        } else if starts_with_at(input, offset, b"/*") {
            in_comment = true;
            changed = true;
            offset += 2;
        } else if starts_with_at(input, offset, b"<!--") {
            in_comment = true;
            changed = true;
            offset += 4;
        } else if starts_with_at(input, offset, b"--") || byte == b'#' {
            changed = true;
            break;
        } else {
            transformed.push(byte);
            offset += 1;
        }
    }
    if in_comment {
        changed = true;
        transformed.push(b' ');
    }
    (transformed, changed, None)
}

/// Removes comment delimiter characters as Go Coraza's
/// `t:removeCommentsChar` does.
///
/// Comment content is preserved; only `/*`, `*/`, `<!--`, `-->`, `--` and `#`
/// markers are removed.
pub fn remove_comments_char(input: &[u8]) -> TransformationResult {
    let mut transformed = Vec::with_capacity(input.len());
    let mut changed = false;
    let mut offset = 0;
    while let Some(&byte) = input.get(offset) {
        if starts_with_at(input, offset, b"/*") || starts_with_at(input, offset, b"*/") {
            offset += 2;
            changed = true;
        } else if starts_with_at(input, offset, b"<!--") {
            offset += 4;
            changed = true;
        } else if starts_with_at(input, offset, b"-->") {
            offset += 3;
            changed = true;
        } else if starts_with_at(input, offset, b"--") {
            offset += 2;
            changed = true;
        } else if byte == b'#' {
            offset += 1;
            changed = true;
        } else {
            transformed.push(byte);
            offset += 1;
        }
    }
    (transformed, changed, None)
}

/// Replaces C-style comments with one space as Go Coraza's
/// `t:replaceComments` does.
///
/// An unterminated comment becomes a single trailing space. HTML, `--` and
/// `#` markers are not comments for this transformation.
pub fn replace_comments(input: &[u8]) -> TransformationResult {
    let mut transformed = Vec::with_capacity(input.len());
    let mut in_comment = false;
    let mut changed = false;
    let mut offset = 0;
    while let Some(&byte) = input.get(offset) {
        if in_comment {
            if starts_with_at(input, offset, b"*/") {
                in_comment = false;
                offset += 2;
                transformed.push(b' ');
            } else {
                offset += 1;
            }
        } else if starts_with_at(input, offset, b"/*") {
            in_comment = true;
            changed = true;
            offset += 2;
        } else {
            transformed.push(byte);
            offset += 1;
        }
    }
    if in_comment {
        transformed.push(b' ');
    }
    (transformed, changed, None)
}

/// Returns whether `byte` starts a command-line normalization.
fn needs_cmd_line(byte: u8) -> bool {
    byte.is_ascii_uppercase()
        || matches!(
            byte,
            b'"' | b'\'' | b'\\' | b'^' | b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' | b'/' | b'('
        )
}

/// Returns whether `needle` occurs at `offset` in `input`.
fn starts_with_at(input: &[u8], offset: usize, needle: &[u8]) -> bool {
    input
        .get(offset..offset.saturating_add(needle.len()))
        .is_some_and(|candidate| candidate == needle)
}

/// Maps valid UTF-8 with Go's simple case mapping and malformed bytes to U+FFFD.
fn map_case(input: &[u8], lowercase: bool) -> Vec<u8> {
    let mut transformed = Vec::with_capacity(input.len());
    for_each_utf8(input, |item| match item {
        Ok(character) => {
            let mapped = if lowercase {
                lowercase_char(character)
            } else {
                uppercase_char(character)
            };
            let mut buffer = [0; 4];
            transformed.extend_from_slice(mapped.encode_utf8(&mut buffer).as_bytes());
        },
        // Go's strings.ToLower and strings.ToUpper iterate runes, so each byte
        // outside a valid UTF-8 sequence contributes one U+FFFD.
        Err(_) => transformed.extend_from_slice("\u{FFFD}".as_bytes()),
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

/// Returns whether `character` is one of the Latin-1 whitespace characters
/// the Go reference collapses.
fn is_latin_space(character: char) -> bool {
    matches!(
        character,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{85}' | '\u{a0}'
    )
}

#[cfg(test)]
mod tests {
    use super::{
        cmd_line, compress_whitespace, lowercase, remove_comments, remove_comments_char, remove_whitespace,
        replace_comments, trim, trim_left, trim_right, uppercase, url_decode,
    };

    #[test]
    fn case_mapping_uses_go_simple_mapping_and_replaces_malformed_bytes() {
        let (lower, lower_changed, lower_error) = lowercase(b"TEST \xff \xc3\x84");
        assert_eq!(lower, b"test \xef\xbf\xbd \xc3\xa4");
        assert!(lower_changed);
        assert_eq!(lower_error, None);

        // Go's simple uppercase leaves `ß` and `ﬃ` alone, unlike Rust's full mapping.
        let (upper, upper_changed, upper_error) = uppercase(b"gro\xc3\x9f");
        assert_eq!(upper, b"GRO\xc3\x9f");
        assert!(upper_changed);
        assert_eq!(upper_error, None);
        assert_eq!(uppercase(b"Stra\xc3\x9fe").0, b"STRA\xc3\x9fE");
        assert_eq!(uppercase(b"\xef\xac\x83").0, b"\xef\xac\x83");
    }

    #[test]
    fn case_mapping_matches_go_for_turkish_and_greek() {
        // U+0130 lower-cases to `i` with the simple mapping, not `i` + U+0307.
        assert_eq!(lowercase(b"\xc4\xb0").0, b"i");
        // Greek capital sigma lower-cases to sigma, never final sigma.
        assert_eq!(lowercase(b"\xce\x9f\xce\xa3").0, b"\xce\xbf\xcf\x83");
        assert_eq!(lowercase(b"\xcf\x82").0, b"\xcf\x82");
        assert_eq!(uppercase(b"\xcf\x82").0, b"\xce\xa3");
    }

    #[test]
    fn case_mapping_replaces_each_malformed_byte_like_go() {
        assert_eq!(lowercase(b"\xe2\x82").0, b"\xef\xbf\xbd\xef\xbf\xbd");
        assert_eq!(uppercase(b"A\xffB").0, b"A\xef\xbf\xbdB");
        let (untouched, changed, error) = lowercase(b"already");
        assert_eq!(untouched, b"already");
        assert!(!changed);
        assert_eq!(error, None);
    }

    #[test]
    fn trim_variants_preserve_non_whitespace_bytes() {
        assert_eq!(trim(b"\t \xff value \r"), (b"\xff value".to_vec(), true, None));
        assert_eq!(trim_left(b" \xffvalue"), (b"\xffvalue".to_vec(), true, None));
        assert_eq!(trim_right(b"value\xff "), (b"value\xff".to_vec(), true, None));
        assert_eq!(trim(b"value"), (b"value".to_vec(), false, None));
    }

    #[test]
    fn whitespace_transforms_handle_unicode_and_malformed_bytes() {
        let (removed, removed_changed, removed_error) = remove_whitespace(b"a \t\xc2\xa0\xffb");
        assert_eq!(removed, b"a\xffb");
        assert!(removed_changed);
        assert_eq!(removed_error, None);
    }

    // Ported from: coraza/internal/transformations/compress_whitespace.go::isLatinSpace
    // and its raw 0xA0 handling.
    #[test]
    fn compress_whitespace_uses_the_latin1_whitespace_set() {
        for (input, output, changed) in [
            (b"".as_slice(), b"".as_slice(), false),
            (b"word", b"word", false),
            (b"a b", b"a b", false),
            (b"a  b", b"a b", true),
            (b"\t \r\n\x0b\x0c", b" ", true),
            (b"\xc2\xa0a\xc2\xa0", b" a ", true),
            (b"\xc2\x85a", b" a", true),
            (b"SELECT\xa01", b"SELECT 1", true),
            (b"a\xa0\xa0b", b"a b", true),
            // U+3000 and the other Unicode spaces are outside the Latin-1 set.
            (b"a\xe3\x80\x80b", b"a\xe3\x80\x80b", false),
            (b"a\xe2\x80\x89b", b"a\xe2\x80\x89b", false),
            // A stray 0x85 is not whitespace; malformed bytes are preserved.
            (b"a\x85b", b"a\x85b", false),
            (b"a\xff\xffb", b"a\xff\xffb", false),
            (b"a \xff b", b"a \xff b", false),
            (b"a\xc3", b"a\xc3", false),
        ] {
            let (result, result_changed, error) = compress_whitespace(input);
            assert_eq!(result, output, "input: {input:?}");
            assert_eq!(result_changed, changed, "input: {input:?}");
            assert_eq!(error, None);
        }
    }

    #[test]
    fn url_decode_preserves_decoded_binary_and_invalid_escapes() {
        let (decoded, changed, error) = url_decode(b"a%00%FF+z");
        assert_eq!(decoded, b"a\x00\xff z");
        assert!(changed);
        assert_eq!(error, None);

        let (invalid, invalid_changed, invalid_error) = url_decode(b"%G1%");
        assert_eq!(invalid, b"%G1%");
        assert!(invalid_changed);
        assert_eq!(invalid_error, None);

        let (unchanged, unchanged_changed, unchanged_error) = url_decode(b"plain");
        assert_eq!(unchanged, b"plain");
        assert!(!unchanged_changed);
        assert_eq!(unchanged_error, None);
    }

    // Ported from: coraza/internal/transformations/cmd_line_test.go::TestCmdLine and
    // coraza/internal/transformations/testdata/cmdLine.json.
    #[test]
    fn cmd_line_matches_go_semantics() {
        for (input, output, changed) in [
            (b"".as_slice(), b"".as_slice(), false),
            (b"test", b"test", false),
            (b"/etc/passwd", b"/etc/passwd", false),
            (b"/?file=../../etc/passwd", b"/?file=../../etc/passwd", false),
            (b" trail ", b" trail ", false),
            (b"C^OMMAND", b"command", true),
            (b"\"command\"", b"command", true),
            (b"'command'", b"command", true),
            (br#""command" /c DiR"#, b"command/c dir", true),
            (br#"\"quoted\""#, b"quoted", true),
            (b"a , b", b"a b", true),
            (b"dir /s", b"dir/s", true),
            (b"a  b", b"a b", true),
            (b"a\t\r\nb", b"a b", true),
            (b"a (b)", b"a(b)", true),
            (b"C^OMMAND /C DIR", b"command/c dir", true),
            (b"C^oMMaNd /C DiR", b"command/c dir", true),
            (b"cmd,/c DiR", b"cmd/c dir", true),
            (b"C^OMMAND\xff /C DIR", b"command\xff/c dir", true),
        ] {
            let (result, result_changed, error) = cmd_line(input);
            assert_eq!(result, output, "input: {input:?}");
            assert_eq!(result_changed, changed, "input: {input:?}");
            assert_eq!(error, None);
        }
    }

    // Ported from: coraza/internal/transformations/remove_comments_test.go::TestRemoveComments and
    // coraza/internal/transformations/testdata/removeComments.json.
    #[test]
    fn remove_comments_matches_go_semantics() {
        for (input, output, changed) in [
            (b"hello world".as_slice(), b"hello world".as_slice(), false),
            (b"hello /* comment */ world", b"hello  world", true),
            (b"hello <!-- comment --> world", b"hello  world", true),
            (b"/* comment */", b"\x00", true),
            (b"<!-- comment -->", b"\x00", true),
            (b"hello /* unclosed", b"hello  ", true),
            (b"hello <!-- unclosed", b"hello  ", true),
            (b"hello -- rest", b"hello ", true),
            (b"hello # rest", b"hello ", true),
            (b"", b"", false),
            (b"Before/* TestCase */After", b"BeforeAfter", true),
            (b"Before /* */ ops */ Test\nCase ", b"Before  ops */ Test\nCase ", true),
            (b"Test\nCase /**/ After", b"Test\nCase  After", true),
            (b"Test/*\nCase */ After", b"Test After", true),
            (b"/*Test\r\nCase */After", b"After", true),
            (b"Test\r\nCase */After", b"Test\r\nCase */After", false),
            (b"/*Before/* Test\r\nCase ", b" ", true),
            (b"/*a/*b*/c", b"c", true),
            (b"/*a*//*b*/", b"/*b*/", true),
            (b"a<!-b", b"a<!-b", false),
            (b"a/", b"a/", false),
            (b"a#b", b"a", true),
            (b"a--b", b"a", true),
            (b"\xff/*x*/y\xfe", b"\xffy\xfe", true),
        ] {
            let (result, result_changed, error) = remove_comments(input);
            assert_eq!(result, output, "input: {input:?}");
            assert_eq!(result_changed, changed, "input: {input:?}");
            assert_eq!(error, None);
        }
    }

    // Ported from: coraza/internal/transformations/testdata/removeCommentsChar.json.
    #[test]
    fn remove_comments_char_matches_go_semantics() {
        for (input, output, changed) in [
            (b"".as_slice(), b"".as_slice(), false),
            (b"TestCase", b"TestCase", false),
            (br"Test\u0000Case", br"Test\u0000Case", false),
            (b"Test\x00Case", b"Test\x00Case", false),
            (b"/* TestCase */", b" TestCase ", true),
            (b"/*TestCase*/", b"TestCase", true),
            (b"/* TestCase*/", b" TestCase", true),
            (b"/*TestCase */", b"TestCase ", true),
            (b"Before/* TestCase */After", b"Before TestCase After", true),
            (b"Before /* TestCase */ After", b"Before  TestCase  After", true),
            (b"/* Test\nCase */", b" Test\nCase ", true),
            (b"/* Test\r\nCase */", b" Test\r\nCase ", true),
            (b"Before/* Test\r\nCase ", b"Before Test\r\nCase ", true),
            (b"Before /* Test\nCase ", b"Before  Test\nCase ", true),
            (b"Test\r\nCase */After", b"Test\r\nCase After", true),
            (b"Test\nCase */ After", b"Test\nCase  After", true),
            (b"a<!--b-->c", b"abc", true),
            (b"a#b", b"ab", true),
            (b"/*/**/*/", b"", true),
            (b"*/*", b"*", true),
            (b"\xff/*x*/\xfe", b"\xffx\xfe", true),
        ] {
            let (result, result_changed, error) = remove_comments_char(input);
            assert_eq!(result, output, "input: {input:?}");
            assert_eq!(result_changed, changed, "input: {input:?}");
            assert_eq!(error, None);
        }
    }

    // Ported from: coraza/internal/transformations/replace_comments_test.go::TestReplaceComments and
    // coraza/internal/transformations/testdata/replaceComments.json.
    #[test]
    fn replace_comments_matches_go_semantics() {
        for (input, output, changed) in [
            (b"".as_slice(), b"".as_slice(), false),
            (b"Not a comment", b"Not a comment", false),
            (b"Test\r\nCase */After", b"Test\r\nCase */After", false),
            (b"This is/*this is a comment*/text", b"This is text", true),
            (b"/*this is a comment*/a comment", b" a comment", true),
            (b"/**/", b" ", true),
            (b"/*comment", b" ", true),
            (b"Before/* TestCase */After", b"Before After", true),
            (b"Before /* TestCase */ After", b"Before   After", true),
            (b"Before/* Test\r\nCase ", b"Before ", true),
            (b"/*a*//*b*/", b"  ", true),
            (b"/**/*/", b" */", true),
            (b"a/*b", b"a ", true),
            (b"\xff/*x*/\xfe", b"\xff \xfe", true),
        ] {
            let (result, result_changed, error) = replace_comments(input);
            assert_eq!(result, output, "input: {input:?}");
            assert_eq!(result_changed, changed, "input: {input:?}");
            assert_eq!(error, None);
        }
    }
}
