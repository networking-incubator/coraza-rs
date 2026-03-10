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

//! Byte-oriented entity decoding and path normalization transformations.

use super::TransformationResult;

/// Normalizes slash-separated paths using Go's `path.Clean` behavior.
pub fn normalise_path(input: &[u8]) -> TransformationResult {
    if input.is_empty() {
        return (Vec::new(), false, None);
    }

    let clean = clean_path(input);
    if clean == b"." {
        return (Vec::new(), true, None);
    }

    let result = if input.ends_with(b"/") && !clean.ends_with(b"/") {
        [clean.as_slice(), b"/"].concat()
    } else {
        clean
    };
    let changed = result != input;
    (result, changed, None)
}

/// Cleans a slash-separated byte path while preserving arbitrary bytes.
fn clean_path(path: &[u8]) -> Vec<u8> {
    let rooted = path.first() == Some(&b'/');
    let mut clean = Vec::with_capacity(path.len());
    let mut floor = 0;
    if rooted {
        clean.push(b'/');
        floor = 1;
    }

    for element in path.split(|&byte| byte == b'/') {
        match element {
            b"" | b"." => {},
            b".." if clean.len() > floor => {
                let parent = clean
                    .get(floor..)
                    .unwrap_or_default()
                    .iter()
                    .rposition(|&byte| byte == b'/')
                    .map_or(floor, |slash| floor + slash);
                clean.truncate(parent);
            },
            b".." if rooted => {},
            _ => {
                if clean.len() > usize::from(rooted) {
                    clean.push(b'/');
                }
                clean.extend_from_slice(element);
                if element == b".." {
                    floor = clean.len();
                }
            },
        }
    }

    if clean.is_empty() {
        clean.push(b'.');
    }
    clean
}

/// Normalizes a Windows path and removes alternate streams and trailing dots
/// or spaces that Windows ignores when opening a path.
pub fn normalise_path_win(input: &[u8]) -> TransformationResult {
    if input.is_empty() {
        return (Vec::new(), false, None);
    }

    let converted: Vec<u8> = input
        .iter()
        .map(|&byte| if byte == b'\\' { b'/' } else { byte })
        .collect();
    let (normalized, ..) = normalise_path(&converted);
    let result = strip_trailing_dots_and_spaces(&strip_alternate_data_stream(&normalized));
    let changed = result != input;
    (result, changed, None)
}

/// Removes the NTFS alternate data stream from the final path element.
fn strip_alternate_data_stream(path: &[u8]) -> Vec<u8> {
    let (drive, rest) = match path {
        [letter, b':', ..] if letter.is_ascii_alphabetic() => {
            (path.get(..2).unwrap_or_default(), path.get(2..).unwrap_or_default())
        },
        _ => (&[][..], path),
    };
    let (rest, trailing_slash): (&[u8], &[u8]) = match rest.strip_suffix(b"/") {
        Some(rest) => (rest, b"/"),
        None => (rest, b""),
    };
    let last_element = rest.iter().rposition(|&byte| byte == b'/').map_or(0, |slash| slash + 1);
    let end = rest
        .get(last_element..)
        .unwrap_or_default()
        .iter()
        .position(|&byte| byte == b':')
        .map_or(rest.len(), |colon| last_element + colon);
    [drive, rest.get(..end).unwrap_or_default(), trailing_slash].concat()
}

/// Removes trailing dots and spaces from Windows path elements.
fn strip_trailing_dots_and_spaces(path: &[u8]) -> Vec<u8> {
    let mut stripped = Vec::with_capacity(path.len());
    let mut first = true;
    for element in path.split(|&byte| byte == b'/') {
        let element = if element.iter().all(|&byte| byte == b'.') {
            element
        } else {
            let end = element
                .iter()
                .rposition(|&byte| byte != b'.' && byte != b' ')
                .map_or(0, |last| last + 1);
            if end == 0 {
                continue;
            }
            element.get(..end).unwrap_or_default()
        };
        if !first {
            stripped.push(b'/');
        }
        stripped.extend_from_slice(element);
        first = false;
    }
    stripped
}

#[cfg(test)]
mod tests {
    use super::{normalise_path, normalise_path_win};

    #[test]
    fn normalise_path_matches_go_and_preserves_binary_segments() {
        for (input, output) in [
            (b"".as_slice(), b"".as_slice()),
            (b"/foo/bar/baz", b"/foo/bar/baz"),
            (b"/foo/bar\0/baz", b"/foo/bar\0/baz"),
            (b"x", b"x"),
            (b".", b""),
            (b"./", b""),
            (b"./..", b".."),
            (b"./../", b"../"),
            (b"..", b".."),
            (b"../", b"../"),
            (b"../.", b".."),
            (b".././", b"../"),
            (b"../..", b"../.."),
            (b"../../", b"../../"),
            (b"/dir/foo//bar", b"/dir/foo/bar"),
            (b"/foo//bar/", b"/foo/bar/"),
            (b"dir/../foo", b"foo"),
            (b"dir/../../foo", b"../foo"),
            (b"dir/./.././../../foo/bar", b"../../foo/bar"),
            (b"dir/./.././../../foo/bar/.", b"../../foo/bar"),
            (b"dir/./.././../../foo/bar/./", b"../../foo/bar/"),
            (b"dir/./.././../../foo/bar/..", b"../../foo"),
            (b"dir/./.././../../foo/bar/../", b"../../foo/"),
            (b"dir/./.././../../foo/bar/", b"../../foo/bar/"),
            (b"dir//.//..//.//..//..//foo//bar", b"../../foo/bar"),
            (b"dir//.//..//.//..//..//foo//bar//", b"../../foo/bar/"),
            (b"dir/subdir/subsubdir/subsubsubdir/../../..", b"dir"),
            (b"dir/./subdir/./subsubdir/./subsubsubdir/../../..", b"dir"),
            (b"dir/./subdir/../subsubdir/../subsubsubdir/..", b"dir"),
            (b"/dir/./subdir/../subsubdir/../subsubsubdir/../", b"/dir/"),
            (b"../../foo", b"../../foo"),
            (b"/./.././../../../../../../../\0/../etc/./passwd", b"/etc/passwd"),
            (b"/a/../\xff//b", b"/\xff/b"),
            (b"a\\..\\b", b"a\\..\\b"),
        ] {
            let (result, changed, error) = normalise_path(input);
            assert_eq!(result, output, "input: {input:?}");
            assert_eq!(changed, result != input, "input: {input:?}");
            assert_eq!(error, None);
        }
    }

    #[test]
    fn normalise_path_win_matches_windows_opening_rules() {
        for (input, output) in [
            (b"".as_slice(), b"".as_slice()),
            (br"\foo\bar\baz", b"/foo/bar/baz"),
            (br"C:\inetpub\wwwroot\index.html", b"C:/inetpub/wwwroot/index.html"),
            (br"..\..\etc\passwd", b"../../etc/passwd"),
            (br"foo\..\bar", b"bar"),
            (b".", b""),
            (b".\\", b""),
            (b".\\..", b".."),
            (b".\\..\\", b"../"),
            (b"..", b".."),
            (b"..\\", b"../"),
            (b"..\\.", b".."),
            (b"..\\.\\", b"../"),
            (b"..\\..", b"../.."),
            (b"..\\..\\", b"../../"),
            (br"\dir\foo\\bar", b"/dir/foo/bar"),
            (br"dir\foo\\bar\", b"dir/foo/bar/"),
            (br"dir\..\foo", b"foo"),
            (br"dir\..\..\foo", b"../foo"),
            (br"dir\.\..\.\..\..\foo\bar", b"../../foo/bar"),
            (br"dir\.\..\.\..\..\foo\bar\.", b"../../foo/bar"),
            (br"dir\.\..\.\..\..\foo\bar\.\", b"../../foo/bar/"),
            (br"dir\.\..\.\..\..\foo\bar\..", b"../../foo"),
            (br"dir\.\..\.\..\..\foo\bar\..\", b"../../foo/"),
            (br"dir\.\..\.\..\..\foo\bar\", b"../../foo/bar/"),
            (br"dir\\.\\..\\.\\..\\..\\foo\\bar", b"../../foo/bar"),
            (br"dir\\.\\..\\.\\..\\..\\foo\\bar\\", b"../../foo/bar/"),
            (br"dir\subdir\subsubdir\subsubsubdir\..\..\..", b"dir"),
            (br"dir\.\subdir\.\subsubdir\.\subsubsubdir\..\..\..", b"dir"),
            (br"dir\.\subdir\..\subsubdir\..\subsubsubdir\..", b"dir"),
            (br"\dir\.\subdir\..\subsubdir\..\subsubsubdir\..\", b"/dir/"),
            (br"C:\inetpub\wwwroot\web.config.", b"C:/inetpub/wwwroot/web.config"),
            (
                br"C:\inetpub\wwwroot\web.config::$DATA",
                b"C:/inetpub/wwwroot/web.config",
            ),
            (
                br"C:\inetpub\wwwroot\web.config:hidden",
                b"C:/inetpub/wwwroot/web.config",
            ),
            (br"C:\path\web.config:$DATA\", b"C:/path/web.config/"),
            (br"C:\ \file.txt", b"C:/file.txt"),
            (b"\\a\\..\\\xff", b"/\xff"),
        ] {
            let (result, changed, error) = normalise_path_win(input);
            assert_eq!(result, output, "input: {input:?}");
            assert_eq!(changed, result != input, "input: {input:?}");
            assert_eq!(error, None);
        }
    }
}
