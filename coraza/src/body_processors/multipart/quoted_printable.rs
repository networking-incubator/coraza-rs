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

//! Quoted-printable decoding of a multipart part body, as Go's `mime/multipart` does it.
//!
//! `Reader.NextPart` hides a `Content-Transfer-Encoding: quoted-printable` header and reads the part through
//! `mime/quotedprintable.NewReader` (`mime/multipart/multipart.go`, go1.27.4). That reader gets its lines from a
//! `bufio.Reader` of the default 4096 bytes, so this port keeps both: [`decode`] is `quotedprintable.Reader.Read`
//! (`mime/quotedprintable/reader.go`, go1.27.4) run over the whole body, line by line, with the reader's
//! deviations from RFC 2045 and its errors, which Go's body processor returns as they are.

use super::quoted;

/// The size of the buffer `quotedprintable.NewReader` reads lines through: `bufio.NewReader`'s default. A line
/// longer than this, line end included, is `bufio.ErrBufferFull`.
const LINE_BUFFER_BYTES: usize = 4096;

/// What the reader under the decoder reports after the last byte of the part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum End {
    /// The part ended at its delimiter: `io.EOF`.
    Eof,
    /// The body ended inside the part, or was cut by the limit: `io.ErrUnexpectedEOF`.
    UnexpectedEof,
}

/// Why decoding stopped before the end of the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Stop {
    /// `io.ErrUnexpectedEOF`, which Go's processor reads as the end of a partial body and not as an error.
    UnexpectedEof,
    /// An error Go's processor returns from copying the part, with `MULTIPART_STRICT_ERROR`; this is its message.
    Error(String),
}

/// What the line reader holds back until the line has been decoded: `quotedprintable.Reader.rerr`.
enum Pending {
    /// Nothing: the line ended in a line feed.
    None,
    /// The end of the part.
    End(End),
    /// `bufio.ErrBufferFull`.
    BufferFull,
    /// The error of a soft line break that a line end does not follow.
    Invalid(String),
}

/// Decode the quoted-printable `data`, which is a whole part body, as `quotedprintable.Reader` does.
///
/// Returns the bytes decoded and why decoding stopped early, if it did. A body that fails still returns what was
/// decoded up to the failure, as Go's `Read` does. The result is never longer than `data`.
pub(super) fn decode(data: &[u8], end: End) -> (Vec<u8>, Option<Stop>) {
    let mut decoded = Vec::with_capacity(data.len());
    let mut rest = data;
    loop {
        // `bufio.Reader.ReadSlice('\n')`: up to the first line feed, if it is within the buffer. Without one, the
        // rest of the body is the line when it leaves room to see the end. A part that ends at its delimiter has
        // the delimiter in the bytes that carry its last line, so the line may fill the buffer (as the
        // `multipart` reader frames them, which is the usual case). The end of a body that was cut only shows
        // in a read of its own, which a full buffer does not make.
        let window = rest.get(..LINE_BUFFER_BYTES.min(rest.len())).unwrap_or_default();
        let room = match end {
            End::Eof => LINE_BUFFER_BYTES.saturating_add(1),
            End::UnexpectedEof => LINE_BUFFER_BYTES,
        };
        let (line, mut pending) = match window.iter().position(|&byte| byte == b'\n') {
            Some(feed) => (rest.get(..=feed).unwrap_or_default(), Pending::None),
            None if rest.len() < room => (rest, Pending::End(end)),
            None => (window, Pending::BufferFull),
        };

        // `r.line = bytes.TrimRightFunc(wholeLine, isQPDiscardWhitespace)`
        let kept = line
            .iter()
            .rposition(|byte| !matches!(byte, b'\n' | b'\r' | b' ' | b'\t'))
            .map_or(0, |last| last.saturating_add(1));
        let mut text = line.get(..kept).unwrap_or_default();
        // What follows the text: the line end, normalized as the reader does, unless the line is a soft break.
        let mut line_end: &[u8] = b"";
        if let Some(without_equals) = text.strip_suffix(b"=") {
            let after = line.get(kept..).unwrap_or_default();
            let after = after.get(after.iter().take_while(|byte| matches!(byte, b' ' | b'\t')).count()..);
            let after = after.unwrap_or_default();
            text = without_equals;
            let ends_the_line = after.starts_with(b"\n") || after.starts_with(b"\r\n");
            let ends_the_part = after.is_empty() && !text.is_empty() && matches!(pending, Pending::End(End::Eof));
            if !ends_the_line && !ends_the_part {
                pending = Pending::Invalid(format!("quotedprintable: invalid bytes after =: {}", quoted(after)));
            }
        } else if line.ends_with(b"\r\n") {
            line_end = b"\r\n";
        } else if line.ends_with(b"\n") {
            line_end = b"\n";
        }

        if let Some(stop) = decode_line(text, line_end, &mut decoded) {
            return (decoded, Some(stop));
        }
        match pending {
            Pending::None => rest = rest.get(line.len()..).unwrap_or_default(),
            Pending::End(End::Eof) => return (decoded, None),
            Pending::End(End::UnexpectedEof) => return (decoded, Some(Stop::UnexpectedEof)),
            Pending::BufferFull => return (decoded, Some(Stop::Error("bufio: buffer full".to_owned()))),
            Pending::Invalid(message) => return (decoded, Some(Stop::Error(message))),
        }
    }
}

/// Decode one line, `text` followed by `line_end`, into `decoded`: the loop of `quotedprintable.Reader.Read`.
fn decode_line(text: &[u8], line_end: &[u8], decoded: &mut Vec<u8>) -> Option<Stop> {
    let line_len = text.len().saturating_add(line_end.len());
    let at = |index: usize| {
        text.get(index)
            .or_else(|| index.checked_sub(text.len()).and_then(|offset| line_end.get(offset)))
            .copied()
    };
    let mut index = 0_usize;
    while let Some(byte) = at(index) {
        match byte {
            b'=' => match read_hex_byte(at(index.saturating_add(1)), at(index.saturating_add(2))) {
                Ok(escaped) => {
                    decoded.push(escaped);
                    index = index.saturating_add(3);
                    continue;
                },
                // "Take the = as a literal =" unless a line end follows it.
                Err(_)
                    if line_len.saturating_sub(index) >= 2
                        && !matches!(at(index.saturating_add(1)), Some(b'\r' | b'\n')) =>
                {
                    decoded.push(b'=');
                },
                Err(HexError::UnexpectedEof) => return Some(Stop::UnexpectedEof),
                Err(HexError::Invalid(byte)) => {
                    return Some(Stop::Error(format!("quotedprintable: invalid hex byte 0x{byte:02x}")));
                },
            },
            // An extension to RFC 2045 that Go accepts: bytes of 0x80 and above.
            b'\t' | b'\r' | b'\n' | 0x80..=0xFF => decoded.push(byte),
            byte if !(b' '..=b'~').contains(&byte) => {
                return Some(Stop::Error(format!(
                    "quotedprintable: invalid unescaped byte 0x{byte:02x} in body"
                )));
            },
            byte => decoded.push(byte),
        }
        index = index.saturating_add(1);
    }
    None
}

/// Why two bytes are not a hex escape: `quotedprintable.readHexByte`'s errors.
enum HexError {
    /// Fewer than two bytes follow the `=`.
    UnexpectedEof,
    /// The first of the two that is not a hex digit.
    Invalid(u8),
}

/// The byte `=` and the two bytes `high` and `low` that follow it stand for.
///
/// Lowercase digits are accepted, as in Go ("accept badly encoded bytes").
fn read_hex_byte(high: Option<u8>, low: Option<u8>) -> Result<u8, HexError> {
    let (Some(high), Some(low)) = (high, low) else {
        return Err(HexError::UnexpectedEof);
    };
    let digit = |byte: u8| char::from(byte).to_digit(16).and_then(|value| u8::try_from(value).ok());
    let high = digit(high).ok_or(HexError::Invalid(high))?;
    let low = digit(low).ok_or(HexError::Invalid(low))?;
    Ok(high << 4 | low)
}

#[cfg(test)]
mod tests {
    use super::{End, Stop, decode};

    /// Decode a part that ended at its delimiter.
    fn whole(data: &[u8]) -> (Vec<u8>, Option<Stop>) {
        decode(data, End::Eof)
    }

    fn failure(message: &str) -> Stop {
        Stop::Error(message.to_owned())
    }

    #[test]
    fn a_body_without_escapes_decodes_to_itself_with_its_line_ends_normalized() {
        assert_eq!(whole(b"plain text"), (b"plain text".to_vec(), None));
        assert_eq!(whole(b""), (Vec::new(), None));
        // Trailing white space goes, a line end is kept as `\n` or `\r\n`, and a bare CR stays inside a line.
        assert_eq!(whole(b"a  \r\nb \t\nc\rd"), (b"a\r\nb\nc\rd".to_vec(), None));
        assert_eq!(whole(b"a\r\r\nb"), (b"a\r\nb".to_vec(), None));
        assert_eq!(whole(b"a\r \nb"), (b"a\nb".to_vec(), None));
        assert_eq!(whole(b"\n\n"), (b"\n\n".to_vec(), None));
    }

    #[test]
    fn escapes_decode_with_either_case_and_invalid_ones_stay() {
        assert_eq!(whole(b"=3D=3d=41=4a=00=FF"), (b"==AJ\x00\xff".to_vec(), None));
        // Not two hex digits: the `=` is literal, wherever it is, and what follows is read as it is.
        assert_eq!(whole(b"a=ZZb=4 c=4"), (b"a=ZZb=4 c=4".to_vec(), None));
        assert_eq!(whole(b"=4"), (b"=4".to_vec(), None));
        assert_eq!(whole(b"=4\r\n"), (b"=4\r\n".to_vec(), None));
        assert_eq!(whole(b"==41"), (b"=A".to_vec(), None));
        assert_eq!(whole(b"=4=41"), (b"=4A".to_vec(), None));
    }

    #[test]
    fn soft_line_breaks_join_lines_and_may_end_the_body() {
        assert_eq!(whole(b"a=\r\nb=\nc= \r\nd=\t\r\ne"), (b"abcde".to_vec(), None));
        assert_eq!(whole(b"abc="), (b"abc".to_vec(), None));
        assert_eq!(whole(b"abc=\r\n"), (b"abc".to_vec(), None));
        assert_eq!(whole(b"abc=  \t"), (b"abc".to_vec(), None));
        assert_eq!(whole(b"=\r\n=41=\r\n4=\r\n2"), (b"A42".to_vec(), None));
        // A soft break is two bytes of line, so it takes the white space before the line end with it.
        assert_eq!(whole(b"a  =  \r\nb"), (b"a  b".to_vec(), None));
    }

    #[test]
    fn soft_breaks_go_rejects_stop_after_the_line_they_end() {
        assert_eq!(
            whole(b"=\r\n"),
            (Vec::new(), None),
            "a line end after the = is a soft break even when nothing came before it"
        );
        assert_eq!(
            whole(b"="),
            (
                Vec::new(),
                Some(failure("quotedprintable: invalid bytes after =: \"\""))
            )
        );
        assert_eq!(
            whole(b"x=\r \nrest"),
            (
                b"x".to_vec(),
                Some(failure("quotedprintable: invalid bytes after =: \"\\r \\n\""))
            )
        );
        assert_eq!(
            whole(b"x=\r\r\nrest"),
            (
                b"x".to_vec(),
                Some(failure("quotedprintable: invalid bytes after =: \"\\r\\r\\n\""))
            )
        );
        assert_eq!(
            whole(b"a\r\nx=\r"),
            (
                b"a\r\nx".to_vec(),
                Some(failure("quotedprintable: invalid bytes after =: \"\\r\""))
            )
        );
    }

    #[test]
    fn a_doubled_equals_before_a_line_end_is_an_unexpected_eof_that_drops_the_rest() {
        // The first `=` of `==` before a line end is a soft break, which leaves the second one alone on the line
        // with nothing to read after it: `readHexByte` reports `io.ErrUnexpectedEOF`, and the lines after it are
        // never read.
        let eof = Some(Stop::UnexpectedEof);
        assert_eq!(whole(b"a==\r\nb"), (b"a".to_vec(), eof.clone()));
        assert_eq!(whole(b"a=="), (b"a".to_vec(), eof.clone()));
        assert_eq!(whole(b"=="), (Vec::new(), eof.clone()));
        assert_eq!(whole(b"a=\r\n==\r\nb"), (b"a".to_vec(), eof.clone()));
        assert_eq!(whole(b"x=3D==\r\nrest"), (b"x=".to_vec(), eof.clone()));
        assert_eq!(whole(b"=4==\r\n"), (b"=4".to_vec(), eof));
    }

    #[test]
    fn bytes_go_does_not_accept_unescaped_stop_the_decoding_there() {
        assert_eq!(
            whole(b"ok=3Dpart\x01bad"),
            (
                b"ok=part".to_vec(),
                Some(failure("quotedprintable: invalid unescaped byte 0x01 in body"))
            )
        );
        assert_eq!(
            whole(b"a\x7fb"),
            (
                b"a".to_vec(),
                Some(failure("quotedprintable: invalid unescaped byte 0x7f in body"))
            )
        );
        assert_eq!(
            whole(b"a\x00"),
            (
                b"a".to_vec(),
                Some(failure("quotedprintable: invalid unescaped byte 0x00 in body"))
            )
        );
        // Bytes of 0x80 and above, tabs and line ends are fine, and so is any byte that is escaped.
        assert_eq!(whole(b"\t\x80\xff=00=7F"), (b"\t\x80\xff\x00\x7f".to_vec(), None));
        assert_eq!(
            whole(b"a=\rb"),
            (b"a".to_vec(), Some(failure("quotedprintable: invalid hex byte 0x0d"))),
            "a CR after the = is not a line end the reader can join"
        );
    }

    #[test]
    fn a_line_over_the_reader_buffer_is_an_error_after_its_first_4096_bytes() {
        let line = |length: usize| "a".repeat(length).into_bytes();
        // 4096 bytes with no line feed that end the body are read; one more is not.
        assert_eq!(whole(&line(4096)), (line(4096), None));
        assert_eq!(whole(&line(4097)), (line(4096), Some(failure("bufio: buffer full"))));
        // A line feed within the first 4096 bytes ends the line.
        let mut body = line(4095);
        body.extend_from_slice(b"\nrest");
        assert_eq!(whole(&body), (body.clone(), None));
        let mut body = line(4096);
        body.extend_from_slice(b"\nrest");
        assert_eq!(whole(&body), (line(4096), Some(failure("bufio: buffer full"))));
        // The chunk that fills the buffer loses its trailing white space and may end in an escape or a soft break.
        let mut body = line(4092);
        body.extend_from_slice(b"    z");
        let mut kept = line(4092);
        assert_eq!(
            whole(&body),
            (std::mem::take(&mut kept), Some(failure("bufio: buffer full")))
        );
        let mut body = line(4095);
        body.extend_from_slice(b"=3D");
        assert_eq!(
            whole(&body),
            (
                line(4095),
                Some(failure("quotedprintable: invalid bytes after =: \"\""))
            ),
            "the 4096th byte is a = that the buffer end makes a soft break with nothing after it"
        );
        let mut body = line(4094);
        body.extend_from_slice(b"=3D");
        let mut read = line(4094);
        read.extend_from_slice(b"=3");
        assert_eq!(
            whole(&body),
            (read, Some(failure("bufio: buffer full"))),
            "the buffer ends inside the escape, whose = is then literal"
        );
    }

    #[test]
    fn the_end_of_a_part_that_was_cut_is_an_unexpected_eof_unless_a_soft_break_ends_it() {
        let cut = |data: &[u8]| decode(data, End::UnexpectedEof);
        assert_eq!(cut(b"cmd=3Bcat"), (b"cmd;cat".to_vec(), Some(Stop::UnexpectedEof)));
        assert_eq!(cut(b"abc=3"), (b"abc=3".to_vec(), Some(Stop::UnexpectedEof)));
        assert_eq!(cut(b"abc"), (b"abc".to_vec(), Some(Stop::UnexpectedEof)));
        // The end of a cut body shows only in a read of its own, so the last line must leave room for it.
        let line = |length: usize| "a".repeat(length).into_bytes();
        assert_eq!(cut(&line(4095)), (line(4095), Some(Stop::UnexpectedEof)));
        assert_eq!(cut(&line(4096)), (line(4096), Some(failure("bufio: buffer full"))));
        assert_eq!(cut(b""), (Vec::new(), Some(Stop::UnexpectedEof)));
        assert_eq!(
            cut(b"abc="),
            (
                b"abc".to_vec(),
                Some(failure("quotedprintable: invalid bytes after =: \"\""))
            ),
            "a soft break at the end of a cut body is an error, not an unexpected EOF"
        );
    }

    #[test]
    fn hostile_bytes_never_panic_and_never_grow() {
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let alphabet = b"=\r\n \t0123456789ABCDEFabcdefgz\x00\x01\x7f\x80\xff;<";
        for length in 0..300 {
            let data: Vec<u8> = (0..length)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    alphabet
                        .get(usize::try_from(state % alphabet.len() as u64).unwrap_or_default())
                        .copied()
                        .unwrap_or_default()
                })
                .collect();
            for end in [End::Eof, End::UnexpectedEof] {
                let (decoded, _) = decode(&data, end);
                assert!(decoded.len() <= data.len(), "{data:?}");
            }
        }
    }
}
