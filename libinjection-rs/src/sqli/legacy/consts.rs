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

//! Constants ported from `sqli_const.go`.
//!
//! Many constants are used by fold/detect (Agent 2) and appear unused until then.

// -- Flags (sqliFlagQuote* / sqliFlagSQL*) --

/// Parse input as-is (no simulated quote context).
pub(crate) const FLAG_QUOTE_NONE: u32 = 1;
/// Simulate `'...'` at pos 0.
pub(crate) const FLAG_QUOTE_SINGLE: u32 = 2;
/// Simulate `"..."` at pos 0.
pub(crate) const FLAG_QUOTE_DOUBLE: u32 = 4;
/// ANSI SQL: `--[not-white]` is a comment; `#` is an operator.
pub(crate) const FLAG_SQL_ANSI: u32 = 8;
/// `MySQL`: `#` is an EOL comment; `--foo` is two unary `-`.
pub(crate) const FLAG_SQL_MYSQL: u32 = 16;

// -- Lookup kinds --

/// Word lookup (keywords, functions, types).
pub(crate) const LOOKUP_WORD: u8 = 1;
/// Operator lookup.
pub(crate) const LOOKUP_OPERATOR: u8 = 3;
/// Fingerprint lookup (used by `checkFingerprint` in detection).
pub(crate) const LOOKUP_FINGERPRINT: u8 = 4;

// -- Delimiter bytes --

/// Null byte (no delimiter / unset).
pub(crate) const BYTE_NULL: u8 = 0;
/// Single-quote delimiter.
pub(crate) const BYTE_SINGLE: u8 = b'\'';
/// Double-quote delimiter.
pub(crate) const BYTE_DOUBLE: u8 = b'"';
/// Backtick delimiter.
pub(crate) const BYTE_TICK: u8 = b'`';

// -- Token type bytes (sqliTokenType*) --

/// No token emitted (whitespace consumed).
pub(crate) const TT_NONE: u8 = 0;
/// Generic SQL keyword.
pub(crate) const TT_KEYWORD: u8 = b'k';
/// `UNION` / `UNION ALL`.
pub(crate) const TT_UNION: u8 = b'U';
/// `GROUP BY`.
pub(crate) const TT_GROUP: u8 = b'B';
/// `SELECT`, `CASE`, `WHEN`, ...
pub(crate) const TT_EXPRESSION: u8 = b'E';
/// `CAST`, `CHAR`, collation types.
pub(crate) const TT_SQLTYPE: u8 = b't';
/// SQL function call.
pub(crate) const TT_FUNCTION: u8 = b'f';
/// Unrecognized identifier.
pub(crate) const TT_BAREWORD: u8 = b'n';
/// Numeric literal.
pub(crate) const TT_NUMBER: u8 = b'1';
/// `@var` / `@@var`.
pub(crate) const TT_VARIABLE: u8 = b'v';
/// Quoted string.
pub(crate) const TT_STRING: u8 = b's';
/// `=`, `||`, `>=`, ...
pub(crate) const TT_OPERATOR: u8 = b'o';
/// `AND`, `OR`, `XOR`.
pub(crate) const TT_LOGIC_OPERATOR: u8 = b'&';
/// Comment (`--`, `#`, `/* */`).
pub(crate) const TT_COMMENT: u8 = b'c';
/// `COLLATE`.
pub(crate) const TT_COLLATE: u8 = b'A';
/// `(`.
pub(crate) const TT_LPAREN: u8 = b'(';
/// `)`.
pub(crate) const TT_RPAREN: u8 = b')';
/// `{`.
pub(crate) const TT_LBRACE: u8 = b'{';
/// `}`.
pub(crate) const TT_RBRACE: u8 = b'}';
/// `.` (dot / member access).
pub(crate) const TT_DOT: u8 = b'.';
/// `,`.
pub(crate) const TT_COMMA: u8 = b',';
/// `:`.
pub(crate) const TT_COLON: u8 = b':';
/// `;`.
pub(crate) const TT_SEMICOLON: u8 = b';';
/// T-SQL `IF` after `;`.
pub(crate) const TT_TSQL: u8 = b'T';
/// Unrecognized byte.
pub(crate) const TT_UNKNOWN: u8 = b'?';
/// Unparsable (nested `/*`, `MySQL` brace-backtick, etc.).
pub(crate) const TT_EVIL: u8 = b'X';
/// Fingerprint match marker (map value only, never in output).
pub(crate) const TT_FINGERPRINT: u8 = b'F';
/// T-SQL backslash (transient, folded away).
pub(crate) const TT_BACKSLASH: u8 = b'\\';

// -- Limits --

/// Maximum folded tokens in fingerprint.
pub(crate) const MAX_TOKENS: usize = 5;
/// Maximum token value length (including null in Go).
pub(crate) const TOKEN_SIZE: usize = 32;
