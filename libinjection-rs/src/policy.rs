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

//! Built-in minimal detect policies for Coraza `@detectSQLi` / `@detectXSS`.

use crate::snapshot::ConstructFlags;

/// Constructs that trigger built-in `@detectSQLi` (library-side, backward compat).
pub(crate) const BUILTIN_SQLI_DETECT: ConstructFlags = ConstructFlags(
    ConstructFlags::SQL_UNION
        | ConstructFlags::SQL_TAUTOLOGY
        | ConstructFlags::SQL_STRING_BREAK
        | ConstructFlags::SQL_STACKED_QUERY
        | ConstructFlags::SQL_COMMENT_INJECTION
        | ConstructFlags::SQL_FUNCTION_CALL
        | ConstructFlags::SQL_BOOLEAN_BLIND
        | ConstructFlags::SQL_KEYWORD_CHAIN,
);

/// Constructs that trigger built-in `@detectXSS`.
pub(crate) const BUILTIN_XSS_DETECT: ConstructFlags = ConstructFlags(
    ConstructFlags::XSS_TAG_SCRIPT
        | ConstructFlags::XSS_TAG_IFRAME
        | ConstructFlags::XSS_TAG_OBJECT
        | ConstructFlags::XSS_TAG_SVG
        | ConstructFlags::XSS_EVENT_HANDLER
        | ConstructFlags::XSS_URL_JAVASCRIPT
        | ConstructFlags::XSS_URL_DATA
        | ConstructFlags::XSS_STYLE_EXPRESSION
        | ConstructFlags::XSS_COMMENT_BYPASS
        | ConstructFlags::XSS_DOCTYPE
        | ConstructFlags::XSS_HTML_DENYLIST,
);

/// Dialect-only hints: ambiguous when scan/normalize was limited.
pub(crate) const WEAK_SIGNAL: ConstructFlags = ConstructFlags(
    ConstructFlags::SQL_DIALECT_MYSQL | ConstructFlags::SQL_DIALECT_MSSQL | ConstructFlags::SQL_DIALECT_ORACLE,
);
