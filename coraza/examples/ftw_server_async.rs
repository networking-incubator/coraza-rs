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

//! FTW Test Server - Async Version
//!
//! Async HTTP server using hyper/tokio for running go-ftw tests against coraza-rs.
//!
//! This server:
//! - Loads CRS rules via SecLang parser
//! - Reads the raw request line itself and parses the header block with httparse, so the targets Go's server accepts
//!   reach the WAF, validates the head as Go's server does, and answers 400/501/505 before any handler where Go does
//! - Renders the target with Go's `url.ParseRequestURI(...).String()`, the form Go Coraza's middleware passes to
//!   `ProcessURI`, instead of the raw request bytes
//! - Sets the connection variables and processes HTTP requests through the WAF (async)
//! - Writes Go Coraza's error log line for every matched rule with `log`, as its CRS test harness does, and answers
//!   `/reflect` as CRS's albedo test backend
//! - Supports concurrent requests via tokio
//!
//! Usage:
//!   cargo run --example `ftw_server_async` --features async-server -- \
//!     --port 8080 \
//!     --logfile /tmp/coraza-audit.log \
//!     --rules crs-setup.conf

use std::{
    convert::Infallible,
    fmt::Write as _,
    fs::OpenOptions,
    io::{self, Write as _},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use coraza::{config::WafConfig, seclang::Parser, types::RuleEngineStatus, waf::Waf};
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{HeaderName, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
};

/// The log FTW reads: request markers and Go Coraza's error log lines.
type Logfile = Arc<Mutex<std::fs::File>>;

/// Read deadline, kept below FTW's 30-second client timeout.
const REQUEST_BODY_READ_TIMEOUT: Duration = Duration::from_secs(25);

/// Server startup options, parsed from the command line.
struct Options {
    /// Port to listen on.
    port: u16,
    /// Audit log file the FTW runner reads.
    logfile: String,
    /// Optional SecLang rules file.
    rules_file: Option<String>,
    /// Readiness token echoed by the health endpoint.
    readiness_token: Option<String>,
    /// Reject unsupported rules and require a rules file.
    strict: bool,
    /// Expected loaded rule count in strict mode.
    expected_rules: Option<usize>,
    /// Optional path for the machine-readable startup inventory.
    inventory_file: Option<String>,
}

impl Options {
    /// Parse options, rejecting combinations that would hide missing rules.
    fn parse(args: &[String]) -> Result<Self, Box<dyn std::error::Error>> {
        let port = get_arg(args, "--port")
            .unwrap_or_else(|| "8080".to_owned())
            .parse::<u16>()?;
        let logfile = get_arg(args, "--logfile").unwrap_or_else(|| "/tmp/coraza-ftw-audit.log".to_owned());
        let rules_file = get_arg(args, "--rules");
        let readiness_token = get_arg(args, "--readiness-token");
        let strict = args.iter().any(|argument| argument == "--strict");
        let expected_rules = match get_arg(args, "--expected-rules") {
            Some(value) => Some(
                value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid --expected-rules {value:?}: {error}"))?,
            ),
            None => None,
        };
        let inventory_file = get_arg(args, "--inventory-file");

        if strict && rules_file.is_none() {
            return Err("--strict requires --rules".into());
        }
        if !strict && expected_rules.is_some() {
            return Err("--expected-rules requires --strict".into());
        }

        Ok(Self {
            port,
            logfile,
            rules_file,
            readiness_token,
            strict,
            expected_rules,
            inventory_file,
        })
    }
}

/// Startup facts the Go runner checks before trusting a result.
struct Inventory {
    /// "strict" or "legacy".
    mode: &'static str,
    /// Number of compiled rules.
    rules_loaded: usize,
    /// Directives the parser skipped (always empty in strict mode).
    skipped_directives: Vec<String>,
    /// Rule count the caller required, if any.
    expected_rules: Option<usize>,
}

impl Inventory {
    /// Machine-readable form written for the Go runner.
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "mode": self.mode,
            "rules_loaded": self.rules_loaded,
            "skipped_directives": self.skipped_directives,
            "expected_rules": self.expected_rules,
        })
    }
}

/// Builds a WAF from the options and reports what was actually loaded.
#[expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "The standalone FTW server reports rule loading to its console."
)]
fn load_policy(options: &Options, logfile: &Logfile) -> Result<(Waf, Inventory), Box<dyn std::error::Error>> {
    // Base configuration; directives in the rules file override it
    let mut parser = Parser::new();
    *parser.config_mut() = WafConfig {
        rule_engine: RuleEngineStatus::On,
        request_body_access: true,
        response_body_access: true,
        request_body_limit: 1_048_576, // 1MB
        web_app_id: "ftw-test".to_owned(),
        ..WafConfig::default()
    };
    // Legacy mode keeps loading past directives this engine doesn't support yet, so a full
    // CRS still loads. Strict mode must not hide unsupported rules.
    if !options.strict {
        parser.skip_failed_directives();
    }
    log_errors_to(&mut parser, logfile);

    if let Some(rules_path) = &options.rules_file {
        println!("Loading rules from {rules_path}...");
        parser.from_file(rules_path)?;
        for e in parser.skipped() {
            eprintln!("Warning: skipped {e}");
        }
    } else {
        // Options::parse requires --rules in strict mode.
        println!("No rules file specified, WAF running without rules");
    }

    let skipped_directives: Vec<String> = parser.skipped().iter().map(ToString::to_string).collect();
    if options.strict && !skipped_directives.is_empty() {
        return Err(format!("strict mode: {} directive(s) were skipped", skipped_directives.len()).into());
    }

    let waf = parser.into_waf()?;
    let rules_loaded = waf.rule_count();
    if let Some(expected) = options.expected_rules
        && expected != rules_loaded
    {
        return Err(format!("strict mode: expected {expected} rule(s), loaded {rules_loaded}").into());
    }

    let inventory = Inventory {
        mode: if options.strict { "strict" } else { "legacy" },
        rules_loaded,
        skipped_directives,
        expected_rules: options.expected_rules,
    };
    Ok((waf, inventory))
}

/// Write the startup inventory after the policy loaded successfully.
fn write_inventory(inventory: &Inventory, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = serde_json::to_vec_pretty(&inventory.to_json())?;
    std::fs::write(path, data)?;
    Ok(())
}

/// The largest request head the server buffers before handing it to hyper.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// The request line and headers as the client sent them.
///
/// Hyper's `Uri` rejects request targets Go's server accepts (`<`, `>`, `"` and other bytes
/// outside RFC 3986), so the raw line is parsed here and only a form hyper accepts is forwarded.
#[derive(Debug)]
struct RequestHead {
    /// Request method, as sent.
    method: String,
    /// Request target, as sent, including absolute-form targets.
    target: Vec<u8>,
    /// Request protocol, as sent.
    protocol: String,
    /// What Go's server answers before running any handler.
    verdict: Verdict,
    /// Go's rendering of the target, `url.ParseRequestURI(target).String()`, which its
    /// middleware passes to `ProcessURI`.
    rendered: Vec<u8>,
    /// The decoded path, as Go's handler reads it from `req.URL.Path`.
    path: Vec<u8>,
    /// `req.Host`: the target's authority when it has one, else the `Host` header.
    host: Option<Vec<u8>>,
    /// Header names, canonicalized as Go's server does, with their raw values.
    headers: Vec<(String, Vec<u8>)>,
}

/// What Go's `net/http` server answers a request head before the handler runs.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The handler runs.
    Serve,
    /// The server rejects the head with 400.
    BadRequest,
    /// The server rejects the protocol with 505 (`net/http/server.go:1127-1140`).
    UnsupportedVersion,
    /// The server rejects the transfer coding with 501 (`net/http/server.go:2103-2110`).
    NotImplemented,
}

/// How Go's server treats a request's `Transfer-Encoding` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferEncoding {
    /// No header, or one Go ignores on an HTTP/1.0 request.
    Absent,
    /// One `chunked` coding, which Go decodes.
    Chunked,
    /// Any other coding or more than one header, which Go answers 501.
    Unsupported,
}

impl RequestHead {
    /// Parse a complete request head and return it with the head to forward to hyper.
    ///
    /// The request line is split from its raw bytes because httparse only exposes a target that
    /// is valid UTF-8; its header parser validates the header block. Returns `None` for a head
    /// hyper would reject: a malformed request line, method, version or headers. The forwarded
    /// head is always rebuilt with CRLF line endings, an HTTP/1.x request line and an
    /// origin-form target, so hyper answers 400 instead of stalling on the bare-LF heads Go
    /// accepts, an unsupported version still reaches the handler, which answers 505, and a
    /// target hyper would reject cannot preempt the WAF.
    #[expect(
        clippy::too_many_lines,
        reason = "The steps follow Go's `readRequest` and server checks in order."
    )]
    fn parse(head: &[u8]) -> (Option<Self>, Vec<u8>) {
        // A complete head ends with a blank line, so the last split is empty.
        let mut lines: Vec<&[u8]> = head
            .split(|&byte| byte == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .collect();
        if lines.last().is_some_and(|line| line.is_empty()) {
            lines.pop();
        }
        let Some((request_line, header_lines)) = lines.split_first() else {
            return (None, forwarded_head(b"GET / HTTP/1.1", &[]));
        };

        let mut fields = request_line.split(|&byte| byte == b' ');
        let method = fields.next().unwrap_or_default();
        let target = fields.next().unwrap_or_default();
        let version = fields.next().unwrap_or_default();
        // Go parses the protocol before the target and method checks, and rejects every
        // malformed form with 400 (`net/http/request.go:1105-1126`).
        let Some((major, minor)) = parse_http_version(version) else {
            return (None, forwarded_head(b"GET / HTTP/1.1", header_lines));
        };
        if fields.next().is_some()
            || method.is_empty()
            || target.is_empty()
            || !method.iter().all(|&byte| is_token(byte))
            || !target.iter().all(|&byte| byte > b' ' && byte != 0x7F)
        {
            return (None, forwarded_head(b"GET / HTTP/1.1", header_lines));
        }

        // Go renders the target through `net/url` before its middleware sees it.
        let target_rendering = go_url::render_target(method, target);
        // The handler reads only the captured head, so hyper gets an origin-form target it
        // accepts: an absolute, authority-form or opaque target Go serves is forwarded as
        // `/`, and cannot be rejected by hyper's URI parser before the WAF runs.
        let forwarded_target = target_rendering
            .as_ref()
            .map(|rendering| rendering.rendered.as_slice())
            .filter(|rendered| rendered.starts_with(b"/") && is_forwardable_target(rendered))
            .unwrap_or(b"/");
        let mut forwarded_line = Vec::with_capacity(
            method
                .len()
                .saturating_add(forwarded_target.len())
                .saturating_add(b" HTTP/1.1".len()),
        );
        forwarded_line.extend_from_slice(method);
        forwarded_line.push(b' ');
        forwarded_line.extend_from_slice(forwarded_target);
        forwarded_line.push(b' ');
        // hyper only understands HTTP/1.x.
        forwarded_line.extend_from_slice(if matches!(version, b"HTTP/1.0" | b"HTTP/1.1") {
            version
        } else {
            b"HTTP/1.1"
        });
        // Go's server removes `Transfer-Encoding` before it frames the body, and decodes
        // only a single `chunked` coding, so hyper must not see the forms Go rejects or
        // ignores: its own parser would answer before the handler (`Verdict`).
        let transfer_encoding = parse_transfer_encoding((major, minor), header_lines);
        let forwarded_lines: Vec<&[u8]> = if transfer_encoding == TransferEncoding::Chunked {
            header_lines.to_vec()
        } else {
            header_lines
                .iter()
                .copied()
                .filter(|line| transfer_encoding_value(line).is_none())
                .collect()
        };
        let forwarded = forwarded_head(&forwarded_line, &forwarded_lines);

        let mut header_storage = [httparse::EMPTY_HEADER; 128];
        let Ok(httparse::Status::Complete((_, headers))) = httparse::parse_headers(
            forwarded
                .get(forwarded_line.len().saturating_add(2)..)
                .unwrap_or_default(),
            &mut header_storage,
        ) else {
            // shortcut: more than 128 header lines fail closed with 400 before the WAF;
            // Go accepts 500 values (`DefaultMaxHeaderValueCount`).
            return (None, forwarded);
        };
        let mut headers: Vec<(String, Vec<u8>)> = headers
            .iter()
            .map(|header| (canonical_header_name(header.name), header.value.to_vec()))
            .collect();
        if transfer_encoding == TransferEncoding::Chunked {
            // Go re-adds one header per accepted coding, lowercased, not the raw value
            // (`http/middleware.go:71-74`, v3.8.1).
            for (name, value) in &mut headers {
                if name.eq_ignore_ascii_case("transfer-encoding") {
                    *value = b"chunked".to_vec();
                }
            }
        }
        let content_lengths_agree = collapse_content_length(&mut headers);

        let hosts: Vec<&[u8]> = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.as_slice())
            .collect();
        let target_valid = target_rendering.is_some();
        let method = String::from_utf8_lossy(method).into_owned();
        // Go uses the target's authority as `req.Host` and falls back to the header when that
        // authority is empty (`net/http/request.go:1158-1163`).
        let host = target_rendering
            .as_ref()
            .and_then(|rendering| rendering.host.as_deref())
            .filter(|host| !host.is_empty())
            .map(<[u8]>::to_vec)
            .or_else(|| hosts.first().map(|host| (*host).to_vec()));
        let path = target_rendering
            .as_ref()
            .map_or_else(Vec::new, |rendering| rendering.path.clone());
        let rendered = target_rendering.map_or_else(Vec::new, |rendering| rendering.rendered);

        // Go's `isH2Upgrade` accepts the HTTP/2 preface only with no headers at all; the
        // HTTP/1 server then skips its missing-Host check for it
        // (`net/http/request.go:532-536`, `net/http/server.go:1062-1083`).
        let is_h2_upgrade =
            method == "PRI" && path.as_slice() == b"*" && (major, minor) == (2, 0) && headers.is_empty();
        // Go rejects the request line and target (`readRequest`), then an unsupported
        // transfer coding and the `Content-Length`/`Host` checks, then the protocol
        // (`http1ServerSupportsRequest`), all before its handler
        // (`net/http/server.go:1062-1083`, `2103-2110`). Both `Host` checks answer 400.
        let missing_host =
            proto_at_least(major, minor, (1, 1)) && hosts.is_empty() && !is_h2_upgrade && method != "CONNECT";
        let malformed_host = hosts.first().is_some_and(|host| !is_valid_host_header(host));
        let verdict = if !target_valid {
            Verdict::BadRequest
        } else if transfer_encoding == TransferEncoding::Unsupported {
            Verdict::NotImplemented
        } else if !content_lengths_agree || hosts.len() > 1 {
            Verdict::BadRequest
        } else if !supports_version(major, minor, method.as_bytes(), target) {
            Verdict::UnsupportedVersion
        } else if missing_host || malformed_host {
            Verdict::BadRequest
        } else {
            Verdict::Serve
        };

        (
            Some(Self {
                method,
                target: target.to_vec(),
                protocol: String::from_utf8_lossy(version).into_owned(),
                verdict,
                rendered,
                path,
                host,
                headers,
            }),
            forwarded,
        )
    }

    /// The first header with `name`, compared case-insensitively.
    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_slice())
    }
}

/// Rebuild a request head with CRLF line endings and no trailing blank line of its own.
fn forwarded_head(request_line: &[u8], header_lines: &[&[u8]]) -> Vec<u8> {
    let mut head = Vec::new();
    head.extend_from_slice(request_line);
    head.extend_from_slice(b"\r\n");
    for line in header_lines {
        head.extend_from_slice(line);
        head.extend_from_slice(b"\r\n");
    }
    head
}

/// Parse `HTTP/<major>.<minor>`, the only protocol syntax Go's server accepts.
///
/// `ParseHTTPVersion` requires exactly one digit per number, so `HTTP/12.3` is a bad request
/// rather than an unsupported version (`net/http/request.go:827-848`, go1.27).
fn parse_http_version(version: &[u8]) -> Option<(u8, u8)> {
    match version.strip_prefix(b"HTTP/")? {
        [major, b'.', minor] if major.is_ascii_digit() && minor.is_ascii_digit() => Some((major - b'0', minor - b'0')),
        _ => None,
    }
}

/// Whether Go's HTTP/1.x server supports the request's protocol.
///
/// A 1.x major runs the handler; HTTP/2.0 is only accepted for the `PRI *` preface, which Go
/// lets through so handlers can wire up HTTP/2 upgrades (`net/http/server.go:1127-1140`).
fn supports_version(major: u8, minor: u8, method: &[u8], target: &[u8]) -> bool {
    major == 1 || (major == 2 && minor == 0 && method == b"PRI" && target == b"*")
}

/// The value of a `Transfer-Encoding` header line, or `None` for any other line.
fn transfer_encoding_value(line: &[u8]) -> Option<&[u8]> {
    let colon = line.iter().position(|&byte| byte == b':')?;
    let name = line.get(..colon)?;
    if name.eq_ignore_ascii_case(b"transfer-encoding") {
        line.get(colon.saturating_add(1)..)
    } else {
        None
    }
}

/// Classify a request's `Transfer-Encoding` as Go's `parseTransferEncoding` does.
///
/// Go ignores the header on HTTP/1.0 requests, and accepts exactly one header whose only
/// coding is `chunked`, compared without case. Every other form is an
/// `unsupportedTEError`, which the server answers 501 before any handler
/// (`net/http/transfer.go:639-664`, `net/http/server.go:2103-2110`, go1.27).
fn parse_transfer_encoding(protocol: (u8, u8), header_lines: &[&[u8]]) -> TransferEncoding {
    let mut values = header_lines.iter().filter_map(|line| transfer_encoding_value(line));
    let Some(value) = values.next() else {
        return TransferEncoding::Absent;
    };
    if !proto_at_least(protocol.0, protocol.1, (1, 1)) {
        return TransferEncoding::Absent;
    }
    if values.next().is_some() {
        return TransferEncoding::Unsupported;
    }
    if trim_ascii_whitespace(value).eq_ignore_ascii_case(b"chunked") {
        TransferEncoding::Chunked
    } else {
        TransferEncoding::Unsupported
    }
}

/// Whether a protocol is at least `wanted`, as Go's `Request.ProtoAtLeast`.
fn proto_at_least(major: u8, minor: u8, wanted: (u8, u8)) -> bool {
    major > wanted.0 || (major == wanted.0 && minor >= wanted.1)
}

/// Whether Go's `httpguts.ValidHostHeader` accepts `host` (`x/net/http/httpguts/httplex.go`).
fn is_valid_host_header(host: &[u8]) -> bool {
    host.iter().all(|&byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'$'
                    | b'%'
                    | b'&'
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b'-'
                    | b'.'
                    | b':'
                    | b';'
                    | b'='
                    | b'['
                    | b'\''
                    | b']'
                    | b'_'
                    | b'~'
            )
    })
}

/// Collapse byte-identical duplicate `Content-Length` headers to the first.
///
/// Go's `fixLength` deletes the duplicates and re-adds the trimmed first value, and rejects
/// differing values as a smuggling attempt (`net/http/transfer.go:669-691`). Returns whether
/// the values agree.
fn collapse_content_length(headers: &mut Vec<(String, Vec<u8>)>) -> bool {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| trim_ascii_whitespace(value));
    let Some(first) = values.next() else {
        return true;
    };
    if values.any(|value| value != first) {
        return false;
    }
    let mut kept = false;
    headers.retain(|(name, _)| {
        if !name.eq_ignore_ascii_case("content-length") {
            return true;
        }
        let keep = !kept;
        kept = true;
        keep
    });
    true
}

/// `bytes` without leading or trailing spaces and tabs, as Go's `textproto.TrimString` does.
fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |end| end.saturating_add(1));
    bytes.get(start..end).unwrap_or_default()
}

/// Go's `net/url` rendering of a request target.
///
/// This mirrors the engine's private helpers in `coraza/src/transaction.rs`: Go Coraza's
/// middleware passes `req.URL.String()` to `ProcessURI`, so the target the WAF sees is the
/// escaped, re-rendered URL rather than the bytes on the wire (`http/middleware.go:48`,
/// v3.8.1). The engine cannot be reached from this example, so the subset of `net/url` that
/// request targets use is ported here.
mod go_url {
    /// Go's rendering of one target: `url.ParseRequestURI(target).String()`.
    pub(super) struct RequestTarget {
        /// The escaped target.
        pub(super) rendered: Vec<u8>,
        /// The decoded path, as Go's handler reads it from `req.URL.Path`.
        pub(super) path: Vec<u8>,
        /// The authority's host for absolute-form targets, as `req.URL.Host`.
        pub(super) host: Option<Vec<u8>>,
    }

    /// Which Go `encode*` set applies when percent-encoding.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum EscapeMode {
        /// A URL path.
        Path,
        /// A host name.
        Host,
        /// An IPv6 zone identifier.
        Zone,
        /// A userinfo user name or password.
        UserPassword,
    }

    /// A user name and optional password, both decoded.
    type UserInfo = (Vec<u8>, Option<Vec<u8>>);

    /// Parse and render a request target as Go's server does before its handler runs.
    ///
    /// Returns `None` for the targets `url.ParseRequestURI` rejects, which Go answers with
    /// 400 (`net/http/request.go:1141-1147`, `net/url/url.go:432-620`, go1.27).
    #[expect(
        clippy::too_many_lines,
        reason = "The steps follow Go's `net/url` parse and `URL.String` in order."
    )]
    pub(super) fn render_target(method: &[u8], target: &[u8]) -> Option<RequestTarget> {
        if target.is_empty() || target.iter().any(|&byte| byte < 0x20 || byte == 0x7F) {
            return None;
        }

        // Go reads a CONNECT target as authority-form by prefixing `http://`, then strips
        // the scheme back off.
        let mut prefixed = Vec::new();
        let authority_form = method == b"CONNECT" && !target.starts_with(b"/");
        // `ParseRequestURI` treats `*` as the asterisk-form path, unless CONNECT made the
        // target part of an authority.
        if target == b"*" && !authority_form {
            return Some(RequestTarget {
                rendered: b"*".to_vec(),
                path: b"*".to_vec(),
                host: None,
            });
        }
        let raw = if authority_form {
            prefixed.extend_from_slice(b"http://");
            prefixed.extend_from_slice(target);
            prefixed.as_slice()
        } else {
            target
        };

        let (scheme, rest) = split_scheme(raw)?;
        let (rest, raw_query, force_query) = split_query(rest);
        if !rest.starts_with(b"/") {
            if scheme.is_empty() {
                // `ParseRequestURI` only accepts absolute URIs or absolute paths.
                return None;
            }
            // A rootless path after a scheme is opaque.
            let mut rendered = scheme;
            rendered.push(b':');
            rendered.extend_from_slice(rest);
            if force_query || !raw_query.is_empty() {
                rendered.push(b'?');
                rendered.extend_from_slice(raw_query);
            }
            return Some(RequestTarget {
                rendered,
                path: Vec::new(),
                host: None,
            });
        }

        let (host, userinfo, path_source, omit_host) = if !scheme.is_empty() && rest.starts_with(b"//") {
            let after_slashes = rest.strip_prefix(b"//").unwrap_or_default();
            let (authority, path) = match after_slashes.iter().position(|&byte| byte == b'/') {
                Some(index) => (
                    after_slashes.get(..index).unwrap_or_default(),
                    after_slashes.get(index..).unwrap_or_default(),
                ),
                None => (after_slashes, &b""[..]),
            };
            let (userinfo, host) = parse_authority(authority)?;
            (Some(host), userinfo, path, false)
        } else if scheme.is_empty() {
            (None, None, rest, false)
        } else {
            (None, None, rest, true)
        };
        let scheme = if authority_form { Vec::new() } else { scheme };

        let path = unescape(path_source, EscapeMode::Path)?;
        // `setPath` keeps the raw path only when Go's default encoding of it differs and the
        // raw form is already valid, and `EscapedPath` then returns it unchanged.
        let escaped_path = if valid_encoded(path_source) {
            path_source.to_vec()
        } else {
            escape(&path, EscapeMode::Path)
        };

        let mut rendered = Vec::new();
        if !scheme.is_empty() {
            rendered.extend_from_slice(&scheme);
            rendered.push(b':');
        }
        if scheme.is_empty() && host.is_none() && userinfo.is_none() {
            rendered.extend_from_slice(&escaped_path);
        } else if omit_host {
            match escaped_path.strip_prefix(b"//") {
                Some(path) => {
                    // Escape the first slash so re-parsing does not read an authority.
                    rendered.extend_from_slice(b"%2F");
                    rendered.extend_from_slice(path);
                },
                None => rendered.extend_from_slice(&escaped_path),
            }
        } else {
            let host_present = host.as_ref().is_some_and(|host| !host.is_empty());
            if host_present || !escaped_path.is_empty() || userinfo.is_some() {
                rendered.extend_from_slice(b"//");
            }
            if let Some((username, password)) = &userinfo {
                rendered.extend_from_slice(&escape(username, EscapeMode::UserPassword));
                if let Some(password) = password {
                    rendered.push(b':');
                    rendered.extend_from_slice(&escape(password, EscapeMode::UserPassword));
                }
                rendered.push(b'@');
            }
            if let Some(host) = &host {
                rendered.extend_from_slice(&escape(host, EscapeMode::Host));
            }
            if !escaped_path.is_empty() && !escaped_path.starts_with(b"/") && host_present {
                rendered.push(b'/');
            }
            rendered.extend_from_slice(&escaped_path);
        }
        if force_query || !raw_query.is_empty() {
            rendered.push(b'?');
            rendered.extend_from_slice(raw_query);
        }

        Some(RequestTarget { rendered, path, host })
    }

    /// Split the scheme from a target, lowercased, following Go's `getScheme`.
    fn split_scheme(target: &[u8]) -> Option<(Vec<u8>, &[u8])> {
        for (index, &byte) in target.iter().enumerate() {
            match byte {
                b'a'..=b'z' | b'A'..=b'Z' => {},
                b'0'..=b'9' | b'+' | b'-' | b'.' => {
                    if index == 0 {
                        return Some((Vec::new(), target));
                    }
                },
                b':' => {
                    if index == 0 {
                        return None;
                    }
                    return Some((
                        target.get(..index).unwrap_or_default().to_ascii_lowercase(),
                        target.get(index.saturating_add(1)..)?,
                    ));
                },
                _ => return Some((Vec::new(), target)),
            }
        }
        Some((Vec::new(), target))
    }

    /// Split a trailing query from the rest of the target.
    fn split_query(rest: &[u8]) -> (&[u8], &[u8], bool) {
        if rest.ends_with(b"?") && rest.iter().filter(|&&byte| byte == b'?').count() == 1 {
            (rest.get(..rest.len().saturating_sub(1)).unwrap_or_default(), b"", true)
        } else {
            match rest.iter().position(|&byte| byte == b'?') {
                Some(index) => (
                    rest.get(..index).unwrap_or_default(),
                    rest.get(index.saturating_add(1)..).unwrap_or_default(),
                    false,
                ),
                None => (rest, b"", false),
            }
        }
    }

    /// Parse an authority into optional userinfo and a host.
    fn parse_authority(authority: &[u8]) -> Option<(Option<UserInfo>, Vec<u8>)> {
        let at = authority.iter().rposition(|&byte| byte == b'@');
        let host_part = match at {
            Some(index) => authority.get(index.saturating_add(1)..).unwrap_or_default(),
            None => authority,
        };
        let host = parse_host(host_part)?;
        let Some(at) = at else {
            return Some((None, host));
        };
        let userinfo = authority.get(..at).unwrap_or_default();
        if !valid_userinfo(userinfo) {
            return None;
        }
        let userinfo = match userinfo.iter().position(|&byte| byte == b':') {
            None => (unescape(userinfo, EscapeMode::UserPassword)?, None),
            Some(colon) => (
                unescape(userinfo.get(..colon).unwrap_or_default(), EscapeMode::UserPassword)?,
                Some(unescape(
                    userinfo.get(colon.saturating_add(1)..).unwrap_or_default(),
                    EscapeMode::UserPassword,
                )?),
            ),
        };
        Some((Some(userinfo), host))
    }

    /// Validate and decode a host, rejecting the malformed ports and IP literals Go rejects.
    fn parse_host(host: &[u8]) -> Option<Vec<u8>> {
        if let Some(open) = host.iter().rposition(|&byte| byte == b'[') {
            if open > 0 {
                return None;
            }
            let close = host.iter().rposition(|&byte| byte == b']')?;
            let colon_port = host.get(close.saturating_add(1)..).unwrap_or_default();
            if !valid_optional_port(colon_port) {
                return None;
            }
            let colon_port = unescape(colon_port, EscapeMode::Host)?;
            let literal = host.get(1..close)?;
            let literal = match literal.windows(3).position(|window| window == b"%25") {
                Some(zone) => {
                    let mut hostname = unescape(literal.get(..zone)?, EscapeMode::Host)?;
                    hostname.extend_from_slice(&unescape(literal.get(zone..)?, EscapeMode::Zone)?);
                    hostname
                },
                None => unescape(literal, EscapeMode::Host)?,
            };
            if !valid_ip_literal(&literal) {
                return None;
            }
            let mut host = Vec::new();
            host.push(b'[');
            host.extend_from_slice(&literal);
            host.push(b']');
            host.extend_from_slice(&colon_port);
            return Some(host);
        }
        if let Some(colon) = host.iter().rposition(|&byte| byte == b':') {
            // The pinned Coraza module declares Go 1.25, so `net/url` keeps its historical
            // last-colon port split instead of the stricter Go 1.26 multi-colon rule.
            if !valid_optional_port(host.get(colon..).unwrap_or_default()) {
                return None;
            }
        }
        unescape(host, EscapeMode::Host)
    }

    /// Whether `text` contains only the characters Go accepts before an `@` in a URL.
    fn valid_userinfo(text: &[u8]) -> bool {
        text.iter().all(|&byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'.'
                        | b'_'
                        | b':'
                        | b'~'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'\''
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b'%'
                        | b'@'
                )
        })
    }

    /// Whether a bracketed host is an IPv6 literal, optionally with a non-empty zone.
    ///
    /// Go's `netip.ParseAddr` requires a non-empty zone but does not require it to be UTF-8
    /// (`net/netip/netip.go:214-220`). Only the address part is parsed.
    fn valid_ip_literal(hostname: &[u8]) -> bool {
        let (address, zone) = match hostname.iter().position(|&byte| byte == b'%') {
            Some(percent) => (
                hostname.get(..percent).unwrap_or_default(),
                Some(hostname.get(percent.saturating_add(1)..).unwrap_or_default()),
            ),
            None => (hostname, None),
        };
        if zone.is_some_and(<[u8]>::is_empty) {
            return false;
        }
        let Ok(address) = std::str::from_utf8(address) else {
            return false;
        };
        address.parse::<std::net::Ipv6Addr>().is_ok()
    }

    /// Whether `port` is empty or a colon followed by digits.
    fn valid_optional_port(port: &[u8]) -> bool {
        match port {
            [] => true,
            [b':', digits @ ..] => digits.iter().all(u8::is_ascii_digit),
            _ => false,
        }
    }

    /// Whether bytes form an escaped path Go would return unchanged from `EscapedPath`.
    fn valid_encoded(bytes: &[u8]) -> bool {
        bytes.iter().all(|&byte| {
            matches!(
                byte,
                b'!' | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'['
                    | b']'
                    | b'%'
            ) || !should_escape(byte, EscapeMode::Path)
        })
    }

    /// Whether `byte` must be percent-encoded in `mode`, following Go's `shouldEscape`.
    fn should_escape(byte: u8, mode: EscapeMode) -> bool {
        if byte.is_ascii_alphanumeric() {
            return false;
        }
        if matches!(mode, EscapeMode::Host | EscapeMode::Zone)
            && matches!(
                byte,
                b'!' | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'['
                    | b']'
                    | b'<'
                    | b'>'
                    | b'"'
            )
        {
            return false;
        }
        match byte {
            b'-' | b'_' | b'.' | b'~' => false,
            b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
                EscapeMode::Path => byte == b'?',
                EscapeMode::UserPassword => matches!(byte, b'@' | b'/' | b'?' | b':'),
                EscapeMode::Host | EscapeMode::Zone => true,
            },
            _ => true,
        }
    }

    /// Percent-encode `bytes` for `mode` with upper-case hex digits.
    fn escape(bytes: &[u8], mode: EscapeMode) -> Vec<u8> {
        let mut escaped = Vec::with_capacity(bytes.len());
        for &byte in bytes {
            if should_escape(byte, mode) {
                escaped.push(b'%');
                escaped.push(hex_digit(byte >> 4));
                escaped.push(hex_digit(byte & 0x0F));
            } else {
                escaped.push(byte);
            }
        }
        escaped
    }

    /// The upper-case hex digit of a nibble.
    const fn hex_digit(value: u8) -> u8 {
        if value < 10 { b'0' + value } else { b'A' + value - 10 }
    }

    /// Percent-decode `bytes`, enforcing the mode-specific restrictions Go applies.
    fn unescape(bytes: &[u8], mode: EscapeMode) -> Option<Vec<u8>> {
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut offset = 0;
        while let Some(&byte) = bytes.get(offset) {
            match byte {
                b'%' => {
                    let high = *bytes.get(offset.saturating_add(1))?;
                    let low = *bytes.get(offset.saturating_add(2))?;
                    if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                        return None;
                    }
                    let value = (unhex(high) << 4) | unhex(low);
                    let escaped = bytes.get(offset..offset.saturating_add(3));
                    if mode == EscapeMode::Host && unhex(high) < 8 && escaped != Some(&b"%25"[..]) {
                        return None;
                    }
                    if mode == EscapeMode::Zone
                        && escaped != Some(&b"%25"[..])
                        && value != b' '
                        && should_escape(value, EscapeMode::Host)
                    {
                        return None;
                    }
                    decoded.push(value);
                    offset = offset.saturating_add(3);
                },
                byte => {
                    if matches!(mode, EscapeMode::Host | EscapeMode::Zone) && byte < 0x80 && should_escape(byte, mode) {
                        return None;
                    }
                    decoded.push(byte);
                    offset = offset.saturating_add(1);
                },
            }
        }
        Some(decoded)
    }

    /// The value of one hex digit.
    const fn unhex(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => 0,
        }
    }
}

/// Whether hyper's URI parser accepts every byte of an origin-form request target.
fn is_forwardable_target(target: &[u8]) -> bool {
    target.iter().all(|&byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b':'
                    | b'/'
                    | b'?'
                    | b'['
                    | b']'
                    | b'@'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b'%'
            )
    })
}

/// Whether `byte` is a valid HTTP method character (RFC 7230 `tchar`).
fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

/// Reads the first request head to record it for the WAF, then forwards the rest untouched.
///
/// The connection serves one request, so only the first head needs rewriting.
struct HeadCapturingIo<S> {
    /// The wrapped connection.
    inner: S,
    /// Bytes read before the head was complete.
    pending: Vec<u8>,
    /// Bytes waiting to be returned to hyper.
    out: Vec<u8>,
    /// How much of `out` was already returned.
    out_pos: usize,
    /// Whether the head was handled and reads pass through.
    head_done: bool,
    /// The head the handler consumes.
    head: Arc<Mutex<Option<RequestHead>>>,
}

impl<S> HeadCapturingIo<S> {
    /// Wrap a connection.
    fn new(inner: S, head: Arc<Mutex<Option<RequestHead>>>) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            head_done: false,
            head,
        }
    }

    /// Parse a complete head and queue the bytes hyper will see.
    fn finish_head(&mut self, head_end: usize) {
        let pending = std::mem::take(&mut self.pending);
        let (head, rest) = pending.split_at(head_end);
        // A malformed head still yields a forwarded head, so hyper answers 400 instead of
        // stalling on bare-LF or otherwise unparseable bytes.
        let (parsed, forwarded) = RequestHead::parse(head);
        *self.head.lock().unwrap_or_else(PoisonError::into_inner) = parsed;
        self.out = forwarded;
        self.out.extend_from_slice(rest);
        self.out_pos = 0;
        self.head_done = true;
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HeadCapturingIo<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.out_pos < this.out.len() {
                let count = (this.out.len() - this.out_pos).min(buf.remaining());
                let end = this.out_pos.saturating_add(count);
                if let Some(chunk) = this.out.get(this.out_pos..end) {
                    buf.put_slice(chunk);
                }
                this.out_pos = end;
                return Poll::Ready(Ok(()));
            }
            if this.head_done {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            let mut scratch = [0_u8; 8192];
            let mut read = ReadBuf::new(&mut scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let filled = read.filled();
                    if filled.is_empty() || this.pending.len().saturating_add(filled.len()) > MAX_HEAD_BYTES {
                        // EOF or an oversized head: forward what arrived and leave it to hyper.
                        this.out = std::mem::take(&mut this.pending);
                        this.out.extend_from_slice(filled);
                        this.out_pos = 0;
                        this.head_done = true;
                        continue;
                    }
                    this.pending.extend_from_slice(filled);
                    if let Some(head_end) = find_head_end(&this.pending) {
                        this.finish_head(head_end);
                    }
                },
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HeadCapturingIo<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The offset just past the first blank line, which ends the request head.
///
/// Go's `textproto.Reader.ReadLine` accepts a bare LF, so a head may also end with `\n\n`,
/// `\r\n\n` or `\n\r\n`; only looking for `\r\n\r\n` would make those wait forever
/// (`net/textproto/reader.go:ReadLine`, go1.27).
fn find_head_end(bytes: &[u8]) -> Option<usize> {
    let mut line_start = 0;
    while let Some(offset) = bytes.get(line_start..)?.iter().position(|&byte| byte == b'\n') {
        let line_end = line_start.saturating_add(offset).saturating_add(1);
        let rest = bytes.get(line_end..)?;
        let blank_len = match rest {
            [b'\n', ..] => 1,
            [b'\r', b'\n', ..] => 2,
            _ => {
                line_start = line_end;
                continue;
            },
        };
        return Some(line_end.saturating_add(blank_len));
    }
    None
}

/// Set the connection variables Go Coraza's `ProcessConnection` sets.
fn set_connection(tx: &mut coraza::transaction::Transaction, peer_addr: SocketAddr, local_addr: SocketAddr) {
    tx.set_remote_addr(peer_addr.ip().to_string());
    tx.set_remote_port(peer_addr.port());
    tx.set_server_addr(local_addr.ip().to_string());
    tx.set_server_port(local_addr.port());
}

#[expect(
    clippy::print_stdout,
    reason = "The standalone FTW server reports startup and connection status to its console."
)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Coraza FTW test server (async)");

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let options = Options::parse(&args)?;

    println!("Configuration:");
    println!("   Port: {}", options.port);
    println!("   Logfile: {}", options.logfile);
    if let Some(rules) = &options.rules_file {
        println!("   Rules: {rules}");
    }
    if options.strict {
        println!("   Mode: strict");
    }
    println!();

    let logfile: Logfile = Arc::new(Mutex::new(
        OpenOptions::new().create(true).append(true).open(&options.logfile)?,
    ));
    let (waf, inventory) = load_policy(&options, &logfile)?;
    if let Some(path) = &options.inventory_file {
        write_inventory(&inventory, path)?;
    }
    if options.rules_file.is_some() {
        println!("Loaded {} rules", inventory.rules_loaded);
    }

    // Create shared state
    let waf = Arc::new(waf);

    // Bind to address
    let addr = SocketAddr::from(([127, 0, 0, 1], options.port));

    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;

    println!("Server listening on http://{local_addr}");

    // Accept connections
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let waf = Arc::clone(&waf);
        let logfile = Arc::clone(&logfile);
        let readiness_token = options.readiness_token.clone();

        // Spawn a task to handle the connection
        tokio::task::spawn(async move {
            serve_connection(stream, peer_addr, local_addr, waf, logfile, readiness_token).await;
        });
    }
}

/// Serve one connection: capture the raw request head, then let hyper handle the body and response.
#[expect(
    clippy::too_many_arguments,
    clippy::print_stderr,
    reason = "The standalone FTW server forwards the listener's settings unchanged and reports \
              connection failures to its console."
)]
async fn serve_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    waf: Arc<Waf>,
    logfile: Logfile,
    readiness_token: Option<String>,
) {
    let head = Arc::new(Mutex::new(None));
    let io = TokioIo::new(HeadCapturingIo::new(stream, Arc::clone(&head)));
    let service = service_fn(move |req| {
        let head = head.lock().unwrap_or_else(PoisonError::into_inner).take();
        handle_request(
            req,
            head,
            Arc::clone(&waf),
            Arc::clone(&logfile),
            readiness_token.clone(),
            peer_addr,
            local_addr,
        )
    });

    // One request per connection: only its first head is captured for the WAF.
    if let Err(err) = http1::Builder::new()
        .keep_alive(false)
        .serve_connection(io, service)
        .await
    {
        eprintln!("Error serving connection: {err:?}");
    }
}

/// Handle a single HTTP request through the WAF
#[expect(
    clippy::too_many_arguments,
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "The request needs its connection context and the FTW server logs each request."
)]
async fn handle_request(
    req: Request<Incoming>,
    head: Option<RequestHead>,
    waf: Arc<Waf>,
    logfile: Logfile,
    readiness_token: Option<String>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // The head capture only fails on a request hyper accepted but the server could not inspect.
    let Some(head) = head else {
        return Ok(create_error_response(400, "Bad Request"));
    };
    let method = head.method.as_str();
    let protocol = head.protocol.as_str();

    println!("{method} {} {protocol}", String::from_utf8_lossy(&head.target));

    // Go's server answers 501/505/400 before running the handler, as `readRequest`,
    // `http1ServerSupportsRequest` and its transfer-coding checks do.
    match head.verdict {
        Verdict::UnsupportedVersion => return Ok(create_error_response(505, "HTTP Version Not Supported")),
        Verdict::NotImplemented => return Ok(create_error_response(501, "Unsupported transfer encoding")),
        Verdict::BadRequest => return Ok(create_error_response(400, "Bad Request")),
        Verdict::Serve => {},
    }

    let path = head.path.as_slice();
    if let Some(token) = readiness_token
        && method == "GET"
        && path.strip_prefix(b"/.well-known/coraza-ftw-health/") == Some(token.as_bytes())
    {
        return Ok(response(200, &[], token.into_bytes()));
    }

    // Before the request's own error log lines, which FTW looks for after it
    if let Some(marker) = head
        .header("x-crs-test")
        .and_then(|value| std::str::from_utf8(value).ok())
    {
        write_marker(&logfile, marker);
    }

    let mut tx = waf.new_transaction();
    // Go sets the connection before the URI.
    set_connection(&mut tx, peer_addr, local_addr);
    // Go's middleware processes `req.URL.String()`, not the bytes on the wire.
    tx.process_uri(&head.rendered, method, protocol);
    if let Some(host) = head.host.as_deref().filter(|host| !host.is_empty()) {
        tx.set_server_name(host);
    }
    add_request_headers(&mut tx, &head.headers, head.host.as_deref());

    let response = if let Some(interruption) = tx.process_request_headers() {
        create_blocking_response(&interruption)
    } else {
        let max_body_bytes = usize::try_from(tx.request_body_limit())
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        match tokio::time::timeout(
            REQUEST_BODY_READ_TIMEOUT,
            collect_body_prefix(req.into_body(), max_body_bytes),
        )
        .await
        {
            Ok(Ok(body)) => run_transaction(&mut tx, path, &body),
            Ok(Err(error)) => {
                eprintln!("Error reading body: {error}");
                create_error_response(500, "Internal Server Error")
            },
            Err(_) => {
                eprintln!("Timed out reading request body");
                create_error_response(408, "Request Timeout")
            },
        }
    };

    // As Go Coraza's HTTP middleware does, whether or not the transaction was interrupted
    if let Err(e) = tx.process_logging() {
        eprintln!("failed to write the audit log: {e}");
    }

    Ok(response)
}

/// Collect at most `max_bytes` of request data while draining the body stream to EOF.
///
/// # Errors
///
/// Returns the body error if reading a frame fails.
async fn collect_body_prefix<B>(mut body: B, max_bytes: usize) -> Result<Vec<u8>, B::Error>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if collected.len() >= max_bytes {
            continue;
        }
        if let Ok(data) = frame.into_data() {
            let count = (max_bytes - collected.len()).min(data.len());
            collected.extend_from_slice(data.get(..count).unwrap_or_default());
        }
    }
    Ok(collected)
}

/// Copy request header names and original values into the transaction, as Go Coraza's
/// HTTP middleware hands them over.
///
/// Go's server removes `Host` and `Transfer-Encoding` from the header map, its request
/// reader removes `Content-Length` when `Transfer-Encoding` is present
/// (`net/http/transfer.go:726-729`), and the middleware re-adds a non-empty `Host` and
/// each `Transfer-Encoding` value (`http/middleware.go:48-62`, v3.8.1). A clone of a Go
/// server therefore never shows the WAF a `Content-Length` beside a `Transfer-Encoding`
/// (CRS 920181) and shows it no `Host` at all when the header is empty (CRS 920280, not
/// 920290). `Host` is added from `req.Host`, which the server takes from the target's
/// authority for absolute-form requests.
fn add_request_headers(tx: &mut coraza::transaction::Transaction, headers: &[(String, Vec<u8>)], host: Option<&[u8]>) {
    let has_transfer_encoding = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"));
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        if has_transfer_encoding && name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        tx.add_request_header(name, value);
    }
    if let Some(host) = host.filter(|host| !host.is_empty()) {
        tx.add_request_header("Host", host);
    }
}

/// Runs the request body and response phases after request headers were processed.
/// The backend answers between them, as CRS's albedo test backend does for `/reflect`.
fn run_transaction(tx: &mut coraza::transaction::Transaction, path: &[u8], body: &[u8]) -> Response<Full<Bytes>> {
    if let Some(interruption) = tx.process_request_body(body) {
        return create_blocking_response(&interruption);
    }

    let backend = BackendResponse::for_request(path, body);

    // Go Coraza's CRS test harness sets this on every response
    if !has_content_type(&backend.headers) {
        tx.add_response_header("Content-Type", "text/plain");
    }
    for (name, value) in &backend.headers {
        tx.add_response_header(name, value);
    }
    if let Some(interruption) = tx.process_response_headers(backend.status, "HTTP/1.1") {
        return create_blocking_response(&interruption);
    }
    if let Some(interruption) = tx.process_response_body(&backend.body) {
        return create_blocking_response(&interruption);
    }

    response(backend.status, &backend.headers, backend.body)
}

/// What the backend behind the WAF answers.
struct BackendResponse {
    /// HTTP status returned by the backend.
    status: u16,
    /// Headers returned by the backend.
    headers: Vec<(String, String)>,
    /// Response body returned by the backend.
    body: Vec<u8>,
}

impl BackendResponse {
    /// `OK`; for `/reflect`, what the JSON request body asks for, as albedo answers:
    /// `status`, `headers` and `body` (or base64 `encodedBody`).
    fn for_request(path: &[u8], body: &[u8]) -> Self {
        let ok = Self {
            status: 200,
            headers: Vec::new(),
            body: b"OK".to_vec(),
        };
        if path != b"/reflect" {
            return Self { body: Vec::new(), ..ok };
        }
        let Ok(spec) = serde_json::from_slice::<serde_json::Value>(body) else {
            return ok;
        };
        let body = match (
            spec.get("body").and_then(serde_json::Value::as_str),
            spec.get("encodedBody").and_then(serde_json::Value::as_str),
        ) {
            (Some(body), _) => body.as_bytes().to_vec(),
            (None, Some(encoded)) => STANDARD.decode(encoded).unwrap_or_default(),
            (None, None) => Vec::new(),
        };
        let headers = spec
            .get("headers")
            .and_then(serde_json::Value::as_object)
            .into_iter()
            .flatten()
            .filter_map(|(name, value)| value.as_str().map(|value| (name.clone(), value.to_owned())))
            .collect();
        Self {
            status: spec
                .get("status")
                .and_then(serde_json::Value::as_u64)
                .and_then(|status| u16::try_from(status).ok())
                .unwrap_or(200),
            headers,
            body,
        }
    }
}

/// Has the WAF write Go Coraza's error log line to `logfile` for each matched rule with
/// `log`, as its CRS test harness reads it.
#[expect(
    clippy::print_stderr,
    reason = "The standalone FTW server reports audit log write failures to its console."
)]
fn log_errors_to(parser: &mut Parser, logfile: &Logfile) {
    let logfile = Arc::clone(logfile);
    parser.on_error_log(move |matched| {
        let mut file = logfile.lock().unwrap_or_else(PoisonError::into_inner);
        // A line FTW can't read fails the test that looks for it
        if let Err(error) = writeln!(file, "{}", matched.error_log()) {
            eprintln!("failed to write the FTW error log: {error}");
        }
    });
}

/// Writes the FTW marker of a request, by which FTW finds the request's lines.
#[expect(
    clippy::print_stderr,
    reason = "The standalone FTW server reports marker write failures to its console."
)]
fn write_marker(logfile: &Logfile, marker: &str) {
    let escaped = match log_field(marker) {
        Ok(escaped) => escaped,
        Err(error) => {
            eprintln!("failed to escape the FTW request marker: {error}");
            return;
        },
    };
    let mut file = logfile.lock().unwrap_or_else(PoisonError::into_inner);
    if let Err(error) = writeln!(file, "[X-CRS-Test \"{escaped}\"]") {
        eprintln!("failed to write the FTW request marker: {error}");
    }
}

/// Escape a request marker field so it stays on one log line.
fn log_field(value: &str) -> Result<String, std::fmt::Error> {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\r' => escaped.push_str("\\r"),
            '\n' => escaped.push_str("\\n"),
            character if character.is_control() => {
                write!(escaped, "\\u{{{:x}}}", character as u32)?;
            },
            character => escaped.push(character),
        }
    }
    Ok(escaped)
}

/// Build an HTTP response, adding a default content type when needed.
fn response(status: u16, headers: &[(String, String)], body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    if !has_content_type(headers) {
        response
            .headers_mut()
            .insert("content-type", HeaderValue::from_static("text/plain"));
    }
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            response.headers_mut().append(name, value);
        }
    }
    response
}

/// Return whether backend headers contain a content type.
fn has_content_type(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
}

/// Create an error HTTP response.
fn create_error_response(status: u16, body: &str) -> Response<Full<Bytes>> {
    response(status, &[], body.as_bytes().to_vec())
}

/// Create a blocking response when the WAF interrupts.
#[expect(
    clippy::print_stdout,
    reason = "The standalone FTW server reports blocking decisions to its console."
)]
fn create_blocking_response(interruption: &coraza::transaction::Interruption) -> Response<Full<Bytes>> {
    println!("Blocked by rule {}: {}", interruption.rule_id, interruption.action);
    let status = if interruption.status == 0 {
        StatusCode::INTERNAL_SERVER_ERROR.as_u16()
    } else {
        interruption.status
    };
    let mut response = response(status, &[], b"Blocked by WAF".to_vec());
    if (300..400).contains(&status)
        && !interruption.data.is_empty()
        && let Ok(location) = HeaderValue::from_bytes(interruption.data.as_bytes())
    {
        response.headers_mut().insert("location", location);
    }
    response
}

/// `name` as Go's net/http writes a header name: each letter that starts it or follows
/// a `-` uppercase, the others lowercase.
fn canonical_header_name(name: &str) -> String {
    let mut starts_word = true;
    name.chars()
        .map(|c| {
            let c = if starts_word {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            starts_word = c == '-';
            c
        })
        .collect()
}

/// Get command line argument value
fn get_arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|pos| args.get(pos + 1))
        .cloned()
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "FTW adapter tests use fixed valid inputs")]
mod tests {
    use std::{
        collections::VecDeque,
        convert::Infallible,
        fs::OpenOptions,
        net::SocketAddr,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use coraza::{seclang::Parser, transaction::Interruption};
    use http_body_util::Full;
    use hyper::{
        StatusCode,
        body::{Bytes, Frame},
    };
    use tempfile::{TempDir, tempdir};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        BackendResponse, Logfile, Options, RequestHead, Verdict, add_request_headers, collect_body_prefix,
        create_blocking_response, find_head_end, go_url, has_content_type, load_policy, response, serve_connection,
        set_connection, write_inventory,
    };

    fn test_args(extra: &[&str]) -> Vec<String> {
        let mut args = vec!["ftw_server_async".to_owned()];
        args.extend(extra.iter().map(|value| (*value).to_owned()));
        args
    }

    fn rules_path(dir: &TempDir) -> String {
        dir.path().join("rules.conf").to_string_lossy().into_owned()
    }

    fn test_logfile(dir: &TempDir) -> Logfile {
        Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.path().join("audit.log"))
                .unwrap(),
        ))
    }

    fn write_rules(dir: &TempDir, content: &str) -> String {
        let path = rules_path(dir);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn strict_mode_requires_a_rules_file() {
        let error = Options::parse(&test_args(&["--strict"])).err().unwrap();
        assert!(error.to_string().contains("--strict requires --rules"));
    }

    #[test]
    fn expected_rule_count_requires_strict_mode() {
        let dir = tempdir().unwrap();
        let path = write_rules(&dir, "SecRuleEngine On\n");
        let error = Options::parse(&test_args(&["--rules", &path, "--expected-rules", "1"]))
            .err()
            .unwrap();
        assert!(error.to_string().contains("--expected-rules requires --strict"));
    }

    #[test]
    fn strict_mode_rejects_an_unsupported_directive() {
        let dir = tempdir().unwrap();
        let path = write_rules(&dir, "SecRuleEngine On\nSecBogusDirective value\n");
        let options = Options::parse(&test_args(&["--strict", "--rules", &path])).unwrap();

        let error = load_policy(&options, &test_logfile(&dir)).err().unwrap();
        let message = error.to_string();
        assert!(message.contains("unknown directive"), "unexpected error: {message}");
        assert!(message.contains("SecBogusDirective"), "unexpected error: {message}");
    }

    #[test]
    fn legacy_mode_skips_an_unsupported_rule() {
        let dir = tempdir().unwrap();
        let path = write_rules(
            &dir,
            "SecRuleEngine On\nSecRule ARGS \"@bogusOperator x\" \"id:1,phase:1,pass\"\n",
        );
        let options = Options::parse(&test_args(&["--rules", &path])).unwrap();

        let (_waf, inventory) = load_policy(&options, &test_logfile(&dir)).unwrap();

        assert_eq!(inventory.mode, "legacy");
        assert_eq!(inventory.skipped_directives.len(), 1);
        assert!(inventory.skipped_directives[0].contains("unknown operator"));
    }

    #[test]
    fn legacy_mode_rejects_an_unsupported_directive() {
        let dir = tempdir().unwrap();
        let path = write_rules(&dir, "SecRuleEngine On\nSecBogusDirective value\n");
        let options = Options::parse(&test_args(&["--rules", &path])).unwrap();

        let error = load_policy(&options, &test_logfile(&dir)).err().unwrap();

        assert!(
            error.to_string().contains("unknown directive"),
            "unexpected error: {error}"
        );
        assert!(
            error.to_string().contains("SecBogusDirective"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn strict_mode_checks_the_expected_rule_count() {
        let dir = tempdir().unwrap();
        let path = write_rules(
            &dir,
            "SecRule ARGS \"@contains x\" \"id:998101,phase:1,deny,status:403\"\n",
        );
        let options = Options::parse(&test_args(&["--strict", "--rules", &path, "--expected-rules", "2"])).unwrap();

        let error = load_policy(&options, &test_logfile(&dir)).err().unwrap();
        assert!(
            error.to_string().contains("expected 2 rule(s), loaded 1"),
            "unexpected error: {error}"
        );

        let options = Options::parse(&test_args(&["--strict", "--rules", &path, "--expected-rules", "1"])).unwrap();
        let (_waf, inventory) = load_policy(&options, &test_logfile(&dir)).unwrap();
        assert_eq!(inventory.rules_loaded, 1);
        assert_eq!(inventory.expected_rules, Some(1));
    }

    #[test]
    fn strict_inventory_is_machine_readable() {
        let dir = tempdir().unwrap();
        let path = write_rules(
            &dir,
            "SecRule ARGS \"@contains x\" \"id:998102,phase:1,deny,status:403\"\n",
        );
        let options = Options::parse(&test_args(&["--strict", "--rules", &path])).unwrap();
        let (_waf, inventory) = load_policy(&options, &test_logfile(&dir)).unwrap();

        let value = inventory.to_json();
        assert_eq!(value["mode"], "strict");
        assert_eq!(value["rules_loaded"], 1);
        assert_eq!(value["skipped_directives"].as_array().unwrap().len(), 0);
        assert!(value["expected_rules"].is_null());

        let inventory_path = dir.path().join("inventory.json");
        write_inventory(&inventory, inventory_path.to_str().unwrap()).unwrap();
        let written: serde_json::Value = serde_json::from_slice(&std::fs::read(&inventory_path).unwrap()).unwrap();
        assert_eq!(written["mode"], "strict");
        assert_eq!(written["rules_loaded"], 1);
    }

    #[test]
    fn response_uses_backend_content_type_without_adding_a_default() {
        let headers = [("Content-Type".to_owned(), "application/json".to_owned())];
        let response = response(200, &headers, Vec::new());

        assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
        assert_eq!(response.headers().get_all("content-type").iter().count(), 1);
    }

    #[test]
    fn response_defaults_content_type_when_backend_omits_it() {
        let response = response(200, &[], Vec::new());

        assert_eq!(response.headers().get("content-type").unwrap(), "text/plain");
        assert!(!has_content_type(&[]));
    }

    #[test]
    fn blocking_responses_handle_zero_status_and_redirect_data() {
        let no_status = create_blocking_response(&Interruption {
            rule_id: 1,
            action: "drop".to_owned(),
            status: 0,
            data: String::new(),
        });
        assert_eq!(no_status.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let redirect = create_blocking_response(&Interruption {
            rule_id: 2,
            action: "redirect".to_owned(),
            status: 302,
            data: "https://example.test/blocked".to_owned(),
        });
        assert_eq!(redirect.status(), StatusCode::FOUND);
        assert_eq!(
            redirect.headers().get("location").unwrap(),
            "https://example.test/blocked"
        );

        let denied = create_blocking_response(&Interruption {
            rule_id: 3,
            action: "deny".to_owned(),
            status: 403,
            data: "ignored".to_owned(),
        });
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert!(denied.headers().get("location").is_none());
        assert_eq!(denied.headers().get("content-type").unwrap(), "text/plain");
    }

    #[test]
    fn unmatched_backend_paths_return_an_empty_body() {
        assert!(BackendResponse::for_request(b"/other", b"").body.is_empty());
        assert_eq!(BackendResponse::for_request(b"/reflect", b"invalid JSON").body, b"OK");
    }

    #[test]
    fn request_header_import_preserves_non_utf8_bytes() {
        let mut parser = Parser::new();
        parser
            .from_string(r#"SecRule REQUEST_HEADERS:X-Trace "@rx \xff" "id:998001,phase:1,deny,status:403""#)
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction();
        let headers = [("X-Trace".to_owned(), b"\xff".to_vec())];

        add_request_headers(&mut tx, &headers, None);

        assert_eq!(tx.process_request_headers().unwrap().status, 403);
    }

    #[test]
    fn request_header_import_replaces_host_with_the_request_host() {
        let rules = "\
SecRule REQUEST_HEADERS:Host \"@streq authority.example\" \"id:998002,phase:1,deny,status:403\"\n\
SecRule REQUEST_HEADERS:Host \"@streq header.example\" \"id:998003,phase:1,deny,status:418\"\n";
        let mut parser = Parser::new();
        parser.from_string(rules).unwrap();
        let mut tx = parser.into_waf().unwrap().new_transaction();
        let headers = [
            ("Host".to_owned(), b"header.example".to_vec()),
            ("X-Trace".to_owned(), b"1".to_vec()),
        ];

        add_request_headers(&mut tx, &headers, Some(b"authority.example"));

        assert_eq!(tx.process_request_headers().unwrap().status, 403);
    }

    /// Parse a head and return its parsed form, which every well-formed head yields.
    fn parsed_head(head: &[u8]) -> RequestHead {
        RequestHead::parse(head).0.expect("head should parse")
    }

    /// The verdict for a request line sent with a valid `Host` header.
    fn verdict_for(request_line: &[u8]) -> Verdict {
        let mut head = request_line.to_vec();
        head.extend_from_slice(b"\r\nHost: localhost\r\n\r\n");
        parsed_head(&head).verdict
    }

    #[test]
    fn request_head_keeps_target_bytes_and_forwards_go_rendering() {
        let (parsed, forwarded) = RequestHead::parse(b"GET /x<y>\"z HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let parsed = parsed.unwrap();
        assert_eq!(parsed.target, b"/x<y>\"z");
        assert_eq!(parsed.rendered, b"/x%3Cy%3E%22z");
        assert_eq!(parsed.path, b"/x<y>\"z");
        assert_eq!(parsed.protocol, "HTTP/1.1");
        assert_eq!(parsed.verdict, Verdict::Serve);
        // hyper's URI parser rejects the raw bytes, so it sees Go's rendering.
        assert!(forwarded.starts_with(b"GET /x%3Cy%3E%22z HTTP/1.1\r\n"));

        let (parsed, forwarded) = RequestHead::parse(b"GET http://localhost HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(parsed.unwrap().target, b"http://localhost");
        // Only origin-form targets are forwarded, so hyper cannot reject the target first.
        assert!(forwarded.starts_with(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn request_head_flags_unsupported_versions() {
        let (parsed, forwarded) = RequestHead::parse(b"GET / HTTP/4.0\r\nHost: localhost\r\n\r\n");
        let parsed = parsed.unwrap();
        assert_eq!(parsed.verdict, Verdict::UnsupportedVersion);
        assert_eq!(parsed.protocol, "HTTP/4.0");
        // hyper only understands HTTP/1.x, so the forwarded line uses the supported version.
        assert!(forwarded.starts_with(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn request_head_rejects_malformed_request_lines() {
        for head in [
            b"GET / 1.1\r\nHost: localhost\r\n\r\n".as_slice(),
            b"GET / TEST\r\nHost: localhost\r\n\r\n",
            b"GET / HTTP/12.3\r\nHost: localhost\r\n\r\n",
            b"G@T / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GET /a\x01b HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GET / HTTP/1.1 extra\r\nHost: localhost\r\n\r\n",
        ] {
            let (parsed, forwarded) = RequestHead::parse(head);
            assert!(parsed.is_none(), "{head:?} parsed");
            // hyper still gets a parseable head, so the client sees 400 rather than a stall.
            assert!(forwarded.starts_with(b"GET / HTTP/1.1\r\n"), "{head:?}");
        }
    }

    #[test]
    fn request_head_flags_the_targets_go_rejects() {
        for target in [b"\\".as_slice(), b"\\\\", b"\\foo", b"abc", b"?q=1", b":80", b"/%zz"] {
            let mut line = b"GET ".to_vec();
            line.extend_from_slice(target);
            line.extend_from_slice(b" HTTP/1.1");
            assert_eq!(verdict_for(&line), Verdict::BadRequest, "{target:?} was accepted");
        }

        for target in [
            b"/".as_slice(),
            b"//x",
            b"/x<y>\"z",
            b"*",
            b"abc:def",
            b"localhost:80",
            b"http://localhost",
        ] {
            let mut line = b"GET ".to_vec();
            line.extend_from_slice(target);
            line.extend_from_slice(b" HTTP/1.1");
            assert_eq!(verdict_for(&line), Verdict::Serve, "{target:?} was rejected");
        }

        // Go reads a CONNECT target as authority-form by prefixing `http://`.
        assert_eq!(verdict_for(b"CONNECT www.example.com:443 HTTP/1.1"), Verdict::Serve);
        assert_eq!(verdict_for(b"CONNECT /rpc HTTP/1.1"), Verdict::Serve);
        // CONNECT targets get the same checks as every other method.
        assert_eq!(verdict_for(b"CONNECT bad\\host:443 HTTP/1.1"), Verdict::BadRequest);
    }

    #[test]
    fn target_rendering_matches_go_url_string() {
        // Expected values come from Go 1.27.3 `url.ParseRequestURI(target).String()`.
        for (method, target, rendered, path) in [
            (
                b"GET".as_slice(),
                b"/x<y".as_slice(),
                b"/x%3Cy".as_slice(),
                b"/x<y".as_slice(),
            ),
            (b"GET", b"/x>y", b"/x%3Ey", b"/x>y"),
            (b"GET", b"/x\"y", b"/x%22y", b"/x\"y"),
            (b"GET", b"/x|{}^", b"/x%7C%7B%7D%5E", b"/x|{}^"),
            (b"GET", b"/a#frag", b"/a%23frag", b"/a#frag"),
            (b"GET", b"/a?b#frag", b"/a?b#frag", b"/a"),
            (b"GET", b"/a?q=%zz", b"/a?q=%zz", b"/a"),
            (b"GET", b"/a%2fb", b"/a%2fb", b"/a/b"),
            (b"GET", b"/a%2Fb", b"/a%2Fb", b"/a/b"),
            (b"GET", b"/caf\xff", b"/caf%FF", b"/caf\xff"),
            (b"GET", b"/x?", b"/x?", b"/x"),
            (b"GET", b"//x", b"//x", b"//x"),
            (b"GET", b"*", b"*", b"*"),
            (b"GET", b"http://localhost", b"http://localhost", b""),
            (
                b"GET",
                b"HTTP://User:Pa%20ss@LocalHost:8080/A%2fb?Q=%zz#f",
                b"http://User:Pa%20ss@LocalHost:8080/A%2fb?Q=%zz#f",
                b"/A/b",
            ),
            (b"GET", b"abc:def", b"abc:def", b""),
            (b"GET", b"http:///x", b"http:///x", b"/x"),
            (b"GET", b"http://", b"http:", b""),
            (b"GET", b"http:/x", b"http:/x", b"/x"),
            (b"CONNECT", b"www.example.com:443", b"//www.example.com:443", b""),
            (b"CONNECT", b"/rpc", b"/rpc", b"/rpc"),
            (b"CONNECT", b"*", b"//*", b""),
        ] {
            let rendering = go_url::render_target(method, target).expect("target should parse");
            assert_eq!(rendering.rendered, rendered, "{target:?}");
            assert_eq!(rendering.path, path, "{target:?}");
        }
    }

    #[test]
    fn target_rendering_rejects_what_go_rejects() {
        for target in [
            b"\\".as_slice(),
            b"\\\\",
            b"abc",
            b"?q=1",
            b":80",
            b"/%zz",
            b"/a%2",
            b"http://host:bad/x",
            b"/a\tb",
        ] {
            assert!(
                go_url::render_target(b"GET", target).is_none(),
                "{target:?} was accepted"
            );
        }
    }

    #[test]
    fn request_authority_supplies_the_request_host() {
        let head = parsed_head(b"GET http://user:pw@authority.example:8080/x HTTP/1.1\r\nHost: header.example\r\n\r\n");
        assert_eq!(head.host.as_deref(), Some(b"authority.example:8080".as_slice()));
        assert_eq!(head.path, b"/x");

        let head = parsed_head(b"GET /x HTTP/1.1\r\nHost: header.example\r\n\r\n");
        assert_eq!(head.host.as_deref(), Some(b"header.example".as_slice()));

        // Go falls back to the `Host` header when the target's authority is empty.
        let head = parsed_head(b"GET http:///x HTTP/1.1\r\nHost: header.example\r\n\r\n");
        assert_eq!(head.host.as_deref(), Some(b"header.example".as_slice()));

        let head = parsed_head(b"CONNECT www.example.com:443 HTTP/1.1\r\nHost: header.example\r\n\r\n");
        assert_eq!(head.host.as_deref(), Some(b"www.example.com:443".as_slice()));
        assert_eq!(head.path, b"");
    }

    #[test]
    fn request_head_applies_go_host_and_version_checks() {
        for head in [
            b"GET / HTTP/1.1\r\nHost: one\r\nHost: two\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: bad/host\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: bad\\host\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: bad?host\r\n\r\n",
            // Go validates the `Host` header even when the target's authority wins.
            b"GET http://authority.example/x HTTP/1.1\r\nHost: bad host\r\n\r\n",
        ] {
            assert_eq!(parsed_head(head).verdict, Verdict::BadRequest, "{head:?}");
        }

        // Go only requires a Host header for HTTP/1.1 and later, and accepts an empty one.
        assert_eq!(verdict_for(b"GET / HTTP/1.0"), Verdict::Serve);
        assert_eq!(parsed_head(b"GET / HTTP/1.0\r\n\r\n").verdict, Verdict::Serve);
        assert_eq!(parsed_head(b"GET / HTTP/1.1\r\nHost: \r\n\r\n").verdict, Verdict::Serve);
        assert_eq!(
            parsed_head(b"CONNECT www.example.com:443 HTTP/1.1\r\n\r\n").verdict,
            Verdict::Serve
        );

        // A 1.x major runs the handler; only a well-formed other major is a 505.
        assert_eq!(verdict_for(b"GET / HTTP/1.2"), Verdict::Serve);
        assert_eq!(verdict_for(b"GET / HTTP/4.0"), Verdict::UnsupportedVersion);
        assert_eq!(verdict_for(b"PRI * HTTP/2.0"), Verdict::Serve);
    }

    #[test]
    fn only_the_exact_h2_preface_skips_the_missing_host_check() {
        // Go's `isH2Upgrade` needs method PRI, path `*`, HTTP/2.0 and no headers at all.
        assert_eq!(parsed_head(b"PRI * HTTP/2.0\r\n\r\n").verdict, Verdict::Serve);
        // A `Host` header satisfies the missing-Host check instead.
        assert_eq!(
            parsed_head(b"PRI * HTTP/2.0\r\nHost: localhost\r\n\r\n").verdict,
            Verdict::Serve
        );
        // Any other header makes it not the preface, so the missing Host is a 400.
        assert_eq!(
            parsed_head(b"PRI * HTTP/2.0\r\nX-Test: 1\r\n\r\n").verdict,
            Verdict::BadRequest
        );
        // The exemption is the preface, not the method.
        assert_eq!(parsed_head(b"PRI /x HTTP/1.1\r\n\r\n").verdict, Verdict::BadRequest);
    }

    #[test]
    fn transfer_encoding_matches_go_s_parser() {
        for (head, verdict) in [
            (
                b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
                Verdict::Serve,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: CHUNKED\r\n\r\n",
                Verdict::Serve,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n",
                Verdict::NotImplemented,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
                Verdict::NotImplemented,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: identity\r\n\r\n",
                Verdict::NotImplemented,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\
Transfer-Encoding: chunked\r\n\r\n",
                Verdict::NotImplemented,
            ),
            // Go ignores the header on HTTP/1.0.
            (
                b"POST / HTTP/1.0\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n",
                Verdict::Serve,
            ),
        ] {
            assert_eq!(parsed_head(head).verdict, verdict, "{head:?}");
        }
    }

    #[test]
    fn identical_content_length_headers_collapse_and_differing_ones_are_rejected() {
        let head = parsed_head(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n");
        let lengths: Vec<&[u8]> = head
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.as_slice())
            .collect();
        assert_eq!(lengths, [b"3".as_slice()]);
        assert_eq!(head.verdict, Verdict::Serve);

        let head = parsed_head(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n");
        assert_eq!(head.verdict, Verdict::BadRequest);
    }

    #[test]
    fn head_end_accepts_the_blank_line_forms_go_reads() {
        for head in [
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\nHost: x\n\n",
            b"GET / HTTP/1.1\r\nHost: x\r\n\n",
            b"GET / HTTP/1.1\nHost: x\n\r\n",
        ] {
            assert_eq!(find_head_end(head), Some(head.len()), "{head:?}");
        }
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n"), None);
        assert_eq!(find_head_end(b"GET / HTTP/1.1\nHost: x\n"), None);
    }

    #[test]
    fn lf_only_heads_are_parsed_and_forwarded_with_crlf() {
        let (parsed, forwarded) = RequestHead::parse(b"GET /x HTTP/1.1\nHost: localhost\nX-Test: 1\n\n");
        let parsed = parsed.unwrap();

        assert_eq!(parsed.verdict, Verdict::Serve);
        assert_eq!(parsed.header("host"), Some(b"localhost".as_slice()));
        assert_eq!(forwarded, b"GET /x HTTP/1.1\r\nHost: localhost\r\nX-Test: 1\r\n\r\n");
    }

    #[test]
    fn request_head_keeps_non_utf8_targets() {
        let (parsed, forwarded) = RequestHead::parse(b"GET /a\xffb?q=1 HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let parsed = parsed.unwrap();

        assert_eq!(parsed.target, b"/a\xffb?q=1");
        assert_eq!(parsed.rendered, b"/a%FFb?q=1");
        assert_eq!(parsed.path, b"/a\xffb");
        // Go escapes the non-UTF-8 byte, so hyper can parse the forwarded target.
        assert!(forwarded.starts_with(b"GET /a%FFb?q=1 HTTP/1.1\r\n"));
    }

    #[test]
    fn connection_variables_are_set() {
        let peer: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        for (id, variable, value) in [
            (998211, "REMOTE_ADDR", "127.0.0.1"),
            (998212, "REMOTE_PORT", "54321"),
            (998213, "SERVER_ADDR", "127.0.0.1"),
            (998214, "SERVER_PORT", "8080"),
        ] {
            let mut parser = Parser::new();
            parser
                .from_string(&format!(
                    r#"SecRule {variable} "@streq {value}" "id:{id},phase:1,deny,status:403""#
                ))
                .unwrap();
            let mut tx = parser.into_waf().unwrap().new_transaction();
            set_connection(&mut tx, peer, local);

            assert_eq!(
                tx.process_request_headers().map(|interruption| interruption.status),
                Some(403),
                "{variable} was not set"
            );
        }
    }

    /// Start the server for one connection and return its address.
    async fn serve_with_rules(rules: &str) -> (SocketAddr, TempDir) {
        let mut parser = Parser::new();
        parser.from_string(rules).unwrap();
        let waf = Arc::new(parser.into_waf().unwrap());
        let dir = tempdir().unwrap();
        let logfile = test_logfile(&dir);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            serve_connection(stream, peer, addr, waf, logfile, None).await;
        });
        (addr, dir)
    }

    async fn send_raw(addr: SocketAddr, request: &[u8]) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn escaped_targets_reach_the_waf_as_go_renders_them() {
        // Go's middleware processes `req.URL.String()`, so the unescaped `<`, `>` and `"`
        // never reach the WAF: Go 1.27.3 renders `GET /x<y` as `GET /x%3Cy HTTP/1.1`.
        let rules = r#"SecRule REQUEST_LINE "@rx [<>\"]" "id:998232,phase:1,deny,status:418""#;
        for target in ["/x<y", "/x>y", "/x\"y"] {
            let (addr, _dir) = serve_with_rules(rules).await;
            let request = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            let response = send_raw(addr, request.as_bytes()).await;
            assert!(response.starts_with("HTTP/1.1 200"), "target {target}: {response}");
        }

        let rules = r#"SecRule REQUEST_URI_RAW "@contains /x%3Cy" "id:998233,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET /x<y HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");

        let rules = r#"SecRule REQUEST_LINE "@contains GET /x%3Cy HTTP/1.1" "id:998234,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET /x<y HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn fragment_is_escaped_as_in_go() {
        // Go renders `/a#frag` as `/a%23frag`, so a rule matching the raw fragment cannot fire.
        let rules = r#"SecRule REQUEST_URI_RAW "@rx [#]" "id:998235,phase:1,deny,status:418""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET /a#frag HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");

        let rules = r#"SecRule REQUEST_URI_RAW "@contains /a%23frag" "id:998236,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET /a#frag HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn an_unescaped_query_reaches_the_waf() {
        // Go neither validates nor escapes the raw query, so `%zz` stays as sent.
        let rules = r#"SecRule QUERY_STRING "@streq q=%zz" "id:998237,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET /a?q=%zz HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn absolute_form_request_lines_reach_the_waf() {
        let rules = r#"SecRule REQUEST_LINE "@contains http://localhost" "id:998238,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET http://localhost HTTP/1.1\r\nHost: localhost\r\n\r\n").await;

        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn absolute_and_opaque_targets_reach_the_waf() {
        // Go serves these targets, so the WAF must run: hyper only sees an origin-form
        // target, so its URI parser cannot answer 400 first.
        for target in ["http:///x", "http:/x", "h:1/x", "a:b?c=d"] {
            let rules = format!(
                r#"SecRule REQUEST_LINE "@contains GET {target} HTTP/1.1" "id:998241,phase:1,deny,status:403""#
            );
            let (addr, _dir) = serve_with_rules(&rules).await;
            let request = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            let response = send_raw(addr, request.as_bytes()).await;
            assert!(response.starts_with("HTTP/1.1 403"), "target {target}: {response}");
        }
    }

    #[tokio::test]
    async fn absolute_form_authority_supplies_the_request_host() {
        // Go sets `req.Host` from the URI authority and the middleware adds that, not the
        // `Host` header, so the WAF sees and names the authority.
        let rules = "\
SecRule SERVER_NAME \"@streq authority.example\" \"id:998239,phase:1,deny,status:403\"\n\
SecRule REQUEST_HEADERS:Host \"@streq header.example\" \"id:998240,phase:1,deny,status:418\"\n";
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(
            addr,
            b"GET http://authority.example/x HTTP/1.1\r\nHost: header.example\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn unsupported_protocol_gets_505_without_reaching_the_waf() {
        // The rule would answer 403 if the WAF ran, as Go's server does not for this version.
        let rules = r#"SecRule REQUEST_URI "@rx ." "id:998214,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET / HTTP/4.0\r\nHost: localhost\r\n\r\n").await;

        assert!(response.starts_with("HTTP/1.1 505"), "response: {response}");
    }

    #[tokio::test]
    async fn the_host_less_h2_preface_reaches_the_waf() {
        // Go's exact `isH2Upgrade` exemption keeps the missing `Host` from being a 400, so
        // the handler runs and the WAF sees the raw preface request line.
        let rules = r#"SecRule REQUEST_LINE "@streq PRI * HTTP/2.0" "id:998249,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"PRI * HTTP/2.0\r\n\r\n").await;

        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn normal_requests_still_work() {
        let (addr, _dir) = serve_with_rules("SecRuleEngine On\n").await;
        let response = send_raw(addr, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;

        assert!(response.starts_with("HTTP/1.1 200"), "response: {response}");
    }

    #[tokio::test]
    async fn non_utf8_target_reaches_the_waf() {
        let rules = r#"SecRule REQUEST_FILENAME "@rx ^/a\xffb$" "id:998215,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET /a\xffb?q=1 HTTP/1.1\r\nHost: localhost\r\n\r\n").await;

        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn non_utf8_target_sets_the_query_string() {
        let rules = r#"SecRule QUERY_STRING "@streq q=1" "id:998216,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET /a\xffb?q=1 HTTP/1.1\r\nHost: localhost\r\n\r\n").await;

        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn backslash_target_gets_400_without_reaching_the_waf() {
        // The rule would answer 403 if the WAF ran, as Go's server answers 400 first.
        let rules = r#"SecRule REQUEST_LINE "@rx ." "id:998217,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET \\ HTTP/1.1\r\nHost: localhost\r\n\r\n").await;

        assert!(response.starts_with("HTTP/1.1 400"), "response: {response}");
    }

    #[tokio::test]
    async fn content_length_is_hidden_when_transfer_encoding_is_present() {
        // Go removes Content-Length from the headers its middleware hands over, so CRS
        // 920181 sees no pair; Transfer-Encoding itself stays visible.
        let rules = "\
SecRule &REQUEST_HEADERS:Content-Length \"!@eq 0\" \"id:998218,phase:1,deny,status:418\"\n\
SecRule &REQUEST_HEADERS:Transfer-Encoding \"!@eq 0\" \"id:998219,phase:1,deny,status:403\"\n";
        let (addr, _dir) = serve_with_rules(rules).await;
        let request = b"POST /anything HTTP/1.1\r\nHost: localhost\r\nContent-Length: 7\r\n\
Transfer-Encoding: chunked\r\n\r\n7\r\nfoo=bar\r\n0\r\n\r\n";
        let response = send_raw(addr, request).await;

        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn unsupported_transfer_encoding_gets_501_without_reaching_the_waf() {
        // The rule would answer 403 if the WAF ran; Go answers 501 before its handler.
        let rules = r#"SecRule REQUEST_LINE "@rx ." "id:998244,phase:1,deny,status:403""#;
        for request in [
            b"POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip\r\n\r\n".as_slice(),
            b"POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: identity\r\n\r\n",
            b"POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\
Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ] {
            let (addr, _dir) = serve_with_rules(rules).await;
            let response = send_raw(addr, request).await;
            assert!(response.starts_with("HTTP/1.1 501"), "{request:?}: {response}");
        }
    }

    #[tokio::test]
    async fn an_http_1_0_transfer_encoding_is_ignored_as_in_go() {
        // Go removes Transfer-Encoding from an HTTP/1.0 request instead of answering 501,
        // so the WAF runs and never sees the header.
        let rules = "\
SecRule &REQUEST_HEADERS:Transfer-Encoding \"@ge 1\" \"id:998245,phase:1,deny,status:418\"\n\
SecRule REQUEST_LINE \"@contains POST /x HTTP/1.0\" \"id:998246,phase:1,deny,status:403\"\n";
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(
            addr,
            b"POST /x HTTP/1.0\r\nHost: localhost\r\nTransfer-Encoding: gzip\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.0 403"), "response: {response}");
    }

    #[tokio::test]
    async fn accepted_transfer_encoding_reaches_the_waf_as_go_reshapes_it() {
        // Go re-adds one lowercased `chunked` header per accepted coding, not the raw value.
        let rules = "\
SecRule &REQUEST_HEADERS:Transfer-Encoding \"@eq 1\" \"id:998247,phase:1,deny,status:403\"\n\
SecRule REQUEST_HEADERS:Transfer-Encoding \"@streq chunked\" \"id:998248,phase:1,deny,status:418\"\n";
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(
            addr,
            b"POST /x HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: CHUNKED\r\n\r\n0\r\n\r\n",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn empty_host_reaches_the_missing_host_rule_as_in_go() {
        // Go's middleware only adds a non-empty Host, so CRS 920280 fires, not 920290.
        // The second rule answers 418 only if the empty Host is still visible.
        let rules = "\
SecRule &REQUEST_HEADERS:Host \"@eq 0\" \"id:998220,phase:1,deny,status:403\"\n\
SecRule REQUEST_HEADERS:Host \"@rx ^$\" \"id:998221,phase:1,deny,status:418\"\n";
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET / HTTP/1.1\r\nHost: \r\n\r\n").await;

        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn host_validation_matches_go() {
        // The rule would answer 403 if the WAF ran; Go answers 400 before any handler.
        let rules = r#"SecRule REQUEST_LINE "@rx ." "id:998222,phase:1,deny,status:403""#;
        for request in [
            b"GET / HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: bad\\host\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: bad/host\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
        ] {
            let (addr, _dir) = serve_with_rules(rules).await;
            let response = send_raw(addr, request).await;
            assert!(response.starts_with("HTTP/1.1 400"), "{request:?}: {response}");
        }
    }

    #[tokio::test]
    async fn http_1_2_runs_the_handler_and_a_multi_digit_version_is_a_bad_request() {
        // Go refuses only a non-1 major of a well-formed version, so 1.2 runs the handler.
        let rules = r#"SecRule REQUEST_LINE "@contains HTTP/1.2" "id:998223,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET / HTTP/1.2\r\nHost: localhost\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");

        // `HTTP/12.3` is not `HTTP/<digit>.<digit>`, so Go's parser answers 400.
        let rules = r#"SecRule REQUEST_LINE "@rx ." "id:998224,phase:1,deny,status:418""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET / HTTP/12.3\r\nHost: localhost\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 400"), "response: {response}");
    }

    #[tokio::test]
    async fn lf_only_heads_are_served_as_go_does() {
        let rules = r#"SecRule REQUEST_HEADERS:Host "@streq localhost" "id:998225,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"GET / HTTP/1.1\nHost: localhost\n\n").await;
        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn a_malformed_head_gets_400_instead_of_a_stall() {
        let rules = r#"SecRule REQUEST_LINE "@rx ." "id:998226,phase:1,deny,status:418""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            send_raw(addr, b"GET / HTTP/1.1\nNot A Header\n\n"),
        )
        .await
        .expect("server did not answer a malformed head");

        assert!(response.starts_with("HTTP/1.1 400"), "response: {response}");
    }

    #[tokio::test]
    async fn connect_targets_get_the_same_validation() {
        // Go answers 400 for a CONNECT authority with a byte its host parser rejects.
        let rules = r#"SecRule REQUEST_LINE "@rx ." "id:998227,phase:1,deny,status:418""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"CONNECT \\ HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 400"), "response: {response}");

        // A valid CONNECT target reaches the WAF as Go renders it: `//host:port`.
        let rules = r#"SecRule REQUEST_URI_RAW "@contains //www.example.com:443" "id:998228,phase:1,deny,status:403""#;
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(addr, b"CONNECT www.example.com:443 HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn identical_content_length_headers_are_collapsed() {
        // Go's `fixLength` hands the WAF a single Content-Length; the second rule answers
        // 418 only if the duplicate is still visible.
        let rules = "\
SecRule &REQUEST_HEADERS:Content-Length \"@eq 1\" \"id:998229,phase:1,deny,status:403\"\n\
SecRule &REQUEST_HEADERS:Content-Length \"@eq 2\" \"id:998230,phase:1,deny,status:418\"\n";
        let (addr, _dir) = serve_with_rules(rules).await;
        let response = send_raw(
            addr,
            b"POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nfoo",
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 403"), "response: {response}");
    }

    #[tokio::test]
    async fn body_collection_keeps_only_the_configured_prefix() {
        let body = Full::new(Bytes::from_static(b"oversized body"));
        let collected = collect_body_prefix(body, 5).await.unwrap();

        assert_eq!(collected, b"overs");
    }

    struct ChunkedBody {
        frames: VecDeque<Bytes>,
        poll_count: Arc<AtomicUsize>,
    }

    impl hyper::body::Body for ChunkedBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            self.poll_count.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(self.frames.pop_front().map(|data| Ok(Frame::data(data))))
        }
    }

    #[tokio::test]
    async fn body_collection_drains_frames_after_the_prefix_limit() {
        let poll_count = Arc::new(AtomicUsize::new(0));
        let body = ChunkedBody {
            frames: VecDeque::from([
                Bytes::from_static(b"over"),
                Bytes::from_static(b"sized"),
                Bytes::from_static(b" body"),
            ]),
            poll_count: Arc::clone(&poll_count),
        };

        let collected = collect_body_prefix(body, 5).await.unwrap();

        assert_eq!(collected, b"overs");
        assert_eq!(poll_count.load(Ordering::Relaxed), 4);
    }
}
