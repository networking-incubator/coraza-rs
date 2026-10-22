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
//! - Processes HTTP requests through the WAF (async)
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
    io::Write as _,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use coraza::{config::WafConfig, seclang::Parser, types::RuleEngineStatus, waf::Waf};
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{HeaderName, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

/// The log FTW reads: request markers and Go Coraza's error log lines.
type Logfile = Arc<Mutex<std::fs::File>>;

#[expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "The standalone FTW server reports startup and connection status to its console."
)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Coraza FTW test server (async)");

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let port = get_arg(&args, "--port")
        .unwrap_or_else(|| "8080".to_owned())
        .parse::<u16>()?;
    let logfile = get_arg(&args, "--logfile").unwrap_or_else(|| "/tmp/coraza-ftw-audit.log".to_owned());
    let rules_file = get_arg(&args, "--rules");
    let readiness_token = get_arg(&args, "--readiness-token");

    println!("Configuration:");
    println!("   Port: {port}");
    println!("   Logfile: {logfile}");
    if let Some(rules) = &rules_file {
        println!("   Rules: {rules}");
    }
    println!();

    let logfile: Logfile = Arc::new(Mutex::new(OpenOptions::new().create(true).append(true).open(&logfile)?));

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
    // Keep loading past directives this engine doesn't support yet, so a full CRS still loads
    parser.skip_failed_directives();
    log_errors_to(&mut parser, &logfile);

    // Load rules if specified
    if let Some(rules_path) = &rules_file {
        println!("Loading rules from {rules_path}...");
        parser.from_file(rules_path)?;
        for e in parser.skipped() {
            eprintln!("Warning: skipped {e}");
        }
    } else {
        println!("No rules file specified, WAF running without rules");
    }

    let waf = parser.into_waf()?;
    if rules_file.is_some() {
        println!("Loaded {} rules", waf.rule_count());
    }

    // Create shared state
    let waf = Arc::new(waf);

    // Bind to address
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;

    println!("Server listening on http://{local_addr}");

    // Accept connections
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);

        let waf = Arc::clone(&waf);
        let logfile = Arc::clone(&logfile);
        let readiness_token = readiness_token.clone();

        // Spawn a task to handle the connection
        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                handle_request(
                    req,
                    Arc::clone(&waf),
                    Arc::clone(&logfile),
                    readiness_token.clone(),
                    peer_addr,
                    local_addr,
                )
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Error serving connection: {err:?}");
            }
        });
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
    waf: Arc<Waf>,
    logfile: Logfile,
    readiness_token: Option<String>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().as_str().to_owned();

    // CONNECT requests use authority (host:port) instead of path
    let full_uri = if req.method() == Method::CONNECT {
        req.uri()
            .authority()
            .map_or_else(|| req.uri().path().to_owned(), ToString::to_string)
    } else {
        match req.uri().query() {
            Some(query) => format!("{}?{query}", req.uri().path()),
            None => req.uri().path().to_owned(),
        }
    };
    let path = req.uri().path().to_owned();
    let protocol = format!("{:?}", req.version());

    println!("{method} {full_uri} {protocol}");

    if let Some(token) = readiness_token
        && req.method() == Method::GET
        && path.strip_prefix("/.well-known/coraza-ftw-health/") == Some(token.as_str())
    {
        return Ok(response(200, &[], token.into_bytes()));
    }

    let marker_header = req
        .headers()
        .get("X-CRS-Test")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // Before the request's own error log lines, which FTW looks for after it
    if let Some(marker) = &marker_header {
        write_marker(&logfile, marker);
    }

    let mut tx = waf.new_transaction();
    tx.process_uri(&full_uri, &method, &protocol);
    tx.set_remote_addr(peer_addr.ip().to_string());
    tx.set_remote_port(peer_addr.port());
    tx.set_server_addr(local_addr.ip().to_string());
    tx.set_server_port(local_addr.port());
    if let Some(host) = req.headers().get("host").and_then(|value| value.to_str().ok()) {
        tx.set_server_name(host);
    }
    // As Go's net/http hands them to Go Coraza: hyper lowercases names, and a value
    // needn't be ASCII
    for (name, value) in req.headers() {
        let value = String::from_utf8_lossy(value.as_bytes());
        tx.add_request_header(&canonical_header_name(name.as_str()), value.as_bytes());
    }

    let body = match req.collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(e) => {
            eprintln!("Error reading body: {e}");
            return Ok(create_error_response(500, "Internal Server Error"));
        },
    };

    let response = run_transaction(&mut tx, &path, &body);

    // As Go Coraza's HTTP middleware does, whether or not the transaction was interrupted
    if let Err(e) = tx.process_logging() {
        eprintln!("failed to write the audit log: {e}");
    }

    Ok(response)
}

/// Runs the request and response phases of `tx`, the backend answering in between (as
/// CRS's albedo test backend does for `/reflect`); returns the backend's response, or
/// the interruption's.
fn run_transaction(tx: &mut coraza::transaction::Transaction, path: &str, body: &[u8]) -> Response<Full<Bytes>> {
    if let Some(interruption) = tx.process_request_headers() {
        return create_blocking_response(&interruption);
    }

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
    fn for_request(path: &str, body: &[u8]) -> Self {
        let ok = Self {
            status: 200,
            headers: Vec::new(),
            body: b"OK".to_vec(),
        };
        if path != "/reflect" {
            return ok;
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
        let mut file = logfile.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
    let mut file = logfile.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
    response(interruption.status, &[], b"Blocked by WAF".to_vec())
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
#[expect(clippy::unwrap_used, reason = "FTW response tests assert fixed headers")]
mod tests {
    use super::{has_content_type, response};

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
}
