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
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use coraza::{config::WafConfig, seclang::Parser, types::RuleEngineStatus, waf::Waf};
use http_body_util::{BodyExt as _, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{HeaderMap, HeaderName, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

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
        let io = TokioIo::new(stream);

        let waf = Arc::clone(&waf);
        let logfile = Arc::clone(&logfile);
        let readiness_token = options.readiness_token.clone();

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
    add_request_headers(&mut tx, req.headers());

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
            Ok(Ok(body)) => run_transaction(&mut tx, &path, &body),
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

/// Copy request header names and original values into the transaction.
fn add_request_headers(tx: &mut coraza::transaction::Transaction, headers: &HeaderMap) {
    // Hyper lowercases names, and a header value need not be ASCII.
    for (name, value) in headers {
        tx.add_request_header(&canonical_header_name(name.as_str()), value.as_bytes());
    }
}

/// Runs the request body and response phases after request headers were processed.
/// The backend answers between them, as CRS's albedo test backend does for `/reflect`.
fn run_transaction(tx: &mut coraza::transaction::Transaction, path: &str, body: &[u8]) -> Response<Full<Bytes>> {
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
        header::HeaderValue,
    };
    use tempfile::{TempDir, tempdir};

    use super::{
        BackendResponse, Logfile, Options, add_request_headers, collect_body_prefix, create_blocking_response,
        has_content_type, load_policy, response, write_inventory,
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
    fn legacy_mode_skips_an_unsupported_directive() {
        let dir = tempdir().unwrap();
        let path = write_rules(&dir, "SecRuleEngine On\nSecBogusDirective value\n");
        let options = Options::parse(&test_args(&["--rules", &path])).unwrap();

        let (_waf, inventory) = load_policy(&options, &test_logfile(&dir)).unwrap();

        assert_eq!(inventory.mode, "legacy");
        assert_eq!(inventory.skipped_directives.len(), 1);
        assert!(inventory.skipped_directives[0].contains("SecBogusDirective"));
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
        assert!(BackendResponse::for_request("/other", b"").body.is_empty());
        assert_eq!(BackendResponse::for_request("/reflect", b"invalid JSON").body, b"OK");
    }

    #[test]
    fn request_header_import_preserves_non_utf8_bytes() {
        let mut parser = Parser::new();
        parser
            .from_string(r#"SecRule REQUEST_HEADERS:X-Trace "@rx \xff" "id:998001,phase:1,deny,status:403""#)
            .unwrap();
        let waf = parser.into_waf().unwrap();
        let mut tx = waf.new_transaction();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("X-Trace", HeaderValue::from_bytes(b"\xff").unwrap());

        add_request_headers(&mut tx, &headers);

        assert_eq!(tx.process_request_headers().unwrap().status, 403);
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
