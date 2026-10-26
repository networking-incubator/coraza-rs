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

//! SecLang parser implementation.
//!
//! This module implements the core parser for ModSecurity SecLang directives, one at a
//! time:
//!
//! 1. Read the directive's lines, with continuation (`\`) support
//! 2. Skip comments (`#`) and blank lines
//! 3. Handle multi-line backtick blocks
//! 4. Extract directive name and options
//! 5. Dispatch to directive handler

#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "The private directive table and handlers are documented inline and implement Parser."
    )
)]
#![expect(
    clippy::unnecessary_wraps,
    reason = "Directive handlers share one fallible signature for parser dispatch."
)]

use std::{
    borrow::Cow,
    ops::RangeInclusive,
    path::Path,
    str::FromStr as _,
    sync::atomic::{AtomicU64, Ordering},
};

use winnow::{
    ModalResult, Parser as _,
    combinator::{alt, cut_err, eof, not, repeat_till, terminated},
    error::{EmptyError, ErrMode},
    token::{rest, take_until},
};

use crate::{
    audit_log::{ErrorLog, MatchedRule},
    config::{UploadKeepFiles, WafConfig},
    operators::{CustomOperatorFactory, CustomOperators, Datasets, OperatorContext},
    rules::{Rule, RuleGroup},
    seclang::{
        CompileError, parse_actions,
        rule_compiler::{
            DefaultActions, apply_actions, compile_sec_action_in, compile_sec_marker, compile_sec_rule_in,
        },
        variable_parser::VariableList,
    },
    types::{
        AuditEngineStatus, AuditLogFormat, AuditLogType, BodyLimitAction, RuleEngineStatus, parse_audit_log_parts,
    },
    waf::{ConfigError, Waf},
};

/// Maximum include recursion depth to prevent `DoS` attacks.
const MAX_INCLUDE_RECURSION: usize = 100;
/// Unique suffix for temporary upload directory probes.
static UPLOAD_PROBE_ID: AtomicU64 = AtomicU64::new(0);

/// Error returned when a `SecLang` directive cannot be parsed or compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Human-readable description of the parse failure.
    pub message: String,
    /// Line where the directive ended, starting from 1.
    pub line: usize,
    /// File being parsed, or `_inline_` for [`Parser::from_string`].
    pub file: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

impl ParseError {
    fn new(message: String, line: usize, file: String) -> Self {
        Self { message, line, file }
    }
}

type ParseResult<T> = Result<T, ParseError>;

/// Directive handler: applies the directive, or returns why it can't; the parser adds
/// the location to the message.
type DirectiveFn = fn(&mut DirectiveOptions<'_>) -> Result<(), String>;

/// A known directive, by whether it takes an argument.
#[derive(Clone, Copy)]
enum Directive {
    /// Needs a non-empty argument
    WithArgument(DirectiveFn),
    /// Takes no argument
    WithoutArgument(DirectiveFn),
    /// Accepted with any argument and ignored, as Go Coraza does, so that configurations
    /// written for it load
    Ignored,
}

/// What a directive handler works on: its (non-empty) argument and the parser's output.
struct DirectiveOptions<'a> {
    /// Directive options/arguments (everything after directive name)
    opts: String,

    /// Directory of the file holding the directive (empty for a string), which relative
    /// paths in it are relative to
    config_dir: &'a Path,

    /// File holding the directive (`_inline_` for a string)
    file: &'a str,

    /// Line of `file` the directive ends on
    line: usize,

    /// The directive as written, continuation lines joined
    raw: &'a str,

    /// Mutable reference to WAF configuration
    waf_config: &'a mut WafConfig,

    /// Rules compiled so far, in file order
    rules: &'a mut RuleGroup,

    /// Defaults that rules compiled from now on merge their actions with
    default_actions: &'a mut DefaultActions,

    /// Datasets defined so far
    datasets: &'a mut Datasets,

    /// Operator factories registered on the parser
    custom_operators: &'a CustomOperators,

    /// Whether a directive that fails from now on is skipped rather than returned; see
    /// [`Parser::skip_failed_directives`]
    skip_failed: &'a mut bool,
}

/// `SecLang` parser state
#[derive(Debug, Clone, Default)]
struct ParserState {
    /// Current line number
    current_line: usize,

    /// Current file being parsed
    current_file: String,

    /// Current directory (for resolving relative includes)
    current_dir: String,
}

/// `SecLang` parser.
///
/// Parses ModSecurity `SecLang` directives into a WAF configuration and compiled rules.
///
/// # Example
///
/// ```
/// use coraza::seclang::Parser;
///
/// let mut parser = Parser::new();
/// parser.from_string(
///     r#"
///     SecRuleEngine On
///     SecRule ARGS "@contains attack" "id:1,phase:1,deny,status:403"
/// "#,
/// )?;
///
/// assert_eq!(parser.rule_count(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Parser {
    /// Current parser state
    state: ParserState,

    /// Include recursion counter (prevents `DoS`)
    include_count: usize,

    /// WAF configuration (populated by directives)
    waf_config: WafConfig,

    /// Rules compiled from `SecRule`, `SecAction` and `SecMarker`, in file order
    rules: RuleGroup,

    /// Defaults set by `SecDefaultAction` so far
    default_actions: DefaultActions,

    /// Datasets defined by `SecDataset` so far
    datasets: Datasets,

    /// Operator factories registered by the embedder, consulted before built-ins
    custom_operators: CustomOperators,

    /// Whether a failing directive is recorded in `skipped` instead of returned
    skip_failed: bool,

    /// Whether later rule directives belong to a chain whose earlier member failed
    dropping_chain: bool,

    /// Directives skipped because they failed, in parse order
    skipped: Vec<ParseError>,

    /// Optional callback for rules with the `log` action.
    error_log: Option<ErrorLog>,
}

impl Parser {
    /// Create a new parser.
    pub fn new() -> Self {
        Self {
            state: ParserState::default(),
            include_count: 0,
            waf_config: WafConfig::new(),
            rules: RuleGroup::new(),
            default_actions: DefaultActions::default(),
            datasets: Datasets::new(),
            custom_operators: CustomOperators::new(),
            skip_failed: false,
            dropping_chain: false,
            skipped: Vec::new(),
            error_log: None,
        }
    }

    /// Get reference to the parsed WAF configuration.
    pub fn config(&self) -> &WafConfig {
        &self.waf_config
    }

    /// Get mutable reference to the parsed WAF configuration.
    pub fn config_mut(&mut self) -> &mut WafConfig {
        &mut self.waf_config
    }

    /// Register an operator factory under `name`, matched case-insensitively.
    ///
    /// A registered name is looked up before the built-in operators when a `SecRule`
    /// operator is compiled, so an embedder can add or override an operator. It applies
    /// only to rules compiled after the call: rules already compiled keep the operator
    /// they resolved.
    pub fn register_operator(&mut self, name: &str, factory: CustomOperatorFactory) {
        self.custom_operators.insert(name.to_owned(), factory);
    }

    /// Number of rules compiled so far.
    pub fn rule_count(&self) -> usize {
        self.rules.count()
    }

    /// Consume the parser and build a WAF without activating its audit resources.
    ///
    /// Files are not created and sockets are not connected: the audit writer is opened
    /// by [`Waf::activate`] or by the first [`Waf::new_transaction`]. This is the entry
    /// point for validating a candidate policy before deciding to use it.
    ///
    /// # Errors
    ///
    /// Returns an error when the parsed configuration is invalid for WAF construction.
    pub fn compile(self) -> Result<Waf, ConfigError> {
        Waf::with_rules(self.waf_config, self.rules, self.error_log)
    }

    /// Consume the parser and build a WAF from its configuration and compiled rules.
    ///
    /// Alias for [`Parser::compile`]: the audit writer opens on the first transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the parsed configuration is invalid for WAF construction.
    pub fn into_waf(self) -> Result<Waf, ConfigError> {
        self.compile()
    }

    /// Set a callback that receives each rule with the `log` action when it matches.
    pub fn on_error_log(&mut self, log: impl Fn(&MatchedRule) + Send + Sync + 'static) {
        self.error_log = Some(ErrorLog::new(log));
    }

    /// Makes later parsing skip directives that fail, instead of stopping at the first one.
    ///
    /// Use this to load a rule set the engine only partly supports. Each skipped
    /// directive's error is kept, in order, and returned by [`Parser::skipped`].
    /// A chain with a skipped link is dropped whole.
    pub fn skip_failed_directives(&mut self) {
        self.skip_failed = true;
    }

    /// Errors of the directives skipped so far; empty unless
    /// [`Parser::skip_failed_directives`] was called.
    pub fn skipped(&self) -> &[ParseError] {
        &self.skipped
    }

    /// Parse directives from a string.
    ///
    /// # Arguments
    ///
    /// * `data` - `SecLang` directive text
    ///
    /// # Returns
    ///
    /// Ok(()) if all directives parsed successfully, Err otherwise
    ///
    /// # Errors
    ///
    /// Returns an error with the directive location if parsing or compilation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use coraza::seclang::Parser;
    ///
    /// let mut parser = Parser::new();
    /// parser.from_string("SecRuleEngine On")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[expect(clippy::wrong_self_convention, reason = "Preserves the upstream Parser API name.")]
    pub fn from_string(&mut self, data: &str) -> ParseResult<()> {
        let old_file = std::mem::replace(&mut self.state.current_file, "_inline_".to_owned());
        let old_line = std::mem::take(&mut self.state.current_line);
        let result = self.parse_string(data);
        self.state.current_file = old_file;
        self.state.current_line = old_line;
        result
    }

    /// Parse directives from a file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to `SecLang` configuration file or glob pattern
    ///
    /// # Returns
    ///
    /// Ok(()) if file parsed successfully, Err otherwise
    ///
    /// # Errors
    ///
    /// Returns an error with the file and directive location if reading, parsing, or
    /// compilation fails.
    ///
    /// # Features
    ///
    /// - Supports glob patterns like `/path/to/rules/*.conf`
    /// - Handles relative paths (resolved from current directory)
    /// - Handles absolute paths
    /// - Tracks current directory for nested includes
    ///
    /// # Example
    ///
    /// ```no_run
    /// use coraza::seclang::Parser;
    ///
    /// let mut parser = Parser::new();
    /// parser.from_file("/etc/coraza/rules.conf")?;
    /// parser.from_file("./local_rules/*.conf")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[expect(clippy::wrong_self_convention, reason = "Preserves the upstream Parser API name.")]
    pub fn from_file<P: AsRef<Path>>(&mut self, path: P) -> ParseResult<()> {
        let state = self.state.clone();
        let result = self.parse_file(path.as_ref());
        self.state = state;
        result
    }

    fn parse_file(&mut self, path: &Path) -> ParseResult<()> {
        let base_dir = self.state.current_dir.clone();
        let pattern_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            Path::new(&base_dir).join(path)
        };
        let pattern = pattern_path.to_string_lossy();
        let files = if pattern.contains('*') {
            let paths = glob::glob(&pattern)
                .map_err(|error| self.error(format!("failed to glob pattern '{pattern}': {error}")))?;
            let mut files = Vec::new();
            for path in paths {
                files.push(
                    path.map_err(|error| self.error(format!("failed to expand glob pattern '{pattern}': {error}")))?,
                );
            }
            if files.is_empty() {
                return Err(self.error(format!("glob pattern '{pattern}' matched no files")));
            }
            files
        } else {
            vec![pattern_path]
        };

        for file in files {
            let resolved_path = file.to_string_lossy().into_owned();
            let resolved = file;
            self.state.current_file.clone_from(&resolved_path);
            self.state.current_dir = resolved
                .parent()
                .map_or_else(|| ".".to_owned(), |parent| parent.to_string_lossy().into_owned());

            let content = std::fs::read_to_string(&resolved)
                .map_err(|error| self.error(format!("failed to read file '{resolved_path}': {error}")))?;
            let line = std::mem::take(&mut self.state.current_line);
            let result = self.parse_string(&content);
            self.state.current_line = line;
            self.state.current_dir.clone_from(&base_dir);
            result?;
        }
        Ok(())
    }

    /// Internal string parsing implementation
    ///
    /// Handles:
    /// - Line continuations (`\` at end of line)
    /// - Comments (`#` at start of line)
    /// - Multi-line backtick blocks (for `SecDataset`)
    /// - Directive dispatch
    fn parse_string(&mut self, data: &str) -> ParseResult<()> {
        let mut input = data;
        loop {
            let start = input;
            let directive = written_directive.parse_next(&mut input);
            // Count the consumed source, including lines inside a backtick block.
            let read = start.strip_suffix(input).unwrap_or_default();
            self.state.current_line += read.lines().count();
            let directive = match directive {
                Ok(directive) => directive,
                // Only blank lines and comments are left, or a directive continued past
                // the last line, which is dropped
                Err(ErrMode::Backtrack(_)) => return Ok(()),
                Err(_) => return Err(self.error("backticks left open".to_owned())),
            };

            if self.dropping_chain
                && let Some(has_chain) = super::rule_compiler::directive_chain_status(&directive)
            {
                self.skipped
                    .push(self.error("skipped because parsing failed while a rule chain was open".to_owned()));
                self.dropping_chain = has_chain;
                continue;
            }

            match self.evaluate_line(&directive) {
                Err(e) if self.skip_failed => {
                    let chain_status = super::rule_compiler::directive_chain_status(&directive);
                    let discarded_chain = self.rules.discard_open_chain();
                    if let Some(has_chain) = chain_status {
                        self.dropping_chain = has_chain;
                    } else if discarded_chain {
                        self.dropping_chain = true;
                    }
                    self.skipped.push(e);
                },
                result => result?,
            }
        }
    }

    /// Evaluate a single complete directive line
    ///
    /// Extracts directive name and options, then dispatches to handler.
    fn evaluate_line(&mut self, line: &str) -> ParseResult<()> {
        if line.is_empty() || line.starts_with('#') {
            return Err(self.error("empty directive".to_owned()));
        }

        // Extract directive name and options
        // Format: "DirectiveName options..."
        let (directive_name, mut opts) = match line.split_once(' ') {
            Some((name, rest)) => (name, rest.to_owned()),
            None => (line, String::new()),
        };

        // Convert directive name to lowercase (case-insensitive)
        let directive_lower = directive_name.to_lowercase();

        // Remove surrounding quotes if present
        if opts.len() >= 2 && opts.starts_with('"') && opts.ends_with('"') {
            opts.remove(0);
            opts.truncate(opts.len() - 1);
        }

        // Special case: Include directive (handled separately due to recursion)
        if directive_lower == "include" {
            if self.include_count >= MAX_INCLUDE_RECURSION {
                return Err(self.error(format!("cannot include more than {MAX_INCLUDE_RECURSION} files")));
            }
            self.include_count += 1;
            let result = self.from_file(&opts);
            self.include_count -= 1;
            return result;
        }

        let Some(directive) = directive_handler(&directive_lower) else {
            return Err(self.error(format!("unknown directive \"{directive_name}\"")));
        };

        let result = match directive {
            Directive::WithArgument(_) if opts.is_empty() => Err("requires an argument".to_owned()),
            Directive::WithoutArgument(_) if !opts.is_empty() => Err("takes no argument".to_owned()),
            Directive::Ignored => Ok(()),
            Directive::WithArgument(handler) | Directive::WithoutArgument(handler) => handler(&mut DirectiveOptions {
                opts,
                config_dir: Path::new(&self.state.current_dir),
                file: &self.state.current_file,
                line: self.state.current_line,
                raw: line,
                waf_config: &mut self.waf_config,
                rules: &mut self.rules,
                default_actions: &mut self.default_actions,
                datasets: &mut self.datasets,
                custom_operators: &self.custom_operators,
                skip_failed: &mut self.skip_failed,
            }),
        };
        result.map_err(|message| self.error(format!("failed to compile directive \"{directive_name}\": {message}")))
    }

    /// An error at the current position.
    fn error(&self, message: String) -> ParseError {
        ParseError::new(message, self.state.current_line, self.state.current_file.clone())
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

/// The next directive, as written: its lines up to one not ending with `\`, joined
/// without their trailing backslashes, blank lines and comments left out.
///
/// A line ending with a backtick opens a block, which the next line starting with one
/// closes: the lines of the block are kept with their newline, `\` included.
///
/// Fails as a backtrack at the end of the input, and as a cut if a block is left open.
fn written_directive<'i>(input: &mut &'i str) -> ModalResult<Cow<'i, str>, EmptyError> {
    // Borrowed while it is a single line
    let mut written = Cow::Borrowed("");
    loop {
        let mut line = content_line(input)?;
        if line.ends_with('`') {
            let (inside, closing) = backtick_block(input)?;
            for line in [line].into_iter().chain(inside) {
                written += line;
                written += "\n";
            }
            line = closing;
        }
        written += line.trim_end_matches('\\');
        if !line.ends_with('\\') {
            return Ok(written);
        }
    }
}

/// What follows the line opening a backtick block: the lines inside it, then the one
/// closing it, which starts with a backtick.
fn backtick_block<'i>(input: &mut &'i str) -> ModalResult<(Vec<&'i str>, &'i str), EmptyError> {
    let closing = content_line.verify(|line: &str| line.starts_with('`'));
    cut_err(repeat_till(0.., content_line, closing)).parse_next(input)
}

/// The next line, trimmed, that is neither blank nor a comment.
fn content_line<'i>(input: &mut &'i str) -> ModalResult<&'i str, EmptyError> {
    loop {
        let line = line(input)?;
        if !(line.is_empty() || line.starts_with('#')) {
            return Ok(line);
        }
    }
}

/// The next line, trimmed.
fn line<'i>(input: &mut &'i str) -> ModalResult<&'i str, EmptyError> {
    not(eof).parse_next(input)?;
    alt((terminated(take_until(0.., '\n'), '\n'), rest))
        .map(str::trim)
        .parse_next(input)
}

/// Handler of the directive with the given lowercase name; `None` if unknown.
///
/// `Include` is handled by the parser itself.
fn directive_handler(name: &str) -> Option<Directive> {
    use Directive::{Ignored, WithArgument, WithoutArgument};
    let directive = match name {
        "secrule" => WithArgument(directive_sec_rule),
        "secaction" => WithArgument(directive_sec_action),
        "secmarker" => WithArgument(directive_sec_marker),
        "secdefaultaction" => WithArgument(directive_sec_default_action),
        "secdataset" => WithArgument(directive_sec_dataset),
        "secruleremovebyid" => WithArgument(directive_sec_rule_remove_by_id),
        "secruleremovebymsg" => WithArgument(directive_sec_rule_remove_by_msg),
        "secruleremovebytag" => WithArgument(directive_sec_rule_remove_by_tag),
        "secruleupdateactionbyid" => WithArgument(directive_sec_rule_update_action_by_id),
        "secruleupdatetargetbyid" => WithArgument(directive_sec_rule_update_target_by_id),
        "secruleupdatetargetbytag" => WithArgument(directive_sec_rule_update_target_by_tag),
        "secruleengine" => WithArgument(directive_sec_rule_engine),
        "secrequestbodyaccess" => WithArgument(directive_sec_request_body_access),
        "secresponsebodyaccess" => WithArgument(directive_sec_response_body_access),
        "secrequestbodylimit" => WithArgument(directive_sec_request_body_limit),
        "secrequestbodylimitaction" => WithArgument(directive_sec_request_body_limit_action),
        "secdebugloglevel" => WithArgument(directive_sec_debug_log_level),
        "secwebappid" => WithArgument(directive_sec_web_app_id),
        "seccomponentsignature" => WithArgument(directive_sec_component_signature),
        "secserversignature" => WithArgument(directive_sec_server_signature),
        "secsensorid" => WithArgument(directive_sec_sensor_id),
        "secresponsebodylimit" => WithArgument(directive_sec_response_body_limit),
        "secresponsebodylimitaction" => WithArgument(directive_sec_response_body_limit_action),
        "secrequestbodyinmemorylimit" => WithArgument(directive_sec_request_body_in_memory_limit),
        "secrequestbodynofileslimit" => WithArgument(directive_sec_request_body_no_files_limit),
        "secargumentslimit" => WithArgument(directive_sec_arguments_limit),
        "secuploaddir" => WithArgument(directive_sec_upload_dir),
        "secuploadfilelimit" => WithArgument(directive_sec_upload_file_limit),
        "secuploadfilemode" => WithArgument(directive_sec_upload_file_mode),
        "secuploadkeepfiles" => WithArgument(directive_sec_upload_keep_files),
        "secauditengine" => WithArgument(directive_sec_audit_engine),
        "secauditlog" => WithArgument(directive_sec_audit_log),
        "secauditlogformat" => WithArgument(directive_sec_audit_log_format),
        "secauditlogparts" => WithArgument(directive_sec_audit_log_parts),
        "secauditlogtype" => WithArgument(directive_sec_audit_log_type),
        "secauditlogrelevantstatus" => WithArgument(directive_sec_audit_log_relevant_status),
        "secrxprefilter" => WithArgument(directive_sec_rx_pre_filter),
        "secrequestbodyjsondepthlimit" => WithArgument(directive_sec_request_body_json_depth_limit),
        "secresponsebodyjsondepthlimit" => WithArgument(directive_sec_response_body_json_depth_limit),
        "secresponsebodymimetype" => WithArgument(directive_sec_response_body_mime_type),
        "secdatadir" => WithArgument(directive_sec_data_dir),
        "seccollectiontimeout" => WithArgument(directive_sec_collection_timeout),
        "secdebuglog" => WithArgument(directive_sec_debug_log),
        "secauditlogdirmode" => WithArgument(directive_sec_audit_log_dir_mode),
        "secauditlogfilemode" => WithArgument(directive_sec_audit_log_file_mode),
        "secauditlogstoragedir" => WithArgument(directive_sec_audit_log_storage_dir),
        "secignorerulecompilationerrors" => WithArgument(directive_sec_ignore_rule_compilation_errors),
        "secremoterulesfailaction" => WithArgument(directive_sec_remote_rules_fail_action),
        "secresponsebodymimetypesclear" => WithoutArgument(directive_sec_response_body_mime_types_clear),
        "secremoterules" => WithArgument(directive_sec_remote_rules),
        "secargumentseparator"
        | "secconnengine"
        | "secconnreadstatelimit"
        | "secconnwritestatelimit"
        | "seccookieformat"
        | "secgsblookupdb"
        | "sechashengine"
        | "sechashkey"
        | "sechashmethodpm"
        | "sechashmethodrx"
        | "sechashparam"
        | "sechttpblkey"
        | "secpcrematchlimit"
        | "secpcrematchlimitrecursion"
        | "secruleperftime"
        | "secrulescript"
        | "secruleupdatetargetbymsg"
        | "sectmpdir"
        | "secunicodemap" => Ignored,
        _ => return None,
    };
    Some(directive)
}

// ============================================================================
// Directive Implementations
// ============================================================================

/// Helper function to parse boolean values (On/Off)
fn parse_boolean(value: &str) -> Result<bool, String> {
    match value.to_lowercase().as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(format!("expected On or Off, got: {value}")),
    }
}

/// Adds a compiled rule, noting where it was written; fails on compile errors and
/// duplicate ids.
fn add_rule(options: &mut DirectiveOptions<'_>, rule: Result<Rule, CompileError>) -> Result<(), String> {
    let mut rule = rule.map_err(|e| e.message)?;
    let metadata = rule.metadata_mut();
    options.file.clone_into(&mut metadata.file);
    metadata.line = options.line;
    options.raw.clone_into(&mut metadata.raw);
    options.rules.add(rule)
}

/// `SecRule` VARIABLES "OPERATOR" "ACTIONS"
fn directive_sec_rule(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let context = OperatorContext {
        base_dir: options.config_dir,
        datasets: options.datasets,
        custom: (!options.custom_operators.is_empty()).then_some(options.custom_operators),
    };
    let case_sensitive_args_keys = options.waf_config.case_sensitive_args_keys;
    options
        .rules
        .record_case_sensitive_args_keys(case_sensitive_args_keys)?;
    let rule = compile_sec_rule_in(
        &options.opts,
        &context,
        options.default_actions,
        case_sensitive_args_keys,
    );
    add_rule(options, rule)
}

/// `SecAction` "ACTIONS"
fn directive_sec_action(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let rule = compile_sec_action_in(&options.opts, options.default_actions);
    add_rule(options, rule)
}

/// `SecDefaultAction` "ACTIONS"
///
/// Sets the actions that rules of the phase named in ACTIONS, from here on, merge their
/// own with; `block` takes the disruptive one.
fn directive_sec_default_action(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.default_actions.add(&options.opts).map_err(|e| e.message)
}

/// `SecMarker` LABEL
fn directive_sec_marker(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let rule = compile_sec_marker(&options.opts);
    add_rule(options, rule)
}

/// Splits `ARGUMENTS LAST` at its last argument, which may be double-quoted and then
/// hold spaces. Quotes around either part are removed.
fn split_last_argument(opts: &str) -> Option<(&str, &str)> {
    let opts = opts.trim();
    let (rest, last) = match opts.strip_suffix('"') {
        Some(quoted) => quoted.rsplit_once('"')?,
        None => opts.rsplit_once(char::is_whitespace)?,
    };
    let rest = rest.trim().trim_matches('"');
    let last = last.trim_matches('"');
    (!rest.is_empty() && !last.is_empty()).then_some((rest, last))
}

/// Parses a rule id (`942100`) or an inclusive range of them (`942100-942199`).
fn parse_id_range(spec: &str) -> Result<RangeInclusive<i32>, String> {
    let parse = |id: &str| {
        id.parse::<i32>()
            .map_err(|_error| format!("invalid rule id or range: {spec}"))
    };
    let range = match spec.split_once('-') {
        Some((start, end)) => parse(start)?..=parse(end)?,
        None => parse(spec).map(|id| id..=id)?,
    };
    if range.is_empty() {
        return Err(format!("invalid rule id range: {spec}"));
    }
    Ok(range)
}

/// `SecRuleRemoveById` ID|RANGE...
///
/// Removes the rules defined so far with the given ids or in the inclusive ranges.
fn directive_sec_rule_remove_by_id(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    for spec in options.opts.split_whitespace() {
        let range = parse_id_range(spec)?;
        options.rules.delete_by_range(*range.start(), *range.end());
    }
    Ok(())
}

/// `SecRuleRemoveByMsg` MSG
///
/// Removes the rules defined so far whose `msg` is MSG, as written.
fn directive_sec_rule_remove_by_msg(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.rules.delete_by_msg(&options.opts);
    Ok(())
}

/// `SecRuleRemoveByTag` TAG
///
/// Removes the rules defined so far tagged TAG.
fn directive_sec_rule_remove_by_tag(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.rules.delete_by_tag(&options.opts);
    Ok(())
}

/// `SecRuleUpdateActionById` ID|RANGE... "ACTIONS"
///
/// Applies ACTIONS to the rules with the given ids or in the given inclusive ranges, as
/// if appended to each rule's own, without the defaults of `SecDefaultAction`: a
/// disruptive action replaces the rule's. A single id must name a rule defined earlier.
fn directive_sec_rule_update_action_by_id(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let (ids, actions) =
        split_last_argument(&options.opts).ok_or("syntax error: SecRuleUpdateActionById ID \"ACTIONS\"")?;
    let actions = parse_actions(actions).map_err(|e| e.message)?;

    for spec in ids.split_whitespace() {
        let range = parse_id_range(spec)?;
        let mut found = false;
        for rule in options
            .rules
            .iter_mut()
            .filter(|rule| range.contains(&rule.metadata().id))
        {
            apply_actions(rule, &actions).map_err(|e| e.message)?;
            found = true;
        }
        if !found && range.start() == range.end() {
            return Err(format!("rule {} not found", range.start()));
        }
    }
    Ok(())
}

/// `SecRuleUpdateTargetById` ID|RANGE... "VARIABLES"
///
/// Adds VARIABLES to the rules with the given ids or in the given inclusive ranges, as
/// if appended to each rule's own: `!ARGS:id` excludes a key. A single id must name a
/// rule defined earlier.
fn directive_sec_rule_update_target_by_id(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let (ids, variables) =
        split_last_argument(&options.opts).ok_or("syntax error: SecRuleUpdateTargetById ID \"VARIABLES\"")?;
    let case_sensitive_args_keys = options.waf_config.case_sensitive_args_keys;
    options
        .rules
        .record_case_sensitive_args_keys(case_sensitive_args_keys)?;
    let variables = VariableList::parse(variables, case_sensitive_args_keys).map_err(|e| e.message)?;

    for spec in ids.split_whitespace() {
        let range = parse_id_range(spec)?;
        let mut found = false;
        for rule in options
            .rules
            .iter_mut()
            .filter(|rule| range.contains(&rule.metadata().id))
        {
            variables.apply_to(rule.variables_mut());
            found = true;
        }
        if !found && range.start() == range.end() {
            return Err(format!("rule {} not found", range.start()));
        }
    }
    Ok(())
}

/// `SecRuleUpdateTargetByTag` TAG "VARIABLES"
///
/// Adds VARIABLES to every rule tagged TAG, as [`directive_sec_rule_update_target_by_id`]
/// does.
fn directive_sec_rule_update_target_by_tag(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let (tag, variables) =
        split_last_argument(&options.opts).ok_or("syntax error: SecRuleUpdateTargetByTag TAG \"VARIABLES\"")?;
    let case_sensitive_args_keys = options.waf_config.case_sensitive_args_keys;
    options
        .rules
        .record_case_sensitive_args_keys(case_sensitive_args_keys)?;
    let variables = VariableList::parse(variables, case_sensitive_args_keys).map_err(|e| e.message)?;

    options
        .rules
        .update_by_tag(tag, |rule| variables.apply_to(rule.variables_mut()));
    Ok(())
}

/// `SecDataset` NAME `ITEMS`
///
/// Defines (or replaces) dataset NAME: one item per line of ITEMS, between backticks
/// and over several lines; blank lines and `#` comments are skipped.
fn directive_sec_dataset(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let (name, items) = options
        .opts
        .split_once(char::is_whitespace)
        .ok_or("syntax error: SecDataset NAME `ITEMS`")?;
    let items = items
        .trim()
        .trim_matches('`')
        .lines()
        .map(str::trim)
        .filter(|item| !item.is_empty() && !item.starts_with('#'))
        .map(str::to_owned)
        .collect();
    options.datasets.insert(name.to_owned(), items);
    Ok(())
}

/// `SecRuleEngine` On|Off|DetectionOnly
///
/// Configures the rules engine.
fn directive_sec_rule_engine(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let status = RuleEngineStatus::from_str(&options.opts).map_err(|e| e.to_string())?;

    options.waf_config.rule_engine = status;
    Ok(())
}

/// `SecRequestBodyAccess` On|Off
///
/// Configures whether request bodies will be buffered and processed.
fn directive_sec_request_body_access(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let value = parse_boolean(&options.opts.to_lowercase())?;

    options.waf_config.request_body_access = value;
    Ok(())
}

/// `SecResponseBodyAccess` On|Off
///
/// Configures whether response bodies will be buffered and processed.
fn directive_sec_response_body_access(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let value = parse_boolean(&options.opts.to_lowercase())?;

    options.waf_config.response_body_access = value;
    Ok(())
}

/// `SecRequestBodyLimit` `LIMIT_IN_BYTES`
///
/// Configures the maximum request body size.
fn directive_sec_request_body_limit(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let limit = options
        .opts
        .parse::<i64>()
        .map_err(|e| format!("invalid limit value: {e}"))?;

    options.waf_config.request_body_limit = limit;
    Ok(())
}

/// `SecRequestBodyLimitAction` Reject|ProcessPartial
///
/// Controls what happens when request body limit is reached.
fn directive_sec_request_body_limit_action(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let action = match options.opts.to_lowercase().as_str() {
        "reject" => BodyLimitAction::Reject,
        "processpartial" => BodyLimitAction::ProcessPartial,
        _ => {
            return Err(format!(
                "invalid SecRequestBodyLimitAction value: {} (expected Reject or ProcessPartial)",
                options.opts
            ));
        },
    };

    options.waf_config.request_body_limit_action = action;
    Ok(())
}

/// `SecDebugLogLevel` [0-9]
///
/// Configures the verboseness of the debug log.
fn directive_sec_debug_log_level(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let level = options
        .opts
        .parse::<u8>()
        .map_err(|e| format!("invalid debug log level: {e}"))?;

    if level > 9 {
        return Err(format!("debug log level must be 0-9, got {level}"));
    }

    options.waf_config.debug_log_level = level;
    Ok(())
}

/// `SecWebAppId` [ID]
///
/// Configures the web application ID.
fn directive_sec_web_app_id(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.web_app_id.clone_from(&options.opts);
    Ok(())
}

/// `SecComponentSignature` `COMPONENT_NAME/X.Y.Z (COMMENT)`
///
/// Appends component signature to the Coraza signature.
fn directive_sec_component_signature(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.component_names.push(options.opts.clone());
    Ok(())
}

/// `SecServerSignature` [signature]
///
/// Sets the server signature that will be sent in the Server response header.
fn directive_sec_server_signature(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.server_signature.clone_from(&options.opts);
    Ok(())
}

/// `SecSensorID` [id]
///
/// Sets the sensor ID that will identify this WAF instance in a cluster.
fn directive_sec_sensor_id(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.sensor_id.clone_from(&options.opts);
    Ok(())
}

/// `SecResponseBodyLimit` `limit_in_bytes`
///
/// Sets the maximum response body size that will be buffered.
fn directive_sec_response_body_limit(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let limit = options
        .opts
        .parse::<i64>()
        .map_err(|e| format!("invalid response body limit: {e}"))?;

    options.waf_config.response_body_limit = limit;
    Ok(())
}

/// `SecResponseBodyLimitAction` [Reject|ProcessPartial]
///
/// Controls what happens when response body limit is reached.
fn directive_sec_response_body_limit_action(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let action = match options.opts.to_lowercase().as_str() {
        "reject" => BodyLimitAction::Reject,
        "processpartial" => BodyLimitAction::ProcessPartial,
        _ => {
            return Err(format!("invalid SecResponseBodyLimitAction value: {}", options.opts));
        },
    };

    options.waf_config.response_body_limit_action = action;
    Ok(())
}

/// `SecRequestBodyInMemoryLimit` `limit_in_bytes`
///
/// Sets the limit for request body data stored in memory before writing to disk.
/// `0` means unset, so the effective limit follows `SecRequestBodyLimit`.
fn directive_sec_request_body_in_memory_limit(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let limit = options
        .opts
        .parse::<i64>()
        .map_err(|e| format!("invalid in-memory limit: {e}"))?;

    options.waf_config.request_body_in_memory_limit = limit;
    Ok(())
}

/// `SecRequestBodyNoFilesLimit` `limit_in_bytes`
///
/// Sets the limit for request body excluding files.
fn directive_sec_request_body_no_files_limit(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let limit = options
        .opts
        .parse::<i64>()
        .map_err(|e| format!("invalid no-files limit: {e}"))?;

    options.waf_config.request_body_no_files_limit = limit;
    Ok(())
}

/// `SecArgumentsLimit` [limit]
///
/// Sets the maximum number of ARGS that will be accepted.
fn directive_sec_arguments_limit(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let limit = options
        .opts
        .parse::<usize>()
        .map_err(|e| format!("invalid arguments limit: {e}"))?;

    // Validate limit is > 0
    if limit == 0 {
        return Err("arguments limit must be greater than 0".to_owned());
    }

    options.waf_config.argument_limit = limit;
    Ok(())
}

/// `SecUploadDir` [directory]
///
/// Sets the directory where uploaded files will be stored, which must be writable: as Go
/// Coraza does, it checks by writing a file in it.
fn directive_sec_upload_dir(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let probe = Path::new(&options.opts).join(format!(
        "checkfsfile-{}-{}",
        std::process::id(),
        UPLOAD_PROBE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|e| format!("upload directory {} is not writable: {e}", options.opts))?;
    // A probe that can't be removed is only left behind
    drop(std::fs::remove_file(&probe));

    options.waf_config.upload_dir.clone_from(&options.opts);
    Ok(())
}

/// `SecUploadFileLimit` [limit]
///
/// Sets the maximum number of files that will be processed in a multipart request.
fn directive_sec_upload_file_limit(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let limit = options
        .opts
        .parse::<usize>()
        .map_err(|e| format!("invalid upload file limit: {e}"))?;

    options.waf_config.upload_file_limit = limit;
    Ok(())
}

/// `SecUploadFileMode` [mode]
///
/// Sets the file mode (permissions) for uploaded files.
fn directive_sec_upload_file_mode(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let mode = u32::from_str_radix(&options.opts, 8).map_err(|e| format!("invalid file mode (expected octal): {e}"))?;

    options.waf_config.upload_file_mode = mode;
    Ok(())
}

/// `SecUploadKeepFiles` [On|Off|RelevantOnly]
///
/// Controls whether uploaded files are kept after transaction.
fn directive_sec_upload_keep_files(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.upload_keep_files = match options.opts.to_ascii_lowercase().as_str() {
        "on" => UploadKeepFiles::On,
        "off" => UploadKeepFiles::Off,
        "relevantonly" => UploadKeepFiles::RelevantOnly,
        _ => return Err(format!("expected On, Off, or RelevantOnly, got: {}", options.opts)),
    };
    Ok(())
}

/// `SecAuditEngine` [On|Off|RelevantOnly]
///
/// Configures the audit logging engine.
fn directive_sec_audit_engine(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let status = AuditEngineStatus::from_str(&options.opts).map_err(|_error| {
        format!(
            "invalid SecAuditEngine value: {} (expected On, Off, or RelevantOnly)",
            options.opts
        )
    })?;

    options.waf_config.audit_engine = status;
    Ok(())
}

/// `SecAuditLog` [path]
///
/// Sets the path to the audit log file.
fn directive_sec_audit_log(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.audit_log.clone_from(&options.opts);
    Ok(())
}

/// `SecAuditLogFormat` Native|JSON|JSONLegacy|OCSF
fn directive_sec_audit_log_format(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.audit_log_format = AuditLogFormat::from_str(&options.opts).map_err(|e| e.to_string())?;
    Ok(())
}

/// `SecAuditLogParts` PARTS, e.g. `ABCFHZ`
fn directive_sec_audit_log_parts(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.audit_log_parts = parse_audit_log_parts(&options.opts).map_err(|e| e.to_string())?;
    Ok(())
}

/// `SecAuditLogType` Serial|Concurrent|HTTPS|Syslog
fn directive_sec_audit_log_type(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.audit_log_type = AuditLogType::from_str(&options.opts).map_err(|e| e.to_string())?;
    Ok(())
}

/// `SecAuditLogRelevantStatus` REGEX
fn directive_sec_audit_log_relevant_status(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    regex::Regex::new(&options.opts).map_err(|e| format!("invalid regular expression: {e}"))?;
    options.waf_config.audit_log_relevant_status.clone_from(&options.opts);
    Ok(())
}

/// `SecRxPreFilter` On|Off
///
/// In Go Coraza it lets `@rx` skip a regex that can't match, a speed-up only. The
/// regex engine here does that on its own, so the setting is checked and has no effect.
fn directive_sec_rx_pre_filter(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    parse_boolean(&options.opts).map(|_| ())
}

/// A positive integer argument.
fn parse_positive(opts: &str) -> Result<usize, String> {
    match opts.parse::<usize>() {
        Ok(value) if value > 0 => Ok(value),
        _ => Err(format!("expected a positive integer, got: {opts}")),
    }
}

/// `SecRequestBodyJsonDepthLimit` LIMIT
fn directive_sec_request_body_json_depth_limit(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.request_body_json_depth_limit = parse_positive(&options.opts)?;
    Ok(())
}

/// `SecResponseBodyJsonDepthLimit` LIMIT
fn directive_sec_response_body_json_depth_limit(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.response_body_json_depth_limit = parse_positive(&options.opts)?;
    Ok(())
}

/// `SecResponseBodyMimeType` TYPE...
///
/// Sets the response content types whose body is inspected, replacing earlier ones.
fn directive_sec_response_body_mime_type(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.response_body_mime_types = options.opts.split_whitespace().map(str::to_owned).collect();
    Ok(())
}

/// `SecDebugLog` PATH
fn directive_sec_debug_log(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.debug_log.clone_from(&options.opts);
    Ok(())
}

/// An octal permission mode, e.g. `0640`.
fn parse_mode(opts: &str) -> Result<u32, String> {
    u32::from_str_radix(opts, 8).map_err(|e| format!("invalid file mode (expected octal): {e}"))
}

/// `SecAuditLogDirMode` MODE
fn directive_sec_audit_log_dir_mode(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.audit_log_dir_mode = parse_mode(&options.opts)?;
    Ok(())
}

/// `SecAuditLogFileMode` MODE
fn directive_sec_audit_log_file_mode(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.audit_log_file_mode = parse_mode(&options.opts)?;
    Ok(())
}

/// `SecAuditLogStorageDir` DIRECTORY
fn directive_sec_audit_log_storage_dir(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.audit_log_storage_dir.clone_from(&options.opts);
    Ok(())
}

/// `SecIgnoreRuleCompilationErrors` On|Off
///
/// With `On`, later directives that fail are skipped, as with
/// [`Parser::skip_failed_directives`]. Go Coraza acts on it for `SecRule`: a rule that
/// fails to compile is skipped and its error logged
/// (`internal/seclang/directives.go:186-206`, v3.8.1).
fn directive_sec_ignore_rule_compilation_errors(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    *options.skip_failed = parse_boolean(&options.opts)?;
    Ok(())
}

/// `SecRemoteRulesFailAction` Abort|Warn
///
/// Checked, and has no effect: `SecRemoteRules` isn't supported, as in Go Coraza.
fn directive_sec_remote_rules_fail_action(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    match options.opts.to_lowercase().as_str() {
        "abort" | "warn" => Ok(()),
        _ => Err(format!("expected Abort or Warn, got: {}", options.opts)),
    }
}

/// `SecRemoteRules` KEY URL
///
/// Not supported, as in Go Coraza: loading rules over the network is left to the
/// embedder.
fn directive_sec_remote_rules(_options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    Err("not supported".to_owned())
}

/// `SecResponseBodyMimeTypesClear`
///
/// Clears the response content types set by `SecResponseBodyMimeType`.
fn directive_sec_response_body_mime_types_clear(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.response_body_mime_types.clear();
    Ok(())
}

/// `SecDataDir` [directory]
///
/// Sets the directory for storing data files.
fn directive_sec_data_dir(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    options.waf_config.data_dir.clone_from(&options.opts);
    Ok(())
}

/// `SecCollectionTimeout` [seconds]
///
/// Sets the timeout for IP/SESSION/USER collections.
fn directive_sec_collection_timeout(options: &mut DirectiveOptions<'_>) -> Result<(), String> {
    let timeout = options
        .opts
        .parse::<i64>()
        .map_err(|e| format!("invalid collection timeout: {e}"))?;

    options.waf_config.collection_timeout = timeout;
    Ok(())
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "parser tests use fixed directives and temporary fixtures"
)]
mod tests {
    use super::*;

    #[test]
    fn test_split_last_argument() {
        assert_eq!(split_last_argument("1 2 ARGS"), Some(("1 2", "ARGS")));
        assert_eq!(split_last_argument(r#"1 "!ARGS:a b""#), Some(("1", "!ARGS:a b")));
        // As left by the parser once it removed the quotes around the whole argument
        assert_eq!(split_last_argument(r#"tag" "!ARGS:a"#), Some(("tag", "!ARGS:a")));
        assert_eq!(split_last_argument("ARGS"), None);
    }

    #[test]
    fn test_parse_id_range() {
        assert_eq!(parse_id_range("5"), Ok(5..=5));
        assert_eq!(parse_id_range("5-9"), Ok(5..=9));
        assert!(parse_id_range("9-5").is_err());
        assert!(parse_id_range("-5").is_err());
        assert!(parse_id_range("a").is_err());
    }

    #[test]
    fn test_parser_new() {
        let parser = Parser::new();
        assert_eq!(parser.state.current_line, 0);
        assert_eq!(parser.include_count, 0);
    }

    #[test]
    fn test_parse_empty_string() {
        let mut parser = Parser::new();
        assert!(parser.from_string("").is_ok());
    }

    #[test]
    fn compile_does_not_create_the_audit_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut parser = Parser::new();
        parser
            .from_string(&format!("SecAuditEngine On\nSecAuditLog {}", path.to_string_lossy()))
            .unwrap();

        let waf = parser.compile().unwrap();
        assert!(!path.exists(), "compiling activated the audit writer");
        waf.activate().unwrap();
        assert!(path.exists(), "activation did not open the audit writer");
    }

    #[test]
    fn compile_rejects_a_bad_syslog_audit_target() {
        let mut parser = Parser::new();
        parser
            .from_string("SecAuditEngine On\nSecAuditLogType Syslog\nSecAuditLog unix://")
            .unwrap();

        let error = parser.compile().unwrap_err();
        assert!(error.to_string().contains("invalid syslog target"), "{error}");
    }

    #[cfg(feature = "https-audit")]
    #[test]
    fn compile_does_not_connect_an_https_audit_target() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut parser = Parser::new();
        parser
            .from_string(&format!(
                "SecAuditEngine On\nSecAuditLogType HTTPS\nSecAuditLog http://{}/audit",
                listener.local_addr().unwrap()
            ))
            .unwrap();

        let waf = parser.compile().unwrap();
        assert!(
            listener.accept().is_err(),
            "compiling connected to the HTTPS audit target"
        );
        drop(waf);
    }

    #[test]
    fn registered_custom_operator_compiles_and_evaluates() {
        use crate::{
            operators::{Operator, Outputs},
            transaction::Transaction,
        };

        struct Equals(String);
        impl Operator for Equals {
            fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
                input == self.0.as_bytes()
            }
        }

        let mut parser = Parser::new();
        parser.register_operator(
            "equals",
            std::sync::Arc::new(|argument: &str| {
                let operator: Box<dyn Operator> = Box::new(Equals(argument.to_owned()));
                Ok(operator)
            }),
        );
        parser
            .from_string("SecRule ARGS:q \"@equals yes\" \"id:1,phase:1,pass\"")
            .unwrap();
        let waf = parser.compile().unwrap();
        let mut tx = waf.new_transaction_with_id("custom-operator");
        tx.add_get_argument("q", "yes");
        tx.process_request_headers();

        assert!(tx.matched_rules().iter().any(|matched| matched.rule.id == 1));
    }

    #[test]
    fn into_waf_accepts_each_case_sensitive_args_keys_mode() {
        for case_sensitive_args_keys in [false, true] {
            let mut parser = Parser::new();
            parser.config_mut().case_sensitive_args_keys = case_sensitive_args_keys;
            parser
                .from_string("SecRule ARGS:/^userId$/ \"@contains secret\" \"id:1,phase:1,deny\"")
                .unwrap();
            assert!(parser.into_waf().is_ok(), "{case_sensitive_args_keys}");
        }
    }

    #[test]
    fn changing_case_sensitive_args_keys_after_rules_fails_into_waf() {
        let mut parser = Parser::new();
        parser
            .from_string("SecRule ARGS:password \"@contains secret\" \"id:1,phase:1,deny\"")
            .unwrap();
        parser.config_mut().case_sensitive_args_keys = true;

        let error = parser.into_waf().unwrap_err();

        assert!(error.to_string().contains("case_sensitive_args_keys"));
    }

    #[test]
    fn changing_case_sensitive_args_keys_between_rules_is_rejected() {
        let mut parser = Parser::new();
        parser
            .from_string("SecRule ARGS:password \"@contains secret\" \"id:1,phase:1,deny\"")
            .unwrap();
        parser.config_mut().case_sensitive_args_keys = true;

        let error = parser
            .from_string("SecRule ARGS:token \"@contains secret\" \"id:2,phase:1,deny\"")
            .unwrap_err();

        assert!(error.to_string().contains("case_sensitive_args_keys"));
        assert_eq!(parser.rule_count(), 1);
        assert!(parser.into_waf().is_err());
    }

    #[test]
    fn changing_case_sensitive_args_keys_before_target_update_is_rejected() {
        let mut parser = Parser::new();
        parser
            .from_string("SecRule ARGS:password \"@contains secret\" \"id:1,phase:1,deny\"")
            .unwrap();
        parser.config_mut().case_sensitive_args_keys = true;

        let error = parser
            .from_string("SecRuleUpdateTargetById 1 \"ARGS:/^token/\"")
            .unwrap_err();

        assert!(error.to_string().contains("case_sensitive_args_keys"));
    }

    #[test]
    fn waf_with_rules_rejects_a_different_key_mode() {
        let mut parser = Parser::new();
        parser
            .from_string("SecRule ARGS:password \"@contains secret\" \"id:1,phase:1,deny\"")
            .unwrap();
        let config = WafConfig {
            case_sensitive_args_keys: true,
            ..parser.config().clone()
        };

        let error = Waf::with_rules(config, parser.rules, None).unwrap_err();

        assert!(error.to_string().contains("case_sensitive_args_keys"));
    }

    #[test]
    fn test_parse_comment_only() {
        let mut parser = Parser::new();
        assert!(parser.from_string("# This is a comment").is_ok());
    }

    #[test]
    fn test_parse_multiple_comments() {
        let mut parser = Parser::new();
        let input = "
# Comment 1
# Comment 2
  # Indented comment
";
        assert!(parser.from_string(input).is_ok());
    }

    #[test]
    fn test_parse_directive_case_insensitive() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRuleEngine On").is_ok());
        assert!(parser.from_string("secruleengine On").is_ok());
        assert!(parser.from_string("SECRULEENGINE On").is_ok());
        assert!(parser.from_string("sEcRuLeEnGiNe On").is_ok());
    }

    #[test]
    fn test_parse_unknown_directive() {
        let mut parser = Parser::new();
        let result = parser.from_string("UnknownDirective foo");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("unknown directive"));
        assert!(err.message.contains("UnknownDirective"));
    }

    #[test]
    fn test_parse_line_continuation() {
        let mut parser = Parser::new();
        let input = r"
SecRuleEngine \
On
";
        assert!(parser.from_string(input).is_ok());
    }

    #[test]
    fn test_parse_multiple_line_continuations() {
        let mut parser = Parser::new();
        let input = r"
SecRuleEngine \
\
\
On
";
        assert!(parser.from_string(input).is_ok());
    }

    #[test]
    fn test_parse_backticks_unclosed() {
        let mut parser = Parser::new();
        let input = "SecDataset test `";
        let result = parser.from_string(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("backticks left open"));
    }

    #[test]
    fn test_written_directives() {
        let mut input = "# comment\n\n  SecRuleEngine \\\n  On  \r\n\
                         SecDataset d `\n  a\\\n# skipped\nb\n`\nSecMarker END";
        let mut next = || written_directive.parse_next(&mut input);
        assert_eq!(next(), Ok("SecRuleEngine On".into()));
        assert_eq!(next(), Ok("SecDataset d `\na\\\nb\n`".into()));
        assert_eq!(next(), Ok("SecMarker END".into()));
        assert!(matches!(next(), Err(ErrMode::Backtrack(_))));
    }

    #[test]
    fn test_written_directive_continued_past_the_end_is_dropped() {
        let mut input = "SecMarker A \\\n# comment\n";
        assert!(matches!(
            written_directive.parse_next(&mut input),
            Err(ErrMode::Backtrack(_))
        ));
    }

    #[test]
    fn test_written_directive_with_block_left_open() {
        let mut input = "SecDataset d `\na\n";
        assert!(matches!(written_directive.parse_next(&mut input), Err(ErrMode::Cut(_))));
    }

    #[test]
    fn test_directives_are_located_on_their_last_line() {
        let mut parser = Parser::new();
        parser
            .from_string("# rules\nSecAction \\\n  \"id:1,pass\"\n\nSecMarker END")
            .unwrap();
        let metadata = parser.rules.find_by_id(1).unwrap().metadata();
        assert_eq!((metadata.line, metadata.raw.as_str()), (3, "SecAction \"id:1,pass\""));

        let mut parser = Parser::new();
        let err = parser.from_string("SecRuleEngine \\\n\nInvalid\n").unwrap_err();
        assert_eq!(err.line, 3);
        let err = parser.from_string("SecMarker A\nSecDataset d `\na\n\n").unwrap_err();
        assert_eq!((err.line, err.message.as_str()), (4, "backticks left open"));
    }

    #[test]
    fn test_parse_directive_with_quotes() {
        let mut parser = Parser::new();
        // Quotes around options should be removed
        assert!(parser.from_string("SecRuleEngine \"On\"").is_ok());
    }

    #[test]
    fn test_sec_rule_engine_valid_values() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRuleEngine On").is_ok());
        assert!(parser.from_string("SecRuleEngine Off").is_ok());
        assert!(parser.from_string("SecRuleEngine DetectionOnly").is_ok());
    }

    #[test]
    fn test_sec_rule_engine_invalid_value() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRuleEngine Invalid");
        assert!(result.is_err());
        let err = result.unwrap_err();
        // Error message should indicate invalid value
        assert!(err.message.to_lowercase().contains("invalid"));
    }

    #[test]
    fn test_sec_rule_engine_no_argument() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRuleEngine");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("requires an argument"));
    }

    #[test]
    fn test_parse_error_includes_line_number() {
        let mut parser = Parser::new();
        let input = "
# Line 1 (comment)
SecRuleEngine On
UnknownDirective
";
        let result = parser.from_string(input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.line, 4); // Comment is line 2, SecRuleEngine is line 3, Unknown is line 4
    }

    // ========================================================================
    // SecRequestBodyAccess Tests
    // ========================================================================

    #[test]
    fn test_sec_request_body_access_on() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyAccess On").is_ok());
        assert!(parser.config().request_body_access);
    }

    #[test]
    fn test_sec_request_body_access_off() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyAccess Off").is_ok());
        assert!(!parser.config().request_body_access);
    }

    #[test]
    fn test_sec_request_body_access_case_insensitive() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyAccess ON").is_ok());
        assert!(parser.config().request_body_access);
    }

    #[test]
    fn test_sec_request_body_access_invalid() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRequestBodyAccess Invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_request_body_access_no_argument() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRequestBodyAccess");
        assert!(result.is_err());
    }

    // ========================================================================
    // SecResponseBodyAccess Tests
    // ========================================================================

    #[test]
    fn test_sec_response_body_access_on() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecResponseBodyAccess On").is_ok());
        assert!(parser.config().response_body_access);
    }

    #[test]
    fn test_sec_response_body_access_off() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecResponseBodyAccess Off").is_ok());
        assert!(!parser.config().response_body_access);
    }

    // ========================================================================
    // SecRequestBodyLimit Tests
    // ========================================================================

    #[test]
    fn test_sec_request_body_limit_valid() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyLimit 1024").is_ok());
        assert_eq!(parser.config().request_body_limit, 1024);
    }

    #[test]
    fn test_sec_request_body_limit_large() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyLimit 134217728").is_ok());
        assert_eq!(parser.config().request_body_limit, 134_217_728);
    }

    #[test]
    fn test_sec_request_body_limit_invalid() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRequestBodyLimit abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_request_body_limit_no_argument() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRequestBodyLimit");
        assert!(result.is_err());
    }

    // ========================================================================
    // SecRequestBodyLimitAction Tests
    // ========================================================================

    #[test]
    fn test_sec_request_body_limit_action_reject() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyLimitAction Reject").is_ok());
        assert_eq!(parser.config().request_body_limit_action, BodyLimitAction::Reject);
    }

    #[test]
    fn test_sec_request_body_limit_action_process_partial() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyLimitAction ProcessPartial").is_ok());
        assert_eq!(
            parser.config().request_body_limit_action,
            BodyLimitAction::ProcessPartial
        );
    }

    #[test]
    fn test_sec_request_body_limit_action_case_insensitive() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyLimitAction REJECT").is_ok());
        assert_eq!(parser.config().request_body_limit_action, BodyLimitAction::Reject);
    }

    #[test]
    fn test_sec_request_body_limit_action_invalid() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecRequestBodyLimitAction Invalid");
        assert!(result.is_err());
    }

    // ========================================================================
    // SecDebugLogLevel Tests
    // ========================================================================

    #[test]
    fn test_sec_debug_log_level_valid_range() {
        let mut parser = Parser::new();
        for level in 0..=9 {
            let directive = format!("SecDebugLogLevel {level}");
            assert!(parser.from_string(&directive).is_ok());
            assert_eq!(parser.config().debug_log_level, level);
        }
    }

    #[test]
    fn test_sec_debug_log_level_out_of_range() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecDebugLogLevel 10");
        assert!(result.is_err());
    }

    #[test]
    fn test_sec_debug_log_level_invalid() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecDebugLogLevel abc");
        assert!(result.is_err());
    }

    // ========================================================================
    // SecWebAppId Tests
    // ========================================================================

    #[test]
    fn test_sec_web_app_id() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecWebAppId myapp").is_ok());
        assert_eq!(parser.config().web_app_id, "myapp");
    }

    #[test]
    fn test_sec_web_app_id_with_spaces() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecWebAppId my application").is_ok());
        assert_eq!(parser.config().web_app_id, "my application");
    }

    #[test]
    fn test_sec_web_app_id_no_argument() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecWebAppId");
        assert!(result.is_err());
    }

    // ========================================================================
    // SecComponentSignature Tests
    // ========================================================================

    #[test]
    fn test_sec_component_signature() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecComponentSignature \"OWASP_CRS/4.0.0\"").is_ok());
        assert_eq!(parser.config().component_names.len(), 1);
        assert_eq!(parser.config().component_names[0], "OWASP_CRS/4.0.0");
    }

    #[test]
    fn test_sec_component_signature_multiple() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecComponentSignature \"Component1\"").is_ok());
        assert!(parser.from_string("SecComponentSignature \"Component2\"").is_ok());
        assert_eq!(parser.config().component_names.len(), 2);
        assert_eq!(parser.config().component_names[0], "Component1");
        assert_eq!(parser.config().component_names[1], "Component2");
    }

    #[test]
    fn test_sec_component_signature_no_argument() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecComponentSignature");
        assert!(result.is_err());
    }

    // ========================================================================
    // Integration Tests (multiple directives)
    // ========================================================================

    #[test]
    fn test_multiple_directives() {
        let mut parser = Parser::new();
        let input = "
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 1048576
SecDebugLogLevel 3
SecWebAppId production
";
        assert!(parser.from_string(input).is_ok());
        assert_eq!(parser.config().rule_engine, RuleEngineStatus::On);
        assert!(parser.config().request_body_access);
        assert!(!parser.config().response_body_access);
        assert_eq!(parser.config().request_body_limit, 1_048_576);
        assert_eq!(parser.config().debug_log_level, 3);
        assert_eq!(parser.config().web_app_id, "production");
    }

    // ========================================================================
    // Additional Configuration Directives Tests
    // ========================================================================

    #[test]
    fn test_sec_server_signature() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecServerSignature \"Apache/2.4.0\"").is_ok());
        assert_eq!(parser.config().server_signature, "Apache/2.4.0");
    }

    #[test]
    fn test_sec_sensor_id() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecSensorID sensor-01").is_ok());
        assert_eq!(parser.config().sensor_id, "sensor-01");
    }

    #[test]
    fn test_sec_response_body_limit() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecResponseBodyLimit 524288").is_ok());
        assert_eq!(parser.config().response_body_limit, 524_288);
    }

    #[test]
    fn test_sec_response_body_limit_action() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecResponseBodyLimitAction ProcessPartial").is_ok());
        assert_eq!(
            parser.config().response_body_limit_action,
            BodyLimitAction::ProcessPartial
        );
    }

    #[test]
    fn test_sec_request_body_in_memory_limit() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyInMemoryLimit 131072").is_ok());
        assert_eq!(parser.config().request_body_in_memory_limit, 131_072);
    }

    #[test]
    fn test_sec_request_body_no_files_limit() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecRequestBodyNoFilesLimit 65536").is_ok());
        assert_eq!(parser.config().request_body_no_files_limit, 65536);
    }

    #[test]
    fn test_sec_arguments_limit() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecArgumentsLimit 500").is_ok());
        assert_eq!(parser.config().argument_limit, 500);
    }

    #[test]
    fn test_sec_upload_dir() {
        let mut parser = Parser::new();
        let upload_dir = std::env::temp_dir();
        let directive = format!("SecUploadDir {}", upload_dir.display());
        assert!(parser.from_string(&directive).is_ok());
        assert_eq!(parser.config().upload_dir, upload_dir.to_string_lossy());
    }

    #[test]
    fn test_sec_upload_file_limit() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecUploadFileLimit 50").is_ok());
        assert_eq!(parser.config().upload_file_limit, 50);
    }

    #[test]
    fn test_sec_upload_file_mode() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecUploadFileMode 0644").is_ok());
        assert_eq!(parser.config().upload_file_mode, 0o644);
    }

    #[test]
    fn test_sec_upload_keep_files() {
        use crate::config::UploadKeepFiles;

        let mut parser = Parser::new();
        let result = parser.from_string("SecUploadKeepFiles On");
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(parser.config().upload_keep_files, UploadKeepFiles::On);

        let mut parser = Parser::new();
        assert!(parser.from_string("SecUploadKeepFiles off").is_ok());
        assert_eq!(parser.config().upload_keep_files, UploadKeepFiles::Off);

        let mut parser = Parser::new();
        assert!(parser.from_string("SecUploadKeepFiles RelevantOnly").is_ok());
        assert_eq!(parser.config().upload_keep_files, UploadKeepFiles::RelevantOnly);

        let mut parser = Parser::new();
        let error = parser.from_string("SecUploadKeepFiles Always").unwrap_err();
        assert!(error.message.contains("expected On, Off, or RelevantOnly"), "{error}");
    }

    #[test]
    fn test_sec_audit_engine() {
        use crate::types::AuditEngineStatus;

        let mut parser = Parser::new();
        assert!(parser.from_string("SecAuditEngine On").is_ok());
        assert_eq!(parser.config().audit_engine, AuditEngineStatus::On);

        let mut parser = Parser::new();
        assert!(parser.from_string("SecAuditEngine Off").is_ok());
        assert_eq!(parser.config().audit_engine, AuditEngineStatus::Off);

        let mut parser = Parser::new();
        assert!(parser.from_string("SecAuditEngine RelevantOnly").is_ok());
        assert_eq!(parser.config().audit_engine, AuditEngineStatus::RelevantOnly);
    }

    #[test]
    fn test_sec_audit_log() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecAuditLog /var/log/coraza/audit.log").is_ok());
        assert_eq!(parser.config().audit_log, "/var/log/coraza/audit.log");
    }

    #[test]
    fn test_sec_data_dir() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecDataDir /var/cache/coraza").is_ok());
        assert_eq!(parser.config().data_dir, "/var/cache/coraza");
    }

    #[test]
    fn test_sec_collection_timeout() {
        let mut parser = Parser::new();
        assert!(parser.from_string("SecCollectionTimeout 7200").is_ok());
        assert_eq!(parser.config().collection_timeout, 7200);
    }

    // ========================================================================
    // Include Directive Tests
    // ========================================================================

    #[test]
    fn test_include_file() {
        use std::{fs, io::Write as _};

        // Create a temporary directory for test files
        let temp_dir = std::env::temp_dir().join("coraza_include_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create a test config file
        let test_file = temp_dir.join("test_rules.conf");
        let mut file = fs::File::create(&test_file).unwrap();
        writeln!(file, "SecRuleEngine On").unwrap();
        writeln!(file, "SecWebAppId included_file").unwrap();

        // Parse with include
        let mut parser = Parser::new();
        parser.state.current_dir = temp_dir.to_string_lossy().into_owned();
        assert!(parser.from_file(&test_file).is_ok());

        assert_eq!(parser.config().rule_engine, RuleEngineStatus::On);
        assert_eq!(parser.config().web_app_id, "included_file");

        // Cleanup
        assert!(fs::remove_dir_all(&temp_dir).is_ok());
    }

    #[test]
    fn test_include_directive_from_string() {
        use std::{fs, io::Write as _};

        // Create a temporary directory
        let temp_dir = std::env::temp_dir().join("coraza_include_directive_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create included file
        let included_file = temp_dir.join("included.conf");
        let mut file = fs::File::create(&included_file).unwrap();
        writeln!(file, "SecWebAppId from_included").unwrap();

        // Create main file with Include directive
        let main_file = temp_dir.join("main.conf");
        let mut file = fs::File::create(&main_file).unwrap();
        writeln!(file, "SecRuleEngine DetectionOnly").unwrap();
        writeln!(file, "Include included.conf").unwrap();

        // Parse main file
        let mut parser = Parser::new();
        parser.state.current_dir = temp_dir.to_string_lossy().into_owned();
        assert!(parser.from_file(&main_file).is_ok());

        assert_eq!(parser.config().rule_engine, RuleEngineStatus::DetectionOnly);
        assert_eq!(parser.config().web_app_id, "from_included");

        // Cleanup
        assert!(fs::remove_dir_all(&temp_dir).is_ok());
    }

    #[test]
    fn test_include_glob_pattern() {
        use std::{fs, io::Write as _};

        // Create a temporary directory
        let temp_dir = std::env::temp_dir().join("coraza_glob_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create multiple .conf files
        for i in 1..=3 {
            let file_path = temp_dir.join(format!("rules{i}.conf"));
            let mut file = fs::File::create(&file_path).unwrap();
            writeln!(file, "SecComponentSignature \"Component{i}\"").unwrap();
        }

        // Parse with glob pattern
        let mut parser = Parser::new();
        let glob_pattern = temp_dir.join("*.conf").to_string_lossy().into_owned();
        assert!(parser.from_file(&glob_pattern).is_ok());

        // Should have loaded all 3 components
        assert_eq!(parser.config().component_names.len(), 3);

        // Cleanup
        assert!(fs::remove_dir_all(&temp_dir).is_ok());
    }

    #[test]
    fn test_include_glob_pattern_with_no_matches() {
        let glob_pattern = std::env::temp_dir()
            .join(format!("coraza_glob_no_match_{}", std::process::id()))
            .join("*.conf")
            .to_string_lossy()
            .into_owned();
        let mut parser = Parser::new();

        let error = parser.from_file(&glob_pattern).unwrap_err();

        assert!(error.message.contains(&glob_pattern));
    }

    #[test]
    fn test_include_recursion_limit() {
        use std::{fs, io::Write as _};

        // Create a temporary directory
        let temp_dir = std::env::temp_dir().join("coraza_recursion_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create file that includes itself (infinite recursion)
        let self_include = temp_dir.join("self_include.conf");
        let mut file = fs::File::create(&self_include).unwrap();
        writeln!(file, "Include self_include.conf").unwrap();

        // Try to parse - should hit recursion limit
        let mut parser = Parser::new();
        parser.state.current_dir = temp_dir.to_string_lossy().into_owned();
        let result = parser.from_file(&self_include);

        // Should error due to recursion limit
        assert!(result.is_err());
        assert_eq!(parser.include_count, 0);
        if let Err(e) = result {
            assert!(e.message.contains("cannot include more than"));
        }

        // Cleanup
        assert!(fs::remove_dir_all(&temp_dir).is_ok());
    }

    #[test]
    fn test_include_relative_path() {
        use std::{fs, io::Write as _};

        // Create a temporary directory structure
        let temp_dir = std::env::temp_dir().join("coraza_relative_test");
        let sub_dir = temp_dir.join("subdir");
        fs::create_dir_all(&sub_dir).unwrap();

        // Create file in subdirectory
        let sub_file = sub_dir.join("sub_rules.conf");
        let mut file = fs::File::create(&sub_file).unwrap();
        writeln!(file, "SecWebAppId from_subdir").unwrap();

        // Create main file with relative include
        let main_file = temp_dir.join("main.conf");
        let mut file = fs::File::create(&main_file).unwrap();
        writeln!(file, "Include subdir/*.conf").unwrap();

        // Parse main file
        let mut parser = Parser::new();
        parser.state.current_dir = temp_dir.to_string_lossy().into_owned();
        assert!(parser.from_file(&main_file).is_ok());

        assert_eq!(parser.config().web_app_id, "from_subdir");

        // Cleanup
        assert!(fs::remove_dir_all(&temp_dir).is_ok());
    }

    #[test]
    fn test_include_nonexistent_file() {
        let mut parser = Parser::new();
        let result = parser.from_file("/nonexistent/path/to/file.conf");

        // Should error
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.message.contains("failed to read file"));
        }
    }

    // ===== Rule directives =====

    #[test]
    fn test_rule_directives_compile() {
        let mut parser = Parser::new();
        parser
            .from_string(
                r#"
                SecRule ARGS "@contains attack" "id:1,phase:1,deny"
                SecAction "id:2,phase:1,pass"
                SecMarker END
                "#,
            )
            .unwrap();

        assert_eq!(parser.rule_count(), 3);
        assert!(parser.rules.find_by_id(1).is_some());
        assert!(parser.rules.find_by_id(2).is_some());
    }

    #[test]
    fn test_rule_compile_error_reports_location() {
        let mut parser = Parser::new();
        let err = parser
            .from_string("SecRuleEngine On\nSecRule ARGS \"@nosuchop x\" \"id:1\"")
            .unwrap_err();

        assert_eq!(err.line, 2);
        assert!(err.message.contains("unknown operator"), "{err:?}");
    }

    #[test]
    fn test_duplicate_rule_id_rejected() {
        let mut parser = Parser::new();
        let err = parser
            .from_string("SecAction \"id:1,pass\"\nSecAction \"id:1,pass\"")
            .unwrap_err();

        assert_eq!(err.line, 2);
        assert!(err.message.contains("duplicated rule id 1"), "{err:?}");
    }

    #[test]
    fn test_rule_update_and_remove_directives() {
        let mut parser = Parser::new();
        parser
            .from_string(
                "SecAction \"id:1,phase:1,log,pass\"\nSecAction \"id:2,phase:1,pass\"\nSecRuleUpdateActionById 1 \"nolog\"\nSecRuleRemoveById 2",
            )
            .unwrap();

        assert_eq!(parser.rule_count(), 1);
        let rule = parser.rules.find_by_id(1).unwrap();
        assert!(!rule.metadata().log);
        assert_eq!(rule.actions().first().map(|action| action.name.as_str()), Some("pass"));
    }

    #[test]
    fn test_chained_rules_join_their_parent() {
        let mut parser = Parser::new();
        parser
            .from_string(
                r#"
                SecRule ARGS "@contains a" "id:1,phase:1,deny,chain"
                    SecRule ARGS "@contains b" ""
                "#,
            )
            .unwrap();

        assert_eq!(parser.rule_count(), 1);
        assert_eq!(parser.rules.find_by_id(1).unwrap().chain.len(), 1);
    }

    #[test]
    fn test_skip_failed_directives() {
        let mut parser = Parser::new();
        parser.skip_failed_directives();
        parser
            .from_string(
                r#"
                SecNoSuchDirective On
                SecRule ARGS "@nosuchop x" "id:1"
                SecRule ARGS "@contains attack" "id:2,phase:1,deny"
                "#,
            )
            .unwrap();

        let lines: Vec<usize> = parser.skipped().iter().map(|e| e.line).collect();
        assert_eq!(lines, vec![2, 3]);
        assert_eq!(parser.rule_count(), 1);
    }

    #[test]
    fn test_failed_directive_stops_parsing_by_default() {
        let mut parser = Parser::new();
        let result = parser.from_string("SecDefaultAction \"phase:1\"\nSecAction \"id:2,pass\"");

        assert!(result.is_err());
        assert!(parser.skipped().is_empty());
        assert_eq!(parser.rule_count(), 0);
    }

    #[test]
    fn test_skip_failed_directives_drops_a_chain_with_a_failed_link() {
        let mut parser = Parser::new();
        parser.skip_failed_directives();
        parser
            .from_string(
                r#"
                SecRule ARGS "@contains a" "id:1,phase:1,deny,chain"
                    SecRule ARGS "@nosuchop b" "chain"
                SecRule ARGS "@contains c" ""
                SecAction "id:2,phase:1,pass"
                "#,
            )
            .unwrap();

        assert!(parser.rules.find_by_id(1).is_none());
        assert!(parser.rules.find_by_id(2).is_some());
        assert_eq!(parser.rule_count(), 1);
        assert_eq!(parser.skipped().len(), 2);
    }

    #[test]
    fn test_skip_failed_chain_parent_and_links() {
        let mut parser = Parser::new();
        parser.skip_failed_directives();
        parser
            .from_string(
                "SecRule ARGS \"@nosuchop a\" \"id:1,phase:1,deny,chain\"\n\
                 SecRuleEngine On\n\
                 SecRule ARGS \"@contains b\" \"chain\"\n\
                 SecAction \"id:2,phase:1,pass\"\n\
                 SecRule ARGS \"@contains c\" \"id:3,phase:1,deny\"",
            )
            .unwrap();

        assert_eq!(parser.config().rule_engine, RuleEngineStatus::On);
        assert!(parser.rules.find_by_id(1).is_none());
        assert!(parser.rules.find_by_id(2).is_none());
        assert!(parser.rules.find_by_id(3).is_some());
        assert_eq!(parser.rule_count(), 1);
        assert_eq!(
            parser.skipped().iter().map(|error| error.line).collect::<Vec<_>>(),
            [1, 3, 4]
        );
    }

    #[test]
    fn test_skip_failed_directive_discards_open_chain_before_following_rule() {
        let mut parser = Parser::new();
        parser.skip_failed_directives();
        parser
            .from_string(
                "SecRule ARGS \"@contains a\" \"id:1,phase:1,deny,chain\"\n\
                 SecNoSuchDirective On\n\
                 SecRule ARGS \"@contains b\" \"id:2,phase:1,deny\"\n\
                 SecAction \"id:3,phase:1,pass\"",
            )
            .unwrap();

        assert!(parser.rules.find_by_id(1).is_none());
        assert!(parser.rules.find_by_id(2).is_none());
        assert!(parser.rules.find_by_id(3).is_some());
        assert_eq!(parser.rule_count(), 1);
        assert_eq!(parser.skipped().len(), 2);
    }
}
