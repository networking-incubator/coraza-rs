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

//! Operators that match transaction values.
//!
//! This slice includes comparisons, regular expressions, phrase and path
//! matching, IP, validation, `SQLi`, and XSS operators. Compiled rules use
//! these operators during request-phase evaluation.

pub mod detection;
#[cfg(feature = "inspect-file")]
pub mod inspect_file;
pub mod ip;
mod macros;
mod pattern;
#[cfg(feature = "rbl")]
pub mod rbl;
mod simple;
#[cfg(feature = "validate-schema")]
pub mod validate_schema;
pub mod validation;

use std::{collections::BTreeMap, path::Path, sync::Arc};

pub use detection::{DetectSQLi, DetectXSS, detect_sqli, detect_xss};
#[cfg(feature = "inspect-file")]
pub use inspect_file::{InspectFile, inspect_file};
pub use ip::{IpMatch, IpMatchFromDataset, IpMatchFromFile, ip_match, ip_match_from_dataset, ip_match_from_file};
pub use macros::{Macro, MacroError};
pub use pattern::{
    Pm, PmFromDataset, PmFromFile, RestPath, Rx, StrMatch, Within, pm, pm_from_dataset, pm_from_file, rest_path, rx,
    strmatch, within,
};
#[cfg(feature = "rbl")]
pub use rbl::{Rbl, rbl};
pub use simple::{
    BeginsWith, Contains, EndsWith, Eq, Ge, Gt, Le, Lt, StrEq, begins_with, contains, ends_with, eq, ge, gt, le, lt,
    streq,
};
#[cfg(feature = "validate-schema")]
pub use validate_schema::{ValidateSchema, validate_schema};
pub use validation::{
    NoMatch, UnconditionalMatch, ValidateByteRange, ValidateNid, ValidateUrlEncoding, ValidateUtf8Encoding, no_match,
    unconditional_match, validate_byte_range, validate_nid, validate_url_encoding, validate_utf8_encoding,
};

use crate::transaction::Transaction;

/// The result of evaluating an operator against one input value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorOutcome {
    /// The operator inspected the input and it matched.
    Matched,
    /// The operator inspected the input and it did not match.
    NotMatched,
    /// The operator could not inspect the input, so it has no verdict.
    ///
    /// Rules treat this as not matched and record it on the transaction so an
    /// embedder can tell a skipped inspection from a benign value.
    NotInspected,
}

/// An operator evaluates one transaction value without changing the transaction.
///
/// Operators are shared across a WAF's threads, so an implementation must be
/// `Send` and `Sync`; every built-in operator is.
pub trait Operator: Send + Sync {
    /// Whether `input` matches this operator's configured parameter.
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool;

    /// Evaluate `input` and report whether it matched, did not match, or could
    /// not be inspected.
    ///
    /// The default implementation maps [`Operator::evaluate`] onto
    /// [`OperatorOutcome::Matched`] and [`OperatorOutcome::NotMatched`]. An
    /// operator that can skip an input overrides this method and reports
    /// [`OperatorOutcome::NotInspected`] instead.
    fn evaluate_outcome(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> OperatorOutcome {
        if self.evaluate(tx, input, out) {
            OperatorOutcome::Matched
        } else {
            OperatorOutcome::NotMatched
        }
    }
}

/// Named lists used by the `...FromDataset` operators.
pub type Datasets = BTreeMap<String, Vec<String>>;

/// Builds one embedder-supplied operator from its SecLang argument.
pub type CustomOperatorFactory = Arc<dyn Fn(&str) -> Result<Box<dyn Operator>, String> + Send + Sync>;

/// Embedder-supplied operator factories, keyed by lower-case SecLang name.
///
/// Lookup is case-insensitive: [`insert`](CustomOperators::insert) lower-cases
/// the name, so registering `MyOp` and then `myop` leaves one entry whose
/// factory is the later registration. A later registration with the same name
/// always replaces the earlier one.
#[derive(Clone, Default)]
pub struct CustomOperators(BTreeMap<String, CustomOperatorFactory>);

impl CustomOperators {
    /// Create an empty set of factories.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `factory` under `name`, replacing any factory registered for
    /// the same name in any letter case, and return the one it replaced.
    pub fn insert(&mut self, mut name: String, factory: CustomOperatorFactory) -> Option<CustomOperatorFactory> {
        name.make_ascii_lowercase();
        self.0.insert(name, factory)
    }

    /// The factory registered for `name`, matched case-insensitively.
    pub fn get(&self, name: &str) -> Option<&CustomOperatorFactory> {
        self.0.get(&name.to_ascii_lowercase())
    }

    /// Whether no factory is registered.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The registered names, lower-cased and sorted.
    pub fn keys(&self) -> std::collections::btree_map::Keys<'_, String, CustomOperatorFactory> {
        self.0.keys()
    }
}

/// Inputs needed when an operator reads a configured file or dataset.
#[derive(Clone, Copy)]
pub struct OperatorContext<'a> {
    /// Base directory for relative operator file paths.
    pub base_dir: &'a Path,
    /// Named operator datasets.
    pub datasets: &'a Datasets,
    /// Operator factories registered by the embedder, consulted before the built-in names.
    pub custom: Option<&'a CustomOperators>,
}

impl std::fmt::Debug for OperatorContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorContext")
            .field("base_dir", &self.base_dir)
            .field("datasets", &self.datasets)
            .field("custom", &self.custom.map(CustomOperators::keys))
            .finish()
    }
}

impl Default for OperatorContext<'_> {
    fn default() -> Self {
        static EMPTY_DATASETS: Datasets = BTreeMap::new();
        Self {
            base_dir: Path::new(""),
            datasets: &EMPTY_DATASETS,
            custom: None,
        }
    }
}

/// An embedder-supplied operator shared by [`OperatorEnum`].
///
/// [`OperatorEnum`] is cloneable but trait objects are not, so a registered
/// operator is shared through an [`Arc`] instead of the factory's `Box`. The
/// hand-written `Debug` keeps the embedder's type out of the output without
/// requiring every operator to implement `Debug`.
#[derive(Clone)]
pub struct Registered(Arc<dyn Operator>);

impl From<Box<dyn Operator>> for Registered {
    fn from(operator: Box<dyn Operator>) -> Self {
        Self(Arc::from(operator))
    }
}

impl std::fmt::Debug for Registered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CustomOperator")
    }
}

/// Values an operator hands back to its rule, such as regex captures.
#[derive(Debug, Default)]
pub struct Outputs {
    /// Whether the rule asked to record captures.
    capturing: bool,
    /// Captured bytes indexed by regex group number.
    captures: Vec<(usize, Vec<u8>)>,
    /// Path arguments extracted by operators such as `@restpath`.
    path_arguments: Vec<(String, String)>,
}

impl Outputs {
    /// Create outputs for a rule that may store captures.
    pub fn new(capturing: bool) -> Self {
        Self {
            capturing,
            ..Self::default()
        }
    }

    /// Whether the rule asked for captures.
    pub fn wants_captures(&self) -> bool {
        self.capturing
    }

    /// Add a capture when the rule requested them.
    pub fn capture(&mut self, index: usize, value: &[u8]) {
        if self.capturing {
            self.captures.push((index, value.to_vec()));
        }
    }

    /// Add a path argument extracted from the input.
    pub fn add_path_argument(&mut self, key: &str, value: &str) {
        self.path_arguments.push((key.to_owned(), value.to_owned()));
    }

    /// Take the captures in the order they were produced.
    pub(crate) fn take_captures(&mut self) -> std::vec::Drain<'_, (usize, Vec<u8>)> {
        self.captures.drain(..)
    }

    /// Take the path arguments in the order they were produced.
    pub(crate) fn take_path_arguments(&mut self) -> std::vec::Drain<'_, (String, String)> {
        self.path_arguments.drain(..)
    }
}

/// A supported operator selected by its SecLang name.
#[derive(Debug, Clone)]
pub enum OperatorEnum {
    /// Regular expression matching.
    Rx(Rx),
    /// Named path segment matching.
    RestPath(RestPath),
    /// Case-insensitive phrase matching.
    Pm(Pm),
    /// Case-insensitive phrase matching loaded from a file.
    PmFromFile(PmFromFile),
    /// Case-insensitive phrase matching loaded from a dataset.
    PmFromDataset(PmFromDataset),
    /// Case-sensitive substring matching against the parameter.
    StrMatch(StrMatch),
    /// Substring matching inside the parameter.
    Within(Within),
    /// Numeric equality.
    Eq(Eq),
    /// Numeric less-than comparison.
    Lt(Lt),
    /// Numeric less-than-or-equal comparison.
    Le(Le),
    /// Numeric greater-than comparison.
    Gt(Gt),
    /// Numeric greater-than-or-equal comparison.
    Ge(Ge),
    /// Case-sensitive byte equality.
    StrEq(StrEq),
    /// Byte substring matching.
    Contains(Contains),
    /// Byte prefix matching.
    BeginsWith(BeginsWith),
    /// Byte suffix matching.
    EndsWith(EndsWith),
    /// SQL injection detection.
    DetectSQLi(DetectSQLi),
    /// Cross-site scripting detection.
    DetectXSS(DetectXSS),
    /// IP and CIDR matching.
    IpMatch(IpMatch),
    /// IP and CIDR matching loaded from a file.
    IpMatchFromFile(IpMatchFromFile),
    /// IP and CIDR matching loaded from a dataset.
    IpMatchFromDataset(IpMatchFromDataset),
    /// Byte range violation detection.
    ValidateByteRange(ValidateByteRange),
    /// Invalid URL encoding detection.
    ValidateUrlEncoding(ValidateUrlEncoding),
    /// Invalid UTF-8 detection.
    ValidateUtf8Encoding(ValidateUtf8Encoding),
    /// National ID validation.
    ValidateNid(ValidateNid),
    /// Unconditional match.
    UnconditionalMatch(UnconditionalMatch),
    /// Unconditional non-match.
    NoMatch(NoMatch),
    /// An operator registered by an embedder's [`CustomOperatorFactory`].
    Custom(Registered),
    /// Runs an external program over each value.
    #[cfg(feature = "inspect-file")]
    InspectFile(InspectFile),
    /// Looks an address up in a DNS blocklist.
    #[cfg(feature = "rbl")]
    Rbl(Rbl),
    /// Validates a JSON document against a JSON Schema.
    #[cfg(feature = "validate-schema")]
    ValidateSchema(ValidateSchema),
}

impl OperatorEnum {
    /// Create an operator by its case-insensitive SecLang name, without `@`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown operator or invalid argument.
    pub fn new(name: &str, argument: &str) -> Result<Self, String> {
        Self::with_context(name, argument, &OperatorContext::default())
    }

    /// Create an operator using file and dataset settings from `context`.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown operator, invalid argument, missing dataset,
    /// or unreadable operator file.
    pub fn with_context(name: &str, argument: &str, context: &OperatorContext<'_>) -> Result<Self, String> {
        if let Some(factory) = context.custom.and_then(|custom| custom.get(name)) {
            return factory(argument)
                .map(|operator| Self::Custom(Registered::from(operator)))
                .map_err(|error| format!("custom operator {name}: {error}"));
        }

        match name.to_ascii_lowercase().as_str() {
            "rx" => rx(argument).map(Self::Rx).map_err(|error| error.to_string()),
            "restpath" => rest_path(argument).map(Self::RestPath),
            "pm" => pm(argument).map(Self::Pm).map_err(|error| error.to_string()),
            "pmfromfile" | "pmf" => pm_from_file(context.base_dir.join(argument)).map(Self::PmFromFile),
            "pmfromdataset" => pm_from_dataset(argument, context.datasets).map(Self::PmFromDataset),
            "strmatch" => strmatch(argument)
                .map(Self::StrMatch)
                .map_err(|error| error.to_string()),
            "within" => within(argument).map(Self::Within).map_err(|error| error.to_string()),
            "eq" => eq(argument).map(Self::Eq).map_err(|error| error.to_string()),
            "lt" => lt(argument).map(Self::Lt).map_err(|error| error.to_string()),
            "le" => le(argument).map(Self::Le).map_err(|error| error.to_string()),
            "gt" => gt(argument).map(Self::Gt).map_err(|error| error.to_string()),
            "ge" => ge(argument).map(Self::Ge).map_err(|error| error.to_string()),
            "streq" => streq(argument).map(Self::StrEq).map_err(|error| error.to_string()),
            "contains" => contains(argument)
                .map(Self::Contains)
                .map_err(|error| error.to_string()),
            "beginswith" => begins_with(argument)
                .map(Self::BeginsWith)
                .map_err(|error| error.to_string()),
            "endswith" => ends_with(argument)
                .map(Self::EndsWith)
                .map_err(|error| error.to_string()),
            "detectsqli" => Ok(Self::DetectSQLi(detect_sqli())),
            "detectxss" => Ok(Self::DetectXSS(detect_xss())),
            "ipmatch" => ip_match(argument).map(Self::IpMatch),
            "ipmatchfromfile" | "ipmatchf" => {
                ip_match_from_file(context.base_dir.join(argument)).map(Self::IpMatchFromFile)
            },
            "ipmatchfromdataset" => ip_match_from_dataset(argument, context.datasets).map(Self::IpMatchFromDataset),
            "validatebyterange" => validate_byte_range(argument).map(Self::ValidateByteRange),
            "validateurlencoding" => Ok(Self::ValidateUrlEncoding(validate_url_encoding())),
            "validateutf8encoding" => Ok(Self::ValidateUtf8Encoding(validate_utf8_encoding())),
            "validatenid" => validate_nid(argument).map(Self::ValidateNid),
            "unconditionalmatch" | "geolookup" => Ok(Self::UnconditionalMatch(unconditional_match())),
            "nomatch" => Ok(Self::NoMatch(no_match())),
            #[cfg(feature = "inspect-file")]
            "inspectfile" => Ok(Self::InspectFile(inspect_file(argument))),
            #[cfg(feature = "rbl")]
            "rbl" => rbl(argument).map(Self::Rbl),
            #[cfg(feature = "validate-schema")]
            "validateschema" => validate_schema(context.base_dir, argument).map(Self::ValidateSchema),
            _ => Err(format!("unknown operator: {name}")),
        }
    }

    /// Evaluate the selected operator.
    pub fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.evaluate_outcome(tx, input, out) == OperatorOutcome::Matched
    }

    /// Evaluate the selected operator, keeping a skipped-inspection result.
    pub fn evaluate_outcome(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> OperatorOutcome {
        match self {
            Self::Rx(operator) => operator.evaluate_outcome(tx, input, out),
            Self::RestPath(operator) => operator.evaluate_outcome(tx, input, out),
            Self::Pm(operator) => operator.evaluate_outcome(tx, input, out),
            Self::PmFromFile(operator) => operator.evaluate_outcome(tx, input, out),
            Self::PmFromDataset(operator) => operator.evaluate_outcome(tx, input, out),
            Self::StrMatch(operator) => operator.evaluate_outcome(tx, input, out),
            Self::Within(operator) => operator.evaluate_outcome(tx, input, out),
            Self::Eq(operator) => operator.evaluate_outcome(tx, input, out),
            Self::Lt(operator) => operator.evaluate_outcome(tx, input, out),
            Self::Le(operator) => operator.evaluate_outcome(tx, input, out),
            Self::Gt(operator) => operator.evaluate_outcome(tx, input, out),
            Self::Ge(operator) => operator.evaluate_outcome(tx, input, out),
            Self::StrEq(operator) => operator.evaluate_outcome(tx, input, out),
            Self::Contains(operator) => operator.evaluate_outcome(tx, input, out),
            Self::BeginsWith(operator) => operator.evaluate_outcome(tx, input, out),
            Self::EndsWith(operator) => operator.evaluate_outcome(tx, input, out),
            Self::DetectSQLi(operator) => operator.evaluate_outcome(tx, input, out),
            Self::DetectXSS(operator) => operator.evaluate_outcome(tx, input, out),
            Self::IpMatch(operator) => operator.evaluate_outcome(tx, input, out),
            Self::IpMatchFromFile(operator) => operator.evaluate_outcome(tx, input, out),
            Self::IpMatchFromDataset(operator) => operator.evaluate_outcome(tx, input, out),
            Self::ValidateByteRange(operator) => operator.evaluate_outcome(tx, input, out),
            Self::ValidateUrlEncoding(operator) => operator.evaluate_outcome(tx, input, out),
            Self::ValidateUtf8Encoding(operator) => operator.evaluate_outcome(tx, input, out),
            Self::ValidateNid(operator) => operator.evaluate_outcome(tx, input, out),
            Self::UnconditionalMatch(operator) => operator.evaluate_outcome(tx, input, out),
            Self::NoMatch(operator) => operator.evaluate_outcome(tx, input, out),
            Self::Custom(operator) => operator.0.evaluate_outcome(tx, input, out),
            #[cfg(feature = "inspect-file")]
            Self::InspectFile(operator) => operator.evaluate_outcome(tx, input, out),
            #[cfg(feature = "rbl")]
            Self::Rbl(operator) => operator.evaluate_outcome(tx, input, out),
            #[cfg(feature = "validate-schema")]
            Self::ValidateSchema(operator) => operator.evaluate_outcome(tx, input, out),
        }
    }
}

/// Implement conversions from supported operator types to [`OperatorEnum`].
macro_rules! impl_operator_from {
    ($($operator:ty => $variant:ident),+ $(,)?) => {
        $(
            impl From<$operator> for OperatorEnum {
                fn from(operator: $operator) -> Self {
                    Self::$variant(operator)
                }
            }
        )+
    };
}

impl_operator_from! {
    Rx => Rx,
    RestPath => RestPath,
    Pm => Pm,
    PmFromFile => PmFromFile,
    PmFromDataset => PmFromDataset,
    StrMatch => StrMatch,
    Within => Within,
    Eq => Eq,
    Lt => Lt,
    Le => Le,
    Gt => Gt,
    Ge => Ge,
    StrEq => StrEq,
    Contains => Contains,
    BeginsWith => BeginsWith,
    EndsWith => EndsWith,
    DetectSQLi => DetectSQLi,
    DetectXSS => DetectXSS,
    IpMatch => IpMatch,
    IpMatchFromFile => IpMatchFromFile,
    IpMatchFromDataset => IpMatchFromDataset,
    ValidateByteRange => ValidateByteRange,
    ValidateUrlEncoding => ValidateUrlEncoding,
    ValidateUtf8Encoding => ValidateUtf8Encoding,
    ValidateNid => ValidateNid,
    UnconditionalMatch => UnconditionalMatch,
    NoMatch => NoMatch,
}

#[cfg(feature = "inspect-file")]
impl_operator_from! {
    InspectFile => InspectFile,
}

#[cfg(feature = "rbl")]
impl_operator_from! {
    Rbl => Rbl,
}

#[cfg(feature = "validate-schema")]
impl_operator_from! {
    ValidateSchema => ValidateSchema,
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "operator tests use fixed valid parameters")]
mod tests {
    use super::{CustomOperatorFactory, CustomOperators, Datasets, Operator, OperatorContext, OperatorEnum, Outputs};
    use crate::transaction::Transaction;

    /// Custom operator used here: matches only the exact argument.
    #[derive(Debug)]
    struct Exact(String);

    impl Operator for Exact {
        fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
            input == self.0.as_bytes()
        }
    }

    fn exact_factory(argument: &str) -> Result<Box<dyn Operator>, String> {
        if argument.is_empty() {
            return Err("missing argument".to_owned());
        }
        Ok(Box::new(Exact(argument.to_owned())))
    }

    fn custom_context<'a>(custom: &'a CustomOperators, datasets: &'a Datasets) -> OperatorContext<'a> {
        OperatorContext {
            base_dir: std::path::Path::new(""),
            datasets,
            custom: Some(custom),
        }
    }

    #[test]
    fn operator_names_are_case_insensitive() {
        assert!(matches!(
            OperatorEnum::new("BeginsWith", "a"),
            Ok(OperatorEnum::BeginsWith(_))
        ));
        assert!(matches!(
            OperatorEnum::new("DetectSQLi", ""),
            Ok(OperatorEnum::DetectSQLi(_))
        ));
        assert!(matches!(
            OperatorEnum::new("validateURLencoding", ""),
            Ok(OperatorEnum::ValidateUrlEncoding(_))
        ));
        assert!(matches!(
            OperatorEnum::new("geoLookup", ""),
            Ok(OperatorEnum::UnconditionalMatch(_))
        ));
        assert!(matches!(
            OperatorEnum::new("RestPath", "/users/{id}"),
            Ok(OperatorEnum::RestPath(_))
        ));
    }

    #[test]
    fn unknown_operator_names_are_rejected() {
        assert_eq!(
            OperatorEnum::new("noSuchOp", "").unwrap_err(),
            "unknown operator: noSuchOp"
        );
    }

    #[test]
    fn enum_dispatch_evaluates_the_operator() {
        let operator = OperatorEnum::new("contains", "needle").unwrap();
        let tx = Transaction::new("operator-test");
        assert!(operator.evaluate(&tx, b"a needle here", &mut Outputs::default()));
        assert!(!operator.evaluate(&tx, b"no match", &mut Outputs::default()));
    }

    #[test]
    fn operator_context_supplies_named_datasets() {
        let mut datasets = Datasets::new();
        datasets.insert("phrases".to_owned(), vec!["blocked".to_owned()]);
        datasets.insert("networks".to_owned(), vec!["10.0.0.0/8".to_owned()]);
        let context = OperatorContext {
            base_dir: std::path::Path::new(""),
            datasets: &datasets,
            custom: None,
        };
        let tx = Transaction::new("operator-test");

        let phrase = OperatorEnum::with_context("pmFromDataset", "phrases", &context).unwrap();
        assert!(phrase.evaluate(&tx, b"BLOCKED", &mut Outputs::default()));
        let network = OperatorEnum::with_context("ipMatchFromDataset", "networks", &context).unwrap();
        assert!(network.evaluate(&tx, b"10.1.2.3", &mut Outputs::default()));
        assert!(!network.evaluate(&tx, b"192.0.2.1", &mut Outputs::default()));
        assert!(OperatorEnum::with_context("pmFromDataset", "missing", &context).is_err());
    }

    #[test]
    fn operator_context_resolves_phrase_and_ip_files() {
        let temp_dir = std::env::temp_dir();
        let suffix = std::process::id();
        let phrase_path = temp_dir.join(format!("coraza-phrases-{suffix}.txt"));
        let ip_path = temp_dir.join(format!("coraza-ips-{suffix}.txt"));
        std::fs::write(&phrase_path, "# ignored\nblocked-agent\n").unwrap();
        std::fs::write(&ip_path, "# ignored\n203.0.113.0/24\n").unwrap();
        let datasets = Datasets::new();
        let context = OperatorContext {
            base_dir: &temp_dir,
            datasets: &datasets,
            custom: None,
        };
        let tx = Transaction::new("operator-test");
        let phrase_name = phrase_path.file_name().unwrap().to_str().unwrap();
        let phrase = OperatorEnum::with_context("pmf", phrase_name, &context).unwrap();
        assert!(phrase.evaluate(&tx, b"BLOCKED-AGENT", &mut Outputs::default()));
        let ip_name = ip_path.file_name().unwrap().to_str().unwrap();
        let ip = OperatorEnum::with_context("ipMatchF", ip_name, &context).unwrap();
        assert!(ip.evaluate(&tx, b"203.0.113.7", &mut Outputs::default()));
        std::fs::remove_file(phrase_path).unwrap();
        std::fs::remove_file(ip_path).unwrap();
    }

    #[test]
    fn restpath_outputs_update_transaction_path_arguments() {
        use crate::{transaction::VariableCollection, types::RuleVariable};

        let mut tx = Transaction::new("operator-test");
        tx.add_get_argument("id", "same");
        tx.add_path_argument("id", "same");
        let operator = OperatorEnum::new("restPath", "/users/{id}/{name}").unwrap();
        let mut out = Outputs::default();

        assert!(operator.evaluate(&tx, b"/users/42/Alice?active=1", &mut out));
        tx.store_operator_outputs(&mut out);

        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPath, Some("id")).as_deref(),
            Some("42")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsPath, Some("name")).as_deref(),
            Some("Alice")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::Args, Some("name")).as_deref(),
            Some("Alice")
        );
        assert_eq!(
            tx.get_variable(RuleVariable::ArgsGet, Some("id")).as_deref(),
            Some("same")
        );
        let args = tx.collection(RuleVariable::Args);
        assert!(matches!(&args, Some(VariableCollection::Map(_))), "ARGS is a map");
        if let Some(VariableCollection::Map(args)) = args {
            assert_eq!(args.values("id").collect::<Vec<_>>(), [b"same".as_slice(), b"42"]);
        }
    }

    #[test]
    fn custom_factories_are_consulted_before_built_in_names() {
        let mut custom = CustomOperators::new();
        custom.insert("contains".to_owned(), std::sync::Arc::new(exact_factory));
        let datasets = Datasets::new();
        let context = custom_context(&custom, &datasets);
        let tx = Transaction::new("operator-test");

        let operator = OperatorEnum::with_context("contains", "needle", &context).unwrap();
        assert!(
            matches!(operator, OperatorEnum::Custom(_)),
            "a registered name returns the custom variant"
        );
        // The built-in `contains` would match both inputs.
        assert!(operator.evaluate(&tx, b"needle", &mut Outputs::default()));
        assert!(!operator.evaluate(&tx, b"a needle here", &mut Outputs::default()));
    }

    #[test]
    fn custom_names_are_matched_case_insensitively() {
        let mut custom = CustomOperators::new();
        custom.insert("ExactOp".to_owned(), std::sync::Arc::new(exact_factory));
        let datasets = Datasets::new();
        let context = custom_context(&custom, &datasets);
        let operator = OperatorEnum::with_context("exactop", "value", &context).unwrap();
        assert!(operator.evaluate(&Transaction::new("operator-test"), b"value", &mut Outputs::default()));
    }

    #[test]
    fn an_unregistered_name_falls_through_to_the_built_in_lookup() {
        let mut custom = CustomOperators::new();
        custom.insert("exactop".to_owned(), std::sync::Arc::new(exact_factory));
        let datasets = Datasets::new();
        let context = custom_context(&custom, &datasets);

        assert!(matches!(
            OperatorEnum::with_context("contains", "needle", &context).unwrap(),
            OperatorEnum::Contains(_)
        ));
        assert_eq!(
            OperatorEnum::with_context("noSuchOp", "", &context).unwrap_err(),
            "unknown operator: noSuchOp"
        );
    }

    #[test]
    fn custom_factory_errors_keep_their_message() {
        let mut custom = CustomOperators::new();
        custom.insert("exactop".to_owned(), std::sync::Arc::new(exact_factory));
        let datasets = Datasets::new();
        let context = custom_context(&custom, &datasets);

        assert_eq!(
            OperatorEnum::with_context("exactop", "", &context).unwrap_err(),
            "custom operator exactop: missing argument"
        );
    }

    #[test]
    fn the_default_context_registers_no_custom_operators() {
        assert!(OperatorContext::default().custom.is_none());
    }

    #[test]
    fn context_debug_lists_custom_names() {
        let mut custom = CustomOperators::new();
        let factory: CustomOperatorFactory = std::sync::Arc::new(exact_factory);
        custom.insert("exactop".to_owned(), factory);
        let datasets = Datasets::new();
        let context = custom_context(&custom, &datasets);
        assert!(format!("{context:?}").contains("exactop"));
        let operator = OperatorEnum::with_context("exactop", "value", &context).unwrap();
        assert!(format!("{operator:?}").contains("CustomOperator"));
    }

    #[test]
    fn registering_the_same_name_in_another_case_replaces_the_factory() {
        let mut custom = CustomOperators::new();
        custom.insert("ExactOp".to_owned(), std::sync::Arc::new(exact_factory));
        let first: CustomOperatorFactory = std::sync::Arc::new(|_argument: &str| {
            let operator: Box<dyn Operator> = Box::new(Exact("second".to_owned()));
            Ok(operator)
        });
        // `insert` reports the factory it replaced.
        assert!(custom.insert("exactop".to_owned(), first).is_some());
        assert_eq!(custom.keys().count(), 1, "one entry per name, not per spelling");
        assert!(custom.get("EXACTOP").is_some(), "lookup ignores case");
        let datasets = Datasets::new();
        let context = custom_context(&custom, &datasets);
        let operator = OperatorEnum::with_context("exactop", "", &context).unwrap();
        let tx = Transaction::new("operator-test");
        assert!(
            operator.evaluate(&tx, b"second", &mut Outputs::default()),
            "the later registration wins"
        );
    }

    #[cfg(not(feature = "inspect-file"))]
    #[test]
    fn inspect_file_is_unknown_without_its_feature() {
        assert_eq!(
            OperatorEnum::with_context("inspectFile", "argument", &OperatorContext::default()).unwrap_err(),
            "unknown operator: inspectFile"
        );
    }

    #[cfg(not(feature = "rbl"))]
    #[test]
    fn rbl_is_unknown_without_its_feature() {
        assert_eq!(
            OperatorEnum::with_context("rbl", "argument", &OperatorContext::default()).unwrap_err(),
            "unknown operator: rbl"
        );
    }

    #[cfg(not(feature = "validate-schema"))]
    #[test]
    fn validate_schema_is_unknown_without_the_feature() {
        assert_eq!(
            OperatorEnum::with_context("validateSchema", "schema.json", &OperatorContext::default()).unwrap_err(),
            "unknown operator: validateSchema"
        );
    }
}
