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
//! matching, IP, validation, `SQLi`, and XSS operators. Rule compilation,
//! actions, and phase evaluation are not included yet.

pub mod detection;
pub mod ip;
mod macros;
mod pattern;
mod simple;
pub mod validation;

use std::{collections::BTreeMap, path::Path};

pub use detection::{DetectSQLi, DetectXSS, detect_sqli, detect_xss};
pub use ip::{IpMatch, IpMatchFromDataset, IpMatchFromFile, ip_match, ip_match_from_dataset, ip_match_from_file};
pub use macros::{Macro, MacroError};
pub use pattern::{
    Pm, PmFromDataset, PmFromFile, RestPath, Rx, StrMatch, Within, pm, pm_from_dataset, pm_from_file, rest_path, rx,
    strmatch, within,
};
pub use simple::{
    BeginsWith, Contains, EndsWith, Eq, Ge, Gt, Le, Lt, StrEq, begins_with, contains, ends_with, eq, ge, gt, le, lt,
    streq,
};
pub use validation::{
    NoMatch, UnconditionalMatch, ValidateByteRange, ValidateNid, ValidateUrlEncoding, ValidateUtf8Encoding, no_match,
    unconditional_match, validate_byte_range, validate_nid, validate_url_encoding, validate_utf8_encoding,
};

use crate::transaction::Transaction;

/// An operator evaluates one transaction value without changing the transaction.
pub trait Operator {
    /// Whether `input` matches this operator's configured parameter.
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool;
}

/// Named lists used by the `...FromDataset` operators.
pub type Datasets = BTreeMap<String, Vec<String>>;

/// Inputs needed when an operator reads a configured file or dataset.
#[derive(Debug, Clone, Copy)]
pub struct OperatorContext<'a> {
    /// Base directory for relative operator file paths.
    pub base_dir: &'a Path,
    /// Named operator datasets.
    pub datasets: &'a Datasets,
}

impl Default for OperatorContext<'_> {
    fn default() -> Self {
        static EMPTY_DATASETS: Datasets = BTreeMap::new();
        Self {
            base_dir: Path::new(""),
            datasets: &EMPTY_DATASETS,
        }
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by rule evaluation in a later port slice")
    )]
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
            _ => Err(format!("unknown operator: {name}")),
        }
    }

    /// Evaluate the selected operator.
    pub fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        match self {
            Self::Rx(operator) => operator.evaluate(tx, input, out),
            Self::RestPath(operator) => operator.evaluate(tx, input, out),
            Self::Pm(operator) => operator.evaluate(tx, input, out),
            Self::PmFromFile(operator) => operator.evaluate(tx, input, out),
            Self::PmFromDataset(operator) => operator.evaluate(tx, input, out),
            Self::StrMatch(operator) => operator.evaluate(tx, input, out),
            Self::Within(operator) => operator.evaluate(tx, input, out),
            Self::Eq(operator) => operator.evaluate(tx, input, out),
            Self::Lt(operator) => operator.evaluate(tx, input, out),
            Self::Le(operator) => operator.evaluate(tx, input, out),
            Self::Gt(operator) => operator.evaluate(tx, input, out),
            Self::Ge(operator) => operator.evaluate(tx, input, out),
            Self::StrEq(operator) => operator.evaluate(tx, input, out),
            Self::Contains(operator) => operator.evaluate(tx, input, out),
            Self::BeginsWith(operator) => operator.evaluate(tx, input, out),
            Self::EndsWith(operator) => operator.evaluate(tx, input, out),
            Self::DetectSQLi(operator) => operator.evaluate(tx, input, out),
            Self::DetectXSS(operator) => operator.evaluate(tx, input, out),
            Self::IpMatch(operator) => operator.evaluate(tx, input, out),
            Self::IpMatchFromFile(operator) => operator.evaluate(tx, input, out),
            Self::IpMatchFromDataset(operator) => operator.evaluate(tx, input, out),
            Self::ValidateByteRange(operator) => operator.evaluate(tx, input, out),
            Self::ValidateUrlEncoding(operator) => operator.evaluate(tx, input, out),
            Self::ValidateUtf8Encoding(operator) => operator.evaluate(tx, input, out),
            Self::ValidateNid(operator) => operator.evaluate(tx, input, out),
            Self::UnconditionalMatch(operator) => operator.evaluate(tx, input, out),
            Self::NoMatch(operator) => operator.evaluate(tx, input, out),
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "operator tests use fixed valid parameters")]
mod tests {
    use super::{Datasets, OperatorContext, OperatorEnum, Outputs};
    use crate::transaction::Transaction;

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
}
