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

//! The `@rbl` operator: look an address up in a DNS blocklist.
//!
//! Ported from `internal/operators/rbl.go` in Coraza v3.8.1. The query name is
//! `<value>.<service>`, exactly as Go builds it with
//! `fmt.Sprintf("%s.%s", ipAddr, o.service)`: the address is neither reversed
//! nor normalised, so an IPv6 value yields a name a blocklist does not publish.
//! The lookup is bounded by Go's 500ms deadline and any failure is no match.
//!
//! Go then looks up the address's TXT record, stores its first entry in
//! `TX.httpbl_msg`, copies it into capture 0, and reports no match when the TXT
//! lookup fails. This port has no DNS dependency, so it performs the A/AAAA
//! lookup only: the TXT message and its capture are absent, and an address with
//! a record but no TXT entry matches here where Go would not.

use std::{net::ToSocketAddrs as _, sync::mpsc, time::Duration};

use crate::{
    operators::{Operator, Outputs},
    transaction::Transaction,
};

/// Go's `500 * time.Millisecond` budget for the whole lookup in `rbl.go`.
const LOOKUP_TIMEOUT: Duration = Duration::from_millis(500);

/// Looks an inspected value up in a DNS blocklist.
#[derive(Debug, Clone)]
pub struct Rbl {
    /// Blocklist zone appended to the value, e.g. `sbl.spamhaus.org`.
    service: String,
}

impl Rbl {
    /// Create an operator that queries `service`.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty service. Go builds `<value>.` for it and
    /// relies on the TXT lookup to reject that self-resolving name; without the
    /// TXT lookup this port would report a match, so it rejects the service.
    pub fn new(service: &str) -> Result<Self, String> {
        if service.is_empty() {
            return Err("missing rbl service".to_owned());
        }
        Ok(Self {
            service: service.to_owned(),
        })
    }

    /// The blocklist query name for `address`, verbatim as in Go.
    fn query_name(&self, address: &str) -> String {
        format!("{address}.{}", self.service)
    }
}

impl Operator for Rbl {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let name = self.query_name(&String::from_utf8_lossy(input));
        // Go's `LookupHost` returns every A and AAAA record and errors when the
        // name has none; `ToSocketAddrs` is the same getaddrinfo lookup.
        bounded(LOOKUP_TIMEOUT, move || {
            (name.as_str(), 0)
                .to_socket_addrs()
                .is_ok_and(|mut addresses| addresses.next().is_some())
        })
        .unwrap_or(false)
    }
}

/// Creates a new `rbl` operator.
///
/// # Errors
///
/// Returns an error for an empty service; see [`Rbl::new`].
pub fn rbl(service: &str) -> Result<Rbl, String> {
    Rbl::new(service)
}

/// Run `work` on a worker thread and give up after `timeout`.
///
/// The resolver has no cancellation, so a lookup that overruns the deadline is
/// abandoned: its thread lives until the system resolver returns.
fn bounded<T: Send + 'static>(timeout: Duration, work: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        // A timeout drops the receiver, and the result is unusable then.
        drop(sender.send(work()));
    });
    receiver.recv_timeout(timeout).ok()
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "rbl tests use fixed service names")]
mod tests {
    use std::time::Duration;

    use super::{Rbl, bounded};
    use crate::{
        operators::{Operator as _, OperatorContext, OperatorEnum, Outputs},
        transaction::Transaction,
    };

    fn operator(service: &str) -> Rbl {
        Rbl::new(service).unwrap()
    }

    fn operator_result(service: &str) -> Result<(), String> {
        Rbl::new(service).map(|_rbl| ())
    }

    #[test]
    fn query_name_puts_the_address_before_the_service() {
        let rbl = operator("zen.spamhaus.org");
        assert_eq!(rbl.query_name("192.0.2.1"), "192.0.2.1.zen.spamhaus.org");
    }

    #[test]
    fn ipv6_addresses_are_not_reversed() {
        // Go's `fmt.Sprintf("%s.%s", ipAddr, service)` keeps the address as is,
        // so the nibble-reversed form a blocklist publishes is never produced.
        let rbl = operator("zen.spamhaus.org");
        assert_eq!(rbl.query_name("2001:db8::1"), "2001:db8::1.zen.spamhaus.org");
    }

    #[test]
    fn malformed_addresses_are_queried_verbatim() {
        // Go leaves address validation as a TODO, so the value is not checked.
        let rbl = operator("zen.spamhaus.org");
        assert_eq!(rbl.query_name("not-an-ip"), "not-an-ip.zen.spamhaus.org");
    }

    #[test]
    fn an_empty_service_is_rejected() {
        assert_eq!(operator_result(""), Err("missing rbl service".to_owned()));
        assert_eq!(operator_result("   "), Ok(()));
    }

    #[test]
    fn a_lookup_that_overruns_the_budget_is_no_match() {
        assert_eq!(
            bounded(Duration::from_millis(20), || {
                std::thread::sleep(Duration::from_millis(200));
                true
            }),
            None
        );
        assert_eq!(bounded(Duration::from_secs(1), || false), Some(false));
    }

    #[test]
    fn an_unresolvable_name_is_no_match() {
        // A NUL byte cannot be part of a resolver request, so this fails without
        // reaching the network.
        let rbl = operator("zen.spamhaus.org");
        assert!(!rbl.evaluate(&Transaction::new("rbl"), b"192.0.2.1\0", &mut Outputs::default()));
    }

    #[test]
    fn the_operator_is_registered_under_its_name() {
        assert!(matches!(
            OperatorEnum::with_context("rbl", "zen.spamhaus.org", &OperatorContext::default()),
            Ok(OperatorEnum::Rbl(_))
        ));
        assert!(OperatorEnum::with_context("rbl", "", &OperatorContext::default()).is_err());
    }
}
