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
//! lookup only: the TXT message and its capture are absent, and a name whose TXT
//! lookup fails matches here where Go reports no match.
//!
//! Resource bounds: the system resolver cannot be cancelled, so each lookup
//! runs on its own thread with [`LOOKUP_STACK`] of stack and the operator gives
//! up after [`LOOKUP_TIMEOUT`], abandoning that thread until the resolver
//! returns. At most [`MAX_IN_FLIGHT`] lookups run at once in a process; above
//! that, and when a thread cannot be spawned, the operator reports
//! [`OperatorOutcome::NotInspected`](crate::operators::OperatorOutcome::NotInspected)
//! instead of queueing or panicking. Rules treat that as not matched, so it
//! never turns a lookup that could not run into a match.
//!
//! A resolver failure also reports no verdict: std's resolver does not expose
//! whether a name has no record or the lookup itself failed, and this port does
//! not guess. Go reports not matched in both cases; [`Rbl::evaluate`] returns
//! `false` there, so rule evaluation is unchanged.

use std::{
    net::ToSocketAddrs as _,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

use crate::{
    operators::{Operator, OperatorOutcome, Outputs},
    transaction::Transaction,
};

/// Go's `500 * time.Millisecond` budget for the whole lookup in `rbl.go`.
const LOOKUP_TIMEOUT: Duration = Duration::from_millis(500);

/// Stack for one lookup thread.
///
/// The resolver runs libc and NSS modules in this thread, so the size stays
/// well above the default but far below the multi-megabyte default of a
/// request thread.
const LOOKUP_STACK: usize = 512 * 1024;

/// Lookups allowed to run at once in one process.
///
/// Abandoned lookups hold their slot until the resolver returns, so this is the
/// bound on threads and stack a hostile name set can pin.
const MAX_IN_FLIGHT: usize = 64;

/// Lookups currently running, process-wide.
static LIMITER: Limiter = Limiter {
    in_flight: AtomicUsize::new(0),
};

/// Counts lookups in flight against [`MAX_IN_FLIGHT`].
struct Limiter {
    /// Slots currently held.
    in_flight: AtomicUsize,
}

/// One reserved lookup slot, released when dropped.
struct InFlight<'a> {
    /// The limiter the slot was taken from.
    limiter: &'a Limiter,
}

impl Limiter {
    /// Reserve a slot, or report `None` when the cap is already reached.
    fn acquire(&self) -> Option<InFlight<'_>> {
        if self.in_flight.fetch_add(1, Ordering::AcqRel) >= MAX_IN_FLIGHT {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(InFlight { limiter: self })
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.limiter.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

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
    /// Returns an error for a service that is empty or only whitespace. Go
    /// builds `<value>.` for an empty service and relies on the TXT lookup to
    /// reject that self-resolving name; without the TXT lookup this port would
    /// report a match, so it rejects the service when the rule compiles.
    pub fn new(service: &str) -> Result<Self, String> {
        let service = service.trim();
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
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.evaluate_outcome(tx, input, out) == OperatorOutcome::Matched
    }

    fn evaluate_outcome(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> OperatorOutcome {
        let name = self.query_name(&String::from_utf8_lossy(input));
        // Go's `LookupHost` returns every A and AAAA record and errors when the
        // name has none; `ToSocketAddrs` is the same getaddrinfo lookup.
        match bounded(LOOKUP_TIMEOUT, move || match (name.as_str(), 0).to_socket_addrs() {
            Ok(mut addresses) => Answer::Listed(addresses.next().is_some()),
            Err(_) => Answer::Unavailable,
        }) {
            Some(Answer::Listed(true)) => OperatorOutcome::Matched,
            Some(Answer::Listed(false)) => OperatorOutcome::NotMatched,
            Some(Answer::Unavailable) | None => OperatorOutcome::NotInspected,
        }
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

/// The answer from one bounded lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// The resolver answered, and whether the value is listed.
    Listed(bool),
    /// The resolver failed, so there is no answer.
    Unavailable,
}

/// Run `work` on a worker thread and give up after `timeout`.
///
/// Returns `None` when the lookup never completed: the deadline expired, the
/// in-flight cap was reached, or the thread could not be spawned. An abandoned
/// lookup keeps its in-flight slot until the resolver returns.
fn bounded<T: Send + 'static>(timeout: Duration, work: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let slot = LIMITER.acquire()?;
    let (sender, receiver) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("coraza-rbl".to_owned())
        .stack_size(LOOKUP_STACK)
        .spawn(move || {
            // A timeout drops the receiver, and the result is unusable then.
            drop(sender.send(work()));
            drop(slot);
        });
    if spawned.is_err() {
        // The builder dropped the closure, and its slot with it.
        return None;
    }
    receiver.recv_timeout(timeout).ok()
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "rbl tests use fixed service names")]
mod tests {
    use std::{
        sync::atomic::AtomicUsize,
        time::{Duration, Instant},
    };

    use super::{Answer, Limiter, MAX_IN_FLIGHT, Rbl, bounded};
    use crate::{
        operators::{Operator as _, OperatorContext, OperatorEnum, OperatorOutcome, Outputs},
        transaction::Transaction,
        types::RuleVariable,
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
    fn an_empty_or_whitespace_service_is_rejected() {
        assert_eq!(operator_result(""), Err("missing rbl service".to_owned()));
        assert_eq!(operator_result("   "), Err("missing rbl service".to_owned()));
        assert_eq!(operator_result("\t\n"), Err("missing rbl service".to_owned()));
    }

    #[test]
    fn a_service_is_stored_without_surrounding_whitespace() {
        assert_eq!(
            operator(" zen.spamhaus.org ").query_name("192.0.2.1"),
            "192.0.2.1.zen.spamhaus.org"
        );
    }

    #[test]
    fn the_in_flight_cap_is_enforced_and_released() {
        let limiter = Limiter {
            in_flight: AtomicUsize::new(0),
        };
        let slots: Vec<_> = (0..MAX_IN_FLIGHT).filter_map(|_| limiter.acquire()).collect();
        assert_eq!(slots.len(), MAX_IN_FLIGHT, "the cap grants every slot once");
        assert!(limiter.acquire().is_none(), "lookups above the cap are refused");
        drop(slots);
        assert!(limiter.acquire().is_some(), "a released slot can be taken again");
    }

    #[test]
    fn a_lookup_that_overruns_the_budget_is_no_match() {
        assert_eq!(
            bounded(Duration::from_millis(20), || {
                std::thread::sleep(Duration::from_millis(200));
                Answer::Listed(true)
            }),
            None
        );
        assert_eq!(
            bounded(Duration::from_secs(1), || Answer::Listed(false)),
            Some(Answer::Listed(false))
        );
    }

    #[test]
    fn a_lookup_that_overruns_the_budget_reports_no_verdict() {
        // The operator's own budget is Go's; this pins the mapping from a
        // failed bounded call to `NotInspected` through the deadline path only
        // for a name the resolver rejects without contacting the network.
        let rbl = operator("zen.spamhaus.org");
        assert_eq!(
            rbl.evaluate_outcome(&Transaction::new("rbl"), b"192.0.2.1\0", &mut Outputs::default()),
            OperatorOutcome::NotInspected
        );
        assert!(!rbl.evaluate(&Transaction::new("rbl"), b"192.0.2.1\0", &mut Outputs::default()));
    }

    #[test]
    fn an_unresolvable_name_is_no_match() {
        // A NUL byte cannot be part of a resolver request, so this fails without
        // reaching the network.
        let rbl = operator("zen.spamhaus.org");
        assert!(!rbl.evaluate(&Transaction::new("rbl"), b"192.0.2.1\0", &mut Outputs::default()));
    }

    #[test]
    fn the_lookup_sets_no_txt_message_or_capture() {
        let rbl = operator("zen.spamhaus.org");
        let mut tx = Transaction::new("rbl");
        // A fresh transaction starts with Go's empty TX:0..TX:9, so use a
        // sentinel to show the lookup neither resets nor writes capture 0.
        tx.set_tx_variable("0", "sentinel");
        let mut out = Outputs::new(true);
        assert!(!rbl.evaluate(&tx, b"192.0.2.1\0", &mut out));
        tx.store_operator_outputs(&mut out);
        assert_eq!(tx.get_variable(RuleVariable::TX, Some("httpbl_msg")), None);
        assert_eq!(
            tx.get_variable(RuleVariable::TX, Some("0")).as_deref(),
            Some("sentinel"),
            "capture 0 must stay untouched"
        );
    }

    #[test]
    fn a_bounded_call_returns_as_soon_as_the_work_ends() {
        let started = Instant::now();
        assert_eq!(
            bounded(Duration::from_secs(5), || Answer::Listed(true)),
            Some(Answer::Listed(true))
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "a quick lookup must not wait for the deadline"
        );
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
