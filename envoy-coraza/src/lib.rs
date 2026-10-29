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

// Production builds forbid unsafe code outright; the cfg(test) Proxy-Wasm hostcall stubs in
// test_hostcalls.rs need the (attribute-level) no_mangle escape, so test builds fall back to
// the workspace deny and allow it inside that one module.
#![cfg_attr(not(test), forbid(unsafe_code))]
#![expect(missing_docs, reason = "The Proxy-Wasm SDK generates the Wasm ABI entry point.")]
//! Envoy's Proxy-Wasm HTTP filter backed by the `coraza` engine.
//!
//! The filter compiles immutable policy generations, pins one to each stream,
//! enforces request and response phases, and finalizes one transaction per stream.
//! Terminal data, filter-state properties, and selected audit records
//! are published through checked Proxy-Wasm hostcalls.

mod config;
mod observability;
mod policy;
mod stream;
#[cfg(test)]
mod test_hostcalls;

use std::{cell::Cell, rc::Rc};

use config::Config;
use policy::Generation;
use proxy_wasm::{
    hostcalls,
    traits::{Context, HttpContext, RootContext},
    types::{BufferType, ContextType, LogLevel},
};
use stream::CorazaHttp;

/// Largest plugin configuration, in bytes, one `on_configure` call accepts.
///
/// `serde` cannot produce more directive text than the document's own bytes, so
/// this single bound covers both the document and the directives it carries.
const MAX_CONFIGURATION_BYTES: usize = 8 * 1024 * 1024;

proxy_wasm::main! {{
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(CorazaRoot {
            generation: None,
            retained_bytes: Rc::new(Cell::new(0)),
            next_generation_id: 0,
        })
    });
}}

/// Root context: compiles the plugin configuration and serves stream contexts.
struct CorazaRoot {
    /// Generation compiled by the most recent successful `on_configure`.
    ///
    /// Kept on the root context rather than in a module-global so that two
    /// plugins sharing one VM cannot see each other's policies.
    generation: Option<Rc<Generation>>,
    /// Per-root retained-body accounting shared with streams created by this root.
    retained_bytes: Rc<Cell<usize>>,
    /// Monotonic identifier assigned only to successful configuration generations.
    next_generation_id: u64,
}

impl CorazaRoot {
    /// Parses, compiles and installs a configuration.
    ///
    /// The generation is replaced only after a successful compile, so a rejected
    /// reload keeps the active generation serving its streams.
    fn apply(&mut self, bytes: &[u8]) -> Result<(), String> {
        let config = Config::parse(bytes).map_err(|error| error.to_string())?;
        let next_id = self
            .next_generation_id
            .checked_add(1)
            .ok_or_else(|| "configuration generation id exhausted".to_owned())?;
        let mut generation = Generation::compile(config).map_err(|error| error.to_string())?;
        generation.set_id(next_id);
        self.generation = Some(Rc::new(generation));
        self.next_generation_id = next_id;
        Ok(())
    }

    /// The generation installed by the most recent successful configuration.
    fn current_generation(&self) -> Option<Rc<Generation>> {
        self.generation.clone()
    }

    /// Builds the stream context that pins the current generation.
    fn http_context(&self) -> CorazaHttp {
        CorazaHttp::new(self.current_generation(), Rc::clone(&self.retained_bytes))
    }
}

impl Context for CorazaRoot {}

impl RootContext for CorazaRoot {
    /// Registers this plugin as an HTTP filter.
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    /// Compiles the plugin configuration, rejecting it on any error.
    ///
    /// Returning `false` makes Envoy reject the configuration, which is the only
    /// supported way to refuse an invalid policy set or update.
    fn on_configure(&mut self, plugin_configuration_size: usize) -> bool {
        if let Err(error) = check_configuration_size(plugin_configuration_size) {
            log_error(&error);
            return false;
        }
        // A successful hostcall with no buffer means Envoy supplied no plugin configuration.
        let configuration = match hostcalls::get_buffer(BufferType::PluginConfiguration, 0, usize::MAX) {
            Ok(configuration) => configuration.unwrap_or_default(),
            Err(status) => {
                log_error(&format!(
                    "envoy-coraza: cannot read the plugin configuration: {status:?}"
                ));
                return false;
            },
        };
        if let Err(error) = check_configuration_size(configuration.len()) {
            log_error(&error);
            return false;
        }
        match self.apply(&configuration) {
            Ok(()) => {
                #[cfg(feature = "embed-crs")]
                log_info(&format!(
                    "envoy-coraza: embedded CRS {} files available to Include",
                    policy::embedded_crs::EMBEDDED_CRS_VERSION
                ));
                if let Some(generation) = &self.generation {
                    for warning in generation.warnings() {
                        log_warn(warning);
                    }
                }
                true
            },
            Err(error) => {
                log_error(&format!("envoy-coraza: rejected plugin configuration: {error}"));
                false
            },
        }
    }

    /// Pins the current generation for one stream.
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(self.http_context()))
    }
}

/// Rejects a configuration over [`MAX_CONFIGURATION_BYTES`].
fn check_configuration_size(size: usize) -> Result<(), String> {
    if size > MAX_CONFIGURATION_BYTES {
        return Err(format!(
            "plugin configuration is {size} bytes, over the {MAX_CONFIGURATION_BYTES}-byte limit"
        ));
    }
    Ok(())
}

/// Writes one line to the Envoy log; a failed hostcall has no other report path.
fn log_error(message: &str) {
    hostcalls::log(LogLevel::Error, message).unwrap_or_default();
}

/// Writes one configure-time warning to the Envoy log.
fn log_warn(message: &str) {
    hostcalls::log(LogLevel::Warn, message).unwrap_or_default();
}

/// Writes one informational line to the Envoy log.
#[cfg(feature = "embed-crs")]
fn log_info(message: &str) {
    hostcalls::log(LogLevel::Info, message).unwrap_or_default();
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Configuration tests use fixed fixtures."
)]
/// Configuration publishing tests.
mod tests {
    use std::rc::Rc;

    use super::{check_configuration_size, CorazaRoot, MAX_CONFIGURATION_BYTES};

    /// A root context with no configuration applied yet.
    fn root() -> CorazaRoot {
        CorazaRoot {
            generation: None,
            retained_bytes: Rc::new(std::cell::Cell::new(0)),
            next_generation_id: 0,
        }
    }

    /// The rule id a generation's selected policy reports for `/attack`.
    fn interrupting_rule(root: &CorazaRoot, authority: &str) -> i32 {
        let generation = root.current_generation().expect("a generation is published");
        let policy = generation.select(authority).expect("a policy is selected");
        let mut transaction = policy.waf.new_transaction();
        transaction.process_uri("/attack", "GET", "HTTP/1.1");
        transaction
            .process_request_headers()
            .expect("the configured rule interrupts")
            .rule_id
    }

    #[test]
    fn an_accepted_configuration_becomes_the_current_generation() {
        let mut root = root();
        root.apply(br#"{"directives_map": {"p": []}, "default_directives": "p"}"#)
            .expect("configuration is valid");
        assert!(
            root.current_generation()
                .is_some_and(|generation| generation.select("a.example").is_some()),
            "the accepted generation is published for streams"
        );
    }

    #[test]
    fn a_rejected_configuration_keeps_the_previous_generation() {
        let mut root = root();
        root.apply(br#"{"directives_map": {"p": []}, "default_directives": "p"}"#)
            .expect("configuration is valid");
        let rejected = root.apply(br#"{"directives_map": {"p": ["SecNotADirective x"]}}"#);
        assert!(rejected.is_err(), "an invalid policy is rejected");
        assert!(
            root.current_generation()
                .is_some_and(|generation| generation.select("a.example").is_some()),
            "the rejected reload leaves the active generation in place"
        );
    }

    #[test]
    fn two_root_contexts_do_not_share_generations() {
        let mut first = root();
        let mut second = root();
        first
            .apply(br#"{"directives_map": {"p": []}, "default_directives": "p"}"#)
            .expect("configuration is valid");
        assert!(
            second.current_generation().is_none(),
            "a second plugin has its own state"
        );
        second
            .apply(br#"{"directives_map": {"q": []}}"#)
            .expect("configuration is valid");
        assert!(
            first
                .current_generation()
                .is_some_and(|generation| generation.select("a.example").is_some()),
            "the second plugin's configuration does not replace the first's"
        );
    }

    #[test]
    fn a_valid_reload_replaces_the_generation() {
        let mut root = root();
        root.apply(
            br#"{
                "directives_map": {"p": ["SecRule REQUEST_URI \"@contains attack\" \"id:1,phase:1,deny,status:403\""]},
                "default_directives": "p"
            }"#,
        )
        .expect("the first configuration is valid");
        assert_eq!(interrupting_rule(&root, "a.example"), 1, "the first rule fires");

        root.apply(
            br#"{
                "directives_map": {"q": ["SecRule REQUEST_URI \"@contains attack\" \"id:2,phase:1,deny,status:403\""]},
                "default_directives": "q"
            }"#,
        )
        .expect("the reload is valid");
        assert_eq!(
            interrupting_rule(&root, "a.example"),
            2,
            "the reload replaced the generation"
        );
    }

    #[test]
    fn a_stream_keeps_the_generation_it_started_with_across_a_reload() {
        let mut root = root();
        root.apply(
            br#"{
                "directives_map": {"old": ["SecRule REQUEST_URI \"@contains attack\" \"id:11,phase:1,deny,status:403\""]},
                "default_directives": "old"
            }"#,
        )
        .expect("the first configuration is valid");
        let pinned = root.http_context();

        root.apply(
            br#"{
                "directives_map": {"new": ["SecRule REQUEST_URI \"@contains attack\" \"id:22,phase:1,deny,status:403\""]},
                "default_directives": "new"
            }"#,
        )
        .expect("the reload is valid");

        let pinned = pinned.pinned_generation().expect("the stream pinned a generation");
        assert!(
            !Rc::ptr_eq(
                &pinned,
                &root.current_generation().expect("the reload published a generation")
            ),
            "the reload published a different generation"
        );
        let policy = pinned.select("a.example").expect("the pinned generation still selects");
        let mut transaction = policy.waf.new_transaction();
        transaction.process_uri("/attack", "GET", "HTTP/1.1");
        assert_eq!(
            transaction
                .process_request_headers()
                .expect("the pinned rule interrupts")
                .rule_id,
            11,
            "the stream keeps its original policy"
        );

        assert_eq!(interrupting_rule(&root, "a.example"), 22, "new streams use the reload");
    }

    #[test]
    fn a_scalar_directives_map_value_is_enforced_end_to_end() {
        let mut root = root();
        root.apply(
            br#"{
                "directives_map": {
                    "p": "SecRule REQUEST_URI \"@contains attack\" \"id:7,phase:1,deny,status:403\""
                },
                "default_directives": "p"
            }"#,
        )
        .expect("a scalar policy value is one directive");
        assert_eq!(
            interrupting_rule(&root, "a.example"),
            7,
            "the scalar directive is enforced, not dropped"
        );
    }

    #[test]
    fn legacy_rules_config_is_rejected_instead_of_failing_open() {
        let mut root = root();
        let error = root
            .apply(
                br#"{
                "rules": "SecRule REQUEST_URI \"@contains attack\" \"id:8,phase:1,deny,status:403\""
            }"#,
            )
            .unwrap_err();
        assert_eq!(
            error,
            "rules is no longer supported; use directives_map and default_directives"
        );
        assert!(
            root.current_generation().is_none(),
            "no empty pass-through generation was installed"
        );
    }

    #[test]
    fn an_empty_configuration_warns_that_requests_are_uninspected() {
        let mut root = root();
        root.apply(b"{}").expect("an empty configuration is valid");
        let generation = root.current_generation().expect("a generation is published");
        assert!(
            generation
                .warnings()
                .any(|warning| warning.contains("no policies configured")),
            "warnings were {:?}",
            generation.warnings().collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_non_scalar_policy_directive_is_rejected_not_silently_empty() {
        let mut root = root();
        let error = root
            .apply(
                br#"{
                    "directives_map": {
                        "p": [["SecRule REQUEST_URI \"@contains attack\" \"id:9,phase:1,deny,status:403\""]]
                    },
                    "default_directives": "p"
                }"#,
            )
            .unwrap_err();
        assert!(
            error.contains("directives_map policy \"p\" element 0 must be a scalar"),
            "message was {error:?}"
        );
        assert!(
            root.current_generation().is_none(),
            "a policy with zero rules was not installed"
        );
    }

    #[test]
    fn the_configuration_bound_accepts_the_edge_and_rejects_one_more() {
        assert!(
            check_configuration_size(MAX_CONFIGURATION_BYTES).is_ok(),
            "exactly {MAX_CONFIGURATION_BYTES} bytes are accepted"
        );
        let error = check_configuration_size(MAX_CONFIGURATION_BYTES + 1).unwrap_err();
        assert!(
            error.contains(&format!("{MAX_CONFIGURATION_BYTES}-byte limit")),
            "message was {error:?}"
        );
    }
}
