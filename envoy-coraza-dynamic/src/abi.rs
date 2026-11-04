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

//! Native dynamic-module ABI and HTTP filter factory.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use envoy_coraza_common::{
    config::{Config, MAX_CONFIGURATION_BYTES},
    observability::Diagnostics,
    policy::Generation,
};
use envoy_proxy_dynamic_modules_rust_sdk::{
    declare_init_functions, EnvoyHttpFilter, EnvoyHttpFilterConfig, HttpFilterConfig,
};

use crate::{
    observability::{self, EnvoyDebugLogger},
    stream::FilterConfig,
};

declare_init_functions!(init, new_http_filter_config_fn);

/// Next ID assigned to successfully compiled native policy generations.
static NEXT_GENERATION_ID: AtomicU64 = AtomicU64::new(0);

/// Reports successful process initialization; policy state belongs to configurations.
fn init() -> bool {
    true
}

/// Parses and compiles the full policy generation before publishing native state.
fn new_http_filter_config_fn<EC: EnvoyHttpFilterConfig, EHF: EnvoyHttpFilter>(
    _envoy_filter_config: &mut EC,
    filter_name: &str,
    config_bytes: &[u8],
) -> Option<Box<dyn HttpFilterConfig<EHF>>> {
    compile_config(filter_name, config_bytes).map(|config| {
        let boxed: Box<dyn HttpFilterConfig<EHF>> = Box::new(config);
        boxed
    })
}

/// Validates, compiles and packages one native filter configuration.
fn compile_config(filter_name: &str, config_bytes: &[u8]) -> Option<FilterConfig> {
    if filter_name != "coraza" {
        envoy_proxy_dynamic_modules_rust_sdk::envoy_log_warn!("envoy-coraza-dynamic: unknown filter name");
        return None;
    }
    if config_bytes.len() > MAX_CONFIGURATION_BYTES {
        envoy_proxy_dynamic_modules_rust_sdk::envoy_log_warn!(
            "envoy-coraza-dynamic: configuration exceeds the {MAX_CONFIGURATION_BYTES}-byte limit"
        );
        return None;
    }
    let config = match Config::parse(config_bytes) {
        Ok(config) => config,
        Err(error) => {
            envoy_proxy_dynamic_modules_rust_sdk::envoy_log_error!("envoy-coraza-dynamic: {error}");
            return None;
        },
    };
    let diagnostics = Arc::new(Diagnostics::default());
    let mut generation = match Generation::compile_with_debug_logger(
        config,
        Arc::clone(&diagnostics),
        observability::error_log,
        observability::audit_log,
        Arc::new(EnvoyDebugLogger),
    ) {
        Ok(generation) => generation,
        Err(error) => {
            envoy_proxy_dynamic_modules_rust_sdk::envoy_log_error!("envoy-coraza-dynamic: {error}");
            return None;
        },
    };
    let Some(generation_id) = NEXT_GENERATION_ID
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| current.checked_add(1))
        .ok()
        .and_then(|current| current.checked_add(1))
    else {
        envoy_proxy_dynamic_modules_rust_sdk::envoy_log_error!("envoy-coraza-dynamic: generation id exhausted");
        return None;
    };
    generation.set_id(generation_id);
    for warning in generation.warnings() {
        envoy_proxy_dynamic_modules_rust_sdk::envoy_log_warn!("{warning}");
    }
    Some(FilterConfig::new(Arc::new(generation)))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Configuration tests use fixed valid fixtures.")]
mod tests {
    use envoy_coraza_common::config::MAX_CONFIGURATION_BYTES;
    use envoy_proxy_dynamic_modules_rust_sdk::{HttpFilterConfig as _, MockEnvoyHttpFilter};

    use super::compile_config;

    #[test]
    fn factory_rejects_unknown_name_invalid_json_and_oversize_config() {
        assert!(compile_config("unknown", b"{}").is_none());
        assert!(compile_config("coraza", b"not-json").is_none());
        assert!(compile_config("coraza", &[b' '; MAX_CONFIGURATION_BYTES + 1]).is_none());
        let config = compile_config("coraza", b"{}").unwrap();
        let mut host = MockEnvoyHttpFilter::default();
        let _filter = config.new_http_filter(&mut host);
    }

    #[test]
    fn generation_compilation_errors_reject_the_configuration() {
        assert!(compile_config(
            "coraza",
            br#"{"directives_map":{"p":["SecNotADirective x"]},"default_directives":"p"}"#,
        )
        .is_none());
    }
}
