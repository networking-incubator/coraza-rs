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

//! Minimal native test host symbols for SDK logging used by `CatchUnwind`.
//!
//! Dynamic-module callbacks remain unresolved in production and are provided by Envoy. The unit
//! test executable only needs these two symbols; logging is disabled so the stubs never inspect
//! the ABI buffers.
#![expect(unsafe_code, reason = "test-only no_mangle stubs satisfy the SDK ABI linker")]

use envoy_proxy_dynamic_modules_rust_sdk::abi::{
    envoy_dynamic_module_type_log_level, envoy_dynamic_module_type_module_buffer,
};

#[no_mangle]
extern "C" fn envoy_dynamic_module_callback_log_enabled(_level: envoy_dynamic_module_type_log_level) -> bool {
    false
}

#[no_mangle]
extern "C" fn envoy_dynamic_module_callback_log_v2(
    _level: envoy_dynamic_module_type_log_level,
    _message: envoy_dynamic_module_type_module_buffer,
    _source_file: envoy_dynamic_module_type_module_buffer,
    _source_line: u32,
) {
}
