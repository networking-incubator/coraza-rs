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

//! Native-test stand-ins for the Proxy-Wasm hostcall imports.
//!
//! `cargo test` links this `cdylib` crate into a native lib-test harness, but the Proxy-Wasm
//! SDK declares its hostcalls as `extern "C"` imports that only a Proxy-Wasm host provides.
//! These `#[no_mangle]` definitions satisfy the native linker with stubs that report
//! `Status::NotFound`, the same checked failure the previous out-of-repo
//! `/tmp/envoy-coraza-test-hostcalls.o` shim returned, so no test fabricates host data.
//! The signatures mirror the SDK's `extern "C"` blocks exactly; the WASM build is
//! unaffected because this module is `#[cfg(test)]`-gated. Buffers, maps, and properties
//! are reported missing rather than fabricated, so no stub ever hands the SDK bytes to
//! `Vec::from_raw_parts`. The stubs satisfy the native linker; they are not a test host.

// no_mangle is an attribute-level escape from the crate's unsafe-code guard; there are no
// unsafe blocks and no pointer dereferences in this module.
#![expect(unsafe_code, reason = "test-only hostcall stubs export symbols via no_mangle")]

use proxy_wasm::types::{BufferType, LogLevel, MapType, Status};

#[no_mangle]
extern "C" fn proxy_log(_level: LogLevel, _message_data: *const u8, _message_size: usize) -> Status {
    Status::NotFound
}

#[no_mangle]
extern "C" fn proxy_get_buffer_bytes(
    _buffer_type: BufferType,
    _start: usize,
    _max_size: usize,
    _return_buffer_data: *mut *mut u8,
    _return_buffer_size: *mut usize,
) -> Status {
    Status::NotFound
}

#[no_mangle]
extern "C" fn proxy_set_buffer_bytes(
    _buffer_type: BufferType,
    _start: usize,
    _size: usize,
    _buffer_data: *const u8,
    _buffer_size: usize,
) -> Status {
    Status::NotFound
}

#[no_mangle]
extern "C" fn proxy_get_header_map_pairs(
    _map_type: MapType,
    _return_map_data: *mut *mut u8,
    _return_map_size: *mut usize,
) -> Status {
    Status::NotFound
}

#[no_mangle]
extern "C" fn proxy_set_header_map_pairs(_map_type: MapType, _map_data: *const u8, _map_size: usize) -> Status {
    Status::NotFound
}

#[no_mangle]
extern "C" fn proxy_send_local_response(
    _status_code: u32,
    _status_code_details_data: *const u8,
    _status_code_details_size: usize,
    _body_data: *const u8,
    _body_size: usize,
    _headers_data: *const u8,
    _headers_size: usize,
    _grpc_status: i32,
) -> Status {
    Status::NotFound
}

#[no_mangle]
extern "C" fn proxy_get_property(
    _path_data: *const u8,
    _path_size: usize,
    _return_value_data: *mut *mut u8,
    _return_value_size: *mut usize,
) -> Status {
    Status::NotFound
}

#[no_mangle]
extern "C" fn proxy_set_property(
    _path_data: *const u8,
    _path_size: usize,
    _value_data: *const u8,
    _value_size: usize,
) -> Status {
    Status::NotFound
}

#[cfg(test)]
mod tests {
    use super::{proxy_log, proxy_set_property, LogLevel, Status};

    #[test]
    fn stubs_report_a_checked_missing_host_instead_of_succeeding() {
        assert_eq!(
            proxy_log(LogLevel::Info, std::ptr::null(), 0),
            Status::NotFound,
            "a stub must not pretend the host accepted the log"
        );
        assert_eq!(
            proxy_set_property(std::ptr::null(), 0, std::ptr::null(), 0),
            Status::NotFound,
            "a stub must not pretend the host stored a property"
        );
    }
}
