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
//! These `#[no_mangle]` definitions satisfy the native linker; they are not a test host.
//!
//! Upstream `proxy-wasm` 0.2.5 panics on any status its wrapper does not model, so each stub
//! returns the one status the matching wrapper tolerates:
//!
//! - the write hostcalls behind `log`, `set_buffer`, `set_map`, `set_map_bytes`, `set_property`, and
//!   `send_http_response` accept only `Status::Ok` and panic on everything else, so those stubs report `Status::Ok`;
//! - `get_map` and `get_map_bytes` likewise accept only `Status::Ok`, and read an empty map from the null out-pointer
//!   the SDK initializes before the call;
//! - `get_buffer` and `get_property` map `Status::NotFound` to "absent", so those stubs keep reporting
//!   `Status::NotFound`.
//!
//! No stub writes through an out-pointer, so the SDK keeps the `null` it initialized and never
//! reaches `Vec::from_raw_parts`: buffers, maps, and properties stay missing or empty rather than
//! fabricated. `Status::Ok` from a write stub only means the call was accepted; no stub ever hands
//! the SDK bytes, so no test fabricates host data. The signatures mirror the SDK's `extern "C"`
//! blocks exactly; the WASM build is unaffected because this module is `#[cfg(test)]`-gated.

// no_mangle is an attribute-level escape from the crate's unsafe-code guard; there are no
// unsafe blocks and no pointer dereferences in this module.
#![expect(unsafe_code, reason = "test-only hostcall stubs export symbols via no_mangle")]

use proxy_wasm::types::{BufferType, LogLevel, MapType, Status};

#[no_mangle]
extern "C" fn proxy_log(_level: LogLevel, _message_data: *const u8, _message_size: usize) -> Status {
    Status::Ok
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
    Status::Ok
}

// `get_map` and `get_map_bytes` have no `Status::NotFound` arm; leaving the out-parameters
// untouched keeps the SDK's own null pointer, which it reads as an empty map.
#[no_mangle]
extern "C" fn proxy_get_header_map_pairs(
    _map_type: MapType,
    _return_map_data: *mut *mut u8,
    _return_map_size: *mut usize,
) -> Status {
    Status::Ok
}

#[no_mangle]
extern "C" fn proxy_set_header_map_pairs(_map_type: MapType, _map_data: *const u8, _map_size: usize) -> Status {
    Status::Ok
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
    Status::Ok
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
    Status::Ok
}

#[cfg(test)]
mod tests {
    use proxy_wasm::{
        hostcalls,
        types::{BufferType, LogLevel, MapType},
    };

    #[test]
    fn write_stubs_return_the_only_status_the_sdk_accepts() {
        // Each wrapper panics instead of returning an error for any status but `Status::Ok`, so a
        // stub that reported a failure would abort the calling test rather than be handled.
        assert_eq!(
            hostcalls::log(LogLevel::Info, "stub"),
            Ok(()),
            "the log stub is accepted"
        );
        assert_eq!(
            hostcalls::set_buffer(BufferType::HttpResponseBody, 0, 0, b""),
            Ok(()),
            "the buffer stub is accepted"
        );
        assert_eq!(
            hostcalls::set_map(MapType::HttpResponseHeaders, Vec::new()),
            Ok(()),
            "the header-map stub is accepted"
        );
        assert_eq!(
            hostcalls::set_property(vec!["io.coraza.waf.stub"], Some(b"stub".as_slice())),
            Ok(()),
            "the property stub is accepted"
        );
        assert_eq!(
            hostcalls::send_http_response(403, Vec::new(), None),
            Ok(()),
            "the local-response stub is accepted"
        );
    }

    #[test]
    fn read_stubs_report_a_missing_host_instead_of_fabricating_data() {
        assert_eq!(
            hostcalls::get_map(MapType::HttpRequestHeaders),
            Ok(Vec::new()),
            "a stub must not fabricate request headers"
        );
        assert_eq!(
            hostcalls::get_buffer(BufferType::HttpRequestBody, 0, usize::MAX),
            Ok(None),
            "a stub must not fabricate a request body"
        );
        assert_eq!(
            hostcalls::get_property(vec!["source", "address"]),
            Ok(None),
            "a stub must not fabricate a property"
        );
    }
}
