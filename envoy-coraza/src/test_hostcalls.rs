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
//! are reported missing unless a test scripts them.
//!
//! Several hostcalls are programmable per test thread, so a test can drive the filter without
//! fabricating anything it did not ask for: the plugin configuration buffer
//! ([`set_plugin_configuration`]), the request header and trailer maps and the response header map
//! ([`set_request_headers`], [`set_request_trailers`], [`set_response_headers`]), the request and response body buffers
//! ([`set_request_body`], [`set_response_body`]), a property value or failure ([`set_property`], [`fail_property`]),
//! and what the filter did: the status codes of local replies ([`local_reply_statuses`]), of response replacements
//! ([`response_replacement_statuses`]) and the filter-state properties it published ([`published_property`]).
//! Each test runs on its own thread, so the scripted state is isolated; call [`reset`] to
//! clear it explicitly. Everything else stays a fixed stub that reports `Status::NotFound`.

// no_mangle is an attribute-level escape from the crate's unsafe-code guard. The scripted
// host also needs two unsafe blocks, in `hand_out` and `proxy_get_property`, to read and
// write the SDK's FFI pointers; each carries its own SAFETY comment.
#![expect(
    unsafe_code,
    reason = "test-only hostcall stubs export symbols via no_mangle and exchange FFI pointers"
)]

use std::{cell::RefCell, collections::BTreeMap};

use proxy_wasm::types::{BufferType, LogLevel, MapType, Status};

/// The scripted host state of one test thread.
struct Host {
    /// Plugin configuration buffer, or `None` to report it missing.
    plugin_configuration: Option<Vec<u8>>,
    /// Request header map, or `None` to report it missing.
    request_headers: Option<Vec<(String, Vec<u8>)>>,
    /// Request body buffer, or `None` to report it missing.
    request_body: Option<Vec<u8>>,
    /// Request trailer map, or `None` to report it missing.
    request_trailers: Option<Vec<(String, Vec<u8>)>>,
    /// Response header map, or `None` to report it missing.
    response_headers: Option<Vec<(String, Vec<u8>)>>,
    /// Response body buffer, or `None` to report it missing.
    response_body: Option<Vec<u8>>,
    /// The `:status` of every response header map the filter set, in order.
    response_replacements: Vec<String>,
    /// Filter-state properties the filter published, by dotted path.
    published: BTreeMap<String, String>,
    /// Dotted property path to its scripted value or failure status.
    properties: BTreeMap<String, Result<Vec<u8>, Status>>,
    /// Status codes of the local replies the filter sent.
    local_replies: Vec<u32>,
}

thread_local! {
    static HOST: RefCell<Host> = const {
        RefCell::new(Host {
            plugin_configuration: None,
            request_headers: None,
            request_body: None,
            request_trailers: None,
            response_headers: None,
            response_body: None,
            response_replacements: Vec::new(),
            published: BTreeMap::new(),
            properties: BTreeMap::new(),
            local_replies: Vec::new(),
        })
    };
}

/// Clears everything scripted on this thread.
pub(crate) fn reset() {
    HOST.with_borrow_mut(|host| {
        host.plugin_configuration = None;
        host.request_headers = None;
        host.request_body = None;
        host.request_trailers = None;
        host.response_headers = None;
        host.response_body = None;
        host.response_replacements.clear();
        host.published.clear();
        host.properties.clear();
        host.local_replies.clear();
    });
}

/// Scripts the plugin configuration buffer, or its absence with `None`.
pub(crate) fn set_plugin_configuration(configuration: Option<&[u8]>) {
    HOST.with_borrow_mut(|host| host.plugin_configuration = configuration.map(<[u8]>::to_vec));
}

/// Scripts the request header map the host returns.
pub(crate) fn set_request_headers(headers: &[(&str, &[u8])]) {
    HOST.with_borrow_mut(|host| host.request_headers = Some(owned_map(headers)));
}

/// Scripts the request trailer map the host returns.
pub(crate) fn set_request_trailers(trailers: &[(&str, &[u8])]) {
    HOST.with_borrow_mut(|host| host.request_trailers = Some(owned_map(trailers)));
}

/// A header map the host owns.
fn owned_map(map: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
    map.iter()
        .map(|(name, value)| ((*name).to_owned(), value.to_vec()))
        .collect()
}

/// Scripts the request body buffer the host returns.
pub(crate) fn set_request_body(body: &[u8]) {
    HOST.with_borrow_mut(|host| host.request_body = Some(body.to_vec()));
}

/// Scripts the response header map the host returns.
pub(crate) fn set_response_headers(headers: &[(&str, &[u8])]) {
    HOST.with_borrow_mut(|host| host.response_headers = Some(owned_map(headers)));
}

/// Scripts the response body buffer the host returns.
pub(crate) fn set_response_body(body: &[u8]) {
    HOST.with_borrow_mut(|host| host.response_body = Some(body.to_vec()));
}

/// The `:status` of every response header map the filter has set so far, in order: the replacements it made.
pub(crate) fn response_replacement_statuses() -> Vec<String> {
    HOST.with_borrow(|host| host.response_replacements.clone())
}

/// What the filter published at the filter-state property `path`, such as `io.coraza.waf.v1.inspection_complete`.
pub(crate) fn published_property(path: &str) -> Option<String> {
    HOST.with_borrow(|host| host.published.get(path).cloned())
}

/// Scripts a property (dotted path, such as `source.address`) the host returns.
pub(crate) fn set_property(path: &str, value: &[u8]) {
    HOST.with_borrow_mut(|host| host.properties.insert(path.to_owned(), Ok(value.to_vec())));
}

/// Makes the host report a property missing again.
pub(crate) fn remove_property(path: &str) {
    HOST.with_borrow_mut(|host| host.properties.remove(path));
}

/// Scripts a hostcall failure for a property: the host answers `status` instead of a value.
pub(crate) fn fail_property(path: &str, status: Status) {
    HOST.with_borrow_mut(|host| host.properties.insert(path.to_owned(), Err(status)));
}

/// The status codes of every local reply sent so far, in order.
pub(crate) fn local_reply_statuses() -> Vec<u32> {
    HOST.with_borrow(|host| host.local_replies.clone())
}

/// Hands `data` to the SDK the way a host does: a heap allocation whose capacity equals its
/// length, which the SDK takes ownership of with `Vec::from_raw_parts`. Empty data is left
/// as the null pointer the SDK reads as an empty result.
fn hand_out(data: Vec<u8>, data_out: *mut *mut u8, size_out: *mut usize) {
    if data.is_empty() {
        return;
    }
    let size = data.len();
    let leaked = Box::leak(data.into_boxed_slice());
    // SAFETY: the SDK passes pointers to live locals for both out-parameters, and the leaked
    // boxed slice is exactly `size` bytes, as `Vec::from_raw_parts(ptr, size, size)` requires.
    unsafe {
        *data_out = leaked.as_mut_ptr();
        *size_out = size;
    }
}

/// Serializes a header map in the Proxy-Wasm wire format the SDK deserializes.
fn serialize_map(map: &[(String, Vec<u8>)]) -> Vec<u8> {
    let length = |len: usize| u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&length(map.len()));
    for (name, value) in map {
        bytes.extend_from_slice(&length(name.len()));
        bytes.extend_from_slice(&length(value.len()));
    }
    for (name, value) in map {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(value);
        bytes.push(0);
    }
    bytes
}

#[no_mangle]
extern "C" fn proxy_log(_level: LogLevel, _message_data: *const u8, _message_size: usize) -> Status {
    Status::NotFound
}

#[no_mangle]
extern "C" fn proxy_get_buffer_bytes(
    buffer_type: BufferType,
    start: usize,
    max_size: usize,
    return_buffer_data: *mut *mut u8,
    return_buffer_size: *mut usize,
) -> Status {
    let window = |body: &[u8]| {
        let end = start.saturating_add(max_size).min(body.len());
        body.get(start.min(end)..end).unwrap_or_default().to_vec()
    };
    let data = HOST.with_borrow(|host| match buffer_type {
        BufferType::PluginConfiguration => host.plugin_configuration.clone(),
        BufferType::HttpRequestBody => host.request_body.as_deref().map(window),
        BufferType::HttpResponseBody => host.response_body.as_deref().map(window),
        _ => None,
    });
    match data {
        Some(data) => {
            hand_out(data, return_buffer_data, return_buffer_size);
            Status::Ok
        },
        None => Status::NotFound,
    }
}

#[no_mangle]
extern "C" fn proxy_set_buffer_bytes(
    buffer_type: BufferType,
    _start: usize,
    _size: usize,
    _buffer_data: *const u8,
    _buffer_size: usize,
) -> Status {
    // A response replaced by the filter is scripted to succeed, so that the filter's reply can be observed.
    match buffer_type {
        BufferType::HttpResponseBody => Status::Ok,
        _ => Status::NotFound,
    }
}

#[no_mangle]
extern "C" fn proxy_get_header_map_pairs(
    map_type: MapType,
    return_map_data: *mut *mut u8,
    return_map_size: *mut usize,
) -> Status {
    let serialized = HOST.with_borrow(|host| match map_type {
        MapType::HttpRequestHeaders => host.request_headers.as_deref().map(serialize_map),
        MapType::HttpRequestTrailers => host.request_trailers.as_deref().map(serialize_map),
        MapType::HttpResponseHeaders => host.response_headers.as_deref().map(serialize_map),
        _ => None,
    });
    match serialized {
        Some(serialized) => {
            hand_out(serialized, return_map_data, return_map_size);
            Status::Ok
        },
        None => Status::NotFound,
    }
}

#[no_mangle]
extern "C" fn proxy_set_header_map_pairs(map_type: MapType, map_data: *const u8, map_size: usize) -> Status {
    match map_type {
        MapType::HttpResponseHeaders => {
            let status = if map_size == 0 {
                None
            } else {
                // SAFETY: the SDK passes the serialized map it owns for the duration of the call.
                let raw = unsafe { std::slice::from_raw_parts(map_data, map_size) };
                status_of(raw)
            };
            HOST.with_borrow_mut(|host| host.response_replacements.push(status.unwrap_or_default()));
            Status::Ok
        },
        MapType::HttpResponseTrailers => Status::Ok,
        _ => Status::NotFound,
    }
}

/// The `:status` value in a serialized header map, if it has one.
fn status_of(raw: &[u8]) -> Option<String> {
    let word = |at: usize| -> Option<usize> {
        let bytes: [u8; 4] = raw.get(at..at.checked_add(4)?)?.try_into().ok()?;
        usize::try_from(u32::from_le_bytes(bytes)).ok()
    };
    let count = word(0)?;
    let mut offset = 4_usize.checked_add(count.checked_mul(8)?)?;
    for index in 0..count {
        let name_len = word(4 + index * 8)?;
        let value_len = word(8 + index * 8)?;
        let name = raw.get(offset..offset.checked_add(name_len)?)?;
        offset = offset.checked_add(name_len)?.checked_add(1)?;
        let value = raw.get(offset..offset.checked_add(value_len)?)?;
        offset = offset.checked_add(value_len)?.checked_add(1)?;
        if name == b":status" {
            return Some(String::from_utf8_lossy(value).into_owned());
        }
    }
    None
}

#[no_mangle]
extern "C" fn proxy_send_local_response(
    status_code: u32,
    _status_code_details_data: *const u8,
    _status_code_details_size: usize,
    _body_data: *const u8,
    _body_size: usize,
    _headers_data: *const u8,
    _headers_size: usize,
    _grpc_status: i32,
) -> Status {
    HOST.with_borrow_mut(|host| host.local_replies.push(status_code));
    Status::NotFound
}

#[no_mangle]
extern "C" fn proxy_get_property(
    path_data: *const u8,
    path_size: usize,
    return_value_data: *mut *mut u8,
    return_value_size: *mut usize,
) -> Status {
    // SAFETY: the SDK passes the serialized property path it owns for the duration of the call.
    let raw = unsafe { std::slice::from_raw_parts(path_data, path_size) };
    let path = String::from_utf8_lossy(raw).replace('\0', ".");
    match HOST.with_borrow(|host| host.properties.get(&path).cloned()) {
        Some(Ok(value)) => {
            hand_out(value, return_value_data, return_value_size);
            Status::Ok
        },
        Some(Err(status)) => status,
        None => Status::NotFound,
    }
}

#[no_mangle]
extern "C" fn proxy_set_property(
    path_data: *const u8,
    path_size: usize,
    value_data: *const u8,
    value_size: usize,
) -> Status {
    // Published values are remembered for the tests to read, and the host still reports the property missing.
    if path_size > 0 && value_size > 0 {
        // SAFETY: the SDK passes the serialized path and the value it owns for the duration of the call.
        let (path, value) = unsafe {
            (
                std::slice::from_raw_parts(path_data, path_size),
                std::slice::from_raw_parts(value_data, value_size),
            )
        };
        let path = String::from_utf8_lossy(path).replace('\0', ".");
        let value = String::from_utf8_lossy(value).into_owned();
        HOST.with_borrow_mut(|host| host.published.insert(path, value));
    }
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
