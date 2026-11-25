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
//! and what the filter did: log calls it attempted ([`log_messages`]), local replies it sent ([`local_replies`],
//! [`local_reply_statuses`]) and filter-state properties it published ([`published_property`]). Each test runs on its
//! own thread, so the scripted state is isolated; call [`reset`] to clear it explicitly. A local reply is recorded and
//! then refused with `Status::NotFound`, so every test also covers a host that cannot send it. The filter answers a
//! response it refuses with a local reply and never rewrites one in place: replacing the response body, headers or
//! trailers is recorded, and the test fails on the next read of any recorded output (a stub cannot panic, since it is
//! `extern "C"`). Everything else stays a fixed stub that reports `Status::NotFound`.

// no_mangle is an attribute-level escape from the crate's unsafe-code guard. The scripted
// host also needs unsafe blocks to read and write the SDK's FFI pointers; each carries its
// own SAFETY comment.
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
    /// Filter-state properties the filter published, by dotted path.
    published: BTreeMap<String, String>,
    /// Dotted property path to its scripted value or failure status.
    properties: BTreeMap<String, Result<Vec<u8>, Status>>,
    /// The local replies the filter sent, in order.
    local_replies: Vec<LocalReply>,
    /// What of the response the filter rewrote in place, which it must never do.
    response_rewrites: Vec<&'static str>,
    /// Proxy-Wasm log calls, captured even though this stub reports the host as unavailable.
    logs: Vec<(LogLevel, String)>,
    /// How many serialized maps the filter sent that did not decode.
    malformed_maps: usize,
}

/// A local reply the filter sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalReply {
    /// Its status code.
    pub(crate) status: u32,
    /// Its headers, in the order the filter gave them.
    pub(crate) headers: Vec<(String, Vec<u8>)>,
    /// Its body.
    pub(crate) body: Vec<u8>,
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
            published: BTreeMap::new(),
            properties: BTreeMap::new(),
            local_replies: Vec::new(),
            response_rewrites: Vec::new(),
            logs: Vec::new(),
            malformed_maps: 0,
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
        host.published.clear();
        host.properties.clear();
        host.local_replies.clear();
        host.response_rewrites.clear();
        host.logs.clear();
        host.malformed_maps = 0;
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

/// Reads what the filter did, failing the test if it rewrote the response in place or sent a map that did not decode.
fn observed<T>(read: impl FnOnce(&Host) -> T) -> T {
    HOST.with_borrow(|host| {
        assert!(
            host.response_rewrites.is_empty(),
            "the filter rewrote the {:?} in place instead of answering with a local reply",
            host.response_rewrites
        );
        assert_eq!(
            host.malformed_maps, 0,
            "the filter sent a serialized map that does not decode"
        );
        read(host)
    })
}

/// What the filter published at the filter-state property `path`, such as `io.coraza.waf.v1.inspection_complete`.
pub(crate) fn published_property(path: &str) -> Option<String> {
    observed(|host| host.published.get(path).cloned())
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
    observed(|host| host.local_replies.iter().map(|reply| reply.status).collect())
}

/// Every local reply sent so far, in order.
pub(crate) fn local_replies() -> Vec<LocalReply> {
    observed(|host| host.local_replies.clone())
}

/// The log calls the filter attempted, even though this host reports each call unavailable.
pub(crate) fn log_messages() -> Vec<(LogLevel, String)> {
    observed(|host| host.logs.clone())
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
extern "C" fn proxy_log(level: LogLevel, message_data: *const u8, message_size: usize) -> Status {
    let message = String::from_utf8_lossy(&copied(message_data, message_size)).into_owned();
    HOST.with_borrow_mut(|host| host.logs.push((level, message)));
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
    // Envoy refuses a response body replacement outside the body callbacks, and the filter must not need one.
    if buffer_type == BufferType::HttpResponseBody {
        HOST.with_borrow_mut(|host| host.response_rewrites.push("response body"));
    }
    Status::NotFound
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
extern "C" fn proxy_set_header_map_pairs(map_type: MapType, _map_data: *const u8, _map_size: usize) -> Status {
    let rewritten = match map_type {
        MapType::HttpResponseHeaders => Some("response headers"),
        MapType::HttpResponseTrailers => Some("response trailers"),
        _ => None,
    };
    if let Some(rewritten) = rewritten {
        HOST.with_borrow_mut(|host| host.response_rewrites.push(rewritten));
    }
    Status::NotFound
}

/// The header map a serialized Proxy-Wasm map holds, or `None` when it is malformed. No bytes at all is the empty map
/// a host reads from a null pointer.
fn deserialize_map(raw: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    if raw.is_empty() {
        return Some(Vec::new());
    }
    let word = |at: usize| -> Option<usize> {
        let bytes: [u8; 4] = raw.get(at..at.checked_add(4)?)?.try_into().ok()?;
        usize::try_from(u32::from_le_bytes(bytes)).ok()
    };
    let count = word(0)?;
    let mut offset = 4_usize.checked_add(count.checked_mul(8)?)?;
    // The length table must fit before it sizes anything.
    if offset > raw.len() {
        return None;
    }
    let mut map = Vec::with_capacity(count);
    for index in 0..count {
        let name_len = word(4 + index * 8)?;
        let value_len = word(8 + index * 8)?;
        let name = raw.get(offset..offset.checked_add(name_len)?)?;
        offset = offset.checked_add(name_len)?;
        // Each name and value ends with a NUL byte that its length leaves out.
        if *raw.get(offset)? != 0 {
            return None;
        }
        offset = offset.checked_add(1)?;
        let value = raw.get(offset..offset.checked_add(value_len)?)?;
        offset = offset.checked_add(value_len)?;
        if *raw.get(offset)? != 0 {
            return None;
        }
        offset = offset.checked_add(1)?;
        map.push((String::from_utf8_lossy(name).into_owned(), value.to_vec()));
    }
    Some(map)
}

/// A copy of the `size` bytes at `data`, which the SDK may pass as a null pointer when there are none.
fn copied(data: *const u8, size: usize) -> Vec<u8> {
    if data.is_null() || size == 0 {
        return Vec::new();
    }
    // SAFETY: the SDK passes a pointer to `size` bytes it owns for the duration of the call.
    unsafe { std::slice::from_raw_parts(data, size) }.to_vec()
}

#[no_mangle]
extern "C" fn proxy_send_local_response(
    status_code: u32,
    _status_code_details_data: *const u8,
    _status_code_details_size: usize,
    body_data: *const u8,
    body_size: usize,
    headers_data: *const u8,
    headers_size: usize,
    _grpc_status: i32,
) -> Status {
    let headers = deserialize_map(&copied(headers_data, headers_size));
    let malformed = headers.is_none();
    let reply = LocalReply {
        status: status_code,
        headers: headers.unwrap_or_default(),
        body: copied(body_data, body_size),
    };
    HOST.with_borrow_mut(|host| {
        host.malformed_maps += usize::from(malformed);
        host.local_replies.push(reply);
    });
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
    use super::{
        deserialize_map, local_replies, log_messages, proxy_log, proxy_send_local_response, proxy_set_buffer_bytes,
        proxy_set_header_map_pairs, proxy_set_property, reset, serialize_map, BufferType, LogLevel, MapType, Status,
    };

    #[test]
    fn a_serialized_map_decodes_only_when_every_length_and_terminator_fits() {
        let map = vec![("a".to_owned(), b"1".to_vec()), ("bc".to_owned(), Vec::new())];
        let serialized = serialize_map(&map);
        assert_eq!(deserialize_map(&serialized), Some(map));
        assert_eq!(deserialize_map(&[]), Some(Vec::new()), "no bytes is the empty map");
        assert_eq!(
            deserialize_map(&serialize_map(&[])),
            Some(Vec::new()),
            "a zero count is the empty map"
        );
        // Missing last terminator, a non-NUL terminator after a name, and a table longer than the bytes.
        let mut truncated = serialized.clone();
        truncated.pop();
        assert_eq!(deserialize_map(&truncated), None);
        // The first name starts after the count and two length pairs, and its terminator follows it.
        let mut bad_name_terminator = serialized;
        bad_name_terminator.splice(4 + 2 * 8 + 1..4 + 2 * 8 + 2, *b"x");
        assert_eq!(deserialize_map(&bad_name_terminator), None);
        assert_eq!(deserialize_map(&u32::MAX.to_le_bytes()), None);
    }

    #[test]
    fn a_local_reply_with_a_malformed_header_map_fails_the_test_that_reads_the_host() {
        reset();
        let mut malformed = serialize_map(&[("a".to_owned(), b"1".to_vec())]);
        malformed.pop();
        let status = proxy_send_local_response(
            403,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            malformed.as_ptr(),
            malformed.len(),
            -1,
        );
        assert_eq!(status, Status::NotFound);
        assert!(
            std::panic::catch_unwind(local_replies).is_err(),
            "reading the host fails the test"
        );
        reset();
        proxy_send_local_response(403, std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0, -1);
        assert_eq!(local_replies().len(), 1, "a reply with no headers is not malformed");
    }

    #[test]
    fn stubs_report_a_checked_missing_host_instead_of_succeeding() {
        reset();
        assert_eq!(
            proxy_log(LogLevel::Info, std::ptr::null(), 0),
            Status::NotFound,
            "a stub must not pretend the host accepted the log"
        );
        assert_eq!(log_messages(), [(LogLevel::Info, String::new())]);
        assert_eq!(
            proxy_set_property(std::ptr::null(), 0, std::ptr::null(), 0),
            Status::NotFound,
            "a stub must not pretend the host stored a property"
        );
    }

    #[test]
    fn a_response_rewritten_in_place_fails_only_the_test_that_reads_the_host() {
        let rewrites: [fn() -> Status; 3] = [
            || proxy_set_buffer_bytes(BufferType::HttpResponseBody, 0, 0, std::ptr::null(), 0),
            || proxy_set_header_map_pairs(MapType::HttpResponseHeaders, std::ptr::null(), 0),
            || proxy_set_header_map_pairs(MapType::HttpResponseTrailers, std::ptr::null(), 0),
        ];
        for rewrite in rewrites {
            reset();
            assert_eq!(rewrite(), Status::NotFound, "the stub returns instead of aborting");
            assert!(
                std::panic::catch_unwind(local_replies).is_err(),
                "reading the host fails the test"
            );
        }
        reset();
        assert_eq!(
            proxy_set_header_map_pairs(MapType::HttpRequestHeaders, std::ptr::null(), 0),
            Status::NotFound
        );
        assert!(local_replies().is_empty(), "a request header rewrite is not recorded");
    }
}
