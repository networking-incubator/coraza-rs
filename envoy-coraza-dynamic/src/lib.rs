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

//! Native Envoy dynamic-module request enforcement for the `coraza` engine.

/// SDK ABI entry point and filter-configuration factory.
mod abi;
/// Bounded native Envoy filter-state and diagnostic publication.
mod observability;
/// Request/response policy selection, body gating and enforcement.
mod stream;
#[cfg(test)]
/// Minimal logging imports needed by the native unit-test linker.
mod test_hostcalls;
