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

//! Helpers the body memory budget tests share.

/// The smallest budget up to `high` that `admits`, by bisection.
pub(crate) fn smallest_budget(mut high: usize, mut admits: impl FnMut(usize) -> bool) -> usize {
    assert!(admits(high), "a budget of {high} admits it");
    let mut low = 0;
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if admits(middle) {
            high = middle;
        } else {
            low = middle;
        }
    }
    high
}
