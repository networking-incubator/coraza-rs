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

//! Calendar time in UTC, from Unix time, for the variables and logs that show dates.
//!
//! The standard library has no time zones, so these are in UTC where Go Coraza uses
//! local time.

/// A second of a UTC calendar day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UtcTime {
    /// Four-digit year
    pub year: u64,
    /// 1 to 12
    pub month: u64,
    /// 1 to 31
    pub day: u64,
    /// 0 to 23
    pub hour: u64,
    /// 0 to 59
    pub minute: u64,
    /// 0 to 59
    pub second: u64,
    /// 0 (Sunday) to 6
    pub weekday: u64,
}

impl UtcTime {
    /// The UTC time `seconds` after the Unix epoch.
    pub(crate) fn from_unix(seconds: u64) -> Self {
        let days = seconds / 86_400;
        let second_of_day = seconds % 86_400;
        let (year, month, day) = civil_from_days(days);
        Self {
            year,
            month,
            day,
            hour: second_of_day / 3600,
            minute: second_of_day / 60 % 60,
            second: second_of_day % 60,
            // 1970-01-01 was a Thursday
            weekday: (days + 4) % 7,
        }
    }
}

/// The (year, month 1-12, day 1-31) of a count of days since 1970-01-01, by Howard
/// Hinnant's `civil_from_days`.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_unix() {
        let at = |year, month, day, hour, minute, second, weekday| UtcTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
            weekday,
        };
        assert_eq!(UtcTime::from_unix(0), at(1970, 1, 1, 0, 0, 0, 4));
        assert_eq!(UtcTime::from_unix(951_782_400), at(2000, 2, 29, 0, 0, 0, 2));
        assert_eq!(UtcTime::from_unix(1_700_000_000), at(2023, 11, 14, 22, 13, 20, 2));
    }
}
