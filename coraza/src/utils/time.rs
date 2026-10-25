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

//! Calendar time in the process time zone, from Unix time, for the variables and logs
//! that show dates, as Go Coraza formats them.
//!
//! The standard library has no time zones, so the process zone is read from its zoneinfo
//! file, chosen as Go's `time.Local` chooses it at startup: `TZ` when set, `/etc/localtime`
//! otherwise.

use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

/// A second of a calendar day in the process local time zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalTime {
    /// Four-digit year
    pub year: i64,
    /// 1 to 12
    pub month: i64,
    /// 1 to 31
    pub day: i64,
    /// 0 to 23
    pub hour: i64,
    /// 0 to 59
    pub minute: i64,
    /// 0 to 59
    pub second: i64,
    /// 0 (Sunday) to 6
    pub weekday: i64,
    /// Seconds east of UTC at this instant
    pub offset: i64,
}

impl LocalTime {
    /// The local time `seconds` after the Unix epoch.
    pub(crate) fn from_unix(seconds: i64) -> Self {
        Self::at_offset(seconds, process_zone().offset_at(seconds))
    }

    /// The time `seconds` after the Unix epoch in a zone `offset` seconds east of UTC.
    pub(crate) fn at_offset(seconds: i64, offset: i64) -> Self {
        let local = seconds.saturating_add(offset);
        let days = local.div_euclid(86_400);
        let second_of_day = local.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        Self {
            year,
            month,
            day,
            hour: second_of_day / 3600,
            minute: second_of_day / 60 % 60,
            second: second_of_day % 60,
            // 1970-01-01 was a Thursday
            weekday: (days + 4).rem_euclid(7),
            offset,
        }
    }

    /// The time as Go's `time.Stamp` layout writes it, `Jan _2 15:04:05`, which is the
    /// header of a message to the local syslog.
    pub(crate) fn syslog_stamp(&self) -> String {
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let month = usize::try_from(self.month.saturating_sub(1))
            .ok()
            .and_then(|month| MONTHS.get(month))
            .copied()
            .unwrap_or("Jan");
        format!(
            "{month} {:>2} {:02}:{:02}:{:02}",
            self.day, self.hour, self.minute, self.second
        )
    }

    /// The time as Go's `time.RFC3339` layout writes it, `2006-01-02T15:04:05Z07:00`, which
    /// is the header of a message to a remote syslog.
    pub(crate) fn rfc3339(&self) -> String {
        let zone = match self.offset {
            0 => "Z".to_owned(),
            offset => {
                let sign = if offset < 0 { '-' } else { '+' };
                let offset = offset.unsigned_abs();
                format!("{sign}{:02}:{:02}", offset / 3600, offset / 60 % 60)
            },
        };
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{zone}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// The (year, month 1-12, day 1-31) of a count of days since 1970-01-01, by Howard
/// Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The UTC offsets and daylight shifts a zoneinfo file records.
#[derive(Debug, Default)]
struct Zone {
    /// Unix seconds at which the transition at the same index starts, ascending
    transitions: Vec<i64>,
    /// Seconds east of UTC from the transition at the same index on
    offsets: Vec<i64>,
    /// Seconds east of UTC before the first transition
    initial: i64,
}

impl Zone {
    /// The zone a `TZif` file records. Its POSIX rule for the instants after the last
    /// transition is not read.
    ///
    /// shortcut: instants past the last recorded transition keep its offset, so a zone
    /// whose file stops before them ignores a later daylight saving rule; read the
    /// footer's POSIX rule if that ever matters.
    fn from_tzif(data: &[u8]) -> Option<Self> {
        if !data.starts_with(b"TZif") {
            return None;
        }
        let first = header(data, 0)?;
        // Version 2 files repeat their header and their tables in 64-bit form, after the
        // 32-bit block they keep for older readers.
        let (start, counts, width) = match data.get(4).copied() {
            Some(b'2' | b'3' | b'4') => {
                let second = HEADER.checked_add(block_len(&first, 4)?)?;
                (second.checked_add(HEADER)?, header(data, second)?, 8)
            },
            _ => (HEADER, first, 4),
        };
        // No count can exceed the file's own length; refusing larger ones keeps a corrupt
        // file from reserving an arbitrary amount of memory.
        let length = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if counts.iter().any(|&count| count > length) {
            return None;
        }
        let time_count = usize::try_from(counts[3]).ok()?;
        let kind_count = usize::try_from(counts[4]).ok()?;
        let times_at = start;
        let indices_at = times_at.checked_add(time_count.checked_mul(width)?)?;
        let kinds_at = indices_at.checked_add(time_count)?;

        let mut kind_offsets = Vec::with_capacity(kind_count);
        let mut kind_daylight = Vec::with_capacity(kind_count);
        for index in 0..kind_count {
            let at = kinds_at.checked_add(index * 6)?;
            kind_offsets.push(be_i32(data, at)?);
            kind_daylight.push(data.get(at.checked_add(4)?) == Some(&1));
        }

        let mut transitions = Vec::with_capacity(time_count);
        let mut transition_offsets = Vec::with_capacity(time_count);
        let mut transition_kinds = Vec::with_capacity(time_count);
        for index in 0..time_count {
            let at = be_time(data, times_at.checked_add(index.checked_mul(width)?)?, width)?;
            let kind = usize::from(*data.get(indices_at.checked_add(index)?)?);
            // A type index outside the table is corrupt; skip the transition it names.
            if let Some(offset) = kind_offsets.get(kind) {
                transitions.push(at);
                transition_offsets.push(*offset);
                transition_kinds.push(kind);
            }
        }

        Some(Self {
            initial: first_offset(&kind_offsets, &kind_daylight, &transition_kinds),
            transitions,
            offsets: transition_offsets,
        })
    }

    /// The seconds east of UTC at `seconds`.
    fn offset_at(&self, seconds: i64) -> i64 {
        match self.transitions.partition_point(|&transition| transition <= seconds) {
            0 => self.initial,
            count => self
                .offsets
                .get(count.saturating_sub(1))
                .copied()
                .unwrap_or(self.initial),
        }
    }
}

/// The bytes a `TZif` header takes before its data block.
const HEADER: usize = 44;

/// The counts a `TZif` header holds at `at`, in the order the file writes them.
fn header(data: &[u8], at: usize) -> Option<[u64; 6]> {
    let mut counts = [0; 6];
    for (index, count) in counts.iter_mut().enumerate() {
        *count = be_u64(data, at.checked_add(20 + index * 4)?, 4)?;
    }
    Some(counts)
}

/// The bytes a `TZif` data block takes, with times of `width` bytes.
fn block_len(counts: &[u64; 6], width: usize) -> Option<usize> {
    let [utility, standard, leaps, times, kinds, abbreviations] = *counts;
    let width = u64::try_from(width).ok()?;
    let length = times
        .checked_mul(width)?
        .checked_add(times)?
        .checked_add(kinds.checked_mul(6)?)?
        .checked_add(abbreviations)?
        .checked_add(leaps.checked_mul(width.checked_add(4)?)?)?
        .checked_add(standard)?
        .checked_add(utility)?;
    usize::try_from(length).ok()
}

/// The big-endian number of `width` bytes at `at`.
fn be_u64(data: &[u8], at: usize, width: usize) -> Option<u64> {
    let bytes = data.get(at..at.checked_add(width)?)?;
    Some(bytes.iter().fold(0, |value, byte| value << 8 | u64::from(*byte)))
}

/// The big-endian signed 32-bit UTC offset at `at`.
fn be_i32(data: &[u8], at: usize) -> Option<i64> {
    let bytes: [u8; 4] = data.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(i64::from(i32::from_be_bytes(bytes)))
}

/// The big-endian signed transition time of `width` bytes at `at`.
fn be_time(data: &[u8], at: usize, width: usize) -> Option<i64> {
    match width {
        4 => be_i32(data, at),
        8 => {
            let bytes: [u8; 8] = data.get(at..at.checked_add(8)?)?.try_into().ok()?;
            Some(i64::from_be_bytes(bytes))
        },
        _ => None,
    }
}

/// The offset the reference `localtime.c` uses before the first transition, as Go's
/// `lookupFirstZone` applies it.
fn first_offset(offsets: &[i64], daylight: &[bool], kinds: &[usize]) -> i64 {
    let standard = |index: usize| !daylight.get(index).copied().unwrap_or(false);
    // 1. The first type is unused by the transitions.
    if !kinds.contains(&0) {
        return offsets.first().copied().unwrap_or_default();
    }
    // 2. The first transition is to daylight time: the closest standard type before it.
    if let Some(&first) = kinds.first()
        && !standard(first)
        && let Some(index) = (0..first).rev().find(|&index| standard(index))
    {
        return offsets.get(index).copied().unwrap_or_default();
    }
    // 3. The first standard type, 4. otherwise the first type.
    let index = (0..daylight.len()).find(|&index| standard(index)).unwrap_or_default();
    offsets.get(index).copied().unwrap_or_default()
}

/// The process time zone, read once, as Go reads `time.Local` once.
static PROCESS_ZONE: OnceLock<Zone> = OnceLock::new();

/// The offsets of the process time zone.
fn process_zone() -> &'static Zone {
    PROCESS_ZONE.get_or_init(|| match env::var_os("TZ") {
        None => read_zone(Path::new("/etc/localtime")),
        // Go reads an empty `TZ` as UTC.
        Some(target) if target.is_empty() => Zone::default(),
        Some(target) => read_zone(&zone_path(&target)),
    })
}

/// The zoneinfo file a `TZ` value names: an absolute path, or a name under
/// `/usr/share/zoneinfo`, as Go reads it.
fn zone_path(target: &OsStr) -> PathBuf {
    let name = target.to_string_lossy();
    let name = name.strip_prefix(':').unwrap_or(&name);
    let path = Path::new(name);
    if path.is_absolute() {
        path.to_owned()
    } else {
        Path::new("/usr/share/zoneinfo").join(path)
    }
}

/// The zone `path` records; UTC if it is missing or unreadable, as Go falls back.
fn read_zone(path: &Path) -> Zone {
    fs::read(path)
        .ok()
        .and_then(|data| Zone::from_tzif(&data))
        .unwrap_or_default()
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "the time tests use fixed zone data")]
mod tests {
    use std::{ffi::OsStr, path::Path};

    use super::{HEADER, LocalTime, Zone, zone_path};

    /// The calendar fields of `seconds` in a zone `offset` seconds east of UTC, in the
    /// layout of the audit entry's timestamp, with the weekday appended.
    fn format(seconds: i64, offset: i64) -> String {
        let at = LocalTime::at_offset(seconds, offset);
        format!(
            "{:04}/{:02}/{:02} {:02}:{:02}:{:02} {}",
            at.year, at.month, at.day, at.hour, at.minute, at.second, at.weekday
        )
    }

    #[test]
    fn an_offset_moves_the_whole_calendar_time() {
        // 2023-11-14T22:13:20Z, a Tuesday
        assert_eq!(format(1_700_000_000, 0), "2023/11/14 22:13:20 2");
        assert_eq!(format(1_700_000_000, 32_400), "2023/11/15 07:13:20 3");
        assert_eq!(format(1_700_000_000, 19_800), "2023/11/15 03:43:20 3");
        assert_eq!(format(1_700_000_000, -18_000), "2023/11/14 17:13:20 2");
        assert_eq!(format(1_700_000_000, -12_600), "2023/11/14 18:43:20 2");
        assert_eq!(format(951_782_400, 32_400), "2000/02/29 09:00:00 2");
    }

    #[test]
    fn an_offset_moves_the_date_across_the_epoch() {
        assert_eq!(format(0, 0), "1970/01/01 00:00:00 4");
        assert_eq!(format(0, 32_400), "1970/01/01 09:00:00 4");
        assert_eq!(format(0, -18_000), "1969/12/31 19:00:00 3");
        assert_eq!(format(-86_400, 0), "1969/12/31 00:00:00 3");
    }

    #[test]
    fn timestamps_use_go_layouts() {
        let tokyo = LocalTime::at_offset(1_700_000_000, 32_400);
        let india = LocalTime::at_offset(1_700_000_000, 19_800);
        let new_york = LocalTime::at_offset(1_700_000_000, -18_000);
        assert_eq!(tokyo.syslog_stamp(), "Nov 15 07:13:20");
        assert_eq!(tokyo.rfc3339(), "2023-11-15T07:13:20+09:00");
        assert_eq!(india.rfc3339(), "2023-11-15T03:43:20+05:30");
        assert_eq!(new_york.rfc3339(), "2023-11-14T17:13:20-05:00");
        assert_eq!(LocalTime::at_offset(1_700_000_000, 0).rfc3339(), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn a_tz_value_names_a_zoneinfo_file() {
        assert_eq!(
            zone_path(OsStr::new("Asia/Tokyo")),
            Path::new("/usr/share/zoneinfo/Asia/Tokyo")
        );
        assert_eq!(
            zone_path(OsStr::new(":Asia/Tokyo")),
            Path::new("/usr/share/zoneinfo/Asia/Tokyo")
        );
        assert_eq!(zone_path(OsStr::new("/tmp/zone")), Path::new("/tmp/zone"));
    }

    /// A version 2 `TZif` file with an empty 32-bit block, `kinds` as its types and
    /// `transitions` as its transitions.
    fn tzif(transitions: &[(i64, u8)], kinds: &[(i32, bool)]) -> Vec<u8> {
        let mut data = Vec::new();
        let write_header = |data: &mut Vec<u8>, times: usize, kinds: usize| {
            data.extend_from_slice(b"TZif2");
            data.extend_from_slice(&[0; 15]);
            for count in [0, 0, 0, times, kinds, 0] {
                let count = u32::try_from(count).unwrap();
                data.extend_from_slice(&count.to_be_bytes());
            }
        };
        write_header(&mut data, 0, 0);
        write_header(&mut data, transitions.len(), kinds.len());
        for (at, _) in transitions {
            data.extend_from_slice(&at.to_be_bytes());
        }
        for (_, kind) in transitions {
            data.push(*kind);
        }
        for (offset, daylight) in kinds {
            data.extend_from_slice(&offset.to_be_bytes());
            data.push(u8::from(*daylight));
            data.push(0);
        }
        data
    }

    #[test]
    fn transitions_select_the_offset_of_their_instant() {
        // +01:00 until 2021-01-01, then the +02:00 of daylight time
        let data = tzif(
            &[(1_609_459_200, 0), (1_625_097_600, 1)],
            &[(3_600, false), (7_200, true)],
        );
        let zone = Zone::from_tzif(&data).unwrap();
        assert_eq!(zone.offset_at(i64::MIN), 3_600);
        assert_eq!(zone.offset_at(1_609_459_199), 3_600);
        assert_eq!(zone.offset_at(1_609_459_200), 3_600);
        assert_eq!(zone.offset_at(1_625_097_599), 3_600);
        assert_eq!(zone.offset_at(1_625_097_600), 7_200);
        assert_eq!(zone.offset_at(i64::MAX), 7_200);
    }

    #[test]
    fn a_corrupt_zone_file_is_not_read() {
        assert!(Zone::from_tzif(b"").is_none());
        assert!(Zone::from_tzif(b"not a zone file").is_none());
        let data = tzif(&[(1_609_459_200, 1)], &[(3_600, false)]);
        assert!(Zone::from_tzif(data.get(..HEADER).unwrap()).is_none());
        assert!(Zone::from_tzif(data.get(..data.len() - 4).unwrap()).is_none());
    }

    #[test]
    fn a_real_zone_file_offsets_a_known_instant() {
        let Ok(data) = std::fs::read("/usr/share/zoneinfo/Asia/Tokyo") else {
            // No zoneinfo on this host; the parsing above is the check that remains.
            return;
        };
        let zone = Zone::from_tzif(&data).unwrap();
        assert_eq!(zone.offset_at(1_700_000_000), 32_400);
        assert_eq!(zone.offset_at(0), 32_400);
    }
}
