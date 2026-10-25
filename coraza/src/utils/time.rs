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

/// The count of days since 1970-01-01 of a calendar date, by Howard Hinnant's
/// `days_from_civil`, which inverts [`civil_from_days`].
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let year = year.checked_sub(i64::from(month <= 2))?;
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?.checked_add(day_of_era)?.checked_sub(719_468)
}

/// Whether `year` is a leap year.
fn is_leap(year: i64) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

/// The days each month of a common year holds.
const MONTH_DAYS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// The days a common year holds before each month starts.
const MONTH_STARTS: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

/// The UTC offsets and daylight shifts a zoneinfo file records.
#[derive(Debug, Default)]
struct Zone {
    /// Unix seconds at which the transition at the same index starts, ascending
    transitions: Vec<i64>,
    /// Seconds east of UTC from the transition at the same index on
    offsets: Vec<i64>,
    /// Seconds east of UTC before the first transition
    initial: i64,
    /// The POSIX rule for the instants the transitions do not reach
    footer: Option<PosixRule>,
}

impl Zone {
    /// The zone a `TZif` file records, with the POSIX rule it states for the instants
    /// after its last transition.
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
        let end = start.checked_add(block_len(&counts, width)?)?;
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
            // Version 2 and later files, whose times are the 64-bit ones, end with the
            // POSIX rule for the years their tables stop short of.
            footer: if width == 8 { footer_rule(data, end) } else { None },
        })
    }

    /// The seconds east of UTC at `seconds`.
    fn offset_at(&self, seconds: i64) -> i64 {
        // The footer's rule covers the instants no transition reaches, and all of them
        // for a file that records none.
        if let Some(footer) = &self.footer
            && self.transitions.last().is_none_or(|&last| seconds >= last)
        {
            return footer.offset_at(seconds);
        }
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

/// The POSIX rule a version 2 or later `TZif` file writes between the newlines after
/// its tables, if it states one that parses.
fn footer_rule(data: &[u8], at: usize) -> Option<PosixRule> {
    let rest = data.get(at..)?;
    parse_posix(rest.strip_prefix(b"\n")?.strip_suffix(b"\n")?)
}

/// A POSIX `TZ` rule, `std offset [dst [offset]] [, start[/time], end[/time]]`, as
/// `tzfile(5)` writes it after the transition tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PosixRule {
    /// Seconds east of UTC in standard time
    standard: i64,
    /// The daylight saving rule, absent in a zone that has none
    daylight: Option<DaylightRule>,
}

/// The dates at which a zone with daylight time changes to and from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaylightRule {
    /// Seconds east of UTC in daylight time
    offset: i64,
    /// The date daylight time starts
    start: DateRule,
    /// The date daylight time ends
    end: DateRule,
}

/// A date on which a rule changes the offset, and the time of day it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DateRule {
    /// The day the rule names
    kind: DateKind,
    /// Seconds after local midnight, in the time in effect before the change
    at: i64,
}

/// The three ways a POSIX rule names the day of a change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DateKind {
    /// `Jn`: day 1 to 365, never counting February 29
    Julian(i64),
    /// `n`: day 0 to 365, counting February 29
    DayOfYear(i64),
    /// `Mm.w.d`: month 1 to 12, week 1 to 5 where 5 is the last, day 0 Sunday to 6
    MonthWeekDay {
        /// Month, 1 to 12
        month: i64,
        /// Week of the month, 1 to 5, where 5 is the last such day of the month
        week: i64,
        /// Day of the week, 0 (Sunday) to 6
        day: i64,
    },
}

impl PosixRule {
    /// The seconds east of UTC at `seconds`, as Go's `tzset` reads the same rule.
    fn offset_at(self, seconds: i64) -> i64 {
        let Some(daylight) = self.daylight else {
            return self.standard;
        };
        // The rule dates its changes in the year of the instant, counted in UTC.
        let (year, ..) = civil_from_days(seconds.div_euclid(86_400));
        // A change happens in the local time of the offset it leaves behind, so reaching
        // UTC from it means subtracting that offset.
        let (Some(start), Some(end)) = (
            date_seconds(daylight.start, year, self.standard),
            date_seconds(daylight.end, year, daylight.offset),
        ) else {
            // A date whose seconds overflow the clock leaves standard time standing.
            return self.standard;
        };
        // A rule that starts after it ends runs from one year's end date to the next
        // year's start date, so daylight time is the state outside the two dates.
        let (start, end, outside, inside) = if end < start {
            (end, start, daylight.offset, self.standard)
        } else {
            (start, end, self.standard, daylight.offset)
        };
        if seconds < start || seconds >= end {
            outside
        } else {
            inside
        }
    }
}

/// The Unix second at which `rule` takes effect in `year`, with `offset` the seconds
/// east of UTC in effect before it.
fn date_seconds(rule: DateRule, year: i64, offset: i64) -> Option<i64> {
    let day = day_of_year(rule.kind, year)?;
    let days = days_from_civil(year, 1, 1)?.checked_add(day)?;
    days.checked_mul(86_400)?.checked_add(rule.at)?.checked_sub(offset)
}

/// The day of `year`, counted from 0 for January 1, that `kind` names.
fn day_of_year(kind: DateKind, year: i64) -> Option<i64> {
    let leap = is_leap(year);
    match kind {
        DateKind::Julian(day) => Some(day - 1 + i64::from(leap && day >= 60)),
        DateKind::DayOfYear(day) => Some(day),
        DateKind::MonthWeekDay { month, week, day } => {
            let index = usize::try_from(month.checked_sub(1)?).ok()?;
            // Only February is longer in a leap year.
            let length = MONTH_DAYS.get(index)?.checked_add(i64::from(leap && month == 2))?;
            // The weekday of the month's first day, 1970-01-01 being a Thursday.
            let weekday = days_from_civil(year, month, 1)?.checked_add(4)?.rem_euclid(7);
            let mut date = day - weekday;
            if date < 0 {
                date += 7;
            }
            // Week 5 is the last such day of the month, which can fall in week 4.
            for _ in 1..week {
                if date + 7 >= length {
                    break;
                }
                date += 7;
            }
            Some(MONTH_STARTS.get(index)?.checked_add(i64::from(leap && month > 2))? + date)
        },
    }
}

/// The rule `bytes` states, or `None` if it does not parse.
fn parse_posix(bytes: &[u8]) -> Option<PosixRule> {
    let mut text = Text { bytes };
    text.name()?;
    // POSIX writes an offset as the time to add to local time to reach UTC, so a zone
    // west of Greenwich has a positive one.
    let standard = text.offset()?.checked_neg()?;
    // A string that stops here, or that continues with a comma, has no daylight time.
    if matches!(text.peek(), None | Some(b',')) {
        return Some(PosixRule {
            standard,
            daylight: None,
        });
    }
    text.name()?;
    // Go reads a daylight offset only where one follows; a separator here means the
    // default of an hour after standard time.
    let offset = match text.peek() {
        None | Some(b',') => standard.checked_add(3_600)?,
        _ => text.offset()?.checked_neg()?,
    };
    if text.peek().is_none() {
        // The rules tzcode assumes where the string states none.
        text.bytes = b",M3.2.0,M11.1.0";
    }
    text.separator()?;
    let start = text.date()?;
    text.separator()?;
    let end = text.date()?;
    // Anything left over means the string states more than this reader understands.
    if text.peek().is_some() {
        return None;
    }
    Some(PosixRule {
        standard,
        daylight: Some(DaylightRule { offset, start, end }),
    })
}

/// A cursor over the bytes of a POSIX `TZ` string.
struct Text<'a> {
    /// The bytes not read yet
    bytes: &'a [u8],
}

impl Text<'_> {
    /// The byte the unread text starts with.
    fn peek(&self) -> Option<u8> {
        self.bytes.first().copied()
    }

    /// The unread text without its first `count` bytes.
    fn skip(&mut self, count: usize) -> Option<()> {
        self.bytes = self.bytes.get(count..)?;
        Some(())
    }

    /// Consumes `byte`.
    fn eat(&mut self, byte: u8) -> Option<()> {
        if self.peek()? != byte {
            return None;
        }
        self.skip(1)
    }

    /// Consumes the separator before a rule, a comma or the semicolon tzcode accepts.
    fn separator(&mut self) -> Option<()> {
        match self.peek()? {
            b',' | b';' => self.skip(1),
            _ => None,
        }
    }

    /// Consumes a zone name, which the offsets alone do not need.
    fn name(&mut self) -> Option<()> {
        if self.peek()? == b'<' {
            let end = self.bytes.iter().position(|byte| *byte == b'>')?;
            return self.skip(end.checked_add(1)?);
        }
        // POSIX names a zone with at least three characters.
        match self
            .bytes
            .iter()
            .position(|byte| byte.is_ascii_digit() || matches!(byte, b',' | b'-' | b'+'))
        {
            Some(end) if end >= 3 => self.skip(end),
            None if self.bytes.len() >= 3 => self.skip(self.bytes.len()),
            Some(_) | None => None,
        }
    }

    /// Consumes a decimal number of `min` to `max`.
    fn number(&mut self, min: i64, max: i64) -> Option<i64> {
        let end = self.bytes.iter().take_while(|byte| byte.is_ascii_digit()).count();
        let mut value = 0_i64;
        for digit in self.bytes.get(..end)? {
            value = value.checked_mul(10)?.checked_add(i64::from(digit - b'0'))?;
            // Refusing a number the caller bounds keeps a long run of digits from
            // overflowing before the comparison.
            if value > max {
                return None;
            }
        }
        if end == 0 || value < min {
            return None;
        }
        self.skip(end)?;
        Some(value)
    }

    /// Consumes `[+-]hh[:mm[:ss]]` as written, in POSIX's direction of positive west.
    fn offset(&mut self) -> Option<i64> {
        let mut sign = 1;
        if let Some(byte @ (b'+' | b'-')) = self.peek() {
            sign = if byte == b'-' { -1 } else { 1 };
            self.skip(1)?;
        }
        // tzcode permits up to a week of hours here, though POSIX does not.
        let mut seconds = self.number(0, 24 * 7)?.checked_mul(3_600)?;
        if self.peek() == Some(b':') {
            self.skip(1)?;
            seconds = seconds.checked_add(self.number(0, 59)?.checked_mul(60)?)?;
            if self.peek() == Some(b':') {
                self.skip(1)?;
                seconds = seconds.checked_add(self.number(0, 59)?)?;
            }
        }
        seconds.checked_mul(sign)
    }

    /// Consumes a transition date rule and its optional time of day.
    fn date(&mut self) -> Option<DateRule> {
        let kind = match self.peek()? {
            b'J' => {
                self.skip(1)?;
                DateKind::Julian(self.number(1, 365)?)
            },
            b'M' => {
                self.skip(1)?;
                let month = self.number(1, 12)?;
                self.eat(b'.')?;
                let week = self.number(1, 5)?;
                self.eat(b'.')?;
                let day = self.number(0, 6)?;
                DateKind::MonthWeekDay { month, week, day }
            },
            _ => DateKind::DayOfYear(self.number(0, 365)?),
        };
        // Two in the morning local time, as tzcode assumes when no time is stated.
        if self.peek() != Some(b'/') {
            return Some(DateRule { kind, at: 7_200 });
        }
        self.skip(1)?;
        Some(DateRule {
            kind,
            at: self.offset()?,
        })
    }
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

    use super::{
        DateKind, HEADER, LocalTime, Zone, be_i32, be_time, block_len, day_of_year, header, parse_posix, zone_path,
    };

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
        tzif_with_footer(transitions, kinds, None)
    }

    /// A version 2 `TZif` file with an empty 32-bit block, `kinds` as its types,
    /// `transitions` as its transitions and `footer` as its POSIX rule.
    fn tzif_with_footer(transitions: &[(i64, u8)], kinds: &[(i32, bool)], footer: Option<&str>) -> Vec<u8> {
        let mut data = Vec::new();
        let write_header = |data: &mut Vec<u8>, times: usize, kinds: usize, chars: usize| {
            data.extend_from_slice(b"TZif2");
            data.extend_from_slice(&[0; 15]);
            for count in [0, 0, 0, times, kinds, chars] {
                let count = u32::try_from(count).unwrap();
                data.extend_from_slice(&count.to_be_bytes());
            }
        };
        write_header(&mut data, 0, 0, 0);
        write_header(&mut data, transitions.len(), kinds.len(), 4);
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
        // Every type names the abbreviation at index 0, which Go requires to exist.
        data.extend_from_slice(b"LMT\0");
        if let Some(footer) = footer {
            data.push(b'\n');
            data.extend_from_slice(footer.as_bytes());
            data.push(b'\n');
        }
        data
    }

    /// The real zone `data` rewritten as a version 2 file whose transitions all start
    /// before `cutoff`, with `footer` as its POSIX rule, as `zic -b slim` writes a zone.
    fn slim(data: &[u8], cutoff: i64, footer: &str) -> Vec<u8> {
        let first = header(data, 0).unwrap();
        let second = HEADER + block_len(&first, 4).unwrap();
        let counts = header(data, second).unwrap();
        let start = second + HEADER;
        let time_count = usize::try_from(counts[3]).unwrap();
        let kind_count = usize::try_from(counts[4]).unwrap();
        let indices_at = start + time_count * 8;
        let kinds_at = indices_at + time_count;

        let mut kinds = Vec::with_capacity(kind_count);
        for index in 0..kind_count {
            let at = kinds_at + index * 6;
            let offset = i32::try_from(be_i32(data, at).unwrap()).unwrap();
            kinds.push((offset, data.get(at + 4) == Some(&1)));
        }
        let mut transitions = Vec::new();
        for index in 0..time_count {
            let at = be_time(data, start + index * 8, 8).unwrap();
            let kind = *data.get(indices_at + index).unwrap();
            if at < cutoff {
                transitions.push((at, kind));
            }
        }
        tzif_with_footer(&transitions, &kinds, Some(footer))
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
        // Cutting the last 8 bytes takes the abbreviations and part of the last type.
        assert!(Zone::from_tzif(data.get(..data.len() - 8).unwrap()).is_none());
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

    #[test]
    fn the_three_date_rules_select_the_days_they_name() {
        // 2024 is a leap year: Julian day 60 is March 1, and day 59 February 29.
        assert_eq!(day_of_year(DateKind::Julian(60), 2024), Some(60));
        assert_eq!(day_of_year(DateKind::Julian(60), 2023), Some(59));
        assert_eq!(day_of_year(DateKind::DayOfYear(59), 2024), Some(59));
        assert_eq!(day_of_year(DateKind::DayOfYear(365), 2023), Some(365));
        let sunday = |month, week| DateKind::MonthWeekDay { month, week, day: 0 };
        // The second Sunday of March 2024 is the 10th, the last of March the 31st and
        // the last of October the 27th.
        assert_eq!(day_of_year(sunday(3, 2), 2024), Some(69));
        assert_eq!(day_of_year(sunday(3, 5), 2024), Some(90));
        assert_eq!(day_of_year(sunday(10, 5), 2024), Some(300));
        // A fifth week that does not exist is the last the month holds.
        assert_eq!(day_of_year(sunday(4, 5), 2024), Some(118));
        // The last Sunday of March 2040 is the 25th, a leap year in which counting the
        // leap day in March's own length would have pointed into April.
        assert_eq!(day_of_year(sunday(3, 5), 2040), Some(84));
    }

    #[test]
    fn a_footer_states_offsets_the_way_posix_does() {
        let tokyo = parse_posix(b"JST-9").unwrap();
        assert_eq!(tokyo.standard, 32_400);
        assert!(tokyo.daylight.is_none());
        // A quoted name, a leading plus, and offsets with minutes and seconds.
        assert_eq!(parse_posix(b"<+0330>-3:30").unwrap().standard, 12_600);
        assert_eq!(parse_posix(b"JST-9:30:30").unwrap().standard, 34_230);
        // A daylight offset nobody states is an hour after standard time, and the rules
        // nobody states are tzcode's.
        let default = parse_posix(b"EST5EDT").unwrap();
        assert_eq!(default.daylight.unwrap().offset, -14_400);
        assert_eq!(default.offset_at(1_719_835_200), -14_400);
        assert_eq!(default.offset_at(1_705_320_000), -18_000);
        // tzcode accepts a semicolon where POSIX writes a comma.
        assert!(parse_posix(b"EST5EDT4;M3.2.0,M11.1.0").is_some());
    }

    #[test]
    fn the_footer_governs_the_instants_after_the_last_transition() {
        // +01:00, even in daylight time, until 2024-07-01T12:00:00Z, where the footer's
        // rule takes over and states +02:00 for that day.
        let data = tzif_with_footer(
            &[(1_704_067_200, 0), (1_719_835_200, 0)],
            &[(3_600, false), (7_200, true)],
            Some("CET-1CEST,M3.5.0,M10.5.0/3"),
        );
        let zone = Zone::from_tzif(&data).unwrap();
        assert_eq!(zone.offset_at(1_719_835_199), 3_600);
        assert_eq!(zone.offset_at(1_719_835_200), 7_200);
        // The rule dates no change in the years of the largest instant, so standard time
        // stands there.
        assert_eq!(zone.offset_at(i64::MAX), 3_600);
    }

    #[test]
    fn a_daylight_rule_dates_its_changes_in_the_local_time_it_leaves() {
        // Europe/Berlin's rule: daylight time from the last Sunday of March to the last
        // Sunday of October, at 02:00 in both the standard and the daylight offset.
        let data = tzif_with_footer(
            &[(1_704_067_200, 0)],
            &[(3_600, false), (7_200, true)],
            Some("CET-1CEST,M3.5.0,M10.5.0/3"),
        );
        let zone = Zone::from_tzif(&data).unwrap();
        assert_eq!(zone.offset_at(1_705_320_000), 3_600, "2024-01-15 is winter");
        assert_eq!(zone.offset_at(1_719_835_200), 7_200, "2024-07-01 is summer");
        // The change happens at 03:00 local time, that is 01:00 UTC.
        assert_eq!(zone.offset_at(1_711_846_800 - 1), 3_600);
        assert_eq!(zone.offset_at(1_711_846_800), 7_200);
        assert_eq!(zone.offset_at(1_729_990_800 - 1), 7_200);
        assert_eq!(zone.offset_at(1_729_990_800), 3_600);
        // The year after the rule dates the same days.
        assert_eq!(zone.offset_at(1_751_371_200), 7_200, "2025-07-01 is summer");
        assert_eq!(zone.offset_at(1_767_268_800), 3_600, "2026-01-01 is winter");
        // The last Sunday of March 2040 is the 25th, and the change is at 01:00 UTC.
        assert_eq!(zone.offset_at(2_216_250_000 - 1), 3_600);
        assert_eq!(zone.offset_at(2_216_250_000), 7_200);
    }

    #[test]
    fn a_southern_rule_makes_daylight_time_the_state_outside_its_dates() {
        // Australia/Sydney's rule: daylight time from October to April.
        let data = tzif_with_footer(
            &[(1_704_067_200, 0)],
            &[(36_000, false), (39_600, true)],
            Some("AEST-10AEDT,M10.1.0,M4.1.0/3"),
        );
        let zone = Zone::from_tzif(&data).unwrap();
        assert_eq!(zone.offset_at(1_705_320_000), 39_600, "2024-01-15 is summer");
        assert_eq!(zone.offset_at(1_719_835_200), 36_000, "2024-07-01 is winter");
    }

    #[test]
    fn a_slim_zone_file_applies_the_footer_after_the_last_transition() {
        let Ok(data) = std::fs::read("/usr/share/zoneinfo/America/New_York") else {
            return;
        };
        let data = slim(&data, 1_704_067_200, "EST5EDT,M3.2.0,M11.1.0");
        if let Some(path) = std::env::var_os("CORAZA_TZIF_DUMP") {
            // Lets the Go oracle read the exact bytes these assertions check.
            drop(std::fs::write(path, &data));
        }
        let zone = Zone::from_tzif(&data).unwrap();
        assert!(zone.footer.is_some(), "the footer parsed");
        // July 2024 is daylight time and January 2024 standard time.
        assert_eq!(zone.offset_at(1_719_835_200), -14_400);
        assert_eq!(zone.offset_at(1_705_320_000), -18_000);
        // The 2024 changes happen at 07:00 UTC on March 10 and 06:00 UTC on November 3,
        // which is 02:00 in the local time each leaves behind.
        assert_eq!(zone.offset_at(1_710_054_000 - 1), -18_000);
        assert_eq!(zone.offset_at(1_710_054_000), -14_400);
        assert_eq!(zone.offset_at(1_730_613_600 - 1), -14_400);
        assert_eq!(zone.offset_at(1_730_613_600), -18_000);
        // The table still governs the instants it records.
        assert_eq!(zone.offset_at(1_704_067_200 - 1), -18_000);
    }

    #[test]
    fn a_real_zone_file_applies_its_footer_after_its_last_transition() {
        // The recorded transitions of these files stop in 2037; 2040 is the footer's.
        for (path, winter, summer) in [
            ("/usr/share/zoneinfo/America/New_York", -18_000, -14_400),
            ("/usr/share/zoneinfo/Europe/Berlin", 3_600, 7_200),
        ] {
            let Ok(data) = std::fs::read(path) else {
                return;
            };
            let zone = Zone::from_tzif(&data).unwrap();
            if zone.footer.is_none() {
                // A file whose transitions reach far enough needs no footer.
                continue;
            }
            assert_eq!(zone.offset_at(2_210_241_600), winter, "{path} in January");
            assert_eq!(zone.offset_at(2_224_756_800), summer, "{path} in July");
        }
    }

    #[test]
    fn a_footer_that_does_not_parse_leaves_the_last_transition_in_force() {
        let kinds = [(3_600, false), (7_200, true)];
        let transitions = [(1_704_067_200, 0), (1_719_835_200, 1)];
        for footer in [
            "",
            "EST",
            "EST5EDT,",
            "EST5EDT,M3.2.0",
            "EST5EDT,M3.2.0,",
            "EST5EDT,M3.2.0,M11.1.",
            "EST5EDT,M3.2.0,M11.1.0x",
            "EST5EDT,M3.2.0,M11.1.0,M1.1.0",
            "EST5EDT,M13.1.0,M11.1.0",
            "EST5EDT,M0.1.0,M11.1.0",
            "EST5EDT,M3.6.0,M11.1.0",
            "EST5EDT,M3.0.0,M11.1.0",
            "EST5EDT,M3.2.7,M11.1.0",
            "EST5EDT,J0,M11.1.0",
            "EST5EDT,367,M11.1.0",
            "\u{fffd}",
        ] {
            let data = tzif_with_footer(&transitions, &kinds, Some(footer));
            let zone = Zone::from_tzif(&data).unwrap();
            assert!(zone.footer.is_none(), "footer {footer:?} parsed");
            assert_eq!(zone.offset_at(1_719_835_200), 7_200, "footer {footer:?}");
            assert_eq!(zone.offset_at(i64::MAX), 7_200, "footer {footer:?}");
        }
    }

    #[test]
    fn an_instant_no_rule_can_date_does_not_overflow() {
        let data = tzif_with_footer(
            &[(1_704_067_200, 0)],
            &[(3_600, false)],
            Some("CET-1CEST,M3.5.0,M10.5.0/3"),
        );
        let zone = Zone::from_tzif(&data).unwrap();
        // The year of these instants is far outside any date the rule can name, so the
        // offset falls back to standard time instead of wrapping.
        assert!(zone.offset_at(i64::MAX) == 3_600 || zone.offset_at(i64::MAX) == 7_200);
        assert!(zone.offset_at(i64::MIN) == 3_600 || zone.offset_at(i64::MIN) == 7_200);
    }
}
