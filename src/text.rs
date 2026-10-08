//! SkyDrive's text logs, as the SkyDrive desktop client (2012–2013, before
//! OneDrive's sync engine) and OneDrive's first versions wrote them in
//! `%LocalAppData%\Microsoft\SkyDrive\logs\` (`SyncDiagnostics.log`,
//! `SkyDriveErr.log`, …). Text in UTF-8 or UTF-16; two layouts.
//!
//! Version 1, one entry per line, times in UTC (`openErrorLog` logs the
//! local time beside it):
//!
//! ```text
//! 08-01-2013 21:22:28.999 global.cpp:626!logVersionInfo (DETAIL): 17.0.2011.0627 (Ship)
//! ```
//!
//! Version 2: a line opening each session, then comma-separated entries
//! (date, time, sequence number and thread in hexadecimal, a zero, module,
//! source, two addresses, level, message); times in UTC, as the session
//! line's system time shows:
//!
//! ```text
//! ######Logging started. Version=17.0.2011.0627 StartSystemTime:2013-07-25-160323.291 StartLocalTime:2013-07-25-180323.291 PID=0x8f4 TID=0x718 ContinuedFrom=
//! 07-25-13,16:03:24.649,13,a98,0,AUTH,authapi.cpp(280),0,0,ERR,Sign in failed : DRX_E_AUTH_NO_VALID_CREDENTIALS,
//! ```
//!
//! In both, the lines after an entry that don't start one continue its
//! message (a sync token, a server's reply).

use common::time::{civil_from_days, days_from_civil, Precision, Ts};

use crate::Error;

/// What opens a version 2 session line.
const SESSION_MARK: &str = "######";
/// A version 1 entry's date and time: `9` a digit, `|` a `.` or `,`.
const V1_TIME_SHAPE: &str = "99-99-9999 99:99:99|999";
/// A version 2 entry's date and time.
const V2_TIME_SHAPE: &str = "99-99-99,99:99:99.999,";
/// A session line's times.
const SESSION_TIME_SHAPE: &str = "9999-99-99-999999.999";
/// The columns of a version 2 entry, its message last.
const V2_COLUMNS: usize = 11;
/// Version 2 years are two digits, from 2000.
const V2_CENTURY: i64 = 2000;
/// The most bytes of a log decoded to find its layout.
const DETECT_BYTES: usize = 4096;
/// Ticks (100 ns) in a millisecond.
const TICKS_PER_MS: i64 = 10_000;

/// Which layout a text log has.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum TextVersion {
    /// `MM-DD-YYYY hh:mm:ss.fff source (LEVEL): message`.
    #[default]
    V1,
    /// `######Logging started.` session lines, then comma-separated
    /// entries.
    V2,
}

/// A SkyDrive text log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextLog {
    /// Its layout.
    pub version: TextVersion,
    /// The entries, in file order.
    pub entries: Vec<Entry>,
    /// Damage met.
    pub problems: Vec<String>,
}

/// An entry, or a version 2 session's start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// The line it starts on (from 1).
    pub line: usize,
    /// When (UTC); a session's start in UTC.
    pub time: Option<Ts>,
    /// The level (`DETAIL`, `NORMAL`, `ERROR`; `VRB`, `NRM`, `ERR`).
    pub level: Option<String>,
    /// The module (version 2: `AUTH`, `WNS`, `PAL`, …).
    pub module: Option<String>,
    /// The source: `file:line!function` (version 1), `file(line)`
    /// (version 2).
    pub source: Option<String>,
    /// The sequence number (version 2).
    pub sequence: Option<u64>,
    /// The thread (version 2).
    pub thread_id: Option<u32>,
    /// The message, the lines continuing it after a line break; a session
    /// line's text after `######`.
    pub message: String,
    /// What a version 2 session line says.
    pub session: Option<Session>,
}

/// A version 2 session line (`######Logging started. …`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    /// The client's version (`17.0.2011.0627`).
    pub client_version: String,
    /// The start, as the local wall clock read.
    pub local_time: Option<Ts>,
    /// The process.
    pub process_id: Option<u32>,
    /// The log it continues, when named.
    pub continued_from: Option<String>,
}

/// Which layout a log starting with `head` has, if it is a SkyDrive text
/// log.
#[must_use]
pub fn text_version(head: &[u8]) -> Option<TextVersion> {
    let text = crate::decode(head.get(..DETECT_BYTES).unwrap_or(head));
    let first = text.lines().find(|line| !line.trim().is_empty())?;
    line_version(first)
}

/// The layout a log's first line shows.
fn line_version(line: &str) -> Option<TextVersion> {
    if line.starts_with(SESSION_MARK) || is_v2_entry(line) {
        Some(TextVersion::V2)
    } else if has_shape(line, V1_TIME_SHAPE) {
        Some(TextVersion::V1)
    } else {
        None
    }
}

/// Read a SkyDrive text log, either layout.
///
/// # Errors
/// When its first line is neither layout's.
pub fn read_text_log(data: &[u8]) -> Result<TextLog, Error> {
    let text = crate::decode(data);
    let version = text
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(line_version)
        .ok_or_else(|| Error("not a SkyDrive log: no entry on its first line".to_owned()))?;
    let mut log = TextLog {
        version,
        ..TextLog::default()
    };
    let mut continuation: Vec<&str> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        let line_number = index + 1;
        let entry = match version {
            TextVersion::V1 => v1_entry(line, line_number),
            TextVersion::V2 => v2_entry(line, line_number),
        };
        let Some(entry) = entry else {
            continuation.push(line);
            continue;
        };
        attach_continuation(&mut log, &mut continuation);
        if entry.time.is_none() {
            log.problems
                .push(format!("line {line_number}: no readable date and time"));
        }
        log.entries.push(entry);
    }
    attach_continuation(&mut log, &mut continuation);
    Ok(log)
}

/// Add the lines after the last entry to its message (or, before any,
/// to `problems`).
fn attach_continuation(log: &mut TextLog, continuation: &mut Vec<&str>) {
    while continuation
        .last()
        .is_some_and(|line| line.trim().is_empty())
    {
        continuation.pop();
    }
    if continuation.is_empty() {
        return;
    }
    match log.entries.last_mut() {
        Some(entry) => {
            for line in continuation.iter() {
                entry.message.push('\n');
                entry.message.push_str(line);
            }
        }
        None => log.problems.push(format!(
            "{} lines before the first entry",
            continuation.len()
        )),
    }
    continuation.clear();
}

/// A version 1 entry, if `line` starts one.
fn v1_entry(line: &str, line_number: usize) -> Option<Entry> {
    if !has_shape(line, V1_TIME_SHAPE) {
        return None;
    }
    let (stamp, rest) = line.split_at_checked(V1_TIME_SHAPE.len())?;
    let rest = rest.trim_start();
    let (source, rest) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    let rest = rest.trim_start();
    let (level, message) = rest
        .strip_prefix('(')
        .and_then(|inner| inner.split_once(')'))
        .map_or((None, rest), |(level, after)| {
            (
                Some(level.to_owned()),
                after.strip_prefix(':').unwrap_or(after),
            )
        });
    Some(Entry {
        line: line_number,
        time: v1_time(stamp),
        level,
        source: Some(source.to_owned()).filter(|s| !s.is_empty()),
        message: message.trim().to_owned(),
        ..Entry::default()
    })
}

/// `MM-DD-YYYY hh:mm:ss.fff`.
fn v1_time(stamp: &str) -> Option<Ts> {
    Civil {
        year: digits(stamp, 6..10)?,
        month: digits(stamp, 0..2)?,
        day: digits(stamp, 3..5)?,
        hour: digits(stamp, 11..13)?,
        minute: digits(stamp, 14..16)?,
        second: digits(stamp, 17..19)?,
        millisecond: digits(stamp, 20..23)?,
    }
    .utc()
}

/// Whether `line` is a version 2 entry.
fn is_v2_entry(line: &str) -> bool {
    has_shape(line, V2_TIME_SHAPE) && line.split(',').count() >= V2_COLUMNS
}

/// A version 2 entry or session line, if `line` starts one.
fn v2_entry(line: &str, line_number: usize) -> Option<Entry> {
    if let Some(text) = line.strip_prefix(SESSION_MARK) {
        return Some(session_entry(text.trim(), line_number));
    }
    if !is_v2_entry(line) {
        return None;
    }
    let columns: Vec<&str> = line.splitn(V2_COLUMNS, ',').collect();
    let column = |at: usize| columns.get(at).copied().unwrap_or_default();
    let date = column(0);
    let clock = column(1);
    Some(Entry {
        line: line_number,
        time: Civil {
            year: V2_CENTURY + digits::<i64>(date, 6..8)?,
            month: digits(date, 0..2)?,
            day: digits(date, 3..5)?,
            hour: digits(clock, 0..2)?,
            minute: digits(clock, 3..5)?,
            second: digits(clock, 6..8)?,
            millisecond: digits(clock, 9..12)?,
        }
        .utc(),
        sequence: u64::from_str_radix(column(2), 16).ok(),
        thread_id: u32::from_str_radix(column(3), 16).ok(),
        module: Some(column(5).to_owned()),
        source: Some(column(6).to_owned()),
        level: Some(column(9).to_owned()),
        message: column(10).trim().to_owned(),
        ..Entry::default()
    })
}

/// A session line's entry, from its text after `######`.
fn session_entry(text: &str, line_number: usize) -> Entry {
    let mut entry = Entry {
        line: line_number,
        message: text.to_owned(),
        ..Entry::default()
    };
    let mut session = Session::default();
    for token in text.split_whitespace() {
        if let Some(version) = token.strip_prefix("Version=") {
            version.clone_into(&mut session.client_version);
        } else if let Some(time) = token.strip_prefix("StartSystemTime:") {
            entry.time = session_time(time).map(|t| Ts::from_ticks(t, Precision::Millisecond));
        } else if let Some(time) = token.strip_prefix("StartLocalTime:") {
            session.local_time =
                session_time(time).map(|t| Ts::from_local_ticks(t, Precision::Millisecond));
        } else if let Some(id) = token.strip_prefix("PID=") {
            session.process_id = hex(id);
        } else if let Some(id) = token.strip_prefix("TID=") {
            entry.thread_id = hex(id);
        }
    }
    session.continued_from = text
        .split_once("ContinuedFrom=")
        .map(|(_, name)| name.trim().to_owned())
        .filter(|name| !name.is_empty());
    entry.session = Some(session);
    entry
}

/// `YYYY-MM-DD-hhmmss.fff` as ticks, counting the wall clock as UTC.
fn session_time(stamp: &str) -> Option<i64> {
    if !has_shape(stamp, SESSION_TIME_SHAPE) || stamp.len() != SESSION_TIME_SHAPE.len() {
        return None;
    }
    Civil {
        year: digits(stamp, 0..4)?,
        month: digits(stamp, 5..7)?,
        day: digits(stamp, 8..10)?,
        hour: digits(stamp, 11..13)?,
        minute: digits(stamp, 13..15)?,
        second: digits(stamp, 15..17)?,
        millisecond: digits(stamp, 18..21)?,
    }
    .ticks()
}

/// `0x1f` or `1f`.
fn hex(text: &str) -> Option<u32> {
    u32::from_str_radix(text.strip_prefix("0x").unwrap_or(text), 16).ok()
}

/// The decimal number in `text[range]`.
fn digits<T: std::str::FromStr>(text: &str, range: std::ops::Range<usize>) -> Option<T> {
    text.get(range)?.parse().ok()
}

/// Whether `text` starts with `shape`: `9` a digit, `|` a `.` or `,`, any
/// other character itself.
fn has_shape(text: &str, shape: &str) -> bool {
    text.len() >= shape.len()
        && text
            .bytes()
            .zip(shape.bytes())
            .all(|(byte, want)| match want {
                b'9' => byte.is_ascii_digit(),
                b'|' => byte == b'.' || byte == b',',
                _ => byte == want,
            })
}

/// A date and time as written.
#[derive(Clone, Copy)]
struct Civil {
    year: i64,
    month: u32,
    day: u32,
    hour: i64,
    minute: i64,
    second: i64,
    millisecond: i64,
}

impl Civil {
    /// Ticks since 1970, counting the wall clock as UTC; `None` for a day
    /// or time that doesn't exist.
    fn ticks(self) -> Option<i64> {
        let days = days_from_civil(self.year, self.month, self.day);
        let real_day = civil_from_days(days) == (self.year, self.month, self.day);
        let real_time = (0..24).contains(&self.hour)
            && (0..60).contains(&self.minute)
            && (0..60).contains(&self.second)
            && (0..1000).contains(&self.millisecond);
        if !(real_day && real_time) {
            return None;
        }
        let seconds = days * 86_400 + self.hour * 3_600 + self.minute * 60 + self.second;
        Some(seconds * common::time::TICKS_PER_SECOND + self.millisecond * TICKS_PER_MS)
    }

    /// The time in UTC.
    fn utc(self) -> Option<Ts> {
        self.ticks()
            .map(|ticks| Ts::from_ticks(ticks, Precision::Millisecond))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_entry_and_continuation() {
        let log = read_text_log(
            b"08-01-2013 21:22:29.702 lc.cpp:5959!persist (NORMAL): Persisting.\n\
              SyncToken = LM\n\n\
              13-33-2013 21:28:46.742 invalid.cpp:666!timestamp (PLASO): invalid\n",
        )
        .unwrap();
        assert_eq!(log.version, TextVersion::V1);
        let entry = &log.entries[0];
        assert_eq!(
            entry.time.and_then(|t| t.ticks()),
            Some(13_753_921_497_020_000)
        );
        assert_eq!(entry.source.as_deref(), Some("lc.cpp:5959!persist"));
        assert_eq!(entry.level.as_deref(), Some("NORMAL"));
        assert_eq!(entry.message, "Persisting.\nSyncToken = LM");
        assert_eq!(log.entries[1].time, None);
        assert_eq!(log.problems, ["line 4: no readable date and time"]);
    }

    #[test]
    fn v2_session_and_entry() {
        let log = read_text_log(
            b"\xef\xbb\xbf######Logging started. Version=17.0.2011.0627 \
              StartSystemTime:2013-07-25-160323.291 StartLocalTime:2013-07-25-180323.291 \
              PID=0x8f4 TID=0x718 ContinuedFrom=\r\n\
              07-25-13,16:03:24.649,13,a98,0,AUTH,authapi.cpp(280),0,0,ERR,Sign in, failed\r\n\
              data\r\n",
        )
        .unwrap();
        assert_eq!(log.version, TextVersion::V2);
        let start = &log.entries[0];
        let session = start.session.as_ref().unwrap();
        assert_eq!(session.client_version, "17.0.2011.0627");
        assert_eq!(session.process_id, Some(0x8f4));
        assert_eq!(start.thread_id, Some(0x718));
        assert_eq!(session.continued_from, None);
        let difference = session.local_time.and_then(|t| t.ticks()).unwrap()
            - start.time.and_then(|t| t.ticks()).unwrap();
        assert_eq!(difference, 2 * 3_600 * 10_000_000);
        let entry = &log.entries[1];
        assert_eq!((entry.sequence, entry.thread_id), (Some(0x13), Some(0xa98)));
        assert_eq!(entry.module.as_deref(), Some("AUTH"));
        assert_eq!(entry.message, "Sign in, failed\ndata");
    }

    #[test]
    fn utf16_and_not_a_log() {
        let text: Vec<u8> = "\u{feff}08-01-2013 21:22:28.999 g.cpp:1!f (DETAIL): x"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(read_text_log(&text).unwrap().entries[0].message, "x");
        assert!(read_text_log(b"Jan 22 07:52:33 host client[30840]: INFO").is_err());
    }
}
