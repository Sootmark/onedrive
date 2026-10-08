//! plaso's OneDrive and SkyDrive logs (Apache-2.0, `tests/fixtures/plaso/`):
//! every event plaso's `onedrive_log`, `text/skydrive_log_v1` and
//! `text/skydrive_log_v2` parsers read, read the same
//! (`tests/oracle/plaso.tsv.gz`, written from plaso's output): time, source
//! file, function, raw and decoded parameters; level, module, source and
//! message. Differences, all counted below:
//!
//! - The sync engine log holds 3,038 records; psort shows 2,768, the
//!   other 270 repeating one to the millisecond, parameters included.
//! - With `ObfuscationStringMap.txt` beside it, plaso restores the
//!   obfuscated words (`tests/oracle/plaso_map.tsv.gz`, a second run):
//!   [`onedrive::ObfuscationMap`] restores the same.
//! - plaso joins a version 2 message's lines with spaces, unevenly; here
//!   they keep their line breaks. Compared with whitespace collapsed.
//! - Version 1: plaso makes each line that continues an entry an event of
//!   its own (with the entry's time, `->` taken off) and keeps only the
//!   first after each entry; here they continue the entry's message. One
//!   line plaso drops (`This line should be skipped!`) is counted here;
//!   the line with an impossible date (`13-33-2013`, plaso's warning) is an
//!   entry without a time and a problem.

use std::collections::BTreeSet;
use std::fmt::Write;
use std::io::Read;

use common::time::civil_from_days;
use onedrive::{Entry, ObfuscationMap, TextVersion};

const ODL_NAME: &str = "SyncEngine-2022-11-24.2341.10688.1.odlgz";
const TEXT_LOGS: [&str; 4] = [
    "skydrive.log",
    "skydrive_v1.log",
    "skydriveerr.log",
    "skydriveerr-unicode.log",
];
const TICKS_PER_MS: i64 = 10_000;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn oracle(path: &str) -> BTreeSet<String> {
    let mut text = String::new();
    common::gzip::Decoder::new(&read(path)[..])
        .read_to_string(&mut text)
        .unwrap();
    text.lines().map(str::to_owned).collect()
}

/// Control characters and backslashes as `\xNN`, as the oracle writes them.
fn escape(text: &str) -> String {
    text.chars().fold(String::new(), |mut out, c| {
        if (c as u32) < 0x20 || c == '\\' {
            let _ = write!(out, "\\x{:02x}", c as u32);
        } else {
            out.push(c);
        }
        out
    })
}

fn row(columns: &[&str]) -> String {
    columns
        .iter()
        .map(|c| escape(c))
        .collect::<Vec<_>>()
        .join("\t")
}

fn millis(entry_time: Option<common::time::Ts>) -> i64 {
    entry_time.and_then(|t| t.ticks()).unwrap() / TICKS_PER_MS
}

fn odl_rows(map: &ObfuscationMap) -> Vec<String> {
    let odl = onedrive::read_odl(&read(&format!("fixtures/plaso/{ODL_NAME}"))).unwrap();
    assert_eq!(odl.problems, Vec::<String>::new());
    assert_eq!((odl.version, odl.compressed), (2, true));
    assert_eq!(odl.onedrive_version, "21.220.1024.0005");
    assert_eq!(odl.os_version, "10.0.22000");
    odl.records
        .iter()
        .map(|record| {
            let time = millis(record.time).to_string();
            let raw = record
                .raw_parameters
                .iter()
                .fold(String::new(), |mut hex, b| {
                    let _ = write!(hex, "{b:02x}");
                    hex
                });
            let parameters: Vec<String> = record
                .parameters
                .iter()
                .map(|p| map.deobfuscate(p))
                .collect();
            let mut columns = vec![
                "odl",
                ODL_NAME,
                &time,
                &record.code_file,
                &record.function,
                &raw,
            ];
            columns.extend(parameters.iter().map(String::as_str));
            row(&columns)
        })
        .collect()
}

#[test]
fn every_sync_engine_record_as_plaso_reads_it() {
    let got = odl_rows(&ObfuscationMap::default());
    let expected = oracle("oracle/plaso.tsv.gz");
    let expected: BTreeSet<String> = expected
        .into_iter()
        .filter(|l| l.starts_with("odl\t"))
        .collect();
    assert_eq!(got.len(), 3038);
    assert_eq!(expected.len(), 2768);
    assert_eq!(got.into_iter().collect::<BTreeSet<_>>(), expected);
}

#[test]
fn deobfuscated_as_plaso_does_it() {
    let map = ObfuscationMap::read(&read("fixtures/plaso/ObfuscationStringMap.txt"));
    assert_eq!(map.len(), 303);
    let got: BTreeSet<String> = odl_rows(&map).into_iter().collect();
    let expected = oracle("oracle/plaso_map.tsv.gz");
    assert_eq!(expected.len(), 2768);
    assert_eq!(got, expected);
    let deobfuscated = odl_rows(&map);
    assert!(deobfuscated
        .iter()
        .any(|r| r.contains("\ttest document.docx\tDocument\tB201A0178F192B2B!107\t")));
}

/// `YYYY-MM-DD-hhmmss.fff`, as a session line writes its local time.
fn session_time(ticks: i64) -> String {
    let ms = ticks / TICKS_PER_MS;
    let (days, ms_of_day) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    let (year, month, day) = civil_from_days(days);
    let seconds = ms_of_day / 1000;
    format!(
        "{year:04}-{month:02}-{day:02}-{:02}{:02}{:02}.{:03}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60,
        ms_of_day % 1000
    )
}

/// What plaso writes for a session line, from what was read of it.
fn session_detail(entry: &Entry) -> String {
    let session = entry.session.as_ref().unwrap();
    format!(
        "Logging started. Version= {} StartLocalTime: {} PID={:#x} TID={:#x} ContinuedFrom={}",
        session.client_version,
        session_time(session.local_time.and_then(|t| t.ticks()).unwrap()),
        session.process_id.unwrap(),
        entry.thread_id.unwrap(),
        session.continued_from.as_deref().unwrap_or_default()
    )
}

/// plaso's events for a text log's entries, and the lines it drops.
fn text_rows(name: &str, entries: &[Entry], version: TextVersion) -> (Vec<String>, usize) {
    let mut rows = Vec::new();
    let mut dropped = 0;
    for entry in entries.iter().filter(|e| e.time.is_some()) {
        let time = millis(entry.time).to_string();
        let field = |value: &Option<String>| value.clone().unwrap_or_default();
        let (level, module, source) = (
            field(&entry.level),
            field(&entry.module),
            field(&entry.source),
        );
        if version == TextVersion::V2 {
            let detail = match entry.session {
                Some(_) => session_detail(entry),
                None => entry.message.clone(),
            };
            let detail = detail.split_whitespace().collect::<Vec<_>>().join(" ");
            rows.push(row(&["v2", name, &time, &level, &module, &source, &detail]));
            continue;
        }
        let mut lines = entry.message.lines().filter(|l| !l.trim().is_empty());
        let head = lines.next().unwrap_or_default();
        rows.push(row(&["v1", name, &time, &level, "", &source, head]));
        if let Some(next) = lines.next() {
            let detail = next.strip_prefix("->").unwrap_or(next);
            rows.push(row(&["v1", name, &time, "", "", "", detail]));
        }
        dropped += lines.count();
    }
    (rows, dropped)
}

#[test]
fn every_text_log_entry_as_plaso_reads_it() {
    let expected = oracle("oracle/plaso.tsv.gz");
    let mut got = BTreeSet::new();
    let mut counts = Vec::new();
    for name in TEXT_LOGS {
        let data = read(&format!("fixtures/plaso/{name}"));
        let log = onedrive::read_text_log(&data).unwrap();
        assert_eq!(
            onedrive::detect(&data),
            Some(onedrive::Kind::Text(log.version))
        );
        let (rows, dropped) = text_rows(name, &log.entries, log.version);
        counts.push((name, log.entries.len(), rows.len(), dropped, log.problems));
        got.extend(rows);
    }
    let no_problem = Vec::<String>::new;
    assert_eq!(
        counts,
        [
            ("skydrive.log", 17, 17, 0, no_problem()),
            (
                "skydrive_v1.log",
                16,
                18,
                1,
                vec!["line 22: no readable date and time".to_owned()]
            ),
            ("skydriveerr.log", 19, 19, 0, no_problem()),
            ("skydriveerr-unicode.log", 19, 19, 0, no_problem()),
        ]
    );
    let expected: BTreeSet<String> = expected
        .into_iter()
        .filter(|l| !l.starts_with("odl\t"))
        .collect();
    assert_eq!(expected.len(), 73);
    assert_eq!(got, expected);
}

#[test]
fn messages_keep_their_lines() {
    let log = onedrive::read_text_log(&read("fixtures/plaso/skydrive.log")).unwrap();
    let reply = log
        .entries
        .iter()
        .find(|e| e.message.contains("PNG 110"))
        .unwrap();
    assert_eq!(
        reply.message,
        "Received data from server,dwID=0x0;dwSize=0x40;pbData=PNG 110 CON 48\n\n\
         <ping-response><wait>48</wait></ping-response>"
    );
    assert_eq!(
        (reply.sequence, reply.thread_id),
        (Some(0x67f), Some(0x1998))
    );
    let unicode = onedrive::read_text_log(&read("fixtures/plaso/skydriveerr-unicode.log")).unwrap();
    assert!(unicode
        .entries
        .iter()
        .any(|e| e.message.contains("Passport-Jméno-člena")));
}
