//! The sync engine's binary logs: `*.odl`, `*.odlgz` (the same,
//! gzip-compressed), `*.odlsent` and `*.aodl`, in
//! `%LocalAppData%\Microsoft\OneDrive\logs\<Business1|Personal|Common>\`.
//!
//! A log is a 256-byte header, then its records, all little-endian:
//!
//! - Header: `EBFGONED`, the format version (`u32`, 2 or 3), then at 0x1C
//!   the OneDrive version and at 0x5C the Windows version (64 bytes each,
//!   ASCII, NUL-padded).
//! - At 0x100, either the records or one gzip stream holding them
//!   (`.odlgz`).
//! - A record: a block header, `CC DD EE FF 00 00 00 00`, the time it was
//!   logged (Unix milliseconds, UTC), then in version 2 the process id,
//!   the thread id, a GUID, two unknown `u32`, the size of what follows
//!   and an unknown `u32` (56 bytes); in version 3 two unknown `u32`, the
//!   size and an unknown `u32` (32 bytes). Then what follows: the source
//!   file's name (`u32` length, bytes), the source line, the function's
//!   name (`u32` length, bytes), and the function's parameters.
//!
//! The parameters' layout is not published. Their strings are found the
//! way plaso and the published ODL readers find them: a `u32` length and
//! that many bytes of text, stepping on 4 bytes where none fits. Many are
//! obfuscated (`MawRedNorth`), each word replaced by a random one:
//! [`ObfuscationMap`](crate::ObfuscationMap) restores them.

use std::io::Read;

use common::bytes::Reader;
use common::time::Ts;
use common::win::guid_to_string;

use crate::Error;

/// The header's signature.
const SIGNATURE: &[u8; 8] = b"EBFGONED";
/// The header's size: the records start here.
const HEADER_SIZE: usize = 0x100;
/// Where the format version is.
const VERSION_AT: usize = 8;
/// Where the OneDrive version is.
const ONEDRIVE_VERSION_AT: usize = 0x1C;
/// Where the Windows version is.
const OS_VERSION_AT: usize = 0x5C;
/// The size of each version field.
const VERSION_FIELD_SIZE: usize = 0x40;
/// Each record's signature.
const BLOCK_SIGNATURE: [u8; 8] = [0xCC, 0xDD, 0xEE, 0xFF, 0, 0, 0, 0];
/// The two unknown `u32` before a block header's size.
const UNKNOWN_BEFORE_SIZE: usize = 8;
/// The most bytes a compressed log is decompressed to (logs roll over at a
/// few megabytes).
const MAX_DECOMPRESSED: u64 = 64 << 20;
/// The step taken where no string fits in the parameters.
const PARAMETER_STEP: usize = 4;

/// A sync engine log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Odl {
    /// The format version (2 or 3).
    pub version: u32,
    /// The OneDrive version that wrote it (`21.220.1024.0005`).
    pub onedrive_version: String,
    /// The Windows version it ran on (`10.0.22000`).
    pub os_version: String,
    /// Whether its records were gzip-compressed (`.odlgz`).
    pub compressed: bool,
    /// The records, in file order.
    pub records: Vec<Record>,
    /// Damage met.
    pub problems: Vec<String>,
}

/// A record: one call to the logger.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    /// Where its block starts: in the file, or in the decompressed records
    /// of a compressed log.
    pub offset: u64,
    /// When it was logged (UTC).
    pub time: Option<Ts>,
    /// The process that logged it (version 2; the log's name carries it
    /// too).
    pub process_id: Option<u32>,
    /// The thread that logged it (version 2).
    pub thread_id: Option<u32>,
    /// A GUID records of one session share (version 2).
    pub guid: Option<String>,
    /// The source file that logged it (`SyncServiceProxy.cpp`).
    pub code_file: String,
    /// The line in that file.
    pub code_line: u32,
    /// The function that logged it
    /// (`SyncServiceProxy::OnDownloadedSelectiveSyncEntries`).
    pub function: String,
    /// The strings found in the parameters, as stored (obfuscated or not).
    pub parameters: Vec<String>,
    /// The parameters as stored.
    pub raw_parameters: Vec<u8>,
}

/// Whether `data` starts like a sync engine log.
#[must_use]
pub fn is_odl(data: &[u8]) -> bool {
    data.starts_with(SIGNATURE)
}

/// Read a sync engine log, compressed (`.odlgz`) or not.
///
/// # Errors
/// When it doesn't start with `EBFGONED`.
pub fn read_odl(data: &[u8]) -> Result<Odl, Error> {
    if !is_odl(data) {
        return Err(Error(
            "not a OneDrive log: no EBFGONED signature".to_owned(),
        ));
    }
    let mut odl = Odl {
        version: u32_at(data, VERSION_AT).unwrap_or_default(),
        onedrive_version: ascii_field(data, ONEDRIVE_VERSION_AT),
        os_version: ascii_field(data, OS_VERSION_AT),
        ..Odl::default()
    };
    let Some(body) = data.get(HEADER_SIZE..) else {
        odl.problems.push("header cut short: no records".to_owned());
        return Ok(odl);
    };
    let layout = match odl.version {
        2 => Layout::V2,
        3 => Layout::V3,
        other => {
            odl.problems.push(format!(
                "format version {other} not known: records not read"
            ));
            return Ok(odl);
        }
    };
    if common::gzip::is_gzip(body) {
        odl.compressed = true;
        let records = decompress(body, &mut odl.problems);
        odl.records = read_records(&records, 0, layout, &mut odl.problems);
    } else {
        odl.records = read_records(body, HEADER_SIZE as u64, layout, &mut odl.problems);
    }
    Ok(odl)
}

/// A block header's layout, by format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// Process, thread and GUID before the size: 56 bytes.
    V2,
    /// Two unknown `u32` before the size: 32 bytes.
    V3,
}

impl Layout {
    /// The block header's size: what follows it starts here.
    const fn header_size(self) -> usize {
        match self {
            Self::V2 => 56,
            Self::V3 => 32,
        }
    }
}

/// The little-endian `u32` at `at`.
fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    let mut reader = Reader::new(data);
    reader.seek(at).ok()?;
    reader.u32_le().ok()
}

/// The NUL-padded ASCII text of the version field at `at`.
fn ascii_field(data: &[u8], at: usize) -> String {
    let end = data.len().min(at + VERSION_FIELD_SIZE);
    let field = data.get(at..end).unwrap_or_default();
    let text = field.split(|&b| b == 0).next().unwrap_or_default();
    String::from_utf8_lossy(text).into_owned()
}

/// The records of a compressed log, up to [`MAX_DECOMPRESSED`] bytes;
/// what could be read of a damaged stream.
fn decompress(compressed: &[u8], problems: &mut Vec<String>) -> Vec<u8> {
    let mut records = Vec::new();
    let read = common::gzip::Decoder::new(compressed)
        .take(MAX_DECOMPRESSED + 1)
        .read_to_end(&mut records);
    if let Err(error) = read {
        problems.push(format!("compressed records: {error}"));
    }
    if records.len() as u64 > MAX_DECOMPRESSED {
        records.truncate(MAX_DECOMPRESSED as usize);
        problems.push(format!(
            "compressed records over {} MiB: the rest not read",
            MAX_DECOMPRESSED >> 20
        ));
    }
    records
}

/// Every record in `data`, whose first byte is at `base` in the file (or
/// decompressed records).
fn read_records(data: &[u8], base: u64, layout: Layout, problems: &mut Vec<String>) -> Vec<Record> {
    let mut records = Vec::new();
    let mut at = 0;
    while data.len().saturating_sub(at) > layout.header_size() {
        let offset = base + at as u64;
        let rest = data.get(at..).unwrap_or_default();
        if !rest.starts_with(&BLOCK_SIGNATURE) {
            if rest.iter().all(|&b| b == 0) {
                break;
            }
            let Some(next) = find_block(rest) else {
                problems.push(format!("offset {offset}: no record signature to the end"));
                break;
            };
            problems.push(format!(
                "offset {offset}: no record signature, {next} bytes skipped"
            ));
            at += next;
            continue;
        }
        match read_record(rest, layout) {
            Ok((record, size)) => {
                records.push(Record { offset, ..record });
                at += size;
            }
            Err(what) => {
                problems.push(format!("record at offset {offset}: {what}"));
                at += find_block(rest).unwrap_or(rest.len());
            }
        }
    }
    records
}

/// Where the next record signature after the first byte of `data` is.
fn find_block(data: &[u8]) -> Option<usize> {
    data.get(1..)?
        .windows(BLOCK_SIGNATURE.len())
        .position(|w| w == BLOCK_SIGNATURE)
        .map(|at| at + 1)
}

/// The record at the start of `data` and its size.
fn read_record(data: &[u8], layout: Layout) -> Result<(Record, usize), String> {
    let cut = |_| "cut short".to_owned();
    let mut header = Reader::new(data);
    header.skip(BLOCK_SIGNATURE.len()).map_err(cut)?;
    let millis = header.u64_le().map_err(cut)?;
    let mut record = Record {
        time: i64::try_from(millis)
            .ok()
            .filter(|&ms| ms != 0)
            .map(Ts::from_unix_millis),
        ..Record::default()
    };
    if layout == Layout::V2 {
        record.process_id = Some(header.u32_le().map_err(cut)?);
        record.thread_id = Some(header.u32_le().map_err(cut)?);
        record.guid = Some(guid_to_string(&header.array().map_err(cut)?));
    }
    header.skip(UNKNOWN_BEFORE_SIZE).map_err(cut)?;
    let size = header.u32_le().map_err(cut)? as usize;
    let end = layout
        .header_size()
        .checked_add(size)
        .filter(|&end| end <= data.len())
        .ok_or_else(|| format!("its {size} bytes run past the end"))?;
    let body = data.get(layout.header_size()..end).unwrap_or_default();
    read_body(body, &mut record).ok_or_else(|| "source and function cut short".to_owned())?;
    Ok((record, end))
}

/// The source file, line, function and parameters of a record.
fn read_body(body: &[u8], record: &mut Record) -> Option<()> {
    let mut reader = Reader::new(body);
    record.code_file = counted_name(&mut reader)?;
    record.code_line = reader.u32_le().ok()?;
    record.function = counted_name(&mut reader)?;
    let raw = body.get(reader.position()..).unwrap_or_default();
    record.parameters = parameter_strings(raw);
    record.raw_parameters = raw.to_vec();
    Some(())
}

/// A `u32` length and that many bytes of a name.
fn counted_name(reader: &mut Reader<'_>) -> Option<String> {
    let length = reader.u32_le().ok()? as usize;
    let bytes = reader.bytes(length).ok()?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// The strings in a record's parameters: each a `u32` length and that many
/// bytes of UTF-8 text; where none fits, the search steps on 4 bytes.
#[must_use]
pub fn parameter_strings(raw: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut at = 0;
    while at < raw.len() {
        match counted_text(raw, at) {
            Some(text) => {
                at += PARAMETER_STEP + text.len();
                strings.push(text.to_owned());
            }
            None => at += PARAMETER_STEP,
        }
    }
    strings
}

/// The counted UTF-8 text at `at`, if one fits.
fn counted_text(raw: &[u8], at: usize) -> Option<&str> {
    let mut reader = Reader::new(raw);
    reader.seek(at).ok()?;
    let length = reader.u32_le().ok()? as usize;
    std::str::from_utf8(reader.bytes(length).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(version: u32) -> Vec<u8> {
        let mut data = vec![0u8; HEADER_SIZE];
        data[..8].copy_from_slice(SIGNATURE);
        data[VERSION_AT..VERSION_AT + 4].copy_from_slice(&version.to_le_bytes());
        data[ONEDRIVE_VERSION_AT..ONEDRIVE_VERSION_AT + 4].copy_from_slice(b"23.1");
        data[OS_VERSION_AT..OS_VERSION_AT + 4].copy_from_slice(b"10.0");
        data
    }

    fn body(file: &str, line: u32, function: &str, parameters: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(file.len() as u32).to_le_bytes());
        body.extend_from_slice(file.as_bytes());
        body.extend_from_slice(&line.to_le_bytes());
        body.extend_from_slice(&(function.len() as u32).to_le_bytes());
        body.extend_from_slice(function.as_bytes());
        body.extend_from_slice(parameters);
        body
    }

    #[test]
    fn a_version_3_record() {
        let mut data = header(3);
        let body = body("a.cpp", 12, "A::B", b"\x02\x00\x00\x00hi");
        data.extend_from_slice(&BLOCK_SIGNATURE);
        data.extend_from_slice(&1_669_333_291_913u64.to_le_bytes());
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(&(body.len() as u32).to_le_bytes());
        data.extend_from_slice(&[0; 4]);
        data.extend_from_slice(&body);
        let odl = read_odl(&data).unwrap();
        assert_eq!(odl.problems, Vec::<String>::new());
        assert_eq!((odl.version, odl.onedrive_version.as_str()), (3, "23.1"));
        let record = &odl.records[0];
        assert_eq!(record.offset, 256);
        assert_eq!(
            record.time.and_then(|t| t.ticks()),
            Some(16_693_332_919_130_000)
        );
        assert_eq!((record.code_file.as_str(), record.code_line), ("a.cpp", 12));
        assert_eq!(record.function, "A::B");
        assert_eq!(record.parameters, ["hi"]);
        assert_eq!(record.process_id, None);
    }

    #[test]
    fn strings_step_over_what_is_not_text() {
        let raw =
            b"\x01\x00\x00\x00\xff\x00\x00\x00\x03\x00\x00\x00abc\xff\xff\xff\xff\x00\x00\x00\x00";
        assert_eq!(parameter_strings(raw), ["abc", ""]);
        assert_eq!(
            parameter_strings(b"\xad\x00\x00\x00\x0e\xda\x04\x80"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn damage_is_skipped_to_the_next_record() {
        let mut data = header(2);
        data.extend_from_slice(b"garbage!");
        let body = body("a.cpp", 1, "f", &[]);
        let mut block = BLOCK_SIGNATURE.to_vec();
        block.extend_from_slice(&[0; 40]);
        block.extend_from_slice(&(body.len() as u32).to_le_bytes());
        block.extend_from_slice(&[0; 4]);
        block.extend_from_slice(&body);
        data.extend_from_slice(&block);
        data.extend_from_slice(&[0; 100]);
        let odl = read_odl(&data).unwrap();
        assert_eq!(odl.records.len(), 1);
        assert_eq!(odl.records[0].time, None);
        assert_eq!(
            odl.problems,
            ["offset 256: no record signature, 8 bytes skipped"]
        );
    }

    #[test]
    fn not_a_log() {
        assert!(read_odl(b"EBFGONE").is_err());
        let odl = read_odl(SIGNATURE).unwrap();
        assert_eq!(odl.problems, ["header cut short: no records"]);
    }
}
