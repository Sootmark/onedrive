//! OneDrive's logs, for forensics: what the sync client did and when,
//! file and folder names included (uploads, downloads, deletions, renames,
//! shares, the accounts signed in).
//!
//! - [`odl`]: the sync engine's binary logs (`*.odl`, `*.odlgz`,
//!   `*.odlsent`, `*.aodl` in
//!   `%LocalAppData%\Microsoft\OneDrive\logs\<Business1|Personal|Common>\`):
//!   each record's time (UTC), the source file, line and function that
//!   logged it, and the strings of its parameters.
//! - [`ObfuscationMap`]: `ObfuscationStringMap.txt`, found beside those
//!   logs, which restores the words OneDrive obfuscated in them.
//! - [`text`]: the text logs the SkyDrive client (OneDrive's earlier name)
//!   wrote, in its two layouts.
//!
//! [`detect`] says which a file is from its first bytes. Damage goes to
//! `problems`, never a panic.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let odl = onedrive::read_odl(&std::fs::read("SyncEngine-2022-11-24.2341.10688.1.odlgz")?)?;
//! let map = onedrive::ObfuscationMap::read(&std::fs::read("ObfuscationStringMap.txt")?);
//! for record in &odl.records {
//!     let parameters: Vec<String> = record.parameters.iter().map(|p| map.deobfuscate(p)).collect();
//!     println!("{:?} {} {:?}", record.time, record.function, parameters);
//! }
//! # Ok(())
//! # }
//! ```

pub mod obfuscation;
pub mod odl;
pub mod text;

pub use obfuscation::ObfuscationMap;
pub use odl::{read_odl, Odl, Record};
pub use text::{read_text_log, Entry, Session, TextLog, TextVersion};

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Which log a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A sync engine log (`.odl`, `.odlgz`, `.odlsent`, `.aodl`).
    Odl,
    /// A SkyDrive text log, in the layout given.
    Text(TextVersion),
}

/// Which log a file starting with `head` is, if one of these.
#[must_use]
pub fn detect(head: &[u8]) -> Option<Kind> {
    if odl::is_odl(head) {
        Some(Kind::Odl)
    } else {
        text::text_version(head).map(Kind::Text)
    }
}

/// Why a file can't be read as the log asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// A file's text: UTF-16LE when it starts with its byte order mark or
/// looks like it (an ASCII character then a zero byte), UTF-8 (lossy)
/// otherwise, without the mark.
fn decode(data: &[u8]) -> String {
    if let Some(rest) = data.strip_prefix(&[0xFF, 0xFE]) {
        common::text::utf16le(rest).text
    } else if matches!(data, [first, 0, ..] if first.is_ascii() && *first != 0) {
        common::text::utf16le(data).text
    } else {
        let rest = data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(data);
        String::from_utf8_lossy(rest).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_each_kind() {
        assert_eq!(detect(b"EBFGONED\x02\x00\x00\x00"), Some(Kind::Odl));
        assert_eq!(
            detect(b"\n######Logging started. Version=17.0.2011.0627"),
            Some(Kind::Text(TextVersion::V2))
        );
        assert_eq!(
            detect(b"08-01-2013 21:22:28.999 global.cpp:626!logVersionInfo (DETAIL): x"),
            Some(Kind::Text(TextVersion::V1))
        );
        assert_eq!(detect(b"Jan 22 07:52:33 host client: INFO"), None);
        assert_eq!(detect(b""), None);
    }

    #[test]
    fn decodes_utf16_with_or_without_its_mark() {
        assert_eq!(decode(b"\xff\xfea\x00b\x00"), "ab");
        assert_eq!(decode(b"a\x00b\x00"), "ab");
        assert_eq!(decode(b"\xef\xbb\xbfab"), "ab");
    }
}
