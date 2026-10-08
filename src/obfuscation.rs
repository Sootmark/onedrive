//! `ObfuscationStringMap.txt`, beside the logs: what each obfuscated word
//! stands for.
//!
//! OneDrive replaces each word of the paths, names and addresses it logs
//! with a made-up one (`JokeYakLog:\RodOafGad\…`) and keeps the pairs in
//! this file: UTF-16LE text, one `obfuscated<TAB>original` pair per line.
//! A word is what lies between the separators `%`, `\`, `/`, `://`, `?`,
//! `:` and `.`. The first pair of a word is the one used, as plaso does.
//!
//! Logs of recent versions encrypt the words instead, with a key kept in
//! `general.keystore`: those are not restored here.

use std::collections::HashMap;

/// The separators between obfuscated words; `://` is tried before `:`.
const SEPARATORS: [&str; 7] = ["://", "%", "\\", "/", "?", ":", "."];

/// The pairs of an `ObfuscationStringMap.txt`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObfuscationMap {
    words: HashMap<String, String>,
}

impl ObfuscationMap {
    /// Read an `ObfuscationStringMap.txt` (UTF-16LE, byte order mark
    /// optional); lines that aren't one pair are passed over.
    #[must_use]
    pub fn read(data: &[u8]) -> Self {
        let text = common::text::utf16le(data).text;
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        let mut words = HashMap::new();
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            let mut fields = line.split('\t');
            if let (Some(obfuscated), Some(original), None) =
                (fields.next(), fields.next(), fields.next())
            {
                if !obfuscated.is_empty() {
                    words
                        .entry(obfuscated.to_owned())
                        .or_insert_with(|| original.to_owned());
                }
            }
        }
        Self { words }
    }

    /// How many words it maps.
    #[must_use]
    pub fn len(&self) -> usize {
        self.words.len()
    }

    /// Whether it maps none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// The original of one obfuscated word.
    #[must_use]
    pub fn word(&self, obfuscated: &str) -> Option<&str> {
        self.words.get(obfuscated).map(String::as_str)
    }

    /// `text` with each word it maps restored, separators kept.
    #[must_use]
    pub fn deobfuscate(&self, text: &str) -> String {
        let mut restored = String::with_capacity(text.len());
        let mut rest = text;
        while !rest.is_empty() {
            let (word, separator, after) = split_word(rest);
            restored.push_str(self.word(word).unwrap_or(word));
            restored.push_str(separator);
            rest = after;
        }
        restored
    }
}

/// The word `text` starts with, the separator after it (empty at the
/// end) and what follows.
fn split_word(text: &str) -> (&str, &'static str, &str) {
    for (at, _) in text.char_indices() {
        let (word, tail) = (
            text.get(..at).unwrap_or_default(),
            text.get(at..).unwrap_or_default(),
        );
        if let Some(separator) = SEPARATORS.iter().find(|s| tail.starts_with(**s)) {
            return (
                word,
                separator,
                tail.get(separator.len()..).unwrap_or_default(),
            );
        }
    }
    (text, "", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn words_between_separators() {
        let map = ObfuscationMap::read(&utf16(
            "\u{feff}JokeYakLog\tC\r\nRodOafGad\tUsers\r\nRodOafGad\tlater\r\nbad line\r\n",
        ));
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.deobfuscate(r"JokeYakLog:\RodOafGad\x.RodOafGad?a://RodOafGad%"),
            r"C:\Users\x.Users?a://Users%"
        );
        assert_eq!(map.deobfuscate(""), "");
        assert_eq!(map.deobfuscate("::"), "::");
    }
}
