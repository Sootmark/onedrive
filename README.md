# onedrive

OneDrive's logs, for forensics: what the sync client did and when, file and folder names included. The sync engine's binary logs (`*.odl`, `*.odlgz`, `*.odlsent`, `*.aodl` in `%LocalAppData%\Microsoft\OneDrive\logs\<Business1|Personal|Common>\`), with the `ObfuscationStringMap.txt` beside them that restores their obfuscated words, and the text logs the SkyDrive client (OneDrive's earlier name) wrote. One dependency, its sibling `sootmark-common` (gzip, times, UTF-16).

```toml
[dependencies]
sootmark-onedrive = "0.1"
```

```rust
let odl = onedrive::read_odl(&std::fs::read("SyncEngine-2022-11-24.2341.10688.1.odlgz")?)?;
let map = onedrive::ObfuscationMap::read(&std::fs::read("ObfuscationStringMap.txt")?);
for record in &odl.records {
    let parameters: Vec<String> = record.parameters.iter().map(|p| map.deobfuscate(p)).collect();
    println!("{:?} {} {:?}", record.time, record.function, parameters);
}
```

## What you get

- `detect(bytes)`: a sync engine log (`EBFGONED`) or a SkyDrive text log of either layout, from its first bytes.
- `read_odl(bytes)`: a sync engine log, gzip-compressed (`.odlgz`) or not, format versions 2 and 3: the OneDrive and Windows versions it was written by and on, and each record's time (UTC, milliseconds), the source file, line and function that logged it (`SyncServiceProxy::OnDownloadedSelectiveSyncEntries`), the process, thread and session GUID (version 2), its raw parameters and the strings found in them.
- `ObfuscationMap::read(bytes)`: `ObfuscationStringMap.txt` (UTF-16LE pairs); `deobfuscate` restores each word of a parameter (`JokeYakLog:\RodOafGad` to `C:\Users`).
- `read_text_log(bytes)`: SkyDrive's text logs (UTF-8 or UTF-16). Version 1 (`MM-DD-YYYY hh:mm:ss.fff source (LEVEL): message`) and version 2 (`######Logging started.` session lines with the client version, start in UTC and local time, process and thread; then comma-separated entries with module, source, level, sequence number and thread). Times in UTC (the logs' own local-time lines show it). The lines continuing an entry (a sync token, a server's reply) stay in its message.
- Damage goes to `problems`, never a panic: records skipped to the next signature, compressed logs read as far as they decompress (64 MiB at most).

## How it's checked

- plaso's test logs (Apache-2.0, `tests/fixtures/plaso/`, see `NOTICE`): every event plaso's `onedrive_log`, `text/skydrive_log_v1` and `text/skydrive_log_v2` parsers read, read the same (`tests/oracle/`): time, source file, function, raw parameters and each string in them; level, module, source and message.
  - The sync engine log: all 3,038 records; psort shows 2,768, the other 270 repeating one to the millisecond, parameters included. Read with its `ObfuscationStringMap.txt`, the same as plaso restores (a second run).
  - SkyDrive version 2 (55 entries in three logs): plaso joins a message's lines with spaces, unevenly; here they keep their line breaks (compared with whitespace collapsed).
  - SkyDrive version 1 (16 entries, 18 plaso events): plaso makes the first line continuing an entry an event of its own (with the entry's time) and drops the others (one here); here they stay in the entry's message. The line with an impossible date (plaso's warning) is an entry without a time, and a problem.
- Parameter strings are UTF-8 here where plaso takes ASCII only: the same on the test log.
- Version 3 records are read from their published layout; no open log of that version exists to check them on.
- Property tests: arbitrary bytes, the logs cut anywhere and bytes flipped in them never panic.

## Not yet

- Decrypting parameters: recent OneDrive versions encrypt the words (AES, the key in `general.keystore`) instead of obfuscating them; those are given as stored.
- The parameters' other values (numbers, flags): their layout isn't published; only their strings are read.

## Licence

MIT or Apache-2.0, at your option.
