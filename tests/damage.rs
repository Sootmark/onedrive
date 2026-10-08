//! Arbitrary bytes, the test logs cut anywhere and bytes flipped in them
//! read or are refused: never a panic.

use std::io::Read;

use proptest::prelude::*;

const ODLGZ: &[u8] = include_bytes!("fixtures/plaso/SyncEngine-2022-11-24.2341.10688.1.odlgz");
const TEXT_LOGS: [&[u8]; 4] = [
    include_bytes!("fixtures/plaso/skydrive.log"),
    include_bytes!("fixtures/plaso/skydrive_v1.log"),
    include_bytes!("fixtures/plaso/skydriveerr.log"),
    include_bytes!("fixtures/plaso/skydriveerr-unicode.log"),
];
/// Where the records start in a log.
const HEADER_SIZE: usize = 0x100;

/// The test log with its records decompressed (an `.odl`).
fn odl() -> Vec<u8> {
    let mut data = ODLGZ[..HEADER_SIZE].to_vec();
    common::gzip::Decoder::new(&ODLGZ[HEADER_SIZE..])
        .read_to_end(&mut data)
        .unwrap();
    data
}

fn read_all(data: &[u8]) {
    let _ = onedrive::detect(data);
    let _ = onedrive::read_odl(data);
    let _ = onedrive::read_text_log(data);
    let _ = onedrive::ObfuscationMap::read(data).deobfuscate(&String::from_utf8_lossy(data));
}

#[test]
fn the_decompressed_log_reads_the_same() {
    let compressed = onedrive::read_odl(ODLGZ).unwrap();
    let plain = onedrive::read_odl(&odl()).unwrap();
    assert!(!plain.compressed && plain.problems.is_empty());
    assert_eq!(plain.records.len(), compressed.records.len());
    assert_eq!(plain.records[0].offset, HEADER_SIZE as u64);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        read_all(&data);
        let mut log = b"EBFGONED\x02\x00\x00\x00".to_vec();
        log.resize(HEADER_SIZE, 0);
        log.extend_from_slice(&data);
        let _ = onedrive::read_odl(&log);
    }

    #[test]
    fn logs_cut_anywhere(fraction in 0.0f64..1.0) {
        let plain = odl();
        for data in [ODLGZ, &plain[..]].into_iter().chain(TEXT_LOGS) {
            read_all(&data[..(data.len() as f64 * fraction) as usize]);
        }
    }

    #[test]
    fn bytes_flipped(flips in proptest::collection::vec((0.0f64..1.0, any::<u8>()), 1..16)) {
        for original in [ODLGZ.to_vec(), odl()].into_iter().chain(TEXT_LOGS.map(<[u8]>::to_vec)) {
            let mut data = original;
            for &(at, value) in &flips {
                let at = (data.len() as f64 * at) as usize;
                data[at] ^= value;
            }
            read_all(&data);
        }
    }
}
