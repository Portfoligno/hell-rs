mod support;

use std::fs;

use hell_release_verifier::{ArchiveLimits, read_canonical_gnu_tar_gzip};
use miniz_oxide::deflate::compress_to_vec;
use support::TestDirectory;

const SOURCE_DATE_EPOCH: u64 = 1_800_000_000;
const TAR_BLOCK_BYTES: usize = 512;

#[derive(Clone, Copy)]
struct Member<'a> {
    path: &'a str,
    kind: u8,
    mode: u64,
    payload: &'a [u8],
}

#[test]
fn canonical_archive_is_read_through_the_public_independent_seam() {
    let root = TestDirectory::new("canonical-archive");
    let archive = root.path().join("evidence.tar.gz");
    let members = [
        Member {
            path: "evidence",
            kind: b'5',
            mode: 0o755,
            payload: b"",
        },
        Member {
            path: "evidence/result.json",
            kind: b'0',
            mode: 0o644,
            payload: b"{\"state\":\"verified\"}\n",
        },
    ];
    fs::write(&archive, gzip(&tar(&members, SOURCE_DATE_EPOCH)))
        .expect("write canonical archive fixture");

    let observed =
        read_canonical_gnu_tar_gzip(&archive, Some(SOURCE_DATE_EPOCH), ArchiveLimits::default())
            .expect("canonical archive must be admitted");
    assert_eq!(
        observed.directories.into_iter().collect::<Vec<_>>(),
        ["evidence"]
    );
    assert_eq!(
        observed
            .files
            .get("evidence/result.json")
            .map(Vec::as_slice),
        Some(b"{\"state\":\"verified\"}\n".as_slice())
    );
}

#[test]
fn path_order_and_member_kind_violations_are_rejected() {
    let cases = [
        (
            "escape",
            vec![Member {
                path: "../escape.json",
                kind: b'0',
                mode: 0o644,
                payload: b"x",
            }],
            "tar path is absolute, noncanonical, or escapes its root",
        ),
        (
            "absolute",
            vec![Member {
                path: "/escape.json",
                kind: b'0',
                mode: 0o644,
                payload: b"x",
            }],
            "tar path is absolute, noncanonical, or escapes its root",
        ),
        (
            "duplicate",
            vec![
                Member {
                    path: "same.json",
                    kind: b'0',
                    mode: 0o644,
                    payload: b"a",
                },
                Member {
                    path: "same.json",
                    kind: b'0',
                    mode: 0o644,
                    payload: b"b",
                },
            ],
            "tar contains a duplicate path",
        ),
        (
            "unordered",
            vec![
                Member {
                    path: "z.json",
                    kind: b'0',
                    mode: 0o644,
                    payload: b"z",
                },
                Member {
                    path: "a.json",
                    kind: b'0',
                    mode: 0o644,
                    payload: b"a",
                },
            ],
            "tar paths are not in canonical order",
        ),
        (
            "link",
            vec![Member {
                path: "link",
                kind: b'2',
                mode: 0o777,
                payload: b"",
            }],
            "tar contains a link, extension, or special entry",
        ),
    ];

    for (label, members, expected) in cases {
        let root = TestDirectory::new(label);
        let archive = root.path().join("invalid.tar.gz");
        fs::write(&archive, gzip(&tar(&members, SOURCE_DATE_EPOCH)))
            .expect("write invalid archive fixture");
        let error = read_canonical_gnu_tar_gzip(
            &archive,
            Some(SOURCE_DATE_EPOCH),
            ArchiveLimits::default(),
        )
        .expect_err("invalid archive must fail");
        assert_eq!(error, expected, "unexpected result for {label}");
    }
}

#[test]
fn archive_limits_and_expected_time_are_enforced() {
    let root = TestDirectory::new("archive-limits");
    let archive = root.path().join("bounded.tar.gz");
    let members = [Member {
        path: "result.json",
        kind: b'0',
        mode: 0o644,
        payload: b"release evidence",
    }];
    let bytes = gzip(&tar(&members, SOURCE_DATE_EPOCH));
    fs::write(&archive, &bytes).expect("write bounded archive fixture");

    let compressed_error = read_canonical_gnu_tar_gzip(
        &archive,
        Some(SOURCE_DATE_EPOCH),
        ArchiveLimits {
            maximum_compressed_bytes: bytes.len() - 1,
            ..ArchiveLimits::default()
        },
    )
    .expect_err("compressed byte limit must fail");
    assert_eq!(compressed_error, "archive is not a bounded regular file");

    let member_error = read_canonical_gnu_tar_gzip(
        &archive,
        Some(SOURCE_DATE_EPOCH),
        ArchiveLimits {
            maximum_members: 0,
            ..ArchiveLimits::default()
        },
    )
    .expect_err("member limit must fail");
    assert_eq!(
        member_error,
        "tar member count exceeds the independent verifier limit"
    );

    let path_error = read_canonical_gnu_tar_gzip(
        &archive,
        Some(SOURCE_DATE_EPOCH),
        ArchiveLimits {
            maximum_path_bytes: "result.json".len() - 1,
            ..ArchiveLimits::default()
        },
    )
    .expect_err("path limit must fail");
    assert_eq!(
        path_error,
        "tar path is absolute, noncanonical, or escapes its root"
    );

    let time_error = read_canonical_gnu_tar_gzip(
        &archive,
        Some(SOURCE_DATE_EPOCH + 1),
        ArchiveLimits::default(),
    )
    .expect_err("mtime binding must fail");
    assert_eq!(
        time_error,
        "tar ownership or modification time is not canonical"
    );
}

#[test]
fn gzip_header_crc_and_single_member_requirements_are_enforced() {
    let root = TestDirectory::new("gzip-envelope");
    let archive = root.path().join("gzip.tar.gz");
    let members = [Member {
        path: "result.json",
        kind: b'0',
        mode: 0o644,
        payload: b"evidence",
    }];
    let canonical = gzip(&tar(&members, SOURCE_DATE_EPOCH));

    let mut header = canonical.clone();
    header[3] = 1;
    fs::write(&archive, header).expect("write noncanonical gzip header");
    assert_eq!(
        read_canonical_gnu_tar_gzip(&archive, None, ArchiveLimits::default())
            .expect_err("gzip flags must fail"),
        "gzip header is not the canonical single-member header"
    );

    let mut crc = canonical.clone();
    let trailer = crc.len() - std::mem::size_of::<u64>();
    crc[trailer] ^= 1;
    fs::write(&archive, crc).expect("write invalid gzip CRC");
    assert_eq!(
        read_canonical_gnu_tar_gzip(&archive, None, ArchiveLimits::default())
            .expect_err("gzip CRC must fail"),
        "gzip CRC differs from expanded bytes"
    );

    let mut concatenated = canonical.clone();
    concatenated.extend_from_slice(&canonical);
    fs::write(&archive, concatenated).expect("write concatenated gzip members");
    assert_eq!(
        read_canonical_gnu_tar_gzip(&archive, None, ArchiveLimits::default())
            .expect_err("second gzip member must fail"),
        "gzip contains an invalid stream, trailing bytes, or another member"
    );
}

fn tar(members: &[Member<'_>], mtime: u64) -> Vec<u8> {
    let mut output = Vec::new();
    for member in members {
        let mut header = [0_u8; TAR_BLOCK_BYTES];
        let path = member.path.as_bytes();
        header[..path.len()].copy_from_slice(path);
        write_octal(&mut header[100..108], member.mode);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(
            &mut header[124..136],
            u64::try_from(member.payload.len()).expect("payload length fits u64"),
        );
        write_octal(&mut header[136..148], mtime);
        header[148..156].fill(b' ');
        header[156] = member.kind;
        header[257..265].copy_from_slice(b"ustar  \0");
        write_checksum(&mut header);
        output.extend_from_slice(&header);
        output.extend_from_slice(member.payload);
        let remainder = member.payload.len() % TAR_BLOCK_BYTES;
        if remainder != 0 {
            output.resize(output.len() + TAR_BLOCK_BYTES - remainder, 0);
        }
    }
    output.resize(output.len() + TAR_BLOCK_BYTES * 2, 0);
    output
}

fn write_octal(field: &mut [u8], value: u64) {
    let digits = format!("{value:0width$o}", width = field.len() - 1);
    field[..digits.len()].copy_from_slice(digits.as_bytes());
    field[digits.len()] = 0;
}

fn write_checksum(header: &mut [u8; TAR_BLOCK_BYTES]) {
    header[148..156].fill(b' ');
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
    let field = &mut header[148..156];
    let digits = format!("{checksum:0width$o}", width = field.len() - 2);
    field[..digits.len()].copy_from_slice(digits.as_bytes());
    let terminator = field.len() - 2;
    field[terminator] = 0;
    field[terminator + 1] = b' ';
}

fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut output = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 255];
    output.extend_from_slice(&compress_to_vec(payload, 9));
    output.extend_from_slice(&crc32(payload).to_le_bytes());
    output.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("archive payload length fits gzip trailer")
            .to_le_bytes(),
    );
    output
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..u8::BITS {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
