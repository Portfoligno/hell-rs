use hell_release_verifier::fuzz::{Target, exercise};

const TAR_BLOCK_BYTES: usize = 512;

#[test]
fn context_bound_targets_reject_structurally_valid_but_unbound_objects() {
    for target in [
        Target::Evidence,
        Target::Ledger,
        Target::PublicationEnvelope,
    ] {
        assert!(
            exercise(target, b"{}\n").is_err(),
            "{target:?} must execute its typed semantic verifier, not only JSON object parsing"
        );
    }
}

#[test]
fn gzip_target_rejects_a_header_and_trailer_without_a_deflate_stream() {
    let bytes = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 255, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(
        exercise(Target::Gzip, &bytes).is_err(),
        "gzip fuzzing must execute bounded decompression and trailer validation"
    );
}

#[test]
fn gnu_tar_target_rejects_a_checksummed_absolute_member_path() {
    let bytes = tar_with_path("/escape.json", b"evidence");
    assert!(
        exercise(Target::GnuTar, &bytes).is_err(),
        "GNU tar fuzzing must execute canonical safe-path validation"
    );
}

fn tar_with_path(path: &str, payload: &[u8]) -> Vec<u8> {
    let mut header = [0_u8; TAR_BLOCK_BYTES];
    header[..path.len()].copy_from_slice(path.as_bytes());
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(
        &mut header[124..136],
        u64::try_from(payload.len()).expect("payload length must fit u64"),
    );
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..265].copy_from_slice(b"ustar  \0");
    write_checksum(&mut header);

    let mut output = header.to_vec();
    output.extend_from_slice(payload);
    let remainder = payload.len() % TAR_BLOCK_BYTES;
    if remainder != 0 {
        output.resize(output.len() + TAR_BLOCK_BYTES - remainder, 0);
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
