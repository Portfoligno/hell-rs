use hell_release_verifier::strict_json::parse_canonical;

#[test]
fn canonical_json_accepts_exact_sorted_unsigned_input() {
    parse_canonical(
        br#"{"a":[0,true,null,"release"],"b":1}
"#,
    )
    .expect("canonical JSON must be admitted");
}

#[test]
fn duplicate_keys_and_trailing_bytes_are_rejected_before_admission() {
    let duplicate = parse_canonical(b"{\"a\":1,\"a\":2}\n").expect_err("duplicate key must fail");
    assert_eq!(duplicate, "duplicate JSON object key \"a\"");

    let trailing = parse_canonical(b"{}\nfalse").expect_err("trailing value must fail");
    assert_eq!(trailing, "trailing JSON data at byte 3");
}

#[test]
fn noncanonical_encodings_are_rejected() {
    for bytes in [
        b"{\"b\":1,\"a\":2}\n".as_slice(),
        b"{ \"a\":1}\n".as_slice(),
        b"{\"a\":1}".as_slice(),
        b"{\"a\":1}\n\n".as_slice(),
        b"{\"a\":\"\\u0061\"}\n".as_slice(),
    ] {
        let error = parse_canonical(bytes).expect_err("noncanonical JSON must fail");
        assert_eq!(
            error, "JSON input is not canonical with exactly one trailing LF",
            "unexpected result for {bytes:?}"
        );
    }
}

#[test]
fn unsupported_numbers_and_invalid_utf8_are_rejected() {
    for bytes in [b"-1\n".as_slice(), b"1.0\n".as_slice(), b"1e1\n".as_slice()] {
        assert!(
            parse_canonical(bytes).is_err(),
            "number must fail: {bytes:?}"
        );
    }
    assert_eq!(
        parse_canonical(&[0xff]).expect_err("invalid UTF-8 must fail"),
        "JSON input is not UTF-8"
    );
}
