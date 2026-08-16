//! Exact Windows upstream-presentation dialect authority.

#[cfg(windows)]
use super::{CausalSignal, CoverageEvent, DifferentialMismatch, Observation, SemanticObservation};
use super::{
    ClaimPlatform, DifferentialCase, DifferentialComparisonProjection, Digest, MismatchKind,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsPresentationField {
    Stdout,
    Stderr,
}

impl WindowsPresentationField {
    #[must_use]
    pub const fn mismatch_kind(self) -> MismatchKind {
        match self {
            Self::Stdout => MismatchKind::Stdout,
            Self::Stderr => MismatchKind::Stderr,
        }
    }

    #[must_use]
    pub const fn descriptor_name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

#[derive(Clone, Copy)]
struct WindowsPresentationAuthority {
    case_id: &'static str,
    field: WindowsPresentationField,
    oracle_sha256: &'static str,
    candidate_sha256: &'static str,
    oracle_bytes: u64,
    candidate_bytes: u64,
}

impl WindowsPresentationAuthority {
    const fn new(
        case_id: &'static str,
        field: WindowsPresentationField,
        oracle_sha256: &'static str,
        candidate_sha256: &'static str,
        oracle_bytes: u64,
        candidate_bytes: u64,
    ) -> Self {
        Self {
            case_id,
            field,
            oracle_sha256,
            candidate_sha256,
            oracle_bytes,
            candidate_bytes,
        }
    }
}

// Reviewed from the retained Windows Nightly evidence for candidate e219b2c:
// run 31924866164, job 95110818994, artifact 9257878065. The exact case,
// stream, digest, and length tuple is the authority; a changed upstream or
// candidate presentation remains a mismatch until separately reviewed.
const WINDOWS_PRESENTATION_AUTHORITIES: &[WindowsPresentationAuthority] = &[
    WindowsPresentationAuthority::new(
        "text-decodeutf8-boundary-invalid-encoding",
        WindowsPresentationField::Stderr,
        "93dc2c13553b5e37c537f53ce190d6960af4b66cb575e86cda55fe3bce3c4bc5",
        "aee637cecab61b54303e991bf249aac025246d695e62700ec24368fa0fd72df6",
        79,
        74,
    ),
    WindowsPresentationAuthority::new(
        "text-getcontents-boundary-invalid-encoding",
        WindowsPresentationField::Stderr,
        "93dc2c13553b5e37c537f53ce190d6960af4b66cb575e86cda55fe3bce3c4bc5",
        "aee637cecab61b54303e991bf249aac025246d695e62700ec24368fa0fd72df6",
        79,
        74,
    ),
    WindowsPresentationAuthority::new(
        "text-getline-boundary-empty-input",
        WindowsPresentationField::Stderr,
        "b674b178de9b28517768b33403d4a82763456d28d0d82b3a5e0bfbdf548a5d2f",
        "9b8750bc04bdd988d1c36b403b8505bcea9954f3d21413c45fcc947020af5aa8",
        58,
        53,
    ),
    WindowsPresentationAuthority::new(
        "text-getline-boundary-invalid-encoding",
        WindowsPresentationField::Stderr,
        "93dc2c13553b5e37c537f53ce190d6960af4b66cb575e86cda55fe3bce3c4bc5",
        "aee637cecab61b54303e991bf249aac025246d695e62700ec24368fa0fd72df6",
        79,
        74,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-io-text-writefile-failure",
        WindowsPresentationField::Stderr,
        "141f1a45cb59eca63014792fee352f43ba4c6130b51f77462f2059701c19d7e4",
        "a3db50909c5ad2cc3bda7b624515917870db46770e486e6206a480f23dd983e3",
        95,
        90,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-io-text-appendfile-failure",
        WindowsPresentationField::Stderr,
        "141f1a45cb59eca63014792fee352f43ba4c6130b51f77462f2059701c19d7e4",
        "a3db50909c5ad2cc3bda7b624515917870db46770e486e6206a480f23dd983e3",
        95,
        90,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-io-bytestring-writefile-failure",
        WindowsPresentationField::Stderr,
        "85703f685ad4d156653c58dc57d8c7162f9e5ecaf1693563ace0aab952144f68",
        "327811c6227889ce08125f25b87720e92950f5d84db2f14a67f4748925588d3b",
        95,
        90,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-io-bytestring-readfile-failure",
        WindowsPresentationField::Stderr,
        "da13e4960ec91fa183055ad5c2951b4479b8298bfb00c5687d754c418b657e87",
        "260c082870595b506a69434653d19845742a0fda555a4f4b70b3640c011691ed",
        83,
        78,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-io-bytestring-readprocess-failure",
        WindowsPresentationField::Stderr,
        "f0f98b0178fce59a46a7aa8b0257aeb8003705362788adc6c9bad02793721127",
        "0ab4f485e4bb90a13052e200cc7e9867dae25f4aad2487f9e20e3df550f2f7c2",
        94,
        104,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-io-bytestring-readprocess-checked-failure",
        WindowsPresentationField::Stderr,
        "f0f98b0178fce59a46a7aa8b0257aeb8003705362788adc6c9bad02793721127",
        "0ab4f485e4bb90a13052e200cc7e9867dae25f4aad2487f9e20e3df550f2f7c2",
        94,
        104,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-io-bytestring-readprocess-stdout-checked-failure",
        WindowsPresentationField::Stderr,
        "f0f98b0178fce59a46a7aa8b0257aeb8003705362788adc6c9bad02793721127",
        "0ab4f485e4bb90a13052e200cc7e9867dae25f4aad2487f9e20e3df550f2f7c2",
        94,
        104,
    ),
    WindowsPresentationAuthority::new(
        "runtime-environment-get-env-missing",
        WindowsPresentationField::Stderr,
        "e720299ba1298fa32f73450bd9e81d524479022d2e9070edf0c2ea5ff81e0a0e",
        "358e9842199dc9271d54d315c64547c526e6c3967add09245eee23929eed9c11",
        82,
        77,
    ),
    WindowsPresentationAuthority::new(
        "runtime-io-open-file-failure",
        WindowsPresentationField::Stderr,
        "b5e08b66f2db36d5cf6823e2fb34e974740e5a5ddaee0fe73d4687febf8249d0",
        "dba4477d2e1ec2c416453cee996432246173d3daae558c319ecaebcb0fc7e3a8",
        77,
        72,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-map-singleton-key-strict",
        WindowsPresentationField::Stderr,
        "8a9904dec530003e74f1a6fe77bd7bd1bfe8dda6ee2926b6dd140e8212c0812a",
        "fa248062f52e66117192bad89f3bcea5d310b51e1d3ad6e3ea0ac52e440aea90",
        116,
        109,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-set-singleton-element-strict",
        WindowsPresentationField::Stderr,
        "33780b2c982d74e5bbfbfa22cd6eb24b5f09d7b00b796e8f7debc89d2398e978",
        "ff8413b845776a1fd427079d4909d86058bdec2d84ee6df272088f016e0846d7",
        120,
        113,
    ),
    WindowsPresentationAuthority::new(
        "runtime-io-mapm-failure",
        WindowsPresentationField::Stderr,
        "33dd56c6d03bf32ab12f4d2a60cfa5a2a51e7599ec27bd6d06c87ad0dcf95d39",
        "829f770435e45ecd203fb25e43e497827df361da3004edb83d94a1cd4c6e8848",
        108,
        101,
    ),
    WindowsPresentationAuthority::new(
        "runtime-io-form-failure",
        WindowsPresentationField::Stderr,
        "5768faf9c537e9269307bec5005336d2193985485e4b896eb7fb8e70f3652c4b",
        "8e2327876a4ea33a2b9b1bc32d61477352c7bee6dfee3809e549c8f584d964e1",
        108,
        101,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-timeout-positive-action-failure",
        WindowsPresentationField::Stderr,
        "320ff15ea1f7bdd0bbfa3c82a456bc68bc3fb05206311d60cbdff012d943c662",
        "4ae14de084be4a2c0f2f85cd3cc674f21698413a503815e4a642d6de64a4d36a",
        104,
        97,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-exit-die",
        WindowsPresentationField::Stderr,
        "6c69afecf6aace47b110d70727c7294d3899bbc8c9603f6be36b7a2ebfadbfa8",
        "b672f9eabd6a04f74e79c76da3d495962f5b7b02a6645bce7f67b4660fd69f4a",
        15,
        14,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-alternative-optional-parser-partial",
        WindowsPresentationField::Stderr,
        "f8caf2f5e78bf16d0cf5ac2206dbc192642fb5ebf9f4e270d4f10118c8a69402",
        "5cc14e858652662901009df7eabd7baad47a2cff61267e6f87d67133b84da607",
        74,
        67,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-alternative-many-parser-partial",
        WindowsPresentationField::Stderr,
        "f8caf2f5e78bf16d0cf5ac2206dbc192642fb5ebf9f4e270d4f10118c8a69402",
        "5cc14e858652662901009df7eabd7baad47a2cff61267e6f87d67133b84da607",
        74,
        67,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-functor-fmap-parser-short",
        WindowsPresentationField::Stderr,
        "481c9ab3ea1f849962c54671287218c43ff98061497191e6d68ee2267859c6b6",
        "4adc4f8b07a4b8a9650d831c71abdbbf02b298fe51b11446a296a37b08780319",
        51,
        44,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-functor-operator-parser-short",
        WindowsPresentationField::Stderr,
        "481c9ab3ea1f849962c54671287218c43ff98061497191e6d68ee2267859c6b6",
        "4adc4f8b07a4b8a9650d831c71abdbbf02b298fe51b11446a296a37b08780319",
        51,
        44,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-applicative-apply-parser-absent",
        WindowsPresentationField::Stderr,
        "9b0d04cd5941303babc5b8a014ff23c4f8d70aef6d8780e67b30ac015cdd3613",
        "84f5160ca5a58bf8c9add55ce4a539eb4c42720ff1ee962ae284417f3c46f7f9",
        83,
        76,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-applicative-apply-parser-consumed-missing",
        WindowsPresentationField::Stderr,
        "de5e125345dc1da827077d2ae496d48b723a8ba2cc38530d3fa8e383373b0519",
        "55c250c4ba858904575dc128cc467028aa6ba29d172da0bc49e7ad86069d7d29",
        68,
        61,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-applicative-apply-flipped-parser-absent",
        WindowsPresentationField::Stderr,
        "e225ca736097dae34282fadb91614f36fa8381d4e52cc78722548fbc904e363f",
        "36c973d11a7aefba9899cd80a7eaa98453012f6f7dd47a67394da0598736b6b5",
        83,
        76,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-applicative-apply-flipped-parser-consumed-missing",
        WindowsPresentationField::Stderr,
        "81b14b5b63be6d370fbff4f50fed47066c21afb5f335218ba67ad4fae5ee1291",
        "96401896100185b251793706d54ecdc13b851f2e4bcadeb517b47b2b010d5f84",
        71,
        64,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-semigroup-options-mod-left-right",
        WindowsPresentationField::Stdout,
        "a4063126aa2645c447af4aa8a6d874041bd326ed3f8cc3d13011ddd4dc3f805b",
        "e4739bc631a4c6bbff0cb350a1c837d95295be1aff21369374c2aae82075b8a9",
        101,
        93,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-semigroup-options-mod-right-left",
        WindowsPresentationField::Stdout,
        "a4063126aa2645c447af4aa8a6d874041bd326ed3f8cc3d13011ddd4dc3f805b",
        "e4739bc631a4c6bbff0cb350a1c837d95295be1aff21369374c2aae82075b8a9",
        101,
        93,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-semigroup-options-info-mod-right-precedence",
        WindowsPresentationField::Stdout,
        "c82fee099671ca7e58f374b2280580604c8c4eb7bb860df34411cc0fe4b9d9be",
        "ae5d0d38684cfd1e5b74a44d578dfe91df2d867e97661f5021d603d2936e71ed",
        105,
        95,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-semigroup-options-info-mod-reversed-precedence",
        WindowsPresentationField::Stdout,
        "8aa7efe1c5beca42063cf48a2473e5972438e93e476114eb7fa930cd8a88872f",
        "3cdb164dc51c1537dfede5a2664bb7f113c2bee13fdf104b7bc79295c99f652f",
        104,
        94,
    ),
    WindowsPresentationAuthority::new(
        "runtime-typed-semigroup-options-info-mod-full-description",
        WindowsPresentationField::Stdout,
        "8dca0d712af3dcfdf4901f77280af85e3101c7e1dba26f8882e4f9b52f06c84b",
        "b7f72571b48d969de5b09137495328d1d86297d3c94da3a7b90fad0d82f28f8f",
        104,
        94,
    ),
    WindowsPresentationAuthority::new(
        "runtime-directory-create-directory-failure",
        WindowsPresentationField::Stderr,
        "5f72b449df6301051020f7d1d28d470c4f65e0f337aeb90bbaf5871f66db89c7",
        "1d0379db15acb6699adfddcee5fd762d5446f7a6e5a97e5f080d490e8601edd8",
        190,
        55,
    ),
    WindowsPresentationAuthority::new(
        "runtime-directory-create-directory-if-missing-failure",
        WindowsPresentationField::Stderr,
        "9f609c225513eb8133730562a79c928554f416651759fd351e9a41c1a85dc6af",
        "84aeb1a6d243b39ac57d31547033887fb49c69115ba26596daea3772db8739b8",
        213,
        83,
    ),
    WindowsPresentationAuthority::new(
        "runtime-directory-get-file-size-failure",
        WindowsPresentationField::Stderr,
        "fe2897c210b426beb8a7b9254c56a65dbe102dfb2766bdc64bddb8aa8574a035",
        "714548326ee71324c7e9a04646d62a387ee234e2ecc22b8ef57f39fbaa43c1c7",
        211,
        89,
    ),
    WindowsPresentationAuthority::new(
        "runtime-directory-remove-file-failure",
        WindowsPresentationField::Stderr,
        "a9cba525357b7ea048b4af25b6acdbc567c3f15d50dc99cf0cead8390895fc99",
        "dc56fe58beb4cf06a14cc12d9346b63dc30858f3f6b31d4a5ec87cfed449e351",
        199,
        74,
    ),
    WindowsPresentationAuthority::new(
        "runtime-directory-rename-file-failure",
        WindowsPresentationField::Stderr,
        "7357b47394e0ecfdd8aae8c340910c5cd668cdc18ce4d9b9bd6847e0ab490583",
        "5579b01abfb4f1e982c2c4d81135f64b7184f78851d977374bc6d739e2ca2d64",
        328,
        109,
    ),
    WindowsPresentationAuthority::new(
        "runtime-directory-list-directory-failure",
        WindowsPresentationField::Stderr,
        "329fa6360cfd40abe788d62a7ff38310d9d160231ae7aa7a87d851031f942fdf",
        "0ce16c7c69dd363921fb2b63d63050c5f80a9a11a213fe72707e3ef6d107c796",
        116,
        94,
    ),
    WindowsPresentationAuthority::new(
        "runtime-directory-remove-directory-failure",
        WindowsPresentationField::Stderr,
        "a40d2ebd6ba5c320be872eb37acbb0a50df58b02687d62893af20aa68ff0c55f",
        "21594ac231ee86bf25286c221fb177f9c8ca1b367f4aec19645176bae2dc2d8f",
        196,
        75,
    ),
    WindowsPresentationAuthority::new(
        "runtime-directory-set-current-directory-failure",
        WindowsPresentationField::Stderr,
        "b64a74cd6fa9c3793e388c5a2d23dbaa7eff2c74e2c3611f4249af9e83f7c324",
        "c45b001c6e1d8d7013a7f5efbd3b89408b435e6eb17210de0f91a8e7450e324a",
        102,
        82,
    ),
    WindowsPresentationAuthority::new(
        "runtime-temp-directory-failure",
        WindowsPresentationField::Stderr,
        "320ff15ea1f7bdd0bbfa3c82a456bc68bc3fb05206311d60cbdff012d943c662",
        "4ae14de084be4a2c0f2f85cd3cc674f21698413a503815e4a642d6de64a4d36a",
        104,
        97,
    ),
    WindowsPresentationAuthority::new(
        "runtime-temp-file-failure",
        WindowsPresentationField::Stderr,
        "320ff15ea1f7bdd0bbfa3c82a456bc68bc3fb05206311d60cbdff012d943c662",
        "4ae14de084be4a2c0f2f85cd3cc674f21698413a503815e4a642d6de64a4d36a",
        104,
        97,
    ),
    WindowsPresentationAuthority::new(
        "options-execparser-boundary-absent-option",
        WindowsPresentationField::Stderr,
        "481c9ab3ea1f849962c54671287218c43ff98061497191e6d68ee2267859c6b6",
        "4adc4f8b07a4b8a9650d831c71abdbbf02b298fe51b11446a296a37b08780319",
        51,
        44,
    ),
    WindowsPresentationAuthority::new(
        "options-execparser-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "e37d69e79cabd5f8e94ef005c441c621df40f76346ff19451f49619e26f7cd0f",
        "c743cd74ace8c79ba4ec87e0831bf15fbcb4d9ec5da4e9142ea2b9d7329a900f",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-stroption-boundary-absent-option",
        WindowsPresentationField::Stderr,
        "481c9ab3ea1f849962c54671287218c43ff98061497191e6d68ee2267859c6b6",
        "4adc4f8b07a4b8a9650d831c71abdbbf02b298fe51b11446a296a37b08780319",
        51,
        44,
    ),
    WindowsPresentationAuthority::new(
        "options-stroption-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "f1e2d00f0cf442cb58cf77f8e05659b40a07a23677a39a3f8b1a0b54aa796db0",
        "60b891f1412b50084f35a93658531afe77f60c53185c283d10ff321df48d4327",
        72,
        65,
    ),
    WindowsPresentationAuthority::new(
        "options-strargument-boundary-absent-option",
        WindowsPresentationField::Stderr,
        "920311702d9215aa1f5c521c7c311a14202584f9c216bebfc84336b3dd0c7ee3",
        "a95dd1716f3a4863cde258b33032e166e2e896546826bb8934af63496ea8ab71",
        39,
        32,
    ),
    WindowsPresentationAuthority::new(
        "options-strargument-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "37f4305900e69ab2165b54ee3027d0f97de3b8336ca386eedc5e52f2a26cd3ab",
        "fa9e6b7e0d1d58fc60a6fe8d3e30d0da0a013b8d4abf3da949a07328463ae02c",
        48,
        41,
    ),
    WindowsPresentationAuthority::new(
        "options-strargument-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "f136496b924e91eb5f3a225692be94b78ff3314b124cfce1a708ac1838230da4",
        "aa4fd00211bf5148ca39be97aa40c46969225e762f5ac8201b38ac75e01780bb",
        52,
        45,
    ),
    WindowsPresentationAuthority::new(
        "options-switch-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "7109edc45e50d83f5c654f42c2612423d034bdede918ba9b0f1911d8dd3fa490",
        "cb3dfbdafcd5000a37368b49334d9d96543da2d59566fdff08ad92d535c74696",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-switch-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "e37d69e79cabd5f8e94ef005c441c621df40f76346ff19451f49619e26f7cd0f",
        "c743cd74ace8c79ba4ec87e0831bf15fbcb4d9ec5da4e9142ea2b9d7329a900f",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-flag-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "7109edc45e50d83f5c654f42c2612423d034bdede918ba9b0f1911d8dd3fa490",
        "cb3dfbdafcd5000a37368b49334d9d96543da2d59566fdff08ad92d535c74696",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-flag-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "e37d69e79cabd5f8e94ef005c441c621df40f76346ff19451f49619e26f7cd0f",
        "c743cd74ace8c79ba4ec87e0831bf15fbcb4d9ec5da4e9142ea2b9d7329a900f",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-flag-prime-boundary-absent-option",
        WindowsPresentationField::Stderr,
        "a7c8406d822565d10f56505130e62f4792b7c56f78eb90315dc1809172e7fddb",
        "38882154c2aaa5f4809c3b1eaf1b17eaa7d0b6b854265888c20010bd258ff75c",
        49,
        42,
    ),
    WindowsPresentationAuthority::new(
        "options-flag-prime-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "4c44a823ba865d0985e509ae821edf46b95e87d04c473d0684db16fa6bb53b0e",
        "9825de70ae147797bfbb5309f7996d6a0c210cb89e09aa3f213d6f8198d1bc55",
        57,
        50,
    ),
    WindowsPresentationAuthority::new(
        "options-flag-prime-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "d23897f9d0c3d834409fc07c71b3391c14dd0723ad3460a3e0d63940562504ab",
        "6f727bbc391d23756a70b6b4ef8a70541ce4953142b66f9312ab76272cadb4c5",
        57,
        50,
    ),
    WindowsPresentationAuthority::new(
        "flag-long-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "7109edc45e50d83f5c654f42c2612423d034bdede918ba9b0f1911d8dd3fa490",
        "cb3dfbdafcd5000a37368b49334d9d96543da2d59566fdff08ad92d535c74696",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "flag-long-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "e37d69e79cabd5f8e94ef005c441c621df40f76346ff19451f49619e26f7cd0f",
        "c743cd74ace8c79ba4ec87e0831bf15fbcb4d9ec5da4e9142ea2b9d7329a900f",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "flag-help-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "7109edc45e50d83f5c654f42c2612423d034bdede918ba9b0f1911d8dd3fa490",
        "cb3dfbdafcd5000a37368b49334d9d96543da2d59566fdff08ad92d535c74696",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "flag-help-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "e37d69e79cabd5f8e94ef005c441c621df40f76346ff19451f49619e26f7cd0f",
        "c743cd74ace8c79ba4ec87e0831bf15fbcb4d9ec5da4e9142ea2b9d7329a900f",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "option-long-boundary-absent-option",
        WindowsPresentationField::Stderr,
        "481c9ab3ea1f849962c54671287218c43ff98061497191e6d68ee2267859c6b6",
        "4adc4f8b07a4b8a9650d831c71abdbbf02b298fe51b11446a296a37b08780319",
        51,
        44,
    ),
    WindowsPresentationAuthority::new(
        "option-long-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "f1e2d00f0cf442cb58cf77f8e05659b40a07a23677a39a3f8b1a0b54aa796db0",
        "60b891f1412b50084f35a93658531afe77f60c53185c283d10ff321df48d4327",
        72,
        65,
    ),
    WindowsPresentationAuthority::new(
        "option-help-boundary-absent-option",
        WindowsPresentationField::Stderr,
        "481c9ab3ea1f849962c54671287218c43ff98061497191e6d68ee2267859c6b6",
        "4adc4f8b07a4b8a9650d831c71abdbbf02b298fe51b11446a296a37b08780319",
        51,
        44,
    ),
    WindowsPresentationAuthority::new(
        "option-help-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "f1e2d00f0cf442cb58cf77f8e05659b40a07a23677a39a3f8b1a0b54aa796db0",
        "60b891f1412b50084f35a93658531afe77f60c53185c283d10ff321df48d4327",
        72,
        65,
    ),
    WindowsPresentationAuthority::new(
        "runtime-parser-observable-flag-help",
        WindowsPresentationField::Stdout,
        "1a7f93cb903dd8fd6d0bd8e76bc4e5121c5c9008dbb439b0e2078ed6b9db5996",
        "0306395e110352a4ade2f41e59833a74a20c6595e048b2976246058936cca95a",
        137,
        128,
    ),
    WindowsPresentationAuthority::new(
        "runtime-parser-observable-option-help",
        WindowsPresentationField::Stdout,
        "743717997da0e5ee96ab6e59813f457b40adf26376b079f52de1d06b025aca8d",
        "aa92aa4766c6baea6eee179ea2d574365b6506b03a73f5e180e5702fbd4bec57",
        138,
        129,
    ),
    WindowsPresentationAuthority::new(
        "argument-metavar-boundary-absent-option",
        WindowsPresentationField::Stderr,
        "920311702d9215aa1f5c521c7c311a14202584f9c216bebfc84336b3dd0c7ee3",
        "a95dd1716f3a4863cde258b33032e166e2e896546826bb8934af63496ea8ab71",
        39,
        32,
    ),
    WindowsPresentationAuthority::new(
        "argument-metavar-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "37f4305900e69ab2165b54ee3027d0f97de3b8336ca386eedc5e52f2a26cd3ab",
        "fa9e6b7e0d1d58fc60a6fe8d3e30d0da0a013b8d4abf3da949a07328463ae02c",
        48,
        41,
    ),
    WindowsPresentationAuthority::new(
        "argument-metavar-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "f136496b924e91eb5f3a225692be94b78ff3314b124cfce1a708ac1838230da4",
        "aa4fd00211bf5148ca39be97aa40c46969225e762f5ac8201b38ac75e01780bb",
        52,
        45,
    ),
    WindowsPresentationAuthority::new(
        "argument-help-boundary-absent-option",
        WindowsPresentationField::Stderr,
        "920311702d9215aa1f5c521c7c311a14202584f9c216bebfc84336b3dd0c7ee3",
        "a95dd1716f3a4863cde258b33032e166e2e896546826bb8934af63496ea8ab71",
        39,
        32,
    ),
    WindowsPresentationAuthority::new(
        "argument-help-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "37f4305900e69ab2165b54ee3027d0f97de3b8336ca386eedc5e52f2a26cd3ab",
        "fa9e6b7e0d1d58fc60a6fe8d3e30d0da0a013b8d4abf3da949a07328463ae02c",
        48,
        41,
    ),
    WindowsPresentationAuthority::new(
        "argument-help-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "f136496b924e91eb5f3a225692be94b78ff3314b124cfce1a708ac1838230da4",
        "aa4fd00211bf5148ca39be97aa40c46969225e762f5ac8201b38ac75e01780bb",
        52,
        45,
    ),
    WindowsPresentationAuthority::new(
        "runtime-parser-observable-argument-metavar",
        WindowsPresentationField::Stdout,
        "d3ed793644a78529f8cf47bd9ffde2881aebe7ae12b23badaf55ef2adf6ae0b6",
        "873508baf04f1f2d3f6f6eacb14a1f1af25a9c3204ae81dfdcdd67dffd4166a5",
        92,
        84,
    ),
    WindowsPresentationAuthority::new(
        "runtime-parser-observable-argument-help",
        WindowsPresentationField::Stdout,
        "744d42820b0d887b4fba9bfb94a231f07ae67ba9285d8daee4b7b4bf71c25ddb",
        "6769eb0c62233c3e170e41b2a51dd86f96a06bfe6df74841587a0ecc1f1dd275",
        132,
        123,
    ),
    WindowsPresentationAuthority::new(
        "option-value-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "75c508105d284ebcc581184d7bbdfa6cbc061d2a013a7732d38a0c9076576f5d",
        "ef1042017d3106071ef1d2b1910f245751c5282d61e4c42b784c71dba55f696a",
        57,
        50,
    ),
    WindowsPresentationAuthority::new(
        "option-value-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "f8caf2f5e78bf16d0cf5ac2206dbc192642fb5ebf9f4e270d4f10118c8a69402",
        "5cc14e858652662901009df7eabd7baad47a2cff61267e6f87d67133b84da607",
        74,
        67,
    ),
    WindowsPresentationAuthority::new(
        "argument-value-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "634e1d24ee78f4de56906c14c7c52171923524983b225cc2e879fa94f3a17bc3",
        "84c41858011b01d33a38119f4f963602b87d6a7ac686f0f2bb649a6da1ebbdda",
        50,
        43,
    ),
    WindowsPresentationAuthority::new(
        "argument-value-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "1d2f32b396217db19ac9422d448e0286ab1efc10430d0e059d55148518286194",
        "256bdea9a6057d87a9953cd789d29649eba046f2c420b6bd88d0fc16a0997628",
        54,
        47,
    ),
    WindowsPresentationAuthority::new(
        "options-header-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "7109edc45e50d83f5c654f42c2612423d034bdede918ba9b0f1911d8dd3fa490",
        "cb3dfbdafcd5000a37368b49334d9d96543da2d59566fdff08ad92d535c74696",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-header-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "e37d69e79cabd5f8e94ef005c441c621df40f76346ff19451f49619e26f7cd0f",
        "c743cd74ace8c79ba4ec87e0831bf15fbcb4d9ec5da4e9142ea2b9d7329a900f",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-progdesc-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "84483b473791206a266691cf6f31220c1d81104a28d94a9003b4636b7ac3da69",
        "be15bc7db9aac90ec786c347381782d2e73246e3ad1833d6882a31726b44bbee",
        85,
        76,
    ),
    WindowsPresentationAuthority::new(
        "options-progdesc-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "c5e37d8591780e94ba007f78efddb5550388397d5e5f53bc5c126e7ecd0987b4",
        "7d6a740058ffa1234f3c9a711c60560f5ae7c389f64a7cbbbcf0d42e16136a6f",
        85,
        76,
    ),
    WindowsPresentationAuthority::new(
        "options-helper-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "7109edc45e50d83f5c654f42c2612423d034bdede918ba9b0f1911d8dd3fa490",
        "cb3dfbdafcd5000a37368b49334d9d96543da2d59566fdff08ad92d535c74696",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-helper-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "e37d69e79cabd5f8e94ef005c441c621df40f76346ff19451f49619e26f7cd0f",
        "c743cd74ace8c79ba4ec87e0831bf15fbcb4d9ec5da4e9142ea2b9d7329a900f",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-info-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "7109edc45e50d83f5c654f42c2612423d034bdede918ba9b0f1911d8dd3fa490",
        "cb3dfbdafcd5000a37368b49334d9d96543da2d59566fdff08ad92d535c74696",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-info-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "e37d69e79cabd5f8e94ef005c441c621df40f76346ff19451f49619e26f7cd0f",
        "c743cd74ace8c79ba4ec87e0831bf15fbcb4d9ec5da4e9142ea2b9d7329a900f",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-fulldesc-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "7109edc45e50d83f5c654f42c2612423d034bdede918ba9b0f1911d8dd3fa490",
        "cb3dfbdafcd5000a37368b49334d9d96543da2d59566fdff08ad92d535c74696",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-fulldesc-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "e37d69e79cabd5f8e94ef005c441c621df40f76346ff19451f49619e26f7cd0f",
        "c743cd74ace8c79ba4ec87e0831bf15fbcb4d9ec5da4e9142ea2b9d7329a900f",
        59,
        52,
    ),
    WindowsPresentationAuthority::new(
        "options-command-boundary-absent-option",
        WindowsPresentationField::Stderr,
        "de470b3e60b447fbf0b49ea7f95bbd5e72ea7a1df257b9c2780c5b9d84919a70",
        "bd4cc60b1374bcdb6f974031ee2d4437056a083bee7d03fc2e16babd679814e2",
        45,
        38,
    ),
    WindowsPresentationAuthority::new(
        "options-command-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "4f4db9b1e591f1dcb6c96ddaa73ccda9008cd6b82d87d041612f692ce9267f04",
        "93f9228b05bb00585645e80421788116b0288f46589e717e2dc3b5a7da54d778",
        51,
        44,
    ),
    WindowsPresentationAuthority::new(
        "options-command-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "563191e1b5c2c7bcdb537bfb3f251669d6d9fcc5b1f3084d9ecb86a7b45eaf0d",
        "e285bcce1e4bbf73318f709c7e5d67010641b47b1772c8272bc25d683bd233ff",
        55,
        48,
    ),
    WindowsPresentationAuthority::new(
        "options-hsubparser-boundary-absent-option",
        WindowsPresentationField::Stderr,
        "de470b3e60b447fbf0b49ea7f95bbd5e72ea7a1df257b9c2780c5b9d84919a70",
        "bd4cc60b1374bcdb6f974031ee2d4437056a083bee7d03fc2e16babd679814e2",
        45,
        38,
    ),
    WindowsPresentationAuthority::new(
        "options-hsubparser-boundary-repeated-option",
        WindowsPresentationField::Stderr,
        "4f4db9b1e591f1dcb6c96ddaa73ccda9008cd6b82d87d041612f692ce9267f04",
        "93f9228b05bb00585645e80421788116b0288f46589e717e2dc3b5a7da54d778",
        51,
        44,
    ),
    WindowsPresentationAuthority::new(
        "options-hsubparser-boundary-malformed-option",
        WindowsPresentationField::Stderr,
        "563191e1b5c2c7bcdb537bfb3f251669d6d9fcc5b1f3084d9ecb86a7b45eaf0d",
        "e285bcce1e4bbf73318f709c7e5d67010641b47b1772c8272bc25d683bd233ff",
        55,
        48,
    ),
    WindowsPresentationAuthority::new(
        "runtime-parser-observable-options-header",
        WindowsPresentationField::Stdout,
        "dc548678891636910f159415be52328b7bbcf52510ab8ca6849e62cfd54845b3",
        "84c02d6d73bd65fffac7db788ccf4c1ae272c3fda6886e7882f424b21eb4423c",
        118,
        108,
    ),
    WindowsPresentationAuthority::new(
        "runtime-parser-observable-options-progdesc",
        WindowsPresentationField::Stdout,
        "52246d61b52c2401b024a85bd6b6383a91c062c7399d499febadc8841a6ee797",
        "1c625a85adc094f996c530bcaa516e91e6a750f6915535031aca48854888fb9a",
        125,
        115,
    ),
    WindowsPresentationAuthority::new(
        "runtime-parser-observable-options-helper",
        WindowsPresentationField::Stdout,
        "990abb06d3bc3a0f85ecdb23e3525f23e03b4a4608d2f24df35c019fe6560387",
        "bed301cf85e3ce6e6eef88165b28cbc90e9285b98dad047ff49b51f1df3e5df5",
        99,
        91,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-command",
        WindowsPresentationField::Stdout,
        "8bb842b88bf49699b871838ba420a50951200060dbd43a0fb5f8f46d64a45333",
        "e65e93c90a1853b63c41732d4ae36deff514935f2bb472a23ba0dbb0cbe04cc9",
        153,
        142,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-exec-parser",
        WindowsPresentationField::Stdout,
        "990abb06d3bc3a0f85ecdb23e3525f23e03b4a4608d2f24df35c019fe6560387",
        "bed301cf85e3ce6e6eef88165b28cbc90e9285b98dad047ff49b51f1df3e5df5",
        99,
        91,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-flag",
        WindowsPresentationField::Stdout,
        "990abb06d3bc3a0f85ecdb23e3525f23e03b4a4608d2f24df35c019fe6560387",
        "bed301cf85e3ce6e6eef88165b28cbc90e9285b98dad047ff49b51f1df3e5df5",
        99,
        91,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-flag-prime",
        WindowsPresentationField::Stdout,
        "2e1c5fcdd683b1b34bdf097314f001f54fa2fc101e1bd50c743547eaefa3a293",
        "8e3dc6c88394e67b1504a0835dcd12c9d45874f458382a34d3b985923a7d9ab3",
        97,
        89,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-full-desc",
        WindowsPresentationField::Stdout,
        "990abb06d3bc3a0f85ecdb23e3525f23e03b4a4608d2f24df35c019fe6560387",
        "bed301cf85e3ce6e6eef88165b28cbc90e9285b98dad047ff49b51f1df3e5df5",
        99,
        91,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-header",
        WindowsPresentationField::Stdout,
        "dc548678891636910f159415be52328b7bbcf52510ab8ca6849e62cfd54845b3",
        "84c02d6d73bd65fffac7db788ccf4c1ae272c3fda6886e7882f424b21eb4423c",
        118,
        108,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-helper",
        WindowsPresentationField::Stdout,
        "990abb06d3bc3a0f85ecdb23e3525f23e03b4a4608d2f24df35c019fe6560387",
        "bed301cf85e3ce6e6eef88165b28cbc90e9285b98dad047ff49b51f1df3e5df5",
        99,
        91,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-hsubparser",
        WindowsPresentationField::Stdout,
        "8bb842b88bf49699b871838ba420a50951200060dbd43a0fb5f8f46d64a45333",
        "e65e93c90a1853b63c41732d4ae36deff514935f2bb472a23ba0dbb0cbe04cc9",
        153,
        142,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-info",
        WindowsPresentationField::Stdout,
        "990abb06d3bc3a0f85ecdb23e3525f23e03b4a4608d2f24df35c019fe6560387",
        "bed301cf85e3ce6e6eef88165b28cbc90e9285b98dad047ff49b51f1df3e5df5",
        99,
        91,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-prog-desc",
        WindowsPresentationField::Stdout,
        "52246d61b52c2401b024a85bd6b6383a91c062c7399d499febadc8841a6ee797",
        "1c625a85adc094f996c530bcaa516e91e6a750f6915535031aca48854888fb9a",
        125,
        115,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-str-argument",
        WindowsPresentationField::Stdout,
        "d3ed793644a78529f8cf47bd9ffde2881aebe7ae12b23badaf55ef2adf6ae0b6",
        "873508baf04f1f2d3f6f6eacb14a1f1af25a9c3204ae81dfdcdd67dffd4166a5",
        92,
        84,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-str-option",
        WindowsPresentationField::Stdout,
        "f6733cb08444b77aebce37174e7e6baf9ded97f5122e8861e1de88c8ae9a703d",
        "5e7aa3b31d1c0bdf35dcb1b155d8bfd13a30a3b63aa8193b6d6dff653d9f1c89",
        98,
        90,
    ),
    WindowsPresentationAuthority::new(
        "runtime-options-presentation-switch",
        WindowsPresentationField::Stdout,
        "990abb06d3bc3a0f85ecdb23e3525f23e03b4a4608d2f24df35c019fe6560387",
        "bed301cf85e3ce6e6eef88165b28cbc90e9285b98dad047ff49b51f1df3e5df5",
        99,
        91,
    ),
    WindowsPresentationAuthority::new(
        "list-cycle-boundary-empty-input",
        WindowsPresentationField::Stderr,
        "885a7f438469051d3b200b2a66bc2eadf508c953066720cc214ce66ba22f9913",
        "23550ac659ca952c5bfca4665d67808675625a7d96ef381b579d116a982b6a31",
        272,
        263,
    ),
    WindowsPresentationAuthority::new(
        "list-take-boundary-bottom-after-demanded-prefix",
        WindowsPresentationField::Stderr,
        "d7b258c41cdf1a3f77941174c9285b70e24d1d022ed6eabf776a7351ed3e5d74",
        "0bb4f4b972b90acbad16930068486ec15dd8e2f4ce50cdfd387994c6933926d4",
        116,
        109,
    ),
    WindowsPresentationAuthority::new(
        "runtime-interaction-list-laziness-error",
        WindowsPresentationField::Stderr,
        "4a392e1d7066a083ce3a3d91fb320ec379035cc8e5952826df4993bb6bb2752c",
        "0278c6b8bbbf40df5da18a70fa1cc69f9cc07541f1604752411b1e3c9bcd2da1",
        114,
        107,
    ),
    WindowsPresentationAuthority::new(
        "runtime-interaction-http-stream-disconnect",
        WindowsPresentationField::Stderr,
        "50cac504ce055439bf141d98894092ec620d710730dc9880b450b0eeb20269fe",
        "2b00ccdd1659ff64fb1cf2e741aa92fb28cf619603057adf0b2167be3919e8cb",
        184,
        74,
    ),
];

#[cfg(windows)]
fn target_platform_is_windows(platforms: &[ClaimPlatform]) -> bool {
    platforms.contains(&ClaimPlatform::All) || platforms.contains(&ClaimPlatform::Windows)
}

#[cfg(windows)]
fn semantic_causality_matches(
    signal: CausalSignal,
    builtin: super::BuiltinId,
    semantic: &SemanticObservation,
) -> bool {
    let has = |predicate: fn(&CoverageEvent, super::BuiltinId) -> bool| {
        semantic
            .coverage
            .iter()
            .any(|event| predicate(event, builtin))
    };
    match signal {
        CausalSignal::ParsedBuiltin => has(
            |event, builtin| matches!(event, CoverageEvent::ParsedBuiltin(found) if *found == builtin),
        ),
        CausalSignal::ResolvedBuiltin => has(
            |event, builtin| matches!(event, CoverageEvent::ResolvedBuiltin(found) if *found == builtin),
        ),
        CausalSignal::SpecializedBuiltin => has(
            |event, builtin| matches!(event, CoverageEvent::SpecializedBuiltin(found) if *found == builtin),
        ),
        CausalSignal::RuntimeAdapter => has(
            |event, builtin| matches!(event, CoverageEvent::EnteredAdapter(found) if *found == builtin),
        ),
        CausalSignal::RuntimeAdapterAndForceTrace => {
            has(
                |event, builtin| matches!(event, CoverageEvent::EnteredAdapter(found) if *found == builtin),
            ) && has(
                |event, builtin| matches!(event, CoverageEvent::ForcedArgument(found, _) if *found == builtin),
            )
        }
        CausalSignal::ForceTrace => has(
            |event, builtin| matches!(event, CoverageEvent::ForcedArgument(found, _) if *found == builtin),
        ),
        CausalSignal::EffectEvent => has(
            |event, builtin| matches!(event, CoverageEvent::ExecutedEffect(found, _) if *found == builtin),
        ),
        CausalSignal::TaskAndCancellation => has(
            |event, builtin| matches!(event, CoverageEvent::TaskEvent(found, _) if *found == builtin),
        ),
        CausalSignal::PresentationField => has(
            |event, builtin| matches!(event, CoverageEvent::PresentedField(found, _) if *found == builtin),
        ),
        CausalSignal::ResourceLifecycle => has(
            |event, builtin| matches!(event, CoverageEvent::AcquiredResource(found, _) if *found == builtin),
        ),
    }
}

#[cfg(windows)]
fn case_has_windows_semantic_causality(case: &DifferentialCase, candidate: &Observation) -> bool {
    let Some(descriptor) = case.claim_evidence.as_ref() else {
        return false;
    };
    let Some(semantic) = candidate.semantic.as_ref() else {
        return false;
    };
    super::validate_case_descriptor(case, descriptor).is_ok()
        && super::validate_legacy_targets(case, descriptor).is_ok()
        && super::validate_semantic_targets(case, descriptor).is_ok()
        && super::validate_callback_contracts(case, descriptor).is_ok()
        && descriptor.semantic_targets.iter().any(|target| {
            target_platform_is_windows(&target.platforms)
                && hell_builtins::lookup(&target.builtin).is_some_and(|spec| {
                    semantic_causality_matches(target.causal_signal, spec.id, semantic)
                })
        })
}

#[cfg(windows)]
fn observations_are_bound(
    case: &DifferentialCase,
    oracle: &Observation,
    candidate: &Observation,
) -> bool {
    oracle.identity.role == super::ExecutableRole::Oracle
        && candidate.identity.role == super::ExecutableRole::Candidate
        && oracle.case_id == case.id
        && candidate.case_id == case.id
        && oracle.environment_profile == case.environment_profile
        && candidate.environment_profile == case.environment_profile
        && oracle.process_helper_sha256 == case.process_helper_sha256
        && candidate.process_helper_sha256 == case.process_helper_sha256
        && oracle.harness_normalizers == super::applied_harness_normalizers()
        && candidate.harness_normalizers == super::applied_harness_normalizers()
        && oracle.claim_normalizers == super::applied_claim_normalizers(case)
        && candidate.claim_normalizers == super::applied_claim_normalizers(case)
        && oracle.mode == candidate.mode
}

#[cfg(windows)]
pub fn reviewed_windows_presentation_projection(
    platform: ClaimPlatform,
    case: &DifferentialCase,
    oracle: &Observation,
    candidate: &Observation,
    mismatches: &[DifferentialMismatch],
) -> Option<DifferentialComparisonProjection> {
    if platform != ClaimPlatform::Windows
        || mismatches.len() != 1
        || !observations_are_bound(case, oracle, candidate)
        || !case_has_windows_semantic_causality(case, candidate)
    {
        return None;
    }
    let authority = WINDOWS_PRESENTATION_AUTHORITIES
        .iter()
        .find(|authority| authority.case_id == case.id.as_ref())?;
    let mismatch = &mismatches[0];
    if mismatch.kind != authority.field.mismatch_kind() {
        return None;
    }
    let (oracle_capture, candidate_capture) = match authority.field {
        WindowsPresentationField::Stdout => (&oracle.stdout, &candidate.stdout),
        WindowsPresentationField::Stderr => (&oracle.stderr, &candidate.stderr),
    };
    let oracle_sha256 = Digest::from_hex(authority.oracle_sha256).ok()?;
    let candidate_sha256 = Digest::from_hex(authority.candidate_sha256).ok()?;
    if oracle_capture.sha256 != oracle_sha256
        || candidate_capture.sha256 != candidate_sha256
        || oracle_capture.total_bytes != authority.oracle_bytes
        || candidate_capture.total_bytes != authority.candidate_bytes
    {
        return None;
    }
    Some(
        DifferentialComparisonProjection::ReviewedWindowsPresentation {
            platform,
            field: authority.field,
            oracle_sha256,
            candidate_sha256,
            oracle_bytes: authority.oracle_bytes,
            candidate_bytes: authority.candidate_bytes,
        },
    )
}

pub fn retained_windows_presentation_projection(
    case: &DifferentialCase,
    mismatches: &[(MismatchKind, Digest, Digest, u64, u64)],
) -> Option<DifferentialComparisonProjection> {
    let authority = WINDOWS_PRESENTATION_AUTHORITIES
        .iter()
        .find(|authority| authority.case_id == case.id.as_ref())?;
    let [(kind, oracle_sha256, candidate_sha256, oracle_bytes, candidate_bytes)] = mismatches
    else {
        return None;
    };
    let expected_oracle = Digest::from_hex(authority.oracle_sha256).ok()?;
    let expected_candidate = Digest::from_hex(authority.candidate_sha256).ok()?;
    if *kind != authority.field.mismatch_kind()
        || *oracle_sha256 != expected_oracle
        || *candidate_sha256 != expected_candidate
        || *oracle_bytes != authority.oracle_bytes
        || *candidate_bytes != authority.candidate_bytes
    {
        return None;
    }
    Some(
        DifferentialComparisonProjection::ReviewedWindowsPresentation {
            platform: ClaimPlatform::Windows,
            field: authority.field,
            oracle_sha256: expected_oracle,
            candidate_sha256: expected_candidate,
            oracle_bytes: authority.oracle_bytes,
            candidate_bytes: authority.candidate_bytes,
        },
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn exact_e219_windows_authority_projects_114_presentation_cases_only() {
        let ids = WINDOWS_PRESENTATION_AUTHORITIES
            .iter()
            .map(|authority| authority.case_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(WINDOWS_PRESENTATION_AUTHORITIES.len(), 114);
        assert_eq!(ids.len(), WINDOWS_PRESENTATION_AUTHORITIES.len());
        assert_eq!(
            WINDOWS_PRESENTATION_AUTHORITIES
                .iter()
                .filter(|authority| authority.field == WindowsPresentationField::Stdout)
                .count(),
            25,
        );
        assert_eq!(
            WINDOWS_PRESENTATION_AUTHORITIES
                .iter()
                .filter(|authority| authority.field == WindowsPresentationField::Stderr)
                .count(),
            89,
        );
        for substantive in [
            "runtime-typed-thread-delay-forced-argument-failure",
            "runtime-directory-copy-file-failure",
            "runtime-directory-get-home-home-a",
            "runtime-directory-get-home-home-b",
            "runtime-interaction-timeout-process",
        ] {
            assert!(!ids.contains(substantive));
        }

        let cases = super::super::corpus::committed_differential_cases();
        for authority in WINDOWS_PRESENTATION_AUTHORITIES {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == authority.case_id)
                .unwrap_or_else(|| panic!("missing reviewed case {}", authority.case_id));
            let descriptor = case
                .claim_evidence
                .as_ref()
                .expect("reviewed Windows presentation case has a descriptor");
            assert!(
                descriptor.semantic_targets.iter().any(|target| {
                    target.platforms.contains(&ClaimPlatform::All)
                        || target.platforms.contains(&ClaimPlatform::Windows)
                }),
                "{} lacks Windows semantic authority",
                authority.case_id,
            );
            assert!(Digest::from_hex(authority.oracle_sha256).is_ok());
            assert!(Digest::from_hex(authority.candidate_sha256).is_ok());
            assert_ne!(authority.oracle_sha256, authority.candidate_sha256);
            assert!(authority.oracle_bytes > 0 || authority.candidate_bytes > 0);
            let retained = [(
                authority.field.mismatch_kind(),
                Digest::from_hex(authority.oracle_sha256).unwrap(),
                Digest::from_hex(authority.candidate_sha256).unwrap(),
                authority.oracle_bytes,
                authority.candidate_bytes,
            )];
            assert!(
                retained_windows_presentation_projection(case, &retained).is_some(),
                "{} did not replay as the reviewed Windows dialect",
                authority.case_id,
            );
        }
    }

    #[test]
    fn retained_windows_projection_rejects_field_hash_size_and_case_substitution() {
        let cases = super::super::corpus::committed_differential_cases();
        let authority = WINDOWS_PRESENTATION_AUTHORITIES[0];
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == authority.case_id)
            .expect("first reviewed case");
        let oracle = Digest::from_hex(authority.oracle_sha256).unwrap();
        let candidate = Digest::from_hex(authority.candidate_sha256).unwrap();
        let exact = [(
            authority.field.mismatch_kind(),
            oracle,
            candidate,
            authority.oracle_bytes,
            authority.candidate_bytes,
        )];
        assert!(retained_windows_presentation_projection(case, &exact).is_some());

        let wrong_field = [(
            match authority.field {
                WindowsPresentationField::Stdout => MismatchKind::Stderr,
                WindowsPresentationField::Stderr => MismatchKind::Stdout,
            },
            oracle,
            candidate,
            authority.oracle_bytes,
            authority.candidate_bytes,
        )];
        assert!(retained_windows_presentation_projection(case, &wrong_field).is_none());
        let wrong_hash = [(
            authority.field.mismatch_kind(),
            candidate,
            oracle,
            authority.oracle_bytes,
            authority.candidate_bytes,
        )];
        assert!(retained_windows_presentation_projection(case, &wrong_hash).is_none());
        let wrong_size = [(
            authority.field.mismatch_kind(),
            oracle,
            candidate,
            authority.oracle_bytes.saturating_add(1),
            authority.candidate_bytes,
        )];
        assert!(retained_windows_presentation_projection(case, &wrong_size).is_none());
        let unrelated = cases
            .iter()
            .find(|candidate| candidate.id.as_ref() == "bool-ordinary-success")
            .expect("unrelated case");
        assert!(retained_windows_presentation_projection(unrelated, &exact).is_none());
    }
}
