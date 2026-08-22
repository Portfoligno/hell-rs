use std::fmt::Write as _;

const INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const ROUND: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    let bit_len = u64::try_from(bytes.len())
        .expect("addressable input length fits in u64")
        .checked_mul(8)
        .expect("addressable input bit length fits in u64");
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    let mut state = INITIAL;
    for block in padded.chunks_exact(64) {
        compress(&mut state, block);
    }
    let mut output = [0_u8; 32];
    for (chunk, word) in output.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    output
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&sha256(bytes))
}

pub(crate) fn domain(object_type: &str, schema_version: u64, bytes: &[u8]) -> String {
    let mut separated = b"hell-rs:".to_vec();
    separated.extend_from_slice(object_type.as_bytes());
    separated.push(b':');
    separated.extend_from_slice(schema_version.to_string().as_bytes());
    separated.push(0);
    separated.extend_from_slice(bytes);
    sha256_hex(&separated)
}

fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut words = [0_u32; 64];
    for (index, chunk) in block.chunks_exact(4).enumerate() {
        words[index] = u32::from_be_bytes(chunk.try_into().expect("four-byte word"));
    }
    for index in 16..64 {
        let first = words[index - 15].rotate_right(7)
            ^ words[index - 15].rotate_right(18)
            ^ (words[index - 15] >> 3);
        let second = words[index - 2].rotate_right(17)
            ^ words[index - 2].rotate_right(19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16]
            .wrapping_add(first)
            .wrapping_add(words[index - 7])
            .wrapping_add(second);
    }
    let [
        mut first_state,
        mut second_state,
        mut third_state,
        mut fourth_state,
        mut fifth_state,
        mut sixth_state,
        mut seventh_state,
        mut eighth_state,
    ] = *state;
    for index in 0..64 {
        let choose = (fifth_state & sixth_state) ^ (!fifth_state & seventh_state);
        let majority = (first_state & second_state)
            ^ (first_state & third_state)
            ^ (second_state & third_state);
        let upper_first = first_state.rotate_right(2)
            ^ first_state.rotate_right(13)
            ^ first_state.rotate_right(22);
        let upper_fifth = fifth_state.rotate_right(6)
            ^ fifth_state.rotate_right(11)
            ^ fifth_state.rotate_right(25);
        let first_round = eighth_state
            .wrapping_add(upper_fifth)
            .wrapping_add(choose)
            .wrapping_add(ROUND[index])
            .wrapping_add(words[index]);
        let second_round = upper_first.wrapping_add(majority);
        eighth_state = seventh_state;
        seventh_state = sixth_state;
        sixth_state = fifth_state;
        fifth_state = fourth_state.wrapping_add(first_round);
        fourth_state = third_state;
        third_state = second_state;
        second_state = first_state;
        first_state = first_round.wrapping_add(second_round);
    }
    for (slot, value) in state.iter_mut().zip([
        first_state,
        second_state,
        third_state,
        fourth_state,
        fifth_state,
        sixth_state,
        seventh_state,
        eighth_state,
    ]) {
        *slot = slot.wrapping_add(value);
    }
}
