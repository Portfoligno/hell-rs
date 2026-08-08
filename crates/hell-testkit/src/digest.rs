//! Small dependency-free streaming SHA-256 used for retained evidence.

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// Parses one lowercase or uppercase hexadecimal SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns an error when `hex` is not exactly 64 hexadecimal digits.
    pub fn from_hex(hex: &str) -> Result<Self, &'static str> {
        if hex.len() != 64 {
            return Err("SHA-256 must contain exactly 64 hexadecimal digits");
        }
        let mut bytes = [0_u8; 32];
        for (target, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            *target = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(self.0.len() * 2);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

fn nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("SHA-256 contains a non-hexadecimal digit"),
    }
}

pub struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total_bytes: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: INITIAL,
            block: [0; 64],
            block_len: 0,
            total_bytes: 0,
        }
    }

    pub fn update(&mut self, mut bytes: &[u8]) {
        self.total_bytes = self
            .total_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if self.block_len != 0 {
            let copy = (self.block.len() - self.block_len).min(bytes.len());
            self.block[self.block_len..self.block_len + copy].copy_from_slice(&bytes[..copy]);
            self.block_len += copy;
            bytes = &bytes[copy..];
            if self.block_len == self.block.len() {
                compress(&mut self.state, &self.block);
                self.block_len = 0;
            } else {
                return;
            }
        }
        while bytes.len() >= self.block.len() {
            let (block, rest) = bytes.split_at(self.block.len());
            let block: &[u8; 64] = block
                .try_into()
                .expect("split SHA-256 block has fixed size");
            compress(&mut self.state, block);
            bytes = rest;
        }
        self.block[..bytes.len()].copy_from_slice(bytes);
        self.block_len = bytes.len();
    }

    pub fn finish(mut self) -> Digest {
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.block[self.block_len] = 0x80;
        self.block_len += 1;
        if self.block_len > self.block.len() - std::mem::size_of::<u64>() {
            self.block[self.block_len..].fill(0);
            compress(&mut self.state, &self.block);
            self.block.fill(0);
        } else {
            self.block[self.block_len..].fill(0);
        }
        let length_offset = self.block.len() - std::mem::size_of::<u64>();
        self.block[length_offset..].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut self.state, &self.block);
        let mut output = [0_u8; 32];
        for (chunk, word) in output.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        Digest(output)
    }
}

#[allow(clippy::many_single_char_names)]
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut words = [0_u32; 64];
    for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().expect("SHA-256 word has fixed size"));
    }
    for index in 16..words.len() {
        let s0 = words[index - 15].rotate_right(7)
            ^ words[index - 15].rotate_right(18)
            ^ (words[index - 15] >> 3);
        let s1 = words[index - 2].rotate_right(17)
            ^ words[index - 2].rotate_right(19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16]
            .wrapping_add(s0)
            .wrapping_add(words[index - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (word, constant) in words.into_iter().zip(ROUND) {
        let choice = (e & f) ^ ((!e) & g);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let first = h
            .wrapping_add(sum1)
            .wrapping_add(choice)
            .wrapping_add(constant)
            .wrapping_add(word);
        let second = sum0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);
    }
    for (target, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *target = target.wrapping_add(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_vector_and_chunking_match() {
        let mut single = Sha256::new();
        single.update(b"abc");
        let mut chunked = Sha256::new();
        chunked.update(b"a");
        chunked.update(b"bc");
        let single = single.finish();
        let chunked = chunked.finish();
        assert_eq!(single, chunked);
        assert_eq!(
            chunked.hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
