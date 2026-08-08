//! Arbitrary-precision signed integers used by the guest `Integer` type.

use std::cmp::Ordering;
use std::fmt;

const BASE: u64 = 1_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigInteger {
    negative: bool,
    limbs: Vec<u32>,
}

impl BigInteger {
    pub(crate) fn from_i64(value: i64) -> Self {
        let negative = value.is_negative();
        let mut magnitude = value.unsigned_abs();
        let mut limbs = Vec::new();
        while magnitude != 0 {
            limbs.push(u32::try_from(magnitude % BASE).expect("limb is below the base"));
            magnitude /= BASE;
        }
        Self::normalized(negative, limbs)
    }

    pub(crate) fn from_u64(mut value: u64) -> Self {
        let mut limbs = Vec::new();
        while value != 0 {
            limbs.push(u32::try_from(value % BASE).expect("limb is below the base"));
            value /= BASE;
        }
        Self::normalized(false, limbs)
    }

    pub(crate) fn from_i128(value: i128) -> Self {
        let negative = value.is_negative();
        let mut magnitude = value.unsigned_abs();
        let mut limbs = Vec::new();
        while magnitude != 0 {
            limbs
                .push(u32::try_from(magnitude % u128::from(BASE)).expect("limb is below the base"));
            magnitude /= u128::from(BASE);
        }
        Self::normalized(negative, limbs)
    }

    pub(crate) fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        let (negative, digits) = input.strip_prefix('-').map_or_else(
            || (false, input.strip_prefix('+').unwrap_or(input)),
            |rest| (true, rest),
        );
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }

        let mut value = Self::from_i64(0);
        for byte in digits.bytes() {
            value.multiply_small(10);
            value.add_small(u32::from(byte - b'0'));
        }
        value.negative = negative && !value.is_zero();
        Some(value)
    }

    pub(crate) fn add(&self, other: &Self) -> Self {
        match (self.negative, other.negative) {
            (left, right) if left == right => {
                Self::normalized(left, add_magnitudes(&self.limbs, &other.limbs))
            }
            _ => match compare_magnitudes(&self.limbs, &other.limbs) {
                Ordering::Greater => Self::normalized(
                    self.negative,
                    subtract_magnitudes(&self.limbs, &other.limbs),
                ),
                Ordering::Less => Self::normalized(
                    other.negative,
                    subtract_magnitudes(&other.limbs, &self.limbs),
                ),
                Ordering::Equal => Self::from_i64(0),
            },
        }
    }

    pub(crate) fn subtract(&self, other: &Self) -> Self {
        let mut negated = other.clone();
        if !negated.is_zero() {
            negated.negative = !negated.negative;
        }
        self.add(&negated)
    }

    pub(crate) fn multiply(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::from_i64(0);
        }
        let mut result = vec![0_u32; self.limbs.len() + other.limbs.len()];
        for (left_index, left) in self.limbs.iter().copied().enumerate() {
            let mut carry = 0_u64;
            for (right_index, right) in other.limbs.iter().copied().enumerate() {
                let index = left_index + right_index;
                let value = u64::from(result[index]) + u64::from(left) * u64::from(right) + carry;
                result[index] = u32::try_from(value % BASE).expect("limb is below the base");
                carry = value / BASE;
            }
            let mut index = left_index + other.limbs.len();
            while carry != 0 {
                let value = u64::from(result[index]) + carry;
                result[index] = u32::try_from(value % BASE).expect("limb is below the base");
                carry = value / BASE;
                index += 1;
            }
        }
        Self::normalized(self.negative != other.negative, result)
    }

    #[allow(clippy::cast_possible_wrap)]
    pub(crate) fn wrapping_i64(&self) -> i64 {
        let mut value = 0_u64;
        for limb in self.limbs.iter().rev().copied() {
            value = value.wrapping_mul(BASE).wrapping_add(u64::from(limb));
        }
        if self.negative {
            value = 0_u64.wrapping_sub(value);
        }
        value as i64
    }

    pub(crate) fn to_u64(&self) -> Option<u64> {
        if self.negative {
            return None;
        }
        let mut value = 0_u64;
        for limb in self.limbs.iter().rev().copied() {
            value = value.checked_mul(BASE)?.checked_add(u64::from(limb))?;
        }
        Some(value)
    }

    #[allow(clippy::cast_precision_loss)]
    pub(crate) fn to_f64(&self) -> f64 {
        let mut value = 0.0_f64;
        for limb in self.limbs.iter().rev().copied() {
            value = value.mul_add(BASE as f64, f64::from(limb));
        }
        if self.negative { -value } else { value }
    }

    pub(crate) fn div_rem_euclid_small(&self, divisor: u32) -> (Self, u32) {
        assert_ne!(divisor, 0, "division by zero");
        let mut quotient = vec![0_u32; self.limbs.len()];
        let mut remainder = 0_u64;
        for (index, limb) in self.limbs.iter().copied().enumerate().rev() {
            let current = remainder * BASE + u64::from(limb);
            quotient[index] =
                u32::try_from(current / u64::from(divisor)).expect("quotient limb fits");
            remainder = current % u64::from(divisor);
        }
        let remainder = u32::try_from(remainder).expect("remainder is below divisor");
        if !self.negative || remainder == 0 {
            return (Self::normalized(self.negative, quotient), remainder);
        }
        let quotient = Self::normalized(true, quotient).subtract(&Self::from_i64(1));
        (quotient, divisor - remainder)
    }

    fn normalized(negative: bool, mut limbs: Vec<u32>) -> Self {
        while limbs.last() == Some(&0) {
            limbs.pop();
        }
        Self {
            negative: negative && !limbs.is_empty(),
            limbs,
        }
    }

    fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    fn multiply_small(&mut self, factor: u32) {
        let mut carry = 0_u64;
        for limb in &mut self.limbs {
            let value = u64::from(*limb) * u64::from(factor) + carry;
            *limb = u32::try_from(value % BASE).expect("limb is below the base");
            carry = value / BASE;
        }
        if carry != 0 {
            self.limbs
                .push(u32::try_from(carry).expect("small multiplication has one-limb carry"));
        }
    }

    fn add_small(&mut self, addend: u32) {
        let mut carry = u64::from(addend);
        for limb in &mut self.limbs {
            let value = u64::from(*limb) + carry;
            *limb = u32::try_from(value % BASE).expect("limb is below the base");
            carry = value / BASE;
            if carry == 0 {
                return;
            }
        }
        if carry != 0 {
            self.limbs
                .push(u32::try_from(carry).expect("small addition has one-limb carry"));
        }
    }
}

impl Ord for BigInteger {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => compare_magnitudes(&self.limbs, &other.limbs),
            (true, true) => compare_magnitudes(&other.limbs, &self.limbs),
        }
    }
}

impl PartialOrd for BigInteger {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for BigInteger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative {
            formatter.write_str("-")?;
        }
        let Some(last) = self.limbs.last() else {
            return formatter.write_str("0");
        };
        write!(formatter, "{last}")?;
        for limb in self.limbs[..self.limbs.len() - 1].iter().rev() {
            write!(formatter, "{limb:09}")?;
        }
        Ok(())
    }
}

fn compare_magnitudes(left: &[u32], right: &[u32]) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.iter().rev().cmp(right.iter().rev()))
}

fn add_magnitudes(left: &[u32], right: &[u32]) -> Vec<u32> {
    let mut output = Vec::with_capacity(left.len().max(right.len()) + 1);
    let mut carry = 0_u64;
    for index in 0..left.len().max(right.len()) {
        let value = left.get(index).copied().map_or(0, u64::from)
            + right.get(index).copied().map_or(0, u64::from)
            + carry;
        output.push(u32::try_from(value % BASE).expect("limb is below the base"));
        carry = value / BASE;
    }
    if carry != 0 {
        output.push(u32::try_from(carry).expect("addition carry is below the base"));
    }
    output
}

fn subtract_magnitudes(larger: &[u32], smaller: &[u32]) -> Vec<u32> {
    let mut output = Vec::with_capacity(larger.len());
    let mut borrow = 0_i64;
    for (index, larger) in larger.iter().copied().enumerate() {
        let smaller = smaller.get(index).copied().unwrap_or(0);
        let mut value = i64::from(larger) - i64::from(smaller) - borrow;
        if value < 0 {
            value += i64::try_from(BASE).expect("base fits i64");
            borrow = 1;
        } else {
            borrow = 0;
        }
        output.push(u32::try_from(value).expect("subtraction limb is non-negative"));
    }
    output
}
