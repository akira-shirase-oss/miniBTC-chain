//! `Sats` — the only unit money exists in inside MiniBTC.
//!
//! Every amount in the system is an integer count of base units (satoshis).
//! There are no floats anywhere near value: the 2010 overflow bug happened
//! because C++ used a plain integer where checked arithmetic was required —
//! here the *type itself* refuses unchecked math by offering only
//! `checked_*`/`saturating_*` constructors.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::ops::{Add, Sub};
use std::str::FromStr;

/// Errors converting external representations into `Sats`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MoneyError {
    /// The value was negative.
    #[error("negative amount")]
    Negative,
    /// The value exceeded what a u64 can hold.
    #[error("amount overflows u64")]
    Overflow,
    /// A string did not parse as a non-negative integer.
    #[error("invalid amount: {0}")]
    Parse(String),
}

/// A non-negative amount in base units. Copy + Ord; arithmetic is explicit.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Sats(pub u64);

impl Sats {
    /// Zero.
    pub const ZERO: Self = Self(0);
    /// One base unit.
    pub const ONE: Self = Self(1);

    /// The raw count.
    pub fn sats(&self) -> u64 {
        self.0
    }

    /// Checked addition — `None` on overflow. **The only way to add money.**
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    /// Checked subtraction — `None` when `rhs > self`. You cannot create
    /// money by subtracting.
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }

    /// Total of an iterator, checked. `None` on any overflow — used for
    /// "sum all inputs/outputs" where a wrap would be catastrophic.
    pub fn checked_sum<I: IntoIterator<Item = Self>>(items: I) -> Option<Self> {
        items
            .into_iter()
            .try_fold(Self::ZERO, |acc, v| acc.checked_add(v))
    }

    /// `a * b` checked — fee-rate math.
    pub fn checked_mul(self, rhs: u64) -> Option<Self> {
        self.0.checked_mul(rhs).map(Self)
    }

    /// Integer division for fee-rate comparisons (rounds down — fine for
    /// ordering, never used to compute a spendable amount).
    pub fn fee_rate_per_byte(self, bytes: u64) -> u64 {
        if bytes == 0 {
            return 0;
        }
        self.0 / bytes
    }

    /// Human display: `1.50` for 150_000_000-style values is *not* assumed —
    /// MiniBTC has no decimal exponent; display is plain integer sats.
    pub fn to_sats_string(self) -> String {
        self.0.to_string()
    }
}

impl fmt::Debug for Sats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sats({})", self.0)
    }
}

impl fmt::Display for Sats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} sats", self.0)
    }
}

impl FromStr for Sats {
    type Err = MoneyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v: u64 = s
            .trim()
            .parse()
            .map_err(|_| MoneyError::Parse(s.to_string()))?;
        Ok(Self(v))
    }
}

impl TryFrom<u64> for Sats {
    type Error = MoneyError;
    fn try_from(v: u64) -> Result<Self, Self::Error> {
        Ok(Self(v))
    }
}

impl TryFrom<i64> for Sats {
    type Error = MoneyError;
    fn try_from(v: i64) -> Result<Self, Self::Error> {
        u64::try_from(v).map(Self).map_err(|_| MoneyError::Negative)
    }
}

impl Add for Sats {
    type Output = Option<Sats>;
    /// Deliberately returns `Option` — `a + b` on money is always fallible.
    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(rhs)
    }
}

impl Sub for Sats {
    type Output = Option<Sats>;
    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_sub(rhs)
    }
}

impl Serialize for Sats {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.0)
    }
}
impl<'de> Deserialize<'de> for Sats {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = u64::deserialize(d)?;
        Ok(Self(v))
    }
}
