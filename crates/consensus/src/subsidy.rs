//! Coinbase subsidy: the only place new money enters the chain.
//!
//! `subsidy(height) = subsidy_start >> (height / halving_interval)` —
//! Bitcoin's geometric halving. All arithmetic is checked; the result is
//! `Sats`, and callers must still verify `coinbase_outputs ≤ subsidy +
//! fees` with checked math (see [`crate::txval`]).

use crate::params::ChainParams;
use minibtc_primitives::Sats;

/// Errors computing subsidy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SubsidyError {
    /// The halving exponent is absurd (height/interval overflowed usize).
    #[error("halving interval computation overflow")]
    Overflow,
}

/// The block subsidy at `height` — before fees. Returns `Sats`.
pub fn subsidy_at(params: &ChainParams, height: u64) -> Result<Sats, SubsidyError> {
    let halvings = height / u64::from(params.subsidy_halving_interval);
    // Beyond ~64 halvings the subsidy is zero — cap the shift.
    if halvings >= 64 {
        return Ok(Sats::ZERO);
    }
    // subsidy_start >> halvings, but never below 1 sat until it truly hits 0.
    let v = params.subsidy_start >> halvings;
    Ok(Sats(v))
}

/// Maximum a coinbase transaction may create: subsidy + fees, all checked.
/// `fees` is the sum of (inputs - outputs) over the block's non-coinbase
/// txs, already computed with checked arithmetic by the caller.
pub fn max_coinbase_value(
    params: &ChainParams,
    height: u64,
    fees: Sats,
) -> Result<Sats, SubsidyError> {
    subsidy_at(params, height)?.checked_add(fees).ok_or(SubsidyError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halving_schedule() {
        let p = ChainParams::devnet();
        assert_eq!(subsidy_at(&p, 0).unwrap(), Sats(50 * 100_000_000));
        assert_eq!(subsidy_at(&p, 149).unwrap(), Sats(50 * 100_000_000));
        assert_eq!(subsidy_at(&p, 150).unwrap(), Sats(25 * 100_000_000));
        assert_eq!(subsidy_at(&p, 300).unwrap(), Sats(12 * 100_000_000 + 50_000_000));
        assert_eq!(subsidy_at(&p, 100_000).unwrap(), Sats::ZERO);
    }

    #[test]
    fn coinbase_cap_includes_fees() {
        let p = ChainParams::devnet();
        let cap = max_coinbase_value(&p, 0, Sats(1_000)).unwrap();
        assert_eq!(cap, Sats(50 * 100_000_000 + 1_000));
    }
}
