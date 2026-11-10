//! # minibtc-consensus
//!
//! Every rule that decides whether a block or transaction is *valid* —
//! pure functions over data, no I/O, no clocks (time arrives as an
//! argument so tests are deterministic). This is the crate to read
//! line-by-line: it is the security boundary.
//!
//! Modules: [`params`] (ChainParams + config loading), [`pow`] (compact
//! bits + retarget), [`subsidy`] (halving), [`txval`] (UTXO validation),
//! [`blockval`] (block validation).

pub mod blockval;
pub mod genesis;
pub mod params;
pub mod pow;
pub mod subsidy;
pub mod txval;

pub use blockval::{
    BlockError, BlockValidation, median_time_past, validate_block, validate_block_with_time,
};
pub use genesis::{genesis_block, genesis_key, genesis_secret};
pub use params::{ChainParams, ParamsError};
pub use pow::{PowError, decode_compact, encode_compact, retarget_bits, target_for_bits};
pub use subsidy::{SubsidyError, max_coinbase_value, subsidy_at};
pub use txval::{TxError, UtxoView, validate_tx};
