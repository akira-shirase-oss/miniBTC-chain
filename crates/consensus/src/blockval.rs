//! Block-level consensus validation: header rules, coinbase rules, fee
//! accounting, timestamp policy, sigop limits. Runs *after* the cheap
//! structural checks (decode, merkle, PoW) — ordered cheapest-first.

use minibtc_crypto::Hash256;
use minibtc_primitives::{check_merkle_root, Block, BlockHeader, MerkleError, Sats};

use crate::params::ChainParams;
use crate::pow::{self, PowError};
use crate::subsidy::{self, SubsidyError};
use crate::txval::{validate_tx, TxError, UtxoView};

/// Why a block was rejected.
#[derive(Debug, thiserror::Error)]
pub enum BlockError {
    /// Structural/merkle problem.
    #[error("merkle: {0}")]
    Merkle(#[from] MerkleError),
    /// PoW target invalid or hash above target.
    #[error("pow: {0}")]
    Pow(#[from] PowError),
    /// Subsidy math failed.
    #[error("subsidy: {0}")]
    Subsidy(#[from] SubsidyError),
    /// A non-coinbase tx in the block failed validation.
    #[error("tx {index}: {source}")]
    Tx {
        /// Position in the block.
        index: usize,
        /// The tx-level error.
        source: TxError,
    },
    /// First tx wasn't a valid coinbase.
    #[error("first transaction is not a valid coinbase: {0}")]
    BadCoinbase(&'static str),
    /// Coinbase claimed more than subsidy+fees.
    #[error("coinbase over-claims: outputs {outputs} > allowed {allowed}")]
    CoinbaseOverclaim {
        /// Sum of coinbase outputs.
        outputs: u64,
        /// subsidy + fees cap.
        allowed: u64,
    },
    /// Timestamp too far in the future vs adjusted time.
    #[error("block time {block_time} exceeds adjusted time {adjusted_time} + {max_future}")]
    TimeTooNew {
        /// The block's claimed time.
        block_time: u32,
        /// Our adjusted time.
        adjusted_time: u32,
        /// Allowed future drift.
        max_future: u32,
    },
    /// Timestamp not greater than median of past blocks.
    #[error("block time does not exceed median-time-past")]
    TimeTooOld,
    /// Block exceeded size/tx/sigop limits.
    #[error("block limits exceeded: {0}")]
    Limits(&'static str),
    /// A non-first tx was coinbase-shaped.
    #[error("non-first transaction is coinbase-shaped")]
    StrayCoinbase,
}

/// Result of validating a block's transactions: total fees collected.
#[derive(Debug)]
pub struct BlockValidation {
    /// Sum of fees from all non-coinbase txs (sats).
    pub total_fees: Sats,
    /// Sigops counted (for the block sigop limit).
    pub sigops: usize,
}

/// Validate a full block against the UTXO view *as it was before this
/// block*. Checks, in order:
///
/// 1. merkle root matches txs (with CVE-2012-2459 ambiguity check);
/// 2. PoW: `bits` decodes and `hash <= target`;
/// 3. size/tx-count limits;
/// 4. first tx is coinbase-shaped; no other tx is;
/// 5. every non-coinbase tx passes [`validate_tx`];
/// 6. coinbase outputs ≤ subsidy(height) + fees — checked;
/// 7. sigop total ≤ limit.
///
/// Timestamp rules need chain context (median-time-past, adjusted time)
/// — those live in [`crate::chaindb`] where the block index exists; this
/// function takes `adjusted_time`/`median_time_past` as inputs when the
/// caller wants them checked via [`validate_block_with_time`].
pub fn validate_block<V: UtxoView>(
    block: &Block,
    view: &V,
    params: &ChainParams,
    height: u64,
) -> Result<BlockValidation, BlockError> {
    validate_block_with_time(block, view, params, height, None, None)
}

/// [`validate_block`] plus optional timestamp policy checks.
///
/// `adjusted_time` — our clock's median-adjusted time (caller computes).
/// `median_time_past` — median of up to `params.median_time_span` previous
/// block times (caller computes from the index). Pass `Some` for both to
/// enforce; `None` skips (used by tests that isolate other rules).
pub fn validate_block_with_time<V: UtxoView>(
    block: &Block,
    view: &V,
    params: &ChainParams,
    height: u64,
    adjusted_time: Option<u32>,
    median_time_past: Option<u32>,
) -> Result<BlockValidation, BlockError> {
    // 1. Merkle (includes ambiguity check).
    check_merkle_root(&block.header, &block.txs)?;

    // 2. PoW.
    let target = pow::target_for_bits(block.header.bits)?;
    if !block.header.check_pow(&target) {
        return Err(PowError::BadBits(block.header.bits).into());
    }

    // 3. Limits.
    let size = block.encode().len();
    if size > params.max_block_size {
        return Err(BlockError::Limits("block too large"));
    }
    if block.txs.len() > params.max_block_txs {
        return Err(BlockError::Limits("too many transactions"));
    }
    if block.txs.is_empty() {
        return Err(BlockError::Limits("empty block"));
    }

    // 4. Coinbase shape: first tx coinbase, others not.
    let coinbase = &block.txs[0];
    if !coinbase.is_coinbase() {
        return Err(BlockError::BadCoinbase("first tx is not coinbase-shaped"));
    }
    for (i, tx) in block.txs.iter().enumerate().skip(1) {
        if tx.is_coinbase() {
            return Err(BlockError::StrayCoinbase);
        }
        let _ = i;
    }

    // 5./6./7. Transactions, fees, sigops.
    let mut total_fees = Sats::ZERO;
    let mut sigops = 0usize;
    for (i, tx) in block.txs.iter().enumerate().skip(1) {
        let fee = validate_tx(tx, view, params).map_err(|e| BlockError::Tx {
            index: i,
            source: e,
        })?;
        total_fees = total_fees.checked_add(fee).ok_or(BlockError::Limits("fee overflow"))?;
        sigops = sigops.saturating_add(count_sigops(tx));
    }
    if sigops > params.max_block_sigops {
        return Err(BlockError::Limits("sigop limit exceeded"));
    }

    // Coinbase value cap: outputs ≤ subsidy + fees (checked).
    let allowed = subsidy::max_coinbase_value(params, height, total_fees)?;
    let cb_out = coinbase
        .output_sum()
        .ok_or(BlockError::Limits("coinbase value overflow"))?;
    if cb_out > allowed {
        return Err(BlockError::CoinbaseOverclaim {
            outputs: cb_out.sats(),
            allowed: allowed.sats(),
        });
    }
    // Coinbase must have exactly one output? No — Bitcoin allows many
    // outputs (payout splitting); we allow it too.

    // Timestamp policy when context is supplied.
    if let (Some(adj), Some(mtp)) = (adjusted_time, median_time_past) {
        if block.header.time > adj.saturating_add(params.max_future_time_secs) {
            return Err(BlockError::TimeTooNew {
                block_time: block.header.time,
                adjusted_time: adj,
                max_future: params.max_future_time_secs,
            });
        }
        if block.header.time <= mtp {
            return Err(BlockError::TimeTooOld);
        }
    }

    Ok(BlockValidation {
        total_fees,
        sigops,
    })
}

/// Count sigops in a tx — our script subset has exactly one sigop per
/// `OP_CHECKSIG` byte in any scriptPubKey/scriptSig position where it
/// would execute. For the block limit we count occurrences in output
/// scripts (standardness approximation — precise counting needs execution;
/// our subset makes OP_CHECKSIG count = 1 wherever it appears in a
/// scriptPubKey, matching Bitcoin's `ConnectBlock` sigop accounting for
/// P2PKH).
fn count_sigops(tx: &minibtc_primitives::Transaction) -> usize {
    tx.outputs
        .iter()
        .map(|o| o.script_pubkey.iter().filter(|&&b| b == minibtc_script::OP_CHECKSIG).count())
        .sum()
}

/// Median of up to `span` block times, most-recent-first — Bitcoin's
/// "median time past". Caller supplies the past block times (newest first).
pub fn median_time_past(times_newest_first: &[u32], span: usize) -> Option<u32> {
    let take = span.min(times_newest_first.len());
    if take == 0 {
        return None;
    }
    let mut v: Vec<u32> = times_newest_first[..take].to_vec();
    v.sort_unstable();
    Some(v[take / 2])
}

/// Re-exported for callers that build headers.
pub type Header = BlockHeader;
pub type HeaderHash = Hash256;
