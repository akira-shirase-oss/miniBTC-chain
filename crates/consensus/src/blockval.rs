//! Block-level consensus validation: header rules, coinbase rules, fee
//! accounting, timestamp policy, sigop limits. Runs *after* the cheap
//! structural checks (decode, merkle, PoW) — ordered cheapest-first.

use minibtc_crypto::Hash256;
use minibtc_primitives::{
    Block, BlockHeader, MerkleError, OutPoint, Sats, Transaction, TxOutput, check_merkle_root,
};
use std::collections::{HashMap, HashSet};

use crate::params::ChainParams;
use crate::pow::{self, PowError};
use crate::subsidy::{self, SubsidyError};
use crate::txval::{TxError, UtxoView, validate_tx};

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
    /// BIP34: the coinbase scriptSig does not start with the block height
    /// (Bitcoin Core's `bad-cb-height`).
    #[error("coinbase does not commit to block height {height}")]
    BadCoinbaseHeight {
        /// The block's height.
        height: u64,
    },
    /// BIP30: a transaction creates an outpoint that already exists
    /// unspent — it would overwrite (destroy) that coin.
    #[error("tx {index} would overwrite unspent output {outpoint} (BIP30)")]
    Bip30 {
        /// Position of the offending tx in the block.
        index: usize,
        /// The already-unspent outpoint.
        outpoint: OutPoint,
    },
    /// `bits` is not what the retarget schedule requires after the
    /// parent (Bitcoin Core's `bad-diffbits`).
    #[error("bad difficulty bits 0x{got:08x}, schedule requires 0x{expected:08x}")]
    BadDiffBits {
        /// The block's bits.
        got: u32,
        /// The bits the schedule requires.
        expected: u32,
    },
}

/// The chain context a block is judged in. The caller derives every field
/// from the block's **parent** (never from the active tip), so a side
/// branch is judged by its own history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockContext {
    /// Height of the block being validated.
    pub height: u64,
    /// The compact bits the retarget schedule requires for this block
    /// (see [`crate::pow::next_bits_for_period`]).
    pub expected_bits: u32,
    /// Median time of the parent and its ancestors (up to
    /// `params.median_time_span` blocks).
    pub median_time_past: u32,
    /// The validating node's adjusted clock.
    pub adjusted_time: u32,
}

/// Result of validating a block's transactions: total fees collected.
#[derive(Debug)]
pub struct BlockValidation {
    /// Sum of fees from all non-coinbase txs (sats).
    pub total_fees: Sats,
    /// Sigops counted (for the block sigop limit).
    pub sigops: usize,
}

/// The view transaction *i* of a block is validated against: the
/// pre-block view, plus outputs created by transactions `0..i` of the same
/// block, minus the outpoints they spent — the per-block coins cache
/// Bitcoin Core's `ConnectBlock` uses. Without it, two transactions can
/// spend one coin (CVE-2018-17144's inflation case) and a child can never
/// spend its parent in the same block.
#[derive(Debug)]
struct BlockView<'a, V: UtxoView> {
    base: &'a V,
    created: HashMap<OutPoint, TxOutput>,
    spent: HashSet<OutPoint>,
}

impl<'a, V: UtxoView> BlockView<'a, V> {
    fn new(base: &'a V) -> Self {
        Self {
            base,
            created: HashMap::new(),
            spent: HashSet::new(),
        }
    }

    /// BIP30: none of `tx`'s outpoints may already exist unspent (in the
    /// pre-block view or created earlier in this block).
    fn check_no_overwrite(&self, tx: &Transaction, index: usize) -> Result<(), BlockError> {
        let txid = tx.txid();
        for vout in 0..tx.outputs.len() {
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            if self.get(&outpoint).is_some() {
                return Err(BlockError::Bip30 { index, outpoint });
            }
        }
        Ok(())
    }

    /// Record a validated transaction: its inputs are spent for every
    /// later transaction, its outputs exist for them.
    fn record(&mut self, tx: &Transaction, is_coinbase: bool) {
        if !is_coinbase {
            self.spent.extend(tx.inputs.iter().map(|i| i.prev));
        }
        let txid = tx.txid();
        for (vout, out) in tx.outputs.iter().enumerate() {
            let op = OutPoint {
                txid,
                vout: vout as u32,
            };
            self.created.insert(op, out.clone());
        }
    }
}

impl<V: UtxoView> UtxoView for BlockView<'_, V> {
    fn get(&self, op: &OutPoint) -> Option<TxOutput> {
        if self.spent.contains(op) {
            return None;
        }
        if let Some(out) = self.created.get(op) {
            return Some(out.clone());
        }
        self.base.get(op)
    }
}

/// Validate a full block against the UTXO view *as it was before this
/// block*; each transaction sees the effects of the ones before it (see
/// [`BlockView`]). Checks, in order:
///
/// 1. merkle root matches txs (with CVE-2012-2459 ambiguity check);
/// 2. PoW: `bits` decodes, its target is not above the pow limit, and
///    `hash <= target`;
/// 3. size/tx-count limits;
/// 4. first tx is coinbase-shaped; no other tx is;
/// 5. every non-coinbase tx passes [`validate_tx`] against the pre-block
///    view updated by the earlier txs of this block (coinbase outputs
///    included — spending them is refused by the maturity rule at
///    connect time);
/// 6. coinbase outputs ≤ subsidy(height) + fees — checked;
/// 7. sigop total ≤ limit.
///
/// Rules that need chain context — the retarget schedule (`bits`),
/// median-time-past and the future-time limit — are checked only by
/// [`validate_block_in_context`]; this function is for callers (and tests)
/// that isolate the other rules. The node always uses the contextual form.
pub fn validate_block<V: UtxoView>(
    block: &Block,
    view: &V,
    params: &ChainParams,
    height: u64,
) -> Result<BlockValidation, BlockError> {
    validate_block_inner(block, view, params, height, None)
}

/// [`validate_block`] plus every contextual header rule from `ctx`:
/// `bits` must equal `ctx.expected_bits`, the timestamp must exceed
/// `ctx.median_time_past` and be at most `ctx.adjusted_time +
/// params.max_future_time_secs`.
pub fn validate_block_in_context<V: UtxoView>(
    block: &Block,
    view: &V,
    params: &ChainParams,
    ctx: &BlockContext,
) -> Result<BlockValidation, BlockError> {
    validate_block_inner(block, view, params, ctx.height, Some(ctx))
}

/// Every block rule that needs no UTXO set: merkle root and mutation,
/// proof of work and the pow limit, size/count limits, coinbase shape,
/// BIP34, the sigop limit and — from `ctx` — the retarget schedule and the
/// timestamp rules. A side-branch block must pass this before it is
/// stored; its transactions are checked against the fork point's UTXO
/// state only when its branch is activated (Bitcoin Core's
/// `CheckBlock` + `ContextualCheckBlockHeader` vs `ConnectBlock`).
pub fn check_block_in_context(
    block: &Block,
    params: &ChainParams,
    ctx: &BlockContext,
) -> Result<(), BlockError> {
    check_block_inner(block, params, ctx.height, Some(ctx))
}

fn check_block_inner(
    block: &Block,
    params: &ChainParams,
    height: u64,
    ctx: Option<&BlockContext>,
) -> Result<(), BlockError> {
    // 1. Merkle (includes ambiguity check).
    check_merkle_root(&block.header, &block.txs)?;

    // 2. PoW: target in range (not above the pow limit), hash meets it.
    pow::checked_target(block.header.bits, params)?;
    let target = pow::target_for_bits(block.header.bits)?;
    if !block.header.check_pow(&target) {
        return Err(PowError::BadBits(block.header.bits).into());
    }
    if let Some(ctx) = ctx {
        // The retarget schedule fixes `bits` exactly.
        if block.header.bits != ctx.expected_bits {
            return Err(BlockError::BadDiffBits {
                got: block.header.bits,
                expected: ctx.expected_bits,
            });
        }
        // Timestamp rules.
        if block.header.time
            > ctx
                .adjusted_time
                .saturating_add(params.max_future_time_secs)
        {
            return Err(BlockError::TimeTooNew {
                block_time: block.header.time,
                adjusted_time: ctx.adjusted_time,
                max_future: params.max_future_time_secs,
            });
        }
        if block.header.time <= ctx.median_time_past {
            return Err(BlockError::TimeTooOld);
        }
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
    for tx in block.txs.iter().skip(1) {
        if tx.is_coinbase() {
            return Err(BlockError::StrayCoinbase);
        }
    }
    // BIP34: every coinbase after genesis starts with its height, so no
    // two coinbases on one chain can share a txid.
    if height > 0
        && !coinbase.inputs[0]
            .script_sig
            .starts_with(&coinbase_height_prefix(height))
    {
        return Err(BlockError::BadCoinbaseHeight { height });
    }

    // 5. Sigops (counted from the txs alone).
    let sigops = block
        .txs
        .iter()
        .skip(1)
        .fold(0usize, |n, tx| n.saturating_add(count_sigops(tx)));
    if sigops > params.max_block_sigops {
        return Err(BlockError::Limits("sigop limit exceeded"));
    }
    Ok(())
}

fn validate_block_inner<V: UtxoView>(
    block: &Block,
    view: &V,
    params: &ChainParams,
    height: u64,
    ctx: Option<&BlockContext>,
) -> Result<BlockValidation, BlockError> {
    check_block_inner(block, params, height, ctx)?;
    let coinbase = &block.txs[0];

    // 6. Transactions and fees — tx i sees txs 0..i.
    let mut total_fees = Sats::ZERO;
    let mut sigops = 0usize;
    let mut block_view = BlockView::new(view);
    block_view.check_no_overwrite(coinbase, 0)?;
    block_view.record(coinbase, true);
    for (i, tx) in block.txs.iter().enumerate().skip(1) {
        let fee = validate_tx(tx, &block_view, params).map_err(|e| BlockError::Tx {
            index: i,
            source: e,
        })?;
        block_view.check_no_overwrite(tx, i)?;
        block_view.record(tx, false);
        total_fees = total_fees
            .checked_add(fee)
            .ok_or(BlockError::Limits("fee overflow"))?;
        sigops = sigops.saturating_add(count_sigops(tx));
    }

    // 7. Coinbase value cap: outputs ≤ subsidy + fees (checked). Bitcoin
    // allows several coinbase outputs (payout splitting); so do we.
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

    Ok(BlockValidation { total_fees, sigops })
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
        .map(|o| {
            o.script_pubkey
                .iter()
                .filter(|&&b| b == minibtc_script::OP_CHECKSIG)
                .count()
        })
        .sum()
}

/// The BIP34 height commitment a coinbase scriptSig must start with:
/// exactly Bitcoin Core's `CScript() << nHeight` — `OP_0` for 0,
/// `OP_1`..`OP_16` for 1..=16, otherwise a direct push of the minimal
/// little-endian script number (a `0x00` byte is appended when the top
/// byte's high bit is set, so the number stays positive).
pub fn coinbase_height_prefix(height: u64) -> Vec<u8> {
    const OP_0: u8 = 0x00;
    const OP_1: u8 = 0x51;
    match height {
        0 => vec![OP_0],
        1..=16 => vec![OP_1 + (height as u8 - 1)],
        _ => {
            let mut num = Vec::with_capacity(9);
            let mut v = height;
            while v > 0 {
                num.push((v & 0xff) as u8);
                v >>= 8;
            }
            if num.last().is_some_and(|b| b & 0x80 != 0) {
                num.push(0x00);
            }
            let mut out = Vec::with_capacity(num.len() + 1);
            out.push(num.len() as u8); // ≤ 9 bytes: a direct push opcode
            out.extend_from_slice(&num);
            out
        }
    }
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

#[cfg(test)]
mod tests {
    use super::coinbase_height_prefix;

    #[test]
    fn height_prefix_matches_core_script_number_encoding() {
        assert_eq!(coinbase_height_prefix(0), [0x00]);
        assert_eq!(coinbase_height_prefix(1), [0x51]);
        assert_eq!(coinbase_height_prefix(16), [0x60]);
        assert_eq!(coinbase_height_prefix(17), [0x01, 0x11]);
        assert_eq!(coinbase_height_prefix(127), [0x01, 0x7f]);
        assert_eq!(coinbase_height_prefix(128), [0x02, 0x80, 0x00]);
        assert_eq!(coinbase_height_prefix(255), [0x02, 0xff, 0x00]);
        assert_eq!(coinbase_height_prefix(256), [0x02, 0x00, 0x01]);
        assert_eq!(coinbase_height_prefix(65_535), [0x03, 0xff, 0xff, 0x00]);
        // Bitcoin mainnet block 227,931 (BIP34 activation) coinbase starts
        // with 03 5b 7a 03.
        assert_eq!(coinbase_height_prefix(227_931), [0x03, 0x5b, 0x7a, 0x03]);
    }
}
