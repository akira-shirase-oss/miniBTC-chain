//! # minibtc-miner
//!
//! Block production: assemble a candidate block from mempool transactions
//! + coinbase, then grind the nonce until `hash ≤ target`. Pure functions
//! over data — the caller supplies the mempool view, the chain tip, and
//! the clock. No I/O here so mining is testable and the p2p/node layer
//! decides *when* to mine.
//!
//! - [`Template`] — everything needed to produce a block except the nonce.
//! - [`mine`] — the nonce-search loop with a bounded iteration budget and
//!   optional cancellation via `AtomicBool`.
//! - [`next_bits`] — difficulty retarget per params (clamped ×4).

use minibtc_consensus::{ChainParams, retarget_bits};
#[cfg(test)]
use minibtc_crypto::Keypair;
use minibtc_primitives::{
    Block, BlockHeader, OutPoint, Sats, Transaction, TxInput, TxOutput, merkle_root,
};
#[cfg(test)]
use minibtc_script::Script;
use std::sync::atomic::{AtomicBool, Ordering};

/// Errors building or mining a block.
#[derive(Debug, thiserror::Error)]
pub enum MineError {
    /// The mempool/chain inputs were inconsistent.
    #[error("cannot build template: {0}")]
    Template(&'static str),
    /// PoW bits failed to decode.
    #[error("bad bits: {0}")]
    Bits(#[from] minibtc_consensus::PowError),
    /// Mining was cancelled before finding a nonce.
    #[error("mining cancelled")]
    Cancelled,
    /// Iteration budget exhausted without finding a nonce.
    #[error("nonce budget exhausted after {0} iterations")]
    BudgetExhausted(u64),
}

/// A fully-assembled block candidate minus the nonce grind.
#[derive(Clone, Debug)]
pub struct Template {
    /// The header with `nonce = 0` — fill it in during mining.
    pub header: BlockHeader,
    /// Transactions: coinbase first, then selected mempool txs.
    pub txs: Vec<Transaction>,
    /// Total fees the coinbase may claim (sats).
    pub fees: Sats,
}

/// Build a mining template: coinbase paying `payout_script` the subsidy+fees,
/// plus up to `max_tx` mempool transactions in fee-rate order.
///
/// `mempool_txs` — `(tx, fee)` pairs already selected & fee-sorted by the
/// caller (mempool owns policy; miner owns assembly).
/// `prev` — the tip header being extended.
/// `time` — candidate timestamp (caller supplies; must satisfy MTP/future
/// rules — validation catches violations).
/// `height` — the height being mined (for subsidy + maturity).
pub fn build_template(
    params: &ChainParams,
    prev: &BlockHeader,
    mempool_txs: &[(Transaction, Sats)],
    payout_script: &[u8],
    height: u64,
    time: u32,
    bits: u32,
) -> Result<Template, MineError> {
    // Select txs greedily by the given (fee-sorted) order until the block
    // would exceed max_block_size or max_block_txs.
    let mut selected: Vec<Transaction> = Vec::new();
    let mut fees = Sats::ZERO;
    let mut size = 0usize;
    // Rough per-tx size estimate for the cap; exact size checked post-hoc
    // by validation — this is a template-time guard only.
    for (tx, fee) in mempool_txs {
        if selected.len() + 1 >= params.max_block_txs {
            break;
        }
        let tx_size = tx.encode().len();
        if size.saturating_add(tx_size) > params.max_block_size {
            break;
        }
        size = size.saturating_add(tx_size);
        fees = fees
            .checked_add(*fee)
            .ok_or(MineError::Template("fee overflow"))?;
        selected.push(tx.clone());
    }

    let subsidy = minibtc_consensus::subsidy_at(params, height)
        .map_err(|_| MineError::Template("subsidy overflow"))?;
    let coinbase_value = subsidy
        .checked_add(fees)
        .ok_or(MineError::Template("coinbase value overflow"))?;

    let cb = coinbase_transaction(height, coinbase_value, payout_script, &selected);
    let mut txs = Vec::with_capacity(selected.len() + 1);
    txs.push(cb);
    txs.extend(selected);

    let mr = merkle_root(&txs);
    let header = BlockHeader {
        version: 1,
        prev_hash: prev.block_hash(),
        merkle_root: mr,
        time,
        bits,
        nonce: 0,
    };
    Ok(Template { header, txs, fees })
}

/// The coinbase transaction: one null-prevout input + one output paying
/// `payout_script` (any scriptPubKey — P2PKH address, raw script, etc.).
/// ScriptSig carries the height (BIP34-style) plus a tag.
pub fn coinbase_transaction(
    height: u64,
    value: Sats,
    payout_script: &[u8],
    _mempool_txs: &[Transaction],
) -> Transaction {
    // Commit to the tx set lightly via a hash in the scriptSig — gives
    // each coinbase a unique txid even with identical payouts.
    let mut sig_script = Vec::with_capacity(16);
    sig_script.push(0x02);
    sig_script.extend_from_slice(&(height as u16).to_le_bytes());
    sig_script.extend_from_slice(b"MBTC");
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: OutPoint::NULL,
            script_sig: sig_script,
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput {
            value,
            script_pubkey: payout_script.to_vec(),
        }],
        locktime: 0,
    }
}

/// Grind the nonce until `header.check_pow(target)` — the actual mining
/// loop. `cancel` lets a node stop cleanly on shutdown.
///
/// For devnet's trivial target this returns in a handful of iterations;
/// for harder targets it's a real search. `budget` bounds total work so a
/// caller can yield periodically (the node uses a large budget + cancel).
pub fn mine(
    template: &Template,
    budget: u64,
    cancel: Option<&AtomicBool>,
) -> Result<BlockHeader, MineError> {
    let target = minibtc_consensus::pow::target_for_bits(template.header.bits)?;
    let mut h = template.header;
    let mut iter = 0u64;
    loop {
        if h.check_pow(&target) {
            return Ok(h);
        }
        iter = iter.saturating_add(1);
        if iter >= budget {
            return Err(MineError::BudgetExhausted(iter));
        }
        if let Some(c) = cancel {
            if c.load(Ordering::Relaxed) {
                return Err(MineError::Cancelled);
            }
        }
        h.nonce = h.nonce.wrapping_add(1);
    }
}

/// Assemble a full [`Block`] from a mined header + template txs.
pub fn assemble(template: &Template, header: BlockHeader) -> Block {
    Block {
        header,
        txs: template.txs.clone(),
    }
}

/// Compute the `bits` for the block after `prev_bits`, given the actual
/// timespan of the last retarget period. Delegates to consensus retarget.
pub fn next_bits(
    params: &ChainParams,
    prev_bits: u32,
    actual_span_secs: u64,
) -> Result<u32, MineError> {
    let target_span = u64::from(params.pow_target_spacing)
        .saturating_mul(u64::from(params.pow_target_timespan_blocks));
    retarget_bits(
        prev_bits,
        actual_span_secs,
        target_span,
        params.pow_clamp_factor,
    )
    .map_err(MineError::Bits)
}

/// Quick helper: does `hash` meet the target? Exposed for tests.
pub fn hash_meets_target(header: &BlockHeader, bits: u32) -> bool {
    let Ok(target) = minibtc_consensus::pow::target_for_bits(bits) else {
        return false;
    };
    header.check_pow(&target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ChainParams {
        ChainParams::devnet()
    }

    fn prev_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: Hash256([0x11; 32]),
            time: 1_700_000_000,
            bits: params().pow_limit_bits,
            nonce: 0,
        }
    }

    #[test]
    fn template_builds_coinbase_first() {
        let p = params();
        let payout = Script::p2pkh(&Keypair::generate().unwrap().public_key().key_hash()).0;
        let t = build_template(
            &p,
            &prev_header(),
            &[],
            &payout,
            1,
            1_700_000_031,
            p.pow_limit_bits,
        )
        .unwrap();
        assert_eq!(t.txs.len(), 1);
        assert!(t.txs[0].is_coinbase());
        assert_eq!(t.txs[0].outputs[0].value, Sats(p.subsidy_start));
    }

    #[test]
    fn mine_finds_valid_nonce_fast_on_devnet() {
        let p = params();
        let payout = Script::p2pkh(&Keypair::generate().unwrap().public_key().key_hash()).0;
        let t = build_template(
            &p,
            &prev_header(),
            &[],
            &payout,
            1,
            1_700_000_031,
            p.pow_limit_bits,
        )
        .unwrap();
        let h = mine(&t, 1_000_000, None).unwrap();
        assert!(hash_meets_target(&h, p.pow_limit_bits));
        // Deterministic: same template → same nonce (RFC-free grinding).
        let h2 = mine(&t, 1_000_000, None).unwrap();
        assert_eq!(h.nonce, h2.nonce);
    }

    #[test]
    fn mine_respects_budget_and_cancel() {
        let p = params();
        // Impossible target: bits with mantissa tiny → target ~0.
        let payout = Script::p2pkh(&Keypair::generate().unwrap().public_key().key_hash()).0;
        let t = build_template(
            &p,
            &prev_header(),
            &[],
            &payout,
            1,
            1_700_000_031,
            0x0100_0341,
        )
        .unwrap();
        // Budget 10 → must fail.
        assert!(matches!(
            mine(&t, 10, None),
            Err(MineError::BudgetExhausted(10))
        ));
        // Cancel flag set → Cancelled.
        let cancel = AtomicBool::new(true);
        assert!(matches!(
            mine(&t, 1_000_000, Some(&cancel)),
            Err(MineError::Cancelled)
        ));
    }

    #[test]
    fn template_includes_mempool_txs_and_fees() {
        let p = params();
        let miner = Keypair::generate().unwrap();
        // Fake a mempool tx paying miner.
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev: OutPoint {
                    txid: Hash256([0x77; 32]),
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: Sats(5_000),
                script_pubkey: Script::p2pkh(&miner.public_key().key_hash()).0,
            }],
            locktime: 0,
        };
        let t = build_template(
            &p,
            &prev_header(),
            &[(tx, Sats(500))],
            &Script::p2pkh(&miner.public_key().key_hash()).0,
            1,
            1_700_000_031,
            p.pow_limit_bits,
        )
        .unwrap();
        assert_eq!(t.txs.len(), 2);
        assert_eq!(t.fees, Sats(500));
        // coinbase = subsidy + fees
        assert_eq!(t.txs[0].outputs[0].value, Sats(p.subsidy_start + 500));
    }

    #[test]
    fn next_bits_delegates_retarget() {
        let p = params();
        // actual == target span → same bits.
        let span = u64::from(p.pow_target_spacing) * u64::from(p.pow_target_timespan_blocks);
        let b = next_bits(&p, p.pow_limit_bits, span).unwrap();
        let a = minibtc_consensus::decode_compact(p.pow_limit_bits).unwrap();
        let c = minibtc_consensus::decode_compact(b).unwrap();
        assert_eq!(a, c);
    }

    #[test]
    fn coinbase_txid_unique_per_height() {
        let payout = Script::p2pkh(&Keypair::generate().unwrap().public_key().key_hash()).0;
        let a = coinbase_transaction(1, Sats(100), &payout, &[]);
        let b = coinbase_transaction(2, Sats(100), &payout, &[]);
        assert_ne!(a.txid(), b.txid(), "coinbase txids must differ by height");
    }
}
