//! Rejected blocks leave no trace. Every block the chain refuses must
//! leave the UTXO set, tip, block index and undo store exactly as they
//! were. A block that passes the cheap checks but fails half-way through
//! applying its transactions is the dangerous case: if the earlier
//! transactions stay applied, this node's ledger silently diverges from
//! every honest node's (and the shutdown snapshot makes it permanent).

mod common;

use common::*;
use minibtc_chainstate::Chain;
use minibtc_crypto::{Hash256, Keypair};
use minibtc_primitives::*;
use minibtc_script::Script;

/// Everything a rejected block must not change.
#[derive(Debug, PartialEq, Eq)]
struct ChainSnapshot {
    utxo_fingerprint: Hash256,
    utxo_count: usize,
    tip: Hash256,
    height: u32,
    indexed_blocks: usize,
    undo_records: usize,
}

fn snapshot(chain: &Chain) -> ChainSnapshot {
    ChainSnapshot {
        utxo_fingerprint: chain.utxos.fingerprint(),
        utxo_count: chain.utxos.len(),
        tip: chain.tip,
        height: chain.height(),
        indexed_blocks: chain.blocks.len(),
        undo_records: chain.undos.len(),
    }
}

/// Submit `block`, require a rejection, and require that nothing moved.
fn assert_rejected_cleanly(chain: &mut Chain, block: Block, case: &str) {
    let before = snapshot(chain);
    let hash = block.header.block_hash();
    let result = chain.consider_block(block);
    assert!(result.is_err(), "{case}: block must be rejected");
    assert_eq!(
        snapshot(chain),
        before,
        "{case}: rejected block changed chain state ({result:?})"
    );
    assert!(
        !chain.blocks.contains_key(&hash),
        "{case}: rejected block must not be indexed"
    );
}

fn tip_header(chain: &Chain) -> BlockHeader {
    chain
        .blocks
        .get(&chain.tip)
        .map(|r| r.block.header)
        .unwrap_or_else(|| panic!("tip record missing"))
}

/// The coinbase outpoint and output of the active block at `height`.
fn coinbase_at(chain: &Chain, height: u32) -> (OutPoint, TxOutput) {
    let rec = chain
        .blocks
        .values()
        .find(|r| r.height == height)
        .unwrap_or_else(|| panic!("no block at height {height}"));
    let op = OutPoint {
        txid: rec.block.txs[0].txid(),
        vout: 0,
    };
    let out = chain
        .utxos
        .get(&op)
        .unwrap_or_else(|| panic!("coinbase at {height} already spent"))
        .output
        .clone();
    (op, out)
}

/// A chain 105 blocks deep: coinbases at heights 1..=5 are mature,
/// those at 100..=105 are not.
fn chain_with_mature_coins() -> (Chain, Keypair) {
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    assert_eq!(chain.height(), 105);
    (chain, miner)
}

fn next_block(chain: &Chain, miner: &Keypair, extra: Vec<Transaction>) -> Block {
    let prev = tip_header(chain);
    let mut txs = vec![coinbase_tx(
        miner,
        chain.height() + 1,
        chain.params.subsidy_start,
    )];
    txs.extend(extra);
    build_block(&prev, txs, prev.time + 31, &chain.params)
}

/// Re-mine `block` after changing it, keeping the merkle root honest.
fn remine(mut block: Block) -> Block {
    block.header.merkle_root = merkle_root(&block.txs);
    block.header.nonce = 0;
    block.header = mine_header(block.header);
    block
}

#[test]
fn immature_coinbase_spend_leaves_no_trace() {
    // The coinbase is applied before the immature spend is noticed, so a
    // non-atomic apply keeps the rejected block's coinbase output.
    let (mut chain, miner) = chain_with_mature_coins();
    let (op, out) = coinbase_at(&chain, 100);
    let spend = signed_spend(
        op,
        &out.script_pubkey,
        out.value,
        &miner,
        &p2pkh_spk(&miner),
        Sats(1_000_000),
        Sats(1_000),
    );
    let block = next_block(&chain, &miner, vec![spend]);
    assert_rejected_cleanly(&mut chain, block, "immature coinbase spend");
}

#[test]
fn intra_block_double_spend_leaves_no_trace() {
    // Two transactions spend the same mature coin. The first applies,
    // the second finds its input gone — the first must be rolled back.
    let (mut chain, miner) = chain_with_mature_coins();
    let (op, out) = coinbase_at(&chain, 1);
    let a = signed_spend(
        op,
        &out.script_pubkey,
        out.value,
        &miner,
        &p2pkh_spk(&Keypair::generate().unwrap()),
        Sats(1_000_000),
        Sats(1_000),
    );
    let b = signed_spend(
        op,
        &out.script_pubkey,
        out.value,
        &miner,
        &p2pkh_spk(&Keypair::generate().unwrap()),
        Sats(2_000_000),
        Sats(1_000),
    );
    assert_ne!(a.txid(), b.txid());
    let block = next_block(&chain, &miner, vec![a, b]);
    assert_rejected_cleanly(&mut chain, block, "intra-block double spend");
}

#[test]
fn every_other_rejected_block_leaves_no_trace() {
    let (mut chain, miner) = chain_with_mature_coins();
    let (op, out) = coinbase_at(&chain, 2);

    // Missing input: spends an outpoint that never existed.
    let ghost = OutPoint {
        txid: Hash256([0x5a; 32]),
        vout: 0,
    };
    let missing = signed_spend(
        ghost,
        &out.script_pubkey,
        out.value,
        &miner,
        &p2pkh_spk(&miner),
        Sats(1_000),
        Sats(1_000),
    );
    let block = next_block(&chain, &miner, vec![missing]);
    assert_rejected_cleanly(&mut chain, block, "missing input");

    // Overspend: outputs exceed the input value.
    let mut overspend = signed_spend(
        op,
        &out.script_pubkey,
        out.value,
        &miner,
        &p2pkh_spk(&miner),
        Sats(1_000),
        Sats(1_000),
    );
    overspend.outputs[0].value = Sats(out.value.sats() + 1);
    let sig =
        minibtc_script::sighash::sign_input(&overspend, 0, &out.script_pubkey, &miner).unwrap();
    overspend.inputs[0].script_sig = Script::p2pkh_spend(&sig, &miner.public_key()).0;
    let block = next_block(&chain, &miner, vec![overspend]);
    assert_rejected_cleanly(&mut chain, block, "overspend");

    // Coinbase over-claim.
    let mut block = next_block(&chain, &miner, vec![]);
    block.txs[0].outputs[0].value = Sats(chain.params.subsidy_start + 1);
    let block = remine(block);
    assert_rejected_cleanly(&mut chain, block, "coinbase over-claim");

    // Header merkle root that does not commit to the transactions.
    let mut block = next_block(&chain, &miner, vec![]);
    block.header.merkle_root = Hash256([0x11; 32]);
    block.header = mine_header(block.header);
    assert_rejected_cleanly(&mut chain, block, "merkle mismatch");

    // Hash above target.
    let mut block = next_block(&chain, &miner, vec![]);
    let target = minibtc_consensus::target_for_bits(block.header.bits).unwrap();
    while block.header.check_pow(&target) {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    assert_rejected_cleanly(&mut chain, block, "proof of work");

    // Timestamp not above median-time-past.
    let mut block = next_block(&chain, &miner, vec![]);
    block.header.time = tip_header(&chain).time.saturating_sub(10_000);
    block.header = mine_header(block.header);
    assert_rejected_cleanly(&mut chain, block, "time too old");

    // A second coinbase-shaped transaction.
    let stray = coinbase_tx(&Keypair::generate().unwrap(), 7, 1);
    let block = next_block(&chain, &miner, vec![stray]);
    assert_rejected_cleanly(&mut chain, block, "stray coinbase");

    // The chain still accepts an honest block afterwards.
    let honest = next_block(&chain, &miner, vec![]);
    chain.consider_block(honest).unwrap();
    assert_eq!(chain.height(), 106);
}
