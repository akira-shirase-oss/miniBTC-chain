//! `--reindex` must rebuild the most-work *valid* chain from whatever the
//! store holds, including side blocks a peer supplied. Side blocks are
//! stored after header and context-free checks only (their transactions
//! are judged when their branch is activated), so the store can hold a
//! tx-invalid side block. Reindex used to follow an arbitrary child of the
//! tip with `connect_tip(..)?` (one bad side block made it fail) and to
//! feed leftovers through `consider_block` in hash-map order (it could end
//! on a less-work tip). Every test here is deterministic: pass/fail does
//! not depend on iteration order.

mod common;

use common::*;
use minibtc_chainstate::Chain;
use minibtc_crypto::{Hash256, Keypair};
use minibtc_primitives::*;
use minibtc_storage::Store;

fn header_of(chain: &Chain, hash: Hash256) -> BlockHeader {
    chain
        .blocks
        .get(&hash)
        .map(|r| r.block.header)
        .unwrap_or_else(|| panic!("block {hash} missing"))
}

fn active_at(chain: &Chain, height: u32) -> Hash256 {
    let mut cur = chain.tip;
    loop {
        let rec = chain.blocks.get(&cur).unwrap_or_else(|| panic!("walk"));
        if rec.height == height {
            return cur;
        }
        cur = rec.block.header.prev_hash;
    }
}

/// A child of `parent` (at `height`) carrying `extra`, with the bits the
/// schedule requires there.
fn child_of(
    chain: &Chain,
    parent: Hash256,
    height: u32,
    dt: u32,
    extra: Vec<Transaction>,
) -> Block {
    let p = header_of(chain, parent);
    let miner = Keypair::generate().unwrap_or_else(|e| panic!("{e:?}"));
    let mut txs = vec![coinbase_tx(&miner, height, chain.params.subsidy_start)];
    txs.extend(extra);
    let bits = chain
        .next_bits_after(parent)
        .unwrap_or_else(|e| panic!("{e:?}"));
    build_block_with_bits(&p, txs, p.time + dt, &chain.params, bits)
}

/// Spends an outpoint that never existed: invalid at every fork point.
fn bad_spend() -> Transaction {
    let key = Keypair::generate().unwrap_or_else(|e| panic!("{e:?}"));
    signed_spend(
        OutPoint {
            txid: Hash256([0x99; 32]),
            vout: 7,
        },
        &p2pkh_spk(&key),
        Sats(10_000),
        &key,
        &p2pkh_spk(&key),
        Sats(1_000),
        Sats(1_000),
    )
}

fn genesis_of(chain: &Chain) -> Block {
    chain
        .blocks
        .get(&chain.genesis)
        .unwrap_or_else(|| panic!("genesis missing"))
        .block
        .clone()
}

#[test]
fn reindex_survives_stored_tx_invalid_side_blocks() {
    // A bad-spend side block hangs off every main block from 90 to 104.
    // Each has the same work as the main block at its height, so it is
    // stored as a side branch and never judged.
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    for h in 90..=104u32 {
        let parent = active_at(&chain, h);
        let side = child_of(&chain, parent, h + 1, 7, vec![bad_spend()]);
        chain.consider_block(side).unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.snapshot(&chain).unwrap();

    let rebuilt = store
        .reindex(chain.params.clone(), genesis_of(&chain))
        .unwrap_or_else(|e| panic!("reindex must not fail on a stored side block: {e:?}"));
    assert_eq!(rebuilt.tip, chain.tip);
    assert_eq!(rebuilt.utxos.fingerprint(), chain.utxos.fingerprint());
}

#[test]
fn reindex_ends_on_the_most_work_tip() {
    // Valid three-block side branches fork off at 80, 85, 90, 95 and 100;
    // the main chain (105) has the most work.
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    for fork in [80u32, 85, 90, 95, 100] {
        let mut parent = active_at(&chain, fork);
        for i in 1..=3u32 {
            let b = child_of(&chain, parent, fork + i, 7, vec![]);
            parent = b.header.block_hash();
            chain.consider_block(b).unwrap();
        }
    }
    assert_eq!(chain.height(), 105);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.snapshot(&chain).unwrap();

    let rebuilt = store
        .reindex(chain.params.clone(), genesis_of(&chain))
        .unwrap();
    assert_eq!(
        rebuilt.tip, chain.tip,
        "reindex must end on the most-work tip"
    );
    assert_eq!(rebuilt.height(), 105);
    assert_eq!(rebuilt.utxos.fingerprint(), chain.utxos.fingerprint());
}

#[test]
fn failed_reorg_reports_dropped_blocks_for_deletion() {
    // A heavier side branch off 100 whose second block spends nothing.
    // Its first five blocks are stored as side blocks; the sixth has more
    // work than the tip, so the reorg runs, fails, and the chain reports
    // the invalid block and its descendants for the node to delete.
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let tip = chain.tip;
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.snapshot(&chain).unwrap();

    let mut parent = active_at(&chain, 100);
    let mut branch = Vec::new();
    for i in 1..=6u32 {
        let extra = if i == 2 { vec![bad_spend()] } else { vec![] };
        let b = child_of(&chain, parent, 100 + i, 7, extra);
        parent = b.header.block_hash();
        if i < 6 {
            chain.consider_block(b.clone()).unwrap(); // stored as a side block
            store.put_side_block(&chain, &parent).unwrap();
        }
        branch.push(b);
    }
    assert!(chain.consider_block(branch[5].clone()).is_err());
    assert_eq!(chain.tip, tip);
    let mut dropped = chain.take_dropped();
    dropped.sort();
    let mut expected: Vec<Hash256> = branch[1..].iter().map(|b| b.header.block_hash()).collect();
    expected.sort();
    assert_eq!(dropped, expected, "invalid block and descendants reported");
    assert!(chain.take_dropped().is_empty(), "reported once");

    store.delete_blocks(&dropped).unwrap();
    for h in &dropped {
        assert!(
            store.get_block(h).unwrap().is_none(),
            "dropped block kept on disk"
        );
    }
    assert!(
        store
            .get_block(&branch[0].header.block_hash())
            .unwrap()
            .is_some()
    );
}

#[test]
fn reindex_rejects_a_heavier_invalid_branch_and_writes_it_out() {
    // The store holds a side branch off 100 that is heavier than the main
    // chain it holds, with a bad spend in its second block. Reindex must
    // judge it, refuse it, end on the valid tip, and the snapshot of the
    // result must not contain the invalid blocks.
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let valid_tip = chain.tip;
    // Extend main to 108 so the 6-block branch (to 106) is stored as a
    // side branch, then drop 106..108 from the store.
    let mut top = Vec::new();
    for h in 106..=108u32 {
        let b = child_of(&chain, chain.tip, h, 31, vec![]);
        top.push(b.header.block_hash());
        chain.consider_block(b).unwrap();
    }
    let mut parent = active_at(&chain, 100);
    let mut branch = Vec::new();
    for i in 1..=6u32 {
        let extra = if i == 2 { vec![bad_spend()] } else { vec![] };
        let b = child_of(&chain, parent, 100 + i, 7, extra);
        parent = b.header.block_hash();
        branch.push(parent);
        chain.consider_block(b).unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.snapshot(&chain).unwrap();
    store.delete_blocks(&top).unwrap();

    let rebuilt = store
        .reindex(chain.params.clone(), genesis_of(&chain))
        .unwrap();
    assert_eq!(
        rebuilt.tip, valid_tip,
        "valid tip, not the invalid heavier branch"
    );
    assert_eq!(rebuilt.height(), 105);
    store.snapshot(&rebuilt).unwrap();
    for h in &branch[1..] {
        assert!(
            store.get_block(h).unwrap().is_none(),
            "invalid block kept on disk"
        );
    }
}

#[test]
fn reindex_leaves_no_pending_reorg_report() {
    // The store's recorded tip is main 105; a heavier valid side branch
    // (to 106) was stored block by block. The replay follows main first
    // and then reorgs onto the branch. That replay-internal reorg must not
    // be handed to the node as if it had just happened.
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.snapshot(&chain).unwrap();
    let mut parent = active_at(&chain, 100);
    for h in 101..=106u32 {
        let b = child_of(&chain, parent, h, 7, vec![]);
        parent = b.header.block_hash();
        chain.consider_block(b).unwrap();
        store.put_side_block(&chain, &parent).unwrap();
    }
    assert_eq!(chain.tip, parent, "the live chain reorged onto the branch");

    let mut rebuilt = store
        .reindex(chain.params.clone(), genesis_of(&chain))
        .unwrap();
    assert_eq!(rebuilt.tip, parent, "reindex ends on the heavier branch");
    assert!(
        rebuilt.take_reorg().is_none(),
        "the replay's own reorg must not leak to the node"
    );
}
