//! Reorgs judge a side branch by the fork point's state, and a reorg that
//! fails half-way leaves the node on its old tip.
//!
//! A side-branch block must be checked against the UTXO set as it was at
//! the fork point plus the branch's own earlier blocks — not the active
//! tip's set. Checking it against the tip rejects valid branches (a
//! conflicting spend of a coin the active chain already spent: the
//! double-spend race, where honest nodes then split) and lets invalid
//! ones in (spending a coin that only exists on the active chain). And if
//! connecting the heavier branch fails midway, the node must end on its
//! previous tip with its previous UTXO set, not on the fork point.

mod common;

use common::*;
use minibtc_chainstate::{BlockStatus, Chain};
use minibtc_crypto::Keypair;
use minibtc_primitives::*;

fn header_of(chain: &Chain, hash: minibtc_crypto::Hash256) -> BlockHeader {
    chain
        .blocks
        .get(&hash)
        .map(|r| r.block.header)
        .unwrap_or_else(|| panic!("block {hash} missing"))
}

fn coinbase_at(chain: &Chain, height: u32) -> (OutPoint, TxOutput) {
    let rec = chain
        .blocks
        .values()
        .find(|r| r.height == height && r.status == BlockStatus::Active)
        .unwrap_or_else(|| panic!("no active block at height {height}"));
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

/// A child of `parent` at `height`, `dt` seconds later, paying `miner`.
fn child(
    chain: &Chain,
    parent: &BlockHeader,
    height: u32,
    dt: u32,
    miner: &Keypair,
    extra: Vec<Transaction>,
) -> Block {
    let mut txs = vec![coinbase_tx(miner, height, chain.params.subsidy_start)];
    txs.extend(extra);
    build_block(parent, txs, parent.time + dt, &chain.params)
}

fn pay(op: OutPoint, out: &TxOutput, key: &Keypair, to: &Keypair, amount: u64) -> Transaction {
    signed_spend(
        op,
        &out.script_pubkey,
        out.value,
        key,
        &p2pkh_spk(to),
        Sats(amount),
        Sats(1_000),
    )
}

fn new_key() -> Keypair {
    Keypair::generate().unwrap_or_else(|e| panic!("keygen: {e:?}"))
}

#[test]
fn heavier_branch_with_a_conflicting_spend_wins() {
    // Active: F -> A1 (T1 spends X). Side: F -> B1 (T2 spends X) -> B2.
    // B1 is valid at the fork point; checked against the tip it looked
    // like a double spend and the heavier branch could never be followed.
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let fork = header_of(&chain, chain.tip);
    let (x, x_out) = coinbase_at(&chain, 1);
    let t1 = pay(x, &x_out, &miner, &new_key(), 1_000_000);
    let t2 = pay(x, &x_out, &miner, &new_key(), 2_000_000);
    let t1_out = OutPoint {
        txid: t1.txid(),
        vout: 0,
    };
    let t2_out = OutPoint {
        txid: t2.txid(),
        vout: 0,
    };

    let a1 = child(&chain, &fork, 106, 31, &miner, vec![t1]);
    chain.consider_block(a1).unwrap();
    assert!(chain.utxos.get(&t1_out).is_some());

    let other = new_key();
    let b1 = child(&chain, &fork, 106, 40, &other, vec![t2]);
    chain
        .consider_block(b1.clone())
        .unwrap_or_else(|e| panic!("side block valid at the fork point refused: {e:?}"));
    let b2 = child(&chain, &b1.header, 107, 31, &other, vec![]);
    chain.consider_block(b2.clone()).unwrap();

    assert_eq!(chain.tip, b2.header.block_hash(), "most work must win");
    assert!(chain.utxos.get(&t2_out).is_some(), "T2 confirmed");
    assert!(chain.utxos.get(&t1_out).is_none(), "T1 reorged out");
    assert!(chain.utxos.get(&x).is_none(), "X spent exactly once");
}

#[test]
fn failed_reorg_leaves_the_old_tip_and_utxo_set() {
    // Active: F -> A1 (creates Y) -> A2. Side: F -> B1 (spends Y) -> B2 ->
    // B3. Y does not exist at the fork point, so B1 is invalid there; the
    // heavier side branch must be refused as a whole.
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let fork = header_of(&chain, chain.tip);
    let (x, x_out) = coinbase_at(&chain, 1);
    let y_owner = new_key();
    let make_y = pay(x, &x_out, &miner, &y_owner, 5_000_000);
    let y = OutPoint {
        txid: make_y.txid(),
        vout: 0,
    };
    let y_out = make_y.outputs[0].clone();

    let a1 = child(&chain, &fork, 106, 31, &miner, vec![make_y]);
    chain.consider_block(a1.clone()).unwrap();
    let a2 = child(&chain, &a1.header, 107, 31, &miner, vec![]);
    chain.consider_block(a2.clone()).unwrap();
    let before_fp = chain.utxos.fingerprint();
    let before_len = chain.utxos.len();
    let before_tip = chain.tip;

    let other = new_key();
    let spend_y = pay(y, &y_out, &y_owner, &other, 1_000_000);
    let b1 = child(&chain, &fork, 106, 40, &other, vec![spend_y]);
    let b2 = child(&chain, &b1.header, 107, 31, &other, vec![]);
    let b3 = child(&chain, &b2.header, 108, 31, &other, vec![]);
    let _ = chain.consider_block(b1.clone());
    let _ = chain.consider_block(b2.clone());
    let res = chain.consider_block(b3.clone());

    assert!(res.is_err(), "reorg onto an invalid branch must fail");
    assert_eq!(chain.tip, before_tip, "node must stay on its old tip");
    assert_eq!(chain.height(), 107);
    assert_eq!(chain.utxos.fingerprint(), before_fp, "UTXO set changed");
    assert_eq!(chain.utxos.len(), before_len);
    for b in [&a1, &a2] {
        assert_eq!(
            chain.blocks.get(&b.header.block_hash()).map(|r| r.status),
            Some(BlockStatus::Active),
            "old branch must stay active"
        );
    }
    for b in [&b1, &b2, &b3] {
        assert_ne!(
            chain.blocks.get(&b.header.block_hash()).map(|r| r.status),
            Some(BlockStatus::Active),
            "invalid branch must not be active"
        );
    }

    // The node keeps working on the old branch.
    let a3 = child(&chain, &a2.header, 108, 31, &miner, vec![]);
    chain.consider_block(a3.clone()).unwrap();
    assert_eq!(chain.tip, a3.header.block_hash());
}

#[test]
fn two_nodes_with_conflicting_spends_converge_on_one() {
    // Node 1 confirms T1, node 2 confirms T2 (same coin). Once node 2's
    // branch gets ahead, both nodes must end on the same tip and the same
    // UTXO set, with exactly one of the two spends confirmed.
    let (mut node1, miner) = fresh_chain();
    mine_empty(&mut node1, &miner, 105);
    let genesis = node1.blocks.get(&node1.genesis).unwrap().block.clone();
    let mut node2 = Chain::new(node1.params.clone(), genesis).unwrap();
    let mut history: Vec<Block> = node1
        .blocks
        .values()
        .filter(|r| r.height > 0)
        .map(|r| r.block.clone())
        .collect();
    history.sort_by_key(|b| {
        node1
            .blocks
            .get(&b.header.block_hash())
            .map(|r| r.height)
            .unwrap_or(0)
    });
    for b in history {
        node2.consider_block(b).unwrap();
    }
    assert_eq!(node1.tip, node2.tip);
    assert_eq!(node1.utxos.fingerprint(), node2.utxos.fingerprint());

    let fork = header_of(&node1, node1.tip);
    let (x, x_out) = coinbase_at(&node1, 1);
    let t1 = pay(x, &x_out, &miner, &new_key(), 1_000_000);
    let t2 = pay(x, &x_out, &miner, &new_key(), 2_000_000);
    let (t1_id, t2_id) = (t1.txid(), t2.txid());

    let a1 = child(&node1, &fork, 106, 31, &miner, vec![t1]);
    let m2 = new_key();
    let b1 = child(&node2, &fork, 106, 33, &m2, vec![t2]);
    node1.consider_block(a1.clone()).unwrap();
    node2.consider_block(b1.clone()).unwrap();

    // Gossip: each node hears the other's block (equal work, side branch).
    node1
        .consider_block(b1.clone())
        .unwrap_or_else(|e| panic!("node 1 refused node 2's valid block: {e:?}"));
    node2
        .consider_block(a1)
        .unwrap_or_else(|e| panic!("node 2 refused node 1's valid block: {e:?}"));

    // Node 2 extends its branch; both hear it.
    let b2 = child(&node2, &b1.header, 107, 31, &m2, vec![]);
    node2.consider_block(b2.clone()).unwrap();
    node1
        .consider_block(b2.clone())
        .unwrap_or_else(|e| panic!("node 1 cannot follow the heavier branch: {e:?}"));

    assert_eq!(node1.tip, b2.header.block_hash());
    assert_eq!(node2.tip, b2.header.block_hash());
    assert_eq!(node1.utxos.fingerprint(), node2.utxos.fingerprint());
    let confirmed = |c: &Chain, id| c.utxos.get(&OutPoint { txid: id, vout: 0 }).is_some();
    for node in [&node1, &node2] {
        assert!(confirmed(node, t2_id), "T2 must be confirmed");
        assert!(!confirmed(node, t1_id), "T1 must not be confirmed");
    }
}

#[test]
fn a_failed_reorg_drops_every_descendant_of_the_invalid_block() {
    // Off the main block at 100: B1 (invalid spend) with two stored
    // descendant branches, x (to 105, equal work) and y (to 104). Block x6
    // makes branch x heavier; the reorg fails at B1, and every descendant
    // of B1 on both branches must go. The active chain stays.
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let tip = chain.tip;
    let mut cur = chain.tip;
    while chain.blocks[&cur].height > 100 {
        cur = chain.blocks[&cur].block.header.prev_hash;
    }
    let fork = header_of(&chain, cur);
    let other = new_key();
    let ghost = OutPoint {
        txid: minibtc_crypto::Hash256([0x77; 32]),
        vout: 0,
    };
    let bad = signed_spend(
        ghost,
        &p2pkh_spk(&other),
        Sats(10_000),
        &other,
        &p2pkh_spk(&other),
        Sats(1_000),
        Sats(1_000),
    );
    let b1 = child(&chain, &fork, 101, 40, &other, vec![bad]);
    chain
        .consider_block(b1.clone())
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut expected = vec![b1.header.block_hash()];
    let mut branch = |chain: &mut Chain, first_dt: u32, to: u32| -> BlockHeader {
        let key = new_key();
        let mut parent = b1.header;
        for (i, h) in (102..=to).enumerate() {
            let dt = if i == 0 { first_dt } else { 31 };
            let b = child(chain, &parent, h, dt, &key, vec![]);
            parent = b.header;
            expected.push(b.header.block_hash());
            chain.consider_block(b).unwrap_or_else(|e| panic!("{e:?}"));
        }
        parent
    };
    let x5 = branch(&mut chain, 31, 105);
    let _y4 = branch(&mut chain, 33, 104);
    assert_eq!(chain.tip, tip, "equal or less work: still side branches");
    let x6 = child(&chain, &x5, 106, 31, &other, vec![]);
    expected.push(x6.header.block_hash());
    assert!(
        chain.consider_block(x6).is_err(),
        "reorg onto B1's branch fails"
    );

    assert_eq!(chain.tip, tip);
    for h in &expected {
        assert!(!chain.blocks.contains_key(h), "descendant of B1 kept");
        assert!(chain.is_invalid(h));
    }
    let mut dropped = chain.take_dropped();
    dropped.sort();
    expected.sort();
    assert_eq!(dropped, expected);
}

#[test]
fn a_block_too_far_in_the_future_is_retried_not_marked_invalid() {
    // "Too far in the future" depends on the clock, not on the block: if
    // the clock steps back after a side block was stored, a reorg can fail
    // on that rule. Bitcoin Core never caches it as invalid; neither may we.
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let tip = chain.tip;
    let mut cur = chain.tip;
    while chain.blocks[&cur].height > 103 {
        cur = chain.blocks[&cur].block.header.prev_hash;
    }
    let fork = header_of(&chain, cur);
    let key = new_key();
    // B104 is timestamped well ahead; B105 and B106 are not (they only need
    // to beat the median of the past 11 blocks).
    let b104 = child(&chain, &fork, 104, 10_000, &key, vec![]);
    chain.consider_block(b104.clone()).unwrap();
    let mut b105 = child(&chain, &b104.header, 105, 0, &key, vec![]);
    b105.header.time = fork.time + 200;
    b105 = remine(b105);
    chain.consider_block(b105.clone()).unwrap();
    // The clock steps back: B104 is now more than 2 hours ahead of it.
    let max_future = chain.params.max_future_time_secs;
    chain.set_now(Some(b104.header.time - max_future - 1_000));
    let mut b106 = child(&chain, &b105.header, 106, 0, &key, vec![]);
    b106.header.time = fork.time + 300;
    b106 = remine(b106);
    assert!(
        chain.consider_block(b106.clone()).is_err(),
        "reorg fails on B104's time"
    );
    assert_eq!(chain.tip, tip);
    assert!(
        !chain.is_invalid(&b104.header.block_hash()),
        "a time-too-new block must not be remembered as invalid"
    );
    assert!(
        chain.take_dropped().is_empty(),
        "nothing dropped from the index"
    );

    // The clock is right again: the next block on the branch reorgs onto it.
    chain.set_now(None);
    let b107 = child(&chain, &b106.header, 107, 31, &key, vec![]);
    chain
        .consider_block(b107.clone())
        .unwrap_or_else(|e| panic!("branch must still be usable: {e:?}"));
    assert_eq!(chain.tip, b107.header.block_hash());
}

/// Re-mine `block` after changing its header or transactions.
fn remine(mut block: Block) -> Block {
    block.header.merkle_root = merkle_root(&block.txs);
    block.header.nonce = 0;
    block.header = mine_header(block.header);
    block
}
