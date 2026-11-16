//! CVE-2012-2459: duplicated transactions that keep the merkle root.
//!
//! Bitcoin's merkle tree pads an odd level by repeating its last hash, so
//! `[cb, A, B]` and `[cb, A, B, B]` have the same root and therefore the
//! same block hash. A node that rejects the padded copy and remembers the
//! *hash* as bad can never accept the honest block. Bitcoin Core detects
//! the padded form by looking for two identical hashes in a pair position
//! at any level of the tree, rejects it as "mutated", and does not mark the
//! hash invalid. MiniBTC must do the same.

mod common;

use common::*;
use minibtc_chainstate::{Chain, ChainError};
use minibtc_consensus::BlockError;
use minibtc_crypto::Keypair;
use minibtc_primitives::*;

fn tip_header(chain: &Chain) -> BlockHeader {
    chain
        .blocks
        .get(&chain.tip)
        .map(|r| r.block.header)
        .unwrap_or_else(|| panic!("tip record missing"))
}

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

/// `n` distinct, cheap transactions (only their txids matter here).
fn distinct_txs(n: u32) -> Vec<Transaction> {
    (0..n)
        .map(|i| Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev: OutPoint {
                    txid: minibtc_crypto::Hash256([i as u8 + 1; 32]),
                    vout: i,
                },
                script_sig: vec![i as u8],
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: Sats(u64::from(i) + 1),
                script_pubkey: vec![0x51],
            }],
            locktime: 0,
        })
        .collect()
}

fn header_with_root(root: minibtc_crypto::Hash256) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_hash: minibtc_crypto::Hash256::ZERO,
        merkle_root: root,
        time: 1_700_000_000,
        bits: 0x207f_ffff,
        nonce: 0,
    }
}

#[test]
fn duplicated_tail_at_leaf_level_is_detected() {
    // [cb, A, B] pads to [cb, A, B, B] — same root, different list.
    let txs = distinct_txs(3);
    let honest_root = merkle_root(&txs);
    let mut padded = txs.clone();
    padded.push(txs[2].clone());
    assert_eq!(merkle_root(&padded), honest_root, "same root by padding");

    let header = header_with_root(honest_root);
    assert_eq!(check_merkle_root(&header, &txs), Ok(()));
    assert_eq!(
        check_merkle_root(&header, &padded),
        Err(MerkleError::Ambiguous),
        "padded [cb,A,B,B] must be detected as mutated"
    );
}

#[test]
fn duplicated_subtree_at_a_higher_level_is_detected() {
    // Six leaves → level 1 has three hashes and pads its last one. The
    // list with leaves 4 and 5 repeated produces that padded level
    // explicitly: identical hashes at level 1, not at the leaves.
    let txs = distinct_txs(6);
    let honest_root = merkle_root(&txs);
    let mut padded = txs.clone();
    padded.push(txs[4].clone());
    padded.push(txs[5].clone());
    assert_eq!(merkle_root(&padded), honest_root, "same root by padding");

    let header = header_with_root(honest_root);
    assert_eq!(check_merkle_root(&header, &txs), Ok(()));
    assert_eq!(
        check_merkle_root(&header, &padded),
        Err(MerkleError::Ambiguous),
        "level-1 duplication must be detected"
    );
}

#[test]
fn honest_odd_and_single_lists_are_not_mutations() {
    for n in [1u32, 2, 3, 5, 7, 9] {
        let txs = distinct_txs(n);
        let header = header_with_root(merkle_root(&txs));
        assert_eq!(check_merkle_root(&header, &txs), Ok(()), "{n} leaves");
    }
}

#[test]
fn mutated_block_first_then_honest_block_is_accepted() {
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let (op_a, out_a) = coinbase_at(&chain, 1);
    let (op_b, out_b) = coinbase_at(&chain, 2);
    let pay = |op, out: &TxOutput| {
        signed_spend(
            op,
            &out.script_pubkey,
            out.value,
            &miner,
            &p2pkh_spk(&Keypair::generate().unwrap_or_else(|e| panic!("{e:?}"))),
            Sats(1_000_000),
            Sats(1_000),
        )
    };
    let a = pay(op_a, &out_a);
    let b = pay(op_b, &out_b);
    let prev = tip_header(&chain);
    let cb = coinbase_tx(&miner, chain.height() + 1, chain.params.subsidy_start);
    let honest = build_block(&prev, vec![cb, a, b], prev.time + 31, &chain.params);
    let mut mutated = honest.clone();
    mutated.txs.push(honest.txs[2].clone());
    assert_eq!(
        mutated.header.block_hash(),
        honest.header.block_hash(),
        "the mutated copy carries the honest block's hash"
    );

    let err = chain.consider_block(mutated).unwrap_err();
    assert!(
        matches!(
            err,
            ChainError::InvalidBlock(BlockError::Merkle(MerkleError::Ambiguous))
        ),
        "mutated block must be refused as a merkle mutation, got {err:?}"
    );
    assert_eq!(chain.height(), 105, "nothing connected");

    chain
        .consider_block(honest.clone())
        .unwrap_or_else(|e| panic!("honest block must still connect: {e:?}"));
    assert_eq!(chain.tip, honest.header.block_hash());
    assert_eq!(chain.height(), 106);
}
