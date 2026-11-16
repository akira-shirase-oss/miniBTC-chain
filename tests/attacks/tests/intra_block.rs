//! Transactions inside one block see each other (CVE-2018-17144 class).
//!
//! Bitcoin validates transaction *i* of a block against the UTXO set as
//! it stands after transactions `0..i` of the same block: a coin spent by
//! an earlier transaction is gone, an output created by an earlier
//! transaction exists. Validating every transaction against the
//! pre-block set instead lets two transactions spend one coin (the
//! inflation half of CVE-2018-17144) and makes a child that spends its
//! parent in the same block impossible to confirm.

mod common;

use common::*;
use minibtc_chainstate::{Chain, ChainError};
use minibtc_consensus::{BlockError, ChainParams, TxError, validate_block};
use minibtc_crypto::Keypair;
use minibtc_primitives::*;
use std::collections::HashMap;

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

/// `parent` pays `owner`; `child` spends the parent's first output.
fn parent_and_child(op: OutPoint, out: &TxOutput, owner: &Keypair) -> (Transaction, Transaction) {
    let parent = signed_spend(
        op,
        &out.script_pubkey,
        out.value,
        owner,
        &p2pkh_spk(owner),
        Sats(10_000_000),
        Sats(1_000),
    );
    let parent_op = OutPoint {
        txid: parent.txid(),
        vout: 0,
    };
    let child = signed_spend(
        parent_op,
        &p2pkh_spk(owner),
        parent.outputs[0].value,
        owner,
        &p2pkh_spk(&Keypair::generate().unwrap_or_else(|e| panic!("keygen: {e:?}"))),
        Sats(5_000_000),
        Sats(1_000),
    );
    (parent, child)
}

#[test]
fn two_spends_of_one_coin_in_one_block_fail_consensus_validation() {
    // Pure consensus check over a map view: the second spend of X must be
    // refused by validate_block itself, not left to a later apply step.
    let params = ChainParams::devnet();
    let owner = Keypair::generate().unwrap();
    let x = OutPoint {
        txid: minibtc_crypto::Hash256([0x42; 32]),
        vout: 0,
    };
    let x_out = TxOutput {
        value: Sats(50_000_000),
        script_pubkey: p2pkh_spk(&owner),
    };
    let view = MapView(HashMap::from([(x, x_out.clone())]));
    let pay = |to: &Keypair, amount: u64| {
        signed_spend(
            x,
            &x_out.script_pubkey,
            x_out.value,
            &owner,
            &p2pkh_spk(to),
            Sats(amount),
            Sats(1_000),
        )
    };
    let a = pay(&Keypair::generate().unwrap(), 1_000_000);
    let b = pay(&Keypair::generate().unwrap(), 2_000_000);
    let genesis_like = BlockHeader {
        version: 1,
        prev_hash: minibtc_crypto::Hash256::ZERO,
        merkle_root: minibtc_crypto::Hash256::ZERO,
        time: 1_700_000_000,
        bits: params.pow_limit_bits,
        nonce: 0,
    };
    let block = build_block(
        &genesis_like,
        vec![coinbase_tx(&owner, 1, params.subsidy_start), a, b],
        1_700_000_031,
        &params,
    );
    let err = validate_block(&block, &view, &params, 1).unwrap_err();
    assert!(
        matches!(
            err,
            BlockError::Tx {
                index: 2,
                source: TxError::MissingInput(op)
            } if op == x
        ),
        "second spend of one coin must fail as tx 2 / missing input, got {err:?}"
    );
}

#[test]
fn intra_block_double_spend_is_a_validation_error_on_chain() {
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let (op, out) = coinbase_at(&chain, 1);
    let spend = |amount: u64| {
        signed_spend(
            op,
            &out.script_pubkey,
            out.value,
            &miner,
            &p2pkh_spk(&Keypair::generate().unwrap()),
            Sats(amount),
            Sats(1_000),
        )
    };
    let block = next_block(&chain, &miner, vec![spend(1_000_000), spend(2_000_000)]);
    let err = chain.consider_block(block).unwrap_err();
    assert!(
        matches!(
            err,
            ChainError::InvalidBlock(BlockError::Tx {
                index: 2,
                source: TxError::MissingInput(_)
            })
        ),
        "expected tx 2 missing-input validation error, got {err:?}"
    );
    assert_eq!(chain.height(), 105);
}

#[test]
fn child_spending_parent_in_same_block_is_accepted() {
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let (op, out) = coinbase_at(&chain, 1);
    let (parent, child) = parent_and_child(op, &out, &miner);
    let parent_op = OutPoint {
        txid: parent.txid(),
        vout: 0,
    };
    let child_op = OutPoint {
        txid: child.txid(),
        vout: 0,
    };
    let block = next_block(&chain, &miner, vec![parent, child]);
    chain
        .consider_block(block)
        .unwrap_or_else(|e| panic!("child-spends-parent block must connect: {e:?}"));
    assert_eq!(chain.height(), 106);
    assert!(chain.utxos.get(&op).is_none(), "funding coin spent");
    assert!(chain.utxos.get(&parent_op).is_none(), "parent output spent");
    assert!(chain.utxos.get(&child_op).is_some(), "child output unspent");
}

#[test]
fn child_before_parent_in_same_block_is_rejected() {
    // Order matters: a child listed before its parent spends an output
    // that does not exist yet.
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let (op, out) = coinbase_at(&chain, 1);
    let (parent, child) = parent_and_child(op, &out, &miner);
    let block = next_block(&chain, &miner, vec![child, parent]);
    let err = chain.consider_block(block).unwrap_err();
    assert!(
        matches!(
            err,
            ChainError::InvalidBlock(BlockError::Tx {
                index: 1,
                source: TxError::MissingInput(_)
            })
        ),
        "child before parent must fail as tx 1 / missing input, got {err:?}"
    );
}

#[test]
fn spending_this_blocks_coinbase_is_immature() {
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let prev = tip_header(&chain);
    let cb = coinbase_tx(&miner, chain.height() + 1, chain.params.subsidy_start);
    let cb_op = OutPoint {
        txid: cb.txid(),
        vout: 0,
    };
    let spend = signed_spend(
        cb_op,
        &cb.outputs[0].script_pubkey,
        cb.outputs[0].value,
        &miner,
        &p2pkh_spk(&miner),
        Sats(1_000_000),
        Sats(1_000),
    );
    let block = build_block(&prev, vec![cb, spend], prev.time + 31, &chain.params);
    let err = chain.consider_block(block).unwrap_err();
    assert!(
        matches!(err, ChainError::ImmatureCoinbase { depth: 0, .. }),
        "same-block coinbase spend must be immature, got {err:?}"
    );
    assert_eq!(chain.height(), 105);
}
