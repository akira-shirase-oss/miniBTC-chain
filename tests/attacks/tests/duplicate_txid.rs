//! BIP30 / BIP34: a transaction id may not be reused while its outputs
//! are unspent.
//!
//! Two coinbases that pay the same script the same amount with the same
//! scriptSig have the same txid. Without a rule against it the second
//! one overwrites the first's still-unspent output in the UTXO set (one
//! coin silently destroyed), and disconnecting the second block later
//! deletes the original entry. Bitcoin fixed this twice: BIP30 rejects any
//! transaction whose outputs already exist unspent, and BIP34 makes every
//! coinbase start with its block height, so coinbase txids cannot repeat.

mod common;

use common::*;
use minibtc_chainstate::Chain;
use minibtc_consensus::{ChainParams, validate_block};
use minibtc_crypto::{Hash256, Keypair};
use minibtc_primitives::*;
use minibtc_script::Script;
use std::collections::HashMap;

fn tip_header(chain: &Chain) -> BlockHeader {
    chain
        .blocks
        .get(&chain.tip)
        .map(|r| r.block.header)
        .unwrap_or_else(|| panic!("tip record missing"))
}

/// A coinbase with a fixed scriptSig — what a careless miner (or this
/// repo's old miner after 65,536 blocks) produces at every height.
fn fixed_coinbase(miner: &Keypair, value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: OutPoint::NULL,
            script_sig: b"same-every-time".to_vec(),
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput {
            value: Sats(value),
            script_pubkey: Script::p2pkh(&miner.public_key().key_hash()).0,
        }],
        locktime: 0,
    }
}

#[test]
fn repeated_coinbase_txid_cannot_overwrite_an_unspent_output() {
    // Two consecutive blocks with byte-identical coinbases. At most one may
    // connect, and if one does its coin must survive the attempt.
    let (mut chain, miner) = fresh_chain();
    let cb = fixed_coinbase(&miner, chain.params.subsidy_start);
    let op = OutPoint {
        txid: cb.txid(),
        vout: 0,
    };
    let prev = tip_header(&chain);
    let first = build_block(&prev, vec![cb.clone()], prev.time + 31, &chain.params);
    let first_ok = chain.consider_block(first).is_ok();
    let after_first = (chain.utxos.fingerprint(), chain.utxos.len());

    let prev = tip_header(&chain);
    let second = build_block(&prev, vec![cb], prev.time + 31, &chain.params);
    let second_ok = chain.consider_block(second).is_ok();

    assert!(
        !(first_ok && second_ok),
        "both copies of one coinbase txid connected: the second overwrote the first's unspent coin"
    );
    if first_ok {
        assert!(chain.utxos.get(&op).is_some(), "original coin destroyed");
    }
    assert_eq!(
        (chain.utxos.fingerprint(), chain.utxos.len()),
        after_first,
        "rejected duplicate changed the UTXO set"
    );
}

#[test]
fn bip30_rejects_outputs_that_already_exist_unspent() {
    // Consensus-level, independent of BIP34: the view already holds an
    // unspent output at (coinbase txid, 0). Creating it again must fail.
    let params = ChainParams::devnet();
    let miner = Keypair::generate().unwrap();
    let cb = coinbase_tx(&miner, 1, params.subsidy_start);
    let existing = OutPoint {
        txid: cb.txid(),
        vout: 0,
    };
    let view = MapView(HashMap::from([(existing, cb.outputs[0].clone())]));
    let prev = BlockHeader {
        version: 1,
        prev_hash: Hash256::ZERO,
        merkle_root: Hash256::ZERO,
        time: 1_700_000_000,
        bits: params.pow_limit_bits,
        nonce: 0,
    };
    let block = build_block(&prev, vec![cb], 1_700_000_031, &params);
    let err = validate_block(&block, &view, &params, 1).unwrap_err();
    assert!(
        format!("{err:?}").contains("Bip30"),
        "expected a BIP30 rejection, got {err:?}"
    );

    // The same block over an empty view is fine.
    let empty = MapView(HashMap::new());
    assert!(validate_block(&block, &empty, &params, 1).is_ok());
}

#[test]
fn bip34_coinbase_must_start_with_the_block_height() {
    let (mut chain, miner) = fresh_chain();
    let prev = tip_header(&chain);
    let value = chain.params.subsidy_start;

    // No height at all.
    let block = build_block(
        &prev,
        vec![fixed_coinbase(&miner, value)],
        prev.time + 31,
        &chain.params,
    );
    assert!(
        chain.consider_block(block).is_err(),
        "coinbase without its height accepted"
    );
    // The wrong height (claims 2 at height 1).
    let wrong = coinbase_tx(&miner, 2, value);
    let block = build_block(&prev, vec![wrong], prev.time + 31, &chain.params);
    assert!(
        chain.consider_block(block).is_err(),
        "coinbase with the wrong height accepted"
    );
    assert_eq!(chain.height(), 0);

    // The right height connects.
    let right = coinbase_tx(&miner, 1, value);
    let block = build_block(&prev, vec![right], prev.time + 31, &chain.params);
    chain.consider_block(block).unwrap();
    assert_eq!(chain.height(), 1);
}

#[test]
fn utxo_set_refuses_to_overwrite_an_unspent_entry() {
    // Defense in depth below consensus: applying a transaction whose
    // outputs exist must fail and leave the set unchanged.
    let (mut chain, miner) = fresh_chain();
    let cb = fixed_coinbase(&miner, 1_000);
    let txid = cb.txid();
    chain.utxos.apply_tx(&cb, txid, 5, true).unwrap();
    let before = chain.utxos.fingerprint();
    let again = chain.utxos.apply_tx(&cb, txid, 6, true);
    assert!(again.is_err(), "overwrite of an unspent output allowed");
    assert_eq!(chain.utxos.fingerprint(), before);
}
