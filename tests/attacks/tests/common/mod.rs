//! Shared fixtures for the attack lab: real PoW-mined devnet blocks,
//! signed P2PKH spends, and a map-backed UTXO view for tx-level tests.

#![allow(
    dead_code,
    reason = "shared fixtures: helpers may be unused per test binary"
)]

use minibtc_chainstate::Chain;
use minibtc_consensus::ChainParams;
use minibtc_consensus::UtxoView;
use minibtc_crypto::{Hash256, Keypair};
use minibtc_primitives::*;
use minibtc_script::Script;
use std::collections::HashMap;

/// Grind a nonce until the header passes PoW (devnet target ~2^255).
pub fn mine_header(mut h: BlockHeader) -> BlockHeader {
    let target = minibtc_consensus::pow::target_for_bits(h.bits)
        .unwrap_or_else(|e| panic!("pow target failed: {e:?}"));
    for _ in 0..1_000_000 {
        if h.check_pow(&target) {
            return h;
        }
        h.nonce = h.nonce.wrapping_add(1);
    }
    panic!("could not mine header in 1M tries");
}

/// A coinbase paying `miner`'s P2PKH, BIP34-style height in scriptSig.
pub fn coinbase_tx(miner: &Keypair, height: u32, value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: OutPoint::NULL,
            script_sig: {
                let mut s = vec![0x02, height as u8];
                s.extend_from_slice(b"minibtc");
                s
            },
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput {
            value: Sats(value),
            script_pubkey: Script::p2pkh(&miner.public_key().key_hash()).0,
        }],
        locktime: 0,
    }
}

/// Assemble + mine a block on `prev`. `txs` must already include a
/// coinbase first if desired; otherwise one is prepended.
pub fn build_block(
    prev: &BlockHeader,
    txs: Vec<Transaction>,
    time: u32,
    params: &ChainParams,
) -> Block {
    let mut txs = txs;
    if txs.is_empty() || !txs[0].is_coinbase() {
        txs.insert(
            0,
            coinbase_tx(
                &Keypair::generate().unwrap_or_else(|e| panic!("keygen failed: {e:?}")),
                0,
                params.subsidy_start,
            ),
        );
    }
    let mr = merkle_root(&txs);
    let header = mine_header(BlockHeader {
        version: 1,
        prev_hash: prev.block_hash(),
        merkle_root: mr,
        time,
        bits: params.pow_limit_bits,
        nonce: 0,
    });
    Block { header, txs }
}

/// Genesis + empty chain with a known miner key.
pub fn fresh_chain() -> (Chain, Keypair) {
    let params = ChainParams::devnet();
    let miner = Keypair::generate().unwrap_or_else(|e| panic!("keygen failed: {e:?}"));
    let cb = coinbase_tx(&miner, 0, params.subsidy_start);
    let genesis = Block {
        header: BlockHeader {
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: merkle_root(std::slice::from_ref(&cb)),
            time: 1_700_000_000,
            bits: params.pow_limit_bits,
            nonce: 0,
        },
        txs: vec![cb],
    };
    let chain = Chain::new(params, genesis).unwrap_or_else(|e| panic!("chain init failed: {e:?}"));
    (chain, miner)
}

/// Mine `n` empty blocks on `chain`; returns new tip header.
pub fn mine_empty(chain: &mut Chain, miner: &Keypair, n: u32) {
    let mut prev = *chain
        .blocks
        .get(&chain.tip)
        .map(|r| &r.block.header)
        .unwrap_or_else(|| panic!("tip record missing"));
    let mut time = prev.time;
    for h in 1..=(chain.height() + n) {
        time += 31;
        let cb = coinbase_tx(miner, h, chain.params.subsidy_start);
        let blk = build_block(&prev, vec![cb], time, &chain.params);
        chain
            .consider_block(blk.clone())
            .unwrap_or_else(|e| panic!("consider_block failed: {e:?}"));
        prev = blk.header;
    }
}

/// Build a signed P2PKH spend of `prev` (must be a wallet-controlled
/// output) to `dest_spk`, returning the signed tx.
pub fn signed_spend(
    prev_op: OutPoint,
    prev_spk: &[u8],
    prev_value: Sats,
    key: &Keypair,
    dest_spk: &[u8],
    amount: Sats,
    fee: Sats,
) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: prev_op,
            script_sig: vec![],
            sequence: 0xffff_ffff,
        }],
        outputs: vec![
            TxOutput {
                value: amount,
                script_pubkey: dest_spk.to_vec(),
            },
            TxOutput {
                value: prev_value
                    .checked_sub(amount)
                    .and_then(|v| v.checked_sub(fee))
                    .unwrap_or_else(|| panic!("change output underflow")),
                script_pubkey: Script::p2pkh(&key.public_key().key_hash()).0,
            },
        ],
        locktime: 0,
    };
    // Drop change output if it would be dust/negative — rebuild.
    let change = prev_value
        .checked_sub(amount)
        .and_then(|v| v.checked_sub(fee));
    if change.map(|c| c.sats() < 546).unwrap_or(true) {
        tx.outputs.pop();
    }
    let sig = minibtc_script::sighash::sign_input(&tx, 0, prev_spk, key)
        .unwrap_or_else(|e| panic!("sign_input failed: {e:?}"));
    tx.inputs[0].script_sig = Script::p2pkh_spend(&sig, &key.public_key()).0;
    tx
}

/// A UTXO view over a plain map — for tx-level validation tests.
pub struct MapView(pub HashMap<OutPoint, TxOutput>);

impl UtxoView for MapView {
    fn get(&self, op: &OutPoint) -> Option<TxOutput> {
        self.0.get(op).cloned()
    }
}

/// p2pkh scriptPubKey bytes for a key.
pub fn p2pkh_spk(key: &Keypair) -> Vec<u8> {
    Script::p2pkh(&key.public_key().key_hash()).0
}
