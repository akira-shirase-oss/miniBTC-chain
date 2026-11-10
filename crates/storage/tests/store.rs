//! Storage integration tests: snapshot/load roundtrip, crash recovery,
//! reindex, index lookups, and the UTXO consistency proof.

use minibtc_chainstate::Chain;
use minibtc_consensus::ChainParams;
use minibtc_crypto::{Hash256, Keypair};
use minibtc_primitives::*;
use minibtc_script::Script;
use minibtc_storage::Store;
use std::path::PathBuf;

fn mine_header(mut h: BlockHeader) -> BlockHeader {
    let target = minibtc_consensus::pow::target_for_bits(h.bits)
        .unwrap_or_else(|e| panic!("pow target failed: {e:?}"));
    loop {
        if h.check_pow(&target) {
            return h;
        }
        h.nonce = h.nonce.wrapping_add(1);
    }
}

fn p2pkh_tx(miner: &Keypair, height: u32, value: u64) -> Transaction {
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

fn build_chain(nblocks: u32) -> (Chain, Keypair, ChainParams) {
    let params = ChainParams::devnet();
    let miner = Keypair::generate().unwrap_or_else(|e| panic!("keygen failed: {e:?}"));
    let cb = p2pkh_tx(&miner, 0, params.subsidy_start);
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
    let mut chain =
        Chain::new(params.clone(), genesis).unwrap_or_else(|e| panic!("chain init failed: {e:?}"));
    // Mine nblocks empty blocks (coinbase only) — exercises connect path.
    for h in 1..=nblocks {
        let tip = chain.blocks[&chain.tip].block.header;
        let cb = p2pkh_tx(&miner, h, params.subsidy_start);
        let block = Block {
            header: mine_header(BlockHeader {
                version: 1,
                prev_hash: tip.block_hash(),
                merkle_root: merkle_root(std::slice::from_ref(&cb)),
                time: tip.time + 1,
                bits: params.pow_limit_bits,
                nonce: 0,
            }),
            txs: vec![cb],
        };
        chain
            .connect_tip(block)
            .unwrap_or_else(|e| panic!("connect_tip failed: {e:?}"));
    }
    (chain, miner, params)
}

fn tempdir() -> (PathBuf, tempfile::TempDir) {
    let d = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir failed: {e}"));
    (d.path().to_path_buf(), d)
}

#[test]
fn snapshot_load_roundtrip_preserves_state() {
    let (chain, _miner, params) = build_chain(5);
    let expected_fp = chain.utxos.fingerprint();
    let (dir, _g) = tempdir();
    let store = Store::open(&dir).unwrap();
    store.snapshot(&chain).unwrap();
    drop(store);

    let store = Store::open(&dir).unwrap();
    let loaded = store
        .load(params.clone(), {
            // genesis must be identical — rebuild it the same way
            let miner2 = Keypair::generate().unwrap(); // NOTE: genesis cb differs!
            // We need the SAME genesis block. Rebuild via chain's stored block.
            let _ = miner2;
            chain.blocks[&chain.genesis].block.clone()
        })
        .unwrap()
        .expect("store should have data");

    assert_eq!(loaded.utxos.fingerprint(), expected_fp);
    assert_eq!(loaded.tip, chain.tip);
    assert_eq!(loaded.height(), chain.height());
}

#[test]
fn crash_recovery_reopen_same_state() {
    let (chain, _m, params) = build_chain(3);
    let fp = chain.utxos.fingerprint();
    let (dir, _g) = tempdir();
    {
        let store = Store::open(&dir).unwrap();
        store.snapshot(&chain).unwrap();
        // simulate crash: drop without clean shutdown
    }
    // Reopen — redb recovers to last commit.
    let store = Store::open(&dir).unwrap();
    let genesis = chain.blocks[&chain.genesis].block.clone();
    let loaded = store.load(params, genesis).unwrap().unwrap();
    assert_eq!(loaded.utxos.fingerprint(), fp);
}

#[test]
fn consistency_check_replay_matches() {
    let (chain, _m, params) = build_chain(4);
    let (dir, _g) = tempdir();
    let store = Store::open(&dir).unwrap();
    store.snapshot(&chain).unwrap();
    let genesis = chain.blocks[&chain.genesis].block.clone();
    let ok = store.consistency_check(params, genesis, &chain).unwrap();
    assert!(ok, "replayed UTXO fingerprint must equal stored");
}

#[test]
fn indexes_resolve_tx_block_utxo_addr() {
    let (chain, miner, params) = build_chain(2);
    let (dir, _g) = tempdir();
    let store = Store::open(&dir).unwrap();
    store.snapshot(&chain).unwrap();

    // txindex: pick a non-coinbase... all blocks here are coinbase-only.
    // txindex still maps coinbase txids → their block.
    let tip_rec = &chain.blocks[&chain.tip];
    let cb_txid = tip_rec.block.txs[0].txid();
    let found = store.tx_block(&cb_txid).unwrap();
    assert_eq!(found, Some(chain.tip));

    // addrindex: miner's p2pkh script.
    let script = Script::p2pkh(&miner.public_key().key_hash()).0;
    let ops = store.addr_outpoints(&script).unwrap();
    // Each block pays miner → ≥ height+1 outpoints (genesis + blocks).
    assert!(
        ops.len() >= 3,
        "expected several miner UTXOs, got {}",
        ops.len()
    );

    // get_utxo / all_utxos
    assert!(store.get_utxo(&ops[0]).unwrap().is_some());
    let all = store.all_utxos().unwrap();
    assert_eq!(all.len(), chain.utxos.len());

    // get_block
    let b = store.get_block(&chain.tip).unwrap().unwrap();
    assert_eq!(b.header.block_hash(), chain.tip);
    let _ = params;
}

#[test]
fn empty_store_loads_none() {
    let (_dir, _g) = tempdir();
    let (dir2, _g2) = tempdir();
    let store = Store::open(&dir2).unwrap();
    let params = ChainParams::devnet();
    // Build a throwaway genesis for the call signature.
    let miner = Keypair::generate().unwrap_or_else(|e| panic!("keygen failed: {e:?}"));
    let cb = p2pkh_tx(&miner, 0, params.subsidy_start);
    let genesis = Block {
        header: BlockHeader {
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: merkle_root(std::slice::from_ref(&cb)),
            time: 1,
            bits: params.pow_limit_bits,
            nonce: 0,
        },
        txs: vec![cb],
    };
    assert!(store.load(params, genesis).unwrap().is_none());
    let _ = _dir;
}

#[test]
fn append_block_incremental_matches_snapshot() {
    // Persist every block via append_block (the node's hot path) and prove
    // the loaded state equals a snapshot-built store.
    let (chain, _m, params) = build_chain(6);
    let expected_fp = chain.utxos.fingerprint();
    let (dir, _g) = tempdir();
    let store = Store::open(&dir).unwrap();
    // Walk active chain genesis → tip.
    let mut order = Vec::new();
    let mut cur = chain.tip;
    loop {
        order.push(cur);
        let rec = &chain.blocks[&cur];
        if cur == chain.genesis {
            break;
        }
        cur = rec.block.header.prev_hash;
    }
    order.reverse();
    for h in &order {
        store.append_block(&chain, h).unwrap();
    }
    let genesis = chain.blocks[&chain.genesis].block.clone();
    let loaded = store.load(params, genesis).unwrap().unwrap();
    assert_eq!(loaded.utxos.fingerprint(), expected_fp);
    assert_eq!(loaded.tip, chain.tip);
    assert_eq!(loaded.height(), chain.height());
    // Indexes populated by append path.
    let tip_cb = chain.blocks[&chain.tip].block.txs[0].txid();
    assert_eq!(store.tx_block(&tip_cb).unwrap(), Some(chain.tip));
}

#[test]
fn disconnect_block_persists_utxo_reversal() {
    let (mut chain, _m, params) = build_chain(5);
    let full_fp = chain.utxos.fingerprint();
    let (dir, _g) = tempdir();
    let store = Store::open(&dir).unwrap();
    store.snapshot(&chain).unwrap();

    // Disconnect two tips, persisting each BEFORE chainstate consumes
    // the undo — the exact order the node uses.
    for _ in 0..2 {
        let tip = chain.tip;
        store.disconnect_block(&chain, &tip).unwrap();
        chain.disconnect_tip().unwrap();
    }
    assert_ne!(chain.utxos.fingerprint(), full_fp);
    let genesis = chain.blocks[&chain.genesis].block.clone();
    let loaded = store.load(params, genesis).unwrap().unwrap();
    assert_eq!(loaded.utxos.fingerprint(), chain.utxos.fingerprint());
    assert_eq!(loaded.tip, chain.tip);
    assert_eq!(loaded.height(), 3);
}

#[test]
fn snapshot_is_atomic_wipe_and_rewrite() {
    let (chain, _m, params) = build_chain(3);
    let (dir, _g) = tempdir();
    let store = Store::open(&dir).unwrap();
    store.snapshot(&chain).unwrap();
    // Snapshot again — must not duplicate or leave stale keys.
    store.snapshot(&chain).unwrap();
    let genesis = chain.blocks[&chain.genesis].block.clone();
    let loaded = store.load(params, genesis).unwrap().unwrap();
    assert_eq!(loaded.utxos.len(), chain.utxos.len());
    assert_eq!(loaded.blocks.len(), chain.blocks.len());
}
