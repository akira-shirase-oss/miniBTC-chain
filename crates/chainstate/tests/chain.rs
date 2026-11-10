//! End-to-end chain tests: connect, maturity, reorg exactness.
//! These exercise the real consensus path — blocks are *mined* (nonce
//! grinding against devnet's trivial target), not fabricated.

use minibtc_chainstate::*;
use minibtc_consensus::ChainParams;
use minibtc_crypto::{Hash256, Keypair};
use minibtc_primitives::*;
use minibtc_script::Script;

/// Grind a nonce until the header passes PoW (devnet target ~2^255 →
/// ~2 tries average).
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

fn coinbase_tx(miner: &Keypair, height: u32, value: u64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: OutPoint::NULL,
            script_sig: {
                // BIP34-style: push height then arbitrary data.
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

fn build_block(
    prev: &BlockHeader,
    txs: Vec<Transaction>,
    time: u32,
    params: &ChainParams,
) -> Block {
    let mut txs = txs;
    // Ensure coinbase present: if caller didn't supply one, prepend.
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

fn fresh_chain() -> (Chain, Keypair) {
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

#[test]
fn genesis_connects_and_issues_coinbase() {
    let (chain, miner) = fresh_chain();
    assert_eq!(chain.height(), 0);
    // Genesis coinbase output exists (unspendable until maturity).
    let mut found = false;
    for (_op, e) in chain.utxos.iter() {
        if e.output.script_pubkey == Script::p2pkh(&miner.public_key().key_hash()).0 {
            found = true;
            assert!(e.coinbase);
            assert_eq!(e.height, 0);
        }
    }
    assert!(found, "genesis coinbase output missing");
}

#[test]
fn connect_blocks_extends_tip_and_utxo() {
    let (mut chain, miner) = fresh_chain();
    let mut prev = *chain
        .blocks
        .get(&chain.tip)
        .map(|r| &r.block.header)
        .unwrap();
    let mut time = prev.time;
    for h in 1..=5u32 {
        time += 31;
        let cb = coinbase_tx(&miner, h, chain.params.subsidy_start);
        let blk = build_block(&prev, vec![cb], time, &chain.params);
        chain.consider_block(blk.clone()).unwrap();
        assert_eq!(chain.height(), h);
        prev = blk.header;
    }
    assert_eq!(chain.utxos.len(), 6); // genesis + 5 coinbases
}

#[test]
fn coinbase_maturity_blocks_early_spend() {
    let (mut chain, miner) = fresh_chain();
    // Mine 3 blocks (depth of genesis coinbase = 3 < 100).
    let mut prev = *chain
        .blocks
        .get(&chain.tip)
        .map(|r| &r.block.header)
        .unwrap();
    let mut time = prev.time;
    for h in 1..=3u32 {
        time += 31;
        let cb = coinbase_tx(&miner, h, chain.params.subsidy_start);
        let blk = build_block(&prev, vec![cb], time, &chain.params);
        chain.consider_block(blk.clone()).unwrap();
        prev = blk.header;
    }
    // Try to spend the genesis coinbase — must fail maturity.
    let genesis_cb_op = OutPoint {
        txid: chain.blocks.get(&chain.genesis).unwrap().block.txs[0].txid(),
        vout: 0,
    };
    let mut spend = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: genesis_cb_op,
            script_sig: vec![],
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput {
            value: Sats(1),
            script_pubkey: Script::p2pkh(&miner.public_key().key_hash()).0,
        }],
        locktime: 0,
    };
    // Sign it properly so only maturity can fail — need sighash against
    // the coinbase's scriptPubKey.
    let prev_spk = chain
        .utxos
        .get(&genesis_cb_op)
        .unwrap()
        .output
        .script_pubkey
        .clone();
    let item = minibtc_script::sighash::sign_input(&spend, 0, &prev_spk, &miner).unwrap();
    spend.inputs[0].script_sig = Script::p2pkh_spend(&item, &miner.public_key()).0;
    let blk = build_block(
        &prev,
        vec![coinbase_tx(&miner, 4, chain.params.subsidy_start), spend],
        time + 31,
        &chain.params,
    );
    // Wait — build_block puts cb first; spend second. Height 4 < maturity.
    let err = chain.consider_block(blk);
    assert!(err.is_err(), "immature coinbase spend must fail");
}

#[test]
fn reorg_restores_utxo_exactly() {
    let (mut chain_a, miner) = fresh_chain();
    // Build branch A: 3 blocks. Record fingerprint after each.
    let prev_a = *chain_a
        .blocks
        .get(&chain_a.tip)
        .map(|r| &r.block.header)
        .unwrap();
    let mut time = prev_a.time;
    // Simpler: build two independent chains to same height, then feed the
    // heavier fork's blocks into chain_a and check fingerprint equality
    // with a fresh replay.
    // --- chain_a branch: blocks a1..a3 ---
    let mut a_blocks = Vec::new();
    let mut h = prev_a;
    for i in 0..3u32 {
        time += 31;
        let cb = coinbase_tx(&miner, i + 1, chain_a.params.subsidy_start);
        let blk = build_block(&h, vec![cb], time, &chain_a.params);
        h = blk.header;
        a_blocks.push(blk);
    }
    for b in &a_blocks {
        chain_a.consider_block(b.clone()).unwrap();
    }
    let fp_a = chain_a.utxos.fingerprint();

    // --- fresh replay of the same blocks must give identical fingerprint.
    // The replay chain MUST share chain_a's genesis block (same coinbase →
    // same hash), otherwise the a-blocks' prev_hash is unknown to it.
    let genesis_block = chain_a.blocks.get(&chain_a.genesis).unwrap().block.clone();
    let mut replay = Chain::new(chain_a.params.clone(), genesis_block).unwrap();
    // replay needs the SAME prev chain — but a_blocks build on genesis only
    // if prev_a was genesis. prev_a IS genesis header here (fresh chain).
    for b in &a_blocks {
        replay.consider_block(b.clone()).unwrap();
    }
    assert_eq!(
        fp_a,
        replay.utxos.fingerprint(),
        "replay fingerprint differs"
    );

    // --- now a competing fork b1..b4 (one block longer = more work) ---
    // Build fork from genesis.
    let genesis_hdr = *chain_a
        .blocks
        .get(&chain_a.genesis)
        .map(|r| &r.block.header)
        .unwrap();
    let mut fh = genesis_hdr;
    // Fork timestamps must exceed the a-branch's median-time-past —
    // start well above it (a realistic "mined later" fork).
    let mut ftime = genesis_hdr.time + 400;
    let mut f_blocks = Vec::new();
    for i in 0..4u32 {
        ftime += 31;
        let cb = coinbase_tx(
            &Keypair::generate().unwrap(),
            i + 1,
            chain_a.params.subsidy_start,
        );
        let blk = build_block(&fh, vec![cb], ftime, &chain_a.params);
        fh = blk.header;
        f_blocks.push(blk);
    }
    // Feed fork blocks: b1 connects as side branch (parent=genesis≠tip a3).
    // b2,b3,b4 build on it.
    for b in &f_blocks {
        chain_a.consider_block(b.clone()).unwrap();
    }
    // After b4 (height 4 > a-branch height 3), tip should be fork tip.
    assert_eq!(chain_a.height(), 4, "heavier fork did not win");
    let fp_fork = chain_a.utxos.fingerprint();

    // Fresh replay of fork must match (same genesis again).
    let genesis_block2 = chain_a.blocks.get(&chain_a.genesis).unwrap().block.clone();
    let mut replay2 = Chain::new(chain_a.params.clone(), genesis_block2).unwrap();
    for b in &f_blocks {
        replay2.consider_block(b.clone()).unwrap();
    }
    assert_eq!(fp_fork, replay2.utxos.fingerprint(), "fork replay differs");

    // And the fork's coinbase outputs exist, a-branch's do NOT (they were
    // never connected... wait — a-branch WAS connected then disconnected;
    // its coinbases must be gone from utxo set).
    let a3_cb_txid = a_blocks[2].txs[0].txid();
    assert!(
        chain_a
            .utxos
            .get(&OutPoint {
                txid: a3_cb_txid,
                vout: 0
            })
            .is_none(),
        "disconnected branch coinbase still in UTXO set"
    );
}
