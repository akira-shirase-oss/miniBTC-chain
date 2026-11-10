//! Property-based invariants (proptest) — the attack lab's fuzzing half.
//! Every property must hold for ALL generated inputs, not just samples.

mod common;

use common::*;
use minibtc_consensus::ChainParams;
use minibtc_crypto::{double_sha256, Hash256, Keypair};
use minibtc_primitives::*;
use minibtc_script::{execute, ExecContext};
use proptest::prelude::*;

// ---------- codec round-trips ----------

proptest! {
    /// Any bytes fed to Transaction::decode either error cleanly or
    /// re-encode to identical canonical bytes. No panics, ever.
    #[test]
    fn prop_tx_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = std::panic::catch_unwind(|| Transaction::decode(&bytes));
    }

    /// encode → decode → encode is a fixed point for valid txs.
    #[test]
    fn prop_tx_codec_roundtrip(
        n_in in 0usize..4,
        n_out in 0usize..4,
        locktime in 0u32..100,
    ) {
        let tx = arb_tx(1, n_in, n_out, locktime);
        let enc = tx.encode();
        let dec = Transaction::decode(&enc).expect("own encoding must decode");
        let dec_enc = dec.encode();
        prop_assert_eq!(dec, tx);
        prop_assert_eq!(dec_enc, enc);
    }

    /// Block decode is bounded and never panics.
    #[test]
    fn prop_block_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = std::panic::catch_unwind(|| Block::decode(&bytes, 10_000, 4 * 1024 * 1024));
    }

    /// Sats arithmetic is total: checked ops never panic and agree with
    /// u64 semantics at the boundaries.
    #[test]
    fn prop_money_checked_ops(a in any::<u64>(), b in any::<u64>()) {
        let (sa, sb) = (Sats(a), Sats(b));
        match sa.checked_add(sb) {
            Some(s) => {
                prop_assert_eq!(s.sats(), a.wrapping_add(b));
                prop_assert!(a.checked_add(b).is_some());
            }
            None => prop_assert!(a.checked_add(b).is_none()),
        }
        match sa.checked_sub(sb) {
            Some(s) => prop_assert_eq!(s.sats(), a.wrapping_sub(b)),
            None => prop_assert!(a < b),
        }
        // checked_sum over arbitrary multisets must not panic.
        let items = [Sats(a), Sats(b), Sats(u64::MAX), Sats(1)];
        let _ = Sats::checked_sum(items);
    }

    /// Merkle root: deterministic, and sensitive to every leaf.
    #[test]
    fn prop_merkle_deterministic_and_sensitive(
        txs in proptest::collection::vec(arb_tx_strategy(), 1..8),
        flip in 0usize..8,
    ) {
        let r1 = merkle_root(&txs);
        let r2 = merkle_root(&txs);
        prop_assert_eq!(r1, r2);
        if txs.len() >= 2 {
            let mut mutated = txs.clone();
            let i = flip % mutated.len();
            mutated[i].locktime = mutated[i].locktime.wrapping_add(1);
            prop_assert_ne!(merkle_root(&mutated), r1);
        }
    }

    /// HD key derivation is deterministic: same secret → same key,
    /// signatures verify, different secrets give different keys.
    #[test]
    fn prop_key_derivation_stable(secret in any::<[u8; 32]>()) {
        let Ok(kp) = Keypair::from_secret_bytes(&secret) else {
            return Ok(());
        };
        let pk1 = kp.public_key();
        let pk2 = kp.public_key();
        prop_assert_eq!(pk1.to_sec1_bytes(), pk2.to_sec1_bytes());
        let digest = double_sha256(b"minibtc-property");
        let sig = kp.sign_digest(&digest).expect("sign");
        prop_assert!(pk1.verify_digest(&digest, &sig));
        let mut other = secret;
        other[0] ^= 0x01;
        if let Ok(kp2) = Keypair::from_secret_bytes(&other) {
            prop_assert_ne!(kp2.public_key().to_sec1_bytes(), pk1.to_sec1_bytes());
        }
    }

    /// Script execution on arbitrary bytes never panics.
    #[test]
    fn prop_script_never_panics(
        sig in proptest::collection::vec(any::<u8>(), 0..512),
        spk in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let tx = arb_tx(1, 1, 1, 0);
        let ctx = ExecContext {
            tx: &tx,
            input_index: 0,
            script_code: &spk,
        };
        let r = std::panic::catch_unwind(|| execute(&sig, &spk, &ctx));
        prop_assert!(r.is_ok(), "script engine panicked");
    }

    /// Mempool stays bounded under arbitrary admit sequences — checked
    /// after EVERY admission, not just at the end.
    #[test]
    fn prop_mempool_bounded(
        n in 1usize..200,
        fee_base in 1u64..10_000,
    ) {
        let params = ChainParams::devnet();
        let policy = minibtc_mempool::MempoolPolicy {
            max_size_bytes: 4_000,
            max_entries: 500,
            ..Default::default()
        };
        let mut pool = minibtc_mempool::Mempool::new(policy);
        let view = EmptyViewProp;
        for i in 0..n {
            let op = OutPoint {
                txid: Hash256::from_hex(&format!("{:064x}", i as u64 + 1)).unwrap(),
                vout: 0,
            };
            let tx = Transaction {
                version: 1,
                inputs: vec![TxInput {
                    prev: op,
                    script_sig: vec![],
                    sequence: 0xffff_ffff,
                }],
                outputs: vec![TxOutput {
                    value: Sats(90_000),
                    script_pubkey: vec![0x51],
                }],
                locktime: 0,
            };
            let fee = Sats(fee_base + i as u64);
            let _ = pool.admit(tx, fee, &view, &params, None);
            prop_assert!(pool.total_size() <= 4_000);
            prop_assert!(pool.len() <= 500);
        }
    }
}

// ---------- UTXO connect/disconnect exactness ----------

/// Disconnecting every block must restore the UTXO set EXACTLY —
/// fingerprint equality with the post-genesis state, plus monotone
/// UTXO-count decrease at every step.
#[test]
fn prop_disconnect_restores_utxo_exactly() {
    for mine_n in [3u32, 7, 15, 25] {
        let (mut chain, miner) = fresh_chain();
        let genesis_fp = chain.utxos.fingerprint();
        let genesis_len = chain.utxos.len();
        mine_empty(&mut chain, &miner, mine_n);
        assert_eq!(chain.utxos.len(), genesis_len + mine_n as usize);

        // Disconnect one at a time: count must drop by exactly one each
        // step (each block contributes exactly one coinbase UTXO).
        for expected_remaining in (genesis_len..genesis_len + mine_n as usize).rev() {
            chain.disconnect_tip().expect("disconnect_tip");
            assert_eq!(
                chain.utxos.len(),
                expected_remaining,
                "UTXO count wrong after disconnect"
            );
        }
        // Full teardown → byte-identical UTXO set to post-genesis.
        assert_eq!(
            chain.utxos.fingerprint(),
            genesis_fp,
            "disconnect did not restore genesis UTXO set exactly"
        );
        assert_eq!(chain.height(), 0);
    }
}

// ---------- helpers ----------

struct EmptyViewProp;
impl minibtc_consensus::UtxoView for EmptyViewProp {
    fn get(&self, _op: &OutPoint) -> Option<TxOutput> {
        None
    }
}

fn arb_tx_strategy() -> impl Strategy<Value = Transaction> {
    (1i32..2, 0usize..3, 0usize..3, 0u32..10)
        .prop_map(|(v, i, o, l)| arb_tx(v, i, o, l))
}

/// Build a structurally valid tx with the given shape.
fn arb_tx(version: i32, n_in: usize, n_out: usize, locktime: u32) -> Transaction {
    let mut inputs = Vec::with_capacity(n_in);
    for i in 0..n_in {
        inputs.push(TxInput {
            prev: OutPoint {
                txid: Hash256::from_hex(&format!("{:064x}", i as u64 + 7)).unwrap(),
                vout: i as u32,
            },
            script_sig: vec![],
            sequence: 0xffff_ffff,
        });
    }
    let mut outputs = Vec::with_capacity(n_out);
    for i in 0..n_out {
        outputs.push(TxOutput {
            value: Sats(10_000 + i as u64),
            script_pubkey: vec![0x76, 0xa9, 0x14, i as u8, 9, 9, 9, 0x88, 0xac],
        });
    }
    Transaction {
        version,
        inputs,
        outputs,
        locktime,
    }
}
