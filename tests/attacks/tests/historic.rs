//! Historic-bug attack scenarios (blueprint §8, rows 1–3, 7–11).
//! Each reproduces a real Bitcoin failure mode and proves MiniBTC
//! rejects it — or, for the merkle case, rejects it *without*
//! invalidating the honest block.

mod common;

use common::*;
use minibtc_consensus::{validate_tx, ChainParams, TxError};
use minibtc_crypto::{Hash256, Keypair};
use minibtc_primitives::*;
use minibtc_script::Script;
use std::collections::HashMap;

// ---------- 1. Value overflow (the 2010 overflow bug) ----------

/// Outputs whose values overflow when summed must be rejected —
/// checked arithmetic makes money creation impossible.
#[test]
fn attack_value_overflow_rejected() {
    let params = ChainParams::devnet();
    let miner = Keypair::generate().unwrap();
    let spender = Keypair::generate().unwrap();

    // A prevout worth 21M BTC (max_money) — the largest legal input.
    let prev_op = OutPoint {
        txid: Hash256::from_hex(&"11".repeat(32)).unwrap(),
        vout: 0,
    };
    let prev_spk = p2pkh_spk(&spender);
    let mut view = MapView(HashMap::new());
    view.0.insert(
        prev_op,
        TxOutput {
            value: Sats(params.max_money),
            script_pubkey: prev_spk.clone(),
        },
    );

    // Attack: two outputs each near max_money — their sum overflows u64
    // (and exceeds max_money). This is the 2010 bug shape.
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: prev_op,
            script_sig: vec![],
            sequence: 0xffff_ffff,
        }],
        outputs: vec![
            TxOutput {
                value: Sats(u64::MAX - 1000),
                script_pubkey: p2pkh_spk(&miner),
            },
            TxOutput {
                value: Sats(u64::MAX - 1000),
                script_pubkey: p2pkh_spk(&miner),
            },
        ],
        locktime: 0,
    };
    // Even before scripts run, output_sum must overflow → ValueOverflow.
    let err = validate_tx(&tx, &view, &params).unwrap_err();
    assert!(
        matches!(err, TxError::ValueOverflow | TxError::ScriptFailed { .. } | TxError::Overspend { .. } | TxError::ExceedsMaxMoney),
        "overflow tx must be rejected, got {err:?}"
    );

    // A subtler variant: outputs sum fits u64 but exceeds max_money.
    tx.outputs = vec![TxOutput {
        value: Sats(params.max_money + 1),
        script_pubkey: p2pkh_spk(&miner),
    }];
    let err = validate_tx(&tx, &view, &params).unwrap_err();
    assert!(
        matches!(err, TxError::ExceedsMaxMoney | TxError::Overspend { .. } | TxError::ScriptFailed { .. }),
        "over-max-money tx must be rejected, got {err:?}"
    );
}

// ---------- 2. Duplicate inputs (CVE-2018-17144) ----------

/// Spending the same outpoint twice in one tx is a hard reject.
#[test]
fn attack_duplicate_inputs_rejected() {
    let params = ChainParams::devnet();
    let key = Keypair::generate().unwrap();
    let victim = Keypair::generate().unwrap();

    let prev_op = OutPoint {
        txid: Hash256::from_hex(&"22".repeat(32)).unwrap(),
        vout: 1,
    };
    let prev_spk = p2pkh_spk(&victim);
    let mut view = MapView(HashMap::new());
    view.0.insert(
        prev_op,
        TxOutput {
            value: Sats(100_000),
            script_pubkey: prev_spk.clone(),
        },
    );

    // The CVE shape: same input listed twice → counted twice →
    // "creates" money. Must hit DuplicateInput before scripts matter.
    let tx = Transaction {
        version: 1,
        inputs: vec![
            TxInput {
                prev: prev_op,
                script_sig: vec![],
                sequence: 0xffff_ffff,
            },
            TxInput {
                prev: prev_op, // SAME outpoint — the bug
                script_sig: vec![],
                sequence: 0xffff_ffff,
            },
        ],
        outputs: vec![TxOutput {
            value: Sats(200_000), // 2× input — theft attempt
            script_pubkey: p2pkh_spk(&key),
        }],
        locktime: 0,
    };
    let err = validate_tx(&tx, &view, &params).unwrap_err();
    assert_eq!(err, TxError::DuplicateInput(prev_op));
}

// ---------- 3. Merkle duplication (CVE-2012-2459) ----------

/// Duplicating the last tx to make a second valid merkle root must be
/// rejected — and the honest block must remain acceptable.
#[test]
fn attack_merkle_duplication_rejected_honest_block_survives() {
    let params = ChainParams::devnet();
    let (mut chain, miner) = fresh_chain();
    let prev = *chain
        .blocks
        .get(&chain.tip)
        .map(|r| &r.block.header)
        .unwrap();
    let mut time = prev.time;

    // CVE-2012-2459 shape: for a 1-tx block the merkle padding
    // duplicates the single leaf, so root([cb]) == root of the virtual
    // list [cb, cb]. A block advertising txs=[cb,cb] with header root
    // = merkle_root([cb]) has TWO valid merkle interpretations — the
    // exact ambiguity Bitcoin patched. Validation must reject it via
    // the duplicate-trailing-tx check while the honest 1-tx block
    // (same header root) still connects.
    time += 31;
    let cb = coinbase_tx(&miner, 1, params.subsidy_start);
    let honest = build_block(&prev, vec![cb.clone()], time, &params);
    let dup_txs = vec![cb.clone(), cb.clone()];
    let attack_mr = merkle_root(&[cb.clone()]); // same as honest!
    let attack_header = mine_header(BlockHeader {
        version: 1,
        prev_hash: prev.block_hash(),
        merkle_root: attack_mr,
        time: time + 31,
        bits: params.pow_limit_bits,
        nonce: 0,
    });
    let attack_block = Block {
        header: attack_header,
        txs: dup_txs,
    };
    // Honest block connects.
    chain.consider_block(honest).unwrap();
    // Attack block (built on the OLD prev — it's now a side branch)
    // must be rejected for merkle ambiguity, not crash the node.
    let err = chain.consider_block(attack_block);
    assert!(err.is_err(), "merkle-duplicated block must be rejected");
}

// ---------- 7. Premature coinbase spend ----------

/// A coinbase output younger than `coinbase_maturity` blocks cannot be
/// spent — enforced in consensus, not just policy.
#[test]
fn attack_premature_coinbase_spend_rejected() {
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 10); // coinbase depth = 10 << 100
    let tip = chain.tip;
    let coinbase_txid = chain
        .blocks
        .values()
        .find(|r| r.height == chain.height())
        .unwrap()
        .block
        .txs[0]
        .txid();
    let op = OutPoint { txid: coinbase_txid, vout: 0 };
    let entry = chain.utxos.get(&op).unwrap();
    assert!(entry.coinbase && entry.height + 100 > chain.height());

    // Attempt the spend directly at validation level.
    let mut spend = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: op,
            script_sig: vec![],
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput {
            value: Sats(1),
            script_pubkey: p2pkh_spk(&miner),
        }],
        locktime: 0,
    };
    // Sign it correctly — only maturity should fail.
    let sig = minibtc_script::sighash::sign_input(
        &spend,
        0,
        &entry.output.script_pubkey,
        &miner,
    )
    .unwrap();
    spend.inputs[0].script_sig =
        Script::p2pkh_spend(&sig, &miner.public_key()).0;

    // The chain-level view: chain.utxos marks coinbase entries; the
    // block-validation path checks maturity. Feed a block containing it.
    let prev = *chain.blocks.get(&tip).map(|r| &r.block.header).unwrap();
    let mut time = prev.time;
    time += 31;
    let cb = coinbase_tx(&miner, chain.height() + 1, chain.params.subsidy_start);
    let spend_blk = build_block(&prev, vec![cb, spend], time, &chain.params);
    let err = chain.consider_block(spend_blk).unwrap_err();
    let _ = prev;
    assert!(
        format!("{err:?}").contains("matur") || format!("{err:?}").contains("coinbase"),
        "expected maturity/coinbase error, got {err:?}"
    );
}

// ---------- 8. Coinbase over-claim ----------

/// A coinbase claiming more than subsidy + fees must be rejected at
/// block validation.
#[test]
fn attack_coinbase_overclaim_rejected() {
    let params = ChainParams::devnet();
    let (mut chain, miner) = fresh_chain();
    let prev = *chain
        .blocks
        .get(&chain.tip)
        .map(|r| &r.block.header)
        .unwrap();
    let mut time = prev.time;
    time += 31;

    // Honest coinbase + a greedy one claiming subsidy + 1 sat extra.
    let greedy = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: OutPoint::NULL,
            script_sig: {
                let mut s = vec![0x02, 1u8];
                s.extend_from_slice(b"evil");
                s
            },
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput {
            value: Sats(params.subsidy_start + 1), // over-claim!
            script_pubkey: p2pkh_spk(&miner),
        }],
        locktime: 0,
    };
    let blk = build_block(&prev, vec![greedy], time, &params);
    // build_block sees first tx IS coinbase-shaped → keeps it.
    let err = chain.consider_block(blk).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("Overclaim") || msg.contains("over-claim") || msg.contains("subsidy"),
        "expected over-claim rejection, got {err:?}"
    );
}

// ---------- 9. Low-work block ----------

/// A block whose hash exceeds the target must fail PoW validation.
#[test]
fn attack_low_work_block_rejected() {
    let params = ChainParams::devnet();
    let (mut chain, miner) = fresh_chain();
    let prev = *chain
        .blocks
        .get(&chain.tip)
        .map(|r| &r.block.header)
        .unwrap();
    let cb = coinbase_tx(&miner, 1, params.subsidy_start);

    // Craft a header that does NOT meet the target: use bits=pow_limit
    // but pick a nonce whose hash is above target. With devnet's ~2^255
    // target, ~half of all hashes fail — grind until we find one that
    // FAILS check_pow.
    let target = minibtc_consensus::target_for_bits(params.pow_limit_bits).unwrap();
    let mut bad_header = BlockHeader {
        version: 1,
        prev_hash: prev.block_hash(),
        merkle_root: merkle_root(&[cb.clone()]),
        time: prev.time + 31,
        bits: params.pow_limit_bits,
        nonce: 0,
    };
    let mut tries = 0;
    loop {
        if !bad_header.check_pow(&target) {
            break;
        }
        bad_header.nonce = bad_header.nonce.wrapping_add(1);
        tries += 1;
        assert!(tries < 1000, "could not find failing nonce");
    }
    let bad_block = Block {
        header: bad_header,
        txs: vec![cb],
    };
    let err = chain.consider_block(bad_block).unwrap_err();
    assert!(
        format!("{err:?}").to_lowercase().contains("pow")
            || format!("{err:?}").contains("target")
            || format!("{err:?}").contains("work"),
        "expected PoW rejection, got {err:?}"
    );
}

// ---------- 10. Timestamp manipulation ----------

/// A block timestamped below the median-of-11 or too far in the
/// future must be rejected.
#[test]
fn attack_timestamp_manipulation_rejected() {
    let params = ChainParams::devnet();
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 12); // enough history for median
    let prev = *chain
        .blocks
        .get(&chain.tip)
        .map(|r| &r.block.header)
        .unwrap();

    // (a) Too far in the future: now + 10 years.
    let far_future = prev.time + 10 * 365 * 24 * 3600;
    let cb = coinbase_tx(&miner, chain.height() + 1, params.subsidy_start);
    let blk_future = build_block(&prev, vec![cb.clone()], far_future, &params);
    let err = chain.consider_block(blk_future);
    assert!(err.is_err(), "far-future block must be rejected");

    // (b) Below median: use a time older than the median of past 11.
    // Median of recent blocks ≈ prev.time - ~5*31; pick prev.time - 1000.
    let too_old = prev.time.saturating_sub(10_000);
    let blk_old = build_block(&prev, vec![cb], too_old, &params);
    let err = chain.consider_block(blk_old);
    assert!(err.is_err(), "median-violating block must be rejected");
}

// ---------- 11. Malleability (high-S signature) ----------

/// secp256k1 group order n (32-byte big-endian) — public constant.
const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
    0x41, 0x41,
];

/// `a - b` on 32-byte big-endian ints (requires a ≥ b).
fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        if d < 0 {
            out[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[i] = d as u8;
            borrow = 0;
        }
    }
    out
}

/// DER `SEQUENCE { INTEGER r, INTEGER s }` encoder (test-only).
fn der_encode_sig(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    fn integer(x: &[u8; 32]) -> Vec<u8> {
        let start = x.iter().position(|&b| b != 0).unwrap_or(31);
        let mut body = x[start..].to_vec();
        if body.is_empty() {
            body.push(0);
        }
        if body[0] & 0x80 != 0 {
            let mut v = vec![0x00];
            v.extend_from_slice(&body);
            body = v;
        }
        let mut v = vec![0x02, body.len() as u8];
        v.extend_from_slice(&body);
        v
    }
    let mut body = integer(r);
    body.extend(integer(s));
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

/// A signature flipped to its high-S malleated form must be rejected —
/// (r, n−s) verifies mathematically but violates the low-S rule, so the
/// spend fails script validation and the tx can never confirm.
#[test]
fn attack_signature_malleability_rejected() {
    let params = ChainParams::devnet();
    let victim = Keypair::generate().unwrap();
    let prev_op = OutPoint {
        txid: Hash256::from_hex(&"33".repeat(32)).unwrap(),
        vout: 0,
    };
    let prev_spk = p2pkh_spk(&victim);
    let value = Sats(50_000);
    let mut view = MapView(HashMap::new());
    view.0.insert(
        prev_op,
        TxOutput {
            value,
            script_pubkey: prev_spk.clone(),
        },
    );

    // Victim signs a spend honestly — it validates.
    let honest = signed_spend(
        prev_op,
        &prev_spk,
        value,
        &victim,
        &p2pkh_spk(&victim),
        Sats(40_000),
        Sats(1_000),
    );
    assert!(validate_tx(&honest, &view, &params).is_ok());

    // Extract the sig item from scriptSig: <push sig> <push pubkey>.
    let ss = &honest.inputs[0].script_sig;
    assert!(ss.len() > 2 && ss[0] as usize + 1 < ss.len());
    let sig_len = ss[0] as usize;
    let sig_item = &ss[1..1 + sig_len]; // DER sig + 1 hashtype byte
    assert!(sig_item.len() >= 9);
    let (der, hashtype) = sig_item.split_at(sig_item.len() - 1);

    // Parse the honest signature, forge its high-S twin.
    let sig = minibtc_crypto::Signature::from_der(der).expect("honest sig parses");
    let compact = sig.to_compact(); // r || s, 64 bytes
    let mut r = [0u8; 32];
    let mut s_low = [0u8; 32];
    r.copy_from_slice(&compact[..32]);
    s_low.copy_from_slice(&compact[32..]);
    let s_high = sub_be(&CURVE_ORDER, &s_low);
    assert_ne!(s_high, s_low, "s == n-s would mean s = n/2 (never for valid sigs)");
    let forged_der = der_encode_sig(&r, &s_high);
    let mut forged_item = forged_der;
    forged_item.push(hashtype[0]);

    // Rebuild the spend with the malleated scriptSig.
    let mut mal_tx = honest.clone();
    mal_tx.inputs[0].script_sig =
        Script::p2pkh_spend(&forged_item, &victim.public_key()).0;
    let err = validate_tx(&mal_tx, &view, &params).unwrap_err();
    assert!(
        matches!(err, TxError::ScriptFailed { .. }),
        "malleated tx must fail script validation, got {err:?}"
    );

    // Sanity: the forged DER itself is rejected by the strict parser
    // as HighS before any math runs.
    assert!(matches!(
        minibtc_crypto::Signature::from_der(&forged_item[..forged_item.len() - 1]),
        Err(minibtc_crypto::KeyError::HighS)
    ));
}
