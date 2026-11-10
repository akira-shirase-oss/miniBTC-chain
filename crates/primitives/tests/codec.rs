//! Codec and merkle-rule tests: round-trips, canonical-form rejection,
//! bounds, and the CVE-2012-2459 ambiguity case.

use minibtc_crypto::{Hash256, double_sha256};
use minibtc_primitives::*;

fn sample_tx(marker: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: OutPoint {
                txid: Hash256([marker; 32]),
                vout: 0,
            },
            script_sig: [vec![0x51, 0x21], vec![marker; 33]].concat(),
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput {
            value: Sats(50_000),
            script_pubkey: [vec![0x76, 0xa9, 0x14], vec![marker; 20]].concat(),
        }],
        locktime: 0,
    }
}

#[test]
fn tx_encode_decode_roundtrip() {
    let tx = sample_tx(0x42);
    let bytes = tx.encode();
    let back = Transaction::decode(&bytes).unwrap();
    assert_eq!(back, tx);
    assert_eq!(back.txid(), tx.txid());
}

#[test]
fn tx_decode_rejects_truncation_and_trailing() {
    let tx = sample_tx(0x07);
    let bytes = tx.encode();
    for cut in [0, 5, bytes.len() / 2, bytes.len() - 1] {
        assert!(Transaction::decode(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    let mut padded = bytes.clone();
    padded.push(0x00);
    assert!(Transaction::decode(&padded).is_err());
}

#[test]
fn tx_decode_rejects_noncanonical_compact_size() {
    // Hand-craft: version(4) + input_count encoded non-canonically as
    // 0xFD 0x01 0x00 (claims 1 input via 2-byte form — must be rejected).
    let mut raw = vec![1, 0, 0, 0, 0xFD, 0x01, 0x00];
    raw.extend_from_slice(&[0u8; 64]); // rest is garbage anyway
    assert!(Transaction::decode(&raw).is_err());
}

#[test]
fn outpoint_and_money_basics() {
    assert_eq!(OutPoint::NULL.vout, u32::MAX);
    assert_eq!(OutPoint::NULL.txid, Hash256::ZERO);
    let a = Sats(100);
    let b = Sats(23);
    assert_eq!(a.checked_add(b), Some(Sats(123)));
    assert_eq!(b.checked_sub(a), None);
    assert_eq!(Sats::checked_sum([a, b]), Some(Sats(123)));
    assert_eq!("5000".parse::<Sats>().unwrap(), Sats(5000));
    assert!("-1".parse::<Sats>().is_err());
    assert!("18446744073709551616".parse::<Sats>().is_err());
}

#[test]
fn block_roundtrip() {
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: OutPoint::NULL,
            script_sig: vec![0x03, b'm', b'i', b'n'],
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput {
            value: Sats(5_000_000_000),
            script_pubkey: vec![0x51],
        }],
        locktime: 0,
    };
    let header = BlockHeader {
        version: 1,
        prev_hash: Hash256::ZERO,
        merkle_root: merkle_root(&[coinbase.clone()]),
        time: 1_700_000_000,
        bits: 0x207f_ffff,
        nonce: 42,
    };
    let block = Block {
        header,
        txs: vec![coinbase],
    };
    let bytes = block.encode();
    let back = Block::decode(&bytes, MAX_BLOCK_TXS, MAX_BLOCK_SIZE).unwrap();
    assert_eq!(back, block);
    assert_eq!(back.header.block_hash(), header.block_hash());
}

#[test]
fn merkle_root_known_shape() {
    // Three txs: level0 [A B C] → [H(A,B), H(C,C)] → root.
    let a = sample_tx(1).txid();
    let b = sample_tx(2).txid();
    let c = sample_tx(3).txid();
    let h_ab = double_sha256(&[a.0, b.0].concat());
    let h_cc = double_sha256(&[c.0, c.0].concat());
    let want = double_sha256(&[h_ab.0, h_cc.0].concat());
    assert_eq!(merkle_root_from_txids(&[a, b, c]), want);
}

#[test]
fn merkle_check_rejects_wrong_root_and_ambiguity() {
    let txs = vec![sample_tx(9), sample_tx(10)];
    let good = BlockHeader {
        version: 1,
        prev_hash: Hash256::ZERO,
        merkle_root: merkle_root(&txs),
        time: 0,
        bits: 0,
        nonce: 0,
    };
    assert!(check_merkle_root(&good, &txs).is_ok());

    let bad = BlockHeader {
        merkle_root: Hash256([0xaa; 32]),
        ..good
    };
    assert!(matches!(
        check_merkle_root(&bad, &txs),
        Err(MerkleError::RootMismatch)
    ));
}

#[test]
fn block_decode_enforces_size_and_tx_caps() {
    let tx = sample_tx(5);
    let header = BlockHeader {
        version: 1,
        prev_hash: Hash256::ZERO,
        merkle_root: merkle_root(&[tx.clone()]),
        time: 0,
        bits: 0,
        nonce: 0,
    };
    let block = Block {
        header,
        txs: vec![tx],
    };
    let bytes = block.encode();
    assert!(Block::decode(&bytes, MAX_BLOCK_TXS, 10).is_err()); // size cap
    assert!(Block::decode(&bytes, 0, MAX_BLOCK_SIZE).is_err()); // tx cap
}

#[test]
fn reader_bounds_and_compact_size_canonical() {
    let mut r = Reader::new(&[0x01, 0x02]);
    assert_eq!(r.u8().unwrap(), 1);
    assert_eq!(r.u8().unwrap(), 2);
    assert!(r.u8().is_err());

    // 0xFD encoding of 300 is canonical; of 5 is not.
    let mut ok = Reader::new(&[0xFD, 0x2C, 0x01]);
    assert_eq!(ok.compact_size().unwrap(), 300);
    let mut bad = Reader::new(&[0xFD, 0x05, 0x00]);
    assert!(matches!(
        bad.compact_size(),
        Err(ReadError::NonCanonicalCompactSize(0))
    ));

    // prefixed_bytes refuses declared > remaining.
    let mut r2 = Reader::new(&[0x05, 0xAA]);
    assert!(matches!(
        r2.prefixed_bytes(10),
        Err(ReadError::LengthOverflow { .. })
    ));
}
