//! Block types, merkle trees, and the CVE-2012-2459 ambiguity check.
//!
//! A block is a [`BlockHeader`] plus the transactions it commits to. The
//! header's `merkle_root` must equal the computed root of `txs` — checked
//! with Bitcoin Core's mutation test, not just equality, because the
//! odd-leaf duplication rule means two *different* transaction lists can
//! hash to the same root (CVE-2012-2459). We detect that case explicitly
//! and reject the block rather than picking a winner arbitrarily. A
//! mutated block carries the honest block's hash, so callers must not
//! remember the hash as invalid (see [`MerkleError::Ambiguous`]).

use minibtc_crypto::{Hash256, double_sha256};
use serde::{Deserialize, Serialize};

use crate::de::{ReadError, Reader};
use crate::ser::Writer;
use crate::tx::Transaction;

/// Consensus bound: the serialized block may not exceed this (the
/// `MAX_BLOCK_SIZE` consensus rule — deliberately generous for devnet,
/// still a hard cap so a peer can't send unbounded data).
pub const MAX_BLOCK_SIZE: usize = 1_000_000;
/// Bound on transactions per block (defense against absurd vectors).
pub const MAX_BLOCK_TXS: usize = 10_000;

/// The 80-byte block header — everything consensus commits to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Format version.
    pub version: i32,
    /// Hash of the previous block (`Hash256::ZERO` for genesis).
    pub prev_hash: Hash256,
    /// Merkle root of the transaction list.
    pub merkle_root: Hash256,
    /// Unix timestamp (seconds).
    pub time: u32,
    /// Compact difficulty target.
    pub bits: u32,
    /// Proof-of-work nonce.
    pub nonce: u32,
}

impl BlockHeader {
    /// Canonical 80-byte encoding — the bytes that get hashed for PoW.
    pub fn encode(&self) -> [u8; 80] {
        let mut w = Writer::with_capacity(80);
        w.i32(self.version);
        w.hash256(&self.prev_hash);
        w.hash256(&self.merkle_root);
        w.u32(self.time);
        w.u32(self.bits);
        w.u32(self.nonce);
        let bytes = w.into_bytes();
        let mut out = [0u8; 80];
        out.copy_from_slice(&bytes);
        out
    }

    /// Decode an 80-byte header from a reader (used by the `headers`
    /// P2P message and block decode).
    pub fn decode(r: &mut crate::de::Reader<'_>) -> Result<Self, ReadError> {
        let version = r.i32()?;
        let prev_hash = r.hash256()?;
        let merkle_root = r.hash256()?;
        let time = r.u32()?;
        let bits = r.u32()?;
        let nonce = r.u32()?;
        Ok(Self {
            version,
            prev_hash,
            merkle_root,
            time,
            bits,
            nonce,
        })
    }

    /// The block hash: `double_sha256(header_encoding)`.
    pub fn block_hash(&self) -> Hash256 {
        double_sha256(&self.encode())
    }

    /// Whether `hash <= target` — the PoW predicate, where `target` is
    /// decoded from compact `bits` (see `minibtc_consensus::pow`).
    pub fn check_pow(&self, target: &Hash256) -> bool {
        // Hash256 Ord is byte-wise big-endian = numeric order for the
        // display convention; PoW compares the *internal* byte order as a
        // little-endian 256-bit integer — we compare via reversed bytes.
        let hash_int = reversed(&self.block_hash().0);
        let target_int = reversed(&target.0);
        hash_int <= target_int
    }
}

/// Compare two 32-byte arrays as little-endian 256-bit integers.
fn reversed(b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = b[31 - i];
    }
    out
}

/// A full block: header + transactions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// The committed header.
    pub header: BlockHeader,
    /// Transactions, coinbase first (enforced by validation).
    pub txs: Vec<Transaction>,
}

impl Block {
    /// Canonical block serialization (header + tx vector).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(1024);
        w.bytes(&self.header.encode());
        w.count_prefix(self.txs.len());
        for tx in &self.txs {
            let tx_bytes = tx.encode();
            w.bytes(&tx_bytes);
        }
        w.into_bytes()
    }

    /// Strict decode. `tx_limit`/`size_limit` come from consensus params —
    /// the decoder never trusts the peer's declared sizes.
    pub fn decode(bytes: &[u8], tx_limit: usize, size_limit: usize) -> Result<Self, ReadError> {
        if bytes.len() > size_limit {
            return Err(ReadError::LengthOverflow {
                declared: bytes.len() as u64,
                remaining: size_limit as u64,
            });
        }
        let mut r = Reader::new(bytes);
        let header_bytes = r.take(80)?;
        let mut hb = [0u8; 80];
        hb.copy_from_slice(header_bytes);
        let header = BlockHeader {
            version: i32::from_le_bytes([hb[0], hb[1], hb[2], hb[3]]),
            prev_hash: {
                let mut h = [0u8; 32];
                h.copy_from_slice(&hb[4..36]);
                Hash256(h)
            },
            merkle_root: {
                let mut h = [0u8; 32];
                h.copy_from_slice(&hb[36..68]);
                Hash256(h)
            },
            time: u32::from_le_bytes([hb[68], hb[69], hb[70], hb[71]]),
            bits: u32::from_le_bytes([hb[72], hb[73], hb[74], hb[75]]),
            nonce: u32::from_le_bytes([hb[76], hb[77], hb[78], hb[79]]),
        };
        let txs = r.vec(tx_limit.min(MAX_BLOCK_TXS), |r2| {
            // Transactions are not length-prefixed inside a block — each is
            // self-delimiting via its own CompactSize vectors. We decode by
            // scanning: read the whole remainder is wrong; instead decode
            // incrementally is complex, so blocks carry a per-tx size cap and
            // we decode from the remaining buffer by trying the canonical
            // parse. Bitcoin solves this with a serializer that knows where
            // each tx ends; we do the same by decoding one tx at a time via
            // a sub-reader over the remaining bytes — but Transaction::decode
            // requires *exact* consumption.
            //
            // Practical approach: tx serialization is self-terminating only
            // at the locktime field. We implement `decode_prefix` below.
            Transaction::decode_prefix(r2)
        })?;
        r.finish()?;
        Ok(Self { header, txs })
    }
}

/// Errors specific to merkle computation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MerkleError {
    /// The block claimed a merkle root that doesn't match its transactions.
    #[error("merkle root mismatch")]
    RootMismatch,
    /// CVE-2012-2459: two different transaction lists produce this root —
    /// the block is ambiguous and must be rejected. The block hash is
    /// shared with the honest list, so this rejection says nothing about
    /// the hash: never cache it as an invalid block.
    #[error("ambiguous merkle root (CVE-2012-2459 duplicate-trailing-tx)")]
    Ambiguous,
}

/// Compute the merkle root of `txids` using Bitcoin's duplication rule:
/// an odd leaf is duplicated to make the level even.
pub fn merkle_root_from_txids(txids: &[Hash256]) -> Hash256 {
    merkle_root_and_mutation(txids).0
}

/// Merkle root plus Bitcoin Core's mutation flag (`ComputeMerkleRoot`
/// with `mutated`): `true` when, at any level, a pair position holds two
/// identical hashes. That is exactly the shape the odd-leaf padding
/// produces, so a list with it hashes to the same root as a shorter list
/// (CVE-2012-2459). The pair check runs before a level is padded, so an
/// honest odd level is never flagged.
pub fn merkle_root_and_mutation(txids: &[Hash256]) -> (Hash256, bool) {
    if txids.is_empty() {
        return (Hash256::ZERO, false);
    }
    let mut mutated = false;
    let mut level: Vec<Hash256> = txids.to_vec();
    while level.len() > 1 {
        if level.as_chunks::<2>().0.iter().any(|[a, b]| a == b) {
            mutated = true;
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            // Odd trailing element duplicates itself (Bitcoin's rule).
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                left
            };
            next.push(double_sha256(&[left.0, right.0].concat()));
            i = i.saturating_add(2);
        }
        level = next;
    }
    (level[0], mutated)
}

/// Merkle root of a transaction list.
pub fn merkle_root(txs: &[Transaction]) -> Hash256 {
    let txids: Vec<Hash256> = txs.iter().map(Transaction::txid).collect();
    merkle_root_from_txids(&txids)
}

/// Verify `header.merkle_root` against `txs`, including the CVE-2012-2459
/// mutation check from Bitcoin Core's `CheckBlock`: the root must match
/// (`bad-txnmrklroot`) and no tree level may contain an identical pair
/// (`bad-txns-duplicate`). Context-free and cheap — run it before a block
/// is queued or its hash remembered.
pub fn check_merkle_root(header: &BlockHeader, txs: &[Transaction]) -> Result<(), MerkleError> {
    let txids: Vec<Hash256> = txs.iter().map(Transaction::txid).collect();
    let (computed, mutated) = merkle_root_and_mutation(&txids);
    if computed != header.merkle_root {
        return Err(MerkleError::RootMismatch);
    }
    if mutated {
        return Err(MerkleError::Ambiguous);
    }
    Ok(())
}
