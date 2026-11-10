//! Transaction types and their canonical serialization.
//!
//! A MiniBTC transaction is Bitcoin's pre-segwit format: no witness data,
//! so `txid = double_sha256(serialization)` covers *everything* — there is
//! no malleable witness plane to reason about. Every integer is little-endian,
//! every variable-length field is CompactSize-prefixed, and decoding is
//! strict: non-canonical CompactSize, trailing bytes, and oversized vectors
//! are all errors (see [`crate::de`]).

use minibtc_crypto::{Hash256, double_sha256};
use serde::{Deserialize, Serialize};

use crate::de::{ReadError, Reader};
use crate::money::Sats;
use crate::ser::Writer;

/// Consensus bounds (enforced by validation, mirrored here for decode caps).
pub const MAX_TX_SIZE: usize = 100_000;
/// Maximum inputs or outputs a single transaction may declare.
pub const MAX_TX_IO: usize = 100_000;

/// A reference to a previous transaction output: `(txid, vout)`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OutPoint {
    /// The transaction being spent.
    pub txid: Hash256,
    /// Which output index within it.
    pub vout: u32,
}

impl OutPoint {
    /// The null outpoint — used only by coinbase inputs.
    pub const NULL: Self = Self {
        txid: Hash256::ZERO,
        vout: u32::MAX,
    };

    fn encode(&self, w: &mut Writer) {
        w.hash256(&self.txid);
        w.u32(self.vout);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ReadError> {
        Ok(Self {
            txid: r.hash256()?,
            vout: r.u32()?,
        })
    }
}

impl std::fmt::Debug for OutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

impl std::fmt::Display for OutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// One input: which outpoint it spends plus its unlocking script.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInput {
    /// The outpoint being spent.
    pub prev: OutPoint,
    /// Unlocking script — for P2PKH: `<sig> <pubkey>` pushes.
    pub script_sig: Vec<u8>,
    /// Sequence number (finality/locktime semantics; we keep the field for
    /// wire compatibility).
    pub sequence: u32,
}

impl TxInput {
    fn encode(&self, w: &mut Writer) {
        self.prev.encode(w);
        w.prefixed_bytes(&self.script_sig);
        w.u32(self.sequence);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ReadError> {
        Ok(Self {
            prev: OutPoint::decode(r)?,
            script_sig: r.prefixed_bytes(MAX_TX_SIZE)?,
            sequence: r.u32()?,
        })
    }
}

impl std::fmt::Debug for TxInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxInput")
            .field("prev", &self.prev)
            .field("script_sig", &crate::tx::hex::encode_hex(&self.script_sig))
            .field("sequence", &self.sequence)
            .finish()
    }
}

/// One output: how much and under which locking script.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    /// Amount in base units.
    pub value: Sats,
    /// Locking script — for P2PKH: `OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG`.
    pub script_pubkey: Vec<u8>,
}

impl TxOutput {
    fn encode(&self, w: &mut Writer) {
        w.u64(self.value.sats());
        w.prefixed_bytes(&self.script_pubkey);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ReadError> {
        Ok(Self {
            value: Sats(r.u64()?),
            script_pubkey: r.prefixed_bytes(MAX_TX_SIZE)?,
        })
    }
}

impl std::fmt::Debug for TxOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxOutput")
            .field("value", &self.value)
            .field(
                "script_pubkey",
                &crate::tx::hex::encode_hex(&self.script_pubkey),
            )
            .finish()
    }
}

/// A whole transaction.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Format version (i32 on the wire).
    pub version: i32,
    /// Inputs spending previous outputs.
    pub inputs: Vec<TxInput>,
    /// Outputs creating new UTXOs.
    pub outputs: Vec<TxOutput>,
    /// Block height/time before which this tx is not final (0 = final).
    pub locktime: u32,
}

impl Transaction {
    /// A coinbase has exactly one input whose prevout is null.
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].prev == OutPoint::NULL
    }

    /// Canonical serialization — the bytes the txid commits to.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(256);
        w.i32(self.version);
        w.count_prefix(self.inputs.len());
        for i in &self.inputs {
            i.encode(&mut w);
        }
        w.count_prefix(self.outputs.len());
        for o in &self.outputs {
            o.encode(&mut w);
        }
        w.u32(self.locktime);
        w.into_bytes()
    }

    /// Strict canonical decode of `bytes`. Rejects trailing bytes, bad
    /// CompactSize, oversized vectors — anything not byte-exact.
    pub fn decode(bytes: &[u8]) -> Result<Self, ReadError> {
        let mut r = Reader::new(bytes);
        let tx = Self::decode_body(&mut r)?;
        r.finish()?;
        Ok(tx)
    }

    /// Decode one transaction from the front of a shared reader — used for
    /// blocks, where transactions are concatenated without per-tx length
    /// prefixes. Consumes exactly this tx's bytes; the caller continues
    /// with the next tx or `finish()`.
    pub fn decode_prefix(r: &mut Reader<'_>) -> Result<Self, ReadError> {
        Self::decode_body(r)
    }

    fn decode_body(r: &mut Reader<'_>) -> Result<Self, ReadError> {
        let version = r.i32()?;
        let inputs = r.vec(MAX_TX_IO, TxInput::decode)?;
        let outputs = r.vec(MAX_TX_IO, TxOutput::decode)?;
        let locktime = r.u32()?;
        Ok(Self {
            version,
            inputs,
            outputs,
            locktime,
        })
    }

    /// The transaction id: `double_sha256` of the canonical encoding.
    /// Displayed reversed (Bitcoin convention); stored raw internally.
    pub fn txid(&self) -> Hash256 {
        double_sha256(&self.encode())
    }

    /// Total output value — checked; `None` if it would overflow u64
    /// (which valid chains never reach, but hostile txs can claim).
    pub fn output_sum(&self) -> Option<Sats> {
        Sats::checked_sum(self.outputs.iter().map(|o| o.value))
    }
}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("version", &self.version)
            .field("inputs", &self.inputs)
            .field("outputs", &self.outputs)
            .field("locktime", &self.locktime)
            .finish()
    }
}

/// Tiny hex helper kept private to primitives (display/debug only).
pub(crate) mod hex {
    pub(crate) fn encode_hex(bytes: &[u8]) -> String {
        minibtc_crypto::hash::hex_encode(bytes)
    }
}
