//! # minibtc-primitives
//!
//! Data types and canonical serialization for MiniBTC: `Sats`, `OutPoint`,
//! `Transaction`, `Block`/`BlockHeader`, the `Writer`/`Reader` byte codec
//! with CompactSize, and the merkle-tree rules including the CVE-2012-2459
//! ambiguity check. Pure data + pure functions — no I/O, no clocks, no
//! validation policy (that lives in `minibtc-consensus`/`minibtc-script`).

pub mod block;
pub mod de;
pub mod money;
pub mod ser;
pub mod tx;

pub use block::{
    check_merkle_root, merkle_root, merkle_root_from_txids, Block, BlockHeader, MerkleError,
    MAX_BLOCK_SIZE, MAX_BLOCK_TXS,
};
pub use de::{ReadError, Reader};
pub use money::{MoneyError, Sats};
pub use ser::Writer;
pub use tx::{OutPoint, Transaction, TxInput, TxOutput, MAX_TX_IO, MAX_TX_SIZE};
