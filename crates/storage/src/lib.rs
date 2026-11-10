//! # minibtc-storage
//!
//! Durable persistence on `redb`: blocks, the UTXO set, undo data, the
//! transaction index and the address index — all committed in **one
//! atomic write transaction** per snapshot, so a crash can never leave a
//! half-written chain.
//!
//! Invariants:
//! - `snapshot(chain)` is atomic: either the whole chain state lands or
//!   none of it does (redb write-txn semantics).
//! - `load` rebuilds a [`Chain`] whose UTXO fingerprint equals a fresh
//!   replay of the stored blocks — proven by `consistency_check`.
//! - `reindex` replays every stored block through validation, discarding
//!   any state derived from corrupt data.
//! - All keys/values are canonical byte encodings; decode paths are
//!   bounded and reject trailing bytes.

use minibtc_chainstate::{Chain, ChainError, IndexedBlock, UtxoEntry};
use minibtc_consensus::ChainParams;
use minibtc_crypto::Hash256;
use minibtc_primitives::de::Reader;
use minibtc_primitives::ser::Writer;
use minibtc_primitives::{Block, OutPoint, Sats};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::path::Path;
use std::sync::Arc;

/// Table: block_hash(32B) → canonical block bytes.
const BLOCKS: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("blocks");
/// Table: block_hash(32B) → header metadata (height, cum_work, status,
/// prev_hash) for index reconstruction without re-validating.
const META: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("meta");
/// Table: outpoint(36B) → encoded UtxoEntry.
const UTKOS: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("utxos");
/// Table: block_hash(32B) → encoded UndoData (for disconnect after load).
const UNDOS: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("undos");
/// Table: txid(32B) → block_hash(32B) it was confirmed in.
const TXINDEX: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("txindex");
/// Table: script_pubkey bytes → concatenated outpoints it pays to.
const ADDRINDEX: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("addrindex");
/// Table: single-row "meta" → chain params fingerprint + genesis hash.
const CHAINMETA: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("chainmeta");

/// Storage errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// redb failure.
    #[error("redb: {0}")]
    Redb(#[from] redb::Error),
    /// redb database-open failure.
    #[error("redb db: {0}")]
    Db(#[from] redb::DatabaseError),
    /// redb storage failure on insert/commit.
    #[error("redb storage: {0}")]
    Storage(#[from] redb::StorageError),
    /// redb commit failure.
    #[error("redb commit: {0}")]
    Commit(#[from] redb::CommitError),
    /// redb transaction failure.
    #[error("redb txn: {0}")]
    Txn(#[from] redb::TransactionError),
    /// Table access failure.
    #[error("table: {0}")]
    Table(#[from] redb::TableError),
    /// Stored bytes failed to decode — corruption or version skew.
    #[error("corrupt stored value: {0}")]
    Corrupt(String),
    /// Chain-level error during load/replay.
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    /// IO error creating the data directory.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// The durable store. `Clone`-able handle — redb databases are
/// thread-safe; each method opens its own transaction.
#[derive(Clone, Debug)]
pub struct Store {
    db: Arc<Database>,
}

/// What the store knows about which chain it holds.
#[derive(Clone, Debug)]
pub struct StoreInfo {
    /// Genesis block hash the stored chain starts from.
    pub genesis: Hash256,
    /// Number of stored blocks.
    pub blocks: usize,
    /// Number of stored UTXOs.
    pub utxos: usize,
    /// Tip block hash (most work).
    pub tip: Option<Hash256>,
}

type BytesTable = redb::ReadOnlyTable<&'static [u8], &'static [u8]>;

/// Open a read table that may not exist yet (fresh store) → None.
fn opt_table(
    txn: &redb::ReadTransaction,
    def: TableDefinition<'static, &'static [u8], &'static [u8]>,
) -> Result<Option<BytesTable>, StoreError> {
    match txn.open_table(def) {
        Ok(t) => Ok(Some(t)),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
        Err(e) => Err(StoreError::Table(e)),
    }
}

impl Store {
    /// Open (creating if needed) the store at `dir`.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(dir)?;
        let db = Database::create(dir.join("minibtc.redb"))?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Atomically persist the entire chain state: every indexed block,
    /// the full UTXO set, undo data, tx/address indexes and chain meta.
    /// One redb write transaction — all-or-nothing.
    pub fn snapshot(&self, chain: &Chain) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut blocks = txn.open_table(BLOCKS)?;
            let mut meta = txn.open_table(META)?;
            let mut utxos = txn.open_table(UTKOS)?;
            let mut undos = txn.open_table(UNDOS)?;
            let mut txindex = txn.open_table(TXINDEX)?;
            let mut addrindex = txn.open_table(ADDRINDEX)?;
            let mut chainmeta = txn.open_table(CHAINMETA)?;

            // Wipe then rewrite — snapshot semantics (a stale key from a
            // previous longer chain must not survive).
            blocks.retain(|_, _| false)?;
            meta.retain(|_, _| false)?;
            utxos.retain(|_, _| false)?;
            undos.retain(|_, _| false)?;
            txindex.retain(|_, _| false)?;
            addrindex.retain(|_, _| false)?;

            // Chain meta: genesis ++ tip (tip makes load robust across
            // partial disconnects where inactive blocks still hold the
            // highest cum_work).
            let mut cm = Writer::new();
            cm.hash256(&chain.genesis);
            cm.hash256(&chain.tip);
            chainmeta.insert(&b"chain"[..], cm.into_bytes().as_slice())?;

            // Blocks + meta + txindex + addrindex inputs.
            let mut addr_map: std::collections::BTreeMap<Vec<u8>, Vec<u8>> =
                std::collections::BTreeMap::new();
            for (hash, rec) in &chain.blocks {
                blocks.insert(hash.as_bytes(), rec.block.encode().as_slice())?;
                let mut m = Writer::new();
                m.u32(rec.height);
                m.bytes(&rec.cum_work.to_le_bytes());
                m.u8(match rec.status {
                    minibtc_chainstate::BlockStatus::Active => 1,
                    minibtc_chainstate::BlockStatus::Inactive => 0,
                });
                m.hash256(&rec.block.header.prev_hash);
                meta.insert(hash.as_bytes(), m.into_bytes().as_slice())?;
                for tx in &rec.block.txs {
                    let txid = tx.txid();
                    txindex.insert(txid.as_bytes(), hash.as_bytes())?;
                    let txid_b = txid.as_bytes();
                    for (vout, out) in tx.outputs.iter().enumerate() {
                        let mut op = Vec::with_capacity(36);
                        op.extend_from_slice(txid_b);
                        op.extend_from_slice(&(vout as u32).to_le_bytes());
                        addr_map
                            .entry(out.script_pubkey.clone())
                            .or_default()
                            .extend_from_slice(&op);
                    }
                }
            }
            for (script, ops) in &addr_map {
                addrindex.insert(script.as_slice(), ops.as_slice())?;
            }

            // UTXOs + undos.
            for (op, entry) in chain.utxos.iter() {
                utxos.insert(outpoint_key(op).as_slice(), encode_utxo(entry).as_slice())?;
            }
            for (hash, undo) in &chain.undos {
                undos.insert(hash.as_bytes(), encode_undo(undo).as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Incrementally persist one newly-connected block: block bytes,
    /// index meta, tx/address indexes, the UTXO delta and its undo data —
    /// one atomic write txn, cost O(block) instead of O(chain). Use for
    /// the common direct-tip-extension path; reorgs and side branches
    /// still go through [`Self::snapshot`].
    ///
    /// The caller must invoke this *after* `chain.connect_tip`/`consider_block`
    /// has applied the block, while `chain.undos` still holds its undo.
    pub fn append_block(&self, chain: &Chain, hash: &Hash256) -> Result<(), StoreError> {
        let rec = chain
            .blocks
            .get(hash)
            .ok_or_else(|| StoreError::Corrupt("append_block: unknown block".into()))?
            .clone();
        let undo = chain
            .undos
            .get(hash)
            .ok_or_else(|| StoreError::Corrupt("append_block: missing undo".into()))?;
        let txn = self.db.begin_write()?;
        {
            let mut blocks = txn.open_table(BLOCKS)?;
            let mut meta = txn.open_table(META)?;
            let mut utxos = txn.open_table(UTKOS)?;
            let mut undos = txn.open_table(UNDOS)?;
            let mut txindex = txn.open_table(TXINDEX)?;
            let mut addrindex = txn.open_table(ADDRINDEX)?;
            let mut chainmeta = txn.open_table(CHAINMETA)?;

            blocks.insert(hash.as_bytes(), rec.block.encode().as_slice())?;
            let mut m = Writer::new();
            m.u32(rec.height);
            m.bytes(&rec.cum_work.to_le_bytes());
            m.u8(match rec.status {
                minibtc_chainstate::BlockStatus::Active => 1,
                minibtc_chainstate::BlockStatus::Inactive => 0,
            });
            m.hash256(&rec.block.header.prev_hash);
            meta.insert(hash.as_bytes(), m.into_bytes().as_slice())?;
            undos.insert(hash.as_bytes(), encode_undo(undo).as_slice())?;

            // Tx-by-tx in order: spend prevouts, create outputs. Sequential
            // order keeps intra-block spends correct.
            for (i, tx) in rec.block.txs.iter().enumerate() {
                let txid = tx.txid();
                txindex.insert(txid.as_bytes(), hash.as_bytes())?;
                let is_cb = i == 0;
                if !is_cb {
                    for inp in &tx.inputs {
                        let _ = utxos.remove(outpoint_key(&inp.prev).as_slice())?;
                    }
                }
                for (vout, out) in tx.outputs.iter().enumerate() {
                    let vout32 = vout as u32;
                    let mut buf = addrindex
                        .get(out.script_pubkey.as_slice())?
                        .map(|g| g.value().to_vec())
                        .unwrap_or_default();
                    buf.extend_from_slice(txid.as_bytes());
                    buf.extend_from_slice(&vout32.to_le_bytes());
                    addrindex.insert(out.script_pubkey.as_slice(), buf.as_slice())?;
                    let entry = UtxoEntry {
                        output: out.clone(),
                        height: rec.height,
                        coinbase: is_cb,
                    };
                    let op = OutPoint {
                        txid,
                        vout: vout32,
                    };
                    utxos.insert(
                        outpoint_key(&op).as_slice(),
                        encode_utxo(&entry).as_slice(),
                    )?;
                }
            }
            // Advance the recorded tip.
            let mut cm = Writer::new();
            cm.hash256(&chain.genesis);
            cm.hash256(hash);
            chainmeta.insert(&b"chain"[..], cm.into_bytes().as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Persist a tip disconnect: restore spent outputs, remove created
    /// ones, mark the block inactive. Call *before* `chain.disconnect_tip`
    /// while the undo record is still in `chain.undos`. Reorgs that
    /// disconnect several blocks should use [`Self::snapshot`] instead.
    pub fn disconnect_block(&self, chain: &Chain, hash: &Hash256) -> Result<(), StoreError> {
        let undo = chain
            .undos
            .get(hash)
            .ok_or_else(|| StoreError::Corrupt("disconnect_block: missing undo".into()))?;
        let txn = self.db.begin_write()?;
        {
            let mut utxos = txn.open_table(UTKOS)?;
            let mut meta = txn.open_table(META)?;
            let mut chainmeta = txn.open_table(CHAINMETA)?;
            // Reverse order — mirrors chainstate::disconnect_tip. A spent
            // entry recorded for an intra-block spend is itself deleted by
            // the creating tx's `created` list when its turn comes.
            for u in undo.txs.iter().rev() {
                for op in &u.created {
                    let _ = utxos.remove(outpoint_key(op).as_slice())?;
                }
                for (op, entry) in &u.spent {
                    utxos.insert(
                        outpoint_key(op).as_slice(),
                        encode_utxo(entry).as_slice(),
                    )?;
                }
            }
            let mut new_tip = None;
            if let Some(rec) = chain.blocks.get(hash) {
                let mut m = Writer::new();
                m.u32(rec.height);
                m.bytes(&rec.cum_work.to_le_bytes());
                m.u8(0u8); // inactive
                m.hash256(&rec.block.header.prev_hash);
                meta.insert(hash.as_bytes(), m.into_bytes().as_slice())?;
                new_tip = Some(rec.block.header.prev_hash);
            }
            if let Some(tip) = new_tip {
                let mut cm = Writer::new();
                cm.hash256(&chain.genesis);
                cm.hash256(&tip);
                chainmeta.insert(&b"chain"[..], cm.into_bytes().as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Load the stored chain state into memory. Returns `None` if the
    /// store is empty.
    ///
    /// This trusts stored meta — use [`Self::reindex`] to rebuild from
    /// blocks alone when integrity matters.
    pub fn load(&self, params: ChainParams, genesis: Block) -> Result<Option<Chain>, StoreError> {
        let txn = self.db.begin_read()?;
        let Some(blocks_t) = opt_table(&txn, BLOCKS)? else {
            return Ok(None);
        };
        if blocks_t.is_empty()? {
            return Ok(None);
        }
        // Snapshot writes all tables atomically — a missing sibling table
        // alongside blocks means corruption.
        let meta_t =
            opt_table(&txn, META)?.ok_or(StoreError::Corrupt("meta table missing".into()))?;
        let utxos_t =
            opt_table(&txn, UTKOS)?.ok_or(StoreError::Corrupt("utxos table missing".into()))?;
        let undos_t =
            opt_table(&txn, UNDOS)?.ok_or(StoreError::Corrupt("undos table missing".into()))?;

        let genesis_hash = genesis.header.block_hash();
        let mut chain = Chain::new(params.clone(), genesis)?;
        // Replace genesis-derived empty index with stored state.
        chain.blocks.clear();
        chain.utxos = minibtc_chainstate::UtxoSet::default();
        chain.undos.clear();

        // Recorded tip (genesis++tip written by snapshot/append/disconnect).
        // Fall back to max-work for stores written before tip tracking.
        let recorded_tip = {
            let txn2 = self.db.begin_read()?;
            match opt_table(&txn2, CHAINMETA)? {
                Some(t) => match t.get(&b"chain"[..])? {
                    Some(g) => {
                        let b = g.value();
                        if b.len() >= 64 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&b[32..64]);
                            Some(Hash256(arr))
                        } else {
                            None
                        }
                    }
                    None => None,
                },
                None => None,
            }
        };

        // Rebuild UTXO set from stored entries.
        for row in utxos_t.iter()? {
            let (k, v) = row?;
            let op = decode_outpoint_key(k.value())?;
            let entry = decode_utxo(v.value())?;
            chain.utxos.insert(op, entry);
        }
        // Blocks + meta.
        let mut max_work = (0u128, Hash256::ZERO);
        for row in blocks_t.iter()? {
            let (k, v) = row?;
            let kb = k.value();
            if kb.len() != 32 {
                return Err(StoreError::Corrupt("bad block key".into()));
            }
            let mut karr = [0u8; 32];
            karr.copy_from_slice(kb);
            let hash = Hash256(karr);
            let block = Block::decode(v.value(), params.max_block_txs, params.max_block_size)
                .map_err(|e| StoreError::Corrupt(format!("block decode: {e}")))?;
            let meta_guard = meta_t
                .get(hash.as_bytes())?
                .ok_or_else(|| StoreError::Corrupt("missing meta for block".into()))?;
            let mut r = Reader::new(meta_guard.value());
            let height = r.u32().map_err(|e| StoreError::Corrupt(e.to_string()))?;
            let cw_bytes = r.take(16).map_err(|e| StoreError::Corrupt(e.to_string()))?;
            let mut cw = [0u8; 16];
            cw.copy_from_slice(cw_bytes);
            let cum_work = u128::from_le_bytes(cw);
            let status_byte = r.u8().map_err(|e| StoreError::Corrupt(e.to_string()))?;
            let prev = r
                .hash256()
                .map_err(|e| StoreError::Corrupt(e.to_string()))?;
            let status = if status_byte == 1 {
                minibtc_chainstate::BlockStatus::Active
            } else {
                minibtc_chainstate::BlockStatus::Inactive
            };
            let rec = IndexedBlock {
                block,
                height,
                cum_work,
                status,
            };
            let _ = prev;
            if hash == genesis_hash {
                // Genesis already connected by Chain::new; restore its
                // recorded meta but keep the canonical entry.
                chain.blocks.insert(hash, rec);
                continue;
            }
            chain.blocks.insert(hash, rec);
            if cum_work > max_work.0 {
                max_work = (cum_work, hash);
            }
        }
        // Undos.
        for row in undos_t.iter()? {
            let (k, v) = row?;
            let kb = k.value();
            if kb.len() != 32 {
                return Err(StoreError::Corrupt("bad undo key".into()));
            }
            let mut karr = [0u8; 32];
            karr.copy_from_slice(kb);
            let hash = Hash256(karr);
            chain.undos.insert(hash, decode_undo(v.value())?);
        }
        // Tip = recorded tip when it names a stored block, else most work.
        chain.tip = recorded_tip
            .filter(|t| *t == genesis_hash || chain.blocks.contains_key(t))
            .unwrap_or(if max_work.0 > 0 { max_work.1 } else { genesis_hash });
        // Recompute active status: mark only the active-chain blocks.
        mark_active(&mut chain);
        Ok(Some(chain))
    }

    /// Rebuild the chain by replaying every stored block through full
    /// validation — the integrity path. Discards all derived state first.
    pub fn reindex(&self, params: ChainParams, genesis: Block) -> Result<Chain, StoreError> {
        let txn = self.db.begin_read()?;
        let Some(blocks_t) = opt_table(&txn, BLOCKS)? else {
            // Empty store → replay just genesis.
            return Ok(Chain::new(params.clone(), genesis)?);
        };
        let mut blocks: Vec<Block> = Vec::new();
        for row in blocks_t.iter()? {
            let (_, v) = row?;
            blocks.push(
                Block::decode(v.value(), params.max_block_txs, params.max_block_size)
                    .map_err(|e| StoreError::Corrupt(format!("block decode: {e}")))?,
            );
        }
        drop(blocks_t);
        drop(txn);

        // Order by height via prev-chain walk from tips: simplest correct
        // approach — repeatedly connect any block whose parent is known.
        let genesis_hash = genesis.header.block_hash();
        let mut chain = Chain::new(params.clone(), genesis)?;
        let mut pending: std::collections::HashMap<Hash256, Block> = blocks
            .into_iter()
            .map(|b| (b.header.block_hash(), b))
            .collect();
        pending.remove(&genesis_hash);
        // Iteratively connect blocks whose prev is the tip or known.
        loop {
            let tip_hash = chain.tip;
            // Find a pending block building on tip.
            let next = pending
                .values()
                .find(|b| b.header.prev_hash == tip_hash)
                .map(|b| b.header.block_hash());
            match next {
                Some(h) => {
                    let b = pending
                        .remove(&h)
                        .ok_or_else(|| StoreError::Corrupt("pending block vanished".into()))?;
                    chain.connect_tip(b)?;
                }
                None => break,
            }
        }
        // Any leftovers are side-branch — consider them for completeness.
        for (_, b) in pending {
            let _ = chain.consider_block(b);
        }
        Ok(chain)
    }

    /// The consistency proof: replay stored blocks fresh and compare the
    /// resulting UTXO fingerprint against `chain`'s.
    pub fn consistency_check(
        &self,
        params: ChainParams,
        genesis: Block,
        chain: &Chain,
    ) -> Result<bool, StoreError> {
        let replayed = self.reindex(params, genesis)?;
        Ok(replayed.utxos.fingerprint() == chain.utxos.fingerprint())
    }

    /// Store metadata for observability.
    pub fn info(&self, chain: &Chain) -> Result<StoreInfo, StoreError> {
        let txn = self.db.begin_read()?;
        let blocks_t = opt_table(&txn, BLOCKS)?;
        let utxos_t = opt_table(&txn, UTKOS)?;
        Ok(StoreInfo {
            genesis: chain.genesis,
            blocks: blocks_t.as_ref().map(|t| t.len()).transpose()?.unwrap_or(0) as usize,
            utxos: utxos_t.as_ref().map(|t| t.len()).transpose()?.unwrap_or(0) as usize,
            tip: Some(chain.tip),
        })
    }

    /// Raw block lookup by hash (for RPC/explorer).
    pub fn get_block(&self, hash: &Hash256) -> Result<Option<Block>, StoreError> {
        let txn = self.db.begin_read()?;
        let Some(t) = opt_table(&txn, BLOCKS)? else {
            return Ok(None);
        };
        match t.get(hash.as_bytes())? {
            Some(v) => Ok(Some(
                Block::decode(v.value(), usize::MAX, usize::MAX)
                    .map_err(|e| StoreError::Corrupt(format!("block decode: {e}")))?,
            )),
            None => Ok(None),
        }
    }

    /// Transaction lookup → the block hash that confirmed it.
    pub fn tx_block(&self, txid: &Hash256) -> Result<Option<Hash256>, StoreError> {
        let txn = self.db.begin_read()?;
        let Some(t) = opt_table(&txn, TXINDEX)? else {
            return Ok(None);
        };
        match t.get(txid.as_bytes())? {
            Some(v) => {
                let b = v.value();
                if b.len() != 32 {
                    return Err(StoreError::Corrupt("bad txindex value".into()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                Ok(Some(Hash256(arr)))
            }
            None => Ok(None),
        }
    }

    /// Outpoints paying to a script (address index).
    pub fn addr_outpoints(&self, script: &[u8]) -> Result<Vec<OutPoint>, StoreError> {
        let txn = self.db.begin_read()?;
        let Some(t) = opt_table(&txn, ADDRINDEX)? else {
            return Ok(Vec::new());
        };
        match t.get(script)? {
            Some(v) => {
                let b = v.value();
                if b.len() % 36 != 0 {
                    return Err(StoreError::Corrupt("bad addrindex value".into()));
                }
                let mut out = Vec::with_capacity(b.len() / 36);
                for chunk in b.chunks_exact(36) {
                    let mut txid = [0u8; 32];
                    txid.copy_from_slice(&chunk[..32]);
                    let vout = u32::from_le_bytes([chunk[32], chunk[33], chunk[34], chunk[35]]);
                    out.push(OutPoint {
                        txid: Hash256(txid),
                        vout,
                    });
                }
                Ok(out)
            }
            None => Ok(Vec::new()),
        }
    }

    /// UTXO lookup by outpoint (for wallet/RPC).
    pub fn get_utxo(&self, op: &OutPoint) -> Result<Option<UtxoEntry>, StoreError> {
        let txn = self.db.begin_read()?;
        let Some(t) = opt_table(&txn, UTKOS)? else {
            return Ok(None);
        };
        match t.get(outpoint_key(op).as_slice())? {
            Some(v) => Ok(Some(decode_utxo(v.value())?)),
            None => Ok(None),
        }
    }

    /// All UTXOs (wallet scan).
    pub fn all_utxos(&self) -> Result<Vec<(OutPoint, UtxoEntry)>, StoreError> {
        let txn = self.db.begin_read()?;
        let Some(t) = opt_table(&txn, UTKOS)? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for row in t.iter()? {
            let (k, v) = row?;
            out.push((decode_outpoint_key(k.value())?, decode_utxo(v.value())?));
        }
        Ok(out)
    }
}

/// Mark only the active-chain blocks as `Active` (recomputed on load —
/// stored status bytes are hints, the tip walk is authoritative).
fn mark_active(chain: &mut Chain) {
    // Walk back from tip marking ancestors active.
    let mut cur = chain.tip;
    let mut seen = std::collections::HashSet::new();
    while seen.insert(cur) {
        let Some(rec) = chain.blocks.get_mut(&cur) else {
            break;
        };
        rec.status = minibtc_chainstate::BlockStatus::Active;
        cur = rec.block.header.prev_hash;
    }
}

fn outpoint_key(op: &OutPoint) -> Vec<u8> {
    let mut k = Vec::with_capacity(36);
    k.extend_from_slice(op.txid.as_bytes());
    k.extend_from_slice(&op.vout.to_le_bytes());
    k
}

fn decode_outpoint_key(b: &[u8]) -> Result<OutPoint, StoreError> {
    if b.len() != 36 {
        return Err(StoreError::Corrupt("bad outpoint key".into()));
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&b[..32]);
    Ok(OutPoint {
        txid: Hash256(txid),
        vout: u32::from_le_bytes([b[32], b[33], b[34], b[35]]),
    })
}

fn encode_utxo(e: &UtxoEntry) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(e.output.value.sats());
    w.u32(e.height);
    w.u8(if e.coinbase { 1 } else { 0 });
    w.prefixed_bytes(&e.output.script_pubkey);
    w.into_bytes()
}

fn decode_utxo(b: &[u8]) -> Result<UtxoEntry, StoreError> {
    let mut r = Reader::new(b);
    let value = r.u64().map_err(|e| StoreError::Corrupt(e.to_string()))?;
    let height = r.u32().map_err(|e| StoreError::Corrupt(e.to_string()))?;
    let coinbase = r.u8().map_err(|e| StoreError::Corrupt(e.to_string()))? != 0;
    let script = r
        .prefixed_bytes(1 << 20)
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
    r.finish().map_err(|e| StoreError::Corrupt(e.to_string()))?;
    Ok(UtxoEntry {
        output: minibtc_primitives::TxOutput {
            value: Sats(value),
            script_pubkey: script,
        },
        height,
        coinbase,
    })
}

fn encode_undo(u: &minibtc_chainstate::UndoData) -> Vec<u8> {
    let mut w = Writer::new();
    w.compact_size(u.txs.len() as u64);
    for tx in &u.txs {
        w.compact_size(tx.spent.len() as u64);
        for (op, e) in &tx.spent {
            w.hash256(&op.txid);
            w.u32(op.vout);
            w.u64(e.output.value.sats());
            w.u32(e.height);
            w.u8(if e.coinbase { 1 } else { 0 });
            w.prefixed_bytes(&e.output.script_pubkey);
        }
        w.compact_size(tx.created.len() as u64);
        for op in &tx.created {
            w.hash256(&op.txid);
            w.u32(op.vout);
        }
    }
    w.into_bytes()
}

fn decode_undo(b: &[u8]) -> Result<minibtc_chainstate::UndoData, StoreError> {
    let mut r = Reader::new(b);
    let ntx = r
        .compact_size()
        .map_err(|e| StoreError::Corrupt(e.to_string()))? as usize;
    let mut txs = Vec::with_capacity(ntx.min(1 << 20));
    for _ in 0..ntx {
        let nspent = r
            .compact_size()
            .map_err(|e| StoreError::Corrupt(e.to_string()))? as usize;
        let mut spent = Vec::with_capacity(nspent.min(1 << 20));
        for _ in 0..nspent {
            let txid = r
                .hash256()
                .map_err(|e| StoreError::Corrupt(e.to_string()))?;
            let vout = r.u32().map_err(|e| StoreError::Corrupt(e.to_string()))?;
            let value = r.u64().map_err(|e| StoreError::Corrupt(e.to_string()))?;
            let height = r.u32().map_err(|e| StoreError::Corrupt(e.to_string()))?;
            let coinbase = r.u8().map_err(|e| StoreError::Corrupt(e.to_string()))? != 0;
            let script = r
                .prefixed_bytes(1 << 20)
                .map_err(|e| StoreError::Corrupt(e.to_string()))?;
            spent.push((
                OutPoint { txid, vout },
                UtxoEntry {
                    output: minibtc_primitives::TxOutput {
                        value: Sats(value),
                        script_pubkey: script,
                    },
                    height,
                    coinbase,
                },
            ));
        }
        let ncreated = r
            .compact_size()
            .map_err(|e| StoreError::Corrupt(e.to_string()))? as usize;
        let mut created = Vec::with_capacity(ncreated.min(1 << 20));
        for _ in 0..ncreated {
            let txid = r
                .hash256()
                .map_err(|e| StoreError::Corrupt(e.to_string()))?;
            let vout = r.u32().map_err(|e| StoreError::Corrupt(e.to_string()))?;
            created.push(OutPoint { txid, vout });
        }
        txs.push(minibtc_chainstate::UndoTx { spent, created });
    }
    r.finish().map_err(|e| StoreError::Corrupt(e.to_string()))?;
    Ok(minibtc_chainstate::UndoData { txs })
}
