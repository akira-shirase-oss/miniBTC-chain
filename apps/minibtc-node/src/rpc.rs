//! JSON-RPC backend: implements `minibtc_rpc::RpcBackend` over the live
//! `Node`. Every method treats params as untrusted JSON, bounds its work,
//! and never exposes key material (there is none to expose — the node
//! holds no wallet secrets).

use crate::core::{self, Node, NodeInner};
use minibtc_crypto::hash::hex_decode;
use minibtc_crypto::{Address, Hash256};
use minibtc_primitives::{OutPoint, Sats, Transaction};
use minibtc_rpc::NODE_METHODS;
use minibtc_rpc::backend::RpcBackend;
use minibtc_rpc::render;
use minibtc_rpc::types::{RpcError, param_str, param_u64, param_u64_opt};
use serde_json::{Value, json};
use std::sync::Arc;

/// Cap on `getrawmempool` / address-history style listings.
const LIST_CAP: usize = 10_000;
/// The node's RPC surface.
pub struct NodeBackend {
    node: Node,
}

impl NodeBackend {
    /// Wrap a node for serving.
    pub fn new(node: Node) -> Self {
        Self { node }
    }

    /// Shared handle for `rpc::router`/`serve`.
    pub fn shared(self) -> Arc<dyn RpcBackend> {
        Arc::new(self)
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, NodeInner> {
        self.node.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Decode a Base58Check address to its P2PKH scriptPubKey bytes.
    fn address_script(&self, addr_s: &str) -> Result<Vec<u8>, RpcError> {
        let a = Address::from_base58(addr_s, Some(self.node.params.address_version))
            .map_err(|e| RpcError::InvalidParams(format!("bad address: {e}")))?;
        Ok(minibtc_script::Script::p2pkh(&a.hash160)
            .as_bytes()
            .to_vec())
    }

    /// Parse a txid-or-height block reference.
    fn block_ref(&self, inner: &NodeInner, s: &str) -> Result<Hash256, RpcError> {
        if let Ok(h) = s.parse::<u64>() {
            return core::block_at_height(inner, h as u32)
                .ok_or_else(|| RpcError::App(format!("no block at height {h}")));
        }
        Hash256::from_hex(s)
            .map_err(|_| RpcError::InvalidParams(format!("bad block hash {s}")))
            .and_then(|h| {
                if inner.chain.blocks.contains_key(&h) {
                    Ok(h)
                } else {
                    Err(RpcError::App(format!("block not found: {s}")))
                }
            })
    }

    /// Confirmations of `hash` on the active chain (0 if side/unknown).
    fn confirmations_of(inner: &NodeInner, hash: &Hash256) -> Option<u64> {
        if !matches!(
            inner.chain.blocks.get(hash).map(|r| &r.status),
            Some(minibtc_chainstate::BlockStatus::Active)
        ) {
            return Some(0);
        }
        let tip_h = inner.chain.height();
        // Walk active chain counting depth.
        let mut cur = inner.chain.tip;
        let mut h = tip_h;
        loop {
            if cur == *hash {
                return Some(u64::from(tip_h.saturating_sub(h)) + 1);
            }
            let rec = inner.chain.blocks.get(&cur)?;
            if h == 0 {
                return None;
            }
            cur = rec.block.header.prev_hash;
            h = h.saturating_sub(1);
        }
    }
}

impl RpcBackend for NodeBackend {
    fn methods(&self) -> &'static [&'static str] {
        NODE_METHODS
    }

    fn call(&self, method: &str, params: &[Value]) -> Result<Value, RpcError> {
        match method {
            "getblockchaininfo" => {
                let inner = self.inner();
                let tip_h = inner.chain.height();
                let money_sum = inner.money_supply();
                Ok(json!({
                    "chain": self.node.params.name,
                    "devnet": self.node.params.devnet,
                    "coinbase_maturity": self.node.params.coinbase_maturity,
                    "blocks": tip_h,
                    "headers": tip_h,
                    "bestblockhash": inner.chain.tip.to_hex(),
                    "difficulty": render::difficulty(
                        inner
                            .chain
                            .blocks
                            .get(&inner.chain.tip)
                            .map(|r| r.block.header.bits)
                            .unwrap_or(self.node.params.pow_limit_bits),
                        &self.node.params,
                    ),
                    "mediantime": inner.chain.median_time_past().unwrap_or(0),
                    "verificationprogress": 1.0,
                    "initialblockdownload": false,
                    "size_on_disk": 0,
                    "pruned": false,
                    "warnings": "",
                    "subversion": "/MiniBTC:0.1.0/",
                    "relayfee": render::money(Sats(inner.mempool.policy().min_relay_fee_rate)),
                    "errors": "",
                    "money_supply_sats": money_sum.sats(),
                    "sync_pending_blocks": inner.pending.len(),
                }))
            }

            "getblockcount" => Ok(json!(self.inner().chain.height())),

            "getblockhash" => {
                let h = param_u64(params, 0, "height")?;
                let inner = self.inner();
                core::block_at_height(&inner, h as u32)
                    .map(|bh| json!(bh.to_hex()))
                    .ok_or_else(|| RpcError::App(format!("height {h} out of range")))
            }

            "getbestblockhash" => Ok(json!(self.inner().chain.tip.to_hex())),

            "getblock" => {
                let r = param_str(params, 0, "blockhash")?;
                let verbosity = param_u64_opt(params, 1, 1)? as u8;
                let inner = self.inner();
                let bh = self.block_ref(&inner, r)?;
                let rec = inner
                    .chain
                    .blocks
                    .get(&bh)
                    .ok_or_else(|| RpcError::App("block not found".into()))?;
                let conf = Self::confirmations_of(&inner, &bh);
                Ok(render::block_json(
                    &rec.block,
                    &self.node.params,
                    Some(rec.height),
                    conf,
                    verbosity.min(2),
                ))
            }

            "getrawtransaction" => {
                let txid_s = param_str(params, 0, "txid")?;
                let verbose = param_u64_opt(params, 1, 0)? != 0;
                let txid = Hash256::from_hex(txid_s)
                    .map_err(|_| RpcError::InvalidParams("bad txid".into()))?;
                let inner = self.inner();
                let tx = core::find_tx(&self.node, &inner, &txid)
                    .ok_or_else(|| RpcError::App(format!("tx not found: {txid_s}")))?;
                let conf = core::tx_confirmations(&inner, &txid);
                if verbose {
                    let fee = core::tx_fee(&self.node, &inner, &tx).map(|f| f.sats());
                    Ok(render::tx_json(
                        &tx,
                        self.node.params.address_version,
                        fee,
                        conf,
                    ))
                } else {
                    Ok(json!(minibtc_crypto::hex_encode(&tx.encode())))
                }
            }

            "gettxout" => {
                let txid_s = param_str(params, 0, "txid")?;
                let vout = param_u64(params, 1, "vout")? as u32;
                let txid = Hash256::from_hex(txid_s)
                    .map_err(|_| RpcError::InvalidParams("bad txid".into()))?;
                let op = OutPoint { txid, vout };
                let inner = self.inner();
                match inner.chain.utxos.get(&op) {
                    Some(e) => {
                        let tip = inner.chain.height();
                        let c = u64::from(tip.saturating_sub(e.height)) + 1;
                        Ok(render::utxo_json(
                            &op,
                            e.output.value,
                            &e.output.script_pubkey,
                            e.height,
                            e.coinbase,
                            c,
                            self.node.params.address_version,
                        ))
                    }
                    None => Ok(Value::Null),
                }
            }

            "getaddressinfo" | "validateaddress" => {
                let addr_s = param_str(params, 0, "address")?;
                let script = self.address_script(addr_s)?;
                // Balance = sum of unspent outputs paying this script.
                // Scan the UTXO set (devnet scale; indexed in storage too).
                let inner = self.inner();
                let mut balance = Sats::ZERO;
                let mut txs_seen: std::collections::HashSet<Hash256> = Default::default();
                for (op, e) in inner.chain.utxos.iter() {
                    if e.output.script_pubkey == script {
                        balance = balance.checked_add(e.output.value).unwrap_or(balance);
                        txs_seen.insert(op.txid);
                    }
                }
                let _ = txs_seen;
                Ok(json!({
                    "address": addr_s,
                    "scriptPubKey": render::script_pubkey_json(&script, self.node.params.address_version),
                    "ismine": false,
                    "iswatchonly": false,
                    "isscript": false,
                    "isvalid": true,
                    "balance": render::money(balance),
                    "balance_sats": balance.sats(),
                }))
            }

            "getmempoolinfo" => {
                let inner = self.inner();
                let entries = inner.mempool.len();
                let bytes: usize = inner.mempool.by_fee_rate().iter().map(|e| e.size).sum();
                Ok(json!({
                    "size": entries,
                    "bytes": bytes,
                    "usage": bytes,
                    "maxmempool": inner.mempool.policy().max_size_bytes,
                    "mempoolminfee": render::money(Sats(inner.mempool.policy().min_relay_fee_rate)),
                    "minrelaytxfee": render::money(Sats(inner.mempool.policy().min_relay_fee_rate)),
                }))
            }

            "getrawmempool" => {
                let verbose = param_u64_opt(params, 0, 0)? != 0;
                let inner = self.inner();
                let txs = inner.mempool.by_fee_rate();
                if verbose {
                    let mut out = serde_json::Map::new();
                    for e in txs.iter().take(LIST_CAP) {
                        let fee = e.fee.sats();
                        out.insert(
                            e.txid.to_hex(),
                            render::tx_json(
                                &e.tx,
                                self.node.params.address_version,
                                Some(fee),
                                None,
                            ),
                        );
                    }
                    Ok(Value::Object(out))
                } else {
                    Ok(Value::Array(
                        txs.iter()
                            .take(LIST_CAP)
                            .map(|e| json!(e.txid.to_hex()))
                            .collect(),
                    ))
                }
            }

            "getpeerinfo" => {
                let inner = self.inner();
                let peers: Vec<Value> = inner
                    .peers
                    .snapshot()
                    .into_iter()
                    .map(|(addr, p)| {
                        json!({
                            "id": addr.to_string(),
                            "addr": addr.to_string(),
                            "services": format!("0x{:016x}", p.services),
                            "subver": p.user_agent,
                            "startingheight": p.start_height,
                            "synced_headers": inner.chain.height(),
                            "synced_blocks": inner.chain.height(),
                            "inbound": !p.outbound,
                            "bip152_hb_from": false,
                            "bip152_hb_to": false,
                            "addr_relay_enabled": true,
                            "permissions": [],
                            "minfeefilter": 0.0,
                            "bytessent": 0,
                            "bytesrecv": 0,
                            "conntime": p.connected_at.elapsed().as_secs(),
                            "timeoffset": 0,
                            "pingtime": 0.0,
                            "minping": 0.0,
                            "version": p.version,
                        })
                    })
                    .collect();
                Ok(Value::Array(peers))
            }

            "banpeer" => {
                let ip_s = param_str(params, 0, "ip")?;
                let ip: std::net::IpAddr = ip_s
                    .parse()
                    .map_err(|_| RpcError::InvalidParams("bad ip".into()))?;
                let mut inner = self.inner();
                inner.peers.ban(ip);
                // Also drop any live session from that IP.
                let addrs: Vec<std::net::SocketAddr> = inner
                    .peers
                    .snapshot()
                    .into_iter()
                    .map(|(a, _)| a)
                    .filter(|a| a.ip() == ip)
                    .collect();
                drop(inner);
                for a in addrs {
                    self.node.peer_tx.lock().ok().map(|mut m| m.remove(&a));
                }
                Ok(json!({ "banned": ip_s }))
            }

            "getnetworkinfo" => {
                let inner = self.inner();
                Ok(json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "subversion": "/MiniBTC:0.1.0/",
                    "protocolversion": crate::net::PROTOCOL_VERSION,
                    "localservices": "0x0",
                    "localrelay": true,
                    "time": core::now_secs(),
                    "networkactive": true,
                    "connections": inner.peers.len(),
                    "networks": [],
                    "relayfee": 0.0,
                    "incrementalfee": 0.0,
                    "localaddresses": [],
                }))
            }

            "getaddressutxos" => {
                let addr_s = param_str(params, 0, "address")?;
                let script = self.address_script(addr_s)?;
                let inner = self.inner();
                let tip = inner.chain.height();
                let mut out = Vec::new();
                for (op, e) in inner.chain.utxos.iter() {
                    if e.output.script_pubkey == script {
                        out.push(render::utxo_json(
                            op,
                            e.output.value,
                            &e.output.script_pubkey,
                            e.height,
                            e.coinbase,
                            u64::from(tip.saturating_sub(e.height)) + 1,
                            self.node.params.address_version,
                        ));
                    }
                }
                Ok(Value::Array(out))
            }

            "getaddresshistory" => {
                // Every output ever paid to this address: received
                // history with spent/unspent flags. Uses the storage
                // address index when available, else scans blocks.
                let addr_s = param_str(params, 0, "address")?;
                let script = self.address_script(addr_s)?;
                let inner = self.inner();
                let tip = inner.chain.height();
                let mut ops: Vec<OutPoint> = Vec::new();
                let mut indexed = false;
                if let Some(store) = &self.node.store
                    && let Ok(v) = store.addr_outpoints(&script)
                {
                    ops = v;
                    indexed = true;
                }
                if !indexed {
                    for rec in inner.chain.blocks.values() {
                        for t in &rec.block.txs {
                            for (i, o) in t.outputs.iter().enumerate() {
                                if o.script_pubkey == script {
                                    ops.push(OutPoint {
                                        txid: t.txid(),
                                        vout: i as u32,
                                    });
                                }
                            }
                        }
                    }
                }
                let mut seen = std::collections::HashSet::new();
                let mut out = Vec::new();
                for op in ops {
                    if !seen.insert(op) {
                        continue;
                    }
                    let Some(tx) = core::find_tx(&self.node, &inner, &op.txid) else {
                        continue;
                    };
                    let Some(o) = tx.outputs.get(op.vout as usize) else {
                        continue;
                    };
                    // Block height via txindex → block record.
                    let (bh, h) = inner
                        .txindex
                        .get(&op.txid)
                        .and_then(|bh| inner.chain.blocks.get(bh).map(|r| (*bh, r.height)))
                        .unwrap_or((op.txid, 0));
                    let _ = bh;
                    let spent = inner.chain.utxos.get(&op).is_none();
                    out.push(json!({
                        "txid": op.txid.to_hex(),
                        "vout": op.vout,
                        "value_sats": o.value.sats(),
                        "height": h,
                        "confirmations": u64::from(tip.saturating_sub(h)) + 1,
                        "spent": spent,
                    }));
                }
                // Newest first.
                out.sort_by(|a, b| b["height"].as_u64().cmp(&a["height"].as_u64()));
                Ok(json!({
                    "address": addr_s,
                    "indexed": indexed,
                    "count": out.len(),
                    "outputs": out,
                }))
            }

            "scantxoutset" => {
                // Full UTXO dump for wallet scanning — devnet scale,
                // hard-capped so a hostile/buggy caller can't OOM us.
                let inner = self.inner();
                let tip = inner.chain.height();
                let mut out = Vec::new();
                for (op, e) in inner.chain.utxos.iter() {
                    if out.len() >= 1_000_000 {
                        break;
                    }
                    out.push(json!({
                        "txid": op.txid.to_hex(),
                        "vout": op.vout,
                        "value": e.output.value.sats(),
                        "scriptPubKey": minibtc_crypto::hex_encode(&e.output.script_pubkey),
                        "height": e.height,
                        "coinbase": e.coinbase,
                        "confirmations": u64::from(tip.saturating_sub(e.height)) + 1,
                    }));
                }
                Ok(json!({
                    "chain": self.node.params.name,
                    "devnet": self.node.params.devnet,
                    "coinbase_maturity": self.node.params.coinbase_maturity,
                    "tip_height": tip,
                    "count": out.len(),
                    "utxos": out,
                }))
            }

            "sendrawtransaction" => {
                let hex_tx = param_str(params, 0, "hex_tx")?;
                if hex_tx.len() > 4 * 1024 * 1024 {
                    return Err(RpcError::InvalidParams("tx hex too large".into()));
                }
                let raw = hex_decode(hex_tx)
                    .map_err(|e| RpcError::InvalidParams(format!("bad hex: {e}")))?;
                let tx = Transaction::decode(&raw)
                    .map_err(|e| RpcError::InvalidParams(format!("bad tx: {e}")))?;
                match self.node.accept_tx(tx, None, None) {
                    Ok(txid) => Ok(json!(txid.to_hex())),
                    Err(crate::core::AcceptError::Invalid(e)) => {
                        Err(RpcError::App(format!("tx rejected: {e}")))
                    }
                    Err(crate::core::AcceptError::Policy(e)) => {
                        Err(RpcError::App(format!("tx rejected: {e}")))
                    }
                }
            }

            "generatetoaddress" => {
                if !self.node.params.devnet {
                    return Err(RpcError::App("generatetoaddress is devnet-only".into()));
                }
                let n = param_u64(params, 0, "nblocks")?;
                let addr = param_str(params, 1, "address")?;
                if n > 10_000 {
                    return Err(RpcError::InvalidParams("nblocks too large".into()));
                }
                let script = self.address_script(addr)?;
                let hashes = self
                    .node
                    .generate(n, &script)
                    .map_err(|e| RpcError::App(format!("generate failed: {e}")))?;
                Ok(Value::Array(
                    hashes.iter().map(|h| json!(h.to_hex())).collect(),
                ))
            }

            other => Err(RpcError::MethodNotFound(other.to_string())),
        }
    }
}
