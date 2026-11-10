//! Render chain objects (blocks, transactions, UTXOs) as JSON-RPC
//! result payloads. Hashes display in internal byte order (our canonical
//! hex); amounts are integer sats plus an 8-decimal string — never floats.

use minibtc_consensus::{ChainParams, pow};
use minibtc_crypto::{Address, Hash160, Hash256};
use minibtc_primitives::{Block, BlockHeader, OutPoint, Sats, Transaction, TxOutput};
use serde_json::{Value, json};

/// Sats → `{ "sats": n, "amount": "x.yyyyyyyy" }` (8 decimals, BTC-style).
pub fn money(sats: Sats) -> Value {
    let v = sats.sats();
    json!({
        "sats": v,
        "amount": format!("{}.{:08}", v / 100_000_000, v % 100_000_000),
    })
}

/// Classify a scriptPubKey.
pub fn script_type(script: &[u8]) -> &'static str {
    // P2PKH: OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        return "pubkeyhash";
    }
    // P2PK: <33B|65B pubkey> OP_CHECKSIG
    if (script.len() == 35 && script[0] == 0x21 && script[33] == 0xac)
        || (script.len() == 67 && script[0] == 0x41 && script[65] == 0xac)
    {
        return "pubkey";
    }
    "nonstandard"
}

/// scriptSig → JSON.
pub fn script_sig_json(script: &[u8]) -> Value {
    json!({ "hex": hex::encode(script) })
}

/// scriptPubKey → JSON `{hex, type, addresses?, reqSigs?}`.
pub fn script_pubkey_json(script: &[u8], address_version: u8) -> Value {
    let mut v = json!({
        "hex": hex::encode(script),
        "type": script_type(script),
    });
    if script_type(script) == "pubkeyhash" && script.len() == 25 {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[3..23]);
        let addr = Address::p2pkh(address_version, Hash160(h));
        v["addresses"] = json!([addr.to_base58()]);
        v["reqSigs"] = json!(1);
    }
    v
}

/// Transaction input → JSON.
pub fn txin_json(tx: &Transaction, idx: usize) -> Value {
    let inp = &tx.inputs[idx];
    let is_coinbase = idx == 0 && inp.prev.txid == Hash256::ZERO;
    json!({
        "txid": inp.prev.txid.to_hex(),
        "vout": inp.prev.vout,
        "scriptSig": script_sig_json(&inp.script_sig),
        "sequence": inp.sequence,
        "coinbase": is_coinbase,
    })
}

/// Transaction output → JSON.
pub fn txout_json(out: &TxOutput, n: usize, address_version: u8) -> Value {
    json!({
        "value": money(out.value),
        "n": n,
        "scriptPubKey": script_pubkey_json(&out.script_pubkey, address_version),
    })
}

/// Full decoded transaction JSON.
/// `fee`/`confirmations` filled by the caller when known.
pub fn tx_json(
    tx: &Transaction,
    address_version: u8,
    fee_sats: Option<u64>,
    confirmations: Option<u64>,
) -> Value {
    let txid = tx.txid();
    let size = tx.encode().len();
    let mut v = json!({
        "txid": txid.to_hex(),
        "version": tx.version,
        "locktime": tx.locktime,
        "size": size,
        "vin": tx
            .inputs
            .iter()
            .enumerate()
            .map(|(i, _)| txin_json(tx, i))
            .collect::<Vec<_>>(),
        "vout": tx
            .outputs
            .iter()
            .enumerate()
            .map(|(i, o)| txout_json(o, i, address_version))
            .collect::<Vec<_>>(),
    });
    if let Some(f) = fee_sats {
        v["fee"] = money(Sats(f));
    }
    if let Some(c) = confirmations {
        v["confirmations"] = json!(c);
    }
    v
}

/// Serialized transaction hex.
pub fn tx_hex(tx: &Transaction) -> String {
    hex::encode(tx.encode())
}

/// bits → relative difficulty vs `params.pow_limit_bits` (display only).
pub fn difficulty(bits: u32, params: &ChainParams) -> f64 {
    let wt = pow::work_units(bits).unwrap_or(0);
    let wl = pow::work_units(params.pow_limit_bits).unwrap_or(0);
    if wt == 0 {
        return 0.0;
    }
    wl as f64 / wt as f64
}

/// Block header → JSON fields.
pub fn header_json(h: &BlockHeader, params: &ChainParams) -> Value {
    json!({
        "hash": h.block_hash().to_hex(),
        "version": h.version,
        "previousblockhash": h.prev_hash.to_hex(),
        "merkleroot": h.merkle_root.to_hex(),
        "time": h.time,
        "bits": format!("{:08x}", h.bits),
        "nonce": h.nonce,
        "difficulty": difficulty(h.bits, params),
    })
}

/// Block → JSON. `verbosity`: 0 = serialized hex, ≥1 = decoded txs.
pub fn block_json(
    block: &Block,
    params: &ChainParams,
    height: Option<u32>,
    confirmations: Option<u64>,
    verbosity: u8,
) -> Value {
    let size = block.encode().len();
    let mut v = header_json(&block.header, params);
    v["size"] = json!(size);
    v["txcount"] = json!(block.txs.len());
    if let Some(h) = height {
        v["height"] = json!(h);
    }
    if let Some(c) = confirmations {
        v["confirmations"] = json!(c);
    }
    if verbosity == 0 {
        v["hex"] = json!(hex::encode(block.encode()));
    } else {
        v["tx"] = Value::Array(
            block
                .txs
                .iter()
                .map(|t| tx_json(t, params.address_version, None, confirmations))
                .collect(),
        );
    }
    v
}

/// UTXO entry → JSON for gettxout.
pub fn utxo_json(
    op: &OutPoint,
    value: Sats,
    script: &[u8],
    height: u32,
    coinbase: bool,
    confirmations: u64,
    address_version: u8,
) -> Value {
    json!({
        "txid": op.txid.to_hex(),
        "vout": op.vout,
        "value": money(value),
        "scriptPubKey": script_pubkey_json(script, address_version),
        "height": height,
        "coinbase": coinbase,
        "confirmations": confirmations,
    })
}

/// Outpoint → JSON.
pub fn outpoint_json(op: &OutPoint) -> Value {
    json!({ "txid": op.txid.to_hex(), "vout": op.vout })
}
