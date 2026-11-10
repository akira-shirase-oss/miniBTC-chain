//! Million-op load evidence runner.
//!
//! Every scenario executes ≥1,000,000 operations (or requests for the
//! RPC scenario) and writes a JSON report to `perf/results/` carrying
//! the machine spec, git commit, per-scenario throughput and the
//! threshold verdict. Thresholds are conservative dev-machine floors —
//! a miss is a failure, never hidden by a rerun.

use anyhow::{Context, Result};
use clap::Parser;
use minibtc_consensus::ChainParams;
use minibtc_crypto::{Hash256, Keypair};
use minibtc_mempool::{Mempool, MempoolPolicy};
use minibtc_p2p::codec::{self, Message};
use minibtc_primitives::*;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(name = "minibtc-load", about = "Million-op load evidence for MiniBTC")]
struct Args {
    /// Scenario to run: all|codec|script|mempool|wire|rpc|chain.
    #[arg(default_value = "all")]
    scenario: String,

    /// Operations per scenario (default 1,000,000).
    #[arg(long, default_value_t = 1_000_000usize)]
    ops: usize,

    /// Node datadir for the rpc scenario (reads .cookie).
    #[arg(long, default_value = "data")]
    datadir: PathBuf,

    /// RPC port for the rpc scenario.
    #[arg(long, default_value_t = 18446)]
    rpc_port: u16,

    /// Output directory for the JSON report.
    #[arg(long, default_value = "perf/results")]
    outdir: PathBuf,
}

struct Report {
    machine: Value,
    commit: String,
    ops_per_scenario: usize,
    results: Vec<ScenarioResult>,
}

struct ScenarioResult {
    name: &'static str,
    unit: &'static str,
    ops: usize,
    seconds: f64,
    ops_per_sec: f64,
    threshold_ops_per_sec: f64,
    pass: bool,
    detail: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let commit = git_commit();
    let machine = machine_spec();
    let mut results = Vec::new();

    let want = |name: &str| args.scenario == "all" || args.scenario == name;

    if want("codec") {
        results.push(run_codec(args.ops));
    }
    if want("wire") {
        results.push(run_wire(args.ops));
    }
    if want("script") {
        results.push(run_script(args.ops));
    }
    if want("mempool") {
        results.push(run_mempool(args.ops));
    }
    if want("chain") {
        results.push(run_chain(args.ops));
    }
    if want("rpc") {
        results.push(run_rpc(&args).await?);
    }

    let report = Report {
        machine,
        commit,
        ops_per_scenario: args.ops,
        results,
    };
    write_report(&args.outdir, &report)?;
    let all_pass = report.results.iter().all(|r| r.pass);
    for r in &report.results {
        println!(
            "{:>10} {:>12} ops  {:>10.0} ops/s  threshold {:>8.0}  {}",
            r.name,
            r.ops,
            r.ops_per_sec,
            r.threshold_ops_per_sec,
            if r.pass { "PASS" } else { "FAIL" }
        );
    }
    anyhow::ensure!(all_pass, "one or more load thresholds missed");
    Ok(())
}

// ---------- scenarios ----------

fn run_codec(ops: usize) -> ScenarioResult {
    let t0 = Instant::now();
    let mut acc = 0u64;
    // Mix: tx encode+decode roundtrips + merkle roots over tx sets.
    let tx = sample_tx();
    let enc = tx.encode();
    for i in 0..ops {
        let dec = Transaction::decode(&enc).expect("codec roundtrip");
        acc = acc.wrapping_add(dec.txid().0[0] as u64);
        acc = acc.wrapping_add(dec.encode().len() as u64);
        if i % 64 == 0 {
            let root = merkle_root(&[tx.clone(), dec.clone()]);
            acc = acc.wrapping_add(root.0[0] as u64);
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    finish("codec", "ops", ops, secs, 150_000.0, format!("acc={acc}"))
}

fn run_wire(ops: usize) -> ScenarioResult {
    let params = ChainParams::devnet();
    let t0 = Instant::now();
    let msgs = [
        Message::Ping(1),
        Message::Verack,
        Message::GetHeaders {
            locator: vec![Hash256::ZERO],
            stop: Hash256::ZERO,
        },
        Message::Inv(vec![codec::InvItem {
            kind: codec::InvType::Tx,
            hash: Hash256::ZERO,
        }]),
    ];
    let mut acc = 0usize;
    for i in 0..ops {
        let m = &msgs[i % msgs.len()];
        let payload = codec::encode_payload(m, &params);
        let name = codec::command_name(m);
        if let Ok(back) = codec::decode_payload(name, &payload) {
            acc = acc.wrapping_add(codec::encode_payload(&back, &params).len());
        }
        // Also frame it — bounded wire image.
        let _frame = codec::frame(m, &params);
    }
    let secs = t0.elapsed().as_secs_f64();
    finish("wire", "ops", ops, secs, 200_000.0, format!("acc={acc}"))
}

fn run_script(ops: usize) -> ScenarioResult {
    // Real P2PKH spend verification — the hot consensus path.
    let key = Keypair::generate().unwrap();
    let dest = Keypair::generate().unwrap();
    let prev_spk = minibtc_script::Script::p2pkh(&key.public_key().key_hash()).0;
    let prev_op = OutPoint {
        txid: Hash256::from_hex(&"ab".repeat(32)).unwrap(),
        vout: 0,
    };
    let mut tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: prev_op,
            script_sig: vec![],
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput {
            value: Sats(40_000),
            script_pubkey: minibtc_script::Script::p2pkh(&dest.public_key().key_hash()).0,
        }],
        locktime: 0,
    };
    let sig = minibtc_script::sighash::sign_input(&tx, 0, &prev_spk, &key).unwrap();
    tx.inputs[0].script_sig = minibtc_script::Script::p2pkh_spend(&sig, &key.public_key()).0;
    let ss = tx.inputs[0].script_sig.clone();

    let t0 = Instant::now();
    let mut ok = 0usize;
    let ctx_tx = tx.clone();
    for _ in 0..ops {
        if minibtc_script::sighash::verify_input_scripts(&ctx_tx, 0, &ss, &prev_spk) {
            ok += 1;
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    assert_eq!(ok, ops, "every script verification must pass");
    finish(
        "script",
        "verifies",
        ops,
        secs,
        5_000.0,
        "all p2pkh verifies passed".into(),
    )
}

fn run_mempool(ops: usize) -> ScenarioResult {
    let params = ChainParams::devnet();
    let policy = MempoolPolicy {
        max_size_bytes: 8_000,
        max_entries: 2_000,
        ..Default::default()
    };
    let max_entries = policy.max_entries;
    let max_size = policy.max_size_bytes;
    let mut pool = Mempool::new(policy);
    let view = NoView;
    let t0 = Instant::now();
    let mut admitted = 0usize;
    let mut evicted_or_rejected = 0usize;
    for i in 0..ops {
        let op = OutPoint {
            txid: Hash256::from_hex(&format!("{:064x}", i as u64 % 50_000 + 1)).unwrap(),
            vout: (i % 3) as u32,
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
        // Vary fee so eviction has an order to enforce; wrap input space
        // so conflicts occasionally force rejects too.
        let fee = Sats(500 + (i as u64 % 4_000));
        match pool.admit(tx, fee, &view, &params, None) {
            Ok(_) => admitted += 1,
            Err(_) => evicted_or_rejected += 1,
        }
        // Boundedness must hold after EVERY op.
        debug_assert!(pool.total_size() <= max_size);
        debug_assert!(pool.len() <= max_entries);
    }
    let secs = t0.elapsed().as_secs_f64();
    finish(
        "mempool",
        "admits",
        ops,
        secs,
        50_000.0,
        format!(
            "admitted={admitted} rejected={evicted_or_rejected} final_len={}",
            pool.len()
        ),
    )
}

fn run_chain(ops: usize) -> ScenarioResult {
    // UTXO-set + merkle + money validation throughput — the consensus
    // hot path minus PoW grinding.
    let params = ChainParams::devnet();
    let view = RichView::new(&params);
    let t0 = Instant::now();
    let mut ok = 0usize;
    for i in 0..ops {
        let tx = spend_tx(i);
        if minibtc_consensus::validate_tx(&tx, &view, &params).is_ok() {
            ok += 1;
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    finish(
        "chain",
        "validations",
        ops,
        secs,
        20_000.0,
        format!("valid={ok}"),
    )
}

async fn run_rpc(args: &Args) -> Result<ScenarioResult> {
    let client = minibtc_rpc::client::RpcClient::from_datadir(&args.datadir, args.rpc_port)
        .context("rpc client from datadir")?;
    // Warmup + sanity.
    let info = client.getblockchaininfo().await?;
    let tip = info["bestblockhash"].as_str().unwrap_or("").to_string();
    anyhow::ensure!(!tip.is_empty(), "node not reachable / empty tip");

    let ops = args.ops;
    let t0 = Instant::now();
    // Mix of read methods across `ops` total requests, sequential per
    // worker but concurrent across workers (real HTTP keep-alive).
    let workers = 8usize;
    let per = ops / workers;
    let mut handles = Vec::new();
    for _w in 0..workers {
        let c = client.clone();
        let tip = tip.clone();
        handles.push(tokio::spawn(async move {
            let mut n = 0usize;
            for i in 0..per {
                let r = match i % 4 {
                    0 => c.getblockchaininfo().await.map(|_| ()),
                    1 => c.getblock(&tip, 1).await.map(|_| ()),
                    2 => c.getrawmempool(false).await.map(|_| ()),
                    _ => c.getpeerinfo().await.map(|_| ()),
                };
                if r.is_ok() {
                    n += 1;
                }
            }
            n
        }));
    }
    let mut ok = 0usize;
    for h in handles {
        ok += h.await.unwrap_or(0);
    }
    let secs = t0.elapsed().as_secs_f64();
    Ok(finish(
        "rpc",
        "requests",
        ops,
        secs,
        200.0,
        format!("ok={ok}/{ops} tip={}", &tip[..12.min(tip.len())]),
    ))
}

// ---------- helpers ----------

fn finish(
    name: &'static str,
    unit: &'static str,
    ops: usize,
    secs: f64,
    threshold: f64,
    detail: String,
) -> ScenarioResult {
    let ops_per_sec = ops as f64 / secs.max(1e-9);
    ScenarioResult {
        name,
        unit,
        ops,
        seconds: secs,
        ops_per_sec,
        threshold_ops_per_sec: threshold,
        pass: ops_per_sec >= threshold,
        detail,
    }
}

fn sample_tx() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: OutPoint {
                txid: Hash256::from_hex(&"11".repeat(32)).unwrap(),
                vout: 0,
            },
            script_sig: vec![0x47, 0x30, 0x44, 0x02, 0x20],
            sequence: 0xffff_ffff,
        }],
        outputs: vec![
            TxOutput {
                value: Sats(50_000),
                script_pubkey: vec![
                    0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                    0x88, 0xac,
                ],
            },
            TxOutput {
                value: Sats(49_000),
                script_pubkey: vec![0x51],
            },
        ],
        locktime: 0,
    }
}

fn spend_tx(i: usize) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: OutPoint {
                txid: Hash256::from_hex(&format!("{:064x}", i as u64 % 512 + 1)).unwrap(),
                vout: 0,
            },
            script_sig: vec![0x51],
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput {
            value: Sats(90_000),
            script_pubkey: vec![0x51],
        }],
        locktime: 0,
    }
}

struct NoView;
impl minibtc_consensus::UtxoView for NoView {
    fn get(&self, _op: &OutPoint) -> Option<TxOutput> {
        None
    }
}

/// UTXO view preloaded with the spend_tx input space — every tx spends
/// a distinct-ish prevout worth 100k sats so validation is real work.
struct RichView {
    map: std::collections::HashMap<OutPoint, TxOutput>,
}

impl RichView {
    fn new(_params: &ChainParams) -> Self {
        let mut map = std::collections::HashMap::with_capacity(512);
        for i in 0..512u64 {
            let op = OutPoint {
                txid: Hash256::from_hex(&format!("{:064x}", i + 1)).unwrap(),
                vout: 0,
            };
            map.insert(
                op,
                TxOutput {
                    value: Sats(100_000),
                    script_pubkey: vec![0x51],
                },
            );
        }
        Self { map }
    }
}

impl minibtc_consensus::UtxoView for RichView {
    fn get(&self, op: &OutPoint) -> Option<TxOutput> {
        self.map.get(op).cloned()
    }
}

// ---------- report ----------

fn git_commit() -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn machine_spec() -> Value {
    let chip = Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let mem_gb = Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|b| b / (1024 * 1024 * 1024))
        .unwrap_or(0);
    let os = Command::new("sw_vers")
        .args(["-productVersion"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    json!({
        "chip": chip,
        "memory_gb": mem_gb,
        "os": os,
        "note": "laptop dev numbers — not production capacity",
    })
}

fn write_report(outdir: &PathBuf, report: &Report) -> Result<PathBuf> {
    std::fs::create_dir_all(outdir)?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let path = outdir.join(format!("load-{stamp}.json"));
    let doc = json!({
        "generated_unix": stamp,
        "machine": report.machine,
        "commit": report.commit,
        "ops_per_scenario": report.ops_per_scenario,
        "scenarios": report.results.iter().map(|r| json!({
            "name": r.name,
            "unit": r.unit,
            "ops": r.ops,
            "seconds": r.seconds,
            "ops_per_sec": r.ops_per_sec,
            "threshold_ops_per_sec": r.threshold_ops_per_sec,
            "pass": r.pass,
            "detail": r.detail,
        })).collect::<Vec<_>>(),
        "all_pass": report.results.iter().all(|r| r.pass),
    });
    std::fs::write(&path, serde_json::to_string_pretty(&doc)?)?;
    println!("report: {}", path.display());
    Ok(path)
}
