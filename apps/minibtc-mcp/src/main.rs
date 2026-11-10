//! minibtc-mcp — Model Context Protocol server for MiniBTC.
//!
//! Lets AI assistants inspect the chain and *draft* payments through the
//! node's public JSON-RPC API. Hard rules from the blueprint:
//!
//! - Never holds seeds, private keys, or wallet files. Wallet signing
//!   happens inside `minibtc-cli` subprocesses; this process only ever
//!   sees the public RPC surface and signed-transaction hex in drafts.
//! - Every spend needs explicit human approval *outside* the model:
//!   `request_send` refuses until a human runs
//!   `minibtc-mcp --confirm <draft-id>` in their own terminal, which
//!   writes an approval token the tool then verifies.
//! - Per-request and per-day spend caps, configurable.
//! - Every call — tool, resource, prompt — is appended to an audit log.
//!
//! Transport: stdio (the standard for local MCP clients).

mod mcp;

use anyhow::{Context, Result};
use clap::Parser;
use minibtc_rpc::client::RpcClient;
use rmcp::ServiceExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default per-request spend cap: 10 BTC in sats.
const DEFAULT_MAX_SPEND_SATS: u64 = 1_000_000_000;
/// Default per-day spend cap: 100 BTC in sats.
const DEFAULT_MAX_DAILY_SATS: u64 = 10_000_000_000;
/// Drafts expire after 15 minutes — a stale signed tx must not linger.
const DRAFT_TTL_SECS: u64 = 15 * 60;
/// Path to the minibtc-cli binary used for wallet draft signing.
const DEFAULT_CLI: &str = "minibtc-cli";
/// Fallback devnet coinbase address (any valid devnet P2PKH works).
const DEFAULT_MINER_ADDRESS: &str = "mqmLVoDnuDpSH4FyWn8enX3ksHVEDGX4Ke";

/// MiniBTC MCP server — inspect the chain, draft payments, never spend
/// without human approval.
#[derive(Parser, Debug)]
#[command(name = "minibtc-mcp", version, about)]
struct Args {
    /// Node datadir (holds .cookie and the MCP draft/audit state).
    #[arg(long, default_value = "data")]
    datadir: PathBuf,

    /// Node RPC port (cookie read from datadir).
    #[arg(long, default_value_t = 18446)]
    rpc_port: u16,

    /// Optional chain-params JSON matching the node's (default: devnet).
    #[arg(long)]
    params: Option<PathBuf>,

    /// Path to the minibtc-cli binary (wallet drafting subprocess).
    #[arg(long, default_value = DEFAULT_CLI)]
    cli: String,

    /// Per-request spend cap in sats.
    #[arg(long, default_value_t = DEFAULT_MAX_SPEND_SATS)]
    max_spend_sats: u64,

    /// Per-day spend cap in sats.
    #[arg(long, default_value_t = DEFAULT_MAX_DAILY_SATS)]
    max_daily_sats: u64,

    /// Default address for mine_blocks coinbase (devnet only).
    #[arg(long, default_value = DEFAULT_MINER_ADDRESS)]
    miner_address: String,

    /// One-shot: approve a pending payment draft, then exit.
    /// This is the human-in-the-loop gate — run it yourself, outside
    /// the AI conversation.
    #[arg(long)]
    confirm: Option<String>,

    /// One-shot: list pending payment drafts, then exit.
    #[arg(long)]
    list_drafts: bool,

    /// One-shot: revoke a pending draft, then exit.
    #[arg(long)]
    revoke: Option<String>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append one JSON line to the audit log. Never logs secrets: callers
/// pass only tool names and sanitized argument summaries.
fn audit(datadir: &Path, entry: &Value) -> Result<()> {
    let path = datadir.join("mcp-audit.jsonl");
    let mut line = serde_json::to_string(entry)?;
    line.push('\n');
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open audit log {}", path.display()))?;
    // Restrict audit log to owner-only like the cookie.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(line.as_bytes())?;
    Ok(())
}

// ---------- draft store ----------

/// A signed-but-unbroadcast payment draft. `hex` is spend authority
/// until expiry — stored owner-only, never logged, never returned by
/// any tool except the gated send path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Draft {
    pub id: String,
    pub wallet: String,
    pub to_address: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub fee_rate: u64,
    pub txid: String,
    pub hex: String,
    pub inputs: usize,
    pub outputs: Vec<Value>,
    pub created_unix: u64,
    pub expires_unix: u64,
}

impl Draft {
    fn path(dir: &Path, id: &str) -> PathBuf {
        dir.join(format!("{id}.json"))
    }

    fn approved_path(dir: &Path, id: &str) -> PathBuf {
        dir.join(format!("{id}.approved"))
    }

    fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let path = Self::path(dir, &self.id);
        let bytes = serde_json::to_vec_pretty(self)?;
        std::fs::write(&path, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn load(dir: &Path, id: &str) -> Result<Self> {
        let path = Self::path(dir, id);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("no such draft {id} (expired or never created?)"))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn list(dir: &Path) -> Vec<Draft> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(dir) else {
            return out;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&p)
                && let Ok(d) = serde_json::from_slice::<Draft>(&bytes)
            {
                out.push(d);
            }
        }
        out.sort_by_key(|d| d.created_unix);
        out
    }

    /// An approval token exists AND was minted for exactly this draft
    /// content (sha256 of the canonical draft JSON).
    fn is_approved(&self, dir: &Path) -> bool {
        let Ok(bytes) = std::fs::read(Self::approved_path(dir, &self.id)) else {
            return false;
        };
        let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
            return false;
        };
        let Some(expected) = v["draft_sha256"].as_str() else {
            return false;
        };
        expected == self.content_hash()
    }

    /// sha256 over the fields that define the payment (excludes id and
    /// timestamps, which are bookkeeping).
    pub fn content_hash(&self) -> String {
        let canon = json!({
            "wallet": self.wallet,
            "to_address": self.to_address,
            "amount_sats": self.amount_sats,
            "fee_sats": self.fee_sats,
            "txid": self.txid,
            "hex": self.hex,
        });
        minibtc_crypto::double_sha256(&serde_json::to_vec(&canon).unwrap_or_default()).to_hex()
    }

    fn approve(&self, dir: &Path) -> Result<()> {
        let path = Self::approved_path(dir, &self.id);
        let v = json!({
            "draft_sha256": self.content_hash(),
            "approved_unix": unix_now(),
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&v)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn revoke(&self, dir: &Path) -> Result<()> {
        let _ = std::fs::remove_file(Self::path(dir, &self.id));
        let _ = std::fs::remove_file(Self::approved_path(dir, &self.id));
        Ok(())
    }
}

// ---------- daily spend tracker ----------

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SpendDay {
    /// YYYY-MM-DD (UTC, derived from unix time — no chrono dep).
    day: String,
    total_sats: u64,
}

fn ymd(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}")
}

fn spend_path(datadir: &Path) -> PathBuf {
    datadir.join("mcp-spend.json")
}

fn daily_spent(datadir: &Path) -> u64 {
    let Ok(bytes) = std::fs::read(spend_path(datadir)) else {
        return 0;
    };
    let Ok(v) = serde_json::from_slice::<SpendDay>(&bytes) else {
        return 0;
    };
    if v.day == ymd(unix_now()) {
        v.total_sats
    } else {
        0
    }
}

fn record_spend(datadir: &Path, sats: u64) -> Result<()> {
    let mut v = SpendDay {
        day: ymd(unix_now()),
        total_sats: daily_spent(datadir),
    };
    v.total_sats = v.total_sats.saturating_add(sats);
    std::fs::write(spend_path(datadir), serde_json::to_vec_pretty(&v)?)?;
    Ok(())
}

// ---------- shared server state ----------

/// Everything the MCP handler needs. `Arc` because rmcp requires
/// `Send + Sync + 'static`.
#[derive(Debug)]
pub struct Shared {
    pub rpc: RpcClient,
    pub rpc_port: u16,
    pub datadir: PathBuf,
    pub params: minibtc_consensus::ChainParams,
    pub cli: String,
    pub max_spend_sats: u64,
    pub max_daily_sats: u64,
    pub miner_address: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("warn")
        .with_target(false)
        .init();
    let args = Args::parse();
    let drafts_dir = args.datadir.join("mcp").join("drafts");

    // ---- one-shot human-gate commands (outside any MCP session) ----
    if let Some(id) = &args.confirm {
        let d = Draft::load(&drafts_dir, id)?;
        if d.expires_unix < unix_now() {
            anyhow::bail!("draft {id} expired ({}s TTL)", DRAFT_TTL_SECS);
        }
        d.approve(&drafts_dir)?;
        println!(
            "approved draft {} — pay {} sats to {} (txid {}, fee {} sats). \
             The model may now call request_send once; the spend caps still apply.",
            d.id, d.amount_sats, d.to_address, d.txid, d.fee_sats
        );
        audit(
            &args.datadir,
            &json!({"ts": unix_now(), "kind": "gate", "name": "confirm",
                    "ok": true, "detail": {"draft_id": id, "amount_sats": d.amount_sats}}),
        )?;
        return Ok(());
    }
    if args.list_drafts {
        for d in Draft::list(&drafts_dir) {
            let state = if d.is_approved(&drafts_dir) {
                "APPROVED"
            } else if d.expires_unix < unix_now() {
                "expired"
            } else {
                "pending"
            };
            println!(
                "{} [{}] {} sats -> {} (fee {} sats, txid {})",
                d.id, state, d.amount_sats, d.to_address, d.fee_sats, d.txid
            );
        }
        return Ok(());
    }
    if let Some(id) = &args.revoke {
        Draft::load(&drafts_dir, id)?.revoke(&drafts_dir)?;
        println!("revoked draft {id}");
        return Ok(());
    }

    // ---- MCP server over stdio ----
    let rpc = RpcClient::from_datadir(&args.datadir, args.rpc_port)
        .context("connect to node RPC (is the node running?)")?;
    let params = match &args.params {
        Some(p) => minibtc_consensus::ChainParams::load(p)
            .with_context(|| format!("load params {}", p.display()))?,
        None => minibtc_consensus::ChainParams::devnet(),
    };
    let shared = Arc::new(Shared {
        rpc,
        rpc_port: args.rpc_port,
        datadir: args.datadir.clone(),
        params,
        cli: args.cli.clone(),
        max_spend_sats: args.max_spend_sats,
        max_daily_sats: args.max_daily_sats,
        miner_address: args.miner_address.clone(),
    });
    let handler = mcp::MiniBtcMcp::new(shared);
    let transport = rmcp::transport::io::stdio();
    let service = handler.serve(transport).await?;
    service.waiting().await?;
    Ok(())
}
