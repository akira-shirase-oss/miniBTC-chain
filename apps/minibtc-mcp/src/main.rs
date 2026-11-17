//! minibtc-mcp — Model Context Protocol server for MiniBTC.
//!
//! Lets AI assistants inspect the chain and *draft* payments through the
//! node's public JSON-RPC API. Hard rules from the blueprint:
//!
//! - Never holds seeds, private keys, wallet files or the wallet
//!   passphrase. `draft_payment` runs `minibtc-cli wallet draft`, which
//!   builds an UNSIGNED transaction from the wallet's public watch-only
//!   scripts (the child gets no passphrase in its environment).
//! - Every spend needs explicit human approval *outside* the model: the
//!   wallet owner runs `minibtc-cli wallet approve-draft` at an
//!   interactive terminal, reviews the outputs and fee decoded from the
//!   draft's bytes, types the wallet passphrase and `sign`. The approval
//!   *is* the signature: no file a process (or a model with a shell) can
//!   write without the wallet's keys counts as approval.
//! - `request_send` broadcasts only a signed transaction whose bytes are
//!   exactly the draft plus signatures, and applies the per-request and
//!   per-day caps to the spend computed from those bytes.
//! - Every call — tool, resource, prompt — is appended to an audit log.
//!
//! Transport: stdio (the standard for local MCP clients).

mod mcp;

use anyhow::{Context, Result};
use clap::Parser;
use minibtc_primitives::Transaction;
use minibtc_rpc::client::RpcClient;
use rmcp::ServiceExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
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
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600); // owner-only from creation, like the cookie
    }
    let mut f = opts
        .open(&path)
        .with_context(|| format!("open audit log {}", path.display()))?;
    #[cfg(unix)]
    {
        // An older log may have been created with the umask's mode.
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("make audit log {} owner-only", path.display()))?;
    }
    f.write_all(line.as_bytes())?;
    Ok(())
}

// ---------- draft store ----------

/// An UNSIGNED payment draft. Carries no spend authority: broadcasting
/// needs the signed form, which only the wallet owner can produce
/// (`minibtc-cli wallet approve-draft`). Summaries are always recomputed
/// from `unsigned_hex`, never trusted from fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Draft {
    pub id: String,
    pub wallet: String,
    /// The exact unsigned transaction the owner will review and sign.
    pub unsigned_hex: String,
    /// Which output returns to the wallet (from the drafter; the owner's
    /// approval re-derives it from the wallet's own scripts).
    pub change_index: Option<usize>,
    pub created_unix: u64,
    pub expires_unix: u64,
}

/// What `approve-draft` writes after the owner signed.
#[derive(Clone, Debug, Deserialize)]
pub struct SignedDraft {
    pub signed_hex: String,
    /// Outputs the wallet recognised as its own when signing.
    pub change_outputs: Vec<usize>,
}

impl Draft {
    fn path(dir: &Path, id: &str) -> PathBuf {
        dir.join(format!("{id}.json"))
    }

    fn signed_path(dir: &Path, id: &str) -> PathBuf {
        dir.join(format!("{id}.signed.json"))
    }

    fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let path = Self::path(dir, &self.id);
        let bytes = serde_json::to_vec_pretty(self)?;
        minibtc_wallet::owner_only::write_owner_only(&path, &bytes)
            .with_context(|| format!("write draft {} owner-only", path.display()))?;
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
            let is_draft = p.extension().and_then(|s| s.to_str()) == Some("json")
                && !p.to_string_lossy().ends_with(".signed.json");
            if !is_draft {
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

    /// The owner's signed form, if `approve-draft` produced one.
    fn signed(&self, dir: &Path) -> Option<SignedDraft> {
        let bytes = std::fs::read(Self::signed_path(dir, &self.id)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// The draft's transaction, decoded and checked to be unsigned.
    fn unsigned_tx(&self) -> Result<Transaction> {
        let tx = decode_tx_hex(&self.unsigned_hex)?;
        minibtc_wallet::draft::ensure_unsigned(&tx)?;
        Ok(tx)
    }

    fn revoke(&self, dir: &Path) -> Result<()> {
        let _ = std::fs::remove_file(Self::path(dir, &self.id));
        let _ = std::fs::remove_file(Self::signed_path(dir, &self.id));
        Ok(())
    }
}

/// Decode a hex-encoded transaction (strict: no trailing bytes).
pub fn decode_tx_hex(hex: &str) -> Result<Transaction> {
    let bytes = minibtc_crypto::hex_decode(hex).context("transaction hex")?;
    Transaction::decode(&bytes).context("transaction bytes")
}

/// Indices of `tx`'s outputs that pay one of the wallet's own scripts.
pub fn change_outputs(tx: &Transaction, wallet_scripts: &HashSet<Vec<u8>>) -> Vec<usize> {
    tx.outputs
        .iter()
        .enumerate()
        .filter(|(_, o)| wallet_scripts.contains(&o.script_pubkey))
        .map(|(i, _)| i)
        .collect()
}

/// The gate `request_send` applies before broadcasting: there must be a
/// signed form, it must be exactly the draft plus signatures, and the
/// spend computed from the signed bytes must fit both caps. Input values
/// come from the node; which outputs are change comes from the wallet's
/// watch-only scripts (`wallet_scripts`), never from the draft or approval
/// files — those are plain JSON a process could relabel to dodge the caps.
/// Returns the signed tx and its spend.
pub fn check_send(
    draft: &Draft,
    signed: Option<&SignedDraft>,
    input_values: &[minibtc_primitives::Sats],
    wallet_scripts: &HashSet<Vec<u8>>,
    max_spend_sats: u64,
    spent_today_sats: u64,
    max_daily_sats: u64,
) -> Result<(Transaction, u64)> {
    let unsigned = draft.unsigned_tx()?;
    let Some(signed) = signed else {
        anyhow::bail!(
            "draft {} is not approved: the wallet owner must sign it with \
             `minibtc-cli wallet approve-draft` in their own terminal. The model \
             cannot approve its own spends.",
            draft.id
        );
    };
    let signed_tx = decode_tx_hex(&signed.signed_hex)?;
    minibtc_wallet::draft::matches_draft(&unsigned, &signed_tx)?;
    let change = change_outputs(&signed_tx, wallet_scripts);
    let s = minibtc_wallet::draft::spend_summary(&signed_tx, input_values, &change)?;
    let spend = s.spend.sats();
    if spend > max_spend_sats {
        anyhow::bail!("spend {spend} sats exceeds the per-request cap {max_spend_sats}");
    }
    if spent_today_sats.saturating_add(spend) > max_daily_sats {
        anyhow::bail!("daily spend cap exceeded: {spent_today_sats} + {spend} > {max_daily_sats}");
    }
    Ok((signed_tx, spend))
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

    // ---- one-shot draft housekeeping (outside any MCP session) ----
    // Approval is NOT here: the wallet owner signs with
    // `minibtc-cli wallet approve-draft` (passphrase typed at a terminal).
    if args.list_drafts {
        for d in Draft::list(&drafts_dir) {
            let state = if d.signed(&drafts_dir).is_some() {
                "SIGNED"
            } else if d.expires_unix < unix_now() {
                "expired"
            } else {
                "pending"
            };
            let outputs = d
                .unsigned_tx()
                .map(|t| t.outputs.len().to_string())
                .unwrap_or_else(|e| format!("undecodable ({e})"));
            println!(
                "{} [{}] wallet {} — {} outputs; review with `minibtc-cli wallet approve-draft`",
                d.id, state, d.wallet, outputs
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
        Some(p) => {
            let text = tokio::fs::read_to_string(p)
                .await
                .with_context(|| format!("read params file {}", p.display()))?;
            minibtc_consensus::ChainParams::from_json(&text)
                .with_context(|| format!("parse params {}", p.display()))?
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use minibtc_primitives::{OutPoint, Sats, TxInput, TxOutput};

    /// Output 0 pays the payee (script 0xaa); any further output pays the
    /// wallet's own change script (0xbb).
    fn tx(signed: bool, outputs: &[u64]) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev: OutPoint {
                    txid: minibtc_crypto::Hash256([3; 32]),
                    vout: 1,
                },
                script_sig: if signed { vec![0x01, 0xaa] } else { vec![] },
                sequence: 0xffff_fffe,
            }],
            outputs: outputs
                .iter()
                .enumerate()
                .map(|(i, v)| TxOutput {
                    value: Sats(*v),
                    script_pubkey: if i == 0 { vec![0xaa] } else { vec![0xbb] },
                })
                .collect(),
            locktime: 0,
        }
    }

    fn wallet() -> HashSet<Vec<u8>> {
        HashSet::from([vec![0xbb]])
    }

    fn draft(outputs: &[u64], change: Option<usize>) -> Draft {
        Draft {
            id: "dtest".into(),
            wallet: "w".into(),
            unsigned_hex: minibtc_crypto::hex_encode(&tx(false, outputs).encode()),
            change_index: change,
            created_unix: 0,
            expires_unix: u64::MAX,
        }
    }

    fn signed(outputs: &[u64], change: &[usize]) -> SignedDraft {
        SignedDraft {
            signed_hex: minibtc_crypto::hex_encode(&tx(true, outputs).encode()),
            change_outputs: change.to_vec(),
        }
    }

    const CAP: u64 = 1_000_000;

    #[test]
    fn no_file_a_process_can_write_counts_as_approval() {
        // The old gate accepted `<id>.approved` holding the draft hash —
        // anything running as this user could mint it. Now only a signed
        // transaction approves, and writing that needs the wallet keys.
        let dir = std::env::temp_dir().join(format!("mcp-gate-{}", std::process::id()));
        let d = draft(&[700, 200], Some(1));
        d.save(&dir).unwrap();
        std::fs::write(
            dir.join("dtest.approved"),
            serde_json::json!({"draft_sha256": "anything"}).to_string(),
        )
        .unwrap();
        let rec = d.signed(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(rec.is_none());
        let err = check_send(&d, rec.as_ref(), &[Sats(1_000)], &wallet(), CAP, 0, CAP).unwrap_err();
        assert!(err.to_string().contains("not approved"), "{err}");
    }

    #[test]
    fn the_signed_bytes_must_be_the_drafted_payment() {
        let d = draft(&[700, 200], Some(1));
        // Same draft, signed: accepted, spend = 700 + fee 100.
        let (_, spend) = check_send(
            &d,
            Some(&signed(&[700, 200], &[1])),
            &[Sats(1_000)],
            &wallet(),
            CAP,
            0,
            CAP,
        )
        .unwrap();
        assert_eq!(spend, 800);
        // Different outputs behind the same draft id: refused.
        assert!(
            check_send(
                &d,
                Some(&signed(&[900], &[])),
                &[Sats(1_000)],
                &wallet(),
                CAP,
                0,
                CAP
            )
            .is_err()
        );
        // An unsigned "signed" record: refused.
        let unsigned = SignedDraft {
            signed_hex: d.unsigned_hex.clone(),
            change_outputs: vec![1],
        };
        assert!(check_send(&d, Some(&unsigned), &[Sats(1_000)], &wallet(), CAP, 0, CAP).is_err());
    }

    #[test]
    fn caps_apply_to_the_spend_decoded_from_the_bytes() {
        let d = draft(&[700, 200], Some(1));
        let s = signed(&[700, 200], &[1]);
        // Per-request cap below the decoded spend (800).
        assert!(check_send(&d, Some(&s), &[Sats(1_000)], &wallet(), 799, 0, CAP).is_err());
        // Daily cap: 300 already spent today, 1,000 allowed.
        assert!(check_send(&d, Some(&s), &[Sats(1_000)], &wallet(), CAP, 300, 1_000).is_err());
        assert!(check_send(&d, Some(&s), &[Sats(1_000)], &wallet(), CAP, 200, 1_000).is_ok());
    }

    #[test]
    fn relabelling_the_payment_as_change_cannot_dodge_the_cap() {
        // Both JSON files claim output 0 (the payment) is change. The gate
        // ignores them: change is what pays the wallet's own scripts, so
        // the spend is still 700 + fee 100 = 800, above a 799 cap.
        let mut d = draft(&[700, 200], Some(0));
        d.change_index = Some(0);
        let relabelled = signed(&[700, 200], &[0]);
        assert!(
            check_send(
                &d,
                Some(&relabelled),
                &[Sats(1_000)],
                &wallet(),
                799,
                0,
                CAP
            )
            .is_err()
        );
        let (_, spend) = check_send(
            &d,
            Some(&relabelled),
            &[Sats(1_000)],
            &wallet(),
            CAP,
            0,
            CAP,
        )
        .unwrap();
        assert_eq!(spend, 800);
        // With no wallet scripts known, every output counts as leaving.
        let (_, all) = check_send(
            &d,
            Some(&relabelled),
            &[Sats(1_000)],
            &HashSet::new(),
            CAP,
            0,
            CAP,
        )
        .unwrap();
        assert_eq!(all, 1_000);
    }

    #[test]
    fn drafts_must_be_unsigned() {
        let mut d = draft(&[700], None);
        d.unsigned_hex = minibtc_crypto::hex_encode(&tx(true, &[700]).encode());
        assert!(d.unsigned_tx().is_err(), "a pre-signed draft is refused");
    }
}
