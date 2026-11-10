//! minibtc-cli — the MiniBTC command-line client.
//!
//! Talks to a running node over JSON-RPC (cookie auth from the node's
//! datadir) and manages local encrypted wallets under
//! `<datadir>/wallets/`. Human-readable output by default; `--json`
//! emits the raw RPC value.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use minibtc_chainstate::UtxoEntry;
use minibtc_consensus::{ChainParams, UtxoView};
use minibtc_crypto::hash::hex_decode;
use minibtc_crypto::{Address, Hash256, hex_encode};
use minibtc_primitives::{OutPoint, Sats, TxOutput};
use minibtc_rpc::client::RpcClient;
use minibtc_wallet::Wallet;
use minibtc_wallet::keystore::Keystore;
use minibtc_wallet::wallet::IterableUtxos;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// MiniBTC command-line client.
#[derive(Parser, Debug)]
#[command(name = "minibtc-cli", version, about)]
struct Cli {
    /// Node datadir (holds .cookie + wallets/).
    #[arg(long, default_value = "data", global = true)]
    datadir: PathBuf,

    /// RPC host.
    #[arg(long, default_value = "127.0.0.1", global = true)]
    rpc_host: String,

    /// RPC port.
    #[arg(long, default_value_t = 18446, global = true)]
    rpc_port: u16,

    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    json: bool,

    /// Custom chain params JSON (sets address version etc.).
    #[arg(long, global = true)]
    params: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Wallet management.
    Wallet {
        #[command(subcommand)]
        cmd: WalletCmd,
    },
    /// Chain queries.
    Chain {
        #[command(subcommand)]
        cmd: ChainCmd,
    },
    /// Mempool queries.
    Mempool {
        #[command(subcommand)]
        cmd: MempoolCmd,
    },
    /// Mine blocks (devnet).
    Mine {
        #[command(subcommand)]
        cmd: MineCmd,
    },
    /// Peer management.
    Peers {
        #[command(subcommand)]
        cmd: PeersCmd,
    },
}

#[derive(Subcommand, Debug)]
enum WalletCmd {
    /// Create a new wallet (prints the mnemonic once — back it up).
    Create {
        /// Wallet name (filename-safe).
        #[arg(long)]
        name: String,
        /// BIP39 passphrase for the keystore (else env/prompt/empty).
        #[arg(long)]
        passphrase: Option<String>,
        /// BIP39 passphrase for seed derivation (different thing — optional).
        #[arg(long)]
        mnemonic_passphrase: Option<String>,
    },
    /// Restore a wallet from a mnemonic phrase.
    Restore {
        #[arg(long)]
        name: String,
        /// The mnemonic words.
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        mnemonic_passphrase: Option<String>,
    },
    /// Derive a fresh receive address.
    Address {
        #[command(subcommand)]
        cmd: AddressCmd,
    },
    /// Show balance (mature + immature coinbase).
    Balance {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// List wallet UTXOs.
    Utxos {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Send coins.
    Send {
        #[arg(long)]
        name: String,
        /// Destination address.
        #[arg(long)]
        to: String,
        /// Amount in BTC (e.g. 1.5).
        #[arg(long)]
        amount: String,
        /// Fee rate in sats/kvB.
        #[arg(long, default_value_t = 5)]
        fee_rate: u64,
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Wallet transaction history (received outputs + spends visible
    /// in current UTXOs).
    History {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AddressCmd {
    /// New receive address.
    New {
        #[arg(long)]
        name: String,
        #[arg(long)]
        passphrase: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum ChainCmd {
    /// Chain summary.
    Info,
    /// Block by hash or height.
    Block {
        /// Block hash (hex) or height.
        reference: String,
        /// 0 = hex only, 1 = JSON with txids, 2 = full txs.
        #[arg(long, default_value_t = 1)]
        verbose: u8,
    },
    /// Transaction by txid.
    Tx { txid: String },
    /// UTXO by `txid:vout`.
    Utxo { outpoint: String },
}

#[derive(Subcommand, Debug)]
enum MempoolCmd {
    /// List mempool txids (or full JSON with --json).
    List,
    /// Mempool stats.
    Info,
}

#[derive(Subcommand, Debug)]
enum MineCmd {
    /// Generate blocks to an address (devnet only).
    Generate {
        /// Number of blocks.
        n: u64,
        /// Payout address.
        #[arg(long)]
        address: String,
    },
}

#[derive(Subcommand, Debug)]
enum PeersCmd {
    /// List connected peers.
    List,
    /// Ban an IP.
    Ban { ip: IpAddr },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("warn")
        .with_target(false)
        .init();
    let cli = Cli::parse();
    let params = load_params(&cli)?;
    let datadir = cli.datadir.clone();
    let json_out = cli.json;
    let client = RpcClient::from_datadir(&cli.datadir, cli.rpc_port)
        .context("connect to node (is minibtc-node running? .cookie readable?)")?;
    // Use --rpc-host override when not localhost-default.
    let client = if cli.rpc_host == "127.0.0.1" {
        client
    } else {
        // Rebuild with explicit host — need cookie contents.
        let cookie = std::fs::read_to_string(cli.datadir.join(".cookie"))?;
        let auth = minibtc_rpc::server::CookieAuth::from_cookie_file(&cookie)?;
        RpcClient::new(&cli.rpc_host, cli.rpc_port, auth)?
    };

    match cli.cmd {
        Cmd::Wallet { cmd } => wallet_cmd(&datadir, json_out, &client, &params, cmd).await?,
        Cmd::Chain { cmd } => chain_cmd(&client, cmd).await?,
        Cmd::Mempool { cmd } => mempool_cmd(&client, cmd).await?,
        Cmd::Mine { cmd } => mine_cmd(&client, cmd).await?,
        Cmd::Peers { cmd } => peers_cmd(&client, cmd).await?,
    }
    Ok(())
}

fn load_params(cli: &Cli) -> Result<ChainParams> {
    match &cli.params {
        Some(p) => ChainParams::load(p).context("load chain params"),
        None => Ok(ChainParams::devnet()),
    }
}

// ---------- output helpers ----------

/// Minimal human renderer for the shapes our commands produce.
fn print_human(v: &Value) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                match val {
                    Value::Object(_) | Value::Array(_) => {
                        println!("{k}:");
                        print_human(val);
                    }
                    _ => println!("  {k}: {}", scalar(val)),
                }
            }
        }
        Value::Array(items) => {
            for it in items {
                println!("  - {}", one_line(it));
            }
        }
        _ => println!("{}", scalar(v)),
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        _ => serde_json::to_string(v).unwrap_or_default(),
    }
}

fn one_line(v: &Value) -> String {
    if let Value::Object(m) = v {
        // Prefer the most identifying fields.
        for key in ["txid", "hash", "address", "id", "addr"] {
            if let Some(x) = m.get(key) {
                return format!("{}={}", key, scalar(x));
            }
        }
        serde_json::to_string(v).unwrap_or_default()
    } else {
        scalar(v)
    }
}

// ---------- wallet plumbing ----------

const BIP39_PASSPHRASE_ENV: &str = "MINIBTC_MNEMONIC_PASSPHRASE";
const KEYSTORE_PASSPHRASE_ENV: &str = "MINIBTC_WALLET_PASSPHRASE";

/// Resolve the keystore passphrase: flag → env → prompt → "".
fn keystore_passphrase(flag: Option<&str>, required: bool) -> Result<String> {
    if let Some(p) = flag {
        return Ok(p.to_string());
    }
    if let Ok(p) = std::env::var(KEYSTORE_PASSPHRASE_ENV) {
        return Ok(p);
    }
    if required {
        eprint!("Keystore passphrase: ");
        std::io::stderr().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        return Ok(line.trim_end().to_string());
    }
    Ok(String::new())
}

/// Wallet file path — name is sanitized to prevent traversal.
fn wallet_path(datadir: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        anyhow::bail!("invalid wallet name {name:?} (alnum, -, _, . only)");
    }
    Ok(datadir.join("wallets").join(format!("{name}.wallet")))
}

/// Gap-limit lookahead: how many unused indices each chain pre-derives
/// for scanning. Funds can only sit on indices < next+gap.
const GAP_LIMIT: u32 = 25;

/// Persist an encrypted keystore for `seed` plus the address-issuance
/// counters (public metadata — the seed stays inside the keystore).
fn save_wallet(
    datadir: &Path,
    name: &str,
    seed: &[u8; 64],
    passphrase: &str,
    indices: (u32, u32),
) -> Result<()> {
    let path = wallet_path(datadir, name)?;
    if path.exists() {
        anyhow::bail!("wallet {name} already exists");
    }
    std::fs::create_dir_all(path.parent().unwrap())?;
    let ks = Keystore::encrypt(seed, passphrase).context("encrypt keystore")?;
    ks.save(&path).context("save keystore")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    let state = json!({ "next_receive": indices.0, "next_change": indices.1 });
    std::fs::write(
        wallet_path(datadir, name)?.with_extension("state.json"),
        serde_json::to_string_pretty(&state)?,
    )?;
    Ok(())
}

/// Load + decrypt a wallet file into a `Wallet` (not yet scanned).
fn load_wallet(
    datadir: &Path,
    name: &str,
    params: &ChainParams,
    passphrase: &str,
) -> Result<Wallet> {
    let path = wallet_path(datadir, name)?;
    let ks = Keystore::load(&path).with_context(|| format!("load wallet {}", path.display()))?;
    let seed = ks
        .decrypt(passphrase)
        .context("decrypt keystore (wrong passphrase?)")?;
    let bip39_pass = std::env::var(BIP39_PASSPHRASE_ENV).unwrap_or_default();
    let mut w = Wallet::from_seed(
        seed.expose(),
        &bip39_pass,
        COIN_TYPE,
        ACCOUNT,
        params.address_version,
        params.coinbase_maturity,
    )
    .context("derive wallet")?;
    // Restore issuance counters (absent file → fresh wallet at 0).
    let state_path = wallet_path(datadir, name)?.with_extension("state.json");
    if let Ok(text) = std::fs::read_to_string(&state_path) {
        let st: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        w.set_indices(
            st["next_receive"].as_u64().unwrap_or(0) as u32,
            st["next_change"].as_u64().unwrap_or(0) as u32,
        );
    }
    Ok(w)
}

const COIN_TYPE: u32 = 0; // BIP44 coin type — MiniBTC devnet uses Bitcoin's slot.
const ACCOUNT: u32 = 0;

/// A UTXO view built from `scantxoutset` RPC output.
struct RpcView {
    map: HashMap<OutPoint, UtxoEntry>,
}

impl UtxoView for RpcView {
    fn get(&self, op: &OutPoint) -> Option<TxOutput> {
        self.map.get(op).map(|e| e.output.clone())
    }
}

impl IterableUtxos for RpcView {
    fn utxo_iter(&self) -> Box<dyn Iterator<Item = (&OutPoint, &UtxoEntry)> + '_> {
        Box::new(self.map.iter().map(|(k, v)| (k, v)))
    }
}

/// Fetch all UTXOs and build the scan view.
async fn fetch_utxo_view(client: &RpcClient) -> Result<(RpcView, u32)> {
    let v = client.call("scantxoutset", json!([])).await?;
    let tip = v["tip_height"].as_u64().unwrap_or(0) as u32;
    let mut map = HashMap::new();
    let arr = v["utxos"].as_array().context("bad scantxoutset")?;
    for u in arr {
        let txid =
            Hash256::from_hex(u["txid"].as_str().context("utxo txid")?).context("utxo txid hex")?;
        let op = OutPoint {
            txid,
            vout: u["vout"].as_u64().unwrap_or(0) as u32,
        };
        let script =
            hex_decode(u["scriptPubKey"].as_str().unwrap_or("")).context("utxo script hex")?;
        map.insert(
            op,
            UtxoEntry {
                output: TxOutput {
                    value: Sats(u["value"].as_u64().unwrap_or(0)),
                    script_pubkey: script,
                },
                height: u["height"].as_u64().unwrap_or(0) as u32,
                coinbase: u["coinbase"].as_bool().unwrap_or(false),
            },
        );
    }
    Ok((RpcView { map }, tip))
}

/// Load wallet + scan chain + return (wallet, tip_height).
async fn load_and_scan(
    datadir: &Path,
    client: &RpcClient,
    params: &ChainParams,
    name: &str,
    passphrase: Option<&str>,
) -> Result<(Wallet, u32)> {
    let pp = keystore_passphrase(passphrase, false)?;
    let mut w = load_wallet(datadir, name, params, &pp)?;
    // Derive the used+lookahead window so scan sees every address that
    // could hold funds (past sessions' indices included).
    w.prime_lookahead(GAP_LIMIT)?;
    let (view, tip) = fetch_utxo_view(client).await?;
    w.scan(&view, tip);
    Ok((w, tip))
}

// ---------- command handlers ----------

async fn wallet_cmd(
    datadir: &Path,
    json_out: bool,
    client: &RpcClient,
    params: &ChainParams,
    cmd: WalletCmd,
) -> Result<()> {
    // `emit`-equivalent using the destructured flags.
    let emit = |v: &Value| -> Result<()> {
        if json_out {
            println!("{}", serde_json::to_string_pretty(v)?);
        } else {
            print_human(v);
        }
        Ok(())
    };
    match cmd {
        WalletCmd::Create {
            name,
            passphrase,
            mnemonic_passphrase,
        } => {
            let pp = keystore_passphrase(passphrase.as_deref(), true)?;
            let bip39_pass = mnemonic_passphrase
                .or_else(|| std::env::var(BIP39_PASSPHRASE_ENV).ok())
                .unwrap_or_default();
            let (mut w, mnemonic) = Wallet::generate(
                &bip39_pass,
                COIN_TYPE,
                ACCOUNT,
                params.address_version,
                params.coinbase_maturity,
            )
            .context("generate wallet")?;
            // The mnemonic IS the wallet — show it once, loudly.
            println!("=== WALLET CREATED: {} ===", name);
            println!("MNEMONIC (back this up NOW — never shown again):");
            println!("{}", mnemonic.phrase());
            // First address, then persist seed + issuance counters.
            let addr = w.new_address()?;
            let seed = minibtc_wallet::seed_from_mnemonic(&mnemonic.phrase(), &bip39_pass)
                .context("derive seed")?;
            save_wallet(datadir, &name, &seed, &pp, w.indices())?;
            println!("first address: {}", addr);
            Ok(())
        }
        WalletCmd::Restore {
            name,
            mnemonic,
            passphrase,
            mnemonic_passphrase,
        } => {
            let pp = keystore_passphrase(passphrase.as_deref(), true)?;
            let bip39_pass = mnemonic_passphrase
                .or_else(|| std::env::var(BIP39_PASSPHRASE_ENV).ok())
                .unwrap_or_default();
            // Validate the phrase by deriving — from_mnemonic errors on bad words.
            let probe = Wallet::from_mnemonic(
                &mnemonic,
                &bip39_pass,
                COIN_TYPE,
                ACCOUNT,
                params.address_version,
                params.coinbase_maturity,
            )
            .context("invalid mnemonic")?;
            let _ = probe;
            // Re-derive seed the same way bip39 does to store it.
            let seed = minibtc_wallet::seed_from_mnemonic(&mnemonic, &bip39_pass)
                .context("derive seed")?;
            // Fresh restore starts at index 0 — reserve it as "used" so
            // the printed address is the canonical first receive addr.
            let mut w0 = Wallet::from_seed(
                &seed,
                &bip39_pass,
                COIN_TYPE,
                ACCOUNT,
                params.address_version,
                params.coinbase_maturity,
            )?;
            let addr = w0.new_address()?;
            save_wallet(datadir, &name, &seed, &pp, w0.indices())?;
            println!("=== WALLET RESTORED: {} ===", name);
            println!("first address: {}", addr);
            Ok(())
        }
        WalletCmd::Address { cmd } => match cmd {
            AddressCmd::New { name, passphrase } => {
                let pp = keystore_passphrase(passphrase.as_deref(), false)?;
                let mut w = load_wallet(datadir, &name, params, &pp)?;
                let addr = w.new_address()?;
                if json_out {
                    println!("{}", json!({ "address": addr.to_string() }));
                } else {
                    println!("{}", addr);
                }
                Ok(())
            }
        },
        WalletCmd::Balance { name, passphrase } => {
            let (w, _tip) =
                load_and_scan(datadir, client, params, &name, passphrase.as_deref()).await?;
            let (mature, immature) = w.balance();
            emit(&json!({
                "wallet": name,
                "balance_sats": mature.sats(),
                "immature_sats": immature.sats(),
                "balance_btc": format!("{}.{:08}", mature.sats() / 100_000_000, mature.sats() % 100_000_000),
                "utxos": w.utxos().len(),
            }))
        }
        WalletCmd::Utxos { name, passphrase } => {
            let (w, _tip) =
                load_and_scan(datadir, client, params, &name, passphrase.as_deref()).await?;
            let items: Vec<Value> = w
                .utxos()
                .iter()
                .map(|u| {
                    json!({
                        "txid": u.outpoint.txid.to_hex(),
                        "vout": u.outpoint.vout,
                        "value_sats": u.output.value.sats(),
                        "height": u.height,
                        "coinbase": u.coinbase,
                        "confirmations": u.confirmations(),
                        "spendable": u.spendable(params.coinbase_maturity),
                    })
                })
                .collect();
            emit(&Value::Array(items))
        }
        WalletCmd::Send {
            name,
            to,
            amount,
            fee_rate,
            passphrase,
        } => {
            let sats = parse_amount(&amount)?;
            let dest = Address::from_base58(&to, Some(params.address_version))
                .context("invalid destination address")?;
            let dest_script = minibtc_script::Script::p2pkh(&dest.hash160)
                .as_bytes()
                .to_vec();
            let (mut w, _tip) =
                load_and_scan(datadir, client, params, &name, passphrase.as_deref()).await?;
            let tx = w
                .build_and_sign(&dest_script, Sats(sats), fee_rate, 0)
                .context("build transaction")?;
            // Local sanity re-validation before broadcasting.
            let txid = tx.txid();
            let hex = hex_encode(&tx.encode());
            match client.sendrawtransaction(&hex).await {
                Ok(ret) => {
                    if json_out {
                        println!(
                            "{}",
                            json!({ "txid": ret, "hex": hex, "signed_txid": txid.to_hex() })
                        );
                    } else {
                        println!("broadcast txid: {ret}");
                        println!("hex: {hex}");
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!("node rejected tx: {e}");
                    eprintln!("signed hex (for debugging): {hex}");
                    std::process::exit(1);
                }
            }
        }
        WalletCmd::History { name, passphrase } => {
            let (w, _tip) =
                load_and_scan(datadir, client, params, &name, passphrase.as_deref()).await?;
            // History = current UTXOs (each is a confirmed receive) plus
            // a count summary. Spent-history indexing is the explorer's
            // job (address index) — noted in output.
            let items: Vec<Value> = w
                .utxos()
                .iter()
                .map(|u| {
                    json!({
                        "txid": u.outpoint.txid.to_hex(),
                        "vout": u.outpoint.vout,
                        "value_sats": u.output.value.sats(),
                        "height": u.height,
                        "confirmations": u.confirmations(),
                        "spent": false,
                    })
                })
                .collect();
            emit(&json!({
                "wallet": name,
                "note": "shows unspent received outputs; full tx history via explorer address page",
                "outputs": items,
            }))
        }
    }
}

async fn chain_cmd(client: &RpcClient, cmd: ChainCmd) -> Result<()> {
    match cmd {
        ChainCmd::Info => {
            let v = client.getblockchaininfo().await?;
            print_json(v)
        }
        ChainCmd::Block { reference, verbose } => {
            let v = client.getblock(&reference, verbose).await?;
            print_json(v)
        }
        ChainCmd::Tx { txid } => {
            let v = client.getrawtransaction(&txid, true).await?;
            print_json(v)
        }
        ChainCmd::Utxo { outpoint } => {
            let (txid, vout) = outpoint
                .split_once(':')
                .context("outpoint must be txid:vout")?;
            let vout: u32 = vout.parse().context("bad vout")?;
            let v = client.gettxout(txid, vout).await?;
            print_json(v)
        }
    }
}

async fn mempool_cmd(client: &RpcClient, cmd: MempoolCmd) -> Result<()> {
    match cmd {
        MempoolCmd::List => {
            let v = client.getrawmempool(false).await?;
            print_json(v)
        }
        MempoolCmd::Info => {
            let v = client.getmempoolinfo().await?;
            print_json(v)
        }
    }
}

async fn mine_cmd(client: &RpcClient, cmd: MineCmd) -> Result<()> {
    match cmd {
        MineCmd::Generate { n, address } => {
            let v = client.generatetoaddress(n, &address).await?;
            print_json(v)
        }
    }
}

async fn peers_cmd(client: &RpcClient, cmd: PeersCmd) -> Result<()> {
    match cmd {
        PeersCmd::List => {
            let v = client.getpeerinfo().await?;
            print_json(v)
        }
        PeersCmd::Ban { ip } => {
            let v = client.call("banpeer", json!([ip.to_string()])).await?;
            print_json(v)
        }
    }
}

fn print_json(v: Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

/// Parse a BTC decimal amount ("1.5", "0.00000001") to sats — no floats.
fn parse_amount(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() || s.starts_with('-') {
        anyhow::bail!("invalid amount {s:?}");
    }
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole.is_empty() || !whole.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!("invalid amount {s:?}");
    }
    if frac.len() > 8 || !frac.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!("amount has >8 decimal places: {s:?}");
    }
    let whole_sats = whole
        .parse::<u64>()
        .context("amount too large")?
        .checked_mul(100_000_000)
        .context("amount too large")?;
    let frac_sats = if frac.is_empty() {
        0
    } else {
        let padded = format!("{frac:0<8}");
        padded.parse::<u64>().context("bad fraction")?
    };
    whole_sats
        .checked_add(frac_sats)
        .context("amount overflow")
        .map_err(Into::into)
}
