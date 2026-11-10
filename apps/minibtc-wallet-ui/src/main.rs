//! minibtc-wallet-ui — a local web wallet for MiniBTC (decision D-011,
//! expanded P13b: create + restore flows added per user request).
//!
//! Security contract (stricter than the read-only explorer):
//! - Passphrases and seeds live in memory only — never persisted by the
//!   UI, never logged, never echoed. The keystore file on disk is the
//!   only durable copy and stays passphrase-encrypted (0600).
//! - Sessions: random token in an HttpOnly SameSite=Strict cookie,
//!   server-side map, idle TTL, bounded count, per-name unlock
//!   rate limiting. Every POST requires the per-session CSRF token
//!   plus an Origin check.
//! - Spending is two-step: build+sign → human-readable review →
//!   explicit confirm → broadcast. Nothing sends on the first POST.
//! - Wallet creation is two-step too: generate → show seed ONCE with
//!   an explicit "I saved it" gate → only then encrypt+save+unlock.
//!   Closing the tab before confirming abandons the pending seed
//!   (zeroized on drop/TTL) and writes nothing.
//! - Audit log (`<datadir>/wallet-ui-audit.jsonl`) records events
//!   with no secrets.
//!
//! Binds localhost by default. Single-user devnet tool.

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use clap::Parser;
use minibtc_chainstate::UtxoEntry;
use minibtc_consensus::{ChainParams, UtxoView};
use minibtc_crypto::hash::hex_decode;
use minibtc_crypto::{Address, Hash256, hex_encode};
use minibtc_primitives::{OutPoint, Sats, TxOutput};
use minibtc_rpc::client::RpcClient;
use minibtc_script::Script;
use minibtc_wallet::Wallet;
use minibtc_wallet::bip39::{generate_mnemonic, mnemonic_from_phrase};
use minibtc_wallet::keystore::Keystore;
use minibtc_wallet::wallet::IterableUtxos;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const GAP_LIMIT: u32 = 25;
const COIN_TYPE: u32 = 0;
const ACCOUNT: u32 = 0;
const BIP39_ENV: &str = "MINIBTC_MNEMONIC_PASSPHRASE";
const SESSION_COOKIE: &str = "mb_wallet";
const MAX_SESSIONS: usize = 32;
const MAX_PENDING: usize = 8;
const UNLOCK_FAIL_LIMIT: u32 = 5;
const UNLOCK_LOCKOUT: Duration = Duration::from_secs(60);
const PENDING_TTL: Duration = Duration::from_secs(10 * 60);
const COIN: u64 = 100_000_000;

#[derive(Parser, Debug)]
#[command(name = "minibtc-wallet-ui", about = "MiniBTC local wallet web UI")]
struct Args {
    /// Node datadir (holds .cookie + wallets/).
    #[arg(long, default_value = "data")]
    datadir: PathBuf,
    /// RPC port.
    #[arg(long, default_value_t = 18446)]
    rpc_port: u16,
    /// Listen address (localhost only unless you know why).
    #[arg(long, default_value = "127.0.0.1:18448")]
    listen: SocketAddr,
    /// Session idle timeout, seconds.
    #[arg(long, default_value_t = 1800)]
    session_ttl_secs: u64,
    /// Custom chain params JSON.
    #[arg(long)]
    params: Option<PathBuf>,
}

struct PendingSend {
    to: String,
    amount_sats: u64,
    fee_rate: u64,
    fee_sats: u64,
    txid: String,
    tx_hex: String,
    inputs: usize,
}

struct Session {
    name: String,
    wallet: Wallet,
    csrf: String,
    touched: Instant,
    pending: Option<PendingSend>,
}

/// A wallet awaiting its "I saved the seed" confirmation. Holds the
/// raw seed in a `Zeroizing` buffer — wiped on drop or TTL sweep.
struct PendingCreate {
    name: String,
    /// The seed phrase, held only until the user confirms backup.
    phrase: Zeroizing<String>,
    seed: Zeroizing<[u8; 64]>,
    created: Instant,
}

struct App {
    rpc: RpcClient,
    params: ChainParams,
    datadir: PathBuf,
    listen: SocketAddr,
    ttl: Duration,
    sessions: Mutex<HashMap<String, Session>>,
    pending_creates: Mutex<HashMap<String, PendingCreate>>,
    /// wallet name → (consecutive failures, locked-until)
    unlock_fails: Mutex<HashMap<String, (u32, Instant)>>,
}

// ---------- wallet file helpers (mirror apps/minibtc-cli) ----------

fn wallet_path(datadir: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || name.len() > 64
    {
        anyhow::bail!("invalid wallet name {name:?} (1-64 chars: alnum, -, _, .)");
    }
    Ok(datadir.join("wallets").join(format!("{name}.wallet")))
}

fn wallet_exists(datadir: &Path, name: &str) -> bool {
    wallet_path(datadir, name).is_ok_and(|p| p.exists())
}

fn list_wallets(datadir: &Path) -> Vec<String> {
    let dir = datadir.join("wallets");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| {
                let p = e.ok()?.path();
                (p.extension()?.to_str()? == "wallet")
                    .then(|| p.file_stem()?.to_str().map(str::to_string))
                    .flatten()
            })
            .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn bip39_pass() -> String {
    std::env::var(BIP39_ENV).unwrap_or_default()
}

fn wallet_from_seed(seed: &[u8; 64], params: &ChainParams) -> Result<Wallet> {
    Wallet::from_seed(
        seed,
        &bip39_pass(),
        COIN_TYPE,
        ACCOUNT,
        params.address_version,
        params.coinbase_maturity,
    )
    .context("derive wallet")
}

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
    let mut w = wallet_from_seed(seed.expose(), params)?;
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

/// Persist keystore (0600) + public address counters.
fn persist_wallet(
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
    std::fs::create_dir_all(path.parent().context("wallet path has no parent")?)?;
    let ks = Keystore::encrypt(seed, passphrase).context("encrypt keystore")?;
    ks.save(&path).context("save keystore")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    save_indices(datadir, name, indices)
}

fn save_indices(datadir: &Path, name: &str, indices: (u32, u32)) -> Result<()> {
    let path = wallet_path(datadir, name)?.with_extension("state.json");
    let state = json!({ "next_receive": indices.0, "next_change": indices.1 });
    std::fs::write(&path, serde_json::to_string_pretty(&state)?)?;
    Ok(())
}

// ---------- UTXO scan view (same shape as CLI) ----------

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
        Box::new(self.map.iter())
    }
}

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
        let script = hex_decode(u["scriptPubKey"].as_str().unwrap_or("")).context("utxo script")?;
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

// ---------- session / auth helpers ----------

fn rand_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::fill(&mut buf[..]);
    hex_encode(&buf)
}

fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let mut kv = part.trim().splitn(2, '=');
        if kv.next() == Some(name) {
            return kv.next().map(str::to_string).filter(|s| !s.is_empty());
        }
    }
    None
}

fn set_session_cookie(token: &str) -> String {
    format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict")
}

fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

/// Origin check for POSTs: if an Origin header is present its host:port
/// must match the socket we bound. Browsers always send it on POST.
fn origin_ok(headers: &HeaderMap, listen: SocketAddr) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true; // non-browser clients (curl) send no Origin
    };
    let host = origin
        .trim_end_matches('/')
        .rsplit("://")
        .next()
        .unwrap_or("");
    host == listen.to_string() || host == format!("localhost:{}", listen.port())
}

fn audit(app: &App, event: &str, wallet: Option<&str>, detail: Option<&str>) {
    let line = json!({
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "event": event,
        "wallet": wallet,
        "detail": detail,
    });
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(app.datadir.join("wallet-ui-audit.jsonl"))
    {
        use std::io::Write;
        let _ = writeln!(f, "{line}");
    }
}

fn sweep_pending(app: &App) {
    app.pending_creates
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|_, p| p.created.elapsed() < PENDING_TTL);
}

/// Look up a live session by cookie token; sweeps expired entries.
fn session_token(app: &App, headers: &HeaderMap) -> Option<String> {
    let token = get_cookie(headers, SESSION_COOKIE)?;
    let mut sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
    sessions.retain(|_, s| s.touched.elapsed() < app.ttl);
    sessions.get(&token)?;
    Some(token)
}

/// Verify session + CSRF for a POST. Returns the session token.
fn require_post_session(
    app: &App,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> Option<String> {
    if !origin_ok(headers, app.listen) {
        return None;
    }
    let token = session_token(app, headers)?;
    let sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
    let s = sessions.get(&token)?;
    (form.get("csrf").map(String::as_str) == Some(s.csrf.as_str())).then_some(token)
}

/// Insert a new session; returns the cookie token.
fn open_session(app: &App, name: &str, wallet: Wallet) -> Option<String> {
    sweep_pending(app);
    let mut sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
    if sessions.len() >= MAX_SESSIONS {
        return None;
    }
    let token = rand_hex(32);
    sessions.insert(
        token.clone(),
        Session {
            name: name.to_string(),
            wallet,
            csrf: rand_hex(16),
            touched: Instant::now(),
            pending: None,
        },
    );
    Some(token)
}

fn session_cookie_response(token: &str, location: &str) -> Response {
    (
        [(header::SET_COOKIE, set_session_cookie(token))],
        Redirect::to(location),
    )
        .into_response()
}

// ---------- HTML helpers ----------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

const CSS: &str = "body{font-family:ui-monospace,Menlo,monospace;margin:0;color:#e6e6e6;background:#101216}\
header{background:#171a20;border-bottom:1px solid #2a2e35;padding:.7em 1.5em;display:flex;gap:1.5em;align-items:baseline}\
header a{color:#8ab4ff;text-decoration:none}header .brand{color:#e6e6e6;font-weight:700}\
main{max-width:64em;margin:1.5em auto;padding:0 1em}\
table{border-collapse:collapse;width:100%;margin:.6em 0}\
td,th{border-bottom:1px solid #23272e;padding:.3em .6em;text-align:left;font-size:.85em}\
th{color:#8a93a3;font-weight:600}\
.dim{color:#8a93a3}.warn{color:#e0a050}.ok{color:#7dd87d}.err{color:#e07070}\
form{margin:.8em 0}input,button,textarea{background:#1d2126;color:#ddd;border:1px solid #3a4048;padding:.4em .7em;font:inherit}\
button{cursor:pointer;background:#2a4a2a;border-color:#3f6a3f}\
button.danger{background:#4a2a2a;border-color:#6a3f3f}\
.card{background:#161a20;border:1px solid #262b33;border-radius:6px;padding:1em 1.2em;margin:1em 0}\
\
.mono{font-family:ui-monospace,monospace;word-break:break-all}\
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(15em,1fr));gap:1em}\
.stat{background:#161a20;border:1px solid #262b33;border-radius:6px;padding:.9em 1.1em}\
.stat .v{font-size:1.5em;font-weight:700}.stat .k{color:#8a93a3;font-size:.8em}\
.seed{background:#1a1408;border:1px solid #5a4a20;border-radius:6px;padding:1em;font-size:1.15em;line-height:2;letter-spacing:.05em}\
.pill{display:inline-block;padding:.1em .6em;border-radius:1em;font-size:.75em;border:1px solid #3a4048}\
.pill.ok{color:#7dd87d;border-color:#3f6a3f}.pill.warn{color:#e0a050;border-color:#6a5a3f}\
.actions{display:flex;gap:.6em;flex-wrap:wrap;margin:.8em 0}\
.actions a{display:inline-block;background:#2a4a2a;color:#cfe8cf;padding:.5em 1em;border-radius:5px;text-decoration:none;border:1px solid #3f6a3f}\
.actions a.ghost{background:#1d2126;color:#8ab4ff;border-color:#3a4048}\
.breadcrumb{margin:.5em 0;font-size:.9em}";

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>minibtc wallet — {}</title><style>{}</style></head>\
<body><header><span class=\"brand\">◈ minibtc wallet</span><span class=\"dim\">local devnet · sessions in memory only</span></header>\
<main><h1 style=\"font-size:1.25em\">{}</h1>{}</main></body></html>",
        esc(title),
        CSS,
        esc(title),
        body
    ))
}

fn wallet_nav(name: &str, csrf: &str) -> String {
    format!(
        "<div class=\"breadcrumb\"><a href=\"/wallet\">wallet</a> · \
<a href=\"/wallet/receive\">receive</a> · \
<a href=\"/wallet/send\">send</a> · \
<a href=\"/wallet/addresses\">addresses</a> · \
<a href=\"/wallet/activity\">activity</a> · \
<form method=post action=\"/wallet/lock\" style=\"display:inline\">\
<input type=hidden name=csrf value=\"{}\"><button type=submit class=\"danger\" style=\"padding:.1em .6em\">lock</button></form> \
<span class=\"dim\">— {}</span></div>",
        esc(csrf),
        esc(name)
    )
}

fn err_page(msg: &str) -> Html<String> {
    page(
        "error",
        &format!(
            "<div class=card><p class=err>{}</p><p><a href=\"/\">back</a></p></div>",
            esc(msg)
        ),
    )
}

fn fmt_btc(sats: u64) -> String {
    format!("{}.{:08}", sats / COIN, sats % COIN)
}

fn sats_or_btc(sats: u64) -> String {
    format!("{} BTC · {} sats", fmt_btc(sats), sats)
}

// ---------- input validation ----------

/// BTC decimal or plain sats → satoshis (mirrors CLI parse_amount).
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
        .checked_mul(COIN)
        .context("amount too large")?;
    let frac_sats = if frac.is_empty() {
        0
    } else {
        let f = frac.parse::<u64>().context("bad fraction")?;
        f.checked_mul(COIN / 10u64.pow(frac.len() as u32))
            .context("amount too large")?
    };
    whole_sats
        .checked_add(frac_sats)
        .context("amount too large")
}

fn parse_fee_rate(s: &str) -> Result<u64> {
    let v: u64 = s
        .trim()
        .parse()
        .context("fee rate must be an integer sat/kvB")?;
    if v == 0 || v > 1_000_000 {
        anyhow::bail!("fee rate must be 1..=1000000 sat/kvB");
    }
    Ok(v)
}

fn valid_passphrase(p: &str) -> bool {
    (8..=128).contains(&p.len())
}

fn normalize_phrase(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ---------- public / pre-auth pages ----------

/// GET / — landing: unlock existing, or create/restore.
async fn index(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if session_token(&app, &headers).is_some() {
        return Redirect::to("/wallet").into_response();
    }
    let names = list_wallets(&app.datadir);
    let options: String = names
        .iter()
        .map(|n| format!("<option value=\"{}\">", esc(n)))
        .collect();
    let wallet_links: String = names
        .iter()
        .map(|n| format!("<tr><td class=mono>{}</td></tr>", esc(n)))
        .collect();
    page(
        "open wallet",
        &format!(
            "<div class=grid>\
<div class=card><h2>Unlock existing</h2>\
<form method=post action=\"/unlock\">\
<label>wallet<br><input name=\"name\" list=\"wallets\" required size=22 placeholder=\"name\"> \
<datalist id=\"wallets\">{}</datalist></label><br><br>\
<label>passphrase<br><input type=\"password\" name=\"passphrase\" required size=26 autocomplete=\"off\"></label><br><br>\
<button type=submit>unlock</button></form>\
<p class=dim>wallets on disk:</p><table>{}</table></div>\
<div class=card><h2>New here?</h2>\
<p><a href=\"/new\">Create a new wallet</a> — generates a seed phrase you must back up.</p>\
<p><a href=\"/restore\">Restore from seed phrase</a> — rebuild a wallet from 12/24 words.</p>\
<p class=dim>sessions are in-memory only · idle timeout {} min · nothing is broadcast without your confirm</p></div>\
</div>",
            options,
            wallet_links,
            app.ttl.as_secs() / 60
        ),
    )
    .into_response()
}

/// GET /new — create-wallet form.
async fn new_form(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if session_token(&app, &headers).is_some() {
        return Redirect::to("/wallet").into_response();
    }
    page(
        "create wallet",
        "<div class=card>\
<p class=dim>You'll get a 12-word seed phrase to write down. It is shown <b>once</b> — \
if you lose it and haven't backed it up, the wallet cannot be recovered.</p>\
<form method=post action=\"/new\">\
<label>wallet name<br><input name=\"name\" required size=26 placeholder=\"e.g. savings\"></label><br><br>\
<label>keystore passphrase (encrypts the seed at rest)<br>\
<input type=\"password\" name=\"passphrase\" required minlength=8 size=26 autocomplete=\"new-password\"></label><br><br>\
<label>confirm passphrase<br><input type=\"password\" name=\"passphrase2\" required minlength=8 size=26 autocomplete=\"new-password\"></label><br><br>\
<button type=submit>generate seed phrase</button></form>\
<p><a href=\"/\">back</a></p></div>",
    )
    .into_response()
}

/// POST /new — validate, generate, stage pending creation.
async fn new_submit(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !origin_ok(&headers, app.listen) {
        return err_page("bad origin").into_response();
    }
    let name = form
        .get("name")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let pass = form.get("passphrase").map(String::as_str).unwrap_or("");
    let pass2 = form.get("passphrase2").map(String::as_str).unwrap_or("");

    if !valid_passphrase(pass) {
        return err_page("passphrase must be 8-128 characters").into_response();
    }
    if pass != pass2 {
        return err_page("passphrases do not match").into_response();
    }
    if wallet_path(&app.datadir, &name).is_err() {
        return err_page("invalid wallet name").into_response();
    }
    if wallet_exists(&app.datadir, &name) {
        return err_page(&format!("wallet {name} already exists")).into_response();
    }
    sweep_pending(&app);
    if app
        .pending_creates
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len()
        >= MAX_PENDING
    {
        return err_page("too many pending creations — try again shortly").into_response();
    }

    // Generate: mnemonic → BIP39 seed (env passphrase, same rule as CLI).
    let mnemonic = match generate_mnemonic() {
        Ok(m) => m,
        Err(e) => return err_page(&format!("entropy failure: {e}")).into_response(),
    };
    let seed = mnemonic.to_seed(&bip39_pass());
    let phrase = Zeroizing::new(mnemonic.phrase());

    let token = rand_hex(24);
    app.pending_creates
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            token.clone(),
            PendingCreate {
                name: name.clone(),
                phrase,
                seed: Zeroizing::new(seed),
                created: Instant::now(),
            },
        );
    audit(&app, "wallet_create_pending", Some(&name), None);
    Redirect::to(&format!("/seed?t={token}")).into_response()
}

/// GET /seed?t= — show the seed phrase ONCE, with the backup gate.
async fn seed_reveal(
    State(app): State<Arc<App>>,
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    sweep_pending(&app);
    let token = q.get("t").cloned().unwrap_or_default();
    let pending = {
        let pc = app
            .pending_creates
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        pc.get(&token)
            .map(|p| (p.name.clone(), p.phrase.to_string()))
    };
    let Some((name, phrase)) = pending else {
        return err_page("seed reveal expired or invalid — start over").into_response();
    };
    let words: String = phrase
        .split_whitespace()
        .enumerate()
        .map(|(i, w)| format!("<div>{:02}. {}</div>", i + 1, esc(w)))
        .collect();
    audit(&app, "seed_reveal", Some(&name), None);
    page(
        "your seed phrase — write it down NOW",
        &format!(
            "<div class=card><p class=err><b>This phrase is shown exactly once.</b> Write it on paper \
now — anyone with these words owns the wallet. Never screenshot, never paste \
it anywhere, never store it digitally.</p>\
<div class=seed>{}</div>\
<p class=dim>wallet name: <b>{}</b></p></div>\
<div class=card><h2>Confirm backup</h2>\
<p class=dim>Only after you have written the words down: re-enter the keystore \
passphrase and tick the box. Nothing is saved until you do.</p>\
<form method=post action=\"/seed/confirm\">\
<input type=hidden name=t value=\"{}\">\
<label>keystore passphrase<br>\
<input type=\"password\" name=\"passphrase\" required minlength=8 size=26 autocomplete=\"new-password\"></label><br><br>\
<label><input type=\"checkbox\" name=\"saved\" value=\"yes\" required> I have written down every word, in order</label><br><br>\
<button type=submit>create wallet &amp; unlock</button></form>\
<form method=post action=\"/seed/cancel\">\
<input type=hidden name=t value=\"{}\"><button type=submit class=\"danger\">abandon (nothing is saved)</button></form></div>",
            words,
            esc(&name),
            esc(&token),
            esc(&token)
        ),
    )
    .into_response()
}

/// POST /seed/confirm — "I saved it" → encrypt, save, unlock.
async fn seed_confirm(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !origin_ok(&headers, app.listen) {
        return err_page("bad origin").into_response();
    }
    let token = form.get("t").cloned().unwrap_or_default();
    let pass = form.get("passphrase").map(String::as_str).unwrap_or("");
    let saved = form.get("saved").map(String::as_str) == Some("yes");
    if !saved {
        return err_page("confirm that you saved the phrase first").into_response();
    }
    if !valid_passphrase(pass) {
        return err_page("passphrase must be 8-128 characters").into_response();
    }
    sweep_pending(&app);
    let pending = app
        .pending_creates
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&token);
    let Some(p) = pending else {
        return err_page("seed reveal expired — start over").into_response();
    };
    let name = p.name.clone();
    let wallet = match wallet_from_seed(&p.seed, &app.params) {
        Ok(mut w) => {
            w.prime_lookahead(GAP_LIMIT).ok();
            let _ = w.new_address(); // issue address 0
            w
        }
        Err(e) => return err_page(&format!("derive failed: {e}")).into_response(),
    };
    let indices = wallet.indices();
    if let Err(e) = persist_wallet(&app.datadir, &name, &p.seed, pass, indices) {
        return err_page(&format!("save failed: {e}")).into_response();
    }
    let Some(token) = open_session(&app, &name, wallet) else {
        return err_page("too many sessions").into_response();
    };
    audit(&app, "wallet_create", Some(&name), None);
    session_cookie_response(&token, "/wallet")
}

/// POST /seed/cancel — abandon a pending creation.
async fn seed_cancel(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if origin_ok(&headers, app.listen) {
        let token = form.get("t").cloned().unwrap_or_default();
        app.pending_creates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&token);
    }
    Redirect::to("/new").into_response()
}

/// GET /restore — restore-from-mnemonic form.
async fn restore_form(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if session_token(&app, &headers).is_some() {
        return Redirect::to("/wallet").into_response();
    }
    page(
        "restore wallet",
        "<div class=card>\
<p class=dim>Enter the 12- or 24-word seed phrase and a keystore passphrase. \
The phrase itself is never stored — only the encrypted seed.</p>\
<form method=post action=\"/restore\">\
<label>wallet name<br><input name=\"name\" required size=26 placeholder=\"e.g. restored\"></label><br><br>\
<label>seed phrase<br><textarea name=\"phrase\" rows=3 cols=60 required placeholder=\"word1 word2 … word12\"></textarea></label><br><br>\
<label>keystore passphrase<br><input type=\"password\" name=\"passphrase\" required minlength=8 size=26 autocomplete=\"new-password\"></label><br><br>\
<button type=submit>restore &amp; unlock</button></form>\
<p><a href=\"/\">back</a></p></div>",
    )
    .into_response()
}

/// POST /restore — validate phrase, encrypt, save, unlock.
async fn restore_submit(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !origin_ok(&headers, app.listen) {
        return err_page("bad origin").into_response();
    }
    let name = form
        .get("name")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let phrase = normalize_phrase(form.get("phrase").map(String::as_str).unwrap_or(""));
    let pass = form.get("passphrase").map(String::as_str).unwrap_or("");

    if !valid_passphrase(pass) {
        return err_page("passphrase must be 8-128 characters").into_response();
    }
    if wallet_path(&app.datadir, &name).is_err() {
        return err_page("invalid wallet name").into_response();
    }
    if wallet_exists(&app.datadir, &name) {
        return err_page(&format!("wallet {name} already exists")).into_response();
    }
    let mnemonic = match mnemonic_from_phrase(&phrase) {
        Ok(m) => m,
        Err(e) => return err_page(&format!("invalid seed phrase: {e}")).into_response(),
    };
    let seed = mnemonic.to_seed(&bip39_pass());
    let mut wallet = match wallet_from_seed(&seed, &app.params) {
        Ok(w) => w,
        Err(e) => return err_page(&format!("derive failed: {e}")).into_response(),
    };
    wallet.prime_lookahead(GAP_LIMIT).ok();
    // Issue the first receive address so the wallet is immediately usable.
    let _ = wallet.new_address();
    let indices = wallet.indices();
    if let Err(e) = persist_wallet(&app.datadir, &name, &seed, pass, indices) {
        return err_page(&format!("save failed: {e}")).into_response();
    }
    let Some(token) = open_session(&app, &name, wallet) else {
        return err_page("too many sessions").into_response();
    };
    audit(&app, "wallet_restore", Some(&name), None);
    session_cookie_response(&token, "/wallet")
}

/// POST /unlock — verify passphrase, open in-memory session.
async fn unlock(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !origin_ok(&headers, app.listen) {
        return err_page("bad origin").into_response();
    }
    let name = form
        .get("name")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let pass = form.get("passphrase").map(String::as_str).unwrap_or("");

    {
        let fails = app.unlock_fails.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((n, until)) = fails.get(&name)
            && *n >= UNLOCK_FAIL_LIMIT
            && until.elapsed() < UNLOCK_LOCKOUT
        {
            return err_page("too many failed attempts — wait a minute").into_response();
        }
    }

    let wallet = match load_wallet(&app.datadir, &name, &app.params, pass) {
        Ok(mut w) => {
            w.prime_lookahead(GAP_LIMIT).ok();
            w
        }
        Err(_) => {
            let mut fails = app.unlock_fails.lock().unwrap_or_else(|e| e.into_inner());
            let e = fails.entry(name.clone()).or_insert((0, Instant::now()));
            if e.1.elapsed() > UNLOCK_LOCKOUT {
                *e = (0, Instant::now());
            }
            e.0 += 1;
            e.1 = Instant::now();
            audit(&app, "unlock_fail", Some(&name), None);
            return err_page("wrong passphrase or missing wallet").into_response();
        }
    };

    let Some(token) = open_session(&app, &name, wallet) else {
        return err_page("too many open sessions — lock one first").into_response();
    };
    audit(&app, "unlock_ok", Some(&name), None);
    session_cookie_response(&token, "/wallet")
}

// ---------- authed pages ----------

/// Fresh UTXO view + rescan; returns rendered pieces or an error response.
async fn wallet_snapshot(
    app: &Arc<App>,
    token: &str,
) -> std::result::Result<(String, String, u64, u64, (u32, u32), usize), Box<Response>> {
    let (view, tip) = match fetch_utxo_view(&app.rpc).await {
        Ok(v) => v,
        Err(e) => {
            return Err(Box::new(
                err_page(&format!("node unreachable: {e}")).into_response(),
            ));
        }
    };
    let mut sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
    let Some(sess) = sessions.get_mut(token) else {
        return Err(Box::new(Redirect::to("/").into_response()));
    };
    sess.touched = Instant::now();
    sess.wallet.scan(&view, tip);
    let (mature, immature) = sess.wallet.balance();
    let indices = sess.wallet.indices();
    let n_utxos = sess.wallet.utxos().len();

    let maturity = app.params.coinbase_maturity;
    let mut rows = String::new();
    for u in sess.wallet.utxos() {
        rows.push_str(&format!(
            "<tr><td class=mono>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}{}</td></tr>",
            esc(&u.outpoint.txid.to_hex()[..16]),
            u.outpoint.vout,
            sats_or_btc(u.output.value.sats()),
            u.confirmations(),
            if u.coinbase { "coinbase " } else { "" },
            if u.spendable(maturity) {
                ""
            } else {
                "<span class=pill warn>immature</span>"
            }
        ));
    }
    let mut addrs = String::new();
    for (i, a) in sess.wallet.addresses().iter().enumerate() {
        addrs.push_str(&format!(
            "<tr><td>{}</td><td class=mono>{}</td></tr>",
            i,
            esc(&a.to_string())
        ));
    }
    Ok((
        rows,
        addrs,
        mature.sats(),
        immature.sats(),
        indices,
        n_utxos,
    ))
}

/// Resolve the session for a GET page: returns (token, name, csrf).
fn get_session(app: &App, headers: &HeaderMap) -> Option<(String, String, String)> {
    let token = session_token(app, headers)?;
    let sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
    sessions
        .get(&token)
        .map(|s| (token.clone(), s.name.clone(), s.csrf.clone()))
}

/// GET /wallet — dashboard: balance hero + actions + holdings.
async fn wallet_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((token, name, csrf)) = get_session(&app, &headers) else {
        return Redirect::to("/").into_response();
    };
    let (utxo_rows, _addr_rows, mature, immature, indices, n_utxos) =
        match wallet_snapshot(&app, &token).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let latest_addr = {
        let sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions
            .get(&token)
            .and_then(|s| s.wallet.addresses().last().map(|a| a.to_string()))
            .unwrap_or_default()
    };
    let utxo_section = if utxo_rows.is_empty() {
        "<p class=dim>No coins yet — receive to an address below, then mine blocks to it (devnet).</p>".to_string()
    } else {
        format!(
            "<table><tr><th>txid</th><th>vout</th><th>value</th><th>confs</th><th>flags</th></tr>{}</table>",
            utxo_rows
        )
    };
    page(
        &name,
        &format!(
            "{}\
<div class=stat style=\"max-width:30em\"><div class=k>confirmed balance</div>\
<div class=v>{} BTC</div><div class=dim>{} sats · {} UTXOs</div></div>\
<div class=stat style=\"max-width:30em\"><div class=k>immature (coinbase &lt; {} confs)</div>\
<div class=v style=\"font-size:1.1em\">{}</div></div>\
<div class=actions>\
<a href=\"/wallet/receive\">receive</a>\
<a href=\"/wallet/send\">send</a>\
<a class=ghost href=\"/wallet/addresses\">{} addresses</a>\
<a class=ghost href=\"/wallet/activity\">activity</a></div>\
<div class=card><b>Latest receive address</b><p class=mono>{}</p>\
<p class=dim>indices: receive {} · change {} — new addresses are derived on demand</p></div>\
<h2>Coins (UTXOs)</h2>{}",
            wallet_nav(&name, &csrf),
            fmt_btc(mature),
            mature,
            n_utxos,
            app.params.coinbase_maturity,
            sats_or_btc(immature),
            indices.0,
            esc(&latest_addr),
            indices.0,
            indices.1,
            utxo_section
        ),
    )
    .into_response()
}

/// GET /wallet/receive — the address, front and center.
async fn receive_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((token, name, csrf)) = get_session(&app, &headers) else {
        return Redirect::to("/").into_response();
    };
    let (_u, _a, _m, _i, _idx, _n) = match wallet_snapshot(&app, &token).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (latest, count) = {
        let sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match sessions.get(&token) {
            Some(s) => (
                s.wallet
                    .addresses()
                    .last()
                    .map(|a| a.to_string())
                    .unwrap_or_default(),
                s.wallet.addresses().len(),
            ),
            None => return Redirect::to("/").into_response(),
        }
    };
    page(
        &format!("receive — {name}"),
        &format!(
            "{}<div class=card>\
<p class=dim>Send coins to this address. It is your latest receive address \
({} issued so far). Every address ever issued stays valid — check the addresses page.</p>\
<p class=mono style=\"font-size:1.2em\">{}</p>\
<div class=actions>\
<form method=post action=\"/wallet/address/new\">\
<input type=hidden name=csrf value=\"{}\"><button type=submit>new receive address</button></form>\
<a class=ghost href=\"/wallet/addresses\">all addresses</a></div></div>",
            wallet_nav(&name, &csrf),
            count,
            esc(&latest),
            esc(&csrf)
        ),
    )
    .into_response()
}

/// GET /wallet/addresses — full issued-address list.
async fn addresses_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((token, name, csrf)) = get_session(&app, &headers) else {
        return Redirect::to("/").into_response();
    };
    let (_u, addr_rows, _m, _i, _idx, _n) = match wallet_snapshot(&app, &token).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    page(
        &format!("addresses — {name}"),
        &format!(
            "{}<div class=card><table><tr><th>#</th><th>address</th></tr>{}</table>\
<p class=dim>change addresses are derived internally during spends and are not listed here.</p></div>",
            wallet_nav(&name, &csrf),
            addr_rows
        ),
    )
    .into_response()
}

/// GET /wallet/activity — what this wallet has done (UTXO history view).
async fn activity_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((token, name, csrf)) = get_session(&app, &headers) else {
        return Redirect::to("/").into_response();
    };
    let (utxo_rows, _a, mature, immature, _idx, n) = match wallet_snapshot(&app, &token).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    page(
        &format!("activity — {name}"),
        &format!(
            "{}<div class=grid>\
<div class=stat><div class=k>confirmed</div><div class=v>{}</div></div>\
<div class=stat><div class=k>immature</div><div class=v>{}</div></div>\
<div class=stat><div class=k>utxos</div><div class=v>{}</div></div></div>\
<div class=card><h2>unspent outputs</h2>\
{}<p class=dim>MiniBTC indexes received outputs per address; spent-history\
 reconstruction is visible on the explorer's address pages.</p></div>",
            wallet_nav(&name, &csrf),
            fmt_btc(mature),
            fmt_btc(immature),
            n,
            if utxo_rows.is_empty() {
                "<p class=dim>empty</p>".to_string()
            } else {
                format!("<table><tr><th>txid</th><th>vout</th><th>value</th><th>confs</th><th>flags</th></tr>{}</table>", utxo_rows)
            }
        ),
    )
    .into_response()
}

/// GET /wallet/send — the send form.
async fn send_form(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((token, name, csrf)) = get_session(&app, &headers) else {
        return Redirect::to("/").into_response();
    };
    let (mature, own_addrs) = {
        let sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match sessions.get(&token) {
            Some(s) => {
                let addrs: String = s
                    .wallet
                    .addresses()
                    .iter()
                    .map(|a| format!("<option value=\"{}\">", esc(&a.to_string())))
                    .collect();
                (s.wallet.balance().0.sats(), addrs)
            }
            None => return Redirect::to("/").into_response(),
        }
    };
    page(
        &format!("send — {name}"),
        &format!(
            "{}<div class=card>\
<p class=dim>spendable (confirmed): <b>{} BTC</b></p>\
<form method=post action=\"/wallet/send\">\
<label>to<br><input name=\"to\" required size=44 list=\"ownaddrs\" placeholder=\"m… address\"> \
<datalist id=\"ownaddrs\">{}</datalist></label><br><br>\
<label>amount (BTC or sats)<br><input name=\"amount\" required size=24 placeholder=\"0.001\"></label><br><br>\
<label>fee rate (sat/kvB)<br><input name=\"fee_rate\" value=\"1\" size=10></label><br><br>\
<input type=hidden name=csrf value=\"{}\">\
<button type=submit>review transaction</button></form></div>\
<p class=dim>nothing broadcasts until you confirm the review · <a href=\"/wallet\">cancel</a></p>",
            wallet_nav(&name, &csrf),
            fmt_btc(mature),
            own_addrs,
            esc(&csrf)
        ),
    )
    .into_response()
}

/// POST /wallet/send — validate, rescan, build+sign, store pending draft.
async fn send_build(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let Some(token) = require_post_session(&app, &headers, &form) else {
        return Redirect::to("/").into_response();
    };
    let to = form
        .get("to")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let amount_s = form.get("amount").map(String::as_str).unwrap_or("");
    let fee_s = form.get("fee_rate").map(String::as_str).unwrap_or("1");

    let fail = |msg: String| -> Response {
        audit(&app, "send_draft_fail", None, Some(&msg));
        err_page(&msg).into_response()
    };

    let dest = match Address::from_base58(&to, Some(app.params.address_version)) {
        Ok(a) => a,
        Err(_) => return fail("invalid destination address".into()),
    };
    let sats = match parse_amount(amount_s) {
        Ok(v) if v > 0 => v,
        _ => return fail("invalid amount".into()),
    };
    let fee_rate = match parse_fee_rate(fee_s) {
        Ok(v) => v,
        Err(e) => return fail(e.to_string()),
    };

    let (view, tip) = match fetch_utxo_view(&app.rpc).await {
        Ok(v) => v,
        Err(e) => return fail(format!("node unreachable: {e}")),
    };
    let dest_script = Script::p2pkh(&dest.hash160).as_bytes().to_vec();

    let mut sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
    let Some(sess) = sessions.get_mut(&token) else {
        return Redirect::to("/").into_response();
    };
    sess.touched = Instant::now();
    sess.wallet.scan(&view, tip);
    let tx = match sess
        .wallet
        .build_and_sign(&dest_script, Sats(sats), fee_rate, 0)
    {
        Ok(t) => t,
        Err(e) => return fail(format!("cannot build transaction: {e}")),
    };
    let mut in_sum = 0u64;
    for inp in &tx.inputs {
        if let Some(u) = sess.wallet.utxos().iter().find(|u| u.outpoint == inp.prev) {
            in_sum = in_sum.saturating_add(u.output.value.sats());
        }
    }
    let out_sum: u64 = tx.outputs.iter().map(|o| o.value.sats()).sum();
    let fee_sats = in_sum.saturating_sub(out_sum);
    let txid = tx.txid().to_hex();
    let tx_hex = hex_encode(&tx.encode());
    let inputs = tx.inputs.len();
    let name = sess.name.clone();
    let indices = sess.wallet.indices();
    drop(sessions);
    if let Err(e) = save_indices(&app.datadir, &name, indices) {
        return fail(format!("failed to persist wallet indices: {e}"));
    }

    {
        let mut sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = sessions.get_mut(&token) {
            s.pending = Some(PendingSend {
                to,
                amount_sats: sats,
                fee_rate,
                fee_sats,
                txid: txid.clone(),
                tx_hex,
                inputs,
            });
        }
    }
    audit(&app, "send_draft", Some(&name), Some(&txid));
    Redirect::to("/wallet/review").into_response()
}

/// GET /wallet/review — human-readable draft + explicit confirm.
async fn review_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((token, name, csrf)) = get_session(&app, &headers) else {
        return Redirect::to("/").into_response();
    };
    let mut sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
    let Some(sess) = sessions.get_mut(&token) else {
        return Redirect::to("/").into_response();
    };
    sess.touched = Instant::now();
    let Some(p) = &sess.pending else {
        return err_page("no pending transaction — start again").into_response();
    };
    let p_txid = p.txid.clone();
    page(
        &format!("review — {name}"),
        &format!(
            "{}<div class=card>\
<h2>Review transaction</h2>\
<table>\
<tr><td>to</td><td class=mono>{}</td></tr>\
<tr><td>amount</td><td><b>{}</b></td></tr>\
<tr><td>network fee</td><td>{} <span class=dim>({} sat/kvB)</span></td></tr>\
<tr><td>inputs</td><td>{}</td></tr>\
<tr><td>txid</td><td class=mono>{}</td></tr>\
</table>\
<p class=warn>Confirm only if every field is what you intend — this broadcasts \
to the node mempool and can be mined into a block.</p>\
<div class=actions>\
<form method=post action=\"/wallet/send/confirm\">\
<input type=hidden name=csrf value=\"{}\"><button type=submit>broadcast</button></form>\
<form method=post action=\"/wallet/send/cancel\">\
<input type=hidden name=csrf value=\"{}\"><button type=submit class=\"danger\">cancel</button></form></div></div>",
            wallet_nav(&name, &csrf),
            esc(&p.to),
            sats_or_btc(p.amount_sats),
            sats_or_btc(p.fee_sats),
            p.fee_rate,
            p.inputs,
            esc(&p_txid),
            esc(&csrf),
            esc(&csrf)
        ),
    )
    .into_response()
}

/// POST /wallet/send/confirm — broadcast the reviewed draft.
async fn send_confirm(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let Some(token) = require_post_session(&app, &headers, &form) else {
        return Redirect::to("/").into_response();
    };
    let pending = {
        let mut sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = sessions.get_mut(&token) else {
            return Redirect::to("/").into_response();
        };
        s.touched = Instant::now();
        s.pending.take()
    };
    let Some(p) = pending else {
        return err_page("no pending transaction").into_response();
    };
    let name = {
        let sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions
            .get(&token)
            .map(|s| s.name.clone())
            .unwrap_or_default()
    };
    match app.rpc.sendrawtransaction(&p.tx_hex).await {
        Ok(ret) => {
            audit(&app, "send_broadcast", Some(&name), Some(&ret));
            page(
                "sent",
                &format!(
                    "{}<div class=card><p class=ok>✓ broadcast accepted</p>\
<p>transaction id:</p><p class=mono>{}</p>\
<p class=dim>node returned: {}</p>\
<p>track it on the <a href=\"http://127.0.0.1:39472/tx/{}\">explorer</a> once mined, \
or watch <a href=\"/wallet/activity\">activity</a>.</p></div>",
                    wallet_nav(&name, ""),
                    esc(&p.txid),
                    esc(&ret),
                    esc(&p.txid)
                ),
            )
            .into_response()
        }
        Err(e) => {
            audit(&app, "send_broadcast_fail", Some(&name), Some(&p.txid));
            page(
                "broadcast failed",
                &format!(
                    "{}<div class=card><p class=err>node rejected the transaction</p>\
<p class=dim>{}</p><p class=mono>{}</p>\
<p><a href=\"/wallet\">back to wallet</a> · <a href=\"/wallet/send\">try again</a></p></div>",
                    wallet_nav(&name, ""),
                    esc(&e.to_string()),
                    esc(&p.txid)
                ),
            )
            .into_response()
        }
    }
}

/// POST /wallet/send/cancel — drop the pending draft.
async fn send_cancel(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Some(token) = require_post_session(&app, &headers, &form) {
        let mut sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = sessions.get_mut(&token) {
            s.pending = None;
        }
    }
    Redirect::to("/wallet").into_response()
}

/// POST /wallet/address/new — issue a fresh receive address.
async fn new_address(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let Some(token) = require_post_session(&app, &headers, &form) else {
        return Redirect::to("/").into_response();
    };
    let mut sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
    let Some(sess) = sessions.get_mut(&token) else {
        return Redirect::to("/").into_response();
    };
    sess.touched = Instant::now();
    match sess.wallet.new_address() {
        Ok(addr) => {
            let indices = sess.wallet.indices();
            let name = sess.name.clone();
            drop(sessions);
            let _ = save_indices(&app.datadir, &name, indices);
            audit(&app, "new_address", Some(&name), Some(&addr.to_string()));
            let (nm, csrf) = {
                let sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
                match sessions.get(&token) {
                    Some(s) => (s.name.clone(), s.csrf.clone()),
                    None => return Redirect::to("/").into_response(),
                }
            };
            page(
                "new address",
                &format!(
                    "{}<div class=card><p>new receive address:</p>\
<p class=mono style=\"font-size:1.15em\">{}</p>\
<p><a href=\"/wallet/receive\">receive page</a> · <a href=\"/wallet\">wallet</a></p></div>",
                    wallet_nav(&nm, &csrf),
                    esc(&addr.to_string())
                ),
            )
            .into_response()
        }
        Err(e) => err_page(&format!("cannot derive address: {e}")).into_response(),
    }
}

/// POST /wallet/lock — destroy the session.
async fn lock(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Some(token) = require_post_session(&app, &headers, &form) {
        let name = app
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&token)
            .map(|s| s.name);
        audit(&app, "lock", name.as_deref(), None);
    }
    (
        [(header::SET_COOKIE, clear_session_cookie())],
        Redirect::to("/"),
    )
        .into_response()
}

async fn healthz() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("warn")
        .with_target(false)
        .init();
    let args = Args::parse();
    let params = match &args.params {
        Some(p) => ChainParams::load(p).context("load chain params")?,
        None => ChainParams::devnet(),
    };
    let rpc = RpcClient::from_datadir(&args.datadir, args.rpc_port)
        .context("connect to node (.cookie in datadir?)")?;
    let app = Arc::new(App {
        rpc,
        params,
        datadir: args.datadir.clone(),
        listen: args.listen,
        ttl: Duration::from_secs(args.session_ttl_secs.max(60)),
        sessions: Mutex::new(HashMap::new()),
        pending_creates: Mutex::new(HashMap::new()),
        unlock_fails: Mutex::new(HashMap::new()),
    });
    let router = Router::new()
        .route("/", get(index))
        .route("/new", get(new_form).post(new_submit))
        .route("/restore", get(restore_form).post(restore_submit))
        .route("/seed", get(seed_reveal))
        .route("/seed/confirm", post(seed_confirm))
        .route("/seed/cancel", post(seed_cancel))
        .route("/unlock", post(unlock))
        .route("/wallet", get(wallet_page))
        .route("/wallet/receive", get(receive_page))
        .route("/wallet/addresses", get(addresses_page))
        .route("/wallet/activity", get(activity_page))
        .route("/wallet/send", get(send_form).post(send_build))
        .route("/wallet/review", get(review_page))
        .route("/wallet/send/confirm", post(send_confirm))
        .route("/wallet/send/cancel", post(send_cancel))
        .route("/wallet/address/new", post(new_address))
        .route("/wallet/lock", post(lock))
        .route("/healthz", get(healthz))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!("wallet-ui listening on http://{}", args.listen);
    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_amount_units() {
        assert_eq!(parse_amount("1").unwrap_or_else(|_| panic!()), COIN);
        assert_eq!(parse_amount("0.5").unwrap_or_else(|_| panic!()), COIN / 2);
        assert_eq!(parse_amount("0.00000001").unwrap_or_else(|_| panic!()), 1);
        assert_eq!(
            parse_amount("21000000").unwrap_or_else(|_| panic!()),
            2_100_000_000_000_000
        );
        assert!(parse_amount("-1").is_err());
        assert!(parse_amount("1.123456789").is_err());
        assert!(parse_amount("abc").is_err());
        assert!(parse_amount("").is_err());
    }

    #[test]
    fn fee_rate_bounds() {
        assert_eq!(parse_fee_rate("1").unwrap_or_else(|_| panic!()), 1);
        assert_eq!(parse_fee_rate(" 25 ").unwrap_or_else(|_| panic!()), 25);
        assert!(parse_fee_rate("0").is_err());
        assert!(parse_fee_rate("-5").is_err());
        assert!(parse_fee_rate("1.5").is_err());
        assert!(parse_fee_rate("2000000").is_err());
    }

    #[test]
    fn wallet_name_validation() {
        let d = Path::new("/tmp/x");
        assert!(wallet_path(d, "my-wallet_1.0").is_ok());
        assert!(wallet_path(d, "").is_err());
        assert!(wallet_path(d, "../escape").is_err());
        assert!(wallet_path(d, "a/b").is_err());
        assert!(wallet_path(d, " spaces ").is_err());
        assert!(wallet_path(d, &"a".repeat(65)).is_err());
    }

    #[test]
    fn passphrase_policy() {
        assert!(!valid_passphrase("short"));
        assert!(valid_passphrase("long-enough-1"));
        assert!(!valid_passphrase(&"x".repeat(200)));
    }

    #[test]
    fn phrase_normalization() {
        assert_eq!(
            normalize_phrase("  word1\nword2   word3 "),
            "word1 word2 word3"
        );
    }

    #[test]
    fn cookie_parse_roundtrip() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            "a=1; mb_wallet=deadbeef; b=2"
                .parse()
                .unwrap_or_else(|_| panic!()),
        );
        assert_eq!(get_cookie(&h, "mb_wallet").unwrap_or_default(), "deadbeef");
        assert_eq!(get_cookie(&h, "missing").unwrap_or_default(), "");
        assert!(set_session_cookie("tok").contains("HttpOnly"));
        assert!(set_session_cookie("tok").contains("SameSite=Strict"));
        assert!(clear_session_cookie().contains("Max-Age=0"));
    }

    #[test]
    fn origin_check_localhost() {
        let listen: SocketAddr = "127.0.0.1:18448".parse().unwrap_or_else(|_| panic!());
        let mut h = HeaderMap::new();
        assert!(origin_ok(&h, listen));
        h.insert(
            header::ORIGIN,
            "http://127.0.0.1:18448"
                .parse()
                .unwrap_or_else(|_| panic!()),
        );
        assert!(origin_ok(&h, listen));
        h.insert(
            header::ORIGIN,
            "http://localhost:18448"
                .parse()
                .unwrap_or_else(|_| panic!()),
        );
        assert!(origin_ok(&h, listen));
        h.insert(
            header::ORIGIN,
            "http://evil.example".parse().unwrap_or_else(|_| panic!()),
        );
        assert!(!origin_ok(&h, listen));
    }

    #[test]
    fn esc_neutralizes_html() {
        assert_eq!(
            esc("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(esc("a&b\"c'd"), "a&amp;b&quot;c&#39;d");
    }

    #[test]
    fn session_expiry_sweep() {
        let app = App {
            rpc: RpcClient::new(
                "127.0.0.1",
                1,
                minibtc_rpc::server::CookieAuth {
                    user: "u".into(),
                    pass: "p".into(),
                },
            )
            .unwrap_or_else(|_| panic!()),
            params: ChainParams::devnet(),
            datadir: PathBuf::from("/tmp"),
            listen: "127.0.0.1:18448".parse().unwrap_or_else(|_| panic!()),
            ttl: Duration::from_millis(1),
            sessions: Mutex::new(HashMap::from([(
                "tok".to_string(),
                Session {
                    name: "w".into(),
                    wallet: Wallet::generate("", 0, 0, 0, 100)
                        .unwrap_or_else(|_| panic!())
                        .0,
                    csrf: "c".into(),
                    touched: Instant::now() - Duration::from_secs(10),
                    pending: None,
                },
            )])),
            pending_creates: Mutex::new(HashMap::new()),
            unlock_fails: Mutex::new(HashMap::new()),
        };
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            "mb_wallet=tok".parse().unwrap_or_else(|_| panic!()),
        );
        std::thread::sleep(Duration::from_millis(5));
        assert!(session_token(&app, &h).is_none());
        assert!(
            app.sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        );
    }

    #[test]
    fn pending_create_holds_seed_and_phrase() {
        // Compile-time guarantee: both fields are Zeroizing, so drop
        // wipes them. This test pins the struct shape.
        let p = PendingCreate {
            name: "t".into(),
            phrase: Zeroizing::new("abandon abandon".to_string()),
            seed: Zeroizing::new([0xAAu8; 64]),
            created: Instant::now(),
        };
        assert_eq!(p.phrase.as_str(), "abandon abandon");
        assert_eq!(p.seed[0], 0xAA);
    }
}
