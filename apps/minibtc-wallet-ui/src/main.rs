//! minibtc-wallet-ui — a local web wallet for MiniBTC (decision D-011).
//!
//! Security contract (stricter than the read-only explorer):
//! - The passphrase unlocks an **in-memory** session only; it is never
//!   persisted, logged, or echoed back.
//! - Sessions live in a server-side map keyed by a random token carried
//!   in an HttpOnly SameSite=Strict cookie. Idle TTL, bounded count.
//! - Every POST requires the per-session CSRF token plus an Origin check.
//! - Seeds, xprvs, private keys can never appear in any response — only
//!   addresses, balances, txids and summaries.
//! - Spending is two-step: build+sign → human-readable review → explicit
//!   confirm → broadcast. Nothing is sent on the first POST.
//! - Audit log (`<datadir>/wallet-ui-audit.jsonl`) records events with
//!   no secrets.
//!
//! Binds localhost by default. Wallet create/restore stays CLI-only.

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
use minibtc_wallet::keystore::Keystore;
use minibtc_wallet::wallet::IterableUtxos;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const GAP_LIMIT: u32 = 25;
const COIN_TYPE: u32 = 0;
const ACCOUNT: u32 = 0;
const BIP39_ENV: &str = "MINIBTC_MNEMONIC_PASSPHRASE";
const SESSION_COOKIE: &str = "mb_wallet";
const MAX_SESSIONS: usize = 32;
const UNLOCK_FAIL_LIMIT: u32 = 5;
const UNLOCK_LOCKOUT: Duration = Duration::from_secs(60);
const COIN: u64 = 100_000_000;

#[derive(clap::Parser, Debug)]
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

struct App {
    rpc: RpcClient,
    params: ChainParams,
    datadir: PathBuf,
    listen: SocketAddr,
    ttl: Duration,
    sessions: Mutex<HashMap<String, Session>>,
    /// wallet name → (consecutive failures, locked-until)
    unlock_fails: Mutex<HashMap<String, (u32, Instant)>>,
}

// ---------- wallet file helpers (mirror apps/minibtc-cli) ----------

fn wallet_path(datadir: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        anyhow::bail!("invalid wallet name {name:?}");
    }
    Ok(datadir.join("wallets").join(format!("{name}.wallet")))
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
    let bip39_pass = std::env::var(BIP39_ENV).unwrap_or_default();
    let mut w = Wallet::from_seed(
        seed.expose(),
        &bip39_pass,
        COIN_TYPE,
        ACCOUNT,
        params.address_version,
        params.coinbase_maturity,
    )
    .context("derive wallet")?;
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

// ---------- HTML helpers ----------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
<title>minibtc wallet — {}</title><style>\
body{{font-family:ui-monospace,Menlo,monospace;margin:2em auto;max-width:60em;color:#ddd;background:#14161a}}\
a{{color:#7db4ff}}table{{border-collapse:collapse;width:100%;margin:.6em 0}}\
td,th{{border-bottom:1px solid #2a2e35;padding:.25em .6em;text-align:left;font-size:.85em}}\
th{{color:#8a93a3}}.dim{{color:#8a93a3}}form{{margin:.8em 0}}\
input,button{{background:#1d2126;color:#ddd;border:1px solid #3a4048;padding:.35em .6em;font:inherit}}\
button{{cursor:pointer;background:#2a4a2a}}.warn{{color:#e0a050}}.ok{{color:#7dd87d}}\
.err{{color:#e07070}}h1{{font-size:1.3em}}.mono{{font-family:ui-monospace,monospace}}\
.card{{background:#1a1d22;border:1px solid #2a2e35;padding:1em;margin:1em 0}}\
</style></head><body><div class=\"dim\">minibtc wallet · local session · \u{26a0} devnet \u{2014} never reuse seed material here</div>\
<h1>{}</h1>{}</body></html>",
        esc(title),
        esc(title),
        body
    ))
}

fn err_page(msg: &str) -> Html<String> {
    page(
        "error",
        &format!(
            "<p class=\"err\">{}</p><p><a href=\"/\">back</a></p>",
            esc(msg)
        ),
    )
}

fn fmt_btc(sats: u64) -> String {
    format!("{}.{:08} BTC ({} sats)", sats / COIN, sats % COIN, sats)
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

// ---------- handlers ----------

/// GET / — unlock page listing wallet files (or bounce into a live session).
async fn index(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if session_token(&app, &headers).is_some() {
        return Redirect::to("/wallet").into_response();
    }
    // If a live session exists, go straight to the wallet.
    let names = list_wallets(&app.datadir);
    let options: String = names
        .iter()
        .map(|n| format!("<option value=\"{}\">", esc(n)))
        .collect();
    let rows: String = names
        .iter()
        .map(|n| format!("<tr><td class=mono>{}</td></tr>", esc(n)))
        .collect();
    page(
        "unlock wallet",
        &format!(
            "<div class=card><form method=post action=\"/unlock\">\
<label>wallet <input name=\"name\" list=\"wallets\" required size=20 placeholder=\"name\"> \
<datalist id=\"wallets\">{}</datalist></label><br><br>\
<label>passphrase <input type=\"password\" name=\"passphrase\" required size=30 autocomplete=\"off\"></label><br><br>\
<button type=submit>unlock (in-memory session)</button></form></div>\
<p class=dim>wallets on disk:</p><table>{}</table>\
<p class=dim>sessions expire after {} min idle · passphrase is never stored or shown again</p>",
            options,
            rows,
            app.ttl.as_secs() / 60
        ),
    )
    .into_response()
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

    // Rate limit per wallet name.
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

    if app.sessions.lock().unwrap_or_else(|e| e.into_inner()).len() >= MAX_SESSIONS {
        return err_page("too many open sessions — lock one first").into_response();
    }
    let token = rand_hex(32);
    let csrf = rand_hex(16);
    app.sessions
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            token.clone(),
            Session {
                name: name.clone(),
                wallet,
                csrf,
                touched: Instant::now(),
                pending: None,
            },
        );
    audit(&app, "unlock_ok", Some(&name), None);
    (
        [(header::SET_COOKIE, set_session_cookie(&token))],
        Redirect::to("/wallet"),
    )
        .into_response()
}

/// Shared: fetch fresh UTXO view, rescan the session wallet, return
/// (balance, utxo rows html, addresses html) — or an error page.
async fn wallet_snapshot(
    app: &Arc<App>,
    token: &str,
) -> std::result::Result<(String, String, u64, u64, (u32, u32)), Box<Response>> {
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

    let maturity = app.params.coinbase_maturity;
    let mut rows = String::new();
    for u in sess.wallet.utxos() {
        rows.push_str(&format!(
            "<tr><td class=mono>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}{}</td></tr>",
            esc(&u.outpoint.txid.to_hex()[..16]),
            u.outpoint.vout,
            fmt_btc(u.output.value.sats()),
            u.confirmations(),
            if u.coinbase { "coinbase " } else { "" },
            if u.spendable(maturity) {
                ""
            } else {
                "<span class=warn>immature</span>"
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
    Ok((rows, addrs, mature.sats(), immature.sats(), indices))
}

/// GET /wallet — dashboard.
async fn wallet_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some(token) = session_token(&app, &headers) else {
        return Redirect::to("/").into_response();
    };
    let (utxo_rows, addr_rows, mature, immature, indices) =
        match wallet_snapshot(&app, &token).await {
            Ok(v) => v,
            Err(r) => return *r,
        };
    let (name, n_utxos, csrf) = {
        let sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let s = sessions.get(&token);
        match s {
            Some(s) => (s.name.clone(), s.wallet.utxos().len(), s.csrf.clone()),
            None => return Redirect::to("/").into_response(),
        }
    };
    let _ = n_utxos;
    page(
        &format!("wallet: {name}"),
        &format!(
            "<div class=card>\
<p><b>mature balance:</b> {} &nbsp;·&nbsp; <b>immature:</b> {} &nbsp;·&nbsp; \
indices: receive {} / change {}</p>\
<p><a href=\"/wallet/addresses\">addresses</a> · \
<a href=\"/wallet/send\">send</a> · \
<form method=post action=\"/wallet/address/new\" style=\"display:inline\">\
<input type=hidden name=csrf value=\"{}\"><button type=submit>new receive address</button></form> · \
<form method=post action=\"/wallet/lock\" style=\"display:inline\">\
<input type=hidden name=csrf value=\"{}\"><button type=submit>lock session</button></form></p></div>\
<h2>UTXOs</h2>\
<table><tr><th>txid</th><th>vout</th><th>value</th><th>confs</th><th>flags</th></tr>{}</table>\
<h2>recent addresses</h2>\
<table><tr><th>#</th><th>address</th></tr>{}</table>",
            fmt_btc(mature),
            fmt_btc(immature),
            indices.0,
            indices.1,
            esc(&csrf),
            esc(&csrf),
            utxo_rows,
            // show only the tail of issued addresses to keep the page tight
            addr_rows
        ),
    )
    .into_response()
}

/// GET /wallet/addresses — full issued-address list.
async fn addresses_page(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some(token) = session_token(&app, &headers) else {
        return Redirect::to("/").into_response();
    };
    // Reuse snapshot for a fresh scan (keeps utxo state honest).
    let (_u, addr_rows, _m, _i, _idx) = match wallet_snapshot(&app, &token).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let (name, csrf) = {
        let sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match sessions.get(&token) {
            Some(s) => (s.name.clone(), s.csrf.clone()),
            None => return Redirect::to("/").into_response(),
        }
    };
    page(
        &format!("addresses — {name}"),
        &format!(
            "<p><a href=\"/wallet\">&larr; wallet</a></p>\
<table><tr><th>#</th><th>address</th></tr>{}</table>\
<form method=post action=\"/wallet/address/new\">\
<input type=hidden name=csrf value=\"{}\"><button type=submit>new receive address</button></form>",
            addr_rows,
            esc(&csrf)
        ),
    )
    .into_response()
}

/// GET /wallet/send — the send form.
async fn send_form(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some(token) = session_token(&app, &headers) else {
        return Redirect::to("/").into_response();
    };
    let (name, csrf, mature) = {
        let sessions = app.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match sessions.get(&token) {
            Some(s) => (s.name.clone(), s.csrf.clone(), s.wallet.balance().0.sats()),
            None => return Redirect::to("/").into_response(),
        }
    };
    page(
        &format!("send — {name}"),
        &format!(
            "<p class=dim>spendable (mature): {}</p>\
<div class=card><form method=post action=\"/wallet/send\">\
<label>to <input name=\"to\" required size=40 placeholder=\"m…/n… address\"></label><br><br>\
<label>amount (BTC or sats) <input name=\"amount\" required size=20 placeholder=\"0.001\"></label><br><br>\
<label>fee rate (sat/kvB) <input name=\"fee_rate\" value=\"1\" size=10></label><br><br>\
<input type=hidden name=csrf value=\"{}\">\
<button type=submit>build &amp; sign</button></form></div>\
<p class=dim>nothing broadcasts until you confirm the review page · <a href=\"/wallet\">cancel</a></p>",
            fmt_btc(mature),
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

    // Fresh UTXO view, then sign inside the session lock.
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
    // Fee = wallet inputs consumed − outputs created.
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
    // build_and_sign may have issued a change address — persist counters.
    let indices = sess.wallet.indices();
    drop(sessions);
    if let Err(e) = save_indices(&app.datadir, &name, indices) {
        return fail(format!("failed to persist wallet indices: {e}"));
    }

    // Stash the draft in the session for the review step.
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
    let Some(token) = session_token(&app, &headers) else {
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
    let csrf = sess.csrf.clone();
    let name = sess.name.clone();
    page(
        &format!("review send — {name}"),
        &format!(
            "<div class=card>\
<table>\
<tr><td>to</td><td class=mono>{}</td></tr>\
<tr><td>amount</td><td>{}</td></tr>\
<tr><td>fee</td><td>{} ({} sat/kvB)</td></tr>\
<tr><td>inputs</td><td>{}</td></tr>\
<tr><td>txid</td><td class=mono>{}</td></tr>\
</table>\
<p class=warn>confirm only if every field is what you intend — this broadcasts to the node mempool.</p>\
<form method=post action=\"/wallet/send/confirm\">\
<input type=hidden name=csrf value=\"{}\"><button type=submit>broadcast transaction</button></form>\
<form method=post action=\"/wallet/send/cancel\">\
<input type=hidden name=csrf value=\"{}\"><button type=submit>cancel</button></form></div>",
            esc(&p.to),
            fmt_btc(p.amount_sats),
            fmt_btc(p.fee_sats),
            p.fee_rate,
            p.inputs,
            esc(&p.txid),
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
    Form(_form): Form<HashMap<String, String>>,
) -> Response {
    let Some(token) = require_post_session(&app, &headers, &_form) else {
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
                "broadcast",
                &format!(
                    "<div class=card><p class=ok>broadcast accepted</p>\
<p>txid: <span class=mono>{}</span></p>\
<p class=dim>returned: {}</p>\
<p><a href=\"/wallet\">back to wallet</a></p></div>",
                    esc(&p.txid),
                    esc(&ret)
                ),
            )
            .into_response()
        }
        Err(e) => {
            audit(&app, "send_broadcast_fail", Some(&name), Some(&p.txid));
            page(
                "broadcast failed",
                &format!(
                    "<div class=card><p class=err>node rejected the transaction</p>\
<p class=dim>{}</p>\
<p>txid: <span class=mono>{}</span></p>\
<p><a href=\"/wallet\">back to wallet</a> · <a href=\"/wallet/send\">try again</a></p></div>",
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
            page(
                "new address",
                &format!(
                    "<div class=card><p>new receive address:</p>\
<p class=mono>{}</p><p><a href=\"/wallet\">back to wallet</a></p></div>",
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
        unlock_fails: Mutex::new(HashMap::new()),
    });
    let router = Router::new()
        .route("/", get(index))
        .route("/unlock", post(unlock))
        .route("/wallet", get(wallet_page))
        .route("/wallet/addresses", get(addresses_page))
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
        assert!(origin_ok(&h, listen)); // no Origin → allowed (curl)
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
        // Sessions older than TTL are evicted by session_token's retain.
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
}
