//! minibtc-explorer — a read-only web UI over the node's RPC.
//!
//! Pages: latest blocks, block detail, transaction detail, address
//! balance + history, mempool. Every dynamic string is HTML-escaped
//! before rendering — chain data is untrusted input.

use anyhow::{Context, Result};
use axum::extract::{Path as AxumPath, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use clap::Parser;
use minibtc_rpc::client::RpcClient;
use serde_json::Value;

/// MiniBTC block explorer (read-only).
#[derive(Parser, Debug)]
#[command(name = "minibtc-explorer", version, about)]
struct Args {
    /// Node datadir (holds .cookie).
    #[arg(long, default_value = "data")]
    datadir: std::path::PathBuf,

    /// Node RPC port (cookie read from datadir).
    #[arg(long, default_value_t = 18446)]
    rpc_port: u16,

    /// Explorer listen address (localhost only).
    #[arg(long, default_value = "127.0.0.1:18447")]
    listen: std::net::SocketAddr,
}

#[derive(Clone)]
struct App {
    rpc: RpcClient,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();
    let args = Args::parse();
    let rpc = RpcClient::from_datadir(&args.datadir, args.rpc_port)
        .context("connect to node RPC")?;
    let app = Router::new()
        .route("/", get(index))
        .route("/block/{id}", get(block_page))
        .route("/tx/{txid}", get(tx_page))
        .route("/address/{addr}", get(address_page))
        .route("/mempool", get(mempool_page))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(App { rpc });
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(%args.listen, "explorer listening (read-only)");
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------- HTML helpers (escape EVERYTHING dynamic) ----------

/// HTML-escape a string — the only way dynamic data reaches the page.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
<title>{} — MiniBTC Explorer</title>\
<style>body{{font-family:ui-monospace,Menlo,monospace;max-width:1100px;margin:2em auto;padding:0 1em;color:#222}}\
h1{{font-size:1.3em;border-bottom:2px solid #444;padding-bottom:.3em}}\
table{{border-collapse:collapse;width:100%}}\
td,th{{border:1px solid #ccc;padding:.3em .6em;text-align:left;font-size:.85em}}\
th{{background:#f4f4f4}}\
a{{color:#0645ad}}code{{background:#f6f6f6;padding:.1em .3em}}\
.nav a{{margin-right:1em}}.dim{{color:#777}}.err{{color:#a00}}</style></head>\
<body><div class=\"nav\"><a href=\"/\">blocks</a><a href=\"/mempool\">mempool</a></div>\
<h1>{}</h1>{}</body></html>",
        esc(title),
        esc(title),
        body
    ))
}

fn err_page(msg: &str) -> Html<String> {
    page(
        "error",
        &format!("<p class=\"err\">{}</p>", esc(msg)),
    )
}

fn sats(v: &Value) -> String {
    // money() renders {"amount":"x.y","sats":n} — prefer sats.
    v["sats"]
        .as_u64()
        .map(|n| format!("{} ({:.8} BTC)", n, n as f64 / 100_000_000.0))
        .unwrap_or_else(|| v["amount"].as_str().unwrap_or("?").to_string())
}

fn short_hash(h: &str) -> String {
    if h.len() > 16 {
        format!("{}…{}", &h[..8], &h[h.len() - 8..])
    } else {
        h.to_string()
    }
}

fn link_tx(txid: &str) -> String {
    format!("<a href=\"/tx/{}\"><code>{}</code></a>", esc(txid), esc(&short_hash(txid)))
}

fn link_addr(addr: &str) -> String {
    format!(
        "<a href=\"/address/{}\"><code>{}</code></a>",
        esc(addr),
        esc(addr)
    )
}

fn fmt_time(t: u64) -> String {
    // Render as UTC-ish via civil-from-days (no chrono dep).
    let days = (t / 86_400) as i64;
    let secs = t % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------- pages ----------

async fn index(State(app): State<App>) -> Html<String> {
    let info = match app.rpc.getblockchaininfo().await {
        Ok(v) => v,
        Err(e) => return err_page(&format!("node unreachable: {e}")),
    };
    let tip_h = info["blocks"].as_u64().unwrap_or(0) as u32;
    // Fetch the last 25 blocks by height (bounded).
    let mut rows = String::new();
    let start = tip_h.saturating_sub(24);
    for h in (start..=tip_h).rev() {
        let hash = match app.rpc.getblockhash(h as u64).await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let b = match app.rpc.getblock(&hash, 1).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let time = b["time"].as_u64().unwrap_or(0);
        let txs = b["txcount"].as_u64().unwrap_or(0);
        let bits = b["bits"].as_str().unwrap_or("0").to_string();
        rows.push_str(&format!(
            "<tr><td><a href=\"/block/{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            esc(&hash),
            esc(&hash),
            h,
            fmt_time(time),
            txs,
            esc(&bits)
        ));
    }
    let supply = info["money_supply_sats"].as_u64().unwrap_or(0);
    let net = app.rpc.getnetworkinfo().await.unwrap_or(Value::Null);
    let peers = net["connections"].as_u64().unwrap_or(0);
    page(
        "latest blocks",
        &format!(
            "<p>chain: <b>{}</b> — tip height {} — money supply {} sats — peers: {} — <a href=\"/mempool\">mempool</a></p>\
<table><tr><th>hash</th><th>height</th><th>time</th><th>txs</th><th>bits</th></tr>{}</table>",
            esc(info["chain"].as_str().unwrap_or("?")),
            tip_h,
            supply,
            peers,
            rows
        ),
    )
}

async fn block_page(
    State(app): State<App>,
    AxumPath(id): AxumPath<String>,
) -> Html<String> {
    // id may be a hash or a decimal height.
    let v = match app.rpc.getblock(&id, 1).await {
        Ok(v) => v,
        Err(e) => return err_page(&format!("block not found: {e}")),
    };
    let hash = v["hash"].as_str().unwrap_or("").to_string();
    let height = v["height"].as_u64().unwrap_or(0);
    let mut rows = String::new();
    if let Some(txs) = v["tx"].as_array() {
        for t in txs {
            let txid = t["txid"].as_str().unwrap_or("");
            let fee = t["fee"]["sats"].as_u64().map(|n| format!("{}", n)).unwrap_or_default();
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                link_tx(txid),
                esc(&t["size"].to_string()),
                esc(&fee)
            ));
        }
    }
    page(
        &format!("block {}", short_hash(&hash)),
        &format!(
            "<p><a href=\"/\">← blocks</a></p>\
<table>\
<tr><th>field</th><th>value</th></tr>\
<tr><td>hash</td><td><code>{}</code></td></tr>\
<tr><td>height</td><td>{}</td></tr>\
<tr><td>prev</td><td>{}</td></tr>\
<tr><td>merkle</td><td><code>{}</code></td></tr>\
<tr><td>time</td><td>{}</td></tr>\
<tr><td>bits</td><td><code>{}</code></td></tr>\
<tr><td>nonce</td><td>{}</td></tr>\
<tr><td>size</td><td>{}</td></tr>\
<tr><td>txcount</td><td>{}</td></tr>\
<tr><td>confirmations</td><td>{}</td></tr>\
</table>\
<h2>transactions</h2>\
<table><tr><th>txid</th><th>size</th><th>fee sats</th></tr>{}</table>",
            esc(&hash),
            height,
            &{
                let p = v["previousblockhash"].as_str().unwrap_or("");
                if p.is_empty() || p.chars().all(|c| c == '0') {
                    "genesis".to_string()
                } else {
                    format!("<a href=\"/block/{}\"><code>{}</code></a>", esc(p), esc(&short_hash(p)))
                }
            },
            esc(v["merkleroot"].as_str().unwrap_or("")),
            fmt_time(v["time"].as_u64().unwrap_or(0)),
            esc(v["bits"].as_str().unwrap_or("").to_string().as_str()),
            v["nonce"].as_u64().unwrap_or(0),
            v["size"].as_u64().unwrap_or(0),
            v["txcount"].as_u64().unwrap_or(0),
            v["confirmations"].as_u64().unwrap_or(0),
            rows
        ),
    )
}

async fn tx_page(
    State(app): State<App>,
    AxumPath(txid): AxumPath<String>,
) -> Html<String> {
    let v = match app.rpc.getrawtransaction(&txid, true).await {
        Ok(v) => v,
        Err(e) => return err_page(&format!("tx not found: {e}")),
    };
    // Inputs.
    let mut vin = String::new();
    if let Some(inputs) = v["vin"].as_array() {
        for i in inputs {
            let prev = i["txid"].as_str().unwrap_or("");
            let vout = i["vout"].as_u64().unwrap_or(0);
            let coinbase = i["coinbase"].as_bool().unwrap_or(false);
            let cell = if coinbase || prev.is_empty() || prev.chars().all(|c| c == '0') {
                "coinbase".to_string()
            } else {
                format!("{}:{}", link_tx(prev), vout)
            };
            vin.push_str(&format!(
                "<tr><td>{}</td><td><code>{}</code></td></tr>",
                cell,
                esc(i["scriptSig"]["hex"].as_str().unwrap_or(""))
            ));
        }
    }
    // Outputs.
    let mut vout = String::new();
    if let Some(outputs) = v["vout"].as_array() {
        for o in outputs {
            let spk = &o["scriptPubKey"];
            let addr = spk["addresses"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|x| x.as_str())
                .map(link_addr)
                .unwrap_or_else(|| {
                    format!("<code>{}</code>", esc(spk["hex"].as_str().unwrap_or("")))
                });
            vout.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                o["n"].as_u64().unwrap_or(0),
                sats(&o["value"]),
                addr
            ));
        }
    }
    page(
        &format!("tx {}", short_hash(&txid)),
        &format!(
            "<p><a href=\"/\">← blocks</a></p>\
<table>\
<tr><th>field</th><th>value</th></tr>\
<tr><td>txid</td><td><code>{}</code></td></tr>\
<tr><td>size</td><td>{}</td></tr>\
<tr><td>version</td><td>{}</td></tr>\
<tr><td>locktime</td><td>{}</td></tr>\
<tr><td>fee</td><td>{}</td></tr>\
<tr><td>confirmations</td><td>{}</td></tr>\
</table>\
<h2>inputs</h2><table><tr><th>prevout</th><th>scriptSig</th></tr>{}</table>\
<h2>outputs</h2><table><tr><th>n</th><th>value</th><th>scriptPubKey</th></tr>{}</table>",
            esc(v["txid"].as_str().unwrap_or("")),
            v["size"].as_u64().unwrap_or(0),
            v["version"].as_i64().unwrap_or(0),
            v["locktime"].as_u64().unwrap_or(0),
            v["fee"]["sats"].as_u64().map(|n| n.to_string()).unwrap_or_else(|| "—".into()),
            v["confirmations"].as_u64().map(|n| n.to_string()).unwrap_or_else(|| "unconfirmed".into()),
            vin,
            vout
        ),
    )
}

async fn address_page(
    State(app): State<App>,
    AxumPath(addr): AxumPath<String>,
) -> Html<String> {
    // Balance + utxos + history in parallel-ish (sequential awaits fine).
    let info = app.rpc.getaddressinfo(&addr).await;
    let utxos = app.rpc.call("getaddressutxos", serde_json::json!([addr])).await;
    let hist = app.rpc.call("getaddresshistory", serde_json::json!([addr])).await;
    let (Ok(info), Ok(utxos), Ok(hist)) = (info, utxos, hist) else {
        return err_page("address query failed (bad address or node error)");
    };
    let balance = info["balance_sats"].as_u64().unwrap_or(0);
    // UTXO table.
    let mut urows = String::new();
    if let Some(arr) = utxos.as_array() {
        for u in arr {
            urows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                link_tx(u["txid"].as_str().unwrap_or("")),
                u["vout"].as_u64().unwrap_or(0),
                u["value"].as_u64().unwrap_or(0),
                u["height"].as_u64().unwrap_or(0),
                if u["spendable"].as_bool().unwrap_or(true) { "yes" } else { "no (immature)" }
            ));
        }
    }
    // History table.
    let mut hrows = String::new();
    if let Some(arr) = hist["outputs"].as_array() {
        for o in arr {
            hrows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                link_tx(o["txid"].as_str().unwrap_or("")),
                o["vout"].as_u64().unwrap_or(0),
                o["value_sats"].as_u64().unwrap_or(0),
                o["height"].as_u64().unwrap_or(0),
                o["confirmations"].as_u64().unwrap_or(0),
                if o["spent"].as_bool().unwrap_or(false) { "spent" } else { "unspent" }
            ));
        }
    }
    page(
        &format!("address {}", addr),
        &format!(
            "<p><a href=\"/\">← blocks</a></p>\
<table>\
<tr><th>field</th><th>value</th></tr>\
<tr><td>address</td><td><code>{}</code></td></tr>\
<tr><td>balance</td><td>{} sats ({:.8} BTC)</td></tr>\
<tr><td>utxos</td><td>{}</td></tr>\
<tr><td>outputs ever</td><td>{}</td></tr>\
</table>\
<h2>unspent outputs</h2>\
<table><tr><th>txid</th><th>vout</th><th>value sats</th><th>height</th><th>spendable</th></tr>{}</table>\
<h2>history</h2>\
<table><tr><th>txid</th><th>vout</th><th>value sats</th><th>height</th><th>conf</th><th>status</th></tr>{}</table>",
            esc(&addr),
            balance,
            balance as f64 / 100_000_000.0,
            utxos.as_array().map(|a| a.len()).unwrap_or(0),
            hist["count"].as_u64().unwrap_or(0),
            urows,
            hrows
        ),
    )
}

async fn mempool_page(State(app): State<App>) -> Html<String> {
    let v = match app.rpc.getrawmempool(true).await {
        Ok(v) => v,
        Err(e) => return err_page(&format!("mempool query failed: {e}")),
    };
    let mut rows = String::new();
    if let Value::Object(map) = &v {
        for (txid, t) in map.iter().take(500) {
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                link_tx(txid),
                t["size"].as_u64().unwrap_or(0),
                t["fee"]["sats"].as_u64().unwrap_or(0),
                t["vin"].as_array().map(|a| a.len()).unwrap_or(0)
            ));
        }
    }
    let info = app.rpc.getmempoolinfo().await.unwrap_or(Value::Null);
    page(
        "mempool",
        &format!(
            "<p><a href=\"/\">← blocks</a> — {} txs, {} bytes, min relay fee {} sats/kvB</p>\
<table><tr><th>txid</th><th>size</th><th>fee sats</th><th>inputs</th></tr>{}</table>",
            info["size"].as_u64().unwrap_or(0),
            info["bytes"].as_u64().unwrap_or(0),
            info["mempoolminfee"]["sats"].as_u64().unwrap_or(0),
            rows
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every dynamic byte reaching the page must pass through esc().
    #[test]
    fn esc_neutralizes_html() {
        assert_eq!(esc("<script>alert(1)</script>"), "&lt;script&gt;alert(1)&lt;/script&gt;");
        assert_eq!(esc("a&b\"c'd"), "a&amp;b&quot;c&#39;d");
        assert_eq!(esc("plain-123"), "plain-123");
        // Attribute-context safety: quotes are escaped.
        assert!(!esc("\"").contains('"'));
    }

    #[test]
    fn short_hash_bounds() {
        assert_eq!(short_hash("abcd"), "abcd");
        let h = "0123456789abcdef0123456789abcdef";
        assert_eq!(short_hash(h), "01234567…89abcdef");
    }
}
