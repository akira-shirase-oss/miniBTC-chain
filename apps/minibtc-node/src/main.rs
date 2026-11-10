//! minibtc-node — the MiniBTC full node daemon.
//!
//! Wires chainstate + storage + mempool + P2P + miner + RPC into one
//! process. Devnet-first: trivial PoW, localhost RPC with cookie auth,
//! optional `--mine` block production.

mod core;
mod net;
mod rpc;

use anyhow::{Context, Result};
use clap::Parser;
use minibtc_consensus::ChainParams;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// MiniBTC full node.
#[derive(Parser, Debug)]
#[command(name = "minibtc-node", version, about)]
struct Args {
    /// Data directory (chainstate DB, wallet dir, .cookie).
    #[arg(long, default_value = "data")]
    datadir: PathBuf,

    /// P2P listen address.
    #[arg(long, default_value = "127.0.0.1:18445")]
    listen: SocketAddr,

    /// Peers to connect to on startup (repeatable via comma list).
    #[arg(long, value_delimiter = ',')]
    connect: Vec<SocketAddr>,

    /// RPC listen address (localhost only — cookie auth).
    #[arg(long, default_value = "127.0.0.1:18446")]
    rpc: SocketAddr,

    /// Mine blocks continuously, paying `address`.
    #[arg(long, requires = "mining_address")]
    mine: bool,

    /// Address/scriptPubKey destination for mined coinbase (required with --mine).
    #[arg(long)]
    mining_address: Option<String>,

    /// Replay all stored blocks through validation on startup.
    #[arg(long)]
    reindex: bool,

    /// Use a custom chain params JSON file instead of devnet defaults.
    #[arg(long)]
    params: Option<PathBuf>,

    /// Log level (trace/debug/info/warn/error).
    #[arg(long, default_value = "info")]
    log: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Logging — stderr only; never log secrets.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&args.log)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // Params: custom file or devnet preset.
    let params: ChainParams = match &args.params {
        Some(p) => ChainParams::load(p)
            .with_context(|| format!("load params {}", p.display()))?,
        None => ChainParams::devnet(),
    };
    if !params.devnet {
        tracing::warn!("non-devnet params: mining and generatetoaddress disabled");
    }

    // Node: open store, load/reindex chain.
    let node = core::open(&args.datadir, params.clone(), args.reindex)
        .context("open node")?;
    tracing::info!(
        datadir = %args.datadir.display(),
        tip = %node_tip(&node),
        "node state loaded"
    );

    // RPC auth cookie — written into datadir, never logged.
    let auth = minibtc_rpc::server::CookieAuth::generate();
    std::fs::write(
        args.datadir.join(".cookie"),
        auth.to_cookie_file(),
    )
    .context("write .cookie")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            args.datadir.join(".cookie"),
            std::fs::Permissions::from_mode(0o600),
        );
    }

    // Shutdown wiring: SIGINT/SIGTERM → cancel flag → tasks exit.
    let cancel = node.cancel.clone();
    {
        let c = cancel.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received");
            c.store(true, Ordering::Relaxed);
        });
    }

    // RPC server.
    let backend = rpc::NodeBackend::new(node.clone()).shared();
    let rpc_addr = args.rpc;
    let rpc_task = tokio::spawn(async move {
        if let Err(e) = minibtc_rpc::server::serve(backend, auth, rpc_addr).await {
            tracing::error!("rpc server exited: {e}");
        }
    });

    // P2P.
    let p2p_task = {
        let n = node.clone();
        let listen = args.listen;
        let connect = args.connect.clone();
        tokio::spawn(async move {
            net::run(n, listen, connect).await;
        })
    };

    // Optional mining loop.
    let mine_task = if args.mine {
        let n = node.clone();
        let addr = args.mining_address.clone();
        Some(tokio::spawn(async move {
            mine_loop(n, addr).await;
        }))
    } else {
        None
    };

    // Wait for shutdown.
    while !node.cancel.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tracing::info!("shutting down");
    rpc_task.abort();
    p2p_task.abort();
    if let Some(t) = mine_task {
        t.abort();
    }
    // Final snapshot so the last state is durable.
    if let Some(store) = &node.store {
        let inner = node.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = store.snapshot(&inner.chain) {
            tracing::error!("final snapshot failed: {e}");
        }
    }
    Ok(())
}

/// Tip hash for startup logging.
fn node_tip(node: &core::Node) -> String {
    node.inner
        .lock()
        .map(|i| i.chain.tip.to_hex())
        .unwrap_or_else(|_| "?".into())
}

/// Continuous mining loop: build template → grind → connect → relay.
/// Runs until cancel. Each iteration re-reads mempool + tip fresh.
async fn mine_loop(node: core::Node, address: Option<String>) {
    let payout = match address {
        Some(a) => match minibtc_crypto::Address::from_base58(
            &a,
            Some(node.params.address_version),
        ) {
            Ok(addr) => minibtc_script::Script::p2pkh(&addr.hash160)
                .as_bytes()
                .to_vec(),
            Err(e) => {
                tracing::error!("bad --mining-address: {e}");
                return;
            }
        },
        None => vec![0x51], // OP_TRUE anyone-can-spend (shouldn't happen — clap requires)
    };
    tracing::info!("mining enabled");
    loop {
        if node.cancel.load(Ordering::Relaxed) {
            break;
        }
        match node.generate(1, &payout) {
            Ok(hashes) => {
                for h in hashes {
                    tracing::info!(hash = %h, "block mined");
                }
                // Devnet target is trivial — yield briefly to keep the
                // loop from starving the runtime.
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => {
                tracing::warn!("mine iteration failed: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
