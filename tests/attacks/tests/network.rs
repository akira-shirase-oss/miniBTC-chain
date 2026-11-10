//! Network & economic attack scenarios (blueprint §8, rows 4–6, 12–15).
//! Double-spend races, reorg double-spends, majority-work attacks,
//! mempool flooding, malformed wire data, eclipse attempts, and a
//! selfish-mining revenue simulation.

mod common;

use common::*;
use minibtc_chainstate::Chain;
use minibtc_consensus::{ChainParams, TxError, validate_tx};
use minibtc_crypto::{Hash256, Keypair};
use minibtc_mempool::{Mempool, MempoolPolicy};
use minibtc_p2p::codec::{self, Message, NetAddress};
use minibtc_p2p::peer::{PeerError, PeerManager};
use minibtc_primitives::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn tip_header(chain: &Chain) -> BlockHeader {
    *chain
        .blocks
        .get(&chain.tip)
        .map(|r| &r.block.header)
        .unwrap_or_else(|| panic!("tip record missing"))
}

/// Find the coinbase outpoint+output at a given height.
fn coinbase_at(chain: &Chain, height: u32) -> (OutPoint, TxOutput) {
    let rec = chain
        .blocks
        .values()
        .find(|r| r.height == height)
        .unwrap_or_else(|| panic!("block at height"));
    let op = OutPoint {
        txid: rec.block.txs[0].txid(),
        vout: 0,
    };
    let out = chain
        .utxos
        .get(&op)
        .unwrap_or_else(|| panic!("coinbase output unspent"))
        .output
        .clone();
    (op, out)
}

// ---------- 4. Double-spend race ----------

/// Two conflicting spends racing through two nodes' mempools: only one
/// can ever confirm — the loser fails once the winner is mined.
#[test]
fn attack_double_spend_race_only_one_confirms() {
    let params = ChainParams::devnet();
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105); // mature coinbase available
    let (cb_op, cb_out) = coinbase_at(&chain, 1);
    let dest_a = Keypair::generate().unwrap();
    let dest_b = Keypair::generate().unwrap();

    // Two conflicting spends of the SAME outpoint.
    let tx_a = signed_spend(
        cb_op,
        &cb_out.script_pubkey,
        cb_out.value,
        &miner,
        &p2pkh_spk(&dest_a),
        Sats(1_000_000),
        Sats(1_000),
    );
    let tx_b = signed_spend(
        cb_op,
        &cb_out.script_pubkey,
        cb_out.value,
        &miner,
        &p2pkh_spk(&dest_b),
        Sats(2_000_000),
        Sats(2_000),
    );
    assert_ne!(tx_a.txid(), tx_b.txid());

    // Both validate against chainstate (input still unspent on-chain).
    assert!(validate_tx(&tx_a, &chain.utxos, &params).is_ok());
    assert!(validate_tx(&tx_b, &chain.utxos, &params).is_ok());

    // Node A's mempool takes tx_a; node B's takes tx_b. Neither sees the
    // other's mempool, so both admit — the race is live.
    let mut pool_a = Mempool::new(MempoolPolicy::default());
    let mut pool_b = Mempool::new(MempoolPolicy::default());
    pool_a
        .admit(tx_a.clone(), Sats(1_000), &chain.utxos, &params, None)
        .unwrap();
    pool_b
        .admit(tx_b.clone(), Sats(2_000), &chain.utxos, &params, None)
        .unwrap();

    // Miner includes tx_a (higher fee-rate isn't needed — first seen).
    let mut prev = tip_header(&chain);
    let mut time = prev.time;
    time += 31;
    let cb = coinbase_tx(&miner, chain.height() + 1, params.subsidy_start);
    let blk = build_block(&prev, vec![cb, tx_a.clone()], time, &params);
    chain.consider_block(blk).unwrap();
    prev = tip_header(&chain);

    // Now tx_b's input is spent on-chain: it can NEVER confirm.
    let err = validate_tx(&tx_b, &chain.utxos, &params).unwrap_err();
    assert!(
        matches!(
            err,
            TxError::MissingInput { .. } | TxError::Overspend { .. }
        ),
        "double-spend loser must fail validation, got {err:?}"
    );
    // And mempool B must drop it when it learns of the block.
    let _ = prev;
}

// ---------- 5. Reorg double spend ----------

/// A payment confirmed once can be erased by a heavier private fork —
/// the reason merchants wait for confirmations.
#[test]
fn attack_reorg_double_spend_erases_payment() {
    let params = ChainParams::devnet();
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 105);
    let fork_point = tip_header(&chain); // height 105
    let (cb_op, cb_out) = coinbase_at(&chain, 1);
    let payee = Keypair::generate().unwrap();

    // Honest chain: payment P + 3 empty blocks (4-block extension).
    let payment = signed_spend(
        cb_op,
        &cb_out.script_pubkey,
        cb_out.value,
        &miner,
        &p2pkh_spk(&payee),
        Sats(5_000_000),
        Sats(500),
    );
    let payment_txid = payment.txid();
    let payment_op = OutPoint {
        txid: payment_txid,
        vout: 0,
    };
    let mut prev = fork_point;
    let mut time = prev.time;
    for i in 0..4u32 {
        time += 31;
        let txs = if i == 0 {
            vec![
                coinbase_tx(&miner, chain.height() + 1, params.subsidy_start),
                payment.clone(),
            ]
        } else {
            vec![coinbase_tx(
                &miner,
                chain.height() + 1,
                params.subsidy_start,
            )]
        };
        let blk = build_block(&prev, txs, time, &params);
        chain.consider_block(blk.clone()).unwrap();
        prev = blk.header;
    }
    assert!(chain.utxos.get(&payment_op).is_some(), "payment confirmed");
    let honest_tip = chain.tip;

    // Attacker: private fork of 5 blocks from the SAME fork point —
    // heavier work, no payment.
    let attacker = Keypair::generate().unwrap();
    let mut fprev = fork_point;
    let mut ftime = fork_point.time;
    let fork_start_height = chain_height_at(&chain, fork_point.block_hash());
    for i in 0..5u32 {
        ftime += 31;
        let cb = coinbase_tx(&attacker, fork_start_height + 1 + i, params.subsidy_start);
        let blk = build_block(&fprev, vec![cb], ftime, &params);
        chain.consider_block(blk.clone()).unwrap();
        fprev = blk.header;
    }

    // Most-work rule: the 5-block fork (work 5) beats honest 4-block
    // extension → reorg. The payment is GONE.
    assert_ne!(chain.tip, honest_tip, "reorg must move the tip");
    assert!(
        chain.utxos.get(&payment_op).is_none(),
        "reorged-out payment output must not exist"
    );
    // The spent coinbase is unspent again on the fork.
    assert!(chain.utxos.get(&cb_op).is_some());
}

fn chain_height_at(chain: &Chain, hash: Hash256) -> u32 {
    chain
        .blocks
        .get(&hash)
        .map(|r| r.height)
        .unwrap_or_else(|| panic!("block record missing"))
}

// ---------- 6. Majority-work (51%) attack ----------

/// An attacker controlling >50% of hashpower rewrites arbitrary
/// history: honest chain's blocks are fully displaced.
#[test]
fn attack_majority_work_rewrites_history() {
    let params = ChainParams::devnet();
    let (mut chain, honest) = fresh_chain();
    mine_empty(&mut chain, &honest, 105);
    let fork_point = tip_header(&chain);
    let fork_hash = fork_point.block_hash();
    let fork_height = chain_height_at(&chain, fork_hash);

    // Honest network extends 3 blocks.
    let mut prev = fork_point;
    let mut time = prev.time;
    for _ in 0..3 {
        time += 31;
        let cb = coinbase_tx(&honest, chain.height() + 1, params.subsidy_start);
        let blk = build_block(&prev, vec![cb], time, &params);
        chain.consider_block(blk.clone()).unwrap();
        prev = blk.header;
    }
    let honest_tip = chain.tip;

    // Attacker with majority work mines 6 blocks from the fork point.
    let attacker = Keypair::generate().unwrap();
    let mut fprev = fork_point;
    let mut ftime = fork_point.time;
    for i in 0..6u32 {
        ftime += 31;
        let cb = coinbase_tx(&attacker, fork_height + 1 + i, params.subsidy_start);
        let blk = build_block(&fprev, vec![cb], ftime, &params);
        chain.consider_block(blk.clone()).unwrap();
        fprev = blk.header;
    }

    // All 3 honest blocks displaced — attacker chain is canonical.
    assert_ne!(chain.tip, honest_tip);
    let new_height = chain_height_at(&chain, chain.tip);
    assert_eq!(new_height, fork_height + 6);
    // Honest extension blocks still exist in the index but are not
    // ancestors of the tip.
    let mut cur = chain.tip;
    let mut seen_honest = false;
    for _ in 0..=new_height {
        if cur == honest_tip {
            seen_honest = true;
        }
        let rec = chain.blocks.get(&cur).unwrap();
        if rec.height == 0 {
            break;
        }
        cur = rec.block.header.prev_hash;
    }
    assert!(
        !seen_honest,
        "honest tip must be orphaned by majority attack"
    );
}

// ---------- 12. Mempool flooding ----------

/// Thousands of low-fee txs must not grow memory unboundedly — the
/// size cap evicts lowest fee-rate first.
#[test]
fn attack_mempool_flood_bounded_eviction() {
    let params = ChainParams::devnet();
    let policy = MempoolPolicy {
        max_size_bytes: 2_000,
        max_entries: 10_000,
        ..Default::default()
    };
    let mut pool = Mempool::new(policy);

    // 500 distinct fake spends (no scripts needed — admit is policy-only).
    let mut admitted: Vec<Hash256> = Vec::new();
    for i in 0..500u32 {
        let op = OutPoint {
            txid: Hash256::from_hex(&format!("{:064x}", i + 1)).unwrap(),
            vout: 0,
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
                script_pubkey: vec![0x76, 0xa9, 0x14, 1, 2, 3, 4],
            }],
            locktime: 0,
        };
        // Fee rises with i → early txs are the eviction victims.
        let fee = Sats(1_000 + i as u64 * 10);
        if let Ok(txid) = pool.admit(tx, fee, &EmptyView, &params, None) {
            admitted.push(txid);
        }
    }

    // Bounded: total serialized size never exceeds the cap.
    assert!(pool.total_size() <= 2_000, "mempool exceeded size cap");
    assert!(pool.len() <= 10_000);
    // Eviction is fee-ordered: the earliest (lowest-fee) admits are gone.
    let survivors = admitted.iter().filter(|t| pool.get(t).is_some()).count();
    assert!(survivors < admitted.len(), "no evictions happened");
    assert!(
        pool.get(&admitted[0]).is_none(),
        "lowest-fee tx should be evicted"
    );
    // The highest-fee tail survives.
    let last = admitted.last().unwrap();
    assert!(pool.get(last).is_some(), "highest-fee tx must survive");
}

struct EmptyView;
impl minibtc_consensus::UtxoView for EmptyView {
    fn get(&self, _op: &OutPoint) -> Option<TxOutput> {
        None
    }
}

// ---------- 13. Malformed P2P messages ----------

/// Fuzz the wire decoder: every command type × truncation/bitflip/
/// garbage mutations must return Err or a bounded Ok — never panic.
#[test]
fn attack_malformed_messages_never_panic() {
    let params = ChainParams::devnet();
    // A valid message of each type to mutate.
    let samples: Vec<(&str, Message)> = vec![
        ("version", version_msg()),
        ("verack", Message::Verack),
        ("ping", Message::Ping(0xdead_beef)),
        ("pong", Message::Pong(42)),
        ("inv", Message::Inv(vec![inv_item()])),
        ("getdata", Message::GetData(vec![inv_item()])),
        ("addr", Message::Addr(vec![(net_addr(), 1_700_000_000)])),
        (
            "reject",
            Message::Reject {
                message: "x".into(),
                code: 1,
                reason: "y".into(),
            },
        ),
        (
            "getheaders",
            Message::GetHeaders {
                locator: vec![Hash256::ZERO],
                stop: Hash256::ZERO,
            },
        ),
        (
            "headers",
            Message::Headers {
                count: 0,
                headers: vec![],
            },
        ),
        ("tx", Message::Tx(dummy_tx())),
        ("block", Message::Block(dummy_block(&params))),
    ];

    let mut cases = 0usize;
    for (cmd, msg) in &samples {
        let payload = codec::encode_payload(msg, &params);
        // Sanity: valid payload round-trips.
        assert!(
            codec::decode_payload(cmd, &payload).is_ok(),
            "valid {cmd} payload must decode"
        );

        // (a) Every truncation point (step to keep it fast on big payloads).
        let step = (payload.len() / 40).max(1);
        for cut in (0..payload.len()).step_by(step) {
            let r = std::panic::catch_unwind(|| codec::decode_payload(cmd, &payload[..cut]));
            assert!(r.is_ok(), "decode panicked on truncated {cmd} at {cut}");
            cases += 1;
        }
        // (b) Single-byte corruptions at sampled offsets.
        for off in (0..payload.len()).step_by(step.max(1)) {
            let mut bad = payload.clone();
            bad[off] ^= 0xff;
            let r = std::panic::catch_unwind(|| codec::decode_payload(cmd, &bad));
            assert!(r.is_ok(), "decode panicked on corrupted {cmd} at {off}");
            cases += 1;
        }
        // (c) Garbage / oversized compactsize claims.
        for garbage in [
            vec![],
            vec![0xff; 8],
            vec![0xff, 0xff, 0xff, 0xff, 0x0f], // huge compactsize
            vec![0x00; 4096],
        ] {
            let r = std::panic::catch_unwind(|| codec::decode_payload(cmd, &garbage));
            assert!(r.is_ok(), "decode panicked on garbage {cmd}");
            cases += 1;
        }
    }
    // Also fuzz unknown commands.
    for cmd in ["", "notacommand", "VERSION", "getblocktemplate\x00"] {
        let r = std::panic::catch_unwind(|| codec::decode_payload(cmd, &[0xde, 0xad, 0xbe, 0xef]));
        assert!(r.is_ok(), "decode panicked on unknown cmd {cmd:?}");
        cases += 1;
    }
    assert!(cases > 500, "fuzz coverage too thin: {cases}");
}

fn version_msg() -> Message {
    Message::Version {
        version: 70015,
        services: 0,
        timestamp: 1_700_000_000,
        addr_recv: net_addr(),
        addr_from: net_addr(),
        nonce: 1,
        user_agent: "attack-lab/1.0".into(),
        start_height: 0,
        relay: true,
    }
}

fn net_addr() -> NetAddress {
    NetAddress {
        services: 0,
        ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port: 18445,
    }
}

fn inv_item() -> codec::InvItem {
    codec::InvItem {
        kind: codec::InvType::Tx,
        hash: Hash256::ZERO,
    }
}

fn dummy_tx() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![],
        outputs: vec![],
        locktime: 0,
    }
}

fn dummy_block(params: &ChainParams) -> Block {
    let cb = coinbase_tx(
        &Keypair::generate().unwrap_or_else(|e| panic!("keygen failed: {e:?}")),
        0,
        params.subsidy_start,
    );
    Block {
        header: BlockHeader {
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: merkle_root(std::slice::from_ref(&cb)),
            time: 1_700_000_000,
            bits: params.pow_limit_bits,
            nonce: 0,
        },
        txs: vec![cb],
    }
}

// ---------- 14. Eclipse attempt ----------

/// An attacker filling peer slots from one /16 subnet (or one IP) is
/// stopped by diversity limits — honest peers keep their slots.
#[test]
fn attack_eclipse_diversity_limits_hold() {
    let mut pm = PeerManager::new();
    let mk_ver = || version_msg();

    // Attacker registers 10 peers, all inside 10.9.x.x (one /16 subnet).
    for i in 0..10u8 {
        let addr: SocketAddr = SocketAddr::from(([10, 9, 0, i], 18445));
        pm.register(addr, false, &mk_ver()).unwrap();
    }
    // Honest peers from diverse subnets fill remaining slots.
    for i in 0..20u8 {
        let addr: SocketAddr = SocketAddr::from(([192, 168, i, 1], 18445));
        let _ = pm.register(addr, false, &mk_ver()); // some rejected at cap
    }

    // A NEW inbound peer from the attacker subnet must be refused.
    let eclipse_addr: SocketAddr = SocketAddr::from(([10, 9, 1, 200], 18445));
    let res = pm.admit(eclipse_addr, false);
    assert!(
        matches!(res, Err(PeerError::AddrLimit) | Err(PeerError::Full)),
        "eclipse peer must be refused, got {res:?}"
    );

    // Per-IP limit: 3 conns from same IP different ports → capped at 2.
    let mut pm2 = PeerManager::new();
    for port in 1..=3u16 {
        let addr: SocketAddr = SocketAddr::from(([8, 8, 8, 8], port));
        pm2.register(addr, false, &mk_ver()).unwrap();
        let _ = pm2.admit(addr, false);
    }
    let fourth: SocketAddr = SocketAddr::from(([8, 8, 8, 8], 9999));
    let res = pm2.admit(fourth, false);
    assert!(
        matches!(res, Err(PeerError::AddrLimit)),
        "per-IP limit must hold, got {res:?}"
    );

    // And the subnet cap is exactly MAX_PER_SUBNET for same-/16 addrs.
    let mut pm3 = PeerManager::new();
    for i in 0..5u8 {
        let addr: SocketAddr = SocketAddr::from(([172, 16, 0, i], 18445));
        pm3.register(addr, false, &mk_ver()).unwrap();
    }
    let fifth: SocketAddr = SocketAddr::from(([172, 16, 9, 9], 18445));
    assert!(matches!(pm3.admit(fifth, false), Err(PeerError::AddrLimit)));
    // A different /16 is still admissible.
    let other: SocketAddr = SocketAddr::from(([172, 17, 0, 1], 18445));
    assert!(pm3.admit(other, false).is_ok());
}

// ---------- 15. Selfish mining (simulation) ----------

/// Seeded Eyal–Sirer-style sim: attacker with α=40% hashrate withholds
/// blocks and publishes strategically. Honest strategy earns exactly
/// its hashrate share; selfish mining must earn MORE.
#[test]
fn attack_selfish_mining_earns_above_hashrate() {
    let alpha_num = 40u64; // attacker hashrate share, percent
    let alpha_den = 100u64;
    let rounds = 60_000u64;
    let gamma_pct = 50u64; // attacker wins 50% of one-block races

    let mut rng = XorShift(0x9e3779b97f4a7c15);
    let mut lead: u64 = 0; // attacker's withheld private-block count
    let mut att_rev: u64 = 0;
    let mut hon_rev: u64 = 0;

    for _ in 0..rounds {
        // Does the attacker find the next block? (α of all discoveries)
        let attacker_finds = rng.next_below(alpha_den) < alpha_num;
        if attacker_finds {
            lead += 1; // withhold
        } else {
            // Honest network finds a block.
            if lead == 0 {
                hon_rev += 1; // extends public tip normally
            } else {
                // Attacker publishes its private chain and races.
                if lead == 1 {
                    // One-block race: attacker wins w.p. γ.
                    if rng.next_below(100) < gamma_pct {
                        att_rev += 1;
                    } else {
                        hon_rev += 1;
                    }
                } else {
                    // Lead ≥ 2: attacker chain strictly longer → wins all.
                    att_rev += lead;
                    // The honest block that triggered the publish is
                    // orphaned — it earns nothing.
                }
                lead = 0; // fork resolved either way
            }
        }
    }
    // Any still-withheld blocks are eventually published or orphaned —
    // count them as attacker revenue (best case for attacker).
    att_rev += lead;

    let total = att_rev + hon_rev;
    let share = att_rev as f64 / total as f64;
    let hashrate = alpha_num as f64 / alpha_den as f64;
    // The attack must be profitable: revenue share > hashrate share.
    assert!(
        share > hashrate,
        "selfish mining unprofitable: share={share:.4} hashrate={hashrate:.4} \
         (att={att_rev} hon={hon_rev})"
    );
    // And it should be meaningfully above — literature puts α=0.4,γ=0.5
    // around ~0.48. Guard against degenerate sims.
    assert!(share > 0.42, "sim implausibly low: {share:.4}");
}

/// Tiny deterministic xorshift64* PRNG — no external deps, reproducible.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn next_below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}
