//! Deterministic genesis block for a MiniBTC network.
//!
//! Every node must construct the *identical* genesis or their chains can
//! never agree — so this is a pure function of [`ChainParams`]. The
//! coinbase pays a fixed devnet key whose secret is a public constant:
//! anyone can spend matured genesis subsidy on a learning chain. This is
//! intentional and documented; it is never used for real value.

use crate::ChainParams;
use minibtc_crypto::{Keypair, double_sha256};
use minibtc_primitives::{
    Block, BlockHeader, OutPoint, Sats, Transaction, TxInput, TxOutput, merkle_root,
};
use minibtc_script::Script;

/// Fixed genesis timestamp (deterministic across all nodes).
const GENESIS_TIME: u32 = 1_700_000_000;

/// The public devnet genesis secret — `SHA256("minibtc-devnet-genesis-v1")`.
/// Documented openly: genesis subsidy is claimable by design on devnets.
pub fn genesis_secret() -> [u8; 32] {
    double_sha256(b"minibtc-devnet-genesis-v1").0
}

/// The genesis payout keypair (public constant).
pub fn genesis_key() -> Keypair {
    let secret = genesis_secret();
    // The secret is a hash output — valid scalar with overwhelming
    // probability; fall back through counters if the curve rejects it.
    for i in 0u32..16 {
        let mut candidate = secret;
        if i > 0 {
            let h = double_sha256(&[&secret[..], &i.to_le_bytes()[..]].concat());
            candidate = h.0;
        }
        if let Ok(k) = Keypair::from_secret_bytes(&candidate) {
            return k;
        }
    }
    // Unreachable in practice; a zero key would be a consensus bug, so
    // panic loudly rather than emit an invalid genesis.
    panic!("genesis key derivation failed — impossible hash output")
}

/// Build the deterministic genesis block for `params`.
///
/// Structure mirrors the miner's coinbase (BIP34-style height in
/// scriptSig) paying `subsidy_start` to [`genesis_key`]'s P2PKH address
/// under `params.address_version`.
pub fn genesis_block(params: &ChainParams) -> Block {
    let key = genesis_key();
    let payout = Script::p2pkh(&key.public_key().key_hash()).0;
    let coinbase = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: OutPoint::NULL,
            script_sig: {
                let mut s = vec![0x02, 0x00, 0x00]; // height 0, BIP34-style
                s.extend_from_slice(b"MBTC");
                s.extend_from_slice(params.name.as_bytes());
                s
            },
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput {
            value: Sats(params.subsidy_start),
            script_pubkey: payout,
        }],
        locktime: 0,
    };
    let mut header = BlockHeader {
        version: 1,
        prev_hash: minibtc_crypto::Hash256::ZERO,
        merkle_root: merkle_root(std::slice::from_ref(&coinbase)),
        time: GENESIS_TIME,
        bits: params.pow_limit_bits,
        nonce: 0,
    };
    // On instant-difficulty networks, grind the genesis nonce so even the
    // genesis header satisfies its own PoW check (nice invariant; real
    // networks can't afford this and skip it).
    if params.instant_difficulty
        && let Ok(target) = crate::pow::target_for_bits(header.bits)
    {
        let mut n = 0u32;
        loop {
            header.nonce = n;
            if header.check_pow(&target) || n >= 1_000_000 {
                break;
            }
            n = n.wrapping_add(1);
        }
    }
    Block {
        header,
        txs: vec![coinbase],
    }
}
