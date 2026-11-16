//! Proof-of-work rules a validating node must enforce itself.
//!
//! "Hash below the target in `bits`" is only half the rule: the block
//! also chooses `bits`. Bitcoin Core requires `bits` to equal the value
//! the retarget schedule gives for the block's parent
//! (`GetNextWorkRequired`, "bad-diffbits") and the target to be no easier
//! than the network's proof-of-work limit (`CheckProofOfWork`). If only
//! the miner applies the schedule, a peer can pick any difficulty it
//! likes: trivially easy blocks on a real network, or difficulty games
//! that skew most-work fork choice.

mod common;

use common::*;
use minibtc_chainstate::Chain;
use minibtc_consensus::{ChainParams, decode_compact, encode_compact, retarget_bits};
use minibtc_crypto::{Hash256, Keypair};
use minibtc_primitives::*;

fn tip_header(chain: &Chain) -> BlockHeader {
    chain
        .blocks
        .get(&chain.tip)
        .map(|r| r.block.header)
        .unwrap_or_else(|| panic!("tip record missing"))
}

/// A block on the tip with chosen `bits`, mined to meet them.
fn block_with_bits(chain: &Chain, miner: &Keypair, bits: u32) -> Block {
    let prev = tip_header(chain);
    let cb = coinbase_tx(miner, chain.height() + 1, chain.params.subsidy_start);
    let txs = vec![cb];
    let header = mine_header(BlockHeader {
        version: 1,
        prev_hash: prev.block_hash(),
        merkle_root: merkle_root(&txs),
        time: prev.time + 31,
        bits,
        nonce: 0,
    });
    Block { header, txs }
}

fn chain_with_params(params: ChainParams) -> (Chain, Keypair) {
    let miner = Keypair::generate().unwrap_or_else(|e| panic!("keygen: {e:?}"));
    let cb = coinbase_tx(&miner, 0, params.subsidy_start);
    let genesis = Block {
        header: BlockHeader {
            version: 1,
            prev_hash: Hash256::ZERO,
            merkle_root: merkle_root(std::slice::from_ref(&cb)),
            time: 1_700_000_000,
            bits: params.pow_limit_bits,
            nonce: 0,
        },
        txs: vec![cb],
    };
    let chain = Chain::new(params, genesis).unwrap_or_else(|e| panic!("chain init: {e:?}"));
    (chain, miner)
}

#[test]
fn bits_other_than_the_schedule_are_rejected() {
    // Height 1 is not a retarget height: the block must carry its
    // parent's bits. A harder target still meets its own PoW check, so
    // only the schedule rule can refuse it.
    let (mut chain, miner) = fresh_chain();
    let harder = 0x1f7f_ffff;
    let block = block_with_bits(&chain, &miner, harder);
    let err = chain.consider_block(block).unwrap_err();
    assert!(
        format!("{err:?}").contains("DiffBits"),
        "bits off the schedule must be rejected as bad difficulty bits, got {err:?}"
    );
    assert_eq!(chain.height(), 0);

    // A "negative" compact encoding (sign bit set): it used to decode to
    // the same target as the limit with the sign silently dropped. It is
    // not a valid target at all (it cannot even be mined against now).
    let negative = chain.params.pow_limit_bits | 0x0080_0000;
    assert!(decode_compact(negative).is_err(), "negative bits decoded");
    let mut block = block_with_bits(&chain, &miner, chain.params.pow_limit_bits);
    block.header.bits = negative;
    assert!(
        chain.consider_block(block).is_err(),
        "sign-bit bits accepted"
    );

    // The scheduled bits connect.
    let block = block_with_bits(&chain, &miner, chain.params.pow_limit_bits);
    chain.consider_block(block).unwrap();
    assert_eq!(chain.height(), 1);
}

#[test]
fn target_easier_than_the_pow_limit_is_rejected() {
    // A network whose limit is harder than the block's bits.
    let mut params = ChainParams::devnet();
    params.pow_limit_bits = 0x1f7f_ffff;
    let (mut chain, miner) = chain_with_params(params.clone());

    let easy = 0x207f_ffff;
    let block = block_with_bits(&chain, &miner, easy);
    // Context-free check: no chain needed to know this target is too easy.
    let view = MapView(Default::default());
    assert!(
        minibtc_consensus::validate_block(&block, &view, &params, 1).is_err(),
        "a target above the pow limit must fail context-free validation"
    );
    assert!(
        chain.consider_block(block).is_err(),
        "too-easy block connected"
    );
    assert_eq!(chain.height(), 0);
}

#[test]
fn retarget_is_enforced_at_the_period_boundary() {
    // 19 blocks 31 s apart: the first period (genesis..19) took 589 s
    // against a 600 s target, so block 20 must carry slightly harder bits.
    let (mut chain, miner) = fresh_chain();
    mine_empty(&mut chain, &miner, 19);
    assert_eq!(chain.height(), 19);
    let params = chain.params.clone();
    let parent = tip_header(&chain);
    let genesis_time = chain.blocks.get(&chain.genesis).unwrap().block.header.time;
    let span = u64::from(parent.time - genesis_time);
    assert_eq!(span, 19 * 31);
    let target_span =
        u64::from(params.pow_target_spacing) * u64::from(params.pow_target_timespan_blocks);
    let expected = retarget_bits(parent.bits, span, target_span, params.pow_clamp_factor).unwrap();
    assert_ne!(expected, parent.bits, "this period must retarget");

    let stale = block_with_bits(&chain, &miner, parent.bits);
    assert!(
        chain.consider_block(stale).is_err(),
        "block 20 without the retarget must be rejected"
    );
    let retargeted = block_with_bits(&chain, &miner, expected);
    chain.consider_block(retargeted).unwrap();
    assert_eq!(chain.height(), 20);
}

#[test]
fn a_slow_period_never_makes_mining_harder() {
    // At the devnet limit, a period twice as slow as the target asks for
    // an easier target, which the limit caps. It must not overflow and
    // come back harder.
    let params = ChainParams::devnet();
    let target_span =
        u64::from(params.pow_target_spacing) * u64::from(params.pow_target_timespan_blocks);
    let bits = minibtc_miner::next_bits(&params, params.pow_limit_bits, 2 * target_span).unwrap();
    assert_eq!(
        bits, params.pow_limit_bits,
        "slow period must clamp to the limit"
    );
}

#[test]
fn compact_encoding_keeps_a_high_mantissa_bit() {
    // A target whose top significant byte is >= 0x80 must be encoded with
    // one more exponent byte (Bitcoin's GetCompact); otherwise the bit
    // lands on the compact sign bit and decoding drops it.
    let mut target = [0u8; 32];
    target[2] = 0x80;
    target[3] = 0x12;
    target[4] = 0x34;
    let bits = encode_compact(&target);
    assert_eq!(bits & 0x0080_0000, 0, "encoded bits must not be negative");
    let back = decode_compact(bits).unwrap();
    assert_eq!(back[..4], target[..4], "round trip lost the high bit");
}
