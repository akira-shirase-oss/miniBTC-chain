//! The MCP payment gate's wallet half: drafts are built unsigned (and the
//! watch-only builder produces the same bytes as the keyed wallet), only
//! the owner's keys sign them, and the signed result is valid consensus.

use minibtc_chainstate::{UtxoEntry, UtxoSet};
use minibtc_consensus::{ChainParams, validate_tx};
use minibtc_crypto::{Hash256, Keypair};
use minibtc_primitives::{OutPoint, Sats, TxOutput};
use minibtc_script::Script;
use minibtc_wallet::draft::{ensure_unsigned, matches_draft};
use minibtc_wallet::{Wallet, WalletUtxo, build_unsigned_payment};

const SEED: [u8; 64] = [7u8; 64];

fn wallet(params: &ChainParams) -> Wallet {
    Wallet::from_seed(&SEED, "", 0, 0, params.address_version, 100)
        .unwrap_or_else(|e| panic!("wallet: {e:?}"))
}

/// A wallet with two confirmed coins on its first receive address.
fn funded(params: &ChainParams) -> (Wallet, UtxoSet) {
    let mut w = wallet(params);
    w.prime_lookahead(5)
        .unwrap_or_else(|e| panic!("lookahead: {e:?}"));
    let (scripts, _) = w.watch_scripts();
    let mut set = UtxoSet::default();
    for (i, v) in [5_000_000u64, 3_000_000].iter().enumerate() {
        set.insert(
            OutPoint {
                txid: Hash256([i as u8 + 1; 32]),
                vout: 0,
            },
            UtxoEntry {
                output: TxOutput {
                    value: Sats(*v),
                    script_pubkey: scripts[0].clone(),
                },
                height: 1,
                coinbase: false,
            },
        );
    }
    w.scan(&set, 10);
    (w, set)
}

fn payee() -> Vec<u8> {
    let key = Keypair::generate().unwrap_or_else(|e| panic!("keygen: {e:?}"));
    Script::p2pkh(&key.public_key().key_hash()).0
}

#[test]
fn draft_is_unsigned_and_only_the_owner_signs_it() {
    let params = ChainParams::devnet();
    let (mut w, set) = funded(&params);
    let to = payee();
    let draft = w.build_unsigned(&to, Sats(6_000_000), 5, 0).unwrap();
    ensure_unsigned(&draft.tx).unwrap();
    assert_eq!(draft.change_index, Some(1));

    let signed = w.sign_payment(&draft.tx).unwrap();
    matches_draft(&draft.tx, &signed).unwrap();
    let fee = validate_tx(&signed, &set, &params).unwrap();
    assert_eq!(fee, draft.fee, "fee decoded from bytes matches the draft");

    // A different wallet cannot sign it.
    let other = Wallet::from_seed(&[9u8; 64], "", 0, 0, params.address_version, 100).unwrap();
    assert!(other.sign_payment(&draft.tx).is_err());
}

#[test]
fn watch_only_builder_produces_the_same_bytes() {
    // The MCP drafts from public scripts only; the owner's keyed wallet
    // must arrive at the identical unsigned transaction.
    let params = ChainParams::devnet();
    let (mut w, set) = funded(&params);
    let (_, fresh_change) = w.watch_scripts();
    let mut coins: Vec<WalletUtxo> = set
        .iter()
        .map(|(op, e)| WalletUtxo {
            outpoint: *op,
            output: e.output.clone(),
            height: e.height,
            coinbase: e.coinbase,
            tip_height: 10,
        })
        .collect();
    coins.sort_by_key(|u| (u.outpoint.txid, u.outpoint.vout));
    let to = payee();
    let watch =
        build_unsigned_payment(&coins, &fresh_change[0], &to, Sats(6_000_000), 5, 0).unwrap();
    let keyed = w.build_unsigned(&to, Sats(6_000_000), 5, 0).unwrap();
    assert_eq!(watch.tx.outputs, keyed.tx.outputs);
    let mut a: Vec<_> = watch.tx.inputs.iter().map(|i| i.prev).collect();
    let mut b: Vec<_> = keyed.tx.inputs.iter().map(|i| i.prev).collect();
    a.sort_by_key(|o| (o.txid, o.vout));
    b.sort_by_key(|o| (o.txid, o.vout));
    assert_eq!(a, b);
    // And the owner can sign the watch-only draft.
    let signed = w.sign_payment(&watch.tx).unwrap();
    validate_tx(&signed, &set, &params).unwrap();
}
