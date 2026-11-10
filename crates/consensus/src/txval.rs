//! Transaction validation against the UTXO set — the rules that make
//! "can't spend what doesn't exist" and "can't create money" enforceable.
//!
//! [`UtxoView`] is the read-only view consensus needs; `minibtc-chainstate`
//! implements it over the real UTXO set. Validation is pure: same inputs →
//! same verdict, no I/O, no clocks.
//!
//! The checks, in order (each maps to a named error so attackers and tests
//! can tell *which* rule fired):
//!
//! 1. tx decodes canonically (done by caller — `Transaction::decode`);
//! 2. non-empty inputs and outputs;
//! 3. **no duplicate inputs** — the same outpoint twice (CVE-2018-17144);
//! 4. every input's outpoint exists in the UTXO set and is unspent;
//! 5. every input's `scriptSig`+prevout `scriptPubKey` executes true
//!    (script engine — P2PKH today);
//! 6. `sum(outputs) ≤ sum(input values)` with **checked** arithmetic —
//!    the difference is the fee (the 2010 overflow class is dead by
//!    construction: `Sats` has no unchecked `+`);
//! 7. `sum(outputs) ≤ params.max_money`;
//! 8. coinbase txs get their own rules (single null-prevout input,
//!    outputs ≤ subsidy+fees — checked in [`crate::blockval`]).

use minibtc_primitives::{OutPoint, Sats, Transaction};
use minibtc_script::{self, ExecContext};
use std::collections::HashSet;

use crate::params::ChainParams;

/// Read-only view of the UTXO set for validation.
pub trait UtxoView {
    /// The output an outpoint refers to, if it exists and is unspent.
    fn get(&self, op: &OutPoint) -> Option<minibtc_primitives::TxOutput>;
}

/// Why a transaction was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxError {
    /// No inputs or no outputs.
    #[error("transaction has empty inputs or outputs")]
    Empty,
    /// The same outpoint appears twice (CVE-2018-17144 duplicate-input).
    #[error("duplicate input outpoint {0}")]
    DuplicateInput(OutPoint),
    /// An input references an outpoint not in the UTXO set.
    #[error("input spends unknown outpoint {0}")]
    MissingInput(OutPoint),
    /// scriptSig+scriptPubKey did not evaluate true.
    #[error("script failed for input {index}: {reason}")]
    ScriptFailed {
        /// Input index that failed.
        index: usize,
        /// Script engine's reason.
        reason: String,
    },
    /// Outputs exceed inputs — creating money.
    #[error("outputs ({out}) exceed inputs ({input})")]
    Overspend {
        /// Sum of output values.
        out: u64,
        /// Sum of input values.
        input: u64,
    },
    /// A value sum overflowed u64 — impossible for valid chains, treated
    /// as an attack and rejected.
    #[error("value sum overflow")]
    ValueOverflow,
    /// Outputs exceed the chain's max-money ceiling.
    #[error("outputs exceed max_money")]
    ExceedsMaxMoney,
    /// A non-coinbase tx tried to look like a coinbase (null prevout).
    #[error("non-coinbase transaction uses null outpoint")]
    BadCoinbaseShape,
}

/// Validate a *non-coinbase* transaction against `view`.
///
/// `params` supplies `max_money`/`max_tx_io`; `view` supplies prevouts.
/// Returns the fee (inputs − outputs) on success — callers use it for
/// coinbase subsidy math and mempool accounting.
pub fn validate_tx<V: UtxoView>(
    tx: &Transaction,
    view: &V,
    params: &ChainParams,
) -> Result<Sats, TxError> {
    if tx.inputs.is_empty() || tx.outputs.is_empty() {
        return Err(TxError::Empty);
    }
    if tx.inputs.len() > params.max_tx_io || tx.outputs.len() > params.max_tx_io {
        return Err(TxError::Empty); // reuse: caller enforces decode bound too
    }
    // Coinbase-shaped txs must not enter this path at all.
    for inp in &tx.inputs {
        if inp.prev == OutPoint::NULL {
            return Err(TxError::BadCoinbaseShape);
        }
    }

    // 1. Duplicate-input rejection — hash set, O(n).
    let mut seen = HashSet::with_capacity(tx.inputs.len());
    for inp in &tx.inputs {
        if !seen.insert(inp.prev) {
            return Err(TxError::DuplicateInput(inp.prev));
        }
    }

    // 2./3. Resolve inputs, sum values, run scripts.
    let mut in_sum = Sats::ZERO;
    let mut prevouts: Vec<minibtc_primitives::TxOutput> = Vec::with_capacity(tx.inputs.len());
    for (i, inp) in tx.inputs.iter().enumerate() {
        let prev = view.get(&inp.prev).ok_or(TxError::MissingInput(inp.prev))?;
        in_sum = in_sum
            .checked_add(prev.value)
            .ok_or(TxError::ValueOverflow)?;
        // scriptSig + prevout scriptPubKey must evaluate true.
        let ctx = ExecContext {
            tx,
            input_index: i,
            script_code: &prev.script_pubkey,
        };
        minibtc_script::execute(&inp.script_sig, &prev.script_pubkey, &ctx).map_err(|e| {
            TxError::ScriptFailed {
                index: i,
                reason: e.to_string(),
            }
        })?;
        prevouts.push(prev);
    }

    // 4. Output sum — checked, bounded by max_money.
    let out_sum = tx.output_sum().ok_or(TxError::ValueOverflow)?;
    if out_sum > params.max_money_sats() {
        return Err(TxError::ExceedsMaxMoney);
    }
    if out_sum > in_sum {
        return Err(TxError::Overspend {
            out: out_sum.sats(),
            input: in_sum.sats(),
        });
    }
    let fee = in_sum.checked_sub(out_sum).ok_or(TxError::ValueOverflow)?;
    let _ = prevouts; // kept for future per-input script variants
    Ok(fee)
}

#[cfg(test)]
mod tests {
    use super::*;
    use minibtc_crypto::Hash256;
    use minibtc_crypto::Keypair;
    use minibtc_primitives::{OutPoint, Transaction, TxInput, TxOutput};
    use minibtc_script::{Script, sighash};
    use std::collections::HashMap;

    struct MapView(HashMap<OutPoint, minibtc_primitives::TxOutput>);
    impl UtxoView for MapView {
        fn get(&self, op: &OutPoint) -> Option<minibtc_primitives::TxOutput> {
            self.0.get(op).cloned()
        }
    }

    fn p2pkh_outpoint_value(kp: &Keypair, value: u64) -> (OutPoint, minibtc_primitives::TxOutput) {
        let op = OutPoint {
            txid: Hash256([0xAA; 32]),
            vout: 0,
        };
        let out = minibtc_primitives::TxOutput {
            value: Sats(value),
            script_pubkey: Script::p2pkh(&kp.public_key().key_hash()).0,
        };
        (op, out)
    }

    fn signed_spend(kp: &Keypair, op: OutPoint, prev_spk: &[u8], out_value: u64) -> Transaction {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev: op,
                script_sig: vec![],
                sequence: 0xffff_ffff,
            }],
            outputs: vec![TxOutput {
                value: Sats(out_value),
                script_pubkey: Script::p2pkh(&kp.public_key().key_hash()).0,
            }],
            locktime: 0,
        };
        let item = sighash::sign_input(&tx, 0, prev_spk, kp).unwrap();
        tx.inputs[0].script_sig = Script::p2pkh_spend(&item, &kp.public_key()).0;
        tx
    }

    #[test]
    fn valid_spend_accepted_and_fee_computed() {
        let p = ChainParams::devnet();
        let kp = Keypair::generate().unwrap();
        let (op, out) = p2pkh_outpoint_value(&kp, 10_000);
        let mut map = HashMap::new();
        map.insert(op, out.clone());
        let view = MapView(map);
        let tx = signed_spend(&kp, op, &out.script_pubkey, 9_000);
        let fee = validate_tx(&tx, &view, &p).unwrap();
        assert_eq!(fee, Sats(1_000));
    }

    #[test]
    fn missing_input_rejected() {
        let p = ChainParams::devnet();
        let kp = Keypair::generate().unwrap();
        let view = MapView(HashMap::new());
        let tx = signed_spend(
            &kp,
            OutPoint {
                txid: Hash256([1; 32]),
                vout: 0,
            },
            &[0x51],
            1,
        );
        assert!(matches!(
            validate_tx(&tx, &view, &p),
            Err(TxError::MissingInput(_))
        ));
    }

    #[test]
    fn duplicate_inputs_rejected() {
        let p = ChainParams::devnet();
        let kp = Keypair::generate().unwrap();
        let (op, out) = p2pkh_outpoint_value(&kp, 10_000);
        let mut map = HashMap::new();
        map.insert(op, out);
        let view = MapView(map);
        let mut tx = signed_spend(
            &kp,
            op,
            &Script::p2pkh(&kp.public_key().key_hash()).0,
            5_000,
        );
        // Duplicate the input — same outpoint twice.
        tx.inputs.push(tx.inputs[0].clone());
        assert!(matches!(
            validate_tx(&tx, &view, &p),
            Err(TxError::DuplicateInput(_))
        ));
    }

    #[test]
    fn overspend_rejected() {
        let p = ChainParams::devnet();
        let kp = Keypair::generate().unwrap();
        let (op, out) = p2pkh_outpoint_value(&kp, 1_000);
        let mut map = HashMap::new();
        map.insert(op, out.clone());
        let view = MapView(map);
        // Sign for output value 5_000 > input 1_000 — script verifies
        // (sig commits to the overspend tx!) but value rule must reject.
        let tx = signed_spend(&kp, op, &out.script_pubkey, 5_000);
        assert!(matches!(
            validate_tx(&tx, &view, &p),
            Err(TxError::Overspend { .. })
        ));
    }

    #[test]
    fn wrong_signer_script_fails() {
        let p = ChainParams::devnet();
        let owner = Keypair::generate().unwrap();
        let thief = Keypair::generate().unwrap();
        let (op, out) = p2pkh_outpoint_value(&owner, 10_000);
        let mut map = HashMap::new();
        map.insert(op, out.clone());
        let view = MapView(map);
        // Thief signs — signature verifies against *thief's* key but the
        // prevout commits to owner's hash160 → script fails.
        let tx = signed_spend(&thief, op, &out.script_pubkey, 9_000);
        assert!(matches!(
            validate_tx(&tx, &view, &p),
            Err(TxError::ScriptFailed { .. })
        ));
    }

    #[test]
    fn coinbase_shaped_input_rejected() {
        let p = ChainParams::devnet();
        let view = MapView(HashMap::new());
        let tx = Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev: OutPoint::NULL,
                script_sig: vec![],
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: Sats(1),
                script_pubkey: vec![],
            }],
            locktime: 0,
        };
        assert!(matches!(
            validate_tx(&tx, &view, &p),
            Err(TxError::BadCoinbaseShape)
        ));
    }
}
