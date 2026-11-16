//! Reviewing a payment draft from its **bytes**.
//!
//! An AI-drafted payment is reviewed and capped from the decoded
//! transaction, never from a JSON summary next to it: a summary can say
//! "1 sat to Bob" while the bytes pay everything to someone else. These
//! helpers are pure so the MCP gate, the CLI approval prompt and the tests
//! all use the same rules.

use minibtc_crypto::{Address, Hash160};
use minibtc_primitives::{Sats, Transaction};

/// Why a draft or its signed form was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DraftError {
    /// A draft must be unsigned: signing happens only after approval.
    #[error("draft input {0} already carries a signature")]
    AlreadySigned(usize),
    /// The approved transaction is not the drafted one.
    #[error("signed transaction differs from the draft: {0}")]
    Mismatch(&'static str),
    /// A signed input has no signature.
    #[error("signed transaction input {0} is unsigned")]
    Unsigned(usize),
    /// Input values do not line up with the inputs.
    #[error("expected {expected} input values, got {got}")]
    InputValues {
        /// Inputs in the transaction.
        expected: usize,
        /// Values supplied.
        got: usize,
    },
    /// A change index points past the outputs.
    #[error("change index {0} out of range")]
    BadChangeIndex(usize),
    /// Outputs exceed inputs, or a sum overflowed.
    #[error("value arithmetic failed: {0}")]
    Value(&'static str),
}

/// What a transaction spends, computed from its bytes and its inputs'
/// values. `external` is everything not returning to the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpendSummary {
    /// Sum of input values.
    pub total_in: Sats,
    /// Sum of output values.
    pub total_out: Sats,
    /// `total_in − total_out`.
    pub fee: Sats,
    /// Outputs that are not change.
    pub external: Sats,
    /// `external + fee`: what leaves the wallet — the number caps apply to.
    pub spend: Sats,
}

/// The P2PKH address a script pays, if it is a standard P2PKH script.
pub fn p2pkh_address(script: &[u8], version: u8) -> Option<Address> {
    if script.len() == 25 && script[..3] == [0x76, 0xa9, 0x14] && script[23..] == [0x88, 0xac] {
        let mut h = [0u8; 20];
        h.copy_from_slice(&script[3..23]);
        Some(Address::p2pkh(version, Hash160(h)))
    } else {
        None
    }
}

/// A draft must carry no signatures.
pub fn ensure_unsigned(tx: &Transaction) -> Result<(), DraftError> {
    match tx.inputs.iter().position(|i| !i.script_sig.is_empty()) {
        Some(i) => Err(DraftError::AlreadySigned(i)),
        None => Ok(()),
    }
}

/// `signed` must be exactly `unsigned` plus a signature on every input:
/// same version, locktime, outputs, and inputs (outpoint + sequence).
pub fn matches_draft(unsigned: &Transaction, signed: &Transaction) -> Result<(), DraftError> {
    if unsigned.version != signed.version || unsigned.locktime != signed.locktime {
        return Err(DraftError::Mismatch("version or locktime"));
    }
    if unsigned.outputs != signed.outputs {
        return Err(DraftError::Mismatch("outputs"));
    }
    if unsigned.inputs.len() != signed.inputs.len() {
        return Err(DraftError::Mismatch("input count"));
    }
    for (i, (u, s)) in unsigned.inputs.iter().zip(&signed.inputs).enumerate() {
        if u.prev != s.prev || u.sequence != s.sequence {
            return Err(DraftError::Mismatch("inputs"));
        }
        if s.script_sig.is_empty() {
            return Err(DraftError::Unsigned(i));
        }
    }
    Ok(())
}

/// Spend of `tx` given each input's value (in input order) and which
/// outputs are change.
pub fn spend_summary(
    tx: &Transaction,
    input_values: &[Sats],
    change: &[usize],
) -> Result<SpendSummary, DraftError> {
    if input_values.len() != tx.inputs.len() {
        return Err(DraftError::InputValues {
            expected: tx.inputs.len(),
            got: input_values.len(),
        });
    }
    if let Some(&bad) = change.iter().find(|&&c| c >= tx.outputs.len()) {
        return Err(DraftError::BadChangeIndex(bad));
    }
    let total_in = input_values
        .iter()
        .try_fold(Sats::ZERO, |acc, v| acc.checked_add(*v))
        .ok_or(DraftError::Value("input sum overflow"))?;
    let total_out = tx
        .output_sum()
        .ok_or(DraftError::Value("output sum overflow"))?;
    let fee = total_in
        .checked_sub(total_out)
        .ok_or(DraftError::Value("outputs exceed inputs"))?;
    let external = tx
        .outputs
        .iter()
        .enumerate()
        .filter(|(i, _)| !change.contains(i))
        .try_fold(Sats::ZERO, |acc, (_, o)| acc.checked_add(o.value))
        .ok_or(DraftError::Value("external sum overflow"))?;
    let spend = external
        .checked_add(fee)
        .ok_or(DraftError::Value("spend overflow"))?;
    Ok(SpendSummary {
        total_in,
        total_out,
        fee,
        external,
        spend,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use minibtc_primitives::{OutPoint, TxInput, TxOutput};

    fn tx(sig: bool, outputs: &[u64]) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxInput {
                prev: OutPoint {
                    txid: minibtc_crypto::Hash256([1; 32]),
                    vout: 0,
                },
                script_sig: if sig { vec![0x01, 0x02] } else { vec![] },
                sequence: 0xffff_fffe,
            }],
            outputs: outputs
                .iter()
                .map(|v| TxOutput {
                    value: Sats(*v),
                    script_pubkey: vec![0x51],
                })
                .collect(),
            locktime: 0,
        }
    }

    #[test]
    fn drafts_must_be_unsigned() {
        assert_eq!(ensure_unsigned(&tx(false, &[1])), Ok(()));
        assert_eq!(
            ensure_unsigned(&tx(true, &[1])),
            Err(DraftError::AlreadySigned(0))
        );
    }

    #[test]
    fn signed_form_must_be_the_drafted_transaction() {
        let draft = tx(false, &[700, 200]);
        assert_eq!(matches_draft(&draft, &tx(true, &[700, 200])), Ok(()));
        assert!(matches!(
            matches_draft(&draft, &tx(true, &[900])),
            Err(DraftError::Mismatch("outputs"))
        ));
        assert_eq!(
            matches_draft(&draft, &tx(false, &[700, 200])),
            Err(DraftError::Unsigned(0))
        );
    }

    #[test]
    fn spend_comes_from_the_bytes() {
        // 1,000 in: 700 to the payee, 200 change, fee 100.
        let t = tx(true, &[700, 200]);
        let s = spend_summary(&t, &[Sats(1_000)], &[1]).unwrap();
        assert_eq!(s.fee, Sats(100));
        assert_eq!(s.external, Sats(700));
        assert_eq!(s.spend, Sats(800));
        // Claiming the payee output as change does not hide it if the
        // claim is not believed: with no change, everything counts.
        let all = spend_summary(&t, &[Sats(1_000)], &[]).unwrap();
        assert_eq!(all.spend, Sats(1_000));
        assert!(spend_summary(&t, &[Sats(500)], &[1]).is_err(), "overspend");
        assert!(spend_summary(&t, &[], &[1]).is_err(), "values missing");
        assert!(
            spend_summary(&t, &[Sats(1_000)], &[5]).is_err(),
            "bad index"
        );
    }

    #[test]
    fn p2pkh_scripts_map_to_addresses() {
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&[7u8; 20]);
        script.extend_from_slice(&[0x88, 0xac]);
        let a = p2pkh_address(&script, 0x6f).unwrap();
        assert_eq!(a.hash160.0, [7u8; 20]);
        assert!(p2pkh_address(&[0x51], 0x6f).is_none());
    }
}
