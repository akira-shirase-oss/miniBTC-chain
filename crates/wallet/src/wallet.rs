//! # Wallet
//!
//! The spending wallet: BIP44 account management, address gap-limit
//! tracking, UTXO scanning, balance, coin selection, change, fee policy,
//! and build+sign.
//!
//! Design:
//! - One BIP44 account: `m/44'/0'/0'` (coin type 0 = "Bitcoin-like" on
//!   our devnet; configurable).
//! - Receive chain `/0/i`, change chain `/1/i`, gap limit 20 (BIP44).
//! - Every address we hand out is recorded with its derivation index so
//!   signing can find the right key — we never scan the whole tree.
//! - `scan` matches chain UTXOs against our scripts → wallet UTXOs with
//!   confirmation depth (coinbase maturity enforced by chainstate; wallet
//!   additionally reports spendable vs immature).
//! - `build_and_sign` produces a fully-signed legacy transaction ready
//!   for mempool/relay.

use crate::bip32::{ChildNumber, DerivationPath, Xpriv};
use crate::bip39;
use minibtc_consensus::UtxoView;
use minibtc_crypto::{Address, Keypair, hash160};
use minibtc_primitives::{OutPoint, Sats, Transaction, TxInput, TxOutput};
use minibtc_script::{Script, sighash};
use std::collections::HashMap;
use thiserror::Error;

/// BIP44 gap limit — stop deriving after this many unused addresses.
pub const GAP_LIMIT: u32 = 20;
/// Default fee rate: sats per 1000 bytes (sats/kvB).
pub const DEFAULT_FEE_RATE: u64 = 1;
/// Max coin-selection iterations for fee-size convergence.
const FEE_ITERS: usize = 4;

/// Wallet errors.
#[derive(Debug, Error)]
pub enum WalletError {
    /// HD derivation failed.
    #[error("key derivation: {0}")]
    Derivation(#[from] crate::bip32::Bip32Error),
    /// BIP39 failure.
    #[error("mnemonic: {0}")]
    Mnemonic(#[from] bip39::Bip39Error),
    /// Not enough spendable balance.
    #[error("insufficient funds: need {need} sats, have {have}")]
    InsufficientFunds {
        /// Required amount incl. fee.
        need: u64,
        /// Available.
        have: u64,
    },
    /// A UTXO we tried to spend isn't ours / is immature.
    #[error("unspendable utxo {0}")]
    Unspendable(OutPoint),
    /// Signing failed.
    #[error("signing: {0}")]
    Sign(#[from] sighash::SignError),
    /// Output would be dust.
    #[error("output below dust limit")]
    Dust,
    /// Arithmetic overflow.
    #[error("amount overflow")]
    Overflow,
    /// Key material rejected.
    #[error("bad key: {0}")]
    Key(#[from] minibtc_crypto::KeyError),
}

/// A wallet UTXO: an outpoint paying one of our scripts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletUtxo {
    /// The outpoint.
    pub outpoint: OutPoint,
    /// The output (value + script_pubkey).
    pub output: TxOutput,
    /// Creating block height.
    pub height: u32,
    /// Whether it came from a coinbase (maturity rules apply).
    pub coinbase: bool,
    /// Current chain tip height (for confirmation math) — set by scan.
    pub tip_height: u32,
}

impl WalletUtxo {
    /// Confirmations = tip − height + 1.
    pub fn confirmations(&self) -> u32 {
        self.tip_height
            .saturating_sub(self.height)
            .saturating_add(1)
    }

    /// Spendable given coinbase maturity `m`.
    pub fn spendable(&self, maturity: u32) -> bool {
        !self.coinbase || self.confirmations() > maturity
    }
}

/// A tracked address + its derivation info.
#[derive(Clone, Debug)]
struct AddressEntry {
    /// Derivation index within its chain (receive=0, change=1).
    index: u32,
    /// 0 = receive, 1 = change.
    chain: u8,
    /// The address.
    address: Address,
    /// script_pubkey bytes.
    script: Vec<u8>,
    /// The Xpriv at the leaf (for signing).
    key: Xpriv,
}

/// Coin selection result.
#[derive(Clone, Debug)]
pub struct CoinSelection {
    /// Chosen UTXOs.
    pub inputs: Vec<WalletUtxo>,
    /// Total input value.
    pub total_in: Sats,
    /// Amount going to the recipient.
    pub payment: Sats,
    /// Change returning to us (0 if none / dust).
    pub change: Sats,
    /// Fee paid.
    pub fee: Sats,
}

/// The wallet.
pub struct Wallet {
    /// Account-level extended private key (m/44'/coin'/account').
    account: Xpriv,
    /// Next receive index to hand out.
    next_receive: u32,
    /// Next change index.
    next_change: u32,
    /// All addresses we've generated, by script_pubkey.
    addresses: HashMap<Vec<u8>, AddressEntry>,
    /// Wallet UTXOs found by the last scan.
    utxos: Vec<WalletUtxo>,
    /// Address version byte (params).
    address_version: u8,
    /// coinbase maturity for spendable() — set by node scan.
    maturity: u32,
    /// BIP39 passphrase used at seed time (empty default) — kept so a
    /// re-derive produces the same keys.
    _bip39_passphrase: String,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("addresses", &self.addresses.len())
            .field("utxos", &self.utxos.len())
            .field("next_receive", &self.next_receive)
            .field("next_change", &self.next_change)
            .finish_non_exhaustive()
    }
}

impl Wallet {
    /// New wallet from a mnemonic phrase (+ optional BIP39 passphrase).
    /// Derives `m/44'/coin_type'/account'`.
    pub fn from_mnemonic(
        phrase: &str,
        bip39_passphrase: &str,
        coin_type: u32,
        account: u32,
        address_version: u8,
        maturity: u32,
    ) -> Result<Self, WalletError> {
        let seed = bip39::seed_from_mnemonic(phrase, bip39_passphrase)?;
        Self::from_seed(
            &seed,
            bip39_passphrase,
            coin_type,
            account,
            address_version,
            maturity,
        )
    }

    /// New wallet from a raw 64-byte seed.
    pub fn from_seed(
        seed: &[u8; 64],
        bip39_passphrase: &str,
        coin_type: u32,
        account: u32,
        address_version: u8,
        maturity: u32,
    ) -> Result<Self, WalletError> {
        let master = Xpriv::master(seed)?;
        let path = DerivationPath::bip44_account(coin_type, account);
        let account_key = master.derive_path(&path)?;
        Ok(Self {
            account: account_key,
            next_receive: 0,
            next_change: 0,
            addresses: HashMap::new(),
            utxos: Vec::new(),
            address_version,
            maturity,
            _bip39_passphrase: bip39_passphrase.to_string(),
        })
    }

    /// Fresh wallet: new mnemonic + seed (caller must back up the phrase).
    pub fn generate(
        bip39_passphrase: &str,
        coin_type: u32,
        account: u32,
        address_version: u8,
        maturity: u32,
    ) -> Result<(Self, crate::bip39::Mnemonic), WalletError> {
        let mnemonic = crate::bip39::generate_mnemonic()?;
        let w = Self::from_mnemonic(
            &mnemonic.phrase(),
            bip39_passphrase,
            coin_type,
            account,
            address_version,
            maturity,
        )?;
        Ok((w, mnemonic))
    }

    /// Derive the leaf key + address for (chain, index), registering it.
    fn derive_address(&mut self, chain: u8, index: u32) -> Result<AddressEntry, WalletError> {
        let child = ChildNumber {
            index,
            hardened: false,
        };
        // Path from account: /chain/index — chain is itself an index.
        let path = DerivationPath {
            children: vec![
                ChildNumber {
                    index: u32::from(chain),
                    hardened: false,
                },
                child,
            ],
        };
        let key = self.account.derive_path(&path)?;
        let pub_bytes = key.public_key_bytes()?;
        let h160 = hash160(&pub_bytes);
        let script = Script::p2pkh(&h160).0;
        let address = Address::p2pkh(self.address_version, h160);
        Ok(AddressEntry {
            index,
            chain,
            address,
            script: script.clone(),
            key,
        })
    }

    /// A fresh receive address (gap-limit managed).
    pub fn new_address(&mut self) -> Result<Address, WalletError> {
        // Gap limit bounds *scanning*, not explicit requests — always
        // derive the next fresh index.
        let i = self.next_receive;
        let entry = self.derive_address(0, i)?;
        let script = entry.script.clone();
        let address = entry.address.clone();
        self.addresses.insert(script, entry);
        self.next_receive = i.saturating_add(1);
        Ok(address)
    }

    /// A fresh change address.
    pub fn new_change_address(&mut self) -> Result<Address, WalletError> {
        let i = self.next_change;
        let entry = self.derive_address(1, i)?;
        let address = entry.address.clone();
        self.addresses.insert(entry.script.clone(), entry);
        self.next_change = i.saturating_add(1);
        Ok(address)
    }

    /// Issuance counters `(next_receive, next_change)` — persisted by the
    /// wallet-file layer so reloads resume where they left off.
    pub fn indices(&self) -> (u32, u32) {
        (self.next_receive, self.next_change)
    }

    /// Restore issuance counters (wallet-file load path). Only the
    /// wallet-file owner should call this — skipping indices orphans
    /// addresses that may already have funds.
    pub fn set_indices(&mut self, receive: u32, change: u32) {
        self.next_receive = receive;
        self.next_change = change;
    }

    /// Pre-derive receive+change addresses for indices
    /// `[0, next+gap)` on both chains so `scan` sees the full
    /// used+lookahead window. Does NOT advance issuance counters —
    /// `new_address` still hands out `next_receive` fresh.
    pub fn prime_lookahead(&mut self, gap: u32) -> Result<(), WalletError> {
        let r_end = self.next_receive.saturating_add(gap);
        for i in 0..r_end {
            let entry = self.derive_address(0, i)?;
            self.addresses.insert(entry.script.clone(), entry);
        }
        let c_end = self.next_change.saturating_add(gap);
        for i in 0..c_end {
            let entry = self.derive_address(1, i)?;
            self.addresses.insert(entry.script.clone(), entry);
        }
        Ok(())
    }

    /// All addresses we've issued (receive chain).
    pub fn addresses(&self) -> Vec<Address> {
        let mut v: Vec<&AddressEntry> = self.addresses.values().filter(|e| e.chain == 0).collect();
        v.sort_by_key(|e| e.index);
        v.into_iter().map(|e| e.address.clone()).collect()
    }

    /// Look up the key entry for a script_pubkey (our addresses only).
    fn key_for_script(&self, script: &[u8]) -> Option<&AddressEntry> {
        self.addresses.get(script)
    }

    /// Rescan the chain's UTXO set: keep outputs paying our scripts.
    /// `view` must cover the active chain's UTXOs (chainstate UtxoSet or
    /// a storage-loaded equivalent).
    pub fn scan<V: UtxoView + IterableUtxos>(&mut self, view: &V, tip_height: u32) -> usize {
        self.utxos.clear();
        let mut found = 0usize;
        for (op, entry) in view.utxo_iter() {
            if self
                .addresses
                .contains_key(entry.output.script_pubkey.as_slice())
            {
                self.utxos.push(WalletUtxo {
                    outpoint: *op,
                    output: entry.output.clone(),
                    height: entry.height,
                    coinbase: entry.coinbase,
                    tip_height,
                });
                found += 1;
            }
        }
        found
    }

    /// Total balance across all wallet UTXOs (mature + immature shown
    /// separately).
    pub fn balance(&self) -> (Sats, Sats) {
        let mut mature = Sats::ZERO;
        let mut immature = Sats::ZERO;
        for u in &self.utxos {
            if u.spendable(self.maturity) {
                mature = mature.checked_add(u.output.value).unwrap_or(mature);
            } else {
                immature = immature.checked_add(u.output.value).unwrap_or(immature);
            }
        }
        (mature, immature)
    }

    /// Spendable UTXOs only.
    pub fn spendable_utxos(&self) -> Vec<&WalletUtxo> {
        self.utxos
            .iter()
            .filter(|u| u.spendable(self.maturity))
            .collect()
    }

    /// All wallet UTXOs (for display).
    pub fn utxos(&self) -> &[WalletUtxo] {
        &self.utxos
    }

    /// Select coins to cover `target` (payment + estimated fee) using a
    /// greedy-largest-first strategy. Returns the selection or
    /// InsufficientFunds.
    pub fn select_coins(
        &self,
        target: Sats,
        fee_estimate: Sats,
    ) -> Result<CoinSelection, WalletError> {
        let need = target
            .checked_add(fee_estimate)
            .ok_or(WalletError::Overflow)?;
        let mut candidates: Vec<&WalletUtxo> = self.spendable_utxos();
        candidates.sort_by(|a, b| b.output.value.cmp(&a.output.value));
        let mut selected: Vec<WalletUtxo> = Vec::new();
        let mut total = Sats::ZERO;
        for u in candidates {
            if total >= need {
                break;
            }
            selected.push(u.clone());
            total = total
                .checked_add(u.output.value)
                .ok_or(WalletError::Overflow)?;
        }
        if total < need {
            return Err(WalletError::InsufficientFunds {
                need: need.sats(),
                have: total.sats(),
            });
        }
        Ok(CoinSelection {
            inputs: selected,
            total_in: total,
            payment: target,
            change: Sats::ZERO, // computed later
            fee: fee_estimate,
        })
    }

    /// Build + sign a payment transaction.
    ///
    /// `payment_script` — destination script_pubkey (e.g. P2PKH of
    /// recipient address).
    /// `payment` — amount in sats.
    /// `fee_rate` — sats per 1000 bytes (kvB); fee converges iteratively.
    ///
    /// Returns the signed transaction (ready for mempool admit).
    pub fn build_and_sign(
        &mut self,
        payment_script: &[u8],
        payment: Sats,
        fee_rate: u64,
        locktime: u32,
    ) -> Result<Transaction, WalletError> {
        // Iteratively converge on fee: size depends on input count and
        // whether change output exists.
        let mut fee = Sats(estimate_fee(fee_rate, 1, 2)); // rough start
        let mut selection: Option<CoinSelection> = None;
        for _ in 0..FEE_ITERS {
            let sel = self.select_coins(payment, fee)?;
            // Would change be dust? Then no change output → smaller fee.
            let change_val = sel
                .total_in
                .checked_sub(payment)
                .and_then(|v| v.checked_sub(fee))
                .ok_or(WalletError::Overflow)?;
            let has_change = change_val.sats() >= DUST_LIMIT;
            let est_size = estimate_tx_size(sel.inputs.len(), has_change);
            let new_fee = fee_rate_to_fee(fee_rate, est_size);
            if new_fee == fee {
                selection = Some(sel);
                break;
            }
            fee = new_fee;
            selection = Some(sel);
        }
        let mut sel = selection.ok_or(WalletError::Overflow)?;

        // Final change computation.
        let mut outputs = vec![TxOutput {
            value: payment,
            script_pubkey: payment_script.to_vec(),
        }];
        let change_val = sel
            .total_in
            .checked_sub(payment)
            .and_then(|v| v.checked_sub(sel.fee))
            .ok_or(WalletError::Overflow)?;
        if change_val.sats() >= DUST_LIMIT {
            let change_addr = self.new_change_address()?;
            let change_script = self
                .addresses
                .values()
                .find(|e| e.address == change_addr)
                .map(|e| e.script.clone())
                .ok_or(WalletError::Overflow)?;
            outputs.push(TxOutput {
                value: change_val,
                script_pubkey: change_script,
            });
            sel.change = change_val;
        } else {
            // No change → fold remainder into fee.
            sel.fee = sel
                .total_in
                .checked_sub(payment)
                .ok_or(WalletError::Overflow)?;
        }

        // Build inputs.
        let mut inputs = Vec::with_capacity(sel.inputs.len());
        for u in &sel.inputs {
            let script = u.output.script_pubkey.clone();
            inputs.push(TxInput {
                prev: u.outpoint,
                script_sig: vec![],    // filled after signing
                sequence: 0xffff_fffe, // signal RBF
            });
            let _ = script;
        }

        let mut tx = Transaction {
            version: 1,
            inputs,
            outputs,
            locktime,
        };

        // Sign each input with its owning key.
        for i in 0..tx.inputs.len() {
            let op = tx.inputs[i].prev;
            let utxo = sel
                .inputs
                .iter()
                .find(|u| u.outpoint == op)
                .ok_or(WalletError::Unspendable(op))?;
            let script = utxo.output.script_pubkey.clone();
            let entry = self
                .key_for_script(&script)
                .ok_or(WalletError::Unspendable(op))?;
            let keypair = Keypair::from_secret_bytes(&entry.key.secret_bytes())?;
            let prev_script = Script::from_bytes(script);
            let script_sig = sighash::p2pkh_script_sig(&tx, i, &prev_script, &keypair)?;
            tx.inputs[i].script_sig = script_sig.0;
        }
        Ok(tx)
    }

    // Broadcast is the node's job — build_and_sign returns the tx.
}

/// Dust limit (sats) — matches mempool policy default.
const DUST_LIMIT: u64 = 546;

/// Rough tx size estimate: base + per-input + per-output.
fn estimate_tx_size(n_inputs: usize, has_change: bool) -> usize {
    // version(4) + locktime(4) + counts(~2) + inputs(~107 each for
    // P2PKH spend) + outputs(~34 each).
    10 + n_inputs * 107 + (1 + usize::from(has_change)) * 34
}

/// fee_rate (sats/kvB) × size → sats, rounded up.
fn fee_rate_to_fee(fee_rate: u64, size_bytes: usize) -> Sats {
    let sats = (fee_rate.saturating_mul(size_bytes as u64)).div_ceil(1000);
    Sats(sats.max(1))
}

fn estimate_fee(fee_rate: u64, n_inputs: usize, n_outputs: usize) -> u64 {
    fee_rate_to_fee(fee_rate, estimate_tx_size(n_inputs, n_outputs > 1)).sats()
}

/// A UTXO view that also yields all entries — implemented by chainstate's
/// UtxoSet and by storage scans.
pub trait IterableUtxos {
    /// Iterate (outpoint, entry) pairs.
    fn utxo_iter(
        &self,
    ) -> Box<dyn Iterator<Item = (&OutPoint, &minibtc_chainstate::UtxoEntry)> + '_>;
}

impl IterableUtxos for minibtc_chainstate::UtxoSet {
    fn utxo_iter(
        &self,
    ) -> Box<dyn Iterator<Item = (&OutPoint, &minibtc_chainstate::UtxoEntry)> + '_> {
        Box::new(self.iter())
    }
}

// Re-export for callers.
pub use minibtc_chainstate::UtxoEntry;
