//! MiniBTC script: a deliberately small, bounded Bitcoin-Script subset.
//!
//! What we implement (and only this):
//!
//! - **Push ops**: direct pushes `0x01..=0x4b`, `OP_PUSHDATA1/2/4`,
//!   `OP_0`, `OP_1NEGATE`→unsupported, `OP_1..=OP_16`.
//! - **P2PKH**: `OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG`.
//! - **`OP_EQUAL`**, **`OP_RETURN`** (provably unspendable output marker).
//!
//! Everything else — arithmetic, flow control, `OP_CHECKMULTISIG`, `OP_IF`,
//! disabled/undefined opcodes — is a hard script error. A smaller opcode
//! surface is a security feature: there is no Turing-complete interpreter
//! to fuzz into consensus splits. If a future phase adds opcodes, each one
//! lands with its own limits and vectors.
//!
//! Limits mirror Bitcoin's standardness/consensus bounds:
//! [`MAX_SCRIPT_SIZE`] bytes per script, [`MAX_OPS_PER_SCRIPT`] non-push
//! opcodes, [`MAX_STACK_SIZE`] stack elements, [`MAX_PUSH_SIZE`] per push.

use minibtc_crypto::{double_sha256, hash160, Hash256, KeyError, PublicKey, Signature};
use minibtc_primitives::Transaction;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Max serialized bytes per script (consensus bound).
pub const MAX_SCRIPT_SIZE: usize = 10_000;
/// Max non-push opcodes executed per script (counted per input's combined
/// scriptSig+scriptPubKey execution).
pub const MAX_OPS_PER_SCRIPT: usize = 201;
/// Max stack elements.
pub const MAX_STACK_SIZE: usize = 1_000;
/// Max bytes in a single push ("520-byte rule").
pub const MAX_PUSH_SIZE: usize = 520;
/// Sighash type: all outputs + all inputs committed (the only mode we sign).
pub const SIGHASH_ALL: u8 = 0x01;

// --- Opcodes we implement -------------------------------------------------
pub const OP_0: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE: u8 = 0x4f;
pub const OP_RESERVED: u8 = 0x50;
pub const OP_1: u8 = 0x51;
pub const OP_TRUE: u8 = OP_1;
pub const OP_16: u8 = 0x60;
pub const OP_NOP: u8 = 0x61;
pub const OP_RETURN: u8 = 0x6a;
pub const OP_DUP: u8 = 0x76;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_CHECKSIG: u8 = 0xac;

/// A locking/unlocking script — raw bytes in Bitcoin's format.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Script(pub Vec<u8>);

impl Script {
    /// Empty script.
    pub fn new() -> Self {
        Self(Vec::new())
    }
    /// From raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Push `data` onto the script (canonical push encoding).
    pub fn push(data: &[u8]) -> Self {
        let mut out = Vec::with_capacity(data.len() + 5);
        if data.is_empty() {
            out.push(OP_0);
        } else if data.len() <= 0x4b {
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        } else if data.len() <= 0xff {
            out.push(OP_PUSHDATA1);
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        } else if data.len() <= 0xffff {
            out.push(OP_PUSHDATA2);
            out.extend_from_slice(&(data.len() as u16).to_le_bytes());
            out.extend_from_slice(data);
        } else {
            out.push(OP_PUSHDATA4);
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(data);
        }
        Self(out)
    }

    /// The standard P2PKH locking script for a 20-byte key hash:
    /// `OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG`.
    pub fn p2pkh(hash160: &minibtc_crypto::Hash160) -> Self {
        let mut out = vec![OP_DUP, OP_HASH160, 20];
        out.extend_from_slice(&hash160.0);
        out.push(OP_EQUALVERIFY);
        out.push(OP_CHECKSIG);
        Self(out)
    }

    /// The standard P2PKH unlocking script: `<sig+hashtype> <pubkey>`.
    pub fn p2pkh_spend(sig_der_with_type: &[u8], pubkey: &PublicKey) -> Self {
        let mut out = Script::push(sig_der_with_type).0;
        out.extend_from_slice(&Script::push(&pubkey.to_sec1_bytes()).0);
        Self(out)
    }
}

impl Default for Script {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Script({} bytes)", self.0.len())
    }
}

/// Why script execution failed. Every variant is a consensus-visible
/// rejection — there is no "warning" outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScriptError {
    /// Script bytes ended mid-instruction or push.
    #[error("malformed script: {0}")]
    Malformed(&'static str),
    /// An opcode outside the implemented subset appeared.
    #[error("unsupported opcode 0x{0:02x}")]
    UnsupportedOpcode(u8),
    /// A push exceeded [`MAX_PUSH_SIZE`].
    #[error("push exceeds {MAX_PUSH_SIZE} bytes")]
    PushTooLarge,
    /// Stack exceeded [`MAX_STACK_SIZE`].
    #[error("stack limit exceeded")]
    StackLimit,
    /// Opcode budget exceeded.
    #[error("opcode limit exceeded")]
    OpLimit,
    /// A required stack item was missing.
    #[error("stack underflow")]
    Underflow,
    /// Top stack element was not the expected truth value.
    #[error("script evaluated false")]
    False,
    /// `OP_RETURN` executed — provable failure by design.
    #[error("OP_RETURN executed")]
    OpReturn,
    /// A signature/pubkey failed to parse or verify.
    #[error("signature check failed: {0}")]
    SigCheck(String),
    /// Script exceeded [`MAX_SCRIPT_SIZE`].
    #[error("script exceeds size limit")]
    ScriptTooLarge,
}

/// The execution result context a sighash needs.
#[derive(Debug)]
pub struct ExecContext<'a> {
    /// The full transaction being validated.
    pub tx: &'a Transaction,
    /// Index of the input whose scripts are running.
    pub input_index: usize,
    /// The scriptCode for sighash: the *prevout's* scriptPubKey bytes.
    pub script_code: &'a [u8],
}

/// Execute `script_sig` then `script_pubkey` as one stack machine — exactly
/// Bitcoin's model. `ctx` supplies what `OP_CHECKSIG` needs for sighash.
pub fn execute(
    script_sig: &[u8],
    script_pubkey: &[u8],
    ctx: &ExecContext<'_>,
) -> Result<(), ScriptError> {
    if script_sig.len().saturating_add(script_pubkey.len()) > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptTooLarge);
    }
    let mut vm = Vm::new(ctx);
    vm.run(script_sig)?;
    vm.run(script_pubkey)?;
    vm.finish()
}

struct Vm<'a> {
    stack: Vec<Vec<u8>>,
    ops: usize,
    ctx: &'a ExecContext<'a>,
}

impl<'a> Vm<'a> {
    fn new(ctx: &'a ExecContext<'a>) -> Self {
        Self {
            stack: Vec::with_capacity(16),
            ops: 0,
            ctx,
        }
    }

    fn push(&mut self, item: Vec<u8>) -> Result<(), ScriptError> {
        if self.stack.len() >= MAX_STACK_SIZE {
            return Err(ScriptError::StackLimit);
        }
        self.stack.push(item);
        Ok(())
    }

    fn pop(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.stack.pop().ok_or(ScriptError::Underflow)
    }

    fn top(&self) -> Result<&[u8], ScriptError> {
        self.stack.last().map(Vec::as_slice).ok_or(ScriptError::Underflow)
    }

    fn cast_bool(b: &[u8]) -> bool {
        // Bitcoin truth rule: false iff all bytes are zero.
        b.iter().any(|&x| x != 0)
    }

    fn run(&mut self, script: &[u8]) -> Result<(), ScriptError> {
        let mut pc = 0usize;
        while pc < script.len() {
            let op = script[pc];
            pc = pc.saturating_add(1);
            // Push opcodes do not count against the op budget (Bitcoin rule:
            // only non-push operations count toward the 201 limit).
            match op {
                OP_0 => self.push(Vec::new())?,
                OP_PUSHDATA1 | OP_PUSHDATA2 | OP_PUSHDATA4 => {
                    let (len, hdr) = read_push_len(script, pc, op)?;
                    pc = pc.saturating_add(hdr);
                    if len > MAX_PUSH_SIZE {
                        return Err(ScriptError::PushTooLarge);
                    }
                    if pc.saturating_add(len) > script.len() {
                        return Err(ScriptError::Malformed("pushdata truncated"));
                    }
                    let data = script[pc..pc + len].to_vec();
                    pc = pc.saturating_add(len);
                    self.push(data)?;
                }
                0x01..=0x4b => {
                    let len = usize::from(op);
                    if pc.saturating_add(len) > script.len() {
                        return Err(ScriptError::Malformed("direct push truncated"));
                    }
                    let data = script[pc..pc + len].to_vec();
                    pc = pc.saturating_add(len);
                    self.push(data)?;
                }
                OP_1..=OP_16 => {
                    self.count_op()?;
                    self.push(vec![op - OP_1 + 1])?;
                }
                OP_DUP => {
                    self.count_op()?;
                    let top = self.top()?.to_vec();
                    self.push(top)?;
                }
                OP_HASH160 => {
                    self.count_op()?;
                    let item = self.pop()?;
                    self.push(hash160(&item).0.to_vec())?;
                }
                OP_EQUAL => {
                    self.count_op()?;
                    let a = self.pop()?;
                    let b = self.pop()?;
                    self.push(if a == b { vec![1] } else { Vec::new() })?;
                }
                OP_EQUALVERIFY => {
                    self.count_op()?;
                    let a = self.pop()?;
                    let b = self.pop()?;
                    if a != b {
                        return Err(ScriptError::False);
                    }
                }
                OP_CHECKSIG => {
                    self.count_op()?;
                    self.do_checksig()?;
                }
                OP_RETURN => {
                    self.count_op()?;
                    return Err(ScriptError::OpReturn);
                }
                OP_NOP => {
                    self.count_op()?;
                }
                OP_1NEGATE | OP_RESERVED => {
                    return Err(ScriptError::UnsupportedOpcode(op));
                }
                _ => return Err(ScriptError::UnsupportedOpcode(op)),
            }
        }
        Ok(())
    }

    fn count_op(&mut self) -> Result<(), ScriptError> {
        self.ops = self.ops.saturating_add(1);
        if self.ops > MAX_OPS_PER_SCRIPT {
            return Err(ScriptError::OpLimit);
        }
        Ok(())
    }

    fn do_checksig(&mut self) -> Result<(), ScriptError> {
        // Stack (top→bottom): pubkey, sig — pubkey pushed last by scriptSig.
        let pubkey_bytes = self.pop()?;
        let sig_item = self.pop()?;
        if sig_item.is_empty() {
            // Empty signature = verify false (Bitcoin behavior for CHECKSIG
            // with an empty sig item — used by some spending templates).
            self.push(Vec::new())?;
            return Ok(());
        }
        // sig_item = DER sig + 1-byte hashtype.
        if sig_item.len() < 2 {
            self.push(Vec::new())?;
            return Ok(());
        }
        let hashtype = sig_item[sig_item.len() - 1];
        let der = &sig_item[..sig_item.len() - 1];
        let pubkey = PublicKey::from_sec1_bytes(&pubkey_bytes)
            .map_err(|e| ScriptError::SigCheck(format!("pubkey: {e}")))?;
        let sig = Signature::from_der(der)
            .map_err(|e| ScriptError::SigCheck(format!("sig: {e}")))?;
        if hashtype != SIGHASH_ALL {
            self.push(Vec::new())?;
            return Ok(());
        }
        let digest = sighash::signature_hash(self.ctx.tx, self.ctx.input_index, self.ctx.script_code);
        let ok = pubkey.verify_digest(&digest, &sig);
        self.push(if ok { vec![1] } else { Vec::new() })?;
        Ok(())
    }

    fn finish(mut self) -> Result<(), ScriptError> {
        // Cleanstack: exactly one element, and it must be true.
        if self.stack.len() != 1 {
            return Err(ScriptError::False);
        }
        let top = self.stack.pop().unwrap_or_default();
        if Self::cast_bool(&top) {
            Ok(())
        } else {
            Err(ScriptError::False)
        }
    }
}

/// Decode a PUSHDATA length at `pc`; returns (length, header_bytes).
fn read_push_len(script: &[u8], pc: usize, op: u8) -> Result<(usize, usize), ScriptError> {
    match op {
        OP_PUSHDATA1 => {
            if pc >= script.len() {
                return Err(ScriptError::Malformed("pushdata1 missing length"));
            }
            Ok((usize::from(script[pc]), 1))
        }
        OP_PUSHDATA2 => {
            if pc.saturating_add(2) > script.len() {
                return Err(ScriptError::Malformed("pushdata2 truncated"));
            }
            let n = u16::from_le_bytes([script[pc], script[pc + 1]]);
            Ok((usize::from(n), 2))
        }
        OP_PUSHDATA4 => {
            if pc.saturating_add(4) > script.len() {
                return Err(ScriptError::Malformed("pushdata4 truncated"));
            }
            let n = u32::from_le_bytes([script[pc], script[pc + 1], script[pc + 2], script[pc + 3]]);
            // A u32 can exceed usize on 16-bit targets; on 64-bit it's fine,
            // and MAX_PUSH_SIZE rejects anything huge right after anyway.
            Ok((n as usize, 4))
        }
        _ => Err(ScriptError::Malformed("not a pushdata op")),
    }
}

/// Re-exported so callers can name the digest type without importing crypto.
pub type Sighash = Hash256;

/// SIGHASH_ALL: commit to every input's outpoint+sequence and every output.
///
/// This is Bitcoin's legacy (pre-segwun) algorithm, simplified because we
/// have no `OP_CODESEPARATOR` and no witness: serialize the tx with input
/// `i`'s scriptSig replaced by `script_code` (the prevout's scriptPubKey),
/// all other inputs' scriptSigs emptied, then append the 4-byte hashtype
/// and double-SHA-256.
pub mod sighash {
    use super::*;
    use minibtc_primitives::{Transaction, Writer};

    /// Compute the sighash for `input_index` of `tx`.
    pub fn signature_hash(tx: &Transaction, input_index: usize, script_code: &[u8]) -> Hash256 {
        // Serialize manually: version, inputs (scriptCode for `i`, empty
        // elsewhere), outputs, locktime, hashtype.
        let mut w = Writer::with_capacity(tx.encode().len() + 4);
        w.i32(tx.version);
        w.count_prefix(tx.inputs.len());
        for (i, inp) in tx.inputs.iter().enumerate() {
            w.hash256(&inp.prev.txid);
            w.u32(inp.prev.vout);
            if i == input_index {
                w.prefixed_bytes(script_code);
            } else {
                w.prefixed_bytes(&[]);
            }
            w.u32(inp.sequence);
        }
        w.count_prefix(tx.outputs.len());
        for out in &tx.outputs {
            w.u64(out.value.sats());
            w.prefixed_bytes(&out.script_pubkey);
        }
        w.u32(tx.locktime);
        w.u32(u32::from(SIGHASH_ALL));
        double_sha256(w.as_slice())
    }

    /// Build the `scriptSig` push for a signature: DER bytes + hashtype.
    pub fn sig_with_hashtype(sig: &Signature) -> Vec<u8> {
        let mut v = sig.to_der();
        v.push(SIGHASH_ALL);
        v
    }

    /// Errors surfaced to wallet callers.
    #[derive(Debug, thiserror::Error)]
    pub enum SignError {
        /// The crypto layer rejected the signature.
        #[error("signature failed: {0}")]
        Crypto(#[from] KeyError),
        /// Input index out of range.
        #[error("input index {0} out of range")]
        BadIndex(usize),
    }

    /// Sign input `input_index` of `tx` — caller must already know which
    /// key signs (the wallet resolves prevout → key). `script_code` is the
    /// prevout's scriptPubKey bytes.
    pub fn sign_input(
        tx: &Transaction,
        input_index: usize,
        script_code: &[u8],
        keypair: &minibtc_crypto::Keypair,
    ) -> Result<Vec<u8>, SignError> {
        if input_index >= tx.inputs.len() {
            return Err(SignError::BadIndex(input_index));
        }
        let digest = signature_hash(tx, input_index, script_code);
        let sig = keypair.sign_digest(&digest)?;
        Ok(sig_with_hashtype(&sig))
    }

    /// Produce a complete signed P2PKH scriptSig for `input_index`, given
    /// the keypair whose hash160 the prevout commits to.
    pub fn p2pkh_script_sig(
        tx: &Transaction,
        input_index: usize,
        prev_script_pubkey: &Script,
        keypair: &minibtc_crypto::Keypair,
    ) -> Result<Script, SignError> {
        let sig_item = sign_input(tx, input_index, prev_script_pubkey.as_bytes(), keypair)?;
        Ok(Script::p2pkh_spend(&sig_item, &keypair.public_key()))
    }

    /// Verify a fully-built input: run scriptSig+scriptPubKey.
    /// Convenience wrapper returning bool for callers that pre-validated.
    pub fn verify_input_scripts(
        tx: &Transaction,
        input_index: usize,
        script_sig: &[u8],
        prev_script_pubkey: &[u8],
    ) -> bool {
        let ctx = ExecContext {
            tx,
            input_index,
            script_code: prev_script_pubkey,
        };
        execute(script_sig, prev_script_pubkey, &ctx).is_ok()
    }
}
