#![no_main]

use libfuzzer_sys::fuzz_target;
use minibtc_primitives::{OutPoint, Transaction, TxInput, TxOutput, Sats};
use minibtc_script::{execute, ExecContext};
use minibtc_crypto::Hash256;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let split = (data[0] as usize) % (data.len() - 1) + 1;
    let (sig, spk) = (&data[..split], &data[split..]);
    // Bounded scripts only — the engine enforces its own limits anyway.
    if sig.len() > 10_000 || spk.len() > 10_000 {
        return;
    }
    let tx = Transaction {
        version: 1,
        inputs: vec![TxInput {
            prev: OutPoint { txid: Hash256::ZERO, vout: 0 },
            script_sig: vec![],
            sequence: 0xffff_ffff,
        }],
        outputs: vec![TxOutput {
            value: Sats(1),
            script_pubkey: vec![],
        }],
        locktime: 0,
    };
    let ctx = ExecContext {
        tx: &tx,
        input_index: 0,
        script_code: spk,
    };
    let _ = execute(sig, spk, &ctx); // Ok or Err — must not panic
});
