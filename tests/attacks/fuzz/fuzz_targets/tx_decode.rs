#![no_main]

use libfuzzer_sys::fuzz_target;
use minibtc_primitives::Transaction;

fuzz_target!(|data: &[u8]| {
    // Must never panic; canonical re-encode must be stable.
    if let Ok(tx) = Transaction::decode(data) {
        let enc = tx.encode();
        if let Ok(tx2) = Transaction::decode(&enc) {
            assert_eq!(tx2.encode(), enc, "codec not a fixed point");
        }
    }
});
