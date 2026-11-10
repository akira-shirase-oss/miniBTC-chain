#![no_main]

use libfuzzer_sys::fuzz_target;
use minibtc_primitives::Block;

fuzz_target!(|data: &[u8]| {
    // Bounded decode: tx_limit and size_limit cap resource use.
    if let Ok(block) = Block::decode(data, 10_000, 4 * 1024 * 1024) {
        let enc = block.encode();
        let _ = Block::decode(&enc, 10_000, 4 * 1024 * 1024);
    }
});
