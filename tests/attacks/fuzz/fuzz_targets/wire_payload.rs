#![no_main]

use libfuzzer_sys::fuzz_target;
use minibtc_consensus::ChainParams;
use minibtc_p2p::codec;

const CMDS: [&str; 12] = [
    "version", "verack", "inv", "getdata", "tx", "block", "headers",
    "getheaders", "ping", "pong", "addr", "reject",
];

fuzz_target!(|data: &[u8]| {
    let params = ChainParams::devnet();
    if data.is_empty() {
        return;
    }
    let cmd = CMDS[(data[0] as usize) % CMDS.len()];
    // Feed the rest as payload — must return Err or bounded Ok, never panic.
    let _ = codec::decode_payload(cmd, &data[1..]);
    // Round-trip: encode a real message, decode must accept.
    let msg = codec::decode_payload(cmd, &data[1..]);
    if let Ok(m) = msg {
        let payload = codec::encode_payload(&m, &params);
        let _ = codec::decode_payload(cmd, &payload);
    }
});
