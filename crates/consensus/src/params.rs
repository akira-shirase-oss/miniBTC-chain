//! Chain parameters — every consensus knob in one struct, parsed from a
//! JSON document so devnet can tune PoW/subsidy/maturity without
//! recompiling. Two presets ship: `mainnet`-like defaults and a `devnet`
//! preset with trivial difficulty for tests.
//!
//! This crate is pure: it parses and validates text it is handed. Reading
//! the file is the binary's job (see `minibtc-node --params`), so consensus
//! never touches the filesystem.

use minibtc_primitives::Sats;
use serde::{Deserialize, Serialize};

/// Errors parsing or validating parameters.
#[derive(Debug, thiserror::Error)]
pub enum ParamsError {
    /// The document was not valid JSON for this schema.
    #[error("invalid params JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A parameter value is self-inconsistent (e.g. interval = 0).
    #[error("invalid params: {0}")]
    Invalid(&'static str),
}

/// Everything consensus needs to know about *this* chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainParams {
    /// Human name (`"minibtc-devnet"` etc.) — appears in `getblockchaininfo`.
    pub name: String,
    /// Whether this is the dev/regtest-style preset (affects RPC defaults,
    /// never consensus math).
    #[serde(default)]
    pub devnet: bool,

    // --- Proof of work -------------------------------------------------
    /// Compact bits for the *minimum* allowed difficulty (genesis + clamp).
    /// `0x207fffff` ≈ target ~2^255 — trivial for devnet.
    pub pow_limit_bits: u32,
    /// Target block spacing in seconds (drives retarget math).
    pub pow_target_spacing: u32,
    /// Retarget every this many blocks.
    pub pow_target_timespan_blocks: u32,
    /// Clamp: new target may not differ from old by more than this factor.
    /// Bitcoin uses 4 (×4 / ÷4); we keep the same clamp.
    pub pow_clamp_factor: u32,

    // --- Money ----------------------------------------------------------
    /// Coinbase subsidy at height 0, in sats.
    pub subsidy_start: u64,
    /// Subsidy halves every this many blocks (Bitcoin: 210,000).
    pub subsidy_halving_interval: u32,
    /// Hard cap on total money ever created — the UTXO sum may never exceed
    /// this. Checked-add arithmetic everywhere makes overflow impossible
    /// before this bound anyway; this is the *policy* ceiling.
    pub max_money: u64,

    // --- Rules ----------------------------------------------------------
    /// Coinbase outputs must be this many blocks deep before spendable.
    pub coinbase_maturity: u32,
    /// A block timestamp may exceed adjusted time by at most this many
    /// seconds ("not more than 2 hours in the future").
    pub max_future_time_secs: u32,
    /// Median-of-N window for past-time checks (Bitcoin: 11).
    pub median_time_span: usize,
    /// Maximum serialized block size in bytes.
    pub max_block_size: usize,
    /// Maximum transactions per block.
    pub max_block_txs: usize,
    /// Maximum sigops per block (our script subset: OP_CHECKSIG counts 1).
    pub max_block_sigops: usize,
    /// Maximum a single tx's inputs+outputs may declare (decode bound).
    pub max_tx_io: usize,

    // --- Network identity ----------------------------------------------
    /// P2PKH address version byte (Bitcoin mainnet 0x00, testnet 0x6f).
    pub address_version: u8,
    /// Magic bytes prefixing every P2P message — network identity on the
    /// wire. MiniBTC mainnet-style uses its own constant so we can never
    /// accidentally peer with Bitcoin.
    pub p2p_magic: [u8; 4],
    /// Default P2P listen port.
    pub p2p_port: u16,
    /// Default RPC port.
    pub rpc_port: u16,
    /// Grind the genesis header's nonce so genesis meets its own proof of
    /// work (cheap only at an easy pow limit). That is all it does: it does
    /// **not** turn off retargeting — the difficulty schedule is a
    /// consensus rule on every network (D-013). Formerly named
    /// `instant_difficulty`, which suggested otherwise; the old key is
    /// still accepted in params files.
    #[serde(default, alias = "instant_difficulty")]
    pub grind_genesis_nonce: bool,
}

impl ChainParams {
    /// The devnet preset: trivial PoW, fast retarget, small subsidy,
    /// 100-block maturity (matching Bitcoin's rule for learning value).
    pub fn devnet() -> Self {
        Self {
            name: "minibtc-devnet".to_string(),
            devnet: true,
            pow_limit_bits: 0x207f_ffff,
            pow_target_spacing: 30,
            pow_target_timespan_blocks: 20,
            pow_clamp_factor: 4,
            subsidy_start: 50 * 100_000_000, // 50 coins in sats
            subsidy_halving_interval: 150,
            max_money: 21_000_000 * 100_000_000,
            coinbase_maturity: 100,
            max_future_time_secs: 2 * 60 * 60,
            median_time_span: 11,
            max_block_size: 1_000_000,
            max_block_txs: 10_000,
            max_block_sigops: 80_000,
            max_tx_io: 100_000,
            address_version: 0x6f,
            p2p_magic: *b"MBTC",
            p2p_port: 18_445,
            rpc_port: 18_446,
            grind_genesis_nonce: true,
        }
    }

    /// A "mainnet-like" preset for documentation/fuzzing — still MiniBTC
    /// parameters, never Bitcoin's, but with production-shaped numbers.
    pub fn default_net() -> Self {
        Self {
            name: "minibtc".to_string(),
            devnet: false,
            pow_limit_bits: 0x1d00_ffff,
            pow_target_spacing: 600,
            pow_target_timespan_blocks: 2016,
            pow_clamp_factor: 4,
            subsidy_start: 50 * 100_000_000,
            subsidy_halving_interval: 210_000,
            max_money: 21_000_000 * 100_000_000,
            coinbase_maturity: 100,
            max_future_time_secs: 2 * 60 * 60,
            median_time_span: 11,
            max_block_size: 1_000_000,
            max_block_txs: 10_000,
            max_block_sigops: 80_000,
            max_tx_io: 100_000,
            address_version: 0x00,
            p2p_magic: *b"MBTC",
            p2p_port: 18_445,
            rpc_port: 18_446,
            grind_genesis_nonce: false,
        }
    }

    /// Parse params from a JSON document and validate them. Every field
    /// except the `#[serde(default)]` flags is required, so a config is
    /// explicit, not silently half-specified. The caller reads the file.
    pub fn from_json(text: &str) -> Result<Self, ParamsError> {
        let params: Self = serde_json::from_str(text)?;
        params.validate()?;
        Ok(params)
    }

    /// Sanity-check the parameter set — consensus math divides by some of
    /// these, so zero/overflow must be caught at load time, not mid-chain.
    pub fn validate(&self) -> Result<(), ParamsError> {
        if self.pow_target_timespan_blocks == 0
            || self.pow_target_spacing == 0
            || self.pow_clamp_factor == 0
            || self.subsidy_halving_interval == 0
            || self.median_time_span == 0
            || self.max_tx_io == 0
            || self.max_block_txs == 0
            || self.max_block_size == 0
        {
            return Err(ParamsError::Invalid("zero-valued interval/size parameter"));
        }
        if self.subsidy_start > self.max_money {
            return Err(ParamsError::Invalid("subsidy exceeds max_money"));
        }
        if self.coinbase_maturity == 0 {
            return Err(ParamsError::Invalid("coinbase_maturity must be ≥ 1"));
        }
        Ok(())
    }

    /// `Sats` view of the subsidy cap for checked arithmetic call sites.
    pub fn max_money_sats(&self) -> Sats {
        Sats(self.max_money)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_json_round_trips_a_preset() {
        let text = serde_json::to_string(&ChainParams::devnet()).unwrap();
        let parsed = ChainParams::from_json(&text).unwrap();
        assert_eq!(parsed.name, "minibtc-devnet");
        assert_eq!(parsed.pow_limit_bits, ChainParams::devnet().pow_limit_bits);
    }

    #[test]
    fn old_instant_difficulty_key_still_loads() {
        let text = serde_json::to_string(&ChainParams::devnet())
            .unwrap()
            .replace("grind_genesis_nonce", "instant_difficulty");
        assert!(text.contains("instant_difficulty"));
        let p = ChainParams::from_json(&text).unwrap();
        assert!(p.grind_genesis_nonce);
    }

    #[test]
    fn from_json_rejects_invalid_values_and_bad_json() {
        let mut p = ChainParams::devnet();
        p.pow_target_timespan_blocks = 0;
        let text = serde_json::to_string(&p).unwrap();
        assert!(matches!(
            ChainParams::from_json(&text),
            Err(ParamsError::Invalid(_))
        ));
        assert!(matches!(
            ChainParams::from_json("{\"name\": 1}"),
            Err(ParamsError::Json(_))
        ));
    }
}
