//! Chain parameters — every consensus knob in one struct, loadable from a
//! JSON config file so devnet can tune PoW/subsidy/maturity without
//! recompiling. Two presets ship: `mainnet`-like defaults and a `devnet`
//! preset with trivial difficulty for tests.

use minibtc_primitives::Sats;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Errors loading or validating parameters.
#[derive(Debug, thiserror::Error)]
pub enum ParamsError {
    /// The config file could not be read.
    #[error("cannot read params file {path}: {source}")]
    Io {
        /// File path attempted.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The config file was not valid JSON for this schema.
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
    /// Default regtest-style instant-difficulty flag consumed by the miner.
    #[serde(default)]
    pub instant_difficulty: bool,
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
            instant_difficulty: true,
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
            instant_difficulty: false,
        }
    }

    /// Load params from a JSON file; missing fields fall back to devnet
    /// defaults via `#[serde(default)]` on a wrapper — here we require the
    /// full struct so a config is explicit, not silently half-specified.
    pub fn load(path: &Path) -> Result<Self, ParamsError> {
        let text = std::fs::read_to_string(path).map_err(|e| ParamsError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let params: Self = serde_json::from_str(&text)?;
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
            return Err(ParamsError::Invalid(
                "zero-valued interval/size parameter",
            ));
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
