//! Compact-difficulty (`nBits`) encode/decode and retarget math.
//!
//! Bitcoin's `nBits` packs a 256-bit target into 4 bytes:
//! `0xTTSSSSSS` — `TT` exponent (bytes), `SSSSSS` mantissa. The target is
//! compared against `double_sha256(header)` as a *little-endian* 256-bit
//! integer (hash bytes reversed) — matching `BlockHeader::check_pow`.
//!
//! All 256-bit arithmetic here is on big-endian byte arrays with explicit
//! carry propagation. Retarget uses Bitcoin's formula with the same ×4/÷4
//! clamp; overflow saturates rather than wraps — a saturated (harder)
//! target is the safe direction, an accidental wrap would make blocks
//! *easier* to produce.

use minibtc_crypto::Hash256;

/// Errors decoding compact bits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PowError {
    /// The compact encoding's exponent/mantissa is degenerate.
    #[error("invalid compact bits 0x{0:08x}")]
    BadBits(u32),
    /// Retarget inputs were degenerate.
    #[error("bad retarget input: {0}")]
    BadRetarget(&'static str),
}

/// Decode compact `bits` → 256-bit target as **big-endian** bytes (the
/// integer's canonical order).
pub fn decode_compact(bits: u32) -> Result<[u8; 32], PowError> {
    let exponent = (bits >> 24) as i64;
    let mantissa = bits & 0x007f_ffff;
    if mantissa == 0 {
        return Err(PowError::BadBits(bits));
    }
    let mut out = [0u8; 32];
    if exponent <= 3 {
        let shift = (3 - exponent) * 8;
        if shift >= 32 {
            return Ok(out); // target underflows to zero — invalid for PoW
        }
        #[allow(clippy::cast_possible_truncation, reason = "shift < 32 checked above; value fits u32")]
        let v = mantissa >> shift;
        out[28] = (v >> 24) as u8;
        out[29] = (v >> 16) as u8;
        out[30] = (v >> 8) as u8;
        out[31] = v as u8;
    } else {
        let shift_bytes = exponent - 3;
        if shift_bytes > 29 {
            return Err(PowError::BadBits(bits)); // target exceeds 256 bits
        }
        // mantissa is ≤ 0x7fffff → its 3 significant bytes, big-endian.
        let sig = [
            (mantissa >> 16) as u8,
            (mantissa >> 8) as u8,
            mantissa as u8,
        ];
        // Right-align the 3-byte mantissa, then shift left by shift_bytes.
        // Equivalent: place sig ending at index 31-shift_bytes.
        let end = 31usize.saturating_sub(shift_bytes as usize);
        for (k, &b) in sig.iter().enumerate() {
            // sig[0] is most significant → sits 2 places before `end`.
            let idx = end.saturating_sub(2usize.saturating_sub(k));
            if idx < 32 {
                out[idx] = b;
            }
        }
    }
    Ok(out)
}

/// Encode a 256-bit big-endian target back to compact bits (round-trip
/// helper — precision loss beyond 3 mantissa bytes is inherent to the
/// format, same as Bitcoin).
pub fn encode_compact(target: &[u8; 32]) -> u32 {
    let mut i = 0usize;
    while i < 32 && target[i] == 0 {
        i = i.saturating_add(1);
    }
    if i == 32 {
        return 0;
    }
    let exponent = (32 - i) as u32;
    let mut mantissa: u32 = 0;
    for j in 0..3 {
        let idx = i.saturating_add(j);
        let b = if idx < 32 { u32::from(target[idx]) } else { 0 };
        mantissa = (mantissa << 8) | b;
    }
    (exponent << 24) | mantissa
}

/// The PoW target for a block's `bits`, returned in the byte order
/// `BlockHeader::check_pow` compares against (reversed from big-endian).
pub fn target_for_bits(bits: u32) -> Result<Hash256, PowError> {
    let t = decode_compact(bits)?;
    let mut rev = [0u8; 32];
    for i in 0..32 {
        rev[i] = t[31 - i];
    }
    Ok(Hash256(rev))
}

/// Retarget compact bits for the next period.
///
/// `old_bits` — current difficulty. `actual_span_secs` — time the last
/// period actually took. `target_span_secs` — time a period should take
/// (`spacing × blocks_per_period`). Bitcoin's formula:
/// `new_target = old_target × actual / target`, clamped to ×`clamp_factor`.
pub fn retarget_bits(
    old_bits: u32,
    actual_span_secs: u64,
    target_span_secs: u64,
    clamp_factor: u32,
) -> Result<u32, PowError> {
    if actual_span_secs == 0 || target_span_secs == 0 {
        return Err(PowError::BadRetarget("zero timespan"));
    }
    let old_target = decode_compact(old_bits)?;
    // new = old * actual / target — mul first (may need >256 bits
    // transiently), divide, then clamp.
    let scaled = mul_u256(&old_target, actual_span_secs)?;
    let new_target = div_u256(&scaled, target_span_secs)?;
    let clamped = clamp_target(&new_target, &old_target, u64::from(clamp_factor.max(1)))?;
    Ok(encode_compact(&clamped))
}

/// `a * factor` where `a` is 32-byte big-endian and `factor` ≤ u64::MAX.
/// Saturates at 2^256−1 on overflow (safe direction: harder, never easier).
fn mul_u256(a: &[u8; 32], factor: u64) -> Result<[u8; 32], PowError> {
    // 40-byte product: a occupies low 32 bytes (indices 8..40).
    let mut product = [0u8; 40];
    let mut carry: u128 = 0;
    for i in (0..32usize).rev() {
        let idx = i.saturating_add(8);
        let cur = u128::from(a[i]) * u128::from(factor) + carry;
        product[idx] = (cur & 0xff) as u8;
        carry = cur >> 8;
    }
    // Remaining carry lands in indices 0..8.
    let mut j = 8usize;
    while carry > 0 {
        if j == 0 {
            return Ok([0xff; 32]); // saturated
        }
        j = j.saturating_sub(1);
        let sum = u128::from(product[j]) + carry;
        product[j] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    // Check the high 8 bytes for overflow beyond 256 bits.
    if product[..8].iter().any(|&b| b != 0) {
        return Ok([0xff; 32]);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&product[8..40]);
    Ok(out)
}

/// `a / divisor` where `a` is 32-byte big-endian, `divisor` ≤ u64::MAX.
/// Long division, one byte at a time; quotient digits stay < 256 because
/// the remainder invariant `rem < divisor` is maintained.
fn div_u256(a: &[u8; 32], divisor: u64) -> Result<[u8; 32], PowError> {
    if divisor == 0 {
        return Err(PowError::BadRetarget("zero divisor"));
    }
    let d = u128::from(divisor);
    let mut rem: u128 = 0;
    let mut out = [0u8; 32];
    for i in 0..32 {
        rem = (rem << 8) | u128::from(a[i]);
        let q = rem / d;
        rem %= d;
        out[i] = q as u8; // q < 256 by the rem < d invariant
    }
    Ok(out)
}

/// Clamp `new` into `[old / factor, old * factor]` (saturating bounds).
fn clamp_target(new: &[u8; 32], old: &[u8; 32], factor: u64) -> Result<[u8; 32], PowError> {
    let upper = mul_u256(old, factor)?;
    let lower = div_u256(old, factor.max(1))?;
    if new > &upper {
        return Ok(upper);
    }
    if new < &lower {
        return Ok(lower);
    }
    Ok(*new)
}
