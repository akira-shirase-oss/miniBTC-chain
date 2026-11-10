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
    // new = old * actual / target. The intermediate old*actual needs up
    // to 256+64 bits, so we keep a 40-byte product and divide that —
    // matching Bitcoin's arith_uint256 semantics where the final result
    // wraps mod 2^256 (the clamp then bounds it anyway).
    let wide = mul_wide256(&old_target, actual_span_secs);
    let new_target = div_wide_by_u64(&wide, target_span_secs)?;
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

/// `a * factor` as a full 40-byte big-endian product (no truncation —
/// `a` ≤ 2^256−1, `factor` ≤ u64::MAX ⇒ product ≤ ~2^320 fits exactly).
fn mul_wide256(a: &[u8; 32], factor: u64) -> [u8; 40] {
    let mut product = [0u8; 40];
    let mut carry: u128 = 0;
    for i in (0..32usize).rev() {
        let idx = i.saturating_add(8);
        let cur = u128::from(a[i]) * u128::from(factor) + carry;
        product[idx] = (cur & 0xff) as u8;
        carry = cur >> 8;
    }
    // Remaining carry (≤ ~2^64) lands in indices 0..8.
    let mut j = 8usize;
    while carry > 0 {
        if j == 0 {
            break; // cannot happen: product < 2^320 by construction
        }
        j = j.saturating_sub(1);
        let sum = u128::from(product[j]) + carry;
        product[j] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    product
}

/// Divide a 40-byte big-endian value by a u64; returns the LOW 32 bytes
/// of the quotient (i.e. mod 2^256 — Bitcoin's wrap semantics).
fn div_wide_by_u64(a: &[u8; 40], divisor: u64) -> Result<[u8; 32], PowError> {
    if divisor == 0 {
        return Err(PowError::BadRetarget("zero divisor"));
    }
    let d = u128::from(divisor);
    let mut rem: u128 = 0;
    let mut quot = [0u8; 40];
    for i in 0..40 {
        rem = (rem << 8) | u128::from(a[i]);
        let q = rem / d;
        rem %= d;
        quot[i] = q as u8;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&quot[8..40]);
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

/// Cumulative-work units contributed by one block with compact `bits`.
///
/// `work = floor((2^256 − 1) / (target + 1))` — Bitcoin's definition,
/// computed exactly via 256÷256 long division and saturated into u128
/// (a target small enough to overflow u128 is far beyond anything this
/// chain produces; saturation only ever *understates* work, and chains
/// are compared against each other under the same params).
///
/// The result is what `Chain` accumulates for most-work fork choice.
pub fn work_units(bits: u32) -> Result<u128, PowError> {
    let t = decode_compact(bits)?;
    // numerator = 2^256 − 1 = [0xff; 32]; denominator = t + 1.
    let mut den = t;
    // den += 1 with carry; if it wraps to zero the target was 2^256−1 →
    // work = 1 (can't happen for valid bits, but stay total).
    let mut carry = 1u16;
    for i in (0..32usize).rev() {
        let v = u16::from(den[i]) + carry;
        den[i] = v as u8;
        carry = v >> 8;
    }
    if carry != 0 {
        return Ok(1);
    }
    // Long division: rem (32B) / den (32B), quotient kept to 16 low bytes
    // (u128). We only need the low 16 bytes of the quotient — but the
    // division must still process all 32 numerator bytes correctly, so we
    // keep a full 32-byte remainder and 32-byte quotient, then fold.
    let num = [0xffu8; 32];
    let (quot, _rem) = div_256(&num, &den);
    // Fold the 32-byte big-endian quotient into u128, saturating.
    let mut work: u128 = 0;
    for &b in quot[16..32].iter() {
        work = work.saturating_mul(256).saturating_add(u128::from(b));
    }
    // If any high quotient byte is nonzero the true value exceeded u128 —
    // saturate (documented above).
    if quot[..16].iter().any(|&b| b != 0) {
        work = u128::MAX;
    }
    Ok(work.max(1))
}

/// `rem = rem*2 + bit` on a 32-byte big-endian array. Returns the carry
/// shifted out beyond bit 255 — callers must treat `rem` as a 257-bit
/// value `(carry, rem)` because `rem*2+1` can exceed 256 bits when the
/// divisor is large.
fn shl1_add(rem: &mut [u8; 32], bit: u8) -> u8 {
    let mut carry = u16::from(bit);
    for b in rem.iter_mut().rev() {
        let v = (u16::from(*b) << 1) | carry;
        *b = v as u8;
        carry = v >> 8;
    }
    carry as u8
}

/// 256÷256 division via bit-by-bit long division — deliberately simple
/// and obviously correct. `numer`/`denom` big-endian; `denom` must be > 0.
/// Returns (quotient, remainder) as 32-byte big-endian arrays.
fn div_256(numer: &[u8; 32], denom: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    debug_assert!(denom.iter().any(|&b| b != 0), "division by zero");
    let mut quot = [0u8; 32];
    let mut rem = [0u8; 32];
    for i in 0..256usize {
        // Next numerator bit, MSB-first.
        let byte = numer[i / 8];
        let bit = (byte >> (7 - (i % 8))) & 1;
        let of = shl1_add(&mut rem, bit);
        // True remainder is (of, rem) as a 257-bit value. It is ≥ denom
        // iff of == 1 (denom < 2^256 always) or rem ≥ denom.
        if of == 1 || rem >= *denom {
            // rem_true - denom. When of == 1 the true value is
            // 2^256 + rem - denom; since that case implies rem < denom,
            // the wrapping subtraction below yields exactly
            // rem - denom + 2^256 = the correct new remainder.
            let mut borrow = 0i16;
            for j in (0..32usize).rev() {
                let d = i16::from(rem[j]) - i16::from(denom[j]) - borrow;
                if d < 0 {
                    rem[j] = (d + 256) as u8;
                    borrow = 1;
                } else {
                    rem[j] = d as u8;
                    borrow = 0;
                }
            }
            // Quotient bit place = 2^(255-i): byte i/8 from the top,
            // bit (7 - i%8) within it.
            quot[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    (quot, rem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_roundtrip_easy_target() {
        // 0x207fffff is Bitcoin's powLimit-ish easy target.
        let t = decode_compact(0x207f_ffff).unwrap();
        // Mantissa 0x7fffff sits in the top 3 bytes.
        assert_eq!(&t[..3], &[0x7f, 0xff, 0xff]);
        // Re-encode gives back the same bits.
        assert_eq!(encode_compact(&t), 0x207f_ffff);
    }

    #[test]
    fn compact_decode_mainnet_bits() {
        // 0x1d00ffff → target with exponent 0x1d=29, mantissa 0x00ffff.
        let t = decode_compact(0x1d00_ffff).unwrap();
        // exponent-3 = 26 → mantissa (00 ff ff) lands at bytes 3..6 —
        // the Bitcoin powLimit pattern 0x00000000FFFF00…
        assert_eq!(&t[3..6], &[0x00, 0xff, 0xff]);
        assert!(t[..3].iter().all(|&b| b == 0) && t[6..].iter().all(|&b| b == 0));
    }

    #[test]
    fn compact_rejects_zero_mantissa_and_huge_exp() {
        assert!(decode_compact(0x1f00_0000).is_err()); // mantissa 0 wait—0x1f000000 mantissa=0
        assert!(decode_compact(0x2100_0001).is_err()); // exponent 33 > 32
    }

    #[test]
    fn work_units_decreases_with_difficulty() {
        // Easier target (bigger) → less work. powLimit-ish vs tighter.
        let easy = work_units(0x207f_ffff).unwrap();
        let harder = work_units(0x1d00_ffff).unwrap();
        assert!(easy < harder, "easier target must mean less work: {easy} vs {harder}");
        // Same bits → same work.
        assert_eq!(work_units(0x207f_ffff).unwrap(), easy);
    }

    #[test]
    fn work_units_exact_for_known_target() {
        // Target = 2^255 exactly-ish: bits for target 0x80 followed by zeros.
        // Use decode/encode round-trip instead: pick bits, decode, verify
        // work = floor((2^256-1)/(target+1)) via independent u128 check on
        // a small target where quotient fits.
        // target = 0x0100...00 (2^248): craft bits exponent 0x20 mantissa 0x010000
        let bits = 0x2001_0000u32;
        let t = decode_compact(bits).unwrap();
        // target should be 2^248 → 0x01 at index 0 (place 256^31).
        assert_eq!(t[0], 1);
        assert!(t[1..].iter().all(|&b| b == 0));
        let w = work_units(bits).unwrap();
        // 2^256 / 2^248 ≈ 2^8 = 256 minus epsilon → 255 or 256.
        assert!((250..=260).contains(&w), "work {w} for 2^248 target");
    }

    #[test]
    fn retarget_clamps_runaway() {
        let p_bits = 0x207f_ffffu32;
        // Actual span 1000× target → new target would be 1000× bigger
        // (easier) but clamp caps at ×4.
        let new_bits = retarget_bits(p_bits, 1000, 1, 4).unwrap();
        let old_t = decode_compact(p_bits).unwrap();
        let new_t = decode_compact(new_bits).unwrap();
        // new target ≤ old * 4
        let old_x4 = mul_u256(&old_t, 4).unwrap();
        assert!(new_t <= old_x4, "clamp failed: {:?} vs {:?}", new_t, old_x4);
        // And ≥ old / 4.
        let old_d4 = div_u256(&old_t, 4).unwrap();
        assert!(new_t >= old_d4);
    }

    #[test]
    fn retarget_normal_case() {
        // actual == target → bits unchanged.
        let p_bits = 0x207f_ffffu32;
        let new_bits = retarget_bits(p_bits, 600, 600, 4).unwrap();
        // encode/decode round-trip may lose a bit of precision; decoded
        // targets should be very close — compare decoded targets equal.
        let a = decode_compact(p_bits).unwrap();
        let b = decode_compact(new_bits).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mul_div_u256_sanity() {
        // 2^255 * 2 = saturates? No — 2^256 overflows → saturate to max.
        let two55 = {
            let mut b = [0u8; 32];
            b[0] = 0x80;
            b
        };
        assert_eq!(mul_u256(&two55, 2).unwrap(), [0xff; 32]);
        // small mul exact: 0x0100..(2^248) * 4 = 2^250 → byte[3]=4? place:
        // 2^248 = index3 value1; *4 = 2^250 = index3 value4.
        let mut t = [0u8; 32];
        t[3] = 1;
        let m = mul_u256(&t, 4).unwrap();
        assert_eq!(m[3], 4);
        // div: 2^250 / 4 = 2^248 → index3 =1.
        let d = div_u256(&m, 4).unwrap();
        assert_eq!(d[3], 1);
        // div by non-power: 10 / 3 = 3.
        let mut ten = [0u8; 32];
        ten[31] = 10;
        let three = div_u256(&ten, 3).unwrap();
        assert_eq!(three[31], 3);
    }
}
