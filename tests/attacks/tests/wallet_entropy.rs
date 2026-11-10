//! Wallet-side attack scenarios — beyond the blueprint's consensus §8
//! list, covering real-world key-generation failures.
//!
//! Scenario W1 (Coldcard-class, disclosed Nov 2025): a 2021 build-config
//! mistake selected a weak software RNG on older devices, cutting
//! effective seed entropy to ~40 bits. TRM Labs counts ~1,816 BTC stolen
//! from 5,200+ addresses. The defense is architectural — entropy must
//! come from the OS CSPRNG — plus honest tests that catch grossly
//! broken generators. (Public dispute at the time: whether an AI model
//! or earlier human review found it first is irrelevant to the fix.)

use minibtc_wallet::bip39::{generate_mnemonic, mnemonic_from_entropy, mnemonic_from_phrase};
use std::collections::{HashMap, HashSet};

/// A deterministic PRNG for the *test only* — models "draws with
/// replacement" from a small entropy pool, which is what a weak RNG
/// actually does (its outputs live in a tiny space).
struct WeakRng(u64);
impl WeakRng {
    fn next_u32(&mut self) -> u32 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32
    }
}

/// Simulate a weak entropy source: draw a 32-bit pool index, hash it
/// into the 128-bit BIP39 entropy field. The mnemonic *encodes* 128
/// bits but only 32 bits are unpredictable — the exact Coldcard
/// failure shape (weak source, wide encoding, silent entropy deficit).
/// 32 bits is used so the birthday collision fits in a unit test;
/// Coldcard's ~40 bits scales the required draws to ~2^20.
fn weak_entropy_mnemonic(pool_index: u32) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(pool_index.to_le_bytes());
    let d = h.finalize();
    mnemonic_from_entropy(&d[..16])
        .unwrap_or_else(|_| panic!("entropy encode failed"))
        .phrase()
}

/// W1a — seeds from a low-entropy source collide at the birthday
/// bound. With 32 effective bits, ~2^16 draws make a collision
/// near-certain; 200k fixed inputs make this deterministic.
#[test]
fn attack_weak_entropy_seeds_collide_at_birthday_bound() {
    let n = 200_000u32;
    let mut rng = WeakRng(0x9E37_79B9_7F4A_7C15);
    let mut first_seen: HashMap<String, u32> = HashMap::with_capacity(n as usize);
    let mut collisions = 0u32;
    let mut first_pair: Option<(u32, u32)> = None;
    for i in 0..n {
        let phrase = weak_entropy_mnemonic(rng.next_u32());
        match first_seen.entry(phrase) {
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(i);
            }
            std::collections::hash_map::Entry::Occupied(o) => {
                collisions += 1;
                if first_pair.is_none() {
                    first_pair = Some((*o.get(), i));
                }
            }
        }
    }
    let (a, b) =
        first_pair.unwrap_or_else(|| panic!("no collision in {n} draws from 32-bit entropy"));
    assert!(collisions > 0);
    eprintln!(
        "weak-entropy proof: {collisions} duplicate phrases in {n} draws; \
         first collision between draws {a} and {b} — an attacker enumerates \
         the whole 2^32 pool instead of facing 2^128"
    );
}

/// W1b — positive control: our `generate_mnemonic()` must show a
/// full-width, unbiased word distribution.
///
/// Honest limit: ~8k samples cannot distinguish 128-bit from ~40-bit
/// entropy (Coldcard's case needed ~2^20 draws for collisions). This
/// guards against *catastrophic* breakage — masked word indices, a
/// short-period stream, a deterministically seeded generator. The
/// Coldcard-class defense itself is the OS-CSPRNG dependency
/// (`bip39` crate → `rand_core` OsRng → getrandom), recorded in
/// `docs/DECISIONS.md`.
#[test]
fn wallet_mnemonic_shows_full_width_entropy() {
    let words = bip39::Language::English.word_list();
    let n = 8192usize;
    let mut distinct_words = HashSet::new();
    let mut distinct_phrases = HashSet::new();
    for _ in 0..n {
        let m = generate_mnemonic().unwrap_or_else(|_| panic!());
        let phrase = m.phrase();
        assert!(
            mnemonic_from_phrase(&phrase).is_ok(),
            "generated mnemonic must round-trip (checksum intact)"
        );
        let first = phrase.split(' ').next().unwrap_or("");
        if let Some(idx) = words.iter().position(|&w| w == first) {
            distinct_words.insert(idx);
        }
        distinct_phrases.insert(phrase);
    }
    assert_eq!(
        distinct_phrases.len(),
        n,
        "duplicate mnemonics in {n} draws — generator is not full-width"
    );
    // Expected distinct first-words ≈ 2048·(1−e^(−4)) ≈ 2010; floor 1900
    // tolerates RNG luck while still catching truncated support.
    assert!(
        distinct_words.len() > 1900,
        "first-word distribution looks biased: {} distinct of 2048",
        distinct_words.len()
    );
}
