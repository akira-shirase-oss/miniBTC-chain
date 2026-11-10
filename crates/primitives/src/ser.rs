//! Canonical binary writer — the single encoder every MiniBTC type uses.
//!
//! Bitcoin's wire format is little-endian for integers, raw bytes for
//! hashes, and CompactSize length prefixes for variable data. There is no
//! serde/bincode here on purpose: consensus bytes must be byte-exact and
//! stable across releases, so the encoding is written out explicitly.

use minibtc_crypto::{Hash160, Hash256};

/// Append-only byte buffer for canonical serialization.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// Empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Writer pre-sized for `cap` bytes.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// The accumulated bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Current length.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Borrow the buffer mid-build.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Raw bytes.
    pub fn bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// A single byte.
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Unsigned 16-bit, little-endian.
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Unsigned 32-bit, little-endian.
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Unsigned 64-bit, little-endian — also how `Sats` amounts are encoded.
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Signed 32-bit, little-endian (transaction/block versions).
    pub fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// A 32-byte hash in internal byte order (display reverses it, the wire
    /// does not — Bitcoin hashes serialize "as stored").
    pub fn hash256(&mut self, h: &Hash256) {
        self.bytes(h.as_bytes());
    }

    /// A 20-byte hash.
    pub fn hash160(&mut self, h: &Hash160) {
        self.bytes(h.as_bytes());
    }

    /// Bitcoin CompactSize: `<253` → 1 byte; `≤0xFFFF` → `0xFD`+u16le;
    /// `≤0xFFFFFFFF` → `0xFE`+u32le; else `0xFF`+u64le. The canonical form —
    /// non-minimal encodings are rejected on decode.
    pub fn compact_size(&mut self, n: u64) {
        if n < 253 {
            self.buf.push(n as u8);
        } else if n <= 0xFFFF {
            self.buf.push(0xFD);
            self.u16(n as u16);
        } else if n <= 0xFFFF_FFFF {
            self.buf.push(0xFE);
            self.u32(n as u32);
        } else {
            self.buf.push(0xFF);
            self.u64(n);
        }
    }

    /// `compact_size(len)` + raw bytes — the standard vector prefix.
    pub fn prefixed_bytes(&mut self, data: &[u8]) {
        self.compact_size(data.len() as u64);
        self.bytes(data);
    }

    /// `compact_size(count)` + `count` fixed-size items — vector prefix form.
    pub fn count_prefix(&mut self, count: usize) {
        self.compact_size(count as u64);
    }
}
