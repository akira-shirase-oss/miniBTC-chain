//! Bounded canonical reader — every decode checks bounds before slicing.
//!
//! This is the decoder half of the wire format. The rules that keep parsers
//! safe on hostile input:
//!
//! - every read verifies remaining bytes *before* touching them;
//! - CompactSize rejects non-canonical encodings (a `0xFD` prefix must
//!   encode a value ≥ 253, and so on);
//! - length-prefixed reads are capped by what remains, never trusted;
//! - nothing here allocates attacker-controlled sizes unchecked — a
//!   declared length larger than the buffer is an immediate error.

use minibtc_crypto::{Hash160, Hash256};

/// Errors from canonical decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadError {
    /// Fewer bytes remained than the read required.
    #[error("unexpected end of data: need {need} bytes, {have} remain")]
    UnexpectedEof {
        /// Bytes the read wanted.
        need: usize,
        /// Bytes actually left.
        have: usize,
    },
    /// A CompactSize prefix was not in canonical (minimal) form.
    #[error("non-canonical CompactSize encoding at offset {0}")]
    NonCanonicalCompactSize(usize),
    /// A vector length prefix claimed more items/bytes than remain.
    #[error("declared length {declared} exceeds remaining {remaining}")]
    LengthOverflow {
        /// What the prefix claimed.
        declared: u64,
        /// Bytes/items actually available.
        remaining: u64,
    },
    /// A fixed-size field had trailing bytes after it.
    #[error("{0} trailing bytes after decode")]
    TrailingBytes(usize),
}

/// Cursor over a byte slice. Cheap to clone; position is explicit.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Reader over `buf`, positioned at 0.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Whether everything has been consumed.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Borrow the unconsumed tail.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Take `n` bytes, advancing the cursor. Bounds-checked.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ReadError> {
        let have = self.remaining();
        if n > have {
            return Err(ReadError::UnexpectedEof { need: n, have });
        }
        let start = self.pos;
        self.pos = self.pos.saturating_add(n);
        Ok(&self.buf[start..self.pos])
    }

    /// Require the cursor be at the end — canonical decoders reject
    /// trailing garbage rather than silently ignoring it.
    pub fn finish(&self) -> Result<(), ReadError> {
        let left = self.remaining();
        if left == 0 {
            Ok(())
        } else {
            Err(ReadError::TrailingBytes(left))
        }
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8, ReadError> {
        Ok(self.take(1)?[0])
    }

    /// u16 little-endian.
    pub fn u16(&mut self) -> Result<u16, ReadError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    /// u32 little-endian.
    pub fn u32(&mut self) -> Result<u32, ReadError> {
        let b = self.take(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(b);
        Ok(u32::from_le_bytes(a))
    }

    /// u64 little-endian.
    pub fn u64(&mut self) -> Result<u64, ReadError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    /// i32 little-endian.
    pub fn i64(&mut self) -> Result<i64, ReadError> {
        let b = self.take(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(i64::from_le_bytes(arr))
    }

    pub fn i32(&mut self) -> Result<i32, ReadError> {
        Ok(self.u32()? as i32)
    }

    /// 32-byte hash.
    pub fn hash256(&mut self) -> Result<Hash256, ReadError> {
        let b = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(Hash256(a))
    }

    /// 20-byte hash.
    pub fn hash160(&mut self) -> Result<Hash160, ReadError> {
        let b = self.take(20)?;
        let mut a = [0u8; 20];
        a.copy_from_slice(b);
        Ok(Hash160(a))
    }

    /// CompactSize with canonical-form enforcement. The prefix byte
    /// determines the width; the decoded value must be representable in the
    /// *smaller* widths to count as canonical (Bitcoin's rule, made strict).
    pub fn compact_size(&mut self) -> Result<u64, ReadError> {
        let at = self.pos;
        let tag = self.u8()?;
        let (v, min_for_tag) = match tag {
            0xFF => (self.u64()?, 0x1_0000_0000),
            0xFE => {
                let v = u64::from(self.u32()?);
                (v, 0x1_0000)
            }
            0xFD => {
                let v = u64::from(self.u16()?);
                (v, 253)
            }
            // A single byte *is* the value 0..=252 — always canonical.
            t => (u64::from(t), 0),
        };
        if v < min_for_tag {
            return Err(ReadError::NonCanonicalCompactSize(at));
        }
        Ok(v)
    }

    /// Read a CompactSize-prefixed byte vector. The declared length must fit
    /// in the remaining buffer — no speculative allocation.
    pub fn prefixed_bytes(&mut self, max: usize) -> Result<Vec<u8>, ReadError> {
        let len = self.compact_size()?;
        if len > max as u64 {
            return Err(ReadError::LengthOverflow {
                declared: len,
                remaining: max as u64,
            });
        }
        if len > self.remaining() as u64 {
            return Err(ReadError::LengthOverflow {
                declared: len,
                remaining: self.remaining() as u64,
            });
        }
        Ok(self.take(len as usize)?.to_vec())
    }

    /// Read `count` items via `read_one`, where `count` came from a
    /// CompactSize prefix. `max` bounds the declared count before any
    /// allocation — callers pass the protocol limit (e.g. max txs per
    /// block), never an attacker-influenced number.
    pub fn vec<T>(
        &mut self,
        max: usize,
        mut read_one: impl FnMut(&mut Self) -> Result<T, ReadError>,
    ) -> Result<Vec<T>, ReadError> {
        let count = self.compact_size()?;
        if count > max as u64 {
            return Err(ReadError::LengthOverflow {
                declared: count,
                remaining: max as u64,
            });
        }
        let mut out = Vec::with_capacity(count.min(1024) as usize);
        for _ in 0..count {
            out.push(read_one(self)?);
        }
        Ok(out)
    }
}
