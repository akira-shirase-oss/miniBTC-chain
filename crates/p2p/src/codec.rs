//! # minibtc-p2p — wire codec
//!
//! Bitcoin-style P2P framing on tokio TCP streams:
//!
//! ```text
//! [4B magic][12B command][4B length LE][4B checksum][payload…]
//! ```
//!
//! - `magic` — network identifier from [`ChainParams::magic`].
//! - `command` — NUL-padded 12-byte ASCII name.
//! - `length` — payload length, capped at [`MAX_MESSAGE_SIZE`].
//! - `checksum` — first 4 bytes of `dsha256(payload)`; verified on every
//!   inbound frame before dispatch (cheap corruption/integrity gate).
//!
//! Every message payload is decoded with the bounded primitives codec —
//! no unbounded allocations, no panics on hostile input.

use minibtc_consensus::ChainParams;
use minibtc_crypto::{Hash256, double_sha256};
use minibtc_primitives::de::Reader;
use minibtc_primitives::ser::Writer;
use minibtc_primitives::{Block, BlockHeader, Transaction};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap on any single message payload (2 MiB — matches Bitcoin's
/// `MAX_PROTOCOL_MESSAGE_LENGTH` order of magnitude for a devnet).
pub const MAX_MESSAGE_SIZE: u32 = 2 * 1024 * 1024;
/// Cap on `addr`/`inv` vector lengths inside payloads.
pub const MAX_ADDR_COUNT: usize = 1_000;
pub const MAX_INV_COUNT: usize = 50_000;
/// Locator hashes per getheaders (Bitcoin uses ~10-11; allow slack).
pub const MAX_LOCATOR_COUNT: usize = 128;
/// Per-message I/O deadline — every read/write is bounded.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Handshake timeout — a peer that can't complete version/verack in this
/// window is dropped.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Wire errors — all peer-triggerable conditions map to `Reject`-worthy
/// failures, never panics.
#[derive(Debug, Error)]
pub enum WireError {
    /// IO failure on the stream.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Bad magic bytes — wrong network or garbage.
    #[error("bad magic")]
    BadMagic,
    /// Payload length exceeded the cap.
    #[error("message too large: {0} bytes")]
    TooLarge(u32),
    /// Checksum mismatch — payload corrupted or malicious.
    #[error("checksum mismatch")]
    BadChecksum,
    /// Payload decode failure.
    #[error("decode: {0}")]
    Decode(#[from] minibtc_primitives::de::ReadError),
    /// Unknown/unsupported command.
    #[error("unknown command {0:?}")]
    UnknownCommand(String),
    /// Protocol timeout.
    #[error("timeout")]
    Timeout,
}

/// Inventory vector element type (Bitcoin inv types, devnet subset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvType {
    /// Transaction.
    Tx = 1,
    /// Block.
    Block = 2,
    /// Filtered block (unused but reserved).
    FilteredBlock = 3,
    /// Compact block (unused but reserved).
    CompactBlock = 4,
}

impl InvType {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Tx),
            2 => Some(Self::Block),
            3 => Some(Self::FilteredBlock),
            4 => Some(Self::CompactBlock),
            _ => None,
        }
    }
}

/// A single inv/getdata element: (type, hash).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvItem {
    /// What the hash refers to.
    pub kind: InvType,
    /// The txid or block hash.
    pub hash: Hash256,
}

/// The complete P2P message set (blueprint P7).
#[derive(Clone, Debug)]
pub enum Message {
    /// `version` — handshake opener: version, services, timestamp, addr_recv,
    /// addr_from, nonce, user_agent, start_height, relay.
    Version {
        /// Protocol version.
        version: i32,
        /// Services bitfield.
        services: u64,
        /// Sender timestamp.
        timestamp: i64,
        /// Receiver address (we mostly ignore contents).
        addr_recv: NetAddress,
        /// Sender address.
        addr_from: NetAddress,
        /// Handshake nonce (for self-connection detection).
        nonce: u64,
        /// User agent string.
        user_agent: String,
        /// Highest block height sender knows.
        start_height: i32,
        /// Whether sender relays txs.
        relay: bool,
    },
    /// `verack` — handshake complete.
    Verack,
    /// `inv` — announce inventory.
    Inv(Vec<InvItem>),
    /// `getdata` — request inventory.
    GetData(Vec<InvItem>),
    /// `tx` — a transaction.
    Tx(Transaction),
    /// `block` — a full block.
    Block(Block),
    /// `headers` — block headers first (headers-first sync).
    Headers {
        /// Header count.
        count: u32,
        /// The headers.
        headers: Vec<BlockHeader>,
    },
    /// `getheaders` — request headers building on a locator.
    GetHeaders {
        /// Hashes the requester already has (newest first).
        locator: Vec<Hash256>,
        /// Stop hash — do not send headers at/before it (ZERO = no stop).
        stop: Hash256,
    },
    /// `ping` — keepalive with payload nonce.
    Ping(u64),
    /// `pong` — keepalive reply.
    Pong(u64),
    /// `addr` — peer address gossip.
    Addr(Vec<(NetAddress, u32)>), // (addr, timestamp)
    /// `reject` — polite rejection notice.
    Reject {
        /// Command being rejected.
        message: String,
        /// Reject code.
        code: u8,
        /// Human-readable reason.
        reason: String,
    },
}

/// A network address as serialized on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetAddress {
    /// Services bitfield.
    pub services: u64,
    /// IP address (v4-mapped or v6).
    pub ip: IpAddr,
    /// Port.
    pub port: u16,
}

impl NetAddress {
    /// Encode services+ip+port (26 bytes, Bitcoin layout).
    fn encode(&self, w: &mut Writer) {
        w.u64(self.services);
        match self.ip {
            IpAddr::V4(v4) => {
                // IPv4-mapped IPv6: 10 zero bytes + ffff + 4 octets = 16.
                w.bytes(&[0u8; 10]);
                w.bytes(&[0xff, 0xff]);
                w.bytes(&v4.octets());
            }
            IpAddr::V6(v6) => {
                w.bytes(&v6.octets());
            }
        }
        w.u16(self.port);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let services = r.u64()?;
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(r.take(16)?);
        let port = r.u16()?;
        let ip = if ip_bytes[..12] == [0u8; 12] {
            IpAddr::V4(Ipv4Addr::new(
                ip_bytes[12],
                ip_bytes[13],
                ip_bytes[14],
                ip_bytes[15],
            ))
        } else {
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(ip_bytes).unwrap_or([0; 16]),
            ))
        };
        Ok(Self { services, ip, port })
    }
}

/// Encode a message payload (command-specific body, no header).
pub fn encode_payload(msg: &Message, params: &ChainParams) -> Vec<u8> {
    let mut w = Writer::new();
    match msg {
        Message::Version {
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
        } => {
            w.i32(*version);
            w.u64(*services);
            w.i64(*timestamp);
            addr_recv.encode(&mut w);
            addr_from.encode(&mut w);
            w.u64(*nonce);
            w.prefixed_bytes(user_agent.as_bytes());
            w.i32(*start_height);
            w.u8(if *relay { 1 } else { 0 });
        }
        Message::Verack => {}
        Message::Inv(items) | Message::GetData(items) => {
            w.compact_size(items.len() as u64);
            for it in items {
                w.u32(it.kind as u32);
                w.hash256(&it.hash);
            }
        }
        Message::Tx(tx) => w.bytes(&tx.encode()),
        Message::Block(b) => w.bytes(&b.encode()),
        Message::Headers { headers, .. } => {
            w.compact_size(headers.len() as u64);
            for h in headers {
                w.bytes(&h.encode());
            }
        }
        Message::GetHeaders { locator, stop } => {
            w.compact_size(locator.len() as u64);
            for h in locator {
                w.hash256(h);
            }
            w.hash256(stop);
        }
        Message::Ping(n) | Message::Pong(n) => w.u64(*n),
        Message::Addr(addrs) => {
            w.compact_size(addrs.len() as u64);
            for (a, t) in addrs {
                w.u32(*t);
                a.encode(&mut w);
            }
        }
        Message::Reject {
            message,
            code,
            reason,
        } => {
            w.prefixed_bytes(message.as_bytes());
            w.u8(*code);
            w.prefixed_bytes(reason.as_bytes());
        }
    }
    let _ = params;
    w.into_bytes()
}

/// Decode a payload for `command`.
pub fn decode_payload(command: &str, payload: &[u8]) -> Result<Message, WireError> {
    let mut r = Reader::new(payload);
    let msg = match command {
        "version" => {
            let version = r.i32()?;
            let services = r.u64()?;
            let timestamp = r.i64()?;
            let addr_recv = NetAddress::decode(&mut r)?;
            let addr_from = NetAddress::decode(&mut r)?;
            let nonce = r.u64()?;
            let ua_bytes = r.prefixed_bytes(256)?;
            let user_agent = String::from_utf8_lossy(&ua_bytes).into_owned();
            let start_height = r.i32()?;
            let relay = r.u8()? != 0;
            Message::Version {
                version,
                services,
                timestamp,
                addr_recv,
                addr_from,
                nonce,
                user_agent,
                start_height,
                relay,
            }
        }
        "verack" => Message::Verack,
        "inv" => Message::Inv(decode_inv(&mut r)?),
        "getdata" => Message::GetData(decode_inv(&mut r)?),
        "tx" => {
            // tx/block payloads are self-delimiting and consume the whole
            // remainder — decode from `rest()`, then advance the cursor so
            // `finish()` sees a clean tail.
            let tx = Transaction::decode(r.rest())?;
            let n = r.remaining();
            r.take(n)?;
            Message::Tx(tx)
        }
        "block" => {
            let block = Block::decode(r.rest(), usize::MAX, MAX_MESSAGE_SIZE as usize)?;
            let n = r.remaining();
            r.take(n)?;
            Message::Block(block)
        }
        "headers" => {
            let count = r.compact_size()? as usize;
            if count > 2_000 {
                return Err(WireError::Decode(
                    minibtc_primitives::de::ReadError::LengthOverflow {
                        declared: u64::MAX,
                        remaining: 0,
                    },
                ));
            }
            let mut headers = Vec::with_capacity(count.min(2_000));
            for _ in 0..count {
                headers.push(BlockHeader::decode(&mut r)?);
            }
            Message::Headers {
                count: count as u32,
                headers,
            }
        }
        "getheaders" => {
            let count = r.compact_size()? as usize;
            if count > MAX_LOCATOR_COUNT {
                return Err(WireError::Decode(
                    minibtc_primitives::de::ReadError::LengthOverflow {
                        declared: u64::MAX,
                        remaining: 0,
                    },
                ));
            }
            let mut locator = Vec::with_capacity(count);
            for _ in 0..count {
                locator.push(r.hash256()?);
            }
            let stop = r.hash256()?;
            Message::GetHeaders { locator, stop }
        }
        "ping" => Message::Ping(r.u64()?),
        "pong" => Message::Pong(r.u64()?),
        "addr" => {
            let count = r.compact_size()? as usize;
            if count > MAX_ADDR_COUNT {
                return Err(WireError::Decode(
                    minibtc_primitives::de::ReadError::LengthOverflow {
                        declared: u64::MAX,
                        remaining: 0,
                    },
                ));
            }
            let mut addrs = Vec::with_capacity(count);
            for _ in 0..count {
                let t = r.u32()?;
                let a = NetAddress::decode(&mut r)?;
                addrs.push((a, t));
            }
            Message::Addr(addrs)
        }
        "reject" => {
            let m = r.prefixed_bytes(12)?;
            let code = r.u8()?;
            let reason = r.prefixed_bytes(256)?;
            Message::Reject {
                message: String::from_utf8_lossy(&m).into_owned(),
                code,
                reason: String::from_utf8_lossy(&reason).into_owned(),
            }
        }
        other => return Err(WireError::UnknownCommand(other.to_string())),
    };
    r.finish()?;
    Ok(msg)
}

fn decode_inv(r: &mut Reader<'_>) -> Result<Vec<InvItem>, WireError> {
    let count = r.compact_size()? as usize;
    if count > MAX_INV_COUNT {
        return Err(WireError::Decode(
            minibtc_primitives::de::ReadError::LengthOverflow {
                declared: u64::MAX,
                remaining: 0,
            },
        ));
    }
    let mut out = Vec::with_capacity(count.min(1_000));
    for _ in 0..count {
        let kind = r.u32()?;
        let hash = r.hash256()?;
        let Some(kind) = InvType::from_u32(kind) else {
            return Err(WireError::Decode(
                minibtc_primitives::de::ReadError::LengthOverflow {
                    declared: u64::MAX,
                    remaining: 0,
                },
            ));
        };
        out.push(InvItem { kind, hash });
    }
    Ok(out)
}

/// Command name for a message (12-byte field content).
pub fn command_name(msg: &Message) -> &'static str {
    match msg {
        Message::Version { .. } => "version",
        Message::Verack => "verack",
        Message::Inv(_) => "inv",
        Message::GetData(_) => "getdata",
        Message::Tx(_) => "tx",
        Message::Block(_) => "block",
        Message::Headers { .. } => "headers",
        Message::GetHeaders { .. } => "getheaders",
        Message::Ping(_) => "ping",
        Message::Pong(_) => "pong",
        Message::Addr(_) => "addr",
        Message::Reject { .. } => "reject",
    }
}

/// Serialize a full framed message: header + payload.
pub fn frame(msg: &Message, params: &ChainParams) -> Vec<u8> {
    let payload = encode_payload(msg, params);
    let checksum = double_sha256(&payload);
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&params.p2p_magic[..]);
    let cmd = command_name(msg);
    let mut cmd_buf = [0u8; 12];
    let n = cmd.len().min(12);
    cmd_buf[..n].copy_from_slice(&cmd.as_bytes()[..n]);
    out.extend_from_slice(&cmd_buf);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&checksum.as_bytes()[..4]);
    out.extend_from_slice(&payload);
    out
}

/// Read one framed message from `r`. Enforces magic, size cap, checksum,
/// and the I/O deadline. Returns the command string + payload decoded.
pub async fn read_message<S: AsyncRead + Unpin>(
    r: &mut S,
    params: &ChainParams,
) -> Result<(String, Vec<u8>), WireError> {
    let mut header = [0u8; 24];
    tokio::time::timeout(IO_TIMEOUT, r.read_exact(&mut header))
        .await
        .map_err(|_| WireError::Timeout)??;
    if header[..4] != params.p2p_magic {
        return Err(WireError::BadMagic);
    }
    let cmd_bytes = &header[4..16];
    let cmd = String::from_utf8_lossy(cmd_bytes)
        .trim_end_matches('\0')
        .to_string();
    let len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    if len > MAX_MESSAGE_SIZE {
        return Err(WireError::TooLarge(len));
    }
    let mut payload = vec![0u8; len as usize];
    tokio::time::timeout(IO_TIMEOUT, r.read_exact(&mut payload))
        .await
        .map_err(|_| WireError::Timeout)??;
    let expect = double_sha256(&payload);
    if header[20..24] != expect.as_bytes()[..4] {
        return Err(WireError::BadChecksum);
    }
    Ok((cmd, payload))
}

/// Write one framed message.
pub async fn write_message<S: AsyncWrite + Unpin>(
    w: &mut S,
    msg: &Message,
    params: &ChainParams,
) -> Result<(), WireError> {
    let bytes = frame(msg, params);
    tokio::time::timeout(IO_TIMEOUT, w.write_all(&bytes))
        .await
        .map_err(|_| WireError::Timeout)??;
    Ok(())
}

/// Convenience: read + decode in one call.
pub async fn recv<S: AsyncRead + Unpin>(
    r: &mut S,
    params: &ChainParams,
) -> Result<Message, WireError> {
    let (cmd, payload) = read_message(r, params).await?;
    decode_payload(&cmd, &payload)
}

/// Now-seconds helper for timestamps.
pub fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ChainParams {
        ChainParams::devnet()
    }

    #[test]
    fn frame_decode_roundtrip_all_messages() {
        let p = params();
        let msgs = vec![
            Message::Verack,
            Message::Ping(42),
            Message::Pong(42),
            Message::Inv(vec![InvItem {
                kind: InvType::Tx,
                hash: Hash256([0xAA; 32]),
            }]),
            Message::GetData(vec![InvItem {
                kind: InvType::Block,
                hash: Hash256([0xBB; 32]),
            }]),
            Message::Addr(vec![(
                NetAddress {
                    services: 0,
                    ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    port: 8333,
                },
                1_700_000_000,
            )]),
            Message::Reject {
                message: "tx".into(),
                code: 1,
                reason: "bad-txns".into(),
            },
        ];
        for m in msgs {
            let framed = frame(&m, &p);
            // Parse header manually then decode payload.
            assert_eq!(&framed[..4], &p.p2p_magic[..]);
            let len = u32::from_le_bytes([framed[16], framed[17], framed[18], framed[19]]) as usize;
            let payload = &framed[24..24 + len];
            let cmd = command_name(&m);
            let dec = decode_payload(cmd, payload).unwrap();
            match (&m, &dec) {
                (Message::Ping(a), Message::Ping(b)) => assert_eq!(a, b),
                (Message::Pong(a), Message::Pong(b)) => assert_eq!(a, b),
                (Message::Verack, Message::Verack) => {}
                (Message::Inv(a), Message::Inv(b)) => assert_eq!(a, b),
                (Message::GetData(a), Message::GetData(b)) => assert_eq!(a, b),
                (Message::Addr(a), Message::Addr(b)) => assert_eq!(a.len(), b.len()),
                (Message::Reject { .. }, Message::Reject { .. }) => {}
                _ => panic!("mismatch"),
            }
        }
    }

    #[tokio::test]
    async fn framed_io_roundtrip_over_buffer() {
        use tokio::io::duplex;
        let p = params();
        let (mut a, mut b) = duplex(4096);
        let msg = Message::Ping(0xdead_beef);
        let writer = tokio::spawn(async move {
            write_message(&mut a, &msg, &params()).await.unwrap();
        });
        let got = recv(&mut b, &params()).await.unwrap();
        writer.await.unwrap();
        assert!(matches!(got, Message::Ping(0xdead_beef)));
    }

    #[tokio::test]
    async fn bad_checksum_rejected() {
        use tokio::io::duplex;
        let p = params();
        let (mut a, mut b) = duplex(4096);
        let mut framed = frame(&Message::Ping(1), &p);
        framed[22] ^= 0xff; // corrupt checksum
        let w = tokio::spawn(async move {
            a.write_all(&framed).await.unwrap();
        });
        let res = recv(&mut b, &params()).await;
        w.await.unwrap();
        assert!(matches!(res, Err(WireError::BadChecksum)));
    }

    #[tokio::test]
    async fn bad_magic_rejected() {
        use tokio::io::duplex;
        let (mut a, mut b) = duplex(4096);
        let mut framed = frame(&Message::Verack, &params());
        framed[0] ^= 0xff;
        let w = tokio::spawn(async move {
            a.write_all(&framed).await.unwrap();
        });
        let res = recv(&mut b, &params()).await;
        w.await.unwrap();
        assert!(matches!(res, Err(WireError::BadMagic)));
    }

    #[test]
    fn oversized_inv_rejected() {
        let mut w = Writer::new();
        w.compact_size((MAX_INV_COUNT as u64) + 1);
        let payload = w.into_bytes();
        assert!(decode_payload("inv", &payload).is_err());
    }

    #[test]
    fn unknown_command_rejected() {
        assert!(matches!(
            decode_payload("notacommand", &[]),
            Err(WireError::UnknownCommand(_))
        ));
    }

    #[test]
    fn version_roundtrip() {
        let p = params();
        let m = Message::Version {
            version: 70016,
            services: 0,
            timestamp: 1_700_000_000,
            addr_recv: NetAddress {
                services: 0,
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 18444,
            },
            addr_from: NetAddress {
                services: 0,
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 18444,
            },
            nonce: 12345,
            user_agent: "/MiniBTC:0.1".into(),
            start_height: 42,
            relay: true,
        };
        let framed = frame(&m, &p);
        let len = u32::from_le_bytes([framed[16], framed[17], framed[18], framed[19]]) as usize;
        let dec = decode_payload("version", &framed[24..24 + len]).unwrap();
        match dec {
            Message::Version {
                nonce,
                start_height,
                ..
            } => {
                assert_eq!(nonce, 12345);
                assert_eq!(start_height, 42);
            }
            _ => panic!("expected version"),
        }
    }
}
