//! IPv4 + TCP wire-format helpers.
//!
//! Strictly minimal, but with **TCP options** (MSS, Timestamps, NOPs) and
//! a guard against IP fragments — both are mandatory for sane interop.
//!
//! All parsing routines are bounds-checked and return `Result`, never panic.

use crate::error::TcpError;

pub const IPV4_HDR_LEN: usize = 20;
pub const TCP_HDR_LEN: usize = 20;
pub const IPPROTO_TCP: u8 = 6;

pub mod flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    // ECN flags (RFC 3168 §6.1).
    /// Echo Congestion Experienced. Receiver-set: signals to sender that
    /// a CE-marked segment was observed. Sender responds with CWR.
    pub const ECE: u8 = 0x40;
    /// Congestion Window Reduced. Sender-set: signals to receiver that
    /// the sender has reacted to the previous ECE signal.
    pub const CWR: u8 = 0x80;
}

/// IP-layer ECN codepoints carried in the lower 2 bits of the IPv4 TOS
/// byte (RFC 3168 §5).
pub mod ecn {
    /// Not ECN-Capable Transport. Default for non-ECN connections.
    pub const NOT_ECT: u8 = 0b00;
    /// ECN-Capable Transport, codepoint 1 (currently used by L4S — RFC 9331).
    pub const ECT_1: u8 = 0b01;
    /// ECN-Capable Transport, codepoint 0. The conventional choice for
    /// classic ECN; emitted by this stack on all data segments once ECN
    /// is negotiated.
    pub const ECT_0: u8 = 0b10;
    /// Congestion Experienced. Set by a router along the path to signal
    /// queue buildup. The receiver responds by setting TCP ECE on the
    /// next ACK.
    pub const CE: u8 = 0b11;

    /// Mask for the 2-bit field within the IPv4 TOS byte.
    pub const MASK: u8 = 0b11;
}

/// SACK block list: up to 4 disjoint `(left_edge, right_edge)` pairs per
/// RFC 2018 §3. The maximum useful number of blocks alongside Timestamps
/// is 3 (TS=10b + 3×SACK=26b + 2 NOPs = 38b, fitting in the 40-byte TCP
/// option cap). When TS is absent we can carry the full 4 (34b + NOPs).
///
/// Wire emission rounds down to the count that fits in `40 - other_opts`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SackBlocks {
    /// Number of populated entries in `blocks` (0..=4).
    n: u8,
    /// First-N entries are valid; trailing slots are zero-padding.
    blocks: [(u32, u32); 4],
}

impl SackBlocks {
    pub const EMPTY: Self = Self {
        n: 0,
        blocks: [(0, 0); 4],
    };

    #[inline]
    pub const fn one(left: u32, right: u32) -> Self {
        let mut s = Self::EMPTY;
        s.n = 1;
        s.blocks[0] = (left, right);
        s
    }

    /// Construct directly from an existing slice; clamps to 4 blocks.
    pub fn from_slice(src: &[(u32, u32)]) -> Self {
        let mut s = Self::EMPTY;
        let n = core::cmp::min(src.len(), 4);
        for i in 0..n {
            if let Some(b) = src.get(i) {
                if let Some(slot) = s.blocks.get_mut(i) {
                    *slot = *b;
                }
            }
        }
        s.n = n as u8;
        s
    }

    /// Append a block. Saturates silently at 4 (caller is responsible
    /// for ordering / deduping).
    pub fn push(&mut self, left: u32, right: u32) {
        if (self.n as usize) < self.blocks.len() {
            if let Some(slot) = self.blocks.get_mut(self.n as usize) {
                *slot = (left, right);
                self.n += 1;
            }
        }
    }

    #[inline]
    pub const fn len(&self) -> usize {
        self.n as usize
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn as_slice(&self) -> &[(u32, u32)] {
        let n = self.n as usize;
        self.blocks.get(..n).unwrap_or(&[])
    }

    /// Truncate to at most `max` blocks.
    pub fn truncate(&mut self, max: usize) {
        if (self.n as usize) > max {
            self.n = max as u8;
        }
    }
}

impl From<Option<(u32, u32)>> for SackBlocks {
    fn from(o: Option<(u32, u32)>) -> Self {
        match o {
            Some((l, r)) => Self::one(l, r),
            None => Self::EMPTY,
        }
    }
}

/// TCP options carried by a parsed/emitted segment.
///
/// We model the five options we actually emit or react to:
/// * **MSS** (RFC 9293) — handshake-only.
/// * **Window Scale** (RFC 7323 §2) — handshake-only. Shift count in
///   `0..=14`; values above 14 are clamped on parse per RFC §2.3.
/// * **Timestamps** (RFC 7323) — every segment once negotiated.
/// * **SACK_PERMITTED** (RFC 2018 §2) — handshake-only.
/// * **SACK** (RFC 2018 §3) — up to 4 blocks (RFC 2018 max). Outbound
///   emission caps the count to whatever fits alongside other options
///   in the 40-byte TCP option budget (typically 3 when TS is present,
///   4 otherwise).
///
/// Anything else (MD5, …) is parsed-and-skipped and never emitted.
#[derive(Copy, Clone, Debug, Default)]
pub struct TcpOptions {
    pub mss: Option<u16>,
    /// Window Scale shift count (RFC 7323 §2). Valid only on SYN /
    /// SYN-ACK; ignored elsewhere. Parser clamps to 14.
    pub wscale: Option<u8>,
    /// (TSval, TSecr) per RFC 7323 §3.
    pub ts: Option<(u32, u32)>,
    /// SACK_PERMITTED option present (RFC 2018 §2). Valid only on SYN /
    /// SYN-ACK; ignored elsewhere.
    pub sack_permitted: bool,
    /// SACK blocks (RFC 2018 §3). Up to 4 entries; empty == option absent.
    pub sack: SackBlocks,
}

impl TcpOptions {
    pub const NONE: Self = Self {
        mss: None,
        wscale: None,
        ts: None,
        sack_permitted: false,
        sack: SackBlocks::EMPTY,
    };

    /// Raw byte cost of the five options without any alignment padding.
    const fn raw_len(&self) -> usize {
        let mut n = 0;
        if self.mss.is_some() {
            n += 4; // kind=2, length=4
        }
        if self.wscale.is_some() {
            n += 3; // kind=3, length=3
        }
        if self.sack_permitted {
            n += 2; // kind=4, length=2
        }
        if self.ts.is_some() {
            n += 10; // kind=8, length=10
        }
        if !self.sack.is_empty() {
            n += 2 + 8 * self.sack.len(); // kind=5, length=2 + 8*N
        }
        n
    }

    /// Bytes the encoded option block consumes inside the TCP header. Always
    /// a multiple of 4 (NOPs are inserted as needed for alignment).
    pub const fn encoded_len(&self) -> usize {
        // Round up to multiple of 4.
        let n = self.raw_len();
        (n + 3) & !3
    }

    fn write(&self, out: &mut [u8]) -> Result<usize, TcpError> {
        // Order: MSS, WS, SACK_PERMITTED, TS, SACK. Each option is
        // byte-aligned; the trailing pad to a 4-byte boundary is filled
        // with NOPs (kind=1) rather than EOL so middleboxes that scan past
        // the data offset see a syntactically valid options block.
        let mut idx = 0usize;
        if let Some(mss) = self.mss {
            put_u8(out, idx, 2)?; // kind = MSS
            put_u8(out, idx + 1, 4)?; // length
            put_u16(out, idx + 2, mss)?;
            idx += 4;
        }
        if let Some(ws) = self.wscale {
            // RFC 7323 §2.3: shift_cnt MUST NOT exceed 14. Clamp.
            put_u8(out, idx, 3)?; // kind = Window Scale
            put_u8(out, idx + 1, 3)?; // length
            put_u8(out, idx + 2, ws.min(14))?;
            idx += 3;
        }
        if self.sack_permitted {
            put_u8(out, idx, 4)?; // kind = SACK_PERMITTED
            put_u8(out, idx + 1, 2)?; // length
            idx += 2;
        }
        if let Some((tsval, tsecr)) = self.ts {
            put_u8(out, idx, 8)?; // kind = Timestamps
            put_u8(out, idx + 1, 10)?; // length
            put_u32(out, idx + 2, tsval)?;
            put_u32(out, idx + 6, tsecr)?;
            idx += 10;
        }
        if !self.sack.is_empty() {
            let n = self.sack.len();
            let length = 2 + 8 * n;
            if length > 255 {
                return Err(TcpError::Overflow);
            }
            put_u8(out, idx, 5)?; // kind = SACK
            put_u8(out, idx + 1, length as u8)?;
            for (k, (left, right)) in self.sack.as_slice().iter().enumerate() {
                put_u32(out, idx + 2 + k * 8, *left)?;
                put_u32(out, idx + 6 + k * 8, *right)?;
            }
            idx += length;
        }
        // Pad to multiple of 4 with NOPs.
        let target = (idx + 3) & !3;
        while idx < target {
            put_u8(out, idx, 1)?; // NOP
            idx += 1;
        }
        Ok(idx)
    }

    fn parse(opt_bytes: &[u8]) -> Result<Self, TcpError> {
        let mut o = TcpOptions::NONE;
        let mut i = 0usize;
        while i < opt_bytes.len() {
            let kind = *opt_bytes.get(i).ok_or(TcpError::MalformedPacket)?;
            match kind {
                0 => break, // EOL
                1 => {
                    i += 1;
                } // NOP
                2 => {
                    let len = *opt_bytes.get(i + 1).ok_or(TcpError::MalformedPacket)?;
                    if len != 4 || i + 4 > opt_bytes.len() {
                        return Err(TcpError::MalformedPacket);
                    }
                    o.mss = Some(u16::from_be_bytes(read2(opt_bytes, i + 2)?));
                    i += 4;
                }
                3 => {
                    // Window Scale — RFC 7323 §2. Length must be exactly 3.
                    // Per §2.3, shift counts > 14 are silently clamped.
                    let len = *opt_bytes.get(i + 1).ok_or(TcpError::MalformedPacket)?;
                    if len != 3 || i + 3 > opt_bytes.len() {
                        return Err(TcpError::MalformedPacket);
                    }
                    let shift = *opt_bytes.get(i + 2).ok_or(TcpError::MalformedPacket)?;
                    o.wscale = Some(shift.min(14));
                    i += 3;
                }
                4 => {
                    // SACK_PERMITTED — RFC 2018 §2. Length must be exactly 2.
                    let len = *opt_bytes.get(i + 1).ok_or(TcpError::MalformedPacket)?;
                    if len != 2 || i + 2 > opt_bytes.len() {
                        return Err(TcpError::MalformedPacket);
                    }
                    o.sack_permitted = true;
                    i += 2;
                }
                5 => {
                    // SACK — RFC 2018 §3. Length is 2 + 8*n_blocks for
                    // n_blocks in 1..=4. We keep all blocks; downstream
                    // (the RFC 6675 scoreboard) merges them into its
                    // sender-side state.
                    let len = *opt_bytes.get(i + 1).ok_or(TcpError::MalformedPacket)?;
                    if len < 10
                        || (len - 2) % 8 != 0
                        || (len - 2) / 8 > 4
                        || i + len as usize > opt_bytes.len()
                    {
                        return Err(TcpError::MalformedPacket);
                    }
                    let n_blocks = (len - 2) / 8;
                    let mut sb = SackBlocks::EMPTY;
                    for k in 0..n_blocks {
                        let off = i + 2 + (k as usize) * 8;
                        let left = u32::from_be_bytes(read4(opt_bytes, off)?);
                        let right = u32::from_be_bytes(read4(opt_bytes, off + 4)?);
                        sb.push(left, right);
                    }
                    o.sack = sb;
                    i += len as usize;
                }
                8 => {
                    let len = *opt_bytes.get(i + 1).ok_or(TcpError::MalformedPacket)?;
                    if len != 10 || i + 10 > opt_bytes.len() {
                        return Err(TcpError::MalformedPacket);
                    }
                    let tsval = u32::from_be_bytes(read4(opt_bytes, i + 2)?);
                    let tsecr = u32::from_be_bytes(read4(opt_bytes, i + 6)?);
                    o.ts = Some((tsval, tsecr));
                    i += 10;
                }
                _ => {
                    // Length-prefixed unknown option; skip.
                    let len = *opt_bytes.get(i + 1).ok_or(TcpError::MalformedPacket)?;
                    if len < 2 || i + len as usize > opt_bytes.len() {
                        return Err(TcpError::MalformedPacket);
                    }
                    i += len as usize;
                }
            }
        }
        Ok(o)
    }
}

/// View over a parsed inbound segment. References borrow from the caller's
/// receive buffer — no copies are made.
#[derive(Debug)]
pub struct Segment<'a> {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub options: TcpOptions,
    pub payload: &'a [u8],
    /// IPv4 ECN codepoint (lower 2 bits of TOS): one of [`ecn::NOT_ECT`],
    /// [`ecn::ECT_0`], [`ecn::ECT_1`], or [`ecn::CE`]. Per RFC 3168, a
    /// receiver MUST treat `CE` as a congestion signal and echo `ECE`
    /// back on subsequent ACKs.
    pub ecn: u8,
}

impl<'a> Segment<'a> {
    #[inline]
    pub fn has(&self, f: u8) -> bool {
        (self.flags & f) == f
    }

    /// Length consumed in sequence-number space: payload bytes + 1 per
    /// SYN/FIN flag (RFC 793 §3.3).
    #[inline]
    pub fn seq_len(&self) -> u32 {
        let mut n = self.payload.len() as u32;
        if self.has(flags::SYN) {
            n = n.wrapping_add(1);
        }
        if self.has(flags::FIN) {
            n = n.wrapping_add(1);
        }
        n
    }
}

/// Parse a single IPv4 + TCP datagram. Validates lengths, both checksums,
/// and rejects fragments.
pub fn parse(packet: &[u8]) -> Result<Segment<'_>, TcpError> {
    let ip = packet
        .get(..IPV4_HDR_LEN)
        .ok_or(TcpError::MalformedPacket)?;
    let version_ihl = *ip.first().ok_or(TcpError::MalformedPacket)?;
    if version_ihl >> 4 != 4 {
        return Err(TcpError::MalformedPacket);
    }
    let ihl = (version_ihl & 0x0F) as usize * 4;
    if ihl < IPV4_HDR_LEN {
        return Err(TcpError::MalformedPacket);
    }
    let total_len = u16::from_be_bytes(read2(ip, 2)?) as usize;
    if total_len > packet.len() || total_len < ihl + TCP_HDR_LEN {
        return Err(TcpError::MalformedPacket);
    }

    // Reject fragments — MF bit set, or non-zero fragment offset.
    let flags_frag = u16::from_be_bytes(read2(ip, 6)?);
    if (flags_frag & 0x2000) != 0 || (flags_frag & 0x1FFF) != 0 {
        return Err(TcpError::MalformedPacket);
    }

    let proto = *ip.get(9).ok_or(TcpError::MalformedPacket)?;
    if proto != IPPROTO_TCP {
        return Err(TcpError::NotForUs);
    }
    // RFC 3168 §5: IP TOS byte (offset 1) lower 2 bits carry the ECN
    // codepoint. The top 6 bits (DSCP) are ignored by this stack.
    let ecn = *ip.get(1).ok_or(TcpError::MalformedPacket)? & ecn::MASK;
    let src_ip = read4(ip, 12)?;
    let dst_ip = read4(ip, 16)?;

    let ip_full = packet.get(..ihl).ok_or(TcpError::MalformedPacket)?;
    if checksum(ip_full, 0) != 0 {
        return Err(TcpError::MalformedPacket);
    }

    let tcp_total = total_len - ihl;
    let tcp = packet
        .get(ihl..ihl + tcp_total)
        .ok_or(TcpError::MalformedPacket)?;
    if tcp.len() < TCP_HDR_LEN {
        return Err(TcpError::MalformedPacket);
    }
    let src_port = u16::from_be_bytes(read2(tcp, 0)?);
    let dst_port = u16::from_be_bytes(read2(tcp, 2)?);
    let seq = u32::from_be_bytes(read4(tcp, 4)?);
    let ack = u32::from_be_bytes(read4(tcp, 8)?);
    let data_off = (*tcp.get(12).ok_or(TcpError::MalformedPacket)? >> 4) as usize * 4;
    if data_off < TCP_HDR_LEN || data_off > tcp.len() {
        return Err(TcpError::MalformedPacket);
    }
    let flags = *tcp.get(13).ok_or(TcpError::MalformedPacket)?;
    let window = u16::from_be_bytes(read2(tcp, 14)?);

    if tcp_checksum(&src_ip, &dst_ip, tcp) != 0 {
        return Err(TcpError::MalformedPacket);
    }

    let opt_bytes = tcp
        .get(TCP_HDR_LEN..data_off)
        .ok_or(TcpError::MalformedPacket)?;
    let options = TcpOptions::parse(opt_bytes)?;
    let payload = tcp.get(data_off..).ok_or(TcpError::MalformedPacket)?;

    Ok(Segment {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        window,
        options,
        payload,
        ecn,
    })
}

/// Build an IPv4+TCP datagram into `out`. Returns the number of bytes written.
///
/// `ecn` controls the IPv4 TOS byte's lower 2 bits — pass [`ecn::NOT_ECT`]
/// for non-ECN traffic, [`ecn::ECT_0`] on ECN-capable data segments per
/// RFC 3168 §5.
#[allow(clippy::too_many_arguments)]
pub fn emit(
    out: &mut [u8],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &TcpOptions,
    payload: &[u8],
    ip_id: u16,
    ecn: u8,
) -> Result<usize, TcpError> {
    let opt_len = options.encoded_len();
    if !opt_len.is_multiple_of(4) || opt_len > 40 {
        return Err(TcpError::Overflow);
    }
    let tcp_hdr_len = TCP_HDR_LEN + opt_len;
    let total = IPV4_HDR_LEN + tcp_hdr_len + payload.len();
    if out.len() < total {
        return Err(TcpError::BufferTooSmall);
    }
    let total_u16 = u16::try_from(total).map_err(|_| TcpError::Overflow)?;

    // ---- IPv4 header --------------------------------------------------------
    let ip = out
        .get_mut(..IPV4_HDR_LEN)
        .ok_or(TcpError::BufferTooSmall)?;
    ip.fill(0);
    put_u8(ip, 0, 0x45)?; // version=4, IHL=5
    // TOS byte: DSCP=0, ECN codepoint in low 2 bits (RFC 3168 §5).
    put_u8(ip, 1, ecn & ecn::MASK)?;
    put_u16(ip, 2, total_u16)?;
    put_u16(ip, 4, ip_id)?;
    put_u16(ip, 6, 0x4000)?; // DF set, no fragment offset
    put_u8(ip, 8, 64)?; // TTL
    put_u8(ip, 9, IPPROTO_TCP)?;
    put_u16(ip, 10, 0)?;
    put4(ip, 12, src_ip)?;
    put4(ip, 16, dst_ip)?;
    let ip_csum = checksum(ip, 0);
    put_u16(ip, 10, ip_csum)?;

    // ---- TCP header --------------------------------------------------------
    let tcp_end = IPV4_HDR_LEN + tcp_hdr_len + payload.len();
    let tcp = out
        .get_mut(IPV4_HDR_LEN..tcp_end)
        .ok_or(TcpError::BufferTooSmall)?;
    let (hdr, body) = tcp.split_at_mut(tcp_hdr_len);
    hdr.fill(0);
    put_u16(hdr, 0, src_port)?;
    put_u16(hdr, 2, dst_port)?;
    put_u32(hdr, 4, seq)?;
    put_u32(hdr, 8, ack)?;
    let data_off = ((tcp_hdr_len / 4) as u8) << 4;
    put_u8(hdr, 12, data_off)?;
    put_u8(hdr, 13, flags)?;
    put_u16(hdr, 14, window)?;
    // checksum (16) + urgent (18) start zeroed.

    if opt_len > 0 {
        let opt_slice = hdr
            .get_mut(TCP_HDR_LEN..TCP_HDR_LEN + opt_len)
            .ok_or(TcpError::BufferTooSmall)?;
        let written = options.write(opt_slice)?;
        if written != opt_len {
            return Err(TcpError::Overflow);
        }
    }

    if let Some(dst) = body.get_mut(..payload.len()) {
        dst.copy_from_slice(payload);
    }

    let tcp_segment = out
        .get(IPV4_HDR_LEN..tcp_end)
        .ok_or(TcpError::BufferTooSmall)?;
    let tcp_csum = tcp_checksum(&src_ip, &dst_ip, tcp_segment);
    let tcp_mut = out
        .get_mut(IPV4_HDR_LEN..tcp_end)
        .ok_or(TcpError::BufferTooSmall)?;
    put_u16(tcp_mut, 16, tcp_csum)?;

    Ok(total)
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

fn checksum(data: &[u8], seed: u32) -> u16 {
    let mut sum = seed;
    let mut i = 0;
    while i + 1 < data.len() {
        let hi = match data.get(i) {
            Some(b) => *b as u32,
            None => break,
        };
        let lo = match data.get(i + 1) {
            Some(b) => *b as u32,
            None => break,
        };
        sum = sum.wrapping_add((hi << 8) | lo);
        i += 2;
    }
    if i < data.len() {
        if let Some(b) = data.get(i) {
            sum = sum.wrapping_add((*b as u32) << 8);
        }
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
    let len = tcp_segment.len() as u32;
    let pseudo: u32 = (((src_ip[0] as u32) << 8) | src_ip[1] as u32)
        .wrapping_add(((src_ip[2] as u32) << 8) | src_ip[3] as u32)
        .wrapping_add(((dst_ip[0] as u32) << 8) | dst_ip[1] as u32)
        .wrapping_add(((dst_ip[2] as u32) << 8) | dst_ip[3] as u32)
        .wrapping_add(IPPROTO_TCP as u32)
        .wrapping_add(len & 0xFFFF);
    checksum(tcp_segment, pseudo)
}

// ---------------------------------------------------------------------------
// Tiny safe accessors — every read/write is bounds-checked.
// ---------------------------------------------------------------------------

fn read2(buf: &[u8], off: usize) -> Result<[u8; 2], TcpError> {
    let s = buf.get(off..off + 2).ok_or(TcpError::MalformedPacket)?;
    let mut a = [0u8; 2];
    a.copy_from_slice(s);
    Ok(a)
}

fn read4(buf: &[u8], off: usize) -> Result<[u8; 4], TcpError> {
    let s = buf.get(off..off + 4).ok_or(TcpError::MalformedPacket)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Ok(a)
}

fn put_u8(buf: &mut [u8], off: usize, v: u8) -> Result<(), TcpError> {
    *buf.get_mut(off).ok_or(TcpError::BufferTooSmall)? = v;
    Ok(())
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) -> Result<(), TcpError> {
    let dst = buf.get_mut(off..off + 2).ok_or(TcpError::BufferTooSmall)?;
    dst.copy_from_slice(&v.to_be_bytes());
    Ok(())
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) -> Result<(), TcpError> {
    let dst = buf.get_mut(off..off + 4).ok_or(TcpError::BufferTooSmall)?;
    dst.copy_from_slice(&v.to_be_bytes());
    Ok(())
}

fn put4(buf: &mut [u8], off: usize, v: [u8; 4]) -> Result<(), TcpError> {
    let dst = buf.get_mut(off..off + 4).ok_or(TcpError::BufferTooSmall)?;
    dst.copy_from_slice(&v);
    Ok(())
}
