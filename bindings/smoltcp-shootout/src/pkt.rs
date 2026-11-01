//! A small IPv4 + TCP codec, independent of both stacks under test: it
//! observes their traffic on the simulated wire and builds the scripted
//! peer's segments for the probes.

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

/// Parsed view of one IPv4/TCP datagram.
#[derive(Clone, Copy, Debug, Default)]
pub struct Seg {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub win: u16,
    pub mss: Option<u16>,
    pub ws: Option<u8>,
    pub sack_ok: bool,
    pub sacks: [(u32, u32); 4],
    pub nsacks: usize,
    pub ts: Option<(u32, u32)>,
    /// TCP option bytes (header length minus 20).
    pub opt_len: usize,
    pub payload_len: usize,
}

impl Seg {
    pub fn has(&self, f: u8) -> bool {
        self.flags & f == f
    }
    /// Sequence space the segment occupies (payload, SYN and FIN).
    pub fn seq_len(&self) -> u32 {
        self.payload_len as u32 + u32::from(self.has(SYN)) + u32::from(self.has(FIN))
    }
    pub fn end(&self) -> u32 {
        self.seq.wrapping_add(self.seq_len())
    }
    pub fn sack_blocks(&self) -> &[(u32, u32)] {
        &self.sacks[..self.nsacks]
    }
}

pub fn flags_str(f: u8) -> String {
    let mut s = String::new();
    for (bit, c) in [(SYN, 'S'), (FIN, 'F'), (RST, 'R'), (PSH, 'P'), (ACK, '.')] {
        if f & bit != 0 {
            s.push(c);
        }
    }
    s
}

fn be16(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}
fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// Parse an IPv4/TCP datagram. Lengths are validated; checksums are not
/// (see [`checksums_ok`]).
pub fn parse(p: &[u8]) -> Option<Seg> {
    if p.len() < 40 || p[0] >> 4 != 4 || p[9] != 6 {
        return None;
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    let total = usize::from(be16(p, 2));
    if ihl < 20 || total > p.len() || total < ihl + 20 {
        return None;
    }
    let t = &p[ihl..total];
    let doff = usize::from(t[12] >> 4) * 4;
    if doff < 20 || doff > t.len() {
        return None;
    }
    let mut s = Seg {
        src: [p[12], p[13], p[14], p[15]],
        dst: [p[16], p[17], p[18], p[19]],
        sport: be16(t, 0),
        dport: be16(t, 2),
        seq: be32(t, 4),
        ack: be32(t, 8),
        flags: t[13],
        win: be16(t, 14),
        opt_len: doff - 20,
        payload_len: total - ihl - doff,
        ..Seg::default()
    };
    let o = &t[20..doff];
    let mut i = 0;
    while i < o.len() {
        match o[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let len = usize::from(*o.get(i + 1)?);
                if len < 2 || i + len > o.len() {
                    return Some(s);
                }
                let v = &o[i + 2..i + len];
                match (kind, len) {
                    (2, 4) => s.mss = Some(be16(v, 0)),
                    (3, 3) => s.ws = Some(v[0]),
                    (4, 2) => s.sack_ok = true,
                    (5, _) => {
                        for b in v.as_chunks::<8>().0.iter().take(4) {
                            s.sacks[s.nsacks] = (be32(b, 0), be32(b, 4));
                            s.nsacks += 1;
                        }
                    }
                    (8, 10) => s.ts = Some((be32(v, 0), be32(v, 4))),
                    _ => {}
                }
                i += len;
            }
        }
    }
    Some(s)
}

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let (pairs, rest) = data.as_chunks::<2>();
    for c in pairs {
        acc += u32::from(u16::from_be_bytes(*c));
    }
    if let [b] = rest {
        acc += u32::from(*b) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn tcp_csum(src: &[u8], dst: &[u8], tcp: &[u8]) -> u16 {
    let mut acc = sum16(src, 0);
    acc = sum16(dst, acc);
    acc += 6 + tcp.len() as u32;
    fold(sum16(tcp, acc))
}

/// Both the IPv4 header and the TCP checksum verify.
#[cfg(test)]
pub fn checksums_ok(p: &[u8]) -> bool {
    if p.len() < 40 {
        return false;
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    let total = usize::from(be16(p, 2));
    if ihl < 20 || total > p.len() || total < ihl + 20 {
        return false;
    }
    fold(sum16(&p[..ihl], 0)) == 0 && tcp_csum(&p[12..16], &p[16..20], &p[ihl..total]) == 0
}

/// Recompute both checksums in place (after a deliberate mutation).
pub fn fix_checksums(p: &mut [u8]) {
    if p.len() < 40 {
        return;
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    let total = usize::from(be16(p, 2)).min(p.len());
    if ihl < 20 || total < ihl + 18 {
        return;
    }
    p[10] = 0;
    p[11] = 0;
    let c = fold(sum16(&p[..ihl], 0));
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p[ihl + 16] = 0;
    p[ihl + 17] = 0;
    let (hdr, tcp) = p.split_at_mut(ihl);
    let c = tcp_csum(&hdr[12..16], &hdr[16..20], &tcp[..total - ihl]);
    tcp[16..18].copy_from_slice(&c.to_be_bytes());
}

/// A segment for the scripted peer to send.
#[derive(Clone, Debug, Default)]
pub struct Build {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub win: u16,
    pub mss: Option<u16>,
    pub ws: Option<u8>,
    pub sack_ok: bool,
    pub sacks: Vec<(u32, u32)>,
    pub ts: Option<(u32, u32)>,
    pub payload: Vec<u8>,
    pub ip_id: u16,
}

impl Build {
    pub fn emit(&self) -> Vec<u8> {
        let mut opt = Vec::with_capacity(40);
        if let Some(m) = self.mss {
            opt.extend_from_slice(&[2, 4]);
            opt.extend_from_slice(&m.to_be_bytes());
        }
        if let Some(w) = self.ws {
            opt.extend_from_slice(&[1, 3, 3, w]);
        }
        if self.sack_ok {
            opt.extend_from_slice(&[1, 1, 4, 2]);
        }
        if let Some((v, e)) = self.ts {
            opt.extend_from_slice(&[1, 1, 8, 10]);
            opt.extend_from_slice(&v.to_be_bytes());
            opt.extend_from_slice(&e.to_be_bytes());
        }
        if !self.sacks.is_empty() {
            // TCP options are at most 40 bytes: send the SACK blocks that fit.
            let room = (40usize.saturating_sub(opt.len() + 4)) / 8;
            let n = self.sacks.len().min(room);
            if n > 0 {
                opt.extend_from_slice(&[1, 1, 5, 2 + 8 * n as u8]);
                for &(l, r) in &self.sacks[..n] {
                    opt.extend_from_slice(&l.to_be_bytes());
                    opt.extend_from_slice(&r.to_be_bytes());
                }
            }
        }
        while opt.len() % 4 != 0 {
            opt.push(0);
        }
        debug_assert!(opt.len() <= 40);
        let doff = ((20 + opt.len()) / 4) as u8;
        let tcp_len = 20 + opt.len() + self.payload.len();
        let total = 20 + tcp_len;
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[4..6].copy_from_slice(&self.ip_id.to_be_bytes());
        p[6] = 0x40; // DF
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&self.src);
        p[16..20].copy_from_slice(&self.dst);
        let t = &mut p[20..];
        t[0..2].copy_from_slice(&self.sport.to_be_bytes());
        t[2..4].copy_from_slice(&self.dport.to_be_bytes());
        t[4..8].copy_from_slice(&self.seq.to_be_bytes());
        t[8..12].copy_from_slice(&self.ack.to_be_bytes());
        t[12] = doff << 4;
        t[13] = self.flags;
        t[14..16].copy_from_slice(&self.win.to_be_bytes());
        t[20..20 + opt.len()].copy_from_slice(&opt);
        t[20 + opt.len()..].copy_from_slice(&self.payload);
        fix_checksums(&mut p);
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let b = Build {
            src: [10, 0, 0, 1],
            dst: [10, 0, 0, 2],
            sport: 1234,
            dport: 80,
            seq: 0xdead_beef,
            ack: 7,
            flags: SYN | ACK,
            win: 512,
            mss: Some(1460),
            ws: Some(7),
            sack_ok: true,
            ts: Some((5, 6)),
            sacks: vec![(100, 200)],
            payload: b"hello".to_vec(),
            ip_id: 9,
        };
        let p = b.emit();
        assert!(checksums_ok(&p));
        let s = parse(&p).unwrap();
        assert_eq!((s.sport, s.dport, s.seq, s.ack), (1234, 80, 0xdead_beef, 7));
        assert_eq!(
            (s.mss, s.ws, s.sack_ok, s.ts),
            (Some(1460), Some(7), true, Some((5, 6)))
        );
        assert_eq!(s.sack_blocks(), &[(100, 200)]);
        assert_eq!(s.payload_len, 5);
        assert_eq!(&p[p.len() - 5..], b"hello");
        assert_eq!(s.seq_len(), 6);
    }

    #[test]
    fn sack_blocks_are_cut_to_the_40_byte_option_space() {
        let b = Build {
            mss: Some(1460),
            ws: Some(7),
            sack_ok: true,
            ts: Some((1, 2)),
            sacks: vec![(1, 2), (3, 4), (5, 6), (7, 8)],
            ..Build::default()
        };
        let p = b.emit();
        let s = parse(&p).unwrap();
        assert!(checksums_ok(&p));
        assert!(s.opt_len <= 40);
        assert_eq!(s.sack_blocks(), &[(1, 2)]);
        assert_eq!(s.ts, Some((1, 2)));
    }
}
