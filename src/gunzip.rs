//! Minimal gzip (RFC 1952) + DEFLATE (RFC 1951) reader.
//!
//! Why it exists instead of a crate: the target shape's only kernel config is
//! `/proc/config.gz` (verified 2026-10-05 on the CI microVM: `/proc/config.gz`
//! present, no `/boot`, no `/lib/modules`, and `/proc/modules` missing so even
//! `lsmod` fails), so reading it needs an inflater — while this binary is a
//! stripped static-pie musl tool whose dependencies are deliberately only
//! `libc`, `clap`, `serde`, `serde_json`. Decompression is a bounded, fully
//! testable problem, so it lives here rather than pulling a crate in.
//!
//! Scope: single-member gzip streams with any header flags, and stored /
//! fixed-Huffman / dynamic-Huffman deflate blocks. `None` on malformed input,
//! with a hard output ceiling so a crafted archive cannot exhaust memory in a
//! tool that runs as root inside a guest.

/// Ceiling on decompressed size: the largest real config seen here is ~290 KB
/// (`/boot/config-6.8.0-142-generic`); 64 MiB is a guard, not a limit.
pub const MAX_OUTPUT: usize = 64 * 1024 * 1024;

/// Decompress a gzip stream. `None` for anything that is not a well-formed
/// single-member gzip stream, including an `ISIZE` that disagrees with the
/// number of bytes produced (a truncated config would silently lose symbols).
pub fn gunzip(src: &[u8]) -> Option<Vec<u8>> {
    let body = gzip_body(src)?;
    let out = inflate(body.data, MAX_OUTPUT)?;
    if body.isize != (out.len() as u32) {
        return None;
    }
    Some(out)
}

/// Does this look like gzip? Callers sniff before choosing a decoder:
/// `/lib/modules/<release>/config` is plain text on some distros.
pub fn is_gzip(src: &[u8]) -> bool {
    src.len() >= 19 && src[0] == 0x1f && src[1] == 0x8b && src[2] == 8
}

struct GzipBody<'a> {
    data: &'a [u8],
    isize: u32,
}

/// Skip the gzip header, honouring every FLG bit; read the trailing ISIZE.
fn gzip_body(src: &[u8]) -> Option<GzipBody<'_>> {
    // Fixed header magic(2) CM(1) FLG(1) MTIME(4) XFL(1) OS(1) = 10, plus an
    // 8-byte trailer.
    if src.len() < 18 || src[0] != 0x1f || src[1] != 0x8b || src[2] != 8 {
        return None;
    }
    let flg = src[3];
    let mut p = 10usize;
    if flg & 0x04 != 0 {
        // FEXTRA: two little-endian length bytes, then that many bytes.
        let n = u16::from_le_bytes([*src.get(p)?, *src.get(p + 1)?]) as usize;
        p += 2 + n;
    }
    for bit in [0x08u8, 0x10] {
        // FNAME, FCOMMENT: NUL-terminated.
        if flg & bit != 0 {
            while *src.get(p)? != 0 {
                p += 1;
            }
            p += 1;
        }
    }
    if flg & 0x02 != 0 {
        p += 2; // FHCRC
    }
    let end = src.len();
    if p + 8 > end {
        return None;
    }
    let isize_field = u32::from_le_bytes([src[end - 4], src[end - 3], src[end - 2], src[end - 1]]);
    Some(GzipBody {
        data: &src[p..end - 8],
        isize: isize_field,
    })
}

/// Canonical-Huffman decoder table: `counts[len]` codes of that length with the
/// symbols in canonical order (the classic zlib `decode` walk).
struct Huff {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huff {
    fn new(lengths: &[u8]) -> Option<Huff> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            counts[l as usize] += 1;
        }
        counts[0] = 0;
        // Over-subscribed code (needs more bits than the length allows) is corrupt.
        let mut left: i32 = 1;
        for (_len, count) in counts.iter().enumerate().skip(1) {
            left <<= 1;
            left -= *count as i32;
            if left < 0 {
                return None;
            }
        }
        // An incomplete distance table is legal (a block with no matches), so it
        // is not rejected here; decoding a symbol out of it fails, which makes
        // the whole stream fail.
        let mut offs = [0u16; 16];
        for len in 1..15 {
            offs[len + 1] = offs[len] + counts[len];
        }
        let mut symbols = vec![0u16; lengths.iter().filter(|&&l| l != 0).count()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbols[offs[l as usize] as usize] = sym as u16;
                offs[l as usize] += 1;
            }
        }
        Some(Huff { counts, symbols })
    }

    fn decode(&self, r: &mut BitReader) -> Option<u16> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..16 {
            code |= r.bit()? as i32;
            let count = self.counts[len] as i32;
            if code - first < count {
                return self.symbols.get((index + (code - first)) as usize).copied();
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        None
    }
}

struct BitReader<'a> {
    src: &'a [u8],
    pos: usize,
    bit: u32,
    acc: u32,
}

impl<'a> BitReader<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            pos: 0,
            bit: 0,
            acc: 0,
        }
    }

    fn bit(&mut self) -> Option<u8> {
        if self.bit == 0 {
            self.acc = *self.src.get(self.pos)? as u32;
            self.pos += 1;
            self.bit = 8;
        }
        let b = (self.acc & 1) as u8;
        self.acc >>= 1;
        self.bit -= 1;
        Some(b)
    }

    /// Non-Huffman fields: least-significant bit first.
    fn bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for i in 0..n {
            v |= (self.bit()? as u32) << i;
        }
        Some(v)
    }

    /// Drop the rest of the current byte (before a stored block's LEN field).
    /// `bit()` advances `pos` as it loads a byte, so zeroing the remaining-bit
    /// counter is the entire alignment step.
    fn align(&mut self) {
        self.bit = 0;
    }
}

// Length and distance tables (RFC 1951 3.2.5).
const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// Code-length code order of a dynamic block (RFC 1951 3.2.7).
const CLO: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

fn fixed_tables() -> (Huff, Huff) {
    let mut lit = [0u8; 288];
    for (i, v) in lit.iter_mut().enumerate() {
        *v = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let dist = [5u8; 30];
    (Huff::new(&lit).unwrap(), Huff::new(&dist).unwrap())
}

fn inflate(src: &[u8], limit: usize) -> Option<Vec<u8>> {
    let mut r = BitReader::new(src);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let bfinal = r.bit()?;
        let btype = r.bits(2)?;
        match btype {
            0 => {
                r.align();
                let len = u16::from_le_bytes([*r.src.get(r.pos)?, *r.src.get(r.pos + 1)?]);
                let nlen = u16::from_le_bytes([*r.src.get(r.pos + 2)?, *r.src.get(r.pos + 3)?]);
                if len != !nlen {
                    return None;
                }
                let start = r.pos + 4;
                let chunk = r.src.get(start..start + len as usize)?;
                if out.len() + chunk.len() > limit {
                    return None;
                }
                out.extend_from_slice(chunk);
                r.pos = start + len as usize;
            }
            1 => {
                let (lit, dist) = fixed_tables();
                block(&mut r, &lit, &dist, &mut out, limit)?;
            }
            2 => {
                let (lit, dist) = dynamic_tables(&mut r)?;
                block(&mut r, &lit, &dist, &mut out, limit)?;
            }
            _ => return None, // BTYPE 03 is reserved
        }
        if bfinal == 1 {
            return Some(out);
        }
    }
}

/// One Huffman block's symbol stream.
fn block(
    r: &mut BitReader,
    lit: &Huff,
    dist: &Huff,
    out: &mut Vec<u8>,
    limit: usize,
) -> Option<()> {
    loop {
        let sym = lit.decode(r)?;
        if sym < 256 {
            if out.len() >= limit {
                return None;
            }
            out.push(sym as u8);
        } else if sym == 256 {
            return Some(());
        } else {
            let idx = sym as usize - 257;
            let len = LEN_BASE
                .get(idx)?
                .checked_add(r.bits(LEN_EXTRA[idx])? as u16)?;
            let dsym = dist.decode(r)? as usize;
            let d = DIST_BASE
                .get(dsym)
                .copied()?
                .checked_add(r.bits(DIST_EXTRA[dsym])? as u16)? as usize;
            if d > out.len() {
                return None; // back-reference before the start of the window
            }
            if out.len() + len as usize > limit {
                return None;
            }
            // Byte at a time: an overlapping copy (len > d) is legal and must
            // replicate the bytes it just wrote.
            let from = out.len() - d;
            for i in 0..len as usize {
                let b = out[from + i];
                out.push(b);
            }
        }
    }
}

fn dynamic_tables(r: &mut BitReader) -> Option<(Huff, Huff)> {
    let hlit = r.bits(5)? as usize + 257;
    let hdist = r.bits(5)? as usize + 1;
    let hclen = r.bits(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return None;
    }
    let mut cl_lengths = [0u8; 19];
    for i in 0..hclen {
        cl_lengths[CLO[i]] = r.bits(3)? as u8;
    }
    let cl = Huff::new(&cl_lengths)?;
    let mut lengths = vec![0u8; hlit + hdist];
    let mut i = 0usize;
    while i < lengths.len() {
        match cl.decode(r)? {
            s @ 0..=15 => {
                lengths[i] = s as u8;
                i += 1;
            }
            16 => {
                // Repeat the previous length 3-6 times.
                if i == 0 {
                    return None;
                }
                let prev = lengths[i - 1];
                let n = 3 + r.bits(2)? as usize;
                if i + n > lengths.len() {
                    return None;
                }
                for _ in 0..n {
                    lengths[i] = prev;
                    i += 1;
                }
            }
            17 => {
                let n = 3 + r.bits(3)? as usize;
                if i + n > lengths.len() {
                    return None;
                }
                i += n;
            }
            18 => {
                let n = 11 + r.bits(7)? as usize;
                if i + n > lengths.len() {
                    return None;
                }
                i += n;
            }
            _ => return None,
        }
    }
    let lit = Huff::new(&lengths[..hlit])?;
    let dist = Huff::new(&lengths[hlit..])?;
    Some((lit, dist))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// gzip bytes produced by CPython's `gzip`, kept as base64 so the fixtures
    /// need no binary files and no toolchain to check out.
    fn b64(s: &str) -> Vec<u8> {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut acc = 0u32;
        let mut nbits = 0u32;
        for c in s.bytes() {
            if c == b'=' {
                break;
            }
            acc = (acc << 6) | T.iter().position(|&x| x == c).expect("base64") as u32;
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                out.push((acc >> nbits) as u8);
            }
        }
        out
    }

    // `gzip.compress(b"hello world hello world hello\n", 9)` — a dynamic block.
    const HELLO: &str = "H4sIAAAAAAAC/8tIzcnJVyjPL8pJUchAZ3MBAO7Meb8eAAAA";
    /// Real zlib output at level 1, which uses **fixed** Huffman blocks
    /// (`(out[0] >> 1) & 3 == 1` for all three). These are what settle the fixed
    /// table: my own encoder could only ever agree with itself.
    const FIXED_ABC: &str = "H4sIAAAAAAAE/0tMSgYAwkEkNQMAAAA=";
    const FIXED_HELLO: &str = "H4sIAAAAAAAE/8tIzcnJVyjPL8pJAQCFEUoNCwAAAA==";
    const FIXED_A30: &str = "H4sIAAAAAAAE/0tMxAcAwdPBax4AAAA=";
    // Config-shaped text (the symbol lines a real .config has), gzip -9.
    const CONFIGISH: &str = include_str!("../tests/fixtures/configish.gz.b64");

    /// Test-side bit writer: Huffman codes go in most-significant-bit first, the
    /// other fields least-significant-bit first (RFC 1951 3.1).
    struct Bits {
        bytes: Vec<u8>,
        acc: u32,
        n: u32,
    }

    impl Bits {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                acc: 0,
                n: 0,
            }
        }
        fn le(&mut self, v: u32, len: u32) {
            for i in 0..len {
                self.push((v >> i) & 1);
            }
        }
        fn code(&mut self, v: u32, len: u32) {
            for i in (0..len).rev() {
                self.push((v >> i) & 1);
            }
        }
        fn push(&mut self, b: u32) {
            self.acc |= (b & 1) << self.n;
            self.n += 1;
            if self.n == 8 {
                self.bytes.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.bytes.push(self.acc as u8);
            }
            self.bytes
        }
    }

    /// Canonical code of `sym` for a length table, computed independently of
    /// `Huff` so the two cannot be wrong in the same way.
    fn canon_code(lengths: &[u8], sym: usize) -> (u32, u32) {
        let len = lengths[sym] as u32;
        let mut code = 0u32;
        for l in 1..len {
            code = (code + lengths.iter().filter(|&&x| x as u32 == l).count() as u32) << 1;
        }
        let before = lengths
            .iter()
            .take(sym)
            .filter(|&&x| x as u32 == len)
            .count() as u32;
        (code + before, len)
    }

    fn fixed_lit_lengths() -> [u8; 288] {
        let mut t = [0u8; 288];
        for (i, v) in t.iter_mut().enumerate() {
            *v = match i {
                0..=143 => 8,
                144..=255 => 9,
                256..=279 => 7,
                _ => 8,
            };
        }
        t
    }

    fn wrap(deflate: &[u8], isize_: u32) -> Vec<u8> {
        let mut v: Vec<u8> = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        v.extend_from_slice(deflate);
        v.extend_from_slice(&[0, 0, 0, 0]); // crc32 (gunzip does not verify it)
        v.extend_from_slice(&isize_.to_le_bytes());
        v
    }

    #[test]
    fn hello_fixture() {
        let gz = b64(HELLO.trim());
        assert!(is_gzip(&gz));
        assert_eq!(
            gunzip(&gz).expect("inflates"),
            b"hello world hello world hello\n"
        );
    }

    #[test]
    fn dynamic_huffman_fixture() {
        let gz = b64(CONFIGISH.trim());
        let out = gunzip(&gz).expect("inflates");
        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.contains("CONFIG_VSOCKETS=y"));
        assert!(text.contains("# CONFIG_VHOST_VSOCK is not set"));
        assert!(text.contains("CONFIG_VIRTIO_VSOCKETS=m"));
        assert!(text.lines().count() > 170, "fixture too small to be real");
    }

    #[test]
    fn fixed_huffman_literals_and_overlap_match() {
        // "abc" then a length-6 distance-3 match: the copy overlaps its own
        // source, which a naive slice copy gets wrong.
        let lit = fixed_lit_lengths();
        let dist = [5u8; 30];
        let mut b = Bits::new();
        b.le(1, 1); // BFINAL
        b.le(1, 2); // BTYPE 01 = fixed Huffman
        for c in b"abc" {
            let (code, len) = canon_code(&lit, *c as usize);
            b.code(code, len);
        }
        let (lc, ll) = canon_code(&lit, 260); // LEN 6, no extra bits
        b.code(lc, ll);
        let (dc, dl) = canon_code(&dist, 2); // DIST 3
        b.code(dc, dl);
        let (ec, el) = canon_code(&lit, 256); // end of block
        b.code(ec, el);
        assert_eq!(gunzip(&wrap(&b.finish(), 9)).expect("fixed block"), b"abcabcabc");
    }

    #[test]
    fn stored_block_with_all_header_flags() {
        let payload = b"CONFIG_VSOCKETS=m\n";
        let mut v: Vec<u8> = vec![0x1f, 0x8b, 8, 0x1e, 0, 0, 0, 0, 0, 3]; // FEXTRA|FNAME|FCOMMENT|FHCRC
        v.extend_from_slice(&[2, 0, 0xaa, 0xbb]); // FEXTRA: length 2, then 2 bytes
        v.extend_from_slice(b"name.gz\0"); // FNAME
        v.extend_from_slice(b"a comment\0"); // FCOMMENT
        v.extend_from_slice(&[0x11, 0x22]); // FHCRC
        let mut b = Bits::new();
        b.le(1, 1); // BFINAL
        b.le(0, 2); // BTYPE 00 = stored
        let mut stream = b.finish();
        let len = payload.len() as u16;
        stream.extend_from_slice(&len.to_le_bytes());
        stream.extend_from_slice(&(!len).to_le_bytes());
        stream.extend_from_slice(payload);
        v.extend_from_slice(&stream);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        assert_eq!(gunzip(&v).expect("stored block"), payload);
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(gunzip(b"not gzip"), None);
        assert_eq!(gunzip(&[0x1f, 0x8b]), None); // truncated header
        assert_eq!(gunzip(&wrap(&[0b111], 0)), None); // BTYPE 03 is reserved
        assert_eq!(gunzip(&wrap(&[0b001, 0b0000_0000, 0, 0], 4)), None); // LEN != ~NLEN
        let mut bad = b64(HELLO.trim());
        let n = bad.len();
        bad[n - 4] ^= 0xff; // ISIZE no longer matches the byte count
        assert_eq!(gunzip(&bad), None);
        let mut truncated = b64(HELLO.trim());
        truncated.truncate(truncated.len() - 12);
        assert_eq!(gunzip(&truncated), None);
    }

    #[test]
    fn distance_beyond_output_is_rejected() {
        let lit = fixed_lit_lengths();
        let dist = [5u8; 30];
        let mut b = Bits::new();
        b.le(1, 1);
        b.le(1, 2);
        for c in b"ab" {
            let (code, len) = canon_code(&lit, *c as usize);
            b.code(code, len);
        }
        let (lc, ll) = canon_code(&lit, 257); // LEN 3
        b.code(lc, ll);
        let (dc, dl) = canon_code(&dist, 5); // DIST 7 > 2 bytes of output
        b.code(dc, dl);
        assert_eq!(gunzip(&wrap(&b.finish(), 5)), None);
    }

    #[test]
    fn canon_code_matches_the_fixed_table_codes() {
        // RFC 1951 3.2.6: symbol 0 is the first 8-bit code, 0b00110000 (48);
        // 256 is the first 7-bit code, 0b0000000.
        let lit = fixed_lit_lengths();
        assert_eq!(canon_code(&lit, 0), (48, 8));
        assert_eq!(canon_code(&lit, 143), (191, 8));
        // 200..=255 are unused 8-bit codes, so the first 9-bit code is
        // (199 + 1) << 1 = 400, not the 384 that RFC 1951's prose suggests.
        assert_eq!(canon_code(&lit, 144), (400, 9));
        assert_eq!(canon_code(&lit, 256), (0, 7));
        assert_eq!(canon_code(&lit, 279), (23, 7));
        // The decoder agrees with those codes, literal by literal.
        let (table, _) = fixed_tables();
        for sym in [0u8, 65, 143, 144, 200, 255] {
            let (code, len) = canon_code(&lit, sym as usize);
            let mut b = Bits::new();
            b.code(code, len);
            let bytes = b.finish();
            let mut r = BitReader::new(&bytes);
            assert_eq!(table.decode(&mut r), Some(sym as u16), "symbol {sym}");
        }
        assert_eq!(table.counts[7], 24); // 256..=279
        assert_eq!(table.counts[8], 152); // 0..=143 plus 280..=287
        assert_eq!(table.counts[9], 112); // 144..=255
    }

    /// The archive this module exists for: the running kernel's own config.
    /// Skipped (not faked) when `/proc/config.gz` is unreadable.
    #[test]
    fn real_proc_config_gz_inflates() {
        let Ok(raw) = std::fs::read("/proc/config.gz") else {
            eprintln!("skipping: /proc/config.gz not readable");
            return;
        };
        assert!(is_gzip(&raw));
        let text = String::from_utf8(gunzip(&raw).expect("real config inflates")).expect("utf-8");
        assert!(text.contains("CONFIG_NET=y"), "not a kernel config?");
        assert!(text.lines().count() > 500, "a real config is bigger than this");
    }

    #[test]
    fn real_zlib_fixed_huffman_blocks() {
        // zlib level 1 emits BTYPE=01 for these inputs, so they exercise the
        // fixed table against bytes no code of mine produced.
        for (src, want) in [
            (FIXED_ABC, b"abc".to_vec()),
            (FIXED_HELLO, b"hello world".to_vec()),
            (FIXED_A30, vec![b'a'; 30]),
        ] {
            let gz = b64(src);
            assert!(is_gzip(&gz));
            assert_eq!(gunzip(&gz).expect("fixed block decodes"), want, "fixture {src}");
        }
    }
}
