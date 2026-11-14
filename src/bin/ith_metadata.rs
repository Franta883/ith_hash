// hash-engine.rs  —  compile: rustc -O hash-engine.rs
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::env;
use std::fs;
use std::process;

// ═══════════════════════════════════════════════════════════════════════
//  Small byte readers (bounds-checked, overflow-safe, no unsafe)
// ═══════════════════════════════════════════════════════════════════════

fn ru16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o.checked_add(2)?).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn ru32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn ru64(b: &[u8], o: usize) -> Option<u64> {
    let s = b.get(o..o.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}
fn ru16b(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o.checked_add(2)?).map(|s| u16::from_be_bytes([s[0], s[1]]))
}
fn ru32b(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}
fn ru64b(b: &[u8], o: usize) -> Option<u64> {
    let s = b.get(o..o.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_be_bytes(a))
}

/// Reads a null-terminated byte slice without lossy UTF-8 conversion or arbitrary 4KB truncation.
/// Caps individual symbol length at 1 MiB to prevent memory exhaustion on corrupted binaries.
const MAX_SYM_LEN: usize = 1024 * 1024;

fn read_cbytes(b: &[u8], o: usize) -> Option<Vec<u8>> {
    let s = b.get(o..)?;
    let limit = s.len().min(MAX_SYM_LEN);
    let e = s[..limit].iter().position(|&c| c == 0)?;
    Some(s[..e].to_vec())
}

fn slice(b: &[u8], off: u64, len: u64) -> Option<&[u8]> {
    let s = usize::try_from(off).ok()?;
    let end_u64 = off.checked_add(len)?;
    let e = usize::try_from(end_u64).ok()?;
    b.get(s..e)
}

// ═══════════════════════════════════════════════════════════════════════
//  Streaming SHA-256 (RFC 6234), zero allocations, no external crates
// ═══════════════════════════════════════════════════════════════════════

const K: [u32; 64] = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
];

struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_bytes: u128,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_bytes: 0,
        }
    }

    fn compress_block(h: &mut [u32; 8], chunk: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4*i], chunk[4*i+1], chunk[4*i+2], chunk[4*i+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_bytes = self.total_bytes.saturating_add(data.len() as u128);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                Self::compress_block(&mut self.h, &self.buf);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let mut aligned = [0u8; 64];
            aligned.copy_from_slice(block);
            Self::compress_block(&mut self.h, &aligned);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Feeds a 64-bit big-endian length prefix followed by the raw bytes.
    /// Prevents all delimiter-injection and canonicalization collisions.
    fn update_len_prefixed(&mut self, data: &[u8]) {
        let len = data.len() as u64;
        self.update(&len.to_be_bytes());
        self.update(data);
    }

    fn update_u64(&mut self, val: u64) {
        self.update(&val.to_be_bytes());
    }

    fn finalize(mut self) -> [u8; 32] {
        let bitlen = (self.total_bytes << 3) as u64;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            for b in &mut self.buf[self.buf_len..64] { *b = 0; }
            Self::compress_block(&mut self.h, &self.buf);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..56] { *b = 0; }
        self.buf[56..64].copy_from_slice(&bitlen.to_be_bytes());
        Self::compress_block(&mut self.h, &self.buf);

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[4*i..4*i+4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Findings container (stores raw bytes to prevent UTF-8 lossy collisions)
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
enum ImportEntry {
    ElfNeededLib(Vec<u8>),
    ElfSymbol(Vec<u8>),
    PeNamed { dll_lower: Vec<u8>, func: Vec<u8> },
    PeOrdinal { dll_lower: Vec<u8>, ordinal: u64 },
}

impl ImportEntry {
    fn display(&self) -> String {
        match self {
            ImportEntry::ElfNeededLib(lib) => format!("lib:{}", String::from_utf8_lossy(lib)),
            ImportEntry::ElfSymbol(sym) => String::from_utf8_lossy(sym).into_owned(),
            ImportEntry::PeNamed { dll_lower, func } => {
                format!("{}!{}", String::from_utf8_lossy(dll_lower), String::from_utf8_lossy(func))
            }
            ImportEntry::PeOrdinal { dll_lower, ordinal } => {
                format!("{}!#{}", String::from_utf8_lossy(dll_lower), ordinal)
            }
        }
    }
}

#[derive(Default)]
struct Findings {
    format: &'static str,
    arch: String,
    imports: BTreeSet<ImportEntry>,
    exports: BTreeSet<Vec<u8>>,
    sections: BTreeSet<Vec<u8>>,
    comments: BTreeSet<Vec<u8>>,
    rdata_strings: BTreeSet<String>,
}

// ═══════════════════════════════════════════════════════════════════════
//  ELF parser
// ═══════════════════════════════════════════════════════════════════════

fn parse_elf(data: &[u8]) -> Option<Findings> {
    if data.len() < 64 || !data.starts_with(b"\x7fELF") { return None; }
    let class = data[4]; // 1=32, 2=64
    let enc   = data[5]; // 1=LE, 2=BE
    if (class != 1 && class != 2) || (enc != 1 && enc != 2) { return None; }
    let is64  = class == 2;
    let is_le = enc == 1;

    macro_rules! rd {
        (16, $o:expr) => { if is_le { ru16(data, $o)? } else { ru16b(data, $o)? } };
        (32, $o:expr) => { if is_le { ru32(data, $o)? } else { ru32b(data, $o)? } };
        (64, $o:expr) => { if is_le { ru64(data, $o)? } else { ru64b(data, $o)? } };
    }

    let e_machine = rd!(16, 18);

    let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is64 {
        (rd!(64, 40), rd!(16, 58), rd!(16, 60), rd!(16, 62))
    } else {
        (rd!(32, 32) as u64, rd!(16, 46), rd!(16, 48), rd!(16, 50))
    };
    if e_shnum == 0 { return None; }

    let shoff_usize = usize::try_from(e_shoff).ok()?;
    let mut secs: Vec<(u32, u32, u64, u64, u64, u32)> = Vec::with_capacity(e_shnum as usize);
    for i in 0..e_shnum as usize {
        let base = shoff_usize.checked_add(i.checked_mul(e_shentsize as usize)?)?;
        let (n, t, o, sz, link, es) = if is64 {
            (
                rd!(32, base),
                rd!(32, base.checked_add(4)?),
                rd!(64, base.checked_add(24)?),
                rd!(64, base.checked_add(32)?),
                rd!(32, base.checked_add(40)?),
                rd!(64, base.checked_add(56)?),
            )
        } else {
            (
                rd!(32, base),
                rd!(32, base.checked_add(4)?),
                rd!(32, base.checked_add(16)?) as u64,
                rd!(32, base.checked_add(20)?) as u64,
                rd!(32, base.checked_add(24)?),
                rd!(32, base.checked_add(36)?) as u64,
            )
        };
        secs.push((n, t, o, sz, es, link));
    }

    let shstrndx = e_shstrndx as usize;
    let shstr_tab = secs.get(shstrndx)?;
    let shstr_data = slice(data, shstr_tab.2, shstr_tab.3)?;
    let names: Vec<Vec<u8>> = secs.iter()
        .map(|s| read_cbytes(shstr_data, s.0 as usize).unwrap_or_default())
        .collect();

    let mut f = Findings::default();
    f.format = "ELF";
    f.arch = match e_machine {
        0x03 => "x86", 0x3e => "x86_64", 0x28 => "ARM", 0xb7 => "AArch64",
        0x08 => "MIPS", 0x14 => "PowerPC", 0x16 => "S390", 0xf3 => "RISC-V",
        _ => "other",
    }.to_string();

    for n in &names {
        if !n.is_empty() { f.sections.insert(n.clone()); }
    }

    // ── .comment (compiler fingerprints) ──────────────────────────────
    for (i, name) in names.iter().enumerate() {
        if name.as_slice() == b".comment" {
            if let Some(seg) = slice(data, secs[i].2, secs[i].3) {
                for c in seg.split(|&b| b == 0) {
                    if !c.is_empty() && c.len() < 256 {
                        f.comments.insert(c.to_vec());
                    }
                }
            }
        }
    }

    // ── .dynstr & .dynamic → DT_NEEDED libraries ─────────────────────
    let dynstr_data = names.iter().position(|n| n.as_slice() == b".dynstr")
        .and_then(|i| slice(data, secs[i].2, secs[i].3));

    for (i, name) in names.iter().enumerate() {
        if name.as_slice() != b".dynamic" { continue; }
        let (off, size) = (secs[i].2, secs[i].3);
        let entsize: u64 = if is64 { 16 } else { 8 };
        let count = size / entsize;
        for j in 0..count {
            let b_u64 = off.checked_add(j.checked_mul(entsize)?)?;
            let b = usize::try_from(b_u64).ok()?;
            let tag = if is64 { rd!(64, b) } else { rd!(32, b) as u64 };
            let val = if is64 { rd!(64, b.checked_add(8)?) } else { rd!(32, b.checked_add(4)?) as u64 };
            match tag {
                0 => break, // DT_NULL
                1 => if let Some(sd) = dynstr_data { // DT_NEEDED
                    if let Some(val_usize) = usize::try_from(val).ok() {
                        if let Some(lib) = read_cbytes(sd, val_usize) {
                            f.imports.insert(ImportEntry::ElfNeededLib(lib));
                        }
                    }
                },
                _ => {}
            }
        }
    }

    // ── symbol tables ─────────────────────────────────────────────────
    for &(_, sh_type, sh_off, sh_size, sh_entsize, sh_link) in &secs {
        if sh_type != 2 && sh_type != 11 { continue; } // SYMTAB | DYNSYM
        let strtab = secs.get(sh_link as usize)?;
        let sd = slice(data, strtab.2, strtab.3)?;
        let entsize = if sh_entsize > 0 { sh_entsize } else { if is64 { 24 } else { 16 } };
        let count = sh_size / entsize;
        let (info_off, shndx_off) = if is64 { (4usize, 6usize) } else { (12, 14) };

        for k in 0..count {
            let b_u64 = sh_off.checked_add(k.checked_mul(entsize)?)?;
            let b = usize::try_from(b_u64).ok()?;
            let st_name = match rd!(32, b) { 0 => continue, n => n };
            let st_info = *data.get(b.checked_add(info_off)?)?;
            let shndx_pos = b.checked_add(shndx_off)?;
            let st_shndx = if is_le {
                ru16(data, shndx_pos).unwrap_or(0)
            } else {
                ru16b(data, shndx_pos).unwrap_or(0)
            };
            let Some(sym) = read_cbytes(sd, st_name as usize) else { continue };
            let (bind, typ) = (st_info >> 4, st_info & 0xf);
            let global = bind == 1 || bind == 2;   // GLOBAL | WEAK
            let exportable = typ == 1 || typ == 2; // OBJECT | FUNC
            if st_shndx == 0 && global {
                f.imports.insert(ImportEntry::ElfSymbol(sym));
            } else if st_shndx != 0 && global && exportable {
                f.exports.insert(sym);
            }
        }
    }

    Some(f)
}

// ═══════════════════════════════════════════════════════════════════════
//  PE parser
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct PeSection {
    name: Vec<u8>,
    vaddr: u32,
    rawsize: u32,
    rawptr: u32,
}

fn rva_to_off(secs: &[PeSection], rva: u32) -> Option<usize> {
    for s in secs {
        if rva >= s.vaddr {
            let delta = rva - s.vaddr;
            if delta < s.rawsize {
                let file_off = s.rawptr.checked_add(delta)?;
                return usize::try_from(file_off).ok();
            }
        }
    }
    None
}

fn parse_pe(data: &[u8]) -> Option<Findings> {
    if data.len() < 64 || !data.starts_with(b"MZ") { return None; }
    let pe_off = ru32(data, 0x3c)? as usize;
    if data.get(pe_off..pe_off.checked_add(4)?)? != b"PE\0\0" { return None; }

    let coff = pe_off.checked_add(4)?;
    let machine      = ru16(data, coff)?;
    let num_sections = ru16(data, coff.checked_add(2)?)? as usize;
    let opt_size     = ru16(data, coff.checked_add(16)?)? as usize;
    let opt          = coff.checked_add(20)?;
    let magic        = ru16(data, opt)?;

    let (_nrva_off, dd_off, ptr_bits) = match magic {
        0x10b => (92usize,  96usize,  32u32),
        0x20b => (108usize, 112usize, 64u32),
        _ => return None,
    };

    // ── section table ─────────────────────────────────────────────────
    let sec_tab = opt.checked_add(opt_size)?;
    let mut secs: Vec<PeSection> = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let b = sec_tab.checked_add(i.checked_mul(40)?)?;
        let nb = data.get(b..b.checked_add(8)?)?;
        let name: Vec<u8> = nb.iter().take_while(|&&c| c != 0).copied().collect();
        let vaddr   = ru32(data, b.checked_add(12)?)?;
        let rawsize = ru32(data, b.checked_add(16)?)?;
        let rawptr  = ru32(data, b.checked_add(20)?)?;
        secs.push(PeSection { name, vaddr, rawsize, rawptr });
    }

    let mut f = Findings::default();
    f.format = "PE";
    f.arch = match machine {
        0x14c => "x86", 0x8664 => "x86_64", 0xaa64 => "AArch64",
        0x1c0 => "ARM", 0x1c4 => "ARMNT", _ => "other",
    }.to_string();
    for s in &secs {
        if !s.name.is_empty() { f.sections.insert(s.name.clone()); }
    }

    // ── import directory (index 1) ────────────────────────────────────
    let imp_rva = opt.checked_add(dd_off).and_then(|o| o.checked_add(8)).and_then(|o| ru32(data, o)).unwrap_or(0);
    if imp_rva != 0 {
        if let Some(mut id_off) = rva_to_off(&secs, imp_rva) {
            const MAX_IMPORT_DLLS: usize = 16_384;
            for _ in 0..MAX_IMPORT_DLLS {
                if id_off.checked_add(20).map_or(true, |end| end > data.len()) { break; }
                let ilt  = ru32(data, id_off).unwrap_or(0);
                let name = ru32(data, id_off + 12).unwrap_or(0);
                let iat  = ru32(data, id_off + 16).unwrap_or(0);
                if ilt == 0 && name == 0 && iat == 0 { break; }

                // Canonicalize DLL name to ASCII lowercase (Windows loader is case-insensitive)
                let dll_lower: Vec<u8> = rva_to_off(&secs, name)
                    .and_then(|o| read_cbytes(data, o))
                    .map(|mut b| { b.make_ascii_lowercase(); b })
                    .unwrap_or_else(|| b"?".to_vec());

                let thunk_rva = if ilt != 0 { ilt } else { iat };
                if let Some(mut toff) = rva_to_off(&secs, thunk_rva) {
                    let sz = if ptr_bits == 64 { 8usize } else { 4usize };
                    const MAX_THUNKS: usize = 65_536;
                    for _ in 0..MAX_THUNKS {
                        let tv = if ptr_bits == 64 {
                            let Some(v) = ru64(data, toff) else { break };
                            v
                        } else {
                            let Some(v) = ru32(data, toff) else { break };
                            v as u64
                        };
                        if tv == 0 { break; }
                        let hi_bit = 1u64 << (ptr_bits - 1);
                        if tv & hi_bit == 0 {
                            if let Ok(rva32) = u32::try_from(tv & 0x7fff_ffff) {
                                if let Some(hn) = rva_to_off(&secs, rva32) {
                                    if let Some(name_off) = hn.checked_add(2) {
                                        if let Some(fname) = read_cbytes(data, name_off) {
                                            f.imports.insert(ImportEntry::PeNamed {
                                                dll_lower: dll_lower.clone(),
                                                func: fname,
                                            });
                                        }
                                    }
                                }
                            }
                        } else {
                            f.imports.insert(ImportEntry::PeOrdinal {
                                dll_lower: dll_lower.clone(),
                                ordinal: tv & 0xffff,
                            });
                        }
                        let Some(next_toff) = toff.checked_add(sz) else { break };
                        toff = next_toff;
                    }
                }
                let Some(next_id) = id_off.checked_add(20) else { break };
                id_off = next_id;
            }
        }
    }

    // ── export directory (index 0) ────────────────────────────────────
    let exp_rva = opt.checked_add(dd_off).and_then(|o| ru32(data, o)).unwrap_or(0);
    if exp_rva != 0 {
        if let Some(eo) = rva_to_off(&secs, exp_rva) {
            let n_names = eo.checked_add(24).and_then(|o| ru32(data, o)).unwrap_or(0) as usize;
            let names_rva = eo.checked_add(32).and_then(|o| ru32(data, o)).unwrap_or(0);
            if let Some(no) = rva_to_off(&secs, names_rva) {
                let capped_names = n_names.min(262_144);
                for i in 0..capped_names {
                    let Some(entry_off) = i.checked_mul(4).and_then(|x| no.checked_add(x)) else { break };
                    let Some(nr) = ru32(data, entry_off) else { break };
                    if let Some(o) = rva_to_off(&secs, nr) {
                        if let Some(n) = read_cbytes(data, o) {
                            f.exports.insert(n);
                        }
                    }
                }
            }
        }
    }

    // ── language-artifact strings in .rdata/.rodata ───────────────────
    for s in &secs {
        if s.name.as_slice() != b".rdata" && s.name.as_slice() != b".rodata" { continue; }
        let start = s.rawptr as usize;
        let end = start.saturating_add(s.rawsize as usize).min(data.len());
        if start >= end { continue; }
        for txt in extract_ascii_strings(&data[start..end], 8) {
            let lc = txt.to_lowercase();
            if lc.contains("rustc") || lc.contains("golang") || lc.contains("go.buildinfo")
                || lc.contains("msvc") || lc.contains("clang") || lc.contains("gcc ")
                || lc.contains("go1.")
            {
                f.rdata_strings.insert(txt);
            }
        }
    }

    Some(f)
}

// ═══════════════════════════════════════════════════════════════════════
//  String extraction helper
// ═══════════════════════════════════════════════════════════════════════

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            cur.push(b);
        } else {
            if cur.len() >= min_len {
                if let Ok(s) = std::str::from_utf8(&cur) {
                    out.push(s.to_string());
                }
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        if let Ok(s) = std::str::from_utf8(&cur) {
            out.push(s.to_string());
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════
//  Language fingerprinting (saturating arithmetic prevents overflow)
// ═══════════════════════════════════════════════════════════════════════

fn is_rust_legacy(s: &str) -> bool {
    s.starts_with("_ZN") && s.ends_with('E') && s.contains("17h")
}
fn is_rust_v0(s: &str) -> bool {
    s.starts_with("_RN") || (s.starts_with("_R") && s.len() > 4 && s.as_bytes()[2].is_ascii_uppercase())
}
fn is_cpp_itanium(s: &str) -> bool {
    if !s.starts_with("_Z") || s.len() < 3 { return false; }
    let c = s.as_bytes()[2];
    c.is_ascii_digit() || c.is_ascii_uppercase()
}

fn detect_language(f: &Findings) -> String {
    let mut score: Vec<(&'static str, u32)> = vec![
        ("Rust", 0), ("C++", 0), ("Go", 0), ("C", 0),
    ];
    let mut add = |lang: &'static str, v: u32| {
        if let Some(e) = score.iter_mut().find(|(l, _)| *l == lang) {
            e.1 = e.1.saturating_add(v);
        }
    };

    // 1. .comment section strings (ELF)
    for c in &f.comments {
        let lc = String::from_utf8_lossy(c).to_lowercase();
        if lc.contains("rustc")                        { add("Rust", 100); }
        if lc.contains("go1.") || lc.contains("golang") { add("Go", 100); }
        if lc.contains("clang")                        { add("C", 30); add("C++", 30); }
        if lc.contains("gnu c") || lc.contains("gcc")  { add("C", 30); add("C++", 30); }
        if lc.contains("msvc") || lc.contains("microsoft") { add("C", 20); add("C++", 20); }
    }

    // 2. Symbol mangling patterns
    let sym_strings = f.exports.iter()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .chain(f.imports.iter().map(|i| i.display()));

    for sym in sym_strings {
        if is_rust_legacy(&sym) || is_rust_v0(&sym)           { add("Rust", 40); }
        else if is_cpp_itanium(&sym)                          { add("C++", 40); }
        let lc = sym.to_lowercase();
        if lc.contains("rust_begin_unwind") || lc.contains("__rust") { add("Rust", 60); }
        if lc.contains("runtime.main") || lc.contains("runtime.goexit")
            || lc.contains("runtime.morestack")               { add("Go", 100); }
        if sym.starts_with("go.") || lc.contains("golang.")   { add("Go", 40); }
        if lc.contains("__cxa_") || lc.contains("operator new") { add("C++", 40); }
    }

    // 3. Import library dependencies
    for imp in &f.imports {
        let lc = imp.display().to_lowercase();
        if lc.contains("vcruntime") || lc.contains("msvcp") || lc.contains("ucrtbase") {
            add("C++", 15); add("Rust", 10);
        }
        if lc.contains("libstdc++") || lc.contains("libgcc_s") { add("C++", 30); }
        if lc.contains("libc.so") || lc.contains("libc.so.6")  { add("C", 5); }
        if lc.contains("libgo") || lc.contains("golang")       { add("Go", 60); }
    }

    // 4. Section names
    for s in &f.sections {
        if s.as_slice() == b".note.go.buildid" || s.as_slice() == b".gopclntab" { add("Go", 100); }
        if s.as_slice() == b".rustc"                                            { add("Rust", 100); }
    }

    // 5. Artifact strings in PE .rdata
    for s in &f.rdata_strings {
        let lc = s.to_lowercase();
        if lc.contains("rustc") || lc.contains("__rust")        { add("Rust", 60); }
        if lc.contains("go.buildinfo") || lc.contains("golang") { add("Go", 60); }
        if lc.contains("clang") || lc.contains("msvc")          { add("C++", 20); }
    }

    score.into_iter().max_by_key(|(_, v)| *v)
        .filter(|(_, v)| *v > 0)
        .map(|(l, _)| l.to_string())
        .unwrap_or_else(|| "Unknown".into())
}

// ═══════════════════════════════════════════════════════════════════════
//  Canonical, collision-resistant structural hash (TLV encoded)
// ═══════════════════════════════════════════════════════════════════════

fn structural_hash(f: &Findings, lang: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain separation tag + version
    hasher.update_len_prefixed(b"ith-structural-hash-v2");
    hasher.update_len_prefixed(f.format.as_bytes());
    hasher.update_len_prefixed(f.arch.as_bytes());
    hasher.update_len_prefixed(lang.as_bytes());

    // 1. Imports (count-prefixed, type-tagged, and length-prefixed per field)
    hasher.update_u64(f.imports.len() as u64);
    for imp in &f.imports {
        match imp {
            ImportEntry::ElfNeededLib(lib) => {
                hasher.update(&[0x01]);
                hasher.update_len_prefixed(lib);
            }
            ImportEntry::ElfSymbol(sym) => {
                hasher.update(&[0x02]);
                hasher.update_len_prefixed(sym);
            }
            ImportEntry::PeNamed { dll_lower, func } => {
                hasher.update(&[0x03]);
                hasher.update_len_prefixed(dll_lower);
                hasher.update_len_prefixed(func);
            }
            ImportEntry::PeOrdinal { dll_lower, ordinal } => {
                hasher.update(&[0x04]);
                hasher.update_len_prefixed(dll_lower);
                hasher.update_u64(*ordinal);
            }
        }
    }

    // 2. Exports (count-prefixed + length-prefixed raw bytes)
    hasher.update_u64(f.exports.len() as u64);
    for exp in &f.exports {
        hasher.update_len_prefixed(exp);
    }

    // 3. Sections (count-prefixed + length-prefixed raw bytes)
    hasher.update_u64(f.sections.len() as u64);
    for sec in &f.sections {
        hasher.update_len_prefixed(sec);
    }

    hasher.finalize()
}

// ═══════════════════════════════════════════════════════════════════════
//  main
// ═══════════════════════════════════════════════════════════════════════

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: {} <binary>", args[0]);
        process::exit(1);
    }
    let path = &args[1];
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => { eprintln!("read error: {e}"); process::exit(1); }
    };

    let findings = if data.starts_with(b"\x7fELF") {
        parse_elf(&data)
    } else if data.starts_with(b"MZ") {
        parse_pe(&data)
    } else {
        None
    };

    let f = match findings {
        Some(f) => f,
        None => { eprintln!("unrecognized or malformed binary"); process::exit(1); }
    };

    let lang = detect_language(&f);
    let h    = structural_hash(&f, &lang);
    let hex: String = h.iter().map(|b| format!("{:02x}", b)).collect();

    println!("=== Binary: {} ===", path);
    println!("Format    : {}", f.format);
    println!("Arch      : {}", f.arch);
    println!("Language  : {}", lang);
    println!("Sections  : {}", f.sections.len());
    println!("Imports   : {}", f.imports.len());
    println!("Exports   : {}", f.exports.len());
    println!();

    if !f.comments.is_empty() {
        println!("--- Compiler comments ---");
        for c in f.comments.iter().take(8) {
            println!("  {}", String::from_utf8_lossy(c));
        }
        println!();
    }
    if !f.rdata_strings.is_empty() {
        println!("--- .rdata artifacts ---");
        for c in f.rdata_strings.iter().take(5) {
            println!("  {c}");
        }
        println!();
    }

    println!("--- Imports (first 30) ---");
    for i in f.imports.iter().take(30) {
        println!("  {}", i.display());
    }
    println!();

    println!("--- Exports (first 30) ---");
    for e in f.exports.iter().take(30) {
        println!("  {}", String::from_utf8_lossy(e));
    }
    println!();

    println!("=== Structural SHA-256 ===");
    println!("{hex}");
}