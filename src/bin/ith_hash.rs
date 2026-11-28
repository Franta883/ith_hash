#![deny(unsafe_code)]

use core::hint::black_box;
use core::sync::atomic::{compiler_fence, Ordering};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const INTERNAL_HASH_HEX_LEN: usize = 128; // 512-bit internal security bound for Merkle nodes
const MIN_CHECK_HEX_LEN: usize = 64; // 256-bit minimum digest length in /check mode
const MAX_OUTPUT_HEX_LEN: usize = 1_048_576; // 1 MiB hex char DoS cap
const READ_BUF_SIZE: usize = 65_536; // 64 KB zeroizing stack read buffer
const DEFAULT_MAX_DEPTH: usize = 64; // Default directory traversal depth limit

// Standard Profile (Opt-in): c = 1024 bits (16 lanes), r = 576 bits (9 lanes / 72 bytes)
const STANDARD_RATE_WORDS: usize = 9;
const STANDARD_BLOCK: usize = STANDARD_RATE_WORDS * 8; // 72 bytes
const DOMAIN_STANDARD: u8 = 0x0A; // domain bits `10` + pad10*1 start bit `1`

// Paranoid Profile (Default): c = 1536 bits (24 lanes), r = 64 bits (1 lane / 8 bytes)
const PARANOID_RATE_WORDS: usize = 1;
const PARANOID_BLOCK: usize = PARANOID_RATE_WORDS * 8; // 8 bytes
const DOMAIN_PARANOID: u8 = 0x06; // domain bits `01` + pad10*1 start bit `1`

const COLOR_RESET: &str = "\x1b[0m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RED: &str = "\x1b[31m";
const COLOR_CYAN: &str = "\x1b[36m";
const COLOR_YELLOW: &str = "\x1b[33m";

// Standard Keccak-f[1600] 24 round constants (Iota step)
const KECCAK_RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

// 3D-indexed rotation offsets KECCAK_RHO[x][y]
const KECCAK_RHO: [[u32; 5]; 5] = [
    [ 0, 36,  3, 41, 18], // x = 0, y = 0..5
    [ 1, 44, 10, 45,  2], // x = 1, y = 0..5
    [62,  6, 43, 15, 61], // x = 2, y = 0..5
    [28, 55, 25, 21, 56], // x = 3, y = 0..5
    [27, 20, 39,  8, 14], // x = 4, y = 0..5
];

// ========================================================================
//  1. Audited Side-Channel Hygiene & Volatile Memory Zeroization
// ========================================================================
#[allow(unsafe_code)]
fn volatile_zero_u64_grid(grid: &mut [[u64; 5]; 5]) {
    for row in grid.iter_mut() {
        for lane in row.iter_mut() {
            unsafe {
                core::ptr::write_volatile(lane, 0);
            }
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[allow(unsafe_code)]
fn volatile_zero_u64_slice(slice: &mut [u64]) {
    for lane in slice.iter_mut() {
        unsafe {
            core::ptr::write_volatile(lane, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[allow(unsafe_code)]
fn volatile_zero_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Stack-allocated buffer that guarantees volatile zeroization on drop (including early `?` returns).
struct ZeroizingBuf<const N: usize>([u8; N]);

impl<const N: usize> ZeroizingBuf<N> {
    fn new() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Drop for ZeroizingBuf<N> {
    fn drop(&mut self) {
        volatile_zero_bytes(&mut self.0);
    }
}

/// Heap-allocated byte vector that guarantees volatile zeroization on drop.
struct ZeroizingVec(Vec<u8>);

impl Drop for ZeroizingVec {
    fn drop(&mut self) {
        volatile_zero_bytes(&mut self.0);
    }
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff = black_box(diff | black_box(x ^ y));
    }
    black_box(diff) == 0
}

// ========================================================================
//  2. Hardened 3D Keccak-f[1600] Permutation (Theta, Rho, Pi, Chi, Iota)
// ========================================================================
fn permute_state(state: &mut [[u64; 5]; 5]) {
    let mut c = [0u64; 5];
    let mut b = [[0u64; 5]; 5];

    for round in 0..24 {
        // Theta (θ): Column parity mixing & 1-bit z-rotation
        for x in 0..5 {
            c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x][y] ^= d;
            }
        }

        // Rho (ρ) & Pi (π): Z-axis rotation and transverse plane permutation
        for x in 0..5 {
            for y in 0..5 {
                b[y][(2 * x + 3 * y) % 5] = state[x][y].rotate_left(KECCAK_RHO[x][y]);
            }
        }

        // Chi (χ): Row-wise non-linear degree-2 mapping
        for x in 0..5 {
            for y in 0..5 {
                state[x][y] = b[x][y] ^ ((!b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
            }
        }

        // Iota (ι): Round constant injection into lane (0, 0)
        state[0][0] ^= KECCAK_RC[round];
    }

    volatile_zero_u64_slice(&mut c);
    volatile_zero_u64_grid(&mut b);
}

// ========================================================================
//  3. Stateful Sponge Engine with Strict Capacity Isolation & Phase Lock
// ========================================================================
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Paranoid,
    Standard,
}

impl Profile {
    pub fn from_str(mode: &str) -> Self {
        if mode.eq_ignore_ascii_case("standard") {
            Profile::Standard
        } else {
            Profile::Paranoid
        }
    }

    #[inline]
    pub const fn rate_words(self) -> usize {
        match self {
            Profile::Paranoid => PARANOID_RATE_WORDS,
            Profile::Standard => STANDARD_RATE_WORDS,
        }
    }

    #[inline]
    pub const fn rate_bytes(self) -> usize {
        match self {
            Profile::Paranoid => PARANOID_BLOCK,
            Profile::Standard => STANDARD_BLOCK,
        }
    }

    #[inline]
    pub const fn domain_suffix(self) -> u8 {
        match self {
            Profile::Paranoid => DOMAIN_PARANOID,
            Profile::Standard => DOMAIN_STANDARD,
        }
    }
}

pub struct IthHasher {
    state: [[u64; 5]; 5],
    buffer: [u8; STANDARD_BLOCK],
    buf_len: usize,
    squeeze_offset: usize,
    rate_words: usize,
    rate_bytes: usize,
    domain_suffix: u8,
    finalized: bool,
}

impl IthHasher {
    pub fn new(profile: Profile) -> Self {
        Self {
            state: [[0u64; 5]; 5],
            buffer: [0u8; STANDARD_BLOCK],
            buf_len: 0,
            squeeze_offset: 0,
            rate_words: profile.rate_words(),
            rate_bytes: profile.rate_bytes(),
            domain_suffix: profile.domain_suffix(),
            finalized: false,
        }
    }

    #[inline]
    fn absorb_rate_block(&mut self, block: &[u8]) {
        // Strict capacity isolation: only touch the first `rate_words` lanes
        // mapped via x = i % 5, y = i / 5
        let mut word_bytes = ZeroizingBuf::<8>::new();
        for i in 0..self.rate_words {
            let start = i * 8;
            word_bytes.0.copy_from_slice(&block[start..start + 8]);
            let x = i % 5;
            let y = i / 5;
            self.state[x][y] ^= u64::from_le_bytes(word_bytes.0);
        }
        drop(word_bytes);
        permute_state(&mut self.state);
    }

    #[inline]
    fn extract_rate_block(&mut self) {
        // Strict capacity isolation: read only from the first `rate_words` lanes
        let mut word_bytes = ZeroizingBuf::<8>::new();
        for i in 0..self.rate_words {
            let x = i % 5;
            let y = i / 5;
            word_bytes.0 = self.state[x][y].to_le_bytes();
            let start = i * 8;
            self.buffer[start..start + 8].copy_from_slice(&word_bytes.0);
        }
        self.squeeze_offset = 0;
    }

    pub fn try_absorb(&mut self, mut data: &[u8]) -> Result<(), &'static str> {
        if self.finalized {
            return Err("Sponge phase violation: cannot call absorb() after squeeze() has started");
        }

        while !data.is_empty() {
            let space = self.rate_bytes - self.buf_len;
            if self.buf_len == 0 && data.len() >= self.rate_bytes {
                self.absorb_rate_block(&data[..self.rate_bytes]);
                data = &data[self.rate_bytes..];
            } else {
                let take = data.len().min(space);
                self.buffer[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
                self.buf_len += take;
                data = &data[take..];

                if self.buf_len == self.rate_bytes {
                    let mut local_block = ZeroizingBuf::<STANDARD_BLOCK>::new();
                    local_block.0[..self.rate_bytes]
                        .copy_from_slice(&self.buffer[..self.rate_bytes]);
                    self.absorb_rate_block(&local_block.0[..self.rate_bytes]);
                    self.buf_len = 0;
                }
            }
        }
        Ok(())
    }

    pub fn absorb(&mut self, data: &[u8]) {
        if let Err(msg) = self.try_absorb(data) {
            panic!("{}", msg);
        }
    }

    fn finalize_absorb(&mut self) {
        let pad_len = self.rate_bytes - self.buf_len;
        if pad_len == 1 {
            self.buffer[self.buf_len] = self.domain_suffix | 0x80;
        } else {
            self.buffer[self.buf_len] = self.domain_suffix;
            for b in &mut self.buffer[self.buf_len + 1..self.rate_bytes - 1] {
                *b = 0x00;
            }
            self.buffer[self.rate_bytes - 1] = 0x80;
        }

        let mut final_block = ZeroizingBuf::<STANDARD_BLOCK>::new();
        final_block.0[..self.rate_bytes].copy_from_slice(&self.buffer[..self.rate_bytes]);
        self.absorb_rate_block(&final_block.0[..self.rate_bytes]);

        self.buf_len = 0;
        self.finalized = true;
        self.extract_rate_block();
    }

    pub fn squeeze(&mut self, output: &mut [u8]) {
        if !self.finalized {
            self.finalize_absorb();
        }

        let mut out_pos = 0;
        while out_pos < output.len() {
            if self.squeeze_offset == self.rate_bytes {
                permute_state(&mut self.state);
                self.extract_rate_block();
            }
            let available = self.rate_bytes - self.squeeze_offset;
            let need = output.len() - out_pos;
            let take = available.min(need);

            output[out_pos..out_pos + take]
                .copy_from_slice(&self.buffer[self.squeeze_offset..self.squeeze_offset + take]);
            self.squeeze_offset += take;
            out_pos += take;
        }
    }

    pub fn squeeze_hex(&mut self, target_char_len: usize) -> String {
        assert!(
            target_char_len <= MAX_OUTPUT_HEX_LEN,
            "Requested output length {} exceeds maximum allowed ({} hex chars)",
            target_char_len,
            MAX_OUTPUT_HEX_LEN
        );

        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

        let target_byte_len = (target_char_len + 1) / 2;
        let mut output_bytes = ZeroizingVec(vec![0u8; target_byte_len]);
        self.squeeze(&mut output_bytes.0);

        let mut hex_bytes = Vec::with_capacity(target_char_len);
        for &byte in &output_bytes.0 {
            hex_bytes.push(HEX_CHARS[(byte >> 4) as usize]);
            if hex_bytes.len() < target_char_len {
                hex_bytes.push(HEX_CHARS[(byte & 0x0f) as usize]);
            }
        }
        drop(output_bytes);

        String::from_utf8(hex_bytes).expect("HEX_CHARS produces valid ASCII UTF-8")
    }
}

impl Drop for IthHasher {
    fn drop(&mut self) {
        volatile_zero_u64_grid(&mut self.state);
        volatile_zero_bytes(&mut self.buffer);
    }
}

// ========================================================================
//  4. High-Level Byte & File XOF Helpers
// ========================================================================
pub fn hash_bytes_xof(mode: &str, payload_bytes: &[u8], char_len: usize) -> String {
    let mut hasher = IthHasher::new(Profile::from_str(mode));
    hasher.absorb(payload_bytes);
    hasher.squeeze_hex(char_len)
}

fn read_full<R: Read + ?Sized>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total_read = 0;
    while total_read < buf.len() {
        match reader.read(&mut buf[total_read..]) {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total_read)
}

/// Hashes a file using a 64 KB zeroizing stack buffer fed in `BLOCK_SIZE_BYTES` sponge chunks.
/// Returns `(hex_digest, actual_bytes_hashed)`.
pub fn get_internal_tools_xof<
    const RATE_WORDS: usize,
    const BLOCK_SIZE_BYTES: usize,
    P: AsRef<Path>,
>(
    file_path: P,
    target_char_len: usize,
) -> io::Result<(String, u64)> {
    if target_char_len > MAX_OUTPUT_HEX_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Requested output length {} exceeds maximum allowed ({} hex chars)",
                target_char_len, MAX_OUTPUT_HEX_LEN
            ),
        ));
    }

    let profile = if RATE_WORDS == STANDARD_RATE_WORDS {
        Profile::Standard
    } else {
        Profile::Paranoid
    };

    let mut hasher = IthHasher::new(profile);
    let mut file = File::open(file_path)?;
    let mut read_buf = ZeroizingBuf::<READ_BUF_SIZE>::new();
    let mut bytes_hashed: u64 = 0;

    loop {
        let bytes_read = read_full(&mut file, &mut read_buf.0)?;
        if bytes_read == 0 {
            break;
        }
        bytes_hashed = bytes_hashed.checked_add(bytes_read as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Hashed byte counter overflowed u64")
        })?;

        for chunk in read_buf.0[..bytes_read].chunks(BLOCK_SIZE_BYTES) {
            hasher.absorb(chunk);
        }

        if bytes_read < READ_BUF_SIZE {
            break;
        }
    }

    drop(read_buf);
    Ok((hasher.squeeze_hex(target_char_len), bytes_hashed))
}

fn run_hash(mode: &str, file_path: &Path, char_len: usize) -> io::Result<(String, u64)> {
    if Profile::from_str(mode) == Profile::Standard {
        get_internal_tools_xof::<STANDARD_RATE_WORDS, STANDARD_BLOCK, _>(file_path, char_len)
    } else {
        get_internal_tools_xof::<PARANOID_RATE_WORDS, PARANOID_BLOCK, _>(file_path, char_len)
    }
}

// ========================================================================
//  5. Hardened Iterative Directory Traversal & Merkle Tree
// ========================================================================
/// Encodes path components unambiguously without normalizing separators or losing non-UTF-8 bytes:
/// `[component_count: u64 LE] ([component_len: u64 LE][raw_os_str_bytes])*`
fn encode_path_components(path: &Path, out: &mut Vec<u8>) {
    let components: Vec<_> = path.components().collect();
    out.extend_from_slice(&(components.len() as u64).to_le_bytes());
    for comp in components {
        let bytes = comp.as_os_str().as_encoded_bytes();
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(bytes);
    }
}

fn special_file_type_label(_ft: &fs::FileType) -> &'static str {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if ft.is_fifo() {
            return "fifo";
        }
        if ft.is_socket() {
            return "socket";
        }
        if ft.is_block_device() {
            return "block_device";
        }
        if ft.is_char_device() {
            return "char_device";
        }
    }
    "other"
}

struct DirStats {
    file_count: usize,
    dir_count: usize,
    symlink_count: usize,
    special_count: usize,
    total_size: u64,
}

enum WorkItem {
    Dir { path: PathBuf, depth: usize },
    Entry { entry: fs::DirEntry, depth: usize },
}

fn collect_directory_entries(
    root_dir: &Path,
    mode: &str,
    max_depth: usize,
    stats: &mut DirStats,
    entries_out: &mut Vec<String>,
) -> io::Result<()> {
    let mut stack = vec![WorkItem::Dir {
        path: root_dir.to_path_buf(),
        depth: 0,
    }];

    while let Some(item) = stack.pop() {
        match item {
            WorkItem::Dir { path, depth } => {
                let mut sorted_entries = Vec::new();
                for entry in fs::read_dir(&path)? {
                    sorted_entries.push(entry?);
                }
                sorted_entries.sort_by(|a, b| {
                    a.file_name()
                        .as_encoded_bytes()
                        .cmp(b.file_name().as_encoded_bytes())
                });

                // Push in reverse order so LIFO pop preserves deterministic lexicographical DFS order.
                for entry in sorted_entries.into_iter().rev() {
                    stack.push(WorkItem::Entry { entry, depth });
                }
            }
            WorkItem::Entry { entry, depth } => {
                let path = entry.path();
                let file_type = entry.file_type()?;
                let rel_path = path.strip_prefix(root_dir).unwrap_or(&path);

                let mut record = Vec::new();

                if file_type.is_symlink() {
                    stats.symlink_count += 1;
                    record.extend_from_slice(b"SYMLINK:");
                    encode_path_components(rel_path, &mut record);

                    match fs::read_link(&path) {
                        Ok(target) => {
                            let target_bytes = target.as_os_str().as_encoded_bytes();
                            record.extend_from_slice(b"TARGET:");
                            record.extend_from_slice(&(target_bytes.len() as u64).to_le_bytes());
                            record.extend_from_slice(target_bytes);
                        }
                        Err(err) => {
                            eprintln!(
                                "{}Warning: unreadable symlink '{}': {}{}",
                                COLOR_YELLOW,
                                path.display(),
                                err,
                                COLOR_RESET
                            );
                            record.extend_from_slice(b"ERROR:");
                            if let Some(errno) = err.raw_os_error() {
                                record.extend_from_slice(b"ERRNO:");
                                record.extend_from_slice(&errno.to_le_bytes());
                            } else {
                                let kind_str = format!("{:?}", err.kind());
                                record.extend_from_slice(b"KIND:");
                                record.extend_from_slice(&(kind_str.len() as u64).to_le_bytes());
                                record.extend_from_slice(kind_str.as_bytes());
                            }
                        }
                    }

                    entries_out.push(hash_bytes_xof(mode, &record, INTERNAL_HASH_HEX_LEN));
                } else if file_type.is_dir() {
                    stats.dir_count += 1;
                    record.extend_from_slice(b"DIR:");
                    encode_path_components(rel_path, &mut record);
                    entries_out.push(hash_bytes_xof(mode, &record, INTERNAL_HASH_HEX_LEN));

                    if depth >= max_depth {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!(
                                "Maximum directory traversal depth ({}) exceeded at '{}'",
                                max_depth,
                                path.display()
                            ),
                        ));
                    }

                    stack.push(WorkItem::Dir {
                        path,
                        depth: depth + 1,
                    });
                } else if file_type.is_file() {
                    stats.file_count += 1;
                    let (content_hash, bytes_hashed) = run_hash(mode, &path, INTERNAL_HASH_HEX_LEN)?;
                    stats.total_size = stats.total_size.checked_add(bytes_hashed).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "Total size overflowed u64")
                    })?;

                    record.extend_from_slice(b"FILE:");
                    encode_path_components(rel_path, &mut record);
                    record.extend_from_slice(&bytes_hashed.to_le_bytes());
                    record.extend_from_slice(content_hash.as_bytes());
                    entries_out.push(hash_bytes_xof(mode, &record, INTERNAL_HASH_HEX_LEN));
                } else {
                    stats.special_count += 1;
                    let kind_label = special_file_type_label(&file_type);
                    eprintln!(
                        "{}Warning: special file ({}) encountered at '{}'{}",
                        COLOR_YELLOW,
                        kind_label,
                        path.display(),
                        COLOR_RESET
                    );

                    record.extend_from_slice(b"SPECIAL:");
                    encode_path_components(rel_path, &mut record);
                    record.extend_from_slice(&(kind_label.len() as u64).to_le_bytes());
                    record.extend_from_slice(kind_label.as_bytes());
                    entries_out.push(hash_bytes_xof(mode, &record, INTERNAL_HASH_HEX_LEN));
                }
            }
        }
    }

    Ok(())
}

fn compute_merkle_root(mode: &str, mut hashes: Vec<String>, final_char_len: usize) -> String {
    if hashes.is_empty() {
        return hash_bytes_xof(mode, b"MERKLE_EMPTY_TREE", final_char_len);
    }

    // Always domain-separate 1-entry directories with NODE_ODD: + ROOT_FINAL:
    if hashes.len() == 1 {
        let single_combined = format!("NODE_ODD:{}", hashes.remove(0));
        let single_node = hash_bytes_xof(mode, single_combined.as_bytes(), INTERNAL_HASH_HEX_LEN);
        let root_payload = format!("ROOT_FINAL:{}", single_node);
        return hash_bytes_xof(mode, root_payload.as_bytes(), final_char_len);
    }

    while hashes.len() > 1 {
        let mut next_level = Vec::with_capacity((hashes.len() + 1) / 2);
        for chunk in hashes.chunks(2) {
            if chunk.len() == 2 {
                let combined = format!("NODE:{}:{}", chunk[0], chunk[1]);
                next_level.push(hash_bytes_xof(
                    mode,
                    combined.as_bytes(),
                    INTERNAL_HASH_HEX_LEN,
                ));
            } else {
                let combined = format!("NODE_ODD:{}", chunk[0]);
                next_level.push(hash_bytes_xof(
                    mode,
                    combined.as_bytes(),
                    INTERNAL_HASH_HEX_LEN,
                ));
            }
        }
        hashes = next_level;
    }

    let root = hashes.remove(0);
    let root_payload = format!("ROOT_FINAL:{}", root);
    hash_bytes_xof(mode, root_payload.as_bytes(), final_char_len)
}

// ========================================================================
//  6. Strict CLI Parser & Verification
// ========================================================================
fn is_valid_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_prefixed_usize(lower: &str, prefixes: &[&str]) -> Option<Result<usize, String>> {
    for prefix in prefixes {
        if let Some(rest) = lower.strip_prefix(prefix) {
            return Some(
                rest.parse::<usize>()
                    .map_err(|_| format!("invalid numeric value for '{}': '{}'", prefix, rest)),
            );
        }
    }
    None
}

fn print_usage() {
    println!("--- ITH-XOF Cryptographic Hash Engine (Hardened 3D Sponge) ---");
    println!("Usage:");
    println!("  ith_hash [flags] [--] <file_path> [output_length]");
    println!("  ith_hash [flags] /folder [/usemerkletree] [--] <dir_path> [output_length]");
    println!();
    println!("Verification:");
    println!("  ith_hash [flags] /check [--] <path> <expected_hash>");
    println!();
    println!("Flags:");
    println!("  /paranoid | /standard : profile (default: /paranoid, c=1536, r=64; /standard: c=1024, r=576)");
    println!("  /folder               : hash directory contents");
    println!("  /usemerkletree        : compute Merkle root (requires /folder)");
    println!("  /check                : verify <path> against <expected_hash> (strict positional order)");
    println!("  /len:<N>              : explicit output/expected hex length (1..={}, min {} in /check)", MAX_OUTPUT_HEX_LEN, MIN_CHECK_HEX_LEN);
    println!("  /maxdepth:<N>         : max directory traversal depth (default: {})", DEFAULT_MAX_DEPTH);
    println!("  --                    : end of flags; treat all remaining arguments as positional");
}

fn verify_or_print(computed: &str, check_mode: bool, expected_hash: Option<String>) {
    if check_mode {
        let expected = match expected_hash {
            Some(h) => h,
            None => {
                eprintln!(
                    "{}Error: no expected hash provided for /check.{}",
                    COLOR_RED, COLOR_RESET
                );
                std::process::exit(1);
            }
        };

        if constant_time_eq(computed.as_bytes(), expected.as_bytes()) {
            println!("{} [OK] Hash matches! {}{}", COLOR_GREEN, computed, COLOR_RESET);
        } else {
            eprintln!("{} [FAIL] Hash mismatch! {}", COLOR_RED, COLOR_RESET);
            eprintln!("{}Expected: {}{}", COLOR_CYAN, expected, COLOR_RESET);
            eprintln!("{}Computed: {}{}", COLOR_RED, computed, COLOR_RESET);
            std::process::exit(1);
        }
    } else {
        println!("{}", computed);
    }
}

fn main() {
    let raw_args: Vec<OsString> = env::args_os().skip(1).collect();
    if raw_args.is_empty() {
        print_usage();
        return;
    }

    // Default to Paranoid profile; Standard is opt-in
    let mut mode: &str = "paranoid";
    let mut folder_mode = false;
    let mut merkle_mode = false;
    let mut check_mode = false;
    let mut explicit_len: Option<usize> = None;
    let mut max_depth: usize = DEFAULT_MAX_DEPTH;
    let mut end_of_flags = false;
    let mut positional: Vec<OsString> = Vec::new();

    for arg in raw_args {
        if !end_of_flags {
            if let Some(s) = arg.to_str() {
                if s == "--" {
                    end_of_flags = true;
                    continue;
                }

                let lower = s.to_ascii_lowercase();
                match lower.as_str() {
                    "/standard" | "--standard" | "-standard" => {
                        mode = "standard";
                        continue;
                    }
                    "/paranoid" | "--paranoid" | "-paranoid" => {
                        mode = "paranoid";
                        continue;
                    }
                    "/folder" | "--folder" | "-folder" => {
                        folder_mode = true;
                        continue;
                    }
                    "/usemerkletree" | "--usemerkletree" | "-usemerkletree" => {
                        merkle_mode = true;
                        continue;
                    }
                    "/check" | "--check" | "-check" => {
                        check_mode = true;
                        continue;
                    }
                    _ => {}
                }

                if let Some(parsed) = parse_prefixed_usize(
                    &lower,
                    &["/len:", "--len:", "-len:", "/len=", "--len=", "-len="],
                ) {
                    match parsed {
                        Ok(n) if (1..=MAX_OUTPUT_HEX_LEN).contains(&n) => {
                            explicit_len = Some(n);
                            continue;
                        }
                        Ok(n) => {
                            eprintln!(
                                "{}Error: /len must be between 1 and {} (got {}).{}",
                                COLOR_RED, MAX_OUTPUT_HEX_LEN, n, COLOR_RESET
                            );
                            std::process::exit(1);
                        }
                        Err(msg) => {
                            eprintln!("{}Error: {}{}", COLOR_RED, msg, COLOR_RESET);
                            std::process::exit(1);
                        }
                    }
                }

                if let Some(parsed) = parse_prefixed_usize(
                    &lower,
                    &[
                        "/maxdepth:",
                        "--maxdepth:",
                        "-maxdepth:",
                        "/maxdepth=",
                        "--maxdepth=",
                        "-maxdepth=",
                    ],
                ) {
                    match parsed {
                        Ok(n) => {
                            max_depth = n;
                            continue;
                        }
                        Err(msg) => {
                            eprintln!("{}Error: {}{}", COLOR_RED, msg, COLOR_RESET);
                            std::process::exit(1);
                        }
                    }
                }
            }
        }

        positional.push(arg);
    }

    if merkle_mode && !folder_mode {
        eprintln!(
            "{}Error: /usemerkletree can only be used with /folder.{}",
            COLOR_RED, COLOR_RESET
        );
        std::process::exit(1);
    }

    let target_path: PathBuf;
    let expected_hash: Option<String>;
    let char_len: usize;

    if check_mode {
        // Strict positional order: <path> <expected_hash>
        if positional.len() != 2 {
            eprintln!(
                "{}Error: /check requires exact positional arguments: <path> <expected_hash>{}",
                COLOR_RED, COLOR_RESET
            );
            print_usage();
            std::process::exit(1);
        }

        target_path = PathBuf::from(&positional[0]);
        let expected_str = match positional[1].to_str() {
            Some(s) => s,
            None => {
                eprintln!(
                    "{}Error: expected hash in /check must be valid UTF-8 ASCII hex.{}",
                    COLOR_RED, COLOR_RESET
                );
                std::process::exit(1);
            }
        };

        if !is_valid_hex(expected_str) {
            eprintln!(
                "{}Error: expected hash in /check must contain only hexadecimal characters.{}",
                COLOR_RED, COLOR_RESET
            );
            std::process::exit(1);
        }

        if expected_str.len() < MIN_CHECK_HEX_LEN {
            eprintln!(
                "{}Error: /check requires a hash of at least {} hex characters ({} bits) to prevent truncation downgrades.{}",
                COLOR_RED,
                MIN_CHECK_HEX_LEN,
                MIN_CHECK_HEX_LEN * 4,
                COLOR_RESET
            );
            std::process::exit(1);
        }

        if expected_str.len() > MAX_OUTPUT_HEX_LEN {
            eprintln!(
                "{}Error: expected hash length ({}) exceeds maximum allowed ({} hex chars).{}",
                COLOR_RED,
                expected_str.len(),
                MAX_OUTPUT_HEX_LEN,
                COLOR_RESET
            );
            std::process::exit(1);
        }

        if let Some(req_len) = explicit_len {
            if req_len < MIN_CHECK_HEX_LEN {
                eprintln!(
                    "{}Error: /len in /check mode must be at least {} hex characters ({} bits).{}",
                    COLOR_RED,
                    MIN_CHECK_HEX_LEN,
                    MIN_CHECK_HEX_LEN * 4,
                    COLOR_RESET
                );
                std::process::exit(1);
            }
            if expected_str.len() != req_len {
                eprintln!(
                    "{}Error: expected hash length ({}) does not match explicit /len:{} requirement.{}",
                    COLOR_RED,
                    expected_str.len(),
                    req_len,
                    COLOR_RESET
                );
                std::process::exit(1);
            }
            char_len = req_len;
        } else {
            char_len = expected_str.len();
        }

        expected_hash = Some(expected_str.to_ascii_lowercase());
    } else {
        if positional.is_empty() || positional.len() > 2 {
            eprintln!(
                "{}Error: expected <path> [output_length] (got {} positional arguments).{}",
                COLOR_RED,
                positional.len(),
                COLOR_RESET
            );
            print_usage();
            std::process::exit(1);
        }

        // First positional argument is always <path>, even if numeric (e.g., "12345" or "2026").
        target_path = PathBuf::from(&positional[0]);
        expected_hash = None;

        if positional.len() == 2 {
            if explicit_len.is_some() {
                eprintln!(
                    "{}Error: output length specified both via /len and positional argument.{}",
                    COLOR_RED, COLOR_RESET
                );
                std::process::exit(1);
            }

            let len_arg = &positional[1];
            let parsed_len = len_arg
                .to_str()
                .and_then(|s| s.parse::<usize>().ok());

            match parsed_len {
                Some(n) if (1..=MAX_OUTPUT_HEX_LEN).contains(&n) => char_len = n,
                Some(n) => {
                    eprintln!(
                        "{}Error: output_length must be between 1 and {} (got {}).{}",
                        COLOR_RED, MAX_OUTPUT_HEX_LEN, n, COLOR_RESET
                    );
                    std::process::exit(1);
                }
                None => {
                    eprintln!(
                        "{}Error: invalid output_length '{}'. Use /len:<N> or a positive integer.{}",
                        COLOR_RED,
                        Path::new(len_arg).display(),
                        COLOR_RESET
                    );
                    std::process::exit(1);
                }
            }
        } else {
            char_len = explicit_len.unwrap_or(64);
        }
    }

    if folder_mode {
        if !target_path.is_dir() {
            eprintln!(
                "{}Error: not a valid directory: {}{}",
                COLOR_RED,
                target_path.display(),
                COLOR_RESET
            );
            std::process::exit(1);
        }

        let mut stats = DirStats {
            file_count: 0,
            dir_count: 0,
            symlink_count: 0,
            special_count: 0,
            total_size: 0,
        };
        let mut leaf_hashes = Vec::new();

        if let Err(e) =
            collect_directory_entries(&target_path, mode, max_depth, &mut stats, &mut leaf_hashes)
        {
            eprintln!("{}Error scanning directory: {}{}", COLOR_RED, e, COLOR_RESET);
            std::process::exit(1);
        }

        let digest = if merkle_mode {
            compute_merkle_root(mode, leaf_hashes, char_len)
        } else {
            let mut manifest = format!(
                "MANIFEST:{}:{}:{}:{}:{}\n",
                stats.file_count,
                stats.dir_count,
                stats.symlink_count,
                stats.special_count,
                stats.total_size
            );
            for h in &leaf_hashes {
                manifest.push_str(h);
                manifest.push('\n');
            }
            hash_bytes_xof(mode, manifest.as_bytes(), char_len)
        };

        if !check_mode {
            let label = if merkle_mode {
                "Directory Merkle Root Hash"
            } else {
                "Directory Content Hash"
            };
            println!("=== {}: {} ===", label, target_path.display());
            println!(
                "Files: {}, Folders: {}, Symlinks: {}, Special: {}, Total size: {} bytes",
                stats.file_count,
                stats.dir_count,
                stats.symlink_count,
                stats.special_count,
                stats.total_size
            );
        }

        verify_or_print(&digest, check_mode, expected_hash);
        return;
    }

    if !target_path.is_file() {
        eprintln!(
            "{}Error: file not found: {}{}",
            COLOR_RED,
            target_path.display(),
            COLOR_RESET
        );
        std::process::exit(1);
    }

    match run_hash(mode, &target_path, char_len) {
        Ok((computed, _bytes_hashed)) => verify_or_print(&computed, check_mode, expected_hash),
        Err(e) => {
            eprintln!("{}Error reading target file: {}{}", COLOR_RED, e, COLOR_RESET);
            std::process::exit(1);
        }
    }
}