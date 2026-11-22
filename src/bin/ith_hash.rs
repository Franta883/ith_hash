#![deny(unsafe_code)]

use core::sync::atomic::{compiler_fence, Ordering};
use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

const INTERNAL_HASH_HEX_LEN: usize = 128; // 512-bit internal security bound for Merkle nodes

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
fn volatile_zero_bytes(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[allow(unsafe_code)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // Prevent compiler from turning bitwise accumulation into a branch
    unsafe { core::ptr::read_volatile(&diff) == 0 }
}

// ========================================================================
//  2. Hardened 3D Keccak-f[1600] Permutation (Theta, Rho, Pi, Chi, Iota)
// ========================================================================
fn permute_state(state: &mut [[u64; 5]; 5]) {
    for round in 0..24 {
        // Theta (θ): Column parity mixing & 1-bit z-rotation
        let mut c = [0u64; 5];
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
        let mut b = [[0u64; 5]; 5];
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
        for i in 0..self.rate_words {
            let start = i * 8;
            let mut word_bytes = [0u8; 8];
            word_bytes.copy_from_slice(&block[start..start + 8]);
            let x = i % 5;
            let y = i / 5;
            self.state[x][y] ^= u64::from_le_bytes(word_bytes);
        }
        permute_state(&mut self.state);
    }

    #[inline]
    fn extract_rate_block(&mut self) {
        // Strict capacity isolation: read only from the first `rate_words` lanes
        for i in 0..self.rate_words {
            let x = i % 5;
            let y = i / 5;
            let word_bytes = self.state[x][y].to_le_bytes();
            let start = i * 8;
            self.buffer[start..start + 8].copy_from_slice(&word_bytes);
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
                    let mut local_block = [0u8; STANDARD_BLOCK];
                    local_block[..self.rate_bytes].copy_from_slice(&self.buffer[..self.rate_bytes]);
                    self.absorb_rate_block(&local_block[..self.rate_bytes]);
                    volatile_zero_bytes(&mut local_block);
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

        let mut final_block = [0u8; STANDARD_BLOCK];
        final_block[..self.rate_bytes].copy_from_slice(&self.buffer[..self.rate_bytes]);
        self.absorb_rate_block(&final_block[..self.rate_bytes]);
        volatile_zero_bytes(&mut final_block);

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
        let target_byte_len = (target_char_len + 1) / 2;
        let mut output_bytes = vec![0u8; target_byte_len];
        self.squeeze(&mut output_bytes);

        let mut digest = String::with_capacity(target_char_len);
        for &byte in &output_bytes {
            digest.push_str(&format!("{:02x}", byte));
        }
        volatile_zero_bytes(&mut output_bytes);
        digest.truncate(target_char_len);
        digest
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

pub fn get_internal_tools_xof<
    const RATE_WORDS: usize,
    const BLOCK_SIZE_BYTES: usize,
    P: AsRef<Path>,
>(
    file_path: P,
    target_char_len: usize,
) -> io::Result<String> {
    let profile = if RATE_WORDS == STANDARD_RATE_WORDS {
        Profile::Standard
    } else {
        Profile::Paranoid
    };

    let mut hasher = IthHasher::new(profile);
    let mut file = File::open(file_path)?;
    let mut buffer = [0u8; BLOCK_SIZE_BYTES];

    loop {
        let bytes_read = read_full(&mut file, &mut buffer[..])?;
        if bytes_read == 0 {
            break;
        }
        hasher.absorb(&buffer[..bytes_read]);
        if bytes_read < BLOCK_SIZE_BYTES {
            break;
        }
    }

    volatile_zero_bytes(&mut buffer);
    Ok(hasher.squeeze_hex(target_char_len))
}

fn run_hash(mode: &str, file_path: &str, char_len: usize) -> io::Result<String> {
    if Profile::from_str(mode) == Profile::Standard {
        get_internal_tools_xof::<STANDARD_RATE_WORDS, STANDARD_BLOCK, _>(file_path, char_len)
    } else {
        get_internal_tools_xof::<PARANOID_RATE_WORDS, PARANOID_BLOCK, _>(file_path, char_len)
    }
}

// ========================================================================
//  5. Hardened Directory Traversal & Merkle Tree (Length-Prefixed)
// ========================================================================
fn collect_directory_entries(
    dir: &Path,
    base_dir: &Path,
    mode: &str,
    file_count: &mut usize,
    dir_count: &mut usize,
    symlink_count: &mut usize,
    total_size: &mut u64,
    entries_out: &mut Vec<String>,
) -> io::Result<()> {
    let mut sorted_entries = Vec::new();
    for entry in fs::read_dir(dir)? {
        sorted_entries.push(entry?);
    }
    sorted_entries.sort_by_key(|e| e.path());

    for entry in sorted_entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        let rel_path = path
            .strip_prefix(base_dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");

        if file_type.is_symlink() {
            *symlink_count += 1;
            let target = fs::read_link(&path)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| "<unreadable>".to_string());
            let record = format!(
                "SYMLINK:{}:{}:{}:{}",
                rel_path.len(),
                rel_path,
                target.len(),
                target
            );
            entries_out.push(hash_bytes_xof(mode, record.as_bytes(), INTERNAL_HASH_HEX_LEN));
        } else if file_type.is_dir() {
            *dir_count += 1;
            let record = format!("DIR:{}:{}", rel_path.len(), rel_path);
            entries_out.push(hash_bytes_xof(mode, record.as_bytes(), INTERNAL_HASH_HEX_LEN));
            collect_directory_entries(
                &path,
                base_dir,
                mode,
                file_count,
                dir_count,
                symlink_count,
                total_size,
                entries_out,
            )?;
        } else if file_type.is_file() {
            *file_count += 1;
            let meta = entry.metadata()?;
            let size = meta.len();
            *total_size += size;

            let path_str = path.to_string_lossy();
            let content_hash = run_hash(mode, &path_str, INTERNAL_HASH_HEX_LEN)?;
            let record = format!("FILE:{}:{}:{}:{}", rel_path.len(), rel_path, size, content_hash);
            entries_out.push(hash_bytes_xof(mode, record.as_bytes(), INTERNAL_HASH_HEX_LEN));
        }
    }
    Ok(())
}

fn compute_merkle_root(mode: &str, mut hashes: Vec<String>, final_char_len: usize) -> String {
    if hashes.is_empty() {
        return hash_bytes_xof(mode, b"MERKLE_EMPTY_TREE", final_char_len);
    }

    while hashes.len() > 1 {
        let mut next_level = Vec::with_capacity((hashes.len() + 1) / 2);
        let is_last_level = hashes.len() <= 2;
        let target_len = if is_last_level {
            final_char_len
        } else {
            INTERNAL_HASH_HEX_LEN
        };

        for chunk in hashes.chunks(2) {
            if chunk.len() == 2 {
                let combined = format!("NODE:{}:{}", chunk[0], chunk[1]);
                next_level.push(hash_bytes_xof(mode, combined.as_bytes(), target_len));
            } else {
                let combined = format!("NODE_ODD:{}", chunk[0]);
                next_level.push(hash_bytes_xof(mode, combined.as_bytes(), target_len));
            }
        }
        hashes = next_level;
    }

    let root = hashes.remove(0);
    if root.len() == final_char_len {
        root
    } else {
        hash_bytes_xof(
            mode,
            format!("ROOT_FINAL:{}", root).as_bytes(),
            final_char_len,
        )
    }
}

// ========================================================================
//  6. Order-Independent CLI Parser & Verification
// ========================================================================
fn is_valid_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn clean_arg(s: &str) -> String {
    let mut out = s.trim();
    while out.len() >= 2
        && ((out.starts_with('"') && out.ends_with('"'))
            || (out.starts_with('\'') && out.ends_with('\'')))
    {
        out = &out[1..out.len() - 1];
    }
    out.trim().to_string()
}

fn print_usage() {
    println!("--- ITH-XOF Cryptographic Hash Engine (Hardened 3D Sponge) ---");
    println!("Usage:");
    println!("  ith_hash [/paranoid|/standard] <file_path> [output_length]");
    println!("  ith_hash [/paranoid|/standard] /folder [/usemerkletree] <dir_path> [output_length]");
    println!();
    println!("Verification:");
    println!("  ith_hash [/paranoid|/standard] [/folder [/usemerkletree]] <path> /check <expected_hash>");
    println!();
    println!("  Profile       : defaults to /paranoid (c=1536, r=64); opt-in /standard (c=1024, r=576)");
    println!("  output_length : default 64 hex characters (min 32 in /check mode)");
    println!("  Flags and arguments may be supplied in any order.");
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
    let raw_args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<String> = raw_args
        .iter()
        .map(|s| clean_arg(s))
        .filter(|s| !s.is_empty())
        .collect();

    if args.is_empty() {
        print_usage();
        return;
    }

    // Default to Paranoid profile; Standard is opt-in
    let mut mode: &str = "paranoid";
    let mut folder_mode = false;
    let mut merkle_mode = false;
    let mut check_mode = false;
    let mut numeric_buffer: Vec<usize> = Vec::new();
    let mut non_flag_tokens: Vec<String> = Vec::new();

    for arg in &args {
        let lower = arg.to_lowercase();
        match lower.as_str() {
            "/standard" | "--standard" | "-standard" => mode = "standard",
            "/paranoid" | "--paranoid" | "-paranoid" => mode = "paranoid",
            "/folder" | "--folder" | "-folder" => folder_mode = true,
            "/usemerkletree" | "--usemerkletree" | "-usemerkletree" => merkle_mode = true,
            "/check" | "--check" | "-check" => check_mode = true,
            _ => {
                if let Ok(n) = arg.parse::<usize>() {
                    if n > 0 {
                        numeric_buffer.push(n);
                    }
                } else {
                    non_flag_tokens.push(arg.clone());
                }
            }
        }
    }

    if merkle_mode && !folder_mode {
        eprintln!(
            "{}Error: /usemerkletree can only be used with /folder.{}",
            COLOR_RED, COLOR_RESET
        );
        std::process::exit(1);
    }

    let mut target_path: Option<String> = None;
    let mut expected_hash: Option<String> = None;

    if check_mode {
        for token in &non_flag_tokens {
            let p = Path::new(token);
            if target_path.is_none() && p.exists() {
                target_path = Some(token.clone());
            } else if expected_hash.is_none() && is_valid_hex(token) {
                expected_hash = Some(token.to_lowercase());
            } else if target_path.is_none() {
                target_path = Some(token.clone());
            } else if expected_hash.is_none() {
                expected_hash = Some(token.to_lowercase());
            }
        }

        if let Some(ref h) = expected_hash {
            if !is_valid_hex(h) || h.len() < 32 {
                eprintln!(
                    "{}Error: /check requires a valid hex hash of at least 32 characters (128 bits).{}",
                    COLOR_RED, COLOR_RESET
                );
                std::process::exit(1);
            }
        }
    } else if !non_flag_tokens.is_empty() {
        target_path = Some(non_flag_tokens[0].clone());
    }

    let path_str = match target_path {
        Some(p) => p,
        None => {
            eprintln!("{}Error: no target path provided.{}", COLOR_RED, COLOR_RESET);
            print_usage();
            std::process::exit(1);
        }
    };

    let char_len = if check_mode {
        expected_hash.as_ref().map(|h| h.len()).unwrap_or(64)
    } else {
        numeric_buffer.first().copied().unwrap_or(64)
    };

    if folder_mode {
        let target_dir = Path::new(&path_str);
        if !target_dir.is_dir() {
            eprintln!(
                "{}Error: not a valid directory: {}{}",
                COLOR_RED, path_str, COLOR_RESET
            );
            std::process::exit(1);
        }

        let mut file_count = 0;
        let mut dir_count = 0;
        let mut symlink_count = 0;
        let mut total_size = 0u64;
        let mut leaf_hashes = Vec::new();

        if let Err(e) = collect_directory_entries(
            target_dir,
            target_dir,
            mode,
            &mut file_count,
            &mut dir_count,
            &mut symlink_count,
            &mut total_size,
            &mut leaf_hashes,
        ) {
            eprintln!("{}Error scanning directory: {}{}", COLOR_RED, e, COLOR_RESET);
            std::process::exit(1);
        }

        let digest = if merkle_mode {
            compute_merkle_root(mode, leaf_hashes, char_len)
        } else {
            let mut manifest = format!(
                "MANIFEST:{}:{}:{}:{}\n",
                file_count, dir_count, symlink_count, total_size
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
            println!("=== {}: {} ===", label, target_dir.to_string_lossy());
            println!(
                "Files: {}, Folders: {}, Symlinks: {}, Total size: {} bytes",
                file_count, dir_count, symlink_count, total_size
            );
        }

        verify_or_print(&digest, check_mode, expected_hash);
        return;
    }

    if !Path::new(&path_str).is_file() {
        eprintln!("{}Error: file not found: {}{}", COLOR_RED, path_str, COLOR_RESET);
        std::process::exit(1);
    }

    match run_hash(mode, &path_str, char_len) {
        Ok(computed) => verify_or_print(&computed, check_mode, expected_hash),
        Err(e) => {
            eprintln!("{}Error reading target file: {}{}", COLOR_RED, e, COLOR_RESET);
            std::process::exit(1);
        }
    }
}