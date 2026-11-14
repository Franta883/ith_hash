use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

const STATE_WORDS: usize = 25;
const INTERNAL_HASH_HEX_LEN: usize = 128; // 512-bit internal security bound for Merkle nodes

const STANDARD_RATE_WORDS: usize = 9;
const STANDARD_BLOCK: usize = STANDARD_RATE_WORDS * 8; // 72 bytes

const PARANOID_RATE_WORDS: usize = 1;
const PARANOID_BLOCK: usize = PARANOID_RATE_WORDS * 8; // 8 bytes

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

// Standard Keccak-f[1600] 2D rotation offsets indexed by (x + 5 * y)
const KECCAK_RHO: [u32; 25] = [
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
];

// ========================================================================
//  1. Hardened 2D Keccak-f[1600] Permutation (Theta, Rho, Pi, Chi, Iota)
// ========================================================================
fn permute_state(state: &mut [u64; STATE_WORDS]) {
    for round in 0..24 {
        // Theta: Column parity mixing
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }

        // Rho & Pi: Full 2D inter-column dispersion (x, y) -> (y, (2x + 3y) % 5)
        let mut b = [0u64; 25];
        for y in 0..5 {
            for x in 0..5 {
                let idx = x + 5 * y;
                let new_x = y;
                let new_y = (2 * x + 3 * y) % 5;
                b[new_x + 5 * new_y] = state[idx].rotate_left(KECCAK_RHO[idx]);
            }
        }

        // Chi: Row-wise non-linear quadratic mapping (degree 2)
        for y in 0..5 {
            let row = 5 * y;
            for x in 0..5 {
                state[row + x] = b[row + x] ^ ((!b[row + ((x + 1) % 5)]) & b[row + ((x + 2) % 5)]);
            }
        }

        // Iota: Asymmetric round constant injection into lane (0, 0)
        state[0] ^= KECCAK_RC[round];
    }
}

// ========================================================================
//  2. Absorption, Standard pad10*1 Padding & Squeezing
// ========================================================================
fn absorb_block_dynamic(state: &mut [u64; STATE_WORDS], block: &[u8], rate_words: usize) {
    for i in 0..rate_words {
        let start = i * 8;
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&block[start..start + 8]);
        state[i] ^= u64::from_le_bytes(word_bytes);
    }
    permute_state(state);
}

fn squeeze_xof(state: &mut [u64; STATE_WORDS], rate_words: usize, target_char_len: usize) -> String {
    let target_byte_len = (target_char_len + 1) / 2;
    let mut output_bytes = Vec::with_capacity(target_byte_len);

    while output_bytes.len() < target_byte_len {
        for i in 0..rate_words {
            if output_bytes.len() >= target_byte_len {
                break;
            }
            let word_bytes = state[i].to_le_bytes();
            for &byte in &word_bytes {
                if output_bytes.len() < target_byte_len {
                    output_bytes.push(byte);
                } else {
                    break;
                }
            }
        }
        if output_bytes.len() < target_byte_len {
            permute_state(state);
        }
    }

    let mut digest = String::with_capacity(target_char_len);
    for byte in output_bytes {
        digest.push_str(&format!("{:02x}", byte));
    }
    digest.truncate(target_char_len);
    digest
}

pub fn hash_bytes_xof(mode: &str, payload_bytes: &[u8], char_len: usize) -> String {
    let (rate_words, block_size) = if mode == "paranoid" {
        (PARANOID_RATE_WORDS, PARANOID_BLOCK)
    } else {
        (STANDARD_RATE_WORDS, STANDARD_BLOCK)
    };

    let mut state: [u64; STATE_WORDS] = [0; STATE_WORDS];
    let mut data_idx = 0;

    loop {
        let remaining = payload_bytes.len() - data_idx;
        if remaining >= block_size {
            absorb_block_dynamic(&mut state, &payload_bytes[data_idx..data_idx + block_size], rate_words);
            data_idx += block_size;
        } else {
            // Standard pad10*1: handles remaining == block_size - 1 in a single block (0x81)
            let mut padded_block = vec![0u8; block_size];
            padded_block[..remaining].copy_from_slice(&payload_bytes[data_idx..]);
            padded_block[remaining] |= 0x01;
            padded_block[block_size - 1] |= 0x80;
            absorb_block_dynamic(&mut state, &padded_block, rate_words);
            break;
        }
    }

    squeeze_xof(&mut state, rate_words, char_len)
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
    let mut state: [u64; STATE_WORDS] = [0; STATE_WORDS];
    let mut file = File::open(file_path)?;
    let mut buffer = [0u8; BLOCK_SIZE_BYTES];

    loop {
        let bytes_read = read_full(&mut file, &mut buffer[..])?;

        if bytes_read == BLOCK_SIZE_BYTES {
            absorb_block_dynamic(&mut state, &buffer, RATE_WORDS);
        } else {
            // Standard pad10*1 single final block
            let mut padded_block = [0u8; BLOCK_SIZE_BYTES];
            padded_block[..bytes_read].copy_from_slice(&buffer[..bytes_read]);
            padded_block[bytes_read] |= 0x01;
            padded_block[BLOCK_SIZE_BYTES - 1] |= 0x80;
            absorb_block_dynamic(&mut state, &padded_block, RATE_WORDS);
            break;
        }
    }

    Ok(squeeze_xof(&mut state, RATE_WORDS, target_char_len))
}

fn run_hash(mode: &str, file_path: &str, char_len: usize) -> io::Result<String> {
    if mode == "paranoid" {
        get_internal_tools_xof::<PARANOID_RATE_WORDS, PARANOID_BLOCK, _>(file_path, char_len)
    } else {
        get_internal_tools_xof::<STANDARD_RATE_WORDS, STANDARD_BLOCK, _>(file_path, char_len)
    }
}

// ========================================================================
//  3. Hardened Directory Traversal & Merkle Tree (Length-Prefixed)
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
            // Length-prefixed symlink record prevents delimiter injection
            let record = format!("SYMLINK:{}:{}:{}:{}", rel_path.len(), rel_path, target.len(), target);
            entries_out.push(hash_bytes_xof(mode, record.as_bytes(), INTERNAL_HASH_HEX_LEN));
        } else if file_type.is_dir() {
            *dir_count += 1;
            // Commit to directory existence (catches empty directory additions/renames)
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
            // Always hash file contents using full 512-bit internal width
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
        let target_len = if is_last_level { final_char_len } else { INTERNAL_HASH_HEX_LEN };

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

    // If tree had only 1 leaf (128 hex chars), squeeze/truncate cleanly to final_char_len
    let root = hashes.remove(0);
    if root.len() == final_char_len {
        root
    } else {
        hash_bytes_xof(mode, format!("ROOT_FINAL:{}", root).as_bytes(), final_char_len)
    }
}

// ========================================================================
//  4. Constant-Time Verification & Order-Independent CLI Parser
// ========================================================================
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

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
    println!("--- ITH-XOF Cryptographic Hash Engine (Hardened) ---");
    println!("Usage:");
    println!("  ith_hash [/standard|/paranoid] <file_path> [output_length]");
    println!("  ith_hash [/standard|/paranoid] /folder [/usemerkletree] <dir_path> [output_length]");
    println!();
    println!("Verification:");
    println!("  ith_hash [/standard|/paranoid] [/folder [/usemerkletree]] <path> /check <expected_hash>");
    println!();
    println!("  output_length : default 64 hex characters (min 32 in /check mode)");
    println!("  Flags and arguments may be supplied in any order.");
}

fn verify_or_print(computed: &str, check_mode: bool, expected_hash: Option<String>) {
    if check_mode {
        let expected = match expected_hash {
            Some(h) => h,
            None => {
                eprintln!("{}Error: no expected hash provided for /check.{}", COLOR_RED, COLOR_RESET);
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

    let mut mode: &str = "standard";
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
        eprintln!("{}Error: /usemerkletree can only be used with /folder.{}", COLOR_RED, COLOR_RESET);
        std::process::exit(1);
    }

    // Order-independent path & expected hash resolution
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
            eprintln!("{}Error: not a valid directory: {}{}", COLOR_RED, path_str, COLOR_RESET);
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
            let mut manifest = format!("MANIFEST:{}:{}:{}:{}\n", file_count, dir_count, symlink_count, total_size);
            for h in &leaf_hashes {
                manifest.push_str(h);
                manifest.push('\n');
            }
            hash_bytes_xof(mode, manifest.as_bytes(), char_len)
        };

        if !check_mode {
            let label = if merkle_mode { "Directory Merkle Root Hash" } else { "Directory Content Hash" };
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