use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

// ---- Engine constants ---------------------------------------------------
const STATE_WORDS: usize = 25;

const STANDARD_RATE_WORDS: usize = 9;
const STANDARD_BLOCK: usize = STANDARD_RATE_WORDS * 8; // 72 bytes

const PARANOID_RATE_WORDS: usize = 1;
const PARANOID_BLOCK: usize = PARANOID_RATE_WORDS * 8; // 8 bytes

// ---- ANSI colours -------------------------------------------------------
const COLOR_RESET: &str = "\x1b[0m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RED: &str = "\x1b[31m";
const COLOR_CYAN: &str = "\x1b[36m";

// ========================================================================
//  Shared permutation (identical in both original editions)
// ========================================================================
fn permute_state(state: &mut [u64; STATE_WORDS]) {
    let rho_constants: [u32; 25] = [
        0,  1,  62, 28, 27,
        36, 44, 6,  55, 20,
        3,  10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2,  61, 56, 14,
    ];

    for round in 1..=24u32 {
        // 1. Bijective Theta Layer
        let mut c_parity = [0u64; 5];
        for i in 0..5 {
            c_parity[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        for i in 0..5 {
            let m_mix = c_parity[(i + 4) % 5] ^ c_parity[(i + 1) % 5].rotate_left(1);
            for j in 0..5 {
                state[i + j * 5] ^= m_mix;
            }
        }

        // 2. Rho Diffusion & Pi Shuffle Layer
        let mut advanced_state = [0u64; STATE_WORDS];
        for i in 0..STATE_WORDS {
            let target_index = (i * 7) % STATE_WORDS;
            advanced_state[target_index] = state[i].rotate_left(rho_constants[i]);
        }
        *state = advanced_state;

        // 3. Non-Linear Quadratic Chi Layer
        let mut chi_state = [0u64; STATE_WORDS];
        for i in 0..STATE_WORDS {
            let s1 = state[(i + 1) % STATE_WORDS];
            let s2 = state[(i + 2) % STATE_WORDS];
            chi_state[i] = state[i] ^ ((!s1) & s2);
        }
        *state = chi_state;

        // 4. Asymmetrical Round Constant Injection
        let r = round as u64;
        let base_constant = 0x9e3779b97f4a7c15u64.rotate_left(round) ^ (r << 48) ^ (!r);
        for i in 0..STATE_WORDS {
            let unique_word_salt = (i as u64)
                .wrapping_mul(0xbf58476d1ce4e5b9u64)
                .rotate_left(i as u32);
            state[i] ^= base_constant ^ unique_word_salt;
        }
    }
}

// ========================================================================
//  Absorb a single block (rate length is a const generic)
// ========================================================================
fn absorb_block<const RATE_WORDS: usize, const BLOCK_SIZE_BYTES: usize>(
    state: &mut [u64; STATE_WORDS],
    block: &[u8; BLOCK_SIZE_BYTES],
) {
    for i in 0..RATE_WORDS {
        let start = i * 8;
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&block[start..start + 8]);
        state[i] ^= u64::from_le_bytes(word_bytes);
    }
    permute_state(state);
}

// ========================================================================
//  Unified XOF hash engine
// ========================================================================
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
    let mut total_bytes_read = 0;

    loop {
        let bytes_read = file.read(&mut buffer[..])?;
        total_bytes_read += bytes_read;

        if bytes_read == BLOCK_SIZE_BYTES {
            absorb_block::<RATE_WORDS, BLOCK_SIZE_BYTES>(&mut state, &buffer);
        } else {
            let mut padded_block = [0u8; BLOCK_SIZE_BYTES];
            padded_block[..bytes_read].copy_from_slice(&buffer[..bytes_read]);
            padded_block[bytes_read] |= 0x01;

            if bytes_read < BLOCK_SIZE_BYTES - 1 {
                padded_block[BLOCK_SIZE_BYTES - 1] |= 0x80;
                absorb_block::<RATE_WORDS, BLOCK_SIZE_BYTES>(&mut state, &padded_block);
            } else {
                absorb_block::<RATE_WORDS, BLOCK_SIZE_BYTES>(&mut state, &padded_block);
                let mut final_block = [0u8; BLOCK_SIZE_BYTES];
                final_block[BLOCK_SIZE_BYTES - 1] |= 0x80;
                absorb_block::<RATE_WORDS, BLOCK_SIZE_BYTES>(&mut state, &final_block);
            }
            break;
        }
    }

    if total_bytes_read == 0 {
        let mut empty_padded = [0u8; BLOCK_SIZE_BYTES];
        empty_padded[0] |= 0x01;
        empty_padded[BLOCK_SIZE_BYTES - 1] |= 0x80;
        absorb_block::<RATE_WORDS, BLOCK_SIZE_BYTES>(&mut state, &empty_padded);
    }

    let target_byte_len = (target_char_len + 1) / 2;
    let mut output_bytes = Vec::with_capacity(target_byte_len);

    while output_bytes.len() < target_byte_len {
        for i in 0..RATE_WORDS {
            if output_bytes.len() >= target_byte_len {
                break;
            }
            let word_bytes = state[i].to_le_bytes();
            for byte in word_bytes.iter() {
                if output_bytes.len() < target_byte_len {
                    output_bytes.push(*byte);
                } else {
                    break;
                }
            }
        }
        if output_bytes.len() < target_byte_len {
            permute_state(&mut state);
        }
    }

    let mut digest = String::with_capacity(target_char_len);
    for byte in output_bytes {
        digest.push_str(&format!("{:02x}", byte));
    }
    digest.truncate(target_char_len);
    Ok(digest)
}

// ========================================================================
//  CLI:  argument parsing / cleanup
// ========================================================================

/// Trim surrounding whitespace and any wrapping quotes (Windows / POSIX style).
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
    println!("--- ITH-XOF Cryptographic Hash Engine ---");
    println!("Usage:");
    println!("  ith_hash /standard <file_path> [output_length]");
    println!("  ith_hash /paranoid <file_path> [output_length]");
    println!("  ith_hash <file_path> [output_length]    (default: /standard)");
    println!();
    println!("Verification:");
    println!("  ith_hash [/standard|/paranoid] <file_path> /check <expected_hash>");
    println!();
    println!("  output_length : default 64 hex characters (XOF variable output)");
    println!("  Flags and arguments may be supplied in any order.");
}

fn run_hash(mode: &str, file_path: &str, char_len: usize) -> io::Result<String> {
    if mode == "paranoid" {
        get_internal_tools_xof::<PARANOID_RATE_WORDS, PARANOID_BLOCK, _>(file_path, char_len)
    } else {
        get_internal_tools_xof::<STANDARD_RATE_WORDS, STANDARD_BLOCK, _>(file_path, char_len)
    }
}

fn main() {
    // -- Collect & sanitize args ----------------------------------------
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

    // -- State machine over args (order-independent) --------------------
    let mut mode: &str = "standard";
    let mut check_mode = false;
    let mut expect_hash_next = false;
    let mut expected_hash: Option<String> = None;
    let mut numeric_buffer: Vec<usize> = Vec::new();
    let mut path_buffer: Vec<String> = Vec::new();

    for arg in &args {
        let lower = arg.to_lowercase();

        if expect_hash_next {
            expected_hash = Some(lower);
            expect_hash_next = false;
            continue;
        }

        match lower.as_str() {
            "/standard" | "--standard" | "-standard" => mode = "standard",
            "/paranoid" | "--paranoid" | "-paranoid" => mode = "paranoid",
            "/check" | "--check" | "-check" => {
                check_mode = true;
                expect_hash_next = true;
            }
            _ => {
                if let Ok(n) = arg.parse::<usize>() {
                    if n > 0 {
                        numeric_buffer.push(n);
                    }
                } else {
                    path_buffer.push(arg.clone());
                }
            }
        }
    }

    // -- Resolve the file path ------------------------------------------
    if path_buffer.is_empty() {
        eprintln!("{}Error: no file path provided.{}", COLOR_RED, COLOR_RESET);
        print_usage();
        std::process::exit(1);
    }
    let file_path = path_buffer[0].clone();

    if !Path::new(&file_path).exists() {
        eprintln!(
            "{}Error: file not found: {}{}",
            COLOR_RED, file_path, COLOR_RESET
        );
        std::process::exit(1);
    }

    // -- Verification mode ----------------------------------------------
    if check_mode {
        let expected = expected_hash
            .or_else(|| path_buffer.get(1).map(|s| s.to_lowercase()));

        let expected = match expected {
            Some(h) => h,
            None => {
                eprintln!(
                    "{}Error: no expected hash provided after /check.{}",
                    COLOR_RED, COLOR_RESET
                );
                std::process::exit(1);
            }
        };

        let target_len = expected.len();

        match run_hash(mode, &file_path, target_len) {
            Ok(computed) => {
                if computed == expected {
                    println!(
                        "{} [OK] Hash matches! {}{}",
                        COLOR_GREEN, computed, COLOR_RESET
                    );
                } else {
                    eprintln!("{} [FAIL] Hash mismatch! {}", COLOR_RED, COLOR_RESET);
                    eprintln!("{}Expected: {}{}", COLOR_CYAN, expected, COLOR_RESET);
                    eprintln!("{}Computed: {}{}", COLOR_RED, computed, COLOR_RESET);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("{}Error reading target file: {}{}", COLOR_RED, e, COLOR_RESET);
                std::process::exit(1);
            }
        }
        return;
    }

    // -- Normal hash mode -----------------------------------------------
    let char_len = numeric_buffer.first().copied().unwrap_or(64);

    match run_hash(mode, &file_path, char_len) {
        Ok(hash) => println!("{}", hash),
        Err(e) => eprintln!("{}Error reading target file: {}{}", COLOR_RED, e, COLOR_RESET),
    }
}