use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

// Sponge Parameters: b = 1600 bits (25 words), c = 1536 bits (24 words), r = 64 bits (1 word)
const RATE_WORDS: usize = 1;          // r = 64 bits
const STATE_WORDS: usize = 25;        // b = 1600 bits
const BLOCK_SIZE_BYTES: usize = 8;    // = RATE_WORDS * 8

const COLOR_RESET: &str = "\x1b[0m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RED: &str = "\x1b[31m";
const COLOR_CYAN: &str = "\x1b[36m";

pub fn get_internal_tools_xof<P: AsRef<Path>>(file_path: P, target_char_len: usize) -> io::Result<String> {
    let mut state: [u64; STATE_WORDS] = [0; STATE_WORDS];
    let mut file = File::open(file_path)?;
    let mut buffer = [0u8; BLOCK_SIZE_BYTES];
    let mut total_bytes_read = 0;

    let rot1: u32 = 19;
    let rot2: u32 = 43;

    // Absorbing Phase
    loop {
        let bytes_read = file.read(&mut buffer[..])?;
        total_bytes_read += bytes_read;

        if bytes_read == BLOCK_SIZE_BYTES {
            absorb_block(&mut state, &buffer, rot1, rot2);
        } else {
            let mut padded_block = [0u8; BLOCK_SIZE_BYTES];
            padded_block[..bytes_read].copy_from_slice(&buffer[..bytes_read]);
            padded_block[bytes_read] |= 0x01;

            if bytes_read < BLOCK_SIZE_BYTES - 1 {
                padded_block[BLOCK_SIZE_BYTES - 1] |= 0x80;
                absorb_block(&mut state, &padded_block, rot1, rot2);
            } else {
                absorb_block(&mut state, &padded_block, rot1, rot2);
                let mut final_block = [0u8; BLOCK_SIZE_BYTES];
                final_block[BLOCK_SIZE_BYTES - 1] |= 0x80;
                absorb_block(&mut state, &final_block, rot1, rot2);
            }
            break;
        }
    }

    // Handle empty file edge-case
    if total_bytes_read == 0 {
        let mut empty_padded = [0u8; BLOCK_SIZE_BYTES];
        empty_padded[0] |= 0x01;
        empty_padded[BLOCK_SIZE_BYTES - 1] |= 0x80;
        absorb_block(&mut state, &empty_padded, rot1, rot2);
    }

    // Squeezing Phase (XOF output generation)
    let target_byte_len = (target_char_len + 1) / 2;
    let mut output_bytes = Vec::with_capacity(target_byte_len);

    while output_bytes.len() < target_byte_len {
        for i in 0..RATE_WORDS {
            if output_bytes.len() >= target_byte_len { break; }
            let word_bytes = state[i].to_le_bytes();
            for byte in word_bytes.iter() {
                if output_bytes.len() < target_byte_len {
                    output_bytes.push(*byte);
                } else { break; }
            }
        }
        if output_bytes.len() < target_byte_len {
            permute_state(&mut state, rot1, rot2);
        }
    }

    let mut digest = String::with_capacity(target_char_len);
    for byte in output_bytes {
        digest.push_str(&format!("{:02x}", byte));
    }
    digest.truncate(target_char_len);
    Ok(digest)
}

fn absorb_block(state: &mut [u64; STATE_WORDS], block: &[u8; BLOCK_SIZE_BYTES], rot1: u32, rot2: u32) {
    for i in 0..RATE_WORDS {
        let start = i * 8;
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&block[start..start + 8]);
        state[i] ^= u64::from_le_bytes(word_bytes);
    }
    permute_state(state, rot1, rot2);
}

// Core Cryptographic Permutation Function f (24 rounds of Fixed-Degree Logical Operations + Shift-Shuffle)
fn permute_state(state: &mut [u64; STATE_WORDS], rot1: u32, rot2: u32) {
    for round in 1..=24 {
        // 1a. Linear Logical Diffusion (Algebraic Degree = 1)
        let mut parity = 0u64;
        for i in 0..STATE_WORDS {
            parity ^= state[i];
        }
        let theta_mix = parity.rotate_left(rot1) ^ parity.rotate_left(rot2);
        for i in 0..STATE_WORDS {
            let j = (i + 7) % STATE_WORDS;
            state[i] ^= theta_mix ^ state[j].rotate_left(rot1);
            state[j] ^= state[i].rotate_left(32) ^ state[j].rotate_left(rot2);
        }

        // 1b. Non-Linear Quadratic Chi Layer (Fixed Algebraic Degree = 2)
        // Uses purely logical NOT (!), AND (&), and XOR (^) across the 25-word state
        let mut chi_state = [0u64; STATE_WORDS];
        for i in 0..STATE_WORDS {
            let s1 = state[(i + 1) % STATE_WORDS];
            let s2 = state[(i + 2) % STATE_WORDS];
            chi_state[i] = state[i] ^ ((!s1) & s2);
        }
        *state = chi_state;

        // 2. Shift-Shuffle Layer with bijection (7) and word-specific bit rotations (Algebraic Degree = 1)
        let mut shuffled_state = [0u64; STATE_WORDS];
        for i in 0..STATE_WORDS {
            let target_index = (i * 7) % STATE_WORDS;
            let shift_amount = ((i * 3) + 1) % 64;
            shuffled_state[target_index] = state[i].rotate_left(shift_amount as u32);
        }
        *state = shuffled_state;

        // 3. Avalanche Symmetry Disruption (Purely logical round constant injection)
        let r = round as u64;
        let round_constant = 0x9e3779b97f4a7c15u64.rotate_left(round as u32) ^ (r << 32) ^ (!r);
        for i in 0..STATE_WORDS {
            state[i] ^= round_constant ^ (i as u64);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("--- ITH-XOF Cryptographic Hash Engine (Rust CLI) ---");
        println!("Hash execution:  Hash-File <file_path> [/char_length]");
        println!("Verification:    Hash-File <file_path> /check <expected_hash>");
        return;
    }

    let file_path = &args[1];

    // Verification Mode Loop
    let check_mode = args.iter().any(|x| x == "/check" || x == "--check");

    if check_mode {
        let mut expected_hash = String::new();
        for arg in args.iter().skip(2) {
            if arg != "/check" && arg != "--check" && arg.len() > expected_hash.len() {
                expected_hash = arg.clone();
            }
        }

        let expected_hash = expected_hash.trim().to_lowercase();
        let target_len = expected_hash.len();

        if target_len == 0 {
            eprintln!("{}Error: No target hash provided for validation.{}", COLOR_RED, COLOR_RESET);
            std::process::exit(1);
        }

        match get_internal_tools_xof(file_path, target_len) {
            Ok(calculated_hash) => {
                if calculated_hash == expected_hash {
                    println!("{} [OK] Hash matches! {}{}", COLOR_GREEN, calculated_hash, COLOR_RESET);
                } else {
                    eprintln!("{} [FAIL] Hash mismatch! {}", COLOR_RED, COLOR_RESET);
                    eprintln!("{}Expected: {}{}", COLOR_CYAN, expected_hash, COLOR_RESET);
                    eprintln!("{}Computed: {}{}", COLOR_RED, calculated_hash, COLOR_RESET);
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

    // Standard Output Mode
    let mut char_len = 64;
    if args.len() >= 3 {
        let clean_len_str = args[2].trim_start_matches('/');
        if let Ok(parsed_len) = clean_len_str.parse::<usize>() {
            if parsed_len > 0 {
                char_len = parsed_len;
            }
        }
    }

    match get_internal_tools_xof(file_path, char_len) {
        Ok(hash) => println!("{}", hash),
        Err(e) => eprintln!("{}Error reading target file: {}{}", COLOR_RED, e, COLOR_RESET),
    }
}
