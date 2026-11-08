use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

const STATE_WORDS: usize = 25;

const STANDARD_RATE_WORDS: usize = 9;
const STANDARD_BLOCK: usize = STANDARD_RATE_WORDS * 8;

const PARANOID_RATE_WORDS: usize = 1;
const PARANOID_BLOCK: usize = PARANOID_RATE_WORDS * 8;

const COLOR_RESET: &str = "\x1b[0m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RED: &str = "\x1b[31m";
const COLOR_CYAN: &str = "\x1b[36m";

fn permute_state(state: &mut [u64; STATE_WORDS]) {
    let rho_constants: [u32; 25] = [
        0,  1,  62, 28, 27,
        36, 44, 6,  55, 20,
        3,  10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2,  61, 56, 14,
    ];

    for round in 1..=24u32 {
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

        let mut advanced_state = [0u64; STATE_WORDS];
        for i in 0..STATE_WORDS {
            let target_index = (i * 7) % STATE_WORDS;
            advanced_state[target_index] = state[i].rotate_left(rho_constants[i]);
        }
        *state = advanced_state;

        let mut chi_state = [0u64; STATE_WORDS];
        for i in 0..STATE_WORDS {
            let s1 = state[(i + 1) % STATE_WORDS];
            let s2 = state[(i + 2) % STATE_WORDS];
            chi_state[i] = state[i] ^ ((!s1) & s2);
        }
        *state = chi_state;

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

fn absorb_block_dynamic(
    state: &mut [u64; STATE_WORDS],
    block: &[u8],
    rate_words: usize,
) {
    for i in 0..rate_words {
        let start = i * 8;
        let mut word_bytes = [0u8; 8];
        word_bytes.copy_from_slice(&block[start..start + 8]);
        state[i] ^= u64::from_le_bytes(word_bytes);
    }
    permute_state(state);
}

fn squeeze_xof(
    state: &mut [u64; STATE_WORDS],
    rate_words: usize,
    target_char_len: usize,
) -> String {
    let target_byte_len = (target_char_len + 1) / 2;
    let mut output_bytes = Vec::with_capacity(target_byte_len);

    while output_bytes.len() < target_byte_len {
        for i in 0..rate_words {
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
            absorb_block_dynamic(
                &mut state,
                &payload_bytes[data_idx..data_idx + block_size],
                rate_words,
            );
            data_idx += block_size;
        } else {
            let mut padded_block = vec![0u8; block_size];
            padded_block[..remaining].copy_from_slice(&payload_bytes[data_idx..]);
            padded_block[remaining] |= 0x01;
            if remaining < block_size - 1 {
                padded_block[block_size - 1] |= 0x80;
                absorb_block_dynamic(&mut state, &padded_block, rate_words);
            } else {
                absorb_block_dynamic(&mut state, &padded_block, rate_words);
                let mut final_block = vec![0u8; block_size];
                final_block[block_size - 1] |= 0x80;
                absorb_block_dynamic(&mut state, &final_block, rate_words);
            }
            break;
        }
    }

    squeeze_xof(&mut state, rate_words, char_len)
}

/// Helper that ensures the buffer is completely filled unless EOF or an error occurs.
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

    Ok(squeeze_xof(&mut state, RATE_WORDS, target_char_len))
}

fn scan_directory_metadata(
    dir: &Path,
    base_dir: &Path,
    file_count: &mut usize,
    dir_count: &mut usize,
    total_size: &mut u64,
    structure_str: &mut String,
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

        if file_type.is_dir() {
            *dir_count += 1;
            structure_str.push_str(&format!("D:{}\n", rel_path));
            scan_directory_metadata(
                &path,
                base_dir,
                file_count,
                dir_count,
                total_size,
                structure_str,
            )?;
        } else if file_type.is_file() {
            *file_count += 1;
            let meta = entry.metadata()?;
            let size = meta.len();
            *total_size += size;
            structure_str.push_str(&format!("F:{}:{}\n", rel_path, size));
        }
    }
    Ok(())
}

fn collect_merkle_leaves(
    dir: &Path,
    base_dir: &Path,
    mode: &str,
    char_len: usize,
    file_count: &mut usize,
    dir_count: &mut usize,
    total_size: &mut u64,
    leaves: &mut Vec<String>,
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

        if file_type.is_dir() {
            *dir_count += 1;
            collect_merkle_leaves(
                &path,
                base_dir,
                mode,
                char_len,
                file_count,
                dir_count,
                total_size,
                leaves,
            )?;
        } else if file_type.is_file() {
            *file_count += 1;
            let meta = entry.metadata()?;
            *total_size += meta.len();

            let path_str = path.to_string_lossy();
            let content_hash = run_hash(mode, &path_str, char_len)?;
            // Domain separation ("LEAF:") + relative path + file content hash
            let leaf_payload = format!("LEAF:{}:{}", rel_path, content_hash);
            let leaf_hash = hash_bytes_xof(mode, leaf_payload.as_bytes(), char_len);
            leaves.push(leaf_hash);
        }
    }
    Ok(())
}

fn compute_merkle_root(mode: &str, mut hashes: Vec<String>, char_len: usize) -> String {
    if hashes.is_empty() {
        return hash_bytes_xof(mode, b"MERKLE_EMPTY_TREE", char_len);
    }

    while hashes.len() > 1 {
        let mut next_level = Vec::with_capacity((hashes.len() + 1) / 2);
        for chunk in hashes.chunks(2) {
            if chunk.len() == 2 {
                let combined = format!("NODE:{}:{}", chunk[0], chunk[1]);
                next_level.push(hash_bytes_xof(mode, combined.as_bytes(), char_len));
            } else {
                let combined = format!("NODE_ODD:{}", chunk[0]);
                next_level.push(hash_bytes_xof(mode, combined.as_bytes(), char_len));
            }
        }
        hashes = next_level;
    }

    hashes.remove(0)
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
    println!("--- ITH-XOF Cryptographic Hash Engine ---");
    println!("Usage:");
    println!("  ith_hash /standard <file_path> [output_length]");
    println!("  ith_hash /paranoid <file_path> [output_length]");
    println!("  ith_hash <file_path> [output_length]    (default: /standard)");
    println!();
    println!("Directory Mode:");
    println!("  ith_hash [/standard|/paranoid] /folder [/usemerkletree] <dir_path> [output_length]");
    println!();
    println!("Verification:");
    println!("  ith_hash [/standard|/paranoid] [/folder [/usemerkletree]] <path> /check <expected_hash>");
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

fn verify_or_print(computed: &str, check_mode: bool, expected_hash: Option<String>, fallback_arg: Option<&String>) {
    if check_mode {
        let expected = expected_hash.or_else(|| fallback_arg.map(|s| s.to_lowercase()));
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
            "/folder" | "--folder" | "-folder" => folder_mode = true,
            "/usemerkletree" | "--usemerkletree" | "-usemerkletree" => merkle_mode = true,
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

    if merkle_mode && !folder_mode {
        eprintln!(
            "{}Error: /usemerkletree can only be used with the /folder parameter.{}",
            COLOR_RED, COLOR_RESET
        );
        std::process::exit(1);
    }

    if folder_mode {
        if path_buffer.is_empty() {
            eprintln!(
                "{}Error: No directory path provided for /folder mode.{}",
                COLOR_RED, COLOR_RESET
            );
            std::process::exit(1);
        }

        let target_dir = Path::new(&path_buffer[0]);
        if !target_dir.is_dir() {
            eprintln!(
                "{}Error: Provided path is not a valid directory: {}{}",
                COLOR_RED,
                target_dir.to_string_lossy(),
                COLOR_RESET
            );
            std::process::exit(1);
        }

        let char_len = if check_mode {
            expected_hash
                .as_ref()
                .or_else(|| path_buffer.get(1))
                .map(|h| h.len())
                .unwrap_or(64)
        } else {
            numeric_buffer.first().copied().unwrap_or(64)
        };

        let mut file_count = 0;
        let mut dir_count = 0;
        let mut total_size = 0u64;

        let digest = if merkle_mode {
            let mut leaves = Vec::new();
            if let Err(e) = collect_merkle_leaves(
                target_dir,
                target_dir,
                mode,
                char_len,
                &mut file_count,
                &mut dir_count,
                &mut total_size,
                &mut leaves,
            ) {
                eprintln!(
                    "{}Error computing Merkle tree leaves: {}{}",
                    COLOR_RED, e, COLOR_RESET
                );
                std::process::exit(1);
            }
            compute_merkle_root(mode, leaves, char_len)
        } else {
            let mut structure_str = String::new();
            if let Err(e) = scan_directory_metadata(
                target_dir,
                target_dir,
                &mut file_count,
                &mut dir_count,
                &mut total_size,
                &mut structure_str,
            ) {
                eprintln!(
                    "{}Error scanning directory structure: {}{}",
                    COLOR_RED, e, COLOR_RESET
                );
                std::process::exit(1);
            }

            let final_payload = format!(
                "{}:{}:{}:\n{}",
                file_count, dir_count, total_size, structure_str
            );
            hash_bytes_xof(mode, final_payload.as_bytes(), char_len)
        };

        if !check_mode {
            let mode_label = if merkle_mode {
                "Directory Merkle Root Hash"
            } else {
                "Directory Integrity Hash"
            };
            println!("=== {}: {} ===", mode_label, target_dir.to_string_lossy());
            println!(
                "Files counted: {}, Folders counted: {}, Total payload size: {} bytes",
                file_count, dir_count, total_size
            );
        }

        verify_or_print(&digest, check_mode, expected_hash, path_buffer.get(1));
        return;
    }

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

    let char_len = if check_mode {
        expected_hash
            .as_ref()
            .or_else(|| path_buffer.get(1))
            .map(|h| h.len())
            .unwrap_or(64)
    } else {
        numeric_buffer.first().copied().unwrap_or(64)
    };

    match run_hash(mode, &file_path, char_len) {
        Ok(computed) => verify_or_print(&computed, check_mode, expected_hash, path_buffer.get(1)),
        Err(e) => {
            eprintln!("{}Error reading target file: {}{}", COLOR_RED, e, COLOR_RESET);
            std::process::exit(1);
        }
    }
}
