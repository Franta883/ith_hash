#![deny(unsafe_op_in_unsafe_fn)]

use core::fmt;
use core::hint::black_box;
use core::ops::Deref;
use core::sync::atomic::{compiler_fence, Ordering};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;

const INTERNAL_HASH_HEX_LEN: usize = 128;
const MIN_CHECK_HEX_LEN: usize = 64;
const MAX_OUTPUT_HEX_LEN: usize = 1_048_576;
const READ_BUF_SIZE: usize = 65_536;
const DEFAULT_MAX_DEPTH: usize = 64;

pub const OBJ_DOMAIN_FILE_DATA: u8 = 0x00;
pub const OBJ_DOMAIN_MERKLE_LEAF: u8 = 0x01;
pub const OBJ_DOMAIN_MERKLE_NODE: u8 = 0x02;
pub const OBJ_DOMAIN_DIR_ROOT: u8 = 0x03;

const STANDARD_RATE_WORDS: usize = 9;
const STANDARD_BLOCK: usize = STANDARD_RATE_WORDS * 8;
const DOMAIN_STANDARD: u8 = 0x0A;

const PARANOID_RATE_WORDS: usize = 1;
const PARANOID_BLOCK: usize = PARANOID_RATE_WORDS * 8;
const DOMAIN_PARANOID: u8 = 0x06;

const COLOR_RESET: &str = "\x1b[0m";
const COLOR_GREEN: &str = "\x1b[32m";
const COLOR_RED: &str = "\x1b[31m";
const COLOR_CYAN: &str = "\x1b[36m";
const COLOR_YELLOW: &str = "\x1b[33m";

const KECCAK_RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

const KECCAK_RHO: [[u32; 5]; 5] = [
    [ 0, 36,  3, 41, 18],
    [ 1, 44, 10, 45,  2],
    [62,  6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39,  8, 14],
];

#[cfg(unix)]
#[allow(non_camel_case_types, dead_code)]
mod libc {
    pub type c_int = std::os::raw::c_int;
    pub type c_char = std::os::raw::c_char;

    pub const O_RDONLY: c_int = 0;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub const O_NONBLOCK: c_int = 0o4000;
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "arm", target_arch = "aarch64")
    ))]
    pub const O_DIRECTORY: c_int = 0o40000;
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        not(any(target_arch = "arm", target_arch = "aarch64"))
    ))]
    pub const O_DIRECTORY: c_int = 0o200000;
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "arm", target_arch = "aarch64")
    ))]
    pub const O_NOFOLLOW: c_int = 0o100000;
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        not(any(target_arch = "arm", target_arch = "aarch64"))
    ))]
    pub const O_NOFOLLOW: c_int = 0o400000;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub const O_CLOEXEC: c_int = 0o2000000;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub const AT_FDCWD: c_int = -100;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub const AT_SYMLINK_NOFOLLOW: c_int = 0x100;

    #[cfg(target_os = "macos")]
    pub const O_NONBLOCK: c_int = 0x0004;
    #[cfg(target_os = "macos")]
    pub const O_NOFOLLOW: c_int = 0x0100;
    #[cfg(target_os = "macos")]
    pub const O_DIRECTORY: c_int = 0x100000;
    #[cfg(target_os = "macos")]
    pub const O_CLOEXEC: c_int = 0x01000000;
    #[cfg(target_os = "macos")]
    pub const AT_FDCWD: c_int = -2;
    #[cfg(target_os = "macos")]
    pub const AT_SYMLINK_NOFOLLOW: c_int = 0x0020;

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    pub const O_NONBLOCK: c_int = 0x0004;
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    pub const O_NOFOLLOW: c_int = 0x0100;
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    pub const O_DIRECTORY: c_int = 0x00020000;
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    pub const O_CLOEXEC: c_int = 0x00100000;
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    pub const AT_FDCWD: c_int = -100;
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    pub const AT_SYMLINK_NOFOLLOW: c_int = 0x0200;

    pub const S_IFMT: u32 = 0o170000;
    pub const S_IFIFO: u32 = 0o010000;
    pub const S_IFCHR: u32 = 0o020000;
    pub const S_IFDIR: u32 = 0o040000;
    pub const S_IFBLK: u32 = 0o060000;
    pub const S_IFREG: u32 = 0o100000;
    pub const S_IFLNK: u32 = 0o120000;
    pub const S_IFSOCK: u32 = 0o140000;

    #[cfg(all(any(target_os = "linux", target_os = "android"), target_arch = "x86_64"))]
    #[repr(C)]
    pub struct stat {
        pub st_dev: u64,
        pub st_ino: u64,
        pub st_nlink: u64,
        pub st_mode: u32,
        pub st_uid: u32,
        pub st_gid: u32,
        pub __pad0: i32,
        pub st_rdev: u64,
        pub st_size: i64,
        pub st_blksize: i64,
        pub st_blocks: i64,
        pub st_atime: i64,
        pub st_atime_nsec: i64,
        pub st_mtime: i64,
        pub st_mtime_nsec: i64,
        pub st_ctime: i64,
        pub st_ctime_nsec: i64,
        pub __unused: [i64; 3],
    }

    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        not(target_arch = "x86_64")
    ))]
    #[repr(C)]
    pub struct stat {
        pub st_dev: u64,
        pub st_ino: u64,
        pub st_mode: u32,
        pub st_nlink: u32,
        pub st_uid: u32,
        pub st_gid: u32,
        pub st_rdev: u64,
        pub __pad1: u64,
        pub st_size: i64,
        pub st_blksize: i32,
        pub __pad2: i32,
        pub st_blocks: i64,
        pub st_atime: i64,
        pub st_atime_nsec: i64,
        pub st_mtime: i64,
        pub st_mtime_nsec: i64,
        pub st_ctime: i64,
        pub st_ctime_nsec: i64,
        pub __unused4: u32,
        pub __unused5: u32,
    }

    #[cfg(target_os = "macos")]
    #[repr(C)]
    pub struct stat {
        pub st_dev: i32,
        pub st_mode: u16,
        pub st_nlink: u16,
        pub st_ino: u64,
        pub st_uid: u32,
        pub st_gid: u32,
        pub st_rdev: i32,
        pub st_atime: i64,
        pub st_atime_nsec: i64,
        pub st_mtime: i64,
        pub st_mtime_nsec: i64,
        pub st_ctime: i64,
        pub st_ctime_nsec: i64,
        pub st_birthtime: i64,
        pub st_birthtime_nsec: i64,
        pub st_size: i64,
        pub st_blocks: i64,
        pub st_blksize: i32,
        pub st_flags: u32,
        pub st_gen: u32,
        pub st_lspare: i32,
        pub st_qspare: [i64; 2],
    }

    extern "C" {
        pub fn openat(dirfd: c_int, pathname: *const c_char, flags: c_int, ...) -> c_int;
        pub fn readlinkat(
            dirfd: c_int,
            pathname: *const c_char,
            buf: *mut c_char,
            bufsiz: usize,
        ) -> isize;
        pub fn dup(oldfd: c_int) -> c_int;

        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        #[cfg_attr(
            all(target_os = "macos", target_arch = "x86_64"),
            link_name = "fstatat$INODE64"
        )]
        pub fn fstatat(
            dirfd: c_int,
            pathname: *const c_char,
            buf: *mut stat,
            flags: c_int,
        ) -> c_int;
    }
}

#[cfg(windows)]
mod win_ffi {
    pub const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    #[repr(C)]
    #[derive(Default)]
    pub struct FILETIME {
        pub dw_low_date_time: u32,
        pub dw_high_date_time: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct BY_HANDLE_FILE_INFORMATION {
        pub dw_file_attributes: u32,
        pub ft_creation_time: FILETIME,
        pub ft_last_access_time: FILETIME,
        pub ft_last_write_time: FILETIME,
        pub dw_volume_serial_number: u32,
        pub n_file_size_high: u32,
        pub n_file_size_low: u32,
        pub n_number_of_links: u32,
        pub n_file_index_high: u32,
        pub n_file_index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetFileInformationByHandle(
            h_file: *mut core::ffi::c_void,
            lp_file_information: *mut BY_HANDLE_FILE_INFORMATION,
        ) -> i32;
    }
}

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

#[allow(unsafe_code)]
fn volatile_zero_vec_capacity(vec: &mut Vec<u8>) {
    let cap = vec.capacity();
    let ptr = vec.as_mut_ptr();
    for i in 0..cap {
        unsafe {
            core::ptr::write_volatile(ptr.add(i), 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

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

pub struct ZeroizingVec(pub Vec<u8>);

impl ZeroizingVec {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }
}

impl Drop for ZeroizingVec {
    fn drop(&mut self) {
        volatile_zero_vec_capacity(&mut self.0);
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ZeroizingString(String);

impl ZeroizingString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Deref for ZeroizingString {
    type Target = str;

    #[inline]
    fn deref(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<str> for ZeroizingString {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<[u8]> for ZeroizingString {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for ZeroizingString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl fmt::Debug for ZeroizingString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl Drop for ZeroizingString {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        let vec = unsafe { self.0.as_mut_vec() };
        volatile_zero_vec_capacity(vec);
    }
}

#[inline]
fn nibble_to_hex(n: u8) -> u8 {
    let n = n & 0x0f;
    let mask = ((9u8.wrapping_sub(n)) >> 7).wrapping_neg();
    n + b'0' + (mask & 39)
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

pub fn sanitize_display(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        let code = ch as u32;
        if (0x00..=0x1F).contains(&code) || (0x7F..=0x9F).contains(&code) {
            use std::fmt::Write;
            let _ = write!(&mut out, "\\x{:02x}", code);
        } else {
            out.push(ch);
        }
    }
    out
}

pub fn sanitize_path_display(path: &Path) -> String {
    sanitize_display(&path.to_string_lossy())
}

fn permute_state(state: &mut [[u64; 5]; 5]) {
    let mut c = [0u64; 5];
    let mut b = [[0u64; 5]; 5];

    for round in 0..24 {
        for x in 0..5 {
            c[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x][y] ^= d;
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                b[y][(2 * x + 3 * y) % 5] = state[x][y].rotate_left(KECCAK_RHO[x][y]);
            }
        }

        for x in 0..5 {
            for y in 0..5 {
                state[x][y] = b[x][y] ^ ((!b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]);
            }
        }

        state[0][0] ^= KECCAK_RC[round];
    }

    volatile_zero_u64_slice(&mut c);
    volatile_zero_u64_grid(&mut b);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Paranoid,
    Standard,
}

impl Profile {
    pub fn from_str(mode: &str) -> Result<Self, String> {
        if mode.eq_ignore_ascii_case("standard") {
            Ok(Profile::Standard)
        } else if mode.eq_ignore_ascii_case("paranoid") {
            Ok(Profile::Paranoid)
        } else {
            Err(format!(
                "unknown profile '{}' (expected 'paranoid' or 'standard')",
                sanitize_display(mode)
            ))
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

pub fn validate_output_hex_len(target_char_len: usize) -> Result<(), String> {
    if !(MIN_CHECK_HEX_LEN..=MAX_OUTPUT_HEX_LEN).contains(&target_char_len) {
        return Err(format!(
            "Requested output length {} must be between {} and {} hex characters",
            target_char_len, MIN_CHECK_HEX_LEN, MAX_OUTPUT_HEX_LEN
        ));
    }
    if target_char_len % 2 != 0 {
        return Err(format!(
            "Requested output length {} must be an even number of hex characters",
            target_char_len
        ));
    }
    Ok(())
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
        Self::new_with_domain(profile, OBJ_DOMAIN_FILE_DATA)
    }

    pub fn new_with_domain(profile: Profile, obj_domain: u8) -> Self {
        let mut buffer = [0u8; STANDARD_BLOCK];
        buffer[0] = obj_domain;
        Self {
            state: [[0u64; 5]; 5],
            buffer,
            buf_len: 1,
            squeeze_offset: 0,
            rate_words: profile.rate_words(),
            rate_bytes: profile.rate_bytes(),
            domain_suffix: profile.domain_suffix(),
            finalized: false,
        }
    }

    #[inline]
    #[allow(unsafe_code)]
    fn absorb_rate_block(&mut self, block: &[u8]) {
        let mut word_bytes = ZeroizingBuf::<8>::new();
        let mut lane_val: u64 = 0;
        for i in 0..self.rate_words {
            let start = i * 8;
            word_bytes.0.copy_from_slice(&block[start..start + 8]);
            lane_val = u64::from_le_bytes(word_bytes.0);
            let x = i % 5;
            let y = i / 5;
            self.state[x][y] ^= lane_val;
        }
        unsafe {
            core::ptr::write_volatile(&mut lane_val, 0);
        }
        compiler_fence(Ordering::SeqCst);
        drop(word_bytes);
        permute_state(&mut self.state);
    }

    #[inline]
    #[allow(unsafe_code)]
    fn extract_rate_block(&mut self) {
        let mut lane_val: u64 = 0;
        for i in 0..self.rate_words {
            let x = i % 5;
            let y = i / 5;
            lane_val = self.state[x][y];
            let start = i * 8;
            for b_idx in 0..8 {
                self.buffer[start + b_idx] = ((lane_val >> (b_idx * 8)) & 0xff) as u8;
            }
        }
        unsafe {
            core::ptr::write_volatile(&mut lane_val, 0);
        }
        compiler_fence(Ordering::SeqCst);
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

    pub fn squeeze_hex(&mut self, target_char_len: usize) -> ZeroizingString {
        if let Err(msg) = validate_output_hex_len(target_char_len) {
            panic!("{}", msg);
        }

        let target_byte_len = target_char_len / 2;
        let mut output_bytes = ZeroizingVec(vec![0u8; target_byte_len]);
        self.squeeze(&mut output_bytes.0);

        let mut hex_bytes = Vec::with_capacity(target_char_len);
        for &byte in &output_bytes.0 {
            hex_bytes.push(nibble_to_hex(byte >> 4));
            hex_bytes.push(nibble_to_hex(byte & 0x0f));
        }
        drop(output_bytes);

        ZeroizingString::new(
            String::from_utf8(hex_bytes).expect("nibble_to_hex produces valid ASCII UTF-8"),
        )
    }
}

impl Drop for IthHasher {
    fn drop(&mut self) {
        volatile_zero_u64_grid(&mut self.state);
        volatile_zero_bytes(&mut self.buffer);
    }
}

pub fn hash_domain_bytes_xof(
    profile: Profile,
    obj_domain: u8,
    payload_bytes: &[u8],
    char_len: usize,
) -> ZeroizingString {
    let mut hasher = IthHasher::new_with_domain(profile, obj_domain);
    hasher.absorb(payload_bytes);
    hasher.squeeze_hex(char_len)
}

pub fn hash_bytes_xof(
    mode: &str,
    payload_bytes: &[u8],
    char_len: usize,
) -> Result<ZeroizingString, String> {
    let profile = Profile::from_str(mode)?;
    validate_output_hex_len(char_len)?;
    Ok(hash_domain_bytes_xof(
        profile,
        OBJ_DOMAIN_FILE_DATA,
        payload_bytes,
        char_len,
    ))
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

fn open_regular_file_no_follow(path: &Path) -> io::Result<(File, fs::Metadata)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Target descriptor is not a regular file",
            ));
        }
        Ok((file, meta))
    }

    #[cfg(windows)]
    #[allow(unsafe_code)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;

        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(win_ffi::FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;

        let mut info = win_ffi::BY_HANDLE_FILE_INFORMATION::default();
        let ok = unsafe {
            win_ffi::GetFileInformationByHandle(
                file.as_raw_handle() as *mut core::ffi::c_void,
                &mut info,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if (info.dw_file_attributes & win_ffi::FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Refusing to follow reparse point / symlink",
            ));
        }
        if (info.dw_file_attributes & win_ffi::FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Target handle is a directory, not a regular file",
            ));
        }
        let meta = file.metadata()?;
        if !meta.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Target handle is not a regular file",
            ));
        }
        Ok((file, meta))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let sym_meta = fs::symlink_metadata(path)?;
        if !sym_meta.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Target is not a regular file",
            ));
        }
        let file = File::open(path)?;
        let meta = file.metadata()?;
        if !meta.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Target descriptor is not a regular file",
            ));
        }
        Ok((file, meta))
    }
}

fn hash_open_file_xof(
    profile: Profile,
    file: &mut File,
    target_char_len: usize,
) -> io::Result<(ZeroizingString, u64)> {
    validate_output_hex_len(target_char_len)
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;

    let block_size_bytes = profile.rate_bytes();
    let mut hasher = IthHasher::new_with_domain(profile, OBJ_DOMAIN_FILE_DATA);
    let mut read_buf = ZeroizingBuf::<READ_BUF_SIZE>::new();
    let mut bytes_hashed: u64 = 0;

    loop {
        let bytes_read = read_full(file, &mut read_buf.0)?;
        if bytes_read == 0 {
            break;
        }
        bytes_hashed = bytes_hashed.checked_add(bytes_read as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Hashed byte counter overflowed u64",
            )
        })?;

        for chunk in read_buf.0[..bytes_read].chunks(block_size_bytes) {
            hasher.absorb(chunk);
        }

        if bytes_read < READ_BUF_SIZE {
            break;
        }
    }

    drop(read_buf);
    Ok((hasher.squeeze_hex(target_char_len), bytes_hashed))
}

pub fn get_internal_tools_xof<P: AsRef<Path>>(
    profile: Profile,
    file_path: P,
    target_char_len: usize,
) -> io::Result<(ZeroizingString, u64)> {
    validate_output_hex_len(target_char_len)
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;

    let (mut file, _meta) = open_regular_file_no_follow(file_path.as_ref())?;
    hash_open_file_xof(profile, &mut file, target_char_len)
}

fn run_hash(
    profile: Profile,
    file_path: &Path,
    char_len: usize,
) -> io::Result<(ZeroizingString, u64)> {
    get_internal_tools_xof(profile, file_path, char_len)
}

fn encode_path_components(path: &Path, out: &mut Vec<u8>) {
    let components: Vec<_> = path.components().collect();
    let mut len_buf = ZeroizingBuf::<8>::new();
    len_buf.0 = (components.len() as u64).to_le_bytes();
    out.extend_from_slice(&len_buf.0);
    for comp in components {
        let bytes = comp.as_os_str().as_encoded_bytes();
        len_buf.0 = (bytes.len() as u64).to_le_bytes();
        out.extend_from_slice(&len_buf.0);
        out.extend_from_slice(bytes);
    }
}

fn special_file_type_label(
    #[cfg_attr(not(unix), allow(unused_variables))] ft: &fs::FileType,
) -> &'static str {
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

#[cfg(unix)]
fn special_mode_type_label(st_mode: u32) -> &'static str {
    match st_mode & libc::S_IFMT {
        libc::S_IFIFO => "fifo",
        libc::S_IFSOCK => "socket",
        libc::S_IFBLK => "block_device",
        libc::S_IFCHR => "char_device",
        _ => "other",
    }
}

fn metadata_mode_or_attributes(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.mode()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = meta;
        0u32
    }
}

fn metadata_special_rdev(
    #[cfg_attr(not(unix), allow(unused_variables))] meta: &fs::Metadata,
    #[cfg_attr(not(unix), allow(unused_variables))] ft: &fs::FileType,
) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if ft.is_block_device() || ft.is_char_device() {
            return Some(meta.rdev());
        }
    }
    None
}

struct DirStats {
    file_count: usize,
    dir_count: usize,
    symlink_count: usize,
    special_count: usize,
    total_size: u64,
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn open_dir_at(dir_fd: libc::c_int, path_os: & std::ffi::OsStr) -> io::Result<(File, fs::Metadata)> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;

    let c_path = CString::new(path_os.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Path contains interior NUL byte",
        )
    })?;

    let fd = unsafe {
        libc::openat(
            dir_fd,
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if !meta.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Opened descriptor is not a directory",
        ));
    }
    Ok((file, meta))
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn open_regular_file_at(
    dir_fd: libc::c_int,
    name_c: &std::ffi::CStr,
    expected_dev: u64,
    expected_ino: u64,
) -> io::Result<(File, fs::Metadata)> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::FromRawFd;

    let fd = unsafe {
        libc::openat(
            dir_fd,
            name_c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Opened entry descriptor is not a regular file",
        ));
    }
    if meta.dev() != expected_dev || meta.ino() != expected_ino {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TOCTOU race detected: file inode/device changed between fstatat and openat",
        ));
    }
    Ok((file, meta))
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn read_link_at(dir_fd: libc::c_int, name_c: &std::ffi::CStr) -> io::Result<OsString> {
    use std::os::unix::ffi::OsStringExt;

    let mut buf_size: usize = 256;
    loop {
        let mut buf = vec![0u8; buf_size];
        let len = unsafe {
            libc::readlinkat(
                dir_fd,
                name_c.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        let len = len as usize;
        if len < buf.len() {
            buf.truncate(len);
            return Ok(OsString::from_vec(buf));
        }
        if buf_size >= 65_536 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Symlink target exceeds 64 KiB maximum length",
            ));
        }
        buf_size *= 2;
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn list_pinned_dir_names(dir_file: &File, fallback_path: &Path) -> io::Result<Vec<OsString>> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let raw_fd = dir_file.as_raw_fd();
    let dup_fd = unsafe { libc::dup(raw_fd) };
    if dup_fd >= 0 {
        let dup_file = unsafe { File::from_raw_fd(dup_fd) };
        let fd_path = format!("/dev/fd/{}", dup_file.as_raw_fd());
        if let Ok(rd) = fs::read_dir(&fd_path) {
            let mut names = Vec::new();
            for entry in rd {
                names.push(entry?.file_name());
            }
            return Ok(names);
        }
    }

    let fd_meta = dir_file.metadata()?;
    let path_meta = fs::symlink_metadata(fallback_path)?;
    if fd_meta.dev() != path_meta.dev() || fd_meta.ino() != path_meta.ino() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TOCTOU race detected: directory inode changed during traversal",
        ));
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(fallback_path)? {
        names.push(entry?.file_name());
    }
    Ok(names)
}

#[cfg(unix)]
enum UnixWorkItem {
    Dir {
        dir_file: Arc<File>,
        rel_dir: PathBuf,
        display_path: PathBuf,
        depth: usize,
    },
    Entry {
        parent_dir: Arc<File>,
        entry_name: OsString,
        rel_path: PathBuf,
        display_path: PathBuf,
        depth: usize,
    },
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn collect_directory_entries(
    root_dir: &Path,
    profile: Profile,
    max_depth: usize,
    stats: &mut DirStats,
    entries_out: &mut Vec<ZeroizingString>,
) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;

    let (root_file, _root_meta) = open_dir_at(libc::AT_FDCWD, root_dir.as_os_str())?;
    let mut stack = vec![UnixWorkItem::Dir {
        dir_file: Arc::new(root_file),
        rel_dir: PathBuf::new(),
        display_path: root_dir.to_path_buf(),
        depth: 0,
    }];

    while let Some(item) = stack.pop() {
        match item {
            UnixWorkItem::Dir {
                dir_file,
                rel_dir,
                display_path,
                depth,
            } => {
                let mut sorted_names = list_pinned_dir_names(&dir_file, &display_path)?;
                sorted_names.sort_by(|a, b| a.as_encoded_bytes().cmp(b.as_encoded_bytes()));

                for entry_name in sorted_names.into_iter().rev() {
                    let rel_path = if rel_dir.as_os_str().is_empty() {
                        PathBuf::from(&entry_name)
                    } else {
                        rel_dir.join(&entry_name)
                    };
                    let child_display = display_path.join(&entry_name);
                    stack.push(UnixWorkItem::Entry {
                        parent_dir: Arc::clone(&dir_file),
                        entry_name,
                        rel_path,
                        display_path: child_display,
                        depth,
                    });
                }
            }
            UnixWorkItem::Entry {
                parent_dir,
                entry_name,
                rel_path,
                display_path,
                depth,
            } => {
                let c_name = CString::new(entry_name.as_bytes()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Directory entry contains interior NUL byte",
                    )
                })?;

                #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
                let (st_mode, st_dev, st_ino, st_rdev) = {
                    let mut st: libc::stat = unsafe { core::mem::zeroed() };
                    let rc = unsafe {
                        libc::fstatat(
                            parent_dir.as_raw_fd(),
                            c_name.as_ptr(),
                            &mut st,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    };
                    if rc < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    (
                        st.st_mode as u32,
                        st.st_dev as u64,
                        st.st_ino as u64,
                        st.st_rdev as u64,
                    )
                };

                #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
                let (st_mode, st_dev, st_ino, st_rdev) = {
                    let sym_meta = fs::symlink_metadata(&display_path)?;
                    (
                        sym_meta.mode(),
                        sym_meta.dev(),
                        sym_meta.ino(),
                        sym_meta.rdev(),
                    )
                };

                let file_kind = st_mode & libc::S_IFMT;
                let mut record = ZeroizingVec::with_capacity(256);

                if file_kind == libc::S_IFLNK {
                    stats.symlink_count += 1;
                    let target = read_link_at(parent_dir.as_raw_fd(), &c_name)?;
                    let target_bytes = target.as_encoded_bytes();

                    record.0.extend_from_slice(b"SYMLINK:");
                    encode_path_components(&rel_path, &mut record.0);
                    record.0.extend_from_slice(b"TARGET:");
                    record
                        .0
                        .extend_from_slice(&(target_bytes.len() as u64).to_le_bytes());
                    record.0.extend_from_slice(target_bytes);

                    entries_out.push(hash_domain_bytes_xof(
                        profile,
                        OBJ_DOMAIN_MERKLE_LEAF,
                        &record.0,
                        INTERNAL_HASH_HEX_LEN,
                    ));
                } else if file_kind == libc::S_IFDIR {
                    stats.dir_count += 1;
                    let (child_dir, child_meta) =
                        open_dir_at(parent_dir.as_raw_fd(), entry_name.as_os_str())?;
                    if child_meta.dev() != st_dev || child_meta.ino() != st_ino {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "TOCTOU race detected: subdirectory inode/device changed between fstatat and openat",
                        ));
                    }

                    let mode_bits = metadata_mode_or_attributes(&child_meta);
                    record.0.extend_from_slice(b"DIR:");
                    encode_path_components(&rel_path, &mut record.0);
                    record.0.extend_from_slice(&mode_bits.to_le_bytes());

                    entries_out.push(hash_domain_bytes_xof(
                        profile,
                        OBJ_DOMAIN_MERKLE_LEAF,
                        &record.0,
                        INTERNAL_HASH_HEX_LEN,
                    ));

                    if depth >= max_depth {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!(
                                "Maximum directory traversal depth ({}) exceeded at '{}'",
                                max_depth,
                                sanitize_path_display(&display_path)
                            ),
                        ));
                    }

                    stack.push(UnixWorkItem::Dir {
                        dir_file: Arc::new(child_dir),
                        rel_dir: rel_path,
                        display_path,
                        depth: depth + 1,
                    });
                } else if file_kind == libc::S_IFREG {
                    stats.file_count += 1;
                    let (mut child_file, child_meta) =
                        open_regular_file_at(parent_dir.as_raw_fd(), &c_name, st_dev, st_ino)?;
                    let (content_hash, bytes_hashed) =
                        hash_open_file_xof(profile, &mut child_file, INTERNAL_HASH_HEX_LEN)?;

                    stats.total_size =
                        stats.total_size.checked_add(bytes_hashed).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "Total size overflowed u64")
                        })?;

                    let mode_bits = metadata_mode_or_attributes(&child_meta);
                    record.0.extend_from_slice(b"FILE:");
                    encode_path_components(&rel_path, &mut record.0);
                    record.0.extend_from_slice(&mode_bits.to_le_bytes());
                    record.0.extend_from_slice(&bytes_hashed.to_le_bytes());
                    record.0.extend_from_slice(content_hash.as_bytes());

                    entries_out.push(hash_domain_bytes_xof(
                        profile,
                        OBJ_DOMAIN_MERKLE_LEAF,
                        &record.0,
                        INTERNAL_HASH_HEX_LEN,
                    ));
                } else {
                    stats.special_count += 1;
                    let kind_label = if let Ok(sym_meta) = fs::symlink_metadata(&display_path) {
                        special_file_type_label(&sym_meta.file_type())
                    } else {
                        special_mode_type_label(st_mode)
                    };

                    eprintln!(
                        "{}Warning: special file ({}) encountered at '{}'{}",
                        COLOR_YELLOW,
                        kind_label,
                        sanitize_path_display(&display_path),
                        COLOR_RESET
                    );

                    record.0.extend_from_slice(b"SPECIAL:");
                    encode_path_components(&rel_path, &mut record.0);
                    record.0.extend_from_slice(&st_mode.to_le_bytes());
                    record
                        .0
                        .extend_from_slice(&(kind_label.len() as u64).to_le_bytes());
                    record.0.extend_from_slice(kind_label.as_bytes());
                    if file_kind == libc::S_IFBLK || file_kind == libc::S_IFCHR {
                        record.0.extend_from_slice(b"RDEV:");
                        record.0.extend_from_slice(&st_rdev.to_le_bytes());
                    }

                    entries_out.push(hash_domain_bytes_xof(
                        profile,
                        OBJ_DOMAIN_MERKLE_LEAF,
                        &record.0,
                        INTERNAL_HASH_HEX_LEN,
                    ));
                }
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn open_pinned_dir_windows(path: &Path) -> io::Result<(File, u32)> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    let dir_handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            win_ffi::FILE_FLAG_OPEN_REPARSE_POINT | win_ffi::FILE_FLAG_BACKUP_SEMANTICS,
        )
        .open(path)?;

    let mut info = win_ffi::BY_HANDLE_FILE_INFORMATION::default();
    let ok = unsafe {
        win_ffi::GetFileInformationByHandle(
            dir_handle.as_raw_handle() as *mut core::ffi::c_void,
            &mut info,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if (info.dw_file_attributes & win_ffi::FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Refusing to traverse directory reparse point / symlink",
        ));
    }
    if (info.dw_file_attributes & win_ffi::FILE_ATTRIBUTE_DIRECTORY) == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Target handle is not a directory",
        ));
    }
    Ok((dir_handle, info.dw_file_attributes))
}

#[cfg(not(unix))]
enum WorkItem {
    Dir { path: PathBuf, depth: usize },
    Entry { entry: fs::DirEntry, depth: usize },
}

#[cfg(not(unix))]
fn collect_directory_entries(
    root_dir: &Path,
    profile: Profile,
    max_depth: usize,
    stats: &mut DirStats,
    entries_out: &mut Vec<ZeroizingString>,
) -> io::Result<()> {
    let mut stack = vec![WorkItem::Dir {
        path: root_dir.to_path_buf(),
        depth: 0,
    }];

    while let Some(item) = stack.pop() {
        match item {
            WorkItem::Dir { path, depth } => {
                #[cfg(windows)]
                let _pinned_dir = open_pinned_dir_windows(&path)?;

                let mut sorted_entries = Vec::new();
                for entry in fs::read_dir(&path)? {
                    sorted_entries.push(entry?);
                }
                sorted_entries.sort_by(|a, b| {
                    a.file_name()
                        .as_encoded_bytes()
                        .cmp(b.file_name().as_encoded_bytes())
                });

                for entry in sorted_entries.into_iter().rev() {
                    stack.push(WorkItem::Entry { entry, depth });
                }
            }
            WorkItem::Entry { entry, depth } => {
                let path = entry.path();
                let sym_meta = fs::symlink_metadata(&path)?;
                let file_type = sym_meta.file_type();
                let rel_path = path.strip_prefix(root_dir).unwrap_or(&path);

                let mut record = ZeroizingVec::with_capacity(256);

                if file_type.is_symlink() {
                    stats.symlink_count += 1;
                    let target = fs::read_link(&path)?;
                    let target_bytes = target.as_os_str().as_encoded_bytes();

                    record.0.extend_from_slice(b"SYMLINK:");
                    encode_path_components(rel_path, &mut record.0);
                    record.0.extend_from_slice(b"TARGET:");
                    record
                        .0
                        .extend_from_slice(&(target_bytes.len() as u64).to_le_bytes());
                    record.0.extend_from_slice(target_bytes);

                    entries_out.push(hash_domain_bytes_xof(
                        profile,
                        OBJ_DOMAIN_MERKLE_LEAF,
                        &record.0,
                        INTERNAL_HASH_HEX_LEN,
                    ));
                } else if file_type.is_dir() {
                    stats.dir_count += 1;
                    #[cfg(windows)]
                    let (_pinned_subdir, mode_bits) = open_pinned_dir_windows(&path)?;
                    #[cfg(not(windows))]
                    let mode_bits = metadata_mode_or_attributes(&sym_meta);

                    record.0.extend_from_slice(b"DIR:");
                    encode_path_components(rel_path, &mut record.0);
                    record.0.extend_from_slice(&mode_bits.to_le_bytes());
                    entries_out.push(hash_domain_bytes_xof(
                        profile,
                        OBJ_DOMAIN_MERKLE_LEAF,
                        &record.0,
                        INTERNAL_HASH_HEX_LEN,
                    ));

                    if depth >= max_depth {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!(
                                "Maximum directory traversal depth ({}) exceeded at '{}'",
                                max_depth,
                                sanitize_path_display(&path)
                            ),
                        ));
                    }

                    stack.push(WorkItem::Dir {
                        path,
                        depth: depth + 1,
                    });
                } else if file_type.is_file() {
                    stats.file_count += 1;
                    let (mut file, file_meta) = open_regular_file_no_follow(&path)?;
                    let (content_hash, bytes_hashed) =
                        hash_open_file_xof(profile, &mut file, INTERNAL_HASH_HEX_LEN)?;
                    stats.total_size =
                        stats.total_size.checked_add(bytes_hashed).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "Total size overflowed u64")
                        })?;

                    let mode_bits = metadata_mode_or_attributes(&file_meta);
                    record.0.extend_from_slice(b"FILE:");
                    encode_path_components(rel_path, &mut record.0);
                    record.0.extend_from_slice(&mode_bits.to_le_bytes());
                    record.0.extend_from_slice(&bytes_hashed.to_le_bytes());
                    record.0.extend_from_slice(content_hash.as_bytes());
                    entries_out.push(hash_domain_bytes_xof(
                        profile,
                        OBJ_DOMAIN_MERKLE_LEAF,
                        &record.0,
                        INTERNAL_HASH_HEX_LEN,
                    ));
                } else {
                    stats.special_count += 1;
                    let kind_label = special_file_type_label(&file_type);
                    eprintln!(
                        "{}Warning: special file ({}) encountered at '{}'{}",
                        COLOR_YELLOW,
                        kind_label,
                        sanitize_path_display(&path),
                        COLOR_RESET
                    );

                    let mode_bits = metadata_mode_or_attributes(&sym_meta);
                    record.0.extend_from_slice(b"SPECIAL:");
                    encode_path_components(rel_path, &mut record.0);
                    record.0.extend_from_slice(&mode_bits.to_le_bytes());
                    record
                        .0
                        .extend_from_slice(&(kind_label.len() as u64).to_le_bytes());
                    record.0.extend_from_slice(kind_label.as_bytes());
                    if let Some(rdev) = metadata_special_rdev(&sym_meta, &file_type) {
                        record.0.extend_from_slice(b"RDEV:");
                        record.0.extend_from_slice(&rdev.to_le_bytes());
                    }
                    entries_out.push(hash_domain_bytes_xof(
                        profile,
                        OBJ_DOMAIN_MERKLE_LEAF,
                        &record.0,
                        INTERNAL_HASH_HEX_LEN,
                    ));
                }
            }
        }
    }

    Ok(())
}

fn compute_merkle_root(
    profile: Profile,
    hashes: Vec<ZeroizingString>,
    final_char_len: usize,
) -> ZeroizingString {
    let leaf_count = hashes.len();
    if leaf_count == 0 {
        return hash_domain_bytes_xof(
            profile,
            OBJ_DOMAIN_DIR_ROOT,
            b"ROOT_FINAL:0:MERKLE_EMPTY_TREE",
            final_char_len,
        );
    }

    let mut current_level: Vec<ZeroizingString> = hashes
        .into_iter()
        .map(|entry_hash| {
            let leaf_payload = ZeroizingString::new(format!("LEAF:{}", entry_hash.as_str()));
            hash_domain_bytes_xof(
                profile,
                OBJ_DOMAIN_MERKLE_LEAF,
                leaf_payload.as_bytes(),
                INTERNAL_HASH_HEX_LEN,
            )
        })
        .collect();

    if current_level.len() == 1 {
        let single = current_level.remove(0);
        let single_combined = ZeroizingString::new(format!("NODE_ODD:{}", single.as_str()));
        let single_node = hash_domain_bytes_xof(
            profile,
            OBJ_DOMAIN_MERKLE_NODE,
            single_combined.as_bytes(),
            INTERNAL_HASH_HEX_LEN,
        );
        let root_payload =
            ZeroizingString::new(format!("ROOT_FINAL:{}:{}", leaf_count, single_node.as_str()));
        return hash_domain_bytes_xof(
            profile,
            OBJ_DOMAIN_DIR_ROOT,
            root_payload.as_bytes(),
            final_char_len,
        );
    }

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                let combined =
                    ZeroizingString::new(format!("NODE:{}:{}", chunk[0].as_str(), chunk[1].as_str()));
                next_level.push(hash_domain_bytes_xof(
                    profile,
                    OBJ_DOMAIN_MERKLE_NODE,
                    combined.as_bytes(),
                    INTERNAL_HASH_HEX_LEN,
                ));
            } else {
                let combined = ZeroizingString::new(format!("NODE_ODD:{}", chunk[0].as_str()));
                next_level.push(hash_domain_bytes_xof(
                    profile,
                    OBJ_DOMAIN_MERKLE_NODE,
                    combined.as_bytes(),
                    INTERNAL_HASH_HEX_LEN,
                ));
            }
        }
        current_level = next_level;
    }

    let root = current_level.remove(0);
    let root_payload = ZeroizingString::new(format!("ROOT_FINAL:{}:{}", leaf_count, root.as_str()));
    hash_domain_bytes_xof(
        profile,
        OBJ_DOMAIN_DIR_ROOT,
        root_payload.as_bytes(),
        final_char_len,
    )
}

fn is_valid_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_prefixed_usize(
    raw: &str,
    lower: &str,
    prefixes: &[&str],
) -> Option<Result<usize, String>> {
    for prefix in prefixes {
        if lower.starts_with(prefix) {
            let rest = &raw[prefix.len()..];
            return Some(rest.parse::<usize>().map_err(|_| {
                format!(
                    "invalid numeric value for '{}': '{}'",
                    prefix,
                    sanitize_display(rest)
                )
            }));
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
    println!("  /check                : verify <path> against <expected_hash> (defaults strictly to {} chars unless /len:<N> is set)", INTERNAL_HASH_HEX_LEN);
    println!(
        "  /len:<N>              : explicit even output/expected hex length ({}..={}, even only)",
        MIN_CHECK_HEX_LEN, MAX_OUTPUT_HEX_LEN
    );
    println!(
        "  /maxdepth:<N>         : max directory traversal depth (default: {})",
        DEFAULT_MAX_DEPTH
    );
    println!("  --                    : end of flags; treat all remaining arguments as positional");
}

fn verify_or_print(computed: &str, check_mode: bool, expected_hash: Option<ZeroizingString>) {
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
            println!(
                "{} [OK] Hash matches! {}{}",
                COLOR_GREEN, computed, COLOR_RESET
            );
        } else {
            eprintln!("{} [FAIL] Hash mismatch! {}", COLOR_RED, COLOR_RESET);
            eprintln!(
                "{}Expected: {}{}",
                COLOR_CYAN,
                sanitize_display(expected.as_str()),
                COLOR_RESET
            );
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
                    s,
                    &lower,
                    &["/len:", "--len:", "-len:", "/len=", "--len=", "-len="],
                ) {
                    match parsed {
                        Ok(n) => {
                            if let Err(msg) = validate_output_hex_len(n) {
                                eprintln!("{}Error: /len: {}{}", COLOR_RED, msg, COLOR_RESET);
                                std::process::exit(1);
                            }
                            explicit_len = Some(n);
                            continue;
                        }
                        Err(msg) => {
                            eprintln!("{}Error: {}{}", COLOR_RED, msg, COLOR_RESET);
                            std::process::exit(1);
                        }
                    }
                }

                if let Some(parsed) = parse_prefixed_usize(
                    s,
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

    let profile = match Profile::from_str(mode) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("{}Error: {}{}", COLOR_RED, msg, COLOR_RESET);
            std::process::exit(1);
        }
    };

    if merkle_mode && !folder_mode {
        eprintln!(
            "{}Error: /usemerkletree can only be used with /folder.{}",
            COLOR_RED, COLOR_RESET
        );
        std::process::exit(1);
    }

    let target_path: PathBuf;
    let expected_hash: Option<ZeroizingString>;
    let char_len: usize;

    if check_mode {
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

        if let Err(msg) = validate_output_hex_len(expected_str.len()) {
            eprintln!(
                "{}Error in /check expected hash: {}.{}",
                COLOR_RED, msg, COLOR_RESET
            );
            std::process::exit(1);
        }

        let required_len = explicit_len.unwrap_or(INTERNAL_HASH_HEX_LEN);
        if expected_str.len() != required_len {
            if explicit_len.is_some() {
                eprintln!(
                    "{}Error: expected hash length ({}) does not match explicit /len:{} requirement.{}",
                    COLOR_RED,
                    expected_str.len(),
                    required_len,
                    COLOR_RESET
                );
            } else {
                eprintln!(
                    "{}Error: /check defaults strictly to the canonical {}-char (512-bit) digest length (got {} chars). Pass /len:{} explicitly to verify a non-default digest length.{}",
                    COLOR_RED,
                    INTERNAL_HASH_HEX_LEN,
                    expected_str.len(),
                    expected_str.len(),
                    COLOR_RESET
                );
            }
            std::process::exit(1);
        }
        char_len = required_len;
        expected_hash = Some(ZeroizingString::new(expected_str.to_ascii_lowercase()));
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
            let parsed_len = len_arg.to_str().and_then(|s| s.parse::<usize>().ok());

            match parsed_len {
                Some(n) => {
                    if let Err(msg) = validate_output_hex_len(n) {
                        eprintln!("{}Error: {}{}", COLOR_RED, msg, COLOR_RESET);
                        std::process::exit(1);
                    }
                    char_len = n;
                }
                None => {
                    eprintln!(
                        "{}Error: invalid output_length '{}'. Use /len:<N> or an even integer ({}..={}).{}",
                        COLOR_RED,
                        sanitize_path_display(Path::new(len_arg)),
                        MIN_CHECK_HEX_LEN,
                        MAX_OUTPUT_HEX_LEN,
                        COLOR_RESET
                    );
                    std::process::exit(1);
                }
            }
        } else {
            char_len = explicit_len.unwrap_or(INTERNAL_HASH_HEX_LEN);
        }
    }

    if folder_mode {
        let mut stats = DirStats {
            file_count: 0,
            dir_count: 0,
            symlink_count: 0,
            special_count: 0,
            total_size: 0,
        };
        let mut leaf_hashes = Vec::new();

        if let Err(e) = collect_directory_entries(
            &target_path,
            profile,
            max_depth,
            &mut stats,
            &mut leaf_hashes,
        ) {
            eprintln!(
                "{}Error scanning directory '{}': {}{}",
                COLOR_RED,
                sanitize_path_display(&target_path),
                sanitize_display(&e.to_string()),
                COLOR_RESET
            );
            std::process::exit(1);
        }

        let digest = if merkle_mode {
            compute_merkle_root(profile, leaf_hashes, char_len)
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
                manifest.push_str(h.as_str());
                manifest.push('\n');
            }
            let manifest_zeroizing = ZeroizingString::new(manifest);
            hash_domain_bytes_xof(
                profile,
                OBJ_DOMAIN_DIR_ROOT,
                manifest_zeroizing.as_bytes(),
                char_len,
            )
        };

        if !check_mode {
            let label = if merkle_mode {
                "Directory Merkle Root Hash"
            } else {
                "Directory Content Hash"
            };
            println!(
                "=== {}: {} ===",
                label,
                sanitize_path_display(&target_path)
            );
            println!(
                "Files: {}, Folders: {}, Symlinks: {}, Special: {}, Total size: {} bytes",
                stats.file_count,
                stats.dir_count,
                stats.symlink_count,
                stats.special_count,
                stats.total_size
            );
        }

        verify_or_print(digest.as_str(), check_mode, expected_hash);
        return;
    }

    match run_hash(profile, &target_path, char_len) {
        Ok((computed, _bytes_hashed)) => {
            verify_or_print(computed.as_str(), check_mode, expected_hash)
        }
        Err(e) => {
            eprintln!(
                "{}Error reading target file '{}': {}{}",
                COLOR_RED,
                sanitize_path_display(&target_path),
                sanitize_display(&e.to_string()),
                COLOR_RESET
            );
            std::process::exit(1);
        }
    }
}
