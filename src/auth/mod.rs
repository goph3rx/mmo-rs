//! Auth server implementation.
mod crypt;
mod message;
mod sender;

/// Size of the packet header.
pub const HEADER_SIZE: usize = 2;
/// Size of the buffers for IO, packet bodies cannot exceed this.
pub const BUFFER_SIZE: usize = 1024;
/// Size of the block for IO operations.
pub const BLOCK_SIZE: usize = 4;
/// Initial encryption key for the traffic.
pub const INIT_KEY: &[u8] = &[
    0x6B, 0x60, 0xCB, 0x5B, 0x82, 0xCE, 0x90, 0xB1, 0xCC, 0x2B, 0x6C, 0x55, 0x6C, 0x6C, 0x6C, 0x6C,
];
