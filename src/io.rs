//! Low-level primitives for IO operations.

use std::io::{Result, Write};

use byteorder::{LittleEndian, WriteBytesExt};

/// Extends the writer to support writing MMO values.
pub trait WriteMMO: Write {
    /// Write B value.
    #[inline]
    fn write_b(&mut self, buf: &[u8]) -> Result<()> {
        self.write_all(buf)
    }

    /// Write C value (1 byte).
    #[inline]
    fn write_c(&mut self, n: i8) -> Result<()> {
        self.write_i8(n)
    }

    /// Write D value (4 bytes).
    #[inline]
    fn write_d(&mut self, n: i32) -> Result<()> {
        self.write_i32::<LittleEndian>(n)
    }
}

impl<T: Write> WriteMMO for T {}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    const BUFFER_SIZE: usize = 1024;

    #[test]
    fn write_b() {
        // Arrange
        let mut buffer = vec![0; BUFFER_SIZE];
        let mut writer = Cursor::new(&mut buffer);

        // Act
        let result = writer.write_b(&[1, 2, 3]);

        // Assert
        let position = writer.position() as usize;
        assert_eq!(result.is_ok(), true);
        assert_eq!(position, 3);
        assert_eq!(hex::encode(&buffer[..position]), "010203");
    }

    #[test]
    fn write_c() {
        // Arrange
        let mut buffer = vec![0; BUFFER_SIZE];
        let mut writer = Cursor::new(&mut buffer);

        // Act
        let result = writer.write_c(0x7b);

        // Assert
        let position = writer.position() as usize;
        assert_eq!(result.is_ok(), true);
        assert_eq!(position, 1);
        assert_eq!(hex::encode(&buffer[..position]), "7b");
    }

    #[test]
    fn write_d() {
        // Arrange
        let mut buffer = vec![0; BUFFER_SIZE];
        let mut writer = Cursor::new(&mut buffer);

        // Act
        let result = writer.write_d(0x105c6a7b);

        // Assert
        let position = writer.position() as usize;
        assert_eq!(result.is_ok(), true);
        assert_eq!(position, 4);
        assert_eq!(hex::encode(&buffer[..position]), "7b6a5c10");
    }
}
