//! Low-level primitives for IO operations.

use std::io::{Read, Result, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

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

    /// Write H value (2 bytes).
    #[inline]
    fn write_h(&mut self, n: i16) -> Result<()> {
        self.write_i16::<LittleEndian>(n)
    }

    /// Write D value (4 bytes).
    #[inline]
    fn write_d(&mut self, n: i32) -> Result<()> {
        self.write_i32::<LittleEndian>(n)
    }
}

impl<T: Write> WriteMMO for T {}

/// Extends the reader to support reading MMO values.
pub trait ReadMMO: Read {
    /// Read H value (2 bytes).
    #[inline]
    fn read_h(&mut self) -> Result<i16> {
        self.read_i16::<LittleEndian>()
    }

    /// Read D value (4 bytes).
    #[inline]
    fn read_d(&mut self) -> Result<i32> {
        self.read_i32::<LittleEndian>()
    }
}

impl<T: Read> ReadMMO for T {}

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
    fn write_h() {
        // Arrange
        let mut buffer = vec![0; BUFFER_SIZE];
        let mut writer = Cursor::new(&mut buffer);

        // Act
        let result = writer.write_h(0x105c);

        // Assert
        let position = writer.position() as usize;
        assert_eq!(result.is_ok(), true);
        assert_eq!(position, 2);
        assert_eq!(hex::encode(&buffer[..position]), "5c10");
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

    #[test]
    fn read_h() {
        // Arrange
        let buffer = hex::decode("7b10").expect("Failed to decode buffer");
        let mut reader = Cursor::new(&buffer);

        // Act
        let result = reader.read_h();

        // Assert
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap(), 0x107b);
    }

    #[test]
    fn read_d() {
        // Arrange
        let buffer = hex::decode("7b6a5c10").expect("Failed to decode buffer");
        let mut reader = Cursor::new(&buffer);

        // Act
        let result = reader.read_d();

        // Assert
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap(), 0x105C6A7B);
    }
}
