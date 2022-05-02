use crate::auth::crypt::{blowfish_compat, scramble_init, AuthClientCrypt};
use crate::auth::message::{encode, ServerMessage};
use crate::auth::{BLOCK_SIZE, BUFFER_SIZE, HEADER_SIZE};
use crate::io::{ReadMMO, WriteMMO};
use log::debug;
use mockall::automock;
use openssl::rand::rand_bytes;
use openssl::symm::Cipher;
use std::io::{Cursor, Error, ErrorKind, Result, Write};
use std::sync::{Arc, Mutex};

pub struct AuthClientSenderImpl {
    writer: Box<dyn Write + Send>,
    packet: Vec<u8>,
    buffer: Vec<u8>,
    crypt: Arc<Mutex<AuthClientCrypt>>,
}

#[automock]
pub trait AuthClientSender: Send {
    fn send(&mut self, msg: ServerMessage) -> Result<()>;
}

impl AuthClientSenderImpl {
    pub fn new(writer: Box<dyn Write + Send>, crypt: Arc<Mutex<AuthClientCrypt>>) -> Box<Self> {
        Box::new(Self {
            writer,
            packet: vec![0; BUFFER_SIZE],
            buffer: vec![0; BUFFER_SIZE],
            crypt,
        })
    }

    #[inline]
    fn pad(&self, size: usize, block_size: usize) -> Result<usize> {
        let size = if size % block_size != 0 {
            size + (block_size - size % block_size)
        } else {
            size
        };
        if size < BUFFER_SIZE {
            Ok(size)
        } else {
            Err(Error::new(ErrorKind::InvalidData, format!("Buffer size ({}) exceeded limit ({})", size, BUFFER_SIZE)))
        }
    }
}

impl AuthClientSender for AuthClientSenderImpl {
    fn send(&mut self, msg: ServerMessage) -> Result<()> {
        debug!("Sending {:?}", msg);
        let new_crypt_key = if let ServerMessage::Init { crypt_key, .. } = msg {
            Some(crypt_key)
        } else {
            None
        };

        // Reset buffers for writing
        self.packet.fill(0);
        self.buffer.fill(0);

        // Encode the message
        let mut writer = Cursor::new(&mut self.packet);
        encode(msg, &mut writer)?;
        let mut size = writer.position() as usize;

        // Checksum
        size = self.pad(size, BLOCK_SIZE)?;
        let checksum = 0;
        Cursor::new(&mut self.packet[size..]).write_d(checksum)?;
        size += BLOCK_SIZE;

        // Additional encryption for the first packet
        if new_crypt_key.is_some() {
            let mut key = [0u8; 4];
            rand_bytes(&mut key)?;

            size = self.pad(size, BLOCK_SIZE)?;
            scramble_init(&mut self.packet, size, Cursor::new(key).read_d()?)?;
            size += BLOCK_SIZE;
        }

        // Encryption
        size = self.pad(size, BLOCK_SIZE)?;
        blowfish_compat(&mut self.packet[..size]);
        size = self.pad(size, Cipher::bf_ecb().block_size())?;
        {
            let mut crypt = self
                .crypt
                .lock()
                .map_err(|_| Error::new(ErrorKind::Other, "Cannot unlock crypt"))?;
            size = crypt
                .encrypt
                .update(&self.packet[..size], &mut self.buffer)?;

            // Change key
            if new_crypt_key.is_some() {
                crypt.update_key(&new_crypt_key.unwrap())?;
            }
        }
        blowfish_compat(&mut self.buffer[..size]);

        // Header
        let mut header: [u8; HEADER_SIZE] = [0; HEADER_SIZE];
        Cursor::new(&mut header[..]).write_h((size + HEADER_SIZE) as i16)?;

        // Send
        self.writer.write_all(&header)?;
        self.writer.write_all(&self.buffer[..size])?;
        self.writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::INIT_KEY;
    use mockall::{mock, predicate};
    use std::io::Write;

    mock! {
        Writer {}
        impl Write for Writer {
            fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> { todo!() }
            fn flush(&mut self) -> std::result::Result<(), std::io::Error> { todo!() }
        }
    }

    #[test]
    fn send_init() {
        // Arrange
        let mut writer = Box::new(MockWriter::new());
        writer
            .expect_write()
            .with(predicate::function(|buf: &[u8]| buf.len() == 2))
            .times(1)
            .returning(|_| Ok(2));
        writer
            .expect_write()
            .with(predicate::function(|buf: &[u8]| buf.len() == 184))
            .times(1)
            .returning(|_| Ok(184));
        writer.expect_flush().times(1).returning(|| Ok(()));

        let crypt = AuthClientCrypt::new(INIT_KEY).expect("Failed to create crypt");
        let mut sender = AuthClientSenderImpl::new(writer, crypt);

        // Act
        let result = sender.send(ServerMessage::Init {
            session_id: 0,
            modulus: [0; 128],
            crypt_key: [0; 16],
        });

        // Assert
        assert_eq!(result.is_ok(), true);
    }
}
