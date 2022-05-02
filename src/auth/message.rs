use crate::auth::crypt::scramble_modulus;
use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom, Write};

use crate::io::{ReadMMO, WriteMMO};

#[derive(Debug)]
pub enum GGAuthResult {
    Skip = 0x0b,
}

#[derive(Debug)]
pub enum ServerMessage {
    Init {
        session_id: i32,
        modulus: [u8; 128],
        crypt_key: [u8; 16],
    },
    GGAuth {
        result: GGAuthResult,
    },
}

const PROTOCOL_VERSION: i32 = 0xc621;

pub fn encode(msg: ServerMessage, io: &mut (impl Write + Seek)) -> Result<()> {
    match msg {
        ServerMessage::Init {
            session_id,
            mut modulus,
            crypt_key,
        } => {
            scramble_modulus(&mut modulus);

            io.write_c(0x00)?;
            io.write_d(session_id)?;
            io.write_d(PROTOCOL_VERSION)?;
            io.write_b(&modulus)?;
            io.seek(SeekFrom::Current(16))?;
            io.write_b(&crypt_key)?;
        }
        ServerMessage::GGAuth { result } => {
            io.write_c(0x0b)?;
            io.write_d(result as i32)?;
            io.seek(SeekFrom::Current(16))?;
        }
    }
    Ok(())
}

#[derive(PartialEq, Debug)]
pub enum ClientMessage {
    AuthGameGuard {},
}

pub fn decode(io: &mut (impl Read + Seek)) -> Result<ClientMessage> {
    match io.read_c()? {
        0x07 => Ok(ClientMessage::AuthGameGuard {}),
        id => Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid packet id (0x{:02x})", id),
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::auth::BUFFER_SIZE;
    use std::io::Cursor;

    use super::*;

    #[test]
    fn server_init() {
        // Arrange
        let mut buffer = vec![0; BUFFER_SIZE];
        let mut writer = Cursor::new(&mut buffer);
        let msg = ServerMessage::Init{
            session_id: -559038737,
            modulus: hex::decode("9a277669023723947d0ebdccef967a24c715018df6ce66414fccd0f5bab54124b8caac6d7f52f8bbbab7de926b4f0ac4cc84793196e44928774a57737d0e4ee02962952257506e898846e353fa5fee31409a1d32124fb8df53d969dd7aa222866fa85e106f8a07e333d8ded4b10a8300b32d5f47cc5eab14033fa2bc0950b5c9").
                expect("Fail to decode modulus").
                try_into().
                expect("Invalid modulus length"),
            crypt_key: hex::decode("0102030405060708090a0b0c0d0e0f10").
                expect("Failed to decode crypt key").
                try_into().
                expect("Invalid crypt key length"),
        };

        // Act
        let result = encode(msg, &mut writer);

        // Assert
        let position = writer.position() as usize;
        assert_eq!(result.is_ok(), true);
        assert_eq!(position, 1 + 4 + 4 + 128 + 16 + 16);
        assert_eq!(hex::encode(&buffer[..position]), "00efbeadde21c60000768ca46255674d1df5485e9f1556e7b0928f1cbfe481de9e1c15b928c01763a2d762f27d10d8ff58896f0046da4589c47fa926765abae23c7475f5cf745efb295fee3140023723947d0ebdccefccc0c6fb15018df6ce66414fccd0f5bab54124b8caac6d7f52f8bbbab7de926b4f0ac4cc84793196e44928774a57737d0e4ee0000000000000000000000000000000000102030405060708090a0b0c0d0e0f10");
    }

    #[test]
    fn server_gg_auth() {
        // Arrange
        let mut buffer = vec![0; BUFFER_SIZE];
        let mut writer = Cursor::new(&mut buffer);
        let msg = ServerMessage::GGAuth {
            result: GGAuthResult::Skip,
        };

        // Act
        let result = encode(msg, &mut writer);

        // Assert
        let position = writer.position() as usize;
        assert_eq!(result.is_ok(), true);
        assert_eq!(position, 1 + 4 + 16);
        assert_eq!(
            hex::encode(&buffer[..position]),
            "0b0b00000000000000000000000000000000000000"
        );
    }

    #[test]
    fn client_auth_game_guard() {
        // Arrange
        let buffer = hex::decode("0725c7892400000000000000000000000000000000000000")
            .expect("Failed to decode buffer");
        let mut reader = Cursor::new(&buffer);
        let message = ClientMessage::AuthGameGuard {};

        // Act
        let result = decode(&mut reader);

        // Assert
        assert_eq!(result.is_ok(), true);
        assert_eq!(result.unwrap(), message);
    }

    #[test]
    fn client_invalid() {
        // Arrange
        let buffer = hex::decode("ff").expect("Failed to decode buffer");
        let mut reader = Cursor::new(&buffer);

        // Act
        let result = decode(&mut reader);

        // Assert
        assert_eq!(result.is_err(), true);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "Invalid packet id (0xff)");
    }
}
