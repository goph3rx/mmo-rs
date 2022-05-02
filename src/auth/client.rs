use crate::auth::message::ServerMessage;
use crate::auth::sender::AuthClientSender;
use anyhow::Result;
use openssl::pkey::Private;
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use std::io::{Error, ErrorKind};
use std::sync::{Arc, Mutex, MutexGuard};

pub struct AuthClient {
    state: Mutex<AuthClientState>,
}

impl AuthClient {
    pub fn new(sender: Box<dyn AuthClientSender>) -> Result<Arc<Self>> {
        // Generate keys for traffic/credential encryption
        let mut crypt_key = [0; 16];
        rand_bytes(&mut crypt_key)?;
        let credentials_key = Rsa::generate(1024)?;

        // Construct client
        Ok(Arc::new(Self {
            state: Mutex::new(AuthClientState {
                sender,
                crypt_key,
                credentials_key,
            }),
        }))
    }

    pub fn init(&self) -> Result<()> {
        let mut state = self.state()?;
        let msg = ServerMessage::Init {
            session_id: 0x1eadbeef,
            modulus: state
                .credentials_key
                .n()
                .to_vec()
                .try_into()
                .expect("Invalid modulus length"),
            crypt_key: state.crypt_key,
        };
        state.sender.send(msg)?;
        Ok(())
    }

    fn state(&self) -> std::io::Result<MutexGuard<AuthClientState>> {
        self.state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Other, "Cannot unlock state"))
    }
}

struct AuthClientState {
    sender: Box<dyn AuthClientSender>,

    crypt_key: [u8; 16],
    credentials_key: Rsa<Private>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::sender::MockAuthClientSender;
    use mockall::predicate;
    use std::io::{Error, ErrorKind};

    #[test]
    fn init_success() {
        // Arrange
        let mut sender = Box::new(MockAuthClientSender::new());
        sender
            .expect_send()
            .with(predicate::function(|msg: &ServerMessage| match msg {
                ServerMessage::Init { .. } => true,
                _ => false,
            }))
            .times(1)
            .returning(|_| Ok(()));
        let client = AuthClient::new(sender).expect("Failed to create client");

        // Act
        let result = client.init();

        // Assert
        assert_eq!(result.is_ok(), true);
    }

    #[test]
    fn init_fail() {
        // Arrange
        let mut sender = Box::new(MockAuthClientSender::new());
        sender
            .expect_send()
            .with(predicate::function(|msg: &ServerMessage| match msg {
                ServerMessage::Init { .. } => true,
                _ => false,
            }))
            .times(1)
            .returning(|_| Err(Error::from(ErrorKind::InvalidData)));
        let client = AuthClient::new(sender).expect("Failed to create client");

        // Act
        let result = client.init();

        // Assert
        assert_eq!(result.is_err(), true);
    }
}
