use ring::error::Unspecified;
use ring::{agreement, digest, rand};

use crate::encrypt::cose::CoseKey;
use crate::encrypt::enc_aes256_cbc;
use crate::encrypt::p256;
use crate::pintoken::PinToken;

#[derive(Debug, Default, Clone)]
pub struct SharedSecret {
    pub public_key: CoseKey,
    pub secret: [u8; 32],
}

impl SharedSecret {
    pub fn new(peer_key: &CoseKey) -> Result<Self, String> {
        let rng = rand::SystemRandom::new();
        let my_private_key =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();

        let my_public_key = my_private_key.compute_public_key().unwrap();

        let peer_public_key = {
            let peer_public_key = p256::P256Key::from_cose(peer_key).unwrap().bytes();
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_key)
        };

        let shared_secret =
            agreement::agree_ephemeral(my_private_key, &peer_public_key, Unspecified, |material| {
                Ok(digest::digest(&digest::SHA256, material))
            })
            .unwrap();

        let mut res = SharedSecret {
            public_key: p256::P256Key::from_bytes(my_public_key.as_ref())
                .unwrap()
                .to_cose(),
            secret: [0; 32],
        };
        res.secret.copy_from_slice(shared_secret.as_ref());

        Ok(res)
    }

    pub fn encrypt_pin(&self, pin: &str) -> Result<[u8; 16], String> {
        self.encrypt(pin.as_bytes())
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<[u8; 16], String> {
        let hash = digest::digest(&digest::SHA256, data);
        let message = &hash.as_ref()[0..16];
        let enc = enc_aes256_cbc::encrypt_message(&self.secret, message);
        let mut out_bytes = [0; 16];
        out_bytes.copy_from_slice(&enc[0..16]);
        Ok(out_bytes)
    }

    pub fn decrypt_token(&self, data: &mut [u8]) -> Result<PinToken, String> {
        let dec = enc_aes256_cbc::decrypt_message(&self.secret, data);
        let pin_token = PinToken::new(&dec);
        Ok(pin_token)
    }
}