use crate::{
    encrypt::cose::CoseKey, encrypt::enc_aes256_cbc, encrypt::p256,
    result::Result,
};
use ring::{agreement, digest, error::Unspecified, hkdf, rand::{self, SecureRandom}};

#[derive(Debug, Default, Clone)]
pub struct SharedSecret {
    pub public_key: CoseKey,
    pub secret: [u8; 32],
}

pub enum SharedSecrets {
    Protocol1(SharedSecretProtocol1),
    Protocol2(SharedSecretProtocol2),
}
pub struct SharedSecretProtocol1 {
    pub public_key: CoseKey,
    pub secret: [u8; 32],
}

impl SharedSecretProtocol1 {
    pub fn new(peer_key: &CoseKey) -> Result<Self> {
        let rng = rand::SystemRandom::new();
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(anyhow::Error::msg)?;

        let my_public_key = my_private_key.compute_public_key().map_err(anyhow::Error::msg)?;

        let peer_public_key = {
            let peer_public_key = p256::P256Key::from_cose(peer_key)?.bytes();
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_key)
        };

        let shared_secret =
            agreement::agree_ephemeral(my_private_key, &peer_public_key, Unspecified, |material| {
                Ok(digest::digest(&digest::SHA256, material))
            })
            .map_err(anyhow::Error::msg)?;

        let mut res = SharedSecretProtocol1 {
            public_key: p256::P256Key::from_bytes(my_public_key.as_ref())?.to_cose(),
            secret: [0; 32],
        };
        res.secret.copy_from_slice(shared_secret.as_ref());

        Ok(res)
    }

    pub fn encrypt_pin(&self, pin: &str) -> Result<[u8; 16]> {
        self.encrypt(pin.as_bytes())
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<[u8; 16]> {
        let hash = digest::digest(&digest::SHA256, data);
        let message = &hash.as_ref()[0..16];
        let enc = enc_aes256_cbc::encrypt_message(&self.secret, message);
        let mut out_bytes = [0; 16];
        out_bytes.copy_from_slice(&enc[0..16]);
        Ok(out_bytes)
    }

    pub fn decrypt(self, data: &mut [u8]) -> Result<Vec<u8>> {
        let result = enc_aes256_cbc::decrypt_message(&self.secret, data);
        Ok(result)
    }
}

pub struct SharedSecretProtocol2 {
    pub public_key: CoseKey,
    pub secret: [u8; 64],
}

impl SharedSecretProtocol2 {
    pub fn new(peer_key: &CoseKey) -> Result<Self> {
        let rng = rand::SystemRandom::new();
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(anyhow::Error::msg)?;

        let my_public_key = my_private_key.compute_public_key().map_err(anyhow::Error::msg)?;

        let peer_public_key = {
            let peer_public_key = p256::P256Key::from_cose(peer_key)?.bytes();
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_key)
        };

        
        let shared_secret =
            agreement::agree_ephemeral(my_private_key, &peer_public_key, Unspecified, |input_key_material| {
                let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[0, 32]);
                let pseudo_random_key = salt.extract(input_key_material);

                let hmac_context = &["CTAP2 HMAC key".as_bytes()];
                let hmac_output_key_material = pseudo_random_key.expand(hmac_context, hkdf::HKDF_SHA256).unwrap();
                let mut hmac_secret = [0u8; digest::SHA256_OUTPUT_LEN];
                hmac_output_key_material.fill(&mut hmac_secret).unwrap();

                let aes_context = &["CTAP2 AES key".as_bytes()];
                let aes_output_key_material = pseudo_random_key.expand(aes_context, hkdf::HKDF_SHA256).unwrap();
                let mut aes_secret = [0u8; digest::SHA256_OUTPUT_LEN];
                aes_output_key_material.fill(&mut aes_secret).unwrap();

                Ok([hmac_secret, aes_secret].concat())
            })
            .map_err(anyhow::Error::msg)?;

        let mut res = SharedSecretProtocol2 {
            public_key: p256::P256Key::from_bytes(my_public_key.as_ref())?.to_cose(),
            secret: [0; 64],
        };
        res.secret.copy_from_slice(shared_secret.as_ref());

        Ok(res)
    }

    pub fn encrypt_pin(&self, pin: &str) -> Result<[u8; 32]> {
        self.encrypt(pin.as_bytes())
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<[u8; 32]> {
        let rng = rand::SystemRandom::new();

        let mut iv = [0u8; 16];
        rng.fill(&mut iv).unwrap();

        let mut key = [0u8; 32];
        key.copy_from_slice(&self.secret[32..]);

        let hash = digest::digest(&digest::SHA256, data);
        let message = &hash.as_ref()[0..16];

        let encrypted = enc_aes256_cbc::encrypt_message_with_iv(&key, &iv, &message);
        let mut ct = [0u8; 16];
        ct.copy_from_slice(&encrypted[0..16]);

        let mut result = [0u8; 32];
        result.copy_from_slice(&[ct, iv].concat()[..]);
        Ok(result)
    }

    pub fn decrypt(self, data: &mut [u8]) -> Result<Vec<u8>> {
        if data.len() < 16 {
            panic!("Not enough data");
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&self.secret[32..]);

        let mut iv = [0u8; 16];
        iv.copy_from_slice(&data[..16]);

        let ct = &data[16..];

        let result = enc_aes256_cbc::decrypt_message_with_iv(&key, &iv, &ct);
        Ok(result)
    }
}

impl SharedSecret {
    pub fn new(peer_key: &CoseKey) -> Result<Self> {
        let rng = rand::SystemRandom::new();
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(anyhow::Error::msg)?;

        let my_public_key = my_private_key.compute_public_key().map_err(anyhow::Error::msg)?;

        let peer_public_key = {
            let peer_public_key = p256::P256Key::from_cose(peer_key)?.bytes();
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_key)
        };

        let shared_secret =
            agreement::agree_ephemeral(my_private_key, &peer_public_key, Unspecified, |material| {
                Ok(digest::digest(&digest::SHA256, material))
            })
            .map_err(anyhow::Error::msg)?;

        let mut res = SharedSecret {
            public_key: p256::P256Key::from_bytes(my_public_key.as_ref())?.to_cose(),
            secret: [0; 32],
        };
        res.secret.copy_from_slice(shared_secret.as_ref());

        Ok(res)
    }

    pub fn encrypt_pin(&self, pin: &str) -> Result<[u8; 16]> {
        self.encrypt_protocol_1(pin.as_bytes())
    }

    pub fn encrypt_protocol_1(&self, data: &[u8]) -> Result<[u8; 16]> {
        let hash = digest::digest(&digest::SHA256, data);
        let message = &hash.as_ref()[0..16];
        let enc = enc_aes256_cbc::encrypt_message(&self.secret, message);
        let mut out_bytes = [0; 16];
        out_bytes.copy_from_slice(&enc[0..16]);
        Ok(out_bytes)
    }

    pub fn encrypt_protocol_2(&self, data: &[u8]) -> Result<[u8; 16]> {
        let hash = digest::digest(&digest::SHA256, data);
        panic!();
    }

    pub fn decrypt_protocol_1(self, data: &mut [u8]) -> Result<Vec<u8>> {
        let dec = enc_aes256_cbc::decrypt_message(&self.secret, data);
        Ok(dec)
    }
}
