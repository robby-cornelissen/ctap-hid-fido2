use crate::{
    encrypt::cose::CoseKey, encrypt::enc_aes256_cbc, encrypt::enc_hmac_sha_256, encrypt::p256,
    result::Result,
};
use ring::{
    agreement, digest,
    error::Unspecified,
    hkdf,
    rand::{SecureRandom, SystemRandom},
};

#[derive(Clone, Debug)]
pub enum SharedSecret {
    Protocol1(SharedSecretProtocol1),
    Protocol2(SharedSecretProtocol2),
}

impl SharedSecret {
    pub fn create(pin_uv_auth_protocol: u32, peer_key: &CoseKey) -> Result<Self> {
        match pin_uv_auth_protocol {
            1 => SharedSecretProtocol1::new(peer_key).map(|ss| SharedSecret::Protocol1(ss)),
            2 => SharedSecretProtocol2::new(peer_key).map(|ss| SharedSecret::Protocol2(ss)),
            _ => Err(anyhow::anyhow!("Unsupported PIN/UV auth protocol").into()),
        }
    }

    pub fn get_public_key(&self) -> CoseKey {
        match self {
            SharedSecret::Protocol1(ss) => ss.public_key.clone(),
            SharedSecret::Protocol2(ss) => ss.public_key.clone(),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            SharedSecret::Protocol1(ss) => ss.encrypt(data),
            SharedSecret::Protocol2(ss) => ss.encrypt(data),
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            SharedSecret::Protocol1(ss) => ss.decrypt(data),
            SharedSecret::Protocol2(ss) => ss.decrypt(data),
        }
    }

    pub fn authenticate(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            SharedSecret::Protocol1(ss) => ss.authenticate(data),
            SharedSecret::Protocol2(ss) => ss.authenticate(data),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SharedSecretProtocol1 {
    pub public_key: CoseKey,
    pub secret: [u8; 32],
}

impl SharedSecretProtocol1 {
    pub fn new(peer_key: &CoseKey) -> Result<Self> {
        let rng = SystemRandom::new();
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(anyhow::Error::msg)?;

        let my_public_key = my_private_key
            .compute_public_key()
            .map_err(anyhow::Error::msg)?;

        let peer_public_key = {
            let peer_public_key = p256::P256Key::from_cose(peer_key)?.bytes();
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_key)
        };

        let shared_secret =
            agreement::agree_ephemeral(my_private_key, &peer_public_key, Unspecified, |key_material| {
                Ok(digest::digest(&digest::SHA256, key_material))
            })
            .map_err(anyhow::Error::msg)?;

        let mut res = Self {
            public_key: p256::P256Key::from_bytes(my_public_key.as_ref())?.to_cose(),
            secret: [0; 32],
        };
        res.secret.copy_from_slice(shared_secret.as_ref());

        Ok(res)
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let encrypted = enc_aes256_cbc::encrypt_message(&self.secret, data);

        Ok(encrypted.to_vec())
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let result = enc_aes256_cbc::decrypt_message(&self.secret, data);
        Ok(result)
    }

    pub fn authenticate(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature = enc_hmac_sha_256::authenticate(&self.secret, message);

        Ok(signature[0..16].to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct SharedSecretProtocol2 {
    pub public_key: CoseKey,
    pub secret: [u8; 64],
}

impl SharedSecretProtocol2 {
    pub fn new(peer_key: &CoseKey) -> Result<Self> {
        let rng = SystemRandom::new();
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(anyhow::Error::msg)?;

        let my_public_key = my_private_key
            .compute_public_key()
            .map_err(anyhow::Error::msg)?;

        let peer_public_key = {
            let peer_public_key = p256::P256Key::from_cose(peer_key)?.bytes();
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_key)
        };

        let shared_secret = agreement::agree_ephemeral(
            my_private_key,
            &peer_public_key,
            Unspecified,
            |input_key_material| {
                let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[0, 32]);
                let pseudo_random_key = salt.extract(input_key_material);

                let hmac_context = &["CTAP2 HMAC key".as_bytes()];
                let hmac_output_key_material = pseudo_random_key
                    .expand(hmac_context, hkdf::HKDF_SHA256)
                    .unwrap();
                let mut hmac_secret = [0u8; digest::SHA256_OUTPUT_LEN];
                hmac_output_key_material.fill(&mut hmac_secret).unwrap();

                let aes_context = &["CTAP2 AES key".as_bytes()];
                let aes_output_key_material = pseudo_random_key
                    .expand(aes_context, hkdf::HKDF_SHA256)
                    .unwrap();
                let mut aes_secret = [0u8; digest::SHA256_OUTPUT_LEN];
                aes_output_key_material.fill(&mut aes_secret).unwrap();

                Ok([hmac_secret, aes_secret].concat())
            },
        )
        .map_err(anyhow::Error::msg)?;

        let mut res = Self {
            public_key: p256::P256Key::from_bytes(my_public_key.as_ref())?.to_cose(),
            secret: [0; 64],
        };
        res.secret.copy_from_slice(shared_secret.as_ref());

        Ok(res)
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();

        let mut key = [0u8; 32];
        key.copy_from_slice(&self.secret[32..]);

        let mut iv = [0u8; 16];
        rng.fill(&mut iv).unwrap();

        println!("{:?}", data);
        let mut ct = enc_aes256_cbc::encrypt_message_with_iv(&key, &iv, &data);
        println!("{:?}", iv);
        println!("{:?}", ct);

        let mut result = Vec::new();
        result.append(&mut iv.to_vec());
        result.append(&mut ct);
        println!("{:?}", result);

        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
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

    pub fn authenticate(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut key = [0u8; 32];
        key.copy_from_slice(&self.secret[..32]);

        let signature = enc_hmac_sha_256::authenticate(&key, message);

        Ok(signature)
    }
}
