use crate::encrypt::cose::CoseKey;
use crate::util;
use serde_cbor::{to_vec, Value};
use std::fmt;

#[derive(Debug, Default, Clone)]
pub enum PublicKeyType {
    #[default]
    Unknown = 0,
    Ecdsa256 = 1,
    Ed25519 = 2,
}

#[derive(Debug, Default, Clone)]
pub struct PublicKey {
    pub key_type: PublicKeyType,
    pub pem: String,
    pub der: Vec<u8>,
    pub raw: Vec<u8>,
}
impl PublicKey {
    pub fn new(cbor: &Value) -> Self {
        let cose_key = CoseKey::new(cbor).unwrap();

        let mut public_key = PublicKey::default();

        public_key.key_type = if cose_key.key_type == 1 {
            PublicKeyType::Ed25519
        } else if cose_key.key_type == 2 {
            PublicKeyType::Ecdsa256
        } else {
            PublicKeyType::Unknown
        };
        public_key.der = cose_key.to_public_key_der();
        public_key.pem = util::convert_to_publickey_pem(&public_key.der);
        // need to rework error handling here
        public_key.raw = to_vec(cbor).expect("Cannot convert CBOR public key to vec");
        public_key
    }

    pub fn with_der(der: &[u8], public_key_type: PublicKeyType) -> Self {
        let mut public_key = PublicKey::default();
        public_key.key_type = public_key_type;
        public_key.der = der.to_vec();
        public_key
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(der : {} , pem : {})",
            util::to_hex_str(&self.der),
            self.pem
        )
    }
}
