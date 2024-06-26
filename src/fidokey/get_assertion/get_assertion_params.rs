use crate::auth_data::Flags;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ring::digest;
use std::convert::TryFrom;
use strum_macros::AsRefStr;

#[derive(Debug, Default, Clone)]
pub struct Assertion {
    pub rpid_hash: Vec<u8>,
    pub flags: Flags,
    pub sign_count: u32,
    pub number_of_credentials: i32,
    pub signature: Vec<u8>,
    pub user: PublicKeyCredentialUserEntity,
    pub credential_id: Vec<u8>,
    pub extensions: Vec<Extension>,
    // row - audh_data
    pub auth_data: Vec<u8>,
    pub user_selected: bool,
}

#[derive(Debug, Clone, strum_macros::Display, AsRefStr)]
pub enum Extension {
    #[strum(serialize = "hmac-secret")]
    HmacSecret(Option<[u8; 32]>),
    #[strum(serialize = "largeBlobKey")]
    LargeBlobKey((Option<bool>, Option<Vec<u8>>)),
    #[strum(serialize = "credBlob")]
    CredBlob((Option<bool>, Option<Vec<u8>>)),
}

impl Extension {
    pub fn create_hmac_secret_from_string(message: &str) -> Extension {
        let hasher = digest::digest(&digest::SHA256, message.as_bytes());
        Extension::HmacSecret(Some(<[u8; 32]>::try_from(hasher.as_ref()).unwrap()))
    }
}
pub struct GetAssertionArgs {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub credential_ids: Vec<Vec<u8>>,
    pub uv: Option<bool>,
    pub extensions: Option<Vec<Extension>>,
}

impl GetAssertionArgs {
    pub fn builder() -> GetAssertionArgsBuilder {
        GetAssertionArgsBuilder::default()
    }
}

#[derive(Default)]
pub struct GetAssertionArgsBuilder {
    rp_id: String,
    challenge: Vec<u8>,
    credential_ids: Vec<Vec<u8>>,
    uv: Option<bool>,
    extensions: Option<Vec<Extension>>,
}

impl GetAssertionArgsBuilder {
    pub fn new(rp_id: &str, challenge: &[u8]) -> Self {
        Self {
            uv: Some(true), // TODO need to check this
            rp_id: String::from(rp_id),
            challenge: challenge.to_vec(),
            ..Default::default()
        }
    }

    pub fn without_pin_and_uv(mut self) -> Self {
        self.uv = None;
        self
    }

    pub fn extensions(mut self, extensions: &[Extension]) -> Self {
        self.extensions = Some(extensions.to_vec());
        self
    }

    pub fn credential_id(mut self, credential_id: &[u8]) -> Self {
        self.credential_ids.clear();
        self.add_credential_id(credential_id)
    }

    pub fn add_credential_id(mut self, credential_id: &[u8]) -> Self {
        self.credential_ids.push(credential_id.to_vec());
        self
    }

    pub fn build(self) -> GetAssertionArgs {
        GetAssertionArgs {
            rp_id: self.rp_id,
            challenge: self.challenge,
            credential_ids: self.credential_ids,
            uv: self.uv,
            extensions: self.extensions,
        }
    }
}
