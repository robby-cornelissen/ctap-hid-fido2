use super::make_credential_params::Extension as Mext;
use super::CredentialProtectionPolicy;
use crate::{public_key::PublicKey, public_key_credential_rp_entity::PublicKeyCredentialRpEntity};
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::str_buf::StrBuf;
use std::fmt;
use strum_macros::{AsRefStr, Display};

/// Attestation Object
/// [https://www.w3.org/TR/webauthn/#sctn-attestation](https://www.w3.org/TR/webauthn/#sctn-attestation)
#[derive(Debug, Default, Clone)]
pub struct Attestation {
    pub fmt: String,
    pub rpid_hash: Vec<u8>,
    pub flags_user_present_result: bool,
    pub flags_user_verified_result: bool,
    pub flags_attested_credential_data_included: bool,
    pub flags_extension_data_included: bool,
    pub sign_count: u32,
    pub aaguid: Vec<u8>,
    pub credential_descriptor: PublicKeyCredentialDescriptor,
    pub credential_publickey: PublicKey,
    pub extensions: Vec<Extension>,
    pub auth_data: Vec<u8>,
    pub attstmt_raw: Vec<u8>,
    pub attstmt_alg: i32,
    pub attstmt_sig: Vec<u8>,
    pub attstmt_x5c: Vec<Vec<u8>>,
}

// TODO probably remove
impl fmt::Display for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strbuf = StrBuf::new(42);
        strbuf
            .append_hex("- rpid_hash", &self.rpid_hash)
            .append(
                "- flags_user_present_result",
                &self.flags_user_present_result,
            )
            .append(
                "- flags_attested_credential_data_included",
                &self.flags_attested_credential_data_included,
            )
            .append(
                "- flags_extension_data_included",
                &self.flags_extension_data_included,
            )
            .append("- sign_count", &self.sign_count)
            .append_hex("- aaguid", &self.aaguid)
            .append("- credential_descriptor", &self.credential_descriptor)
            .append("- credential_publickey", &self.credential_publickey)
            .append("- attstmt_alg", &self.attstmt_alg)
            .append_hex("- attstmt_sig", &self.attstmt_sig)
            .append("- attstmt_x5c_num", &self.attstmt_x5c.len());

        for ex in &self.extensions {
            strbuf.append("- extension", &format!("{:?}", ex));
        }

        write!(f, "{}", strbuf.build())
    }
}

#[derive(Debug, Clone, Display, AsRefStr)]
pub enum Extension {
    #[strum(serialize = "credBlob")]
    CredBlob((Option<Vec<u8>>, Option<bool>)),
    #[strum(serialize = "credProtect")]
    CredProtect(Option<CredentialProtectionPolicy>),
    #[strum(serialize = "hmac-secret")]
    HmacSecret(Option<bool>),
    #[strum(serialize = "largeBlobKey")]
    LargeBlobKey((Option<bool>, Option<Vec<u8>>)),
    #[strum(serialize = "minPinLength")]
    MinPinLength((Option<bool>, Option<u8>)),
}

#[derive(Debug, Copy, Clone)]
pub enum CredentialSupportedKeyType {
    Ecdsa256 = -7,
    Ed25519 = -8,
}

impl std::default::Default for CredentialSupportedKeyType {
    fn default() -> Self {
        Self::Ecdsa256
    }
}

pub struct MakeCredentialArgsT {
    pub rpid: String,
    pub challenge: Vec<u8>,
    pub key_types: Vec<CredentialSupportedKeyType>,
    pub uv: Option<bool>,
    pub exclude_list: Vec<Vec<u8>>,
    pub user_entity: Option<PublicKeyCredentialUserEntity>,
    pub rp_entity: Option<PublicKeyCredentialRpEntity>,
    pub rk: Option<bool>,
    pub extensions: Option<Vec<Mext>>,
}

// TODO remove
#[derive(Debug)]
pub struct MakeCredentialArgs<'a> {
    pub rpid: String,
    pub challenge: Vec<u8>,
    pub pin: Option<&'a str>,
    pub key_types: Vec<CredentialSupportedKeyType>,
    pub uv: Option<bool>,
    pub exclude_list: Vec<Vec<u8>>,
    pub user_entity: Option<PublicKeyCredentialUserEntity>,
    pub rp_entity: Option<PublicKeyCredentialRpEntity>,
    pub rk: Option<bool>,
    pub extensions: Option<Vec<Mext>>,
}

impl<'a> MakeCredentialArgs<'a> {
    pub fn builder() -> MakeCredentialArgsBuilder<'a> {
        MakeCredentialArgsBuilder::default()
    }
}

#[derive(Default)]
pub struct MakeCredentialArgsBuilderT<> {
    rpid: String,
    challenge: Vec<u8>,
    key_types: Vec<CredentialSupportedKeyType>,
    uv: Option<bool>,
    exclude_list: Vec<Vec<u8>>,
    user_entity: Option<PublicKeyCredentialUserEntity>,
    rp_entity: Option<PublicKeyCredentialRpEntity>,
    rk: Option<bool>,
    extensions: Option<Vec<Mext>>,
}

// TODO remove
#[derive(Default)]
pub struct MakeCredentialArgsBuilder<'a> {
    rpid: String,
    challenge: Vec<u8>,
    pin: Option<&'a str>,
    key_types: Vec<CredentialSupportedKeyType>,
    uv: Option<bool>,
    exclude_list: Vec<Vec<u8>>,
    user_entity: Option<PublicKeyCredentialUserEntity>,
    rp_entity: Option<PublicKeyCredentialRpEntity>,
    rk: Option<bool>,
    extensions: Option<Vec<Mext>>,
}

impl<'a> MakeCredentialArgsBuilderT {
    pub fn new(rpid: &str, challenge: &[u8]) -> Self {
        Self {
            uv: Some(true), // TODO look into this
            rpid: String::from(rpid),
            challenge: challenge.to_vec(),
            ..Default::default()
        }
    }

    /// Adds a credential_id to the excludeList, preventing further credentials being created on
    /// the same authenticator
    pub fn exclude_authenticator(mut self, credential_id: &[u8]) -> Self {
        self.exclude_list.push(credential_id.to_vec());
        self
    }

    pub fn key_type(
        mut self,
        key_type: CredentialSupportedKeyType,
    ) -> Self {
        self.key_types.push(key_type);
        self
    }

    pub fn extensions(mut self, extensions: &[Mext]) -> Self {
        self.extensions = Some(extensions.to_vec());
        self
    }

    pub fn user_entity(
        mut self,
        user_entity: &PublicKeyCredentialUserEntity,
    ) -> Self {
        self.user_entity = Some(user_entity.clone());
        self
    }

    // There's some additional work to be done here because the ID of the RP
    // entity might conflict with the one already set on the builder. Probably
    // should favor refactoring to require the RP entity instead of the RP ID
    // on the builder's constructor.
    pub fn rp_entity(
        mut self,
        rp_entity: &PublicKeyCredentialRpEntity,
    ) -> Self {
        self.rp_entity = Some(rp_entity.clone());
        self
    }

    pub fn resident_key(mut self) -> Self {
        self.rk = Some(true);
        self
    }

    pub fn build(self) -> MakeCredentialArgsT {
        MakeCredentialArgsT {
            rpid: self.rpid,
            challenge: self.challenge,
            key_types: self.key_types,
            uv: self.uv,
            exclude_list: self.exclude_list,
            user_entity: self.user_entity,
            rp_entity: self.rp_entity,
            rk: self.rk,
            extensions: self.extensions,
        }
    }
}

// TODO remove
impl<'a> MakeCredentialArgsBuilder<'a> {
    pub fn new(rpid: &str, challenge: &[u8]) -> MakeCredentialArgsBuilder<'a> {
        MakeCredentialArgsBuilder::<'_> {
            uv: Some(true),
            rpid: String::from(rpid),
            challenge: challenge.to_vec(),
            ..Default::default()
        }
    }

    pub fn pin(mut self, pin: &'a str) -> MakeCredentialArgsBuilder<'a> {
        self.pin = Some(pin);
        self.uv = None;
        self
    }

    pub fn without_pin_and_uv(mut self) -> MakeCredentialArgsBuilder<'a> {
        self.pin = None;
        self.uv = None;
        self
    }

    /// Adds a credential_id to the excludeList, preventing further credentials being created on
    /// the same authenticator
    pub fn exclude_authenticator(mut self, credential_id: &[u8]) -> MakeCredentialArgsBuilder<'a> {
        self.exclude_list.push(credential_id.to_vec());
        self
    }

    pub fn key_type(
        mut self,
        key_type: CredentialSupportedKeyType,
    ) -> MakeCredentialArgsBuilder<'a> {
        self.key_types.push(key_type);
        self
    }

    pub fn extensions(mut self, extensions: &[Mext]) -> MakeCredentialArgsBuilder<'a> {
        self.extensions = Some(extensions.to_vec());
        self
    }

    pub fn user_entity(
        mut self,
        user_entity: &PublicKeyCredentialUserEntity,
    ) -> MakeCredentialArgsBuilder<'a> {
        self.user_entity = Some(user_entity.clone());
        self
    }

    // There's some additional work to be done here because the ID of the RP
    // entity might conflict with the one already set on the builder. Probably
    // should favor refactoring to require the RP entity instead of the RP ID
    // on the builder's constructor.
    pub fn rp_entity(
        mut self,
        rp_entity: &PublicKeyCredentialRpEntity,
    ) -> MakeCredentialArgsBuilder<'a> {
        self.rp_entity = Some(rp_entity.clone());
        self
    }

    pub fn resident_key(mut self) -> MakeCredentialArgsBuilder<'a> {
        self.rk = Some(true);
        self
    }

    pub fn build(self) -> MakeCredentialArgs<'a> {
        MakeCredentialArgs {
            rpid: self.rpid,
            challenge: self.challenge,
            pin: self.pin,
            key_types: self.key_types,
            uv: self.uv,
            exclude_list: self.exclude_list,
            user_entity: self.user_entity,
            rp_entity: self.rp_entity,
            rk: self.rk,
            extensions: self.extensions,
        }
    }
}
