pub mod credential_management_command;
pub mod credential_management_params;
pub mod credential_management_response;
use super::{pin::DEFAULT_PIN_UV_AUTH_PROTOCOL, FidoKeyHid};
use crate::{
    ctaphid, pintoken::Permissions, public_key_credential_descriptor::PublicKeyCredentialDescriptor, public_key_credential_user_entity::PublicKeyCredentialUserEntity, result::Result, token::Token, util
};
use {
    credential_management_command::SubCommand,
    credential_management_params::{Credential, CredentialManagementData, CredentialsCount, Rp},
};

impl FidoKeyHid {
    pub fn credential_management_get_creds_metadata_t(
        &self,
        token: &Token,
        use_preview: bool,
    ) -> Result<CredentialsCount> {
        let meta = self.credential_management_t(token, SubCommand::GetCredsMetadata, use_preview)?;

        Ok(CredentialsCount::new(&meta))
    }
    
    // TODO remove
    pub fn credential_management_get_creds_metadata(
        &self,
        pin: Option<&str>,
    ) -> Result<CredentialsCount> {
        let meta = self.credential_management(pin, SubCommand::GetCredsMetadata)?;
        Ok(CredentialsCount::new(&meta))
    }

    pub fn credential_management_enumerate_rps_t(&self, token: &Token, use_preview: bool) -> Result<Vec<Rp>> {
        let mut rps: Vec<Rp> = Vec::new();
        let data = self.credential_management_t(token, SubCommand::EnumerateRPsBegin, use_preview)?;

        if data.total_rps > 0 {
            rps.push(Rp::new(&data));

            let remaining_rps = data.total_rps - 1;
            for _ in 0..remaining_rps {
                let data = self.credential_management_t(token, SubCommand::EnumerateRPsGetNextRp, use_preview)?;
                rps.push(Rp::new(&data));
            }
        }

        Ok(rps)
    }

    // TODO remove
    pub fn credential_management_enumerate_rps(&self, pin: Option<&str>) -> Result<Vec<Rp>> {
        let mut datas: Vec<Rp> = Vec::new();
        let data = self.credential_management(pin, SubCommand::EnumerateRPsBegin)?;

        if data.total_rps > 0 {
            datas.push(Rp::new(&data));
            let roop_n = data.total_rps - 1;
            for _ in 0..roop_n {
                let data = self.credential_management(pin, SubCommand::EnumerateRPsGetNextRp)?;
                datas.push(Rp::new(&data));
            }
        }
        Ok(datas)
    }

    pub fn credential_management_enumerate_credentials_t(
        &self,
        token: &Token,
        rpid_hash: &[u8],
        use_preview: bool
    ) -> Result<Vec<credential_management_params::Credential>> {
        let mut credentials: Vec<Credential> = Vec::new();

        let data = self.credential_management_t(
            token,
            SubCommand::EnumerateCredentialsBegin(rpid_hash.to_vec()),
            use_preview
        )?;

        if data.total_credentials > 0 {
            credentials.push(Credential::new(&data));

            let remaining_credentials = data.total_credentials - 1;
            for _ in 0..remaining_credentials {
                let data = self.credential_management_t(
                    token,
                    SubCommand::EnumerateCredentialsGetNextCredential(rpid_hash.to_vec()),
                    use_preview
                )?;
                credentials.push(Credential::new(&data));
            }
        }

        Ok(credentials)
    }

    // TODO remove
    pub fn credential_management_enumerate_credentials(
        &self,
        pin: Option<&str>,
        rpid_hash: &[u8],
    ) -> Result<Vec<credential_management_params::Credential>> {
        let mut datas: Vec<Credential> = Vec::new();

        let data = self.credential_management(
            pin,
            SubCommand::EnumerateCredentialsBegin(rpid_hash.to_vec()),
        )?;

        datas.push(Credential::new(&data));
        if data.total_credentials > 0 {
            let roop_n = data.total_credentials - 1;
            for _ in 0..roop_n {
                let data = self.credential_management(
                    pin,
                    SubCommand::EnumerateCredentialsGetNextCredential(rpid_hash.to_vec()),
                )?;
                datas.push(Credential::new(&data));
            }
        }
        Ok(datas)
    }

    pub fn credential_management_delete_credential_t(
        &self,
        token: &Token,
        pkcd: PublicKeyCredentialDescriptor,
        use_preview: bool,
    ) -> Result<()> {
        self.credential_management_t(token, SubCommand::DeleteCredential(pkcd), use_preview)?;
        Ok(())
    }

    // TODO remove
    pub fn credential_management_delete_credential(
        &self,
        pin: Option<&str>,
        pkcd: PublicKeyCredentialDescriptor,
    ) -> Result<()> {
        self.credential_management(pin, SubCommand::DeleteCredential(pkcd))?;
        Ok(())
    }

    pub fn credential_management_update_user_information_t(
        &self,
        token: &Token,
        pkcd: PublicKeyCredentialDescriptor,
        pkcue: PublicKeyCredentialUserEntity,
        use_preview: bool
    ) -> Result<()> {
        // Technically, the credential management preview feature does not have a update
        // user information function. Some authenticators do seem to support it though.
        self.credential_management_t(token, SubCommand::UpdateUserInformation(pkcd, pkcue), use_preview)?;
        Ok(())
    }

    // TODO remove
    pub fn credential_management_update_user_information(
        &self,
        pin: Option<&str>,
        pkcd: PublicKeyCredentialDescriptor,
        pkcue: PublicKeyCredentialUserEntity,
    ) -> Result<()> {
        self.credential_management(pin, SubCommand::UpdateUserInformation(pkcd, pkcue))?;
        Ok(())
    }

    fn credential_management_t(
        &self,
        token: &Token,
        sub_command: SubCommand,
        use_preview: bool,
    ) -> Result<CredentialManagementData> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload = credential_management_command::create_payload_t(
            token,
            sub_command,
            use_preview
        )?;

        if self.enable_log {
            println!("send(cbor) = {}", util::to_hex_str(&send_payload));
        }

        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        if self.enable_log {
            println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
        }

        credential_management_response::parse_cbor(&response_cbor)
    }


    // TODO remove
    fn credential_management(
        &self,
        pin: Option<&str>,
        sub_command: SubCommand,
    ) -> Result<CredentialManagementData> {
        let cid = ctaphid::ctaphid_init(self)?;

        let pin_token = {
            if let Some(pin) = pin {
                if true {
                // TODO entire method needs to go anyway
                // if self.use_pre_credential_management {
                    Some(self.get_pin_token(DEFAULT_PIN_UV_AUTH_PROTOCOL, pin)?)
                } else {
                    Some(self.get_pin_uv_auth_token(
                        &cid,
                        DEFAULT_PIN_UV_AUTH_PROTOCOL,
                        Some(pin),
                        Permissions::CREDENTIAL_MANAGEMENT,
                        None,
                    )?)
                }
            } else {
                None
            }
        };

        let send_payload = credential_management_command::create_payload(
            pin_token,
            sub_command,
            true,
            // TODO entire method needs to go anyway
            // self.use_pre_credential_management,
        )?;

        if self.enable_log {
            println!("send(cbor) = {}", util::to_hex_str(&send_payload));
        }

        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        if self.enable_log {
            println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
        }

        credential_management_response::parse_cbor(&response_cbor)
    }
}
