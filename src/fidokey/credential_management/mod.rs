pub mod credential_management_command;
pub mod credential_management_params;
pub mod credential_management_response;
use super::FidoKeyHid;
use crate::{
    ctaphid, public_key_credential_descriptor::PublicKeyCredentialDescriptor,
    public_key_credential_user_entity::PublicKeyCredentialUserEntity, result::Result, token::Token,
    util,
};
use {
    credential_management_command::SubCommand,
    credential_management_params::{Credential, CredentialManagementData, CredentialsCount, Rp},
};

impl FidoKeyHid {
    pub fn credential_management_get_creds_metadata(
        &self,
        token: &Token,
        use_preview: bool,
    ) -> Result<CredentialsCount> {
        let meta = self.credential_management(token, SubCommand::GetCredsMetadata, use_preview)?;

        Ok(CredentialsCount::new(&meta))
    }

    pub fn credential_management_enumerate_rps(
        &self,
        token: &Token,
        use_preview: bool,
    ) -> Result<Vec<Rp>> {
        let mut rps: Vec<Rp> = Vec::new();
        let data = self.credential_management(token, SubCommand::EnumerateRPsBegin, use_preview)?;

        if data.total_rps > 0 {
            rps.push(Rp::new(&data));

            let remaining_rps = data.total_rps - 1;
            for _ in 0..remaining_rps {
                let data = self.credential_management(
                    token,
                    SubCommand::EnumerateRPsGetNextRp,
                    use_preview,
                )?;
                rps.push(Rp::new(&data));
            }
        }

        Ok(rps)
    }

    pub fn credential_management_enumerate_credentials(
        &self,
        token: &Token,
        rpid_hash: &[u8],
        use_preview: bool,
    ) -> Result<Vec<credential_management_params::Credential>> {
        let mut credentials: Vec<Credential> = Vec::new();

        let data = self.credential_management(
            token,
            SubCommand::EnumerateCredentialsBegin(rpid_hash.to_vec()),
            use_preview,
        )?;

        if data.total_credentials > 0 {
            credentials.push(Credential::new(&data));

            let remaining_credentials = data.total_credentials - 1;
            for _ in 0..remaining_credentials {
                let data = self.credential_management(
                    token,
                    SubCommand::EnumerateCredentialsGetNextCredential(rpid_hash.to_vec()),
                    use_preview,
                )?;
                credentials.push(Credential::new(&data));
            }
        }

        Ok(credentials)
    }

    pub fn credential_management_delete_credential(
        &self,
        token: &Token,
        pkcd: PublicKeyCredentialDescriptor,
        use_preview: bool,
    ) -> Result<()> {
        self.credential_management(token, SubCommand::DeleteCredential(pkcd), use_preview)?;
        Ok(())
    }

    pub fn credential_management_update_user_information(
        &self,
        token: &Token,
        pkcd: PublicKeyCredentialDescriptor,
        pkcue: PublicKeyCredentialUserEntity,
        use_preview: bool,
    ) -> Result<()> {
        // Technically, the credential management preview feature does not have a update
        // user information function. Some authenticators do seem to support it though.
        self.credential_management(
            token,
            SubCommand::UpdateUserInformation(pkcd, pkcue),
            use_preview,
        )?;
        Ok(())
    }

    fn credential_management(
        &self,
        token: &Token,
        sub_command: SubCommand,
        use_preview: bool,
    ) -> Result<CredentialManagementData> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload =
            credential_management_command::create_payload(token, sub_command, use_preview)?;

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
