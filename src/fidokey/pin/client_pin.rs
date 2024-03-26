use super::client_pin_command;
use super::client_pin_command::SubCommand as PinCmd;
use super::client_pin_response;
use super::FidoKeyHid;
use crate::ctaphid;
use crate::encrypt::cose;
use crate::result::Result;

impl FidoKeyHid {
    pub fn get_authenticator_key_agreement(
        &self,
        cid: &[u8],
        pin_uv_auth_protocol: u32,
    ) -> Result<cose::CoseKey> {
        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement, pin_uv_auth_protocol)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, cid, &send_payload)?;
        let authenticator_key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;
        Ok(authenticator_key_agreement)
    }
}
