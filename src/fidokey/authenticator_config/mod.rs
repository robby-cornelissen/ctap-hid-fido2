mod authenticator_config_command;

use super::pin::DEFAULT_PIN_UV_AUTH_PROTOCOL;
use super::FidoKeyHid;

use crate::ctaphid;
use crate::pintoken::Permissions;
use crate::result::Result;

use authenticator_config_command::SubCommand;

impl FidoKeyHid {
    pub fn toggle_always_uv(&self, pin: Option<&str>) -> Result<()> {
        self.config(pin, SubCommand::ToggleAlwaysUv)
    }

    pub fn set_min_pin_length(&self, new_min_pin_length: u8, pin: Option<&str>) -> Result<()> {
        self.config(pin, SubCommand::SetMinPinLength(new_min_pin_length))
    }

    pub fn set_min_pin_length_rpids(&self, rpids: Vec<String>, pin: Option<&str>) -> Result<()> {
        self.config(pin, SubCommand::SetMinPinLengthRpIds(rpids))
    }

    pub fn force_change_pin(&self, pin: Option<&str>) -> Result<()> {
        self.config(pin, SubCommand::ForceChangePin)
    }

    // needs to be reworked in regards to the auth token
    fn config(&self, pin: Option<&str>, sub_command: SubCommand) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;

        let pin_token = self.get_pin_uv_auth_token(
            &cid,
            DEFAULT_PIN_UV_AUTH_PROTOCOL,
            pin,
            Permissions::AUTHENTICATOR_CONFIGURATION,
            None,
        )?;

        let send_payload = authenticator_config_command::create_payload(pin_token, sub_command)?;
        let _response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;
        Ok(())
    }
}
