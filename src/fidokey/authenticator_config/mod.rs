mod authenticator_config_command;

use super::FidoKeyHid;

use crate::ctaphid;
use crate::result::Result;
use crate::token::Token;

use authenticator_config_command::SubCommand;

impl FidoKeyHid {
    pub fn toggle_always_uv_t(&self, token: &Token) -> Result<()> {
        self.config_t(token, SubCommand::ToggleAlwaysUv)
    }

    pub fn set_min_pin_length_t(&self, new_min_pin_length: u8, token: &Token) -> Result<()> {
        self.config_t(token, SubCommand::SetMinPinLength(new_min_pin_length))
    }

    pub fn set_min_pin_length_rpids_t(&self, rpids: Vec<String>, token: &Token) -> Result<()> {
        self.config_t(token, SubCommand::SetMinPinLengthRpIds(rpids))
    }

    pub fn force_change_pin_t(&self, token: &Token) -> Result<()> {
        self.config_t(token, SubCommand::ForceChangePin)
    }

    fn config_t(&self, token: &Token, sub_command: SubCommand) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload = authenticator_config_command::create_payload_t(token, sub_command)?;
        let _response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        Ok(())
    }
}
