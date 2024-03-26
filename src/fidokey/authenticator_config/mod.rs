mod authenticator_config_command;

use super::FidoKeyHid;

use crate::ctaphid;
use crate::result::Result;
use crate::token::Token;

use authenticator_config_command::SubCommand;

impl FidoKeyHid {
    pub fn toggle_always_uv(&self, token: &Token) -> Result<()> {
        self.config(token, SubCommand::ToggleAlwaysUv)
    }

    pub fn set_min_pin_length(&self, new_min_pin_length: u8, token: &Token) -> Result<()> {
        self.config(token, SubCommand::SetMinPinLength(new_min_pin_length))
    }

    pub fn set_min_pin_length_rpids(&self, rpids: Vec<String>, token: &Token) -> Result<()> {
        self.config(token, SubCommand::SetMinPinLengthRpIds(rpids))
    }

    pub fn force_change_pin(&self, token: &Token) -> Result<()> {
        self.config(token, SubCommand::ForceChangePin)
    }

    fn config(&self, token: &Token, sub_command: SubCommand) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload = authenticator_config_command::create_payload(token, sub_command)?;
        let _response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        Ok(())
    }
}
