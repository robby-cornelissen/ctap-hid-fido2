use crate::{ctaphid, FidoKeyHid};
use crate::result::Result;

mod authenticator_reset_command;

impl FidoKeyHid {
    pub fn reset_authenticator(&self) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;
        let send_payload = authenticator_reset_command::create_payload()?;

        ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        Ok(())
    }
}