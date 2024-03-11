mod client_pin;
mod client_pin_command;
mod client_pin_response;
use super::{get_info::InfoParam, FidoKeyHid};
use crate::{ctaphid, pintoken::PinToken, result::Result};
use client_pin_command::SubCommand as PinCmd;
pub use client_pin_command::*;
pub use client_pin_response::*;

impl FidoKeyHid {
    /// Get PIN retry count
    pub fn get_pin_retries(&self) -> Result<u32> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload = client_pin_command::create_payload(PinCmd::GetRetries)?;

        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        let pin = client_pin_response::parse_cbor_client_pin_get_retries(&response_cbor)?;

        pin.pin_retries
            .ok_or(anyhow::anyhow!("No PIN retries value found in authenticator response").into())
    }

    /// Get power cycle state, since CTAP 2.1
    /// This is very inefficient as at the same information is obtained from the PIN retries
    /// command, but we don't have a good result object to expose all PIN information
    pub fn get_power_cycle_state(&self) -> Result<Option<bool>> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload = client_pin_command::create_payload(PinCmd::GetRetries)?;

        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        let pin = client_pin_response::parse_cbor_client_pin_get_retries(&response_cbor)?;

        Ok(pin.power_cycle_state)
    }

    /// Get UV retry count, since CTAP 2.1
    pub fn get_uv_retries(&self) -> Result<Option<u32>> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload = client_pin_command::create_payload(PinCmd::GetUVRetries)?;

        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        let pin = client_pin_response::parse_cbor_client_pin_get_retries(&response_cbor)?;

        Ok(pin.uv_retries)
    }

    // Set New PIN
    pub fn set_new_pin(&self, pin: &str) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;
        self.set_pin(&cid, pin)?;
        Ok(())
    }

    // Change PIN
    pub fn change_pin(&self, current_pin: &str, new_pin: &str) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;
        client_pin::change_pin(self, &cid, current_pin, new_pin)?;
        Ok(())
    }

    // Have yet to find an appropriate command to test a PIN in the spec;
    // For now, we just try to get any PIN token
    pub fn get_any_pin_token(&self, pin: &str) -> Result<PinToken> {
        let cid = ctaphid::ctaphid_init(self)?;
        let info = self.get_info()?;

        match info.supports_version(InfoParam::VersionsFido21.as_ref().to_string()) {
            // This permission is very much chosen at random and not at all fool-proof
            // It might be better to request an undefined permission and get a token with no permissions
            // See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#getPinUvAuthTokenUsingPinWithPermissions
            true => {
                self.get_pinuv_auth_token_with_permission(&cid, pin, Permissions::LARGE_BLOB_WRITE)
            }
            false => self.get_pin_token(&cid, pin),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SubCommand as PinCmd;
    use super::*;
    use crate::ctaphid;
    use crate::fidokey::FidoKeyHid;
    use crate::Cfg;
    use crate::HidParam;

    #[test]
    fn test_client_pin_get_keyagreement() {
        let hid_params = HidParam::get();
        let device = FidoKeyHid::new(&hid_params, &Cfg::init(), None).unwrap();
        let cid = ctaphid::ctaphid_init(&device).unwrap();

        let send_payload = create_payload(PinCmd::GetKeyAgreement).unwrap();
        let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload).unwrap();

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor).unwrap();
        println!("authenticatorClientPIN (0x06) - getKeyAgreement");
        println!("{}", key_agreement);

        assert!(true);
    }

    #[test]
    fn test_client_pin_get_any_pin_token() {
        let hid_params = HidParam::get();
        let mut hid_cfg = Cfg::init();
        hid_cfg.enable_log = true;
        let device = FidoKeyHid::new(&hid_params, &hid_cfg, None).unwrap();

        match device.get_any_pin_token("0000") {
            Ok(_) => println!("Got PIN token"),
            Err(e) => println!("{}", e),
        }

        assert!(true);
    }
}
