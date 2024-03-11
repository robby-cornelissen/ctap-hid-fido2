use crate::{ctapdef, result::Result};

pub fn create_payload() -> Result<Vec<u8>> {
    let payload = [ctapdef::AUTHENTICATOR_RESET].to_vec();

    Ok(payload)
}