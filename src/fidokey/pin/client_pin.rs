use super::client_pin_command;
use super::client_pin_command::SubCommand as PinCmd;
use super::client_pin_response;
use super::FidoKeyHid;
use crate::ctaphid;
use crate::encrypt::cose;
use crate::encrypt::shared_secret::SharedSecret;
use crate::pintoken::{Permissions, PinToken};
use crate::result::Result;
use anyhow::anyhow;

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

    // needs to go
    pub fn get_pin_uv_auth_token(
        &self,
        cid: &[u8],
        pin_uv_auth_protocol: u32,
        pin: Option<&str>,
        permissions: Permissions,
        rp_id: Option<&str>,
    ) -> Result<PinToken> {
        let authenticator_key_agreement =
            self.get_authenticator_key_agreement(cid, pin_uv_auth_protocol)?;
        let shared_secret = SharedSecret::new(&authenticator_key_agreement)?;

        let send_payload = match pin {
            Some(pin) => {
                let pin_hash_enc = shared_secret.encrypt_pin(pin)?;

                client_pin_command::create_payload_get_pin_uv_auth_token_using_pin_with_permissions(
                    pin_uv_auth_protocol,
                    &shared_secret.public_key,
                    &pin_hash_enc,
                    permissions,
                    rp_id,
                )
            }
            None => {
                client_pin_command::create_payload_get_pin_uv_auth_token_using_uv_with_permissions(
                    pin_uv_auth_protocol,
                    &shared_secret.public_key,
                    permissions,
                    rp_id,
                )
            }
        };

        let response_cbor = ctaphid::ctaphid_cbor(self, cid, &send_payload)?;
        let mut pin_token_enc =
            client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;
        let pin_token_dec = shared_secret.decrypt_token(&mut pin_token_enc)?;

        Ok(pin_token_dec)
    }

    // This method needs to disappear at some point, currently large BLOB still reference it
    pub fn get_pin_uv_auth_token_with_permissions(
        &self,
        cid: &[u8],
        pin_uv_auth_protocol: u32,
        pin: &str,
        permissions: Permissions,
    ) -> Result<PinToken> {
        if !pin.is_empty() {
            let authenticator_key_agreement =
                self.get_authenticator_key_agreement(cid, pin_uv_auth_protocol)?;

            // Get pinHashEnc
            // - shared_secret.public_key -> platform KeyAgreement
            let shared_secret = SharedSecret::new(&authenticator_key_agreement)?;
            let pin_hash_enc = shared_secret.encrypt_pin(pin)?;

            // Get pin token
            let send_payload =
                client_pin_command::create_payload_get_pin_uv_auth_token_using_pin_with_permissions(
                    pin_uv_auth_protocol,
                    &shared_secret.public_key,
                    &pin_hash_enc,
                    permissions,
                    None,
                );
            let response_cbor = ctaphid::ctaphid_cbor(self, cid, &send_payload)?;

            // get pin_token (enc)
            let mut pin_token_enc =
                client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;

            // pintoken -> dec(pintoken)
            let pin_token_dec = shared_secret.decrypt_token(&mut pin_token_enc)?;

            Ok(pin_token_dec)
        } else {
            Err(anyhow!("No PIN provided").into())
        }
    }
}
