use super::client_pin_command;
use super::client_pin_command::Permissions;
use super::client_pin_command::SubCommand as PinCmd;
use super::client_pin_response;
use super::FidoKeyHid;
use crate::ctaphid;
use crate::encrypt::cose;
use crate::encrypt::enc_aes256_cbc;
use crate::encrypt::enc_hmac_sha_256;
use crate::encrypt::shared_secret::SharedSecret;
use crate::pintoken::PinToken;
use crate::result::Result;
use anyhow::anyhow;

impl FidoKeyHid {
    pub fn get_authenticator_key_agreement(
        &self,
        cid: &[u8],
        pin_uv_auth_protocol: Option<u32>,
    ) -> Result<cose::CoseKey> {
        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement, pin_uv_auth_protocol)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, cid, &send_payload)?;
        let authenticator_key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;
        Ok(authenticator_key_agreement)
    }

    pub fn get_pin_token(&self, cid: &[u8], pin_uv_auth_protocol: Option<u32>, pin: &str) -> Result<PinToken> {
        if !pin.is_empty() {
            let authenticator_key_agreement = self.get_authenticator_key_agreement(cid, pin_uv_auth_protocol)?;

            let shared_secret = SharedSecret::new(&authenticator_key_agreement)?;
            let pin_hash_enc = shared_secret.encrypt_pin(pin)?;

            let send_payload = client_pin_command::create_payload_get_pin_token(
                pin_uv_auth_protocol,
                &shared_secret.public_key,
                &pin_hash_enc,
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

    /* 
    pub fn get_pin_uv_auth_token(
        &self,
        cid: &[u8],
        permissions: Permissions,
        pin: Option<&str>,
        rp_id: Option<&str>,
    ) -> Result<PinToken> {
    }
    */

    pub fn get_pin_uv_auth_token_with_permissions(
        &self,
        cid: &[u8],
        pin_uv_auth_protocol: Option<u32>,
        pin: &str,
        permissions: Permissions,
    ) -> Result<PinToken> {
        if !pin.is_empty() {
            let authenticator_key_agreement = self.get_authenticator_key_agreement(cid, pin_uv_auth_protocol)?;

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

    pub fn set_pin(&self, cid: &[u8], pin_uv_auth_protocol: Option<u32>, pin: &str) -> Result<()> {
        if pin.is_empty() {
            return Err(anyhow!("No PIN provided").into());
        }

        let send_payload = client_pin_command::create_payload(PinCmd::GetKeyAgreement, pin_uv_auth_protocol)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, cid, &send_payload)?;

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        let shared_secret = SharedSecret::new(&key_agreement)?;

        let new_pin_enc = create_new_pin_enc(&shared_secret, pin)?;

        let pin_auth = create_pin_auth_for_set_pin(&shared_secret, &new_pin_enc)?;

        let send_payload = client_pin_command::create_payload_set_pin(
            pin_uv_auth_protocol,
            &shared_secret.public_key,
            &pin_auth,
            &new_pin_enc,
        );

        ctaphid::ctaphid_cbor(self, cid, &send_payload)?;

        Ok(())
    }
}

// pinAuth = LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16)
fn create_pin_auth_for_set_pin(
    shared_secret: &SharedSecret,
    new_pin_enc: &[u8],
) -> Result<Vec<u8>> {
    // HMAC-SHA-256(sharedSecret, newPinEnc)
    let sig = enc_hmac_sha_256::authenticate(&shared_secret.secret, new_pin_enc);

    // left 16
    let pin_auth = sig[0..16].to_vec();

    Ok(pin_auth)
}

fn create_pin_auth_for_change_pin(
    shared_secret: &SharedSecret,
    new_pin_enc: &[u8],
    current_pin_hash_enc: &[u8],
) -> Result<Vec<u8>> {
    // source data
    let mut message = vec![];
    message.append(&mut new_pin_enc.to_vec());
    message.append(&mut current_pin_hash_enc.to_vec());

    // HMAC-SHA-256(sharedSecret, message)
    let sig = enc_hmac_sha_256::authenticate(&shared_secret.secret, &message);

    // left 16
    let pin_auth = sig[0..16].to_vec();

    Ok(pin_auth)
}

fn padding_pin_64(pin: &str) -> Result<Vec<u8>> {
    // 5.5.5. Setting a New PIN
    // 5.5.6. Changing existing PIN
    // During encryption,
    // newPin is padded with trailing 0x00 bytes and is of minimum 64 bytes length.
    // This is to prevent leak of PIN length while communicating to the authenticator.
    // There is no PKCS #7 padding used in this scheme.

    let mut bpin64: Vec<u8> = vec![0; 64];
    let pintmp = pin.as_bytes();

    for (i, val) in pintmp.iter().enumerate() {
        bpin64[i] = *val;
    }

    Ok(bpin64)
}

// newPinEnc: AES256-CBC(sharedSecret, IV = 0, newPin)
fn create_new_pin_enc(shared_secret: &SharedSecret, new_pin: &str) -> Result<Vec<u8>> {
    let new_pin_64 = padding_pin_64(new_pin)?;

    let new_pin_enc = enc_aes256_cbc::encrypt_message(&shared_secret.secret, &new_pin_64);

    Ok(new_pin_enc)
}

pub fn change_pin(device: &FidoKeyHid, cid: &[u8], pin_uv_auth_protocol: Option<u32>, current_pin: &str, new_pin: &str) -> Result<()> {
    if current_pin.is_empty() {
        return Err(anyhow!("Current PIN not provided").into());
    }
    if new_pin.is_empty() {
        return Err(anyhow!("New PIN not provided").into());
    }

    let send_payload = client_pin_command::create_payload(PinCmd::GetKeyAgreement, pin_uv_auth_protocol)?;
    let response_cbor = ctaphid::ctaphid_cbor(device, cid, &send_payload)?;

    let key_agreement =
        client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

    let shared_secret = SharedSecret::new(&key_agreement)?;

    let new_pin_enc = create_new_pin_enc(&shared_secret, new_pin)?;

    let current_pin_hash_enc = shared_secret.encrypt_pin(current_pin)?;

    let pin_auth =
        create_pin_auth_for_change_pin(&shared_secret, &new_pin_enc, &current_pin_hash_enc)?;

    let send_payload = client_pin_command::create_payload_change_pin(
        pin_uv_auth_protocol,
        &shared_secret.public_key,
        &pin_auth,
        &new_pin_enc,
        &current_pin_hash_enc,
    );

    ctaphid::ctaphid_cbor(device, cid, &send_payload)?;

    Ok(())
}
