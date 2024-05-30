mod client_pin;
mod client_pin_command;
mod client_pin_response;
use super::FidoKeyHid;
use crate::{
    ctaphid,
    encrypt::{enc_aes256_cbc, enc_hmac_sha_256, shared_secret::SharedSecret},
    result::Result, token::{Permissions, Token},
};
use client_pin_command::SubCommand as PinCmd;
pub use client_pin_command::*;
pub use client_pin_response::*;

pub const DEFAULT_PIN_UV_AUTH_PROTOCOL: u32 = 1;

impl FidoKeyHid {
    /// Get PIN retry count
    pub fn get_pin_retries(&self, pin_uv_auth_protocol: u32) -> Result<u32> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload =
            client_pin_command::create_payload(PinCmd::GetRetries, pin_uv_auth_protocol)?;

        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        let pin = client_pin_response::parse_cbor_client_pin_get_retries(&response_cbor)?;

        pin.pin_retries
            .ok_or(anyhow::anyhow!("No PIN retries value found in authenticator response").into())
    }

    /// Get power cycle state, since CTAP 2.1
    /// This is very inefficient as at the same information is obtained from the PIN retries
    /// command, but we don't have a good result object to expose all PIN information
    pub fn get_power_cycle_state(&self, pin_uv_auth_protocol: u32) -> Result<Option<bool>> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload =
            client_pin_command::create_payload(PinCmd::GetRetries, pin_uv_auth_protocol)?;

        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        let pin = client_pin_response::parse_cbor_client_pin_get_retries(&response_cbor)?;

        Ok(pin.power_cycle_state)
    }

    /// Get UV retry count, since CTAP 2.1
    pub fn get_uv_retries(&self, pin_uv_auth_protocol: u32) -> Result<Option<u32>> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload =
            client_pin_command::create_payload(PinCmd::GetUVRetries, pin_uv_auth_protocol)?;

        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        let pin = client_pin_response::parse_cbor_client_pin_get_retries(&response_cbor)?;

        Ok(pin.uv_retries)
    }

    // Set New PIN
    pub fn set_pin(&self, pin_uv_auth_protocol: u32, pin: &str) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement, pin_uv_auth_protocol)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        let shared_secret = SharedSecret::new(&key_agreement)?;

        let pin_encrypted = encrypt_pin(&shared_secret, pin)?;

        let pin_auth = create_pin_auth_for_set_pin(&shared_secret, &pin_encrypted)?;

        let send_payload = client_pin_command::create_payload_set_pin(
            pin_uv_auth_protocol,
            &shared_secret.public_key,
            &pin_auth,
            &pin_encrypted,
        );

        ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        Ok(())
    }

    // Change PIN
    pub fn change_pin(
        &self,
        pin_uv_auth_protocol: u32,
        current_pin: &str,
        new_pin: &str,
    ) -> Result<()> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement, pin_uv_auth_protocol)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;
        let shared_secret = SharedSecret::new(&key_agreement)?;
        let new_pin_encrypted = encrypt_pin(&shared_secret, new_pin)?;
        let current_pin_hash_encrypted = shared_secret.encrypt_pin(current_pin)?;
        let pin_auth = create_pin_auth_for_change_pin(
            &shared_secret,
            &new_pin_encrypted,
            &current_pin_hash_encrypted,
        )?;

        let send_payload = client_pin_command::create_payload_change_pin(
            pin_uv_auth_protocol,
            &shared_secret.public_key,
            &pin_auth,
            &new_pin_encrypted,
            &current_pin_hash_encrypted,
        );
        ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        Ok(())
    }

    // CTAP 2.0 PIN token
    pub fn get_pin_token(&self, pin_uv_auth_protocol: u32, pin: &str) -> Result<Token> {
        let cid = ctaphid::ctaphid_init(self)?;

        let authenticator_key_agreement =
            self.get_authenticator_key_agreement(&cid, pin_uv_auth_protocol)?;

        let shared_secret = SharedSecret::new(&authenticator_key_agreement)?;
        let pin_encrypted = shared_secret.encrypt_pin(pin)?;

        let send_payload = client_pin_command::create_payload_get_pin_token(
            pin_uv_auth_protocol,
            &shared_secret.public_key,
            &pin_encrypted,
        );

        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        let mut pin_token_encrypted =
            client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;

        let pin_token_decrypted = shared_secret.decrypt_protocol_1(&mut pin_token_encrypted)?;

        Ok(Token {
            key: pin_token_decrypted,
            protocol: pin_uv_auth_protocol,
        })
    }

    // CTAP 2.1 PIN auth token using permissions
    pub fn get_auth_token_using_pin(
        &self,
        pin_uv_auth_protocol: u32,
        pin: &str,
        permissions: u8,
        rp_id: Option<&str>,
    ) -> Result<Token> {
        let cid = ctaphid::ctaphid_init(self)?;

        let authenticator_key_agreement =
            self.get_authenticator_key_agreement(&cid, pin_uv_auth_protocol)?;
        let shared_secret = SharedSecret::new(&authenticator_key_agreement)?;
        let pin_encrypted = shared_secret.encrypt_pin(pin)?;

        let send_payload =
            client_pin_command::create_payload_get_pin_uv_auth_token_using_pin_with_permissions(
                pin_uv_auth_protocol,
                &shared_secret.public_key,
                &pin_encrypted,
                Permissions::from_bits_truncate(permissions),
                rp_id,
            );
        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        let mut auth_token_encrypted =
            client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;
        let auth_token_decrypted = shared_secret.decrypt_protocol_1(&mut auth_token_encrypted)?;

        Ok(Token {
            key: auth_token_decrypted,
            protocol: pin_uv_auth_protocol,
        })
    }

    // CTAP 2.1 UV auth token using permissions
    pub fn get_auth_token_using_uv(
        &self,
        pin_uv_auth_protocol: u32,
        permissions: u8,
        rp_id: Option<&str>,
    ) -> Result<Token> {
        let cid = ctaphid::ctaphid_init(self)?;

        let authenticator_key_agreement =
            self.get_authenticator_key_agreement(&cid, pin_uv_auth_protocol)?;
        let shared_secret = SharedSecret::new(&authenticator_key_agreement)?;

        let send_payload =
            client_pin_command::create_payload_get_pin_uv_auth_token_using_uv_with_permissions(
                pin_uv_auth_protocol,
                &shared_secret.public_key,
                Permissions::from_bits_truncate(permissions),
                rp_id,
            );
        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        let mut auth_token_encrypted =
            client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;
        let auth_token_decrypted = shared_secret.decrypt_protocol_1(&mut auth_token_encrypted)?;

        Ok(Token {
            key: auth_token_decrypted,
            protocol: pin_uv_auth_protocol,
        })
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

// newPinEnc: AES256-CBC(sharedSecret, IV = 0, newPin)
fn encrypt_pin(shared_secret: &SharedSecret, pin: &str) -> Result<Vec<u8>> {
    let padded_pin = pad_pin(pin)?;
    let encrypted_pin = enc_aes256_cbc::encrypt_message(&shared_secret.secret, &padded_pin);

    Ok(encrypted_pin)
}

fn pad_pin(pin: &str) -> Result<Vec<u8>> {
    // 5.5.5. Setting a New PIN
    // 5.5.6. Changing existing PIN
    // During encryption,
    // newPin is padded with trailing 0x00 bytes and is of minimum 64 bytes length.
    // This is to prevent leak of PIN length while communicating to the authenticator.
    // There is no PKCS #7 padding used in this scheme.

    let mut padded_pin: Vec<u8> = vec![0; 64];

    for (i, val) in pin.as_bytes().iter().enumerate() {
        padded_pin[i] = *val;
    }

    Ok(padded_pin)
}
