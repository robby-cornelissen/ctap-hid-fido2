use crate::ctaphid;
use crate::encrypt::shared_secret::SharedSecret;
use crate::fidokey::pin::DEFAULT_PIN_UV_AUTH_PROTOCOL;
use crate::fidokey::pin::{
    create_payload, parse_cbor_client_pin_get_keyagreement, SubCommand as PinCmd,
};
use crate::result::Result;
use crate::FidoKeyHid;

#[derive(Clone, Debug)]
pub struct HmacExt {
    pub shared_secret: SharedSecret,
    pub salt_enc: Vec<u8>,
    pub salt_auth: Vec<u8>,
}

impl HmacExt {
    pub fn create(
        device: &FidoKeyHid,
        cid: &[u8],
        salt1: &[u8; 32],
        _salt2: Option<&[u8; 32]>,
    ) -> Result<Self> {
        //println!("----------");
        //println!("{}", StrBuf::bufh("salt1", salt1));

        let send_payload = create_payload(PinCmd::GetKeyAgreement, DEFAULT_PIN_UV_AUTH_PROTOCOL)?;
        let response_cbor = ctaphid::ctaphid_cbor(device, cid, &send_payload)?;

        let key_agreement = parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        //println!("key_agreement");
        //println!("{}", self.key_agreement);

        let shared_secret = SharedSecret::create(DEFAULT_PIN_UV_AUTH_PROTOCOL, &key_agreement)?;

        // saltEnc
        //  Encryption of the one or two salts (called salt1 (32 bytes)
        //  and salt2 (32 bytes)) using the shared secret as follows
        // One salt case: encrypt(shared secret, salt1)
        // Two salt case: encrypt(shared secret, salt1 || salt2)
        //  encrypt(key, demPlaintext) → ciphertext
        //      Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext.
        //      The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
        let salt_enc = shared_secret.encrypt(salt1)?.to_vec();
        //println!("{}", StrBuf::bufh("salt_enc", &self.salt_enc));

        // saltAuth
        let salt_auth = shared_secret.authenticate(&salt_enc)?;
        //println!("{}", StrBuf::bufh("salt_auth", &self.salt_auth));

        Ok(HmacExt{ shared_secret, salt_enc, salt_auth })
    }
}
