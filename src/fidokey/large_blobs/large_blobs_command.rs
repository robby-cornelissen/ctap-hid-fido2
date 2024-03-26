use crate::result::Result;
use crate::token::Token;
use crate::{ctapdef, encrypt::enc_hmac_sha_256};
use ring::digest;
use serde_cbor::{to_vec, Value};
use std::collections::BTreeMap;

pub fn create_payload_t(
    token: Option<&Token>,
    offset: u32,
    get: Option<u32>,
    set: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    // create cbor
    let mut map = BTreeMap::new();

    // 0x01: get
    if let Some(read_bytes) = get {
        map.insert(Value::Integer(0x01), Value::Integer(read_bytes.into()));
    }

    // 0x03: offset
    map.insert(Value::Integer(0x03), Value::Integer(offset.into()));

    if let Some(write_data) = set {
        let large_blob_array = create_large_blob_array(write_data)?;

        // 0x02: set
        map.insert(
            Value::Integer(0x02),
            Value::Bytes(large_blob_array.to_vec()),
        );

        // 0x04: length
        map.insert(
            Value::Integer(0x04),
            Value::Integer(large_blob_array.len() as i128),
        );

        if let Some(token) = token {
            // 0x05: pinUvAuthParam
            let pin_uv_auth_param = {
                let mut message = vec![0xff; 32];
                message.append(&mut vec![0x0c, 0x00]);
                message.append(&mut offset.to_le_bytes().to_vec());

                let hash = digest::digest(&digest::SHA256, &large_blob_array);
                message.append(&mut hash.as_ref().to_vec());

                let sig = enc_hmac_sha_256::authenticate(&token.key, &message);
                sig[0..16].to_vec()
            };
            map.insert(Value::Integer(0x05), Value::Bytes(pin_uv_auth_param));

            // 0x06: pinUvAuthProtocol
            map.insert(Value::Integer(0x06), Value::Integer(token.protocol.into()));
        }
    }

    // CBOR
    let cbor = Value::Map(map);

    let mut payload = [ctapdef::AUTHENTICATOR_LARGEBLOBS].to_vec();
    payload.append(&mut to_vec(&cbor).map_err(anyhow::Error::new)?);

    Ok(payload)
}

fn create_large_blob_array(write_data: Vec<u8>) -> Result<Vec<u8>> {
    let data = write_data.to_vec();

    let hash = digest::digest(&digest::SHA256, &data);
    let message = &hash.as_ref()[0..16];

    let mut large_blob_array = data.to_vec();
    large_blob_array.append(&mut message.to_vec());

    Ok(large_blob_array)
}
