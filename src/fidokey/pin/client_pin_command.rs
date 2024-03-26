use crate::ctapdef;
use crate::encrypt::cose;
use crate::result::Result;
use crate::token::Permissions;
use serde_cbor::Value;
use std::collections::BTreeMap;

pub enum SubCommand {
    GetRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    GetUVRetries = 0x07,
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

fn create_payload_get_uv_retries(pin_uv_auth_protocol: u32) -> Vec<u8> {
    let mut map = BTreeMap::new();
    insert_pin_uv_auth_protocol(&mut map, pin_uv_auth_protocol);
    insert_sub_command(&mut map, SubCommand::GetUVRetries);
    to_payload(map)
}

fn create_payload_get_retries(pin_uv_auth_protocol: u32) -> Vec<u8> {
    let mut map = BTreeMap::new();
    insert_pin_uv_auth_protocol(&mut map, pin_uv_auth_protocol);
    insert_sub_command(&mut map, SubCommand::GetRetries);
    to_payload(map)
}

fn create_payload_get_keyagreement(pin_uv_auth_protocol: u32) -> Vec<u8> {
    let mut map = BTreeMap::new();
    insert_pin_uv_auth_protocol(&mut map, pin_uv_auth_protocol);
    insert_sub_command(&mut map, SubCommand::GetKeyAgreement);
    to_payload(map)
}

pub fn create_payload_get_pin_token(
    pin_uv_auth_protocol: u32,
    key_agreement: &cose::CoseKey,
    pin_hash_enc: &[u8],
) -> Vec<u8> {
    let mut map = BTreeMap::new();
    insert_pin_uv_auth_protocol(&mut map, pin_uv_auth_protocol);
    insert_sub_command(&mut map, SubCommand::GetPinToken);
    insert_key_agreement(&mut map, key_agreement);
    insert_pin_hash_enc(&mut map, pin_hash_enc);
    to_payload(map)
}

pub fn create_payload_set_pin(
    pin_uv_auth_protocol: u32,
    key_agreement: &cose::CoseKey,
    pin_auth: &[u8],
    new_pin_enc: &[u8],
) -> Vec<u8> {
    let mut map = BTreeMap::new();
    insert_pin_uv_auth_protocol(&mut map, pin_uv_auth_protocol);
    insert_sub_command(&mut map, SubCommand::SetPin);
    insert_key_agreement(&mut map, key_agreement);
    insert_pin_auth(&mut map, pin_auth);
    insert_new_pin_enc(&mut map, new_pin_enc);
    to_payload(map)
}

pub fn create_payload_change_pin(
    pin_uv_auth_protocol: u32,
    key_agreement: &cose::CoseKey,
    pin_auth: &[u8],
    new_pin_enc: &[u8],
    pin_hash_enc: &[u8],
) -> Vec<u8> {
    let mut map = BTreeMap::new();
    insert_pin_uv_auth_protocol(&mut map, pin_uv_auth_protocol);
    insert_sub_command(&mut map, SubCommand::ChangePin);
    insert_key_agreement(&mut map, key_agreement);
    insert_pin_auth(&mut map, pin_auth);
    insert_new_pin_enc(&mut map, new_pin_enc);
    insert_pin_hash_enc(&mut map, pin_hash_enc);
    to_payload(map)
}

pub fn create_payload_get_pin_uv_auth_token_using_pin_with_permissions(
    pin_uv_auth_protocol: u32,
    key_agreement: &cose::CoseKey,
    pin_hash_enc: &[u8],
    permissions: Permissions,
    rp_id: Option<&str>,
) -> Vec<u8> {
    let mut map = BTreeMap::new();
    insert_pin_uv_auth_protocol(&mut map, pin_uv_auth_protocol);
    insert_sub_command(
        &mut map,
        SubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
    );
    insert_key_agreement(&mut map, key_agreement);

    // pinHashEnc(0x06) - Byte String
    let value = Value::Bytes(pin_hash_enc.to_vec());
    map.insert(Value::Integer(0x06), value);

    // permission(0x09) - Unsigned Integer
    let value = Value::Integer(permissions.bits() as i128);
    map.insert(Value::Integer(0x09), value);

    // rpid(0x0A) - String
    if let Some(rp_id) = rp_id {
        let value = Value::Text(rp_id.to_string());
        map.insert(Value::Integer(0x0A), value);
    }

    to_payload(map)
}

pub fn create_payload_get_pin_uv_auth_token_using_uv_with_permissions(
    pin_uv_auth_protocol: u32,
    key_agreement: &cose::CoseKey,
    permissions: Permissions,
    rp_id: Option<&str>,
) -> Vec<u8> {
    let mut map = BTreeMap::new();
    insert_pin_uv_auth_protocol(&mut map, pin_uv_auth_protocol);
    insert_sub_command(
        &mut map,
        SubCommand::GetPinUvAuthTokenUsingUvWithPermissions,
    );
    insert_key_agreement(&mut map, key_agreement);

    // permission(0x09) - Unsigned Integer
    let value = Value::Integer(permissions.bits() as i128);
    map.insert(Value::Integer(0x09), value);

    // rpid(0x0A) - String
    if let Some(rp_id) = rp_id {
        let value = Value::Text(rp_id.to_string());
        map.insert(Value::Integer(0x0A), value);
    }

    to_payload(map)
}

// create payload
fn to_payload(map: BTreeMap<Value, Value>) -> Vec<u8> {
    let cbor = Value::Map(map);
    let mut payload = [ctapdef::AUTHENTICATOR_CLIENT_PIN].to_vec();
    payload.append(&mut serde_cbor::to_vec(&cbor).unwrap());
    payload.to_vec()
}

// 0x01 : pin_protocol
fn insert_pin_uv_auth_protocol(
    map: &mut BTreeMap<Value, Value>,
    pin_uv_auth_protocol: u32,
) {
    let pin_uv_auth_protocol = Value::Integer(pin_uv_auth_protocol.into());
    map.insert(Value::Integer(0x01), pin_uv_auth_protocol);
}

// 0x02 : sub_command
fn insert_sub_command(map: &mut BTreeMap<Value, Value>, cmd: SubCommand) {
    let sub_cmd = Value::Integer(cmd as i128);
    map.insert(Value::Integer(0x02), sub_cmd);
}

// 0x03 : key_agreement : COSE_Key
fn insert_key_agreement(map: &mut BTreeMap<Value, Value>, key_agreement: &cose::CoseKey) {
    let mut ka_val = BTreeMap::new();
    ka_val.insert(
        Value::Integer(1),
        Value::Integer(key_agreement.key_type.into()),
    );
    ka_val.insert(
        Value::Integer(3),
        Value::Integer(key_agreement.algorithm.into()),
    );
    if let Value::Integer(ival) = key_agreement.parameters.get(&-1).unwrap() {
        ka_val.insert(Value::Integer(-1), Value::Integer(*ival));
    }
    if let Value::Bytes(bval) = key_agreement.parameters.get(&-2).unwrap() {
        ka_val.insert(Value::Integer(-2), Value::Bytes(bval.to_vec()));
    }
    if let Value::Bytes(bval) = key_agreement.parameters.get(&-3).unwrap() {
        ka_val.insert(Value::Integer(-3), Value::Bytes(bval.to_vec()));
    }
    let ka = Value::Map(ka_val);

    map.insert(Value::Integer(0x03), ka);
}

// 0x04 : pin_auth
fn insert_pin_auth(map: &mut BTreeMap<Value, Value>, pin_auth: &[u8]) {
    let pin_auth_val = Value::Bytes(pin_auth.to_vec());
    map.insert(Value::Integer(0x04), pin_auth_val);
}

// 0x05 : new_pin_enc
fn insert_new_pin_enc(map: &mut BTreeMap<Value, Value>, new_pin_enc: &[u8]) {
    let new_pin_enc_val = Value::Bytes(new_pin_enc.to_vec());
    map.insert(Value::Integer(0x05), new_pin_enc_val);
}

// 0x06 : pin_hash_enc
fn insert_pin_hash_enc(map: &mut BTreeMap<Value, Value>, pin_hash_enc: &[u8]) {
    let pin_hash_enc_val = Value::Bytes(pin_hash_enc.to_vec());
    map.insert(Value::Integer(0x06), pin_hash_enc_val);
}

pub fn create_payload(
    sub_command: SubCommand,
    pin_uv_auth_protocol: u32,
) -> Result<Vec<u8>> {
    match sub_command {
        SubCommand::GetRetries => Ok(create_payload_get_retries(pin_uv_auth_protocol)),
        SubCommand::GetKeyAgreement => Ok(create_payload_get_keyagreement(pin_uv_auth_protocol)),
        SubCommand::SetPin => Err(anyhow::anyhow!("Not Supported").into()),
        SubCommand::ChangePin => Err(anyhow::anyhow!("Not Supported").into()),
        SubCommand::GetPinToken => Err(anyhow::anyhow!("Not Supported").into()),
        SubCommand::GetPinUvAuthTokenUsingUvWithPermissions => {
            Err(anyhow::anyhow!("Not Supported").into())
        }
        SubCommand::GetUVRetries => Ok(create_payload_get_uv_retries(pin_uv_auth_protocol)),
        SubCommand::GetPinUvAuthTokenUsingPinWithPermissions => {
            Err(anyhow::anyhow!("Not Supported").into())
        }
    }
}
