use super::make_credential_params::{CredentialSupportedKeyType, Extension};
use crate::ctapdef;
use crate::encrypt::enc_hmac_sha_256;
use crate::token::Token;
use crate::util;
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct ParamsT {
    pub rp_id: String,
    pub rp_name: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub exclude_list: Vec<Vec<u8>>,
    pub option_rk: bool,
    pub option_up: Option<bool>,
    pub option_uv: Option<bool>,
    pub client_data_hash: Vec<u8>,
    pub key_types: Vec<CredentialSupportedKeyType>,
}

// TODO probably can remove this as well
impl ParamsT {
    pub fn new(rp_id: &str, challenge: Vec<u8>, user_id: Vec<u8>) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            user_id: user_id.to_vec(),
            client_data_hash: util::create_clientdata_hash(challenge),
            key_types: vec![CredentialSupportedKeyType::Ecdsa256],
            ..Default::default()
        }
    }
}

pub fn create_payload_t(
    token: Option<&Token>,
    params: ParamsT,
    extensions: Option<&Vec<Extension>>,
) -> Vec<u8> {
    // 0x01 : clientDataHash
    let client_data_hash = Value::Bytes(params.client_data_hash.clone());

    // 0x02 : rp
    let mut rp_map = BTreeMap::new();
    rp_map.insert(
        Value::Text("id".to_string()),
        Value::Text(params.rp_id.to_string()),
    );
    rp_map.insert(
        Value::Text("name".to_string()),
        Value::Text(params.rp_name.to_string()),
    );
    let rp = Value::Map(rp_map);

    // 0x03 : user
    let mut user_map = BTreeMap::new();

    // user id
    let user_id = {
        if !params.user_id.is_empty() {
            params.user_id.to_vec()
        } else {
            vec![0x00]
        }
    };
    user_map.insert(Value::Text("id".to_string()), Value::Bytes(user_id));

    // user name
    let user_name = {
        if !params.user_name.is_empty() {
            params.user_name.to_string()
        } else {
            " ".to_string() // TODO get a better default
        }
    };
    user_map.insert(Value::Text("name".to_string()), Value::Text(user_name));

    // displayName
    let display_name = {
        if !params.user_display_name.is_empty() {
            params.user_display_name.to_string()
        } else {
            " ".to_string() // TODO get a better default
        }
    };
    user_map.insert(
        Value::Text("displayName".to_string()),
        Value::Text(display_name),
    );

    let user = Value::Map(user_map);

    // 0x04 : pubKeyCredParams
    let pub_key_cred_params = Value::Array(
        params
            .key_types
            .iter()
            .map(|key_type| {
                let mut pub_key_cred_params_map = BTreeMap::new();
                pub_key_cred_params_map.insert(
                    Value::Text("alg".to_string()),
                    Value::Integer(*key_type as i128),
                );
                pub_key_cred_params_map.insert(
                    Value::Text("type".to_string()),
                    Value::Text("public-key".to_string()),
                );
                Value::Map(pub_key_cred_params_map)
            })
            .collect(),
    );

    // 0x05 : excludeList
    let exclude_list = Value::Array(
        params
            .exclude_list
            .iter()
            .cloned()
            .map(|credential_id| {
                let mut exclude_list_map = BTreeMap::new();
                exclude_list_map.insert(Value::Text("id".to_string()), Value::Bytes(credential_id));
                exclude_list_map.insert(
                    Value::Text("type".to_string()),
                    Value::Text("public-key".to_string()),
                );
                Value::Map(exclude_list_map)
            })
            .collect(),
    );

    // 0x06 : extensions
    let extensions = if let Some(extensions) = extensions {
        let mut extensions_map = BTreeMap::new();
        for extension in extensions {
            match *extension {
                Extension::CredBlob((ref n, _)) => {
                    let x = n.clone().unwrap();
                    extensions_map.insert(Value::Text(extension.to_string()), Value::Bytes(x));
                }
                Extension::CredProtect(n) => {
                    extensions_map.insert(
                        Value::Text(extension.to_string()),
                        Value::Integer(n.unwrap() as i128),
                    );
                }
                Extension::HmacSecret(n)
                | Extension::LargeBlobKey((n, _))
                | Extension::MinPinLength((n, _)) => {
                    extensions_map
                        .insert(Value::Text(extension.to_string()), Value::Bool(n.unwrap()));
                }
            };
        }
        Some(Value::Map(extensions_map))
    } else {
        None
    };

    // 0x07 : options
    let options = {
        let mut options_map = BTreeMap::new();

        options_map.insert(Value::Text("rk".to_string()), Value::Bool(params.option_rk));

        if let Some(v) = params.option_up {
            options_map.insert(Value::Text("up".to_string()), Value::Bool(v));
        }

        if let Some(v) = params.option_uv {
            options_map.insert(Value::Text("uv".to_string()), Value::Bool(v));
        }

        Value::Map(options_map)
    };

    // pinUvAuthParam(0x08)
    let pin_uv_auth_param = if let Some(token) = token {
        let signature = enc_hmac_sha_256::authenticate(&token.key, &params.client_data_hash);
        let pin_uv_auth_param = signature[0..16].to_vec();

        Some(Value::Bytes(pin_uv_auth_param))
    } else {
        None
    };

    // 0x09:pinProtocol
    let pin_uv_auth_protocol = if let Some(token) = token {
        Some(Value::Integer(token.protocol.into()))
    } else {
        None
    };

    // create cbor object
    let mut make_credential = BTreeMap::new();
    make_credential.insert(Value::Integer(0x01), client_data_hash);
    make_credential.insert(Value::Integer(0x02), rp);
    make_credential.insert(Value::Integer(0x03), user);
    make_credential.insert(Value::Integer(0x04), pub_key_cred_params);

    if !params.exclude_list.is_empty() {
        make_credential.insert(Value::Integer(0x05), exclude_list);
    }

    if let Some(extensions) = extensions {
        make_credential.insert(Value::Integer(0x06), extensions);
    }

    make_credential.insert(Value::Integer(0x07), options);

    if let Some(pin_uv_auth_param) = pin_uv_auth_param {
        make_credential.insert(Value::Integer(0x08), pin_uv_auth_param);
    }

    if let Some(pin_uv_auth_protocol) = pin_uv_auth_protocol {
        make_credential.insert(Value::Integer(0x09), pin_uv_auth_protocol);
    }

    let cbor = Value::Map(make_credential);

    // Command - authenticatorMakeCredential (0x01)
    let mut payload = [ctapdef::AUTHENTICATOR_MAKE_CREDENTIAL].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());

    payload
}
