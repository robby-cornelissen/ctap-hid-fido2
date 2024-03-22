use super::get_assertion_params::Extension;
use crate::ctapdef;
use crate::encrypt::enc_hmac_sha_256;
use crate::hmac_ext::HmacExt;
use crate::token::Token;
use crate::util;
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct ParamsT {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub allowlist_credential_ids: Vec<Vec<u8>>,
    pub option_up: bool,
    pub option_uv: Option<bool>,
}

// TODO remove
#[derive(Debug, Default)]
pub struct Params {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub allowlist_credential_ids: Vec<Vec<u8>>,
    pub option_up: bool,
    pub option_uv: Option<bool>,
    pub pin_auth: Vec<u8>,
}

impl ParamsT {
    pub fn new(rp_id: &str, challenge: Vec<u8>, credential_ids: Vec<Vec<u8>>) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            client_data_hash: util::create_clientdata_hash(challenge),
            allowlist_credential_ids: credential_ids,
            ..Default::default()
        }
    }
}

// TODO remove
impl Params {
    pub fn new(rp_id: &str, challenge: Vec<u8>, credential_ids: Vec<Vec<u8>>) -> Params {
        Params {
            rp_id: rp_id.to_string(),
            client_data_hash: util::create_clientdata_hash(challenge),
            allowlist_credential_ids: credential_ids,
            ..Default::default()
        }
    }
}

pub fn create_payload_t(
    token: Option<&Token>,
    params: ParamsT,
    extensions: Option<&Vec<Extension>>,
    hmac_ext: Option<HmacExt>,
) -> Vec<u8> {
    // 0x01 : rpid
    let rp_id = Value::Text(params.rp_id.to_string());

    // 0x02 : clientDataHash
    let client_data_hash = Value::Bytes(params.client_data_hash.clone());

    // 0x03 : allowList
    let allow_list = {
        if !params.allowlist_credential_ids.is_empty() {
            let allow_list = Value::Array(
                params
                    .allowlist_credential_ids
                    .iter()
                    .cloned()
                    .map(|credential_id| {
                        let mut allow_list_val = BTreeMap::new();
                        allow_list_val
                            .insert(Value::Text("id".to_string()), Value::Bytes(credential_id));
                        allow_list_val.insert(
                            Value::Text("type".to_string()),
                            Value::Text("public-key".to_string()),
                        );
                        Value::Map(allow_list_val)
                    })
                    .collect(),
            );
            Some(allow_list)
        } else {
            None
        }
    };

    // 0x04 : extensions
    let extensions = {
        let mut extensions_map = BTreeMap::new();

        // HMAC Secret Extension
        if let Some(hmac_ext) = hmac_ext {
            let mut hmac_ext_map = BTreeMap::new();

            // keyAgreement(0x01)
            let val = hmac_ext.shared_secret.public_key.to_value().unwrap();
            hmac_ext_map.insert(Value::Integer(0x01), val);

            // saltEnc(0x02)
            hmac_ext_map.insert(Value::Integer(0x02), Value::Bytes(hmac_ext.salt_enc));

            // saltAuth(0x03)
            hmac_ext_map.insert(Value::Integer(0x03), Value::Bytes(hmac_ext.salt_auth));

            extensions_map.insert(
                Value::Text(Extension::HmacSecret(None).to_string()),
                Value::Map(hmac_ext_map),
            );
        }

        if let Some(extensions) = extensions {
            for extension in extensions {
                match *extension {
                    Extension::HmacSecret(_) => (),
                    Extension::LargeBlobKey((n, _)) | Extension::CredBlob((n, _)) => {
                        extensions_map.insert(Value::Text(extension.to_string()), Value::Bool(n.unwrap()));
                    }
                };
            }
        }
        if extensions_map.is_empty() {
            None
        } else {
            Some(Value::Map(extensions_map))
        }
    };

    // 0x05 : options
    let mut options_map = BTreeMap::new();
    options_map.insert(Value::Text("up".to_string()), Value::Bool(params.option_up));

    if let Some(v) = params.option_uv {
        options_map.insert(Value::Text("uv".to_string()), Value::Bool(v));
    }

    let options = Value::Map(options_map);

    // pinUvAuthParam(0x06)
    let pin_uv_auth_param = if let Some(token) = token {
        let signature = enc_hmac_sha_256::authenticate(&token.key, &params.client_data_hash);
        let pin_uv_auth_param = signature[0..16].to_vec();

        Some(Value::Bytes(pin_uv_auth_param))
    } else {
        None
    };

    // 0x07:pinProtocol
    let pin_uv_auth_protocol = if let Some(token) = token {
        Some(Value::Integer(token.protocol.into()))
    } else {
        None
    };

    // create cbor object
    let mut get_assertion_map = BTreeMap::new();
    get_assertion_map.insert(Value::Integer(0x01), rp_id);
    get_assertion_map.insert(Value::Integer(0x02), client_data_hash);

    if let Some(obj) = allow_list {
        get_assertion_map.insert(Value::Integer(0x03), obj);
    }

    if let Some(extensions) = extensions {
        get_assertion_map.insert(Value::Integer(0x04), extensions);
    }
    get_assertion_map.insert(Value::Integer(0x05), options);

    if let Some(pin_uv_auth_param) = pin_uv_auth_param {
        get_assertion_map.insert(Value::Integer(0x06), pin_uv_auth_param);
    }

    if let Some(pin_uv_auth_protocol) = pin_uv_auth_protocol {
        get_assertion_map.insert(Value::Integer(0x07), pin_uv_auth_protocol);

    }

    let get_assertion = Value::Map(get_assertion_map);

    // Command - authenticatorGetAssertion (0x02)
    let mut payload = [ctapdef::AUTHENTICATOR_GET_ASSERTION].to_vec();
    payload.append(&mut to_vec(&get_assertion).unwrap());

    payload
}

// TODO remove
pub fn create_payload(
    params: Params,
    extensions: Option<&Vec<Extension>>,
    hmac_ext: Option<HmacExt>,
) -> Vec<u8> {
    // 0x01 : rpid
    let rpid = Value::Text(params.rp_id.to_string());

    // 0x02 : clientDataHash
    let cdh = Value::Bytes(params.client_data_hash);

    // 0x03 : allowList
    let allow_list = {
        if !params.allowlist_credential_ids.is_empty() {
            let allow_list = Value::Array(
                params
                    .allowlist_credential_ids
                    .iter()
                    .cloned()
                    .map(|credential_id| {
                        let mut allow_list_val = BTreeMap::new();
                        allow_list_val
                            .insert(Value::Text("id".to_string()), Value::Bytes(credential_id));
                        allow_list_val.insert(
                            Value::Text("type".to_string()),
                            Value::Text("public-key".to_string()),
                        );
                        Value::Map(allow_list_val)
                    })
                    .collect(),
            );
            Some(allow_list)
        } else {
            None
        }
    };

    // 0x04 : extensions
    let extensions = {
        let mut ext_val = BTreeMap::new();

        // HMAC Secret Extension
        if let Some(hmac_ext) = hmac_ext {
            let mut param = BTreeMap::new();

            // keyAgreement(0x01)
            let val = hmac_ext.shared_secret.public_key.to_value().unwrap();
            param.insert(Value::Integer(0x01), val);

            // saltEnc(0x02)
            param.insert(Value::Integer(0x02), Value::Bytes(hmac_ext.salt_enc));

            // saltAuth(0x03)
            param.insert(Value::Integer(0x03), Value::Bytes(hmac_ext.salt_auth));

            ext_val.insert(
                Value::Text(Extension::HmacSecret(None).to_string()),
                Value::Map(param),
            );
        }

        if let Some(extensions) = extensions {
            for ext in extensions {
                match *ext {
                    Extension::HmacSecret(_) => (),
                    Extension::LargeBlobKey((n, _)) | Extension::CredBlob((n, _)) => {
                        ext_val.insert(Value::Text(ext.to_string()), Value::Bool(n.unwrap()));
                    }
                };
            }
        }
        if ext_val.is_empty() {
            None
        } else {
            Some(Value::Map(ext_val))
        }
    };

    // 0x05 : options
    let mut options_val = BTreeMap::new();
    options_val.insert(Value::Text("up".to_string()), Value::Bool(params.option_up));
    if let Some(v) = params.option_uv {
        options_val.insert(Value::Text("uv".to_string()), Value::Bool(v));
    }

    let options = Value::Map(options_val);

    // pinAuth(0x06)
    let pin_auth = {
        if !params.pin_auth.is_empty() {
            Some(Value::Bytes(params.pin_auth))
        } else {
            None
        }
    };

    // 0x07:pinProtocol
    let pin_protocol = Value::Integer(1);

    // create cbor object
    let mut get_assertion = BTreeMap::new();
    get_assertion.insert(Value::Integer(0x01), rpid);
    get_assertion.insert(Value::Integer(0x02), cdh);
    if let Some(obj) = allow_list {
        get_assertion.insert(Value::Integer(0x03), obj);
    }
    if let Some(extensions) = extensions {
        get_assertion.insert(Value::Integer(0x04), extensions);
    }
    get_assertion.insert(Value::Integer(0x05), options);
    if let Some(x) = pin_auth {
        get_assertion.insert(Value::Integer(0x06), x);
        get_assertion.insert(Value::Integer(0x07), pin_protocol);
    }
    let cbor = Value::Map(get_assertion);

    // Command - authenticatorGetAssertion (0x02)
    let mut payload = [ctapdef::AUTHENTICATOR_GET_ASSERTION].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());

    payload
}
