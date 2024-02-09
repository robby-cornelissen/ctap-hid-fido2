use super::get_info_params;
use crate::public_key_credential_parameters::PublicKeyCredentialParameters;
use crate::result::Result;
use crate::util;
use serde_cbor::Value;

pub fn parse_cbor(bytes: &[u8]) -> Result<get_info_params::Info> {
    let mut info = get_info_params::Info::default();
    let maps = util::cbor_bytes_to_map(bytes)?;
    for (key, val) in &maps {
        if let Value::Integer(member) = key {
            match member {
                0x01 => info.versions = util::cbor_value_to_vec_string(val)?,
                0x02 => info.extensions = Some(util::cbor_value_to_vec_string(val)?),
                0x03 => info.aaguid = util::cbor_value_to_vec_u8(val)?,
                0x04 => {
                    if let Value::Map(xs) = val {
                        let mut options = Vec::new();

                        for (key, val) in xs {
                            if let Value::Text(s) = key {
                                if let Value::Bool(b) = val {
                                    options.push((s.to_string(), *b));
                                }
                            }
                        }

                        info.options = Some(options);
                    }
                }
                0x05 => info.max_msg_size = Some(util::cbor_value_to_num(val)?),
                0x06 => {
                    if let Value::Array(xs) = val {
                        let mut pin_uv_auth_protocols = Vec::new();

                        for x in xs {
                            pin_uv_auth_protocols.push(util::cbor_value_to_num(x)?);
                        }

                        info.pin_uv_auth_protocols = Some(pin_uv_auth_protocols);
                    }
                }
                0x07 => info.max_credential_count_in_list = Some(util::cbor_value_to_num(val)?),
                0x08 => info.max_credential_id_length = Some(util::cbor_value_to_num(val)?),
                0x09 => info.transports = Some(util::cbor_value_to_vec_string(val)?),
                0x0A => {
                    if let Value::Array(xs) = val {
                        let mut algorithms = Vec::new();

                        for x in xs {
                            if let Value::Map(_n) = x {
                                algorithms.push(PublicKeyCredentialParameters {
                                    ctype: util::cbor_get_string_from_map(x, "type")?,
                                    alg: util::cbor_get_num_from_map(x, "alg")?,
                                });
                            }
                        }

                        info.algorithms = Some(algorithms);
                    }
                }
                0x0B => info.max_serialized_large_blob_array = Some(util::cbor_value_to_num(val)?),
                0x0C => info.force_pin_change = Some(util::cbor_value_to_bool(val)?),
                0x0D => info.min_pin_length = Some(util::cbor_value_to_num(val)?),
                0x0E => info.firmware_version = Some(util::cbor_value_to_num(val)?),
                0x0F => info.max_cred_blob_length = Some(util::cbor_value_to_num(val)?),
                0x10 => info.max_rpids_for_set_min_pin_length = Some(util::cbor_value_to_num(val)?),
                0x11 => info.preferred_platform_uv_attempts = Some(util::cbor_value_to_num(val)?),
                0x12 => info.uv_modality = Some(util::cbor_value_to_num(val)?),
                0x14 => {
                    info.remaining_discoverable_credentials = Some(util::cbor_value_to_num(val)?)
                }
                0x15 => {
                    // Should probably create a cbor_value_to_num_vec utility function
                    if let Value::Array(xs) = val {
                        let mut vendor_prototype_config_commands = Vec::new();

                        for x in xs {
                            // Or could get rid of this overly careful parsing and do the same as for pin_uv_auth_protocols
                            match util::cbor_value_to_num(x) {
                                Ok(value) => vendor_prototype_config_commands.push(value),
                                Err(e) => eprintln!("{}", e),
                            }
                        }

                        info.vendor_prototype_config_commands =
                            Some(vendor_prototype_config_commands);
                    }
                }
                _ => println!(
                    "Unknown member found in authenticator info CBOR map: [{:?}]",
                    member
                ),
            }
        }
    }
    Ok(info)
}
