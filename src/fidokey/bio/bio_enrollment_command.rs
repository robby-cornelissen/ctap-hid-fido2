use super::super::sub_command_base::SubCommandBase;
use super::bio_enrollment_params::TemplateInfo;
use crate::{ctapdef, encrypt::enc_hmac_sha_256, result::Result, token::Token};
use serde_cbor::{to_vec, Value};
use std::collections::BTreeMap;
use strum_macros::EnumProperty;

#[allow(dead_code)]
#[derive(Debug, Clone, EnumProperty)]
pub enum SubCommand {
    #[strum(props(SubCommandId = "1"))]
    EnrollBegin(Option<u16>),
    #[strum(props(SubCommandId = "2"))]
    EnrollCaptureNextSample(TemplateInfo, Option<u16>),
    #[strum(props(SubCommandId = "3"))]
    CancelCurrentEnrollment,
    #[strum(props(SubCommandId = "4"))]
    EnumerateEnrollments,
    #[strum(props(SubCommandId = "5"))]
    SetFriendlyName(TemplateInfo),
    #[strum(props(SubCommandId = "6"))]
    RemoveEnrollment(TemplateInfo),
    #[strum(props(SubCommandId = "7"))]
    GetFingerprintSensorInfo,
}
impl SubCommandBase for SubCommand {
    fn has_param(&self) -> bool {
        matches!(
            self,
            SubCommand::EnrollBegin(_)
                | SubCommand::EnrollCaptureNextSample(_, _)
                | SubCommand::SetFriendlyName(_)
                | SubCommand::RemoveEnrollment(_)
        )
    }
}

pub fn create_payload(
    token: Option<&Token>,
    sub_command: Option<SubCommand>,
    use_pre_bio_enrollment: bool,
) -> Result<Vec<u8>> {
    let mut map = BTreeMap::new();

    if let Some(sub_command) = sub_command {
        // modality (0x01) = fingerprint (0x01)
        map.insert(Value::Integer(0x01), Value::Integer(0x01_i128));

        // subCommand(0x02)
        let sub_command_value = Value::Integer(sub_command.id()?.into());
        map.insert(Value::Integer(0x02), sub_command_value);

        // subCommandParams (0x03): Map containing following parameters
        let mut sub_command_params_vec = Vec::new();
        if sub_command.has_param() {
            let param = match sub_command {
                SubCommand::EnrollBegin(timeout_milliseconds) => {
                    Some(to_value_timeout(None, timeout_milliseconds))
                }
                SubCommand::EnrollCaptureNextSample(ref template_info, timeout_milliseconds) => {
                    Some(to_value_timeout(Some(template_info), timeout_milliseconds))
                }
                SubCommand::SetFriendlyName(ref template_info)
                | SubCommand::RemoveEnrollment(ref template_info) => {
                    Some(to_value_template_info(template_info))
                }
                _ => None,
            };
            if let Some(param) = param {
                map.insert(Value::Integer(0x03), param.clone());
                sub_command_params_vec = to_vec(&param).map_err(anyhow::Error::new)?;
            }
        }

        if let Some(token) = token {
            // pinUvAuthProtocol(0x04)
            let pin_protocol = Value::Integer(token.protocol.into());
            map.insert(Value::Integer(0x04), pin_protocol);

            // pinUvAuthParam (0x05)
            // - authenticate(pinUvAuthToken, fingerprint (0x01) || enumerateEnrollments (0x04)).
            let pin_uv_auth_param = {
                let mut message = vec![0x01_u8];
                message.append(&mut vec![sub_command.id()?]);
                message.append(&mut sub_command_params_vec.to_vec());

                let signature = enc_hmac_sha_256::authenticate(&token.key, &message);
                signature[0..16].to_vec()
            };

            map.insert(Value::Integer(0x05), Value::Bytes(pin_uv_auth_param));
        }
    } else {
        // getModality (0x06)
        map.insert(Value::Integer(0x06), Value::Bool(true));
    }

    // create cbor
    let cbor = Value::Map(map);

    // create payload
    let mut payload = if use_pre_bio_enrollment {
        [ctapdef::AUTHENTICATOR_BIO_ENROLLMENT_P].to_vec()
    } else {
        [ctapdef::AUTHENTICATOR_BIO_ENROLLMENT].to_vec()
    };
    payload.append(&mut to_vec(&cbor).map_err(anyhow::Error::new)?);

    Ok(payload)
}

fn to_value_template_info(in_param: &TemplateInfo) -> Value {
    let mut param = BTreeMap::new();
    param.insert(
        Value::Integer(0x01),
        Value::Bytes(in_param.template_id.clone()),
    );
    if let Some(v) = in_param.template_friendly_name.clone() {
        param.insert(Value::Integer(0x02), Value::Text(v));
    }
    Value::Map(param)
}

fn to_value_timeout(
    template_info: Option<&TemplateInfo>,
    timeout_milliseconds: Option<u16>,
) -> Value {
    let mut param = BTreeMap::new();
    if let Some(v) = template_info {
        param.insert(Value::Integer(0x01), Value::Bytes(v.template_id.clone()));
    }
    if let Some(v) = timeout_milliseconds {
        param.insert(Value::Integer(0x03), Value::Integer(v as i128));
    }
    Value::Map(param)
}
