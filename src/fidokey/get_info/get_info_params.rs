use crate::str_buf::StrBuf;
use crate::public_key_credential_parameters::PublicKeyCredentialParameters;
use std::fmt;

#[derive(Debug, Default)]
pub struct Info {
    // CTAP 2.0
    pub versions: Vec<String>,
    pub extensions: Option<Vec<String>>,
    pub aaguid: Vec<u8>,
    pub options: Option<Vec<(String, bool)>>,
    pub max_msg_size: Option<u32>,
    //pub pin_protocols: Vec<i32>,
    // CTAP 2.1
    pub pin_uv_auth_protocols: Option<Vec<u32>>,
    pub max_credential_count_in_list: Option<u32>,
    pub max_credential_id_length: Option<u32>,
    pub transports: Option<Vec<String>>,
    pub algorithms: Option<Vec<PublicKeyCredentialParameters>>,
    pub max_serialized_large_blob_array: Option<u32>,
    pub force_pin_change: Option<bool>,
    pub min_pin_length: Option<u32>,
    pub firmware_version: Option<u32>,
    pub max_cred_blob_length: Option<u32>,
    pub max_rpids_for_set_min_pin_length: Option<u32>,
    pub preferred_platform_uv_attempts: Option<u32>,
    pub uv_modality: Option<u32>,
    pub remaining_discoverable_credentials: Option<u32>,
    pub vendor_prototype_config_commands: Option<Vec<u64>>,
}

impl fmt::Display for Info {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strbuf = StrBuf::new(36);
        strbuf
            .append("- versions", &format!("{:?}", self.versions))
            .append("- extensions", &format!("{:?}", self.extensions))
            .append_hex("- aaguid", &self.aaguid)
            .append("- options", &format!("{:?}", self.options))
            .append_option("- max_msg_size", &self.max_msg_size)
            .append(
                "- pin_uv_auth_protocols",
                &format!("{:?}", self.pin_uv_auth_protocols),
            )
            .append_option(
                "- max_credential_count_in_list",
                &self.max_credential_count_in_list,
            )
            .append_option("- max_credential_id_length", &self.max_credential_id_length)
            .append("- transports", &format!("{:?}", self.transports))
            .append("- algorithms", &format!("{:?}", self.algorithms))
            .append(
                "- max_serialized_large_blob_array",
                &format!("{:?}", self.max_serialized_large_blob_array),
            )
            .append(
                "- force_pin_change",
                &format!("{:?}", self.force_pin_change),
            )
            .append("- min_pin_length", &format!("{:?}", self.min_pin_length))
            .append(
                "- firmware_version",
                &format!("{:?}", self.firmware_version),
            )
            .append(
                "- max_cred_blob_length",
                &format!("{:?}", self.max_cred_blob_length),
            )
            .append(
                "- max_rpids_for_set_min_pin_length",
                &format!("{:?}", self.max_rpids_for_set_min_pin_length),
            )
            .append(
                "- preferred_platform_uv_attempts",
                &format!("{:?}", self.preferred_platform_uv_attempts),
            )
            .append("- uv_modality", &format!("{:?}", self.uv_modality))
            .append(
                "- remaining_discoverable_credentials",
                &format!("{:?}", self.remaining_discoverable_credentials),
            );

        write!(f, "{}", strbuf.build())
    }
}
