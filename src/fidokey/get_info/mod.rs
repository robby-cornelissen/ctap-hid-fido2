use crate::ctaphid;
use crate::result::Result;
mod get_info_command;
mod get_info_params;
mod get_info_response;
use super::FidoKeyHid;

#[derive(Debug, Clone, PartialEq, strum_macros::AsRefStr)]
pub enum InfoOption {
    #[strum(serialize = "alwaysUv")]
    AlwaysUv,
    #[strum(serialize = "authnrCfg")]
    AuthnrCfg,
    #[strum(serialize = "bioEnroll")]
    BioEnroll,
    #[strum(serialize = "clientPin")]
    ClientPin,
    #[strum(serialize = "credentialMgmtPreview")]
    CredentialMgmtPreview,
    #[strum(serialize = "credMgmt")]
    CredMgmt,
    #[strum(serialize = "ep")]
    Ep,
    #[strum(serialize = "largeBlobs")]
    LargeBlobs,
    #[strum(serialize = "makeCredUvNotRqd")]
    MakeCredUvNotRqd,
    #[strum(serialize = "noMcGaPermissionsWithClientPin")]
    NoMcGaPermissionsWithClientPin,
    #[strum(serialize = "pinUvAuthToken")]
    PinUvAuthToken,
    #[strum(serialize = "plat")]
    Plat,
    #[strum(serialize = "rk")]
    Rk,
    #[strum(serialize = "setMinPINLength")]
    SetMinPINLength,
    #[strum(serialize = "up")]
    Up,
    #[strum(serialize = "userVerificationMgmtPreview")]
    UserVerificationMgmtPreview,
    #[strum(serialize = "uv")]
    Uv,
    #[strum(serialize = "uvAcfg")]
    UvAcfg,
    #[strum(serialize = "uvBioEnroll")]
    UvBioEnroll,
    #[strum(serialize = "uvToken")]
    UvToken,
}

// This really needs to split up into something like InfoVersion and InfoExtension
#[derive(Debug, Clone, PartialEq, strum_macros::AsRefStr)]
pub enum InfoParam {
    #[strum(serialize = "U2F_V2")]
    VersionsU2Fv2,
    #[strum(serialize = "FIDO_2_0")]
    VersionsFido20,
    #[strum(serialize = "FIDO_2_1_PRE")]
    VersionsFido21Pre,
    #[strum(serialize = "FIDO_2_1")]
    VersionsFido21,
    #[strum(serialize = "credProtect")]
    ExtensionsCredProtect,
    #[strum(serialize = "credBlob")]
    ExtensionsCredBlob,
    #[strum(serialize = "credBlobKey")]
    ExtensionsLargeBlobKey,
    #[strum(serialize = "minPinLength")]
    ExtensionsMinPinLength,
    #[strum(serialize = "hmac-secret")]
    ExtensionsHmacSecret,
}

impl FidoKeyHid {
    pub fn get_info(&self) -> Result<get_info_params::Info> {
        let cid = ctaphid::ctaphid_init(self)?;
        let send_payload = get_info_command::create_payload();
        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;
        let info = get_info_response::parse_cbor(&response_cbor)?;
        Ok(info)
    }

    pub fn get_info_u2f(&self) -> Result<String> {
        let cid = ctaphid::ctaphid_init(self)?;

        let _data: Vec<u8> = Vec::new();

        // CTAP1_INS.Version = 3
        match ctaphid::send_apdu(self, &cid, 0, 3, 0, 0, &_data) {
            Ok(result) => {
                let version: String = String::from_utf8(result).unwrap();
                Ok(version)
            }
            Err(error) => Err(anyhow::anyhow!(error).into()),
        }
    }

    pub fn is_info_param_enabled(&self, info_param: &InfoParam) -> Result<bool> {
        let info = self.get_info()?;

        let ret = info.versions.iter().find(|v| *v == info_param.as_ref());
        if ret.is_some() {
            return Ok(true);
        }

        if info.extensions.is_some() {
            let extensions = info.extensions.unwrap();

            let ret = extensions.iter().find(|v| *v == info_param.as_ref());
            if ret.is_some() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn is_info_option_enabled(&self, info_option: &InfoOption) -> Result<Option<bool>> {
        let info = self.get_info()?;

        if info.options.is_some() {
            let options = info.options.unwrap();

            let ret = options.iter().find(|v| (v).0 == info_option.as_ref());
            if let Some(v) = ret {
                // v.1 == true or false
                // - present and set to true
                // - present and set to false
                return Ok(Some(v.1));
            }
        }
        // absent
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Cfg, HidParam};

    use super::*;

    #[test]
    fn test_check_version_support() {
        let hid_params = HidParam::get();
        let device = FidoKeyHid::new(&hid_params, &Cfg::init()).unwrap();

        let info = device.get_info().expect("Could not get authenticator info");

        if info.supports_version(InfoParam::VersionsU2Fv2.as_ref().to_string()) {
            println!("Supports U2F_V2");
        }

        if info.supports_version(InfoParam::VersionsFido20.as_ref().to_string()) {
            println!("Supports FIDO2");
        }

        if info.supports_version(InfoParam::VersionsFido21Pre.as_ref().to_string()) {
            println!("Supports FIDO2.1_PRE");
        }

        if info.supports_version(InfoParam::VersionsFido21.as_ref().to_string()) {
            println!("Supports FIDO2.1");
        }

        assert!(true)
    }

    #[test]
    fn test_check_extension() {
        let hid_params = HidParam::get();
        let device = FidoKeyHid::new(&hid_params, &Cfg::init()).unwrap();

        let info = device.get_info().expect("Could not get authenticator info");

        if info.has_extension(InfoParam::ExtensionsHmacSecret.as_ref().to_string()) {
            println!("Has hmac-secret extension");
        }

        assert!(true)
    }

    #[test]
    fn test_get_option() {
        let hid_params = HidParam::get();
        let device = FidoKeyHid::new(&hid_params, &Cfg::init()).unwrap();

        let info = device.get_info().expect("Could not get authenticator info");

        match info.get_option(InfoOption::ClientPin.as_ref().to_string()) {
            Some(true) => {
                println!("Client PIN option present and set")
            },
            Some(false) => {
                println!("Client PIN option present and not set")
            },
            None => {
                println!("Client PIN option absent")
            }
        }

        assert!(true)
    }
}
