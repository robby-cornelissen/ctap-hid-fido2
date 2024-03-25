use crate::{hid::hid_api, HidParam};
use std::ffi::CString;
use std::sync::mpsc::Sender;

// Complex Submodules
pub mod authenticator_config;
pub mod authenticator_reset;
pub mod bio;
pub mod credential_management;
pub mod get_assertion;
pub mod get_info;
pub mod large_blobs;
pub mod make_credential;
pub mod pin;

// Simple Submodules
mod selection;
mod sub_command_base;
mod wink;

use crate::Result;

pub use get_assertion::{Extension as AssertionExtension, GetAssertionArgsBuilder};

pub use make_credential::{
    CredentialSupportedKeyType, Extension as CredentialExtension, MakeCredentialArgsBuilder,
    MakeCredentialArgsBuilderT,
};

pub struct FidoKeyHid {
    device_internal: hidapi::HidDevice,
    pub enable_log: bool,
    pub use_pre_bio_enrollment: bool,
    pub use_pre_credential_management: bool,
    pub up_needed_prompt: String, // should turn this into an option
    pub prompt_tx: Option<Sender<Option<String>>>,
}

impl FidoKeyHid {
    pub fn new(
        params: &[crate::HidParam],
        cfg: &crate::LibCfg,
        prompt_tx: Option<Sender<Option<String>>>,
    ) -> Result<Self> {
        let api = hid_api().expect("Failed to get HidApi instance");
        for param in params {
            let path = get_path(&api, param);
            if path.is_none() {
                continue;
            }

            if let Ok(dev) = api.open_path(&path.unwrap()) {
                let result = FidoKeyHid {
                    device_internal: dev,
                    enable_log: cfg.enable_log,
                    use_pre_bio_enrollment: cfg.use_pre_bio_enrollment,
                    use_pre_credential_management: cfg.use_pre_credential_management,
                    up_needed_prompt: cfg.keep_alive_msg.to_string(),
                    prompt_tx,
                };
                return Ok(result);
            }
        }
        Err(anyhow::anyhow!("Failed to open device.").into())
    }

    pub fn prompt(&self, prompt: Option<String>) -> Result<()> {
        if !self.up_needed_prompt.is_empty() {
            if self.prompt_tx.is_some() {
                self.prompt_tx
                    .as_ref()
                    .unwrap()
                    .send(prompt.clone())
                    .map_err(|e| anyhow::anyhow!(e))?;
            }

            if let Some(prompt) = prompt {
                println!("{}", prompt);
            }
        }

        Ok(())
    }

    pub(crate) fn write(&self, cmd: &[u8]) -> Result<usize, String> {
        match self.device_internal.write(cmd) {
            Ok(size) => Ok(size),
            Err(_) => Err("Write error".into()),
        }
    }

    pub(crate) fn read(&self) -> Result<Vec<u8>, String> {
        let mut buf: Vec<u8> = vec![0; 64];
        match self.device_internal.read(&mut buf[..]) {
            Ok(_) => Ok(buf),
            Err(_) => Err("Read error".into()),
        }
    }
}

/// Abstraction for getting a path from a provided HidParam
fn get_path(api: &hidapi::HidApi, param: &crate::HidParam) -> Option<CString> {
    match param {
        HidParam::Path(s) => {
            if let Ok(p) = CString::new(s.as_bytes()) {
                return Some(p);
            }
        }
        HidParam::VidPid { vid, pid } => {
            let devices = api.device_list();
            for x in devices {
                if x.vendor_id() == *vid && x.product_id() == *pid {
                    return Some(x.path().to_owned());
                }
            }
        }
    };

    None
}

impl Drop for FidoKeyHid {
    // When the FidoKeyHid instance is dropped, we also drop the prompt sender;
    // this should close the channel as well and unblock the receiver.
    fn drop(&mut self) {
        if self.prompt_tx.is_some() {
            drop(self.prompt_tx.take());
        }
    }
}
