use crate::result::Result;
use crate::str_buf::StrBuf;
use hidapi::HidApi;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
/// Storage for device related information
pub struct DeviceInfo {
    pub path: PathBuf,
    pub usage_page: u16,
    pub usage: u16,
    pub report_size: u16,
}

/// HID device vendor ID , product ID
#[derive(Clone)]
pub enum HidParam {
    /// Specified when looking for any FIDO device of a certain kind
    VidPid { vid: u16, pid: u16 },
    /// Specified when looking to open a specific device. This is non-ambiguous
    /// when multiple devices of the same kind are connected.
    Path(String),
}

/// Struct that contains information about found HID devices. Also
/// contains a HidParam which can be used to lookup the device
/// later.
#[derive(Clone)]
pub struct HidInfo {
    /// Product ID
    pub pid: u16,
    /// Vendor ID
    pub vid: u16,
    /// A string describing the path to the device
    pub path: String,
    /// Device manufacturer
    pub manufacturer: Option<String>,
    /// A string describing the device
    pub product: Option<String>,
    /// Serial number
    pub serial_number: Option<String>,
    /// A generic information string build by this crate
    pub info: String,
    /// An parameter structure to be used to open this device
    /// later. This is almost always HidParam::Path.
    pub param: HidParam,
}

impl HidParam {
    /// Generate HID parameters for FIDO key devices
    pub fn get() -> Vec<HidParam> {
        vec![
            HidParam::VidPid {
                vid: 0x1050,
                pid: 0x0402,
            }, // Yubikey 4/5 U2F
            HidParam::VidPid {
                vid: 0x1050,
                pid: 0x0407,
            }, // Yubikey 4/5 OTP+U2F+CCID
            HidParam::VidPid {
                vid: 0x1050,
                pid: 0x0120,
            }, // Yubikey Touch U2F
            HidParam::VidPid {
                vid: 0x096E,
                pid: 0x085D,
            }, // Biopass
            HidParam::VidPid {
                vid: 0x096E,
                pid: 0x0866,
            }, // All in pass
            HidParam::VidPid {
                vid: 0x0483,
                pid: 0xA2CA,
            }, // Solokey
            HidParam::VidPid {
                vid: 0x096E,
                pid: 0x0858,
            }, // ePass FIDO(A4B)
            HidParam::VidPid {
                vid: 0x20a0,
                pid: 0x42b1,
            }, // Nitrokey FIDO2 2.0.0
            HidParam::VidPid {
                vid: 0x32a3,
                pid: 0x3201,
            }, // Idem Key
            HidParam::VidPid {
                vid: 0x31bb,
                pid: 0x0622,
            }, // Authentrend ATKey.Pro
        ]
    }
    pub fn auto() -> Vec<HidParam> {
        vec![]
    }
}

pub fn get_hid_devices(usage_page: Option<u16>) -> Vec<HidInfo> {
    let api = hid_api().expect("Failed to get HidAPI instance");
    let mut res = vec![];

    let devices = api.device_list();
    for dev in devices {
        if usage_page.is_none() || dev.usage_page() == usage_page.unwrap() {
            let mut memo = StrBuf::new(0);

            if let Some(n) = dev.product_string() {
                memo.add("product=");
                memo.add(n);
            }
            memo.add(" usage_page=");
            memo.add(&dev.usage_page().to_string());

            memo.add(" usage=");
            memo.add(&dev.usage().to_string());

            if let Some(n) = dev.serial_number() {
                memo.add(" serial_number=");
                memo.add(n);
            }

            memo.add(format!(" path={:?}", dev.path()).as_str());

            let param = match dev.path().to_str() {
                Ok(s) => HidParam::Path(s.to_string()),
                _ => HidParam::VidPid {
                    vid: dev.vendor_id(),
                    pid: dev.product_id(),
                },
            };

            res.push(HidInfo {
                pid: dev.product_id(),
                vid: dev.vendor_id(),
                manufacturer: dev.manufacturer_string().map(String::from),
                product: dev.product_string().map(String::from),
                path: String::from_utf8_lossy(dev.path().to_bytes()).to_string(),
                serial_number: dev.serial_number().map(String::from),
                info: memo.build().to_string(),
                param,
            });
        }
    }
    res
}

pub fn hid_api() -> Result<&'static HidApi> {
    static HID_API: OnceLock<HidApi> = OnceLock::new();

    match HID_API.get() {
        Some(hid_api) => Ok(hid_api),
        None => match HidApi::new() {
            Ok(hid_api) => Ok(HID_API.get_or_init(|| hid_api)),
            Err(e) => Err(anyhow::anyhow!(e).into())
        },
    }
}
