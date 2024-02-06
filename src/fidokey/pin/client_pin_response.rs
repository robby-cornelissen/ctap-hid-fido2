use crate::encrypt::cose::CoseKey;
use crate::util;
use anyhow::{anyhow, Result};
use serde_cbor::Value;

#[derive(Default)]
pub struct Pin {
    pub pin_retries: Option<u32>,
    pub uv_retries: Option<u32>,
    pub power_cycle_state: Option<bool>,
}

pub fn parse_cbor_client_pin_get_pin_token(bytes: &[u8]) -> Result<Vec<u8>> {
    let cbor: Value = serde_cbor::from_slice(bytes)?;

    if let Value::Map(n) = cbor {
        // 最初の要素を取得
        let (key, val) = n.iter().next().unwrap();
        if let Value::Integer(member) = key {
            if *member == 2 {
                return Ok(util::cbor_value_to_vec_u8(val).unwrap());
            }
        }
    }
    Err(anyhow!("parse_cbor_client_pin_get_pin_token error"))
}

pub fn parse_cbor_client_pin_get_keyagreement(bytes: &[u8]) -> Result<CoseKey> {
    let cbor: Value = serde_cbor::from_slice(bytes)?;

    if let Value::Map(n) = cbor {
        // 最初の要素を取得
        let (key, val) = n.iter().next().unwrap();
        if let Value::Integer(member) = key {
            if *member == 1 {
                return Ok(CoseKey::new(val).unwrap());
            }
        }
    }
    Err(anyhow!("parse_cbor_client_pin_get_keyagreement error"))
}

pub fn parse_cbor_client_pin_get_retries(bytes: &[u8]) -> Result<Pin> {
    // deserialize to a serde_cbor::Value
    let cbor: Value = serde_cbor::from_slice(bytes)?;

    let mut pin = Pin::default();

    if let Value::Map(n) = cbor {
        for (key, val) in &n {
            if let Value::Integer(member) = key {
                match member {
                    0x03 => pin.pin_retries = Some(util::cbor_value_to_num(val)?),
                    0x04 => pin.power_cycle_state = Some(util::cbor_value_to_bool(val)?),
                    0x05 => pin.uv_retries = Some(util::cbor_value_to_num(val)?),
                    _ => println!("- anything error"),
                }
            }
        }
        Ok(pin)
    } else {
        Err(anyhow!("parse_cbor_client_pin_get_retries error"))
    }
}
