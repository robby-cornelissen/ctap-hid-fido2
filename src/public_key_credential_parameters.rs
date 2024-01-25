use crate::util;
use serde_cbor::Value;
use std::fmt;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct PublicKeyCredentialParameters {
    pub ctype: String,
    pub alg: i32
}

impl PublicKeyCredentialParameters {
    pub fn get_type(self: &mut PublicKeyCredentialParameters, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.ctype = util::cbor_get_string_from_map(cbor, "type").unwrap_or_default();
        ret
    }

    pub fn get_alg(self: &mut PublicKeyCredentialParameters, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.alg = util::cbor_get_num_from_map(cbor, "alg").unwrap_or_default();
        ret
    }
}

impl fmt::Display for PublicKeyCredentialParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(type: {} , alg: {})",
            self.ctype,
            self.alg
        )
    }
}