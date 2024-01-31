use crate::util;
use serde_cbor::Value;
use std::fmt;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct PublicKeyCredentialDescriptor {
    pub id: Vec<u8>,
    pub ctype: String,
    pub transports: Option<Vec<String>>
}

impl PublicKeyCredentialDescriptor {
    // Method naming is weird here, just like in other classes of this type
    // This is actually some sort of chained setter pattern; needs revisiting
    pub fn get_id(self: &mut PublicKeyCredentialDescriptor, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.id = util::cbor_get_bytes_from_map(cbor, "id").unwrap_or_default();
        ret
    }
    pub fn get_type(self: &mut PublicKeyCredentialDescriptor, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.ctype = util::cbor_get_string_from_map(cbor, "type").unwrap_or_default();
        ret
    }

    pub fn get_transports(self: &mut PublicKeyCredentialDescriptor, cbor: &Value) -> Self {
        let mut ret = self.clone();
        ret.transports = util::cbor_get_vec_string_from_map(cbor, "transports").ok();
        ret
    }
}

impl fmt::Display for PublicKeyCredentialDescriptor {
    // Formatting could do with some work, as it could for other classes of this type
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(id: {} , type: {}, transports: {:?})",
            util::to_hex_str(&self.id),
            self.ctype,
            self.transports
        )
    }
}
