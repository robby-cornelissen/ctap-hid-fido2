use crate::str_buf::StrBuf;
use std::fmt;

#[derive(Debug, Default, Clone)]
pub struct LargeBlobData {
    pub large_blob_array: Vec<u8>,
    pub hash: Vec<u8>,
}

// TODO probably remove
impl fmt::Display for LargeBlobData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strbuf = StrBuf::new(33);
        strbuf.append_hex("- large_blob_array", &self.large_blob_array);
        strbuf.append_hex("- rpid_hash", &self.hash);
        write!(f, "{}", strbuf.build())
    }
}
