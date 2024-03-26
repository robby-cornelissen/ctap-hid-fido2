pub mod large_blobs_command;
pub mod large_blobs_params;
pub mod large_blobs_response;
use super::FidoKeyHid;
use crate::ctaphid;
use crate::result::Result;
use crate::token::Token;
use large_blobs_params::LargeBlobData;

impl FidoKeyHid {
    pub fn get_large_blob_t(&self) -> Result<LargeBlobData> {
        let offset = 0; // TODO
        let read_bytes = 1024; // TODO
        self.large_blobs_t(None, offset, Some(read_bytes), None)
    }

    pub fn write_large_blob_t(
        &self,
        token: &Token,
        write_data: Vec<u8>,
    ) -> Result<LargeBlobData> {
        let offset = 0; // TODO
        self.large_blobs_t(Some(token), offset, None, Some(write_data))
    }

    fn large_blobs_t(
        &self,
        token: Option<&Token>,
        offset: u32,
        get: Option<u32>,
        set: Option<Vec<u8>>,
    ) -> Result<LargeBlobData> {
        let cid = ctaphid::ctaphid_init(self)?;

        let send_payload = large_blobs_command::create_payload_t(token, offset, get, set)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        large_blobs_response::parse_cbor(&response_cbor)
    }
}
