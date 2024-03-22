pub mod large_blobs_command;
pub mod large_blobs_params;
pub mod large_blobs_response;
use super::pin::DEFAULT_PIN_UV_AUTH_PROTOCOL;
use super::FidoKeyHid;
use crate::ctaphid;
use crate::pintoken::Permissions;
use crate::result::Result;
use crate::token::Token;
use large_blobs_params::LargeBlobData;

impl FidoKeyHid {
    pub fn get_large_blob_t(&self) -> Result<LargeBlobData> {
        let offset = 0; // TODO
        let read_bytes = 1024; // TODO
        self.large_blobs_t(None, offset, Some(read_bytes), None)
    }

    // TODO remove
    pub fn get_large_blob(&self) -> Result<LargeBlobData> {
        let offset = 0; // TODO
        let read_bytes = 1024; // TODO
        self.large_blobs(None, offset, Some(read_bytes), None)
    }

    pub fn write_large_blob_t(
        &self,
        token: &Token,
        write_data: Vec<u8>,
    ) -> Result<LargeBlobData> {
        let offset = 0; // TODO
        self.large_blobs_t(Some(token), offset, None, Some(write_data))
    }

    // TODO remove
    pub fn write_large_blob(
        &self,
        pin: Option<&str>,
        write_datas: Vec<u8>,
    ) -> Result<LargeBlobData> {
        let offset = 0; // TODO
        self.large_blobs(pin, offset, None, Some(write_datas))
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

    // TODO remove
    fn large_blobs(
        &self,
        pin: Option<&str>,
        offset: u32,
        get: Option<u32>,
        set: Option<Vec<u8>>,
    ) -> Result<LargeBlobData> {
        let cid = ctaphid::ctaphid_init(self)?;

        // get pintoken
        let pin_token = if let Some(pin) = pin {
            Some(self.get_pin_uv_auth_token_with_permissions(
                &cid,
                DEFAULT_PIN_UV_AUTH_PROTOCOL,
                pin,
                Permissions::LARGE_BLOB_WRITE,
            )?)
        } else {
            None
        };

        let send_payload = large_blobs_command::create_payload(pin_token, offset, get, set)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload)?;

        large_blobs_response::parse_cbor(&response_cbor)
    }
}
